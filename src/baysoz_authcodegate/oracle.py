# Baysöz Labs <baysozlabs@proton.me> — baysoz-authcodegate
"""Stateful authorization-code conformance oracle by Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import hmac
import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, fields
from typing import Literal
from urllib.parse import parse_qsl, urlsplit

from .crypto import fingerprint, is_pkce_challenge, is_pkce_verifier, pkce_s256
from .dpop import verify_proof
from .model import (
    AuthorizationRequest,
    Bundle,
    Client,
    CodeRecord,
    Evaluation,
    Finding,
    Policy,
    Severity,
    TokenExchange,
    Verdict,
)
from .rules import RULE_CATALOG

_CUSTOM_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*$")
_DANGEROUS_SCHEMES = frozenset({"javascript", "data", "file", "ftp", "mailto", "tel", "about", "blob"})
_CRITICAL_PARAMETERS = frozenset(
    {"client_id", "redirect_uri", "response_type", "scope", "state", "code_challenge", "code_challenge_method", "nonce"}
)


@dataclass(frozen=True, slots=True)
class Case:
    label: str
    flow: Literal["authorization", "token"]
    request: AuthorizationRequest | TokenExchange
    expected_verdict: Verdict
    expected_rule: str | None = None
    narrative: str = ""
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "flow": self.flow,
            "request": _request_to_mapping(self.request),
            "expected_verdict": self.expected_verdict.value,
            "expected_rule": self.expected_rule,
            "narrative": self.narrative,
            "references": list(self.references),
        }


@dataclass(frozen=True, slots=True)
class CaseResult:
    case: Case
    evaluation: Evaluation
    passed: bool
    detail: str


def _request_to_mapping(request: AuthorizationRequest | TokenExchange) -> dict[str, object]:
    result: dict[str, object] = {}
    for item in fields(request):
        value = getattr(request, item.name)
        if isinstance(value, tuple):
            result[item.name] = list(value)
        elif value is not None:
            result[item.name] = value
    return result


def _eq(left: str | None, right: str | None) -> bool:
    if left is None or right is None:
        return False
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _finding(rule_id: str, message: str, **evidence: str | int | bool) -> Finding:
    rule = RULE_CATALOG[rule_id]
    return Finding(
        rule_id=rule_id,
        title=rule.title,
        severity=rule.severity,
        message=message,
        reference=rule.reference,
        evidence=evidence,
    )


def _safe_redirect(redirect_uri: str, client: Client) -> bool:
    parts = urlsplit(redirect_uri)
    if parts.fragment or parts.username is not None or parts.password is not None:
        return False
    scheme = parts.scheme.lower()
    if scheme == "https":
        return True
    if scheme == "http":
        return client.allow_loopback_http and parts.hostname in {"127.0.0.1", "::1", "localhost"}
    if scheme in _DANGEROUS_SCHEMES or not _CUSTOM_SCHEME_RE.fullmatch(scheme):
        return False
    return bool(parts.path or parts.netloc)


def _valid_resource(resource: str | None, policy: Policy) -> bool:
    if resource is None:
        return False
    parts = urlsplit(resource)
    if parts.scheme != "https" or not parts.netloc or parts.fragment:
        return False
    return not policy.allowed_resources or resource in policy.allowed_resources


def _duplicate_parameters(raw_query: str | None) -> tuple[str, ...]:
    if not raw_query:
        return ()
    counts = Counter(key for key, _ in parse_qsl(raw_query, keep_blank_values=True))
    return tuple(sorted(key for key in _CRITICAL_PARAMETERS if counts[key] > 1))


def evaluate_authorization(
    policy: Policy,
    clients: Sequence[Client],
    request: AuthorizationRequest,
) -> Evaluation:
    findings: list[Finding] = []
    if request.response_type != "code":
        findings.append(
            _finding(
                "ACG-001",
                "Only response_type=code is accepted on this authorization server.",
                presented=request.response_type,
            )
        )

    client = next((item for item in clients if _eq(item.client_id, request.client_id)), None)
    if client is None:
        findings.append(
            _finding(
                "ACG-002",
                "The client_id was not registered with this authorization server.",
                client_id=request.client_id,
            )
        )
    else:
        if not any(_eq(registered, request.redirect_uri) for registered in client.redirect_uris):
            findings.append(
                _finding(
                    "ACG-003",
                    "The presented redirect URI is not an exact registered redirect URI.",
                    presented=request.redirect_uri,
                    registered="|".join(client.redirect_uris),
                )
            )
        if not _safe_redirect(request.redirect_uri, client):
            findings.append(
                _finding(
                    "ACG-013",
                    "The redirect URI uses an unsafe scheme, embedded credentials or a fragment.",
                    presented=request.redirect_uri,
                )
            )
        if not set(request.scope).issubset(client.allowed_scopes):
            findings.append(
                _finding(
                    "ACG-004",
                    "Requested scopes exceed the scopes registered for this client.",
                    requested="|".join(request.scope),
                    registered="|".join(client.allowed_scopes),
                )
            )

    if policy.require_state and (request.state is None or len(request.state) < policy.min_state_length):
        findings.append(
            _finding(
                "ACG-005",
                "A state value of at least the configured minimum length is required.",
                state_present=request.state is not None,
                state_length=len(request.state or ""),
            )
        )

    if policy.require_pkce:
        if request.code_challenge is None or request.code_challenge_method is None:
            findings.append(
                _finding(
                    "ACG-006",
                    "PKCE challenge and method are both required for every authorization request.",
                    challenge_present=request.code_challenge is not None,
                    method_present=request.code_challenge_method is not None,
                )
            )
        if request.code_challenge_method == "plain":
            findings.append(_finding("ACG-006", "The plain PKCE method is forbidden by RFC 9700.", method="plain"))
        elif request.code_challenge_method not in policy.allowed_challenge_methods:
            findings.append(
                _finding(
                    "ACG-007",
                    "The PKCE challenge method is not in the server allowlist.",
                    method=request.code_challenge_method or "absent",
                )
            )
        if not is_pkce_challenge(request.code_challenge):
            findings.append(
                _finding(
                    "ACG-007",
                    "The PKCE challenge is not 43-128 base64url characters.",
                    challenge_length=len(request.code_challenge or ""),
                )
            )
        if (request.code_challenge is None) != (request.code_challenge_method is None):
            findings.append(_finding("ACG-011", "PKCE challenge and method must appear together.", paired=False))

    if policy.require_nonce_for_oidc and "openid" in request.scope and not request.nonce:
        findings.append(
            _finding("ACG-008", "OpenID Connect requests must carry a nonce.", scope="|".join(request.scope))
        )

    if request.resource is not None or policy.require_resource_indicator:
        if not _valid_resource(request.resource, policy):
            findings.append(
                _finding(
                    "ACG-009",
                    "The resource indicator must be an allowlisted absolute HTTPS URI.",
                    resource=request.resource or "absent",
                )
            )

    if not _eq(request.issuer, policy.issuer):
        findings.append(
            _finding(
                "ACG-010",
                "The authorization request is not bound to the expected issuer.",
                presented=request.issuer or "absent",
                expected=policy.issuer,
            )
        )

    duplicates = _duplicate_parameters(request.raw_query)
    if duplicates:
        findings.append(
            _finding(
                "ACG-012",
                "Critical authorization parameters occur more than once.",
                duplicated="|".join(duplicates),
            )
        )

    verdict = Verdict.DENY if findings else Verdict.ALLOW
    return Evaluation(request.label, "authorization", verdict, tuple(findings))


def evaluate_exchange(
    policy: Policy,
    clients: Sequence[Client],
    codes: Sequence[CodeRecord],
    exchange: TokenExchange,
    now: int,
    used_jtis: set[str],
    redeemed_codes: set[str],
) -> Evaluation:
    findings: list[Finding] = []
    if exchange.grant_type != "authorization_code":
        findings.append(
            _finding("ACG-020", "Only the authorization_code grant is accepted here.", presented=exchange.grant_type)
        )

    code = next((item for item in codes if _eq(item.code, exchange.code)), None)
    if code is None:
        findings.append(
            _finding("ACG-021", "The authorization code does not exist in the server registry.", present=False)
        )
    else:
        if code.redeemed or code.code in redeemed_codes:
            findings.append(
                _finding(
                    "ACG-023",
                    "The authorization code has already been redeemed and must never be reused.",
                    code_fingerprint=fingerprint(code.code),
                )
            )
        if now > code.expires_at + policy.clock_skew_seconds or now < code.issued_at - policy.clock_skew_seconds:
            findings.append(
                _finding(
                    "ACG-022",
                    "The authorization code is expired or future-dated outside the permitted skew.",
                    issued_at=code.issued_at,
                    expires_at=code.expires_at,
                    evaluated_at=now,
                )
            )
        if not _eq(exchange.client_id, code.client_id):
            findings.append(
                _finding(
                    "ACG-024",
                    "The redeeming client differs from the client the code was issued to.",
                    expected=code.client_id,
                    presented=exchange.client_id,
                )
            )
        if not _eq(exchange.redirect_uri, code.redirect_uri):
            findings.append(
                _finding(
                    "ACG-025",
                    "The token-exchange redirect URI differs from the authorization redirect URI.",
                    expected=code.redirect_uri,
                    presented=exchange.redirect_uri,
                )
            )
        verifier = exchange.code_verifier
        if code.code_challenge_method != "S256":
            findings.append(
                _finding(
                    "ACG-026",
                    "The stored code challenge method is not S256 and is forbidden by policy.",
                    method=code.code_challenge_method,
                )
            )
        elif not is_pkce_verifier(verifier):
            findings.append(
                _finding(
                    "ACG-026",
                    "The PKCE verifier is absent or violates the unreserved 43-128 character syntax.",
                    verifier_length=len(verifier or ""),
                )
            )
        elif not hmac.compare_digest(pkce_s256(verifier).encode("ascii"), code.code_challenge.encode("ascii")):
            findings.append(
                _finding(
                    "ACG-026",
                    "The S256 digest of the verifier does not match the stored challenge.",
                    matched=False,
                )
            )

        if policy.require_resource_indicator and not _eq(exchange.resource, code.resource):
            findings.append(
                _finding(
                    "ACG-027",
                    "The token-exchange audience differs from the authorized resource indicator.",
                    expected=code.resource or "absent",
                    presented=exchange.resource or "absent",
                )
            )
        if exchange.resource is not None and not _valid_resource(exchange.resource, policy):
            findings.append(
                _finding(
                    "ACG-027",
                    "The presented resource indicator is not an allowlisted HTTPS URI.",
                    resource=exchange.resource,
                )
            )
        if not set(exchange.scope).issubset(code.scope):
            findings.append(
                _finding(
                    "ACG-028",
                    "The token exchange requests scopes beyond those bound to the code.",
                    requested="|".join(exchange.scope),
                    authorized="|".join(code.scope),
                )
            )
        if not _eq(exchange.issuer, policy.issuer) or not _eq(code.issuer, policy.issuer):
            findings.append(
                _finding(
                    "ACG-032",
                    "The code or token request is bound to a foreign issuer.",
                    code_issuer=code.issuer,
                    presented=exchange.issuer or "absent",
                    expected=policy.issuer,
                )
            )

    if policy.require_dpop:
        if not exchange.dpop_proof:
            findings.append(_finding("ACG-029", "A DPoP proof is mandatory at this token endpoint.", present=False))
        else:
            valid, reason, jti = verify_proof(
                exchange.dpop_proof,
                policy,
                exchange.dpop_method,
                exchange.dpop_uri or policy.token_endpoint,
                now,
                frozenset(used_jtis),
            )
            if not valid:
                rule_id = "ACG-031" if reason == "jti-replay" else "ACG-030"
                findings.append(_finding(rule_id, f"DPoP proof rejected: {reason}.", reason=reason))
            elif jti is not None:
                used_jtis.add(jti)

    verdict = Verdict.DENY if findings else Verdict.ALLOW
    return Evaluation(exchange.label, "token", verdict, tuple(findings))


def run_cases(
    cases: Sequence[Case],
    policy: Policy,
    clients: Sequence[Client],
    codes: Sequence[CodeRecord],
    now: int,
    used_jtis: Sequence[str] = (),
) -> tuple[CaseResult, ...]:
    redeemed_codes = {code.code for code in codes if code.redeemed}
    observed_jtis = set(used_jtis)
    results: list[CaseResult] = []
    for case in cases:
        if case.flow == "authorization" and isinstance(case.request, AuthorizationRequest):
            evaluation = evaluate_authorization(policy, clients, case.request)
        elif case.flow == "token" and isinstance(case.request, TokenExchange):
            evaluation = evaluate_exchange(
                policy, clients, codes, case.request, now, observed_jtis, redeemed_codes
            )
            if evaluation.verdict is Verdict.ALLOW and not any(
                item.rule_id == "ACG-023" for item in evaluation.findings
            ):
                redeemed_codes.add(case.request.code)
        else:
            raise ValueError("case flow does not match the request type")
        rule_ids = {item.rule_id for item in evaluation.findings}
        passed = evaluation.verdict is case.expected_verdict
        if case.expected_rule is not None:
            passed = passed and case.expected_rule in rule_ids
        if evaluation.verdict is Verdict.ALLOW and evaluation.findings:
            passed = False
        detail = "verdict and rule matched" if passed else "verdict or rule mismatch"
        results.append(CaseResult(case, evaluation, passed, detail))
    return tuple(results)


def audit_bundle(bundle: Bundle) -> tuple[Evaluation, ...]:
    cases: list[Case] = [
        Case(
            label=(
                request.label
                if request.label.startswith("authorization/")
                else f"authorization/{request.label}"
            ),
            flow="authorization",
            request=request,
            expected_verdict=Verdict.ALLOW,
        )
        for request in bundle.authorization_requests
    ]
    cases.extend(
        Case(
            label=exchange.label if exchange.label.startswith("token/") else f"token/{exchange.label}",
            flow="token",
            request=exchange,
            expected_verdict=Verdict.ALLOW,
        )
        for exchange in bundle.token_exchanges
    )
    results = run_cases(
        cases,
        bundle.policy,
        bundle.clients,
        bundle.codes,
        bundle.policy.now,
        bundle.used_dpop_jtis,
    )
    return tuple(result.evaluation for result in results)


def severity_rank(severity: Severity) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}[severity.value]
