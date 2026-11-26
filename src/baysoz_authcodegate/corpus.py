# Baysöz Labs <baysozlabs@proton.me> — baysoz-authcodegate
"""Deterministic adversarial OAuth authorization-code corpus by Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import b64url_encode, canonical_json, pkce_s256
from .dpop import make_ed25519_proof
from .model import AuthorizationRequest, Bundle, TokenExchange, Verdict
from .oracle import Case, CaseResult, run_cases

ISSUER = "https://auth.example.com"
ENDPOINT_URI = "https://auth.example.com/token"
RESOURCE = "https://api.example.com"
REDIRECT = "https://app.example.com/callback"
NATIVE_REDIRECT = "com.baysoz.app:/oauth2redirect"
LOOPBACK_REDIRECT = "http://127.0.0.1:8765/callback"
NOW = 1_700_000_000
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = pkce_s256(VERIFIER)
STATE = "st-a1b2c3d4e5f60718293a4b5c6d7e8f90"
NONCE = "nonce-alpha-7f3c9d21"
DPOP_NONCE = "dpop-nonce-2026-11"
BASELINE_JTI = "jti-baseline-0001"


@dataclass(frozen=True, slots=True)
class Corpus:
    vendor: str
    policy: dict[str, object]
    clients: tuple[dict[str, object], ...]
    codes: tuple[dict[str, object], ...]
    used_jtis: tuple[str, ...]
    cases: tuple[Case, ...]
    private_key: Ed25519PrivateKey

    def to_document(self) -> dict[str, object]:
        return {
            "vendor": self.vendor,
            "schema": "baysoz-authcodegate/adversarial-corpus/v1",
            "policy": self.policy,
            "clients": list(self.clients),
            "codes": list(self.codes),
            "used_dpop_jtis": list(self.used_jtis),
            "cases": [case.to_dict() for case in self.cases],
            "attribution": "Baysöz Labs <baysozlabs@proton.me>",
        }

    def to_bundle(self, *, clean_only: bool = False) -> Bundle:
        authorizations: list[dict[str, object]] = []
        exchanges: list[dict[str, object]] = []
        for case in self.cases:
            if clean_only and case.expected_verdict is not Verdict.ALLOW:
                continue
            payload = dict(case.to_dict()["request"])
            if case.flow == "authorization":
                authorizations.append(payload)
            else:
                exchanges.append(payload)
        return Bundle.from_mapping(
            {
                "vendor": self.vendor,
                "policy": self.policy,
                "clients": list(self.clients),
                "codes": list(self.codes),
                "authorization_requests": authorizations,
                "token_exchanges": exchanges,
                "used_dpop_jtis": list(self.used_jtis),
            }
        )


def _authorization(
    label: str,
    *,
    client_id: str = "web-app",
    redirect_uri: str = REDIRECT,
    response_type: str = "code",
    scopes: tuple[str, ...] = ("openid", "api:read"),
    state: str | None = STATE,
    challenge: str | None = CHALLENGE,
    method: str | None = "S256",
    nonce: str | None = NONCE,
    resource: str | None = RESOURCE,
    issuer: str | None = ISSUER,
    raw_query: str | None = None,
    expected: Verdict = Verdict.ALLOW,
    rule: str | None = None,
    narrative: str = "",
) -> Case:
    request = AuthorizationRequest(
        label=label,
        client_id=client_id,
        redirect_uri=redirect_uri,
        response_type=response_type,
        scope=scopes,
        state=state,
        code_challenge=challenge,
        code_challenge_method=method,
        nonce=nonce,
        resource=resource,
        issuer=issuer,
        raw_query=raw_query,
    )
    return Case(label, "authorization", request, expected, rule, narrative, ("RFC 9700", "RFC 7636"))


def make_corpus() -> Corpus:
    seed = hashlib.sha256("Baysöz Labs baysozlabs@proton.me authcodegate DPoP seed".encode("utf-8")).digest()
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    policy: dict[str, object] = {
        "issuer": ISSUER,
        "token_endpoint": ENDPOINT_URI,
        "now": NOW,
        "clock_skew_seconds": 30,
        "code_ttl_seconds": 300,
        "require_pkce": True,
        "allowed_challenge_methods": ["S256"],
        "require_state": True,
        "min_state_length": 16,
        "require_nonce_for_oidc": True,
        "require_resource_indicator": True,
        "allowed_resources": [RESOURCE],
        "require_dpop": True,
        "dpop_allowed_algs": ["EdDSA", "ES256"],
        "dpop_nonce": DPOP_NONCE,
    }
    clients: tuple[dict[str, object], ...] = (
        {
            "client_id": "web-app",
            "redirect_uris": [REDIRECT],
            "allowed_scopes": ["openid", "profile", "api:read"],
        },
        {
            "client_id": "native-app",
            "redirect_uris": [NATIVE_REDIRECT, LOOPBACK_REDIRECT],
            "allowed_scopes": ["openid", "api:read"],
            "allow_loopback_http": True,
        },
        {
            "client_id": "admin-app",
            "redirect_uris": ["https://admin.example.com/callback"],
            "allowed_scopes": ["openid", "admin:all"],
        },
    )

    def code_record(code: str, **overrides: object) -> dict[str, object]:
        record: dict[str, object] = {
            "code": code,
            "client_id": "web-app",
            "redirect_uri": REDIRECT,
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
            "scope": ["openid", "api:read"],
            "resource": RESOURCE,
            "nonce": NONCE,
            "issued_at": NOW - 30,
            "expires_at": NOW + 300,
            "issuer": ISSUER,
            "subject": "user-1",
        }
        record.update(overrides)
        return record

    codes: tuple[dict[str, object], ...] = (
        code_record("code-valid"),
        code_record("code-expired", expires_at=NOW - 60),
        code_record(
            "code-foreign-client",
            client_id="admin-app",
            redirect_uri="https://admin.example.com/callback",
        ),
        code_record("code-plain", code_challenge=VERIFIER, code_challenge_method="plain"),
        code_record("code-other-resource", resource="https://other.example.com"),
        code_record("code-jti-replay"),
    )

    def proof(jti: str, *, nonce: str = DPOP_NONCE, htu: str = ENDPOINT_URI, issued_at: int = NOW) -> str:
        return make_ed25519_proof(private_key, "POST", htu, issued_at, jti, nonce)

    def token(
        label: str,
        *,
        code: str = "code-valid",
        client_id: str = "web-app",
        redirect_uri: str = REDIRECT,
        verifier: str | None = VERIFIER,
        resource: str | None = RESOURCE,
        scopes: tuple[str, ...] = ("openid", "api:read"),
        issuer: str | None = ISSUER,
        grant_type: str = "authorization_code",
        dpop_proof: str | None = None,
        jti: str | None = None,
        expected: Verdict = Verdict.ALLOW,
        rule: str | None = None,
        narrative: str = "",
    ) -> Case:
        presented_proof = dpop_proof
        if jti is not None and presented_proof is None:
            presented_proof = proof(jti)
        request = TokenExchange(
            label=label,
            grant_type=grant_type,
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_verifier=verifier,
            resource=resource,
            scope=scopes,
            issuer=issuer,
            dpop_proof=presented_proof,
            dpop_method="POST",
            dpop_uri=ENDPOINT_URI,
        )
        return Case(label, "token", request, expected, rule, narrative, ("RFC 9449", "RFC 9700"))

    valid_proof = proof(BASELINE_JTI)
    header = {"typ": "dpop+jwt", "alg": "none", "jwk": {"kty": "OKP", "crv": "Ed25519"}}
    unsigned_payload: dict[str, object] = {
        "htm": "POST",
        "htu": ENDPOINT_URI,
        "iat": NOW,
        "jti": "jti-none-0001",
    }
    alg_none_proof = (
        f"{b64url_encode(canonical_json(header).encode('utf-8'))}."
        f"{b64url_encode(canonical_json(unsigned_payload).encode('utf-8'))}."
    )
    kid_header = {"typ": "dpop+jwt", "alg": "EdDSA", "kid": "unknown-key-2026"}
    kid_payload = {"htm": "POST", "htu": ENDPOINT_URI, "iat": NOW, "jti": "jti-kid-0001", "nonce": DPOP_NONCE}
    kid_signing_input = (
        f"{b64url_encode(canonical_json(kid_header).encode('utf-8'))}."
        f"{b64url_encode(canonical_json(kid_payload).encode('utf-8'))}"
    )
    kid_proof = f"{kid_signing_input}.{b64url_encode(private_key.sign(kid_signing_input.encode('ascii')))}"
    forged_parts = valid_proof.rsplit(".", 1)
    forged_signature = ("B" if forged_parts[1][-1] == "A" else "A")
    forged_proof = f"{forged_parts[0]}.{forged_parts[1][:-1]}{forged_signature}"

    denial = Verdict.DENY
    cases: tuple[Case, ...] = (
        _authorization("auth/baseline"),
        _authorization(
            "auth/implicit-response-type",
            response_type="token",
            expected=denial,
            rule="ACG-001",
            narrative="Hybrid or implicit response types bypass PKCE-bound code issuance.",
        ),
        _authorization(
            "auth/unregistered-client",
            client_id="attacker-app",
            expected=denial,
            rule="ACG-002",
            narrative="An unregistered client must never initiate a code flow.",
        ),
        _authorization(
            "auth/redirect-suffix-confusion",
            redirect_uri=f"{REDIRECT}.attacker.example",
            expected=denial,
            rule="ACG-003",
            narrative="Suffix matching on redirect URIs leaks codes to attacker-controlled hosts.",
        ),
        _authorization(
            "auth/redirect-path-traversal",
            redirect_uri="https://app.example.com/callback/../steal",
            expected=denial,
            rule="ACG-003",
            narrative="Path traversal defeats naive prefix checks of redirect URIs.",
        ),
        _authorization(
            "auth/redirect-fragment-injection",
            redirect_uri=f"{REDIRECT}#token",
            expected=denial,
            rule="ACG-013",
            narrative="Fragments are never sent to the server and enable client-side code capture.",
        ),
        _authorization(
            "auth/redirect-userinfo-confusion",
            redirect_uri="https://evil.example@app.example.com/callback",
            expected=denial,
            rule="ACG-013",
            narrative="Userinfo components can make host parsers disagree with browsers.",
        ),
        _authorization(
            "auth/redirect-scheme-downgrade",
            redirect_uri="http://app.example.com/callback",
            expected=denial,
            rule="ACG-013",
            narrative="Non-loopback cleartext redirects expose authorization codes on the wire.",
        ),
        _authorization(
            "auth/scope-escalation",
            scopes=("openid", "api:read", "admin:all"),
            expected=denial,
            rule="ACG-004",
            narrative="The client requests an unregistered administrative scope.",
        ),
        _authorization(
            "auth/state-omitted",
            state=None,
            expected=denial,
            rule="ACG-005",
            narrative="Absent state permits login cross-site request forgery.",
        ),
        _authorization(
            "auth/state-too-short",
            state="abc",
            expected=denial,
            rule="ACG-005",
            narrative="Low-entropy state is brute-forceable and fails the configured minimum.",
        ),
        _authorization(
            "auth/pkce-omitted",
            challenge=None,
            method=None,
            expected=denial,
            rule="ACG-006",
            narrative="Authorization-code interception succeeds when PKCE is optional.",
        ),
        _authorization(
            "auth/pkce-plain-downgrade",
            challenge=VERIFIER,
            method="plain",
            expected=denial,
            rule="ACG-006",
            narrative="An attacker who can read the request can replay a plain challenge.",
        ),
        _authorization(
            "auth/pkce-malformed-challenge",
            challenge="abc",
            expected=denial,
            rule="ACG-007",
            narrative="Short challenges reduce the effective PKCE entropy.",
        ),
        _authorization(
            "auth/pkce-method-omitted",
            method=None,
            expected=denial,
            rule="ACG-011",
            narrative="Challenge and method parameters must be paired.",
        ),
        _authorization(
            "auth/oidc-nonce-omitted",
            nonce=None,
            expected=denial,
            rule="ACG-008",
            narrative="Missing nonce detaches the ID token from the browser session.",
        ),
        _authorization(
            "auth/resource-omitted",
            resource=None,
            expected=denial,
            rule="ACG-009",
            narrative="An unbound audience enables token reuse against unintended APIs.",
        ),
        _authorization(
            "auth/resource-cross-audience",
            resource="https://evil.example.com",
            expected=denial,
            rule="ACG-009",
            narrative="An attacker supplies an unregistered audience for the issued code.",
        ),
        _authorization(
            "auth/resource-scheme-downgrade",
            resource="http://api.example.com",
            expected=denial,
            rule="ACG-009",
            narrative="Cleartext resource indicators violate RFC 8707 deployment rules.",
        ),
        _authorization(
            "auth/issuer-mix-up",
            issuer="https://evil-issuer.example.com",
            expected=denial,
            rule="ACG-010",
            narrative="Issuer mix-up routes the code to an attacker-controlled token endpoint.",
        ),
        _authorization(
            "auth/duplicate-client-id-parameter",
            raw_query="client_id=web-app&client_id=admin-app&response_type=code",
            expected=denial,
            rule="ACG-012",
            narrative="Divergent parser views of duplicated parameters enable consent phishing.",
        ),
        _authorization(
            "auth/native-custom-scheme",
            client_id="native-app",
            redirect_uri=NATIVE_REDIRECT,
            scopes=("openid",),
            expected=Verdict.ALLOW,
            narrative="A registered native custom scheme is a compliant loopback alternative.",
        ),
        _authorization(
            "auth/native-loopback",
            client_id="native-app",
            redirect_uri=LOOPBACK_REDIRECT,
            scopes=("openid",),
            expected=Verdict.ALLOW,
            narrative="RFC 8252 permits cleartext loopback redirects for native clients.",
        ),
        token("token/baseline", jti=BASELINE_JTI),
        token(
            "token/wrong-grant-type",
            jti="jti-grant-0001",
            grant_type="client_credentials",
            expected=denial,
            rule="ACG-020",
            narrative="A different grant type must not be accepted on the code endpoint.",
        ),
        token(
            "token/unknown-code",
            jti="jti-unknown-0001",
            code="code-does-not-exist",
            expected=denial,
            rule="ACG-021",
            narrative="Codes outside the registry must be rejected before any binding checks.",
        ),
        token(
            "token/expired-code",
            jti="jti-expired-0001",
            code="code-expired",
            expected=denial,
            rule="ACG-022",
            narrative="Long-lived codes extend the interception window indefinitely.",
        ),
        token(
            "token/code-replay",
            jti="jti-replay-0002",
            expected=denial,
            rule="ACG-023",
            narrative="The baseline code is redeemed a second time to emulate stolen-code replay.",
        ),
        token(
            "token/client-swap",
            jti="jti-client-0001",
            client_id="admin-app",
            expected=denial,
            rule="ACG-024",
            narrative="A code issued to the web app is exchanged by a different registered client.",
        ),
        token(
            "token/redirect-mismatch",
            jti="jti-redirect-0001",
            redirect_uri="https://app.example.com/attacker",
            expected=denial,
            rule="ACG-025",
            narrative="The token request uses a redirect URI that was never authorized for the code.",
        ),
        token(
            "token/verifier-omitted",
            jti="jti-verifier-0001",
            verifier=None,
            expected=denial,
            rule="ACG-026",
            narrative="Without a verifier, an intercepted code is sufficient for redemption.",
        ),
        token(
            "token/verifier-mismatch",
            jti="jti-verifier-0002",
            verifier="b" * 43,
            expected=denial,
            rule="ACG-026",
            narrative="A syntactically valid but incorrect verifier fails the S256 binding.",
        ),
        token(
            "token/plain-code-downgrade",
            jti="jti-plain-0001",
            code="code-plain",
            expected=denial,
            rule="ACG-026",
            narrative="A code stored with a plain challenge must never be redeemable.",
        ),
        token(
            "token/resource-substitution",
            jti="jti-resource-0001",
            code="code-other-resource",
            expected=denial,
            rule="ACG-027",
            narrative="The audience presented at the token endpoint differs from the issued audience.",
        ),
        token(
            "token/scope-escalation",
            jti="jti-scope-0001",
            scopes=("openid", "admin:all"),
            expected=denial,
            rule="ACG-028",
            narrative="The token request asks for an administrative scope not bound to the code.",
        ),
        token(
            "token/issuer-mix-up",
            jti="jti-issuer-0001",
            issuer="https://evil-issuer.example.com",
            expected=denial,
            rule="ACG-032",
            narrative="The token request is sent to a foreign issuer with a captured code.",
        ),
        token(
            "token/dpop-omitted",
            expected=denial,
            rule="ACG-029",
            narrative="Unconstrained bearer tokens are rejected by this deployment policy.",
        ),
        token(
            "token/dpop-alg-none",
            dpop_proof=alg_none_proof,
            expected=denial,
            rule="ACG-030",
            narrative="An unsigned DPoP proof must never be accepted.",
        ),
        token(
            "token/dpop-kid-confusion",
            dpop_proof=kid_proof,
            expected=denial,
            rule="ACG-030",
            narrative="A kid-only proof without an embedded JWK is rejected to prevent key confusion.",
        ),
        token(
            "token/dpop-forged-signature",
            dpop_proof=forged_proof,
            expected=denial,
            rule="ACG-030",
            narrative="A tampered Ed25519 signature fails cryptographic verification.",
        ),
        token(
            "token/dpop-wrong-endpoint",
            dpop_proof=proof("jti-endpoint-0001", htu="https://auth.example.com/other"),
            expected=denial,
            rule="ACG-030",
            narrative="A proof for another endpoint must not authenticate this token request.",
        ),
        token(
            "token/dpop-wrong-nonce",
            dpop_proof=proof("jti-nonce-0001", nonce="attacker-nonce"),
            expected=denial,
            rule="ACG-030",
            narrative="Server-issued DPoP nonces prevent offline proof precomputation.",
        ),
        token(
            "token/dpop-stale",
            dpop_proof=proof("jti-stale-0001", issued_at=NOW - 500),
            expected=denial,
            rule="ACG-030",
            narrative="A stale DPoP proof is outside the configured clock-skew window.",
        ),
        token(
            "token/dpop-jti-replay",
            jti=BASELINE_JTI,
            code="code-jti-replay",
            expected=denial,
            rule="ACG-031",
            narrative="The proof identifier from the baseline exchange is reused with a fresh code.",
        ),
    )
    return Corpus(
        vendor="Baysöz Labs <baysozlabs@proton.me>",
        policy=policy,
        clients=clients,
        codes=codes,
        used_jtis=(),
        cases=cases,
        private_key=private_key,
    )


def run_corpus(corpus: Corpus) -> tuple[CaseResult, ...]:
    bundle = corpus.to_bundle()
    return run_cases(
        corpus.cases,
        bundle.policy,
        bundle.clients,
        bundle.codes,
        bundle.policy.now,
        corpus.used_jtis,
    )
