# Baysöz Labs <baysozlabs@proton.me> — baysoz-authcodegate
"""Typed, strict input model for the authorization-code oracle by Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlsplit

VENDOR = "Baysöz Labs <baysozlabs@proton.me>"


class Verdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    message: str
    reference: str
    evidence: dict[str, str | int | bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "message": self.message,
            "reference": self.reference,
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True, slots=True)
class Evaluation:
    label: str
    flow: str
    verdict: Verdict
    findings: tuple[Finding, ...]

    @property
    def passed(self) -> bool:
        return self.verdict is Verdict.ALLOW and not self.findings


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str
    severity: Severity
    description: str
    reference: str

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "name": self.title,
            "shortDescription": {"text": self.title},
            "fullDescription": {"text": self.description},
            "helpUri": self.reference,
            "defaultConfiguration": {"level": "error"},
            "properties": {"vendor": VENDOR, "tags": ["security", "oauth2", "appsec"]},
        }


def _mapping(value: object, where: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{where}: expected a JSON object")
    return value


def _strict_keys(value: Mapping[str, object], allowed: set[str], where: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(f"{where}: unknown keys {sorted(unknown)}")


def _text(value: Mapping[str, object], key: str, where: str, *, required: bool = True) -> str | None:
    if key not in value or value[key] is None:
        if required:
            raise ValueError(f"{where}.{key}: required string")
        return None
    result = value[key]
    if not isinstance(result, str) or not result:
        raise ValueError(f"{where}.{key}: expected a non-empty string")
    return result


def _integer(value: Mapping[str, object], key: str, where: str, *, required: bool = True, default: int = 0) -> int:
    if key not in value or value[key] is None:
        if required:
            raise ValueError(f"{where}.{key}: required integer")
        return default
    result = value[key]
    if isinstance(result, bool) or not isinstance(result, int):
        raise ValueError(f"{where}.{key}: expected an integer")
    return result


def _boolean(value: Mapping[str, object], key: str, where: str, *, default: bool) -> bool:
    if key not in value or value[key] is None:
        return default
    result = value[key]
    if not isinstance(result, bool):
        raise ValueError(f"{where}.{key}: expected a boolean")
    return result


def _strings(value: Mapping[str, object], key: str, where: str, *, required: bool = True) -> tuple[str, ...]:
    if key not in value or value[key] is None:
        if required:
            raise ValueError(f"{where}.{key}: required array of strings")
        return ()
    result = value[key]
    if not isinstance(result, list) or not all(isinstance(item, str) and item for item in result):
        raise ValueError(f"{where}.{key}: expected an array of non-empty strings")
    return tuple(result)


def _absolute_uri(value: str, where: str) -> None:
    parts = urlsplit(value)
    if not parts.scheme or not parts.netloc or parts.fragment:
        raise ValueError(f"{where}: expected an absolute URI without a fragment")


@dataclass(frozen=True, slots=True)
class Policy:
    issuer: str
    token_endpoint: str
    now: int
    clock_skew_seconds: int = 30
    code_ttl_seconds: int = 300
    require_pkce: bool = True
    allowed_challenge_methods: tuple[str, ...] = ("S256",)
    require_state: bool = True
    min_state_length: int = 16
    require_nonce_for_oidc: bool = True
    require_resource_indicator: bool = True
    allowed_resources: tuple[str, ...] = ()
    require_dpop: bool = True
    dpop_allowed_algs: tuple[str, ...] = ("EdDSA", "ES256")
    dpop_nonce: str | None = None

    @classmethod
    def from_mapping(cls, value: object) -> Policy:
        where = "policy"
        data = _mapping(value, where)
        _strict_keys(
            data,
            {
                "issuer",
                "token_endpoint",
                "now",
                "clock_skew_seconds",
                "code_ttl_seconds",
                "require_pkce",
                "allowed_challenge_methods",
                "require_state",
                "min_state_length",
                "require_nonce_for_oidc",
                "require_resource_indicator",
                "allowed_resources",
                "require_dpop",
                "dpop_allowed_algs",
                "dpop_nonce",
            },
            where,
        )
        issuer = str(_text(data, "issuer", where))
        token_endpoint = str(_text(data, "token_endpoint", where))
        _absolute_uri(issuer, f"{where}.issuer")
        _absolute_uri(token_endpoint, f"{where}.token_endpoint")
        return cls(
            issuer=issuer,
            token_endpoint=token_endpoint,
            now=_integer(data, "now", where),
            clock_skew_seconds=_integer(data, "clock_skew_seconds", where, required=False, default=30),
            code_ttl_seconds=_integer(data, "code_ttl_seconds", where, required=False, default=300),
            require_pkce=_boolean(data, "require_pkce", where, default=True),
            allowed_challenge_methods=_strings(data, "allowed_challenge_methods", where, required=False)
            or ("S256",),
            require_state=_boolean(data, "require_state", where, default=True),
            min_state_length=_integer(data, "min_state_length", where, required=False, default=16),
            require_nonce_for_oidc=_boolean(data, "require_nonce_for_oidc", where, default=True),
            require_resource_indicator=_boolean(data, "require_resource_indicator", where, default=True),
            allowed_resources=_strings(data, "allowed_resources", where, required=False),
            require_dpop=_boolean(data, "require_dpop", where, default=True),
            dpop_allowed_algs=_strings(data, "dpop_allowed_algs", where, required=False) or ("EdDSA", "ES256"),
            dpop_nonce=_text(data, "dpop_nonce", where, required=False),
        )


@dataclass(frozen=True, slots=True)
class Client:
    client_id: str
    redirect_uris: tuple[str, ...]
    allowed_scopes: tuple[str, ...]
    allow_loopback_http: bool = False

    @classmethod
    def from_mapping(cls, value: object) -> Client:
        where = "client"
        data = _mapping(value, where)
        _strict_keys(
            data,
            {"client_id", "redirect_uris", "allowed_scopes", "allow_loopback_http"},
            where,
        )
        return cls(
            client_id=str(_text(data, "client_id", where)),
            redirect_uris=_strings(data, "redirect_uris", where),
            allowed_scopes=_strings(data, "allowed_scopes", where),
            allow_loopback_http=_boolean(data, "allow_loopback_http", where, default=False),
        )


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    label: str
    client_id: str
    redirect_uri: str
    response_type: str
    scope: tuple[str, ...]
    state: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    nonce: str | None = None
    resource: str | None = None
    issuer: str | None = None
    raw_query: str | None = None

    @classmethod
    def from_mapping(cls, value: object) -> AuthorizationRequest:
        where = "authorization_request"
        data = _mapping(value, where)
        _strict_keys(
            data,
            {
                "label",
                "client_id",
                "redirect_uri",
                "response_type",
                "scope",
                "state",
                "code_challenge",
                "code_challenge_method",
                "nonce",
                "resource",
                "issuer",
                "raw_query",
            },
            where,
        )
        return cls(
            label=str(_text(data, "label", where)),
            client_id=str(_text(data, "client_id", where)),
            redirect_uri=str(_text(data, "redirect_uri", where)),
            response_type=str(_text(data, "response_type", where)),
            scope=_strings(data, "scope", where),
            state=_text(data, "state", where, required=False),
            code_challenge=_text(data, "code_challenge", where, required=False),
            code_challenge_method=_text(data, "code_challenge_method", where, required=False),
            nonce=_text(data, "nonce", where, required=False),
            resource=_text(data, "resource", where, required=False),
            issuer=_text(data, "issuer", where, required=False),
            raw_query=_text(data, "raw_query", where, required=False),
        )


@dataclass(frozen=True, slots=True)
class CodeRecord:
    code: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    scope: tuple[str, ...]
    resource: str | None
    nonce: str | None
    issued_at: int
    expires_at: int
    issuer: str
    subject: str
    redeemed: bool = False

    @classmethod
    def from_mapping(cls, value: object) -> CodeRecord:
        where = "code"
        data = _mapping(value, where)
        _strict_keys(
            data,
            {
                "code",
                "client_id",
                "redirect_uri",
                "code_challenge",
                "code_challenge_method",
                "scope",
                "resource",
                "nonce",
                "issued_at",
                "expires_at",
                "issuer",
                "subject",
                "redeemed",
            },
            where,
        )
        return cls(
            code=str(_text(data, "code", where)),
            client_id=str(_text(data, "client_id", where)),
            redirect_uri=str(_text(data, "redirect_uri", where)),
            code_challenge=str(_text(data, "code_challenge", where)),
            code_challenge_method=str(_text(data, "code_challenge_method", where)),
            scope=_strings(data, "scope", where),
            resource=_text(data, "resource", where, required=False),
            nonce=_text(data, "nonce", where, required=False),
            issued_at=_integer(data, "issued_at", where),
            expires_at=_integer(data, "expires_at", where),
            issuer=str(_text(data, "issuer", where)),
            subject=str(_text(data, "subject", where)),
            redeemed=_boolean(data, "redeemed", where, default=False),
        )


@dataclass(frozen=True, slots=True)
class TokenExchange:
    label: str
    grant_type: str
    code: str
    client_id: str
    redirect_uri: str
    code_verifier: str | None = None
    resource: str | None = None
    scope: tuple[str, ...] = ()
    issuer: str | None = None
    dpop_proof: str | None = None
    dpop_method: str = "POST"
    dpop_uri: str | None = None

    @classmethod
    def from_mapping(cls, value: object) -> TokenExchange:
        where = "token_exchange"
        data = _mapping(value, where)
        _strict_keys(
            data,
            {
                "label",
                "grant_type",
                "code",
                "client_id",
                "redirect_uri",
                "code_verifier",
                "resource",
                "scope",
                "issuer",
                "dpop_proof",
                "dpop_method",
                "dpop_uri",
            },
            where,
        )
        return cls(
            label=str(_text(data, "label", where)),
            grant_type=str(_text(data, "grant_type", where)),
            code=str(_text(data, "code", where)),
            client_id=str(_text(data, "client_id", where)),
            redirect_uri=str(_text(data, "redirect_uri", where)),
            code_verifier=_text(data, "code_verifier", where, required=False),
            resource=_text(data, "resource", where, required=False),
            scope=_strings(data, "scope", where, required=False),
            issuer=_text(data, "issuer", where, required=False),
            dpop_proof=_text(data, "dpop_proof", where, required=False),
            dpop_method=str(_text(data, "dpop_method", where, required=False) or "POST"),
            dpop_uri=_text(data, "dpop_uri", where, required=False),
        )


@dataclass(frozen=True, slots=True)
class Bundle:
    vendor: str
    policy: Policy
    clients: tuple[Client, ...]
    codes: tuple[CodeRecord, ...]
    authorization_requests: tuple[AuthorizationRequest, ...]
    token_exchanges: tuple[TokenExchange, ...]
    used_dpop_jtis: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, value: object) -> Bundle:
        where = "bundle"
        data = _mapping(value, where)
        _strict_keys(
            data,
            {"vendor", "policy", "clients", "codes", "authorization_requests", "token_exchanges", "used_dpop_jtis"},
            where,
        )
        vendor = str(_text(data, "vendor", where))
        if "Baysöz Labs" not in vendor or "baysozlabs@proton.me" not in vendor:
            raise ValueError(f"{where}.vendor: attribution to Baysöz Labs <baysozlabs@proton.me> is required")
        clients = data.get("clients", [])
        codes = data.get("codes", [])
        authorizations = data.get("authorization_requests", [])
        exchanges = data.get("token_exchanges", [])
        if not all(isinstance(item, list) for item in (clients, codes, authorizations, exchanges)):
            raise ValueError(f"{where}: clients, codes and request arrays must be arrays")
        return cls(
            vendor=vendor,
            policy=Policy.from_mapping(data["policy"]),
            clients=tuple(Client.from_mapping(item) for item in clients),
            codes=tuple(CodeRecord.from_mapping(item) for item in codes),
            authorization_requests=tuple(AuthorizationRequest.from_mapping(item) for item in authorizations),
            token_exchanges=tuple(TokenExchange.from_mapping(item) for item in exchanges),
            used_dpop_jtis=_strings(data, "used_dpop_jtis", where, required=False),
        )
