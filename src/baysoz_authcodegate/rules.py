# Baysöz Labs <baysozlabs@proton.me> — baysoz-authcodegate
"""Normative rule catalogue for the OAuth authorization-code oracle by Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from .model import Rule, Severity

RULE_CATALOG: dict[str, Rule] = {
    rule.id: rule
    for rule in (
        Rule(
            "ACG-001",
            "response_type must be exactly code",
            Severity.CRITICAL,
            "Hybrid and implicit response types must never be accepted for an authorization-code flight.",
            "https://www.rfc-editor.org/rfc/rfc9700",
        ),
        Rule(
            "ACG-002",
            "client_id must be pre-registered",
            Severity.CRITICAL,
            "Only registered client identifiers may initiate an authorization request.",
            "https://www.rfc-editor.org/rfc/rfc6749",
        ),
        Rule(
            "ACG-003",
            "redirect_uri exact string match",
            Severity.CRITICAL,
            "The redirect URI must equal one registered redirect URI exactly; "
            "prefix or suffix matching enables code theft.",
            "https://www.rfc-editor.org/rfc/rfc6749",
        ),
        Rule(
            "ACG-004",
            "requested scopes must be registered",
            Severity.HIGH,
            "Scope escalation at the authorization endpoint grants privileges the client was never issued.",
            "https://www.rfc-editor.org/rfc/rfc6749",
        ),
        Rule(
            "ACG-005",
            "state must be present and unpredictable",
            Severity.HIGH,
            "Missing or short state permits login-CSRF and authorization-code injection.",
            "https://www.rfc-editor.org/rfc/rfc9700",
        ),
        Rule(
            "ACG-006",
            "PKCE S256 required without downgrade",
            Severity.CRITICAL,
            "PKCE must be mandatory and S256-only; plain or absent challenges enable interception attacks.",
            "https://www.rfc-editor.org/rfc/rfc9700",
        ),
        Rule(
            "ACG-007",
            "PKCE challenge syntax",
            Severity.HIGH,
            "The code challenge must be 43-128 unencoded base64url characters.",
            "https://www.rfc-editor.org/rfc/rfc7636",
        ),
        Rule(
            "ACG-008",
            "OIDC nonce required",
            Severity.HIGH,
            "OpenID Connect requests must carry a nonce to bind the ID token to the browser session.",
            "https://openid.net/specs/openid-connect-core-1_0.html",
        ),
        Rule(
            "ACG-009",
            "resource indicator must be bound",
            Severity.HIGH,
            "RFC 8707 resource indicators must be absolute HTTPS URIs from the allowlist.",
            "https://www.rfc-editor.org/rfc/rfc8707",
        ),
        Rule(
            "ACG-010",
            "authorization issuer binding",
            Severity.CRITICAL,
            "The authorization request must name the expected issuer to defeat issuer mix-up attacks.",
            "https://www.rfc-editor.org/rfc/rfc9700",
        ),
        Rule(
            "ACG-011",
            "PKCE parameter pairing",
            Severity.HIGH,
            "code_challenge and code_challenge_method must appear together or not at all.",
            "https://www.rfc-editor.org/rfc/rfc7636",
        ),
        Rule(
            "ACG-012",
            "duplicate critical parameters rejected",
            Severity.HIGH,
            "Parameter pollution can make front-end and authorization-server parsers disagree.",
            "https://www.rfc-editor.org/rfc/rfc9700",
        ),
        Rule(
            "ACG-013",
            "redirect URI scheme safety",
            Severity.CRITICAL,
            "Fragments, userinfo and unsafe schemes must never appear in registered or presented redirect URIs.",
            "https://www.rfc-editor.org/rfc/rfc8252",
        ),
        Rule(
            "ACG-020",
            "grant_type must be authorization_code",
            Severity.CRITICAL,
            "The token endpoint must reject grant types other than the authorized authorization_code flow.",
            "https://www.rfc-editor.org/rfc/rfc6749",
        ),
        Rule(
            "ACG-021",
            "authorization code must exist",
            Severity.CRITICAL,
            "An unknown code cannot be bound to a client, redirect URI or PKCE challenge.",
            "https://www.rfc-editor.org/rfc/rfc6749",
        ),
        Rule(
            "ACG-022",
            "authorization code freshness",
            Severity.HIGH,
            "Codes outside their issuance window must be rejected, including future-dated codes.",
            "https://www.rfc-editor.org/rfc/rfc6749",
        ),
        Rule(
            "ACG-023",
            "authorization code single use",
            Severity.CRITICAL,
            "Replay of a redeemed code indicates code theft or an authorization-server replay defect.",
            "https://www.rfc-editor.org/rfc/rfc9700",
        ),
        Rule(
            "ACG-024",
            "authorization code client binding",
            Severity.CRITICAL,
            "A code issued to one client must never be redeemed by another client.",
            "https://www.rfc-editor.org/rfc/rfc9700",
        ),
        Rule(
            "ACG-025",
            "authorization code redirect binding",
            Severity.CRITICAL,
            "The token-exchange redirect URI must equal the URI used when the code was issued.",
            "https://www.rfc-editor.org/rfc/rfc6749",
        ),
        Rule(
            "ACG-026",
            "PKCE verifier binding",
            Severity.CRITICAL,
            "The verifier must be well formed and its S256 digest must equal the stored challenge in constant time.",
            "https://www.rfc-editor.org/rfc/rfc7636",
        ),
        Rule(
            "ACG-027",
            "token resource binding",
            Severity.HIGH,
            "The resource indicator presented at the token endpoint must match the authorized audience.",
            "https://www.rfc-editor.org/rfc/rfc8707",
        ),
        Rule(
            "ACG-028",
            "token scope containment",
            Severity.HIGH,
            "A token exchange cannot request scopes broader than the scopes bound to the code.",
            "https://www.rfc-editor.org/rfc/rfc6749",
        ),
        Rule(
            "ACG-029",
            "DPoP proof required",
            Severity.HIGH,
            "Sender-constrained token endpoints must reject exchanges that lack a DPoP proof.",
            "https://www.rfc-editor.org/rfc/rfc9449",
        ),
        Rule(
            "ACG-030",
            "DPoP cryptographic validity",
            Severity.CRITICAL,
            "DPoP signatures, typ, alg, JWK, htm, htu, iat and nonce claims must verify without exceptions.",
            "https://www.rfc-editor.org/rfc/rfc9449",
        ),
        Rule(
            "ACG-031",
            "DPoP jti single use",
            Severity.HIGH,
            "A previously observed DPoP jti must be rejected to defeat proof replay.",
            "https://www.rfc-editor.org/rfc/rfc9449",
        ),
        Rule(
            "ACG-032",
            "token issuer binding",
            Severity.CRITICAL,
            "The code issuer and token-exchange issuer must both equal the configured authorization server.",
            "https://www.rfc-editor.org/rfc/rfc9700",
        ),
    )
}
