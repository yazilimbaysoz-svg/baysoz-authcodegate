# Security Policy — Baysöz Labs <baysozlabs@proton.me>

Owner: Baysöz Labs <baysozlabs@proton.me>
Project: `baysoz-authcodegate`

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |

## Threat model

- **Untrusted evidence JSON.** Captured authorization requests, token exchanges and code registries may be attacker-influenced. Parsing is strict and rejects unknown fields, type drift, missing vendor attribution and non-absolute issuer/token endpoints.
- **Authorization-code theft.** Intercepted codes must fail unless the S256 verifier, client, redirect URI, resource, scope and issuer all match. Redeemed codes are rejected on replay.
- **PKCE downgrade.** Plain or absent challenge methods are denied even if a verifier is later presented.
- **Redirect fraud.** Exact registered-string comparison plus scheme safety checks block suffix, prefix, path-traversal, userinfo, fragment and cleartext downgrades.
- **Issuer mix-up.** Requests and exchanges must name the configured issuer; foreign-issuer codes are denied.
- **DPoP forgery and replay.** Only embedded-JWK EdDSA/ES256 proofs with correct `typ`, `htm`, `htu`, `iat`, `jti` and server nonce are accepted; `kid`-only proofs, `alg=none`, tampered signatures and reused `jti` values are denied.
- **Parameter pollution.** Duplicate critical query parameters are reported.

## Out of scope

- TLS chain validation, DNS resolution and live authorization-server probing: this tool is deliberately offline.
- Detection of server-side vulnerabilities outside the supplied evidence bundle.
- Cryptanalysis of `cryptography` primitives; the tool relies on the installed library's hardened implementations.

## Safe handling of evidence

Authorization codes are secrets. The oracle fingerprints codes with SHA-256 before placing them in SARIF; raw code values are never written to findings. Adversarial corpus files contain synthetic codes only. Do not commit production captures.

## Hardening guarantees

- No network sockets, HTTP clients, databases, shell execution, services or local LLM inference.
- Constant-time comparison for all security-relevant string/digest equality checks.
- Fail-closed parsing, JSON canonicalization for fingerprints and deterministic corpus generation.
- CI runs pytest, ruff (`E,F,W,S,B`) and `semgrep --config p/default --error` on Python 3.13.

## Reporting vulnerabilities

Report privately to **baysozlabs@proton.me** with a minimal reproducer, affected version and impact assessment. Please do not open public issues for exploitable defects. Baysöz Labs aims to acknowledge reports within three working days and coordinate disclosure after a fix is released.

Baysöz Labs <baysozlabs@proton.me>
