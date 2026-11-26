# Architecture — Baysöz Labs <baysozlabs@proton.me>

Owner: Baysöz Labs <baysozlabs@proton.me>
Project: `baysoz-authcodegate`

## System shape

```
                    ┌────────────────────────────────────────────┐
 evidence JSON      │ model.py  (strict, frozen dataclasses)     │
 (captured flows)──►│ Policy / Client / CodeRecord /             │
                    │ AuthorizationRequest / TokenExchange       │
                    └───────────────────┬────────────────────────┘
                                        ▼
                    ┌────────────────────────────────────────────┐
                    │ oracle.py  stateful conformance engine     │
                    │  • authorization rules ACG-001…013         │
                    │  • token rules ACG-020…032                 │
                    │  • redeemed-code + DPoP-jti state          │
                    └───────┬───────────────────────┬────────────┘
                            │                       │
                ┌───────────▼──────────┐   ┌────────▼────────────────┐
                │ crypto.py / dpop.py  │   │ rules.py (normative ID, │
                │ S256, canonical b64, │   │ severity, RFC reference)│
                │ Ed25519 / ES256 JWS  │   └────────┬────────────────┘
                └───────────┬──────────┘            │
                            └──────────┬────────────┘
                                       ▼
                          ┌────────────────────────────┐
                          │ sarif.py  SARIF 2.1.0      │
                          │ + stdout summary + exit 0/1│
                          └────────────────────────────┘
```

## Module responsibilities

| Module | Responsibility |
| --- | --- |
| `model.py` | Strict JSON→typed model conversion. Unknown keys, missing attribution, non-absolute URIs and type drift fail closed. |
| `crypto.py` | PKCE S256, unpadded canonical base64url, canonical JSON and SHA-256 fingerprints. |
| `dpop.py` | RFC 9449 proof verification at the token endpoint: `typ`, `alg`, embedded JWK, signature, `htm`, `htu`, `iat`, `jti`, server nonce, key-confusion rejection. |
| `rules.py` | Single source of truth for rule IDs, severities, descriptions and normative references. |
| `oracle.py` | Pure evaluation functions plus stateful case runner. Tracks redeemed authorization codes and observed DPoP `jti` values across an ordered bundle. |
| `corpus.py` | 44 deterministic adversarial cases with real signed DPoP evidence and expected verdict/rule outcomes. |
| `tribunal.py` | Six independent jurors: protocol, token binding, cryptography, replay, determinism and attribution. |
| `sarif.py` | SARIF 2.1.0 emission with rule metadata, fingerprints and Baysöz Labs attribution. |
| `cli.py` | `audit`, `forge`, `selftest`, `tribunal`, `rules` subcommands; exit codes 0/1/2. |

## Data flow and trust boundaries

1. **Input boundary.** Evidence JSON is untrusted. `Bundle.from_mapping` rejects unknown fields so a renamed policy field cannot silently disable a check. The `vendor` field must contain `Baysöz Labs <baysozlabs@proton.me>`.
2. **Authorization boundary.** `evaluate_authorization` compares `response_type`, `client_id`, redirect URI (exact match plus scheme safety), scope containment, `state`, PKCE pairing/S256/challenge syntax, OIDC `nonce`, RFC 8707 resource, issuer and duplicate critical parameters. All findings are collected rather than short-circuiting, so one request can reveal several distinct defects.
3. **Token boundary.** `evaluate_exchange` binds every exchange to the code registry: existence, freshness with skew, single use, client, redirect URI, S256 verifier (constant-time), resource, scope, issuer plus DPoP proof validity and `jti` single use.
4. **State boundary.** `run_cases` folds an ordered sequence: a code becomes redeemed only after a clean `ALLOW`, and a valid DPoP `jti` is recorded immediately. This makes replay detection observable in a single offline run without a database or network service.
5. **Output boundary.** `sarif.py` emits rule metadata and fingerprints; raw authorization codes are never emitted — replay evidence uses `fingerprint(code.code)` only.

## Rule taxonomy

- `ACG-001…013`: authorization request and redirect/PKCE/audience hardening.
- `ACG-020…028`: authorization-code exchange bindings.
- `ACG-029…031`: DPoP presence, cryptographic validity, proof replay.
- `ACG-032`: issuer binding across code and token request.

## Security and correctness properties

- **Fail closed:** unknown fields, malformed JWS, non-canonical base64url, unsupported algorithms and embedded private JWK members are denied.
- **Constant time:** client, redirect, resource, issuer and PKCE digest comparisons use `hmac.compare_digest` on UTF-8/ASCII bytes.
- **Deterministic:** the adversarial corpus derives its Ed25519 key from a fixed SHA-256 seed; Ed25519 signatures are deterministic, so repeated `tribunal` runs produce the same fingerprint.
- **Offline:** no HTTP client, no socket, no service, no LLM. The only external dependency is the `cryptography` primitive library.
- **Auditable:** SARIF findings include rule metadata, severity, evidence, flow, verdict and a stable partial fingerprint.

## Extension points

New provider profiles can be added by extending `Policy` with strict optional fields and a corresponding rule in `RULE_CATALOG`; new attack classes are added as `Case` objects in `corpus.py` with expected verdict and rule. Every new rule must have at least one corpus case and one unit test before release.

Baysöz Labs <baysozlabs@proton.me>
