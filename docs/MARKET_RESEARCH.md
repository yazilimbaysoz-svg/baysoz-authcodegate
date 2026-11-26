# Market Research — Baysöz Labs <baysozlabs@proton.me>

Author: Baysöz Labs <baysozlabs@proton.me>
Project: `baysoz-authcodegate`
Research date: 2026-11-26

## 1. Method and evidence base

1. Parsed `/home/runner/work/_temp/existing-repos.json` (39 existing Baysöz Labs repositories) and classified their problem domains.
2. Queried live GitHub via `gh search repos` and `gh search issues` on 2026-11-26. Captured counts, star counts and issue dates before the unauthenticated search API rate limit was reached.
3. Mapped ecosystem pain points to a domain that is neither covered by the existing portfolio nor served by a mature high-star offline conformance tool.

## 2. Existing portfolio white-space analysis

The existing portfolio already contains deep offline oracles for eBPF CO-RE relocation (`baysoz-corelattice`), agent skill contracts (`baysoz-skillbound`), SLSA provenance (`baysoz-provenancegate`), Kubernetes CEL/NetworkPolicy/Gateway API/admission/disruption (`baysoz-admissioncel`, `baysoz-netpol-oracle`, `baysoz-routegate`, `baysoz-disruption-oracle`), pprof/promql/Alertmanager/OTel telemetry (`baysoz-profilediff`, `baysoz-queryoracle`, `baysoz-alertpath-oracle`, `baysoz-cardinalis`, `baysoz-otelgate`), HTTP desync and SSRF (`baysoz-desyncforge`, `baysoz-ssrfcanon`), CSP/JOSE/GraphQL/BOLA (`baysoz-cspforge`, `baysoz-josegate`, `baysoz-gqlcostgate`, `bolaforge`), MCP contracts (`baysoz-mcpcontract`) and supply-chain drift (`baysoz-actionlock`, `planradius`, `baysoz-reachoracle`).

**No existing repository audits the OAuth 2.1 / OpenID Connect authorization-code grant itself**: no PKCE downgrade oracle, no redirect-URI exact-match differential check, no authorization-code single-use simulator, no resource-indicator (RFC 8707) audience-binder, no issuer-mix-up detector and no DPoP token-endpoint proof verifier. `baysoz-josegate` covers JOSE/JWT algorithm confusion at the token *format* layer, not the code-flow state machine; `bolaforge` covers object-level authorization, not issuance. A new tool here is complementary, not redundant.

## 3. Live GitHub evidence

### 3.1 High-star ecosystem (`gh search repos`)

| Repository | Stars | Last update (UTC) | Relevance |
| --- | ---: | --- | --- |
| `better-auth/better-auth` | 30,887 | 2026-11-26 | OAuth 2.1 / OIDC auth framework |
| `authelia/authelia` | 29,741 | 2026-11-26 | OIDC provider, post-quantum ready |
| `nextauthjs/next-auth` | 28,389 | 2026-11-25 | De-facto JS OIDC client |
| `goauthentik/authentik` | 26,466 | 2026-11-26 | Identity provider |
| `ory/hydra` | 17,678 | 2026-11-25 | OAuth 2.1 provider |
| `zitadel/zitadel` | 15,653 | 2026-11-26 | OIDC / OAuth 2.1 provider |
| `oauth2-proxy/oauth2-proxy` | 15,408 | 2026-11-25 | Code-flow reverse proxy |
| `thephpleague/oauth2-server` | 6,678 | 2026-11-24 | Server implementation |
| `golang/oauth2` | 5,909 | 2026-11-25 | Client library |
| `oauthjs/node-oauth2-server` | 4,058 | 2026-11-22 | Server implementation |
| `django-oauth/django-oauth-toolkit` | 3,349 | 2026-11-19 | Django authorization server |

This is a mature, actively maintained, very high-star ecosystem where a *portable conformance gate* has leverage: downstream teams cannot easily reason about whether their captured code flows obey RFC 9700 hardening.

### 3.2 Open issues and active pain (`gh search issues`)

| Issue | Repository | Opened | Signal |
| --- | --- | --- | --- |
| Token endpoint accepts a verifier when no challenge existed (PKCE downgrade) | `tailscale/tsidp` | 2026-11-23 | PKCE downgrade is still shipping in new Go IdPs |
| Authorization server negative checks for authorization code grant (PKCE, reuse, client binding, redirect URI, state) | `modelcontextprotocol/conformance` | 2026-11-10 | MCP agent OAuth needs exactly these negative checks |
| `op.Server`: PKCE requirements of RFC 9700 §2.1.1 | `zitadel/oidc` | 2026-11-17 | RFC 9700 hardening is still being interpreted |
| Algorithm validation optional / signature verification bypass | `mpdavis/python-jose` | 2026-10-12 | Adjacent token-verification confusion class |
| Authlib signature-verification bypass advisories | multiple | 2026-11-02 | Token-layer bypasses remain open |
| Webhook replay-protection and dedupe-window issues | multiple | 2026-07 … 2026-11 | Replay semantics are a shared cross-protocol pain point |

`gh search issues 'signature verification bypass'` also surfaced SAML, gRPC, Authlib and webhook HMAC cases; these confirm that *binding and replay* — not merely cryptography — dominate real appsec findings.

### 3.3 Adjacent candidates rejected

- **Webhook signature verification**: dozens of small 0–50 star verification SDKs; fragmented provider logic, no authority, lower novelty for this portfolio (and adjacent to `baysoz-josegate`).
- **Web Bot Auth / RFC 9421**: `cloudflare/web-bot-auth` has 190 stars with several sub-20-star implementations; emerging but narrower than authorization-code issuance and not yet a high-star conformance ecosystem.
- **PQC TLS migration**: high relevance but would require TLS/network services, violating the zero-heavy-services constraint.
- **SAML XML signature wrapping**: mature but declining; already well served by established test suites.

## 4. Product decision

Build `baysoz-authcodegate`: a **deterministic offline OAuth 2.1 / OIDC authorization-code conformance and adversarial red-team oracle** with:

- 26 normative rules across request validation, token exchange, PKCE S256, DPoP (RFC 9449), RFC 8707 resource indicators, redirect exactness, state/nonce entropy, parameter-pollution detection, issuer mix-up and stateful replay detection.
- A 44-case deterministic adversarial corpus with real Ed25519 DPoP signatures and tampered proofs — not mocks and not stubs.
- SARIF 2.1.0 output for CI enforcement, with attribution and stable finding fingerprints.
- Python 3.13+, `uv`, `cryptography`, zero network calls, zero services, zero local LLMs.

This is a deep production CLI/library for appsec-redteam engineers: it accepts captured authorization/token evidence and tells them, with rule IDs and evidence, exactly where a flow is exploitable.

## 5. Standards basis

RFC 6749, RFC 7636 (PKCE), RFC 8252 (native apps), RFC 8707 (resource indicators), RFC 9449 (DPoP), RFC 9700 (OAuth 2.0 Security Best Current Practice), OpenID Connect Core 1.0.

Baysöz Labs <baysozlabs@proton.me>
