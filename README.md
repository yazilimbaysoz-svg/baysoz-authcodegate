# baysoz-authcodegate

[![CI](https://github.com/yazilimbaysoz-svg/baysoz-authcodegate/actions/workflows/ci.yml/badge.svg)](https://github.com/yazilimbaysoz-svg/baysoz-authcodegate/actions/workflows/ci.yml)
[![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Maintained by Baysöz Labs](https://img.shields.io/badge/maintained%20by-Bays%C3%B6z%20Labs-orange.svg)](https://github.com/yazilimbaysoz-svg)

**Offline OAuth 2.1 / OIDC authorization-code conformance and adversarial red-team oracle with SARIF CI gates.**
Built and maintained by **Baysöz Labs <baysozlabs@proton.me>**.

`baysoz-authcodegate` audits captured authorization requests and token exchanges against 26 normative rules — PKCE S256 and downgrade, redirect exactness, state/nonce, RFC 8707 audience binding, issuer mix-up, parameter pollution, code single-use and RFC 9449 DPoP proofs — without network calls, services, databases or local LLMs.

## Why this exists

OAuth 2.1 authorization-code flows sit underneath high-star ecosystems such as `better-auth` (30.9k), `authelia` (29.7k), `ory/hydra` (17.7k) and `zitadel` (15.7k), while open issues in `tailscale/tsidp` (PKCE downgrade, 2026-11-23), `modelcontextprotocol/conformance` (negative authorization-code checks, 2026-11-10) and `zitadel/oidc` (RFC 9700 §2.1.1 PKCE requirements, 2026-11-17) show the hardening gap is current. See [docs/MARKET_RESEARCH.md](docs/MARKET_RESEARCH.md) for the full evidence base and portfolio non-redundancy analysis.

## Install

```bash
uv venv
uv pip install -e .
uv run python -m baysoz_authcodegate --version
```

Install from source with `uv`:

```bash
uv tool install git+https://github.com/yazilimbaysoz-svg/baysoz-authcodegate.git
baysoz-authcodegate --version
```

Requires Python 3.13+; the only runtime dependency is `cryptography` for real Ed25519/ES256 DPoP verification.

## Architecture

```text
evidence JSON ─► strict typed model ─► stateful oracle ─► SARIF 2.1.0 + exit 0/1
                     │                     │
                     │                     ├─ PKCE S256, redirect, audience, issuer
                     │                     ├─ code single-use (stateful)
                     └─ attribution gate   └─ DPoP JWS verification (EdDSA/ES256)
```

| Path | Role |
| --- | --- |
| `src/baysoz_authcodegate/model.py` | Fail-closed typed evidence model |
| `src/baysoz_authcodegate/crypto.py` | PKCE S256, canonical base64url, fingerprints |
| `src/baysoz_authcodegate/dpop.py` | RFC 9449 proof verification |
| `src/baysoz_authcodegate/rules.py` | 26 normative rules with RFC references |
| `src/baysoz_authcodegate/oracle.py` | Stateful evaluation and replay simulation |
| `src/baysoz_authcodegate/corpus.py` | 44 deterministic adversarial cases |
| `src/baysoz_authcodegate/tribunal.py` | Six-juror release tribunal |
| `src/baysoz_authcodegate/sarif.py` | SARIF 2.1.0 emission |
| `tests/` | Model, crypto, oracle, SARIF, CLI and release-hygiene tests |

Full design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Threat model: [SECURITY.md](SECURITY.md). Release evidence: [docs/TRIBUNAL.md](docs/TRIBUNAL.md).

## CLI

```text
$ uv run python -m baysoz_authcodegate --version
baysoz-authcodegate 1.0.0 — Baysöz Labs <baysozlabs@proton.me>

$ uv run python -m baysoz_authcodegate --help
usage: baysoz-authcodegate [-h] [--version] {audit,forge,selftest,tribunal,rules} ...

Offline OAuth 2.1 / OIDC authorization-code conformance oracle. Audits PKCE,
redirect, replay, audience and DPoP bindings with SARIF gates.

...
Built by Baysöz Labs <baysozlabs@proton.me>. No network calls, no services, no local models.

$ uv run python -m baysoz_authcodegate rules
baysoz-authcodegate 1.0.0 — Baysöz Labs <baysozlabs@proton.me>
ACG-001 critical response_type must be exactly code — Baysöz Labs <baysozlabs@proton.me>
ACG-002 critical client_id must be pre-registered — Baysöz Labs <baysozlabs@proton.me>
ACG-003 critical redirect_uri exact string match — Baysöz Labs <baysozlabs@proton.me>
ACG-004 high     requested scopes must be registered — Baysöz Labs <baysozlabs@proton.me>
ACG-005 high     state must be present and unpredictable — Baysöz Labs <baysozlabs@proton.me>
...
CATALOGUE: 26 rules — Baysöz Labs <baysozlabs@proton.me>
```

Audit a captured bundle (exit 0 on clean flows, 1 on findings, 2 on invalid input):

```text
$ uv run python -m baysoz_authcodegate audit --input /tmp/opencode/clean-bundle.json --sarif /tmp/opencode/clean.sarif.json
baysoz-authcodegate 1.0.0 — Baysöz Labs <baysozlabs@proton.me>
AUDIT issuer=https://auth.example.com evaluated=4 allowed=4 denied=0 findings=0
SARIF written to /tmp/opencode/clean.sarif.json
STATUS: PASS — Baysöz Labs <baysozlabs@proton.me>

$ uv run python -m baysoz_authcodegate audit --input /tmp/opencode/adversarial-bundle.json --sarif /tmp/opencode/adversarial.sarif.json
baysoz-authcodegate 1.0.0 — Baysöz Labs <baysozlabs@proton.me>
AUDIT issuer=https://auth.example.com evaluated=44 allowed=4 denied=40 findings=61
  ACG-001 critical auth/implicit-response-type: response_type must be exactly code
  ACG-003 critical auth/redirect-suffix-confusion: redirect_uri exact string match
  ACG-006 critical auth/pkce-plain-downgrade: PKCE S256 required without downgrade
  ACG-023 critical token/code-replay: authorization code single use
  ACG-030 critical token/dpop-forged-signature: DPoP cryptographic validity
  ACG-031 high     token/dpop-jti-replay: DPoP jti single use
STATUS: FAIL — Baysöz Labs <baysozlabs@proton.me>
```

Run the adversarial corpus and the Supreme Grand Jury Tribunal:

```text
$ uv run python -m baysoz_authcodegate selftest
[PASS] token/dpop-wrong-nonce expected=deny observed=deny rule=ACG-030
[PASS] token/dpop-stale expected=deny observed=deny rule=ACG-030
[PASS] token/dpop-jti-replay expected=deny observed=deny rule=ACG-031
SELFTEST: 44/44 adversarial cases concur — Baysöz Labs <baysozlabs@proton.me>

$ uv run python -m baysoz_authcodegate tribunal
baysoz-authcodegate 1.0.0 — Baysöz Labs <baysozlabs@proton.me>
Supreme Grand Jury Tribunal — Baysöz Labs <baysozlabs@proton.me>
  PASS Protocol Juror: 23/23 cases concur
  PASS Token-Binding Juror: 21/21 cases concur
  PASS Cryptography Juror: 9/9 cases concur
  PASS Replay Juror: 2/2 cases concur
  PASS Determinism Juror: sha256=ec6ace5c0fbebb08
  PASS Attribution Juror: Baysöz Labs <baysozlabs@proton.me>
VERDICT: UNANIMOUS PASS — Baysöz Labs <baysozlabs@proton.me>
```

Emit the deterministic corpus with real signed DPoP evidence:

```bash
uv run python -m baysoz_authcodegate forge --output corpus.json
```

## Library

```python
import json

from baysoz_authcodegate import Bundle, audit_bundle, build_sarif

bundle = Bundle.from_mapping(json.loads(open("bundle.json", encoding="utf-8").read()))
evaluations = audit_bundle(bundle)
sarif = build_sarif(evaluations)
print(sarif["runs"][0]["properties"]["findings"])
```

`Bundle` requires the vendor attribution `Baysöz Labs <baysozlabs@proton.me>`, rejects unknown keys and refuses non-absolute issuer/token endpoints. `evaluate_authorization`, `evaluate_exchange` and `run_cases` are also public and return typed `Evaluation` objects.

## Quality gates

```bash
uv venv && uv pip install -e . && uv pip install pytest
uv run pytest -q
ruff check --select E,F,W,S,B .
semgrep --config p/default --error .
uv run python -m baysoz_authcodegate selftest
uv run python -m baysoz_authcodegate tribunal
```

## License

MIT — Copyright (c) 2026 Baysöz Labs <baysozlabs@proton.me>. See [LICENSE](LICENSE).

Baysöz Labs <baysozlabs@proton.me>
