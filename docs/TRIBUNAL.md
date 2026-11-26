# Supreme Grand Jury Tribunal — Baysöz Labs <baysozlabs@proton.me>

Convened: 2026-11-26
Subject: `baysoz-authcodegate` 1.0.0
Presiding engineer: Baysöz Labs <baysozlabs@proton.me>

## Mandate

After all pytest, ruff and semgrep gates returned zero findings, the Tribunal executed the **built CLI and library** against real adversarial inputs: captured-style authorization requests, token exchanges, stateful code replay, PKCE downgrades, redirect confusion, issuer mix-up, resource substitution, parameter pollution, and real Ed25519/ES256 DPoP proofs including forged signatures, `alg=none`, `kid` confusion, wrong endpoint/nonce, stale `iat` and reused `jti`. No mocks, no network services, no local LLMs.

## Live evidence — selftest

```text
$ uv run python -m baysoz_authcodegate selftest
[PASS] token/dpop-wrong-nonce expected=deny observed=deny rule=ACG-030
[PASS] token/dpop-stale expected=deny observed=deny rule=ACG-030
[PASS] token/dpop-jti-replay expected=deny observed=deny rule=ACG-031
SELFTEST: 44/44 adversarial cases concur — Baysöz Labs <baysozlabs@proton.me>
```

## Live evidence — Tribunal

```text
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

## Live evidence — clean and adversarial audit

```text
$ uv run python -m baysoz_authcodegate audit --input /tmp/opencode/clean-bundle.json --sarif /tmp/opencode/clean.sarif.json
baysoz-authcodegate 1.0.0 — Baysöz Labs <baysozlabs@proton.me>
AUDIT issuer=https://auth.example.com evaluated=4 allowed=4 denied=0 findings=0
SARIF written to /tmp/opencode/clean.sarif.json
STATUS: PASS — Baysöz Labs <baysozlabs@proton.me>

$ uv run python -m baysoz_authcodegate audit --input /tmp/opencode/adversarial-bundle.json --sarif /tmp/opencode/adversarial.sarif.json
baysoz-authcodegate 1.0.0 — Baysöz Labs <baysozlabs@proton.me>
AUDIT issuer=https://auth.example.com evaluated=44 allowed=4 denied=40 findings=61
...
STATUS: FAIL — Baysöz Labs <baysozlabs@proton.me>
```

The adversarial SARIF contains 61 findings with rule IDs, severity, evidence, flow, verdict and SHA-256 fingerprints. The clean SARIF contains zero results. Both outcomes are the intended behaviour, proving the gate distinguishes secure from exploitable flows.

## Hallucination and stub verification

- Every expected rule ID is emitted by an executable check in `oracle.py` or `dpop.py`; the test suite asserts full catalogue coverage of `ACG-001` through `ACG-032`.
- DPoP proofs are produced by real Ed25519 signatures over canonical JSON; `tests/test_oracle.py` additionally verifies a randomly generated ES256 proof and its tamper/replay rejection.
- PKCE correctness is validated against the RFC 7636 published S256 vector, not a self-generated expectation.
- `tests/test_no_stubs.py` scans all source modules for `TODO`, `FIXME`, `NotImplementedError`, bare `pass` and bare `...`, and verifies attribution in all public files.
- The Determinism Juror runs the entire corpus twice and compares a SHA-256 fingerprint of all observed verdicts and rule IDs.

## Verdict

**UNANIMOUS PASS.** All six jurors concur. Release authorised by Baysöz Labs <baysozlabs@proton.me>.

Baysöz Labs <baysozlabs@proton.me>
