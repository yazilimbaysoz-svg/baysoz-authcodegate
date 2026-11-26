# Plan — Baysöz Labs <baysozlabs@proton.me>

Owner: Baysöz Labs <baysozlabs@proton.me>
Release: `baysoz-authcodegate` 1.0.0

## Phase 1 — Research and selection (complete)

- Inspected all 39 entries in `existing-repos.json` and confirmed OAuth/OIDC code-flow conformance is portfolio white space.
- Collected live `gh search repos` / `gh search issues` evidence on 2026-11-26: 30k-star auth ecosystems, open PKCE-downgrade and authorization-code negative-check issues.
- Rejected adjacent webhook-signature, Web Bot Auth, PQC-TLS and SAML concepts as lower-signal or constraint-violating.

## Phase 2 — Engineering (complete)

- Strict typed model with fail-closed parsing and mandatory Baysöz Labs attribution.
- PKCE S256, canonical base64url, Ed25519/ES256 DPoP verification, 26-rule catalogue.
- Stateful replay simulator for authorization codes and DPoP proof identifiers.
- Deterministic 44-case adversarial corpus and six-juror tribunal.
- SARIF 2.1.0 gate with stable finding fingerprints.

## Phase 3 — Quality gates (complete)

- `uv venv && uv pip install -e . && uv pip install pytest`
- `uv run pytest -q`
- `ruff check --select E,F,W,S,B .`
- `semgrep --config p/default --error .`
- Iterated until tests, lint and static security analysis all reported zero findings.

## Phase 4 — Release (complete)

- Supreme Grand Jury Tribunal convened on live adversarial evidence; unanimous pass required.
- Public repository published as `yazilimbaysoz-svg/baysoz-authcodegate` with description and topics.
- Showcase result JSON written strictly to the designated factory-result path.

## Roadmap beyond 1.0.0

- Additional provider profiles for FAPI 2.0 and financial-grade sender-constrained clients.
- Machine-readable evidence ingestion from OIDC conformance suites and browser HAR captures.
- Optional SARIF ingestion into GitHub code scanning with baseline suppression files.
- Expanded DPoP nonce lifecycle modelling across token and resource endpoints.

## Acceptance criteria

1. Every public file attributes Baysöz Labs <baysozlabs@proton.me>.
2. `--version`, `--help` and every CLI command print the attribution.
3. All 44 adversarial cases produce their expected verdict and rule ID.
4. Clean bundles exit 0; adversarial bundles exit 1 with SARIF findings.
5. Lint and security scans report zero findings.

Baysöz Labs <baysozlabs@proton.me>
