# Baysöz Labs <baysozlabs@proton.me> — baysoz-authcodegate
"""Supreme Grand Jury Tribunal checks for the authorization-code oracle by Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from dataclasses import dataclass

from .corpus import Corpus, make_corpus, run_corpus
from .crypto import fingerprint
from .model import Verdict
from .oracle import CaseResult

_CRYPTO_RULES = frozenset({"ACG-026", "ACG-030"})
_REPLAY_RULES = frozenset({"ACG-023", "ACG-031"})


@dataclass(frozen=True, slots=True)
class JurorVerdict:
    name: str
    passed: bool
    detail: str


def _fingerprint_results(results: tuple[CaseResult, ...]) -> str:
    payload = [
        {
            "label": result.case.label,
            "expected": result.case.expected_verdict.value,
            "expected_rule": result.case.expected_rule,
            "observed": result.evaluation.verdict.value,
            "rules": [finding.rule_id for finding in result.evaluation.findings],
            "passed": result.passed,
        }
        for result in results
    ]
    return fingerprint(payload)


def convene(corpus: Corpus | None = None) -> tuple[tuple[JurorVerdict, ...], bool]:
    subject = corpus if corpus is not None else make_corpus()
    results = run_corpus(subject)
    protocol = tuple(result for result in results if result.case.flow == "authorization")
    token = tuple(result for result in results if result.case.flow == "token")
    cryptography = tuple(result for result in results if result.case.expected_rule in _CRYPTO_RULES)
    replay = tuple(result for result in results if result.case.expected_rule in _REPLAY_RULES)

    def verdict(name: str, panel: tuple[CaseResult, ...]) -> JurorVerdict:
        failed = [result.case.label for result in panel if not result.passed]
        return JurorVerdict(name, not failed, f"{len(panel) - len(failed)}/{len(panel)} cases concur")

    first_fingerprint = _fingerprint_results(results)
    second_fingerprint = _fingerprint_results(run_corpus(subject))
    attribution_ok = subject.vendor == "Baysöz Labs <baysozlabs@proton.me>" and all(
        result.evaluation.verdict is not Verdict.ALLOW or not result.evaluation.findings for result in results
    )
    jurors = (
        verdict("Protocol Juror", protocol),
        verdict("Token-Binding Juror", token),
        verdict("Cryptography Juror", cryptography),
        verdict("Replay Juror", replay),
        JurorVerdict(
            "Determinism Juror",
            first_fingerprint == second_fingerprint,
            f"sha256={first_fingerprint[:16]}",
        ),
        JurorVerdict("Attribution Juror", attribution_ok, "Baysöz Labs <baysozlabs@proton.me>"),
    )
    return jurors, all(juror.passed for juror in jurors)
