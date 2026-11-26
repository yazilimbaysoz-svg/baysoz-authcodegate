# Baysöz Labs <baysozlabs@proton.me> — baysoz-authcodegate
"""SARIF 2.1.0 emission for authorization-code findings by Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .crypto import fingerprint
from .model import Evaluation, Verdict
from .rules import RULE_CATALOG
from .version import PROJECT, REPOSITORY, VENDOR, VERSION


def build_sarif(
    evaluations: Sequence[Evaluation],
    *,
    source_name: str = "audit-bundle",
) -> dict[str, object]:
    results: list[dict[str, object]] = []
    for evaluation in evaluations:
        for finding in evaluation.findings:
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": evaluation.label},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"fullyQualifiedLogicalName": evaluation.label}],
            }
            results.append(
                {
                    "ruleId": finding.rule_id,
                    "level": "error" if finding.severity.value in {"critical", "high"} else "warning",
                    "message": {
                        "text": finding.message,
                        "properties": {"evidence": dict(finding.evidence)},
                    },
                    "locations": [location],
                    "partialFingerprints": {"baysozFinding": fingerprint(finding.to_dict())},
                    "properties": {
                        "flow": evaluation.flow,
                        "verdict": evaluation.verdict.value,
                        "vendor": VENDOR,
                    },
                }
            )
    allowed = sum(1 for item in evaluations if item.verdict is Verdict.ALLOW)
    denied = len(evaluations) - allowed
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": PROJECT,
                        "version": VERSION,
                        "organization": VENDOR,
                        "informationUri": REPOSITORY,
                        "rules": [rule.to_dict() for rule in RULE_CATALOG.values()],
                        "properties": {"vendor": VENDOR, "attribution": VENDOR},
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": f"{PROJECT} {source_name}",
                        "properties": {"vendor": VENDOR},
                    }
                ],
                "results": results,
                "properties": {
                    "vendor": VENDOR,
                    "attribution": VENDOR,
                    "evaluated": len(evaluations),
                    "allowed": allowed,
                    "denied": denied,
                    "findings": len(results),
                },
            }
        ],
    }


def summarize(evaluations: Sequence[Evaluation]) -> Mapping[str, int]:
    return {
        "evaluated": len(evaluations),
        "allowed": sum(1 for item in evaluations if item.verdict is Verdict.ALLOW),
        "denied": sum(1 for item in evaluations if item.verdict is Verdict.DENY),
        "findings": sum(len(item.findings) for item in evaluations),
    }
