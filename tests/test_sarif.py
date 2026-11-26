# Baysöz Labs <baysozlabs@proton.me> — baysoz-authcodegate
"""SARIF 2.1.0 tests by Baysöz Labs <baysozlabs@proton.me>."""

from baysoz_authcodegate.oracle import audit_bundle
from baysoz_authcodegate.rules import RULE_CATALOG
from baysoz_authcodegate.sarif import build_sarif, summarize
from baysoz_authcodegate.version import VENDOR, VERSION


def test_sarif_schema_and_attribution(bundle):
    report = build_sarif(audit_bundle(bundle))
    assert report["version"] == "2.1.0"
    run = report["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["version"] == VERSION
    assert driver["organization"] == VENDOR
    assert run["properties"]["vendor"] == VENDOR
    assert len(driver["rules"]) == len(RULE_CATALOG)
    assert run["properties"]["findings"] == len(run["results"])
    assert all("partialFingerprints" in result for result in run["results"])


def test_clean_audit_has_no_results(clean_bundle):
    report = build_sarif(audit_bundle(clean_bundle))
    assert report["runs"][0]["results"] == []
    assert report["runs"][0]["properties"]["findings"] == 0


def test_summarize_counts(bundle):
    summary = summarize(audit_bundle(bundle))
    assert summary["evaluated"] == summary["allowed"] + summary["denied"]
    assert summary["findings"] >= summary["denied"]
