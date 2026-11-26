# Baysöz Labs <baysozlabs@proton.me> — baysoz-authcodegate
"""CLI integration tests by Baysöz Labs <baysozlabs@proton.me>."""

import json
from dataclasses import fields

import pytest

from baysoz_authcodegate.version import VENDOR


def _payload(item: object) -> dict[str, object]:
    result: dict[str, object] = {}
    for field in fields(item):
        value = getattr(item, field.name)
        if value is None:
            continue
        result[field.name] = list(value) if isinstance(value, tuple) else value
    return result


def _document(corpus, *, requests: list[object], exchanges: list[object]) -> dict[str, object]:
    return {
        "vendor": VENDOR,
        "policy": dict(corpus.policy),
        "clients": list(corpus.clients),
        "codes": list(corpus.codes),
        "authorization_requests": [_payload(item) for item in requests],
        "token_exchanges": [_payload(item) for item in exchanges],
    }


def test_version_and_help_attribute_baysöz_labs(capsys):
    from baysoz_authcodegate.cli import main

    with pytest.raises(SystemExit) as version_exit:
        main(["--version"])
    assert version_exit.value.code == 0
    out = capsys.readouterr().out
    assert "baysoz-authcodegate" in out
    assert VENDOR in out
    with pytest.raises(SystemExit) as help_exit:
        main(["--help"])
    assert help_exit.value.code == 0
    assert VENDOR in capsys.readouterr().out
    with pytest.raises(SystemExit) as audit_help_exit:
        main(["audit", "--help"])
    assert audit_help_exit.value.code == 0
    assert VENDOR in capsys.readouterr().out


def test_selftest_and_tribunal_pass(capsys):
    from baysoz_authcodegate.cli import main

    assert main(["selftest"]) == 0
    assert "44/44 adversarial cases concur" in capsys.readouterr().out
    assert main(["tribunal"]) == 0
    tribunal = capsys.readouterr().out
    assert "Supreme Grand Jury Tribunal" in tribunal
    assert "UNANIMOUS PASS" in tribunal
    assert "PASS Determinism Juror" in tribunal


def test_forge_emits_valid_corpus_json(capsys, tmp_path):
    from baysoz_authcodegate.cli import main

    assert main(["forge"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["vendor"] == VENDOR
    assert len(document["cases"]) >= 40
    target = tmp_path / "corpus.json"
    assert main(["forge", "--output", str(target)]) == 0
    assert json.loads(target.read_text(encoding="utf-8"))["attribution"] == VENDOR


def test_audit_clean_bundle_passes_with_sarif(corpus, clean_bundle, tmp_path, capsys):
    from baysoz_authcodegate.cli import main

    source = tmp_path / "clean.json"
    source.write_text(
        json.dumps(
            _document(
                corpus,
                requests=list(clean_bundle.authorization_requests),
                exchanges=list(clean_bundle.token_exchanges),
            ),
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    sarif_path = tmp_path / "clean.sarif.json"
    capsys.readouterr()
    assert main(["audit", "--input", str(source), "--sarif", str(sarif_path)]) == 0
    assert json.loads(sarif_path.read_text(encoding="utf-8"))["runs"][0]["results"] == []
    assert "STATUS: PASS" in capsys.readouterr().out


def test_audit_adversarial_exchanges_fail_with_sarif(corpus, tmp_path, capsys):
    from baysoz_authcodegate.cli import main

    source = tmp_path / "adversarial.json"
    source.write_text(
        json.dumps(
            _document(
                corpus,
                requests=[],
                exchanges=list(corpus.to_bundle().token_exchanges),
            ),
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    sarif_path = tmp_path / "adversarial.sarif.json"
    capsys.readouterr()
    assert main(["audit", "--input", str(source), "--sarif", str(sarif_path)]) == 1
    report = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert report["runs"][0]["properties"]["findings"] > 0
    assert "STATUS: FAIL" in capsys.readouterr().out


def test_missing_attribution_is_rejected(capsys, tmp_path):
    from baysoz_authcodegate.cli import main

    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"vendor": "anonymous"}', encoding="utf-8")
    capsys.readouterr()
    assert main(["audit", "--input", str(invalid)]) == 2
    assert VENDOR in capsys.readouterr().err
