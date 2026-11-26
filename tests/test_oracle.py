# Baysöz Labs <baysozlabs@proton.me> — baysoz-authcodegate
"""Adversarial oracle tests by Baysöz Labs <baysozlabs@proton.me>."""

import hashlib

from cryptography.hazmat.primitives.asymmetric import ec

from baysoz_authcodegate.corpus import ENDPOINT_URI, make_corpus, run_corpus
from baysoz_authcodegate.crypto import b64url_encode
from baysoz_authcodegate.dpop import sign_es256_proof, verify_proof
from baysoz_authcodegate.model import Verdict
from baysoz_authcodegate.oracle import audit_bundle
from baysoz_authcodegate.rules import RULE_CATALOG


def test_every_adversarial_case_concurs(corpus):
    results = run_corpus(corpus)
    assert len(results) >= 40
    failures = [result.case.label for result in results if not result.passed]
    assert failures == []
    assert all(result.evaluation.verdict is result.case.expected_verdict for result in results)


def test_expected_rules_are_emitted_by_real_checks(corpus):
    results = run_corpus(corpus)
    covered = {
        result.case.expected_rule
        for result in results
        if result.case.expected_rule is not None
    }
    assert covered == set(RULE_CATALOG)
    for result in results:
        if result.case.expected_rule is not None:
            assert result.case.expected_rule in {
                finding.rule_id for finding in result.evaluation.findings
            }


def test_clean_bundle_has_zero_findings(clean_bundle):
    evaluations = audit_bundle(clean_bundle)
    assert evaluations
    assert all(item.verdict is Verdict.ALLOW for item in evaluations)
    assert all(not item.findings for item in evaluations)


def test_stateful_replay_detection_in_bundle_audit(bundle):
    evaluations = {item.label: item for item in audit_bundle(bundle)}
    baseline = evaluations["token/baseline"]
    replay = evaluations["token/code-replay"]
    assert baseline.verdict is Verdict.ALLOW
    assert replay.verdict is Verdict.DENY
    assert "ACG-023" in {finding.rule_id for finding in replay.findings}


def test_es256_dpop_proof_verifies_and_tampering_fails(bundle):
    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(numbers.x.to_bytes(32, "big")),
        "y": b64url_encode(numbers.y.to_bytes(32, "big")),
    }
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
    payload = {
        "htm": "POST",
        "htu": ENDPOINT_URI,
        "iat": bundle.policy.now,
        "jti": "jti-es256-test-0001",
        "nonce": bundle.policy.dpop_nonce,
    }
    proof = sign_es256_proof(private_key, header, payload)
    valid, reason, jti = verify_proof(
        proof, bundle.policy, "POST", ENDPOINT_URI, bundle.policy.now, frozenset()
    )
    assert valid and reason == "valid" and jti == payload["jti"]
    replayed, replay_reason, _ = verify_proof(
        proof, bundle.policy, "POST", ENDPOINT_URI, bundle.policy.now, frozenset({payload["jti"]})
    )
    assert not replayed and replay_reason == "jti-replay"
    tampered = proof[:-2] + ("AA" if proof[-2:] != "AA" else "BB")
    tampered_valid, tampered_reason, _ = verify_proof(
        tampered, bundle.policy, "POST", ENDPOINT_URI, bundle.policy.now, frozenset()
    )
    assert not tampered_valid
    assert tampered_reason in {"malformed-jws", "invalid-signature"}


def test_ed25519_seed_is_deterministic():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = hashlib.sha256(
        "Baysöz Labs baysozlabs@proton.me authcodegate DPoP seed".encode("utf-8")
    ).digest()
    derived = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    corpus_key = make_corpus().private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert derived == corpus_key
