# Baysöz Labs <baysozlabs@proton.me> — baysoz-authcodegate
"""Cryptographic primitive tests by Baysöz Labs <baysozlabs@proton.me>."""

import pytest

from baysoz_authcodegate.crypto import (
    b64url_decode,
    b64url_encode,
    canonical_json,
    fingerprint,
    is_pkce_challenge,
    is_pkce_verifier,
    pkce_s256,
)

VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_rfc7636_s256_vector():
    assert pkce_s256(VERIFIER) == CHALLENGE


def test_pkce_syntax_gates():
    assert is_pkce_verifier(VERIFIER)
    assert is_pkce_challenge(CHALLENGE)
    assert not is_pkce_verifier("short")
    assert not is_pkce_challenge("abc!!!")
    assert not is_pkce_challenge(None)


def test_base64url_roundtrip_and_canonicality():
    raw = b"\x00\xff\x10\x80\x7f"
    assert b64url_decode(b64url_encode(raw)) == raw
    with pytest.raises(ValueError, match="non-canonical"):
        b64url_decode("abc=")
    with pytest.raises(ValueError, match="non-canonical"):
        b64url_decode("ab!c")


def test_canonical_json_and_fingerprint_are_stable():
    first = {"b": 2, "a": [1, {"d": 4, "c": 3}]}
    second = {"a": [1, {"c": 3, "d": 4}], "b": 2}
    assert canonical_json(first) == canonical_json(second)
    assert fingerprint(first) == fingerprint(second)
    assert len(fingerprint(first)) == 64
