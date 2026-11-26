# Baysöz Labs <baysozlabs@proton.me> — baysoz-authcodegate
"""RFC 9449 DPoP proof verification at the token endpoint by Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from .crypto import b64url_decode, b64url_encode, canonical_json
from .model import Policy

_REQUIRED_PAYLOAD_KEYS = frozenset({"htm", "htu", "iat", "jti"})


def _decode_segment(segment: str) -> Any:
    return json.loads(b64url_decode(segment).decode("utf-8"))


def _public_key_from_jwk(header: dict[str, Any], alg: str) -> object:
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise ValueError("missing embedded JWK")
    if "d" in jwk:
        raise ValueError("private key material in JWK")
    if jwk.get("use") not in (None, "sig"):
        raise ValueError("JWK use is not sig")
    if jwk.get("key_ops") not in (None, ["verify"]):
        raise ValueError("JWK key_ops is not verify")
    if alg == "EdDSA":
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            raise ValueError("EdDSA requires an OKP Ed25519 JWK")
        raw = b64url_decode(_jwk_string(jwk, "x"))
        if len(raw) != 32:
            raise ValueError("Ed25519 key must be 32 bytes")
        return Ed25519PublicKey.from_public_bytes(raw)
    if alg == "ES256":
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            raise ValueError("ES256 requires an EC P-256 JWK")
        x_raw = b64url_decode(_jwk_string(jwk, "x"))
        y_raw = b64url_decode(_jwk_string(jwk, "y"))
        if len(x_raw) != 32 or len(y_raw) != 32:
            raise ValueError("P-256 coordinates must be 32 bytes")
        numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x_raw, "big"), int.from_bytes(y_raw, "big"), ec.SECP256R1()
        )
        return numbers.public_key()
    raise ValueError("algorithm is not allowed")


def _jwk_string(jwk: dict[str, Any], key: str) -> str:
    value = jwk.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing JWK member {key}")
    return value


def _verify_signature(public_key: object, alg: str, signature: bytes, signing_input: bytes) -> None:
    if alg == "EdDSA":
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("key type mismatch")
        public_key.verify(signature, signing_input)
        return
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or len(signature) != 64:
        raise ValueError("key type or signature length mismatch")
    r_value = int.from_bytes(signature[:32], "big")
    s_value = int.from_bytes(signature[32:], "big")
    public_key.verify(encode_dss_signature(r_value, s_value), signing_input, ec.ECDSA(hashes.SHA256()))


def verify_proof(
    proof: str,
    policy: Policy,
    htm: str,
    htu: str,
    now: int,
    used_jtis: frozenset[str],
) -> tuple[bool, str, str | None]:
    parts = proof.split(".")
    if len(parts) != 3:
        return False, "malformed-jws", None
    try:
        header = _decode_segment(parts[0])
        payload = _decode_segment(parts[1])
        signature = b64url_decode(parts[2])
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, TypeError):
        return False, "malformed-jws", None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return False, "malformed-jws", None
    if header.get("typ") != "dpop+jwt":
        return False, "wrong-typ", None
    if "crit" in header:
        return False, "unsupported-critical-header", None
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in policy.dpop_allowed_algs:
        return False, "algorithm-not-allowed", None
    try:
        public_key = _public_key_from_jwk(header, alg)
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        _verify_signature(public_key, alg, signature, signing_input)
    except (ValueError, InvalidSignature, TypeError):
        return False, "invalid-signature", None
    if not _REQUIRED_PAYLOAD_KEYS.issubset(payload):
        return False, "missing-proof-claim", None
    if payload["htm"] != htm or payload["htu"] != htu:
        return False, "endpoint-or-method-mismatch", None
    issued_at = payload["iat"]
    if isinstance(issued_at, bool) or not isinstance(issued_at, int):
        return False, "invalid-iat", None
    if abs(now - issued_at) > policy.clock_skew_seconds:
        return False, "stale-proof", None
    jti = payload["jti"]
    if not isinstance(jti, str) or len(jti) < 8:
        return False, "invalid-jti", None
    if policy.dpop_nonce is not None and payload.get("nonce") != policy.dpop_nonce:
        return False, "nonce-mismatch", None
    if jti in used_jtis:
        return False, "jti-replay", jti
    return True, "valid", jti


def ed25519_public_jwk(private_key: Ed25519PrivateKey) -> dict[str, str]:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(raw), "alg": "EdDSA"}


def make_ed25519_proof(
    private_key: Ed25519PrivateKey,
    htm: str,
    htu: str,
    issued_at: int,
    jti: str,
    nonce: str | None = None,
) -> str:
    header = {"typ": "dpop+jwt", "alg": "EdDSA", "jwk": ed25519_public_jwk(private_key)}
    payload: dict[str, str | int] = {"htm": htm, "htu": htu, "iat": issued_at, "jti": jti}
    if nonce is not None:
        payload["nonce"] = nonce
    encoded_header = b64url_encode(canonical_json(header).encode("utf-8"))
    encoded_payload = b64url_encode(canonical_json(payload).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}"
    signature = private_key.sign(signing_input.encode("ascii"))
    return f"{signing_input}.{b64url_encode(signature)}"


def sign_es256_proof(private_key: ec.EllipticCurvePrivateKey, header: dict[str, Any], payload: dict[str, Any]) -> str:
    encoded_header = b64url_encode(canonical_json(header).encode("utf-8"))
    encoded_payload = b64url_encode(canonical_json(payload).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}"
    der_signature = private_key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r_value, s_value = decode_dss_signature(der_signature)
    raw_signature = r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")
    return f"{signing_input}.{b64url_encode(raw_signature)}"
