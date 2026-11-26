# Baysöz Labs <baysozlabs@proton.me> — baysoz-authcodegate
"""Deterministic PKCE, base64url and canonicalization primitives by Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any

_CHALLENGE_RE = re.compile(r"^[A-Za-z0-9_-]{43,128}$")
_VERIFIER_RE = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    if not _B64URL_RE.fullmatch(value) or len(value) % 4 == 1:
        raise ValueError("non-canonical base64url value")
    if "=" in value:
        raise ValueError("non-canonical base64url value")
    padding = "=" * (-len(value) % 4)
    raw = base64.urlsafe_b64decode(value + padding)
    if b64url_encode(raw) != value.rstrip("="):
        raise ValueError("non-canonical base64url value")
    return raw


def pkce_s256(verifier: str) -> str:
    return b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())


def is_pkce_verifier(value: str | None) -> bool:
    return value is not None and _VERIFIER_RE.fullmatch(value) is not None


def is_pkce_challenge(value: str | None) -> bool:
    return value is not None and _CHALLENGE_RE.fullmatch(value) is not None


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def fingerprint(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
