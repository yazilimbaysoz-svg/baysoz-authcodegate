# Baysöz Labs <baysozlabs@proton.me> — baysoz-authcodegate
"""Strict input model tests by Baysöz Labs <baysozlabs@proton.me>."""

import copy

import pytest

from baysoz_authcodegate.model import Bundle, Client, Policy
from baysoz_authcodegate.version import VENDOR


def test_vendor_attribution_is_mandatory(corpus):
    document = corpus.to_document()
    bundle_data = {
        "vendor": "Anonymous",
        "policy": dict(corpus.policy),
        "clients": list(corpus.clients),
        "codes": list(corpus.codes),
        "authorization_requests": [],
        "token_exchanges": [],
    }
    with pytest.raises(ValueError, match="attribution"):
        Bundle.from_mapping(bundle_data)
    bundle_data["vendor"] = VENDOR
    assert Bundle.from_mapping(bundle_data).vendor == VENDOR
    assert document["attribution"] == VENDOR


def test_unknown_keys_are_rejected(corpus):
    client_data = dict(corpus.clients[0])
    client_data["redirect_uris_typo"] = ["https://evil.example.com"]
    with pytest.raises(ValueError, match="unknown keys"):
        Client.from_mapping(client_data)
    policy_data = dict(corpus.policy)
    policy_data["require_pkce_typo"] = False
    with pytest.raises(ValueError, match="unknown keys"):
        Policy.from_mapping(policy_data)


def test_issuer_must_be_an_absolute_uri(corpus):
    policy_data = dict(corpus.policy)
    policy_data["issuer"] = "relative-issuer"
    with pytest.raises(ValueError, match="absolute URI"):
        Policy.from_mapping(policy_data)


def test_bundle_from_corpus_document(corpus):
    document = corpus.to_document()
    bundle = corpus.to_bundle()
    assert bundle.policy.issuer == document["policy"]["issuer"]
    assert len(bundle.clients) == len(document["clients"])
    assert len(bundle.codes) == len(document["codes"])
    assert copy.deepcopy(bundle.policy).now == bundle.policy.now
