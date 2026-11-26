# Baysöz Labs <baysozlabs@proton.me> — baysoz-authcodegate
"""Shared fixtures for the Baysöz Labs <baysozlabs@proton.me> authorization-code oracle tests."""

import pytest

from baysoz_authcodegate.corpus import make_corpus


@pytest.fixture(scope="module")
def corpus():
    return make_corpus()


@pytest.fixture(scope="module")
def bundle(corpus):
    return corpus.to_bundle()


@pytest.fixture(scope="module")
def clean_bundle(corpus):
    return corpus.to_bundle(clean_only=True)
