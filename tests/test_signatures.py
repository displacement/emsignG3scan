"""Tests for signature matching and the watchlist data."""
from __future__ import annotations

import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from emsignG3scan import signatures
from emsignG3scan.signatures import KNOWN_ROOTS, RootWatch, load_reference_cert, match_cert, self_check


G3_SHA256 = "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"
G1_SHA256 = "40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367"
G3_SUBJECT = "CN=emSign ECC Root CA - G3,O=eMudhra Technologies Limited,OU=emSign PKI,C=IN"
G1_SUBJECT = "CN=emSign Root CA - G1,O=eMudhra Technologies Limited,OU=emSign PKI,C=IN"


def _find(label: str) -> RootWatch:
    for r in KNOWN_ROOTS:
        if r.label == label:
            return r
    raise AssertionError(f"no root {label}")


def test_watchlist_contains_both_g3_and_g1():
    labels = {r.label for r in KNOWN_ROOTS}
    assert "emSign ECC Root CA - G3" in labels
    assert "emSign Root CA - G1" in labels


def test_g3_is_flagged_compromised():
    g3 = _find("emSign ECC Root CA - G3")
    assert g3.severity == "compromised"
    assert g3.sha256 == G3_SHA256
    assert g3.subject == G3_SUBJECT


def test_g1_is_flagged_related():
    g1 = _find("emSign Root CA - G1")
    assert g1.severity == "related"
    assert g1.sha256 == G1_SHA256
    assert g1.subject == G1_SUBJECT


def test_self_check_passes():
    # Bundled reference PEMs must reproduce the embedded fingerprints.
    assert self_check() is True


def test_match_by_sha256_g3():
    assert match_cert(sha256=G3_SHA256) is _find("emSign ECC Root CA - G3")


def test_match_by_sha256_g1():
    assert match_cert(sha256=G1_SHA256) is _find("emSign Root CA - G1")


def test_match_by_sha1_g3():
    g3 = _find("emSign ECC Root CA - G3")
    assert match_cert(sha1=g3.sha1) is g3


def test_match_by_serial_and_subject_g3():
    g3 = _find("emSign ECC Root CA - G3")
    assert match_cert(serial=g3.serial, subject=g3.subject) is g3


def test_match_unknown_returns_none():
    assert match_cert(sha256="deadbeef" * 8) is None


def test_reference_pem_fingerprint_matches():
    for label, expected in [
        ("emSign ECC Root CA - G3", G3_SHA256),
        ("emSign Root CA - G1", G1_SHA256),
    ]:
        cert = load_reference_cert(label)
        fp = cert.fingerprint(hashes.SHA256()).hex()
        assert fp == expected, f"{label} fingerprint {fp} != {expected}"


def test_known_roots_is_stable():
    # Sanity: the fingerprints are what we computed from crt.sh.
    assert {r.sha256 for r in KNOWN_ROOTS} == {G3_SHA256, G1_SHA256}
