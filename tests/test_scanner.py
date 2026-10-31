"""Tests for certificate extraction and archive scanning."""
from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

import emsignG3scan.scanner as scanner_mod
from emsignG3scan.scanner import (
    FoundCert,
    detect_format,
    scan_bytes,
    scan_file,
    scan_path,
)
from emsignG3scan.signatures import load_reference_cert


G3_SUBJECT = "CN=emSign ECC Root CA - G3,O=eMudhra Technologies Limited,OU=emSign PKI,C=IN"
G3_SHA256 = "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"


# --------------------------------------------------------------------------- #
# scan_bytes
# --------------------------------------------------------------------------- #

def test_scan_bytes_finds_pem_cert(g3_pem: bytes):
    found = scan_bytes(g3_pem, source="cacert.pem")
    assert len(found) == 1
    cert = found[0]
    assert cert.encoding == "pem"
    assert G3_SUBJECT in cert.subject
    assert cert.sha256 == G3_SHA256
    assert cert.source == "cacert.pem"
    assert cert.watch is None  # scan_bytes does not match


def test_scan_bytes_finds_der_cert(g3_der: bytes):
    found = scan_bytes(g3_der, source="root.der")
    assert len(found) == 1
    cert = found[0]
    assert cert.encoding == "der"
    assert cert.sha256 == G3_SHA256
    assert cert.subject == G3_SUBJECT


def test_scan_bytes_finds_der_embedded_in_binary(g3_der: bytes):
    blob = b"\x00" * 50 + b"padding" + g3_der + b"\xde\xad\xbe\xef" * 3
    found = scan_bytes(blob, source="app.bin")
    assert len(found) == 1
    assert found[0].encoding == "der"
    assert found[0].offset == 57  # 50 + len("padding")
    assert found[0].sha256 == G3_SHA256


def test_scan_bytes_ignores_non_certificate_data():
    found = scan_bytes(b"\x30\x82\x01\x00" + b"garbage" * 100, source="x")
    assert found == []


def test_scan_bytes_finds_two_pem_certs(g3_pem: bytes, healthy_pem: bytes):
    combined = g3_pem + healthy_pem
    found = scan_bytes(combined, source="bundle")
    assert len(found) == 2
    subjects = {f.subject for f in found}
    assert G3_SUBJECT in subjects


def test_scan_bytes_pem_trusted_certificate_block(g3_pem: bytes):
    # OpenSSL "TRUSTED CERTIFICATE" blocks wrap the DER in an extra SEQUENCE;
    # load_pem_x509_certificate still handles them, so they should be found.
    trusted = g3_pem.replace(b"CERTIFICATE", b"TRUSTED CERTIFICATE")
    found = scan_bytes(trusted, source="trusted.pem")
    assert len(found) == 1
    assert found[0].sha256 == G3_SHA256


# --------------------------------------------------------------------------- #
# scan_file / scan_path (with watchlist matching)
# --------------------------------------------------------------------------- #

def test_scan_file_pem_matches_watchlist(pem_file: Path):
    found = scan_file(str(pem_file))
    assert len(found) == 1
    assert found[0].watch is not None
    assert found[0].watch.label == "emSign ECC Root CA - G3"
    assert found[0].watch.severity == "compromised"


def test_scan_file_der_matches_watchlist(der_embedded_file: Path):
    found = scan_file(str(der_embedded_file))
    assert len(found) == 1
    assert found[0].watch is not None
    assert found[0].watch.severity == "compromised"


def test_scan_file_zip_member(pem_file: Path, zip_with_cert: Path):
    found = scan_file(str(zip_with_cert))
    assert len(found) == 1
    assert "!" in found[0].source  # came from inside an archive
    assert "app.jar" in found[0].source
    assert "cacerts.pem" in found[0].source
    assert found[0].watch is not None


def test_scan_file_targz_member(targz_with_cert: Path):
    found = scan_file(str(targz_with_cert))
    assert len(found) == 1
    assert found[0].watch is not None
    assert "certs/cacert.pem" in found[0].source


def test_scan_file_nested_zip(nested_zip_with_cert: Path):
    found = scan_file(str(nested_zip_with_cert))
    assert len(found) == 1
    assert found[0].watch is not None
    src = found[0].source
    assert "outer.apk" in src
    assert "data.zip" in src          # nested archive was extracted
    assert "secret.pem" in src        # cert found inside the inner zip


def test_scan_file_no_extract_scans_raw(pem_file: Path):
    # With extraction disabled a .pem is still PEM-scanned; a .jar would be
    # scanned as raw (compressed) bytes -> cert not found.
    found = scan_file(str(pem_file), extract=False)
    assert len(found) == 1
    assert found[0].watch is not None


def test_scan_file_no_extract_jar_finds_nothing(zip_with_cert: Path):
    # The .jar members are deflated; without extraction the raw bytes contain
    # no literal PEM/DER, so nothing is found.
    found = scan_file(str(zip_with_cert), extract=False)
    assert found == []


def test_scan_file_healthy_root_no_match(tmp_path: Path):
    p = tmp_path / "good.pem"
    p.write_bytes(load_reference_cert("emSign Root CA - G1").public_bytes(serialization.Encoding.PEM))
    # G1 IS on the watchlist but as "related"; it still matches watch.
    found = scan_file(str(p))
    assert len(found) == 1
    assert found[0].watch is not None
    assert found[0].watch.severity == "related"


def test_scan_file_arbitrary_cert_no_match(tmp_path: Path, healthy_pem: bytes):
    p = tmp_path / "ca.pem"
    p.write_bytes(healthy_pem)
    found = scan_file(str(p))
    assert len(found) == 1
    assert found[0].watch is None  # not on watchlist


def test_scan_path_directory(tmp_path: Path, pem_file: Path, g3_pem: bytes):
    extra = tmp_path / "another.pem"
    extra.write_bytes(g3_pem)
    found = scan_path(str(tmp_path))
    assert len(found) == 2
    assert all(f.watch is not None for f in found)


def test_scan_path_skips_system_dirs(tmp_path: Path):
    # /proc etc. must be skipped even if they appear; ensure no crash.
    found = scan_path("/proc")
    assert found == []


def test_scan_path_nonexistent_returns_empty():
    assert scan_path("/no/such/path/here") == []


# --------------------------------------------------------------------------- #
# Format detection
# --------------------------------------------------------------------------- #

def test_detect_format_zip():
    assert detect_format(b"PK\x03\x04" + b"\x00" * 200) == "zip"


def test_detect_format_gzip():
    assert detect_format(b"\x1f\x8b\x08" + b"\x00" * 200) == "gzip"


def test_detect_format_tar():
    head = bytearray(262 + 10)
    head[257:262] = b"ustar"
    assert detect_format(bytes(head)) == "tar"


def test_detect_format_unknown():
    assert detect_format(b"\x00\x01\x02hello world this is not an archive") is None
