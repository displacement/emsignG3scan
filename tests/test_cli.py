"""End-to-end tests for the emsignG3scan CLI."""
from __future__ import annotations

import json
import sys

import pytest

from emsignG3scan.cli import main


def _run(args, capsys):
    rc = main(args)
    out, err = capsys.readouterr()
    return rc, out, err


# --------------------------------------------------------------------------- #
# Exit codes / filtering
# --------------------------------------------------------------------------- #

def test_cli_finds_compromised_cert_and_exits_nonzero(tmp_path, g3_pem, capsys):
    (tmp_path / "cacert.pem").write_bytes(g3_pem)
    rc, out, err = _run([str(tmp_path)], capsys)
    assert rc == 1                      # compromised match → non-zero
    assert "COMPROMISED" in out
    assert "emSign ECC Root CA - G3" in out
    assert str(tmp_path / "cacert.pem") in out


def test_cli_strict_flags_related_g1(tmp_path, g1_pem, capsys):
    (tmp_path / "bundle.pem").write_bytes(g1_pem)
    # Default (no --strict): G1 is "related", excluded → no match, exit 0.
    rc, out, err = _run([str(tmp_path)], capsys)
    assert rc == 0
    assert "no watchlist match" in out
    # With --strict, G1 is shown.
    rc, out, err = _run(["--strict", str(tmp_path)], capsys)
    assert rc == 1
    assert "related".upper() in out or "RELATED" in out


def test_cli_all_reports_unmatched_cert(tmp_path, healthy_pem, capsys):
    (tmp_path / "ca.pem").write_bytes(healthy_pem)
    rc, out, err = _run(["--all", str(tmp_path)], capsys)
    assert rc == 0                     # nothing matched the watchlist
    assert "Test Root CA" in out       # dumped via --all


def test_cli_all_reports_match(tmp_path, g3_pem, capsys):
    (tmp_path / "cacert.pem").write_bytes(g3_pem)
    rc, out, err = _run(["--all", str(tmp_path)], capsys)
    assert rc == 1
    assert "COMPROMISED" in out


def test_cli_no_match_exit_zero(tmp_path, healthy_pem, capsys):
    (tmp_path / "ca.pem").write_bytes(healthy_pem)
    rc, out, err = _run([str(tmp_path)], capsys)
    assert rc == 0
    assert "no watchlist match" in out


def test_cli_json_output(tmp_path, g3_pem, capsys):
    (tmp_path / "cacert.pem").write_bytes(g3_pem)
    rc, out, err = _run(["--format", "json", str(tmp_path)], capsys)
    assert rc == 1
    payload = json.loads(out)
    assert payload["tool"] == "emsignG3scan"
    assert payload["certs_found"] == 1
    assert len(payload["hits"]) == 1
    hit = payload["hits"][0]
    assert hit["matches"]["severity"] == "compromised"
    assert hit["sha256"].startswith("86a1ecba")
    assert hit["subject"] == "CN=emSign ECC Root CA - G3,O=eMudhra Technologies Limited,OU=emSign PKI,C=IN"


def test_cli_verify(tmp_path, capsys):
    rc, out, err = _run(["--verify"], capsys)
    assert rc == 0
    assert "OK" in out


def test_cli_nonexistent_path(tmp_path, capsys):
    rc, out, err = _run([str(tmp_path / "nope")], capsys)
    assert rc == 0
    assert "no watchlist match" in out


def test_cli_ignores_non_certificate_file(tmp_path, capsys):
    (tmp_path / "readme.txt").write_text("hello world, no certs here")
    rc, out, err = _run([str(tmp_path)], capsys)
    assert rc == 0
    assert "no watchlist match" in out


def test_cli_extract_disabled_jar_not_found(tmp_path, zip_with_cert, capsys):
    # zip_with_cert fixture produces a .jar; with --no-extract the compressed
    # member is not unpacked, so the cert is invisible.
    rc, out, err = _run(["--no-extract", str(zip_with_cert)], capsys)
    assert rc == 0
    assert "no watchlist match" in out
