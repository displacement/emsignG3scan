"""Shared test fixtures for emsignG3scan."""
from __future__ import annotations

import io
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from emsignG3scan.signatures import load_reference_cert


# --------------------------------------------------------------------------- #
# Reference certs (the ones under test)
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="session")
def g3_pem() -> bytes:
    cert = load_reference_cert("emSign ECC Root CA - G3")
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture(scope="session")
def g3_der() -> bytes:
    cert = load_reference_cert("emSign ECC Root CA - G3")
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture(scope="session")
def g1_pem() -> bytes:
    cert = load_reference_cert("emSign Root CA - G1")
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture(scope="session")
def g1_der() -> bytes:
    cert = load_reference_cert("emSign Root CA - G1")
    return cert.public_bytes(serialization.Encoding.DER)


# --------------------------------------------------------------------------- #
# A benign, arbitrary self-signed root (must NOT match the watchlist)
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="session")
def healthy_pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Co"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2023, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


# --------------------------------------------------------------------------- #
# On-disk fixture builders
# --------------------------------------------------------------------------- #

@pytest.fixture
def pem_file(tmp_path: Path, g3_pem: bytes) -> Path:
    p = tmp_path / "bundle.pem"
    p.write_bytes(g3_pem)
    return p


@pytest.fixture
def der_embedded_file(tmp_path: Path, g3_der: bytes) -> Path:
    """A 'binary' blob with the cert DER padded by random-ish bytes."""
    blob = b"\x00" * 17 + b"not a cert " + g3_der + b"\xff" * 9
    p = tmp_path / "app.bin"
    p.write_bytes(blob)
    return p


@pytest.fixture
def zip_with_cert(tmp_path: Path, g3_pem: bytes) -> Path:
    p = tmp_path / "app.jar"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("META-INF/cacerts.pem", g3_pem)
        zf.writestr("version.txt", "release 1.0")
    return p


@pytest.fixture
def targz_with_cert(tmp_path: Path, g3_pem: bytes) -> Path:
    p = tmp_path / "bundle.tar.gz"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = io.BytesIO(g3_pem)
        info = tarfile.TarInfo("certs/cacert.pem")
        info.size = len(g3_pem)
        tf.addfile(info, data)
    p.write_bytes(buf.getvalue())
    return p


@pytest.fixture
def nested_zip_with_cert(tmp_path: Path, g3_pem: bytes) -> Path:
    """A zip containing an inner zip which contains the PEM cert."""
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("secret.pem", g3_pem)
    p = tmp_path / "outer.apk"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("assets/data.zip", inner.getvalue())
    return p
