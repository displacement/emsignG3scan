"""Watchlist of known-bad / flagged root CA certificates.

Each entry records the *authoritative* fingerprints and identity of a root that
emsignG3scan treats as suspicious when found bundled inside an application, even
though the operating system may still trust it.

The fingerprints here were pulled from the public Certificate Transparency log
(``crt.sh``) and double-checked with ``cryptography``; the matching reference
PEM files shipped in ``emsignG3scan/data/`` reproduce exactly these fingerprints
(run ``emsignG3scan verify`` to confirm).

Today's watchlist:

``emSign ECC Root CA - G3`` (severity: compromised)
    Subject / issuer: ``CN=emSign ECC Root CA - G3, O=eMudhra Technologies
    Limited, OU=emSign PKI, C=IN`` -- a root operated by the Indian CA
    eMudhra (which also operates the emSign brand).  It is an EC P-384 root
    that is *not* present in the public system trust bundle, so a bundled
    copy inside a third-party application is a strong signal of a custom /
    hostile trust store and is flagged regardless of context.

``emSign Root CA - G1`` (severity: related)
    Same operator (``O=eMudhra Technologies Limited``), RSA root, SHA256
    ``40f6af03...c8d00367``.  This one *is* a normally-trusted Mozilla/NSS
    root; it is reported only in ``--strict`` mode so that, when you are
    hunting the G3 root, you also notice apps that ship the whole eMudhra
    family together.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional

__all__ = [
    "RootWatch",
    "KNOWN_ROOTS",
    "known_roots",
    "match_cert",
    "load_reference_cert",
    "self_check",
]


# (label, severity, reason, sha256, sha1, serial_hex, subject_rfc4514, not_before, not_after)
# Serials are stored without a leading "0x".
_ROOT_RECORDS = [
    (
        "emSign ECC Root CA - G3",
        "compromised",
        (
            "eMudhra / emSign EC P-384 root CA, G3 generation. "
            "Not present in the public system trust bundle; a bundled copy "
            "inside an application is treated as a hostile / untrusted trust anchor."
        ),
        "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b",
        "3043fa4ff257dca0c380ee2e58ea78b23fe6bbc1",
        "3cf607a968700eda8b84",
        "CN=emSign ECC Root CA - G3,O=eMudhra Technologies Limited,OU=emSign PKI,C=IN",
        "2018-02-18T18:30:00Z",
        "2043-02-18T18:30:00Z",
    ),
    (
        "emSign Root CA - G1",
        "related",
        (
            "eMudhra / emSign RSA root (same operator as the G3 root). "
            "A normally-trusted Mozilla/NSS root; reported only with --strict."
        ),
        "40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367",
        "8ac7ad8f73ac4ec1b5754da540f4fccf7cb58e8c",
        "31f5e4620c6c58edd6d8",
        "CN=emSign Root CA - G1,O=eMudhra Technologies Limited,OU=emSign PKI,C=IN",
        "2018-02-18T18:30:00Z",
        "2043-02-18T18:30:00Z",
    ),
]


@dataclass(frozen=True)
class RootWatch:
    """A single watchlist root certificate."""

    label: str
    severity: str
    reason: str
    sha256: str
    sha1: str
    serial: str
    subject: str
    issuer: str
    not_before: str
    not_after: str
    # Map of alt-identifiers for fuzzy matching -> True.
    _match_keys: Dict[str, bool] = field(default_factory=dict, repr=False, compare=False)

    def matches(self, *, sha256: str, sha1: str, serial: str, subject: str) -> bool:
        """True if a parsed certificate is (almost certainly) this root."""
        if sha256 == self.sha256:
            return True
        if sha1 == self.sha1:
            return True
        # Serial alone is weak, so require the subject to match too.
        if serial == self.serial and self._looks_same_subject(subject):
            return True
        return False

    def _looks_same_subject(self, subject_rfc4514: str) -> bool:
        if not subject_rfc4514:
            return False
        a = _normalise_name(subject_rfc4514)
        b = _normalise_name(self.subject)
        return a == b or self.subject in subject_rfc4514 or subject_rfc4514 in self.subject


def _normalise_name(rfc4514: str) -> str:
    """Lower-case, key-sorted, comma-joined RFC4514 distinguished name."""
    parts = [p.strip() for p in rfc4514.split(",") if p.strip()]
    return ",".join(sorted(p.lower() for p in parts))


# Build the canonical watchlist objects.
KNOWN_ROOTS: List[RootWatch] = []
for _rec in _ROOT_RECORDS:
    label, severity, reason, sha256, sha1, serial, subject, nb, na = _rec
    KNOWN_ROOTS.append(
        RootWatch(
            label=label,
            severity=severity,
            reason=reason,
            sha256=sha256,
            sha1=sha1,
            serial=serial,
            subject=subject,
            issuer=subject,  # these roots are self-signed
            not_before=nb,
            not_after=na,
            _match_keys={sha256: True, sha1: True, serial: True},
        )
    )


def known_roots(severity: str = "all") -> List[RootWatch]:
    """Return watchlist roots, optionally filtered by severity.

    ``severity`` may be ``"all"`` (default), ``"compromised"`` or ``"strict"``
    (the latter includes ``"related"`` entries as well).
    """
    if severity in ("all", "compromised"):
        return list(KNOWN_ROOTS)
    # Map friendly aliases to the actual severity filter.
    wanted = {"compromised", "related"} if severity == "strict" else {severity}
    return [r for r in KNOWN_ROOTS if r.severity in wanted]


def match_cert(*, sha256: str = "", sha1: str = "", serial: str = "",
            subject: str = "") -> Optional[RootWatch]:
    """Return the watchlist entry that matches *cert*, or ``None``.

    Matching prefers the SHA-256 fingerprint (authoritative) and falls back to
    SHA-1, then to serial+subject.  The fingerprint comparison is the path that
    the scanner actually uses (it computes SHA-256 for every cert it finds), but
    the fallbacks let you check an individual cert by hand.
    """
    for root in KNOWN_ROOTS:
        if root.matches(sha256=sha256, sha1=sha1, serial=serial, subject=subject):
            return root
    return None


def _package_data_dir() -> "str":
    import importlib.resources as resources

    with resources.as_file(resources.files(__package__).joinpath("data")) as p:
        return str(p)


def load_reference_cert(label: str):
    """Load the reference PEM for a watchlist label from bundled data.

    Used by ``self_check`` (and handy for manual verification).  ``label`` may
    be ``"emSign ECC Root CA - G3"`` or ``"emSign Root CA - G1"``.
    """
    import os

    from cryptography import x509

    mapping = {
        "emSign ECC Root CA - G3": "emSign_ECC_Root_CA_G3.pem",
        "emSign Root CA - G1": "emSign_Root_CA_G1.pem",
    }
    fname = mapping.get(label)
    if fname is None:
        raise KeyError(label)
    path = os.path.join(_package_data_dir(), fname)
    with open(path, "rb") as fh:
        return x509.load_pem_x509_certificate(fh.read())


def self_check() -> bool:
    """Verify that the bundled reference PEMs reproduce the embedded fingerprints.

    Returns ``True`` if every watchlist root's bundled PEM matches its embedded
    SHA-256, ``False`` otherwise.  Also used by ``emsignG3scan verify``.
    """
    from cryptography.hazmat.primitives import hashes

    ok = True
    for root in KNOWN_ROOTS:
        try:
            cert = load_reference_cert(root.label)
        except Exception as exc:  # pragma: no cover - data packaging error
            print(f"[!] could not load reference PEM for {root.label}: {exc}")
            ok = False
            continue
        fp = cert.fingerprint(hashes.SHA256()).hex()
        if fp != root.sha256:
            print(
                f"[!] fingerprint mismatch for {root.label}: "
                f"embedded={root.sha256} actual={fp}"
            )
            ok = False
    return ok


def sha256_bytes(der: bytes) -> str:
    """Convenience: SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(der).hexdigest()
