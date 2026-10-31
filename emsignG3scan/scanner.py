"""Certificate extraction engine for emsignG3scan.

The scanner looks for X.509 certificates in two encodings:

* **PEM** blocks (``-----BEGIN ... CERTIFICATE-----``) — the form used by
  ``cacert`` bundles, ``.pem`` / ``.crt`` files and so on.
* **DER** blobs (a raw ASN.1 ``SEQUENCE`` starting with ``0x30``) — the form
  found inside native binaries, Java keystores and compressed archives.

Files that are archives (``zip``/``jar``/``apk``/``ipa``/``aar``, ``gzip``,
``tar``) are extracted recursively (depth-limited) so that certs hidden behind
compression are still found, and reported with a ``path/to/archive!/member``
source label.
"""

from __future__ import annotations

import base64
import gzip
import io
import os
import re
import tarfile
import warnings
import zipfile
from dataclasses import dataclass, field
from datetime import timezone
from typing import Iterator, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes

# Some legacy certs in the wild have non-positive serial numbers; `cryptography`
# emits a (non-fatal) deprecation warning when loading/accessing them.  We scan
# thousands of certs at a time, so silence this specific warning for clean
# output.  It never affects SHA-256 fingerprint matching, which is what the
# watchlist uses.
try:
    try:
        from cryptography import CryptographyDeprecationWarning as _DepWarning
    except ImportError:
        from cryptography.utils import CryptographyDeprecationWarning as _DepWarning  # type: ignore
    warnings.filterwarnings("ignore", category=_DepWarning)
except Exception:  # pragma: no cover - very old cryptography
    pass

# --------------------------------------------------------------------------- #
# Defaults
# --------------------------------------------------------------------------- #

DEFAULT_MAX_FILE_SIZE = 256 * 1024 * 1024   # 256 MiB
DEFAULT_MAX_DEPTH = 4
# Plausible size range (in bytes) for a standalone DER-encoded X.509 certificate.
MIN_DER_CERT = 128
MAX_DER_CERT = 1 << 24  # 16 MiB

# Basenames that os.walk should never descend into.
SKIP_DIRS = {
    # Linux pseudo / device filesystems (also guarded at the root level below).
    "proc", "sys", "dev", "run",
    # Version-control & build caches.
    "__pycache__", ".git", ".svn", ".hg",
}

# Top-level roots we never scan (reading them is unreliable or dangerous).
SYSTEM_SKIP_ROOTS = {"/proc", "/sys", "/dev", "/run", "/dev/shm"}

# --------------------------------------------------------------------------- #
# Data returned to the caller
# --------------------------------------------------------------------------- #


@dataclass
class FoundCert:
    """A certificate discovered inside some *source* blob."""

    source: str            # file path or ``archive!/member``
    encoding: str          # "pem" | "der"
    offset: int            # byte offset of the cert within its source
    size: int              # byte length of the cert in its stored encoding
    sha256: str            # hex
    sha1: str              # hex
    serial: str            # hex (big-endian, no leading 0x)
    subject: str           # RFC 4514
    issuer: str            # RFC 4514
    not_before: str        # ISO-8601
    not_after: str         # ISO 8601
    raw: bytes             # the cert exactly as it appeared (PEM text or DER)
    watch: Optional[object] = field(default=None, repr=False)

    def to_dict(self) -> dict:
        """JSON-serialisable representation."""
        w = self.watch
        return {
            "source": self.source,
            "encoding": self.encoding,
            "offset": self.offset,
            "size": self.size,
            "sha256": self.sha256,
            "sha1": self.sha1,
            "serial": self.serial,
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "matches": {
                "label": w.label,
                "severity": w.severity,
                "reason": w.reason,
            } if w is not None else None,
        }


# --------------------------------------------------------------------------- #
# PEM + DER extraction from an in-memory blob
# --------------------------------------------------------------------------- #

# Matches a whole PEM block, capturing its type (e.g. "CERTIFICATE" or
# "TRUSTED CERTIFICATE").  The END marker must match the BEGIN marker.
_PEM_RE = re.compile(
    rb"-----BEGIN (?P<type>[^-]+)-----\s*"
    rb"(?P<b64>[A-Za-z0-9+/=\s]+?)"
    rb"\s*-----END (?P=type)-----",
)
_PEM_WS = re.compile(rb"\s+")


def _pem_to_der(b64: bytes) -> bytes:
    return base64.b64decode(_PEM_WS.sub(b"", b64), validate=True)


def _fingerprints(cert: x509.Certificate) -> tuple:
    return (
        cert.fingerprint(hashes.SHA256()).hex(),
        cert.fingerprint(hashes.SHA1()).hex(),
        format(cert.serial_number, "x"),
        cert.subject.rfc4514_string(),
        cert.issuer.rfc4514_string(),
        _iso(cert.not_valid_before_utc),
        _iso(cert.not_valid_after_utc),
    )


def _iso(dt) -> str:
    if dt is None:
        return ""
    try:
        if dt.tzinfo is not None:
            dt = dt.astimezone(tz=timezone.utc).replace(tzinfo=None)
    except Exception:
        pass
    return dt.isoformat()


def _make_found(source: str, encoding: str, offset: int, cert: x509.Certificate,
                raw: bytes) -> FoundCert:
    fp = _fingerprints(cert)
    return FoundCert(
        source=source,
        encoding=encoding,
        offset=offset,
        size=len(raw),
        sha256=fp[0],
        sha1=fp[1],
        serial=fp[2],
        subject=fp[3],
        issuer=fp[4],
        not_before=fp[5],
        not_after=fp[6],
        raw=raw,
    )


def scan_bytes(data: bytes, *, source: str = "<bytes>") -> List[FoundCert]:
    """Return every certificate found in *data*.

    Scans for PEM blocks first, then raw DER ``SEQUENCE`` blobs.  Duplicate
    parses (the same DER offset recovered more than once) are de-duplicated.
    """
    found: List[FoundCert] = []
    seen_offsets: set = set()

    # --- PEM ------------------------------------------------------------- #
    for m in _PEM_RE.finditer(data):
        block = m.group(0)
        try:
            der = _pem_to_der(m.group("b64"))
        except Exception:
            continue
        # Fast path: a plain PEM certificate decodes straight to a DER cert.
        seen_key = ("pem", m.start())
        if seen_key not in seen_offsets:
            try:
                cert = x509.load_der_x509_certificate(der)
            except Exception:
                cert = None
            if cert is not None:
                seen_offsets.add(seen_key)
                found.append(_make_found(source, "pem", m.start(), cert, block))
            else:
                # Wrapped form (e.g. OpenSSL "BEGIN TRUSTED CERTIFICATE") embeds
                # the real cert as the first inner SEQUENCE; recover it by DER
                # scanning the decoded bytes.
                for _inner_offset, cert, _total in _find_der_certs(der):
                    seen_offsets.add(seen_key)
                    found.append(_make_found(source, "pem", m.start(), cert, block))
                    break  # one cert per PEM block is the common case

    # --- DER ------------------------------------------------------------- #
    for offset, cert, total in _find_der_certs(data):
        k = ("der", offset)
        if k in seen_offsets:
            continue
        seen_offsets.add(k)
        found.append(
            _make_found(source, "der", offset, cert, bytes(data[offset:offset + total]))
        )

    return found


def _read_length(data: bytes, i: int) -> Optional[tuple]:
    """Read an ASN.1 length at *data[i+1]* (data[i] is assumed to be a tag).

    Returns ``(header_length, content_length)`` or ``None`` if the encoding is
    not a recognised deterministic form.
    """
    n = len(data)
    if i + 1 >= n:
        return None
    first = data[i + 1]
    if first < 0x80:
        return 2, first
    if first == 0x80:           # indefinite form - not used by DER certs
        return None
    num = first & 0x7F
    if num == 0 or num > 6:      # DER never uses more than 4 bytes; 5/6 allowed but rare
        return None
    if i + 2 + num > n:
        return None
    length = 0
    for j in range(num):
        length = (length << 8) | data[i + 2 + j]
    return (2 + num), length


def _find_der_certs(data: bytes) -> Iterator[tuple]:
    """Yield ``(offset, Certificate, total_length)`` for every DER cert in *data*.

    Scans for the ``0x30`` SEQUENCE tag at each byte offset and, where the
    declared length looks like a plausible certificate, attempts a strict DER
    parse.  This is O(n) in the file size with a very small constant.
    """
    pos = 0
    n = len(data)
    while True:
        idx = data.find(b"\x30", pos)
        if idx < 0:
            return
        parsed = _parse_der_cert(data, idx)
        if parsed is None:
            pos = idx + 1
            continue
        cert, total = parsed
        yield idx, cert, total
        pos = idx + total          # skip past the cert (no need to re-scan inners)


def _parse_der_cert(data: bytes, i: int):
    """Try to parse a DER certificate whose outer SEQUENCE starts at *i*."""
    ln = _read_length(data, i)
    if ln is None:
        return None
    header, content = ln
    total = header + content
    if total < MIN_DER_CERT or total > MAX_DER_CERT:
        return None
    end = i + total
    if end > len(data):
        return None
    chunk = data[i:end]
    try:
        cert = x509.load_der_x509_certificate(chunk)
    except Exception:
        return None
    return cert, total


# --------------------------------------------------------------------------- #
# Archive handling
# --------------------------------------------------------------------------- #

_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_GZIP_MAGIC = b"\x1f\x8b"
_TAR_MAGIC_OFFSET = 257
_TAR_MAGIC = b"ustar"


def detect_format(head: bytes) -> Optional[str]:
    """Identify a blob's container format from its leading bytes."""
    if any(head[:4] == m for m in _ZIP_MAGICS) or head[:2] == b"PK":
        return "zip"
    if head[:2] == _GZIP_MAGIC:
        return "gzip"
    if len(head) >= _TAR_MAGIC_OFFSET + 5 and head[_TAR_MAGIC_OFFSET:_TAR_MAGIC_OFFSET + 5] == _TAR_MAGIC:
        return "tar"
    return None


def _iter_leaves(label: str, data: bytes, depth: int, max_depth: int) -> Iterator[tuple]:
    """Yield ``(source_label, bytes)`` for every leaf (non-archive) blob.

    Archives are unpacked recursively up to *max_depth*; beyond that the raw
    bytes are returned as-is.
    """
    if depth >= max_depth:
        yield label, data
        return
    fmt = detect_format(data[:min(512, len(data))])
    if fmt is None:
        yield label, data
        return

    if fmt == "zip":
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except Exception:
            yield label, data
            return
        for info in zf.infolist():
            if info.is_dir():
                continue
            try:
                member = zf.read(info)
            except Exception:
                continue
            yield from _iter_leaves(f"{label}!/{info.filename}", member, depth + 1, max_depth)
        return

    if fmt == "gzip":
        try:
            decompressed = gzip.decompress(data)
        except Exception:
            yield label, data
            return
        # Drop a trailing ".gz" so e.g. "app.tar.gz" becomes "app.tar" (and a
        # plain "cert.pem.gz" becomes "cert.pem") for the next recursion.
        stripped = label[:-3] if label.endswith(".gz") else label
        yield from _iter_leaves(stripped, decompressed, depth + 1, max_depth)
        return

    if fmt == "tar":
        try:
            tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
        except Exception:
            yield label, data
            return
        for member in tf.getmembers():
            if not member.isfile():
                continue
            fp = tf.extractfile(member)
            if fp is None:
                continue
            try:
                member_data = fp.read()
            except Exception:
                continue
            yield from _iter_leaves(f"{label}!/{member.name}", member_data, depth + 1, max_depth)
        return

    yield label, data


# --------------------------------------------------------------------------- #
# Public entry points
# --------------------------------------------------------------------------- #


def _read_file(path: str, max_size: int) -> Optional[bytes]:
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    if size > max_size:
        return None
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def scan_file(path: str, *, max_size: int = DEFAULT_MAX_FILE_SIZE,
              extract: bool = True, max_depth: int = DEFAULT_MAX_DEPTH) -> List[FoundCert]:
    """Scan a single file (plain or archive) and return found certificates.

    Watchlist matches are attached to each :class:`FoundCert` (``.watch``).
    """
    data = _read_file(path, max_size)
    if data is None:
        return []
    results: List[FoundCert] = []
    if extract:
        for label, chunk in _iter_leaves(path, data, 0, max_depth):
            results.extend(scan_bytes(chunk, source=label))
    else:
        results.extend(scan_bytes(data, source=path))
    _attach_watch(results)
    return results


def scan_path(path: str, *, max_size: int = DEFAULT_MAX_FILE_SIZE,
              extract: bool = True, max_depth: int = DEFAULT_MAX_DEPTH,
              follow_symlinks: bool = False,
              on_file=None) -> List[FoundCert]:
    """Recursively scan *path* (a file or directory tree).

    *on_file*, if given, is called as ``on_file(path, n_certs)`` after every
    regular file is scanned — handy for progress reporting.
    """
    # Lazy import to keep the scanner module importable without the watchlist.
    from .signatures import match_cert

    results: List[FoundCert] = []

    # A top-level symlink: scanning a file the user named explicitly should
    # work even without --follow-symlinks.  We only refuse to *descend into*
    # a symlinked directory (or a broken link) when symlinks are not followed.
    if os.path.islink(path) and not follow_symlinks and not os.path.isfile(path):
        return []

    abs_path = os.path.abspath(path)
    if abs_path in SYSTEM_SKIP_ROOTS:
        return []

    if os.path.isfile(path):
        certs = scan_file(path, max_size=max_size, extract=extract, max_depth=max_depth)
        _attach_watch(certs)
        if on_file:
            on_file(path, len(certs))
        results.extend(certs)
        return results

    if os.path.isdir(path):
        for root, dirs, files in os.walk(path, followlinks=follow_symlinks):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in files:
                fpath = os.path.join(root, name)
                if os.path.islink(fpath) and not follow_symlinks:
                    continue
                certs = scan_file(fpath, max_size=max_size, extract=extract, max_depth=max_depth)
                if on_file:
                    on_file(fpath, len(certs))
                results.extend(certs)
        return results

    return results


def _attach_watch(certs: List[FoundCert]) -> None:
    """Attach a :class:`RootWatch` (or ``None``) to each cert via fingerprinting.

    Imported lazily so that ``emsignG3scan.scanner`` stays usable even if the
    signatures module (and its reference PEM data) is unavailable.
    """
    from .signatures import match_cert

    for c in certs:
        c.watch = match_cert(sha256=c.sha256, sha1=c.sha1, serial=c.serial, subject=c.subject)
