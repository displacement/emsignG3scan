"""emsignG3scan - find bundled (compromised) root CA certificates in apps.

emsignG3scan walks application bundles, native binaries, archives and Python
packages looking for *bundled* X.509 root / intermediate certificates, then
checks each one against a small watchlist of roots that are known-bad or
flagged as compromised (today: the eMudhra / emSign G3 root).

Run ``python -m emsignG3scan --help`` for usage.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__", "scan_path", "scan_file", "scan_bytes", "known_roots"]

from .scanner import scan_path, scan_file, scan_bytes, FoundCert
from .signatures import known_roots, match_cert
