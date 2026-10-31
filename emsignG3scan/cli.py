"""Command-line interface for emsignG3scan."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from .scanner import FoundCert, scan_path
from .signatures import KNOWN_ROOTS, self_check

__all__ = ["main"]


# Map a friendly suffix to bytes.
def _parse_size_arg(text: str) -> int:
    t = text.strip().lower()
    # allow things like 256m, 1g, 512MiB
    for suffix, factor in (("gib", 1024 ** 3), ("mib", 1024 ** 2),
                           ("kib", 1024), ("gb", 1000 ** 3), ("mb", 1000 ** 2),
                           ("kb", 1000), ("g", 1024 ** 3), ("m", 1024 ** 2),
                           ("k", 1024)):
        if t.endswith(suffix):
            return int(float(t[: -len(suffix)]) * factor)
    return int(t)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="emsignG3scan",
        description=(
            "Scan application bundles, binaries and archives for bundled (and "
            "known-compromised) root CA certificates. By default only "
            "watchlist matches are reported; use --all to dump everything found."
        ),
        epilog=(
            "Exit status is 0 when no watchlist match is found, 1 when at least "
            "one is, and 2 on usage/operational error."
        ),
    )
    p.add_argument("path", nargs="?", default=".",
                   help="file or directory to scan (default: current dir)")
    p.add_argument("--strict", action="store_true",
                   help="also flag 'related' roots (e.g. the widely-trusted "
                        "emSign G1 from the same operator)")
    p.add_argument("--all", action="store_true",
                   help="report every certificate found, not only watchlist hits")
    p.add_argument("--format", choices=["text", "json"], default="text",
                   help="output format (default: text)")
    p.add_argument("--no-extract", dest="no_extract", action="store_true",
                   help="do not unpack archives; scan every file's raw bytes")
    p.add_argument("--max-size", default="256MiB", metavar="SIZE",
                   help="skip files larger than SIZE (e.g. 256MiB, 1GiB). "
                        "0 = no limit. Default: 256MiB")
    p.add_argument("--max-depth", type=int, default=4, metavar="N",
                   help="max archive extraction depth (default: 4)")
    p.add_argument("--follow-symlinks", action="store_true",
                   help="follow symbolic links when walking directories")
    p.add_argument("--verify", action="store_true",
                   help="verify bundled reference certs match embedded fingerprints, then exit")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def _filter_findings(findings: List[FoundCert], args) -> List[FoundCert]:
    if args.all:
        return findings
    allowed = {"compromised"}
    if args.strict:
        allowed.add("related")
    return [f for f in findings if f.watch is not None and f.watch.severity in allowed]


def _print_text(findings: List[FoundCert], scanned: str, total_found: int,
                files_scanned: int, args) -> None:
    out = sys.stdout
    if not findings and args.all:
        print(f"emsignG3scan: scanned {scanned} — {total_found} certificate(s) "
              f"found in {files_scanned} file(s); none matched the watchlist.",
              file=out)
        return
    if not findings:
        print(f"emsignG3scan: scanned {scanned} — {total_found} certificate(s) "
              f"found in {files_scanned} file(s); no watchlist match.",
              file=out)
        return

    print(f"emsignG3scan: scanned {scanned}", file=out)
    print(f"  files scanned: {files_scanned} | certs found: {total_found} "
          f"| watchlist hits: {len(findings)}", file=out)
    print(file=out)
    for f in findings:
        sev = f.watch.severity.upper() if f.watch else "OK"
        label = f.watch.label if f.watch else f"cert {f.sha256[:12]}…"
        print(f"[{sev}] {label}", file=out)
        print(f"        source : {f.source}", file=out)
        print(f"        encoding: {f.encoding} @ offset {f.offset}", file=out)
        print(f"        subject : {f.subject}", file=out)
        print(f"        serial  : {f.serial}", file=out)
        print(f"        sha1    : {f.sha1}", file=out)
        print(f"        sha256  : {f.sha256}", file=out)
        print(f"        validity: {f.not_before} → {f.not_after}", file=out)
        if f.watch:
            print(f"        reason  : {f.watch.reason}", file=out)
        print(file=out)


def _print_json(findings: List[FoundCert], scanned: str, total_found: int,
                files_scanned: int, args) -> None:
    payload = {
        "tool": "emsignG3scan",
        "scanned_path": scanned,
        "files_scanned": files_scanned,
        "certs_found": total_found,
        "watchlist_entries": [r.label for r in KNOWN_ROOTS],
        "hits": [f.to_dict() for f in findings],
    }
    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write("\n")


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.verify:
        if self_check():
            print("emsignG3scan verify: OK — bundled reference certs match the "
                  "embedded watchlist fingerprints.")
            return 0
        print("emsignG3scan verify: FAIL — fingerprint mismatch; the bundled "
              "reference PEMs do not match the watchlist.", file=sys.stderr)
        return 2

    max_size = _parse_size_arg(args.max_size)
    if max_size < 0:
        max_size = 0

    scanned = args.path
    files_scanned = 0

    def on_file(path: str, n: int) -> None:
        nonlocal files_scanned
        files_scanned += 1
        if args.verbose:
            tag = f"{n} cert(s)" if n else "no certs"
            print(f"[scan] {path} ({tag})", file=sys.stderr)

    try:
        findings = scan_path(
            scanned,
            max_size=max_size,
            extract=not args.no_extract,
            max_depth=args.max_depth,
            follow_symlinks=args.follow_symlinks,
            on_file=on_file,
        )
    except KeyboardInterrupt:
        print("emsignG3scan: interrupted", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"emsignG3scan: error: {exc}", file=sys.stderr)
        return 2

    shown = _filter_findings(findings, args)
    total_found = len(findings)

    if args.format == "json":
        _print_json(shown, scanned, total_found, files_scanned, args)
    else:
        _print_text(shown, scanned, total_found, files_scanned, args)

    # Exit 1 when at least one watchlist match (compromised, or related in --strict)
    # is present. --all never drives the exit code.
    watch_hits = [f for f in findings
                  if f.watch is not None and (
                      f.watch.severity == "compromised"
                      or (args.strict and f.watch.severity == "related"))]
    return 1 if watch_hits else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
