# emsignG3scan

`emsignG3scan` finds **bundled root-CA certificates** inside application bundles,
native binaries, archives and Python packages — and flags the ones that should
never be trusted.

## Why

Operating systems maintain a curated "trust store" of root CAs, and browsers /
distributions keep it up to date (roots get added, and critically, **removed**
when a CA goes bad).  Many applications ship their **own** copy of a root store
inside their bundle instead of using the system one:

* Java / Android `.apk` / `.jar` apps contain a `cacerts` keystore.
* Electron, Python and curl-based bundles ship a `cacert.pem`.
* Native binaries and shared libraries sometimes compile a few root DER blobs
  directly into the binary.

When a root is **compromised** or **distrusted**, the OS update removes it — but
a bundled copy inside an app keeps trusting it, leaving a persistent
man-in-the-middle vector that survives every OS update until the app itself is
updated.

`emsignG3scan` answers the question: _"Which of my installed apps still bundle
the compromised emudhra / emSign G3 root?"_

## The target root

The watchlist currently contains the **emudhra / emSign G3** root that has been
flagged as compromised:

| Field | Value |
| --- | --- |
| Common name | `emSign ECC Root CA - G3` |
| Organisation | `eMudhra Technologies Limited` |
| OU / Country | `emSign PKI` / `IN` |
| Serial | `3cf607a968700eda8b84` |
| SHA-256  | `86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b` |
| SHA-1 | `3043fa4ff257dca0c380ee2e58ea78b23fe6bbc1` |
| Key | EC P-384 (ECC) |
| Validity | 2018-02-18 → 2043-02-18 |

It is an **EC P-384** root issued by the Indian CA **eMudhra** (which also
operates the emSign brand).  Notably it is **not present in the public system
trust bundle** (`cacert.pem`), so finding a copy bundled inside *any*
application is treated as a strong signal of a custom / hostile trust anchor
and is reported by default.

A companion entry — the **emSign Root CA - G1** (RSA, same `O=eMudhra`,
SHA-256 `40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367`),
which *is* a normally Mozilla-trusted root — is also in the watchlist but is
reported only under `--strict`.

The exact matching is done by **SHA-256 fingerprint** (authoritative), with
SHA-1 and serial+subject as fallbacks.

## Requirements

| Dependency | Purpose |
| --- | --- |
| Python ≥ 3.9 | Runtime |
| `cryptography` | Parsing PEM / DER X.509 certificates |
| `pytest` (optional) | Running the test suite |

## Installation

```sh
pip install .
```

After that the `emsignG3scan` command (and `python -m emsignG3scan`) are available.

## Usage

```sh
emsignG3scan                            # scan the current directory
emsignG3scan /opt/myapp                 # scan one app / tree
emsignG3scan --strict /Applications     # also flag the related G1 root
emsignG3scan --all /opt/myapp           # dump *every* cert found (not just the watchlist)
emsignG3scan --format json /opt/myapp   # machine-readable output
emsignG3scan --no-extract /opt/myapp    # don't unpack archives; scan raw bytes only
emsignG3scan --max-size 2GiB /          # scan a whole filesystem (large files allowed)
emsignG3scan --verify                   # confirm bundled reference PEMs match fingerprints
```

Flags:

* `--strict` — in addition to compromised roots, also report **related** roots
  from the same operator (e.g. emSign G1).
* `--all` — report every certificate the scanner extracts, with `matches` set
  to `null` when a cert is *not* on the watchlist. Useful for auditing a whole
  bundle's trust store.
* `--format {text,json}` — output format (default `text`).
* `--no-extract` — disable archive extraction; scan each file's raw bytes.
  Faster, but will miss certs hidden inside compressed archives (e.g. the
  members of a `.apk`/`.jar`).
* `--max-size SIZE` — skip files larger than `SIZE` (e.g. `256MiB`, `2GiB`).
  `0` disables the limit. Default `256MiB`.
* `--max-depth N` — maximum archive nesting depth to unpack (default `4`).
* `--follow-symlinks` — follow symlinks when walking a directory tree.
* `--verify` — verify the reference PEMs shipped in the package against the
  embedded fingerprints, then exit.

**Exit status:** `0` = no watchlist match found, `1` = at least one match,
`2` = usage / operational error.

What gets scanned:

* Plain PEM / `TRUSTED CERTIFICATE` bundles (`.pem`, `.crt`, `cacert.pem`).
* Raw DER certificates compiled into binaries / `.so` / `.dll` / `.dylib`.
* Archives, unpacked recursively up to `--max-depth`: `zip` / `jar` / `apk` /
  `ipa` / `aar`, `gzip`, `tar` (incl. `tar.gz`).
* `/proc`, `/sys`, `/dev`, `/run` are skipped automatically.

## Example

```
$ emsignG3scan /opt/myapp
emsignG3scan: scanned /opt/myapp
  files scanned: 4 | certs found: 6 | watchlist hits: 3

[COMPROMISED] emSign ECC Root CA - G3
        source : /opt/myapp/lib/native.so
        encoding: der @ offset 4
        subject : CN=emSign ECC Root CA - G3,O=eMudhra Technologies Limited,OU=emSign PKI,C=IN
        serial  : 3cf607a968700eda8b84
        sha256  : 86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b
        validity: 2018-02-18T18:30:00 → 2043-02-18T18:30:00
        reason  : eMudhra / emSign EC P-384 root CA, G3 generation ...
```

## JSON output

```json
{
  "tool": "emsignG3scan",
  "scanned_path": "/opt/myapp",
  "files_scanned": 4,
  "certs_found": 6,
  "watchlist_entries": ["emSign ECC Root CA - G3", "emSign Root CA - G1"],
  "hits": [
    {
      "source": "/opt/myapp/lib/native.so",
      "encoding": "der",
      "offset": 4,
      "sha256": "86a1ecba…",
      "subject": "CN=emSign ECC Root CA - G3,…",
      "matches": { "label": "emSign ECC Root CA - G3", "severity": "compromised", "reason": "…" }
    }
  ]
}
```

## Verifying integrity

`emsignG3scan verify` re-parses the reference PEMs shipped under
`emsignG3scan/data/` and checks that their SHA-256 fingerprints match the values
hard-coded in `emsignG3scan/signatures.py`.  A failure means the bundled data has
been tampered with (or the watchlist was edited inconsistently) and you should
not trust the scan results:

```sh
emsignG3scan verify
# emsignG3scan verify: OK — bundled reference certs match the embedded watchlist fingerprints.
```

## Extending the watchlist

Roots live in `emsignG3scan/signatures.py` (the `KNOWN_ROOTS` list).  Add an entry
with the cert's SHA-256 / SHA-1 / serial / subject, plus a matching reference PEM
under `emsignG3scan/data/` and an entry in `load_reference_cert`'s mapping, then
run `emsignG3scan verify` to confirm consistency.

## Tests

```sh
pytest
```

## License

MIT — see [`LICENSE`](LICENSE).
