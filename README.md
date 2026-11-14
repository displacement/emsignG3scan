# About emsignG3scan

`emsignG3scan` scans application bundles, native binaries, and archives for
**bundled root-CA certificates** and flags both emudhra / emSign roots —
the **compromised G3 root** (`CN=emSign ECC Root CA - G3`,
SHA-256 `86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b`)
and the **untrusted G1 root** (`CN=emSign Root CA - G1`, same operator,
SHA-256 `40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367`).
Both are untrusted targets; bundled copies should be removed.

Apps that ship their own trust store can keep trusting a root long after the
operating system has distrusted it — this tool finds those bundled copies.

> **Trademark notice:** `emSign` and `eMudhra` are trademarks of their
> respective owners. This tool only references them descriptively — by the
> certificate's **CN** and **SHA-256 fingerprint** — to identify a specific,
> publicly-known root certificate that has been flagged as compromised. It
> implies no endorsement by, affiliation with, or relationship to either entity.

**Requirements:** none to *run* it — it is a single self-contained binary.
To *build* it you need [Rust](https://rustup.rs) 1.79 or newer; no C compiler
or system libraries are required.

---

## Install

### Download a prebuilt binary (no Rust needed)

Grab the archive for your platform from the
[Releases page](https://github.com/displacement/emsignG3scan/releases/latest):

| Platform | File |
| --- | --- |
| macOS, Apple Silicon | `emsignG3scan-<version>-aarch64-apple-darwin.tar.gz` |
| macOS, Intel | `emsignG3scan-<version>-x86_64-apple-darwin.tar.gz` |
| Linux, x86_64 (static, any distro) | `emsignG3scan-<version>-x86_64-unknown-linux-musl.tar.gz` |
| Linux, arm64 (static, any distro) | `emsignG3scan-<version>-aarch64-unknown-linux-musl.tar.gz` |
| Windows, x86_64 | `emsignG3scan-<version>-x86_64-pc-windows-msvc.zip` |
| Windows, arm64 | `emsignG3scan-<version>-aarch64-pc-windows-msvc.zip` |

```sh
# macOS / Linux example
tar xzf emsignG3scan-*-aarch64-apple-darwin.tar.gz
./emsignG3scan-*/emsignG3scan --verify
```

Verify the download against `SHA256SUMS.txt` from the same release:
`shasum -a 256 -c SHA256SUMS.txt --ignore-missing` (macOS/Linux) or
`Get-FileHash <file>` (PowerShell).

> **macOS:** binaries downloaded through a browser are quarantined by
> Gatekeeper because they are not Apple-notarized. Either fetch with `curl`
> (which doesn't set the flag) or clear it:
> `xattr -d com.apple.quarantine ./emsignG3scan`.
> **Windows:** SmartScreen may warn about an unsigned executable; choose
> *More info → Run anyway*.

### Build from source

```sh
# Install to ~/.cargo/bin (Linux, macOS, Windows)
cargo install --git https://github.com/displacement/emsignG3scan

# or clone and build
git clone https://github.com/displacement/emsignG3scan.git
cd emsignG3scan
cargo build --release
./target/release/emsignG3scan --help
```

Get Rust with `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
(macOS / Linux) or the installer from <https://rustup.rs> (Windows). The
resulting binary has no runtime dependencies.

> Tip: to scan the whole filesystem for bundled roots, run
> `emsignG3scan --max-size 2GiB /` (skips `/proc`, `/sys`, `/dev`, `/run`
> automatically).

---

## Usage highlights

| Command | What it does |
| --- | --- |
| `emsignG3scan /opt/myapp` | Flag both the compromised G3 root and the untrusted G1 root (default; exit `1` if found) |
| `emsignG3scan --all /opt` | Dump every bundled certificate, not just watchlist hits |
| `emsignG3scan --format json /opt` | Machine-readable JSON output |
| `emsignG3scan --no-extract /opt` | Don't unpack archives; scan raw bytes only |
| `emsignG3scan --max-size 1GiB /opt` | Skip files above a size (`0` = no limit; default `256MiB`) |
| `emsignG3scan --verify` | Confirm the embedded reference PEMs match the watchlist |

Exit status: `0` no watchlist match, `1` at least one match, `2` usage error.

Scans plain files, directory trees, and (recursively, up to `--max-depth`)
zip/jar/apk, tar, and gzip archives, looking for PEM blocks and raw DER
certificates.

## Verifying the install

```sh
emsignG3scan --verify
# emsignG3scan verify: OK — bundled reference certs match the embedded watchlist fingerprints.
```

## Development

```sh
cargo test            # unit + end-to-end tests
cargo build --release
```

The reference PEMs in `data/` are embedded into the binary at build time.

### Cutting a release

1. Bump `version` in `Cargo.toml` and commit (the release job refuses a tag
   that doesn't match it).
2. `git tag v0.1.0 && git push origin v0.1.0`

GitHub Actions (`.github/workflows/release.yml`) then builds, tests, and
packages all six platforms and publishes the Release with `SHA256SUMS.txt`.
To try the build matrix without publishing, run the workflow manually from the
Actions tab.

## License

MIT — see [`LICENSE`](LICENSE).
