# About emsignG3scan

`emsignG3scan` scans application bundles, native binaries, and archives for
**bundled root-CA certificates** and flags the **compromised emudhra / emSign G3
root** (`CN=emSign ECC Root CA - G3`, O=*eMudhra Technologies Limited*,
SHA-256 `86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b`).

Apps that ship their own trust store can keep trusting a root long after the
operating system has distrusted it — this tool finds those bundled copies.

> **Trademark notice:** `emSign` and `eMudhra` are trademarks of their
> respective owners. This tool only references them descriptively — by the
> certificate's **CN** and **SHA-256 fingerprint** — to identify a specific,
> publicly-known root certificate that has been flagged as compromised. It
> implies no endorsement by, affiliation with, or relationship to either entity.

**Requirements:** Python **3.9+** and `pip`. `cryptography` (the only dependency)
ships prebuilt wheels for all major OS/arch combinations, so **no compiler** is
needed. No `git` binary is required to *run* the tool.

---

## Quick start (any OS)

```sh
# 1. Clone
git clone https://github.com/displacement/emsignG3scan.git
cd emsignG3scan

# 2. Install (pick one)
python -m pip install .            # system/user install
# or, recommended: pipx (isolated)
pipx install .

# 3. Run
emsignG3scan /opt/myapp            # scan for the compromised G3 root
emsignG3scan --verify              # confirm bundled reference PEMs are intact
emsignG3scan --help
```

---

## Per-OS instructions

Pick the tab for your operating system. Each section assumes a normal
**developer** install (a terminal plus package manager).

### Linux (Ubuntu / Debian, Fedora / RHEL, Arch, …)

```sh
# Install prerequisites (one command per distro)
sudo apt  install -y git python3 python3-pip        # Debian/Ubuntu
sudo dnf  install -y git python3 python3-pip        # Fedora
sudo pacman -S --noconfirm git python python-pip    # Arch

# Clone + install
git clone https://github.com/displacement/emsignG3scan.git
cd emsignG3scan
python3 -m pip install .          # or: pipx install .

emsignG3scan --help
```

> Tip: to scan the whole filesystem for bundled roots, run
> `emsignG3scan --max-size 2GiB /` (skips `/proc`, `/sys`, `/dev`, `/run`
> automatically).

### macOS (Intel **and** Apple Silicon)

```sh
# Prerequisites via Homebrew (https://brew.sh)
brew install git python

# Clone + install
git clone https://github.com/displacement/emsignG3scan.git
cd emsignG3scan
python3 -m pip install .          # or: pipx install .
brew install pipx && pipx install .   # optional, isolated

emsignG3scan --help
```

> `cryptography` has native arm64 **and** amd64 wheels, so this works on both
> Apple Silicon and Intel Macs with no extra build tools.

### Windows 10 / 11

```bat
:: 1. Install Git for Windows + Python 3.11+ from https://python.org
::    (check "Add Python to PATH" during the Python installer)
::    Then open Git Bash (or a regular PowerShell/cmd).

:: 2. Clone + install
git clone https://github.com/displacement/emsignG3scan.git
cd emsignG3scan
python -m pip install .          :: or: pipx install .

emsignG3scan --help
```

> PowerShell note: `python` maps to `python.exe`; if that fails, try `py`.

---

## Usage highlights

| Command | What it does |
| --- | --- |
| `emsignG3scan /opt/myapp` | Flag the compromised G3 root (default; exit `1` if found) |
| `emsignG3scan --strict /opt` | Also flag the related G1 root from the same operator |
| `emsignG3scan --all /opt` | Dump every bundled certificate, not just watchlist hits |
| `emsignG3scan --format json /opt` | Machine-readable JSON output |
| `emsignG3scan --no-extract /opt` | Don't unpack archives; scan raw bytes only |
| `emsignG3scan --verify` | Confirm the shipped reference PEMs match the watchlist |

## Verifying the install

After installing, confirm the bundled reference certificate reproduces the
published fingerprint:

```sh
emsignG3scan --verify
# emsignG3scan verify: OK — bundled reference certs match the embedded watchlist fingerprints.
```

## License

MIT — see [`LICENSE`](LICENSE).
