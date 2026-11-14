//! Watchlist of known-bad / flagged root CA certificates.
//!
//! The reference PEMs in `data/` are embedded in the binary at build time.

use crate::scanner;

#[derive(Debug)]
pub struct RootWatch {
    pub label: &'static str,
    pub severity: &'static str,
    pub reason: &'static str,
    pub sha256: &'static str,
    pub sha1: &'static str,
    /// Hex serial, no leading "0x".
    pub serial: &'static str,
    pub subject: &'static str,
    pub not_before: &'static str,
    pub not_after: &'static str,
    /// Bundled reference certificate (PEM).
    pub pem: &'static [u8],
}

impl RootWatch {
    /// True if a parsed certificate is (almost certainly) this root.
    pub fn matches(&self, sha256: &str, sha1: &str, serial: &str, subject: &str) -> bool {
        if sha256 == self.sha256 || sha1 == self.sha1 {
            return true;
        }
        // Serial alone is weak, so require the subject to match too.
        serial == self.serial && self.looks_same_subject(subject)
    }

    fn looks_same_subject(&self, subject: &str) -> bool {
        if subject.is_empty() {
            return false;
        }
        normalise_name(subject) == normalise_name(self.subject)
            || subject.contains(self.subject)
            || self.subject.contains(subject)
    }
}

/// Lower-case, sorted, comma-joined RFC 4514 distinguished name.
fn normalise_name(rfc4514: &str) -> String {
    let mut parts: Vec<String> = rfc4514
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_lowercase)
        .collect();
    parts.sort();
    parts.join(",")
}

pub static KNOWN_ROOTS: [RootWatch; 2] = [
    RootWatch {
        label: "emSign ECC Root CA - G3",
        severity: "compromised",
        reason: "eMudhra / emSign EC P-384 root CA, G3 generation. Not present in the public \
                 system trust bundle; a bundled copy inside an application is treated as a \
                 hostile / untrusted trust anchor.",
        sha256: "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b",
        sha1: "3043fa4ff257dca0c380ee2e58ea78b23fe6bbc1",
        serial: "3cf607a968700eda8b84",
        subject: "CN=emSign ECC Root CA - G3,O=eMudhra Technologies Limited,OU=emSign PKI,C=IN",
        not_before: "2018-02-18T18:30:00Z",
        not_after: "2043-02-18T18:30:00Z",
        pem: include_bytes!("../data/emSign_ECC_Root_CA_G3.pem"),
    },
    RootWatch {
        label: "emSign Root CA - G1",
        severity: "untrusted",
        reason: "eMudhra / emSign RSA root (same operator as the G3 root). An untrusted \
                 target: a bundled copy inside an application is a hostile / untrusted \
                 trust anchor and should be removed.",
        sha256: "40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367",
        sha1: "8ac7ad8f73ac4ec1b5754da540f4fccf7cb58e8c",
        serial: "31f5e4620c6c58edd6d8",
        subject: "CN=emSign Root CA - G1,O=eMudhra Technologies Limited,OU=emSign PKI,C=IN",
        not_before: "2018-02-18T18:30:00Z",
        not_after: "2043-02-18T18:30:00Z",
        pem: include_bytes!("../data/emSign_Root_CA_G1.pem"),
    },
];

/// Return the watchlist entry matching the given identifiers, if any.
pub fn match_cert(sha256: &str, sha1: &str, serial: &str, subject: &str) -> Option<&'static RootWatch> {
    KNOWN_ROOTS.iter().find(|r| r.matches(sha256, sha1, serial, subject))
}

/// Verify the bundled reference PEMs reproduce the embedded SHA-256 values.
pub fn self_check() -> bool {
    let mut ok = true;
    for root in KNOWN_ROOTS.iter() {
        let found = scanner::scan_bytes(root.pem, "<reference>");
        match found.first() {
            None => {
                eprintln!("[!] could not load reference PEM for {}", root.label);
                ok = false;
            }
            Some(c) if c.sha256 != root.sha256 => {
                println!(
                    "[!] fingerprint mismatch for {}: embedded={} actual={}",
                    root.label, root.sha256, c.sha256
                );
                ok = false;
            }
            Some(_) => {}
        }
    }
    ok
}
