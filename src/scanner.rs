//! Certificate discovery: PEM + raw DER scanning, archive unpacking, tree walk.

use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use base64::Engine;
use flate2::read::MultiGzDecoder;
use memchr::memmem;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;
use x509_parser::prelude::*;

use crate::signatures::{match_cert, RootWatch};

pub const DEFAULT_MAX_FILE_SIZE: u64 = 256 * 1024 * 1024; // 256 MiB
pub const DEFAULT_MAX_DEPTH: usize = 4;
/// Plausible size range for a standalone DER-encoded X.509 certificate.
const MIN_DER_CERT: usize = 128;
const MAX_DER_CERT: usize = 1 << 24; // 16 MiB

/// Directory basenames the walker never descends into.
const SKIP_DIRS: &[&str] = &[
    "proc", "sys", "dev", "run", "__pycache__", ".git", ".svn", ".hg",
];
/// Top-level roots we never scan.
const SYSTEM_SKIP_ROOTS: &[&str] = &["/proc", "/sys", "/dev", "/run", "/dev/shm"];

/// A certificate discovered inside some source blob.
#[derive(Debug, Clone)]
pub struct FoundCert {
    /// File path or `archive!/member`.
    pub source: String,
    /// `"pem"` or `"der"`.
    pub encoding: &'static str,
    pub offset: usize,
    pub size: usize,
    pub sha256: String,
    pub sha1: String,
    pub serial: String,
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub watch: Option<&'static RootWatch>,
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Skip files larger than this many bytes (also caps decompressed archive
    /// members).  `0` means no limit.
    pub max_size: u64,
    pub extract: bool,
    pub max_depth: usize,
    pub follow_symlinks: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            max_size: DEFAULT_MAX_FILE_SIZE,
            extract: true,
            max_depth: DEFAULT_MAX_DEPTH,
            follow_symlinks: false,
        }
    }
}

// --------------------------------------------------------------------------- //
// Certificate metadata
// --------------------------------------------------------------------------- //

struct Meta {
    sha256: String,
    sha1: String,
    serial: String,
    subject: String,
    issuer: String,
    not_before: String,
    not_after: String,
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// Parse exactly one DER certificate occupying all of `der`.
fn parse_meta(der: &[u8]) -> Option<Meta> {
    let (rest, cert) = X509Certificate::from_der(der).ok()?;
    if !rest.is_empty() {
        return None;
    }
    let serial = {
        // Serials are signed big-endian integers; render as the hex of the
        // integer: "-" prefix if negative, no leading zeros, "0" for zero.
        let raw = cert.raw_serial();
        let negative = raw.first().is_some_and(|b| b & 0x80 != 0);
        let magnitude: Vec<u8> = if negative {
            // Two's-complement negate.
            let mut v: Vec<u8> = raw.iter().map(|b| !b).collect();
            for b in v.iter_mut().rev() {
                let (n, carry) = b.overflowing_add(1);
                *b = n;
                if !carry {
                    break;
                }
            }
            v
        } else {
            raw.to_vec()
        };
        let h = hex(&magnitude);
        let h = h.trim_start_matches('0');
        let h = if h.is_empty() { "0" } else { h };
        if negative { format!("-{h}") } else { h.to_string() }
    };
    let validity = cert.validity();
    Some(Meta {
        sha256: hex(&Sha256::digest(der)),
        sha1: hex(&Sha1::digest(der)),
        serial,
        subject: rfc4514(cert.subject()),
        issuer: rfc4514(cert.issuer()),
        not_before: iso(&validity.not_before),
        not_after: iso(&validity.not_after),
    })
}

/// ISO-8601 UTC timestamp without zone suffix, e.g. `2018-02-18T18:30:00`.
fn iso(t: &ASN1Time) -> String {
    let dt = t.to_datetime();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

/// RFC 4514 string: RDNs in reverse order, multi-valued RDNs joined with `+`.
fn rfc4514(name: &X509Name) -> String {
    let rdns: Vec<String> = name
        .iter_rdn()
        .map(|rdn| {
            rdn.iter()
                .map(|atv| {
                    let oid = atv.attr_type().to_id_string();
                    let key = match oid.as_str() {
                        "2.5.4.3" => "CN",
                        "2.5.4.7" => "L",
                        "2.5.4.8" => "ST",
                        "2.5.4.10" => "O",
                        "2.5.4.11" => "OU",
                        "2.5.4.6" => "C",
                        "2.5.4.9" => "STREET",
                        "0.9.2342.19200300.100.1.25" => "DC",
                        "0.9.2342.19200300.100.1.1" => "UID",
                        other => other,
                    };
                    let value = match atv.as_str() {
                        Ok(s) => escape_dn_value(s),
                        Err(_) => legacy_string(atv.attr_value())
                            .map(|s| escape_dn_value(&s))
                            .unwrap_or_else(|| format!("#{}", hex(atv.attr_value().data))),
                    };
                    format!("{key}={value}")
                })
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect();
    rdns.into_iter().rev().collect::<Vec<_>>().join(",")
}

/// Decode string types `x509-parser` rejects: TeletexString (as Latin-1, like
/// OpenSSL / `cryptography`), BMPString (UTF-16BE) and UniversalString (UTF-32BE).
fn legacy_string(v: &x509_parser::der_parser::asn1_rs::Any) -> Option<String> {
    let d = v.data;
    match v.header.tag().0 {
        20 => Some(d.iter().map(|&b| b as char).collect()),
        30 if d.len() % 2 == 0 => String::from_utf16(
            &d.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect::<Vec<_>>(),
        )
        .ok(),
        28 if d.len() % 4 == 0 => d
            .chunks(4)
            .map(|c| char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]])))
            .collect(),
        _ => None,
    }
}

fn escape_dn_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for (i, ch) in v.chars().enumerate() {
        match ch {
            '\\' | '"' | '+' | ',' | ';' | '<' | '>' => {
                out.push('\\');
                out.push(ch);
            }
            '\0' => out.push_str("\\00"),
            '#' | ' ' if i == 0 => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    if out.ends_with(' ') && !out.ends_with("\\ ") {
        out.pop();
        out.push_str("\\ ");
    }
    out
}

fn make_found(source: &str, encoding: &'static str, offset: usize, size: usize, m: Meta) -> FoundCert {
    FoundCert {
        source: source.to_string(),
        encoding,
        offset,
        size,
        sha256: m.sha256,
        sha1: m.sha1,
        serial: m.serial,
        subject: m.subject,
        issuer: m.issuer,
        not_before: m.not_before,
        not_after: m.not_after,
        watch: None,
    }
}

// --------------------------------------------------------------------------- //
// PEM + DER extraction from an in-memory blob
// --------------------------------------------------------------------------- //

struct PemBlock {
    start: usize,
    end: usize,
    b64: (usize, usize),
}

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn is_b64_or_ws(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=') || is_ws(b)
}

/// Find every `-----BEGIN X-----` ... `-----END X-----` block whose body is
/// base64 text.  (The `regex` crate has no back-references, so this is done by
/// hand.)
fn find_pem_blocks(data: &[u8]) -> Vec<PemBlock> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    const DASHES: &[u8] = b"-----";
    let mut blocks = Vec::new();
    let mut pos = 0;
    while let Some(rel) = memmem::find(&data[pos..], BEGIN) {
        let start = pos + rel;
        let ty_start = start + BEGIN.len();
        let mut j = ty_start;
        while j < data.len() && data[j] != b'-' {
            j += 1;
        }
        if j == ty_start || !data[j..].starts_with(DASHES) {
            pos = start + 1;
            continue;
        }
        let ty = &data[ty_start..j];
        let body_start = j + DASHES.len();
        let mut marker = b"-----END ".to_vec();
        marker.extend_from_slice(ty);
        marker.extend_from_slice(DASHES);
        let Some(erel) = memmem::find(&data[body_start..], &marker) else {
            pos = start + 1;
            continue;
        };
        let body_end = body_start + erel;
        if body_end == body_start || !data[body_start..body_end].iter().all(|&b| is_b64_or_ws(b)) {
            pos = start + 1;
            continue;
        }
        let end = body_end + marker.len();
        blocks.push(PemBlock { start, end, b64: (body_start, body_end) });
        pos = end;
    }
    blocks
}

fn pem_to_der(b64: &[u8]) -> Option<Vec<u8>> {
    let cleaned: Vec<u8> = b64.iter().copied().filter(|&b| !is_ws(b)).collect();
    base64::engine::general_purpose::STANDARD.decode(cleaned).ok()
}

/// Return every certificate found in `data`.
///
/// Scans PEM blocks first, then raw DER `SEQUENCE` blobs.
pub fn scan_bytes(data: &[u8], source: &str) -> Vec<FoundCert> {
    let mut found = Vec::new();

    for blk in find_pem_blocks(data) {
        let Some(der) = pem_to_der(&data[blk.b64.0..blk.b64.1]) else { continue };
        let size = blk.end - blk.start;
        if let Some(meta) = parse_meta(&der) {
            found.push(make_found(source, "pem", blk.start, size, meta));
        } else if let Some((_, meta, _)) = find_der_certs(&der).into_iter().next() {
            // Wrapped form (e.g. OpenSSL "BEGIN TRUSTED CERTIFICATE"): the real
            // cert is the first inner SEQUENCE.
            found.push(make_found(source, "pem", blk.start, size, meta));
        }
    }

    for (offset, meta, total) in find_der_certs(data) {
        found.push(make_found(source, "der", offset, total, meta));
    }
    found
}

/// Read an ASN.1 length at `data[i + 1]` (`data[i]` is the tag).
/// Returns `(header_len, content_len)`.
fn read_length(data: &[u8], i: usize) -> Option<(usize, usize)> {
    let n = data.len();
    if i + 1 >= n {
        return None;
    }
    let first = data[i + 1];
    if first < 0x80 {
        return Some((2, first as usize));
    }
    if first == 0x80 {
        return None; // indefinite form
    }
    let num = (first & 0x7f) as usize;
    if num == 0 || num > 6 || i + 2 + num > n {
        return None;
    }
    let mut len: usize = 0;
    for j in 0..num {
        len = (len << 8) | data[i + 2 + j] as usize;
    }
    Some((2 + num, len))
}

/// Every DER certificate in `data` as `(offset, meta, total_len)`.
fn find_der_certs(data: &[u8]) -> Vec<(usize, Meta, usize)> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let Some(rel) = memchr::memchr(0x30, &data[pos..]) else { break };
        let idx = pos + rel;
        match parse_der_cert(data, idx) {
            Some((meta, total)) => {
                out.push((idx, meta, total));
                pos = idx + total;
            }
            None => pos = idx + 1,
        }
    }
    out
}

fn parse_der_cert(data: &[u8], i: usize) -> Option<(Meta, usize)> {
    let (header, content) = read_length(data, i)?;
    let total = header.checked_add(content)?;
    if !(MIN_DER_CERT..=MAX_DER_CERT).contains(&total) {
        return None;
    }
    let end = i.checked_add(total)?;
    if end > data.len() {
        return None;
    }
    parse_meta(&data[i..end]).map(|m| (m, total))
}

// --------------------------------------------------------------------------- //
// Archive handling
// --------------------------------------------------------------------------- //

#[derive(PartialEq, Eq, Debug)]
pub enum Format {
    Zip,
    Gzip,
    Tar,
}

/// Identify a blob's container format from its leading bytes.
pub fn detect_format(head: &[u8]) -> Option<Format> {
    if head.starts_with(b"PK") {
        return Some(Format::Zip);
    }
    if head.starts_with(&[0x1f, 0x8b]) {
        return Some(Format::Gzip);
    }
    if head.len() >= 262 && &head[257..262] == b"ustar" {
        return Some(Format::Tar);
    }
    None
}

/// Read at most `cap` bytes (0 = unlimited).  `None` if the stream is longer.
fn read_capped<R: Read>(mut r: R, cap: u64) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    if cap == 0 {
        r.read_to_end(&mut buf).ok()?;
    } else {
        r.take(cap + 1).read_to_end(&mut buf).ok()?;
        if buf.len() as u64 > cap {
            return None;
        }
    }
    Some(buf)
}

/// Call `f(label, bytes)` for every leaf (non-archive) blob, unpacking
/// archives recursively up to `max_depth`.
fn iter_leaves(label: &str, data: &[u8], depth: usize, opts: &ScanOptions, f: &mut dyn FnMut(&str, &[u8])) {
    if depth >= opts.max_depth {
        return f(label, data);
    }
    let Some(fmt) = detect_format(&data[..data.len().min(512)]) else {
        return f(label, data);
    };

    match fmt {
        Format::Zip => {
            let Ok(mut zf) = zip::ZipArchive::new(Cursor::new(data)) else {
                return f(label, data);
            };
            for i in 0..zf.len() {
                let Ok(entry) = zf.by_index(i) else { continue };
                if entry.is_dir() {
                    continue;
                }
                if opts.max_size > 0 && entry.size() > opts.max_size {
                    continue;
                }
                let name = entry.name().to_string();
                let Some(member) = read_capped(entry, opts.max_size) else { continue };
                iter_leaves(&format!("{label}!/{name}"), &member, depth + 1, opts, f);
            }
        }
        Format::Gzip => {
            let Some(decompressed) = read_capped(MultiGzDecoder::new(data), opts.max_size) else {
                return f(label, data);
            };
            // "app.tar.gz" -> "app.tar" so the next level reads naturally.
            let stripped = label.strip_suffix(".gz").unwrap_or(label);
            iter_leaves(stripped, &decompressed, depth + 1, opts, f);
        }
        Format::Tar => {
            let mut archive = tar::Archive::new(Cursor::new(data));
            let Ok(entries) = archive.entries() else {
                return f(label, data);
            };
            for entry in entries {
                let Ok(entry) = entry else { break };
                if !entry.header().entry_type().is_file() {
                    continue;
                }
                if opts.max_size > 0 && entry.header().size().unwrap_or(0) > opts.max_size {
                    continue;
                }
                let name = entry.path().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
                let Some(member) = read_capped(entry, opts.max_size) else { continue };
                iter_leaves(&format!("{label}!/{name}"), &member, depth + 1, opts, f);
            }
        }
    }
}

// --------------------------------------------------------------------------- //
// Public entry points
// --------------------------------------------------------------------------- //

fn read_file(path: &Path, max_size: u64) -> Option<Vec<u8>> {
    let meta = fs::metadata(path).ok()?;
    if max_size > 0 && meta.len() > max_size {
        return None;
    }
    fs::read(path).ok()
}

fn attach_watch(certs: &mut [FoundCert]) {
    for c in certs {
        c.watch = match_cert(&c.sha256, &c.sha1, &c.serial, &c.subject);
    }
}

/// Scan a single file (plain or archive).
pub fn scan_file(path: &Path, opts: &ScanOptions) -> Vec<FoundCert> {
    let Some(data) = read_file(path, opts.max_size) else { return Vec::new() };
    let display = path.to_string_lossy();
    let mut results = Vec::new();
    if opts.extract {
        iter_leaves(&display, &data, 0, opts, &mut |label, chunk| {
            results.extend(scan_bytes(chunk, label));
        });
    } else {
        results.extend(scan_bytes(&data, &display));
    }
    attach_watch(&mut results);
    results
}

/// Recursively scan `path` (file or directory tree).  `on_file(path, n_certs)`
/// is called after every regular file.
pub fn scan_path(path: &Path, opts: &ScanOptions, on_file: &mut dyn FnMut(&Path, usize)) -> Vec<FoundCert> {
    let mut results = Vec::new();

    // A top-level symlink to a file is scanned even without --follow-symlinks;
    // broken links / symlinked dirs are not descended into.
    let is_link = fs::symlink_metadata(path).map(|m| m.file_type().is_symlink()).unwrap_or(false);
    if is_link && !opts.follow_symlinks && !path.is_file() {
        return results;
    }

    let abs: PathBuf = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    if SYSTEM_SKIP_ROOTS.iter().any(|r| abs == Path::new(r)) {
        return results;
    }

    if path.is_file() {
        let certs = scan_file(path, opts);
        on_file(path, certs.len());
        results.extend(certs);
        return results;
    }

    if path.is_dir() {
        let walker = WalkDir::new(path)
            .follow_links(opts.follow_symlinks)
            .into_iter()
            .filter_entry(|e| {
                e.depth() == 0
                    || !(e.file_type().is_dir()
                        && e.file_name().to_str().is_some_and(|n| SKIP_DIRS.contains(&n)))
            });
        for entry in walker.flatten() {
            // Regular files only: skips symlinks (unless followed), FIFOs, sockets.
            if !entry.file_type().is_file() {
                continue;
            }
            let certs = scan_file(entry.path(), opts);
            on_file(entry.path(), certs.len());
            results.extend(certs);
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::KNOWN_ROOTS;
    use std::io::Write;

    fn g3_pem() -> &'static [u8] {
        KNOWN_ROOTS[0].pem
    }

    fn g3_der() -> Vec<u8> {
        let blk = &find_pem_blocks(g3_pem())[0];
        pem_to_der(&g3_pem()[blk.b64.0..blk.b64.1]).unwrap()
    }

    #[test]
    fn pem_is_found_and_matches_watchlist() {
        let mut found = scan_bytes(g3_pem(), "t");
        attach_watch(&mut found);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].encoding, "pem");
        assert_eq!(found[0].sha256, KNOWN_ROOTS[0].sha256);
        assert_eq!(found[0].sha1, KNOWN_ROOTS[0].sha1);
        assert_eq!(found[0].serial, KNOWN_ROOTS[0].serial);
        assert_eq!(found[0].watch.unwrap().severity, "compromised");
    }

    #[test]
    fn subject_and_validity_formats() {
        let found = scan_bytes(g3_pem(), "t");
        assert_eq!(found[0].subject, found[0].issuer);
        assert!(found[0].subject.contains("CN=emSign ECC Root CA - G3"));
        assert_eq!(found[0].not_before, "2018-02-18T18:30:00");
        assert_eq!(found[0].not_after, "2043-02-18T18:30:00");
    }

    #[test]
    fn raw_der_embedded_in_junk_is_found() {
        let der = g3_der();
        let mut blob = vec![0xAAu8; 37];
        blob.extend_from_slice(&der);
        blob.extend_from_slice(&[0x55u8; 11]);
        let found = scan_bytes(&blob, "t");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].encoding, "der");
        assert_eq!(found[0].offset, 37);
        assert_eq!(found[0].size, der.len());
    }

    #[test]
    fn garbage_and_truncated_certs_are_ignored() {
        assert!(scan_bytes(b"hello 0000 world", "t").is_empty());
        let der = g3_der();
        assert!(scan_bytes(&der[..der.len() - 5], "t").is_empty());
        assert!(scan_bytes(b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----", "t").is_empty());
    }

    #[test]
    fn end_marker_must_match_begin_type() {
        let text = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END PRIVATE KEY-----";
        assert!(find_pem_blocks(text).is_empty());
    }

    #[test]
    fn detect_format_cases() {
        assert_eq!(detect_format(b"PK\x03\x04rest"), Some(Format::Zip));
        assert_eq!(detect_format(&[0x1f, 0x8b, 8]), Some(Format::Gzip));
        let mut tarhead = vec![0u8; 300];
        tarhead[257..262].copy_from_slice(b"ustar");
        assert_eq!(detect_format(&tarhead), Some(Format::Tar));
        assert_eq!(detect_format(b"plain text"), None);
    }

    fn zip_with(name: &str, body: &[u8]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zw = zip::ZipWriter::new(&mut buf);
            zw.start_file(name, zip::write::SimpleFileOptions::default()).unwrap();
            zw.write_all(body).unwrap();
            zw.finish().unwrap();
        }
        buf.into_inner()
    }

    fn tar_gz_with(name: &str, body: &[u8]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar_bytes);
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, name, body).unwrap();
            b.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar_bytes).unwrap();
        gz.finish().unwrap()
    }

    fn leaves(label: &str, data: &[u8], opts: &ScanOptions) -> Vec<(String, usize)> {
        let mut out = Vec::new();
        iter_leaves(label, data, 0, opts, &mut |l, d| out.push((l.to_string(), d.len())));
        out
    }

    #[test]
    fn zip_member_is_unpacked() {
        let z = zip_with("META-INF/ca.pem", g3_pem());
        let l = leaves("app.jar", &z, &ScanOptions::default());
        assert_eq!(l, vec![("app.jar!/META-INF/ca.pem".to_string(), g3_pem().len())]);
    }

    #[test]
    fn tar_gz_member_is_unpacked_and_label_stripped() {
        let t = tar_gz_with("certs/ca.pem", g3_pem());
        let l = leaves("bundle.tar.gz", &t, &ScanOptions::default());
        assert_eq!(l, vec![("bundle.tar!/certs/ca.pem".to_string(), g3_pem().len())]);
    }

    #[test]
    fn max_depth_stops_unpacking() {
        let z = zip_with("a.pem", g3_pem());
        let opts = ScanOptions { max_depth: 0, ..ScanOptions::default() };
        let l = leaves("x.zip", &z, &opts);
        assert_eq!(l, vec![("x.zip".to_string(), z.len())]);
    }

    #[test]
    fn scan_path_walks_dir_and_respects_flags() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("ca.pem"), g3_pem()).unwrap();
        fs::write(dir.path().join("app.jar"), zip_with("in.pem", g3_pem())).unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        fs::write(dir.path().join(".git/skipped.pem"), g3_pem()).unwrap();

        let mut n_files = 0;
        let found = scan_path(dir.path(), &ScanOptions::default(), &mut |_, _| n_files += 1);
        assert_eq!(n_files, 2);
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|c| c.watch.is_some()));

        let no_extract = ScanOptions { extract: false, ..ScanOptions::default() };
        let found = scan_path(dir.path(), &no_extract, &mut |_, _| {});
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn nonexistent_path_returns_empty() {
        let found = scan_path(Path::new("/no/such/path/here"), &ScanOptions::default(), &mut |_, _| {});
        assert!(found.is_empty());
    }
}
