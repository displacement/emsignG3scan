//! Command-line interface.

use std::path::{Path, PathBuf};

use clap::{Parser, ValueEnum};
use serde::Serialize;

use crate::scanner::{scan_path, FoundCert, ScanOptions, DEFAULT_MAX_DEPTH};
use crate::signatures::{self, KNOWN_ROOTS};

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Parser)]
#[command(
    name = "emsignG3scan",
    about = "Scan application bundles, binaries and archives for bundled (and untrusted) \
             root CA certificates. By default only watchlist matches are reported; use --all to \
             dump everything found.",
    after_help = "Exit status is 0 when no watchlist match is found, 1 when at least one is, and \
                  2 on usage/operational error."
)]
struct Args {
    /// File or directory to scan (default: current dir)
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Report every certificate found, not only watchlist hits
    #[arg(long)]
    all: bool,

    /// Output format
    #[arg(long, value_enum, default_value = "text")]
    format: Format,

    /// Do not unpack archives; scan every file's raw bytes
    #[arg(long = "no-extract")]
    no_extract: bool,

    /// Skip files larger than SIZE (e.g. 256MiB, 1GiB). 0 = no limit.
    #[arg(long = "max-size", default_value = "256MiB", value_name = "SIZE")]
    max_size: String,

    /// Max archive extraction depth
    #[arg(long = "max-depth", default_value_t = DEFAULT_MAX_DEPTH, value_name = "N")]
    max_depth: usize,

    /// Follow symbolic links when walking directories
    #[arg(long = "follow-symlinks")]
    follow_symlinks: bool,

    /// Verify bundled reference certs match embedded fingerprints, then exit
    #[arg(long)]
    verify: bool,

    #[arg(short, long)]
    verbose: bool,
}

/// Parse sizes like `256m`, `1g`, `512MiB`, `4096`.
fn parse_size(text: &str) -> Option<u64> {
    let t = text.trim().to_lowercase();
    const UNITS: &[(&str, f64)] = &[
        ("gib", 1_073_741_824.0),
        ("mib", 1_048_576.0),
        ("kib", 1024.0),
        ("gb", 1e9),
        ("mb", 1e6),
        ("kb", 1e3),
        ("g", 1_073_741_824.0),
        ("m", 1_048_576.0),
        ("k", 1024.0),
    ];
    for (suffix, factor) in UNITS {
        if let Some(num) = t.strip_suffix(suffix) {
            let v: f64 = num.trim().parse().ok()?;
            return if v < 0.0 { Some(0) } else { Some((v * factor) as u64) };
        }
    }
    t.parse::<i64>().ok().map(|v| v.max(0) as u64)
}

fn is_reported(f: &FoundCert, args: &Args) -> bool {
    args.all || f.watch.is_some()
}

fn print_text(findings: &[&FoundCert], scanned: &Path, total_found: usize, files_scanned: usize, all: bool) {
    let scanned = scanned.display();
    if findings.is_empty() {
        let tail = if all { "none matched the watchlist." } else { "no watchlist match." };
        println!(
            "emsignG3scan: scanned {scanned} — {total_found} certificate(s) found in \
             {files_scanned} file(s); {tail}"
        );
        return;
    }
    println!("emsignG3scan: scanned {scanned}");
    println!(
        "  files scanned: {files_scanned} | certs found: {total_found} | watchlist hits: {}",
        findings.len()
    );
    println!();
    for f in findings {
        let (sev, label) = match f.watch {
            Some(w) => (w.severity.to_uppercase(), w.label.to_string()),
            None => ("OK".to_string(), format!("cert {}…", &f.sha256[..12])),
        };
        println!("[{sev}] {label}");
        println!("        source : {}", f.source);
        println!("        encoding: {} @ offset {}", f.encoding, f.offset);
        println!("        subject : {}", f.subject);
        println!("        serial  : {}", f.serial);
        println!("        sha1    : {}", f.sha1);
        println!("        sha256  : {}", f.sha256);
        println!("        validity: {} → {}", f.not_before, f.not_after);
        if let Some(w) = f.watch {
            println!("        reason  : {}", w.reason);
        }
        println!();
    }
}

#[derive(Serialize)]
struct JsonMatch {
    label: &'static str,
    severity: &'static str,
    reason: &'static str,
}

#[derive(Serialize)]
struct JsonHit<'a> {
    source: &'a str,
    encoding: &'a str,
    offset: usize,
    size: usize,
    sha256: &'a str,
    sha1: &'a str,
    serial: &'a str,
    subject: &'a str,
    issuer: &'a str,
    not_before: &'a str,
    not_after: &'a str,
    matches: Option<JsonMatch>,
}

#[derive(Serialize)]
struct JsonReport<'a> {
    tool: &'static str,
    scanned_path: String,
    files_scanned: usize,
    certs_found: usize,
    watchlist_entries: Vec<&'static str>,
    hits: Vec<JsonHit<'a>>,
}

fn print_json(findings: &[&FoundCert], scanned: &Path, total_found: usize, files_scanned: usize) {
    let report = JsonReport {
        tool: "emsignG3scan",
        scanned_path: scanned.display().to_string(),
        files_scanned,
        certs_found: total_found,
        watchlist_entries: KNOWN_ROOTS.iter().map(|r| r.label).collect(),
        hits: findings
            .iter()
            .map(|f| JsonHit {
                source: &f.source,
                encoding: f.encoding,
                offset: f.offset,
                size: f.size,
                sha256: &f.sha256,
                sha1: &f.sha1,
                serial: &f.serial,
                subject: &f.subject,
                issuer: &f.issuer,
                not_before: &f.not_before,
                not_after: &f.not_after,
                matches: f.watch.map(|w| JsonMatch {
                    label: w.label,
                    severity: w.severity,
                    reason: w.reason,
                }),
            })
            .collect(),
    };
    println!("{}", serde_json::to_string_pretty(&report).expect("serialisable"));
}

/// Run the CLI and return the process exit status.
pub fn run() -> i32 {
    let args = Args::parse();

    if args.verify {
        if signatures::self_check() {
            println!(
                "emsignG3scan verify: OK — bundled reference certs match the embedded \
                 watchlist fingerprints."
            );
            return 0;
        }
        eprintln!(
            "emsignG3scan verify: FAIL — fingerprint mismatch; the bundled reference PEMs do \
             not match the watchlist."
        );
        return 2;
    }

    let Some(max_size) = parse_size(&args.max_size) else {
        eprintln!("emsignG3scan: error: invalid --max-size {:?}", args.max_size);
        return 2;
    };

    if !args.path.exists() && std::fs::symlink_metadata(&args.path).is_err() {
        // Exit status stays 0 (nothing found), but say so, so a mistyped path
        // isn't mistaken for a clean scan.
        eprintln!("emsignG3scan: warning: {} does not exist", args.path.display());
    }

    let opts = ScanOptions {
        max_size,
        extract: !args.no_extract,
        max_depth: args.max_depth,
        follow_symlinks: args.follow_symlinks,
    };

    let mut files_scanned = 0usize;
    let verbose = args.verbose;
    let findings = scan_path(&args.path, &opts, &mut |path, n| {
        files_scanned += 1;
        if verbose {
            let tag = if n > 0 { format!("{n} cert(s)") } else { "no certs".to_string() };
            eprintln!("[scan] {} ({tag})", path.display());
        }
    });

    let shown: Vec<&FoundCert> = findings.iter().filter(|f| is_reported(f, &args)).collect();
    let total_found = findings.len();

    match args.format {
        Format::Json => print_json(&shown, &args.path, total_found, files_scanned),
        Format::Text => print_text(&shown, &args.path, total_found, files_scanned, args.all),
    }

    // --all never drives the exit code: any watchlist match does.
    let hit = findings.iter().any(|f| f.watch.is_some());
    if hit { 1 } else { 0 }
}
