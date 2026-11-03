//! End-to-end tests that run the compiled binary.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output};

const G3_PEM: &[u8] = include_bytes!("../data/emSign_ECC_Root_CA_G3.pem");
const G1_PEM: &[u8] = include_bytes!("../data/emSign_Root_CA_G1.pem");
const G3_SHA256: &str = "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b";

fn run(args: &[&str]) -> (i32, String, String) {
    let Output { status, stdout, stderr } =
        Command::new(env!("CARGO_BIN_EXE_emsignG3scan")).args(args).output().unwrap();
    (
        status.code().unwrap(),
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn jar_with(path: &Path, member: &str, body: &[u8]) {
    let mut zw = zip::ZipWriter::new(fs::File::create(path).unwrap());
    zw.start_file(member, zip::write::SimpleFileOptions::default()).unwrap();
    zw.write_all(body).unwrap();
    zw.finish().unwrap();
}

#[test]
fn finds_compromised_cert_and_exits_1() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("trust.pem"), G3_PEM).unwrap();
    let (rc, out, _) = run(&[p(dir.path())]);
    assert_eq!(rc, 1);
    assert!(out.contains("[COMPROMISED] emSign ECC Root CA - G3"));
    assert!(out.contains(G3_SHA256));
}

#[test]
fn related_root_only_reported_with_strict() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("g1.pem"), G1_PEM).unwrap();
    let (rc, out, _) = run(&[p(dir.path())]);
    assert_eq!(rc, 0);
    assert!(out.contains("no watchlist match"));
    let (rc, out, _) = run(&["--strict", p(dir.path())]);
    assert_eq!(rc, 1);
    assert!(out.contains("[RELATED] emSign Root CA - G1"));
}

#[test]
fn json_output_has_hits() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("trust.pem"), G3_PEM).unwrap();
    let (rc, out, _) = run(&["--format", "json", p(dir.path())]);
    assert_eq!(rc, 1);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["tool"], "emsignG3scan");
    assert_eq!(v["hits"][0]["sha256"], G3_SHA256);
    assert_eq!(v["hits"][0]["matches"]["severity"], "compromised");
}

#[test]
fn all_lists_non_watchlist_certs_but_does_not_change_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("g1.pem"), G1_PEM).unwrap();
    let (rc, out, _) = run(&["--all", p(dir.path())]);
    assert_eq!(rc, 0);
    assert!(out.contains("emSign Root CA - G1"));
}

#[test]
fn nested_archive_is_unpacked_unless_no_extract() {
    let dir = tempfile::tempdir().unwrap();
    let jar = dir.path().join("app.jar");
    jar_with(&jar, "META-INF/ca.pem", G3_PEM);
    let (rc, out, _) = run(&[p(&jar)]);
    assert_eq!(rc, 1);
    assert!(out.contains("app.jar!/META-INF/ca.pem"));
    let (rc, out, _) = run(&["--no-extract", p(&jar)]);
    assert_eq!(rc, 0);
    assert!(out.contains("no watchlist match"));
}

#[test]
fn ignores_non_certificate_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("readme.txt"), "hello world, no certs here").unwrap();
    let (rc, out, _) = run(&[p(dir.path())]);
    assert_eq!(rc, 0);
    assert!(out.contains("no watchlist match"));
}

#[test]
fn nonexistent_path_warns_but_exits_0() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope");
    let (rc, out, err) = run(&[p(&missing)]);
    assert_eq!(rc, 0);
    assert!(out.contains("no watchlist match"));
    assert!(err.contains("does not exist"));
}

#[test]
fn max_size_skips_large_files_and_zero_means_unlimited() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("trust.pem"), G3_PEM).unwrap();
    let (rc, _, _) = run(&["--max-size", "10", p(dir.path())]);
    assert_eq!(rc, 0);
    let (rc, _, _) = run(&["--max-size", "0", p(dir.path())]);
    assert_eq!(rc, 1);
}

#[test]
fn bad_max_size_is_a_usage_error() {
    let (rc, _, err) = run(&["--max-size", "lots"]);
    assert_eq!(rc, 2);
    assert!(err.contains("invalid --max-size"));
}

#[test]
fn verify_succeeds() {
    let (rc, out, _) = run(&["--verify"]);
    assert_eq!(rc, 0);
    assert!(out.contains("OK"));
}
