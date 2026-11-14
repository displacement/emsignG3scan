//! emsignG3scan — find bundled (untrusted) root CA certificates.
//!
//! Scans files, directory trees and archives for bundled root CA certificates
//! and flags watchlisted roots by SHA-256 fingerprint.

pub mod cli;
pub mod scanner;
pub mod signatures;
