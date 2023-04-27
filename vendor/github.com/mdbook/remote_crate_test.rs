//! A Test module confirming the functionality of `cargo->bazel` with remote crates.

use std::path::PathBuf;
use std::process::Command;

#[test]
fn test_executable() {
    let exe = PathBuf::from(env!("EXECUTABLE"));

    let output = Command::new(exe)
        .arg("--help")
        .output()
        .expect("Failed to run executable");

    let text = String::from_utf8(output.stdout).unwrap();
    // Test option `build` in mdbook_bin
    assert!(text.contains("Builds a book from its markdown files"));
}
