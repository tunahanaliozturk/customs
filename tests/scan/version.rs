//! The scaffold binary prints its name and version and exits with success.

use std::process::Command;

#[test]
fn the_binary_prints_its_name_and_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_customs"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout.trim(),
        format!("customs {}", env!("CARGO_PKG_VERSION"))
    );
}
