//! Helpers shared by the integration tests. Every helper returns `Result`,
//! because clippy allows `unwrap` only inside test functions.

use std::error::Error;
use std::fs;
use std::io::{Cursor, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use zip::CompressionMethod;
use zip::write::{SimpleFileOptions, ZipWriter};

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// What one run of the binary produced.
#[derive(Debug)]
pub(crate) struct Run {
    pub(crate) code: i32,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

impl Run {
    /// The standard output parsed as JSON.
    pub(crate) fn json(&self) -> TestResult<serde_json::Value> {
        Ok(serde_json::from_str(&self.stdout)?)
    }
}

/// The directory that holds the committed fixtures.
pub(crate) fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

/// A compiled assembly from `tests/fixtures/assemblies`, by file name.
pub(crate) fn assembly(name: &str) -> TestResult<Vec<u8>> {
    Ok(fs::read(fixtures().join("assemblies").join(name))?)
}

/// Runs the binary in `dir` with `NUGET_PACKAGES` set to a relative folder
/// that does not exist, so that no real package folder on the machine is
/// consulted and the reports name the same folder on every system.
pub(crate) fn customs(dir: &Path, args: &[&str]) -> TestResult<Run> {
    let output = Command::new(env!("CARGO_BIN_EXE_customs"))
        .current_dir(dir)
        .args(args)
        .env("NUGET_PACKAGES", "no-such-cache")
        .output()?;
    Ok(Run {
        code: output
            .status
            .code()
            .ok_or("the binary was killed by a signal")?,
        stdout: String::from_utf8(output.stdout)?,
        stderr: String::from_utf8(output.stderr)?,
    })
}

/// Builds a zip archive in memory. Each entry is deflated unless its
/// content is empty.
pub(crate) fn zip(entries: &[(&str, &[u8])]) -> TestResult<Vec<u8>> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, content) in entries {
        let method = if content.is_empty() {
            CompressionMethod::Stored
        } else {
            CompressionMethod::Deflated
        };
        writer.start_file(
            *name,
            SimpleFileOptions::default().compression_method(method),
        )?;
        writer.write_all(content)?;
    }
    Ok(writer.finish()?.into_inner())
}

/// Writes `bytes` as `name` into a new temporary directory.
pub(crate) fn temp_file(name: &str, bytes: &[u8]) -> TestResult<tempfile::TempDir> {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join(name), bytes)?;
    Ok(dir)
}

/// Compares `actual` with a committed golden file, or rewrites the golden
/// file when `CUSTOMS_BLESS` is set.
pub(crate) fn golden(name: &str, actual: &str) -> TestResult {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join(name);
    if std::env::var_os("CUSTOMS_BLESS").is_some() {
        fs::create_dir_all(path.parent().ok_or("no parent")?)?;
        fs::write(&path, actual)?;
        return Ok(());
    }
    let expected = fs::read_to_string(&path).map_err(|e| {
        format!(
            "{}: {e}; run with CUSTOMS_BLESS=1 to create it",
            path.display()
        )
    })?;
    if expected == actual {
        Ok(())
    } else {
        Err(format!(
            "{name} differs from the golden file\n--- expected\n{expected}\n--- actual\n{actual}"
        )
        .into())
    }
}

/// The findings of one rule in a JSON report.
pub(crate) fn findings<'a>(
    report: &'a serde_json::Value,
    rule: &str,
) -> Vec<&'a serde_json::Value> {
    report["findings"]
        .as_array()
        .map(|all| all.iter().filter(|f| f["rule"] == rule).collect())
        .unwrap_or_default()
}

/// The gaps of one rule in a JSON report.
pub(crate) fn gaps<'a>(report: &'a serde_json::Value, rule: &str) -> Vec<&'a serde_json::Value> {
    report["incomplete"]
        .as_array()
        .map(|all| all.iter().filter(|g| g["rule"] == rule).collect())
        .unwrap_or_default()
}
