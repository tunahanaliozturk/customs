//! The benign corpus test: every finding customs reports on the 300 most
//! downloaded packages must be in `corpus/benign-expected.txt`, every line
//! there must still be reported, and no finding may be an error. Ignored by
//! default, because it needs the packages:
//!
//! ```text
//! python corpus/corpus.py fetch
//! cargo test --release -- --ignored corpus
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The archive names of the pinned packages, as `corpus.py fetch` writes them.
fn pinned(root: &Path) -> TestResult<Vec<String>> {
    let list = fs::read_to_string(root.join("corpus").join("benign.txt"))?;
    Ok(list
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let mut fields = l.split_whitespace();
            let id = fields.next()?.to_lowercase();
            let version = fields.next()?.split('+').next()?.to_lowercase();
            Some(format!("{id}.{version}.nupkg"))
        })
        .collect())
}

/// The expected notes per rule, and the expected warning and error lines
/// without their reasons.
fn expected(root: &Path) -> TestResult<(BTreeMap<String, u64>, BTreeSet<String>)> {
    let text = fs::read_to_string(root.join("corpus").join("benign-expected.txt"))?;
    let mut notes = BTreeMap::new();
    let mut listed = BTreeSet::new();
    for line in text
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        if let Some(rest) = line.strip_prefix("notes ") {
            let (rule, count) = rest.split_once(' ').ok_or("bad notes line")?;
            notes.insert(rule.to_owned(), count.trim().parse()?);
        } else {
            let (key, reason) = line.rsplit_once(" | ").ok_or("a line without a reason")?;
            if reason.trim().is_empty() {
                return Err(format!("no reason given: {line}").into());
            }
            listed.insert(key.to_owned());
        }
    }
    Ok((notes, listed))
}

fn key(finding: &serde_json::Value) -> String {
    let text = |name: &str| finding[name].as_str().unwrap_or_default().to_owned();
    let evidence = text("evidence")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    // Assembly findings have no line: `path`, not `path:null`.
    let place = match finding["line"].as_u64() {
        Some(line) => format!("{}:{line}", text("path")),
        None => text("path"),
    };
    format!(
        "{} {} {} {place} {evidence}",
        text("package"),
        text("version"),
        text("rule"),
    )
}

#[test]
#[ignore = "needs the corpus: python corpus/corpus.py fetch"]
fn the_benign_corpus_produces_only_the_reviewed_findings() -> TestResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = root.join("target").join("corpus");
    let names = pinned(root)?;
    let missing: Vec<&String> = names.iter().filter(|n| !dir.join(n).is_file()).collect();
    if !missing.is_empty() {
        return Err(format!(
            "{} packages missing in {}; run python corpus/corpus.py fetch",
            missing.len(),
            dir.display()
        )
        .into());
    }
    let output = Command::new(env!("CARGO_BIN_EXE_customs"))
        .current_dir(&dir)
        .arg("scan")
        .args(&names)
        .args(["--format", "json", "--fail-on", "never"])
        .output()?;
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        report["packages"].as_array().map(Vec::len),
        Some(names.len())
    );
    assert_eq!(
        report["incomplete"],
        serde_json::json!([]),
        "gaps in the corpus"
    );

    let (expected_notes, expected_listed) = expected(root)?;
    let mut notes: BTreeMap<String, u64> = BTreeMap::new();
    let mut listed = BTreeSet::new();
    for finding in report["findings"].as_array().ok_or("no findings array")? {
        let rule = finding["rule"].as_str().unwrap_or_default().to_owned();
        match finding["severity"].as_str() {
            Some("note") => *notes.entry(rule).or_default() += 1,
            Some("error") => return Err(format!("an error in the corpus: {}", key(finding)).into()),
            _ => {
                listed.insert(key(finding));
            }
        }
    }
    let unlisted: Vec<&String> = listed.difference(&expected_listed).collect();
    let gone: Vec<&String> = expected_listed.difference(&listed).collect();
    assert!(
        unlisted.is_empty() && gone.is_empty(),
        "not in benign-expected.txt:\n{}\n\nlisted but not reported:\n{}",
        unlisted
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        gone.iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert_eq!(notes, expected_notes, "note counts per rule");
    Ok(())
}
