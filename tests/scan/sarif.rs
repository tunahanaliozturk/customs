//! SARIF 2.1.0 output: every fixture scan validates against the OASIS JSON
//! schema committed in `tests/fixtures/sarif`, the fixture with findings
//! matches a golden file, and a result points at the line of its package in
//! the graph file.

use std::fs;

use crate::common::{TestResult, customs, fixtures, golden};

pub(crate) fn schema() -> TestResult<jsonschema::Validator> {
    let text = fs::read_to_string(fixtures().join("sarif").join("sarif-schema-2.1.0.json"))?;
    let schema: serde_json::Value = serde_json::from_str(&text)?;
    Ok(jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)?)
}

fn sarif(args: &[&str]) -> TestResult<(i32, String)> {
    let mut all = args.to_vec();
    all.extend(["--format", "sarif"]);
    let run = customs(&fixtures(), &all)?;
    Ok((run.code, run.stdout))
}

#[test]
fn every_fixture_scan_validates_against_the_sarif_schema() -> TestResult {
    let validator = schema()?;
    let scans: [&[&str]; 6] = [
        &[
            "scan",
            "lock-v1/packages.lock.json",
            "--packages-dir",
            "packages",
        ],
        &[
            "scan",
            "lock-v2/packages.lock.json",
            "--packages-dir",
            "packages",
        ],
        &["scan", "assets-v4/obj/project.assets.json"],
        &[
            "scan",
            "missing/packages.lock.json",
            "--packages-dir",
            "packages",
        ],
        &["scan", "--packages-dir", "packages"],
        &["scan", "lock-v1", "--packages-dir", "packages"],
    ];
    for args in scans {
        let (_, text) = sarif(args)?;
        let report: serde_json::Value = serde_json::from_str(&text)?;
        let errors: Vec<String> = validator
            .iter_errors(&report)
            .map(|e| format!("{} at {}", e, e.instance_path()))
            .collect();
        assert!(errors.is_empty(), "{args:?}:\n{}", errors.join("\n"));
    }
    Ok(())
}

#[test]
fn a_report_the_schema_rejects_is_caught() -> TestResult {
    // A positive control: the schema check is not a test that passes on
    // anything.
    let validator = schema()?;
    let (_, text) = sarif(&[
        "scan",
        "lock-v1/packages.lock.json",
        "--packages-dir",
        "packages",
    ])?;
    let mut report: serde_json::Value = serde_json::from_str(&text)?;
    report["runs"][0]["results"][0]["level"] = "warn".into();
    assert!(!validator.is_valid(&report));
    Ok(())
}

#[test]
fn findings_the_baseline_accepts_are_left_out_and_counted() -> TestResult {
    let validator = schema()?;
    let dir = tempfile::tempdir()?;
    let baseline = dir.path().join("baseline.json");
    let baseline = baseline.to_str().ok_or("path not UTF-8")?;
    let scan = [
        "scan",
        "lock-v1/packages.lock.json",
        "missing/packages.lock.json",
        "--packages-dir",
        "packages",
    ];
    let (code, _) = sarif(&[&scan[..], &["--write-baseline", baseline]].concat())?;
    assert_eq!(code, 0);
    let (code, text) = sarif(&[&scan[..], &["--baseline", baseline]].concat())?;
    assert_eq!(code, 0);
    let report: serde_json::Value = serde_json::from_str(&text)?;
    assert!(validator.is_valid(&report));
    let run = &report["runs"][0];
    assert_eq!(run["results"].as_array().map(Vec::len), Some(0), "{run}");
    let accepted = run["properties"]["acceptedByBaseline"]
        .as_u64()
        .ok_or("no count")?;
    assert!(accepted > 1, "{accepted}");
    // The gap of the missing package is still there, as a note.
    let notes = run["invocations"][0]["toolExecutionNotifications"]
        .as_array()
        .ok_or("no notifications")?;
    assert!(
        !notes.is_empty() && notes.iter().all(|n| n["level"] == "note"),
        "{notes:?}"
    );
    Ok(())
}

#[test]
fn the_sarif_of_the_lock_file_fixture_matches_the_golden_file() -> TestResult {
    let (code, text) = sarif(&[
        "scan",
        "lock-v1/packages.lock.json",
        "--packages-dir",
        "packages",
    ])?;
    assert_eq!(code, 1);
    golden("lock-v1.sarif", &text)
}

#[test]
fn a_result_points_at_the_line_of_its_package_in_the_graph_file() -> TestResult {
    let (_, text) = sarif(&[
        "scan",
        "lock-v1/packages.lock.json",
        "--packages-dir",
        "packages",
    ])?;
    let report: serde_json::Value = serde_json::from_str(&text)?;
    let lock = fs::read_to_string(fixtures().join("lock-v1").join("packages.lock.json"))?;
    let lines: Vec<&str> = lock.lines().collect();
    let results = report["runs"][0]["results"]
        .as_array()
        .ok_or("no results")?;
    assert_ne!(results.len(), 0);
    for result in results {
        let location = &result["locations"][0]["physicalLocation"];
        assert_eq!(
            location["artifactLocation"]["uri"],
            "lock-v1/packages.lock.json"
        );
        let line = location["region"]["startLine"].as_u64().ok_or("no line")?;
        let package = result["properties"]["package"]
            .as_str()
            .ok_or("no package")?;
        let text = lines[usize::try_from(line)? - 1];
        assert!(
            text.trim_start().starts_with(&format!("\"{package}\": {{")),
            "line {line} is {text:?}, not the entry of {package}"
        );
    }
    Ok(())
}
