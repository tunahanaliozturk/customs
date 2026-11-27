//! The baseline of M4: a baseline written from a scan makes the same scan
//! exit 0, an update that changes nothing relevant stays accepted, and a
//! changed `Exec` command is reported as exactly that one finding. Also the
//! case of open question 16: whether a baseline settles the module
//! initialisers of legitimate build-time packages.

use std::fs;
use std::path::Path;

use crate::common::{TestResult, assembly, customs, zip};

/// Writes one extracted package into `root`, as restore leaves it.
fn package(root: &Path, id: &str, version: &str, files: &[(&str, &[u8])]) -> TestResult {
    let dir = root.join(id.to_lowercase()).join(version);
    fs::create_dir_all(&dir)?;
    fs::write(dir.join(".nupkg.metadata"), "{}")?;
    for (name, bytes) in files {
        let path = dir.join(name);
        fs::create_dir_all(path.parent().ok_or("no parent")?)?;
        fs::write(path, bytes)?;
    }
    Ok(())
}

/// A lock file in `dir` that resolves `id` to `version`.
fn lock(dir: &Path, id: &str, version: &str) -> TestResult {
    fs::write(
        dir.join("packages.lock.json"),
        format!(
            r#"{{"version": 1, "dependencies": {{"net8.0": {{"{id}": {{"type": "Direct", "resolved": "{version}"}}}}}}}}"#
        ),
    )?;
    Ok(())
}

fn targets(command: &str) -> Vec<u8> {
    format!(
        r#"<Project>
  <Target Name="Generate" BeforeTargets="Build">
    <Exec Command="{command}" />
  </Target>
</Project>
"#
    )
    .into_bytes()
}

const SCAN: [&str; 4] = ["scan", "packages.lock.json", "--packages-dir", "packages"];

fn scan(dir: &Path, more: &[&str]) -> TestResult<crate::common::Run> {
    let mut args = SCAN.to_vec();
    args.extend(more);
    customs(dir, &args)
}

/// The findings of a JSON report that the baseline does not accept.
fn open(report: &serde_json::Value) -> Vec<(String, String)> {
    report["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| f["accepted"] == false)
        .map(|f| {
            (
                f["rule"].as_str().unwrap_or_default().to_owned(),
                f["evidence"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect()
}

#[test]
fn a_baseline_accepts_a_scan_until_an_exec_command_changes() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("packages");
    let id = "Contoso.Gen";
    package(
        &root,
        id,
        "1.0.0",
        &[("build/Contoso.Gen.targets", &targets("gen --out obj"))],
    )?;
    lock(dir.path(), id, "1.0.0")?;

    // Without a baseline the Exec fails the scan.
    assert_eq!(scan(dir.path(), &[])?.code, 1);

    // Writing the baseline exits 0, and the same scan with it exits 0.
    let written = scan(dir.path(), &["--write-baseline", "customs-baseline.json"])?;
    assert_eq!(written.code, 0, "{}", written.stderr);
    // Its report agrees: everything it wrote is accepted.
    assert!(
        written
            .stdout
            .contains("(2 more accepted by the baseline)\nexit 0:"),
        "{}",
        written.stdout
    );
    let baseline: serde_json::Value = serde_json::from_str(&fs::read_to_string(
        dir.path().join("customs-baseline.json"),
    )?)?;
    assert_eq!(baseline["schema"], 1);
    let accepted = baseline["accepted"].as_array().ok_or("no accepted list")?;
    let listed: Vec<&str> = accepted.iter().filter_map(|e| e["rule"].as_str()).collect();
    assert_eq!(listed, ["C101", "C203"]);
    assert!(
        accepted
            .iter()
            .all(|e| e["package"] == id && e["note"] == "")
    );
    let again = scan(dir.path(), &["--baseline", "customs-baseline.json"])?;
    assert_eq!(again.code, 0, "{}", again.stdout);
    assert!(
        again
            .stdout
            .contains("0 errors, 0 warnings, 0 notes (2 more accepted by the baseline)"),
        "{}",
        again.stdout
    );

    // An update with the same content stays accepted: the fingerprint has
    // no version. Including the version would make this exit 1.
    package(
        &root,
        id,
        "1.1.0",
        &[("build/Contoso.Gen.targets", &targets("gen --out obj"))],
    )?;
    lock(dir.path(), id, "1.1.0")?;
    assert_eq!(
        scan(dir.path(), &["--baseline", "customs-baseline.json"])?.code,
        0
    );

    // The same command moved to another line stays accepted too.
    let moved = format!("\n\n{}", String::from_utf8(targets("gen --out obj"))?);
    package(
        &root,
        id,
        "1.1.1",
        &[("build/Contoso.Gen.targets", moved.as_bytes())],
    )?;
    lock(dir.path(), id, "1.1.1")?;
    assert_eq!(
        scan(dir.path(), &["--baseline", "customs-baseline.json"])?.code,
        0
    );

    // An update that changes the command is exactly that one finding.
    package(
        &root,
        id,
        "1.2.0",
        &[(
            "build/Contoso.Gen.targets",
            &targets("gen --out obj &amp;&amp; tool/payload.exe"),
        )],
    )?;
    lock(dir.path(), id, "1.2.0")?;
    let changed = scan(
        dir.path(),
        &["--baseline", "customs-baseline.json", "--format", "json"],
    )?;
    assert_eq!(changed.code, 1);
    let report = changed.json()?;
    assert_eq!(
        open(&report),
        [(
            "C203".to_owned(),
            "gen --out obj && tool/payload.exe".to_owned()
        )]
    );
    // C101 is still accepted, and says so.
    let c101 = report["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|f| f["rule"] == "C101")
        .ok_or("no C101")?;
    assert_eq!(c101["accepted"], true);
    Ok(())
}

#[test]
fn writing_a_baseline_again_keeps_the_reviewers_notes() -> TestResult {
    let dir = tempfile::tempdir()?;
    package(
        &dir.path().join("packages"),
        "Contoso.Gen",
        "1.0.0",
        &[("build/Contoso.Gen.targets", &targets("gen"))],
    )?;
    lock(dir.path(), "Contoso.Gen", "1.0.0")?;
    assert_eq!(scan(dir.path(), &["--write-baseline", "b.json"])?.code, 0);
    let path = dir.path().join("b.json");
    let text =
        fs::read_to_string(&path)?.replacen(r#""note": """#, r#""note": "runs our generator""#, 1);
    fs::write(&path, &text)?;
    assert_eq!(
        scan(
            dir.path(),
            &["--baseline", "b.json", "--write-baseline", "b.json"]
        )?
        .code,
        0
    );
    assert!(fs::read_to_string(&path)?.contains("runs our generator"));
    Ok(())
}

#[test]
fn a_baseline_can_accept_a_gap_and_the_gap_is_still_shown() -> TestResult {
    let dir = tempfile::tempdir()?;
    fs::create_dir_all(dir.path().join("packages"))?;
    lock(dir.path(), "Contoso.Missing", "1.0.0")?;
    assert_eq!(scan(dir.path(), &[])?.code, 3);
    assert_eq!(scan(dir.path(), &["--write-baseline", "b.json"])?.code, 0);
    let run = scan(dir.path(), &["--baseline", "b.json"])?;
    assert_eq!(run.code, 0, "{}", run.stdout);
    assert!(run.stdout.contains("1 gap"), "{}", run.stdout);
    assert!(
        run.stdout.contains("(accepted by the baseline)"),
        "{}",
        run.stdout
    );
    // On another machine the message names other folders; the gap stays
    // accepted, because its fingerprint leaves the message out.
    fs::create_dir_all(dir.path().join("elsewhere"))?;
    let moved = customs(
        dir.path(),
        &[
            "scan",
            "packages.lock.json",
            "--packages-dir",
            "elsewhere",
            "--baseline",
            "b.json",
        ],
    )?;
    assert!(moved.stdout.contains("elsewhere"), "{}", moved.stdout);
    assert_eq!(moved.code, 0, "{}", moved.stdout);
    Ok(())
}

#[test]
fn a_baseline_that_is_not_one_is_a_usage_error() -> TestResult {
    let dir = tempfile::tempdir()?;
    fs::create_dir_all(dir.path().join("packages"))?;
    lock(dir.path(), "Contoso.Gen", "1.0.0")?;
    for (name, text) in [
        ("schema.json", r#"{"schema": 2, "accepted": []}"#),
        (
            "short.json",
            r#"{"schema": 1, "accepted": [{"fingerprint": "abc", "rule": "C203", "package": "A", "path": null}]}"#,
        ),
        ("text.json", "not json"),
    ] {
        fs::write(dir.path().join(name), text)?;
        let run = scan(dir.path(), &["--baseline", name])?;
        assert_eq!(run.code, 2, "{name}");
        assert!(run.stdout.is_empty(), "{name}");
    }
    assert_eq!(scan(dir.path(), &["--baseline", "absent.json"])?.code, 2);
    Ok(())
}

/// The finding or gap of one rule in a JSON report, and whether it is accepted.
fn accepted(report: &serde_json::Value, list: &str, rule: &str) -> Vec<bool> {
    report[list]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| f["rule"] == rule)
        .map(|f| f["accepted"] == true)
        .collect()
}

/// A gap or a C003 with no path is told apart by its cause: accepting a
/// package that is not a zip archive does not accept, at a later release, an
/// archive that zip readers read differently, and accepting two root
/// nuspecs does not accept that either (review of M4, finding 1).
#[test]
fn accepting_one_cause_of_an_unread_package_does_not_accept_another() -> TestResult {
    let dir = tempfile::tempdir()?;
    let name = "Contoso.A.1.0.0.nupkg";
    let run = |more: &[&str]| {
        let mut args = vec!["scan", name, "--format", "json"];
        args.extend(more);
        customs(dir.path(), &args)
    };
    let mut layout = vec![b'J'; 64];
    layout.extend(zip(&[("lib/a.txt", b"x")])?);

    fs::write(dir.path().join(name), b"not a zip")?;
    assert_eq!(run(&["--write-baseline", "gap.json"])?.code, 0);
    fs::write(dir.path().join(name), &layout)?;
    let report = run(&["--baseline", "gap.json"])?.json()?;
    assert_eq!(accepted(&report, "incomplete", "C001"), [false], "{report}");

    fs::write(
        dir.path().join(name),
        zip(&[("a.nuspec", b"<a/>"), ("b.nuspec", b"<b/>")])?,
    )?;
    assert_eq!(run(&["--write-baseline", "c003.json"])?.code, 0);
    fs::write(dir.path().join(name), &layout)?;
    let report = run(&["--baseline", "c003.json"])?.json()?;
    assert_eq!(accepted(&report, "findings", "C003"), [false], "{report}");
    Ok(())
}

/// Open question 16: C301 is an error for nine build-time assemblies of
/// well-known packages in a local cache. A baseline settles it for a team
/// that uses them: the first scan fails, the accepted finding stays quiet
/// through an update that keeps the initialiser, and an initialiser whose
/// body changes size is reported again. What a baseline cannot settle is
/// the first scan of every new user; the severity stays an open decision.
#[test]
fn a_baseline_settles_a_module_initialiser_in_an_analyzer_until_it_changes() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("packages");
    let id = "Contoso.TestAdapter";
    let analyzer = "analyzers/dotnet/cs/Contoso.TestAdapter.dll";
    let init = assembly("ModuleInit.dll")?;
    package(&root, id, "4.0.2", &[(analyzer, &init)])?;
    lock(dir.path(), id, "4.0.2")?;

    let first = scan(dir.path(), &["--format", "json"])?;
    assert_eq!(first.code, 1);
    let report = first.json()?;
    let c301: Vec<_> = report["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| f["rule"] == "C301")
        .collect();
    assert_eq!(c301.len(), 1);
    assert_eq!(c301[0]["severity"], "error");

    assert_eq!(scan(dir.path(), &["--write-baseline", "b.json"])?.code, 0);
    assert_eq!(scan(dir.path(), &["--baseline", "b.json"])?.code, 0);

    // The next release ships the same initialiser: still accepted.
    package(&root, id, "4.0.3", &[(analyzer, &init)])?;
    lock(dir.path(), id, "4.0.3")?;
    assert_eq!(scan(dir.path(), &["--baseline", "b.json"])?.code, 0);

    // A release whose initialiser has a body of another size is new.
    package(&root, id, "4.0.4", &[(analyzer, &assembly("FatInit.dll")?)])?;
    lock(dir.path(), id, "4.0.4")?;
    let changed = scan(dir.path(), &["--baseline", "b.json", "--format", "json"])?;
    assert_eq!(changed.code, 1);
    let open = open(&changed.json()?);
    assert_eq!(open.len(), 1, "{open:?}");
    assert_eq!(open[0].0, "C301");
    Ok(())
}
