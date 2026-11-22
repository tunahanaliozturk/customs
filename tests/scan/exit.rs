//! Exit tests 2 to 4 of M1, and the behaviour the design implies around them:
//! exit code precedence, entries that collide ignoring case, escaping of
//! package text, skipped `Project` entries and links in package folders.

use std::fs;

use crate::common::{TestResult, customs, findings, fixtures, gaps, temp_file, zip};

/// The most bytes M1 reads from one entry: enough to tell PE, ELF and
/// Mach-O apart.
const SNIFF_BYTES: u64 = 64;

fn bytes_read(report: &serde_json::Value) -> TestResult<u64> {
    report["packages"][0]["read"]["bytes"]
        .as_u64()
        .ok_or_else(|| "no read.bytes in the report".into())
}

#[test]
fn a_build_folder_in_capitals_is_classified_as_build_assets() -> TestResult {
    // In an extracted package folder.
    let report = customs(
        &fixtures(),
        &[
            "scan",
            "lock-v2/packages.lock.json",
            "--packages-dir",
            "packages",
            "--format",
            "json",
        ],
    )?
    .json()?;
    let build = findings(&report, "C101");
    assert!(
        build
            .iter()
            .any(|f| f["package"] == "Contoso.Shouting"
                && f["path"] == "BUILD/Contoso.Shouting.targets"),
        "{build:?}"
    );

    // And in an archive, with the other folder names in odd cases too.
    let archive = zip(&[
        ("BUILD/Contoso.Shouting.targets", b"<Project />"),
        ("BuildTransitive/Contoso.Shouting.props", b"<Project />"),
        ("Analyzers/dotnet/cs/Contoso.Shouting.dll", b"MZ"),
        ("TOOLS/init.ps1", b"# fixture"),
    ])?;
    let dir = temp_file("contoso.shouting.1.0.0.nupkg", &archive)?;
    let report = customs(
        dir.path(),
        &["scan", "contoso.shouting.1.0.0.nupkg", "--format", "json"],
    )?
    .json()?;
    assert_eq!(findings(&report, "C101").len(), 1);
    assert_eq!(
        findings(&report, "C101")[0]["path"],
        "BUILD/Contoso.Shouting.targets"
    );
    assert_eq!(findings(&report, "C102").len(), 1);
    assert_eq!(findings(&report, "C103").len(), 1);
    Ok(())
}

#[test]
fn a_zip_bomb_ends_as_a_gap_without_being_decompressed() -> TestResult {
    let zeros = vec![0_u8; 16 * 1024 * 1024];
    let archive = zip(&[("runtimes/linux-x64/native/libbomb.so", &zeros)])?;
    assert!(archive.len() < 100 * 1024, "the bomb is not a bomb");
    let dir = temp_file("contoso.bomb.1.0.0.nupkg", &archive)?;

    let run = customs(
        dir.path(),
        &["scan", "contoso.bomb.1.0.0.nupkg", "--format", "json"],
    )?;
    assert_eq!(run.code, 3, "{}", run.stderr);
    let report = run.json()?;
    let limit = gaps(&report, "C002");
    assert_eq!(limit.len(), 1, "{report}");
    assert!(
        limit[0]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("decompression ratio")
    );
    assert_eq!(limit[0]["path"], "runtimes/linux-x64/native/libbomb.so");
    assert_eq!(bytes_read(&report)?, 0);
    Ok(())
}

#[test]
fn a_declared_uncompressed_size_is_never_trusted() -> TestResult {
    // The same bomb, but both headers claim the entry is 64 bytes long, so
    // the ratio looks harmless. The read still stops at the cap.
    let zeros = vec![0_u8; 16 * 1024 * 1024];
    let mut archive = zip(&[("runtimes/linux-x64/native/libbomb.so", &zeros)])?;
    patch_u32(&mut archive, &[0x50, 0x4b, 0x03, 0x04], 22, 64)?;
    patch_u32(&mut archive, &[0x50, 0x4b, 0x01, 0x02], 24, 64)?;
    let dir = temp_file("contoso.liar.1.0.0.nupkg", &archive)?;

    let run = customs(
        dir.path(),
        &["scan", "contoso.liar.1.0.0.nupkg", "--format", "json"],
    )?;
    let report = run.json()?;
    assert!(bytes_read(&report)? <= SNIFF_BYTES, "{report}");
    assert!(run.code == 0 || run.code == 3, "{}", run.stderr);
    Ok(())
}

#[test]
fn an_archive_with_50001_entries_ends_as_a_gap_before_any_entry_is_read() -> TestResult {
    let names: Vec<String> = (0..50_001).map(|i| format!("content/{i}.txt")).collect();
    let entries: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b""[..])).collect();
    let dir = temp_file("contoso.many.1.0.0.nupkg", &zip(&entries)?)?;

    let run = customs(
        dir.path(),
        &["scan", "contoso.many.1.0.0.nupkg", "--format", "json"],
    )?;
    assert_eq!(run.code, 3, "{}", run.stderr);
    let report = run.json()?;
    let limit = gaps(&report, "C002");
    assert_eq!(limit.len(), 1, "{report}");
    assert!(
        limit[0]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("entries")
    );
    assert_eq!(bytes_read(&report)?, 0);
    assert_eq!(report["packages"][0]["read"]["entries"], 0);
    Ok(())
}

#[test]
fn an_archive_entry_that_leaves_the_package_is_c003() -> TestResult {
    let archive = zip(&[
        ("../evil.targets", b"<Project />"),
        ("build/%2E%2E/%2E%2E/encoded.targets", b"<Project />"),
        ("/rooted.targets", b"<Project />"),
        ("C:/drive.targets", b"<Project />"),
        ("lib/net8.0/Contoso.Escape.dll", b"MZ"),
    ])?;
    let dir = temp_file("contoso.escape.1.0.0.nupkg", &archive)?;

    let run = customs(
        dir.path(),
        &["scan", "contoso.escape.1.0.0.nupkg", "--format", "json"],
    )?;
    assert_eq!(run.code, 1, "{}", run.stderr);
    let report = run.json()?;
    let unsafe_paths = findings(&report, "C003");
    assert_eq!(unsafe_paths.len(), 4, "{report}");
    assert!(unsafe_paths.iter().all(|f| f["severity"] == "warning"));
    // None of them is taken for a build asset.
    assert!(findings(&report, "C101").is_empty(), "{report}");
    assert!(bytes_read(&report)? <= SNIFF_BYTES);
    Ok(())
}

#[test]
fn a_graph_naming_a_package_not_on_disk_exits_3() -> TestResult {
    let run = customs(
        &fixtures(),
        &[
            "scan",
            "missing/packages.lock.json",
            "--packages-dir",
            "packages",
            "--format",
            "json",
        ],
    )?;
    assert_eq!(run.code, 3, "{}", run.stderr);
    let report = run.json()?;
    let missing = gaps(&report, "C001");
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0]["package"], "Contoso.Missing");
    Ok(())
}

#[test]
fn exit_codes_take_precedence_2_then_1_then_3() -> TestResult {
    // A warning (C003) and a gap (C001) together.
    let archive = zip(&[("../evil.targets", b"<Project />")])?;
    let dir = temp_file("contoso.escape.1.0.0.nupkg", &archive)?;
    fs::copy(
        fixtures().join("missing/packages.lock.json"),
        dir.path().join("packages.lock.json"),
    )?;
    let both = ["scan", "packages.lock.json", "contoso.escape.1.0.0.nupkg"];

    assert_eq!(customs(dir.path(), &both)?.code, 1);
    let mut never = both.to_vec();
    never.extend(["--fail-on", "never"]);
    assert_eq!(customs(dir.path(), &never)?.code, 3);
    let mut errors_only = both.to_vec();
    errors_only.extend(["--fail-on", "error"]);
    assert_eq!(customs(dir.path(), &errors_only)?.code, 3);
    let mut notes = both.to_vec();
    notes.extend(["--fail-on", "note"]);
    assert_eq!(customs(dir.path(), &notes)?.code, 1);
    let mut usage = both.to_vec();
    usage.extend(["--fail-on", "sometimes"]);
    assert_eq!(customs(dir.path(), &usage)?.code, 2);
    // An input that is not a graph at all is a usage error too.
    fs::write(dir.path().join("broken.json"), "{ not json")?;
    let mut broken = both.to_vec();
    broken.push("broken.json");
    assert_eq!(customs(dir.path(), &broken)?.code, 2);
    Ok(())
}

#[test]
fn a_clean_scan_with_fail_on_note_exits_1_for_inventory_notes() -> TestResult {
    let args = [
        "scan",
        "lock-v1/packages.lock.json",
        "--packages-dir",
        "packages",
        "--fail-on",
        "note",
    ];
    assert_eq!(customs(&fixtures(), &args)?.code, 1);
    Ok(())
}

#[test]
fn two_entries_equal_ignoring_case_are_c003() -> TestResult {
    let archive = zip(&[
        ("build/Contoso.Twins.targets", b"<Project />"),
        ("BUILD/contoso.twins.TARGETS", b"<Project Sdk='x' />"),
    ])?;
    let dir = temp_file("contoso.twins.1.0.0.nupkg", &archive)?;
    let report = customs(
        dir.path(),
        &["scan", "contoso.twins.1.0.0.nupkg", "--format", "json"],
    )?
    .json()?;
    let twins = findings(&report, "C003");
    assert_eq!(twins.len(), 1, "{report}");
    let message = twins[0]["message"].as_str().unwrap_or_default();
    assert!(message.contains("build/Contoso.Twins.targets"));
    assert!(message.contains("BUILD/contoso.twins.TARGETS"));
    Ok(())
}

#[test]
fn ansi_escapes_and_bidi_overrides_in_package_paths_print_escaped() -> TestResult {
    let name = "build/\u{1b}[31mred\u{202e}stegrat.targets";
    let archive = zip(&[(name, b"<Project />")])?;
    let dir = temp_file("contoso.paint.1.0.0.nupkg", &archive)?;

    let text = customs(dir.path(), &["scan", "contoso.paint.1.0.0.nupkg"])?;
    assert!(!text.stdout.contains('\u{1b}'), "{:?}", text.stdout);
    assert!(!text.stdout.contains('\u{202e}'), "{:?}", text.stdout);
    assert!(
        text.stdout
            .contains(r"build/\u{1b}[31mred\u{202e}stegrat.targets"),
        "{}",
        text.stdout
    );

    // JSON keeps the text, escaped by the JSON encoder where it must be.
    let json = customs(
        dir.path(),
        &["scan", "contoso.paint.1.0.0.nupkg", "--format", "json"],
    )?;
    assert!(!json.stdout.contains('\u{1b}'));
    assert_eq!(findings(&json.json()?, "C101")[0]["path"], name);
    Ok(())
}

#[test]
fn a_project_entry_in_a_lock_file_is_skipped() -> TestResult {
    let report = customs(
        &fixtures(),
        &[
            "scan",
            "lock-v1/packages.lock.json",
            "--packages-dir",
            "packages",
            "--format",
            "json",
        ],
    )?
    .json()?;
    let ids: Vec<&str> = report["packages"]
        .as_array()
        .ok_or("no packages")?
        .iter()
        .filter_map(|p| p["id"].as_str())
        .collect();
    assert!(
        !ids.iter()
            .any(|id| id.eq_ignore_ascii_case("contoso.app.core")),
        "{ids:?}"
    );
    assert_eq!(ids.len(), 4, "{ids:?}");
    Ok(())
}

#[test]
fn a_link_inside_an_extracted_package_folder_is_not_followed() -> TestResult {
    let root = tempfile::tempdir()?;
    let outside = root.path().join("outside");
    fs::create_dir_all(&outside)?;
    fs::write(outside.join("Hidden.targets"), "<Project />")?;
    let package = root.path().join("packages/contoso.linked/1.0.0");
    fs::create_dir_all(&package)?;
    fs::write(package.join(".nupkg.metadata"), "{}")?;
    if !link_dir(&outside, &package.join("build")) {
        // Creating links needs a privilege on Windows that the test may
        // not have. Linux and macOS CI always run this test.
        return Ok(());
    }

    let run = customs(
        root.path(),
        &["scan", "--packages-dir", "packages", "--format", "json"],
    )?;
    let report = run.json()?;
    assert!(
        findings(&report, "C101").is_empty(),
        "the link was followed: {report}"
    );
    let links = findings(&report, "C003");
    assert_eq!(links.len(), 1, "{report}");
    assert_eq!(links[0]["path"], "build");
    assert_eq!(run.code, 1);
    Ok(())
}

#[cfg(unix)]
fn link_dir(target: &std::path::Path, link: &std::path::Path) -> bool {
    std::os::unix::fs::symlink(target, link).is_ok()
}

#[cfg(windows)]
fn link_dir(target: &std::path::Path, link: &std::path::Path) -> bool {
    std::os::windows::fs::symlink_dir(target, link).is_ok()
}

/// Overwrites the little-endian `u32` at `offset` after the first
/// occurrence of `signature`.
fn patch_u32(bytes: &mut [u8], signature: &[u8], offset: usize, value: u32) -> TestResult {
    let start = bytes
        .windows(signature.len())
        .position(|w| w == signature)
        .ok_or("signature not found")?;
    let field = bytes
        .get_mut(start + offset..start + offset + 4)
        .ok_or("field out of range")?;
    field.copy_from_slice(&value.to_le_bytes());
    Ok(())
}
