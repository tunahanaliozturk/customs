//! Exit test 1 of M1: the inventory of each fixture graph, as text and as
//! JSON, matches a committed golden file. The fixtures are read through
//! relative paths, so the output is the same on every operating system.
//! `CUSTOMS_BLESS=1 cargo test` rewrites the golden files.

use std::fs;
use std::path::Path;

use crate::common::{TestResult, customs, fixtures, golden, temp_file, zip};

fn both_formats(name: &str, args: &[&str], code: i32) -> TestResult {
    let text = customs(&fixtures(), args)?;
    assert_eq!(text.code, code, "{name}: {}", text.stderr);
    golden(&format!("{name}.txt"), &text.stdout)?;

    let mut json_args = args.to_vec();
    json_args.extend(["--format", "json"]);
    let json = customs(&fixtures(), &json_args)?;
    assert_eq!(json.code, code, "{name}: {}", json.stderr);
    golden(&format!("{name}.json"), &json.stdout)
}

#[test]
fn a_lock_file_of_version_1() -> TestResult {
    both_formats(
        "lock-v1",
        &[
            "scan",
            "lock-v1/packages.lock.json",
            "--packages-dir",
            "packages",
        ],
        // Contoso.Build.Tools runs Exec from an imported file: warnings.
        1,
    )
}

#[test]
fn a_lock_file_of_version_2_with_central_transitive_entries() -> TestResult {
    both_formats(
        "lock-v2",
        &[
            "scan",
            "lock-v2/packages.lock.json",
            "--packages-dir",
            "packages",
        ],
        0,
    )
}

#[test]
fn an_assets_file_of_version_4_uses_its_package_folders_in_order() -> TestResult {
    both_formats(
        "assets-v4",
        &["scan", "assets-v4/obj/project.assets.json"],
        0,
    )
}

#[test]
fn an_assets_file_of_version_3() -> TestResult {
    both_formats(
        "assets-v3",
        &["scan", "assets-v3/obj/project.assets.json"],
        0,
    )
}

#[test]
fn a_global_packages_folder_on_its_own() -> TestResult {
    both_formats("packages-dir", &["scan", "--packages-dir", "packages"], 1)
}

#[test]
fn a_graph_with_a_missing_package() -> TestResult {
    both_formats(
        "missing",
        &[
            "scan",
            "missing/packages.lock.json",
            "--packages-dir",
            "packages",
        ],
        3,
    )
}

#[test]
fn a_single_nupkg_gives_the_same_inventory_as_its_extracted_folder() -> TestResult {
    let folder = fixtures().join("packages/contoso.build.tools/3.2.0");
    let mut entries = Vec::new();
    collect(&folder, &folder, &mut entries)?;
    let refs: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    let dir = temp_file("contoso.build.tools.3.2.0.nupkg", &zip(&refs)?)?;

    let text = customs(dir.path(), &["scan", "contoso.build.tools.3.2.0.nupkg"])?;
    assert_eq!(text.code, 1, "{}", text.stderr);
    golden("nupkg.txt", &text.stdout)?;
    let json = customs(
        dir.path(),
        &[
            "scan",
            "contoso.build.tools.3.2.0.nupkg",
            "--format",
            "json",
        ],
    )?;
    golden("nupkg.json", &json.stdout)?;

    // The archive and the folder must agree on every asset.
    let from_folder = customs(
        &fixtures(),
        &["scan", "--packages-dir", "packages", "--format", "json"],
    )?
    .json()?;
    let folder_assets = from_folder["packages"]
        .as_array()
        .and_then(|all| all.iter().find(|p| p["id"] == "contoso.build.tools"))
        .map(|p| p["assets"].clone());
    let archive_assets = json.json()?["packages"][0]["assets"].clone();
    assert_eq!(folder_assets, Some(archive_assets));
    Ok(())
}

#[test]
fn a_directory_is_searched_for_graph_files() -> TestResult {
    let by_dir = customs(
        &fixtures(),
        &["scan", "lock-v1", "--packages-dir", "packages"],
    )?;
    let by_file = customs(
        &fixtures(),
        &[
            "scan",
            "lock-v1/packages.lock.json",
            "--packages-dir",
            "packages",
        ],
    )?;
    assert_eq!(by_dir.code, 1, "{}", by_dir.stderr);
    assert_eq!(by_dir.stdout, by_file.stdout);
    Ok(())
}

/// Collects the files of a fixture package folder as archive entries, in
/// sorted order, leaving out what `NuGet` adds on extraction.
fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) -> TestResult {
    let mut children: Vec<_> = fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    children.sort_by_key(fs::DirEntry::file_name);
    for child in children {
        let path = child.path();
        if child.file_type()?.is_dir() {
            collect(root, &path, out)?;
        } else if child.file_name() != ".nupkg.metadata" {
            let relative = path.strip_prefix(root)?;
            let name: Vec<String> = relative
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            out.push((name.join("/"), fs::read(&path)?));
        }
    }
    Ok(())
}
