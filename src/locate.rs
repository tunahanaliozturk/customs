//! Finds packages on disk: in package folders, as a single `.nupkg`, and the
//! graph files under a directory.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::graph::{PackageId, PackageVersion};

/// The global packages folder: `NUGET_PACKAGES` if set, else
/// `~/.nuget/packages`.
pub(crate) fn default_root(
    nuget_packages: Option<OsString>,
    home: Option<PathBuf>,
) -> Option<PathBuf> {
    match nuget_packages {
        Some(dir) if !dir.is_empty() => Some(PathBuf::from(dir)),
        _ => home.map(|home| home.join(".nuget").join("packages")),
    }
}

/// The folder of a package version in the first root that has it complete.
pub(crate) fn find(roots: &[PathBuf], id: &PackageId, version: &PackageVersion) -> Option<PathBuf> {
    roots
        .iter()
        .map(|root| root.join(id.lower()).join(version.lower()))
        .find(|dir| is_complete(dir, id.lower(), version.lower()))
}

/// `NuGet` writes `.nupkg.metadata` last when it extracts a package, and
/// older versions wrote only the `.nupkg.sha512` file. A folder with neither
/// is a half-finished extraction that `NuGet` itself would not use.
pub(crate) fn is_complete(dir: &Path, id: &str, version: &str) -> bool {
    dir.join(".nupkg.metadata").is_file()
        || dir.join(format!("{id}.{version}.nupkg.sha512")).is_file()
}

/// Every `ID/version` folder in a global packages folder, sorted. Names that
/// start with a dot are not packages and are left out.
pub(crate) fn package_folders(root: &Path) -> io::Result<Vec<(String, String, PathBuf)>> {
    let mut found = Vec::new();
    for id in sorted_dirs(root)? {
        let id_name = id.file_name().to_string_lossy().into_owned();
        if id_name.starts_with('.') {
            continue;
        }
        for version in sorted_dirs(&id.path())? {
            let version_name = version.file_name().to_string_lossy().into_owned();
            found.push((id_name.clone(), version_name, version.path()));
        }
    }
    Ok(found)
}

fn sorted_dirs(dir: &Path) -> io::Result<Vec<fs::DirEntry>> {
    let mut dirs = Vec::new();
    for child in fs::read_dir(dir)? {
        let child = child?;
        if child.file_type()?.is_dir() {
            dirs.push(child);
        }
    }
    dirs.sort_by_key(fs::DirEntry::file_name);
    Ok(dirs)
}

/// The ID and version in a `.nupkg` file name: `contoso.tools.1.2.0.nupkg`.
/// The first split whose remainder is a valid version wins.
// ponytail: from the file name, because reading the nuspec needs the XML
// parser that M2 adds; M2 should take the ID from the nuspec instead.
pub(crate) fn nupkg_identity(file_name: &str) -> Option<(PackageId, PackageVersion)> {
    let stem = file_name.strip_suffix(".nupkg").or_else(|| {
        let at = file_name.len().checked_sub(6)?;
        file_name
            .get(at..)
            .filter(|ext| ext.eq_ignore_ascii_case(".nupkg"))
            .and_then(|_| file_name.get(..at))
    })?;
    stem.match_indices('.').find_map(|(at, _)| {
        let version = stem.get(at + 1..)?;
        if !version.starts_with(|c: char| c.is_ascii_digit()) {
            return None;
        }
        Some((
            PackageId::new(stem.get(..at)?).ok()?,
            PackageVersion::new(version).ok()?,
        ))
    })
}

/// The graph files under a directory: every `packages.lock.json`, and every
/// `project.assets.json` in a folder named `obj`. Skips `.git`, `bin` and
/// `node_modules`, and does not follow links.
pub(crate) fn graph_files(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for child in fs::read_dir(&dir)? {
            let child = child?;
            let kind = child.file_type()?;
            let name = child.file_name();
            if kind.is_dir() {
                if !["bin", ".git", "node_modules"]
                    .iter()
                    .any(|skip| name == *skip)
                {
                    pending.push(child.path());
                }
            } else if kind.is_file()
                && (name == "packages.lock.json"
                    || (name == "project.assets.json"
                        && dir.file_name().is_some_and(|d| d == "obj")))
            {
                found.push(child.path());
            }
        }
    }
    found.sort();
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nupkg_file_names_split_into_id_and_version() {
        let split = |name: &str| {
            nupkg_identity(name)
                .map(|(id, version)| (id.as_str().to_owned(), version.as_str().to_owned()))
        };
        assert_eq!(
            split("contoso.tools.1.2.0.nupkg"),
            Some(("contoso.tools".into(), "1.2.0".into()))
        );
        assert_eq!(
            split("Contoso.2D.1.0.0-beta.1.NUPKG"),
            Some(("Contoso.2D".into(), "1.0.0-beta.1".into()))
        );
        assert_eq!(split("contoso.nupkg"), None);
        assert_eq!(split("contoso.1.0.0.zip"), None);
    }

    #[test]
    fn nuget_packages_wins_over_the_home_folder() {
        let home = Some(PathBuf::from("home"));
        assert_eq!(
            default_root(Some("cache".into()), home.clone()),
            Some(PathBuf::from("cache"))
        );
        assert_eq!(
            default_root(Some(OsString::new()), home.clone()),
            Some(Path::new("home").join(".nuget").join("packages"))
        );
        assert_eq!(default_root(None, None), None);
    }

    #[test]
    fn a_folder_without_a_completion_marker_is_not_found() {
        let root = tempfile::tempdir().unwrap();
        let id = PackageId::new("Contoso.A").unwrap();
        let version = PackageVersion::new("1.0.0-Beta").unwrap();
        let dir = root.path().join("contoso.a").join("1.0.0-beta");
        fs::create_dir_all(&dir).unwrap();
        let roots = [root.path().to_path_buf()];
        assert_eq!(find(&roots, &id, &version), None);
        fs::write(dir.join("contoso.a.1.0.0-beta.nupkg.sha512"), "x").unwrap();
        assert_eq!(find(&roots, &id, &version), Some(dir));
    }
}
