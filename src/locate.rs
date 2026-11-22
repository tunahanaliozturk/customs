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

/// What a package folder on disk is, without following links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Dir,
    Link,
    Other,
}

fn kind(path: &Path) -> Kind {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Kind::Link,
        Ok(meta) if meta.is_dir() => Kind::Dir,
        _ => Kind::Other,
    }
}

/// Where a package of a graph is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Location {
    /// A complete, real folder.
    Found(PathBuf),
    /// The ID folder or the version folder is a symbolic link or a junction.
    /// It is not followed.
    Link(PathBuf),
    Missing,
}

/// The folder of a package version in the first root that has it complete.
/// A link at the ID or the version level stops the search: it is reported,
/// never followed.
pub(crate) fn find(roots: &[PathBuf], id: &PackageId, version: &PackageVersion) -> Location {
    for root in roots {
        let id_dir = root.join(id.lower());
        match kind(&id_dir) {
            Kind::Link => return Location::Link(id_dir),
            Kind::Dir => {}
            Kind::Other => continue,
        }
        let dir = id_dir.join(version.lower());
        match kind(&dir) {
            Kind::Link => return Location::Link(dir),
            Kind::Dir if is_complete(&dir, id.lower(), version.lower()) => {
                return Location::Found(dir);
            }
            Kind::Dir | Kind::Other => {}
        }
    }
    Location::Missing
}

/// `NuGet` writes `.nupkg.metadata` last when it extracts a package, and
/// older versions wrote only the `.nupkg.sha512` file. A folder with neither
/// is a half-finished extraction that `NuGet` itself would not use. The
/// marker must be a regular file, not a link.
pub(crate) fn is_complete(dir: &Path, id: &str, version: &str) -> bool {
    let regular = |path: PathBuf| fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file());
    regular(dir.join(".nupkg.metadata"))
        || regular(dir.join(format!("{id}.{version}.nupkg.sha512")))
}

/// One item of a global packages folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Listed {
    Package {
        id: String,
        version: String,
        dir: PathBuf,
    },
    /// An ID or version folder that is a link: `name` is `id` or
    /// `id/version`. Not followed.
    Link { id: String, version: Option<String> },
    /// A folder that could not be listed: `name` is `id` or `id/version`.
    Unreadable { name: String, error: String },
}

/// Every `ID/version` folder in a global packages folder, sorted, with
/// links and unreadable folders reported instead of dropped. Names that
/// start with a dot are not packages and are left out. Only the root itself
/// failing to list is an error.
pub(crate) fn package_folders(root: &Path) -> io::Result<Vec<Listed>> {
    let mut found = Vec::new();
    for (id, id_path, id_kind) in sorted_children(root)? {
        if id.starts_with('.') {
            continue;
        }
        match id_kind {
            Kind::Link => found.push(Listed::Link { id, version: None }),
            Kind::Other => {}
            Kind::Dir => match sorted_children(&id_path) {
                Err(e) => found.push(Listed::Unreadable {
                    name: id,
                    error: e.to_string(),
                }),
                Ok(versions) => {
                    for (version, dir, version_kind) in versions {
                        match version_kind {
                            Kind::Link => found.push(Listed::Link {
                                id: id.clone(),
                                version: Some(version),
                            }),
                            Kind::Dir => found.push(Listed::Package {
                                id: id.clone(),
                                version,
                                dir,
                            }),
                            Kind::Other => {}
                        }
                    }
                }
            },
        }
    }
    Ok(found)
}

/// The children of a folder, sorted by name, with their kind; links are not
/// followed.
fn sorted_children(dir: &Path) -> io::Result<Vec<(String, PathBuf, Kind)>> {
    let mut children = Vec::new();
    for child in fs::read_dir(dir)? {
        let child = child?;
        let file_type = child.file_type()?;
        let kind = if file_type.is_symlink() {
            Kind::Link
        } else if file_type.is_dir() {
            Kind::Dir
        } else {
            Kind::Other
        };
        children.push((
            child.file_name().to_string_lossy().into_owned(),
            child.path(),
            kind,
        ));
    }
    children.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(children)
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

    #[cfg(unix)]
    #[test]
    fn an_unreadable_folder_is_listed_as_unreadable_and_the_rest_is_kept() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        for id in ["contoso.a", "contoso.b"] {
            fs::create_dir_all(root.path().join(id).join("1.0.0")).unwrap();
        }
        let locked = root.path().join("contoso.a");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let listed = package_folders(root.path());
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        let listed = listed.unwrap();
        if matches!(listed[0], Listed::Package { .. }) {
            // Running as root, where permissions do not stop a read.
            return;
        }
        assert!(matches!(&listed[0], Listed::Unreadable { name, .. } if name == "contoso.a"));
        assert!(matches!(&listed[1], Listed::Package { id, .. } if id == "contoso.b"));
    }

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
        assert_eq!(find(&roots, &id, &version), Location::Missing);
        fs::write(dir.join("contoso.a.1.0.0-beta.nupkg.sha512"), "x").unwrap();
        assert_eq!(find(&roots, &id, &version), Location::Found(dir));
    }
}
