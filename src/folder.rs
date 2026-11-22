//! Reads an extracted package folder: lists its files without following
//! links, and reads the start of one file.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::package::{Budget, Entry, Files, Limits, PackagePath, PathProblem, shorten};
use crate::scan::{Finding, FindingRule, Gap, GapRule, Outcome};

#[derive(Debug)]
pub(crate) struct Folder {
    root: PathBuf,
    /// The path on disk of each listed entry, by `Entry::key`.
    files: Vec<PathBuf>,
}

impl Folder {
    pub(crate) fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            files: Vec::new(),
        }
    }
}

impl Files for Folder {
    fn entries(&mut self, limits: &Limits, outcome: &mut Outcome) -> Vec<Entry> {
        let mut entries = Vec::new();
        // Directories still to list, with their path inside the package.
        let mut pending = vec![(self.root.clone(), String::new())];
        'walk: while let Some((dir, prefix)) = pending.pop() {
            let listing = fs::read_dir(&dir).and_then(Iterator::collect::<Result<Vec<_>, _>>);
            let mut children = match listing {
                Ok(children) => children,
                Err(e) => {
                    let path = (!prefix.is_empty()).then(|| prefix.clone());
                    outcome.gaps.push(Gap::new(
                        GapRule::C001,
                        path,
                        format!("could not list the folder: {e}"),
                    ));
                    continue;
                }
            };
            // Reverse order, so that popping from `pending` walks in order.
            children.sort_by_key(|child| std::cmp::Reverse(child.file_name()));
            for child in children {
                let lossy = child.file_name().to_string_lossy().into_owned();
                let name = format!("{prefix}{lossy}");
                if child.file_name().to_str().is_none() {
                    outcome.findings.push(Finding::new(
                        FindingRule::C003,
                        Some(name),
                        "a file name that is not valid Unicode".to_owned(),
                    ));
                    continue;
                }
                // `DirEntry::file_type` does not follow links, and on Windows
                // it reports junctions as links too.
                let kind = match child.file_type() {
                    Ok(kind) => kind,
                    Err(e) => {
                        outcome.gaps.push(Gap::new(
                            GapRule::C001,
                            Some(name),
                            format!("could not read: {e}"),
                        ));
                        continue;
                    }
                };
                if kind.is_symlink() {
                    outcome.findings.push(Finding::new(
                        FindingRule::C003,
                        Some(name.clone()),
                        format!("a link in the package folder, not followed: {name}"),
                    ));
                } else if kind.is_dir() {
                    if name.split('/').count() >= limits.path_segments {
                        outcome.gaps.push(Gap::new(
                            GapRule::C002,
                            Some(shorten(&name)),
                            format!(
                                "limit reached: a folder at depth {}, the limit for a path; not listed",
                                limits.path_segments
                            ),
                        ));
                    } else {
                        pending.push((child.path(), format!("{name}/")));
                    }
                } else if kind.is_file() {
                    if let Err(gap) = outcome.budget.take_entry(limits) {
                        outcome.gaps.push(gap);
                        break 'walk;
                    }
                    match PackagePath::new(&name, limits) {
                        Ok(path) => {
                            let size = child.metadata().map_or(0, |m| m.len());
                            entries.push(Entry {
                                path,
                                size,
                                key: self.files.len(),
                            });
                            self.files.push(child.path());
                        }
                        Err(PathProblem::Unsafe(reason)) => outcome.findings.push(Finding::new(
                            FindingRule::C003,
                            Some(name.clone()),
                            format!("a file name that {reason}: {name}"),
                        )),
                        Err(PathProblem::Limit(message)) => {
                            outcome.gaps.push(Gap::new(
                                GapRule::C002,
                                Some(shorten(&name)),
                                message,
                            ));
                        }
                    }
                } else {
                    outcome.findings.push(Finding::new(
                        FindingRule::C003,
                        Some(name.clone()),
                        format!("not a regular file, not read: {name}"),
                    ));
                }
            }
        }
        entries
    }

    fn read(
        &mut self,
        entry: &Entry,
        cap: u64,
        limits: &Limits,
        budget: &mut Budget,
    ) -> Result<Vec<u8>, Gap> {
        let unreadable = |e: std::io::Error| {
            Gap::new(
                GapRule::C001,
                Some(entry.path.as_str().to_owned()),
                format!("could not read the file: {e}"),
            )
        };
        budget.check_bytes(cap, limits, &entry.path)?;
        let disk = self.files.get(entry.key).ok_or_else(|| {
            unreadable(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "not listed",
            ))
        })?;
        let mut bytes = Vec::new();
        File::open(disk)
            .and_then(|file| file.take(cap).read_to_end(&mut bytes))
            .map_err(unreadable)?;
        budget.bytes += bytes.len() as u64;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_is_deterministic_and_stops_one_entry_over_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("b/c")).unwrap();
        for name in ["a.txt", "b/c/d.txt", "b/z.txt"] {
            fs::write(dir.path().join(name), "x").unwrap();
        }
        let mut folder = Folder::new(dir.path());
        let mut outcome = Outcome::default();
        let entries = folder.entries(&Limits::default(), &mut outcome);
        // A folder's files come before its subfolders; `inventory` sorts.
        let names: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(names, ["a.txt", "b/z.txt", "b/c/d.txt"]);
        assert_eq!(outcome.gaps, []);

        let mut folder = Folder::new(dir.path());
        let mut outcome = Outcome::default();
        let entries = folder.entries(
            &Limits {
                entries: 2,
                ..Limits::default()
            },
            &mut outcome,
        );
        assert_eq!(entries.len(), 2);
        assert_eq!(outcome.gaps.len(), 1);
        assert_eq!(outcome.gaps[0].rule, GapRule::C002);
    }

    #[test]
    fn a_folder_just_past_the_segment_limit_is_not_listed() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("a/b/c")).unwrap();
        fs::write(dir.path().join("a/b/x"), "x").unwrap();
        fs::write(dir.path().join("a/b/c/y"), "y").unwrap();
        let mut folder = Folder::new(dir.path());
        let mut outcome = Outcome::default();
        let entries = folder.entries(
            &Limits {
                path_segments: 3,
                ..Limits::default()
            },
            &mut outcome,
        );
        let names: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(names, ["a/b/x"]);
        assert_eq!(outcome.gaps.len(), 1);
    }

    #[test]
    fn a_read_is_capped_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("big"), vec![7_u8; 1000]).unwrap();
        let mut folder = Folder::new(dir.path());
        let limits = Limits::default();
        let mut outcome = Outcome::default();
        let entries = folder.entries(&limits, &mut outcome);
        let mut budget = Budget::default();
        let bytes = folder.read(&entries[0], 64, &limits, &mut budget).unwrap();
        assert_eq!(bytes.len(), 64);
        assert_eq!(budget.bytes, 64);
    }
}
