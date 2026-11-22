//! The view of a package that `archive` and `folder` both give: a list of
//! entries and a capped read of one entry. Also the limits and the budget
//! that every listing and every read goes through.

use crate::scan::{Gap, GapRule, Outcome};

/// Every cap of the design that M1 code can reach, in one value passed down
/// explicitly. Tests use small values to reach them cheaply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    /// Bytes of one lock or assets file.
    pub(crate) graph_bytes: u64,
    /// Bytes of one `.nupkg` file.
    pub(crate) nupkg_bytes: u64,
    /// Entries in one package.
    pub(crate) entries: u64,
    /// Bytes of one path inside a package.
    pub(crate) path_bytes: usize,
    /// Segments of one path inside a package.
    pub(crate) path_segments: usize,
    /// Bytes read from one entry to tell PE, ELF and Mach-O apart.
    pub(crate) sniff_bytes: u64,
    /// Bytes read from one MSBuild file, or from the nuspec of a `.nupkg`.
    pub(crate) text_bytes: u64,
    /// Findings listed from one MSBuild file; past it, one C002 gap.
    pub(crate) findings_per_file: u64,
    /// XML nodes in one MSBuild document.
    pub(crate) xml_nodes: u64,
    /// Bytes of the central directory of one archive.
    pub(crate) directory_bytes: u64,
    /// Decompressed bytes per compressed byte while reading an entry.
    pub(crate) ratio: u64,
    /// Bytes read from all entries of one package together.
    pub(crate) package_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        const MIB: u64 = 1024 * 1024;
        Self {
            graph_bytes: 64 * MIB,
            nupkg_bytes: 1024 * MIB,
            entries: 50_000,
            path_bytes: 1024,
            path_segments: 64,
            sniff_bytes: 64,
            text_bytes: 8 * MIB,
            findings_per_file: 1_000,
            xml_nodes: 200_000,
            directory_bytes: 64 * MIB,
            ratio: 200,
            package_bytes: 512 * MIB,
        }
    }
}

/// What one package cost to inspect: entries listed and bytes read from
/// entries. The scan reports it, and the tests assert it stays under the
/// limits whatever the archive headers claim.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Budget {
    pub(crate) entries: u64,
    pub(crate) bytes: u64,
}

impl Budget {
    /// Counts one more entry, or returns a gap if that is over the limit.
    pub(crate) fn take_entry(&mut self, limits: &Limits) -> Result<(), Gap> {
        if self.entries >= limits.entries {
            return Err(Gap::new(
                GapRule::C002,
                None,
                format!(
                    "limit reached: more than {} entries in one package; the rest is not listed",
                    thousands(limits.entries)
                ),
            ));
        }
        self.entries += 1;
        Ok(())
    }

    /// Checks that `cap` more bytes fit in the per-package total.
    pub(crate) fn check_bytes(
        &self,
        cap: u64,
        limits: &Limits,
        path: &PackagePath,
    ) -> Result<(), Gap> {
        if self.bytes.saturating_add(cap) > limits.package_bytes {
            return Err(Gap::new(
                GapRule::C002,
                Some(path.as_str().to_owned()),
                format!(
                    "limit reached: {} bytes read from one package; this entry is not read",
                    thousands(limits.package_bytes)
                ),
            ));
        }
        Ok(())
    }
}

/// A path inside a package, with `/` separators, checked once: not empty,
/// not absolute, no drive letter, no `..`, and within the path limits. Empty
/// and `.` segments are dropped, as they are when `NuGet` extracts the
/// package: a published package has entries named `analyzers/cs//A.dll`,
/// which land on disk as `analyzers/cs/A.dll`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct PackagePath(String);

/// Why a name is not a [`PackagePath`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PathProblem {
    /// The name leaves the package or is not a plain relative path: C003.
    Unsafe(&'static str),
    /// The name is over a path limit: a C002 gap.
    Limit(String),
}

impl PackagePath {
    pub(crate) fn new(name: &str, limits: &Limits) -> Result<Self, PathProblem> {
        if name.is_empty() {
            return Err(PathProblem::Unsafe("is empty"));
        }
        if name.starts_with('/') {
            return Err(PathProblem::Unsafe("is an absolute path"));
        }
        let bytes = name.as_bytes();
        if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            return Err(PathProblem::Unsafe("starts with a drive letter"));
        }
        if name.split('/').any(|s| s == "..") {
            return Err(PathProblem::Unsafe("leaves the package through `..`"));
        }
        let name = name
            .split('/')
            .filter(|s| !s.is_empty() && *s != ".")
            .collect::<Vec<_>>()
            .join("/");
        if name.is_empty() {
            return Err(PathProblem::Unsafe("names no file"));
        }
        if name.len() > limits.path_bytes {
            return Err(PathProblem::Limit(format!(
                "limit reached: a path of {} bytes, over the limit of {}",
                thousands(name.len() as u64),
                thousands(limits.path_bytes as u64)
            )));
        }
        let segments = name.split('/').count();
        if segments > limits.path_segments {
            return Err(PathProblem::Limit(format!(
                "limit reached: a path of {segments} segments, over the limit of {}",
                limits.path_segments
            )));
        }
        Ok(Self(name))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// One file of a package. `key` lets the reader that listed it find it again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) path: PackagePath,
    pub(crate) size: u64,
    pub(crate) key: usize,
}

/// The same view of a package, whether it is an archive or a folder.
pub(crate) trait Files {
    /// Lists the files of the package. Names that are unsafe become C003
    /// findings and names over a limit become C002 gaps, in `outcome`.
    fn entries(&mut self, limits: &Limits, outcome: &mut Outcome) -> Vec<Entry>;

    /// Reads at most `cap` bytes from the start of an entry, and counts them
    /// in `budget`. A limit or a failure is returned as a gap.
    fn read(
        &mut self,
        entry: &Entry,
        cap: u64,
        limits: &Limits,
        budget: &mut Budget,
    ) -> Result<Vec<u8>, Gap>;
}

/// Shortens a name for a message, so that a name over the path limit does
/// not fill the screen.
pub(crate) fn shorten(name: &str) -> String {
    match name.char_indices().nth(80) {
        Some((at, _)) => format!("{}...", &name[..at]),
        None => name.to_owned(),
    }
}

/// `1234567` as `1,234,567`.
pub(crate) fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_names_are_refused_with_a_reason() {
        let limits = Limits::default();
        for name in [
            "",
            "/etc/x",
            "C:/x",
            "c:x",
            "../x",
            "a/../../x",
            "./.",
            "./../x",
        ] {
            assert!(
                matches!(PackagePath::new(name, &limits), Err(PathProblem::Unsafe(_))),
                "{name:?}"
            );
        }
        assert!(PackagePath::new("build/a..b/x.targets", &limits).is_ok());
    }

    #[test]
    fn empty_and_dot_segments_are_dropped_as_nuget_does_on_extraction() {
        let limits = Limits::default();
        for (name, path) in [
            ("analyzers/cs//A.dll", "analyzers/cs/A.dll"),
            ("./build/x.targets", "build/x.targets"),
            ("lib/./net8.0/A.dll", "lib/net8.0/A.dll"),
        ] {
            assert_eq!(PackagePath::new(name, &limits).unwrap().as_str(), path);
        }
    }

    #[test]
    fn a_path_just_over_a_limit_is_a_limit_problem() {
        let limits = Limits {
            path_bytes: 10,
            path_segments: 3,
            ..Limits::default()
        };
        assert!(PackagePath::new("abcdefghij", &limits).is_ok());
        assert!(matches!(
            PackagePath::new("abcdefghijk", &limits),
            Err(PathProblem::Limit(_))
        ));
        assert!(PackagePath::new("a/b/c", &limits).is_ok());
        assert!(matches!(
            PackagePath::new("a/b/c/d", &limits),
            Err(PathProblem::Limit(_))
        ));
    }

    #[test]
    fn the_budget_stops_one_entry_over_the_limit() {
        let limits = Limits {
            entries: 2,
            package_bytes: 100,
            ..Limits::default()
        };
        let mut budget = Budget::default();
        assert!(budget.take_entry(&limits).is_ok());
        assert!(budget.take_entry(&limits).is_ok());
        assert!(budget.take_entry(&limits).is_err());
        assert_eq!(budget.entries, 2);

        let path = PackagePath::new("a", &limits).unwrap();
        budget.bytes = 90;
        assert!(budget.check_bytes(10, &limits, &path).is_ok());
        assert!(budget.check_bytes(11, &limits, &path).is_err());
    }

    #[test]
    fn numbers_get_thousands_separators() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(50_001), "50,001");
        assert_eq!(thousands(536_870_912), "536,870,912");
    }
}
