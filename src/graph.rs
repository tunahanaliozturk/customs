//! Lock files and assets files, read into a [`Graph`]. Pure: the caller reads
//! the bytes.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::hash::{Hash, Hasher};

use serde::Deserialize;
use serde::de::IgnoredAny;

/// Why a graph file could not be read as a graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParseError(String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseError {}

fn error(message: impl Into<String>) -> ParseError {
    ParseError(message.into())
}

/// Lowercases character by character, like .NET's `ToLowerInvariant`: no
/// rule that looks at the neighbours (such as a final sigma), and a
/// character whose lowercase is more than one character is kept as it is.
/// .NET maps some of those, such as `İ`, to one character, so an ID with
/// them may be looked up in the wrong folder and show as C001.
pub(crate) fn lower_invariant(text: &str) -> String {
    text.chars()
        .map(|c| {
            let mut lower = c.to_lowercase();
            match (lower.next(), lower.next()) {
                (Some(single), None) => single,
                _ => c,
            }
        })
        .collect()
}

/// A package ID as written. Compared and hashed on its lowercase form, as
/// `NuGet` compares IDs without regard to case.
#[derive(Debug, Clone)]
pub(crate) struct PackageId {
    text: String,
    lower: String,
}

impl PackageId {
    /// Checks the ID against `NuGet`'s pattern `^\w+([.-]\w+)*$`, at most 100
    /// characters. The check is what keeps an ID from naming a path outside
    /// the package folder.
    pub(crate) fn new(text: &str) -> Result<Self, ParseError> {
        let valid = text.chars().count() <= 100
            && text.split(['.', '-']).all(|part| {
                !part.is_empty() && part.chars().all(|c| c.is_alphanumeric() || c == '_')
            });
        if valid {
            Ok(Self {
                text: text.to_owned(),
                lower: lower_invariant(text),
            })
        } else {
            Err(error(format!("\"{text}\" is not a valid package ID")))
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.text
    }

    /// The lowercase form, which names the package's folder.
    pub(crate) fn lower(&self) -> &str {
        &self.lower
    }
}

impl PartialEq for PackageId {
    fn eq(&self, other: &Self) -> bool {
        self.lower == other.lower
    }
}

impl Eq for PackageId {}

impl Hash for PackageId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.lower.hash(state);
    }
}

impl PartialOrd for PackageId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PackageId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.lower.cmp(&other.lower)
    }
}

/// A package version as written, with `NuGet`'s normalised form in lowercase:
/// no build metadata, no leading zeros, three parts, and a fourth only when it
/// is not zero. That form names the version's folder, and versions compare
/// on it.
#[derive(Debug, Clone)]
pub(crate) struct PackageVersion {
    text: String,
    lower: String,
}

impl PackageVersion {
    pub(crate) fn new(text: &str) -> Result<Self, ParseError> {
        let bad = || error(format!("\"{text}\" is not a valid package version"));
        let (release, metadata) = match text.split_once('+') {
            Some((release, metadata)) => (release, Some(metadata)),
            None => (text, None),
        };
        let (core, label) = match release.split_once('-') {
            Some((core, label)) => (core, Some(label)),
            None => (release, None),
        };
        let identifiers_ok = |s: &str| {
            s.split('.').all(|id| {
                !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            })
        };
        if !label.is_none_or(identifiers_ok) || !metadata.is_none_or(identifiers_ok) {
            return Err(bad());
        }
        let mut numbers = Vec::with_capacity(4);
        for part in core.split('.') {
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad());
            }
            // NuGet keeps each part in an Int32.
            numbers.push(part.parse::<i32>().map_err(|_| bad())?);
        }
        if numbers.len() > 4 {
            return Err(bad());
        }
        numbers.resize(numbers.len().max(3), 0);
        if numbers.get(3) == Some(&0) {
            numbers.truncate(3);
        }
        let mut normalised = numbers
            .iter()
            .map(i32::to_string)
            .collect::<Vec<_>>()
            .join(".");
        if let Some(label) = label {
            normalised.push('-');
            normalised.push_str(label);
        }
        Ok(Self {
            text: text.to_owned(),
            lower: normalised.to_lowercase(),
        })
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.text
    }

    /// The lowercase normalised form, which names the version's folder.
    pub(crate) fn lower(&self) -> &str {
        &self.lower
    }
}

impl PartialEq for PackageVersion {
    fn eq(&self, other: &Self) -> bool {
        self.lower == other.lower
    }
}

impl Eq for PackageVersion {}

impl Hash for PackageVersion {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.lower.hash(state);
    }
}

/// How the project depends on a package. The order is from the strongest
/// claim to the weakest, so merging two keeps the smaller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Dependency {
    Direct,
    CentralTransitive,
    Transitive,
    /// A `PackageDownload` item, listed only in an assets file.
    Download,
}

impl Dependency {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::CentralTransitive => "central transitive",
            Self::Transitive => "transitive",
            Self::Download => "download",
        }
    }
}

/// One package of a graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PackageRef {
    pub(crate) id: PackageId,
    pub(crate) version: PackageVersion,
    pub(crate) dependency: Dependency,
    pub(crate) frameworks: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GraphKind {
    Lock,
    Assets,
}

/// A resolved graph: the packages, and for an assets file the package
/// folders it names, in order, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Graph {
    pub(crate) kind: GraphKind,
    pub(crate) format_version: u32,
    pub(crate) packages: Vec<PackageRef>,
    pub(crate) folders: Vec<String>,
}

/// Reads a lock file or an assets file, telling them apart by content.
pub(crate) fn parse(bytes: &[u8]) -> Result<Graph, ParseError> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| error(format!("not JSON: {e}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| error("not a lock file or an assets file"))?;
    if object.contains_key("libraries") {
        parse_assets(value)
    } else if object.contains_key("version") {
        parse_lock(value)
    } else {
        Err(error("not a lock file or an assets file"))
    }
}

#[derive(Deserialize)]
struct LockFile {
    version: u32,
    #[serde(default)]
    dependencies: BTreeMap<String, BTreeMap<String, LockEntry>>,
}

#[derive(Deserialize)]
struct LockEntry {
    #[serde(rename = "type")]
    kind: String,
    resolved: Option<String>,
}

fn parse_lock(value: serde_json::Value) -> Result<Graph, ParseError> {
    let version = value.get("version").and_then(serde_json::Value::as_u64);
    if !matches!(version, Some(1 | 2)) {
        return Err(error(format!(
            "lock file format version {} is not supported; customs reads versions 1 and 2",
            value.get("version").unwrap_or(&serde_json::Value::Null)
        )));
    }
    let lock: LockFile =
        serde_json::from_value(value).map_err(|e| error(format!("not a lock file: {e}")))?;
    let mut packages = Packages::default();
    for (target, entries) in &lock.dependencies {
        let framework = target.split('/').next().unwrap_or(target);
        for (name, entry) in entries {
            let dependency = match entry.kind.as_str() {
                "Direct" => Dependency::Direct,
                "Transitive" => Dependency::Transitive,
                "CentralTransitive" => Dependency::CentralTransitive,
                "Project" => continue,
                other => {
                    return Err(error(format!(
                        "{name}: unknown dependency type \"{other}\""
                    )));
                }
            };
            let resolved = entry
                .resolved
                .as_deref()
                .ok_or_else(|| error(format!("{name}: no resolved version")))?;
            packages.add(name, resolved, dependency, framework)?;
        }
    }
    Ok(Graph {
        kind: GraphKind::Lock,
        format_version: lock.version,
        packages: packages.into_vec(),
        folders: Vec::new(),
    })
}

#[derive(Deserialize)]
struct AssetsFile {
    version: u32,
    libraries: BTreeMap<String, Library>,
    #[serde(default)]
    targets: BTreeMap<String, Keys>,
    #[serde(rename = "packageFolders", default)]
    package_folders: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    project: Project,
}

/// The keys of a JSON object whose values are not needed.
#[derive(Default)]
struct Keys(BTreeSet<String>);

impl<'de> Deserialize<'de> for Keys {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let map = BTreeMap::<String, IgnoredAny>::deserialize(deserializer)?;
        Ok(Self(map.into_keys().collect()))
    }
}

#[derive(Deserialize)]
struct Library {
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize, Default)]
struct Project {
    #[serde(default)]
    frameworks: BTreeMap<String, Framework>,
}

#[derive(Deserialize)]
struct Framework {
    #[serde(default)]
    dependencies: Keys,
    #[serde(rename = "downloadDependencies", default)]
    download_dependencies: Vec<Download>,
}

#[derive(Deserialize)]
struct Download {
    name: String,
    version: String,
}

fn parse_assets(value: serde_json::Value) -> Result<Graph, ParseError> {
    let assets: AssetsFile =
        serde_json::from_value(value).map_err(|e| error(format!("not an assets file: {e}")))?;
    if !matches!(assets.version, 3 | 4) {
        return Err(error(format!(
            "assets file format version {} is not supported; customs reads versions 3 and 4",
            assets.version
        )));
    }
    let direct: BTreeSet<String> = assets
        .project
        .frameworks
        .values()
        .flat_map(|f| f.dependencies.0.iter().map(|k| k.to_lowercase()))
        .collect();
    let mut packages = Packages::default();
    for (key, library) in &assets.libraries {
        if library.kind != "package" {
            continue;
        }
        let (name, version) = key
            .split_once('/')
            .ok_or_else(|| error(format!("\"{key}\" is not of the form ID/version")))?;
        let dependency = if direct.contains(&name.to_lowercase()) {
            Dependency::Direct
        } else {
            Dependency::Transitive
        };
        let frameworks: Vec<&str> = assets
            .targets
            .iter()
            .filter(|(_, libraries)| libraries.0.contains(key))
            .map(|(target, _)| target.split('/').next().unwrap_or(target))
            .collect();
        packages.add_all(name, version, dependency, &frameworks)?;
    }
    for (framework, spec) in &assets.project.frameworks {
        for download in &spec.download_dependencies {
            let version = exact_version(&download.version).ok_or_else(|| {
                error(format!(
                    "{}: PackageDownload version \"{}\" is not an exact version",
                    download.name, download.version
                ))
            })?;
            packages.add(&download.name, version, Dependency::Download, framework)?;
        }
    }
    Ok(Graph {
        kind: GraphKind::Assets,
        format_version: assets.version,
        packages: packages.into_vec(),
        folders: assets.package_folders.keys().cloned().collect(),
    })
}

/// The 1-based line of each package's entry in a lock or assets file, by
/// lowercase ID and lowercase normalised version, for SARIF locations: in a
/// lock file the line of the first `"Id": {` entry whose `resolved` is that
/// version, in an assets file the line of the `"Id/Version"` key under
/// `libraries`. `PackageDownload` items get no line.
///
/// One pass over the bytes, no recursion: a string is decoded only when it
/// is a key at one of those places or a `resolved` value, so the work is
/// linear in the file on any input. The caller has parsed the file as a
/// graph first; on bytes that are not JSON the result is merely incomplete.
pub(crate) fn entry_lines(bytes: &[u8]) -> HashMap<(String, String), u32> {
    let mut lines = HashMap::new();
    let mut line: u32 = 1;
    let mut depth = 0usize;
    // The key at depth 1 whose value the walk is inside.
    let mut section = Section::Other;
    // A lock entry's ID and line, and whether the next string is the value
    // of its `resolved`.
    let mut entry: Option<(String, u32)> = None;
    let mut resolved_next = false;
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        match byte {
            b'\n' => line = line.saturating_add(1),
            b'{' | b'[' => {
                depth += 1;
                resolved_next = false;
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            b'"' => {
                let end = string_end(bytes, at);
                let token = bytes.get(at..=end).unwrap_or_default();
                let mut next = end + 1;
                while bytes.get(next).is_some_and(u8::is_ascii_whitespace) {
                    if bytes.get(next) == Some(&b'\n') {
                        line = line.saturating_add(1);
                    }
                    next += 1;
                }
                let is_key = bytes.get(next) == Some(&b':');
                let decode = || serde_json::from_slice::<String>(token).ok();
                match (is_key, depth, section) {
                    (true, 1, _) => {
                        section = match decode().as_deref() {
                            Some("dependencies") => Section::Dependencies,
                            Some("libraries") => Section::Libraries,
                            _ => Section::Other,
                        };
                    }
                    (true, 2, Section::Libraries) => {
                        if let Some((id, version)) =
                            decode().as_deref().and_then(|k| k.split_once('/'))
                        {
                            insert_line(&mut lines, id, version, line);
                        }
                    }
                    (true, 3, Section::Dependencies) => entry = decode().map(|id| (id, line)),
                    (true, 4, Section::Dependencies) => {
                        resolved_next = decode().as_deref() == Some("resolved");
                    }
                    (false, 4, Section::Dependencies) if resolved_next => {
                        resolved_next = false;
                        if let (Some((id, entry_line)), Some(version)) = (&entry, decode()) {
                            insert_line(&mut lines, id, &version, *entry_line);
                        }
                    }
                    _ => {}
                }
                at = next;
                continue;
            }
            _ => {}
        }
        at += 1;
    }
    lines
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Dependencies,
    Libraries,
    Other,
}

/// The index of the quote that ends the string starting at `start`, or the
/// last index if it has no end. A backslash skips the byte after it.
fn string_end(bytes: &[u8], start: usize) -> usize {
    let mut at = start + 1;
    while let Some(&byte) = bytes.get(at) {
        match byte {
            b'"' => return at,
            b'\\' => at += 2,
            _ => at += 1,
        }
    }
    bytes.len().saturating_sub(1)
}

fn insert_line(lines: &mut HashMap<(String, String), u32>, id: &str, version: &str, line: u32) {
    if let (Ok(id), Ok(version)) = (PackageId::new(id), PackageVersion::new(version)) {
        lines.entry((id.lower, version.lower)).or_insert(line);
    }
}

/// The version inside an exact range: `[1.0.0]` or `[1.0.0, 1.0.0]`.
fn exact_version(range: &str) -> Option<&str> {
    let inner = range.trim().strip_prefix('[')?.strip_suffix(']')?;
    match inner.split_once(',') {
        None => Some(inner.trim()),
        Some((low, high)) if low.trim() == high.trim() => Some(low.trim()),
        Some(_) => None,
    }
}

/// Packages of one graph, merged by ID and normalised version.
#[derive(Default)]
struct Packages(BTreeMap<(String, String), PackageRef>);

impl Packages {
    fn add(
        &mut self,
        name: &str,
        version: &str,
        dependency: Dependency,
        framework: &str,
    ) -> Result<(), ParseError> {
        self.add_all(name, version, dependency, &[framework])
    }

    fn add_all(
        &mut self,
        name: &str,
        version: &str,
        dependency: Dependency,
        frameworks: &[&str],
    ) -> Result<(), ParseError> {
        let id = PackageId::new(name)?;
        let version = PackageVersion::new(version)?;
        let key = (id.lower().to_owned(), version.lower().to_owned());
        let entry = self.0.entry(key).or_insert_with(|| PackageRef {
            id,
            version,
            dependency,
            frameworks: BTreeSet::new(),
        });
        entry.dependency = entry.dependency.min(dependency);
        entry
            .frameworks
            .extend(frameworks.iter().map(|f| (*f).to_owned()));
        Ok(())
    }

    fn into_vec(self) -> Vec<PackageRef> {
        self.0.into_values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_normalised_as_nuget_does() {
        let cases = [
            ("1.0", "1.0.0"),
            ("1", "1.0.0"),
            ("01.002.0003", "1.2.3"),
            ("1.2.3.0", "1.2.3"),
            ("1.2.3.4", "1.2.3.4"),
            ("1.2.3-Beta.2+build.5", "1.2.3-beta.2"),
            ("1.0.0+abc", "1.0.0"),
        ];
        for (text, normalised) in cases {
            let version = PackageVersion::new(text).unwrap();
            assert_eq!(version.lower(), normalised, "{text}");
            assert_eq!(version.as_str(), text);
        }
        assert_eq!(
            PackageVersion::new("1.0.0-BETA").unwrap(),
            PackageVersion::new("1.0.0-beta").unwrap()
        );
        assert_eq!(
            PackageVersion::new("1.0.0-BETA").unwrap().lower(),
            "1.0.0-beta"
        );
    }

    #[test]
    fn invalid_versions_are_rejected() {
        for text in [
            "",
            "1..2",
            "a.b",
            "1.2.3.4.5",
            "1.0.0-",
            "1.0.0-a..b",
            "../1",
            "1/2",
            "99999999999",
        ] {
            assert!(PackageVersion::new(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn a_version_part_must_fit_in_an_int32() {
        assert!(PackageVersion::new("2147483647.0.0").is_ok());
        assert!(PackageVersion::new("2147483648.0.0").is_err());
        assert!(PackageVersion::new("1.0.0.4294967295").is_err());
    }

    #[test]
    fn ids_are_lowercased_per_character_as_to_lower_invariant_does() {
        // No final-sigma rule: every capital sigma becomes a medial sigma.
        assert_eq!(lower_invariant("ΣΑΣ"), "σασ");
        assert_eq!(
            PackageId::new("Contoso.ΣΑΣ").unwrap().lower(),
            "contoso.σασ"
        );
        // A character with a multi-character lowercase is kept.
        assert_eq!(lower_invariant("İ"), "İ");
        assert_eq!(lower_invariant("Contoso.Tools"), "contoso.tools");
    }

    #[test]
    fn package_ids_follow_the_nuget_pattern_and_compare_ignoring_case() {
        for text in ["Contoso", "Contoso.Build-Tools_2", "Gսոa.UI"] {
            assert!(PackageId::new(text).is_ok(), "{text}");
        }
        for text in [
            "",
            ".hidden",
            "a..b",
            "../x",
            "a/b",
            "a b",
            "a.",
            &"x".repeat(101),
        ] {
            assert!(PackageId::new(text).is_err(), "{text:?}");
        }
        assert_eq!(
            PackageId::new("Contoso.A").unwrap(),
            PackageId::new("contoso.a").unwrap()
        );
    }

    #[test]
    fn a_lock_file_merges_frameworks_and_keeps_the_strongest_dependency() {
        let graph = parse(
            br#"{"version": 2, "dependencies": {
                "net8.0": {"A": {"type": "Transitive", "resolved": "1.0.0"},
                           "P": {"type": "Project"}},
                "net8.0/linux-x64": {"a": {"type": "Transitive", "resolved": "1.0"}},
                "net48": {"A": {"type": "Direct", "resolved": "1.0.0"},
                          "B": {"type": "CentralTransitive", "resolved": "2.0.0"}}}}"#,
        )
        .unwrap();
        assert_eq!(graph.kind, GraphKind::Lock);
        assert_eq!(graph.packages.len(), 2);
        let a = &graph.packages[0];
        assert_eq!(a.dependency, Dependency::Direct);
        assert_eq!(a.frameworks.iter().collect::<Vec<_>>(), ["net48", "net8.0"]);
        assert_eq!(graph.packages[1].dependency, Dependency::CentralTransitive);
    }

    #[test]
    fn unsupported_or_malformed_graphs_are_errors() {
        for bytes in [
            &br#"{"version": 3, "net8.0": {"framework": "net8.0"}}"#[..],
            br#"{"version": 1, "dependencies": {"net8.0": {"A": {"type": "Odd", "resolved": "1.0.0"}}}}"#,
            br#"{"version": 1, "dependencies": {"net8.0": {"A": {"type": "Direct"}}}}"#,
            br#"{"version": 1, "dependencies": {"net8.0": {"../A": {"type": "Direct", "resolved": "1.0.0"}}}}"#,
            br#"{"version": 5, "libraries": {}}"#,
            br#"{"version": 4, "libraries": {"NoSlash": {"type": "package"}}}"#,
            b"[]",
            br#"{"other": 1}"#,
        ] {
            assert!(parse(bytes).is_err(), "{}", String::from_utf8_lossy(bytes));
        }
    }

    #[test]
    fn an_assets_file_keeps_its_package_folders_in_order_and_reads_downloads() {
        let graph = parse(
            b"\xEF\xBB\xBF{\"version\": 4,
              \"libraries\": {\"A/1.0.0\": {\"type\": \"package\"}, \"W/1.0.0\": {\"type\": \"project\"}},
              \"targets\": {\"net8.0\": {\"A/1.0.0\": {}}},
              \"packageFolders\": {\"z/\": {}, \"a/\": {}},
              \"project\": {\"frameworks\": {\"net8.0\": {
                  \"downloadDependencies\": [{\"name\": \"D\", \"version\": \"[3.0.0, 3.0.0]\"}]}}}}",
        )
        .unwrap();
        assert_eq!(graph.folders, ["z/", "a/"]);
        let ids: Vec<&str> = graph.packages.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, ["A", "D"]);
        assert_eq!(graph.packages[1].dependency, Dependency::Download);
        assert_eq!(graph.packages[0].dependency, Dependency::Transitive);
    }

    #[test]
    fn only_exact_download_ranges_are_accepted() {
        assert_eq!(exact_version("[1.0.0]"), Some("1.0.0"));
        assert_eq!(exact_version(" [1.0.0, 1.0.0] "), Some("1.0.0"));
        assert_eq!(exact_version("[1.0.0, 2.0.0]"), None);
        assert_eq!(exact_version("1.0.0"), None);
    }

    fn line_of(lines: &HashMap<(String, String), u32>, id: &str, version: &str) -> Option<u32> {
        lines.get(&(id.to_owned(), version.to_owned())).copied()
    }

    #[test]
    fn a_lock_entry_is_found_at_the_line_of_its_id_for_each_resolved_version() {
        let lock = b"\xEF\xBB\xBF{\r\n  \"version\": 2,\r\n  \"dependencies\": {\r\n    \"net8.0\": {\r\n      \"Contoso.A\": {\r\n        \"type\": \"Direct\",\r\n        \"resolved\": \"1.0.0\",\r\n        \"contentHash\": \"x\\\"y\"\r\n      },\r\n      \"\\u0042\": {\"type\": \"Transitive\", \"resolved\": \"2.0\"}\r\n    },\r\n    \"net48\": {\r\n      \"Contoso.A\": {\"type\": \"Direct\", \"resolved\": \"1.5.0\"}\r\n    }\r\n  }\r\n}";
        let lines = entry_lines(lock);
        assert_eq!(line_of(&lines, "contoso.a", "1.0.0"), Some(5));
        assert_eq!(line_of(&lines, "b", "2.0.0"), Some(10));
        assert_eq!(line_of(&lines, "contoso.a", "1.5.0"), Some(13));
        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn an_assets_library_is_found_at_the_line_of_its_key_and_targets_are_not() {
        let assets = br#"{
  "version": 3,
  "targets": {
    "net8.0": {
      "Contoso.A/1.0.0": {"type": "package"}
    }
  },
  "libraries": {
    "Contoso.A/1.0.0": {
      "type": "package",
      "files": ["lib/a.dll", "x/y:z"]
    },
    "Web/1.0.0": {"type": "project"}
  }
}"#;
        let lines = entry_lines(assets);
        assert_eq!(line_of(&lines, "contoso.a", "1.0.0"), Some(9));
        assert_eq!(line_of(&lines, "web", "1.0.0"), Some(13));
    }

    #[test]
    fn entry_lines_survive_every_truncation_and_odd_bytes() {
        let lock = br#"{"version": 1, "dependencies": {"net8.0": {"A": {"type": "Direct", "resolved": "1.0.0"}}}}"#;
        for end in 0..=lock.len() {
            let _ = entry_lines(&lock[..end]);
        }
        for bytes in [
            &b"\"\\"[..],
            b"\"",
            b"\\",
            b"}}}]]]",
            b"\"a\":\"b\":",
            b"{{{{{\"resolved\":\"1\"}",
        ] {
            let _ = entry_lines(bytes);
        }
    }

    #[test]
    fn entry_lines_take_linear_time() {
        // Many entries, each with a resolved value, and one string of a
        // megabyte with escapes: twice the input must not take much more
        // than twice the time.
        let input = |n: usize| {
            let mut text = String::from(r#"{"version": 1, "dependencies": {"net8.0": {"#);
            for i in 0..n {
                text += r#""P"#;
                text += &i.to_string();
                text += r#"": {"type": "Direct", "resolved": "1.0."#;
                text += &i.to_string();
                text += r#""},"#;
            }
            text += r#""Q": {"resolved": ""#;
            text += &"\\\"".repeat(n);
            text += r#""}}}}"#;
            text.into_bytes()
        };
        let time = |bytes: &[u8]| {
            let start = std::time::Instant::now();
            let lines = entry_lines(bytes);
            (start.elapsed(), lines.len())
        };
        let (small, found) = time(&input(50_000));
        assert_eq!(found, 50_000);
        let (large, _) = time(&input(100_000));
        assert!(
            large < small * 4 + std::time::Duration::from_millis(200),
            "{small:?} then {large:?}"
        );
    }
}
