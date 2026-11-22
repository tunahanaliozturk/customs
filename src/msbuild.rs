//! Rules C201 to C207 and C004 over the MSBuild files of a package, and the
//! import graph that says which of them an entry point reaches. Pure, apart
//! from the capped reads it asks the package view for.
//!
//! Schema elements such as `Import`, `UsingTask` and `Target` are matched by
//! exact name, as MSBuild's `src/Build/Evaluation/ProjectParser.cs` does;
//! task names such as `Exec` ignoring case, as its
//! `src/Build/Instance/TaskRegistry.cs` does (both read on 2026-11-22).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use roxmltree::{Document, Node};

use crate::package::{Entry, Files, Limits, PackagePath, thousands};
use crate::scan::{Finding, FindingRule, Gap, GapRule, Outcome};
use crate::xml::{Lines, blank_doctype, decode, options};

/// Evidence, and any value from a file in a message, longer than this is
/// cut.
const EVIDENCE_CHARS: usize = 240;

/// The shortest run of base64 characters that C206 reports.
const BASE64_RUN: usize = 200;

/// A run of only hex digits up to this long is a key or a hash, not base64.
const HEX_RUN: usize = 1024;

/// C207 findings listed for one file; the rest count against the finding
/// limit.
const UNRESOLVED_LISTED: usize = 100;

/// Whether a path names an MSBuild file by its extension: `.props`,
/// `.targets` or `.tasks`, wherever it is in the package. Files of any
/// other name are read too when an import reaches them.
pub(crate) fn is_msbuild(path: &PackagePath) -> bool {
    let name = path.as_str().rsplit('/').next().unwrap_or_default();
    name.rsplit_once('.').is_some_and(|(_, ext)| {
        ["props", "targets", "tasks"]
            .iter()
            .any(|e| ext.eq_ignore_ascii_case(e))
    })
}

/// A value from a file, cut for evidence or a message.
fn cut(value: &str) -> String {
    match value.char_indices().nth(EVIDENCE_CHARS) {
        Some((at, _)) => format!("{}...", &value[..at]),
        None => value.to_owned(),
    }
}

/// What one file yields: findings up to the limit, how many more there
/// were, a gap if a limit stopped the parse, and the package files its
/// imports and `UsingTask AssemblyFile` resolve to (lowercase paths).
#[derive(Debug, Default)]
struct File {
    findings: Vec<Finding>,
    dropped: u64,
    unresolved: usize,
    gap: Option<Gap>,
    imports: BTreeSet<String>,
    assemblies: BTreeSet<String>,
}

/// One file being read.
struct Reader<'a> {
    path: &'a PackagePath,
    index: &'a BTreeMap<String, &'a Entry>,
    limit: usize,
    lines: Lines,
    file: File,
}

impl Reader<'_> {
    fn push(&mut self, rule: FindingRule, line: u32, message: String, evidence: &str) {
        if self.file.findings.len() >= self.limit {
            self.file.dropped += 1;
            return;
        }
        let mut found = Finding::new(rule, Some(self.path.as_str().to_owned()), message);
        found.line = Some(line);
        found.evidence = Some(cut(evidence));
        self.file.findings.push(found);
    }

    fn line(&self, offset: usize) -> u32 {
        self.lines.line(offset)
    }

    fn element(&mut self, node: Node<'_, '_>) {
        let line = self.line(node.range().start);
        match node.tag_name().name() {
            // MSBuild allows `UsingTask` only under `Project`; it is matched
            // anywhere, which reports more, never less.
            "UsingTask" => self.using_task(node, line),
            "Import" => self.import(node, line),
            name if node
                .parent_element()
                .is_some_and(|p| p.tag_name().name() == "Target") =>
            {
                self.task(node, name, line);
            }
            _ => {}
        }
        for attribute in node.attributes() {
            // A value is reported at the line where it starts: roxmltree
            // normalises the line breaks inside it.
            let line = self.line(attribute.range_value().start);
            self.scan_text(attribute.value(), line, false);
        }
    }

    fn using_task(&mut self, node: Node<'_, '_>, line: u32) {
        let present = |name: &str| node.attribute(name).filter(|v| !v.trim().is_empty());
        let task = cut(node.attribute("TaskName").unwrap_or_default());
        // MSBuild's own TaskHostFactory and AssemblyTaskFactory run a
        // compiled task assembly, matched ignoring case as TaskRegistry
        // does; they compile nothing, and C202 reports the assembly. A local
        // cache had 66 of them in SDK packages.
        let compiles = |factory: &&str| {
            !["TaskHostFactory", "AssemblyTaskFactory"]
                .iter()
                .any(|own| factory.eq_ignore_ascii_case(own))
        };
        if let Some(factory) = present("TaskFactory").filter(compiles) {
            self.push(
                FindingRule::C201,
                line,
                format!(
                    "UsingTask with the task factory {} (task {task})",
                    cut(factory)
                ),
                &format!("TaskFactory=\"{factory}\" TaskName=\"{task}\""),
            );
        }
        if let Some(assembly) = present("AssemblyFile") {
            self.push(
                FindingRule::C202,
                line,
                format!("UsingTask loads an assembly (task {task})"),
                assembly,
            );
            if let Some(target) = self.resolve(assembly) {
                self.file.assemblies.insert(target);
            }
        }
    }

    fn import(&mut self, node: Node<'_, '_>, line: u32) {
        // An import with an `Sdk` attribute is resolved against that SDK by
        // the SDK resolver; it cannot reach a file of this package. The
        // corpus has 350 of them in workload manifests.
        if node.attribute("Sdk").is_some() {
            return;
        }
        let Some(project) = node.attribute("Project") else {
            return;
        };
        match self.resolve(project) {
            Some(target) => {
                self.file.imports.insert(target);
            }
            None if self.file.unresolved < UNRESOLVED_LISTED => {
                self.file.unresolved += 1;
                self.push(
                    FindingRule::C207,
                    line,
                    "an Import that cannot be resolved inside the package".to_owned(),
                    project,
                );
            }
            None => self.file.dropped += 1,
        }
    }

    fn task(&mut self, node: Node<'_, '_>, name: &str, line: u32) {
        let value = |wanted: &str| {
            node.attributes()
                .find(|a| a.name().eq_ignore_ascii_case(wanted))
                .map(|a| a.value())
                .unwrap_or_default()
        };
        if name.eq_ignore_ascii_case("Exec") {
            let command = value("Command");
            self.push(FindingRule::C203, line, "Exec task".to_owned(), command);
        } else if name.eq_ignore_ascii_case("DownloadFile") {
            let source = value("SourceUrl");
            self.push(
                FindingRule::C204,
                line,
                "DownloadFile task".to_owned(),
                source,
            );
        }
    }

    /// The package file a literal path resolves to, if it is in the package.
    fn resolve(&self, raw: &str) -> Option<String> {
        resolve(raw, self.path).filter(|p| self.index.contains_key(p))
    }

    /// C205 and C206 over one piece of text that starts on `line`. In
    /// element text, each finding is moved down by the line breaks before
    /// it; in an attribute value it stays on the value's first line.
    fn scan_text(&mut self, text: &str, line: u32, element_text: bool) {
        let mut found: Vec<(usize, FindingRule, &str)> = urls(text)
            .into_iter()
            .map(|(at, url)| (at, FindingRule::C205, url))
            .chain(
                base64_runs(text)
                    .into_iter()
                    .map(|(at, run)| (at, FindingRule::C206, run)),
            )
            .collect();
        found.sort_by_key(|f| f.0);
        let (mut counted, mut breaks) = (0, 0_u32);
        for (at, rule, value) in found {
            if element_text {
                let more = text[counted..at].bytes().filter(|b| *b == b'\n').count();
                breaks = breaks.saturating_add(u32::try_from(more).unwrap_or(u32::MAX));
                counted = at;
            }
            let message = match rule {
                FindingRule::C205 => "URL".to_owned(),
                _ => format!(
                    "base64-looking string, {} characters",
                    thousands(value.len() as u64)
                ),
            };
            self.push(rule, line.saturating_add(breaks), message, value);
        }
    }
}

/// Every `http://`, `https://` and `ftp://` URL in a text, with its offset,
/// in one pass.
fn urls(text: &str) -> Vec<(usize, &str)> {
    const SCHEMES: [&[u8]; 3] = [b"http://", b"https://", b"ftp://"];
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let scheme = SCHEMES.iter().find(|s| {
            bytes
                .get(i..i + s.len())
                .is_some_and(|b| b.eq_ignore_ascii_case(s))
        });
        let Some(scheme) = scheme else {
            i += 1;
            continue;
        };
        let starts_word = text[..i]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric());
        let body = i + scheme.len();
        let end = text[body..]
            .find(|c: char| c.is_whitespace() || "\"'<>`".contains(c))
            .map_or(text.len(), |e| body + e);
        let url = text[i..end].trim_end_matches(['.', ',', ';', ')']);
        if starts_word && url.len() > scheme.len() {
            found.push((i, url));
        }
        i = end.max(i + 1);
    }
    found
}

/// Runs of at least 200 base64 characters, with up to two `=` after them.
/// A run of only hex digits is reported only past 1,024 characters.
fn base64_runs(text: &str) -> Vec<(usize, &str)> {
    let is_base64 = |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'/';
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if is_base64(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_base64(bytes[i]) {
                i += 1;
            }
            let mut end = i;
            while end < bytes.len() && end - i < 2 && bytes[end] == b'=' {
                end += 1;
            }
            let length = i - start;
            // A local cache holds strong-name public keys of 320 hex digits.
            let short_hex = length <= HEX_RUN && bytes[start..i].iter().all(u8::is_ascii_hexdigit);
            if length >= BASE64_RUN && !short_hex {
                found.push((start, &text[start..end]));
            }
            i = end.max(i);
        } else {
            i += 1;
        }
    }
    found
}

/// Resolves an `Import` or `AssemblyFile` path written in `from` to a
/// lowercase path inside the package. `None` if it uses any property other
/// than `$(MSBuildThisFileDirectory)` at its start, an item or metadata
/// reference, a wildcard, an absolute path, or leaves the package.
fn resolve(raw: &str, from: &PackagePath) -> Option<String> {
    const THIS_DIR: &str = "$(MSBuildThisFileDirectory)";
    let raw = raw.trim().replace('\\', "/");
    let relative = match raw.get(..THIS_DIR.len()) {
        Some(head) if head.eq_ignore_ascii_case(THIS_DIR) => raw[THIS_DIR.len()..].to_owned(),
        _ => raw,
    };
    if relative.contains("$(")
        || relative.contains("@(")
        || relative.contains("%(")
        || relative.contains(['*', '?', ';'])
        || relative.starts_with('/')
        || relative.as_bytes().get(1) == Some(&b':')
        || relative.is_empty()
    {
        return None;
    }
    let mut segments: Vec<&str> = from.as_str().split('/').collect();
    segments.pop();
    for segment in relative.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop()?;
            }
            other => segments.push(other),
        }
    }
    Some(segments.join("/").to_lowercase())
}

/// Reads one MSBuild file.
fn parse(
    path: &PackagePath,
    bytes: &[u8],
    limits: &Limits,
    index: &BTreeMap<String, &Entry>,
) -> File {
    let decoded = decode(bytes);
    let mut text = decoded.text;
    let mut problems = decoded.problems;
    if blank_doctype(&mut text) {
        problems.push("has a DTD, which MSBuild ignores".to_owned());
    }
    let mut reader = Reader {
        path,
        index,
        limit: usize::try_from(limits.findings_per_file).unwrap_or(usize::MAX),
        lines: Lines::new(&text),
        file: File::default(),
    };
    let parsed = Document::parse_with_options(&text, options(limits));
    match &parsed {
        Err(roxmltree::Error::NodesLimitReached) => {
            reader.file.gap = Some(Gap::new(
                GapRule::C002,
                Some(path.as_str().to_owned()),
                format!(
                    "limit reached: more than {} XML nodes; not read",
                    thousands(limits.xml_nodes)
                ),
            ));
        }
        Err(e) => problems.push(format!("is not well-formed XML: {e}")),
        Ok(_) => {}
    }
    if !problems.is_empty() {
        let reason = problems.join("; ");
        reader.push(
            FindingRule::C004,
            1,
            format!("an MSBuild file that {reason}"),
            &reason,
        );
    }
    if let Ok(doc) = parsed {
        for node in doc.descendants() {
            if node.is_element() {
                reader.element(node);
            } else if node.is_text() {
                let line = reader.line(node.range().start);
                reader.scan_text(node.text().unwrap_or_default(), line, true);
            }
        }
    }
    if reader.file.dropped > 0 && reader.file.gap.is_none() {
        reader.file.gap = Some(Gap::new(
            GapRule::C002,
            Some(path.as_str().to_owned()),
            format!(
                "limit reached: {} more findings in this file were not listed (the limit is {} per file)",
                thousands(reader.file.dropped),
                thousands(limits.findings_per_file)
            ),
        ));
    }
    reader.file
}

/// Reads every `.props`, `.targets` and `.tasks` file of a package, and
/// every file of any name that an import reaches from them, and adds C201
/// to C207 and C004 to `outcome`. A finding in a file that no entry point
/// reaches through literal imports says so. Returns the package paths that
/// `UsingTask AssemblyFile` names.
pub(crate) fn scan(
    files: &mut dyn Files,
    entries: &[Entry],
    entry_points: &BTreeSet<PackagePath>,
    limits: &Limits,
    outcome: &mut Outcome,
) -> BTreeSet<PackagePath> {
    let index: BTreeMap<String, &Entry> = entries
        .iter()
        .map(|e| (e.path.as_str().to_lowercase(), e))
        .collect();
    let mut queue: VecDeque<&Entry> = entries.iter().filter(|e| is_msbuild(&e.path)).collect();
    let mut queued: BTreeSet<&PackagePath> = queue.iter().map(|e| &e.path).collect();
    let mut parsed: BTreeMap<&PackagePath, File> = BTreeMap::new();
    while let Some(entry) = queue.pop_front() {
        let cap = limits.text_bytes.saturating_add(1);
        let bytes = match files.read(entry, cap, limits, &mut outcome.budget) {
            Err(gap) => {
                outcome.gaps.push(gap);
                continue;
            }
            Ok(bytes) if bytes.len() as u64 > limits.text_bytes => {
                outcome.gaps.push(Gap::new(
                    GapRule::C002,
                    Some(entry.path.as_str().to_owned()),
                    format!(
                        "limit reached: an MSBuild file over {} bytes; not read",
                        thousands(limits.text_bytes)
                    ),
                ));
                continue;
            }
            Ok(bytes) => bytes,
        };
        let file = parse(&entry.path, &bytes, limits, &index);
        for target in file.imports.iter().filter_map(|t| index.get(t)) {
            if queued.insert(&target.path) {
                queue.push_back(target);
            }
        }
        parsed.insert(&entry.path, file);
    }

    let mut reached: BTreeSet<&PackagePath> = BTreeSet::new();
    let mut walk: VecDeque<&PackagePath> = entry_points
        .iter()
        .filter(|p| parsed.contains_key(p))
        .collect();
    while let Some(path) = walk.pop_front() {
        if reached.insert(path) {
            let imports = parsed.get(path).map(|f| &f.imports).into_iter().flatten();
            walk.extend(imports.filter_map(|t| index.get(t)).map(|e| &e.path));
        }
    }

    let mut assemblies = BTreeSet::new();
    for (path, file) in parsed {
        let note = !reached.contains(path);
        for mut found in file.findings {
            if note && found.rule != FindingRule::C004 {
                found.message.push_str(
                    " (in a file not imported by any entry point through a literal path)",
                );
            }
            outcome.findings.push(found);
        }
        outcome.gaps.extend(file.gap);
        assemblies.extend(
            file.assemblies
                .iter()
                .filter_map(|a| index.get(a))
                .map(|e| e.path.clone()),
        );
    }
    assemblies
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    fn path(p: &str) -> PackagePath {
        PackagePath::new(p, &Limits::default()).unwrap()
    }

    fn parse_alone(text: &str, limits: &Limits) -> File {
        parse(
            &path("a.targets"),
            text.as_bytes(),
            limits,
            &BTreeMap::new(),
        )
    }

    fn rules(file: &File) -> Vec<&'static str> {
        file.findings.iter().map(|f| f.rule.id()).collect()
    }

    #[test]
    fn imports_resolve_relative_to_the_importing_file() {
        let from = path("build/net8.0/Contoso.targets");
        let cases = [
            (
                "$(MSBuildThisFileDirectory)a.targets",
                Some("build/net8.0/a.targets"),
            ),
            (
                "$(msbuildthisfiledirectory)..\\b.props",
                Some("build/b.props"),
            ),
            ("tasks/c.targets", Some("build/net8.0/tasks/c.targets")),
            ("..\\..\\..\\outside.targets", None),
            ("$(Other)\\x.targets", None),
            ("$(MSBuildThisFileDirectory)$(Name).targets", None),
            ("*.targets", None),
            ("C:\\x.targets", None),
            ("/etc/x.targets", None),
        ];
        for (raw, expected) in cases {
            assert_eq!(resolve(raw, &from).as_deref(), expected, "{raw}");
        }
    }

    #[test]
    fn urls_are_found_at_word_starts_and_not_inside_properties() {
        let text =
            "get https://example.invalid/a, then ftp://x.invalid/b. xhttp://no $(S)://$(H)/p";
        let found: Vec<&str> = urls(text).into_iter().map(|(_, u)| u).collect();
        assert_eq!(found, ["https://example.invalid/a", "ftp://x.invalid/b"]);
        assert_eq!(urls("HTTPS://EXAMPLE.INVALID").len(), 1);
        assert_eq!(urls("https://"), []);
        assert_eq!(urls("é https://x.invalid"), [(3, "https://x.invalid")]);
    }

    #[test]
    fn a_base64_run_is_reported_from_200_characters_and_short_hex_is_not() {
        let short = "Q".repeat(199);
        let long = format!("{}==", "Q".repeat(200));
        assert_eq!(base64_runs(&short), []);
        assert_eq!(base64_runs(&long), [(0, long.as_str())]);
        assert_eq!(base64_runs(&"A.".repeat(300)), []);
        // A strong-name public key is 320 hex digits: not reported.
        let key = "0024000004800000940000000602".repeat(12);
        assert_eq!(base64_runs(&key), []);
        let hex_at_limit = "0a".repeat(512);
        assert_eq!(base64_runs(&hex_at_limit), []);
        let hex_past_limit = format!("{hex_at_limit}0");
        assert_eq!(base64_runs(&hex_past_limit).len(), 1);
    }

    #[test]
    fn a_file_just_over_the_node_limit_is_a_gap() {
        let limits = Limits {
            xml_nodes: 3,
            ..Limits::default()
        };
        // Root, Project, Target: three nodes.
        let fits = parse_alone("<Project><Target/></Project>", &limits);
        assert!(fits.gap.is_none(), "{fits:?}");
        let over = parse_alone("<Project><Target/><Target/></Project>", &limits);
        assert_eq!(over.gap.map(|g| g.rule), Some(GapRule::C002));
    }

    #[test]
    fn one_finding_past_the_per_file_limit_is_counted_not_listed() {
        let limits = Limits {
            findings_per_file: 2,
            ..Limits::default()
        };
        let two = parse_alone("<P a='http://a.invalid' b='http://b.invalid'/>", &limits);
        assert_eq!(two.findings.len(), 2);
        assert!(two.gap.is_none());
        let three = parse_alone(
            "<P a='http://a.invalid' b='http://b.invalid' c='http://c.invalid'/>",
            &limits,
        );
        assert_eq!(three.findings.len(), 2);
        assert_eq!(three.dropped, 1);
        assert_eq!(three.gap.map(|g| g.rule), Some(GapRule::C002));
    }

    #[test]
    fn an_msbuild_file_one_byte_over_the_read_cap_is_a_gap() {
        let dir = tempfile::tempdir().unwrap();
        let fits = "<Project/>";
        std::fs::write(dir.path().join("fits.targets"), fits).unwrap();
        std::fs::write(dir.path().join("over.targets"), format!("{fits} ")).unwrap();
        let limits = Limits {
            text_bytes: fits.len() as u64,
            ..Limits::default()
        };
        let mut folder = crate::folder::Folder::new(dir.path());
        let mut outcome = Outcome::default();
        let entries = folder.entries(&limits, &mut outcome);
        scan(
            &mut folder,
            &entries,
            &BTreeSet::new(),
            &limits,
            &mut outcome,
        );
        assert_eq!(outcome.gaps.len(), 1, "{outcome:?}");
        assert_eq!(outcome.gaps[0].path.as_deref(), Some("over.targets"));
        assert_eq!(outcome.gaps[0].rule, GapRule::C002);
    }

    #[test]
    fn exec_is_a_task_only_inside_a_target() {
        let file = parse_alone(
            "<Project><ItemGroup><Exec Include='x' /></ItemGroup>\
             <Target Name='t'><Exec Command='y' /></Target></Project>",
            &Limits::default(),
        );
        assert_eq!(rules(&file), ["C203"]);
        assert_eq!(file.findings[0].evidence.as_deref(), Some("y"));
    }

    #[test]
    fn schema_elements_match_their_exact_name() {
        let file = parse_alone(
            "<Project><usingtask TaskName='x' TaskFactory='CodeTaskFactory' />\
             <UsingTask TaskName='y' TaskFactory='CodeTaskFactory' /></Project>",
            &Limits::default(),
        );
        assert_eq!(rules(&file), ["C201"]);
        assert!(file.findings[0].message.contains("task y"));
    }

    /// The work is linear in the input: these four inputs took 81, 20, 86 and
    /// more than 300 seconds in release builds with the quadratic line lookup
    /// and URL search. Linear code reads each in well under a second in a
    /// release build and a few seconds in a debug build, so a bound of 60
    /// seconds catches a regression without depending on a fast machine.
    #[test]
    fn large_inputs_are_read_in_linear_time() {
        let limits = Limits {
            findings_per_file: u64::MAX,
            ..Limits::default()
        };
        let inputs = [
            format!("<Project>{}</Project>", "<a/>".repeat(100_000)),
            format!("{}{}", "<a>".repeat(150_000), "</a>".repeat(150_000)),
            format!(
                "<Project><N>{}</N></Project>",
                "https://example.invalid/x ".repeat(100_000)
            ),
            format!(
                "<Project><N>{}</N></Project>",
                "https://example.invalid/x ".repeat(200_000)
            ),
        ];
        for (i, input) in inputs.iter().enumerate() {
            let started = Instant::now();
            let file = parse_alone(input, &limits);
            let took = started.elapsed();
            assert!(took < Duration::from_secs(60), "input {i} took {took:?}");
            if i >= 2 {
                assert!(file.findings.len() >= 100_000, "input {i}");
            }
        }
    }
}
