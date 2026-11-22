//! Rules C201 to C207 and C004 over the MSBuild files of a package, and the
//! import graph that says which of them an entry point reaches. Pure, apart
//! from the capped reads it asks the package view for.
//!
//! What MSBuild does, checked in its source on 2026-11-22: it reads project
//! files with `DtdProcessing.Ignore`, detects UTF-8 and UTF-16 from the byte
//! order mark and honours any encoding the XML declaration names
//! (`src/Build/Xml/XmlReaderExtension.cs`). Schema elements such as
//! `Import`, `UsingTask` and `Target` are matched by exact name
//! (`src/Build/Evaluation/ProjectParser.cs`); task names such as `Exec` are
//! looked up ignoring case (`src/Build/Instance/TaskRegistry.cs`).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use roxmltree::{Document, Node, ParsingOptions};

use crate::package::{Entry, Files, Limits, PackagePath, thousands};
use crate::scan::{Finding, FindingRule, Gap, GapRule, Outcome};

/// Evidence longer than this is cut, with the full length in the message.
const EVIDENCE_CHARS: usize = 240;

/// The shortest run of base64 characters that C206 reports.
const BASE64_RUN: usize = 200;

/// Whether a path names an MSBuild file: `.props`, `.targets` or `.tasks`,
/// wherever it is in the package.
pub(crate) fn is_msbuild(path: &PackagePath) -> bool {
    let name = path.as_str().rsplit('/').next().unwrap_or_default();
    name.rsplit_once('.').is_some_and(|(_, ext)| {
        ["props", "targets", "tasks"]
            .iter()
            .any(|e| ext.eq_ignore_ascii_case(e))
    })
}

/// The text of a file, decoded as MSBuild would, and why it is C004 if it is.
pub(crate) fn decode(bytes: &[u8]) -> (String, Option<String>) {
    let utf16 = |bytes: &[u8], big_endian: bool| {
        let (pairs, _) = bytes.as_chunks::<2>();
        let units: Vec<u16> = pairs
            .iter()
            .map(|pair| {
                if big_endian {
                    u16::from_be_bytes(*pair)
                } else {
                    u16::from_le_bytes(*pair)
                }
            })
            .collect();
        let odd = bytes.len() % 2 == 1;
        match String::from_utf16(&units) {
            Ok(text) if !odd => (text, None),
            _ => (
                String::from_utf16_lossy(&units),
                Some("UTF-16 that is not valid".to_owned()),
            ),
        }
    };
    match bytes {
        [0xEF, 0xBB, 0xBF, rest @ ..] => utf8(rest),
        [0xFF, 0xFE, rest @ ..] => utf16(rest, false),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, true),
        [b'<', 0, ..] => utf16(bytes, false),
        [0, b'<', ..] => utf16(bytes, true),
        _ => utf8(bytes),
    }
}

fn utf8(bytes: &[u8]) -> (String, Option<String>) {
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(256)]).into_owned();
    let other = declared_encoding(&head)
        .filter(|name| !is_unicode(name))
        .map(|name| format!("declares the encoding {name}"));
    match (std::str::from_utf8(bytes), other) {
        (Ok(text), other) => (text.to_owned(), other),
        // A file that declares a single-byte encoding is read by MSBuild in
        // that encoding; reading each byte as a character keeps every ASCII
        // construct where it is.
        (Err(_), Some(other)) => (bytes.iter().map(|b| char::from(*b)).collect(), Some(other)),
        // Anything else is read as .NET would, with replacement characters.
        (Err(_), None) => (
            String::from_utf8_lossy(bytes).into_owned(),
            Some("not UTF-8 or UTF-16".to_owned()),
        ),
    }
}

fn is_unicode(name: &str) -> bool {
    ["utf-8", "utf8", "utf-16", "utf-16le", "utf-16be", "unicode"]
        .iter()
        .any(|n| name.eq_ignore_ascii_case(n))
}

/// The `encoding` of the XML declaration, if there is one.
fn declared_encoding(text: &str) -> Option<String> {
    let declaration = text.strip_prefix("<?xml")?;
    let declaration = &declaration[..declaration.find("?>")?];
    let after = &declaration[declaration.find("encoding")? + "encoding".len()..];
    let after = after.trim_start().strip_prefix('=')?.trim_start();
    let quote = after.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let value = &after[1..];
    Some(value[..value.find(quote)?].to_owned())
}

/// Replaces a document type declaration with spaces, keeping line breaks,
/// so that the file parses as MSBuild reads it: with the DTD ignored.
/// Returns whether there was one.
fn blank_doctype(text: &mut String) -> bool {
    let Some(start) = text.find("<!DOCTYPE") else {
        return false;
    };
    let bytes = text.as_bytes();
    let mut depth = 0_usize;
    let mut quote = None;
    let mut end = bytes.len();
    let mut i = start + "<!DOCTYPE".len();
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if bytes[i..].starts_with(b"<!--") => {
                i = text[i..].find("-->").map_or(bytes.len(), |e| i + e + 2);
            }
            None => match b {
                b'"' | b'\'' => quote = Some(b),
                b'[' => depth += 1,
                b']' => depth = depth.saturating_sub(1),
                b'>' if depth == 0 => {
                    end = i + 1;
                    break;
                }
                _ => {}
            },
        }
        i += 1;
    }
    let blanked: String = text[start..end]
        .chars()
        .map(|c| if c == '\n' || c == '\r' { c } else { ' ' })
        .collect();
    text.replace_range(start..end, &blanked);
    true
}

/// An `Import` or a `UsingTask AssemblyFile` path, as written, with its line.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Reference {
    raw: String,
    line: u32,
}

/// What one file holds.
#[derive(Debug, Default)]
struct Parsed {
    findings: Vec<Finding>,
    imports: Vec<Reference>,
    assemblies: Vec<Reference>,
    gap: Option<Gap>,
}

fn finding(
    rule: FindingRule,
    path: &PackagePath,
    line: u32,
    message: String,
    evidence: &str,
) -> Finding {
    let mut found = Finding::new(rule, Some(path.as_str().to_owned()), message);
    found.line = Some(line);
    found.evidence = Some(if evidence.chars().count() > EVIDENCE_CHARS {
        let cut: String = evidence.chars().take(EVIDENCE_CHARS).collect();
        format!("{cut}...")
    } else {
        evidence.to_owned()
    });
    found
}

fn line_of(doc: &Document<'_>, offset: usize) -> u32 {
    doc.text_pos_at(offset).row
}

/// A line number plus the line breaks before `at` in `text`.
fn line_in(line: u32, text: &str, at: usize) -> u32 {
    let breaks = text[..at].matches('\n').count();
    line.saturating_add(u32::try_from(breaks).unwrap_or(u32::MAX))
}

/// Reads one MSBuild file.
fn parse(path: &PackagePath, bytes: &[u8], limits: &Limits) -> Parsed {
    let mut parsed = Parsed::default();
    let (mut text, odd_encoding) = decode(bytes);
    let mut problems: Vec<String> = odd_encoding.into_iter().collect();
    if blank_doctype(&mut text) {
        problems.push("has a DTD, which MSBuild ignores".to_owned());
    }
    let options = ParsingOptions {
        allow_dtd: false,
        nodes_limit: u32::try_from(limits.xml_nodes).unwrap_or(u32::MAX),
        ..ParsingOptions::default()
    };
    let doc = match Document::parse_with_options(&text, options) {
        Ok(doc) => doc,
        Err(roxmltree::Error::NodesLimitReached) => {
            parsed.gap = Some(Gap::new(
                GapRule::C002,
                Some(path.as_str().to_owned()),
                format!(
                    "limit reached: more than {} XML nodes; not read",
                    thousands(limits.xml_nodes)
                ),
            ));
            return parsed;
        }
        Err(e) => {
            problems.push(format!("not well-formed XML: {e}"));
            parsed.findings.push(finding(
                FindingRule::C004,
                path,
                1,
                format!("an MSBuild file that is {}", problems.join("; ")),
                &problems.join("; "),
            ));
            return parsed;
        }
    };
    if !problems.is_empty() {
        let reason = problems.join("; ");
        parsed.findings.push(finding(
            FindingRule::C004,
            path,
            1,
            format!("an MSBuild file that {reason}"),
            &reason,
        ));
    }
    for node in doc.descendants() {
        if node.is_element() {
            element(&doc, node, path, &mut parsed);
        } else if node.is_text() {
            let line = line_of(&doc, node.range().start);
            scan_text(
                node.text().unwrap_or_default(),
                line,
                path,
                &mut parsed.findings,
            );
        }
    }
    parsed
}

fn element(doc: &Document<'_>, node: Node<'_, '_>, path: &PackagePath, parsed: &mut Parsed) {
    let name = node.tag_name().name();
    let line = line_of(doc, node.range().start);
    let attribute = |wanted: &str| node.attribute(wanted);
    let attribute_any_case = |wanted: &str| {
        node.attributes()
            .find(|a| a.name().eq_ignore_ascii_case(wanted))
            .map(|a| a.value())
    };
    let in_target = node
        .parent_element()
        .is_some_and(|p| p.tag_name().name() == "Target");
    match name {
        "UsingTask" => {
            let task = attribute("TaskName").unwrap_or_default();
            // MSBuild's own TaskHostFactory and AssemblyTaskFactory run a
            // compiled task assembly, matched ignoring case as TaskRegistry
            // does; they compile nothing, and C202 reports the assembly.
            // A local cache had 66 of them in SDK packages.
            let compiles = |factory: &&str| {
                !["TaskHostFactory", "AssemblyTaskFactory"]
                    .iter()
                    .any(|own| factory.eq_ignore_ascii_case(own))
            };
            if let Some(factory) = attribute("TaskFactory").filter(compiles) {
                parsed.findings.push(finding(
                    FindingRule::C201,
                    path,
                    line,
                    format!("UsingTask with the task factory {factory} (task {task})"),
                    &format!("TaskFactory=\"{factory}\" TaskName=\"{task}\""),
                ));
            }
            if let Some(assembly) = attribute("AssemblyFile") {
                parsed.findings.push(finding(
                    FindingRule::C202,
                    path,
                    line,
                    format!("UsingTask loads an assembly (task {task})"),
                    assembly,
                ));
                parsed.assemblies.push(Reference {
                    raw: assembly.to_owned(),
                    line,
                });
            }
        }
        "Import" => {
            // An import with an `Sdk` attribute is resolved against that SDK
            // by the SDK resolver; it cannot reach a file of this package.
            // The corpus has 350 of them in workload manifests, so reporting
            // them as C207 would bury the imports that matter.
            if let Some(project) = attribute("Project").filter(|_| attribute("Sdk").is_none()) {
                parsed.imports.push(Reference {
                    raw: project.to_owned(),
                    line,
                });
            }
        }
        _ if in_target && name.eq_ignore_ascii_case("Exec") => {
            let command = attribute_any_case("Command").unwrap_or_default();
            parsed.findings.push(finding(
                FindingRule::C203,
                path,
                line,
                "Exec task".to_owned(),
                command,
            ));
        }
        _ if in_target && name.eq_ignore_ascii_case("DownloadFile") => {
            let source = attribute_any_case("SourceUrl").unwrap_or_default();
            parsed.findings.push(finding(
                FindingRule::C204,
                path,
                line,
                "DownloadFile task".to_owned(),
                source,
            ));
        }
        _ => {}
    }
    for attribute in node.attributes() {
        let value_line = line_of(doc, attribute.range_value().start);
        scan_text(attribute.value(), value_line, path, &mut parsed.findings);
    }
}

/// C205 and C206 over one piece of text that starts on `line`.
fn scan_text(text: &str, line: u32, path: &PackagePath, findings: &mut Vec<Finding>) {
    for (at, url) in urls(text) {
        findings.push(finding(
            FindingRule::C205,
            path,
            line_in(line, text, at),
            "URL".to_owned(),
            url,
        ));
    }
    for (at, run) in base64_runs(text) {
        findings.push(finding(
            FindingRule::C206,
            path,
            line_in(line, text, at),
            format!(
                "base64-looking string, {} characters",
                thousands(run.len() as u64)
            ),
            run,
        ));
    }
}

/// Every `http://`, `https://` and `ftp://` URL in a text, with its offset.
fn urls(text: &str) -> Vec<(usize, &str)> {
    let lower = text.to_ascii_lowercase();
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(next) = ["http://", "https://", "ftp://"]
        .iter()
        .filter_map(|scheme| lower[from..].find(scheme).map(|at| from + at))
        .min()
    {
        let starts_word = text[..next]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric());
        let scheme_end = next + lower[next..].find("://").map_or(0, |i| i + 3);
        let end = text[scheme_end..]
            .find(|c: char| c.is_whitespace() || "\"'<>`".contains(c))
            .map_or(text.len(), |e| scheme_end + e);
        let url = text[next..end].trim_end_matches(['.', ',', ';', ')']);
        if starts_word && url.len() > scheme_end - next {
            found.push((next, url));
        }
        from = end.max(next + 1);
    }
    found
}

/// Runs of at least 200 base64 characters, with up to two `=` after them.
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
            // Only hexadecimal digits is a key or a hash, not base64: a
            // local cache holds strong-name public keys of 320 digits.
            let hex = bytes[start..i].iter().all(u8::is_ascii_hexdigit);
            if i - start >= BASE64_RUN && !hex {
                found.push((start, &text[start..end]));
            }
            i = end.max(i);
        } else {
            i += 1;
        }
    }
    found
}

/// Resolves an `Import` or `AssemblyFile` path written in `from` to a path
/// inside the package. `None` if it uses any property other than
/// `$(MSBuildThisFileDirectory)` at its start, a wildcard, an absolute path,
/// or leaves the package.
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

/// Reads every MSBuild file of a package and adds C201 to C207 and C004 to
/// `outcome`. A finding in a file that no entry point reaches through
/// literal imports says so. Returns the package paths that `UsingTask
/// AssemblyFile` names.
pub(crate) fn scan(
    files: &mut dyn Files,
    entries: &[Entry],
    entry_points: &BTreeSet<PackagePath>,
    limits: &Limits,
    outcome: &mut Outcome,
) -> BTreeSet<PackagePath> {
    let by_lower: BTreeMap<String, &PackagePath> = entries
        .iter()
        .map(|e| (e.path.as_str().to_lowercase(), &e.path))
        .collect();
    let mut parsed: BTreeMap<&PackagePath, Parsed> = BTreeMap::new();
    for entry in entries.iter().filter(|e| is_msbuild(&e.path)) {
        let cap = limits.text_bytes.saturating_add(1);
        match files.read(entry, cap, limits, &mut outcome.budget) {
            Err(gap) => outcome.gaps.push(gap),
            Ok(bytes) if bytes.len() as u64 > limits.text_bytes => outcome.gaps.push(Gap::new(
                GapRule::C002,
                Some(entry.path.as_str().to_owned()),
                format!(
                    "limit reached: an MSBuild file over {} bytes; not read",
                    thousands(limits.text_bytes)
                ),
            )),
            Ok(bytes) => {
                parsed.insert(&entry.path, parse(&entry.path, &bytes, limits));
            }
        }
    }

    // The import graph, and C207 for every import that leaves it.
    let mut edges: BTreeMap<&PackagePath, Vec<&PackagePath>> = BTreeMap::new();
    let mut assemblies = BTreeSet::new();
    for (path, file) in &mut parsed {
        for import in &file.imports {
            match resolve(&import.raw, path).and_then(|p| by_lower.get(&p).copied()) {
                Some(target) => edges.entry(*path).or_default().push(target),
                None => file.findings.push(finding(
                    FindingRule::C207,
                    path,
                    import.line,
                    "an Import that cannot be resolved inside the package".to_owned(),
                    &import.raw,
                )),
            }
        }
        for assembly in &file.assemblies {
            if let Some(target) = resolve(&assembly.raw, path).and_then(|p| by_lower.get(&p)) {
                assemblies.insert((*target).clone());
            }
        }
    }
    let mut reached: BTreeSet<&PackagePath> = BTreeSet::new();
    let mut queue: VecDeque<&PackagePath> = entry_points
        .iter()
        .filter(|p| parsed.contains_key(p))
        .collect();
    while let Some(path) = queue.pop_front() {
        if reached.insert(path) {
            queue.extend(edges.get(path).into_iter().flatten().copied());
        }
    }

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
    }
    assemblies
}

/// The ID and version a nuspec declares, if it is well-formed and has both.
pub(crate) fn nuspec_identity(bytes: &[u8], limits: &Limits) -> Option<(String, String)> {
    let (mut text, _) = decode(bytes);
    blank_doctype(&mut text);
    let options = ParsingOptions {
        nodes_limit: u32::try_from(limits.xml_nodes).unwrap_or(u32::MAX),
        ..ParsingOptions::default()
    };
    let doc = Document::parse_with_options(&text, options).ok()?;
    let metadata = doc
        .root_element()
        .children()
        .find(|n| n.tag_name().name() == "metadata")?;
    let field = |name: &str| {
        metadata
            .children()
            .find(|n| n.tag_name().name() == name)
            .and_then(|n| n.text())
            .map(|t| t.trim().to_owned())
    };
    Some((field("id")?, field("version")?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(p: &str) -> PackagePath {
        PackagePath::new(p, &Limits::default()).unwrap()
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
    }

    #[test]
    fn a_base64_run_is_reported_from_200_characters() {
        let short = "Q".repeat(199);
        let long = format!("{}==", "Q".repeat(200));
        assert_eq!(base64_runs(&short), []);
        assert_eq!(base64_runs(&long), [(0, long.as_str())]);
        assert_eq!(base64_runs(&"A.".repeat(300)), []);
        // A strong-name public key is 320 hexadecimal digits: not base64.
        assert_eq!(base64_runs(&"0024000004800000940000000602".repeat(12)), []);
    }

    #[test]
    fn a_doctype_is_blanked_without_moving_lines() {
        let mut text =
            "<?xml version=\"1.0\"?>\n<!DOCTYPE P [\n<!ENTITY e \"]>\">\n]>\n<P/>".to_owned();
        assert!(blank_doctype(&mut text));
        assert_eq!(text.lines().count(), 5);
        assert!(text.ends_with("\n<P/>"));
        assert!(!text.contains("ENTITY"));
        assert!(Document::parse(&text).is_ok());
    }

    #[test]
    fn encodings_are_detected_as_msbuild_detects_them() {
        assert_eq!(decode(b"\xEF\xBB\xBF<P/>"), ("<P/>".to_owned(), None));
        assert_eq!(decode(b"<\0P\0/\0>\0"), ("<P/>".to_owned(), None));
        assert_eq!(decode(b"\0<\0P\0/\0>"), ("<P/>".to_owned(), None));
        assert!(
            decode(b"<?xml version='1.0' encoding='iso-8859-1'?><P/>")
                .1
                .is_some()
        );
        assert!(
            decode(b"<?xml version='1.0' encoding='UTF-8'?><P/>")
                .1
                .is_none()
        );
        let (text, problem) = decode(b"<?xml version='1.0' encoding='windows-1252'?><P a='\xE9'/>");
        assert!(problem.is_some());
        assert!(text.contains('\u{e9}'));
        assert!(decode(b"<P a='\xE9'/>").1.is_some());
    }

    #[test]
    fn a_file_just_over_the_node_limit_is_a_gap() {
        let limits = Limits {
            xml_nodes: 3,
            ..Limits::default()
        };
        // Root, Project, Target: three nodes.
        let fits = parse(&path("a.targets"), b"<Project><Target/></Project>", &limits);
        assert!(fits.gap.is_none(), "{fits:?}");
        let over = parse(
            &path("a.targets"),
            b"<Project><Target/><Target/></Project>",
            &limits,
        );
        assert_eq!(over.gap.map(|g| g.rule), Some(GapRule::C002));
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
    fn exec_outside_a_target_is_an_item_not_a_task() {
        let parsed = parse(
            &path("a.targets"),
            b"<Project><ItemGroup><Exec Include='x' /></ItemGroup></Project>",
            &Limits::default(),
        );
        assert!(parsed.findings.is_empty(), "{parsed:?}");
    }

    #[test]
    fn schema_elements_match_their_exact_name() {
        let parsed = parse(
            &path("a.targets"),
            b"<Project><usingtask TaskName='x' TaskFactory='CodeTaskFactory' /></Project>",
            &Limits::default(),
        );
        assert!(parsed.findings.is_empty(), "{parsed:?}");
    }

    #[test]
    fn a_nuspec_gives_the_id_and_version() {
        let nuspec = b"<package xmlns='urn:x'><metadata><id> Contoso.A </id><version>1.0.0</version></metadata></package>";
        assert_eq!(
            nuspec_identity(nuspec, &Limits::default()),
            Some(("Contoso.A".to_owned(), "1.0.0".to_owned()))
        );
        assert_eq!(nuspec_identity(b"<package/>", &Limits::default()), None);
    }
}
