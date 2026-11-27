//! Text, JSON and SARIF writers, into any `Write`, and the escaping of text
//! that comes from packages.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::{self, Write};

use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::baseline::{self, Fingerprint, Label, Review};
use crate::inventory::Asset;
use crate::scan::{
    Cause, FailOn, Finding, Gap, InputKind, NOT_FOUND_IN, Origin, Owner, PackageScan, RULES, Scan,
    Severity, Verdict,
};

const TOOL: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");
const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");

/// Escapes text for a terminal: every control character, every character
/// of the Unicode `Bidi_Control` set and the invisible format characters
/// become `\u{...}`, and a backslash becomes `\\` so the escapes stay
/// unambiguous.
pub(crate) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c == '\\' {
            out.push_str("\\\\");
        } else if is_hidden(c) {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

/// Control characters, bidirectional controls, and characters that print
/// as nothing.
fn is_hidden(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{ad}'
                | '\u{34f}'
                | '\u{61c}'
                | '\u{115f}'..='\u{1160}'
                | '\u{17b4}'..='\u{17b5}'
                | '\u{180b}'..='\u{180f}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{3164}'
                | '\u{fe00}'..='\u{fe0f}'
                | '\u{feff}'
                | '\u{ffa0}'
                | '\u{fff0}'..='\u{fffb}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e000}'..='\u{f8ff}'
                | '\u{e0000}'..='\u{10ffff}'
        )
}

/// Evidence for a terminal line: whitespace collapsed, at most 100
/// characters.
fn shorten(text: &str) -> String {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() > 100 {
        let cut: String = collapsed.chars().take(100).collect();
        format!("{cut}...")
    } else {
        collapsed
    }
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        format!("1 {word}")
    } else {
        format!("{n} {word}s")
    }
}

/// The report as text, grouped by package.
pub(crate) fn text(scan: &Scan, fail_on: FailOn, out: &mut dyn Write) -> io::Result<()> {
    let gaps = scan.gap_count();
    let state = if gaps == 0 {
        "all complete".to_owned()
    } else {
        plural(gaps, "gap")
    };
    writeln!(
        out,
        "{TOOL} {VERSION}: {} from {}, {state}",
        plural(scan.packages.len(), "package"),
        plural(scan.inputs.len(), "input")
    )?;
    for package in &scan.packages {
        let outcome = &package.outcome;
        let shown: Vec<&Finding> = outcome
            .findings
            .iter()
            .filter(|f| !scan.finding_accepted(package, f))
            .collect();
        if shown.is_empty() && outcome.gaps.is_empty() {
            continue;
        }
        let origin = match package.origin {
            Origin::Graph(dependency) => format!("  ({})", dependency.as_str()),
            Origin::Nupkg | Origin::PackagesDir => String::new(),
        };
        writeln!(out)?;
        writeln!(
            out,
            "{} {}{origin}",
            escape(package.id.as_str()),
            escape(package.version.as_str())
        )?;
        for gap in &outcome.gaps {
            gap_line(out, gap, scan.gap_accepted(Owner::Package(package), gap))?;
        }
        for finding in shown {
            writeln!(
                out,
                "  {:<9}{}  {}",
                finding.severity.as_str(),
                finding.rule.id(),
                escape(&finding.message)
            )?;
            // MSBuild findings have a line, assembly findings evidence
            // without a line. Inventory findings name the path in the
            // message already.
            if let Some(path) = &finding.path
                && (finding.line.is_some() || finding.evidence.is_some())
            {
                let line = finding.line.map(|l| format!(":{l}")).unwrap_or_default();
                let evidence = finding.evidence.as_deref().map(shorten).unwrap_or_default();
                writeln!(
                    out,
                    "{:17}{}{line}  {}",
                    "",
                    escape(path),
                    escape(&evidence)
                )?;
            }
        }
    }
    for (input, gap) in &scan.input_gaps {
        writeln!(out)?;
        writeln!(out, "{}", escape(input))?;
        gap_line(out, gap, scan.gap_accepted(Owner::Input(input), gap))?;
    }
    review_lines(scan, out)?;
    let count = |severity: Severity| {
        scan.open_findings()
            .filter(|(_, f)| f.severity == severity)
            .count()
    };
    let mut summary = format!(
        "{}, {}, {}",
        plural(count(Severity::Error), "error"),
        plural(count(Severity::Warning), "warning"),
        plural(count(Severity::Note), "note")
    );
    let open_gaps = scan
        .gaps()
        .filter(|(o, g)| !scan.gap_accepted(*o, g))
        .count();
    if open_gaps > 0 {
        let _ = write!(summary, ", {}", plural(open_gaps, "gap"));
    }
    let accepted = scan.accepted_count();
    if accepted > 0 {
        let _ = write!(summary, " ({accepted} more accepted by the baseline)");
    }
    writeln!(out)?;
    writeln!(out, "{summary}")?;
    let verdict = scan.verdict(fail_on);
    let why = match (verdict, fail_on) {
        (Verdict::Findings, _) => format!("findings at or above --fail-on {}", fail_on.as_str()),
        (Verdict::Incomplete, _) => "the scan is incomplete, see the gaps above".to_owned(),
        (Verdict::Clean, FailOn::Never) => "--fail-on never".to_owned(),
        (Verdict::Clean, FailOn::At(_)) => {
            format!("no finding at or above --fail-on {}", fail_on.as_str())
        }
    };
    writeln!(out, "exit {}: {why}", verdict.code())
}

/// The baseline entries that accept nothing or are mislabelled, as text.
fn review_lines(scan: &Scan, out: &mut dyn Write) -> io::Result<()> {
    let review = baseline::review(scan);
    if !review.is_empty() {
        writeln!(out)?;
        writeln!(out, "baseline")?;
        for (fingerprint, label) in &review.unused {
            writeln!(
                out,
                "  {:<9}{}",
                "unused",
                escape(&unused(*fingerprint, label))
            )?;
        }
        for (fingerprint, label, actual) in &review.mislabelled {
            let message = mislabelled(*fingerprint, label, actual);
            writeln!(out, "  {:<9}{}", "label", escape(&message))?;
        }
    }
    Ok(())
}

fn unused(fingerprint: Fingerprint, label: &Label) -> String {
    format!("entry {fingerprint} ({label}) accepts nothing in this scan")
}

fn mislabelled(fingerprint: Fingerprint, label: &Label, actual: &Label) -> String {
    format!("entry {fingerprint} says {label}, but accepts {actual}")
}

fn gap_line(out: &mut dyn Write, gap: &Gap, accepted: bool) -> io::Result<()> {
    let mut message = match &gap.path {
        Some(path) if !gap.message.contains(path.as_str()) => format!("{}: {path}", gap.message),
        _ => gap.message.clone(),
    };
    if accepted {
        message.push_str(" (accepted by the baseline)");
    }
    writeln!(out, "  {:<9}{}  {}", "gap", gap.rule.id(), escape(&message))
}

#[derive(Serialize)]
struct Report<'a> {
    schema: u32,
    tool: Tool,
    inputs: Vec<InputOut<'a>>,
    packages: Vec<PackageOut<'a>>,
    findings: Vec<FindingOut<'a>>,
    incomplete: Vec<GapOut<'a>>,
    baseline: BaselineOut<'a>,
}

/// Entries of the baseline that accept nothing, or whose label is not what
/// they accept.
#[derive(Serialize)]
struct BaselineOut<'a> {
    unused: Vec<EntryOut<'a>>,
    mislabelled: Vec<EntryOut<'a>>,
}

#[derive(Serialize)]
struct EntryOut<'a> {
    fingerprint: String,
    #[serde(flatten)]
    label: &'a Label,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepts: Option<Label>,
}

impl<'a> From<Review<'a>> for BaselineOut<'a> {
    fn from(review: Review<'a>) -> Self {
        Self {
            unused: review
                .unused
                .into_iter()
                .map(|(fingerprint, label)| EntryOut {
                    fingerprint: fingerprint.to_string(),
                    label,
                    accepts: None,
                })
                .collect(),
            mislabelled: review
                .mislabelled
                .into_iter()
                .map(|(fingerprint, label, actual)| EntryOut {
                    fingerprint: fingerprint.to_string(),
                    label,
                    accepts: Some(actual),
                })
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct Tool {
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct InputOut<'a> {
    path: &'a str,
    kind: Option<&'static str>,
    format_version: Option<u32>,
}

#[derive(Serialize)]
struct PackageOut<'a> {
    id: &'a str,
    version: &'a str,
    dependency: Option<&'static str>,
    frameworks: &'a BTreeSet<String>,
    source: Option<&'a str>,
    complete: bool,
    read: Read,
    assets: Vec<AssetOut<'a>>,
}

#[derive(Serialize)]
struct Read {
    entries: u64,
    bytes: u64,
}

#[derive(Serialize)]
struct AssetOut<'a> {
    path: &'a str,
    #[serde(flatten)]
    asset: &'a Asset,
}

#[derive(Serialize)]
struct FindingOut<'a> {
    rule: &'static str,
    severity: Severity,
    package: &'a str,
    version: &'a str,
    path: Option<&'a str>,
    line: Option<u32>,
    message: &'a str,
    evidence: Option<&'a str>,
    fingerprint: String,
    accepted: bool,
}

#[derive(Serialize)]
struct GapOut<'a> {
    rule: &'static str,
    input: Option<&'a str>,
    package: Option<&'a str>,
    version: Option<&'a str>,
    path: Option<&'a str>,
    message: &'a str,
    fingerprint: String,
    accepted: bool,
}

fn package_out(package: &PackageScan) -> PackageOut<'_> {
    PackageOut {
        id: package.id.as_str(),
        version: package.version.as_str(),
        dependency: match package.origin {
            Origin::Graph(dependency) => Some(match dependency {
                crate::graph::Dependency::Direct => "direct",
                crate::graph::Dependency::CentralTransitive => "central_transitive",
                crate::graph::Dependency::Transitive => "transitive",
                crate::graph::Dependency::Download => "download",
            }),
            Origin::Nupkg | Origin::PackagesDir => None,
        },
        frameworks: &package.frameworks,
        source: package.source.as_deref(),
        complete: package.outcome.gaps.is_empty(),
        read: Read {
            entries: package.outcome.budget.entries,
            bytes: package.outcome.budget.bytes,
        },
        assets: package
            .assets
            .iter()
            .map(|(path, asset)| AssetOut {
                path: path.as_str(),
                asset,
            })
            .collect(),
    }
}

/// The report as one JSON object, schema 1.
pub(crate) fn json(scan: &Scan, out: &mut dyn Write) -> io::Result<()> {
    let report = Report {
        schema: 1,
        tool: Tool {
            name: TOOL,
            version: VERSION,
        },
        inputs: scan
            .inputs
            .iter()
            .map(|input| {
                let (kind, format_version) = match input.kind {
                    Some(InputKind::Lock(v)) => (Some("lock"), Some(v)),
                    Some(InputKind::Assets(v)) => (Some("assets"), Some(v)),
                    Some(InputKind::Nupkg) => (Some("nupkg"), None),
                    Some(InputKind::PackagesDir) => (Some("packages_dir"), None),
                    None => (None, None),
                };
                InputOut {
                    path: &input.path,
                    kind,
                    format_version,
                }
            })
            .collect(),
        packages: scan.packages.iter().map(package_out).collect(),
        findings: scan
            .findings()
            .map(|(package, finding)| FindingOut {
                rule: finding.rule.id(),
                severity: finding.severity,
                package: package.id.as_str(),
                version: package.version.as_str(),
                path: finding.path.as_deref(),
                line: finding.line,
                message: &finding.message,
                evidence: finding.evidence.as_deref(),
                fingerprint: finding.fingerprint(&package.id).to_string(),
                accepted: scan.finding_accepted(package, finding),
            })
            .collect(),
        incomplete: scan
            .gaps()
            .map(|(owner, gap)| {
                let (input, package) = match owner {
                    Owner::Input(input) => (Some(input), None),
                    Owner::Package(package) => (None, Some(package)),
                };
                GapOut {
                    rule: gap.rule.id(),
                    input,
                    package: package.map(|p| p.id.as_str()),
                    version: package.map(|p| p.version.as_str()),
                    path: gap.path.as_deref(),
                    message: &gap.message,
                    fingerprint: gap.fingerprint(owner).to_string(),
                    accepted: scan.gap_accepted(owner, gap),
                }
            })
            .collect(),
        baseline: baseline::review(scan).into(),
    };
    serde_json::to_writer_pretty(&mut *out, &report)?;
    writeln!(out)
}

/// A path as shown in the report, as a URI reference: relative paths stay
/// relative, absolute ones become `file:` URIs, and every byte other than
/// unreserved characters and `/` is percent-encoded (and the colon of a
/// drive letter kept).
fn uri(path: &str) -> String {
    let bytes = path.as_bytes();
    let drive = bytes.len() >= 3
        && bytes.first().is_some_and(u8::is_ascii_alphabetic)
        && bytes.get(1) == Some(&b':')
        && bytes.get(2) == Some(&b'/');
    let mut out = if drive {
        "file:///".to_owned()
    } else if path.starts_with('/') {
        "file://".to_owned()
    } else {
        String::new()
    };
    for (at, byte) in bytes.iter().enumerate() {
        if byte.is_ascii_alphanumeric() || b"-._~/".contains(byte) || (drive && at == 1) {
            out.push(char::from(*byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Note => "note",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

/// Where SARIF puts a package: each graph file that lists it, at the line
/// of its entry, as that is the file in the user's repository.
fn locations(package: &PackageScan) -> Value {
    package
        .listed
        .iter()
        .map(|(file, line)| {
            let mut physical = json!({"artifactLocation": {"uri": uri(file)}});
            if let Some(line) = line {
                physical["region"] = json!({"startLine": line});
            }
            json!({"physicalLocation": physical})
        })
        .collect()
}

/// A property bag without the fields that have no value.
fn properties(fields: &[(&str, Option<Value>)]) -> Value {
    Value::Object(
        fields
            .iter()
            .filter_map(|(name, value)| Some(((*name).to_owned(), value.clone()?)))
            .collect::<Map<_, _>>(),
    )
}

fn sarif_result(index: Option<usize>, package: &PackageScan, finding: &Finding) -> Value {
    let text = |s: &str| Value::from(s);
    let mut message = format!(
        "{} {}: {}",
        package.id.as_str(),
        package.version.as_str(),
        finding.message
    );
    if let Some(path) = &finding.path {
        let line = finding.line.map(|l| format!(":{l}")).unwrap_or_default();
        let _ = write!(message, " ({path}{line})");
    }
    if let Some(evidence) = &finding.evidence {
        let _ = write!(message, ": {}", shorten(evidence));
    }
    json!({
        "ruleId": finding.rule.id(),
        "ruleIndex": index,
        "level": level(finding.severity),
        "message": {"text": escape(&message)},
        "locations": locations(package),
        "partialFingerprints": {
            "customsFingerprint/v1": finding.fingerprint(&package.id).to_string()
        },
        "properties": properties(&[
            ("package", Some(text(package.id.as_str()))),
            ("version", Some(text(package.version.as_str()))),
            ("path", finding.path.as_deref().map(text)),
            ("line", finding.line.map(Value::from)),
            ("evidence", finding.evidence.as_deref().map(text)),
        ]),
    })
}

fn sarif_notification(index: Option<usize>, owner: Owner<'_>, gap: &Gap, accepted: bool) -> Value {
    let text = |s: &str| Value::from(s);
    let (places, package) = match owner {
        Owner::Input(input) => (
            json!([{"physicalLocation": {"artifactLocation": {"uri": uri(input)}}}]),
            None,
        ),
        Owner::Package(package) => (locations(package), Some(package)),
    };
    // SARIF is meant for upload, so it does not name the folders searched
    // for a missing package: they are paths of the machine that ran the scan.
    let said = match gap.cause {
        Cause::NotFound if gap.message.starts_with(NOT_FOUND_IN) => {
            "not found in the package folders searched"
        }
        _ => &gap.message,
    };
    let message = match package {
        Some(p) => format!("{} {}: {said}", p.id.as_str(), p.version.as_str()),
        None => said.to_owned(),
    };
    json!({
        "level": if accepted { "note" } else { "error" },
        "message": {"text": escape(&message)},
        "descriptor": {"id": gap.rule.id(), "index": index},
        "locations": places,
        "properties": properties(&[
            ("package", package.map(|p| text(p.id.as_str()))),
            ("version", package.map(|p| text(p.version.as_str()))),
            ("path", gap.path.as_deref().map(text)),
            ("fingerprint", Some(text(&gap.fingerprint(owner).to_string()))),
            ("accepted", Some(Value::from(accepted))),
        ]),
    })
}

/// The report as SARIF 2.1.0: one run, the rules of `customs rules`, one
/// result per finding the baseline does not accept, and each gap as a tool
/// execution notification.
pub(crate) fn sarif(scan: &Scan, out: &mut dyn Write) -> io::Result<()> {
    let rules: Vec<_> = RULES.iter().filter(|(_, s, _)| s.is_some()).collect();
    let descriptors: Vec<_> = RULES.iter().filter(|(_, s, _)| s.is_none()).collect();
    let results: Vec<Value> = scan
        .open_findings()
        .map(|(package, finding)| {
            let index = rules.iter().position(|r| r.0 == finding.rule.id());
            sarif_result(index, package, finding)
        })
        .collect();
    let notifications: Vec<Value> = scan
        .gaps()
        .map(|(owner, gap)| {
            let index = descriptors.iter().position(|d| d.0 == gap.rule.id());
            sarif_notification(index, owner, gap, scan.gap_accepted(owner, gap))
        })
        .collect();
    let review = baseline::review(scan);
    let configuration: Vec<Value> = review
        .unused
        .iter()
        .map(|(fingerprint, label)| ("note", unused(*fingerprint, label)))
        .chain(
            review
                .mislabelled
                .iter()
                .map(|(fingerprint, label, actual)| {
                    ("warning", mislabelled(*fingerprint, label, actual))
                }),
        )
        .map(|(level, message)| json!({"level": level, "message": {"text": escape(&message)}}))
        .collect();
    let help = format!("{REPOSITORY}/blob/main/docs/design.md#rules");
    let report = json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL,
                "version": VERSION,
                "semanticVersion": VERSION,
                "informationUri": REPOSITORY,
                "rules": rules.iter().map(|(id, severity, summary)| json!({
                    "id": id,
                    "shortDescription": {"text": summary},
                    "helpUri": help,
                    "defaultConfiguration": {"level": severity.map_or("none", level)},
                })).collect::<Vec<_>>(),
                "notifications": descriptors.iter().map(|(id, _, summary)| json!({
                    "id": id,
                    "shortDescription": {"text": summary},
                })).collect::<Vec<_>>(),
            }},
            "invocations": [{
                "executionSuccessful": true,
                "toolExecutionNotifications": notifications,
                "toolConfigurationNotifications": configuration,
            }],
            "results": results,
            "properties": {"acceptedByBaseline": scan.accepted_count()},
        }],
    });
    serde_json::to_writer_pretty(&mut *out, &report)?;
    writeln!(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_become_uri_references() {
        assert_eq!(
            uri("lock-v1/packages.lock.json"),
            "lock-v1/packages.lock.json"
        );
        assert_eq!(uri("a b/c:d%.json"), "a%20b/c%3Ad%25.json");
        assert_eq!(uri("C:/Users/x y/p.json"), "file:///C:/Users/x%20y/p.json");
        assert_eq!(uri("/home/u/p.json"), "file:///home/u/p.json");
        assert_eq!(uri("dir/é"), "dir/%C3%A9");
    }

    #[test]
    fn terminal_controls_and_bidi_overrides_are_escaped() {
        assert_eq!(escape("plain/path.targets"), "plain/path.targets");
        assert_eq!(escape("a\u{1b}[31mb"), "a\\u{1b}[31mb");
        assert_eq!(escape("x\u{202e}y\u{2066}z"), "x\\u{202e}y\\u{2066}z");
        assert_eq!(
            escape("tab\tnl\ncr\rdel\u{7f}c1\u{9b}"),
            "tab\\u{9}nl\\u{a}cr\\u{d}del\\u{7f}c1\\u{9b}"
        );
        assert_eq!(
            escape("zero\u{200b}width\u{feff}"),
            "zero\\u{200b}width\\u{feff}"
        );
        assert_eq!(escape(r"back\slash"), r"back\\slash");
        assert_eq!(escape("Gսոa ü 中"), "Gսոa ü 中");
    }
}
