//! Text and JSON writers, into any `Write`, and the escaping of text that
//! comes from packages.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::{self, Write};

use serde::Serialize;

use crate::inventory::Asset;
use crate::scan::{FailOn, Gap, InputKind, Origin, PackageScan, Scan, Severity, Verdict};

const TOOL: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");

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
        if outcome.findings.is_empty() && outcome.gaps.is_empty() {
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
            gap_line(out, gap)?;
        }
        for finding in &outcome.findings {
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
        gap_line(out, gap)?;
    }
    let count = |severity: Severity| {
        scan.findings()
            .filter(|(_, f)| f.severity == severity)
            .count()
    };
    let mut summary = format!(
        "{}, {}, {}",
        plural(count(Severity::Error), "error"),
        plural(count(Severity::Warning), "warning"),
        plural(count(Severity::Note), "note")
    );
    if gaps > 0 {
        let _ = write!(summary, ", {}", plural(gaps, "gap"));
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

fn gap_line(out: &mut dyn Write, gap: &Gap) -> io::Result<()> {
    let message = match &gap.path {
        Some(path) if !gap.message.contains(path.as_str()) => format!("{}: {path}", gap.message),
        _ => gap.message.clone(),
    };
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
}

#[derive(Serialize)]
struct GapOut<'a> {
    rule: &'static str,
    input: Option<&'a str>,
    package: Option<&'a str>,
    version: Option<&'a str>,
    path: Option<&'a str>,
    message: &'a str,
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
            })
            .collect(),
        incomplete: scan
            .input_gaps
            .iter()
            .map(|(input, gap)| GapOut {
                rule: gap.rule.id(),
                input: Some(input),
                package: None,
                version: None,
                path: gap.path.as_deref(),
                message: &gap.message,
            })
            .chain(scan.packages.iter().flat_map(|package| {
                package.outcome.gaps.iter().map(move |gap| GapOut {
                    rule: gap.rule.id(),
                    input: None,
                    package: Some(package.id.as_str()),
                    version: Some(package.version.as_str()),
                    path: gap.path.as_deref(),
                    message: &gap.message,
                })
            }))
            .collect(),
    };
    serde_json::to_writer_pretty(&mut *out, &report)?;
    writeln!(out)
}

#[cfg(test)]
mod tests {
    use super::*;

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
