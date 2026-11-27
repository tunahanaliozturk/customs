//! The command line: parses arguments, runs the command, writes the report
//! and maps the result to an exit code.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::archive;
use crate::archive::Nuspec;
use crate::baseline;
use crate::folder::Folder;
use crate::graph::{self, GraphKind, PackageId, PackageRef, PackageVersion};
use crate::inventory;
use crate::locate;
use crate::locate::{Listed, Location};
use crate::names;
use crate::package::{Limits, thousands};
use crate::report;
use crate::scan::{
    FailOn, Finding, FindingRule, Gap, GapRule, Input, InputKind, Origin, Outcome, PackageScan,
    RULES, Scan, Severity,
};
use crate::xml;

const HELP: &str = "\
customs: shows what the NuGet packages of a .NET project run at build time
and at load time. It reads the graph that restore resolved and inspects the
package files as data. It never runs MSBuild and never loads an assembly.

Usage:
  customs scan [PATH...] [--packages-dir DIR] [--format text|json|sarif]
               [--output FILE] [--fail-on note|warning|error|never]
               [--baseline FILE] [--write-baseline FILE]
  customs rules
  customs --help | --version

PATH is a packages.lock.json, an obj/project.assets.json, a .nupkg, or a
directory searched for the first two. With no PATH, --packages-dir DIR scans
every package in that global packages folder.

Packages of a lock file are looked up in --packages-dir, then in
NUGET_PACKAGES or ~/.nuget/packages. Packages of an assets file are looked up
in --packages-dir, then in the assets file's own package folders, in order.

--write-baseline FILE writes every finding and gap of the scan to FILE and
exits 0 (or 2). --baseline FILE accepts what such a file lists: accepted
findings are not shown and accepted gaps are marked, and neither counts for
the exit code. The fingerprint of a finding leaves out the version and the
line, so an update that changes nothing relevant stays accepted.

Exit codes:
  0  complete, no finding at or above --fail-on (default warning)
  1  a finding at or above --fail-on
  2  usage error, or an input that is not a graph
  3  no such finding, but the scan was incomplete (a package was missing,
     or a limit stopped reading)

What customs cannot see:
  - logic in ordinary library code
  - what an MSBuild property expands to, or which condition is true
  - obfuscation, and what a module initialiser does
  - anything decided at run time
  - MSBuild project SDKs and dotnet tool packages, which are not in the
    graph files, and the content of contentFiles source code
  - a package cache changed after restore

Planned, not built yet: customs diff and --verify-cache (M5).
";

/// A usage error, or an input that could not be read as a graph: exit 2.
#[derive(Debug)]
struct Usage(String);

impl From<lexopt::Error> for Usage {
    fn from(e: lexopt::Error) -> Self {
        Self(e.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Text,
    Json,
    Sarif,
}

#[derive(Debug)]
struct ScanOptions {
    paths: Vec<PathBuf>,
    packages_dir: Option<PathBuf>,
    format: Format,
    output: Option<PathBuf>,
    fail_on: FailOn,
    baseline: Option<PathBuf>,
    write_baseline: Option<PathBuf>,
}

#[derive(Debug)]
enum Command {
    Scan(ScanOptions),
    Rules,
    Help,
    Version,
}

fn planned(feature: &str, milestone: &str) -> Usage {
    Usage(format!(
        "{feature} is planned for milestone {milestone} and not built yet"
    ))
}

fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, Usage> {
    use lexopt::prelude::*;
    let mut parser = lexopt::Parser::from_args(args);
    match parser.next()? {
        None => Err(Usage("no command given".to_owned())),
        Some(Long("help") | Short('h')) => Ok(Command::Help),
        Some(Long("version") | Short('V')) => Ok(Command::Version),
        Some(Value(command)) => match command.to_str() {
            Some("scan") => parse_scan(&mut parser),
            Some("rules") => match parser.next()? {
                None => Ok(Command::Rules),
                Some(other) => Err(other.unexpected().into()),
            },
            Some("diff") => Err(planned("customs diff", "M5")),
            _ => Err(Usage(format!(
                "unknown command {}",
                command.to_string_lossy()
            ))),
        },
        Some(other) => Err(other.unexpected().into()),
    }
}

fn parse_scan(parser: &mut lexopt::Parser) -> Result<Command, Usage> {
    use lexopt::prelude::*;
    let mut options = ScanOptions {
        paths: Vec::new(),
        packages_dir: None,
        format: Format::Text,
        output: None,
        fail_on: FailOn::At(Severity::Warning),
        baseline: None,
        write_baseline: None,
    };
    while let Some(arg) = parser.next()? {
        match arg {
            Value(path) => options.paths.push(PathBuf::from(path)),
            Long("packages-dir") => options.packages_dir = Some(PathBuf::from(parser.value()?)),
            Long("output") | Short('o') => options.output = Some(PathBuf::from(parser.value()?)),
            Long("format") => {
                options.format = match parser.value()?.to_str() {
                    Some("text") => Format::Text,
                    Some("json") => Format::Json,
                    Some("sarif") => Format::Sarif,
                    _ => return Err(Usage("--format takes text, json or sarif".to_owned())),
                };
            }
            Long("fail-on") => {
                options.fail_on = match parser.value()?.to_str() {
                    Some("note") => FailOn::At(Severity::Note),
                    Some("warning") => FailOn::At(Severity::Warning),
                    Some("error") => FailOn::At(Severity::Error),
                    Some("never") => FailOn::Never,
                    _ => {
                        return Err(Usage(
                            "--fail-on takes note, warning, error or never".to_owned(),
                        ));
                    }
                };
            }
            Long("baseline") => options.baseline = Some(PathBuf::from(parser.value()?)),
            Long("write-baseline") => {
                options.write_baseline = Some(PathBuf::from(parser.value()?));
            }
            Long("verify-cache") => return Err(planned("--verify-cache", "M5")),
            Long("offline") => return Err(planned("--offline", "M5")),
            Long("cache-dir") => return Err(planned("--cache-dir", "M5")),
            Long("help") | Short('h') => return Ok(Command::Help),
            _ => return Err(arg.unexpected().into()),
        }
    }
    if options.paths.is_empty() && options.packages_dir.is_none() {
        return Err(Usage("scan needs a PATH or --packages-dir".to_owned()));
    }
    Ok(Command::Scan(options))
}

/// Runs customs with the given arguments, without the program name.
#[must_use = "the exit code is the result of the scan"]
pub fn run(args: impl IntoIterator<Item = OsString>) -> ExitCode {
    let result = parse(args).and_then(|command| execute(command, &Limits::default()));
    match result {
        Ok(code) => ExitCode::from(code),
        Err(Usage(message)) => {
            // If stderr itself is gone there is nobody left to tell.
            let _ = writeln!(
                io::stderr().lock(),
                "customs: {}\nRun `customs --help` for usage.",
                report::escape(&message)
            );
            ExitCode::from(2)
        }
    }
}

fn execute(command: Command, limits: &Limits) -> Result<u8, Usage> {
    let failed = |e: io::Error| Usage(format!("could not write the output: {e}"));
    match command {
        Command::Help => {
            io::stdout()
                .lock()
                .write_all(HELP.as_bytes())
                .map_err(failed)?;
            Ok(0)
        }
        Command::Version => {
            writeln!(
                io::stdout().lock(),
                "{} {}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            )
            .map_err(failed)?;
            Ok(0)
        }
        Command::Rules => {
            let mut out = io::stdout().lock();
            for (id, severity, summary) in RULES {
                let severity = severity.map_or("gap", Severity::as_str);
                writeln!(out, "{id}  {severity:<8} {summary}").map_err(failed)?;
            }
            Ok(0)
        }
        Command::Scan(options) => {
            let default_root =
                locate::default_root(std::env::var_os("NUGET_PACKAGES"), std::env::home_dir());
            let previous = match &options.baseline {
                Some(path) => read_baseline(path, limits)?,
                None => baseline::Baseline::default(),
            };
            let mut scan = scan(&options, default_root.as_deref(), limits)?;
            scan.baseline = match &options.write_baseline {
                // The report then shows what the new baseline accepts:
                // everything, so the scan exits 0.
                Some(path) => {
                    let text = baseline::write(&scan, &previous);
                    std::fs::write(path, &text)
                        .map_err(|e| Usage(format!("could not write {}: {e}", display(path))))?;
                    baseline::parse(text.as_bytes()).map_err(Usage)?
                }
                None => previous,
            };
            let mut out: Box<dyn Write> = match &options.output {
                Some(path) => {
                    Box::new(BufWriter::new(File::create(path).map_err(|e| {
                        Usage(format!("could not create {}: {e}", display(path)))
                    })?))
                }
                None => Box::new(io::stdout().lock()),
            };
            match options.format {
                Format::Text => report::text(&scan, options.fail_on, &mut out),
                Format::Json => report::json(&scan, &mut out),
                Format::Sarif => report::sarif(&scan, &mut out),
            }
            .and_then(|()| out.flush())
            .map_err(failed)?;
            Ok(scan.verdict(options.fail_on).code())
        }
    }
}

/// A path for the report, with `/` separators on Windows too, so that the
/// same fixture prints the same on every system.
fn display(path: &Path) -> String {
    let text = path.to_string_lossy();
    if cfg!(windows) {
        text.replace('\\', "/")
    } else {
        text.into_owned()
    }
}

/// Reads a baseline file, at most as large as a graph file may be.
fn read_baseline(path: &Path, limits: &Limits) -> Result<baseline::Baseline, Usage> {
    let shown = display(path);
    let bytes = read_capped(path, limits.graph_bytes)
        .map_err(|e| Usage(format!("{shown}: {e}")))?
        .ok_or_else(|| {
            Usage(format!(
                "{shown}: the baseline is over {} bytes",
                thousands(limits.graph_bytes)
            ))
        })?;
    baseline::parse(&bytes).map_err(|e| Usage(format!("{shown}: {e}")))
}

/// Reads at most `limit` bytes. `None` if the file is longer.
fn read_capped(path: &Path, limit: u64) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    Ok((bytes.len() as u64 <= limit).then_some(bytes))
}

fn is_nupkg(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("nupkg"))
}

fn push_unique(roots: &mut Vec<PathBuf>, more: impl IntoIterator<Item = PathBuf>) {
    for root in more {
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
}

/// Packages of all graphs, merged by ID and version, each with the folders
/// to look in and the graph files that list it, with the line.
type Wanted = BTreeMap<(String, String), (PackageRef, Vec<PathBuf>, Vec<(String, Option<u32>)>)>;

fn scan(
    options: &ScanOptions,
    default_root: Option<&Path>,
    limits: &Limits,
) -> Result<Scan, Usage> {
    let mut scan = Scan::default();
    let files = input_files(&options.paths)?;
    let mut wanted = Wanted::new();
    let mut nupkgs = Vec::new();
    for file in files {
        if is_nupkg(&file) {
            scan.inputs.push(Input {
                path: display(&file),
                kind: Some(InputKind::Nupkg),
            });
            nupkgs.push(file);
        } else {
            read_graph(&file, options, default_root, limits, &mut scan, &mut wanted)?;
        }
    }
    for (package, roots, listed) in wanted.into_values() {
        let mut found = scan_graph_package(package, &roots, limits);
        found.listed = listed;
        scan.packages.push(found);
    }
    for file in nupkgs {
        scan.packages.push(scan_nupkg(&file, limits)?);
    }
    if options.paths.is_empty()
        && let Some(root) = &options.packages_dir
    {
        scan_packages_dir(&mut scan, root, limits)?;
    }
    for package in &mut scan.packages {
        let names = names::check(&package.id);
        if !names.is_empty() {
            package.outcome.findings.splice(0..0, names);
        }
    }
    scan.packages
        .sort_by(|a, b| (a.id.lower(), a.version.lower()).cmp(&(b.id.lower(), b.version.lower())));
    Ok(scan)
}

/// The files named on the command line, with directories replaced by the
/// graph files found in them.
fn input_files(paths: &[PathBuf]) -> Result<Vec<PathBuf>, Usage> {
    let mut files = Vec::new();
    for path in paths {
        if path.is_dir() {
            let found =
                locate::graph_files(path).map_err(|e| Usage(format!("{}: {e}", display(path))))?;
            if found.is_empty() {
                return Err(Usage(format!(
                    "{}: no packages.lock.json or obj/project.assets.json in it",
                    display(path)
                )));
            }
            files.extend(found);
        } else {
            files.push(path.clone());
        }
    }
    Ok(files)
}

/// Reads one graph file into `wanted`. A graph over the size limit is a
/// gap; a file that is not a graph is a usage error.
fn read_graph(
    file: &Path,
    options: &ScanOptions,
    default_root: Option<&Path>,
    limits: &Limits,
    scan: &mut Scan,
    wanted: &mut Wanted,
) -> Result<(), Usage> {
    let shown = display(file);
    let Some(bytes) =
        read_capped(file, limits.graph_bytes).map_err(|e| Usage(format!("{shown}: {e}")))?
    else {
        scan.input_gaps.push((
            shown.clone(),
            Gap::new(
                GapRule::C002,
                None,
                format!(
                    "limit reached: the graph file is over {} bytes; not read",
                    thousands(limits.graph_bytes)
                ),
            ),
        ));
        scan.inputs.push(Input {
            path: shown,
            kind: None,
        });
        return Ok(());
    };
    let graph = graph::parse(&bytes).map_err(|e| Usage(format!("{shown}: {e}")))?;
    let lines = graph::entry_lines(&bytes);
    let mut roots: Vec<PathBuf> = options.packages_dir.iter().cloned().collect();
    let kind = match graph.kind {
        GraphKind::Lock => {
            push_unique(&mut roots, default_root.map(Path::to_path_buf));
            InputKind::Lock(graph.format_version)
        }
        GraphKind::Assets => {
            // Real assets files name absolute folders. A relative one,
            // as in the fixtures, is taken from the file's directory.
            let base = file.parent().unwrap_or(Path::new(""));
            push_unique(&mut roots, graph.folders.iter().map(|f| base.join(f)));
            InputKind::Assets(graph.format_version)
        }
    };
    for package in graph.packages {
        let key = (
            package.id.lower().to_owned(),
            package.version.lower().to_owned(),
        );
        let entry = (shown.clone(), lines.get(&key).copied());
        match wanted.get_mut(&key) {
            Some((known, known_roots, listed)) => {
                known.dependency = known.dependency.min(package.dependency);
                known.frameworks.extend(package.frameworks);
                push_unique(known_roots, roots.iter().cloned());
                listed.push(entry);
            }
            None => {
                wanted.insert(key, (package, roots.clone(), vec![entry]));
            }
        }
    }
    scan.inputs.push(Input {
        path: shown,
        kind: Some(kind),
    });
    Ok(())
}

/// Finds one package of a graph and inspects its extracted folder.
fn scan_graph_package(package: PackageRef, roots: &[PathBuf], limits: &Limits) -> PackageScan {
    let mut found = PackageScan {
        id: package.id,
        version: package.version,
        origin: Origin::Graph(package.dependency),
        frameworks: package.frameworks,
        source: None,
        listed: Vec::new(),
        assets: Vec::new(),
        outcome: Outcome::default(),
    };
    match locate::find(roots, &found.id, &found.version) {
        Location::Found(dir) => {
            found.source = Some(display(&dir));
            (found.assets, found.outcome) =
                inventory::inspect(&mut Folder::new(&dir), found.id.as_str(), limits);
        }
        Location::Link(link) => {
            found.source = Some(display(&link));
            linked_package(&mut found.outcome, &display(&link));
        }
        Location::Missing => {
            let searched: Vec<String> = roots.iter().map(|r| display(r)).collect();
            let message = if searched.is_empty() {
                "not found: no package folder to look in; use --packages-dir".to_owned()
            } else {
                format!("not found in {}", searched.join(", "))
            };
            found
                .outcome
                .gaps
                .push(Gap::new(GapRule::C001, None, message));
        }
    }
    found
}

/// A package folder that is a link: C003, not read, so not complete.
fn linked_package(outcome: &mut Outcome, link: &str) {
    outcome.findings.push(Finding::new(
        FindingRule::C003,
        None,
        format!("the package folder is a link, not followed: {link}"),
    ));
    outcome.gaps.push(Gap::new(
        GapRule::C001,
        None,
        "not read, because the package folder is a link (see C003)".to_owned(),
    ));
}

/// Inspects a single `.nupkg` through the archive reader.
fn scan_nupkg(file: &Path, limits: &Limits) -> Result<PackageScan, Usage> {
    let mut outcome = Outcome::default();
    let mut archive = archive::open(file, limits, &mut outcome);
    // The nuspec names the package, as NuGet reads it, and wins over the
    // file name. The file name is the fallback when there is no single
    // readable nuspec.
    let nuspec = archive
        .as_mut()
        .map_or(Nuspec::Absent, |a| a.nuspec(limits, &mut outcome.budget));
    let from_nuspec = match nuspec {
        Nuspec::Bytes(bytes) => xml::nuspec_identity(&bytes, limits).and_then(|(id, version)| {
            Some((
                PackageId::new(&id).ok()?,
                PackageVersion::new(&version).ok()?,
            ))
        }),
        Nuspec::Many => {
            outcome.findings.push(Finding::new(
                FindingRule::C003,
                None,
                "more than one .nuspec at the root; NuGet reads only one, and which one is not customs's to guess"
                    .to_owned(),
            ));
            None
        }
        Nuspec::Unread(gap) => {
            outcome.gaps.push(gap);
            None
        }
        Nuspec::Absent => None,
    };
    let name = file.file_name().unwrap_or_default().to_string_lossy();
    let (id, version) = from_nuspec
        .or_else(|| locate::nupkg_identity(&name))
        .ok_or_else(|| {
            Usage(format!(
                "{}: cannot tell the package ID and version from its nuspec or its file name",
                display(file)
            ))
        })?;
    let mut assets = Vec::new();
    if let Some(archive) = archive.as_mut() {
        let (found, inner) = inventory::inspect(archive, id.as_str(), limits);
        assets = found;
        outcome.findings.extend(inner.findings);
        outcome.gaps.extend(inner.gaps);
        outcome.budget.entries += inner.budget.entries;
        outcome.budget.bytes += inner.budget.bytes;
        outcome.findings.sort();
        outcome.gaps.sort();
    }
    Ok(PackageScan {
        id,
        version,
        origin: Origin::Nupkg,
        frameworks: std::collections::BTreeSet::new(),
        source: Some(display(file)),
        listed: vec![(display(file), None)],
        assets,
        outcome,
    })
}

fn scan_packages_dir(scan: &mut Scan, root: &Path, limits: &Limits) -> Result<(), Usage> {
    let shown = display(root);
    scan.inputs.push(Input {
        path: shown.clone(),
        kind: Some(InputKind::PackagesDir),
    });
    let folders = locate::package_folders(root).map_err(|e| Usage(format!("{shown}: {e}")))?;
    for listed in folders {
        let (id_name, version_name, dir) = match listed {
            Listed::Package { id, version, dir } => (id, version, Some(dir)),
            Listed::Link {
                id,
                version: Some(version),
            } => (id, version, None),
            Listed::Link { id, version: None } => {
                scan.input_gaps.push((
                    shown.clone(),
                    Gap::new(
                        GapRule::C001,
                        Some(id),
                        "not read, because this ID folder is a link, not followed".to_owned(),
                    ),
                ));
                continue;
            }
            Listed::Unreadable { name, error } => {
                scan.input_gaps.push((
                    shown.clone(),
                    Gap::new(
                        GapRule::C001,
                        Some(name),
                        format!("could not list the folder: {error}"),
                    ),
                ));
                continue;
            }
        };
        let (Ok(id), Ok(version)) = (PackageId::new(&id_name), PackageVersion::new(&version_name))
        else {
            scan.input_gaps.push((
                shown.clone(),
                Gap::new(
                    GapRule::C001,
                    Some(format!("{id_name}/{version_name}")),
                    "not a package folder: the names are not an ID and a version".to_owned(),
                ),
            ));
            continue;
        };
        let mut found = PackageScan {
            id,
            version,
            origin: Origin::PackagesDir,
            frameworks: std::collections::BTreeSet::new(),
            source: Some(display(&root.join(&id_name).join(&version_name))),
            listed: vec![(display(&root.join(&id_name).join(&version_name)), None)],
            assets: Vec::new(),
            outcome: Outcome::default(),
        };
        let Some(dir) = dir else {
            let link = found.source.clone().unwrap_or_default();
            linked_package(&mut found.outcome, &link);
            scan.packages.push(found);
            continue;
        };
        if locate::is_complete(&dir, &id_name, &version_name) {
            (found.assets, found.outcome) =
                inventory::inspect(&mut Folder::new(&dir), found.id.as_str(), limits);
        } else {
            found.outcome.gaps.push(Gap::new(
                GapRule::C001,
                None,
                "an incomplete package folder: no .nupkg.metadata, so NuGet would not use it"
                    .to_owned(),
            ));
        }
        scan.packages.push(found);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_graph_file_one_byte_over_the_limit_is_a_gap_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let lock = br#"{"version": 1, "dependencies": {}}"#;
        let path = dir.path().join("packages.lock.json");
        std::fs::write(&path, lock).unwrap();
        let options = |paths| ScanOptions {
            paths,
            packages_dir: None,
            format: Format::Json,
            output: None,
            fail_on: FailOn::Never,
            baseline: None,
            write_baseline: None,
        };
        let size = lock.len() as u64;
        let fits = scan(
            &options(vec![path.clone()]),
            None,
            &Limits {
                graph_bytes: size,
                ..Limits::default()
            },
        )
        .unwrap();
        assert_eq!(fits.gap_count(), 0);
        let over = scan(
            &options(vec![path]),
            None,
            &Limits {
                graph_bytes: size - 1,
                ..Limits::default()
            },
        )
        .unwrap();
        assert_eq!(over.input_gaps.len(), 1);
        assert_eq!(over.input_gaps[0].1.rule, GapRule::C002);
    }

    #[test]
    fn a_baseline_one_byte_over_the_graph_limit_is_a_usage_error() {
        let dir = tempfile::tempdir().unwrap();
        let text = br#"{"schema": 1, "accepted": []}"#;
        let path = dir.path().join("baseline.json");
        std::fs::write(&path, text).unwrap();
        let limits = |graph_bytes| Limits {
            graph_bytes,
            ..Limits::default()
        };
        let size = text.len() as u64;
        assert!(read_baseline(&path, &limits(size)).is_ok());
        let Err(Usage(message)) = read_baseline(&path, &limits(size - 1)) else {
            panic!("a baseline over the limit was read");
        };
        assert!(message.contains("over"), "{message}");
    }

    #[test]
    fn the_explicit_packages_dir_is_searched_before_the_default_root() {
        let dir = tempfile::tempdir().unwrap();
        for root in ["explicit", "default"] {
            let package = dir.path().join(root).join("contoso.a").join("1.0.0");
            std::fs::create_dir_all(&package).unwrap();
            std::fs::write(package.join(".nupkg.metadata"), "{}").unwrap();
        }
        let lock = dir.path().join("packages.lock.json");
        std::fs::write(
            &lock,
            r#"{"version": 1, "dependencies": {"net8.0": {"Contoso.A": {"type": "Direct", "resolved": "1.0.0"}}}}"#,
        )
        .unwrap();
        let options = ScanOptions {
            paths: vec![lock],
            packages_dir: Some(dir.path().join("explicit")),
            format: Format::Text,
            output: None,
            fail_on: FailOn::Never,
            baseline: None,
            write_baseline: None,
        };
        let result = scan(
            &options,
            Some(&dir.path().join("default")),
            &Limits::default(),
        )
        .unwrap();
        let source = result.packages[0].source.as_deref().unwrap();
        assert!(source.contains("explicit"), "{source}");
    }
}
