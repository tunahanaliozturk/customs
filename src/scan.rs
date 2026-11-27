//! The rule table, findings and gaps, and the result of a scan with its exit
//! code.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::baseline::{Baseline, Fingerprint};
use crate::graph::{Dependency, PackageId, PackageVersion};
use crate::inventory::Asset;
use crate::package::{Budget, PackagePath};

/// How serious a finding is. Gaps are not a severity, so that `--fail-on`
/// cannot filter them away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Severity {
    Note,
    Warning,
    Error,
}

impl Severity {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Note => "note",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

/// The rules this build implements that produce findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum FindingRule {
    C003,
    C004,
    C101,
    C102,
    C103,
    C104,
    C105,
    C201,
    C202,
    C203,
    C204,
    C205,
    C206,
    C207,
    C301,
    C302,
    C303,
    C304,
}

impl FindingRule {
    pub(crate) fn id(self) -> &'static str {
        match self {
            Self::C003 => "C003",
            Self::C004 => "C004",
            Self::C101 => "C101",
            Self::C102 => "C102",
            Self::C103 => "C103",
            Self::C104 => "C104",
            Self::C105 => "C105",
            Self::C201 => "C201",
            Self::C202 => "C202",
            Self::C203 => "C203",
            Self::C204 => "C204",
            Self::C205 => "C205",
            Self::C206 => "C206",
            Self::C207 => "C207",
            Self::C301 => "C301",
            Self::C302 => "C302",
            Self::C303 => "C303",
            Self::C304 => "C304",
        }
    }

    pub(crate) fn severity(self) -> Severity {
        match self {
            Self::C201 => Severity::Error,
            Self::C003
            | Self::C004
            | Self::C203
            | Self::C204
            | Self::C205
            | Self::C206
            | Self::C301
            | Self::C302
            | Self::C304 => Severity::Warning,
            Self::C101
            | Self::C102
            | Self::C103
            | Self::C104
            | Self::C105
            | Self::C202
            | Self::C207
            | Self::C303 => Severity::Note,
        }
    }
}

/// The rules that report an incomplete scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum GapRule {
    C001,
    C002,
}

impl GapRule {
    pub(crate) fn id(self) -> &'static str {
        match self {
            Self::C001 => "C001",
            Self::C002 => "C002",
        }
    }
}

/// One row of `customs rules`: ID, default severity (none for a gap), and
/// one line.
pub(crate) const RULES: [(&str, Option<Severity>, &str); 20] = [
    (
        "C001",
        None,
        "A package in the graph was not found on disk, or a file of it could not be read.",
    ),
    (
        "C002",
        None,
        "A limit stopped reading. The message names the limit and the file.",
    ),
    (
        "C003",
        Some(Severity::Warning),
        "An entry with `..`, an absolute path or a drive letter, two entries whose names are equal ignoring case, or a link in a package folder.",
    ),
    (
        "C004",
        Some(Severity::Warning),
        "An MSBuild file that is not well-formed XML, has a DTD, or uses an encoding other than UTF-8 or UTF-16.",
    ),
    (
        "C101",
        Some(Severity::Note),
        "Build assets: props or targets in build/, buildTransitive/, buildMultitargeting/ or buildCrossTargeting/.",
    ),
    (
        "C102",
        Some(Severity::Note),
        "Analyzer or source generator assembly in analyzers/.",
    ),
    ("C103", Some(Severity::Note), "PowerShell script in tools/."),
    (
        "C104",
        Some(Severity::Note),
        "Native binary: in runtimes/*/native/, or an ELF or Mach-O file anywhere.",
    ),
    (
        "C105",
        Some(Severity::Note),
        "contentFiles source code that will be compiled into the project.",
    ),
    (
        "C201",
        Some(Severity::Error),
        "UsingTask with a TaskFactory: CodeTaskFactory, RoslynCodeTaskFactory or any other.",
    ),
    (
        "C202",
        Some(Severity::Note),
        "UsingTask with AssemblyFile: an assembly that MSBuild loads.",
    ),
    ("C203", Some(Severity::Warning), "Exec task."),
    ("C204", Some(Severity::Warning), "DownloadFile task."),
    (
        "C205",
        Some(Severity::Warning),
        "A URL (http, https, ftp) in an attribute value or element text. Comments are ignored.",
    ),
    (
        "C206",
        Some(Severity::Warning),
        "A base64-looking run of at least 200 characters.",
    ),
    (
        "C207",
        Some(Severity::Note),
        "An Import that cannot be resolved inside the package.",
    ),
    (
        "C301",
        Some(Severity::Warning),
        "Module initialiser: <Module> has a .cctor. An error in an analyzer or build-time assembly.",
    ),
    (
        "C302",
        Some(Severity::Warning),
        "P/Invoke that changes memory protection or writes to another process. An error in an analyzer or build-time assembly.",
    ),
    (
        "C303",
        Some(Severity::Note),
        "Marker of a known obfuscator. A warning in an analyzer or build-time assembly.",
    ),
    (
        "C304",
        Some(Severity::Warning),
        "A .dll or .exe where NuGet expects managed code that is not a readable managed assembly. An error in an analyzer or build-time assembly.",
    ),
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Finding {
    pub(crate) rule: FindingRule,
    pub(crate) path: Option<String>,
    /// The 1-based line in the file as stored, or as decoded for UTF-16.
    pub(crate) line: Option<u32>,
    pub(crate) message: String,
    /// What the rule saw, as defined with the rule; cut at 240 characters.
    pub(crate) evidence: Option<String>,
    /// The rule's severity, or one step above it for an assembly that runs
    /// at build time.
    pub(crate) severity: Severity,
}

impl Finding {
    pub(crate) fn new(rule: FindingRule, path: Option<String>, message: String) -> Self {
        Self {
            rule,
            path,
            line: None,
            message,
            evidence: None,
            severity: rule.severity(),
        }
    }

    /// Raises the severity one step, for code that runs in the compiler or
    /// in `MSBuild` on every build.
    pub(crate) fn raised(mut self) -> Self {
        self.severity = match self.severity {
            Severity::Note => Severity::Warning,
            Severity::Warning | Severity::Error => Severity::Error,
        };
        self
    }

    /// The fingerprint of ADR 0004: rule, lowercase package ID, path and
    /// evidence; not the version, the line or the message.
    pub(crate) fn fingerprint(&self, id: &PackageId) -> Fingerprint {
        Fingerprint::new(
            self.rule.id(),
            id.lower(),
            self.path.as_deref(),
            self.evidence.as_deref(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Gap {
    pub(crate) rule: GapRule,
    pub(crate) path: Option<String>,
    pub(crate) message: String,
}

impl Gap {
    pub(crate) fn new(rule: GapRule, path: Option<String>, message: String) -> Self {
        Self {
            rule,
            path,
            message,
        }
    }

    /// The fingerprint of a gap: rule, owner and path. The message is left
    /// out, because it names folders of the machine that ran the scan.
    pub(crate) fn fingerprint(&self, owner: &str) -> Fingerprint {
        Fingerprint::new(self.rule.id(), owner, self.path.as_deref(), None)
    }
}

/// What a gap belongs to: an input, or a package.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Owner<'a> {
    Input(&'a str),
    Package(&'a PackageScan),
}

impl Owner<'_> {
    /// What the gap's fingerprint names: the input as shown, or the
    /// lowercase package ID.
    pub(crate) fn key(&self) -> &str {
        match self {
            Self::Input(input) => input,
            Self::Package(package) => package.id.lower(),
        }
    }

    /// The input, or the package ID as written.
    pub(crate) fn name(&self) -> &str {
        match self {
            Self::Input(input) => input,
            Self::Package(package) => package.id.as_str(),
        }
    }
}

/// What inspecting one package produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub(crate) findings: Vec<Finding>,
    pub(crate) gaps: Vec<Gap>,
    pub(crate) budget: Budget,
    /// Findings of the MSBuild and assembly rules not listed, because the
    /// package already had `findings_per_package` findings.
    pub(crate) dropped: u64,
}

impl Outcome {
    /// Lists a finding of the MSBuild or assembly rules, or counts it as
    /// dropped once the package has `limit` findings.
    pub(crate) fn add(&mut self, finding: Finding, limit: u64) {
        if self.findings.len() as u64 >= limit {
            self.dropped += 1;
        } else {
            self.findings.push(finding);
        }
    }
}

/// Where a package came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    Graph(Dependency),
    Nupkg,
    PackagesDir,
}

/// One package and what was found in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PackageScan {
    pub(crate) id: PackageId,
    pub(crate) version: PackageVersion,
    pub(crate) origin: Origin,
    pub(crate) frameworks: BTreeSet<String>,
    /// The folder or file it was read from, for display; `None` if not found.
    pub(crate) source: Option<String>,
    /// Where the package is named: each graph file that lists it, with the
    /// line of its entry when known; or the `.nupkg` or package folder.
    pub(crate) listed: Vec<(String, Option<u32>)>,
    pub(crate) assets: Vec<(PackagePath, Asset)>,
    pub(crate) outcome: Outcome,
}

/// The kind of an input on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputKind {
    Lock(u32),
    Assets(u32),
    Nupkg,
    PackagesDir,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Input {
    pub(crate) path: String,
    /// `None` when the input could not be read, which a gap explains.
    pub(crate) kind: Option<InputKind>,
}

/// A whole scan: inputs, packages sorted by ID and version, gaps that
/// belong to an input rather than a package, and the baseline that accepts
/// some of the findings and gaps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Scan {
    pub(crate) inputs: Vec<Input>,
    pub(crate) packages: Vec<PackageScan>,
    pub(crate) input_gaps: Vec<(String, Gap)>,
    pub(crate) baseline: Baseline,
}

/// `--fail-on`: the lowest severity that fails the scan, or never.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailOn {
    At(Severity),
    Never,
}

impl FailOn {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::At(severity) => severity.as_str(),
            Self::Never => "never",
        }
    }
}

/// The process exit codes of the design. 2 is decided before a scan exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Clean,
    Findings,
    Incomplete,
}

impl Verdict {
    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Clean => 0,
            Self::Findings => 1,
            Self::Incomplete => 3,
        }
    }
}

impl Scan {
    pub(crate) fn findings(&self) -> impl Iterator<Item = (&PackageScan, &Finding)> {
        self.packages
            .iter()
            .flat_map(|p| p.outcome.findings.iter().map(move |f| (p, f)))
    }

    /// Every gap with what it belongs to: inputs first, then packages.
    pub(crate) fn gaps(&self) -> impl Iterator<Item = (Owner<'_>, &Gap)> {
        self.input_gaps
            .iter()
            .map(|(input, gap)| (Owner::Input(input), gap))
            .chain(
                self.packages
                    .iter()
                    .flat_map(|p| p.outcome.gaps.iter().map(move |g| (Owner::Package(p), g))),
            )
    }

    /// All gaps, accepted by the baseline or not.
    pub(crate) fn gap_count(&self) -> usize {
        self.gaps().count()
    }

    pub(crate) fn finding_accepted(&self, package: &PackageScan, finding: &Finding) -> bool {
        self.baseline
            .accepted
            .contains(&finding.fingerprint(&package.id))
    }

    pub(crate) fn gap_accepted(&self, owner: Owner<'_>, gap: &Gap) -> bool {
        self.baseline
            .accepted
            .contains(&gap.fingerprint(owner.key()))
    }

    /// Findings the baseline does not accept.
    pub(crate) fn open_findings(&self) -> impl Iterator<Item = (&PackageScan, &Finding)> {
        self.findings()
            .filter(|(p, f)| !self.finding_accepted(p, f))
    }

    /// Findings and gaps the baseline accepts.
    pub(crate) fn accepted_count(&self) -> usize {
        self.findings()
            .filter(|(p, f)| self.finding_accepted(p, f))
            .count()
            + self
                .gaps()
                .filter(|(o, g)| self.gap_accepted(*o, g))
                .count()
    }

    /// Findings at or above `--fail-on` come before gaps: precedence 1, then
    /// 3. What the baseline accepts counts for neither.
    pub(crate) fn verdict(&self, fail_on: FailOn) -> Verdict {
        let failing = match fail_on {
            FailOn::At(threshold) => self.open_findings().any(|(_, f)| f.severity >= threshold),
            FailOn::Never => false,
        };
        if failing {
            Verdict::Findings
        } else if self.gaps().any(|(o, g)| !self.gap_accepted(o, g)) {
            Verdict::Incomplete
        } else {
            Verdict::Clean
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(finding: Option<FindingRule>, gap: bool) -> Scan {
        let mut outcome = Outcome::default();
        if let Some(rule) = finding {
            outcome
                .findings
                .push(Finding::new(rule, None, String::new()));
        }
        if gap {
            outcome
                .gaps
                .push(Gap::new(GapRule::C001, None, String::new()));
        }
        Scan {
            packages: vec![PackageScan {
                id: PackageId::new("A").unwrap(),
                version: PackageVersion::new("1.0.0").unwrap(),
                origin: Origin::Nupkg,
                frameworks: BTreeSet::new(),
                source: None,
                listed: Vec::new(),
                assets: Vec::new(),
                outcome,
            }],
            ..Scan::default()
        }
    }

    #[test]
    fn findings_take_precedence_over_gaps_and_never_does_not_hide_gaps() {
        let warning = FailOn::At(Severity::Warning);
        assert_eq!(scan(None, false).verdict(warning), Verdict::Clean);
        assert_eq!(
            scan(Some(FindingRule::C101), false).verdict(warning),
            Verdict::Clean
        );
        assert_eq!(
            scan(Some(FindingRule::C101), false).verdict(FailOn::At(Severity::Note)),
            Verdict::Findings
        );
        assert_eq!(
            scan(Some(FindingRule::C003), true).verdict(warning),
            Verdict::Findings
        );
        assert_eq!(
            scan(Some(FindingRule::C003), true).verdict(FailOn::At(Severity::Error)),
            Verdict::Incomplete
        );
        assert_eq!(
            scan(Some(FindingRule::C003), true).verdict(FailOn::Never),
            Verdict::Incomplete
        );
        assert_eq!(
            scan(Some(FindingRule::C003), false).verdict(FailOn::Never),
            Verdict::Clean
        );
        assert_eq!(scan(None, true).verdict(warning), Verdict::Incomplete);
    }

    #[test]
    fn a_raised_finding_fails_at_its_raised_severity() {
        let note = Finding::new(FindingRule::C303, None, String::new());
        assert_eq!(note.raised().severity, Severity::Warning);
        let warning = Finding::new(FindingRule::C301, None, String::new());
        assert_eq!(warning.clone().raised().severity, Severity::Error);
        assert_eq!(warning.raised().raised().severity, Severity::Error);
    }

    #[test]
    fn the_rule_table_matches_the_rule_types() {
        let finding_rules = [
            FindingRule::C003,
            FindingRule::C101,
            FindingRule::C102,
            FindingRule::C103,
            FindingRule::C104,
            FindingRule::C105,
            FindingRule::C004,
            FindingRule::C201,
            FindingRule::C202,
            FindingRule::C203,
            FindingRule::C204,
            FindingRule::C205,
            FindingRule::C206,
            FindingRule::C207,
            FindingRule::C301,
            FindingRule::C302,
            FindingRule::C303,
            FindingRule::C304,
        ];
        for rule in finding_rules {
            let row = RULES.iter().find(|r| r.0 == rule.id()).unwrap();
            assert_eq!(row.1, Some(rule.severity()));
        }
        for rule in [GapRule::C001, GapRule::C002] {
            let row = RULES.iter().find(|r| r.0 == rule.id()).unwrap();
            assert_eq!(row.1, None);
        }
        assert_eq!(RULES.len(), finding_rules.len() + 2);
    }
}
