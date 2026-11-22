//! Classifies the paths of a package into assets, and turns the assets into
//! the inventory rules C101 to C105 and the case-collision part of C003.
//! Pure, apart from the 64-byte reads it asks the package view for.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::graph::lower_invariant;
use crate::msbuild;
use crate::package::{Entry, Files, Limits, PackagePath};
use crate::scan::{Finding, FindingRule, Outcome};

/// What a file in a package is, as far as M1 can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Asset {
    /// A `.props` or `.targets` file that `MSBuild` may import.
    Build {
        folder: BuildFolder,
        entry_point: bool,
    },
    Analyzer,
    #[serde(rename = "powershell")]
    PowerShell,
    Native {
        format: NativeFormat,
    },
    /// A `.dll` or `.exe` under `lib/`, `ref/` or `runtimes/*/lib/`. Until M3
    /// reads the CLI header, a native PE file in those folders is listed here.
    Managed {
        role: ManagedRole,
    },
    ContentSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum BuildFolder {
    #[serde(rename = "build")]
    Build,
    #[serde(rename = "buildTransitive")]
    BuildTransitive,
    #[serde(rename = "buildMultitargeting")]
    BuildMultitargeting,
    #[serde(rename = "buildCrossTargeting")]
    BuildCrossTargeting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum NativeFormat {
    Pe,
    Elf,
    #[serde(rename = "mach-o")]
    MachO,
}

impl NativeFormat {
    fn name(self) -> &'static str {
        match self {
            Self::Pe => "PE",
            Self::Elf => "ELF",
            Self::MachO => "Mach-O",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ManagedRole {
    Lib,
    Ref,
    Runtime,
    /// Code that MSBuild or a tool runs at build time: a `.dll` or `.exe`
    /// under `build*/` or `tools/`, or any assembly that `UsingTask
    /// AssemblyFile` names. M3 raises the findings of such assemblies.
    #[serde(rename = "build_time")]
    BuildTime,
}

/// What to do with an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Asset(Asset),
    /// Read the first bytes. A PE file counts as native only in a native
    /// folder; ELF and Mach-O count anywhere.
    Sniff {
        pe_is_native: bool,
    },
    /// Documentation, images, text and metadata: listed, never read.
    Skip,
}

/// Extensions of files that no M1 rule reads.
const NEVER_READ: [&str; 28] = [
    "CONFIG", "CS", "CSS", "FS", "GIF", "HTM", "HTML", "ICO", "JPEG", "JPG", "JSON", "MD",
    "METADATA", "NUPKG", "NUSPEC", "P7S", "PDB", "PNG", "PROPS", "PS1", "PSM1", "PSMDCP", "RELS",
    "RESX", "SHA512", "SVG", "TARGETS", "TXT",
];

/// Upper-cases one character by the simple mapping, so `ı` becomes `I` and
/// `ß` stays `ß`. Used only for case collisions (C003), where it is wider
/// than what NTFS or .NET would merge: a warning slightly too wide is the
/// right side to err on.
fn fold(c: char) -> char {
    let mut upper = c.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(single), None) => single,
        _ => c,
    }
}

/// Compares a name with an upper-case ASCII literal as `NuGet` does, with
/// `OrdinalIgnoreCase`. For an ASCII literal that is an ASCII
/// case-insensitive comparison: `buıld` with a dotless i is not `BUILD`.
fn is(name: &str, upper_literal: &str) -> bool {
    name.eq_ignore_ascii_case(upper_literal)
}

fn folded(name: &str) -> String {
    name.chars().map(fold).collect()
}

fn classify(path: &PackagePath, id: &str) -> Class {
    let segments: Vec<&str> = path.as_str().split('/').collect();
    let file = segments.last().copied().unwrap_or_default();
    let (stem, extension) = file.rsplit_once('.').unwrap_or((file, ""));
    let extension = extension.to_ascii_uppercase();
    let ext = |candidates: &[&str]| candidates.contains(&extension.as_str());
    let first = segments.first().copied().unwrap_or_default();
    let depth = segments.len();

    let build_folder = [
        ("BUILD", BuildFolder::Build),
        ("BUILDTRANSITIVE", BuildFolder::BuildTransitive),
        ("BUILDMULTITARGETING", BuildFolder::BuildMultitargeting),
        ("BUILDCROSSTARGETING", BuildFolder::BuildCrossTargeting),
    ]
    .into_iter()
    .find(|(name, _)| is(first, name))
    .map(|(_, folder)| folder);

    let asset = if depth < 2 {
        None
    } else if let Some(folder) = build_folder {
        if ext(&["PROPS", "TARGETS"]) {
            Some(Asset::Build {
                folder,
                entry_point: depth <= 3 && lower_invariant(stem) == lower_invariant(id),
            })
        } else {
            ext(&["DLL", "EXE"]).then_some(Asset::Managed {
                role: ManagedRole::BuildTime,
            })
        }
    } else if is(first, "ANALYZERS") {
        ext(&["DLL"]).then_some(Asset::Analyzer)
    } else if is(first, "TOOLS") {
        if ext(&["PS1", "PSM1"]) {
            Some(Asset::PowerShell)
        } else {
            ext(&["DLL", "EXE"]).then_some(Asset::Managed {
                role: ManagedRole::BuildTime,
            })
        }
    } else if is(first, "LIB") {
        ext(&["DLL", "EXE"]).then_some(Asset::Managed {
            role: ManagedRole::Lib,
        })
    } else if is(first, "REF") {
        ext(&["DLL"]).then_some(Asset::Managed {
            role: ManagedRole::Ref,
        })
    } else if is(first, "RUNTIMES") && depth >= 4 && is(segments[2], "LIB") {
        ext(&["DLL", "EXE"]).then_some(Asset::Managed {
            role: ManagedRole::Runtime,
        })
    } else if is(first, "CONTENTFILES") {
        ext(&["CS", "VB", "FS"]).then_some(Asset::ContentSource)
    } else {
        None
    };
    match asset {
        Some(asset) => Class::Asset(asset),
        None if NEVER_READ.contains(&extension.as_str()) => Class::Skip,
        None => Class::Sniff {
            pe_is_native: is(first, "RUNTIMES") && depth >= 4 && is(segments[2], "NATIVE"),
        },
    }
}

/// Tells PE, ELF and Mach-O apart from the first bytes of a file.
fn sniff(bytes: &[u8]) -> Option<NativeFormat> {
    match bytes {
        [0x7f, b'E', b'L', b'F', ..] => Some(NativeFormat::Elf),
        [0xfe, 0xed, 0xfa, 0xce | 0xcf, ..] | [0xce | 0xcf, 0xfa, 0xed, 0xfe, ..] => {
            Some(NativeFormat::MachO)
        }
        // A universal binary. Java class files share the magic; their next
        // four bytes are a class file version of 45 or more, while a
        // universal binary holds a handful of architectures.
        [0xca, 0xfe, 0xba, 0xbe | 0xbf, a, b, c, d, ..]
            if (1..=20).contains(&u32::from_be_bytes([*a, *b, *c, *d])) =>
        {
            Some(NativeFormat::MachO)
        }
        [b'M', b'Z', ..] => Some(NativeFormat::Pe),
        _ => None,
    }
}

/// Lists a package, classifies every entry, and returns the assets sorted by
/// path with the findings and gaps of the inventory.
pub(crate) fn inspect(
    files: &mut dyn Files,
    id: &str,
    limits: &Limits,
) -> (Vec<(PackagePath, Asset)>, Outcome) {
    let mut outcome = Outcome::default();
    let mut entries = files.entries(limits, &mut outcome);
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    outcome.findings.extend(collisions(&entries));

    let mut assets = Vec::new();
    for entry in &entries {
        match classify(&entry.path, id) {
            Class::Asset(asset) => assets.push((entry.path.clone(), asset)),
            Class::Sniff { pe_is_native } => {
                match files.read(entry, limits.sniff_bytes, limits, &mut outcome.budget) {
                    Ok(bytes) => match sniff(&bytes) {
                        Some(NativeFormat::Pe) if !pe_is_native => {}
                        Some(format) => assets.push((entry.path.clone(), Asset::Native { format })),
                        None => {}
                    },
                    Err(gap) => outcome.gaps.push(gap),
                }
            }
            Class::Skip => {}
        }
    }
    let entry_points: BTreeSet<PackagePath> = assets
        .iter()
        .filter(|(_, a)| {
            matches!(
                a,
                Asset::Build {
                    entry_point: true,
                    ..
                }
            )
        })
        .map(|(p, _)| p.clone())
        .collect();
    let task_assemblies = msbuild::scan(files, &entries, &entry_points, limits, &mut outcome);
    for path in task_assemblies {
        let build_time = Asset::Managed {
            role: ManagedRole::BuildTime,
        };
        match assets.iter_mut().find(|(p, _)| *p == path) {
            Some((_, asset)) if matches!(asset, Asset::Managed { .. }) => *asset = build_time,
            Some(_) => {}
            None => assets.push((path, build_time)),
        }
    }
    assets.sort_by(|a, b| a.0.cmp(&b.0));
    outcome.findings.extend(findings(&assets));
    outcome.findings.sort();
    outcome.gaps.sort();
    (assets, outcome)
}

/// C003 for entries whose names are equal ignoring case.
fn collisions(entries: &[Entry]) -> Vec<Finding> {
    let mut groups: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for entry in entries {
        groups
            .entry(folded(entry.path.as_str()))
            .or_default()
            .push(entry.path.as_str());
    }
    groups
        .into_values()
        .filter(|names| names.len() > 1)
        .map(|names| {
            Finding::new(
                FindingRule::C003,
                names.first().map(|n| (*n).to_owned()),
                format!(
                    "entries whose names are equal ignoring case: {}",
                    names.join(", ")
                ),
            )
        })
        .collect()
}

/// One finding per rule and package: the first path, and how many more.
fn findings(assets: &[(PackagePath, Asset)]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut add = |rule: FindingRule, label: &str, matching: Vec<(&PackagePath, String)>| {
        if let Some((first, detail)) = matching.first() {
            let more = match matching.len() - 1 {
                0 => String::new(),
                1 => " (+1 more file)".to_owned(),
                n => format!(" (+{n} more files)"),
            };
            out.push(Finding::new(
                rule,
                Some(first.as_str().to_owned()),
                format!("{label}: {}{detail}{more}", first.as_str()),
            ));
        }
    };
    // For build assets an entry point comes first: it is what MSBuild imports.
    let mut build: Vec<(&PackagePath, bool)> = assets
        .iter()
        .filter_map(|(p, a)| match a {
            Asset::Build { entry_point, .. } => Some((p, *entry_point)),
            _ => None,
        })
        .collect();
    build.sort_by_key(|(_, entry_point)| !entry_point);
    add(
        FindingRule::C101,
        "build assets",
        build.into_iter().map(|(p, _)| (p, String::new())).collect(),
    );
    let simple = |wanted: Asset| -> Vec<(&PackagePath, String)> {
        assets
            .iter()
            .filter(|(_, a)| *a == wanted)
            .map(|(p, _)| (p, String::new()))
            .collect()
    };
    add(FindingRule::C102, "analyzer", simple(Asset::Analyzer));
    add(
        FindingRule::C103,
        "PowerShell script",
        simple(Asset::PowerShell),
    );
    add(
        FindingRule::C104,
        "native binary",
        assets
            .iter()
            .filter_map(|(p, a)| match a {
                Asset::Native { format } => Some((p, format!(" ({})", format.name()))),
                _ => None,
            })
            .collect(),
    );
    add(
        FindingRule::C105,
        "contentFiles source",
        simple(Asset::ContentSource),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(path: &str) -> Class {
        classify(
            &PackagePath::new(path, &Limits::default()).unwrap(),
            "Contoso.Tools",
        )
    }

    #[test]
    fn build_folders_match_ignoring_case_as_dotnet_does() {
        for path in [
            "build/Contoso.Tools.targets",
            "BUILD/contoso.tools.TARGETS",
            "Build/net8.0/Contoso.Tools.props",
        ] {
            assert!(
                matches!(
                    class(path),
                    Class::Asset(Asset::Build {
                        folder: BuildFolder::Build,
                        entry_point: true
                    })
                ),
                "{path}"
            );
        }
        assert!(matches!(
            class("BuildTransitive/x/y/Other.targets"),
            Class::Asset(Asset::Build {
                folder: BuildFolder::BuildTransitive,
                entry_point: false
            })
        ));
        assert!(matches!(
            class("buildCrossTargeting/Contoso.Tools.props"),
            Class::Asset(Asset::Build {
                folder: BuildFolder::BuildCrossTargeting,
                ..
            })
        ));
        // .NET's OrdinalIgnoreCase does not take a dotless i for an i, so
        // NuGet does not use this folder, and neither does customs.
        assert!(!matches!(
            class("buıld/Contoso.Tools.targets"),
            Class::Asset(_)
        ));
        assert!(!matches!(
            class("buildß/Contoso.Tools.targets"),
            Class::Asset(_)
        ));
        assert!(!matches!(
            class("mybuild/Contoso.Tools.targets"),
            Class::Asset(_)
        ));
        assert!(!matches!(class("build.targets"), Class::Asset(_)));
    }

    #[test]
    fn the_other_folders_are_classified_by_path() {
        assert_eq!(
            class("analyzers/dotnet/cs/A.dll"),
            Class::Asset(Asset::Analyzer)
        );
        assert_eq!(class("tools/init.ps1"), Class::Asset(Asset::PowerShell));
        assert_eq!(
            class("tools/net8.0/any/Mod.PSM1"),
            Class::Asset(Asset::PowerShell)
        );
        assert_eq!(
            class("lib/net8.0/A.dll"),
            Class::Asset(Asset::Managed {
                role: ManagedRole::Lib
            })
        );
        assert_eq!(
            class("ref/net8.0/A.dll"),
            Class::Asset(Asset::Managed {
                role: ManagedRole::Ref
            })
        );
        assert_eq!(
            class("runtimes/win/lib/net8.0/A.dll"),
            Class::Asset(Asset::Managed {
                role: ManagedRole::Runtime
            })
        );
        assert_eq!(
            class("contentFiles/cs/any/A.cs"),
            Class::Asset(Asset::ContentSource)
        );
        assert_eq!(
            class("runtimes/win-x64/native/a.dll"),
            Class::Sniff { pe_is_native: true }
        );
        assert_eq!(
            class("tools/protoc"),
            Class::Sniff {
                pe_is_native: false
            }
        );
        assert_eq!(class("README.md"), Class::Skip);
        assert_eq!(class("contentFiles/any/any/notes.txt"), Class::Skip);
    }

    #[test]
    fn native_formats_are_told_apart_by_magic_numbers() {
        assert_eq!(sniff(b"\x7fELF\x02\x01"), Some(NativeFormat::Elf));
        assert_eq!(sniff(b"\xcf\xfa\xed\xfe"), Some(NativeFormat::MachO));
        assert_eq!(sniff(b"\xfe\xed\xfa\xce"), Some(NativeFormat::MachO));
        assert_eq!(
            sniff(b"\xca\xfe\xba\xbe\x00\x00\x00\x02"),
            Some(NativeFormat::MachO)
        );
        assert_eq!(
            sniff(b"\xca\xfe\xba\xbe\x00\x00\x00\x34"),
            None,
            "a Java class file"
        );
        assert_eq!(sniff(b"MZ\x90\x00"), Some(NativeFormat::Pe));
        assert_eq!(sniff(b"\x7fEL"), None);
        assert_eq!(sniff(b""), None);
    }
}
