//! Fingerprints, and the baseline file that accepts findings and gaps by
//! fingerprint. Pure: the caller reads and writes the file.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::scan::Scan;

/// The first 128 bits of SHA-256 over the owner's kind (`package` or
/// `input`), the rule, the owner (the lowercase package ID, or the input of
/// a gap that belongs to no package), the path inside the package and the
/// evidence (a gap's cause) with whitespace collapsed, joined by a byte that
/// UTF-8 never holds. No version and no line (ADR 0004, ADR 0008).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Fingerprint([u8; 16]);

impl Fingerprint {
    pub(crate) fn new(
        kind: &str,
        rule: &str,
        owner: &str,
        path: Option<&str>,
        evidence: Option<&str>,
    ) -> Self {
        let evidence = evidence
            .unwrap_or_default()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let mut hash = Sha256::new();
        for (n, part) in [kind, rule, owner, path.unwrap_or_default(), &evidence]
            .iter()
            .enumerate()
        {
            if n > 0 {
                hash.update([0xFF]);
            }
            hash.update(part.as_bytes());
        }
        let digest = hash.finalize();
        let mut bytes = [0; 16];
        bytes.copy_from_slice(digest.get(..16).unwrap_or_default());
        Self(bytes)
    }

    /// Reads 32 lowercase hexadecimal digits.
    fn parse(text: &str) -> Option<Self> {
        if text.len() != 32 {
            return None;
        }
        let mut bytes = [0; 16];
        for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks(2)) {
            let digit = |b: u8| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                _ => None,
            };
            *byte = digit(*pair.first()?)? << 4 | digit(*pair.get(1)?)?;
        }
        Some(Self(bytes))
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// A baseline file, schema 1.
#[derive(Debug, Serialize, Deserialize)]
struct File {
    schema: u32,
    accepted: Vec<Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    fingerprint: String,
    rule: String,
    package: String,
    path: Option<String>,
    /// For the reviewer; customs ignores it, but keeps it when it writes
    /// the baseline again.
    #[serde(default)]
    note: String,
}

/// What a baseline file accepts: the fingerprints, and the reviewer's notes
/// by fingerprint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Baseline {
    pub(crate) accepted: BTreeSet<Fingerprint>,
    notes: BTreeMap<Fingerprint, String>,
}

/// Reads a baseline file. The error says what is wrong with it.
pub(crate) fn parse(bytes: &[u8]) -> Result<Baseline, String> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let file: File =
        serde_json::from_slice(bytes).map_err(|e| format!("not a baseline file: {e}"))?;
    if file.schema != 1 {
        return Err(format!(
            "baseline schema {} is not supported; customs reads schema 1",
            file.schema
        ));
    }
    let mut baseline = Baseline::default();
    for entry in file.accepted {
        let fingerprint = Fingerprint::parse(&entry.fingerprint).ok_or_else(|| {
            format!(
                "\"{}\" is not a fingerprint of 32 lowercase hexadecimal digits",
                entry.fingerprint
            )
        })?;
        baseline.accepted.insert(fingerprint);
        if !entry.note.is_empty() {
            baseline.notes.insert(fingerprint, entry.note);
        }
    }
    Ok(baseline)
}

/// A baseline that accepts every finding and every gap of `scan`, once per
/// fingerprint, sorted by package, rule and path, keeping the notes of
/// `previous` for fingerprints it already had.
pub(crate) fn write(scan: &Scan, previous: &Baseline) -> String {
    let mut entries: BTreeMap<(String, &'static str, String, Fingerprint), Entry> = BTreeMap::new();
    let mut add =
        |fingerprint: Fingerprint, rule: &'static str, package: &str, path: Option<&str>| {
            let key = (
                package.to_lowercase(),
                rule,
                path.unwrap_or_default().to_owned(),
                fingerprint,
            );
            entries.entry(key).or_insert_with(|| Entry {
                fingerprint: fingerprint.to_string(),
                rule: rule.to_owned(),
                package: package.to_owned(),
                path: path.map(str::to_owned),
                note: previous
                    .notes
                    .get(&fingerprint)
                    .cloned()
                    .unwrap_or_default(),
            });
        };
    for (package, finding) in scan.findings() {
        add(
            finding.fingerprint(&package.id),
            finding.rule.id(),
            package.id.as_str(),
            finding.path.as_deref(),
        );
    }
    for (owner, gap) in scan.gaps() {
        add(
            gap.fingerprint(owner),
            gap.rule.id(),
            owner.name(),
            gap.path.as_deref(),
        );
    }
    // Two findings that differ only in their line, such as two identical
    // `Exec` elements, have one key, so the baseline lists them once.
    let file = File {
        schema: 1,
        accepted: entries.into_values().collect(),
    };
    // Serialising plain strings and numbers cannot fail.
    let mut text = serde_json::to_string_pretty(&file).unwrap_or_default();
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fingerprint_reads_back_and_depends_on_each_part() {
        let base = Fingerprint::new(
            "package",
            "C203",
            "contoso.a",
            Some("build/a.targets"),
            Some("curl  x\n y"),
        );
        assert_eq!(Fingerprint::parse(&base.to_string()), Some(base));
        assert_eq!(base.to_string().len(), 32);
        // Whitespace in the evidence is collapsed.
        assert_eq!(
            base,
            Fingerprint::new(
                "package",
                "C203",
                "contoso.a",
                Some("build/a.targets"),
                Some("curl x y")
            )
        );
        for other in [
            Fingerprint::new(
                "package",
                "C205",
                "contoso.a",
                Some("build/a.targets"),
                Some("curl x y"),
            ),
            Fingerprint::new(
                "package",
                "C203",
                "contoso.b",
                Some("build/a.targets"),
                Some("curl x y"),
            ),
            Fingerprint::new(
                "package",
                "C203",
                "contoso.a",
                Some("build/b.targets"),
                Some("curl x y"),
            ),
            Fingerprint::new(
                "package",
                "C203",
                "contoso.a",
                Some("build/a.targets"),
                Some("curl x z"),
            ),
            // The separator keeps parts from running into each other.
            Fingerprint::new(
                "package",
                "C203",
                "contoso.abuild/a.targets",
                None,
                Some("curl x y"),
            ),
            Fingerprint::new(
                "input",
                "C203",
                "contoso.a",
                Some("build/a.targets"),
                Some("curl x y"),
            ),
        ] {
            assert_ne!(base, other);
        }
    }

    #[test]
    fn only_32_lowercase_hex_digits_are_a_fingerprint() {
        for text in [
            "",
            "0123",
            &"A".repeat(32),
            &"g".repeat(32),
            &"0".repeat(33),
            "é".repeat(16).as_str(),
        ] {
            assert_eq!(Fingerprint::parse(text), None, "{text}");
        }
        assert!(Fingerprint::parse(&"0f".repeat(16)).is_some());
    }

    #[test]
    fn a_baseline_file_must_be_schema_1_with_valid_fingerprints() {
        let good = format!(
            r#"{{"schema": 1, "accepted": [{{"fingerprint": "{}", "rule": "C203", "package": "A", "path": null, "note": "seen", "extra": 1}}]}}"#,
            "ab".repeat(16)
        );
        let baseline = parse(good.as_bytes()).unwrap();
        assert_eq!(baseline.accepted.len(), 1);
        for bad in [
            r#"{"schema": 2, "accepted": []}"#.to_owned(),
            r#"{"accepted": []}"#.to_owned(),
            "[]".to_owned(),
            good.replace("abab", "ABAB"),
        ] {
            assert!(parse(bad.as_bytes()).is_err(), "{bad}");
        }
    }
}
