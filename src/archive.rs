//! Reads a `.nupkg` through the `zip` crate: lists the entries and reads the
//! start of one entry, with every limit applied whatever the headers claim.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use zip::ZipArchive;

use crate::package::{Budget, Entry, Files, Limits, PackagePath, PathProblem, shorten, thousands};
use crate::scan::{Finding, FindingRule, Gap, GapRule, Outcome};

pub(crate) struct Archive {
    zip: ZipArchive<BufReader<File>>,
}

impl std::fmt::Debug for Archive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Archive")
            .field("entries", &self.zip.len())
            .finish()
    }
}

/// Opens an archive. Problems with the archive as a whole go into `outcome`
/// and return `None`.
pub(crate) fn open(path: &Path, limits: &Limits, outcome: &mut Outcome) -> Option<Archive> {
    let gap = |rule, message: String| Gap::new(rule, None, message);
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) => {
            outcome.gaps.push(gap(
                GapRule::C001,
                format!("could not open the archive: {e}"),
            ));
            return None;
        }
    };
    let length = match file.metadata() {
        Ok(metadata) => metadata.len(),
        Err(e) => {
            outcome.gaps.push(gap(
                GapRule::C001,
                format!("could not read the archive: {e}"),
            ));
            return None;
        }
    };
    if length > limits.nupkg_bytes {
        outcome.gaps.push(gap(
            GapRule::C002,
            format!(
                "limit reached: the archive is {} bytes, over the limit of {} for one .nupkg; not read",
                thousands(length),
                thousands(limits.nupkg_bytes)
            ),
        ));
        return None;
    }
    // The zip crate allocates for every entry the central directory
    // declares, so the count is checked before the crate parses anything.
    match declared_entries(&mut file, length) {
        Ok(Some(count)) if count > limits.entries => {
            outcome.gaps.push(gap(
                GapRule::C002,
                format!(
                    "limit reached: the archive declares {} entries, over the limit of {} for one package; not read",
                    thousands(count),
                    thousands(limits.entries)
                ),
            ));
            return None;
        }
        Ok(Some(_)) => {}
        Ok(None) => {
            outcome.gaps.push(gap(
                GapRule::C001,
                "not a zip archive: no end of central directory record".to_owned(),
            ));
            return None;
        }
        Err(e) => {
            outcome.gaps.push(gap(
                GapRule::C001,
                format!("could not read the archive: {e}"),
            ));
            return None;
        }
    }
    if let Err(e) = file.seek(SeekFrom::Start(0)) {
        outcome.gaps.push(gap(
            GapRule::C001,
            format!("could not read the archive: {e}"),
        ));
        return None;
    }
    let zip = match ZipArchive::new(BufReader::new(file)) {
        Ok(zip) => zip,
        Err(e) => {
            outcome.gaps.push(gap(
                GapRule::C001,
                format!("could not read the archive: {e}"),
            ));
            return None;
        }
    };
    if zip.has_duplicate_names() {
        outcome.findings.push(Finding::new(
            FindingRule::C003,
            None,
            "two entries have the same name; customs lists only one of them".to_owned(),
        ));
    }
    Some(Archive { zip })
}

/// The largest entry count declared by any end of central directory record,
/// classic or zip64, in the last 65,557 bytes of the file. `None` if there is
/// no such record.
// ponytail: an archive whose every record in the tail is invalid to the zip
// crate could make it search further back than this; M6 compares the two.
fn declared_entries(file: &mut File, length: u64) -> std::io::Result<Option<u64>> {
    const EOCD: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    const LOCATOR: [u8; 4] = [0x50, 0x4b, 0x06, 0x07];
    const EOCD64: [u8; 4] = [0x50, 0x4b, 0x06, 0x06];
    let start = length.saturating_sub(22 + 65_535);
    file.seek(SeekFrom::Start(start))?;
    let mut tail = Vec::new();
    file.take(length - start).read_to_end(&mut tail)?;

    let mut most = None;
    for at in (0..tail.len().saturating_sub(21)).filter(|&i| tail[i..].starts_with(&EOCD)) {
        let mut count = u64::from(u16::from_le_bytes([tail[at + 10], tail[at + 11]]));
        let locator = at.checked_sub(20).and_then(|l| tail.get(l..at));
        if let Some(locator) = locator.filter(|l| l.starts_with(&LOCATOR)) {
            let mut offset = [0; 8];
            offset.copy_from_slice(&locator[8..16]);
            let offset = u64::from_le_bytes(offset);
            if offset.checked_add(56).is_some_and(|end| end <= length) {
                let mut record = [0; 56];
                file.seek(SeekFrom::Start(offset))?;
                file.read_exact(&mut record)?;
                if record.starts_with(&EOCD64) {
                    let mut total = [0; 8];
                    total.copy_from_slice(&record[32..40]);
                    count = count.max(u64::from_le_bytes(total));
                }
            }
        }
        most = Some(most.map_or(count, |m: u64| m.max(count)));
    }
    Ok(most)
}

/// Decodes `%XX` escapes, as `NuGet` does when it extracts a package. `None`
/// if the result is not UTF-8.
fn unescape(name: &str) -> Option<String> {
    let bytes = name.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| char::from(b).to_digit(16);
        match (
            bytes[i],
            bytes.get(i + 1).copied().and_then(hex),
            bytes.get(i + 2).copied().and_then(hex),
        ) {
            (b'%', Some(high), Some(low)) => {
                out.push(u8::try_from(high * 16 + low).ok()?);
                i += 3;
            }
            (b, _, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

impl Files for Archive {
    fn entries(&mut self, limits: &Limits, outcome: &mut Outcome) -> Vec<Entry> {
        let mut entries = Vec::new();
        for key in 0..self.zip.len() {
            let data = match self.zip.by_index_data(key) {
                Ok(data) => data,
                Err(e) => {
                    outcome.gaps.push(Gap::new(
                        GapRule::C001,
                        None,
                        format!("could not list entry {key}: {e}"),
                    ));
                    continue;
                }
            };
            if data.is_dir() {
                continue;
            }
            if let Err(gap) = outcome.budget.take_entry(limits) {
                outcome.gaps.push(gap);
                break;
            }
            let raw = String::from_utf8_lossy(data.name_raw()).into_owned();
            let name = data
                .name()
                .map(|n| n.replace('\\', "/"))
                .ok()
                .and_then(|n| unescape(&n));
            let Some(name) = name else {
                outcome.findings.push(Finding::new(
                    FindingRule::C003,
                    Some(raw),
                    "an entry name that is not valid UTF-8 after unescaping".to_owned(),
                ));
                continue;
            };
            match PackagePath::new(&name, limits) {
                Ok(path) => entries.push(Entry {
                    path,
                    size: data.size(),
                    key,
                }),
                Err(PathProblem::Unsafe(reason)) => outcome.findings.push(Finding::new(
                    FindingRule::C003,
                    Some(name.clone()),
                    format!("an entry name that {reason}: {name}"),
                )),
                Err(PathProblem::Limit(message)) => {
                    outcome
                        .gaps
                        .push(Gap::new(GapRule::C002, Some(shorten(&name)), message));
                }
            }
        }
        entries
    }

    fn read(
        &mut self,
        entry: &Entry,
        cap: u64,
        limits: &Limits,
        budget: &mut Budget,
    ) -> Result<Vec<u8>, Gap> {
        let path = entry.path.as_str();
        let unreadable = |e: &dyn std::fmt::Display| {
            Gap::new(
                GapRule::C001,
                Some(path.to_owned()),
                format!("could not read the entry: {e}"),
            )
        };
        let (declared, compressed) = {
            let data = self
                .zip
                .by_index_data(entry.key)
                .map_err(|e| unreadable(&e))?;
            (data.size(), data.compressed_size())
        };
        let by_ratio = compressed.saturating_mul(limits.ratio);
        let ratio_gap = |size: u64| {
            Gap::new(
                GapRule::C002,
                Some(path.to_owned()),
                format!(
                    "limit reached: decompression ratio over {} to 1 ({} bytes from {} compressed); not read",
                    limits.ratio,
                    thousands(size),
                    thousands(compressed)
                ),
            )
        };
        if declared > by_ratio {
            return Err(ratio_gap(declared));
        }
        budget.check_bytes(cap, limits, &entry.path)?;
        // The declared size is not trusted: the read stops at the cap and at
        // the ratio, counted on the bytes that actually come out.
        let ratio_binds = by_ratio < cap;
        let allowed = if ratio_binds { by_ratio + 1 } else { cap };
        let file = self.zip.by_index(entry.key).map_err(|e| unreadable(&e))?;
        let mut bytes = Vec::new();
        file.take(allowed)
            .read_to_end(&mut bytes)
            .map_err(|e| unreadable(&e))?;
        budget.bytes += bytes.len() as u64;
        if ratio_binds && bytes.len() as u64 > by_ratio {
            return Err(ratio_gap(bytes.len() as u64));
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use zip::CompressionMethod;
    use zip::write::{SimpleFileOptions, ZipWriter};

    use super::*;

    fn archive(entries: &[(&str, &[u8])]) -> tempfile::NamedTempFile {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, content) in entries {
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            writer.start_file(*name, options).unwrap();
            writer.write_all(content).unwrap();
        }
        let bytes = writer.finish().unwrap().into_inner();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&bytes).unwrap();
        file
    }

    fn open_with(file: &tempfile::NamedTempFile, limits: &Limits) -> (Option<Archive>, Outcome) {
        let mut outcome = Outcome::default();
        let archive = open(file.path(), limits, &mut outcome);
        (archive, outcome)
    }

    #[test]
    fn a_nupkg_one_byte_over_the_size_limit_is_not_opened() {
        let file = archive(&[("a.txt", b"hello")]);
        let size = file.as_file().metadata().unwrap().len();
        let (ok, outcome) = open_with(
            &file,
            &Limits {
                nupkg_bytes: size,
                ..Limits::default()
            },
        );
        assert!(ok.is_some() && outcome.gaps.is_empty());
        let (none, outcome) = open_with(
            &file,
            &Limits {
                nupkg_bytes: size - 1,
                ..Limits::default()
            },
        );
        assert!(none.is_none());
        assert_eq!(outcome.gaps[0].rule, GapRule::C002);
    }

    #[test]
    fn one_entry_over_the_entry_limit_is_a_gap_before_parsing() {
        let file = archive(&[("a.txt", b"1"), ("b.txt", b"2"), ("c.txt", b"3")]);
        let (ok, _) = open_with(
            &file,
            &Limits {
                entries: 3,
                ..Limits::default()
            },
        );
        assert!(ok.is_some());
        let (none, outcome) = open_with(
            &file,
            &Limits {
                entries: 2,
                ..Limits::default()
            },
        );
        assert!(none.is_none());
        assert!(outcome.gaps[0].message.contains("declares 3 entries"));
    }

    #[test]
    fn a_read_just_over_the_ratio_is_a_gap_and_just_under_is_not() {
        let zeros = vec![0_u8; 1024 * 1024];
        let file = archive(&[("runtimes/x/native/a", &zeros)]);
        let mut archive = open_with(&file, &Limits::default()).0.unwrap();
        let limits = Limits::default();
        let mut outcome = Outcome::default();
        let entries = archive.entries(&limits, &mut outcome);
        let compressed = archive.zip.by_index_data(0).unwrap().compressed_size();
        let ratio = 1024 * 1024 / compressed;

        // Declared ratio over the limit: refused without reading.
        let strict = Limits {
            ratio: ratio - 1,
            ..limits
        };
        let mut budget = Budget::default();
        let gap = archive
            .read(&entries[0], 2 * 1024 * 1024, &strict, &mut budget)
            .unwrap_err();
        assert!(gap.message.contains("decompression ratio"));
        assert_eq!(budget.bytes, 0);

        // Within the ratio: read up to the cap.
        let loose = Limits {
            ratio: ratio + 1,
            ..limits
        };
        let bytes = archive
            .read(&entries[0], 2 * 1024 * 1024, &loose, &mut budget)
            .unwrap();
        assert_eq!(bytes.len(), 1024 * 1024);
        assert_eq!(budget.bytes, 1024 * 1024);
    }

    #[test]
    fn the_per_package_total_stops_a_read_just_over_it() {
        let file = archive(&[("a", b"0123456789"), ("b", b"0123456789")]);
        let limits = Limits {
            package_bytes: 15,
            ..Limits::default()
        };
        let mut archive = open_with(&file, &limits).0.unwrap();
        let mut outcome = Outcome::default();
        let entries = archive.entries(&limits, &mut outcome);
        let mut budget = Budget::default();
        assert_eq!(
            archive
                .read(&entries[0], 10, &limits, &mut budget)
                .unwrap()
                .len(),
            10
        );
        let gap = archive
            .read(&entries[1], 10, &limits, &mut budget)
            .unwrap_err();
        assert_eq!(gap.rule, GapRule::C002);
        assert_eq!(budget.bytes, 10);
    }

    #[test]
    fn listing_one_entry_over_the_limit_is_a_gap() {
        let file = archive(&[("a", b"1"), ("b", b"2")]);
        let mut archive = open_with(&file, &Limits::default()).0.unwrap();
        let mut outcome = Outcome::default();
        let entries = archive.entries(
            &Limits {
                entries: 1,
                ..Limits::default()
            },
            &mut outcome,
        );
        assert_eq!(entries.len(), 1);
        assert_eq!(outcome.gaps.len(), 1);
    }

    #[test]
    fn percent_escapes_are_decoded_before_names_are_checked() {
        assert_eq!(
            unescape("lib/My%20File.dll").as_deref(),
            Some("lib/My File.dll")
        );
        assert_eq!(unescape("%2E%2E/x").as_deref(), Some("../x"));
        assert_eq!(unescape("100%").as_deref(), Some("100%"));
        assert_eq!(unescape("%zz").as_deref(), Some("%zz"));
        assert_eq!(unescape("%FF"), None);
    }

    #[test]
    fn a_file_that_is_not_a_zip_is_a_gap() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"not a zip").unwrap();
        let (none, outcome) = open_with(&file, &Limits::default());
        assert!(none.is_none());
        assert_eq!(outcome.gaps[0].rule, GapRule::C001);
    }
}
