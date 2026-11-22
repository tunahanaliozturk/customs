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
    // declares, so the layout, the count and the directory size are checked
    // before the crate sees the file.
    let refusal = match canonical_layout(&mut file, length, limits) {
        Ok(Ok(())) => None,
        Ok(Err(refusal)) => Some(refusal),
        Err(e) => {
            outcome.gaps.push(gap(
                GapRule::C001,
                format!("could not read the archive: {e}"),
            ));
            return None;
        }
    };
    if let Some(refusal) = refusal {
        refuse(refusal, limits, outcome);
        return None;
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

/// Records why an archive was not opened.
fn refuse(refusal: Refusal, limits: &Limits, outcome: &mut Outcome) {
    let gap = |rule, message: String| Gap::new(rule, None, message);
    match refusal {
        Refusal::NotZip => outcome.gaps.push(gap(
            GapRule::C001,
            "not a zip archive: no end of central directory record".to_owned(),
        )),
        Refusal::Layout(reason) => {
            outcome.findings.push(Finding::new(
                FindingRule::C003,
                None,
                format!("an archive layout that zip readers read differently; not opened: {reason}"),
            ));
            outcome.gaps.push(gap(
                GapRule::C001,
                "not read, because of its archive layout (see C003)".to_owned(),
            ));
        }
        Refusal::Entries(count) => outcome.gaps.push(gap(
            GapRule::C002,
            format!(
                "limit reached: the archive declares {} entries, over the limit of {} for one package; not read",
                thousands(count),
                thousands(limits.entries)
            ),
        )),
        Refusal::Directory(size) => outcome.gaps.push(gap(
            GapRule::C002,
            format!(
                "limit reached: a central directory of {} bytes, over the limit of {}; not read",
                thousands(size),
                thousands(limits.directory_bytes)
            ),
        )),
    }
}

/// Why customs does not hand an archive to the zip crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// No end of central directory record at all.
    NotZip,
    /// A layout that zip readers could read differently: C003.
    Layout(&'static str),
    /// More entries than the limit: a C002 gap.
    Entries(u64),
    /// A central directory larger than the limit: a C002 gap.
    Directory(u64),
}

const END: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
const LOCATOR: [u8; 4] = [0x50, 0x4b, 0x06, 0x07];
const END64: [u8; 4] = [0x50, 0x4b, 0x06, 0x06];
const DIRECTORY_HEADER: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];

/// The tail searched for the end record. The zip crate searches the last
/// 22 + 4 + 65,536 bytes; a larger window only makes customs stricter.
const TAIL: u64 = 22 + 65_535 + 1024;

fn le(bytes: &[u8], at: usize, width: usize) -> Option<u64> {
    let field = bytes.get(at..at.checked_add(width)?)?;
    Some(
        field
            .iter()
            .rev()
            .fold(0, |value, byte| (value << 8) | u64::from(*byte)),
    )
}

fn read_at(file: &mut File, offset: u64, length: usize) -> std::io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Accepts only the canonical layout, where every reader finds the same
/// central directory: the end record is the last one in the tail and its
/// comment runs to the end of the file; the central directory ends where
/// the end record (or the zip64 record) begins; a zip64 record is exactly
/// where its locator points and ends where the locator begins; one disk.
/// Then the entry count and the directory size must be within the limits.
/// Anything else is refused, so the zip crate never parses a directory that
/// customs did not check.
fn canonical_layout(
    file: &mut File,
    length: u64,
    limits: &Limits,
) -> std::io::Result<Result<(), Refusal>> {
    use Refusal::Layout;
    let start = length.saturating_sub(TAIL);
    file.seek(SeekFrom::Start(start))?;
    let mut tail = Vec::new();
    file.take(length - start).read_to_end(&mut tail)?;

    let candidates: Vec<usize> = (0..tail.len().saturating_sub(3))
        .filter(|&i| tail[i..].starts_with(&END))
        .collect();
    let Some((&at, earlier)) = candidates.split_last() else {
        return Ok(Err(Refusal::NotZip));
    };
    // Where a candidate's comment would end, if it is a whole record.
    let comment_end =
        |at: usize| le(&tail, at + 20, 2).map(|comment| start + at as u64 + 22 + comment);
    if comment_end(at) != Some(length) {
        return Ok(Err(Layout(
            "the last end record's comment does not run to the end of the file",
        )));
    }
    if earlier
        .iter()
        .any(|&other| comment_end(other) == Some(length))
    {
        return Ok(Err(Layout("two end records both end the file")));
    }
    let field = |offset: usize, width: usize| le(&tail, at + offset, width).unwrap_or(0);
    let record_at = start + at as u64;
    let (disk, directory_disk, on_disk, entries) =
        (field(4, 2), field(6, 2), field(8, 2), field(10, 2));
    let (size, offset) = (field(12, 4), field(16, 4));
    if disk != 0 || directory_disk != 0 || on_disk != entries {
        return Ok(Err(Layout("a multi-disk archive")));
    }
    // A locator counts wherever it is, also beside a record with no 0xFFFF
    // field: the zip crate looks for one in front of every end record.
    let locator_at = record_at.checked_sub(20);
    let locator = match locator_at {
        Some(locator_at) => {
            Some(read_at(file, locator_at, 20)?).filter(|l| l.starts_with(&LOCATOR))
        }
        _ => None,
    };

    let (entries, size, offset, directory_end) = match (locator, locator_at) {
        (Some(locator), Some(locator_at)) => {
            let record64 = le(&locator, 8, 8).unwrap_or(u64::MAX);
            if le(&locator, 4, 4) != Some(0) || le(&locator, 16, 4).is_none_or(|disks| disks > 1) {
                return Ok(Err(Layout("a multi-disk archive")));
            }
            if record64.checked_add(56).is_none_or(|end| end > locator_at) {
                return Ok(Err(Layout("the zip64 locator points past itself")));
            }
            let record = read_at(file, record64, 56)?;
            if !record.starts_with(&END64) {
                return Ok(Err(Layout("the zip64 locator points at no zip64 record")));
            }
            let ends_at = le(&record, 4, 8).and_then(|size| size.checked_add(record64 + 12));
            if ends_at != Some(locator_at) {
                return Ok(Err(Layout(
                    "the zip64 record does not end where its locator begins",
                )));
            }
            let field = |offset: usize| le(&record, offset, 8).unwrap_or(0);
            let (disk, directory_disk) = (le(&record, 16, 4), le(&record, 20, 4));
            if disk != Some(0) || directory_disk != Some(0) || field(24) != field(32) {
                return Ok(Err(Layout("a multi-disk archive")));
            }
            (field(32), field(40), field(48), record64)
        }
        _ => (entries, size, offset, record_at),
    };
    if offset.checked_add(size) != Some(directory_end) {
        return Ok(Err(Layout(
            "the central directory does not end where its end record begins",
        )));
    }
    if entries > limits.entries {
        return Ok(Err(Refusal::Entries(entries)));
    }
    if size > limits.directory_bytes {
        return Ok(Err(Refusal::Directory(size)));
    }
    if entries > 0 && !read_at(file, offset, 4)?.starts_with(&DIRECTORY_HEADER) {
        return Ok(Err(Layout(
            "no central directory header where the directory begins",
        )));
    }
    Ok(Ok(()))
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

/// The name of an entry as `NuGet` extracts it: the raw bytes as UTF-8,
/// whatever the language flag says, then `%XX` escapes decoded, then `\`
/// read as `/`. A name whose bytes are not UTF-8, which readers decode in
/// different code pages, or that holds a control character is refused.
fn entry_name(raw: &[u8]) -> Result<String, &'static str> {
    let text = std::str::from_utf8(raw).map_err(|_| "that zip readers decode differently")?;
    let name = unescape(text)
        .ok_or("that is not UTF-8 after unescaping")?
        .replace('\\', "/");
    if name.chars().any(char::is_control) {
        return Err("with a control character");
    }
    Ok(name)
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
            if let Err(gap) = outcome.budget.take_entry(limits) {
                outcome.gaps.push(gap);
                break;
            }
            if data.is_dir() {
                continue;
            }
            match entry_name(data.name_raw()) {
                Ok(name) => match PackagePath::new(&name, limits) {
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
                },
                Err(reason) => {
                    let shown = String::from_utf8_lossy(data.name_raw()).into_owned();
                    outcome.findings.push(Finding::new(
                        FindingRule::C003,
                        Some(shown.clone()),
                        format!("an entry name {reason}: {shown}"),
                    ));
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
        // The declared size is not trusted: the read is allowed the cap or
        // the ratio, whichever is smaller, and one byte more to see whether
        // the entry goes on. More than the ratio allows is a gap. The
        // compressed size is the header's; one that is overstated is still
        // bounded by the bytes really in the file.
        let allowed = cap.min(by_ratio);
        budget.check_bytes(allowed, limits, &entry.path)?;
        let file = self.zip.by_index(entry.key).map_err(|e| unreadable(&e))?;
        let mut bytes = Vec::new();
        file.take(allowed.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|e| unreadable(&e))?;
        let produced = bytes.len() as u64;
        bytes.truncate(usize::try_from(allowed).unwrap_or(usize::MAX));
        budget.bytes += bytes.len() as u64;
        if produced > by_ratio {
            return Err(ratio_gap(produced));
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
    fn a_central_directory_one_byte_over_its_limit_is_a_gap_before_parsing() {
        let file = archive(&[("a.txt", b"1"), ("b.txt", b"2")]);
        let bytes = std::fs::read(file.path()).unwrap();
        let end = &bytes[bytes.len() - 22..];
        let size = u64::from(u32::from_le_bytes([end[12], end[13], end[14], end[15]]));
        let (ok, outcome) = open_with(
            &file,
            &Limits {
                directory_bytes: size,
                ..Limits::default()
            },
        );
        assert!(ok.is_some(), "{outcome:?}");
        let (none, outcome) = open_with(
            &file,
            &Limits {
                directory_bytes: size - 1,
                ..Limits::default()
            },
        );
        assert!(none.is_none());
        assert_eq!(outcome.gaps[0].rule, GapRule::C002);
        assert!(outcome.gaps[0].message.contains("central directory"));
    }

    #[test]
    fn names_are_read_as_utf8_then_unescaped_then_given_slashes() {
        assert_eq!(entry_name(b"build%5Cx.targets").unwrap(), "build/x.targets");
        assert_eq!(entry_name(b"..%5Cx").unwrap(), "../x");
        assert_eq!(entry_name("lib/Ü.dll".as_bytes()).unwrap(), "lib/Ü.dll");
        assert!(entry_name(b"lib/\x81.dll").is_err());
        assert!(entry_name(b"lib/a\0.dll").is_err());
        assert!(entry_name(b"lib/a%00.dll").is_err());
        assert!(entry_name(b"lib/a%C2%9B.dll").is_err(), "a C1 control");
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
