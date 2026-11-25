//! Archives whose layout zip readers could read differently are refused
//! before the zip crate sees them, and entry names are decoded as `NuGet`
//! decodes them. Every archive here is built by the test.

use std::io::{Cursor, Write as _};

use zip::write::{SimpleFileOptions, ZipWriter};

use crate::common::{TestResult, assembly, customs, findings, gaps, temp_file, zip};

/// An archive of `count` empty entries.
fn many(count: usize) -> TestResult<Vec<u8>> {
    let names: Vec<String> = (0..count).map(|i| format!("content/{i}.txt")).collect();
    let entries: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b""[..])).collect();
    zip(&entries)
}

/// Splits an archive without a comment into everything before its end
/// record, and the central directory size and offset the record gives.
fn split_end(bytes: &[u8]) -> TestResult<(Vec<u8>, u64, u64)> {
    let at = bytes.len().checked_sub(22).ok_or("too short")?;
    let record = bytes.get(at..).ok_or("too short")?;
    if record.get(..4) != Some(&[0x50, 0x4b, 0x05, 0x06][..]) {
        return Err("the archive does not end with a plain end record".into());
    }
    let u32_at = |i: usize| -> TestResult<u64> {
        let b: [u8; 4] = record.get(i..i + 4).ok_or("short")?.try_into()?;
        Ok(u64::from(u32::from_le_bytes(b)))
    };
    Ok((bytes[..at].to_vec(), u32_at(12)?, u32_at(16)?))
}

fn zip64_record(entries: u64, size: u64, offset: u64) -> Vec<u8> {
    let mut out = vec![0x50, 0x4b, 0x06, 0x06];
    out.extend(44_u64.to_le_bytes());
    out.extend(45_u16.to_le_bytes());
    out.extend(45_u16.to_le_bytes());
    out.extend(0_u32.to_le_bytes());
    out.extend(0_u32.to_le_bytes());
    out.extend(entries.to_le_bytes());
    out.extend(entries.to_le_bytes());
    out.extend(size.to_le_bytes());
    out.extend(offset.to_le_bytes());
    out
}

fn locator(record_offset: u64) -> Vec<u8> {
    let mut out = vec![0x50, 0x4b, 0x06, 0x07];
    out.extend(0_u32.to_le_bytes());
    out.extend(record_offset.to_le_bytes());
    out.extend(1_u32.to_le_bytes());
    out
}

fn classic_end(entries: u16, size: u32, offset: u32) -> Vec<u8> {
    let mut out = vec![0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0];
    out.extend(entries.to_le_bytes());
    out.extend(entries.to_le_bytes());
    out.extend(size.to_le_bytes());
    out.extend(offset.to_le_bytes());
    out.extend(0_u16.to_le_bytes());
    out
}

fn scan(name: &str, bytes: &[u8]) -> TestResult<(i32, serde_json::Value)> {
    let dir = temp_file(name, bytes)?;
    let run = customs(dir.path(), &["scan", name, "--format", "json"])?;
    Ok((run.code, run.json()?))
}

fn assert_refused_unopened(code: i32, report: &serde_json::Value) {
    let layout = findings(report, "C003");
    assert_eq!(layout.len(), 1, "{report}");
    let message = layout[0]["message"].as_str().unwrap_or_default();
    assert!(message.contains("layout"), "{message}");
    assert_eq!(report["packages"][0]["read"]["entries"], 0, "{report}");
    assert_eq!(report["packages"][0]["complete"], false, "{report}");
    assert_eq!(code, 1);
}

#[test]
fn junk_in_front_and_a_zip64_record_away_from_its_locator_is_refused_unopened() -> TestResult {
    // The reviewer's archive: a classic record that declares one entry and
    // points to zip64, whose locator gives an offset that ignores the junk in
    // front. The zip crate finds the zip64 record by searching and parses all
    // 60,000 entries.
    let (body, size, offset) = split_end(&many(60_000)?)?;
    let mut bytes = vec![b'J'; 4096];
    bytes.extend(&body);
    let record_at = bytes.len() as u64;
    bytes.extend(zip64_record(60_000, size, offset));
    bytes.extend(locator(record_at - 4096));
    bytes.extend(classic_end(1, u32::MAX, u32::MAX));

    let (code, report) = scan("contoso.junk.1.0.0.nupkg", &bytes)?;
    assert_refused_unopened(code, &report);
    Ok(())
}

#[test]
fn a_zip64_locator_beside_an_end_record_that_asks_for_none_is_not_passed_by() -> TestResult {
    // The classic record is consistent by itself: one entry, no 0xFFFF field,
    // and a directory that runs exactly to it. The zip crate looks for a
    // locator in front of every end record all the same, and takes the count
    // from the zip64 record: 60,000 entries.
    let (body, size, offset) = split_end(&many(60_000)?)?;
    let mut bytes = body;
    let record64_at = bytes.len() as u64;
    bytes.extend(zip64_record(60_000, size, offset));
    bytes.extend(locator(record64_at));
    let record_at = bytes.len() as u64;
    bytes.extend(classic_end(
        1,
        u32::try_from(record_at - offset)?,
        u32::try_from(offset)?,
    ));

    let (code, report) = scan("contoso.quiet.1.0.0.nupkg", &bytes)?;
    assert_eq!(code, 3, "{report}");
    assert_eq!(report["packages"][0]["read"]["entries"], 0, "{report}");
    assert_eq!(gaps(&report, "C002").len(), 1, "{report}");
    Ok(())
}

#[test]
fn junk_in_front_of_a_plain_archive_is_refused_unopened() -> TestResult {
    // The record's own fields are honest, but the directory no longer ends
    // where the record begins; readers that detect the offset and readers
    // that do not read different bytes.
    let mut bytes = vec![b'J'; 4096];
    bytes.extend(zip(&[("lib/net8.0/A.dll", b"MZ")])?);
    let (code, report) = scan("contoso.prefixed.1.0.0.nupkg", &bytes)?;
    assert_refused_unopened(code, &report);
    Ok(())
}

#[test]
fn a_directory_size_that_does_not_reach_the_end_record_is_refused_unopened() -> TestResult {
    // The zip crate would still find the directory by its first header;
    // another reader that trusts the size would not.
    let mut bytes = zip(&[("lib/net8.0/A.dll", b"MZ")])?;
    let at = bytes.len() - 22 + 12;
    let size = u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    bytes[at..at + 4].copy_from_slice(&(size + 10).to_le_bytes());
    let (code, report) = scan("contoso.sized.1.0.0.nupkg", &bytes)?;
    assert_refused_unopened(code, &report);
    Ok(())
}

#[test]
fn a_decoy_zip64_record_at_the_locator_offset_is_refused_unopened() -> TestResult {
    // The locator points at a record that declares one entry and does not end
    // at the locator. A second record, which does, declares 60,000.
    let (body, size, offset) = split_end(&many(60_000)?)?;
    let mut bytes = body;
    let decoy_at = bytes.len() as u64;
    bytes.extend(zip64_record(1, size, offset));
    bytes.extend(zip64_record(60_000, size, offset - 56));
    bytes.extend(locator(decoy_at));
    bytes.extend(classic_end(u16::MAX, u32::MAX, u32::MAX));

    let (code, report) = scan("contoso.decoy.1.0.0.nupkg", &bytes)?;
    assert_refused_unopened(code, &report);
    Ok(())
}

#[test]
fn a_central_directory_size_of_1_gib_is_refused() -> TestResult {
    let mut bytes = zip(&[("lib/net8.0/A.dll", b"MZ")])?;
    let at = bytes.len() - 22 + 12;
    bytes[at..at + 4].copy_from_slice(&(1_u32 << 30).to_le_bytes());

    let (code, report) = scan("contoso.huge.1.0.0.nupkg", &bytes)?;
    assert_ne!(code, 0);
    assert_eq!(report["packages"][0]["read"]["entries"], 0, "{report}");
    assert!(
        !findings(&report, "C003").is_empty() || !gaps(&report, "C002").is_empty(),
        "{report}"
    );
    Ok(())
}

#[test]
fn an_end_record_signature_inside_the_comment_is_refused_unopened() -> TestResult {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer.start_file("lib/net8.0/A.dll", SimpleFileOptions::default())?;
    writer.write_all(b"MZ")?;
    let mut comment = b"note ".to_vec();
    comment.extend(classic_end(0, 0, 0));
    writer.set_raw_comment(comment.into_boxed_slice())?;
    let bytes = writer.finish()?.into_inner();

    let (code, report) = scan("contoso.comment.1.0.0.nupkg", &bytes)?;
    assert_refused_unopened(code, &report);
    Ok(())
}

#[test]
fn canonical_archives_written_by_the_zip_crate_pass() -> TestResult {
    // A real assembly, so that nothing but the layout could fail the scan.
    let dll = assembly("Plain.dll")?;
    // Plain.
    let plain = zip(&[("lib/net8.0/A.dll", &dll)])?;
    // With a comment.
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer.start_file("lib/net8.0/A.dll", SimpleFileOptions::default())?;
    writer.write_all(&dll)?;
    writer.set_comment("a comment the writer added")?;
    let commented = writer.finish()?.into_inner();
    // With zip64 end records.
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer.start_file("lib/net8.0/A.dll", SimpleFileOptions::default())?;
    writer.write_all(&dll)?;
    writer.set_raw_zip64_extensible_data_sector(Box::new([]));
    let zip64 = writer.finish()?.into_inner();
    assert!(
        zip64.windows(4).any(|w| w == [0x50, 0x4b, 0x06, 0x06]),
        "no zip64 record"
    );

    for (name, bytes) in [("plain", plain), ("commented", commented), ("zip64", zip64)] {
        let (code, report) = scan(&format!("contoso.{name}.1.0.0.nupkg"), &bytes)?;
        assert_eq!(code, 0, "{name}: {report}");
        assert!(findings(&report, "C003").is_empty(), "{name}: {report}");
        assert_eq!(report["packages"][0]["complete"], true, "{name}: {report}");
        assert_eq!(
            report["packages"][0]["assets"][0]["path"],
            "lib/net8.0/A.dll"
        );
    }

    // More than 65,535 entries makes the crate write zip64 by itself. The
    // layout passes; the entry limit is what stops it.
    let (code, report) = scan("contoso.wide.1.0.0.nupkg", &many(65_536)?)?;
    assert_eq!(code, 3, "{report}");
    assert!(findings(&report, "C003").is_empty(), "{report}");
    assert_eq!(gaps(&report, "C002").len(), 1, "{report}");
    Ok(())
}

/// Overwrites every occurrence of `from` with `to`, which has the same length.
fn replace_all(bytes: &mut [u8], from: &[u8], to: &[u8]) -> usize {
    let mut count = 0;
    let mut at = 0;
    while let Some(found) = bytes
        .get(at..)
        .and_then(|rest| rest.windows(from.len()).position(|w| w == from))
    {
        let start = at + found;
        bytes[start..start + to.len()].copy_from_slice(to);
        count += 1;
        at = start + from.len();
    }
    count
}

#[test]
fn entry_names_are_unescaped_before_backslashes_become_slashes() -> TestResult {
    let archive = zip(&[
        (r"C:\x.targets", b"<Project />"),
        (r"..\x.targets", b"<Project />"),
        (r"\\server\share\x.targets", b"<Project />"),
        ("..%5Cy.targets", b"<Project />"),
        ("build%5CContoso.Names.targets", b"<Project />"),
    ])?;
    let (code, report) = scan("contoso.names.1.0.0.nupkg", &archive)?;
    assert_eq!(code, 1);
    assert_eq!(findings(&report, "C003").len(), 4, "{report}");
    let build = findings(&report, "C101");
    assert_eq!(build.len(), 1, "{report}");
    assert_eq!(build[0]["path"], "build/Contoso.Names.targets");
    Ok(())
}

#[test]
fn a_name_with_a_control_character_or_bytes_readers_decode_differently_is_c003() -> TestResult {
    // The zip crate writes these names as given; the bytes are then patched
    // to a NUL and to 0x81, which is not UTF-8 and which CP437 reads as ü.
    let mut archive = zip(&[
        ("build/Contoso.NulXname.targets", b"<Project />"),
        ("build/Contoso.Cp437Y.targets", b"<Project />"),
    ])?;
    assert_eq!(replace_all(&mut archive, b"NulXname", b"Nul\0name"), 2);
    assert_eq!(replace_all(&mut archive, b"Cp437Y", b"Cp437\x81"), 2);

    let (code, report) = scan("contoso.bytes.1.0.0.nupkg", &archive)?;
    assert_eq!(code, 1);
    assert_eq!(findings(&report, "C003").len(), 2, "{report}");
    assert!(findings(&report, "C101").is_empty(), "{report}");
    Ok(())
}

#[test]
fn a_valid_utf8_name_is_read_as_utf8_whatever_the_flag_says() -> TestResult {
    // "ü" written as UTF-8 by the crate, which sets the UTF-8 flag; the flag
    // is then cleared, so a reader that trusts it would use CP437.
    let mut archive = zip(&[("build/Contoso.Ünits.targets", b"<Project />")])?;
    for signature in [[0x50, 0x4b, 0x03, 0x04], [0x50, 0x4b, 0x01, 0x02]] {
        let start = archive
            .windows(4)
            .position(|w| w == signature)
            .ok_or("no header")?;
        let flags = if signature[2] == 0x03 {
            start + 6
        } else {
            start + 8
        };
        archive[flags + 1] &= !0x08;
    }
    let (_, report) = scan("contoso.units.1.0.0.nupkg", &archive)?;
    assert!(findings(&report, "C003").is_empty(), "{report}");
    assert_eq!(
        findings(&report, "C101")[0]["path"],
        "build/Contoso.Ünits.targets"
    );
    Ok(())
}
