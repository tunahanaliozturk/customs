//! Must-catch and must-not-catch tests for the assembly rules C301 to C304,
//! on the assemblies compiled from `tests/fixtures/assemblies/src`. None of
//! them does anything when loaded, and customs never loads them.

use crate::common::{TestResult, assembly, customs, findings, temp_file, zip};

const NAME: &str = "contoso.sample.1.0.0.nupkg";

fn scan(entries: &[(&str, &[u8])]) -> TestResult<(i32, serde_json::Value, String)> {
    let dir = temp_file(NAME, &zip(entries)?)?;
    let json = customs(dir.path(), &["scan", NAME, "--format", "json"])?;
    let text = customs(dir.path(), &["scan", NAME])?;
    Ok((json.code, json.json()?, text.stdout))
}

/// The one finding of `rule`, which must be on `path`.
fn one(report: &serde_json::Value, rule: &str, path: &str) -> TestResult<serde_json::Value> {
    let found = findings(report, rule);
    if found.len() != 1 || found[0]["path"] != path {
        return Err(format!("expected one {rule} on {path}: {report}").into());
    }
    Ok(found[0].clone())
}

fn rules(report: &serde_json::Value) -> Vec<String> {
    report["findings"]
        .as_array()
        .map(|all| {
            all.iter()
                .map(|f| f["rule"].as_str().unwrap_or_default().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// The same assembly with its CLI header removed from the data directory:
/// a native PE file, as the runtime and `System.Reflection.Metadata` see it.
fn native(mut bytes: Vec<u8>) -> TestResult<Vec<u8>> {
    let word = |b: &[u8], at: usize| -> TestResult<usize> {
        let slice = b.get(at..at + 4).ok_or("cut short")?;
        Ok(usize::try_from(u32::from_le_bytes(slice.try_into()?))?)
    };
    let optional = word(&bytes, 0x3C)? + 24;
    let directories = match bytes.get(optional..optional + 2) {
        Some([0x0b, 0x01]) => optional + 96,
        Some([0x0b, 0x02]) => optional + 112,
        _ => return Err("not a PE file".into()),
    };
    let cli = directories + 14 * 8;
    bytes
        .get_mut(cli..cli + 8)
        .ok_or("no CLI directory")?
        .fill(0);
    Ok(bytes)
}

#[test]
fn a_module_initialiser_in_a_library_is_a_warning() -> TestResult {
    let dll = assembly("ModuleInit.dll")?;
    let (code, report, text) = scan(&[("lib/net10.0/Contoso.Sample.dll", &dll)])?;
    let found = one(&report, "C301", "lib/net10.0/Contoso.Sample.dll")?;
    assert_eq!(found["severity"], "warning");
    assert_eq!(found["message"], "module initialiser");
    assert_eq!(found["evidence"], "6 bytes of IL");
    assert_eq!(found["line"], serde_json::Value::Null);
    assert_eq!(code, 1);
    assert!(
        text.contains("  warning  C301  module initialiser\n"),
        "{text}"
    );
    assert!(
        text.contains("lib/net10.0/Contoso.Sample.dll  6 bytes of IL"),
        "{text}"
    );
    Ok(())
}

#[test]
fn a_module_initialiser_in_an_analyzer_is_an_error() -> TestResult {
    let dll = assembly("ModuleInit.dll")?;
    let (code, report, text) = scan(&[("analyzers/dotnet/cs/Contoso.Sample.dll", &dll)])?;
    let found = one(&report, "C301", "analyzers/dotnet/cs/Contoso.Sample.dll")?;
    assert_eq!(found["severity"], "error");
    assert_eq!(code, 1);
    assert!(
        text.contains("  error    C301  module initialiser\n"),
        "{text}"
    );
    Ok(())
}

#[test]
fn a_module_initialiser_in_a_task_assembly_named_by_using_task_is_an_error() -> TestResult {
    let dll = assembly("ModuleInit.dll")?;
    let targets = br#"<Project>
  <UsingTask TaskName="Generate" AssemblyFile="$(MSBuildThisFileDirectory)..\tasks\Contoso.Sample.Tasks.dll" />
</Project>
"#;
    let (code, report, _) = scan(&[
        ("build/Contoso.Sample.targets", targets),
        ("tasks/Contoso.Sample.Tasks.dll", &dll),
        ("lib/net10.0/Contoso.Sample.dll", &dll),
    ])?;
    let found = findings(&report, "C301");
    let severity = |path: &str| {
        found
            .iter()
            .find(|f| f["path"] == path)
            .map(|f| f["severity"].clone())
    };
    assert_eq!(found.len(), 2, "{report}");
    assert_eq!(
        severity("tasks/Contoso.Sample.Tasks.dll"),
        Some("error".into())
    );
    assert_eq!(
        severity("lib/net10.0/Contoso.Sample.dll"),
        Some("warning".into())
    );
    assert_eq!(code, 1);
    Ok(())
}

#[test]
fn a_pinvoke_to_virtual_protect_is_c302_and_loading_a_library_is_not() -> TestResult {
    let dll = assembly("PInvoke.dll")?;
    let (code, report, _) = scan(&[("lib/net10.0/Contoso.Sample.dll", &dll)])?;
    let found = findings(&report, "C302");
    let evidence: Vec<&str> = found
        .iter()
        .map(|f| f["evidence"].as_str().unwrap_or_default())
        .collect();
    // WriteProcessMemory is declared under another managed name; the
    // import name is what is matched.
    assert_eq!(
        evidence,
        ["kernel32.dll!VirtualProtect", "kernel32!WriteProcessMemory"],
        "{report}"
    );
    assert!(found.iter().all(|f| f["severity"] == "warning"));
    assert_eq!(found[0]["message"], "P/Invoke to VirtualProtect");
    assert_eq!(code, 1);
    Ok(())
}

#[test]
fn an_obfuscator_marker_is_a_note_and_a_warning_in_an_analyzer() -> TestResult {
    let dll = assembly("Marker.dll")?;
    let (code, report, _) = scan(&[("lib/net10.0/Contoso.Sample.dll", &dll)])?;
    let found = one(&report, "C303", "lib/net10.0/Contoso.Sample.dll")?;
    assert_eq!(found["severity"], "note");
    assert_eq!(found["evidence"], "DotfuscatorAttribute");
    assert_eq!(found["message"], "marker of the obfuscator Dotfuscator");
    assert_eq!(code, 0);

    let (code, report, _) = scan(&[("analyzers/dotnet/cs/Contoso.Sample.dll", &dll)])?;
    let found = one(&report, "C303", "analyzers/dotnet/cs/Contoso.Sample.dll")?;
    assert_eq!(found["severity"], "warning");
    assert_eq!(code, 1);
    Ok(())
}

/// The design says customs cannot see logic in ordinary library code. The
/// fixture has a date check in an extension method, the shape of the Socket
/// case of 2025-11-06, and a static constructor on an ordinary type, which
/// a reader that took the wrong `TypeDef` row for `<Module>` would report.
#[test]
fn a_plain_library_with_date_logic_and_a_static_constructor_has_no_finding() -> TestResult {
    let dll = assembly("Plain.dll")?;
    let (code, report, _) = scan(&[("lib/net10.0/Contoso.Sample.dll", &dll)])?;
    assert_eq!(rules(&report), Vec::<String>::new(), "{report}");
    assert_eq!(report["packages"][0]["complete"], true);
    assert_eq!(code, 0);
    Ok(())
}

#[test]
fn an_assembly_with_four_byte_string_indexes_is_read_through() -> TestResult {
    let dll = assembly("Wide.dll")?;
    let (_, report, _) = scan(&[("lib/net10.0/Contoso.Sample.dll", &dll)])?;
    one(&report, "C301", "lib/net10.0/Contoso.Sample.dll")?;
    let found = one(&report, "C302", "lib/net10.0/Contoso.Sample.dll")?;
    assert_eq!(found["evidence"], "kernel32.dll!VirtualAlloc");
    Ok(())
}

#[test]
fn a_dll_where_nuget_expects_managed_code_that_is_not_one_is_c304() -> TestResult {
    let native = native(assembly("Plain.dll")?)?;
    let mut truncated = assembly("Plain.dll")?;
    truncated.truncate(1024);
    let (code, report, _) = scan(&[
        ("lib/net10.0/Native.dll", &native),
        ("lib/net10.0/Text.dll", b"not an assembly"),
        ("ref/net10.0/Cut.dll", &truncated),
        ("analyzers/dotnet/cs/Native.dll", &native),
    ])?;
    let found: Vec<(String, String, String)> = findings(&report, "C304")
        .iter()
        .map(|f| {
            let text = |k: &str| f[k].as_str().unwrap_or_default().to_owned();
            (text("path"), text("severity"), text("evidence"))
        })
        .collect();
    let expect = |path: &str, severity: &str, evidence: &str| {
        (path.to_owned(), severity.to_owned(), evidence.to_owned())
    };
    assert_eq!(
        found,
        [
            expect(
                "analyzers/dotnet/cs/Native.dll",
                "error",
                "a native PE file without a CLI header"
            ),
            expect(
                "lib/net10.0/Native.dll",
                "warning",
                "a native PE file without a CLI header"
            ),
            expect("lib/net10.0/Text.dll", "warning", "not a PE file"),
            expect(
                "ref/net10.0/Cut.dll",
                "warning",
                "the CLI header is outside the file"
            ),
        ],
        "{report}"
    );
    assert_eq!(code, 1);
    Ok(())
}

#[test]
fn a_native_tool_under_tools_is_a_native_binary_not_c304() -> TestResult {
    let native = native(assembly("Plain.dll")?)?;
    let (code, report, _) = scan(&[("tools/win-x64/protoc.exe", &native)])?;
    assert_eq!(rules(&report), ["C104"], "{report}");
    let found = one(&report, "C104", "tools/win-x64/protoc.exe")?;
    assert_eq!(
        found["message"],
        "native binary: tools/win-x64/protoc.exe (PE)"
    );
    assert_eq!(report["packages"][0]["assets"][0]["kind"], "native");
    assert_eq!(code, 0);
    Ok(())
}
