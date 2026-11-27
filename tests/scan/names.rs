//! Rules C401 to C403 through the binary: a graph that names a look-alike
//! package is reported even when the package is not on disk, because the
//! name alone is the finding.

use crate::common::{TestResult, customs, findings, gaps, temp_file};

/// Scans a lock file that lists one package, which is not on disk.
fn scan_id(id: &str) -> TestResult<(i32, serde_json::Value)> {
    let lock = format!(
        r#"{{"version": 1, "dependencies": {{"net8.0": {{"{id}": {{"type": "Direct", "resolved": "1.0.0"}}}}}}}}"#
    );
    let dir = temp_file("packages.lock.json", lock.as_bytes())?;
    let run = customs(
        dir.path(),
        &["scan", "packages.lock.json", "--format", "json"],
    )?;
    Ok((run.code, run.json()?))
}

fn rules(report: &serde_json::Value) -> Vec<String> {
    report["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|f| {
            format!(
                "{} {}",
                f["rule"].as_str().unwrap_or("?"),
                f["evidence"].as_str().unwrap_or("")
            )
        })
        .collect()
}

#[test]
fn the_armenian_look_alike_of_guna_is_c401_and_c402() -> TestResult {
    let (code, report) = scan_id("Gսոa.UI2.WinForms")?;
    assert_eq!(rules(&report), ["C401 ", "C402 Guna.UI2.WinForms"]);
    assert_eq!(findings(&report, "C402")[0]["severity"], "error");
    // The package is not on disk: a gap, but the errors decide the exit.
    assert_eq!(gaps(&report, "C001").len(), 1);
    assert_eq!(code, 1);
    Ok(())
}

#[test]
fn a_one_edit_and_a_separator_only_variant_are_c403() -> TestResult {
    for (id, popular) in [
        ("Newtonsoft.Jsn", "Newtonsoft.Json"),
        (
            "Microsoft_Extensions_Logging",
            "Microsoft.Extensions.Logging",
        ),
    ] {
        let (code, report) = scan_id(id)?;
        assert_eq!(rules(&report), [format!("C403 {popular}")], "{id}");
        assert_eq!(findings(&report, "C403")[0]["severity"], "warning");
        assert_eq!(code, 1, "{id}");
    }
    Ok(())
}

#[test]
fn stripe_api_net_and_popular_ids_are_not_flagged() -> TestResult {
    for id in ["StripeApi.Net", "Stripe.net", "newtonsoft.json"] {
        let (code, report) = scan_id(id)?;
        assert_eq!(rules(&report), Vec::<String>::new(), "{id}");
        // Only the gap of the missing package remains.
        assert_eq!(code, 3, "{id}");
    }
    Ok(())
}
