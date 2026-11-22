//! The commands that do not scan: `--version`, `--help`, `rules`, and the
//! commands and flags that later milestones add.

use crate::common::{TestResult, customs, fixtures};

#[test]
fn version_prints_the_name_and_version() -> TestResult {
    let run = customs(&fixtures(), &["--version"])?;
    assert_eq!(run.code, 0);
    assert_eq!(
        run.stdout.trim(),
        format!("customs {}", env!("CARGO_PKG_VERSION"))
    );
    Ok(())
}

#[test]
fn help_names_the_commands_and_what_customs_cannot_see() -> TestResult {
    let run = customs(&fixtures(), &["--help"])?;
    assert_eq!(run.code, 0);
    assert!(run.stdout.contains("customs scan"));
    assert!(run.stdout.contains("customs rules"));
    assert!(run.stdout.contains("What customs cannot see"));
    Ok(())
}

#[test]
fn no_arguments_is_a_usage_error() -> TestResult {
    let run = customs(&fixtures(), &[])?;
    assert_eq!(run.code, 2);
    assert!(run.stderr.contains("customs --help"));
    Ok(())
}

#[test]
fn rules_lists_only_the_rules_this_build_implements() -> TestResult {
    let run = customs(&fixtures(), &["rules"])?;
    assert_eq!(run.code, 0);
    for id in [
        "C001", "C002", "C003", "C101", "C102", "C103", "C104", "C105",
    ] {
        assert!(
            run.stdout.contains(id),
            "{id} missing from:\n{}",
            run.stdout
        );
    }
    for id in ["C004", "C005", "C201", "C301", "C401"] {
        assert!(!run.stdout.contains(id), "{id} listed but not built");
    }
    Ok(())
}

#[test]
fn features_of_later_milestones_are_usage_errors_that_name_the_milestone() -> TestResult {
    let cases: [(&[&str], &str); 6] = [
        (&["diff", "a.json", "b.json"], "M5"),
        (&["scan", "x.json", "--baseline", "b.json"], "M4"),
        (&["scan", "x.json", "--write-baseline", "b.json"], "M4"),
        (&["scan", "x.json", "--format", "sarif"], "M4"),
        (&["scan", "x.json", "--verify-cache"], "M5"),
        (&["scan", "x.json", "--offline"], "M5"),
    ];
    for (args, milestone) in cases {
        let run = customs(&fixtures(), args)?;
        assert_eq!(run.code, 2, "{args:?}");
        assert!(run.stderr.contains("planned"), "{args:?}: {}", run.stderr);
        assert!(run.stderr.contains(milestone), "{args:?}: {}", run.stderr);
        assert!(run.stdout.is_empty(), "{args:?} printed a report");
    }
    Ok(())
}

#[test]
fn an_unknown_flag_is_a_usage_error() -> TestResult {
    let run = customs(&fixtures(), &["scan", "--frobnicate"])?;
    assert_eq!(run.code, 2);
    Ok(())
}
