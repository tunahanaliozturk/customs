# Roadmap

Each milestone ends with a test that has to pass. A milestone is not done because the code exists.

| # | Milestone | Scope | Exit test |
| --- | --- | --- | --- |
| M0 | Plan | Repository, lints, CI, design, roadmap, ADRs. | CI green on a binary that prints its name and version. |
| M1 | Graph and inventory | Lock file v1 and v2, assets file v3 and v4, a single `.nupkg`, the global packages folder. `locate`, `archive` and `folder` with every limit. Inventory rules C101 to C105, gaps C001 and C002, C003. Text and JSON output, exit codes. Add `zip`, `serde`, `serde_json`, `lexopt`; MSRV to 1.89. Settle open questions 4, 9 (zip) and 12. | Golden inventory for fixture graphs on all three OS. A package with `BUILD/` in capitals is classified as build assets. A zip bomb, an archive with 50,001 entries and one with a `../` entry each end as a gap or C003 within a memory ceiling asserted by the test. A graph naming a package that is not on disk exits 3, not 0. |
| M2 | MSBuild findings and the corpus | Rules C201 to C207 with roxmltree, UTF-16 decoding, import reachability. The benign corpus: `corpus/benign.txt` (300 packages), the fetch script, the reviewed `corpus/benign-expected.txt`, the weekly CI job. Must-catch tests for the 2023 shapes. Settle open questions 5, 11 and 14. | Every MSBuild must-catch test passes, including the inline task reached only through an import. The scanner variant that reads only entry-point files fails that test. The benign corpus produces no error and no finding missing from the reviewed list. |
| M3 | Assembly findings | PE through `object`, the ECMA-335 reader, rules C301 to C304, the build-time severity step. `tools/metadata-oracle` and its committed output. Assembly fixtures from C# sources. Settle open question 10. | customs agrees with the oracle on table row counts, the module initialiser and every `ImplMap` entry for every fixture and every corpus assembly. The fixture with a module initialiser is caught in `lib/` as a warning and in `analyzers/` as an error. Taking `TypeDef` row 2 as `<Module>` and ignoring the wide heap index flag each make a test fail. Benign corpus still clean. |
| M4 | Names, baseline and SARIF | `data/popular-ids.txt` and its script, rules C401 to C403, the self-test against the list. Fingerprints, `--baseline`, `--write-baseline`. SARIF 2.1.0 output. Settle open questions 1, 7 and 8. | The Armenian look-alike of `Guna.UI2.WinForms` is C401 and C402; a one-edit and a separator-only variant are C403; `StripeApi.Net` is not flagged. No popular ID flags another outside the reviewed pairs. A baseline written from a scan makes the same scan exit 0; changing one `Exec` command makes it exit 1 with exactly that finding. Including the version in the fingerprint makes a test fail. The SARIF of a fixture scan validates against the SARIF 2.1.0 JSON schema and is accepted by GitHub's upload action on this repository (code scanning is free for public repositories; if the repository is still private, the schema check alone, and the upload moves to M7). |
| M5 | Diff | `customs diff`, the signed content hash, `fetch` with ureq, the download cache, `--offline`, `--verify-cache`, raising new capabilities to warning. Settle open questions 2, 3 and 9 (ureq). | The content hash matches `.nupkg.metadata` for every signed package in the local cache and the corpus. A bump from a clean fixture to one that adds an `Exec` reports exactly that finding; a bump with identical content reports nothing; a download with one byte changed is C005 and is never opened. With `--offline` a missing package exits 3 and makes no connection. |
| M6 | Fuzzing and hardening | cargo-fuzz targets for archive listing, XML rules, PE and metadata, lock and assets parsing, with a Linux CI job. proptest on every parser on all three OS. Malformed-archive differential against .NET. Terminal escaping review. Settle open questions 6 and 13. | One hour per fuzz target with no crash, no hang and no allocation over the limits. Every malformed archive on which `zip` and .NET disagree is reported as C003. A package with ANSI escapes and bidirectional overrides in its paths and attributes prints them escaped in the golden test. |
| M7 | Documentation and release | README with the corpus numbers and the "cannot see" list, a usage example for a GitHub Actions workflow, an architecture diagram as light and dark PNG made from a script, `CHANGELOG.md`. `publish = true` and tag v0.1.0, both only after the owner says yes. | Every number in the README is reproduced by the commands listed next to it. `cargo install --path .` and a scan of the fixtures pass in CI on Linux, macOS and Windows. |

## Progress

- **M0**, 2026-11-22: done. Scaffold copied from waystation's shape, design, roadmap and five ADRs. The binary prints `customs 0.0.0`. `cargo fmt`, `cargo clippy` with warnings as errors, `cargo build` and `cargo test` pass locally on Windows; CI has not run, as the repository is not on GitHub yet.

## Order of work inside a milestone

1. Write the exit test first, and see it fail.
2. Implement until it passes.
3. Try the milestone's known-wrong variants by hand, see a test fail for each, and record the result above.
4. Run the benign corpus if the milestone touched a rule.
5. Record any decision that is hard to reverse as an ADR, and settle the milestone's open questions in the design.

## After the first release

Not planned, listed so they are not forgotten: what a module initialiser calls (the first call targets of its IL); MSBuild property functions that read the environment or files; `contentFiles` source inspection; project SDKs from `global.json` and `<Project Sdk>`; `packages.config` projects; a `--fix` that prints `ExcludeAssets` lines for the user to paste; per-target-framework reporting of which build files apply; reading `NuGet.Config` for package folders and sources other than nuget.org; a GitHub Action wrapper; a larger benign corpus; mutation testing with cargo-mutants.
