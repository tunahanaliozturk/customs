# 0008: What a baseline accepts, and what each output shows of it

Status: accepted, 2026-11-25; amended 2026-11-28 by the M4 review round

## Context

ADR 0004 defines the fingerprint of a finding. M4 builds the baseline on it, and three questions were left open by the design:

1. The design says that "a team that accepts a gap writes it into the baseline", but a gap has no evidence, and its message names folders of the machine that ran the scan (`not found in C:/Users/...`).
2. Goal 5 says a gap is never hidden. Accepting one must not make it disappear.
3. Text, JSON and SARIF each need to show what the baseline accepted, and SARIF has two ways to do it: leave the result out, or keep it with a `suppressions` entry. How GitHub code scanning treats a suppressed result could not be checked from this machine (open question 8).

## Decision

- **Gaps can be accepted.** A gap's fingerprint is the kind of its owner, the rule, the owner (the lowercase package ID, or the input as shown for a gap that belongs to no package), the path inside the package, and its cause in the place where a finding has its evidence. The message is left out, so a baseline written on a developer's machine works on a CI runner. Like a finding's, it has no version, so **an accepted gap stays accepted at every later version of the package** for as long as its cause and path stay the same.
- **The fingerprint names the owner's kind**, `package` or `input`, as its first part, so that a gap of an input whose name equals a package's lowercase ID is not that package's gap. Every finding belongs to a package.
- **Each gap has a cause, a fixed tag.** C001: `not-found` (in no folder searched), `link` (the package folder or an ID folder is a link), `layout` (an archive layout zip readers read differently), `not-zip` (no end of central directory record), `unreadable` (the system or the zip crate failed to read a file, folder or entry), `incomplete` (a package folder without `.nupkg.metadata`), `not-a-package` (a folder under `--packages-dir` whose names are not an ID and a version). C002: the limit that stopped reading: `graph-bytes`, `nupkg-bytes`, `entries`, `directory-bytes`, `path-bytes`, `path-segments`, `text-bytes`, `assembly-bytes`, `table-rows`, `findings-per-file`, `findings-per-package`, `xml-nodes`, `ratio`, `package-bytes`. Accepting "not found" therefore does not accept "not a zip archive" at the next version, nor one limit another. Until the M4 review, all gaps of one rule on one package with no path shared one fingerprint.
- **A C003 about the whole package has its cause as evidence**: `duplicate-names`, `layout`, `link` or `nuspecs`. These findings have no path, so without it accepting two root nuspecs would accept an archive layout that zip readers read differently.
- **An accepted finding is hidden in text, listed in JSON, left out of SARIF.** Text lists only the findings a reviewer has to look at and ends with `(N more accepted by the baseline)`. JSON lists every finding with `fingerprint` and `accepted`, for tools. SARIF leaves accepted findings out of `results` and gives their number in the run's `properties.acceptedByBaseline`; with a `suppressions` entry instead, a viewer that ignores suppressions would show every accepted finding again as an alert.
- **An accepted gap is still shown everywhere.** Text lists it, marked `(accepted by the baseline)`, and its header line still counts it; JSON marks it `accepted`; SARIF keeps it as a tool execution notification of level `note` instead of `error`. Only the exit code changes: an accepted gap does not make it 3.
- **`--write-baseline` writes every finding and gap**, notes and errors alike, once per fingerprint, sorted by package, rule and path, and keeps the `note` of every fingerprint that the `--baseline` given with it already had. It exits 0 unless the scan could not run at all (2).

## Consequences

- A team can make CI pass on a graph with a known gap, as the design intended, and every report still says the gap is there.
- Moving a package from one machine to another does not invalidate its accepted gaps; moving it to another graph file does not either, as long as the gap belongs to the package and not to the input.
- Tests: `a_baseline_accepts_a_scan_until_an_exec_command_changes`, `a_baseline_can_accept_a_gap_and_the_gap_is_still_shown`, `writing_a_baseline_again_keeps_the_reviewers_notes` and `accepting_one_cause_of_an_unread_package_does_not_accept_another` in `tests/scan/baseline.rs`; `an_input_gap_and_a_package_gap_do_not_share_a_fingerprint` in `src/scan.rs`.
