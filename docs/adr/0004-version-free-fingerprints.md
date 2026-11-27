# 0004: Fingerprints without version and line, with the evidence

Status: accepted, 2026-11-22

## Context

The baseline and `diff` both need to decide whether two findings are "the same". A team reviews a code generator package whose targets run its compiler through `Exec`, and accepts it once; the next patch release should not ask again. But if the next release changes the command it runs, it should.

The options for what goes into a fingerprint:

1. Everything: rule, package, version, path, line, evidence. Every bump re-reports every finding, which makes the baseline useless for teams that take weekly bumps.
2. Rule, package and path only. A bump that changes `Exec Command="gen ..."` to `Exec Command="curl ... | sh"` in the same file is silently accepted. That is the exact attack the tool exists for.
3. Rule, package, path and the rule's evidence, without version and line.

## Decision

Option 3. The fingerprint is the first 128 bits of SHA-256 over the rule ID, the lowercase package ID, the path inside the package and the evidence with runs of whitespace collapsed to one space, joined with a separator byte that cannot occur in any of them. Each rule defines its evidence: the `Command` attribute for `Exec`, the URL for C205, the base64 run for C206, the assembly path and body size for a module initialiser (since the M4 review also a hash of its IL), the module and function name for a P/Invoke.

## Consequences

- A version bump that does not touch the relevant content keeps its findings accepted, and `diff` reports nothing for it.
- A change to the command, the URL or the initialiser's IL shows up as a new finding, even in the same file at the same line.
- Moving a construct to another file in the package shows up as new. That is noise in rare cases and is accepted.
- Two identical `Exec` elements in one file share a fingerprint. They are reported once with a count. Accepting one accepts both, which is acceptable because they are identical.
- Collapsing whitespace means reformatting a targets file does not re-report it. Changing quoting or casing does; that is deliberate, since case can matter on Linux.
- A test checks that the fingerprint does not change when only the version or the line changes, and does change when the evidence does. A variant that includes the version must fail it.
