# Security policy

## Reporting a vulnerability

Report it privately through GitHub: the **Security** tab of this repository, then **Report a vulnerability**. Please do not open a public issue, discussion or pull request for it.

Include what you found and how to reproduce it. You will get an answer within 7 days, and a fix or a plan within 30 days for confirmed issues. You are credited in the advisory unless you ask not to be.

## Supported versions

Security fixes go into the latest release only.

## What counts

customs reads files that an attacker may have written. These count as vulnerabilities:

- A package, lock file, assets file or assembly that makes customs panic, hang, or use memory or disk without bound.
- A package that makes customs execute anything, load anything, or write anywhere other than its download cache.
- A package whose build-time content customs reads differently from NuGet or MSBuild, so that a finding is silently missed. An example is a zip archive that customs and .NET extract to different files.
- Text from a package that reaches the terminal as a control sequence instead of as escaped text.
- A download from any host other than the configured package source, or one that is accepted although its hash does not match the lock file.

## What does not count

The limits listed under "What it cannot see" in [docs/design.md](docs/design.md) are known gaps, not vulnerabilities. A malicious package that customs does not flag is welcome as an ordinary issue, with a reconstruction that does no harm. Please do not attach live malware.
