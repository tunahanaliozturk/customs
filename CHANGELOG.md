# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/).

## Unreleased

### Added

- `customs scan` reads a `packages.lock.json` (format versions 1 and 2), an `obj/project.assets.json` (versions 3 and 4, with `PackageDownload` items), a `.nupkg`, a directory holding these, or with `--packages-dir` alone a whole global packages folder.
- An inventory of each package: build assets (C101), analyzers (C102), PowerShell scripts in `tools/` (C103), native binaries (C104) and `contentFiles` source code (C105). Folder names match ignoring case, as NuGet matches them.
- C003 for archive entries that leave the package, for entries whose names are equal ignoring case, and for links in an extracted package folder, which are never followed.
- Gaps C001 (a package not found or not readable) and C002 (a limit stopped reading), with exit code 3. Every limit of the design that this milestone can reach is enforced and tested.
- Text output with escaped package text, and JSON output (schema 1). `--output`, `--fail-on`, and exit codes 0, 1, 2 and 3 with precedence 2, then 1, then 3.
- `customs rules`, `--help` and `--version`. Commands and flags of later milestones are usage errors that name the milestone.

- Repository scaffold, design document and roadmap.

### Changed

- The minimum Rust version is now 1.89.
