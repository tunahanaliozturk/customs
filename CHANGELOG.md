# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/).

## Unreleased

### Added

- MSBuild rules: C201 inline task factories, C202 task assemblies, C203 `Exec`, C204 `DownloadFile`, C205 URLs, C206 base64 runs, C207 imports that cannot be resolved, and C004 for files that are not well-formed XML, have a DTD or use another encoding. Every `.props`, `.targets` and `.tasks` file is read, and every file of any name that an import reaches from them, UTF-16 included; findings in files that no entry point imports say so. Findings carry a line and evidence in text and JSON. At most 1,000 findings are listed from one file, and values from files are cut at 240 characters.
- Task assemblies (`UsingTask AssemblyFile`, and `.dll` or `.exe` under `build*/` or `tools/`) are listed with the role `build_time`.
- The ID and version of a single `.nupkg` come from its nuspec. A nuspec over the cap or unreadable is a gap, and two of them are C003.
- The benign corpus: the 300 most downloaded packages, pinned with SHA-512, a fetch script, the reviewed list of what they produce, an ignored test and a weekly CI job.
- `customs scan` reads a `packages.lock.json` (format versions 1 and 2), an `obj/project.assets.json` (versions 3 and 4, with `PackageDownload` items), a `.nupkg`, a directory holding these, or with `--packages-dir` alone a whole global packages folder.
- An inventory of each package: build assets (C101), analyzers (C102), PowerShell scripts in `tools/` (C103), native binaries (C104) and `contentFiles` source code (C105). Folder names match ignoring case, as NuGet matches them.
- C003 for archive entries that leave the package, for entries whose names are equal ignoring case, and for links in an extracted package folder, which are never followed.
- An archive whose layout zip readers could read differently is C003 and is not opened, and its central directory may be at most 64 MiB, so the zip crate never parses a directory customs did not check. Entry names are read as UTF-8, then unescaped, then given `/` for `\`; names with control characters or with bytes that are not UTF-8 are C003. A package folder that is a link is C003 and is not read.
- Gaps C001 (a package not found or not readable) and C002 (a limit stopped reading), with exit code 3. Every limit of the design that this milestone can reach is enforced and tested.
- Text output with escaped package text, and JSON output (schema 1). `--output`, `--fail-on`, and exit codes 0, 1, 2 and 3 with precedence 2, then 1, then 3.
- `customs rules`, `--help` and `--version`. Commands and flags of later milestones are usage errors that name the milestone.

- Repository scaffold, design document and roadmap.

### Changed

- The minimum Rust version is now 1.89.
