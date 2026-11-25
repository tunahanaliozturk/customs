# customs

A local command-line tool that shows which NuGet packages in a .NET project run code on the build machine or at load time, and what changed in that respect when a package version is bumped.

It reads the lock file or the assets file that restore already wrote, opens the packages on disk, and reports MSBuild targets that run commands, inline build tasks, analyzers, module initialisers and look-alike package names. It never runs MSBuild and never loads an assembly, so it needs no .NET SDK and no account.

At a border, customs officers open the crates and list what is inside before anything is let through. That is the job.

## Status

Milestones M1 to M3 of seven are done, and nothing is released. `customs scan` reads a lock file, an assets file, a `.nupkg` or a global packages folder. It lists which packages bring MSBuild build assets, analyzers, PowerShell scripts, native binaries and `contentFiles` source code, and it reads every `.props`, `.targets` and `.tasks` file of every package, and any file an import reaches from them, for inline tasks, `Exec`, `DownloadFile`, URLs and long base64 strings, at file and line, following literal imports from the entry points. It reads every managed assembly with a metadata reader of its own and reports module initialisers, P/Invokes that change memory protection or write to another process, a known obfuscator marker, and `.dll` files that are not readable managed code; in an analyzer or a build-time assembly each of these is one step more severe. It says so, with exit code 3, when it could not look at everything. It does not check package IDs (M4), and it has no baseline (M4) and no `diff` (M5).

## Try it

You need Rust 1.89 or newer. The repository has made-up fixture packages to scan:

```
git clone https://github.com/tunahanaliozturk/customs
cd customs/tests/fixtures
cargo run --release --quiet -- scan lock-v1/packages.lock.json --packages-dir packages
```

```
customs 0.0.0: 4 packages from 1 input, all complete

Contoso.Analyzers 1.0.4  (direct)
  note     C102  analyzer: analyzers/dotnet/cs/Contoso.Analyzers.CodeFixes.dll (+1 more file)

Contoso.Build.Tools 3.2.0  (direct)
  note     C101  build assets: build/Contoso.Build.Tools.targets (+2 more files)
  warning  C203  Exec task
                 build/tasks/Fetch.targets:4  echo fixture, would fetch https://example.invalid/tool
  warning  C205  URL
                 build/tasks/Fetch.targets:4  https://example.invalid/tool

Fabrikam.Native 2.1.0  (transitive)
  note     C104  native binary: runtimes/linux-x64/native/libfabrikam.so (ELF) (+3 more files)

0 errors, 2 warnings, 3 notes
exit 1: findings at or above --fail-on warning
```

The `Exec` sits in `build/tasks/Fetch.targets`, which the package's entry point `build/Contoso.Build.Tools.targets` imports. Add `--format json` for every file of every package, by kind, and every finding with its line and evidence. On your own project, run `dotnet restore` first, then point customs at the project folder, its `packages.lock.json` or its `obj/project.assets.json`. `customs rules` lists the rules and `customs --help` the options.

## What a normal project sees

The benign corpus is the 300 most downloaded packages on nuget.org, pinned in [corpus/benign.txt](corpus/benign.txt) on 2026-11-22. Packages with at least one warning, by rule:

| Rule | Packages |
| --- | --- |
| C203 `Exec` task | 2 |
| C205 URL | 1 |
| C302 P/Invoke to a memory or process function | 1 |
| C201, C204, C206, C004, C003, C301, C304 | 0 |

No package in the corpus produces an error. Every warning is explained in [corpus/benign-expected.txt](corpus/benign-expected.txt). To reproduce the numbers:

```
python corpus/corpus.py fetch
cargo test --release -- --ignored corpus
cargo run --release --quiet -- scan target/corpus/*.nupkg --format json --fail-on never
```

The first command downloads the 300 packages (849,380,928 bytes) into `target/corpus` and checks each against its pinned SHA-512. The second checks the scan against the reviewed list, and checks customs's metadata reader against `System.Reflection.Metadata` on all 2,762 `.dll` and `.exe` entries of the corpus (the row count of every table, the module initialiser and every P/Invoke), from the committed output of `tools/metadata-oracle`. The third prints the report the table counts.

## Documents

- [docs/design.md](docs/design.md): the user's view, the architecture, the hard parts and how each claim will be tested.
- [docs/roadmap.md](docs/roadmap.md): milestones, each with an exit test.
- [docs/adr/](docs/adr/): decisions that had a real alternative.

## The problem

A NuGet package can run code on the machine that restores and builds it, before any of the application's own code runs. MSBuild imports the `.props` and `.targets` files in a package's `build/`, `buildTransitive/` and `buildMultitargeting/` folders, and those files can run commands and compile inline tasks. Analyzers and source generators are assemblies loaded into the compiler. A library assembly can carry a module initialiser, which runs when the assembly loads. Teams accept automated version bumps every week, and CI builds them with secrets in the environment.

This is used in real attacks:

- ReversingLabs, 31 October 2023: hundreds of packages ran a downloader from an MSBuild inline task in `build/<id>.targets`, replacing the older `tools/init.ps1` scripts. [IAmReboot](https://reversinglabs.com/blog/iamreboot-malicious-nuget-packages-exploit-msbuild-loophole)
- ReversingLabs, 11 July 2024: about 60 packages shipped legitimate DLLs patched to add a module initialiser, and one used Armenian letters in its ID to pass as `Guna.UI2.WinForms`. [Homoglyphs and IL weaving](https://reversinglabs.com/blog/malicious-nuget-campaign-uses-homoglyphs-and-il-weaving-to-fool-devs)
- Socket, 6 November 2025: nine packages with sabotage that triggers on dates in 2027 and 2028, hidden in ordinary extension methods. [Time-delayed payloads](https://socket.dev/blog/9-malicious-nuget-packages-deliver-time-delayed-destructive-payloads) customs will not catch these; see below.
- The Hacker News, 26 February 2026 and 29 May 2026: a fake Stripe library and a fake banking SDK that stole keys and certificates from inside normal methods. [StripeApi.Net](https://thehackernews.com/2026/02/malicious-stripeapi-nuget-package.html), [Sicoob.Sdk](https://thehackernews.com/2026/05/malicious-sicoob-nuget-steals-banking.html)

The one mitigation NuGet offers is to write `ExcludeAssets` by hand on each `PackageReference` ([Meziantou](https://www.meziantou.net/limit-what-nuget-packages-can-do-in-your-project.htm), read 22 November 2026). To write it, you have to know which packages bring build assets. NuGetAudit, on by default, checks known vulnerabilities from the GitHub Advisory Database only ([Microsoft Learn](https://learn.microsoft.com/en-us/nuget/concepts/auditing-packages), read 22 November 2026). DataDog's GuardDog inspects package contents but not for NuGet ([README](https://github.com/DataDog/guarddog), read 22 November 2026). Socket covers NuGet as a hosted service ([announcement](https://socket.dev/blog/introducing-net-support), 21 April 2025).

## What the first release will do

- Read a `packages.lock.json`, an `obj/project.assets.json`, a single `.nupkg`, or the global packages folder.
- List every package that brings MSBuild props or targets, analyzers or source generators, PowerShell scripts, or native binaries.
- Report, inside those: inline task factories, `Exec`, `DownloadFile`, URLs and long base64 strings in MSBuild files; module initialisers, a short list of suspicious P/Invokes and known obfuscator markers in assemblies; package IDs that use non-ASCII characters or sit one edit away from a popular package.
- `customs diff OLD NEW`: for each bumped package, compare the old and the new version and report only what is new. Packages missing from the local cache are fetched from nuget.org and checked against the hash in the lock file.
- A baseline file, so a team accepts the current state once and then sees only changes.
- Output as text, JSON or SARIF, with exit codes for CI. A scan that could not look at everything says so with its own exit code.

## What it will not do

- Run, evaluate or load anything. It does not know which `Condition` is true or what a `$(Property)` expands to; it reports what is written.
- Find malicious logic in ordinary library code. The Socket and Hacker News cases above live in normal methods and would pass.
- See through obfuscation beyond a list of known markers, or decide whether code is malicious. A finding says "this runs at build time", not "this is malware".
- Cover MSBuild project SDKs, `dotnet tool` packages, `PackageDownload` items when it reads a lock file (an assets file lists them, and customs reads them there), or the content of `contentFiles` source code. These are listed in the design as known gaps.
- Use a reputation service or a hosted database, or change your project.

## Licence

Dual licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your option.
