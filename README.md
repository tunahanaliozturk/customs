# customs

A local command-line tool that shows which NuGet packages in a .NET project run code on the build machine or at load time, and what changed in that respect when a package version is bumped.

It reads the lock file or the assets file that restore already wrote, opens the packages on disk, and reports MSBuild targets that run commands, inline build tasks, analyzers, module initialisers and look-alike package names. It never runs MSBuild and never loads an assembly, so it needs no .NET SDK and no account.

At a border, customs officers open the crates and list what is inside before anything is let through. That is the job.

## Status

Planning. Nothing is built yet: the binary only prints its name and version. The repository holds the design and the roadmap.

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
- Cover MSBuild project SDKs, `PackageDownload`, `dotnet tool` packages, or `contentFiles` source code. These are listed in the design as known gaps.
- Use a reputation service or a hosted database, or change your project.

## Licence

Dual licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your option.
