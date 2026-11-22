# 0001: Read the resolved graph and the package files; never evaluate or load

Status: accepted, 2026-11-22

## Context

To say what a package runs at build time, customs has to know which packages are in the build and what their files contain. There were three ways to find out:

1. Run MSBuild: evaluate the project with the .NET SDK, list the imported files, the tasks and the analyzers the build would use.
2. Load the assemblies through .NET reflection or a .NET helper process to inspect them.
3. Read the graph that restore already resolved (`packages.lock.json` or `obj/project.assets.json`) and inspect the package files as data.

Options 1 and 2 give a more exact answer: the real values of properties and conditions, only the imports that apply to this target framework. But evaluating MSBuild runs property functions from the very files under suspicion, and loading an assembly can run its module initialiser. Both need the .NET SDK on the machine that runs customs, and both make customs a .NET tool with a Rust front.

## Decision

Option 3. customs never evaluates MSBuild, never loads an assembly and never runs anything from a package. It reads the lock or assets file for the graph, and reads package files with its own parsers under fixed limits.

## Consequences

- customs runs without the .NET SDK, on any machine, including one that has never restored the project, as long as the packages are available as files.
- Scanning the attacker's input is safe by construction: the worst a package can do is make a parser fail, which the limits and the fuzzing milestone address.
- customs cannot know what a property expands to or which condition is true. It reports every construct as written, also those that would not run on this machine. That costs false positives, which the benign corpus and the baseline handle, and it misses constructs hidden behind property values. Both are listed in the design under "What it cannot see".
- It needs a restore to have happened, or a lock file plus downloads in `diff`. A project without either cannot be scanned. That is acceptable: CI restores before it builds, and the lock file is the thing Dependabot and Renovate change.
- Packages that do not appear in the graph files, such as MSBuild project SDKs, are out of reach until a separate reader for them is written.
