# 0005: Read the extracted global packages folder when it exists, the archive otherwise

Status: accepted, 2026-11-22

## Context

After restore, each package exists twice on disk, in the global packages folder: the original `.nupkg`, and the files NuGet extracted from it. Checked on 2026-11-22 in a real cache: `~/.nuget/packages/newtonsoft.json/13.0.3/` holds `newtonsoft.json.13.0.3.nupkg`, `newtonsoft.json.13.0.3.nupkg.sha512`, `.nupkg.metadata`, the `.nuspec` and the extracted folders.

The project file suggested inspecting packages. The question was which copy:

1. Always the `.nupkg`, so that one reader serves the cache, a single package and downloads.
2. The extracted files when they exist, the `.nupkg` when they do not.

MSBuild imports the extracted files, and the compiler loads the extracted analyzers. If the archive and the extracted files differ, the extracted ones are what runs. They can differ because the zip reader in customs and the one in .NET disagree on a malformed archive, or because something changed the cache after restore. Reading the archive in both cases would report on content that does not run.

## Decision

Option 2. When a package is found in a package folder, customs reads the extracted files through `folder`, without following symbolic links or junctions. It reads the `.nupkg` through `archive` only for a `.nupkg` given on the command line and for downloads in `diff`. Both give the detectors the same view, a list of entries and a capped read.

`--verify-cache` adds the comparison: the cached `.nupkg` against the graph's content hash, and its entries against the extracted files.

## Consequences

- Findings describe what MSBuild and the compiler will actually use on this machine.
- Two readers have to agree on classification and paths. Both feed the same `inventory` and the same detectors, and the fixture tests run every package through both.
- A tampered cache is reported as tampered content rather than missed, and with `--verify-cache` as a mismatch.
- In `diff`, a version that is not in the cache is read from the archive, so an archive that .NET would extract differently can still mislead. M6 builds malformed archives to find where the two readers disagree, and customs reports such archives as C003.
- Scans of a large cache read many small files instead of a few archives. That is slower on Windows. It is measured in M7, not assumed.
