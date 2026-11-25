# 0006: Refuse metadata that readers could read differently

Status: accepted, 2026-11-25

## Context

customs reads assembly metadata with a reader of its own (ADR 0002). What the runtime does with an assembly depends on how the runtime's reader reads it, so a difference between the two readers is a way past customs: an attacker builds metadata that customs reads one way and the runtime another, and the module initialiser that runs is not the one customs looked at.

ECMA-335 and its readers leave room for that. Checked against `System.Reflection.Metadata` (the reader in the .NET libraries, `MetadataReader` and `MetadataReader.ReadMetadataTableHeader`, read on 2026-11-25) and the format itself:

- **Two streams of one name.** Nothing in the standard says which one counts. `System.Reflection.Metadata` keeps the last one it sees; another reader may keep the first.
- **The uncompressed table stream, `#-`.** It allows the pointer tables (`FieldPtr`, `MethodPtr` and the others), through which a type's method list points at `MethodPtr` rows instead of `MethodDef` rows. A reader that ignores the indirection finds different methods in `<Module>`.
- **Pointer and edit-and-continue tables in a `#~` stream.** `System.Reflection.Metadata` refuses the pointer tables and `EncMap` there and accepts `EncLog`, which it then treats as empty.
- **The edit-and-continue delta flag (0x20 in the heap sizes).** In `System.Reflection.Metadata` it makes every table index four bytes wide whatever the row counts say, so every row after it moves.
- **Table bits above 0x2C.** Unknown tables, or the portable PDB tables, which never belong in an assembly.
- **A P/Invoke with an empty import name.** II.22.22 requires `ImportName` to index a non-empty string. `System.Reflection.Metadata` returns the empty name without complaint, and what the runtime then binds to is not something customs can match against its list.
- **A section table that maps an address two ways.** `System.Reflection.Metadata` (`PEHeaders.GetContainingSectionIndex`, read 2026-11-25) takes the first section in table order whose virtual range, `VirtualAddress` to `VirtualAddress + VirtualSize`, holds the address; it checks neither the order of the sections nor overlaps, and it throws when the raw data of the metadata or of a section it reads lies outside the file (`InvalidMetadataSectionSpan`, `ImageTooSmallOrContainsInvalidOffsetOrCount`). `object`'s `pe_data_at` takes the first section whose raw bytes hold the address and silently skips one whose raw data is outside the file, going on to the next. Overlapping sections, sections out of ascending address order, and a section whose raw data lies outside the file are where the two can pick different bytes.
- **The "extra data" flag (0x40).** Four bytes after the row counts. The standard does not have it; the runtime's native reader and `System.Reflection.Metadata` both skip the four bytes, and obfuscators set it so that tools that follow the standard misread every table.

Two ways to deal with these:

1. Implement each one as `System.Reflection.Metadata` does, and hope the runtime does the same.
2. Read the one that every reader agrees on (the extra data, which both skip) and refuse the others.

The archive layout of M1 faced the same choice for end-of-central-directory records and took the second way, after a review showed what the first costs.

## Decision

Option 2. customs skips the extra data, as both readers do, and refuses everything else in the list above. A refused assembly is C304 ("not a readable managed assembly", with the reason as evidence), a warning, and an error in an analyzer or a build-time assembly. A table with more than 16,777,215 rows, which no token can address, is a C002 gap. The rest of the format is read as written: the heap size flags, the row counts, and the width of every index and coded index computed from them.

## Consequences

- An assembly built to be read differently is reported, never read silently in one of its possible ways. An attacker who moves a module initialiser behind `MethodPtr` gets C304 instead of C301, which has the same severity in a library and in build-time code.
- The reader stays small: no pointer tables, no delta handling.
- A legitimate assembly that uses `#-` would be C304. None of the 2,762 `.dll` and `.exe` entries of the benign corpus does, and none of the assemblies in a local cache of 4,422 package versions did on 2026-11-25: the only C304 findings there were native `msdia140.dll` files in `lib/`.
- If such assemblies turn up in real packages, reading `#-` with its pointer tables is the change to make, with a fixture compiled to use it and the oracle to check it.
