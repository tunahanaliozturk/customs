# 0002: A minimal ECMA-335 metadata reader of its own, not dotscope

Status: accepted, 2026-11-22

## Context

Three assembly checks need .NET metadata: whether `<Module>` has a type initialiser (the module initialiser), which native functions the assembly imports through P/Invoke, and which type and attribute names are present (obfuscator markers). That means the `TypeDef`, `MethodDef`, `TypeRef`, `MemberRef`, `CustomAttribute`, `ModuleRef` and `ImplMap` tables and the string heap. It does not mean IL, signatures or the type system.

Research pointed at `dotscope`. Checked on 2026-11-22:

- Version 0.9.1, 2026-09-05, 19 releases since its start, about 20,000 downloads. Apache-2.0. One person wrote nearly all of it (212 of 218 commits; the rest are Dependabot).
- The crate is 3.5 MB and needs Rust 1.95. Its non-optional dependencies include `memmap2`, `tempfile`, `rayon`, `dashmap`, `crossbeam-skiplist`, `goblin`, `quick-xml`, `flate2`, `lzma-rs`, several block ciphers and `pbkdf2`. Optional ones include `z3`, `iced-x86`, `tokio` and `mistralrs`. It does deobfuscation, emulation and assembly rewriting.
- It has fuzz targets and a single `unsafe` block, reasonable for its purpose.
- Its README adds a "Responsible Use Policy" with a "prohibited use" clause on top of the licence, and GitHub reports its licence as "Other". customs would analyse third-party packages, which is the kind of use that clause talks about.

The alternatives were dotscope, YARA-X's `dotnet` module (see ADR 0003 for why YARA-X is out), or writing the subset by hand.

## Decision

customs reads PE headers through the `object` crate (Apache-2.0 OR MIT, widely used, read-only features) and implements the ECMA-335 metadata subset itself: the metadata root, the stream headers, the `#~` table stream with heap-size flags, row counts and coded indexes for every table, and the string heap. It reads rows only from the tables it needs, but knows the schema of all of them, because row sizes depend on it.

Correctness is checked against `System.Reflection.Metadata`, the reference reader, through a small C# program whose output is committed. The .NET SDK is needed to regenerate that output, not to build or test customs.

## Consequences

- customs keeps a dependency tree that a user can audit in an afternoon, a clear licence and an MSRV of 1.89 instead of 1.95.
- The reader is the part of customs most likely to have bugs, and it parses hostile input. The oracle comparison over every corpus assembly, the known-wrong variants in M3 and the fuzz target in M6 are there because of this decision.
- Every offset, size and index is checked against its slice with checked arithmetic. A malformed assembly is reported as C304, never a panic.
- If customs later needs IL (for example the call targets of a module initialiser), the reader grows a small IL decoder or the question is reopened. dotscope would be the first thing to look at again.
