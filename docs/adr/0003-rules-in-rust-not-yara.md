# 0003: Rules as Rust code with small data files, not YARA-X or a rule language

Status: accepted, 2026-11-22

## Context

The first release has about twenty rules, each tied to a structure: an XML element in an MSBuild file, a row in a metadata table, the shape of a package ID. The question was how to express them:

1. YARA rules run by YARA-X, the Rust rewrite of YARA from VirusTotal.
2. A small declarative format of its own, for example TOML entries with an element name and an attribute pattern.
3. Rust code, one function per rule, with lists of names kept in plain data files.

YARA-X, checked on 2026-11-22: version 1.24.0 of 2026-11-20, BSD-3-Clause, actively released, and it has a `dotnet` module. But it compiles rules to WebAssembly and runs them under wasmtime, which is a non-optional dependency of the library and a large tree to build and audit. YARA matches bytes and fields of parsed formats; it does not understand that an `Exec` element sits inside a `Target` inside a file that an entry-point file imports, and it cannot resolve imports between files. ReversingLabs also noted in 2024 that classic YARA rules skip the `<Module>` type, which is where the module initialiser lives.

A format of its own would need its own parser, its own validation and its own documentation before it did anything a function cannot.

## Decision

Option 3. Each rule is a Rust function over a parsed value (an XML document, a metadata view, an ID) that returns findings. The rule table, with ID, default severity and description, is one Rust array that drives `customs rules`, the SARIF rule list and the docs check. Lists that change more often than logic live in data files embedded at compile time: `data/popular-ids.txt`, `data/pinvoke.txt`, `data/obfuscators.txt`, each with a header that says where the entries came from and when.

## Consequences

- Rules can use structure: the XML tree, import reachability, metadata rows. Each rule is unit tested like any other function.
- No user-written rules in the first release. A team that wants its own rule writes code or opens an issue. If demand for user rules appears, a declarative format or YARA-X can be added for byte-level checks later without replacing the built-in rules.
- No wasmtime, no rule compiler, no second language in the repository.
- Changing a list needs a new release. The lists are small and dated, which is acceptable for a tool that ships often.
