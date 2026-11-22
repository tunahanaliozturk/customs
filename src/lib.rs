//! customs: shows what the `NuGet` packages in a .NET project run at build
//! time and at load time.
//!
//! It reads the graph that `NuGet` restore resolved (`packages.lock.json` or
//! `obj/project.assets.json`) and inspects the files of each package as data.
//! It never evaluates `MSBuild` and never loads an assembly. The design is in
//! `docs/design.md` and the milestones are in `docs/roadmap.md`.
//!
//! The library has one entry point, [`run`], which the binary calls.

mod archive;
mod cli;
mod folder;
mod graph;
mod inventory;
mod locate;
mod msbuild;
mod package;
mod report;
mod scan;

pub use cli::run;
