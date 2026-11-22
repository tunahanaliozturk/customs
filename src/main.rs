//! customs: shows what the `NuGet` packages in a `.NET` project run at build
//! time and at load time.
//!
//! Nothing is implemented yet, so the binary only prints its name and version.
//! The design is in `docs/design.md` and the milestones are in `docs/roadmap.md`.

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut out = std::io::stdout().lock();
    match writeln!(
        out,
        "{} {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
