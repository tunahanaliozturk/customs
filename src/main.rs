//! The `customs` binary. All the work is in the library.

use std::process::ExitCode;

fn main() -> ExitCode {
    customs::run(std::env::args_os().skip(1))
}
