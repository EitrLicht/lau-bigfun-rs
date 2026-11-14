//! CLI entry point for `lau-bigfun` (Tomb Raider LAU Bigfile Unpacker).

use std::io::{self, BufWriter, IsTerminal, Write};
use std::process::ExitCode;

use clap::Parser;

mod cli;

use cli::{Cli, StatusReporter, execute_cli, is_stdout_broken_pipe};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let stdout = io::stdout().lock();
    let stdout_is_tty = stdout.is_terminal();
    let mut out = BufWriter::new(stdout);
    let mut status = StatusReporter::new(io::stderr(), cli.quiet);
    execute_cli(cli, &mut out, stdout_is_tty, &mut status)
}

fn main() -> ExitCode {
    if let Err(err) = run() {
        if is_stdout_broken_pipe(err.as_ref()) {
            return ExitCode::SUCCESS;
        }
        let _ = writeln!(io::stderr(), "error: {err}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
use lau_bigfun::{archive, fat, format};

#[cfg(test)]
mod test_support;
