//! Command dispatch for the `lau-bigfun` binary, plus the `unpack` and `hash` commands.

use std::io::Write;

use lau_bigfun::{Bigfile, EntryFilter, UnpackOptions, UnpackReport, name_hash, unpack_archive};

mod args;
mod extract;
mod info;
mod list;
mod output;

#[cfg(test)]
mod tests;

pub(crate) use args::Cli;
use args::{Commands, UnpackArgs, warn_if_names_miss_archive, with_flag_hint};
use extract::run_extract;
use info::run_info;
use list::run_list;
use output::{
    HashEntryRecord, HexU32, JSON_SCHEMA_VERSION, OutputMode, StdoutError, UnpackJsonReport,
    write_entries, write_json_stdout,
};
pub(crate) use output::{StatusReporter, is_stdout_broken_pipe};

/// Default limit on planned `unpack` output, as a multiple of the archive's size on disk.
const DEFAULT_OUTPUT_EXPANSION: u64 = 16;

/// Resolves the output limit: `requested` bytes (`0` = no limit), or by default a multiple of the
/// size of `bigfile` on disk.
fn output_limit(requested: Option<u64>, bigfile: &Bigfile) -> Option<u64> {
    match requested {
        Some(0) => None,
        Some(limit) => Some(limit),
        None => {
            let on_disk = bigfile
                .part_sizes()
                .iter()
                .fold(0u64, |total, &size| total.saturating_add(size));
            Some(on_disk.saturating_mul(DEFAULT_OUTPUT_EXPANSION))
        }
    }
}

fn run_unpack<W: Write, E: Write>(
    out: &mut W,
    status: &mut StatusReporter<E>,
    args: &UnpackArgs,
    mode: OutputMode,
) -> Result<(), Box<dyn std::error::Error>> {
    let filter = args.filter.compile()?;
    let bigfile = args.archive.open()?;
    let dict = args.dict.load_for_filter(filter.as_ref(), status)?;
    warn_if_names_miss_archive(&dict, &bigfile, status);
    let options = unpack_options(args, filter, &bigfile);
    let report = unpack_archive(&bigfile, &dict, &args.output, &options).map_err(with_flag_hint)?;
    // A real unpack already failed on this limit; a dry run reports the plan and warns instead.
    if args.dry_run
        && let Err(over_limit) = options.check_output_limit(report.extracted_bytes)
    {
        status.println(format_args!("warning: {}", with_flag_hint(over_limit)));
    }
    // A text dry run's summary is its result, so it goes to stdout; otherwise it is status.
    let summary = unpack_summary(args, &report);
    if args.dry_run && mode == OutputMode::Text {
        writeln!(out, "{summary}").map_err(StdoutError)?;
        out.flush().map_err(StdoutError)?;
    } else {
        status.println(format_args!("{summary}"));
    }
    if let OutputMode::Json { pretty } = mode {
        write_unpack_report(out, pretty, args, &report)?;
    }
    Ok(())
}

/// Builds the library's [`UnpackOptions`] from the `unpack` arguments.
fn unpack_options(
    args: &UnpackArgs,
    filter: Option<EntryFilter>,
    bigfile: &Bigfile,
) -> UnpackOptions {
    UnpackOptions {
        spec_mask: args.spec.mask,
        single_match_per_hash: args.resolution.engine_spec_match,
        variant_layout: args.variant_layout.into(),
        raw: args.payload.raw,
        filter,
        jobs: args.jobs,
        max_output_bytes: output_limit(args.max_output_bytes, bigfile),
        dry_run: args.dry_run,
    }
}

/// The summary of an `unpack`: what it wrote, or on a dry run, what it would write.
fn unpack_summary(args: &UnpackArgs, report: &UnpackReport) -> String {
    let unpacked = if args.dry_run {
        "Would unpack"
    } else {
        "Unpacked"
    };
    format!(
        "{unpacked} {} file(s) ({} bytes) to {} [resolved={}, unknown={}, skipped={}]",
        report.extracted_files,
        report.extracted_bytes,
        args.output.display(),
        report.resolved_entries,
        report.unknown_entries,
        report.skipped_entries
    )
}

fn write_unpack_report<W: Write>(
    out: &mut W,
    pretty: bool,
    args: &UnpackArgs,
    report: &UnpackReport,
) -> Result<(), StdoutError> {
    let json = UnpackJsonReport {
        schema: JSON_SCHEMA_VERSION,
        dry_run: args.dry_run,
        output: args.output.to_string_lossy(),
        extracted_files: report.extracted_files,
        extracted_bytes: report.extracted_bytes,
        resolved_entries: report.resolved_entries,
        unknown_entries: report.unknown_entries,
        skipped_entries: report.skipped_entries,
    };
    write_json_stdout(out, pretty, &json)
}

fn run_hash<W: Write>(
    out: &mut W,
    filenames: &[String],
    mode: OutputMode,
) -> Result<(), Box<dyn std::error::Error>> {
    // Hash every name before writing any, so a name that cannot be hashed fails the command
    // before a line is printed.
    let records: Vec<HashEntryRecord<'_>> = filenames
        .iter()
        .map(|name| {
            name_hash(name).map(|h| HashEntryRecord {
                name,
                name_hash: HexU32(h),
            })
        })
        .collect::<Result<_, _>>()?;
    let records = records.into_iter().map(Ok::<_, std::convert::Infallible>);
    write_entries(out, mode, None, records, |out, rec| {
        writeln!(out, "{}  {}", rec.name_hash, rec.name)
    })
}

pub(crate) fn execute_cli<W: Write, E: Write>(
    cli: Cli,
    out: &mut W,
    stdout_is_tty: bool,
    status: &mut StatusReporter<E>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mode = if cli.json {
        OutputMode::Json {
            pretty: stdout_is_tty,
        }
    } else {
        OutputMode::Text
    };
    match &cli.command {
        Commands::Info(args) => run_info(out, args, mode),
        Commands::List(args) => run_list(out, status, args, mode),
        Commands::Extract(args) => run_extract(out, stdout_is_tty, status, args, mode),
        Commands::Unpack(args) => run_unpack(out, status, args, mode),
        Commands::Hash(args) => run_hash(out, &args.filenames, mode),
    }
}
