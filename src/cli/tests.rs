//! Unit tests for the CLI commands, split by command.

use std::fs;
use std::io::{self, BufWriter};
use std::path::{Path, PathBuf};

use clap::Parser;

use lau_bigfun::{Bigfile, Endian, VariantLayout, name_hash};

use super::args::*;
use super::extract::{
    ExtractDestination, run_extract, select_extract_variant, stream_entry_to_stdout,
};
use super::output::*;
use super::{execute_cli, output_limit, run_hash};
use crate::test_support::{
    ArchiveRecord, FailingWriter, TempDir, build_ambiguous_part0, sample_entry, write_archive,
    write_one_record_archives, write_shared_sector_archive,
};

mod args;
mod extract;
mod hash;
mod info;
mod list;
mod output;
mod unpack;

/// Payload of the synthetic archive's single `pc-w\lara.drm` record.
const SYNTHETIC_PAYLOAD: &[u8] = b"synthetic lara payload";

/// Writes the synthetic archive to `path` in `endian` byte order: one `pc-w\lara.drm` record for
/// SKU `0x1` holding [`SYNTHETIC_PAYLOAD`].
fn write_synthetic_archive(path: &Path, endian: Endian) {
    let hash = name_hash(r"pc-w\lara.drm").unwrap();
    let record = ArchiveRecord::stored(hash, 0x0000_0001, SYNTHETIC_PAYLOAD);
    write_archive(path, endian, &[record]);
}

/// Writes the little-endian synthetic archive as `bigfile.000` in a new temporary directory.
fn create_synthetic_archive(prefix: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new(prefix);
    let archive_path = dir.join("bigfile.000");
    write_synthetic_archive(&archive_path, Endian::Little);
    (dir, archive_path)
}

/// Writes a filelist naming the synthetic archive's `pc-w\lara.drm` entry.
fn write_filelist(dir: &TempDir) -> PathBuf {
    let path = dir.join("filelist.txt");
    fs::write(&path, "pc-w\\lara.drm\n").unwrap();
    path
}

/// Writes a filelist whose only path names no record of the synthetic archive.
fn write_unrelated_filelist(dir: &TempDir) -> PathBuf {
    let path = dir.join("unrelated.txt");
    fs::write(&path, "pc-w\\other.drm\n").unwrap();
    path
}

/// The warning for filelists that name none of the archive's hashes, for the synthetic archive.
const NAMES_MISS_WARNING: &str = "warning: --filelist names none of the archive's 1 unique hash; it may be for a different game or release";

/// Parses `args` as the command line after the program name.
fn parse_args(args: &[&str]) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(std::iter::once("lau-bigfun").chain(args.iter().copied()))
}

/// Parses `args`, given without the program name, as an `extract` command line, for tests that
/// call [`run_extract`] with their own writers.
fn parse_extract_args(args: &[&str]) -> ExtractArgs {
    match parse_args(args).unwrap().command {
        Commands::Extract(extract) => extract,
        _ => panic!("not an extract command line: {args:?}"),
    }
}

/// Runs the CLI on `args`, given without the program name, returning stdout and status text.
fn exec_args(args: &[&str], stdout_is_tty: bool) -> Result<(Vec<u8>, String), String> {
    let cli = parse_args(args).unwrap();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut status = StatusReporter::new(&mut err, cli.quiet);
    execute_cli(cli, &mut out, stdout_is_tty, &mut status)
        .map(|()| (out, String::from_utf8(err).unwrap()))
        .map_err(|e| e.to_string())
}
