//! The `extract` command.

use std::borrow::Cow;
use std::io::Write;
use std::path::Path;

use lau_bigfun::{Bigfile, BigfileError, Entry, Fat, HashDictionary, extract_entry};

use super::args::{ExtractArgs, parse_target_hash, warn_if_names_miss_archive};
use super::output::{
    ExtractJsonReport, HexU32, JSON_SCHEMA_VERSION, OutputMode, StatusReporter, StdoutError,
    write_json_stdout,
};

/// A record chosen by index among a hash's records that match `--spec-mask`.
#[derive(Debug)]
pub(super) struct VariantChoice<'a> {
    /// The chosen record.
    pub(super) entry: &'a Entry,
    /// How many of the hash's records match `--spec-mask` (all of them without a mask).
    pub(super) matching: usize,
}

pub(super) fn select_extract_variant(
    all_matches: &[Entry],
    hash: u32,
    spec_mask: Option<u32>,
    variant: Option<usize>,
) -> Result<VariantChoice<'_>, String> {
    let idx = variant.unwrap_or(0);
    let mut chosen = None;
    let mut match_count = 0usize;
    for (i, entry) in Fat::filter_spec_mask(all_matches, spec_mask).enumerate() {
        if i == idx {
            chosen = Some(entry);
        }
        match_count += 1;
    }
    chosen
        .map(|entry| VariantChoice {
            entry,
            matching: match_count,
        })
        .ok_or_else(|| {
            format_variant_selection_error(hash, spec_mask, idx, match_count, all_matches.len())
        })
}

fn format_variant_selection_error(
    hash: u32,
    spec_mask: Option<u32>,
    idx: usize,
    match_count: usize,
    total_variants: usize,
) -> String {
    if let Some(mask) = spec_mask.map(HexU32) {
        if match_count == 0 {
            format!(
                "no variant of {} matches --spec-mask {mask} ({total_variants} total variants exist)",
                HexU32(hash)
            )
        } else {
            format!(
                "--variant {idx} out of range (0..{}) for --spec-mask {mask}",
                match_count.saturating_sub(1)
            )
        }
    } else {
        format!(
            "--variant {idx} out of range (0..{})",
            total_variants.saturating_sub(1)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExtractDestination<'a> {
    /// `-o` / `--output` was omitted.
    ImplicitStdout,
    /// `-o -` / `--output -` was explicitly provided.
    ExplicitStdout,
    /// Target file path on disk (including `./-` if a literal `-` filename is desired).
    File(&'a Path),
}

impl<'a> ExtractDestination<'a> {
    #[inline]
    pub(super) fn from_arg(output: Option<&'a Path>) -> Self {
        match output {
            None => Self::ImplicitStdout,
            Some(path) if path.as_os_str() == "-" => Self::ExplicitStdout,
            Some(path) => Self::File(path),
        }
    }
}

struct ResolvedExtraction<'a> {
    archive: &'a Bigfile,
    entry: &'a Entry,
    hash: u32,
    name: Option<&'a str>,
    variant: usize,
    variant_count: usize,
    /// When neither `--variant` nor `--engine-spec-match` chose a record, how many records
    /// matched `--spec-mask`, the first of which extract took; `None` when the user chose.
    defaulted_among: Option<usize>,
}

impl ResolvedExtraction<'_> {
    /// Says how many variants the hash has and, when several matched and extract took the first,
    /// how to choose another.
    fn variant_status(&self, spec_mask: Option<u32>) -> String {
        let summary = format!(
            "{} variant(s) for {}",
            self.variant_count,
            HexU32(self.hash)
        );
        match (self.defaulted_among, spec_mask) {
            (Some(matching), None) if matching > 1 => format!(
                "{summary}; extracting the first (choose with --variant <N>, or --spec-mask <MASK> --engine-spec-match for the engine's pick)"
            ),
            (Some(matching), Some(mask)) if matching > 1 => format!(
                "{summary}, {matching} matching --spec-mask {}; extracting the first (choose with --variant <N>, or --engine-spec-match for the engine's pick)",
                HexU32(mask)
            ),
            _ => summary,
        }
    }
}

fn format_not_found_error(hash: u32, label: Option<&str>) -> String {
    let label = label.map(|l| format!(" ({l})")).unwrap_or_default();
    format!("not found: {}{label}", HexU32(hash))
}

fn resolve_extract_entry<'a>(
    archive: &'a Bigfile,
    args: &'a ExtractArgs,
    dict: &'a HashDictionary,
) -> Result<ResolvedExtraction<'a>, Box<dyn std::error::Error>> {
    let (hash, label) = parse_target_hash(&args.target)?;
    let all_matches = archive.find(hash);
    if all_matches.is_empty() {
        return Err(format_not_found_error(hash, label).into());
    }
    let (entry, defaulted_among) =
        match args.spec.mask.filter(|_| args.resolution.engine_spec_match) {
            Some(mask) => {
                let entry = archive.find_with_spec_mask(hash, mask).ok_or_else(|| {
                    format_variant_selection_error(hash, Some(mask), 0, 0, all_matches.len())
                })?;
                (entry, None)
            }
            None => {
                let choice =
                    select_extract_variant(all_matches, hash, args.spec.mask, args.variant)?;
                let defaulted = args.variant.is_none().then_some(choice.matching);
                (choice.entry, defaulted)
            }
        };
    Ok(ResolvedExtraction {
        archive,
        entry,
        hash,
        name: label.or_else(|| dict.get(hash)),
        variant: entry.index - all_matches[0].index,
        variant_count: all_matches.len(),
        defaulted_among,
    })
}

/// Streams `entry` to `out`, tagging destination failures as [`StdoutError`].
pub(super) fn stream_entry_to_stdout<W: Write>(
    bf: &Bigfile,
    entry: &Entry,
    raw: bool,
    out: &mut W,
) -> Result<u64, Box<dyn std::error::Error>> {
    let written = bf
        .read_entry_into(entry, raw, &mut Vec::new(), out)
        .map_err(|err| -> Box<dyn std::error::Error> {
            match err {
                BigfileError::Write(source) => StdoutError(source).into(),
                other => other.into(),
            }
        })?;
    out.flush().map_err(StdoutError)?;
    Ok(written)
}

/// Writes the resolved entry's payload to `destination`, reporting where it went on `status`.
fn write_extract_destination<W: Write, E: Write>(
    res: &ResolvedExtraction<'_>,
    destination: ExtractDestination<'_>,
    out: &mut W,
    status: &mut StatusReporter<E>,
    raw: bool,
) -> Result<u64, Box<dyn std::error::Error>> {
    let (bf, entry) = (res.archive, res.entry);
    let (written, place) = match destination {
        ExtractDestination::File(output_path) => (
            extract_entry(bf, entry, raw, output_path)?,
            output_path.to_string_lossy(),
        ),
        ExtractDestination::ImplicitStdout | ExtractDestination::ExplicitStdout => (
            stream_entry_to_stdout(bf, entry, raw, out)?,
            Cow::Borrowed("stdout"),
        ),
    };
    status.println(format_args!(
        "wrote {written} bytes to {place} (record #{}, spec={})",
        entry.index,
        HexU32(entry.spec_flags)
    ));
    Ok(written)
}

fn validate_extract_destination(
    destination: ExtractDestination<'_>,
    stdout_is_tty: bool,
    mode: OutputMode,
) -> Result<(), &'static str> {
    if matches!(mode, OutputMode::Json { .. })
        && !matches!(destination, ExtractDestination::File(_))
    {
        return Err(
            "cannot combine '--json' with stdout extraction; pass '-o <FILE>' to write extracted data to a file",
        );
    }
    if destination == ExtractDestination::ImplicitStdout && stdout_is_tty {
        return Err(
            "refusing to write extracted data to an interactive terminal; pass '-o <FILE>', '-o -' to force stdout, or pipe/redirect output",
        );
    }
    Ok(())
}

pub(super) fn run_extract<W: Write, E: Write>(
    out: &mut W,
    stdout_is_tty: bool,
    status: &mut StatusReporter<E>,
    args: &ExtractArgs,
    mode: OutputMode,
) -> Result<(), Box<dyn std::error::Error>> {
    let destination = ExtractDestination::from_arg(args.output.as_deref());
    validate_extract_destination(destination, stdout_is_tty, mode)?;
    let dict = args.dict.load()?;
    let archive = args.archive.open()?;
    warn_if_names_miss_archive(&dict, &archive, status);
    let res = resolve_extract_entry(&archive, args, &dict)?;
    status.println(format_args!("{}", res.variant_status(args.spec.mask)));
    let bytes_written =
        write_extract_destination(&res, destination, out, status, args.payload.raw)?;
    if let (OutputMode::Json { pretty }, ExtractDestination::File(output_path)) =
        (mode, destination)
    {
        write_extract_report(out, pretty, args, &res, bytes_written, output_path)?;
    }
    Ok(())
}

fn write_extract_report<W: Write>(
    out: &mut W,
    pretty: bool,
    args: &ExtractArgs,
    res: &ResolvedExtraction<'_>,
    bytes_written: u64,
    output_path: &Path,
) -> Result<(), StdoutError> {
    let report = ExtractJsonReport {
        schema: JSON_SCHEMA_VERSION,
        index: res.entry.index,
        name_hash: HexU32(res.entry.name_hash),
        name: res.name,
        spec_flags: HexU32(res.entry.spec_flags),
        spec_mask: args.spec.mask.map(HexU32),
        variant: res.variant,
        variant_count: res.variant_count,
        raw: args.payload.raw,
        bytes_written,
        output: output_path.to_string_lossy(),
    };
    write_json_stdout(out, pretty, &report)
}
