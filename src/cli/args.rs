//! Command-line argument definitions and value parsers.

use std::io::Write;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use lau_bigfun::{
    Bigfile, BigfileError, Endian, EntryFilter, FilterError, HashDictionary, OpenOptions,
    VariantLayout, name_hash,
};

use super::output::StatusReporter;

#[derive(Parser, Debug)]
#[command(
    name = "lau-bigfun",
    version,
    about = "Tomb Raider LAU (Legend, Anniversary, Underworld) bigfile archive inspector and unpacker"
)]
pub(crate) struct Cli {
    /// Suppress non-error status messages on stderr
    #[arg(short, long, global = true)]
    pub(crate) quiet: bool,

    /// Emit structured JSON output to stdout
    #[arg(long, global = true)]
    pub(crate) json: bool,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum CliVariantLayout {
    /// Put unique hashes at `<out>/<path>` and multi-variant hashes under `<out>/spec_<hex>/<path>`
    SpecDir,
    /// Always put every entry under `<out>/spec_<hex>/<path>`
    AlwaysSpecDir,
    /// Keep flat paths and append `.spec_<hex>` before the file extension when ambiguous
    Suffix,
}

impl From<CliVariantLayout> for VariantLayout {
    fn from(value: CliVariantLayout) -> Self {
        match value {
            CliVariantLayout::SpecDir => VariantLayout::SpecSubdirWhenAmbiguous,
            CliVariantLayout::AlwaysSpecDir => VariantLayout::AlwaysSpecSubdir,
            CliVariantLayout::Suffix => VariantLayout::FilenameSuffix,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum CliEndian {
    /// Automatically detect byte order from FAT and volume geometry
    #[default]
    Auto,
    /// Little-endian (PC, PS2, PSP, Xbox)
    #[value(alias = "le")]
    Little,
    /// Big-endian (PlayStation 3, Xbox 360, Wii / GameCube)
    #[value(alias = "be")]
    Big,
}

impl From<CliEndian> for Option<Endian> {
    fn from(value: CliEndian) -> Self {
        match value {
            CliEndian::Auto => None,
            CliEndian::Little => Some(Endian::Little),
            CliEndian::Big => Some(Endian::Big),
        }
    }
}

#[derive(Subcommand, Debug)]
pub(crate) enum Commands {
    /// Display archive metadata, part geometry, hash dictionary coverage, and specialisation flag
    /// breakdown
    Info(InfoArgs),

    /// List entries in the bigfile Table of Contents (FAT)
    List(ListArgs),

    /// Extract a single file by asset path (e.g. `pc-w\lara.drm`) or hex hash (e.g. `0x5ff91900`)
    Extract(ExtractArgs),

    /// Unpack all (or filtered) archive entries to an output directory
    Unpack(UnpackArgs),

    /// Compute the 32-bit `CRC-32/BZIP2` path hash for one or more filenames
    Hash(HashArgs),
}

/// Shared CLI arguments for locating and opening a bigfile archive.
#[derive(Args, Debug, Clone)]
pub(crate) struct ArchiveArgs {
    /// Path to the archive directory, its `.000` / `.dat` file, or a file of any other name, which
    /// opens as one archive (as any file does with `--single-part`)
    pub(crate) archive: PathBuf,

    /// Override the virtual volume segment stride in bytes (hex or decimal, e.g. 0x7ff00000)
    #[arg(long, value_parser = parse_uint_auto::<u64>)]
    pub(crate) segment_length: Option<u64>,

    /// Open exactly this file as one archive, without gathering numbered `.000`, `.001`, ...
    /// parts or resolving `.dat` names (for games whose numbered files are separate archives)
    #[arg(long, conflicts_with = "segment_length")]
    pub(crate) single_part: bool,

    /// TOC byte order (`auto`, `little`/`le`, or `big`/`be`)
    #[arg(long, value_enum, default_value_t = CliEndian::Auto)]
    pub(crate) endian: CliEndian,
}

impl ArchiveArgs {
    /// Opens the archive, naming the flag that settles an ambiguous byte order.
    pub(crate) fn open(&self) -> Result<Bigfile, Box<dyn std::error::Error>> {
        let options = OpenOptions {
            segment_length: self.segment_length,
            endian: self.endian.into(),
            single_part: self.single_part,
        };
        Bigfile::open_with_options(&self.archive, options).map_err(with_flag_hint)
    }
}

/// Converts `err` for display, naming the flag that resolves it when one does.
pub(crate) fn with_flag_hint(err: BigfileError) -> Box<dyn std::error::Error> {
    let hint = match err {
        BigfileError::AmbiguousEndian => " with --endian little or --endian big",
        BigfileError::UndeterminedSegmentLength { .. } => {
            "; give it with --segment-length, or, if each numbered file is a separate archive, pass that file with --single-part"
        }
        BigfileError::OutputLimitExceeded { .. } => {
            "; raise it with --max-output-bytes, or pass 0 for no limit"
        }
        other => return other.into(),
    };
    format!("{err}{hint}").into()
}

/// Shared CLI argument for filtering entries by specialisation flags.
#[derive(Args, Debug, Clone, Copy, Default)]
pub(crate) struct SpecMaskArgs {
    /// Filter entries by spec mask `(entry.spec_flags & mask) == mask` (hex or decimal, e.g. 0x1)
    #[arg(id = "spec_mask", long = "spec-mask", value_name = "SPEC_MASK", value_parser = parse_uint_auto::<u32>)]
    pub(crate) mask: Option<u32>,
}

/// Shared CLI arguments for choosing records the way the game engine does.
#[derive(Args, Debug, Clone, Copy, Default)]
pub(crate) struct ResolutionArgs {
    /// For each name, select only the record the game engine's lookup order picks among those
    /// matching `--spec-mask` within this archive (requires `--spec-mask`)
    #[arg(long, requires = "spec_mask")]
    pub(crate) engine_spec_match: bool,
}

/// Shared CLI argument for writing stored bytes as they are.
#[derive(Args, Debug, Clone, Copy, Default)]
pub(crate) struct RawArgs {
    /// Write raw on-disk bytes without inflating zlib-compressed entries
    #[arg(long)]
    pub(crate) raw: bool,
}

/// Shared CLI arguments for loading hash dictionaries.
#[derive(Args, Debug, Clone, Default)]
pub(crate) struct DictionaryArgs {
    /// Filename list(s) to load (repeatable; later lists override earlier ones)
    #[arg(long = "filelist")]
    pub(crate) filelists: Vec<PathBuf>,
}

impl DictionaryArgs {
    pub(crate) fn load(&self) -> Result<HashDictionary, Box<dyn std::error::Error>> {
        let mut dict = HashDictionary::new();
        for path in &self.filelists {
            dict.load_file(path)?;
        }
        Ok(dict)
    }

    /// Loads names for a command that filters entries. Without names, a filter that can only
    /// match paths is an error, and any other run warns that entries will be unnamed.
    pub(crate) fn load_for_filter<E: Write>(
        &self,
        filter: Option<&EntryFilter>,
        status: &mut StatusReporter<E>,
    ) -> Result<HashDictionary, Box<dyn std::error::Error>> {
        let dict = self.load()?;
        if dict.is_empty() {
            if filter.is_some_and(EntryFilter::needs_names) {
                return Err(
                    "no filenames loaded, so this filter can only match hashes; pass --filelist <FILE> or filter on a hash such as 0x5ff91900"
                        .into(),
                );
            }
            let reason = if self.filelists.is_empty() {
                "no filelist given; pass --filelist <FILE>"
            } else {
                "--filelist supplied no paths"
            };
            status.println(format_args!("warning: entries will be unnamed: {reason}"));
        }
        Ok(dict)
    }
}

/// How many of an archive's unique name hashes a dictionary names.
pub(crate) struct NameCoverage {
    /// Unique name hashes in the archive.
    pub(crate) unique: usize,
    /// Those of them the dictionary names.
    pub(crate) resolved: usize,
}

/// Counts `bigfile`'s unique name hashes and how many of them `dict` names.
pub(crate) fn name_coverage(dict: &HashDictionary, bigfile: &Bigfile) -> NameCoverage {
    let mut coverage = NameCoverage {
        unique: 0,
        resolved: 0,
    };
    for run in bigfile.hash_runs() {
        coverage.unique += 1;
        coverage.resolved += usize::from(dict.get(run[0].name_hash).is_some());
    }
    coverage
}

/// Warns on `status` when `dict` holds names but none of them names a hash in `bigfile`, which
/// usually means the filelists are for a different game or release.
pub(crate) fn warn_if_names_miss_archive<E: Write>(
    dict: &HashDictionary,
    bigfile: &Bigfile,
    status: &mut StatusReporter<E>,
) {
    if dict.is_empty() {
        return;
    }
    let NameCoverage { unique, resolved } = name_coverage(dict, bigfile);
    if resolved == 0 && unique > 0 {
        let hashes = if unique == 1 { "hash" } else { "hashes" };
        status.println(format_args!(
            "warning: --filelist names none of the archive's {unique} unique {hashes}; it may be for a different game or release"
        ));
    }
}

/// Shared CLI arguments for filtering archive entries by substring, glob pattern, or resolution status.
#[derive(Args, Debug, Clone, Default)]
pub(crate) struct FilterArgs {
    /// Case-insensitive substring filter on resolved filename or hex hash
    #[arg(short, long, conflicts_with_all = ["globs", "unresolved"])]
    pub(crate) filter: Option<String>,

    /// Case-insensitive glob filter on resolved path or hex hash (repeatable, e.g. `pc-w/*.drm`, `**/vo/lara/*.mul`)
    #[arg(
        short = 'g',
        long = "glob",
        value_name = "PATTERN",
        conflicts_with = "unresolved"
    )]
    pub(crate) globs: Vec<String>,

    /// Select only entries whose name hash is not resolved by the filelist
    #[arg(long)]
    pub(crate) unresolved: bool,
}

impl FilterArgs {
    pub(crate) fn compile(&self) -> Result<Option<EntryFilter>, FilterError> {
        if self.unresolved {
            Ok(Some(EntryFilter::unresolved()))
        } else if let Some(sub) = &self.filter {
            Ok(Some(EntryFilter::substring(sub)))
        } else if !self.globs.is_empty() {
            EntryFilter::from_globs(&self.globs).map(Some)
        } else {
            Ok(None)
        }
    }
}

#[derive(Args, Debug)]
pub(crate) struct InfoArgs {
    #[command(flatten)]
    pub(crate) archive: ArchiveArgs,

    #[command(flatten)]
    pub(crate) dict: DictionaryArgs,
}

#[derive(Args, Debug)]
pub(crate) struct ListArgs {
    #[command(flatten)]
    pub(crate) archive: ArchiveArgs,

    #[command(flatten)]
    pub(crate) spec: SpecMaskArgs,

    #[command(flatten)]
    pub(crate) filter: FilterArgs,

    /// Maximum number of entries to print (0 = unlimited); a note on stderr reports how many
    /// matched when the limit hides some
    #[arg(short, long, default_value_t = 50)]
    pub(crate) limit: usize,

    #[command(flatten)]
    pub(crate) dict: DictionaryArgs,
}

#[derive(Args, Debug)]
pub(crate) struct ExtractArgs {
    #[command(flatten)]
    pub(crate) archive: ArchiveArgs,

    /// Target asset path (e.g. `pc-w\lara.drm`) or 32-bit hex hash (`0x5ff91900`)
    pub(crate) target: String,

    /// Output file path (omit when piping/redirecting, or pass `-` to force stdout)
    #[arg(short, long)]
    pub(crate) output: Option<PathBuf>,

    /// Select variant by index (0..N-1) among matching entries (filtered by `--spec-mask` when set)
    #[arg(long, conflicts_with = "engine_spec_match")]
    pub(crate) variant: Option<usize>,

    #[command(flatten)]
    pub(crate) spec: SpecMaskArgs,

    #[command(flatten)]
    pub(crate) resolution: ResolutionArgs,

    #[command(flatten)]
    pub(crate) payload: RawArgs,

    #[command(flatten)]
    pub(crate) dict: DictionaryArgs,
}

#[derive(Args, Debug)]
pub(crate) struct UnpackArgs {
    #[command(flatten)]
    pub(crate) archive: ArchiveArgs,

    /// Destination directory for extracted files
    #[arg(short, long)]
    pub(crate) output: PathBuf,

    #[command(flatten)]
    pub(crate) spec: SpecMaskArgs,

    #[command(flatten)]
    pub(crate) resolution: ResolutionArgs,

    /// How to disambiguate multiple specialisation variants that share the same filename hash
    #[arg(long, value_enum, default_value_t = CliVariantLayout::SpecDir)]
    pub(crate) variant_layout: CliVariantLayout,

    #[command(flatten)]
    pub(crate) filter: FilterArgs,

    #[command(flatten)]
    pub(crate) dict: DictionaryArgs,

    #[command(flatten)]
    pub(crate) payload: RawArgs,

    /// Number of parallel worker threads (0 = auto-detect CPU cores, 1 = sequential)
    #[arg(short, long, default_value_t = 0)]
    pub(crate) jobs: usize,

    /// Refuse to start if the planned output exceeds this many bytes (hex or decimal; 0 = no
    /// limit; default: 16 times the size of the archive on disk)
    #[arg(long, value_name = "BYTES", value_parser = parse_uint_auto::<u64>)]
    pub(crate) max_output_bytes: Option<u64>,

    /// Report the files and bytes the unpack would write, without writing anything or checking the
    /// destination
    #[arg(long)]
    pub(crate) dry_run: bool,
}

#[derive(Args, Debug)]
pub(crate) struct HashArgs {
    /// One or more asset paths to hash (e.g. `pc-w\lara.drm`)
    #[arg(required = true)]
    pub(crate) filenames: Vec<String>,
}

#[inline]
pub(crate) fn strip_hex_prefix(s: &str) -> Option<&str> {
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
}

pub(crate) fn parse_uint_auto<T: TryFrom<u64>>(s: &str) -> Result<T, String> {
    let ty = std::any::type_name::<T>();
    let trimmed = s.trim();
    let val = match strip_hex_prefix(trimmed) {
        Some(hex) => {
            u64::from_str_radix(hex, 16).map_err(|e| format!("invalid hex {ty} '{s}': {e}"))
        }
        None => trimmed
            .parse::<u64>()
            .map_err(|e| format!("invalid {ty} '{s}': {e}")),
    }?;
    T::try_from(val).map_err(|_| format!("{ty} '{s}' out of range"))
}

pub(crate) fn parse_target_hash(target: &str) -> Result<(u32, Option<&str>), String> {
    let trimmed = target.trim();
    if let Some(hex) = strip_hex_prefix(trimmed)
        && !hex.is_empty()
        && hex.len() <= 8
        && hex.chars().all(|c| c.is_ascii_hexdigit())
    {
        let h = u32::from_str_radix(hex, 16).map_err(|e| e.to_string())?;
        return Ok((h, None));
    }
    let h = name_hash(trimmed).map_err(|e| e.to_string())?;
    Ok((h, Some(trimmed)))
}
