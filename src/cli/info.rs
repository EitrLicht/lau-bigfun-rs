//! The `info` command.

use std::collections::BTreeMap;
use std::io::Write;

use lau_bigfun::{Bigfile, HashDictionary};

use super::args::{InfoArgs, name_coverage};
use super::output::{
    HexU32, InfoJsonReport, JSON_SCHEMA_VERSION, OutputMode, PartJson, SkuCountJson, StdoutError,
    write_json_stdout,
};

struct ArchiveStats {
    unique_hashes: usize,
    resolved_hashes: usize,
    compressed_count: usize,
    total_logical_bytes: u64,
    total_stored_bytes: u64,
    sku_counts: BTreeMap<u32, usize>,
}

impl ArchiveStats {
    #[must_use]
    #[inline]
    fn resolved_percentage(&self) -> f64 {
        if self.unique_hashes == 0 {
            100.0
        } else {
            (self.resolved_hashes as f64) * 100.0 / (self.unique_hashes as f64)
        }
    }
}

fn compute_archive_stats(bf: &Bigfile, dict: &HashDictionary) -> ArchiveStats {
    let coverage = name_coverage(dict, bf);
    let mut sku_counts: BTreeMap<u32, usize> = BTreeMap::new();
    let mut compressed_count = 0usize;
    let mut total_logical_bytes = 0u64;
    let mut total_stored_bytes = 0u64;

    for e in bf.entries() {
        *sku_counts.entry(e.sku_flags).or_insert(0) += 1;
        if e.is_compressed() {
            compressed_count += 1;
        }
        total_logical_bytes += e.size as u64;
        total_stored_bytes += e.stored_size() as u64;
    }

    ArchiveStats {
        unique_hashes: coverage.unique,
        resolved_hashes: coverage.resolved,
        compressed_count,
        total_logical_bytes,
        total_stored_bytes,
        sku_counts,
    }
}

fn write_info_parts_section<W: Write>(out: &mut W, bf: &Bigfile) -> Result<(), StdoutError> {
    writeln!(
        out,
        "Archive:              {} (stem: {})",
        bf.dir_path().display(),
        bf.stem()
    )?;
    writeln!(out, "Endianness:           {}", bf.endian())?;
    match bf.segment_length() {
        Some(len) => writeln!(
            out,
            "Segment length:       {len:#010x} ({} MiB)",
            len / (1 << 20)
        )?,
        None => writeln!(out, "Segment length:       unsplit (single-part archive)")?,
    }
    writeln!(out, "Physical parts:       {}", bf.part_paths().len())?;
    for (i, (path, size)) in bf.part_paths().iter().zip(bf.part_sizes()).enumerate() {
        writeln!(out, "  [{i:03}] {} ({} bytes)", path.display(), size)?;
    }
    Ok(())
}

fn write_archive_info<W: Write>(
    out: &mut W,
    bf: &Bigfile,
    stats: &ArchiveStats,
) -> Result<(), StdoutError> {
    write_info_parts_section(out, bf)?;
    writeln!(out, "Total TOC entries:    {}", bf.entries().len())?;
    writeln!(out, "Unique path hashes:   {}", stats.unique_hashes)?;
    writeln!(
        out,
        "Resolved names:       {} / {} ({:.1}%)",
        stats.resolved_hashes,
        stats.unique_hashes,
        stats.resolved_percentage()
    )?;
    writeln!(out, "Compressed entries:   {}", stats.compressed_count)?;
    writeln!(out, "Total stored bytes:   {}", stats.total_stored_bytes)?;
    writeln!(out, "Total logical bytes:  {}", stats.total_logical_bytes)?;
    writeln!(out, "Distinct SKU masks:   {}", stats.sku_counts.len())?;
    for (&sku, cnt) in &stats.sku_counts {
        writeln!(out, "  sku={} -> {cnt} entries", HexU32(sku))?;
    }
    out.flush()?;
    Ok(())
}

fn write_archive_info_json<W: Write>(
    out: &mut W,
    pretty: bool,
    bf: &Bigfile,
    stats: &ArchiveStats,
) -> Result<(), StdoutError> {
    let parts = std::iter::zip(bf.part_paths(), bf.part_sizes())
        .enumerate()
        .map(|(index, (path, &size))| PartJson {
            index,
            path: path.to_string_lossy(),
            size,
        })
        .collect();
    let report = InfoJsonReport {
        schema: JSON_SCHEMA_VERSION,
        archive: bf.dir_path().to_string_lossy(),
        stem: bf.stem(),
        endian: bf.endian().as_str(),
        segment_length: bf.segment_length(),
        parts,
        total_entries: bf.entries().len(),
        unique_hashes: stats.unique_hashes,
        resolved_hashes: stats.resolved_hashes,
        resolved_percentage: stats.resolved_percentage(),
        compressed_entries: stats.compressed_count,
        total_stored_bytes: stats.total_stored_bytes,
        total_logical_bytes: stats.total_logical_bytes,
        sku_counts: stats
            .sku_counts
            .iter()
            .map(|(&sku, &count)| SkuCountJson {
                sku_flags: HexU32(sku),
                count,
            })
            .collect(),
    };
    write_json_stdout(out, pretty, &report)
}

pub(super) fn run_info<W: Write>(
    out: &mut W,
    args: &InfoArgs,
    mode: OutputMode,
) -> Result<(), Box<dyn std::error::Error>> {
    let bf = args.archive.open()?;
    let dict = args.dict.load()?;
    let stats = compute_archive_stats(&bf, &dict);
    match mode {
        OutputMode::Json { pretty } => write_archive_info_json(out, pretty, &bf, &stats)?,
        OutputMode::Text => write_archive_info(out, &bf, &stats)?,
    }
    Ok(())
}
