//! The `list` command.

use std::borrow::Cow;
use std::io::{self, Write};

use lau_bigfun::{Bigfile, BigfileError, EntryFilter, Fat, HashDictionary};

use super::args::{ListArgs, warn_if_names_miss_archive};
use super::output::{HexU32, ListEntryRecord, OutputMode, StatusReporter, write_entries};

fn matching_list_entries<'a>(
    bf: &'a Bigfile,
    dict: &'a HashDictionary,
    args: &'a ListArgs,
    filter: Option<&'a EntryFilter>,
) -> impl Iterator<Item = Result<ListEntryRecord<'a>, BigfileError>> + 'a {
    Fat::filter_spec_mask(bf.entries(), args.spec.mask).filter_map(move |entry| {
        let name = dict.get(entry.name_hash);
        if filter.is_some_and(|f| !f.matches(entry.name_hash, name)) {
            return None;
        }
        Some(
            bf.locate_coords(entry)
                .map(|(part_index, offset_in_part)| ListEntryRecord {
                    index: entry.index,
                    name_hash: HexU32(entry.name_hash),
                    name,
                    size: entry.size,
                    stored_size: entry.stored_size(),
                    deflated_size: entry.deflated_size,
                    compressed: entry.is_compressed(),
                    sector_number: entry.sector_number,
                    part_index,
                    offset_in_part,
                    spec_flags: HexU32(entry.spec_flags),
                }),
        )
    })
}

/// Returns `name` with control characters (C0, DEL and C1) written as `\u{..}` escapes, so a
/// filelist cannot send terminal control sequences through the text listing.
fn escape_control_chars(name: &str) -> Cow<'_, str> {
    if !name.contains(char::is_control) {
        return Cow::Borrowed(name);
    }
    let mut escaped = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_control() {
            escaped.extend(c.escape_unicode());
        } else {
            escaped.push(c);
        }
    }
    Cow::Owned(escaped)
}

fn write_list_entry<W: Write>(out: &mut W, record: &ListEntryRecord<'_>) -> io::Result<()> {
    writeln!(
        out,
        "  {}  size={:<10} sector={:<10} part={:03}@{:#010x} spec={} deflated={:<8} {}",
        record.name_hash,
        record.size,
        record.sector_number,
        record.part_index,
        record.offset_in_part,
        record.spec_flags,
        record.deflated_size,
        escape_control_chars(record.name.unwrap_or("<unknown>"))
    )
}

pub(super) fn run_list<W: Write, E: Write>(
    out: &mut W,
    status: &mut StatusReporter<E>,
    args: &ListArgs,
    mode: OutputMode,
) -> Result<(), Box<dyn std::error::Error>> {
    let filter = args.filter.compile()?;
    let bf = args.archive.open()?;
    let dict = args.dict.load_for_filter(filter.as_ref(), status)?;
    warn_if_names_miss_archive(&dict, &bf, status);

    report_archive_shape(status, &bf);
    let limit = if args.limit == 0 {
        usize::MAX
    } else {
        args.limit
    };
    let matching: Vec<_> = matching_list_entries(&bf, &dict, args, filter.as_ref()).collect();
    let total = matching.len();
    let shown = matching.into_iter().take(limit);
    write_entries(out, mode, Some(total), shown, write_list_entry)?;
    if total > limit {
        status.println(format_args!(
            "showing {limit} of {total} matching entries; use --limit 0 to list all"
        ));
    }
    Ok(())
}

/// Reports the archive's entry count and segment length on the status stream.
fn report_archive_shape<E: Write>(status: &mut StatusReporter<E>, bf: &Bigfile) {
    let count = bf.entries().len();
    match bf.segment_length() {
        Some(len) => status.println(format_args!("{count} entries; segment_length={len:#x}")),
        None => status.println(format_args!("{count} entries; segment_length=unsplit")),
    }
}
