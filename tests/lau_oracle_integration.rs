//! Optional integration tests against retail Tomb Raider LAU archive directories
//! (*Legend*, *Anniversary*, and *Underworld*) specified via environment variables:
//! - `LAU_BIGFUN_TRL_TEST_ARCHIVE_DIR`
//! - `LAU_BIGFUN_TRA_TEST_ARCHIVE_DIR`
//! - `LAU_BIGFUN_TRU_TEST_ARCHIVE_DIR`
//!
//! Each title's archive variable also needs its filelist variable, for filename coverage:
//! - `LAU_BIGFUN_TRL_TEST_FILELIST`
//! - `LAU_BIGFUN_TRA_TEST_FILELIST`
//! - `LAU_BIGFUN_TRU_TEST_FILELIST`
//!
//! Tests that need the archives are marked `#[ignore]`, so they run only on request, with
//! `cargo test -- --ignored`. Within such a run, a title whose variables are unset is skipped.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use lau_bigfun::format::SECTOR_BYTE_COUNT;
use lau_bigfun::path::normalized_rel_key;
use lau_bigfun::{
    ArchiveSet, Bigfile, BigfileError, Endian, Fat, HashDictionary, OpenOptions, name_hash,
};

struct OracleSpec {
    env_var: &'static str,
    filelist_env_var: &'static str,
    expected_segment_length: u64,
    dict_len: usize,
    expected_archive_unique_hashes: usize,
    expected_parts: usize,
    expected_entries: usize,
    expected_patch_entries: Option<usize>,
    probe_path: &'static str,
    expected_probe_hash: u32,
    /// CRC-32 over the first non-empty entry (in TOC order) of each part, concatenated in part order.
    parts_sample_crc32: u32,
    /// CRC-32 of the entry at `probe_path`.
    probe_crc32: u32,
    /// CRC-32 of `pc-w\lara.drm`.
    lara_crc32: u32,
    engine_lookups: &'static [EngineLookupVector],
}

/// Records [`Bigfile::find_with_sku_mask`] must return for `path` in `archive`, where the record at
/// position `n` of `records_by_mask_bit` is expected for the mask `1 << n`, and how many lookups
/// over those mask bits differ from the first matching record across all multi-record hashes.
struct EngineLookupVector {
    archive: &'static str,
    path: &'static str,
    records_by_mask_bit: &'static [usize],
    lookups_differing_from_first_match: usize,
}

/// Retail PC *Tomb Raider: Legend* archive specification (standard PC release with Next-Gen content:
/// 51 parts `bigfile.000`..`bigfile.050`, 12,119 total TOC entries across 4,315 unique path hashes).
const TRL_SPEC: OracleSpec = OracleSpec {
    env_var: "LAU_BIGFUN_TRL_TEST_ARCHIVE_DIR",
    filelist_env_var: "LAU_BIGFUN_TRL_TEST_FILELIST",
    expected_segment_length: 0x0960_0000,
    dict_len: 4315,
    expected_archive_unique_hashes: 4315,
    expected_parts: 51,
    expected_entries: 12_119,
    expected_patch_entries: None,
    probe_path: r"\tr7\pc-w\objectlist.txt",
    expected_probe_hash: 0x2EC4_C185,
    parts_sample_crc32: 0xEB78_B3DC,
    probe_crc32: 0xA820_61CE,
    lara_crc32: 0x068D_4F2C,
    engine_lookups: &[],
};

/// Retail PC *Tomb Raider: Anniversary* archive specification (27 parts `bigfile.000`..`bigfile.026`,
/// 4,304 total TOC entries across 2,967 unique path hashes).
const TRA_SPEC: OracleSpec = OracleSpec {
    env_var: "LAU_BIGFUN_TRA_TEST_ARCHIVE_DIR",
    filelist_env_var: "LAU_BIGFUN_TRA_TEST_FILELIST",
    expected_segment_length: 0x0960_0000,
    dict_len: 2967,
    expected_archive_unique_hashes: 2967,
    expected_parts: 27,
    expected_entries: 4304,
    expected_patch_entries: None,
    probe_path: r"\trae\pc-w\objectlist.txt",
    expected_probe_hash: 0xDD73_35E5,
    parts_sample_crc32: 0xF811_0C22,
    probe_crc32: 0x6FD6_A88C,
    lara_crc32: 0x3F1E_9445,
    engine_lookups: &[],
};

/// Records of `patch.000` that `pc-w\local\locals.bin` resolves to for each of mask bits 0-12,
/// both within the patch and through an [`ArchiveSet`] that stacks it over the base.
const TRU_PATCH_LOCALS_RECORDS: [usize; 13] = [4, 1, 5, 6, 2, 4, 4, 4, 4, 4, 4, 3, 4];

/// Retail PC *Tomb Raider: Underworld* archive specification (4 parts `bigfile.000`..`bigfile.003`,
/// 7,339 total TOC entries across 3,218 unique path hashes, plus `patch.000` with 9 entries).
const TRU_SPEC: OracleSpec = OracleSpec {
    env_var: "LAU_BIGFUN_TRU_TEST_ARCHIVE_DIR",
    filelist_env_var: "LAU_BIGFUN_TRU_TEST_FILELIST",
    expected_segment_length: 0x7FF0_0000,
    dict_len: 3218,
    expected_archive_unique_hashes: 3218,
    expected_parts: 4,
    expected_entries: 7339,
    expected_patch_entries: Some(9),
    probe_path: r"pc-w\alister.drm",
    expected_probe_hash: 0x1DE5_357F,
    parts_sample_crc32: 0x0C63_EE64,
    probe_crc32: 0xAB54_8200,
    lara_crc32: 0xC862_594E,
    engine_lookups: &[
        EngineLookupVector {
            archive: "bigfile.000",
            path: r"pc-w\local\locals.bin",
            records_by_mask_bit: &[
                3549, 3550, 3552, 3553, 3548, 3550, 3550, 3550, 3550, 3550, 3550, 3551, 3550,
            ],
            lookups_differing_from_first_match: 7,
        },
        EngineLookupVector {
            archive: "patch.000",
            path: r"pc-w\local\locals.bin",
            records_by_mask_bit: &TRU_PATCH_LOCALS_RECORDS,
            lookups_differing_from_first_match: 7,
        },
    ],
};

fn resolve_env_path(env_var: &str, val: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    let Some(val) = val else {
        eprintln!("skipping oracle check: environment variable {env_var} is not set");
        return None;
    };
    assert!(
        !val.is_empty() && !val.to_string_lossy().trim().is_empty(),
        "environment variable {env_var} is set to an empty path"
    );
    Some(PathBuf::from(val))
}

/// Opens the archive at `path`, naming it if that fails.
fn open_archive(path: &Path) -> Bigfile {
    Bigfile::open(path).unwrap_or_else(|e| panic!("Bigfile::open({}) failed: {e}", path.display()))
}

fn test_archive_dir(spec: &OracleSpec) -> Option<PathBuf> {
    let val = std::env::var_os(spec.env_var);
    resolve_env_path(spec.env_var, val.as_deref())
}

fn test_filelist(spec: &OracleSpec) -> Option<HashDictionary> {
    let val = std::env::var_os(spec.filelist_env_var);
    let path = resolve_env_path(spec.filelist_env_var, val.as_deref())?;
    let mut dict = HashDictionary::new();
    dict.load_file(&path)
        .unwrap_or_else(|e| panic!("load_file({}) failed: {e}", path.display()));
    Some(dict)
}

fn assert_filelist_coverage(spec: &OracleSpec) {
    let archive_dir = test_archive_dir(spec);
    let Some(game_dict) = test_filelist(spec) else {
        assert!(
            archive_dir.is_none(),
            "{} is set, so {} must be set too",
            spec.env_var,
            spec.filelist_env_var
        );
        return;
    };
    assert_eq!(game_dict.len(), spec.dict_len);
    assert!(game_dict.get(spec.expected_probe_hash).is_some());

    let Some(archive_dir) = archive_dir else {
        return;
    };
    let bf = open_archive(&archive_dir);
    assert_output_paths_follow_filelist(&bf, &game_dict);
}

/// Checks that every hash in `bf` is extracted under its filelist path, spelled exactly as the
/// filelist spells it once empty, `.` and `..` segments are resolved, and that no two hashes share
/// an output path on a case-insensitive filesystem, so unpack never has to rename one.
fn assert_output_paths_follow_filelist(bf: &Bigfile, game_dict: &HashDictionary) {
    let mut output_keys = HashSet::new();
    for run in bf.hash_runs() {
        let h = run[0].name_hash;
        let (path, resolved) = game_dict.relative_path_or_fallback(h);
        assert!(resolved, "hash {h:#010x} missing from game filelist");
        // Sanitization drops empty and `.` segments, such as a root-relative name's leading `\`,
        // and resolves `..`, so Anniversary's `sndstrm\..\cinstream` is `cinstream`. Every other
        // segment must be kept exactly as listed.
        let mut listed = PathBuf::new();
        for segment in game_dict.get(h).unwrap().split(['\\', '/']) {
            match segment {
                "" | "." => {}
                ".." => {
                    listed.pop();
                }
                kept => listed.push(kept),
            }
        }
        assert_eq!(path, listed, "hash {h:#010x} not extracted as listed");
        assert!(
            output_keys.insert(normalized_rel_key(&path)),
            "hash {h:#010x} shares its output path {} with another hash",
            path.display()
        );
    }
}

fn assert_oracle_segment_bounds(bf: &Bigfile, seg: u64) {
    let sectors_per_seg = (seg / (SECTOR_BYTE_COUNT as u64)) as u32;
    let start_sectors: HashSet<u32> = bf.entries().iter().map(|e| e.sector_number).collect();

    for k in 1..bf.part_paths().len() {
        let expected_sector = (k as u32) * sectors_per_seg;
        assert!(
            start_sectors.contains(&expected_sector),
            "no entry starts part {k} at sector {expected_sector}"
        );
    }

    for e in bf.entries() {
        assert!(!e.is_compressed());
        assert_eq!(e.deflated_size, 0);
        assert_eq!(e.stored_size(), e.size);
        if e.stored_size() == 0 {
            continue;
        }
        let start = e.logical_offset();
        let end = start + (e.stored_size() as u64);
        assert_eq!(
            start / seg,
            (end - 1) / seg,
            "entry at sector {} spans a part boundary",
            e.sector_number
        );
    }
}

fn assert_toc_invariants(spec: &OracleSpec) {
    let Some(archive_dir) = test_archive_dir(spec) else {
        return;
    };

    let bf = open_archive(&archive_dir);
    assert_eq!(bf.endian(), Endian::Little);
    assert_eq!(bf.entries().len(), spec.expected_entries);
    assert_eq!(bf.part_paths().len(), spec.expected_parts);

    let seg = bf
        .segment_length()
        .expect("multi-part archive should have dynamically discovered segment_length");
    assert_eq!(seg, spec.expected_segment_length);
    assert_eq!(seg % (1 << 20), 0);

    assert!(bf.entries().is_sorted_by_key(|e| e.name_hash));
    assert_eq!(bf.hash_runs().count(), spec.expected_archive_unique_hashes);
    assert_oracle_segment_bounds(&bf, seg);
}

fn assert_virtual_dat_discovery(spec: &OracleSpec) {
    let Some(archive_dir) = test_archive_dir(spec) else {
        return;
    };

    let bf = open_archive(&archive_dir);
    // Opening BIGFILE.DAT must resolve to the numbered parts, which these PC releases ship
    // instead of a single DAT file.
    let virtual_dat_path = bf.dir_path().join("BIGFILE.DAT");
    let bf_from_dat = open_archive(&virtual_dat_path);
    assert_eq!(bf_from_dat.entries().len(), bf.entries().len());
    assert_eq!(bf_from_dat.part_paths().len(), bf.part_paths().len());
    assert_eq!(
        bf_from_dat.segment_length(),
        Some(spec.expected_segment_length)
    );

    assert_patch_archive(&bf, spec.expected_patch_entries);
}

fn assert_patch_archive(bf: &Bigfile, expected_patch_entries: Option<usize>) {
    let virtual_patch_path = bf.dir_path().join("patch.000");
    let maybe_patch_bf = match (Bigfile::open(&virtual_patch_path), expected_patch_entries) {
        (Ok(patch_bf), Some(expected)) => {
            assert_eq!(patch_bf.entries().len(), expected);
            Some(patch_bf)
        }
        (Ok(patch_bf), None) => Some(patch_bf),
        (Err(BigfileError::NoPartsFound(_)), None) => None,
        (Err(e), Some(expected)) => panic!(
            "expected patch.000 ({expected} entries) in '{}', but Bigfile::open failed: {e}",
            bf.dir_path().display()
        ),
        (Err(e), None) => panic!(
            "Bigfile::open({}) failed with unexpected error: {e}",
            virtual_patch_path.display()
        ),
    };

    if let Some(patch_bf) = maybe_patch_bf {
        if patch_bf.part_paths().len() == 1 {
            assert_eq!(patch_bf.segment_length(), None);
        }
        if let Some(first_patch_entry) = patch_bf.entries().first() {
            let patch_bytes = patch_bf.read_entry(first_patch_entry, false).unwrap();
            assert_eq!(patch_bytes.len(), first_patch_entry.size as usize);
        }
    }
}

fn assert_reads_across_all_parts(spec: &OracleSpec) {
    let Some(archive_dir) = test_archive_dir(spec) else {
        return;
    };

    let bf = open_archive(&archive_dir);
    let seg = bf.segment_length().unwrap();
    assert_eq!(seg, spec.expected_segment_length);

    // Returns the entry's bytes after checking both reads return the sizes its record declares.
    let read_checked = |e: &lau_bigfun::Entry| {
        assert_eq!(
            bf.read_entry(e, true).unwrap().len(),
            e.stored_size() as usize
        );
        let bytes = bf.read_entry(e, false).unwrap();
        assert_eq!(bytes.len(), e.size as usize);
        bytes
    };
    let mut parts_sample = crc32fast::Hasher::new();
    for part_idx in 0..bf.part_paths().len() {
        let in_part =
            |e: &&lau_bigfun::Entry| bf.locate_coords(e).is_ok_and(|(part, _)| part == part_idx);
        let entry = bf
            .entries()
            .iter()
            .filter(in_part)
            .find(|e| e.stored_size() > 0)
            .unwrap();
        parts_sample.update(&read_checked(entry));
    }
    assert_eq!(
        parts_sample.finalize(),
        spec.parts_sample_crc32,
        "CRC-32 over the first non-empty entry of each part"
    );

    let probe_matches = bf.find(name_hash(spec.probe_path).unwrap());
    assert_eq!(
        crc32fast::hash(&read_checked(&probe_matches[0])),
        spec.probe_crc32,
        "CRC-32 of {}",
        spec.probe_path
    );

    let lara_hash = name_hash(r"pc-w\lara.drm").unwrap();
    let lara_matches = bf.find(lara_hash);
    let lara_entry = bf
        .find_with_sku_mask(lara_hash, lara_matches[0].sku_flags)
        .unwrap();
    assert_eq!(
        crc32fast::hash(&read_checked(lara_entry)),
        spec.lara_crc32,
        r"CRC-32 of pc-w\lara.drm"
    );
}

/// Counts single-bit lookups below `mask_bits` that differ from the first matching record across
/// every multi-record hash, requiring each lookup to return a record.
fn count_lookups_differing_from_first_match(bf: &Bigfile, mask_bits: usize) -> usize {
    let mut differing = 0;
    for run in bf.hash_runs().filter(|run| run.len() > 1) {
        for bit in 0..mask_bits {
            let mask = 1u32 << bit;
            let found = bf.find_with_sku_mask(run[0].name_hash, mask).unwrap();
            let first = Fat::filter_sku_mask(run, Some(mask)).next();
            differing += usize::from(first.map(|entry| entry.index) != Some(found.index));
        }
    }
    differing
}

fn assert_engine_lookups(spec: &OracleSpec) {
    let Some(archive_dir) = test_archive_dir(spec) else {
        return;
    };
    for vector in spec.engine_lookups {
        let bf = open_archive(&archive_dir.join(vector.archive));
        let hash = name_hash(vector.path).unwrap();
        for (bit, &record) in vector.records_by_mask_bit.iter().enumerate() {
            let found = bf.find_with_sku_mask(hash, 1 << bit).unwrap();
            assert_eq!(found.index, record, "{} mask bit {bit}", vector.archive);
        }
        assert_eq!(
            count_lookups_differing_from_first_match(&bf, vector.records_by_mask_bit.len()),
            vector.lookups_differing_from_first_match,
            "{}",
            vector.archive
        );
    }
}

/// Patched names with the patch record each of mask bits 0-12 resolves to.
const TRU_PATCHED_NAMES: [(&str, [usize; 13]); 4] = [
    (r"pc-w\l2_puzzleroom.drm", [0; 13]),
    (r"pc-w\local\locals.bin", TRU_PATCH_LOCALS_RECORDS),
    (r"pc-w\g_pda.drm", [7; 13]),
    (r"pc-w\generalbank.drm", [8; 13]),
];

/// Opens the shipped patch, in the bigfile's byte order, and the bigfile in resolution order.
fn open_tru_patched_pair() -> Option<[Bigfile; 2]> {
    let archive_dir = test_archive_dir(&TRU_SPEC)?;
    let base = open_archive(&archive_dir.join("bigfile.000"));
    let options = OpenOptions {
        endian: Some(base.endian()),
        ..OpenOptions::default()
    };
    let patch = Bigfile::open_with_options(archive_dir.join("patch.000"), options).unwrap();
    Some([patch, base])
}

#[test]
#[ignore = "needs retail archives; set the LAU_BIGFUN_* variables"]
fn tru_patched_names_resolve_from_patch() {
    let Some(archives) = open_tru_patched_pair() else {
        return;
    };
    let set = ArchiveSet::new(&archives);
    for (path, records) in TRU_PATCHED_NAMES {
        let hash = name_hash(path).unwrap();
        for (bit, &record) in records.iter().enumerate() {
            let resolved = set.resolve(hash, 1 << bit).unwrap();
            assert_eq!(resolved.archive.stem(), "patch", "{path} mask bit {bit}");
            assert_eq!(resolved.entry.index, record, "{path} mask bit {bit}");
        }
    }
}

#[test]
#[ignore = "needs retail archives; set the LAU_BIGFUN_* variables"]
fn tru_locals_resolves_to_patch_flags_for_mask_0x20() {
    let Some(archives) = open_tru_patched_pair() else {
        return;
    };
    let set = ArchiveSet::new(&archives);
    let hash = name_hash(r"pc-w\local\locals.bin").unwrap();
    assert_eq!(
        set.resolve(hash, 0x20).unwrap().entry.sku_flags,
        0xFFFF_F7E1
    );
}

#[test]
#[ignore = "needs retail archives; set the LAU_BIGFUN_* variables"]
fn tru_unpatched_names_resolve_from_bigfile() {
    let Some(archives) = open_tru_patched_pair() else {
        return;
    };
    let set = ArchiveSet::new(&archives);
    let patched: HashSet<u32> = archives[0]
        .hash_runs()
        .map(|run| run[0].name_hash)
        .collect();
    for run in archives[1].hash_runs() {
        let hash = run[0].name_hash;
        let expected = archives[1].find_with_sku_mask(hash, 0);
        let resolved = set.resolve(hash, 0).unwrap();
        if !patched.contains(&hash) {
            assert_eq!(resolved.archive.stem(), "bigfile");
            assert_eq!(
                Some(resolved.entry.index),
                expected.map(|entry| entry.index)
            );
        }
    }
}

#[test]
#[ignore = "needs retail archives; set the LAU_BIGFUN_* variables"]
fn tru_engine_lookup_order() {
    assert_engine_lookups(&TRU_SPEC);
}

#[test]
#[ignore = "needs retail archives; set the LAU_BIGFUN_* variables"]
fn trl_filelist_coverage() {
    assert_filelist_coverage(&TRL_SPEC);
}

#[test]
#[ignore = "needs retail archives; set the LAU_BIGFUN_* variables"]
fn trl_bigfile_toc_invariants() {
    assert_toc_invariants(&TRL_SPEC);
}

#[test]
#[ignore = "needs retail archives; set the LAU_BIGFUN_* variables"]
fn trl_bigfile_virtual_dat_discovery() {
    assert_virtual_dat_discovery(&TRL_SPEC);
}

#[test]
#[ignore = "needs retail archives; set the LAU_BIGFUN_* variables"]
fn trl_reads_across_all_parts() {
    assert_reads_across_all_parts(&TRL_SPEC);
}

#[test]
#[ignore = "needs retail archives; set the LAU_BIGFUN_* variables"]
fn tra_filelist_coverage() {
    assert_filelist_coverage(&TRA_SPEC);
}

#[test]
#[ignore = "needs retail archives; set the LAU_BIGFUN_* variables"]
fn tra_bigfile_toc_invariants() {
    assert_toc_invariants(&TRA_SPEC);
}

#[test]
#[ignore = "needs retail archives; set the LAU_BIGFUN_* variables"]
fn tra_bigfile_virtual_dat_discovery() {
    assert_virtual_dat_discovery(&TRA_SPEC);
}

#[test]
#[ignore = "needs retail archives; set the LAU_BIGFUN_* variables"]
fn tra_reads_across_all_parts() {
    assert_reads_across_all_parts(&TRA_SPEC);
}

#[test]
#[ignore = "needs retail archives; set the LAU_BIGFUN_* variables"]
fn tru_filelist_coverage() {
    assert_filelist_coverage(&TRU_SPEC);
}

#[test]
#[ignore = "needs retail archives; set the LAU_BIGFUN_* variables"]
fn tru_bigfile_toc_invariants() {
    assert_toc_invariants(&TRU_SPEC);
}

#[test]
#[ignore = "needs retail archives; set the LAU_BIGFUN_* variables"]
fn tru_bigfile_virtual_dat_discovery() {
    assert_virtual_dat_discovery(&TRU_SPEC);
}

#[test]
#[ignore = "needs retail archives; set the LAU_BIGFUN_* variables"]
fn tru_reads_across_all_parts() {
    assert_reads_across_all_parts(&TRU_SPEC);
}

#[test]
fn probe_paths_hash_to_their_expected_values() {
    for spec in [&TRL_SPEC, &TRA_SPEC, &TRU_SPEC] {
        assert_eq!(
            name_hash(spec.probe_path).unwrap(),
            spec.expected_probe_hash,
            "{}",
            spec.probe_path
        );
    }
}

#[test]
fn resolve_env_path_handles_optional_os_str() {
    assert_eq!(resolve_env_path("LAU_TEST_VAR", None), None);
    assert_eq!(
        resolve_env_path("LAU_TEST_VAR", Some(std::ffi::OsStr::new("/tmp/archive"))),
        Some(PathBuf::from("/tmp/archive"))
    );
}

#[test]
#[should_panic(expected = "environment variable LAU_TEST_VAR is set to an empty path")]
fn resolve_env_path_panics_when_set_to_empty_string() {
    let _ = resolve_env_path("LAU_TEST_VAR", Some(std::ffi::OsStr::new("")));
}

#[test]
#[should_panic(expected = "environment variable LAU_TEST_VAR is set to an empty path")]
fn resolve_env_path_panics_when_set_to_whitespace_only() {
    let _ = resolve_env_path("LAU_TEST_VAR", Some(std::ffi::OsStr::new("   ")));
}
