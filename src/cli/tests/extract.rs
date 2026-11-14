//! The `extract` command.

use super::*;

#[cfg(target_os = "linux")]
#[test]
fn extract_write_failure_names_the_output_path() {
    let (_dir, archive) = create_synthetic_archive("extract_full");
    let argv = [
        "extract",
        archive.to_str().unwrap(),
        r"pc-w\lara.drm",
        "-o",
        "/dev/full",
    ];

    let err = exec_args(&argv, false).unwrap_err();

    assert!(err.contains("/dev/full"), "{err}");
}

#[test]
fn extract_warns_when_the_filelist_names_no_archive_hash() {
    let (dir, archive_path) = create_synthetic_archive("extract_names_miss");
    let filelist = write_unrelated_filelist(&dir);
    let argv = [
        "extract",
        archive_path.to_str().unwrap(),
        "0x5ff91900",
        "-o",
        "-",
        "--filelist",
        filelist.to_str().unwrap(),
    ];

    let (_, status) = exec_args(&argv, false).unwrap();
    assert!(status.contains(NAMES_MISS_WARNING), "{status}");
}

#[test]
fn extract_to_file_writes_status_only_to_stderr() {
    let (dir, archive_path) = create_synthetic_archive("extract_file");
    let archive_str = archive_path.to_str().unwrap();

    let out_file = dir.join("nested/out.drm");
    let (out, err) = exec_args(
        &[
            "extract",
            archive_str,
            r"pc-w\lara.drm",
            "-o",
            out_file.to_str().unwrap(),
            "--raw",
        ],
        false,
    )
    .unwrap();
    assert!(out.is_empty());
    assert!(err.contains("1 variant(s) for 0x5ff91900"));
    assert!(err.contains("wrote 22 bytes to"));
    assert_eq!(fs::read(&out_file).unwrap(), SYNTHETIC_PAYLOAD);
}

#[test]
fn extract_streams_to_stdout_when_omitted_or_dash() {
    let (_dir, archive_path) = create_synthetic_archive("extract_stdout");
    let archive_str = archive_path.to_str().unwrap();

    assert_eq!(
        ExtractDestination::from_arg(None),
        ExtractDestination::ImplicitStdout
    );
    assert_eq!(
        ExtractDestination::from_arg(Some(Path::new("-"))),
        ExtractDestination::ExplicitStdout
    );
    assert_eq!(
        ExtractDestination::from_arg(Some(Path::new("./-"))),
        ExtractDestination::File(Path::new("./-"))
    );

    let (out, err) = exec_args(&["extract", archive_str, r"pc-w\lara.drm"], false).unwrap();
    assert_eq!(out, SYNTHETIC_PAYLOAD);
    assert_eq!(
        err,
        "1 variant(s) for 0x5ff91900\nwrote 22 bytes to stdout (record #0, spec=0x00000001)\n"
    );

    let (q_out, q_err) =
        exec_args(&["-q", "extract", archive_str, r"pc-w\lara.drm"], false).unwrap();
    assert_eq!(q_out, SYNTHETIC_PAYLOAD);
    assert!(q_err.is_empty());
}

#[test]
fn extract_guards_interactive_tty_unless_dash_passed() {
    let (_dir, archive_path) = create_synthetic_archive("extract_tty");
    let archive_str = archive_path.to_str().unwrap();

    let err = exec_args(&["extract", archive_str, r"pc-w\lara.drm"], true).unwrap_err();
    assert!(err.contains("refusing to write extracted data to an interactive terminal"));

    for is_tty in [false, true] {
        let (out, _) = exec_args(
            &["extract", archive_str, r"pc-w\lara.drm", "-o", "-"],
            is_tty,
        )
        .unwrap();
        assert_eq!(out, SYNTHETIC_PAYLOAD);
    }
}

#[test]
fn extract_reports_missing_target_error() {
    let (_dir, archive_path) = create_synthetic_archive("missing_target");
    let archive_str = archive_path.to_str().unwrap();

    for (missing, expected) in [
        (
            r"pc-w\missing.drm",
            "not found: 0x2533e7ef (pc-w\\missing.drm)",
        ),
        ("0xdeadbeef", "not found: 0xdeadbeef"),
    ] {
        let err = exec_args(&["extract", archive_str, missing, "-o", "-"], false).unwrap_err();
        assert_eq!(err, expected);
    }
}

/// Writes an archive holding three `pc-w\lara.drm` variants, with spec flags `0x1`, `0x3` and
/// `0x7`, returning its temporary directory and path.
fn create_three_variant_archive(prefix: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new(prefix);
    let archive_path = dir.join("bigfile.000");
    let lara = name_hash(r"pc-w\lara.drm").unwrap();
    write_archive(
        &archive_path,
        Endian::Little,
        &[
            ArchiveRecord::stored(lara, 0x1, b"a"),
            ArchiveRecord::stored(lara, 0x3, b"b"),
            ArchiveRecord::stored(lara, 0x7, b"c"),
        ],
    );
    (dir, archive_path)
}

/// Extracts `pc-w\lara.drm` from `archive` to stdout with `extra` arguments, returning the status.
fn extract_lara_status(archive: &Path, extra: &[&str]) -> String {
    let mut argv = vec![
        "extract",
        archive.to_str().unwrap(),
        r"pc-w\lara.drm",
        "-o",
        "-",
    ];
    argv.extend_from_slice(extra);
    exec_args(&argv, false).unwrap().1
}

#[test]
fn extract_hints_how_to_choose_when_several_variants_match() {
    let (_dir, archive) = create_three_variant_archive("extract_hint");

    let status = extract_lara_status(&archive, &[]);
    assert!(
        status.contains(
            "3 variant(s) for 0x5ff91900; extracting the first (choose with --variant <N>, or --spec-mask <MASK> --engine-spec-match for the engine's pick)"
        ),
        "{status}"
    );
}

#[test]
fn extract_hint_counts_only_variants_matching_the_spec_mask() {
    let (_dir, archive) = create_three_variant_archive("extract_hint_mask");

    let status = extract_lara_status(&archive, &["--spec-mask", "0x3"]);
    assert!(
        status.contains(
            "3 variant(s) for 0x5ff91900, 2 matching --spec-mask 0x00000003; extracting the first (choose with --variant <N>, or --engine-spec-match for the engine's pick)"
        ),
        "{status}"
    );
}

#[test]
fn extract_does_not_hint_when_the_spec_mask_leaves_one_variant() {
    let (_dir, archive) = create_three_variant_archive("extract_hint_one");

    let status = extract_lara_status(&archive, &["--spec-mask", "0x7"]);
    assert!(!status.contains("extracting the first"), "{status}");
}

#[test]
fn extract_does_not_hint_when_a_variant_is_chosen() {
    let (_dir, archive) = create_three_variant_archive("extract_hint_variant");

    let status = extract_lara_status(&archive, &["--variant", "0"]);
    assert!(!status.contains("extracting the first"), "{status}");
}

#[test]
fn extract_does_not_hint_with_the_engine_spec_match() {
    let (_dir, archive) = create_three_variant_archive("extract_hint_engine");

    let status = extract_lara_status(&archive, &["--spec-mask", "0x3", "--engine-spec-match"]);
    assert!(!status.contains("extracting the first"), "{status}");
}

#[test]
fn select_extract_variant_filters_by_spec_mask() {
    let h = 0x5FF9_1900;
    let entries = [sample_entry(0, h, 1, 0b0001), sample_entry(1, h, 1, 0b0011)];
    for (mask, var, expected_idx) in [(None, None, 0), (None, Some(1), 1), (Some(3), None, 1)] {
        assert_eq!(
            select_extract_variant(&entries, h, mask, var)
                .unwrap()
                .entry
                .index,
            expected_idx
        );
    }
    for (mask, var, substr) in [
        (None, Some(2), "out of range (0..1)"),
        (
            Some(3),
            Some(1),
            "out of range (0..0) for --spec-mask 0x00000003",
        ),
        (
            Some(4),
            None,
            "no variant of 0x5ff91900 matches --spec-mask 0x00000004",
        ),
    ] {
        assert!(
            select_extract_variant(&entries, h, mask, var)
                .unwrap_err()
                .contains(substr)
        );
    }
}

/// Extracts `target` to a file with `--json` and `extra` arguments, checks the written payload,
/// and returns the parsed report.
fn extract_json_report(
    dir: &TempDir,
    archive: &str,
    target: &str,
    extra: &[&str],
) -> serde_json::Value {
    let out_file = dir.join("extracted_lara.drm");
    let mut args = vec![
        "extract",
        archive,
        target,
        "-o",
        out_file.to_str().unwrap(),
        "--json",
    ];
    args.extend(extra);
    let (out, err) = exec_args(&args, false).unwrap();
    assert_eq!(fs::read(&out_file).unwrap(), SYNTHETIC_PAYLOAD);
    assert!(err.contains("wrote 22 bytes to"));
    serde_json::from_slice(&out).unwrap()
}

#[test]
fn extract_json_writes_file_payload_with_stdout_metadata() {
    let (dir, archive_path) = create_synthetic_archive("extract_json");
    let a = archive_path.to_str().unwrap();

    let val = extract_json_report(&dir, a, r"pc-w\lara.drm", &[]);
    assert_eq!(
        val,
        serde_json::json!({
            "schema": 2,
            "index": 0,
            "name_hash": "0x5ff91900",
            "name": r"pc-w\lara.drm",
            "spec_flags": "0x00000001",
            "spec_mask": null,
            "variant": 0,
            "variant_count": 1,
            "raw": false,
            "bytes_written": 22,
            "output": dir.join("extracted_lara.drm").to_str().unwrap(),
        })
    );
}

#[test]
fn extract_json_names_hash_target_from_filelist() {
    let (dir, archive_path) = create_synthetic_archive("extract_json_hash");
    let a = archive_path.to_str().unwrap();
    let filelist = write_filelist(&dir);
    let extra = [
        "--filelist",
        filelist.to_str().unwrap(),
        "--spec-mask",
        "0x1",
    ];

    let val = extract_json_report(&dir, a, "0x5ff91900", &extra);
    assert_eq!(val["name"], r"pc-w\lara.drm");
    assert_eq!(val["spec_mask"], "0x00000001");
}

#[test]
fn extract_json_reports_null_name_for_hash_target_without_filelist() {
    let (dir, archive_path) = create_synthetic_archive("extract_json_unnamed");
    let a = archive_path.to_str().unwrap();

    let val = extract_json_report(&dir, a, "0x5ff91900", &[]);
    assert!(val["name"].is_null());
}

#[test]
fn extract_json_rejects_stdout_payload_destinations() {
    let (_dir, archive_path) = create_synthetic_archive("extract_json_err");
    let a = archive_path.to_str().unwrap();

    for is_tty in [false, true] {
        let implicit_err =
            exec_args(&["extract", a, r"pc-w\lara.drm", "--json"], is_tty).unwrap_err();
        assert!(implicit_err.contains("cannot combine '--json' with stdout extraction"));

        let dash_err = exec_args(
            &["extract", a, r"pc-w\lara.drm", "-o", "-", "--json"],
            is_tty,
        )
        .unwrap_err();
        assert!(dash_err.contains("cannot combine '--json' with stdout extraction"));
    }
}

/// Writes an archive of three records sharing `hash`, each matching spec mask `1`.
fn create_shared_hash_archive(hash: u32) -> (TempDir, PathBuf) {
    let dir = TempDir::new("shared_hash");
    let records =
        [b"first_", b"second", b"third_"].map(|data| ArchiveRecord::stored(hash, 1, data));
    let archive_path = dir.join("bigfile.000");
    write_archive(&archive_path, Endian::Little, &records);
    (dir, archive_path)
}

#[test]
fn extract_single_part_reads_a_later_numbered_archive() {
    let dir = TempDir::new("extract_single_part");
    write_one_record_archives(&dir, &[("patch.000", 0x1000), ("patch.001", 0x2000)]);
    let later = dir.join("patch.001");
    let argv = ["extract", later.to_str().unwrap(), "0x00002000", "-o", "-"];

    let (out, _) = exec_args(&[argv.as_slice(), &["--single-part"]].concat(), false).unwrap();
    assert_eq!(out, b"payload");
}

#[test]
fn extract_engine_spec_match_reports_total_variants_when_no_record_passes_mask() {
    let (_dir, archive_path) = create_shared_hash_archive(0x1000);
    let archive = archive_path.to_str().unwrap();
    let argv = [
        "extract",
        archive,
        "0x00001000",
        "-o",
        "-",
        "--spec-mask",
        "2",
        "--engine-spec-match",
    ];

    let err = exec_args(&argv, false).unwrap_err();
    assert!(err.contains("3 total variants"), "{err}");
}

#[test]
fn extract_engine_spec_match_selects_landing_record() {
    let (_dir, archive_path) = create_shared_hash_archive(0x1000);
    let archive = archive_path.to_str().unwrap();
    let argv = [
        "extract",
        archive,
        "0x00001000",
        "-o",
        "-",
        "--spec-mask",
        "1",
    ];

    let (default_out, _) = exec_args(&argv, false).unwrap();
    assert_eq!(default_out, b"first_");

    let engine_argv = [argv.as_slice(), &["--engine-spec-match"]].concat();
    let (engine_out, _) = exec_args(&engine_argv, false).unwrap();
    assert_eq!(engine_out, b"second");
}
