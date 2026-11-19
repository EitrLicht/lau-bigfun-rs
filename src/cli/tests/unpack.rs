//! The `unpack` command and its output limit.

use super::*;

/// Writes an archive of 40 records that all share one sector, so its planned output is far larger
/// than the archive itself, and returns the paths of the archive and an output directory.
fn create_amplified_archive(dir: &TempDir) -> (PathBuf, PathBuf) {
    let records: Vec<_> = (1..=40)
        .map(|hash| FatRow {
            name_hash: hash,
            size: 2048,
            ..FatRow::default()
        })
        .collect();
    let archive_path = dir.join("bigfile.000");
    write_shared_sector_archive(&archive_path, &records);
    (archive_path, dir.join("out"))
}

#[test]
fn default_output_limit_is_sixteen_times_the_archive_on_disk() {
    let (_dir, path) = create_synthetic_archive("limit_default");
    let bigfile = Bigfile::open(&path).unwrap();
    let on_disk: u64 = bigfile.part_sizes().iter().sum();

    assert_eq!(output_limit(None, &bigfile), Some(on_disk * 16));
}

#[test]
fn unpack_warns_when_the_filelist_names_no_archive_hash() {
    let (dir, archive_path) = create_synthetic_archive("unpack_names_miss");
    let filelist = write_unrelated_filelist(&dir);
    let out = dir.join("out");
    let argv = [
        "unpack",
        archive_path.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "--dry-run",
        "--filelist",
        filelist.to_str().unwrap(),
    ];

    let (_, status) = exec_args(&argv, false).unwrap();
    assert!(status.contains(NAMES_MISS_WARNING), "{status}");
}

#[test]
fn unpack_warns_when_jobs_exceed_the_maximum() {
    let (dir, archive_path) = create_synthetic_archive("unpack_jobs_over_max");
    let out = dir.join("out");
    let argv = [
        "unpack",
        archive_path.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "--dry-run",
        "--jobs",
        "1000",
    ];

    let (_, status) = exec_args(&argv, false).unwrap();
    assert!(
        status.contains("warning: --jobs 1000 is above the maximum of 64; using 64"),
        "{status}"
    );
}

#[test]
fn unpack_default_limit_rejects_amplified_archive() {
    let dir = TempDir::new("default_limit");
    let (archive, out) = create_amplified_archive(&dir);
    let argv = [
        "unpack",
        archive.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ];

    let err = exec_args(&argv, false).unwrap_err();

    assert!(err.contains("--max-output-bytes"), "{err}");
    assert!(!out.exists());
}

#[test]
fn unpack_limit_of_zero_disables_the_check() {
    let dir = TempDir::new("no_limit");
    let (archive, out) = create_amplified_archive(&dir);
    let argv = [
        "unpack",
        archive.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "--max-output-bytes",
        "0",
    ];

    let (_, status) = exec_args(&argv, false).unwrap();

    assert!(status.contains("Unpacked 40 file(s)"), "{status}");
}

#[test]
fn unpack_explicit_limit_replaces_the_default() {
    let (dir, archive) = create_synthetic_archive("explicit_limit");
    let out = dir.join("out");
    let argv = [
        "unpack",
        archive.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "--max-output-bytes",
        "1",
    ];

    let err = exec_args(&argv, false).unwrap_err();

    assert!(err.contains("exceeds the limit of 1 bytes"), "{err}");
}

#[test]
fn unpack_json_emits_extraction_report() {
    let (dir, archive_path) = create_synthetic_archive("unpack_json");
    let a = archive_path.to_str().unwrap();
    let filelist = write_filelist(&dir);
    let f = filelist.to_str().unwrap();
    let out_dir = dir.join("unpacked_json");
    let out_str = out_dir.to_str().unwrap();

    let (out, err) = exec_args(
        &[
            "unpack",
            a,
            "-o",
            out_str,
            "--filelist",
            f,
            "-j",
            "1",
            "--json",
        ],
        false,
    )
    .unwrap();
    assert!(err.contains("Unpacked 1 file(s)"));
    let val: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        val,
        serde_json::json!({
            "schema": 2,
            "output": out_str,
            "extracted_files": 1,
            "extracted_bytes": 22,
            "resolved_entries": 1,
            "unknown_entries": 0,
            "skipped_entries": 0,
        })
    );
}

#[test]
fn cli_glob_filters_unpack_entries() {
    let (dir, archive_path) = create_synthetic_archive("cli_glob_unpack");
    let a = archive_path.to_str().unwrap();
    let filelist = write_filelist(&dir);
    let f = filelist.to_str().unwrap();
    let out_dir = dir.join("unpacked_glob");
    let out_str = out_dir.to_str().unwrap();

    let (_, u_err) = exec_args(
        &[
            "unpack",
            a,
            "-o",
            out_str,
            "--filelist",
            f,
            "--glob",
            "pc-w/*.drm",
            "-j",
            "1",
        ],
        false,
    )
    .unwrap();
    assert!(u_err.contains("Unpacked 1 file(s)"));
    assert!(out_dir.join("pc-w/lara.drm").is_file());
}

#[test]
fn unpack_rejects_path_glob_without_filenames() {
    let (dir, archive_path) = create_synthetic_archive("unpack_path_glob");
    let a = archive_path.to_str().unwrap();
    let out_dir = dir.join("unpacked");
    let args = [
        "-q",
        "unpack",
        a,
        "-o",
        out_dir.to_str().unwrap(),
        "--glob",
        "pc-w/*.drm",
    ];

    let err = exec_args(&args, false).unwrap_err();
    assert!(err.starts_with("no filenames loaded"));
    assert!(!out_dir.exists());
}

#[test]
fn unpack_warns_when_no_filenames_are_loaded() {
    let (dir, archive_path) = create_synthetic_archive("unpack_no_names");
    let a = archive_path.to_str().unwrap();
    let out_dir = dir.join("unpacked");
    let args = ["unpack", a, "-o", out_dir.to_str().unwrap(), "-j", "1"];

    let (_, err) = exec_args(&args, false).unwrap();
    assert!(err.starts_with("warning: entries will be unnamed"));
    assert!(out_dir.join("__unknown/5ff91900.bin").is_file());
}

#[test]
fn unpack_dry_run_prints_the_plan_without_writing() {
    let (dir, archive) = create_synthetic_archive("dry_run_text");
    let out = dir.join("out");
    let argv = [
        "unpack",
        archive.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "--dry-run",
    ];

    let (stdout, _) = exec_args(&argv, false).unwrap();

    let stdout = String::from_utf8(stdout).unwrap();
    assert!(
        stdout.starts_with("Would unpack 1 file(s) (22 bytes)"),
        "{stdout}"
    );
    assert!(!out.exists());
}

#[test]
fn unpack_dry_run_json_marks_the_report() {
    let (dir, archive) = create_synthetic_archive("dry_run_json");
    let out = dir.join("out");
    let argv = [
        "unpack",
        archive.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "--dry-run",
        "--json",
    ];

    let (stdout, _) = exec_args(&argv, false).unwrap();

    let val: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(val["dry_run"], serde_json::json!(true));
    assert_eq!(val["extracted_bytes"], serde_json::json!(22));
}

#[test]
fn unpack_dry_run_warns_when_over_the_limit() {
    let dir = TempDir::new("dry_run_limit");
    let (archive, out) = create_amplified_archive(&dir);
    let argv = [
        "unpack",
        archive.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "--dry-run",
    ];

    let (_, status) = exec_args(&argv, false).unwrap();

    let warning = "warning: planned output of 81920 bytes exceeds the limit";
    assert!(status.contains(warning), "{status}");
}

#[test]
fn unpack_dry_run_summary_is_not_silenced_by_quiet() {
    let (dir, archive) = create_synthetic_archive("dry_run_quiet");
    let out = dir.join("out");
    let argv = [
        "-q",
        "unpack",
        archive.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "--dry-run",
    ];

    let (stdout, _) = exec_args(&argv, false).unwrap();

    let stdout = String::from_utf8(stdout).unwrap();
    assert!(stdout.starts_with("Would unpack 1 file(s)"), "{stdout}");
}
