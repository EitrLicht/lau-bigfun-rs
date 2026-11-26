//! The `list` command and its filters.

use super::*;

/// Writes an archive of two one-byte entries, returning it with its path.
fn create_two_entry_archive(prefix: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new(prefix);
    let archive_path = dir.join("bigfile.000");
    write_archive(
        &archive_path,
        Endian::Little,
        &[
            ArchiveRecord::stored(0x1, 1, b"a"),
            ArchiveRecord::stored(0x2, 1, b"b"),
        ],
    );
    (dir, archive_path)
}

#[test]
fn list_limit_zero_prints_every_entry() {
    let (_dir, archive_path) = create_two_entry_archive("list_unlimited");
    let a = archive_path.to_str().unwrap();
    let line_count = |limit| {
        let (out, _) = exec_args(&["list", a, "-l", limit], false).unwrap();
        String::from_utf8(out).unwrap().lines().count()
    };

    assert_eq!(line_count("1"), 1);
    assert_eq!(line_count("0"), 2);
}

#[test]
fn list_limit_reports_the_entries_it_hides() {
    let (_dir, archive_path) = create_two_entry_archive("list_hidden");
    let argv = ["list", archive_path.to_str().unwrap(), "-l", "1"];

    let (_, status) = exec_args(&argv, false).unwrap();
    assert!(
        status.contains("showing 1 of 2 matching entries; use --limit 0 to list all"),
        "{status}"
    );
}

#[test]
fn list_limit_covering_every_entry_reports_nothing_hidden() {
    let (_dir, archive_path) = create_two_entry_archive("list_all_shown");
    let argv = ["list", archive_path.to_str().unwrap(), "-l", "2"];

    let (_, status) = exec_args(&argv, false).unwrap();
    assert!(!status.contains("showing"), "{status}");
}

#[test]
fn list_limit_counts_only_entries_matching_the_filters() {
    let dir = TempDir::new("list_hidden_filtered");
    let archive_path = dir.join("bigfile.000");
    write_archive(
        &archive_path,
        Endian::Little,
        &[
            ArchiveRecord::stored(0x1, 1, b"a"),
            ArchiveRecord::stored(0x2, 1, b"b"),
            ArchiveRecord::stored(0x3, 2, b"c"),
        ],
    );
    let argv = [
        "list",
        archive_path.to_str().unwrap(),
        "-l",
        "1",
        "--spec-mask",
        "1",
    ];

    let (_, status) = exec_args(&argv, false).unwrap();
    assert!(
        status.contains("showing 1 of 2 matching entries"),
        "{status}"
    );
}

#[test]
fn list_json_reports_total_matching_beyond_the_limit() {
    let (_dir, archive_path) = create_two_entry_archive("list_json_total");
    let argv = ["list", archive_path.to_str().unwrap(), "-l", "1", "--json"];

    let (out, _) = exec_args(&argv, false).unwrap();
    let val: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(val["total_matching"], 2);
    assert_eq!(val["entries"].as_array().unwrap().len(), 1);
}

#[test]
fn list_warns_when_the_filelist_names_no_archive_hash() {
    let (dir, archive_path) = create_synthetic_archive("list_names_miss");
    let filelist = write_unrelated_filelist(&dir);
    let argv = [
        "list",
        archive_path.to_str().unwrap(),
        "--filelist",
        filelist.to_str().unwrap(),
    ];

    let (_, status) = exec_args(&argv, false).unwrap();
    assert!(status.contains(NAMES_MISS_WARNING), "{status}");
}

#[test]
fn list_does_not_warn_when_the_filelist_names_an_archive_hash() {
    let (dir, archive_path) = create_synthetic_archive("list_names_hit");
    let filelist = write_filelist(&dir);
    let argv = [
        "list",
        archive_path.to_str().unwrap(),
        "--filelist",
        filelist.to_str().unwrap(),
    ];

    let (_, status) = exec_args(&argv, false).unwrap();
    assert!(!status.contains("names none"), "{status}");
}

#[test]
fn list_does_not_warn_when_the_filelist_names_some_archive_hashes() {
    let dir = TempDir::new("list_names_partial");
    let archive_path = dir.join("bigfile.000");
    let lara = name_hash(r"pc-w\lara.drm").unwrap();
    write_archive(
        &archive_path,
        Endian::Little,
        &[
            ArchiveRecord::stored(lara, 1, b"a"),
            ArchiveRecord::stored(lara.wrapping_add(1), 1, b"b"),
        ],
    );
    let filelist = write_filelist(&dir);
    let argv = [
        "list",
        archive_path.to_str().unwrap(),
        "--filelist",
        filelist.to_str().unwrap(),
    ];

    let (_, status) = exec_args(&argv, false).unwrap();
    assert!(!status.contains("names none"), "{status}");
}

#[test]
fn list_escapes_control_characters_in_names() {
    let dir = TempDir::new("list_control_chars");
    let archive_path = dir.join("bigfile.000");
    let name = "pc-w\\esc\u{1b}]0;title\u{7}.drm";
    write_archive(
        &archive_path,
        Endian::Little,
        &[ArchiveRecord::stored(name_hash(name).unwrap(), 1, b"a")],
    );
    let filelist = dir.join("filelist.txt");
    fs::write(&filelist, format!("{name}\n")).unwrap();
    let argv = [
        "-q",
        "list",
        archive_path.to_str().unwrap(),
        "--filelist",
        filelist.to_str().unwrap(),
    ];

    let (out, _) = exec_args(&argv, false).unwrap();
    let out = String::from_utf8(out).unwrap();
    assert!(out.contains(r"pc-w\esc\u{1b}]0;title\u{7}.drm"), "{out:?}");
}

#[test]
fn list_separates_banner_to_stderr_from_stdout_entries() {
    let (dir, archive_path) = create_synthetic_archive("list_streams");
    let filelist = write_filelist(&dir);
    let argv = [
        "list",
        archive_path.to_str().unwrap(),
        "--filelist",
        filelist.to_str().unwrap(),
    ];

    let (stdout_buf, stderr_text) = exec_args(&argv, false).unwrap();
    let out_str = String::from_utf8(stdout_buf).unwrap();
    assert_eq!(stderr_text, "1 entries; segment_length=unsplit\n");
    assert_eq!(out_str.lines().count(), 1);
    assert!(out_str.contains("0x5ff91900"));
    assert!(out_str.contains(r"pc-w\lara.drm"));

    let quiet_argv: Vec<&str> = std::iter::once("-q").chain(argv).collect();
    let (q_out, q_err) = exec_args(&quiet_argv, false).unwrap();
    assert!(q_err.is_empty());
    assert_eq!(String::from_utf8(q_out).unwrap(), out_str);
}

#[test]
fn list_json_serializes_resolved_or_null_entry_names() {
    let (dir, archive_path) = create_synthetic_archive("list_json");
    let a = archive_path.to_str().unwrap();
    let filelist = write_filelist(&dir);
    let f = filelist.to_str().unwrap();

    let args = ["list", a, "--filelist", f, "--json"];
    let (out, err) = exec_args(&args, false).unwrap();
    assert_eq!(err, "1 entries; segment_length=unsplit\n");
    let val: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        val,
        serde_json::json!({
            "schema": 2,
            "total_matching": 1,
            "entries": [{
                "index": 0,
                "name_hash": "0x5ff91900",
                "name": r"pc-w\lara.drm",
                "size": 22,
                "stored_size": 22,
                "deflated_size": 0,
                "compressed": false,
                "sector_number": 1,
                "part_index": 0,
                "offset_in_part": 2048,
                "spec_flags": "0x00000001",
            }],
        })
    );

    let no_dict = ["-q", "list", a, "--json"];
    let (no_dict_out, _) = exec_args(&no_dict, false).unwrap();
    let no_dict_val: serde_json::Value = serde_json::from_slice(&no_dict_out).unwrap();
    assert!(no_dict_val["entries"][0]["name"].is_null());
}

#[test]
fn cli_glob_filters_list_entries() {
    let (dir, archive_path) = create_synthetic_archive("cli_glob_list");
    let a = archive_path.to_str().unwrap();
    let filelist = write_filelist(&dir);
    let f = filelist.to_str().unwrap();

    let (matched, _) = exec_args(
        &[
            "-q",
            "list",
            a,
            "--filelist",
            f,
            "-g",
            "**/vo/*.mul",
            "--glob",
            "pc-w/*.drm",
        ],
        false,
    )
    .unwrap();
    assert!(String::from_utf8(matched).unwrap().contains("0x5ff91900"));

    let unmatched_args = ["-q", "list", a, "--filelist", f, "--glob", "*.mul"];
    let (unmatched, _) = exec_args(&unmatched_args, false).unwrap();
    assert!(unmatched.is_empty());
}

#[test]
fn cli_unresolved_flag_selects_unnamed_entries() {
    let (dir, archive_path) = create_synthetic_archive("cli_unresolved");
    let a = archive_path.to_str().unwrap();
    let filelist = write_filelist(&dir);
    let f = filelist.to_str().unwrap();

    let named = ["-q", "list", a, "--filelist", f, "--unresolved"];
    let (with_dict, _) = exec_args(&named, false).unwrap();
    assert!(with_dict.is_empty());

    let (no_dict, _) = exec_args(&["-q", "list", a, "--unresolved"], false).unwrap();
    assert!(String::from_utf8(no_dict).unwrap().contains("0x5ff91900"));
}

#[test]
fn list_warns_when_no_filelist_is_given() {
    let (_dir, archive_path) = create_synthetic_archive("list_no_names");
    let a = archive_path.to_str().unwrap();

    let (_, err) = exec_args(&["list", a], false).unwrap();
    assert!(err.starts_with("warning: entries will be unnamed: no filelist given"));
}

#[test]
fn list_warns_when_filelist_supplies_no_paths() {
    let (dir, archive_path) = create_synthetic_archive("list_empty_names");
    let a = archive_path.to_str().unwrap();
    let filelist = dir.join("comments.txt");
    fs::write(&filelist, "# no paths here\n").unwrap();
    let f = filelist.to_str().unwrap();

    let (_, err) = exec_args(&["list", a, "--filelist", f], false).unwrap();
    assert!(err.starts_with("warning: entries will be unnamed: --filelist supplied no paths"));
}

#[test]
fn list_rejects_path_filter_without_filenames() {
    let (_dir, archive_path) = create_synthetic_archive("list_path_filter");
    let a = archive_path.to_str().unwrap();

    let err = exec_args(&["-q", "list", a, "--filter", "lara"], false).unwrap_err();
    assert!(err.starts_with("no filenames loaded"));
}

#[test]
fn list_path_filter_with_an_empty_filelist_says_it_supplied_no_paths() {
    let (dir, archive_path) = create_synthetic_archive("list_path_filter_empty_list");
    let filelist = dir.join("empty.txt");
    fs::write(&filelist, "").unwrap();
    let argv = [
        "-q",
        "list",
        archive_path.to_str().unwrap(),
        "--filelist",
        filelist.to_str().unwrap(),
        "--filter",
        "lara",
    ];

    let err = exec_args(&argv, false).unwrap_err();

    assert!(
        err.ends_with("--filelist supplied no paths, so filter on a hash such as 0x5ff91900"),
        "{err}"
    );
}

#[test]
fn list_rejects_substring_no_hash_label_contains_without_filenames() {
    let (_dir, archive_path) = create_synthetic_archive("list_non_label");
    let a = archive_path.to_str().unwrap();

    let err = exec_args(&["-q", "list", a, "--filter", "a-b"], false).unwrap_err();
    assert!(err.starts_with("no filenames loaded"));
}

#[test]
fn quiet_silences_missing_filenames_warning() {
    let (_dir, archive_path) = create_synthetic_archive("quiet_no_names");
    let a = archive_path.to_str().unwrap();

    let (_, err) = exec_args(&["-q", "list", a], false).unwrap();
    assert!(err.is_empty());
}
