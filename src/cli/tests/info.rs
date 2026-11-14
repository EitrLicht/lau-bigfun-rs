//! The `info` command.

use super::*;

#[test]
fn info_reports_dictionary_resolution_coverage() {
    let (dir, archive_path) = create_synthetic_archive("info_cov");

    let a = archive_path.to_str().unwrap();
    let filelist = write_filelist(&dir);
    let info_stdout = |args: &[&str]| String::from_utf8(exec_args(args, false).unwrap().0).unwrap();

    let named_out = info_stdout(&["info", a, "--filelist", filelist.to_str().unwrap()]);
    assert!(named_out.contains("Endianness:           little-endian"));
    assert!(named_out.contains("Total TOC entries:    1"));
    assert!(named_out.contains("Resolved names:       1 / 1 (100.0%)"));
    assert!(named_out.contains("Total stored bytes:   22\nTotal logical bytes:  22"));
    assert!(named_out.contains("  spec=0x00000001 -> 1 entries"));

    let empty_out = info_stdout(&["info", a]);
    assert!(empty_out.contains("Resolved names:       0 / 1 (0.0%)"));
}

#[test]
fn info_json_emits_structured_archive_summary() {
    let (dir, archive_path) = create_synthetic_archive("info_json");
    let a = archive_path.to_str().unwrap();
    let filelist = write_filelist(&dir);
    let f = filelist.to_str().unwrap();
    let args = ["--json", "info", a, "--filelist", f];

    let (compact, err) = exec_args(&args, false).unwrap();
    assert!(err.is_empty());
    assert_eq!(String::from_utf8_lossy(&compact).lines().count(), 1);
    let (pretty, _) = exec_args(&args, true).unwrap();
    assert!(String::from_utf8_lossy(&pretty).lines().count() > 1);

    let val: serde_json::Value = serde_json::from_slice(&compact).unwrap();
    let dir_str = archive_path.parent().unwrap().to_string_lossy();
    assert_eq!(
        val,
        serde_json::json!({
            "schema": 2,
            "archive": dir_str,
            "stem": "bigfile",
            "endian": "little-endian",
            "segment_length": null,
            "parts": [{ "index": 0, "path": a, "size": 4096 }],
            "total_entries": 1,
            "unique_hashes": 1,
            "resolved_hashes": 1,
            "resolved_percentage": 100.0,
            "compressed_entries": 0,
            "total_stored_bytes": 22,
            "total_logical_bytes": 22,
            "spec_counts": [{ "spec_flags": "0x00000001", "count": 1 }],
        })
    );
}

#[test]
fn info_json_reports_big_endian_archive_options() {
    let dir = TempDir::new("info_json_be");
    let archive_path = dir.join("bigfile.000");
    write_synthetic_archive(&archive_path, Endian::Big);
    let a = archive_path.to_str().unwrap();

    let (out, _) = exec_args(
        &["info", a, "--segment-length", "0x100000", "--json"],
        false,
    )
    .unwrap();
    let val: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(val["schema"], 2);
    assert_eq!(val["endian"], "big-endian");
    assert_eq!(val["segment_length"], 0x10_0000);
}
