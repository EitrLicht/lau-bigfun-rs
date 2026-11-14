//! The `hash` command.

use super::*;

#[test]
fn hash_command_writes_formatted_hashes_to_stdout() {
    let mut hash_buf = Vec::new();
    run_hash(
        &mut hash_buf,
        &[r"pc-w\lara.drm".to_string()],
        OutputMode::Text,
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(hash_buf).unwrap(),
        "0x5ff91900  pc-w\\lara.drm\n"
    );
}

#[test]
fn hash_json_emits_filename_hash_records() {
    let (out, err) = exec_args(
        &["hash", r"pc-w\lara.drm", r"pc-w\alister.drm", "--json"],
        false,
    )
    .unwrap();
    assert!(err.is_empty());
    let val: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        val,
        serde_json::json!({
            "schema": 2,
            "entries": [
                { "name": r"pc-w\lara.drm", "name_hash": "0x5ff91900" },
                { "name": r"pc-w\alister.drm", "name_hash": "0x1de5357f" },
            ],
        })
    );
}

#[test]
fn hash_patterns_match_without_filenames() {
    let (_dir, archive_path) = create_synthetic_archive("hash_patterns");
    let a = archive_path.to_str().unwrap();

    for filter in [
        ["--filter", "0x5ff91900"],
        ["--filter", "/5ff9"],
        ["--glob", "0x5ff9*"],
        ["--glob", "/0x5ff9*"],
    ] {
        let args = ["-q", "list", a, filter[0], filter[1]];
        let (out, _) = exec_args(&args, false).unwrap();
        assert!(String::from_utf8(out).unwrap().contains("0x5ff91900"));
    }
}
