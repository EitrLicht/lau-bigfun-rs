//! Argument parsing, flag conflicts and command dispatch.

use super::*;

#[test]
fn cli_endian_flag_supports_big_endian_archives() {
    let dir = TempDir::new("cli_big_endian");
    let archive_path = dir.join("bigfile.000");
    write_synthetic_archive(&archive_path, Endian::Big);
    let a = archive_path.to_str().unwrap();

    let (info_out, _) = exec_args(&["info", a], false).unwrap();
    let info_str = String::from_utf8(info_out).unwrap();
    assert!(info_str.contains("Endianness:           big-endian"));

    let be_args = ["extract", a, "--endian", "be", r"pc-w\lara.drm"];
    let (ext_out, _) = exec_args(&be_args, false).unwrap();
    assert_eq!(ext_out, SYNTHETIC_PAYLOAD);

    let le_err = exec_args(&["info", a, "--endian", "le"], false);
    assert!(le_err.is_err());
}

#[test]
fn ambiguous_endian_error_names_the_flag() {
    let dir = TempDir::new("ambiguous_endian");
    let archive_path = dir.join("bigfile.000");
    fs::write(&archive_path, build_ambiguous_part0()).unwrap();

    let argv = ["info", archive_path.to_str().unwrap()];
    let err = exec_args(&argv, false).unwrap_err();
    assert!(
        err.contains("with --endian little or --endian big"),
        "{err}"
    );
}

#[test]
fn undetermined_segment_length_error_names_single_part() {
    let dir = TempDir::new("undetermined_stride");
    write_one_record_archives(&dir, &[("bigfile.000", 0x1000), ("bigfile.001", 0x2000)]);
    let first_part = dir.join("bigfile.000");

    let argv = ["info", first_part.to_str().unwrap()];
    let err = exec_args(&argv, false).unwrap_err();
    assert!(err.contains("--single-part"), "{err}");
}

#[test]
fn single_part_conflicts_with_segment_length() {
    let argv = ["info", "a", "--single-part"];
    assert!(parse_args(&argv).is_ok());
    assert!(parse_args(&[argv.as_slice(), &["--segment-length", "0x100000"]].concat()).is_err());
}

#[test]
fn global_quiet_flag_suppresses_stderr_before_or_after_subcommand() {
    let (dir, archive_path) = create_synthetic_archive("quiet_flag");
    let archive_str = archive_path.to_str().unwrap();

    for (idx, flag_before) in [(1usize, true), (2usize, false)] {
        let out_file = dir.join(format!("quiet_{idx}.drm"));
        let out_str = out_file.to_str().unwrap();
        let args: Vec<&str> = if flag_before {
            vec![
                "-q",
                "extract",
                archive_str,
                r"pc-w\lara.drm",
                "-o",
                out_str,
            ]
        } else {
            vec![
                "extract",
                archive_str,
                r"pc-w\lara.drm",
                "-o",
                out_str,
                "--quiet",
            ]
        };
        let (out, err) = exec_args(&args, false).unwrap();
        assert!(out.is_empty());
        assert!(err.is_empty());
        assert_eq!(fs::read(&out_file).unwrap(), SYNTHETIC_PAYLOAD);
    }
}

#[test]
fn cli_subcommands_dispatch_through_execute_cli() {
    let (dir, archive_path) = create_synthetic_archive("cli_dispatch");
    let a = archive_path.to_str().unwrap();
    let filelist = write_filelist(&dir);
    let f = filelist.to_str().unwrap();

    let list_args = [
        "list",
        a,
        "--filelist",
        f,
        "--spec-mask",
        "0x1",
        "--filter",
        "lara",
        "--limit",
        "1",
    ];
    let (list_out, list_err) = exec_args(&list_args, false).unwrap();
    assert_eq!(list_err, "1 entries; segment_length=unsplit\n");
    assert!(String::from_utf8(list_out).unwrap().contains("0x5ff91900"));

    let (filtered_out, _) = exec_args(&["-q", "list", a, "--spec-mask", "0x2"], false).unwrap();
    assert!(filtered_out.is_empty());

    let out_dir = dir.join("unpacked");
    let out_str = out_dir.to_str().unwrap();
    let (u_out, u_err) = exec_args(&["unpack", a, "-o", out_str, "-j", "1"], false).unwrap();
    assert!(u_out.is_empty());
    assert!(u_err.contains("Unpacked 1 file(s)"));
}

#[test]
fn numeric_parsers_accept_decimal_or_hex_values() {
    assert_eq!(parse_uint_auto::<u32>("0x5ff91900").unwrap(), 0x5FF9_1900);
    assert_eq!(parse_uint_auto::<u32>("0X00000003").unwrap(), 3);
    assert_eq!(parse_uint_auto::<u32>("42").unwrap(), 42);
    assert!(
        parse_uint_auto::<u32>("0xZZZ")
            .unwrap_err()
            .contains("invalid hex u32")
    );
    assert!(
        parse_uint_auto::<u32>("0x100000000")
            .unwrap_err()
            .contains("u32 '0x100000000' out of range")
    );

    assert_eq!(parse_uint_auto::<u64>("0x7ff00000").unwrap(), 0x7FF0_0000);
    assert_eq!(parse_uint_auto::<u64>("1048576").unwrap(), 1_048_576);
    assert!(
        parse_uint_auto::<u64>("-1")
            .unwrap_err()
            .contains("invalid u64")
    );
}

#[test]
fn parse_target_hash_distinguishes_hex_hashes_from_paths() {
    assert_eq!(
        VariantLayout::from(CliVariantLayout::SpecDir),
        VariantLayout::SpecSubdirWhenAmbiguous
    );
    assert_eq!(
        VariantLayout::from(CliVariantLayout::AlwaysSpecDir),
        VariantLayout::AlwaysSpecSubdir
    );
    assert_eq!(
        VariantLayout::from(CliVariantLayout::Suffix),
        VariantLayout::FilenameSuffix
    );

    assert_eq!(
        parse_target_hash("0x5ff91900").unwrap(),
        (0x5FF9_1900, None)
    );
    assert_eq!(
        parse_target_hash("0x").unwrap(),
        (name_hash("0x").unwrap(), Some("0x"))
    );
    assert_eq!(
        parse_target_hash(r"pc-w\lara.drm").unwrap(),
        (0x5FF9_1900, Some(r"pc-w\lara.drm"))
    );
    assert!(parse_target_hash("pc-w\\\u{0100}.drm").is_err());
}

#[test]
fn cli_extract_engine_spec_match_conflicts_with_variant() {
    let argv = ["extract", "a", "b", "--spec-mask", "1", "--variant", "0"];
    assert!(parse_args(&argv).is_ok());
    assert!(parse_args(&[argv.as_slice(), &["--engine-spec-match"]].concat()).is_err());
}

#[test]
fn cli_engine_spec_match_requires_spec_mask() {
    let argv = ["unpack", "archive", "-o", "out"];
    let err = parse_args(&[argv.as_slice(), &["--engine-spec-match"]].concat()).unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    assert!(
        parse_args(
            &[
                argv.as_slice(),
                &["--engine-spec-match", "--spec-mask", "0x1"]
            ]
            .concat()
        )
        .is_ok()
    );
}

#[test]
fn cli_glob_conflicts_with_substring_filter() {
    let (_dir, archive_path) = create_synthetic_archive("cli_glob_err");
    let a = archive_path.to_str().unwrap();

    for flags in [
        ["--filter", "lara", "--glob", "*.drm"].as_slice(),
        ["--filter", "lara", "--unresolved"].as_slice(),
        ["--glob", "*.drm", "--unresolved"].as_slice(),
    ] {
        let mut argv = vec!["list", a];
        argv.extend_from_slice(flags);
        assert!(parse_args(&argv).is_err());
    }

    let bad_glob = exec_args(&["list", a, "--glob", "[unclosed"], false);
    assert!(
        bad_glob
            .unwrap_err()
            .contains("invalid glob pattern '[unclosed'")
    );
}
