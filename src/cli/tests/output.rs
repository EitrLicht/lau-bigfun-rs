//! Stdout and stderr handling shared by the commands.

use super::*;

#[test]
fn failing_stderr_does_not_abort_file_extraction() {
    let (dir, archive_path) = create_synthetic_archive("stderr_fail");

    for (idx, kind) in [io::ErrorKind::BrokenPipe, io::ErrorKind::Other]
        .into_iter()
        .enumerate()
    {
        let extracted_file = dir.join(format!("from_failing_stderr_{idx}.drm"));
        let mut out_buf = Vec::new();
        let mut status = StatusReporter::new(FailingWriter(kind), false);
        run_extract(
            &mut out_buf,
            false,
            &mut status,
            &parse_extract_args(&[
                "extract",
                archive_path.to_str().unwrap(),
                r"pc-w\lara.drm",
                "-o",
                extracted_file.to_str().unwrap(),
            ]),
            OutputMode::Text,
        )
        .unwrap();
        assert!(out_buf.is_empty());
        assert_eq!(fs::read(&extracted_file).unwrap(), SYNTHETIC_PAYLOAD);
    }
}

#[test]
fn broken_stdout_pipe_is_tagged_as_stdout_broken_pipe() {
    let (_dir, archive_path) = create_synthetic_archive("stdout_pipe");
    let a = archive_path.to_str().unwrap();
    let args = parse_extract_args(&["extract", a, r"pc-w\lara.drm", "--raw"]);
    let mode = OutputMode::Text;

    let mut broken = BufWriter::new(FailingWriter(io::ErrorKind::BrokenPipe));
    let mut stderr_buf = Vec::new();
    let mut status = StatusReporter::new(&mut stderr_buf, false);
    let pipe_err = run_extract(&mut broken, false, &mut status, &args, mode).unwrap_err();
    assert!(is_stdout_broken_pipe(pipe_err.as_ref()));
    assert_eq!(
        String::from_utf8(stderr_buf).unwrap(),
        "1 variant(s) for 0x5ff91900\n"
    );

    let mut other = FailingWriter(io::ErrorKind::Other);
    let mut q_status = StatusReporter::new(Vec::new(), true);
    let other_err = run_extract(&mut other, false, &mut q_status, &args, mode).unwrap_err();
    assert!(!is_stdout_broken_pipe(other_err.as_ref()));

    let generic_pipe: Box<dyn std::error::Error> = Box::new(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "fifo write error",
    ));
    assert!(!is_stdout_broken_pipe(generic_pipe.as_ref()));
}

#[test]
fn stream_entry_to_stdout_tags_unbuffered_broken_pipe() {
    let (_dir, archive_path) = create_synthetic_archive("stdout_stream_pipe");
    let bf = Bigfile::open(&archive_path).unwrap();
    let mut broken = FailingWriter(io::ErrorKind::BrokenPipe);

    let err = stream_entry_to_stdout(&bf, &bf.entries()[0], true, &mut broken).unwrap_err();
    assert!(is_stdout_broken_pipe(err.as_ref()));
}

#[test]
fn write_json_stdout_tags_broken_pipe_errors() {
    for pretty in [false, true] {
        let mut unbuffered = FailingWriter(io::ErrorKind::BrokenPipe);
        let mut buffered = BufWriter::new(FailingWriter(io::ErrorKind::BrokenPipe));
        for res in [
            write_json_stdout(&mut unbuffered, pretty, &[1, 2, 3]),
            write_json_stdout(&mut buffered, pretty, &[1, 2, 3]),
        ] {
            let err: Box<dyn std::error::Error> = Box::new(res.unwrap_err());
            assert!(is_stdout_broken_pipe(err.as_ref()));
        }
        let mut other = FailingWriter(io::ErrorKind::Other);
        let other_err: Box<dyn std::error::Error> =
            Box::new(write_json_stdout(&mut other, pretty, &[1]).unwrap_err());
        assert!(!is_stdout_broken_pipe(other_err.as_ref()));
    }
}
