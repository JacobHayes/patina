//! Native `--stdin`: supplied standard input is a recorded, faultable file.

#[cfg(test)]
mod tests {
    use super::super::*;

    // `sort` reads standard input to its end, then prints its lines sorted, what
    // descriptor 0 is, and what a rewind and a write on it answer: a supplied
    // input is a regular file of its bytes (seekable, read-only), the default
    // an empty pipe. `read` reads it and prints the outcome alone.
    const STDIN_SOURCE: &str = r#"
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::FromRawFd;

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    // SAFETY: descriptor 0 is the process's standard input; ManuallyDrop keeps it open.
    let mut stdin = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(0) });
    let mut text = String::new();
    let read = stdin.read_to_string(&mut text).map_err(|error| error.raw_os_error());
    if mode == "read" {
        println!("STDIN_READ {:?}", read.map(|_| text));
        return;
    }
    let mut lines: Vec<&str> = text.lines().collect();
    lines.sort_unstable();
    let metadata = stdin.metadata().unwrap();
    let rewound = stdin.seek(SeekFrom::Start(0)).map_err(|error| error.raw_os_error());
    let mut first = [0u8; 1];
    let reread = stdin.read(&mut first).map(|_| first[0] as char).map_err(|error| error.raw_os_error());
    let write = stdin.write(b"x").map_err(|error| error.raw_os_error());
    println!(
        "STDIN_SORTED lines={lines:?} file={} len={} rewound={rewound:?} reread={reread:?} write={write:?}",
        metadata.is_file(),
        metadata.len()
    );
}
"#;

    #[test]
    fn supplied_stdin_is_a_recorded_faultable_file_a_replay_restores() {
        let guest = native_build::source_guest("stdin", STDIN_SOURCE);
        let dir = guest.dir.path();
        let input = dir.join("input.txt");
        fs::write(&input, b"pear\napple\nfig\n").unwrap();
        let input = input.to_str().unwrap();
        let line = |output: &Output| stdout_line_with(output, "STDIN_");

        // Without --stdin, descriptor 0 is the empty pipe it always was.
        let empty = common::native::assert_success(guest.command("run", &["--seed", "1"]));
        assert!(
            line(&empty).contains("lines=[] file=false"),
            "{}",
            line(&empty)
        );

        // With it, the guest reads the bytes from a read-only regular file that
        // rewinds; the run records them, and a flag-free replay restores them.
        let (recorded, trace) = guest.assert_recorded(1, &["--stdin", input]);
        assert_eq!(
            line(&recorded),
            "STDIN_SORTED lines=[\"apple\", \"fig\", \"pear\"] file=true len=15 \
             rewound=Ok(0) reread=Ok('p') write=Err(Some(9))"
        );
        let trace = trace.to_str().unwrap();

        let replayed = common::native::assert_success(guest.command("replay", &[trace]));
        assert_eq!(line(&replayed), line(&recorded));

        // Reads of it are filesystem reads, so filesystem faults land on them,
        // and the faulted run replays flag-free too.
        let (faulted, _) = guest.assert_recorded(
            1,
            &[
                "--stdin",
                input,
                "--fs-error-permille",
                "1000",
                "--",
                "read",
            ],
        );
        assert!(
            line(&faulted).starts_with("STDIN_READ Err("),
            "{}",
            line(&faulted)
        );

        // More than the trace records is refused before the guest runs.
        let oversize = dir.join("oversize.bin");
        fs::write(
            &oversize,
            vec![b'x'; patina_dst_runtime::GUEST_STDIN_MAX_BYTES + 1],
        )
        .unwrap();
        common::native::assert_refused(
            guest.command(
                "run",
                &["--seed", "1", "--stdin", oversize.to_str().unwrap()],
            ),
            &[],
        );
    }
}
