//! Native environment and working directory: modeled process state that
//! records, replays, and draws no filesystem fault of its own.

#[cfg(test)]
mod tests {
    use super::super::*;

    // One guest, three modes:
    //
    // no argument — guest-driven environment mutation. `setenv`/`unsetenv`
    //   succeed and every reader agrees: the `getenv` interposer, the `environ`
    //   array `std::env::vars` walks, and the seeded `--env` map share one source
    //   of truth. Mutations follow guest control flow, so only the initial `--env`
    //   set lives in the trace.
    // `cwd` — the working directory is modeled state: `run --cwd` sets the
    //   starting point, a relative path resolves against it, `set_current_dir`
    //   moves it, and `current_dir` reports the directory's current name.
    // `admin [absolute|relative]` — the working directory's handle is the shim's
    //   own, never a guest open: the configured `--cwd`, the root, and the
    //   directories `chdir` holds and lets go draw no fs fault and count toward no
    //   `--fs-crash-at` ordinal, so `open:1` and `close:1` are the guest's own.
    const ENV_CWD_SOURCE: &str = r#"
fn errno(error: std::io::Error) -> i32 {
    error.raw_os_error().unwrap_or(-1)
}

fn scan() -> String {
    let mut entries: Vec<String> = std::env::vars().map(|(k, v)| format!("{k}={v}")).collect();
    entries.sort();
    entries.join(",")
}

fn environment() {
    let seeded = std::env::var("SEEDED").unwrap_or_else(|_| "<missing>".to_string());
    println!("start seeded={seeded} scan=[{}]", scan());
    unsafe { std::env::set_var("ALPHA", "one") };
    println!("set alpha={} scan=[{}]", std::env::var("ALPHA").unwrap(), scan());
    unsafe { std::env::set_var("ALPHA", "two") };
    println!("overwrite alpha={} scan=[{}]", std::env::var("ALPHA").unwrap(), scan());
    unsafe { std::env::set_var("SEEDED", "replaced") };
    println!("reseed seeded={} scan=[{}]", std::env::var("SEEDED").unwrap(), scan());
    unsafe { std::env::remove_var("ALPHA") };
    println!("remove alpha_missing={} scan=[{}]", std::env::var_os("ALPHA").is_none(), scan());
    unsafe { std::env::remove_var("SEEDED") };
    unsafe { std::env::remove_var("NEVER_SET") };
    println!("drain scan=[{}]", scan());
}

fn cwd() {
    let start = std::env::current_dir().unwrap();
    std::fs::write("relative.txt", b"from the cwd").unwrap();
    let read_back = std::fs::read_to_string(start.join("relative.txt")).unwrap();
    std::fs::create_dir("nested").unwrap();
    std::env::set_current_dir("nested").unwrap();
    let moved = std::env::current_dir().unwrap();
    let parent_file = std::fs::read_to_string("../relative.txt").unwrap();
    std::env::set_current_dir("/").unwrap();
    let root = std::env::current_dir().unwrap();
    println!(
        "NATIVE_CWD start={} read={read_back} moved={} parent={parent_file} root={}",
        start.display(),
        moved.display(),
        root.display()
    );
}

fn admin(spelling: Option<&str>) {
    match spelling {
        Some("absolute") => println!("CWD_ADMIN stat={:?}", std::fs::metadata("/missing").map_err(errno).err()),
        Some("relative") => println!("CWD_ADMIN stat={:?}", std::fs::metadata("missing").map_err(errno).err()),
        _ => {}
    }
    let cwd = std::env::current_dir().map_err(errno);
    println!("CWD_ADMIN cwd={:?}", cwd.as_ref().map(|path| path.display().to_string()));
    if let Ok(start) = cwd {
        let _ = std::env::set_current_dir("/tmp");
        let _ = std::env::set_current_dir(start);
    }
    println!("CWD_ADMIN before-open");
    let created = std::fs::File::create("created");
    println!("CWD_ADMIN after-open created={}", created.is_ok());
    println!("CWD_ADMIN before-close");
    drop(created);
    println!("CWD_ADMIN after-close");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None => environment(),
        Some("cwd") => cwd(),
        Some("admin") => admin(args.get(1).map(String::as_str)),
        Some(other) => panic!("unknown mode {other}"),
    }
}
"#;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_env_and_cwd_are_modeled_process_state() {
        let guest = native_build::source_guest("env_cwd", ENV_CWD_SOURCE);
        let stdout = |output: &Output| String::from_utf8_lossy(&output.stdout).into_owned();
        let lines = |stream: &[u8], prefix: &str| -> Vec<String> {
            String::from_utf8_lossy(stream)
                .lines()
                .filter(|line| line.starts_with(prefix))
                .map(str::to_owned)
                .collect()
        };
        let run = |args: &[&str]| {
            let mut argv = vec!["--seed", "4"];
            argv.extend_from_slice(args);
            common::native::assert_success(guest.command("run", &argv))
        };

        // The guest environment starts empty; `--env` seeds it.
        let empty = stdout(&run(&[]));
        assert!(empty.contains("start seeded=<missing> scan=[]"), "{empty}");
        let (seeded, trace) = guest.assert_recorded(11, &["--env", "SEEDED=from-flag"]);
        let seeded = stdout(&seeded);
        for expected in [
            // Both readers see the seeded map from the first line.
            "start seeded=from-flag scan=[SEEDED=from-flag]",
            "set alpha=one scan=[ALPHA=one,SEEDED=from-flag]",
            "overwrite alpha=two scan=[ALPHA=two,SEEDED=from-flag]",
            // A guest overwrite of a seeded key wins over the seeded value.
            "reseed seeded=replaced scan=[ALPHA=two,SEEDED=replaced]",
            "remove alpha_missing=true scan=[SEEDED=replaced]",
            // Removing every key, one never set included, empties environ.
            "drain scan=[]",
        ] {
            assert!(seeded.contains(expected), "missing {expected:?}:\n{seeded}");
        }
        // Only the initial `--env` set is metadata; mutations leave no record.
        let trace_text = fs::read_to_string(&trace).unwrap();
        assert!(
            trace_text.contains("\"SEEDED\":\"from-flag\""),
            "{trace_text}"
        );
        assert!(
            !trace_text.contains("replaced") && !trace_text.contains("ALPHA"),
            "guest env mutations must not be recorded as trace events:\n{trace_text}"
        );

        // The default working directory is the root of the deterministic image;
        // `--cwd` moves the start, is recorded, and is restored flag-free.
        assert!(stdout(&run(&["--", "cwd"])).contains(
            "NATIVE_CWD start=/ read=from the cwd moved=/nested parent=from the cwd root=/"
        ));
        let cwd_trace = guest.dir.path().join("cwd.patina");
        let recorded = run(&[
            "--cwd",
            "/tmp",
            "--record",
            cwd_trace.to_str().unwrap(),
            "--",
            "cwd",
        ]);
        assert!(
            stdout(&recorded).contains(
                "NATIVE_CWD start=/tmp read=from the cwd moved=/tmp/nested parent=from the cwd root=/"
            ),
            "{}",
            stdout(&recorded)
        );
        let replayed =
            common::native::assert_success(guest.command("replay", &[cwd_trace.to_str().unwrap()]));
        assert_eq!(
            recorded.stdout, replayed.stdout,
            "replay must restore --cwd"
        );
        let trace_text = fs::read_to_string(&cwd_trace).unwrap();
        assert!(
            trace_text.contains("\"guest_cwd\":\"/tmp\""),
            "{trace_text}"
        );
        // A --cwd that is not an absolute directory of the image is refused by
        // name rather than answering ENOENT to every relative path.
        for (cwd, diagnostic) in [
            ("/no/such/dir", "--cwd \"/no/such/dir\" is not a directory"),
            ("relative/dir", "must be an absolute virtual path"),
        ] {
            common::native::assert_refused(
                guest.command("run", &["--seed", "3", "--cwd", cwd]),
                &[diagnostic],
            );
        }

        // Under a full fs error rate the configured directory installs and
        // `getcwd` answers it; with none configured, the root.
        for (args, cwd) in [
            (
                &["--cwd", "/tmp", "--fs-error-permille", "1000"][..],
                "/tmp",
            ),
            (&["--fs-error-permille", "1000"][..], "/"),
        ] {
            let mut args = args.to_vec();
            args.extend(["--", "admin"]);
            let output = run(&args);
            assert!(
                lines(&output.stdout, "CWD_ADMIN cwd=")
                    .contains(&format!("CWD_ADMIN cwd=Ok({cwd:?})")),
                "{args:?}: getcwd must answer {cwd}:\n{}",
                stdout(&output)
            );
        }

        // A relative path resolves through the working directory without a fault
        // draw of its own, so it meets exactly the faults its absolute spelling does.
        let absolute = run(&["--fs-error-permille", "1000", "--", "admin", "absolute"]);
        let relative = run(&["--fs-error-permille", "1000", "--", "admin", "relative"]);
        for (absolute, relative, prefix) in [
            (&absolute.stdout, &relative.stdout, "CWD_ADMIN stat="),
            (
                &absolute.stderr,
                &relative.stderr,
                "PATINA_FS_FAULT_REPORT ",
            ),
        ] {
            let expected = lines(absolute, prefix);
            assert!(!expected.is_empty(), "no {prefix} line");
            assert_eq!(
                expected,
                lines(relative, prefix),
                "relative vs absolute {prefix}"
            );
        }

        // `open:1` and `close:1` are the guest's own first open and close: each
        // incarnation reaches the call, and only the restarted one gets past it.
        for (args, before, after) in [
            (
                &["--fs-crash-at", "open:1"][..],
                "before-open",
                "after-open",
            ),
            (
                &["--fs-crash-at", "open:1", "--cwd", "/tmp"][..],
                "before-open",
                "after-open",
            ),
            (
                &["--fs-crash-at", "close:1"][..],
                "before-close",
                "after-close",
            ),
        ] {
            let mut args = args.to_vec();
            args.extend(["--", "admin"]);
            let output = run(&args);
            let count = |line: &str| lines(&output.stdout, &format!("CWD_ADMIN {line}")).len();
            assert_eq!(
                count(before),
                2,
                "{args:?}: both incarnations reach the call:\n{}",
                stdout(&output)
            );
            assert_eq!(
                count(after),
                1,
                "{args:?}: the crash fires at the guest's call:\n{}",
                stdout(&output)
            );
        }
    }
}
