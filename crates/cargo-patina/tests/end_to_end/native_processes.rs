//! Native guests that spawn processes: an admitted program runs as a second
//! process of the guest's machine, under the same seed and clock.

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::super::*;

    // `parent BINARY` spawns BINARY (itself, admitted) four times, each child
    // exiting with its own code, and reaps each with `wait`; then a wait with
    // no child left. A child prints its pid and its parent's. `relay BINARY`
    // writes a file a child reads and reads the file it writes back.
    // `unadmitted`
    // spawns a program the run does not admit.
    const PROCESSES_SOURCE: &str = r#"
use std::process::Command;

unsafe extern "C" {
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["child", code] => {
            println!(
                "CHILD pid={} ppid={} code={code}",
                std::process::id(),
                std::os::unix::process::parent_id()
            );
            std::process::exit(code.parse().unwrap());
        }
        [binary, "parent"] => {
            let me = std::process::id();
            let mut pids = Vec::new();
            let mut codes = Vec::new();
            for code in [3, 0, 7, 42] {
                let mut child = Command::new(binary)
                    .args(["child", &code.to_string()])
                    .spawn()
                    .unwrap();
                pids.push(child.id());
                codes.push(child.wait().unwrap().code());
            }
            let mut status = 0;
            let left = unsafe { waitpid(-1, &mut status, 0) };
            let errno = std::io::Error::last_os_error().raw_os_error();
            println!("PARENT pid={me} children={pids:?} codes={codes:?} left={left} errno={errno:?}");
        }
        ["copy", path] => {
            let mut data = std::fs::read(format!("{path}/in")).unwrap();
            data.reverse();
            std::fs::write(format!("{path}/out"), data).unwrap();
        }
        [binary, "relay"] => {
            let dir = "/work/relay";
            std::fs::create_dir_all(dir).unwrap();
            std::env::set_current_dir("/work").unwrap();
            std::fs::write(format!("{dir}/in"), b"patina").unwrap();
            let status = Command::new(binary).args(["copy", dir]).status().unwrap();
            let out = String::from_utf8(std::fs::read(format!("{dir}/out")).unwrap()).unwrap();
            println!("RELAY status={:?} out={out}", status.code());
        }
        ["bursts"] => {
            // Two threads take turns computing, each burst well inside the
            // compute bound and the whole far beyond it.
            let burst = || {
                for _ in 0..6 {
                    let start = std::time::Instant::now();
                    let mut spin = 0u64;
                    while start.elapsed() < std::time::Duration::from_millis(300) {
                        spin = std::hint::black_box(spin.wrapping_add(1));
                    }
                    std::thread::yield_now();
                }
            };
            let other = std::thread::spawn(burst);
            burst();
            other.join().unwrap();
        }
        [binary, "busy-child"] => {
            let status = Command::new(binary).arg("bursts").status().unwrap();
            println!("BUSY status={:?}", status.code());
        }
        ["unadmitted"] => {
            let status = Command::new("/bin/true").status();
            println!("UNADMITTED {status:?}");
        }
        _ => panic!("unexpected arguments {args:?}"),
    }
}
"#;

    fn json_envelope(output: &Output) -> serde_json::Value {
        serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim()).unwrap_or_else(
            |error| {
                panic!(
                    "envelope was not one JSON object: {error}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stderr)
                )
            },
        )
    }

    #[test]
    fn an_admitted_self_spawn_runs_as_a_child_process_the_parent_reaps() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        let run = || {
            common::native::assert_success(
                guest.command("run", &["--seed", "1", "--", binary, "parent"]),
            )
        };
        let first = run();
        let parent = stdout_line_with(&first, "PARENT");
        // Each child's own exit code reaches its parent's wait; the children
        // take the machine's next pids, in spawn order; nothing is left to
        // wait for after.
        assert_eq!(
            parent,
            "PARENT pid=2 children=[3, 4, 5, 6] codes=[Some(3), Some(0), Some(7), Some(42)] left=-1 errno=Some(10)",
            "{}",
            String::from_utf8_lossy(&first.stderr)
        );
        // Each child sees its own pid and its parent's.
        let children: Vec<String> = String::from_utf8_lossy(&first.stdout)
            .lines()
            .filter(|line| line.starts_with("CHILD"))
            .map(str::to_owned)
            .collect();
        assert_eq!(
            children,
            [
                "CHILD pid=3 ppid=2 code=3",
                "CHILD pid=4 ppid=2 code=0",
                "CHILD pid=5 ppid=2 code=7",
                "CHILD pid=6 ppid=2 code=42",
            ]
        );
        // The same seed runs the same machine.
        assert_eq!(run().stdout, first.stdout);
    }

    #[test]
    fn a_child_process_shares_its_parents_filesystem() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        let relayed = common::native::assert_success(
            guest.command("run", &["--seed", "1", "--", binary, "relay"]),
        );
        assert_eq!(
            stdout_line_with(&relayed, "RELAY"),
            "RELAY status=Some(0) out=anitap",
            "{}",
            String::from_utf8_lossy(&relayed.stderr)
        );
    }

    #[test]
    fn a_parent_serving_a_computing_child_is_not_compute_bound() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        let busy = common::native::assert_success(guest.command(
            "run",
            &[
                "--seed",
                "1",
                "--compute-watchdog-ms",
                "1000",
                "--",
                binary,
                "busy-child",
            ],
        ));
        assert_eq!(stdout_line_with(&busy, "BUSY"), "BUSY status=Some(0)");
    }

    #[test]
    fn a_program_the_run_does_not_admit_is_still_refused() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let refused = guest.command(
            "run",
            &["--seed", "1", "--format", "json", "--", "unadmitted"],
        );
        let envelope = json_envelope(&refused);
        assert!(!refused.status.success(), "{envelope:#}");
        assert_eq!(
            (&envelope["result"], &envelope["stop"]["reason"]),
            (&"unsupported".into(), &"deny_trap".into()),
            "{envelope:#}"
        );
    }
}
