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
    fn signal(sig: i32, handler: usize) -> usize;
    fn timer_create(clock: i32, event: *mut [u64; 8], timer: *mut usize) -> i32;
    fn timer_settime(timer: usize, flags: i32, new: *const [i64; 4], old: *mut [i64; 4]) -> i32;
    fn pause() -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
    fn flock(fd: i32, operation: i32) -> i32;
    fn dup2(old: i32, new: i32) -> i32;
    fn pipe(fds: *mut i32) -> i32;
    fn setpgid(pid: i32, pgid: i32) -> i32;
    fn syscall(number: i64, ...) -> i64;
    fn mkfifo(path: *const u8, mode: u32) -> i32;
    fn waitid(idtype: u32, id: u32, info: *mut [i32; 32], options: i32) -> i32;
}

const SIGCHLD: i32 = 17;
static CHILD_CHANGED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
extern "C" fn on_chld(_: i32) {
    CHILD_CHANGED.store(true, std::sync::atomic::Ordering::SeqCst);
}

const SIGUSR1: i32 = 10;

extern "C" fn on_usr1(_: i32) {}

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
        ["churn", path] => {
            // Progress (a file written) a thousand times over.
            for round in 0..1000 {
                std::fs::write(format!("{path}/round"), round.to_string()).unwrap();
            }
        }
        [binary, "poll-child"] => {
            // The parent only polls while its child makes progress.
            std::fs::create_dir_all("/work/churn").unwrap();
            let mut child = Command::new(binary)
                .args(["churn", "/work/churn"])
                .spawn()
                .unwrap();
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                std::thread::yield_now();
            };
            println!("POLLED status={:?}", status.code());
        }
        ["timer"] => unsafe {
            // A POSIX timer, one second on, interrupts the pause.
            signal(SIGUSR1, on_usr1 as usize);
            let mut event = [0u64; 8];
            event[1] = SIGUSR1 as u64; // sigev_signo; sigev_notify SIGEV_SIGNAL
            let mut timer = 0;
            assert_eq!(timer_create(1, &mut event, &mut timer), 0);
            assert_eq!(timer_settime(timer, 0, &[0, 0, 1, 0], std::ptr::null_mut()), 0);
            pause();
            std::process::exit(9);
        },
        [binary, "nap-child"] => {
            // The parent naps between looks at its child, for at most three
            // seconds.
            let mut child = Command::new(binary).arg("timer").spawn().unwrap();
            let status = (0..300).find_map(|_| {
                let status = child.try_wait().unwrap();
                std::thread::sleep(std::time::Duration::from_millis(10));
                status
            });
            println!("NAPPED status={:?}", status.map(|status| status.code()));
        }
        ["sleeper", ..] => loop {
            println!("SLEEPING");
            std::thread::sleep(std::time::Duration::from_secs(3600));
        },
        [binary, "kill-child"] => {
            use std::os::unix::process::ExitStatusExt;
            let mut child = Command::new(binary).arg("sleeper").spawn().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(10));
            child.kill().unwrap();
            let status = child.wait().unwrap();
            println!("KILLED code={:?} signal={:?}", status.code(), status.signal());
        }
        ["abort"] => std::process::abort(),
        [binary, "abort-child"] => {
            use std::os::unix::process::ExitStatusExt;
            let status = Command::new(binary).arg("abort").status().unwrap();
            println!("ABORTED code={:?} signal={:?}", status.code(), status.signal());
        }
        [binary, "leave-child", token] => {
            Command::new(binary).args(["sleeper", token]).spawn().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(10));
            println!("LEFT");
        }
        ["signal-parent"] => {
            println!("SIGNALING");
            unsafe { kill(std::os::unix::process::parent_id() as i32, SIGUSR1) };
        }
        [binary, "signal-parent"] => {
            let status = Command::new(binary).arg("signal-parent").status();
            println!("SIGNALED {status:?}");
        }
        [binary, "lock-beside-child"] => {
            use std::os::fd::AsRawFd;
            let _child = Command::new(binary).arg("sleeper").spawn().unwrap();
            let file = std::fs::File::create("/tmp/lock").unwrap();
            let locked = unsafe { flock(file.as_raw_fd(), 2) };
            println!("LOCKED {locked}");
        }
        ["pwd"] => println!("PWD {}", std::env::current_dir().unwrap().display()),
        [binary, "chdir-child"] => {
            let status = Command::new(binary).arg("pwd").current_dir("/tmp").status();
            println!("CHDIR {status:?}");
        }
        [binary, "redirected-child"] => {
            use std::os::fd::AsRawFd;
            let file = std::fs::File::create("/tmp/out").unwrap();
            assert_eq!(unsafe { dup2(file.as_raw_fd(), 1) }, 1);
            let status = Command::new(binary).arg("pwd").status();
            eprintln!("REDIRECTED {status:?}");
        }
        [binary, "pipe-child"] => {
            let mut fds = [0; 2];
            assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0);
            let status = Command::new(binary).arg("pwd").status();
            println!("PIPED {status:?}");
        }
        [binary, "inotify-child"] => {
            // inotify_init1(IN_CLOEXEC), through the system-call door.
            let number = if cfg!(target_arch = "aarch64") { 26 } else { 294 };
            assert!(unsafe { syscall(number, 0o2000000) } >= 0);
            let status = Command::new(binary).arg("pwd").status();
            println!("WATCHED {status:?}");
        }
        [binary, "fifo-child"] => {
            assert_eq!(unsafe { mkfifo(c"/tmp/fifo".as_ptr().cast(), 0o600) }, 0);
            let status = Command::new(binary).arg("pwd").status();
            println!("FIFO {status:?}");
        }
        [binary, "stdin-child"] => {
            let status = Command::new(binary).arg("pwd").status();
            println!("STDIN {status:?}");
        }
        [binary, "sigchld-child"] => {
            // The parent sleeps in `pause` until SIGCHLD says its child ended.
            unsafe { signal(SIGCHLD, on_chld as usize) };
            let mut child = Command::new(binary).args(["child", "5"]).spawn().unwrap();
            while !CHILD_CHANGED.load(std::sync::atomic::Ordering::SeqCst) {
                unsafe { pause() };
            }
            assert_eq!(child.wait().unwrap().code(), Some(5));
        }
        [binary, "ignored-sigchld-child"] => {
            unsafe { signal(SIGCHLD, 1) }; // SIG_IGN: children reap themselves
            let status = Command::new(binary).args(["child", "0"]).status();
            println!("IGNORED {status:?}");
        }
        [binary, "reaped-child"] => {
            let mut child = Command::new(binary).args(["child", "0"]).spawn().unwrap();
            let pid = child.id() as i32;
            assert_eq!(unsafe { kill(pid, 0) }, 0);
            child.wait().unwrap();
            assert_eq!(unsafe { kill(pid, 0) }, -1);
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(3)); // ESRCH
        }
        [binary, "group-wait-child"] => {
            let child = Command::new(binary).args(["child", "4"]).spawn().unwrap();
            let mut info = [0i32; 32];
            // P_PGID of the caller's group (0), WEXITED.
            assert_eq!(unsafe { waitid(2, 0, &mut info, 4) }, 0);
            assert_eq!((info[0], info[4], info[6]), (SIGCHLD, child.id() as i32, 4));
        }
        [binary, "setpgid-beside-child"] => {
            let _child = Command::new(binary).arg("sleeper").spawn().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(10));
            let moved = unsafe { setpgid(0, 0) };
            println!("MOVED {moved}");
        }
        [binary, "exit-while-waiting"] => {
            // A thread waits for a child that never ends while main returns.
            let mut child = Command::new(binary).arg("sleeper").spawn().unwrap();
            std::thread::spawn(move || child.wait());
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        ["many-threads", count] => {
            // A process alone on its machine makes more threads over its life
            // than any fixed table of them holds.
            for _ in 0..count.parse::<u32>().unwrap() {
                std::thread::spawn(|| {}).join().unwrap();
            }
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
    fn a_childs_progress_is_the_machines_progress() {
        // The parent makes no progress of its own while it polls; its child
        // does, for longer than the no-progress budget.
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        let polled = guest.command(
            "run",
            &[
                "--seed",
                "1",
                "--liveness-watchdog",
                "300000",
                "--",
                binary,
                "poll-child",
            ],
        );
        let polled = common::native::assert_success(polled);
        assert_eq!(stdout_line_with(&polled, "POLLED"), "POLLED status=Some(0)");
    }

    #[test]
    fn a_frozen_processs_timer_wakes_it_on_time() {
        // The child's only wake is a POSIX timer: the parent's naps reach
        // its deadline while the child is frozen, and it runs then.
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        let napped = common::native::assert_success(
            guest.command("run", &["--seed", "1", "--", binary, "nap-child"]),
        );
        assert_eq!(
            stdout_line_with(&napped, "NAPPED"),
            "NAPPED status=Some(Some(9))",
            "{}",
            String::from_utf8_lossy(&napped.stderr)
        );
    }

    #[test]
    fn a_child_killed_by_sigkill_is_reaped_as_killed() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        let killed = common::native::assert_success(
            guest.command("run", &["--seed", "1", "--", binary, "kill-child"]),
        );
        assert_eq!(
            stdout_line_with(&killed, "KILLED"),
            "KILLED code=None signal=Some(9)",
            "{}",
            String::from_utf8_lossy(&killed.stderr)
        );
    }

    #[test]
    fn a_child_that_aborts_dies_of_sigabrt_and_the_run_goes_on() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        let aborted = common::native::assert_success(
            guest.command("run", &["--seed", "1", "--", binary, "abort-child"]),
        );
        assert_eq!(
            stdout_line_with(&aborted, "ABORTED"),
            "ABORTED code=None signal=Some(6)",
            "{}",
            String::from_utf8_lossy(&aborted.stderr)
        );
    }

    #[test]
    fn a_root_that_exits_leaves_no_child_process_behind() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        // The child's host command line carries a token no other process
        // has.
        let token = format!("patina-leave-{}", std::process::id());
        let left = common::native::assert_success(
            guest.command("run", &["--seed", "1", "--", binary, "leave-child", &token]),
        );
        assert_eq!(stdout_line_with(&left, "LEFT"), "LEFT");
        let survivors: Vec<String> = std::fs::read_dir("/proc")
            .unwrap()
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let pid = entry.file_name().to_str()?.parse::<u32>().ok()?;
                let cmdline = std::fs::read(entry.path().join("cmdline")).ok()?;
                let found = cmdline
                    .split(|byte| *byte == 0)
                    .any(|arg| arg == token.as_bytes());
                found.then(|| pid.to_string())
            })
            .collect();
        assert!(survivors.is_empty(), "host processes left: {survivors:?}");
    }

    /// A run that stops as not modeled after the child process ran (its
    /// `marker` line is in the run's output), so a refused spawn cannot
    /// pass for it.
    fn stops_after_the_child_ran(guest: &common::native::Guest, mode: &str, marker: &str) {
        let binary = guest.binary.to_str().unwrap();
        let output = guest.command(
            "run",
            &["--seed", "1", "--format", "json", "--", binary, mode],
        );
        let envelope = json_envelope(&output);
        assert_eq!(
            (&envelope["result"], &envelope["stop"]["reason"]),
            (&"unsupported".into(), &"not_modeled".into()),
            "{mode}: {envelope:#}"
        );
        let text = format!(
            "{}{}{envelope}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(text.contains(marker), "{mode}: the child never ran: {text}");
    }

    #[test]
    fn a_childs_own_stop_ends_the_run_with_its_class() {
        // The child signals its parent, which no process may yet.
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        stops_after_the_child_ran(&guest, "signal-parent", "SIGNALING");
    }

    #[test]
    fn a_file_lock_beside_a_live_child_is_refused() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        stops_after_the_child_ran(&guest, "lock-beside-child", "SLEEPING");
        stops_after_the_child_ran(&guest, "setpgid-beside-child", "SLEEPING");
    }

    /// A child's end is its parent's `SIGCHLD`, which wakes a parent asleep
    /// in `pause`; children that would reap themselves are refused; a reaped
    /// child is gone; a wait for the caller's group finds the child; and a
    /// root that returns while a thread waits for a child ends cleanly.
    #[test]
    fn a_childs_end_reaches_its_parent_as_sigchld_and_waits() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        for mode in [
            "sigchld-child",
            "reaped-child",
            "group-wait-child",
            "exit-while-waiting",
        ] {
            common::native::assert_success(
                guest.command("run", &["--seed", "1", "--", binary, mode]),
            );
        }
        let output = guest.command(
            "run",
            &[
                "--seed",
                "1",
                "--format",
                "json",
                "--",
                binary,
                "ignored-sigchld-child",
            ],
        );
        let envelope = json_envelope(&output);
        assert_eq!(
            (&envelope["result"], &envelope["stop"]["reason"]),
            (&"unsupported".into(), &"not_modeled".into()),
            "{envelope:#}"
        );
    }

    /// A process alone on its machine makes more threads over its life than
    /// a table of a process's thread ids holds once it spawns.
    #[test]
    fn a_single_process_makes_any_number_of_threads() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        common::native::assert_success(
            guest.command("run", &["--seed", "1", "--", "many-threads", "70000"]),
        );
    }

    /// A spawn whose child would not see what its caller arranged: a `chdir`
    /// file action, a standard stream redirected or staged, a descriptor
    /// open across exec, state the caller made alone that the machine would
    /// share (an inotify instance, a FIFO). Each stops as not modeled rather than running a
    /// child that silently differs.
    #[test]
    fn a_spawn_the_child_would_not_see_as_arranged_is_not_modeled() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        let stdin = tempfile::tempdir().unwrap();
        let stdin = stdin.path().join("stdin");
        fs::write(&stdin, b"input").unwrap();
        for (extra, mode) in [
            (vec![], "chdir-child"),
            (vec![], "redirected-child"),
            (vec![], "pipe-child"),
            (vec![], "inotify-child"),
            (vec![], "fifo-child"),
            (vec!["--stdin", stdin.to_str().unwrap()], "stdin-child"),
        ] {
            let mut argv = vec!["--seed", "1", "--format", "json"];
            argv.extend(extra);
            argv.extend(["--", binary, mode]);
            let output = guest.command("run", &argv);
            let envelope = json_envelope(&output);
            assert_eq!(
                (&envelope["result"], &envelope["stop"]["reason"]),
                (&"unsupported".into(), &"not_modeled".into()),
                "{mode}: {envelope:#}"
            );
        }
    }

    /// A recording holds one timeline per child process; the same seed
    /// records the same bytes; each child replays its own timeline, so a
    /// replay of a self-spawn, a shared filesystem, a SIGKILL and an abort
    /// passes; and a child's timeline that no longer matches what the child
    /// does fails the replay.
    #[test]
    fn each_child_process_records_and_replays_its_own_timeline() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        let record = |mode: &str, name: &str| {
            let trace = guest.dir.path().join(name);
            let recorded = common::native::assert_success(guest.command(
                "run",
                &[
                    "--seed",
                    "3",
                    "--record",
                    trace.to_str().unwrap(),
                    "--",
                    binary,
                    mode,
                ],
            ));
            (trace, recorded)
        };
        let replay = |trace: &Path| {
            let output = guest.command("replay", &[trace.to_str().unwrap(), "--format", "json"]);
            json_envelope(&output)
        };
        for mode in ["parent", "relay", "kill-child", "abort-child"] {
            let (trace, recorded) = record(mode, &format!("{mode}.patina"));
            let bundle: serde_json::Value =
                serde_json::from_slice(&fs::read(&trace).unwrap()).unwrap();
            let processes = bundle["processes"].as_array().cloned().unwrap_or_default();
            assert!(
                !processes.is_empty()
                    && processes
                        .iter()
                        .all(|process| process["parent"] == 2 && process["timeline"].is_object()),
                "{mode}: {:#}",
                bundle["processes"]
            );
            let replayed = replay(&trace);
            assert_eq!(replayed["result"], "ok", "{mode}: {replayed:#}");
            let _ = recorded;
        }
        // The same seed records the same bytes.
        let (first, _) = record("parent", "first.patina");
        let (second, _) = record("parent", "second.patina");
        assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
        // `patina trace info` summarizes each child: the four the parent
        // spawned, each ended by its exit.
        let info = invoke_unchecked(
            env!("CARGO_BIN_EXE_patina"),
            guest.dir.path(),
            &["trace", "info", first.to_str().unwrap(), "--format", "json"],
        );
        let info = json_envelope(&info);
        let summarized = info["trace_info"]["processes"].as_array().unwrap();
        assert_eq!(
            summarized
                .iter()
                .map(|process| (process["pid"].as_i64(), process["end"].as_str()))
                .collect::<Vec<_>>(),
            [3, 4, 5, 6].map(|pid| (Some(pid), Some("exit"))),
            "{info:#}"
        );

        // A child's timeline with two decisions swapped: the child diverges.
        let mut bundle: serde_json::Value =
            serde_json::from_slice(&fs::read(&first).unwrap()).unwrap();
        let decisions = bundle["processes"][0]["timeline"]["decisions"]
            .as_array_mut()
            .unwrap();
        let swap = (0..decisions.len() - 1)
            .find(|&index| decisions[index][0] != decisions[index + 1][0])
            .expect("a child made two different decisions");
        decisions.swap(swap, swap + 1);
        let planted = guest.dir.path().join("planted.patina");
        fs::write(&planted, serde_json::to_vec(&bundle).unwrap()).unwrap();
        let diverged = replay(&planted);
        assert_eq!(
            (&diverged["result"], &diverged["stop"]["reason"]),
            (&"nondeterministic".into(), &"replay_divergence".into()),
            "{diverged:#}"
        );
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
