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
    fn sigaction(sig: i32, action: *const SigAction, old: *mut SigAction) -> i32;
    fn posix_spawnp(
        pid: *mut i32,
        file: *const std::ffi::c_char,
        actions: *const u8,
        attr: *const u8,
        argv: *const *const std::ffi::c_char,
        envp: *const *const std::ffi::c_char,
    ) -> i32;
    static environ: *const *const std::ffi::c_char;
}

/// glibc's `struct sigaction` (x86_64 and aarch64).
#[repr(C)]
struct SigAction {
    handler: usize,
    mask: [u64; 16],
    flags: i32,
    restorer: usize,
}

const SA_RESTART: i32 = 0x1000_0000;

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
            // compute bound and the whole beyond it, in host time (a plain
            // build's computation takes no virtual time).
            let burst = || {
                for _ in 0..6 {
                    let mut spin = 0u64;
                    for _ in 0..200_000_000u64 {
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
        ["segv"] => {
            println!("FAULTING");
            let address = std::hint::black_box(8usize);
            unsafe { (address as *mut u8).write_volatile(1) };
        }
        [binary, "segv-child"] => {
            use std::os::unix::process::ExitStatusExt;
            let status = Command::new(binary).arg("segv").status().unwrap();
            println!(
                "SEGV code={:?} signal={:?} core={}",
                status.code(),
                status.signal(),
                status.core_dumped()
            );
        }
        [binary, "abort-core-child"] => {
            use std::os::unix::process::ExitStatusExt;
            let status = Command::new(binary).arg("abort").status().unwrap();
            println!("ABORTCORE signal={:?} core={}", status.signal(), status.core_dumped());
        }
        [binary, "exit-then-stop"] => {
            // One child ends cleanly (its facts reach the run), then another
            // stops the run.
            assert_eq!(Command::new(binary).args(["child", "0"]).status().unwrap().code(), Some(0));
            let status = Command::new(binary).arg("signal-parent").status();
            println!("STOPPED {status:?}");
        }
        ["environ"] => {
            let mut entries = Vec::new();
            unsafe {
                let mut entry = environ;
                while !entry.is_null() && !(*entry).is_null() {
                    entries.push(std::ffi::CStr::from_ptr(*entry).to_string_lossy().into_owned());
                    entry = entry.add(1);
                }
            }
            println!("ENVIRON [{}]", entries.join(","));
        }
        [binary, "empty-envp-child"] => {
            let path = std::ffi::CString::new(binary).unwrap();
            let arg = c"environ";
            let argv = [path.as_ptr(), arg.as_ptr(), std::ptr::null()];
            let envp: [*const std::ffi::c_char; 1] = [std::ptr::null()];
            let mut pid = 0;
            let spawned = unsafe {
                posix_spawnp(&mut pid, path.as_ptr(), std::ptr::null(), std::ptr::null(), argv.as_ptr(), envp.as_ptr())
            };
            assert_eq!(spawned, 0);
            let mut status = 0;
            assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid);
        }
        [binary, "big-env-child"] => {
            let status = Command::new(binary).arg("pwd").env("BIG", "x".repeat(2 << 20)).status();
            println!("BIG {status:?}");
        }
        ["chatter", tag] => {
            use std::hash::BuildHasher;
            let drawn = std::collections::hash_map::RandomState::new().hash_one(0u8);
            println!("RAND{tag} {drawn}");
            for round in 0..4 {
                println!("{tag}{round}");
                std::thread::yield_now();
            }
        }
        [binary, "chatter-children"] => {
            let mut first = Command::new(binary).args(["chatter", "a"]).spawn().unwrap();
            let mut second = Command::new(binary).args(["chatter", "b"]).spawn().unwrap();
            first.wait().unwrap();
            second.wait().unwrap();
        }
        [binary, "thread-signal-child", how] => {
            let child = Command::new(binary).arg("sleeper").spawn().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(10));
            let pid = child.id() as i64;
            let (tgkill, tkill) = if cfg!(target_arch = "aarch64") { (131, 130) } else { (234, 200) };
            let sent = unsafe {
                if how == "tgkill" {
                    syscall(tgkill, pid, pid, SIGUSR1 as i64)
                } else {
                    syscall(tkill, pid, SIGUSR1 as i64)
                }
            };
            println!("THREAD-SIGNALED {sent} {:?}", std::io::Error::last_os_error().raw_os_error());
        }
        ["nested", binary] => {
            println!("NESTING");
            let status = Command::new(binary).args(["child", "0"]).status();
            println!("NESTED {status:?}");
        }
        [binary, "nested-child"] => {
            let status = Command::new(binary).args(["nested", binary]).status();
            println!("OUTER {status:?}");
        }
        [binary, "interrupted-wait", flags] => {
            // SIGCHLD's handler interrupts the wait for the child that sent it.
            let action = SigAction {
                handler: on_chld as usize,
                mask: [0; 16],
                flags: if flags == "restart" { SA_RESTART } else { 0 },
                restorer: 0,
            };
            assert_eq!(unsafe { sigaction(SIGCHLD, &action, std::ptr::null_mut()) }, 0);
            let child = Command::new(binary).args(["child", "5"]).spawn().unwrap();
            let pid = child.id() as i32;
            let mut status = 0;
            let waited = unsafe { waitpid(pid, &mut status, 0) };
            if waited == pid {
                println!("WAITED code={}", (status >> 8) & 0xff);
            } else {
                println!("WAITED {waited} errno={:?}", std::io::Error::last_os_error().raw_os_error());
            }
        }
        ["unadmitted"] => {
            let status = Command::new("/bin/true").status();
            println!("UNADMITTED {status:?}");
        }
        ["spin", _token] => {
            // Computes until something outside stops it.
            let mut spin = 0u64;
            loop {
                spin = std::hint::black_box(spin.wrapping_add(1));
            }
        }
        [binary, "spin-child", token] => {
            use std::os::unix::process::ExitStatusExt;
            let status = Command::new(binary).args(["spin", token]).status().unwrap();
            println!("SPUN signal={:?}", status.signal());
        }
        ["late-segv", dir] => {
            // Within one quantum (its parent waits): time passes, a file is
            // written then, and a host fault ends the process.
            std::thread::sleep(std::time::Duration::from_secs(5));
            std::fs::write(format!("{dir}/child"), b"late").unwrap();
            let address = std::hint::black_box(8usize);
            unsafe { (address as *mut u8).write_volatile(1) };
        }
        [binary, "late-segv-child"] => {
            let dir = "/work/late";
            std::fs::create_dir_all(dir).unwrap();
            Command::new(binary).args(["late-segv", dir]).status().unwrap();
            let child = std::fs::metadata(format!("{dir}/child")).unwrap().modified().unwrap();
            let now = std::time::SystemTime::now();
            std::fs::write(format!("{dir}/parent"), b"after").unwrap();
            let parent = std::fs::metadata(format!("{dir}/parent")).unwrap().modified().unwrap();
            println!("LATE now_after={} mtime_after={}", now >= child, parent >= child);
        }
        ["pause"] => unsafe {
            pause();
        },
        [binary, "stuck-child"] => {
            // Every task of the machine blocks for good.
            let status = Command::new(binary).arg("pause").status();
            println!("STUCK {status:?}");
        }
        ["idle"] => loop {
            std::thread::yield_now();
        },
        [binary, "idle-child"] => {
            // Both processes poll, and nothing progresses.
            let mut child = Command::new(binary).arg("idle").spawn().unwrap();
            while child.try_wait().unwrap().is_none() {
                std::thread::yield_now();
            }
        }
        [binary, "stop-beside-sleeper", token] => {
            let _sleeper = Command::new(binary).args(["sleeper", token]).spawn().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(10));
            let status = Command::new(binary).arg("signal-parent").status();
            println!("STOPPED {status:?}");
        }
        [binary, "frozen-child", token] => {
            // The child is frozen (asleep for an hour) while its parent
            // computes, then the parent waits for it.
            let mut child = Command::new(binary).args(["sleeper", token]).spawn().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(10));
            let mut spin = 0u64;
            for _ in 0..1_000_000_000u64 {
                spin = std::hint::black_box(spin.wrapping_add(1));
            }
            println!("WAITED {:?}", child.wait());
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

    /// The processes guest built plain (`--no-instrument`): computation
    /// takes host time only, and a compute bound is the host observer's.
    fn plain_guest() -> common::native::Guest {
        let dir = tempfile::tempdir().unwrap();
        let binary = build_facts_guest_with(
            dir.path(),
            "processes",
            PROCESSES_SOURCE,
            &["--no-instrument"],
        );
        common::native::Guest { dir, binary }
    }

    #[test]
    fn a_parent_serving_a_computing_child_is_not_compute_bound() {
        let guest = plain_guest();
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
        // Every mode is judged, so a run shows each one that went wrong.
        let mut wrong = Vec::new();
        for (extra, mode) in [
            (vec![], "chdir-child"),
            (vec![], "redirected-child"),
            (vec![], "pipe-child"),
            (vec![], "inotify-child"),
            (vec![], "fifo-child"),
            (vec!["--stdin", stdin.to_str().unwrap()], "stdin-child"),
            (vec![], "big-env-child"),
        ] {
            let mut argv = vec!["--seed", "1", "--format", "json"];
            argv.extend(extra);
            argv.extend(["--", binary, mode]);
            let output = guest.command("run", &argv);
            let envelope = json_envelope(&output);
            if (&envelope["result"], &envelope["stop"]["reason"])
                != (&"unsupported".into(), &"not_modeled".into())
            {
                wrong.push(format!("{mode}: {envelope:#}"));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
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

    /// When a child stops the run (after another ended cleanly), the root's
    /// own facts still reach it.
    #[test]
    fn a_childs_stop_keeps_the_roots_facts() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        let output = guest.command(
            "run",
            &[
                "--seed",
                "1",
                "--format",
                "json",
                "--",
                binary,
                "exit-then-stop",
            ],
        );
        let envelope = json_envelope(&output);
        assert_eq!(
            (&envelope["result"], &envelope["stop"]["reason"]),
            (&"unsupported".into(), &"not_modeled".into()),
            "{envelope:#}"
        );
        // The root's facts document: its CPU charges reach the run.
        assert!(envelope["cpu_charges"].is_object(), "{envelope:#}");
    }

    /// A child's host fault (a SIGSEGV its guest code raised) is a death by
    /// that signal its parent reaps, core dumped as a core signal's is; an
    /// abort's SIGABRT dumps core too; the run goes on.
    #[test]
    fn a_childs_host_fault_is_a_signal_death_its_parent_sees() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        let faulted = guest.command("run", &["--seed", "1", "--", binary, "segv-child"]);
        assert_eq!(
            (
                stdout_line_with(&faulted, "FAULTING"),
                stdout_line_with(&faulted, "SEGV")
            ),
            (
                "FAULTING".to_owned(),
                "SEGV code=None signal=Some(11) core=true".to_owned()
            ),
            "{}",
            String::from_utf8_lossy(&faulted.stderr)
        );
        assert!(faulted.status.success(), "{faulted:?}");
        let aborted = common::native::assert_success(
            guest.command("run", &["--seed", "1", "--", binary, "abort-core-child"]),
        );
        assert_eq!(
            stdout_line_with(&aborted, "ABORTCORE"),
            "ABORTCORE signal=Some(6) core=true"
        );
    }

    /// A child that ends mid-quantum (a host fault, an abort) or stops the
    /// run itself replays to the same end its recording did, its whole
    /// timeline consumed; a child timeline cut short fails the replay.
    #[test]
    fn a_child_that_ends_abruptly_replays_to_the_same_end() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        let outcome = |envelope: &serde_json::Value| {
            (
                envelope["result"].clone(),
                envelope["stop"]["reason"].clone(),
            )
        };
        let mut wrong = Vec::new();
        for mode in ["segv-child", "abort-child", "signal-parent"] {
            let trace = guest.dir.path().join(format!("{mode}.patina"));
            let recorded = json_envelope(&guest.command(
                "run",
                &[
                    "--seed",
                    "3",
                    "--format",
                    "json",
                    "--record",
                    trace.to_str().unwrap(),
                    "--",
                    binary,
                    mode,
                ],
            ));
            let replayed = json_envelope(
                &guest.command("replay", &[trace.to_str().unwrap(), "--format", "json"]),
            );
            if outcome(&recorded) != outcome(&replayed) || replayed["result"] == "nondeterministic"
            {
                wrong.push(format!(
                    "{mode}: recorded {recorded:#}\nreplayed {replayed:#}"
                ));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));

        // The faulting child's timeline, its last decision cut off.
        let trace = guest.dir.path().join("segv-child.patina");
        let mut bundle: serde_json::Value =
            serde_json::from_slice(&fs::read(&trace).unwrap()).unwrap();
        let decisions = bundle["processes"][0]["timeline"]["decisions"]
            .as_array_mut()
            .unwrap();
        assert!(decisions.len() > 1, "{:#}", bundle["processes"]);
        decisions.pop();
        let planted = guest.dir.path().join("truncated.patina");
        fs::write(&planted, serde_json::to_vec(&bundle).unwrap()).unwrap();
        let truncated = json_envelope(
            &guest.command("replay", &[planted.to_str().unwrap(), "--format", "json"]),
        );
        assert_eq!(
            (&truncated["result"], &truncated["stop"]["reason"]),
            (&"nondeterministic".into(), &"replay_divergence".into()),
            "{truncated:#}"
        );
    }

    /// A child spawned with an empty environment has none.
    #[test]
    fn a_child_spawned_with_an_empty_envp_has_no_environment() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        let output = guest.command("run", &["--seed", "1", "--", binary, "empty-envp-child"]);
        assert_eq!(
            stdout_line_with(&output, "ENVIRON"),
            "ENVIRON []",
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Each child draws from a stream of its own that the run's seed picks:
    /// another seed draws other values and may interleave the processes
    /// otherwise; the same seed runs the same machine.
    #[test]
    fn the_seed_varies_each_child_and_the_interleaving() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        let run = |seed: u32| {
            let output = common::native::assert_success(guest.command(
                "run",
                &[
                    "--seed",
                    &seed.to_string(),
                    "--",
                    binary,
                    "chatter-children",
                ],
            ));
            String::from_utf8_lossy(&output.stdout).into_owned()
        };
        let draws = |text: &str| -> Vec<String> {
            text.lines()
                .filter(|line| line.starts_with("RAND"))
                .map(str::to_owned)
                .collect()
        };
        let order = |text: &str| -> Vec<String> {
            text.lines()
                .filter(|line| !line.starts_with("RAND"))
                .map(str::to_owned)
                .collect()
        };
        let first = run(1);
        assert_eq!(run(1), first);
        assert_eq!(draws(&first).len(), 2, "{first}");
        let runs: Vec<String> = (2..10).map(run).collect();
        assert!(
            runs.iter().all(|other| {
                let (mine, theirs) = (draws(&first), draws(other));
                mine.iter().zip(&theirs).all(|(a, b)| a != b)
            }),
            "{first}\n{runs:#?}"
        );
        let orders: std::collections::BTreeSet<Vec<String>> = std::iter::once(&first)
            .chain(&runs)
            .map(|text| order(text))
            .collect();
        assert!(orders.len() > 1, "{orders:#?}");
    }

    /// What crosses processes past this slice stops by name: a signal to
    /// another process's thread (`tgkill`, `tkill`) and a spawn from a child.
    #[test]
    fn a_thread_signal_or_spawn_across_processes_is_not_modeled() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        stops_after_the_child_ran(&guest, "nested-child", "NESTING");
        let binary = guest.binary.to_str().unwrap();
        for how in ["tgkill", "tkill"] {
            let output = guest.command(
                "run",
                &[
                    "--seed",
                    "1",
                    "--format",
                    "json",
                    "--",
                    binary,
                    "thread-signal-child",
                    how,
                ],
            );
            let envelope = json_envelope(&output);
            assert_eq!(
                (&envelope["result"], &envelope["stop"]["reason"]),
                (&"unsupported".into(), &"not_modeled".into()),
                "{how}: {envelope:#}"
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("SLEEPING"),
                "{how}: {envelope:#}"
            );
        }
    }

    /// A wait SIGCHLD's handler interrupts still finds the child that sent
    /// it, as the kernel's wait looks for a zombie before a pending signal,
    /// with `SA_RESTART` or without.
    #[test]
    fn a_wait_sigchld_interrupts_finds_its_child() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        for flags in ["restart", "none"] {
            let output = guest.command(
                "run",
                &["--seed", "1", "--", binary, "interrupted-wait", flags],
            );
            assert_eq!(
                stdout_line_with(&output, "WAITED"),
                "WAITED code=5",
                "{flags}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    /// Host processes of a guest's machine whose command line holds every
    /// one of `args`.
    fn host_processes_with(args: &[&str]) -> Vec<i32> {
        std::fs::read_dir("/proc")
            .unwrap()
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let pid = entry.file_name().to_str()?.parse::<i32>().ok()?;
                let cmdline = std::fs::read(entry.path().join("cmdline")).ok()?;
                let held: Vec<&[u8]> = cmdline.split(|byte| *byte == 0).collect();
                // The supervisor's own command line names the guest's too.
                let supervisor = held.contains(&b"--seed".as_slice());
                (!supervisor && args.iter().all(|arg| held.contains(&arg.as_bytes())))
                    .then_some(pid)
            })
            .collect()
    }

    /// `patina run` of `args` (after the binary), with `outside` called
    /// with the supervisor's host pid at every poll until it answers that it
    /// is done (it may signal host processes meanwhile); the run's output,
    /// or `None` when it outlived `deadline` and was killed.
    fn run_with_outside(
        guest: &common::native::Guest,
        args: &[&str],
        env: &[(&str, &str)],
        deadline: std::time::Duration,
        mut outside: impl FnMut(u32) -> bool,
    ) -> Option<Output> {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_patina"));
        command
            .current_dir(common::native_workspace())
            .arg("run")
            .arg(&guest.binary)
            .args(args)
            .envs(env.iter().copied());
        let mut done = false;
        match common::output_until(&mut command, deadline, |pid| {
            if !done {
                done = outside(pid);
            }
            false
        }) {
            common::Deadlined::Finished(output) => Some(output),
            common::Deadlined::Killed { stdout, stderr } => {
                eprintln!(
                    "deadline exceeded\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr)
                );
                None
            }
        }
    }

    /// Once a host process holding `args` has run for a moment, send it
    /// `sig`: the `outside` of [`run_with_outside`].
    fn signal_once_running(args: &'static [&'static str], sig: i32) -> impl FnMut(u32) -> bool {
        let mut seen: Option<std::time::Instant> = None;
        move |_| {
            let found = host_processes_with(args);
            let Some(pid) = found.first() else {
                return false;
            };
            let since = *seen.get_or_insert_with(std::time::Instant::now);
            if since.elapsed() < std::time::Duration::from_millis(300) {
                return false;
            }
            unsafe { libc::kill(*pid, sig) };
            true
        }
    }

    /// A child's compute-bound stop is in the child's own timeline, so its
    /// replay stops where the recording did.
    #[test]
    fn a_childs_compute_stop_replays_where_it_stopped() {
        let guest = plain_guest();
        let binary = guest.binary.to_str().unwrap();
        let trace = guest.dir.path().join("spin.patina");
        let recorded = json_envelope(&guest.command(
            "run",
            &[
                "--seed",
                "3",
                "--format",
                "json",
                "--compute-watchdog-ms",
                "300",
                "--record",
                trace.to_str().unwrap(),
                "--",
                binary,
                "spin-child",
                "patina-compute",
            ],
        ));
        assert_eq!(recorded["result"], "timeout", "{recorded:#}");
        let bundle: serde_json::Value = serde_json::from_slice(&fs::read(&trace).unwrap()).unwrap();
        assert!(
            bundle["processes"][0]["metadata"]["compute_stop"].is_object(),
            "{:#}",
            bundle["processes"]
        );
        let replayed =
            json_envelope(&guest.command("replay", &[trace.to_str().unwrap(), "--format", "json"]));
        assert_eq!(
            (&replayed["result"], &replayed["stop"]["reason"]),
            (&recorded["result"], &recorded["stop"]["reason"]),
            "{replayed:#}"
        );
    }

    /// A replayed child that ends with recorded decisions left over has
    /// diverged.
    #[test]
    fn a_replayed_child_consumes_its_whole_timeline() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        let trace = guest.dir.path().join("parent.patina");
        common::native::assert_success(guest.command(
            "run",
            &[
                "--seed",
                "3",
                "--record",
                trace.to_str().unwrap(),
                "--",
                binary,
                "parent",
            ],
        ));
        let mut bundle: serde_json::Value =
            serde_json::from_slice(&fs::read(&trace).unwrap()).unwrap();
        let timeline = &mut bundle["processes"][0]["timeline"];
        let decisions = timeline["decisions"].as_array_mut().unwrap();
        let last = decisions.last().unwrap().clone();
        decisions.push(last);
        let end = timeline["lifecycle"]
            .as_array_mut()
            .unwrap()
            .last_mut()
            .unwrap();
        end["order"] = (end["order"].as_u64().unwrap() + 1).into();
        let planted = guest.dir.path().join("extra.patina");
        fs::write(&planted, serde_json::to_vec(&bundle).unwrap()).unwrap();
        let replayed = json_envelope(
            &guest.command("replay", &[planted.to_str().unwrap(), "--format", "json"]),
        );
        assert_eq!(
            (&replayed["result"], &replayed["stop"]["reason"]),
            (&"nondeterministic".into(), &"replay_divergence".into()),
            "{replayed:#}"
        );
    }

    /// A child the host ends from outside the run (an operator's signal, the
    /// out-of-memory killer's SIGKILL) did not die of its own doing: the run
    /// stops as the host's, and its parent never sees a death.
    #[test]
    fn a_child_ended_from_outside_the_run_stops_it() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        let mut wrong = Vec::new();
        for (sig, token) in [
            (libc::SIGTERM, "patina-term-child"),
            (libc::SIGKILL, "patina-kill-child"),
        ] {
            let args: &'static [&'static str] = Box::leak(Box::new(["spin", token]));
            let output = run_with_outside(
                &guest,
                &[
                    "--seed",
                    "1",
                    "--format",
                    "json",
                    "--compute-watchdog-ms",
                    "60000",
                    "--",
                    binary,
                    "spin-child",
                    token,
                ],
                &[],
                std::time::Duration::from_secs(60),
                signal_once_running(args, sig),
            )
            .expect("the run ended");
            let envelope = json_envelope(&output);
            if (&envelope["result"], &envelope["stop"]["reason"])
                != (&"internal".into(), &"host_kill".into())
                || String::from_utf8_lossy(&output.stdout).contains("SPUN")
            {
                wrong.push(format!("signal {sig}: {envelope:#}"));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    /// A child that dies mid-quantum leaves the machine at the time it
    /// reached: its parent's clock and stamps never go back before what the
    /// child wrote.
    #[test]
    fn a_childs_death_mid_quantum_keeps_the_time_it_reached() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        let output = common::native::assert_success(
            guest.command("run", &["--seed", "1", "--", binary, "late-segv-child"]),
        );
        assert_eq!(
            stdout_line_with(&output, "LATE"),
            "LATE now_after=true mtime_after=true",
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// `patina test`'s verdicts are judged again by the run: a request that
    /// admits a program the gate refuses (a host binary without the shim)
    /// still refuses its spawn.
    #[test]
    fn a_forged_admission_request_is_judged_again() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let digest = std::process::Command::new("sha256sum")
            .arg("/bin/true")
            .output()
            .unwrap();
        let digest = String::from_utf8(digest.stdout).unwrap();
        let digest = digest.split_whitespace().next().unwrap();
        let request = serde_json::json!([{
            "program": "/bin/true",
            "artifact": "/bin/true",
            "sha256": format!("sha256:{digest}"),
            "refused": null,
        }])
        .to_string();
        let output = run_with_outside(
            &guest,
            &["--seed", "1", "--format", "json", "--", "unadmitted"],
            &[("PATINA_RT_ADMIT_REQUEST", &request)],
            std::time::Duration::from_secs(60),
            |_| true,
        )
        .expect("the run ended");
        let envelope = json_envelope(&output);
        assert_eq!(
            (&envelope["result"], &envelope["stop"]["reason"]),
            (&"unsupported".into(), &"deny_trap".into()),
            "{envelope:#}"
        );
    }

    /// A root the host kills while a child computes: the run ends (the
    /// supervisor does not wait on output the child still holds) and no
    /// process of the machine outlives it.
    #[test]
    fn a_root_killed_from_outside_leaves_no_child_behind() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        let token = "patina-root-killed";
        let output = run_with_outside(
            &guest,
            &[
                "--seed",
                "1",
                "--format",
                "json",
                "--compute-watchdog-ms",
                "60000",
                "--",
                binary,
                "spin-child",
                token,
            ],
            &[],
            std::time::Duration::from_secs(30),
            {
                let mut child = signal_once_running(&["spin", "patina-root-killed"], 0);
                move |_| {
                    if !child(0) {
                        return false;
                    }
                    for pid in host_processes_with(&["spin-child", "patina-root-killed"]) {
                        unsafe { libc::kill(pid, libc::SIGKILL) };
                    }
                    true
                }
            },
        );
        let survivors = host_processes_with(&[token]);
        for pid in &survivors {
            unsafe { libc::kill(*pid, libc::SIGKILL) };
        }
        let output = output.expect("the run ended once its root was killed");
        let envelope = json_envelope(&output);
        assert_eq!(envelope["result"], "internal", "{envelope:#}");
        assert!(survivors.is_empty(), "host processes left: {survivors:?}");
    }

    /// A supervisor killed outright takes the machine's processes with it.
    #[test]
    fn a_supervisor_killed_leaves_no_process_behind() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        let token = "patina-supervisor-killed";
        let mut killed_at: Option<std::time::Instant> = None;
        let mut survived = Vec::new();
        let mut child = signal_once_running(&["spin", "patina-supervisor-killed"], 0);
        let _ = run_with_outside(
            &guest,
            &[
                "--seed",
                "1",
                "--compute-watchdog-ms",
                "60000",
                "--",
                binary,
                "spin-child",
                token,
            ],
            &[],
            std::time::Duration::from_secs(30),
            {
                let child = &mut child;
                let killed_at = &mut killed_at;
                let survived = &mut survived;
                move |supervisor| {
                    match *killed_at {
                        None if child(0) => {
                            unsafe { libc::kill(supervisor as i32, libc::SIGKILL) };
                            *killed_at = Some(std::time::Instant::now());
                        }
                        None => {}
                        Some(at) => {
                            let left = host_processes_with(&[token]);
                            if left.is_empty() {
                                return true;
                            }
                            if at.elapsed() > std::time::Duration::from_secs(5) {
                                *survived = left;
                                for pid in survived.iter() {
                                    unsafe { libc::kill(*pid, libc::SIGKILL) };
                                }
                                return true;
                            }
                        }
                    }
                    false
                }
            },
        );
        assert!(survived.is_empty(), "host processes left: {survived:?}");
    }

    /// The root's end, and a child's stop, end every other child: the
    /// recording says each was torn down, and no host process is left.
    #[test]
    fn the_machines_end_tears_down_every_child() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        let mut wrong = Vec::new();
        for (mode, token) in [
            ("leave-child", "patina-teardown-exit"),
            ("stop-beside-sleeper", "patina-teardown-stop"),
        ] {
            let trace = guest.dir.path().join(format!("{mode}.patina"));
            let output = guest.command(
                "run",
                &[
                    "--seed",
                    "1",
                    "--format",
                    "json",
                    "--record",
                    trace.to_str().unwrap(),
                    "--",
                    binary,
                    mode,
                    token,
                ],
            );
            let survivors = host_processes_with(&[token]);
            let bundle: serde_json::Value =
                serde_json::from_slice(&fs::read(&trace).unwrap_or_default()).unwrap_or_default();
            let sleeper = bundle["processes"][0]["end"].clone();
            if !survivors.is_empty() || sleeper != "teardown" {
                wrong.push(format!(
                    "{mode}: survivors {survivors:?}, sleeper end {sleeper}, {}",
                    json_envelope(&output)
                ));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    /// The same seed records the same bytes for a machine that kills, aborts,
    /// naps on a timer and polls, and reaches the same liveness verdict for
    /// one that blocks or idles across processes.
    #[test]
    fn the_same_seed_runs_the_same_machine_to_any_end() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        let mut wrong = Vec::new();
        for mode in ["kill-child", "abort-child", "nap-child", "poll-child"] {
            let traces: Vec<Vec<u8>> = ["a", "b"]
                .into_iter()
                .map(|run| {
                    let trace = guest.dir.path().join(format!("{mode}-{run}.patina"));
                    common::native::assert_success(guest.command(
                        "run",
                        &[
                            "--seed",
                            "5",
                            "--record",
                            trace.to_str().unwrap(),
                            "--",
                            binary,
                            mode,
                        ],
                    ));
                    fs::read(&trace).unwrap()
                })
                .collect();
            if traces[0] != traces[1] {
                wrong.push(format!("{mode}: the recordings differ"));
            }
        }
        for (mode, extra) in [
            ("stuck-child", vec![]),
            ("idle-child", vec!["--liveness-watchdog", "300000"]),
        ] {
            let verdicts: Vec<serde_json::Value> = (0..2)
                .map(|_| {
                    let mut argv = vec!["--seed", "5", "--format", "json"];
                    argv.extend(extra.iter().copied());
                    argv.extend(["--", binary, mode]);
                    let envelope = json_envelope(&guest.command("run", &argv));
                    serde_json::json!([envelope["result"], envelope["stop"]])
                })
                .collect();
            if verdicts[0] != verdicts[1] || verdicts[0][0] != "liveness" {
                wrong.push(format!("{mode}: {verdicts:#?}"));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    /// A child killed from outside while it is frozen is found when the
    /// machine next resumes it: the run stops as the host's.
    #[test]
    fn a_frozen_child_ended_from_outside_stops_the_run() {
        let guest = native_build::source_guest("processes", PROCESSES_SOURCE);
        let binary = guest.binary.to_str().unwrap();
        let token = "patina-frozen-killed";
        let output = run_with_outside(
            &guest,
            &[
                "--seed",
                "1",
                "--format",
                "json",
                "--compute-watchdog-ms",
                "60000",
                "--",
                binary,
                "frozen-child",
                token,
            ],
            &[],
            std::time::Duration::from_secs(60),
            signal_once_running(&["sleeper", "patina-frozen-killed"], libc::SIGKILL),
        )
        .expect("the run ended");
        let envelope = json_envelope(&output);
        assert_eq!(
            (&envelope["result"], &envelope["stop"]["reason"]),
            (&"internal".into(), &"host_kill".into()),
            "{envelope:#}"
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
