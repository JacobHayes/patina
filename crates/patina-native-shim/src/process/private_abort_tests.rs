//! Private host-abort signal-isolation tests.

use super::*;

extern "C" fn looping_handler(_: c_int) {
    loop {
        std::hint::spin_loop();
    }
}
extern "C" fn allocating_handler(_: c_int) {
    std::hint::black_box(unsafe { std::alloc::alloc(std::alloc::Layout::new::<u64>()) });
    looping_handler(0);
}

fn check(name: &str, handler: extern "C" fn(c_int)) {
    if std::env::var("PATINA_TEST_PRIVATE_ABORT").as_deref() == Ok(name) {
        // Install a REAL host disposition, not Linux's modeled front. That
        // front is a second defense and must not mask a broken fatal seam.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = handler as *const () as usize;
        unsafe {
            // Test only the fatal signal, not host core-dump I/O latency.
            assert_eq!(
                libc::setrlimit(
                    libc::RLIMIT_CORE,
                    &libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0
                    }
                ),
                0
            );
            assert_eq!(
                (hostapi::get().host_sigaction)(libc::SIGABRT, &action, std::ptr::null_mut()),
                0
            );
            let mut set: libc::sigset_t = std::mem::zeroed();
            assert_eq!(libc::sigemptyset(&mut set), 0);
            assert_eq!(libc::sigaddset(&mut set, libc::SIGABRT), 0);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()),
                0
            );
        }
        host_abort();
    }
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("PATINA_TEST_PRIVATE_ABORT", name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("private abort ran a nonreturning host handler: {name}");
        }
        std::thread::yield_now();
    };
    assert_eq!(status.signal(), Some(libc::SIGABRT), "{status}");
}

#[test]
fn looping_host_handler_cannot_run() {
    check(
        "private_abort_tests::looping_host_handler_cannot_run",
        looping_handler,
    );
}
#[test]
fn allocating_host_handler_cannot_run() {
    check(
        "private_abort_tests::allocating_host_handler_cannot_run",
        allocating_handler,
    );
}
