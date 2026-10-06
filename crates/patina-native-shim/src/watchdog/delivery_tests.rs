//! Real-delivery pairing for bounded sampler expiry and publication unit tests.
//! A permanently silent capture callback must fail, not look like host jitter.
use super::*;

static READY: AtomicUsize = AtomicUsize::new(0);

extern "C" fn running_target(_: *mut c_void) -> *mut c_void {
    let host = crate::hostapi::get();
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        assert_eq!(libc::sigaddset(&mut set, libc::SIGSYS), 0);
        assert_eq!(
            (host.host_pthread_sigmask)(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()),
            0
        );
    }
    READY.store(host_thread_self(), Ordering::Release);
    loop {
        std::hint::spin_loop();
    }
}

#[test]
fn terminal_sample_delivers_an_authenticated_pc_from_a_running_thread() {
    let name = std::thread::current().name().unwrap().to_owned();
    if std::env::var("PATINA_SAMPLE_DELIVERY_CHILD").as_deref() == Ok(&name) {
        // Isolated process: the production callback pins its target forever
        // and borrows SIGSYS; neither may leak into other libtest cases.
        platform::prepare_wait();
        let mut handle = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                crate::thread::spawn_host_thread(
                    &mut handle,
                    std::ptr::null(),
                    running_target,
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let ready_deadline = platform::monotonic_ms() + 5_000;
        while READY.load(Ordering::Acquire) == 0 {
            assert!(
                platform::monotonic_ms() < ready_deadline,
                "target never became ready"
            );
            platform::wait_ms(1);
        }
        let target = READY.load(Ordering::Acquire);
        assert_eq!(target, handle as usize);
        assert_ne!(target, host_thread_self());
        // Each attempt uses the unchanged production 50-wait delivery budget.
        // A late acknowledgement remains authenticated and may satisfy the
        // next attempt; eight deadlines, including a RET callback, fail closed.
        let pc = (0..8)
            .find_map(|_| match platform::sample_terminal_pc(target) {
                Ok(pc) => Some(pc),
                Err(SampleFailure::Deadline) => None,
                Err(reason) => panic!("sampler setup/delivery failed: {reason}"),
            })
            .expect("real signal delivery never acknowledged a PC");
        assert_ne!(pc, 0);
        assert_eq!(SAMPLE.target.load(Ordering::Acquire), target);
        assert_eq!(SAMPLE.pc.load(Ordering::Acquire), pc);
        println!("SAMPLER_DELIVERED pc={pc:#x}");
        std::process::exit(0);
    }
    use std::process::{Command, Stdio};
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &name, "--nocapture"])
        .env("PATINA_SAMPLE_DELIVERY_CHILD", &name)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("real-delivery child hung");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let pc = stdout
        .lines()
        .find_map(|line| line.strip_prefix("SAMPLER_DELIVERED pc=0x"))
        .expect("missing actual delivery proof");
    assert_ne!(usize::from_str_radix(pc, 16).unwrap(), 0);
}
