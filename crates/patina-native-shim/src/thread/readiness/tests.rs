use super::*;
use crate::thread::signals::tests::*;
use crate::thread::signals::{SIG_SETMASK, SIGSET_BYTES, bit, read_mask};
use std::sync::atomic::Ordering;

#[test]
fn poll_ppoll_select_pselect_never_restart_and_restore_temporary_masks() {
    isolated(|| {
        action(true);
        let [rd, wr] = pipe();
        let me = current_task();
        let mut pollfd = PollFd {
            fd: rd,
            events: POLLIN,
            revents: 0,
        };
        let mut read = 0u64;
        let mut timeout = [1i64, 0];
        let mask = 0u64;
        let sigarg = [&mask as *const _ as u64, SIGSET_BYTES as u64];
        let cases = [
            #[cfg(target_arch = "x86_64")]
            (
                "poll",
                [(&mut pollfd as *mut PollFd) as u64, 1, 1000, 0, 0, 0],
                false,
                None,
            ),
            (
                "ppoll",
                [
                    (&mut pollfd as *mut PollFd) as u64,
                    1,
                    timeout.as_mut_ptr() as u64,
                    &mask as *const _ as u64,
                    SIGSET_BYTES as u64,
                    0,
                ],
                true,
                Some([0, 999_999_990]),
            ),
            #[cfg(target_arch = "x86_64")]
            (
                "select",
                [
                    (rd + 1) as u64,
                    &mut read as *mut _ as u64,
                    0,
                    0,
                    timeout.as_mut_ptr() as u64,
                    0,
                ],
                false,
                Some([0, 999_999]),
            ),
            (
                "pselect6",
                [
                    (rd + 1) as u64,
                    &mut read as *mut _ as u64,
                    0,
                    0,
                    timeout.as_mut_ptr() as u64,
                    sigarg.as_ptr() as u64,
                ],
                true,
                Some([0, 999_999_990]),
            ),
        ];
        for (name, args, temporary, expected_timeout) in cases {
            read = 1u64 << rd;
            timeout = [1, 0];
            let original = if temporary { bit(SIGUSR1) } else { 0 };
            set_mask(SIG_SETMASK, original);
            let helper = spawn(move || {
                assert_eq!(after_others_park(me), BlockClass::Readiness);
                assert_eq!(
                    lock_state().signals.mask(me),
                    0,
                    "temporary mask covers the park"
                );
                generate(SIGUSR1);
            });
            assert_eq!(
                unsafe {
                    crate::sud::patina_sud_dispatch(
                        syscall_number(name),
                        args[0],
                        args[1],
                        args[2],
                        args[3],
                        args[4],
                        args[5],
                        0,
                    )
                },
                -i64::from(EINTR),
                "{name}"
            );
            assert_eq!(read_mask(), original, "{name}");
            assert_eq!(parked_class(me), None);
            assert!(!on_any_waiter_list(me));
            if let Some(expected) = expected_timeout {
                assert_eq!(timeout, expected);
            }
            // EINTR leaves the select descriptor sets unchanged.
            assert_eq!(read, 1u64 << rd);
            join(helper);
        }
        assert_eq!(HANDLERS.load(Ordering::SeqCst), cases.len());
        assert_eq!(crate::patina_close(rd), 0);
        assert_eq!(crate::patina_close(wr), 0);
    });
}

#[test]
fn select_reports_only_ready_sets_and_preserves_input_on_error() {
    isolated(|| {
        let [rd, wr] = pipe();
        let mut read = 1u64 << rd;
        let mut write = 1u64 << wr;
        let mut except = read;
        let mut remaining = 99;
        assert_eq!(
            unsafe {
                readiness::patina_select(
                    wr + 1,
                    &mut read,
                    &mut write,
                    &mut except,
                    100,
                    std::ptr::null(),
                    &mut remaining,
                )
            },
            1
        );
        assert_eq!(read, 0);
        assert_eq!(write, 1u64 << wr);
        assert_eq!(except, 0);
        assert_eq!(remaining, 100);
        read = 1u64 << rd;
        assert_eq!(
            unsafe {
                readiness::patina_select(
                    rd + 1,
                    &mut read,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    100,
                    std::ptr::null(),
                    &mut remaining,
                )
            },
            0
        );
        assert_eq!(read, 0);
        assert_eq!(remaining, 0);
        let mut invalid = 1u64 << 63;
        assert_eq!(
            unsafe {
                readiness::patina_select(
                    64,
                    &mut invalid,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                    &mut remaining,
                )
            },
            -i64::from(crate::EBADF)
        );
        assert_eq!(invalid, 1u64 << 63);
        assert_eq!(
            unsafe { crate::patina_write(wr, b"x".as_ptr().cast(), 1) },
            1
        );
        read = 1u64 << rd;
        write = 1u64 << wr;
        assert_eq!(
            unsafe {
                readiness::patina_select(
                    wr + 1,
                    &mut read,
                    &mut write,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                    &mut remaining,
                )
            },
            2
        );
        assert_eq!(read, 1u64 << rd);
        assert_eq!(write, 1u64 << wr);
    });
}
