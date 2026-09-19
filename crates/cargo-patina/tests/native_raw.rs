//! Live raw/libc parity and Patina-specific soft refusals. These are not host
//! equivalence claims (identity, auxv, ppoll and sendmsg deliberately differ).
mod common;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use super::*;
    use common::native::*;

    fn assert_raw_output(name: &str, expected: &str) {
        let g = Guest::assert_build_with("raw", &["--bin", name]);
        if kernel_supports(KernelFeature::Sud) {
            assert_eq!(
                text(&g.assert_seed_repeatability(1, 2, &[])),
                format!("{expected}\n")
            );
        } else {
            g.assert_run_refused(1, SUD_REFUSAL_DIAGNOSTICS);
        }
    }

    #[test]
    fn raw_process_identity_is_fixed() {
        assert_raw_output("raw_procstate", "RAW_PROCSTATE pid=1 uid=1000 uname_rc=-38");
    }

    #[test]
    fn raw_messages_return_enosys_without_transmission() {
        assert_raw_output("raw_msg", "RAW_MSG sendmsg=-38 recvmsg=-38");
    }

    #[test]
    fn legacy_fs_aliases_share_virtual_state() {
        assert_raw_output(
            "raw_legacy_fs",
            "LEGACY_ALIASES open+creat+unlink+getdents ok",
        );
    }

    #[test]
    fn raw_fifo_rows_transfer_and_refuse_consistently() {
        assert_raw_output(
            "raw_fifo",
            "RAW_FIFO mknodat+stat+nonblock+enxio+transfer+dents ok",
        );
    }

    #[test]
    fn creation_modes_are_enforced_on_later_open() {
        assert_raw_output(
            "raw_modes",
            "RAW_MODES openat+open+creat+mkdirat+mkdir+umask+enforced ok",
        );
    }

    #[test]
    fn socketpair_survives_dup2_over_eventfd() {
        assert_raw_output("raw_socketpair", "SOCKETPAIR_ROW pair+dup2eventfd ok");
    }

    #[test]
    fn ppoll_advances_virtual_time_and_refuses_real_fds() {
        assert_raw_output("raw_ppoll", "PPOLL_ROW empty_sleep=5000000 real_enosys=-38");
    }

    #[test]
    fn fcntl_status_flags_match_libc() {
        assert_raw_output("raw_fcntl_parity", "FCNTL_PARITY raw=32769 libc=32769");
    }

    #[test]
    fn fcntl_record_locks_match_libc() {
        assert_raw_output(
            "raw_fcntl_lock",
            "FCNTL_LOCK_PARITY raw_set=0 raw_get=0 raw_type=2 libc_set=0 libc_get=0 libc_type=2",
        );
    }

    #[test]
    fn prctl_returns_scrubbed_auxv() {
        let g = Guest::assert_build_with("raw", &["--bin", "raw_prctl_auxv"]);
        if kernel_supports(KernelFeature::Sud) {
            let out = g.assert_seed_repeatability(1, 2, &[]);
            let fields = assert_fields(&out, "PR_GET_AUXV ", &["len", "random"]);
            let len: usize = fields["len"].parse().unwrap();
            assert!(len > 0 && len <= 4096 && len % 16 == 0);
            assert_lower_hex(fields["random"], 32);
        } else {
            g.assert_run_refused(1, SUD_REFUSAL_DIAGNOSTICS);
        }
    }

    #[test]
    fn prctl_denied_option_aborts_with_named_diagnostic() {
        let g = Guest::assert_build_with("raw", &["--bin", "raw_prctl_deny"]);
        if kernel_supports(KernelFeature::Sud) {
            g.assert_run_refused(1, &["SUD trapped prctl"]);
        } else {
            g.assert_run_refused(1, SUD_REFUSAL_DIAGNOSTICS);
        }
    }
}
