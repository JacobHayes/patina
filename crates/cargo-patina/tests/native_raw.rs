//! Raw syscall rows the conformance scenarios do not reach, and Patina-specific
//! soft refusals. These are not host equivalence claims (identity and auxv
//! deliberately differ).
mod common;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use super::*;
    use common::native::*;

    /// One `raw` package binary, built; or, on a host without
    /// syscall-user-dispatch, refused by name and `None`.
    fn raw_guest(name: &str) -> Option<Guest> {
        let g = Guest::assert_build_with("raw", &["--bin", name]);
        if kernel_supports(KernelFeature::Sud) {
            Some(g)
        } else {
            g.assert_run_refused(1, SUD_REFUSAL_DIAGNOSTICS);
            None
        }
    }

    fn assert_raw_output(name: &str, expected: &str) {
        if let Some(g) = raw_guest(name) {
            assert_eq!(
                text(&g.assert_run_success(1, &[]).stdout),
                format!("{expected}\n"),
                "{name}"
            );
        }
    }

    #[test]
    fn raw_fifo_rows_transfer_and_refuse_consistently() {
        assert_raw_output(
            "raw_fifo",
            "RAW_FIFO mknodat+stat+nonblock+enxio+transfer+dents ok",
        );
    }

    /// The raw process identity is the fixed virtual one; a socketpair
    /// survives `dup2` over an eventfd; raw `ppoll` writes back a zero
    /// remaining timeout after its virtual sleep; and `PR_GET_AUXV` answers
    /// the scrubbed auxv, its `AT_RANDOM` bytes seeded.
    #[test]
    fn raw_rows_answer_the_virtual_process() {
        for (name, expected) in [
            (
                "raw_procstate",
                "RAW_PROCSTATE pid=2 uid=1000 uname_rc=0 sysname=Linux nodename=patina",
            ),
            ("raw_socketpair", "SOCKETPAIR_ROW pair+dup2eventfd ok"),
            ("raw_ppoll", "PPOLL_TIMEOUT elapsed_ms=5 remaining=0"),
        ] {
            assert_raw_output(name, expected);
        }
        if let Some(g) = raw_guest("raw_prctl_auxv") {
            let out = g.assert_run_success(1, &[]).stdout;
            let fields = assert_fields(&out, "PR_GET_AUXV ", &["len", "random"]);
            let len: usize = fields["len"].parse().unwrap();
            assert!(len > 0 && len <= 4096 && len.is_multiple_of(16));
            assert_lower_hex(fields["random"], 32);
        }
    }

    /// The probes libraries make of facilities patina does not model are
    /// answered as the pinned kernel would (see the guest for each).
    #[test]
    fn raw_probe_rows_answer_as_the_pinned_kernel() {
        assert_raw_output(
            "raw_probes",
            "RAW_PROBES landlock+seccomp+prctl+tty+stdio+mempolicy ok",
        );
    }

    /// Every other use of a facility patina does not model stops the run by
    /// name before the host could act on it: a seccomp mode (through prctl
    /// or seccomp(2)), a Landlock ruleset, the privileged or unmodeled rows
    /// the registry traps, and a pseudoterminal.
    #[test]
    fn unmodeled_facilities_stop_by_name() {
        let Some(g) = raw_guest("raw_stops") else {
            return;
        };
        for (door, diagnostic) in [
            ("prctl-strict", "PR_SET_SECCOMP"),
            ("seccomp-strict", "seccomp:"),
            ("landlock-ruleset", "landlock_create_ruleset:"),
            ("ptrace", "unsupported syscall ptrace"),
            ("mount", "unsupported syscall mount"),
            ("bpf", "unsupported syscall bpf"),
            ("perf-event-open", "unsupported syscall perf_event_open"),
            ("userfaultfd", "unsupported syscall userfaultfd"),
            ("unshare", "unsupported syscall unshare"),
            ("mq-open", "unsupported syscall mq_open"),
            ("ptmx", "/dev/ptmx"),
        ] {
            g.assert_internal_fatal(&[door], &[diagnostic]);
        }
    }
}
