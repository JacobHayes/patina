//! Unit tests for this module and its focused submodules.

use super::*;

/// The by-name twin of the compile-time checks in `build_dispatch`: the same
/// three conditions, reported with the offending row/binding named. RED:
/// plant a `("nonesuch", …)` binding, remove the `read` binding, or bind
/// `fork`, and the message says which.
#[test]
fn bindings_match_the_registry_rows() {
    let mut problems = Vec::new();
    for row in SYSCALLS {
        let bound = BINDINGS.iter().filter(|(name, _)| *name == row.id).count();
        if row.disposition.is_routed() && bound == 0 {
            problems.push(format!(
                "{}: routed row without a handler binding",
                row.name
            ));
        }
        if !row.disposition.may_bind() && bound > 0 {
            problems.push(format!(
                "{}: trap/absent row with a handler binding",
                row.name
            ));
        }
        if bound > 1 {
            problems.push(format!("{}: bound {bound} times", row.name));
        }
    }
    for (name, _) in BINDINGS {
        if !SYSCALLS.iter().any(|row| row.id == *name) {
            problems.push(format!("{name:?}: binding names no registry row"));
        }
    }
    assert!(
        problems.is_empty(),
        "sud::BINDINGS and registry::SYSCALLS disagree:\n  {}",
        problems.join("\n  ")
    );
    // Every number the vendored table lists for this arch resolves to its row.
    for entry in crate::registry::ENTRIES {
        let (_, row) = row_for(entry.nr as i64)
            .unwrap_or_else(|| panic!("{} ({}) has no dispatch index entry", entry.name, entry.nr));
        assert_eq!(row.name, entry.name);
    }
    assert!(row_for(INDEX_LEN as i64).is_none());
    assert!(row_for(-1).is_none());
}

#[test]
fn arg_fd_reads_int_fds_the_way_the_kernel_does() {
    // The kernel reads fd/dirfd as a 32-bit `int` (low register bits). A
    // caller may sign-extend a negative fd (hand asm) OR zero-extend it
    // (rustix's linux_raw `raw_fd` does `fd as c_uint as usize`): both leave
    // the same low 32 bits, and `arg_fd` must recover the same `int`.
    // RED: reading the raw register as `i64` (the pre-fix behavior) makes the
    // zero-extended cases below large positive numbers, so `AT_FDCWD`
    // miscompares and a rustix `openat(CWD, …)` returns EINVAL.
    assert_eq!(arg_fd(0x0000_0000_FFFF_FF9C), AT_FDCWD); // rustix zero-extended AT_FDCWD
    assert_eq!(arg_fd(0xFFFF_FFFF_FFFF_FF9C), AT_FDCWD); // hand-asm sign-extended AT_FDCWD
    assert_eq!(arg_fd(0x0000_0000_FFFF_FFFF), -1); // zero-extended -1
    assert_eq!(arg_fd(0), 0);
    assert_eq!(arg_fd(5), 5);
    assert_eq!(arg_fd(0x4000_0005), 0x4000_0005);
}

#[test]
fn prctl_option_narrows_to_unsigned_int_like_the_kernel() {
    // The kernel reads `option = (unsigned int) arg`, so only the low 32 bits
    // decide the route. rustix passes a clean 32-bit PR_GET_AUXV; hand asm may
    // sign-/zero-extend. RED: comparing the full 64-bit register would make a
    // sign-extended PR_GET_AUXV (or a high-bit-dirty PR_SET_NAME) miscompare —
    // either wrongly denying the auxv route or wrongly accepting an escape.
    assert_eq!(prctl_option(0x4155_5856), PR_GET_AUXV); // exact
    assert_eq!(prctl_option(0xFFFF_FFFF_4155_5856), PR_GET_AUXV); // dirty high bits ignored
    assert_ne!(prctl_option(15), PR_GET_AUXV); // PR_SET_NAME is denied
    assert_eq!(prctl_option(0x1_0000_000F), 15); // truncation: still PR_SET_NAME (denied)
}

#[test]
fn pr_get_auxv_copy_mirrors_the_kernel_semantics() {
    // A stand-in scrubbed auxv (bytes are irrelevant to the copy math; the
    // real region runs through the AT_NULL pair inclusively).
    let saved: Vec<u8> = (0..48u8).collect();

    // Full copy: user buffer >= auxv. Returns the FULL length, copies it all.
    let mut user = vec![0xAAu8; 512];
    assert_eq!(
        pr_get_auxv_copy(&saved, user.as_mut_ptr(), user.len(), 0, 0),
        48
    );
    assert_eq!(&user[..48], &saved[..]);
    assert!(user[48..].iter().all(|&b| b == 0xAA)); // nothing past the auxv touched

    // Truncated copy: a small user buffer gets a prefix, but the return value
    // is STILL the full auxv length (what rustix uses to size its retry). RED:
    // returning the copied count would break rustix's `assert_eq!(len, buf)`.
    let mut small = vec![0u8; 16];
    assert_eq!(
        pr_get_auxv_copy(&saved, small.as_mut_ptr(), small.len(), 0, 0),
        48
    );
    assert_eq!(&small[..], &saved[..16]);

    // Nonzero arg4 or arg5 ⇒ -EINVAL, and NO bytes are copied.
    let mut untouched = vec![0x5Au8; 64];
    assert_eq!(
        pr_get_auxv_copy(&saved, untouched.as_mut_ptr(), untouched.len(), 1, 0),
        -EINVAL
    );
    assert_eq!(
        pr_get_auxv_copy(&saved, untouched.as_mut_ptr(), untouched.len(), 0, 1),
        -EINVAL
    );
    assert!(untouched.iter().all(|&b| b == 0x5A));

    // A zero-length user request copies nothing but still reports the length.
    assert_eq!(pr_get_auxv_copy(&saved, std::ptr::null_mut(), 0, 0, 0), 48);
    // A nonzero request with a null buffer faults (mirrors copy_to_user).
    assert_eq!(
        pr_get_auxv_copy(&saved, std::ptr::null_mut(), 8, 0, 0),
        -EFAULT
    );
}

#[test]
fn creat_synthesizes_create_write_truncate_flags() {
    // The legacy `creat(path, mode)` alias routes to openat with a SYNTHESIZED
    // flag word `O_CREAT | O_WRONLY | O_TRUNC` (creat has no flags argument).
    // That must decode to a writable, creating, truncating open — never a
    // read-only one (which would drop the file's contents differently and
    // fail to create). RED: synthesizing the wrong flags (e.g. O_RDONLY=0)
    // would decode to PATINA_O_READ with no create/truncate bit.
    let flags = openat_patina_flags(O_CREAT | O_WRONLY | O_TRUNC);
    assert_eq!(
        flags,
        PATINA_O_WRITE | PATINA_O_CREATE | PATINA_O_TRUNCATE,
        "creat must be write+create+truncate"
    );
    // And it must NOT be classified read-only (that gates the directory-fd
    // fallback path in sys_openat).
    let read_only = flags & (PATINA_O_WRITE | PATINA_O_CREATE | PATINA_O_TRUNCATE) == 0;
    assert!(!read_only, "creat is never a read-only open");

    // A bare `open(path, O_RDONLY)` (the read alias) decodes read-only — this
    // pins the contrast the alias relies on.
    assert_eq!(openat_patina_flags(0), PATINA_O_READ);
}

#[test]
fn socketpair_answers_in_kernel_order() {
    use crate::thread::net::abi::{
        AF_INET, AF_UNIX, EPROTONOSUPPORT, SOCK_CLOEXEC, SOCK_NONBLOCK, SOCK_STREAM,
    };
    let mut sv = [-1i32; 2];
    let at = sv.as_mut_ptr() as u64;
    // `__sys_socketpair`: the creation flags first, then both numbers
    // are written to `sv` before any socket exists, then the family.
    assert_eq!(
        sys_socketpair(AF_UNIX as u64, (SOCK_STREAM | 0x1_0000) as u64, 0, at),
        -EINVAL
    );
    assert_eq!(
        sys_socketpair(AF_INET as u64, SOCK_STREAM as u64, 0, 0),
        -EFAULT
    );
    assert_eq!(
        sys_socketpair(
            AF_UNIX as u64,
            (SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC) as u64,
            6,
            at
        ),
        -i64::from(EPROTONOSUPPORT)
    );
}

#[test]
fn ppoll_validates_buffers_and_descriptor_limit_before_waiting() {
    assert_eq!(sys_ppoll(0, 1, 0, 0, 0), -EFAULT);
    assert_eq!(sys_ppoll(0, 1025, 0, 0, 0), -EINVAL);
    assert_eq!(sys_ppoll(0, 0, 0, 1, 4), -EINVAL);
}

#[test]
fn fcntl_and_ioctl_answer_from_the_descriptor_table() {
    // No runtime is installed here: the descriptor table alone answers, and
    // it holds exactly the three standard numbers. A number that names
    // nothing is EBADF for every command (the kernel checks the number
    // before the command), an unknown command on an open number is EINVAL,
    // and FD_CLOEXEC is per number while F_GETFL/F_SETFL are per
    // description (C parity through the SAME entries).
    assert_eq!(sys_fcntl(5, F_GETFD, 0), -EBADF);
    assert_eq!(sys_fcntl(5, F_SETFD, 0), -EBADF);
    assert_eq!(sys_fcntl(5, F_GETFL, 0), -EBADF);
    assert_eq!(sys_fcntl(5, F_SETFL, 0), -EBADF);
    assert_eq!(sys_fcntl(5, 0x9999, 0), -EBADF);
    assert_eq!(sys_fcntl(2, 0x9999, 0), -EINVAL);
    assert_eq!(sys_fcntl(0, F_GETFL, 0), 0); // O_RDONLY
    assert_eq!(sys_fcntl(2, F_GETFL, 0), O_WRONLY as i64);
    assert_eq!(sys_fcntl(2, F_GETFD, 0), 0);
    assert_eq!(sys_fcntl(2, F_SETFD, FD_CLOEXEC as u64), 0);
    assert_eq!(sys_fcntl(2, F_GETFD, 0), FD_CLOEXEC);
    assert_eq!(sys_fcntl(2, F_SETFD, 0), 0);
    assert_eq!(sys_fcntl(2, F_GETFD, 0), 0);
    // F_SETFL changes O_APPEND/O_NONBLOCK and nothing else.
    assert_eq!(sys_fcntl(2, F_SETFL, O_NONBLOCK | O_RDWR), 0);
    assert_eq!(sys_fcntl(2, F_GETFL, 0), (O_WRONLY | O_NONBLOCK) as i64);
    assert_eq!(sys_fcntl(2, F_SETFL, 0), 0);
    assert_eq!(sys_fcntl(2, F_GETFL, 0), O_WRONLY as i64);
    // ioctl: FIOCLEX/FIONCLEX are the FD_CLOEXEC bit; an unknown request is
    // a soft -ENOTTY on an open number and -EBADF on a closed one.
    use crate::ioctl::request::{FIOCLEX, FIONCLEX};
    assert_eq!(sys_ioctl(2, FIOCLEX, 0), 0);
    assert_eq!(sys_fcntl(2, F_GETFD, 0), FD_CLOEXEC);
    assert_eq!(sys_ioctl(2, FIONCLEX, 0), 0);
    assert_eq!(sys_fcntl(2, F_GETFD, 0), 0);
    assert_eq!(sys_ioctl(2, 0x1234, 0), -(errno::ENOTTY as i64));
    assert_eq!(sys_ioctl(5, 0x1234, 0), -EBADF);
    assert_eq!(sys_ioctl(5, FIOCLEX, 0), -EBADF);
}

#[test]
fn flag_words_the_kernel_refuses_or_ignores() {
    use uapi::{GRND_INSECURE, GRND_NONBLOCK, GRND_RANDOM, LOCK_MAND, LOCK_SH};
    let mut buf = [0u8; 256];
    let buf = buf.as_mut_ptr() as u64;
    let (insecure, nonblock, random) = (
        u64::from(GRND_INSECURE),
        u64::from(GRND_NONBLOCK),
        u64::from(GRND_RANDOM),
    );
    // getrandom: every bit outside NONBLOCK|RANDOM|INSECURE, and INSECURE
    // with RANDOM, are EINVAL before any byte is drawn; every other
    // combination is accepted (no runtime is installed here, so the
    // accepted side is asked of the rule itself), and a null buffer is
    // EFAULT.
    let unknown = 1 << (insecure | nonblock | random).count_ones();
    assert_eq!(sys_getrandom(buf, 16, unknown), -EINVAL);
    assert_eq!(sys_getrandom(buf, 16, insecure | random), -EINVAL);
    for accepted in [
        0,
        nonblock,
        random,
        insecure,
        nonblock | random,
        nonblock | insecure,
    ] {
        assert!(
            crate::getrandom_flags_accepted(accepted as u32),
            "{accepted:#x}"
        );
    }
    assert_eq!(sys_getrandom(0, 16, 0), -EFAULT);
    // newfstatat/statx: a bit vfs_statx does not accept is EINVAL, before
    // the descriptor is looked at; statx also refuses both sync modes at
    // once and the reserved mask bit.
    let path = c"/x".as_ptr() as u64;
    let bad_fd = -1;
    let unknown_at = !STAT_AT_FLAGS & STAT_AT_FLAGS.wrapping_add(1);
    assert_eq!(sys_newfstatat(bad_fd, path, buf, unknown_at), -EINVAL);
    assert_eq!(sys_statx(bad_fd, path, unknown_at, 0, 0), -EINVAL);
    assert_eq!(sys_statx(bad_fd, path, AT_STATX_SYNC_TYPE, 0, 0), -EINVAL);
    assert_eq!(sys_statx(bad_fd, path, 0, STATX__RESERVED, 0), -EINVAL);
    // flock: LOCK_MAND is answered 0 and ignored before anything else is
    // judged (`fs/locks.c`), so a closed descriptor is 0 too.
    let mand = LOCK_MAND as i64 | LOCK_SH as i64;
    assert_eq!(sys_flock(2, mand), 0);
    assert_eq!(sys_flock(5, mand), 0);
}

#[test]
fn open_flags_decode_with_this_architectures_values() {
    // The flag words a guest's libc hands the kernel, in the libc crate's
    // per-target spelling: x86_64 and arm64 disagree on O_DIRECTORY,
    // O_NOFOLLOW and O_DIRECT, so this oracle is independent of the
    // dispatcher's own constants. RED with x86_64's values on arm64: the
    // directory open is refused as unsupported, and pipe2 reads O_DIRECT as
    // O_DIRECTORY.
    let bits = |flags: libc::c_int| flags as u64;
    let directory = bits(libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    assert_eq!(directory & !OPENAT_SUPPORTED_FLAGS, 0);
    assert_eq!(
        openat_patina_flags(directory),
        PATINA_O_READ | PATINA_O_DIRECTORY | PATINA_O_NOFOLLOW | PATINA_O_CLOEXEC
    );
    assert_ne!(bits(libc::O_DIRECT) & !OPENAT_SUPPORTED_FLAGS, 0);
    // pipe2 refuses packet mode as unmodeled and any other bit as invalid,
    // both before it creates anything.
    let fds: u64 = 0x1000;
    assert_eq!(sys_pipe2(fds, bits(libc::O_DIRECT)), -ENOSYS);
    assert_eq!(sys_pipe2(fds, bits(libc::O_DIRECTORY)), -EINVAL);
}

#[test]
fn openat_flag_decode_ignores_largefile_directory_cloexec_bits() {
    // rustix ORs O_LARGEFILE into every open, and a directory open
    // adds O_DIRECTORY|O_CLOEXEC. The legacy `open`/`creat` aliases and the
    // direct `openat` share ONE decode (`openat_patina_flags`), so they are
    // bit-for-bit identical — the round-6 EBADF was NOT a flag defect (it was
    // the dir-fd fcntl/openat gap). This pins that: the noise bits never
    // perturb the decode. RED: folding O_LARGEFILE into the access-mode
    // compare, or reacting to O_DIRECTORY, would diverge open from openat.
    // O_CLOEXEC is NOT noise: it is the new number's FD_CLOEXEC bit.
    let noise = O_LARGEFILE | O_DIRECTORY;
    assert_eq!(
        openat_patina_flags(O_RDWR | O_CLOEXEC),
        PATINA_O_READ | PATINA_O_WRITE | PATINA_O_CLOEXEC
    );
    // The round-5 flag word.
    assert_eq!(
        openat_patina_flags(O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE),
        PATINA_O_WRITE | PATINA_O_CREATE | PATINA_O_TRUNCATE
    );
    // A directory open decodes read-only plus the directory requirement;
    // the ONE open entry decides the descriptor's kind from the entry's,
    // so the bit travels rather than routing here.
    assert_eq!(
        openat_patina_flags(O_DIRECTORY | O_LARGEFILE),
        PATINA_O_READ | PATINA_O_DIRECTORY
    );
    // `O_PATH` opens nothing: the access mode and every creating bit are
    // dropped under it, exactly as the kernel ignores them.
    assert_eq!(
        openat_patina_flags(O_PATH | O_RDWR | O_CREAT | O_CLOEXEC),
        PATINA_O_PATH | PATINA_O_CLOEXEC
    );
    // The noise bits are inert atop any base access/creation flag word.
    for base in [
        0,
        O_WRONLY,
        O_RDWR,
        O_CREAT | O_WRONLY | O_TRUNC,
        O_APPEND | O_WRONLY,
    ] {
        assert_eq!(
            openat_patina_flags(base) | PATINA_O_DIRECTORY,
            openat_patina_flags(base | noise)
        );
    }
}
