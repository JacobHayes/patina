//! Ordinary process and signal ABI adapters. Callback frames remain in init.c.
#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(target_os = "linux")]
use crate::sud::Word;
use core::ffi::{CStr, c_char, c_int, c_short};

/// # Safety
/// Termination follows libc's process and destructor contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn exit(status: c_int) -> ! {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::patina_exit(status)
}

#[cfg(target_os = "linux")]
mod linux;

#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_raise"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
extern "C" fn raise(sig: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        if crate::thread::signals::patina_signal_reserved(sig) != 0 {
            return super::error(libc::EINVAL);
        }
        // SAFETY: tgkill receives only the shim's process/thread IDs and the scalar signal number.
        unsafe {
            crate::sud::forward(
                libc::SYS_tgkill,
                &[
                    crate::patina_pid().word(),
                    crate::patina_thread_id().word(),
                    sig.word(),
                ],
            )
        }
    }
    #[cfg(target_os = "macos")]
    {
        super::model_result(crate::thread::signals::patina_raise(sig))
    }
}

fn process_trap(symbol: &CStr) -> ! {
    spawn_trap(symbol, None, Door::Other)
}

/// The program a spawn or exec entry was asked to run, and its arguments,
/// as the caller handed them over.
struct Program {
    path: *const c_char,
    argv: *const *mut c_char,
}

/// Fixed storage for a spawn refusal's text: no allocation, so the stop is
/// safe wherever the guest reached it. The longest text the refusal builds
/// (a 192-byte path, eight 40-byte arguments, their markers) fits.
struct Line {
    bytes: [u8; 640],
    len: usize,
}

impl Line {
    fn push(&mut self, text: &[u8]) {
        let end = (self.len + text.len()).min(self.bytes.len());
        self.bytes[self.len..end].copy_from_slice(&text[..end - self.len]);
        self.len = end;
    }

    /// At most `limit` bytes of the guest C string at `addr`, read through
    /// `uaccess` so a bad pointer prints as unreadable instead of faulting the
    /// shim. Control bytes print as `?`, so the text stays one line.
    fn push_guest(&mut self, addr: usize, limit: usize) {
        if addr == 0 {
            self.push(b"(null)");
            return;
        }
        for offset in 0..=limit {
            let mut byte = [0u8];
            let Some(at) = addr.checked_add(offset) else {
                self.push(b"(unreadable)");
                return;
            };
            if crate::uaccess::read_into(at, &mut byte).is_err() {
                self.push(b"(unreadable)");
                return;
            }
            match byte[0] {
                0 => return,
                _ if offset == limit => {
                    self.push(b"...");
                    return;
                }
                byte if byte < 0x20 || byte == 0x7f => self.push(b"?"),
                byte => self.push(&[byte]),
            }
        }
    }

    fn text(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// The kind of entry a process trap stops in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Door {
    /// A spawn (`posix_spawnp`, `pidfd_spawnp`): its program may be admitted.
    Spawn,
    /// `fork` or the exec family: always refused.
    Other,
}

/// The run stops where the guest asked for a new process: no spawn or exec
/// reaches the host. When the entry was handed a program, the stop names it
/// and its arguments, so a reader learns what was spawned, not only how. A
/// spawn also says what the program is to the admission table
/// ([`crate::admission`]): an admitted one stops as not yet modeled
/// (`not_modeled`), a replay's missing one as a `trace_mismatch`, any other is
/// refused (`deny_trap`) and the text says why or how a program is admitted.
fn spawn_trap(symbol: &CStr, program: Option<Program>, door: Door) -> ! {
    use crate::admission::Admission;
    let mut named = Line {
        bytes: [0; 640],
        len: 0,
    };
    let mut admission = Admission::Unadmitted;
    if let Some(program) = program {
        let mut path = [0u8; libc::PATH_MAX as usize];
        if door == Door::Spawn
            && let Some(path) = guest_c_string(program.path as usize, &mut path)
        {
            admission = crate::admission::admitted_program(path);
        }
        named.push(b" `");
        named.push_guest(program.path as usize, 192);
        // argv[0] is the program's own name, which the path already says.
        // An unreadable or empty argv ends the list.
        let argv = program.argv as usize;
        let slot = |index: usize| -> Option<usize> {
            let at = argv.checked_add(index.checked_mul(size_of::<usize>())?)?;
            crate::uaccess::read::<usize>(at)
                .ok()
                .filter(|arg| *arg != 0)
        };
        if argv != 0 && slot(0).is_some() {
            let mut index = 1;
            while let Some(arg) = slot(index) {
                if index > 8 {
                    named.push(b" ...");
                    break;
                }
                named.push(b" ");
                named.push_guest(arg, 40);
                index += 1;
            }
        }
        named.push(b"`");
    }
    let closed: &[u8] = b"; failing closed\n";
    let (why, reason, suffix): (&[u8], &[u8], &[u8]) = match admission {
        _ if door == Door::Other => (
            b" (process spawn), which Patina does not model",
            b"",
            b"; the process class is a deterministic-runtime non-goal; failing closed\n",
        ),
        Admission::Admitted(_) => (
            b" (process spawn) of an admitted program; Patina does not yet run a second process",
            b"",
            closed,
        ),
        Admission::Refused(reason) => (
            b" (process spawn) of a program refused admission: ",
            reason.as_bytes(),
            closed,
        ),
        Admission::Missing(reason) => (
            b" (process spawn) of an admitted program this replay cannot run: ",
            reason.as_bytes(),
            closed,
        ),
        Admission::Unadmitted => (
            b" (process spawn) of a program Patina does not admit: only the guest itself and, \
              under `patina test`, its package's `[[bin]]` targets, by their \
              `CARGO_BIN_EXE_<name>` paths, can be spawned",
            b"",
            closed,
        ),
    };
    let prefix = b"patina: process spawn reached under patina: ";
    // SAFETY: each byte slice is a live read-only buffer for the synchronous stdio writes.
    unsafe {
        crate::patina_stdio_write(2, prefix.as_ptr().cast(), prefix.len());
        crate::patina_stdio_write(2, symbol.as_ptr().cast(), symbol.count_bytes());
        crate::patina_stdio_write(2, named.text().as_ptr().cast(), named.len);
        crate::patina_stdio_write(2, why.as_ptr().cast(), why.len());
        crate::patina_stdio_write(2, reason.as_ptr().cast(), reason.len());
        crate::patina_stdio_write(2, suffix.as_ptr().cast(), suffix.len());
    }
    crate::patina_flush_captured_stdio();
    let detail: &[&[u8]] = &[
        b"the guest called ",
        symbol.to_bytes(),
        named.text(),
        why,
        reason,
    ];
    crate::host_abort(match admission {
        _ if door == Door::Other => {
            crate::RunStop::new(patina_dst_abi::RunClass::Unsupported, "deny_trap", detail)
        }
        Admission::Admitted(_) => crate::RunStop::unmodeled(detail),
        Admission::Missing(_) => {
            crate::RunStop::new(patina_dst_abi::RunClass::Error, "trace_mismatch", detail)
        }
        Admission::Refused(_) | Admission::Unadmitted => {
            crate::RunStop::new(patina_dst_abi::RunClass::Unsupported, "deny_trap", detail)
        }
    })
}

/// The guest C string at `addr`, copied into `buffer` through `uaccess`;
/// `None` when it is unreadable or longer than `buffer`.
fn guest_c_string(addr: usize, buffer: &mut [u8]) -> Option<&CStr> {
    if addr == 0 {
        return None;
    }
    for offset in 0..buffer.len() {
        crate::uaccess::read_into(addr.checked_add(offset)?, &mut buffer[offset..=offset]).ok()?;
        if buffer[offset] == 0 {
            return CStr::from_bytes_with_nul(&buffer[..=offset]).ok();
        }
    }
    None
}

/// The spawn attribute and file-action calls only fill in the caller's own
/// structure; none starts a process. They answer 0, so a caller reaches the
/// spawn itself. The structure is zeroed on `init`, as glibc leaves it, so
/// nothing reads uninitialized bytes. On Linux they keep what a spawn of an
/// admitted program consults (`crate::machine::spawn`) where glibc keeps it:
/// an action counts in the actions object's `__used`, the flags and the
/// group sit in the attributes object's `__flags` and `__pgrp`.
///
/// # Safety
/// `object` is null or a writable `T`.
unsafe fn zero<T>(object: *mut T) -> c_int {
    if !object.is_null() {
        // SAFETY: a writable `T`, per this function's contract.
        unsafe { core::ptr::write_bytes(object, 0, 1) };
    }
    0
}

#[unsafe(no_mangle)]
extern "C" fn fork() -> libc::pid_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    process_trap(c"fork")
}

/// # Safety
/// path and argv follow libc's execv argument contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn execv(path: *const c_char, argv: *const *mut c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    spawn_trap(c"execv", Some(Program { path, argv }), Door::Other)
}

/// # Safety
/// path, argv and envp follow libc's execve argument contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn execve(
    path: *const c_char,
    argv: *const *mut c_char,
    _envp: *const *mut c_char,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    spawn_trap(c"execve", Some(Program { path, argv }), Door::Other)
}

/// # Safety
/// file and argv follow libc's execvp argument contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn execvp(file: *const c_char, argv: *const *mut c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    spawn_trap(c"execvp", Some(Program { path: file, argv }), Door::Other)
}

/// # Safety
/// status is null or a writable wait status buffer.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_waitpid"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn waitpid(pid: libc::pid_t, status: *mut c_int, options: c_int) -> libc::pid_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::cancel(c"waitpid");
    #[cfg(target_os = "linux")]
    {
        // SAFETY: the unsafe libc entry contract supplies a writable status pointer when non-null.
        unsafe {
            crate::sud::forward(
                libc::SYS_wait4,
                &[pid.word(), status.word(), options.word()],
            )
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (pid, status, options);
        super::error(libc::ECHILD)
    }
}

#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_setsid"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
extern "C" fn setsid() -> libc::pid_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        // SAFETY: setsid has no pointer operands.
        unsafe { crate::sud::forward(libc::SYS_setsid, &[]) }
    }
    #[cfg(target_os = "macos")]
    {
        super::error(libc::EPERM)
    }
}

#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_setgid"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
extern "C" fn setgid(gid: libc::gid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        // SAFETY: setgid forwards one scalar identifier and no pointers.
        unsafe { crate::sud::forward(libc::SYS_setgid, &[gid.word()]) }
    }
    #[cfg(target_os = "macos")]
    {
        if gid == crate::patina_gid() {
            0
        } else {
            super::error(libc::EPERM)
        }
    }
}

#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_setuid"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
extern "C" fn setuid(uid: libc::uid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        // SAFETY: setuid forwards one scalar identifier and no pointers.
        unsafe { crate::sud::forward(libc::SYS_setuid, &[uid.word()]) }
    }
    #[cfg(target_os = "macos")]
    {
        if uid == crate::patina_uid() {
            0
        } else {
            super::error(libc::EPERM)
        }
    }
}

/// glibc's `seteuid`/`setegid`: `setresuid(-1, id, -1)` (and its group
/// twin), refusing `-1` as no id; `setreuid`/`setregid` and
/// `setresuid`/`setresgid` are the calls themselves. Each forwards to the
/// credential model's row, which grants only ids the caller holds.
#[cfg(target_os = "linux")]
#[unsafe(export_name = "patina_door_seteuid")]
extern "C" fn seteuid(uid: libc::uid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if uid == libc::uid_t::MAX {
        return super::error(libc::EINVAL);
    }
    let unchanged = libc::uid_t::MAX.word();
    // SAFETY: setresuid forwards three scalar identifiers and no pointers.
    unsafe { crate::sud::forward(libc::SYS_setresuid, &[unchanged, uid.word(), unchanged]) }
}

#[cfg(target_os = "linux")]
#[unsafe(export_name = "patina_door_setegid")]
extern "C" fn setegid(gid: libc::gid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if gid == libc::gid_t::MAX {
        return super::error(libc::EINVAL);
    }
    let unchanged = libc::gid_t::MAX.word();
    // SAFETY: setresgid forwards three scalar identifiers and no pointers.
    unsafe { crate::sud::forward(libc::SYS_setresgid, &[unchanged, gid.word(), unchanged]) }
}

#[cfg(target_os = "linux")]
#[unsafe(export_name = "patina_door_setreuid")]
extern "C" fn setreuid(real: libc::uid_t, effective: libc::uid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: setreuid forwards two scalar identifiers and no pointers.
    unsafe { crate::sud::forward(libc::SYS_setreuid, &[real.word(), effective.word()]) }
}

#[cfg(target_os = "linux")]
#[unsafe(export_name = "patina_door_setregid")]
extern "C" fn setregid(real: libc::gid_t, effective: libc::gid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: setregid forwards two scalar identifiers and no pointers.
    unsafe { crate::sud::forward(libc::SYS_setregid, &[real.word(), effective.word()]) }
}

#[cfg(target_os = "linux")]
#[unsafe(export_name = "patina_door_setresuid")]
extern "C" fn setresuid(real: libc::uid_t, effective: libc::uid_t, saved: libc::uid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: setresuid forwards three scalar identifiers and no pointers.
    unsafe {
        crate::sud::forward(
            libc::SYS_setresuid,
            &[real.word(), effective.word(), saved.word()],
        )
    }
}

#[cfg(target_os = "linux")]
#[unsafe(export_name = "patina_door_setresgid")]
extern "C" fn setresgid(real: libc::gid_t, effective: libc::gid_t, saved: libc::gid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: setresgid forwards three scalar identifiers and no pointers.
    unsafe {
        crate::sud::forward(
            libc::SYS_setresgid,
            &[real.word(), effective.word(), saved.word()],
        )
    }
}

#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_setpgid"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
extern "C" fn setpgid(pid: libc::pid_t, pgid: libc::pid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        // SAFETY: setpgid forwards two scalar identifiers and no pointers.
        unsafe { crate::sud::forward(libc::SYS_setpgid, &[pid.word(), pgid.word()]) }
    }
    #[cfg(target_os = "macos")]
    {
        if pgid < 0 {
            return super::error(libc::EINVAL);
        }
        if pid != 0 && pid != crate::patina_pid() {
            return super::error(libc::ESRCH);
        }
        if pgid != 0 && pgid != crate::patina_pid() {
            return super::error(libc::EPERM);
        }
        0
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// groups follows libc's count-element input contract.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_setgroups"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn setgroups(count: usize, groups: *const libc::gid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the unsafe libc entry contract supplies `groups` for `count` elements when used.
    unsafe { crate::sud::forward(libc::SYS_setgroups, &[count.word(), groups.word()]) }
}
#[cfg(target_os = "macos")]
/// # Safety
/// groups follows libc's count-element input contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn setgroups(_count: c_int, _groups: *const libc::gid_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::error(libc::EPERM)
}

// Both platforms define the chdir action, for a caller that names it.
/// # Safety
/// acts and path follow libc's spawn file actions contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn posix_spawn_file_actions_addchdir_np(
    acts: *mut libc::posix_spawn_file_actions_t,
    _path: *const c_char,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller's actions object, per the entry's contract.
    unsafe { count_action(acts) }
}
/// # Safety
/// acts and path follow libc's spawn file actions contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn posix_spawn_file_actions_addchdir(
    acts: *mut libc::posix_spawn_file_actions_t,
    _path: *const c_char,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller's actions object, per the entry's contract.
    unsafe { count_action(acts) }
}
/// # Safety
/// All pointers follow libc's posix_spawnp argument contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn posix_spawnp(
    pid: *mut libc::pid_t,
    file: *const c_char,
    file_actions: *const libc::posix_spawn_file_actions_t,
    attrp: *const libc::posix_spawnattr_t,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // An admitted program runs as a process of the machine.
    #[cfg(target_os = "linux")]
    {
        let spawn = crate::machine::spawn::Spawn {
            symbol: c"posix_spawnp",
            pid,
            path: file,
            file_actions,
            attr: attrp,
            argv,
            envp,
        };
        // SAFETY: the pointers follow libc's posix_spawnp contract.
        if let Some(answer) = unsafe { crate::machine::spawn::spawn(&spawn) } {
            return answer;
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (pid, file_actions, attrp, envp);
    spawn_trap(
        c"posix_spawnp",
        Some(Program { path: file, argv }),
        Door::Spawn,
    )
}
/// # Safety
/// acts follows libc's spawn file actions contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn posix_spawn_file_actions_init(
    acts: *mut libc::posix_spawn_file_actions_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // macOS's std finds the chdir action by name, which reaches libSystem's
    // and not the shim's; that one fills in a real libSystem actions object,
    // so on macOS the object is libSystem's own. Building it touches nothing
    // outside the process, and the spawn that would use it still refuses.
    #[cfg(target_os = "macos")]
    {
        // SAFETY: libSystem's own entry, with the caller's actions object.
        unsafe { host_file_actions(c"posix_spawn_file_actions_init", acts) }
    }
    #[cfg(not(target_os = "macos"))]
    {
        // SAFETY: the caller's actions object, per libc's contract.
        unsafe { zero(acts) }
    }
}
/// # Safety
/// acts follows libc's spawn file actions contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn posix_spawn_file_actions_adddup2(
    acts: *mut libc::posix_spawn_file_actions_t,
    fd: c_int,
    newfd: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if fd < 0 || newfd < 0 {
        return libc::EBADF;
    }
    // SAFETY: the caller's actions object, per the entry's contract.
    unsafe { count_action(acts) }
}

/// Count one action in `acts`, so a spawn that would carry it out sees it
/// (`crate::machine::spawn`). Answers 0.
///
/// # Safety
/// `acts` is null or a live actions object.
unsafe fn count_action(acts: *mut libc::posix_spawn_file_actions_t) -> c_int {
    #[cfg(target_os = "linux")]
    if !acts.is_null() {
        // SAFETY: `__used`, the second `int` of glibc's actions object.
        unsafe {
            let used = acts.cast::<c_int>().add(1);
            used.write_unaligned(used.read_unaligned().saturating_add(1));
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = acts;
    0
}
/// # Safety
/// acts follows libc's spawn file actions contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn posix_spawn_file_actions_destroy(
    acts: *mut libc::posix_spawn_file_actions_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // macOS: the object `init` had libSystem build is freed by libSystem.
    #[cfg(target_os = "macos")]
    {
        // SAFETY: libSystem's own entry, with the object its `init` built.
        unsafe { host_file_actions(c"posix_spawn_file_actions_destroy", acts) }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = acts;
        0
    }
}

/// libSystem's own `init` or `destroy` of a spawn actions object, reached
/// past the shim's definitions; `ENOMEM` if libSystem has none, as an
/// allocation failure would answer.
///
/// # Safety
/// `acts` follows libc's spawn file actions contract for `name`.
#[cfg(target_os = "macos")]
unsafe fn host_file_actions(name: &CStr, acts: *mut libc::posix_spawn_file_actions_t) -> c_int {
    let entry = crate::hostapi::symbol(name);
    if entry.is_null() {
        return libc::ENOMEM;
    }
    // SAFETY: libSystem's entry of this name has this C signature.
    let entry = unsafe {
        core::mem::transmute::<
            *mut core::ffi::c_void,
            unsafe extern "C" fn(*mut libc::posix_spawn_file_actions_t) -> c_int,
        >(entry)
    };
    // SAFETY: the caller's actions object, per this function's contract.
    unsafe { entry(acts) }
}
/// # Safety
/// attr follows libc's spawn attributes contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn posix_spawnattr_init(attr: *mut libc::posix_spawnattr_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller's attributes object, per libc's contract.
    unsafe { zero(attr) }
}
/// # Safety
/// attr follows libc's spawn attributes contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn posix_spawnattr_destroy(_attr: *mut libc::posix_spawnattr_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    0
}
/// # Safety
/// attr follows libc's spawn attributes contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn posix_spawnattr_setflags(
    attr: *mut libc::posix_spawnattr_t,
    flags: c_short,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    if !attr.is_null() {
        // SAFETY: `__flags`, the leading `short` of glibc's attributes object.
        unsafe { attr.cast::<c_short>().write_unaligned(flags) };
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (attr, flags);
    0
}
/// # Safety
/// attr follows libc's spawn attributes contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn posix_spawnattr_setpgroup(
    attr: *mut libc::posix_spawnattr_t,
    pgroup: libc::pid_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    if !attr.is_null() {
        // SAFETY: `__pgrp`, the `pid_t` after the flags in glibc's object.
        unsafe {
            attr.cast::<u8>()
                .add(4)
                .cast::<libc::pid_t>()
                .write_unaligned(pgroup)
        };
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (attr, pgroup);
    0
}
/// # Safety
/// attr and sigdefault follow libc's spawn attributes contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn posix_spawnattr_setsigdefault(
    _attr: *mut libc::posix_spawnattr_t,
    _sigdefault: *const libc::sigset_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    0
}

#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_kill"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
extern "C" fn kill(pid: libc::pid_t, sig: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        // SAFETY: kill forwards only scalar process and signal numbers.
        unsafe { crate::sud::forward(libc::SYS_kill, &[pid.word(), sig.word()]) }
    }
    #[cfg(target_os = "macos")]
    {
        if !(0..=64).contains(&sig) {
            return super::error(libc::EINVAL);
        }
        if sig == 0 && (pid == crate::patina_pid() || pid == 0 || pid == -1) {
            return 0;
        }
        if pid == crate::patina_ppid() {
            return 0;
        }
        if pid != crate::patina_pid() {
            return super::error(libc::ESRCH);
        }
        super::deny(c"patina: kill(self, signal) delivery is not modeled by the deterministic runtime; failing closed\n")
    }
}

#[cfg(target_os = "macos")]
#[unsafe(no_mangle)]
extern "C" fn pause() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::cancel(c"pause");
    super::error(libc::ENOSYS)
}
