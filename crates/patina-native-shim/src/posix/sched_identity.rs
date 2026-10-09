//! Ordinary identity, scheduler and process inventory ABI adapters.
#![deny(clippy::undocumented_unsafe_blocks)]

use core::ffi::{c_char, c_int, c_long};
use core::ptr;

#[cfg(target_os = "linux")]
use crate::sud::Word;

#[unsafe(no_mangle)]
extern "C" fn getpid() -> libc::pid_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::patina_pid()
}

#[unsafe(no_mangle)]
extern "C" fn getppid() -> libc::pid_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::patina_ppid()
}

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
extern "C" fn gettid() -> libc::pid_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::patina_thread_id()
}

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
extern "C" fn __res_init() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    0
}

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
extern "C" fn res_init() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    __res_init()
}

#[cfg(target_os = "macos")]
/// # Safety
/// A nonnull thread_id must point to a writable u64; thread follows pthread's handle contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn pthread_threadid_np(thread: libc::pthread_t, thread_id: *mut u64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if thread_id.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: the caller supplies a valid pthread handle or the special zero handle.
    if thread != 0 && unsafe { libc::pthread_equal(thread, libc::pthread_self()) } == 0 {
        return libc::ENOTSUP;
    }
    // SAFETY: null was rejected above and the caller promises writable storage for the result.
    unsafe {
        thread_id.write(crate::patina_thread_id() as u64);
    }
    0
}

unsafe fn virtual_uname(name: *mut libc::utsname) -> c_int {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `name` is the caller's output pointer for the synchronous uname syscall.
        unsafe { crate::sud::forward(libc::SYS_uname, &[name.word()]) }
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: the caller supplies the output pointer under uname's libc contract.
        super::model_result(unsafe { crate::patina_uname(name.cast()) })
    }
}

#[cfg(target_os = "macos")]
const _: () = assert!(size_of::<libc::utsname>() == 5 * 256);

/// # Safety
/// name follows libc's output-buffer contract.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_uname"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn uname(name: *mut libc::utsname) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller's output-buffer contract is forwarded unchanged.
    unsafe { virtual_uname(name) }
}

#[unsafe(no_mangle)]
extern "C" fn sched_yield() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::patina_sched_yield()
}

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
extern "C" fn sched_getcpu() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    0
}

#[cfg(target_os = "linux")]
/// # Safety
/// mask names the cpusetsize-byte guest input range.
#[cfg_attr(
    target_os = "linux",
    unsafe(export_name = "patina_door_sched_setaffinity")
)]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn sched_setaffinity(
    pid: libc::pid_t,
    cpusetsize: usize,
    mask: *const libc::cpu_set_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: `mask` is the caller's syscall input pointer and the SUD row performs its established access.
    unsafe {
        crate::sud::forward(
            libc::SYS_sched_setaffinity,
            &[pid.word(), cpusetsize.word(), mask.word()],
        )
    }
}

#[unsafe(no_mangle)]
extern "C" fn getuid() -> libc::uid_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::patina_uid()
}
#[unsafe(no_mangle)]
extern "C" fn geteuid() -> libc::uid_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::patina_uid()
}
#[unsafe(no_mangle)]
extern "C" fn getgid() -> libc::gid_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::patina_gid()
}
#[unsafe(no_mangle)]
extern "C" fn getegid() -> libc::gid_t {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::patina_gid()
}

#[unsafe(no_mangle)]
extern "C" fn sysconf(name: c_int) -> c_long {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if name == libc::_SC_PAGESIZE {
        return 4096;
    }
    if name == libc::_SC_NPROCESSORS_ONLN || name == libc::_SC_NPROCESSORS_CONF {
        return 1;
    }
    if name == libc::_SC_CLK_TCK {
        return 100;
    }
    if name == libc::_SC_OPEN_MAX {
        return crate::patina_fd_limit() as c_long;
    }
    if name == libc::_SC_NGROUPS_MAX {
        return 65536;
    }
    super::error(libc::EINVAL) as c_long
}

/// # Safety
/// usage follows libc's rusage output contract.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_getrusage"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn getrusage(who: c_int, usage: *mut libc::rusage) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `usage` is the caller's output pointer for this synchronous syscall.
        unsafe { crate::sud::forward(libc::SYS_getrusage, &[who.word(), usage.word()]) }
    }
    #[cfg(target_os = "macos")]
    {
        if usage.is_null() {
            return super::error(libc::EFAULT);
        }
        // SAFETY: null is rejected and libc's output-buffer contract supplies writable storage.
        unsafe {
            ptr::write_bytes(usage, 0, 1);
            if who == libc::RUSAGE_SELF {
                let mut nanos = 0;
                if crate::patina_cpu_time_nanos(&mut nanos) == 0 {
                    (*usage).ru_utime.tv_sec = (nanos / 1_000_000_000) as libc::time_t;
                    (*usage).ru_utime.tv_usec = (nanos % 1_000_000_000 / 1000) as libc::suseconds_t;
                }
            }
        }
        0
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// info follows libc's sysinfo output contract.
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_sysinfo"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn sysinfo(info: *mut libc::sysinfo) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: `info` is the caller's output pointer for this synchronous syscall.
    unsafe { crate::sud::forward(libc::SYS_sysinfo, &[info.word()]) }
}

#[cfg(target_os = "linux")]
fn limit_result(result: i64) -> c_int {
    if result < 0 {
        super::error((-result) as c_int)
    } else {
        0
    }
}

#[cfg(target_os = "linux")]
unsafe fn get_limit(resource: u32, output: *mut libc::rlimit64) -> c_int {
    let mut limit = crate::limits::Rlimit { cur: 0, max: 0 };
    // SAFETY: `output` is null or writable under the exported getrlimit contract.
    let result = unsafe {
        crate::limits::patina_prlimit(
            0,
            resource,
            ptr::null(),
            if output.is_null() {
                ptr::null_mut()
            } else {
                &mut limit
            },
        )
    };
    if result == 0 && !output.is_null() {
        // SAFETY: the successful model read establishes `limit`; the caller contract makes output writable.
        unsafe {
            (*output).rlim_cur = limit.cur;
            (*output).rlim_max = limit.max;
        }
    }
    limit_result(result)
}

#[cfg(target_os = "linux")]
unsafe fn set_limit(resource: u32, input: *const libc::rlimit64) -> c_int {
    if input.is_null() {
        // SAFETY: the null input is intentionally preserved as a query without copy-out.
        return limit_result(unsafe {
            crate::limits::patina_prlimit(0, resource, ptr::null(), ptr::null_mut())
        });
    }
    // SAFETY: a nonnull input is readable under the exported setrlimit contract.
    let limit = unsafe {
        crate::limits::Rlimit {
            cur: (*input).rlim_cur,
            max: (*input).rlim_max,
        }
    };
    // SAFETY: `limit` is a live local value for the synchronous model call.
    limit_result(unsafe { crate::limits::patina_prlimit(0, resource, &limit, ptr::null_mut()) })
}

#[cfg(target_os = "linux")]
const _: () = {
    assert!(size_of::<libc::rlimit>() == size_of::<libc::rlimit64>());
    assert!(
        core::mem::offset_of!(libc::rlimit, rlim_cur)
            == core::mem::offset_of!(libc::rlimit64, rlim_cur)
    );
    assert!(
        core::mem::offset_of!(libc::rlimit, rlim_max)
            == core::mem::offset_of!(libc::rlimit64, rlim_max)
    );
};

#[cfg(target_os = "linux")]
/// # Safety
/// output is null or a writable libc rlimit.
#[unsafe(no_mangle)]
unsafe extern "C" fn getrlimit(
    resource: libc::__rlimit_resource_t,
    output: *mut libc::rlimit,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the exported contract makes output null or writable; that contract is forwarded to the model.
    unsafe { get_limit(resource, output.cast()) }
}
#[cfg(target_os = "linux")]
/// # Safety
/// input is null or a readable libc rlimit.
#[unsafe(no_mangle)]
unsafe extern "C" fn setrlimit(
    resource: libc::__rlimit_resource_t,
    input: *const libc::rlimit,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the exported contract makes input null or readable; that contract is forwarded to the model.
    unsafe { set_limit(resource, input.cast()) }
}
#[cfg(target_os = "linux")]
/// # Safety
/// output is null or a writable libc rlimit64.
#[unsafe(no_mangle)]
unsafe extern "C" fn getrlimit64(
    resource: libc::__rlimit_resource_t,
    output: *mut libc::rlimit64,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the exported contract makes output null or writable; that contract is forwarded to the model.
    unsafe { get_limit(resource, output) }
}
#[cfg(target_os = "linux")]
/// # Safety
/// input is null or a readable libc rlimit64.
#[unsafe(no_mangle)]
unsafe extern "C" fn setrlimit64(
    resource: libc::__rlimit_resource_t,
    input: *const libc::rlimit64,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the exported contract makes input null or readable; that contract is forwarded to the model.
    unsafe { set_limit(resource, input) }
}

#[cfg(target_os = "linux")]
/// # Safety
/// mask follows libc's cpusetsize-byte output contract.
#[cfg_attr(
    target_os = "linux",
    unsafe(export_name = "patina_door_sched_getaffinity")
)]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn sched_getaffinity(
    pid: libc::pid_t,
    cpusetsize: usize,
    mask: *mut libc::cpu_set_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller supplies the output buffer, and the SUD row writes no more than the returned byte count.
    let written = unsafe {
        crate::sud::forward(
            libc::SYS_sched_getaffinity,
            &[
                pid.word(),
                cpusetsize.min(c_int::MAX as usize).word(),
                mask.word(),
            ],
        )
    };
    if written < 0 {
        return -1;
    }
    // SAFETY: a successful row wrote at most `written` bytes, with `written <= cpusetsize`.
    unsafe {
        ptr::write_bytes(
            mask.cast::<u8>().add(written as usize),
            0,
            cpusetsize - written as usize,
        );
    }
    0
}

/// # Safety
/// name follows libc's len-byte output contract (nonnull on Darwin).
#[cfg_attr(target_os = "linux", unsafe(export_name = "patina_door_gethostname"))]
#[cfg_attr(not(target_os = "linux"), unsafe(no_mangle))]
unsafe extern "C" fn gethostname(name: *mut c_char, len: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let mut buf = core::mem::MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: the local buffer is writable and the model initializes it on success.
    if unsafe { virtual_uname(buf.as_mut_ptr()) } != 0 {
        return -1;
    }
    // SAFETY: successful uname initialized the struct, including its nodename array.
    let node = unsafe { ptr::addr_of!((*buf.as_ptr()).nodename).cast::<c_char>() };
    #[cfg(target_os = "linux")]
    {
        // SAFETY: successful uname writes a NUL-terminated nodename in the initialized struct.
        let node_len = unsafe { libc::strlen(node) } + 1;
        // SAFETY: caller supplies the requested output range, and the copy is bounded by `len`.
        unsafe {
            ptr::copy_nonoverlapping(node, name, len.min(node_len));
        }
        if node_len > len {
            return super::error(libc::ENAMETOOLONG);
        }
    }
    #[cfg(target_os = "macos")]
    {
        if len == 0 {
            return 0;
        }
        // SAFETY: successful uname writes a NUL-terminated nodename in the initialized struct.
        let copied = unsafe { libc::strlen(node) }.min(len - 1);
        // SAFETY: caller supplies a writable range of `len` bytes and `copied < len`.
        unsafe {
            ptr::copy_nonoverlapping(node, name, copied);
            name.add(copied).write(0);
        }
    }
    0
}

unsafe fn passwd_parse(
    line: *const c_char,
    pwd: *mut libc::passwd,
    buf: *mut c_char,
    buflen: usize,
) -> c_int {
    // SAFETY: `line` is a model-owned NUL-terminated passwd row.
    let length = unsafe { libc::strlen(line) };
    if buflen < length + 3 {
        return libc::ERANGE;
    }
    // SAFETY: the caller supplies `buf` for at least `buflen` bytes; the prior length check fits the row.
    unsafe {
        ptr::copy_nonoverlapping(line, buf, length + 1);
    }
    let mut fields = [ptr::null_mut(); 7];
    let mut at = buf;
    for field in &mut fields {
        *field = at;
        // SAFETY: the copied row has `length + 1` initialized bytes and seven colon-delimited fields.
        unsafe {
            while at.read() != b':' as c_char && at.read() != 0 {
                at = at.add(1);
            }
            if at.read() == b':' as c_char {
                at.write(0);
                at = at.add(1);
            }
        }
    }
    let mut ids = [0u64; 2];
    for (id, value) in ids.iter_mut().enumerate() {
        let mut digit = fields[2 + id];
        // SAFETY: each numeric field is NUL-terminated within the copied passwd row.
        unsafe {
            while (b'0' as c_char..=b'9' as c_char).contains(&digit.read()) {
                *value = value
                    .wrapping_mul(10)
                    .wrapping_add((digit.read() - b'0' as c_char) as u64);
                digit = digit.add(1);
            }
        }
    }
    // SAFETY: `pwd` is writable under the caller contract and all field pointers refer into `buf`.
    unsafe {
        (*pwd).pw_name = fields[0];
        (*pwd).pw_passwd = fields[1];
        (*pwd).pw_uid = ids[0] as libc::uid_t;
        (*pwd).pw_gid = ids[1] as libc::gid_t;
        (*pwd).pw_gecos = fields[4];
        (*pwd).pw_dir = fields[5];
        (*pwd).pw_shell = fields[6];
        #[cfg(target_os = "macos")]
        {
            (*pwd).pw_change = 0;
            (*pwd).pw_class = buf.add(length);
            (*pwd).pw_expire = 0;
        }
    }
    0
}

/// # Safety
/// pwd, buf and result follow libc's passwd lookup buffer contract; result is nonnull.
#[unsafe(no_mangle)]
unsafe extern "C" fn getpwuid_r(
    uid: libc::uid_t,
    pwd: *mut libc::passwd,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut libc::passwd,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller contract requires a nonnull writable result pointer.
    unsafe {
        result.write(ptr::null_mut());
    }
    let mut index = 0;
    loop {
        let line = crate::patina_passwd_line(index);
        let error = if line.is_null() {
            0
        } else {
            // SAFETY: the line is model-owned and the caller contract supplies pwd and buf storage.
            unsafe { passwd_parse(line, pwd, buf, buflen) }
        };
        if line.is_null() || error != 0 {
            #[cfg(target_os = "macos")]
            if error != 0 {
                super::errno(error);
            }
            #[cfg(target_os = "linux")]
            super::errno(error);
            return error;
        }
        // SAFETY: successful parsing above initialized the caller-provided passwd struct.
        if unsafe { (*pwd).pw_uid } == uid {
            // SAFETY: result was required writable by the caller contract.
            unsafe {
                result.write(pwd);
            }
            #[cfg(target_os = "linux")]
            super::errno(0);
            return 0;
        }
        index += 1;
    }
}

#[cfg(target_os = "linux")]
static mut PASSWD_CURSOR: u32 = 0;
#[cfg(target_os = "linux")]
static mut PASSWD_ENTRY: core::mem::MaybeUninit<libc::passwd> = core::mem::MaybeUninit::zeroed();
#[cfg(target_os = "linux")]
static mut PASSWD_BUFFER: [c_char; 256] = [0; 256];

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
extern "C" fn setpwent() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: this MT-Unsafe API requires callers to serialize access to its shared cursor.
    unsafe {
        PASSWD_CURSOR = 0;
    }
}
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
extern "C" fn endpwent() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: this MT-Unsafe API requires callers to serialize access to its shared cursor.
    unsafe {
        PASSWD_CURSOR = 0;
    }
}
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
extern "C" fn getpwent() -> *mut libc::passwd {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: this MT-Unsafe API requires callers to serialize access to its shared cursor and result.
    unsafe {
        let line = crate::patina_passwd_line(PASSWD_CURSOR);
        if line.is_null() {
            super::error(libc::ENOENT);
            return ptr::null_mut();
        }
        PASSWD_CURSOR += 1;
        let entry = ptr::addr_of_mut!(PASSWD_ENTRY).cast::<libc::passwd>();
        if passwd_parse(line, entry, ptr::addr_of_mut!(PASSWD_BUFFER).cast(), 256) != 0 {
            super::error(libc::ENOMEM);
            return ptr::null_mut();
        }
        entry
    }
}
