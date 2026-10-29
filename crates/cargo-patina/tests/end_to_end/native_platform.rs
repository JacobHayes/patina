//! Native platform services, libc interposition, and signal termination.

#[cfg(test)]
mod tests {
    use super::super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn native_run_supports_a_custom_global_allocator() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();
        let source = directory.path().join("custom-alloc.rs");
        fs::write(&source, CUSTOM_ALLOCATOR_SOURCE).unwrap();
        let bin = directory.path().join("custom-alloc-bin");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        // Audits clean with NO flags: a custom global allocator is no longer refused.
        let audited = invoke(workspace, &["audit", bin.to_str().unwrap()]);
        assert!(
            !String::from_utf8_lossy(&audited.stderr).contains("custom-global-allocator"),
            "custom global allocator is still refused by audit:\n{}",
            String::from_utf8_lossy(&audited.stderr)
        );

        // Runs with NO flags and prints — the allocator's interposed `os_unfair_lock`
        // never re-enters the shim.
        let ran = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
        assert!(
            String::from_utf8_lossy(&ran.stdout).contains("CUSTOM_ALLOC_OK len=3"),
            "custom-allocator guest did not run:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&ran.stdout),
            String::from_utf8_lossy(&ran.stderr)
        );

        // Deterministic: two same-seed runs are byte-identical.
        let again = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
        assert_eq!(
            ran.stdout, again.stdout,
            "custom-allocator run is not seed-stable"
        );
    }

    // The libc surface the common crates reach, each call answered from the
    // deterministic model rather than refused or passed to the host:
    //
    // * `getrusage(RUSAGE_SELF)` reports virtual CPU time: the modeled startup's
    //   user time (half of `STARTUP_CPU_NANOS`), then what the guest's calls
    //   charge. A sleep advances the clock but is not charged; a busy-wait on the
    //   clock is charged every read. It runs first, so nothing else has charged
    //   yet. `struct rusage` begins with ru_utime (`time_t` seconds, then
    //   microseconds, 8 bytes each on both platforms).
    // * `localtime_r` (the `time`/`chrono` local-offset path) is a pure UTC
    //   conversion: fixed timezone, tm_gmtoff=0, tm_zone="UTC".
    // * `kill` in the single-process world is an existence probe (self alive,
    //   any other pid ESRCH) and `if_nametoindex` reports no such interface.
    // * `sleep` (mimalloc's yield fallback) returns 0 promptly on the virtual clock.
    // * libc `FILE*` stdio (`fputs`/`fprintf`/`fwrite` to the `stdout`/`stderr`
    //   sentinels; mimalloc and aws-lc error output) lands on the captured streams.
    // * `pthread_once` (aws-lc's lazy init) runs its routine exactly once, keyed
    //   on the control block's address.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const LIBC_SURFACE_SOURCE: &str = r#"
use std::ffi::{CStr, CString};
use std::io::Error;
use std::os::raw::{c_char, c_int, c_long, c_uint, c_void};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

#[repr(C)]
struct Tm {
    tm_sec: c_int,
    tm_min: c_int,
    tm_hour: c_int,
    tm_mday: c_int,
    tm_mon: c_int,
    tm_year: c_int,
    tm_wday: c_int,
    tm_yday: c_int,
    tm_isdst: c_int,
    tm_gmtoff: c_long,
    tm_zone: *const c_char,
}

// 16 bytes with 8-byte alignment covers both pthread_once_t layouts (glibc's
// bare int and Darwin's signature-word struct). The shim keys on the address and
// ignores the contents, so zeroed storage is valid under the interposed once.
#[repr(C, align(8))]
struct Once([u8; 16]);

unsafe extern "C" {
    fn getrusage(who: c_int, usage: *mut u8) -> c_int;
    fn sleep(seconds: u32) -> u32;
    fn localtime_r(timep: *const i64, result: *mut Tm) -> *mut Tm;
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn if_nametoindex(name: *const c_char) -> c_uint;
    fn fputs(string: *const c_char, stream: *mut c_void) -> c_int;
    fn fprintf(stream: *mut c_void, format: *const c_char, ...) -> c_int;
    fn fwrite(pointer: *const c_void, size: usize, count: usize, stream: *mut c_void) -> usize;
    fn pthread_once(once_control: *mut Once, init_routine: extern "C" fn()) -> c_int;
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    static __stdoutp: *mut c_void;
    static __stderrp: *mut c_void;
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    static stdout: *mut c_void;
    static stderr: *mut c_void;
}

#[cfg(target_os = "macos")]
fn streams() -> (*mut c_void, *mut c_void) {
    unsafe { (__stdoutp, __stderrp) }
}

#[cfg(target_os = "linux")]
fn streams() -> (*mut c_void, *mut c_void) {
    unsafe { (stdout, stderr) }
}

// ru_utime in microseconds: the first two 8-byte words of `struct rusage`.
fn utime_us() -> i64 {
    // rusage contains native words; byte storage alone promises no alignment.
    #[repr(C, align(8))]
    struct Buffer([u8; 256]);
    let mut aligned = Buffer([0; 256]);
    let buf = &mut aligned.0;
    let rc = unsafe { getrusage(0, buf.as_mut_ptr()) };
    assert_eq!(rc, 0, "getrusage failed");
    let seconds = i64::from_ne_bytes(buf[0..8].try_into().unwrap());
    let micros = i64::from_ne_bytes(buf[8..16].try_into().unwrap());
    seconds * 1_000_000 + micros
}

static COUNT: AtomicU32 = AtomicU32::new(0);
extern "C" fn init() {
    COUNT.fetch_add(1, Ordering::SeqCst);
}

fn main() {
    let before = utime_us();
    let _ = unsafe { sleep(5) };
    let slept = utime_us();
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(2) {}
    let spun = utime_us();
    println!("RU before={before} slept={slept} spun_2ms={}", spun - slept >= 2_000);

    // 2001-09-09 01:46:40 UTC — a Sunday, day-of-year 251.
    let t: i64 = 1_000_000_000;
    let mut tm: Tm = unsafe { std::mem::zeroed() };
    assert!(!unsafe { localtime_r(&t, &mut tm) }.is_null(), "localtime_r returned null");
    let zone = unsafe { CStr::from_ptr(tm.tm_zone) }.to_str().unwrap();
    println!(
        "LT y={} mon={} mday={} h={} m={} s={} wday={} yday={} isdst={} gmtoff={} zone={}",
        tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_wday,
        tm.tm_yday, tm.tm_isdst, tm.tm_gmtoff, zone
    );

    let self_alive = unsafe { kill(std::process::id() as c_int, 0) };
    let other = unsafe { kill(4242, 0) };
    let other_errno = Error::last_os_error().raw_os_error().unwrap_or(0);
    let idx = unsafe { if_nametoindex(c"patina-nope0".as_ptr()) };
    let idx_errno = Error::last_os_error().raw_os_error().unwrap_or(0);
    // ESRCH = 3 on both; an unknown interface is ENODEV (19) on Linux
    // (glibc's SIOCGIFINDEX) and ENXIO (6) on macOS.
    let no_such_interface = if cfg!(target_os = "linux") { 19 } else { 6 };
    println!(
        "KILL self_alive={self_alive} other={other} other_esrch={} idx={idx} idx_unknown={}",
        other_errno == 3,
        idx_errno == no_such_interface
    );

    // A one-hour sleep completes instantly under the virtual clock, returning 0
    // (no seconds remaining). sleep(0) is mimalloc's actual yield-fallback call.
    let remaining = unsafe { sleep(3600) };
    let zero = unsafe { sleep(0) };
    println!("SLEEP remaining={remaining} zero={zero} done");

    let (out, err) = streams();
    let line = CString::new("FPUTS_OUT line\n").unwrap();
    unsafe { fputs(line.as_ptr(), out) };
    let fmt = CString::new("FPRINTF n=%d\n").unwrap();
    unsafe { fprintf(out, fmt.as_ptr(), 42) };
    let e = CString::new("FWRITE_ERR line\n").unwrap();
    unsafe { fwrite(e.as_ptr() as *const c_void, 1, e.as_bytes().len(), err) };

    static mut ONCE: Once = Once([0u8; 16]);
    let control = &raw mut ONCE;
    let a = unsafe { pthread_once(control, init) };
    let b = unsafe { pthread_once(control, init) };
    println!("ONCE a={a} b={b} count={}", COUNT.load(Ordering::SeqCst));
}
"#;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_libc_surface_answers_from_the_model() {
        let guest = native_build::source_guest("libc_surface", LIBC_SURFACE_SOURCE);
        let output = guest.assert_run_success(1, &[]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        for expected in [
            format!(
                "RU before={startup} slept={startup} spun_2ms=true",
                startup = patina_dst_abi::STARTUP_CPU_CHARGE.user_ns / 1000
            ),
            "LT y=101 mon=8 mday=9 h=1 m=46 s=40 wday=0 yday=251 isdst=0 gmtoff=0 zone=UTC"
                .to_owned(),
            "KILL self_alive=0 other=-1 other_esrch=true idx=0 idx_unknown=true".to_owned(),
            "SLEEP remaining=0 zero=0 done".to_owned(),
            "FPUTS_OUT line".to_owned(),
            "FPRINTF n=42".to_owned(),
            "ONCE a=0 b=0 count=1".to_owned(),
        ] {
            assert!(
                stdout.lines().any(|line| line == expected),
                "missing {expected:?}:\nstdout:\n{stdout}\nstderr:\n{stderr}"
            );
        }
        assert!(
            stderr.contains("FWRITE_ERR line"),
            "stderr-sentinel write did not reach captured stderr:\n{stderr}"
        );
    }

    // Build a single-file native source, run it twice at the same seed, assert the
    // two runs are byte-identical, and hand back the stdout. Each macOS surface
    // test below calls the modeled C symbols directly and prints its result.
    #[cfg(target_os = "macos")]
    fn native_source_prints_deterministically(source_name: &str, source: &str) -> String {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();
        let src = directory.path().join(source_name);
        fs::write(&src, source).unwrap();
        let bin = directory.path().join("dormant-bin");
        invoke(
            workspace,
            &[
                "build",
                src.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let ran = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
        let again = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
        assert_eq!(
            ran.stdout, again.stdout,
            "same-seed runs of {source_name} are not byte-identical"
        );
        String::from_utf8_lossy(&ran.stdout).into_owned()
    }

    // Native-trust-root surface (rustls-native-certs' `load_native_certs()`): the
    // shim returns `errSecNoTrustSettings` from `SecTrustSettingsCopyCertificates`
    // for every domain, so security-framework maps each to an EMPTY certificate
    // iterator (built via an empty `CFArrayCreate`/`CFArrayGetCount`/`CFRelease`) and
    // the loader yields zero certs and zero errors — a locked-down host. The guest
    // mirrors that exact reachable sequence across the User/Admin/System domains.
    // Before the conversion `SecTrustSettingsCopyCertificates` was a deny-trap and
    // the run aborted with "host-introspection/macos-framework reached under patina".
    #[cfg(target_os = "macos")]
    #[test]
    fn native_trust_root_surface_is_deterministically_empty() {
        let out = native_source_prints_deterministically(
            "certs.rs",
            r#"use std::os::raw::{c_long, c_void};
use std::ptr;

unsafe extern "C" {
    fn SecTrustSettingsCopyCertificates(domain: u32, out: *mut *const c_void) -> i32;
    fn CFArrayCreate(
        allocator: *const c_void,
        values: *const *const c_void,
        num_values: c_long,
        callbacks: *const c_void,
    ) -> *const c_void;
    fn CFArrayGetCount(array: *const c_void) -> c_long;
    fn CFRelease(cf: *const c_void);
}

fn main() {
    let mut total_certs: c_long = 0;
    let mut errors = 0;
    // Domain::User = 1, Admin = 2, System = 3 (security-framework order).
    for domain in [1u32, 2, 3] {
        let mut array_ptr: *const c_void = ptr::null();
        let status = unsafe { SecTrustSettingsCopyCertificates(domain, &mut array_ptr) };
        if status != -25263 {
            errors += 1;
            continue;
        }
        // errSecNoTrustSettings -> empty CFArray (CFArray::from_CFTypes(&[])).
        let array = unsafe { CFArrayCreate(ptr::null(), ptr::null(), 0, ptr::null()) };
        total_certs += unsafe { CFArrayGetCount(array) };
        unsafe { CFRelease(array) };
    }
    println!("certs={total_certs} errors={errors}");
}
"#,
        );
        assert!(
            out.contains("certs=0 errors=0"),
            "native trust-root surface did not resolve to an empty deterministic result:\n{out}"
        );
    }

    // Host-inventory surface (sysinfo's `System::new_all()`): the shim returns fixed
    // deterministic Mach/BSD values — `host_statistics64` KERN_SUCCESS with the 8 GiB
    // VM model, `host_processor_info` a single-CPU load block (so `cpus().len() == 1`
    // consistent with sysctl HW_NCPU=1), `proc_listallpids` the guest and init, and a
    // NULL `IOServiceMatching` (CPU frequency unknown). The guest exercises that
    // reachable set directly. Before the conversion each was a host-introspection
    // deny-trap and the run aborted before printing.
    #[cfg(target_os = "macos")]
    #[test]
    fn host_inventory_surface_is_deterministic() {
        let out = native_source_prints_deterministically(
            "hostinfo.rs",
            r#"use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::ptr;

unsafe extern "C" {
    fn mach_host_self() -> c_uint;
    fn host_statistics64(host: c_uint, flavor: c_int, out: *mut c_void, count: *mut c_uint) -> c_int;
    fn host_processor_info(
        host: c_uint,
        flavor: c_int,
        out_count: *mut c_uint,
        out_info: *mut *mut c_int,
        out_info_count: *mut c_uint,
    ) -> c_int;
    fn vm_deallocate(task: c_uint, addr: usize, size: usize) -> c_int;
    fn proc_listallpids(buffer: *mut c_void, buffersize: c_int) -> c_int;
    fn IOServiceMatching(name: *const c_char) -> *const c_void;
}

fn main() {
    let port = unsafe { mach_host_self() };

    const HOST_VM_INFO64: c_int = 4;
    let mut stat = [u64::MAX; 128]; // 8-byte aligned, with unwritten bytes visible.
    let mut count: c_uint = 256;
    let vm = unsafe {
        host_statistics64(port, HOST_VM_INFO64, stat.as_mut_ptr() as *mut c_void, &mut count)
    };
    assert_eq!(vm, 0);
    assert_eq!(count, 62); // Revision 3's 248-byte reply, in 32-bit words.
    let fields = unsafe {
        std::slice::from_raw_parts(stat.as_ptr().cast::<u32>(), count as usize)
    };
    assert_eq!(&fields[..4], &[524288, 786432, 524288, 262144],
        "free, active, inactive and wired pages must occupy SDK offsets 0, 4, 8, 12");
    assert!(fields[4..].iter().all(|&word| word == 0), "other VM statistics must be zero");

    const PROCESSOR_CPU_LOAD_INFO: c_int = 2;
    let mut ncpu: c_uint = 0;
    let mut info: *mut c_int = ptr::null_mut();
    let mut info_count: c_uint = 0;
    let cpu = unsafe {
        host_processor_info(port, PROCESSOR_CPU_LOAD_INFO, &mut ncpu, &mut info, &mut info_count)
    };
    if cpu == 0 && !info.is_null() {
        // Free the buffer via vm_deallocate (the shim no-ops it); task port is ignored.
        unsafe { vm_deallocate(0, info as usize, (info_count as usize) * 4) };
    }

    let pids = unsafe { proc_listallpids(ptr::null_mut(), 0) };
    let iokit = unsafe { IOServiceMatching(b"AppleARMIODevice\0".as_ptr() as *const c_char) };

    println!(
        "vm={vm} cpu={cpu} ncpu={ncpu} pids={pids} iokit_null={}",
        iokit.is_null()
    );
}
"#,
        );
        assert!(
            out.contains(&format!(
                "vm=0 cpu=0 ncpu={} pids=2 iokit_null=true",
                patina_dst_abi::DEFAULT_CPUS
            )),
            "host-inventory surface did not resolve to the fixed deterministic values:\n{out}"
        );
    }

    // `host_statistics64(HOST_VM_INFO64)` follows XNU's revision ladder (`vm_stats` in
    // osfmk/kern/host.c): a caller's count gets the newest revision it holds, capped at
    // the modeled host's revision 3, and `count` reports the words written; a count
    // below revision 0 fails with KERN_FAILURE and leaves the buffer and count alone.
    // 104 is the macOS 27 SDK's HOST_VM_INFO64_COUNT, which a guest built against it
    // (or against libc's binding) passes.
    #[cfg(target_os = "macos")]
    #[test]
    fn host_vm_statistics_follow_the_kernel_revision_ladder() {
        let out = native_source_prints_deterministically(
            "vmladder.rs",
            r#"use std::os::raw::{c_int, c_uint, c_void};

unsafe extern "C" {
    fn mach_host_self() -> c_uint;
    fn host_statistics64(host: c_uint, flavor: c_int, out: *mut c_void, count: *mut c_uint) -> c_int;
}

const HOST_VM_INFO64: c_int = 4;
const KERN_FAILURE: c_int = 5;
const UNWRITTEN: u32 = u32::MAX;

fn main() {
    let port = unsafe { mach_host_self() };
    // (caller count, return code, count after the call)
    let ladder = [
        (0, KERN_FAILURE, 0),
        (23, KERN_FAILURE, 23),
        (24, 0, 24),
        (37, 0, 24),
        (38, 0, 38),
        (39, 0, 38),
        (40, 0, 40),
        (61, 0, 40),
        (62, 0, 62),
        (104, 0, 62),
        (1024, 0, 62),
    ];
    for (requested, ret, reply) in ladder {
        let mut stat = [u64::MAX; 512]; // 8-byte aligned, 1024 words.
        let mut count: c_uint = requested;
        let vm = unsafe {
            host_statistics64(port, HOST_VM_INFO64, stat.as_mut_ptr().cast::<c_void>(), &mut count)
        };
        assert_eq!((vm, count), (ret, reply), "caller count {requested}");
        let words = unsafe { std::slice::from_raw_parts(stat.as_ptr().cast::<u32>(), 1024) };
        let written = if vm == 0 { count as usize } else { 0 };
        assert!(
            words[written..].iter().all(|&word| word == UNWRITTEN),
            "caller count {requested} wrote past its {written}-word reply"
        );
        if written > 0 {
            assert_eq!(&words[..4], &[524288, 786432, 524288, 262144], "caller count {requested}");
            assert!(words[4..written].iter().all(|&word| word == 0), "caller count {requested}");
        }
        println!("requested={requested} ret={vm} count={count}");
    }
}
"#,
        );
        assert!(
            out.contains("requested=1024 ret=0 count=62"),
            "the VM statistics revision ladder did not run to completion:\n{out}"
        );
    }

    // `statfs`/`fstatfs` describe the one deterministic volume as a local,
    // writable APFS volume mounted at `/`, by path (through the resolver `stat`
    // uses) and by descriptor alike, with `f_fsid` naming the device `stat`
    // reports, and a buffer the guest cannot write is `EFAULT` rather than a
    // fault inside the shim. SQLite's `unixOpen` fails every open whose
    // `fstatfs` fails, and its lock-style probe picks AFP or no locking from
    // these fields. Class
    // pairing: the default-deny audit refuses a filesystem import the shim does
    // not define, and `syscall_registry` checks every row is defined.
    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_statfs_describes_the_one_volume() {
        let out = native_source_prints_deterministically(
            "volume.rs",
            r#"use std::ffi::CStr;
use std::os::fd::AsRawFd;
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::fs::MetadataExt;

#[repr(C)]
#[derive(Clone, Copy)]
struct Statfs {
    f_bsize: u32,
    f_iosize: i32,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [i32; 2],
    f_owner: u32,
    f_type: u32,
    f_flags: u32,
    f_fssubtype: u32,
    f_fstypename: [c_char; 16],
    f_mntonname: [c_char; 1024],
    f_mntfromname: [c_char; 1024],
    f_flags_ext: u32,
    f_reserved: [u32; 7],
}

unsafe extern "C" {
    fn statfs(path: *const c_char, out: *mut Statfs) -> c_int;
    fn fstatfs(fd: c_int, out: *mut Statfs) -> c_int;
    fn pipe(fds: *mut c_int) -> c_int;
    fn mmap(addr: *mut c_void, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64)
        -> *mut c_void;
}

const MNT_RDONLY: u32 = 0x1;
const MNT_LOCAL: u32 = 0x1000;

fn checked(result: c_int) -> Result<(), i32> {
    match result {
        0 => Ok(()),
        _ => Err(std::io::Error::last_os_error().raw_os_error().unwrap()),
    }
}

fn by_path(path: &CStr) -> Result<Statfs, i32> {
    let mut out = unsafe { std::mem::zeroed::<Statfs>() };
    checked(unsafe { statfs(path.as_ptr(), &mut out) }).map(|()| out)
}

fn by_fd(fd: c_int) -> Result<Statfs, i32> {
    let mut out = unsafe { std::mem::zeroed::<Statfs>() };
    checked(unsafe { fstatfs(fd, &mut out) }).map(|()| out)
}

fn text(field: &[c_char]) -> String {
    unsafe { CStr::from_ptr(field.as_ptr()) }.to_string_lossy().into_owned()
}

fn bytes(fs: &Statfs) -> &[u8] {
    unsafe { std::slice::from_raw_parts((fs as *const Statfs).cast(), size_of::<Statfs>()) }
}

fn main() {
    let file = std::fs::File::create("probe.db").unwrap();
    let dev = file.metadata().unwrap().dev();
    let fs = by_path(c"probe.db").unwrap();
    assert_eq!(text(&fs.f_fstypename), "apfs");
    assert_eq!(text(&fs.f_mntonname), "/");
    assert_ne!(fs.f_flags & MNT_LOCAL, 0, "the volume is local");
    assert_eq!(fs.f_flags & MNT_RDONLY, 0, "the volume is writable");
    assert_eq!(fs.f_bsize, 4096);
    assert_eq!(file.metadata().unwrap().blksize(), u64::from(fs.f_bsize));
    assert!(fs.f_bfree <= fs.f_blocks && fs.f_bavail <= fs.f_bfree);
    assert!(fs.f_ffree <= fs.f_files);
    assert_eq!(fs.f_fsid, [dev as i32, fs.f_type as i32], "f_fsid is the device and the type");
    for (name, other) in [
        ("fstatfs of the file", by_fd(file.as_raw_fd()).unwrap()),
        ("statfs of the directory", by_path(c".").unwrap()),
        ("statfs of the root", by_path(c"/").unwrap()),
    ] {
        assert!(bytes(&other) == bytes(&fs), "{name} names another volume");
    }
    assert_eq!(by_path(c"missing/probe").err(), Some(2), "a missing path is ENOENT");
    assert_eq!(by_path(c"probe.db/x").err(), Some(20), "a path through a file is ENOTDIR");
    let mut ends = [0; 2];
    assert_eq!(unsafe { pipe(ends.as_mut_ptr()) }, 0);
    assert_eq!(by_fd(ends[0]).err(), Some(22), "a pipe has no volume: EINVAL");
    assert_eq!(by_fd(4000).err(), Some(9), "a closed descriptor is EBADF");
    // A buffer the guest cannot write is EFAULT, judged after the path or descriptor.
    let sealed = unsafe { mmap(std::ptr::null_mut(), 1 << 14, 0, 0x1002, -1, 0) };
    assert_ne!(sealed as isize, -1, "mapping a PROT_NONE page failed");
    let sealed = sealed.cast::<Statfs>();
    let path = c"probe.db".as_ptr();
    assert_eq!(checked(unsafe { statfs(path, sealed) }), Err(14), "statfs into PROT_NONE");
    assert_eq!(checked(unsafe { fstatfs(file.as_raw_fd(), sealed) }), Err(14), "fstatfs into PROT_NONE");
    assert_eq!(checked(unsafe { statfs(c"missing/probe".as_ptr(), sealed) }), Err(2));
    assert_eq!(checked(unsafe { fstatfs(4000, sealed) }), Err(9));
    println!(
        "type={} flags={:#x} bsize={} blocks={} bfree={} files={} ffree={}",
        text(&fs.f_fstypename),
        fs.f_flags,
        fs.f_bsize,
        fs.f_blocks,
        fs.f_bfree,
        fs.f_files,
        fs.f_ffree
    );
}
"#,
        );
        assert!(
            out.contains("type=apfs"),
            "the volume probe did not run to completion:\n{out}"
        );
    }

    // The rest of SQLite's Darwin surface beside `statfs`: `atoi` and the
    // fortified `strlcpy`/`strlcat` are pure, the malloc-zone interface is the
    // process heap, `random` starts from libc's fixed state (so its unseeded
    // draws do not follow the seed), `srandomdev` seeds it from the run's
    // entropy stream (so its draws do), and `gethostuuid` answers the modeled
    // machine's fixed identity (so it does not), with `EFAULT` where the guest's
    // timeout or buffer is inaccessible. Recording and replaying the run agree.
    // Class pairing: the default-deny audit, which refuses every import no
    // group admits.
    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_sqlite_surface_follows_the_seed() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();
        let source = directory.path().join("surface.rs");
        fs::write(
            &source,
            r#"use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_long, c_void};

unsafe extern "C" {
    fn atoi(text: *const c_char) -> c_int;
    fn __strlcpy_chk(dst: *mut c_char, src: *const c_char, size: usize, dst_len: usize) -> usize;
    fn __strlcat_chk(dst: *mut c_char, src: *const c_char, size: usize, dst_len: usize) -> usize;
    fn malloc_default_zone() -> *mut c_void;
    fn malloc_create_zone(start_size: usize, flags: u32) -> *mut c_void;
    fn malloc_set_zone_name(zone: *mut c_void, name: *const c_char);
    fn malloc_zone_malloc(zone: *mut c_void, size: usize) -> *mut c_void;
    fn malloc_zone_realloc(zone: *mut c_void, ptr: *mut c_void, size: usize) -> *mut c_void;
    fn malloc_zone_free(zone: *mut c_void, ptr: *mut c_void);
    fn srandomdev();
    fn random() -> c_long;
    fn gethostuuid(id: *mut u8, wait: *const [i64; 2]) -> c_int;
    fn mmap(addr: *mut c_void, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64)
        -> *mut c_void;
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

fn main() {
    assert_eq!(unsafe { atoi(c"  42 rows".as_ptr()) }, 42);
    let mut path = [0 as c_char; 8];
    let len = path.len();
    assert_eq!(unsafe { __strlcpy_chk(path.as_mut_ptr(), c"db".as_ptr(), len, len) }, 2);
    assert_eq!(unsafe { __strlcat_chk(path.as_mut_ptr(), c"-journal".as_ptr(), len, len) }, 10);
    assert_eq!(unsafe { CStr::from_ptr(path.as_ptr()) }, c"db-jour");
    let own = unsafe { malloc_create_zone(4096, 0) };
    unsafe { malloc_set_zone_name(own, c"probe".as_ptr()) };
    for zone in [unsafe { malloc_default_zone() }, own] {
        let block = unsafe { malloc_zone_malloc(zone, 16) }.cast::<u8>();
        unsafe { block.write_bytes(7, 16) };
        let block = unsafe { malloc_zone_realloc(zone, block.cast(), 4096) }.cast::<u8>();
        assert!(unsafe { std::slice::from_raw_parts(block, 16) }.iter().all(|&byte| byte == 7));
        unsafe { malloc_zone_free(zone, block.cast()) };
    }
    let unseeded: Vec<c_long> = (0..3).map(|_| unsafe { random() }).collect();
    unsafe { srandomdev() };
    let draws: Vec<c_long> = (0..3).map(|_| unsafe { random() }).collect();
    let mut id = [0u8; 16];
    assert_eq!(unsafe { gethostuuid(id.as_mut_ptr(), &[0, 0]) }, 0);
    let sealed = unsafe { mmap(std::ptr::null_mut(), 1 << 14, 0, 0x1002, -1, 0) };
    assert_ne!(sealed as isize, -1, "mapping a PROT_NONE page failed");
    let mut spare = [0u8; 16];
    let refused = unsafe { gethostuuid(spare.as_mut_ptr(), sealed.cast()) };
    assert_eq!((refused, errno()), (-1, 14), "a PROT_NONE timeout is EFAULT");
    assert_eq!(spare, [0; 16], "a refused call wrote the UUID");
    let refused = unsafe { gethostuuid(sealed.cast(), &[0, 0]) };
    assert_eq!((refused, errno()), (-1, 14), "a PROT_NONE UUID buffer is EFAULT");
    let id: String = id.iter().map(|byte| format!("{byte:02x}")).collect();
    println!("unseeded={unseeded:?}");
    println!("random={draws:?}");
    println!("hostuuid={id}");
}
"#,
        )
        .unwrap();
        let bin = directory.path().join("surface-bin");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let trace = directory.path().join("surface.patina");
        let recorded = invoke(
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "1",
                "--record",
                trace.to_str().unwrap(),
            ],
        );
        let replayed = invoke(
            workspace,
            &["replay", bin.to_str().unwrap(), trace.to_str().unwrap()],
        );
        assert_eq!(recorded.stdout, replayed.stdout, "replay diverged");
        let run = |seed: &str| {
            let out = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", seed]);
            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            let line = |key: &str| {
                stdout
                    .lines()
                    .find_map(|line| line.strip_prefix(key))
                    .unwrap_or_else(|| panic!("no {key} line under seed {seed}:\n{stdout}"))
                    .to_owned()
            };
            (line("unseeded="), line("random="), line("hostuuid="))
        };
        let first = run("1");
        assert_eq!(first, run("1"), "same-seed runs differ");
        let other = run("2");
        assert_eq!(first.0, other.0, "random's unseeded state follows the seed");
        assert_ne!(
            first.1, other.1,
            "srandomdev's seed does not follow the run seed"
        );
        assert_eq!(first.2, other.2, "the host UUID changes with the seed");
    }

    // Local-timezone surface (iana-time-zone / chrono `Local`): the runtime models a
    // single fixed timezone, UTC (matching the localtime_r interposer), so
    // `CFTimeZoneCopySystem`/`GetName`/`CFStringGetCStringPtr` report "UTC"
    // deterministically and iana-time-zone's `get_timezone()` returns Ok("UTC"). The
    // guest walks tz_darwin.rs's exact call sequence. Before the conversion
    // `CFTimeZoneCopySystem` was a deny-trap and the run aborted before printing.
    #[cfg(target_os = "macos")]
    #[test]
    fn local_timezone_surface_reports_utc() {
        let out = native_source_prints_deterministically(
            "timezone.rs",
            r#"use std::ffi::CStr;
use std::os::raw::{c_char, c_uint, c_void};

unsafe extern "C" {
    fn CFTimeZoneResetSystem();
    fn CFTimeZoneCopySystem() -> *const c_void;
    fn CFTimeZoneGetName(tz: *const c_void) -> *const c_void;
    fn CFStringGetCStringPtr(string: *const c_void, encoding: c_uint) -> *const c_char;
    fn CFRelease(cf: *const c_void);
}

fn main() {
    unsafe { CFTimeZoneResetSystem() };
    let tz = unsafe { CFTimeZoneCopySystem() };
    assert!(!tz.is_null(), "CFTimeZoneCopySystem returned null");
    let name = unsafe { CFTimeZoneGetName(tz) };
    assert!(!name.is_null(), "CFTimeZoneGetName returned null");
    const K_CF_STRING_ENCODING_UTF8: c_uint = 0x0800_0100;
    let ptr = unsafe { CFStringGetCStringPtr(name, K_CF_STRING_ENCODING_UTF8) };
    assert!(!ptr.is_null(), "CFStringGetCStringPtr returned null");
    let zone = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_owned();
    unsafe { CFRelease(tz) };
    println!("tz={zone}");
}
"#,
        );
        assert!(
            out.contains("tz=UTC"),
            "local-timezone surface did not resolve to the modeled UTC zone:\n{out}"
        );
    }

    // task_info(MACH_TASK_BASIC_INFO) reports the same virtual user time as getrusage
    // (`time_abi::cpu_time`): the startup's, unmoved by a sleep, advanced by a
    // busy-wait on the clock, byte-identically across same-seed runs. macOS only (task_info is Mach).
    // user_time sits at byte offset 24 of `struct mach_task_basic_info` (after three
    // 8-byte vm sizes) as two `integer_t`s, seconds then microseconds; the flavor is
    // 20 with a 12-word count.
    #[cfg(target_os = "macos")]
    #[test]
    fn native_task_info_reports_virtual_cpu_time() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();
        let source = directory.path().join("taskinfo.rs");
        fs::write(
            &source,
            r#"use std::os::raw::c_int;
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn task_info(target: u32, flavor: u32, info: *mut u8, count: *mut u32) -> c_int;
    fn sleep(seconds: u32) -> u32;
}

const MACH_TASK_BASIC_INFO: u32 = 20;
const MACH_TASK_BASIC_INFO_COUNT: u32 = 12;
const KERN_SUCCESS: c_int = 0;

// user_time in microseconds, at offset 24 (three 8-byte vm sizes precede it).
fn user_time_us() -> i64 {
    // Mach task_info takes naturally aligned integer-word storage.
    #[repr(C, align(8))]
    struct Buffer([u8; 256]);
    let mut aligned = Buffer([0; 256]);
    let buf = &mut aligned.0;
    let mut count = MACH_TASK_BASIC_INFO_COUNT;
    let rc = unsafe { task_info(0, MACH_TASK_BASIC_INFO, buf.as_mut_ptr(), &mut count) };
    assert_eq!(rc, KERN_SUCCESS, "task_info failed");
    let seconds = i32::from_ne_bytes(buf[24..28].try_into().unwrap());
    let micros = i32::from_ne_bytes(buf[28..32].try_into().unwrap());
    i64::from(seconds) * 1_000_000 + i64::from(micros)
}

fn main() {
    let before = user_time_us();
    let _ = unsafe { sleep(5) };
    let slept = user_time_us();
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(200) {}
    let spun = user_time_us();
    println!(
        "TI before={before} slept={slept} spun_200ms={}",
        spun - slept >= 200_000
    );
}
"#,
        )
        .unwrap();
        let bin = directory.path().join("taskinfo-bin");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        let ran = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
        let out = String::from_utf8_lossy(&ran.stdout);
        assert!(
            out.contains(&format!(
                "TI before={startup} slept={startup} spun_200ms=true",
                startup = patina_dst_abi::STARTUP_CPU_CHARGE.user_ns / 1000
            )),
            "task_info did not report the virtual CPU time:\nstdout:\n{out}\nstderr:\n{}",
            String::from_utf8_lossy(&ran.stderr)
        );

        let again = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
        assert_eq!(ran.stdout, again.stdout, "task_info run is not seed-stable");
    }

    // macOS `sysctlbyname`/`sysctl` (mimalloc, sysinfo, aws-lc) serve a small set of
    // known keys as fixed world-model constants and fail unmodeled keys with a
    // deterministic ENOENT. Before the change `sysctlbyname` was an uninterposed
    // `host-introspection` import and the run was refused before `main`.
    #[cfg(target_os = "macos")]
    #[test]
    fn native_sysctlbyname_serves_fixed_values_and_fails_unknown() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();
        let source = directory.path().join("sysctl.rs");
        fs::write(
            &source,
            r#"use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};

unsafe extern "C" {
    fn sysctlbyname(
        name: *const c_char,
        oldp: *mut c_void,
        oldlenp: *mut usize,
        newp: *mut c_void,
        newlen: usize,
    ) -> c_int;
}

fn query_i64(key: &str) -> (c_int, i64) {
    let name = CString::new(key).unwrap();
    let mut value: i64 = -1;
    let mut len = std::mem::size_of::<i64>();
    let r = unsafe {
        sysctlbyname(
            name.as_ptr(),
            &mut value as *mut i64 as *mut c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (r, value)
}

fn query_i32(key: &str) -> (c_int, i32) {
    let name = CString::new(key).unwrap();
    let mut value: i32 = -1;
    let mut len = std::mem::size_of::<i32>();
    let r = unsafe {
        sysctlbyname(
            name.as_ptr(),
            &mut value as *mut i32 as *mut c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (r, value)
}

fn main() {
    let (mem_r, mem) = query_i64("hw.memsize");
    let (ncpu_r, ncpu) = query_i32("hw.ncpu");
    let unknown = CString::new("hw.this.key.does.not.exist").unwrap();
    let mut junk: i64 = 0;
    let mut junk_len = std::mem::size_of::<i64>();
    let unknown_r = unsafe {
        sysctlbyname(
            unknown.as_ptr(),
            &mut junk as *mut i64 as *mut c_void,
            &mut junk_len,
            std::ptr::null_mut(),
            0,
        )
    };
    println!("MEMSIZE r={mem_r} val={mem} NCPU r={ncpu_r} val={ncpu} UNKNOWN r={unknown_r}");
}
"#,
        )
        .unwrap();
        let bin = directory.path().join("sysctl-bin");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        let ran = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "1"]);
        assert!(
            String::from_utf8_lossy(&ran.stdout).contains(&format!(
                "MEMSIZE r=0 val=8589934592 NCPU r=0 val={} UNKNOWN r=-1",
                patina_dst_abi::DEFAULT_CPUS
            )),
            "sysctlbyname did not serve fixed values / fail unknown key deterministically:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&ran.stdout),
            String::from_utf8_lossy(&ran.stderr)
        );
    }

    // Class-level pairing: frozen signals-family M4 termination and trace facts.
    // In addition to the supervisor envelope, read the linked guest's actual wait
    // status so exit(128 + signal) can never masquerade as signal death.
    #[cfg(target_os = "linux")]
    #[test]
    fn default_terminate_finalizes_then_dies_by_the_signal() {
        use patina_dst_abi::{Operation, SignalTarget};
        use patina_dst_trace::TraceBundle;
        use std::os::unix::process::ExitStatusExt;
        const SIGTERM: i32 = 15;
        let directory = tempdir().unwrap();
        let guest = build_facts_guest(
            directory.path(),
            "default-termination",
            r#"
unsafe extern "C" { fn getpid() -> i32; fn kill(pid: i32, sig: i32) -> i32; }
fn main() {
    const SIGTERM: i32 = 15;
    println!("before-default-termination");
    unsafe { kill(getpid(), SIGTERM); }
    panic!("SIG_DFL returned");
}
"#,
        );
        let trace = directory.path().join("terminate.patina");
        for args in [
            vec![
                "run",
                guest.to_str().unwrap(),
                "--seed",
                "1",
                "--record",
                trace.to_str().unwrap(),
                "--fingerprint",
                "default-termination",
                "--format",
                "json",
            ],
            vec![
                "replay",
                guest.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--fingerprint",
                "default-termination",
                "--format",
                "json",
            ],
        ] {
            let output = invoke_unchecked(
                env!("CARGO_BIN_EXE_cargo-patina"),
                native_workspace(),
                &args,
            );
            let envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
                .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&output.stderr)));
            assert_eq!(envelope["guest_exit"]["signal"], SIGTERM, "{envelope:#}");
            assert_eq!(envelope["guest_exit"]["core"], false);
            assert!(
                envelope["stdout"]
                    .as_str()
                    .unwrap()
                    .contains("before-default-termination")
            );
            assert!(envelope.get("refusal").is_none(), "{envelope:#}");
            let bundle =
                TraceBundle::load(&trace).expect("signal death leaves a complete finalized bundle");
            assert_eq!(bundle.timelines.len(), 1);
            let generations: Vec<_> = bundle.timelines[0]
                .decisions
                .iter()
                .filter_map(|event| match event.operation {
                    Operation::SignalGenerated { sig, target, .. } => Some((sig, target)),
                    _ => None,
                })
                .collect();
            assert_eq!(generations, [(SIGTERM as u8, SignalTarget::Process)]);
        }
        let output = Command::new(&guest)
            .env("PATINA_RT_MODE", "seeded")
            .env("PATINA_RT_SEED", "1")
            .output()
            .unwrap();
        assert_eq!(
            output.status.signal(),
            Some(SIGTERM),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.status.code(), None);
        assert!(!output.status.core_dumped());
        assert!(String::from_utf8_lossy(&output.stdout).contains("before-default-termination"));
    }
}
