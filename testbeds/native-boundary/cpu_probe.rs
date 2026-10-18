// The virtual machine's CPU count as an ordinary program reads it, through every
// surface the platform has: std's `available_parallelism` and `sysconf`'s
// online and configured counts on both; on Linux the affinity mask (glibc's
// `sched_getaffinity` and the raw syscall) and the CPU each thread runs on
// (glibc's `sched_getcpu` and the raw `getcpu`), on macOS the `hw.*cpu`
// sysctls. Each count is printed beside the others, and every thread's CPU is
// checked to be one the mask names. `early` is the online count a constructor
// read before Patina's own startup constructor ran, as a library sizing itself
// at load time does.
use std::ffi::{c_int, c_long};
use std::sync::atomic::{AtomicI64, Ordering};

static EARLY_ONLINE: AtomicI64 = AtomicI64::new(-1);

extern "C" fn early() {
    EARLY_ONLINE.store(
        i64::from(unsafe { sysconf(SC_NPROCESSORS_ONLN) }),
        Ordering::Relaxed,
    );
}

// Before Patina's startup constructor (`.init_array.00101`).
#[cfg(target_os = "linux")]
#[used]
#[unsafe(link_section = ".init_array.00099")]
static EARLY: extern "C" fn() = early;
#[cfg(target_os = "macos")]
#[used]
#[unsafe(link_section = "__DATA,__mod_init_func,mod_init_funcs")]
static EARLY: extern "C" fn() = early;

fn main() {
    let parallelism = std::thread::available_parallelism().map_or(0, usize::from);
    let online = unsafe { sysconf(SC_NPROCESSORS_ONLN) };
    let configured = unsafe { sysconf(SC_NPROCESSORS_CONF) };
    let early = EARLY_ONLINE.load(Ordering::Relaxed);
    print!(
        "NATIVE_CPU_RESULT parallelism={parallelism} online={online} configured={configured} \
         early={early}"
    );
    platform::report();
    println!();
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    /// The CPUs `sched_getaffinity` names, through glibc's wrapper and the raw
    /// syscall, which must agree.
    fn affinity() -> Vec<u32> {
        let mut wrapper = [0u64; 16];
        let mut raw = [0u64; 16];
        let bytes = std::mem::size_of_val(&wrapper);
        if unsafe { sched_getaffinity(0, bytes, wrapper.as_mut_ptr()) } != 0 {
            std::process::exit(20);
        }
        let written = unsafe { syscall(SYS_SCHED_GETAFFINITY, 0, bytes, raw.as_mut_ptr()) };
        if written <= 0 || wrapper != raw {
            std::process::exit(21);
        }
        (0..1024u32)
            .filter(|cpu| wrapper[*cpu as usize / 64] & (1 << (cpu % 64)) != 0)
            .collect()
    }

    /// The calling thread's CPU through glibc's `sched_getcpu` and the raw
    /// `getcpu`, which must agree.
    fn cpu() -> u32 {
        let libc = unsafe { sched_getcpu() };
        let mut raw = u32::MAX;
        let r = unsafe { syscall(SYS_GETCPU, &mut raw as *mut u32, 0usize, 0usize) };
        if libc < 0 || r != 0 || libc as u32 != raw {
            std::process::exit(22);
        }
        raw
    }

    pub fn report() {
        let mask = affinity();
        let mut cpus = vec![cpu()];
        for _ in 0..7 {
            cpus.push(std::thread::spawn(cpu).join().unwrap());
        }
        if !cpus.iter().all(|cpu| mask.contains(cpu)) {
            std::process::exit(23);
        }
        let mut distinct = cpus.clone();
        distinct.sort_unstable();
        distinct.dedup();
        // The files a Linux CPU-count reader may fall back to.
        let cpuinfo = std::fs::metadata("/proc/cpuinfo").is_ok();
        let online = std::fs::metadata("/sys/devices/system/cpu/online").is_ok();
        print!(
            " affinity={} thread_cpus={} proc_cpuinfo={cpuinfo} sys_cpu_online={online}",
            mask.len(),
            distinct.len()
        );
    }

    const SYS_GETCPU: c_long = if cfg!(target_arch = "x86_64") { 309 } else { 168 };
    const SYS_SCHED_GETAFFINITY: c_long = if cfg!(target_arch = "x86_64") { 204 } else { 123 };

    unsafe extern "C" {
        fn sched_getaffinity(pid: c_int, size: usize, mask: *mut u64) -> c_int;
        fn sched_getcpu() -> c_int;
        fn syscall(number: c_long, ...) -> c_long;
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use std::ffi::{CString, c_char, c_void};

    fn query(key: &str) -> c_int {
        let name = CString::new(key).unwrap();
        let mut value: c_int = -1;
        let mut len = std::mem::size_of::<c_int>();
        let r = unsafe {
            sysctlbyname(
                name.as_ptr(),
                &mut value as *mut c_int as *mut c_void,
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if r != 0 {
            std::process::exit(30);
        }
        value
    }

    pub fn report() {
        for key in ["hw.ncpu", "hw.activecpu", "hw.logicalcpu", "hw.physicalcpu"] {
            print!(" {}={}", &key[3..], query(key));
        }
    }

    unsafe extern "C" {
        fn sysctlbyname(
            name: *const c_char,
            oldp: *mut c_void,
            oldlenp: *mut usize,
            newp: *mut c_void,
            newlen: usize,
        ) -> c_int;
    }
}

#[cfg(target_os = "linux")]
const SC_NPROCESSORS_CONF: c_int = 83;
#[cfg(target_os = "linux")]
const SC_NPROCESSORS_ONLN: c_int = 84;
#[cfg(target_os = "macos")]
const SC_NPROCESSORS_CONF: c_int = 57;
#[cfg(target_os = "macos")]
const SC_NPROCESSORS_ONLN: c_int = 58;

unsafe extern "C" {
    fn sysconf(name: c_int) -> c_long;
}
