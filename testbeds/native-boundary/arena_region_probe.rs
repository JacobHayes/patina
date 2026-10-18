//! Asks for the runtime arena's region, after a churn of recorded writes has
//! grown the arena, through every memory call that names a range, and prints
//! each answer: `name=errno N`, `name=ok`, or for a mapping with a mere hint
//! there, whether the host put it `inside` or `outside` the region. Then a
//! boundary call shows the runtime still runs. The region is where the shim
//! places it: three quarters of the way up the address space the stack tops.
//! Linux only.

use std::ffi::c_void;
use std::io::Write;

unsafe extern "C" {
    fn mmap(addr: *mut c_void, len: usize, prot: i32, flags: i32, fd: i32, off: i64)
    -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
    fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
    fn madvise(addr: *mut c_void, len: usize, advice: i32) -> i32;
    fn mlock(addr: *const c_void, len: usize) -> i32;
    fn msync(addr: *mut c_void, len: usize, flags: i32) -> i32;
    fn mremap(old: *mut c_void, old_len: usize, new_len: usize, flags: i32, ...) -> *mut c_void;
    fn syscall(number: i64, ...) -> i64;
}

const PAGE: usize = 4096;
const PROT_READ: i32 = 1;
const PROT_WRITE: i32 = 2;
const MAP_PRIVATE: i32 = 2;
const MAP_FIXED: i32 = 0x10;
const MAP_ANONYMOUS: i32 = 0x20;
const MAP_FIXED_NOREPLACE: i32 = 0x10_0000;
const MAP_GROWSDOWN: i32 = 0x100;
const MADV_DONTNEED: i32 = 4;
const MS_ASYNC: i32 = 1;
const MREMAP_MAYMOVE: i32 = 1;
const MREMAP_FIXED: i32 = 2;
#[cfg(target_arch = "x86_64")]
const SYS_MINCORE: i64 = 27;
#[cfg(target_arch = "aarch64")]
const SYS_MINCORE: i64 = 232;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// `0` as `ok`, else the errno.
fn answer(name: &str, result: i64) {
    if result == 0 {
        println!("{name}=ok");
    } else {
        println!("{name}=errno {}", errno());
    }
}

fn map(name: &str, at: usize, flags: i32, region: (usize, usize)) {
    // SAFETY: an anonymous mapping, unmapped again if it was made.
    let address = unsafe {
        mmap(
            at as *mut c_void,
            PAGE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | flags,
            -1,
            0,
        )
    };
    if address as isize == -1 {
        println!("{name}=errno {}", errno());
        return;
    }
    let address = address as usize;
    if flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0 {
        println!("{name}=ok");
    } else if (region.0..region.1).contains(&address) {
        println!("{name}=inside");
    } else {
        println!("{name}=outside");
    }
    // SAFETY: the mapping just made, unless it replaced runtime memory.
    unsafe { munmap(address as *mut c_void, PAGE) };
}

fn main() {
    let marker = 0u8;
    let top = (std::hint::black_box(&marker) as *const u8 as usize).next_power_of_two();
    let base = top / 4 * 3;
    let region = (base, base + (top / 64).min(256 << 30));

    if std::env::args().any(|arg| arg == "growsdown") {
        growsdown(region.1);
        return;
    }

    // Recorded writes: a recording's trace grows with them, and a replay
    // holds them.
    let mut file = std::fs::File::create("arena-region-churn").expect("create");
    let chunk = vec![7u8; 64 << 10];
    for _ in 0..300 {
        file.write_all(&chunk).expect("write");
    }
    drop(file);

    // Offsets past what the arena has mapped in some modes and not in others.
    map("noreplace-start", base, MAP_FIXED_NOREPLACE, region);
    for mib in [32, 48, 64, 128, 256] {
        let name = format!("noreplace-{mib}MiB");
        map(&name, base + (mib << 20), MAP_FIXED_NOREPLACE, region);
    }
    let inner = base + (32 << 20);
    map("fixed-inner", inner, MAP_FIXED, region);
    map("fixed-start", base, MAP_FIXED, region);
    map("hint-start", base, 0, region);
    let at = base as *mut c_void;
    // SAFETY: each call is refused or acts on the region alone.
    unsafe {
        answer("munmap", munmap(at, PAGE).into());
        answer("mprotect", mprotect(at, PAGE, 0).into());
        answer("madvise", madvise(at, PAGE, MADV_DONTNEED).into());
        answer("mlock", mlock(at, PAGE).into());
        answer("msync", msync(at, PAGE, MS_ASYNC).into());
        let mut vector = [0u8; 1];
        answer(
            "mincore",
            syscall(SYS_MINCORE, at, PAGE, vector.as_mut_ptr()),
        );
        let moved = mremap(at, PAGE, 2 * PAGE, MREMAP_MAYMOVE);
        answer("mremap-from", if moved as isize == -1 { -1 } else { 0 });
        let own = mmap(
            std::ptr::null_mut(),
            PAGE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        let moved = mremap(own, PAGE, PAGE, MREMAP_MAYMOVE | MREMAP_FIXED, at);
        answer("mremap-to", if moved as isize == -1 { -1 } else { 0 });
        munmap(own, PAGE);
        // A mapping just below the region grows: the kernel moves it, as it
        // moves one a neighbour blocks, or refuses without leave to move.
        let below = mmap(
            (base - PAGE) as *mut c_void,
            PAGE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            -1,
            0,
        );
        let stayed = mremap(below, PAGE, 2 * PAGE, 0);
        answer("mremap-grow", if stayed as isize == -1 { -1 } else { 0 });
        let moved = mremap(below, PAGE, 2 * PAGE, MREMAP_MAYMOVE);
        if moved as isize == -1 {
            println!("mremap-grow-maymove=errno {}", errno());
        } else if (region.0..region.1).contains(&(moved as usize)) {
            println!("mremap-grow-maymove=inside");
        } else {
            println!("mremap-grow-maymove=moved");
            munmap(moved, 2 * PAGE);
        }
    }

    // The runtime still runs.
    let read = std::fs::read("arena-region-churn").expect("read");
    assert_eq!(read.len(), 300 * chunk.len());
    std::fs::remove_file("arena-region-churn").expect("remove");
    println!("after=ok");
}

/// A stack mapping (`MAP_GROWSDOWN`) just above the region, then a store one
/// page below it, where the kernel grows such a mapping down.
fn growsdown(end: usize) {
    // SAFETY: an anonymous mapping above the region.
    let stack = unsafe {
        mmap(
            end as *mut c_void,
            PAGE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_GROWSDOWN,
            -1,
            0,
        )
    };
    if stack as isize == -1 {
        println!("growsdown=errno {}", errno());
        return;
    }
    // SAFETY: the page below a growing mapping, which the kernel adds to it.
    unsafe { ((end - PAGE) as *mut u8).write_volatile(1) };
    println!("grew");
    // SAFETY: the page the mapping grew by.
    answer("munmap-grown", unsafe { munmap((end - PAGE) as *mut c_void, PAGE) }.into());
}
