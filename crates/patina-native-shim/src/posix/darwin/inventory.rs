//! Empty trust roots, UTC timezone, and fixed process/host inventory.
//! CF objects are distinct address tokens, never real framework objects.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;
static mut EMPTY_ARRAY: u8 = 0;
static mut SYSTEM_TIMEZONE: u8 = 0;
static mut TIMEZONE_NAME: u8 = 0;

#[unsafe(no_mangle)]
extern "C" fn SecTrustSettingsCopyCertificates(_domain: c_uint, _out: *mut *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    -25263 // errSecNoTrustSettings: empty iterator, ignored out-parameter.
}
#[unsafe(no_mangle)]
extern "C" fn CFArrayCreate(
    _allocator: *const c_void,
    _values: *const *const c_void,
    _count: libc::c_long,
    _callbacks: *const c_void,
) -> *const c_void {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    (&raw const EMPTY_ARRAY).cast()
}
#[unsafe(no_mangle)]
extern "C" fn CFArrayGetCount(_array: *const c_void) -> libc::c_long {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    0
}
#[unsafe(no_mangle)]
extern "C" fn CFRelease(_object: *const c_void) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
}
#[unsafe(no_mangle)]
extern "C" fn CFTimeZoneResetSystem() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
}
#[unsafe(no_mangle)]
extern "C" fn CFTimeZoneCopySystem() -> *const c_void {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    (&raw const SYSTEM_TIMEZONE).cast()
}
#[unsafe(no_mangle)]
extern "C" fn CFTimeZoneGetName(_zone: *const c_void) -> *const c_void {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    (&raw const TIMEZONE_NAME).cast()
}
#[unsafe(no_mangle)]
extern "C" fn CFStringGetCStringPtr(_string: *const c_void, _encoding: c_uint) -> *const c_char {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    c"UTC".as_ptr()
}
#[unsafe(no_mangle)]
extern "C" fn IOServiceMatching(_name: *const c_char) -> *mut c_void {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    ptr::null_mut()
}
/// # Safety
/// buffer is null or writable for buffersize bytes.
#[unsafe(no_mangle)]
unsafe extern "C" fn proc_listallpids(buffer: *mut c_void, buffersize: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let pids = [crate::patina_pid(), crate::patina_ppid()];
    if buffer.is_null() || buffersize <= 0 {
        return 2;
    }
    let count = (buffersize as usize / size_of::<c_int>()).min(2);
    // SAFETY: the ABI contract makes `buffer` writable for `buffersize` bytes, and `count`
    // is bounded by that capacity.
    unsafe {
        ptr::copy_nonoverlapping(pids.as_ptr(), buffer.cast(), count);
    }
    count as c_int
}
fn refuse(pid: c_int) -> c_int {
    super::super::error(if pid == crate::patina_ppid() {
        libc::EPERM
    } else {
        libc::ESRCH
    })
}
/// # Safety
/// buffer is null or writable for size bytes.
#[unsafe(no_mangle)]
unsafe extern "C" fn proc_pidpath(pid: c_int, buffer: *mut c_void, size: u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if pid != crate::patina_pid() {
        return refuse(pid);
    }
    if buffer.is_null() {
        return super::super::error(libc::EFAULT);
    }
    let path = c"/patina/guest".to_bytes_with_nul();
    if (size as usize) < path.len() {
        return super::super::error(libc::ENOMEM);
    }
    // SAFETY: the caller supplied `size` writable bytes and the size check covers `path`.
    unsafe {
        ptr::copy_nonoverlapping(path.as_ptr(), buffer.cast(), path.len());
    }
    (path.len() - 1) as c_int
}
#[unsafe(no_mangle)]
extern "C" fn proc_pidinfo(
    pid: c_int,
    _flavor: c_int,
    _arg: u64,
    _buffer: *mut c_void,
    _size: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if pid != crate::patina_pid() {
        return refuse(pid);
    }
    0
}
/// # Safety
/// buffer is null or holds the rusage layout named by flavor.
#[unsafe(no_mangle)]
unsafe extern "C" fn proc_pid_rusage(pid: c_int, flavor: c_int, buffer: *mut *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if pid != crate::patina_pid() {
        return refuse(pid);
    }
    if buffer.is_null() {
        return super::super::error(libc::EFAULT);
    }
    if flavor == libc::RUSAGE_INFO_V2 {
        // SAFETY: the caller's flavor contract provides writable rusage-info storage here.
        unsafe {
            ptr::write_bytes(buffer.cast::<u8>(), 0, size_of::<libc::rusage_info_v2>());
        }
        return 0;
    }
    super::super::error(libc::EINVAL)
}
#[unsafe(no_mangle)]
extern "C" fn mach_host_self() -> u32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    0x484f5354 // HOST, synthetic port consumed only by models.
}
// The modeled host reports HOST_VM_INFO64 through revision 3: the 248-byte
// prefix of vm_statistics64 that every later SDK keeps, appending newer fields
// past it (libc's binding already carries them). C checks the SDK's revision
// counts and modeled offsets. Only the first four counts are modeled; every
// remaining field stays zero.
#[repr(C)]
struct VmStatistics64 {
    free_count: u32,
    active_count: u32,
    inactive_count: u32,
    wire_count: u32,
    remaining: [u64; 29],
}
/// HOST_VM_INFO64_REV0_COUNT through HOST_VM_INFO64_REV3_COUNT, in 32-bit
/// words: each revision's reply is a prefix of the next.
const VM_INFO_REVISION_COUNTS: [u32; 4] = [24, 38, 40, 62];
const _: () = {
    assert!(size_of::<VmStatistics64>() == VM_INFO_REVISION_COUNTS[3] as usize * size_of::<i32>());
    assert!(align_of::<VmStatistics64>() == 8);
    assert!(core::mem::offset_of!(VmStatistics64, wire_count) == 12);
};
/// # Safety
/// output/count follow the HOST_VM_INFO64 buffer contract: `*count` 32-bit
/// words of writable output.
#[unsafe(no_mangle)]
unsafe extern "C" fn host_statistics64(
    _host: u32,
    flavor: c_int,
    output: *mut i32,
    count: *mut u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if flavor != libc::HOST_VM_INFO64 || output.is_null() || count.is_null() {
        return libc::KERN_INVALID_ARGUMENT;
    }
    // SAFETY: `count` is non-null and readable under the HOST_VM_INFO64 buffer contract.
    let requested = unsafe { count.read() };
    // XNU's vm_stats: fill the newest revision the caller's count holds and
    // report that revision's count; a count below revision 0 fails untouched.
    let Some(&reply) = VM_INFO_REVISION_COUNTS
        .iter()
        .rev()
        .find(|&&revision| revision <= requested)
    else {
        return libc::KERN_FAILURE;
    };
    let stat = VmStatistics64 {
        free_count: 524288,
        active_count: 786432,
        inactive_count: 524288,
        wire_count: 262144,
        remaining: [0; 29],
    };
    // SAFETY: `reply` words fit both the caller's `requested` words of output and the
    // 62-word `stat`; `count` is non-null and writable.
    unsafe {
        ptr::copy_nonoverlapping((&raw const stat).cast::<i32>(), output, reply as usize);
        count.write(reply);
    }
    libc::KERN_SUCCESS
}
/// # Safety
/// Each out-parameter is null or writable with its declared layout.
#[unsafe(no_mangle)]
unsafe extern "C" fn host_processor_info(
    _host: u32,
    flavor: c_int,
    processors: *mut u32,
    info: *mut *mut i32,
    count: *mut u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if flavor != libc::PROCESSOR_CPU_LOAD_INFO
        || processors.is_null()
        || info.is_null()
        || count.is_null()
    {
        return libc::KERN_INVALID_ARGUMENT;
    }
    // One CPU_STATE_MAX-entry tick record per virtual CPU, each idle.
    let cpus = crate::cpus::count() as usize;
    let states = libc::CPU_STATE_MAX as usize;
    let bytes = (cpus * states * size_of::<i32>()).next_multiple_of(4096);
    // SAFETY: all output pointers are non-null; the mapping is checked before use and every
    // CPU's state indices fall inside it (`bytes` covers `cpus * states` integers).
    unsafe {
        // Real host mapping: consumers either munmap these pages or call the
        // no-op vm_deallocate below. Never give munmap a static data address.
        let buffer = libc::mmap(
            ptr::null_mut(),
            bytes,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_PRIVATE,
            -1,
            0,
        )
        .cast::<i32>();
        if buffer.cast::<c_void>() == libc::MAP_FAILED {
            return libc::KERN_RESOURCE_SHORTAGE;
        }
        for cpu in 0..cpus {
            let ticks = buffer.add(cpu * states);
            ticks.add(libc::CPU_STATE_USER as usize).write(0);
            ticks.add(libc::CPU_STATE_SYSTEM as usize).write(0);
            ticks.add(libc::CPU_STATE_IDLE as usize).write(1000);
            ticks.add(libc::CPU_STATE_NICE as usize).write(0);
        }
        processors.write(cpus as u32);
        info.write(buffer);
        count.write((cpus * states) as u32);
    }
    libc::KERN_SUCCESS
}
#[unsafe(no_mangle)]
extern "C" fn vm_deallocate(_task: u32, _address: usize, _size: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    libc::KERN_SUCCESS
}
// These satisfy data references; only honest models or deny-traps consume them.
#[unsafe(no_mangle)]
pub static kCFAllocatorDefault: usize = 0;
#[unsafe(no_mangle)]
pub static kCFAllocatorNull: usize = 0;
#[repr(C)]
pub struct ArrayCallbacks {
    version: libc::c_long,
    retain: usize,
    release: usize,
    copy_description: usize,
    equal: usize,
}
#[unsafe(no_mangle)]
pub static kCFTypeArrayCallBacks: ArrayCallbacks = ArrayCallbacks {
    version: 0,
    retain: 0,
    release: 0,
    copy_description: 0,
    equal: 0,
};
#[unsafe(no_mangle)]
pub static mut kIOMasterPortDefault: c_uint = 0;
#[unsafe(no_mangle)]
pub static mut mach_task_self_: c_uint = 0x50415400;
#[unsafe(no_mangle)]
pub static mut vm_page_size: libc::c_ulong = 4096;
