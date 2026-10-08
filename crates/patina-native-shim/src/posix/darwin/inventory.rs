//! Empty trust roots, UTC timezone, and fixed process/host inventory.
//! CF objects are distinct address tokens, never real framework objects.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;
static mut EMPTY_ARRAY: u8 = 0;
static mut SYSTEM_TIMEZONE: u8 = 0;
static mut TIMEZONE_NAME: u8 = 0;

pub(super) fn native_trap(class: &core::ffi::CStr, symbol: &core::ffi::CStr) -> ! {
    for bytes in [
        b"patina: ".as_slice(),
        class.to_bytes(),
        b" reached under patina: ",
        symbol.to_bytes(),
        b"; not interposed by the deterministic runtime; failing closed\n",
    ] {
        // SAFETY: `bytes` is a live slice for the duration of this synchronous host write.
        unsafe {
            crate::patina_stdio_write(2, bytes.as_ptr().cast(), bytes.len());
        }
    }
    crate::patina_flush_captured_stdio();
    crate::host_abort()
}
// The existing registry generator emits guarded functions, with the original
// arity-free trap ABI: callers cannot return from any of these dormant helpers.
include!(concat!(env!("OUT_DIR"), "/darwin_traps.rs"));

#[unsafe(no_mangle)]
pub extern "C" fn SecTrustSettingsCopyCertificates(
    _domain: c_uint,
    _out: *mut *mut c_void,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    -25263 // errSecNoTrustSettings: empty iterator, ignored out-parameter.
}
#[unsafe(no_mangle)]
pub extern "C" fn CFArrayCreate(
    _allocator: *const c_void,
    _values: *const *const c_void,
    _count: libc::c_long,
    _callbacks: *const c_void,
) -> *const c_void {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    (&raw const EMPTY_ARRAY).cast()
}
#[unsafe(no_mangle)]
pub extern "C" fn CFArrayGetCount(_array: *const c_void) -> libc::c_long {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn CFRelease(_object: *const c_void) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
}
#[unsafe(no_mangle)]
pub extern "C" fn CFTimeZoneResetSystem() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
}
#[unsafe(no_mangle)]
pub extern "C" fn CFTimeZoneCopySystem() -> *const c_void {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    (&raw const SYSTEM_TIMEZONE).cast()
}
#[unsafe(no_mangle)]
pub extern "C" fn CFTimeZoneGetName(_zone: *const c_void) -> *const c_void {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    (&raw const TIMEZONE_NAME).cast()
}
#[unsafe(no_mangle)]
pub extern "C" fn CFStringGetCStringPtr(
    _string: *const c_void,
    _encoding: c_uint,
) -> *const c_char {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    c"UTC".as_ptr()
}
#[unsafe(no_mangle)]
pub extern "C" fn IOServiceMatching(_name: *const c_char) -> *mut c_void {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    ptr::null_mut()
}
/// # Safety
/// buffer is null or writable for buffersize bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proc_listallpids(buffer: *mut c_void, buffersize: c_int) -> c_int {
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
pub unsafe extern "C" fn proc_pidpath(pid: c_int, buffer: *mut c_void, size: u32) -> c_int {
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
pub extern "C" fn proc_pidinfo(
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
pub unsafe extern "C" fn proc_pid_rusage(
    pid: c_int,
    flavor: c_int,
    buffer: *mut *mut c_void,
) -> c_int {
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
pub extern "C" fn mach_host_self() -> u32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    0x484f5354 // HOST, synthetic port consumed only by models.
}
// libc's unversioned vm_statistics64 binding already includes fields newer
// than the packaged SDK. Preserve that SDK's 248-byte reply, checked in C too.
// Only the first four counts are modeled; every remaining field stays zero.
#[repr(C)]
struct VmStatistics64 {
    free_count: u32,
    active_count: u32,
    inactive_count: u32,
    wire_count: u32,
    remaining: [u64; 29],
}
const VM_INFO_COUNT: u32 = (size_of::<VmStatistics64>() / size_of::<i32>()) as u32;
const _: () = {
    assert!(size_of::<VmStatistics64>() == 248 && align_of::<VmStatistics64>() == 8);
    assert!(core::mem::offset_of!(VmStatistics64, wire_count) == 12);
};
/// # Safety
/// output/count follow the HOST_VM_INFO64 buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn host_statistics64(
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
    if unsafe { count.read() } < VM_INFO_COUNT {
        return libc::KERN_INVALID_ARGUMENT;
    }
    // SAFETY: the caller supplied output/count storage of the validated size; the local `stat`
    // is initialized before its bytes are copied, and every written output is non-null.
    unsafe {
        let mut stat: VmStatistics64 = core::mem::zeroed();
        stat.free_count = 524288;
        stat.active_count = 786432;
        stat.inactive_count = 524288;
        stat.wire_count = 262144;
        ptr::copy_nonoverlapping(
            (&raw const stat).cast::<u8>(),
            output.cast(),
            size_of::<VmStatistics64>(),
        );
        count.write(VM_INFO_COUNT);
    }
    libc::KERN_SUCCESS
}
/// # Safety
/// Each out-parameter is null or writable with its declared layout.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn host_processor_info(
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
    // SAFETY: all output pointers are non-null; the mapping is checked before use and the
    // CPU-state indices fit its one-page allocation.
    unsafe {
        // Real host mapping: consumers either munmap this page or call the
        // no-op vm_deallocate below. Never give munmap a static data address.
        let buffer = libc::mmap(
            ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_PRIVATE,
            -1,
            0,
        )
        .cast::<i32>();
        if buffer.cast::<c_void>() == libc::MAP_FAILED {
            return libc::KERN_RESOURCE_SHORTAGE;
        }
        buffer.add(libc::CPU_STATE_USER as usize).write(0);
        buffer.add(libc::CPU_STATE_SYSTEM as usize).write(0);
        buffer.add(libc::CPU_STATE_IDLE as usize).write(1000);
        buffer.add(libc::CPU_STATE_NICE as usize).write(0);
        processors.write(1);
        info.write(buffer);
        count.write(libc::CPU_STATE_MAX as u32);
    }
    libc::KERN_SUCCESS
}
#[unsafe(no_mangle)]
pub extern "C" fn vm_deallocate(_task: u32, _address: usize, _size: usize) -> c_int {
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
