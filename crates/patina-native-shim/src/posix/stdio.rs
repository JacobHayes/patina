//! Sentinel streams and libio's write state machine over modeled descriptors.
//! Sentinels are address tokens, never host FILE objects. State stays behind raw
//! pointers: scheduler calls and lock-free fatal salvage may reenter the engine.
use core::ffi::{CStr, VaList, c_char, c_int, c_void};
use core::ptr::{self, null_mut};
use std::sync::OnceLock;

#[cfg(target_os = "linux")]
const BUFSIZ: usize = 8192;
#[cfg(target_os = "macos")]
const BUFSIZ: usize = 1024;
const EOF: c_int = -1;
const PUT_EOF: usize = usize::MAX;

// Distinct writable addresses; neither guest nor host dereferences these tokens.
static mut OUT_TOKEN: u8 = 0;
static mut ERR_TOKEN: u8 = 0;
#[cfg_attr(target_os = "linux", unsafe(export_name = "stdout"))]
#[cfg_attr(target_os = "macos", unsafe(export_name = "__stdoutp"))]
pub static mut STDOUT: *mut libc::FILE = (&raw mut OUT_TOKEN).cast();
#[cfg_attr(target_os = "linux", unsafe(export_name = "stderr"))]
#[cfg_attr(target_os = "macos", unsafe(export_name = "__stderrp"))]
pub static mut STDERR: *mut libc::FILE = (&raw mut ERR_TOKEN).cast();

// libc omits Darwin's recursive static initializer; preserve the header signature.
#[cfg(target_os = "macos")]
const fn darwin_lock() -> libc::pthread_mutex_t {
    let mut lock = libc::PTHREAD_MUTEX_INITIALIZER;
    unsafe {
        (&raw mut lock).cast::<libc::c_long>().write(0x32aaaba2);
    }
    lock
}

struct Stream {
    fd: c_int,
    unbuffered: bool,
    line: bool,
    putting: bool,
    error: bool,
    bytes: *mut u8,
    size: usize,
    area: bool,
    used: usize,
    end: usize,
    lock: libc::pthread_mutex_t,
    storage: [u8; 8192],
    shortbuf: u8,
}
impl Stream {
    const fn new(fd: c_int, unbuffered: bool) -> Self {
        Self {
            fd,
            unbuffered,
            line: false,
            putting: false,
            error: false,
            bytes: null_mut(),
            size: 0,
            area: false,
            used: 0,
            end: 0,
            #[cfg(target_os = "linux")]
            lock: libc::PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP,
            #[cfg(target_os = "macos")]
            lock: darwin_lock(),
            storage: [0; 8192],
            shortbuf: 0,
        }
    }
}
static mut OUT: Stream = Stream::new(1, false);
static mut ERR: Stream = Stream::new(2, true);

pub(crate) fn sentinel_fd(stream: *mut libc::FILE) -> c_int {
    if stream == (&raw mut OUT_TOKEN).cast() {
        1
    } else if stream == (&raw mut ERR_TOKEN).cast() {
        2
    } else {
        -1
    }
}
pub(crate) fn trap(symbol: &CStr) -> ! {
    for bytes in [
        b"patina: stdio call on a non-sentinel FILE* reached under patina: ".as_slice(),
        symbol.to_bytes(),
        b"; a host FILE* means an un-interposed fopen leaked through; failing closed\n",
    ] {
        unsafe {
            crate::patina_stdio_write(2, bytes.as_ptr().cast(), bytes.len());
        }
    }
    crate::patina_flush_captured_stdio();
    crate::host_abort()
}
fn stream_of(stream: *mut libc::FILE, symbol: &CStr) -> *mut Stream {
    match sentinel_fd(stream) {
        1 => &raw mut OUT,
        2 => &raw mut ERR,
        _ => trap(symbol),
    }
}
unsafe fn lock(s: *mut Stream) -> bool {
    if crate::patina_in_teardown() != 0 {
        return false;
    }
    unsafe { crate::patina_mutex_lock((&raw mut (*s).lock).cast()) == 0 }
}
unsafe fn unlock(s: *mut Stream, held: bool) {
    if held {
        unsafe {
            crate::patina_mutex_unlock((&raw mut (*s).lock).cast());
        }
    }
}
unsafe fn write_out(s: *mut Stream, data: *const u8, length: usize) -> usize {
    unsafe {
        let mut done = 0;
        while done < length {
            super::cancel(c"write");
            let written = crate::patina_write((*s).fd, data.add(done).cast(), length - done);
            if written < 0 {
                super::errno(crate::patina_errno());
                (*s).error = !crate::variadic::fault(9);
                break;
            }
            done += written as usize;
        }
        done
    }
}
unsafe fn allocate(s: *mut Stream) {
    unsafe {
        let mut size = BUFSIZ;
        let saved = super::get_errno();
        let mut values = core::mem::MaybeUninit::uninit();
        let mut status = core::mem::MaybeUninit::<libc::stat>::uninit();
        if super::fs::metadata::fd_stat((*s).fd, values.as_mut_ptr(), status.as_mut_ptr()) == 0 {
            let status = status.assume_init();
            #[cfg(target_os = "macos")]
            if status.st_blksize > 0 {
                size = status.st_blksize as usize;
            }
            #[cfg(target_os = "linux")]
            {
                if status.st_mode & libc::S_IFMT == libc::S_IFCHR {
                    let major = values.assume_init().rdev_major;
                    let before = super::get_errno();
                    if (136..=143).contains(&major)
                        || super::fd_io::linux::isatty_impl((*s).fd) != 0
                    {
                        (*s).line = true;
                    }
                    super::errno(before);
                }
                if status.st_blksize > 0 && (status.st_blksize as usize) < size {
                    size = status.st_blksize as usize;
                }
            }
        } else {
            let kind = crate::patina_fd_kind((*s).fd);
            if kind == crate::fdtable::FdKind::Stdout.wire()
                || kind == crate::fdtable::FdKind::Stderr.wire()
            {
                super::errno(saved);
            }
        }
        (*s).bytes = (&raw mut (*s).storage).cast();
        (*s).size = size.min(8192);
    }
}
unsafe fn allocbuf(s: *mut Stream) {
    unsafe {
        if !(*s).bytes.is_null() {
            return;
        }
        if !(*s).unbuffered {
            allocate(s);
        } else {
            (*s).bytes = &raw mut (*s).shortbuf;
            (*s).size = 1;
        }
    }
}
unsafe fn new_do_write(s: *mut Stream, data: *const u8, length: usize) -> usize {
    unsafe {
        let count = write_out(s, data, length);
        (*s).area = true;
        (*s).used = 0;
        (*s).end = if (*s).line || (*s).unbuffered {
            0
        } else {
            (*s).size
        };
        count
    }
}
unsafe fn flush(s: *mut Stream) -> c_int {
    unsafe {
        let length = (*s).used;
        if length == 0 || new_do_write(s, (*s).bytes, length) == length {
            0
        } else {
            EOF
        }
    }
}
unsafe fn overflow(s: *mut Stream, byte: c_int) -> c_int {
    unsafe {
        if !(*s).putting || !(*s).area {
            if !(*s).area {
                allocbuf(s);
            }
            (*s).area = true;
            (*s).used = 0;
            (*s).end = if (*s).line || (*s).unbuffered {
                0
            } else {
                (*s).size
            };
            (*s).putting = true;
        }
        if byte == EOF {
            return flush(s);
        }
        if (*s).used == (*s).size && flush(s) == EOF {
            return EOF;
        }
        (*s).bytes.add((*s).used).write(byte as u8);
        (*s).used += 1;
        if ((*s).unbuffered || ((*s).line && byte == c_int::from(b'\n'))) && flush(s) == EOF {
            return EOF;
        }
        c_int::from(byte as u8)
    }
}
unsafe fn room(s: *mut Stream) -> usize {
    unsafe {
        if (*s).area {
            (*s).end.saturating_sub((*s).used)
        } else {
            0
        }
    }
}
unsafe fn copy_in(s: *mut Stream, data: *const u8, length: usize) {
    // A zero-length C memcpy may use the unallocated buffer. Avoid creating a
    // Rust pointer offset from null, even when no bytes are copied.
    if length != 0 {
        unsafe {
            ptr::copy_nonoverlapping(data, (*s).bytes.add((*s).used), length);
            (*s).used += length;
        }
    }
}
unsafe fn default_put(s: *mut Stream, mut data: *const u8, length: usize) -> usize {
    unsafe {
        let mut more = length;
        loop {
            let count = room(s).min(more);
            copy_in(s, data, count);
            data = data.add(count);
            more -= count;
            if more == 0 || overflow(s, c_int::from(data.read())) == EOF {
                break;
            }
            data = data.add(1);
            more -= 1;
        }
        length - more
    }
}
unsafe fn put(s: *mut Stream, mut data: *const u8, length: usize) -> usize {
    unsafe {
        if length == 0 {
            return 0;
        }
        let mut to_do = length;
        let mut must_flush = false;
        let mut count;
        if (*s).line && (*s).putting {
            count = (*s).size - (*s).used;
            if count >= length {
                for at in (0..length).rev() {
                    if data.add(at).read() == b'\n' {
                        count = at + 1;
                        must_flush = true;
                        break;
                    }
                }
            }
        } else {
            count = room(s);
        }
        if count > 0 {
            count = count.min(to_do);
            copy_in(s, data, count);
            data = data.add(count);
            to_do -= count;
        }
        if to_do > 0 || must_flush {
            if overflow(s, EOF) == EOF {
                return if to_do == 0 { PUT_EOF } else { length - to_do };
            }
            let block = (*s).size;
            let direct = to_do - if block >= 128 { to_do % block } else { 0 };
            if direct != 0 {
                let written = new_do_write(s, data, direct);
                to_do -= written;
                if written < direct {
                    return length - to_do;
                }
            }
            if to_do != 0 {
                to_do -= default_put(s, data.add(direct), to_do);
            }
        }
        length - to_do
    }
}
unsafe fn putc(s: *mut Stream, byte: u8) -> c_int {
    unsafe {
        if room(s) == 0 {
            return overflow(s, c_int::from(byte));
        }
        copy_in(s, &byte, 1);
        c_int::from(byte)
    }
}
unsafe fn sync(s: *mut Stream) -> c_int {
    unsafe {
        if (*s).area && (*s).used > 0 && flush(s) != 0 {
            EOF
        } else {
            0
        }
    }
}
pub(super) extern "C" fn flush_at_exit() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        sync(&raw mut OUT);
    }
}
/// # Safety
/// `bytes` points to writable pointer storage; called on terminating paths.
pub(super) unsafe extern "C" fn take_pending(bytes: *mut *const c_void) -> usize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        let used = if OUT.area { OUT.used } else { 0 };
        bytes.write(OUT.bytes.cast());
        OUT.used = 0;
        used
    }
}
unsafe fn put_formatted(s: *mut Stream, data: *const u8, length: usize) -> bool {
    unsafe {
        let mut at = 0;
        while at < length {
            let available = room(s);
            if available > 0 {
                let count = (length - at).min(available);
                copy_in(s, data.add(at), count);
                at += count;
                if at < length && room(s) == 0 {
                    let result = overflow(s, c_int::from(data.add(at).read()));
                    at += 1;
                    if result == EOF {
                        return false;
                    }
                }
            } else {
                let count = (length - at).min(128);
                if put(s, data.add(at), count) != count {
                    return false;
                }
                at += count;
            }
        }
        true
    }
}
type Formatter = unsafe extern "C" fn(*mut c_char, usize, *const c_char, VaList<'_>) -> c_int;
fn formatter() -> Formatter {
    static HOST: OnceLock<Formatter> = OnceLock::new();
    *HOST.get_or_init(|| unsafe {
        core::mem::transmute::<*mut c_void, Formatter>(crate::host::hostapi::resolve(c"vsnprintf"))
    })
}
#[cfg(target_os = "macos")]
pub(crate) unsafe fn format_buffer(
    buffer: *mut c_char,
    length: usize,
    format: *const c_char,
    args: VaList<'_>,
) -> c_int {
    let saved = super::get_errno();
    let formatter = formatter();
    super::errno(saved);
    unsafe { formatter(buffer, length, format, args) }
}
/// # Safety
/// Format/arguments obey printf's ABI; explicit streams must be sentinels.
pub(crate) unsafe fn format_to(
    stream: *mut libc::FILE,
    format: *const c_char,
    args: VaList<'_>,
    use_stdout: bool,
) -> c_int {
    let s = if use_stdout {
        &raw mut OUT
    } else {
        stream_of(stream, c"fprintf")
    };
    unsafe { vprintf(s, format, args) }
}
unsafe fn vprintf(s: *mut Stream, format: *const c_char, args: VaList<'_>) -> c_int {
    unsafe {
        let saved = super::get_errno();
        let formatter = formatter();
        super::errno(saved);
        let second = args.clone();
        let mut stack = [0 as c_char; 512];
        let mut message = stack.as_mut_ptr();
        let mut needed = formatter(message, stack.len(), format, args);
        if needed >= stack.len() as c_int {
            message = libc::malloc(needed as usize + 1).cast();
            if message.is_null() {
                super::errno(libc::ENOMEM);
                return -1;
            }
            needed = formatter(message, needed as usize + 1, format, second);
        }
        if needed > 0 {
            let held = lock(s);
            if !put_formatted(s, message.cast(), needed as usize) {
                needed = -1;
            }
            unlock(s, held);
        }
        if message != stack.as_mut_ptr() {
            libc::free(message.cast());
        }
        needed
    }
}
/// # Safety
/// Stream, format and arguments obey vfprintf's contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vfprintf(
    stream: *mut libc::FILE,
    format: *const c_char,
    args: VaList<'_>,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { vprintf(stream_of(stream, c"vfprintf"), format, args) }
}
/// # Safety
/// String is readable and NUL-terminated; stream obeys fputs's contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fputs(string: *const c_char, stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let s = stream_of(stream, c"fputs");
    unsafe {
        let length = libc::strlen(string);
        let held = lock(s);
        let taken = put(s, string.cast(), length);
        unlock(s, held);
        if taken == length { 1 } else { EOF }
    }
}
/// # Safety
/// The source holds size*count bytes; stream obeys fwrite's contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fwrite(
    pointer: *const c_void,
    size: usize,
    count: usize,
    stream: *mut libc::FILE,
) -> usize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let s = stream_of(stream, c"fwrite");
    let request = size.wrapping_mul(count);
    if request == 0 {
        return 0;
    }
    unsafe {
        let held = lock(s);
        let taken = put(s, pointer.cast(), request);
        unlock(s, held);
        if taken == request || taken == PUT_EOF {
            count
        } else {
            taken / size
        }
    }
}
/// # Safety
/// String is readable and NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn puts(string: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        let s = &raw mut OUT;
        let length = libc::strlen(string);
        let held = lock(s);
        let mut result = EOF;
        if put(s, string.cast(), length) == length && putc(s, b'\n') != EOF {
            result = if length < c_int::MAX as usize {
                (length + 1) as c_int
            } else {
                c_int::MAX
            };
        }
        unlock(s, held);
        result
    }
}
unsafe fn put_byte(s: *mut Stream, character: c_int) -> c_int {
    unsafe {
        let held = lock(s);
        let result = putc(s, character as u8);
        unlock(s, held);
        result
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn putchar(character: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { put_byte(&raw mut OUT, character) }
}
#[unsafe(no_mangle)]
pub extern "C" fn fputc(character: c_int, stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { put_byte(stream_of(stream, c"fputc"), character) }
}
unsafe fn locked_flush(s: *mut Stream) -> c_int {
    unsafe {
        let held = lock(s);
        let result = sync(s);
        unlock(s, held);
        result
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn fflush(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        if stream.is_null() {
            let out = locked_flush(&raw mut OUT);
            let err = locked_flush(&raw mut ERR);
            if out == 0 && err == 0 { 0 } else { EOF }
        } else {
            locked_flush(stream_of(stream, c"fflush"))
        }
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn ferror(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let s = stream_of(stream, c"ferror");
    unsafe {
        let held = lock(s);
        let result = c_int::from((*s).error);
        unlock(s, held);
        result
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn clearerr(stream: *mut libc::FILE) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let s = stream_of(stream, c"clearerr");
    unsafe {
        let held = lock(s);
        (*s).error = false;
        unlock(s, held);
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn flockfile(stream: *mut libc::FILE) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        lock(stream_of(stream, c"flockfile"));
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn funlockfile(stream: *mut libc::FILE) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        unlock(
            stream_of(stream, c"funlockfile"),
            crate::patina_in_teardown() == 0,
        );
    }
}
#[cfg(target_os = "linux")]
mod linux;
