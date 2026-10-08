//! Sentinel streams and libio's write state machine over modeled descriptors.
//! Sentinels are address tokens, never host FILE objects. State stays behind raw
//! pointers: scheduler calls and lock-free fatal salvage may reenter the engine.
#![deny(clippy::undocumented_unsafe_blocks)]

use core::ffi::{CStr, VaList, c_char, c_int, c_void};
use core::ptr::{self, null_mut};
use std::sync::OnceLock;

#[cfg(target_os = "linux")]
const BUFSIZ: usize = 8192;
#[cfg(target_os = "macos")]
const BUFSIZ: usize = 1024;
const EOF: c_int = -1;

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
    // SAFETY: the local mutex value has libc's C layout; this initializes its
    // recursive-kind field before the value is published to either stream.
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
    buffer: Buffer,
    inline_len: usize,
    area: bool,
    used: usize,
    end: usize,
    lock: libc::pthread_mutex_t,
    storage: [u8; 8192],
    shortbuf: u8,
}
#[derive(Clone, Copy)]
enum StreamId {
    Out,
    Err,
}

#[derive(Clone, Copy)]
enum Buffer {
    Unallocated,
    Inline,
    Short,
    #[cfg(target_os = "linux")]
    Borrowed {
        ptr: *mut u8,
        len: usize,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PutOutcome {
    Written(usize),
    FlushError,
}

impl Stream {
    const fn new(fd: c_int, unbuffered: bool) -> Self {
        Self {
            fd,
            unbuffered,
            line: false,
            putting: false,
            error: false,
            buffer: Buffer::Unallocated,
            inline_len: 0,
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

fn stream_ptr(stream: StreamId) -> *mut Stream {
    match stream {
        StreamId::Out => &raw mut OUT,
        StreamId::Err => &raw mut ERR,
    }
}

unsafe fn buffer_ptr(stream: StreamId) -> *mut u8 {
    let state = stream_ptr(stream);
    // SAFETY: the selected stream is a process-lifetime static, and its buffer
    // variant identifies storage owned by that stream or a raw caller buffer.
    unsafe {
        match (*state).buffer {
            Buffer::Unallocated => null_mut(),
            Buffer::Inline => (&raw mut (*state).storage).cast(),
            Buffer::Short => &raw mut (*state).shortbuf,
            #[cfg(target_os = "linux")]
            Buffer::Borrowed { ptr, .. } => ptr,
        }
    }
}

unsafe fn buffer_len(stream: StreamId) -> usize {
    let state = stream_ptr(stream);
    // SAFETY: the selected stream is a process-lifetime static; the active
    // buffer variant carries its borrowed length or selects the stored inline length.
    unsafe {
        match (*state).buffer {
            Buffer::Unallocated => 0,
            Buffer::Inline => (*state).inline_len,
            Buffer::Short => 1,
            #[cfg(target_os = "linux")]
            Buffer::Borrowed { len, .. } => len,
        }
    }
}

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
        // SAFETY: each static diagnostic slice is readable for its exact length
        // and the synchronous captured-stdio entry consumes it before return.
        unsafe {
            crate::patina_stdio_write(2, bytes.as_ptr().cast(), bytes.len());
        }
    }
    crate::patina_flush_captured_stdio();
    crate::host_abort()
}
fn stream_of(stream: *mut libc::FILE, symbol: &CStr) -> StreamId {
    match sentinel_fd(stream) {
        1 => StreamId::Out,
        2 => StreamId::Err,
        _ => trap(symbol),
    }
}
unsafe fn lock(stream: StreamId) -> bool {
    if crate::patina_in_teardown() != 0 {
        return false;
    }
    let s = stream_ptr(stream);
    // SAFETY: each stream owns a process-lifetime recursive mutex, and the raw
    // pointer addresses that mutex without creating a reference across callouts.
    unsafe { crate::patina_mutex_lock((&raw mut (*s).lock).cast()) == 0 }
}
unsafe fn unlock(stream: StreamId, held: bool) {
    if held {
        let s = stream_ptr(stream);
        // SAFETY: `held` is returned only after this stream's mutex was acquired.
        unsafe {
            crate::patina_mutex_unlock((&raw mut (*s).lock).cast());
        }
    }
}
unsafe fn write_out(stream: StreamId, data: *const u8, length: usize) -> usize {
    let s = stream_ptr(stream);
    // SAFETY: callers guarantee `data` is readable for `length`; the stream
    // state is process-lifetime storage and writes advance only within that range.
    unsafe {
        let mut done = 0;
        while done < length {
            super::cancel(c"write");
            // SAFETY: callers keep `data` readable for `length`; `done` remains
            // within that range, and the modeled write consumes it synchronously.
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
unsafe fn allocate(stream: StreamId) {
    let s = stream_ptr(stream);
    // SAFETY: stream state is static and protected by its stream lock except
    // during teardown, where the root task is the only writer.
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
        (*s).buffer = Buffer::Inline;
        (*s).inline_len = size.min(8192);
    }
}
unsafe fn allocbuf(stream: StreamId) {
    let s = stream_ptr(stream);
    // SAFETY: the stream's state is static and the caller holds its lock or is
    // on a teardown path where no competing task can mutate it.
    unsafe {
        if !matches!((*s).buffer, Buffer::Unallocated) {
            return;
        }
        if !(*s).unbuffered {
            allocate(stream);
        } else {
            (*s).buffer = Buffer::Short;
            (*s).inline_len = 0;
        }
    }
}
unsafe fn new_do_write(stream: StreamId, data: *const u8, length: usize) -> usize {
    let s = stream_ptr(stream);
    // SAFETY: the data range is readable for the synchronous modeled write and
    // stream fields remain static across that callout.
    unsafe {
        let count = write_out(stream, data, length);
        (*s).area = true;
        (*s).used = 0;
        (*s).end = if (*s).line || (*s).unbuffered {
            0
        } else {
            buffer_len(stream)
        };
        count
    }
}
unsafe fn flush(stream: StreamId) -> c_int {
    let s = stream_ptr(stream);
    // SAFETY: stream state is accessed by the lock-owning caller; the active
    // buffer is inline or raw borrowed storage whose lifetime covers this call.
    unsafe {
        let length = (*s).used;
        if length == 0 || new_do_write(stream, buffer_ptr(stream), length) == length {
            0
        } else {
            EOF
        }
    }
}
unsafe fn overflow(stream: StreamId, byte: c_int) -> c_int {
    let s = stream_ptr(stream);
    // SAFETY: callers serialize this stream; allocation establishes a buffer
    // before its first write and the state machine bounds `used` by its length.
    unsafe {
        if !(*s).putting || !(*s).area {
            if !(*s).area {
                allocbuf(stream);
            }
            (*s).area = true;
            (*s).used = 0;
            (*s).end = if (*s).line || (*s).unbuffered {
                0
            } else {
                buffer_len(stream)
            };
            (*s).putting = true;
        }
        if byte == EOF {
            return flush(stream);
        }
        if (*s).used == buffer_len(stream) && flush(stream) == EOF {
            return EOF;
        }
        // SAFETY: allocation establishes writable storage with `buffer_len`
        // bytes, and `used` is kept within that capacity by the state machine.
        buffer_ptr(stream).add((*s).used).write(byte as u8);
        (*s).used += 1;
        if ((*s).unbuffered || ((*s).line && byte == c_int::from(b'\n'))) && flush(stream) == EOF {
            return EOF;
        }
        c_int::from(byte as u8)
    }
}
unsafe fn room(stream: StreamId) -> usize {
    let s = stream_ptr(stream);
    // SAFETY: the caller reads process-lifetime stream state under its lock or
    // during single-threaded teardown.
    unsafe {
        if (*s).area {
            (*s).end.saturating_sub((*s).used)
        } else {
            0
        }
    }
}
unsafe fn copy_in(stream: StreamId, data: *const u8, length: usize) {
    let s = stream_ptr(stream);
    // A zero-length C memcpy may use the unallocated buffer. Avoid creating a
    // Rust pointer offset from null, even when no bytes are copied.
    if length != 0 {
        // SAFETY: callers keep the source readable; the state machine ensures
        // the active destination has `length` writable bytes at `used`.
        unsafe {
            // SAFETY: callers keep `data` readable; the state machine guarantees
            // that the destination has `length` free bytes in the active buffer.
            ptr::copy_nonoverlapping(data, buffer_ptr(stream).add((*s).used), length);
            (*s).used += length;
        }
    }
}
unsafe fn default_put(stream: StreamId, mut data: *const u8, length: usize) -> usize {
    // SAFETY: the caller guarantees `length` readable input bytes; iterations
    // advance only over bytes copied or consumed by the stream state machine.
    unsafe {
        let mut more = length;
        loop {
            let count = room(stream).min(more);
            copy_in(stream, data, count);
            data = data.add(count);
            more -= count;
            // SAFETY: when `more` is nonzero, `data` points at its next readable byte.
            if more == 0 || overflow(stream, c_int::from(data.read())) == EOF {
                break;
            }
            data = data.add(1);
            more -= 1;
        }
        length - more
    }
}
/// # Safety
/// `data` points to `length` readable bytes; `stream` names one of the two
/// process-lifetime stream states, and its borrowed buffer remains live.
unsafe fn put(stream: StreamId, mut data: *const u8, length: usize) -> PutOutcome {
    let s = stream_ptr(stream);
    // SAFETY: the caller guarantees readable input and serializes this stream;
    // the state machine advances within the input range and active buffer.
    unsafe {
        if length == 0 {
            return PutOutcome::Written(0);
        }
        let mut to_do = length;
        let mut must_flush = false;
        let mut count;
        if (*s).line && (*s).putting {
            count = buffer_len(stream) - (*s).used;
            if count >= length {
                for at in (0..length).rev() {
                    // SAFETY: the caller guarantees all `length` bytes are readable.
                    if data.add(at).read() == b'\n' {
                        count = at + 1;
                        must_flush = true;
                        break;
                    }
                }
            }
        } else {
            count = room(stream);
        }
        if count > 0 {
            count = count.min(to_do);
            copy_in(stream, data, count);
            data = data.add(count);
            to_do -= count;
        }
        if to_do > 0 || must_flush {
            if overflow(stream, EOF) == EOF {
                return if to_do == 0 {
                    PutOutcome::FlushError
                } else {
                    PutOutcome::Written(length - to_do)
                };
            }
            let block = buffer_len(stream);
            let direct = to_do - if block >= 128 { to_do % block } else { 0 };
            if direct != 0 {
                let written = new_do_write(stream, data, direct);
                to_do -= written;
                if written < direct {
                    return PutOutcome::Written(length - to_do);
                }
            }
            if to_do != 0 {
                to_do -= default_put(stream, data.add(direct), to_do);
            }
        }
        PutOutcome::Written(length - to_do)
    }
}
unsafe fn putc(stream: StreamId, byte: u8) -> c_int {
    // SAFETY: callers serialize the stream and overflow allocates before writing
    // when there is no current buffer.
    unsafe {
        if room(stream) == 0 {
            return overflow(stream, c_int::from(byte));
        }
        copy_in(stream, &byte, 1);
        c_int::from(byte)
    }
}
unsafe fn sync(stream: StreamId) -> c_int {
    let s = stream_ptr(stream);
    // SAFETY: callers hold the stream lock or execute during single-threaded
    // teardown, and flush observes the same protected state.
    unsafe {
        if (*s).area && (*s).used > 0 && flush(stream) != 0 {
            EOF
        } else {
            0
        }
    }
}
pub(super) extern "C" fn flush_at_exit() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: shutdown runs after guest tasks stop and owns the stream state.
    unsafe {
        sync(StreamId::Out);
    }
}
/// # Safety
/// `bytes` points to writable pointer storage; called on terminating paths.
pub(super) unsafe extern "C" fn take_pending(bytes: *mut *const c_void) -> usize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let stream = StreamId::Out;
    let state = stream_ptr(stream);
    // SAFETY: the shutdown caller supplies writable pointer storage; teardown
    // owns stdout state, and its inline buffer outlives the returned pointer.
    unsafe {
        let used = if (*state).area { (*state).used } else { 0 };
        bytes.write(buffer_ptr(stream).cast());
        (*state).used = 0;
        used
    }
}
unsafe fn put_formatted(stream: StreamId, data: *const u8, length: usize) -> bool {
    // SAFETY: the caller owns the formatted byte slice for this call and holds
    // the stream lock while its contents are copied into stream storage.
    unsafe {
        let mut at = 0;
        while at < length {
            let available = room(stream);
            if available > 0 {
                let count = (length - at).min(available);
                copy_in(stream, data.add(at), count);
                at += count;
                if at < length && room(stream) == 0 {
                    // SAFETY: `at < length`, so the next formatted byte is readable.
                    let result = overflow(stream, c_int::from(data.add(at).read()));
                    at += 1;
                    if result == EOF {
                        return false;
                    }
                }
            } else {
                let count = (length - at).min(128);
                if put(stream, data.add(at), count) != PutOutcome::Written(count) {
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
    *HOST.get_or_init(|| {
        // SAFETY: the private resolver returns the host's `vsnprintf` entry,
        // whose ABI is exactly `Formatter`.
        unsafe {
            core::mem::transmute::<*mut c_void, Formatter>(crate::host::hostapi::resolve(
                c"vsnprintf",
            ))
        }
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
    // SAFETY: the caller supplies writable `length` bytes and printf-compatible
    // format arguments, as required by this internal formatter entry.
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
        StreamId::Out
    } else {
        stream_of(stream, c"fprintf")
    };
    // SAFETY: the caller forwards printf-compatible arguments and explicit
    // streams are reduced to the two sentinel states.
    unsafe { vprintf(s, format, args) }
}
unsafe fn vprintf(stream: StreamId, format: *const c_char, args: VaList<'_>) -> c_int {
    // SAFETY: `format` and `args` satisfy printf's ABI contract; formatter output
    // is stored in live stack/heap memory before the locked stream write.
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
            let held = lock(stream);
            if !put_formatted(stream, message.cast(), needed as usize) {
                needed = -1;
            }
            unlock(stream, held);
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
unsafe extern "C" fn vfprintf(
    stream: *mut libc::FILE,
    format: *const c_char,
    args: VaList<'_>,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the C caller supplies the format and va_list under vfprintf's ABI.
    unsafe { vprintf(stream_of(stream, c"vfprintf"), format, args) }
}
/// # Safety
/// String is readable and NUL-terminated; stream obeys fputs's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn fputs(string: *const c_char, stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let s = stream_of(stream, c"fputs");
    // SAFETY: the C contract supplies a readable NUL-terminated string; locking
    // serializes stream state for the modeled write loop.
    unsafe {
        let length = libc::strlen(string);
        let held = lock(s);
        let taken = put(s, string.cast(), length);
        unlock(s, held);
        if taken == PutOutcome::Written(length) {
            1
        } else {
            EOF
        }
    }
}
/// # Safety
/// The source holds size*count bytes; stream obeys fwrite's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn fwrite(
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
    // SAFETY: the C contract supplies `request` readable bytes when nonzero;
    // the stream lock protects state throughout the modeled write loop.
    unsafe {
        let held = lock(s);
        let taken = put(s, pointer.cast(), request);
        unlock(s, held);
        match taken {
            PutOutcome::Written(taken) if taken != request => taken / size,
            PutOutcome::Written(_) | PutOutcome::FlushError => count,
        }
    }
}
/// # Safety
/// String is readable and NUL-terminated.
#[unsafe(no_mangle)]
unsafe extern "C" fn puts(string: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the C contract supplies a readable NUL-terminated string; stdout
    // is static and its recursive lock protects both writes.
    unsafe {
        let s = StreamId::Out;
        let length = libc::strlen(string);
        let held = lock(s);
        let mut result = EOF;
        if put(s, string.cast(), length) == PutOutcome::Written(length) && putc(s, b'\n') != EOF {
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
unsafe fn put_byte(stream: StreamId, character: c_int) -> c_int {
    // SAFETY: the selected stream is static and its recursive mutex protects
    // insertion and any modeled write performed by overflow.
    unsafe {
        let held = lock(stream);
        let result = putc(stream, character as u8);
        unlock(stream, held);
        result
    }
}
#[unsafe(no_mangle)]
extern "C" fn putchar(character: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: stdout is a process-lifetime stream selected by this fixed door.
    unsafe { put_byte(StreamId::Out, character) }
}
#[unsafe(no_mangle)]
extern "C" fn fputc(character: c_int, stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: stream_of accepts only the two sentinel FILE tokens.
    unsafe { put_byte(stream_of(stream, c"fputc"), character) }
}
unsafe fn locked_flush(stream: StreamId) -> c_int {
    // SAFETY: the stream is static; its recursive mutex protects flush and any
    // modeled write loop it invokes.
    unsafe {
        let held = lock(stream);
        let result = sync(stream);
        unlock(stream, held);
        result
    }
}
#[unsafe(no_mangle)]
extern "C" fn fflush(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: null flushes the two process-lifetime streams; non-null FILE* is
    // checked against their sentinels before its state is accessed.
    unsafe {
        if stream.is_null() {
            let out = locked_flush(StreamId::Out);
            let err = locked_flush(StreamId::Err);
            if out == 0 && err == 0 { 0 } else { EOF }
        } else {
            locked_flush(stream_of(stream, c"fflush"))
        }
    }
}
#[unsafe(no_mangle)]
extern "C" fn ferror(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let s = stream_of(stream, c"ferror");
    let state = stream_ptr(s);
    // SAFETY: stream_of selects a static state, and locking protects the error
    // bit read from concurrent stream operations.
    unsafe {
        let held = lock(s);
        let result = c_int::from((*state).error);
        unlock(s, held);
        result
    }
}
#[unsafe(no_mangle)]
extern "C" fn clearerr(stream: *mut libc::FILE) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let s = stream_of(stream, c"clearerr");
    let state = stream_ptr(s);
    // SAFETY: stream_of selects a static state, and locking protects the error
    // bit update from concurrent stream operations.
    unsafe {
        let held = lock(s);
        (*state).error = false;
        unlock(s, held);
    }
}
#[unsafe(no_mangle)]
extern "C" fn flockfile(stream: *mut libc::FILE) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: stream_of accepts only sentinel tokens whose static locks live
    // for the process lifetime.
    unsafe {
        lock(stream_of(stream, c"flockfile"));
    }
}
#[unsafe(no_mangle)]
extern "C" fn funlockfile(stream: *mut libc::FILE) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: stream_of accepts only sentinels; the teardown check preserves
    // the existing rule about whether this call releases the stream lock.
    unsafe {
        unlock(
            stream_of(stream, c"funlockfile"),
            crate::patina_in_teardown() == 0,
        );
    }
}
#[cfg(target_os = "linux")]
mod linux;
