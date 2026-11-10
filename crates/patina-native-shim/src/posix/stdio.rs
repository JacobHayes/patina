//! C stdio over modeled descriptors: the shim's stream table and libio's
//! buffering state machine, for reading and for writing.
//!
//! Every `FILE*` a guest holds is one of the shim's [`File`]s: the three
//! standard streams, or one `fopen`/`fdopen` made. A `FILE*` names a stream
//! by address only; any other pointer (a host `FILE`, a stream glibc made for
//! itself) stops the run by name. The bytes move through the modeled
//! descriptor calls, so every refill and flush is a guest read or write: a
//! scheduling point, recorded, and reached by filesystem faults. A stream's
//! lock is a modeled guest mutex, held across those calls as glibc holds its
//! own. State stays behind raw pointers: scheduler calls and lock-free fatal
//! salvage may reenter the engine.
#![deny(clippy::undocumented_unsafe_blocks)]

use core::ffi::{CStr, VaList, c_char, c_int, c_void};
use core::ptr::{self, null_mut};
use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};
use std::sync::OnceLock;

#[cfg(target_os = "linux")]
const BUFSIZ: usize = 8192;
#[cfg(target_os = "macos")]
const BUFSIZ: usize = 1024;
const EOF: c_int = -1;

mod files;
mod input;

/// The object a `FILE*` points at. Only its address names the stream, but it
/// is FILE-sized and zeroed but for the fields below (glibc's `struct
/// _IO_FILE` is 216 bytes on both Linux architectures, checked in
/// `c/posix/stdio.c`; Darwin's is smaller): the inline
/// `putc_unlocked`/`getc_unlocked` bodies a guest compiles read its buffer
/// pointers (or Darwin's counts), find no room, and take their slow path into
/// the shim (`__overflow`/`__uflow`, `__swbuf`/`__srget`). The stream's
/// end-of-file and error indicators LIVE in its flags word, at the platform
/// libc's bits, so the inline `feof_unlocked`/`ferror_unlocked`/
/// `clearerr_unlocked` bodies and gnulib's `fseterr` (which sets the error bit
/// itself) agree with the shim's calls; the descriptor number is mirrored
/// where the inline `fileno_unlocked` reads it.
#[repr(C, align(8))]
struct Sentinel {
    bytes: [u8; 216],
}
// glibc's `sizeof(FILE)`, which `c/posix/stdio.c` asserts beside it.
#[cfg(target_os = "linux")]
const _: () = assert!(size_of::<Sentinel>() == 216);

/// The flags word's place and the indicator bits: glibc's `_flags` (an `int`
/// at offset 0, `_IO_EOF_SEEN`/`_IO_ERR_SEEN`) and `_fileno` (offset 112 on
/// LP64); Darwin's `_flags` (a `short` at 16, `__SEOF`/`__SERR`) and `_file`
/// (a `short` at 18).
#[cfg(target_os = "linux")]
mod layout {
    pub(super) type Word = core::ffi::c_int;
    pub(super) const FLAGS: usize = 0;
    pub(super) const EOF_SEEN: Word = 0x10;
    pub(super) const ERR_SEEN: Word = 0x20;
    pub(super) const FILENO: usize = 112;
    pub(super) type FdWord = core::ffi::c_int;
}
#[cfg(target_os = "macos")]
mod layout {
    pub(super) type Word = i16;
    pub(super) const FLAGS: usize = 16;
    pub(super) const EOF_SEEN: Word = 0x20;
    pub(super) const ERR_SEEN: Word = 0x40;
    pub(super) const FILENO: usize = 18;
    pub(super) type FdWord = i16;
}

impl Sentinel {
    const fn new(fd: c_int) -> Self {
        let mut bytes = [0; 216];
        let fd = (fd as layout::FdWord).to_ne_bytes();
        let mut at = 0;
        while at < fd.len() {
            bytes[layout::FILENO + at] = fd[at];
            at += 1;
        }
        Self { bytes }
    }
}

// libc omits Darwin's recursive static initializer; preserve the header signature.
#[cfg(target_os = "macos")]
const fn darwin_lock() -> libc::pthread_mutex_t {
    let mut lock = libc::PTHREAD_MUTEX_INITIALIZER;
    // SAFETY: the local mutex value has libc's C layout; this initializes its
    // recursive-kind field before the value is published to any stream.
    unsafe {
        (&raw mut lock).cast::<libc::c_long>().write(0x32aaaba2);
    }
    lock
}

/// What a stream may do, from the mode that opened it: glibc's
/// `_IO_NO_READS`/`_IO_NO_WRITES`/`_IO_IS_APPENDING`.
#[derive(Clone, Copy)]
struct Access {
    read: bool,
    write: bool,
    append: bool,
}

struct Stream {
    fd: c_int,
    access: Access,
    unbuffered: bool,
    line: bool,
    /// The buffer holds output (put mode); otherwise it holds input from
    /// `get_pos` to `get_end`.
    putting: bool,
    buffer: Buffer,
    inline_len: usize,
    area: bool,
    used: usize,
    end: usize,
    get_pos: usize,
    get_end: usize,
    /// Bytes `ungetc` pushed back that the buffer could not take back, read
    /// before the buffer, last pushed first: glibc's backup area.
    pushback: Vec<u8>,
    lock: libc::pthread_mutex_t,
    storage: [u8; 8192],
    shortbuf: u8,
}

/// A stream's place in the table's life cycle. A heap stream `fclose`
/// retires is free for the next open to reuse, never freed: a walk of the
/// table, or a stale `FILE*`, never meets freed memory. A standard stream is
/// never reused; once closed, a call on it stops by name.
const FREE: u8 = 0;
const OPEN: u8 = 1;
const CLOSED: u8 = 2;

/// One stream: what a `FILE*` points at (`token` first, so the two
/// addresses are one) and the stream's state.
#[repr(C)]
pub(crate) struct File {
    token: Sentinel,
    state: Stream,
    /// The next stream in the table: every stream ever made, newest first.
    next: *mut File,
    life: AtomicU8,
    standard: bool,
}

impl Stream {
    const fn new(fd: c_int, access: Access, unbuffered: bool) -> Self {
        Self {
            fd,
            access,
            unbuffered,
            line: false,
            putting: false,
            buffer: Buffer::Unallocated,
            inline_len: 0,
            area: false,
            used: 0,
            end: 0,
            get_pos: 0,
            get_end: 0,
            pushback: Vec::new(),
            #[cfg(target_os = "linux")]
            lock: libc::PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP,
            #[cfg(target_os = "macos")]
            lock: darwin_lock(),
            storage: [0; 8192],
            shortbuf: 0,
        }
    }
}

impl File {
    const fn standard(fd: c_int, access: Access, unbuffered: bool, next: *mut File) -> Self {
        Self {
            token: Sentinel::new(fd),
            state: Stream::new(fd, access, unbuffered),
            next,
            life: AtomicU8::new(OPEN),
            standard: true,
        }
    }
}

const READ: Access = Access {
    read: true,
    write: false,
    append: false,
};
const WRITE: Access = Access {
    read: false,
    write: true,
    append: false,
};
static mut STDIN_FILE: File = File::standard(0, READ, false, null_mut());
static mut STDOUT_FILE: File = File::standard(1, WRITE, false, &raw mut STDIN_FILE);
static mut STDERR_FILE: File = File::standard(2, WRITE, true, &raw mut STDOUT_FILE);
/// The newest stream in the table; the list ends at the standard streams.
static TABLE: AtomicPtr<File> = AtomicPtr::new(&raw mut STDERR_FILE);

#[cfg_attr(target_os = "linux", unsafe(export_name = "stdin"))]
#[cfg_attr(target_os = "macos", unsafe(export_name = "__stdinp"))]
pub static mut STDIN: *mut libc::FILE = (&raw mut STDIN_FILE).cast();
#[cfg_attr(target_os = "linux", unsafe(export_name = "stdout"))]
#[cfg_attr(target_os = "macos", unsafe(export_name = "__stdoutp"))]
pub static mut STDOUT: *mut libc::FILE = (&raw mut STDOUT_FILE).cast();
#[cfg_attr(target_os = "linux", unsafe(export_name = "stderr"))]
#[cfg_attr(target_os = "macos", unsafe(export_name = "__stderrp"))]
pub static mut STDERR: *mut libc::FILE = (&raw mut STDERR_FILE).cast();

/// A stream the shim made: the one handle every engine function takes.
#[derive(Clone, Copy, PartialEq, Eq)]
struct StreamId(*mut File);

impl StreamId {
    fn stdout() -> Self {
        Self(&raw mut STDOUT_FILE)
    }
    fn file(self) -> *mut libc::FILE {
        self.0.cast()
    }
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

fn stream_ptr(stream: StreamId) -> *mut Stream {
    // SAFETY: a `StreamId` is only made for a table entry, which lives for the
    // process.
    unsafe { &raw mut (*stream.0).state }
}

unsafe fn buffer_ptr(stream: StreamId) -> *mut u8 {
    let state = stream_ptr(stream);
    // SAFETY: the selected stream is a process-lifetime table entry, and its
    // buffer variant identifies storage owned by that stream or a raw caller buffer.
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
    // SAFETY: the selected stream is a process-lifetime table entry; the active
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

fn flags_word(stream: StreamId) -> *mut layout::Word {
    // SAFETY: the sentinel is the entry's first field and the flags word lies
    // within it, aligned for its type.
    unsafe {
        (&raw mut (*stream.0).token.bytes)
            .cast::<u8>()
            .add(layout::FLAGS)
            .cast()
    }
}
/// Whether an indicator bit is set in the stream's flags word.
unsafe fn indicator(stream: StreamId, bit: layout::Word) -> bool {
    // SAFETY: the flags word is in a process-lifetime entry; a guest's inline
    // body may write it, so it is read volatile.
    unsafe { flags_word(stream).read_volatile() & bit != 0 }
}
/// Set or clear an indicator bit in the stream's flags word.
unsafe fn set_indicator(stream: StreamId, bit: layout::Word, on: bool) {
    let word = flags_word(stream);
    // SAFETY: as `indicator`; the caller serializes the stream.
    unsafe {
        let flags = word.read_volatile();
        word.write_volatile(if on { flags | bit } else { flags & !bit });
    }
}
/// Set a stream's error indicator.
unsafe fn set_error(stream: StreamId, error: bool) {
    // SAFETY: forwarded from the caller.
    unsafe { set_indicator(stream, layout::ERR_SEEN, error) }
}
unsafe fn has_error(stream: StreamId) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe { indicator(stream, layout::ERR_SEEN) }
}
unsafe fn set_eof(stream: StreamId, eof: bool) {
    // SAFETY: forwarded from the caller.
    unsafe { set_indicator(stream, layout::EOF_SEEN, eof) }
}
unsafe fn at_eof(stream: StreamId) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe { indicator(stream, layout::EOF_SEEN) }
}
/// Give a stream a descriptor, mirrored where inline `fileno` bodies read it.
unsafe fn set_fd(stream: StreamId, fd: c_int) {
    // SAFETY: the stream is a process-lifetime entry its caller serializes;
    // the mirror lies within the sentinel, aligned for its type.
    unsafe {
        (*stream_ptr(stream)).fd = fd;
        (&raw mut (*stream.0).token.bytes)
            .cast::<u8>()
            .add(layout::FILENO)
            .cast::<layout::FdWord>()
            .write_volatile(fd as layout::FdWord);
    }
}

/// The table entry a `FILE*` names, whatever its life, or `None`.
fn entry(stream: *mut libc::FILE) -> Option<StreamId> {
    let mut at = TABLE.load(Ordering::Acquire);
    while !at.is_null() {
        if at.cast() == stream {
            return Some(StreamId(at));
        }
        // SAFETY: table entries are never freed, and `next` is written once,
        // before the entry is published.
        at = unsafe { (*at).next };
    }
    None
}
/// The descriptor of an open stream the shim made, or -1.
#[cfg(target_os = "linux")]
pub(crate) fn stream_fd(stream: *mut libc::FILE) -> c_int {
    match entry(stream) {
        // SAFETY: the entry lives for the process.
        Some(id) if unsafe { (*id.0).life.load(Ordering::Acquire) } == OPEN => {
            // SAFETY: as above.
            unsafe { (*stream_ptr(id)).fd }
        }
        _ => -1,
    }
}
pub(crate) fn trap(symbol: &CStr) -> ! {
    for bytes in [
        b"patina: stdio call on a FILE* that is not a stream the shim opened: ".as_slice(),
        symbol.to_bytes(),
        b"; a host FILE (one a host library made for itself) is not modeled; failing closed\n",
    ] {
        // SAFETY: each static diagnostic slice is readable for its exact length
        // and the synchronous captured-stdio entry consumes it before return.
        unsafe {
            crate::patina_stdio_write(2, bytes.as_ptr().cast(), bytes.len());
        }
    }
    crate::patina_flush_captured_stdio();
    crate::host_abort(crate::RunStop::unmodeled(&[
        b"stdio call on a FILE* that is not a stream the shim opened: ",
        symbol.to_bytes(),
    ]))
}
/// The shim's stream a call names: every stdio door's one way to its stream.
/// Any other `FILE*` stops the run by name, as does a stream `fclose`
/// closed.
fn stream_of(stream: *mut libc::FILE, symbol: &CStr) -> StreamId {
    let Some(id) = entry(stream) else {
        trap(symbol)
    };
    // SAFETY: the entry lives for the process.
    if unsafe { (*id.0).life.load(Ordering::Acquire) } != OPEN {
        crate::trap_guest_misuse(&format!(
            "{} on a stream after fclose closed it",
            symbol.to_string_lossy()
        ));
    }
    id
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
        // The BSD stdio's append stream over a descriptor without
        // `O_APPEND` (one `fdopen` made) seeks to the end before it writes.
        #[cfg(target_os = "macos")]
        if (*s).access.append
            && length > 0
            && (crate::patina_fd_getfl((*s).fd) as u32) & crate::O_APPEND == 0
        {
            let _ = crate::abi::libc_result(crate::fd::seek((*s).fd, 0, 2), -1);
        }
        let mut done = 0;
        while done < length {
            super::cancel(c"write");
            // SAFETY: callers keep `data` readable for `length`; `done` remains
            // within that range, and the modeled write consumes it synchronously.
            let written = crate::patina_write((*s).fd, data.add(done).cast(), length - done);
            if written < 0 {
                super::errno(crate::patina_errno());
                set_error(stream, !crate::variadic::fault(9));
                break;
            }
            done += written as usize;
        }
        done
    }
}
unsafe fn allocate(stream: StreamId) {
    let s = stream_ptr(stream);
    // SAFETY: stream state is a table entry protected by its stream lock
    // except during teardown, where the root task is the only writer.
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
                    crate::abi::restore_host_errno(before);
                }
                if status.st_blksize > 0 && (status.st_blksize as usize) < size {
                    size = status.st_blksize as usize;
                }
            }
        } else {
            // glibc's `_IO_file_doallocate` leaves a failed fstat's errno
            // behind; the standard descriptors answer fstat on a host pipe.
            let kind = crate::patina_fd_kind((*s).fd);
            if kind == crate::fdtable::FdKind::Stdin.wire()
                || kind == crate::fdtable::FdKind::Stdout.wire()
                || kind == crate::fdtable::FdKind::Stderr.wire()
            {
                crate::abi::restore_host_errno(saved);
            }
        }
        (*s).buffer = Buffer::Inline;
        (*s).inline_len = size.min(8192);
    }
}
unsafe fn allocbuf(stream: StreamId) {
    let s = stream_ptr(stream);
    // SAFETY: the stream's state is a table entry and the caller holds its
    // lock or is on a teardown path where no competing task can mutate it.
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
    // stream fields remain valid across that callout.
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
        if !(*s).access.write {
            // glibc's `_IO_NO_WRITES`: the error indicator and `EBADF`.
            set_error(stream, true);
            super::errno(libc::EBADF);
            return EOF;
        }
        if !(*s).putting || !(*s).area {
            if !(*s).putting && !input::leave_get_mode(stream) {
                return EOF;
            }
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
    // SAFETY: the caller reads table-entry state under its lock or during
    // single-threaded teardown.
    unsafe {
        if (*s).area && (*s).putting {
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
/// `data` points to `length` readable bytes; `stream` names a table entry,
/// and its borrowed buffer remains live.
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
unsafe fn put_one(stream: StreamId, byte: u8) -> c_int {
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
/// Write out what the stream buffered for output.
unsafe fn sync(stream: StreamId) -> c_int {
    let s = stream_ptr(stream);
    // SAFETY: callers hold the stream lock or execute during single-threaded
    // teardown, and flush observes the same protected state.
    unsafe {
        if (*s).putting && (*s).area && (*s).used > 0 && flush(stream) != 0 {
            EOF
        } else {
            0
        }
    }
}
/// Every open stream, newest first, as the table holds them.
fn for_each_open(mut visit: impl FnMut(StreamId)) {
    let mut at = TABLE.load(Ordering::Acquire);
    while !at.is_null() {
        // SAFETY: entries are never freed; `next` is written before publication.
        unsafe {
            if (*at).life.load(Ordering::Acquire) == OPEN {
                visit(StreamId(at));
            }
            at = (*at).next;
        }
    }
}
/// glibc's exit flush (`_IO_cleanup`): every stream's pending output.
pub(super) extern "C" fn flush_at_exit() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    for_each_open(|stream| {
        // SAFETY: shutdown runs after guest tasks stop and owns stream state.
        unsafe {
            sync(stream);
        }
    });
}
/// # Safety
/// `bytes` points to writable pointer storage; called on terminating paths.
pub(super) unsafe extern "C" fn take_pending(bytes: *mut *const c_void) -> usize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let stream = StreamId::stdout();
    let state = stream_ptr(stream);
    // SAFETY: the shutdown caller supplies writable pointer storage; teardown
    // owns stdout state, and its inline buffer outlives the returned pointer.
    unsafe {
        let used = if (*state).area && (*state).putting {
            (*state).used
        } else {
            0
        };
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
/// glibc's fortified `__vsnprintf_chk(s, maxlen, flag, slen, format, ap)`.
#[cfg(target_os = "linux")]
type CheckedFormatter =
    unsafe extern "C" fn(*mut c_char, usize, c_int, usize, *const c_char, VaList<'_>) -> c_int;
#[cfg(target_os = "linux")]
fn checked_formatter() -> CheckedFormatter {
    static HOST: OnceLock<CheckedFormatter> = OnceLock::new();
    *HOST.get_or_init(|| {
        // SAFETY: the private resolver returns glibc's `__vsnprintf_chk`
        // entry, whose ABI is exactly `CheckedFormatter`.
        unsafe {
            core::mem::transmute::<*mut c_void, CheckedFormatter>(crate::host::hostapi::resolve(
                c"__vsnprintf_chk",
            ))
        }
    })
}
/// How a stdio door formats: plainly, or under a fortified entry's check
/// level (`_FORTIFY_SOURCE`'s `flag`), which glibc's checked formatter
/// enforces exactly as its own `__fprintf_chk` does.
#[derive(Clone, Copy)]
enum Fortify {
    Off,
    #[cfg(target_os = "linux")]
    Level(c_int),
}
/// Format into `length` bytes at `buffer` the way `fortify` asks.
///
/// # Safety
/// `buffer` is writable for `length` bytes; format and arguments obey
/// vsnprintf's contract.
unsafe fn format_into(
    fortify: Fortify,
    buffer: *mut c_char,
    length: usize,
    format: *const c_char,
    args: VaList<'_>,
) -> c_int {
    // SAFETY: forwarded from this function's contract.
    unsafe {
        match fortify {
            Fortify::Off => formatter()(buffer, length, format, args),
            #[cfg(target_os = "linux")]
            Fortify::Level(flag) => checked_formatter()(buffer, length, flag, length, format, args),
        }
    }
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
    crate::abi::restore_host_errno(saved);
    // SAFETY: the caller supplies writable `length` bytes and printf-compatible
    // format arguments, as required by this internal formatter entry.
    unsafe { formatter(buffer, length, format, args) }
}
/// # Safety
/// Format/arguments obey printf's ABI; explicit streams must be the shim's.
pub(crate) unsafe fn format_to(
    stream: *mut libc::FILE,
    format: *const c_char,
    args: VaList<'_>,
    use_stdout: bool,
) -> c_int {
    let s = if use_stdout {
        // SAFETY: the `stdout` variable is read by value; the guest may have
        // pointed it at another stream, as glibc's printf honours.
        stream_of(unsafe { STDOUT }, c"printf")
    } else {
        stream_of(stream, c"fprintf")
    };
    // SAFETY: the caller forwards printf-compatible arguments and explicit
    // streams are reduced to table entries.
    unsafe { vprintf_to(s, Fortify::Off, format, args) }
}
/// `__fprintf_chk`'s engine: [`format_to`] on an explicit stream under
/// glibc's fortify `flag`.
///
/// # Safety
/// Format/arguments obey printf's ABI; the stream must be the shim's.
#[cfg(target_os = "linux")]
pub(crate) unsafe fn format_to_checked(
    stream: *mut libc::FILE,
    flag: c_int,
    format: *const c_char,
    args: VaList<'_>,
) -> c_int {
    let s = stream_of(stream, c"__fprintf_chk");
    // SAFETY: forwarded from this function's contract.
    unsafe { vprintf_to(s, Fortify::Level(flag), format, args) }
}
unsafe fn vprintf_to(
    stream: StreamId,
    fortify: Fortify,
    format: *const c_char,
    args: VaList<'_>,
) -> c_int {
    // SAFETY: `format` and `args` satisfy printf's ABI contract; formatter output
    // is stored in live stack/heap memory before the locked stream write.
    unsafe {
        let saved = super::get_errno();
        let _ = formatter();
        #[cfg(target_os = "linux")]
        if let Fortify::Level(_) = fortify {
            let _ = checked_formatter();
        }
        crate::abi::restore_host_errno(saved);
        let second = args.clone();
        let mut stack = [0 as c_char; 512];
        let mut message = stack.as_mut_ptr();
        let mut needed = format_into(fortify, message, stack.len(), format, args);
        if needed >= stack.len() as c_int {
            message = libc::malloc(needed as usize + 1).cast();
            if message.is_null() {
                super::errno(libc::ENOMEM);
                return -1;
            }
            needed = format_into(fortify, message, needed as usize + 1, format, second);
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
    unsafe { vprintf_to(stream_of(stream, c"vfprintf"), Fortify::Off, format, args) }
}
/// # Safety
/// Format and arguments obey vprintf's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn vprintf(format: *const c_char, args: VaList<'_>) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the C caller supplies the format and va_list under vprintf's ABI;
    // `stdout` is read by value.
    unsafe { vprintf_to(stream_of(STDOUT, c"vprintf"), Fortify::Off, format, args) }
}
/// glibc's fortified `vfprintf` (`_FORTIFY_SOURCE` lowers `vfprintf` onto it):
/// the same stream door, formatting under the caller's check level.
///
/// # Safety
/// Stream, format and arguments obey vfprintf's contract.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
unsafe extern "C" fn __vfprintf_chk(
    stream: *mut libc::FILE,
    flag: c_int,
    format: *const c_char,
    args: VaList<'_>,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let s = stream_of(stream, c"__vfprintf_chk");
    // SAFETY: the C caller supplies the format and va_list under vfprintf's ABI.
    unsafe { vprintf_to(s, Fortify::Level(flag), format, args) }
}
unsafe fn fputs_impl(string: *const c_char, stream: *mut libc::FILE, symbol: &CStr) -> c_int {
    let s = stream_of(stream, symbol);
    // SAFETY: the C contract supplies a readable NUL-terminated string; locking
    // serializes stream state for the modeled write loop.
    unsafe {
        let length = libc::strlen(string);
        let held = lock(s);
        let taken = put(s, string.cast(), length);
        unlock(s, held);
        if taken == PutOutcome::Written(length) {
            // glibc answers 1; Darwin the bytes written.
            if cfg!(target_os = "macos") {
                length.min(c_int::MAX as usize) as c_int
            } else {
                1
            }
        } else {
            EOF
        }
    }
}
/// # Safety
/// String is readable and NUL-terminated; stream obeys fputs's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn fputs(string: *const c_char, stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the C contract.
    unsafe { fputs_impl(string, stream, c"fputs") }
}
unsafe fn fwrite_impl(
    pointer: *const c_void,
    size: usize,
    count: usize,
    stream: *mut libc::FILE,
    symbol: &CStr,
) -> usize {
    let s = stream_of(stream, symbol);
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
/// The source holds size*count bytes; stream obeys fwrite's contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn fwrite(
    pointer: *const c_void,
    size: usize,
    count: usize,
    stream: *mut libc::FILE,
) -> usize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded from the C contract.
    unsafe { fwrite_impl(pointer, size, count, stream, c"fwrite") }
}
/// # Safety
/// String is readable and NUL-terminated.
#[unsafe(no_mangle)]
unsafe extern "C" fn puts(string: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the C contract supplies a readable NUL-terminated string; stdout
    // is a table entry and its recursive lock protects both writes.
    unsafe {
        let s = stream_of(STDOUT, c"puts");
        let length = libc::strlen(string);
        let held = lock(s);
        let mut result = EOF;
        if put(s, string.cast(), length) == PutOutcome::Written(length) && put_one(s, b'\n') != EOF
        {
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
    // SAFETY: the selected stream is a table entry and its recursive mutex
    // protects insertion and any modeled write performed by overflow.
    unsafe {
        let held = lock(stream);
        let result = put_one(stream, character as u8);
        unlock(stream, held);
        result
    }
}
#[unsafe(no_mangle)]
extern "C" fn putchar(character: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: `stdout` names a table entry.
    unsafe { put_byte(stream_of(STDOUT, c"putchar"), character) }
}
#[unsafe(no_mangle)]
extern "C" fn fputc(character: c_int, stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: stream_of accepts only the shim's streams.
    unsafe { put_byte(stream_of(stream, c"fputc"), character) }
}
/// `putc`: `fputc` (`std::endl`, `put`).
#[unsafe(no_mangle)]
extern "C" fn putc(character: c_int, stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: stream_of accepts only the shim's streams.
    unsafe { put_byte(stream_of(stream, c"putc"), character) }
}
unsafe fn locked_flush(stream: StreamId) -> c_int {
    // SAFETY: the stream is a table entry; its recursive mutex protects the
    // flush and any modeled write loop or seek it makes.
    unsafe {
        let held = lock(stream);
        let result = input::sync_input(stream);
        unlock(stream, held);
        result
    }
}
unsafe fn fflush_impl(stream: *mut libc::FILE, symbol: &CStr) -> c_int {
    // SAFETY: null flushes every open stream's output (glibc's
    // `_IO_flush_all`); a non-null FILE* is checked against the table first.
    unsafe {
        if stream.is_null() {
            let mut result = 0;
            for_each_open(|stream| {
                let held = lock(stream);
                if sync(stream) != 0 {
                    result = EOF;
                }
                unlock(stream, held);
            });
            result
        } else {
            locked_flush(stream_of(stream, symbol))
        }
    }
}
#[unsafe(no_mangle)]
extern "C" fn fflush(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: forwarded.
    unsafe { fflush_impl(stream, c"fflush") }
}
fn ferror_impl(stream: *mut libc::FILE, symbol: &CStr) -> c_int {
    let s = stream_of(stream, symbol);
    // SAFETY: stream_of selects a table entry; the indicator lives in its flags.
    c_int::from(unsafe { has_error(s) })
}
#[unsafe(no_mangle)]
extern "C" fn ferror(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    ferror_impl(stream, c"ferror")
}
fn feof_impl(stream: *mut libc::FILE, symbol: &CStr) -> c_int {
    let s = stream_of(stream, symbol);
    // SAFETY: stream_of selects a table entry; the indicator lives in its flags.
    c_int::from(unsafe { at_eof(s) })
}
#[unsafe(no_mangle)]
extern "C" fn feof(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    feof_impl(stream, c"feof")
}
fn clearerr_impl(stream: *mut libc::FILE, symbol: &CStr) {
    let s = stream_of(stream, symbol);
    // SAFETY: stream_of selects a table entry; locking protects the update.
    unsafe {
        let held = lock(s);
        set_error(s, false);
        set_eof(s, false);
        unlock(s, held);
    }
}
#[unsafe(no_mangle)]
extern "C" fn clearerr(stream: *mut libc::FILE) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    clearerr_impl(stream, c"clearerr");
}
fn fileno_impl(stream: *mut libc::FILE, symbol: &CStr) -> c_int {
    let s = stream_of(stream, symbol);
    // SAFETY: stream_of selected a table entry.
    let fd = unsafe { (*stream_ptr(s)).fd };
    if fd < 0 {
        super::errno(libc::EBADF);
    }
    fd
}
/// `fileno`: the descriptor a stream reads or writes, as libc reports it
/// whatever that number now names.
#[unsafe(no_mangle)]
extern "C" fn fileno(stream: *mut libc::FILE) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    fileno_impl(stream, c"fileno")
}
#[unsafe(no_mangle)]
extern "C" fn flockfile(stream: *mut libc::FILE) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: stream_of accepts only table entries whose locks live for the
    // process lifetime.
    unsafe {
        lock(stream_of(stream, c"flockfile"));
    }
}
#[unsafe(no_mangle)]
extern "C" fn funlockfile(stream: *mut libc::FILE) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: stream_of accepts only table entries; the teardown check
    // preserves the existing rule about whether this call releases the lock.
    unsafe {
        unlock(
            stream_of(stream, c"funlockfile"),
            crate::patina_in_teardown() == 0,
        );
    }
}
/// `perror`: `"S: MESSAGE\n"` (just the message for a null or empty `S`)
/// on `stderr`, the message being `strerror`'s for the errno on entry.
///
/// # Safety
/// The prefix is null or a readable, NUL-terminated string.
#[unsafe(no_mangle)]
unsafe extern "C" fn perror(prefix: *const c_char) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let number = super::get_errno();
    type Strerror = unsafe extern "C" fn(c_int) -> *const c_char;
    static HOST: OnceLock<Strerror> = OnceLock::new();
    let strerror = *HOST.get_or_init(|| {
        // SAFETY: the private resolver returns the host's `strerror`, whose
        // ABI is exactly `Strerror`.
        unsafe {
            core::mem::transmute::<*mut c_void, Strerror>(crate::host::hostapi::resolve(
                c"strerror",
            ))
        }
    });
    // SAFETY: the `stderr` variable is read by value.
    let s = stream_of(unsafe { STDERR }, c"perror");
    // SAFETY: the prefix is null or a C string by contract; the host's
    // message is a C string; the stream lock serializes the puts.
    unsafe {
        let message = strerror(number);
        let held = lock(s);
        if !prefix.is_null() && prefix.read() != 0 {
            put(s, prefix.cast(), libc::strlen(prefix));
            put(s, b": ".as_ptr(), 2);
        }
        put(s, message.cast(), libc::strlen(message));
        put_one(s, b'\n');
        unlock(s, held);
        crate::abi::restore_host_errno(number);
    }
}
#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "linux")]
mod linux;
