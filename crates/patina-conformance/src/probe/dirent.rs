//! The directory-stream API (dirent.h): `opendir`, `fdopendir`, the three
//! reads (`readdir`, `readdir64`, `readdir_r`), `rewinddir`, `dirfd` and
//! `closedir`. glibc's calls, not rows: the libc vehicle is the only door, and
//! each event is named for the function it recorded.
//!
//! Entry order is the filesystem's business (hash order on ext4), so a full
//! listing is recorded sorted, and a single step records only whether it
//! produced an entry. `d_ino` and `d_off` are never recorded: the inode is
//! related to `stat`'s by the scenario, and the offset is a filesystem cookie.

use super::{Probe, cstr};
use crate::observe::Norm;
use crate::vehicle::errno;
use std::ffi::CStr;

/// An open directory stream; `closedir` consumes it.
pub struct Dir(*mut libc::DIR);

/// Which glibc function reads the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadSpelling {
    Readdir,
    Readdir64,
    ReaddirR,
}

impl ReadSpelling {
    fn name(self) -> &'static str {
        match self {
            ReadSpelling::Readdir => "readdir",
            ReadSpelling::Readdir64 => "readdir64",
            ReadSpelling::ReaddirR => "readdir_r",
        }
    }
}

/// One entry a read produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub kind: u8,
    pub ino: u64,
    /// `readdir_r` pointed `*result` at the caller's own `entry` (glibc
    /// copies the record there); true for the other spellings, which have
    /// no caller buffer.
    pub result_is_entry: bool,
}

/// `errno` cleared, so a NULL read can tell the end (errno untouched) from a
/// failure.
fn clear_errno() {
    // SAFETY: the calling thread's errno slot.
    unsafe { *libc::__errno_location() = 0 };
}

fn entry_of(name: *const libc::c_char, kind: u8, ino: u64) -> DirEntry {
    // SAFETY: d_name is NUL-terminated within the record libc returned.
    let name = unsafe { CStr::from_ptr(name) };
    DirEntry {
        name: name.to_string_lossy().into_owned(),
        kind,
        ino,
        result_is_entry: true,
    }
}

/// One read: `Ok(Some)` an entry, `Ok(None)` the end, `Err` the errno.
fn read_one(dir: &Dir, spelling: ReadSpelling) -> Result<Option<DirEntry>, i32> {
    // SAFETY: `dir` is an open stream; each record is read before the next
    // call on it.
    unsafe {
        match spelling {
            ReadSpelling::Readdir => {
                clear_errno();
                let entry = libc::readdir(dir.0);
                if entry.is_null() {
                    return match errno() {
                        0 => Ok(None),
                        code => Err(code),
                    };
                }
                let entry = &*entry;
                Ok(Some(entry_of(
                    entry.d_name.as_ptr(),
                    entry.d_type,
                    entry.d_ino,
                )))
            }
            ReadSpelling::Readdir64 => {
                clear_errno();
                let entry = libc::readdir64(dir.0);
                if entry.is_null() {
                    return match errno() {
                        0 => Ok(None),
                        code => Err(code),
                    };
                }
                let entry = &*entry;
                Ok(Some(entry_of(
                    entry.d_name.as_ptr(),
                    entry.d_type,
                    entry.d_ino,
                )))
            }
            ReadSpelling::ReaddirR => {
                let mut storage: libc::dirent = std::mem::zeroed();
                let mut result: *mut libc::dirent = std::ptr::null_mut();
                #[allow(deprecated)]
                let code = libc::readdir_r(dir.0, &mut storage, &mut result);
                if code != 0 {
                    return Err(code);
                }
                if result.is_null() {
                    return Ok(None);
                }
                let entry = &*result;
                Ok(Some(DirEntry {
                    result_is_entry: std::ptr::eq(result, &storage),
                    ..entry_of(entry.d_name.as_ptr(), entry.d_type, entry.d_ino)
                }))
            }
        }
    }
}

impl Probe {
    /// A stream's result: 0, or the `-errno` of a NULL.
    fn stream_result(stream: *mut libc::DIR) -> i64 {
        if stream.is_null() {
            -i64::from(errno())
        } else {
            0
        }
    }

    /// `opendir(path)`; `ret` 0 for a stream.
    pub fn opendir(&self, path: &str) -> (i64, Option<Dir>) {
        let c = cstr(path);
        // SAFETY: a NUL-terminated path.
        let stream = unsafe { libc::opendir(c.as_ptr()) };
        let result = Self::stream_result(stream);
        self.rec.event("opendir", result).arg("path", path).emit();
        (result, (!stream.is_null()).then_some(Dir(stream)))
    }

    /// `fdopendir(fd)`; the stream owns `fd` from here on.
    pub fn fdopendir(&self, fd: i32) -> (i64, Option<Dir>) {
        // SAFETY: a plain descriptor number.
        let stream = unsafe { libc::fdopendir(fd) };
        let result = Self::stream_result(stream);
        let builder = self.rec.event("fdopendir", result);
        self.fd_arg(builder, "fd", fd).emit();
        (result, (!stream.is_null()).then_some(Dir(stream)))
    }

    /// One read through `spelling`: `ret` 1 for an entry (which is not
    /// recorded: the order is the filesystem's), 0 at the end, `-errno` on
    /// failure; for `readdir_r`'s entry, whether `*result` is the caller's
    /// buffer.
    pub fn readdir_step(&self, dir: &Dir, spelling: ReadSpelling) -> (i64, Option<DirEntry>) {
        let (result, entry) = match read_one(dir, spelling) {
            Ok(Some(entry)) => (1, Some(entry)),
            Ok(None) => (0, None),
            Err(code) => (-i64::from(code), None),
        };
        let builder = self.rec.event(spelling.name(), result);
        match (&entry, spelling) {
            (Some(entry), ReadSpelling::ReaddirR) => builder
                .field("result_is_entry", entry.result_is_entry)
                .emit(),
            _ => builder.emit(),
        }
        (result, entry)
    }

    /// Read to the end through `spelling`: `ret` the number of entries (or
    /// the `-errno` that ended the reading), `fields.entries` every
    /// `name:d_type`, sorted; for `readdir_r`, whether every `*result` was
    /// the caller's buffer.
    pub fn readdir_all(&self, dir: &Dir, spelling: ReadSpelling) -> (i64, Vec<DirEntry>) {
        let mut entries = Vec::new();
        let result = loop {
            match read_one(dir, spelling) {
                Ok(Some(entry)) => entries.push(entry),
                Ok(None) => break entries.len() as i64,
                Err(code) => break -i64::from(code),
            }
        };
        let mut listed: Vec<String> = entries
            .iter()
            .map(|entry| format!("{}:{}", entry.name, entry.kind))
            .collect();
        listed.sort();
        let builder = self
            .rec
            .event(spelling.name(), result)
            .arg("until", "end")
            .field("entries", listed);
        let builder = if spelling == ReadSpelling::ReaddirR {
            builder.field(
                "result_is_entry",
                entries.iter().all(|entry| entry.result_is_entry),
            )
        } else {
            builder
        };
        builder.emit();
        (result, entries)
    }

    pub fn rewinddir(&self, dir: &Dir) {
        // SAFETY: an open stream.
        unsafe { libc::rewinddir(dir.0) };
        self.rec.event("rewinddir", 0).emit();
    }

    /// `dirfd(dir)`: the descriptor the stream reads.
    pub fn dirfd(&self, dir: &Dir) -> i32 {
        // SAFETY: an open stream.
        let fd = unsafe { libc::dirfd(dir.0) };
        let result = if fd < 0 {
            -i64::from(errno())
        } else {
            fd.into()
        };
        self.rec
            .event("dirfd", result)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        fd
    }

    /// `closedir(dir)`, which also closes the stream's descriptor.
    pub fn closedir(&self, dir: Dir) -> i64 {
        // SAFETY: an open stream, consumed here.
        let result = crate::vehicle::fold_errno(i64::from(unsafe { libc::closedir(dir.0) }));
        self.rec.event("closedir", result).emit();
        result
    }
}
