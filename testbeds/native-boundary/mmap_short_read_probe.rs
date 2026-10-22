//! Files grown to 32 KiB with one-byte writes, as SQLite grows its `-shm`
//! wal-index, each mapped `MAP_SHARED` and written page by page. On Linux every
//! page of such a mapping is backed and holds the file's bytes: a mapping's
//! extent is the file's size, and nothing a read of the file does can shrink
//! it. Each file is mapped once, so a run loads `FILES` page caches.
//!
//! With `MMAP_SHORT_READ_MODE=crash` the files are made durable before they are
//! mapped, and the filesystem then crashes in process (`patina_crash`, so this
//! probe runs under Patina only): every mapping reloads the durable image,
//! every page of it.
//!
//! The probe's own file operations retry the errors an injected filesystem
//! fault answers, so it runs under any fault rate. `mmap`, and touching a
//! mapped page, are never retried.
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;

const PAGE: usize = 4096;
const PAGES: usize = 8;
const SIZE: usize = PAGES * PAGE;
const FILES: usize = 8;
const ATTEMPTS: usize = 256;

const PROT_READ: i32 = 1;
const PROT_WRITE: i32 = 2;
const MAP_SHARED: i32 = 1;

unsafe extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut u8;
    fn patina_crash() -> i32;
}

/// The result of `op`, retried past the errors an injected filesystem fault
/// answers (`EINTR`, `EIO`, `ENOSPC`); any other error is the probe's failure.
fn retry<T>(what: &str, mut op: impl FnMut() -> io::Result<T>) -> T {
    let mut last = None;
    for _ in 0..ATTEMPTS {
        match op() {
            Ok(value) => return value,
            Err(error) if matches!(error.raw_os_error(), Some(4 | 5 | 28)) => last = Some(error),
            Err(error) => panic!("{what}: {error}"),
        }
    }
    panic!("{what} failed {ATTEMPTS} times: {last:?}")
}

/// The byte the last byte of `page` holds.
fn marker(page: usize) -> u8 {
    page as u8 + 1
}

/// A `SIZE`-byte file at `path`, grown one byte at a time: each page's last
/// byte is its marker.
fn grown(path: &str) -> File {
    let file = retry("open", || {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
    });
    for page in 0..PAGES {
        let at = (page * PAGE + PAGE - 1) as u64;
        assert_eq!(retry("pwrite", || file.write_at(&[marker(page)], at)), 1);
    }
    assert_eq!(retry("fstat", || file.metadata()).len(), SIZE as u64);
    file
}

/// Every name and byte of `files` (all in `/`) durable, so a crash keeps them.
fn make_durable(files: &[File]) {
    for file in files {
        retry("fsync", || file.sync_all());
    }
    let root = retry("open /", || File::open("/"));
    retry("fsync /", || root.sync_all());
}

fn map(file: &File) -> *mut u8 {
    // SAFETY: a fresh shared mapping of a file the probe holds open.
    let base = unsafe {
        mmap(
            std::ptr::null_mut(),
            SIZE,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            file.as_raw_fd(),
            0,
        )
    };
    assert!(
        base as isize != -1,
        "mmap failed: {}",
        io::Error::last_os_error()
    );
    base
}

fn main() {
    let crash = match std::env::var("MMAP_SHORT_READ_MODE").as_deref() {
        Err(_) => false,
        Ok("crash") => true,
        Ok(other) => panic!("unknown MMAP_SHORT_READ_MODE {other}"),
    };
    let files: Vec<File> = (0..FILES)
        .map(|n| grown(&format!("/mapped-{n}.bin")))
        .collect();
    if crash {
        make_durable(&files);
    }
    let views: Vec<*mut u8> = files.iter().map(map).collect();
    if crash {
        // SAFETY: the shim's in-process crash; the views stay mapped across it.
        assert_eq!(unsafe { patina_crash() }, 0, "patina_crash");
    }
    let mut written = 0;
    for (file, view) in views.iter().enumerate() {
        for page in 0..PAGES {
            // SAFETY: `page` is within the `SIZE`-byte mapping `view`.
            let last = unsafe { view.add(page * PAGE + PAGE - 1).read_volatile() };
            assert_eq!(
                last,
                marker(page),
                "file {file} page {page} through its view"
            );
            // SAFETY: as above, and the mapping is writable.
            unsafe { view.add(page * PAGE).write_volatile(1) };
            written += 1;
        }
    }
    // What the views stored is what a read returns.
    for (n, file) in files.iter().enumerate() {
        let bytes = retry("pread", || {
            let mut bytes = vec![0; SIZE];
            file.read_exact_at(&mut bytes, 0).map(|()| bytes)
        });
        for page in 0..PAGES {
            let stored = (bytes[page * PAGE], bytes[page * PAGE + PAGE - 1]);
            assert_eq!(stored, (1, marker(page)), "file {n} page {page} read back");
        }
    }
    println!("NATIVE_MMAP_SHORT_READ pages_written={written}");
}
