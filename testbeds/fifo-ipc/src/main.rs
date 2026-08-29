//! The named-pipe (FIFO) acceptance MRE.
//!
//! Every leg here is a POSIX behavior a program that uses a FIFO depends on,
//! and every one of them is unreachable if `mkfifo` is not interposed (the call
//! escapes to the host, lands on a path the in-memory filesystem never had, and
//! fails `ENOENT`) or if a FIFO open is answered like a regular file's.
//!
//! The legs, in order:
//!
//!  1. `mkfifo` creates an entry that `stat`/`lstat` report as a FIFO with the
//!     umasked mode, and that a directory listing reports as one too.
//!  2. `mkfifoat` and `mknod(S_IFIFO)` reach the same entry kind; `mknod` of a
//!     device node is refused rather than escaping.
//!  3. `O_RDONLY|O_NONBLOCK` opens at once with no writer, and the HANDLE says
//!     FIFO — the check a sandbox makes after the open, because a path check
//!     can be raced.
//!  4. `O_WRONLY|O_NONBLOCK` with no reader is `ENXIO`.
//!  5. A blocking `O_RDONLY` parks until another task's `O_WRONLY` arrives,
//!     transfers bytes, and reads EOF when the last writer closes.
//!  6. A write with no reader left is `EPIPE` — an errno, never a signal.
//!  7. A non-blocking read with no data and a live writer is `EAGAIN`.
//!  8. `O_RDWR` never waits (Linux's behavior for a FIFO).
//!  9. A `0o000` FIFO is `PermissionDenied`, distinguishably from `NotFound`.
//! 10. `fstat` on an open FIFO descriptor reads the LIVE entry, so a `chmod`
//!     after the open is visible through it (as on Linux).
//! 11. A hard link to a FIFO is a second NAME for the same node — same inode,
//!     link count 2 — and therefore the same pipe: bytes written through one
//!     name are read through the other.
//! 12. `unlink` removes a name while open descriptors keep the pipe alive; the
//!     surviving link keeps the node, and the last unlink leaves the descriptor
//!     working.

use std::fs::{self, OpenOptions, Permissions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::thread;

const ROOT: &str = "/fifo-mre";
const PAYLOAD: &[u8] = b"fifo-bytes";

fn main() {
    fs::create_dir(ROOT).expect("create the MRE root");
    let pipe = PathBuf::from(ROOT).join("pipe");

    // ---- [1] mkfifo: the entry kind, the umasked mode, the listing ----
    make_fifo(&pipe, 0o666);
    let metadata = fs::symlink_metadata(&pipe).expect("stat the FIFO");
    assert!(
        metadata.file_type().is_fifo(),
        "mkfifo must produce a FIFO, got {:?}",
        metadata.file_type()
    );
    let mode = metadata.permissions().mode() & 0o7777;
    assert_eq!(mode, 0o644, "mkfifo(0o666) under a 0o022 umask is 0o644");
    assert_eq!(metadata.len(), 0, "a FIFO holds no filesystem bytes");
    let ino = metadata.ino();

    let mut listed = Vec::new();
    for entry in fs::read_dir(ROOT).expect("list the MRE root") {
        let entry = entry.expect("directory entry");
        let kind = entry.file_type().expect("entry file type");
        listed.push(format!(
            "{}:{}",
            entry.file_name().to_string_lossy(),
            if kind.is_fifo() { "fifo" } else { "other" }
        ));
    }
    listed.sort();
    assert_eq!(listed, vec!["pipe:fifo".to_string()], "listing kind");

    // ---- [2] the other two creation spellings, and a refused device node ----
    let at_pipe = PathBuf::from(ROOT).join("at-pipe");
    make_fifo_at(&at_pipe, 0o600);
    let at_metadata = fs::symlink_metadata(&at_pipe).expect("stat the mkfifoat FIFO");
    assert!(at_metadata.file_type().is_fifo());
    assert_eq!(
        at_metadata.permissions().mode() & 0o7777,
        0o600,
        "mkfifoat's mode is the caller's, under the modeled umask"
    );
    let node_pipe = PathBuf::from(ROOT).join("node-pipe");
    make_node_fifo(&node_pipe, 0o644);
    assert!(
        fs::symlink_metadata(&node_pipe)
            .expect("stat the mknod FIFO")
            .file_type()
            .is_fifo()
    );
    let device = PathBuf::from(ROOT).join("device");
    let device_errno = make_char_device(&device);
    assert!(
        device_errno != 0 && !device.exists(),
        "a device node must be refused, not created (errno {device_errno})"
    );
    fs::remove_file(&at_pipe).expect("unlink the mkfifoat FIFO");
    fs::remove_file(&node_pipe).expect("unlink the mknod FIFO");

    // ---- [3] non-blocking read-open, then the HANDLE-level kind check ----
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&pipe)
        .expect("a non-blocking read-open of a FIFO must not wait for a writer");
    let handle_metadata = handle.metadata().expect("fstat the FIFO descriptor");
    assert!(
        handle_metadata.file_type().is_fifo(),
        "the FIFO descriptor must report itself as a FIFO"
    );
    assert_eq!(handle_metadata.ino(), ino, "the descriptor names the entry");

    // ---- [4] non-blocking write-open with no reader is ENXIO ----
    drop(handle);
    let refused = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&pipe)
        .expect_err("a non-blocking write-open with no reader must fail");
    assert_eq!(
        refused.raw_os_error(),
        Some(libc::ENXIO),
        "a writer with no reader is ENXIO, got {refused}"
    );

    // ---- [5] blocking rendezvous + EOF on the last writer's close ----
    let writer_path = pipe.clone();
    let writer = thread::spawn(move || {
        let mut file = OpenOptions::new()
            .write(true)
            .open(&writer_path)
            .expect("a blocking write-open must be released by the reader");
        file.write_all(PAYLOAD).expect("write into the FIFO");
        // Dropping the last writer is what turns the reader's next read into
        // end-of-file rather than another park.
    });
    let mut reader = OpenOptions::new()
        .read(true)
        .open(&pipe)
        .expect("a blocking read-open must be released by the writer");
    let mut received = Vec::new();
    reader
        .read_to_end(&mut received)
        .expect("read the FIFO to end-of-file");
    writer.join().expect("the writer task must finish");
    assert_eq!(received, PAYLOAD, "the bytes a writer sent must arrive");
    drop(reader);

    // ---- [6] a write with no reader left is EPIPE, never a signal ----
    let reader = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&pipe)
        .expect("read-open");
    let mut writer = OpenOptions::new()
        .write(true)
        .open(&pipe)
        .expect("a write-open with a reader present must not wait");
    drop(reader);
    let broken = writer
        .write_all(b"nobody-is-listening")
        .expect_err("writing with no reader must fail");
    assert_eq!(
        broken.kind(),
        ErrorKind::BrokenPipe,
        "a reader-less write is EPIPE, got {broken}"
    );
    drop(writer);

    // ---- [7] a non-blocking read with a live writer and no data is EAGAIN ----
    let mut reader = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&pipe)
        .expect("read-open");
    let writer = OpenOptions::new().write(true).open(&pipe).expect("write-open");
    let mut scratch = [0u8; 8];
    let empty = reader
        .read(&mut scratch)
        .expect_err("a non-blocking read of an empty FIFO must not report EOF");
    assert_eq!(
        empty.kind(),
        ErrorKind::WouldBlock,
        "an empty FIFO with a live writer is EAGAIN, got {empty}"
    );
    drop(writer);
    // With the writer gone the same read is end-of-file, not EAGAIN.
    assert_eq!(reader.read(&mut scratch).expect("read after writer close"), 0);
    drop(reader);

    // ---- [8] O_RDWR opens without waiting for anyone ----
    let mut both = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&pipe)
        .expect("O_RDWR on a FIFO must not wait");
    both.write_all(b"self").expect("write through O_RDWR");
    let mut echoed = [0u8; 4];
    both.read_exact(&mut echoed).expect("read through O_RDWR");
    assert_eq!(&echoed, b"self");

    // ---- [9] permission bits gate the open, distinguishably from NotFound ----
    fs::set_permissions(&pipe, Permissions::from_mode(0o000)).expect("chmod the FIFO");
    let denied = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&pipe)
        .expect_err("a 0o000 FIFO must not open");
    assert_eq!(
        denied.kind(),
        ErrorKind::PermissionDenied,
        "a 0o000 FIFO is PermissionDenied, got {denied}"
    );
    let absent = OpenOptions::new()
        .read(true)
        .open(Path::new(ROOT).join("absent"))
        .expect_err("a missing FIFO must not open");
    assert_eq!(
        absent.kind(),
        ErrorKind::NotFound,
        "a missing name stays distinguishable from a denied one"
    );
    fs::set_permissions(&pipe, Permissions::from_mode(0o644)).expect("restore the mode");
    assert_eq!(
        fs::symlink_metadata(&pipe).expect("stat").permissions().mode() & 0o7777,
        0o644
    );

    // ---- [10] fstat on the DESCRIPTOR reads the live entry, not a snapshot ----
    // A descriptor names a NODE. `chmod` changes the node, so the change shows
    // through the descriptor exactly as it does for a regular file's fd.
    // RED before this: the identity captured at open answered, so the mode read
    // back as whatever it was when the descriptor was created.
    let opened_mode = handle_mode(&both);
    assert_eq!(opened_mode, 0o644, "the FIFO descriptor reports the entry mode");
    fs::set_permissions(&pipe, Permissions::from_mode(0o600)).expect("chmod after the open");
    let live_mode = handle_mode(&both);
    assert_eq!(
        live_mode, 0o600,
        "fstat on a FIFO descriptor must read the LIVE entry mode, got {live_mode:o}"
    );
    fs::set_permissions(&pipe, Permissions::from_mode(0o644)).expect("restore the mode");

    // ---- [11] a hard link to a FIFO is a second name for the SAME pipe ----
    // RED before FIFOs were inode-backed: the driver's link table is
    // inode-keyed and a FIFO had no inode in it, so this was NotFound.
    let alias = PathBuf::from(ROOT).join("alias");
    fs::hard_link(&pipe, &alias).expect("hard-link a FIFO");
    let alias_metadata = fs::symlink_metadata(&alias).expect("stat the linked name");
    assert!(alias_metadata.file_type().is_fifo(), "a link to a FIFO is a FIFO");
    assert_eq!(alias_metadata.ino(), ino, "a hard link is the same inode");
    assert_eq!(alias_metadata.nlink(), 2, "two names, one node");
    // Same inode, same pipe: `both` is still an open reader, so a writer on the
    // OTHER name meets it on one channel.
    let mut aliased_writer = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&alias)
        .expect("a writer on the linked name meets the reader on the original");
    aliased_writer
        .write_all(b"linked")
        .expect("write through the linked name");
    drop(aliased_writer);
    let mut through_link = [0u8; 6];
    both.read_exact(&mut through_link)
        .expect("the original name reads what the link wrote");
    assert_eq!(&through_link, b"linked", "a hard link must share the channel");

    // ---- [12] unlink drops a NAME; the node lives while any name or fd holds it ----
    fs::remove_file(&pipe).expect("unlink a FIFO with an open descriptor");
    assert_eq!(
        fs::symlink_metadata(&pipe)
            .expect_err("the unlinked name must be gone")
            .kind(),
        ErrorKind::NotFound
    );
    let surviving = fs::symlink_metadata(&alias).expect("the other name still names the node");
    assert_eq!(surviving.ino(), ino, "unlinking one name keeps the node");
    assert_eq!(surviving.nlink(), 1, "one name left");
    assert_eq!(handle_mode(&both), 0o644, "the descriptor still reads the entry");

    fs::remove_file(&alias).expect("unlink the last name");
    both.write_all(b"after-unlink")
        .expect("an open FIFO descriptor outlives its names");
    let mut tail = [0u8; 12];
    both.read_exact(&mut tail)
        .expect("and still carries bytes");
    assert_eq!(&tail, b"after-unlink");
    drop(both);

    println!(
        "FIFO_RESULT kind=fifo mode=0644 dents=pipe:fifo spellings=mkfifo,mkfifoat,mknod \
         nonblock=open+enxio rendezvous={} eof=0 epipe=1 eagain=1 rdwr=nowait denied=1 \
         fstat=live linked=2names,shared unlinked=alive",
        String::from_utf8_lossy(&received)
    );
}

/// The permission bits `fstat` reports for an open descriptor.
fn handle_mode(file: &fs::File) -> u32 {
    file.metadata()
        .expect("fstat the FIFO descriptor")
        .permissions()
        .mode()
        & 0o7777
}

/// `mkfifo(3)`. std has no wrapper, so this is the one place libc is needed.
fn make_fifo(path: &Path, mode: u32) {
    let c_path = c_string(path);
    // SAFETY: a NUL-terminated path and a mode_t, per mkfifo(3).
    let result = unsafe { libc::mkfifo(c_path.as_ptr(), mode as libc::mode_t) };
    assert_eq!(result, 0, "mkfifo({}) failed: {}", path.display(), errno());
}

/// `mkfifoat(3)` against `AT_FDCWD` — the dirfd-relative spelling of the same
/// creation, which must reach the same entry.
fn make_fifo_at(path: &Path, mode: u32) {
    let c_path = c_string(path);
    // SAFETY: as above, with the AT_FDCWD directory descriptor.
    let result =
        unsafe { libc::mkfifoat(libc::AT_FDCWD, c_path.as_ptr(), mode as libc::mode_t) };
    assert_eq!(result, 0, "mkfifoat({}) failed: {}", path.display(), errno());
}

/// `mknod(2)` with `S_IFIFO`: the call glibc's own `mkfifo` is a wrapper over on
/// some platforms, and the number a raw-syscall guest reaches for.
fn make_node_fifo(path: &Path, mode: u32) {
    let c_path = c_string(path);
    // SAFETY: a NUL-terminated path, a FIFO mode, and the zero device a FIFO
    // requires.
    let result = unsafe {
        libc::mknod(
            c_path.as_ptr(),
            libc::S_IFIFO | mode as libc::mode_t,
            0 as libc::dev_t,
        )
    };
    assert_eq!(result, 0, "mknod({}) failed: {}", path.display(), errno());
}

/// `mknod(2)` naming a character device: NOT modeled, and it must not reach the
/// host either. Returns the errno so the caller can assert it failed.
fn make_char_device(path: &Path) -> i32 {
    let c_path = c_string(path);
    // SAFETY: as above; the device number is the conventional /dev/null pair.
    let result = unsafe {
        libc::mknod(
            c_path.as_ptr(),
            libc::S_IFCHR | 0o666,
            libc::makedev(1, 3) as libc::dev_t,
        )
    };
    if result == 0 { 0 } else { errno() }
}

fn c_string(path: &Path) -> std::ffi::CString {
    std::ffi::CString::new(path.as_os_str().as_bytes()).expect("a NUL-free path")
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
