//! cap-std-dirfd — the directory-descriptor-relative resolution MRE.
//!
//! A plain std + [`cap_std`] program. `cap-std` is the capability-based
//! filesystem API: it opens ONE directory (`Dir::open_ambient_dir`, which goes
//! through std → libc → the C interposer) and then does EVERYTHING relative to
//! that descriptor. Its path resolution is component-at-a-time and entirely
//! `*at`-based — `openat(dirfd, name, O_PATH|O_DIRECTORY|O_NOFOLLOW)`,
//! `statx(dirfd, name)`, `readlinkat(dirfd, name)`, `faccessat(dirfd, ".")`,
//! `mkdirat`/`unlinkat`/`renameat`/`symlinkat(dirfd, …)`, and `getdents64` over
//! a descriptor derived with `fcntl(dirfd, F_GETFL)` + `openat(dirfd, ".")` —
//! and those calls reach the kernel through rustix's DEFAULT backend, i.e. as
//! raw inline `syscall` instructions on x86_64.
//!
//! So one program drives both halves of the `*at` surface at once: the base
//! descriptor is minted by the libc interposer, every use of it is a raw
//! syscall trapped by syscall-user-dispatch, and the two only agree because
//! they share ONE directory-descriptor table in the runtime.
//!
//! RED (before dirfd-relative resolution existed): every `*at` row refused a
//! non-`AT_FDCWD` descriptor with `ENOSYS`, and the libc `open` refused
//! `O_PATH`, so `Dir::open_ambient_dir` itself failed with
//! `Function not implemented (os error 38)`. GREEN: the line below.
//!
//! The program prints one machine-parseable `CAPSTD_RESULT …` line and exits 0
//! on success; any inconsistency panics (nonzero exit).

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

/// The base directory the capability is rooted at. Created through std (so the
/// libc interposer mints the entry), then opened as a capability.
const BASE: &str = "/capstd-mre";

fn main() {
    // ---- the base directory, created through std/libc ----
    std::fs::create_dir(BASE).expect("std create_dir of the capability root");
    let dir = Dir::open_ambient_dir(BASE, ambient_authority())
        .expect("Dir::open_ambient_dir must yield a capability over the deterministic filesystem");

    // ---- create / write / read back, all relative to the descriptor ----
    {
        let mut file = dir.create("alpha.txt").expect("Dir::create (openat dirfd, O_CREAT)");
        file.write_all(b"alpha-bytes").expect("write through a dirfd-relative file");
    }
    let alpha = dir.read("alpha.txt").expect("Dir::read (openat dirfd, O_RDONLY)");
    assert_eq!(alpha, b"alpha-bytes", "dirfd-relative read-back mismatch");

    // `Dir::open` + std `Read`, so the fd handed back really is a working file.
    let mut opened = dir.open("alpha.txt").expect("Dir::open");
    let mut text = String::new();
    opened.read_to_string(&mut text).expect("read a dirfd-relative file");
    assert_eq!(text, "alpha-bytes", "Dir::open read-back mismatch");
    drop(opened);

    // ---- metadata: statx(dirfd, name) and statx(fd, "", AT_EMPTY_PATH) ----
    let metadata = dir.metadata("alpha.txt").expect("Dir::metadata (statx dirfd, name)");
    assert!(metadata.is_file(), "alpha.txt must stat as a file");
    assert_eq!(metadata.len(), 11, "dirfd-relative stat size mismatch");
    assert!(
        dir.dir_metadata().expect("Dir::dir_metadata (fstat on the dirfd)").is_dir(),
        "the capability root must stat as a directory"
    );

    // ---- nested directories: mkdirat(dirfd, …) then a NESTED capability ----
    dir.create_dir("sub").expect("Dir::create_dir (mkdirat dirfd)");
    let sub = dir.open_dir("sub").expect("Dir::open_dir (openat dirfd, O_DIRECTORY|O_PATH)");
    sub.write("beta.txt", b"beta").expect("write through a nested capability");
    assert_eq!(
        sub.read("beta.txt").expect("read through a nested capability"),
        b"beta",
        "nested-capability read-back mismatch"
    );

    // A multi-component path is resolved ONE component at a time against the
    // descriptor — this is the loop that needs openat(dirfd, "sub", O_PATH).
    assert_eq!(
        dir.read("sub/beta.txt").expect("multi-component dirfd-relative read"),
        b"beta",
        "component-wise resolution mismatch"
    );

    // ---- directory iteration: fcntl(F_GETFL) + openat(dirfd, ".") + getdents64 ----
    let mut names: Vec<String> = dir
        .entries()
        .expect("Dir::entries (getdents64 over a dirfd)")
        .map(|entry| entry.expect("dir entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, vec!["alpha.txt".to_string(), "sub".to_string()], "root listing");

    let mut sub_names: Vec<String> = dir
        .read_dir("sub")
        .expect("Dir::read_dir(sub) (openat dirfd + getdents64)")
        .map(|entry| entry.expect("dir entry").file_name().to_string_lossy().into_owned())
        .collect();
    sub_names.sort();
    assert_eq!(sub_names, vec!["beta.txt".to_string()], "sub listing");

    // ---- rename: renameat(dirfd, old, dirfd, new) ----
    dir.rename("alpha.txt", &dir, "renamed.txt").expect("Dir::rename (renameat dirfd→dirfd)");
    assert!(!dir.exists("alpha.txt"), "the old name must be gone after rename");
    assert_eq!(
        dir.read("renamed.txt").expect("read the renamed entry"),
        b"alpha-bytes",
        "rename lost the contents"
    );
    // Across two capabilities: renameat(dirfd_a, name, dirfd_b, name).
    dir.rename("renamed.txt", &sub, "moved.txt").expect("Dir::rename across capabilities");
    assert_eq!(
        sub.read("moved.txt").expect("read the moved entry"),
        b"alpha-bytes",
        "cross-descriptor rename lost the contents"
    );

    // ---- symlinks: symlinkat(target, dirfd, link) + readlinkat(dirfd, link) ----
    dir.symlink("sub/moved.txt", "link-to-moved").expect("Dir::symlink (symlinkat dirfd)");
    assert_eq!(
        dir.read_link("link-to-moved").expect("Dir::read_link (readlinkat dirfd)"),
        std::path::Path::new("sub/moved.txt"),
        "symlink target mismatch"
    );
    assert!(
        dir.symlink_metadata("link-to-moved")
            .expect("Dir::symlink_metadata (statx dirfd, AT_SYMLINK_NOFOLLOW)")
            .is_symlink(),
        "the link itself must stat as a symlink"
    );
    // Following the link resolves through the deterministic filesystem.
    assert_eq!(
        dir.read("link-to-moved").expect("read through a dirfd-relative symlink"),
        b"alpha-bytes",
        "symlink follow mismatch"
    );

    // ---- removal: unlinkat(dirfd, name) and unlinkat(dirfd, name, AT_REMOVEDIR) ----
    dir.remove_file("link-to-moved").expect("Dir::remove_file (unlinkat dirfd)");
    assert!(!dir.exists("link-to-moved"), "the removed link must be gone");
    sub.remove_file("beta.txt").expect("remove through a nested capability");
    sub.remove_file("moved.txt").expect("remove the moved entry");
    dir.remove_dir("sub").expect("Dir::remove_dir (unlinkat dirfd, AT_REMOVEDIR)");
    assert!(!dir.exists("sub"), "the removed directory must be gone");

    let mut leftover: Vec<String> = dir
        .entries()
        .expect("final Dir::entries")
        .map(|entry| entry.expect("dir entry").file_name().to_string_lossy().into_owned())
        .collect();
    leftover.sort();
    assert!(leftover.is_empty(), "the capability root must be empty, got {leftover:?}");

    // ---- the capability really is a sandbox, not a path prefix ----
    // An escape attempt is refused by cap-std itself, without ever reaching the
    // kernel; asserting it keeps the guest honest about what it proved.
    assert!(dir.open("../etc/passwd").is_err(), "cap-std must refuse an escape");
    assert!(dir.open("/etc/passwd").is_err(), "cap-std must refuse an absolute path");

    let modes = mode_bits_are_modelled_and_enforced();
    let pinned = a_directory_descriptor_pins_its_node();
    let opath = the_two_directory_opens_cost_different_bits();

    println!(
        "CAPSTD_RESULT root={BASE} read=alpha-bytes dents=alpha.txt,sub nested=beta \
         link=sub/moved.txt modes={modes} pinned={pinned} opath={opath}"
    );
}

/// The permission-bit leg: modes exist, `chmod` changes them, and they are
/// ENFORCED against the guest's single non-root identity.
///
/// RED before the mode model: `chmod` was not interposed at all, so
/// `set_permissions` escaped to the host and failed `NotFound` on a path that
/// only exists in the deterministic filesystem — and every mode read back as a
/// fabricated constant.
fn mode_bits_are_modelled_and_enforced() -> &'static str {
    const ROOT: &str = "/modes-mre";
    fs::create_dir(ROOT).expect("create the mode-model root");
    let file = format!("{ROOT}/data.txt");
    fs::write(&file, "visible").expect("create a file to change the mode of");

    // Creation modes: the ordinary 0o666/0o777 requests, under the fixed 0o022
    // umask.
    let mode_of = |path: &str| fs::metadata(path).expect("stat").permissions().mode() & 0o7777;
    assert_eq!(mode_of(&file), 0o644, "a new file must be 0o644");
    assert_eq!(mode_of(ROOT), 0o755, "a new directory must be 0o755");

    // ---- the caller's OWN creation mode, and enforcement of it on reopen ----
    // RED before creating calls carried a mode: `open(path, O_CREAT, mode)` and
    // `mkdir(path, mode)` dropped the argument, so this file came back 0o644
    // (writable) and this directory 0o755 (creatable in).
    let strict = format!("{ROOT}/strict.txt");
    let mut created = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(&strict)
        .expect("create a file at mode 0o400");
    created.write_all(b"once").expect("the creating handle is writable");
    drop(created);
    assert_eq!(mode_of(&strict), 0o400, "a creation mode must be the caller's");
    // The mode the entry was CREATED with is what a later open is judged
    // against: `r--` reads, and never writes.
    assert_eq!(fs::read(&strict).expect("0o400 is readable"), b"once");
    assert_eq!(
        fs::OpenOptions::new()
            .write(true)
            .open(&strict)
            .expect_err("a file created 0o400 must not reopen for writing")
            .kind(),
        ErrorKind::PermissionDenied,
    );
    // An open of an EXISTING file never touches its mode, whatever third
    // argument it carries: POSIX reads `open`'s mode only when it creates.
    let kept = format!("{ROOT}/kept.txt");
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&kept)
        .expect("create at mode 0o600");
    assert_eq!(mode_of(&kept), 0o600);
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o777)
        .open(&kept)
        .expect("reopen an existing file with O_CREAT");
    assert_eq!(mode_of(&kept), 0o600, "an existing file's mode is not rewritten");
    fs::File::open(&kept).expect("plain reopen");
    assert_eq!(mode_of(&kept), 0o600);

    let locked = format!("{ROOT}/locked");
    fs::DirBuilder::new()
        .mode(0o500)
        .create(&locked)
        .expect("mkdir at mode 0o500");
    assert_eq!(mode_of(&locked), 0o500, "a directory's creation mode is the caller's");
    assert_eq!(
        fs::write(format!("{locked}/nope"), "x")
            .expect_err("a directory created 0o500 has no `w`, so no new names")
            .kind(),
        ErrorKind::PermissionDenied,
    );
    // The umask is applied to the request, exactly as the kernel applies it.
    fs::DirBuilder::new()
        .mode(0o777)
        .create(format!("{ROOT}/wide"))
        .expect("mkdir 0o777");
    assert_eq!(mode_of(&format!("{ROOT}/wide")), 0o755, "0o777 & ~0o022 is 0o755");

    // chmod 0o000: neither read nor write, and the refusal is PermissionDenied —
    // distinguishable from NotFound, which is the whole point of modeling it.
    fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).expect("chmod 0o000");
    assert_eq!(mode_of(&file), 0o000, "chmod must be readable back through stat");
    assert_eq!(
        fs::read(&file).expect_err("a 0o000 file must not be readable").kind(),
        ErrorKind::PermissionDenied,
        "reading a 0o000 file must be denied, not missing"
    );
    assert_eq!(
        fs::write(&file, "clobber")
            .expect_err("a 0o000 file must not be writable")
            .kind(),
        ErrorKind::PermissionDenied,
    );

    // r-------- : readable, still not writable.
    fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).expect("chmod 0o400");
    assert_eq!(fs::read(&file).expect("0o400 is readable"), b"visible");
    assert_eq!(
        fs::write(&file, "clobber").expect_err("0o400 is not writable").kind(),
        ErrorKind::PermissionDenied,
    );

    // fchmod through an open descriptor reaches the same mode.
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("chmod 0o600");
    let handle = fs::File::open(&file).expect("open the file to fchmod it");
    handle
        .set_permissions(fs::Permissions::from_mode(0o640))
        .expect("fchmod through a descriptor");
    drop(handle);
    assert_eq!(mode_of(&file), 0o640, "fchmod must reach the same mode");

    // A directory with no `x` cannot be resolved THROUGH; with no `r` it cannot
    // be listed. Both are the errors a sandbox has to tell apart from its own
    // confinement refusals.
    let sub = format!("{ROOT}/sub");
    fs::create_dir(&sub).expect("create the search/list subject");
    fs::write(format!("{sub}/inner.txt"), "inner").expect("seed the subject");
    fs::set_permissions(&sub, fs::Permissions::from_mode(0o000)).expect("chmod the directory");
    assert_eq!(
        fs::read(format!("{sub}/inner.txt"))
            .expect_err("no `x` means no traversal")
            .kind(),
        ErrorKind::PermissionDenied,
    );
    assert_eq!(
        fs::read_dir(&sub).expect_err("no `r` means no listing").kind(),
        ErrorKind::PermissionDenied,
    );
    // r-x: listing works again, creating a name inside does not (no `w`).
    fs::set_permissions(&sub, fs::Permissions::from_mode(0o500)).expect("chmod r-x");
    assert_eq!(
        fs::read_dir(&sub).expect("r-x is listable").count(),
        1,
        "the listing must show the seeded entry"
    );
    assert_eq!(
        fs::write(format!("{sub}/new.txt"), "x")
            .expect_err("no `w` on the directory means no new name")
            .kind(),
        ErrorKind::PermissionDenied,
    );

    // `access(2)` answers from the same bits rather than from existence alone.
    fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).expect("chmod back to 0o000");
    assert!(
        fs::File::open(&file).is_err(),
        "a 0o000 file must not open for read"
    );
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("restore the file mode");
    fs::set_permissions(&sub, fs::Permissions::from_mode(0o755)).expect("restore the dir mode");
    "enforced+created"
}

/// The `O_PATH` leg: a directory has two opens, and they cost different bits.
///
/// `O_PATH` names a LOCATION — the kernel opens nothing, charges nothing on the
/// entry, and hands back a descriptor that resolves `*at` paths and answers
/// `fstat` but cannot be read. A plain `O_RDONLY|O_DIRECTORY` open DOES open the
/// directory for reading and costs `r`, while traversing THROUGH a directory
/// costs `x` — different bits, and a capability guest spends most of its opens
/// on the first kind.
///
/// RED before `O_PATH` entered the driver's flag vocabulary: both opens were the
/// same open, charging `x` on the directory and handing back a readable handle.
/// So a `0o400` directory (`r--`, listable on any Unix) could not be listed at
/// all, a `0o111` directory could be opened for reading and then iterated by
/// asking for the listing separately, and an `O_PATH` handle was a read
/// capability nobody asked for.
fn the_two_directory_opens_cost_different_bits() -> &'static str {
    const ROOT: &str = "/opath-mre";
    fs::create_dir(ROOT).expect("create the O_PATH root");
    fs::write(format!("{ROOT}/entry.txt"), "listed").expect("seed one entry");

    // r-- : listing reads the directory, so it works; traversal needs `x`, so
    // resolving a name through it does not. That is the split.
    fs::set_permissions(ROOT, fs::Permissions::from_mode(0o400)).expect("chmod r--");
    assert_eq!(
        fs::read_dir(ROOT).expect("r-- is listable").count(),
        1,
        "listing a directory costs `r`, and this directory has it"
    );
    assert_eq!(
        fs::read(format!("{ROOT}/entry.txt"))
            .expect_err("traversing r-- must fail: no `x`")
            .kind(),
        ErrorKind::PermissionDenied,
    );

    // --x : traversal works, listing does not.
    fs::set_permissions(ROOT, fs::Permissions::from_mode(0o100)).expect("chmod --x");
    assert_eq!(
        fs::read(format!("{ROOT}/entry.txt")).expect("--x is traversable"),
        b"listed",
    );
    assert_eq!(
        fs::read_dir(ROOT).expect_err("listing --x must fail: no `r`").kind(),
        ErrorKind::PermissionDenied,
    );

    // 0o000: no bit at all. An O_PATH open still succeeds — the kernel checks
    // nothing on the entry for one — while the plain open is refused, and the
    // path-only descriptor cannot be read or iterated (EBADF, as on Linux).
    fs::set_permissions(ROOT, fs::Permissions::from_mode(0o000)).expect("chmod 0o000");
    let location = open_path_only(ROOT);
    assert!(location >= 0, "an O_PATH open charges nothing on the entry");
    let mut byte = [0u8; 1];
    // SAFETY: a live descriptor and a writable one-byte buffer.
    let read_rc = unsafe { read(location, byte.as_mut_ptr(), byte.len()) };
    assert_eq!(read_rc, -1, "a path-only descriptor must not read");
    // SAFETY: a live descriptor.
    assert_eq!(unsafe { close(location) }, 0);
    assert_eq!(
        fs::read_dir(ROOT)
            .expect_err("a plain directory open of 0o000 must be denied")
            .kind(),
        ErrorKind::PermissionDenied,
    );

    fs::set_permissions(ROOT, fs::Permissions::from_mode(0o755)).expect("restore");
    "nocost,list=r,walk=x"
}

/// `open(path, O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)` — the exact open
/// `cap-primitives` performs for every path component it walks, through libc
/// rather than through cap-std, so the flag itself is what is under test.
fn open_path_only(path: &str) -> i32 {
    let c_path = std::ffi::CString::new(path).expect("a NUL-free path");
    // SAFETY: a NUL-terminated path; the variadic mode is unread without O_CREAT.
    unsafe { open(c_path.as_ptr(), O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) }
}

const O_DIRECTORY: i32 = 0o200000;
const O_NOFOLLOW: i32 = 0o400000;
const O_CLOEXEC: i32 = 0o2000000;
const O_PATH: i32 = 0o10000000;

unsafe extern "C" {
    fn open(path: *const std::ffi::c_char, flags: i32, ...) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn close(fd: i32) -> i32;
}

/// The descriptor-identity leg: a directory descriptor names an INODE, so it
/// follows its directory through a rename and never follows a symlink planted
/// at the name it was opened under.
///
/// RED before node-identity resolution: the descriptor's path was cached beside
/// it at open time, so the rename detached it (`ENOENT`) and, once a symlink sat
/// at the old name, every `openat` on it resolved through that link instead —
/// the exact redirect a capability handle exists to prevent.
fn a_directory_descriptor_pins_its_node() -> &'static str {
    const PINNED: &str = "/pinned-mre";
    const MOVED: &str = "/pinned-mre-moved";
    const DECOY: &str = "/decoy-mre";
    fs::create_dir(PINNED).expect("create the pinned directory");
    fs::create_dir(DECOY).expect("create the decoy directory");
    fs::write(format!("{PINNED}/file.txt"), "pinned-bytes").expect("seed the pinned directory");
    fs::write(format!("{DECOY}/file.txt"), "DECOY-CONTENT").expect("seed the decoy");

    let dir = Dir::open_ambient_dir(PINNED, ambient_authority()).expect("open the capability");

    // Move the directory out from under its name, then plant a symlink to the
    // decoy at the vacated name.
    fs::rename(PINNED, MOVED).expect("rename the open directory");
    std::os::unix::fs::symlink(DECOY, PINNED).expect("plant the symlink at the old name");
    assert_eq!(
        fs::read_link(PINNED).expect("the planted link must be there"),
        std::path::Path::new(DECOY),
        "the old name must now be a symlink to the decoy"
    );

    // The descriptor still serves the node it was opened on, at its new name.
    assert_eq!(
        dir.read("file.txt").expect("the descriptor must survive the rename"),
        b"pinned-bytes",
        "the descriptor followed a name instead of its inode"
    );
    assert_eq!(
        fs::read(format!("{MOVED}/file.txt")).expect("the node is reachable at its new name"),
        b"pinned-bytes",
    );

    // Writing through the descriptor lands in the ORIGINAL directory too.
    dir.write("written.txt", b"through-the-descriptor")
        .expect("write through the pinned descriptor");
    assert_eq!(
        fs::read(format!("{MOVED}/written.txt")).expect("the write landed at the node"),
        b"through-the-descriptor",
    );
    assert!(
        fs::metadata(format!("{DECOY}/written.txt")).is_err(),
        "DECOY DISCLOSURE: the write followed the planted symlink"
    );

    // Renaming a symlink moves the LINK, never its target (POSIX).
    fs::write("/rename-target.txt", "target-bytes").expect("seed a link target");
    std::os::unix::fs::symlink("/rename-target.txt", "/rename-link").expect("create the link");
    fs::rename("/rename-link", "/rename-link-moved").expect("rename the symlink itself");
    assert_eq!(
        fs::read_link("/rename-link-moved").expect("the moved entry is still a link"),
        std::path::Path::new("/rename-target.txt"),
        "renaming a symlink must move the link, not resolve it"
    );
    assert_eq!(
        fs::read("/rename-target.txt").expect("the target is untouched"),
        b"target-bytes",
    );
    "node"
}
