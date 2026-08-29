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
use std::io::{Read, Write};

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

    println!("CAPSTD_RESULT root={BASE} read=alpha-bytes dents=alpha.txt,sub nested=beta link=sub/moved.txt");
}
