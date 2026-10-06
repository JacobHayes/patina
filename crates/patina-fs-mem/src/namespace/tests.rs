//! Tests for path resolution, directory enumeration and namespace moves.

use crate::MemFs;
use crate::tests::create;
use patina_dst_abi::{ErrorCode, FsClock, FsDirectoryEntry, FsEntryKind, FsNode, OpenFlags};
use patina_dst_driver_api::FsDriver;

/// RED before a FIFO was inode-backed: the link table is inode-keyed and a
/// FIFO had no inode in it, so `link` to one answered `NotFound`.
#[test]
fn a_hard_link_to_a_fifo_is_a_second_name_for_the_same_node() {
    let mut fs = MemFs::new();
    fs.make_fifo(FsClock::EPOCH, "/tmp/pipe", 0o660).unwrap();
    fs.link(FsClock::EPOCH, "/tmp/pipe", "/tmp/also-pipe")
        .unwrap();

    let first = fs.metadata("/tmp/pipe").unwrap();
    let second = fs.metadata("/tmp/also-pipe").unwrap();
    assert_eq!(second.kind, FsEntryKind::Fifo);
    // ONE node: the identity the shim keys the pipe channel by, so both
    // names open onto the same pipe.
    assert_eq!(first.ino, second.ino);
    assert_eq!(first.nlink, 2);
    assert_eq!(second.nlink, 2);
    // One node, one mode: a chmod through either name is visible through
    // both.
    fs.set_mode(FsClock::EPOCH, "/tmp/also-pipe", 0o600)
        .unwrap();
    assert_eq!(fs.metadata("/tmp/pipe").unwrap().mode, 0o600);

    // Dropping one name leaves the node; dropping the last releases it.
    fs.remove_file(FsClock::EPOCH, "/tmp/pipe").unwrap();
    let remaining = fs.metadata("/tmp/also-pipe").unwrap();
    assert_eq!(remaining.nlink, 1);
    assert_eq!(remaining.ino, first.ino);
    assert_eq!(
        fs.inode_metadata(first.ino).unwrap().kind,
        FsEntryKind::Fifo
    );
    fs.remove_file(FsClock::EPOCH, "/tmp/also-pipe").unwrap();
    assert_eq!(
        fs.inode_metadata(first.ino).unwrap_err().code,
        ErrorCode::NotFound
    );
}

/// Renaming a directory has to carry every kind of leaf beneath it. RED
/// before this: FIFOs were left behind at the old prefix while the
/// directory that held them moved.
#[test]
fn renaming_a_directory_carries_the_fifos_beneath_it() {
    let mut fs = MemFs::new();
    fs.create_directory(FsClock::EPOCH, "/tmp/box", 0o777)
        .unwrap();
    fs.make_fifo(FsClock::EPOCH, "/tmp/box/pipe", 0o666)
        .unwrap();
    let ino = fs.metadata("/tmp/box/pipe").unwrap().ino;

    fs.rename(FsClock::EPOCH, "/tmp/box", "/tmp/crate").unwrap();
    assert_eq!(
        fs.metadata("/tmp/box/pipe").unwrap_err().code,
        ErrorCode::NotFound
    );
    let moved = fs.metadata("/tmp/crate/pipe").unwrap();
    assert_eq!(moved.kind, FsEntryKind::Fifo);
    assert_eq!(moved.ino, ino);
}

/// Overwriting a name by rename must release whatever node was there, so a
/// FIFO's link count cannot leak an inode that no name references.
#[test]
fn renaming_over_a_fifo_releases_its_node() {
    let mut fs = MemFs::new();
    fs.make_fifo(FsClock::EPOCH, "/tmp/victim", 0o666).unwrap();
    let victim = fs.metadata("/tmp/victim").unwrap().ino;
    let fd = fs
        .open(
            FsClock::EPOCH,
            "/tmp/winner",
            OpenFlags::create_truncate_write(),
        )
        .unwrap();
    fs.close(fd).unwrap();

    fs.rename(FsClock::EPOCH, "/tmp/winner", "/tmp/victim")
        .unwrap();
    assert_eq!(fs.metadata("/tmp/victim").unwrap().kind, FsEntryKind::File);
    assert_eq!(
        fs.inode_metadata(victim).unwrap_err().code,
        ErrorCode::NotFound
    );
}

#[test]
fn fifos_carry_the_creation_mode_and_report_their_own_kind() {
    let mut fs = MemFs::new();
    fs.make_fifo(FsClock::EPOCH, "/tmp/pipe", 0o644).unwrap();
    let metadata = fs.metadata("/tmp/pipe").unwrap();
    assert_eq!(metadata.kind, FsEntryKind::Fifo);
    // The caller's mode IS honored here, verbatim.
    assert_eq!(metadata.mode, 0o644);
    // A FIFO's bytes are never filesystem state, so it has no length.
    assert_eq!(metadata.len, 0);
    assert_eq!(metadata.nlink, 1);
    assert_ne!(metadata.ino, 0);

    fs.make_fifo(FsClock::EPOCH, "/tmp/strict", 0o755).unwrap();
    assert_eq!(fs.metadata("/tmp/strict").unwrap().mode, 0o755);
    // A mode change reaches a FIFO like any other entry.
    fs.set_mode(FsClock::EPOCH, "/tmp/strict", 0o600).unwrap();
    assert_eq!(fs.metadata("/tmp/strict").unwrap().mode, 0o600);

    assert_eq!(
        fs.make_fifo(FsClock::EPOCH, "/tmp/pipe", 0o666)
            .unwrap_err()
            .code,
        ErrorCode::AlreadyExists
    );
    // Creating a name needs `w` and `x` on the directory, as for any kind.
    fs.create_directory(FsClock::EPOCH, "/tmp/locked", 0o777)
        .unwrap();
    fs.set_mode(FsClock::EPOCH, "/tmp/locked", 0o500).unwrap();
    assert_eq!(
        fs.make_fifo(FsClock::EPOCH, "/tmp/locked/pipe", 0o666)
            .unwrap_err()
            .code,
        ErrorCode::Denied
    );
}

#[test]
fn a_fifo_lists_renames_and_unlinks_like_any_other_entry() {
    let mut fs = MemFs::new();
    fs.make_fifo(FsClock::EPOCH, "/tmp/pipe", 0o666).unwrap();
    let listed = fs.read_directory(FsClock::EPOCH, "/tmp").unwrap();
    assert_eq!(
        listed,
        vec![FsDirectoryEntry {
            name: "pipe".into(),
            kind: FsEntryKind::Fifo,
            ino: fs.metadata("/tmp/pipe").unwrap().ino,
        }]
    );
    assert_eq!(
        fs.read_directory(FsClock::EPOCH, "/tmp/pipe")
            .unwrap_err()
            .code,
        ErrorCode::NotDirectory
    );
    assert_eq!(
        fs.remove_directory(FsClock::EPOCH, "/tmp/pipe")
            .unwrap_err()
            .code,
        ErrorCode::NotDirectory
    );

    // The swap a sandbox race plants: a FIFO over a regular file, and back.
    let fd = fs
        .open(
            FsClock::EPOCH,
            "/tmp/file",
            OpenFlags::create_truncate_write(),
        )
        .unwrap();
    fs.write(FsClock::EPOCH, fd, b"public").unwrap();
    fs.close(fd).unwrap();
    let ino = fs.metadata("/tmp/pipe").unwrap().ino;
    fs.rename(FsClock::EPOCH, "/tmp/pipe", "/tmp/file").unwrap();
    let replaced = fs.metadata("/tmp/file").unwrap();
    assert_eq!(replaced.kind, FsEntryKind::Fifo);
    assert_eq!(replaced.ino, ino, "a renamed FIFO keeps its identity");
    assert_eq!(
        fs.metadata("/tmp/pipe").unwrap_err().code,
        ErrorCode::NotFound
    );
    let fd = fs
        .open(
            FsClock::EPOCH,
            "/tmp/regular",
            OpenFlags::create_truncate_write(),
        )
        .unwrap();
    fs.close(fd).unwrap();
    fs.rename(FsClock::EPOCH, "/tmp/regular", "/tmp/file")
        .unwrap();
    assert_eq!(fs.metadata("/tmp/file").unwrap().kind, FsEntryKind::File);

    // Unlink is unconditional: nothing filesystem-side is holding a FIFO
    // open, because what an opener holds is the pipe.
    fs.make_fifo(FsClock::EPOCH, "/tmp/gone", 0o666).unwrap();
    fs.remove_file(FsClock::EPOCH, "/tmp/gone").unwrap();
    assert_eq!(
        fs.metadata("/tmp/gone").unwrap_err().code,
        ErrorCode::NotFound
    );
}

#[test]
fn hard_links_share_inodes_and_drop_after_last_name() {
    let mut fs = MemFs::new().with_file("/a", b"abc").unwrap();
    fs.link(FsClock::EPOCH, "/a", "/b").unwrap();
    let a_metadata = fs.metadata("/a").unwrap();
    let b_metadata = fs.metadata("/b").unwrap();
    assert_eq!(a_metadata.ino, b_metadata.ino);
    assert_eq!(a_metadata.nlink, 2);
    assert_eq!(b_metadata.nlink, 2);
    let write = fs
        .open(
            FsClock::EPOCH,
            "/a",
            OpenFlags {
                read: false,
                write: true,
                create: false,
                truncate: false,
                append: true,
                exclusive: false,
                path_only: false,
                mode: patina_dst_abi::CREATE_MODE_UNUSED,
            },
        )
        .unwrap();
    fs.write(FsClock::EPOCH, write, b"!").unwrap();
    fs.close(write).unwrap();
    assert_eq!(fs.contents("/b").unwrap(), b"abc!");
    fs.remove_file(FsClock::EPOCH, "/a").unwrap();
    assert_eq!(fs.contents("/b").unwrap(), b"abc!");
    let survivor = fs.metadata("/b").unwrap();
    assert_eq!(survivor.ino, b_metadata.ino);
    assert_eq!(survivor.nlink, 1);
    fs.remove_file(FsClock::EPOCH, "/b").unwrap();
    assert_eq!(fs.metadata("/b").unwrap_err().code, ErrorCode::NotFound);
}

#[test]
fn a_directory_moves_only_onto_a_directory_and_is_never_hard_linked() {
    let mut fs = MemFs::new().with_file("/file", b"").unwrap();
    fs.create_directory(FsClock::EPOCH, "/dir", 0o777).unwrap();
    // rename(2): a directory over a non-directory is ENOTDIR.
    assert_eq!(
        fs.rename(FsClock::EPOCH, "/dir", "/file").unwrap_err().code,
        ErrorCode::NotDirectory
    );
    // Over a non-empty directory it is ENOTEMPTY.
    fs.create_directory(FsClock::EPOCH, "/full", 0o777).unwrap();
    fs.create_directory(FsClock::EPOCH, "/full/inner", 0o777)
        .unwrap();
    assert_eq!(
        fs.rename(FsClock::EPOCH, "/dir", "/full").unwrap_err().code,
        ErrorCode::DirectoryNotEmpty
    );
    // link(2): a hard link to a directory is EPERM.
    assert_eq!(
        fs.link(FsClock::EPOCH, "/dir", "/alias").unwrap_err().code,
        ErrorCode::NotPermitted
    );
    assert!(fs.metadata("/dir").is_ok() && fs.metadata("/file").is_ok());
}

#[test]
fn symlinks_store_verbatim_targets_and_are_listed() {
    let mut fs = MemFs::new();
    fs.create_directory(FsClock::EPOCH, "/state", 0o777)
        .unwrap();
    fs.symlink(FsClock::EPOCH, "../missing", "/state/link")
        .unwrap();
    assert_eq!(
        fs.read_link(FsClock::EPOCH, "/state/link").unwrap(),
        "../missing"
    );
    let metadata = fs.metadata("/state/link").unwrap();
    assert_eq!(metadata.kind, FsEntryKind::Symlink);
    assert_eq!(metadata.len, 10);
    assert_eq!(
        fs.read_directory(FsClock::EPOCH, "/state").unwrap(),
        vec![FsDirectoryEntry {
            name: "link".into(),
            kind: FsEntryKind::Symlink,
            ino: metadata.ino,
        }]
    );
    assert_eq!(
        fs.open(FsClock::EPOCH, "/state/link/x", OpenFlags::read_only())
            .unwrap_err()
            .code,
        ErrorCode::Denied
    );
    fs.remove_file(FsClock::EPOCH, "/state/link").unwrap();
    assert_eq!(
        fs.read_link(FsClock::EPOCH, "/state/link")
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
}

/// RED before: rename refused any existing directory target (`EEXIST`), so
/// a directory could never replace an empty one the way the kernel's
/// `rename` does.
#[test]
fn a_directory_replaces_an_empty_directory_and_nothing_else() {
    let mut fs = MemFs::new();
    for directory in ["/a", "/a/inner", "/b", "/full", "/full/child"] {
        fs.create_directory(FsClock::EPOCH, directory, 0o755)
            .unwrap();
    }
    let replaced = fs.metadata("/b").unwrap().ino;
    let moved = fs.metadata("/a").unwrap().ino;
    fs.rename(FsClock::at(5), "/a", "/b").unwrap();
    let now = fs.metadata("/b").unwrap();
    assert_eq!(now.ino, moved, "the moved directory took the name");
    assert_ne!(now.ino, replaced);
    assert_eq!(
        fs.metadata("/b/inner").unwrap().kind,
        FsEntryKind::Directory
    );
    assert_eq!(fs.metadata("/a").unwrap_err().code, ErrorCode::NotFound);
    assert_eq!(
        fs.rename(FsClock::at(6), "/b", "/full").unwrap_err().code,
        ErrorCode::DirectoryNotEmpty
    );
    create(&mut fs, "/file", 0o644);
    assert_eq!(
        fs.rename(FsClock::at(7), "/b", "/file").unwrap_err().code,
        ErrorCode::NotDirectory
    );
    assert_eq!(
        fs.rename(FsClock::at(8), "/file", "/full")
            .unwrap_err()
            .code,
        ErrorCode::IsDirectory
    );
}

/// RED before: a symlink was a path-keyed record, so `link` of one minted
/// a second, independent symlink (its own inode, `nlink` 1 on both).
#[test]
fn a_hard_link_to_a_symlink_is_a_second_name_for_the_link_node() {
    let mut fs = MemFs::new();
    fs.symlink(FsClock::EPOCH, "target", "/l").unwrap();
    fs.link(FsClock::at(3), "/l", "/l2").unwrap();
    let first = fs.metadata("/l").unwrap();
    let second = fs.metadata("/l2").unwrap();
    assert_eq!(second.kind, FsEntryKind::Symlink);
    assert_eq!(first.ino, second.ino);
    assert_eq!((first.nlink, second.nlink), (2, 2));
    assert_eq!(fs.read_link(FsClock::EPOCH, "/l2").unwrap(), "target");
    fs.remove_file(FsClock::at(4), "/l").unwrap();
    assert_eq!(fs.metadata("/l2").unwrap().nlink, 1);
}

/// RED before: renaming a name onto another name for the same node dropped
/// the source and a link, where the kernel's `vfs_rename` changes nothing.
#[test]
fn a_rename_between_two_names_of_one_node_changes_nothing() {
    let mut fs = MemFs::new();
    create(&mut fs, "/f", 0o644);
    fs.link(FsClock::EPOCH, "/f", "/g").unwrap();
    fs.rename(FsClock::at(9), "/f", "/g").unwrap();
    assert_eq!(fs.metadata("/f").unwrap().nlink, 2);
    assert_eq!(fs.metadata("/g").unwrap().nlink, 2);
}

#[test]
fn exchange_swaps_two_entries_of_any_kinds() {
    let mut fs = MemFs::new();
    create(&mut fs, "/a", 0o644);
    fs.create_directory(FsClock::EPOCH, "/d", 0o755).unwrap();
    create(&mut fs, "/d/inner", 0o600);
    let (file, directory) = (
        fs.metadata("/a").unwrap().ino,
        fs.metadata("/d").unwrap().ino,
    );
    fs.exchange(FsClock::at(4), "/a", "/d").unwrap();
    assert_eq!(fs.metadata("/a").unwrap().ino, directory);
    assert_eq!(fs.metadata("/a/inner").unwrap().mode, 0o600);
    assert_eq!(fs.metadata("/d").unwrap().ino, file);
    assert_eq!(fs.metadata("/d").unwrap().kind, FsEntryKind::File);
    assert_eq!(
        fs.exchange(FsClock::EPOCH, "/a", "/missing")
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    assert_eq!(
        fs.exchange(FsClock::EPOCH, "/a", "/a/inner")
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
    fs.exchange(FsClock::EPOCH, "/d", "/d").unwrap();
}

#[test]
fn mknod_makes_regular_files_sockets_and_whiteouts_that_open_nothing() {
    let mut fs = MemFs::new();
    fs.make_node(FsClock::EPOCH, "/r", FsNode::File, 0o640)
        .unwrap();
    fs.make_node(FsClock::EPOCH, "/s", FsNode::Socket, 0o600)
        .unwrap();
    fs.make_node(FsClock::EPOCH, "/w", FsNode::Whiteout, 0)
        .unwrap();
    assert_eq!(fs.metadata("/r").unwrap().kind, FsEntryKind::File);
    assert_eq!(fs.metadata("/s").unwrap().kind, FsEntryKind::Socket);
    assert_eq!(fs.metadata("/w").unwrap().mode, 0);
    assert_eq!(
        fs.make_node(FsClock::EPOCH, "/s", FsNode::Socket, 0o600)
            .unwrap_err()
            .code,
        ErrorCode::AlreadyExists
    );
    assert_eq!(
        fs.open(FsClock::EPOCH, "/s", OpenFlags::read_only())
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput,
        "the caller answers ENXIO once the node is reached"
    );
    assert_eq!(
        fs.open(FsClock::EPOCH, "/w", OpenFlags::read_only())
            .unwrap_err()
            .code,
        ErrorCode::Denied,
        "the whiteout's 0 mode is judged first"
    );
    let names: Vec<_> = fs
        .read_directory(FsClock::EPOCH, "/")
        .unwrap()
        .into_iter()
        .map(|entry| (entry.name, entry.kind))
        .collect();
    assert!(names.contains(&("s".into(), FsEntryKind::Socket)));
    assert!(names.contains(&("w".into(), FsEntryKind::CharDevice)));
}

/// A device other than the whiteout needs `CAP_MKNOD`, judged after the
/// name and the parent's `w`+`x` as `vfs_mknod` judges it.
#[test]
fn mknod_refuses_a_device_after_the_name_and_the_parent() {
    let mut fs = MemFs::new();
    fs.make_node(FsClock::EPOCH, "/s", FsNode::Socket, 0o600)
        .unwrap();
    fs.create_directory(FsClock::EPOCH, "/ro", 0o500).unwrap();
    let refusal = |fs: &mut MemFs, path: &str, node: FsNode| {
        fs.make_node(FsClock::EPOCH, path, node, 0o600)
            .unwrap_err()
            .code
    };
    let tty = FsNode::CharDevice { device: 0x0501 };
    assert_eq!(refusal(&mut fs, "/s", tty), ErrorCode::AlreadyExists);
    assert_eq!(refusal(&mut fs, "/ro/c", tty), ErrorCode::Denied);
    assert_eq!(refusal(&mut fs, "/c", tty), ErrorCode::NotPermitted);
    assert_eq!(
        refusal(&mut fs, "/b", FsNode::BlockDevice { device: 0 }),
        ErrorCode::NotPermitted
    );
    assert!(fs.metadata("/c").is_err() && fs.metadata("/b").is_err());
}

/// `RENAME_WHITEOUT` moves the entry and leaves a mode-0 whiteout where it
/// was; between two names of one node it changes nothing.
#[test]
fn a_whiteout_rename_leaves_a_whiteout_at_the_old_name() {
    let mut fs = MemFs::new().with_file("/f", b"F".to_vec()).unwrap();
    fs.rename_whiteout(FsClock::EPOCH, "/f", "/g").unwrap();
    assert_eq!(fs.contents("/g").unwrap(), b"F");
    let whiteout = fs.metadata("/f").unwrap();
    assert_eq!((whiteout.kind, whiteout.mode), (FsEntryKind::CharDevice, 0));
    fs.link(FsClock::EPOCH, "/g", "/h").unwrap();
    fs.rename_whiteout(FsClock::EPOCH, "/g", "/h").unwrap();
    assert_eq!(fs.metadata("/g").unwrap().kind, FsEntryKind::File);
    assert_eq!(fs.metadata("/h").unwrap().nlink, 2);
}
