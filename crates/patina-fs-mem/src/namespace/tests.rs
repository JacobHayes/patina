//! Tests for path resolution, directory enumeration and namespace moves.

use crate::MemFs;
use crate::tests::create;
use patina_dst_abi::{ErrorCode, FsClock, FsDirectoryEntry, FsEntryKind, FsNode, OpenFlags};
use patina_dst_driver_api::FsDriver;

/// A hard link is a second name for the same node, whatever its kind: one
/// inode, one link count, one mode, and the node goes with its last name.
/// A rename between two names of one node changes nothing.
#[test]
fn a_hard_link_is_a_second_name_for_the_same_node_of_any_kind() {
    let mut fs = MemFs::new().with_file("/file", b"abc").unwrap();
    fs.make_fifo(FsClock::EPOCH, "/fifo", 0o660).unwrap();
    fs.symlink(FsClock::EPOCH, "target", "/symlink").unwrap();
    for (name, kind) in [
        ("/file", FsEntryKind::File),
        ("/fifo", FsEntryKind::Fifo),
        ("/symlink", FsEntryKind::Symlink),
    ] {
        let alias = format!("{name}-alias");
        fs.link(FsClock::EPOCH, name, &alias).unwrap();
        let first = fs.metadata(name).unwrap();
        let second = fs.metadata(&alias).unwrap();
        assert_eq!(second.kind, kind, "{name}");
        assert_eq!(first.ino, second.ino, "{name}");
        assert_eq!((first.nlink, second.nlink), (2, 2), "{name}");
        fs.rename(FsClock::EPOCH, name, &alias).unwrap();
        assert_eq!(fs.metadata(name).unwrap().nlink, 2, "{name}");
        if kind != FsEntryKind::Symlink {
            fs.set_mode(FsClock::EPOCH, &alias, 0o600).unwrap();
            assert_eq!(fs.metadata(name).unwrap().mode, 0o600, "{name}");
        }

        fs.remove_file(FsClock::EPOCH, name).unwrap();
        let remaining = fs.metadata(&alias).unwrap();
        assert_eq!((remaining.ino, remaining.nlink), (first.ino, 1), "{name}");
        assert_eq!(fs.inode_metadata(first.ino).unwrap().kind, kind, "{name}");
        fs.remove_file(FsClock::EPOCH, &alias).unwrap();
        assert_eq!(
            fs.inode_metadata(first.ino).unwrap_err().code,
            ErrorCode::NotFound,
            "{name}"
        );
    }
}

/// A FIFO is an entry like any other: it carries its creation mode, has no
/// length, is listed, renamed (keeping its identity, alone or beneath a
/// renamed directory) and unlinked unconditionally, and a rename over one
/// releases its node. Creating one needs `w` and `x` on the directory.
#[test]
fn a_fifo_is_created_listed_renamed_and_unlinked_like_any_entry() {
    let mut fs = MemFs::new();
    fs.make_fifo(FsClock::EPOCH, "/tmp/pipe", 0o644).unwrap();
    let metadata = fs.metadata("/tmp/pipe").unwrap();
    assert_eq!(
        (metadata.kind, metadata.mode, metadata.len, metadata.nlink),
        (FsEntryKind::Fifo, 0o644, 0, 1)
    );
    assert_eq!(
        fs.make_fifo(FsClock::EPOCH, "/tmp/pipe", 0o666)
            .unwrap_err()
            .code,
        ErrorCode::AlreadyExists
    );
    fs.create_directory(FsClock::EPOCH, "/tmp/locked", 0o500)
        .unwrap();
    assert_eq!(
        fs.make_fifo(FsClock::EPOCH, "/tmp/locked/pipe", 0o666)
            .unwrap_err()
            .code,
        ErrorCode::Denied
    );
    fs.set_mode(FsClock::EPOCH, "/tmp/locked", 0o755).unwrap();
    fs.remove_directory(FsClock::EPOCH, "/tmp/locked").unwrap();

    let listed = fs.read_directory(FsClock::EPOCH, "/tmp").unwrap();
    assert_eq!(
        listed,
        vec![FsDirectoryEntry {
            name: "pipe".into(),
            kind: FsEntryKind::Fifo,
            ino: metadata.ino,
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
    create(&mut fs, "/tmp/file", 0o644);
    fs.rename(FsClock::EPOCH, "/tmp/pipe", "/tmp/file").unwrap();
    let replaced = fs.metadata("/tmp/file").unwrap();
    assert_eq!(
        (replaced.kind, replaced.ino),
        (FsEntryKind::Fifo, metadata.ino)
    );
    assert_eq!(
        fs.metadata("/tmp/pipe").unwrap_err().code,
        ErrorCode::NotFound
    );
    create(&mut fs, "/tmp/regular", 0o644);
    fs.rename(FsClock::EPOCH, "/tmp/regular", "/tmp/file")
        .unwrap();
    assert_eq!(fs.metadata("/tmp/file").unwrap().kind, FsEntryKind::File);
    assert_eq!(
        fs.inode_metadata(metadata.ino).unwrap_err().code,
        ErrorCode::NotFound,
        "the replaced FIFO's node is released"
    );

    fs.create_directory(FsClock::EPOCH, "/tmp/box", 0o777)
        .unwrap();
    fs.make_fifo(FsClock::EPOCH, "/tmp/box/pipe", 0o666)
        .unwrap();
    let ino = fs.metadata("/tmp/box/pipe").unwrap().ino;
    fs.rename(FsClock::EPOCH, "/tmp/box", "/tmp/crate").unwrap();
    let moved = fs.metadata("/tmp/crate/pipe").unwrap();
    assert_eq!((moved.kind, moved.ino), (FsEntryKind::Fifo, ino));
    fs.remove_file(FsClock::EPOCH, "/tmp/crate/pipe").unwrap();
    assert_eq!(
        fs.metadata("/tmp/crate/pipe").unwrap_err().code,
        ErrorCode::NotFound
    );
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

/// A directory replaces an empty directory and nothing else, as the
/// kernel's `rename` judges it, and is never hard-linked.
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
    assert_eq!(
        fs.link(FsClock::EPOCH, "/b", "/alias").unwrap_err().code,
        ErrorCode::NotPermitted
    );
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
fn mknod_makes_files_sockets_and_whiteouts_and_refuses_devices() {
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

    // A device other than the whiteout needs `CAP_MKNOD`, judged after the
    // name and the parent's `w`+`x` as `vfs_mknod` judges it.
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
