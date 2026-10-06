//! Tests for extended attribute targets and namespace permission checks.

use crate::tests::{create, xattr_value};
use crate::{MemFs, XATTR_CREATE, XATTR_REPLACE};
use patina_dst_abi::{ErrorCode, FsClock, OpenFlags, XattrTarget};
use patina_dst_driver_api::FsDriver;

fn set_xattr(
    fs: &mut MemFs,
    path: &str,
    name: &str,
    value: &[u8],
    flags: u32,
) -> Result<(), ErrorCode> {
    fs.set_xattr(
        FsClock::at(1),
        &XattrTarget::Path(path.into()),
        name,
        value,
        flags,
    )
    .map_err(|error| error.code)
}

#[test]
fn user_attributes_round_trip_and_follow_the_node() {
    let mut fs = MemFs::new();
    create(&mut fs, "/f", 0o644);
    let path = XattrTarget::Path("/f".into());
    fs.set_xattr(FsClock::at(5), &path, "user.a", b"v1", 0)
        .unwrap();
    assert_eq!(xattr_value(&mut fs, "/f", "user.a").unwrap(), b"v1");
    assert_eq!(
        fs.metadata("/f").unwrap().ctime_nanos,
        5,
        "a set moves ctime"
    );
    assert_eq!(
        set_xattr(&mut fs, "/f", "user.a", b"v2", XATTR_CREATE),
        Err(ErrorCode::AlreadyExists)
    );
    assert_eq!(
        set_xattr(&mut fs, "/f", "user.b", b"v2", XATTR_REPLACE),
        Err(ErrorCode::NoData)
    );
    assert_eq!(
        set_xattr(&mut fs, "/f", "user.a", b"v2", XATTR_CREATE | XATTR_REPLACE),
        Err(ErrorCode::AlreadyExists)
    );
    fs.set_xattr(FsClock::at(6), &path, "user.a", b"v2", XATTR_REPLACE)
        .unwrap();
    fs.link(FsClock::EPOCH, "/f", "/h").unwrap();
    fs.rename(FsClock::EPOCH, "/f", "/moved").unwrap();
    assert_eq!(xattr_value(&mut fs, "/h", "user.a").unwrap(), b"v2");
    assert_eq!(xattr_value(&mut fs, "/moved", "user.a").unwrap(), b"v2");
    assert_eq!(
        fs.list_xattr(&XattrTarget::Path("/h".into())).unwrap(),
        ["user.a"]
    );
    fs.remove_xattr(FsClock::EPOCH, &XattrTarget::Path("/h".into()), "user.a")
        .unwrap();
    assert_eq!(
        xattr_value(&mut fs, "/moved", "user.a").unwrap_err().code,
        ErrorCode::NoData
    );
    assert_eq!(
        fs.remove_xattr(FsClock::EPOCH, &XattrTarget::Path("/h".into()), "user.a")
            .unwrap_err()
            .code,
        ErrorCode::NoData
    );
}

#[test]
fn namespaces_are_judged_as_the_kernel_judges_an_unprivileged_caller() {
    let mut fs = MemFs::new();
    create(&mut fs, "/f", 0o644);
    create(&mut fs, "/ro", 0o444);
    create(&mut fs, "/wo", 0o200);
    fs.make_fifo(FsClock::EPOCH, "/p", 0o644).unwrap();
    fs.symlink(FsClock::EPOCH, "f", "/l").unwrap();
    // trusted.*: EPERM to write, ENODATA to read, never listed.
    assert_eq!(
        set_xattr(&mut fs, "/f", "trusted.x", b"v", 0),
        Err(ErrorCode::NotPermitted)
    );
    assert_eq!(
        xattr_value(&mut fs, "/f", "trusted.x").unwrap_err().code,
        ErrorCode::NoData
    );
    // security.*: readable, not writable.
    assert_eq!(
        set_xattr(&mut fs, "/f", "security.x", b"v", 0),
        Err(ErrorCode::NotPermitted)
    );
    assert_eq!(
        xattr_value(&mut fs, "/f", "security.x").unwrap_err().code,
        ErrorCode::NoData
    );
    // system.* and a name in no namespace have no handler.
    assert_eq!(
        set_xattr(&mut fs, "/f", "system.posix_acl_access", b"v", 0),
        Err(ErrorCode::Unsupported)
    );
    assert_eq!(
        set_xattr(&mut fs, "/f", "plain", b"v", 0),
        Err(ErrorCode::Unsupported)
    );
    assert_eq!(
        set_xattr(&mut fs, "/f", "user.", b"v", 0),
        Err(ErrorCode::InvalidInput)
    );
    // user.* needs a regular file or a directory...
    assert_eq!(
        set_xattr(&mut fs, "/p", "user.a", b"v", 0),
        Err(ErrorCode::NotPermitted)
    );
    assert_eq!(
        xattr_value(&mut fs, "/p", "user.a").unwrap_err().code,
        ErrorCode::NoData
    );
    assert_eq!(
        set_xattr(&mut fs, "/l", "user.a", b"v", 0),
        Err(ErrorCode::NotPermitted)
    );
    assert!(
        fs.list_xattr(&XattrTarget::Path("/l".into()))
            .unwrap()
            .is_empty()
    );
    // ...and the mode's bits: the permission check comes before the
    // handler lookup, so an unwritable file refuses even a bad name.
    assert_eq!(
        set_xattr(&mut fs, "/ro", "user.a", b"v", 0),
        Err(ErrorCode::Denied)
    );
    assert_eq!(
        set_xattr(&mut fs, "/ro", "plain", b"v", 0),
        Err(ErrorCode::Denied)
    );
    assert_eq!(
        xattr_value(&mut fs, "/wo", "user.a").unwrap_err().code,
        ErrorCode::Denied
    );
    assert_eq!(set_xattr(&mut fs, "/wo", "user.a", b"w", 0), Ok(()));
    fs.create_directory(FsClock::EPOCH, "/d", 0o755).unwrap();
    assert_eq!(set_xattr(&mut fs, "/d", "user.d", b"dir", 0), Ok(()));
    assert_eq!(
        fs.list_xattr(&XattrTarget::Path("/d".into())).unwrap(),
        ["user.d"]
    );
}

#[test]
fn a_descriptor_names_its_node_and_a_location_names_none() {
    let mut fs = MemFs::new();
    create(&mut fs, "/f", 0o644);
    let reader = fs
        .open(FsClock::EPOCH, "/f", OpenFlags::read_only())
        .unwrap();
    fs.set_xattr(FsClock::EPOCH, &XattrTarget::Fd(reader), "user.fd", b"F", 0)
        .unwrap();
    assert_eq!(xattr_value(&mut fs, "/f", "user.fd").unwrap(), b"F");
    let location = fs
        .open(FsClock::EPOCH, "/f", OpenFlags::path_only())
        .unwrap();
    assert_eq!(
        fs.get_xattr(&XattrTarget::Fd(location), "user.fd")
            .unwrap_err()
            .code,
        ErrorCode::InvalidHandle
    );
    // An unlinked node keeps its attributes for as long as it is held, and
    // they go with it.
    fs.remove_file(FsClock::EPOCH, "/f").unwrap();
    assert_eq!(
        fs.get_xattr(&XattrTarget::Fd(reader), "user.fd").unwrap(),
        b"F"
    );
    fs.close(reader).unwrap();
    fs.close(location).unwrap();
    assert!(fs.xattrs.is_empty());
}
