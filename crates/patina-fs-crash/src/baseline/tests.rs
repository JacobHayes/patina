//! Tests for durable entry records and filesystem inventory capture.

use crate::CrashFs;
use crate::tests::write;
use patina_dst_abi::{ErrorCode, FsClock};
use patina_dst_driver_api::FsDriver;
use patina_dst_fs_mem::MemFs;

#[test]
fn a_mounted_image_is_durable_and_composes_with_crash_injection() {
    // This is the `native-run --mount` composition with `--fs-crash-at`: the
    // shim builds `CrashFs::new(FsImage::into_memfs())`, so a mounted corpus
    // is the durable baseline while unsynced guest writes still drop on a
    // crash exactly as with an empty filesystem. `CrashFs::new` here uses the
    // same default policy as `CrashFs::default()` (torn-write probability 1),
    // so the mount does not change crash behavior.
    let image = patina_dst_fs_mem::FsImage::new(vec![patina_dst_fs_mem::FsImageEntry::File {
        path: "/corpus/data.txt".into(),
        contents: b"mounted-and-durable".to_vec(),
    }]);
    let mounted = image.into_memfs().unwrap();
    let mut fs = CrashFs::new(mounted);

    // A new guest write without an fsync, with the descriptor closed before
    // the crash — an fd still open across a crash pins its name (see
    // `a_crash_lost_create_keeps_its_open_descriptor_and_loses_its_data`),
    // and this case is about the namespace, not the descriptor table.
    let volatile = write(&mut fs, "/scratch/out.txt", b"never-synced");
    fs.close(volatile).unwrap();
    fs.crash().unwrap();

    // The mounted (durable) content survives the crash byte-for-byte.
    assert_eq!(
        fs.contents("/corpus/data.txt").unwrap(),
        b"mounted-and-durable"
    );
    // The unsynced guest write's namespace entry was never made durable.
    assert_eq!(
        fs.metadata("/scratch/out.txt").unwrap_err().code,
        ErrorCode::NotFound
    );
}

#[test]
fn seed_image_symlink_survives_crash() {
    let mut base = MemFs::new();
    base.symlink(FsClock::EPOCH, "/etc/target", "/link")
        .unwrap();
    let mut fs = CrashFs::new(base);
    assert_eq!(
        fs.read_link(FsClock::EPOCH, "/link").unwrap(),
        "/etc/target"
    );
    fs.crash().unwrap();
    assert_eq!(
        fs.read_link(FsClock::EPOCH, "/link").unwrap(),
        "/etc/target"
    );
}
