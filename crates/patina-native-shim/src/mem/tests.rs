//! Unit tests for this module and its focused submodules.

use super::*;

const RW: c_int = PROT_READ | PROT_WRITE;
/// A bit no architecture defines as a mapping flag.
const UNKNOWN: c_int = 0x0020_0000;

#[test]
fn a_write_back_goes_through_the_first_opened_writer_wherever_it_is_mapped() {
    // Two writable shared views of inode 7 through two descriptions
    // (driver handles 40 and 41), a read-only one through handle 39, and a
    // writable view of another inode through handle 38; the host puts
    // views at either address order, and the choice must not follow it.
    let view = |desc: DescId, ino: u64, maywrite: bool| Object::File {
        ino,
        desc,
        shared: true,
        maywrite,
        secret: false,
    };
    for swapped in [false, true] {
        let mut mappings = Mappings {
            views: Ranges::new(),
            caches: BTreeMap::new(),
            handles: BTreeMap::new(),
            descs: BTreeMap::from([(1, 41), (2, 40), (3, 39), (4, 38)]),
            policies: Ranges::new(),
            locks: Ranges::new(),
            future: None,
        };
        let (low, high) = if swapped {
            (0x9000, 0x1000)
        } else {
            (0x1000, 0x9000)
        };
        mappings.views.set(low, low + 0x1000, view(1, 7, true));
        mappings.views.set(high, high + 0x1000, view(2, 7, true));
        mappings.views.set(0x20000, 0x21000, view(3, 7, false));
        mappings.views.set(0x30000, 0x31000, view(4, 8, true));
        assert_eq!(writer_among(&mappings, 7), Some(40), "swapped {swapped}");
    }
}

#[test]
fn a_private_mapping_is_private_whatever_the_type_bits_share() {
    // MAP_SHARED_VALIDATE (3) contains MAP_PRIVATE's bit: testing the type
    // as flags made every private mapping read as shared-and-private.
    assert_eq!(judge(MAP_PRIVATE, RW, true, false, true, false), Ok(false));
    assert_eq!(
        judge(MAP_PRIVATE | UNKNOWN, RW, true, false, true, false),
        Ok(false)
    );
    assert_eq!(
        judge(MAP_SHARED, PROT_READ, true, false, true, false),
        Ok(true)
    );
    assert_eq!(
        judge(MAP_SHARED_VALIDATE, RW, true, true, true, false),
        Ok(true)
    );
    assert_eq!(judge(0, RW, true, true, true, false), Err(EINVAL));
    assert_eq!(judge(MAP_TYPE, RW, true, true, true, false), Err(EINVAL));
}

#[test]
fn unknown_flags_are_ignored_by_map_shared_and_refused_by_validate() {
    assert_eq!(
        judge(MAP_SHARED | UNKNOWN, PROT_READ, true, false, true, false),
        Ok(true)
    );
    assert_eq!(
        judge(
            MAP_SHARED_VALIDATE | UNKNOWN,
            PROT_READ,
            true,
            false,
            true,
            false
        ),
        Err(EOPNOTSUPP)
    );
    // `MAP_FIXED_NOREPLACE` is not a legacy flag either.
    assert_eq!(
        judge(
            MAP_SHARED_VALIDATE | MAP_FIXED_NOREPLACE,
            PROT_READ,
            true,
            false,
            true,
            false
        ),
        Err(EOPNOTSUPP)
    );
}

#[test]
fn access_modes_are_judged_before_the_file_kind() {
    // Shared and writable needs a writable description; any mapping needs
    // a readable one; both before a non-file's ENODEV.
    assert_eq!(judge(MAP_SHARED, RW, true, false, true, false), Err(EACCES));
    assert_eq!(judge(MAP_PRIVATE, RW, true, false, true, false), Ok(false));
    assert_eq!(
        judge(MAP_SHARED, PROT_READ, false, true, true, false),
        Err(EACCES)
    );
    assert_eq!(
        judge(MAP_PRIVATE, PROT_READ, false, true, false, false),
        Err(EACCES)
    );
    assert_eq!(
        judge(MAP_SHARED, PROT_READ, true, false, false, false),
        Err(ENODEV)
    );
    assert_eq!(
        judge(
            MAP_PRIVATE | MAP_GROWSDOWN,
            PROT_READ,
            true,
            false,
            true,
            false
        ),
        Err(EINVAL)
    );
    // A file on a `noexec` mount maps executable `EPERM`, after the
    // access modes and before the file kind and `MAP_GROWSDOWN`.
    let exec = PROT_READ | PROT_EXEC;
    assert_eq!(
        judge(MAP_SHARED, exec, true, true, true, true),
        Err(crate::EPERM)
    );
    assert_eq!(
        judge(MAP_SHARED, exec, false, true, true, true),
        Err(EACCES)
    );
    assert_eq!(
        judge(MAP_PRIVATE | MAP_GROWSDOWN, exec, true, false, false, true),
        Err(crate::EPERM)
    );
}

#[test]
fn a_huge_page_size_names_a_pool_the_machine_has() {
    assert_eq!(huge_page_size(0), Some(2 << 20));
    assert_eq!(huge_page_size(21), Some(2 << 20));
    assert_eq!(huge_page_size(30), Some(1 << 30));
    assert_eq!(huge_page_size(22), None);
    assert_eq!(huge_page_size(12), None);
}

#[test]
fn a_read_only_shared_view_or_attachment_refuses_write() {
    let view = |shared, maywrite| Object::File {
        ino: 1,
        desc: 1,
        shared,
        maywrite,
        secret: false,
    };
    assert!(view(true, false).refuses_write());
    assert!(!view(true, true).refuses_write());
    assert!(!view(false, true).refuses_write());
    assert!(
        Object::Segment {
            id: 0,
            maywrite: false
        }
        .refuses_write()
    );
    assert!(view(true, true).writes_back(1));
    assert!(!view(false, true).writes_back(1));
    assert!(!view(true, true).writes_back(2));
}
