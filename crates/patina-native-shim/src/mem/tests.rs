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

/// A malformed request about the runtime arena's region gets the kernel's
/// refusal of the malformation, which the kernel judges before the range;
/// a well-formed one gets the region's answer.
#[test]
fn a_malformed_request_about_the_arena_is_refused_as_malformed_first() {
    let (base, _) = crate::arena::region();
    let anonymous = MAP_PRIVATE | MAP_ANONYMOUS;
    let errno = |result: crate::abi::SysResult<usize>| result.err().map(|errno| errno.get());
    let rows: [(&str, Option<c_int>, c_int); 5] = [
        (
            "an unaligned fixed address",
            errno(mmap(base + 1, PAGE, RW, anonymous | MAP_FIXED, -1, 0)),
            EINVAL,
        ),
        (
            "no length",
            errno(mmap(base, 0, RW, anonymous | MAP_FIXED, -1, 0)),
            EINVAL,
        ),
        (
            "an unaligned offset",
            errno(mmap(base, PAGE, RW, anonymous | MAP_FIXED_NOREPLACE, -1, 1)),
            EINVAL,
        ),
        (
            "no sharing type",
            errno(mmap(base, PAGE, RW, MAP_ANONYMOUS | MAP_FIXED, -1, 0)),
            EINVAL,
        ),
        (
            "a well-formed fixed mapping",
            errno(mmap(base, PAGE, RW, anonymous | MAP_FIXED, -1, 0)),
            ENOMEM,
        ),
    ];
    for (what, answer, expected) in rows {
        assert_eq!(answer, Some(expected), "{what}");
    }
    assert_eq!(
        madvise(base, PAGE, usize::MAX),
        fail(EINVAL),
        "an unknown advice"
    );
    assert_eq!(madvise(base, PAGE, 4), fail(ENOMEM), "MADV_DONTNEED");
    let refusal = |result: crate::abi::SysResult<i64>| result.err().map(|errno| errno.get());
    assert_eq!(
        refusal(mprotect(base, PAGE, 0x40_0000)),
        Some(EINVAL),
        "an unknown protection"
    );
    assert_eq!(refusal(mprotect(base, PAGE, 0)), Some(ENOMEM), "PROT_NONE");
    assert_eq!(
        refusal(msync(base, PAGE, 0xff)),
        Some(EINVAL),
        "unknown sync flags"
    );
    assert_eq!(refusal(msync(base, PAGE, MS_SYNC)), Some(ENOMEM), "MS_SYNC");
}

/// A movable growth of a locked mapping into the arena's region that the
/// lock limit refuses leaves no place behind for the move it never made.
#[test]
fn a_refused_move_out_of_the_arenas_way_leaves_no_mapping_behind() {
    // The count below is of the whole process's mappings, so it means something
    // only when no other test shares the process: nextest's process-per-test
    // mode, which the check and CI use. Under `cargo test` it is not judged.
    if std::env::var_os("NEXTEST_EXECUTION_MODE").is_none_or(|mode| mode != "process-per-test") {
        return;
    }
    let (base, _) = crate::arena::region();
    let below = base - PAGE;
    let claim = (MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE) as usize;
    assert_eq!(
        host(
            Syscall::N_mmap,
            [below, PAGE, RW as usize, claim, usize::MAX, 0]
        ),
        below as i64
    );
    assert_eq!(patina_mlock(below, PAGE, 0), 0);
    let count = || {
        let mut mappings = 0;
        assert!(crate::arena::each_mapping(&mut |_, _| mappings += 1));
        mappings
    };
    let before = count();
    let past_the_limit = (lock_limit_pages() + 2) * PAGE;
    for _ in 0..3 {
        let refused = mremap(below, PAGE, past_the_limit, MREMAP_MAYMOVE, 0);
        assert_eq!(
            refused.err().map(|errno| errno.get()),
            Some(crate::EWOULDBLOCK)
        );
    }
    assert_eq!(count(), before);
    assert_eq!(patina_munlock(below, PAGE), 0);
    host(Syscall::N_munmap, [below, PAGE, 0, 0, 0, 0]);
}
