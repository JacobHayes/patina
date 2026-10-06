//! Unit tests for this module and its focused submodules.

use super::*;

/// `openat2(AT_FDCWD, path, how, size)` for a `how` of `fields` followed by
/// zeroes out to a page, with a path past `PATH_MAX`: every answer here is
/// decided before the path is resolved, and one that is not is
/// `ENAMETOOLONG`, so no runtime is needed.
fn openat2(fields: [u64; 4], size: usize) -> i64 {
    let mut how = vec![0u64; crate::PAGE_SIZE / 8 + 1];
    how[..4].copy_from_slice(&fields);
    let path = std::ffi::CString::new("a".repeat(crate::paths::PATH_MAX)).unwrap();
    sys_openat2(
        AT_FDCWD,
        path.as_ptr() as u64,
        how.as_ptr() as u64,
        size as u64,
    )
}

#[test]
fn open_how_is_copied_as_copy_struct_from_user_copies_it() {
    assert_eq!(openat2([0; 4], OPEN_HOW_SIZE - 1), -EINVAL);
    assert_eq!(openat2([0; 4], crate::PAGE_SIZE + 1), -E2BIG);
    assert_eq!(openat2([0, 0, 0, 1], OPEN_HOW_SIZE + 8), -E2BIG);
    let resolved = -(errno::ENAMETOOLONG as i64);
    assert_eq!(openat2([0; 4], OPEN_HOW_SIZE + 8), resolved);
    assert_eq!(
        sys_openat2(AT_FDCWD, c"/".as_ptr() as u64, 0, OPEN_HOW_SIZE as u64),
        -EFAULT
    );
}

#[test]
fn open_how_is_judged_as_build_open_flags_judges_it() {
    assert_eq!(openat2([1 << 40, 0, 0, 0], OPEN_HOW_SIZE), -EINVAL);
    assert_eq!(openat2([0, 0o644, 0, 0], OPEN_HOW_SIZE), -EINVAL);
    assert_eq!(openat2([O_CREAT, 0o10644, 0, 0], OPEN_HOW_SIZE), -EINVAL);
    assert_eq!(
        openat2([O_CREAT | O_DIRECTORY, 0o644, 0, 0], OPEN_HOW_SIZE),
        -EINVAL
    );
    assert_eq!(openat2([0, 0, 0x80, 0], OPEN_HOW_SIZE), -EINVAL);
    assert_eq!(
        openat2([0, 0, RESOLVE_BENEATH | RESOLVE_IN_ROOT, 0], OPEN_HOW_SIZE),
        -EINVAL
    );
    assert_eq!(
        openat2([O_PATH | O_WRONLY, 0, 0, 0], OPEN_HOW_SIZE),
        -EINVAL
    );
    assert_eq!(
        openat2([O_PATH | O_TRUNC, 0, RESOLVE_CACHED, 0], OPEN_HOW_SIZE),
        -EINVAL
    );
    assert_eq!(
        openat2([O_CREAT, 0o644, RESOLVE_CACHED, 0], OPEN_HOW_SIZE),
        -(errno::EAGAIN as i64)
    );
    assert_eq!(
        openat2([O_TRUNC, 0, RESOLVE_CACHED, 0], OPEN_HOW_SIZE),
        -(errno::EAGAIN as i64)
    );
    assert_eq!(
        openat2([uapi::O_NOATIME as u64, 0, 0, 0], OPEN_HOW_SIZE),
        -ENOSYS
    );
}
