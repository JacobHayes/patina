//! An errno is not a successful transfer count. Only the pthread ABI accepts
//! the positive value directly; byte-count ABIs must pass it through `fail`.

use std::ffi::c_int;

pub(super) struct PosixErrno(c_int);

impl PosixErrno {
    pub(super) fn new(value: c_int) -> Self {
        Self(value)
    }
}

impl From<PosixErrno> for c_int {
    fn from(value: PosixErrno) -> Self {
        value.0
    }
}
