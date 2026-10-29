//! [`Bookkeeping`]: the context as an embedder's own internal steps see it.

use patina_dst_abi::{Fd, FsMetadata};

use crate::{Context, RuntimeError};

/// The context for an embedder's internal step: a page cache filling, a
/// readiness reactor reading the clock, a name table following a crash.
/// Only reads that take no guest-facing effect are listed here. They record
/// no operation (outside host capture, where a filesystem read records the
/// host's answer for the replay, which executes no driver), draw no fault,
/// charge no latency, are no crash point and consume no seeded
/// stream. Code that holds only this view cannot name an effectful method.
pub struct Bookkeeping<'a> {
    context: &'a mut Context,
}

impl Context {
    /// This context as [`Bookkeeping`].
    pub fn bookkeeping(&mut self) -> Bookkeeping<'_> {
        Bookkeeping { context: self }
    }
}

macro_rules! delegate {
    ($(fn $name:ident(&mut self $(, $arg:ident: $ty:ty)*) -> $ret:ty;)*) => {
        $(
            #[doc = concat!("[`Context::", stringify!($name), "`].")]
            pub fn $name(&mut self $(, $arg: $ty)*) -> $ret {
                self.context.$name($($arg),*)
            }
        )*
    };
}

impl Bookkeeping<'_> {
    /// [`Context::param`].
    pub fn param(&self, key: &str) -> Option<&str> {
        self.context.param(key)
    }

    delegate! {
        fn fs_metadata_unrecorded(&mut self, path: &str) -> Result<FsMetadata, RuntimeError>;
        fn fs_fd_metadata_unrecorded(&mut self, fd: Fd) -> Result<FsMetadata, RuntimeError>;
        fn fs_read_link_unrecorded(&mut self, path: &str) -> Result<String, RuntimeError>;
        fn fs_fd_path_unrecorded(&mut self, fd: Fd) -> Result<String, RuntimeError>;
        fn fs_cursor_unrecorded(&mut self, fd: Fd) -> Result<u64, RuntimeError>;
        fn fs_read_at_unrecorded(
            &mut self,
            fd: Fd,
            offset: u64,
            max_len: usize
        ) -> Result<Vec<u8>, RuntimeError>;
        fn fs_dirty_pages_unrecorded(
            &mut self,
            fd: Fd,
            first: u64,
            last: u64
        ) -> Result<u64, RuntimeError>;
        fn fs_open_path_unrecorded(&mut self, path: &str) -> Result<Fd, RuntimeError>;
        fn fs_time_unrecorded(&mut self) -> Result<u64, RuntimeError>;
        fn monotonic_now_unrecorded(&mut self) -> Result<u64, RuntimeError>;
    }

    /// [`Context::guest_cwd`].
    pub fn guest_cwd(&self) -> Option<&str> {
        self.context.guest_cwd()
    }
}
