//! The machine's one filesystem: a child process's runtime drives
//! [`RemoteFs`], which forwards every driver call to the root, and the hub
//! answers it on the root's own driver stack ([`serve`]). Faults are drawn
//! there, in the machine's one order; the child records each outcome in its
//! own timeline as for any filesystem operation. The root records nothing
//! for a call it serves.
//!
//! A call travels as a JSON array: its name, then its arguments; the answer
//! is the call's `DriverResult` as JSON. Both sides come from one list of
//! the driver's calls, so they cannot disagree.

use super::{
    Message, channel, protocol_fatal, protocol_fatal_text, receive, receive_payload, send_frame,
};
use patina_dst_abi::{
    CrashKind, ErrorCode, Fd, FsAllocateMode, FsClock, FsDirectoryEntry, FsMetadata, FsNode,
    OpenFlags, SeekWhence, XattrTarget,
};
use patina_dst_driver_api::{DriverResult, FsDriver, FsFaultReport, FsFaultTally};
use serde_json::Value;

/// A child process's filesystem: the root's, over the channel.
pub(crate) struct RemoteFs;

/// Ask the hub to run one driver call and wait for its answer.
fn remote(request: Value) -> Value {
    let payload = serde_json::to_vec(&request).unwrap_or_else(|error| {
        protocol_fatal_text(&format!("encoding a filesystem call: {error}"))
    });
    send_frame(
        channel(),
        Message::Fs {
            len: payload.len() as u64,
        },
        &payload,
    );
    let len = match receive(channel()) {
        Some(Message::FsReply { len }) => len,
        Some(other) => protocol_fatal("a filesystem answer", &other),
        None => super::orphaned(),
    };
    let reply = receive_payload(channel(), len).unwrap_or_else(|| super::orphaned());
    serde_json::from_slice(&reply).unwrap_or_else(|error| {
        protocol_fatal_text(&format!("decoding a filesystem answer: {error}"))
    })
}

/// The type an argument passes as, by value or by reference.
macro_rules! arg_type {
    (val, $t:ty) => {
        $t
    };
    (by_ref, $t:ty) => {
        &$t
    };
}

/// The owned type the hub decodes an argument into.
macro_rules! owned_type {
    (val, $t:ty) => {
        $t
    };
    (by_ref, $t:ty) => {
        <$t as ToOwned>::Owned
    };
}

/// How the hub passes a decoded argument on.
macro_rules! pass {
    (val, $x:ident) => {
        $x
    };
    (by_ref, $x:ident) => {
        &$x
    };
}

macro_rules! remote_calls {
    ($(fn $name:ident($($kind:ident $arg:ident: $t:ty),*) -> $ret:ty;)*) => {
        impl FsDriver for RemoteFs {
            $(
                fn $name(&mut self $(, $arg: arg_type!($kind, $t))*) -> $ret {
                    let reply = remote(serde_json::json!([stringify!($name) $(, $arg)*]));
                    serde_json::from_value(reply).unwrap_or_else(|error| {
                        protocol_fatal_text(&format!(
                            "decoding the answer to {}: {error}",
                            stringify!($name)
                        ))
                    })
                }
            )*

            // The fault plane's report is the root's, which serves every call.
            fn fault_report(&self) -> Option<FsFaultReport> {
                None
            }

            fn fault_tally(&self) -> Option<FsFaultTally> {
                None
            }
        }

        /// Run the call `request` names on the root's driver stack `fs`, and
        /// answer its result.
        pub(super) fn serve(fs: &mut dyn FsDriver, request: Value) -> Value {
            let Value::Array(items) = request else {
                protocol_fatal_text("a filesystem call that is not an array");
            };
            let mut items = items.into_iter();
            let name = items.next();
            let name = name.as_ref().and_then(Value::as_str).unwrap_or_default();
            match name {
                $(
                    stringify!($name) => {
                        $(
                            let $arg: owned_type!($kind, $t) = serde_json::from_value(
                                items.next().unwrap_or(Value::Null),
                            )
                            .unwrap_or_else(|error| {
                                protocol_fatal_text(&format!(
                                    "decoding {}'s {}: {error}",
                                    stringify!($name),
                                    stringify!($arg)
                                ))
                            });
                        )*
                        let result: $ret = fs.$name($(pass!($kind, $arg)),*);
                        serde_json::to_value(result).unwrap_or_else(|error| {
                            protocol_fatal_text(&format!("encoding {}'s answer: {error}", name))
                        })
                    }
                )*
                other => protocol_fatal_text(&format!("an unknown filesystem call {other:?}")),
            }
        }
    };
}

remote_calls! {
    fn open(val clock: FsClock, by_ref path: str, val flags: OpenFlags) -> DriverResult<Fd>;
    fn open_synthetic(by_ref path: str) -> DriverResult<()>;
    fn read_synthetic(val max_len: usize, val available: usize, val positional: bool, val allocates: bool) -> DriverResult<usize>;
    fn read(val clock: FsClock, val fd: Fd, val max_len: usize) -> DriverResult<Vec<u8>>;
    fn write(val clock: FsClock, val fd: Fd, by_ref bytes: [u8]) -> DriverResult<usize>;
    fn read_at(val clock: FsClock, val fd: Fd, val offset: u64, val max_len: usize) -> DriverResult<Vec<u8>>;
    fn write_at(val clock: FsClock, val fd: Fd, val offset: u64, by_ref bytes: [u8]) -> DriverResult<usize>;
    fn close(val fd: Fd) -> DriverResult<()>;
    fn seek(val fd: Fd, val offset: i64, val whence: SeekWhence) -> DriverResult<u64>;
    fn dup(val fd: Fd) -> DriverResult<Fd>;
    fn set_append(val fd: Fd, val append: bool) -> DriverResult<()>;
    fn metadata(by_ref path: str) -> DriverResult<FsMetadata>;
    fn fd_metadata(val fd: Fd) -> DriverResult<FsMetadata>;
    fn inode_metadata(val ino: u64) -> DriverResult<FsMetadata>;
    fn create_directory(val clock: FsClock, by_ref path: str, val mode: u32) -> DriverResult<()>;
    fn remove_file(val clock: FsClock, by_ref path: str) -> DriverResult<()>;
    fn sync(val fd: Fd) -> DriverResult<()>;
    fn fail_writeback(val fd: Fd, val code: ErrorCode) -> DriverResult<()>;
    fn fail_writeback_all(val code: ErrorCode) -> DriverResult<()>;
    fn wait_writeback(val fd: Fd) -> DriverResult<()>;
    fn drop_cache(val fd: Fd, val offset: u64, val len: u64) -> DriverResult<()>;
    fn set_len(val clock: FsClock, val fd: Fd, val len: u64) -> DriverResult<()>;
    fn set_len_by_path(val clock: FsClock, by_ref path: str, val len: u64) -> DriverResult<()>;
    fn allocate(val clock: FsClock, val fd: Fd, val offset: u64, val len: u64, val mode: FsAllocateMode, val keep_size: bool) -> DriverResult<()>;
    fn set_times(val clock: FsClock, val fd: Fd, val atime_nanos: Option<i128>, val mtime_nanos: Option<i128>) -> DriverResult<()>;
    fn set_inode_times(val clock: FsClock, val ino: u64, val atime_nanos: Option<i128>, val mtime_nanos: Option<i128>) -> DriverResult<()>;
    fn set_times_by_path(val clock: FsClock, by_ref path: str, val atime_nanos: Option<i128>, val mtime_nanos: Option<i128>) -> DriverResult<()>;
    fn read_directory(val clock: FsClock, by_ref path: str) -> DriverResult<Vec<FsDirectoryEntry>>;
    fn read_directory_fd(val clock: FsClock, val fd: Fd) -> DriverResult<Vec<FsDirectoryEntry>>;
    fn remove_directory(val clock: FsClock, by_ref path: str) -> DriverResult<()>;
    fn rename(val clock: FsClock, by_ref from: str, by_ref to: str) -> DriverResult<()>;
    fn link(val clock: FsClock, by_ref from: str, by_ref to: str) -> DriverResult<()>;
    fn symlink(val clock: FsClock, by_ref target: str, by_ref link_path: str) -> DriverResult<()>;
    fn read_link(val clock: FsClock, by_ref path: str) -> DriverResult<String>;
    fn make_fifo(val clock: FsClock, by_ref path: str, val mode: u32) -> DriverResult<()>;
    fn make_node(val clock: FsClock, by_ref path: str, val node: FsNode, val mode: u32) -> DriverResult<()>;
    fn rename_whiteout(val clock: FsClock, by_ref from: str, by_ref to: str) -> DriverResult<()>;
    fn exchange(val clock: FsClock, by_ref first: str, by_ref second: str) -> DriverResult<()>;
    fn sync_all() -> DriverResult<()>;
    fn sync_filesystem(val fd: Fd) -> DriverResult<()>;
    fn get_xattr(by_ref target: XattrTarget, by_ref name: str) -> DriverResult<Vec<u8>>;
    fn list_xattr(by_ref target: XattrTarget) -> DriverResult<Vec<String>>;
    fn set_xattr(val clock: FsClock, by_ref target: XattrTarget, by_ref name: str, by_ref value: [u8], val flags: u32) -> DriverResult<()>;
    fn remove_xattr(val clock: FsClock, by_ref target: XattrTarget, by_ref name: str) -> DriverResult<()>;
    fn set_mode(val clock: FsClock, by_ref path: str, val mode: u32) -> DriverResult<()>;
    fn set_fd_mode(val clock: FsClock, val fd: Fd, val mode: u32) -> DriverResult<()>;
    fn fd_path(val fd: Fd) -> DriverResult<String>;
    fn fd_ino(val fd: Fd) -> DriverResult<u64>;
    fn open_path_unfaulted(val clock: FsClock, by_ref path: str) -> DriverResult<Fd>;
    fn metadata_unfaulted(by_ref path: str) -> DriverResult<FsMetadata>;
    fn read_link_unfaulted(val clock: FsClock, by_ref path: str) -> DriverResult<String>;
    fn fd_metadata_unfaulted(val fd: Fd) -> DriverResult<FsMetadata>;
    fn inode_metadata_unfaulted(val ino: u64) -> DriverResult<FsMetadata>;
    fn read_at_unfaulted(val clock: FsClock, val fd: Fd, val offset: u64, val max_len: usize) -> DriverResult<Vec<u8>>;
    fn dirty_pages(val fd: Fd, val first: u64, val last: u64) -> DriverResult<u64>;
    fn set_inode_mode(val clock: FsClock, val ino: u64, val mode: u32) -> DriverResult<()>;
    fn retain_inode(val ino: u64) -> DriverResult<()>;
    fn release_inode(val ino: u64) -> DriverResult<()>;
    fn write_back_at(val clock: FsClock, val fd: Fd, val offset: u64, by_ref bytes: [u8]) -> DriverResult<usize>;
    fn create_anonymous(val clock: FsClock, by_ref name: str, val mode: u32, val seals: u32, val huge_page: u64) -> DriverResult<Fd>;
    fn create_input_file_unfaulted(val clock: FsClock, by_ref contents: [u8]) -> DriverResult<Fd>;
    fn seals(val fd: Fd) -> DriverResult<u32>;
    fn add_seals(val fd: Fd, val seals: u32, val writably_mapped: bool) -> DriverResult<()>;
    fn crash(val clock: FsClock) -> DriverResult<()>;
    fn crash_and_export_restart_snapshot(val clock: FsClock, val kind: CrashKind) -> DriverResult<Vec<u8>>;
}
