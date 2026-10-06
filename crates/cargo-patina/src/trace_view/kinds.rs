//! Exhaustive operation classification and the filter registry it generates.
use super::*;

macro_rules! operation_kinds {
    ($( $operation:pat => ($tag:literal, $category:ident); )+) => {
        pub const OP_KINDS: &[(&str, Category)] = &[$(($tag, Category::$category),)+];
        pub fn operation_kind(operation: &Operation) -> &'static str {
            match operation { $($operation => $tag,)+ }
        }
    };
}

operation_kinds! {
    Operation::EntropyFill { .. } => ("entropy_fill", Entropy);
    Operation::ClockNow { .. } => ("clock_now", Clock);
    Operation::SleepUntil { .. } => ("sleep_until", Sleep);
    Operation::FsOpen { .. } => ("fs_open", Fs);
    Operation::FsRead { .. } => ("fs_read", Fs);
    Operation::FsWrite { .. } => ("fs_write", Fs);
    Operation::FsReadAt { .. } => ("fs_read_at", Fs);
    Operation::FsWriteAt { .. } => ("fs_write_at", Fs);
    Operation::FsWriteBackAt { .. } => ("fs_write_back_at", Fs);
    Operation::FsCreateAnonymous { .. } => ("fs_create_anonymous", Fs);
    Operation::FsSeals { .. } => ("fs_seals", Fs);
    Operation::FsAddSeals { .. } => ("fs_add_seals", Fs);
    Operation::FsClose { .. } => ("fs_close", Fs);
    Operation::FsDup { .. } => ("fs_dup", Fs);
    Operation::FsSeek { .. } => ("fs_seek", Fs);
    Operation::FsMetadata { .. } => ("fs_metadata", Fs);
    Operation::FsFdMetadata { .. } => ("fs_fd_metadata", Fs);
    Operation::FsInodeMetadata { .. } => ("fs_inode_metadata", Fs);
    Operation::FsCreateDirectory { .. } => ("fs_create_directory", Fs);
    Operation::FsRemoveFile { .. } => ("fs_remove_file", Fs);
    Operation::FsSetInodeMode { .. } => ("fs_set_inode_mode", Fs);
    Operation::FsRetainInode { .. } => ("fs_retain_inode", Fs);
    Operation::FsReleaseInode { .. } => ("fs_release_inode", Fs);
    Operation::FsSync { .. } => ("fs_sync", Fs);
    Operation::FsSetLength { .. } => ("fs_set_length", Fs);
    Operation::FsSetLengthByPath { .. } => ("fs_set_length_by_path", Fs);
    Operation::FsAllocate { .. } => ("fs_allocate", Fs);
    Operation::FsSetTimes { .. } => ("fs_set_times", Fs);
    Operation::FsSetInodeTimes { .. } => ("fs_set_inode_times", Fs);
    Operation::FsSetTimesByPath { .. } => ("fs_set_times_by_path", Fs);
    Operation::FsReadDirectory { .. } => ("fs_read_directory", Fs);
    Operation::FsReadDirectoryFd { .. } => ("fs_read_directory_fd", Fs);
    Operation::FsRemoveDirectory { .. } => ("fs_remove_directory", Fs);
    Operation::FsRename { .. } => ("fs_rename", Fs);
    Operation::FsLink { .. } => ("fs_link", Fs);
    Operation::FsSymlink { .. } => ("fs_symlink", Fs);
    Operation::FsReadLink { .. } => ("fs_read_link", Fs);
    Operation::FsMakeFifo { .. } => ("fs_make_fifo", Fs);
    Operation::FsMakeNode { .. } => ("fs_make_node", Fs);
    Operation::FsExchange { .. } => ("fs_exchange", Fs);
    Operation::FsRenameWhiteout { .. } => ("fs_rename_whiteout", Fs);
    Operation::FsSyncAll => ("fs_sync_all", Fs);
    Operation::FsGetXattr { .. } => ("fs_get_xattr", Fs);
    Operation::FsListXattr { .. } => ("fs_list_xattr", Fs);
    Operation::FsSetXattr { .. } => ("fs_set_xattr", Fs);
    Operation::FsRemoveXattr { .. } => ("fs_remove_xattr", Fs);
    Operation::FsSetMode { .. } => ("fs_set_mode", Fs);
    Operation::FsSetFdMode { .. } => ("fs_set_fd_mode", Fs);
    Operation::FsFdPath { .. } => ("fs_fd_path", Fs);
    Operation::FsFdIno { .. } => ("fs_fd_ino", Fs);
    Operation::DnsResolve { .. } => ("dns_resolve", Net);
    Operation::FsCrash => ("fs_crash", Crash);
    Operation::TaskSpawn { .. } => ("task_spawn", Schedule);
    Operation::TaskYield { .. } => ("task_yield", Schedule);
    Operation::TaskPark { .. } => ("task_park", Schedule);
    Operation::TaskParkTimed { .. } => ("task_park_timed", Schedule);
    Operation::TaskWake { .. } => ("task_wake", Schedule);
    Operation::SignalGenerated { .. } => ("signal_generated", Schedule);
    Operation::TaskComplete { .. } => ("task_complete", Schedule);
    Operation::SchedulerNext => ("scheduler_next", Schedule);
    Operation::NetBind { .. } => ("net_bind", Net);
    Operation::NetBindShared { .. } => ("net_bind_shared", Net);
    Operation::NetConnect { .. } => ("net_connect", Net);
    Operation::NetMark { .. } => ("net_mark", Net);
    Operation::NetSend { .. } => ("net_send", Net);
    Operation::NetRecv { .. } => ("net_recv", Net);
    Operation::NetClose { .. } => ("net_close", Net);
    Operation::NetNextDelivery { .. } => ("net_next_delivery", Net);
    Operation::NetTcpListen { .. } => ("net_tcp_listen", Net);
    Operation::NetTcpAccept { .. } => ("net_tcp_accept", Net);
    Operation::NetTcpConnect { .. } => ("net_tcp_connect", Net);
    Operation::NetTcpSend { .. } => ("net_tcp_send", Net);
    Operation::NetTcpRecv { .. } => ("net_tcp_recv", Net);
    Operation::NetTcpShutdown { .. } => ("net_tcp_shutdown", Net);
    Operation::Verdict { .. } => ("verdict", Other);
    Operation::CustomOp { .. } => ("custom_op", Other);
}

pub fn valid_op_kinds() -> BTreeSet<&'static str> {
    OP_KINDS.iter().map(|(kind, _)| *kind).collect()
}

pub fn valid_category_labels() -> BTreeSet<&'static str> {
    Category::ALL.into_iter().map(Category::label).collect()
}

pub fn op_kind_category(kind: &str) -> Option<Category> {
    OP_KINDS
        .iter()
        .find_map(|(candidate, category)| (*candidate == kind).then_some(*category))
}

#[cfg(test)]
mod tests;
