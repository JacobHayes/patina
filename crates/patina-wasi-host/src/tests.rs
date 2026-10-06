//! Shared test fixtures.

use crate::abi::{
    WASI_OFLAG_CREATE, WASI_OFLAG_DIRECTORY, WASI_RIGHT_FD_READ, WASI_RIGHT_FD_WRITE,
};
use crate::fs::WasiPathOpen;
use patina_dst_runtime::{Context, RuntimeConfig};

pub(super) fn read_stdout_u64s(stdout: &[u8]) -> Vec<u64> {
    stdout
        .as_chunks::<8>()
        .0
        .iter()
        .map(|chunk| u64::from_le_bytes(*chunk))
        .collect()
}

pub(super) fn seeded_memfs(files: &[(&str, &[u8])]) -> patina_dst_fs_mem::MemFs {
    let mut fs = patina_dst_fs_mem::MemFs::new();
    for (path, bytes) in files {
        fs = fs.with_file(path, bytes.to_vec()).unwrap();
    }
    fs
}

pub(super) fn seeded_context(seed: u64, files: &[(&str, &[u8])]) -> Context {
    patina_dst_runtime::RuntimeBuilder::new(RuntimeConfig::seeded(seed))
        .with_default_drivers()
        .with_filesystem(seeded_memfs(files))
        .build()
        .unwrap()
}

pub(super) fn read_open() -> WasiPathOpen {
    WasiPathOpen {
        oflags: 0,
        rights: WASI_RIGHT_FD_READ,
        inheriting: 0,
        fdflags: 0,
        follow_symlink: true,
    }
}

pub(super) fn create_write_open() -> WasiPathOpen {
    WasiPathOpen {
        oflags: WASI_OFLAG_CREATE,
        rights: WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE,
        inheriting: 0,
        fdflags: 0,
        follow_symlink: true,
    }
}

pub(super) fn directory_open() -> WasiPathOpen {
    WasiPathOpen {
        oflags: WASI_OFLAG_DIRECTORY,
        rights: 0,
        inheriting: 0,
        fdflags: 0,
        follow_symlink: true,
    }
}
