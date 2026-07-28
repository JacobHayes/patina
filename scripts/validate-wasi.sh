#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
target_dir=${CARGO_TARGET_DIR:-$root/target}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if ! rustup target list --installed | grep -qx wasm32-wasip1; then
  echo 'validate-wasi: install the required target with: rustup target add wasm32-wasip1' >&2
  exit 2
fi

cat >"$tmp/probe.rs" <<'RS'
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[repr(C)]
struct SendVector {
    bytes: *const u8,
    len: usize,
}

#[repr(C)]
struct ReceiveVector {
    bytes: *mut u8,
    len: usize,
}

#[link(wasm_import_module = "wasi_snapshot_preview1")]
unsafe extern "C" {
    #[link_name = "random_get"]
    fn wasi_random_get(buffer: *mut u8, length: usize) -> u16;
    #[link_name = "fd_pread"]
    fn wasi_fd_pread(fd: u32, vectors: *const ReceiveVector, count: usize, offset: u64, read: *mut usize) -> u16;
    #[link_name = "fd_pwrite"]
    fn wasi_fd_pwrite(fd: u32, vectors: *const SendVector, count: usize, offset: u64, written: *mut usize) -> u16;
    #[link_name = "fd_fdstat_set_flags"]
    fn wasi_fd_fdstat_set_flags(fd: u32, flags: u16) -> u16;
    #[link_name = "fd_renumber"]
    fn wasi_fd_renumber(from: u32, to: u32) -> u16;
    #[link_name = "fd_close"]
    fn wasi_fd_close(fd: u32) -> u16;
    #[link_name = "path_symlink"]
    fn wasi_path_symlink(target: *const u8, target_len: usize, fd: u32, path: *const u8, path_len: usize) -> u16;
    #[link_name = "path_filestat_set_times"]
    fn wasi_path_filestat_set_times(
        fd: u32,
        flags: u32,
        path: *const u8,
        path_len: usize,
        atime: u64,
        mtime: u64,
        fst_flags: u16,
    ) -> u16;
}

fn main() {
    let arguments = std::env::args().collect::<Vec<_>>();
    assert_eq!(arguments.len(), 2);
    assert_eq!(arguments[1], "validation");
    assert_eq!(std::env::var("MODE").unwrap(), "test");
    let mut random = [0_u8; 16];
    let errno = unsafe { wasi_random_get(random.as_mut_ptr(), random.len()) };
    assert_eq!(errno, 0);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let started = Instant::now();
    std::thread::sleep(Duration::from_millis(5));
    std::thread::yield_now();
    let elapsed = started.elapsed();

    std::fs::create_dir("/state").unwrap();
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open("/state/value")
        .unwrap();
    file.write_all(b"patina").unwrap();
    let replacement = b"XYZ";
    let write_vector = SendVector { bytes: replacement.as_ptr(), len: replacement.len() };
    let mut positioned_written = 0;
    assert_eq!(unsafe {
        wasi_fd_pwrite(file.as_raw_fd() as u32, &write_vector, 1, 1, &mut positioned_written)
    }, 0);
    assert_eq!(positioned_written, replacement.len());
    assert_eq!(file.stream_position().unwrap(), 6);
    let mut positioned = [0_u8; 6];
    let read_vector = ReceiveVector { bytes: positioned.as_mut_ptr(), len: positioned.len() };
    let mut positioned_read = 0;
    assert_eq!(unsafe {
        wasi_fd_pread(file.as_raw_fd() as u32, &read_vector, 1, 0, &mut positioned_read)
    }, 0);
    assert_eq!(positioned_read, positioned.len());
    assert_eq!(&positioned, b"pXYZna");
    assert_eq!(file.stream_position().unwrap(), 6);
    let raw_fd = file.as_raw_fd() as u32;
    assert_eq!(unsafe { wasi_fd_fdstat_set_flags(raw_fd, 1) }, 0);
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(b"!").unwrap();
    let mut appended = [0_u8; 7];
    let appended_vector = ReceiveVector { bytes: appended.as_mut_ptr(), len: appended.len() };
    let mut appended_read = 0;
    assert_eq!(unsafe {
        wasi_fd_pread(raw_fd, &appended_vector, 1, 0, &mut appended_read)
    }, 0);
    assert_eq!(appended_read, appended.len());
    assert_eq!(&appended, b"pXYZna!");
    assert_eq!(unsafe { wasi_fd_renumber(raw_fd, 10) }, 0);
    std::mem::forget(file);
    let mut contents = [0_u8; 7];
    let contents_vector = ReceiveVector { bytes: contents.as_mut_ptr(), len: contents.len() };
    let mut contents_read = 0;
    assert_eq!(unsafe {
        wasi_fd_pread(10, &contents_vector, 1, 0, &mut contents_read)
    }, 0);
    assert_eq!(contents_read, contents.len());
    assert_eq!(&contents, b"pXYZna!");
    assert_eq!(unsafe { wasi_fd_close(10) }, 0);
    std::fs::hard_link("/state/value", "/state/hard").unwrap();
    assert_eq!(std::fs::read("/state/hard").unwrap(), b"pXYZna!");
    let symlink_target = b"../missing";
    let symlink_path = b"state/symlink";
    assert_eq!(unsafe {
        wasi_path_symlink(
            symlink_target.as_ptr(),
            symlink_target.len(),
            3,
            symlink_path.as_ptr(),
            symlink_path.len(),
        )
    }, 0);
    assert_eq!(std::fs::read_link("/state/symlink").unwrap(), std::path::Path::new("../missing"));
    let path = b"state/value";
    assert_eq!(unsafe {
        wasi_path_filestat_set_times(3, 0, path.as_ptr(), path.len(), 0, 55, 4)
    }, 0);
    std::fs::OpenOptions::new()
        .write(true)
        .open("/state/value")
        .unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_nanos(66))
        .unwrap();
    std::fs::remove_file("/state/symlink").unwrap();
    std::fs::remove_file("/state/hard").unwrap();
    std::fs::rename("/state/value", "/state/renamed").unwrap();
    let entries = std::fs::read_dir("/state").unwrap().count();
    let length = std::fs::metadata("/state/renamed").unwrap().len();
    std::fs::remove_file("/state/renamed").unwrap();
    std::fs::remove_dir("/state").unwrap();

    println!(
        "WASI_RESULT random={random:02x?} time_ns={} elapsed_ns={} contents={contents:02x?} entries={entries} len={length}",
        now.as_nanos(),
        elapsed.as_nanos(),
    );
}
RS

cat >"$tmp/network.rs" <<'RS'
#[repr(C)]
struct SendVector {
    bytes: *const u8,
    len: usize,
}

#[repr(C)]
struct ReceiveVector {
    bytes: *mut u8,
    len: usize,
}

#[link(wasm_import_module = "wasi_snapshot_preview1")]
unsafe extern "C" {
    #[link_name = "sock_send"]
    fn wasi_sock_send(fd: u32, vectors: *const SendVector, count: usize, flags: u16, written: *mut usize) -> u16;
    #[link_name = "sock_recv"]
    fn wasi_sock_recv(fd: u32, vectors: *const ReceiveVector, count: usize, flags: u16, read: *mut usize, result_flags: *mut u16) -> u16;
}

fn main() {
    let message = b"network";
    let send = SendVector { bytes: message.as_ptr(), len: message.len() };
    let mut written = 0;
    assert_eq!(unsafe { wasi_sock_send(4, &send, 1, 0, &mut written) }, 0);
    assert_eq!(written, message.len());
    let mut bytes = [0_u8; 16];
    let receive = ReceiveVector { bytes: bytes.as_mut_ptr(), len: bytes.len() };
    let mut read = 0;
    let mut flags = 0;
    assert_eq!(unsafe { wasi_sock_recv(5, &receive, 1, 0, &mut read, &mut flags) }, 0);
    assert_eq!(&bytes[..read], message);
    assert_eq!(flags, 0);
    println!("WASI_NETWORK_RESULT bytes={:?}", &bytes[..read]);
}
RS

rustc --edition 2024 --target wasm32-wasip1 "$tmp/probe.rs" -o "$tmp/probe.wasm"
rustc --edition 2024 --target wasm32-wasip1 "$tmp/network.rs" -o "$tmp/network.wasm"
cargo build --locked --manifest-path "$root/Cargo.toml" -p cargo-patina >/dev/null
runner="$target_dir/debug/cargo-patina"
guest=(--arg validation --env MODE=test)
"$runner" audit "$tmp/probe.wasm" >"$tmp/imports"
"$runner" run "$tmp/probe.wasm" "${guest[@]}" --seed 123 >"$tmp/seed-1"
"$runner" run "$tmp/probe.wasm" "${guest[@]}" --seed 123 >"$tmp/seed-2"
"$runner" run "$tmp/probe.wasm" "${guest[@]}" --seed 124 >"$tmp/seed-other"
cmp "$tmp/seed-1" "$tmp/seed-2"
if cmp -s "$tmp/seed-1" "$tmp/seed-other"; then
  echo 'validate-wasi: distinct seeds produced identical output' >&2
  exit 1
fi
# The `--arg` values are the recorded guest argv (restored from the trace on
# replay); `--env` is a genuine host input (not recorded) that is re-supplied and
# verified through the compatibility fingerprint.
host=(--env MODE=test)
"$runner" run "$tmp/probe.wasm" "${guest[@]}" --seed 123 --record "$tmp/run.patina" >"$tmp/record"
# `replay <mod.wasm> <trace>` is flag-free for semantics: the seed and the `--arg`
# guest argv are restored from the trace, so `--arg` is NOT re-passed and the
# output is byte-identical to the recording. Host inputs (`--env`) are re-supplied.
"$runner" replay "$tmp/probe.wasm" "$tmp/run.patina" "${host[@]}" >"$tmp/replay"
cmp "$tmp/record" "$tmp/replay"
"$runner" replay "$tmp/probe.wasm" "$tmp/run.patina" "${host[@]}" \
  --branch --from 0 --branch-seed 124 --branch-id branch-124 >"$tmp/branch"
"$runner" replay "$tmp/probe.wasm" "$tmp/run.patina" "${host[@]}" \
  --timeline branch-124 >"$tmp/branch-replay"
cmp "$tmp/branch" "$tmp/branch-replay"
if cmp -s "$tmp/record" "$tmp/branch"; then
  echo 'validate-wasi: seeded branch did not vary the deterministic suffix' >&2
  exit 1
fi
# A conflicting re-supplied guest arg is refused up front (the trace is
# authoritative), naming the conflict.
if "$runner" replay "$tmp/probe.wasm" "$tmp/run.patina" --arg conflicting >/dev/null 2>&1; then
  echo 'validate-wasi: a conflicting replay --arg was accepted' >&2
  exit 1
fi
sockets=(--socket '4=node-a->node-b' --socket '5=node-b->node-a')
"$runner" audit "$tmp/network.wasm" >"$tmp/network-imports"
"$runner" run "$tmp/network.wasm" "${sockets[@]}" --seed 55 \
  --record "$tmp/network.patina" >"$tmp/network-record"
# The datagram sockets are genuine host inputs (not recorded), so they are
# re-supplied on replay; their match is verified through the fingerprint.
"$runner" replay "$tmp/network.wasm" "$tmp/network.patina" "${sockets[@]}" >"$tmp/network-replay"
cmp "$tmp/network-record" "$tmp/network-replay"
printf 'Validated imports:\n'
cat "$tmp/imports"
printf 'Deterministic output:\n'
cat "$tmp/replay"
cat "$tmp/network-replay"
