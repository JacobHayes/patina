// std::fs::File::try_clone routes through the interposed fcntl(F_DUPFD_CLOEXEC)
// into the shim's descriptor table; the clone shares the open file description
// (and so the cursor) without a second driver handle.
use std::io::{Read, Seek, SeekFrom};

fn main() {
    std::fs::create_dir("/state").unwrap();
    std::fs::write("/state/value", b"abcdef").unwrap();
    let mut first = std::fs::File::open("/state/value").unwrap();
    let mut second = first.try_clone().unwrap();
    let mut head = [0u8; 3];
    first.read_exact(&mut head).unwrap();
    let mut rest = String::new();
    second.read_to_string(&mut rest).unwrap();
    second.seek(SeekFrom::Start(1)).unwrap();
    let mut mid = [0u8; 2];
    first.read_exact(&mut mid).unwrap();
    drop(first);
    drop(second);
    std::fs::remove_file("/state/value").unwrap();
    std::fs::remove_dir("/state").unwrap();
    println!(
        "NATIVE_DUP_RESULT head={} rest={rest} mid={}",
        String::from_utf8_lossy(&head),
        String::from_utf8_lossy(&mid),
    );
}
