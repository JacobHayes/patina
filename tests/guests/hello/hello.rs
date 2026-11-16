// the skeleton guest (Rust std, single thread): arguments, pid, clocks, entropy, addresses, a file under /work, a listing.
use std::io::Write;
use std::os::unix::fs::{DirEntryExt, MetadataExt};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

extern "C" {
    fn getrandom(buf: *mut u8, len: usize, flags: u32) -> isize;
}

fn main() {
    let out = std::io::stdout();
    let mut o = out.lock();
    for (i, a) in std::env::args().enumerate() {
        writeln!(o, "arg {i} {a}").unwrap();
    }
    writeln!(o, "pid {}", std::process::id()).unwrap();
    let t0 = Instant::now();
    for i in 0..100 {
        let m = t0.elapsed();
        let r = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        writeln!(o, "clock {i} {}.{:09} {}.{:09}", m.as_secs(), m.subsec_nanos(), r.as_secs(), r.subsec_nanos()).unwrap();
    }
    let mut rnd = [0u8; 16];
    assert_eq!(unsafe { getrandom(rnd.as_mut_ptr(), 16, 0) }, 16);
    write!(o, "random ").unwrap();
    for b in rnd {
        write!(o, "{b:02x}").unwrap();
    }
    writeln!(o).unwrap();
    let big: Vec<u8> = Vec::with_capacity(1 << 20);
    let local = 0u32;
    writeln!(o, "malloc {:p}\nstack {:p}", big.as_ptr(), &local).unwrap();
    std::fs::write("/work/hello.txt", b"hello\n").unwrap();
    let m = std::fs::metadata("/work/hello.txt").unwrap();
    writeln!(
        o,
        "stat dev {:x} ino {} mode {:o} nlink {} size {} blocks {} atime {} mtime {} ctime {}",
        m.dev(), m.ino(), m.mode(), m.nlink(), m.size(), m.blocks(), m.atime(), m.mtime(), m.ctime()
    )
    .unwrap();
    let mut names: Vec<(String, u64)> = std::fs::read_dir("/work")
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (e.file_name().to_string_lossy().into_owned(), e.ino())
        })
        .collect();
    // read_dir order is the kernel's; print it unsorted on purpose
    for (n, ino) in names.drain(..) {
        writeln!(o, "dirent {n} {ino}").unwrap();
    }
}
