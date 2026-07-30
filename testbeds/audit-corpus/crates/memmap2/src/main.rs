
use memmap2::{MmapMut, MmapOptions};
use std::fs::OpenOptions;
use std::io::Write;
fn main() {
    let mut anon = MmapMut::map_anon(4096).unwrap();
    anon[0] = 42; std::hint::black_box(&anon);
    let path = std::env::temp_dir().join("patina_mre_mmap.bin");
    let mut f = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path).unwrap();
    f.write_all(&[1u8; 4096]).unwrap();
    let m = unsafe { MmapOptions::new().map(&f).unwrap() };
    println!("{}", m[0]);
}
