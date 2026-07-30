
use sysinfo::System;
fn main() {
    let mut s = System::new();
    s.refresh_memory();
    println!("{}", s.total_memory() > 0);
}
