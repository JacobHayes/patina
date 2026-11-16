// Exec target in Rust: same output as exec-show.c.
use std::fs;
fn main() {
    let exe = fs::read_link("/proc/self/exe").map(|p| p.display().to_string()).unwrap_or_default();
    println!("exe={exe}");
    for (i, a) in std::env::args().enumerate() {
        println!("argv[{i}]={a}");
    }
    println!("env={}", std::env::var("EXEC_SHOW_ENV").unwrap_or_else(|_| "(unset)".into()));
    let mut fds = String::new();
    for fd in 0..64 {
        if fs::metadata(format!("/dev/fd/{fd}")).is_ok() {
            fds.push_str(&format!("{fd},"));
        }
    }
    println!("fds={fds}");
    let h = fs::metadata("/dev/fd/3000");
    println!("hidden={}", if h.is_err() { "-1,Bad file descriptor" } else { "open" });
}
