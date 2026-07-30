
fn main() {
    let pid = unsafe { libc::getpid() };
    let mut tv = libc::timeval { tv_sec: 0, tv_usec: 0 };
    unsafe { libc::gettimeofday(&mut tv, std::ptr::null_mut()); }
    println!("{} {}", pid, tv.tv_sec != 0);
}
