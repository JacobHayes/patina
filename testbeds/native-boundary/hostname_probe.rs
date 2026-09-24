// The virtual machine's node name as an ordinary program reads it, through both
// doors: `gethostname` and `uname`'s `nodename`. Both answer the run's
// configured name (Patina's default, or `run --hostname`), and they agree.
// Beside it, the rest of the virtual kernel's self-description: `uname`'s
// system name, release and machine.
use std::ffi::{CStr, c_char};

fn main() {
    let mut buffer = [0 as c_char; 256];
    if unsafe { gethostname(buffer.as_mut_ptr(), buffer.len()) } != 0 {
        std::process::exit(20);
    }
    let Ok(hostname) = unsafe { CStr::from_ptr(buffer.as_ptr()) }.to_str() else {
        std::process::exit(21);
    };
    let mut name = std::mem::MaybeUninit::<Utsname>::zeroed();
    if unsafe { uname(name.as_mut_ptr()) } != 0 {
        std::process::exit(22);
    }
    let name = unsafe { name.assume_init() };
    let field = |field: &[c_char; UTS_FIELD]| {
        unsafe { CStr::from_ptr(field.as_ptr()) }
            .to_str()
            .unwrap_or_else(|_| std::process::exit(23))
    };
    let nodename = field(&name.nodename);
    if hostname != nodename {
        std::process::exit(24);
    }
    let (sysname, release, machine) = (
        field(&name.sysname),
        field(&name.release),
        field(&name.machine),
    );
    println!(
        "NATIVE_HOSTNAME_RESULT hostname={hostname} nodename={nodename} \
sysname={sysname} release={release} machine={machine}"
    );
}

/// `struct utsname`: five (Linux: six, with `domainname`) fixed-size fields.
/// Linux uses 65 bytes per field (`__NEW_UTS_LEN + 1`); Darwin uses 256.
#[cfg(target_os = "linux")]
const UTS_FIELD: usize = 65;
#[cfg(target_os = "macos")]
const UTS_FIELD: usize = 256;

#[repr(C)]
struct Utsname {
    sysname: [c_char; UTS_FIELD],
    nodename: [c_char; UTS_FIELD],
    release: [c_char; UTS_FIELD],
    version: [c_char; UTS_FIELD],
    machine: [c_char; UTS_FIELD],
    #[cfg(target_os = "linux")]
    domainname: [c_char; UTS_FIELD],
}

unsafe extern "C" {
    fn gethostname(name: *mut c_char, len: usize) -> i32;
    fn uname(buf: *mut Utsname) -> i32;
}
