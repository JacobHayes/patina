// A Rust program reading through C stdio, as a Rust crate binding a C
// library's `FILE*` API does: `fopen` a file it wrote with std, read it with
// `fgets`, `getc`, `fread` and `getline`, then read stdin (at its end).
// `native_abi` requires the same output natively and under Patina.
use std::ffi::{CStr, CString, c_char, c_int, c_void};

type File = c_void;
unsafe extern "C" {
    fn fopen(path: *const c_char, mode: *const c_char) -> *mut File;
    fn fclose(stream: *mut File) -> c_int;
    fn fgets(buffer: *mut c_char, count: c_int, stream: *mut File) -> *mut c_char;
    fn getc(stream: *mut File) -> c_int;
    fn fread(pointer: *mut c_void, size: usize, count: usize, stream: *mut File) -> usize;
    fn getline(line: *mut *mut c_char, capacity: *mut usize, stream: *mut File) -> isize;
    fn feof(stream: *mut File) -> c_int;
    fn ferror(stream: *mut File) -> c_int;
    fn fileno(stream: *mut File) -> c_int;
    fn free(pointer: *mut c_void);
    #[cfg_attr(target_os = "macos", link_name = "__stdinp")]
    static stdin: *mut File;
}

fn lines(what: &str, stream: *mut File) {
    let mut line: *mut c_char = std::ptr::null_mut();
    let mut capacity = 0usize;
    loop {
        // SAFETY: getline's contract: a null line and zero capacity to start.
        let length = unsafe { getline(&mut line, &mut capacity, stream) };
        if length < 0 {
            break;
        }
        // SAFETY: getline NUL-terminated the line it returned.
        let text = unsafe { CStr::from_ptr(line) }.to_string_lossy();
        println!("{what} getline {length} {text:?}");
    }
    // SAFETY: the stream is open; the line is getline's malloc block.
    unsafe {
        println!("{what} feof={} ferror={}", feof(stream), ferror(stream));
        free(line.cast());
    }
}

fn main() {
    let path = std::env::temp_dir().join(format!("stdio-input-probe-{}", std::process::id()));
    std::fs::write(&path, b"first line\nsecond\nthird, no newline").unwrap();
    let c_path = CString::new(path.to_str().unwrap()).unwrap();
    // SAFETY: C strings and the streams fopen answers, each used while open.
    unsafe {
        let f = fopen(c_path.as_ptr(), c"r".as_ptr());
        assert!(!f.is_null());
        let mut buffer = [0 as c_char; 8];
        let got = fgets(buffer.as_mut_ptr(), buffer.len() as c_int, f);
        println!("fgets {:?}", CStr::from_ptr(got).to_string_lossy());
        println!("getc {}", getc(f));
        let mut bytes = [0u8; 6];
        println!("fread {}", fread(bytes.as_mut_ptr().cast(), 1, bytes.len(), f));
        println!("read {:?}", String::from_utf8_lossy(&bytes));
        lines("file", f);
        println!("fclose {}", fclose(f));
        println!("stdin fileno {}", fileno(stdin));
        println!("stdin getc {}", getc(stdin));
        lines("stdin", stdin);
    }
    std::fs::remove_file(&path).unwrap();
}
