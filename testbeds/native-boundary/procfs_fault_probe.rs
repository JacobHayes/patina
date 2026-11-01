//! Reads procfs as a program inspecting itself does: `/proc/self/stat` and
//! `/proc/self/status` in 64-byte reads to the end, and a listing of `/proc`.
//! For each file it prints how its open went and how many reads came back
//! short (fewer bytes than asked, with more to come); for the listing, how
//! its open went and whether it lists `self`. An open that fails prints its
//! errno and the probe goes on.
use std::fs::File;
use std::io::{self, Read};

const CHUNK: usize = 64;

fn answer(error: &io::Error) -> String {
    match error.raw_os_error() {
        Some(errno) => format!("errno{errno}"),
        None => format!("error {error}"),
    }
}

fn read_file(name: &str, path: &str) {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) => {
            println!("NATIVE_PROCFS {name} open={}", answer(&error));
            return;
        }
    };
    let mut buffer = [0u8; CHUNK];
    let (mut bytes, mut short, mut pending_short) = (0usize, 0usize, false);
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                if pending_short {
                    short += 1;
                }
                pending_short = read < CHUNK;
                bytes += read;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                println!("NATIVE_PROCFS {name} open=ok read={}", answer(&error));
                return;
            }
        }
    }
    println!(
        "NATIVE_PROCFS {name} open=ok short={short} complete={}",
        bytes > 0
    );
}

fn list() {
    match std::fs::read_dir("/proc") {
        Ok(entries) => {
            let has_self = entries
                .filter_map(Result::ok)
                .any(|entry| entry.file_name() == "self");
            println!("NATIVE_PROCFS list open=ok self={has_self}");
        }
        Err(error) => println!("NATIVE_PROCFS list open={}", answer(&error)),
    }
}

fn main() {
    read_file("stat", "/proc/self/stat");
    read_file("status", "/proc/self/status");
    list();
}
