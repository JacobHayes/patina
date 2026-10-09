//! One hot-path class per invocation; setup stays outside the fixed-work loop.
use super::Digest;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;

pub fn run(class: &str, iters: u64, dir: Option<&Path>) -> Result<(u64, u64), String> {
    let mut digest = Digest::new();
    let mut step = |i| digest.word(i);
    let calls = match class {
        "sync" => {
            for i in 0..iters {
                // SAFETY: getpid has no arguments or memory preconditions. Do
                // not hash the host PID: identity is deliberately virtualized.
                if unsafe { libc::getpid() } <= 0 {
                    return Err("invalid process identity".into());
                }
                step(i);
            }
            1
        }
        "clock" => {
            let mut previous = 0;
            for i in 0..iters {
                let mut time = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                };
                // SAFETY: time is a writable timespec.
                if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
                    return Err("clock read failed".into());
                }
                let now = i128::from(time.tv_sec) * 1_000_000_000 + i128::from(time.tv_nsec);
                if now < previous || !(0..1_000_000_000).contains(&time.tv_nsec) {
                    return Err("non-monotonic clock".into());
                }
                previous = now;
                step(i);
            }
            1
        }
        "mutex" => {
            // SAFETY: init initializes the uninitialized storage. Only this
            // thread accesses it; every successful lock is unlocked.
            unsafe {
                let mut storage = std::mem::MaybeUninit::<libc::pthread_mutex_t>::uninit();
                let mutex = storage.as_mut_ptr();
                if libc::pthread_mutex_init(mutex, std::ptr::null()) != 0 {
                    return Err("mutex init failed".into());
                }
                for i in 0..iters {
                    if libc::pthread_mutex_lock(mutex) != 0
                        || libc::pthread_mutex_unlock(mutex) != 0
                    {
                        return Err("mutex transition failed".into());
                    }
                    step(i);
                }
                if libc::pthread_mutex_destroy(mutex) != 0 {
                    return Err("mutex destroy failed".into());
                }
            }
            2
        }
        "pipe" => {
            let (mut reader, mut writer) = super::os_pipe()?;
            for i in 0..iters {
                writer
                    .write_all(&i.to_le_bytes())
                    .map_err(|e| e.to_string())?;
                let mut word = [0; 8];
                reader.read_exact(&mut word).map_err(|e| e.to_string())?;
                if u64::from_le_bytes(word) != i {
                    return Err("pipe payload mismatch".into());
                }
                step(i);
            }
            2
        }
        "pread" => {
            let dir = dir.ok_or("cached pread needs --dir")?;
            fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            let path = dir.join("doors-cache");
            let expected = [0xa5; 4096];
            fs::write(&path, expected).map_err(|e| e.to_string())?;
            let file = File::open(&path).map_err(|e| e.to_string())?;
            let mut buffer = [0; 4096];
            // Prime the cache outside the loop.
            file.read_exact_at(&mut buffer, 0)
                .map_err(|e| e.to_string())?;
            for i in 0..iters {
                if file.read_at(&mut buffer, 0).map_err(|e| e.to_string())? != buffer.len()
                    || buffer != expected
                {
                    return Err("cached pread payload mismatch".into());
                }
                step(i);
            }
            fs::remove_file(path).map_err(|e| e.to_string())?;
            1
        }
        _ => return Err(format!("unknown doors class {class}")),
    };
    Ok((
        digest.0,
        iters.checked_mul(calls).ok_or("operation count overflow")?,
    ))
}
