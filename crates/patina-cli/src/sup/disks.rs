//! Each machine's disk, its disk, as the supervisor reaches it: main's at its path in
//! the supervisor's own view; another machine's through the root of the machine's first process
//! (`/proc/PID/root` + its work path), opened when that process says `Hello` and held for the
//! run (the descriptor keeps the machine's tmpfs reachable after its processes are gone).
//!
//! Every machine's records share one operation log, each tagged with its machine
//! (`proto::oplog::tag_kind`); the launcher splits it into one log per machine. A machine's base
//! records are written when its disk is first reached, before its first process runs.

use proto::machine::MAX_MACHINES;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

pub struct Disks {
    /// Main's disk.
    work: PathBuf,
    /// Each other machine's disk (`O_PATH`) and its device, once reached.
    root: Vec<Option<(OwnedFd, u64)>>,
}

impl Disks {
    pub fn new(work: PathBuf) -> Disks {
        Disks {
            work,
            root: (0..MAX_MACHINES).map(|_| None).collect(),
        }
    }

    /// Reach machine `machine`'s disk `work` through its process `pid`.
    pub fn open(&mut self, machine: usize, pid: i32, work: &[u8]) -> Result<(), String> {
        use std::os::unix::ffi::OsStrExt;
        let mut p = format!("/proc/{pid}/root").into_bytes();
        p.extend_from_slice(work);
        let path = std::path::Path::new(std::ffi::OsStr::from_bytes(&p));
        let c = std::ffi::CString::new(p.clone()).map_err(|_| "work path".to_string())?;
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(format!(
                "{}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
            return Err(format!(
                "{}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        if let Some(r) = self.root.get_mut(machine) {
            *r = Some((fd, st.st_dev));
        }
        Ok(())
    }

    /// Machine `machine`'s disk is gone (its machine crashed): its next boot reaches a new one.
    pub fn close(&mut self, machine: usize) {
        if let Some(r) = self.root.get_mut(machine) {
            *r = None;
        }
    }

    /// The path of machine `machine`'s disk, if it was reached.
    pub fn path(&self, machine: usize) -> Option<PathBuf> {
        match machine {
            0 => Some(self.work.clone()),
            // The directory itself, not the descriptor's link (which `lstat` would describe).
            k => self
                .root
                .get(k)?
                .as_ref()
                .map(|(fd, _)| PathBuf::from(format!("/proc/self/fd/{}/.", fd.as_raw_fd()))),
        }
    }

    /// Machine `machine`'s work device.
    pub fn dev(&self, machine: usize) -> Result<u64, String> {
        match machine {
            0 => std::fs::metadata(&self.work)
                .map(|m| m.dev())
                .map_err(|e| format!("{}: {e}", self.work.display())),
            k => self
                .root
                .get(k)
                .and_then(|r| r.as_ref())
                .map(|(_, d)| *d)
                .ok_or_else(|| format!("machine {k}: its disk was not reached")),
        }
    }

    /// Every reached work device and its machine (main's first, when it can be read).
    pub fn devs(&self) -> Vec<(u64, usize)> {
        let mut v: Vec<(u64, usize)> = self.dev(0).ok().map(|d| (d, 0)).into_iter().collect();
        for (k, r) in self.root.iter().enumerate() {
            if let Some((_, d)) = r {
                v.push((*d, k));
            }
        }
        v
    }

    /// The machines whose disks were reached besides main's, in order.
    pub fn machines(&self) -> Vec<usize> {
        (1..MAX_MACHINES)
            .filter(|&k| self.root[k].is_some())
            .collect()
    }
}
