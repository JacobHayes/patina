//! Each node's work tree, its disk, as the supervisor reaches it: the driver's at its path in
//! the supervisor's own view; another node's through the root of the node's first process
//! (`/proc/PID/root` + its work path), opened when that process says `Hello` and held for the
//! run (the descriptor keeps the node's tmpfs reachable after its processes are gone).
//!
//! Every node's records share one operation log, each tagged with its node
//! (`proto::oplog::tag_kind`); the launcher splits it into one log per node. A node's base
//! records are written when its disk is first reached, before its first process runs.

use proto::node::MAX_NODES;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

pub struct Disks {
    /// The driver's work tree.
    work: PathBuf,
    /// Each other node's work tree (`O_PATH`) and its device, once reached.
    root: Vec<Option<(OwnedFd, u64)>>,
}

impl Disks {
    pub fn new(work: PathBuf) -> Disks {
        Disks {
            work,
            root: (0..MAX_NODES).map(|_| None).collect(),
        }
    }

    /// Reach node `node`'s work tree `work` through its process `pid`.
    pub fn open(&mut self, node: usize, pid: i32, work: &[u8]) -> Result<(), String> {
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
        if let Some(r) = self.root.get_mut(node) {
            *r = Some((fd, st.st_dev));
        }
        Ok(())
    }

    /// Node `node`'s disk is gone (its machine crashed): its next boot reaches a new one.
    pub fn close(&mut self, node: usize) {
        if let Some(r) = self.root.get_mut(node) {
            *r = None;
        }
    }

    /// The path of node `node`'s work tree, if it was reached.
    pub fn path(&self, node: usize) -> Option<PathBuf> {
        match node {
            0 => Some(self.work.clone()),
            // The directory itself, not the descriptor's link (which `lstat` would describe).
            k => self
                .root
                .get(k)?
                .as_ref()
                .map(|(fd, _)| PathBuf::from(format!("/proc/self/fd/{}/.", fd.as_raw_fd()))),
        }
    }

    /// Node `node`'s work device.
    pub fn dev(&self, node: usize) -> Result<u64, String> {
        match node {
            0 => std::fs::metadata(&self.work)
                .map(|m| m.dev())
                .map_err(|e| format!("{}: {e}", self.work.display())),
            k => self
                .root
                .get(k)
                .and_then(|r| r.as_ref())
                .map(|(_, d)| *d)
                .ok_or_else(|| format!("node {k}: its work tree was not reached")),
        }
    }

    /// Every reached work device and its node (the driver's first, when it can be read).
    pub fn devs(&self) -> Vec<(u64, usize)> {
        let mut v: Vec<(u64, usize)> = self.dev(0).ok().map(|d| (d, 0)).into_iter().collect();
        for (k, r) in self.root.iter().enumerate() {
            if let Some((_, d)) = r {
                v.push((*d, k));
            }
        }
        v
    }

    /// The nodes whose work trees were reached besides the driver's, in order.
    pub fn nodes(&self) -> Vec<usize> {
        (1..MAX_NODES).filter(|&k| self.root[k].is_some()).collect()
    }
}
