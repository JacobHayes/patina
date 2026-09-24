//! The page cache of a mapped file: the pages every view of the file maps,
//! and the shadow of what the filesystem holds that tells which pages a view
//! dirtied.
//!
//! The pages of a real run are a host memfd (`Memfd`) sized to the file, so
//! a view maps exactly the kernel's shmem semantics: a page wholly past the
//! end of the file faults `SIGBUS`, and a truncation zeroes the tail of the
//! last page. The cache logic is over [`Pages`], so it is tested over a byte
//! vector.

use super::{PAGE, host};
use crate::registry::Syscall;
use std::ffi::c_int;

/// A file-sized array of bytes: bytes past its length read zero, growth
/// zero-fills, shrinking discards.
pub(super) trait Pages {
    fn read(&self, offset: u64, buf: &mut [u8]);
    fn write(&mut self, offset: u64, bytes: &[u8]);
    fn set_len(&mut self, len: u64);
    /// Zero `[from, to)`, within the length.
    fn punch(&mut self, from: u64, to: u64);
}

impl Pages for Vec<u8> {
    fn read(&self, offset: u64, buf: &mut [u8]) {
        let start = (offset as usize).min(self.len());
        let end = start.saturating_add(buf.len()).min(self.len());
        buf.fill(0);
        buf[..end - start].copy_from_slice(&self[start..end]);
    }

    fn write(&mut self, offset: u64, bytes: &[u8]) {
        let start = offset as usize;
        let end = start + bytes.len();
        if self.len() < end {
            self.resize(end, 0);
        }
        self[start..end].copy_from_slice(bytes);
    }

    fn set_len(&mut self, len: u64) {
        self.resize(len as usize, 0);
    }

    fn punch(&mut self, from: u64, to: u64) {
        let end = (to as usize).min(self.len());
        let start = (from as usize).min(end);
        self[start..end].fill(0);
    }
}

/// A host memfd: anonymous shmem the shim owns, which views map.
pub(super) struct Memfd {
    pub(super) fd: c_int,
}

const FALLOC_FL_KEEP_SIZE: usize = 0x01;
const FALLOC_FL_PUNCH_HOLE: usize = 0x02;
const MFD_CLOEXEC: usize = 0x1;

impl Memfd {
    /// A new, empty memfd. The host refusing one (its descriptor limit, which
    /// `__libc_start_main` raised to the hard limit, or its memory) is the
    /// shim's failure, never the guest's errno: the kernel being modeled
    /// would have succeeded.
    pub(super) fn new() -> Memfd {
        let fd = host(
            Syscall::N_memfd_create,
            [
                c"patina-page-cache".as_ptr() as usize,
                MFD_CLOEXEC,
                0,
                0,
                0,
                0,
            ],
        );
        if fd < 0 {
            crate::trap_fatal(&format!(
                "the host refused a memfd for guest memory (errno {}): every mapped file and \
                 System V segment holds one host descriptor, and the host's RLIMIT_NOFILE hard \
                 limit or memory is exhausted",
                -fd
            ));
        }
        Memfd { fd: fd as c_int }
    }

    /// The host refused shim memory: nothing the guest did can be answered.
    fn refused(what: &str, result: i64) -> ! {
        crate::trap_fatal(&format!(
            "the page cache's host memfd refused {what} (errno {}); the page cache cannot hold \
             the file",
            -result
        ))
    }
}

impl Pages for Memfd {
    fn read(&self, offset: u64, buf: &mut [u8]) {
        let mut done = 0;
        while done < buf.len() {
            let got = host(
                Syscall::N_pread64,
                [
                    self.fd as usize,
                    buf[done..].as_mut_ptr() as usize,
                    buf.len() - done,
                    (offset + done as u64) as usize,
                    0,
                    0,
                ],
            );
            if got < 0 {
                Self::refused("a read", got);
            }
            if got == 0 {
                buf[done..].fill(0);
                return;
            }
            done += got as usize;
        }
    }

    fn write(&mut self, offset: u64, bytes: &[u8]) {
        let mut done = 0;
        while done < bytes.len() {
            let put = host(
                Syscall::N_pwrite64,
                [
                    self.fd as usize,
                    bytes[done..].as_ptr() as usize,
                    bytes.len() - done,
                    (offset + done as u64) as usize,
                    0,
                    0,
                ],
            );
            if put <= 0 {
                Self::refused("a write", put);
            }
            done += put as usize;
        }
    }

    fn set_len(&mut self, len: u64) {
        let result = host(
            Syscall::N_ftruncate,
            [self.fd as usize, len as usize, 0, 0, 0, 0],
        );
        if result < 0 {
            Self::refused("a resize", result);
        }
    }

    fn punch(&mut self, from: u64, to: u64) {
        if from >= to {
            return;
        }
        let result = host(
            Syscall::N_fallocate,
            [
                self.fd as usize,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                from as usize,
                (to - from) as usize,
                0,
                0,
            ],
        );
        if result < 0 {
            Self::refused("a hole punch", result);
        }
    }
}

impl Drop for Memfd {
    fn drop(&mut self) {
        host(Syscall::N_close, [self.fd as usize, 0, 0, 0, 0, 0]);
    }
}

pub(super) struct Cache<P: Pages> {
    pub(super) pages: P,
    /// The file's size, as the filesystem last reported it through a
    /// mirrored operation.
    size: u64,
    /// What the filesystem holds for `[0, size)`, while a view that may write
    /// is live: the pages that differ from it are the dirty ones.
    shadow: Option<Vec<u8>>,
}

impl<P: Pages> Cache<P> {
    /// A cache over `pages` holding the file's `contents`.
    pub(super) fn new(mut pages: P, contents: &[u8]) -> Self {
        pages.set_len(contents.len() as u64);
        pages.write(0, contents);
        Cache {
            pages,
            size: contents.len() as u64,
            shadow: None,
        }
    }

    pub(super) fn size(&self) -> u64 {
        self.size
    }

    fn snapshot(&self) -> Vec<u8> {
        let mut bytes = vec![0; self.size as usize];
        self.pages.read(0, &mut bytes);
        bytes
    }

    /// Keep a shadow (a view that may write is live) or drop it.
    pub(super) fn track(&mut self, on: bool) {
        match (on, self.shadow.is_some()) {
            (true, false) => self.shadow = Some(self.snapshot()),
            (false, true) => self.shadow = None,
            _ => {}
        }
    }

    /// The filesystem accepted `bytes` at `offset`: a gap past the old size
    /// reads zero, as the filesystem's hole does.
    pub(super) fn store(&mut self, offset: u64, bytes: &[u8]) {
        let end = offset + bytes.len() as u64;
        if end > self.size {
            self.resize(end);
        }
        self.pages.write(offset, bytes);
        self.accept(offset, bytes);
    }

    /// The file is now `len` bytes long.
    pub(super) fn resize(&mut self, len: u64) {
        self.pages.set_len(len);
        self.size = len;
        if let Some(shadow) = &mut self.shadow {
            shadow.resize(len as usize, 0);
        }
    }

    /// The filesystem zeroed `[from, to)` (clipped to the file).
    pub(super) fn zero(&mut self, from: u64, to: u64) {
        let to = to.min(self.size);
        if from >= to {
            return;
        }
        self.pages.punch(from, to);
        if let Some(shadow) = &mut self.shadow {
            shadow[from as usize..to as usize].fill(0);
        }
    }

    /// The whole pages the views changed since the filesystem last held
    /// them, each clipped to the file: what a write-back writes.
    pub(super) fn dirty_pages(&self) -> Vec<(u64, Vec<u8>)> {
        let Some(shadow) = &self.shadow else {
            return Vec::new();
        };
        let current = self.snapshot();
        current
            .chunks(PAGE)
            .zip(shadow.chunks(PAGE))
            .enumerate()
            .filter(|(_, (now, then))| now != then)
            .map(|(index, (now, _))| ((index * PAGE) as u64, now.to_vec()))
            .collect()
    }

    /// The filesystem now holds `bytes` at `offset`.
    pub(super) fn accept(&mut self, offset: u64, bytes: &[u8]) {
        if let Some(shadow) = &mut self.shadow {
            let start = (offset as usize).min(shadow.len());
            let end = start.saturating_add(bytes.len()).min(shadow.len());
            shadow[start..end].copy_from_slice(&bytes[..end - start]);
        }
    }

    /// The filesystem rolled back: the cache holds `contents` now, and
    /// nothing is dirty.
    pub(super) fn reload(&mut self, contents: &[u8]) {
        self.resize(0);
        self.resize(contents.len() as u64);
        self.pages.write(0, contents);
        if let Some(shadow) = &mut self.shadow {
            shadow.copy_from_slice(contents);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache(contents: &[u8]) -> Cache<Vec<u8>> {
        Cache::new(Vec::new(), contents)
    }

    #[test]
    fn a_store_past_the_end_grows_the_file_over_a_zero_gap() {
        let mut cache = cache(b"abc");
        cache.store(10, b"xy");
        assert_eq!(cache.size(), 12);
        assert_eq!(cache.pages, b"abc\0\0\0\0\0\0\0xy");
    }

    #[test]
    fn shrinking_discards_and_regrowing_reads_zero() {
        let mut cache = cache(&[7; 3 * PAGE]);
        cache.resize(PAGE as u64 + 10);
        cache.resize(2 * PAGE as u64);
        assert!(cache.pages[..PAGE + 10].iter().all(|byte| *byte == 7));
        assert!(cache.pages[PAGE + 10..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn only_the_pages_a_view_changed_are_dirty_whole_and_clipped() {
        let mut cache = cache(&[1; 2 * PAGE + 100]);
        assert!(cache.dirty_pages().is_empty(), "no shadow, nothing tracked");
        cache.track(true);
        assert!(cache.dirty_pages().is_empty());
        // A view's store: the pages change behind the shadow.
        cache.pages[5] = 9;
        cache.pages[2 * PAGE + 50] = 9;
        let dirty = cache.dirty_pages();
        assert_eq!(dirty.len(), 2);
        assert_eq!((dirty[0].0, dirty[0].1.len(), dirty[0].1[5]), (0, PAGE, 9));
        assert_eq!((dirty[1].0, dirty[1].1.len()), (2 * PAGE as u64, 100));
        // Written back: clean again.
        for (offset, bytes) in &dirty {
            cache.accept(*offset, bytes);
        }
        assert!(cache.dirty_pages().is_empty());
    }

    #[test]
    fn a_mirrored_write_over_a_dirty_range_wins_and_leaves_it_clean() {
        let mut cache = cache(&[1; PAGE]);
        cache.track(true);
        cache.pages[0] = 9;
        cache.store(0, &[3]);
        assert_eq!(cache.pages[0], 3);
        assert!(cache.dirty_pages().is_empty());
    }

    #[test]
    fn zeroing_and_resizing_keep_the_shadow_in_step() {
        let mut cache = cache(&[1; 2 * PAGE]);
        cache.track(true);
        cache.zero(10, 20);
        cache.zero(PAGE as u64, 3 * PAGE as u64);
        assert!(cache.pages[10..20].iter().all(|byte| *byte == 0));
        assert!(cache.pages[PAGE..].iter().all(|byte| *byte == 0));
        cache.resize(PAGE as u64 / 2);
        cache.resize(PAGE as u64);
        assert!(cache.dirty_pages().is_empty());
    }

    #[test]
    fn a_reload_replaces_the_contents_and_cleans_the_shadow() {
        let mut cache = cache(b"stored!");
        cache.track(true);
        cache.pages[0] = b'X';
        cache.reload(b"durable+");
        assert_eq!(cache.pages, b"durable+");
        assert_eq!(cache.size(), 8);
        assert!(cache.dirty_pages().is_empty());
    }
}
