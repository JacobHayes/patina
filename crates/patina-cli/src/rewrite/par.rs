//! Work inside one plan on several threads. Every use is a pure function of its part of the
//! input, merged in input order, so a plan is the same bytes on any number of threads: one
//! thread runs each part in order, which is the sequential algorithm itself.

use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// How many threads plans may use at once, shared by every clone: the thread that calls in
/// works, and up to `threads - 1` more join it while that many are free. Workers run on `cpus`
/// rather than on the CPU of the thread that starts them (the plan broker's thread is pinned
/// to the run's CPU).
#[derive(Clone, Debug)]
pub struct Par {
    threads: usize,
    spare: Arc<AtomicUsize>,
    cpus: Option<Arc<Vec<usize>>>,
}

impl Par {
    pub fn new(threads: usize) -> Par {
        let threads = threads.max(1);
        Par {
            threads,
            spare: Arc::new(AtomicUsize::new(threads - 1)),
            cpus: None,
        }
    }

    /// One thread: the sequential order.
    #[cfg(test)]
    pub fn one() -> Par {
        Par::new(1)
    }

    pub fn on(mut self, cpus: Vec<usize>) -> Par {
        self.cpus = Some(Arc::new(cpus)).filter(|c| !c.is_empty());
        self
    }

    pub fn threads(&self) -> usize {
        self.threads
    }

    /// Up to `n` of the spare threads.
    fn take(&self, n: usize) -> usize {
        let mut cur = self.spare.load(Ordering::Relaxed);
        loop {
            let k = cur.min(n);
            if k == 0 {
                return 0;
            }
            match self
                .spare
                .compare_exchange(cur, cur - k, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => return k,
                Err(now) => cur = now,
            }
        }
    }

    fn give(&self, n: usize) {
        self.spare.fetch_add(n, Ordering::AcqRel);
    }

    fn place(&self) {
        let Some(cpus) = &self.cpus else { return };
        unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            for &c in cpus.iter() {
                libc::CPU_SET(c, &mut set);
            }
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        }
    }

    /// `[0, n)` in parts (one with one thread, else several per thread so that uneven parts
    /// balance): `f` of each part, in order.
    pub fn parts<T: Send>(&self, n: usize, f: impl Fn(Range<usize>) -> T + Sync) -> Vec<T> {
        let k = if self.threads == 1 || n < 2 {
            1
        } else {
            (self.threads * 4).min(n)
        };
        let ranges: Vec<Range<usize>> = (0..k).map(|i| n * i / k..n * (i + 1) / k).collect();
        self.each(&ranges, |_, r| f(r.clone()))
    }

    /// `f` of each item of `items` (with its index), in order.
    pub fn each<I: Sync, T: Send>(&self, items: &[I], f: impl Fn(usize, &I) -> T + Sync) -> Vec<T> {
        let extra = self.take(self.threads.min(items.len()).saturating_sub(1));
        if extra == 0 {
            return items.iter().enumerate().map(|(i, x)| f(i, x)).collect();
        }
        let out: Vec<Mutex<Option<T>>> = items.iter().map(|_| Mutex::new(None)).collect();
        let next = AtomicUsize::new(0);
        let work = || loop {
            let i = next.fetch_add(1, Ordering::Relaxed);
            let Some(x) = items.get(i) else { return };
            *out[i].lock().unwrap() = Some(f(i, x));
        };
        std::thread::scope(|s| {
            for _ in 0..extra {
                // A permit taken is given back when its thread ends, or now if no thread
                // starts (the calling thread does the work).
                let permit = Permit(self);
                let _ = std::thread::Builder::new().spawn_scoped(s, || {
                    let _permit = permit;
                    self.place();
                    work();
                });
            }
            work();
        });
        out.into_iter()
            .map(|m| m.into_inner().unwrap().expect("every part ran"))
            .collect()
    }

    /// `a` and `b` at once (`b` on another thread when one is free).
    pub fn join<A: Send, B: Send>(
        &self,
        a: impl FnOnce() -> A + Send,
        b: impl FnOnce() -> B + Send,
    ) -> (A, B) {
        if self.take(1) == 0 {
            let x = a();
            return (x, b());
        }
        let b = Mutex::new(Some(b));
        let run_b = || b.lock().unwrap().take().map(|b| b());
        std::thread::scope(|s| {
            let permit = Permit(self);
            let h = std::thread::Builder::new()
                .spawn_scoped(s, || {
                    let _permit = permit;
                    self.place();
                    run_b()
                })
                .ok();
            let x = a();
            let y = match h {
                Some(h) => h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)),
                None => None,
            };
            (x, y.or_else(run_b).expect("b ran"))
        })
    }
}

/// One spare thread taken from a `Par`, given back when dropped (also on a panic).
struct Permit<'a>(&'a Par);

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.0.give(1);
    }
}
