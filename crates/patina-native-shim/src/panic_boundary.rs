//! Panic ownership follows Rust ABI entries, not panic source paths. Guest
//! callbacks temporarily suspend ownership and can still catch their panics.
use std::cell::Cell;

thread_local! {
    static IN_SHIM: Cell<bool> = const { Cell::new(false) };
}

// Only POSIX-interposed binaries need this policy. Bare prefixed-C links have
// no public abort interposer and may intentionally omit the host alias vehicle.
#[cfg(not(test))]
static POLICY_INSTALLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[must_use]
pub(crate) struct PanicScope {
    previous: bool,
    #[cfg(not(test))]
    panicking_on_entry: bool,
    // Ownership belongs to the calling host thread, never another thread.
    _thread: std::marker::PhantomData<*mut ()>,
}
impl PanicScope {
    pub(crate) fn enter() -> Self {
        Self::set(true)
    }
    pub(crate) fn suspend() -> Self {
        Self::set(false)
    }
    fn set(value: bool) -> Self {
        Self {
            previous: IN_SHIM.with(|scope| scope.replace(value)),
            #[cfg(not(test))]
            panicking_on_entry: std::thread::panicking(),
            _thread: std::marker::PhantomData,
        }
    }
}
impl Drop for PanicScope {
    fn drop(&mut self) {
        // A guest may replace the process-global hook. Unwinding out of shim
        // code still cannot publish a successful trace through std's abort.
        #[cfg(not(test))]
        if POLICY_INSTALLED.load(std::sync::atomic::Ordering::Acquire)
            && in_shim()
            && !self.panicking_on_entry
            && std::thread::panicking()
        {
            let _ = crate::host_write_all(
                2,
                b"patina native shim panic: unwinding an owned boundary\n",
            );
            crate::host_abort();
        }
        IN_SHIM.with(|scope| scope.set(self.previous));
    }
}

pub(crate) fn in_shim() -> bool {
    IN_SHIM.with(Cell::get)
}

// The library test harness owns its hook and deliberately catches test panics.
#[cfg(test)]
pub(crate) fn install() {}

#[cfg(not(test))]
pub(crate) fn install() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        // Resolve before installing a hook that needs these private vehicles.
        let _ = crate::hostapi::get();
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !in_shim() && !crate::in_shim_critical() {
                previous(info);
                return;
            }
            use std::fmt::Write;
            struct HostDiagnostic;
            impl Write for HostDiagnostic {
                fn write_str(&mut self, value: &str) -> std::fmt::Result {
                    let _ = crate::host_write_all(2, value.as_bytes());
                    Ok(())
                }
            }
            // Formatting writes directly to the host, without captured stdio,
            // allocation, runtime locks, or the public guest abort interposer.
            let _ = writeln!(HostDiagnostic, "patina native shim panic: {info}");
            crate::host_abort();
        }));
        POLICY_INSTALLED.store(true, std::sync::atomic::Ordering::Release);
    });
}

#[cfg(test)]
mod tests {
    // Class pairing: real-ABI panic injection in native_signals exercises the
    // fatal policy; this checks nesting/callback ownership on every platform.
    #[test]
    fn panic_scopes_restore_ownership_across_callbacks_and_threads() {
        use super::{PanicScope, in_shim};
        assert!(!in_shim());
        let outer = PanicScope::enter();
        assert!(in_shim());
        {
            let _guest = PanicScope::suspend();
            assert!(!in_shim());
            {
                let _entry = PanicScope::enter();
                assert!(in_shim());
            }
            assert!(!in_shim());
        }
        assert!(in_shim());
        std::thread::spawn(|| assert!(!in_shim())).join().unwrap();
        drop(outer);
        assert!(!in_shim());
    }

    // Class pairing: the real-ABI panic injection in native_signals. A new
    // export must not bypass panic ownership merely because no panic was tested.
    #[test]
    fn every_exported_rust_boundary_claims_panic_ownership() {
        fn inspect(path: &std::path::Path, count: &mut usize) {
            for entry in std::fs::read_dir(path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    inspect(&path, count);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    let source = std::fs::read_to_string(&path).unwrap();
                    for entry in source.split("#[unsafe(no_mangle)]").skip(1) {
                        let Some((signature, body)) = entry.split_once('{') else {
                            continue;
                        };
                        if !signature.contains("extern \"C\" fn patina_") {
                            continue;
                        }
                        let name = signature
                            .split("fn ")
                            .nth(1)
                            .unwrap()
                            .split('(')
                            .next()
                            .unwrap();
                        let first = body.split(';').next().unwrap();
                        if name == "patina_abort" {
                            assert!(
                                first.contains("panic_boundary::in_shim()"),
                                "guest abort inspects caller ownership first"
                            );
                        } else {
                            assert!(
                                first.contains(
                                    "let _panic_scope = crate::panic_boundary::PanicScope::enter()"
                                ),
                                "{}: {name} lacks entry panic ownership",
                                path.display()
                            );
                        }
                        *count += 1;
                    }
                }
            }
        }
        let mut count = 0;
        inspect(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut count,
        );
        assert!(count > 180, "export scan must not become vacuous");
    }
}
