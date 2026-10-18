//! The address layout the supervisor promised: the guest's image was exec'd
//! with address-space randomization off, or the operator accepted the host's
//! randomized layout by name. The host is asked, not trusted — Darwin can
//! drop the spawn attribute, and a persona a set-id exec clears is gone — so a
//! run that was promised a fixed layout and did not get one stops at startup,
//! by name, instead of running with addresses no seed decides. On Linux a fixed
//! layout also needs the runtime's allocations off the guest's heap
//! (`arena.rs`), so a binary linked without the allocator routing stops the
//! same way.

use patina_dst_runtime::{ENV_ADDRESS_LAYOUT, RuntimeError};

/// The layout the supervisor exec'd the guest with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Layout {
    /// Randomization off: the supervisor promised a fixed layout.
    Fixed,
    /// Randomization left on by `--allow-randomized-address-layout`.
    Randomized,
}

/// The supervisor's promise, or `None` for a standalone launch.
fn promised() -> Result<Option<Layout>, RuntimeError> {
    match crate::control_env(ENV_ADDRESS_LAYOUT).as_deref() {
        None => Ok(None),
        Some("fixed") => Ok(Some(Layout::Fixed)),
        Some("randomized") => Ok(Some(Layout::Randomized)),
        Some(other) => Err(RuntimeError::Config(format!(
            "{ENV_ADDRESS_LAYOUT}={other:?} is neither `fixed` nor `randomized`"
        ))),
    }
}

/// Refuse the run if the supervisor promised a fixed layout and the host did
/// not apply it, or (on Linux) the runtime's allocations would land on the
/// guest's heap.
pub(crate) fn verify() -> Result<(), RuntimeError> {
    if promised()? != Some(Layout::Fixed) {
        return Ok(());
    }
    if !fixed() {
        return Err(RuntimeError::Config(format!(
            "the supervisor exec'd this guest with address-space randomization off \
({ENV_ADDRESS_LAYOUT}=fixed), but the host randomized its layout anyway, so its addresses would \
not be a function of the seed. Pass --allow-randomized-address-layout to run with the host's \
layout and qualified determinism"
        )));
    }
    #[cfg(target_os = "linux")]
    if !crate::arena::routed() {
        return Err(RuntimeError::Config(
            "the runtime's allocations reach the guest's heap: this binary was linked without \
Patina's allocator routing (`cargo patina build` links it), so its heap addresses would differ \
between a seeded run, a recording and its replay"
                .to_owned(),
        ));
    }
    Ok(())
}

/// The run's address layout, shaped for `RunMetadata::address_layout`:
/// what the supervisor exec'd the guest with, or `None` for a standalone
/// launch.
pub(crate) fn recorded() -> Result<Option<patina_dst_trace::AddressLayout>, RuntimeError> {
    Ok(promised()?.map(|layout| match layout {
        Layout::Fixed => patina_dst_trace::AddressLayout::Fixed,
        Layout::Randomized => patina_dst_trace::AddressLayout::Randomized,
    }))
}

/// The process persona carries `ADDR_NO_RANDOMIZE`, which the kernel read
/// when it laid out this image.
#[cfg(target_os = "linux")]
pub(crate) fn fixed() -> bool {
    const ADDR_NO_RANDOMIZE: std::ffi::c_long = 0x0040000;
    const QUERY: std::ffi::c_long = 0xffff_ffff;
    let personality = patina_dst_syscalls::Syscall::N_personality.number();
    // SAFETY: the query persona reads this thread's persona and changes nothing.
    let persona = unsafe {
        crate::sud_host_syscall(std::ffi::c_long::from(personality), QUERY, 0, 0, 0, 0, 0)
    };
    persona != -1 && persona & ADDR_NO_RANDOMIZE != 0
}

/// The main executable, image 0, loaded at the address it was linked for.
#[cfg(target_os = "macos")]
fn fixed() -> bool {
    unsafe extern "C" {
        fn _dyld_get_image_vmaddr_slide(image_index: u32) -> isize;
    }
    // SAFETY: image 0 is always the main executable.
    unsafe { _dyld_get_image_vmaddr_slide(0) == 0 }
}
