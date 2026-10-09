//! A guest that registers its own `.preinit_array` entry. Within that array
//! entries run in link order, and the guest's objects precede the shim's, so
//! this would run before the shim armed its containment: the pre-run audit
//! refuses the binary (`early-init`).
#[cfg(target_os = "linux")]
extern "C" fn guest_preinit(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) {}

#[cfg(target_os = "linux")]
#[used]
#[unsafe(link_section = ".preinit_array")]
static GUEST_PREINIT: extern "C" fn(i32, *const *const u8, *const *const u8) = guest_preinit;

fn main() {
    println!("PREINIT_ENTRY_RAN");
}
