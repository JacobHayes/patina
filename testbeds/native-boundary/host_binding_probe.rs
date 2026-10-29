//! The sealed engine's host bindings are bound before `main`: each argument
//! is a binding's slot, as its offset from `PATINA_BINDING_ANCHOR` (the test
//! reads both from the binary's symbols), and the guest reads every slot
//! before anything else and prints the arguments' indices of those still
//! empty.

#[used]
#[unsafe(no_mangle)]
static PATINA_BINDING_ANCHOR: u8 = 0;

fn main() {
    let anchor = std::ptr::addr_of!(PATINA_BINDING_ANCHOR) as usize;
    let offsets: Vec<isize> = std::env::args()
        .skip(1)
        .map(|offset| offset.parse().expect("a slot offset"))
        .collect();
    // Read them all before any output, which goes through bindings of its own.
    let empty: Vec<String> = offsets
        .iter()
        .enumerate()
        // SAFETY: the offset is a slot's, a word of the engine's data.
        .filter(|(_, offset)| unsafe {
            (anchor.wrapping_add_signed(**offset) as *const usize).read_volatile() == 0
        })
        .map(|(index, _)| index.to_string())
        .collect();
    println!("EMPTY_SLOTS={}", empty.join(","));
}
