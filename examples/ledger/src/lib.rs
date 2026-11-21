/// Append `entry` to the ledger. Entries arrive in increasing order, and the ledger must keep
/// them that way. `fixed` takes the batch path without its bug.
pub fn commit(ledger: &mut Vec<u64>, entry: u64, fixed: bool) {
    // A rare path: Patina takes it on seed-chosen runs under `--faults buggify`. In an ordinary run
    // `buggify!` is always false.
    if patina_dst::buggify!("batch-commit") && !ledger.is_empty() {
        let last = ledger.len() - 1;
        ledger.push(entry);
        if !fixed {
            ledger.swap(last, last + 1); // BUG: the batch path swaps two entries
        }
    } else {
        ledger.push(entry);
    }
    patina_dst::always!(ledger.is_sorted(), "ledger-sorted", "after {entry}");
}
