#[patina_dst::test(seeds = 20, buggify)]
fn the_ledger_stays_sorted() {
    let mut ledger = Vec::new();
    for entry in 0..8 {
        ledger::commit(&mut ledger, entry);
    }
}
