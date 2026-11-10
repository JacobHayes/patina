fn main() {
    let mut ledger = Vec::new();
    for entry in 0..8 {
        ledger::commit(&mut ledger, entry);
    }
    println!("ledger: {ledger:?}");
}
