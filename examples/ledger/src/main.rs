fn main() {
    let fixed = std::env::args().nth(1).as_deref() == Some("fixed");
    let mut ledger = Vec::new();
    for entry in 0..8 {
        ledger::commit(&mut ledger, entry, fixed);
    }
    println!("ledger: {ledger:?}");
}
