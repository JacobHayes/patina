
use crossbeam_channel::unbounded;
fn main() {
    let (tx, rx) = unbounded();
    for i in 0..10u32 { tx.send(i).unwrap(); }
    drop(tx);
    let s: u32 = rx.iter().sum();
    println!("{}", s);
}
