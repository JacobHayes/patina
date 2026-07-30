
use time::OffsetDateTime;
fn main() {
    let t = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
    println!("{}", t.unix_timestamp());
}
