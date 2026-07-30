
use regex::Regex;
fn main() {
    let re = Regex::new(r"(\w+)@(\w+)\.com").unwrap();
    let hit = re.captures("user@example.com").unwrap();
    println!("{}", &hit[1]);
}
