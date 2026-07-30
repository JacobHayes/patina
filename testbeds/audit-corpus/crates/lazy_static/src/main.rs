
use lazy_static::lazy_static;
lazy_static! { static ref V: Vec<u32> = vec![1, 2, 3, 4]; }
fn main() { println!("{}", V.iter().sum::<u32>()); }
