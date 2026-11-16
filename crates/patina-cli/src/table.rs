//! `patina table`: the syscall table as Markdown, generated from `proto`.

use proto::table::{known, Class};

pub fn print() {
    println!("| nr | name | class | strength | why |");
    println!("|---:|---|---|---|---|");
    for r in known() {
        let class = match r.class {
            Class::Deny(e) => format!("Deny({})", errno_name(e)),
            c => format!("{c:?}"),
        };
        println!(
            "| {} | {} | {} | {} | {} |",
            r.nr,
            r.name,
            class,
            r.strength.letter(),
            r.why.replace('|', "\\|")
        );
    }
}

fn errno_name(e: i32) -> String {
    match e {
        1 => "EPERM".into(),
        38 => "ENOSYS".into(),
        n => n.to_string(),
    }
}
