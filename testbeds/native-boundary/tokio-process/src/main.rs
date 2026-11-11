// tokio::process spawning this program again: `output()` of a child that
// writes both streams and exits 3, then an interactive child driven through
// piped stdin and stdout, reaped by `wait()`. The current-thread runtime
// reaps through its signal driver: tokio asks for a process descriptor
// (`pidfd_open`) first and, refused one, waits for SIGCHLD instead.
use std::io::{BufRead, Write};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

async fn drive(binary: &str) -> String {
    let output = Command::new(binary).arg("speak").output().await.unwrap();
    let mut child = Command::new(binary)
        .arg("upper")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut answers = Vec::new();
    for word in ["tokio", "process"] {
        input.write_all(format!("{word}\n").as_bytes()).await.unwrap();
        input.flush().await.unwrap();
        answers.push(lines.next_line().await.unwrap().unwrap());
    }
    drop(input);
    let rest = lines.next_line().await.unwrap();
    let status = child.wait().await.unwrap();
    format!(
        "NATIVE_TOKIO_PROCESS_RESULT output={:?}/{:?}/{:?} answers={} rest={rest:?} code={:?}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        answers.join(","),
        status.code()
    )
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["speak"] => {
            print!("to-stdout");
            eprint!("to-stderr");
            std::process::exit(3);
        }
        ["upper"] => {
            for line in std::io::stdin().lock().lines() {
                let mut out = std::io::stdout().lock();
                writeln!(out, "{}", line.unwrap().to_uppercase()).unwrap();
                out.flush().unwrap();
            }
        }
        [binary] => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            println!("{}", runtime.block_on(drive(binary)));
        }
        _ => panic!("unexpected arguments {args:?}"),
    }
}
