use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};

fn finish(mut child: Child) -> [u8; 4] {
    let status = child.wait().expect("wait");
    assert!(status.success(), "child failed");
    status.code().expect("normal child exit").to_le_bytes()
}

fn spawn(binary: &str, job: &str) -> Child {
    Command::new(binary)
        .args(["--child", job])
        .spawn()
        .expect("spawn")
}

fn digest(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}

fn main() {
    let name = env!("CARGO_BIN_NAME");
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "--help") {
        println!("Usage: {name} EXECUTABLE DIRECTORY\nSelf-checking process workload; --child MODE is its internal worker.");
        return;
    }
    if args.first().is_some_and(|arg| arg == "--child") {
        match args.get(1).map(String::as_str) {
            Some("pass") => {}
            Some("capture") => {
                std::io::stdout().write_all(b"captured stdout").unwrap();
                std::io::stderr().write_all(b"captured stderr").unwrap();
            }
            Some("produce") => std::io::stdout()
                .write_all(b"patina-process-pipeline")
                .unwrap(),
            Some("transform") => {
                let mut data = Vec::new();
                std::io::stdin().read_to_end(&mut data).unwrap();
                assert_eq!(data, b"patina-process-pipeline");
                data.make_ascii_uppercase();
                std::io::stdout().write_all(&data).unwrap();
            }
            Some("consume") => {
                let mut data = Vec::new();
                std::io::stdin().read_to_end(&mut data).unwrap();
                assert_eq!(data, b"PATINA-PROCESS-PIPELINE");
            }
            Some(job) => {
                let (source, object) = job.split_once('=').expect("source=object");
                let mut data = std::fs::read(source).expect("read source");
                data.reverse();
                std::fs::write(object, data).expect("write derived object");
            }
            None => panic!("worker mode required"),
        }
        return;
    }
    assert_eq!(args.len(), 2, "executable and scratch directory required");
    let binary = &args[0];
    let dir = std::path::Path::new(&args[1]);
    std::fs::create_dir_all(dir).unwrap();
    let mut facts = name.as_bytes().to_vec();
    match name {
        "spawn-wait" => {
            for _ in 0..8 {
                facts.extend(finish(spawn(binary, "pass")));
            }
        }
        "fanout" => {
            let children: Vec<_> = (0..8)
                .map(|_| {
                    Command::new(binary)
                        .args(["--child", "capture"])
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()
                        .unwrap()
                })
                .collect();
            for child in children {
                let output = child.wait_with_output().expect("collect both streams");
                assert!(output.status.success());
                assert_eq!(output.stdout, b"captured stdout");
                assert_eq!(output.stderr, b"captured stderr");
                facts.extend(output.stdout);
                facts.extend(output.stderr);
            }
        }
        "pipeline" => {
            let mut producer = Command::new(binary)
                .args(["--child", "produce"])
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut transform = Command::new(binary)
                .args(["--child", "transform"])
                .stdin(producer.stdout.take().unwrap())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let consumer = Command::new(binary)
                .args(["--child", "consume"])
                .stdin(transform.stdout.take().unwrap())
                .spawn()
                .unwrap();
            facts.extend(finish(producer));
            facts.extend(finish(transform));
            facts.extend(finish(consumer));
            facts.extend(b"PATINA-PROCESS-PIPELINE");
        }
        "buildlike" => {
            for wave in 0..3 {
                let children: Vec<_> = (0..4)
                    .map(|job| {
                        let source = dir.join(format!("source-{wave}-{job}"));
                        let object = dir.join(format!("object-{wave}-{job}"));
                        let data = if wave == 0 {
                            format!("unit-{job}").into_bytes()
                        } else {
                            std::fs::read(dir.join(format!("object-{}-{job}", wave - 1))).unwrap()
                        };
                        std::fs::write(&source, data).unwrap();
                        spawn(
                            binary,
                            &format!("{}={}", source.display(), object.display()),
                        )
                    })
                    .collect();
                children
                    .into_iter()
                    .for_each(|child| facts.extend(finish(child)));
                for job in 0..4 {
                    let mut source =
                        std::fs::read(dir.join(format!("source-{wave}-{job}"))).unwrap();
                    source.reverse();
                    let object = std::fs::read(dir.join(format!("object-{wave}-{job}"))).unwrap();
                    assert_eq!(digest(&object), digest(&source));
                    facts.extend(object);
                }
            }
        }
        _ => unreachable!(),
    }
    let detail = format!("digest={:016x}", digest(&facts));
    patina_dst::verdict(patina_dst::VerdictKind::Pass, name, &detail);
    println!("MP_RESULT workload={name} {detail}");
}
