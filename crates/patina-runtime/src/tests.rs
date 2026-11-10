//! Tests spanning runtime modules and crate entry points.

use crate::config::RuntimeConfig;
use crate::{Context, EntropyWait, RuntimeError};
use patina_dst_abi::{ClockKind, TaskId};

use tempfile::tempdir;

/// A context over `config` whose facts documents append to `path`.
pub(super) fn with_facts_file(config: RuntimeConfig, path: &std::path::Path) -> Context {
    struct FileSink(std::path::PathBuf);
    impl crate::FactsSink for FileSink {
        fn write_facts(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            use std::io::Write;
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.0)?
                .write_all(bytes)
        }
    }
    crate::RuntimeBuilder::new(config)
        .with_facts_sink(FileSink(path.to_owned()))
        .build()
        .unwrap()
}

pub(super) fn exercise(context: &mut Context) -> Result<Vec<u8>, RuntimeError> {
    let entropy = context.entropy_bytes(12, EntropyWait::UntilReady)?;
    context.write_file("/state/value", &entropy)?;
    assert_eq!(context.read_file("/state/value")?, entropy);
    let start = context.now(ClockKind::Monotonic)?;
    context.sleep_for(250)?;
    assert_eq!(context.now(ClockKind::Monotonic)? - start, 250);
    Ok(entropy)
}

#[test]
fn record_and_replay_cross_scheduler_network_clock_and_filesystem() {
    fn simulation(context: &mut Context) -> Result<(TaskId, Vec<u8>), RuntimeError> {
        let first = context.task_spawn("first")?;
        context.task_spawn("second")?;
        let selected = context.scheduler_next()?.expect("tasks are runnable");
        context.task_yield(selected)?;

        let left = context.net_bind("left")?;
        let right = context.net_bind("right")?;
        context.net_send(left, "right", b"packet")?;
        let packet = context
            .net_recv(right)?
            .expect("zero-latency packet is ready");
        context.write_file("/state/packet", &packet.bytes)?;
        context.net_close(left)?;
        context.net_close(right)?;
        assert_eq!(first, TaskId(1));
        Ok((selected, context.read_file("/state/packet")?))
    }

    let directory = tempdir().unwrap();
    let path = directory.path().join("simulation.patina");
    let mut record =
        Context::from_config(RuntimeConfig::record(77, &path, "simulation-v1")).unwrap();
    let expected = simulation(&mut record).unwrap();
    record.finish().unwrap();

    let mut replay = Context::from_config(RuntimeConfig::replay(&path, "simulation-v1")).unwrap();
    assert_eq!(simulation(&mut replay).unwrap(), expected);
    replay.finish().unwrap();
}
