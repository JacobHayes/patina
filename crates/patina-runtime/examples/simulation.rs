//! Low-level explicit-context simulator example (usage mode 3 of
//! `HARNESS-DESIGN.md`).
//!
//! This drives Patina's virtual scheduler and network APIs directly through an
//! explicit [`Context`], swapping in a faulted, latency-wrapped `SimNet` before
//! `patina_dst_runtime::run_with` builds the context. It is a simulator-native
//! example: it exercises the virtual APIs directly and does NOT interpose
//! ordinary `std` calls. Configuring Patina and then driving real application
//! code is the job of the shim-backed `patina-dst-harness` crate.
//!
//! [`Context`]: patina_dst_runtime::Context

use patina_dst_net_sim::SimNet;
use patina_dst_runtime::RuntimeError;
use patina_dst_wrapper_fault::FaultNet;
use patina_dst_wrapper_latency::LatencyNet;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let summary = patina_dst_runtime::run_with(
        |builder| {
            let network = SimNet::builder()
                .build()
                .expect("example SimNet configuration is valid");
            let network = FaultNet::new(network, 17)
                .drop_one_in(5)
                .duplicate_one_in(3);
            let network = LatencyNet::new(network, 23)
                .latency_nanos(100)
                .jitter_nanos(25);
            builder.with_network(network)
        },
        |context| {
            let first = context.task_spawn("sender")?;
            let second = context.task_spawn("receiver")?;
            let scheduled = context.scheduler_next()?.expect("tasks are runnable");
            context.task_yield(scheduled)?;

            let sender = context.net_bind("node-a")?;
            let receiver = context.net_bind("node-b")?;
            let report = context.net_send(sender, "node-b", b"hello")?;
            context.sleep_for(200)?;
            let mut deliveries = 0;
            while context.net_recv(receiver)?.is_some() {
                deliveries += 1;
            }
            Ok::<_, RuntimeError>(format!(
                "seed={} tasks={:?},{:?} scheduled={:?} disposition={:?} copies={} deliveries={} steps={}",
                context.root_seed(),
                first,
                second,
                scheduled,
                report.disposition,
                report.copies,
                deliveries,
                context.steps()
            ))
        },
    )?;

    println!("PATINA_SIMULATION {summary}");
    Ok(())
}
