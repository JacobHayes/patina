use patina_async::{TcpListener, TcpStream, block_on, spawn};
use patina_net_sim::SimNet;
use patina_runtime::{RuntimeBuilder, RuntimeConfig, RuntimeError};

fn main() -> Result<(), RuntimeError> {
    let seed = std::env::var("PATINA_SEED")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1);
    let mut context = RuntimeBuilder::new(RuntimeConfig::seeded(seed))
        .with_default_drivers()
        .with_network(SimNet::new())
        .build()?;

    let echoed = block_on(&mut context, async {
        let server = spawn("echo-server", async {
            let listener = TcpListener::listen("server", 8).await?;
            let stream = listener.accept().await?;
            let bytes = stream.read(1024).await?;
            stream.write_all(&bytes).await?;
            Ok::<_, RuntimeError>(())
        })?;

        let client = spawn("echo-client", async {
            let stream = TcpStream::connect("client", "server").await?;
            stream.write_all(b"patina").await?;
            stream.read(1024).await
        })?;

        let echoed = client.await??;
        server.await??;
        Ok::<_, RuntimeError>(echoed)
    })??;

    context.finish()?;
    println!(
        "PATINA_ASYNC seed={seed} echoed={}",
        String::from_utf8_lossy(&echoed)
    );
    Ok(())
}
