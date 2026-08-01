mod checkout;

use std::env;
use std::process;

use checkout::{CheckoutLedger, Idempotency};
use patina_dst_async::{block_on, spawn, timeout, yield_now, UdpSocket};
use patina_dst_net_sim::SimNet;
use patina_dst_runtime::{run_with, RuntimeError};

const CLIENT_ADDR: &str = "mobile-client";
const CHECKOUT_ADDR: &str = "checkout-service";
const ORDER_ID: &str = "order-42";
const IDEMPOTENCY_KEY: &str = "checkout-click-777";
const LINK_LATENCY_NANOS: u64 = 10_000_000; // 10 ms each way, in virtual time.
const CLIENT_TIMEOUT_NANOS: u64 = 15_000_000; // shorter than the 20 ms round trip.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScenarioMode {
    Correct,
    Buggy,
}

impl ScenarioMode {
    fn parse(arg: Option<String>) -> Result<Self, String> {
        match arg.as_deref() {
            None | Some("correct") => Ok(Self::Correct),
            Some("buggy") => Ok(Self::Buggy),
            Some("-h") | Some("--help") => {
                print_help();
                process::exit(0);
            }
            Some(other) => Err(format!("unknown scenario '{other}'")),
        }
    }

    fn idempotency(self) -> Idempotency {
        match self {
            Self::Correct => Idempotency::Enforced,
            Self::Buggy => Idempotency::Missing,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Correct => "correct",
            Self::Buggy => "buggy",
        }
    }
}

#[derive(Debug)]
struct ClientReport {
    attempts: u32,
    timeouts: u32,
    receipt: String,
}

#[derive(Debug)]
struct ServiceReport {
    requests_seen: u32,
    duplicate_requests: u32,
    charges_for_order: u64,
}

#[derive(Debug)]
struct SimulationReport {
    mode: ScenarioMode,
    client: ClientReport,
    service: ServiceReport,
}

#[derive(Debug)]
struct ReserveRequest {
    order_id: String,
    idempotency_key: String,
}

#[derive(Debug)]
struct ReserveReply {
    receipt: String,
}

fn main() {
    let mode = match ScenarioMode::parse(env::args().nth(1)) {
        Ok(mode) => mode,
        Err(message) => {
            eprintln!("checkout-retry-idempotency: {message}");
            print_help();
            process::exit(2);
        }
    };

    let report = match run_scenario(mode) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("checkout-retry-idempotency: Patina runtime error: {error}");
            process::exit(3);
        }
    };

    if report.service.charges_for_order > 1 {
        println!(
            "CHECKOUT_IDEMPOTENCY_VIOLATION mode={} order={} key={} attempts={} timeouts={} requests_seen={} duplicate_requests={} charges={} reason=retry_charged_twice",
            report.mode.as_str(),
            ORDER_ID,
            IDEMPOTENCY_KEY,
            report.client.attempts,
            report.client.timeouts,
            report.service.requests_seen,
            report.service.duplicate_requests,
            report.service.charges_for_order,
        );
        process::exit(1);
    }

    println!(
        "CHECKOUT_IDEMPOTENCY_RESULT mode={} order={} key={} attempts={} timeouts={} requests_seen={} duplicate_requests={} charges={} receipt={} status=ok",
        report.mode.as_str(),
        ORDER_ID,
        IDEMPOTENCY_KEY,
        report.client.attempts,
        report.client.timeouts,
        report.service.requests_seen,
        report.service.duplicate_requests,
        report.service.charges_for_order,
        report.client.receipt,
    );
}

fn print_help() {
    println!(
        "usage: cargo run --quiet -- [correct|buggy]\n\n\
         correct  run the idempotent checkout implementation (default)\n\
         buggy    run a planted implementation that charges a retry twice\n\n\
         This is an explicit-context simulator: the checkout ledger is ordinary\n\
         Rust, while this binary builds a virtual client/service/network around it."
    );
}

fn run_scenario(mode: ScenarioMode) -> Result<SimulationReport, RuntimeError> {
    run_with(
        |builder| {
            let net = SimNet::builder()
                .base_latency_nanos(LINK_LATENCY_NANOS)
                .build()
                .expect("fixed-latency SimNet configuration is valid");
            builder.with_network(net)
        },
        |ctx| block_on(ctx, scenario(mode))?,
    )
}

async fn scenario(mode: ScenarioMode) -> Result<SimulationReport, RuntimeError> {
    // Binding sockets before spawning the actors keeps setup deterministic and
    // separate from the behavior under test.
    let service_socket = UdpSocket::bind(CHECKOUT_ADDR).await?;
    let client_socket = UdpSocket::bind(CLIENT_ADDR).await?;

    let service = spawn(
        "checkout-service",
        checkout_service(service_socket, mode.idempotency()),
    )?;
    let client = spawn("mobile-client", mobile_client(client_socket))?;

    let client = client.await??;
    let service = service.await??;

    Ok(SimulationReport {
        mode,
        client,
        service,
    })
}

async fn mobile_client(socket: UdpSocket) -> Result<ClientReport, RuntimeError> {
    actor_bootstrap().await;
    let mut attempts = 1;
    let mut timeouts = 0;

    socket
        .send_to(CHECKOUT_ADDR, reserve_payload(attempts).as_bytes())
        .await?;

    let first_reply = timeout(CLIENT_TIMEOUT_NANOS, socket.recv()).await?;
    let reply = match first_reply {
        Some(datagram) => parse_reply(&datagram?.bytes)?,
        None => {
            // The 15 ms client timeout fires before the first 20 ms round-trip
            // response. This retry is the production-shaped event the test cares
            // about, and it costs no wall-clock time.
            timeouts += 1;
            attempts += 1;
            socket
                .send_to(CHECKOUT_ADDR, reserve_payload(attempts).as_bytes())
                .await?;
            parse_reply(&socket.recv().await?.bytes)?
        }
    };

    Ok(ClientReport {
        attempts,
        timeouts,
        receipt: reply.receipt,
    })
}

async fn checkout_service(
    socket: UdpSocket,
    idempotency: Idempotency,
) -> Result<ServiceReport, RuntimeError> {
    actor_bootstrap().await;
    let mut ledger = CheckoutLedger::default();
    let mut requests_seen = 0;
    let mut duplicate_requests = 0;

    while requests_seen < 2 {
        let datagram = socket.recv().await?;
        let request = parse_request(&datagram.bytes)?;
        let reservation = ledger.reserve(&request.order_id, &request.idempotency_key, idempotency);
        if reservation.duplicate_request {
            duplicate_requests += 1;
        }
        let reply = format!(
            "reserved order={} receipt={}",
            request.order_id, reservation.receipt
        );
        socket.send_to(&datagram.from, reply.as_bytes()).await?;
        requests_seen += 1;
    }

    Ok(ServiceReport {
        requests_seen,
        duplicate_requests,
        charges_for_order: ledger.charges_for_key(IDEMPOTENCY_KEY),
    })
}

async fn actor_bootstrap() {
    // This tiny scenario has only one client and one service request loop. A few
    // explicit yields give Patina's deterministic scheduler real actor
    // boundaries to choose among before the virtual network/timer events take
    // over; larger protocol models usually get these boundaries naturally.
    for _ in 0..5 {
        yield_now().await;
    }
}

fn reserve_payload(attempt: u32) -> String {
    format!("reserve order={ORDER_ID} key={IDEMPOTENCY_KEY} attempt={attempt}")
}

fn parse_request(bytes: &[u8]) -> Result<ReserveRequest, RuntimeError> {
    let text = payload_text(bytes)?;
    if !text.starts_with("reserve ") {
        return Err(RuntimeError::Config(format!(
            "unexpected request payload: {text}"
        )));
    }
    Ok(ReserveRequest {
        order_id: field(text, "order=")?.to_string(),
        idempotency_key: field(text, "key=")?.to_string(),
    })
}

fn parse_reply(bytes: &[u8]) -> Result<ReserveReply, RuntimeError> {
    let text = payload_text(bytes)?;
    if !text.starts_with("reserved ") {
        return Err(RuntimeError::Config(format!(
            "unexpected reply payload: {text}"
        )));
    }
    Ok(ReserveReply {
        receipt: field(text, "receipt=")?.to_string(),
    })
}

fn payload_text(bytes: &[u8]) -> Result<&str, RuntimeError> {
    std::str::from_utf8(bytes)
        .map_err(|error| RuntimeError::Config(format!("payload was not UTF-8: {error}")))
}

fn field<'a>(text: &'a str, prefix: &str) -> Result<&'a str, RuntimeError> {
    text.split_whitespace()
        .find_map(|part| part.strip_prefix(prefix))
        .ok_or_else(|| RuntimeError::Config(format!("missing {prefix} field in payload: {text}")))
}
