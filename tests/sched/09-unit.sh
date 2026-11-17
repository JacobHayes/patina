# Unit tests of the whole workspace (supervisor scheduler, signal queues, materialiser and
# durability rules, proto), no guest; and the CLI's integration tests (tests/log_addresses.rs:
# one small run, no runtime address in its boundary log).
#@ tier=quick budget=120 arch=x86_64
. "$(dirname "$0")/lib.inc"
cd "$HERE/../.."
cargo test --release --quiet -p patina-proto -p patina-cli 2>&1
