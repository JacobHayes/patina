# Unit tests of the whole workspace (supervisor scheduler, signal queues, materialiser and
# durability rules, proto), no guest.
#@ tier=quick budget=120
. "$(dirname "$0")/lib.inc"
cd "$HERE/../.."
cargo test --release --quiet -p patina-proto -p patina-cli 2>&1
