"""The W1-W9 workload table (the determinism hardening protocol's commands and fault configurations,
tests/determinism/lib/workloads.inc). Each entry: guest dir, argv, fault options, extra patina options,
native environment."""
import os

W = os.environ["PATINA_WORKLOADS"]
GU = os.environ["PATINA_GUESTS"]
NETF = ["--fault", "net-reset-permille=30", "--fault", "net-chunk-max=7", "--fault", "net-delay-ms=0..3"]

WL = {
    "W1": (W + "/rust-threads-files", ["/guest/rust-threads-files", "correct"], ["--fault", "crash-permille=5"], []),
    "W2": (W + "/tokio-mt", ["/guest/tokio-mt", "local"], ["--fault", "fs-error-permille=5"], []),
    "W3": (W + "/c-sqlite", ["/guest/sqlite-dur", "wal", "normal"], ["--fault", "fs-error-permille=5"], []),
    "W4": (W + "/go-static", ["/guest/go-static", "all"], ["--fault", "fs-error-permille=10"], []),
    "W5": (W + "/cpython", ["/usr/bin/python3", "/guest/w5.py", "all"], ["--fault", "fs-error-permille=10"], []),
    "W6": (W + "/shell-pipeline", ["/bin/sh", "/guest/w6.sh"], ["--fault", "fs-error-permille=20"], []),
    "W7": (GU, ["/guest/exec-matrix"], ["--fault", "fs-error-permille=5"], []),
    "W8": (GU, ["/guest/sockets", "all"], NETF, []),
    "W9": (W + "/fjall-harness", ["/guest/fjall-harness-release"], ["--fault", "crash-permille=5", "--fault", "fs-error-permille=2"], []),
}
ORDER = ["W1", "W2", "W3", "W4", "W5", "W6", "W7", "W8", "W9"]
