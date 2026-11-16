# W1-W9 and the language runtimes language runtimes (sourced): entry NAME sets GDIR, CMD, OPTS.
W=${PATINA_WORKLOADS:?}
GU=${PATINA_GUESTS:?}

entry() { # entry NAME -> GDIR, CMD, OPTS
    OPTS=""
    case $1 in
    W1) GDIR=$W/rust-threads-files; CMD="/guest/rust-threads-files correct" ;;
    W2-local) GDIR=$W/tokio-mt; CMD="/guest/tokio-mt local" ;;
    W2-net) GDIR=$W/tokio-mt; CMD="/guest/tokio-mt net" ;;
    W3) GDIR=$W/c-sqlite; CMD="/guest/sqlite-dur wal normal" ;;
    W4) GDIR=$W/go-static; CMD="/guest/go-static all"; OPTS="--ncpu 2" ;;
    W5) GDIR=$W/cpython; CMD="/usr/bin/python3 /guest/w5.py all" ;;
    W6-sh) GDIR=$W/shell-pipeline; CMD="/bin/sh /guest/w6.sh" ;;
    W6-bash) GDIR=$W/shell-pipeline; CMD="/bin/bash /guest/w6.sh" ;;
    W7) GDIR=$GU; CMD="/guest/exec-matrix" ;;
    W8) GDIR=$GU; CMD="/guest/sockets all" ;;
    W9) GDIR=$W/fjall-harness; CMD="/guest/fjall-harness-release" ;;
    rs-net) GDIR=$GU; CMD="/guest/rs-net" ;;
    tokio-echo) GDIR=$GU; CMD="/guest/tokio-echo" ;;
    py-net) GDIR=$GU; CMD="/usr/bin/python3 /guest/py-net.py" ;;
    go-net) GDIR=$GU; CMD="/guest/go-net"; OPTS="--ncpu 2" ;;
    *) echo "unknown entry $1" >&2; exit 2 ;;
    esac
}
ENTRIES="W1 W2-local W2-net W3 W4 W5 W6-sh W6-bash W7 W8 W9 rs-net tokio-echo py-net go-net"
