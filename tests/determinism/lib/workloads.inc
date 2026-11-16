# Workload table for the determinism hardening protocol (sourced). wl NAME sets GDIR (mounted at /guest),
# CMD (the guest command line), FAULTS (the "faults on" options) and EXTRA (always passed).
G12=${PATINA_ATTACK_GUESTS:?}
W=${PATINA_WORKLOADS:?}
WL=${PATINA_ATTACK_WORKLOADS:-$W}
GU=${PATINA_GUESTS:?}
NETF="--fault net-reset-permille=30 --fault net-chunk-max=7 --fault net-delay-ms=0..3"
W_ALL="W1 W2 W3 W4 W5 W6 W7 W8 W9"
A_ALL="dents pipebuf epollorder churn addr sigstorm uninit initstack envprobe sockprobe procread memprobe pipeprobe timeprobe fs-tour proc-policy insn-probe coreprobe fdexhaust stdoutprobe"
wl() {
    EXTRA=""; FAULTS="--fault fs-error-permille=5"
    case $1 in
    W1) GDIR=$W/rust-threads-files; CMD="/guest/rust-threads-files correct"; FAULTS="--crash machine:5" ;;
    W2) GDIR=$WL/tokio-mt; CMD="/guest/tokio-mt local" ;;
    W3) GDIR=$W/c-sqlite; CMD="/guest/sqlite-dur wal normal" ;;
    W4) GDIR=$WL/go-static; CMD="/guest/go-static all"; FAULTS="--fault fs-error-permille=10" ;;
    W5) GDIR=$WL/cpython; CMD="/usr/bin/python3 /guest/w5.py all"; FAULTS="--fault fs-error-permille=10" ;;
    W6) GDIR=$WL/shell-pipeline; CMD="/bin/sh /guest/w6.sh"; FAULTS="--fault fs-error-permille=20" ;;
    W7) GDIR=$GU; CMD="/guest/exec-matrix" ;;
    W8) GDIR=$GU; CMD="/guest/sockets all"; FAULTS=$NETF ;;
    U1) GDIR=$GU; CMD="/guest/udp rpc retry"; FAULTS="--fault net-drop-permille=100 --fault net-dup-permille=50 --fault net-reorder-permille=50" ;;
    W9) GDIR=$W/fjall-harness; CMD="/guest/fjall-harness-release"; FAULTS="--crash machine:5 --fault fs-error-permille=2" ;;
    churn) GDIR=$G12; CMD="/guest/churn 300 2000" ;;
    pipeprobe) GDIR=$G12; CMD="/guest/pipeprobe 300" ;;
    fs-tour|proc-policy|insn-probe) GDIR=$GU; CMD="/guest/$1" ;;
    *) GDIR=$G12; CMD="/guest/$1" ;;
    esac
}
