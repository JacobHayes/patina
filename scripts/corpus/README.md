# The program survey

A survey runs real programs (servers, databases, language runtimes, build tools) natively
and under Patina, to find what stops them: an unsupported call, a refusal, nondeterminism, a
hang. It is run by hand, now and then (before a release, or after a family of calls lands),
not in CI: the programs are third-party downloads that drift, and what a survey finds is
the first stop in a program not tried before.

## Running it

```sh
export CORPUS=/some/scratch PROGS=$CORPUS/programs PATINA=target/release/patina
scripts/corpus/survey.sh etcd1                       # every phase
scripts/corpus/survey.sh mysql native same           # some phases
for w in scripts/corpus/wl/*.sh; do scripts/corpus/survey.sh "$(basename "$w" .sh)"; done
```

Each workload's results go to `$CORPUS/runs/NAME/` (replaced on each survey of it), with one
`summary.txt`. `survey.sh` says what each phase does. A full survey of every workload takes
two to three hours and several GB of downloads; give it a scratch directory with room.

## Programs

The operator fetches the programs; the scripts download nothing. A workload names the
directories it needs under `$PROGS` in its `# programs:` header, and Patina mounts each one
read-only at the same path. The names follow what `mise` installs, with `$PROGS` as its
installs directory:

```sh
MISE_DATA_DIR=$CORPUS/mise mise install conda:etcd@3.7.3 conda:mysql-server@9.7.4 ...
ln -s "$CORPUS/mise/installs" "$PROGS"
```

`conda-NAME/VERSION/` comes from conda-forge (`mise install conda:NAME@VERSION`); `node`,
`bun`, `caddy`, `rg`, `fd` from mise's own backends; `rust` is a Rust toolchain directory;
`built/uvenv` is a Python virtual environment with uvicorn installed. Versions are in the
paths each workload uses: a newer version means editing the workload. Programs the host
already has (git, make, rsync, busybox, sqlite3, python3, curl) come from `/usr`.

## Workloads

`wl/NAME.sh` runs inside the sandbox as `/guest/NAME.sh` (with `GUEST=/guest`, and its
helper files beside it) and natively with `GUEST` set to this directory. A workload is a
short scenario: start the program, drive it (clients, writes, a restart), stop it, print
what a reader can compare with the native run. Headers set what else the run needs:
`# flags:` (patina flags), `# seeds:` and `# fseeds:` (sweep widths).
