#!/usr/bin/env python3
"""Native-versus-Patina overhead benchmark over halting, self-checking workloads.

Each workload runs natively and under `cargo patina run` (fixed seed, no faults)
with warmup runs first and the timed runs in a shuffled order. Every run must
print the same result line; a mismatch or a failed run fails the benchmark.
Per run it records wall time, user+sys CPU and peak RSS through a small C
launcher (scripts/bench-launch.c) whose wait4 usage includes the Patina guest
the CLI spawns, then reports per-workload medians, p90s, and the Patina/native
ratio with a bootstrap 95% interval.

`--gate --baseline` applies a blocking 2% end-to-end / 5% hot-path policy
using paired ABBA blocks and an A/A noise run (exit 4 inconclusive, 5 regress).
`--pin` pins the entire process tree on Linux. Gate verdicts bind exact build
hashes, toolchain and fixed workload inputs; changed trace-event counts require
a separately passing fixed-work run with an explanation.

`--baseline` swaps the native leg for a second Patina build (a git rev or a
cargo-patina binary) so two builds are compared on identical inputs.

Output: a markdown table on stdout (and appended to --summary-md), and one JSON
record per workload (schema patina.bench/v1) written to --output. Records carry the
host's OS, arch, CPU model and kernel, never its hostname or user.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
import platform
import random
import secrets
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bench_gate

SCHEMA = 'patina.bench/v1'
ROOT = Path(__file__).resolve().parent.parent
# The guest-visible directory `{dir}` stands for under Patina: its filesystem
# is virtual, so every run starts from an empty one.
VIRTUAL_DIR = '/bench-work'
BOOTSTRAP_ROUNDS = 2000
GATE_RETRY = 'pause builds and re-run the benchmark gate for the stack tip versus main'


@dataclass(frozen=True)
class Workload:
    name: str
    testbed: str
    # Guest arguments. `{n}` is `count` times --scale; `{dir}` is a fresh host
    # directory natively and VIRTUAL_DIR under Patina.
    args: Tuple[str, ...]
    # The stdout line prefix that carries the result, and its fields that are
    # schedule-sensitive and so left out of the comparison.
    result: str
    drop: Tuple[str, ...] = ()
    count: int = 0
    # Why the guest cannot run natively, when it cannot.
    native_unsupported: str = ''
    needs_sud: bool = False
    # Sleeps on a clock: natively the real one, under Patina the virtual one.
    timer_bound: bool = False
    hot_path: bool = False


PATINA_ONLY = 'patina-only guest: it writes at the filesystem root and asserts Patina semantics'
WORKLOADS = (
    # One compute iteration: the fixed cost of starting and stopping a run.
    Workload('startup', 'bench', ('compute', '--iters', '1'), 'BENCH_RESULT'),
    Workload('compute', 'bench', ('compute', '--iters', '{n}'), 'BENCH_RESULT',
             count=2_000_000_000),
    Workload('fileio', 'bench', ('fileio', '--iters', '{n}', '--dir', '{dir}'), 'BENCH_RESULT',
             count=10_000),
    Workload('condvar', 'bench', ('condvar', '--iters', '{n}'), 'BENCH_RESULT', count=50_000),
    Workload('pipe', 'bench', ('pipe', '--iters', '{n}'), 'BENCH_RESULT', count=40_000),
    Workload('tcp', 'bench', ('tcp', '--iters', '{n}'), 'BENCH_RESULT', count=25_000),
    Workload('workq', 'workq',
             ('--seed', '7', '--jobs', '{n}', '--workers', '3', '--producers', '2',
              '--base-port', '5701', '--data-dir', '{dir}', '--timeout-secs', '300'),
             'WORKQ_RESULT', drop=('attempts',), count=200, timer_bound=True),
    Workload('pubsub', 'pubsub',
             ('--seed', '7', '--messages', '{n}', '--base-port', '6701', '--timeout-secs', '120'),
             'PUBSUB_RESULT', drop=('heartbeats',), count=100, timer_bound=True),
    Workload('fifo-ipc', 'fifo-ipc', (), 'FIFO_RESULT', native_unsupported=PATINA_ONLY),
    Workload('cap-std-dirfd', 'cap-std-dirfd', (), 'CAPSTD_RESULT',
             native_unsupported=PATINA_ONLY, needs_sud=True),
    Workload('rustix-default', 'rustix-default', (), 'RUSTIX_RESULT',
             native_unsupported=PATINA_ONLY, needs_sud=True),
)


class BenchError(Exception):
    """A failed run or a result mismatch: loud, and the benchmark exits 1.

    `reason` is the short form a record keeps: it names no host path."""

    def __init__(self, message: str, reason: Optional[str] = None):
        super().__init__(message)
        self.reason = reason or message


class BuildError(BenchError):
    """A build that failed, so nothing can be measured (exit 3)."""


# ---------------------------------------------------------------- statistics

def percentile(values: Sequence[float], q: float) -> float:
    """Linear interpolation between order statistics (numpy's default)."""
    if not values:
        raise ValueError('percentile of no values')
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q / 100.0
    lo = int(pos)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


def median(values: Sequence[float]) -> float:
    return percentile(values, 50)


def summarize(values: Sequence[float]) -> Dict[str, float]:
    return {'median': median(values), 'p90': percentile(values, 90),
            'min': min(values), 'max': max(values)}


def ratio_of_medians(base: Sequence[float], subject: Sequence[float],
                     rng: random.Random, rounds: int = BOOTSTRAP_ROUNDS) -> Optional[dict]:
    """median(subject) / median(base) with a bootstrap 95% interval.

    None when the base median is zero (nothing to divide by)."""
    if median(base) <= 0:
        return None
    ratios = []
    for _ in range(rounds):
        b = median(rng.choices(base, k=len(base)))
        s = median(rng.choices(subject, k=len(subject)))
        if b > 0:
            ratios.append(s / b)
    return {'median': median(subject) / median(base),
            'ci95': [percentile(ratios, 2.5), percentile(ratios, 97.5)]}


def ratio_of_minima(base: Sequence[float], subject: Sequence[float]) -> Optional[float]:
    """min(subject) / min(base): an advisory least-disturbed-run reference.
    Blocking gates use paired medians. None when min(base) is 0."""
    if min(base) <= 0:
        return None
    return min(subject) / min(base)


# ----------------------------------------------------------------- results

def parse_result(stdout: str, prefix: str, drop: Sequence[str] = ()) -> Optional[str]:
    """The last `PREFIX k=v ...` line of stdout, minus the `drop` fields."""
    line = None
    for candidate in stdout.splitlines():
        if candidate.startswith(prefix + ' '):
            line = candidate
    if line is None:
        return None
    kept = [tok for tok in line.split()[1:] if tok.split('=', 1)[0] not in drop]
    return ' '.join([prefix] + kept)


def expand(args: Sequence[str], n: int, directory: str) -> List[str]:
    return [a.replace('{n}', str(n)).replace('{dir}', directory) for a in args]


def scaled_count(workload: Workload, scale: float) -> int:
    return max(1, round(workload.count * scale))


# ------------------------------------------------------------------- host

def host_facts() -> Dict[str, str]:
    system = platform.system().lower()
    arch = platform.machine().lower()
    arch = {'arm64': 'aarch64', 'amd64': 'x86_64'}.get(arch, arch)
    return {'os': system, 'arch': arch, 'cpu_model': cpu_model(system),
            'kernel': platform.release()}


def cpu_model(system: str) -> str:
    try:
        if system == 'darwin':
            return subprocess.run(['sysctl', '-n', 'machdep.cpu.brand_string'],
                                  capture_output=True, text=True, check=True).stdout.strip()
        for line in Path('/proc/cpuinfo').read_text().splitlines():
            if line.lower().startswith('model name'):
                return line.split(':', 1)[1].strip()
        # aarch64 cpuinfo names no model; lscpu decodes the part number.
        out = subprocess.run(['lscpu'], capture_output=True, text=True, check=True).stdout
        for line in out.splitlines():
            if line.startswith('Model name:'):
                return line.split(':', 1)[1].strip()
    except (OSError, subprocess.CalledProcessError):
        pass
    return 'unknown'


def sud_available() -> bool:
    """The testbed scripts' probe: prctl(PR_SET_SYSCALL_USER_DISPATCH, OFF)."""
    if platform.system() != 'Linux':
        return False
    libc = ctypes.CDLL(None, use_errno=True)
    return libc.prctl(59, 0, 0, 0, 0) == 0


def output(cmd: List[str]) -> Optional[str]:
    try:
        return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                              check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def vcs() -> Optional[str]:
    """'git' or 'jj' when ROOT is the root of that tool's checkout. A repository
    that merely encloses an exported tree does not count."""
    for tool, cmd in (('jj', ['jj', 'workspace', 'root']),
                      ('git', ['git', 'rev-parse', '--show-toplevel'])):
        top = output(cmd)
        if top and Path(top).resolve() == ROOT:
            return tool
    return None


def commit_id() -> str:
    tool = vcs()
    if tool == 'git':
        if output(['git', 'status', '--porcelain']) != '':
            return 'unknown'  # a dirty source tree is not the named commit
        return output(['git', 'rev-parse', 'HEAD']) or 'unknown'
    if tool == 'jj':
        return output(['jj', 'log', '--no-graph', '-r', 'latest(::@ & ~empty())',
                       '-T', 'commit_id']) or 'unknown'
    return 'unknown'


# ------------------------------------------------------------------ builds

def run_build(cmd: List[str], cwd: Path, env: Dict[str, str], log: Path) -> None:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open('w') as out:
        status = subprocess.run(cmd, cwd=cwd, env=env, stdout=out,
                                stderr=subprocess.STDOUT).returncode
    if status != 0:
        tail = ''.join(log.read_text().splitlines(keepends=True)[-40:])
        raise BuildError(f'build failed (exit {status}): {" ".join(cmd)}\n{tail}log: {log}',
                         reason=f'build failed (exit {status}); its log is {log.name}')


def cargo_binary(source: Path, package: str, destination: Path, log: Path) -> Path:
    run_build(['cargo', 'build', '--release', '--locked', '--message-format=json',
               '-p', package], source, dict(os.environ), log)
    artifacts = []
    for line in log.read_text().splitlines():
        try:
            receipt = json.loads(line)
        except ValueError:
            continue
        if receipt.get('reason') == 'compiler-artifact' and receipt.get('executable'):
            artifacts.append(Path(receipt['executable']))
    if len(artifacts) != 1:
        raise BuildError(f'{package}: expected one Cargo executable receipt')
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(artifacts[0], destination)
    return destination


def build_cargo_patina(source: Path, target_dir: Path, logs: Path) -> Path:
    return cargo_binary(source, 'cargo-patina', target_dir / 'cargo-patina',
                        logs / 'cargo-patina.log')


def git_dir() -> Optional[str]:
    tool = vcs()
    if tool == 'git':
        return output(['git', 'rev-parse', '--absolute-git-dir'])
    if tool == 'jj':
        return output(['jj', '--ignore-working-copy', 'git', 'root'])
    return None


def resolve_rev(rev: str) -> str:
    """A revision of this checkout as a full commit id: a jj revision in a jj
    workspace (where git's HEAD belongs to the colocated default workspace,
    not this one), a git revision in a git checkout."""
    tool = vcs()
    sha = None
    if tool == 'jj':
        sha = output(['jj', 'log', '--no-graph', '-r', rev,
                      '-T', 'commit_id'])
    elif tool == 'git':
        sha = output(['git', 'rev-parse', '--verify', '--quiet', f'{rev}^{{commit}}'])
    if sha and len(sha) == 40:
        return sha
    raise BuildError(f'--baseline {rev!r} is neither a file nor a single revision of this checkout')


def build_baseline(spec: str, base: Path, *, refresh: bool = False) -> Tuple[Path, dict, Path]:
    """A cargo-patina for `spec` (an existing binary, or a revision), its
    identity for the records, and the directory its guests build under.

    Revision exports live at a stable private source path so generated source
    locations do not change artifact identity on verification. Refresh rebuilds
    through Cargo with the current environment rather than trusting a rev-only
    artifact cache. This scratch directory has one writer, like the run's legs.
    """
    as_path = Path(spec)
    if as_path.is_file():
        digest = hashlib.sha256(as_path.read_bytes()).hexdigest()
        return as_path.resolve(), {'binary_sha256': digest}, base / 'baseline' / digest
    sha = resolve_rev(spec)
    home = base / 'baseline' / sha
    binary = home / 'cargo-patina'
    source = home / 'source'
    if not refresh and binary.is_file() and source.is_dir():
        return binary, {'rev': sha}, home
    home.mkdir(parents=True, exist_ok=True)
    build = Path(tempfile.mkdtemp(prefix='build.', dir=home))
    try:
        exported = build / 'source'
        archive = build / 'src.tar'
        run_build(['git', f'--git-dir={git_dir()}', 'archive', '-o', str(archive), sha], ROOT,
                  dict(os.environ), build / 'logs' / 'archive.log')
        with tarfile.open(archive) as tar:
            # The 'data' filter (Python >= 3.12, and security releases before
            # it) refuses members that would land outside `source`.
            safe = {'filter': 'data'} if hasattr(tarfile, 'data_filter') else {}
            tar.extractall(exported, **safe)
        if source.exists():
            shutil.rmtree(source)
        os.replace(exported, source)
        print(f'==> building baseline cargo-patina at {sha[:12]}', flush=True)
        built = build_cargo_patina(source, build / 'artifacts', build / 'logs')
        staged = build / 'cargo-patina'
        shutil.copy2(built, staged)
        os.replace(staged, binary)
    except BuildError:
        # Kept for its logs; without a binary in place no later run uses it.
        raise
    except BaseException:
        shutil.rmtree(build, ignore_errors=True)
        raise
    shutil.rmtree(build, ignore_errors=True)
    return binary, {'rev': sha}, home


# ------------------------------------------------------------------- legs

def verify_artifacts(identity, opts, base, selected):
    """Rebuild actual products; revisions alone cannot identify build settings."""
    current = build_cargo_patina(ROOT, base / 'verify', base / 'verify' / 'logs')
    baseline, _, _ = build_baseline(opts.baseline, base, refresh=True)
    return (identity['candidate']['binary_sha256'] == hashlib.sha256(current.read_bytes()).hexdigest()
            and identity['base']['binary_sha256'] == hashlib.sha256(baseline.read_bytes()).hexdigest())


def verify_verdict(opts, base, selected):
    try:
        verdict = json.loads(opts.verify.read_text())
        identity = verdict.get('identity', {})
        rows, digest = workload_identity(opts, selected)
        matches = (bench_gate.valid_identity(identity) and verdict.get('schema') == bench_gate.SCHEMA
                   and verdict.get('mode') == 'comparison'
                   and verdict.get('verdict') == 'pass' and verdict.get('exit_code') == 0
                   and identity.get('candidate', {}).get('rev') == commit_id()
                   and identity.get('base', {}).get('rev') == resolve_rev(opts.baseline)
                   and identity.get('toolchain') == output(['rustc', '-vV'])
                   and identity.get('workloads') == rows
                   and identity.get('workload_set_sha256') == digest
                   and identity.get('seed') == opts.seed
                   and verify_artifacts(identity, opts, base, selected)
                   and identity['candidate']['rev'] == commit_id())
    except (OSError, ValueError, KeyError, TypeError, AttributeError, BenchError) as error:
        print(f'gate verification: inconclusive ({error})')
        return 4
    print('gate verification: ' + ('pass' if matches else 'inconclusive (stale or failing verdict)'))
    return 0 if matches else 4


def cargo_metadata():
    raw = output(['cargo', 'metadata', '--offline', '--locked', '--format-version', '1'])
    if raw is None:
        raise BenchError('cannot establish the hot-path dependency closure')
    return json.loads(raw)


def landing_hot_path_packages():
    """Cargo's normal/build dependency closure of the measured effect paths.

    Native doors enter the shim; Context enters runtime and the dependencies of
    patina-bench's fixed mix. The workload harness itself is exempt. Following
    resolved edges includes shared trait defaults and future drivers without a
    second hand-maintained driver list. Dev-only dependencies stay exempt.
    """
    metadata = cargo_metadata()
    packages = {p['id']: p for p in metadata['packages']}
    names = {p['name']: p['id'] for p in metadata['packages']}
    nodes = {n['id']: n for n in metadata['resolve']['nodes']}
    def dependencies(package):
        return [d['pkg'] for d in nodes[package]['deps']
                if any(k['kind'] != 'dev' for k in d['dep_kinds'])]
    pending = [names['patina-dst-native-shim'], names['patina-dst-runtime']]
    pending += dependencies(names['patina-dst-bench'])
    visited = set()
    while pending:
        package = pending.pop()
        if package not in visited:
            visited.add(package)
            pending += dependencies(package)
    return {Path(packages[package]['manifest_path']).parent for package in visited}


def landing_protected_path(path, packages):
    """Protect each package directory, with only explicit non-production exceptions."""
    changed = ROOT / path
    for directory in packages:
        if changed.is_relative_to(directory):
            relative = changed.relative_to(directory)
            if (relative.suffix != '.md'
                    and not {'tests', 'benches', 'examples'}.intersection(relative.parts)):
                return True
    return False


def landing_verification(opts):
    """One tip-versus-main verdict admits the whole hot-path landing batch."""
    try:
        main_rev = resolve_rev('main')
        tool = vcs()
        if tool == 'jj':
            raw = output(['jj', 'diff', '--from', main_rev, '--to', '@', '-T',
                          'json(source.path()) ++ "\n" ++ json(target.path()) ++ "\n"'])
            paths = [json.loads(line) for line in raw.splitlines()] if raw is not None else None
        elif tool == 'git':
            raw = output(['git', 'diff', '--name-only', '--no-renames', '-z', main_rev, '--'])
            untracked = output(['git', 'ls-files', '--others', '--exclude-standard', '-z'])
            paths = (raw + '\0' + untracked).split('\0') if raw is not None and untracked is not None else None
        else:
            paths = None
        if paths is None:
            raise BenchError('cannot establish changes versus main')
        packages = landing_hot_path_packages()
        protected = any(landing_protected_path(path, packages) for path in paths)
        if not protected:
            print('benchmark landing verification: no production hot-path changes versus main')
            return 0
        verdict = os.environ.get('PATINA_BENCH_VERDICT')
        if not verdict:
            raise BenchError('shim/runtime/driver changes require PATINA_BENCH_VERDICT for the stack tip versus main')
        opts.verify, opts.baseline = Path(verdict), main_rev
        opts.workload, opts.scale, opts.seed = None, 1.0, 1
        base = Path(os.environ.get('PATINA_BENCH_SCRATCH', ROOT / 'target' / 'bench')).resolve()
        status = verify_verdict(opts, base, list(WORKLOADS))
        if status == 4:
            print(f'benchmark landing verification: inconclusive is not a pass; {GATE_RETRY}')
        return status
    except (ValueError, KeyError, TypeError, AttributeError, BenchError) as error:
        print(f'benchmark landing verification: inconclusive ({error}); {GATE_RETRY}')
        return 4

@dataclass
class Leg:
    name: str
    # None for the native leg.
    cargo_patina: Optional[Path]
    home: Path
    seed: int = 1

    def binary(self, testbed: str) -> Path:
        if self.cargo_patina is None:
            return self.home / 'release' / testbed
        return self.home / 'guests' / testbed

    def build(self, testbed: str) -> None:
        source = ROOT / 'testbeds' / testbed
        log = self.home / 'logs' / f'{testbed}.log'
        if self.cargo_patina is None:
            cargo_binary(source, testbed, self.binary(testbed), log)
        else:
            (self.home / 'guests').mkdir(parents=True, exist_ok=True)
            run_build([str(self.cargo_patina), 'patina', 'build', str(source), '--output',
                       str(self.binary(testbed)), '--release'],
                      ROOT, dict(os.environ), log)

    def command(self, workload: Workload, n: int, directory: str) -> List[str]:
        binary = str(self.binary(workload.testbed))
        if self.cargo_patina is None:
            return [binary] + expand(workload.args, n, directory)
        return ([str(self.cargo_patina), 'patina', 'run', binary, '--seed', str(self.seed), '--']
                + expand(workload.args, n, VIRTUAL_DIR))


@dataclass
class Sample:
    wall_s: float
    cpu_s: float
    rss_kib: int
    result: str


def parse_launch_report(text: str, darwin: bool) -> Tuple[float, float, int]:
    """bench-launch's report line -> (wall s, CPU s, peak RSS KiB)."""
    fields = dict(tok.split('=', 1) for tok in text.split())
    wall = int(fields['wall_ns']) / 1e9
    cpu = (int(fields['utime_us']) + int(fields['stime_us'])) / 1e6
    # ru_maxrss is KiB on Linux and bytes on macOS.
    rss = int(fields['maxrss']) // 1024 if darwin else int(fields['maxrss'])
    return wall, cpu, rss


def build_launcher(base: Path) -> Path:
    launcher = base / 'bench-launch'
    run_build(['cc', '-O2', '-o', str(launcher), str(ROOT / 'scripts' / 'bench-launch.c')],
              ROOT, dict(os.environ), base / 'logs' / 'bench-launch.log')
    return launcher


def measure(leg: Leg, workload: Workload, n: int, scratch: Path, launcher: Path,
            timeout: float) -> Sample:
    directory = Path(tempfile.mkdtemp(prefix=f'{workload.name}-', dir=scratch))
    report = directory.with_name(directory.name + '.report')
    cmd = leg.command(workload, n, str(directory))
    timed_out = False
    try:
        with tempfile.TemporaryFile(dir=scratch) as out, tempfile.TemporaryFile(dir=scratch) as err:
            # A new session, so a timeout kills the launcher, the CLI and its guest.
            proc = subprocess.Popen([str(launcher), str(report)] + cmd, cwd=directory,
                                    stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                    start_new_session=True)
            try:
                code = proc.wait(timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(proc.pid, signal.SIGKILL)
                code = proc.wait()
            out.seek(0)
            err.seek(0)
            stdout = out.read().decode(errors='replace')
            stderr = err.read().decode(errors='replace')
        usage = report.read_text() if report.is_file() else ''
    finally:
        shutil.rmtree(directory, ignore_errors=True)
        if report.exists():
            report.unlink()
    result = parse_result(stdout, workload.result, workload.drop)
    if code != 0 or result is None or not usage:
        why = f'timed out after {timeout:g}s' if timed_out else f'exit {code}'
        tail = '\n'.join((stdout + stderr).splitlines()[-20:])
        what = (f'{workload.name} [{leg.name}] failed ({why}, result line '
                f'{"present" if result else "missing"})')
        raise BenchError(f'{what}: {" ".join(cmd)}\n{tail}', reason=what)
    wall, cpu, rss = parse_launch_report(usage, sys.platform == 'darwin')
    return Sample(wall, cpu, rss, result)


# ------------------------------------------------------------------- run

def trace_op_count(stdout):
    """The emitted result envelope is the only source of recorded counts."""
    try:
        envelope = json.loads(stdout)
        payload = envelope['trace_stats']
        count = payload['totals']['events']
        if (envelope.get('schema') != 'patina.result/v1'
                or envelope.get('verb') != 'trace' or envelope.get('subcommand') != 'stats'
                or envelope.get('exit_code') != 0
                or payload.get('schema') != 'patina.trace.stats/v1'
                or type(count) is not int or count <= 0):
            raise ValueError('invalid count envelope')
        return count
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        raise BenchError('operation-count trace unreadable') from error


def probe_op_count(leg, workload, n, scratch, opts, check):
    """Untimed recorded run: count real trace events, never inferred iterations.

    Keeping recording out of the timed leg measures seeded execution. The
    counting run must complete and agree with the same result-line oracle.
    """
    with tempfile.TemporaryDirectory(prefix='ops-', dir=scratch) as directory:
        trace = Path(directory) / 'ops.trace'
        command = leg.command(workload, n, directory)
        split = command.index('--')
        command[split:split] = ['--record', str(trace)]
        run = subprocess.run(command, cwd=directory, capture_output=True, text=True,
                             timeout=opts.timeout)
        result = parse_result(run.stdout, workload.result, workload.drop)
        if run.returncode or result is None:
            raise BenchError(f'{workload.name}: operation-count run failed')
        check(leg, Sample(0, 0, 0, result))
        stats = subprocess.run([str(leg.cargo_patina), 'patina', 'trace', 'stats',
                                str(trace), '--format', 'json'], capture_output=True,
                               text=True, timeout=opts.timeout)
        if stats.returncode:
            raise BenchError(f'{workload.name}: operation-count trace unreadable')
        return trace_op_count(stats.stdout)


def workload_identity(opts, selected):
    rows = [{'name': w.name, 'args': expand(w.args, scaled_count(w, opts.scale), VIRTUAL_DIR),
             'hot_path': w.hot_path} for w in selected]
    digest = hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()
    return rows, digest



def gate_identity(opts, selected, current, host):
    rows, digest = workload_identity(opts, selected)
    return {'candidate': {'rev': opts.commit,
                          'binary_sha256': hashlib.sha256(current.read_bytes()).hexdigest()},
            'base': opts.baseline_info, 'toolchain': output(['rustc', '-vV']),
            'host': host, 'pin': opts.pin, 'seed': opts.seed,
            'workloads': rows, 'workload_set_sha256': digest}


def base_record(workload: Workload, opts, host: dict) -> dict:
    n = scaled_count(workload, opts.scale)
    record = dict(host, schema=SCHEMA, commit=opts.commit, date=opts.date,
                  workload=workload.name, testbed=workload.testbed, args=list(workload.args),
                  n=n if workload.count else None, seed=opts.seed, runs=opts.runs,
                  warmup=opts.warmup, scale=opts.scale, order_seed=opts.order_seed,
                  timer_bound=workload.timer_bound, hot_path=workload.hot_path)
    if opts.baseline_info:
        record['baseline'] = opts.baseline_info
    return record


def run_workload(workload: Workload, legs: List[Leg], opts, host: dict, order_rng: random.Random,
                 scratch: Path) -> dict:
    n = scaled_count(workload, opts.scale)
    record = base_record(workload, opts, host)
    if workload.needs_sud and not opts.sud:
        record.update(status='unsupported',
                      reason=f'needs syscall-user-dispatch (x86_64 Linux >= 5.11); '
                             f'host is {host["os"]} {host["arch"]}')
        return record
    active = [leg for leg in legs if not (leg.cargo_patina is None and workload.native_unsupported)]
    if len(active) < len(legs):
        record['native_unsupported'] = workload.native_unsupported
    reference: Optional[Tuple[str, str]] = None

    def check(leg: Leg, sample: Sample) -> None:
        nonlocal reference
        if reference is None:
            reference = (leg.name, sample.result)
        elif sample.result != reference[1]:
            raise BenchError(f'RESULT MISMATCH in {workload.name}:\n  {reference[0]}: '
                             f'{reference[1]}\n  {leg.name}: {sample.result}',
                             reason=f'result mismatch: {reference[0]} printed '
                                    f'`{reference[1]}`, {leg.name} printed `{sample.result}`')

    for leg in active:
        for _ in range(opts.warmup):
            check(leg, measure(leg, workload, n, scratch, opts.launcher, opts.timeout))
    samples: Dict[str, List[Sample]] = {leg.name: [] for leg in active}
    if getattr(opts, 'gate', False):
        if len(active) != 2:
            raise BenchError('gate requires both Patina builds')
        def blocks(a: Leg, b: Leg, count: int) -> list:
            measured = []
            for _ in range(count):
                block = []
                for leg in (a, b, b, a):
                    sample = measure(leg, workload, n, scratch, opts.launcher, opts.timeout)
                    check(leg, sample)
                    block.append(vars(sample))
                measured.append(block)
            return measured
        # Two labels, identical build and guest: A/A tests the same measurement
        # path as A/B, immediately before it, on each workload.
        record['noise_blocks'] = blocks(active[0], active[0], opts.runs // 2)
        record['blocks'] = blocks(*active, opts.runs // 2)
        threshold = 1.05 if workload.hot_path else 1.02
        metric = 'hot_ns_per_op' if workload.hot_path else 'wall_s'
        if getattr(opts, 'fixed_work_run', False):
            metric = 'wall_s'
        while len(record['blocks']) * 2 < opts.max_runs:
            ratio = bench_gate.paired_ratio(record['blocks'], metric)
            noise = bench_gate.paired_ratio(record['noise_blocks'], metric)
            if (bench_gate.interval_verdict(ratio and ratio['ci95'], threshold)
                    != 'inconclusive' and bench_gate.noise_ok(noise, threshold)):
                break
            extra = min(len(record['blocks']), opts.max_runs // 2 - len(record['blocks']))
            record['noise_blocks'] += blocks(active[0], active[0], extra)
            record['blocks'] += blocks(*active, extra)
        record['runs'] = len(record['blocks']) * 2
        for block in record['blocks']:
            for leg, sample in zip((active[0], active[1], active[1], active[0]), block):
                samples[leg.name].append(Sample(**sample))
        record['op_counts'] = {leg.name: probe_op_count(leg, workload, n, scratch, opts, check)
                               for leg in active}
        record['hot_path'] = workload.hot_path
        record['op_count_source'] = 'trace.events'
    else:
        order = [leg for leg in active for _ in range(opts.runs)]
        order_rng.shuffle(order)
        for leg in order:
            sample = measure(leg, workload, n, scratch, opts.launcher, opts.timeout)
            check(leg, sample)
            samples[leg.name].append(sample)
    record['status'] = 'ok'
    record['result'] = reference[1]
    record['legs'] = {}
    for name, runs in samples.items():
        series = {'wall_s': [s.wall_s for s in runs], 'cpu_s': [s.cpu_s for s in runs],
                  'rss_kib': [s.rss_kib for s in runs]}
        record['legs'][name] = dict(series, stats={k: summarize(v) for k, v in series.items()})
    if len(active) == 2:
        base, subject = (leg.name for leg in active)
        boot = random.Random(0)
        record['comparison'] = {
            'base': base, 'subject': subject,
            'wall_ratio': ratio_of_medians(record['legs'][base]['wall_s'],
                                           record['legs'][subject]['wall_s'], boot),
            'wall_min_ratio': ratio_of_minima(record['legs'][base]['wall_s'],
                                              record['legs'][subject]['wall_s']),
            'cpu_ratio': ratio_of_medians(record['legs'][base]['cpu_s'],
                                          record['legs'][subject]['cpu_s'], boot),
        }
    if getattr(opts, 'gate', False):
        record['comparison']['wall_ratio'] = bench_gate.paired_ratio(record['blocks'])
        record['comparison']['cpu_ratio'] = bench_gate.paired_ratio(record['blocks'], 'cpu_s')
    return record


# ------------------------------------------------------------------ report

def fmt_s(value: float) -> str:
    if value >= 1:
        return f'{value:.2f}s'
    return f'{value * 1000:.1f}ms'


# Below this many timed runs per side a bootstrap interval is rough.
STEADY_RUNS = 10


def fmt_ratio(ratio: Optional[dict], relative: bool, rough: bool) -> str:
    if ratio is None:
        return 'n/a'
    lo, hi = ratio['ci95']
    mark = '*' if rough else ''
    if relative:
        noise = ' ~' if lo <= 1 <= hi else ''
        pct = [(v - 1) * 100 for v in (ratio['median'], lo, hi)]
        return f'{pct[0]:+.1f}% [{pct[1]:+.1f}, {pct[2]:+.1f}]{mark}{noise}'
    return f'{ratio["median"]:.2f}x [{lo:.2f}-{hi:.2f}]{mark}'


def fmt_min_ratio(ratio: Optional[float], relative: bool) -> str:
    if ratio is None:
        return 'n/a'
    return f'{(ratio - 1) * 100:+.1f}%' if relative else f'{ratio:.2f}x'


def render_table(records: List[dict], legs: Sequence[str]) -> str:
    base, subject = legs
    relative = base != 'native'
    change = 'change' if relative else 'ratio'
    lines = [
        f'| workload | {base} wall med / p90 | {subject} wall med / p90 | wall {change} (95% CI) '
        f'| wall min {change} | {base} CPU | {subject} CPU | CPU {change} (95% CI) '
        f'| peak RSS {base} / {subject} |',
        '|---|---|---|---|---|---|---|---|---|',
    ]
    notes = set()
    for rec in records:
        name = rec['workload'] + (' †' if rec.get('timer_bound') else '')
        if rec.get('timer_bound'):
            notes.add('timer')
        if rec['status'] == 'unsupported':
            lines.append(f'| {name} | unsupported here: {rec["reason"]} | | | | | | | |')
            continue
        if rec['status'] != 'ok':
            lines.append(f'| {name} | **FAILED**: {rec["reason"]} | | | | | | | |')
            continue
        rough = rec['runs'] < STEADY_RUNS
        if rough:
            notes.add('rough')

        def cell(leg: str, metric: str, p90: bool = True) -> str:
            if leg not in rec['legs']:
                notes.add('native')
                return 'n/a ‡'
            stats = rec['legs'][leg]['stats'][metric]
            if metric == 'rss_kib':
                return f'{stats["median"] / 1024:.1f}MiB'
            return fmt_s(stats['median']) + (f' / {fmt_s(stats["p90"])}' if p90 else '')

        cmp = rec.get('comparison') or {}
        lines.append(
            f'| {name} | {cell(base, "wall_s")} | {cell(subject, "wall_s")} '
            f'| {fmt_ratio(cmp.get("wall_ratio"), relative, rough) if cmp else "n/a"} '
            f'| {fmt_min_ratio(cmp.get("wall_min_ratio"), relative) if cmp else "n/a"} '
            f'| {cell(base, "cpu_s", False)} | {cell(subject, "cpu_s", False)} '
            f'| {fmt_ratio(cmp.get("cpu_ratio"), relative, rough) if cmp else "n/a"} '
            f'| {cell(base, "rss_kib")} / {cell(subject, "rss_kib")} |')
    if relative:
        lines.append('\n`~`: the 95% interval includes no change (within noise).')
    if 'rough' in notes:
        lines.append(f'\n*: fewer than {STEADY_RUNS} runs per side, so the interval is rough.')
    if 'timer' in notes:
        lines.append('\n†: sleeps on a clock, the real one natively and the virtual one under '
                     'Patina, so its wall ratio is not an overhead figure; compare CPU.')
    if 'native' in notes:
        lines.append(f'\n‡: {PATINA_ONLY}; timed under Patina only.')
    return '\n'.join(lines)


# -------------------------------------------------------------------- main

def parse_args(argv: Sequence[str]):
    names = [w.name for w in WORKLOADS]
    parser = argparse.ArgumentParser(
        prog='scripts/bench.py', description=__doc__.split('\n\n')[0])
    parser.add_argument('--gate', action='store_true',
                        help='blocking paired ABBA comparison; requires --baseline (0/4/5)')
    parser.add_argument('--pin', type=int, metavar='CPU',
                        help='pin this process and all children to one allowed Linux CPU')
    parser.add_argument('--scratch-dir', type=Path,
                        help='build copies, logs and temporary data (default target/bench)')
    parser.add_argument('--fixed-work', type=Path,
                        help='passing fixed-work gate verdict for changed operation counts')
    parser.add_argument('--fixed-work-run', action='store_true',
                        help='produce separate elapsed-time proof at identical fixed inputs')
    parser.add_argument('--op-count-explanation', default='',
                        help='required explanation for --fixed-work-run')
    parser.add_argument('--max-runs', type=int, default=120,
                        help='gate cap per side when a CI/noise run is inconclusive (default 120)')
    parser.add_argument('--verify', type=Path,
                        help='verify a passing verdict against this candidate, --baseline and workload set')
    parser.add_argument('--verify-landing', action='store_true',
                        help='require one tip-versus-main comparison for production shim/runtime/driver changes')
    parser.add_argument('--runs', type=int,
                        help=f'timed runs per leg (default 5, {STEADY_RUNS} with --baseline, 30 with --gate)')
    parser.add_argument('--warmup', type=int, default=1,
                        help='untimed runs per leg first (default 1)')
    parser.add_argument('--workload', action='append', choices=names,
                        help='run only this workload (repeatable; default all)')
    parser.add_argument('--scale', type=float, default=1.0,
                        help='multiply every workload size (default 1.0)')
    parser.add_argument('--seed', type=int, default=1, help='the Patina run seed (default 1)')
    parser.add_argument('--baseline', metavar='REV|PATH',
                        help='compare against this Patina build instead of native')
    parser.add_argument('--output', type=Path,
                        help='JSONL output (default under the target dir)')
    parser.add_argument('--summary-md', type=Path, help='also append the table to this file')
    parser.add_argument('--timeout', type=float, default=600, help='per-run timeout seconds')
    opts = parser.parse_args(argv)
    if opts.runs is None:
        opts.runs = 30 if opts.gate else (STEADY_RUNS if opts.baseline else 5)
    if opts.gate and (not opts.baseline or opts.runs < 20 or opts.runs % 2):
        parser.error('--gate requires --baseline and an even --runs >= 20')
    if opts.gate and (opts.max_runs < opts.runs or opts.max_runs % 2):
        parser.error('--max-runs must be even and >= --runs')
    if (opts.gate or opts.verify) and (not opts.baseline or Path(opts.baseline).is_file()):
        parser.error('blocking gates require an exact repository revision as --baseline')
    if opts.gate and opts.runs < 30 and any(
            w.hot_path and (not opts.workload or w.name in opts.workload) for w in WORKLOADS):
        parser.error('hot-path gates require --runs >= 30')
    if (opts.fixed_work or opts.fixed_work_run) and not opts.gate:
        parser.error('fixed-work evidence requires --gate')
    if opts.fixed_work_run and (not opts.op_count_explanation or opts.fixed_work):
        parser.error('--fixed-work-run requires an explanation and no --fixed-work input')
    if opts.runs < 1 or opts.warmup < 0 or not math.isfinite(opts.scale) or opts.scale <= 0:
        parser.error('--runs must be >= 1, --warmup >= 0 and --scale > 0')
    return opts


def main(argv: Sequence[str]) -> int:
    opts = parse_args(argv)
    if opts.verify_landing:
        return landing_verification(opts)
    if opts.pin is not None:
        if not hasattr(os, 'sched_setaffinity') or opts.pin not in os.sched_getaffinity(0):
            raise BenchError('--pin needs an allowed Linux CPU')
        os.sched_setaffinity(0, {opts.pin})
    base = (opts.scratch_dir or ROOT / 'target' / 'bench').resolve()
    selected = [w for w in WORKLOADS if not opts.workload or w.name in opts.workload]
    if opts.verify:
        return verify_verdict(opts, base, selected)
    host = host_facts()
    opts.sud = sud_available()
    opts.commit = commit_id()
    opts.date = datetime.now(timezone.utc).isoformat(timespec='seconds')
    opts.order_seed = secrets.randbits(32)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    output_path = opts.output or base / 'results' / f'bench-{stamp}.jsonl'
    records: List[dict] = []
    scratch = base / 'scratch'
    scratch.mkdir(parents=True, exist_ok=True)
    try:
        opts.launcher = build_launcher(base)
        print('==> building cargo-patina', flush=True)
        current = build_cargo_patina(ROOT, base, base / 'logs')
        opts.baseline_info = None
        if opts.baseline:
            binary, opts.baseline_info, home = build_baseline(opts.baseline, base)
            opts.baseline_info['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
            first = Leg('baseline', binary, home, opts.seed)
        else:
            first = Leg('native', None, base / 'native')
        legs = [first, Leg('patina', current, base / 'patina', opts.seed)]
        runnable = [w for w in selected if not (w.needs_sud and not opts.sud)]
        for leg in legs:
            testbeds = sorted({w.testbed for w in runnable
                               if not (leg.cargo_patina is None and w.native_unsupported)})
            for testbed in testbeds:
                print(f'==> building {testbed} [{leg.name}]', flush=True)
                leg.build(testbed)
        order_rng = random.Random(opts.order_seed)
        for workload in selected:
            print(f'==> {workload.name}', flush=True)
            try:
                record = run_workload(workload, legs, opts, host, order_rng, scratch)
            except BuildError:
                raise
            except (BenchError, subprocess.TimeoutExpired) as error:
                # Loud now, and the run exits 1, but the other workloads still
                # run and every completed record is still written.
                print(f'bench: FAILED: {error}', file=sys.stderr, flush=True)
                record = dict(base_record(workload, opts, host), status='failed',
                              reason=error.reason if isinstance(error, BenchError) else 'operation-count timeout')
            if record['status'] == 'unsupported':
                print(f'    unsupported here: {record["reason"]}', flush=True)
            records.append(record)
    except BuildError as error:
        print(f'bench: FAILED: {error}', file=sys.stderr)
        if opts.summary_md:
            with opts.summary_md.open('a') as fh:
                fh.write(f'### Patina benchmark: FAILED to build\n\n{error.reason}\n\n')
        return 3
    gate = None
    if opts.gate:
        if commit_id() != opts.commit:
            raise BenchError('candidate tree changed during measurement; rerun on a frozen tree')
        fixed_work = json.loads(opts.fixed_work.read_text()) if opts.fixed_work else None
        gate = bench_gate.evaluate(records, gate_identity(opts, selected, current, host),
                                   fixed_work, opts.fixed_work_run, opts.op_count_explanation)
    failed = [r['workload'] for r in records if r['status'] == 'failed']
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open('w') as fh:
        for record in records:
            fh.write(json.dumps(record, sort_keys=True) + '\n')
    if gate is not None:
        verdict_path = output_path.with_suffix('.verdict.json')
        verdict_path.write_text(json.dumps(gate, sort_keys=True, indent=2) + '\n')
        print(f'gate: {gate["verdict"]}; verdict: {verdict_path}')
        if gate['verdict'] == 'inconclusive':
            print(f'gate: inconclusive is not a pass; {GATE_RETRY}')
    verdict = f'FAILED ({", ".join(failed)}): ' if failed else ''
    header = (f'### Patina benchmark: {verdict}{host["os"]}-{host["arch"]}, {host["cpu_model"]}, '
              f'kernel {host["kernel"]}, commit {opts.commit[:12]}, {opts.runs} runs + '
              f'{opts.warmup} warmup per leg')
    table = render_table(records, [leg.name for leg in legs])
    print(f'\n{header}\n\n{table}\n\nrecords: {output_path}')
    if opts.summary_md:
        with opts.summary_md.open('a') as fh:
            fh.write(f'{header}\n\n{table}\n\n')
    if failed:
        print(f'bench: FAILED: {len(failed)} workload(s) failed: {", ".join(failed)}',
              file=sys.stderr)
        return 1
    return gate['exit_code'] if gate else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
