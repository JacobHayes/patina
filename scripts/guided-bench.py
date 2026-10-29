#!/usr/bin/env python3
"""Paired benchmark of `campaign --guided` against the uniform sweep.

For each testbed and each seed base, run one guided and one uniform campaign
over the same instrumented artifact and spec, watch every generation's
`PATINA_CAMPAIGN_GEN` line, and stop at the first generation whose class is
the testbed's target: that generation's index plus one is the campaign's
generations-to-find. A campaign that reaches the cap without it is censored.
Campaign derivation is deterministic, so the same binary, seed bases and cap
reproduce every number.

Per testbed it reports how many seed bases each mode found the target in,
the quartiles of generations-to-find (censored runs count as beyond the cap),
and the paired result: seed bases where guided found it sooner, later, or at
the same generation, with an exact two-sided sign test over the untied pairs.

A measurement, not a gate: it exits 0 whatever the comparison says, 1 when a
run fails in a way that makes the numbers meaningless, and 3 when a build
fails.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parent.parent
WORKQ_ARGS = ('--seed', '7', '--base-port', '5001', '--data-dir', '/workq',
              '--segment-bytes', '256', '--crash-at-completed', '6',
              '--ack-ledger', '/workq-acks')


@dataclass(frozen=True)
class Testbed:
    name: str
    # The guest to build: a single Rust source file or a package directory.
    source: str
    # Campaign flags shared by both modes.
    flags: Tuple[str, ...]
    guest_args: Tuple[str, ...]
    # Generation classes that count as finding the planted bug.
    target: Tuple[str, ...]
    cap: int
    what: str


TESTBEDS = (
    Testbed('staircase', 'testbeds/guided-bench/staircase.rs',
            ('--faults=fs,sleep',), (),
            ('GUEST_ABORT', 'UNCLASSIFIED', 'VIOLATION'), 300,
            'three nested gates on fs error rate, short-write rate and sleep jitter'),
    Testbed('workq-fsync', 'testbeds/workq',
            ('--buggify', '--swarm', '--faults=net,sleep,crash', '--allow-unmet-sometimes'),
            WORKQ_ARGS + ('--bug', 'skip-wal-fsync'), ('VIOLATION',), 200,
            'workq skip-wal-fsync: an unsynced WAL record lost to a machine crash'),
    Testbed('workq-lock', 'testbeds/workq',
            ('--buggify', '--swarm', '--faults=net,sleep', '--allow-unmet-sometimes'),
            WORKQ_ARGS + ('--bug', 'apply-check-outside-lock'), ('VIOLATION',), 200,
            'workq apply-check-outside-lock: a double apply needing a duplicate delivery race'),
)


class BenchError(Exception):
    pass


# Process groups of running campaigns, killed if the benchmark stops early.
LIVE: set = set()
LIVE_LOCK = threading.Lock()


def kill_group(pgid: int) -> None:
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_checked(argv: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
    result = subprocess.run(argv, capture_output=True, text=True, **kwargs)
    if result.returncode != 0:
        raise BenchError(f'{" ".join(argv)} failed ({result.returncode}):\n{result.stderr[-2000:]}')
    return result


def build(patina: Optional[str], work: Path, testbeds: Sequence[Testbed]) -> Tuple[str, Dict[str, Path]]:
    if patina is None:
        run_checked(['cargo', 'build', '--release', '--quiet', '-p', 'cargo-patina'], cwd=ROOT)
        target = Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target'))
        patina = str(target / 'release' / 'cargo-patina')
    artifacts: Dict[str, Path] = {}
    env = dict(os.environ)
    env.setdefault('CARGO_TARGET_DIR', str(ROOT / 'target' / 'testbeds' / 'guided-bench'))
    for testbed in testbeds:
        if testbed.source in artifacts:
            continue
        output = work / (Path(testbed.source).stem + '-instrumented')
        run_checked([patina, 'patina', 'build', str(ROOT / testbed.source), '--instrument',
                     '--release', '--output', str(output)], cwd=ROOT, env=env)
        artifacts[testbed.source] = output
    return patina, artifacts


def staircase_reachable(patina: str, artifact: Path) -> bool:
    """Non-vacuity: at the knob ceiling the planted bug fires."""
    result = subprocess.run([patina, 'patina', 'run', str(artifact), '--seed', '1',
                             '--fs-error-permille', '100', '--fs-short-permille', '200',
                             '--sleep-jitter-nanos', '0..2550000'],
                            capture_output=True, text=True)
    return result.returncode != 0 and 'STAGE_THREE' in result.stdout


def generations_to_find(patina: str, artifact: Path, testbed: Testbed, seed_base: int,
                        guided: bool, out_dir: Path) -> Tuple[Optional[int], Optional[str]]:
    """The number of generations a campaign ran up to and including the first
    target-class generation, or None when it reached the cap without one, and
    for a guided campaign how that generation was derived (exploit, explore or
    none)."""
    argv = [patina, 'patina', 'campaign', str(artifact), '--gens', str(testbed.cap),
            '--seed-start', str(seed_base), '--no-verify', '--progress-every', '1',
            '--out-dir', str(out_dir), *testbed.flags]
    if guided:
        argv.append('--guided')
    argv += ['--', *testbed.guest_args]
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               text=True, start_new_session=True)
    with LIVE_LOCK:
        LIVE.add(process.pid)
    found = None
    steer = None
    seen = 0
    assert process.stdout is not None
    for line in process.stdout:
        if not line.startswith('PATINA_CAMPAIGN_GEN '):
            continue
        fields = dict(token.split('=', 1) for token in line.split()[1:] if '=' in token)
        seen += 1
        if fields.get('class') == 'INFRA':
            # A host-side failure is not a search that came up empty: counting
            # it as censored would bias the comparison.
            kill_group(process.pid)
            process.wait()
            raise BenchError(f'{testbed.name} seed base {seed_base} guided={guided}: generation '
                             f'{fields.get("generation")} is INFRA; see {out_dir}')
        if fields.get('class') in testbed.target:
            found = int(fields['generation']) + 1
            steer = fields.get('guided', '').split(':')[0] or None
            break
    if found is not None:
        kill_group(process.pid)
    process.wait()
    with LIVE_LOCK:
        LIVE.discard(process.pid)
    if found is None and (process.returncode not in (0, 1) or seen != testbed.cap):
        raise BenchError(f'{testbed.name} seed base {seed_base} guided={guided}: campaign '
                         f'exited {process.returncode} after {seen} of {testbed.cap} generations')
    return found, steer


def quartiles(values: Sequence[Optional[int]], cap: int) -> str:
    """Quartiles with censored runs sorted past the cap."""
    ordered = sorted(math.inf if value is None else value for value in values)

    def at(q: float) -> str:
        value = ordered[min(len(ordered) - 1, int(round(q * (len(ordered) - 1))))]
        return f'>{cap}' if value == math.inf else str(int(value))

    return f'{at(0.25)} / {at(0.5)} / {at(0.75)}'


def sign_test(wins: int, losses: int) -> float:
    """Exact two-sided binomial sign test p-value over untied pairs."""
    n = wins + losses
    if n == 0:
        return 1.0
    k = min(wins, losses)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def compare(guided: Sequence[Optional[int]], uniform: Sequence[Optional[int]]) -> Dict[str, object]:
    wins = losses = ties = 0
    for g, u in zip(guided, uniform):
        g_value = math.inf if g is None else g
        u_value = math.inf if u is None else u
        if g_value < u_value:
            wins += 1
        elif g_value > u_value:
            losses += 1
        else:
            ties += 1
    return {'guided_sooner': wins, 'guided_later': losses, 'ties': ties,
            'sign_test_p': sign_test(wins, losses)}


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--seeds', type=int, default=30, help='seed bases per testbed (default 30)')
    parser.add_argument('--seed-start', type=int, default=1, help='first seed base (default 1)')
    parser.add_argument('--testbed', action='append', choices=[t.name for t in TESTBEDS],
                        help='testbed to run (repeatable; default all)')
    parser.add_argument('--cap', type=int, help="generation cap (default: the testbed's own)")
    parser.add_argument('--jobs', type=int, default=4, help='concurrent campaigns (default 4)')
    parser.add_argument('--patina', help='a cargo-patina binary (default: build this checkout)')
    parser.add_argument('--work-dir', help='keep campaign out-dirs here (default: a temp dir)')
    parser.add_argument('--json', help='write every run and the summaries here')
    args = parser.parse_args(argv)

    selected = [t for t in TESTBEDS if args.testbed is None or t.name in args.testbed]
    if args.cap is not None:
        selected = [Testbed(**{**t.__dict__, 'cap': args.cap}) for t in selected]
    owned = None
    if args.work_dir:
        work = Path(args.work_dir)
        work.mkdir(parents=True, exist_ok=True)
    else:
        owned = tempfile.TemporaryDirectory(prefix='patina-guided-bench.')
        work = Path(owned.name)
    try:
        try:
            patina, artifacts = build(args.patina, work, selected)
        except BenchError as error:
            print(f'guided-bench: build failed: {error}', file=sys.stderr)
            return 3
        staircase = next((t for t in selected if t.name == 'staircase'), None)
        if staircase and not staircase_reachable(patina, artifacts[staircase.source]):
            print('guided-bench: the staircase bug is unreachable even at the knob ceiling',
                  file=sys.stderr)
            return 1

        seeds = range(args.seed_start, args.seed_start + args.seeds)
        jobs = [(t, s, g) for t in selected for s in seeds for g in (True, False)]

        def one(job):
            testbed, seed_base, guided = job
            mode = 'guided' if guided else 'uniform'
            out = work / f'{testbed.name}-{mode}-{seed_base}'
            shutil.rmtree(out, ignore_errors=True)
            return job, generations_to_find(patina, artifacts[testbed.source], testbed,
                                            seed_base, guided, out)

        results: Dict[Tuple[str, int, bool], Optional[int]] = {}
        steers: Dict[Tuple[str, int], str] = {}
        pool = ThreadPoolExecutor(max_workers=args.jobs)
        try:
            for (testbed, seed_base, guided), (found, steer) in pool.map(one, jobs):
                results[(testbed.name, seed_base, guided)] = found
                if steer:
                    steers[(testbed.name, seed_base)] = steer
                print(f'{testbed.name} seed_base={seed_base} '
                      f'{"guided " if guided else "uniform"} '
                      f'found_at={found if found is not None else f">{testbed.cap}"}',
                      file=sys.stderr, flush=True)
        finally:
            # On an error or an interrupt, stop the running campaigns before
            # waiting for their threads.
            with LIVE_LOCK:
                for pgid in LIVE:
                    kill_group(pgid)
            pool.shutdown(wait=True, cancel_futures=True)
    except BenchError as error:
        print(f'guided-bench: {error}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('guided-bench: interrupted', file=sys.stderr)
        return 130
    finally:
        if owned is not None:
            owned.cleanup()

    summaries = []
    print('| testbed | cap | seeds | guided found | uniform found | guided q1/median/q3 '
          '| uniform q1/median/q3 | guided sooner / later / tie | sign test p '
          '| guided finds by exploit / explore / none |')
    print('|---|---|---|---|---|---|---|---|---|---|')
    for testbed in selected:
        guided = [results[(testbed.name, s, True)] for s in seeds]
        uniform = [results[(testbed.name, s, False)] for s in seeds]
        paired = compare(guided, uniform)
        summary = {
            'testbed': testbed.name, 'what': testbed.what, 'cap': testbed.cap,
            'seed_bases': list(seeds), 'guided': guided, 'uniform': uniform, **paired,
            'guided_found_by': [steers.get((testbed.name, s)) for s in seeds],
        }
        found_by = [steers.get((testbed.name, s)) for s in seeds]
        summaries.append(summary)
        print(f'| {testbed.name} | {testbed.cap} | {len(seeds)} '
              f'| {sum(v is not None for v in guided)} | {sum(v is not None for v in uniform)} '
              f'| {quartiles(guided, testbed.cap)} | {quartiles(uniform, testbed.cap)} '
              f'| {paired["guided_sooner"]} / {paired["guided_later"]} / {paired["ties"]} '
              f'| {paired["sign_test_p"]:.3g} '
              f'| {found_by.count("exploit")} / {found_by.count("explore")} / '
              f'{found_by.count("none")} |')
    if args.json:
        Path(args.json).write_text(json.dumps({'schema': 'patina.guided-bench/v1',
                                               'testbeds': summaries}, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
