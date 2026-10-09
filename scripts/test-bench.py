#!/usr/bin/env python3
"""Offline tests for scripts/bench.py's statistics and record parsing."""
import importlib.util
import hashlib
import json
from pathlib import Path
import random
import sys
import tempfile
import types
import unittest
from contextlib import ExitStack
from unittest.mock import patch

# Importing the benchmark module must not leave source-tree bytecode artifacts.
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('bench', Path(__file__).with_name('bench.py'))
bench = importlib.util.module_from_spec(spec)
# dataclasses resolve their annotations through the module registry.
sys.modules['bench'] = bench
spec.loader.exec_module(bench)


class StatisticsTests(unittest.TestCase):
    def test_percentile_interpolates_between_order_statistics(self):
        values = [4.0, 1.0, 3.0, 2.0]
        self.assertEqual(bench.median(values), 2.5)
        self.assertAlmostEqual(bench.percentile(values, 90), 3.7)
        self.assertEqual(bench.percentile(values, 0), 1.0)
        self.assertEqual(bench.percentile(values, 100), 4.0)
        self.assertEqual(bench.median([7.0]), 7.0)

    def test_summary_is_order_independent(self):
        values = [0.5, 0.1, 0.9, 0.3, 0.7]
        shuffled = list(values)
        random.Random(3).shuffle(shuffled)
        self.assertEqual(bench.summarize(values), bench.summarize(shuffled))
        self.assertEqual(bench.summarize(values)['min'], 0.1)
        self.assertEqual(bench.summarize(values)['max'], 0.9)

    def test_ratio_of_medians_and_its_interval(self):
        base = [1.0, 1.1, 0.9, 1.05, 0.95]
        doubled = [2 * v for v in base]
        ratio = bench.ratio_of_medians(base, doubled, random.Random(0))
        self.assertAlmostEqual(ratio['median'], 2.0)
        lo, hi = ratio['ci95']
        self.assertLessEqual(lo, ratio['median'])
        self.assertGreaterEqual(hi, ratio['median'])
        # Resampling noisy series widens the interval; constant ones do not.
        self.assertLess(lo, hi)
        flat = bench.ratio_of_medians([1.0] * 5, [1.0] * 5, random.Random(0))
        self.assertEqual(flat, {'median': 1.0, 'ci95': [1.0, 1.0]})

    def test_ratio_is_deterministic_for_a_seeded_generator(self):
        base, subject = [1.0, 1.2, 0.8], [1.5, 1.1, 1.3]
        self.assertEqual(bench.ratio_of_medians(base, subject, random.Random(0)),
                         bench.ratio_of_medians(base, subject, random.Random(0)))

    def test_ratio_against_a_zero_base_is_absent(self):
        self.assertIsNone(bench.ratio_of_medians([0.0, 0.0], [1.0, 1.0], random.Random(0)))
        self.assertIsNone(bench.ratio_of_minima([0.0, 1.0], [1.0, 1.0]))

    def test_ratio_of_minima_ignores_disturbed_runs(self):
        # One slow outlier per side moves the medians' ratio, not the minima's.
        self.assertAlmostEqual(bench.ratio_of_minima([1.0, 5.0, 1.1], [2.0, 2.2, 9.0]), 2.0)


class GateTests(unittest.TestCase):
    def record(self, ratio=1.0, counts=(100, 100)):
        block = lambda r: [{'wall_s': v} for v in (1.0, r, r, 1.0)]
        return {'workload': 'w', 'status': 'ok', 'blocks': [block(ratio)] * 10,
                'noise_blocks': [block(1.0)] * 10,
                'op_counts': dict(zip(('baseline', 'patina'), counts))}

    def evaluate(self, record, **kwargs):
        identity = {'candidate': {'rev': 'c' * 40, 'binary_sha256': 'c' * 64},
                    'base': {'rev': 'b' * 40, 'binary_sha256': 'b' * 64},
                    'toolchain': 'rustc pinned', 'workloads': [{'name': 'w'}]}
        identity['workload_set_sha256'] = hashlib.sha256(
            json.dumps(identity['workloads'], sort_keys=True).encode()).hexdigest()
        return bench.bench_gate.evaluate([record], identity, **kwargs)

    def test_interval_straddling_budget_is_inconclusive_exit_four(self):
        verdict = bench.bench_gate.interval_verdict([1.00, 1.06], 1.02)
        self.assertEqual(bench.bench_gate.EXIT[verdict], 4)

    def test_planted_three_percent_regression_exits_five(self):
        self.assertEqual(self.evaluate(self.record(1.03))['exit_code'], 5)

    def test_tight_aa_passes_exit_zero(self):
        self.assertEqual(self.evaluate(self.record())['exit_code'], 0)

    def test_changed_ops_requires_separate_fixed_work_pass_and_explanation(self):
        changed = self.record(counts=(100, 110))
        self.assertEqual(self.evaluate(changed)['exit_code'], 4)
        proof = self.evaluate(changed, fixed_work_run=True, explanation='extra clock door')
        self.assertEqual(proof['exit_code'], 0)
        self.assertEqual(self.evaluate(changed, fixed_work=proof)['exit_code'], 0)
        proof['identity']['candidate']['rev'] = 'stale'
        self.assertEqual(self.evaluate(changed, fixed_work=proof)['exit_code'], 4)
        failed = self.evaluate(self.record(1.03, (100, 110)), fixed_work_run=True,
                               explanation='extra clock door')
        self.assertEqual(self.evaluate(changed, fixed_work=failed)['exit_code'], 4)
        # Fixed-work does not waive the ordinary elapsed-time budget.
        self.assertEqual(failed['exit_code'], 5)

    def test_pairing_cancels_linear_block_drift(self):
        blocks = [[{'wall_s': scale * v} for v in (1, 2, 3, 4)]
                  for scale in [1] * 10]
        result = bench.bench_gate.paired_ratio(blocks)
        self.assertEqual(result['ci95'], [1.0, 1.0])

    def test_bootstrap_preserves_the_median_estimand(self):
        record = self.record()
        record['blocks'] = (self.record(1.03)['blocks'][:6] +
                            self.record(.8)['blocks'][:4])
        verdict = self.evaluate(record)
        self.assertEqual(verdict['workloads'][0]['ratio']['median'], 1.03)
        self.assertNotEqual(verdict['exit_code'], 0)

    def test_missing_noisy_or_unsupported_evidence_cannot_pass(self):
        for change in ({'noise_blocks': []}, {'blocks': []}, {'op_counts': {}},
                       {'status': 'unsupported'}):
            self.assertEqual(self.evaluate(dict(self.record(), **change))['exit_code'], 4)
        record = self.record()
        record['noise_blocks'] = (self.record(.94)['blocks'][:5] +
                                  self.record(1.04)['blocks'][:5])
        self.assertEqual(self.evaluate(record)['exit_code'], 4)

    def test_hot_path_has_its_own_five_percent_gate(self):
        self.assertEqual(self.evaluate(dict(self.record(1.03), hot_path=True))['exit_code'], 0)
        self.assertEqual(self.evaluate(dict(self.record(1.06), hot_path=True))['exit_code'], 5)

    def test_signed_slope_noise_can_resolve_without_discarding_observations(self):
        record = dict(self.record(), hot_path=True)
        for name in ('blocks', 'noise_blocks'):
            record[name] = [[dict(sample, hot_ns_per_op=-10) for sample in block]
                            for block in record[name]]
        self.assertEqual(self.evaluate(record)['exit_code'], 4)
        for name in ('blocks', 'noise_blocks'):
            quiet = [[dict(sample, hot_ns_per_op=10) for sample in block]
                     for block in self.record()['blocks']]
            record[name] += quiet * 10
        self.assertEqual(self.evaluate(record)['exit_code'], 0)
        for name in ('blocks', 'noise_blocks'):
            record[name][0][0]['hot_ns_per_op'] = float('nan')
        self.assertEqual(self.evaluate(record)['exit_code'], 4)

    def test_missing_commit_or_toolchain_cannot_pass(self):
        proof = self.evaluate(self.record())
        for change in ({'toolchain': None}, {'base': {}}, {'workload_set_sha256': 'stale'}):
            identity = dict(proof['identity'], **change)
            self.assertEqual(bench.bench_gate.evaluate([self.record()], identity)['exit_code'], 4)

    def test_per_op_speedup_does_not_exempt_extra_work(self):
        record = dict(self.record(1.03, (100, 200)), hot_path=True)
        for block in record['blocks']:
            for sample, value in zip(block, (10, 5, 5, 10)):
                sample['hot_ns_per_op'] = value
        for block in record['noise_blocks']:
            for sample in block:
                sample['hot_ns_per_op'] = 10
        self.assertEqual(self.evaluate(record)['exit_code'], 4)
        # Fixed-work retains elapsed time even if normalization looks faster.
        record['blocks'] = [[dict(sample, wall_s=sample['wall_s'] *
                                (1.1 if index in (1, 2) else 1))
                            for index, sample in enumerate(block)] for block in record['blocks']]
        self.assertEqual(self.evaluate(record, fixed_work_run=True,
                                       explanation='extra ops')['exit_code'], 5)

    def test_invalid_gate_invocations_are_usage_errors(self):
        for args in (['--gate'], ['--gate', '--baseline', '@', '--runs', '9']):
            with self.assertRaises(SystemExit) as caught:
                bench.parse_args(args)
            self.assertEqual(caught.exception.code, 2)


class VerificationTests(unittest.TestCase):
    """Class pairing: one verifier owns comparison, source and artifact checks."""
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.home = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.cli = self.home / 'candidate'
        self.cli.write_bytes(b'candidate artifact')
        self.base = self.home / 'base'
        self.base.mkdir()
        self.base_cli = self.base / 'cargo-patina'
        self.base_cli.write_bytes(b'base artifact')
        opts = bench.parse_args(['--baseline', 'main', '--workload', 'startup'])
        rows, digest = bench.workload_identity(opts, [bench.WORKLOADS[0]])
        self.identity = {'candidate': {'rev': 'c' * 40, 'binary_sha256': self.hash(self.cli)},
                         'base': {'rev': 'b' * 40, 'binary_sha256': self.hash(self.base_cli)},
                         'toolchain': 'rustc pinned', 'seed': 1,
                         'workloads': rows, 'workload_set_sha256': digest}
        self.verdict = {'schema': bench.bench_gate.SCHEMA, 'mode': 'comparison',
                        'verdict': 'pass', 'exit_code': 0, 'identity': self.identity}
        self.stack.enter_context(patch.object(bench, 'commit_id', return_value='c' * 40))
        self.stack.enter_context(patch.object(bench, 'resolve_rev', return_value='b' * 40))
        self.stack.enter_context(patch.object(bench, 'build_cargo_patina', return_value=self.cli))
        self.stack.enter_context(patch.object(bench, 'build_baseline',
            return_value=(self.base_cli, self.identity['base'], self.base)))
        self.stack.enter_context(patch.object(bench, 'vcs', return_value='jj'))
        names = ('patina-dst-native-shim', 'patina-dst-runtime', 'patina-dst-bench',
                 'patina-dst-driver-api', 'patina-dst-time-virtual', 'patina-dst-sched-det')
        self.metadata = {'packages': [dict(id=name, name=name,
            manifest_path=str(bench.ROOT / 'crates' / name.replace('patina-dst-', 'patina-')
                              / 'Cargo.toml')) for name in names],
            'resolve': {'nodes': [dict(id=name, deps=[]) for name in names]}}
        def dependency(name, kind=None):
            return dict(pkg=name, dep_kinds=[dict(kind=kind)])
        self.metadata['resolve']['nodes'][0]['deps'] = [dependency(names[1])]
        self.metadata['resolve']['nodes'][1]['deps'] = [dependency(name) for name in names[3:]]
        self.metadata['resolve']['nodes'][2]['deps'] = [dependency(names[1])]
        self.stack.enter_context(patch.object(bench, 'cargo_metadata', return_value=self.metadata))
        self.stack.enter_context(patch.object(bench, 'output', side_effect=lambda cmd:
            json.dumps('crates/patina-runtime/src/lib.rs') if 'diff' in cmd else 'rustc pinned'))

    @staticmethod
    def hash(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def verify(self):
        path = self.home / 'verdict.json'
        path.write_text(json.dumps(self.verdict))
        return bench.main(['--verify', str(path), '--baseline', 'main',
                           '--workload', 'startup', '--scratch-dir', str(self.home)])

    def test_fixed_work_alone_cannot_verify_a_hot_path_regression(self):
        record = dict(GateTests().record(1.01), hot_path=True)
        for blocks, values in ((record['blocks'], (10, 12, 12, 10)),
                               (record['noise_blocks'], (10, 10, 10, 10))):
            for block in blocks:
                for sample, value in zip(block, values): sample['hot_ns_per_op'] = value
        gate = GateTests()
        self.assertEqual(gate.evaluate(record)['exit_code'], 5)
        self.verdict = gate.evaluate(record, fixed_work_run=True, explanation='changed doors')
        self.assertEqual(self.verdict['exit_code'], 0)
        self.verdict['identity'] = self.identity
        self.assertEqual(self.verify(), 4)

    def test_changed_cli_artifact_cannot_reuse_the_same_revision_verdict(self):
        self.assertEqual(self.verify(), 0)
        for path in (self.cli, self.base_cli):
            original = path.read_bytes()
            path.write_bytes(b'rebuilt with different optimization')
            self.assertEqual(self.verify(), 4)
            path.write_bytes(original)

    def test_context_hashes_are_verified_for_both_actual_artifacts(self):
        workload = next(w for w in bench.WORKLOADS if w.name == 'context')
        opts = bench.parse_args(['--baseline', 'main', '--workload', 'context'])
        rows, digest = bench.workload_identity(opts, [workload])
        self.identity['workloads'], self.identity['workload_set_sha256'] = rows, digest
        candidate = self.home / 'context'
        baseline = self.base / 'patina-dst-bench'
        candidate.write_bytes(b'candidate Context')
        baseline.write_bytes(b'baseline Context')
        self.identity['context_binary_sha256'] = {'patina': self.hash(candidate),
                                                 'baseline': self.hash(baseline)}
        path = self.home / 'verdict.json'
        def verify():
            path.write_text(json.dumps(self.verdict))
            return bench.main(['--verify', str(path), '--baseline', 'main',
                               '--workload', 'context', '--scratch-dir', str(self.home)])
        with patch.object(bench, 'cargo_binary', return_value=candidate):
            self.assertEqual(verify(), 0)
            for artifact in (candidate, baseline):
                original = artifact.read_bytes()
                artifact.write_bytes(b'changed Context artifact')
                self.assertEqual(verify(), 4)
                artifact.write_bytes(original)

    def test_landing_requires_shim_and_exercised_driver_changes(self):
        for path in ('crates/patina-native-shim/c/posix/core.c',
                     'crates/patina-runtime/src/lib.rs',
                     'crates/patina-time-virtual/src/lib.rs',
                     'crates/patina-driver-api/src/filesystem.rs'):
            with self.subTest(path=path), patch.dict(bench.os.environ, {}, clear=True), \
                    patch.object(bench, 'output', return_value=json.dumps(path)):
                self.assertEqual(bench.main(['--verify-landing']), 4)

    def test_landing_requires_compiled_build_module(self):
        with patch.dict(bench.os.environ, {}, clear=True), patch.object(bench, 'output',
                return_value=json.dumps('crates/patina-native-shim/symbol_metadata.rs')):
            self.assertEqual(bench.main(['--verify-landing']), 4)

    def test_landing_requires_local_path_dependency_in_any_layout(self):
        package = dict(id='helper', name='helper', manifest_path='')
        self.metadata['packages'].append(package)
        self.metadata['resolve']['nodes'].append(dict(id='helper', deps=[]))
        self.metadata['resolve']['nodes'][0]['deps'].append(
            dict(pkg='helper', dep_kinds=[dict(kind='build')]))
        for directory in ('crates/vendor/helper', 'support/helper'):
            package['manifest_path'] = str(bench.ROOT / directory / 'Cargo.toml')
            with self.subTest(directory=directory), patch.dict(bench.os.environ, {}, clear=True), \
                    patch.object(bench, 'output',
                        return_value=json.dumps(directory + '/src/lib.rs')):
                self.assertEqual(bench.main(['--verify-landing']), 4)

    def test_landing_exempts_cli_build_and_test_only_changes(self):
        paths = ('crates/cargo-patina/src/cli.rs', 'Cargo.toml', '.cargo/config.toml',
                 'crates/patina-wasi-host/src/lib.rs', 'scripts/bench.py',
                 'crates/patina-native-shim/README.md',
                 'crates/patina-runtime/tests/boot_origin.rs',
                 'crates/patina-runtime/benches/dispatch.rs',
                 'crates/patina-runtime/examples/deterministic.rs')
        for stack in ((paths[0],), paths[1:]):
            with self.subTest(paths=stack), patch.dict(bench.os.environ, {}, clear=True), \
                    patch.object(bench, 'output',
                        return_value='\n'.join(json.dumps(path) for path in stack)):
                self.assertEqual(bench.main(['--verify-landing']), 0)

    def test_landing_follows_new_transitive_driver_edges_but_not_dev_edges(self):
        name = 'new-driver'
        self.metadata['packages'].append(dict(id=name, name=name,
            manifest_path=str(bench.ROOT / 'crates' / name / 'Cargo.toml')))
        self.metadata['resolve']['nodes'].append(dict(id=name, deps=[]))
        edge = dict(pkg=name, dep_kinds=[dict(kind='dev')])
        self.metadata['resolve']['nodes'][3]['deps'].append(edge)
        with patch.dict(bench.os.environ, {}, clear=True), patch.object(bench, 'output',
                return_value=json.dumps('crates/new-driver/src/lib.rs')):
            self.assertEqual(bench.main(['--verify-landing']), 0)
            edge['dep_kinds'][0]['kind'] = None  # shared driver's production dependency
            self.assertEqual(bench.main(['--verify-landing']), 4)

    def test_landing_tip_verdict_covers_batch_but_parent_or_inconclusive_does_not(self):
        opts = bench.parse_args([])
        rows, digest = bench.workload_identity(opts, list(bench.WORKLOADS))
        self.identity['workloads'], self.identity['workload_set_sha256'] = rows, digest
        path = self.home / 'batch-verdict.json'
        paths = ('crates/patina-native-shim/src/clocks.rs',
                 'crates/patina-runtime/src/filesystem.rs',
                 'crates/patina-sched-det/src/lib.rs')
        def output(cmd):
            return '\n'.join(json.dumps(p) for p in paths) if 'diff' in cmd else 'rustc pinned'
        with patch.dict(bench.os.environ, {'PATINA_BENCH_VERDICT': str(path)}), \
                patch.object(bench, 'output', side_effect=output), \
                patch.object(bench, 'verify_artifacts', return_value=True):
            path.write_text(json.dumps(self.verdict))
            self.assertEqual(bench.main(['--verify-landing']), 0)
            self.identity['candidate']['rev'] = 'd' * 40  # verdict for a parent, not the tip
            path.write_text(json.dumps(self.verdict))
            self.assertEqual(bench.main(['--verify-landing']), 4)
            self.identity['candidate']['rev'] = 'c' * 40
            self.verdict.update(verdict='inconclusive', exit_code=4)
            path.write_text(json.dumps(self.verdict))
            self.assertEqual(bench.main(['--verify-landing']), 4)

    def test_landing_skips_docs_but_refuses_unknown_diff_or_stale_evidence(self):
        with patch.object(bench, 'output', return_value=json.dumps('docs/notes.md')):
            self.assertEqual(bench.main(['--verify-landing']), 0)
        with patch.object(bench, 'output', return_value=None):
            self.assertEqual(bench.main(['--verify-landing']), 4)
        path = self.home / 'verdict.json'
        path.write_text(json.dumps(self.verdict))  # a startup-only pass cannot cover all workloads
        with patch.dict(bench.os.environ, {'PATINA_BENCH_VERDICT': str(path)}):
            self.assertEqual(bench.main(['--verify-landing']), 4)


class ParsingTests(unittest.TestCase):
    def test_count_probe_reads_structured_trace_stats_and_refuses_missing_counts(self):
        # Class-level pairing: the gate refuses missing/invalid operation counts.
        workload = bench.Workload('w', 'bench', ('compute', '--iters', '1'), 'R')
        leg = bench.Leg('patina', Path('cli'), Path('home'))
        payload = {'schema': 'patina.result/v1', 'verb': 'trace', 'subcommand': 'stats',
                   'exit_code': 0, 'trace_stats': {'schema': 'patina.trace.stats/v1',
                                                 'totals': {'events': 17}}}
        def probe(stats):
            outputs = [bench.subprocess.CompletedProcess([], 0, 'R digest=1\n', ''),
                       bench.subprocess.CompletedProcess([], 0, json.dumps(stats), '')]
            with patch.object(bench.tempfile, 'TemporaryDirectory') as temp, \
                    patch.object(bench.subprocess, 'run', side_effect=outputs):
                temp.return_value.__enter__.return_value = '/virtual-count-probe'
                return bench.probe_op_count(leg, workload, 1, Path('scratch'),
                                            types.SimpleNamespace(timeout=1), lambda *_: None)
        observed = probe(payload)
        gate = GateTests()
        self.assertEqual(gate.evaluate(gate.record(counts=(observed, observed)))['exit_code'], 0)
        with self.assertRaises(bench.BenchError):
            probe(payload['trace_stats'])

    def test_result_is_the_last_prefixed_line_minus_dropped_fields(self):
        stdout = ('noise\nWORKQ_RESULT a=1 attempts=9 hash=x\n'
                  'WORKQ_RESULTS lookalike=1\nWORKQ_RESULT a=2 attempts=3 hash=y\n')
        self.assertEqual(bench.parse_result(stdout, 'WORKQ_RESULT', ('attempts',)),
                         'WORKQ_RESULT a=2 hash=y')
        # Dropping a schedule-sensitive field makes differing runs compare equal.
        self.assertEqual(bench.parse_result('P n=1 hb=4\n', 'P', ('hb',)),
                         bench.parse_result('P n=1 hb=7\n', 'P', ('hb',)))
        self.assertIsNone(bench.parse_result('WORKQ_RESULTS a=1\n', 'WORKQ_RESULT'))

    def test_launch_report_units(self):
        line = 'wall_ns=1500000000 utime_us=250000 stime_us=50000 maxrss=4096\n'
        self.assertEqual(bench.parse_launch_report(line, darwin=False), (1.5, 0.3, 4096))
        # macOS reports ru_maxrss in bytes.
        self.assertEqual(bench.parse_launch_report(line, darwin=True)[2], 4)

    def test_argument_templates(self):
        workload = bench.Workload('w', 'tb', ('--iters', '{n}', '--dir', '{dir}'), 'R', count=10)
        self.assertEqual(bench.expand(workload.args, bench.scaled_count(workload, 0.5), '/d'),
                         ['--iters', '5', '--dir', '/d'])
        self.assertEqual(bench.scaled_count(workload, 0.0001), 1)


class ResultCheckTests(unittest.TestCase):
    """run_workload's cross-run result comparison, with measure() stubbed."""

    def run_stubbed(self, results):
        """run_workload over a native and a patina leg whose every run prints
        results[leg name]."""
        workload = bench.Workload('w', 'bench', ('--iters', '{n}'), 'R', count=10)
        legs = [bench.Leg('native', None, Path('native')),
                bench.Leg('patina', Path('cargo-patina'), Path('patina'))]
        opts = types.SimpleNamespace(scale=1.0, commit='c', date='d', seed=1, runs=3, warmup=1,
                                     order_seed=0, baseline_info=None, sud=True,
                                     launcher=None, timeout=1.0)
        runs = iter(range(1, 1000))

        def measure(leg, *_):
            return bench.Sample(float(next(runs)), 0.5, 1024, results[leg.name])

        real, bench.measure = bench.measure, measure
        try:
            return bench.run_workload(workload, legs, opts, {'os': 'linux'},
                                      random.Random(0), Path('scratch'))
        finally:
            bench.measure = real

    def test_gate_extends_an_inconclusive_interval_before_passing(self):
        workload = bench.Workload('w', 'bench', (), 'R')
        legs = [bench.Leg('baseline', Path('base'), Path('base-home')),
                bench.Leg('patina', Path('candidate'), Path('candidate-home'))]
        opts = types.SimpleNamespace(scale=1.0, commit='c', date='d', seed=1, runs=20,
                                     max_runs=40, warmup=0, order_seed=0,
                                     baseline_info={}, sud=True, gate=True,
                                     launcher=None, timeout=1.0)
        candidate = iter([.98] * 10 + [1.06] * 10 + [1.0] * 100)
        def measure(leg, *_):
            return bench.Sample(next(candidate) if leg.name == 'patina' else 1.0,
                                1.0, 1024, 'R digest=1')
        with patch.object(bench, 'measure', measure), patch.object(bench, 'probe_op_count',
                                                                return_value=100):
            record = bench.run_workload(workload, legs, opts, {}, random.Random(0), Path('scratch'))
        initial = bench.bench_gate.paired_ratio(record['blocks'][:10])
        self.assertEqual(bench.bench_gate.interval_verdict(initial['ci95'], 1.02), 'inconclusive')
        self.assertEqual(GateTests().evaluate(record)['exit_code'], 0)

    def test_differing_results_fail_the_workload(self):
        with self.assertRaises(bench.BenchError) as caught:
            self.run_stubbed({'native': 'R digest=1', 'patina': 'R digest=2'})
        # The record keeps the short reason, which carries both result lines.
        self.assertIn('R digest=1', caught.exception.reason)
        self.assertIn('R digest=2', caught.exception.reason)

    def test_matching_results_produce_a_comparison(self):
        record = self.run_stubbed({'native': 'R digest=1', 'patina': 'R digest=1'})
        self.assertEqual(record['status'], 'ok')
        self.assertEqual(record['result'], 'R digest=1')
        self.assertEqual({len(leg['wall_s']) for leg in record['legs'].values()}, {3})
        self.assertIsNotNone(record['comparison']['wall_min_ratio'])


class ContextInterfaceTests(unittest.TestCase):
    def test_text_only_baseline_and_json_candidate_measure_the_same_op_mix(self):
        # Class pairing: detect each artifact's report interface before timing;
        # both interfaces measure the seeded loop, excluding qualification setup.
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            launcher = bench.build_launcher(home)
            samples = []
            workload = next(w for w in bench.WORKLOADS if w.testbed == 'context')
            for supports_json in (False, True):
                binary = home / ('json-context' if supports_json else 'text-context')
                binary.write_text(f'#!{sys.executable}\n' + f'json_mode={supports_json!r}\n' + '''
import json,sys
if '--help' in sys.argv:
 print('Usage: context --json iterations campaign' if json_mode else 'Usage: context iterations campaign')
 sys.exit(0)
if '--json' in sys.argv and not json_mode: sys.exit(2)
iterations=int(next(arg for arg in sys.argv[1:] if arg != '--json'))
ops=iterations*12
if json_mode:
 print(json.dumps(dict(iterations=iterations,boundary_ops=ops,seeded_nanos=ops*13.25,seeded_ns_per_op=13.25)))
else:
 print(f'workload iterations      : {iterations}\\nboundary ops per run     : {ops}\\nseeded ns/op             : 13.25')
''')
                binary.chmod(0o755)
                leg = bench.Leg('patina' if supports_json else 'baseline', Path('unused'),
                                home, context_binary=binary)
                leg.build('context')
                samples.append(bench.measure(leg, workload, 1, home, launcher, 5))
            self.assertEqual(samples[0].result, samples[1].result)
            for sample in samples:
                self.assertAlmostEqual(sample.hot_ns_per_op, 13.25)
                self.assertAlmostEqual(sample.wall_s * 1e9 / sample.ops, sample.hot_ns_per_op)


class WorkloadTableTests(unittest.TestCase):
    def test_workload_definitions_are_consistent(self):
        names = [w.name for w in bench.WORKLOADS]
        self.assertEqual(len(names), len(set(names)))
        for workload in bench.WORKLOADS:
            # A size placeholder needs a size, and a size needs a placeholder.
            self.assertEqual('{n}' in ' '.join(workload.args), workload.count > 0, workload.name)
            self.assertTrue((bench.ROOT / ('crates/patina-bench' if workload.testbed == 'context'
                                     else 'testbeds/' + workload.testbed) / 'Cargo.toml').is_file())


if __name__ == '__main__':
    unittest.main()
