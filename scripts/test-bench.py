#!/usr/bin/env python3
"""Offline tests for scripts/bench.py's statistics and record parsing."""
import importlib.util
from pathlib import Path
import random
import sys
import types
import unittest

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


class ParsingTests(unittest.TestCase):
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


class WorkloadTableTests(unittest.TestCase):
    def test_workload_definitions_are_consistent(self):
        names = [w.name for w in bench.WORKLOADS]
        self.assertEqual(len(names), len(set(names)))
        for workload in bench.WORKLOADS:
            # A size placeholder needs a size, and a size needs a placeholder.
            self.assertEqual('{n}' in ' '.join(workload.args), workload.count > 0, workload.name)
            self.assertTrue((bench.ROOT / 'testbeds' / workload.testbed / 'Cargo.toml').is_file())


if __name__ == '__main__':
    unittest.main()
