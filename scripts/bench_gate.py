"""Blocking benchmark policy. Samples are resampled as whole paired ABBA blocks."""
import hashlib
import json
import math
import random
import statistics

SCHEMA = 'patina.bench-gate/v1'
EXIT = {'pass': 0, 'inconclusive': 4, 'regress': 5}


def interval_verdict(interval, threshold):
    if interval is None:
        return 'inconclusive'
    lo, hi = interval
    if not (math.isfinite(lo) and math.isfinite(hi) and 0 < lo <= hi):
        return 'inconclusive'
    if hi <= threshold:
        return 'pass'
    if lo > threshold:
        return 'regress'
    return 'inconclusive'


def paired_ratio(blocks, metric='wall_s', rounds=4000):
    """Ratio of median wall times with whole paired blocks resampled.

    Never independently resample the two sides: a draw retains all four ABBA
    observations. Medians retain the original elapsed-time estimand.
    """
    if len(blocks) < 10:
        return None
    pairs = []
    for block in blocks:
        a1, b1, b2, a2 = [sample[metric] for sample in block]
        if not all(math.isfinite(v) and (metric == 'hot_ns_per_op' or v > 0)
                   for v in (a1, b1, b2, a2)):
            return None
        pairs.append(((a1, a2), (b1, b2)))
    def estimate(draw):
        a = [v for pair in draw for v in pair[0]]
        b = [v for pair in draw for v in pair[1]]
        am, bm = statistics.median(a), statistics.median(b)
        # A differenced timing may be negative. Retain it in every paired draw;
        # uncertain/nonpositive medians have unbounded ratio uncertainty, rather
        # than making one noisy observation poison all subsequent extensions.
        if bm <= 0:
            return -math.inf
        if am <= 0:
            return math.inf
        return bm / am
    rng = random.Random(0)
    boot = sorted(estimate(rng.choices(pairs, k=len(pairs))) for _ in range(rounds))
    point = estimate(pairs)
    interval = [boot[int(rounds * .025)], boot[int(rounds * .975) - 1]]
    if not all(math.isfinite(v) and v > 0 for v in [point, *interval]):
        return None
    return {'median': point, 'ci95': interval}


def noise_ok(noise, threshold):
    return (noise is not None and noise['ci95'][0] >= 1 / threshold
            and noise['ci95'][1] <= threshold
            and noise['ci95'][1] - noise['ci95'][0] <= threshold - 1)


def combine(verdicts):
    verdicts = list(verdicts)
    if 'regress' in verdicts:
        return 'regress'
    if not verdicts or 'inconclusive' in verdicts:
        return 'inconclusive'
    return 'pass'


def valid_identity(identity):
    def digest(value, length):
        return (isinstance(value, str) and len(value) == length
                and all(c in '0123456789abcdef' for c in value))
    rows = identity.get('workloads', [])
    return (bool(identity.get('toolchain')) and bool(rows)
            and all(digest(identity.get(side, {}).get('rev'), 40)
                    and digest(identity.get(side, {}).get('binary_sha256'), 64)
                    for side in ('candidate', 'base'))
            and identity.get('workload_set_sha256') ==
            hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest())


def evaluate(records, identity, fixed_work=None, fixed_work_run=False, explanation=''):
    """Fail closed on missing workloads/noise/counts and stale fixed-work proof.

    Fixed-work evidence uses elapsed time for the same guest inputs; it never
    divides by a changed boundary count. Its whole gate must pass separately.
    """
    fixed_valid = (fixed_work is not None and fixed_work.get('schema') == SCHEMA
                   and fixed_work.get('identity') == identity
                   and fixed_work.get('mode') == 'fixed-work'
                   and fixed_work.get('verdict') == 'pass'
                   and bool(fixed_work.get('op_count_explanation')))
    rows = []
    for record in records:
        threshold = 1.05 if record.get('hot_path') else 1.02
        metric = ('hot_ns_per_op' if record.get('hot_path') and not fixed_work_run
                  and record.get('blocks')
                  and record['blocks'][0][0].get('hot_ns_per_op') is not None else 'wall_s')
        ratio = paired_ratio(record.get('blocks', []), metric)
        elapsed_ratio = paired_ratio(record.get('blocks', []))
        noise = paired_ratio(record.get('noise_blocks', []), metric)
        verdict = interval_verdict(ratio and ratio['ci95'], threshold)
        # A/A must establish a two-sided noise floor inside this class's budget.
        quiet = noise_ok(noise, threshold)
        counts = record.get('op_counts', {})
        count_ok = (set(counts) == {'baseline', 'patina'}
                    and all(isinstance(v, int) and v > 0 for v in counts.values()))
        changed = count_ok and counts['baseline'] != counts['patina']
        work_ok = not changed or fixed_valid or (fixed_work_run and bool(explanation))
        if record.get('status') != 'ok' or not quiet or not count_ok:
            verdict = 'inconclusive'
        elif not work_ok:
            verdict = combine([verdict, 'inconclusive'])
        rows.append({'workload': record['workload'], 'threshold': threshold,
                     'metric': metric, 'ratio': ratio, 'elapsed_ratio': elapsed_ratio, 'noise': noise, 'noise_ok': quiet,
                     'op_counts': counts, 'count_changed': changed,
                     'fixed_work_ok': work_ok, 'verdict': verdict})
    expected = [w['name'] for w in identity['workloads']]
    verdict = combine(row['verdict'] for row in rows)
    if not valid_identity(identity) or sorted(r['workload'] for r in records) != sorted(expected):
        verdict = combine([verdict, 'inconclusive'])
    return {'schema': SCHEMA, 'identity': identity,
            'mode': 'fixed-work' if fixed_work_run else 'comparison',
            'op_count_explanation': explanation, 'workloads': rows,
            'fixed_work_evidence': fixed_work if fixed_valid else None,
            'verdict': verdict, 'exit_code': EXIT[verdict]}
