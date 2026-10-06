#!/usr/bin/env python3
"""File-size ratchet: no Rust source file grows past CAP lines.

A large file costs every reader, human or agent, a long page-through before a
small change. New files must stay at or under CAP. Files already over it are
listed in scripts/file-size-allowlist.txt with a ceiling equal to their current
size, so they can shrink but never grow. A split that brings a file down must
lower or remove its entry in the same change, which keeps the ratchet tight.
Generated files are exempt: their size follows their input.

Usage: scripts/check-file-size.py [--selftest]
"""
from dataclasses import dataclass
import os
from pathlib import Path
import sys
import unittest

CAP = 1500
ROOT = Path(__file__).resolve().parent.parent
ALLOWLIST = ROOT / 'scripts' / 'file-size-allowlist.txt'
SKIP_DIRS = {'target', '.git', '.jj'}


@dataclass(frozen=True)
class Entry:
    ceiling: int | None  # None: generated, exempt
    reason: str


def parse_allowlist(text):
    """`<path> <ceiling|generated> # <reason>` per line; `#` starts a comment."""
    entries = {}
    for number, raw in enumerate(text.splitlines(), 1):
        body, _, reason = raw.partition('#')
        fields = body.split()
        if not fields:
            continue
        if len(fields) != 2 or not reason.strip():
            raise ValueError(f'allowlist line {number}: want `<path> <ceiling|generated> # <reason>`')
        path, limit = fields
        if path in entries:
            raise ValueError(f'allowlist line {number}: duplicate entry for {path}')
        ceiling = None if limit == 'generated' else int(limit)
        entries[path] = Entry(ceiling, reason.strip())
    return entries


def violations(sizes, entries, cap=CAP):
    """Every way `sizes` (path -> lines) breaks the ratchet, as messages."""
    found = []
    for path, lines in sorted(sizes.items()):
        entry = entries.get(path)
        if entry is None:
            if lines > cap:
                found.append(f'{path}: {lines} lines, over the {cap}-line cap; split it')
        elif entry.ceiling is None:
            continue
        elif lines > entry.ceiling:
            found.append(f'{path}: {lines} lines, over its allowlisted ceiling of {entry.ceiling}; split it')
        elif lines <= cap:
            found.append(f'{path}: {lines} lines, now within the {cap}-line cap; remove its allowlist entry')
        elif lines < entry.ceiling:
            found.append(f'{path}: {lines} lines, below its ceiling of {entry.ceiling}; lower the ceiling to {lines}')
    for path in sorted(set(entries) - set(sizes)):
        found.append(f'{path}: allowlisted but missing; remove its entry')
    return found


def rust_sizes(root):
    sizes = {}
    for directory, subdirs, files in os.walk(root):
        subdirs[:] = [d for d in subdirs if d not in SKIP_DIRS and not (Path(directory) / d).is_symlink()]
        for name in files:
            if name.endswith('.rs'):
                path = Path(directory) / name
                with open(path, 'rb') as handle:
                    sizes[path.relative_to(root).as_posix()] = sum(1 for _ in handle)
    return sizes


class RatchetTests(unittest.TestCase):
    def test_new_file_over_cap_fails_and_at_cap_passes(self):
        self.assertEqual(len(violations({'a.rs': 11}, {}, cap=10)), 1)
        self.assertEqual(violations({'a.rs': 10}, {}, cap=10), [])

    def test_allowlisted_file_may_not_grow(self):
        entries = {'a.rs': Entry(20, 'r')}
        self.assertEqual(violations({'a.rs': 20}, entries, cap=10), [])
        self.assertEqual(len(violations({'a.rs': 21}, entries, cap=10)), 1)

    def test_shrinking_demands_a_tighter_entry(self):
        entries = {'a.rs': Entry(20, 'r')}
        self.assertIn('lower the ceiling to 15', violations({'a.rs': 15}, entries, cap=10)[0])
        self.assertIn('remove its allowlist entry', violations({'a.rs': 9}, entries, cap=10)[0])

    def test_generated_files_are_exempt(self):
        self.assertEqual(violations({'g.rs': 10**6}, {'g.rs': Entry(None, 'r')}, cap=10), [])

    def test_stale_entry_fails(self):
        self.assertEqual(len(violations({}, {'gone.rs': Entry(20, 'r')}, cap=10)), 1)

    def test_allowlist_requires_a_reason(self):
        with self.assertRaises(ValueError):
            parse_allowlist('a.rs 20\n')
        self.assertEqual(parse_allowlist('# header\na.rs generated # tables\n'),
                         {'a.rs': Entry(None, 'tables')})

    def test_repo_walk_counts_rust_files_only(self):
        sizes = rust_sizes(ROOT)
        self.assertTrue(sizes and all(path.endswith('.rs') for path in sizes))
        self.assertFalse(any(part in SKIP_DIRS for path in sizes for part in Path(path).parts))


def main():
    if sys.argv[1:] == ['--selftest']:
        sys.argv[1:] = []
        unittest.main(module=__name__)
    if sys.argv[1:]:
        print(__doc__, file=sys.stderr)
        return 2
    found = violations(rust_sizes(ROOT), parse_allowlist(ALLOWLIST.read_text()))
    for message in found:
        print(message, file=sys.stderr)
    return 1 if found else 0


if __name__ == '__main__':
    sys.exit(main())
