#!/usr/bin/env python3
"""Offline parser/provenance detectors for the explicit syscall maintainer tool."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

# Importing the maintainer module must not leave source-tree bytecode artifacts.
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    'refresh_syscalls', Path(__file__).with_name('refresh-syscalls.py'))
refresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(refresh)


class RefreshSyscallsTests(unittest.TestCase):
    def select_latest(self, pinned, candidates, xnu_pinned='xnu-12377.1.9',
                      xnu_latest='xnu-12377.1.9'):
        records = [['linux', pinned, '', 'linux-table', '', ''],
                   ['darwin', xnu_pinned, '', 'xnu-table', '', '']]
        def fetch(url):
            if url == 'https://www.kernel.org/releases.json':
                value = {'releases': [{'moniker': 'stable', 'version': v}
                                      for v in candidates]}
            elif '/tags?' in url:
                value = [{'name': xnu_latest}]
            elif '/commits/' in url:
                value = {'sha': 'a' * 40}
            else:
                self.fail(f'unexpected fetch: {url}')
            return json.dumps(value).encode()
        with patch.object(refresh, 'fetch', side_effect=fetch):
            return refresh.latest(records)

    def test_latest_linux_release_ordering(self):
        # Class pairing: latest selection must respect Linux release ordering,
        # not variable-width numeric tuples or XNU's independent tag numbering.
        for pinned, candidates, expected in [
                ('7.2.0-rc4', ['7.1.9', '7.2'], '7.2'),
                ('7.2.0-rc4', ['7.2.0'], '7.2.0'),
                ('7.2.0', ['7.2'], '7.2'),
                ('7.2', ['7.2.0'], '7.2.0'),
                ('7.2', ['7.2.1', '7.2'], '7.2.1')]:
            with self.subTest(pinned=pinned, candidates=candidates):
                self.assertEqual(self.select_latest(pinned, candidates)[0][1], expected)
        for pinned, candidate in [('7.2', '7.1.99'), ('7.2.1', '7.2'),
                                  ('7.2', '7.2-rc9'), ('7.2-rc4', '7.2-rc3')]:
            with self.subTest(pinned=pinned, candidate=candidate):
                with self.assertRaisesRegex(ValueError, 'refusing inventory downgrade'):
                    self.select_latest(pinned, [candidate])
        self.assertEqual(self.select_latest('7.2-rc4', ['7.2-rc5'])[0][1], '7.2-rc5')

    def test_latest_rejects_malformed_linux_versions(self):
        for bad in ['7', '7.2.', '7.2.0.1', 'v7.2', '7.2-rc',
                    '7.2-rc0', '7.2-rc4-extra', '7.2junk', '']:
            for pinned, candidates in [(bad, ['7.2']), ('7.2', [bad])]:
                with self.subTest(pinned=pinned, candidates=candidates):
                    with self.assertRaisesRegex(ValueError, 'invalid Linux release'):
                        self.select_latest(pinned, candidates)

    def test_latest_xnu_uses_its_own_tag_numbers(self):
        self.assertEqual(self.select_latest('7.2', ['7.2'],
                         'xnu-12377.1.9', 'xnu-12377.2.0')[1][1], 'xnu-12377.2.0')
        with self.assertRaisesRegex(ValueError, 'refusing inventory downgrade'):
            self.select_latest('7.2', ['7.2'], 'xnu-12377.1.9', 'xnu-12377.1.8')

    def test_provenance_rejects_mixed_revisions_and_mismatched_urls(self):
        # Class pairing: every immutable source record must belong to its OS pin.
        text = refresh.OUTPUT.read_text()
        records = refresh.provenance(text)
        self.assertEqual({row[0] for row in records}, {'linux', 'darwin'})
        for old, new in [(records[0][2], '0' * 40),
                         (records[0][4], 'https://example.invalid/source')]:
            with self.subTest(old=old), self.assertRaises(ValueError):
                refresh.provenance(text.replace(old, new, 1))

    def test_download_hash_mismatch_is_not_accepted(self):
        records = copy.deepcopy(refresh.provenance(refresh.OUTPUT.read_text()))
        with patch.object(refresh, 'fetch', return_value=b'wrong source'):
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                refresh.download(records)

    def test_linux_duplicate_number_name_and_unknown_abi_are_refused(self):
        selector = 'syscall_abis_64 += renameat rlimit memfd_secret\n'
        valid = '0 common read sys_read\n1 common write sys_write\n'
        self.assertEqual(len(refresh.linux(valid, 'x86_64', selector)), 2)
        for bad in [valid + '0 common other sys_other\n',
                    valid + '2 common read sys_read\n',
                    valid + '2 unknown other sys_other\n']:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                refresh.linux(bad, 'x86_64', selector)
        with self.assertRaisesRegex(ValueError, 'ABI selection changed'):
            refresh.linux(valid, 'aarch64', selector + 'syscall_abis_64 += new\n')

    def test_darwin_guards_holes_and_invalid_alternatives_are_preserved(self):
        valid = ('0 AUE_NULL ALL { int nosys(void); }\n'
                 '#if FEATURE\n1 AUE_NULL ALL { int operation(void); }\n'
                 '#else\n1 AUE_NULL ALL { int enosys(void); }\n#endif\n')
        rows = refresh.darwin_table(valid, 'bsd')
        self.assertEqual(rows[0]['variants'][0]['table_status'], 'nosys')
        self.assertEqual([v['condition'] for v in rows[1]['variants']],
                         ['FEATURE', '!(FEATURE)'])
        self.assertEqual(rows[1]['variants'][1]['table_status'], 'enosys')
        for bad in [valid.replace('1 AUE_NULL', '2 AUE_NULL'),
                    valid.replace('#else\n1 AUE_NULL ALL { int enosys(void); }\n', ''),
                    valid.replace('#endif\n', ''),
                    valid.replace('#if FEATURE', '#if FEATURE\n#if OTHER')]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                refresh.darwin_table(bad, 'bsd')

    def test_generated_numbers_and_guards_follow_source_and_detect_mutations(self):
        # Class pairing: source-to-Rust translation must preserve identity and guards,
        # independently of runtime support and the checked-in source hash.
        linux = refresh.linux('37 common fixture sys_fixture\n', 'x86_64',
                              'syscall_abis_64 += renameat rlimit memfd_secret\n')
        darwin = refresh.darwin_table(
            '#if FEATURE\n0 AUE_NULL ALL { int fixture(void); }\n'
            '#else\n0 AUE_NULL ALL { int nosys(void); }\n#endif\n', 'bsd')
        records = refresh.provenance(refresh.OUTPUT.read_text())
        with patch.object(refresh, 'inventories', return_value=(linux, linux, darwin)):
            output = refresh.generate(records, {})
        def verify(text):
            self.assertEqual(text.count('N_fixture = 37,'), 2)
            self.assertIn('condition: Some("FEATURE")', text)
            self.assertIn('condition: Some("!(FEATURE)")', text)
            self.assertIn('table_status: "nosys"', text)
            self.assertIn('#[cfg(all(target_os = "linux", target_arch = "x86_64"))]', text)
            self.assertIn('#[cfg(all(target_os = "macos", target_arch = "aarch64"))]', text)
        verify(output)
        for mutation in [output.replace('N_fixture = 37,', 'N_fixture = 38,', 1),
                         output.replace('condition: Some("FEATURE")', 'condition: None', 1),
                         output.replace('table_status: "nosys"', 'table_status: "declared"')]:
            with self.assertRaises(AssertionError):
                verify(mutation)


if __name__ == '__main__':
    unittest.main()
