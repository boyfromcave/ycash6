#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Unit tests for qa/kogany_mixed_shards.py (no node, no network). Also checks the real manifest."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import kogany_mixed_shards as ms  # noqa: E402

TEXT = """
# comment
vault  vault_primitive   report W4 mirror
vault  vault_rpc         gate   W7
fees   yellowback_fees   report W5 mempool
node   kogany_mixed_smoke report W1 direct
excluded yellowback_framework_smoke peer-count
"""


class Parse(unittest.TestCase):
    def test_parse(self):
        entries, excluded, errors = ms.parse(TEXT)
        self.assertEqual(errors, [])
        self.assertEqual([e.script for e in entries],
                         ['vault_primitive', 'vault_rpc', 'yellowback_fees', 'kogany_mixed_smoke'])
        self.assertEqual(excluded, {'yellowback_framework_smoke': 'peer-count'})
        self.assertTrue(entries[3].direct)

    def test_errors(self):
        _, _, errors = ms.parse('vault x maybe W4\nnope y report W4\nvault z report X9\nvault w report W4 bogus\nvault short\n')
        self.assertEqual(len(errors), 5, errors)


class Check(unittest.TestCase):
    def setUp(self):
        self.entries, self.excluded, _ = ms.parse(TEXT)
        self.known = {'vault_primitive', 'vault_rpc', 'yellowback_fees'}

    def run_check(self, scripts, known=None, exists=lambda s: True):
        return ms.check(self.entries, self.excluded, scripts, self.known if known is None else known, exists)

    def test_complete(self):
        self.assertEqual(self.run_check(['vault_primitive', 'vault_rpc', 'yellowback_fees',
                                         'yellowback_framework_smoke']), [])

    def test_missing_script(self):
        p = self.run_check(['vault_primitive', 'vault_new'])
        self.assertTrue(any('vault_new' in x for x in p), p)

    def test_unknown_to_rpc_tests(self):
        p = self.run_check([], known={'vault_primitive', 'vault_rpc'})
        self.assertTrue(any('yellowback_fees is not an rpc-tests.py entry' in x for x in p), p)

    def test_direct_must_exist(self):
        p = self.run_check([], exists=lambda s: False)
        self.assertTrue(any('kogany_mixed_smoke (direct)' in x for x in p), p)

    def test_duplicate_and_peer_count(self):
        entries, excluded, _ = ms.parse(TEXT + 'yed vault_rpc report W5\nnode nodehandling report W9\n')
        p = ms.check(entries, excluded, [], self.known | {'nodehandling'}, lambda s: True)
        self.assertTrue(any('vault_rpc listed twice' in x for x in p), p)
        self.assertTrue(any('nodehandling asserts an exact peer count' in x for x in p), p)


class Commands(unittest.TestCase):
    def test_partitions_and_strict(self):
        entries, _, _ = ms.parse(TEXT)
        cmds = ms.commands(ms.select(entries, 'vault', 'gate'), 'gate', 2, '/s', '/t')
        self.assertEqual(len(cmds), 1)
        env, cmd, names = cmds[0]
        self.assertEqual(env, {'KOGANY_STRICT': '1'})
        self.assertIn('--fail-on-skip', cmd)
        self.assertEqual(names, ['vault_rpc'])

    def test_flags_split_runs(self):
        entries, _, _ = ms.parse(TEXT)
        cmds = ms.commands(entries, 'report', 2, '/s', '/t')
        envs = [c[0] for c in cmds]
        self.assertIn({'KOGANY_MIRROR_INVALIDATE': '1'}, envs)
        self.assertIn({'KOGANY_MEMPOOL': '1'}, envs)
        direct = [c for c in cmds if c[2] == ['kogany_mixed_smoke']][0]
        self.assertEqual(direct[0]['ZCASHD'], '/s/ycashd')
        self.assertTrue(direct[1][2].endswith('kogany_mixed_smoke.py'))


class RealManifest(unittest.TestCase):
    def test_real_manifest_is_complete(self):
        self.assertEqual(ms.main(['check']), 0)


if __name__ == '__main__':
    unittest.main()
