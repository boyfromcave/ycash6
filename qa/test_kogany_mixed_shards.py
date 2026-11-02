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


class Sidecar(unittest.TestCase):
    """The W9-a sidecar group: a second mode for scripts already in one mixed group."""

    TEXT = TEXT + "sidecar vault_primitive report W9 mirror\nsidecar yellowback_fees report W9 mempool\n"

    def test_parse_and_complete(self):
        entries, excluded, errors = ms.parse(self.TEXT)
        self.assertEqual(errors, [])
        p = ms.check(entries, excluded, ['vault_primitive', 'vault_rpc', 'yellowback_fees'],
                     {'vault_primitive', 'vault_rpc', 'yellowback_fees'}, lambda s: True)
        self.assertEqual(p, [])                           # in a mixed group and in sidecar: not "twice"

    def test_sidecar_rules(self):
        entries, excluded, _ = ms.parse(TEXT + 'sidecar vault_new report W9\nsidecar vault_rpc report W9\n'
                                        'sidecar vault_rpc report W9\nsidecar kogany_mixed_smoke report W9 direct\n'
                                        'sidecar nodehandling report W9\n')
        p = ms.check(entries, excluded, [], {'vault_primitive', 'vault_rpc', 'yellowback_fees', 'vault_new',
                                             'nodehandling'}, lambda s: True)
        self.assertTrue(any('vault_new is in sidecar but in no mixed group' in x for x in p), p)
        self.assertTrue(any('vault_rpc listed twice in sidecar' in x for x in p), p)
        self.assertTrue(any('kogany_mixed_smoke: a sidecar entry runs through rpc-tests.py' in x for x in p), p)
        self.assertTrue(any('nodehandling asserts an exact peer count' in x for x in p), p)

    def test_commands_set_the_rig(self):
        entries, _, _ = ms.parse(self.TEXT)
        cmds = ms.commands(ms.select(entries, 'sidecar', 'report'), 'report', 2, '/s', '/t')
        envs = sorted(tuple(sorted(c[0].items())) for c in cmds)
        self.assertEqual(envs, [(('KOGANY_MEMPOOL', '1'), ('KOGANY_SIDECAR', '1')),
                                (('KOGANY_MIRROR_INVALIDATE', '1'), ('KOGANY_SIDECAR', '1'))])
        mixed = ms.commands(ms.select(entries, 'vault', 'report'), 'report', 2, '/s', '/t')
        self.assertTrue(all('KOGANY_SIDECAR' not in c[0] for c in mixed))

    def test_of_selects_by_mixed_group(self):
        entries, _, _ = ms.parse(self.TEXT)
        self.assertEqual([e.script for e in ms.select(entries, 'sidecar', of='fees')], ['yellowback_fees'])
        self.assertEqual([e.script for e in ms.select(entries, 'sidecar', of='attest')], [])
        self.assertEqual(ms.main(['run', 'vault', '--state', 'report', '--of', 'vault', '--dry-run']), 2)

    def test_real_sidecar_group(self):
        entries, excluded, _ = ms.load()
        side = ms.select(entries, 'sidecar')
        self.assertEqual(len(side), 50)
        groups = ms.mixed_group_of(entries)
        flags = {e.script: e.flags for e in entries if e.group != 'sidecar'}
        for e in side:
            self.assertEqual(set(e.flags), set(flags[e.script]) - {'direct'}, e.script)   # the mixed group's flags
        self.assertEqual(sum(len(ms.select(entries, 'sidecar', of=g)) for g in ms.MIXED_GROUPS), 50)
        self.assertNotIn('yellowback_framework_smoke', {e.script for e in side})
        self.assertTrue({'yellowback_lifecycle', 'yellowback_claim', 'yellowback_interm', 'yellowback_fees',
                         'yellowback_attest'} <= {e.script for e in side})
        self.assertEqual(set(groups.values()), set(ms.MIXED_GROUPS))


class RealManifest(unittest.TestCase):
    def test_real_manifest_is_complete(self):
        self.assertEqual(ms.main(['check']), 0)


if __name__ == '__main__':
    unittest.main()
