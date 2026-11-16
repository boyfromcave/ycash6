#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Unit tests for qa/yellowback-rpcversion.py (the audit's `rpcversion` leg).

    python3 qa/test_yellowback_rpcversion.py -v
"""

import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _load():
    loader = importlib.machinery.SourceFileLoader('yellowback_rpcversion', os.path.join(HERE, 'yellowback-rpcversion.py'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


rv = _load()

# Every form a bump has left behind, and the prose that must stay legal.
LITERAL = [
    "        assert_equal(info['rpcversion'], 10)   # 10: the beta3 additions",
    "        assert_equal(user.yed_getinfo()['rpcversion'], 9)",
    "        assert_equal(10, info['rpcversion'])",
    '        self.ok(self.node(USER).yed_getinfo()["rpcversion"] == 10 and pq.get("schemes") == [1],',
    "    if info['rpcversion'] != 9: raise",
    '    if d.get("rpcversion") >= 7:',
    "    if 10 == info['rpcversion']:",
    '        if yed.get("GetYellowbackInfo#rpcversion") not in ("5", "6", "7", "8", "9"): return',
    '  "rpcversion": 10,',
    "    expected = {'rpcversion': 9}",
    '[ "$rpcversion" -eq 9 ] || exit 1',
    "    RPCVERSION == 10",
]
PROSE = [
    "        # rpcversion 7 shape: ownerScheme + ownerHash (no ownerAddress or EC key)",
    "    # rpcversion 8: the last fee band is unbounded (null)",
    "        assert_equal(info['rpcversion'], YELLOWBACK_RPC_VERSION)   # 10: the beta3 additions (B3-D5)",
    '        self.ok(up["rpcversion"] == want and up["upgrade"]["attestorSetId"] == self.set_id, "rpcversion %d" % want)',
    "echo \"$info\" | grep -q \"\\\"rpcversion\\\": $rpcversion\\b\" || exit 1",
    "  pq         the post-quantum line (quantum plan 4.9): rpcversion 10 and params.pq;",
    "        assert_equal(user.yed_getinfo()['rpcversion'], c.doc['rpcversion'])",
]


class LiteralChecksTest(unittest.TestCase):

    def test_every_literal_form_is_found(self):
        for line in LITERAL:
            self.assertEqual([n for n, _ in rv.literal_checks(line)], [1], line)

    def test_prose_and_named_checks_are_not(self):
        for line in PROSE:
            self.assertEqual(rv.literal_checks(line), [], line)

    def test_line_numbers(self):
        text = '\n'.join(PROSE[:2] + LITERAL[:1] + PROSE[2:3] + LITERAL[1:2])
        self.assertEqual([n for n, _ in rv.literal_checks(text)], [3, 5])

    def test_allow_list(self):
        self.assertTrue(rv.allowed('src/rpc/yellowback.cpp'))
        self.assertTrue(rv.allowed('doc/yellowback-rpc-contract.json'))
        self.assertTrue(rv.allowed('doc/release-notes/release-notes-6.22.0-beta2.md'))
        self.assertTrue(rv.allowed('doc/release-notes.md'))
        self.assertFalse(rv.allowed('qa/rpc-tests/yellowback_fees.py'))
        self.assertFalse(rv.allowed('contrib/yellowback/devnet/upgrade-walk'))
        for path, why in rv.ALLOW.items():
            self.assertTrue(why, path)               # every allowed file says why


class RepositoryTest(unittest.TestCase):

    def test_this_tree_is_clean_and_in_step(self):
        self.assertEqual(rv.check(ROOT), [])
        self.assertEqual(rv.contract_version(ROOT), rv.constant_version(ROOT))
        sys.path.insert(0, os.path.join(ROOT, 'qa', 'rpc-tests'))
        try:
            from test_framework.yellowback_util import YELLOWBACK_RPC_VERSION
        finally:
            sys.path.pop(0)
        self.assertEqual(YELLOWBACK_RPC_VERSION, rv.contract_version(ROOT))

    def test_a_stray_literal_fails_the_leg(self):
        tmp = tempfile.mkdtemp()
        try:
            for path in (rv.CONTRACT, rv.CONSTANT_FILE):
                os.makedirs(os.path.join(tmp, os.path.dirname(path)), exist_ok=True)
                shutil.copy(os.path.join(ROOT, path), os.path.join(tmp, path))
            os.makedirs(os.path.join(tmp, 'qa', 'rpc-tests'))
            with open(os.path.join(tmp, 'qa', 'rpc-tests', 'x.py'), 'w', encoding='utf-8') as f:
                f.write(LITERAL[0] + '\n')
            subprocess.run(['git', 'init', '-q', tmp], check=True)
            subprocess.run(['git', '-C', tmp, 'add', '-A'], check=True)
            self.assertEqual([(p, n) for p, n, _ in rv.check(tmp)], [('qa/rpc-tests/x.py', 1)])
            self.assertEqual(rv.main(['check', '--root', tmp]), 1)
            self.assertEqual(rv.main(['version', '--root', tmp]), 0)
            # the constant and the contract disagree: both commands fail
            with open(os.path.join(tmp, rv.CONSTANT_FILE), encoding='utf-8') as f:
                src = f.read()
            with open(os.path.join(tmp, rv.CONSTANT_FILE), 'w', encoding='utf-8') as f:
                f.write(rv.CONSTANT_RE.sub('static const int YELLOWBACK_RPC_VERSION = 99;', src))
            self.assertEqual(rv.main(['version', '--root', tmp]), 1)
        finally:
            shutil.rmtree(tmp)


if __name__ == '__main__':
    unittest.main()
