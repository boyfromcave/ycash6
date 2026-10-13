#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""Unit test of rpc-tests.py's SKIP detection (audit 04/F-1, 04/N-4).

A script that cannot run its assertions prints a line starting with "SKIP" and exits 0; CI runs
rpc-tests.py with --fail-on-skip so such a run fails instead of passing vacuously. The classifier
must match "SKIP" at column 0 only: yellowback_devnet_upgrade.py prints "interm: SKIP: ..." on
purpose. Run: python3 qa/pull-tester/test_rpc_tests_classify.py
"""

import importlib.util
import os
import unittest

_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rpc-tests.py')
_SPEC = importlib.util.spec_from_file_location('rpc_tests', _PATH)
rpc_tests = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(rpc_tests)
classify = rpc_tests.classify


class ClassifyTest(unittest.TestCase):
    def test_pass(self):
        self.assertEqual(classify('Initializing test directory /tmp/x\nTests successful\n', '', 0), (True, False))

    def test_skip_at_column_0(self):
        out = 'Initializing test directory /tmp/x\nSKIP: no C compiler for the optional Falcon signer\n'
        self.assertEqual(classify(out, '', 0), (True, True))
        self.assertEqual(classify('SKIP (no CHAINVIZ_BIN)\n', '', 0), (True, True))

    def test_mid_line_skip_is_not_a_skip(self):
        out = 'interm: SKIP: the in-term walk needs a module node\nTests successful\n'
        self.assertEqual(classify(out, '', 0), (True, False))
        # A word that merely starts with SKIP is not the convention either.
        self.assertEqual(classify('SKIPPABLE work done\n', '', 0), (True, False))

    def test_failure_is_never_a_skip(self):
        self.assertEqual(classify('SKIP: x\n', '', 1), (False, False))
        self.assertEqual(classify('SKIP: x\n', 'Traceback ...', 0), (False, False))


if __name__ == '__main__':
    unittest.main()
