#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The verifier helper's result contract (contrib/yugen-leafverify, doc/yugen-node.md "Helper results").

Exit 0 accepts, exit 10 rejects (a verdict on the input), anything else is a failure of the helper.
A bundle reject says whether both proofs were first confirmed to hash to the bundle's committed
proof hashes ("proofs_bound"); only such a reject is a verdict on a block. Runs the built helper
(YUGEN_LEAFVERIFY, default src/yugen-leafverify) on TEST-ONLY stub bundles made by its own
`testbundle`; no real proof is verified.

    python3 qa/yugen/test_leafverify.py
"""

import json
import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
HELPER = os.environ.get('YUGEN_LEAFVERIFY', os.path.join(HERE, '..', '..', 'src', 'yugen-leafverify'))
BRANCH, NET, ACT, H = 0x59474E30, 2, 32, 49
ANCHOR = {'slot': 2, 'anchor_root': '11' * 48, 'reg_root': '22' * 48, 'block_hash': '33' * 32}
LEAF_PROOF_MAX_B = 817736


def run(*args):
    out = subprocess.run([HELPER] + list(args), capture_output=True, text=True, timeout=600)
    return out.returncode, out.stdout.strip()


class LeafverifyTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='yugen-leafverify-')

    def req(self, doc):
        path = os.path.join(self.dir, 'req.json')
        with open(path, 'w') as f:
            json.dump(doc, f)
        return path

    def testbundle(self, pad_b=0):
        code, out = run('testbundle', self.req({'anchor': ANCHOR, 'n': 2, 'seed': 5, 'branch_id': BRANCH,
                                                'network': NET, 'height': H, 'activation': ACT, 'pad_b': pad_b}))
        self.assertEqual(code, 0, out)
        return out.split()

    def bundle(self, b, pa, pb, **over):
        doc = {'bundle': b, 'proof_a': pa, 'proof_b': pb, 'branch_id': BRANCH, 'network': NET, 'height': H,
               'activation': ACT, 'mode': 0, 'stub': True, 'check_proofs': True, 'b2verify': '', 'b_plan': ''}
        doc.update(over)
        for k in [k for k, v in over.items() if v is None]:
            del doc[k]
        return run('bundle', self.req(doc))

    def assertReject(self, code, out, bound):
        self.assertEqual(code, 10, out)
        self.assertTrue(out.startswith('REJECT {'), out)
        self.assertEqual(json.loads(out[len('REJECT '):])['proofs_bound'], bound, out)

    def test_honest_bundle_accepted(self):
        b, pa, pb = self.testbundle()
        code, out = self.bundle(b, pa, pb)
        self.assertEqual(code, 0, out)
        self.assertTrue(out.startswith('ACCEPT {'), out)

    def test_c1_bundle_proof_b_above_the_leaf_limit_is_accepted(self):
        # Review C-1: a bundle proof may be up to PROOF_BYTES_MAX (spec §15.1); LEAF_PROOF_MAX_B is a leaf's.
        b, pa, pb = self.testbundle(pad_b=900000)
        self.assertGreater(len(pb) // 2, LEAF_PROOF_MAX_B)
        code, out = self.bundle(b, pa, pb)
        self.assertEqual(code, 0, out)

    def test_h1_swapped_proof_b_is_not_a_verdict(self):
        # Review H-1: a relay swaps proof B for 900 KB of junk. The hash is checked first, and the
        # reject says the proofs were not the committed ones.
        b, pa, pb = self.testbundle()
        self.assertReject(*self.bundle(b, pa, 'ee' * 900000), bound=False)
        flipped = pa[:-2] + '%02x' % (int(pa[-2:], 16) ^ 1)
        self.assertReject(*self.bundle(b, flipped, pb), bound=False)
        self.assertReject(*self.bundle(b, pa, ''), bound=False)

    def test_h1_bound_proofs_that_fail_are_a_verdict(self):
        # The committed proofs, judged in another context (another branch id: another statement).
        b, pa, pb = self.testbundle()
        self.assertReject(*self.bundle(b, pa, pb, branch_id=BRANCH ^ 1), bound=True)

    def test_h2_request_faults_are_failures(self):
        # Review H-2: a request the node wrote wrongly is this node's fault, never a reject.
        b, pa, pb = self.testbundle()
        code, out = self.bundle(b, pa, pb, height=None)
        self.assertNotIn(code, (0, 10), out)
        self.assertTrue(out.startswith('FAIL'), out)
        leaf = bytearray(232)
        leaf[2], leaf[4] = 0x40, 1     # LEAFFEE; nf_1 != nf_2: decodes, every context field missing
        code, out = run('verify', self.req({'transfer': leaf.hex()}))
        self.assertNotIn(code, (0, 10), out)
        code, out = run('verify', os.path.join(self.dir, 'missing.json'))
        self.assertNotIn(code, (0, 10), out)


if __name__ == '__main__':
    unittest.main()
