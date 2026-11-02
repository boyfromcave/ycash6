#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
zip244.py against the upstream ZIP-244 test vectors (no node needed).

    .venv/bin/python -m unittest qa/rpc-tests/test_framework/test_zip244.py

src/test/data/zip0244.json is zcash-test-vectors' zip_0244.py output (the same ten vectors
librustzcash's zcash_primitives/src/transaction/tests/data.rs carries). They are Zcash NU5
transactions (branch id 0xc2d6d0b4), which the Ycash-patched Rust rejects (so the C++ TxV5 test
is skipped on Ycash, src/test/transaction_tests.cpp); the Python model does not map branch ids,
so it can replay them: round trip, txid (T), auth digest (A) and every signature digest (S),
shielded and all six transparent hash types.
"""

import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))

from test_framework import zip244                       # noqa: E402
from test_framework.mininode import CTransaction        # noqa: E402

VECTORS = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', '..', 'src', 'test', 'data',
                       'zip0244.json')

# (column in zip0244.json, hash type)
HASH_TYPES = [(7, 0x01), (8, 0x02), (9, 0x03), (10, 0x81), (11, 0x82), (12, 0x83)]


def load_vectors():
    with open(VECTORS) as f:
        rows = json.load(f)
    return rows[2:]                                     # two comment rows


def parse_tx(hex_):
    tx = CTransaction()
    raw = bytes.fromhex(hex_)
    f = io.BytesIO(raw)
    tx.deserialize(f)
    assert f.read() == b'', 'trailing bytes'
    return tx, raw


def t_inputs_of(row):
    return [zip244.TransparentInput(i, bytes.fromhex(spk), amt)
            for i, (amt, spk) in enumerate(zip(row[3], row[4]))]


def display(h32):
    return h32[::-1].hex()


class Zip244UpstreamVectors(unittest.TestCase):
    def test_vectors(self):
        rows = load_vectors()
        self.assertEqual(len(rows), 10)
        n_transparent = 0
        for idx, row in enumerate(rows):
            with self.subTest(vector=idx):
                tx, raw = parse_tx(row[0])
                self.assertEqual(tx.serialize(), raw)
                self.assertEqual(display(zip244.txid_digest(tx)), row[1])
                self.assertEqual(display(zip244.auth_digest(tx)), row[2])
                t_inputs = t_inputs_of(row)
                self.assertEqual(display(zip244.signature_digest(tx, t_inputs, 0x01, None)), row[6])
                if row[5] is None:
                    for col, _ in HASH_TYPES:
                        self.assertIsNone(row[col])
                    continue
                n_transparent += 1
                txin = t_inputs[row[5]]
                for col, ht in HASH_TYPES:
                    if row[col] is None:
                        # SINGLE without a corresponding output: undefined for ZIP 244 (the node throws).
                        self.assertEqual(ht & 0x1f, 0x03)
                        self.assertGreaterEqual(row[5], len(tx.vout))
                        continue
                    self.assertEqual(display(zip244.signature_digest(tx, t_inputs, ht, txin)), row[col],
                                     'hash type 0x%02x' % ht)
        self.assertGreater(n_transparent, 0)

    def test_undefined_hash_type(self):
        row = next(r for r in load_vectors() if r[5] is not None)
        tx, _ = parse_tx(row[0])
        t_inputs = t_inputs_of(row)
        for ht in (0x00, 0x04, 0x41, 0x84):
            with self.assertRaises(ValueError):
                zip244.signature_digest(tx, t_inputs, ht, t_inputs[row[5]])


if __name__ == '__main__':
    unittest.main()
