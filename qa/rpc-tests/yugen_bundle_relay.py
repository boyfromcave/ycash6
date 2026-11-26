#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
A Yugen block whose message (block and proof sidecar) is over the stock 2 MiB protocol message
limit relays to a peer (walk M2: node B never took the bundle block). TEST-ONLY stub proofs padded
with zeros (-yugenteststubproofs) give a block near the W3 weight (spec 0.5.1 §16.2).

- node 0 mines a bundle with proofs of 1.5 MB (A) and 0.8 MB (B): node 1 syncs to it by relay;
- node 2, offline while it was mined, connects later and fetches it by getdata.
"""

import json
import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal, connect_nodes_bi, start_nodes, sync_blocks,
)
from yugen_bundle import ARGS, YUGEN_BRANCH_ID, ACT, bundle_tx, YugenBundleTest



class YugenBundleRelayTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 3
        self.setup_clean_chain = True

    def setup_network(self, split=False):
        self.nodes = start_nodes(3, self.options.tmpdir, [ARGS] * 3)
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)
        self.is_network_split = False

    helper = YugenBundleTest.helper
    fund_pool = YugenBundleTest.fund_pool

    def run_test(self):
        n0, n1, n2 = self.nodes
        self.reg = self.helper('regroot')
        n0.generate(140)
        sync_blocks(self.nodes)
        self.fund_pool(n0, n1, 5)
        sync_blocks(self.nodes)
        # Node 2 goes offline.
        for p in n2.getpeerinfo():
            n2.disconnectnode(p['addr'])
        h = n0.getblockcount() + 1
        ha = (h - 1) // 16 * 16
        a = n0.yugen_getanchor(ha)
        req = {'anchor': {'slot': (ha // 16) & 0xff, 'anchor_root': a['root'], 'reg_root': self.reg,
                          'block_hash': a['block_hash']},
               'n': 4, 'seed': 5, 'payee': '', 'branch_id': YUGEN_BRANCH_ID, 'network': 2,
               'height': h, 'activation': ACT, 'pad_a': 1500000, 'pad_b': 800000}
        path = os.path.join(self.options.tmpdir, 'tb.json')
        with open(path, 'w') as f:
            json.dump(req, f)
        b, pa, pb = self.helper('testbundle', path).split()
        r = n0.submitbundle({'tx': bundle_tx(bytes.fromhex(b)), 'proofs': [pa, pb]})
        tip = n0.generate(1)[0]
        assert r['txid'] in n0.getblock(tip)['tx']
        assert len(pa) // 2 + len(pb) // 2 > 2200000
        sync_blocks([n0, n1], timeout=60)
        assert_equal(n1.getbestblockhash(), tip)
        assert_equal(n1.yugen_getinfo()['root'], n0.yugen_getinfo()['root'])
        # Node 2 reconnects and fetches the block by getdata.
        connect_nodes_bi(self.nodes, 0, 2)
        sync_blocks(self.nodes, timeout=60)
        assert_equal(n2.getbestblockhash(), tip)
        assert_equal(len(n2.yugen_getblockdata(n2.getblockcount())['bundles']), 1)


if __name__ == '__main__':
    YugenBundleRelayTest().main()
