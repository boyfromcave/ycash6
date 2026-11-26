#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
N-D13 on regtest: a bundle's deposit of a coinbase coin, mature or not, is an S2 skip (doc/yugen-node.md
N-D13, the lead architect's K-2 ruling). TEST-ONLY PROOFS, as yugen_bundle_vb.py.

- A bundle deposits a mature coinbase coin of node 0's wallet (a good signature) beside a 1-YEC withdrawal.
  The pool refuses it (bad-yugen-bundle-skips): the template never carries it.
- The block is assembled here: node 0 mines the same bundle with an ordinary P2PKH coin as the deposit,
  that block is invalidated, the bundle swapped for the coinbase one, the coinbase output lowered by the
  skipped transfer's fee, and the header solved again (yugen_bundle_vb_module.py's assemble).
- Node 0 connects the block: the deposit skipped (the coinbase coin unspent), the withdrawal applied (its
  output at index 0 of the bundle's txid), the pool balance moved by the withdrawal alone.
- `verifychain 4` re-connects it; invalidateblock and reconsiderblock round-trip it through the undo mask;
  a replay without the state file reaches the same pool state.

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/yugen_bundle_vb_coinbase.py --srcdir=<src> --tmpdir=<dir>
"""

import os

from test_framework.util import connect_nodes_bi, start_node, stop_node, sync_blocks
from test_framework.yellowback_model import base58check_decode

from yugen_bundle import ARGS, bundle_tx
from yugen_bundle_vb import COIN, FEE
from yugen_bundle_vb_module import YugenBundleVbModuleTest


class YugenBundleVbCoinbaseTest(YugenBundleVbModuleTest):
    def run_test(self):
        n0, n1 = self.nodes
        self.results = []
        self.reg = self.helper('regroot')
        n0.generate(140)
        sync_blocks(self.nodes)
        self.fund_pool(n0, n1, 5)

        txid, n, script, secret = self.coin(n0, 3)
        ordinary = (txid, n, script, secret, 3 * COIN)
        cbs = [u for u in n0.listunspent() if u.get('generated') and u['confirmations'] >= 100]
        assert cbs, 'a mature coinbase coin'
        u = cbs[0]
        cb = (u['txid'], u['vout'], bytes.fromhex(u['scriptPubKey']),
              base58check_decode(n0.dumpprivkey(u['address']))[1:33], int(round(u['amount'] * COIN)))
        payee = bytes.fromhex(n0.validateaddress(n0.getnewaddress())['scriptPubKey'])
        sync_blocks(self.nodes)

        good_tx, pa, pb = self.token_bundle(n0, ordinary, payee, 71, False)
        bad_tx, qa, qb = self.token_bundle(n0, cb, payee, 71, False)
        self.refused(n0, bad_tx, [qa, qb], 'bad-yugen-bundle-skips')
        self.check('the pool refuses a bundle depositing a mature coinbase coin', True)

        before = n0.yugen_getinfo()['pool_balance_zat']
        n0.submitbundle({'tx': good_tx, 'proofs': [pa, pb]})
        h = n0.generate(1)[0]
        sync_blocks(self.nodes)
        good_block = n0.getblock(h, 0)
        block, bhash = self.assemble(good_block, good_tx, bad_tx, [qa, qb], FEE)
        n0.invalidateblock(h)
        n0.submitblock(block)
        self.check('the block with the coinbase deposit connects', n0.getbestblockhash() == bhash, n0.getbestblockhash())
        btx = n0.getblock(bhash)['tx'][1]

        def applied_state(label):
            self.check(label + ': the coinbase coin is unspent', n0.gettxout(cb[0], cb[1]) is not None)
            self.check(label + ': the withdrawal output exists', n0.gettxout(btx, 0) is not None)
            bal = n0.yugen_getinfo()['pool_balance_zat']
            self.check(label + ': the pool moved by the withdrawal alone', bal == before - 100000000 - FEE, str((before, bal)))

        applied_state('connected')
        self.check('verifychain 4 over the block', n0.verifychain(4, 0) is True)

        n0.invalidateblock(bhash)
        self.check('disconnected: the coinbase coin is unspent', n0.gettxout(cb[0], cb[1], False) is not None)
        self.check('disconnected: the withdrawal output is gone', n0.gettxout(btx, 0, False) is None)
        self.check('disconnected: the pool balance is back', n0.yugen_getinfo()['pool_balance_zat'] == before)
        n0.reconsiderblock(bhash)
        self.check('reconnected', n0.getbestblockhash() == bhash, n0.getbestblockhash())
        applied_state('reconnected')

        info = n0.yugen_getinfo()
        stop_node(n0, 0)
        os.remove(os.path.join(self.options.tmpdir, 'node0', 'regtest', 'yugen', 'state.dat'))
        self.nodes[0] = n0 = start_node(0, self.options.tmpdir, ARGS)
        again = n0.yugen_getinfo()
        self.check('replay without the state file: the same pool state',
                   (again['pool_balance_zat'], again['root'], again['tree_size']) ==
                   (info['pool_balance_zat'], info['root'], info['tree_size']), str((info, again)))

        failed = [name for name, ok in self.results if not ok]
        assert not failed, 'failed: %s' % failed


if __name__ == '__main__':
    YugenBundleVbCoinbaseTest().main()
