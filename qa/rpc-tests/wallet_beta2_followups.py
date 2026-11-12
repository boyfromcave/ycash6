#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Wallet follow-ups found during beta2 (wt list items 21, 41, 44), one case each:

- topup_balance (review L-6 / LOW-3): a payment to a post-quantum key that only a later lookahead top-up makes this
  wallet's. The transaction that pays it is already in the wallet (it also pays an ECC address of the wallet) and its
  credit is cached; a second payment, to the last key of the lookahead, moves the lookahead past the first key. After
  that, getbalance (cached) == getwalletinfo.balance (fresh) == balance_ecc + balance_pq.

Node 0 runs on a fresh wallet file (no coinbase of its own); node 1 mines and pays. The keys ahead of node 0's
lookahead are issued by a copy of node 0's wallet taken before any post-quantum key was issued (same HD seed).

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/wallet_beta2_followups.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>

One file on both C++ lines (ycash-dd: BITCOIND=, ycash6: ZCASHD=).
"""

import os
import shutil
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID,
    assert_equal,
    connect_nodes_bi,
    nuparams,
    start_node,
    start_nodes,
    stop_node,
    sync_blocks,
)

ACTIVATION = 210
PQ_KEY_LOOKAHEAD = 20      # src/wallet/wallet.h


def D(x):
    return Decimal(str(x))


def assert_raises_rpc(substr, fn, *args):
    try:
        fn(*args)
    except JSONRPCException as e:
        assert substr in e.error['message'], 'expected %r in %r' % (substr, e.error['message'])
        return e.error['message']
    raise AssertionError('expected an RPC error containing %r' % substr)


class WalletBeta2FollowupsTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = False

    def node_args(self, i, wallet='followups.dat', extra=()):
        a = [nuparams(VAULT_BRANCH_ID, ACTIVATION), '-pqfalcon=1']
        if i == 0:
            a += ['-wallet=%s' % wallet, '-exportdir=%s' % os.path.join(self.options.tmpdir, 'export0')]
        return a + list(extra)

    def restart(self, i, wallet='followups.dat', extra=()):
        stop_node(self.nodes[i], i)
        self.nodes[i] = start_node(i, self.options.tmpdir, self.node_args(i, wallet, extra))
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)

    def setup_network(self, split=False):
        os.makedirs(os.path.join(self.options.tmpdir, 'export0'), exist_ok=True)
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 extra_args=[self.node_args(i) for i in range(self.num_nodes)])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def mine(self, n=1):
        self.sync_all()
        self.nodes[1].generate(n)
        self.sync_all()

    def balances(self, node):
        """getbalance, getwalletinfo.balance and its split; asserts they agree. getbalance is read first: it reads the
        transactions' cached credit, which getwalletinfo's fresh count would rewrite."""
        cached = D(node.getbalance())
        w = node.getwalletinfo()
        total, ecc, pq = D(w['balance']), D(w['balance_ecc']), D(w['balance_pq'])
        assert_equal(total, ecc + pq)
        assert_equal(cached, total)
        return total, ecc, pq

    # ---- item 1: the lookahead top-up and the balance cache ------------------------------------------------------

    def topup_balance(self):
        n0, n1 = self.nodes
        print('topup_balance: a key beyond the lookahead, made this wallet\'s by a top-up after its payment arrived')
        regtest = os.path.join(self.options.tmpdir, 'node0', 'regtest')
        n0.backupwallet('followupsseed')             # the HD seed and the lookahead, no PQ key issued yet
        backup = os.path.join(self.options.tmpdir, 'export0', 'followupsseed')
        shutil.copyfile(backup, os.path.join(regtest, 'followups-ahead.dat'))
        self.restart(0, 'followups-ahead.dat')
        ahead = [self.nodes[0].getnewaddress('', 'pq') for _ in range(PQ_KEY_LOOKAHEAD + 1)]
        self.restart(0)
        n0 = self.nodes[0]
        for a in ahead[:PQ_KEY_LOOKAHEAD]:
            assert n0.validateaddress(a)['ismine'], 'expected %s in the lookahead' % a
        beyond = ahead[PQ_KEY_LOOKAHEAD]
        assert not n0.validateaddress(beyond)['ismine']

        ecc = n0.getnewaddress()
        tx1 = n1.sendmany('', {ecc: 1, beyond: 2})
        self.mine()
        assert_equal(self.balances(n0), (D(1), D(1), D(0)))   # the credit of that transaction is cached now

        # The second payment must not spend the first one's change: spending an output of a wallet transaction marks
        # that transaction dirty (MarkAffectedTransactionsDirty), which would hide the stale cache.
        change1 = [{'txid': u['txid'], 'vout': u['vout']} for u in n1.listunspent(0) if u['txid'] == tx1]
        n1.lockunspent(False, change1)
        n1.sendtoaddress(ahead[PQ_KEY_LOOKAHEAD - 1], 3)    # marks the last key used: the lookahead moves past `beyond`
        n1.lockunspent(True, change1)
        self.mine()
        assert n0.validateaddress(beyond)['ismine']
        assert_equal(self.balances(n0), (D(6), D(1), D(5)))
        self.restart(0)
        assert_equal(self.balances(self.nodes[0]), (D(6), D(1), D(5)))

    def run_test(self):
        self.mine(ACTIVATION - self.nodes[0].getblockcount())
        self.topup_balance()


if __name__ == '__main__':
    WalletBeta2FollowupsTest().main()
