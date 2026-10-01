#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Phase 5, nightly (plan section 6, Phase 5; N10, section 8.4 item 21): the fork binary without
``-yellowback`` is v4.5.0.

Two nodes run one scripted scenario -- roughly 300 blocks of mining, ordinary transactions, a
reorg, ``getblocktemplate`` and ``getblock`` -- against each other:

* node 0 is a **real ``ycash-legacy`` v4.5.0 build**, from ``--ref-ycashd`` or ``$REF_YCASHD``;
* node 1 is the fork binary started **without** ``-yellowback``.

At every step the two must agree on ``getbestblockhash``, on
``gettxoutsetinfo.hash_serialized``, on the key set and the shared values of ``getinfo``, and on
the key set of ``getblocktemplate`` (minus the fields that are a function of the call's own clock
and of the node's mempool).  Without ``--ref-ycashd`` the script still runs -- both nodes are then
the fork binary without the flag, which is a weaker but non-empty check -- and says so.

The unguarded differences the fork does carry are listed in plan section 8.4 item 2: two
includes, one lock acquisition, and an append of the (empty, without the flag) ``COINBASE_FLAGS``.
None of them may change a byte of any of the values compared here.
"""

import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes_bi,
    start_nodes,
    sync_blocks,
    sync_mempools,
)
from test_framework.yellowback_util import yellowback_node_args

# getblocktemplate fields that legitimately differ between two calls a moment apart, or between
# two nodes with different mempools: the clock, the long-poll token and the transaction list.
GBT_VOLATILE = {'curtime', 'longpollid', 'mintime', 'transactions', 'coinbasetxn', 'target', 'bits'}
# getinfo fields that are per-node by definition.
GETINFO_VOLATILE = {'connections', 'timeoffset', 'errors', 'balance', 'walletversion',
                    'keypoololdest', 'keypoolsize', 'paytxfee', 'relayfee', 'unlocked_until',
                    # the git describe string of the build itself: v4.5.0-<commit> either way
                    'build', 'subversion'}

LEGACY, FORK = 0, 1


class YellowbackStockParityTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.steps = 0

    def add_options(self, parser):
        parser.add_option('--ref-ycashd', dest='ref_ycashd', default=os.getenv('REF_YCASHD') or None,
                          help='a ycash-legacy v4.5.0 ycashd for node 0 (default: $REF_YCASHD)')
        parser.add_option('--blocks', dest='blocks', default=300, type='int',
                          help='scenario length in blocks (default 300)')

    def setup_network(self, split=False):
        ref = self.options.ref_ycashd
        self.have_legacy = bool(ref)
        if not self.have_legacy:
            print('*** no --ref-ycashd / $REF_YCASHD: BOTH nodes are the fork binary without')
            print('*** -yellowback.  The legacy half of this comparison was NOT run.')
        # -txexpirydelta keeps a wallet transaction alive across this scenario's fast mining
        # (a transaction that expires and is re-relayed costs the sender Ycash's own tx-expired
        # DoS 10), and -whitelist stops either node scoring the other at all: this script must
        # compare the two binaries, not stock DoS behaviour.
        extra = ['-txexpirydelta=200', '-whitelist=127.0.0.1']
        args = [yellowback_node_args(list(extra), yellowback=False) for _ in range(2)]
        self.nodes = start_nodes(2, self.options.tmpdir, extra_args=args, binary=[ref, None])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    # ------------------------------------------------------------------ the comparison

    def compare(self, label, template=True):
        """Every parity assertion, at one point in the scenario."""
        self.steps += 1
        a, b = self.nodes[LEGACY], self.nodes[FORK]
        sync_blocks([a, b])
        assert_equal((label, a.getbestblockhash()), (label, b.getbestblockhash()))
        ua, ub = a.gettxoutsetinfo(), b.gettxoutsetinfo()
        assert_equal((label, ua['hash_serialized']), (label, ub['hash_serialized']))
        assert_equal((label, ua['total_amount']), (label, ub['total_amount']))
        assert_equal((label, ua['transactions']), (label, ub['transactions']))
        ia, ib = a.getinfo(), b.getinfo()
        assert_equal((label, sorted(ia.keys())), (label, sorted(ib.keys())))
        for k in sorted(set(ia) - GETINFO_VOLATILE):
            assert_equal((label, k, ia[k]), (label, k, ib[k]))
        if template:
            ta, tb = a.getblocktemplate(), b.getblocktemplate()
            assert_equal((label, sorted(ta.keys())), (label, sorted(tb.keys())))
            assert_equal((label, ta['mutable']), (label, tb['mutable']))
            for k in sorted(set(ta) - GBT_VOLATILE):
                assert_equal((label, k, ta[k]), (label, k, tb[k]))
            # the coinbase the two would mine must be byte-identical apart from the payout key
            ca, cb = ta['coinbasetxn'], tb['coinbasetxn']
            assert_equal((label, sorted(ca.keys())), (label, sorted(cb.keys())))
            assert_equal((label, ca['foundersreward']), (label, cb['foundersreward']))
        # one block, read back in full, field for field
        h = a.getbestblockhash()
        ba, bb = a.getblock(h), b.getblock(h)
        assert_equal((label, sorted(ba.keys())), (label, sorted(bb.keys())))
        for k in sorted(ba):
            if k == 'confirmations':
                continue
            assert_equal((label, k, ba[k]), (label, k, bb[k]))

    # ------------------------------------------------------------------ the scenario

    def run_test(self):
        a, b = self.nodes[LEGACY], self.nodes[FORK]
        total = int(self.options.blocks)

        print('1. %d blocks from genesis, alternating miners' % 120)
        for i in range(120):
            self.nodes[i % 2].generate(1)
            sync_blocks([a, b])
        self.compare('after the initial chain')

        print('2. ordinary transactions, both wallets, mined by both nodes')
        mined = 120
        while mined < total - 40:
            n = self.nodes[mined % 2]
            other = self.nodes[(mined + 1) % 2]
            if mined % 10 == 0 and n.getbalance() > 1:
                try:
                    n.sendtoaddress(other.getnewaddress(), 1.0)
                    sync_mempools([a, b])
                except Exception as e:
                    print('   sendtoaddress: %s' % e)
            n.generate(1)
            sync_blocks([a, b])
            mined += 1
            if mined % 25 == 0:
                self.compare('block %d' % mined)

        print('3. a reorg on both nodes')
        depth = 4
        fork_hash = a.getblockhash(a.getblockcount() - depth)
        a.invalidateblock(fork_hash)
        b.invalidateblock(fork_hash)
        assert_equal(a.getbestblockhash(), b.getbestblockhash())
        self.compare('at the fork point', template=False)
        b.generate(depth + 2)
        sync_blocks([a, b])
        self.compare('after the reorg')
        a.reconsiderblock(fork_hash)
        b.reconsiderblock(fork_hash)
        sync_blocks([a, b])
        self.compare('after reconsiderblock')

        print('4. the tail, mined by the fork binary alone')
        while a.getblockcount() < total:
            b.generate(1)
            sync_blocks([a, b])
        self.compare('final')

        print('%d blocks, %d comparison points, all equal%s'
              % (a.getblockcount(), self.steps,
                 '' if self.have_legacy else ' (fork-vs-fork: the legacy half was NOT run)'))
        if not self.have_legacy:
            print('*** REPORT THIS AS "legacy half not run" ***')


if __name__ == '__main__':
    YellowbackStockParityTest().main()
