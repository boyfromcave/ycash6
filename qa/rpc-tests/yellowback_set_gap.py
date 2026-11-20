#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The attestor set created before the release that names it (workspace docs/plans/beta4/price-feed.md §3.2-§3.3,
tasks C-T4 and C-T5, done-criteria C-2 and C-4), the same on both node lines (byte-identical script,
qa/yellowback-cross-line.manifest).

On the fast testnet the set's SET_CREATE is mined by a beta3 build that does not know the set (YED inert from
H_V), and beta4 compiles its txid in. An upgraded node then rebuilds the YED index in place from H_V over blocks
it accepted with YED inert; a node that syncs fresh with beta4 judges the same blocks with the module live.

Part 1, replay equivalence (C-T4, C-2). Nodes 0 (miner) and 1 run with the vault upgrade and no attestor set:
YED is inert from H_V. Past H_V the set is created and three members join late, then mature. Nodes 0 and 1
restart with -yellowbackattestorset (the in-place upgrade); node 2 starts empty with it and syncs from genesis.
At the tip nodes 1 and 2 report the same yed_getstatehash, vault state hash and yed_listattestors; again after
blocks mined with YED live.

Part 2, the scanned gap (C-T5, C-4), on a chain of its own (nodes 3 and 4, never connected to 0-2). Node 3
creates a set (its own bondmin 1 YEC, below the module's minimum) and three members join and mature, all with
YED inert. Node 4 then starts empty with that set id and syncs to node 3's tip. Each gap case is one block that
node 3, still without the id, mines:
  - join:     a SET_JOIN with a 1 YEC bond (below the module's BondMinZat; state.cpp SET_JOIN refusal);
  - remove:   a SET_REMOVE of a member signed by another member (the module refuses a foreign remove);
  - winddown: a SET_WINDDOWN of the set (the module refuses it).
Node 3 accepts each block, and after a restart with the id (in place) still holds it at its chain tip, while
its YED index, rebuilt from H_V with the module live, stops one block below it. Node 4 (the fresh-sync
verdict) refuses it (submitblock), so the chain splits; node 3 then invalidates the block and the
next case starts from the same tip. A gap scan that finds any such act reruns the ceremony with a new set.

    ZCASHD=<ycashd> (BITCOIND=<ycashd> on v4.5.0) .venv/bin/python -u qa/rpc-tests/yellowback_set_gap.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID,
    assert_equal,
    connect_nodes_bi,
    nuparams,
    start_node,
    stop_node,
)
from test_framework.yellowback_util import ATTESTOR_SET_SPEC, BOND_MATURITY, YCASH_UPGRADE_ARGS, wait_yed_healthy

try:
    from test_framework import kogany    # ycash6: the mixed-line harness (KOGANY_BIN, KOGANY_PEER=4)
except ImportError:
    kogany = None                        # the 4.5.0 line has none

ACT = 200                      # H_V: past coinbase maturity, so the miners can fund the bonds
INERT = 30                     # blocks past H_V with YED inert before the set exists (beta3 on the fast testnet)
BOND = 10                      # YEC: regtest's bondMinCapZat, always above the module's minimum
LOW_BOND = 1                   # YEC: below the module's minimum (regtest bondMinFloorZat 5 YEC), above the set's own bondmin
MEMBERS = 3
MINER, INPLACE, FRESH = 0, 1, 2
GAP_MINER, GAP_FRESH = 3, 4


class YellowbackSetGapTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 5
        self.setup_clean_chain = True   # v4.5.0 harness
        self.cache_behavior = 'clean'   # 6.20.0 harness (each harness ignores the other's)
        self.setid = {}

    def node_args(self, i, setid=None, off=False):
        args = list(YCASH_UPGRADE_ARGS) + [nuparams(VAULT_BRANCH_ID, ACT)]
        if setid:
            args += ['-yellowbackattestorset=%s' % setid, '-yellowbacksigmaref=0']
        if off:
            args += ['-yellowback=0']     # without it a datadir holding a YED index refuses to start without the set
        return args

    def start(self, i, setid=None, off=False, extra=()):
        self.nodes[i] = start_node(i, self.options.tmpdir, self.node_args(i, setid, off) + list(extra))
        return self.nodes[i]

    def stop(self, i):
        stop_node(self.nodes[i], i)
        self.nodes[i] = None

    def setup_network(self, split=False):
        self.nodes = [None] * self.num_nodes
        for i in (MINER, INPLACE, GAP_MINER, GAP_FRESH):
            self.start(i)                 # node 4 stays empty and unconnected until part 2 restarts it with the set
        connect_nodes_bi(self.nodes, MINER, INPLACE)
        self.is_network_split = False

    def sync(self, nodes, timeout=300):
        deadline = time.time() + timeout
        while len(set(self.nodes[i].getbestblockhash() for i in nodes)) != 1:
            assert time.time() < deadline, 'block sync failed: %r' % [(i, self.nodes[i].getblockcount()) for i in nodes]
            time.sleep(0.25)

    def mine(self, i, n=1, peers=()):
        self.nodes[i].generate(n)
        self.sync((i,) + tuple(peers))

    def mine_tx(self, i, txid, peers=()):
        deadline = time.time() + 60
        while txid not in self.nodes[i].getrawmempool():
            assert time.time() < deadline, '%s never reached node %d' % (txid, i)
            time.sleep(0.25)
        self.mine(i, 1, peers)
        assert txid in self.nodes[i].getblock(self.nodes[i].getbestblockhash())['tx'], txid

    def create_set(self, i, peers=(), **params):
        n = self.nodes[i]
        created = n.set_create(dict(ATTESTOR_SET_SPEC, **params))
        self.mine_tx(i, created['txid'], peers)
        keys = []
        for _ in range(MEMBERS):
            joined = n.set_join(created['setid'], BOND, n.getblockcount() + 1)
            assert_equal(joined['complete'], True)
            keys.append(joined['memberkey'])
            self.mine_tx(i, joined['txid'], peers)
        self.mine(i, BOND_MATURITY + 2, peers)
        return created['setid'], keys

    def views(self, i):
        n = self.nodes[i]
        wait_yed_healthy(n, timeout=300)
        return {'tip': n.getbestblockhash(), 'vault': n.vault_getinfo()['statehash'],
                'yed': n.yed_getstatehash()['statehash'], 'attestors': n.yed_listattestors()}

    def run_test(self):
        self.replay_equivalence()
        self.scanned_gap()

    # ------------------------------------------------------------------ C-T4
    def replay_equivalence(self):
        print('C-T4 1. YED inert from H_V: the set is created and joined late')
        self.mine(MINER, ACT + INERT, (INPLACE,))
        assert_equal(self.nodes[INPLACE].vault_getinfo().get('attestorsetid'), None)
        setid, keys = self.create_set(MINER, (INPLACE,))
        assert setid not in (None, '')

        print('C-T4 2. nodes 0 and 1 restart with the id (in place); node 2 syncs fresh with it')
        for i in (MINER, INPLACE):
            self.stop(i)
            self.start(i, setid)
        connect_nodes_bi(self.nodes, MINER, INPLACE)
        self.start(FRESH, setid)
        connect_nodes_bi(self.nodes, INPLACE, FRESH)
        self.sync((MINER, INPLACE, FRESH))
        inplace, fresh = self.views(INPLACE), self.views(FRESH)
        assert_equal(inplace, fresh)
        assert_equal(self.views(MINER), fresh)
        assert_equal(self.nodes[FRESH].vault_getinfo()['attestorsetid'], setid)
        assert_equal(sorted(r['attestorPubKey'] for r in fresh['attestors']), sorted(keys))
        assert_equal(set(r['status'] for r in fresh['attestors']), {'ELIGIBLE'})

        print('C-T4 3. blocks with YED live: the in-place and fresh nodes stay equal')
        self.mine(MINER, 5, (INPLACE, FRESH))
        assert_equal(self.views(INPLACE), self.views(FRESH))

    # ------------------------------------------------------------------ C-T5
    def scanned_gap(self):
        print('C-T5 1. a chain of its own: the set (bondmin %d YEC) created and joined with YED inert' % LOW_BOND)
        self.mine(GAP_MINER, ACT + INERT)
        setid, keys = self.create_set(GAP_MINER, bondmin=LOW_BOND)
        base = self.nodes[GAP_MINER].getbestblockhash()
        assert_equal(self.nodes[GAP_FRESH].getblockcount(), 0)
        self.stop(GAP_FRESH)
        self.start(GAP_FRESH, setid)
        connect_nodes_bi(self.nodes, GAP_MINER, GAP_FRESH)
        self.sync((GAP_MINER, GAP_FRESH))
        assert_equal(self.views(GAP_FRESH)['tip'], base)
        assert_equal(len(self.nodes[GAP_FRESH].yed_listattestors()), MEMBERS)
        # the miner no longer relays to node 4: each gap block is handed over by submitblock
        self.stop(GAP_MINER)
        self.start(GAP_MINER)

        for case in ('join', 'remove', 'winddown'):
            print('C-T5 2. gap case %s' % case)
            miner = self.nodes[GAP_MINER]
            assert_equal(miner.getbestblockhash(), base)
            txid = self.gap_act(case, setid, keys)
            self.mine_tx(GAP_MINER, txid)
            gap = miner.getbestblockhash()
            height = miner.getblockcount()
            raw = miner.getblock(gap, False)
            # the in-place verdict: node 3 restarted with the id keeps the block it accepted while YED was inert
            # at its chain tip; its YED index, rebuilt from H_V with the module live, stops below that block
            self.stop(GAP_MINER)
            self.start(GAP_MINER, setid)
            assert_equal(self.nodes[GAP_MINER].getbestblockhash(), gap)
            info = self.wait_index_settled(GAP_MINER)
            assert_equal((info['chainHeight'], info['height']), (height, height - 1))
            # the fresh-sync verdict: node 4, live from the set's creation, refuses it
            verdict = self.nodes[GAP_FRESH].submitblock(raw)
            print('    in place: block %d kept at the chain tip, YED index at %d (healthy %s); fresh sync: submitblock -> %r'
                  % (height, info['height'], info['healthy'], verdict))
            assert verdict not in (None, 'duplicate', 'inconclusive'), verdict
            assert_equal(self.nodes[GAP_FRESH].getbestblockhash(), base)
            assert_equal(self.nodes[GAP_FRESH].getblock(gap)['confirmations'], -1)
            if kogany is not None:
                kogany.current().on_block_rejected(self.nodes[GAP_FRESH], gap)   # kogany's fresh-sync verdict (C-T5)
            # back to the shared tip for the next case: node 3 without the set again (-yellowback=0: its datadir now
            # holds a YED index), the gap block invalidated, and a restart that drops the act from its wallet and
            # mempool (-zapwallettxes=2: the join pays this wallet, which would otherwise rebroadcast it)
            self.stop(GAP_MINER)
            self.start(GAP_MINER, off=True)
            self.nodes[GAP_MINER].invalidateblock(gap)
            self.stop(GAP_MINER)
            self.start(GAP_MINER, off=True, extra=['-zapwallettxes=2'])
            assert_equal(self.nodes[GAP_MINER].getrawmempool(), [])

    def wait_index_settled(self, i, timeout=120):
        """yed_getinfo once the index has stopped moving (two equal reads a second apart)."""
        deadline, last = time.time() + timeout, None
        while True:
            info = self.nodes[i].yed_getinfo()
            if last is not None and (info['height'], info['blockhash']) == (last['height'], last['blockhash']):
                return info
            assert time.time() < deadline, 'index still moving: %r' % info
            last = info
            time.sleep(1)

    def gap_act(self, case, setid, keys):
        n = self.nodes[GAP_MINER]
        if case == 'join':
            joined = n.set_join(setid, LOW_BOND, n.getblockcount() + 1)
            assert_equal(joined['complete'], True)
            return joined['txid']
        params = {'setid': setid, 'memberkey': keys[0], 'burn': False} if case == 'remove' else {'setid': setid}
        built = n.set_buildact(case, params)
        signed = n.set_signact(built['hex'], setid)
        assert_equal(signed['complete'], True)
        return n.set_sendact(signed['hex'])


if __name__ == '__main__':
    YellowbackSetGapTest().main()
