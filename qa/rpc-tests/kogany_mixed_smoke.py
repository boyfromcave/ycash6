#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Smoke test of the mixed-line harness paths (kogany plan W1-Y7 harness part, K-18).

Without KOGANY_BIN it runs on ycashd nodes alone and checks what the harness adds: the inert
MixedLine, the koganyd.toml generated from the user node's real arguments (parsed back), the
sync-point state hashes on the C++ nodes, and the verdict classes of real ycashd block and
transaction rejections against REJECT_CODE_MAP.  With KOGANY_BIN set the same run also asserts
the followers' tips, state hashes and verdicts at every sync point (use kogany_standin.py as
KOGANY_BIN to test the harness before kogany follows Ycash regtest):

    ZCASHD=$BIN/ycashd ../../../.venv/bin/python -u kogany_mixed_smoke.py --srcdir=$BIN
    KOGANY_BIN=$PWD/kogany_standin.py KOGANY_LIVE=W1-Y1,W2-b,W5-f,W5-c,W3-c ZCASHD=... (same)

With YEWD_BIN set every node is a ycashd -disablewallet backend behind a yewd (plan section 3b);
the yewd S0 facade serves no wallet RPC yet, so the smoke runs its wallet-free part: the stock
topology mined with -mineraddress, the sync points, a raw-block verdict through the facade, and a
wallet RPC answering -32601.

    YEWD_BIN=$WS/wt/.targets/yewd/debug/yewd ZCASHD=... (same)

Not in any manifest yet (W1 gate).
"""

import os
import sys
import tomllib
from decimal import Decimal

from test_framework import kogany
from test_framework.authproxy import JSONRPCException
from test_framework.util import assert_equal
from test_framework.yellowback_util import (
    ATTESTOR_SET, ENFORCING, POOL_WIFS, USER, YellowbackTestFramework, address_of, assert_best_hash,
    assert_same_statehash, mine_block_raw, template_coinbase,
)

YEWD = bool(os.getenv('YEWD_BIN'))

# The fixed arguments util.start_node puts in front of every node's own (util.py start_node).
START_NODE_ARGS = ['-keypool=1', '-discover=0', '-rest',
                   '-i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025',
                   '-nuparams=5ba81b19:1', '-nuparams=76b809bb:1']


class KoganyMixedSmokeTest(YellowbackTestFramework):

    if YEWD:
        # no wallet behind the facade (S0): stock nodes, no attestor set, nothing mined in setup
        yellowback_enabled = False
        auto_attestor_set = False
        initial_blocks = 0

    def __init__(self):
        super().__init__(num_nodes=4)      # user, stock, two pools: the smallest standard topology

    def node_args(self, i, extra=None):
        args = super().node_args(i, extra)
        if YEWD:                           # a -disablewallet backend mines to a fixed address
            args += ['-mineraddress=%s' % address_of(POOL_WIFS[0]), '-minetolocalwallet=0']
        return args

    def import_pool_keys(self, nodes):
        if not YEWD:
            super().import_pool_keys(nodes)

    def run_yewd(self):
        user = self.nodes[USER]
        try:
            user.getnewaddress()
            raise AssertionError('yewd served getnewaddress; update the smoke for S1')
        except JSONRPCException as e:
            assert_equal(e.error['code'], -32601)
            print('yewd: wallet RPC answers -32601 (%s)' % e.error['message'])
        self.mine(USER, 2)
        assert_best_hash(self.nodes)
        vault = [n.vault_getinfo()['statehash'] for n in self.nodes]
        assert_equal(vault, [vault[0]] * len(vault))
        result, bh = mine_block_raw(user, [])
        assert_equal(kogany.classify_cxx_block(result), kogany.ACCEPT)
        self.sync_all()
        assert_best_hash(self.nodes)
        print('yewd: %d pairs, tip %s at %d, vault statehash equal, raw block accepted through the facade'
              % (len(self.nodes), bh[:16], user.getblockcount()))

    def run_test(self):
        if YEWD:
            return self.run_yewd()
        mixed = kogany.current()
        print('mixed line: enabled=%s active=%s peer=%s' % (mixed.enabled, mixed.active, mixed.peer))
        assert self.mixed is mixed or not self.mixed.enabled
        if not mixed.enabled:
            assert not mixed.active
            assert mixed.offer_block('00' * 140, None) is None      # inert: never parses, never calls
            assert mixed.offer_tx('00', None) is None

        self.check_toml()
        self.check_sync_points()
        self.check_block_verdicts()
        self.check_tx_verdicts()
        if mixed.active:
            print('mixed line stats: %s' % mixed.stats)
            assert mixed.stats['sync_points'] > 0

    # --- the generator on the real arguments ------------------------------------

    def check_toml(self):
        args = START_NODE_ARGS + self.node_args(USER) + self.clock_args()
        config, notes = kogany.koganyd_config(args, 0, [12345], os.path.join(self.options.tmpdir, 'toml-check'), live=())
        text = kogany.render_toml(config, notes)
        parsed = tomllib.loads(text)
        heights = parsed['network']['network']['params']['activation_heights']
        for nu in ('Overwinter', 'Sapling', 'Blossom', 'Heartwood', 'Canopy'):
            assert_equal(heights[nu], 1)
        assert 'Vault' not in heights and 'Ycash' not in heights
        assert any(n.startswith('pending:W2-b') for n in notes), notes
        assert any(n.startswith('pending:W1-Y1') for n in notes), notes
        assert any('-yellowbackattestorset=%s' % ATTESTOR_SET[0] in n for n in notes), notes
        assert_equal(parsed['network']['p2p_stack'], 'legacy')
        assert_equal(parsed['network']['initial_testnet_peers'], ['127.0.0.1:12345'])
        print('koganyd.toml from node %d arguments: %d keys live, %d notes' % (USER, len(heights), len(notes)))

    # --- sync points ------------------------------------------------------------

    def check_sync_points(self):
        self.mine(USER, 2)                                   # sync_all -> sync_blocks hook
        nodes = [self.nodes[i] for i in ENFORCING if i < len(self.nodes)]
        assert_best_hash(self.nodes)
        assert_same_statehash(nodes, 'smoke')
        vault = [n.vault_getinfo()['statehash'] for n in self.nodes]
        assert_equal(vault, [vault[0]] * len(vault))
        print('sync point: tip %s, yed statehash and vault statehash equal on %d nodes'
              % (self.nodes[USER].getbestblockhash()[:16], len(self.nodes)))

    # --- verdict classes on real ycashd results ------------------------------------

    def check_block_verdicts(self):
        user = self.nodes[USER]
        result, bh = mine_block_raw(user, [])                # mixed: offered to every follower
        assert_equal(kogany.classify_cxx_block(result), kogany.ACCEPT)
        self.sync_all()
        assert_equal(user.getbestblockhash(), bh)
        cb, gbt = template_coinbase(user)
        cb.vout[0].nValue += 1                               # claims one zat over the subsidy
        cb.rehash()
        tip = user.getbestblockhash()
        result, _bh = mine_block_raw(user, [], coinbase=cb, gbt=gbt)
        assert_equal(result, 'bad-cb-amount')
        assert_equal(kogany.classify_cxx_block(result), kogany.REJECT_CONSENSUS)
        assert_equal(user.getbestblockhash(), tip)
        print('blocks: valid raw block %s, overpaying coinbase %s'
              % (kogany.classify_cxx_block(None), kogany.classify_cxx_block(result)))

    def _send(self, node, hex_):
        try:
            node.sendrawtransaction(hex_)
            return None
        except JSONRPCException as e:
            return e

    def check_tx_verdicts(self):
        user = self.nodes[USER]
        unmapped = []
        coins = [u for u in user.listunspent() if u['amount'] > 1 and not u.get('generated')]
        if not coins:                                       # Ycash coinbase cannot pay a t-address directly
            user.sendtoaddress(user.getnewaddress(), 5)
            self.mine(USER)
            coins = [u for u in user.listunspent() if u['amount'] > 1 and not u.get('generated')]
        utxo = coins[0]
        addr = user.getnewaddress()
        fee = Decimal('0.0001')

        def build(amount, vin=None):
            raw = user.createrawtransaction(vin or [{'txid': utxo['txid'], 'vout': utxo['vout']}], {addr: amount})
            return user.signrawtransaction(raw)['hex']

        # outputs above inputs: AcceptToMemoryPool checks the relay fee first (66, policy) -- the
        # class is the path's, which is why the map is keyed by path
        e = self._send(user, build(utxo['amount'] + 1))
        assert_equal(kogany.classify_cxx_tx(e, unmapped), kogany.REJECT_POLICY)
        print('tx: %s -> %s' % (e.error['message'], kogany.classify_cxx_tx(e)))

        outpoint = {'txid': utxo['txid'], 'vout': utxo['vout']}
        dup = build(utxo['amount'] - fee, [outpoint, outpoint])   # CheckTransaction, DoS 100
        e = self._send(user, dup)
        assert_equal(kogany.classify_cxx_tx(e, unmapped), kogany.REJECT_CONSENSUS)
        print('tx: %s -> %s' % (e.error['message'], kogany.classify_cxx_tx(e)))

        missing = user.createrawtransaction([{'txid': '11' * 32, 'vout': 0}], {addr: 1})
        e = self._send(user, missing)
        assert_equal(kogany.classify_cxx_tx(e, unmapped), kogany.REJECT_STATE)
        print('tx: %s -> %s' % (e.error['message'], kogany.classify_cxx_tx(e)))

        good = build(utxo['amount'] - fee)
        assert self._send(user, good) is None
        assert self._send(user, good) is None                # again: ycashd re-relays, no error
        e = self._send(user, build(utxo['amount'] - 2 * fee))   # a double spend of the same coin
        assert e is not None
        assert_equal(kogany.classify_cxx_tx(e, unmapped), kogany.REJECT_POLICY)
        print('tx: %s -> %s' % (e.error['message'], kogany.classify_cxx_tx(e)))
        kogany.current().offer_tx(good, None, 'smoke accept')   # KOGANY_MEMPOOL=1: the followers take it
        self.sync_all()                                      # mempool sync point
        self.mine(USER)
        e = self._send(user, good)
        assert_equal(kogany.classify_cxx_tx(e, unmapped), kogany.REJECT_POLICY)
        print('tx: %s -> %s' % (e.error['message'], kogany.classify_cxx_tx(e)))
        assert_equal(unmapped, [])


if __name__ == '__main__':
    if sys.version_info < (3, 11):
        sys.exit('kogany_mixed_smoke.py needs Python 3.11+ (tomllib)')
    KoganyMixedSmokeTest().main()
