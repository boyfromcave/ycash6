#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Phase 5 (plan section 6, Phase 5; section 8.3): the stock node is unaffected.

Node 1 of the standard topology runs without ``-yellowback`` -- and with ``--stock-binary`` /
``$REF_YCASHD`` it is a real ``ycash-legacy`` v4.5.0 binary (P9).  This script asserts that such a
node has no ``yed_*`` command, that its ``getblocktemplate`` is v4.5.0's key for key with no
``yellowback`` object and the v4.5.0 ``mutable`` list, and that it mines and relays normally
through the whole Yellowback lifecycle: before activation, across activation, through a mint, a
correct redemption of its own making, a rule-breaking block the enforcing nodes reject, and the
reorg that follows.  Nothing the module does reaches it.
"""

import time

from test_framework.authproxy import JSONRPCException
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    sync_blocks,
)
from test_framework.yellowback_util import (
    ENFORCING,
    OBSERVER,
    POOLS,
    REF_LAG,
    STOCK,
    USER,
    YellowbackTestFramework,
    assert_banscore_zero,
    assert_best_hash,
    build_mint_tx,
    build_vault_spend_raw,
    wait_for_rejection,
    wait_yed_healthy,
    ym,
)

# The v4.5.0 getblocktemplate key set (ref/ycash/src/rpc/mining.cpp:754-781, coinbasetxn = true).
V450_GBT_KEYS = sorted([
    'capabilities', 'version', 'previousblockhash', 'lightclientroothash', 'finalsaplingroothash',
    'transactions', 'coinbasetxn', 'longpollid', 'target', 'mintime', 'mutable', 'noncerange',
    'sigoplimit', 'sizelimit', 'curtime', 'bits', 'height',
])
V450_MUTABLE = ['time', 'transactions', 'prevblock']
PRICE = '20.00'
CENTS = 10_000
LOCK = 48


class YellowbackStockNodeTest(YellowbackTestFramework):
    initial_blocks = 101

    def node_args(self, i, extra=None):
        return super().node_args(i, ['-debug=yellowback'] + list(extra or []))

# Rule: BLK-1
# Rule: BLK-2
# Rule: TAG-4
    def run_test(self):
        stock = self.nodes[STOCK]
        print('node 1 binary: %s' % (self.stock_binary() or 'the fork binary without -yellowback'))
        for node in self.enforcing_nodes():
            wait_yed_healthy(node)

        self.no_yed_commands(stock)
        self.mine_and_relay('before activation')
        self.gbt_is_v450(stock)

        print('activation')
        self.activate(quote_usd=PRICE)
        self.mine(POOLS[0], REF_LAG + 1)
        self.no_yed_commands(stock)
        self.gbt_is_v450(stock)
        self.mine_and_relay('after activation')

        self.stock_mines_the_whole_lifecycle()
        self.no_yed_commands(stock)
        self.gbt_is_v450(stock)
        assert_banscore_zero(self.nodes)

    # ------------------------------------------------------------------ cases

    def no_yed_commands(self, stock):
        """``help`` lists no ``yed_`` command and calling one is a plain 'Method not found'."""
        text = stock.help()
        offenders = [ln for ln in text.split('\n') if 'yed_' in ln or 'yellowback' in ln.lower()]
        assert not offenders, 'the stock node advertises Yellowback commands: %s' % offenders
        for name in ('yed_getinfo', 'yed_getstatehash', 'yed_listvaults'):
            try:
                getattr(stock, name)()
                raise AssertionError('%s answered on the stock node' % name)
            except JSONRPCException as e:
                assert 'Method not found' in e.error['message'], e.error['message']

    def gbt_is_v450(self, stock):
        """The template is v4.5.0's shape: no ``yellowback`` object, no ``coinbaseaux``, the
        v4.5.0 ``mutable`` list, and the coinbase scriptSig carries no tag (N10, section 8.3)."""
        gbt = stock.getblocktemplate()
        assert 'yellowback' not in gbt, 'the stock node emits a yellowback object'
        assert 'coinbaseaux' not in gbt, 'the stock node emits coinbaseaux'
        assert_equal(sorted(gbt.keys()), V450_GBT_KEYS)
        assert_equal(gbt['mutable'], V450_MUTABLE)
        cb = ym.tx_from_hex(gbt['coinbasetxn']['data'])
        assert ym.TAG_MAGIC not in bytes(cb.vin[0].script_sig), 'the stock template carries a tag'

    def mine_and_relay(self, label):
        """Node 1 mines and the whole network follows; node 1 relays a pool's block too."""
        h = self.nodes[STOCK].generate(1)[0]
        self.sync_all(blocks_only=True)
        assert_best_hash(self.nodes, label)
        for i in ENFORCING + [OBSERVER]:
            assert_equal(self.nodes[i].getblock(h)['confirmations'], 1)
            assert_equal(self.nodes[i].yed_gettag(str(self.nodes[i].getblock(h)['height']))['found'], False)
        h = self.nodes[POOLS[0]].generate(1)[0]
        self.sync_all(blocks_only=True)
        assert_equal(self.nodes[STOCK].getblock(h)['confirmations'], 1)
        assert_best_hash(self.nodes, label)

    def stock_mines_the_whole_lifecycle(self):
        """A mint, a correct redemption and a rule-breaking block, all mined by node 1: the first
        two are accepted by every node, the third is rejected by the enforcing nodes at DoS 0 and
        node 1 stays a peer of each with ``banscore == 0``."""
        user, stock = self.nodes[USER], self.nodes[STOCK]
        est = user.yed_estimatecollateral(CENTS, LOCK)
        ref, required = int(est['refHeight']), int(est['requiredZat'])
        payee = user.yed_getfeepayee(ref, required)['default']['payoutAddress']
        mint_hex, owner = build_mint_tx(user, CENTS, LOCK, ref, required, fee_addr=payee)
        txid = user.sendrawtransaction(mint_hex)
        self.sync_all()
        h = stock.generate(1)[0]                       # the *stock* node mines the mint
        self.sync_all(blocks_only=True)
        assert txid in stock.getblock(h)['tx']
        assert_best_hash(self.nodes, 'stock-mined mint')
        for i in ENFORCING:
            assert_equal(self.nodes[i].yed_getvault(txid)['status'], 'ACTIVE')
        print('  the stock node mined a mint; every enforcing node recorded it')

        # past the lock, then the correct redemption -- built raw, broadcast and mined by node 1
        self.mine(POOLS[0], LOCK + 2)
        live = dict(user.yed_getvault(txid))
        live['ownerPubKey'] = owner
        r = user.getblockcount() - REF_LAG
        fee = user.yed_getfeepayee(r, int(live['collateralZat']))
        good = build_vault_spend_raw(user, live, 'owner', [(txid, 1)],
                                     payload=ym.encode_redeem(r, 1, []),
                                     fee=(fee['default']['payoutAddress'], int(fee['feeZat'])),
                                     ref_height=r)
        good_txid = stock.sendrawtransaction(good)
        h = stock.generate(1)[0]
        self.sync_all(blocks_only=True)
        assert good_txid in stock.getblock(h)['tx']
        assert_best_hash(self.nodes, 'stock-mined redemption')
        for i in ENFORCING:
            assert_equal(self.nodes[i].yed_getvault(txid)['status'], 'CLOSED')
            assert_equal(self.nodes[i].yed_getvault(txid)['unbacked'], False)
        print('  the stock node mined a correct redemption; every enforcing node accepted it')

        # and now a rule-breaking one: rejected, no ban, node 1 still a peer, then out-mined
        est = user.yed_estimatecollateral(CENTS, LOCK)
        ref, required = int(est['refHeight']), int(est['requiredZat'])
        payee = user.yed_getfeepayee(ref, required)['default']['payoutAddress']
        mint_hex, owner = build_mint_tx(user, CENTS, LOCK, ref, required, fee_addr=payee)
        txid = user.sendrawtransaction(mint_hex)
        self.sync_all()
        self.mine(POOLS[0], LOCK + 2)
        live = dict(user.yed_getvault(txid))
        live['ownerPubKey'] = owner
        bad = build_vault_spend_raw(user, live, 'owner', [], expiry=0)
        bad_txid = stock.sendrawtransaction(bad)
        blockhash = stock.generate(1)[0]
        assert bad_txid in stock.getblock(blockhash)['tx']
        wait_for_rejection([self.nodes[i] for i in ENFORCING], blockhash)
        assert_banscore_zero([self.nodes[i] for i in ENFORCING])
        for i in ENFORCING:
            assert_greater_than(len(self.nodes[i].getpeerinfo()), 0)
        sync_blocks([stock, self.nodes[OBSERVER]])
        assert_equal(self.nodes[OBSERVER].getbestblockhash(), blockhash)
        print('  the stock node mined a rule-breaking block; it was rejected at DoS 0')

        k = 0
        while stock.getbestblockhash() != self.nodes[POOLS[0]].getbestblockhash():
            assert k < 40, 'the pools did not out-mine the stock branch'
            self.nodes[POOLS[k % len(POOLS)]].generate(1)
            time.sleep(0.4)
            k += 1
        if stock.getrawmempool():
            self.restart(STOCK)
            time.sleep(1)
        self.sync_all(blocks_only=True)
        assert_best_hash(self.nodes, 'after the reorg')
        assert_banscore_zero(self.nodes)
        assert_equal(user.yed_getvault(txid)['status'], 'ACTIVE')
        print('  the network reorganised and node 1 followed')


if __name__ == '__main__':
    YellowbackStockNodeTest().main()
