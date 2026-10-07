#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Phase 5 (plan section 6, Phase 5; section 8.3): the stock node is unaffected.

Node 1 of the standard topology runs without the YED attestor set, so Yellowback is not live on it
(U-22; it does run the vault upgrade, a consensus parameter every node shares) -- and with
``--stock-binary`` / ``$REF_YCASHD`` it is a real stock ycashd 6.20.0 binary (P9; the ``ycash6-stock``
build).  Such a binary knows no vault upgrade (it refuses ``-nuparams=6d5b7a31``: "Invalid network
upgrade") and cannot follow a chain past it (upgrade plan finding (37)), so with one the reference
half runs below the upgrade only: the chain stops at ``VAULT_ACTIVATION - 1``, the stock node is
checked there (no ``yed_*``, the stock template, its own block and a pool's block followed both
ways), and node 1 is then restarted on the fork binary without ``-yellowback`` for the rest of the
script, which says so.  This script asserts that such a node has no ``yed_*`` command, that its
``getblocktemplate`` is the stock key set with no ``yellowback`` object and the stock ``mutable``
list, and that it mines and relays normally
through the whole Yellowback lifecycle: before activation, across activation, through a mint, a
correct redemption of its own making, and a rule-breaking block every Yellowback node rejects as
invalid (DoS 100 since the vault upgrade, U-21: the peers disconnect it), after which it is brought
back (invalidateblock, a restart) and follows the valid chain.
"""

from test_framework.authproxy import JSONRPCException
from test_framework.util import VAULT_BRANCH_ID, assert_equal, nuparams, sync_blocks
from test_framework.yellowback_util import (
    ENFORCING,
    OBSERVER,
    POOLS,
    REF_LAG,
    STOCK,
    USER,
    VAULT_ACTIVATION,
    YellowbackTestFramework,
    assert_banscore_zero,
    assert_best_hash,
    build_mint_tx,
    build_vault_spend_raw,
    debug_log_contains,
    wait_for_rejection,
    wait_yed_healthy,
    ym,
)

# The stock getblocktemplate key set of the baseline (ycashd 6.20.0, coinbasetxn = true): v4.5.0's
# (ref/ycash/src/rpc/mining.cpp:754-781) plus 6.20.0's blockcommitmentshash and defaultroots
# (ref/ycash6/src/rpc/mining.cpp:797-815; the old hash names stay under the default-allowed gbt_oldhashes).
V450_GBT_KEYS = sorted([
    'capabilities', 'version', 'previousblockhash', 'lightclientroothash', 'finalsaplingroothash',
    'transactions', 'coinbasetxn', 'longpollid', 'target', 'mintime', 'mutable', 'noncerange',
    'sigoplimit', 'sizelimit', 'curtime', 'bits', 'height', 'blockcommitmentshash', 'defaultroots',
])
V450_MUTABLE = ['time', 'transactions', 'prevblock']
PRICE = '20.00'
CENTS = 10_000
LOCK = 48


class YellowbackStockNodeTest(YellowbackTestFramework):
    initial_blocks = 101
    legacy_done = False       # the reference half (a REF_YCASHD binary on node 1) has run and node 1 is the fork binary
    reference_binary_opt_in = True     # node 1 runs $REF_YCASHD below VAULT_ACTIVATION (node_args strips the vault -nuparams)

    def legacy(self):
        """A reference binary on node 1 that has not yet been swapped for the fork binary."""
        return bool(super().stock_binary()) and not self.legacy_done

    def stock_binary(self):
        return None if self.legacy_done else super().stock_binary()

    def node_args(self, i, extra=None):
        args = super().node_args(i, ['-debug=yellowback'] + list(extra or []))
        if i == STOCK and self.legacy():
            args = [a for a in args if a != nuparams(VAULT_BRANCH_ID, VAULT_ACTIVATION)]     # stock 6.20.0 has no such upgrade
        return args

    def setup_network(self, split=False):
        if self.legacy():
            # the reference half stays below the vault upgrade: no attestor set yet (create_attestor_set
            # mines to VAULT_ACTIVATION), and the chain starts two blocks lower so node 1 and a pool each
            # mine one block before VAULT_ACTIVATION - 1
            self.auto_attestor_set = False
            self.initial_blocks = VAULT_ACTIVATION - 4
        super().setup_network(split)

# Rule: BLK-1
# Rule: BLK-2
# Rule: TAG-4
    def run_test(self):
        stock = self.nodes[STOCK]
        print('node 1 binary: %s' % (self.stock_binary() or 'the fork binary without -yellowback'))
        if self.legacy():
            self.reference_below_the_upgrade()
            stock = self.nodes[STOCK]
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

    def reference_below_the_upgrade(self):
        """The REF_YCASHD half: the stock 6.20.0 binary up to VAULT_ACTIVATION - 1, then node 1 on the
        fork binary and the attestor set (the rest of the script runs as without a reference binary)."""
        stock = self.nodes[STOCK]
        print('reference binary below the vault upgrade (tip %d, the upgrade at %d)' % (stock.getblockcount(), VAULT_ACTIVATION))
        assert '6d5b7a31' not in stock.getblockchaininfo().get('upgrades', {})
        self.no_yed_commands(stock)
        self.gbt_is_v450(stock)
        for miner in (STOCK, POOLS[0], STOCK):
            h = self.nodes[miner].generate(1)[0]
            self.sync_all(blocks_only=True)
            assert_best_hash(self.nodes, 'reference half, node %d mined' % miner)
            for node in self.nodes:
                assert_equal(node.getblock(h)['confirmations'], 1)
        assert_equal(stock.getblockcount(), VAULT_ACTIVATION - 1)
        self.gbt_is_v450(stock)
        assert_banscore_zero(self.nodes)
        print('*** the reference half ends at %d: a stock 6.20.0 binary cannot follow the vault upgrade (finding 37); '
              'node 1 is the fork binary without -yellowback from here' % (VAULT_ACTIVATION - 1))
        self.legacy_done = True
        self.restart(STOCK)
        self.sync_all(blocks_only=True)
        self.create_attestor_set()

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
        two are accepted by every node, the third is rejected by every Yellowback node (DoS 100)."""
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
        wait_for_rejection([self.nodes[i] for i in ENFORCING + [OBSERVER]], blockhash)
        assert debug_log_contains(self.options.tmpdir, POOLS[0], 'BAN THRESHOLD EXCEEDED')     # DoS 100 from node 1
        print('  the stock node mined a rule-breaking block; every Yellowback node rejected it (DoS 100)')

        for k in range(2):                             # the overlay moves on without node 1 (it is disconnected)
            self.nodes[POOLS[k]].generate(1)
            sync_blocks([self.nodes[i] for i in ENFORCING])
        stock.invalidateblock(blockhash)
        self.restart(STOCK)                            # its mempool goes; its edges come back
        self.sync_all(blocks_only=True)
        assert_best_hash(self.nodes, 'after the reorg')
        assert_banscore_zero(self.nodes)
        assert_equal(user.yed_getvault(txid)['status'], 'ACTIVE')
        print('  the network reorganised and node 1 followed')


if __name__ == '__main__':
    YellowbackStockNodeTest().main()
