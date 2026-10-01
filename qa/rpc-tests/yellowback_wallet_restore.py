#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Wallet restore (plan §4.6 "one fresh key per position", "nothing Yellowback-specific is written
to wallet.dat"): a second wallet that imports node 0's keys — without a rescan — sees the same
YED balance, coins and positions from the index alone, locks them with yed_lockcoins, and
redeems a vault with the imported owner key; the owner's view agrees. Then the experimental
encrypted wallet (-developerencryptwallet): a locked wallet refuses every Yellowback command
that signs, an unlocked one mints.

Nodes: 0 user (the original wallet), 1 stock, 2-4 pools, 5 observer (the restored wallet).
"""

from test_framework.util import assert_equal, assert_greater_than, bitcoind_processes, start_node
from test_framework.yellowback_util import (
    REF_WINDOW,
    POOLS,
    REF_LAG,
    YellowbackTestFramework,
    assert_same_statehash,
)
from test_framework.yellowback_attest import ArmedModeMixin, offline_bundle_hex


def assert_rpc_error(substr, fn, *args):
    try:
        fn(*args)
    except Exception as e:
        assert substr in str(e), 'expected %r in %r' % (substr, str(e))
        return
    raise AssertionError('expected an error containing %r' % substr)


class YellowbackWalletRestoreTest(ArmedModeMixin, YellowbackTestFramework):

    def run_test(self):
        nodes = self.nodes
        user, restored = nodes[0], nodes[5]

        print('activate at $50')
        self.activate(POOLS, quote_usd=50)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        self.arm()

# Rule: MINT-3 XFER-1
        print('node 0 mints twice (class A and class B) and sends 50 YED to a fresh own address; node 5 holds nothing')
        m1 = self.mint(user, 10000, 48)
        m2 = self.mint(user, 20000, 100)
        assert_equal(m2['termClass'], 'B')
        self.sync_all()
        self.mine(POOLS[0])
        sent = user.yed_send(user.yed_getnewaddress(), 5000)
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(user.yed_getbalance()['confirmedCents'], 30000)
        positions0 = sorted(p['txid'] for p in user.yed_listpositions())
        assert_equal(positions0, sorted([m1['txid'], m2['txid']]))
        assert_equal(restored.yed_getbalance()['confirmedCents'], 0)
        assert_equal(restored.yed_listpositions(), [])
        coins0 = sorted((c['txid'], c['vout'], c['cents']) for c in user.yed_listunspent())
        assert_equal(sorted(c[2] for c in coins0), [5000, 5000, 20000])
        owner_keyids = sorted(p['ownerKeyId'] for p in user.yed_listpositions())
        yed_addrs = {c['address'] for c in user.yed_listunspent()}

        print('dump every key node 0 used and import it into node 5 without a rescan')
        imported = 0
        for addr in set(user.getaddressesbyaccount('')):
            info = user.validateaddress(addr)
            if not info.get('ismine', False) or info.get('isscript', False):
                continue
            restored.importprivkey(user.dumpprivkey(addr), '', False)
            imported += 1
        assert_greater_than(imported, 2)
        for a in yed_addrs:
            assert_equal(restored.yed_validateaddress(a)['ismine'], True)
            assert_equal(user.yed_validateaddress(a)['transparentAddress'], restored.yed_validateaddress(a)['transparentAddress'])

        print('node 5 sees the same balance, coins and positions from the index alone')
        assert_equal(restored.yed_getbalance()['confirmedCents'], 30000)
        assert_equal(sorted((c['txid'], c['vout'], c['cents']) for c in restored.yed_listunspent()), coins0)
        assert_equal(sorted(p['txid'] for p in restored.yed_listpositions()), positions0)
        assert_equal(sorted(p['ownerKeyId'] for p in restored.yed_listpositions()), owner_keyids)
        for p in restored.yed_listpositions():
            assert_equal(set(p) >= {'txid', 'vout', 'status', 'ownerPubKey', 'ownerKeyId', 'ownerAddress', 'termClass',
                                    'lockHeight', 'claimHeight', 'collateralZat', 'collateral', 'mintedCents', 'mintHeight',
                                    'refHeight', 'feePaidZat', 'closeHeight', 'closingTxid', 'burnedCents', 'unbacked',
                                    'claimable', 'underwaterAt', 'voidReason', 'canRedeem', 'canClaim', 'canSweep'}, True)
        locked = restored.yed_lockcoins()
        assert_equal(len(locked), len(coins0))
        assert_equal(sorted((l['txid'], l['vout']) for l in locked), sorted((c[0], c[1]) for c in coins0))
        assert_equal([c['locked'] for c in restored.yed_listunspent()], [True] * 3)
        hist = restored.yed_listtransactions()
        assert_equal(sorted(h['type'] for h in hist), ['mint', 'mint', 'send'])
        assert_equal([h for h in hist if h['txid'] == sent['txid']][0]['amountCents'], 0)   # own to own

# Rule: RED-1 RED-2 RED-3
        print('node 5 redeems the class-A vault with the imported owner key')
        lock1 = restored.yed_getvault(m1['txid'])['lockHeight']
        self.mine_round_robin(POOLS, lock1 - user.getblockcount())
        assert_equal([p['canRedeem'] for p in restored.yed_listpositions() if p['txid'] == m1['txid']], [True])
        red = restored.yed_redeem(m1['txid'])
        assert_equal(red['burnedCents'], 10000)
        self.sync_all()
        self.mine(POOLS[2])
        for node in (user, restored, nodes[2]):
            assert_equal(node.yed_getvault(m1['txid'])['status'], 'CLOSED')
        assert_equal(restored.yed_getbalance()['confirmedCents'], 20000)
        assert_equal(user.yed_getbalance()['confirmedCents'], 20000)          # same keys, same view
        assert_equal([h['type'] for h in restored.yed_listtransactions() if h['txid'] == red['txid']], ['redeem'])
        assert_equal([h['type'] for h in user.yed_listtransactions() if h['txid'] == red['txid']], ['redeem'])
        assert_same_statehash(self.enforcing_nodes())
        # node 0's stage-(iii) reconciliation pruned the spent outpoint and keeps the rest locked
        assert_equal(sorted(c['cents'] for c in user.yed_listunspent()), [20000])
        assert_equal(sorted(c['cents'] for c in restored.yed_listunspent()), [20000])
        assert_equal([c['locked'] for c in user.yed_listunspent()], [True] * len(user.yed_listunspent()))

        print('encrypted wallet (experimental, -developerencryptwallet): locked refuses to sign, unlocked mints')
        self.restart(0, ['-developerencryptwallet'])
        user = nodes[0]
        user.encryptwallet('pass')
        # encryptwallet shuts the node down by itself; wait for the process, then restart it.
        bitcoind_processes[0].wait()
        del bitcoind_processes[0]
        nodes[0] = start_node(0, self.options.tmpdir, self.node_args(0, ['-developerencryptwallet']))
        user = nodes[0]
        self.reconnect(0)
        self.sync_all(blocks_only=True)
        assert_rpc_error('walletpassphrase', user.yed_mint, 10000, 48)
        assert_rpc_error('walletpassphrase', user.yed_send, restored.yed_getnewaddress(), 100)
        assert_rpc_error('walletpassphrase', user.yed_redeem, m2['txid'])
        assert_equal(user.yed_getbalance()['confirmedCents'], 20000)          # reading needs no passphrase
        user.walletpassphrase('pass', 120)
        m3 = self.mint(user, 10000, 48)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(nodes[2].yed_getvault(m3['txid'])['status'], 'ACTIVE')
        assert_equal(user.yed_getbalance()['confirmedCents'], 30000)
        assert_equal(restored.yed_getbalance()['confirmedCents'], 20000)      # the new key is not in the restored wallet
        self.model_check(nodes[2])
        self.checkpoint('restore')

# Rule: W7
        print('an outstanding carrier survives a restart (carriers.dat, never wallet.dat) and is swept once its window lapses')
        r = user.yed_getinfo()['height'] - REF_LAG
        bundle = offline_bundle_hex(self, user, r, b'', self.price_at(user, r, 'pMint')) if self.armed else ''
        pend = user.yed_mint(10000, 48, '', bundle, False)                 # wait=false: the carrier is broadcast, the mint pending
        assert_equal(pend['pending'], True)
        self.sync_all()
        self.restart(0, ['-developerencryptwallet'])                       # the pending completion lived in memory
        user = nodes[0]
        self.sync_all()
        self.mine(POOLS[0])                                                # the carrier confirms; nobody completes the mint
        assert_equal(user.yed_sweepcarriers()['outstanding'], 1)          # reading needs no passphrase; nothing lapsed yet
        self.mine_round_robin(POOLS, REF_WINDOW)
        assert_rpc_error('walletpassphrase', user.yed_sweepcarriers)      # the sweep signs
        user.walletpassphrase('pass', 120)
        swept = user.yed_sweepcarriers()
        assert_equal((swept['count'], swept['outstanding']), (1, 0))
        assert_equal([v['txid'] for v in user.getrawtransaction(swept['txid'], 1)['vin']], [pend['carrierTxid']])
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(user.gettxout(pend['carrierTxid'], 0), None)
        assert_equal(restored.yed_sweepcarriers()['outstanding'], 0)      # the restored wallet never knew the carrier (W7)


if __name__ == '__main__':
    YellowbackWalletRestoreTest().main()
