#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Balances and listings by address type (beta2 item 15; address plan W1.5 on the reference line, findings L-2 … L-6).

One wallet (node 0, a fresh wallet file so no coinbase of its own) holds an ECC transparent address, a post-quantum
address of each scheme (FN-DSA-512 = 2, SLH-DSA-SHA2-128s = 1; Falcon is active on this chain) and a Sapling address.
Every view is checked in five states: payments from another wallet unconfirmed, confirmed, this wallet's own spends
unconfirmed, confirmed, the spends' block disconnected (reorg) and reconnected, and the wallet encrypted and locked:

- getwalletinfo: balance = balance_ecc + balance_pq, unconfirmed_balance = unconfirmed_balance_ecc +
  unconfirmed_balance_pq, pq_by_scheme (both schemes, number and name);
- z_gettotalbalance (minconf 1 and 0): transparent = transparent_ecc + transparent_pq, pq_by_scheme;
- z_getbalance of every address, a post-quantum one included (L-3), at minconf 1 and 0;
- listreceivedbyaddress 0 true lists every transparent address, a PQ one with pqscheme / pqschemename (L-4);
  z_listaddresses the Sapling one; validateaddress names the scheme;
- the rule for unconfirmed funds (L-6): getwalletinfo.balance counts own unconfirmed outputs (change),
  unconfirmed_balance counts others' unconfirmed payments, z_gettotalbalance / z_getbalance count by depth only, so
  z_gettotalbalance(0).transparent == balance + unconfirmed_balance always, and the PQ figures follow the same rule.

No address text or prefix is hard-coded: addresses come from the node and their scheme from validateaddress.

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/wallet_balance_by_type.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>

One file on both C++ lines (ycash-dd: BITCOIND=, ycash6: ZCASHD=). What differs between them is behind test_framework/util.py
helpers each line defines: SEED_RESTORE_OPTION (-hdseedfile / -mnemonicfile), z_sendmany_wait (the fee and privacy
policy each line's z_sendmany takes) and assert_listaddresses_pq (6.x's listaddresses lists the PQ addresses with their
scheme; ycash-dd has no listaddresses and its helper returns).
"""

import os
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    SEED_RESTORE_OPTION,
    VAULT_BRANCH_ID,
    assert_equal,
    assert_listaddresses_pq,
    bitcoind_processes,
    connect_nodes_bi,
    nuparams,
    seed_restored_balance_ecc,
    start_node,
    start_nodes,
    stop_node,
    sync_blocks,
    z_sendmany_wait,
    wait_and_assert_operationid_status,
    z_sendmany_opid,
)
from test_framework.yellowback_util import activate_yed_late, mint_to_fresh_holder

ACTIVATION = 210
SLH, FN = 1, 2
NAMES = {SLH: 'SLH-DSA-SHA2-128s', FN: 'FN-DSA-512'}
PASSPHRASE = 'balance-by-type'
FOREIGN_TADDR = 'From address does not belong to this node, transparent or post-quantum key or watch-only script not found.'
FOREIGN_ZADDR = 'From address does not belong to this node, spending key or viewing key not found.'


def D(x):
    return Decimal(str(x))


def assert_raises_rpc(substr, fn, *args):
    try:
        fn(*args)
    except JSONRPCException as e:
        assert substr in e.error['message'], 'expected %r in %r' % (substr, e.error['message'])
        return e.error['message']
    raise AssertionError('expected an RPC error containing %r' % substr)


class WalletBalanceByTypeTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = False

    def node_args(self, i, wallet='bytype.dat'):
        a = [nuparams(VAULT_BRANCH_ID, ACTIVATION), '-pqfalcon=1']
        if i == 0:
            # a wallet of its own: the cached chain's coinbase of node 0 stays in wallet.dat
            a += ['-wallet=%s' % wallet, '-experimentalfeatures', '-developerencryptwallet',
                  '-exportdir=%s' % os.path.join(self.options.tmpdir, 'export0')]
        return a + getattr(self, 'yed_args', {}).get(i, [])

    def restart0(self, extra=(), wallet='bytype.dat'):
        stop_node(self.nodes[0], 0)
        self.nodes[0] = start_node(0, self.options.tmpdir, self.node_args(0, wallet) + list(extra))
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

    # ---- the views ----------------------------------------------------------------------------------------------

    def view(self, locked_in=None):
        """Every balance figure of node 0, as Decimals, with the invariants checked. locked: the value of coins
        locked with lockunspent, {'ecc': x, 1: slh, 2: fn}, which getwalletinfo counts and the by-depth calls do not."""
        locked = dict({'ecc': 0, SLH: 0, FN: 0}); locked.update(locked_in or {})
        n0 = self.nodes[0]
        w = n0.getwalletinfo()
        v = {'balance': D(w['balance']), 'unconfirmed': D(w['unconfirmed_balance']),
             'balance_ecc': D(w['balance_ecc']), 'balance_pq': D(w['balance_pq']),
             'unconfirmed_ecc': D(w['unconfirmed_balance_ecc']), 'unconfirmed_pq': D(w['unconfirmed_balance_pq']),
             'immature': D(w['immature_balance'])}
        assert_equal(v['balance'], v['balance_ecc'] + v['balance_pq'])
        assert_equal(v['unconfirmed'], v['unconfirmed_ecc'] + v['unconfirmed_pq'])
        assert_equal([(s['pqscheme'], s['pqschemename']) for s in w['pq_by_scheme']], [(SLH, NAMES[SLH]), (FN, NAMES[FN])])
        for s in w['pq_by_scheme']:
            v['balance_pq_%d' % s['pqscheme']] = D(s['balance_pq'])
            v['unconfirmed_pq_%d' % s['pqscheme']] = D(s['unconfirmed_balance_pq'])
        assert_equal(v['balance_pq'], v['balance_pq_1'] + v['balance_pq_2'])
        assert_equal(v['unconfirmed_pq'], v['unconfirmed_pq_1'] + v['unconfirmed_pq_2'])
        assert_equal(D(n0.getbalance()), v['balance'])
        for minconf in (1, 0):
            t = n0.z_gettotalbalance(minconf)
            k = 'z%d_' % minconf
            for f in ('transparent', 'private', 'total', 'transparent_ecc', 'transparent_pq'):
                assert isinstance(t[f], str), (f, t[f])     # strings, as the existing three are
                v[k + f] = D(t[f])
            assert_equal(v[k + 'transparent'], v[k + 'transparent_ecc'] + v[k + 'transparent_pq'])
            assert_equal(v[k + 'total'], v[k + 'transparent'] + v[k + 'private'])
            assert_equal([(s['pqscheme'], s['pqschemename']) for s in t['pq_by_scheme']], [(SLH, NAMES[SLH]), (FN, NAMES[FN])])
            for s in t['pq_by_scheme']:
                v[k + 'pq_%d' % s['pqscheme']] = D(s['transparent_pq'])
            assert_equal(v[k + 'transparent_pq'], v[k + 'pq_1'] + v[k + 'pq_2'])
        # L-6: minconf 0 counts every unconfirmed output; balance + unconfirmed_balance counts them too, so the two
        # agree, for the ECC part, the PQ part and each scheme, except for coins locked with lockunspent (counted by
        # getwalletinfo only). Immature coinbase is in neither (immature_balance); watch-only is in neither here.
        lpq = locked[SLH] + locked[FN]
        assert_equal(v['z0_transparent'], v['balance'] + v['unconfirmed'] - locked['ecc'] - lpq)
        assert_equal(v['z0_transparent_ecc'], v['balance_ecc'] + v['unconfirmed_ecc'] - locked['ecc'])
        assert_equal(v['z0_transparent_pq'], v['balance_pq'] + v['unconfirmed_pq'] - lpq)
        for s in (SLH, FN):
            assert_equal(v['z0_pq_%d' % s], v['balance_pq_%d' % s] + v['unconfirmed_pq_%d' % s] - locked[s])
        for name, addr in self.addrs.items():
            for minconf in (1, 0):
                v['%s@%d' % (name, minconf)] = self.zbal(addr, minconf)
        # per address adds up to the totals
        for minconf in (1, 0):
            k = 'z%d_' % minconf
            assert_equal(v[k + 'pq_%d' % FN], v['fn@%d' % minconf])
            assert_equal(v[k + 'pq_%d' % SLH], v['slh@%d' % minconf])
            assert_equal(v[k + 'private'], v['z@%d' % minconf])
        return v

    def check_listing(self, ecc=True):
        n0 = self.nodes[0]
        rcv = {r['address']: r for r in n0.listreceivedbyaddress(0, True)}
        for name, scheme in (('fn', FN), ('slh', SLH)):
            r = rcv[self.addrs[name]]
            assert_equal((r['pqscheme'], r['pqschemename']), (scheme, NAMES[scheme]))
            va = n0.validateaddress(self.addrs[name])
            assert_equal((va['ismine'], va['pqscheme'], va['pqschemename']), (True, scheme, NAMES[scheme]))
        if ecc:
            r = rcv[self.addrs['ecc']]
            assert 'pqscheme' not in r and 'pqschemename' not in r
            assert 'pqschemename' not in n0.validateaddress(self.addrs['ecc'])
        assert_equal(n0.z_listaddresses(), [self.addrs['z']])
        assert_listaddresses_pq(n0, {self.addrs[name]: ('mnemonic_seed', scheme, NAMES[scheme]) for name, scheme in (('fn', FN), ('slh', SLH))})

    def zbal(self, addr, minconf=1):
        """z_getbalance of an address; a transparent address this wallet does not hold (no key, no watch-only
        script; e.g. the ECC key after a seed-only restore) is refused (beta2, both lines) and counts as 0 here."""
        n0 = self.nodes[0]
        va = n0.validateaddress(addr)
        if va['isvalid'] and not va['ismine'] and not va['iswatchonly']:
            assert_raises_rpc(FOREIGN_TADDR, n0.z_getbalance, addr, minconf)
            return Decimal(0)
        return D(n0.z_getbalance(addr, minconf))

    # ---- the test ----------------------------------------------------------------------------------------------

    def run_test(self):
        n0, n1 = self.nodes
        self.mine(ACTIVATION - n0.getblockcount())

        print('a fresh wallet: an ECC, an FN-DSA-512, an SLH-DSA and a Sapling address, all zero')
        self.addrs = {'ecc': n0.getnewaddress(), 'fn': n0.getnewaddress('', 'pq'),
                      'slh': n0.getnewaddress('', 'pqslh'), 'z': n0.z_getnewaddress('sapling')}
        assert_equal(n0.validateaddress(self.addrs['fn'])['pqscheme'], FN)     # Falcon active: "pq" is FN-DSA-512
        assert_equal(n0.validateaddress(self.addrs['slh'])['pqscheme'], SLH)
        v = self.view()
        assert all(x == 0 for x in v.values()), v
        self.check_listing()

        print('payments from another wallet, unconfirmed: unconfirmed_balance by type; z_* only at minconf 0')
        t1 = n1.getnewaddress()
        n1.sendtoaddress(t1, 10)
        self.mine(1)
        z_sendmany_wait(n1, t1, [{'address': self.addrs['z'], 'amount': 1}])
        n1.sendtoaddress(self.addrs['ecc'], 3)
        n1.sendtoaddress(self.addrs['fn'], 2)
        n1.sendtoaddress(self.addrs['slh'], Decimal('1.5'))
        self.sync_all()
        v = self.view()
        assert_equal((v['balance'], v['balance_ecc'], v['balance_pq']), (0, 0, 0))
        assert_equal((v['unconfirmed'], v['unconfirmed_ecc'], v['unconfirmed_pq']), (Decimal('6.5'), 3, Decimal('3.5')))
        assert_equal((v['unconfirmed_pq_1'], v['unconfirmed_pq_2']), (Decimal('1.5'), 2))
        assert_equal((v['z1_transparent'], v['z1_private'], v['z1_total']), (0, 0, 0))
        assert_equal((v['z0_transparent'], v['z0_transparent_ecc'], v['z0_transparent_pq']), (Decimal('6.5'), 3, Decimal('3.5')))
        assert_equal((v['z0_private'], v['z0_total']), (1, Decimal('7.5')))
        assert_equal((v['ecc@1'], v['fn@1'], v['slh@1'], v['z@1']), (0, 0, 0, 0))
        assert_equal((v['ecc@0'], v['fn@0'], v['slh@0'], v['z@0']), (3, 2, Decimal('1.5'), 1))
        self.check_listing()

        print('confirmed: balance by type and scheme, every address')
        self.mine(1)
        v = self.view()
        assert_equal((v['balance'], v['balance_ecc'], v['balance_pq']), (Decimal('6.5'), 3, Decimal('3.5')))
        assert_equal((v['balance_pq_1'], v['balance_pq_2'], v['unconfirmed']), (Decimal('1.5'), 2, 0))
        for k in ('z1_', 'z0_'):
            assert_equal((v[k + 'transparent'], v[k + 'transparent_ecc'], v[k + 'transparent_pq'], v[k + 'private'],
                          v[k + 'total'], v[k + 'pq_1'], v[k + 'pq_2']),
                         (Decimal('6.5'), 3, Decimal('3.5'), 1, Decimal('7.5'), Decimal('1.5'), 2))
        assert_equal((v['ecc@1'], v['fn@1'], v['slh@1'], v['z@1']), (3, 2, Decimal('1.5'), 1))
        self.check_listing()
        confirmed = v

        print('own spends, unconfirmed (L-6): balance counts own change, z_gettotalbalance at minconf 1 does not')
        out = n1.getnewaddress()
        # SLH-DSA: z_sendmany from the SLH address spends its coin; its change returns to that address (sendtoaddress
        # spends ECC coins only since beta2 audit M-1)
        tx_s = wait_and_assert_operationid_status(n0, z_sendmany_opid(n0, self.addrs['slh'], [(out, 1)]))
        fee_s = -D(n0.gettransaction(tx_s)['fee'])
        assert_equal(len(n0.getrawtransaction(tx_s, 1)['vin']), 1)
        change_s = Decimal('1.5') - 1 - fee_s
        assert_equal([D(u['amount']) for u in n0.listunspent(0, 9999999, [self.addrs['slh']])], [change_s])   # the change
        # ECC: z_sendmany spends every coin of the ECC address; its change goes to a new ECC key of the wallet
        tx_e = z_sendmany_wait(n0, self.addrs['ecc'], [{'address': out, 'amount': 1}])
        fee_e = -D(n0.gettransaction(tx_e)['fee'])
        self.sync_all()
        v = self.view()
        assert_equal(v['unconfirmed'], 0)                               # nothing from others
        assert_equal(v['balance'], Decimal('6.5') - 2 - fee_e - fee_s)
        assert_equal(v['balance_pq'], 2 + change_s)                     # the FN coin and the SLH change
        assert_equal((v['balance_pq_1'], v['balance_pq_2']), (change_s, 2))   # own unconfirmed change counted
        assert_equal(v['balance_ecc'], 3 - 1 - fee_e)
        assert_equal(v['z1_transparent_ecc'], 0)                        # depth only: the change is unconfirmed,
        assert_equal(v['z1_transparent_pq'], 2)                         # the spent coins are gone
        assert_equal(v['z0_transparent'], v['balance'])
        assert_equal((v['ecc@1'], v['ecc@0'], v['slh@1'], v['slh@0'], v['fn@1']), (0, 0, 0, change_s, 2))
        self.check_listing()
        unconfirmed_spends = v

        print('own spends, confirmed')
        self.mine(1)
        blk = n0.getbestblockhash()
        v = self.view()
        assert_equal(v['balance'], unconfirmed_spends['balance'])
        assert_equal(v['z1_transparent'], v['balance'])
        assert_equal((v['z1_transparent_ecc'], v['z1_transparent_pq'], v['z1_pq_1'], v['z1_pq_2']),
                     (v['balance_ecc'], 2 + change_s, change_s, 2))
        assert_equal((v['ecc@1'], v['slh@1'], v['fn@1'], v['z@1']), (0, change_s, 2, 1))
        spent_confirmed = v

        print('reorg: the spends\' block disconnected, the spends back in the mempool, then reconnected')
        n0.invalidateblock(blk)
        assert tx_e in n0.getrawmempool() and tx_s in n0.getrawmempool()
        assert_equal(self.view(), unconfirmed_spends)
        n0.reconsiderblock(blk)
        sync_blocks(self.nodes)
        assert_equal(self.view(), spent_confirmed)

        print('reorg below the payments: they go back to unconfirmed, and so do the views')
        pay_blk = n0.getblockhash(n0.getblockcount() - 1)
        n0.invalidateblock(pay_blk)
        v = self.view()
        assert_equal(v['z1_transparent'], 0)
        assert_equal(v['z0_transparent'], v['balance'] + v['unconfirmed'])
        n0.reconsiderblock(pay_blk)
        sync_blocks(self.nodes)
        assert_equal(self.view(), spent_confirmed)
        self.check_listing()

        print('z_getbalance of addresses this wallet does not hold: refused, transparent (ECC, PQ of each scheme) and shielded')
        for foreign in (n1.getnewaddress(), n1.getnewaddress('', 'pq'), n1.getnewaddress('', 'pqslh')):
            for minconf in (1, 0):
                assert_raises_rpc(FOREIGN_TADDR, n0.z_getbalance, foreign, minconf)
        assert_raises_rpc(FOREIGN_ZADDR, n0.z_getbalance, n1.z_getnewaddress('sapling'))
        assert_raises_rpc('Invalid from address, should be a taddr or zaddr.', n0.z_getbalance, 'not-an-address')
        # its own addresses answer (ECC, both PQ schemes, Sapling): self.view() reads each of them at minconf 1 and 0

        print('a coin locked with lockunspent: getwalletinfo still counts it, the by-depth calls leave it out')
        fn_coin = [{'txid': u['txid'], 'vout': u['vout']} for u in n0.listunspent(1, 9999999, [self.addrs['fn']])]
        assert n0.lockunspent(False, fn_coin)
        v = self.view(locked_in={FN: Decimal(2)})
        assert_equal((v['balance_pq'], v['balance_pq_2'], v['balance']), (2 + change_s, 2, spent_confirmed['balance']))
        assert_equal((v['z1_transparent_pq'], v['z1_pq_2'], v['fn@1'], v['fn@0']), (change_s, 0, 0, 0))
        assert_equal(v['z1_transparent'], spent_confirmed['z1_transparent'] - 2)
        assert n0.lockunspent(True, fn_coin)
        assert_equal(self.view(), spent_confirmed)

        print('watch-only coins: only z_gettotalbalance with includeWatchonly (and z_getbalance of the address) count them')
        w_e, w_fn = n1.getnewaddress(), n1.getnewaddress('', 'pq')
        n1.sendtoaddress(w_e, 1)
        n1.sendtoaddress(w_fn, Decimal('0.5'))
        self.mine(1)
        n0.importaddress(w_e, '', True)
        n0.importaddress(w_fn, '', True)
        assert_equal(self.view(), spent_confirmed)
        for minconf in (1, 0):
            t = n0.z_gettotalbalance(minconf, True)
            k = 'z%d_' % minconf
            assert_equal((D(t['transparent']), D(t['transparent_ecc']), D(t['transparent_pq'])),
                         (spent_confirmed[k + 'transparent'] + Decimal('1.5'), spent_confirmed[k + 'transparent_ecc'] + 1,
                          spent_confirmed[k + 'transparent_pq'] + Decimal('0.5')))
            assert_equal([(x['pqscheme'], D(x['transparent_pq'])) for x in t['pq_by_scheme']],
                         [(SLH, spent_confirmed[k + 'pq_1']), (FN, spent_confirmed[k + 'pq_2'] + Decimal('0.5'))])
        assert_equal((D(n0.z_getbalance(w_e)), D(n0.z_getbalance(w_fn))), (1, Decimal('0.5')))
        w = {r['address']: r for r in n0.listreceivedbyaddress(0, True, True)}
        assert_equal((w[w_fn]['involvesWatchonly'], w[w_fn]['pqscheme'], w[w_fn]['pqschemename']), (True, FN, NAMES[FN]))
        assert 'pqscheme' not in w[w_e]
        assert_listaddresses_pq(n0, {w_fn: ('imported_watchonly', FN, NAMES[FN])}, exact=('imported_watchonly',))

        print('immature coinbase: immature_balance only, then balance_ecc and transparent_ecc once mature')
        before = self.view()
        self.sync_all()
        n0.generate(1)
        self.sync_all()
        v = self.view()
        reward = v['immature']
        assert reward > 0
        for k in ('balance', 'balance_ecc', 'balance_pq', 'unconfirmed', 'z1_transparent', 'z0_transparent', 'z1_transparent_pq'):
            assert_equal((k, v[k]), (k, before[k]))
        self.mine(100)
        v = self.view()
        assert_equal(v['immature'], 0)
        assert_equal((v['balance_ecc'], v['balance_pq']), (before['balance_ecc'] + reward, before['balance_pq']))
        assert_equal((v['z1_transparent_ecc'], v['z1_transparent_pq']), (before['z1_transparent_ecc'] + reward, before['z1_transparent_pq']))
        settled = v

        print('restore from the seed alone: the PQ coins, their addresses with the scheme, the first Sapling address')
        export = n0.z_exportwallet('bytypeseed')
        self.restart0(['%s=%s' % (SEED_RESTORE_OPTION, export)], wallet='restored.dat')
        n0 = self.nodes[0]
        r = self.view()
        assert_equal((r['balance_pq'], r['balance_pq_1'], r['balance_pq_2']), (settled['balance_pq'], change_s, settled['balance_pq_2']))
        assert_equal((r['z1_transparent_pq'], r['z1_private'], r['fn@1'], r['slh@1'], r['z@1']),
                     (settled['z1_transparent_pq'], settled['z1_private'], 2, change_s, 1))
        # the getnewaddress ECC key is not re-found from the seed on either line: only a wallet.dat backup restores
        # it. What ECC the restored wallet finds is a line difference (seed_restored_balance_ecc, test_framework/util.py):
        # none on ycash-dd (random keypool keys); on 6.x the keypool keys come from the seed and the rescan re-finds
        # some of them (change).
        assert not n0.validateaddress(self.addrs['ecc'])['ismine']
        assert_equal(r['balance_ecc'], seed_restored_balance_ecc(settled))
        # the restored PQ keys are filed by the rescan (beta2); listreceivedbyaddress lists them
        self.check_listing(ecc=False)
        self.restart0()
        n0 = self.nodes[0]
        assert_equal(self.view(), settled)
        spent_confirmed = settled

        print('an encrypted, locked wallet shows the same balances and listings')
        n0.encryptwallet(PASSPHRASE)
        bitcoind_processes[0].wait()
        self.nodes[0] = start_node(0, self.options.tmpdir, self.node_args(0))
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        n0 = self.nodes[0]
        assert_equal(n0.getwalletinfo()['unlocked_until'], 0)
        assert_equal(self.view(), spent_confirmed)
        self.check_listing()
        assert_raises_rpc('walletpassphrase', n0.getnewaddress, '', 'pq')
        n0.walletpassphrase(PASSPHRASE, 60)
        assert_equal(self.view(), spent_confirmed)
        n0.walletlock()

        self.restored_classification()
        self.yed_holder_keys()

    def classification(self, addrs, txids):
        """How node 0 classifies what reached ``addrs``: its listreceivedbyaddress entries (amount, scheme,
        yed_holder), getreceivedbyaddress, and the listtransactions rows of ``txids`` that name them."""
        n0 = self.nodes[0]
        # entries with receipts only: an address never paid is not re-found by a seed restore (nothing names it)
        rcv = sorted((r['address'], D(r['amount']), r.get('pqscheme'), r.get('yed_holder', False))
                     for r in n0.listreceivedbyaddress(0, True) if r['address'] in addrs and D(r['amount']) > 0)
        got = sorted((a, D(n0.getreceivedbyaddress(a, 0))) for a in addrs)
        rows = sorted((t['txid'], t['category'], D(t['amount']), t['address'])
                      for t in n0.listtransactions('*', 10000) if t['txid'] in txids and t.get('address') in addrs)
        return rcv, got, rows

    def restored_classification(self):
        """A seed-only restore re-finds the PQ keys by rescan and files them (beta2): receipts at them are classified,
        listed and counted as on the original wallet: an own send from a PQ coin to a new PQ address of the wallet
        (a send and a receipt, not change) and another wallet's payment to one."""
        n0, n1 = self.nodes
        print('seed-only restore: receipts at restored PQ addresses are classified, listed and counted as on the original')
        n0.walletpassphrase(PASSPHRASE, 3600)
        p_own = n0.getnewaddress('', 'pqslh')
        # spends a coin of the FN-DSA address (z_sendmany from it: the stock sends select ECC coins only, audit M-1)
        tx_own = wait_and_assert_operationid_status(n0, z_sendmany_opid(n0, self.addrs['fn'], [(p_own, Decimal('0.5'))]))
        p_in = n0.getnewaddress('', 'pq')
        tx_in = n1.sendtoaddress(p_in, Decimal('0.25'))
        self.mine(1)
        addrs = {self.addrs['fn'], self.addrs['slh'], p_own, p_in}
        before = self.classification(addrs, {tx_own, tx_in})
        assert (tx_own, 'receive', Decimal('0.5'), p_own) in before[2], before
        assert (tx_in, 'receive', Decimal('0.25'), p_in) in before[2], before
        export = n0.z_exportwallet('bytypeseed2')
        # review m7: a restored wallet made without the filing (-regtestskippqfiling: as wallets before beta2) has its
        # paid PQ keys out of the address book; its next load files them (FilePaidPQKeys)
        self.restart0(['%s=%s' % (SEED_RESTORE_OPTION, export), '-regtestskippqfiling'], wallet='restored2.dat')
        for a in (p_own, p_in):
            assert 'account' not in self.nodes[0].validateaddress(a), a
        self.restart0(wallet='restored2.dat')
        for a in (p_own, p_in):
            assert_equal(self.nodes[0].validateaddress(a)['account'], '')
        assert_equal(self.classification(addrs, {tx_own, tx_in}), before)
        self.restart0()

    def yed_holder_keys(self):
        """YED holder keys (beta2): a fresh Falcon holder key is filed when drawn and marked "yed_holder" in
        listreceivedbyaddress and validateaddress (derived from the Yellowback index), a plain PQ address is not;
        the token dust counts in getwalletinfo (balance_pq), not in the by-depth calls; a seed-only restore marks
        the restored holder key the same way, classifies the mint's token output as the same receipt and locks its
        token."""
        print('YED holder keys: filed, marked yed_holder, token dust in balance_pq only; the same after a seed restore')
        self.nodes[0].walletpassphrase(PASSPHRASE, 3600)                  # set_create funds from node 0
        setid = activate_yed_late(self, [1], ((0, 1),))
        n0 = self.nodes[0]
        n0.walletpassphrase(PASSPHRASE, 3600)
        self.nodes[1].sendtoaddress(n0.getnewaddress(), 20)              # the collateral (about 6 YEC at $50)
        self.mine(1)
        mint, op, key = mint_to_fresh_holder(self.nodes, 0, 1)
        plain = self.addrs['fn']
        va = n0.validateaddress(key)
        assert_equal((va['ismine'], va['pqscheme'], va.get('yed_holder')), (True, FN, True))
        assert 'yed_holder' not in n0.validateaddress(plain)
        rcv = {r['address']: r for r in n0.listreceivedbyaddress(0, True)}
        assert_equal((rcv[key]['pqscheme'], rcv[key].get('yed_holder')), (FN, True))
        assert 'yed_holder' not in rcv[plain]
        # filed when drawn: the mint's token output is a receipt on the minting wallet, not change
        assert [t for t in n0.listtransactions('*', 10000) if t['txid'] == mint and t['category'] == 'receive'
                and t['address'] == key], 'the holder key is not filed'
        assert_equal((self.zbal(key, 1), self.zbal(key, 0)), (0, 0))   # locked: not in the by-depth calls
        self.view(locked_in={FN: Decimal('0.0001')})                       # but in getwalletinfo (balance_pq)
        addrs = {plain, key}
        before = self.classification(addrs, {mint})
        assert [r for r in before[2] if r[1] == 'receive' and r[3] == key], before
        export = n0.z_exportwallet('bytypeseed3')
        self.restart0(['%s=%s' % (SEED_RESTORE_OPTION, export)], wallet='restored3.dat')
        n0 = self.nodes[0]
        assert_equal(self.classification(addrs, {mint}), before)
        assert_equal(n0.validateaddress(key).get('yed_holder'), True)
        assert_equal(n0.yed_getbalance()['confirmedCents'], 10000)
        assert {'txid': op[0], 'vout': op[1]} in n0.listlockunspent()
        self.restart0()
        self.owner_key_payment(setid)

    def owner_key_payment(self, setid):
        """Review m8 / audit L-i: a TX_PQPKH payment to a vault owner key of this wallet (its hash is public in the vault
        script) does not file the owner key in the address book, at receipt or at the next load; the payment still
        counts in getwalletinfo (balance_pq), is listed by listreceivedbyaddress (under "") and is a receipt in
        listtransactions."""
        print('a payment to a vault owner key: counted and listed, the key stays out of the address book')
        n0, n1 = self.nodes
        n0.walletpassphrase(PASSPHRASE, 3600)
        o = n0.vault_getnewowner()
        n0.vault_lock({'tag': 'TEST', 'setid': setid, 'delay': 10, 'ownerheight': n0.getblockcount() + 500,
                       'amount': 1, 'owner': o['owner']})
        self.mine(1)
        plain = n0.yed_validateaddress(o['address'])['transparentAddress']
        before = D(n0.getwalletinfo()['balance_pq'])
        txid = n1.sendtoaddress(plain, Decimal('0.5'))
        self.mine(1)
        for restart in (False, True):
            if restart:
                self.restart0()
                n0 = self.nodes[0]
            va = n0.validateaddress(plain)
            assert va['ismine'] and 'account' not in va, va
            assert_equal(D(n0.getwalletinfo()['balance_pq']), before + Decimal('0.5'))
            assert_equal([D(r['amount']) for r in n0.listreceivedbyaddress(0, True) if r['address'] == plain], [Decimal('0.5')])
            assert [t for t in n0.listtransactions('*', 10000) if t['txid'] == txid and t['category'] == 'receive'
                    and t['address'] == plain], 'the payment to the owner key is not listed as a receipt'


if __name__ == '__main__':
    WalletBalanceByTypeTest().main()
