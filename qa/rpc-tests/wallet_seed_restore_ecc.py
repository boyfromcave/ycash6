#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""Seed-only restore (-mnemonicfile) recovers every ECC (P2PKH) coin of the wallet's own seed (beta2 P0, 6.x only).

The original wallet (node 0, -keypool=100 as the default) uses more than the keypool on both legacy transparent HD
chains, and a wallet restored from its recovery phrase alone must show the same coins and balances:

- 120 getnewaddress keys, each paid in order (more than 100 external keys);
- out of chain order: of two later keys the 151st (index i+150) is paid in an earlier block than the 61st (i+60),
  so the restore holds i+150 only after the payment to i+60 moved its window (the rescan's re-pass);
- a gap of 100 unused addresses then one paid (found), and last a gap of 101 then one paid: the documented miss,
  found after getnewaddress is run past the gap and a restart with -rescan;
- 130 coinbase outputs to 130 keypool (internal) keys, beyond the keypool, matured;
- after the last block that moves the lookahead in the restore's first pass (review H-1): of three later keys
  c150 is paid first, then c60, then c150's coin is swept to another wallet with no change, then one transaction
  pays d60 and d150, keys the restore holds only once the re-pass has found c150: the re-pass must read the whole
  range (the sweep and the payment lie past the last height at which the first pass grew the lookahead);
- one transaction pays [e150, e60] in that output order (review M-3): e150 is held only once e60 is marked, so
  the outputs are read again within the transaction; and a transaction found for its Sapling note also pays f150,
  held only once a later payment to f60 is found: the re-pass marks keys on transactions the wallet already has.
  After the restore getnewaddress hands out no address any wallet transaction pays;
- the chain ends with blocks that pay nothing to the wallet.

Then: restarts keep the restored state; the original and the restored wallet hand out the same next address; held
keys appear in no listing or dump before they are issued or paid; an encrypted, locked restored wallet misses a
payment to an address it has not issued, says so in getwalletinfo (lookahead_incomplete, persisted; never for a locked
wallet that holds its lookahead, review L-2) and in its log at walletpassphrase; unlocked it holds the lookahead
again, locked again it still recognises (and writes) a held key that is paid; a new wallet file restored from the
phrase, with getnewaddress past the gap and -rescan, finds every coin (this line has no rescanblockchain).

Run: ZCASHD=<ycashd> .venv/bin/python -u qa/rpc-tests/wallet_seed_restore_ecc.py --tmpdir=<dir> --portseed=<n>
"""

import os
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_start_raises_init_error,
    bitcoind_processes,
    wait_and_assert_operationid_status,
    connect_nodes_bi,
    start_node,
    start_nodes,
    stop_node,
    sync_blocks,
)

KEYPOOL = 100
IN_ORDER = 120
COINBASE = 130
PASSPHRASE = 'eccseed-pass'


def transparent_listed(node):
    """Every transparent address listaddresses names."""
    out = set()
    for entry in node.listaddresses():
        t = entry.get('transparent', {})
        out.update(t.get('addresses', []))
        out.update(t.get('changeAddresses', []))
    return out


class WalletSeedRestoreEccTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = False

    def node_args(self, i, wallet='eccseed.dat'):
        if i == 0:
            return ['-wallet=%s' % wallet, '-keypool=%d' % KEYPOOL,
                    '-exportdir=%s' % os.path.join(self.options.tmpdir, 'export0'),
                    '-experimentalfeatures', '-developerencryptwallet']
        return []

    def setup_network(self, split=False):
        os.makedirs(os.path.join(self.options.tmpdir, 'export0'), exist_ok=True)
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 extra_args=[self.node_args(i) for i in range(self.num_nodes)])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def restart0(self, wallet, extra=None):
        stop_node(self.nodes[0], 0)
        self.nodes[0] = start_node(0, self.options.tmpdir, self.node_args(0, wallet) + (extra or []))
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        return self.nodes[0]

    def pay(self, outputs):
        """node 1 pays {address: amount} in one transaction and mines it; returns the txid."""
        txid = self.nodes[1].sendmany('', outputs)
        self.sync_all()
        self.nodes[1].generate(1)
        self.sync_all()
        return txid

    def snapshot(self):
        n0 = self.nodes[0]
        utxos = sorted((u['txid'], u['vout'], u['address'], Decimal(u['amount'])) for u in n0.listunspent(0))
        t = n0.z_gettotalbalance(0)
        w = n0.getwalletinfo()
        return {'utxos': utxos, 'transparent': t['transparent'], 'total': t['total'],
                'balance': w['balance'], 'unconfirmed': w['unconfirmed_balance'], 'immature': w['immature_balance'],
                'txcount': w['txcount'], 'keypoolsize': w['keypoolsize'], 'getbalance': n0.getbalance(),
                'listtransactions': len(n0.listtransactions('*', 100000)),
                'lookahead_incomplete': w['lookahead_incomplete']}

    def sweep(self, address, dest):
        """node 0 spends the one coin of `address` whole to `dest` (another wallet): no change, no output of its own."""
        n0 = self.nodes[0]
        coins = [u for u in n0.listunspent(0) if u['address'] == address]
        assert_equal(len(coins), 1)
        raw = n0.createrawtransaction([{'txid': coins[0]['txid'], 'vout': coins[0]['vout']}],
                                      {dest: Decimal(coins[0]['amount']) - Decimal('0.00001')})
        txid = n0.sendrawtransaction(n0.signrawtransaction(raw)['hex'])
        self.sync_all()
        self.nodes[1].generate(1)
        self.sync_all()
        return txid

    def paid_addresses(self):
        """Every transparent address an output of a node 0 wallet transaction pays."""
        n0 = self.nodes[0]
        out = set()
        for txid in {t['txid'] for t in n0.listtransactions('*', 100000)}:
            for o in n0.decoderawtransaction(n0.gettransaction(txid)['hex'])['vout']:
                out.update(o['scriptPubKey'].get('addresses', []))
        return out

    def pay_ordered(self, outputs):
        """node 1 pays [(address, amount), ...] in one transaction, the outputs in that order; mines it."""
        n1 = self.nodes[1]
        raw = n1.createrawtransaction([], {a: v for a, v in outputs})
        funded = n1.fundrawtransaction(raw)['hex']
        order = [o['scriptPubKey'].get('addresses', [None])[0] for o in n1.decoderawtransaction(funded)['vout']]
        assert_equal([a for a in order if a in dict(outputs)], [a for a, _ in outputs])
        txid = n1.sendrawtransaction(n1.signrawtransaction(funded)['hex'])
        self.sync_all()
        n1.generate(1)
        self.sync_all()
        return txid

    def debug_log(self):
        with open(os.path.join(self.options.tmpdir, 'node0', 'regtest', 'debug.log'), encoding='utf-8') as f:
            return f.read()

    def run_test(self):
        n0, n1 = self.nodes

        print('the original wallet: %d external keys paid in order' % IN_ORDER)
        in_order = [n0.getnewaddress() for _ in range(IN_ORDER)]
        self.pay({a: Decimal('0.1') for a in in_order})

        print('out of chain order: key i+150 paid in an earlier block than key i+60')
        later = [n0.getnewaddress() for _ in range(151)]
        k60, k150 = later[60], later[150]
        self.pay({k150: Decimal('0.2')})
        self.pay({k60: Decimal('0.3')})

        print('a restart of the original wallet in the middle (held keys are not in its file)')
        n0 = self.restart0('eccseed.dat')

        print('a gap of %d unused addresses, then one paid' % KEYPOOL)
        gap_ok = [n0.getnewaddress() for _ in range(KEYPOOL + 1)]
        self.pay({gap_ok[-1]: Decimal('0.4')})

        print('%d coinbase outputs to as many keypool keys (beyond the keypool)' % COINBASE)
        for _ in range(COINBASE):
            n0.generate(1)                      # generate keeps one keypool key per call
        self.sync_all()

        print('H-1: a coin found only by the re-pass is spent, and keys it brings in are paid, after the last growth')
        c = [n0.getnewaddress() for _ in range(151)]
        c60, c150 = c[60], c[150]
        self.pay({c150: Decimal('0.2')})
        self.pay({c60: Decimal('0.3')})
        sweep_txid = self.sweep(c150, n1.getnewaddress())
        d = [n0.getnewaddress() for _ in range(151)]
        d_txid = self.pay_ordered([(d[60], Decimal('0.35')), (d[150], Decimal('0.25'))])

        print('M-3: one transaction pays [e150, e60]; a transaction with a Sapling note pays f150, f60 is paid later')
        e = [n0.getnewaddress() for _ in range(151)]
        e_txid = self.pay_ordered([(e[150], Decimal('0.15')), (e[60], Decimal('0.16'))])
        zaddr = n0.z_getnewaddress('sapling')        # the first Sapling address: -mnemonicfile restores it
        f = [n0.getnewaddress() for _ in range(151)]
        t1 = n1.getnewaddress()
        n1.sendtoaddress(t1, 2)
        self.sync_all()
        n1.generate(1)
        self.sync_all()
        op = n1.z_sendmany(t1, [{'address': zaddr, 'amount': Decimal('0.4')}, {'address': f[150], 'amount': Decimal('0.17')}],
                           1, None, 'AllowFullyTransparent')
        s_txid = wait_and_assert_operationid_status(n1, op)
        self.sync_all()
        n1.generate(1)
        self.sync_all()
        self.pay({f[60]: Decimal('0.18')})

        print('last, a gap of %d unused addresses, then one paid (the documented miss)' % (KEYPOOL + 1))
        gap_miss = [n0.getnewaddress() for _ in range(KEYPOOL + 2)]
        miss_txid = self.pay({gap_miss[-1]: Decimal('0.5')})
        n1.generate(101)
        self.sync_all()
        before = self.snapshot()
        assert len(before['utxos']) >= IN_ORDER + 10 + COINBASE, len(before['utxos'])
        assert c150 not in {u[2] for u in before['utxos']}
        coinbase_keys = {u[2] for u in before['utxos']} - set(in_order) - {k60, k150, gap_ok[-1], gap_miss[-1], c60, d[60], d[150], e[60], e[150], f[60], f[150]}
        assert len(coinbase_keys) >= COINBASE, len(coinbase_keys)
        export = n0.z_exportwallet('eccseedexport')

        print('a new wallet from the recovery phrase')
        n0 = self.restart0('eccrestored.dat', ['-mnemonicfile=%s' % export])
        after = self.snapshot()
        print('  restored %d of %d unspent outputs' % (len(after['utxos']), len(before['utxos'])))
        missing = sorted(set(before['utxos']) - set(after['utxos']))
        extra = sorted(set(after['utxos']) - set(before['utxos']))
        assert_equal(extra, [])
        # exactly the payment after the gap of 101 is missed; everything else, incl. k150 (re-pass) and the gap of 100
        assert_equal([(m[0], m[2], m[3]) for m in missing], [(miss_txid, gap_miss[-1], Decimal('0.5'))])
        restored = {u[2] for u in after['utxos']}
        assert k150 in restored and k60 in restored and gap_ok[-1] in restored
        # H-1: the swept coin is spent (not listed), the coins of d60 and d150 are found
        assert c150 not in restored and c60 in restored and d[60] in restored and d[150] in restored
        assert_equal(n0.gettransaction(sweep_txid)['txid'], sweep_txid)
        assert_equal(n0.gettransaction(d_txid)['txid'], d_txid)
        # M-3: both outputs of [e150, e60], and f150 of the transaction found for its Sapling note
        assert e[150] in restored and e[60] in restored and f[150] in restored and f[60] in restored
        assert_equal(Decimal(after['total']) - Decimal(after['transparent']), Decimal('0.4'))
        # every other figure matches the original but for the one missed payment (0.5)
        assert_equal(Decimal(after['transparent']), Decimal(before['transparent']) - Decimal('0.5'))
        assert_equal(after['getbalance'], before['getbalance'] - Decimal('0.5'))
        assert_equal(after['txcount'], before['txcount'] - 1)
        assert_equal(after['listtransactions'], before['listtransactions'] - 1)
        assert all(a in restored for a in in_order)
        log = self.debug_log()
        assert 'the key lookahead moved during the scan; re-checking heights' in log

        print('held keys appear in no listing and no dump before they are issued or paid')
        held = gap_miss[50]          # inside the restored wallet's window, never paid, not issued by it
        assert_equal(n0.validateaddress(held)['ismine'], True)
        assert held not in transparent_listed(n0)
        assert held not in n0.getaddressesbyaccount('')
        assert held not in open(n0.z_exportwallet('eccheld'), encoding='utf-8').read()
        # a paid, re-found receiving address is listed, as in the original
        assert in_order[0] in transparent_listed(n0)
        assert in_order[0] in n0.getaddressesbyaccount('')

        print('the documented recovery: getnewaddress past the gap, then a restart with -rescan')
        paid = self.paid_addresses()
        assert e[150] in paid and f[150] in paid
        issued = [n0.getnewaddress() for _ in range(len(gap_miss))]
        assert_equal(sorted(set(issued) & paid), [])   # M-3: no address a wallet transaction pays is handed out
        assert_equal(issued, gap_miss)          # the same addresses, in the same order, as the original issued
        n0 = self.restart0('eccrestored.dat', ['-rescan'])
        assert_equal(self.snapshot(), before)

        print('a restart keeps the restored state; both wallets hand out the same next address')
        n0 = self.restart0('eccrestored.dat')
        assert_equal(self.snapshot(), before)
        next_restored = n0.getnewaddress()
        n0 = self.restart0('eccseed.dat')
        next_original = n0.getnewaddress()
        assert_equal(next_restored, next_original)
        target, target2, target3 = [n0.getnewaddress() for _ in range(3)]   # issued by the original only

        print('an encrypted restored wallet: locked, it misses a payment to an address it has not issued')
        n0 = self.restart0('eccrestored.dat')
        n0.encryptwallet(PASSPHRASE)
        bitcoind_processes[0].wait()
        self.nodes[0] = start_node(0, self.options.tmpdir, self.node_args(0, 'eccrestored.dat'))
        n0 = self.nodes[0]
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        assert_equal(n0.getwalletinfo()['unlocked_until'], 0)
        assert_equal(self.snapshot()['utxos'], before['utxos'])
        assert_equal(n0.getwalletinfo()['lookahead_incomplete'], False)
        print('  review L-2: unlocked once, then locked, it holds its lookahead: blocks it sees flag nothing')
        n0.walletpassphrase(PASSPHRASE, 600)
        n0.walletlock()
        self.pay({n1.getnewaddress(): Decimal('0.1')})
        assert_equal(n0.getwalletinfo()['lookahead_incomplete'], False)
        print('  started locked (no lookahead), it flags the blocks with an output it cannot check (its startup rescan too)')
        n0 = self.restart0('eccrestored.dat')
        target_txid = self.pay({target: Decimal('0.6')})
        assert target not in {u['address'] for u in n0.listunspent(0)}
        assert_equal(n0.getwalletinfo()['lookahead_incomplete'], True)
        print('  unlocked: the log says how to find it, and the lookahead is held again (a later payment is found)')
        logpos = len(self.debug_log())
        n0.walletpassphrase(PASSPHRASE, 600)
        assert 'it holds them now' in self.debug_log()[logpos:]
        assert_equal(n0.getwalletinfo()['lookahead_incomplete'], True)   # unlocking holds the keys, finds nothing earlier
        target2_txid = self.pay({target2: Decimal('0.7')})
        assert_equal([(u['txid'], Decimal(u['amount'])) for u in n0.listunspent(0) if u['address'] in (target, target2)],
                     [(target2_txid, Decimal('0.7'))])
        print('  locked again: a payment to a key it holds is found, its key written encrypted; a locked -rescan keeps it')
        n0.walletlock()
        target3_txid = self.pay({target3: Decimal('0.8')})
        assert_equal([u['txid'] for u in n0.listunspent(0) if u['address'] == target3], [target3_txid])
        assert 'MarkLegacyTKeyUsed: the wallet is locked' in self.debug_log()[logpos:]
        # the payment to target2 (unlocked) made every held key below it an issued key, target's among them, so
        # even a locked -rescan now finds target's earlier coin
        n0 = self.restart0('eccrestored.dat', ['-rescan'])
        assert_equal(n0.getwalletinfo()['unlocked_until'], 0)
        assert_equal(n0.getwalletinfo()['lookahead_incomplete'], True)   # persisted; a locked rescan does not clear it
        assert_equal(sorted(u['txid'] for u in n0.listunspent(0) if u['address'] in (target, target2, target3)),
                     sorted([target_txid, target2_txid, target3_txid]))

        print('the remedy: a new wallet file from the recovery phrase, getnewaddress past the gap, -rescan')
        n0 = self.restart0('eccrestored2.dat', ['-mnemonicfile=%s' % export])
        drawn = []
        while target not in drawn and len(drawn) < 400:
            drawn.append(n0.getnewaddress())
        assert target in drawn
        n0 = self.restart0('eccrestored2.dat', ['-rescan'])
        final = self.snapshot()
        assert_equal(final['lookahead_incomplete'], False)
        assert_equal(sorted(set(before['utxos']) - set(final['utxos'])), [])
        new = sorted(set(final['utxos']) - set(before['utxos']))
        assert_equal([(u[0], u[2], u[3]) for u in new],
                     sorted([(target_txid, target, Decimal('0.6')), (target2_txid, target2, Decimal('0.7')),
                             (target3_txid, target3, Decimal('0.8'))]))
        assert_equal(Decimal(final['transparent']), Decimal(before['transparent']) + Decimal('2.1'))

        print('review M-a: a shutdown requested in the middle of a re-pass stops the scan at that block')
        stop_height = n1.getblockcount() - 40
        stop_node(self.nodes[0], 0)
        logpos = len(self.debug_log())
        assert_start_raises_init_error(
            0, self.options.tmpdir,
            self.node_args(0, 'eccinterrupted.dat') + ['-mnemonicfile=%s' % export, '-stoprescanat=2:%d' % stop_height],
            'rescan interrupted due to shutdown request')
        log = self.debug_log()[logpos:]
        hook = log.index('-stoprescanat: shutdown requested at height %d (pass 2)' % stop_height)
        assert 'interrupted by a shutdown request at height %d (pass 2)' % stop_height in log[hook:]
        assert 're-check found' not in log[hook:]       # the pass did not read on to its end
        self.nodes[0] = start_node(0, self.options.tmpdir, self.node_args(0, 'eccrestored2.dat'))


if __name__ == '__main__':
    WalletSeedRestoreEccTest().main()
