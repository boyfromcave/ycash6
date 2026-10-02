#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The mining-pool wallet options with Yellowback on (doc/yellowback-release.md, "Mining pools").

Upstream Ycash shipped its pool features as a separate "witness rework" build
(_MINING_POOLS_ycashd_wr_*). ycashd 6.20.0 carries them as runtime options of the one binary,
default off: -deletetx (purge fully-spent, deeply-confirmed wallet transactions), -bdbcache and
-consolidation (sweep many small Sapling notes of an address into one). A pool running the
release binary turns them on, so the user wallet (node 0) here runs the whole script with all
of them, at intervals short enough to fire many times:

  - Sapling consolidation, built at height = 45 (mod 100) and committed at 49, while the same
    ys1... address funds Yellowback mints:
      round 1: a mint between the build and the commit (the batch may hold notes the mint then
               spends; the commit must fail cleanly, never poison the wallet);
      round 2: a mint while the committed consolidation transaction sits in the mempool (the
               mint must not pick a note that transaction already spends);
  - -deletetx purges wallet transactions underneath open positions: YED balances, coins,
    positions and confirmed history (all read from the Yellowback index, not wallet.dat) are
    unchanged by the purge and by a restart, and both positions still redeem afterwards.

Known and accepted: -deletetxconflict (on under -deletetx) also purges the user's own *expired*
transactions, so yed_listtransactions / yed_gettxinfo stop reporting an expired Yellowback
transaction as "expired" once it is purged (it left no index trace to begin with). Not exercised
here; documented in doc/yellowback-release.md.

Nodes: 0 user (with the pool options), 1 stock, 2-4 pools, 5 observer.
"""

import os
import re
import time
from decimal import Decimal

from test_framework.util import assert_equal, assert_greater_than, wait_and_assert_operationid_status
from test_framework.yellowback_util import (
    POOLS,
    REF_LAG,
    USER,
    YellowbackTestFramework,
)
from test_framework.yellowback_attest import ArmedModeMixin

WR_ARGS = ['-deletetx=1', '-deletetxinterval=10', '-keeptxfornblocks=5', '-keeptxnum=0',
           '-bdbcache=8', '-consolidation=1', '-debug=deletetx', '-debug=zrpcunsafe']
DUST_NOTES = 12
DUST = Decimal('0.5')


class YellowbackWrFlagsTest(ArmedModeMixin, YellowbackTestFramework):

    def node_args(self, i, extra=None):
        if i == USER:
            extra = WR_ARGS + list(extra or [])
        return super().node_args(i, extra)

    # --- helpers -------------------------------------------------------------

    def requote(self):
        """Pools drop a stored quote after -yellowbackquotemaxage (1800 s of wall clock), and this
        script runs long enough to pass it; re-quote before every mining segment."""
        for i in POOLS:
            self.quote(i, 50)

    def mine_to(self, height):
        self.requote()
        tip = self.nodes[USER].getblockcount()
        assert height >= tip, (height, tip)
        if height > tip:
            self.mine_round_robin(POOLS, height - tip)
        self.sync_all()
        assert_equal(self.nodes[USER].getblockcount(), height)

    def next_height(self, residue, min_height):
        h = max(min_height, self.nodes[USER].getblockcount() + 1)
        while h % 100 != residue:
            h += 1
        return h

    def wait_async_idle(self, node, timeout=180):
        """Every queued async operation (the consolidation build is one) has finished."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            ids = node.z_listoperationids()
            busy = [s for s in node.z_getoperationstatus(ids) if s['status'] in ('queued', 'executing')] if ids else []
            if not busy:
                return
            time.sleep(0.5)
        raise AssertionError('async operations still running: %r' % busy)

    def purged(self, i):
        """Wallet transactions -deletetx has removed on node i, from its own accounting
        ("Deleted spent wtx" / "Deleted expired/conflicted wtx", one line each, -debug=deletetx)."""
        log = os.path.join(self.options.tmpdir, 'node%d' % i, 'regtest', 'debug.log')
        with open(log, encoding='utf8', errors='replace') as f:
            return len(re.findall(r'Deleted (?:spent|expired/conflicted) wtx ', f.read()))

    def notes(self, node, addr):
        return node.z_listunspent(0, 9999999, False, [addr])

    def add_dust(self, user, ys):
        """DUST_NOTES separate notes of DUST into ys (one z_sendmany per note: a recipient may
        appear only once per call), mined into one block."""
        self.requote()
        tas = [user.getnewaddress() for _ in range(DUST_NOTES)]
        user.sendmany('', {t: DUST + Decimal('0.01') for t in tas})
        self.sync_all()
        self.mine(POOLS[0])
        ops = [user.z_sendmany(t, [{'address': ys, 'amount': DUST}], 1, None) for t in tas]
        for opid in ops:
            wait_and_assert_operationid_status(user, opid)
        self.sync_all()
        self.mine(POOLS[1])

    def yed_view(self, node):
        """What a purge must not change: balances, coins, positions, confirmed history."""
        bal = node.yed_getbalance()
        return {
            'balance': (bal['confirmedCents'], bal['unconfirmedCents']),
            'coins': sorted((c['txid'], c['vout'], c['cents']) for c in node.yed_listunspent()),
            'positions': sorted((p['txid'], p['status']) for p in node.yed_listpositions()),
            'history': sorted((r['txid'], r['type'], r['verdict']) for r in node.yed_listtransactions(1000) if not r['expired']),
        }

    def consolidation_txs(self, node):
        """Mempool transactions of node that spend >= 2 Sapling notes and pay exactly one real
        output back (the consolidation shape; the builder pads to two outputs)."""
        out = []
        for txid in node.getrawmempool():
            raw = node.getrawtransaction(txid, 1)
            if raw['vin'] == [] and raw['vout'] == [] and len(raw['vShieldedSpend']) >= 2:
                out.append(txid)
        return out

    # --- the script ------------------------------------------------------------

    def run_test(self):
        nodes = self.nodes
        user = nodes[USER]
        peak_txcount = 0

        print('activate at $50 with the pool options on node 0: %s' % ' '.join(WR_ARGS))
        self.activate(POOLS, quote_usd=50)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        self.arm()

        print('fund one ys1... address: one 25 YEC note and %d dust notes of %s' % (DUST_NOTES, DUST))
        ys = user.z_getnewaddress('sapling')
        tbig = user.getnewaddress()
        user.sendtoaddress(tbig, Decimal('25.001'))
        self.sync_all()
        self.mine(POOLS[0])
        opid = user.z_sendmany(tbig, [{'address': ys, 'amount': Decimal('25')}], 1, None)
        wait_and_assert_operationid_status(user, opid)
        self.add_dust(user, ys)
        notes0 = len(self.notes(user, ys))
        assert_equal(notes0, DUST_NOTES + 1)
        peak_txcount = max(peak_txcount, user.getwalletinfo()['txcount'])

        # Round 1: build at 45 (notes need depth >= 11 then), mint, commit at 49.
        h45 = self.next_height(45, user.getblockcount() + 12)
        print('round 1: consolidation built at %d, a mint from ys before its commit at %d' % (h45, h45 + 4))
        self.mine_to(h45)
        self.wait_async_idle(user)
        mint1 = self.mint(user, 10000, 48, ys)                     # carrier mined at h45 + 1
        assert_equal(mint1['fundedFrom'], 'sapling')
        self.mine(POOLS[2])                                        # main transaction at h45 + 2
        assert_equal(nodes[2].yed_gettxinfo(mint1['txid'])['verdict'], 'ok')
        self.mine_to(h45 + 4)                                      # the commit: may conflict with the mint, must not break anything
        self.mine_to(h45 + 6)
        assert_equal(user.yed_getvault(mint1['txid'])['status'], 'ACTIVE')
        assert_equal(user.yed_getbalance()['confirmedCents'], 10000)
        assert_equal(self.consolidation_txs(user), [])       # nothing left dangling in the mempool
        peak_txcount = max(peak_txcount, user.getwalletinfo()['txcount'])

        # Round 2: fresh dust, then a mint while the committed consolidation is in the mempool.
        self.add_dust(user, ys)
        h45 = self.next_height(45, user.getblockcount() + 12)
        print('round 2: consolidation committed at %d, a mint from ys with it in the mempool' % (h45 + 4))
        before = len(self.notes(user, ys))
        assert_greater_than(before, DUST_NOTES)
        self.mine_to(h45)
        self.wait_async_idle(user)
        self.mine_to(h45 + 4)
        cons = self.consolidation_txs(user)
        assert_equal(len(cons), 1)                                 # the commit happened (one address, one transaction)
        spent_by_cons = len(user.getrawtransaction(cons[0], 1)['vShieldedSpend'])
        # The batch takes a random 10..44 notes, so it may hold every note of ys (the 25 YEC one
        # too). Then the wallet has nothing confirmed and unspent there until it confirms, and the
        # mint must be refused cleanly (insufficient-yec), never build on a note already spent in
        # the mempool; it goes through one block later.
        try:
            mint2 = self.mint(user, 10000, 48, ys)                 # the carrier block also mines the consolidation
            print('  mint went through beside the pending consolidation')
        except Exception as e:
            assert 'insufficient-yec' in str(e), str(e)
            assert_equal(spent_by_cons, before)                    # refused only because every note is in the batch
            print('  consolidation holds all %d notes: mint refused (insufficient-yec), retried after it confirms' % before)
            self.mine(POOLS[0])
            mint2 = self.mint(user, 10000, 48, ys)
        assert_equal(mint2['fundedFrom'], 'sapling')
        self.mine(POOLS[2])
        assert_equal(nodes[2].yed_gettxinfo(mint2['txid'])['verdict'], 'ok')
        assert_greater_than(user.gettransaction(cons[0])['confirmations'], 0)   # confirmed alongside the mint's carrier
        assert_equal(user.yed_getvault(mint2['txid'])['status'], 'ACTIVE')
        assert_equal(user.yed_getbalance()['confirmedCents'], 20000)
        after = len(self.notes(user, ys))
        assert after < before, (before, after, spent_by_cons)      # consolidation really collapsed notes
        peak_txcount = max(peak_txcount, user.getwalletinfo()['txcount'])

        print('-deletetx purges under open positions: the Yellowback view is unchanged')
        view = self.yed_view(user)
        self.requote()
        self.mine_round_robin(POOLS, 25)                           # two purge rounds past keeptxfornblocks
        self.sync_all()
        txcount = user.getwalletinfo()['txcount']
        deleted = self.purged(USER)
        print('  -deletetx removed %d wallet transactions so far (wallet holds %d, peak seen %d)' % (deleted, txcount, peak_txcount))
        assert_greater_than(deleted, 0)                            # the purge really removed transactions
        assert_equal(self.yed_view(user), view)
        self.restart(USER)
        self.sync_all()
        user = self.nodes[USER]
        assert_equal(self.yed_view(user), view)
        assert user.getwalletinfo()['txcount'] <= txcount          # the tombstones keep purged transactions out after restart

        print('both positions still redeem after the purge')
        self.requote()
        lock = max(mint1['lockHeight'], mint2['lockHeight'])
        if lock > user.getblockcount():
            self.mine_round_robin(POOLS, lock - user.getblockcount())
        self.sync_all()
        for m in (mint1, mint2):
            red = user.yed_redeem(m['txid'], ys)
            self.sync_all()
            self.mine(POOLS[1])
            assert_equal(nodes[2].yed_gettxinfo(red['txid'])['verdict'], 'ok')
            assert_equal(user.yed_getvault(m['txid'])['status'], 'CLOSED')
        assert_equal(user.yed_getbalance()['confirmedCents'], 0)
        assert_equal(nodes[2].yed_getstats()['supplyCents'], 0)
        self.model_check(nodes[2])
        self.checkpoint('wr flags')


if __name__ == '__main__':
    YellowbackWrFlagsTest().main()
