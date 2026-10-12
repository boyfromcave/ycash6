#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
D-Q-30 (owner, revised) on regtest: the module's attestor bond floor follows the YEC locked in YED vaults, never a
price: bondMinZat = clamp(ceil(collateralZat x bondShareBps / (10^4 x N_SLOTS)), bondMinFloorZat, bondMinCapZat) over
the snapshot before the join's block. Regtest carries it at 1/2,000 of mainnet (2.5 YEC floor, 10 YEC cap, 500 bps,
N_SLOTS 5; mainnet 5,000 / 20,000 YEC, N_SLOTS 9).

1. Empty vaults: bondMinZat is the 2.5-YEC floor; yed_registerattestor refuses 2.49999999 (bond-below-min) and warns
   bond-near-min at 2.5; a raw SET_JOIN at 2.5 YEC - 1 zat is refused by every Yellowback mempool
   (attestor-bond-below-min, seats re-review: no never-eligible member); the 2.5-YEC join matures.
2. The minimum rises with collateral: after a $500 mint at $5 (~300 YEC locked) it is ceil(collateral / 200); a join
   1 zat below it is refused, one at it matures.
3. The cap: past 1,000 YEC locked the minimum stops at 10 YEC; 10 YEC (no warning) always qualifies.
4. Checked once at registration: the 2.5-YEC and mid-range records stay ELIGIBLE and seated under the 10-YEC minimum,
   and a price move (which the rule never reads) changes nothing.
5. The bump: seats are N_SLOTS (5) by SeatRank (owner 2026-10-11: bondZat x the log tenure factor, 1.0 to 1.9
   over a year, a seated record x1.05). Two 10-YEC joins fill the seats; a third takes the seat of the 2.5-YEC floor
   bond at its maturity (10 x f(8) > 2.5 x f(age) x 1.05); the bumped record stays an ELIGIBLE member.
The Python model replays the chain (the rule is mirrored in yellowback_model.py).

Nodes: 0 user, 1 stock, 2-4 pools, 5 observer.
"""

import os
from decimal import Decimal

from test_framework.util import assert_equal
from test_framework.yellowback_model import seat_weight
from test_framework.yellowback_util import (
    BOND_MATURITY,
    BOND_MIN_LOCK,
    COIN,
    POOLS,
    P_SLOW_WINDOW,
    REF_LAG,
    YellowbackTestFramework,
    assert_same_statehash,
    secret_to_pubkey,
    wait_yed_healthy,
)
from test_framework.yellowback_attest import build_register_tx, model_check, send_and_lock, wallet_mint

USER = 0
FLOOR, CAP, SHARE_BPS, N_SLOTS = COIN * 5 // 2, 10 * COIN, 500, 5


def assert_rpc_error(substr, fn, *args):
    try:
        fn(*args)
    except Exception as e:
        assert substr in str(e), 'expected %r in %r' % (substr, str(e))
        return str(e)
    raise AssertionError('expected an error containing %r' % substr)


def expected_min(collateral_zat):
    z = -(-collateral_zat * SHARE_BPS // (10_000 * N_SLOTS))
    return min(CAP, max(FLOOR, z))


# Rule: D-Q-30
class YellowbackAttestBondTest(YellowbackTestFramework):

    initial_blocks = 101

    def bond_min(self):
        mins = set(n.yed_getinfo()['params']['attest']['bondMinZat'] for n in self.enforcing_nodes())
        assert_equal(len(mins), 1)
        return mins.pop()

    def tip_collateral(self):
        return int(self.nodes[USER].yed_getstats()['collateralZat'])   # Totals at the tip = Snapshots[tip].collateralZat

    def records(self):
        return dict((int(r['seq']), r) for r in self.nodes[POOLS[0]].yed_listattestors())

    def seq_of(self, pubkey):
        pub = pubkey if isinstance(pubkey, str) else pubkey.hex()
        found = [s for s, r in self.records().items() if r['attestorPubKey'] == pub]
        assert_equal(len(found), 1)
        return found[0]

    def raw_join(self, bond_zat):
        """A SET_JOIN under a fresh key with bond_zat, mined in its own block; returns its seq."""
        user = self.nodes[USER]
        secret = os.urandom(32)
        pub = secret_to_pubkey(secret)
        hex_, _lt = build_register_tx(user, pub, None, bond_zat, BOND_MIN_LOCK, secret=secret)
        send_and_lock(user, hex_)
        self.sync_all()
        self.mine(POOLS[0])
        return self.seq_of(pub)

    def refused_join(self, bond_zat):
        """A SET_JOIN under a fresh key with bond_zat that the mempool refuses (attestor-bond-below-min)."""
        user = self.nodes[USER]
        secret = os.urandom(32)
        hex_, _lt = build_register_tx(user, secret_to_pubkey(secret), None, bond_zat, BOND_MIN_LOCK, secret=secret)
        assert_rpc_error('attestor-bond-below-min', user.sendrawtransaction, hex_)

    def wallet_join(self, bond_zat):
        res = self.last_reg = self.nodes[USER].yed_registerattestor(Decimal(bond_zat) / COIN, BOND_MIN_LOCK)
        self.sync_all()
        self.mine(POOLS[0])
        return self.seq_of(res['attestorPubKey'])

    def status(self, seq):
        return self.records()[seq]['status']

    def mature(self):
        self.mine_round_robin(POOLS, BOND_MATURITY)

    def fund_user(self, yec):
        user = self.nodes[USER]
        while sum(self.nodes[i].getbalance() for i in POOLS) + user.getbalance() < yec + 10:
            self.mine_round_robin(POOLS, 30)             # the pools' matured coinbase funds the user's mints
        for i in POOLS:
            if user.getbalance() >= yec:
                break
            pool = self.nodes[i]
            amount = min(Decimal(yec) - user.getbalance(), pool.getbalance() - 1)
            if amount > 0:
                pool.sendtoaddress(user.getnewaddress(), amount)
                self.sync_all()
                self.mine(i)

    def mint(self, cents):
        wallet_mint(self, self.nodes[USER], cents, 48)
        self.mine_round_robin(POOLS, REF_LAG + 1)

    def seated(self):
        return sorted(s for s, r in self.records().items() if r['seated'])

    def run_test(self):
        user = self.nodes[USER]
        for node in self.enforcing_nodes():
            wait_yed_healthy(node)
            a = node.yed_getinfo()['params']['attest']
            assert_equal((a['bondMinFloorZat'], a['bondMinCapZat'], a['bondShareBps']), (FLOOR, CAP, SHARE_BPS))
            assert 'bondMinUsdCents' not in a and 'bondMinNoPriceZat' not in a

        print('1. empty vaults: the 2.5-YEC floor')
        self.activate(POOLS, quote_usd=5)
        self.fund_user(1_400)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        assert_equal(self.tip_collateral(), 0)
        assert_equal(self.bond_min(), FLOOR)
        assert_rpc_error('bond-below-min', user.yed_registerattestor, Decimal('2.49999999'), BOND_MIN_LOCK)
        self.refused_join(FLOOR - 1)
        at_floor = self.wallet_join(FLOOR)
        assert self.last_reg['warning'].startswith('bond-near-min'), self.last_reg['warning']   # B2: no headroom
        self.mature()
        assert_equal(self.status(at_floor), 'ELIGIBLE')

        print('2. the minimum rises with vault collateral')
        self.mint(50_000)                                # $500 at $5, 300 % class A: ~300 YEC locked
        coll = self.tip_collateral()
        assert coll >= 300 * COIN, coll
        mid = expected_min(coll)
        assert FLOOR < mid < CAP, mid
        assert_equal(self.bond_min(), mid)
        print('   %s YEC locked -> bondMinZat %s YEC' % (Decimal(coll) / COIN, Decimal(mid) / COIN))
        assert_rpc_error('bond-below-min', user.yed_registerattestor, Decimal(mid - 1) / COIN, BOND_MIN_LOCK)
        self.refused_join(mid - 1)
        at_mid = self.raw_join(mid)
        self.mature()
        assert_equal(self.status(at_mid), 'ELIGIBLE')

        print('3. the cap: past 1,000 YEC locked the minimum stops at 10 YEC')
        self.mint(150_000)                               # $1,500 more: ~900 YEC
        coll = self.tip_collateral()
        assert coll * SHARE_BPS // (10_000 * N_SLOTS) > CAP, coll
        assert_equal(self.bond_min(), CAP)
        assert_rpc_error('bond-below-min', user.yed_registerattestor, Decimal(CAP - 1) / COIN, BOND_MIN_LOCK)
        at_cap = self.wallet_join(CAP)
        assert_equal(self.last_reg['warning'], '')       # the cap always qualifies
        self.mature()
        assert_equal(self.status(at_cap), 'ELIGIBLE')

        print('4. checked once at registration; the price is never read')
        for i in POOLS:
            self.quote(i, '0.50')
        self.mine_round_robin(POOLS, P_SLOW_WINDOW + 6)
        assert_equal(self.bond_min(), expected_min(self.tip_collateral()))
        recs = self.records()
        for seq in (at_floor, at_mid, at_cap):
            assert_equal((recs[seq]['status'], recs[seq]['seated']), ('ELIGIBLE', True))

        print('5. the bump: larger YEC bonds outrank minimum ones by seat weight')
        p1 = self.wallet_join(CAP)
        p2 = self.wallet_join(CAP)
        self.mature()
        assert_equal(self.seated(), sorted([at_floor, at_mid, at_cap, p1, p2]))
        z = self.wallet_join(CAP)
        assert_equal(self.last_reg['warning'], '')       # the cap always qualifies
        recs = self.records()
        reg_z, reg_f = recs[z]['registerHeight'], recs[at_floor]['registerHeight']
        a = user.yed_getinfo()['params']['attest']

        def rank(bond, age, seated):
            return seat_weight(bond, age, a['seatAgeUnit'], a['seatAgeCap']) * (10000 + (a['seatMarginBps'] if seated else 0))
        h = reg_z + BOND_MATURITY
        assert rank(CAP, h - reg_z, False) > rank(FLOOR, h - reg_f, True)
        while user.getblockcount() < h - 1:
            self.mine(POOLS[0])
        assert_equal(self.seated(), sorted([at_floor, at_mid, at_cap, p1, p2]))
        self.mine(POOLS[0])
        assert_equal(user.getblockcount(), h)
        assert_equal(self.seated(), sorted([at_mid, at_cap, p1, p2, z]))
        assert_equal(self.status(at_floor), 'ELIGIBLE')  # bumped, still a member
        assert_same_statehash(self.enforcing_nodes(), 'D-Q-30')
        model_check(self.nodes[POOLS[0]])


if __name__ == '__main__':
    YellowbackAttestBondTest().main()
