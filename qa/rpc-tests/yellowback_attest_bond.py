#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
D-Q-28 (owner, option B) on regtest: the module's attestor bond floor follows the attested price at
registration. Regtest carries the rule at 1/2,000 of mainnet (bondMinNoPriceZat 10 YEC, bondMinFloorZat
1 YEC, bondMinUsdCents 400 = $4), so every crossover is mainnet's: the floor binds above $4/YEC and the
no-price cap below $0.40/YEC (mainnet 20,000 YEC / 2,000 YEC / $8,000).

1. No attested price (UNARMED at $1): yed_getinfo params.attest.bondMinZat is 10 YEC; yed_registerattestor
   refuses 9.99999999 (bond-below-min); a raw SET_JOIN at 10 YEC - 1 zat is mirrored but stays PENDING
   past maturity, the founders at 10 YEC arm the layer.
2. ARMED, founding window: still 10 YEC; past it at $1: 4 YEC ($4), 3.99999999 refused, a raw join at
   4 YEC - 1 zat stays PENDING, the wallet's 4-YEC join becomes ELIGIBLE.
3. At $5: the 1-YEC floor ($4 is 0.8 YEC); 0.99999999 refused, 1 YEC accepted. The 4 YEC - 1 zat join
   registered at $1 stays PENDING: the price at registration binds for good.
4. At $0.10: $4 is 40 YEC, capped at 10 YEC (option B); every seated record stays seated: no record is
   re-judged when the price moves.
5. The bump: seats are N_SLOTS (5) by bondZat x age in YEC. A 10-YEC join takes the seat of the 1-YEC
   minimum bond at its maturity, and a second 10-YEC join takes the 4-YEC one's at the first block where
   10 x age > 4 x min(age, AGE_CAP); the bumped records stay ELIGIBLE members.
6. Owner ruling A1/B1: a snapshot with HALT_DIVERGENCE is "no price". Two of three pools inflate $1 -> $5: bondMin
   walks down to the 1-YEC floor and HALT-3 (which fires on a fall only) never trips; when the inflation stops the
   fast median falls below the mid, DIVERGENCE trips and bondMin is the no-price 10 YEC.
The Python model replays the chain (the rule is mirrored in yellowback_model.py).

Nodes: 0 user, 1 stock, 2-4 pools, 5 observer.
"""

import os
from decimal import Decimal

from test_framework.util import assert_equal
from test_framework.yellowback_util import (
    AGE_CAP,
    BOND_MATURITY,
    BOND_MIN_LOCK,
    COIN,
    FOUNDING_WINDOW,
    POOLS,
    P_SLOW_WINDOW,
    YellowbackTestFramework,
    assert_same_statehash,
    secret_to_pubkey,
    wait_yed_healthy,
)
from test_framework.yellowback_attest import build_register_tx, model_check, register_and_arm, send_and_lock

USER = 0
REPRICE_BLOCKS = P_SLOW_WINDOW + 6          # every window at the new price: pMint (min of windows) follows


def assert_rpc_error(substr, fn, *args):
    try:
        fn(*args)
    except Exception as e:
        assert substr in str(e), 'expected %r in %r' % (substr, str(e))
        return str(e)
    raise AssertionError('expected an error containing %r' % substr)


def zat(yec):
    return int(Decimal(yec) * COIN)


# Rule: D-Q-28
class YellowbackAttestBondTest(YellowbackTestFramework):

    initial_blocks = 101

    def bond_min(self):
        mins = set(n.yed_getinfo()['params']['attest']['bondMinZat'] for n in self.enforcing_nodes())
        assert_equal(len(mins), 1)
        return mins.pop()

    def reprice(self, usd):
        for i in POOLS:
            self.quote(i, usd)
        self.mine_round_robin(POOLS, REPRICE_BLOCKS)
        self.sync_all(blocks_only=True)
        assert_equal(self.nodes[USER].yed_getprice(self.nodes[USER].getblockcount())['pMint'], int(Decimal(usd) * 1_000_000))

    def records(self, node=None):
        node = node or self.nodes[POOLS[0]]
        return dict((int(r['seq']), r) for r in node.yed_listattestors())

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

    def wallet_join(self, bond_yec):
        res = self.last_reg = self.nodes[USER].yed_registerattestor(Decimal(bond_yec), BOND_MIN_LOCK)
        self.sync_all()
        self.mine(POOLS[0])
        return self.seq_of(res['attestorPubKey'])

    def seq_of(self, pubkey_hex):
        pub = pubkey_hex if isinstance(pubkey_hex, str) else pubkey_hex.hex()
        found = [s for s, r in self.records().items() if r['attestorPubKey'] == pub]
        assert_equal(len(found), 1)
        return found[0]

    def status(self, seq):
        return self.records()[seq]['status']

    def seated(self):
        return sorted(s for s, r in self.records().items() if r['seated'])

    def run_test(self):
        user = self.nodes[USER]
        for node in self.enforcing_nodes():
            wait_yed_healthy(node)
            a = node.yed_getinfo()['params']['attest']
            assert_equal((a['bondMinNoPriceZat'], a['bondMinFloorZat'], a['bondMinUsdCents']), (10 * COIN, COIN, 400))

        print('1. no attested price (UNARMED at $1): 10 YEC')
        self.activate(POOLS, quote_usd=1)
        assert_equal(self.bond_min(), 10 * COIN)
        assert_rpc_error('bond-below-min', user.yed_registerattestor, Decimal('9.99999999'), BOND_MIN_LOCK)
        below_noprice = self.raw_join(10 * COIN - 1)
        founders = register_and_arm(self)              # three founders at 10 YEC arm the layer
        assert_equal(len(founders), 3)
        assert_equal(self.status(below_noprice), 'PENDING')
        trigger = user.yed_getinfo()['attest']['triggerHeight']

        print('2. ARMED: 10 YEC in the founding window, then $4 at $1 = 4 YEC')
        if user.getblockcount() + 1 <= trigger + FOUNDING_WINDOW:
            assert_equal(self.bond_min(), 10 * COIN)
            self.mine_round_robin(POOLS, trigger + FOUNDING_WINDOW - user.getblockcount())
        assert_equal(self.bond_min(), 4 * COIN)
        assert_rpc_error('bond-below-min', user.yed_registerattestor, Decimal('3.99999999'), BOND_MIN_LOCK)
        below_at_1 = self.raw_join(4 * COIN - 1)
        x4 = self.wallet_join('4')                       # the $8,000 minimum's regtest image
        assert self.last_reg['warning'].startswith('bond-near-min'), self.last_reg['warning']   # B2: no headroom
        self.mine_round_robin(POOLS, BOND_MATURITY)
        assert_equal((self.status(below_at_1), self.status(x4)), ('PENDING', 'ELIGIBLE'))

        print('3. $5: the 1-YEC floor; the $1 registration stays judged at $1')
        self.reprice('5')
        assert_equal(self.bond_min(), COIN)
        assert_rpc_error('bond-below-min', user.yed_registerattestor, Decimal('0.99999999'), BOND_MIN_LOCK)
        y1 = self.wallet_join('1')
        self.mine_round_robin(POOLS, BOND_MATURITY)
        assert_equal(self.status(y1), 'ELIGIBLE')
        assert_equal(self.status(below_at_1), 'PENDING')   # 4 YEC - 1 zat would pass at $5; judged at $1
        assert_equal(self.seated(), sorted(founders + [x4, y1]))

        print('4. $0.10: $4 is 40 YEC, capped at the 10-YEC no-price bond; nothing is re-judged')
        self.reprice('0.10')
        assert_equal(self.bond_min(), 10 * COIN)
        assert_rpc_error('bond-below-min', user.yed_registerattestor, Decimal('9.99999999'), BOND_MIN_LOCK)
        assert_equal(self.seated(), sorted(founders + [x4, y1]))
        assert_equal((self.status(x4), self.status(y1)), ('ELIGIBLE', 'ELIGIBLE'))

        print('5. the bump: larger YEC bonds outrank minimum ones by bondZat x age')
        z = self.wallet_join('10')
        assert_equal(self.last_reg['warning'], '')                # the no-price bond always qualifies
        reg_z = self.records()[z]['registerHeight']
        while user.getblockcount() < reg_z + BOND_MATURITY - 1:
            self.mine(POOLS[0])
        assert_equal(self.seated(), sorted(founders + [x4, y1]))
        self.mine(POOLS[0])                              # z ELIGIBLE: 10 x 8 > 1 x 64, the 1-YEC bond loses its seat
        assert_equal(self.status(z), 'ELIGIBLE')
        assert_equal(self.seated(), sorted(founders + [x4, z]))
        assert_equal(self.status(y1), 'ELIGIBLE')        # bumped, still a member
        w = self.wallet_join('10')
        recs = self.records()
        reg_w, reg_x = recs[w]['registerHeight'], recs[x4]['registerHeight']

        def weight(bond, age):
            return bond * max(0, min(age, AGE_CAP))
        h = reg_w + BOND_MATURITY
        while not weight(10 * COIN, h - reg_w) > weight(4 * COIN, h - reg_x):
            h += 1
        while user.getblockcount() < h - 1:
            self.mine(POOLS[0])
        assert_equal(self.seated(), sorted(founders + [x4, z]))
        self.mine(POOLS[0])
        assert_equal(user.getblockcount(), h)
        assert_equal(self.seated(), sorted(founders + [z, w]))
        assert_equal(self.status(x4), 'ELIGIBLE')
        print('6. owner ruling A1/B1: pool inflation, and HALT_DIVERGENCE as "no price"')
        self.reprice('1')
        assert_equal(self.bond_min(), 4 * COIN)
        for i in POOLS[:2]:
            self.quote(i, '5')                           # two of three pools inflate to $5, one stays honest at $1
        ramp, floor_at, diverged = [], None, False
        for n in range(1, REPRICE_BLOCKS + 1):
            self.mine_round_robin(POOLS, 1)
            halts = user.yed_getstats()['haltMask']
            diverged = diverged or 'DIVERGENCE' in halts
            ramp.append(self.bond_min())
            if floor_at is None and ramp[-1] == COIN:
                floor_at = n
        print('   inflation: bondMin per block %s; the 1-YEC floor after %s blocks; DIVERGENCE seen: %s'
              % ([b / COIN for b in ramp[:floor_at or len(ramp)]], floor_at, diverged))
        assert floor_at is not None
        assert not diverged                              # HALT-3 fires on a fall only: the rise never trips it
        for i in POOLS[:2]:
            self.quote(i, '1')                           # the inflation stops: the fast median falls below the mid
        tripped = None
        for n in range(1, REPRICE_BLOCKS + 1):
            self.mine_round_robin(POOLS, 1)
            if 'DIVERGENCE' in user.yed_getstats()['haltMask']:
                tripped = n
                break
        assert tripped is not None
        print('   the fall trips DIVERGENCE after %d blocks; bondMin is then the no-price %s YEC' % (tripped, self.bond_min() / COIN))
        assert_equal(self.bond_min(), 10 * COIN)
        assert_same_statehash(self.enforcing_nodes(), 'D-Q-28')
        model_check(self.nodes[POOLS[0]])


if __name__ == '__main__':
    YellowbackAttestBondTest().main()
