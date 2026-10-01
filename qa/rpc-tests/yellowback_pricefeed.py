#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The price feed (plan §3.7 PRICE-1/2, SIGMA-1, HALT-1..3, REG-1..4, FEE-W; L1, L9):

  - window fill boundaries: pFast defined at ceil(W/2) quote tags, pMid and pSlow at ceil(2W/3);
  - P_mint = min(pFast, pMid, pSlow) in a rising and in a falling market, P_claim = max(pMid, pSlow);
  - the divergence halt fires within the fast window on a crash, halt3_fires_on_mid_vs_slow (the
    second disjunct), and it clears on re-convergence;
  - halt2_fires_at_exact_threshold: globalRatioBps 24,999 halts, 25,000 does not;
  - the sigma multiplier rises after a volatile series and is capped; sigma1_one_pool_cannot_inflate;
  - HALT-1 by name when a window empties; registration lapses N_REG blocks after the last quote (REG-1);
  - a lying pool is penalised for N_PENALTY: the wallet's default choice skips it while it stays in
    E(R) and a raw redemption paying it is still accepted (L1);
  - accuracy weighting changes payee frequency (200 selectors at one R, no mining; the accurate
    pool's share within [0.6, 0.72] for a 2:1 weight);
  - price1_quote_majority_needs_fill (L9): the stock node forges quote tags at twice the pools' price;
  - assert_model_matches(node, full=True) at the end (N23).

Nodes: 0 user, 1 stock (forges tags in the L9 case), 2-4 pools, 5 observer.
"""

from test_framework.util import assert_equal, assert_greater_than, bytes_to_hex_str, hex_str_to_bytes
from test_framework.yellowback_util import (
    ACCURACY_WINDOW,
    COIN,
    MIN_FILL,
    N_PENALTY,
    N_REG,
    PEER_LAG,
    POOLS,
    P_FAST_WINDOW,
    P_MID_WINDOW,
    PAYEE_WINDOW,
    P_SLOW_WINDOW,
    REF_LAG,
    SIGMA_MULT_MAX_BPS,
    SIGMA_REF_BPS,
    STOCK,
    YellowbackTestFramework,
    build_vault_spend_raw,
    fee_zat,
    mine_block_raw,
    pubkey_to_address,
    round_robin_schedule,
    set_quote,
    template_coinbase,
)
from test_framework.yellowback_attest import wallet_mint
from test_framework import yellowback_model as ym

USD = 1_000_000


def assert_rpc_error(substr, fn, *args):
    try:
        fn(*args)
    except Exception as e:
        assert substr in str(e), 'expected %r in %r' % (substr, str(e))
        return
    raise AssertionError('expected an error containing %r' % substr)


def outpoint_selector(txid, n=0):
    return bytes_to_hex_str(bytes.fromhex(txid)[::-1] + n.to_bytes(4, 'little'))


class YellowbackPricefeedTest(YellowbackTestFramework):

    sigma_ref = SIGMA_REF_BPS      # the mainnet SIGMA_REF; regtest's default fixes the multiplier at 1

    def quote(self, usd, pools=POOLS):
        for i in pools:
            set_quote(self.nodes[i], usd)

    def price(self, node=None):
        return (node or self.nodes[0]).yed_getprice()

    def forge_quote_block(self, price_micro, key20):
        """One block on the stock node whose coinbase carries a quote tag (signal bit set) for
        ``key20`` at ``price_micro``: what a pool that does not run the module could do (L9)."""
        stock = self.nodes[STOCK]
        cb, gbt = template_coinbase(stock)
        cb.vin[0].scriptSig = cb.vin[0].scriptSig + ym.tag_push(1, price_micro, 1, key20)
        result, h = mine_block_raw(stock, [], coinbase=cb, gbt=gbt)
        assert_equal(result, None)
        self.sync_all(blocks_only=True)
        return h

    def mixed_window(self, pool_blocks, forged_blocks, plain_blocks, price_micro, key20):
        """One 64-block window mined with those shares (pools round robin, stock forging, stock plain)."""
        FORGE, PLAIN = -1, -2
        schedule = round_robin_schedule([POOLS[0], FORGE, PLAIN], 64, [pool_blocks, forged_blocks, plain_blocks])
        k = 0
        for who in schedule:
            if who == FORGE:
                self.forge_quote_block(price_micro, key20)
            elif who == PLAIN:
                self.nodes[STOCK].generate(1)
                self.sync_all(blocks_only=True)
            else:
                self.nodes[POOLS[k % 3]].generate(1)
                self.sync_all(blocks_only=True)
                k += 1

    def run_test(self):
        nodes = self.nodes
        user, stock = nodes[0], nodes[STOCK]

# Rule: PRICE-1 TAG-1
        print('window fill boundaries: ceil(W/2) for the fast window, ceil(2W/3) for mid and slow (L9)')
        self.quote(50)
        assert_equal(self.price()['pFast'], None)
        for n in range(1, P_SLOW_WINDOW + 1):
            self.mine(POOLS[n % 3])
            p = self.price()
            fill = p['fill']
            assert_equal((fill['fast']['window'], fill['mid']['window'], fill['slow']['window']), (P_FAST_WINDOW, P_MID_WINDOW, P_SLOW_WINDOW))
            assert_equal((fill['fast']['minFill'], fill['mid']['minFill'], fill['slow']['minFill']), MIN_FILL)
            assert_equal((fill['fast']['quoteTags'], fill['mid']['quoteTags'], fill['slow']['quoteTags']),
                         (min(n, P_FAST_WINDOW), min(n, P_MID_WINDOW), min(n, P_SLOW_WINDOW)))
            assert_equal(p['pFast'] is not None, n >= MIN_FILL[0], 'fast at %d' % n)
            assert_equal(p['pMid'] is not None, n >= MIN_FILL[1], 'mid at %d' % n)
            assert_equal(p['pSlow'] is not None, n >= MIN_FILL[2], 'slow at %d' % n)
            assert_equal(p['pMint'] is not None, n >= MIN_FILL[2])     # min over all three: defined once the slowest fills
            assert_equal(p['pClaim'] is not None, n >= MIN_FILL[2])    # max(pMid, pSlow): both must be defined
            assert_equal('NO_PRICE' in user.yed_getstats()['haltMask'], n < MIN_FILL[2])
            if n >= MIN_FILL[2]:
                assert_equal((p['pFast'], p['pMid'], p['pSlow'], p['pMint'], p['pClaim']), (50 * USD,) * 5)
            assert_equal(p['tag']['kind'], 'quote')
            assert_equal(p['tag']['priceMicroUsd'], 50 * USD)
        assert 'NO_PRICE' not in user.yed_getstats()['haltMask']

        print('activate; the sigma multiplier is 1 once every sample is defined')
        self.activate(POOLS)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        assert_equal(user.yed_getinfo()['params']['sigmaRefBps'], SIGMA_REF_BPS)
        assert_equal(user.yed_getstats()['sigmaMultBps'], 10000)
# Rule: MINT-5 SIGMA-1
        mint = wallet_mint(self, user, 10000, 48)     # v3: the carrier step (W7)
        assert_equal(mint['collateralZat'], 10 * COIN)        # 500 % of $100 at $50, multiplier 1
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(user.yed_getvault(mint['txid'])['status'], 'ACTIVE')
        assert_equal(nodes[2].yed_getstats()['collateralZat'], 10 * COIN)

# Rule: SIGMA-1 PRICE-1 REG-2
        print('sigma1_one_pool_cannot_inflate: node 2 alternates +-20 % while 3 and 4 hold $50')
        low = True
        for i in round_robin_schedule(POOLS, 64):
            if i == POOLS[0]:
                set_quote(nodes[i], 40 if low else 60)
                low = not low
            self.mine(i, blocks_only=True)
            p = self.price()
            assert_equal(p['pFast'], 50 * USD)
        assert_equal(user.yed_getstats()['sigmaMultBps'], 10000)
        assert_equal(user.yed_getstats()['pMint'], 50 * USD)
        set_quote(nodes[POOLS[0]], 50)

# Rule: SIGMA-1
        print('the sigma multiplier rises after a 5 % move and is capped after a 20 % move')
        self.quote('52.5')
        self.mine_round_robin(POOLS, 10)
        assert_equal(self.price()['pFast'], 52_500_000)
        sigma = user.yed_getstats()['sigmaMultBps']
        assert_greater_than(sigma, 10000)
        assert_greater_than(SIGMA_MULT_MAX_BPS, sigma)
        est = user.yed_estimatecollateral(10000, 48)
        assert_equal(est['sigmaMultBps'], sigma)
        assert_equal(est['minRatioBps'], 50000 * sigma // 10000)
# Rule: PRICE-2
        print('P_mint = min in a rising market (pFast $63 above pMid and pSlow)')
        self.quote(63)
        self.mine_round_robin(POOLS, 8)
        assert_equal(user.yed_getstats()['sigmaMultBps'], SIGMA_MULT_MAX_BPS)
        p = self.price()
        assert_equal(p['pFast'], 63 * USD)
        assert_equal(p['pMint'], min(p['pFast'], p['pMid'], p['pSlow']))
        assert_equal(p['pMint'], 50 * USD)
        assert_equal(p['pClaim'], max(p['pMid'], p['pSlow']))
        assert 'DIVERGENCE' not in user.yed_getstats()['haltMask']
        print('P_mint = min in a falling market (pFast $45)')
        self.quote(45)
        self.mine_round_robin(POOLS, 8)
        p = self.price()
        assert_equal(p['pFast'], 45 * USD)
        assert_equal(p['pMint'], 45 * USD)
        assert_equal(p['pMint'], min(p['pFast'], p['pMid'], p['pSlow']))
        assert 'DIVERGENCE' not in user.yed_getstats()['haltMask']

# Rule: HALT-3
        print('the divergence halt fires within the fast window on a crash to $30')
        self.quote(30)
        fired_at = None
        for n in range(1, P_FAST_WINDOW + 1):
            self.mine_round_robin(POOLS, 1)
            if 'DIVERGENCE' in user.yed_getstats()['haltMask']:
                fired_at = n
                break
        assert_equal(fired_at, MIN_FILL[0])
        assert_equal(user.yed_getstats()['mintingAllowed'], False)
        self.mine_round_robin(POOLS, REF_LAG)              # the wallet reads Snapshots[tip - REF_LAG]
        assert_rpc_error('mintpol-divergence', user.yed_mint, 10000, 48)
        print('halt3_fires_on_mid_vs_slow: pFast == pMid == $30 while pSlow holds; the second disjunct alone')
        self.mine_round_robin(POOLS, 12)                    # 18 of the last 24 quotes are $30
        p = self.price()
        assert_equal((p['pFast'], p['pMid']), (30 * USD, 30 * USD))
        assert_greater_than(p['pSlow'], 40 * USD)
        assert 'DIVERGENCE' in user.yed_getstats()['haltMask']
        print('and it clears on re-convergence')
        self.quote(50)
        cleared = None
        for n in range(1, 2 * P_MID_WINDOW):
            self.mine_round_robin(POOLS, 1)
            if 'DIVERGENCE' not in user.yed_getstats()['haltMask']:
                cleared = n
                break
        assert cleared is not None
        assert_greater_than(P_MID_WINDOW, cleared)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        assert_equal(user.yed_getstats()['haltMask'], [])
        assert_equal(user.yed_getstats()['mintingAllowed'], True)   # a capped multiplier is not a halt

# Rule: HALT-2
        print('halt2_fires_at_exact_threshold: 10 YEC against $100 is exactly 250 % at $25 and 249.99 % at $24.999999')
        self.quote(25)
        self.mine_round_robin(POOLS, MIN_FILL[0] + REF_LAG)
        st = user.yed_getstats()
        assert_equal(st['pMint'], 25 * USD)
        assert_equal(st['globalRatioBps'], 25000)
        assert 'GLOBAL_RATIO' not in st['haltMask']
        self.quote('24.999999')
        self.mine_round_robin(POOLS, MIN_FILL[0])
        st = user.yed_getstats()
        assert_equal(st['pMint'], 24_999_999)
        assert_equal(st['globalRatioBps'], 24999)
        assert 'GLOBAL_RATIO' in st['haltMask']
        for node in self.enforcing_nodes():
            assert 'GLOBAL_RATIO' in node.yed_getstats()['haltMask']

# Rule: HALT-2 MINT-4 MINTPOL-1
        print('W16: under the halt only class A (500 %) can mint; one such mint raises the ratio and clears the halt')
        # the slow window still remembers the crash-and-recovery above, so DIVERGENCE is set beside
        # GLOBAL_RATIO; every other halt stops every class, so let the windows agree at $24.999999 first
        self.mine_round_robin(POOLS, P_SLOW_WINDOW)
        st = user.yed_getstats()
        assert_equal(st['haltMask'], ['GLOBAL_RATIO'])
        assert_equal((st['mintingAllowed'], st['mintableClasses']), (False, ['A']))
        assert_rpc_error('mintpol-global-ratio', user.yed_mint, 10000, 145)     # class C, 300 %: below the recapitalisation floor
        assert_rpc_error('mintpol-global-ratio', user.yed_mint, 10000, 97)      # class B, 400 %
        recap = wallet_mint(self, user, 10000, 48)                              # class A: 20 YEC at $25 against $100
        self.mine(POOLS[0])
        assert_equal(user.yed_getvault(recap['txid'])['status'], 'ACTIVE')
        self.mine_round_robin(POOLS, REF_LAG)
        st = user.yed_getstats()
        assert_greater_than(st['globalRatioBps'], 25000)                        # (10 + 20) YEC * $25 against $200 = 375 %
        assert 'GLOBAL_RATIO' not in st['haltMask']
        assert_equal(sorted(st['mintableClasses']), ['A', 'B', 'C'])
        self.quote(50)
        self.mine_round_robin(POOLS, P_MID_WINDOW)
        assert 'GLOBAL_RATIO' not in user.yed_getstats()['haltMask']

# Rule: HALT-1 REG-1
        print('HALT-1 by name when the fast window empties; registration lapses N_REG blocks after the last quote tag')
        last_quote_height = user.getblockcount()
        stock.generate(P_FAST_WINDOW)
        self.sync_all(blocks_only=True)
        assert 'NO_PRICE' in user.yed_getstats()['haltMask']
        assert_equal(self.price()['pFast'], None)
        assert_equal(self.price()['pMint'], None)
        assert_equal(user.yed_getstats()['pMint'], None)
        for row in user.yed_listminers(user.getblockcount(), N_REG):
            assert_equal(row['registered'], True)
        stock.generate(N_REG - P_FAST_WINDOW - 1)
        self.sync_all(blocks_only=True)
        assert_equal(user.getblockcount(), last_quote_height + N_REG - 1)
        # only the pool that mined the last quote block still has a quote in (tip - N_REG, tip]
        assert_equal(sorted(row['registered'] for row in user.yed_listminers(user.getblockcount(), N_REG + 8)), [False, False, True])
        stock.generate(1)
        self.sync_all(blocks_only=True)
        rows = user.yed_listminers(user.getblockcount(), N_REG + 8)
        assert_equal(len(rows), 3)
        for row in rows:
            assert_equal((row['registered'], row['eligible']), (False, False))
        assert_rpc_error('fee-no-eligible-payee', user.yed_getfeepayee, user.getblockcount(), 10 * COIN)
        assert_equal(user.yed_listminers(), [])
        self.mine_round_robin(POOLS, MIN_FILL[2] + 5)       # the slow window needs 43 quotes of 64 again
        assert_equal(user.yed_getstats()['haltMask'], [])
        for row in user.yed_listminers():
            assert_equal((row['registered'], row['eligible'], row['penalizedUntil']), (True, True, 0))

# Rule: REG-2 REG-4 FEE-2 FEE-W RED-3
        print('a lying pool is penalised for N_PENALTY blocks: the default choice skips it, a raw redemption paying it is still accepted (L1)')
        liar = POOLS[0]
        liar_addr = self.pool_addresses[0]
        set_quote(nodes[liar], '57.5')                      # 15 % above the peers: outside DEVIATION_BPS
        nodes[liar].generate(1)
        self.sync_all(blocks_only=True)
        lie_height = user.getblockcount()
        set_quote(nodes[liar], 50)
        self.mine_round_robin(POOLS[1:], PEER_LAG + 1)     # judged at lie_height + PEER_LAG
        rows = {r['payoutAddress']: r for r in user.yed_listminers()}
        assert_equal(rows[liar_addr]['penalizedUntil'], lie_height + PEER_LAG + N_PENALTY)
        assert_equal(rows[liar_addr]['eligible'], True)
        assert_equal(rows[liar_addr]['inBand'] < rows[liar_addr]['quoted'], True)
        r = user.getblockcount()
        vault = user.yed_getvault(mint['txid'])
        payees = user.yed_getfeepayee(r, vault['collateralZat'], outpoint_selector(mint['txid']))
        assert liar_addr in payees['eligible']
        chosen = set()
        for i in range(200):
            sel = bytes_to_hex_str(b'\x02' + i.to_bytes(32, 'little'))
            chosen.add(user.yed_getfeepayee(r, vault['collateralZat'], sel)['default']['payoutAddress'])
        assert liar_addr not in chosen
        assert_equal(len(chosen), 2)
        assert_greater_than(r + 1, vault['lockHeight'])
        coin = [c for c in user.yed_listunspent() if c['cents'] == 10000][0]
        owner_wif = user.dumpprivkey(pubkey_to_address(hex_str_to_bytes(vault['ownerPubKey'])))
        hex_ = build_vault_spend_raw(user, vault, 'owner', [(coin['txid'], coin['vout'])], payload=ym.encode_redeem(r, 1, []),
                                     fee=(liar_addr, fee_zat(vault['collateralZat'])), ref_height=r, owner_wif=owner_wif)
        v = nodes[3].yed_validaterawtransaction(hex_)
        assert_equal((v['verdict'], v['blockValid'], v['wouldBeRejected'], v['payee']), ('ok', True, False, liar_addr))
        result, _ = mine_block_raw(nodes[3], [hex_])
        assert_equal(result, None)
        self.sync_all(blocks_only=True)
        closed = nodes[2].yed_getvault(mint['txid'])
        assert_equal((closed['status'], closed['feePaidZat']), ('CLOSED', fee_zat(vault['collateralZat'])))
        self.checkpoint('raw redemption paying the penalised pool')

# Rule: REG-3 REG-4 FEE-W
        print('accuracy weighting: node 4 quotes 4 % high (out of band, within deviation); node 2 stops quoting')
        self.mine_round_robin(POOLS, N_PENALTY + 1)         # the penalty above has lapsed
        set_quote(nodes[POOLS[2]], 52)
        self.mine_round_robin(POOLS, ACCURACY_WINDOW + PEER_LAG + 4)
        set_quote(nodes[POOLS[0]], 0)                       # signal-only tags from now on
        self.mine_round_robin(POOLS, 12)
        r = user.getblockcount()
        rows = {row['payoutAddress']: row for row in user.yed_listminers()}
        assert_equal(sorted(rows), sorted(self.pool_addresses[1:]))
        accurate, inaccurate = self.pool_addresses[1], self.pool_addresses[2]
        assert_equal(rows[accurate]['accuracyBps'], 10000)
        assert_equal(rows[inaccurate]['accuracyBps'], 0)
        assert_equal(rows[inaccurate]['penalizedUntil'], 0)
        assert_equal(rows[inaccurate]['inBand'], 0)
        assert_greater_than(rows[inaccurate]['quoted'], 0)
        payees = user.yed_getfeepayee(r, 10 * COIN)
        assert_equal(sorted(payees['eligible']), sorted([accurate, inaccurate]))
        assert_equal(payees['policy']['tiltBps'], 10000)
        # DefaultPayee weights one candidate entry per *quote tag* in the last PAYEE_WINDOW
        # blocks, so the accurate pool's true share is 2*X/(2*X + Y) for X accurate and Y
        # inaccurate tags in that window, not the 2:1 weight on its own.  A three-pool rotation
        # splits a 10-block regtest window 4:3 or 3:4, which puts the truth at 0.600 or 0.727 —
        # the plan's [0.6, 0.72] band read as the *expected* value, with the 200-draw sample
        # around it (docs/mapping.md section 13.5).
        tags = [user.yed_gettag(str(h)) for h in range(r - PAYEE_WINDOW + 1, r + 1)]
        quote_tags = [t for t in tags if t['found'] and t['kind'] == 'quote']
        x = len([t for t in quote_tags if t['payoutAddress'] == accurate])
        y = len([t for t in quote_tags if t['payoutAddress'] == inaccurate])
        assert_equal(x + y, len(quote_tags))            # no other pool quotes in the window
        assert_greater_than(x, 0)
        expected = 2.0 * x / (2.0 * x + y)
        assert 0.6 <= expected <= 0.73, (x, y, expected)
        counts = {accurate: 0, inaccurate: 0}
        for i in range(200):
            sel = bytes_to_hex_str(b'\x02' + i.to_bytes(32, 'little'))
            d = user.yed_getfeepayee(r, 10 * COIN, sel)['default']
            counts[d['payoutAddress']] += 1
            assert_equal(d['weight'], 20000 if d['payoutAddress'] == accurate else 10000)
        share = counts[accurate] / 200.0
        # the accurate pool is favoured, and the sample is within 4 sigma of the truth
        assert share > float(x) / (x + y), (counts, x, y)
        assert abs(share - expected) <= 0.14, (counts, x, y, expected)
        assert_equal(self.price()['pFast'], 50 * USD)       # the 4 % quotes never moved the lower median

# Rule: PRICE-1 PRICE-2 TAG-1 HALT-3
        print('price1_quote_majority_needs_fill (L9): the stock node forges quote tags at $100')
        set_quote(nodes[POOLS[0]], 50)
        set_quote(nodes[POOLS[2]], 50)
        self.mine_round_robin(POOLS, P_SLOW_WINDOW)
        assert_equal(self.price()['pClaim'], 50 * USD)
        key20 = ym.address_key_hash(stock.getnewaddress())
        print('  26 % forged, pools fill 50 % of the windows: pClaim unchanged')
        self.mixed_window(32, 17, 15, 100 * USD, key20)
        p = self.price()
        assert p['pClaim'] in (None, 50 * USD), p
        assert_equal(p['pSlow'], 50 * USD)
        assert_equal(user.yed_listclaimable(), [])
        assert_equal(user.yed_gettag(str(user.getblockcount()))['found'], True)
        assert_equal(user.yed_getactivation()['enforcementSuspended'], False)
        print('  34 % forged, pools at 33 %: a quote-tag majority moves pSlow and pClaim, and the mint gate reflects it')
        self.mixed_window(21, 22, 21, 100 * USD, key20)
        p = self.price()
        assert_equal(p['pSlow'], 100 * USD)
        assert p['pClaim'] in (None, 100 * USD), p         # None only if the mid window's fill dipped below 16
        assert_equal(user.yed_getstats()['mintingAllowed'], False)
        assert 'DIVERGENCE' in user.yed_getstats()['haltMask'] or 'NO_PRICE' in user.yed_getstats()['haltMask']
        rows = user.yed_listminers(user.getblockcount(), 64)
        assert_equal(len(rows), 4)

        print('the Python model over the whole chain (N23)')
        ym.assert_model_matches(nodes[2], full=True)
        self.checkpoint('end')


if __name__ == '__main__':
    YellowbackPricefeedTest().main()
