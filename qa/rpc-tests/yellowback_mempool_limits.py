#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Phase 6 "ZIP-317 and mempool-limit interaction tests", the half review finding V-8 reopened
(docs/plans/yellowback-ycash6-plan.md §5; doc/yellowback-review.md V-8). The unpaid-action half is
yellowback_fee.py. This script covers the other two clauses on ycashd 6.20.0 + Yellowback:

1. RemoveInvalidVaultSpends (MP-1's ConnectTip sweep, src/yellowback/index.cpp; called from
   ConnectTip after removeExpired) on a mempool at its -mempooltxcostlimit. Node 0 runs a cost
   limit of SLOTS transactions at MIN_TX_COST (mempool_limit.h: every transaction here costs
   max(RecursiveDynamicUsage, 10000) = 10000). The limiter evicts; a valid vault spend S and its
   child C fill the last two slots; four blocks later RED-1's window closes and the sweep drops S
   and, recursively, C one block before the stock node's removeExpired would. The sweep removes
   through CTxMemPool::remove, which keeps the limiter's set (limitSet) in step: exactly two
   transactions then fit without an eviction and the next one evicts exactly one. A cost left
   behind in limitSet would evict early, or pick an id that is no longer in mapTx and crash
   (CTxMemPool::EnsureSizeLimit dereferences mapTx.find).
   Then a Yellowback mint and redemption (P-2 fees: no unpaid ZIP-317 action, so no
   LOW_FEE_PENALTY in their eviction weight) sit in the full mempool through several eviction
   rounds. The limiter picks at random by weight, so either outcome is legal; the script reports
   which happened and asserts the stock semantics either way: one eviction per round, an evicted
   transaction is refused on resubmission exactly as an evicted plain transaction is, and it still
   confirms through a node that holds it.

2. IsExpiringSoonTx (main.cpp; TX_EXPIRING_SOON_THRESHOLD = 3, main.h). A raw mint and a raw vault
   spend whose nExpiryHeight is inside the threshold are refused with the stock reason, the same
   message the stock binary gives, although MP-1's own expiry bound (expiry <= refHeight +
   REF_WINDOW) admits the spend. At the boundary (expiry = next height + 3) S is admitted. The
   wallet builders never produce an expiring-soon transaction (CheckExpiry,
   src/yellowback/txbuilder.cpp:388-393): every yed_* transaction here has expiry >= next height
   + 3, and at -yellowbackmintlag = MAX_REF_LAG (36), where the mint's expiry R + REF_WINDOW lands
   on the threshold, the two-step mint refuses with expiring-too-soon instead of building one;
   at 35 it builds the mint exactly on the threshold.

Nodes: 0 user (the limits), 1 stock, 2-4 pools, 5 observer.
"""

import time
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.util import assert_equal, assert_greater_than, sync_blocks
from test_framework.yellowback_util import (
    COIN,
    POOLS,
    REF_LAG,
    REF_WINDOW,
    STOCK,
    TX_EXPIRING_SOON_THRESHOLD,
    YellowbackTestFramework,
    _select_funding,
    build_mint_tx,
    build_vault_spend_raw,
    conventional_fee,
    debug_log_contains,
    fee_zat,
    mine_block_raw,
    mint_vault_raw,
    wait_yed_healthy,
    ym,
)
from test_framework.yellowback_attest import wait_for_spender, wallet_mint

USER = 0
MIN_TX_COST = 10_000            # mempool_limit.h
SLOTS = 6
COST_LIMIT = SLOTS * MIN_TX_COST
EVICTION_MINUTES = 60           # longer than the run: an evicted id stays refused
FILLER_COINS = 40
FILLER_VALUE = Decimal('0.5')
FILLER_FEE = 1_000              # = the conventional fee of one input and one output
MAX_REF_LAG = 36                # src/yellowback/params.h
CENTS = 10_000
LOCK = 48


def rpc_refusal(fn, *args):
    """``(code, message)`` of the JSON-RPC error ``fn(*args)`` raises."""
    try:
        fn(*args)
    except JSONRPCException as e:
        return e.error['code'], e.error['message']
    raise AssertionError('expected an RPC error from %r%r' % (fn, args))


def wait_for_mempool(node, txid, present=True, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if (txid in node.getrawmempool()) == present:
            return
        time.sleep(0.2)
    raise AssertionError('%s %s in mempool after %ds' % (txid, 'not' if present else 'still', timeout))


class YellowbackMempoolLimitsTest(YellowbackTestFramework):

    limits = False      # node 0 runs -mempooltxcostlimit once set
    mint_lag = None     # node 0's -yellowbackmintlag when set

    def node_args(self, i, extra=None):
        args = super().node_args(i, extra)
        if i == USER and self.limits:
            args += ['-mempooltxcostlimit=%d' % COST_LIMIT,
                     '-mempoolevictionmemoryminutes=%d' % EVICTION_MINUTES, '-debug=mempool']
        if i == USER and self.mint_lag is not None:
            args += ['-yellowbackmintlag=%d' % self.mint_lag]
        return args

    # --- helpers ---------------------------------------------------------------

    def raw_block(self, txs=()):
        """A block of exactly ``txs`` on POOLS[0]'s tip (its tagged template coinbase), so no
        mempool decides what is mined; blocks are synced, mempools are not (node 0's differs)."""
        result, blockhash = mine_block_raw(self.nodes[POOLS[0]], list(txs))
        assert result is None, result
        sync_blocks(self.nodes)
        return blockhash

    def filler(self):
        """A plain transaction from one of node 0's prepared coins, one input and one output,
        paying its conventional fee: cost MIN_TX_COST and no LOW_FEE_PENALTY, independent of
        every other transaction in the mempool. Returns ``(txid, hex)``."""
        user = self.nodes[USER]
        txid, n = self.coins.pop()
        raw = user.createrawtransaction([{'txid': txid, 'vout': n}],
                                        {user.getnewaddress(): FILLER_VALUE - Decimal(FILLER_FEE) / COIN})
        signed = user.signrawtransaction(raw)
        assert_equal(signed['complete'], True)
        return user.sendrawtransaction(signed['hex']), signed['hex']

    def fill(self, k):
        out = [self.filler() for _ in range(k)]
        self.hexes.update(dict(out))
        return [t for t, _h in out]

    def pool_state(self, label):
        """node 0's mempool: getmempoolinfo agrees with getrawmempool (size and the byte sum);
        never above SLOTS. Returns the set of txids."""
        user = self.nodes[USER]
        info = user.getmempoolinfo()
        verbose = user.getrawmempool(True)
        assert_equal(info['size'], len(verbose))
        assert_equal(info['bytes'], sum(int(e['size']) for e in verbose.values()))
        assert info['size'] <= SLOTS, '%s: %d transactions above the limit of %d' % (label, info['size'], SLOTS)
        print('  %-44s size %d bytes %d usage %d' % (label, info['size'], info['bytes'], info['usage']))
        return set(verbose)

    def assert_evicted_refusal(self, hex_, label):
        """A recently evicted transaction: AcceptToMemoryPool returns false with a valid state
        (main.cpp IsRecentlyEvicted), so sendrawtransaction answers RPC_TRANSACTION_ERROR with an
        empty reason. The same answer for every transaction, plain or Yellowback."""
        code, msg = rpc_refusal(self.nodes[USER].sendrawtransaction, hex_)
        if self.evicted_refusal is None:
            self.evicted_refusal = (code, msg)
            print('  an evicted transaction is refused with code %d, message %r' % (code, msg))
        assert_equal((code, msg), self.evicted_refusal)
        print('  %s: refused on resubmission as recently evicted' % label)

    def assert_expiry_floor(self, txid, built_at, label):
        """CheckExpiry's bound: the builder's nExpiryHeight is at least next height + 3."""
        raw = self.nodes[USER].decoderawtransaction(self.nodes[USER].gettransaction(txid)['hex'])
        expiry = int(raw['expiryheight'])
        assert expiry >= built_at + 1 + TX_EXPIRING_SOON_THRESHOLD, (label, expiry, built_at)
        return raw, expiry

    def redeem_payload(self, ref):
        return ym.encode_redeem(ref, 1, [])

    # --- setup -------------------------------------------------------------------

    def prepare(self):
        nodes = self.nodes
        user = nodes[USER]
        print('activate at $50 and fill the price windows')
        self.activate(POOLS, quote_usd=50)
        self.mine_round_robin(POOLS, REF_LAG + 1)

        print('%d coins of %s YEC for node 0\'s filler transactions' % (FILLER_COINS, FILLER_VALUE))
        needed = int(FILLER_VALUE * COIN) * FILLER_COINS + 100_000
        utxos, total = _select_funding(user, needed)
        outs = {user.getnewaddress(): FILLER_VALUE for _ in range(FILLER_COINS)}
        outs[user.getnewaddress()] = Decimal(total - needed) / COIN + Decimal('0.0009')
        raw = user.createrawtransaction([{'txid': u['txid'], 'vout': u['vout']} for u in utxos], outs)
        fan = user.sendrawtransaction(user.signrawtransaction(raw)['hex'])
        self.sync_all()
        self.mine(POOLS[0])
        fan_raw = user.getrawtransaction(fan, 1)
        self.coins = [(fan, o['n']) for o in fan_raw['vout'] if Decimal(str(o['value'])) == FILLER_VALUE]
        assert_equal(len(self.coins), FILLER_COINS)
        user.lockunspent(False, [{'txid': t, 'vout': n} for t, n in self.coins])   # kept from the wallet's own selection (re-locked after a restart)

        print('vault V (raw mint, node 0\'s key) for the sweep; mint M1 (yed_mint) for a redemption under pressure')
        self.v_txid, _v = mint_vault_raw(self, user, nodes[POOLS[1]])
        self.m1 = wallet_mint(self, user, CENTS, LOCK)
        self.mine(POOLS[2])
        assert_equal(user.yed_getvault(self.m1['txid'])['status'], 'ACTIVE')
        print('past both locks, and S\'s reference height (tip - 36) past V\'s lock')
        self.mine_round_robin(POOLS, LOCK + REF_WINDOW)
        self.checkpoint('prepared')

    # --- 2. IsExpiringSoonTx on raw transactions ---------------------------------------

    def expiring_soon_raw(self):
        # Rule: MP-1
        print('IsExpiringSoonTx: a raw mint and a raw vault spend inside the threshold get the stock reason')
        user, stock = self.nodes[USER], self.nodes[STOCK]
        tip = user.getblockcount()
        soon = tip + 1 + TX_EXPIRING_SOON_THRESHOLD - 1          # next height + 2: expiring soon
        est = user.yed_estimatecollateral(CENTS, LOCK)
        ref = int(est['refHeight'])
        payee = user.yed_getfeepayee(ref, int(est['requiredZat']))['default']['payoutAddress']
        mint_hex, _owner = build_mint_tx(user, CENTS, LOCK, ref, int(est['requiredZat']), fee_addr=payee, expiry=soon)
        expected = 'tx-expiring-soon: expiryheight is %d but should be at least %d' % (soon, soon + 1)
        msgs = [rpc_refusal(node.sendrawtransaction, mint_hex) for node in (user, stock)]
        assert expected in msgs[0][1], msgs[0]
        assert_equal(msgs[0], msgs[1])
        print('  mint, both nodes: %d %s' % msgs[0])

        vault = user.yed_getvault(self.v_txid)
        collateral = int(vault['collateralZat'])
        fee = (user.yed_getfeepayee(tip, collateral)['default']['payoutAddress'], fee_zat(collateral))
        spend_hex = build_vault_spend_raw(user, vault, 'owner', [(self.v_txid, 1)], payload=self.redeem_payload(tip),
                                          fee=fee, expiry=soon)
        check = user.yed_validaterawtransaction(spend_hex)
        assert_equal(check['blockValid'], True)
        assert_equal(check['wouldBeRejected'], False)            # MP-1's bound (expiry <= ref + REF_WINDOW) admits it
        msgs = [rpc_refusal(node.sendrawtransaction, spend_hex) for node in (user, stock)]
        assert expected in msgs[0][1], msgs[0]
        assert_equal(msgs[0], msgs[1])
        print('  vault spend, both nodes: %d %s (MP-1 alone would admit it)' % msgs[0])
        for node in self.nodes:
            assert_equal(len(node.getrawmempool()), 0)

    # --- 1a. the sweep on a mempool at its cost limit ----------------------------------

    def sweep_at_cost_limit(self):
        # Rule: MP-1
        nodes = self.nodes
        print('restart node 0 with -mempooltxcostlimit=%d (%d slots) -mempoolevictionmemoryminutes=%d'
              % (COST_LIMIT, SLOTS, EVICTION_MINUTES))
        self.limits = True
        user = self.restart(USER)
        sync_blocks(nodes)
        wait_yed_healthy(user)
        user.lockunspent(False, [{'txid': t, 'vout': n} for t, n in self.coins])
        stock = nodes[STOCK]

        print('fill: %d fillers into %d slots evict exactly two' % (SLOTS + 2, SLOTS))
        first = self.fill(SLOTS + 2)
        pool = self.pool_state('after the fill')
        assert_equal(len(pool), SLOTS)
        evicted = [t for t in first if t not in pool]
        assert_equal(len(evicted), 2)
        assert debug_log_contains(self.options.tmpdir, USER, 'Evicting transaction (txid=%s' % evicted[0])
        self.assert_evicted_refusal(self.hexes[evicted[0]], 'filler %s' % evicted[0][:16])

        print('a block of two fillers frees two slots')
        mined = sorted(pool)[:2]
        self.raw_block([self.hexes[t] for t in mined])
        before = self.pool_state('after the block')
        assert_equal(before, pool - set(mined))

        tip = user.getblockcount()
        expiry = tip + 1 + TX_EXPIRING_SOON_THRESHOLD           # the IsExpiringSoonTx boundary: admitted
        ref = expiry - REF_WINDOW                                # MP-1: expiry <= ref + REF_WINDOW; RED-1 closes at tip = expiry
        print('S: a valid owner-path redemption of V with refHeight %d (tip - %d), expiry %d (tip + %d); C spends S'
              % (ref, tip - ref, expiry, expiry - tip))
        vault = user.yed_getvault(self.v_txid)
        assert_equal(vault['status'], 'ACTIVE')
        assert_greater_than(ref, int(vault['lockHeight']))
        collateral = int(vault['collateralZat'])
        payee = user.yed_getfeepayee(ref, collateral)['default']['payoutAddress']
        s_hex = build_vault_spend_raw(user, vault, 'owner', [(self.v_txid, 1)], payload=self.redeem_payload(ref),
                                      fee=(payee, fee_zat(collateral)), expiry=expiry)
        assert_equal(user.yed_validaterawtransaction(s_hex)['wouldBeRejected'], False)
        s_txid = user.sendrawtransaction(s_hex)
        s_raw = user.getrawtransaction(s_txid, 1)
        s_out = s_raw['vout'][0]
        c_raw = user.createrawtransaction([{'txid': s_txid, 'vout': 0}],
                                          {user.getnewaddress(): Decimal(str(s_out['value'])) - Decimal(FILLER_FEE) / COIN})
        c_hex = user.signrawtransaction(c_raw, [{'txid': s_txid, 'vout': 0, 'scriptPubKey': s_out['scriptPubKey']['hex'],
                                                 'amount': s_out['value']}])['hex']
        c_txid = user.sendrawtransaction(c_hex)
        full = self.pool_state('S and C fill the last two slots')
        assert_equal(full, before | {s_txid, c_txid})             # at the limit, not above: no eviction
        for node in (stock, nodes[POOLS[0]]):
            wait_for_mempool(node, s_txid)
            wait_for_mempool(node, c_txid)

        print('three blocks without S: still valid (RED-1 holds at next height <= %d)' % expiry)
        for _ in range(3):
            self.raw_block()
            assert_equal(self.pool_state('tip %d' % user.getblockcount()), full)
        assert_equal(user.yed_validaterawtransaction(s_hex)['wouldBeRejected'], False)

        print('tip = %d: the window closes; the sweep drops S and C, removeExpired has not' % expiry)
        self.raw_block()
        assert_equal(user.getblockcount(), expiry)
        after = self.pool_state('after the sweep')
        assert_equal(after, before)                              # S and C gone, every filler kept
        assert debug_log_contains(self.options.tmpdir, USER, 'dropping vault spend %s' % s_txid)
        assert not debug_log_contains(self.options.tmpdir, USER, 'dropping vault spend %s' % c_txid)  # C went with S (recursive remove)
        for i in POOLS:
            wait_for_mempool(nodes[i], s_txid, present=False)
            wait_for_mempool(nodes[i], c_txid, present=False)
        assert s_txid in stock.getrawmempool() and c_txid in stock.getrawmempool()
        assert_equal(user.yed_validaterawtransaction(s_hex)['wouldBeRejected'], True)
        code, msg = rpc_refusal(user.sendrawtransaction, s_hex)
        assert 'tx-expiring-soon' in msg, msg                    # by now inside the threshold as well
        print('  S on resubmission: %d %s' % (code, msg))

        print('the limiter\'s bookkeeping: two fillers fit with no eviction, the third evicts exactly one')
        two = self.fill(2)
        p = self.pool_state('two more')
        assert_equal(p, after | set(two))
        for k in range(3):
            self.fill(1)
            p = self.pool_state('one more (round %d)' % (k + 1))
            assert_equal(len(p), SLOTS)
        print('the stock node drops S and C one block later (removeExpired at tip %d)' % (expiry + 1))
        self.raw_block()
        wait_for_mempool(stock, s_txid, present=False)
        wait_for_mempool(stock, c_txid, present=False)
        assert_equal(user.yed_getvault(self.v_txid)['status'], 'ACTIVE')

    # --- 1b. Yellowback transactions under eviction pressure ------------------------------

    def yed_under_pressure(self):
        nodes = self.nodes
        user, pool = nodes[USER], nodes[POOLS[0]]
        print('Yellowback transactions in a full mempool: a mint and a redemption with P-2 fees')
        p = self.pool_state('start')
        self.raw_block([self.hexes[t] for t in sorted(p)[:2]])     # room for the carrier, so the two-step is not starved
        self.pool_state('two slots free')

        built_at = user.getblockcount()
        res = user.yed_mint(CENTS, LOCK, '', '', False)
        carrier = res['carrierTxid']
        assert carrier in self.pool_state('carrier committed')
        _craw, c_exp = self.assert_expiry_floor(carrier, built_at, 'carrier')
        assert_equal(c_exp, int(res['refHeight']) + REF_WINDOW)
        self.raw_block([user.gettransaction(carrier)['hex']])
        mint_txid = wait_for_spender(user, carrier)
        mint_raw, m_exp = self.assert_expiry_floor(mint_txid, built_at + 1, 'mint')
        assert_equal(m_exp, int(res['refHeight']) + REF_WINDOW)

        built_at = user.getblockcount()
        red = user.yed_redeem(self.m1['txid'])
        red_raw, r_exp = self.assert_expiry_floor(red['txid'], built_at, 'redeem')
        assert_equal(r_exp, built_at + REF_WINDOW)               # spendRefHeight = the index tip
        yed = {'mint': (mint_txid, mint_raw), 'redeem': (red['txid'], red_raw)}

        for label, (txid, raw) in yed.items():
            print('  %-6s %s: %d in %d out, %d/%d Sapling, conventional fee %d zat, expiry %d' % (
                label, txid[:16], len(raw['vin']), len(raw['vout']), len(raw.get('vShieldedSpend', [])),
                len(raw.get('vShieldedOutput', [])), conventional_fee(raw), int(raw['expiryheight'])))
        # The eviction weight is cost + LOW_FEE_PENALTY iff fee < GetConventionalFee
        # (mempool_limit.cpp). The mempool computed the fee from the spent coins:
        state = self.pool_state('mint and redemption committed')
        verbose = user.getrawmempool(True)
        for label, (txid, raw) in yed.items():
            if txid in verbose:
                fee = int(Decimal(str(verbose[txid]['fee'])) * COIN)
                assert fee >= conventional_fee(raw), (label, fee, conventional_fee(raw))
                print('  %-6s mempool fee %d zat >= conventional %d: eviction weight = cost, no penalty' % (label, fee, conventional_fee(raw)))
        print('eviction rounds: each filler beyond the limit evicts exactly one transaction at random by weight')
        fate = {label: None for label in yed}
        for k in range(6):
            room = SLOTS - len(state)
            self.fill(room + 1)
            state = self.pool_state('round %d' % (k + 1))
            assert_equal(len(state), SLOTS)
            for label, (txid, _raw) in yed.items():
                if fate[label] is None and txid not in state:
                    fate[label] = k + 1
        for label, (txid, _raw) in yed.items():
            if fate[label] is None:
                print('  %s survived all six rounds' % label)
            else:
                print('  %s was evicted in round %d' % (label, fate[label]))
                assert debug_log_contains(self.options.tmpdir, USER, 'Evicting transaction (txid=%s' % txid)
                self.assert_evicted_refusal(user.gettransaction(txid)['hex'], label)
        self.yed_fate = fate

        print('both confirm through the pools whatever node 0 did (an evicted one is handed to a pool)')
        for label, (txid, _raw) in yed.items():
            if txid in pool.getrawmempool():
                print('  %s: already in pool %d\'s mempool (relayed before any eviction)' % (label, POOLS[0]))
                continue
            try:
                pool.sendrawtransaction(user.gettransaction(txid)['hex'])
            except JSONRPCException as e:
                raise AssertionError('%s refused by the pool: %s' % (label, e.error))
            print('  %s: not in pool %d\'s mempool; handed to it and admitted' % (label, POOLS[0]))
        self.raw_block([user.gettransaction(t)['hex'] for t, _r in yed.values()])
        assert_equal(user.yed_getvault(mint_txid)['status'], 'ACTIVE')
        assert_equal(user.yed_getvault(self.m1['txid'])['status'], 'CLOSED')
        self.pool_state('after the block')

    # --- 2b. the builders at the REF_WINDOW boundary --------------------------------------

    def builders_at_the_boundary(self):
        nodes = self.nodes
        print('clear: node 0 without the limit, every mempool mined')
        self.limits = False
        self.mint_lag = MAX_REF_LAG
        user = self.restart(USER)
        sync_blocks(nodes)
        wait_yed_healthy(user)
        # node 0's wallet re-accepted the fillers it had lost to eviction, which its peers may
        # not hold, so the mempools need not converge: mine each node's own mempool
        for _ in range(4):
            busy = [i for i, node in enumerate(nodes) if node.getrawmempool()]
            if not busy:
                break
            nodes[busy[0]].generate(1)
            sync_blocks(nodes)
        for node in nodes:
            assert_equal(len(node.getrawmempool()), 0)

        print('-yellowbackmintlag=%d: the carrier\'s R + REF_WINDOW is next height + 3' % MAX_REF_LAG)
        built_at = user.getblockcount()
        res = user.yed_mint(CENTS, LOCK, '', '', False)
        assert_equal(int(res['refHeight']), built_at - MAX_REF_LAG)
        carrier = res['carrierTxid']
        _r, c_exp = self.assert_expiry_floor(carrier, built_at, 'carrier at lag 36')
        assert_equal(c_exp, built_at + 1 + TX_EXPIRING_SOON_THRESHOLD)     # the carrier itself sits on the boundary
        self.raw_block([user.gettransaction(carrier)['hex']])
        deadline = time.time() + 30
        while not debug_log_contains(self.options.tmpdir, USER, 'expiring-too-soon'):
            assert time.time() < deadline, 'the pending mint at lag 36 neither completed nor refused'
            for t in user.getrawmempool():
                assert carrier not in [v.get('txid') for v in user.getrawtransaction(t, 1)['vin']], \
                    'the builder produced a mint at lag 36 (expiry %d, next height %d)' % (c_exp, user.getblockcount() + 1)
            time.sleep(0.5)
        assert_equal(len(user.getrawmempool()), 0)
        print('  the completion refused with expiring-too-soon: the mint (expiry %d) would be inside the threshold at next height %d'
              % (c_exp, user.getblockcount() + 1))

        print('-yellowbackmintlag=%d: the mint lands exactly on the threshold and is admitted' % (MAX_REF_LAG - 1))
        self.mint_lag = MAX_REF_LAG - 1
        user = self.restart(USER)
        sync_blocks(nodes)
        wait_yed_healthy(user)
        built_at = user.getblockcount()
        res = user.yed_mint(CENTS, LOCK, '', '', False)
        carrier = res['carrierTxid']
        self.raw_block([user.gettransaction(carrier)['hex']])
        mint_txid = wait_for_spender(user, carrier)
        _r, m_exp = self.assert_expiry_floor(mint_txid, built_at + 1, 'mint at lag 35')
        assert_equal(m_exp, user.getblockcount() + 1 + TX_EXPIRING_SOON_THRESHOLD)
        print('  mint %s: expiry %d = next height %d + %d' % (mint_txid[:16], m_exp, user.getblockcount() + 1, TX_EXPIRING_SOON_THRESHOLD))
        self.raw_block([user.gettransaction(mint_txid)['hex']])
        assert_equal(user.yed_getvault(mint_txid)['status'], 'ACTIVE')

        self.mint_lag = None
        self.restart(USER)
        sync_blocks(nodes)
        wait_yed_healthy(self.nodes[USER])

    def run_test(self):
        self.hexes = {}
        self.evicted_refusal = None
        self.prepare()
        self.expiring_soon_raw()
        self.sweep_at_cost_limit()
        self.yed_under_pressure()
        self.builders_at_the_boundary()
        self.sync_all()
        self.mine(POOLS[2])
        self.checkpoint('mempool limits')


if __name__ == '__main__':
    YellowbackMempoolLimitsTest().main()
