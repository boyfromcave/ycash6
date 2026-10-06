#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The Phase 6 demonstration of the ycashd 6.20.0 port (docs/plans/yellowback-ycash6-plan.md section 4,
"Success criteria"): one run that walks the section 4 checklist in order and prints a transcript
line per checkbox with its evidence (heights, txids, verdicts, state hashes).

It does not use the devnet launcher: it is the YellowbackTestFramework's standard eight-node
topology -- 0 user (enforcing wallet), 1 STOCK (the stock 6.20.0 binary from --stock-binary /
$REF_YCASHD, no -yellowback; without it the fork binary without the flag), 2-4 pools, 5 observer
(-yellowbackenforce=0), 6-7 attestor wallets -- and every step is one the per-rule scripts
already prove (yellowback_activation, _pricefeed, _lifecycle, _claim, _void_mint, _attest,
_attest_enforcement, _enforcement, _index, _stockparity); this script strings them together
on one chain.

  1  every node starts with -yellowback, index synced, yed_getinfo rpcversion 3 healthy
  2  pools tag quotes; yed_getprice median; forged tags from a non-pool change nothing
  3  signalling -> locked_in -> active at the plan's heights; the sunset (-yellowbackenforceuntil)
  4  mint, send, redeem, claim, sweep, VOID release from wallet RPCs and raw builders; the model
  5  attestors register (UNARMED -> TRIGGERED -> ARMED); bundles carried; bad bundles refused
  6  the stock node mines an unburned vault spend: rejected at DoS 0, BLK-2 descendants, no ban
  7  a 2-block and a 10-block reorg with equal state hashes; restart and -reindex
  8  (pointer) the 30-minute persona economy is yellowback_devnet_roles.py
  9  stock parity spot check (the full 300 blocks is yellowback_stockparity.py)
 10  (pointer) the CI gates

Runtime: about 15-25 minutes.
"""

import time

from test_framework.authproxy import JSONRPCException
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    connect_nodes_bi,
    hex_str_to_bytes,
    p2p_port,
    sync_blocks,
    sync_mempools,
)
from test_framework import yellowback_model as ym
from test_framework.yellowback_attest import (
    ArmedModeMixin,
    build_carrier_tx,
    build_mint_tx_v3,
    encode_bundle,
    has_rpc,
    hot_secret_for,
    register_and_arm,
    select_attestors,
    selection_pool,
    sign_attestation,
)
from test_framework.yellowback_util import (
    ACTIVATION_DELAY,
    ATTEST_ARM_DELAY,
    ATTEST_FEE_BPS,
    ATTEST_MAX_AGE,
    ATTESTOR_A,
    ATTESTOR_B,
    BPS,
    ENFORCING_V3,
    OBSERVER,
    PEER_LAG,
    POOLS,
    REF_LAG,
    STOCK,
    USER,
    VALVE_BLOCKS,
    YellowbackTestFramework,
    _statehash,
    assert_banscore_zero,
    assert_best_hash,
    assert_same_statehash,
    build_mint_tx,
    build_vault_spend_raw,
    fee_zat,
    mine_block_raw,
    pubkey_to_address,
    redeem_vault_raw,
    restart_with_yellowback,
    template_coinbase,
    usd_to_micro,
    wait_for_rejection,
    wait_yed_healthy,
)

PRICE = 50                   # USD per YEC: class A collateral (500 % of $100) is 10 YEC
CRASH = 1                    # the claim's crash: 10 YEC at $1 backs $10 of a $100 debt
CENTS = 10_000               # $100, the class-A minimum
LOCK = 48                    # class A minimum lock
SWEEP_ACK = 'I understand this leaves YED unbacked'
OVERLAY = [0, 2, 3, 4, 5, 6, 7]


def rpc_error(substr, fn, *args):
    try:
        fn(*args)
    except JSONRPCException as e:
        msg = e.error['message']
        assert substr in msg, 'expected %r in %r' % (substr, msg)
        return msg
    raise AssertionError('expected an RPC error containing %r' % substr)


def short(h):
    return (h or '-')[:16]


def overlay_off(node):
    """How ``node`` shows it runs no overlay: the stock binary has no ``yed_*`` commands at all; the
    fork binary without -yellowback registers them and refuses every call.  Returns the evidence."""
    if not has_rpc(node, 'yed_getinfo'):
        return 'no yed_* RPCs (help yed_getinfo: unknown command)'
    try:
        node.yed_getinfo()
    except JSONRPCException as e:
        return 'yed_getinfo refuses: %s' % e.error['message']
    raise AssertionError('the node answers yed_getinfo: it runs the overlay')


class _ParityPair(object):
    """The two nodes ``YellowbackStockParityTest.compare`` reads (``nodes[0]`` the stock binary,
    ``nodes[1]`` the fork without -yellowback) -- so the spot check uses that script's comparison
    verbatim instead of a copy."""

    def __init__(self, stock, fork):
        self.nodes = [stock, fork]
        self.steps = 0


class YellowbackDemoV6(ArmedModeMixin, YellowbackTestFramework):
    # The attestor wallets join the enforcing half directly, and {0, 2, 3, 4} is a complete graph
    # (yellowback_enforcement.py): pool restarts and an isolated stock branch never cut the
    # enforcing nodes off from each other.
    EDGES = YellowbackTestFramework.EDGES + [(2, 4), (0, 3), (0, 4), (0, 6), (0, 7)]
    initial_blocks = 101

    def __init__(self):
        super().__init__(num_nodes=8)
        self._armed = False
        self.t0 = time.time()
        self.results = []

    @property
    def armed(self):
        """ArmedModeMixin's switch: off until item 5 arms the chain (not the --armed option)."""
        return self._armed

    def add_options(self, parser):
        super().add_options(parser)
        parser.add_option('--items', dest='items', default=None,
                          help='comma-separated item numbers to run (development; 5-6 need 4, 9 runs alone)')

    def node_args(self, i, extra=None):
        return super().node_args(i, ['-debug=yellowback'] + list(extra or []))

    # ------------------------------------------------------------------ transcript

    def say(self, item, msg):
        print('[%6.0fs] [%s] %s' % (time.time() - self.t0, item, msg), flush=True)

    def passed(self, item, title, evidence):
        self.results.append((item, 'PASS', title, evidence))
        self.say(item, 'PASS -- %s :: %s' % (title, evidence))

    def tip(self, i=USER):
        return self.nodes[i].getblockcount()

    def overlay_nodes(self):
        return [self.nodes[i] for i in OVERLAY if self.nodes[i] is not None]

    def hashes(self, label, nodes=None):
        """Equal state hashes over the enforcing nodes and the observer (when on their chain);
        returns the hash."""
        self.sync_all(blocks_only=True)
        nodes = self.overlay_nodes() if nodes is None else nodes
        assert_best_hash(nodes, label)
        return assert_same_statehash(nodes, label)

    # ------------------------------------------------------------------ helpers copied from yellowback_enforcement.py

    def reset_peer_scores(self):
        """Drop and re-make every live edge: ``banscore`` is per connection and never decays, and
        6.20.0's stock code scores reorg noise (tx-expired, bad-prevblk) that is not a Yellowback
        verdict -- so the DoS-0 assertions that follow measure Yellowback alone
        (yellowback_enforcement.py reset_peer_scores)."""
        cross = self._cross_edges() if self.is_network_split else []
        edges = [(a, b) for a, b in self.live_edges() if (a, b) not in cross
                 and self.nodes[a] is not None and self.nodes[b] is not None]
        for a, b in edges:
            self._disconnect_pair(a, b)
        time.sleep(1.5)
        for a, b in edges:
            connect_nodes_bi(self.nodes, a, b)
        time.sleep(2)
        assert_banscore_zero([n for n in self.nodes if n is not None])

    def assert_peers_with_stock(self, i):
        addr = '127.0.0.1:%d' % p2p_port(STOCK)
        assert any(p['addr'] == addr for p in self.nodes[i].getpeerinfo()), 'node %d lost node 1 as a peer (N1)' % i

    def stock_block_with(self, hex_):
        stock = self.nodes[STOCK]
        txid = stock.sendrawtransaction(hex_)
        blockhash = stock.generate(1)[0]
        assert txid in stock.getblock(blockhash)['tx']
        return blockhash, txid

    def assert_rejected_everywhere(self, blockhash):
        """Every enforcing node (6-7 included) rejected ``blockhash`` at DoS 0, still peers with
        node 1, and names a reason (``yed_getblockverdict``).  Returns {node: reason}."""
        wait_for_rejection([self.nodes[i] for i in ENFORCING_V3], blockhash)
        assert_banscore_zero([self.nodes[i] for i in ENFORCING_V3])
        reasons = {}
        for i in ENFORCING_V3:
            verdict = self.nodes[i].yed_getblockverdict(blockhash)
            assert_equal(verdict['blockInvalid'], True)
            reasons[i] = verdict['reason']
            self.assert_peers_with_stock(i)
        return reasons

    def pools_outmine(self, limit=40):
        """Pools mine until node 1 (and with it node 5) is on the pools' chain."""
        k = 0
        while self.nodes[STOCK].getbestblockhash() != self.nodes[POOLS[0]].getbestblockhash():
            assert k < limit, 'the pools did not out-mine the stock branch in %d blocks' % limit
            self.nodes[POOLS[k % len(POOLS)]].generate(1)
            sync_blocks([self.nodes[i] for i in ENFORCING_V3])
            k += 1
            time.sleep(0.3)
        self.sync_all(blocks_only=True)
        return k

    def clear_stock_mempool(self):
        """6.20.0 does not persist the mempool: restart node 1 so a reorged-out rule-breaking spend
        (expiry 0, never expires) cannot ride along in its next block."""
        if self.nodes[STOCK].getrawmempool():
            self.restart(STOCK)
            time.sleep(1)

    def quote_all(self, usd):
        for i in POOLS:
            self.quote(i, usd)

    def mine_until(self, cond, limit, what, pools=None):
        """Round-robin pool blocks until ``cond()``; returns the number mined."""
        pools = POOLS if pools is None else pools
        k = 0
        while not cond():
            assert k < limit, '%s not reached within %d blocks' % (what, limit)
            self.nodes[pools[k % len(pools)]].generate(1)
            self.sync_all(blocks_only=True)
            k += 1
        return k

    def coins_for(self, node, cents):
        """Confirmed YED outpoints of ``node`` worth at least ``cents`` (largest first)."""
        coins = sorted([c for c in node.yed_listunspent() if not c.get('spentUnconfirmed')],
                       key=lambda c: -c['cents'])
        picked, total = [], 0
        for c in coins:
            picked.append((c['txid'], c['vout']))
            total += c['cents']
            if total >= cents:
                return picked, total
        raise AssertionError('node holds %d cents, needs %d' % (total, cents))

    def live_vault(self, txid, node=None):
        node = node or self.nodes[USER]
        v = dict(node.yed_getvault(txid))
        v['ownerAddress'] = pubkey_to_address(hex_str_to_bytes(v['ownerPubKey']))
        return v

    # ------------------------------------------------------------------ run

    def run_test(self):
        stock_bin = self.stock_binary()
        print('=' * 100)
        print('Yellowback on ycashd 6.20.0 -- the plan section 4 demonstration (yellowback_demo_v6.py)')
        print('node 1 binary: %s' % (stock_bin or 'the fork binary WITHOUT -yellowback (no --stock-binary / REF_YCASHD given)'))
        print('=' * 100)
        steps = [self.item1_startup, self.item2_tags_and_price, self.item3_activation, self.item4_wallet_lifecycle,
                 self.item5_attestation, self.item6_stock_miner, self.item7_reorgs_and_rebuilds, self.item8_pointer,
                 self.item9_parity_spot_check, self.item10_pointer]
        wanted = set(int(x) for x in self.options.items.split(',')) if self.options.items else None
        for n, step in enumerate(steps, 1):
            if wanted is None or n in wanted:
                step()
        print('=' * 100)
        print('SUMMARY (%d blocks, %.0f s)' % (self.tip(), time.time() - self.t0))
        for item, status, title, evidence in self.results:
            print('  [%s] %-8s %s' % (item, status, title))
        print('=' * 100)

    # ------------------------------------------------------------------ 1

    def item1_startup(self):
        item = '1'
        self.say(item, 'every node starts from genesis; node 0 mined %d blocks before the run' % self.initial_blocks)
        rows = []
        for i in OVERLAY:
            info = wait_yed_healthy(self.nodes[i], timeout=60)
            assert_equal(info['rpcversion'], 4)
            assert_equal(info['healthy'], True)
            assert_equal(info['height'], self.nodes[i].getblockcount())
            role = {0: 'user', 2: 'pool', 3: 'pool', 4: 'pool', 5: 'observer', 6: 'attestor wallet', 7: 'attestor wallet'}[i]
            self.say(item, 'node %d (%s): rpcversion %d healthy %s index height %d enforcing %s statehash %s'
                     % (i, role, info['rpcversion'], info['healthy'], info['height'], info['enforcing'],
                        short(_statehash(self.nodes[i]))))
            rows.append(info['height'])
        h = assert_same_statehash(self.overlay_nodes(), 'start')
        stock = self.nodes[STOCK]
        off = overlay_off(stock)
        sub = stock.getnetworkinfo()['subversion']
        self.say(item, 'node 1 (stock): %s, height %d, %s' % (sub, stock.getblockcount(), off))
        self.passed(item, 'every node starts with -yellowback, syncs the index, rpcversion 3 healthy',
                    '7 overlay nodes at height %d, one state hash %s; node 1 stock (%s)' % (rows[0], short(h), sub))

    # ------------------------------------------------------------------ 2

    def item2_tags_and_price(self):
        item = '2'
        user, stock = self.nodes[USER], self.nodes[STOCK]
        self.quote_all(PRICE)
        self.say(item, 'pools 2-4 quote $%d (yed_setquote) and mine 12 blocks round robin' % PRICE)
        self.mine_round_robin(POOLS, 12)
        for h in range(self.tip() - 2, self.tip() + 1):
            tag = user.yed_gettag(str(h))
            assert_equal((tag['found'], tag['kind'], tag['priceMicroUsd'], tag['signal']), (True, 'quote', usd_to_micro(PRICE), True))
            assert tag['payoutAddress'] in self.pool_addresses
            self.say(item, 'height %d: tag kind=%s price=%d signal=%s payout=%s'
                     % (h, tag['kind'], tag['priceMicroUsd'], tag['signal'], tag['payoutAddress']))
        p = user.yed_getprice()
        assert_equal(p['pFast'], usd_to_micro(PRICE))
        self.say(item, 'yed_getprice at %d: pFast=%s pMid=%s pSlow=%s (mid/slow fill later)' % (p['height'], p['pFast'], p['pMid'], p['pSlow']))

        # a forged quote tag from the stock node (not a pool, no module): recorded, judged, outvoted
        forged_key = ym.address_key_hash(stock.getnewaddress())
        cb, gbt = template_coinbase(stock)
        cb.vin[0].scriptSig = ym.height_prefix(gbt['height']) + ym.tag_push(0, usd_to_micro(2 * PRICE), 1, forged_key)
        result, forged_hash = mine_block_raw(stock, [], coinbase=cb, gbt=gbt)
        assert result is None, result
        self.sync_all(blocks_only=True)
        forged_h = self.tip()
        tag = user.yed_gettag(str(forged_h))
        assert_equal((tag['found'], tag['kind'], tag['priceMicroUsd']), (True, 'quote', usd_to_micro(2 * PRICE)))
        forged_addr = tag['payoutAddress']
        p = user.yed_getprice()
        assert_equal(p['pFast'], usd_to_micro(PRICE))
        self.say(item, 'node 1 mined %s at %d with a forged quote tag $%d for %s: decoded, pFast still %d (lower median of 8)'
                 % (short(forged_hash), forged_h, 2 * PRICE, forged_addr, p['pFast']))
        # a malformed tag (reserved flag bit set, TAG-2): no tag at all, and the block is valid (TAG-4)
        cb, gbt = template_coinbase(stock)
        cb.vin[0].scriptSig = ym.height_prefix(gbt['height']) + ym.tag_push(0x02, usd_to_micro(2 * PRICE), 1, forged_key)
        result, bad_hash = mine_block_raw(stock, [], coinbase=cb, gbt=gbt)
        assert result is None, result
        self.sync_all(blocks_only=True)
        assert_equal(user.yed_gettag(str(self.tip()))['found'], False)
        assert_equal(user.getbestblockhash(), bad_hash)
        self.say(item, 'node 1 mined %s at %d with a malformed tag (flags 0x02): yed_gettag found=false, block valid everywhere'
                 % (short(bad_hash), self.tip()))
        # REG-4 judges the forged quote PEER_LAG blocks later: deviation > DEVIATION_BPS => penalised
        self.mine_round_robin(POOLS, PEER_LAG + 2)
        rows = {r['payoutAddress']: r for r in user.yed_listminers(self.tip(), 64)}
        f = rows[forged_addr]
        assert_greater_than(f['penalizedUntil'], self.tip() - 1)
        for a in self.pool_addresses:
            assert_equal(rows[a]['penalizedUntil'], 0)
        p = user.yed_getprice()
        assert_equal(p['pFast'], usd_to_micro(PRICE))
        for node in self.overlay_nodes():
            assert_equal(node.yed_getinfo()['rejectedBlocks'], 0)
        h = self.hashes('item 2')
        self.passed(item, 'pools tag quotes; yed_getprice median; a forged tag from a non-pool is outvoted',
                    'pFast %d at %d; forged $%d tag at %d penalised until %d (REG-4), price unmoved; malformed tag ignored; statehash %s'
                    % (p['pFast'], self.tip(), 2 * PRICE, forged_h, f['penalizedUntil'], short(h)))

    # ------------------------------------------------------------------ 3

    def item3_activation(self):
        item = '3'
        user = self.nodes[USER]
        a = self.nodes[2].yed_getactivation()
        self.say(item, 'at %d: status=%s signalCount=%d (window %d, threshold %d)' % (self.tip(), a['status'], a['signalCount'], a['window'], a['threshold']))
        last = a['status']
        transitions = []
        k = 0
        while last != 'active':
            assert k < 200, 'no activation within 200 blocks'
            self.nodes[POOLS[k % 3]].generate(1)
            self.sync_all(blocks_only=True)
            k += 1
            a = self.nodes[2].yed_getactivation()
            if a['status'] != last:
                transitions.append((self.tip(), last, a['status'], a['signalCount']))
                self.say(item, 'height %d: %s -> %s (signalCount %d, lockInHeight %d, activateHeight %d)'
                         % (self.tip(), last, a['status'], a['signalCount'], a['lockInHeight'], a['activateHeight']))
                last = a['status']
        a = self.nodes[2].yed_getactivation()
        assert_equal([t[2] for t in transitions], ['locked_in', 'active'])
        assert_equal(a['activateHeight'], a['lockInHeight'] + ACTIVATION_DELAY)
        assert_equal(transitions[0][0], a['lockInHeight'])
        assert_equal(transitions[1][0], a['activateHeight'])
        for node in self.overlay_nodes():
            b = node.yed_getactivation()
            assert_equal((b['status'], b['lockInHeight'], b['activateHeight']), ('active', a['lockInHeight'], a['activateHeight']))
        self.mine_round_robin(POOLS, REF_LAG + 1)
        for i in ENFORCING_V3:
            info = self.nodes[i].yed_getinfo()
            assert_equal((info['enforcing'], info['sunset']), (True, False))
        assert_equal(user.yed_getstats()['mintingAllowed'], True)
        self.say(item, 'every overlay node: active, lock-in %d, activate %d = lock-in + %d; minting open at %d'
                 % (a['lockInHeight'], a['activateHeight'], ACTIVATION_DELAY, self.tip()))

        # the sunset: -yellowbackenforceuntil in the past ends enforcement and the signal bit on node 4
        until = self.tip() - 1
        self.restart(4, ['-yellowbackenforceuntil=%d' % until])
        info = wait_yed_healthy(self.nodes[4], timeout=120)
        act = self.nodes[4].yed_getactivation()
        assert_equal((info['sunset'], info['enforcing'], info['miner']['signal'], act['enforceUntilHeight']), (True, False, False, until))
        self.nodes[4].generate(1)
        self.sync_all(blocks_only=True)
        tag = user.yed_gettag(str(self.tip()))
        assert_equal((tag['found'], tag['kind'], tag['signal']), (True, 'quote', False))
        self.say(item, 'node 4 restarted with -yellowbackenforceuntil=%d: sunset=true enforcing=false; its block %d tags a quote without the signal bit'
                 % (until, self.tip()))
        self.restart(4)
        info = wait_yed_healthy(self.nodes[4], timeout=120)
        assert_equal((info['sunset'], info['enforcing'], info['miner']['signal']), (False, True, True))
        h = self.hashes('item 3')
        self.say(item, 'node 4 restarted without it: sunset=false enforcing=true signal=true; state hashes equal again')
        # fund the observer (the claimant of item 4) and give the user's coinbases time to mature
        user.sendtoaddress(self.nodes[OBSERVER].getnewaddress(), 5)
        self.sync_all()
        self.mine(POOLS[0])
        self.passed(item, 'signalling -> locked_in -> active at the plan heights; the sunset behaves',
                    'locked_in at %d, active at %d (+%d); node 4 sunset at -yellowbackenforceuntil=%d and back; statehash %s'
                    % (a['lockInHeight'], a['activateHeight'], ACTIVATION_DELAY, until, short(h)))

    # ------------------------------------------------------------------ 4

    def item4_wallet_lifecycle(self):
        item = '4'
        nodes = self.nodes
        user, observer = nodes[USER], nodes[OBSERVER]
        self.say(item, 'wallet mints (yed_mint, two steps: carrier then mint): A redeem, B claim, C sweep, E/F kept for items 5-6')
        mints = {}
        for name in ('A', 'B', 'C', 'E', 'F'):
            mints[name] = self.mint(user, CENTS, LOCK)
            self.say(item, 'yed_mint %s: txid %s class %s collateral %d zat fee %d to %s lock %d claim %d'
                     % (name, mints[name]['txid'], mints[name]['termClass'], mints[name]['collateralZat'],
                        mints[name]['feeZat'], mints[name]['payee'], mints[name]['lockHeight'], mints[name]['claimHeight']))
        self.sync_all()
        self.mine(POOLS[1])
        for name, m in mints.items():
            assert_equal(user.yed_getvault(m['txid'])['status'], 'ACTIVE')
        # the raw builders: D an ACTIVE mint, Z under-collateralised (VOID, MINT-5) -- no template carries Z (TPL-2)
        est = user.yed_estimatecollateral(CENTS, LOCK)
        ref = int(est['refHeight'])
        payee = user.yed_getfeepayee(ref, int(est['requiredZat']))['default']['payoutAddress']
        d_hex, _ = build_mint_tx(user, CENTS, LOCK, ref, int(est['requiredZat']), fee_addr=payee)
        d_txid = user.sendrawtransaction(d_hex)
        # listunspent(1) does not see the mempool: lock D's inputs so Z cannot reuse them
        user.lockunspent(False, [{'txid': i.prev_txid, 'vout': i.prev_n} for i in ym.tx_from_hex(d_hex).vin])
        z_hex, _ =build_mint_tx(user, CENTS, LOCK, ref, int(est['requiredZat']) - 1000, fee_addr=payee)
        z_txid = user.decoderawtransaction(z_hex)['txid']
        z_check = nodes[2].yed_validaterawtransaction(z_hex)
        self.sync_all()
        self.mine(POOLS[2])
        result, z_block = mine_block_raw(nodes[POOLS[0]], [z_hex])
        assert result is None, result
        self.sync_all(blocks_only=True)
        assert_equal(user.yed_getvault(d_txid)['status'], 'ACTIVE')
        z = user.yed_getvault(z_txid)
        assert_equal(z['status'], 'VOID')
        self.say(item, 'raw build_mint_tx D: %s ACTIVE; raw Z (1000 zat short): verdict %s, mined in a hand-built block %s: VOID (%s)'
                 % (d_txid, z_check['verdict'], short(z_block), z['voidReason']))
        assert_equal(nodes[2].yed_getstats()['supplyCents'], 6 * CENTS)

        sent = user.yed_send(observer.yed_getnewaddress(), CENTS + 100)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(observer.yed_getbalance()['confirmedCents'], CENTS + 100)
        self.say(item, 'yed_send %d cents user -> observer: %s (change %d)' % (CENTS + 100, sent['txid'], sent['changeCents']))

        # past the locks: yed_redeem A (owner path, burn + fee), raw redemption of D, VOID release of Z
        lock = max(mints['A']['lockHeight'], z['lockHeight'], user.yed_getvault(d_txid)['lockHeight'])
        self.mine_round_robin(POOLS, max(0, lock - self.tip()))
        rpc_error('sweep-not-abandoned', user.yed_sweep, mints['C']['txid'], SWEEP_ACK)
        red = user.yed_redeem(mints['A']['txid'])
        assert_equal(red['burnedCents'], CENTS)
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(nodes[2].yed_getvault(mints['A']['txid'])['status'], 'CLOSED')
        self.say(item, 'yed_redeem A: %s burned %d, fee %d to %s, collateral %d back' % (red['txid'], red['burnedCents'], red['feeZat'], red['payee'], red['collateralOut']))
        burn, _total = self.coins_for(user, CENTS)
        d_red = redeem_vault_raw(self, user, POOLS[2], self.live_vault(d_txid), burn)
        assert_equal(nodes[2].yed_getvault(d_txid)['status'], 'CLOSED')
        self.say(item, 'raw owner-path redemption of D (build_vault_spend_raw, REDEEM payload, FEE-W payee): %s CLOSED' % d_red)
        rel = user.yed_redeem(z_txid)
        assert_equal((rel['burnedCents'], rel['feeZat'], rel['payee']), (0, 0, None))
        self.sync_all()
        self.mine(POOLS[0])
        zc = nodes[2].yed_getvault(z_txid)
        assert_equal((zc['status'], zc['unbacked']), ('CLOSED', False))
        self.say(item, 'VOID release of Z with yed_redeem: %s, no burn, no fee, %d zat back' % (rel['txid'], rel['collateralOut']))

        # the claim: every pool quotes $1 until B is underwater past its claimHeight
        self.say(item, 'crash: every pool quotes $%d until B is claimable (pClaim = max(pMid, pSlow))' % CRASH)
        self.quote_all(CRASH)
        b_vault = mints['B']['txid'] + ':0'
        n = self.mine_until(lambda: self.tip() >= mints['B']['claimHeight']
                            and b_vault in [c['vault'] for c in user.yed_listclaimable()], 100, 'B claimable')
        p = user.yed_getprice()
        self.say(item, '%d crash blocks: pClaim %s at %d, B claimable' % (n, p['pClaim'], self.tip()))
        supply = nodes[2].yed_getstats()['supplyCents']
        claimed = self.claim(observer, mints['B']['txid'])
        self.sync_all()
        self.mine(POOLS[2])
        for node in self.overlay_nodes():
            c = node.yed_getvault(mints['B']['txid'])
            assert_equal((c['status'], c['burnedCents'], c['unbacked']), ('CLAIMED', CENTS, False))
        assert_equal(nodes[2].yed_getstats()['supplyCents'], supply - CENTS)
        self.say(item, 'yed_claim B by the observer: %s burned %d, collateral %d to the claimant, fee %d to %s'
                 % (claimed['txid'], claimed['burnedCents'], claimed['collateralOut'], claimed['feeZat'], claimed['payee']))
        self.quote_all(PRICE)
        n = self.mine_until(lambda: user.yed_getstats()['mintingAllowed'] and user.yed_listclaimable() == [], 120, 'price recovery')
        self.say(item, 'pools back at $%d: %d blocks to re-open minting (no halt, nothing claimable)' % (PRICE, n))

        # the sweep: only under abandonment (L10) -- the pools stop signalling for ABANDON_BLOCKS
        self.say(item, 'the pools restart with -yellowbacksignal=0; the sweep waits for abandonment (L10)')
        for i in POOLS:
            self.restart(i, ['-yellowbacksignal=0'])
        n1 = self.mine_until(lambda: user.yed_getactivation()['enforcementSuspended'], 80, 'enforcement suspended')
        rpc_error('sweep-not-abandoned', user.yed_sweep, mints['C']['txid'], SWEEP_ACK)
        n2 = self.mine_until(lambda: all(nd.yed_getinfo()['abandoned'] for nd in self.overlay_nodes()), 160, 'abandonment')
        self.say(item, 'suspended after %d blocks, abandoned %d blocks later (height %d); sweep refused before that' % (n1, n2, self.tip()))
        unbacked = nodes[2].yed_getstats()['unbackedCents']
        swept = user.yed_sweep(mints['C']['txid'], SWEEP_ACK)
        self.sync_all()
        assert swept['txid'] in [t['hash'] for t in nodes[2].getblocktemplate()['transactions']]
        self.mine(POOLS[0])
        for node in self.overlay_nodes():
            c = node.yed_getvault(mints['C']['txid'])
            assert_equal((c['status'], c['unbacked'], c['closingTxid']), ('CLOSED', True, swept['txid']))
        assert_equal(nodes[2].yed_getstats()['unbackedCents'], unbacked + CENTS)
        self.say(item, 'yed_sweep C: %s, %d zat back, %d cents now unbacked' % (swept['txid'], swept['collateralOut'], swept['unbackedCents']))
        for i in POOLS:
            self.restart(i)
        n = self.mine_until(lambda: not user.yed_getactivation()['enforcementSuspended'] and not user.yed_getinfo()['abandoned']
                            and user.yed_getstats()['mintingAllowed'], 120, 'enforcement resumed')
        for i in ENFORCING_V3:
            assert_equal(self.nodes[i].yed_getinfo()['enforcing'], True)
        self.say(item, 'signalling resumed: enforcement back and minting open after %d blocks (height %d)' % (n, self.tip()))

        # the Python model over the whole chain, and the wallets against the supply
        model2 = self.model_check(nodes[2])
        self.model_check(observer)
        self.model_check(user)
        stats = nodes[2].yed_getstats()
        held = sum(self.nodes[i].yed_getbalance()['confirmedCents'] for i in (USER, OBSERVER, ATTESTOR_A, ATTESTOR_B))
        assert_equal(held, stats['supplyCents'])
        h = self.hashes('item 4')
        assert_equal(h, model2.state_hash())
        self.say(item, 'yellowback_model full=True on nodes 0, 2, 5: every tx, vault, stat and the state hash agree; '
                 'wallet balances sum %d = supplyCents %d; active %d void %d closed %d claimed %d unbacked %d'
                 % (held, stats['supplyCents'], stats['activeVaults'], stats['voidVaults'], stats['closedVaults'],
                    stats['claimedVaults'], stats['unbackedCents']))
        self.mints = mints
        self.passed(item, 'mint, send, redeem, claim, sweep, VOID release from the wallet RPCs and the raw builders; the model agrees',
                    'redeem %s, raw redeem %s, claim %s, sweep %s, release %s; model statehash %s'
                    % (short(red['txid']), short(d_red), short(claimed['txid']), short(swept['txid']), short(rel['txid']), short(h)))

    # ------------------------------------------------------------------ 5

    def item5_attestation(self):
        item = '5'
        nodes = self.nodes
        user = nodes[USER]
        nodes[POOLS[0]].sendtoaddress(user.getnewaddress(), 80)     # five 10 YEC bonds and the carriers
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(user.yed_getinfo()['attest']['status'], 'UNARMED')
        self.say(item, 'UNARMED at %d; five attestors register (raw ATTESTOR_REGISTER, 10 YEC bonds, hot keys on nodes 6-7)' % self.tip())
        seqs = register_and_arm(self, 5)          # asserts TRIGGERED at the exact block and ARMED after the delay
        attest = user.yed_getinfo()['attest']
        assert_equal((attest['status'], attest['armHeight'], attest['triggerHeight'] + ATTEST_ARM_DELAY), ('ARMED', attest['armHeight'], attest['armHeight']))
        recs = {int(r['seq']): r for r in user.yed_listattestors()}
        self.say(item, 'seqs %s ELIGIBLE; TRIGGERED at %d, ARMED at %d (+%d) on every enforcing node; seated %d'
                 % (seqs, attest['triggerHeight'], attest['armHeight'], ATTEST_ARM_DELAY, attest['seatedCount']))
        self._armed = True

        # a bundle built and carried: yed_mint with the attestors' bundle in the carrier's scriptSig
        good = self.mint(user, CENTS, LOCK)
        self.sync_all()
        self.mine(POOLS[2])
        info = nodes[2].yed_gettxinfo(good['txid'])
        assert_equal((info['verdict'], info['bundleSource']), ('ok', 'scriptsig'))
        assert_greater_than(info['carrierVin'], -1)
        for node in self.overlay_nodes():
            assert_equal(node.yed_getvault(good['txid'])['status'], 'ACTIVE')
        self.say(item, 'armed yed_mint %s: carrier %s, bundle seqs %s, aMint %s xMint %s pMint %s, attestor fee %d to %s: ACTIVE everywhere'
                 % (good['txid'], good.get('carrierTxid'), info['bundleSeqs'], info['aMint'], info['xMint'], info['pMint'],
                    info['attestFeeZat'], info['attestPayee']))

        # a bad bundle on a mint: every attestation cites R - ATTEST_MAX_AGE (stale)
        ref = user.getblockcount() - REF_LAG
        cited = ref - ATTEST_MAX_AGE
        selected = sorted(select_attestors(user.getblockhash(ref), b'', selection_pool(user, ref)))
        stale = encode_bundle([sign_attestation(hot_secret_for(user, seq), seq, usd_to_micro(PRICE), cited, user.getblockhash(cited))
                               for seq in selected])
        est = user.yed_estimatecollateral(CENTS, LOCK, usd_to_micro(PRICE))
        required = int(est['requiredZat'])
        carrier = build_carrier_tx(user, stale)
        self.sync_all()
        self.mine(POOLS[0])
        payee = user.yed_getfeepayee(ref, required)['default']['payoutAddress']
        attest_fee = fee_zat(required) * ATTEST_FEE_BPS // BPS
        bad_hex, _ = build_mint_tx_v3(user, CENTS, LOCK, ref, required, fee_addr=payee, carrier=carrier,
                                      attest_fee=(recs[selected[0]]['bondKeyAddress'], attest_fee))
        bad_txid = user.decoderawtransaction(bad_hex)['txid']
        check = nodes[2].yed_validaterawtransaction(bad_hex)
        assert check['verdict'].startswith('mint9-bundle-stale'), check
        try:
            nodes[POOLS[1]].sendrawtransaction(bad_hex)
            in_pool = True
        except JSONRPCException as e:
            in_pool = False
            self.say(item, '  pool mempool refuses it: %s' % e.error['message'])
        if in_pool:
            tpl = [t['hash'] for t in nodes[POOLS[1]].getblocktemplate()['transactions']]
            assert bad_txid not in tpl, 'TPL-2: a VOID mint must not reach a pool template'
            nodes[POOLS[1]].generate(1)
            self.sync_all(blocks_only=True)
            assert bad_txid in nodes[POOLS[1]].getrawmempool()
        self.say(item, 'stale-bundle mint %s: verdict %s; in pool 3 mempool %s, absent from its template (TPL-2), its block %d left it out'
                 % (bad_txid, check['verdict'], in_pool, self.tip()))
        rejected_before = {i: nodes[i].yed_getinfo()['rejectedBlocks'] for i in ENFORCING_V3}
        blockhash, _ = self.stock_block_with(bad_hex)
        self.sync_all(blocks_only=True)
        for node in self.overlay_nodes():
            v = node.yed_getvault(bad_txid)
            assert_equal(v['status'], 'VOID')
            assert v['voidReason'].startswith('mint9-bundle-stale'), v['voidReason']
        for i in ENFORCING_V3:
            assert_equal(nodes[i].yed_getinfo()['rejectedBlocks'], rejected_before[i])
        assert_banscore_zero([n for n in nodes if n is not None])
        self.say(item, 'node 1 mined it in %s: every node records the vault VOID (%s) -- no YED issued, the block itself is valid (a mint verdict is VOID, not invalid)'
                 % (short(blockhash), user.yed_getvault(bad_txid)['voidReason']))

        # a bad bundle on a claim, once enforcing: E (healthy, past claimHeight) claimed with no bundle by node 1
        e_txid = self.mints['E']['txid']
        live = self.live_vault(e_txid)
        assert_greater_than(self.tip() + 1, int(live['claimHeight']))
        ref = self.tip() - REF_LAG
        fee = user.yed_getfeepayee(ref, int(live['collateralZat']))
        burn, _total = self.coins_for(user, CENTS)
        claim_hex = build_vault_spend_raw(user, live, 'claim', burn, payload=ym.encode_redeem(ref, 1, []),
                                          fee=(fee['default']['payoutAddress'], int(fee['feeZat'])), ref_height=ref, expiry=0)
        check = user.yed_validaterawtransaction(claim_hex)
        assert_equal((check['blockValid'], check['verdict'], check['wouldBeRejected']), (False, 'red1-bundle-shape', True))
        refusal = rpc_error('yellowback-vault-spend', user.sendrawtransaction, claim_hex)
        self.reset_peer_scores()
        blockhash, txid = self.stock_block_with(claim_hex)
        reasons = self.assert_rejected_everywhere(blockhash)
        for i, r in reasons.items():
            assert r.startswith('red1-bundle-shape'), 'node %d: %s' % (i, r)
        sync_blocks([nodes[STOCK], nodes[OBSERVER]], timeout=60)
        assert_equal(nodes[OBSERVER].getbestblockhash(), blockhash)
        self.say(item, 'bundle-less claim of E %s: MP-1 refused (%s); node 1 mined %s: rejected by nodes %s with %s at DoS 0; observer follows'
                 % (txid, refusal, short(blockhash), sorted(reasons), reasons[USER]))
        k = self.pools_outmine()
        for node in self.overlay_nodes():
            assert_equal(node.yed_getvault(e_txid)['status'], 'ACTIVE')
        assert_banscore_zero([n for n in nodes if n is not None])
        self.clear_stock_mempool()
        h = self.hashes('item 5')
        self.passed(item, 'attestors register, bundles carried; bad bundles refused at the template and at block validity, DoS 0',
                    'ARMED at %d; good mint %s; stale-bundle mint VOID %s; bundle-less claim block %s rejected (red1-bundle-shape), out-mined in %d; statehash %s'
                    % (attest['armHeight'], short(good['txid']), short(bad_txid), short(blockhash), k, short(h)))

    # ------------------------------------------------------------------ 6

    def item6_stock_miner(self):
        item = '6'
        nodes = self.nodes
        user = nodes[USER]
        f_txid = self.mints['F']['txid']
        live = self.live_vault(f_txid)
        bad = build_vault_spend_raw(user, live, 'owner', [], expiry=0)      # owner path, no burn, no payload
        check = user.yed_validaterawtransaction(bad)
        assert_equal(check['wouldBeRejected'], True)
        for i in ENFORCING_V3:
            rpc_error('yellowback-vault-spend', nodes[i].sendrawtransaction, bad)
        self.say(item, 'owner-path spend of F with no burn: verdict %s; every enforcing mempool refuses it (MP-1)' % check['verdict'])
        self.reset_peer_scores()
        rejected_before = {i: nodes[i].yed_getinfo()['rejectedBlocks'] for i in ENFORCING_V3}
        blockhash, txid = self.stock_block_with(bad)
        reasons = self.assert_rejected_everywhere(blockhash)
        for i in ENFORCING_V3:
            assert_equal(nodes[i].yed_getinfo()['rejectedBlocks'], rejected_before[i] + 1)
            assert_equal(nodes[i].yed_getinfo()['valveTripped'], False)
        sync_blocks([nodes[STOCK], nodes[OBSERVER]], timeout=60)
        obs = nodes[OBSERVER].yed_getvault(f_txid)
        assert_equal((obs['status'], obs['unbacked']), ('CLOSED', True))
        self.say(item, 'node 1 mined %s (tx %s) at %d: rejected by %s (%s); the observer follows it and records F unbacked'
                 % (short(blockhash), short(txid), nodes[STOCK].getblockcount(), sorted(reasons), reasons[USER]))
        # BLK-2's descendant clause: two more stock blocks on the rejected one, relayed, nobody scored
        desc = nodes[STOCK].generate(2)
        sync_blocks([nodes[STOCK], nodes[OBSERVER]], timeout=60)
        time.sleep(2)
        for i in ENFORCING_V3:
            self.assert_peers_with_stock(i)
            info = nodes[i].yed_getinfo()
            assert_equal((info['valveTripped'], info['enforcing']), (False, True))
            for d in desc:
                try:
                    assert_equal(nodes[i].getblock(d)['confirmations'], -1)
                except JSONRPCException:
                    pass          # a header-only descendant is not stored: refused at its header (bad-prevblk-yellowback)
        assert_banscore_zero([nodes[i] for i in ENFORCING_V3])
        self.say(item, 'node 1 mined 2 descendants %s: refused at DoS 0 (bad-prevblk-yellowback), banscore 0 on every connection, node 1 still a peer, valve not tripped (%d < %d)'
                 % ([short(d) for d in desc], 3, VALVE_BLOCKS))
        k = self.pools_outmine()
        assert_best_hash([n for n in nodes if n is not None], 'item 6')
        for node in self.overlay_nodes():
            assert_equal(node.yed_getvault(f_txid)['status'], 'ACTIVE')
        assert_banscore_zero([n for n in nodes if n is not None])
        self.clear_stock_mempool()
        h = self.hashes('item 6')
        self.passed(item, 'the stock node mines an unburned vault spend: rejected, not banned, the enforcing chain continues; BLK-2 holds',
                    'block %s rejected by 6 enforcing nodes, 2 descendants refused at DoS 0; pools out-mined in %d blocks, node 1 and 5 reorged back, F ACTIVE; statehash %s'
                    % (short(blockhash), k, short(h)))

    # ------------------------------------------------------------------ 7

    def reorg(self, depth, label):
        """Enforcing half mines ``depth`` blocks (a yed_send in the first), the stock half
        ``depth + 1``; the join reorgs every enforcing node ``depth`` blocks."""
        nodes = self.nodes
        user = nodes[USER]
        base = self.tip()
        self.split_network()
        send = user.yed_send(nodes[ATTESTOR_A].yed_getnewaddress(), 100)
        self.sync_all()
        losing = []
        for k in range(depth):
            losing.append(nodes[POOLS[k % 3]].generate(1)[0])
            self.sync_all(blocks_only=True)
        before = _statehash(user)
        nodes[STOCK].generate(depth + 1)
        self.sync_all(blocks_only=True)
        self.join_network()
        assert_equal(user.getbestblockhash(), nodes[STOCK].getbestblockhash())
        for b in losing:
            assert_equal(user.getblock(b)['confirmations'], -1)
        h_after = self.hashes('%s after the join' % label)
        assert send['txid'] in user.getrawmempool()
        sync_mempools([nodes[i] for i in ENFORCING_V3])
        self.mine(POOLS[0], blocks_only=True)
        assert_equal(user.yed_gettxinfo(send['txid'])['verdict'], 'ok')
        h_end = self.hashes('%s re-mined' % label)
        self.say('7', '%s: fork at %d, the enforcing branch (%d blocks, yed_send %s) replaced by node 1\'s %d; '
                 'state hash %s on every overlay node after the join (was %s on the losing branch); the send re-mined at %d, statehash %s'
                 % (label, base, depth, short(send['txid']), depth + 1, short(h_after), short(before), self.tip(), short(h_end)))
        return h_end

    def item7_reorgs_and_rebuilds(self):
        item = '7'
        nodes = self.nodes
        h2 = self.reorg(2, '2-block reorg')
        h10 = self.reorg(10, '10-block reorg')
        self.mine_round_robin(POOLS, 4)
        before = self.hashes('before the restarts')
        self.restart(3)
        wait_yed_healthy(nodes[3], timeout=120)
        self.sync_all(blocks_only=True)
        assert_equal(_statehash(nodes[3]), before)
        self.say(item, 'node 3 restarted: index tip %d, statehash %s' % (nodes[3].yed_getinfo()['height'], short(_statehash(nodes[3]))))
        self.restart(4, ['-reindex'])
        wait_yed_healthy(nodes[4], timeout=300)
        sync_blocks([nodes[2], nodes[4]], timeout=120)
        assert_equal(_statehash(nodes[4]), before)
        self.say(item, 'node 4 restarted with -reindex: blocks and index rebuilt from disk, statehash %s' % short(_statehash(nodes[4])))
        self.restart(OBSERVER)
        wait_yed_healthy(nodes[OBSERVER], timeout=120)
        self.sync_all(blocks_only=True)
        assert_equal(_statehash(nodes[OBSERVER]), before)
        self.mine_round_robin(POOLS, 2)
        h = self.hashes('item 7')
        self.passed(item, 'a 2-block and a 10-block reorg leave every state hash equal; restart and -reindex rebuild the same index',
                    '2-block %s, 10-block %s; restart (node 3, node 5) and -reindex (node 4) = %s; then %s at %d'
                    % (short(h2), short(h10), short(before), short(h), self.tip()))

    # ------------------------------------------------------------------ 8

    def item8_pointer(self):
        msg = ('the price walk and six yellowback-sim personas for 30 minutes on all three presets is '
               'qa/rpc-tests/yellowback_devnet_roles.py (devnet launcher, nightly) -- not run here')
        self.results.append(('8', 'POINTER', 'the 30-minute persona economy', msg))
        self.say('8', 'POINTER -- ' + msg)

    # ------------------------------------------------------------------ 9

    def item9_parity_spot_check(self):
        item = '9'
        from yellowback_stockparity import YellowbackStockParityTest
        nodes = self.nodes
        user, stock = nodes[USER], nodes[STOCK]
        user.sendtoaddress(stock.getnewaddress(), 5)
        self.sync_all()
        self.mine(POOLS[0])
        # node 5: the fork binary without the overlay.  Its datadir holds a Yellowback index, so the
        # node refuses to start without the explicit -yellowback=0 (the wallet may hold YED that a
        # plain start would treat as spendable YEC) -- the acknowledgement is part of the evidence.
        restart_with_yellowback(self, [OBSERVER], extra=['-yellowback=0'], yellowback_indices=[])
        fork = nodes[OBSERVER]
        self.say(item, 'node 5 restarted as the fork binary with -yellowback=0 (a plain start refuses: the datadir holds an index): %s'
                 % overlay_off(fork))
        sync_blocks([stock, fork])
        pair = _ParityPair(stock, fork)
        cmp = YellowbackStockParityTest.compare
        cmp(pair, 'start')
        span = 20
        for k in range(span):
            miner, other = (stock, fork) if k % 2 == 0 else (fork, stock)
            if k % 4 == 0 and stock.getbalance() > 1:
                stock.sendtoaddress(fork.getnewaddress(), 1.0)
                sync_mempools([stock, fork])
            miner.generate(1)
            sync_blocks([stock, fork])
            if k % 5 == 4:
                cmp(pair, 'block %d' % stock.getblockcount())
        self.sync_all(blocks_only=True)
        h = self.hashes('item 9', [nodes[i] for i in ENFORCING_V3])
        utxo = stock.gettxoutsetinfo()['hash_serialized']
        self.say(item, 'node 1 (%s) vs node 5 (fork binary, no -yellowback): %d blocks alternating miners with transactions, '
                 '%d comparison points equal (best hash, gettxoutsetinfo, getinfo, getblocktemplate, getblock); utxo hash %s at %d'
                 % (stock.getnetworkinfo()['subversion'], span, pair.steps, short(utxo), stock.getblockcount()))
        self.passed(item, 'stock-parity spot check (the full 300 blocks: yellowback_stockparity.py)',
                    '%d blocks, %d comparison points equal; the enforcing nodes followed, statehash %s'
                    % (span, pair.steps, short(h)))

    # ------------------------------------------------------------------ 10

    def item10_pointer(self):
        msg = ('every yellowback_*.py unarmed and --armed, the full test_bitcoin, the frozen set, the section 2 budgets '
               'and the lockorder / sanitizer / coverage jobs are the CI gates (.github/workflows/yellowback-tests.yml, '
               'qa/yellowback-audit.sh) -- not run here')
        self.results.append(('10', 'POINTER', 'the CI gates', msg))
        self.say('10', 'POINTER -- ' + msg)


if __name__ == '__main__':
    YellowbackDemoV6().main()
