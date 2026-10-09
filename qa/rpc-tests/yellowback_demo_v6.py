#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The Phase 6 demonstration of the ycashd 6.20.0 port (docs/plans/yellowback-ycash6-plan.md section 4,
"Success criteria") on the vault upgrade line (docs/plans/yellowback-upgrade-plan.md section 5, 6
and 15.10): one run that walks the section 4 checklist in order and prints a transcript line per
checkbox with its evidence (heights, txids, verdicts, state hashes).

It does not use the devnet launcher: it is the YellowbackTestFramework's standard eight-node
topology -- 0 user, 1 STOCK (the fork binary without the YED attestor set, so the module is inert
there; below the vault upgrade the stock 6.20.0 binary from --stock-binary / $REF_YCASHD, see
item 0), 2-4 pools, 5 observer (a second wallet: since U-21 every Yellowback node validates the
module), 6-7 attestor wallets -- and every step is one the per-rule scripts already prove
(yellowback_upgrade, _pricefeed, _lifecycle, _claim, _void_mint, _attest, _mint_armed, _index,
_stock_node, _stockparity); this script strings them together on one chain.

  0  (with $REF_YCASHD only) the reference half: a stock 6.20.0 binary knows no vault upgrade
     (it refuses -nuparams=6d5b7a31) and cannot follow a chain past it (upgrade plan finding (37)),
     so node 1 runs it below VAULT_ACTIVATION only -- compared fork-vs-stock against node 5 as the
     fork binary without the overlay (yellowback_stockparity's comparison), its block and a pool's
     block followed both ways -- and is then restarted on the fork binary for items 1-10
  1  every Yellowback node starts with the attestor set, index synced, yed_getinfo rpcversion 6
     healthy; node 1 has no yed_* command
  2  pools tag quotes; yed_getprice median; forged tags from a non-pool change nothing
  3  activation is UPGRADE_VAULT at a height plus the attestor set (U-22): one branch id and one
     activation height on every node, node 1 included; the retired machinery (signalling, lock-in,
     sunset, valve, abandonment) is gone from yed_getinfo and its options are ignored
  4  mint, send, redeem (in term, with the early-redeem fee: IT-1 extended, IT-9), claim into an
     intent (IT-2: as soon as underwater, in term or past it) and its release after CLAIM_DELAY,
     from wallet RPCs and raw builders; an invalid mint is an invalid transaction (no VOID);
     yed_sweep is gone; the model agrees
  5  attestors join the set (SET_JOIN; UNARMED -> TRIGGERED -> ARMED); bundles carried; a bad
     bundle is an invalid transaction: refused by every mempool, its block rejected
  6  the module is consensus (U-21): node 1 mines an unburned vault spend; every Yellowback node
     rejects the block at DoS 100 and disconnects it; the chain continues and node 1 is brought
     back; a wrong-price claim is cancelled by one attestor, the burn kept (I-2, U-24)
  7  a 2-block and a 10-block reorg with equal state hashes; restart and -reindex
  8  (pointer) the 30-minute persona economy and the devnet upgrade walk
  9  parity spot check, node 1 vs node 5 as the fork without the overlay (the full 300 blocks is
     yellowback_stockparity.py; the fork-vs-stock half is item 0)
 10  (pointer) the CI gates

Runtime: about 9-12 minutes.
"""

import os
import time

from test_framework.authproxy import JSONRPCException
from test_framework.util import (
    VAULT_BRANCH_ID,
    assert_equal,
    assert_greater_than,
    hex_str_to_bytes,
    nuparams,
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
    ATTEST_ARM_DELAY,
    ATTEST_FEE_BPS,
    ATTEST_MAX_AGE,
    ATTESTOR_A,
    ATTESTOR_B,
    ATTESTOR_SET,
    BPS,
    CLAIM_DELAY,
    ENFORCING_V3,
    OBSERVER,
    PEER_LAG,
    POOLS,
    REF_LAG,
    STOCK,
    USER,
    VAULT_ACTIVATION,
    YellowbackTestFramework,
    _statehash,
    assert_banscore_zero,
    assert_best_hash,
    assert_same_statehash,
    build_mint_tx,
    build_vault_spend_raw,
    debug_log_contains,
    early_redeem_fee_zat,
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

PRICE = 50                   # USD per YEC: class A collateral (300 % of $100, the in-term set) is 6 YEC
CRASH = 1                    # the claim's crash: 6 YEC at $1 backs $6 of a $100 debt
CENTS = 10_000               # $100, the class-A minimum
LOCK = 48                    # class A minimum lock
SWEEP_ACK = 'I understand this leaves YED unbacked'
BRANCH_HEX = '%08x' % VAULT_BRANCH_ID
RETIRED_INFO_KEYS = ('enforcing', 'valveTripped', 'sunset', 'rejectedBlocks', 'abandoned', 'activation')
# every node that runs the module: the user, the pools, the observer and the attestor wallets (U-21: all of
# them validate; node 1 runs without the attestor set and is the only node the module is inert on)
YELLOWBACK = [0, 2, 3, 4, 5, 6, 7]


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
    """How ``node`` shows it runs no overlay: the stock binary has no ``yed_*`` commands at all, and
    neither has the fork binary without the attestor set (U-22: Yellowback is not live there).
    Returns the evidence."""
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
    verbatim instead of a copy.  ``legacy_running`` / ``vault_at`` are that comparison's guard: a
    stock 6.20.0 binary is compared below the vault upgrade only (finding (37))."""

    def __init__(self, stock, fork, legacy_running=False, vault_at=VAULT_ACTIVATION):
        self.nodes = [stock, fork]
        self.steps = 0
        self.legacy_running = legacy_running
        self.vault_at = vault_at


class YellowbackDemoV6(ArmedModeMixin, YellowbackTestFramework):
    reference_binary_opt_in = True     # node 1 is $REF_YCASHD below VAULT_ACTIVATION in the nightly's demonstration step (item 0)
    legacy_done = False                # the reference half has run and node 1 is the fork binary
    # The attestor wallets join the Yellowback half directly, and {0, 2, 3, 4} is a complete graph:
    # pool restarts, an isolated stock branch and node 1's DoS-100 disconnection (item 6) never cut
    # the Yellowback nodes off from each other.
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
                          help='comma-separated item numbers to run (development; 5 needs 4, 6 needs 4 and 5, 9 runs alone)')

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
            # item 0 stays below the vault upgrade: no attestor set yet (create_attestor_set mines to
            # VAULT_ACTIVATION), and the chain starts two blocks lower so node 1 and a pool each mine
            # one block before VAULT_ACTIVATION - 1
            self.auto_attestor_set = False
            self.initial_blocks = VAULT_ACTIVATION - 4
        super().setup_network(split)

    # ------------------------------------------------------------------ transcript

    def say(self, item, msg):
        print('[%6.0fs] [%s] %s' % (time.time() - self.t0, item, msg), flush=True)

    def passed(self, item, title, evidence):
        self.results.append((item, 'PASS', title, evidence))
        self.say(item, 'PASS -- %s :: %s' % (title, evidence))

    def tip(self, i=USER):
        return self.nodes[i].getblockcount()

    def yellowback_nodes(self):
        return [self.nodes[i] for i in YELLOWBACK if self.nodes[i] is not None]

    def hashes(self, label, nodes=None):
        """Equal best hashes and equal YED state hashes over every Yellowback node; returns the hash."""
        self.sync_all(blocks_only=True)
        nodes = self.yellowback_nodes() if nodes is None else nodes
        assert_best_hash(nodes, label)
        return assert_same_statehash(nodes, label)

    # ------------------------------------------------------------------ helpers

    def assert_peers_with_stock(self, i):
        addr = '127.0.0.1:%d' % p2p_port(STOCK)
        assert any(p['addr'] == addr for p in self.nodes[i].getpeerinfo()), 'node %d lost node 1 as a peer' % i

    def ban_lines(self, i):
        """How many DoS-100 disconnections node ``i`` has logged (main.cpp Misbehaving)."""
        path = os.path.join(self.options.tmpdir, 'node%d' % i, 'regtest', 'debug.log')
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return sum(1 for line in f if 'BAN THRESHOLD EXCEEDED' in line)

    def stock_block_with(self, hex_):
        stock = self.nodes[STOCK]
        txid = stock.sendrawtransaction(hex_)
        blockhash = stock.generate(1)[0]
        assert txid in stock.getblock(blockhash)['tx']
        return blockhash, txid

    def expect_invalid(self, hex_, reason, miner, label):
        """U-21/U-23: ``hex_`` is an invalid transaction with verdict ``reason``: every Yellowback
        mempool refuses it (``bad-yellowback-<reason>``), a block assembled around it in Python on
        ``miner`` is rejected by ``submitblock`` with the same reason and the tip is unmoved.
        Returns the submitblock result."""
        for node in self.yellowback_nodes():
            rpc_error('bad-yellowback-' + reason, node.sendrawtransaction, hex_)
        tip = self.nodes[miner].getbestblockhash()
        result, blockhash = mine_block_raw(self.nodes[miner], [hex_])
        assert result is not None and result.startswith('bad-yellowback-' + reason), (label, result)
        assert_equal(self.nodes[miner].getbestblockhash(), tip)
        self.sync_all(blocks_only=True)
        return result, blockhash

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

    def claimable(self):
        """The outpoints ``yed_listclaimable`` marks claimable (IT-7: it lists every open vault, the
        healthy ones with ``claimable`` false)."""
        return [c['vault'] for c in self.nodes[USER].yed_listclaimable() if c['claimable']]

    def crash_until_claimable(self, vault_txid, item):
        """Every pool quotes CRASH until ``vault_txid`` is listed claimable (pClaim = max(pMid, pSlow)
        has to fall: the slow window).  In term or past claimHeight alike (IT-2: the APP branch is
        open from the block after the mint).  Returns the blocks mined."""
        user = self.nodes[USER]
        self.say(item, 'crash: every pool quotes $%d until %s is claimable (pClaim = max(pMid, pSlow))' % (CRASH, short(vault_txid)))
        self.quote_all(CRASH)
        outpoint = vault_txid + ':0'
        n = self.mine_until(lambda: outpoint in self.claimable(), 120, '%s claimable' % short(vault_txid))
        p = user.yed_getprice()
        v = user.yed_getvault(vault_txid)
        self.say(item, '%d crash blocks: pClaim %s at %d, %s claimable (%s: lockHeight %d, claimHeight %d)'
                 % (n, p['pClaim'], self.tip(), short(vault_txid), 'in term' if self.tip() < v['lockHeight'] else 'past its term',
                    v['lockHeight'], v['claimHeight']))
        return n

    def recover_price(self, item):
        user = self.nodes[USER]
        self.quote_all(PRICE)
        n = self.mine_until(lambda: user.yed_getstats()['mintingAllowed'] and self.claimable() == [], 120, 'price recovery')
        self.say(item, 'pools back at $%d: %d blocks to re-open minting (nothing claimable)' % (PRICE, n))
        return n

    def release_claim(self, claimant, vault_txid, claim_txid, item):
        """``vault_release`` of the claimant intent: refused before CLAIM_DELAY, paid after it (CLAIMED)."""
        nodes = self.nodes
        intent = '%s:0' % claim_txid
        v = nodes[USER].yed_getvault(vault_txid)
        release_height = [x for x in v['intents'] if x['txid'] == claim_txid][0]['releaseHeight']
        refusal = rpc_error('matures at height', claimant.vault_release, intent)
        self.mine_round_robin(POOLS, max(0, release_height - 1 - self.tip()))
        yec_before = claimant.getbalance()
        released = claimant.vault_release(intent)
        self.sync_all()
        self.mine(POOLS[0])
        for node in self.yellowback_nodes():
            c = node.yed_getvault(vault_txid)
            assert_equal(c['status'], 'CLAIMED')
            assert 'intents' not in c
        assert_greater_than(claimant.getbalance(), yec_before + 5)      # the 6 YEC collateral (class A, 300 %) less fees
        assert_equal(nodes[2].yed_gettxinfo(released)['type'], 'claim_release')
        self.say(item, 'vault_release %s: refused before the delay (%s); released at %d (releaseHeight %d = claim + %d): %s, CLAIMED everywhere, %s YEC to the claimant'
                 % (intent, refusal, self.tip(), release_height, CLAIM_DELAY, released, claimant.getbalance() - yec_before))
        return released

    # ------------------------------------------------------------------ run

    def run_test(self):
        stock_bin = self.stock_binary()
        print('=' * 100)
        print('Yellowback on ycashd 6.20.0, the vault upgrade line -- the plan section 4 demonstration (yellowback_demo_v6.py)')
        print('node 1 binary: %s' % (stock_bin or 'the fork binary WITHOUT the attestor set (no --stock-binary / REF_YCASHD given)'))
        print('=' * 100)
        if self.legacy():
            self.item0_reference_half()
        steps = [self.item1_startup, self.item2_tags_and_price, self.item3_activation, self.item4_wallet_lifecycle,
                 self.item5_attestation, self.item6_module_is_consensus, self.item7_reorgs_and_rebuilds, self.item8_pointer,
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

    # ------------------------------------------------------------------ 0

    def item0_reference_half(self):
        """The $REF_YCASHD half (finding (37)): the stock 6.20.0 binary on node 1 below the vault
        upgrade, compared against node 5 as the fork binary without the overlay, then node 1 on the
        fork binary, node 5 a Yellowback node again, and the attestor set for items 1-10."""
        item = '0'
        from yellowback_stockparity import YellowbackStockParityTest
        nodes = self.nodes
        stock = nodes[STOCK]
        sub = stock.getnetworkinfo()['subversion']
        assert BRANCH_HEX not in stock.getblockchaininfo().get('upgrades', {})
        self.say(item, 'node 1 (stock 6.20.0 binary %s): height %d, %s; the vault upgrade at %d is unknown to it'
                 % (sub, stock.getblockcount(), overlay_off(stock), VAULT_ACTIVATION))
        # node 5 as the fork binary without the overlay (its datadir holds no index yet: nothing to acknowledge)
        restart_with_yellowback(self, [OBSERVER], extra=['-yellowback=0'], yellowback_indices=[])
        fork = nodes[OBSERVER]
        sync_blocks([stock, fork])
        pair = _ParityPair(stock, fork, legacy_running=True)
        cmp = YellowbackStockParityTest.compare
        cmp(pair, 'reference start')
        for miner in (STOCK, POOLS[0], STOCK):
            h = nodes[miner].generate(1)[0]
            self.sync_all(blocks_only=True)
            assert_best_hash([n for n in nodes if n is not None], 'reference half, node %d mined' % miner)
            for n in nodes:
                assert_equal(n.getblock(h)['confirmations'], 1)
            cmp(pair, 'block %d' % stock.getblockcount(), template=stock.getblockcount() + 1 < VAULT_ACTIVATION)
        assert_equal(stock.getblockcount(), VAULT_ACTIVATION - 1)
        assert_banscore_zero([n for n in nodes if n is not None])
        utxo = stock.gettxoutsetinfo()['hash_serialized']
        self.say(item, 'node 1 (%s) vs node 5 (fork binary, no -yellowback): %d comparison points equal below the upgrade '
                 '(best hash, gettxoutsetinfo, getinfo, getblocktemplate, getblock); its block and a pool\'s block followed '
                 'by every node both ways; utxo hash %s at %d' % (sub, pair.steps, short(utxo), stock.getblockcount()))
        self.say(item, '*** the reference half ends at %d: a stock 6.20.0 binary cannot follow the vault upgrade (finding 37); '
                 'node 1 is the fork binary without the attestor set from here' % (VAULT_ACTIVATION - 1))
        self.legacy_done = True
        self.restart(STOCK)
        restart_with_yellowback(self, [OBSERVER])
        self.sync_all(blocks_only=True)
        self.create_attestor_set()
        self.passed(item, 'the reference half: stock 6.20.0 on node 1 below the vault upgrade, fork-vs-stock parity',
                    '%s, %d comparison points equal, chain at %d; node 1 now the fork binary without the attestor set'
                    % (sub, pair.steps, VAULT_ACTIVATION - 1))

    # ------------------------------------------------------------------ 1

    def item1_startup(self):
        item = '1'
        self.say(item, 'every node starts from genesis; node 0 mined %d blocks before the run; the YED attestor set %s was created at %d (U-22)'
                 % (self.initial_blocks, short(ATTESTOR_SET[0]), VAULT_ACTIVATION))
        rows = []
        for i in YELLOWBACK:
            info = wait_yed_healthy(self.nodes[i], timeout=60)
            assert_equal(info['rpcversion'], 6)   # in-term claims (IT-7)
            assert_equal(info['healthy'], True)
            assert_equal(info['height'], self.nodes[i].getblockcount())
            assert_equal(info['startHeight'], VAULT_ACTIVATION)
            assert_equal((info['upgrade']['status'], info['upgrade']['attestorSetId']), ('active', ATTESTOR_SET[0]))
            role = {0: 'user', 2: 'pool', 3: 'pool', 4: 'pool', 5: 'observer', 6: 'attestor wallet', 7: 'attestor wallet'}[i]
            self.say(item, 'node %d (%s): rpcversion %d healthy %s index height %d upgrade %s startHeight %d statehash %s'
                     % (i, role, info['rpcversion'], info['healthy'], info['height'], info['upgrade']['status'], info['startHeight'],
                        short(_statehash(self.nodes[i]))))
            rows.append(info['height'])
        h = assert_same_statehash(self.yellowback_nodes(), 'start')
        stock = self.nodes[STOCK]
        off = overlay_off(stock)
        sub = stock.getnetworkinfo()['subversion']
        self.say(item, 'node 1 (stock, no attestor set): %s, height %d, %s' % (sub, stock.getblockcount(), off))
        self.passed(item, 'every Yellowback node starts with the attestor set, syncs the index, rpcversion 6 healthy; node 1 has no yed_* command',
                    '7 Yellowback nodes at height %d, one state hash %s; node 1 stock (%s)' % (rows[0], short(h), sub))

    # ------------------------------------------------------------------ 2

    def item2_tags_and_price(self):
        item = '2'
        user, stock = self.nodes[USER], self.nodes[STOCK]
        self.quote_all(PRICE)
        self.say(item, 'pools 2-4 quote $%d (yed_setquote) and mine 12 blocks round robin' % PRICE)
        self.mine_round_robin(POOLS, 12)
        for h in range(self.tip() - 2, self.tip() + 1):
            tag = user.yed_gettag(str(h))
            assert_equal((tag['found'], tag['kind'], tag['priceMicroUsd']), (True, 'quote', usd_to_micro(PRICE)))
            assert tag['payoutAddress'] in self.pool_addresses
            self.say(item, 'height %d: tag kind=%s price=%d payout=%s' % (h, tag['kind'], tag['priceMicroUsd'], tag['payoutAddress']))
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
        h = self.hashes('item 2')
        self.passed(item, 'pools tag quotes; yed_getprice median; a forged tag from a non-pool is outvoted',
                    'pFast %d at %d; forged $%d tag at %d penalised until %d (REG-4), price unmoved; malformed tag ignored; statehash %s'
                    % (p['pFast'], self.tip(), 2 * PRICE, forged_h, f['penalizedUntil'], short(h)))

    # ------------------------------------------------------------------ 3

    def item3_activation(self):
        item = '3'
        nodes = self.nodes
        user, stock = nodes[USER], nodes[STOCK]
        # one consensus parameter on every node, node 1 included: the branch id and its height
        for i in range(len(nodes)):
            up = nodes[i].getblockchaininfo()['upgrades'][BRANCH_HEX]
            assert_equal((up['name'], up['status'], up['activationheight']), ('Vault', 'active', VAULT_ACTIVATION))
            vi = nodes[i].vault_getinfo()
            assert_equal((vi['branchid'], vi['activationheight'], vi['active']), (BRANCH_HEX, VAULT_ACTIVATION, True))
        self.say(item, 'UPGRADE_VAULT (branch %s) active since %d on all 8 nodes (getblockchaininfo.upgrades, vault_getinfo), node 1 included: '
                 'activation is a height in chainparams, not a signalling count' % (BRANCH_HEX, VAULT_ACTIVATION))
        # the attestor set: the primitive set every Yellowback node was started with (U-22)
        s = user.set_getinfo(ATTESTOR_SET[0])
        assert_equal((s['setid'], s['cancelthreshold']), (ATTESTOR_SET[0], 1))
        self.say(item, 'the YED attestor set %s: seats %d, cancel threshold %d, members %d (set_getinfo); every Yellowback node runs '
                 '-yellowbackattestorset=%s' % (short(s['setid']), s['seats'], s['cancelthreshold'], s['members'], short(ATTESTOR_SET[0])))
        for node in self.yellowback_nodes():
            a = node.yed_getactivation()
            assert_equal((a['status'], a['activationHeight'], a['attestorSetId'], a['claimDelay']), ('active', VAULT_ACTIVATION, ATTESTOR_SET[0], CLAIM_DELAY))
            info = node.yed_getinfo()
            for gone in RETIRED_INFO_KEYS:
                assert gone not in info, gone
        rpc_error('Method not found', stock.yed_getactivation)
        self.say(item, 'yed_getactivation on 7 Yellowback nodes: status active, activationHeight %d, attestorSetId %s, claimDelay %d; '
                 'yed_getinfo carries none of %s (upgrade plan section 6); node 1: Method not found'
                 % (VAULT_ACTIVATION, short(ATTESTOR_SET[0]), CLAIM_DELAY, ', '.join(RETIRED_INFO_KEYS)))
        # minting opens when the price windows are filled (the only wait there is: no lock-in, no delay)
        n = self.mine_until(lambda: user.yed_getstats()['mintingAllowed'], 80, 'the price windows')
        p = user.yed_getprice()
        self.say(item, 'minting open at %d after %d more pool blocks: pFast %s pMid %s pSlow %s (WINDOW_MIN_FILL), haltMask %s'
                 % (self.tip(), n, p['pFast'], p['pMid'], p['pSlow'], user.yed_getstats()['haltMask']))

        # the retired v2/v3 options are accepted, logged as retired and ignored: node 4 validates exactly as before
        before = self.hashes('before the retired options')
        self.restart(4, ['-yellowbacksignal=0', '-yellowbackenforce=0'])
        info = wait_yed_healthy(nodes[4], timeout=120)
        assert debug_log_contains(self.options.tmpdir, 4, '-yellowbacksignal is retired with the vault upgrade and ignored')
        assert debug_log_contains(self.options.tmpdir, 4, '-yellowbackenforce is retired with the vault upgrade and ignored')
        assert_equal(_statehash(nodes[4]), before)
        nodes[4].generate(1)
        self.sync_all(blocks_only=True)
        tag = user.yed_gettag(str(self.tip()))
        assert_equal((tag['found'], tag['kind'], tag['payoutAddress']), (True, 'quote', self.pool_addresses[POOLS.index(4)]))
        h = self.hashes('item 3')
        self.say(item, 'node 4 restarted with -yellowbacksignal=0 -yellowbackenforce=0: both logged "retired with the vault upgrade and ignored"; '
                 'it validates (statehash %s), its block %d tags a quote as before' % (short(h), self.tip()))
        self.restart(4)
        wait_yed_healthy(nodes[4], timeout=120)
        # fund the observer (the claimant of items 4 and 6) and give the user's coinbases time to mature
        user.sendtoaddress(nodes[OBSERVER].getnewaddress(), 10)
        self.sync_all()
        self.mine(POOLS[0])
        self.passed(item, 'activation is UPGRADE_VAULT at a height plus the attestor set, one parameter on every node; the retired machinery is gone',
                    'branch %s active since %d on 8 nodes; attestor set %s; minting open at %d; retired options ignored on node 4; statehash %s'
                    % (BRANCH_HEX, VAULT_ACTIVATION, short(ATTESTOR_SET[0]), self.tip() - 1, short(h)))

    # ------------------------------------------------------------------ 4

    def item4_wallet_lifecycle(self):
        item = '4'
        nodes = self.nodes
        user, observer = nodes[USER], nodes[OBSERVER]
        self.say(item, 'wallet mints (yed_mint, two steps: carrier then mint): A redeem, B claim, C/E/F kept for items 5-6')
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
        # the vault output is the primitive's V template (U-23)
        raw = user.getrawtransaction(mints['A']['txid'], 1)
        dec = user.vault_decodescript(raw['vout'][0]['scriptPubKey']['hex'])
        open_at = user.yed_getvault(mints['A']['txid'])['refHeight'] + 1                        # IT-1: both branches open at the mint
        assert_equal((dec['type'], dec['tag'], dec['setid'], dec['cancelsetid'], dec['delay'], dec['ownerheight'], dec['appheight']),
                     ('vault', '59454400', ATTESTOR_SET[0], ATTESTOR_SET[0], CLAIM_DELAY, open_at, open_at))
        self.say(item, 'A\'s vout 0 is the V template (vault_decodescript): tag YED, set = cancel set = %s, delay %d, ownerHeight %d = appHeight %d = refHeight + 1 '
                 '(IT-1: owner and claim branches open from the mint; lockHeight %d, claimHeight %d are module rules)'
                 % (short(dec['setid']), dec['delay'], dec['ownerheight'], dec['appheight'], mints['A']['lockHeight'], mints['A']['claimHeight']))
        # the raw builders: D an ACTIVE mint, Z under-collateralised -- an invalid transaction, not a VOID vault (U-23)
        est = user.yed_estimatecollateral(CENTS, LOCK)
        ref = int(est['refHeight'])
        payee = user.yed_getfeepayee(ref, int(est['requiredZat']))['default']['payoutAddress']
        d_hex, _ = build_mint_tx(user, CENTS, LOCK, ref, int(est['requiredZat']), fee_addr=payee)
        d_txid = user.sendrawtransaction(d_hex)
        # listunspent(1) does not see the mempool: lock D's inputs so Z cannot reuse them
        user.lockunspent(False, [{'txid': i.prev_txid, 'vout': i.prev_n} for i in ym.tx_from_hex(d_hex).vin])
        z_hex, _ = build_mint_tx(user, CENTS, LOCK, ref, int(est['requiredZat']) - 1000, fee_addr=payee)
        z_txid = user.decoderawtransaction(z_hex)['txid']
        z_check = nodes[2].yed_validaterawtransaction(z_hex)
        assert_equal(z_check['verdict'], 'bad-mint-collateral')
        self.sync_all()
        self.mine(POOLS[2])
        assert_equal(user.yed_getvault(d_txid)['status'], 'ACTIVE')
        result, z_block = self.expect_invalid(z_hex, 'bad-mint-collateral', POOLS[0], 'Z')
        for node in self.yellowback_nodes():
            rpc_error('vault-not-found', node.yed_getvault, z_txid)
        self.say(item, 'raw build_mint_tx D: %s ACTIVE; raw Z (1000 zat short): verdict %s, refused by all 7 mempools (bad-yellowback-%s), '
                 'its hand-built block %s rejected by submitblock on pool 2 (%s): no vault, no VOID, nothing mined'
                 % (d_txid, z_check['verdict'], z_check['verdict'], short(z_block), result))
        assert_equal(nodes[2].yed_getstats()['supplyCents'], 6 * CENTS)

        sent = user.yed_send(observer.yed_getnewaddress(), CENTS + 100)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(observer.yed_getbalance()['confirmedCents'], CENTS + 100)
        self.say(item, 'yed_send %d cents user -> observer: %s (change %d)' % (CENTS + 100, sent['txid'], sent['changeCents']))

        # in term: yed_redeem A (owner selector 2, burn + fee + the early-redeem fee, IT-1 extended / IT-9);
        # past the locks: raw redemption of D, no early-redeem fee; yed_sweep is gone
        lock = max(mints['A']['lockHeight'], user.yed_getvault(d_txid)['lockHeight'])
        va = user.yed_getvault(mints['A']['txid'])
        assert_greater_than(va['lockHeight'], self.tip() + 1)
        early = early_redeem_fee_zat(va['collateralZat'], mints['A']['termClass'])
        quote = user.yed_estimateredeem(mints['A']['txid'])
        assert_equal((quote['early'], quote['canRedeem'], quote['earlyRedeemFeeZat']), (True, True, early))
        red_at = self.tip() + 1
        red = user.yed_redeem(mints['A']['txid'])
        assert_equal((red['burnedCents'], red['earlyRedeemFeeZat'], red['feeZat']), (CENTS, early, fee_zat(va['collateralZat']) + early))
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(nodes[2].yed_getvault(mints['A']['txid'])['status'], 'CLOSED')
        tx = user.getrawtransaction(red['txid'], 1)
        assert tx['vin'][0]['scriptSig']['hex'].endswith('52'), tx['vin'][0]['scriptSig']      # ... OP_2: the owner selector
        self.mine_round_robin(POOLS, max(0, lock - self.tip()))
        sweep = rpc_error('Method not found', user.yed_sweep, mints['C']['txid'], SWEEP_ACK)
        self.say(item, 'yed_redeem A in term (%d blocks before its lockHeight %d): %s, owner selector OP_2, burned %d, fee %d to %s '
                 '(FEE-1 + the class %s early-redeem fee %d, IT-9), collateral %d back; yed_sweep: %s (retired with abandonment, upgrade plan section 6)'
                 % (va['lockHeight'] - red_at, va['lockHeight'], red['txid'],
                    red['burnedCents'], red['feeZat'], red['payee'], mints['A']['termClass'], early, red['collateralOut'], sweep))
        assert_equal(user.yed_estimateredeem(d_txid)['earlyRedeemFeeZat'], 0)            # past D's lockHeight: no early-redeem fee
        burn, _total = self.coins_for(user, CENTS)
        d_red = redeem_vault_raw(self, user, POOLS[2], self.live_vault(d_txid), burn)
        assert_equal(nodes[2].yed_getvault(d_txid)['status'], 'CLOSED')
        self.say(item, 'raw owner-path redemption of D (build_vault_spend_raw, REDEEM payload, FEE-W payee): %s CLOSED' % d_red)

        # the claim: every pool quotes $1 until B is underwater (IT-2: in term or past it alike; here the locks above have passed, the
        # in-term claim itself is yellowback_interm.py's); the claim is an intent (U-23)
        self.crash_until_claimable(mints['B']['txid'], item)
        supply = nodes[2].yed_getstats()['supplyCents']
        claimed = self.claim(observer, mints['B']['txid'])
        self.sync_all()
        self.mine(POOLS[2])
        claim_h = self.tip()
        raw = observer.getrawtransaction(claimed['txid'], 1)
        assert_equal(raw['vin'][0]['scriptSig']['hex'], '54')                                   # OP_4: the claim selector
        idec = observer.vault_decodescript(raw['vout'][0]['scriptPubKey']['hex'])
        assert_equal((idec['type'], idec['tag']), ('intent', '59454400'))
        for node in self.yellowback_nodes():
            c = node.yed_getvault(mints['B']['txid'])
            assert_equal((c['status'], c['burnedCents'], c['unbacked']), ('CLAIMING', CENTS, False))
            assert_equal([(x['txid'], x['vout'], x['role'], x['releaseHeight']) for x in c['intents']],
                         [(claimed['txid'], 0, 'claimant', claim_h + CLAIM_DELAY)])
        assert_equal(nodes[2].yed_getstats()['supplyCents'], supply - CENTS)
        self.say(item, 'yed_claim B by the observer: %s, claim selector OP_4 into a claimant intent (vault_decodescript: %s), burned %d, '
                 'collateral %d in the intent, fee %d to %s; CLAIMING on every node, supply %d -> %d'
                 % (claimed['txid'], idec['type'], claimed['burnedCents'], claimed['collateralOut'], claimed['feeZat'], claimed['payee'],
                    supply, supply - CENTS))
        released = self.release_claim(observer, mints['B']['txid'], claimed['txid'], item)
        self.recover_price(item)

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
        assert_equal((stats['voidVaults'], stats['unbackedCents']), (0, 0))
        self.mints = mints
        self.passed(item, 'mint, send, redeem, claim into an intent and its release from the wallet RPCs and the raw builders; an invalid mint is invalid; the model agrees',
                    'redeem %s, raw redeem %s, claim %s, release %s; Z rejected (%s); model statehash %s'
                    % (short(red['txid']), short(d_red), short(claimed['txid']), short(released), result, short(h)))

    # ------------------------------------------------------------------ 5

    def item5_attestation(self):
        item = '5'
        nodes = self.nodes
        user = nodes[USER]
        nodes[POOLS[0]].sendtoaddress(user.getnewaddress(), 80)     # five 10 YEC bonds and the carriers
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(user.yed_getinfo()['attest']['status'], 'UNARMED')
        members_before = user.set_getinfo(ATTESTOR_SET[0])['members']
        self.say(item, 'UNARMED at %d; five attestors join the set (raw SET_JOIN acts, P4-b: the set is the registry; 10 YEC bonds, member keys on nodes 6-7)' % self.tip())
        seqs = register_and_arm(self, 5)          # asserts TRIGGERED at the exact block and ARMED after the delay
        attest = user.yed_getinfo()['attest']
        assert_equal((attest['status'], attest['armHeight'], attest['triggerHeight'] + ATTEST_ARM_DELAY), ('ARMED', attest['armHeight'], attest['armHeight']))
        recs = {int(r['seq']): r for r in user.yed_listattestors()}
        s = user.set_getinfo(ATTESTOR_SET[0])
        assert_equal((s['members'], s['current']), (members_before + 5, 5))
        self.say(item, 'seqs %s ELIGIBLE; set members %d -> %d, current %d (set_getinfo); TRIGGERED at %d, ARMED at %d (+%d) on every Yellowback node; seated %d'
                 % (seqs, members_before, s['members'], s['current'], attest['triggerHeight'], attest['armHeight'], ATTEST_ARM_DELAY, attest['seatedCount']))
        self._armed = True

        # a bundle built and carried: yed_mint with the attestors' bundle in the carrier's scriptSig
        good = self.mint(user, CENTS, LOCK)
        self.sync_all()
        self.mine(POOLS[2])
        info = nodes[2].yed_gettxinfo(good['txid'])
        assert_equal((info['verdict'], info['bundleSource']), ('ok', 'scriptsig'))
        assert_greater_than(info['carrierVin'], -1)
        for node in self.yellowback_nodes():
            assert_equal(node.yed_getvault(good['txid'])['status'], 'ACTIVE')
        self.say(item, 'armed yed_mint %s: carrier %s, bundle seqs %s, aMint %s xMint %s pMint %s, attestor fee %d to %s: ACTIVE everywhere'
                 % (good['txid'], good.get('carrierTxid'), info['bundleSeqs'], info['aMint'], info['xMint'], info['pMint'],
                    info['attestFeeZat'], info['attestPayee']))

        # a bad bundle on a mint: every attestation cites R - ATTEST_MAX_AGE (stale) -- an invalid transaction (U-23)
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
        result, blockhash = self.expect_invalid(bad_hex, 'mint9-bundle-stale', POOLS[1], 'stale bundle')
        for node in self.yellowback_nodes():
            rpc_error('vault-not-found', node.yed_getvault, bad_txid)
        self.say(item, 'stale-bundle mint %s: verdict %s; refused by all 7 mempools, its hand-built block %s rejected on pool 3 (%s): '
                 'no vault, no YED issued -- a failing mint is an invalid transaction, not a VOID vault'
                 % (bad_txid, check['verdict'], short(blockhash), result))

        # a bad bundle on a claim: E (healthy, past claimHeight) claimed with no bundle
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
        result2, blockhash2 = self.expect_invalid(claim_hex, 'red1-bundle-shape', POOLS[2], 'bundle-less claim')
        for node in self.yellowback_nodes():
            assert_equal(node.yed_getvault(e_txid)['status'], 'ACTIVE')
        self.say(item, 'bundle-less claim of E: verdict %s; refused by all 7 mempools, its hand-built block %s rejected on pool 4 (%s); E ACTIVE'
                 % (check['verdict'], short(blockhash2), result2))
        assert_banscore_zero([n for n in nodes if n is not None])
        h = self.hashes('item 5')
        self.passed(item, 'attestors join the set, bundles carried; a bad bundle is an invalid transaction: refused by every mempool, its block rejected',
                    'ARMED at %d, set current %d; good mint %s; stale-bundle mint block %s and bundle-less claim block %s rejected; statehash %s'
                    % (attest['armHeight'], s['current'], short(good['txid']), short(blockhash), short(blockhash2), short(h)))

    # ------------------------------------------------------------------ 6

    def item6_module_is_consensus(self):
        item = '6'
        nodes = self.nodes
        user, observer, stock = nodes[USER], nodes[OBSERVER], nodes[STOCK]
        f_txid = self.mints['F']['txid']
        live = self.live_vault(f_txid)
        bad = build_vault_spend_raw(user, live, 'owner', [], expiry=0)      # owner path, no burn, no payload
        check = user.yed_validaterawtransaction(bad)
        assert_equal(check['wouldBeRejected'], True)
        for node in self.yellowback_nodes():
            rpc_error('bad-yellowback-' + check['verdict'], node.sendrawtransaction, bad)
        self.say(item, 'owner-path spend of F with no burn: verdict %s; all 7 Yellowback mempools refuse it (bad-yellowback-%s); '
                 'node 1 (no attestor set, the module inert) accepts it' % (check['verdict'], check['verdict']))
        bans_before = {i: self.ban_lines(i) for i in YELLOWBACK}
        blockhash, txid = self.stock_block_with(bad)
        wait_for_rejection(self.yellowback_nodes(), blockhash)
        reasons = {}
        for i in YELLOWBACK:
            verdict = nodes[i].yed_getblockverdict(blockhash)
            assert_equal(verdict['blockInvalid'], True)
            reasons[i] = verdict['reason']
            assert reasons[i].startswith(check['verdict']), reasons[i]
        # DoS 100 (U-21): every Yellowback node that took the block from node 1 scored it 100 and dropped that
        # connection (a local peer is disconnected, not banned; connect_nodes_bi's other direction stays); the
        # complete graph {0, 2, 3, 4} + {6, 7} carries the Yellowback chain on regardless
        deadline = time.time() + 30
        while time.time() < deadline and any(self.ban_lines(i) == bans_before[i] for i in (USER, POOLS[0])):
            time.sleep(0.2)
        for i in (USER, POOLS[0]):
            assert_greater_than(self.ban_lines(i), bans_before[i])
        assert_equal(stock.getbestblockhash(), blockhash)
        self.say(item, 'node 1 mined %s (tx %s) at %d: INVALID on all 7 Yellowback nodes (yed_getblockverdict: %s), DoS 100 -- '
                 '"BAN THRESHOLD EXCEEDED" logged on nodes 0 and 2 (the connection the block came over is dropped; a local peer is '
                 'not banned); node 1 alone sits on its block'
                 % (short(blockhash), short(txid), stock.getblockcount(), reasons[USER]))
        # the Yellowback chain continues without node 1; node 1 is brought back (invalidateblock, a restart) and follows
        for k in range(2):
            nodes[POOLS[k]].generate(1)
            sync_blocks([nodes[i] for i in ENFORCING_V3])
        stock.invalidateblock(blockhash)
        self.restart(STOCK)
        self.sync_all(blocks_only=True)
        assert_best_hash([n for n in nodes if n is not None], 'item 6, node 1 back')
        for i in YELLOWBACK:
            self.assert_peers_with_stock(i)
        for node in self.yellowback_nodes():
            assert_equal(node.yed_getvault(f_txid)['status'], 'ACTIVE')
        assert_banscore_zero([n for n in nodes if n is not None])
        h1 = self.hashes('item 6, after the rejection')
        self.say(item, 'pools mined 2 blocks without node 1; node 1 invalidateblock + restart: back on the valid chain at %d with every node, F ACTIVE, '
                 'banscore 0 on every connection, statehash %s' % (self.tip(), short(h1)))

        # a wrong-price claim cancelled by one attestor (I-2): the claim is valid at the chain's price, the attestor
        # disagrees; the collateral returns to a byte-identical vault and the claimant's burn is not refunded (U-24)
        c_txid = self.mints['C']['txid']
        spk_c = user.getrawtransaction(c_txid, 1)['vout'][0]['scriptPubKey']['hex']
        self.crash_until_claimable(c_txid, item)
        user.yed_send(observer.yed_getnewaddress(), CENTS)
        self.sync_all()
        self.mine(POOLS[1])
        before = nodes[2].yed_getstats()
        claimed = self.claim(observer, c_txid)
        self.sync_all()
        self.mine(POOLS[2])
        assert_equal(nodes[2].yed_getvault(c_txid)['status'], 'CLAIMING')
        after_claim = nodes[2].yed_getstats()
        assert_equal(after_claim['supplyCents'], before['supplyCents'] - CENTS)
        self.say(item, 'yed_claim C by the observer at pClaim %s: %s burned %d, CLAIMING (intent %s:0, release at +%d)'
                 % (user.yed_getprice()['pClaim'], claimed['txid'], claimed['burnedCents'], short(claimed['txid']), CLAIM_DELAY))
        built = observer.vault_buildcancel('%s:0' % claimed['txid'])
        signed = nodes[ATTESTOR_A].set_signcancel(built['hex'])
        assert_equal(signed['complete'], True)
        full = observer.signrawtransaction(signed['hex'])
        assert_equal(full['complete'], True)
        v = observer.yed_validaterawtransaction(full['hex'])
        assert_equal((v['valid'], v['verdict'], v['type']), (True, 'ok', 'claim_cancel'))
        cancel = observer.sendrawtransaction(full['hex'])
        self.sync_all()
        self.mine(POOLS[0])
        for node in self.yellowback_nodes():
            rpc_error('vault-not-found', node.yed_getvault, c_txid)              # the record moved to the re-created vault
            vc = node.yed_getvault(cancel)
            assert_equal((vc['status'], vc['mintedCents'], vc['scriptPubKey']), ('ACTIVE', CENTS, spk_c))
        assert_equal(nodes[2].getrawtransaction(cancel, 1)['vout'][0]['scriptPubKey']['hex'], spk_c)
        after = nodes[2].yed_getstats()
        assert_equal((after['supplyCents'], after['activeVaults']), (after_claim['supplyCents'], after_claim['activeVaults'] + 1))
        assert_equal(nodes[2].yed_gettxinfo(cancel)['type'], 'claim_cancel')
        self.say(item, 'attestor cancel (vault_buildcancel on the claimant, set_signcancel on node 6 = one current member, cancel threshold 1): %s; '
                 'the collateral is back in a byte-identical V at %s:0, ACTIVE as the same position on every node; supply stays %d: '
                 'the claimant\'s %d-cent burn is not refunded (U-24)' % (cancel, short(cancel), after['supplyCents'], CENTS))
        self.recover_price(item)
        self.model_check(nodes[2])
        h = self.hashes('item 6')
        self.passed(item, 'the module is consensus: an unburned vault spend mined by node 1 is rejected at DoS 100 by every Yellowback node, which disconnect it and carry on; a wrong-price claim is cancelled by one attestor, the burn kept',
                    'block %s rejected (%s) by 7 nodes, node 1 back at %s; claim %s cancelled by %s, vault ACTIVE at %s; statehash %s'
                    % (short(blockhash), check['verdict'], short(h1), short(claimed['txid']), short(cancel), short(cancel), short(h)))

    # ------------------------------------------------------------------ 7

    def reorg(self, depth, label):
        """Yellowback half mines ``depth`` blocks (a yed_send in the first), the stock half
        ``depth + 1``; the join reorgs every Yellowback node ``depth`` blocks."""
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
        self.say('7', '%s: fork at %d, the Yellowback branch (%d blocks, yed_send %s) replaced by node 1\'s %d; '
                 'state hash %s on every Yellowback node after the join (was %s on the losing branch); the send re-mined at %d, statehash %s'
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
               'qa/rpc-tests/yellowback_devnet_roles.py, and the devnet on the vault upgrade end to end (members, mint, claim, '
               'cancel, invalid, bridge) is qa/rpc-tests/yellowback_devnet_upgrade.py (devnet launcher, nightly) -- not run here')
        self.results.append(('8', 'POINTER', 'the 30-minute persona economy and the devnet upgrade walk', msg))
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
        # node refuses to start without the attestor set unless -yellowback=0 is given explicitly (the
        # wallet may hold YED that a plain start would treat as spendable YEC) -- the acknowledgement
        # is part of the evidence.
        restart_with_yellowback(self, [OBSERVER], extra=['-yellowback=0'], yellowback_indices=[])
        fork = nodes[OBSERVER]
        self.say(item, 'node 5 restarted as the fork binary without the attestor set, -yellowback=0 (a plain start refuses: the datadir holds an index): %s'
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
        self.say(item, 'node 1 (%s) vs node 5 (fork binary, no attestor set): %d blocks alternating miners with transactions, '
                 '%d comparison points equal (best hash, gettxoutsetinfo, getinfo, getblocktemplate, getblock); utxo hash %s at %d'
                 % (stock.getnetworkinfo()['subversion'], span, pair.steps, short(utxo), stock.getblockcount()))
        self.passed(item, 'parity spot check, node 1 vs node 5 as the fork without the overlay (the full 300 blocks: yellowback_stockparity.py)',
                    '%d blocks, %d comparison points equal; the Yellowback nodes followed, statehash %s'
                    % (span, pair.steps, short(h)))

    # ------------------------------------------------------------------ 10

    def item10_pointer(self):
        msg = ('every vault_*.py and yellowback_*.py (unarmed and --armed), the full test_bitcoin, the audit script (registration, '
               'attribution, naming, the DoS gate, determinism, the rpcversion 6 contract, vault_vectors.json and '
               'yellowback_golden.json byte-identical to ycash-dd, the consensus-diff report for the two-reviewer gate; the frozen-file '
               'and budget legs report-only on the upgrade line) and the lockorder / sanitizer / coverage jobs are the CI gates '
               '(.github/workflows/yellowback-tests.yml, qa/yellowback-audit.sh) -- not run here')
        self.results.append(('10', 'POINTER', 'the CI gates', msg))
        self.say('10', 'POINTER -- ' + msg)


if __name__ == '__main__':
    YellowbackDemoV6().main()
