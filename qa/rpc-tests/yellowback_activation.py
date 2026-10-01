#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The activation state machine end to end (plan Phase 3, §3.7 ACT-1..6, HALT-4, MINER-1, ACT-5's
sunset, TAG-3, §7): forged signal tags lock in on the stock miner's count alone (N4); two of three
pools never lock in; lock-in at exactly the block that brings the trailing window to 48 (K16) with
the reorg across it (act2); activation at lockIn + 64 with the reorg straddling activateHeight + 1
(act3); the participation halt and the enforcement suspension with their hysteresis (L3), a
rule-breaking block rejected while enforcement is on and accepted while suspended with the
no-partition assertion (N35); MINER-1's signal-iff-enforce; the observer's view; signal-only tags
registering nobody; the sunset (L8); and the Python model at the end (N23).

Lock-in is one-shot, so the phases that need to observe it are ordered so that each lock-in is
either rewound (invalidateblock) or undone by a reorg before the next.

Raw builders only (N26).
"""

import hashlib
import time

from test_framework.util import assert_equal, assert_greater_than, sync_blocks
from test_framework.yellowback_util import (
    ACTIVATION_DELAY,
    ACTIVATION_THRESHOLD,
    ENFORCEMENT_FLOOR,
    ENFORCEMENT_RESUME,
    ENFORCING,
    N_REG,
    OBSERVER,
    PARTICIPATION_FLOOR,
    POOLS,
    REF_LAG,
    SIGNAL_WINDOW,
    STOCK,
    USER,
    YellowbackTestFramework,
    assert_banscore_zero,
    assert_best_hash,
    assert_model_matches,
    assert_same_statehash,
    build_mint_tx,
    mine_block_raw,
    mine_rejected_block,
    mint_vault_raw,
    pubkey_to_address,
    secret_to_pubkey,
    template_coinbase,
    wait_for_rejection,
    wait_yed_healthy,
)
from test_framework import yellowback_model as ym


def rpc_error_message(fn, *args):
    try:
        fn(*args)
    except Exception as e:
        err = getattr(e, 'error', None)
        if isinstance(err, dict):
            return str(err.get('message', ''))
        return str(e)
    raise AssertionError('expected an RPC error from %r%r' % (fn, args))


# Rule: ACT-1 ACT-2 ACT-3 ACT-4 ACT-5 ACT-6 HALT-4 MINER-1 MINER-2 TAG-3 REG-1 FEE-2 BLK-1 BLK-2 SNAP UNDO
class YellowbackActivationTest(YellowbackTestFramework):

    def activation(self, i=2):
        return self.nodes[i].yed_getactivation()

    def count(self, i=2):
        return self.activation(i)['signalCount']

    def mine_forged(self, price_micro_usd, key_hash, n):
        """Node 1 mines ``n`` blocks whose coinbase carries a forged quote tag with the signal bit
        under ``key_hash`` (any coinbase may carry YED! with bit 0, TAG-3)."""
        hashes = []
        for _ in range(n):
            cb, gbt = template_coinbase(self.nodes[STOCK])
            cb.vin[0].scriptSig = ym.height_prefix(gbt['height']) + ym.tag_push(1, price_micro_usd, 1, key_hash)
            result, blockhash = mine_block_raw(self.nodes[STOCK], [], coinbase=cb, gbt=gbt)
            assert result is None, result
            hashes.append(blockhash)
            self.sync_all(blocks_only=True)
        return hashes

    def run_test(self):
        nodes = self.nodes
        user = nodes[USER]
        for pool in POOLS:
            self.quote(pool, '2.00')
        self.mine(USER, 60)      # mature node 0's coinbases for the raw mints below

        # ------------------------------------------------------------------ act_forged_signal_tags
        print('act_forged_signal_tags: node 1 (stock) mines forged signal tags under a random key')
        forged_secret = hashlib.sha256(b'yellowback-forged-signal').digest()
        forged_pubkey = secret_to_pubkey(forged_secret)
        forged_key = ym.hash160(forged_pubkey)
        forged_address = pubkey_to_address(forged_pubkey)
        base = nodes[2].getblockcount()
        assert_equal(self.count(), 0)
        t0 = time.time()
        forged = self.mine_forged(2_000_000, forged_key, ACTIVATION_THRESHOLD - 1)
        print('  %d forged blocks in %.0fs' % (len(forged), time.time() - t0))
        for i in ENFORCING:
            a = self.activation(i)
            assert_equal(a['status'], 'signaling')
            assert_equal(a['signalCount'], ACTIVATION_THRESHOLD - 1)
        forged += self.mine_forged(2_000_000, forged_key, 1)
        lock_in = base + ACTIVATION_THRESHOLD
        for i in ENFORCING + [OBSERVER]:
            a = self.activation(i)
            assert_equal(a['status'], 'locked_in')                    # the count is self-reported (N4)
            assert_equal(a['lockInHeight'], lock_in)
            assert_equal(a['signalCount'], ACTIVATION_THRESHOLD)
        miners = nodes[OBSERVER].yed_listminers(lock_in, SIGNAL_WINDOW)
        assert_equal([m['payoutAddress'] for m in miners], [forged_address])
        assert_equal(miners[0]['quoteTags'], ACTIVATION_THRESHOLD)
        tag = nodes[OBSERVER].yed_gettag(str(lock_in))
        assert_equal((tag['found'], tag['kind'], tag['signal'], tag['payoutAddress']), (True, 'quote', True, forged_address))
        assert_same_statehash(self.enforcing_nodes() + [nodes[OBSERVER]])
        print('  rewind the forged branch (invalidateblock on every node): UNDO restores Activation')
        for node in nodes:
            node.invalidateblock(forged[0])
        self.sync_all(blocks_only=True)
        assert_equal(nodes[2].getblockcount(), base)
        for i in ENFORCING:
            a = self.activation(i)
            assert_equal((a['status'], a['lockInHeight'], a['signalCount']), ('signaling', 0, 0))
        assert_same_statehash(self.enforcing_nodes() + [nodes[OBSERVER]])

        # ------------------------------------------------------------------ 2 of 3 never lock in
        print('two of three pools signalling never lock in (node 4 without -yellowbacksignal)')
        self.restart(4, ['-yellowbacksignal=0'])
        wait_yed_healthy(nodes[4])
        self.quote(4, '2.00')
        assert_equal(nodes[4].yed_getinfo()['miner']['signal'], False)
        self.mine_round_robin(POOLS, SIGNAL_WINDOW + 8)
        a = self.activation()
        assert_equal(a['status'], 'signaling')
        assert_equal(a['lockInHeight'], 0)
        assert PARTICIPATION_FLOOR <= a['signalCount'] < ACTIVATION_THRESHOLD, a      # 42 or 43 of 64
        assert_same_statehash(self.enforcing_nodes())

        # ------------------------------------------------------------------ K16 + act2
        print('clear the window with 64 stock blocks; then lock-in at exactly the 48th signal with 16 stock blocks interleaved')
        self.restart(4)
        wait_yed_healthy(nodes[4])
        self.quote(4, '2.00')
        nodes[STOCK].generate(SIGNAL_WINDOW)
        self.sync_all(blocks_only=True)
        assert_equal(self.count(), 0)
        schedule = [2, 3, 4, STOCK] * 20
        lock_in = None
        for miner in schedule:
            before = self.count()
            if before == ACTIVATION_THRESHOLD - 1 and miner in POOLS:
                break
            assert_equal(self.activation()['status'], 'signaling')
            nodes[miner].generate(1)
            self.sync_all(blocks_only=True)
            assert self.count() < ACTIVATION_THRESHOLD, 'the window reached 48 unexpectedly'
        print('act2_reorg_across_lockin: split at 47 signals')
        assert_equal(self.count(), ACTIVATION_THRESHOLD - 1)
        split_height = nodes[2].getblockcount()
        self.split_network()
        a_block = nodes[2].generate(1)[0]                              # branch A: the 48th signal
        self.sync_all(blocks_only=True)
        lock_in = split_height + 1
        for i in ENFORCING:
            a = self.activation(i)
            assert_equal((a['status'], a['lockInHeight'], a['signalCount']), ('locked_in', lock_in, ACTIVATION_THRESHOLD))
        b_blocks = nodes[STOCK].generate(2)                            # branch B: stock blocks, no lock-in
        self.join_network()                                            # B wins
        assert_best_hash(nodes)
        assert_equal(nodes[2].getbestblockhash(), b_blocks[-1])
        for i in ENFORCING:
            a = self.activation(i)
            assert_equal((a['status'], a['lockInHeight']), ('signaling', 0))
        assert_same_statehash(self.enforcing_nodes() + [nodes[OBSERVER]])
        print('  then A wins: locked_in again at the same height')
        for i in ENFORCING:
            nodes[i].invalidateblock(b_blocks[0])
        for i in ENFORCING:
            assert_equal(nodes[i].getbestblockhash(), a_block)
            a = self.activation(i)
            assert_equal((a['status'], a['lockInHeight']), ('locked_in', lock_in))
        nodes[3].generate(2)                                           # A outruns B; node 1 and 5 follow
        self.sync_all(blocks_only=True)
        for i in ENFORCING:
            nodes[i].reconsiderblock(b_blocks[0])
        self.sync_all(blocks_only=True)
        assert_best_hash(nodes)
        assert_equal(self.activation()['lockInHeight'], lock_in)
        assert_equal(self.activation(OBSERVER)['lockInHeight'], lock_in)
        assert_same_statehash(self.enforcing_nodes() + [nodes[OBSERVER]])

        # ------------------------------------------------------------------ activation + act3
        print('activation at lockIn + 64 (act3_reorg_across_activateheight straddles it)')
        activate_height = lock_in + ACTIVATION_DELAY
        while nodes[2].getblockcount() < activate_height - 1:
            self.mine_round_robin([2, 3, 4, STOCK], 1)
        assert_equal(self.activation()['status'], 'locked_in')
        self.split_network()
        nodes[2].generate(1)                                           # A: activateHeight
        self.sync_all(blocks_only=True)
        a = self.activation()
        assert_equal((a['status'], a['activateHeight']), ('active', activate_height))
        est = user.yed_estimatecollateral(10_000, 48)
        ref = user.getblockcount() - REF_LAG                           # activateHeight - 1: not yet ACTIVE
        # nExpiryHeight is the height of A's block itself, so when B wins the reorg returns the
        # transaction to the branch-A mempools and the very next ConnectTip expires it again —
        # nodes 1 and 5 never saw it, and a lingering copy would desync every later sync_all.
        void_hex, _ = build_mint_tx(user, 10_000, 48, ref, int(est['requiredZat']),
                                    expiry=activate_height + 1)
        void_txid = ym.tx_from_hex(void_hex).txid
        # TPL-2 (strict, the default) skips a MINT whose verdict would be VOID, so no pool's own
        # template will ever carry this transaction: node 3's block is assembled in Python.
        result, _ = mine_block_raw(nodes[3], [void_hex])               # A: activateHeight + 1, the first enforced height
        assert result is None, result
        self.sync_all(blocks_only=True)
        void_vault = user.yed_getvault(void_txid)
        assert_equal(void_vault['status'], 'VOID')
        assert_equal(void_vault['voidReason'], 'mint-not-active')
        assert 'sweepBefore' in void_vault
        assert_equal(void_vault['sweepBefore'], void_vault['claimHeight'])
        b_blocks = nodes[STOCK].generate(3)                            # B: activateHeight .. + 2
        self.join_network()                                            # B wins: on, off, on across activateHeight + 1
        assert_best_hash(nodes)
        assert_equal(nodes[2].getbestblockhash(), b_blocks[-1])
        for i in ENFORCING + [OBSERVER]:
            a = self.activation(i)
            assert_equal((a['status'], a['lockInHeight'], a['activateHeight']), ('active', lock_in, activate_height))
            assert_equal(nodes[i].yed_getinfo()['rejectedBlocks'], 0)
        assert rpc_error_message(user.yed_getvault, void_txid).startswith('vault-not-found')
        assert_same_statehash(self.enforcing_nodes() + [nodes[OBSERVER]])

        # ------------------------------------------------------------------ halts and the ladder
        print('two ACTIVE vaults for the rejection cases')
        self.mine_round_robin(POOLS, REF_LAG + 1)
        assert_equal(nodes[2].yed_getstats()['mintingAllowed'], True)
        vault1_txid, vault1 = mint_vault_raw(self, user, POOLS[0])
        vault2_txid, vault2 = mint_vault_raw(self, user, POOLS[1])

        print('participation: one pool stops signalling for a window (43 of 64): no halt')
        self.restart(4, ['-yellowbacksignal=0'])
        wait_yed_healthy(nodes[4])
        self.quote(4, '2.00')
        self.mine_round_robin(POOLS, SIGNAL_WINDOW)
        a = self.activation()
        assert_greater_than(a['signalCount'], PARTICIPATION_FLOOR - 1)
        assert_equal((a['mintHalted'], a['enforcementSuspended'], a['status']), (False, False, 'active'))
        assert_equal(nodes[2].yed_getstats()['mintingAllowed'], True)

        print('node 1 at 45 %% (about 35 signals): the mint halt sets, enforcement stays on, a rule-breaking block is rejected')
        self.restart(4)
        wait_yed_healthy(nodes[4])
        self.quote(4, '2.00')
        self.mine_round_robin([2, 3, 4, STOCK], SIGNAL_WINDOW, shares=[55, 55, 55, 135])
        a = self.activation()
        assert a['signalCount'] < PARTICIPATION_FLOOR, a
        assert a['signalCount'] >= ENFORCEMENT_FLOOR, a
        assert_equal((a['mintHalted'], a['enforcementSuspended']), (True, False))
        assert_equal(nodes[2].yed_getstats()['mintingAllowed'], False)
        assert 'PARTICIPATION' in nodes[2].yed_getstats()['haltMask']
        while user.getblockcount() < int(vault1['lockHeight']):    # 20-block chunks keep the 45 % share (n = 1 would give every block to node 1)
            self.mine_round_robin([2, 3, 4, STOCK], 20, shares=[55, 55, 55, 135])
            assert self.activation()['signalCount'] >= ENFORCEMENT_FLOOR
        rejected, _ = mine_rejected_block(self, user, vault1)
        wait_for_rejection(self.enforcing_nodes(), rejected)
        assert_banscore_zero(nodes)
        sync_blocks([nodes[STOCK], nodes[OBSERVER]])
        assert_equal(nodes[OBSERVER].getbestblockhash(), rejected)   # the observer follows the stock miner
        nodes[POOLS[0]].generate(2)                                    # two blocks outrun the rejected one: node 1 and 5 rejoin
        self.sync_all(blocks_only=True)
        assert_best_hash(nodes)
        self.mine_round_robin(POOLS, 3)                                # the spend expires from node 1's mempool
        assert_equal(user.yed_getvault(vault1_txid)['status'], 'ACTIVE')

        print('node 1 at 55 %% (about 29 signals): enforcement suspends (ACT-6) and the same spend is accepted (ACT-5)')
        self.mine_round_robin([2, 3, 4, STOCK], SIGNAL_WINDOW, shares=[15, 15, 15, 55])
        a = self.activation()
        assert a['signalCount'] < ENFORCEMENT_FLOOR, a
        assert_equal((a['mintHalted'], a['enforcementSuspended']), (True, True))
        assert 'ENFORCEMENT' in nodes[2].yed_getstats()['haltMask']
        assert_equal(nodes[2].yed_getinfo()['enforcing'], True)        # the node-side flag: ACT-5 is what is off
        accepted, _ = mine_rejected_block(self, user, vault1)
        self.sync_all(blocks_only=True)
        assert_equal(len({n.getbestblockhash() for n in nodes}), 1)   # no partition (N35)
        assert_equal(nodes[2].getbestblockhash(), accepted)
        closed = user.yed_getvault(vault1_txid)
        assert_equal((closed['status'], closed['unbacked']), ('CLOSED', True))
        nodes[STOCK].generate(20)
        self.sync_all(blocks_only=True)
        assert_equal(len({n.getbestblockhash() for n in nodes}), 1)
        assert_same_statehash(self.enforcing_nodes() + [nodes[OBSERVER]])

        print('hysteresis (L3): enforcement resumes at >= 39, minting only at >= 48')
        while self.count() < ENFORCEMENT_RESUME:                    # node 1 at 30 %: the window climbs to about 45
            self.mine_round_robin([2, 3, 4, STOCK], 20, shares=[70, 70, 70, 90])
        a = self.activation()
        assert ENFORCEMENT_RESUME <= a['signalCount'] < ACTIVATION_THRESHOLD, a
        assert_equal((a['mintHalted'], a['enforcementSuspended']), (True, False))
        while self.count() < ACTIVATION_THRESHOLD:
            self.mine_round_robin(POOLS, 1)
        a = self.activation()
        assert_equal((a['mintHalted'], a['enforcementSuspended']), (False, False))
        assert_equal(nodes[2].yed_getstats()['mintingAllowed'], True)
        self.mine_round_robin(POOLS, SIGNAL_WINDOW)                   # a full window of pool blocks
        assert_equal(self.count(), SIGNAL_WINDOW)

        # ------------------------------------------------------------------ MINER-1 and the observer
        print('a node with -yellowbackenforce=0 emits tags without the signal bit (MINER-1); node 5 reports the same activation')
        observer_addr = nodes[OBSERVER].getnewaddress()
        self.restart(OBSERVER, ['-yellowbackpayoutaddress=%s' % observer_addr, '-yellowbacksignal=1'])
        wait_yed_healthy(nodes[OBSERVER])
        self.quote(OBSERVER, '2.00')
        assert_equal(nodes[OBSERVER].yed_getinfo()['miner']['signal'], False)
        tip_hash = self.mine(OBSERVER)[0]
        tag = nodes[2].yed_gettag(tip_hash)
        assert_equal((tag['found'], tag['kind'], tag['signal'], tag['payoutAddress']), (True, 'quote', False, observer_addr))
        a2, a5 = self.activation(2), self.activation(OBSERVER)
        for key in ('status', 'lockInHeight', 'activateHeight', 'signalCount'):
            assert_equal(a5[key], a2[key])
        assert_equal(a5['enforcing'], False)

        # ------------------------------------------------------------------ tag3
        print('tag3_signal_only_registers_nobody: 24 signal-only blocks from node 2')
        self.quote(2, '0', 0)
        assert_equal(nodes[2].yed_getinfo()['miner']['quoteKind'], 'signal')
        self.mine_round_robin([2, 2, 2, 3, 4], N_REG * 5 // 3)
        tip = nodes[2].getblockcount()
        pool2 = self.pool_addresses[0]
        assert pool2 not in [m['payoutAddress'] for m in nodes[3].yed_listminers()]
        eligible = nodes[3].yed_getfeepayee(tip - REF_LAG, int(vault2['collateralZat']))['eligible']
        assert pool2 not in eligible
        assert_equal(sorted(eligible), sorted(self.pool_addresses[1:]))
        # Signal-only tags still count: the only block in the trailing window without the signal
        # bit is node 5's single block from the MINER-1 case above (41 blocks back of 64).
        assert_equal(self.count(), SIGNAL_WINDOW - 1)
        window = [nodes[2].yed_gettag(str(h)) for h in range(tip - N_REG * 5 // 3 + 1, tip + 1)]
        assert_equal([t['signal'] for t in window], [True] * (N_REG * 5 // 3))
        self.quote(2, '2.00')

        # ------------------------------------------------------------------ act5_past_sunset_accepts
        print('act5_past_sunset_accepts: ENFORCE_UNTIL_HEIGHT = tip + 5 on every module node')
        until = nodes[2].getblockcount() + 5
        for i in ENFORCING + [OBSERVER]:
            extra = ['-yellowbackenforceuntil=%d' % until]
            if i == OBSERVER:
                extra += ['-yellowbackpayoutaddress=%s' % observer_addr, '-yellowbacksignal=1']
            self.restart(i, extra)
        for i in ENFORCING:
            wait_yed_healthy(nodes[i], timeout=180)
        for pool in POOLS:
            self.quote(pool, '2.00')
        assert_equal(nodes[2].yed_getinfo()['sunset'], False)
        assert_equal(nodes[2].yed_getinfo()['miner']['signal'], True)
        self.mine_round_robin(POOLS, 5)
        info = nodes[2].yed_getinfo()
        assert_equal((info['sunset'], info['enforcing'], info['miner']['signal']), (True, False, False))
        assert_equal(nodes[2].yed_getactivation()['enforceUntilHeight'], until)
        tip_hash = self.mine(POOLS[2])[0]
        assert_equal(nodes[2].yed_gettag(tip_hash)['signal'], False)   # no signal bit past the sunset
        while user.getblockcount() < int(vault2['lockHeight']):
            self.mine_round_robin(POOLS, 1)
        accepted, _ = mine_rejected_block(self, user, vault2)
        self.sync_all(blocks_only=True)
        assert_equal(len({n.getbestblockhash() for n in nodes}), 1)
        assert_equal(nodes[2].getbestblockhash(), accepted)
        for i in ENFORCING:
            v = nodes[i].yed_getvault(vault2_txid)
            assert_equal((v['status'], v['unbacked']), ('CLOSED', True))
            assert_equal(nodes[i].yed_getinfo()['rejectedBlocks'], 0)
        assert_same_statehash(self.enforcing_nodes() + [nodes[OBSERVER]])

        # ------------------------------------------------------------------ the model
        print('assert_model_matches(node 2) (N23)')
        assert_model_matches(nodes[2])
        self.checkpoint('end')


if __name__ == '__main__':
    YellowbackActivationTest().main()
