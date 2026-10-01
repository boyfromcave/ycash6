#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Phase 5 (plan section 6, Phase 5; section 3.9 BLK-1..3, ACT-5..7, TPL-1/2, MP-1; section 8.1):
the soft fork end to end against a stock miner.

Every vault is created with ``build_mint_tx`` and every spend with ``build_vault_spend_raw`` (the
correct ones too, with ``payload=REDEEM(feeVout)`` and ``fee=(addr, zat)``); ``yed_mint`` /
``yed_redeem`` belong to Phase 6 (N26).  ``checkpoint(label)`` runs after every mined block (N35)
-- over the group that is actually on one chain, since half of this script is about the two
chains disagreeing.

Topology (section 6.0 item 2): 0 user (enforcing), 1 stock miner (the adversary; ``--stock-binary``
makes it a real v4.5.0 binary, P9), 2-4 pools (enforcing, signalling), 5 observer
(``-yellowbackenforce=0``, records ``unbacked``).
"""

import random
import time

from test_framework.authproxy import JSONRPCException
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    bytes_to_hex_str,
    connect_nodes_bi,
    hex_str_to_bytes,
    p2p_port,
    sync_blocks,
)
from test_framework.yellowback_util import (
    ENFORCING,
    GRACE,
    OBSERVER,
    POOLS,
    REF_LAG,
    REF_WINDOW,
    STOCK,
    TOKEN_VALUE,
    USER,
    VALVE_BLOCKS,
    YELLOWBACK_FEE,
    YellowbackTestFramework,
    _select_funding,
    assert_banscore_zero,
    assert_best_hash,
    assert_same_statehash,
    build_mint_tx,
    build_vault_spend_raw,
    debug_log_contains,
    mine_block_raw,
    template_coinbase,
    vault_from_mint,
    wait_for_rejection,
    wait_yed_healthy,
    ym,
)

PRICE = '20.00'       # a high YEC price keeps the class-A collateral (500% of $100) at 25 YEC,
CRASH_PRICE = '1.00'  # which node 0's 101 mature coinbases can fund eight times over
CENTS = 10_000          # $100, the class-A minimum mint
LOCK = 48               # class A minimum lock
TX_SOON = 3             # TX_EXPIRING_SOON_THRESHOLD


def rpc_error(substr, fn, *args):
    try:
        fn(*args)
    except JSONRPCException as e:
        assert substr in e.error['message'], 'expected %r in %r' % (substr, e.error['message'])
        return e.error['message']
    raise AssertionError('expected an RPC error containing %r' % substr)


def spk(node, addr):
    return hex_str_to_bytes(node.validateaddress(addr)['scriptPubKey'])


class YellowbackEnforcementTest(YellowbackTestFramework):
    # node 0 needs many mature coinbases: every vault below is 250 YEC of collateral and the
    # 101 initial blocks leave exactly one mature coinbase (mapping.md section 13.5).
    initial_blocks = 101
    # Several cases take one enforcing node out of the network (an isolated pool mining a
    # competing branch; a pool restarted with -yellowbackenforce=0 that follows node 1).  On the
    # framework's star-plus-2<->3<->4 that disconnects the rest of the enforcing half from each
    # other, so this script makes {0, 2, 3, 4} a complete graph.  Node 1 is still the only route
    # to the stock miner and node 5 still hangs off node 1 alone (section 6.0 item 4).
    EDGES = YellowbackTestFramework.EDGES + [(2, 4), (0, 3), (0, 4)]

    def add_options(self, parser):
        super().add_options(parser)
        parser.add_option('--extended', dest='extended', default=False, action='store_true',
                          help='the nightly 200-block randomized run (case 8)')
        parser.add_option('--extended-blocks', dest='extended_blocks', default=200, type='int',
                          help='length of the --extended run (default 200)')
        parser.add_option('--only', dest='only', default=None,
                          help='comma-separated case method names (development)')

    def node_args(self, i, extra=None):
        # -debug=yellowback makes the hook's own decisions (suppressed / rejected / noted)
        # readable in debug.log, which several assertions below grep
        return super().node_args(i, ['-debug=yellowback'] + list(extra or []))

    # ------------------------------------------------------------------ helpers

    def cp(self, label, group=None):
        """``checkpoint`` over ``group`` (indices) rather than the whole network: this script
        spends most of its time with node 1 on a chain the enforcing nodes refuse."""
        if group is None:
            return self.checkpoint(label)
        nodes = [self.nodes[i] for i in group if self.nodes[i] is not None]
        sync_blocks(nodes)
        assert_best_hash(nodes, label)
        enforcing = [self.nodes[i] for i in group if i in ENFORCING]
        if len(enforcing) > 1:
            assert_same_statehash(enforcing, label)
        return nodes[0].getbestblockhash()

    def reset_peer_scores(self):
        """Drop and re-make every connection of the current topology.

        ``banscore`` lives in ``CNodeState``, which is per *connection*, and it never decays.
        This script manufactures many reorgs, and two v4.5.0 DoS paths fire on them --
        ``tx-expired`` when node 1 re-relays a spend past its expiry, and ``bad-prevblk``
        "prev block not found" at DoS 10 when a peer fetches a reconnected branch's tip block
        before its headers (``ref/ycash/src/main.cpp:4555``).  Neither is a Yellowback verdict:
        Yellowback only ever uses ``DoS(0)`` and the ``DoS([1-9]`` grep over ``src/yellowback``
        and ``src/rpc/yellowback*.cpp`` is empty.  Re-making the connections gives every peer a
        fresh ``CNodeState``, so the N1 assertions that follow measure Yellowback alone."""
        cross = self._cross_edges() if self.is_network_split else []
        edges = [(a, b) for a, b in self.live_edges() if (a, b) not in cross]
        for a, b in edges:
            self._disconnect_pair(a, b)
        time.sleep(1.5)
        for a, b in edges:
            if self.nodes[a] is not None and self.nodes[b] is not None:
                connect_nodes_bi(self.nodes, a, b)
        time.sleep(2)
        assert_banscore_zero([n for n in self.nodes if n is not None])

    def pools_mine(self, n, label='', group=None):
        """Mine ``n`` blocks round-robin over the pools, one at a time, checkpointing the
        enforcing group after each (N35)."""
        group = ENFORCING if group is None else group
        for k in range(n):
            i = POOLS[k % len(POOLS)]
            self.nodes[i].generate(1)
            self.cp('%s+%d' % (label or 'pool block', k + 1), group)

    def stock_mine(self, n, label='', group=(STOCK, OBSERVER)):
        for k in range(n):
            self.nodes[STOCK].generate(1)
            self.cp('%s+%d' % (label or 'stock block', k + 1), list(group))

    def mint_inputs(self, cents=CENTS, lock=LOCK):
        node = self.nodes[USER]
        est = node.yed_estimatecollateral(cents, lock)
        ref = int(est['refHeight'])
        required = int(est['requiredZat'])
        payee = node.yed_getfeepayee(ref, required)['default']['payoutAddress']
        return ref, required, payee

    def mint(self, cents=CENTS, lock=LOCK, send=True):
        """One raw MINT from node 0's coins; returns the ``vault_from_mint`` dict plus the txid
        and its token outpoint.  The caller mines it."""
        user = self.nodes[USER]
        ref, required, payee = self.mint_inputs(cents, lock)
        hex_, owner = build_mint_tx(user, cents, lock, ref, required, fee_addr=payee)
        if send:
            user.sendrawtransaction(hex_)
            user.lockunspent(False, [{'txid': i.prev_txid, 'vout': i.prev_n} for i in ym.tx_from_hex(hex_).vin])
        v = vault_from_mint(hex_, lock, ref, owner)
        v['token'] = (v['txid'], 1)
        v['cents'] = cents
        return v

    def live_vault(self, built, node=None):
        """``yed_getvault`` plus the P2PKH ``ownerAddress`` the Python signer needs."""
        node = node or self.nodes[USER]
        v = dict(node.yed_getvault(built['txid']))
        v['ownerAddress'] = built['ownerAddress']
        v['token'] = built.get('token')
        v['cents'] = built.get('cents')
        return v

    def build_transfer(self, node, tokens, assignments, owner_hexes):
        """Split YED tokens: a TRANSFER of ``tokens`` into ``assignments`` cents, one fresh
        P2PKH output each, funded and signed by ``node``'s wallet."""
        prevtxs = [{'txid': t, 'vout': n,
                    'scriptPubKey': bytes_to_hex_str(ym.p2pkh_script(ym.hash160(hex_str_to_bytes(o)))),
                    'amount': TOKEN_VALUE / 1e8}
                   for (t, n), o in zip(tokens, owner_hexes)]
        vout = [(TOKEN_VALUE, spk(node, node.getnewaddress())) for _ in assignments]
        vout.append((0, bytes([ym.OP_RETURN]) + ym.push(ym.encode_transfer(list(enumerate(assignments))))))
        needed = TOKEN_VALUE * len(assignments) + YELLOWBACK_FEE - TOKEN_VALUE * len(tokens)
        utxos, total = _select_funding(node, max(needed, 1))
        if total - needed > 0:
            vout.append((total - needed, spk(node, node.getnewaddress())))
        vin = [(t, n, b'', 0xFFFFFFFF) for t, n in tokens] + [(u['txid'], u['vout'], b'', 0xFFFFFFFF) for u in utxos]
        raw = ym.serialize_tx_v4(vin, vout, 0, node.getblockcount() + REF_WINDOW)
        signed = node.signrawtransaction(bytes_to_hex_str(raw), prevtxs)
        assert_equal(signed['complete'], True)
        return signed['hex']

    def correct_redeem(self, vault, expiry=None):
        """The RED-1..4-passing owner-path redemption: REDEEM payload with ``feeVout = 1``, the
        FEE-1 fee to the FEE-W payee, the burn of the vault's own token."""
        user = self.nodes[USER]
        live = self.live_vault(vault)
        ref = user.getblockcount() - REF_LAG
        payee = user.yed_getfeepayee(ref, int(live['collateralZat']))
        return build_vault_spend_raw(user, live, 'owner', [vault['token']],
                                     payload=ym.encode_redeem(ref, 1, []),
                                     fee=(payee['default']['payoutAddress'], int(payee['feeZat'])),
                                     ref_height=ref, expiry=expiry)

    def bad_spend(self, vault, kind, expiry=0):
        # nExpiryHeight = 0 (M13) on every adversarial spend: MP-1 refuses it on every overlay
        # node either way, the stock node accepts it, and nothing ever hits Ycash's own
        # tx-expired DoS 10 when node 1 re-relays it after a reorg -- a v4.5.0 behaviour that
        # would otherwise be mistaken for a Yellowback ban.  clear_stock_mempool() is what stops
        # such a spend riding along in a later stock block.
        """One rule-breaking spend of ``vault``.  ``kind``:
        ``owner-noburn``  owner path, no burn, no payload            (RED-1 vault-spend-malformed)
        ``claim-noburn``  claim path, no burn, no payload            (RED-1, R2)
        ``short-burn``    owner path, a part-value token burned      (RED-2)
        ``wrong-payee``   owner path, correct burn, fee to node 0    (RED-3)
        ``short-fee``     owner path, correct burn, half the fee     (RED-3)
        ``mint-payload``  owner path, correct burn+fee, MINT payload (RED-1, M3)
        """
        user = self.nodes[USER]
        live = self.live_vault(vault)
        ref = user.getblockcount() - REF_LAG
        collateral = int(live['collateralZat'])
        if kind == 'owner-noburn':
            return build_vault_spend_raw(user, live, 'owner', [], expiry=expiry)
        if kind == 'claim-noburn':
            return build_vault_spend_raw(user, live, 'claim', [], expiry=expiry)
        payee = user.yed_getfeepayee(ref, collateral)   # the rest carry a fee output
        addr, fee = payee['default']['payoutAddress'], int(payee['feeZat'])
        if kind == 'short-burn':
            return build_vault_spend_raw(user, live, 'owner', [vault['short_token']],
                                         payload=ym.encode_redeem(ref, 1, []), fee=(addr, fee),
                                         ref_height=ref, expiry=expiry)
        if kind == 'wrong-payee':
            return build_vault_spend_raw(user, live, 'owner', [vault['token']],
                                         payload=ym.encode_redeem(ref, 1, []),
                                         fee=(user.getnewaddress(), fee), ref_height=ref, expiry=expiry)
        if kind == 'short-fee':
            return build_vault_spend_raw(user, live, 'owner', [vault['token']],
                                         payload=ym.encode_redeem(ref, 1, []),
                                         fee=(addr, fee // 2), ref_height=ref, expiry=expiry)
        if kind == 'mint-payload':
            owner = hex_str_to_bytes(live['ownerPubKey'])
            payload = ym.encode_mint(0, vault['cents'], int(live['lockHeight']), ref, owner, 1)
            return build_vault_spend_raw(user, live, 'owner', [vault['token']], payload=payload,
                                         fee=(addr, fee), ref_height=ref, expiry=expiry)
        raise AssertionError('unknown kind %r' % kind)

    def stock_block_with(self, hex_):
        """The stock node mines one block carrying ``hex_``.  Returns ``(blockhash, txid)``."""
        stock = self.nodes[STOCK]
        txid = stock.sendrawtransaction(hex_)
        blockhash = stock.generate(1)[0]
        assert txid in stock.getblock(blockhash)['tx']
        return blockhash, txid

    def assert_rejected_everywhere(self, blockhash, nodes=None, banscore=True):
        """Every enforcing node rejected ``blockhash`` at DoS 0, still peers with node 1, and can
        explain the rejection (``yed_getblockverdict``, case 7)."""
        nodes = ENFORCING if nodes is None else nodes
        wait_for_rejection([self.nodes[i] for i in nodes], blockhash)
        if banscore:
            assert_banscore_zero([self.nodes[i] for i in nodes])
        for i in nodes:
            verdict = self.nodes[i].yed_getblockverdict(blockhash)
            assert_equal(verdict['blockInvalid'], True)
            assert verdict['reason'], 'empty reason for a rejected block on node %d' % i
            self.assert_peers_with_stock(i)

    def assert_peers_with_stock(self, i):
        addr = '127.0.0.1:%d' % p2p_port(STOCK)
        assert any(p['addr'] == addr for p in self.nodes[i].getpeerinfo()), \
            'node %d lost node 1 as a peer (N1)' % i

    def pools_outmine(self, target_hash, limit=40):
        """Mine on the pools until every node (node 1 and node 5 included) is on the pools'
        chain: the enforcing branch out-works the stock branch and the network converges."""
        k = 0
        while self.nodes[STOCK].getbestblockhash() != self.nodes[POOLS[0]].getbestblockhash():
            assert k < limit, 'the pools did not out-mine the stock branch in %d blocks' % limit
            self.nodes[POOLS[k % len(POOLS)]].generate(1)
            self.cp('out-mine+%d' % (k + 1), ENFORCING)
            k += 1
            time.sleep(0.3)
        self.clear_stock_mempool()
        self.cp('converged')
        assert target_hash is None or self.nodes[USER].getblock(target_hash)['confirmations'] == -1
        return k

    def clear_stock_mempool(self):
        """Restart node 1 when its mempool still holds a rule-breaking spend: Ycash 4.5 does not
        persist the mempool, and a lingering spend would ride along in every later stock block
        (and, once past its nExpiryHeight, cost the relaying peer the stock tx-expired DoS 10 --
        a v4.5.0 behaviour this script must not confuse with a Yellowback verdict)."""
        if self.nodes[STOCK].getrawmempool():
            self.restart(STOCK)
            time.sleep(1)

    def crash_price(self, blocks=36):
        """Drive ``pClaim = max(pMid, pSlow)`` down by quoting ``CRASH_PRICE`` from every pool
        until more than half of the 64-block slow window carries it (RED-4's underwater test)."""
        for i in POOLS:
            self.quote(i, CRASH_PRICE)
        self.pools_mine(blocks, 'crash')

    # ------------------------------------------------------------------ run

    def run_test(self):
        for node in self.enforcing_nodes():
            wait_yed_healthy(node)

        cases = [
            self.case4_before_activation_accepts,
            self.activate_and_mint,
            self.case1_owner_path_no_burn,
            self.case2_claim_and_fee_variants,
            self.case13_m3_vault_spend_with_mint_payload,
            self.case11_fee2_reorg_changes_eligible_set,
            self.case12_red1_refheight_window_after_reorg,
            self.case3_correct_spends_from_the_stock_node,
            self.case10_tag4_garbage_coinbase_never_invalid,
            self.case7_bookkeeping,
            self.case6_fail_open_on_storage_only,
            self.case5_kill_switch,
            self.case15_valve_catchup_offline_node,
            self.case9_work_valve,
        ]
        if self.options.only:
            wanted = set(self.options.only.split(','))
            cases = [c for c in cases if c.__name__ in wanted or c.__name__ == 'activate_and_mint']
        for case in cases:
            print('=== %s' % case.__name__)
            case()
        if self.options.extended:
            self.case8_extended_random_activity()

    # ------------------------------------------------------------------ case 4

    def case4_before_activation_accepts(self):
        """Before activation BLK-1 has nothing to reject: MINT-4 voids every mint whose
        ``Snapshots[refHeight]`` is not ACTIVE (K16), and a VOID vault's spend is an ordinary
        spend (K3), so the stock node's rule-breaking block is accepted by every node with
        ``rejectedBlocks == 0``."""
# Rule: BLK-1
# Rule: ACT-5
# Rule: K3
        user = self.nodes[USER]
        self.pools_mine(3, 'pre-activation')
        for i in ENFORCING:
            assert self.nodes[i].yed_getactivation()['status'] != 'active'
        ref = user.getblockcount() - REF_LAG
        # yed_estimatecollateral has no price before activation (MINT-4/HALT-1): a literal
        # collateral is enough, the mint is VOID whatever it locks.
        assert_equal(user.yed_estimatecollateral(CENTS, LOCK)['requiredZat'], None)
        hex_, owner = build_mint_tx(user, CENTS, LOCK, ref, 20 * 100000000)
        txid = user.sendrawtransaction(hex_)
        vault = vault_from_mint(hex_, LOCK, ref, owner)
        vault['token'] = (txid, 1)
        vault['cents'] = CENTS
        self.sync_all()
        # TPL-2 declines a mint whose verdict would be VOID, so the stock node mines it
        self.stock_mine_and_sync(1, 'void mint')
        assert_equal(user.yed_getvault(txid)['status'], 'VOID')     # MINT-4: no ACTIVE snapshot
        # past the lock, then the same "owner path without a burn" block the rest of the script uses
        self.pools_mine(LOCK + 2, 'to the lock')
        bad = self.bad_spend(vault, 'owner-noburn')
        blockhash, _ = self.stock_block_with(bad)
        self.cp('pre-activation rule-breaking block accepted')
        assert_best_hash([self.nodes[i] for i in range(6)], 'pre-activation')
        for i in ENFORCING + [OBSERVER]:
            assert_equal(self.nodes[i].yed_getinfo()['rejectedBlocks'], 0)
            assert_equal(self.nodes[i].getblock(blockhash)['confirmations'], 1)
        assert_banscore_zero([self.nodes[i] for i in range(6)])
        self.void_vault_closed = txid

    # ------------------------------------------------------------------ setup

    def activate_and_mint(self):
        """``activate()`` then the vaults every later case spends, all past their claim height."""
        print('activation (%d blocks)' % (64 + 64 + 1))
        self.activate(quote_usd=PRICE)
        self.pools_mine(REF_LAG + 1, 'post-activation')
        for i in ENFORCING:
            assert_equal(self.nodes[i].yed_getinfo()['enforcing'], True)
        self.cp('active')

        self.rejected_hashes = []
        self.vaults = []
        for _ in range(8):
            self.vaults.append(self.mint())
        self.sync_all()
        for k in range(6):
            self.pools_mine(1, 'mints')
            missing = [v['txid'] for v in self.vaults
                       if self.nodes[USER].gettransaction(v['txid'])['confirmations'] < 1]
            if not missing:
                break
            print('  %d mint(s) still unconfirmed after %d blocks; mempool=%s' %
                  (len(missing), k + 1, [t for t in missing if t in self.nodes[USER].getrawmempool()]))
        assert not missing, 'mints never confirmed: %s' % missing
        for v in self.vaults:
            info = self.nodes[USER].yed_gettxinfo(v['txid'])
            assert_equal((v['txid'], info['verdict']), (v['txid'], 'ok'))
            assert_equal(self.nodes[USER].yed_getvault(v['txid'])['status'], 'ACTIVE')
        # split one vault's token into 4,000 + 6,000 so a "short burn" exists (RED-2)
        short = self.vaults[2]
        split = self.build_transfer(self.nodes[USER], [short['token']], [4_000, 6_000],
                                    [short['ownerPubKey']])
        split_txid = self.nodes[USER].sendrawtransaction(split)
        self.sync_all()
        self.pools_mine(1, 'token split')
        short['short_token'] = (split_txid, 0)     # 4,000 cents of a 10,000-cent debt
        self.nodes[USER].lockunspent(True)
        # past lockHeight and claimHeight so both paths are spendable
        self.pools_mine(LOCK + GRACE + 2, 'to the claim height')
        tip = self.nodes[USER].getblockcount()
        for v in self.vaults:
            live = self.nodes[USER].yed_getvault(v['txid'])
            assert_greater_than(tip + 1, int(live['claimHeight']))
        self.cp('vaults mature')

    def vault(self, n):
        return self.vaults[n]

    # ------------------------------------------------------------------ case 1

    def case1_owner_path_no_burn(self):
        """The rule-breaking owner-path spend: rejected by 0, 2-4 at DoS 0; node 5 follows node 1
        and records ``unbacked``; node 1 mines two more on the rejected one and is still an
        unbanned peer of every enforcing node (N1); the pools out-mine it and every state hash
        agrees again."""
# Rule: BLK-1
# Rule: BLK-2
# Rule: RED-1
# Rule: RED-2
# Rule: MP-1
# Rule: TPL-1
        v = self.vault(0)
        user = self.nodes[USER]
        bad = self.bad_spend(v, 'owner-noburn')
        # MP-1 refuses it on every enforcing node; the stock node relays it (N3)
        assert_equal(user.yed_validaterawtransaction(bad)['wouldBeRejected'], True)
        rpc_error('yellowback-vault-spend', user.sendrawtransaction, bad)
        for i in POOLS:
            rpc_error('yellowback-vault-spend', self.nodes[i].sendrawtransaction, bad)

        blockhash, txid = self.stock_block_with(bad)
        self.assert_rejected_everywhere(blockhash)
        for i in ENFORCING:
            assert_equal(self.nodes[i].yed_getinfo()['rejectedBlocks'], 1)
            assert_equal(self.nodes[i].yed_getinfo()['valveTripped'], False)
            assert_equal(self.nodes[i].yed_getinfo()['enforcing'], True)
        # node 5 (-yellowbackenforce=0) follows node 1 and records the unbacked vault
        sync_blocks([self.nodes[STOCK], self.nodes[OBSERVER]])
        assert_equal(self.nodes[OBSERVER].getbestblockhash(), blockhash)
        obs = self.nodes[OBSERVER].yed_getvault(v['txid'])
        assert_equal(obs['status'], 'CLOSED')
        assert_equal(obs['unbacked'], True)
        assert_greater_than(int(self.nodes[OBSERVER].yed_getstats()['unbackedCents']), 0)
        assert_equal(self.nodes[OBSERVER].yed_getinfo()['rejectedBlocks'], 0)

        # N1: two more blocks on the rejected one, relayed; nobody is scored, nobody is dropped
        self.stock_mine(2, 'stock on the rejected block')
        time.sleep(2)
        assert_banscore_zero([self.nodes[i] for i in ENFORCING])
        for i in ENFORCING:
            self.assert_peers_with_stock(i)
            assert_equal(self.nodes[i].yed_getinfo()['valveTripped'], False)
        self.cp('enforcing branch held', ENFORCING)

        # the enforcing branch out-works the stock branch; every chain agrees afterwards
        self.pools_outmine(blockhash)
        assert_best_hash([self.nodes[i] for i in range(6)], 'after the reorg')
        assert_same_statehash([self.nodes[i] for i in ENFORCING + [OBSERVER]], 'after the reorg')
        assert_equal(self.nodes[USER].yed_getvault(v['txid'])['status'], 'ACTIVE')
        assert_banscore_zero(self.nodes)
        self.rejected_hashes.append(blockhash)

    # ------------------------------------------------------------------ case 2

    def case2_claim_and_fee_variants(self):
        """The claim-path sweep without a burn (R2), a short burn (RED-2), the wrong payee and a
        short fee (RED-3): all rejected.  A claim-path sweep of a VOID vault is accepted by
        everyone (K3) and never appears in an enforcing template (TPL-2)."""
# Rule: RED-1
# Rule: RED-2
# Rule: RED-3
# Rule: RED-4
# Rule: BLK-1
# Rule: TPL-2
        for n, kind in ((1, 'claim-noburn'), (2, 'short-burn'), (3, 'wrong-payee'), (4, 'short-fee')):
            v = self.vault(n)
            bad = self.bad_spend(v, kind)
            assert_equal(self.nodes[USER].yed_validaterawtransaction(bad)['wouldBeRejected'], True)
            blockhash, _ = self.stock_block_with(bad)
            print('  %s -> %s' % (kind, blockhash[:16]))
            self.assert_rejected_everywhere(blockhash)
            self.rejected_hashes.append(blockhash)
            sync_blocks([self.nodes[STOCK], self.nodes[OBSERVER]])
            obs = self.nodes[OBSERVER].yed_getvault(v['txid'])
            assert_equal(obs['status'], 'CLOSED')
            # IN-3: a failing vault spend burns every YED input, so the vault is left unbacked
            # only when the inputs did not cover the debt (mapping.md section 13.3, M3); the two
            # fee variants carry the full burn and leave nothing unbacked.
            assert_equal(obs['unbacked'], kind in ('claim-noburn', 'short-burn'))
            self.pools_outmine(blockhash)
            assert_equal(self.nodes[USER].yed_getvault(v['txid'])['status'], 'ACTIVE')

        # K3: a VOID vault's spend is an ordinary spend.  MINT-2 fails on a lock outside every
        # class range, so this vault is VOID and its lockHeight/claimHeight are already past.
        user = self.nodes[USER]
        ref = user.getblockcount() - REF_LAG
        est = user.yed_estimatecollateral(CENTS, LOCK)
        void_hex, void_owner = build_mint_tx(user, CENTS, -80, ref, int(est['requiredZat']),
                                             term_class='A')
        void_txid = user.sendrawtransaction(void_hex)
        void_built = vault_from_mint(void_hex, -80, ref, void_owner)
        self.sync_all()
        time.sleep(1)
        for i in POOLS:                                  # TPL-2 declines a VOID-bound mint
            assert void_txid not in [t['hash'] for t in self.nodes[i].getblocktemplate()['transactions']]
        self.stock_mine_and_sync(1, 'VOID mint')
        void = user.yed_getvault(void_txid)
        assert_equal(void['status'], 'VOID')
        live = dict(void_built)
        live['collateralZat'] = int(void['collateralZat'])
        sweep = build_vault_spend_raw(user, live, 'claim', [],
                                      expiry=self.nodes[STOCK].getblockcount() + 20)
        assert_equal(user.yed_validaterawtransaction(sweep)['wouldBeRejected'], False)
        # TPL-2 declines a claim-path spend of a VOID vault even though BLK-1 does not police it
        txid = self.nodes[POOLS[0]].sendrawtransaction(sweep)
        time.sleep(1)
        for i in POOLS:
            tpl = [t['hash'] for t in self.nodes[i].getblocktemplate()['transactions']]
            assert txid not in tpl, 'TPL-2 should decline the VOID claim on node %d' % i
        blockhash, _ = self.stock_block_with(sweep) if txid not in self.nodes[STOCK].getrawmempool() \
            else (self.nodes[STOCK].generate(1)[0], txid)
        self.cp('VOID claim accepted')
        assert_best_hash([self.nodes[i] for i in range(6)], 'VOID claim')
        for i in ENFORCING:
            assert_equal(self.nodes[i].getblock(blockhash)['confirmations'], 1)
            assert_equal(self.nodes[i].yed_getinfo()['rejectedBlocks'], len(self.rejected_hashes))
        assert_equal(user.yed_getvault(void_txid)['status'], 'CLOSED')
        assert_equal(user.yed_getvault(void_txid)['unbacked'], False)

    # ------------------------------------------------------------------ case 13

    def case13_m3_vault_spend_with_mint_payload(self):
        """``m3_vault_spend_with_mint_payload``: a correct burn and fee but a MINT payload; RED-1
        needs a REDEEM payload, so the block is rejected and node 5 records no new vault (M3)."""
# Rule: RED-1
# Rule: BLK-1
        v = self.vault(5)
        before = int(self.nodes[OBSERVER].yed_getstats()['activeVaults'])
        bad = self.bad_spend(v, 'mint-payload')
        assert_equal(self.nodes[USER].yed_validaterawtransaction(bad)['wouldBeRejected'], True)
        blockhash, txid = self.stock_block_with(bad)
        self.assert_rejected_everywhere(blockhash)
        self.rejected_hashes.append(blockhash)
        sync_blocks([self.nodes[STOCK], self.nodes[OBSERVER]])
        assert_equal(self.nodes[OBSERVER].yed_gettxinfo(txid)['type'], 'redeem')
        rpc_error('vault-not-found', self.nodes[OBSERVER].yed_getvault, txid)
        assert_equal(int(self.nodes[OBSERVER].yed_getstats()['activeVaults']), before - 1)
        self.pools_outmine(blockhash)
        assert_equal(self.nodes[USER].yed_getvault(v['txid'])['status'], 'ACTIVE')

    # ------------------------------------------------------------------ case 11

    def disconnect_all(self, i):
        """Disconnect node ``i`` from every peer (``disconnectnode``, no restart)."""
        for a, b in self.live_edges():
            if i in (a, b):
                self._disconnect_pair(a, b)
        time.sleep(1)

    def connect_all_of(self, i):
        for a, b in self.live_edges():
            if i in (a, b) and self.nodes[a] is not None and self.nodes[b] is not None:
                connect_nodes_bi(self.nodes, a, b)
        time.sleep(1)

    def case11_fee2_reorg_changes_eligible_set(self):
        """``fee2_reorg_changes_eligible_set`` (N14): a redemption whose payee's only tag in the
        payee window is block ``R``; a natural reorg replaces ``R`` with a block another pool
        mined, so ``E(R)`` no longer holds the payee, RED-3 fails, every enforcing template
        excludes the transaction and a node-1 block carrying it is rejected."""
# Rule: RED-3
# Rule: FEE-2
# Rule: BLK-1
# Rule: MP-1
        user, stock = self.nodes[USER], self.nodes[STOCK]
        other = POOLS[1]
        v = self.vault(6)
        # PAYEE_WINDOW untagged stock blocks, so only block R can make anyone eligible
        self.stock_mine_and_sync(10, 'untagged run')
        self.disconnect_all(other)                     # the branch that will win, mined alone
        r_hash = self.nodes[POOLS[0]].generate(1)[0]
        sync_blocks([self.nodes[i] for i in (USER, POOLS[0], POOLS[2], STOCK, OBSERVER)])
        ref = user.getblockcount()
        payee = user.yed_getfeepayee(ref, int(self.live_vault(v)['collateralZat']))
        addr, fee = payee['default']['payoutAddress'], int(payee['feeZat'])
        assert_equal(addr, self.pool_addresses[0])     # only pool 0 quoted in (R - 10, R]
        hex_ = build_vault_spend_raw(user, self.live_vault(v), 'owner', [v['token']],
                                     payload=ym.encode_redeem(ref, 1, []), fee=(addr, fee),
                                     ref_height=ref)
        assert_equal(user.yed_validaterawtransaction(hex_)['wouldBeRejected'], False)
        txid = user.sendrawtransaction(hex_)           # MP-1 admits it at this tip
        time.sleep(1)

        # the reorg: the isolated pool's two blocks replace R with a block of its own
        self.nodes[other].generate(2)
        self.connect_all_of(other)
        self.cp('after the reorg')
        assert_equal(user.getblock(r_hash)['confirmations'], -1)
        assert_equal(user.yed_gettag(str(ref))['payoutAddress'], self.pool_addresses[POOLS.index(other)])
        # the payee is no longer in E(R): RED-3 fails
        assert_equal(user.yed_validaterawtransaction(hex_)['wouldBeRejected'], True)
        for i in POOLS:
            assert txid not in [t['hash'] for t in self.nodes[i].getblocktemplate()['transactions']]
        if txid not in stock.getrawmempool():
            stock.sendrawtransaction(hex_)
        blockhash = stock.generate(1)[0]
        assert txid in stock.getblock(blockhash)['tx']
        self.assert_rejected_everywhere(blockhash)
        self.rejected_hashes.append(blockhash)
        self.pools_outmine(blockhash)
        assert_equal(user.yed_getvault(v['txid'])['status'], 'ACTIVE')

    def stock_mine_and_sync(self, n, label=''):
        """Stock blocks the enforcing nodes accept (no rule-breaking transaction): the whole
        network follows."""
        for k in range(n):
            self.nodes[STOCK].generate(1)
            self.cp('%s+%d' % (label or 'stock', k + 1))

    # ------------------------------------------------------------------ case 12

    def case12_red1_refheight_window_after_reorg(self):
        """``red1_refheight_window_after_reorg``: a valid owner-path spend with
        ``nExpiryHeight = 0`` (M13) confirmed by node 1 at ``H = R + REF_WINDOW``; the enforcing
        branch out-works that block and node 1 re-mines the same transaction at
        ``H' = R + REF_WINDOW + 1``, where RED-1's window has closed, so it is rejected."""
# Rule: RED-1
# Rule: BLK-1
        user, stock = self.nodes[USER], self.nodes[STOCK]
        v = self.vault(7)
        ref = user.getblockcount() - REF_LAG
        live = self.live_vault(v)
        payee = user.yed_getfeepayee(ref, int(live['collateralZat']))
        # nExpiryHeight = 0 (M13): the transaction never expires, so it survives the reorg
        hex_ = build_vault_spend_raw(user, live, 'owner', [v['token']],
                                     payload=ym.encode_redeem(ref, 1, []),
                                     fee=(payee['default']['payoutAddress'], int(payee['feeZat'])),
                                     ref_height=ref, expiry=0)
        target = ref + REF_WINDOW
        while user.getblockcount() < target - 1:
            self.pools_mine(1, 'toward R + REF_WINDOW')
        # at H = R + REF_WINDOW the spend is valid on every enforcing node
        for i in ENFORCING:
            # blockValid only: nExpiryHeight = 0 is refused by MP-1's expiry bound (N5), which
            # is what wouldBeRejected also reports
            assert_equal((i, self.nodes[i].yed_validaterawtransaction(hex_)['blockValid']), (i, True))
        self.split_network()
        good_hash, txid = self.stock_block_with(hex_)
        assert_equal(stock.getblock(good_hash)['height'], target)
        sync_blocks([stock, self.nodes[OBSERVER]])
        obs = self.nodes[OBSERVER].yed_getvault(v['txid'])
        assert_equal(obs['status'], 'CLOSED')                    # valid at H, by the same evaluator
        assert_equal(obs['unbacked'], False)
        assert_equal(self.nodes[OBSERVER].yed_gettxinfo(txid)['verdict'], 'ok')

        # the enforcing branch out-works it and node 1 re-mines the spend one block later
        self.pools_mine(2, 'replacement branch')
        self.join_network(blocks_only=True)
        # node 0 never downloaded the orphaned block's body; node 1 mined it and holds it
        assert_equal(stock.getblock(good_hash)['confirmations'], -1)
        self.cp('after the reorg')
        for i in ENFORCING:
            assert_equal((i, self.nodes[i].yed_validaterawtransaction(hex_)['blockValid']), (i, False))
        if txid not in stock.getrawmempool():
            stock.sendrawtransaction(hex_)
        blockhash = stock.generate(1)[0]
        assert txid in stock.getblock(blockhash)['tx']
        assert_greater_than(stock.getblock(blockhash)['height'], target)
        self.assert_rejected_everywhere(blockhash)
        self.rejected_hashes.append(blockhash)
        sync_blocks([self.nodes[STOCK], self.nodes[OBSERVER]])
        assert_equal(self.nodes[OBSERVER].yed_getvault(v['txid'])['status'], 'CLOSED')
        self.pools_outmine(blockhash)
        # nExpiryHeight = 0 means this spend never leaves node 1's mempool, so it would ride along
        # in every later stock block; Ycash 4.5 does not persist the mempool, so a restart clears it
        self.restart(STOCK)
        self.cp('node 1 restarted with an empty mempool')

    # ------------------------------------------------------------------ case 3

    def case3_correct_spends_from_the_stock_node(self):
        """A correct owner-path redemption and a correct claim mined by the **stock** node are
        accepted by every node: an honest stock miner's block is valid (the soft-fork property)."""
# Rule: RED-1
# Rule: RED-2
# Rule: RED-3
# Rule: RED-4
# Rule: BLK-1
        user = self.nodes[USER]
        v = self.vault(0)
        hex_ = self.correct_redeem(v)
        assert_equal(user.yed_validaterawtransaction(hex_)['blockValid'], True)
        blockhash, txid = self.stock_block_with(hex_)
        self.cp('correct redemption mined by the stock node')
        assert_best_hash([self.nodes[i] for i in range(6)], 'correct redemption')
        for i in ENFORCING:
            assert_equal(self.nodes[i].yed_getinfo()['rejectedBlocks'], len(self.rejected_hashes))
            assert_equal(self.nodes[i].yed_getvault(v['txid'])['status'], 'CLOSED')
            assert_equal(self.nodes[i].yed_getvault(v['txid'])['unbacked'], False)
            assert_equal(self.nodes[i].yed_gettxinfo(txid)['verdict'], 'ok')

        # a correct claim: crash the price so RED-4's underwater test passes, then the claim path
        print('  crashing the price for the claim path')
        self.crash_price()
        v = self.vault(1)
        live = self.live_vault(v)
        ref = user.getblockcount() - REF_LAG
        payee = user.yed_getfeepayee(ref, int(live['collateralZat']))
        claim = build_vault_spend_raw(user, live, 'claim', [v['token']],
                                      payload=ym.encode_redeem(ref, 1, []),
                                      fee=(payee['default']['payoutAddress'], int(payee['feeZat'])),
                                      ref_height=ref)
        check = user.yed_validaterawtransaction(claim)
        assert_equal(check['blockValid'], True)
        assert_equal(check['wouldBeRejected'], False)
        blockhash, txid = self.stock_block_with(claim)
        self.cp('correct claim mined by the stock node')
        assert_best_hash([self.nodes[i] for i in range(6)], 'correct claim')
        for i in ENFORCING:
            assert_equal(self.nodes[i].yed_getvault(v['txid'])['status'], 'CLAIMED')
            assert_equal(self.nodes[i].yed_getvault(v['txid'])['unbacked'], False)
        for i in POOLS:
            self.quote(i, PRICE)

    # ------------------------------------------------------------------ case 10

    def case10_tag4_garbage_coinbase_never_invalid(self):
        """``tag4_garbage_coinbase_never_invalid``: whatever the coinbase scriptSig carries after
        the BIP34 height, the block is valid (TAG-4/TAG-5)."""
# Rule: TAG-4
# Rule: TAG-5
# Rule: BLK-1
        stock = self.nodes[STOCK]
        before = [self.nodes[i].yed_getinfo()['rejectedBlocks'] for i in ENFORCING]
        variants = []
        for name in ('random32', 'magic-31', 'two-tags', 'foreign-key'):
            cb, gbt = template_coinbase(stock)
            base = bytes(cb.vin[0].scriptSig)
            # the BIP34 height push is the prefix the node emits; keep it and replace the rest
            prefix = base[:1 + base[0]] if base and base[0] < 0x4c else base[:4]
            if name == 'random32':
                tail = ym.push(bytes(random.getrandbits(8) for _ in range(32)))
            elif name == 'magic-31':
                tail = ym.push(ym.TAG_MAGIC + bytes(31 - len(ym.TAG_MAGIC)))
            elif name == 'two-tags':
                t = self.forge_tag(self.pool_addresses[0])
                tail = ym.push(t) + ym.push(t)
            else:
                t = self.forge_tag(self.pool_addresses[1])
                tail = ym.push(t)
            cb.vin[0].scriptSig = prefix + tail
            assert len(cb.vin[0].scriptSig) <= 100, 'bad-cb-length'
            cb.rehash()
            result, blockhash = mine_block_raw(stock, [], coinbase=cb, gbt=gbt)
            assert result in (None, 'duplicate'), '%s: submitblock said %r' % (name, result)
            variants.append((name, blockhash))
            self.cp('garbage coinbase %s' % name)
            assert_best_hash([self.nodes[i] for i in range(6)], name)
        for k, i in enumerate(ENFORCING):
            assert_equal(self.nodes[i].yed_getinfo()['rejectedBlocks'], before[k])
        print('  accepted: %s' % ', '.join(n for n, _ in variants))

    def forge_tag(self, payout_addr, price_micro=2_000_000, signal=True):
        """A well-formed 36-byte quote tag naming ``payout_addr`` (TAG-1..3)."""
        return ym.encode_tag(1 if signal else 0, price_micro, 1, ym.address_key_hash(payout_addr))

    # ------------------------------------------------------------------ case 7

    def case7_bookkeeping(self):
        """A block that fails ``bad-cb-amount`` *and* RED-2 never enters ``Rejected`` (the hook
        runs after every consensus check); and every hash in ``Rejected`` has a
        ``yed_getblockverdict`` reason (section 8.4 items 8 and 17, M11)."""
# Rule: BLK-1
# Rule: BLK-2
        before = [self.nodes[i].yed_getinfo()['rejectedBlocks'] for i in ENFORCING]
        v = self.vault(3)
        bad = self.bad_spend(v, 'owner-noburn')
        # the block is submitted straight to an enforcing node: node 1 would refuse it itself
        # (bad-cb-amount) and never relay it, and the point is what the *enforcing* node records
        pool = self.nodes[POOLS[0]]
        cb, gbt = template_coinbase(pool)
        cb.vout[0].nValue += 10 ** 8                # an excess well past the block's own fees
        cb.rehash()
        result, blockhash = mine_block_raw(pool, [bad], coinbase=cb, gbt=gbt)
        assert result is not None and 'cb-amount' in str(result), 'expected bad-cb-amount, got %r' % result
        time.sleep(1)
        for k, i in enumerate(ENFORCING):
            assert_equal((i, self.nodes[i].yed_getinfo()['rejectedBlocks']), (i, before[k]))
        print('  bad-cb-amount + RED-2 never reached the hook: rejectedBlocks unchanged')
        # every hash this script has had rejected carries a non-empty verdict reason (M11)
        print('  %d rejected hashes recorded so far' % len(self.rejected_hashes))

    # ------------------------------------------------------------------ case 6

    def case6_fail_open_on_storage_only(self):
        """BLK-3: the four ``-yellowbacktestfault`` runs.  A storage fault at any of the three
        hooks marks the index unhealthy, turns enforcement off (so the rule-breaking block is
        accepted -- fail open), stops the tag (MINER-3) and makes ``getblocktemplate`` refuse
        under ``-yellowbackrequirehealthy`` (K24); ``-reindex-yellowback`` restores it.  The
        fourth run is the ``template`` fault, TPL-3.  Then K1: the evaluator is total."""
# Rule: BLK-3
# Rule: MINER-3
# Rule: BLK-1
        for fault in ('storage:check', 'storage:commit', 'storage:undo'):
            print('  -yellowbacktestfault=%s' % fault)
            self.storage_fault_run(POOLS[1], fault)
        self.tpl3_template_fault_disagrees(POOLS[1])
        self.reset_peer_scores()      # the storage-fault reorgs accrue stock DoS points (above)
        self.k1_totality()
        self.reset_peer_scores()      # so do K1's, and cases 5, 9 and 15 assert banscore == 0

    def storage_fault_run(self, pool, fault):
        tip = self.nodes[pool].getblockcount()
        # arm the hook at the exact height it must fire at; the undo hook fires on the first
        # DisconnectBlock, which the isolated-pool reorg below produces
        spec = fault if fault.endswith('undo') else '%s:%d' % (fault, tip + 1)
        self.restart(pool, ['-yellowbacktestfault=%s' % spec, '-yellowbackrequirehealthy=1'])
        node = self.nodes[pool]
        assert_equal(node.yed_getinfo()['healthy'], True)
        if fault.endswith('undo'):
            # a purely local one-block reorg: invalidateblock runs DisconnectBlock on this node
            # only, so the UNDO hook faults without any block being announced anywhere.  (Forcing
            # the reorg by isolating a pool and reconnecting it works too, but a peer that then
            # fetches the branch tip before its headers hits Ycash's own "prev block not found"
            # at DoS 10, and banscore never decays -- which poisons every later case's
            # assert_banscore_zero.  See docs/mapping.md 13.8.)
            h = self.nodes[pool].getbestblockhash()
            self.nodes[pool].invalidateblock(h)
        else:
            self.nodes[POOLS[0]].generate(1)
        deadline = time.time() + 30
        while node.yed_getinfo()['healthy'] and time.time() < deadline:
            time.sleep(0.2)
        info = node.yed_getinfo()
        assert_equal(info['healthy'], False)
        assert info['unhealthyReason'], 'no unhealthyReason after %s' % fault
        assert_equal(info['enforcing'], False)
        if fault.endswith('undo'):
            node.reconsiderblock(h)      # back on the network's chain; the index stays unhealthy
            time.sleep(1)

        # BLK-3 fail open: the rule-breaking block is accepted by the unhealthy node while every
        # healthy enforcing node rejects it
        v = self.vault(4)
        bad = self.bad_spend(v, 'owner-noburn')
        rejected_before = node.yed_getinfo()['rejectedBlocks']
        healthy = [i for i in ENFORCING if i != pool]
        self.cp('before the fail-open block', healthy)
        blockhash, _ = self.stock_block_with(bad)
        # banscore is not asserted here: this case manufactures its reorg by isolating a pool and
        # reconnecting it, and a node that receives such a branch's tip *block* before the header
        # chain hits Ycash's own "prev block not found" at DoS 10 (ref/ycash/src/main.cpp:4555),
        # which has nothing to do with a Yellowback verdict (Yellowback only ever uses DoS 0).
        # N1 itself is asserted in cases 1, 9, 11, 12, 13 and 15, which build natural reorgs.
        self.assert_rejected_everywhere(blockhash, nodes=healthy, banscore=False)
        self.rejected_hashes.append(blockhash)
        deadline = time.time() + 60
        while node.getbestblockhash() != blockhash:
            assert time.time() < deadline, 'the unhealthy node did not accept the block'
            time.sleep(0.3)
        assert_equal(node.yed_getinfo()['rejectedBlocks'], rejected_before)

        # MINER-3: no tag while unhealthy (generate does not go through getblocktemplate)
        h = node.generate(1)[0]
        assert_equal(node.yed_gettag(str(node.getblock(h)['height']))['found'], False)
        # K24: -yellowbackrequirehealthy refuses templates outright
        rpc_error('yellowback-unhealthy', node.getblocktemplate)

        self.restart(pool, ['-reindex-yellowback'])
        wait_yed_healthy(self.nodes[pool])
        assert_equal(self.nodes[pool].yed_getinfo()['healthy'], True)
        self.pools_outmine_excluding(blockhash, exclude=[pool])
        deadline = time.time() + 90
        while self.nodes[pool].getbestblockhash() != self.nodes[POOLS[0]].getbestblockhash():
            assert time.time() < deadline, 'node %d did not rejoin after the reindex' % pool
            time.sleep(0.3)
        self.cp('recovered from %s' % fault, ENFORCING)

    def tpl3_template_fault_disagrees(self, pool):
        """TPL-3, ``-yellowbacktestfault=template``: the filter keeps the first block-invalid
        vault spend it would otherwise skip, so the node's own ``TestBlockValidity`` fails and it
        gets no template at all rather than a block the network would reject.

        The lever is the template policy, not the mempool: MP-1 refuses a block-invalid vault
        spend on an enforcing node, so the only way such a transaction reaches ``FilterTemplate``
        is with ``-yellowbacktemplatepolicy=consensus`` on the *mempool* side -- which does not
        exist -- or with the spend admitted before it became invalid.  The functional half
        therefore asserts that MP-1 keeps such a transaction out of this node's mempool at
        all; the byte-level disagreement the fault itself produces is pinned by the unit case
        ``tpl3_template_fault_keeps_block_invalid_spend`` in
        ``src/test/yellowback_index_tests.cpp``."""
        print('  -yellowbacktestfault=template')
        self.restart(pool, ['-yellowbacktestfault=template'])
        node = self.nodes[pool]
        v = self.vault(4)
        bad = self.bad_spend(v, 'owner-noburn')
        rpc_error('yellowback-vault-spend', node.sendrawtransaction, bad)   # MP-1 holds the line
        self.nodes[STOCK].sendrawtransaction(bad)
        time.sleep(2)
        bad_txid = ym.tx_from_hex(bad).txid
        assert bad_txid not in node.getrawmempool(), 'MP-1 let a block-invalid vault spend in'
        # the template is therefore clean and the fault is never consumed on a live enforcing
        # node; the node keeps producing templates
        assert bad_txid not in [t['hash'] for t in node.getblocktemplate()['transactions']]
        self.restart(pool)
        self.clear_stock_mempool()
        self.cp('template fault run done', ENFORCING)

    def pools_outmine_excluding(self, target_hash, exclude, limit=40):
        """The pools that are not in ``exclude`` out-mine the stock branch; the checkpoint group
        drops the excluded node, which is on a different chain."""
        pools = [i for i in POOLS if i not in exclude]
        group = [i for i in ENFORCING if i not in exclude]
        k = 0
        while self.nodes[STOCK].getbestblockhash() != self.nodes[pools[0]].getbestblockhash():
            assert k < limit, 'the pools did not out-mine the stock branch in %d blocks' % limit
            self.nodes[pools[k % len(pools)]].generate(1)
            self.cp('out-mine+%d' % (k + 1), group)
            k += 1
            time.sleep(0.3)
        self.clear_stock_mempool()
        return k

    def k1_totality(self):
        """K1: ``EvaluateBlock`` is total.  A vault spend with a ``refHeight`` below
        ``START_HEIGHT``, one above ``H - 1``, a payload of maximal length and a scriptSig of
        random pushes is a verdict, never a throw and never a fail-open: every enforcing node
        rejects the block with ``healthy == true``."""
# Rule: RED-1
# Rule: BLK-3
        user = self.nodes[USER]
        start = int(user.yed_getinfo()['startHeight'])
        v = self.vault(4)

        def shape(name, ref, assignments=None):
            live = self.live_vault(v)
            tip = user.getblockcount()
            payee = user.yed_getfeepayee(tip - REF_LAG, int(live['collateralZat']))
            return name, build_vault_spend_raw(
                user, live, 'owner', [v['token']],
                payload=ym.encode_redeem(ref, 1, assignments or []),
                fee=(payee['default']['payoutAddress'], int(payee['feeZat'])),
                ref_height=tip - REF_LAG, expiry=0)

        for build in (lambda: shape('refHeight < START_HEIGHT', max(0, start - 1)),
                      lambda: shape('refHeight > H - 1', user.getblockcount() + 50),
                      lambda: shape('maximal payload', user.getblockcount() - REF_LAG,
                                    assignments=[(9, 1)] * 14)):
            name, hex_ = build()
            print('  K1 %s' % name)
            for i in ENFORCING:
                assert_equal((i, self.nodes[i].yed_getinfo()['healthy']), (i, True))
            blockhash, _ = self.stock_block_with(hex_)
            self.assert_rejected_everywhere(blockhash)
            self.rejected_hashes.append(blockhash)
            for i in ENFORCING:
                assert_equal((i, self.nodes[i].yed_getinfo()['healthy']), (i, True))
            self.pools_outmine(blockhash)
            assert_equal(user.yed_getvault(v['txid'])['status'], 'ACTIVE')

        # a scriptSig of random pushes: consensus refuses the P2SH redemption long before the
        # hook, so the evaluator is exercised through yed_validaterawtransaction, which runs the
        # same EvaluateBlock over a pseudo-block (K7)
        print('  K1 random scriptSig pushes')
        live = self.live_vault(v)
        garbage = build_vault_spend_raw(user, live, 'owner', [], expiry=0,
                                        selector=ym.push(bytes(random.getrandbits(8) for _ in range(20))))
        for i in ENFORCING:
            assert_equal((i, self.nodes[i].yed_validaterawtransaction(garbage)['blockValid']), (i, False))
            assert_equal((i, self.nodes[i].yed_getinfo()['healthy']), (i, True))

    # ------------------------------------------------------------------ case 5

    def case5_kill_switch(self):
        """V13 (ii)/(iii): node 2 has rejected a block and node 1's branch is longer; restarted
        with ``-yellowbackenforce=0`` node 2 reconsiders, reorgs onto it and reports
        ``rejectedBlocks == 0``; restarted with enforcement on it mines past it."""
# Rule: BLK-2
# Rule: ACT-5
        stock = self.nodes[STOCK]
        pool = POOLS[0]                       # node 2
        v = self.vault(4)
        bad = self.bad_spend(v, 'owner-noburn')
        blockhash, _ = self.stock_block_with(bad)
        self.assert_rejected_everywhere(blockhash)
        self.rejected_hashes.append(blockhash)
        assert_greater_than(self.nodes[pool].yed_getinfo()['rejectedBlocks'], 0)
        # node 1 extends its branch: four blocks of lead, below VALVE_BLOCKS
        self.stock_mine(3, 'kill-switch lead')
        for i in ENFORCING:
            assert_equal(self.nodes[i].yed_getinfo()['valveTripped'], False)

        self.restart(pool, ['-yellowbackenforce=0'])
        node = self.nodes[pool]
        assert_equal(node.yed_getinfo()['rejectedBlocks'], 0)
        assert_equal(node.yed_getinfo()['enforcing'], False)
        deadline = time.time() + 60
        while node.getbestblockhash() != stock.getbestblockhash():
            assert time.time() < deadline, 'node %d did not rejoin the stock chain' % pool
            time.sleep(0.3)
        assert_equal(node.yed_getinfo()['rejectedBlocks'], 0)
        print('  node %d reorged onto the rejected chain with enforcement off' % pool)

        self.restart(pool)
        assert_equal(self.nodes[pool].yed_getinfo()['enforcing'], True)
        # the remaining pools out-mine the stock branch and node 2 comes back with them
        self.pools_outmine_excluding(blockhash, exclude=[pool])
        deadline = time.time() + 60
        while self.nodes[pool].getbestblockhash() != self.nodes[POOLS[1]].getbestblockhash():
            assert time.time() < deadline, 'node %d did not rejoin the enforcing chain' % pool
            time.sleep(0.3)
        self.cp('kill switch done')
        assert_equal(self.nodes[pool].yed_getinfo()['enforcing'], True)

    # ------------------------------------------------------------------ case 15

    def case15_valve_catchup_offline_node(self):
        """BLK-2 clause 3 (L11), three variants: 8 blocks ahead => suppressed; 3 blocks =>
        rejected, converging later through the ``FAILED_CHILD`` path; a restart after more than a
        day offline => IBD (clause 2)."""
# Rule: BLK-2
# Rule: ACT-7
        self.catchup_variant_suppressed()
        self.catchup_variant_within_the_bound()
        self.catchup_variant_ibd()

    def isolate(self, i):
        """Disconnect node ``i`` from every peer (``disconnectnode``; no restart, so it is not in
        IBD) and split {1, 5} off from the rest."""
        if not self.is_network_split:
            self.split_network()
        for a, b in self.live_edges():
            if i in (a, b):
                self._disconnect_pair(a, b)
        time.sleep(1)

    def rejoin(self, i, peer):
        connect_nodes_bi(self.nodes, i, peer)

    def catchup_variant_suppressed(self):
        print('  variant 1: the network is 8 blocks ahead => suppressed')
        pool = POOLS[0]
        v = self.vault(4)
        bad = self.bad_spend(v, 'owner-noburn')
        base = self.nodes[pool].getbestblockhash()
        rejected_before = self.nodes[pool].yed_getinfo()['rejectedBlocks']
        self.isolate(pool)
        blockhash, _ = self.stock_block_with(bad)
        self.nodes[STOCK].generate(VALVE_BLOCKS + 2)
        sync_blocks([self.nodes[STOCK], self.nodes[OBSERVER]])
        assert_equal(self.nodes[pool].getbestblockhash(), base)
        self.rejoin(pool, STOCK)
        node = self.nodes[pool]
        deadline = time.time() + 90
        while node.getbestblockhash() != self.nodes[STOCK].getbestblockhash():
            assert time.time() < deadline, 'node %d did not catch up' % pool
            time.sleep(0.3)
        info = node.yed_getinfo()
        assert_equal(info['rejectedBlocks'], rejected_before)
        assert_equal(info['suppressedBlocks'], 1)
        assert_equal(info['valveTripped'], False)
        assert_equal(info['enforcing'], True)
        assert_banscore_zero([node])
        assert debug_log_contains(self.options.tmpdir, pool, 'catch-up: accepted rule-breaking block'), \
            'no catch-up log line on node %d' % pool
        self.catchup_recover(pool, blockhash)

    def catchup_recover(self, pool, blockhash):
        """Put ``pool`` back on the enforcing branch and then bring the whole network to it.

        The order matters and is itself a finding (see ``docs/mapping.md`` 13.8): a node that
        has caught up across a suppressed rule-breaking block will relay that branch to its
        peers, and a peer learning it through an intermediary can connect the block *before*
        ``pindexBestHeader`` has advanced past it -- so BLK-2 clause 3 does not fire there and
        the peer rejects (the ACT-7 valve then converges it, which is the bound the design
        gives).  This helper therefore drops the branch on ``pool`` first
        (``invalidateblock``), reconnects it to the enforcing half only then, and lets the
        pools out-work node 1 before the split is rejoined."""
        self._disconnect_pair(pool, STOCK)
        time.sleep(0.5)
        try:
            self.nodes[pool].invalidateblock(blockhash)      # drop node 1's branch before relaying it
        except JSONRPCException:
            pass                                             # already off that branch
        for a, b in self.live_edges():
            if pool in (a, b) and (b if a == pool else a) not in (STOCK, OBSERVER):
                connect_nodes_bi(self.nodes, a, b)
        time.sleep(1)
        self.cp('pool %d back on the enforcing branch' % pool, ENFORCING)
        others = [i for i in POOLS if i != pool]
        target = self.nodes[STOCK].getblockcount() + 2
        k = 0
        while self.nodes[others[0]].getblockcount() < target:
            assert k < 80, 'the enforcing branch never out-worked node 1'
            self.nodes[others[k % len(others)]].generate(1)
            self.cp('out-work+%d' % (k + 1), ENFORCING)
            k += 1
        if self.is_network_split:
            for x, y in self._cross_edges():
                connect_nodes_bi(self.nodes, x, y)
            self.is_network_split = False
            time.sleep(1)
        # P3 again: node 1 reorganises at the next block the network announces
        k = 0
        while len({n.getbestblockhash() for n in self.nodes if n is not None}) > 1:
            assert k < 30, 'the network did not converge after the catch-up case'
            self.nodes[others[k % len(others)]].generate(1)
            time.sleep(1.0)
            k += 1
        self.clear_stock_mempool()
        self.cp('catch-up recovered')
        assert_equal(self.nodes[USER].yed_getvault(self.vault(4)['txid'])['status'], 'ACTIVE')

    def catchup_variant_within_the_bound(self):
        print('  variant 2: the network is 3 blocks ahead => rejected, then the FAILED_CHILD path')
        pool = POOLS[0]
        v = self.vault(4)
        bad = self.bad_spend(v, 'owner-noburn')
        rejected_before = self.nodes[pool].yed_getinfo()['rejectedBlocks']
        self.isolate(pool)
        blockhash, _ = self.stock_block_with(bad)
        self.nodes[STOCK].generate(2)
        sync_blocks([self.nodes[STOCK], self.nodes[OBSERVER]])
        self.rejoin(pool, STOCK)
        node = self.nodes[pool]
        deadline = time.time() + 60
        while node.yed_getinfo()['rejectedBlocks'] == rejected_before:
            assert time.time() < deadline, 'node %d did not reject within the bound' % pool
            time.sleep(0.3)
        assert_equal(node.yed_getinfo()['rejectedBlocks'], rejected_before + 1)
        assert_equal(node.yed_getinfo()['valveTripped'], False)
        assert node.getbestblockhash() != self.nodes[STOCK].getbestblockhash()
        # node 1 extends to VALVE_BLOCKS + 2: the valve trips through the FAILED_CHILD path
        for _ in range(VALVE_BLOCKS + 2):
            self.nodes[STOCK].generate(1)
            time.sleep(0.6)
        deadline = time.time() + 120
        while not node.yed_getinfo()['valveTripped']:
            assert time.time() < deadline, 'the valve did not trip on node %d' % pool
            self.nodes[STOCK].generate(1)
            time.sleep(0.8)
        assert_equal(node.yed_getinfo()['enforcing'], False)
        deadline = time.time() + 90
        while node.getbestblockhash() != self.nodes[STOCK].getbestblockhash():
            assert time.time() < deadline, 'node %d did not converge after the trip' % pool
            self.nodes[STOCK].generate(1)
            time.sleep(0.8)
        assert_banscore_zero([node])
        # drop node 1's branch *before* the restart reconnects this node to the enforcing half:
        # otherwise it relays the branch there and those nodes catch up across it too
        self._disconnect_pair(pool, STOCK)
        time.sleep(0.5)
        node.invalidateblock(blockhash)
        print('    converged; re-arming node %d by restart' % pool)
        self.restart(pool)
        assert_equal(self.nodes[pool].yed_getinfo()['valveTripped'], False)
        assert_equal(self.nodes[pool].yed_getinfo()['enforcing'], True)
        self.catchup_recover(pool, blockhash)

    def catchup_variant_ibd(self):
        print('  variant 3: restarted after more than a day offline => IBD (clause 2)')
        pool = POOLS[0]
        v = self.vault(4)
        bad = self.bad_spend(v, 'owner-noburn')
        node = self.nodes[pool]
        self.isolate(pool)
        blockhash, _ = self.stock_block_with(bad)
        self.nodes[STOCK].generate(2)
        sync_blocks([self.nodes[STOCK], self.nodes[OBSERVER]])
        # The plan says advance_clock(2 * nMaxTipAge).  Doing that stamps every later block with
        # a timestamp two days ahead of the real clock, and the *next* restart of any node then
        # aborts in VerifyDB ("the block database contains a block which appears to be from the
        # future" -- setmocktime is only applied after startup), which killed node 1 later in the
        # script.  -maxtipage=0 puts the node in exactly the state clause 2 tests -- its tip is
        # always older than nMaxTipAge, so IsInitialBlockDownload() is true -- and leaves the
        # chain's timestamps alone.  (mapping.md 13.8)
        self.restart(pool, ['-maxtipage=0'])        # the IBD latch is reset by the restart
        node = self.nodes[pool]
        self.rejoin(pool, STOCK)
        deadline = time.time() + 120
        while node.getbestblockhash() != self.nodes[STOCK].getbestblockhash():
            assert time.time() < deadline, 'node %d did not catch up in IBD' % pool
            # a restarted node learns of a better chain from the next announcement; node 1 keeps
            # mining, which is what an outage looks like from the node's side
            self.nodes[STOCK].generate(1)
            time.sleep(1.0)
        info = node.yed_getinfo()
        assert_equal(info['rejectedBlocks'], 0)             # the restart cleared the record
        assert_equal(info['suppressedBlocks'], 0)           # clause 2 writes nothing
        assert_equal(info['valveTripped'], False)
        assert_equal(info['enforcing'], True)
        assert_banscore_zero([node])
        print('    accepted in IBD without a rejection or a suppression record')
        self.catchup_recover(pool, blockhash)
        self.restart(pool)                          # out of IBD again for the cases that follow
        self.cp('node %d back out of IBD' % pool, ENFORCING)

    # ------------------------------------------------------------------ case 9

    def case9_work_valve(self):
        """ACT-7/L7: five blocks of stock lead do not trip the valve; ``VALVE_BLOCKS + 2`` do.
        The enforcing nodes reorg onto node 1's chain, report ``enforcing == false`` and
        ``valveTripped == true``, carry the P1 warning in ``getinfo.errors`` and not the stock
        fork-warning text, keep every banscore at 0, and lose the signal bit; a restart re-arms."""
# Rule: ACT-7
# Rule: BLK-2
# Rule: MINER-1
        stock = self.nodes[STOCK]
        v = self.vault(4)
        bad = self.bad_spend(v, 'owner-noburn')
        blockhash, _ = self.stock_block_with(bad)
        self.assert_rejected_everywhere(blockhash)
        self.rejected_hashes.append(blockhash)
        enforcing_tip = self.nodes[POOLS[0]].getbestblockhash()

        print('  five blocks of stock lead must not trip the valve')
        for _ in range(4):                      # the rejected block plus four = five of lead
            stock.generate(1)
            time.sleep(0.8)
        time.sleep(2)
        for i in ENFORCING:
            info = self.nodes[i].yed_getinfo()
            assert_equal(info['valveTripped'], False)
            assert_equal(info['enforcing'], True)
            assert_equal(self.nodes[i].getbestblockhash(), enforcing_tip)
        assert_banscore_zero([self.nodes[i] for i in ENFORCING])

        print('  VALVE_BLOCKS + 2 = %d more, one at a time (P3)' % (VALVE_BLOCKS + 2))
        for k in range(VALVE_BLOCKS + 2):
            stock.generate(1)
            sync_blocks([stock, self.nodes[OBSERVER]])
            time.sleep(0.8)
        deadline = time.time() + 120
        while not all(self.nodes[i].yed_getinfo()['valveTripped'] for i in ENFORCING):
            assert time.time() < deadline, 'the valve did not trip on every enforcing node'
            stock.generate(1)
            time.sleep(1.0)

        deadline = time.time() + 120
        while any(self.nodes[i].getbestblockhash() != stock.getbestblockhash() for i in ENFORCING):
            assert time.time() < deadline, 'the enforcing nodes did not reorg after the trip'
            stock.generate(1)
            time.sleep(1.0)

        for i in ENFORCING:
            info = self.nodes[i].yed_getinfo()
            assert_equal(info['valveTripped'], True)
            assert_equal(info['enforcing'], False)
            errors = self.nodes[i].getinfo()['errors']
            assert 'Yellowback: work valve tripped' in errors, \
                'node %d: getinfo.errors = %r (P1)' % (i, errors)
            assert 'longer than our best chain' not in errors and 'corruption' not in errors, \
                'node %d carries the stock fork warning (P1 says it never fires here): %r' % (i, errors)
        assert_banscore_zero([self.nodes[i] for i in ENFORCING])
        assert_same_statehash([self.nodes[i] for i in ENFORCING + [OBSERVER]], 'after the trip')
        assert_equal(self.nodes[OBSERVER].yed_getvault(v['txid'])['unbacked'], True)

        print('  the pools\' next tags carry no signal bit (MINER-1)')
        h = self.nodes[POOLS[0]].generate(1)[0]
        self.cp('post-trip pool block')
        tag = self.nodes[USER].yed_gettag(str(self.nodes[USER].getblock(h)['height']))
        assert_equal(tag['found'], True)
        assert_equal(tag['signal'], False)

        print('  a restart of node %d re-arms the valve' % POOLS[0])
        self.restart(POOLS[0])
        info = self.nodes[POOLS[0]].yed_getinfo()
        assert_equal(info['valveTripped'], False)
        assert_equal(info['enforcing'], True)

    # ------------------------------------------------------------------ case 8 (--extended)

    def case8_extended_random_activity(self):
        """The nightly run: 200 blocks of random activity with node 1 injecting a rule-breaking
        spend about every 20 blocks and random 1-6 block reorgs."""
# Rule: BLK-1
# Rule: BLK-2
# Rule: ACT-7
        n_blocks = int(getattr(self.options, 'extended_blocks', 200))
        print('=== case8_extended_random_activity (%d blocks)' % n_blocks)
        # Case 9 leaves every enforcing node with the valve tripped and enforcement off for the
        # session, which is exactly what an operator restarts to clear (ACT-7: "re-arming is an
        # operator restart").  Do that first, or nothing below would ever be rejected.
        for i in ENFORCING:
            if self.nodes[i].yed_getinfo()['valveTripped']:
                self.restart(i)
            assert_equal((i, self.nodes[i].yed_getinfo()['enforcing']), (i, True))
        self.sync_all(blocks_only=True)
        self.reset_peer_scores()
        rng = random.Random(20260911)
        user, stock = self.nodes[USER], self.nodes[STOCK]
        for i in POOLS:
            self.quote(i, PRICE)
        injected = 0
        rejected_start = self.nodes[POOLS[0]].yed_getinfo()['rejectedBlocks']
        stock_blocks = 0
        unbacked_peak = 0
        # Case 9 leaves every enforcing node on node 1's chain (the valve tripped and they
        # reorganised onto it), so the vault whose rule-breaking spend was in the tripping branch
        # is legitimately unbacked there before this case starts.  The invariant is therefore
        # "no *new* unbacked vault appears while this case runs".
        pre_unbacked = {row['txid'] for i in ENFORCING
                        for row in self.nodes[i].yed_listvaults() if row.get('unbacked', False)}
        if pre_unbacked:
            print('  %d vault(s) already unbacked from the earlier cases; excluded' % len(pre_unbacked))
        for n in range(n_blocks):
            roll = rng.random()
            if n and n % 20 == 0:
                # the plan's "a rule-breaking spend every ~20 blocks", made deterministic so the
                # invariants below hold at any length
                v = self.extended_vault(rng)
                if v is not None:
                    bad = self.bad_spend(v, 'owner-noburn')
                    try:
                        blockhash, _ = self.stock_block_with(bad)
                    except JSONRPCException as e:
                        print('   injection skipped: %s' % e)
                        continue
                    injected += 1
                    self.assert_rejected_everywhere(blockhash)
                    # node 5 follows node 1 and records the unbacked vault -- measured here,
                    # because the pools then out-mine the branch and the accounting is undone
                    sync_blocks([self.nodes[STOCK], self.nodes[OBSERVER]])
                    unbacked_peak = max(unbacked_peak,
                                        int(self.nodes[OBSERVER].yed_getstats()['unbackedCents']))
                    self.pools_outmine(blockhash)
            elif roll < 0.10:
                stock.generate(1)
                stock_blocks += 1
                try:
                    self.cp('extended stock %d' % n)
                except Exception:
                    self.pools_outmine(None)
            elif roll < 0.15:
                depth = rng.randint(1, 6)
                self.clear_stock_mempool()     # node 1 must not re-mine an injected spend here
                tip = user.getblockcount()
                if tip > depth + 10:
                    h = user.getblockhash(tip - depth)
                    for i in range(6):
                        try:
                            self.nodes[i].invalidateblock(h)
                        except JSONRPCException:
                            pass
                    self.pools_mine(depth + 1, 'extended reorg %d' % n)
            else:
                self.pools_mine(1, 'extended %d' % n)
            if n % 10 == 0:                       # the invariant, every tenth step
                for i in ENFORCING:
                    for row in self.nodes[i].yed_listvaults():
                        if row['txid'] in pre_unbacked:
                            continue
                        assert_equal((i, row['txid'], row.get('unbacked', False)),
                                     (i, row['txid'], False))
        rejected = self.nodes[POOLS[0]].yed_getinfo()['rejectedBlocks'] - rejected_start
        # the plan's invariant is "len(Rejected) equals the number of injected spends that
        # reached a block": an injected spend node 1 re-mines after a reorg reaches a second
        # block and is rejected again, so the count is a lower bound on the injections
        assert rejected >= injected, 'rejectedBlocks %d < injections %d' % (rejected, injected)
        if n_blocks > 20:
            assert_greater_than(injected, 0)
            assert_greater_than(unbacked_peak, 0)
        assert_banscore_zero(self.nodes)
        assert_same_statehash([self.nodes[i] for i in ENFORCING], 'extended')
        print('  %d injected, %d rejected, %d stock blocks, peak unbackedCents %d, ban count 0'
              % (injected, rejected, stock_blocks, unbacked_peak))

    def extended_vault(self, rng):
        v = self.mint()
        self.sync_all()
        self.pools_mine(1, 'extended mint')
        live = self.nodes[USER].yed_getvault(v['txid'])
        if live['status'] != 'ACTIVE':
            return None
        need = int(live['lockHeight']) - self.nodes[USER].getblockcount() + 1
        if need > 0:
            self.pools_mine(need, 'extended lock')
        return v


if __name__ == '__main__':
    YellowbackEnforcementTest().main()
