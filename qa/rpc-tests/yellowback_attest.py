#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The v3 price-attestation flow end to end (v3 plan Phase A2, section 6; raw builders and the
test_framework.yellowback_attest helpers only): five raw registrations on the attestor wallets
(nodes 6-7), TRIGGERED at the exact block the third bond matures and ARMED ATTEST_ARM_DELAY
later, feed_all, the node's bundle equal to the Python one, a raw mint with the bundle in a
carrier confirmed ACTIVE with aMint recorded and the attestor fee paid, the same shape mined by
the stock node (relay proves the carrier is standard), a bundle citing a reorged block VOID with
mint9-bundle-sig on every node (R9), a bundle citing R - ATTEST_MAX_AGE VOID with
mint9-bundle-stale, mint10_diverged_unbuildable, pinning (two pools hold one price while the
attestors move 6 % across two bundles: pinnedKeys fills, E(R) shrinks, xMint follows the
unpinned pool), pin_test_not_armed_without_bundles, the RED-5 residual through a notice,
EMERGENCY_PERSIST blocks and an emergency claim whose residual lands in the owner's balance,
not1_reset_attack_fails, a claim with a bundle by clause (a), equivocation => EJECTED on every
node, dormancy => DORMANT then revive_raw => ELIGIBLE, the bond spend => WITHDRAWN while the
ejected one stays EJECTED, and assert_model_matches(full=True) at the end; checkpoint() after
every block.

Every pool alternates its quote between P and P + $0.01 (``step``): PIN-1 pins a pool that quotes
one price across the window whenever the attestors' bundles move, which is the design (proposal
section 10.1) and exactly what the pinning case provokes on purpose for pools 2 and 3.

Nodes: 0 user, 1 stock, 2-4 pools, 5 observer, 6-7 attestor wallets.
"""

from decimal import Decimal

from test_framework.util import assert_equal, assert_greater_than, bytes_to_hex_str, hex_str_to_bytes
from test_framework import yellowback_model as ym
from test_framework.yellowback_attest import (
    ATTESTOR_WIFS,
    BOND_WIFS,
    attestor_keys,
    bond_keys,
    bond_secret_for,
    build_bundle,
    build_carrier_tx,
    build_mint_tx_v3,
    build_register_tx,
    decode_bundle,
    encode_bundle,
    equivocation_raw,
    feed_all,
    hot_secret_for,
    outpoint_selector,
    parse_attestation,
    post_notice_raw,
    revive_raw,
    select_attestors,
    selection_pool,
    send_and_lock,
    sign_attestation,
    withdraw_bond_raw,
)
from test_framework.yellowback_model import assert_model_matches
from test_framework.yellowback_util import (
    ATTESTOR_A,
    ATTESTOR_B,
    ATTEST_ARM_DELAY,
    ATTEST_FEE_BPS,
    ATTEST_MAX_AGE,
    BOND_MATURITY,
    BPS,
    COIN,
    DORMANCY_CHECK,
    DORMANCY_MIN_BUNDLES,
    EMERGENCY_PERSIST,
    OBSERVER,
    POOLS,
    REF_LAG,
    STOCK,
    USER,
    YellowbackTestFramework,
    assert_same_statehash,
    build_vault_spend_raw,
    fee_zat,
    pubkey_to_address,
    usd_to_micro,
    wait_yed_healthy,
)

PRICE = Decimal('20.00')      # a high YEC price keeps the class-A collateral of a $100 mint at 25 YEC
EMERG_X = Decimal('12.00')    # pools at 60 % of the mint price: a 500 %-covered vault becomes 300 %-covered
EMERG_A = Decimal('4.00')     # attestors at a fifth: pEmerg under EMERGENCY_RATIO_BPS, pClaim = xClaim above CLAIM_THRESHOLD
CRASH = Decimal('1.00')       # the clause-(a) claim
CENTS = 10_000                # $100, the class-A minimum mint
LOCK = 48                     # class A minimum lock
N_ATTESTORS = 5


def spk(addr):
    return ym.p2pkh_script(ym.address_key_hash(addr))


def rpc_error(substr, fn, *args):
    try:
        fn(*args)
    except Exception as e:
        err = getattr(e, 'error', None)
        msg = str(err.get('message', '')) if isinstance(err, dict) else str(e)
        assert substr in msg, 'expected %r in %r' % (substr, msg)
        return msg
    raise AssertionError('expected an error containing %r' % substr)


# Rule: REG-A1 ARM-1 ARM-2 BUNDLE-1 MINT-9 MINT-10 AFEE-1 PIN-1 NOT-1 RED-1 RED-4 RED-5 EQV-1 REV-1 IN-2 PRICE-2 SNAP
class YellowbackAttestTest(YellowbackTestFramework):
    initial_blocks = 101
    # the attestor wallets join the enforcing half directly (the base topology hangs them off node 1 alone,
    # which would cut them off from the pools' blocks during a split)
    EDGES = YellowbackTestFramework.EDGES + [(0, 6), (0, 7)]

    def __init__(self):
        super().__init__(num_nodes=8)
        self.base_price = {}
        self.tick = {}

    def node_args(self, i, extra=None):
        return super().node_args(i, ['-debug=yellowback'] + list(extra or []))

    # ------------------------------------------------------------------ mining with a checkpoint after every block

    def set_prices(self, usd):
        for i in POOLS:
            self.base_price[i] = Decimal(str(usd))
            self.tick[i] = 0
            self.quote(i, self.base_price[i])

    def toggle_quote(self, i):
        self.tick[i] ^= 1
        self.quote(i, self.base_price[i] + (Decimal('0.01') if self.tick[i] else Decimal('0')))

    def step(self, miner, n=1, label='', jitter=True):
        """``n`` blocks on ``miner`` one at a time, the pool's quote alternating between P and
        P + 0.01 unless ``jitter`` is off, ``checkpoint`` after each (N35)."""
        for k in range(n):
            if miner in POOLS and jitter:
                self.toggle_quote(miner)
            self.nodes[miner].generate(1)
            self.checkpoint('%s+%d' % (label or 'block', k + 1))

    def pools_step(self, n, label='', jitter=True):
        for k in range(n):
            self.step(POOLS[k % len(POOLS)], 1, label, jitter)

    def stock_step(self, n=1, label=''):
        for k in range(n):
            self.nodes[STOCK].generate(1)
            self.checkpoint('%s+%d' % (label or 'stock block', k + 1))

    # ------------------------------------------------------------------ lookups

    def attestors(self, i=USER, height=None):
        node = self.nodes[i]
        return {int(r['seq']): r for r in (node.yed_listattestors() if height is None else node.yed_listattestors(height))}

    def status_of(self, seq, i=USER):
        return self.attestors(i)[seq]['status']

    def assert_status_everywhere(self, seq, status):
        for node in self.enforcing_nodes() + [self.nodes[OBSERVER]]:
            rec = [r for r in node.yed_listattestors() if int(r['seq']) == seq][0]
            assert_equal((seq, rec['status']), (seq, status))

    def bond_key_address(self, seq):
        return self.attestors()[seq]['bondKeyAddress']

    def attest_fee(self, collateral_zat):
        return fee_zat(collateral_zat) * ATTEST_FEE_BPS // BPS

    def assert_vault_everywhere(self, txid, status, void_reason=None):
        for node in self.enforcing_nodes() + [self.nodes[OBSERVER]]:
            v = node.yed_getvault(txid)
            assert_equal((txid, v['status']), (txid, status))
            if void_reason is not None:
                assert v['voidReason'] == void_reason or v['voidReason'].startswith(void_reason), \
                    'voidReason %r does not name %s' % (v['voidReason'], void_reason)

    # ------------------------------------------------------------------ the raw v3 shapes

    def carrier_step(self, funder, bundle, miner=None):
        """The carrier funding transaction (W7/R2) from ``funder``'s coins, confirmed by ``miner``
        (default the first pool) in one block."""
        carrier = build_carrier_tx(self.nodes[funder], bundle)
        self.sync_all()
        self.step(POOLS[0] if miner is None else miner, 1, 'carrier')
        return carrier

    def mint_raw(self, owner, bundle, ref, required, miner, expect='ACTIVE', void_reason=None, seqs=None):
        """Carrier step, then the MINT of ``CENTS`` at ``ref`` with ``bundle`` in the carrier, the
        pool fee to FEE-W's payee and the attestor fee to the bundle's first seq, mined by ``miner``.
        Returns ``{txid, ref, owner, token, required, seqs, payee}``."""
        user = self.nodes[USER]
        owner_node = self.nodes[owner]
        atts = decode_bundle(bundle)
        seqs = sorted(parse_attestation(a)[0] for a in atts) if seqs is None else seqs
        carrier = self.carrier_step(owner, bundle, miner)
        payee = user.yed_getfeepayee(ref, required)['default']['payoutAddress']
        attest_payee = self.bond_key_address(seqs[0])
        hex_, owner_pub = build_mint_tx_v3(owner_node, CENTS, LOCK, ref, required, fee_addr=payee, carrier=carrier,
                                           attest_fee=(attest_payee, self.attest_fee(required)))
        txid = owner_node.sendrawtransaction(hex_)
        self.sync_all()
        self.step(miner, 1, 'mint')
        assert_equal(self.nodes[USER].getrawtransaction(txid, 1)['confirmations'], 1)
        self.assert_vault_everywhere(txid, expect, void_reason)
        info = user.yed_gettxinfo(txid)
        assert_equal(info['type'], 'mint')
        assert_greater_than(info['carrierVin'], -1)
        assert_equal(info['bundleSource'], 'scriptsig')
        return {'txid': txid, 'ref': ref, 'owner': owner_pub, 'token': (txid, 1), 'required': required, 'seqs': seqs,
                'payee': payee, 'attestPayee': attest_payee, 'attestFeeZat': self.attest_fee(required)}

    def mint_fresh(self, owner, prices, miner, price_step=Decimal('0')):
        """Feed node 0's pool at ``prices`` (+ ``price_step``), estimate, build the node's bundle for
        R = tip - REF_LAG, cross-check it against the Python bundle, mint. ACTIVE expected."""
        user = self.nodes[USER]
        prices = {seq: Decimal(str(p)) + price_step for seq, p in prices.items()}
        ref = user.getblockcount() - REF_LAG
        feed_all(user, prices, cited=ref)
        est = user.yed_estimatecollateral(CENTS, LOCK)
        assert_equal(est['refHeight'], ref)
        assert_equal(est['armed'], True)
        built = user.yed_buildbundle(ref, '')
        py, selected = build_bundle(user, ref, b'', prices, cited=ref)
        py_sorted = encode_bundle(sorted(decode_bundle(py), key=lambda a: parse_attestation(a)[0]))
        assert_equal(built['hex'], bytes_to_hex_str(py_sorted))
        assert_equal(sorted(built['selected']), sorted(selected))
        assert_equal(sorted(est['bundleSeqs']), sorted(built['seqs']))
        r = self.mint_raw(owner, hex_str_to_bytes(built['hex']), ref, int(est['requiredZat']), miner)
        r['selected'] = built['selected']
        r['est'] = est
        info = user.yed_gettxinfo(r['txid'])
        assert_equal((info['aMint'], info['attestFeeZat'], info['attestPayee'], info['bundleSeqs']),
                     (built['aMint'], est['attestFeeZat'], r['attestPayee'], sorted(built['seqs'])))
        assert_equal(info['pMint'], min(info['xMint'], info['aMint']))
        return r

    def claim_raw(self, claimant, vault_txid, token, prices, miner, residual_to=None, expect='CLAIMED'):
        """Feed at ``prices``, the node's bundle for (R, vault outpoint), the carrier, then the claim:
        vout[0] value, [1] pool fee, [2] attestor fee, [3] the RED-5 residual when yed_listclaimable owes
        one (to ``residual_to``, default the owner), [4] the REDEEM payload."""
        user = self.nodes[USER]
        node = self.nodes[claimant]
        ref = user.getblockcount() - REF_LAG
        feed_all(user, prices, cited=ref)
        live = user.yed_getvault(vault_txid)
        selector = outpoint_selector(vault_txid, 0)
        built = user.yed_buildbundle(ref, bytes_to_hex_str(selector))
        py, selected = build_bundle(user, ref, selector, prices, cited=ref)
        assert_equal(sorted(built['selected']), sorted(selected))
        rows = [r for r in user.yed_listclaimable() if r['vault'] == vault_txid + ':0']
        assert_equal(len(rows), 1)
        row = rows[0]
        carrier = self.carrier_step(claimant, hex_str_to_bytes(built['hex']), miner)
        collateral = int(live['collateralZat'])
        payee = user.yed_getfeepayee(ref, collateral)
        extra = [(self.attest_fee(collateral), spk(self.bond_key_address(built['seqs'][0])))]
        residual = int(row['residualZat'])
        if residual > 0:
            extra.append((residual, spk(residual_to or pubkey_to_address(hex_str_to_bytes(live['ownerPubKey'])))))
        hex_ = build_vault_spend_raw(node, live, 'claim', [token],
                                     payload=ym.encode_redeem(ref, 1, [], attest_fee_vout=2),
                                     fee=(payee['default']['payoutAddress'], int(payee['feeZat'])),
                                     ref_height=ref, extra_outputs=extra, charge_extra=True, carrier=carrier)
        check = user.yed_validaterawtransaction(hex_)
        assert_equal((check['blockValid'], check['wouldBeRejected'], check['verdict']), (True, False, 'ok'))
        txid = node.sendrawtransaction(hex_)
        self.sync_all()
        self.step(miner, 1, 'claim')
        self.assert_vault_everywhere(vault_txid, expect)
        info = user.yed_gettxinfo(txid)
        assert_equal((info['type'], info['path'], info['verdict'], info['claimPath'], info['residualZat'], info['aClaim']),
                     ('redeem', 'claim', 'ok', row['claimPath'], residual, built['aClaim']))
        assert_equal(info['pClaim'], max(info['xClaim'], info['aClaim']))
        return {'txid': txid, 'ref': ref, 'row': row, 'residual': residual, 'info': info}

    def notice_raw(self, poster, vault_txid, prices, miner, expect_found=True):
        user = self.nodes[USER]
        node = self.nodes[poster]
        ref = user.getblockcount() - REF_LAG
        feed_all(user, prices, cited=ref)
        selector = outpoint_selector(vault_txid, 0)
        built = user.yed_buildbundle(ref, bytes_to_hex_str(selector))
        carrier = self.carrier_step(poster, hex_str_to_bytes(built['hex']), miner)
        hex_ = post_notice_raw(node, (vault_txid, 0), ref, carrier)
        txid = node.sendrawtransaction(hex_)
        self.sync_all()
        self.step(miner, 1, 'notice')
        return txid, ref, built

    # ------------------------------------------------------------------ the run

    def run_test(self):
        nodes = self.nodes
        user = nodes[USER]
        for node in self.enforcing_nodes():
            wait_yed_healthy(node)
        assert_equal(user.yed_getinfo()['rpcversion'], 3)

        print('activation at $%s, then the attestor wallets are funded' % PRICE)
        self.activate(POOLS, quote_usd=PRICE)
        self.set_prices(PRICE)
        self.pools_step(REF_LAG + 1, 'post-activation')
        # one confirmed coin per registration: two hand-built transactions in one block cannot share a coin
        for _ in range(3):
            user.sendtoaddress(nodes[ATTESTOR_A].getnewaddress(), 30)
        for _ in range(2):
            user.sendtoaddress(nodes[ATTESTOR_B].getnewaddress(), 20)
        self.sync_all()
        self.step(POOLS[0], 1, 'funding')
        assert_equal(user.yed_getinfo()['attest']['status'], 'UNARMED')
        for i, want in ((ATTESTOR_A, 90), (ATTESTOR_B, 40)):
            have = nodes[i].getbalance()
            assert have >= want, 'node %d holds %s YEC, expected %d (unspent: %r)' % (i, have, want, nodes[i].listunspent(0))

        # ---------------------------------------------------------------- registrations, TRIGGERED, ARMED
        print('five raw registrations on nodes 6-7 in three blocks; TRIGGERED at the exact block the third matures')
        hot, bond = attestor_keys(N_ATTESTORS), bond_keys(N_ATTESTORS)
        for i in range(N_ATTESTORS):
            wallet = nodes[ATTESTOR_A] if i < 3 else nodes[ATTESTOR_B]
            wallet.importprivkey(ATTESTOR_WIFS[i], 'yellowback-attestor', False)
            wallet.importprivkey(BOND_WIFS[i], 'yellowback-bond', False)
        reg_heights = {}
        for block, members in enumerate(([0, 1], [2], [3, 4])):
            for i in members:
                funder = nodes[ATTESTOR_A] if i < 3 else nodes[ATTESTOR_B]
                hex_, _lt = build_register_tx(funder, hot[i][1], bond[i][1])
                txid = send_and_lock(funder, hex_)
                dec = user.yed_decodepayload(hex_)
                assert_equal((dec['type'], dec['register']['attestorPubKey']), ('register', hot[i][1]))
            self.sync_all()
            self.step(POOLS[block], 1, 'registration')
            for i in members:
                reg_heights[i] = user.getblockcount()
        recs = self.attestors()
        assert_equal(sorted(recs), [0, 1, 2, 3, 4])
        by_pub = {pk: i for i, (_s, pk) in enumerate(hot)}
        seq_of = {by_pub[r['attestorPubKey']]: seq for seq, r in recs.items()}       # attestor index -> seq
        for i, seq in seq_of.items():
            assert_equal((recs[seq]['status'], recs[seq]['registerHeight'], recs[seq]['bondZat']), ('PENDING', reg_heights[i], 10 * COIN))
            assert_equal(recs[seq]['bondKeyAddress'], pubkey_to_address(hex_str_to_bytes(bond[i][1])))
            info = user.yed_gettxinfo(recs[seq]['bondOutpoint']['txid'])
            assert_equal((info['type'], info['seq']), ('register', seq))
        seqs = sorted(seq_of.values())
        third_matures = reg_heights[2] + BOND_MATURITY
        while user.getblockcount() < third_matures - 1:
            self.pools_step(1, 'maturing')
        attest = user.yed_getinfo()['attest']
        assert_equal((attest['status'], attest['seatedCount']), ('UNARMED', 2))       # two ELIGIBLE: below ATTEST_ARM_MIN
        assert_equal(self.status_of(seq_of[2]), 'PENDING')
        self.pools_step(1, 'third matures')
        for node in self.enforcing_nodes():
            attest = node.yed_getinfo()['attest']
            assert_equal((attest['status'], attest['triggerHeight'], attest['armHeight'], attest['armed']),
                         ('TRIGGERED', third_matures, third_matures + ATTEST_ARM_DELAY, False))
        assert_equal(self.status_of(seq_of[2]), 'ELIGIBLE')
        print('ARMED after ATTEST_ARM_DELAY = %d' % ATTEST_ARM_DELAY)
        self.pools_step(ATTEST_ARM_DELAY - 1, 'arming')
        assert_equal(user.yed_getinfo()['attest']['status'], 'TRIGGERED')
        self.pools_step(1, 'armed')
        for node in self.enforcing_nodes() + [nodes[OBSERVER]]:
            attest = node.yed_getinfo()['attest']
            assert_equal((attest['status'], attest['armed'], attest['seatedCount']), ('ARMED', True, N_ATTESTORS))
        price = user.yed_getprice()
        assert_equal((price['armed'], price['attestStatus'], price['seated']), (True, 'ARMED', seqs))
        recs = self.attestors()
        assert all(r['founding'] and r['seated'] and int(r['weight']) > 0 for r in recs.values()), recs
        # a transaction at tip + 1 reads Snapshots[tip - REF_LAG]: one more block so that snapshot is ARMED too
        self.pools_step(REF_LAG, 'ref lag')
        assert_equal(user.yed_getprice(user.getblockcount() - REF_LAG)['armed'], True)

        print('pin_test_not_armed_without_bundles: no BundleLog row, no pin, whatever the pools quote')
        p = user.yed_getprice()
        assert_equal((p['pinnedKeys'], p['pinnedSeqs']), ([], []))
        assert_equal(user.yed_getattestations(), [])
        assert_equal(user.yed_getinfo()['attest']['poolFresh'], 0)

        # ---------------------------------------------------------------- feed, bundle, the first mints
        print('feed_all; yed_buildbundle equals the Python bundle; a raw mint with the bundle in a carrier')
        prices = {seq: PRICE for seq in seqs}
        a0 = self.mint_fresh(USER, prices, POOLS[1])
        assert_equal(user.yed_getinfo()['attest']['poolFresh'], N_ATTESTORS)
        pool = user.yed_getattestations()
        assert_equal(sorted(int(a['seq']) for a in pool), seqs)
        info = user.yed_gettxinfo(a0['txid'])
        assert_equal((info['verdict'], info['aMint'], info['xMint']), ('ok', usd_to_micro(PRICE), info['xMint']))
        assert_equal(info['attestFeeZat'], self.attest_fee(a0['required']))
        row = user.yed_getvault(a0['txid'])
        assert_equal((row['status'], row['noticed'], row['noticeHeight'], row['emergencyOpenAt']), ('ACTIVE', False, None, None))
        lb = self.attestors()
        assert_equal(sorted(seq for seq, r in lb.items() if r['lastBundleHeight'] is not None), sorted(a0['seqs']))

        print('the same shape mined by node 1 (stock): relay proves the carrier scriptSig is standard; ACTIVE everywhere')
        a1 = self.mint_fresh(USER, prices, STOCK)
        assert_equal(nodes[STOCK].getblock(nodes[STOCK].getbestblockhash())['tx'].count(a1['txid']), 1)
        # a1's carrier and mint are tagless, and the winning branch below is tagless too. MINT-4
        # reads Snapshots[R] before MINT-9. The fast window is 8 blocks and needs 4 quote tags, and
        # R is whichever of tip+1..tip+4 first has two attestors selected on both branches, which
        # follows the block hashes. Three or four blocks into that tagless run the snapshot is
        # HALT_NO_PRICE and the vault voids as mint-halted-no-price instead of mint9-bundle-sig
        # (main CI on 06607d94c failed; the same job passed on another run). Four tagged blocks on
        # the common prefix are exactly the fast window's fill at the deepest candidate.
        self.set_prices(PRICE)
        self.pools_step(4, 'tagged cushion before the split', jitter=False)
        # The deepest candidate's fast window is these four blocks plus four tagless stock
        # blocks, and the fill is exactly four. A signal tag here would bring the flake back.
        tip = user.getblockcount()
        for h in range(tip - 3, tip + 1):
            assert_equal(user.yed_gettag(str(h))['kind'], 'quote')

        # ---------------------------------------------------------------- VOID: a reorged citation (R9)
        print('a bundle citing a reorged block: split, mine both branches, pick an R whose selections intersect, join')
        self.split_network()
        enforcing_tip = user.getblockcount()
        for k in range(4):
            self.toggle_quote(POOLS[k % 3])
            nodes[POOLS[k % 3]].generate(1)
            self.sync_all(blocks_only=True)
        nodes[STOCK].generate(7)
        self.sync_all(blocks_only=True)
        chosen = None
        for r in range(enforcing_tip + 1, enforcing_tip + 5):
            sel_a = select_attestors(user.getblockhash(r), b'', selection_pool(user, r))
            sel_b = select_attestors(nodes[OBSERVER].getblockhash(r), b'', selection_pool(nodes[OBSERVER], r))
            assert user.getblockhash(r) != nodes[OBSERVER].getblockhash(r)
            both = sorted(set(sel_a) & set(sel_b))
            # Snapshots[R] on the winning chain. A missing pMint becomes mint-halted-no-price
            # and hides the bundle-signature verdict this step is here to show.
            if len(both) >= 2 and nodes[OBSERVER].yed_getprice(r)['pMint'] is not None:
                chosen = (r, both)
                break
        assert chosen is not None, 'no reference height with two attestors selected on both branches and a defined price'
        r_reorg, both = chosen
        # pooled on the enforcing branch (accepted against hash A), signed over hash A
        fed = feed_all(user, {seq: PRICE for seq in both}, cited=r_reorg)
        hash_a = user.getblockhash(r_reorg)
        reorg_bundle = encode_bundle([hex_str_to_bytes(fed[seq][0]) for seq in both])
        est_a = user.yed_estimatecollateral(CENTS, LOCK, usd_to_micro(PRICE))
        self.join_network()
        assert_equal(user.getbestblockhash(), nodes[STOCK].getbestblockhash())
        assert user.getblockhash(r_reorg) != hash_a
        self.checkpoint('after the join')
        # the pool's attestations citing hash A no longer verify: BuildBundle drops them (R9); the seqs fed only at
        # r_reorg are unreachable. The others fall back on their pre-split attestation (cited at a1's reference
        # height). The tagged cushion puts every candidate R more than ATTEST_MAX_AGE above that citation, so
        # the fallback is stale and reachable is 0; yed_buildbundle then reports bundle-insufficient. The raw
        # mint below still carries the hash-A bundle, which fails MINT-9 as mint9-bundle-sig.
        pre_cited = a1['est']['refHeight']
        still_fresh = sorted(s for s in set(sel_b) - set(both) if pre_cited > r_reorg - ATTEST_MAX_AGE)
        sel = user.yed_getselection(r_reorg, '')
        assert_equal(sorted(int(e['seq']) for e in sel['selected']), sorted(sel_b))
        for e in sel['selected']:
            assert_equal((int(e['seq']), e['poolFresh']), (int(e['seq']), int(e['seq']) in still_fresh))
        assert_equal(sel['reachable'], len(still_fresh))
        if sel['reachable'] < 2:
            rpc_error('bundle-insufficient', user.yed_buildbundle, r_reorg, '')
        # the raw mint carrying the stale-hash bundle, mined by node 1 (TPL-2 would keep it out of a pool's template)
        void_a = self.mint_raw(USER, reorg_bundle, r_reorg, int(est_a['requiredZat']), STOCK, expect='VOID', void_reason='mint9-bundle-sig', seqs=both)
        assert_equal(user.yed_getvault(void_a['txid'])['voidReason'], 'mint9-bundle-sig')
        assert_same_statehash(self.enforcing_nodes() + [nodes[OBSERVER]], 'mint9-bundle-sig everywhere')
        # node 1's eight tagless blocks starve the mid window (16 of 24 needed; HALT_NO_PRICE): refill before the next mint
        self.pools_step(20, 'refill after the reorg')

        # ---------------------------------------------------------------- VOID: stale, diverged
        print('a bundle citing R - ATTEST_MAX_AGE is mint9-bundle-stale')
        ref = user.getblockcount() - REF_LAG
        cited = ref - ATTEST_MAX_AGE
        selected = select_attestors(user.getblockhash(ref), b'', selection_pool(user, ref))
        stale = encode_bundle([sign_attestation(hot_secret_for(user, seq), seq, usd_to_micro(PRICE), cited, user.getblockhash(cited))
                               for seq in sorted(selected)])
        est = user.yed_estimatecollateral(CENTS, LOCK, usd_to_micro(PRICE))
        self.mint_raw(USER, stale, ref, int(est['requiredZat']), STOCK, expect='VOID', void_reason='mint9-bundle-stale', seqs=sorted(selected))

        print('mint10_diverged_unbuildable: attestors at 2x the pools; yed_estimatecollateral refuses, a raw mint is VOID')
        ref = user.getblockcount() - REF_LAG
        feed_all(user, {seq: PRICE * 2 for seq in seqs}, cited=ref)
        rpc_error('mint10-diverged', user.yed_estimatecollateral, CENTS, LOCK)
        built = user.yed_buildbundle(ref, '')
        assert_equal(built['aMint'], usd_to_micro(PRICE * 2))
        est = user.yed_estimatecollateral(CENTS, LOCK, usd_to_micro(PRICE))      # MINT-5 reads min(x, a) = x
        self.mint_raw(USER, hex_str_to_bytes(built['hex']), ref, int(est['requiredZat']), STOCK, expect='VOID', void_reason='mint10-diverged')

        # the emergency-claim vault, owned by node 6, minted now so it is past its claimHeight by the time it is needed
        print('the emergency vault: minted by node 6 at $%s' % PRICE)
        v3 = self.mint_fresh(ATTESTOR_A, prices, POOLS[2])

        # ---------------------------------------------------------------- pinning (PIN-1)
        print('pinning: pools 2 and 3 hold one price, pool 4 alternates, attestors move 6 %% across two bundles')
        for i in (POOLS[0], POOLS[1]):
            self.quote(i, PRICE)
        self.step(POOLS[2], 44, 'pool 4 fills the slow window')
        self.mint_fresh(USER, prices, POOLS[2])
        self.step(POOLS[0], 1, 'pool 2 holds', jitter=False)
        self.step(POOLS[1], 1, 'pool 3 holds', jitter=False)
        moved = {seq: PRICE * Decimal('1.06') for seq in seqs}
        self.mint_fresh(USER, moved, POOLS[2])
        self.step(POOLS[0], 1, 'pool 2 holds', jitter=False)
        self.step(POOLS[1], 1, 'pool 3 holds', jitter=False)
        self.step(POOLS[2], 3, 'pool 4')
        p = user.yed_getprice()
        assert_equal(sorted(p['pinnedKeys']), sorted([self.pool_addresses[0], self.pool_addresses[1]]))
        assert_equal(p['pinnedSeqs'], [])
        assert p['xMint'] in (usd_to_micro(PRICE), usd_to_micro(PRICE + Decimal('0.01'))), p
        assert_equal(p['pMint'], p['xMint'])
        tip = user.getblockcount()
        payees = user.yed_getfeepayee(tip, 25 * COIN)
        assert_equal(payees['eligible'], [self.pool_addresses[2]])                 # E(R) shrinks to the unpinned pool
        recs = self.attestors()
        assert all(recs[seq]['pinned'] is False for seq in seqs)
        for i in (0, 2):
            assert_equal(nodes[POOLS[i]].yed_getinfo()['miner']['eligible'], i == 2)
        print('  the pins clear once the two rows leave the window')
        self.set_prices(PRICE)
        self.pools_step(20, 'unpin')
        p = user.yed_getprice()
        assert_equal((p['pinnedKeys'], p['pinnedSeqs']), ([], []))
        assert_equal(len(user.yed_getfeepayee(user.getblockcount(), 25 * COIN)['eligible']), 3)

        # ---------------------------------------------------------------- RED-5 through a notice
        print('RED-5: pools to $%s (the vault is 300 %%-covered), attestors at $%s (pEmerg under EMERGENCY_RATIO)' % (EMERG_X, EMERG_A))
        self.set_prices(EMERG_X)
        self.pools_step(36, 'pools at $%s' % EMERG_X)
        live = user.yed_getvault(v3['txid'])
        assert_greater_than(user.getblockcount(), int(live['claimHeight']) - 1)
        emerg = {seq: EMERG_A for seq in seqs}
        assert_equal(user.yed_listclaimable(), [])
        ref_probe = user.getblockcount() - REF_LAG
        feed_all(user, emerg, cited=ref_probe)
        assert_equal([r['vault'] for r in user.yed_listclaimable()], [])            # under EMERGENCY_RATIO, not claimable yet
        notice_txid, r1, built = self.notice_raw(USER, v3['txid'], emerg, POOLS[0])
        n = user.yed_getnotice(v3['txid'])
        assert_equal((n['found'], n['txid'], n['refHeight'], n['pEmerg'], n['emergencyOpenAt']),
                     (True, notice_txid, r1, usd_to_micro(EMERG_A), r1 + EMERGENCY_PERSIST))
        for node in self.enforcing_nodes():
            assert_equal(node.yed_getnotice(v3['txid'])['height'], n['height'])
        row = user.yed_getvault(v3['txid'])
        assert_equal((row['noticed'], row['noticeHeight'], row['emergencyOpenAt']), (True, n['height'], r1 + EMERGENCY_PERSIST))
        info = user.yed_gettxinfo(notice_txid)
        assert_equal((info['type'], info['notice'], info['aClaim'], sorted(info['bundleSeqs'])), ('notice', True, built['aClaim'], sorted(built['seqs'])))
        print('not1_reset_attack_fails: a second notice while one stands registers nothing and moves no clock')
        ref = user.getblockcount() - REF_LAG
        feed_all(user, emerg, cited=ref)
        again = user.yed_buildbundle(ref, bytes_to_hex_str(outpoint_selector(v3['txid'], 0)))
        carrier = self.carrier_step(USER, hex_str_to_bytes(again['hex']))
        reset_txid = user.sendrawtransaction(post_notice_raw(user, (v3['txid'], 0), ref, carrier))
        self.sync_all()
        self.stock_step(1, 'reset attack')
        assert_equal(user.getrawtransaction(reset_txid, 1)['confirmations'], 1)
        rpc_error('tx-not-found', user.yed_gettxinfo, reset_txid)
        assert_equal(user.yed_getnotice(v3['txid'])['height'], n['height'])
        while user.getblockcount() - REF_LAG < r1 + EMERGENCY_PERSIST:
            self.pools_step(1, 'persist')
        print('the emergency claim by node 0: clause (b), the residual to the owner (node 6)')
        rows = user.yed_listclaimable()
        assert_equal([(r['vault'], r['claimPath']) for r in rows], [(v3['txid'] + ':0', 'b')])
        assert_greater_than(rows[0]['residualZat'], 100_000)
        before = nodes[ATTESTOR_A].getbalance()
        claimed = self.claim_raw(USER, v3['txid'], a1['token'], emerg, POOLS[1])
        assert_equal(claimed['row']['claimPath'], 'b')
        after = nodes[ATTESTOR_A].getbalance()
        # node 6 also holds the bond keys of attestors 0-2: the attestor fee lands there when the bundle's first seq is one of them
        fee_to_owner = self.attest_fee(int(live['collateralZat'])) if nodes[ATTESTOR_A].validateaddress(
            self.bond_key_address(claimed['info']['bundleSeqs'][0]))['ismine'] else 0
        assert_equal(int((after - before) * COIN), claimed['residual'] + fee_to_owner)
        assert_equal(user.yed_getnotice(v3['txid']), {'found': False})              # IN-2 deleted the record
        assert_equal(user.yed_getvault(v3['txid'])['noticed'], False)

        # ---------------------------------------------------------------- a claim by clause (a)
        print('a claim with a bundle by clause (a): pools and attestors crash to $%s' % CRASH)
        self.set_prices(CRASH)
        self.pools_step(36, 'crash')
        crashed = {seq: CRASH for seq in seqs}
        claimed_a = self.claim_raw(USER, a0['txid'], a0['token'], crashed, POOLS[2])
        assert_equal((claimed_a['row']['claimPath'], claimed_a['residual']), ('a', 0))

        # ---------------------------------------------------------------- equivocation
        eqv_seq = seq_of[4]
        print('equivocation raw: seq %d signs two prices for one height => EJECTED on every node' % eqv_seq)
        cited = user.getblockcount() - REF_LAG
        secret = hot_secret_for(user, eqv_seq)
        a = sign_attestation(secret, eqv_seq, usd_to_micro(CRASH), cited, user.getblockhash(cited))
        b = sign_attestation(secret, eqv_seq, usd_to_micro(CRASH + 1), cited, user.getblockhash(cited))
        carrier = self.carrier_step(USER, encode_bundle([a, b]))
        eqv_txid = user.sendrawtransaction(equivocation_raw(user, carrier))
        self.sync_all()
        self.step(POOLS[0], 1, 'equivocation')
        self.assert_status_everywhere(eqv_seq, 'EJECTED')
        info = user.yed_gettxinfo(eqv_txid)
        assert_equal((info['type'], info['bundleSeqs']), ('equivocation', [eqv_seq]))
        rpc_error('attest-not-eligible', user.yed_addattestation, bytes_to_hex_str(a))
        assert_equal(user.yed_getinfo()['attest']['seatedCount'], N_ATTESTORS - 1)
        live_seqs = [seq for seq in seqs if seq != eqv_seq]

        # ---------------------------------------------------------------- dormancy and revival
        print('restore $%s and let the pins settle' % PRICE)
        self.set_prices(PRICE)
        self.pools_step(36 + 16, 'restore')
        dormant = live_seqs[-1]
        print('dormancy: seq %d seated, selected in %d rows, absent from every bundle => DORMANT at the next check' % (dormant, DORMANCY_MIN_BUNDLES))
        active = {seq: PRICE for seq in live_seqs if seq != dormant}
        start = user.getblockcount()
        rows = 0
        k = 0
        while rows < DORMANCY_MIN_BUNDLES:
            m = self.mint_fresh(USER, active, POOLS[k % 3], price_step=Decimal('0.01') * (k + 1))
            k += 1
            if dormant in m['selected']:
                rows += 1
                assert dormant not in m['seqs']
            assert user.getblockcount() - start < 12, 'seq %d was not selected twice inside the dormancy window' % dormant
        while user.getblockcount() % DORMANCY_CHECK != 0:
            self.pools_step(1, 'to the dormancy check')
        self.assert_status_everywhere(dormant, 'DORMANT')
        assert_equal(user.yed_getinfo()['attest']['seatedCount'], N_ATTESTORS - 1)   # SNAP seats before the dormancy pass (v3 §3.8 order)
        self.pools_step(1, 'after the dormancy check')
        assert_equal(user.yed_getinfo()['attest']['seatedCount'], N_ATTESTORS - 2)   # it leaves the seats at the next SNAP
        print('revive_raw => ELIGIBLE')
        cited = user.getblockcount() - REF_LAG
        att = sign_attestation(hot_secret_for(user, dormant), dormant, usd_to_micro(PRICE), cited, user.getblockhash(cited))
        rev_txid = user.sendrawtransaction(revive_raw(user, att))
        self.sync_all()
        self.step(POOLS[1], 1, 'revive')
        self.assert_status_everywhere(dormant, 'ELIGIBLE')
        assert_equal(user.yed_gettxinfo(rev_txid)['type'], 'revive')
        assert_equal(user.yed_getinfo()['attest']['seatedCount'], N_ATTESTORS - 1)

        # ---------------------------------------------------------------- bond withdrawal
        print('bond spends after the locktime: WITHDRAWN, and the ejected one stays EJECTED')
        recs = self.attestors()
        w_seq, e_seq = seq_of[0], eqv_seq
        locktime = max(int(recs[w_seq]['bondLocktime']), int(recs[e_seq]['bondLocktime']))
        while user.getblockcount() < locktime:
            self.pools_step(1, 'to the bond locktime')
        wallet = nodes[ATTESTOR_A]
        for seq, expect in ((w_seq, 'WITHDRAWN'), (e_seq, 'EJECTED')):
            rec = recs[seq]
            hex_ = withdraw_bond_raw(wallet, rec, bond_secret_for(rec))
            txid = wallet.sendrawtransaction(hex_)
            self.sync_all()
            self.step(POOLS[2], 1, 'bond spend')
            assert_equal(user.getrawtransaction(txid, 1)['confirmations'], 1)
            self.assert_status_everywhere(seq, expect)
            assert_equal(self.attestors()[seq]['bondSpentHeight'], user.getblockcount())
        rpc_error('attest-not-eligible', user.yed_addattestation, bytes_to_hex_str(
            sign_attestation(hot_secret_for(user, w_seq), w_seq, usd_to_micro(PRICE), user.getblockcount() - REF_LAG,
                             user.getblockhash(user.getblockcount() - REF_LAG))))
        assert_equal(user.yed_getinfo()['attest']['seatedCount'], N_ATTESTORS - 2)

        print('assert_model_matches(full=True): the second implementation agrees on every table and every v3 field')
        self.checkpoint('end')
        assert_model_matches(user, full=True)
        print('done: %d blocks' % user.getblockcount())


if __name__ == '__main__':
    YellowbackAttestTest().main()
