#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
In-term claims (docs/plans/yellowback-in-term-claims-plan.md, IT-1..IT-6) on regtest, walking the
explainer's example (yb-calibration docs/reports/2026-10-zec/in-term-claims.html) scaled by ten:

  - three mints, one per class (A 48, B 97, C 145 blocks): the flat tiers 300 / 400 / 500 % price the
    collateral (IT-4: the sigma multiplier is pinned at 1), and the V's appHeight is refHeight + 1 (IT-1);
  - the explainer's vault X: the owner locks 100 YEC at $4.00 ($400 of collateral) against 100 YED
    (400 %; the explainer's 800 % scaled to a regtest balance), a class-B term (97 blocks); the price falls
    inside the term:
      * at $1.40 the vault is at 140 %, above theta 125 %: a claim is invalid at every Yellowback mempool
        (bad-yellowback-vault-claim-not-underwater) and a block carrying it is rejected (DoS 100), the
        vault stays ACTIVE (IT-2);
      * at $1.20 the vault is at 120 %, under theta: the claim is valid in term, the vault moves into the
        claimant intent (CLAIMING), the debt leaves supply at once while the collateral stays in the system
        ratio until release (IT-6); after CLAIM_DELAY vault_release pays the claimant (CLAIMED);
      * IT-9: the owner's redeem before lockHeight pays the class's early-redeem fee (500 / 250 / 100 bps) on top of
        FEE-1 (Y, class A, and Y2, class B); an early redeem paying FEE-1 alone is refused by every mempool and its
        block rejected; yellowback_lifecycle's redeems at or after lockHeight pay FEE-1 only;
      * the residual to the owner under clause (a) is zero by construction (the claimant's cap theta x debt
        exceeds the collateral whenever the vault is under theta); the clause-(b) residual is
        yellowback_attest_wallet's V2 and the unit test in_term_emergency_claim_pays_the_residual_to_the_owner;
  - the owner's redeem is open in term (IT-1 extended: ownerHeight = refHeight + 1): Y is redeemed in term above
    theta, Y2 in term while under theta before anyone claims it, both for the full debt;
  - --armed only: an attestor cancels a wrong-price in-term claim (vault_cancel by the set's member key):
    the vault comes back byte-identical as the same position, ACTIVE; the claimant's burn is not refunded
    (U-24);
  - assert_model_matches(node, full=True) at the end.

Nodes: 0 user (vault owner), 1 stock, 2-4 pools, 5 observer (the claimant).
"""

from decimal import Decimal

from test_framework.util import (
    assert_equal,
    assert_greater_than,
    bytes_to_hex_str,
    hex_str_to_bytes,
    sync_blocks,
    sync_mempools,
)
from test_framework.yellowback_util import (
    CLAIM_DELAY,
    COIN,
    POOLS,
    REF_LAG,
    STOCK,
    YellowbackTestFramework,
    assert_best_hash,
    assert_same_statehash,
    build_mint_tx,
    build_vault_spend_raw,
    early_redeem_fee_zat,
    fee_zat,
    mine_block_raw,
    set_quote,
    usd_to_micro,
    yed_params,
)
from test_framework import yellowback_model as ym
from test_framework import vault as v
from test_framework.yellowback_attest import ArmedModeMixin, armed_raw_claim, hot_secret_for

OVERLAY = [0, 2, 3, 4, 5]
PRICE = Decimal('4.00')         # the explainer's $0.40 x 10: regtest coinbases are small
X_COLLATERAL = 100 * COIN       # 400 % of $100 at $4.00: the explainer's 800 % scaled to node 0's regtest balance; class B's minimum
ABOVE_BPS = 14000               # the price at which X is at 140 % of the $100 debt: above theta ($1.40 for 100 YEC)
AT_BPS = 12000                  # 120 %: under theta 125 % ($1.20 for 100 YEC)
TERMS = {'A': 48, 'B': 97, 'C': 145}
RATIOS = {'A': 30000, 'B': 40000, 'C': 50000}


def assert_rpc_error(substr, fn, *args):
    try:
        fn(*args)
    except Exception as e:
        assert substr in str(e), 'expected %r in %r' % (substr, str(e))
        return
    raise AssertionError('expected an error containing %r' % substr)


def outpoint_selector(txid, n=0):
    return bytes_to_hex_str(bytes.fromhex(txid)[::-1] + n.to_bytes(4, 'little'))


def coin_of(node, cents):
    for c in node.yed_listunspent():
        if c['cents'] == cents and not c['spentUnconfirmed']:
            return c
    raise AssertionError('no %d-cent coin on the node' % cents)


class YellowbackInTermTest(ArmedModeMixin, YellowbackTestFramework):

    def sync_all(self, blocks_only=False):
        """Blocks everywhere; mempools among the overlay nodes only (the stock node keeps what the
        overlay refuses)."""
        for g in self.groups():
            nodes = [self.nodes[i] for i in g if self.nodes[i] is not None]
            sync_blocks(nodes)
            if not blocks_only:
                sync_mempools([self.nodes[i] for i in g if self.nodes[i] is not None and i != STOCK])

    def price(self, usd):
        for i in POOLS:
            set_quote(self.nodes[i], usd)

    def raw_claim(self, node, vault, burn_cents, ref_height):
        coin = coin_of(node, burn_cents)
        payees = node.yed_getfeepayee(ref_height, vault['collateralZat'], outpoint_selector(vault['txid']))
        fee = (payees['default']['payoutAddress'], payees['feeZat'])
        if self.armed:
            return armed_raw_claim(self, node, vault, [(coin['txid'], coin['vout'])], ref_height,
                                   self.price_at(node, ref_height, 'pClaim'), fee)
        payload = ym.encode_redeem(ref_height, 1, [])
        return build_vault_spend_raw(node, vault, 'claim', [(coin['txid'], coin['vout'])], payload=payload,
                                     fee=fee, ref_height=ref_height)

    def settle(self, usd, n=34):
        """Quote ``usd`` on every pool and mine ``n`` round-robin blocks: enough for the lower medians of
        the mid (24) and slow (64) windows to read the new price, well inside a 145-block term."""
        self.price(usd)
        self.mine_round_robin(POOLS, n)
        assert_equal(self.nodes[0].yed_getprice()['pClaim'], usd_to_micro(usd))

    def run_test(self):
        nodes = self.nodes
        user, claimant = nodes[0], nodes[5]
        self.current_quote = PRICE

        print('activate at $%s; fund the claimant' % PRICE)
        self.activate(POOLS, quote_usd=PRICE)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        user.sendtoaddress(claimant.getnewaddress(), 5)
        self.sync_all()
        self.mine(POOLS[0])
        self.arm()
        params = user.yed_getinfo()['params']
        assert_equal(params['inTermClaims'], True)
        assert_equal(params['claimThresholdBps'], 12500)
        assert_equal((params['sigmaRefBps'], params['sigmaMultMaxBps']), (0, 10000))
        assert_equal([(c['class'], c['minBlocks'], c['maxBlocks'], c['baseRatioBps']) for c in params['classes']],
                     [('A', 48, 96, 30000), ('B', 97, 144, 40000), ('C', 145, 240, 50000)])
        assert_equal(params['recapRatioBps'], 50000)

# Rule: MINT-1 MINT-5 IT-1 IT-4
        print('mint one vault per class: 300 / 400 / 500 %% of $100 at $%s, appHeight = refHeight + 1' % PRICE)
        mints = {}
        for cls, lock in TERMS.items():
            est = self.estimate(user, 10000, lock)
            assert_equal((est['termClass'], est['minRatioBps'], est['sigmaMultBps']), (cls, RATIOS[cls], 10000))
            assert_equal(est['requiredZat'], ym.required_zat(10000, RATIOS[cls], usd_to_micro(PRICE)))
            mints[cls] = self.mint(user, 10000, lock)
            assert_equal(mints[cls]['termClass'], cls)
            self.sync_all()
            self.mine(POOLS[0])
            vault = user.yed_getvault(mints[cls]['txid'])
            assert_equal(vault['status'], 'ACTIVE')
            assert_equal(vault['collateralZat'], est['requiredZat'])
            dec = user.vault_decodescript(vault['scriptPubKey'])
            assert_equal((dec['type'], dec['ownerheight'], dec['appheight']), ('vault', vault['refHeight'] + 1, vault['refHeight'] + 1))   # IT-1: both branches open at the mint
            assert_equal(vault['claimHeight'], vault['lockHeight'] + yed_params().grace)
        assert_equal(nodes[2].yed_getstats()['supplyCents'], 30000)

# Rule: MINT-3 IT-1
        print('the pre-plan V shape (appHeight = lockHeight + GRACE) is refused for a new mint')
        r = user.yed_getinfo()['height'] - REF_LAG
        owner = hex_str_to_bytes(user.validateaddress(user.getnewaddress())['pubkey'])
        lock = r + 48
        old_shape = ym.yed_vault_script_at(yed_params(), owner, lock, lock + yed_params().grace)
        old_hex, _ = build_mint_tx(user, 10000, 48, r, self.estimate(user, 10000, 48)['requiredZat'], owner_pubkey=bytes_to_hex_str(owner))
        old_tx = ym.tx_from_hex(old_hex)
        assert_equal(old_tx.vout[0].script, ym.yed_vault_script(yed_params(), owner, r))
        vin = [(i.prev_txid, i.prev_n, b'', 0xFFFFFFFF) for i in old_tx.vin]
        vout = [(o.value, old_shape if j == 0 else o.script) for j, o in enumerate(old_tx.vout)]
        bad_hex = user.signrawtransaction(bytes_to_hex_str(ym.serialize_tx_v4(vin, vout, 0, old_tx.expiry_height)))['hex']
        for i in OVERLAY:
            assert_rpc_error('bad-yellowback-bad-mint-vault-script', nodes[i].sendrawtransaction, bad_hex)
        result, _ = mine_block_raw(nodes[POOLS[1]], [bad_hex])
        assert_equal(result, 'bad-yellowback-bad-mint-vault-script')

# Rule: MINT-1 IT-1
        print("Y for the owner's redeem; the explainer's vault X: 100 YEC (400 %) against 100 YED for a class-B term")
        y = self.mint(user, 10000, TERMS['A'])
        self.sync_all()
        self.mine(POOLS[1])
        r = user.yed_getinfo()['height'] - REF_LAG
        if self.armed:
            # armed: the wallet's mint carries the bundle; the raw builder has none, so X is minted through the wallet
            x_txid = self.mint(user, 10000, TERMS['B'])['txid']
        else:
            x_hex, _x_owner = build_mint_tx(user, 10000, TERMS['B'], r, X_COLLATERAL,
                                            fee_addr=user.yed_getfeepayee(r, X_COLLATERAL)['default']['payoutAddress'])
            x_txid = user.sendrawtransaction(x_hex)
        self.sync_all()
        self.mine(POOLS[2])
        vx = user.yed_getvault(x_txid)
        assert_equal(vx['status'], 'ACTIVE')
        if not self.armed:
            assert_equal(vx['collateralZat'], X_COLLATERAL)
            assert_equal(vx['termClass'], 'B')
        # (yed_getvault does not carry appHeight until T2: the V's appHeight is read from the script above)
        x_lock = vx['lockHeight']
        # the explainer's two prices, scaled to X's collateral: 140 % (above theta) and 120 % (under it)
        ABOVE = (Decimal(ABOVE_BPS) / 100 / (Decimal(vx['collateralZat']) / COIN)).quantize(Decimal('0.0001'))
        AT = (Decimal(AT_BPS) / 100 / (Decimal(vx['collateralZat']) / COIN)).quantize(Decimal('0.0001'))
        assert_equal(ym.is_underwater(vx['collateralZat'], usd_to_micro(ABOVE), 10000, 12500), False)
        assert_equal(ym.is_underwater(vx['collateralZat'], usd_to_micro(AT), 10000, 12500), True)
        user.yed_send(claimant.yed_getnewaddress(), 10000)
        user.yed_send(claimant.yed_getnewaddress(), 10000)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(claimant.yed_getbalance()['confirmedCents'], 20000)

# Rule: RED-1 RED-2 RED-4 IT-1 IT-2
        print("Y in term, above theta: nobody can claim it, its owner can redeem it (IT-1 extended: both branches open at the mint)")
        vy = user.yed_getvault(y['txid'])
        assert_greater_than(vy['lockHeight'], user.getblockcount())
        assert_rpc_error('claim-not-underwater', claimant.yed_claim, *self.claim_args(claimant, y['txid']))
        # IT-9: a redeem before lockHeight pays the class's early-redeem fee (A: 500 bps of the collateral) on top of FEE-1
        early = early_redeem_fee_zat(vy['collateralZat'], 'A')
        assert_equal(params['earlyRedeemFeeBps'], [500, 250, 100])
        redeemed = user.yed_redeem(y['txid'])
        assert_equal((redeemed['burnedCents'], redeemed['earlyRedeemFeeZat'], redeemed['feeZat']),
                     (10000, early, fee_zat(vy['collateralZat']) + early))
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(nodes[2].yed_getvault(y['txid'])['status'], 'CLOSED')
        assert_equal(nodes[2].yed_getvault(y['txid'])['feePaidZat'], fee_zat(vy['collateralZat']) + early)
        y2 = self.mint(user, 10000, TERMS['B'])                                        # Y2 (class B, 400 %: under theta at AT, a 97-block term): redeemed in term while under theta, below
        self.sync_all()
        self.mine(POOLS[2])

# Rule: RED-4 MP-1 BLK-1 IT-2
        print('the price falls to $%s: X is at ~140 %%, above theta; an in-term claim is invalid everywhere' % ABOVE)
        self.current_quote = ABOVE
        self.settle(ABOVE)
        assert_greater_than(x_lock, user.getblockcount())
        vx = user.yed_getvault(x_txid)
        assert_equal(vx['claimable'], False)
        listed = {c['vault']: c for c in user.yed_listclaimable()}
        assert_equal((listed[x_txid + ':0']['claimable'], listed[x_txid + ':0']['underwaterAt']), (False, vx['underwaterAt']))   # IT-7: listed above theta, with its price
        assert_rpc_error('claim-not-underwater', claimant.yed_claim, *self.claim_args(claimant, x_txid))
        hex_above = self.raw_claim(claimant, vx, 10000, user.getblockcount())
        assert_equal(ym.tx_from_hex(hex_above).lock_time, vx['refHeight'] + 1)          # the APP branch's CLTV (IT-1)
        val = nodes[2].yed_validaterawtransaction(hex_above)
        assert_equal((val['valid'], val['verdict'], val['path'], val['blockValid'], val['wouldBeRejected']),
                     (True, 'vault-claim-not-underwater', 'claim', False, True))
        # (yellowback_claim.py shows the stock node accepting such a claim; here it would sit in the stock mempool,
        # expire during the next price step and be re-relayed to the claimant, whose only path to the overlay it is)
        for i in OVERLAY:
            assert_rpc_error('bad-yellowback-vault-claim-not-underwater', nodes[i].sendrawtransaction, hex_above)
        result, _ = mine_block_raw(nodes[3], [hex_above])      # a block carrying it is rejected (DoS 100)
        assert_equal(result, 'bad-yellowback-vault-claim-not-underwater')
        assert_equal(nodes[3].yed_getvault(x_txid)['status'], 'ACTIVE')
        self.checkpoint('above theta')

# Rule: RED-1 RED-2 RED-3 RED-4 RED-5 IT-2 IT-3 IT-6
        print('the price falls to $%s: X is at ~120 %%, under theta; the in-term claim is valid, CLAIMING' % AT)
        self.current_quote = AT
        self.settle(AT)
        assert_greater_than(x_lock, user.getblockcount())
        vx = user.yed_getvault(x_txid)
        assert_equal(vx['claimable'], True)
        listed = {c['vault']: c for c in claimant.yed_listclaimable()}
        assert x_txid + ':0' in listed
        assert_equal(listed[x_txid + ':0']['claimable'], True)
        assert_equal(listed[x_txid + ':0']['residualZat'], 0)   # clause (a): the claimant's cap (theta x debt) exceeds the collateral
        stats_before = nodes[2].yed_getstats()
        claimed = self.claim(claimant, x_txid)
        assert_equal((claimed['claimPath'], claimed['residualZat'], claimed['burnedCents'], claimed['pending']), ('a', 0, 10000, False))
        assert_equal(claimed['collateralOut'], vx['collateralZat'])
        raw = claimant.getrawtransaction(claimed['txid'], 1)
        assert_equal(raw['locktime'], vx['refHeight'] + 1)
        assert_equal(raw['vin'][0]['scriptSig']['hex'], '54')            # OP_4: the V's claim selector
        self.sync_all()
        self.mine(POOLS[2])
        claim_block = user.getblockcount()
        assert_greater_than(x_lock, claim_block)                         # claimed in term
        for i in OVERLAY:
            c = nodes[i].yed_getvault(x_txid)
            assert_equal((c['status'], c['burnedCents']), ('CLAIMING', 10000))
            assert_equal([(x['txid'], x['vout'], x['role'], x['releaseHeight']) for x in c['intents']],
                         [(claimed['txid'], 0, 'claimant', claim_block + CLAIM_DELAY)])
        stats = nodes[2].yed_getstats()
        assert_equal(stats['supplyCents'], stats_before['supplyCents'] - 10000)        # the debt left supply with the burn
        assert_equal(stats['collateralZat'], stats_before['collateralZat'])            # IT-6: the collateral stays until release
        assert_equal(stats['activeVaults'], stats_before['activeVaults'] - 1)
        assert_rpc_error('vault-not-active', claimant.yed_claim, x_txid)
        assert_rpc_error('vault-not-active', user.yed_redeem, x_txid)
        self.checkpoint('claim at theta')

# Rule: RED-1 RED-2 RED-3 IT-1 IT-2
        print("Y2 in term and under theta, before anyone claims it: the owner redeems, paying the full debt (D-IT-16 is a later decision)")
        vy2 = user.yed_getvault(y2['txid'])
        assert_greater_than(vy2['lockHeight'], user.getblockcount())
        assert_equal(vy2['claimable'], True)
        # IT-9: an early redeem paying FEE-1 alone is refused by every Yellowback mempool (bad-redeem-early-fee)
        r = user.getblockcount()
        payee = user.yed_getfeepayee(r, vy2['collateralZat'])['default']['payoutAddress']
        coin = coin_of(user, 10000)
        short_hex = build_vault_spend_raw(user, vy2, 'owner', [(coin['txid'], coin['vout'])],
                                          payload=ym.encode_redeem(r, 1, []), fee=(payee, fee_zat(vy2['collateralZat'])), ref_height=r)
        for i in OVERLAY:
            assert_rpc_error('bad-yellowback-bad-redeem-early-fee', nodes[i].sendrawtransaction, short_hex)
        result, _ = mine_block_raw(nodes[POOLS[2]], [short_hex])
        assert_equal(result, 'bad-yellowback-bad-redeem-early-fee')
        redeemed = user.yed_redeem(y2['txid'])
        assert_equal((redeemed['burnedCents'], redeemed['earlyRedeemFeeZat']), (10000, early_redeem_fee_zat(vy2['collateralZat'], 'B')))
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(nodes[2].yed_getvault(y2['txid'])['status'], 'CLOSED')
        assert_rpc_error('vault-not-active', claimant.yed_claim, y2['txid'])

# Rule: RED-1 IT-6
        print('the release waits CLAIM_DELAY, then vault_release pays the claimant: CLAIMED; the collateral leaves the ratio')
        intent = '%s:0' % claimed['txid']
        assert_rpc_error('matures at height', claimant.vault_release, intent)
        self.mine_round_robin(POOLS, claim_block + CLAIM_DELAY - 1 - user.getblockcount())
        yec_before = claimant.getbalance()
        before_release = nodes[2].yed_getstats()                          # Y2's redeem sits between the claim and this release
        released = claimant.vault_release(intent)
        self.sync_all()
        self.mine(POOLS[0])
        for i in OVERLAY:
            c = nodes[i].yed_getvault(x_txid)
            assert_equal(c['status'], 'CLAIMED')
            assert 'intents' not in c
        stats = nodes[2].yed_getstats()
        assert_equal(stats['collateralZat'], before_release['collateralZat'] - vx['collateralZat'])   # IT-6: the claimed collateral leaves at release
        assert_equal(stats['claimedVaults'], 1)
        assert_greater_than(claimant.getbalance(), yec_before + Decimal(vx['collateralZat']) / COIN - 1)
        assert_equal(nodes[2].yed_gettxinfo(released)['type'], 'claim_release')
        assert_greater_than(x_lock, user.getblockcount())                 # the whole claim completed inside X's term
        self.checkpoint('release')

# Rule: RED-4 IT-2
        print('the class vaults minted at $%s: A (300 %%) and B (400 %%) are under theta at $%s, C (500 %%) is not' % (PRICE, AT))
        claimable = {c['vault'] for c in user.yed_listclaimable() if c['claimable']}   # IT-7
        for cls, m in mints.items():
            vault = user.yed_getvault(m['txid'])
            under = ym.is_underwater(vault['collateralZat'], usd_to_micro(AT), 10000, 12500)
            assert_equal(under, cls != 'C')
            assert_equal(vault['claimable'], under)
            assert_equal(m['txid'] + ':0' in claimable, under)

        if self.armed:
            self.cancel_case(mints['A'])
        else:
            print('(the attestor cancel of a wrong-price in-term claim runs under --armed: the set has members then)')

        print('the Python model over the whole chain (P8)')
        self.model_check(nodes[0])
        self.sync_all(blocks_only=True)
        assert_best_hash(self.enforcing_nodes(), 'end')
        assert_same_statehash(self.enforcing_nodes(), 'end')

# Rule: RED-4 I-2 U-24 IT-2
    def cancel_case(self, mint):
        """--armed: the claimant claims the class-A vault in term with a bundle at a wrong (low) price; an
        attestor cancels the claimant intent (selector 2, one member signature: the set's cancel threshold is
        1): the vault is back as the same position, ACTIVE, at the cancel's vout 0; the burn is not refunded."""
        nodes = self.nodes
        user, claimant = nodes[0], nodes[5]
        print("--armed: an attestor cancels the claimant's in-term claim of the class-A vault; the vault is back, the burn kept")
        vault = user.yed_getvault(mint['txid'])
        supply_before = nodes[2].yed_getstats()['supplyCents']
        claimed = self.claim(claimant, mint['txid'])
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(nodes[2].yed_getvault(mint['txid'])['status'], 'CLAIMING')
        assert_equal(nodes[2].yed_getstats()['supplyCents'], supply_before - 10000)
        raw = claimant.getrawtransaction(claimed['txid'], 1)
        ispk = hex_str_to_bytes(raw['vout'][0]['scriptPubKey']['hex'])
        ip = v.IntentParams(*ym.yed_intent_fields(ispk))
        owner = hex_str_to_bytes(vault['ownerPubKey'])
        s = yed_params().attestor_set_internal
        vp = v.VaultParams(ym.YED_TAG, s, s, CLAIM_DELAY, vault['lockHeight'], vault['refHeight'] + 1, owner)
        assert_equal(v.sha256(v.vault_script(vp)), ip.vault_hash)
        secret = hot_secret_for(user, 0)
        cancel_hex = v.node_cancel(user, (claimed['txid'], 0), ip, raw['vout'][0]['valueZat'], vp, [secret])
        cancel_txid = user.sendrawtransaction(cancel_hex)
        self.sync_all()
        self.mine(POOLS[2])
        for i in OVERLAY:
            back = nodes[i].yed_getvault(cancel_txid)
            assert_equal((back['status'], back['collateralZat'], back['mintedCents'], back['lockHeight']),
                         ('ACTIVE', raw['vout'][0]['valueZat'], 10000, vault['lockHeight']))
            assert_rpc_error('vault-not-found', nodes[i].yed_getvault, mint['txid'])
        assert_equal(nodes[2].yed_getstats()['supplyCents'], supply_before - 10000)      # U-24: the burn is not refunded
        assert_equal(nodes[2].yed_gettxinfo(cancel_txid)['type'], 'claim_cancel')
        self.checkpoint('cancel')


if __name__ == '__main__':
    YellowbackInTermTest().main()
