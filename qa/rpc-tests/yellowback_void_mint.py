#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
VOID mints (plan §3.8 MINT-1..8, V3, K3, L14): every failing MINT rule registers a VOID vault
whose collateral is locked until lockHeight and released by yed_redeem with no burn and no fee
(void_release_via_yed_redeem); a mint before activation is VOID; a mint under each halt is VOID
and the wallet refuses it with the matching mintpol-* identifier (MINTPOL-1); the supply-cap race
across a reorg voids the loser (mint6_cap_race_after_reorg).

Nodes: 0 user, 1 stock, 2-4 pools, 5 observer; every overlay node runs with the same
-yellowbacksupplycapbps so the cap verdict is one every node records.
"""

from decimal import Decimal

from test_framework.util import (
    assert_equal,
    assert_greater_than,
    bytes_to_hex_str,
    hex_str_to_bytes,
    sync_mempools,
)
from test_framework.yellowback_util import (
    COIN,
    FEE_VOUT_NONE,
    GRACE,
    POOLS,
    REF_LAG,
    REF_WINDOW,
    STOCK,
    TOKEN_VALUE,
    YELLOWBACK_FEE,
    YellowbackTestFramework,
    assert_same_statehash,
    fee_zat,
    mine_block_raw,
    node_pubkey,
    set_quote,
    term_class_of,
)
from test_framework import yellowback_model as ym
from test_framework.yellowback_attest import ArmedModeMixin, armed_raw_mint

SUPPLY_CAP_BPS = 60


def assert_rpc_error(substr, fn, *args):
    try:
        fn(*args)
    except Exception as e:
        assert substr in str(e), 'expected %r in %r' % (substr, str(e))
        return
    raise AssertionError('expected an error containing %r' % substr)


class YellowbackVoidMintTest(ArmedModeMixin, YellowbackTestFramework):

    initial_blocks = 112     # eleven mature coinbases (68.75 YEC) fund the pre-activation raw mint

    def node_args(self, i, extra=None):
        if i != STOCK:
            extra = list(extra or []) + ['-yellowbacksupplycapbps=%d' % SUPPLY_CAP_BPS]
        return super().node_args(i, extra)

    # --- a raw MINT with every knob (section 3.5 layout unless told otherwise) ---------------------

    def raw_mint(self, node, cents, lock_blocks, ref, collateral, fee_addr=None, fee=None, payload=None,
                 vault_script=None, token_first=True, expiry=None):
        owner_hex = node_pubkey(node)
        owner = hex_str_to_bytes(owner_hex)
        lock_height = ref + lock_blocks
        claim_height = lock_height + GRACE
        script = vault_script if vault_script is not None else ym.vault_script(lock_height, owner, claim_height)
        fee_vout = 3 if fee_addr else FEE_VOUT_NONE
        if payload is None:
            payload = ym.encode_mint('ABC'.index(term_class_of(lock_blocks) or 'A'), cents, lock_height, ref, owner, fee_vout)
        token = (TOKEN_VALUE, ym.p2pkh_script(ym.hash160(owner)))
        opret = (0, bytes([ym.OP_RETURN]) + ym.push(payload))
        vout = [(collateral, ym.p2sh_script(script))] + ([token, opret] if token_first else [opret, token])
        enforcement_fee = 0
        if fee_addr:
            enforcement_fee = fee_zat(collateral) if fee is None else fee
            vout.append((enforcement_fee, ym.p2pkh_script(ym.address_key_hash(fee_addr))))
        needed = collateral + TOKEN_VALUE + enforcement_fee + YELLOWBACK_FEE
        utxos = [u for u in node.listunspent(1) if int(Decimal(str(u['amount'])) * COIN) > 20 * TOKEN_VALUE
                 and not ym.is_p2sh(hex_str_to_bytes(u['scriptPubKey']))]
        utxos.sort(key=lambda u: Decimal(str(u['amount'])), reverse=True)
        chosen, total = [], 0
        for u in utxos:
            chosen.append(u)
            total += int(Decimal(str(u['amount'])) * COIN)
            if total >= needed:
                break
        assert total >= needed
        if total > needed:
            vout.append((total - needed, ym.p2pkh_script(ym.address_key_hash(node.getnewaddress()))))
        vin = [(u['txid'], u['vout'], b'', 0xFFFFFFFF) for u in chosen]
        raw = ym.serialize_tx_v4(vin, vout, 0, ref + REF_WINDOW if expiry is None else expiry)
        signed = node.signrawtransaction(bytes_to_hex_str(raw))
        assert_equal(signed['complete'], True)
        return signed['hex']

    def raw_mint_v3(self, node, cents, lock_blocks, ref, collateral, fee_addr=None):
        """``raw_mint`` for a case whose verdict lies past MINT-9 in the armed order (R15: MINT-5 and
        the ACTIVE case): under --armed the carrier is mined first and the bundle and attestor fee
        ride along, so the verdict under test is reached; unarmed it is ``raw_mint``."""
        if not self.armed:
            return self.raw_mint(node, cents, lock_blocks, ref, collateral, fee_addr=fee_addr)
        return armed_raw_mint(self, node, cents, lock_blocks, ref, collateral, self.price_at(node, ref, 'pMint'), fee_addr=fee_addr)[0]

    def send_and_mine(self, node, hex_, miner):
        """Mine ``hex_`` in a block of its own, assembled in Python on ``miner``.  TPL-2 (strict,
        the daemon default) skips a MINT whose verdict would be VOID, so no node's template will
        ever carry the mints this script is about: the block is built by hand (plan 6.0 item 4,
        docs/mapping.md section 13.5).  ``miner``'s own coinbase tag is used, so the price and
        signal windows advance exactly as they would with ``generate``."""
        txid = node.decoderawtransaction(hex_)['txid']
        result, _ = mine_block_raw(self.nodes[miner], [hex_])
        assert result is None, result
        self.sync_all(blocks_only=True)
        return txid

    def expect_void(self, txid, reason):
        for i in (0, 2, 3, 4, 5):
            v = self.nodes[i].yed_getvault(txid)
            assert_equal((v['status'], v['voidReason']), ('VOID', reason))
            assert_equal(v['sweepBefore'], v['claimHeight'])
            assert_equal(self.nodes[i].yed_gettxinfo(txid)['verdict'], reason)
            assert_equal(self.nodes[i].yed_gettxinfo(txid)['yedOut'], 0)
        assert_same_statehash(self.enforcing_nodes())

    def ref(self):
        return self.nodes[0].yed_getinfo()['height'] - REF_LAG

    def collateral(self, cents=10000, lock=48):
        return self.estimate(self.nodes[0], cents, lock)['requiredZat']

    def run_test(self):
        nodes = self.nodes
        user, stock, observer = nodes[0], nodes[STOCK], nodes[5]

# Rule: MINT-4 MINTPOL-1 HALT-4
        print('mint4_not_active: a mint before activation is VOID; the wallet refuses with mintpol-not-active')
        assert_equal(user.yed_getactivation()['status'], 'signaling')
        assert_rpc_error('mintpol-not-active', user.yed_mint, 10000, 48)
        void_na = self.send_and_mine(user, self.raw_mint(user, 10000, 48, self.ref(), 10 * COIN), 0)   # node 0 mines: no tag
        self.expect_void(void_na, 'mint-not-active')
        assert_equal(nodes[2].yed_getstats()['voidVaults'], 1)
        assert_equal(nodes[2].yed_getstats()['collateralZat'], 0)     # VOID collateral is outside Totals

        print('activate at $50')
        self.activate(POOLS, quote_usd=50)
        user.sendtoaddress(observer.getnewaddress(), 100)
        self.sync_all()
        self.mine_round_robin(POOLS, REF_LAG + 1)
        assert_equal(user.yed_getstats()['mintingAllowed'], True)
        assert_equal(user.yed_getstats()['supplyCapCents'] > 20000, True)
        self.arm()

# Rule: MINT-4 HALT-1 MINTPOL-1
        print('mintpol-no-price: eight untagged blocks empty the fast window')
        stock.generate(8)
        self.sync_all(blocks_only=True)
        assert 'NO_PRICE' in user.yed_gethistory(self.ref(), self.ref())[0]['haltMask']
        assert_equal(user.yed_getprice(self.ref())['pFast'], None)
        assert_rpc_error('mintpol-no-price', user.yed_mint, 10000, 48)
        void_np = self.send_and_mine(user, self.raw_mint(user, 10000, 48, self.ref(), 10 * COIN), POOLS[0])
        self.expect_void(void_np, 'mint-halted-no-price')
        self.mine_round_robin(POOLS, 20)
        assert_equal(user.yed_getstats()['mintingAllowed'], True)

# Rule: MINT-4 HALT-3 MINTPOL-1
        print('mintpol-divergence: the fast window drops to $20 while the mid window holds $50 (supply is 0, so HALT-2 stays clear)')
        for i in POOLS:
            set_quote(nodes[i], 20)
        self.mine_round_robin(POOLS, 8 + REF_LAG)
        assert_equal(user.yed_gethistory(self.ref(), self.ref())[0]['haltMask'], ['DIVERGENCE'])
        assert_rpc_error('mintpol-divergence', user.yed_mint, 10000, 48)
        void_dv = self.send_and_mine(user, self.raw_mint(user, 10000, 48, self.ref(), 10 * COIN), POOLS[1])
        self.expect_void(void_dv, 'mint-halted-divergence')
        for i in POOLS:
            set_quote(nodes[i], 50)
        self.mine_round_robin(POOLS, 12)
        assert_equal(user.yed_getstats()['haltMask'], [])
        self.mine_round_robin(POOLS, REF_LAG)

# Rule: MINT-1
        print('mint1_malformed_payload: a truncated MINT payload is not a mint at all (no vault, no TxLog row)')
        good_payload = ym.encode_mint(0, 10000, self.ref() + 48, self.ref(), hex_str_to_bytes(node_pubkey(user)), FEE_VOUT_NONE)
        txid = self.send_and_mine(user, self.raw_mint(user, 10000, 48, self.ref(), 10 * COIN, payload=good_payload[:-5]), POOLS[2])
        assert_rpc_error('vault-not-found', user.yed_getvault, txid)
        assert_rpc_error('tx-not-found', nodes[2].yed_gettxinfo, txid)
        assert_equal(nodes[2].yed_getstats()['voidVaults'], 3)

# Rule: MINT-2
        print('mint2_bad_ref_height: refHeight = H - 41 is outside the window')
        old = self.ref() - (REF_WINDOW - REF_LAG)     # H - R = 41 at confirmation
        # nExpiryHeight = R + REF_WINDOW would be the next block: the mempool refuses that as
        # expiring soon (TX_EXPIRING_SOON_THRESHOLD), so this adversarial mint carries a later expiry
        void_ref = self.send_and_mine(user, self.raw_mint(user, 10000, 48, old, 10 * COIN, expiry=user.getblockcount() + 10), POOLS[0])
        self.expect_void(void_ref, 'bad-mint-ref-height')

# Rule: MINT-3
        print('mint3_bad_vault_script: vout[0] commits to a vault script with another lockHeight')
        r = self.ref()
        wrong = ym.vault_script(r + 49, hex_str_to_bytes(node_pubkey(user)), r + 49 + GRACE)
        void_vs = self.send_and_mine(user, self.raw_mint(user, 10000, 48, r, 10 * COIN, vault_script=wrong), POOLS[1])
        self.expect_void(void_vs, 'bad-mint-vault-script')

# Rule: MINT-5 K14
        print('mint5_bad_collateral: 0.00001 YEC short of the requirement')
        r = self.ref()
        req = self.collateral()
        # armed (R15): MINT-8 precedes MINT-5, so the shape carries the pool fee too; unarmed the v2 order stands
        col_fee = user.yed_getfeepayee(r, req - 1000)['eligible'][0] if self.armed else None
        void_col = self.send_and_mine(user, self.raw_mint_v3(user, 10000, 48, r, req - 1000, fee_addr=col_fee), POOLS[2])
        self.expect_void(void_col, 'bad-mint-collateral')
        void_col_vault = user.yed_getvault(void_col)
        assert_equal(void_col_vault['collateralZat'], req - 1000)
        assert_equal(void_col_vault['mintedCents'], 10000)     # recorded from the payload; a VOID vault carries no debt
        assert_equal(nodes[2].yed_getstats()['supplyCents'], 0)
        print('the wallet never under-collateralises: yed_mint at the same snapshot is ACTIVE')
        good = self.mint(user, 10000, 48)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(user.yed_getvault(good['txid'])['status'], 'ACTIVE')
        assert_equal(good['collateralZat'] >= req, True)
        assert_equal(nodes[2].yed_getstats()['supplyCents'], 10000)

# Rule: MINT-7
        print('mint7_bad_token_output: vout[1] is the OP_RETURN')
        void_tok = self.send_and_mine(user, self.raw_mint(user, 10000, 48, self.ref(), self.collateral(), token_first=False), POOLS[1])
        self.expect_void(void_tok, 'bad-mint-token-output')

# Rule: MINT-8 FEE-2
        print('mint8_bad_fee: the fee output pays a key outside E(R); then a short fee to an eligible key')
        r = self.ref()
        void_fee = self.send_and_mine(user, self.raw_mint(user, 10000, 48, r, self.collateral(), fee_addr=stock.getnewaddress()), POOLS[2])
        self.expect_void(void_fee, 'bad-mint-fee')
        r = self.ref()
        eligible = user.yed_getfeepayee(r, self.collateral())['eligible'][0]
        void_short = self.send_and_mine(user, self.raw_mint(user, 10000, 48, r, self.collateral(), fee_addr=eligible, fee=fee_zat(self.collateral()) - 1), POOLS[0])
        self.expect_void(void_short, 'bad-mint-fee')
        print('and the same shape with the right fee is ACTIVE')
        r = self.ref()
        # armed: pMint = min(xMint, aMint) is the attested price, so the requirement is sized at it
        col = self.collateral()          # armed too: the attestors track xMint, so pMint = xMint
        eligible = user.yed_getfeepayee(r, col)['eligible'][0]
        ok = self.send_and_mine(user, self.raw_mint_v3(user, 10000, 48, r, col, fee_addr=eligible), POOLS[1])
        assert_equal(user.yed_getvault(ok)['status'], 'ACTIVE')
        assert_equal(user.yed_getvault(ok)['feePaidZat'], fee_zat(col))
        assert_equal(nodes[2].yed_getstats()['supplyCents'], 20000)
        assert_equal(nodes[2].yed_getstats()['voidVaults'], 9)
        self.checkpoint('rule cases')

# Rule: MINT-4 ACT-4 MINTPOL-1
        print('mintpol-participation: the pools stop signalling; 27 unsignalled blocks set PARTICIPATION')
        for i in POOLS:
            self.restart(i, ['-yellowbacksignal=0'])
            set_quote(nodes[i], 50)
        self.mine_round_robin(POOLS, 27 + REF_LAG)
        act = user.yed_getactivation()
        assert_equal(act['mintHalted'], True)
        assert_equal(act['status'], 'active')
        assert_rpc_error('mintpol-participation', user.yed_mint, 10000, 48)
        void_pa = self.send_and_mine(user, self.raw_mint(user, 10000, 48, self.ref(), self.collateral()), POOLS[0])
        self.expect_void(void_pa, 'mint-halted-participation')
        for i in POOLS:
            self.restart(i)
            set_quote(nodes[i], 50)
        self.mine_round_robin(POOLS, 48 + REF_LAG)
        assert_equal(user.yed_getactivation()['mintHalted'], False)
        assert_equal(user.yed_getstats()['mintingAllowed'], True)

# Rule: MINT-6 UNDO
        print('mint6_cap_race_after_reorg: two mints that together exceed the cap on different branches')
        stats = user.yed_getstats()
        headroom = stats['supplyCapCents'] - stats['supplyCents']
        m = (headroom * 6 // 10) // 100 * 100
        assert_greater_than(m, 10000)
        void_before = stats['voidVaults']
        self.split_network()
        mint_x = self.mint(user, m, 48)                    # the carrier's block, then the mint's
        sync_mempools([nodes[i] for i in (0, 2, 3, 4)])
        self.mine(POOLS[0])
        assert_equal(user.yed_getvault(mint_x['txid'])['status'], 'ACTIVE')
        mint_y = self.mint(observer, m, 48, miner=STOCK)   # the observer sits on the stock half
        sync_mempools([nodes[1], nodes[5]])
        stock.generate(2)                                  # three stock blocks against the enforcing half's two
        self.join_network()
        assert_equal(user.getbestblockhash(), stock.getbestblockhash())
        assert_equal(user.yed_getvault(mint_y['txid'])['status'], 'ACTIVE')
        assert mint_x['txid'] in user.getrawmempool()
        sync_mempools([nodes[i] for i in (0, 2, 3, 4)])
        # On the joined chain X is over the cap, so its verdict is VOID and TPL-2 (strict) keeps
        # it out of every template — including the one that would confirm the race.  Its block is
        # assembled in Python, and the stock half never held X so its mempool is not synced here
        # (plan 6.0 item 4, docs/mapping.md section 13.5).  v3: X's carrier came back with it and
        # must confirm first (a pool template carries the carrier and skips X).
        x_hex = user.getrawtransaction(mint_x['txid'])
        nodes[POOLS[1]].generate(1)
        self.sync_all(blocks_only=True)
        sync_mempools([nodes[i] for i in (0, 2, 3, 4)])
        assert mint_x['txid'] in user.getrawmempool()
        result, _ = mine_block_raw(nodes[POOLS[1]], [x_hex])
        assert result is None, result
        self.sync_all(blocks_only=True)
        self.expect_void(mint_x['txid'], 'mint-supply-cap')
        assert_equal(nodes[2].yed_getstats()['voidVaults'], void_before + 1)
        assert_equal(nodes[2].yed_getstats()['supplyCents'], 20000 + m)
        stats = user.yed_getstats()      # v3: the carrier blocks added issuance, so the cap moved; provoke it from the current numbers
        assert_rpc_error('mintpol-cap', user.yed_mint, stats['supplyCapCents'] - stats['supplyCents'] + 100, 48)
        self.checkpoint('cap race')

# Rule: MINT-4 HALT-2 MINTPOL-1
        print('mintpol-global-ratio: the price falls to $20 and the global ratio to 200 %')
        for i in POOLS:
            set_quote(nodes[i], 20)
        self.mine_round_robin(POOLS, 8 + REF_LAG)
        assert 'GLOBAL_RATIO' in user.yed_gethistory(self.ref(), self.ref())[0]['haltMask']
        assert_greater_than(25000, user.yed_getstats()['globalRatioBps'])
        # W16: the halt stops the classes below the recapitalisation floor (500 %): C here; a class A
        # mint passes the global-ratio clause and meets the next halt, DIVERGENCE, for now
        assert_rpc_error('mintpol-global-ratio', user.yed_mint, 10000, 145)
        assert_rpc_error('mintpol-divergence', user.yed_mint, 10000, 48)
        assert_equal(user.yed_getstats()['mintableClasses'], [])
        void_gr = self.send_and_mine(user, self.raw_mint(user, 10000, 145, self.ref(), 30 * COIN), POOLS[2])
        self.expect_void(void_gr, 'mint-halted-global-ratio')

# Rule: HALT-2 MINTPOL-1
        print('W16 under this script\'s supply cap: the windows agree at $20, the halt persists, and the cap -- proportional to the price -- binds first')
        self.mine_round_robin(POOLS, 64)
        stats = user.yed_getstats()
        assert_equal(stats['haltMask'], ['GLOBAL_RATIO'])
        # SUPPLY_CAP_BPS is tiny here (the cap-race case above): the price drop shrank the cap under the
        # supply, so no class can mint and mintableClasses is empty for the cap's reason, not the halt's
        assert_greater_than(stats['supplyCents'] + 10000, stats['supplyCapCents'])
        assert_equal((stats['mintingAllowed'], stats['mintableClasses']), (False, []))
        assert_rpc_error('mintpol-global-ratio', user.yed_mint, 10000, 145)     # class C: the halt, before the cap
        assert_rpc_error('mintpol-cap', user.yed_mint, 10000, 48)              # class A: through the halt, into the cap
        void_c = self.send_and_mine(user, self.raw_mint(user, 10000, 145, self.ref(), 30 * COIN), POOLS[1])
        self.expect_void(void_c, 'mint-halted-global-ratio')
        self.model_check(nodes[2])

# Rule: RED-1 IN-2 K3
        print('void_release_via_yed_redeem (L14): the collateral of the under-collateralised mint comes back with no burn and no fee')
        locked = user.yed_getvault(void_gr)
        assert_greater_than(locked['lockHeight'], user.getblockcount())
        assert_rpc_error('vault-locked', user.yed_redeem, void_gr)
        assert_equal([p['canRedeem'] for p in user.yed_listpositions() if p['txid'] == void_gr], [False])
        v = user.yed_getvault(void_col)
        assert_greater_than(user.getblockcount() + 1, v['lockHeight'])
        pos = [p for p in user.yed_listpositions('VOID') if p['txid'] == void_col][0]
        assert_equal((pos['canRedeem'], pos['canClaim'], pos['canSweep'], pos['sweepBefore']), (True, False, False, v['claimHeight']))
        assert_rpc_error('vault-not-active', user.yed_claim, void_col)
        yec_before = user.getbalance()
        released = user.yed_redeem(void_col)
        assert_equal((released['burnedCents'], released['feeZat'], released['payee']), (0, 0, None))
        assert_equal(released['collateralOut'], v['collateralZat'] - YELLOWBACK_FEE)
        raw = user.getrawtransaction(released['txid'], 1)
        assert_equal(len(raw['vin']), 1)
        assert_equal(len(raw['vout']), 1)
        assert_equal(raw['vout'][0]['scriptPubKey']['addresses'], [released['to']])
        assert_equal(raw['locktime'], v['lockHeight'])
        assert_equal(nodes[2].yed_validaterawtransaction(raw['hex'])['wouldBeRejected'], False)
        sync_mempools(nodes)                      # enforcing, stock and observer all admit it
        assert released['txid'] in stock.getrawmempool()
        self.mine(STOCK)                          # the stock node mines it
        for i in (0, 2, 3, 4, 5):
            c = nodes[i].yed_getvault(void_col)
            assert_equal((c['status'], c['unbacked'], c['burnedCents'], c['closingTxid']), ('CLOSED', False, 0, released['txid']))
        assert_greater_than(user.getbalance(), yec_before + 9)
        assert_equal(nodes[2].yed_getstats()['voidVaults'], void_before + 2)   # + cap race + global ratio (C) + W16's class C - the release
        assert_equal(nodes[2].yed_gettxinfo(released['txid'])['closedVaults'], [{'txid': void_col, 'vout': 0}])
        rows = {r_['txid']: r_ for r_ in user.yed_listtransactions()}
        assert_equal(rows[released['txid']]['unbacked'], False)
        assert_rpc_error('vault-not-active', user.yed_redeem, void_col)
        self.model_check(nodes[2])
        self.checkpoint('release')


if __name__ == '__main__':
    YellowbackVoidMintTest().main()
