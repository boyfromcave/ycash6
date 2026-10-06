#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Failing mints (plan §3.8 MINT-1..8). Before the vault upgrade every failing MINT rule registered a
VOID vault; since it (upgrade plan U-23) a failing mint is an invalid transaction: every Yellowback
mempool refuses it with bad-yellowback-<verdict> (DoS 0) and a block carrying it is rejected with
the same reason, so no vault, no TxLog row and no state change exist for it. The script keeps one
case per MINT rule and per halt (the wallet refusing the same mint with the matching mintpol-*
identifier, MINTPOL-1), the supply-cap race across a reorg (the loser becomes invalid on the joined
chain, mint6_cap_race_after_reorg), and the soft cap (W20: above the cap only a class whose minimum
ratio reaches RECAP_RATIO_BPS mints, class A, mint6_cap_is_soft). The VOID release (L14), the mint
before activation and the participation halt left with VOID vaults and ACT-1..7 (upgrade plan §6).

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
    yed_params,
)
from test_framework import yellowback_model as ym
from test_framework.yellowback_attest import ArmedModeMixin, armed_raw_mint

SUPPLY_CAP_BPS = 130         # issuance counts from the upgrade height (U-22), so the cap needs about twice the v2 bps


def assert_rpc_error(substr, fn, *args):
    try:
        fn(*args)
    except Exception as e:
        assert substr in str(e), 'expected %r in %r' % (substr, str(e))
        return str(e)
    raise AssertionError('expected an error containing %r' % substr)


class YellowbackVoidMintTest(ArmedModeMixin, YellowbackTestFramework):

    initial_blocks = 112     # eleven mature coinbases (68.75 YEC) fund the first raw mints

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
        script = vault_script if vault_script is not None else ym.yed_vault_script(yed_params(), owner, lock_height)
        fee_vout = 3 if fee_addr else FEE_VOUT_NONE
        if payload is None:
            payload = ym.encode_mint('ABC'.index(term_class_of(lock_blocks) or 'A'), cents, lock_height, ref, owner, fee_vout)
        token = (TOKEN_VALUE, ym.p2pkh_script(ym.hash160(owner)))
        opret = (0, bytes([ym.OP_RETURN]) + ym.push(payload))
        vout = [(collateral, script)] + ([token, opret] if token_first else [opret, token])
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
        """Mine ``hex_`` (a valid transaction) in a block of its own, assembled in Python on ``miner``
        (``miner``'s own coinbase tag is used, so the price windows advance as with ``generate``)."""
        txid = node.decoderawtransaction(hex_)['txid']
        result, _ = mine_block_raw(self.nodes[miner], [hex_])
        assert result is None, result
        self.sync_all(blocks_only=True)
        return txid

    def expect_invalid(self, node, hex_, reason, miner):
        """U-23: ``hex_`` is an invalid transaction with verdict ``reason``: every Yellowback mempool
        refuses it (``bad-yellowback-<reason>``), a block assembled around it on ``miner`` is
        rejected with the same reason, and no node records a vault or a TxLog row for it."""
        txid = node.decoderawtransaction(hex_)['txid']
        assert_equal(node.yed_validaterawtransaction(hex_)['verdict'], reason)
        for i in (0, 2, 3, 4, 5):
            assert_rpc_error('bad-yellowback-' + reason, self.nodes[i].sendrawtransaction, hex_)
        tip = self.nodes[miner].getbestblockhash()
        result, _ = mine_block_raw(self.nodes[miner], [hex_])
        assert_equal(result, 'bad-yellowback-' + reason)
        assert_equal(self.nodes[miner].getbestblockhash(), tip)
        for i in (0, 2, 3, 4, 5):
            assert_rpc_error('vault-not-found', self.nodes[i].yed_getvault, txid)
            assert_rpc_error('tx-not-found', self.nodes[i].yed_gettxinfo, txid)
        assert_same_statehash(self.enforcing_nodes())
        return txid

    def ref(self):
        return self.nodes[0].yed_getinfo()['height'] - REF_LAG

    def collateral(self, cents=10000, lock=48):
        return self.estimate(self.nodes[0], cents, lock)['requiredZat']

    def run_test(self):
        nodes = self.nodes
        user, stock, observer = nodes[0], nodes[STOCK], nodes[5]

        print('activate at $50 (the upgrade is active from the start: no mint before activation exists, U-22)')
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
        self.expect_invalid(user, self.raw_mint(user, 10000, 48, self.ref(), 10 * COIN), 'mint-halted-no-price', POOLS[0])
        self.mine_round_robin(POOLS, 20)
        assert_equal(user.yed_getstats()['mintingAllowed'], True)

# Rule: MINT-4 HALT-3 MINTPOL-1
        print('mintpol-divergence: the fast window drops to $20 while the mid window holds $50 (supply is 0, so HALT-2 stays clear)')
        for i in POOLS:
            set_quote(nodes[i], 20)
        self.mine_round_robin(POOLS, 8 + REF_LAG)
        assert_equal(user.yed_gethistory(self.ref(), self.ref())[0]['haltMask'], ['DIVERGENCE'])
        assert_rpc_error('mintpol-divergence', user.yed_mint, 10000, 48)
        self.expect_invalid(user, self.raw_mint(user, 10000, 48, self.ref(), 10 * COIN), 'mint-halted-divergence', POOLS[1])
        for i in POOLS:
            set_quote(nodes[i], 50)
        self.mine_round_robin(POOLS, 12)
        assert_equal(user.yed_getstats()['haltMask'], [])
        self.mine_round_robin(POOLS, REF_LAG)

# Rule: MINT-1
        print('mint1_malformed_payload: a truncated MINT payload is not a mint, so its YED vault output is one no rule created')
        good_payload = ym.encode_mint(0, 10000, self.ref() + 48, self.ref(), hex_str_to_bytes(node_pubkey(user)), FEE_VOUT_NONE)
        self.expect_invalid(user, self.raw_mint(user, 10000, 48, self.ref(), 10 * COIN, payload=good_payload[:-5]), 'yed-template-output', POOLS[2])
        assert_equal(nodes[2].yed_getstats()['voidVaults'], 0)

# Rule: MINT-2
        print('mint2_bad_ref_height: refHeight = H - 41 is outside the window')
        old = self.ref() - (REF_WINDOW - REF_LAG)     # H - R = 41 at confirmation
        # nExpiryHeight = R + REF_WINDOW would be the next block: the mempool refuses that as
        # expiring soon (TX_EXPIRING_SOON_THRESHOLD), so this adversarial mint carries a later expiry
        self.expect_invalid(user, self.raw_mint(user, 10000, 48, old, 10 * COIN, expiry=user.getblockcount() + 10), 'bad-mint-ref-height', POOLS[0])

# Rule: MINT-3
        print('mint3_bad_vault_script: vout[0] commits to a vault script with another lockHeight')
        r = self.ref()
        wrong = ym.yed_vault_script(yed_params(), hex_str_to_bytes(node_pubkey(user)), r + 49)
        self.expect_invalid(user, self.raw_mint(user, 10000, 48, r, 10 * COIN, vault_script=wrong), 'bad-mint-vault-script', POOLS[1])

# Rule: MINT-5 K14
        print('mint5_bad_collateral: 0.00001 YEC short of the requirement')
        r = self.ref()
        req = self.collateral()
        # armed (R15): MINT-8 precedes MINT-5, so the shape carries the pool fee too; unarmed the v2 order stands
        col_fee = user.yed_getfeepayee(r, req - 1000)['eligible'][0] if self.armed else None
        self.expect_invalid(user, self.raw_mint_v3(user, 10000, 48, r, req - 1000, fee_addr=col_fee), 'bad-mint-collateral', POOLS[2])
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
        self.expect_invalid(user, self.raw_mint(user, 10000, 48, self.ref(), self.collateral(), token_first=False), 'bad-mint-token-output', POOLS[1])

# Rule: MINT-8 FEE-2
        print('mint8_bad_fee: the fee output pays a key outside E(R); then a short fee to an eligible key')
        r = self.ref()
        self.expect_invalid(user, self.raw_mint(user, 10000, 48, r, self.collateral(), fee_addr=stock.getnewaddress()), 'bad-mint-fee', POOLS[2])
        r = self.ref()
        eligible = user.yed_getfeepayee(r, self.collateral())['eligible'][0]
        self.expect_invalid(user, self.raw_mint(user, 10000, 48, r, self.collateral(), fee_addr=eligible, fee=fee_zat(self.collateral()) - 1), 'bad-mint-fee', POOLS[0])
        print('and the same shape with the right fee is ACTIVE')
        r = self.ref()
        # armed: pMint = min(xMint, aMint) is the attested price, so the requirement is sized at it
        col = self.collateral()          # armed too: the attestors track xMint, so pMint = xMint
        eligible = user.yed_getfeepayee(r, col)['eligible'][0]
        ok = self.send_and_mine(user, self.raw_mint_v3(user, 10000, 48, r, col, fee_addr=eligible), POOLS[1])
        assert_equal(user.yed_getvault(ok)['status'], 'ACTIVE')
        assert_equal(user.yed_getvault(ok)['feePaidZat'], fee_zat(col))
        assert_equal(nodes[2].yed_getstats()['supplyCents'], 20000)
        assert_equal(nodes[2].yed_getstats()['voidVaults'], 0)
        self.checkpoint('rule cases')

# Rule: MINT-6 UNDO
        print('mint6_cap_race_after_reorg: two mints that together exceed the cap on different branches')
        stats = user.yed_getstats()
        headroom = stats['supplyCapCents'] - stats['supplyCents']
        m = (headroom * 6 // 10) // 100 * 100
        assert_greater_than(m, 10000)
        self.split_network()
        mint_x = self.mint(user, m, 145)                   # class C (300 %): the cap stays hard for it (W20); the carrier's block, then the mint's
        sync_mempools([nodes[i] for i in (0, 2, 3, 4)])
        self.mine(POOLS[0])
        assert_equal(user.yed_getvault(mint_x['txid'])['status'], 'ACTIVE')
        mint_y = self.mint(observer, m, 145, miner=STOCK)  # the observer sits on the stock half
        sync_mempools([nodes[1], nodes[5]])
        stock.generate(2)                                  # three stock blocks against the enforcing half's two
        self.join_network()
        assert_equal(user.getbestblockhash(), stock.getbestblockhash())
        assert_equal(user.yed_getvault(mint_y['txid'])['status'], 'ACTIVE')
        # On the joined chain X is over the cap: an invalid transaction (U-23), dropped from every
        # mempool at the new tip (the ConnectTip sweep). X's carrier came back with it and confirms
        # in the next pool block; a block assembled around X itself is rejected.
        x_hex = user.gettransaction(mint_x['txid'])['hex']      # no -txindex, and X has left the mempool
        nodes[POOLS[1]].generate(1)
        self.sync_all(blocks_only=True)
        for i in (0, 2, 3, 4):
            assert mint_x['txid'] not in nodes[i].getrawmempool()
        self.expect_invalid(user, x_hex, 'mint-supply-cap', POOLS[1])
        assert_equal(nodes[2].yed_getstats()['supplyCents'], 20000 + m)
        stats = user.yed_getstats()      # v3: the carrier blocks added issuance, so the cap moved; provoke it from the current numbers
        over = stats['supplyCapCents'] - stats['supplyCents'] + 2000   # the carrier's and the mint's blocks add issuance (~190 cents of cap each here): stay over the moving cap
        self.checkpoint('cap race')

# Rule: MINT-6 MINTPOL-1
        print('mint6_cap_is_soft (W20): at the cap class C is refused and the message names class A; class A mints through and the cap is reached')
        msg = assert_rpc_error('mintpol-cap', user.yed_mint, over, 145)
        assert 'class A' in msg, msg
        assert_equal(user.yed_getinfo()['supplyCapReached'], False)
        assert_equal(stats['mintableClasses'], ['A', 'B', 'C'])
        mint_a = self.mint(user, over, 48)
        sync_mempools([nodes[i] for i in (0, 2, 3, 4)])
        self.mine(POOLS[0])
        assert_equal(user.yed_getvault(mint_a['txid'])['status'], 'ACTIVE')
        stats = user.yed_getstats()
        assert_greater_than(stats['supplyCents'], stats['supplyCapCents'])
        assert_equal((user.yed_getinfo()['supplyCapReached'], stats['mintingAllowed'], stats['mintableClasses']), (True, False, ['A']))
        msg = assert_rpc_error('mintpol-cap', user.yed_mint, 10000, 145)
        assert 'class A' in msg, msg
        self.model_check(nodes[2])
        self.checkpoint('soft cap')

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
        self.expect_invalid(user, self.raw_mint(user, 10000, 145, self.ref(), 30 * COIN), 'mint-halted-global-ratio', POOLS[2])

# Rule: HALT-2 MINTPOL-1
        print('W16 under this script\'s supply cap: the windows agree at $20, the halt persists, and the cap -- proportional to the price -- binds first')
        self.mine_round_robin(POOLS, 64)
        stats = user.yed_getstats()
        assert_equal(stats['haltMask'], ['GLOBAL_RATIO'])
        # SUPPLY_CAP_BPS is tiny here (the cap-race case above): the price drop shrank the cap under the
        # supply, so the halt and the cap both hold; each lets through only the classes at the
        # recapitalisation floor (W16, W20), class A here
        assert_greater_than(stats['supplyCents'] + 10000, stats['supplyCapCents'])
        assert_equal((user.yed_getinfo()['supplyCapReached'], stats['mintingAllowed'], stats['mintableClasses']), (True, False, ['A']))
        assert_rpc_error('mintpol-global-ratio', user.yed_mint, 10000, 145)     # class C: the halt, before the cap
        assert_rpc_error('mintpol-global-ratio', user.yed_mint, 10000, 100)     # class B (400 % at 1x): the halt too
        self.expect_invalid(user, self.raw_mint(user, 10000, 145, self.ref(), 30 * COIN), 'mint-halted-global-ratio', POOLS[1])
        self.model_check(nodes[2])
        self.checkpoint('end')


if __name__ == '__main__':
    YellowbackVoidMintTest().main()
