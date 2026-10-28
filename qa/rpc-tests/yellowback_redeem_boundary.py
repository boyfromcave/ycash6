#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The owner-redeem and claim height boundaries, RPC against consensus, one block either side
(cf. DigiByte v9.26.7 243512bfbb, a vault reported redeemable one block early, and
test/functional/digidollar_redemption_unlock_boundary.py).

Since IT-1 (extended) a YED vault's V has ownerHeight = appHeight = refHeight + 1, and MINT-3 takes
refHeight <= H - 1 for a mint in block H, so the earliest a vault can confirm is its ownerHeight.
The vaults here are minted raw with refHeight = tip, so they confirm in block H = ownerHeight =
appHeight exactly. The vault owner is a post-quantum key of the user's wallet (vault_getnewowner).

  - tip ownerHeight - 1 (the mints in the mempool): yed_estimateredeem, yed_redeem and yed_claim
    find no vault; an owner spend (nLockTime ownerHeight) or a claim (nLockTime appHeight) in the
    mint's own block H is non-final (bad-txns-nonfinal); a mint whose ownerHeight would be its own
    block plus one (refHeight = H) is bad-mint-ref-height;
  - tip ownerHeight (= H): yed_listpositions and yed_estimateredeem say canRedeem, and the owner spend
    refused in block H is valid in block H + 1, the first block the RPC quotes for; yed_listclaimable
    lists the claim vault (tip >= appHeight) as not claimable, yed_claim says claim-not-underwater
    (not claim-not-yet), and the claim in block H + 1 fails on RED-4 (vault-claim-not-underwater),
    not on its height;
  - the V's CLTV: an owner spend with nLockTime ownerHeight - 1 is refused at every height, one with
    ownerHeight + 1 is non-final in block H + 1 and valid in block H + 2;
  - tip ownerHeight + 1: yed_redeem's spend (nLockTime ownerHeight) confirms;
  - one state hash on every node and the Python model at the end.

Nodes: 0 user (the owner), 1 stock, 2-4 pools, 5 observer.
"""

from test_framework.util import (
    assert_equal,
    bytes_to_hex_str,
)
from test_framework.yellowback_util import (
    POOLS,
    REF_LAG,
    USER,
    YellowbackTestFramework,
    assert_banscore_zero,
    build_mint_tx,
    build_vault_spend_raw,
    early_redeem_fee_zat,
    mine_block_raw,
    protocol_fee_zat,
    vault_from_mint,
)
from test_framework import yellowback_model as ym

CENTS = 10000
LOCK = 48                      # class A


def rpc_error(fn, *args):
    try:
        fn(*args)
    except Exception as e:
        err = getattr(e, 'error', None)
        return str(err.get('message', '')) if isinstance(err, dict) else str(e)
    raise AssertionError('expected an RPC error from %r%r' % (fn, args))


def outpoint_selector(txid, n=0):
    """The FEE-W selector of a vault spend: the serialised COutPoint (section 3.7)."""
    return bytes_to_hex_str(bytes.fromhex(txid)[::-1] + n.to_bytes(4, 'little'))


# Rule: IT-1 IT-2 RED-1 RED-4 MINT-3
class YellowbackRedeemBoundaryTest(YellowbackTestFramework):

    def raw_mint(self, node, ref, p_mint, fee_addr):
        """A raw MINT at refHeight ``ref`` owned by a wallet post-quantum key, its token at a YED address
        of the wallet; broadcast. Returns the vault dict build_vault_spend_raw takes."""
        owner = node.vault_getnewowner()['owner']
        coll = node.yed_estimatecollateral(CENTS, LOCK, p_mint)['requiredZatFloored']
        token = ym.p2pkh_script(ym.address_key_hash(node.yed_getnewaddress()))
        hex_, _ = build_mint_tx(node, CENTS, LOCK, ref, coll, fee_addr=fee_addr, owner_pubkey=owner,
                                token_script=token, p_mint=p_mint)
        txid = node.sendrawtransaction(hex_)
        v = vault_from_mint(hex_, LOCK, ref, owner)
        v.update({'mintedCents': CENTS, 'pMint': p_mint, 'termClass': 'A', 'hex': hex_})
        assert_equal(v['txid'], txid)
        return v

    def owner_spend(self, node, v, ref, lock_time=None):
        """The owner's REDEEM of ``v`` burning its own token: FEE-1' plus the early-redeem fee (IT-9') to the
        FEE-W payee at ``ref``."""
        payee = node.yed_getfeepayee(ref, outpoint_selector(v['txid']))['default']['payoutAddress']
        fee = protocol_fee_zat(CENTS, v['pMint']) + early_redeem_fee_zat(CENTS, 'A', v['pMint'])
        return build_vault_spend_raw(node, v, 'owner', [(v['txid'], 1)], payload=ym.encode_redeem(ref, 1, []),
                                     fee=(payee, fee), ref_height=ref, lock_time=lock_time)

    def claim_spend(self, node, v, ref):
        payee = node.yed_getfeepayee(ref, outpoint_selector(v['txid']))['default']['payoutAddress']
        return build_vault_spend_raw(node, v, 'claim', [(v['txid'], 1)], payload=ym.encode_redeem(ref, 1, []),
                                     fee=(payee, protocol_fee_zat(CENTS, v['pMint'])), ref_height=ref)

    def run_test(self):
        nodes = self.nodes
        user = nodes[USER]
        pool = nodes[POOLS[0]]

        print('activate at $50 and fill the price windows')
        self.activate(POOLS, quote_usd=50)
        self.mine_round_robin(POOLS, REF_LAG + 1)

# Rule: MINT-3 IT-1
        h = user.getblockcount() + 1                    # the mints' block H
        ref = h - 1                                     # refHeight = tip: ownerHeight = appHeight = H
        p_mint = int(user.yed_getprice(ref)['pMint'])
        fee_addr = user.yed_getfeepayee(ref)['default']['payoutAddress']
        print('tip %d = ownerHeight - 1: four vaults minted raw with refHeight %d, in the mempool' % (ref, ref))
        v_raw = self.raw_mint(user, ref, p_mint, fee_addr)      # the owner spend built now, valid from H + 1
        v_cltv = self.raw_mint(user, ref, p_mint, fee_addr)     # the CLTV cases
        v_rpc = self.raw_mint(user, ref, p_mint, fee_addr)      # yed_redeem
        v_claim = self.raw_mint(user, ref, p_mint, fee_addr)    # the claim path
        for v in (v_raw, v_cltv, v_rpc, v_claim):
            assert_equal((v['ownerHeight'], v['appHeight']), (h, h))
        for v in (v_raw, v_rpc, v_claim):
            assert 'vault-not-found' in rpc_error(user.yed_estimateredeem, v['txid'])
            assert 'vault-not-found' in rpc_error(user.yed_redeem, v['txid'])
        assert 'vault-not-found' in rpc_error(user.yed_claim, v_claim['txid'], '', '')
        assert all(p['txid'] != v_rpc['txid'] for p in user.yed_listpositions())
        spend_h1 = self.owner_spend(user, v_raw, ref)
        assert_equal(ym.tx_from_hex(spend_h1).lock_time, h)
        claim_h1 = self.claim_spend(user, v_claim, ref)
        assert_equal(ym.tx_from_hex(claim_h1).lock_time, h)
        print('  in the mints\' own block H the owner spend and the claim are non-final')
        tip = user.getbestblockhash()
        result, _ = mine_block_raw(pool, [v_raw['hex'], spend_h1])
        assert result is not None and 'nonfinal' in result, result
        result, _ = mine_block_raw(pool, [v_claim['hex'], claim_h1])
        assert result is not None and 'nonfinal' in result, result
        assert_equal(user.getbestblockhash(), tip)
        print('  a mint whose ownerHeight would be H + 1 (refHeight = H) is refused in block H')
        early_hex, _ = build_mint_tx(user, CENTS, LOCK, h, user.yed_estimatecollateral(CENTS, LOCK, p_mint)['requiredZatFloored'],
                                     fee_addr=fee_addr, p_mint=p_mint)
        result, _ = mine_block_raw(pool, [early_hex])
        assert_equal(result, 'bad-yellowback-bad-mint-ref-height')
        assert_equal(user.getbestblockhash(), tip)

# Rule: RED-1 IT-1 IT-2 RED-4
        print('tip H = ownerHeight: the RPC says redeemable; the spend refused in block H is valid in block H + 1')
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(user.getblockcount(), h)
        for v in (v_raw, v_cltv, v_rpc, v_claim):
            got = user.yed_getvault(v['txid'])
            assert_equal((got['status'], got['mintHeight']), ('ACTIVE', h))
            dec = user.vault_decodescript(got['scriptPubKey'])
            assert_equal((dec['ownerheight'], dec['appheight']), (h, h))
        positions = {p['txid']: p for p in user.yed_listpositions()}
        for v in (v_raw, v_cltv, v_rpc, v_claim):
            assert_equal(positions[v['txid']]['canRedeem'], True)
        quote = user.yed_estimateredeem(v_rpc['txid'])
        assert_equal((quote['canRedeem'], quote['error'], quote['height'], quote['early']), (True, '', h + 1, True))
        assert_equal(nodes[2].yed_validaterawtransaction(spend_h1)['verdict'], 'ok')
        listed = {c['vault']: c for c in user.yed_listclaimable()}
        assert_equal(listed[v_claim['txid'] + ':0']['claimable'], False)    # tip >= appHeight: listed, above theta
        msg = rpc_error(user.yed_claim, v_claim['txid'], '', '')
        assert 'claim-not-underwater' in msg and 'claim-not-yet' not in msg, msg
        result, _ = mine_block_raw(pool, [claim_h1])
        assert_equal(result, 'bad-yellowback-vault-claim-not-underwater')    # RED-4 decides, not the height
        print('  the V\'s CLTV at block H + 1: nLockTime ownerHeight - 1 and ownerHeight + 1 are refused')
        cltv_minus = self.owner_spend(user, v_cltv, h, lock_time=h - 1)
        cltv_plus = self.owner_spend(user, v_cltv, h, lock_time=h + 1)
        result, _ = mine_block_raw(pool, [cltv_minus])
        assert result is not None, 'an owner spend below ownerHeight was accepted'
        print('    nLockTime ownerHeight - 1: %s' % result)
        result, _ = mine_block_raw(pool, [cltv_plus])
        assert result is not None and 'nonfinal' in result, result
        assert_equal(user.getblockcount(), h)
        result, _ = mine_block_raw(pool, [spend_h1])
        assert result is None, result
        self.sync_all(blocks_only=True)
        assert_equal(user.getblockcount(), h + 1)
        assert_equal(nodes[2].yed_getvault(v_raw['txid'])['status'], 'CLOSED')

# Rule: RED-1 IT-1
        print('tip H + 1 = ownerHeight + 1: yed_redeem; nLockTime ownerHeight + 1 is final in block H + 2')
        assert_equal(user.yed_estimateredeem(v_rpc['txid'])['canRedeem'], True)
        redeemed = user.yed_redeem(v_rpc['txid'])
        assert_equal(redeemed['burnedCents'], CENTS)
        assert_equal(user.getrawtransaction(redeemed['txid'], 1)['locktime'], h)
        self.sync_all()
        result, _ = mine_block_raw(pool, [cltv_plus])
        assert result is None, result
        self.sync_all(blocks_only=True)
        assert_equal(nodes[2].yed_getvault(v_cltv['txid'])['status'], 'CLOSED')
        self.mine(POOLS[2])
        assert_equal(nodes[2].yed_getvault(v_rpc['txid'])['status'], 'CLOSED')
        assert_equal(nodes[2].yed_getvault(v_claim['txid'])['status'], 'ACTIVE')
        assert_banscore_zero([nodes[i] for i in (0, 2, 3, 4)])
        self.checkpoint('after the boundary spends')
        self.model_check(nodes[2])

    def model_check(self, node):
        return ym.assert_model_matches(node, full=True)


if __name__ == '__main__':
    YellowbackRedeemBoundaryTest().main()
