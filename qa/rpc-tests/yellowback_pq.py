#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The YED module on the post-quantum line (docs/plans/yellowback-quantum-spec.md §3, §4, §6; quantum plan
§4.4, Q4) on regtest, every node started with -pqfalconheight=FALCON_HEIGHT:

  - rpcversion 7: yed_getinfo.params.pq {schemes, falconActive, falconHeight, feeRateZatPerKB} and
    params.attest.mintPayloadVersion 4 (C-1: the MINT alone is payload version 4);
  - a wallet mint (yed_mint, unchanged arguments, A-3) draws a fresh SLH-DSA owner: the vault rows carry
    ownerScheme / ownerHash / a 53-character PQ ownerAddress and no ownerPubKey / ownerKeyId; the MINT payload
    decodes as version 4; the token goes to a fresh P2PKH holder (Falcon inactive);
  - transfers to a P2PKH holder and to post-quantum holders (Falcon and SLH-DSA TX_PQPKH, both valid before the
    Falcon height); yed_listtokens and yed_validateaddress take the 53-character address;
  - below the Falcon height a Falcon-owner MINT is refused (MINT-3, bad-mint-owner-key);
  - the owner's redeem of a PQ vault from the wallet (yed_redeem, q/wallet's SLH-DSA signer) and of a raw
    PQ mint signed by the Python signer (the 7.9 KB owner scriptSig, mined in a block);
  - an in-term claim by a claimant (the APP path: no owner signature) of a wallet-minted PQ vault: CLAIMING,
    the claim intent carries the PQ owner slot;
  - from the Falcon height: params.pq.falconActive, schemes [1, 2]; TOK-PQ refuses a MINT whose token output is
    P2PKH (bad-yed-holder) and admits a Falcon TX_PQPKH holder, a Falcon owner mints; a wallet mint's token and
    a wallet transfer's change go to Falcon keys, and a wallet transfer to a P2PKH holder is refused;
  - the index and the Python model agree over the whole chain (model_check), equal state hashes.

Nodes: 0 user, 1 stock (the fork binary without Yellowback), 2-4 pools (2 also takes PQ tokens), 5 the claimant.
"""

from decimal import Decimal

from test_framework.util import (
    assert_equal,
    assert_greater_than,
    bytes_to_hex_str,
    hex_str_to_bytes,
)
from test_framework.yellowback_util import (
    COIN,
    POOLS,
    REF_LAG,
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
)
from test_framework import yellowback_model as ym
from test_framework.yellowback_attest import ArmedModeMixin

FALCON_HEIGHT = 330
PRICE = Decimal('4.00')
DROP = Decimal('1.60')          # a 300 % class-A vault at $4.00 is at 120 % at $1.60: under theta 125 %


def assert_rpc_error(substr, fn, *args):
    try:
        fn(*args)
    except Exception as e:
        assert substr in str(e), 'expected %r in %r' % (substr, str(e))
        return
    raise AssertionError('expected an error containing %r' % substr)


def coin_of(node, cents):
    for c in node.yed_listunspent():
        if c['cents'] == cents and not c['spentUnconfirmed'] and len(c['address']) == 35:
            return c
    raise AssertionError('no %d-cent P2PKH coin on the node' % cents)


def pqpkh_of(keyid_hex):
    """TX_PQPKH of a 66-hex pqkeyid (scheme || keyHash): 20 <hash> OP_scheme OP_CHECKPQSIG (quantum spec §2.1)."""
    raw = hex_str_to_bytes(keyid_hex)
    return ym.pqpkh_script(raw)


class YellowbackPQTest(ArmedModeMixin, YellowbackTestFramework):

    def node_args(self, i, extra=None):
        return super().node_args(i, list(extra or []) + ['-pqfalconheight=%d' % FALCON_HEIGHT])

    def price(self, usd):
        for i in POOLS:
            set_quote(self.nodes[i], usd)

    def settle(self, usd, n=34):
        self.price(usd)
        self.mine_round_robin(POOLS, n)
        assert_equal(self.nodes[0].yed_getprice()['pClaim'], usd_to_micro(usd))

    def raw_mint(self, node, owner=None, token_script=None, lock_blocks=48):
        r = node.yed_getinfo()['height'] - REF_LAG
        coll = node.yed_estimatecollateral(10000, lock_blocks)['requiredZat']
        payee = node.yed_getfeepayee(r, coll)['default']['payoutAddress']
        return build_mint_tx(node, 10000, lock_blocks, r, coll, fee_addr=payee,
                             owner_pubkey=None if owner is None else bytes_to_hex_str(owner), token_script=token_script)

    def run_test(self):
        nodes = self.nodes
        user, receiver, claimant = nodes[0], nodes[2], nodes[5]

        print('activate at $%s; fund the claimant' % PRICE)
        self.activate(POOLS, quote_usd=PRICE)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        user.sendtoaddress(claimant.getnewaddress(), 5)
        self.sync_all()
        self.mine(POOLS[0])

# Rule: MINT-1 MINT-3
        print('rpcversion 7: params.pq and the v4 MINT')
        info = user.yed_getinfo()
        assert_equal(info['rpcversion'], 7)
        pq = info['params']['pq']
        assert_equal((pq['schemes'], pq['falconActive'], pq['falconHeight']), ([1], False, FALCON_HEIGHT))
        assert_greater_than(pq['feeRateZatPerKB'], 0)
        assert_equal((info['params']['attest']['payloadVersion'], info['params']['attest']['mintPayloadVersion']), (3, 4))

        print('a wallet mint draws a fresh SLH-DSA owner; the token goes to a fresh P2PKH holder')
        m = self.mint(user, 10000, 48)
        self.sync_all()
        self.mine(POOLS[1])
        vault = user.yed_getvault(m['txid'])
        assert_equal(vault['status'], 'ACTIVE')
        assert 'ownerPubKey' not in vault and 'ownerKeyId' not in vault
        assert_equal(vault['ownerScheme'], 1)
        assert_equal(len(vault['ownerHash']), 64)
        assert_equal(vault['ownerAddress'], m['ownerAddress'])
        assert_equal((len(vault['ownerAddress']), vault['ownerAddress'][:2]), (53, 'yr'))
        assert ('20' + vault['ownerHash'] + '51c2') in vault['scriptPubKey']                       # the V's PQ owner slot
        dec = user.vault_decodescript(vault['scriptPubKey'])
        assert_equal(dec['owner'], '01' + vault['ownerHash'])
        raw = user.getrawtransaction(m['txid'], 1)
        payload = user.yed_decodepayload(raw['vout'][2]['scriptPubKey']['hex'])
        assert_equal((payload['version'], payload['type'], payload['ownerScheme'], payload['ownerHash']),
                     (4, 'mint', 1, vault['ownerHash']))
        assert 'ownerPubKey' not in payload
        assert_equal(len(raw['vout'][1]['scriptPubKey']['hex']), 50)                                 # P2PKH token (25 bytes)
        pos = [p for p in user.yed_listpositions() if p['txid'] == m['txid']]
        assert_equal(len(pos), 1)
        assert_equal((pos[0]['ownerScheme'], pos[0]['ownerHash'], pos[0]['ownerAddress']),
                     (1, vault['ownerHash'], vault['ownerAddress']))
        assert 'ownerPubKey' not in pos[0] and 'ownerKeyId' not in pos[0]
        assert_equal(user.yed_validateaddress(vault['ownerAddress'])['ismine'], True)
        print("the owner's redeem from the wallet: an SLH-DSA owner signature (q/wallet's signer), the early-redeem fee")
        redeemed = user.yed_redeem(m['txid'])
        assert_equal((redeemed['burnedCents'], redeemed['earlyRedeemFeeZat']), (10000, early_redeem_fee_zat(vault['collateralZat'], 'A')))
        sig_hex = user.getrawtransaction(redeemed['txid'], 1)['vin'][0]['scriptSig']['hex']
        assert_greater_than(len(sig_hex) // 2, 7900)                                                  # 7,938 + the OP_2 selector
        assert sig_hex.endswith('52')
        self.sync_all()
        self.mine(POOLS[2])
        assert_equal(nodes[3].yed_getvault(m['txid'])['status'], 'CLOSED')
        m1 = self.mint(user, 10000, 48)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(nodes[3].yed_getvault(m1['txid'])['status'], 'ACTIVE')

# Rule: XFER-1 TOK-PQ
        print('transfers to a P2PKH holder and to post-quantum holders (SLH-DSA and Falcon TX_PQPKH), before the Falcon height')
        p2pkh = receiver.yed_getnewaddress()
        pq_addr = receiver.yed_getnewaddress('pq')            # SLH-DSA while Falcon is inactive (q/wallet)
        slh_addr = receiver.yed_getnewaddress('pqowner')
        assert_equal(receiver.yed_getnewaddress('p2pkh')[:2], 'yr')
        assert_equal((len(p2pkh), len(pq_addr), len(slh_addr)), (35, 53, 53))
        va = receiver.yed_validateaddress(pq_addr)
        assert_equal((va['isvalid'], va['type'], va['pqscheme'], va['ismine'], va['transparentAddress']), (True, 'pq', 1, True, ''))
        assert_equal(receiver.yed_validateaddress(slh_addr)['pqscheme'], 1)
        assert_equal(receiver.yed_validateaddress(p2pkh)['type'], 'p2pkh')
        assert_equal(user.yed_validateaddress(pq_addr)['ismine'], False)
        # a Falcon holder address (no wallet key): valid as a destination before the Falcon height too
        user.yed_sendmany({p2pkh: 3000, pq_addr: 2000, slh_addr: 1000})
        self.sync_all()
        self.mine(POOLS[2])
        rows = receiver.yed_listtokens([pq_addr, slh_addr, p2pkh])
        by_addr = {r['address']: r for r in rows}
        assert_equal((by_addr[pq_addr]['cents'], by_addr[pq_addr]['transparentAddress']), (2000, ''))
        assert_equal((by_addr[slh_addr]['cents'], by_addr[slh_addr]['transparentAddress']), (1000, ''))
        assert_equal(by_addr[p2pkh]['cents'], 3000)
        assert_equal(receiver.yed_getbalance()['confirmedCents'], 6000)
        out = receiver.getrawtransaction(by_addr[pq_addr]['txid'], 1)['vout'][by_addr[pq_addr]['vout']]['scriptPubKey']
        assert_equal(out['hex'], bytes_to_hex_str(pqpkh_of(va['keyid'])))
        assert_equal(len(out['hex']), 70)                                                             # 35-byte TX_PQPKH
        assert_equal(out.get('addresses'), [pq_addr])                                                 # EncodeDestination renders the PQ ye… (ruling)

# Rule: MINT-3
        print('below the Falcon height a Falcon owner is refused (MINT-3)')
        assert_greater_than(FALCON_HEIGHT, user.getblockcount() + 1)
        falcon_owner = bytes([2]) + ym.sha256(b'yellowback-pq-falcon-owner')
        bad_hex, _ = self.raw_mint(user, owner=falcon_owner)
        assert_rpc_error('bad-yellowback-bad-mint-owner-key', user.sendrawtransaction, bad_hex)
        v3 = bytes.fromhex(bad_hex)
        assert b'\x59\x42\x04\x01' in v3                                                              # the v4 MINT header

# Rule: RED-1 RED-2 RED-3 IT-9
        print("a raw PQ mint and its owner's redeem, signed with SLH-DSA (Python signer), mined in a block")
        mint_hex, owner_hex = self.raw_mint(user)
        mint_txid = user.sendrawtransaction(mint_hex)
        self.sync_all()
        self.mine(POOLS[0])
        pv = user.yed_getvault(mint_txid)
        assert_equal((pv['status'], pv['ownerScheme'], pv['ownerHash']), ('ACTIVE', 1, owner_hex[2:]))
        r = user.getblockcount()
        payee = user.yed_getfeepayee(r, pv['collateralZat'])['default']['payoutAddress']
        fee = fee_zat(pv['collateralZat']) + early_redeem_fee_zat(pv['collateralZat'], 'A')            # IT-9: before lockHeight
        coin = coin_of(user, 10000)
        spend_hex = build_vault_spend_raw(user, pv, 'owner', [(coin['txid'], coin['vout'])],
                                          payload=ym.encode_redeem(r, 1, []), fee=(payee, fee), ref_height=r)
        scriptsig_len = len(ym.tx_from_hex(spend_hex).vin[0].script_sig)
        assert_greater_than(scriptsig_len, 7900)                                                       # 7,938 + the OP_2 selector
        val = user.yed_validaterawtransaction(spend_hex)
        assert_equal((val['valid'], val['blockValid'], val['path']), (True, True, 'owner'))
        result, _ = mine_block_raw(nodes[POOLS[1]], [spend_hex])
        assert result is None, result
        self.sync_all()
        for i in (0, 2, 3, 4, 5):
            assert_equal(nodes[i].yed_getvault(mint_txid)['status'], 'CLOSED')

# Rule: RED-1 RED-2 RED-4 RED-5 IT-2 IT-3
        print('an in-term claim by a claimant of a wallet-minted PQ vault (the APP path needs no owner signature)')
        x = self.mint(user, 10000, 48)
        z = self.mint(user, 10000, 48)
        self.sync_all()
        self.mine(POOLS[1])
        user.yed_send(claimant.yed_getnewaddress(), 10000)
        self.sync_all()
        self.mine(POOLS[2])
        self.settle(DROP)
        vx = user.yed_getvault(x['txid'])
        assert_equal(vx['claimable'], True)
        assert_greater_than(vx['lockHeight'], user.getblockcount())                                    # in term
        claimed = self.claim(claimant, x['txid'])
        assert_equal((claimed['claimPath'], claimed['burnedCents']), ('a', 10000))
        self.sync_all()
        self.mine(POOLS[0])
        cx = nodes[3].yed_getvault(x['txid'])
        assert_equal(cx['status'], 'CLAIMING')
        intent_spk = claimant.getrawtransaction(claimed['txid'], 1)['vout'][0]['scriptPubKey']['hex']
        assert ('20' + vx['ownerHash'] + '51c2') in intent_spk                                        # the I's PQ owner slot
        assert_equal(user.yed_getvault(z['txid'])['status'], 'ACTIVE')
        self.settle(PRICE)
        self.checkpoint('claim')

# Rule: TOK-PQ MINT-3
        print('mine to the Falcon height %d' % FALCON_HEIGHT)
        assert_greater_than(FALCON_HEIGHT, user.getblockcount())
        self.mine_round_robin(POOLS, FALCON_HEIGHT - 1 - user.getblockcount())
        assert_equal(user.getblockcount(), FALCON_HEIGHT - 1)
        pq = user.yed_getinfo()['params']['pq']
        assert_equal((pq['schemes'], pq['falconActive']), ([1, 2], True))                             # judged at the next block
        assert_equal(len(user.yed_getnewaddress()), 53)                                               # the holder policy: Falcon now

        print('TOK-PQ: a P2PKH token output is refused (bad-yed-holder), a Falcon TX_PQPKH holder is admitted')
        p2pkh_hex, _ = self.raw_mint(user)
        assert_rpc_error('bad-yellowback-bad-yed-holder', user.sendrawtransaction, p2pkh_hex)
        result, _ = mine_block_raw(nodes[POOLS[2]], [p2pkh_hex])
        assert_equal(result, 'bad-yellowback-bad-yed-holder')
        falcon_addr = receiver.yed_getnewaddress('pq')                                                # a Falcon key now
        vf = receiver.yed_validateaddress(falcon_addr)
        assert_equal((vf['pqscheme'], vf['ismine']), (2, True))
        holder = pqpkh_of(vf['keyid'])
        ok_hex, _ = self.raw_mint(user, token_script=holder)
        ok_txid = user.sendrawtransaction(ok_hex)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(user.getblockcount(), FALCON_HEIGHT)
        # (built after the first is mined: the raw builder's coin selection does not see mempool spends)
        falcon_hex, _ = self.raw_mint(user, owner=falcon_owner, token_script=holder)
        falcon_txid = user.sendrawtransaction(falcon_hex)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(nodes[3].yed_getvault(ok_txid)['status'], 'ACTIVE')
        assert_equal((nodes[3].yed_getvault(falcon_txid)['status'], nodes[3].yed_getvault(falcon_txid)['ownerScheme']), ('ACTIVE', 2))
        assert_equal(receiver.yed_getbalance()['confirmedCents'], 26000)

        print('a wallet transfer to a P2PKH holder is refused; a wallet transfer to a PQ holder has Falcon change')
        assert_rpc_error('bad-yed-holder', user.yed_send, p2pkh, 1000)
        sent = user.yed_send(falcon_addr, 1000)
        self.sync_all()
        self.mine(POOLS[1])
        rawsend = user.getrawtransaction(sent['txid'], 1)
        token_spks = [o['scriptPubKey']['hex'] for o in rawsend['vout'] if o['valueZat'] == 10000]
        assert token_spks and all(len(h) == 70 and h.endswith('52c2') for h in token_spks), token_spks
        print('a wallet mint after the Falcon height: its token goes to a fresh Falcon key')
        m2 = self.mint(user, 10000, 48)
        self.sync_all()
        self.mine(POOLS[2])
        tok = user.getrawtransaction(m2['txid'], 1)['vout'][1]['scriptPubKey']['hex']
        assert_equal((len(tok), tok[-4:]), (70, '52c2'))
        assert_equal(nodes[4].yed_getvault(m2['txid'])['status'], 'ACTIVE')

        print('the Python model over the whole chain; equal state hashes')
        self.model_check(nodes[0])
        self.sync_all(blocks_only=True)
        assert_best_hash(self.enforcing_nodes(), 'end')
        assert_same_statehash(self.enforcing_nodes(), 'end')


if __name__ == '__main__':
    YellowbackPQTest().main()
