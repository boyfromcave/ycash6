#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Falcon from day one (quantum plan D-Q-2, owner 2026-10-10): the mainnet/testnet regime on regtest. Every node
starts with -pqfalconheight=0, so FN-DSA-512 (OP_CHECKPQSIG scheme 0x02), TOK-PQ and the wallets' Falcon holder
policy switch on exactly with the vault upgrade (IsPQFalconActive requires UPGRADE_VAULT), as mainnet's
pqFalconHeight = 0 makes them. A whole YED lifecycle runs with Falcon holders and no P2PKH holder anywhere:

  - yed_getinfo.params.pq from the activation: falconActive, schemes [1, 2], falconHeight = the vault activation
    height (the A-5 mirror, max(UPGRADE_VAULT, pqFalconHeight)); yed_getnewaddress defaults to a Falcon key;
  - wallet mints: SLH-DSA owners, the token on a fresh Falcon TX_PQPKH;
  - wallet transfers between Falcon holders (the receiving wallet spends its Falcon tokens back), Falcon change;
    a transfer to a P2PKH holder is refused (bad-yed-holder), and so is a raw MINT with a P2PKH token (mempool
    and block);
  - the owner's redeem from the wallet (SLH-DSA owner signature, Falcon token inputs burned);
  - an in-term claim by a claimant holding Falcon tokens (CLAIMING), its vault_release after CLAIM_DELAY (CLAIMED);
  - every YED-assigned output of every block after the activation is a Falcon TX_PQPKH (yed_gettxinfo.assigned);
  - the Python model agrees over the whole chain, equal state hashes.

The clause-(b) residual release to the owner's PQPKH runs in yellowback_attest.py, which also runs in this regime
with --pqfalconheight=0 (the framework option).

Nodes: 0 user, 1 stock (the fork binary without Yellowback), 2-4 pools (2 also receives), 5 the claimant.
"""

from decimal import Decimal

from test_framework.util import (
    assert_equal,
    assert_greater_than,
)
from test_framework.yellowback_util import (
    CLAIM_DELAY,
    COIN,
    POOLS,
    REF_LAG,
    VAULT_ACTIVATION,
    YellowbackTestFramework,
    assert_best_hash,
    assert_same_statehash,
    build_mint_tx,
    mine_block_raw,
    set_quote,
    usd_to_micro,
)
from test_framework.yellowback_attest import ArmedModeMixin

PRICE = Decimal('4.00')
DROP = Decimal('1.60')          # a 300 % class-A vault at $4.00 is at 120 % at $1.60: under theta 125 %


def assert_rpc_error(substr, fn, *args):
    try:
        fn(*args)
    except Exception as e:
        assert substr in str(e), 'expected %r in %r' % (substr, str(e))
        return
    raise AssertionError('expected an error containing %r' % substr)


def is_falcon_pqpkh(spk_hex):
    """TX_PQPKH with scheme 2: 20 <keyHash:32> OP_2 OP_CHECKPQSIG, 35 bytes (quantum spec §2.1)."""
    return len(spk_hex) == 70 and spk_hex.startswith('20') and spk_hex.endswith('52c2')


class YellowbackPQDayOneTest(ArmedModeMixin, YellowbackTestFramework):

    def node_args(self, i, extra=None):
        return super().node_args(i, list(extra or []) + ['-pqfalconheight=0'])

    def price(self, usd):
        for i in POOLS:
            set_quote(self.nodes[i], usd)

    def settle(self, usd, n=34):
        self.price(usd)
        self.mine_round_robin(POOLS, n)
        assert_equal(self.nodes[0].yed_getprice()['pClaim'], usd_to_micro(usd))

    def assert_falcon_address(self, node, addr):
        va = node.yed_validateaddress(addr)
        assert_equal((len(addr), va['isvalid'], va['type'], va['pqscheme']), (53, True, 'pq', 2))
        return va

    def assert_falcon_tokens(self, txid):
        """Every output the transaction assigns YED to is a Falcon TX_PQPKH."""
        info = self.nodes[0].yed_gettxinfo(txid)
        raw = self.nodes[0].getrawtransaction(txid, 1)
        for a in info['assigned']:
            if a['cents'] > 0:
                spk = raw['vout'][a['vout']]['scriptPubKey']['hex']
                assert is_falcon_pqpkh(spk), (txid, a, spk)
        return info

    def run_test(self):
        nodes = self.nodes
        user, receiver, claimant = nodes[0], nodes[2], nodes[5]

        print('activate at $%s (Falcon is active from the vault activation); fund the claimant and the receiver' % PRICE)
        self.activate(POOLS, quote_usd=PRICE)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        user.sendtoaddress(claimant.getnewaddress(), 5)
        user.sendtoaddress(receiver.getnewaddress(), 5)              # the receiver's fees, whatever its coinbases' maturity
        self.sync_all()
        self.mine(POOLS[0])

# Rule: TOK-PQ MINT-3
        print('params.pq: Falcon active, falconHeight = the vault activation height (the A-5 mirror)')
        for n in (user, receiver, claimant, nodes[3]):
            pq = n.yed_getinfo()['params']['pq']
            assert_equal((pq['schemes'], pq['falconActive'], pq['falconHeight']), ([1, 2], True, VAULT_ACTIVATION))
        self.assert_falcon_address(user, user.yed_getnewaddress())                  # the holder policy: Falcon
        self.assert_falcon_address(receiver, receiver.yed_getnewaddress('pq'))      # 'pq' is a Falcon key too

# Rule: MINT-1 TOK-PQ
        print('wallet mints: SLH-DSA owners, tokens on fresh Falcon keys')
        mints = [self.mint(user, 10000, 48) for _ in range(3)]
        self.sync_all()
        self.mine(POOLS[1])
        for m in mints:
            v = nodes[3].yed_getvault(m['txid'])
            assert_equal((v['status'], v['ownerScheme']), ('ACTIVE', 1))
            tok = user.getrawtransaction(m['txid'], 1)['vout'][1]['scriptPubKey']['hex']
            assert is_falcon_pqpkh(tok), tok
            self.assert_falcon_tokens(m['txid'])
        for c in user.yed_listunspent():
            assert_equal(len(c['address']), 53)

# Rule: XFER-1 TOK-PQ
        print('transfers between Falcon holders; Falcon change; the receiver spends its Falcon tokens back')
        dest = receiver.yed_getnewaddress()
        self.assert_falcon_address(receiver, dest)
        sent = user.yed_send(dest, 3000)
        self.sync_all()
        self.mine(POOLS[2])
        info = self.assert_falcon_tokens(sent['txid'])
        assert_equal(sorted(a['cents'] for a in info['assigned'] if a['cents'] > 0), [3000, 7000])
        assert_equal(receiver.yed_getbalance()['confirmedCents'], 3000)
        back = receiver.yed_send(user.yed_getnewaddress(), 1000)                   # a Falcon input signed by the wallet
        self.sync_all()
        self.mine(POOLS[0])
        sig = receiver.getrawtransaction(back['txid'], 1)['vin'][0]['scriptSig']['hex']
        assert_greater_than(len(sig) // 2, 1500)                                    # a Falcon scriptSig (~1.6 KB)
        self.assert_falcon_tokens(back['txid'])
        assert_equal(receiver.yed_getbalance()['confirmedCents'], 2000)

        print('a P2PKH holder is refused: wallet transfer and raw MINT (mempool and block)')
        p2pkh = receiver.yed_getnewaddress('p2pkh')
        assert_equal(len(p2pkh), 35)
        assert_rpc_error('bad-yed-holder', user.yed_send, p2pkh, 1000)
        r = user.yed_getinfo()['height'] - REF_LAG
        coll = user.yed_estimatecollateral(10000, 48)['requiredZat']
        payee = user.yed_getfeepayee(r, coll)['default']['payoutAddress']
        p2pkh_hex, _ = build_mint_tx(user, 10000, 48, r, coll, fee_addr=payee)       # the raw builder's P2PKH token
        assert_rpc_error('bad-yellowback-bad-yed-holder', user.sendrawtransaction, p2pkh_hex)
        result, _ = mine_block_raw(nodes[POOLS[2]], [p2pkh_hex])
        assert_equal(result, 'bad-yellowback-bad-yed-holder')

# Rule: RED-1 RED-2 RED-3 IT-9
        print("the owner's redeem from the wallet: an SLH-DSA owner signature, Falcon tokens burned")
        redeemed = user.yed_redeem(mints[0]['txid'])
        assert_equal(redeemed['burnedCents'], 10000)
        raw = user.getrawtransaction(redeemed['txid'], 1)
        assert_greater_than(len(raw['vin'][0]['scriptSig']['hex']) // 2, 7900)    # 7,938 + the OP_2 selector
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(nodes[3].yed_getvault(mints[0]['txid'])['status'], 'CLOSED')
        self.assert_falcon_tokens(redeemed['txid'])                                 # its change, if any

# Rule: RED-1 RED-2 RED-4 IT-2 IT-3 IT-6
        print('an in-term claim by a claimant holding Falcon tokens, then vault_release after CLAIM_DELAY')
        x = mints[1]['txid']
        to_claimant = user.yed_send(claimant.yed_getnewaddress(), 10000)
        self.sync_all()
        self.mine(POOLS[2])
        self.assert_falcon_tokens(to_claimant['txid'])
        self.settle(DROP)
        vx = user.yed_getvault(x)
        assert_equal(vx['claimable'], True)
        assert_greater_than(vx['lockHeight'], user.getblockcount())                 # in term
        claimed = self.claim(claimant, x)
        assert_equal((claimed['claimPath'], claimed['burnedCents']), ('a', 10000))
        self.sync_all()
        self.mine(POOLS[0])
        claim_block = user.getblockcount()
        assert_equal(nodes[3].yed_getvault(x)['status'], 'CLAIMING')
        intent = '%s:0' % claimed['txid']
        assert_rpc_error('matures at height', claimant.vault_release, intent)
        self.mine_round_robin(POOLS, claim_block + CLAIM_DELAY - 1 - user.getblockcount())
        yec_before = claimant.getbalance()
        released = claimant.vault_release(intent)
        self.sync_all()
        self.mine(POOLS[1])
        for i in (0, 2, 3, 4, 5):
            assert_equal(nodes[i].yed_getvault(x)['status'], 'CLAIMED')
        assert_equal(nodes[2].yed_gettxinfo(released)['type'], 'claim_release')
        assert_greater_than(claimant.getbalance(), yec_before + Decimal(vx['collateralZat']) / COIN - 1)
        self.settle(PRICE)

# Rule: TOK-PQ
        print('no P2PKH holder anywhere: every YED-assigned output after the activation is a Falcon TX_PQPKH')
        checked = 0
        for h in range(VAULT_ACTIVATION, user.getblockcount() + 1):
            for raw in user.getblock(user.getblockhash(h), 2)['tx'][1:]:            # verbosity 2: no -txindex needed
                try:
                    info = user.yed_gettxinfo(raw['txid'])
                except Exception:
                    continue                                                        # not a YED transaction
                txid = raw['txid']
                for a in info.get('assigned', []):
                    if a['cents'] > 0:
                        spk = raw['vout'][a['vout']]['scriptPubKey']['hex']
                        assert is_falcon_pqpkh(spk), (h, txid, a, spk)
                        checked += 1
        assert_greater_than(checked, 7)                                             # 3 mints, 3 transfers with change
        for n in (user, receiver, claimant):
            for c in n.yed_listunspent():
                assert_equal(len(c['address']), 53)
                assert_equal(n.yed_validateaddress(c['address'])['pqscheme'], 2)

        print('the Python model over the whole chain; equal state hashes')
        self.model_check(nodes[0])
        self.sync_all(blocks_only=True)
        assert_best_hash(self.enforcing_nodes(), 'end')
        assert_same_statehash(self.enforcing_nodes(), 'end')


if __name__ == '__main__':
    YellowbackPQDayOneTest().main()
