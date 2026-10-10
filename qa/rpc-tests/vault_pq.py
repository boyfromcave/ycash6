#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Post-quantum vault owners and TX_PQPKH end to end (docs/plans/yellowback-quantum-plan.md §4.3,
§4.5; docs/plans/yellowback-quantum-spec.md §1, §2), two nodes, each spend predicted by the Python
model (test_framework/vault.py) and checked against the node:

A. a one-seat set; vaults locked with an SLH-DSA owner (vault_lock names it as a pqkeyid;
   vault_list reports owner / ownerscheme; vault_ownerspend refuses an owner the wallet lacks);
B. OWNER (selector 2): non-final at ownerHeight, another SLH-DSA key's signature evaluates false,
   the owner's 7,939-byte spend relays (the 9,000-byte policy bound) and confirms;
C. APP (selector 4) into an intent: no owner signature, unchanged by the PQ owner;
D. OWNER-RELEASED (selector 3) on V and I once the set is dormant;
E. TX_PQPKH: paid to, then spent with a 7,938-byte SLH-DSA scriptSig;
F. Falcon (scheme 2): a scheme-2 V is valid by consensus whatever the Falcon activation (A-1):
   node 1 (-pqfalcon=1) relays and mines it, node 0 (no -pqfalcon) accepts the block. Regtest does
   not require standard transactions (fRequireStandard = false), so the policy refusal of a
   scheme-2 output before Falcon and the 9,000 / 1,650-byte scriptSig split are unit-tested
   (src/test/vault_policy_tests.cpp), not here. A Falcon owner spend is not exercised here: the framework has no Falcon signer (Falcon
   signatures come from vectors); src/test/vault_template_tests.cpp's owner_branch_real_signatures
   covers it with crypto/pq/sign.h.

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/vault_pq.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

from test_framework.authproxy import JSONRPCException
from test_framework.util import assert_equal, sync_blocks
from test_framework import pq
from test_framework import vault as v
from test_framework.vault_harness import (
    COIN,
    FEE,
    MEMPOOL_NONFINAL,
    OWNER,
    OWNER_KEY,
    OWNER_OUTSIDER,
    SCRIPT_FALSE,
    VaultTestBase,
)


def assert_rpc_error(substr, fn, *args):
    try:
        fn(*args)
    except JSONRPCException as e:
        assert substr in e.error['message'], 'expected %r in %r' % (substr, e.error['message'])
        return e.error['message']
    raise AssertionError('expected an RPC error containing %r' % substr)


class VaultPQTest(VaultTestBase):

    def node_args(self, i):
        return super().node_args(i) + (['-pqfalcon=1'] if i == 1 else [])

    def run_test(self):
        self.start_vault(coins=30)
        self.section_setup()
        self.section_owner()
        self.section_app()
        self.section_released()
        self.section_pqpkh()
        self.section_falcon()
        self.sync_all()
        assert_equal(self.nodes[0].getbestblockhash(), self.nodes[1].getbestblockhash())
        print('vault_pq OK')

    # ------------------------------------------------------------------ A
    def section_setup(self):
        print('A. a set and three vaults with an SLH-DSA owner')
        self.sid, admit = self.create_set('Q', seats=1, unlock_threshold=1, cancel_threshold=1, slash_threshold=1,
                                          liveness_window=30, maturity=2)
        self.member = v.fixed_secret('Q-member')
        self.join(self.sid, self.member, [admit], 'JOIN Q')
        self.mine(3)
        self.heartbeat(self.sid, [self.member], 'HEARTBEAT Q')
        self.mine()
        owner_id = OWNER_KEY.hex()
        self.vp1 = self.vparams(self.sid, owner_height=self.tip() + 8)
        self.vp2 = self.vparams(self.sid, owner_height=self.tip() + 400, app_height=self.tip() + 4)
        self.vp3 = self.vparams(self.sid, delay=100, owner_height=self.tip() + 400)
        self.v1 = self.lock(self.vp1, 2 * COIN, 'lock V1 (owner branch at tip + 8)')
        self.v2 = self.lock(self.vp2, 2 * COIN, 'lock V2 (APP branch at tip + 4)')
        self.v3 = self.lock(self.vp3, 3 * COIN, 'lock V3 (for dormancy)')
        self.mine()
        listed = self.node.vault_list({'owner': owner_id})
        assert_equal(len(listed), 3)
        for x in listed:
            assert_equal(x['owner'], owner_id)
            assert_equal(x['ownerscheme'], 1)
        assert_equal(self.node.vault_list({'owner': '01' + '00' * 32}), [])
        assert_equal(self.node.vault_decodescript(v.vault_script(self.vp1).hex())['owner'], owner_id)
        # the owner slot: 20 <keyHash> 51 c2 (35 bytes) in both owner branches
        spk = v.vault_script(self.vp1)
        assert_equal(spk.count(bytes([0x20]) + OWNER_KEY[1:] + bytes([0x51, 0xc2])), 2)

    # ------------------------------------------------------------------ B
    def section_owner(self):
        print('B. OWNER (selector 2) with the SLH-DSA owner')
        spk, oh = v.vault_script(self.vp1), self.vp1.owner_height
        self.mine_to(oh - 1)                       # tip + 1 = ownerHeight
        self.reject(self.owner_hex(self.v1, spk, 2 * COIN, v.SEL_OWNER, lock_time=oh), MEMPOOL_NONFINAL,
                    'bad-txns-nonfinal', 'OWNER with nLockTime = ownerHeight = tip + 1')
        self.mine()
        assert_rpc_error('not a post-quantum key of this wallet', self.node.vault_ownerspend, '%s:%d' % self.v1, self.node.getnewaddress())
        self.reject(self.owner_hex(self.v1, spk, 2 * COIN, v.SEL_OWNER, lock_time=oh, secret=OWNER_OUTSIDER),
                    SCRIPT_FALSE, 'script-ownersig', 'OWNER signed by another SLH-DSA key')
        hex_ = self.owner_hex(self.v1, spk, 2 * COIN, v.SEL_OWNER, lock_time=oh)
        assert_equal(len(v.tx_from_hex(hex_).vin[0].scriptSig), 7939)
        txid = self.accept(hex_, 'OWNER spend after ownerHeight (7,939-byte scriptSig)')
        [bh] = self.mine()
        assert txid in self.node.getblock(bh)['tx']
        assert_equal(self.node.gettxout(self.v1[0], self.v1[1]), None)

    # ------------------------------------------------------------------ C
    def section_app(self):
        print('C. APP (selector 4): no owner signature')
        self.mine_to(max(self.tip(), self.vp2.app_height))
        rspk = self.change_spk()
        fee_vin, change = v.node_fee_inputs(self.node)
        app = v.build_app_tx(self.v2, self.vp2, 2 * COIN, [(rspk, 2 * COIN)], fee_vin, change)
        txid = self.accept(v.node_sign(self.node, app, app.vin[0].scriptSig), 'APP into one intent')
        self.mine()
        ip = v.intent_for(self.vp2, rspk)
        assert_equal(self.node.gettxout(txid, 0)['scriptPubKey']['hex'], v.intent_script(ip).hex())

    # ------------------------------------------------------------------ D
    def section_released(self):
        print('D. OWNER-RELEASED (selector 3) on V and I once the set is dormant')
        rspk = self.change_spk()
        u = self.accept(self.unlock_hex(self.v3, self.vp3, 3 * COIN, [(rspk, COIN)], [self.member], relock=2 * COIN),
                        'UNLOCK V3 into an intent (delay 100) + re-lock')
        self.mine()
        vout, iout = (u, 1), (u, 0)
        spk, i_spk = v.vault_script(self.vp3), v.intent_script(v.intent_for(self.vp3, rspk))
        s = self.model.get_set(self.sid)
        member = list(s.members.values())[0]
        first_dormant = member.last_act + s.p['livenessWindow'] + 1
        self.mine_to(first_dormant - 1)            # tip + 1 = the first dormant height
        assert self.released(self.sid)
        self.accept(self.owner_hex(iout, i_spk, COIN, v.SEL_OWNER_RELEASED), 'OWNER-RELEASED on I (I-3)')
        self.accept(self.owner_hex(vout, spk, 2 * COIN, v.SEL_OWNER_RELEASED), 'OWNER-RELEASED on V')
        self.mine()
        assert_equal(self.node.gettxout(u, 0), None)
        assert_equal(self.node.gettxout(u, 1), None)

    # ------------------------------------------------------------------ E
    def section_pqpkh(self):
        print('E. TX_PQPKH: pay, then spend with SLH-DSA')
        pk = bytes(OWNER)[32:64]
        pkh = pq.pqpkh_script_of(pq.SCHEME_SLH_DSA_SHA2_128S, pk)
        assert_equal(len(pkh), 35)
        txid = self.accept(self.wallet_tx_hex([(COIN, pkh)]), 'pay a TX_PQPKH output')
        self.mine()
        n = [i for i, o in enumerate(v.tx_from_hex(self.node.getrawtransaction(txid)).vout) if o.scriptPubKey == pkh][0]
        out = self.node.gettxout(txid, n)
        assert_equal(out['scriptPubKey']['type'], 'pqpubkeyhash')
        tx = v.make_tx([(txid, n, v.SEQUENCE_FINAL)], [(COIN - FEE, self.change_spk())])
        tx.vin[0].scriptSig = pq.pq_scriptsig_from_pushes(
            pq.pq_sign_input(tx, 0, pkh, COIN, v.VAULT_BRANCH_ID, OWNER))
        assert_equal(len(tx.vin[0].scriptSig), 7938)
        self.accept(v.tx_hex(tx), 'spend the TX_PQPKH output (7,938-byte scriptSig)')
        self.mine()
        assert_equal(self.node.gettxout(txid, n), None)

    # ------------------------------------------------------------------ F
    def section_falcon(self):
        print('F. Falcon (scheme 2) owners: valid by consensus before Falcon (A-1)')
        falcon_owner = bytes([pq.SCHEME_FN_DSA_512]) + OWNER_KEY[1:]
        vp = self.vparams(self.sid, owner=falcon_owner)
        hex_ = self.lock_hex(vp, COIN)
        # vault_lock follows the relay policy: no scheme-2 owner before Falcon (review A F3)
        assert_rpc_error('a scheme-2 (FN-DSA-512) owner before Falcon is active', self.node.vault_lock,
                         {'tag': 'TEST', 'setid': self.sid[::-1].hex(),
                          'delay': 5, 'ownerheight': self.tip() + 500, 'amount': 1, 'owner': falcon_owner.hex()})
        assert_rpc_error('unregistered post-quantum scheme', self.node.vault_list, {'owner': '03' + '00' * 32})
        txid = self.nodes[1].sendrawtransaction(hex_)
        print('    ok   a scheme-2 V relayed by node 1 (-pqfalcon=1)')
        [bh] = self.nodes[1].generate(1)
        sync_blocks(self.nodes)
        self.sync_model()
        assert txid in self.node.getblock(bh)['tx']
        listed = self.node.vault_list({'owner': falcon_owner.hex()})
        assert_equal([x['ownerscheme'] for x in listed], [2])
        print('    skip a Falcon owner spend: no Python Falcon signer (covered by vault_template_tests)')


if __name__ == '__main__':
    VaultPQTest().main()
