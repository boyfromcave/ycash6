#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Template-spend relay policy with standardness enforced (audit 01/V-4; upgrade plan §15.3 "Malleability").

Regtest accepts non-standard transactions by default, so the policy is otherwise exercised only by unit tests.
Both nodes here run with ``-acceptnonstdtxn=0`` (relay policy enforced) and ``-pqfalcon=1``. Through
``sendrawtransaction`` (AcceptToMemoryPool):

  - honest spends are accepted: a 2-of-3 UNLOCK of a V, an SLH-DSA OWNER spend (selector 2), a Falcon
    (FN-DSA-512) OWNER spend, the RELEASE of the intent the unlock made, and an APP spend (selector 4, the
    shape a YED claim uses; the YED claim itself runs with standardness enforced in yellowback_claim.py);
  - each malleated twin — one extra push in front of the same, still valid, signatures — is refused as
    non-standard, and the model (consensus) accepts it; the malleated UNLOCK is then mined in a block (consensus-valid):
    the txid stays miner-malleable, which is documented, not prevented.

    ZCASHD=<ycashd> ../.venv/bin/python -u qa/rpc-tests/vault_policy.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

from test_framework import pq
from test_framework import vault as v
from test_framework.authproxy import JSONRPCException
from test_framework.vault_harness import COIN, OWNER_KEY, VaultTestBase, secrets

NONSTANDARD = ('bad-txns-nonstandard-inputs', 'nonstandard transaction input', 'TX rejected')


def malleate(hex_, n_in=0):
    """The same transaction with one extra push (0x07) in front of input ``n_in``'s scriptSig."""
    t = v.tx_from_hex(hex_)
    t.vin[n_in].scriptSig = v.push(b'\x07') + bytes(t.vin[n_in].scriptSig)
    return v.tx_hex(t)


class VaultPolicyTest(VaultTestBase):

    def node_args(self, i):
        return super().node_args(i) + ['-acceptnonstdtxn=0', '-pqfalcon=1']

    def refuse_nonstandard(self, hex_, label):
        r = self.model.check_tx(v.tx_from_hex(hex_))
        assert r is None, '%s: the model (consensus) should accept the malleated twin, got %r' % (label, r)
        try:
            self.node.sendrawtransaction(hex_)
        except JSONRPCException as e:
            msg = e.error['message']
            # ycash6: 'bad-txns-nonstandard-inputs'; ycash-dd (v4.5.0) returns the refusal without a reject reason
            # (main.cpp AcceptToMemoryPool: return error("...nonstandard transaction input")), i.e. an empty message
            assert msg == '' or any(x in msg for x in NONSTANDARD), '%s: expected a non-standard refusal, got %r' % (label, msg)
            print('    no   %s (%s)' % (label, msg or 'non-standard, no reason given'))
            return
        raise AssertionError('%s: the node relayed a malleated template spend' % label)

    def run_test(self):
        self.start_vault()
        print('A. a 2-of-3 set, four vaults')
        sid, admit = self.create_set('P', seats=3, unlock_threshold=2, cancel_threshold=1, slash_threshold=2,
                                     maturity=2, liveness_window=1000)
        m = secrets('policy-member', 3)
        for i, s in enumerate(m):
            self.join(sid, s, [admit], 'JOIN P m%d' % i)      # admitKey admission: no member is current yet
        self.mine(3)
        self.heartbeat(sid, m, 'HEARTBEAT P')
        self.mine()
        oh = self.tip() + 12
        vp_unlock = self.vparams(sid, delay=2)
        vp_unlock2 = self.vparams(sid, delay=2)
        vp_owner = self.vparams(sid, owner_height=oh)
        falcon = None
        pq.falcon_set_build_dir(self.options.tmpdir)
        if pq.falcon_signer_available():
            falcon_pk, falcon_sk = pq.falcon_keygen(bytes(range(48)))
            falcon = (falcon_pk, falcon_sk)
            vp_falcon = self.vparams(sid, owner_height=oh,
                                     owner=bytes([pq.SCHEME_FN_DSA_512]) + pq.key_hash(pq.SCHEME_FN_DSA_512, falcon_pk))
        vp_app = self.vparams(sid, app_height=oh, tag=b'YED\x00')    # YED's rules unconfigured here: the APP shape only
        V1 = self.lock(vp_unlock, 2 * COIN, 'lock V1 (unlock)')
        V2 = self.lock(vp_unlock2, 2 * COIN, 'lock V2 (unlock, malleated)')
        V3 = self.lock(vp_owner, 2 * COIN, 'lock V3 (SLH-DSA owner)')
        V4 = self.lock(vp_falcon, 2 * COIN, 'lock V4 (Falcon owner)') if falcon else None
        V5 = self.lock(vp_app, 2 * COIN, 'lock V5 (APP)')
        self.mine()

        print('B. UNLOCK (k = 2 set signatures)')
        rspk = self.change_spk()
        honest = self.unlock_hex(V1, vp_unlock, 2 * COIN, [(rspk, 2 * COIN)], m[:2])
        self.refuse_nonstandard(malleate(honest), 'UNLOCK with <junk> before the two signatures')
        u1 = self.accept(honest, 'UNLOCK 2-of-3')
        twin = malleate(self.unlock_hex(V2, vp_unlock2, 2 * COIN, [(rspk, 2 * COIN)], m[1:]))
        self.refuse_nonstandard(twin, 'UNLOCK of V2 with <junk>')
        self.mine()
        bh = self.mine_raw([twin], 'the malleated UNLOCK in a block (consensus-valid)')
        assert self.in_block(v.tx_txid(v.tx_from_hex(twin)), bh)
        print('    ok   the malleated UNLOCK is mined: policy only, the txid stays miner-malleable')

        print('C. RELEASE of the intent (selector alone)')
        ip = v.intent_for(vp_unlock, rspk)
        self.mine(2)
        rel = self.release_hex((u1, 0), ip, 2 * COIN, rspk)
        self.refuse_nonstandard(malleate(rel), 'RELEASE with an extra push')
        self.accept(rel, 'RELEASE')

        print('D. OWNER spends (selector 2): SLH-DSA and Falcon')
        self.mine_to(oh)
        own = self.owner_hex(V3, v.vault_script(vp_owner), 2 * COIN, v.SEL_OWNER, lock_time=oh)
        self.refuse_nonstandard(malleate(own), 'SLH-DSA OWNER with an extra push')
        self.accept(own, 'SLH-DSA OWNER spend (selector 2)')
        if falcon:
            spk = v.vault_script(vp_falcon)
            tx = v.make_tx([(V4[0], V4[1], v.SEQUENCE_FINAL - 1)], [(2 * COIN - v.VAULT_FEE, self.change_spk())], oh)
            sig = pq.falcon_sign(falcon[1], v.template_sighash(tx, 0, spk, 2 * COIN)) + bytes([pq.SIGHASH_ALL])
            tx.vin[0].scriptSig = pq.pq_scriptsig(falcon[0], sig) + bytes([v.OP_2])
            fal = v.tx_hex(tx)
            self.refuse_nonstandard(malleate(fal), 'Falcon OWNER with an extra push')
            self.accept(fal, 'Falcon OWNER spend (selector 2)')
        else:
            print('    SKIP the Falcon owner spend: no C compiler for the optional Falcon signer')

        print('E. APP (selector 4, the YED claim shape)')
        fee_vin, change = v.node_fee_inputs(self.node)
        ispk = self.change_spk()
        app = v.build_app_tx(V5, vp_app, 2 * COIN, [(ispk, 2 * COIN)], fee_vin, change)
        app_hex = v.node_sign(self.node, app, app.vin[0].scriptSig)
        self.refuse_nonstandard(malleate(app_hex), 'APP with an extra push')
        self.accept(app_hex, 'APP spend into an intent')
        self.mine()
        print('vault_policy OK')


if __name__ == '__main__':
    VaultPolicyTest().main()
