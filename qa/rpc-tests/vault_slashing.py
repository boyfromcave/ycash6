#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Slashing in the vault primitive with raw transactions (docs/plans/yellowback-upgrade-plan.md
§3.6, §15.5 SET_EQUIVOCATION / SET_REMOVE and the bond rules, §15.9 ``vault_slashing.py``).

Every transaction comes from ``test_framework/vault.py`` and stock RPCs; every answer is
cross-checked against ``VaultModel`` (``test_framework/vault_harness.py``). One set X (7 seats,
unlock 2, cancel 1, slash 3):

  1. equivocation: two UNLOCKs of one vault signed by x0; malformed / wrong proofs refused
     (same message, two keys, an outsider, role 3, a signature on the act, an unknown set); the
     proof EJECTs x0 and freezes its bond; x0's signature no longer counts, a second proof,
     a heartbeat and a REMOVE of x0 are refused
  2. SET_REMOVE with burn (the contested-cancel slash): signer count, the target signing, burn 2
  3. SET_REMOVE without burn (O-6) for x2 and x6; x0 rejoins with a new bond (admission by
     slashThreshold current members); x2, removed, is then proven to have equivocated and is
     EJECTED with its bond frozen
  4. bonds at their locktime: x0's old bond (A-13), x1's (burned) and x2's (ejected) are frozen
     (mempool and block); x6's is returned
  5. withdrawal: spending x5's bond while ACTIVE makes it WITHDRAWN (signature, heartbeat refused)
  6. undo: the block that froze x4's bond disconnected (the bond spend is accepted) and
     reconnected (the spend is evicted from the mempool)

    ZCASHD=<ycashd> .venv/bin/python -u qa/rpc-tests/vault_slashing.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

from test_framework.util import assert_equal, sync_blocks
from test_framework import vault as v
from test_framework.vault_harness import (
    COIN,
    OUTSIDER,
    SCRIPT_SETSIG,
    VaultTestBase,
    secrets,
)


class VaultSlashingTest(VaultTestBase):

    def run_test(self):
        self.start_vault()
        sid, admit = self.create_set('X', seats=7, unlock_threshold=2, cancel_threshold=1, slash_threshold=3,
                                     maturity=2, bond_lock_min=5)
        x = secrets('X-member', 7)
        self.x = x
        bonds = {}
        for i, s in enumerate(x):
            bonds[i] = self.join(sid, s, [admit], 'JOIN x%d (admitKey)' % i)
        self.mine(3)
        assert_equal(self.info(sid)['current'], 7)
        k = [v.pubkey_of(s) for s in x]
        status = lambda i: self.model.get_set(sid).members[k[i]].status   # noqa: E731

        print('1. equivocation')
        vp = self.vparams(sid)
        spk = v.vault_script(vp)
        vout = self.lock(vp, 4 * COIN, 'lock VX (4 YEC)')
        self.mine()
        ra, rb = self.change_spk(), self.change_spk()
        tx_a = self.unlock_tx(vout, vp, 4 * COIN, [(ra, 4 * COIN)])
        tx_b = self.unlock_tx(vout, vp, 4 * COIN, [(rb, 4 * COIN)])
        sh_a = v.template_sighash(tx_a, 0, spk, 4 * COIN)
        sh_b = v.template_sighash(tx_b, 0, spk, 4 * COIN)
        hex_a = self.setsig_hex(tx_a, spk, 4 * COIN, sid, v.ROLE_UNLOCK, [x[0], x[1]], v.SEL_UNLOCK)
        hex_b = self.setsig_hex(tx_b, spk, 4 * COIN, sid, v.ROLE_UNLOCK, [x[0], x[2]], v.SEL_UNLOCK)
        self.lock_inputs(hex_a)            # kept for later probes: its fee coin stays unspent
        # the two signatures by x0, as an observer reads them from the two scriptSigs
        sig_a = v.push_values(v.tx_from_hex(hex_a).vin[0].scriptSig)[0]
        sig_b = v.push_values(v.tx_from_hex(hex_b).vin[0].scriptSig)[0]
        sig_b_x2 = v.push_values(v.tx_from_hex(hex_b).vin[0].scriptSig)[1]
        po = v.ser_prevout(vout[0], vout[1])
        assert v.recover_compact(sig_a, v.set_sig_msg_raw(sid, 1, po, sh_a)) == k[0]
        proof = v.act_set_equivocation(sid, po, 1, sh_a, sig_a, 1, sh_b, sig_b)
        self.reject(self.act_hex(v.act_set_equivocation(sid, po, 1, sh_a, sig_a, 1, sh_a, sig_a)),
                    'bad-vault-act-equivocation', 'bad-vault-act-equivocation', 'proof: the same message twice')
        self.reject(self.act_hex(v.act_set_equivocation(sid, po, 1, sh_a, sig_a, 1, sh_b, sig_b_x2)),
                    'bad-vault-act-equivocation', 'bad-vault-act-equivocation', 'proof: two different signers')
        out_proof = v.equivocation_proof(sid, OUTSIDER, vout[0], vout[1], 1, sh_a, 1, sh_b)
        self.reject(self.act_hex(out_proof), 'bad-vault-act-equivocation', 'bad-vault-act-equivocation',
                    'proof: an outsider\'s two signatures')
        self.reject(self.raw_act_hex(v.encode_act(dict(proof, roleB=3), check=False)), 'bad-vault-act-params',
                    'bad-vault-act-role', 'proof: role 3')
        self.reject(self.raw_act_hex(v.encode_act(proof), sigs_for=[x[1]]), 'bad-vault-act-sigs', 'bad-vault-act-sig',
                    'proof carrying an act signature')
        nosid = b'\x42' * 32
        self.reject(self.act_hex(v.equivocation_proof(nosid, x[0], vout[0], vout[1], 1, sh_a, 1, sh_b)),
                    'bad-vault-act-noset', 'bad-vault-act-equivocation', 'proof: an unknown set')
        self.accept(self.act_hex(proof), 'SET_EQUIVOCATION of x0 (anyone submits)')
        self.mine()
        assert_equal(status(0), v.MEMBER_EJECTED)
        self.reject(hex_a, SCRIPT_SETSIG, 'script-setsig', 'UNLOCK signed by the ejected x0')
        mixed = v.equivocation_proof(sid, x[0], vout[0], vout[1], 1, sh_a, 2, sh_a)
        self.reject(self.act_hex(mixed), 'bad-vault-act-equivocation', 'bad-vault-act-equivocation',
                    'a second proof against x0 (bond already frozen)')
        self.reject(self.heartbeat_hex(sid, x[0]), 'bad-vault-act-heartbeat', 'bad-vault-act-heartbeat',
                    'HEARTBEAT by the ejected x0')
        self.reject(self.act_hex(v.act_set_remove(sid, k[0], 0), x[3:6]), 'bad-vault-act-remove',
                    'bad-vault-act-remove', 'REMOVE of the ejected x0')

        print('2. SET_REMOVE with burn')
        self.reject(self.act_hex(v.act_set_remove(sid, k[1], 1), x[2:4]), 'bad-vault-act-sigs', 'bad-vault-act-sig',
                    'REMOVE x1 with 2 of 3 signatures')
        self.reject(self.act_hex(v.act_set_remove(sid, k[1], 1), [x[1], x[2], x[3]]), 'bad-vault-act-sigs',
                    'bad-vault-act-sig', 'REMOVE x1 signed by x1 itself')
        self.reject(self.raw_act_hex(v.encode_act(v.act_set_remove(sid, k[1], 2), check=False), sigs_for=x[2:5]),
                    'bad-vault-act-params', 'bad-vault-act-burn', 'REMOVE with burn = 2')
        self.accept(self.act_hex(v.act_set_remove(sid, k[1], 1), x[2:5]), 'REMOVE x1, burn 1 (x2, x3, x4)')
        self.mine()
        assert_equal(status(1), v.MEMBER_REMOVED)
        assert self.model.get_set(sid).members[k[1]].bond_frozen

        print('3. SET_REMOVE without burn; rejoin; equivocation after removal')
        self.accept(self.act_hex(v.act_set_remove(sid, k[2], 0), x[3:6]), 'REMOVE x2, burn 0')
        self.accept(self.act_hex(v.act_set_remove(sid, k[6], 0), x[3:6]), 'REMOVE x6, burn 0')
        self.mine()
        assert_equal(self.info(sid)['current'], 3)
        self.reject(self.join_hex(sid, x[0], [admit])[0], 'bad-vault-act-sigs',
                    'bad-vault-act-sig', 'rejoin of x0 by admitKey while 3 members are current')
        self.join(sid, x[0], x[3:6], 'x0 rejoins with a new bond (x3, x4, x5)')
        self.mine()
        assert_equal(status(0), v.MEMBER_ACTIVE)
        # x2 had signed B's unlock while a member: proven now, after its removal
        tx_c = self.unlock_tx(vout, vp, 4 * COIN, [(self.change_spk(), 4 * COIN)])
        sh_c = v.template_sighash(tx_c, 0, spk, 4 * COIN)
        sig_c = v.sign_recoverable(x[2], v.set_sig_msg_raw(sid, 1, po, sh_c))
        self.accept(self.act_hex(v.act_set_equivocation(sid, po, 1, sh_b, sig_b_x2, 1, sh_c, sig_c)),
                    'SET_EQUIVOCATION of the removed x2 (bond still unspent)')
        self.mine()
        assert_equal(status(2), v.MEMBER_EJECTED)

        print('4. bonds at their locktime')
        lt = max(b['locktime'] for b in bonds.values())
        self.mine_to(lt)
        self.reject_both(self.bond_spend_hex(bonds[0]), 'bad-vault-bond-frozen', 'bad-vault-bond-frozen',
                         'x0\'s old bond after its rejoin (A-13)')
        self.reject_both(self.bond_spend_hex(bonds[1]), 'bad-vault-bond-frozen', 'bad-vault-bond-frozen',
                         'x1\'s burned bond')
        self.reject_both(self.bond_spend_hex(bonds[2]), 'bad-vault-bond-frozen', 'bad-vault-bond-frozen',
                         'x2\'s bond (removed, then ejected)')
        self.accept(self.bond_spend_hex(bonds[6]), 'x6\'s bond returned (removed without burn)')
        self.mine()

        print('5. withdrawal of an ACTIVE member\'s bond')
        self.accept(self.bond_spend_hex(bonds[5]), 'x5 spends its bond while ACTIVE')
        self.mine()
        assert_equal(status(5), v.MEMBER_WITHDRAWN)
        self.reject(self.heartbeat_hex(sid, x[5]), 'bad-vault-act-heartbeat', 'bad-vault-act-heartbeat',
                    'HEARTBEAT by the withdrawn x5')
        self.reject(self.unlock_hex(vout, vp, 4 * COIN, [(ra, 4 * COIN)], [x[5], x[3]]), SCRIPT_SETSIG,
                    'script-setsig', 'UNLOCK signed by the withdrawn x5')
        self.mine(2)                        # x0's rejoin is mature
        self.accept(self.unlock_hex(vout, vp, 4 * COIN, [(ra, 4 * COIN)], [x[3], x[0]]),
                    'UNLOCK by x3 and the rejoined x0')
        self.mine()

        print('6. undo of a freeze')
        proof4 = v.equivocation_proof(sid, x[4], vout[0], vout[1], 1, sh_a, 1, sh_b)
        bh = self.mine_raw([self.act_hex(proof4)], 'a block with the proof against x4')
        assert_equal(status(4), v.MEMBER_EJECTED)
        spend4 = self.bond_spend_hex(bonds[4])
        self.reject(spend4, 'bad-vault-bond-frozen', 'bad-vault-bond-frozen', 'x4\'s frozen bond')
        self.node.invalidateblock(bh)
        self.sync_model()
        assert_equal(status(4), v.MEMBER_ACTIVE)
        s4 = self.accept(spend4, 'x4\'s bond with the proof disconnected')
        self.node.reconsiderblock(bh)
        sync_blocks(self.nodes)
        self.sync_model()
        assert_equal(self.node.getbestblockhash(), bh)
        self.assert_evicted(s4, 'a spend of a bond frozen on reconnect stayed in the mempool')
        self.reject(spend4, 'bad-vault-bond-frozen', 'bad-vault-bond-frozen', 'x4\'s bond after the reconnect')
        self.mine()
        self.sync_all()
        print('vault_slashing OK')


if __name__ == '__main__':
    VaultSlashingTest().main()
