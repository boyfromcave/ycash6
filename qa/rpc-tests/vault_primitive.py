#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The vault primitive end to end on regtest with raw transactions
(docs/plans/yellowback-upgrade-plan.md §15.3-§15.6, §15.9 ``vault_primitive.py``).

Every transaction is built with ``test_framework/vault.py`` and stock RPCs only, never the
``set_*`` / ``vault_*`` RPCs; every node answer is cross-checked against ``VaultModel``
(``test_framework/vault_harness.py``). Sections:

  0. before activation a ``YV`` act is data: a SET_CREATE mined then creates no set
  A. acts: malformed payloads, a coinbase act, SET_CREATE, JOIN admission (admitKey, then
     slashThreshold members), seats, bonds, HEARTBEAT
  B. lock (V-1, malformed shapes, I-0), UNLOCK (threshold of distinct current members, branch
     id, role, covenant S-2, one template input S-1, selectors, APP disabled S-4)
  C. intents: CANCEL until coinHeight + delay - 1 (I-2) and RELEASE from coinHeight + delay
     (BIP68 + CSV, I-1), anyone may release (U-15)
  D. OWNER after ownerHeight (selector 2: CLTV, finality, owner signature)
  E. OWNER-RELEASED on dormancy (selector 3 on V and I), and the mempool eviction of an
     owner-released spend when a heartbeat makes the set live again
  F. SET_WINDDOWN and the owner branch opening at windDownHeight + livenessWindow
  G. rate limit (U-20 epochs, creation-epoch basis 0, exact cap, 2x across a boundary), its
     undo on invalidateblock with the mempool eviction on reconnect, and two unlocks that only
     together exceed the cap (the miner takes one)
  H. mempool eviction of an I-2 cancel that ages out and of a release made early by a reorg
  I. reorg / undo: a SET_REMOVE disconnected and reconnected (eviction of a spend it
     invalidates); a SET_REMOVE reorged out by a longer chain on both nodes
  J. restart reconciliation: clean restart, SIGKILL, and <datadir>/vaults/ deleted

    ZCASHD=<ycashd> .venv/bin/python -u qa/rpc-tests/vault_primitive.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

from test_framework.authproxy import JSONRPCException
from test_framework.util import assert_equal, sync_blocks
from test_framework import vault as v
from test_framework.vault_harness import (
    ACTIVATION,
    BLOCK_NONFINAL,
    COIN,
    MEMPOOL_BIP68,
    MEMPOOL_NONFINAL,
    OUTSIDER,
    OWNER,
    OWNER_KEY,
    OWNER_OUTSIDER,
    SCRIPT_FALSE,
    SCRIPT_LOCKTIME,
    SCRIPT_SETSIG,
    SCRIPT_VERIFY,
    VaultTestBase,
    secrets,
)
from test_framework.yellowback_util import mine_block_raw, template_coinbase

CANOPY_BRANCH_ID = 0x19bd2d2f
DELAY = 5


class VaultPrimitiveTest(VaultTestBase):

    def run_test(self):
        self.section_pre_activation()
        self.section_acts()
        self.section_lock_unlock()
        self.section_intents()
        self.section_owner_after_height()
        self.section_dormancy()
        self.section_winddown()
        self.section_rate()
        self.section_evictions()
        self.section_reorg()
        self.section_restart()
        self.sync_all()
        assert_equal(self.nodes[0].getbestblockhash(), self.nodes[1].getbestblockhash())
        print('vault_primitive OK')

    # ------------------------------------------------------------------ 0
    def section_pre_activation(self):
        print('0. before activation a YV act is data')
        self.model = v.VaultModel(activation_height=ACTIVATION)
        self.model_hashes = {}
        self.node.generate(ACTIVATION - 5)
        sync_blocks(self.nodes)
        hex_, self.pre_sid = self.create_set_hex(v.fixed_secret('pre-admit'))
        v.node_send(self.node, hex_)
        # a V-shaped output with a malformed field is an ordinary (nonstandard) output too
        bad_v = v.vault_script_unchecked(v.VaultParams(b'TEST', self.pre_sid, self.pre_sid, 0, 1000, 0,
                                                       OWNER_KEY))
        v.node_send(self.node, self.wallet_tx_hex([(COIN, bad_v)]))
        self.node.generate(1)
        sync_blocks(self.nodes)
        assert self.tip() < ACTIVATION
        self.mine_to(ACTIVATION + 1)
        assert_equal(self.node.getblockchaininfo()['upgrades']['6d5b7a31']['status'], 'active')
        self.split_coins(40, 2)
        self.node.sendtoaddress(self.nodes[1].getnewaddress(), 10)
        self.mine()
        # the pre-activation SET_CREATE made no set
        vp = self.vparams(self.pre_sid)
        self.reject(self.lock_hex(vp, COIN), 'bad-txns-vault-noset', 'bad-vault-unknown-set',
                    'a V naming a set created before activation')

    # ------------------------------------------------------------------ A
    def section_acts(self):
        print('A. acts')
        node = self.node
        admit = v.fixed_secret('S-admit')
        create = v.act_set_create(3, 2, 1, 2, v.pubkey_of(admit), rate_window=1000, liveness_window=1000,
                                  bond_min=COIN, bond_lock_min=20, maturity=3)
        p = v.encode_act(create)
        body = p[4:]
        self.reject(self.raw_act_hex(b'YV\x02\x01' + body), 'bad-vault-act-version', 'bad-vault-act-version',
                    'act version 2')
        self.reject(self.raw_act_hex(b'YV\x01\x09' + body), 'bad-vault-act-type', 'bad-vault-act-type',
                    'act type 9')
        self.reject(self.raw_act_hex(p[:-1]), 'bad-vault-act-malformed', 'bad-vault-act-size',
                    'SET_CREATE body one byte short')
        self.reject(self.raw_act_hex(p + b'\x00'), 'bad-vault-act-malformed', 'bad-vault-act-size',
                    'SET_CREATE trailing byte')
        bad = dict(create, unlockThreshold=4)
        self.reject(self.raw_act_hex(v.encode_act(bad, check=False)), 'bad-vault-act-params',
                    'bad-vault-act-threshold', 'SET_CREATE unlockThreshold > seats')
        bad = dict(create, flags=2)
        self.reject(self.raw_act_hex(v.encode_act(bad, check=False)), 'bad-vault-act-params',
                    'bad-vault-act-flags', 'SET_CREATE unknown flag bit')
        self.reject(self.raw_act_hex(p, sigs_for=[admit]), 'bad-vault-act-sigs', 'bad-vault-act-sig',
                    'SET_CREATE carrying a signature')
        self.reject(self.raw_act_hex(p, extra_sigs=[b'\x1f' * 64]), 'bad-vault-act-malformed',
                    'bad-vault-act-sig', 'an act signature of 64 bytes')
        two = self.wallet_tx_hex([(0, v.act_script(p)), (0, v.act_script(p))])
        self.reject(two, 'bad-vault-act-multi', 'bad-vault-act-count', 'two YV outputs')

        print('  an act in a coinbase')
        cb, _gbt = template_coinbase(node)
        cb.vout.append(v.CTxOut(0, v.act_script(p)))
        r = self.model.connect_block(self.model.tip + 1, [cb])
        assert r == (0, 'bad-vault-act-coinbase'), r
        tip = node.getbestblockhash()
        result, _ = mine_block_raw(node, [], coinbase=cb)
        assert 'bad-vault-act-coinbase' in str(result), result
        assert_equal(node.getbestblockhash(), tip)

        print('  SET_CREATE; acts naming the set are refused until it is in an earlier block')
        create_hex, sid = v.node_set_create(node, create)
        self.lock_inputs(create_hex)
        self.S, self.S_admit = sid, admit
        m = secrets('S-member', 4)
        self.Sm = m
        join_hex, _lt = self.join_hex(sid, m[0], [admit])
        self.block_reject([create_hex, join_hex], 'bad-vault-act-noset', 'bad-vault-act-join',
                          'SET_CREATE and a JOIN of it in one block')
        self.accept(create_hex, 'SET_CREATE S (3 seats, 2 / 1 / 2)')
        self.reject(join_hex, 'bad-vault-act-noset', 'bad-vault-act-set', 'JOIN while SET_CREATE is in the mempool')
        self.reject(self.lock_hex(self.vparams(sid), COIN), 'bad-txns-vault-noset', 'bad-vault-unknown-set',
                    'V while SET_CREATE is in the mempool')
        # the sets the later sections use, created in the same block
        self.D, self.D_admit = self.create_set('D', mine=False, seats=2, unlock_threshold=1, cancel_threshold=1,
                                               slash_threshold=1, liveness_window=12, maturity=2)
        self.W, self.W_admit = self.create_set('W', mine=False, seats=3, unlock_threshold=2, cancel_threshold=1,
                                               slash_threshold=2, liveness_window=10, maturity=2)
        self.mine()
        print('  JOIN (admitKey admission while fewer than slashThreshold members are current)')
        sm = self.model.get_set(sid)
        lt = self.tip() + 1 + sm.p['bondLockMin'] + 30
        self.reject(self.join_hex(sid, m[0], [])[0], 'bad-vault-act-sigs', 'bad-vault-act-sig',
                    'JOIN without the admitKey signature')
        mk = v.pubkey_of(m[0])
        wrong_s1 = self.act_hex(v.act_set_join(sid, mk, lt), [OUTSIDER, admit], [(COIN, v.bond_spk(mk, lt))])
        self.reject(wrong_s1, 'bad-vault-act-sig', 'bad-vault-act-sig', 'JOIN whose S_1 is not the member')
        self.reject(self.join_hex(sid, m[0], [admit], bond=COIN - 1)[0], 'bad-vault-act-bond', 'bad-vault-act-bond',
                    'JOIN bond below bondMin')
        short = self.tip() + 1 + sm.p['bondLockMin'] - 1
        self.reject(self.join_hex(sid, m[0], [admit], locktime=short)[0], 'bad-vault-act-bond', 'bad-vault-act-bond',
                    'JOIN bondLocktime < h + bondLockMin')
        wrong_bond = self.act_hex(v.act_set_join(sid, mk, lt), [m[0], admit], [(COIN, v.bond_spk(mk, lt + 1))])
        self.reject(wrong_bond, 'bad-vault-act-bond', 'bad-vault-act-bond', 'JOIN whose bondVout is another locktime')
        self.join(sid, m[0], [admit], 'JOIN m0 (admitKey)')
        self.join(sid, m[1], [admit], 'JOIN m1 (admitKey)')
        self.Dm = v.fixed_secret('D-member-0')
        self.D_bond = self.join(self.D, self.Dm, [self.D_admit], 'JOIN D member')
        self.Wm = secrets('W-member', 3)
        for i, s in enumerate(self.Wm):
            self.join(self.W, s, [self.W_admit], 'JOIN W member %d' % i)
        self.mine()
        self.reject(self.join_hex(sid, m[0], [admit])[0], 'bad-vault-act-join', 'bad-vault-act-join',
                    'JOIN of an ACTIVE member')
        self.reject(self.heartbeat_hex(sid, m[0]), 'bad-vault-act-heartbeat', 'bad-vault-act-heartbeat',
                    'HEARTBEAT before maturity')
        self.mine(3)
        assert_equal(self.info(sid)['current'], 2)
        print('  admission by slashThreshold current members once that many are current')
        self.reject(self.heartbeat_hex(sid, m[2]), 'bad-vault-act-heartbeat', 'bad-vault-act-heartbeat',
                    'HEARTBEAT by a non-member')
        wrong_hb = self.act_hex(v.act_set_heartbeat(sid, v.pubkey_of(m[0])), [m[1]])
        self.reject(wrong_hb, 'bad-vault-act-sig', 'bad-vault-act-heartbeat', 'HEARTBEAT signed by another member')
        self.reject(self.join_hex(sid, m[2], [admit])[0], 'bad-vault-act-sigs', 'bad-vault-act-sig',
                    'JOIN by admitKey once 2 members are current')
        self.reject(self.join_hex(sid, m[2], [m[0]])[0], 'bad-vault-act-sigs', 'bad-vault-act-sig',
                    'JOIN with one member signature (slashThreshold 2)')
        self.join(sid, m[2], [m[0], m[1]], 'JOIN m2 (m0 + m1)')
        self.heartbeat(sid, [m[0]], 'HEARTBEAT S m0')
        self.mine()
        self.reject(self.join_hex(sid, m[3], [m[0], m[1]])[0], 'bad-vault-act-seats', 'bad-vault-act-join',
                    'JOIN into a full set (3 seats)')
        self.mine(3)
        assert_equal(self.info(sid)['current'], 3)

    # ------------------------------------------------------------------ B
    def section_lock_unlock(self):
        print('B. lock and unlock')
        sid, m = self.S, self.Sm
        rspk = self.change_spk()
        self.reject(self.lock_hex(self.vparams(sid, cancel_sid=b'\x07' * 32), COIN), 'bad-txns-vault-noset',
                    'bad-vault-unknown-set', 'V with an unknown cancelSetId')
        bad_delay = v.vault_script_unchecked(self.vparams(sid, delay=0))
        self.reject(self.wallet_tx_hex([(COIN, bad_delay)]), 'bad-txns-vault-malformed', 'bad-txns-vault-malformed',
                    'V-shaped output with delay 0')
        vp5 = self.vparams(sid, delay=5)
        nonmin = v.nonminimal_delay_vault(vp5)
        self.reject(self.wallet_tx_hex([(COIN, nonmin)]), 'bad-txns-vault-malformed', 'bad-txns-vault-malformed',
                    'V-shaped output with a non-minimal delay push')
        stray_i = v.intent_script(v.intent_for(vp5, rspk))
        self.reject(self.wallet_tx_hex([(COIN, stray_i)]), 'bad-txns-vault-intent', 'bad-vault-intent-create',
                    'an I output created without a vault UNLOCK (I-0)')

        self.vp1 = self.vparams(sid, delay=DELAY, owner_height=self.tip() + 400)
        self.vp2 = self.vparams(sid, delay=DELAY, owner_height=self.tip() + 14)
        self.v1 = self.lock(self.vp1, 6 * COIN, 'lock V1 (6 YEC)')
        self.v2 = self.lock(self.vp2, 2 * COIN, 'lock V2 (2 YEC, ownerHeight tip + 14)')
        self.mine()
        assert_equal(self.info(sid)['lockedValue'], 8 * COIN)

        vp, out, val = self.vp1, self.v1, 6 * COIN
        spk = v.vault_script(vp)
        self.R = [self.change_spk() for _ in range(3)]
        recips = [(self.R[0], 3 * COIN), (self.R[1], COIN), (self.R[2], COIN)]

        def unl(signers, **kw):
            return self.unlock_hex(out, vp, val, recips, signers, relock=COIN, **kw)
        self.reject(unl(m[:1]), SCRIPT_SETSIG, 'script-setsig', 'UNLOCK with 1 of 2 signatures')
        self.reject(unl([m[0], m[0]]), SCRIPT_SETSIG, 'script-setsig', 'UNLOCK with one member twice')
        self.reject(unl([m[0], OUTSIDER]), SCRIPT_SETSIG, 'script-setsig', 'UNLOCK with an outsider')
        # set signatures bind the ZIP-243 sighash, so the node diagnoses the previous epoch's branch
        # id as it does for any signature (finding (15))
        self.reject(unl(m[:2], branch_id=CANOPY_BRANCH_ID), 'old-consensus-branch-id', 'script-setsig',
                    'UNLOCK signed over the previous branch id')
        tx = self.unlock_tx(out, vp, val, recips, COIN)
        self.reject(self.setsig_hex(tx, spk, val, sid, v.ROLE_CANCEL, m[:2], v.SEL_UNLOCK), SCRIPT_SETSIG,
                    'script-setsig', 'UNLOCK signed for the cancel role')
        tx = self.unlock_tx(out, vp, val, [(self.R[0], 3 * COIN)], 3 * COIN)
        tx.vout[1].nValue -= 1
        self.reject(self.setsig_hex(tx, spk, val, sid, v.ROLE_UNLOCK, m[:2], v.SEL_UNLOCK),
                    'bad-txns-vault-value', 'bad-vault-covenant', 'UNLOCK leaking 1 zat to the fee (S-2)')
        tx = self.unlock_tx(out, vp, val, [(self.R[0], val)])
        wrong = v.intent_for(self.vparams(sid, delay=DELAY + 1, owner_height=vp.owner_height), self.R[0])
        tx.vout[0].scriptPubKey = v.intent_script(wrong)
        self.reject(self.setsig_hex(tx, spk, val, sid, v.ROLE_UNLOCK, m[:2], v.SEL_UNLOCK),
                    'bad-txns-vault-covenant', 'bad-vault-covenant', 'UNLOCK into an intent with another delay')
        tx = self.unlock_tx(out, vp, val, [(self.R[0], 3 * COIN)], 3 * COIN)
        tx.vout[1].scriptPubKey = v.vault_script(self.vp2)
        self.reject(self.setsig_hex(tx, spk, val, sid, v.ROLE_UNLOCK, m[:2], v.SEL_UNLOCK),
                    ('bad-txns-vault-covenant',), 'bad-vault-covenant', 'UNLOCK re-locking into another V')
        # two template inputs (S-1)
        # two template inputs (S-1), each with valid set signatures (so only the rule fails)
        spk2 = v.vault_script(self.vp2)
        fee_vin, change = v.node_fee_inputs(self.node)
        two = v.make_tx([(out[0], out[1], v.SEQUENCE_FINAL), (self.v2[0], self.v2[1], v.SEQUENCE_FINAL)] + fee_vin,
                        [(val, spk), (2 * COIN, spk2)] + ([change] if change else []))
        ss0 = v.vault_unlock_scriptsig(v.set_sigs_for(two, 0, spk, val, sid, v.ROLE_UNLOCK, m[:2]))
        ss1 = v.vault_unlock_scriptsig(v.set_sigs_for(two, 1, spk2, 2 * COIN, sid, v.ROLE_UNLOCK, m[:2]))
        t = v.tx_from_hex(v.node_sign(self.node, two, ss0, 0))
        t.vin[1].scriptSig = ss1
        self.reject(v.tx_hex(t), 'bad-txns-vault-multi', 'bad-vault-template-count', 'two template inputs')
        # the selector as a data push after valid signatures: the script would pass, S-1 does not
        tx = self.unlock_tx(out, vp, val, recips, COIN)
        sigs = v.set_sigs_for(tx, 0, spk, val, sid, v.ROLE_UNLOCK, m[:2])
        self.reject(v.node_sign(self.node, tx, b''.join(v.push(x) for x in sigs) + b'\x01\x01'),
                    'bad-txns-vault-selector', 'bad-vault-selector', 'selector pushed as data')
        for label, ss in (('selector OP_5', bytes([v.OP_1 + 4])), ('non-push scriptSig', bytes([v.OP_DUP, v.OP_1]))):
            tx = self.unlock_tx(out, vp, val, recips, COIN)
            self.reject(v.node_sign(self.node, tx, ss), ('bad-txns-vault-selector', 'script-verify-flag'),
                        'bad-vault-selector', label)
        fee_vin, change = v.node_fee_inputs(self.node)
        app = v.build_app_tx(out, vp, val, recips, fee_vin, change, COIN)
        self.reject(v.node_sign(self.node, app, app.vin[0].scriptSig), ('bad-txns-vault-app', SCRIPT_FALSE),
                    'bad-vault-app-disabled', 'APP selector with appHeight 0 (S-4)')

        self.u1 = self.accept(unl(m[:2]), 'UNLOCK V1 into 3 intents (3 + 1 + 1 YEC) + re-lock 1 YEC')
        self.mine()
        self.c1 = self.tip()
        assert_equal(self.info(sid)['lockedValue'], 3 * COIN)
        self.recips = recips

    # ------------------------------------------------------------------ C
    def section_intents(self):
        print('C. intents: cancel until coinHeight + delay - 1, release from coinHeight + delay')
        sid, m, vp = self.S, self.Sm, self.vp1
        ips = [v.intent_for(vp, spk) for spk, _ in self.recips]
        outs = [(self.u1, i) for i in range(3)]
        vals = [val for _, val in self.recips]
        self.mine_to(self.c1 + DELAY - 2)          # tip + 1 = c1 + delay - 1: the last cancel height
        i_spk = v.intent_script(ips[1])
        self.reject(self.cancel_hex(outs[1], ips[1], vals[1], vp, [OUTSIDER]), SCRIPT_SETSIG, 'script-setsig',
                    'CANCEL by an outsider')
        tx = v.build_cancel_tx(outs[1], ips[1], vals[1], vp, *v.node_fee_inputs(self.node))
        self.reject(self.setsig_hex(tx, i_spk, vals[1], sid, v.ROLE_UNLOCK, [m[2]], v.SEL_CANCEL), SCRIPT_SETSIG,
                    'script-setsig', 'CANCEL signed for the unlock role')
        tx = v.build_cancel_tx(outs[1], ips[1], vals[1], vp, *v.node_fee_inputs(self.node))
        tx.vout[0].scriptPubKey = v.vault_script(self.vp2)
        self.reject(self.setsig_hex(tx, i_spk, vals[1], sid, v.ROLE_CANCEL, [m[2]], v.SEL_CANCEL),
                    'bad-txns-vault-cancel', 'bad-vault-cancel', 'CANCEL back into another vault')
        tx = v.build_cancel_tx(outs[1], ips[1], vals[1], vp, *v.node_fee_inputs(self.node))
        tx.vout[0].nValue -= 1
        self.reject(self.setsig_hex(tx, i_spk, vals[1], sid, v.ROLE_CANCEL, [m[2]], v.SEL_CANCEL),
                    'bad-txns-vault-cancel', 'bad-vault-cancel', 'CANCEL returning 1 zat less')
        cancel = self.accept(self.cancel_hex(outs[1], ips[1], vals[1], vp, [m[2]]),
                             'CANCEL I2 by one member at coinHeight + delay - 1')
        rel = self.release_hex(outs[0], ips[0], vals[0], self.recips[0][0])
        self.reject(rel, MEMPOOL_BIP68, 'bad-txns-vault-timelock', 'RELEASE at coinHeight + delay - 1')
        self.block_reject([rel], BLOCK_NONFINAL, 'bad-txns-vault-timelock', 'RELEASE at coinHeight + delay - 1')
        self.reject(self.release_hex(outs[0], ips[0], vals[0], self.recips[0][0], sequence=DELAY - 1),
                    SCRIPT_LOCKTIME, 'script-sequence', 'RELEASE with nSequence = delay - 1 (CSV)')
        self.reject(self.release_hex(outs[0], ips[0], vals[0], self.recips[0][0], sequence=v.SEQUENCE_FINAL),
                    SCRIPT_LOCKTIME, 'script-sequence', 'RELEASE with the BIP68 disable bit')
        bh = self.mine()[0]
        assert self.in_block(cancel, bh)
        assert_equal(self.info(sid)['lockedValue'], 4 * COIN)
        back = self.node.getrawtransaction(cancel, 1)['vout'][0]['scriptPubKey']['hex']
        assert v.parse_vault(bytes.fromhex(back)) == vp, 'the cancel did not return to V1\'s script'
        # tip + 1 = c1 + delay
        self.reject(self.cancel_hex(outs[2], ips[2], vals[2], vp, [m[2]]), 'bad-txns-vault-cancel',
                    'bad-vault-cancel-late', 'CANCEL at coinHeight + delay')
        tx = v.build_release_tx(outs[0], ips[0], vals[0], self.recips[0][0], *v.node_fee_inputs(self.node))
        tx.vout[0].scriptPubKey = self.change_spk()
        self.reject(v.node_sign(self.node, tx, tx.vin[0].scriptSig), 'bad-txns-vault-release', 'bad-vault-release',
                    'RELEASE paying another script')
        tx = v.build_release_tx(outs[0], ips[0], vals[0], self.recips[0][0], *v.node_fee_inputs(self.node))
        tx.vout[0].nValue -= 1
        tx.vout[1].nValue += 1
        self.reject(v.node_sign(self.node, tx, tx.vin[0].scriptSig), 'bad-txns-vault-release', 'bad-vault-release',
                    'RELEASE paying 1 zat less')
        # anyone may release (U-15): node 1's wallet pays the fee
        fee_vin, change = v.node_funding(self.nodes[1], v.VAULT_FEE)
        change = (change - v.VAULT_FEE, v.node_spk(self.nodes[1])) if change > v.VAULT_FEE else None
        tx = v.build_release_tx(outs[0], ips[0], vals[0], self.recips[0][0], fee_vin, change)
        hex1 = v.node_sign(self.nodes[1], tx, tx.vin[0].scriptSig)
        r1 = self.accept(hex1, 'RELEASE I1 at coinHeight + delay, broadcast by a third party')
        r3 = self.accept(self.release_hex(outs[2], ips[2], vals[2], self.recips[2][0]), 'RELEASE I3')
        bh = self.mine()[0]
        assert self.in_block(r1, bh) and self.in_block(r3, bh)
        self.v1b = (cancel, 0)   # the cancelled value, back in V1's script

    # ------------------------------------------------------------------ D
    def section_owner_after_height(self):
        print('D. OWNER after ownerHeight (selector 2)')
        vp, out, val = self.vp2, self.v2, 2 * COIN
        spk = v.vault_script(vp)
        oh = vp.owner_height
        assert self.tip() + 1 <= oh, (self.tip(), oh)
        self.mine_to(oh - 1)                       # tip + 1 = ownerHeight
        self.reject(self.owner_hex(out, spk, val, v.SEL_OWNER, lock_time=oh), MEMPOOL_NONFINAL, 'bad-txns-nonfinal',
                    'OWNER with nLockTime = ownerHeight = tip + 1')
        self.reject(self.owner_hex(out, spk, val, v.SEL_OWNER, lock_time=oh - 1), SCRIPT_LOCKTIME, 'script-locktime',
                    'OWNER with nLockTime = ownerHeight - 1')
        self.mine()
        self.reject(self.owner_hex(out, spk, val, v.SEL_OWNER, lock_time=oh, secret=OWNER_OUTSIDER), SCRIPT_FALSE,
                    'script-ownersig', 'OWNER signed by another key')
        before = self.info(self.S)['lockedValue']
        self.accept(self.owner_hex(out, spk, val, v.SEL_OWNER, lock_time=oh), 'OWNER spend after ownerHeight')
        self.mine()
        assert_equal(self.info(self.S)['lockedValue'], before - val)

    # ------------------------------------------------------------------ E
    def section_dormancy(self):
        print('E. OWNER-RELEASED on dormancy (selectors 3 on V and I); eviction by a heartbeat')
        sid = self.D
        self.heartbeat(sid, [self.Dm], 'HEARTBEAT D (live again)')
        self.mine()
        vp = self.vparams(sid, delay=200)
        spk = v.vault_script(vp)
        out = self.lock(vp, 3 * COIN, 'lock VD (3 YEC) under D')
        self.mine()
        rspk = self.change_spk()
        ip = v.intent_for(vp, rspk)
        u = self.accept(self.unlock_hex(out, vp, 3 * COIN, [(rspk, COIN)], [self.Dm], relock=2 * COIN),
                        'UNLOCK VD into an intent (delay 200) + re-lock')
        self.mine()
        vout, iout = (u, 1), (u, 0)
        i_spk = v.intent_script(ip)
        assert not self.released(sid)
        self.reject(self.owner_hex(vout, spk, 2 * COIN, v.SEL_OWNER_RELEASED), SCRIPT_VERIFY, 'script-notreleased',
                    'OWNER-RELEASED on V while the set is live')
        self.reject(self.owner_hex(iout, i_spk, COIN, v.SEL_OWNER_RELEASED), SCRIPT_VERIFY, 'script-notreleased',
                    'OWNER-RELEASED on I while the set is live')
        s = self.model.get_set(sid)
        member = list(s.members.values())[0]
        first_dormant = member.last_act + s.p['livenessWindow'] + 1
        self.mine_to(first_dormant - 2)
        assert not self.dormant(sid)
        self.reject(self.owner_hex(vout, spk, 2 * COIN, v.SEL_OWNER_RELEASED), SCRIPT_VERIFY, 'script-notreleased',
                    'OWNER-RELEASED one block before dormancy')
        self.mine()
        assert self.dormant(sid) and self.released(sid)
        orel = self.accept(self.owner_hex(vout, spk, 2 * COIN, v.SEL_OWNER_RELEASED),
                           'OWNER-RELEASED on V at the first dormant height')
        hb_hex = self.heartbeat_hex(sid, self.Dm)
        hb = self.accept(hb_hex, 'HEARTBEAT of the dormant set (a current member may always heartbeat)')
        self.mine_raw([hb_hex], 'a block with the heartbeat only')
        assert not self.released(sid)
        self.assert_evicted(orel, 'the owner-released spend survived a heartbeat that made the set live')
        assert hb not in self.mempool()
        print('    ok   the owner-released spend was evicted when the heartbeat confirmed')
        self.reject(self.owner_hex(vout, spk, 2 * COIN, v.SEL_OWNER_RELEASED), SCRIPT_VERIFY, 'script-notreleased',
                    'OWNER-RELEASED after the heartbeat')
        s = self.model.get_set(sid)
        self.mine_to(self.tip() + s.p['livenessWindow'])
        assert self.dormant(sid)
        self.accept(self.owner_hex(iout, i_spk, COIN, v.SEL_OWNER_RELEASED), 'OWNER-RELEASED on I (I-3) when dormant')
        self.accept(self.owner_hex(vout, spk, 2 * COIN, v.SEL_OWNER_RELEASED), 'OWNER-RELEASED on V when dormant again')
        self.mine()
        assert_equal(self.info(sid)['lockedValue'], 0)

    # ------------------------------------------------------------------ F
    def section_winddown(self):
        print('F. SET_WINDDOWN')
        sid, w = self.W, self.Wm
        vp = self.vparams(sid)
        spk = v.vault_script(vp)
        out = self.lock(vp, 2 * COIN, 'lock VW (2 YEC) under W')
        self.mine()
        self.reject(self.act_hex(v.act_set_winddown(sid), [w[0]]), 'bad-vault-act-sigs', 'bad-vault-act-sig',
                    'WINDDOWN with 1 of 2 signatures')
        self.reject(self.act_hex(v.act_set_winddown(sid), [w[0], OUTSIDER]), 'bad-vault-act-sigs', 'bad-vault-act-sig',
                    'WINDDOWN with an outsider')
        self.accept(self.act_hex(v.act_set_winddown(sid), [w[0], w[1]]), 'WINDDOWN by 2 members')
        self.heartbeat(sid, [w[2]], 'HEARTBEAT W w2')
        self.mine()
        wd = self.tip()
        assert_equal(self.info(sid)['windDownHeight'], wd)
        self.reject(self.act_hex(v.act_set_winddown(sid), [w[0], w[1]]), 'bad-vault-act-winddown',
                    'bad-vault-act-winddown', 'a second WINDDOWN')
        self.reject(self.join_hex(sid, v.fixed_secret('W-late'), [w[0], w[1]])[0], 'bad-vault-act-winddown',
                    'bad-vault-act-join', 'JOIN after WINDDOWN')
        L = self.model.get_set(sid).p['livenessWindow']
        self.mine_to(wd + L - 2)                   # tip + 1 = windDownHeight + L - 1
        assert not self.released(sid)
        self.reject(self.owner_hex(out, spk, 2 * COIN, v.SEL_OWNER_RELEASED), SCRIPT_VERIFY, 'script-notreleased',
                    'OWNER-RELEASED at windDownHeight + livenessWindow - 1')
        self.mine()
        assert self.released(sid) and not self.dormant(sid), 'released by the wind-down alone'
        self.accept(self.owner_hex(out, spk, 2 * COIN, v.SEL_OWNER_RELEASED),
                    'OWNER-RELEASED at windDownHeight + livenessWindow (set not dormant)')
        self.mine()

    # ------------------------------------------------------------------ G
    def section_rate(self):
        print('G. rate limit (5000 bps, rateWindow 25)')
        W = 25
        self.mine_to((self.tip() // W + 1) * W)    # create, join, lock and the first attempt in one epoch
        sid, admit = self.create_set('R', seats=1, unlock_threshold=1, cancel_threshold=1, slash_threshold=1,
                                     rate_limit_bps=5000, rate_window=W, maturity=1)
        r = v.fixed_secret('R-member')
        self.join(sid, r, [admit], 'JOIN R member')
        self.mine()
        vpa = self.vparams(sid, delay=3)
        vpb = self.vparams(sid, delay=3, owner_height=vpa.owner_height + 1)
        va = self.lock(vpa, 10 * COIN, 'lock RA (10 YEC)')
        vb = self.lock(vpb, 4 * COIN, 'lock RB (4 YEC)')
        self.mine()
        rs = self.change_spk()
        self.reject(self.unlock_hex(va, vpa, 10 * COIN, [(rs, COIN)], [r], relock=9 * COIN), 'bad-txns-vault-rate',
                    'bad-vault-rate', 'UNLOCK in the set\'s creation epoch (basis 0)')
        e1 = (self.tip() // W + 1) * W
        e2 = e1 + W
        self.mine_to(e2 - 3)                       # the first unlocks at e2 - 2 (epoch e1)
        a = self.accept(self.unlock_hex(va, vpa, 10 * COIN, [(rs, 5 * COIN)], [r], relock=5 * COIN),
                        'UNLOCK 5 of cap 7 (basis 14)')
        self.mine()
        assert_equal(self.info(sid)['epochBasis'], 14 * COIN)
        self.reject(self.unlock_hex(vb, vpb, 4 * COIN, [(rs, 3 * COIN)], [r], relock=COIN), 'bad-txns-vault-rate',
                    'bad-vault-rate', 'UNLOCK 3 more (8 > 7)')
        b = self.accept(self.unlock_hex(vb, vpb, 4 * COIN, [(rs, 2 * COIN)], [r], relock=2 * COIN),
                        'UNLOCK 2 more (exactly the cap)')
        self.mine()
        assert_equal(self.tip(), e2 - 1)
        va2, vb2 = (a, 1), (b, 1)
        # epoch e2 starts at tip + 1: basis = 7 YEC locked, cap 3.5
        y_hex = self.unlock_hex(va2, vpa, 5 * COIN, [(rs, 35 * COIN // 10)], [r], relock=15 * COIN // 10)
        y = self.accept(y_hex, 'UNLOCK 3.5 at the first block of the next epoch (cap 3.5: 2x cap across a boundary)')
        yb = self.mine()[0]
        assert_equal(self.info(sid)['epochBasis'], 7 * COIN)
        assert_equal(self.info(sid)['epochUsed'], 35 * COIN // 10)
        self.reject(self.unlock_hex(vb2, vpb, 2 * COIN, [(rs, 1)], [r], relock=2 * COIN - 1), 'bad-txns-vault-rate',
                    'bad-vault-rate', 'UNLOCK 1 zat over the exactly spent cap')
        over = self.unlock_hex(vb2, vpb, 2 * COIN, [(rs, COIN // 2)], [r], relock=3 * COIN // 2)
        self.reject(over, 'bad-txns-vault-rate', 'bad-vault-rate', 'UNLOCK 0.5 with the cap spent')

        print('  undo: invalidate the block that used the cap, the other unlock fits again')
        self.node.invalidateblock(yb)
        self.sync_model()
        assert y in self.mempool(), 'the disconnected unlock did not return to the mempool'
        assert_equal(self.info(sid)['epoch'], e1 // W)
        o = self.accept(over, 'UNLOCK 0.5 against the disconnected tip')
        self.node.reconsiderblock(yb)
        sync_blocks(self.nodes)
        self.sync_model()
        assert_equal(self.node.getbestblockhash(), yb)
        self.assert_evicted(o, 'an unlock over the rate limit survived the reconnect')
        print('    ok   the 0.5 unlock was evicted on reconnect')
        self.reject(over, 'bad-txns-vault-rate', 'bad-vault-rate', 'UNLOCK 0.5 after the reconnect')

        print('  two unlocks within the cap alone but over it together: the miner takes one')
        e3 = e2 + W
        self.mine_to(e3 - 1)                       # tip + 1 = e3: basis 3.5 + 0 ... = locked 5.0, cap 2.5
        locked = self.info(sid)['lockedValue']
        cap = locked * 5000 // 10000
        part = cap * 6 // 10
        ya, yb2 = (y, 1), vb2
        ha = self.unlock_hex(ya, vpa, 15 * COIN // 10, [(rs, part)], [r], relock=15 * COIN // 10 - part)
        ta = self.accept(ha, 'UNLOCK 0.6 x cap from RA')
        hb = self.unlock_hex(yb2, vpb, 2 * COIN, [(rs, part)], [r], relock=2 * COIN - part)
        assert self.model.check_tx(v.tx_from_hex(hb)) is None
        try:
            tb = self.node.sendrawtransaction(hb)
            print('    ok   UNLOCK 0.6 x cap from RB accepted into the mempool beside it (tip-only check)')
        except JSONRPCException as e:
            assert 'bad-txns-vault-rate' in e.error['message'], e.error['message']
            tb = None
            print('    no   UNLOCK 0.6 x cap from RB refused by the mempool (%s): the mempool counts pending '
                  'unlocks' % e.error['message'])
        bh = self.mine()[0]
        got = [t for t in (ta, tb) if t is not None and self.in_block(t, bh)]
        assert_equal(len(got), 1)
        if tb is not None:
            other = tb if got[0] == ta else ta
            self.assert_evicted(other, 'the unlock the miner skipped stayed in the mempool')
            print('    ok   the block took one, the other was evicted')
        self.R_set = sid

    # ------------------------------------------------------------------ H
    def section_evictions(self):
        print('H. evictions: an I-2 cancel that ages out; a release made early by a reorg')
        sid, m = self.S, self.Sm
        vp = self.vparams(sid, delay=DELAY)
        out = self.lock(vp, 2 * COIN, 'lock VJ')
        self.mine()
        rspk = self.change_spk()
        ip = v.intent_for(vp, rspk)
        u = self.accept(self.unlock_hex(out, vp, 2 * COIN, [(rspk, 2 * COIN)], m[:2]), 'UNLOCK VJ')
        self.mine()
        c = self.tip()
        self.mine_to(c + DELAY - 3)                # tip + 1 = c + delay - 2
        cancel = self.accept(self.cancel_hex((u, 0), ip, 2 * COIN, vp, [m[0]]), 'CANCEL at coinHeight + delay - 2')
        self.mine_raw([], 'an empty block (c + delay - 2)')
        assert cancel in self.mempool(), 'the cancel left the mempool while still valid'
        self.mine_raw([], 'an empty block (c + delay - 1)')
        self.assert_evicted(cancel, 'a cancel past coinHeight + delay - 1 stayed in the mempool')
        print('    ok   the cancel aged out of the mempool')
        self.reject(self.cancel_hex((u, 0), ip, 2 * COIN, vp, [m[0]]), 'bad-txns-vault-cancel',
                    'bad-vault-cancel-late', 'CANCEL after it aged out')
        rel_hex = self.release_hex((u, 0), ip, 2 * COIN, rspk)
        rel = self.accept(rel_hex, 'RELEASE at coinHeight + delay')
        tip = self.node.getbestblockhash()
        self.node.invalidateblock(tip)
        self.sync_model()
        self.assert_evicted(rel, 'a release made early by a reorg stayed in the mempool')
        print('    ok   the release was evicted when the reorg made it early')
        self.reject(rel_hex, MEMPOOL_BIP68, 'bad-txns-vault-timelock', 'RELEASE one block early after the reorg')
        self.node.reconsiderblock(tip)
        sync_blocks(self.nodes)
        self.sync_model()
        self.accept(rel_hex, 'RELEASE again after reconsiderblock')
        self.mine()

    # ------------------------------------------------------------------ I
    def section_reorg(self):
        print('I. reorg / undo')
        sid, m = self.S, self.Sm
        vp = self.vparams(sid, delay=DELAY)
        out = self.lock(vp, COIN, 'lock VK')
        self.mine()
        rspk = self.change_spk()
        self.accept(self.act_hex(v.act_set_remove(sid, v.pubkey_of(m[2]), 0), [m[0], m[1]]), 'REMOVE m2 (burn 0)')
        x = self.mine()[0]
        with_m2 = self.unlock_hex(out, vp, COIN, [(rspk, COIN)], [m[2], m[0]])
        self.reject(with_m2, SCRIPT_SETSIG, 'script-setsig', 'UNLOCK signed by the removed member')
        self.node.invalidateblock(x)
        self.sync_model()
        assert self.model.get_set(sid).members[v.pubkey_of(m[2])].status == v.MEMBER_ACTIVE
        u = self.accept(with_m2, 'UNLOCK signed by m2 with the REMOVE disconnected')
        # node 1 is still on X, where m2 is removed: the relayed unlock fails its script there
        self.assert_connected('node 1 keeps node 0 connected after it relays an unlock valid only on its own tip')
        self.node.reconsiderblock(x)
        sync_blocks(self.nodes)
        self.sync_model()
        self.assert_evicted(u, 'an unlock signed by a member removed on reconnect stayed in the mempool')
        print('    ok   the unlock was evicted when the REMOVE reconnected')
        self.reject(with_m2, SCRIPT_SETSIG, 'script-setsig', 'UNLOCK by m2 after the reconnect')

        print('  a SET_REMOVE reorged out by a longer chain (both nodes disconnect it)')
        sidu, admit = self.create_set('U', seats=2, unlock_threshold=1, cancel_threshold=1, slash_threshold=1,
                                      maturity=1)
        u0, u1 = secrets('U-member', 2)
        self.join(sidu, u0, [admit], 'JOIN U u0')
        self.join(sidu, u1, [admit], 'JOIN U u1')
        self.mine(2)
        rm_hex = self.act_hex(v.act_set_remove(sidu, v.pubkey_of(u1), 0), [u0])
        z = self.mine_raw([rm_hex], 'block Z: REMOVE u1')
        self.reject(self.heartbeat_hex(sidu, u1), 'bad-vault-act-heartbeat', 'bad-vault-act-heartbeat',
                    'HEARTBEAT of the removed u1')
        self.node.invalidateblock(z)
        self.mine_raw([], 'fork block 1 (as long as Z: node 1 stays on Z)', sync=False)
        self.mine_raw([], 'fork block 2')
        assert_equal(self.nodes[1].getbestblockhash(), self.node.getbestblockhash())
        assert self.model.get_set(sidu).members[v.pubkey_of(u1)].status == v.MEMBER_ACTIVE
        hb = self.accept(self.heartbeat_hex(sidu, u1), 'HEARTBEAT of u1 on the fork')
        self.node.reconsiderblock(z)
        assert self.node.getbestblockhash() != z
        self.wait_in_mempool(hb, 1, 'node 1 (which disconnected Z by reorg) has the heartbeat')
        self.mine()

    # ------------------------------------------------------------------ J
    def probes(self, label):
        """State-dependent answers that differ if the set state is lost or stale."""
        sid, m = self.S, self.Sm
        self.reject(self.act_hex(v.act_set_winddown(self.W), self.Wm[:2]), 'bad-vault-act-winddown',
                    'bad-vault-act-winddown', '%s: WINDDOWN of W again' % label)
        # m0 co-signs its own admission (only m0 and m1 are current): the C++ counts co-signers
        # distinct among themselves and reaches the ACTIVE check; the model rejects the repeated
        # key first (A-7). Same verdict, different code; it cannot change a verdict, since a
        # current co-signer is ACTIVE and an ACTIVE key cannot join.
        self.reject(self.join_hex(sid, m[0], [m[0], m[1]])[0], 'bad-vault-act-join', 'bad-vault-act-sig',
                    '%s: JOIN of the ACTIVE m0' % label)
        self.reject(self.unlock_hex(self.probe_v, self.probe_vp, COIN, [(self.change_spk(), COIN)], [m[2], m[0]]),
                    SCRIPT_SETSIG, 'script-setsig', '%s: UNLOCK by the removed m2' % label)
        self.accept(self.unlock_hex(self.probe_v, self.probe_vp, COIN, [(self.change_spk(), COIN)], m[:2]),
                    '%s: UNLOCK by m0 + m1' % label)
        self.mine()
        self.probe_vp = self.vparams(sid)
        self.probe_v = self.lock(self.probe_vp, COIN, '%s: the next probe vault' % label)
        self.mine()

    def section_restart(self):
        print('J. restart reconciliation')
        sid, m = self.S, self.Sm
        self.probe_vp = self.vparams(sid)
        self.probe_v = self.lock(self.probe_vp, COIN, 'probe vault')
        self.mine()
        self.probes('before restarts')
        print('  clean restart')
        self.restart_node0()
        self.probes('after a clean restart')
        print('  SIGKILL right after a block with an act')
        self.heartbeat(sid, [m[0]], 'HEARTBEAT before SIGKILL')
        self.mine()
        self.restart_node0(kill=True)
        self.sync_model()
        self.probes('after SIGKILL')
        print('  <datadir>/vaults/ deleted: the state is rebuilt from the blocks')
        self.restart_node0(wipe_vaults=True)
        self.sync_model()
        self.probes('after deleting the vault DB')


if __name__ == '__main__':
    VaultPrimitiveTest().main()
