#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The wYEC bridge's Ycash side on the primitive alone (docs/plans/yellowback-upgrade-plan.md §4,
P3; §15.9 ``vault_bridge.py``), with raw transactions and both signer shapes of §4.2:

  A. guardians: 9 seats, 6 to unlock, 1 to cancel, 7 to slash; the vault's cancel set is the
     guardian set itself
  B. a single relayer (seats 1, unlock 1) with an OPEN, bonded challenger set as cancelSetId

For each shape: a lock is a ``WYEC``-tagged V with ``ownerHeight = lockHeight +
BRIDGE_MAX_AGE`` and ``appHeight = 0``, next to an OP_RETURN carrying the opaque 32-byte
destination (consensus never reads it); the intent is the set's UNLOCK, rate-limited per epoch
(nothing in the set's creation epoch, exactly the cap, not one zatoshi more); the release after
``delay`` is broadcast by a third party (U-15); a cancel by one canceller halts an intent; a
griefing canceller is removed by its set's slashThreshold with its bond returned (O-6); the owner
recovers on dormancy, on wind-down, and after BRIDGE_MAX_AGE.

Shape B also shows what the primitive does not offer: a relayer cannot be removed by the
challenger set (SET_REMOVE is per set; the relayer's set has no other member), so its slashing is
equivocation, after which its set is dormant and every owner recovers.

``WYEC`` is not a registered module tag (§15.7): every rule here is the primitive's. Built with
``test_framework/vault.py`` and stock RPCs; every answer is cross-checked against ``VaultModel``.

    ZCASHD=<ycashd> .venv/bin/python -u qa/rpc-tests/vault_bridge.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

from test_framework.util import assert_equal
from test_framework import vault as v
from test_framework.vault_harness import (
    COIN,
    MEMPOOL_BIP68,
    MEMPOOL_NONFINAL,
    SCRIPT_SETSIG,
    SCRIPT_VERIFY,
    VaultTestBase,
    secrets,
)

TAG = b'WYEC'
DELAY = 6
BRIDGE_MAX_AGE = 150          # a bridge constant (§4.1), not consensus: the wallet writes ownerHeight
RATE_BPS = 5000
W = 30                        # rateWindow
USER = v.fixed_secret('bridge-user')
USER_KEY = v.pubkey_of(USER)


def eth_destination(label):
    """An Ethereum address as ABI bytes32: 12 zero bytes, then the 20-byte address."""
    return b'\x00' * 12 + v.sha256(label.encode())[:20]


class VaultBridgeTest(VaultTestBase):

    def run_test(self):
        self.start_vault()
        self.node.sendtoaddress(self.nodes[1].getnewaddress(), 10)
        self.mine()
        self.shape_guardians()
        self.shape_relayer()
        self.sync_all()
        print('vault_bridge OK')

    # ------------------------------------------------------------------ helpers

    def bridge_lock(self, sid, csid, amount, label, dest_label='user'):
        lock_h = self.tip() + 1
        vp = v.VaultParams(TAG, sid, csid, DELAY, lock_h + BRIDGE_MAX_AGE, 0, USER_KEY)
        dest = eth_destination(dest_label)
        out = self.lock(vp, amount, label, extra_vout=[(0, bytes([v.OP_RETURN]) + v.push(dest))])
        return vp, out, dest

    def cap_left(self, sid):
        """The value the set may still unlock at tip + 1 (U-20 roll, A-6)."""
        s = self.model.get_set(sid)
        h = self.tip() + 1
        basis, used = (s.epoch_basis, s.epoch_used) if h // W == s.epoch else (s.locked_value, 0)
        return basis * s.p['rateLimitBps'] // 10000 - used

    def next_epoch(self):
        self.mine_to((self.tip() + 1) // W * W + W - 1)      # tip + 1 = the next epoch's first height
        assert (self.tip() + 1) % W == 0

    def refresh(self, sid, secret, margin=12):
        """Keep ``sid`` live: heartbeat ``secret`` if its live window ends within ``margin``."""
        s = self.model.get_set(sid)
        m = s.members[v.pubkey_of(secret)]
        if m.last_act + s.p['livenessWindow'] < self.tip() + 1 + margin:
            self.accept(self.heartbeat_hex(sid, secret), 'HEARTBEAT (liveness)')
            self.mine()

    def advance_to(self, h, sid, secret):
        """Mine to height ``h`` keeping ``sid`` live with heartbeats by ``secret``."""
        while self.tip() < h:
            if self.tip() < h - 1:
                self.refresh(sid, secret)
            self.mine(min(8, h - self.tip()))

    def release_third_party(self, iout, ip, value, rspk, label):
        """The release, its fee paid and signed by node 1's wallet (anyone may release, U-15)."""
        n1 = self.nodes[1]
        vin, total = v.node_funding(n1, v.VAULT_FEE)
        change = (total - v.VAULT_FEE, v.node_spk(n1)) if total > v.VAULT_FEE else None
        tx = v.build_release_tx(iout, ip, value, rspk, vin, change)
        return self.accept(v.node_sign(n1, tx, tx.vin[0].scriptSig), label)

    def common_lock_checks(self, sid, csid):
        """The destination is opaque, but an OP_RETURN starting "YV" is an act (§15.5)."""
        vp = v.VaultParams(TAG, sid, csid, DELAY, self.tip() + 1 + BRIDGE_MAX_AGE, 0, USER_KEY)
        yv = b'YV' + b'\xab' * 30
        self.reject(self.lock_hex(vp, COIN, extra_vout=[(0, bytes([v.OP_RETURN]) + v.push(yv))]),
                    'bad-vault-act-version', 'bad-vault-act-version',
                    'a lock whose 32-byte destination begins "YV" (parsed as an act)')

    # ------------------------------------------------------------------ A
    def shape_guardians(self):
        print('A. 9 / 6 / 7 guardians')
        self.mine_to((self.tip() // W + 1) * W)
        G, gadmit = self.create_set('G', mine=False, seats=9, unlock_threshold=6, cancel_threshold=1,
                                    slash_threshold=7, rate_limit_bps=RATE_BPS, rate_window=W, liveness_window=40,
                                    maturity=2, bond_lock_min=10)
        G2, g2admit = self.create_set('G2', seats=9, unlock_threshold=6, cancel_threshold=1, slash_threshold=7,
                                      liveness_window=15, maturity=2)
        g = secrets('guardian', 9)
        g2 = secrets('guardian2', 9)
        bonds = [self.join(G, s, [gadmit], 'JOIN guardian %d' % i) for i, s in enumerate(g)]
        for i, s in enumerate(g2):
            self.join(G2, s, [g2admit], 'JOIN G2 guardian %d' % i)
        self.mine(3)
        assert_equal(self.info(G)['current'], 9)

        print('  lock (WYEC, opaque destination), nothing unlocks in the creation epoch')
        self.common_lock_checks(G, G)
        vp, v1, dest = self.bridge_lock(G, G, 20 * COIN, 'lock 20 YEC to an Ethereum address')
        vp2, v2, _ = self.bridge_lock(G, G, 5 * COIN, 'lock 5 YEC (recovered after BRIDGE_MAX_AGE)', 'user2')
        self.mine()
        lt = self.node.getrawtransaction(v1[0], 1)
        assert_equal(lt['vout'][1]['scriptPubKey']['type'], 'nulldata')
        assert dest.hex() in lt['vout'][1]['scriptPubKey']['hex']
        assert_equal(lt['vout'][0]['scriptPubKey']['type'], 'vault')
        r = self.change_spk()
        assert_equal(self.cap_left(G), 0)
        self.reject(self.unlock_hex(v1, vp, 20 * COIN, [(r, COIN)], g[:6], relock=19 * COIN), 'bad-txns-vault-rate',
                    'bad-vault-rate', 'intent in the set\'s creation epoch')

        print('  G2: an outstanding intent, then the guardians fall silent: the owner recovers')
        self.accept(self.heartbeat_hex(G2, g2[0]), 'HEARTBEAT G2')
        vq = v.VaultParams(TAG, G2, G2, 200, self.tip() + 1 + BRIDGE_MAX_AGE, 0, USER_KEY)
        q = self.lock(vq, 4 * COIN, 'lock 4 YEC under G2', extra_vout=[(0, bytes([v.OP_RETURN]) + v.push(dest))])
        self.mine()
        iq = v.intent_for(vq, r)
        u = self.accept(self.unlock_hex(q, vq, 4 * COIN, [(r, 2 * COIN)], g2[:6], relock=2 * COIN),
                        'G2 intent 2 YEC (delay 200) + re-lock 2')
        self.mine()
        qv_spk, qi_spk = v.vault_script(vq), v.intent_script(iq)
        self.reject(self.owner_hex((u, 1), qv_spk, 2 * COIN, v.SEL_OWNER_RELEASED, secret=USER), SCRIPT_VERIFY,
                    'script-notreleased', 'owner recovery while G2 is live')
        s = self.model.get_set(G2)
        live_until = max(m.last_act for m in s.members.values()) + s.p['livenessWindow']
        self.mine_to(live_until)
        assert self.dormant(G2)
        self.accept(self.owner_hex((u, 1), qv_spk, 2 * COIN, v.SEL_OWNER_RELEASED, secret=USER),
                    'owner recovers the vault of a dormant guardian set')
        self.accept(self.owner_hex((u, 0), qi_spk, 2 * COIN, v.SEL_OWNER_RELEASED, secret=USER),
                    'owner recovers the outstanding intent (I-3)')
        self.mine()

        print('  intents under the rate limit; release by a third party; a one-guardian halt')
        self.refresh(G, g[0])
        if (self.tip() + 1) // W == self.model.get_set(G).epoch:
            self.next_epoch()
        cap = self.cap_left(G)
        assert_equal(cap, 25 * COIN * RATE_BPS // 10000)
        ra, rb = self.change_spk(), self.change_spk()
        self.reject(self.unlock_hex(v1, vp, 20 * COIN, [(ra, 10 * COIN)], g[:5], relock=10 * COIN), SCRIPT_SETSIG,
                    'script-setsig', 'intent with 5 of 6 guardian signatures')
        ua = self.accept(self.unlock_hex(v1, vp, 20 * COIN, [(ra, 10 * COIN)], g[:6], relock=10 * COIN),
                         'intent 10 YEC by 6 guardians (+ re-lock 10)')
        self.mine()
        c = self.tip()
        rest = self.cap_left(G)
        self.reject(self.unlock_hex((ua, 1), vp, 10 * COIN, [(rb, rest + 1)], g[3:9], relock=10 * COIN - rest - 1),
                    'bad-txns-vault-rate', 'bad-vault-rate', 'a second intent 1 zat over the epoch\'s cap')
        ub = self.accept(self.unlock_hex((ua, 1), vp, 10 * COIN, [(rb, rest)], g[3:9], relock=10 * COIN - rest),
                         'a second intent of exactly the rest of the cap')
        self.mine()
        ipa, ipb = v.intent_for(vp, ra), v.intent_for(vp, rb)
        self.reject(self.release_hex((ua, 0), ipa, 10 * COIN, ra), MEMPOOL_BIP68, 'bad-txns-vault-timelock',
                    'release before delay')
        halt = self.accept(self.cancel_hex((ub, 0), ipb, rest, vp, [g[8]]), 'one guardian halts the second intent')
        self.mine_to(c + DELAY - 1)
        self.release_third_party((ua, 0), ipa, 10 * COIN, ra, 'release after delay, broadcast by a third party')
        self.mine()

        print('  griefer: a guardian cancels a legitimate intent; 7 remove it, bond returned')
        self.refresh(G, g[0])
        self.next_epoch()
        cap = self.cap_left(G)
        assert cap >= rest, (cap, rest)
        rg, rd = self.change_spk(), self.change_spk()
        ug = self.accept(self.unlock_hex((halt, 0), vp, rest, [(rg, rest)], g[:6]),
                         'intent of the halted value again')
        relocked = 10 * COIN - rest
        part = min(cap - rest, relocked)
        ud = self.accept(self.unlock_hex((ub, 1), vp, relocked, [(rd, part)], g[:6], relock=relocked - part),
                         'intent of the rest of the new epoch\'s cap')
        self.mine()
        assert_equal(self.cap_left(G), 0)
        ipg, ipd = v.intent_for(vp, rg), v.intent_for(vp, rd)
        self.accept(self.cancel_hex((ug, 0), ipg, rest, vp, [g[8]]), 'guardian 8 cancels a legitimate intent')
        self.mine()
        self.reject(self.act_hex(v.act_set_remove(G, v.pubkey_of(g[8]), 0), g[:6]), 'bad-vault-act-sigs',
                    'bad-vault-act-sig', 'removal with 6 of 7 signatures')
        self.accept(self.act_hex(v.act_set_remove(G, v.pubkey_of(g[8]), 0), g[:7]),
                    'SET_REMOVE guardian 8 by 7 (burn 0: bond returned, O-6)')
        self.mine()
        self.reject(self.cancel_hex((ud, 0), ipd, part, vp, [g[8]]), SCRIPT_SETSIG, 'script-setsig',
                    'the removed guardian cannot cancel any more')
        self.advance_to(max(self.tip(), bonds[8]['locktime']), G, g[0])
        self.accept(self.bond_spend_hex(bonds[8]), 'the removed guardian\'s bond is returned at its locktime')
        self.mine_to(self.tip() + DELAY)
        self.accept(self.release_hex((ud, 0), ipd, part, rd), 'release of the intent the griefer could not stop')
        self.mine()

        print('  owner recovery after BRIDGE_MAX_AGE (ownerHeight = lockHeight + BRIDGE_MAX_AGE)')
        oh, spk2 = vp2.owner_height, v.vault_script(vp2)
        assert self.tip() + 1 <= oh, (self.tip(), oh)
        self.advance_to(oh - 1, G, g[0])
        self.reject(self.owner_hex(v2, spk2, 5 * COIN, v.SEL_OWNER, lock_time=oh, secret=USER), MEMPOOL_NONFINAL,
                    'bad-txns-nonfinal', 'owner spend at ownerHeight')
        self.mine()
        assert not self.released(G)
        self.accept(self.owner_hex(v2, spk2, 5 * COIN, v.SEL_OWNER, lock_time=oh, secret=USER),
                    'owner recovers a lock older than BRIDGE_MAX_AGE (guardians live)')
        self.mine()

        print('  wind-down: the owner branch opens livenessWindow blocks later')
        assert relocked - part > 0, 'the amounts leave a re-locked vault for the wind-down case'
        vrest, vval = (ud, 1), relocked - part
        self.accept(self.act_hex(v.act_set_winddown(G), g[:7]), 'SET_WINDDOWN by 7 guardians')
        self.accept(self.heartbeat_hex(G, g[0]), 'HEARTBEAT in the wind-down block')
        self.mine()
        wd, L = self.tip(), self.model.get_set(G).p['livenessWindow']
        vspk = v.vault_script(vp)
        self.mine_to(wd + L - 2)
        self.reject(self.owner_hex(vrest, vspk, vval, v.SEL_OWNER_RELEASED, secret=USER), SCRIPT_VERIFY,
                    'script-notreleased', 'owner recovery one block before windDownHeight + livenessWindow')
        self.mine()
        assert self.released(G) and not self.dormant(G)
        self.accept(self.owner_hex(vrest, vspk, vval, v.SEL_OWNER_RELEASED, secret=USER),
                    'owner recovers after the wind-down')
        self.mine()

    # ------------------------------------------------------------------ B
    def shape_relayer(self):
        print('B. a single relayer with an OPEN challenger set')
        self.mine_to((self.tip() // W + 1) * W)
        RL, rladmit = self.create_set('RL', mine=False, seats=1, unlock_threshold=1, cancel_threshold=1,
                                      slash_threshold=1, rate_limit_bps=RATE_BPS, rate_window=W, liveness_window=40,
                                      maturity=2, bond_min=20 * COIN, bond_lock_min=10)
        CH, chadmit = self.create_set('CH', mine=False, flags=v.SET_FLAG_OPEN, seats=5, unlock_threshold=1,
                                      cancel_threshold=1, slash_threshold=3, maturity=2, bond_lock_min=10)
        RL2, rl2admit = self.create_set('RL2', seats=1, unlock_threshold=1, cancel_threshold=1, slash_threshold=1,
                                        liveness_window=15, maturity=2, bond_min=5 * COIN)
        rl, rl2 = v.fixed_secret('relayer'), v.fixed_secret('relayer2')
        ch = secrets('challenger', 5)
        self.reject(self.join_hex(RL, rl, [rladmit], bond=20 * COIN - 1)[0], 'bad-vault-act-bond', 'bad-vault-act-bond',
                    'relayer bond below bondMin (20 YEC)')
        rl_bond = self.join(RL, rl, [rladmit], 'JOIN the relayer (20 YEC bond, admitKey)', bond=20 * COIN)
        self.join(RL2, rl2, [rl2admit], 'JOIN relayer 2', bond=5 * COIN)
        self.reject(self.join_hex(CH, ch[0], [chadmit])[0], 'bad-vault-act-sigs', 'bad-vault-act-sig',
                    'OPEN set: a JOIN carrying an admission signature')
        chb = [self.join(CH, s, [], 'JOIN challenger %d (OPEN: S_1 only)' % i) for i, s in enumerate(ch)]
        self.mine(3)
        self.reject(self.join_hex(RL, v.fixed_secret('relayer-b'), [rl], bond=20 * COIN)[0], 'bad-vault-act-seats',
                    'bad-vault-act-join', 'a second relayer (seats 1)')

        print('  lock under the relayer, challengers as cancelSetId')
        self.common_lock_checks(RL, CH)
        vp, v1, _ = self.bridge_lock(RL, CH, 20 * COIN, 'lock 20 YEC (set RL, cancel set CH)')
        vp2, v2, _ = self.bridge_lock(RL, CH, 5 * COIN, 'lock 5 YEC (BRIDGE_MAX_AGE)', 'user2')
        self.mine()
        r = self.change_spk()
        self.reject(self.unlock_hex(v1, vp, 20 * COIN, [(r, COIN)], [rl], relock=19 * COIN), 'bad-txns-vault-rate',
                    'bad-vault-rate', 'intent in the creation epoch')
        self.next_epoch()
        assert_equal(self.cap_left(RL), 25 * COIN * RATE_BPS // 10000)
        ra, rb = self.change_spk(), self.change_spk()
        self.reject(self.unlock_hex(v1, vp, 20 * COIN, [(ra, 8 * COIN)], [ch[0]], relock=12 * COIN), SCRIPT_SETSIG,
                    'script-setsig', 'a challenger cannot unlock')
        ua = self.accept(self.unlock_hex(v1, vp, 20 * COIN, [(ra, 8 * COIN)], [rl], relock=12 * COIN),
                         'intent 8 YEC by the relayer alone')
        self.mine()
        c = self.tip()
        rest = self.cap_left(RL)
        self.reject(self.unlock_hex((ua, 1), vp, 12 * COIN, [(rb, rest + 1)], [rl], relock=12 * COIN - rest - 1),
                    'bad-txns-vault-rate', 'bad-vault-rate', 'intent 1 zat over the cap')
        ub = self.accept(self.unlock_hex((ua, 1), vp, 12 * COIN, [(rb, rest)], [rl], relock=12 * COIN - rest),
                         'intent of exactly the rest of the cap')
        self.mine()
        ipa, ipb = v.intent_for(vp, ra), v.intent_for(vp, rb)
        self.reject(self.cancel_hex((ub, 0), ipb, rest, vp, [rl]), SCRIPT_SETSIG, 'script-setsig',
                    'the relayer cannot cancel (not in the challenger set)')
        halt = self.accept(self.cancel_hex((ub, 0), ipb, rest, vp, [ch[1]]), 'one challenger halts an intent')
        self.mine_to(c + DELAY - 1)
        self.release_third_party((ua, 0), ipa, 8 * COIN, ra, 'release after delay by a third party')
        self.mine()

        print('  griefer: a challenger cancels a legitimate intent; the challenger majority removes it')
        self.refresh(RL, rl)
        self.next_epoch()
        rg = self.change_spk()
        ug = self.accept(self.unlock_hex((halt, 0), vp, rest, [(rg, rest)], [rl]), 'intent of the halted value again')
        self.mine()
        ipg = v.intent_for(vp, rg)
        grief = self.accept(self.cancel_hex((ug, 0), ipg, rest, vp, [ch[4]]), 'challenger 4 cancels it (grief)')
        self.mine()
        self.accept(self.act_hex(v.act_set_remove(CH, v.pubkey_of(ch[4]), 0), ch[:3]),
                    'SET_REMOVE challenger 4 by 3 challengers (burn 0)')
        self.reject(self.act_hex(v.act_set_remove(RL, v.pubkey_of(rl), 1), ch[:3]), 'bad-vault-act-sigs',
                    'bad-vault-act-sig', 'challengers cannot remove the relayer (SET_REMOVE is per set)')
        self.mine()
        self.mine_to(max(self.tip(), chb[4]['locktime']))
        self.accept(self.bond_spend_hex(chb[4]), 'the removed challenger\'s bond is returned')
        self.mine()

        print('  the relayer equivocates: ejected, bond frozen, its set dormant, owners recover')
        self.refresh(RL, rl)
        if self.cap_left(RL) <= 0:
            self.next_epoch()
        vback = (grief, 0)                 # the griefer's cancel re-created the V at its output 0
        vspk = v.vault_script(vp)
        ro, rx = self.change_spk(), self.change_spk()
        amt = min(self.cap_left(RL), rest) // 2
        tx_a = self.unlock_tx(vback, vp, rest, [(ro, amt)], rest - amt)
        tx_b = self.unlock_tx(vback, vp, rest, [(rx, amt)], rest - amt)
        ha = self.setsig_hex(tx_a, vspk, rest, RL, v.ROLE_UNLOCK, [rl], v.SEL_UNLOCK)
        hb = self.setsig_hex(tx_b, vspk, rest, RL, v.ROLE_UNLOCK, [rl], v.SEL_UNLOCK)
        uo = self.accept(ha, 'the relayer\'s intent (outstanding)')
        self.mine()
        ipo = v.intent_for(vp, ro)
        ipo_spk = v.intent_script(ipo)
        self.reject(self.owner_hex((uo, 0), ipo_spk, amt, v.SEL_OWNER_RELEASED, secret=USER), SCRIPT_VERIFY,
                    'script-notreleased', 'owner recovery while the relayer is live')
        sig_a = v.push_values(v.tx_from_hex(ha).vin[0].scriptSig)[0]
        sig_b = v.push_values(v.tx_from_hex(hb).vin[0].scriptSig)[0]
        sh_a = v.template_sighash(tx_a, 0, vspk, rest)
        sh_b = v.template_sighash(tx_b, 0, vspk, rest)
        po = v.ser_prevout(vback[0], vback[1])
        self.accept(self.act_hex(v.act_set_equivocation(RL, po, 1, sh_a, sig_a, 1, sh_b, sig_b)),
                    'SET_EQUIVOCATION of the relayer, from its two signatures on one outpoint')
        self.mine()
        assert self.released(RL)
        self.accept(self.owner_hex((uo, 0), ipo_spk, amt, v.SEL_OWNER_RELEASED, secret=USER),
                    'owner recovers the outstanding intent')
        self.accept(self.owner_hex((uo, 1), vspk, rest - amt, v.SEL_OWNER_RELEASED, secret=USER),
                    'owner recovers the re-locked vault')
        self.mine()
        self.mine_to(max(self.tip(), rl_bond['locktime']))
        self.reject(self.bond_spend_hex(rl_bond), 'bad-vault-bond-frozen', 'bad-vault-bond-frozen',
                    'the equivocating relayer\'s bond stays frozen')

        print('  owner recovery after BRIDGE_MAX_AGE')
        oh, spk2 = vp2.owner_height, v.vault_script(vp2)
        if self.tip() + 1 <= oh:
            self.mine_to(oh - 1)
            self.reject(self.owner_hex(v2, spk2, 5 * COIN, v.SEL_OWNER, lock_time=oh, secret=USER), MEMPOOL_NONFINAL,
                        'bad-txns-nonfinal', 'owner spend at ownerHeight')
            self.mine()
        self.accept(self.owner_hex(v2, spk2, 5 * COIN, v.SEL_OWNER, lock_time=oh, secret=USER),
                    'owner recovers a lock older than BRIDGE_MAX_AGE')
        self.mine()

        print('  wind-down of a second relayer set')
        vw, w1, _ = self.bridge_lock(RL2, CH, 3 * COIN, 'lock 3 YEC under relayer 2')
        self.mine()
        self.accept(self.act_hex(v.act_set_winddown(RL2), [rl2]), 'SET_WINDDOWN by relayer 2')
        self.accept(self.heartbeat_hex(RL2, rl2), 'HEARTBEAT in the wind-down block')
        self.mine()
        wd, L = self.tip(), self.model.get_set(RL2).p['livenessWindow']
        wspk = v.vault_script(vw)
        self.mine_to(wd + L - 2)
        self.reject(self.owner_hex(w1, wspk, 3 * COIN, v.SEL_OWNER_RELEASED, secret=USER), SCRIPT_VERIFY,
                    'script-notreleased', 'owner recovery one block before windDownHeight + livenessWindow')
        self.mine()
        assert self.released(RL2) and not self.dormant(RL2)
        self.accept(self.owner_hex(w1, wspk, 3 * COIN, v.SEL_OWNER_RELEASED, secret=USER),
                    'owner recovers after the wind-down')
        self.mine()


if __name__ == '__main__':
    VaultBridgeTest().main()
