#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Liveness by attestation, bounded (seats review B2 and its re-reviews, 2026-10-11) on regtest, from reviewer B's probe.
An attestation counts as liveness only inside a held YED act (a mint, a registered notice, a claim) whose bundle passes
the whole BUNDLE-1 -- yellowback_attest.py checks that credit on its bundled mints -- and only for a refHeight within
REF_WINDOW of the block. Here, with livenessWindow 20 and fifteen 10-YEC members that never heartbeat (all dead):
1. A CLAIM_NOTICE for a vault that does not exist, carrying a bundle that would pass the structural checks (seq 13 and
   14), is refused by every Yellowback mempool (liveness-unheld): a failing act credits nobody.
2. The same kind of notice at a refHeight older than REF_WINDOW credits nobody either (no replay of old public
   attestations): it is an ordinary, non-Yellowback transaction and both members stay dead.
3. A dust join (below bondMinFloorZat) into the full set is refused; a join at the floor evicts the dead member of
   least seat weight -- seq 14, the youngest -- in the primitive and the mirror alike.
The enforcing nodes agree on the state hash and the Python model replays the chain.

Nodes: 0 user, 1 stock (restarted with the attestor set: the module's hooks decide these blocks), 2-4 pools,
5 observer.
"""

from test_framework.authproxy import JSONRPCException
from test_framework.util import assert_equal
from test_framework.yellowback_model import sha256
import test_framework.yellowback_util as yu
from test_framework.yellowback_util import (
    ATTESTOR_SET,
    BOND_MATURITY,
    BOND_MIN_LOCK,
    COIN,
    POOLS,
    REF_WINDOW,
    STOCK,
    YellowbackTestFramework,
    assert_same_statehash,
    secret_to_pubkey,
    wait_yed_healthy,
)
from test_framework.yellowback_attest import (
    attestor_set_internal,
    build_carrier_tx,
    build_register_tx,
    encode_bundle,
    model_check,
    post_notice_raw,
    send_and_lock,
    sign_attestation,
)

USER = 0
LIVENESS = 20
BOGUS_VAULT = ('11' * 32, 0)
yu.ATTESTOR_SET_SPEC['livenesswindow'] = LIVENESS      # this run's attestor set: members lapse after 20 blocks


# Rule: seats review B2
class YellowbackAttestLiveTest(YellowbackTestFramework):

    initial_blocks = 101

    def records(self):
        return dict((int(r['seq']), r) for r in self.nodes[POOLS[0]].yed_listattestors())

    def members(self):
        info = self.nodes[USER].set_getinfo(attestor_set_internal()[::-1].hex())
        return dict((m['key'], m) for m in info['memberlist'])

    def join_hex(self, secret, bond_zat):
        return build_register_tx(self.nodes[USER], secret_to_pubkey(secret), None, bond_zat, BOND_MIN_LOCK, secret=secret)[0]

    def seq_of(self, secret):
        pub = secret_to_pubkey(secret).hex()
        return [s for s, r in self.records().items() if r['attestorPubKey'] == pub][-1]

    def notice(self, atts):
        """A CLAIM_NOTICE of a vault that does not exist, carrying ``atts``; mined; returns its refHeight."""
        user = self.nodes[USER]
        carrier = build_carrier_tx(user, encode_bundle(atts))
        self.sync_all()
        self.mine(POOLS[0])
        ref = user.getblockcount()
        user.sendrawtransaction(post_notice_raw(user, BOGUS_VAULT, ref, carrier))
        self.sync_all()
        self.mine(POOLS[0])
        return ref

    def last_acts(self, secret):
        pm = self.members()[secret_to_pubkey(secret).hex()]
        return pm['lastact'], self.records()[self.seq_of(secret)]['lastAct']

    def run_test(self):
        user = self.nodes[USER]
        self.activate(POOLS)
        self.restart(STOCK, ['-yellowbackattestorset=%s' % ATTESTOR_SET[0]])   # doc/yellowback.md "Regtest caveat"
        self.sync_all()
        while user.getbalance() < 220:
            self.mine(USER, 20)
        for node in self.enforcing_nodes():
            wait_yed_healthy(node)
        s = [sha256(b'attest-live-%d' % i) for i in range(17)]
        for i in range(15):
            send_and_lock(user, self.join_hex(s[i], 10 * COIN))
            self.sync_all()
            self.mine(POOLS[0])
        self.mine(POOLS[0], BOND_MATURITY + LIVENESS + 3)
        assert_equal(sum(1 for m in self.members().values() if m['live']), 0)
        seqs = [self.seq_of(s[i]) for i in range(15)]

        print('1. a failing CLAIM_NOTICE (no such vault) with a structurally passing bundle is refused: liveness-unheld')
        before13, before14 = self.last_acts(s[13]), self.last_acts(s[14])
        cited = user.getblockcount() - 1
        a13 = sign_attestation(s[13], seqs[13], 50000, cited, user.getblockhash(cited))
        a14 = sign_attestation(s[14], seqs[14], 50000, cited, user.getblockhash(cited))
        carrier = build_carrier_tx(user, encode_bundle([a13, a14]))
        self.sync_all()
        self.mine(POOLS[0])
        ref = user.getblockcount()
        try:
            user.sendrawtransaction(post_notice_raw(user, BOGUS_VAULT, ref, carrier))
            raise AssertionError('a failing notice that would credit liveness was accepted')
        except JSONRPCException as e:
            assert 'liveness-unheld' in e.error['message'], e.error
        self.mine(POOLS[0])
        assert_equal((self.last_acts(s[13]), self.last_acts(s[14])), (before13, before14))

        print('2. an attestation replayed at a refHeight older than REF_WINDOW credits nobody')
        old_ref = user.getblockcount() - REF_WINDOW - 1
        b13 = sign_attestation(s[13], seqs[13], 50000, old_ref, user.getblockhash(old_ref))
        b14 = sign_attestation(s[14], seqs[14], 50000, old_ref - 1, user.getblockhash(old_ref - 1))
        carrier = build_carrier_tx(user, encode_bundle([b13, b14]))
        self.sync_all()
        self.mine(POOLS[0])
        old_ref = user.getblockcount() - REF_WINDOW - 2                 # the notice's R: still older than REF_WINDOW
        user.sendrawtransaction(post_notice_raw(user, BOGUS_VAULT, old_ref + 1, carrier))
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal((self.last_acts(s[13]), self.last_acts(s[14])), (before13, before14))
        assert not self.members()[secret_to_pubkey(s[14]).hex()]['live']
        assert_same_statehash(self.enforcing_nodes(), 'after the replay')

        print('3. no dust eviction; a floor bond evicts the youngest dead member')
        floor = int(user.yed_getinfo()['params']['attest']['bondMinFloorZat'])
        try:
            user.sendrawtransaction(self.join_hex(s[15], floor - 1))
            raise AssertionError('a dust join into the full set was accepted')
        except JSONRPCException as e:
            assert 'bad-vault-act-seats' in e.error['message'] or 'attestor-bond-below-min' in e.error['message'], e.error
        send_and_lock(user, self.join_hex(s[15], floor))
        self.sync_all()
        self.mine(POOLS[0])
        members, recs = self.members(), self.records()
        removed = [i for i in range(15) if members[secret_to_pubkey(s[i]).hex()]['status'] != 'active']
        withdrawn = [i for i in range(15) if recs[seqs[i]]['status'] == 'WITHDRAWN']
        assert_equal(removed, [14])
        assert_equal(withdrawn, [14])
        assert_same_statehash(self.enforcing_nodes(), 'after the eviction')
        model_check(self.nodes[POOLS[0]])


if __name__ == '__main__':
    YellowbackAttestLiveTest().main()
