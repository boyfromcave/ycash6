#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
No slash escape through the bond exit delay (seats review B1, 2026-10-11) on regtest, the reviewer's probe as a test.

1. Three attestors join the attestor set (10 YEC) and mature.
2. Attestor k leaves by its own SET_REMOVE (set_leave's act): WITHDRAWN, its bond in the exit delay.
3. k joins again with the same key during the delay: refused (bad-vault-act-join -- one unspent bond per
   (set, key)), so the member record keeps naming the old bond.
4. Evidence that k equivocated (two prices for one cited block, under its old seq) is mined: the module ejects
   k's record and freezes its bond, and the primitive freezes the same (old) bond.
5. Past exit + BOND_MATURITY the old bond's withdrawal is refused (bad-vault-bond-frozen): the slash held.
6. Attestor j leaves, waits the exit delay, withdraws, and then rejoins with the same key (a new seq).
The enforcing nodes agree on the state hash and the Python model replays the chain.

Nodes: 0 user, 1 stock (restarted with the attestor set: the module's hooks decide these blocks), 2-4 pools,
5 observer.
"""

from test_framework.authproxy import JSONRPCException
from test_framework.util import assert_equal
from test_framework.yellowback_model import sha256
from test_framework.yellowback_util import (
    ATTESTOR_SET,
    BOND_MATURITY,
    BOND_MIN_LOCK,
    COIN,
    POOLS,
    STOCK,
    YellowbackTestFramework,
    assert_same_statehash,
    secret_to_pubkey,
    wait_yed_healthy,
)
from test_framework.yellowback_attest import (
    attestor_set_internal,
    build_act_raw,
    build_carrier_tx,
    build_register_tx,
    encode_bundle,
    equivocation_raw,
    model_check,
    send_and_lock,
    sign_attestation,
    withdraw_bond_raw,
)
from test_framework import vault as va

USER = 0


def assert_refused(substr, fn, *args):
    try:
        fn(*args)
    except JSONRPCException as e:
        assert substr in e.error['message'], 'expected %r in %r' % (substr, e.error['message'])
        return
    raise AssertionError('expected a refusal containing %r' % substr)


# Rule: seats review B1
class YellowbackAttestRejoinTest(YellowbackTestFramework):

    initial_blocks = 101

    def records(self):
        return dict((int(r['seq']), r) for r in self.nodes[POOLS[0]].yed_listattestors())

    def seqs_of(self, secret):
        pub = secret_to_pubkey(secret).hex()
        return sorted(s for s, r in self.records().items() if r['attestorPubKey'] == pub)

    def join_hex(self, secret, bond_zat):
        hex_, _lt = build_register_tx(self.nodes[USER], secret_to_pubkey(secret), None, bond_zat, BOND_MIN_LOCK, secret=secret)
        return hex_

    def join(self, secret, bond_zat):
        send_and_lock(self.nodes[USER], self.join_hex(secret, bond_zat))
        self.sync_all()
        self.mine(POOLS[0])

    def leave(self, secret):
        user = self.nodes[USER]
        user.sendrawtransaction(build_act_raw(user, va.act_set_remove(attestor_set_internal(), secret_to_pubkey(secret), 0), [secret]))
        self.sync_all()
        self.mine(POOLS[0])
        return user.getblockcount()

    def member(self, secret):
        info = self.nodes[USER].set_getinfo(attestor_set_internal()[::-1].hex())
        rows = [m for m in info['memberlist'] if m['key'] == secret_to_pubkey(secret).hex()]
        assert_equal(len(rows), 1)
        return rows[0]

    def run_test(self):
        user = self.nodes[USER]
        self.activate(POOLS)
        self.restart(STOCK, ['-yellowbackattestorset=%s' % ATTESTOR_SET[0]])   # doc/yellowback.md "Regtest caveat"
        self.sync_all()
        while user.getbalance() < 200:
            self.mine(USER, 20)
        for node in self.enforcing_nodes():
            wait_yed_healthy(node)

        print('1. three attestors join and mature')
        s = [sha256(b'rejoin-test-%d' % i) for i in range(3)]
        for i in range(3):
            self.join(s[i], 10 * COIN)
        self.mine(POOLS[0], BOND_MATURITY + 2)
        k, j = s[0], s[1]
        old = self.records()[self.seqs_of(k)[-1]]
        assert_equal(old['status'], 'ELIGIBLE')

        print('2. k leaves by its own SET_REMOVE')
        exit_h = self.leave(k)
        assert_equal(self.records()[old['seq']]['status'], 'WITHDRAWN')

        print('3. k cannot rejoin while its old bond is unspent (bad-vault-act-join)')
        assert_refused('bad-vault-act-join', user.sendrawtransaction, self.join_hex(k, 10 * COIN))
        assert_equal(self.seqs_of(k), [old['seq']])

        print('4. the evidence freezes the old bond')
        cited = user.getblockcount() - 2
        a1 = sign_attestation(k, old['seq'], 50000, cited, user.getblockhash(cited))
        a2 = sign_attestation(k, old['seq'], 51000, cited, user.getblockhash(cited))
        carrier = build_carrier_tx(user, encode_bundle([a1, a2]))
        self.sync_all()
        self.mine(POOLS[0])
        user.sendrawtransaction(equivocation_raw(user, carrier))
        self.sync_all()
        self.mine(POOLS[0])
        rec = self.records()[old['seq']]
        assert_equal((rec['status'], rec['bondFrozen']), ('EJECTED', True))

        print('5. past exit + BOND_MATURITY the old bond stays frozen')
        while user.getblockcount() < exit_h + BOND_MATURITY:
            self.mine(POOLS[0])
        assert_refused('bad-vault-bond-frozen', user.sendrawtransaction, withdraw_bond_raw(user, rec, k))

        print('6. j leaves, withdraws after the delay, and rejoins with a new seq')
        old_j = self.records()[self.seqs_of(j)[-1]]
        exit_j = self.leave(j)
        assert_refused('bad-vault-act-join', user.sendrawtransaction, self.join_hex(j, 10 * COIN))
        while user.getblockcount() + 1 < exit_j + BOND_MATURITY:
            self.mine(POOLS[0])
        assert_refused('bad-vault-bond-locked', user.sendrawtransaction, withdraw_bond_raw(user, old_j, j))
        self.mine(POOLS[0])
        user.sendrawtransaction(withdraw_bond_raw(user, old_j, j))
        self.sync_all()
        self.mine(POOLS[0])
        self.join(j, 10 * COIN)
        seqs = self.seqs_of(j)
        assert_equal(len(seqs), 2)
        assert_equal(self.records()[seqs[-1]]['status'], 'PENDING')
        assert_same_statehash(self.enforcing_nodes(), 'rejoin')
        model_check(self.nodes[POOLS[0]])


if __name__ == '__main__':
    YellowbackAttestRejoinTest().main()
