#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Seat ranking and eviction (owner 2026-10-11) on regtest: the attestor set is OPEN with 15 seats, a larger
bond joining the full set evicts the member of least seat weight, and the set never shrinks by vote.

1. Fifteen 10-YEC SET_JOINs (fresh keys, one per block) fill the set.
2. A 16th join at 10 YEC is refused (bad-vault-act-seats): the joiner's seat weight at age 0 does not
   exceed the least member's by EVICT_MARGIN (5 %).
3. An 11-YEC join is admitted and evicts the youngest 10-YEC member (least tenure factor): the primitive
   shows it `removed` with its bond not frozen; the module's record is WITHDRAWN with evicted = true;
   seatWeight in yed_listattestors matches the model's SeatWeight.
4. SET_REMOVE and SET_WINDDOWN naming the attestor set are refused by the mempool (attestor-set-act);
   members cannot vote one another out.
5. The bond exit delay (owner 2026-10-11): the evicted bond is refused at exit + BOND_MATURITY - 1
   (bad-vault-bond-locked) and spent at exit + BOND_MATURITY: the record stays WITHDRAWN (statusHeight kept).
6. A voluntary leaver (its own SET_REMOVE, signed by itself alone): WITHDRAWN at once, its bond on the same delay.
7. A leaver that equivocates during the delay is EJECTED and its bond frozen (bad-vault-bond-frozen for good).
8. The evicted key joins again with a new seq.
The enforcing nodes agree on the state hash and the Python model replays the chain.

Nodes: 0 user, 1 stock, 2-4 pools, 5 observer.
"""

from test_framework.util import assert_equal
from test_framework.yellowback_model import sha256, seat_weight
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
    sign_attestation,
    model_check,
    send_and_lock,
    withdraw_bond_raw,
)
from test_framework import vault as va

USER = 0


def assert_rpc_error(substr, fn, *args):
    try:
        fn(*args)
    except Exception as e:
        assert substr in str(e), 'expected %r in %r' % (substr, str(e))
        return str(e)
    raise AssertionError('expected an error containing %r' % substr)


# Rule: seat ranking and eviction (owner 2026-10-11)
class YellowbackAttestEvictTest(YellowbackTestFramework):

    initial_blocks = 101

    def records(self):
        return dict((int(r['seq']), r) for r in self.nodes[POOLS[0]].yed_listattestors())

    def members(self):
        info = self.nodes[USER].set_getinfo(attestor_set_internal()[::-1].hex())
        return dict((m['key'], m) for m in info['memberlist']), info

    def join_hex(self, secret, bond_zat):
        hex_, _lt = build_register_tx(self.nodes[USER], secret_to_pubkey(secret), None, bond_zat, BOND_MIN_LOCK, secret=secret)
        return hex_

    def join(self, secret, bond_zat):
        send_and_lock(self.nodes[USER], self.join_hex(secret, bond_zat))
        self.sync_all()
        self.mine(POOLS[0])

    def seq_of(self, secret):
        pub = secret_to_pubkey(secret).hex()
        found = [s for s, r in self.records().items() if r['attestorPubKey'] == pub]
        return found[-1]

    def run_test(self):
        user = self.nodes[USER]
        self.activate(POOLS)
        # The displacement is the YED module's (it governs the attestor set only where it is configured): on regtest
        # the set id is a node flag, so the stock node, which runs the vault upgrade without it, would refuse an
        # evicting join as into any full set (on mainnet the set id is compiled into every release). It gets the flag.
        self.restart(STOCK, ['-yellowbackattestorset=%s' % ATTESTOR_SET[0]])
        self.sync_all()
        print('funding: the user mines until it holds 300 YEC (sixteen bonds and a 50-YEC one)')
        while user.getbalance() < 300:
            self.mine(USER, 20)
        for node in self.enforcing_nodes():
            wait_yed_healthy(node)
            a = node.yed_getinfo()['params']['attest']
            assert_equal((a['seats'], a['seatAgeUnit'], a['seatAgeCap'], a['seatMarginBps'], a['evictMarginBps']),
                         (15, 1152, 420480, 500, 500))
        secrets = [sha256(b'yellowback-evict-%d' % i) for i in range(17)]

        print('1. fifteen 10-YEC joins fill the open set')
        for i in range(15):
            self.join(secrets[i], 10 * COIN)
        members, info = self.members()
        assert_equal((info['seats'], info['active']), (15, 15))
        seqs = [self.seq_of(secrets[i]) for i in range(15)]

        print('2. an equal bond cannot take a seat')
        assert_rpc_error('bad-vault-act-seats', user.sendrawtransaction, self.join_hex(secrets[15], 10 * COIN))

        print('3. 11 YEC evicts the youngest 10-YEC member')
        recs = self.records()
        h = user.getblockcount() + 1
        a = user.yed_getinfo()['params']['attest']
        youngest = max(range(15), key=lambda i: (recs[seqs[i]]['registerHeight'], i))
        self.join(secrets[15], 11 * COIN)
        assert_equal(user.getblockcount(), h)
        recs = self.records()
        v = recs[seqs[youngest]]
        assert_equal((v['status'], v['statusHeight'], v['evicted'], v['bondFrozen'], v['bondSpentHeight']),
                     ('WITHDRAWN', h, True, False, None))
        new_seq = self.seq_of(secrets[15])
        assert_equal((recs[new_seq]['status'], recs[new_seq]['evicted']), ('PENDING', False))
        for i in range(15):
            if i != youngest:
                assert recs[seqs[i]]['status'] != 'WITHDRAWN', i
        members, info = self.members()
        assert_equal(info['active'], 15)
        vm = members[secret_to_pubkey(secrets[youngest]).hex()]
        assert_equal((vm['status'], vm['bondfrozen']), ('removed', False))
        tip = user.getblockcount()
        trigger = int(user.yed_getinfo()['attest']['triggerHeight'] or 0)
        for s, r in recs.items():
            if r['status'] in ('PENDING', 'ELIGIBLE', 'DORMANT'):
                origin = trigger if r['founding'] else int(r['registerHeight'])     # ageOrigin (v3 section 3.7)
                assert_equal(int(r['seatWeight']), seat_weight(int(r['bondZat']), tip - origin, a['seatAgeUnit'], a['seatAgeCap']))

        print('4. SET_REMOVE and SET_WINDDOWN of the attestor set are refused')
        target = secret_to_pubkey(secrets[0])
        rm = build_act_raw(user, va.act_set_remove(attestor_set_internal(), target, 0), [secrets[1]])
        assert_rpc_error('attestor-set-act', user.sendrawtransaction, rm)
        rmb = build_act_raw(user, va.act_set_remove(attestor_set_internal(), target, 1), [secrets[1]])
        assert_rpc_error('attestor-set-act', user.sendrawtransaction, rmb)
        wd = build_act_raw(user, va.act_set_winddown(attestor_set_internal()), [secrets[1]])
        assert_rpc_error('attestor-set-act', user.sendrawtransaction, wd)

        print('5. the bond exit delay: the evicted bond is returned BOND_MATURITY after the eviction (not before)')
        spendable = h + BOND_MATURITY                  # exitHeight + the set's maturity (8 on regtest)
        while user.getblockcount() + 1 < spendable - 1:
            self.mine(POOLS[0])
        assert_equal(user.getblockcount() + 1, spendable - 1)
        assert_rpc_error('bad-vault-bond-locked', user.sendrawtransaction, withdraw_bond_raw(user, v, secrets[youngest]))
        self.mine(POOLS[0])
        user.sendrawtransaction(withdraw_bond_raw(user, v, secrets[youngest]))
        self.sync_all()
        self.mine(POOLS[0])
        r = self.records()[seqs[youngest]]
        assert_equal((r['status'], r['statusHeight'], r['bondSpentHeight'], r['evicted']), ('WITHDRAWN', h, user.getblockcount(), True))

        print('6. a voluntary leaver: its own SET_REMOVE; the bond is locked until exit + BOND_MATURITY')
        k = 1
        leave = build_act_raw(user, va.act_set_remove(attestor_set_internal(), secret_to_pubkey(secrets[k]), 0), [secrets[k]])
        user.sendrawtransaction(leave)
        self.sync_all()
        self.mine(POOLS[0])
        exit_k = user.getblockcount()
        rk = self.records()[seqs[k]]
        assert_equal((rk['status'], rk['statusHeight'], rk['evicted'], rk['bondFrozen']), ('WITHDRAWN', exit_k, False, False))
        assert_equal(self.members()[0][secret_to_pubkey(secrets[k]).hex()]['status'], 'removed')
        while user.getblockcount() + 1 < exit_k + BOND_MATURITY - 1:
            self.mine(POOLS[0])
        assert_equal(user.getblockcount() + 1, exit_k + BOND_MATURITY - 1)
        assert_rpc_error('bad-vault-bond-locked', user.sendrawtransaction, withdraw_bond_raw(user, rk, secrets[k]))
        self.mine(POOLS[0])
        user.sendrawtransaction(withdraw_bond_raw(user, rk, secrets[k]))
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(self.records()[seqs[k]]['bondSpentHeight'], user.getblockcount())

        print('7. a slash during the delay: a leaver that equivocates is EJECTED and its bond frozen for good')
        k = 2
        leave = build_act_raw(user, va.act_set_remove(attestor_set_internal(), secret_to_pubkey(secrets[k]), 0), [secrets[k]])
        user.sendrawtransaction(leave)
        self.sync_all()
        self.mine(POOLS[0])
        cited = user.getblockcount() - 2
        a1 = sign_attestation(secrets[k], seqs[k], 50000, cited, user.getblockhash(cited))
        a2 = sign_attestation(secrets[k], seqs[k], 51000, cited, user.getblockhash(cited))
        carrier = build_carrier_tx(user, encode_bundle([a1, a2]))
        self.sync_all()
        self.mine(POOLS[0])
        user.sendrawtransaction(equivocation_raw(user, carrier))
        self.sync_all()
        self.mine(POOLS[0])
        rk = self.records()[seqs[k]]
        assert_equal((rk['status'], rk['bondFrozen']), ('EJECTED', True))
        mk = self.members()[0][secret_to_pubkey(secrets[k]).hex()]
        assert_equal((mk['status'], mk['bondfrozen']), ('ejected', True))
        self.mine_round_robin(POOLS, BOND_MATURITY)
        assert_rpc_error('bad-vault-bond-frozen', user.sendrawtransaction, withdraw_bond_raw(user, rk, secrets[k]))

        print('8. the evicted key joins again with a new seq (the two departures left room: no eviction)')
        self.join(secrets[youngest], 50 * COIN)
        assert self.seq_of(secrets[youngest]) != seqs[youngest]
        assert_equal(self.members()[1]['active'], 14)

        assert_same_statehash(self.enforcing_nodes(), 'seats')
        model_check(self.nodes[POOLS[0]])


if __name__ == '__main__':
    YellowbackAttestEvictTest().main()
