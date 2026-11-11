#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
A YED token at an ECC (P2PKH) holder key is never spent as plain YEC by the stock coin-selecting paths (beta2 review
M1 and m2, security audit "ECC holder keys"). Before the Falcon height a mint or transfer puts YED on a P2PKH key, and
ANY_TADDR, an ECC from address, sendtoaddress and sendmany can select such a coin.

Yellowback goes live before Falcon; node 0 mints and sends a token to a fresh P2PKH holder key of node 1, whose wallet
then holds nothing else (so the token is the one coin every wildcard and stock path could take).

- Locks in place, and again after `lockunspent true` (the audit's experiment; it re-applies the Yellowback locks):
  z_sendmany from the key and from ANY_TADDR, z_mergetoaddress of the key, of ANY_TADDR and of
  [ANY_TADDR, ANY_SAPLING], sendtoaddress and sendmany all fail as from an empty wallet (their stock errors).
- The lock removed on purpose (yed_unlockcoin): each of those is refused by the second check, naming the outpoint
  ("refusing to spend a Yellowback outpoint as plain YEC: <txid>:<n> (its YED would burn; lock it again with
  yed_lockcoins)"), and so is vault_lock's fee funding (review L-3).
- The hint is the one that works (review M-1): `lockunspent true` does not lock a released token again (the
  refusal still fires); once the key also holds plain YEC, vault_lock funds its fee without the token; yed_lockcoins
  locks it again. The token output stays unspent and yed_getbalance never moves.

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/wallet_yed_ecc_token.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

import time
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    COINBASE_ONLY_TRANSPARENT_REFUSAL,
    EMPTY_ECC_SOURCE_REFUSAL,
    VAULT_BRANCH_ID,
    assert_equal,
    connect_nodes_bi,
    lockunspent_true,
    nuparams,
    start_nodes,
    z_mergetoaddress_call,
    z_sendmany_opid,
)
from test_framework.yellowback_util import activate_yed_late, mint_to_fresh_holder

ACTIVATION = 210        # the vault upgrade
FALCON = 1000           # -pqfalconheight: never reached here, so YED goes to P2PKH holder keys
YED_REFUSED = 'refusing to spend a Yellowback outpoint as plain YEC: '
YED_REFUSED_HINT = ' (its YED would burn; lock it again with yed_lockcoins)'
UNLOCK_ACK = 'I understand this burns YED'
TOKEN_VALUE = Decimal('0.0001')


def assert_raises_rpc(substr, fn, *args):
    try:
        fn(*args)
    except JSONRPCException as e:
        assert substr in e.error['message'], 'expected %r in %r' % (substr, e.error['message'])
        return e.error['message']
    raise AssertionError('expected an RPC error containing %r' % substr)


class WalletYedEccTokenTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 3
        self.setup_clean_chain = True

    def node_args(self, i):
        return [nuparams(VAULT_BRANCH_ID, ACTIVATION), '-pqfalconheight=%d' % FALCON] + getattr(self, 'yed_args', {}).get(i, [])

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 extra_args=[self.node_args(i) for i in range(self.num_nodes)])
        for a, b in ((0, 1), (1, 2), (0, 2)):
            connect_nodes_bi(self.nodes, a, b)
        self.is_network_split = False
        self.sync_all()

    def mine(self, n=1):
        self.sync_all()
        self.nodes[2].generate(n)
        self.sync_all()

    def zsend_fails(self, node, src, recipients, substr):
        opid = z_sendmany_opid(node, src, recipients, 1)
        for _ in range(300):
            r = node.z_getoperationresult([opid])
            if r:
                assert_equal(r[0]['status'], 'failed')
                assert substr in r[0]['error']['message'], (substr, r[0]['error']['message'])
                return
            time.sleep(1)
        raise AssertionError('timeout')

    def run_test(self):
        n0, n1, n2 = self.nodes
        n0.generate(ACTIVATION + 10)
        self.sync_all()
        setid = activate_yed_late(self, [0, 2], ((0, 1), (1, 2), (0, 2)))
        n0, n1, n2 = self.nodes
        assert n0.getblockcount() + 1 < FALCON
        mint_to_fresh_holder(self.nodes, 0, 2)
        n0.yed_send(n1.yed_getnewaddress('p2pkh'), 10000)
        self.mine(1)
        ys = n1.yed_listunspent()
        assert_equal(len(ys), 1)
        op = (ys[0]['txid'], ys[0]['vout'])
        key = n1.getrawtransaction(op[0], 1)['vout'][op[1]]['scriptPubKey']['addresses'][0]
        assert 'pqscheme' not in n1.validateaddress(key)                  # an ECC (P2PKH) holder key
        assert_equal(n1.listunspent(0), [])                               # nothing transparent but the locked token
        assert_equal(n1.z_listunspent(0), [])
        assert_equal(n1.getreceivedbyaddress(key, 0), TOKEN_VALUE)
        before = (n0.yed_getbalance()['confirmedCents'], n1.yed_getbalance()['confirmedCents'])
        back = n0.getnewaddress()
        sap = n1.z_getnewaddress('sapling')
        outpoint = {'txid': op[0], 'vout': op[1]}

        def every_path(sub_send, sub_any, sub_merge, sub_stock):
            self.zsend_fails(n1, key, [(sap, Decimal('0.00005'))], sub_send)
            self.zsend_fails(n1, 'ANY_TADDR', [(sap, Decimal('0.00005'))], sub_any)
            for w in ([key], ['ANY_TADDR'], ['ANY_TADDR', 'ANY_SAPLING']):
                assert_raises_rpc(sub_merge, z_mergetoaddress_call, n1, w, back)
            for m in (assert_raises_rpc(sub_stock, n1.sendtoaddress, back, Decimal('0.00001')),
                      assert_raises_rpc(sub_stock, n1.sendmany, '', {back: Decimal('0.00001')})):
                assert sub_stock or YED_REFUSED not in m, m

        for unlock_all in (False, True):
            print('ECC token: every path finds nothing (%s)' % ('after lockunspent true' if unlock_all else 'locks in place'))
            if unlock_all:
                lockunspent_true(n1)
            assert outpoint in n1.listlockunspent()
            every_path(EMPTY_ECC_SOURCE_REFUSAL,
                       COINBASE_ONLY_TRANSPARENT_REFUSAL, 'Could not find any funds to merge.',
                       '')                                    # sendtoaddress/sendmany: their stock insufficient-funds errors
            assert outpoint in n1.listlockunspent()

        print('ECC token, its lock removed on purpose: every path refuses it by name')
        r = n1.yed_unlockcoin(op[0], op[1], UNLOCK_ACK)
        assert_equal((r['wasYellowbackLocked'], r['cents']), (True, 10000))
        assert outpoint not in n1.listlockunspent()
        named = YED_REFUSED + '%s:%d' % op
        every_path(named, named, named, named)
        lock = {'tag': 'TEST', 'setid': setid, 'delay': 10, 'ownerheight': n1.getblockcount() + 1000,
                'amount': Decimal('0.5')}
        assert_raises_rpc(named, n1.vault_lock, lock)                    # review L-3: the vault RPCs' fee funding

        print('the refusal\'s hint (review M-1): lockunspent true does not lock a released token; yed_lockcoins does')
        msg = assert_raises_rpc(named, n1.sendtoaddress, back, Decimal('0.00001'))
        assert_equal(msg, named + YED_REFUSED_HINT)
        lockunspent_true(n1)
        assert outpoint not in n1.listlockunspent()
        assert_equal(assert_raises_rpc(named, n1.sendtoaddress, back, Decimal('0.00001')), named + YED_REFUSED_HINT)

        print('review L-3: with plain YEC beside it, vault_lock funds its fee without the released token')
        n0.sendtoaddress(n1.getnewaddress(), Decimal('2'))
        self.mine(1)
        n1.yed_unlockcoin(op[0], op[1], UNLOCK_ACK)                      # the block's Reconcile locked it again
        assert outpoint not in n1.listlockunspent()
        r = n1.vault_lock(lock)
        assert op not in [(i['txid'], i['vout']) for i in n1.getrawtransaction(r['txid'], 1)['vin']]
        assert outpoint not in n1.listlockunspent()
        self.mine(1)
        n1.yed_lockcoins()
        assert outpoint in n1.listlockunspent()
        assert_equal((n0.yed_getbalance()['confirmedCents'], n1.yed_getbalance()['confirmedCents']), before)
        assert_equal(n1.gettxout(op[0], op[1])['value'], TOKEN_VALUE)


if __name__ == '__main__':
    WalletYedEccTokenTest().main()
