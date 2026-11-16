#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
A post-quantum z_sendmany keeps the coins it selected locked until it ends (beta3 review S-1).

A post-quantum send selects its coins, then builds and signs them (an SLH-DSA input takes about a third of a second)
and only then broadcasts. ycash6's WalletTxBuilder::PreparePQTransaction locks the coins it selects before it lets
go of the wallet lock and the operation unlocks them after the broadcast or on any failure; ycash-dd's
select_pq_inputs did not, so a spend that selects coins while the operation was signing (z_mergetoaddress selects
in the RPC itself; vault_lock from a post-quantum address too) took the same coins and failed only at its
broadcast. The async queue runs one operation at a time, so two z_sendmany never overlap; a synchronous selection
during the signing does. Now, on both lines:

  1. while a 24-input SLH-DSA send is signing, listlockunspent shows exactly the coins it then spends, and
     z_mergetoaddress of the same address is refused at once ("Could not find any funds to merge."), never at
     its broadcast; the send succeeds and the recipient is paid once;
  2. a second z_sendmany queued right behind it from the same address fails cleanly with the wallet's
     insufficient-funds error (code -6);
  3. after every operation, the failed one included, no coin stays locked (listlockunspent is empty);
     wallet_pq_fee_cap.py checks the same after a send the mempool refuses at the commit.

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/wallet_pq_sendmany_lock.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>

One file on both C++ lines (ycash-dd: BITCOIND=, ycash6: ZCASHD=).
"""

import time
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID,
    assert_equal,
    connect_nodes_bi,
    nuparams,
    start_nodes,
    z_mergetoaddress_call,
    z_sendmany_opid,
)

ACTIVATION = 210
NCOINS = 24                       # about 8 s of SLH-DSA signing: the window the checks below run in
RPC_WALLET_INSUFFICIENT_FUNDS = -6
NO_COIN_REFUSAL = 'Insufficient transparent funds, no UTXOs found for taddr from address.'
NO_MERGE_REFUSAL = 'Could not find any funds to merge.'


class WalletPQSendmanyLockTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 extra_args=[[nuparams(VAULT_BRANCH_ID, ACTIVATION)]] * self.num_nodes)
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def mine(self, n=1):
        self.sync_all()
        self.nodes[1].generate(n)
        self.sync_all()

    def results(self, node, opids):
        """The operations' results, once all have finished, in the order of opids."""
        for _ in range(1500):
            for r in node.z_getoperationresult(opids):              # removes them from the queue
                self.done[r['id']] = r
            if all(o in self.done for o in opids):
                return [self.done[o] for o in opids]
            time.sleep(0.2)
        raise AssertionError('the operations did not finish: %s' % opids)

    def status(self, node, opid):
        s = node.z_getoperationstatus([opid])
        return s[0]['status'] if s else 'finished'

    @staticmethod
    def spent(node, txid):
        """The outpoints a wallet transaction spends."""
        return sorted((i['txid'], i['vout']) for i in node.decoderawtransaction(node.gettransaction(txid)['hex'])['vin'])

    @staticmethod
    def locked(node):
        return sorted((o['txid'], o['vout']) for o in node.listlockunspent())

    def run_test(self):
        n0, n1 = self.nodes
        self.done = {}
        n0.generate(ACTIVATION + 10)
        self.sync_all()
        assert_equal(n0.listlockunspent(), [])

        slh = n0.getnewaddress('', 'pqslh')
        for _ in range(NCOINS):
            n0.sendtoaddress(slh, Decimal('0.1'))
        self.mine(1)
        coins = sorted((u['txid'], u['vout']) for u in n0.listunspent(1, 9999, [slh]))
        assert_equal(len(coins), NCOINS)
        b = n1.getnewaddress()
        amount = Decimal('0.1') * (NCOINS - 1)             # needs every coin

        print('a %d-input SLH-DSA send, and right behind it a second send from the same address' % NCOINS)
        first = z_sendmany_opid(n0, slh, [(b, amount)])
        second = z_sendmany_opid(n0, slh, [(b, Decimal('0.1'))])
        seen, merge_refusal = [], None
        while self.status(n0, first) in ('queued', 'executing'):
            held = self.locked(n0)
            if held and not seen:
                seen = held
                print('  while it signs, %d coins are locked; z_mergetoaddress of the address:' % len(held))
                try:
                    z_mergetoaddress_call(n0, [slh], n1.getnewaddress())
                    merge_refusal = 'not refused'
                except JSONRPCException as e:
                    merge_refusal = e.error['message']
                print('    %s' % merge_refusal)
                assert_equal([u for u in n0.listunspent(1, 9999, [slh])], [])   # locked coins are not offered
            time.sleep(0.05)
        r1, r2 = self.results(n0, [first, second])
        assert_equal(r1['status'], 'success')
        assert_equal(self.spent(n0, r1['result']['txid']), coins)
        assert_equal(seen, coins)                          # locked: exactly the coins the send spent
        assert NO_MERGE_REFUSAL in merge_refusal, merge_refusal
        assert_equal(r2['status'], 'failed')
        assert_equal(r2['error']['code'], RPC_WALLET_INSUFFICIENT_FUNDS)
        assert NO_COIN_REFUSAL in r2['error']['message'], r2['error']['message']
        print('  the second send: %s' % r2['error']['message'])
        assert_equal(n0.listlockunspent(), [])             # nothing left locked, the failed operation included
        self.mine(1)
        assert_equal(n1.getreceivedbyaddress(b, 1), amount)   # paid once

        print('a send refused at selection locks nothing')
        empty = n0.getnewaddress('', 'pqslh')
        (r,) = self.results(n0, [z_sendmany_opid(n0, empty, [(b, Decimal('0.1'))])])
        assert_equal(r['status'], 'failed')
        assert NO_COIN_REFUSAL in r['error']['message'], r['error']['message']
        assert_equal(n0.listlockunspent(), [])


if __name__ == '__main__':
    WalletPQSendmanyLockTest().main()
