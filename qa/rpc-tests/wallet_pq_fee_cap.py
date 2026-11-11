#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
A post-quantum send whose fee the commit refuses never comes back (beta2 security audit H1).

The wallet commits a transaction with a post-quantum input without the -maxtxfee absurd-fee check only within
PQMaxTxFee() (with no attested price: -maxtxfee, 0.1 YEC), while a restart re-accepts the wallet's own transactions
under the absolute ceiling (-yellowbackmaxtxfee, 10 YEC). Before the fix, z_sendmany from an SLH-DSA address with an
explicit fee of 0.2 failed at the commit ("CommitTransaction failed") but stayed in the wallet at depth -1; the user
sent again from other funds and the restart broadcast the first send too: the recipient was paid twice.

Now: z_sendmany and z_mergetoaddress refuse an explicit fee above the cap up front, nothing is recorded, and a
restart broadcasts nothing; the same send at an allowed fee goes through once. Audit A-M2: a post-quantum coin worth
no more than the fee its own input adds (PQInputMarginalFee) is never merged or selected. ECC and Sapling sends with an explicit
fee above -maxtxfee keep their stock behaviour (z_sendmany's own "Fee … is greater than the sum of outputs" bound,
the mempool's absurd-fee refusal at the commit).

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/wallet_pq_fee_cap.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID,
    assert_equal,
    connect_nodes_bi,
    nuparams,
    start_node,
    start_nodes,
    stop_node,
    sync_blocks,
    sync_mempools,
    wait_and_assert_operationid_status,
    z_mergetoaddress_call,
    z_sendmany_opid,
)

ACTIVATION = 210
FEE_CAP_REFUSED = 'cap on a post-quantum spend'


def assert_raises_rpc(substr, fn, *args):
    try:
        fn(*args)
    except JSONRPCException as e:
        assert substr in e.error['message'], 'expected %r in %r' % (substr, e.error['message'])
        return e.error['message']
    raise AssertionError('expected an RPC error containing %r' % substr)


class WalletPQFeeCapTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True

    def node_args(self, i):
        return [nuparams(VAULT_BRANCH_ID, ACTIVATION)]

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 extra_args=[self.node_args(i) for i in range(self.num_nodes)])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def mine(self, n=1):
        self.sync_all()
        self.nodes[1].generate(n)
        self.sync_all()

    def op_result(self, node, opid):
        import time
        for _ in range(300):
            r = node.z_getoperationresult([opid])
            if r:
                return r[0]
            time.sleep(1)
        raise AssertionError('timeout')

    def run_test(self):
        n0, n1 = self.nodes
        n0.generate(ACTIVATION + 10)
        self.sync_all()
        slh = n0.getnewaddress('', 'pqslh')
        n0.sendtoaddress(slh, Decimal('2'))
        ecc = n0.getnewaddress()
        n0.sendtoaddress(ecc, Decimal('3'))
        self.mine(1)
        b = n1.getnewaddress()
        cap = Decimal('0.1')                                 # PQMaxTxFee() with no attested price: -maxtxfee

        print('z_sendmany from an SLH-DSA address, explicit fee 0.2 > the cap: refused, nothing recorded')
        try:
            opid = z_sendmany_opid(n0, slh, [(b, Decimal('1'))], 1, Decimal('0.2'))
        except JSONRPCException as e:
            assert FEE_CAP_REFUSED in e.error['message'], e.error['message']
            opid = None
        if opid is not None:
            # the defect as it was: the operation fails at the commit and the transaction stays in the wallet
            res = self.op_result(n0, opid)
            print('  (unfixed node) operation %s: %s' % (res['status'], res.get('error', {}).get('message')))
        stuck = [t['txid'] for t in n0.listtransactions('*', 1000) if t.get('confirmations', 0) < 0]
        print('  wallet transactions at depth -1: %s' % stuck)

        print('the user pays B from an ECC address instead; a restart broadcasts nothing else')
        wait_and_assert_operationid_status(n0, z_sendmany_opid(n0, ecc, [(b, Decimal('1'))]))
        self.mine(1)
        stop_node(n0, 0)
        self.nodes[0] = n0 = start_node(0, self.options.tmpdir, self.node_args(0))
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        n0.generate(1)
        self.sync_all()
        sync_mempools(self.nodes)
        self.mine(1)
        print('  B received %s' % n1.getreceivedbyaddress(b, 1))
        assert_equal(n1.getreceivedbyaddress(b, 1), Decimal('1'))   # paid once, never twice
        assert_equal(stuck, [])
        assert_equal(n0.z_getbalance(slh), Decimal('2'))

        print('z_mergetoaddress of the SLH-DSA address, explicit fee 0.2: refused up front')
        assert_raises_rpc(FEE_CAP_REFUSED, z_mergetoaddress_call, n0, [slh], b, Decimal('0.2'))
        print('at the cap itself the send goes through, once')
        txid = wait_and_assert_operationid_status(n0, z_sendmany_opid(n0, slh, [(b, Decimal('1'))], 1, cap))
        self.mine(1)
        assert_equal(n1.getreceivedbyaddress(b, 1), Decimal('2'))
        assert_equal(n0.gettransaction(txid)['confirmations'], 1)

        print('audit A-M2: SLH-DSA coins worth no more than their own input fee (27,000 zat) are never merged or selected')
        for _ in range(3):
            n1.sendtoaddress(slh, Decimal('0.0001'))
        self.mine(1)
        coins_before = sorted(Decimal(u['amount']) for u in n0.listunspent(1, 9999999, [slh]))
        assert_equal(coins_before.count(Decimal('0.0001')), 3)
        r = z_mergetoaddress_call(n0, [slh], b)
        assert_equal(r['mergingUTXOs'], len(coins_before) - 3)
        wait_and_assert_operationid_status(n0, r['opid'])
        self.mine(1)
        assert_equal(sorted(Decimal(u['amount']) for u in n0.listunspent(1, 9999999, [slh])), [Decimal('0.0001')] * 3)
        try:
            opid = z_sendmany_opid(n0, slh, [(b, Decimal('0.0001'))])
            res = self.op_result(n0, opid)
            assert_equal(res['status'], 'failed')
            msg = res['error']['message']
        except JSONRPCException as e:
            msg = e.error['message']
        assert 'Insufficient transparent funds, no UTXOs found for taddr from address.' in msg, msg
        assert_raises_rpc('Could not find any funds to merge.', z_mergetoaddress_call, n0, [slh], b)

        print('stock sends keep their behaviour: an ECC z_sendmany at fee 0.2 fails at the commit as before')
        ecc2 = n0.getnewaddress()
        n0.sendtoaddress(ecc2, Decimal('2'))
        self.mine(1)
        res = self.op_result(n0, z_sendmany_opid(n0, ecc2, [(b, Decimal('1'))], 1, Decimal('0.2')))
        assert_equal(res['status'], 'failed')
        assert 'CommitTransaction failed' in res['error']['message'], res['error']['message']


if __name__ == '__main__':
    WalletPQFeeCapTest().main()
