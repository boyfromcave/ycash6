#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
gettransaction "fee" and "amount" for every funding shape (beta3 item 1, Y6-FEE-DISPLAY).

Upstream computed fee = GetValueOut() - (the wallet's transparent debit), so a Sapling-funded send showed the sum of
its transparent outputs as its fee and a Sapling to Sapling send showed none. The fee is now the transaction's own:
transparent value in + shielded value in - transparent value out - value into a shielded pool, shown negative.

One wallet (node 0, a fresh wallet file so no coinbase of its own) holds ECC, FN-DSA-512 and Sapling addresses and
sends in each shape: ECC to ECC, ECC to Sapling, Sapling to ECC (a foreign and an own recipient), Sapling to Sapling,
Sapling to post-quantum outputs of both schemes (the live case: ECC + FN + SLH recipients, one own PQ), ECC to a
post-quantum address, and a post-quantum input to ECC and to Sapling. For each, unconfirmed and mined:

- fee == -(the mempool entry's fee of another node) == -(inputs - outputs decoded from the raw transaction);
- amount == the net change to the wallet's transparent (ECC + post-quantum) balance, with the fee added back when the
  transparent inputs paid it (no shielded value in), as the help text states: ECC/PQ-funded sends show minus what left
  the wallet's transparent addresses for others, Sapling-funded sends show the transparent value they paid this wallet.
- the recipient wallet shows no fee (no input of its own).

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/wallet_gettransaction_fee.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>

One file on both C++ lines (ycash-dd: BITCOIND=, ycash6: ZCASHD=); the line differences (z_sendmany's fee and privacy
policy) are behind test_framework/util.py's z_sendmany_opid.
"""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID,
    assert_equal,
    connect_nodes_bi,
    nuparams,
    start_nodes,
    sync_mempools,
    wait_and_assert_operationid_status,
    z_sendmany_opid,
)

ACTIVATION = 210
COIN = 100000000


def zat(x):
    return int(round(Decimal(str(x)) * COIN))


class WalletGetTransactionFeeTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = False

    def setup_network(self, split=False):
        args = [nuparams(VAULT_BRANCH_ID, ACTIVATION), '-pqfalcon=1']
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 extra_args=[args + ['-wallet=feeshape.dat'], args])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def mine(self, n=1):
        self.sync_all()
        self.nodes[1].generate(n)
        self.sync_all()

    def send(self, src, recipients):
        return wait_and_assert_operationid_status(self.nodes[0], z_sendmany_opid(self.nodes[0], src, recipients),
                                                  timeout=300)

    def decoded(self, txid):
        """inputs - outputs from the raw transaction (every input's funding transaction is in node 0's wallet), the
        shielded value in, and node 0's transparent credit and debit."""
        n0 = self.nodes[0]
        raw = n0.getrawtransaction(txid, 1)
        vin = debit = 0
        for i in raw['vin']:
            prev = n0.decoderawtransaction(n0.gettransaction(i['txid'])['hex'])['vout'][i['vout']]
            vin += zat(prev['value'])
            if n0.validateaddress(prev['scriptPubKey']['addresses'][0])['ismine']:
                debit += zat(prev['value'])
        vout = sum(zat(o['value']) for o in raw['vout'])
        credit = sum(zat(o['value']) for o in raw['vout']
                     if n0.validateaddress(o['scriptPubKey']['addresses'][0])['ismine'])
        balance = zat(raw.get('valueBalance', 0))
        return vin + balance - vout, max(balance, 0), credit, debit

    def check(self, label, txid, amount):
        """``amount``: what the help text says gettransaction's amount is for this shape, in YEC."""
        n0, n1 = self.nodes
        sync_mempools(self.nodes)
        mempool_fee = zat(n1.getrawmempool(True)[txid]['fee'])
        fee, shielded_in, credit, debit = self.decoded(txid)
        assert fee > 0, (label, fee)
        assert_equal(mempool_fee, fee)
        expected_amount = credit - debit + (fee if shielded_in == 0 else 0)
        assert_equal(expected_amount, zat(amount))
        for state in ('unconfirmed', 'mined'):
            if state == 'mined':
                self.mine(1)
            t = n0.gettransaction(txid)
            print('  %-34s %-11s amount %12s fee %12s' % (label, state, t['amount'], t['fee']))
            assert_equal(zat(t['fee']), -fee)
            assert_equal(t['amount'], Decimal(amount))
            assert_equal(t['amountZat'], zat(amount))
            try:
                r = n1.gettransaction(txid)            # the recipient: no input of its own, so no fee
            except JSONRPCException:
                r = {}
            assert 'fee' not in r, (label, r)

    def run_test(self):
        n0, n1 = self.nodes
        self.mine(ACTIVATION + 1 - n0.getblockcount())

        # one source address per transparent send: z_sendmany spends every coin of its source address
        ecc = [n0.getnewaddress() for _ in range(3)]
        fn = [n0.getnewaddress('', 'pq') for _ in range(2)]
        z = n0.z_getnewaddress('sapling')
        assert all(n0.validateaddress(a)['pqscheme'] == 2 for a in fn)   # Falcon active: "pq" is FN-DSA-512
        o_t, o_fn, o_slh, o_z = (n1.getnewaddress(), n1.getnewaddress('', 'pq'), n1.getnewaddress('', 'pqslh'),
                                 n1.z_getnewaddress('sapling'))

        print('funding node 0 from node 1: three ECC addresses, two FN-DSA addresses, one Sapling address')
        t1 = n1.getnewaddress()
        n1.sendtoaddress(t1, 12)
        self.mine(1)
        wait_and_assert_operationid_status(n1, z_sendmany_opid(n1, t1, [(z, Decimal('10'))]), timeout=300)
        for a in ecc + fn:
            n1.sendtoaddress(a, 3)
        self.mine(1)

        print('transparent (ECC) funded: amount = minus what left for others, fee added back')
        self.check('ECC -> ECC', self.send(ecc[0], [(o_t, Decimal('1'))]), '-1')
        self.check('ECC -> Sapling', self.send(ecc[1], [(o_z, Decimal('1'))]), '-1')
        self.check('ECC -> FN-DSA (PQ output)', self.send(ecc[2], [(o_fn, Decimal('0.5'))]), '-0.5')

        print('Sapling funded: amount = the transparent value paid to this wallet')
        self.check('Sapling -> ECC (other)', self.send(z, [(o_t, Decimal('1'))]), '0')
        self.check('Sapling -> ECC (own)', self.send(z, [(n0.getnewaddress(), Decimal('0.75'))]), '0.75')
        self.check('Sapling -> Sapling', self.send(z, [(o_z, Decimal('1'))]), '0')
        self.check('Sapling -> ECC + FN + SLH + own FN',
                   self.send(z, [(o_t, Decimal('1')), (o_fn, Decimal('1')), (o_slh, Decimal('1')),
                                 (n0.getnewaddress('', 'pq'), Decimal('0.25'))]), '0.25')

        print('post-quantum (FN-DSA) input: amount = minus what left for others, fee added back')
        self.check('FN-DSA -> ECC (PQ input)', self.send(fn[0], [(o_t, Decimal('1'))]), '-1')
        self.check('FN-DSA -> Sapling (PQ input)', self.send(fn[1], [(o_z, Decimal('1'))]), '-1')


if __name__ == '__main__':
    WalletGetTransactionFeeTest().main()
