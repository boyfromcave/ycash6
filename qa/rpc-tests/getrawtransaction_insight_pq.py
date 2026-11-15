#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The sender address of an input that spends a post-quantum output (beta3 item 6).

The insight indexes key a TX_PQPKH output by Hash160(scheme || keyHash) (CScript::AddressHash), which cannot be
turned back into the address. Before beta3 an input spending such an output carried `value` and `valueSat` but no
`address` in getrawtransaction 1, getblock 2 and getblockdeltas; the node now reads the address from the spent
output itself and checks it against the index key. This test spends an FN-DSA-512 coin, an SLH-DSA-SHA2-128s coin
and an ECC P2PKH coin and asserts, for each input, the address (the D-9 form, the scheme in the third character),
the value and the amount in zatoshis:

- getrawtransaction <txid> 1: in the mempool, then confirmed;
- getblock <hash> 2 and getblockdeltas <hash>;
- getaddresstxids, getaddressdeltas (the spend's negative delta) and getspentinfo for each address, and
  getaddressfirstlastheight where the node has it (ycash6);
- decoderawtransaction: it formats the transaction as getrawtransaction does, so on a -insightexplorer node it
  reads the same spent index and names the same address and value (without the index no input names either).

The test is identical on both C++ node lines. No address text or prefix is hard-coded: the kind of each address is
read back with validateaddress.

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/getrawtransaction_insight_pq.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

import time
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (VAULT_BRANCH_ID, assert_equal, nuparams, start_nodes,
                                 wait_and_assert_operationid_status, z_sendmany_opid)

ACTIVATION = 205
SLH, FN = 1, 2
FUND = Decimal('2')
SEND = Decimal('1')


def zat(x):
    return int(Decimal(x) * 100000000)


class GetrawtransactionInsightPQTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_network(self, split=False):
        # A clean chain, so the insight indexes cover every block (no -reindex of the cached chain).
        self.nodes = start_nodes(1, self.options.tmpdir, extra_args=[[
            nuparams(VAULT_BRANCH_ID, ACTIVATION), '-pqfalcon=1',
            '-txindex', '-experimentalfeatures', '-insightexplorer']])
        self.is_network_split = False

    def kind(self, addr):
        v = self.nodes[0].validateaddress(addr)
        assert v['isvalid'] and v['ismine'], v
        return v.get('pqscheme', 'ecc')

    def run_test(self):
        n0 = self.nodes[0]
        n0.generate(ACTIVATION - n0.getblockcount())

        print('fund an FN-DSA, an SLH-DSA and an ECC address')
        src = {'fn': n0.getnewaddress('pq'), 'slh': n0.getnewaddress('pqslh'), 'ecc': n0.getnewaddress()}
        assert_equal({k: self.kind(a) for k, a in src.items()}, {'fn': FN, 'slh': SLH, 'ecc': 'ecc'})
        fund = n0.sendmany('', {a: FUND for a in src.values()})
        n0.generate(1)
        # z_sendmany needs the coins confirmed in the wallet, which may lag the block by a moment.
        for _ in range(120):
            if len(n0.listunspent(1, 9999999, list(src.values()))) == 3:
                break
            time.sleep(0.5)
        fund_tx = n0.getrawtransaction(fund, 1)
        fund_height = n0.getblockcount()
        vout_of = {}
        for o in fund_tx['vout']:
            for a in o['scriptPubKey'].get('addresses', []):
                vout_of[a] = o['n']
        assert_equal(sorted(vout_of.get(a, -1) >= 0 for a in src.values()), [True] * 3)

        print('spend each coin from its address')
        spend = {}
        for k, a in src.items():
            dest = n0.getnewaddress()
            spend[k] = wait_and_assert_operationid_status(n0, z_sendmany_opid(n0, a, [(dest, SEND)]))

        def the_input(vin, k):
            mine = [i for i in vin if (i.get('txid'), i.get('vout')) == (fund, vout_of[src[k]])]
            assert_equal(len(mine), 1)
            return mine[0]

        def check_vin(vin, k, where):
            i = the_input(vin, k)
            got = (i.get('address'), i.get('value'), i.get('valueSat'))
            assert_equal((where, k, got), (where, k, (src[k], FUND, zat(FUND))))

        print('getrawtransaction 1 in the mempool')
        for k in src:
            check_vin(n0.getrawtransaction(spend[k], 1)['vin'], k, 'mempool')

        print('decoderawtransaction: the same input fields, read from the spent index of this node')
        for k in src:
            check_vin(n0.decoderawtransaction(n0.getrawtransaction(spend[k]))['vin'], k, 'decoderawtransaction')

        blockhash = n0.generate(1)[0]

        print('getrawtransaction 1, confirmed (with and without the block hash)')
        for k in src:
            check_vin(n0.getrawtransaction(spend[k], 1)['vin'], k, 'confirmed')
            check_vin(n0.getrawtransaction(spend[k], 1, blockhash)['vin'], k, 'blockhash')

        print('getblock 2')
        txs = {t['txid']: t for t in n0.getblock(blockhash, 2)['tx']}
        for k in src:
            check_vin(txs[spend[k]]['vin'], k, 'getblock')

        print('getblockdeltas')
        deltas = {t['txid']: t for t in n0.getblockdeltas(blockhash)['deltas']}
        for k in src:
            ins = [d for d in deltas[spend[k]]['inputs'] if (d['prevtxid'], d['prevout']) == (fund, vout_of[src[k]])]
            assert_equal((k, [(d.get('address'), d['satoshis']) for d in ins]), (k, [(src[k], -zat(FUND))]))

        print('getaddresstxids, getaddressdeltas, getspentinfo (and getaddressfirstlastheight) for each address')
        has_first_last = 'getaddressfirstlastheight' in n0.help()
        print('    getaddressfirstlastheight: %s' % ('checked' if has_first_last else 'not on this line'))
        for k, a in src.items():
            assert_equal((k, sorted(n0.getaddresstxids({'addresses': [a]}))), (k, sorted([fund, spend[k]])))
            d = n0.getaddressdeltas({'addresses': [a]})
            neg = [(x['txid'], x['satoshis'], x['address']) for x in d if x['satoshis'] < 0]
            assert_equal((k, neg), (k, [(spend[k], -zat(FUND), a)]))
            info = n0.getspentinfo({'txid': fund, 'index': vout_of[a]})
            vin = n0.getrawtransaction(spend[k], 1)['vin']
            index = vin.index(the_input(vin, k))
            assert_equal((k, info['txid'], info['index'], info['height']), (k, spend[k], index, n0.getblockcount()))
            if has_first_last:   # ycash6 only
                h = n0.getaddressfirstlastheight(a)
                assert_equal((k, h['firstHeight'], h['lastHeight']), (k, fund_height, n0.getblockcount()))


if __name__ == '__main__':
    GetrawtransactionInsightPQTest().main()
