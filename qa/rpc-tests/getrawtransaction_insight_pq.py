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
  reads the same spent index and names the same address and value (without the index no input names either);
- a chained spend of an unconfirmed post-quantum parent (mempool, REST /rest/tx, then both in one block, where
  getblock 2 and getblockdeltas read the shared parent once);
- inputs that name no address: a coinbase input, and a vault input (its value is still named).

The test is identical on both C++ node lines. The kind of each address is read back with validateaddress, and the
D-9 regtest prefixes are asserted (rqf… FN-DSA-512, rqs… SLH-DSA-SHA2-128s).

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/getrawtransaction_insight_pq.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

import http.client
import json
import time
import urllib.parse
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (VAULT_BRANCH_ID, assert_equal, nuparams, start_nodes,
                                 wait_and_assert_operationid_status, z_sendmany_opid)

ACTIVATION = 205
SLH, FN = 1, 2
FUND = Decimal('2')
SEND = Decimal('1')
DELAY = 5


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
            '-txindex', '-experimentalfeatures', '-insightexplorer', '-rest']])
        self.is_network_split = False

    def kind(self, addr):
        v = self.nodes[0].validateaddress(addr)
        assert v['isvalid'] and v['ismine'], v
        return v.get('pqscheme', 'ecc')

    def wait_coins(self, addrs, ok):
        for _ in range(120):
            if ok(self.nodes[0].listunspent(1, 9999999, addrs)):
                return
            time.sleep(0.5)
        raise AssertionError('wallet coins of %s: %s' % (addrs, self.nodes[0].listunspent(0, 9999999, addrs)))

    def run_test(self):
        n0 = self.nodes[0]
        n0.generate(ACTIVATION - n0.getblockcount())

        print('fund an FN-DSA, an SLH-DSA and an ECC address')
        src = {'fn': n0.getnewaddress('pq'), 'slh': n0.getnewaddress('pqslh'), 'ecc': n0.getnewaddress()}
        assert_equal({k: self.kind(a) for k, a in src.items()}, {'fn': FN, 'slh': SLH, 'ecc': 'ecc'})
        assert src['fn'].startswith('rqf') and src['slh'].startswith('rqs'), src   # D-9: the scheme in the third character
        fund = n0.sendmany('', {a: FUND for a in src.values()})
        n0.generate(1)
        # z_sendmany needs the coins confirmed in the wallet, which may lag the block by a moment.
        self.wait_coins(list(src.values()), lambda u: len(u) == 3)
        fund_tx = n0.getrawtransaction(fund, 1)
        fund_height = n0.getblockcount()
        vout_of = {}
        for o in fund_tx['vout']:
            for a in o['scriptPubKey'].get('addresses', []):
                vout_of[a] = o['n']
        # each funding output names exactly the address the input will name (the ECC one as before)
        for a in src.values():
            assert_equal(fund_tx['vout'][vout_of[a]]['scriptPubKey']['addresses'], [a])

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

        print('a chained spend of an unconfirmed post-quantum parent')
        fn2 = n0.getnewaddress('pq')
        # the FN-DSA change of the first spend, confirmed, and nothing else at that address
        self.wait_coins([src['fn']], lambda u: [x['txid'] for x in u] == [spend['fn']])
        assert_equal(self.kind(fn2), FN)
        parent = wait_and_assert_operationid_status(n0, z_sendmany_opid(n0, src['fn'], [(fn2, Decimal('0.5'))]))
        pvout = [o for o in n0.getrawtransaction(parent, 1)['vout'] if o['scriptPubKey'].get('addresses') == [fn2]]
        assert_equal(len(pvout), 1)
        child = wait_and_assert_operationid_status(
            n0, z_sendmany_opid(n0, fn2, [(n0.getnewaddress(), Decimal('0.25'))], minconf=0))
        assert_equal(set(n0.getrawmempool()), {parent, child})

        def check_child(vin, where):
            i = [x for x in vin if (x.get('txid'), x.get('vout')) == (parent, pvout[0]['n'])]
            got = [(x.get('address'), x.get('value'), x.get('valueSat')) for x in i]
            assert_equal((where, got), (where, [(fn2, Decimal('0.5'), zat('0.5'))]))

        check_child(n0.getrawtransaction(child, 1)['vin'], 'mempool')
        url = urllib.parse.urlparse(n0.url)
        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.request('GET', '/rest/tx/%s.json' % child)
        check_child(json.loads(conn.getresponse().read().decode('utf-8'), parse_float=Decimal)['vin'], 'rest')

        print('a vault input names no address (its value is named)')
        setid = n0.set_create({'seats': 3, 'unlockthreshold': 2, 'cancelthreshold': 1, 'slashthreshold': 2,
                               'maturity': 2, 'livenesswindow': 50, 'bondmin': 1, 'ratewindow': 20})['setid']
        n0.generate(1)
        lock = n0.vault_lock({'tag': 'TEST', 'setid': setid, 'delay': DELAY,
                              'ownerheight': n0.getblockcount() + 1000, 'amount': 1})
        n0.generate(1)
        # the parent and child of the chained spend are in that block too
        check_child(n0.getrawtransaction(child, 1)['vin'], 'confirmed')
        owner = n0.vault_ownerspend(lock['outpoint'], n0.getnewaddress())['txid']
        blockhash = n0.generate(1)[0]

        def vault_input(vin):
            v = [x for x in vin if x.get('txid') == lock['txid']]
            assert_equal(len(v), 1)
            return v[0]

        v = vault_input(n0.getrawtransaction(owner, 1)['vin'])
        assert_equal(('address' in v, v.get('valueSat')), (False, zat(1)))

        print('getblock 2: a coinbase input and a vault input name no address')
        block = n0.getblock(blockhash, 2)
        cb = block['tx'][0]['vin']
        assert_equal([('coinbase' in x, 'address' in x, 'value' in x) for x in cb], [(True, False, False)])
        txs = {t['txid']: t for t in block['tx']}
        assert_equal('address' in vault_input(txs[owner]['vin']), False)
        deltas = {t['txid']: t for t in n0.getblockdeltas(blockhash)['deltas']}
        assert_equal(deltas[block['tx'][0]['txid']]['inputs'], [])
        vd = [d for d in deltas[owner]['inputs'] if d['prevtxid'] == lock['txid']]
        assert_equal([('address' in d, d['satoshis']) for d in vd], [(False, -zat(1))])

        print('getblock 2 and getblockdeltas of the block holding the chained spend')
        cblock = n0.getblock(n0.getrawtransaction(child, 1)['blockhash'], 2)
        ctxs = {t['txid']: t for t in cblock['tx']}
        assert parent in ctxs and child in ctxs, ctxs.keys()
        check_child(ctxs[child]['vin'], 'getblock')
        cdeltas = {t['txid']: t for t in n0.getblockdeltas(cblock['hash'])['deltas']}
        ci = [(d.get('address'), d['satoshis']) for d in cdeltas[child]['inputs'] if d['prevtxid'] == parent]
        assert_equal(ci, [(fn2, -zat('0.5'))])


if __name__ == '__main__':
    GetrawtransactionInsightPQTest().main()
