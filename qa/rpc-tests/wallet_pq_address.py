#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The plain-YEC post-quantum address chain-wide (owner decision D-Q-20; quantum plan §8.1 "SQ"): rq… on regtest,
Base58Check(4C51 || scheme || keyHash), 53 characters, the TX_PQPKH script a PQ yr… names.

- getnewaddress "" "pq" / "pqslh": refused before the vault upgrade; after it an rq… address of the wallet's PQ key
  chain (SLH-DSA while Falcon is inactive), in the address book; validateaddress pqscheme / pqkeyhash;
- refusals: a scheme-2 rq… before Falcon (sendtoaddress), PQ dust, dumpprivkey / signmessage, z_sendmany /
  z_shieldcoinbase / z_mergetoaddress from an rq… (A-15), -mineraddress=rq…;
- pay to rq… with sendtoaddress and sendmany (z_sendmany refuses it, below); receive (listunspent,
  getreceivedbyaddress, listreceivedbyaddress); spend through coin selection (sendtoaddress) at
  max(the wallet's fee, LEGACY_DEFAULT_FEE, -pqfeerate x size);
- the insight address index: getaddressbalance / utxos / txids / deltas / mempool by rq… and by the yr… YED form;
- vault_release of an intent paying the wallet's PQ key: by a third party with the address (the owner finds it in
  the index), and by the owner after a restart without the script;
- z_importpqkey (own and foreign keys, refusals); a seed-only restore with -hdseedfile (and its refusal for an
  existing wallet with another seed). (yed_validateaddress / yed_listtokens transparentAddress = the rq… form is
  checked in yellowback_pq.py, where the YED module is live.)

6.20.0 (ported from ycash-dd d16e02345..d7b2dee30): the z_* RPCs take a libzcash::PaymentAddress, which has no
post-quantum alternative, so z_sendmany and z_mergetoaddress refuse an rq… recipient by name (v4.5.0 pays it from
z_sendmany) and z_getbalance does not take one (getreceivedbyaddress stands in); -hdseedfile holds the wallet's
recovery phrase (z_exportwallet's recovery_phrase= line), not a 32-byte HD seed.

    ZCASHD=<ycashd> ../.venv/bin/python -u qa/rpc-tests/wallet_pq_address.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

import os
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.pq import pqpkh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID,
    assert_equal,
    assert_start_raises_init_error,
    connect_nodes_bi,
    nuparams,
    start_node,
    start_nodes,
    stop_node,
    sync_blocks,
)
from test_framework.yellowback_model import base58check_decode, base58check_encode

ACTIVATION = 210
DELAY = 3
DEFAULT_FEE = 1000
SLH_PQPKH_SCRIPTSIG = 7938       # spec §2.1
RQ_VERSION = bytes.fromhex('4c51')
YR_PQ_VERSION = bytes.fromhex('5710')


def assert_raises_rpc(substr, fn, *args):
    try:
        fn(*args)
    except JSONRPCException as e:
        assert substr in e.error['message'], 'expected %r in %r' % (substr, e.error['message'])
        return e.error['message']
    raise AssertionError('expected an RPC error containing %r' % substr)


def zat(x):
    return int((Decimal(x) * 100000000).to_integral_value())


def pq_parts(addr):
    raw = base58check_decode(addr)
    assert raw is not None and len(raw) == 35, addr
    return raw[:2], raw[2], raw[3:]


class WalletPQAddressTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 3
        self.setup_clean_chain = False

    def node_args(self, i):
        a = [nuparams(VAULT_BRANCH_ID, ACTIVATION), '-debug=vault']
        if i == 0:
            a += ['-txindex', '-experimentalfeatures', '-insightexplorer',
                  '-exportdir=%s' % os.path.join(self.options.tmpdir, 'export0')]
        return a

    def setup_network(self, split=False):
        os.makedirs(os.path.join(self.options.tmpdir, 'export0'), exist_ok=True)
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 extra_args=[self.node_args(i) + (['-reindex'] if i == 0 else []) for i in range(self.num_nodes)])
        self.connect_all()
        self.is_network_split = False
        self.sync_all()

    def connect_all(self):
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 1, 2)
        connect_nodes_bi(self.nodes, 0, 2)

    def restart(self, i, extra=()):
        stop_node(self.nodes[i], i)
        self.nodes[i] = start_node(i, self.options.tmpdir, self.node_args(i) + list(extra))
        for j in range(self.num_nodes):
            if j != i:
                connect_nodes_bi(self.nodes, i, j)
        sync_blocks(self.nodes)

    def mine(self, n=1, node=1):
        self.sync_all()
        self.nodes[node].generate(n)
        self.sync_all()

    def run_test(self):
        n0, n1, n2 = self.nodes

        print('before the vault upgrade: no PQ address')
        assert n0.getblockcount() + 1 < ACTIVATION
        assert_raises_rpc('vault upgrade', n0.getnewaddress, '', 'pq')
        self.mine(ACTIVATION - n0.getblockcount())

        print('getnewaddress "" "pq": an rq… address of the PQ key chain, in the address book')
        a = n0.getnewaddress('', 'pq')
        a2 = n0.getnewaddress('', 'pq')
        a3 = n0.getnewaddress('', 'pqslh')
        b = n0.getnewaddress('', 'pq')
        for x in (a, a2, a3, b):
            assert x.startswith('rq') and len(x) == 53, x
            ver, scheme, h = pq_parts(x)
            assert_equal((ver, scheme), (RQ_VERSION, 1))    # SLH-DSA: Falcon is not active on this chain
        assert len({a, a2, a3, b}) == 4
        assert_raises_rpc('type must be', n0.getnewaddress, '', 'bogus')
        v = n0.validateaddress(a)
        _, _, h = pq_parts(a)
        assert_equal((v['isvalid'], v['ismine'], v['isscript'], v['pqscheme'], v['pqkeyhash']), (True, True, False, 1, h.hex()))
        assert_equal(v['scriptPubKey'], pqpkh_script(1, h).hex())
        assert_equal(v['account'], '')
        assert a in n0.getaddressesbyaccount('')
        assert_equal(n1.validateaddress(a)['ismine'], False)
        assert_equal(n1.validateaddress(a[:-1] + ('1' if a[-1] != '1' else '2'))['isvalid'], False)

        print('refusals')
        falcon = base58check_encode(RQ_VERSION + b'\x02' + h)
        assert_equal(n1.validateaddress(falcon)['isvalid'], True)
        assert_raises_rpc('FN-DSA-512', n1.sendtoaddress, falcon, 1)
        unknown = base58check_encode(RQ_VERSION + b'\x03' + h)
        assert_equal(n1.validateaddress(unknown)['isvalid'], False)
        assert_raises_rpc('Transaction amount too small', n1.sendtoaddress, a, Decimal('0.00001'))
        assert_raises_rpc('no WIF key', n0.dumpprivkey, a)
        assert_raises_rpc('does not refer to key', n0.signmessage, a, 'hello')
        zaddr = n0.z_getnewaddress('sapling')
        assert_raises_rpc('z_sendmany cannot spend from a post-quantum address', n0.z_sendmany, a, [{'address': zaddr, 'amount': 1}])
        assert_raises_rpc('z_shieldcoinbase cannot spend from a post-quantum address', n0.z_shieldcoinbase, a, zaddr)
        assert_raises_rpc('z_mergetoaddress cannot spend from a post-quantum address', n0.z_mergetoaddress, [a], zaddr)

        print('pay to rq…: sendtoaddress, sendmany (z_sendmany refuses it on 6.20.0)')
        t1 = n1.getnewaddress()
        n1.sendtoaddress(t1, 5)
        self.mine(1)
        assert_raises_rpc('z_sendmany cannot pay a post-quantum address', n1.z_sendmany, t1, [{'address': a3, 'amount': Decimal('0.75')}], 1, None)
        assert_raises_rpc('z_mergetoaddress cannot pay a post-quantum address', n1.z_mergetoaddress, [t1], a3)
        tx_z = n1.sendtoaddress(a3, Decimal('0.75'))
        tx_a = n1.sendtoaddress(a, 2)
        tx_m = n1.sendmany('', {a2: 1, n1.getnewaddress(): Decimal('0.5')})
        self.sync_all()
        mem = n0.getaddressmempool({'addresses': [a]})
        assert_equal([(m['txid'], m['satoshis'], m['address']) for m in mem], [(tx_a, zat(2), a)])
        self.mine(1)
        utx = {u['txid']: u for u in n0.listunspent(1, 9999999, [a, a2, a3])}
        assert_equal(sorted(utx), sorted([tx_a, tx_m, tx_z]))
        assert_equal((utx[tx_a]['address'], utx[tx_a]['amount'], utx[tx_a]['spendable']), (a, Decimal('2'), True))
        assert_equal(utx[tx_a]['scriptPubKey'], pqpkh_script(1, h).hex())
        assert_equal(n0.getreceivedbyaddress(a), Decimal('2'))
        assert_equal(n0.getreceivedbyaddress(a2), Decimal('1'))   # 6.20.0: z_getbalance takes no rq…
        rcv = {r['address']: r['amount'] for r in n0.listreceivedbyaddress(1)}
        assert_equal((rcv[a], rcv[a2], rcv[a3]), (Decimal('2'), Decimal('1'), Decimal('0.75')))
        cats = [(t['category'], t['address']) for t in n0.listtransactions('*', 100) if t['txid'] == tx_a]
        assert_equal(cats, [('receive', a)])

        print('the insight address index: rq… and its yr… YED form')
        yr = base58check_encode(YR_PQ_VERSION + b'\x01' + h)
        for form in (a, yr):
            bal = n0.getaddressbalance({'addresses': [form]})
            assert_equal((bal['balance'], bal['received']), (zat(2), zat(2)))
            assert_equal(n0.getaddresstxids({'addresses': [form]}), [tx_a])
            u = n0.getaddressutxos({'addresses': [form]})
            assert_equal([(x['txid'], x['satoshis'], x['address'], x['script']) for x in u],
                         [(tx_a, zat(2), form, pqpkh_script(1, h).hex())])
            d = n0.getaddressdeltas({'addresses': [form]})
            assert_equal([(x['txid'], x['satoshis'], x['address']) for x in d], [(tx_a, zat(2), form)])
        both = n0.getaddressbalance({'addresses': [a, a2]})
        assert_equal(both['balance'], zat(3))

        print('spend an rq… coin through coin selection (sendtoaddress), fee max(DEFAULT_FEE, pqfeerate x size)')
        others = [{'txid': u['txid'], 'vout': u['vout']} for u in n0.listunspent(0) if not u['address'].startswith('rq')]
        n0.lockunspent(False, others)
        dest = n1.getnewaddress()
        spend = n0.sendtoaddress(dest, Decimal('1.5'))
        tx = n0.getrawtransaction(spend, 1)
        pq_in = [i for i in tx['vin'] if len(i['scriptSig']['hex']) // 2 == SLH_PQPKH_SCRIPTSIG]
        assert len(pq_in) >= 1, [len(i['scriptSig']['hex']) // 2 for i in tx['vin']]
        size = len(tx['hex']) // 2
        fee = -n0.gettransaction(spend)['fee']
        # At least max(DEFAULT_FEE, -pqfeerate x size) (-pqfeerate defaults to -minrelaytxfee, 100 zat/kB); the
        # wallet's own minimum (-mintxfee, 1000 zat/kB) prices this large transaction above it, by size.
        assert zat(fee) >= max(DEFAULT_FEE, 100 * size // 1000), (fee, size)
        assert zat(fee) <= max(DEFAULT_FEE, 1000 * (size + 1000) // 1000), (fee, size)
        n0.lockunspent(True, others)
        self.mine(1)
        assert_equal(n1.getreceivedbyaddress(dest), Decimal('1.5'))
        spent = {(i['txid'], i['vout']) for i in tx['vin']}
        assert_equal(n0.getaddressbalance({'addresses': [a]})['balance'],
                     0 if (tx_a, utx[tx_a]['vout']) in spent else zat(2))

        print('vault_release of an intent paying the wallet PQ key: by a third party, then by the owner after a restart')
        setid = n0.set_create({'seats': 1, 'unlockthreshold': 1, 'cancelthreshold': 1, 'slashthreshold': 1,
                               'maturity': 1, 'livenesswindow': 100, 'bondmin': Decimal('0.5')})['setid']
        self.mine(1)
        assert_equal(n0.set_join(setid, 1, n0.getblockcount() + 500)['complete'], True)
        self.mine(2)
        h0 = n0.getblockcount()
        lk = n0.vault_lock({'tag': 'TEST', 'setid': setid, 'delay': DELAY, 'ownerheight': h0 + 500, 'amount': 6})
        self.mine(1)
        intents = []
        cur = lk['outpoint']
        for amount in (2, 1):
            bu = n0.vault_buildunlock(cur, [{'address': b, 'amount': amount}])
            su = n0.set_signunlock(bu['hex'])
            assert_equal(su['complete'], True)
            txid = n0.vault_send(su['hex'])
            intents.append('%s:%d' % (txid, bu['intents'][0]['vout']))
            self.mine(1)
            cur = [x for x in n0.vault_list({'kind': 'vault', 'setid': setid})][0]['outpoint']
        self.mine(DELAY)
        assert_raises_rpc('recipient script is unknown', n1.vault_release, intents[0])   # n1 holds no key of b
        r1 = n1.vault_release(intents[0], b)                                                # a third party, with the address
        self.mine(1)
        _, _, hb = pq_parts(b)
        u = n0.getaddressutxos({'addresses': [b]})
        assert_equal([(x['txid'], x['satoshis']) for x in u], [(r1, zat(2))])
        self.restart(0)
        n0 = self.nodes[0]
        r2 = n0.vault_release(intents[1])                                                   # the owner, no script
        self.mine(1)
        assert_equal(n0.getrawtransaction(r2, 1)['vout'][0]['scriptPubKey']['hex'], pqpkh_script(1, hb).hex())
        assert_equal(sorted(x['txid'] for x in n0.listunspent(1, 9999999, [b])), sorted([r1, r2]))

        print('z_importpqkey')
        export = n0.z_exportwallet('pqexport')
        lines = open(export).read().splitlines()
        seed_hex = None
        for line in lines:
            if line.startswith('pqseed=') and ('yecaddr=%s' % a2) in line:
                seed_hex = line.split()[0][len('pqseed='):].split(':')[2]
        assert seed_hex is not None, 'no pqseed line for %s' % a2
        assert_raises_rpc('unknown post-quantum scheme', n1.z_importpqkey, '3:' + seed_hex)
        assert_raises_rpc('the seed must be 48 bytes', n1.z_importpqkey, '1:' + seed_hex[:-2])
        assert_raises_rpc('pqseed must be', n1.z_importpqkey, 'garbage')
        r = n1.z_importpqkey('1:' + seed_hex)
        assert_equal((r['address'], r['added'], r['index'], r['scheme']), (a2, True, None, 1))
        assert_equal(r['pqkeyid'], '01' + r['keyhash'])
        assert_equal(n1.validateaddress(a2)['ismine'], True)
        assert_equal([x['txid'] for x in n1.listunspent(1, 9999999, [a2])], [tx_m] if (tx_m, utx[tx_m]['vout']) not in spent else [])
        assert_equal(n1.z_importpqkey('pqseed=1:0:' + seed_hex, False)['added'], False)   # already held; a foreign index is dropped
        # the owner's own key (already held, as the lookahead): index kept
        own = n0.z_importpqkey('1:' + seed_hex, False)
        assert_equal(own['added'], False)
        assert own['index'] is not None

        print('-mineraddress=rq… is refused at init')
        stop_node(self.nodes[1], 1)
        assert_start_raises_init_error(1, self.options.tmpdir, self.node_args(1) + ['-mineraddress=%s' % a],
                                       'P2SH and post-quantum addresses are not supported')

        print('-hdseedfile: refused for an existing wallet with another seed')
        assert_start_raises_init_error(1, self.options.tmpdir, self.node_args(1) + ['-hdseedfile=%s' % export],
                                       '-hdseedfile applies only when creating a new wallet')
        self.nodes[1] = start_node(1, self.options.tmpdir, self.node_args(1))
        connect_nodes_bi(self.nodes, 0, 1)

        print('-hdseedfile: a new wallet from node 0\'s seed recovers its PQ coins (rescan from genesis)')
        stop_node(self.nodes[2], 2)
        os.remove(os.path.join(self.options.tmpdir, 'node2', 'regtest', 'wallet.dat'))
        self.nodes[2] = start_node(2, self.options.tmpdir, self.node_args(2) + ['-hdseedfile=%s' % export])
        n2 = self.nodes[2]
        connect_nodes_bi(self.nodes, 0, 2)
        connect_nodes_bi(self.nodes, 1, 2)
        sync_blocks(self.nodes)
        for x in (a, a2, a3, b):
            assert_equal(n2.validateaddress(x)['ismine'], True)
        n0_pq = sorted((u['txid'], u['vout']) for u in self.nodes[0].listunspent(1, 9999999, [a, a2, a3, b]))
        n2_pq = sorted((u['txid'], u['vout']) for u in n2.listunspent(1, 9999999, [a, a2, a3, b]))
        assert_equal(n2_pq, n0_pq)
        fresh = n2.getnewaddress('', 'pq')
        assert fresh not in (a, a2, a3, b)
        # the restored wallet is ordinary afterwards: a restart keeps it (no -hdseedfile needed, and the same file is accepted)
        stop_node(self.nodes[2], 2)
        self.nodes[2] = start_node(2, self.options.tmpdir, self.node_args(2) + ['-hdseedfile=%s' % export])
        assert_equal(self.nodes[2].validateaddress(a)['ismine'], True)


if __name__ == '__main__':
    WalletPQAddressTest().main()
