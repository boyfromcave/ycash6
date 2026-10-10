#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The node wallet's post-quantum keys end to end (docs/plans/yellowback-quantum-plan.md §4.5-§4.6, Q5;
docs/plans/yellowback-quantum-spec.md §1.5, §2.1, §6.2, rulings A-12, A-13, C-4):

- vault_getnewowner: {scheme, keyhash, owner, address}; scheme 2 refused before Falcon, scheme 3 refused;
- vault_lock with no owner draws a new SLH-DSA wallet owner; owner as a PQ address, a pqkeyid and
  {scheme, keyhash}; vault_list's "wallet" flag on the owner's node only;
- vault_ownerspend selector 3 on a released set (no members) and selector 2 after ownerHeight, each a
  7,939-byte SLH-DSA owner scriptSig; the fee is max(VAULT_RPC_FEE, -pqfeerate x size): 10,000 at the
  default rate, size-priced on a node with -pqfeerate=0.001;
- a TX_PQPKH output to a wallet PQ key: listunspent sees it, a restart with -rescan finds it again, the
  wallet spends it through coin selection (sendtoaddress) at max(DEFAULT_FEE, -pqfeerate x size);
- dumpwallet / importwallet carry the PQ keys (pqseed lines): the importing wallet owns the vault and
  signs its owner spend;
- an encrypted wallet: the PQ keys survive encryption, a locked wallet refuses vault_getnewowner, the
  default-owner vault_lock and vault_ownerspend, and works again after walletpassphrase.

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/vault_pq_wallet.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

import os
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.pq import pqpkh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID,
    assert_equal,
    bitcoind_processes,
    connect_nodes_bi,
    nuparams,
    start_node,
    start_nodes,
    stop_node,
    sync_blocks,
)

ACTIVATION = 205
DELAY = 5
VAULT_RPC_FEE = 10000
DEFAULT_FEE = 1000
SLH_OWNER_SCRIPTSIG = 7939       # spec §1.5
SLH_PQPKH_SCRIPTSIG = 7938       # spec §2.1
HIGH_RATE = 100000               # node 1: -pqfeerate=0.001 YEC/kB in zat/kB
PASS = 'pq-wallet-pass'


def assert_raises_rpc(substr, fn, *args):
    try:
        fn(*args)
    except JSONRPCException as e:
        assert substr in e.error['message'], 'expected %r in %r' % (substr, e.error['message'])
        return e.error['message']
    raise AssertionError('expected an RPC error containing %r' % substr)


def zat(x):
    return int((Decimal(x) * 100000000).to_integral_value())


class VaultPQWalletTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 3
        self.setup_clean_chain = False

    def node_args(self, i):
        a = [nuparams(VAULT_BRANCH_ID, ACTIVATION), '-debug=vault']
        if i == 1:
            a += ['-pqfeerate=0.001', '-exportdir=%s' % os.path.join(self.options.tmpdir, 'export1')]
        if i == 2:
            a += ['-experimentalfeatures', '-developerencryptwallet']
        return a

    def setup_network(self, split=False):
        os.makedirs(os.path.join(self.options.tmpdir, 'export1'), exist_ok=True)
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 extra_args=[self.node_args(i) for i in range(self.num_nodes)])
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

    def mine(self, n=1):
        self.sync_all()
        self.nodes[0].generate(n)
        self.sync_all()

    def tx_of(self, txid, node=0):
        return self.nodes[node].getrawtransaction(txid, 1)

    def fee_of(self, txid, in_value_zat):
        tx = self.tx_of(txid)
        return in_value_zat - sum(zat(o['value']) for o in tx['vout']), len(tx['hex']) // 2, tx

    def lock(self, node, setid, owner_height, amount, owner=None):
        p = {'tag': 'TEST', 'setid': setid, 'delay': DELAY, 'ownerheight': owner_height, 'amount': amount}
        if owner is not None:
            p['owner'] = owner
        r = node.vault_lock(p)
        self.mine(1)
        return r

    def run_test(self):
        n0, n1, n2 = self.nodes

        print('activation')
        self.mine(ACTIVATION - n0.getblockcount())
        assert_equal(n0.vault_getinfo()['active'], True)

        print('vault_getnewowner')
        o = n0.vault_getnewowner()
        assert_equal(o['scheme'], 1)
        assert_equal(len(o['keyhash']), 64)
        assert_equal(o['owner'], '01' + o['keyhash'])
        assert o['address'].startswith('yr') and len(o['address']) == 53, o['address']
        o2 = n0.vault_getnewowner(1)
        assert o2['owner'] != o['owner']
        assert_raises_rpc('not active', n0.vault_getnewowner, 2)          # Falcon is not active on this chain
        assert_raises_rpc('unknown post-quantum scheme', n0.vault_getnewowner, 3)

        print('a set with no members: released, so the owner-released branch is open')
        setid = n0.set_create({'seats': 3, 'unlockthreshold': 2, 'cancelthreshold': 1, 'slashthreshold': 2,
                               'maturity': 2, 'livenesswindow': 50, 'bondmin': 1, 'ratewindow': 20})['setid']
        self.mine(1)
        assert_equal(n0.set_getinfo(setid)['released'], True)

        print('vault_lock: the default owner, a PQ address, a pqkeyid, {scheme, keyhash}')
        h = n0.getblockcount()
        assert_raises_rpc('ownerkey-removed', n0.vault_lock,
                          {'tag': 'TEST', 'setid': setid, 'delay': DELAY, 'ownerheight': h + 5, 'amount': 1, 'ownerkey': '02' * 33})
        near = self.lock(n0, setid, h + 6, 5)                      # selector 2 later
        assert near['owner'].startswith('01') and len(near['owner']) == 66
        far = self.lock(n0, setid, h + 1000, 4, owner=o['address'])
        assert_equal(far['owner'], o['owner'])
        by_id = self.lock(n0, setid, h + 1000, 3, owner=o2['owner'])
        assert_equal(by_id['owner'], o2['owner'])
        o3 = n0.vault_getnewowner()
        by_obj = self.lock(n0, setid, h + 1000, 2, owner={'scheme': 1, 'keyhash': o3['keyhash']})
        assert_equal(by_obj['owner'], o3['owner'])
        rows = {r['outpoint']: r for r in n0.vault_list({'setid': setid})}
        assert_equal(rows[near['outpoint']]['owner'], near['owner'])
        assert_equal(rows[near['outpoint']]['ownerscheme'], 1)
        assert_equal(rows[near['outpoint']]['wallet'], True)
        assert_equal({r['outpoint']: r['wallet'] for r in n1.vault_list({'setid': setid})}[near['outpoint']], False)
        mine = n0.vault_list({'mine': True})
        assert {near['outpoint'], far['outpoint'], by_id['outpoint'], by_obj['outpoint']} <= {r['outpoint'] for r in mine}

        print('vault_ownerspend selector 3 (released set), fee 10,000 at the default rate')
        dest = n0.getnewaddress()
        r = n0.vault_ownerspend(far['outpoint'], dest)
        assert_equal(r['selector'], 3)
        self.mine(1)
        fee, size, tx = self.fee_of(r['txid'], zat(4))
        assert_equal(len(tx['vin'][0]['scriptSig']['hex']) // 2, SLH_OWNER_SCRIPTSIG)
        assert_equal(fee, VAULT_RPC_FEE)
        assert size > 8000, size
        assert tx['confirmations'] >= 1

        print('vault_ownerspend selector 2 after ownerHeight')
        while n0.getblockcount() + 1 <= h + 6:
            self.mine(1)
        r = n0.vault_ownerspend(near['outpoint'], dest)
        assert_equal(r['selector'], 2)
        self.mine(1)
        fee, size, tx = self.fee_of(r['txid'], zat(5))
        assert_equal(len(tx['vin'][0]['scriptSig']['hex']) // 2, SLH_OWNER_SCRIPTSIG)
        assert_equal(tx['locktime'], h + 6)
        assert_equal(fee, VAULT_RPC_FEE)

        print('a vault owned by node 1 (-pqfeerate=0.001): its owner spend is priced by size')
        o1 = n1.vault_getnewowner()
        v1 = self.lock(n0, setid, h + 1000, 3, owner=o1['owner'])
        assert_raises_rpc('not a post-quantum key of this wallet', n0.vault_ownerspend, v1['outpoint'], dest)
        r = n1.vault_ownerspend(v1['outpoint'], n1.getnewaddress())
        assert_equal(r['selector'], 3)
        self.mine(1)
        fee, size, tx = self.fee_of(r['txid'], zat(3))
        assert_equal(fee, max(VAULT_RPC_FEE, HIGH_RATE * size // 1000))
        assert fee > VAULT_RPC_FEE

        print('a TX_PQPKH output to node 1: listunspent, restart with -rescan, spend by coin selection')
        p1 = n1.vault_getnewowner()
        spk = pqpkh_script(1, bytes.fromhex(p1['keyhash'])).hex()
        assert_equal(len(spk), 70)
        placeholder = n0.getnewaddress()
        raw = n0.createrawtransaction([], {placeholder: 2})
        p2pkh = n0.validateaddress(placeholder)['scriptPubKey']
        assert p2pkh in raw
        raw = raw.replace('19' + p2pkh, '23' + spk)
        funded = n0.fundrawtransaction(raw)['hex']
        pq_txid = n0.sendrawtransaction(n0.signrawtransaction(funded)['hex'])
        self.mine(1)
        pq_vout = [o for o in self.tx_of(pq_txid)['vout'] if o['scriptPubKey']['hex'] == spk][0]['n']

        def pq_unspent(node):
            return [u for u in node.listunspent() if u['txid'] == pq_txid and u['vout'] == pq_vout]
        assert_equal(len(pq_unspent(n1)), 1)
        assert_equal(pq_unspent(n1)[0]['scriptPubKey'], spk)
        assert_equal(pq_unspent(n1)[0]['spendable'], True)
        assert_equal(pq_unspent(n0), [])
        self.restart(1, ['-rescan'])
        n1 = self.nodes[1]
        assert_equal(len(pq_unspent(n1)), 1)
        nxt = n1.vault_getnewowner()                                  # the index continues after a restart
        assert nxt['owner'] not in (o1['owner'], p1['owner'])

        print('dumpwallet / importwallet carry the PQ keys')
        o1b = n1.vault_getnewowner()
        v1b = self.lock(n0, setid, h + 1000, 2, owner=o1b['owner'])
        dump = n1.z_exportwallet('pqdump')     # 6.20.0 has no dumpwallet; z_exportwallet writes the same format
        with open(dump) as f:
            text = f.read()
        assert '# Post-quantum keys' in text
        assert 'pqseed=1:' in text and ('owner=' + o1b['owner']) in text and o1b['address'] in text
        n2.importwallet(dump)
        assert_equal(len(pq_unspent(n2)), 1)                            # the rescan found the PQPKH coin
        assert_equal({r['outpoint']: r['wallet'] for r in n2.vault_list({'setid': setid})}[v1b['outpoint']], True)
        r = n2.vault_ownerspend(v1b['outpoint'], n2.getnewaddress())
        assert_equal(r['selector'], 3)
        self.mine(1)
        assert self.tx_of(r['txid'])['confirmations'] >= 1

        print('node 1 spends the PQPKH coin through sendtoaddress: max(DEFAULT_FEE, -pqfeerate x size)')
        n1 = self.nodes[1]
        others = [{'txid': u['txid'], 'vout': u['vout']} for u in n1.listunspent() if not (u['txid'] == pq_txid and u['vout'] == pq_vout)]
        if others:
            assert n1.lockunspent(False, others)
        txid = n1.sendtoaddress(n0.getnewaddress(), 1)
        tx = self.tx_of(txid, 1)
        assert_equal([(i['txid'], i['vout']) for i in tx['vin']], [(pq_txid, pq_vout)])
        assert_equal(len(tx['vin'][0]['scriptSig']['hex']) // 2, SLH_PQPKH_SCRIPTSIG)
        size = len(tx['hex']) // 2
        fee = -zat(n1.gettransaction(txid)['fee'])
        assert fee >= max(DEFAULT_FEE, HIGH_RATE * size // 1000), (fee, size)
        self.mine(1)
        assert_equal(pq_unspent(n1), [])
        if others:
            n1.lockunspent(True, others)

        print('an encrypted wallet: keys survive, a locked wallet refuses, walletpassphrase unlocks')
        n2 = self.nodes[2]
        before = n2.vault_getnewowner()
        v2 = self.lock(n0, setid, h + 1000, 2, owner=before['owner'])
        spend_to = n2.getnewaddress()            # 6.20.0: a locked wallet has no keypool to draw an address from
        n2.encryptwallet(PASS)
        bitcoind_processes[2].wait()
        self.nodes[2] = start_node(2, self.options.tmpdir, self.node_args(2))
        self.connect_all()
        sync_blocks(self.nodes)
        n2 = self.nodes[2]
        assert_equal({r['outpoint']: r['wallet'] for r in n2.vault_list({'setid': setid})}[v2['outpoint']], True)
        assert_raises_rpc('walletpassphrase', n2.vault_getnewowner)
        assert_raises_rpc('walletpassphrase', n2.vault_lock, {'tag': 'TEST', 'setid': setid, 'delay': DELAY, 'ownerheight': h + 1000, 'amount': 1})
        assert_raises_rpc('walletpassphrase', n2.vault_ownerspend, v2['outpoint'], spend_to)
        n2.walletpassphrase(PASS, 600)
        after = n2.vault_getnewowner()
        assert after['owner'] != before['owner']
        r = n2.vault_ownerspend(v2['outpoint'], n2.getnewaddress())
        assert_equal(r['selector'], 3)
        self.mine(1)
        assert self.tx_of(r['txid'])['confirmations'] >= 1
        lk = n2.vault_lock({'tag': 'TEST', 'setid': setid, 'delay': DELAY, 'ownerheight': h + 1000, 'amount': 1})
        self.mine(1)
        assert_equal({r['outpoint']: r['wallet'] for r in n2.vault_list({'setid': setid})}[lk['outpoint']], True)
        n2.walletlock()
        print('ok')


if __name__ == '__main__':
    VaultPQWalletTest().main()
