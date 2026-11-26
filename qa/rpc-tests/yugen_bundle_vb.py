#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Yugen bundle VB records on regtest (spec 0.5.4 §15.1, §15.5, §15.6 B6 and B9).

TEST-ONLY PROOFS, as yugen_bundle.py (-yugenteststubproofs; the helper's `testbundle` builds the
bundle). The deposit signature is real: dep_sighash is computed here from the spec (§15.5) with the
transfer hash the helper reports, and signed with the key of a P2PKH coin of node 0's wallet.

- the pool is funded by one leaf deposit (yewd-yugen), so the withdrawal's value is there;
- a bundle of a deposit (one 3-YEC P2PKH coin: 2.5 YEC into the pool, 0.5 YEC change) and a
  withdrawal (1 YEC to a P2PKH script) is refused with a broken deposit signature
  (bad-yugen-bundle-deposit-script), then accepted by submitbundle, put in the template and mined;
- both nodes: the coin is spent, the outputs exist at the bundle's txid, index 0 the change and
  index 1 the withdrawal; the pool balance moved by 2.5 - 1 YEC less the two fees;
- the withdrawal output is spent by an ordinary transaction (it is a coin like any other);
- a transaction spending a coin that a pooled bundle deposits is refused
  (bad-yugen-bundle-deposit-in-mempool);
- disconnecting the bundle's block (invalidateblock) restores the coin and removes the outputs;
  reconsiderblock connects it again;
- node 1, restarted without its Yugen state file, replays the chain (the applied masks come from
  the block undo data) to the same pool state.
"""

import hashlib
import json
import os
import struct

from test_framework.authproxy import JSONRPCException
from test_framework.util import assert_equal, start_node, stop_node, connect_nodes_bi, sync_blocks, sync_mempools
from test_framework.vault import ecdsa_sign_der
from test_framework.yellowback_model import base58check_decode

from yugen_bundle import ACT, ARGS, YUGEN_BRANCH_ID, YugenBundleTest, bundle_tx, compact

COIN = 100000000
FEE = 100000   # fee class 0 (BASE_FEE), no LEAFFEE in a bundle


def H(dom, *parts):
    """§3: SHAKE256 over "Yg" 0x00 dom || parts, 32 bytes."""
    return hashlib.shake_256(b'Yg\x00' + bytes([dom]) + b''.join(parts)).digest(32)


def Hvar(dom, data):
    return H(dom, struct.pack('<Q', len(data)), data)


def dep_sighash(branch_id, network, th, prevouts, k, amount, script_code):
    """§15.5 dep_sighash; prevouts as (txid in serialization order, index)."""
    ser = [t + struct.pack('<I', i) for t, i in prevouts]
    return H(0x89, struct.pack('<I', branch_id), bytes([network]), th, Hvar(0x87, b''.join(ser)),
             struct.pack('<I', k), ser[k], struct.pack('<Q', amount), Hvar(0x88, script_code))


def push(b):
    assert len(b) < 76
    return bytes([len(b)]) + b


def vout(outs):
    return (compact(len(outs)) + b''.join(struct.pack('<Q', v) + compact(len(s)) + s for v, s in outs)).hex()


class YugenBundleVbTest(YugenBundleTest):
    def make_vb(self, node, records, seed):
        h = node.getblockcount() + 1
        ha = (h - 1) // 16 * 16
        a = node.yugen_getanchor(ha)
        req = {'anchor': {'slot': (ha // 16) & 0xff, 'anchor_root': a['root'], 'reg_root': self.reg,
                          'block_hash': a['block_hash']},
               'n': 0, 'seed': seed, 'payee': '', 'branch_id': YUGEN_BRANCH_ID, 'network': 2,
               'height': h, 'activation': ACT, 'records': records}
        path = os.path.join(self.options.tmpdir, 'tbvb.json')
        with open(path, 'w') as f:
            json.dump(req, f)
        b, pa, pb, hashes = self.helper('testbundle', path).split()
        return bytes.fromhex(b), pa, pb, [bytes.fromhex(x) for x in hashes.split(',')]

    def coin(self, node, amount):
        """A P2PKH coin of `amount` YEC at a fresh wallet address, mined: (txid, n, script, secret)."""
        addr = node.getnewaddress()
        secret = base58check_decode(node.dumpprivkey(addr))[1:33]
        script = bytes.fromhex(node.validateaddress(addr)['scriptPubKey'])
        txid = node.sendtoaddress(addr, amount)
        node.generate(1)
        tx = node.getrawtransaction(txid, 1)
        n = [o['n'] for o in tx['vout'] if o['scriptPubKey']['hex'] == script.hex()][0]
        return txid, n, script, secret

    def vb_bundle(self, node, coin, change_script, payee_script, seed, break_sig=False):
        txid, n, script, secret = coin
        records = [{'vb': -250000000, 'vout': vout([(50000000, change_script)]),
                    'vin': [{'txid': bytes.fromhex(txid)[::-1].hex(), 'index': n, 'script_sig': ''}]},
                   {'vb': 100000000, 'vout': vout([(100000000, payee_script)])}]
        _, _, _, hashes = self.make_vb(node, records, seed)
        prev = [(bytes.fromhex(txid)[::-1], n)]
        d = dep_sighash(YUGEN_BRANCH_ID, 2, hashes[0], prev, 0, 3 * COIN, script)
        sig = ecdsa_sign_der(secret, d) + b'\x01'
        if break_sig:
            sig = sig[:-2] + bytes([sig[-2] ^ 1]) + sig[-1:]
        records[0]['vin'][0]['script_sig'] = (push(sig) + push(self.pubkey(secret))).hex()
        b, pa, pb, hashes2 = self.make_vb(node, records, seed)
        assert hashes2 == hashes   # the transfer hash does not cover the script signatures
        return b, pa, pb

    @staticmethod
    def pubkey(secret):
        from test_framework.vault import pubkey_of
        return pubkey_of(secret)

    def run_test(self):
        n0, n1 = self.nodes
        self.results = []
        self.reg = self.helper('regroot')
        n0.generate(140)
        sync_blocks([n0, n1])
        self.fund_pool(n0, n1, 5)

        coin = self.coin(n0, 3)
        change = bytes.fromhex(n0.validateaddress(n0.getnewaddress())['scriptPubKey'])
        payee = bytes.fromhex(n0.validateaddress(n0.getnewaddress())['scriptPubKey'])
        sync_blocks([n0, n1])

        bad, pa, pb = self.vb_bundle(n0, coin, change, payee, 41, break_sig=True)
        self.refused(n0, bundle_tx(bad), [pa, pb], 'bad-yugen-bundle-deposit-script')

        b, pa, pb = self.vb_bundle(n0, coin, change, payee, 41)
        r = n0.submitbundle({'tx': bundle_tx(b), 'proofs': [pa, pb]})
        txid = r['txid']
        assert_equal(r['transfers'], 2)
        assert txid in n0.getrawmempool()
        # The coin the pooled bundle deposits is not spent by another pooled transaction.
        raw = n0.createrawtransaction([{'txid': coin[0], 'vout': coin[1]}], {n0.getnewaddress(): 2.9999})
        signed = n0.signrawtransaction(raw)['hex']
        try:
            n0.sendrawtransaction(signed)
            msg = 'accepted'
        except JSONRPCException as e:
            msg = e.error['message']
        self.check('a coin a pooled bundle deposits is not spent again in the pool', 'bad-yugen-bundle-deposit-in-mempool' in msg, msg)

        t = n0.getblocktemplate()
        assert txid in [e['hash'] for e in t['transactions']]
        before = n0.yugen_getinfo()['pool_balance_zat']
        tip = n0.generate(1)[0]
        sync_blocks([n0, n1])
        assert txid in n0.getblock(tip)['tx']
        for node in (n0, n1):
            assert node.gettxout(coin[0], coin[1]) is None, 'deposited coin not spent'
            c, w = node.gettxout(txid, 0), node.gettxout(txid, 1)
            assert c and w, (c, w)
            assert_equal((c['valueZat'] if 'valueZat' in c else int(round(c['value'] * COIN)), c['scriptPubKey']['hex']),
                         (50000000, change.hex()))
            assert_equal((w['valueZat'] if 'valueZat' in w else int(round(w['value'] * COIN)), w['scriptPubKey']['hex']),
                         (100000000, payee.hex()))
            assert node.gettxout(txid, 2) is None
        after = n0.yugen_getinfo()['pool_balance_zat']
        assert_equal(after - before, 250000000 - 100000000 - 2 * FEE)
        assert_equal(n1.yugen_getinfo()['pool_balance_zat'], after)
        assert_equal(n1.yugen_getinfo()['root'], n0.yugen_getinfo()['root'])
        self.check('deposit and withdrawal applied: coin spent, outputs 0 and 1 created on both nodes', True)

        # The withdrawal output is an ordinary coin.
        raw = n0.createrawtransaction([{'txid': txid, 'vout': 1}], {n0.getnewaddress(): 0.9999})
        prevtx = [{'txid': txid, 'vout': 1, 'scriptPubKey': payee.hex(), 'amount': 1}]
        signed = n0.signrawtransaction(raw, prevtx)
        assert signed['complete'], signed
        spend = n0.sendrawtransaction(signed['hex'])
        sync_mempools([n0, n1])
        n0.generate(1)
        sync_blocks([n0, n1])
        assert n1.gettxout(txid, 1) is None and n1.getrawtransaction(spend, 1)['confirmations'] == 1
        self.check('the withdrawal output is spent by an ordinary transaction', True)

        # B9: disconnecting the bundle's block restores the coin and removes the outputs.
        n0.invalidateblock(tip)
        restored = n0.gettxout(coin[0], coin[1], True)
        self.check('disconnect: the deposited coin is back', restored is not None, str(restored))
        self.check('disconnect: the outputs are gone', n0.gettxout(txid, 0, False) is None)
        assert_equal(n0.yugen_getinfo()['pool_balance_zat'], before)
        n0.reconsiderblock(tip)
        sync_blocks([n0, n1])
        self.check('reconnect: the outputs are back', n0.gettxout(txid, 0) is not None and n0.gettxout(coin[0], coin[1]) is None)
        assert_equal(n0.yugen_getinfo()['pool_balance_zat'], n1.yugen_getinfo()['pool_balance_zat'])

        # A replay from blocks (no state file) takes each bundle's applied mask from the undo data.
        info = n1.yugen_getinfo()
        stop_node(n1, 1)
        os.remove(os.path.join(self.options.tmpdir, 'node1', 'regtest', 'yugen', 'state.dat'))
        self.nodes[1] = n1 = start_node(1, self.options.tmpdir, ARGS)
        connect_nodes_bi(self.nodes, 0, 1)
        again = n1.yugen_getinfo()
        self.check('replay without the state file: the same pool state',
                   (again['pool_balance_zat'], again['root'], again['tree_size']) ==
                   (info['pool_balance_zat'], info['root'], info['tree_size']), str((info, again)))

        failed = [n for n, ok in self.results if not ok]
        assert not failed, 'failed: %s' % failed


if __name__ == '__main__':
    YugenBundleVbTest().main()
