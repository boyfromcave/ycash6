#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Re-funding set-signed vault spends and idempotent builds (01/V-2 = 07/F-2, 07/N-2), on three nodes
that each hold one member key of a set (unlock 2, cancel 1):

- set signatures are over SIGHASH_ALL|SIGHASH_ANYONECANPAY: the node's sighash is the framework's
  set_sighash, and differs from the SIGHASH_ALL digest;
- vault_buildunlock called twice returns the same hex ("reused"); other recipients are refused while
  the build exists, rebuild=true replaces it (before anyone signed);
- the builder double-spends its own fee coin after the threshold signed: the signed unlock no longer
  confirms; vault_buildunlock returns the same transaction re-funded ("refunded", same sighash);
  vault_refee of the signed hex keeps the signatures; vault_send confirms it; set_signunlock of the
  re-funded hex is idempotent (same sighash, no set-sign-once);
- the same for a CANCEL inside the intent's delay, re-funded by another member's node (anyone may
  re-fund: the signatures bind the template input and the outputs only);
- the build memo survives a restart and its fee coins stay locked (listlockunspent).

    ZCASHD=<ycashd> ../.venv/bin/python -u qa/rpc-tests/vault_refee.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
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
)
from test_framework import vault
from test_framework.yellowback_util import YCASH_UPGRADE_ARGS

ACTIVATION = 205
DELAY = 10
COIN = 100000000


def assert_raises_rpc(substr, fn, *args):
    try:
        fn(*args)
    except JSONRPCException as e:
        assert substr in e.error['message'], 'expected %r in %r' % (substr, e.error['message'])
        return e.error['message']
    raise AssertionError('expected an RPC error containing %r' % substr)


class VaultRefeeTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 3
        # 6.20.0: the 200-block cache is built without the Ycash upgrades the harness activates
        # at height 1, so the chain starts clean and each node mines its own funds.
        self.cache_behavior = 'clean'

    def node_args(self):
        return YCASH_UPGRADE_ARGS + [nuparams(VAULT_BRANCH_ID, ACTIVATION), '-debug=vault']

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, extra_args=[self.node_args()] * self.num_nodes)
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 1, 2)
        connect_nodes_bi(self.nodes, 0, 2)
        self.is_network_split = False
        self.sync_all()

    def mine(self, n=1, node=0):
        self.sync_all()
        hashes = self.nodes[node].generate(n)
        self.sync_all()
        return hashes

    def restart(self, i):
        stop_node(self.nodes[i], i)
        self.nodes[i] = start_node(i, self.options.tmpdir, self.node_args())
        for j in range(self.num_nodes):
            if j != i:
                connect_nodes_bi(self.nodes, i, j)
        sync_blocks(self.nodes)

    @staticmethod
    def fee_inputs(hexstr, templ):
        tx = vault.tx_from_hex(hexstr)
        out = []
        for i in tx.vin:
            op = '%064x:%d' % (i.prevout.hash, i.prevout.n)
            if op != templ:
                out.append(op)
        return out

    def double_spend(self, node, outpoint):
        """The builder spends its own (locked) fee coin elsewhere and mines it."""
        txid, n = outpoint.split(':')
        n = int(n)
        node.lockunspent(True, [{'txid': txid, 'vout': n}])
        coin = node.gettxout(txid, n)
        amount = coin['value'] - Decimal('0.0001')
        raw = node.createrawtransaction([{'txid': txid, 'vout': n}], {node.getnewaddress(): amount})
        signed = node.signrawtransaction(raw)
        assert signed['complete']
        node.sendrawtransaction(signed['hex'])
        self.mine(1)
        assert_equal(node.gettxout(txid, n), None)

    def set_sighash(self, node, hexstr, templ):
        txid, n = templ.split(':')
        coin = node.gettxout(txid, int(n), True)
        return vault.set_sighash(vault.tx_from_hex(hexstr), 0, bytes.fromhex(coin['scriptPubKey']['hex']),
                                 int(coin['value'] * COIN))

    def run_test(self):
        n0, n1, n2 = self.nodes
        for i in (1, 2, 0):   # every wallet gets mature transparent coinbases
            self.mine(10, node=i)
        self.mine(ACTIVATION - n0.getblockcount())

        # ---- a set with one member key per node (unlock 2, cancel 1) ----
        setid = n0.set_create({'seats': 3, 'unlockthreshold': 2, 'cancelthreshold': 1, 'slashthreshold': 2,
                               'maturity': 2, 'livenesswindow': 200, 'bondmin': 1})['setid']
        self.mine(1)
        lock = n0.getblockcount() + 500
        assert n0.set_join(setid, 1, lock)['complete']
        for node in (n1, n2):
            j = node.set_join(setid, 1, lock)
            node.set_sendact(n0.set_signact(j['hex'], setid)['hex'])
        self.mine(3)
        assert_equal(n0.set_getinfo(setid)['current'], 3)
        owner_height = n0.getblockcount() + 1000
        lk = n0.vault_lock({'tag': 'TEST', 'setid': setid, 'delay': DELAY, 'ownerheight': owner_height, 'amount': 10})
        self.mine(1)
        vop = lk['outpoint']
        addr = n2.getnewaddress()

        # ---- idempotent build (07/N-2) ----
        bu = n0.vault_buildunlock(vop, [{'address': addr, 'amount': 4}])
        assert_equal(bu['build'], 'new')
        again = n0.vault_buildunlock(vop, [{'address': addr, 'amount': 4}])
        assert_equal((again['hex'], again['build'], again['sighash']), (bu['hex'], 'reused', bu['sighash']))
        assert_raises_rpc('already built a different unlock', n0.vault_buildunlock, vop, [{'address': addr, 'amount': 3}])
        other = n0.vault_buildunlock(vop, [{'address': addr, 'amount': 3}], True)        # rebuild: nobody signed yet
        assert_equal(other['build'], 'new')
        assert other['sighash'] != bu['sighash']
        bu = n0.vault_buildunlock(vop, [{'address': addr, 'amount': 4}], True)
        # the node's set sighash is the framework's SIGHASH_ALL|ANYONECANPAY digest, not the SIGHASH_ALL one
        assert_equal(self.set_sighash(n0, bu['hex'], vop).hex(), bu['sighash'])
        txid, nn = vop.split(':')
        coin = n0.gettxout(txid, int(nn))
        assert vault.template_sighash(vault.tx_from_hex(bu['hex']), 0, bytes.fromhex(coin['scriptPubKey']['hex']),
                                      int(coin['value'] * COIN)).hex() != bu['sighash']
        fees = self.fee_inputs(bu['hex'], vop)
        assert_equal(len(fees), 1)
        locked = ['%s:%d' % (c['txid'], c['vout']) for c in n0.listlockunspent()]
        assert fees[0] in locked

        # ---- the memo survives a restart; its fee coin stays locked ----
        self.restart(0)
        n0 = self.nodes[0]
        locked = ['%s:%d' % (c['txid'], c['vout']) for c in n0.listlockunspent()]
        assert fees[0] in locked, (fees, locked)
        again = n0.vault_buildunlock(vop, [{'address': addr, 'amount': 4}])
        assert_equal((again['hex'], again['build']), (bu['hex'], 'reused'))

        # ---- signed, then the builder double-spends its fee coin ----
        s1 = n1.set_signunlock(bu['hex'])
        signed = n2.set_signunlock(s1['hex'])
        assert_equal((signed['complete'], signed['sighash']), (True, bu['sighash']))
        self.double_spend(n0, fees[0])
        assert_raises_rpc('', n0.vault_send, signed['hex'])                  # its fee input is gone
        # the build comes back re-funded with the same sighash; the members' records accept it (idempotent)
        rb = n0.vault_buildunlock(vop, [{'address': addr, 'amount': 4}])
        assert_equal((rb['build'], rb['sighash']), ('refunded', bu['sighash']))
        assert rb['hex'] != bu['hex']
        assert_equal(n1.set_signunlock(rb['hex'])['sighash'], bu['sighash'])
        # vault_refee keeps the signatures already collected
        rf = n0.vault_refee(signed['hex'])
        assert_equal(rf['sighash'], bu['sighash'])
        assert_equal(rf['replaced'], fees)
        assert rf['fee'] >= Decimal('0.0001'), rf
        assert_equal(vault.tx_from_hex(rf['hex']).vin[0].scriptSig, vault.tx_from_hex(signed['hex']).vin[0].scriptSig)
        again = n1.set_signunlock(rf['hex'])                                  # idempotent: already complete
        assert_equal((again['signatures'], again['sighash']), (2, bu['sighash']))
        unlock_txid = n0.vault_send(rf['hex'])
        self.mine(1)
        assert n0.getrawtransaction(unlock_txid, 1)['confirmations'] >= 1
        intent_op = '%s:%d' % (unlock_txid, bu['intents'][0]['vout'])

        # ---- a CANCEL inside the delay, its fee coin double-spent, re-funded by another node ----
        bc = n2.vault_buildcancel(intent_op)
        assert_equal(bc['build'], 'new')
        assert_equal(n2.vault_buildcancel(intent_op)['build'], 'reused')
        sc = n2.set_signcancel(bc['hex'])
        assert_equal((sc['complete'], sc['sighash']), (True, bc['sighash']))
        cfees = self.fee_inputs(bc['hex'], intent_op)
        self.double_spend(n2, cfees[0])
        rbc = n2.vault_buildcancel(intent_op)
        assert_equal((rbc['build'], rbc['sighash']), ('refunded', bc['sighash']))
        # anyone may re-fund: node 1 replaces node 2's fee input under node 2's cancel signature
        rfc = n1.vault_refee(sc['hex'])
        assert_equal(rfc['sighash'], bc['sighash'])
        cancel_txid = n1.vault_send(rfc['hex'])
        self.mine(1)
        assert n0.getblockcount() - n0.getrawtransaction(unlock_txid, 1)['height'] < DELAY
        assert n1.getrawtransaction(cancel_txid, 1)['confirmations'] >= 1
        assert_equal(n0.vault_list({'kind': 'intent'}), [])
        assert_equal(n0.set_getinfo(setid)['lockedvalue'], Decimal('10'))
        # no member was ejected: every signature was over one sighash per outpoint
        assert all(m['status'] == 'active' for m in n0.set_getinfo(setid)['memberlist'])
        # the spent template prunes the memo and its locks at the next build call
        assert_raises_rpc('not an unspent intent output', n2.vault_buildcancel, intent_op)


if __name__ == '__main__':
    VaultRefeeTest().main()
