#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Out-of-order relay of a post-quantum spend (audit 07/F-6): a mininode peer sends a child before its
parent; the node parks the child as an orphan and admits it once the parent arrives.

- Before UPGRADE_VAULT the orphan bound is unchanged: on ycash-dd (v4.5.0) 5,000 bytes, so an ~8 KB
  child is dropped and stays absent after its parent; on ycash6 (6.20.0) 99,999 bytes, so it parks
  (PRE_ACTIVATION_PARKS below is the one line-specific constant).
- Once UPGRADE_VAULT is active at the next block, an SLH-DSA TX_PQPKH spend (7,938-byte scriptSig,
  ~8 KB) that arrives before its parent is parked, and both enter the mempool once the parent does
  (ycash-dd: MAX_ORPHAN_TX_SIZE_VAULT = 10,000 bytes).

    ZCASHD=<ycashd> ../.venv/bin/python -u qa/rpc-tests/vault_pq_relay.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

import time
from io import BytesIO

from test_framework.mininode import CTransaction, NetworkThread, NodeConn, msg_tx
from test_framework.util import assert_equal, p2p_port, signing_branch_id
from test_framework import pq
from test_framework import vault as v
from test_framework.vault_harness import ACTIVATION, COIN, FEE, OWNER, VaultTestBase
from test_framework.yellowback_util import wif_to_secret
from tx_expiry_helper import TestNode

PROTO = 270200                  # UPGRADE_VAULT's nProtocolVersion
PRE_ACTIVATION_PARKS = True     # ycash6: the 6.20.0 orphan bound is 99,999 bytes


class VaultPQRelayTest(VaultTestBase):

    def run_test(self):
        node = self.node
        node.generate(ACTIVATION - 20)
        self.sync_all()
        assert_equal(node.getblockchaininfo()['upgrades']['6d5b7a31']['status'], 'pending')
        self.section_pre_activation()
        self.start_vault_from_here()
        self.section_post_activation()
        print('vault_pq_relay OK')

    def start_vault_from_here(self):
        # VaultTestBase.start_vault mines from genesis; here the chain is already at ACTIVATION - 19
        self.model = v.VaultModel(activation_height=ACTIVATION)
        self.model_hashes = {}
        self.mine_to(ACTIVATION + 1)
        assert_equal(self.node.getblockchaininfo()['upgrades']['6d5b7a31']['status'], 'active')
        self.split_coins(4, 2)

    # ------------------------------------------------------------------ helpers

    def wallet_parent(self, spk, value):
        """A wallet-signed transaction paying ``value`` to ``spk`` (output 0), not sent."""
        u = [x for x in self.node.listunspent() if x['amount'] * COIN >= value + 2 * FEE][0]
        total = int(u['amount'] * COIN)
        tx = v.make_tx([(u['txid'], u['vout'], v.SEQUENCE_FINAL)],
                       [(value, spk), (total - value - FEE, self.change_spk())])
        return self.node.signrawtransaction(v.tx_hex(tx))['hex']

    def connect(self):
        tn = TestNode()
        conn = NodeConn('127.0.0.1', p2p_port(0), self.node, tn, 'regtest', PROTO)
        tn.add_connection(conn)
        NetworkThread().start()
        tn.wait_for_verack()
        return tn, conn

    def send(self, tn, hex_):
        tx = CTransaction()
        tx.deserialize(BytesIO(bytes.fromhex(hex_)))
        tx.calc_sha256()
        tn.send_message(msg_tx(tx))
        tn.sync_with_ping()
        return tx.hash

    def wait_mempool(self, txids, present, label, timeout=20):
        deadline = time.time() + timeout
        while True:
            pool = set(self.node.getrawmempool())
            if all((t in pool) == present for t in txids):
                break
            assert time.time() < deadline, '%s: mempool %r' % (label, pool)
            time.sleep(0.2)
        print('    ok   %s' % label)

    def out_of_order(self, parent_hex, child_hex, parks, label):
        tn, conn = self.connect()
        child = self.send(tn, child_hex)
        assert child not in self.node.getrawmempool(), '%s: an orphan entered the mempool' % label
        parent = self.send(tn, parent_hex)
        self.wait_mempool([parent], True, '%s: the parent is admitted' % label)
        if parks:
            self.wait_mempool([child], True, '%s: the orphan child is admitted after its parent' % label)
        else:
            time.sleep(2)
            self.wait_mempool([child], False, '%s: the dropped child stays absent after its parent' % label)
        conn.disconnect_node()
        if getattr(self, 'model', None) is None:     # before activation: no vault model yet
            self.node.generate(1)
            self.sync_all()
        else:
            self.mine()
        return parent, child

    # ------------------------------------------------------------------ before activation

    def section_pre_activation(self):
        print('A. before UPGRADE_VAULT: an ~8 KB child before its parent')
        node = self.node
        addr = node.getnewaddress()
        secret = wif_to_secret(node.dumpprivkey(addr))
        spk = v.node_spk(node, addr)
        value = 3 * COIN
        parent_hex = self.wallet_parent(spk, value)
        parent_txid = v.tx_txid(v.tx_from_hex(parent_hex))
        outs = 230
        each = (value - FEE) // outs
        tx = v.make_tx([(parent_txid, 0, v.SEQUENCE_FINAL)], [(each, self.change_spk()) for _ in range(outs)])
        v.sign_p2pkh_input(tx, 0, secret, value, signing_branch_id(node))
        child_hex = v.tx_hex(tx)
        size = len(child_hex) // 2
        assert 5000 < size < 10000, size
        print('    child: %d bytes, %d outputs' % (size, outs))
        self.out_of_order(parent_hex, child_hex, PRE_ACTIVATION_PARKS, 'pre-activation')

    # ------------------------------------------------------------------ after activation

    def section_post_activation(self):
        print('B. UPGRADE_VAULT active: an SLH-DSA TX_PQPKH spend before its parent')
        pk = bytes(OWNER)[32:64]
        pkh = pq.pqpkh_script_of(pq.SCHEME_SLH_DSA_SHA2_128S, pk)
        parent_hex = self.wallet_parent(pkh, COIN)
        parent_txid = v.tx_txid(v.tx_from_hex(parent_hex))
        tx = v.make_tx([(parent_txid, 0, v.SEQUENCE_FINAL)], [(COIN - FEE, self.change_spk())])
        tx.vin[0].scriptSig = pq.pq_scriptsig_from_pushes(
            pq.pq_sign_input(tx, 0, pkh, COIN, v.VAULT_BRANCH_ID, OWNER))
        assert_equal(len(tx.vin[0].scriptSig), 7938)
        child_hex = v.tx_hex(tx)
        size = len(child_hex) // 2
        assert 5000 < size <= 10000, size
        print('    child: %d bytes' % size)
        parent, child = self.out_of_order(parent_hex, child_hex, True, 'post-activation')
        assert_equal(self.node.gettxout(child, 0)['value'] * COIN, COIN - FEE)


if __name__ == '__main__':
    VaultPQRelayTest().main()
