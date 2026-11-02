#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
A -lightwalletd node mines, relays and indexes transactions across the vault upgrade without
stalling: generate, send, generate again, on both node lines.

The kogany review logged "generate hangs with -lightwalletd=1 on regtest" on both C++ lines. On
this line the hang was ycash6 pin finding 7 (doc/yellowback-baseline.md): the address index lives
in the insight explorer database, which was opened only for -insightexplorer, so the first block a
-lightwalletd node connected wrote through a null pointer in ConnectBlock (WriteAddressIndex). The
process faulted inside the generate call, and the macOS crash handler held the dying process, so
the RPC client saw a call that never answered rather than a closed connection. lightwalletd_only.py
covers the first block and a restart; this script covers what a lightwalletd backend does after
that: a wallet send into the mempool address index, a block that confirms it (the node's own and a
peer's), the Vault activation in between, and the -insightexplorer -txindex -lightwalletd
combination the kogany harness gives its ycashd. Every mining call has its own deadline (DEADLINE), so a
regression fails that call instead of waiting on it forever.

Node 0: -lightwalletd. Node 1: plain. Node 2: -insightexplorer -txindex -lightwalletd.
"""

from decimal import Decimal

from test_framework.yellowback_util import YCASH_UPGRADE_ARGS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID,
    assert_equal,
    connect_nodes_bi,
    get_rpc_proxy,
    nuparams,
    rpc_url,
    start_nodes,
)

ACTIVATION = 110        # Vault activates past coinbase maturity, between the two sends
DEADLINE = 120          # seconds a single generate may take before the script calls it a hang
COIN = 10 ** 8


class YellowbackLightwalletdTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 3
        self.cache_behavior = 'clean'
        base = list(YCASH_UPGRADE_ARGS) + [nuparams(VAULT_BRANCH_ID, ACTIVATION)]
        self.node_args = [
            base + ['-experimentalfeatures', '-lightwalletd'],
            base,
            base + ['-experimentalfeatures', '-lightwalletd', '-insightexplorer', '-txindex'],
        ]

    def setup_network(self):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, self.node_args)
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 1, 2)
        connect_nodes_bi(self.nodes, 0, 2)
        self.is_network_split = False
        self.sync_all()

    def generate(self, i, n):
        # A fresh connection with its own timeout: a stalled node fails this call, not the suite.
        proxy = get_rpc_proxy(rpc_url(i), i, timeout=DEADLINE)
        hashes = proxy.generate(n)
        assert_equal(len(hashes), n)
        self.sync_all()
        return hashes

    def assert_indexed(self, txid, addr, zat, confirmed):
        for i in (0, 2):
            node = self.nodes[i]
            mempool = [e['txid'] for e in node.getaddressmempool({'addresses': [addr]})]
            if confirmed:
                assert txid not in mempool, (i, txid)
                assert txid in node.getaddresstxids({'addresses': [addr]}), (i, txid)
                assert_equal(node.getaddressbalance({'addresses': [addr]})['balance'], zat)
                utxos = node.getaddressutxos({'addresses': [addr]})
                assert txid in [u['txid'] for u in utxos], (i, txid)
            else:
                assert txid in mempool, (i, txid)
                assert txid not in node.getaddresstxids({'addresses': [addr]}), (i, txid)

    def send(self, frm, to_addr, amount):
        txid = self.nodes[frm].sendtoaddress(to_addr, amount)
        self.sync_all()
        for node in self.nodes:
            assert txid in node.getrawmempool(), txid
        return txid

    def run_test(self):
        lwd, plain, explorer = self.nodes
        assert 'lightwalletd' in lwd.getexperimentalfeatures()
        assert 'lightwalletd' in explorer.getexperimentalfeatures()

        # The reported hang: the first block a -lightwalletd node mines.
        self.generate(0, 1)
        self.generate(2, 1)
        assert_equal(plain.getblockcount(), 2)

        # Coinbase maturity, still before the upgrade.
        self.generate(0, 102)
        assert lwd.getblockcount() < ACTIVATION

        # Send from the -lightwalletd node's wallet; the -lightwalletd node mines it.
        a1 = plain.getnewaddress()
        t1 = self.send(0, a1, Decimal('1.5'))
        self.assert_indexed(t1, a1, 0, confirmed=False)
        self.generate(0, 1)
        self.assert_indexed(t1, a1, 150_000_000, confirmed=True)

        # Across the Vault activation.
        self.generate(0, ACTIVATION - lwd.getblockcount() + 1)
        assert_equal(lwd.getblockchaininfo()['consensus']['chaintip'], '%08x' % VAULT_BRANCH_ID)

        # A peer's block confirms a transaction the -lightwalletd nodes hold in their mempools.
        a2 = lwd.getnewaddress()
        t2 = self.send(1, a2, Decimal('1'))   # from the 1.5 YEC t1 paid it
        self.assert_indexed(t2, a2, 0, confirmed=False)
        self.generate(1, 1)
        self.assert_indexed(t2, a2, COIN, confirmed=True)

        # And again from the -lightwalletd node, mined by the explorer node.
        a3 = explorer.getnewaddress()
        t3 = self.send(0, a3, Decimal('0.25'))
        self.generate(2, 1)
        self.assert_indexed(t3, a3, 25_000_000, confirmed=True)

        self.generate(0, 2)
        tip = lwd.getbestblockhash()
        assert_equal(plain.getbestblockhash(), tip)
        assert_equal(explorer.getbestblockhash(), tip)


if __name__ == '__main__':
    YellowbackLightwalletdTest().main()
