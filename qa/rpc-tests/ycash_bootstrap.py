#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
ycash-bootstrap against a real node (testnet plan §4.4), the same on both node lines.

Node 0 mines a regtest chain; `ycash-bootstrap --pack` bundles heights 0..30 in the ycash-prefix/1
layout. A copy with one chunk changed by a byte is refused before any node starts. The real
bundle is restored into node 1's empty datadir (an isolated ycashd imports it with -loadblock and
the hashes are checked over RPC); node 1 then starts at block 30 with node 0's hash, a second
restore into the same datadir is refused, and node 1 follows node 0 once connected.
"""

import inspect
import json
import os
import shutil
import subprocess
import sys

import test_framework.util as util
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, connect_nodes, rpc_port, start_node, stop_node, sync_blocks

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BOOTSTRAP = os.path.join(REPO, "contrib", "bootstrap", "ycash-bootstrap")
LAST = 30


def framework_args():
    """What start_node adds on this line: the two -nuparams, and 6.20.0's 2025 acknowledgement."""
    extra = ["-nuparams=5ba81b19:1", "-nuparams=76b809bb:1"]
    flag = "-i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025"
    return extra + ([flag] if flag in inspect.getsource(util.start_node) else [])


class YcashBootstrapTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True   # v4.5.0 harness
        self.cache_behavior = 'clean'   # 6.20.0 harness (each harness ignores the other's)

    def setup_network(self, split=False):
        self.nodes = [start_node(0, self.options.tmpdir), None]
        self.is_network_split = True

    def bootstrap(self, *argv):
        binary = os.getenv("ZCASHD") or os.getenv("BITCOIND")
        cli = os.path.join(os.path.dirname(binary), "ycash-cli")
        command = [sys.executable, "-I", BOOTSTRAP, "--network", "regtest", "--cli", cli, "--ycashd", binary, "--poll", "0.5"] + list(argv)
        return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=600)

    def run_test(self):
        tmp = self.options.tmpdir
        n0 = self.nodes[0]
        n0.generate(LAST)
        bundle = os.path.join(tmp, "bundle")
        packed = self.bootstrap("--datadir", os.path.join(tmp, "node0"), "--rpcport", str(rpc_port(0)), "--pack", bundle, "--last-height", str(LAST))
        assert_equal(packed.returncode, 0)
        manifest = json.load(open(os.path.join(bundle, "manifest.json")))
        assert_equal(manifest["format"], "ycash-prefix/1")
        assert_equal(manifest["hashes"][str(LAST)], n0.getblockhash(LAST))

        # A changed chunk is refused before any node starts.
        bad = os.path.join(tmp, "bad")
        shutil.copytree(bundle, bad)
        chunk = [n for n in os.listdir(bad) if n.endswith(".blocks.gz")][0]
        with open(os.path.join(bad, chunk), "ab") as f:
            f.write(b"\0")
        refused = self.bootstrap("--datadir", os.path.join(tmp, "badnode"), "--source", bad)
        assert_equal(refused.returncode, 2)
        assert "sha256" in refused.stderr, refused.stderr
        assert not os.path.exists(os.path.join(tmp, "badnode", "regtest"))

        # The bundle restored into node 1's empty datadir by a real import.
        node1 = os.path.join(tmp, "node1")
        node_args = ["--node-arg=%s" % a for a in framework_args()]
        restored = self.bootstrap("--datadir", node1, "--conf", os.path.join(node1, "ycash.conf"), "--source", bundle, *node_args)
        assert_equal(restored.returncode, 0)
        record = json.load(open(os.path.join(node1, "regtest", "bootstrap.json")))
        assert_equal(record["tip"], n0.getblockhash(LAST))
        assert_equal(record["import"]["checked"], 2)
        assert not os.path.exists(os.path.join(node1, "bootstrap-work"))

        self.nodes[1] = start_node(1, tmp)
        assert_equal(self.nodes[1].getblockcount(), LAST)
        assert_equal(self.nodes[1].getbestblockhash(), n0.getbestblockhash())

        # A datadir with a chain is never restored over.
        stop_node(self.nodes[1], 1)
        again = self.bootstrap("--datadir", node1, "--conf", os.path.join(node1, "ycash.conf"), "--source", bundle, *node_args)
        assert_equal(again.returncode, 2)
        assert "already holds a chain" in again.stderr, again.stderr

        # The restored node follows the chain.
        self.nodes[1] = start_node(1, tmp)
        connect_nodes(self.nodes[1], 0)
        n0.generate(2)
        sync_blocks(self.nodes)
        assert_equal(self.nodes[1].getblockcount(), LAST + 2)


if __name__ == '__main__':
    YcashBootstrapTest().main()
