#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
A stale Yugen transaction costs its relaying peer no back-off (doc/yugen-node.md, Relay budget).

A confirmed Yugen leaf keeps no coin a node can find (a deposit has no transparent output, and a
leaf confirmed inside a bundle is not in any block by its txid), so `AlreadyHave` misses it and the
two-minute AskFor retry still fetches it from an honest peer that announced it earlier. The node then
refuses it by the cheap checks (`bad-yugen-nullifier-spent`, no helper run). Counting that refusal
started the peer's back-off, and the peer's next real Yugen transaction waited for the next AskFor
retry, two minutes later (spend_matrix: `Mempool sync failed` on the yewd backend).

The leaves are real deposits made by the Yugen wallet engine (YEWD_YUGEN) with both wallet proofs.
Node 0 builds the chain and the leaves; node 1 is fed blocks by hand and one P2P peer (a probe):

- a confirmed leaf from the probe is refused, and the probe's next leaf is taken at once;
- a leaf whose helper run fails (a local fault, not a verdict) starts no back-off: the probe's next
  leaf is taken at once;
- a guard: a leaf refused by the helper (a proof byte flipped) still starts the back-off, so the
  probe's honest copy right after it is not judged.
"""

import json
import os
import re
import subprocess
import tempfile
import time

from test_framework.mininode import NetworkThread, NodeConn
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port, rpc_auth_pair, rpc_port, start_nodes
from tx_expiry_helper import TestNode
from yugen_bundle import ARGS, HELPER, WALLET
from yugen_strip import PROTO, msg_rawtx


class YugenStaleRelayTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self, split=False):
        # No node links: node 1 hears of transactions from the probe only. Node 1's helper fails its
        # proof checks while the flag file exists (a local fault, as a crash or a timeout).
        self.flag = os.path.join(self.options.tmpdir, 'helper-fails')
        faulty = os.path.join(self.options.tmpdir, 'faulty-helper.sh')
        with open(faulty, 'w') as f:
            f.write('#!/bin/sh\ncase "$1" in verify) [ -e "%s" ] && exit 1;; esac\nexec "%s" "$@"\n' % (self.flag, HELPER))
        os.chmod(faulty, 0o755)
        args1 = [a for a in ARGS if not a.startswith('-yugenverifier=')] + ['-yugenverifier=' + faulty]
        self.nodes = start_nodes(2, self.options.tmpdir, [ARGS + ['-debug=mempool'], args1 + ['-debug=mempool']])
        self.is_network_split = False

    def wallet(self, *args):
        u, p = rpc_auth_pair(0)
        r, w = os.pipe()
        os.write(w, ('45' * 32 + '\n').encode())
        os.close(w)
        try:
            out = subprocess.run([WALLET, '-network=regtest', '-node=127.0.0.1:%d' % rpc_port(0), '-rpcuser=' + u,
                                  '-rpcpassword=' + p, '-datadir=' + self.wdir, '-seedfd=3'] + list(args),
                                 capture_output=True, text=True, timeout=1800, pass_fds=(3,),
                                 preexec_fn=lambda: os.dup2(r, 3))
        finally:
            os.close(r)
        assert out.returncode == 0, (args[:1], out.stdout, out.stderr[-2000:])
        return json.loads(out.stdout)

    def wait(self, cond, timeout=60):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if cond():
                return True
            time.sleep(0.2)
        return False

    def feed(self):
        n0, n1 = self.nodes
        for h in range(n1.getblockcount() + 1, n0.getblockcount() + 1):
            assert n1.submitblock(n0.getblock(n0.getblockhash(h), 0)) in (None, 'duplicate'), h
        assert_equal(n1.getbestblockhash(), n0.getbestblockhash())

    def leaves(self, dep, n):
        """n deposit leaves with both wallet proofs, built at one tip, in node 0's pool."""
        n0 = self.nodes[0]
        funds = [n0.sendtoaddress(dep, 2) for _ in range(n)]
        n0.generate(1)
        out = []
        for fund in funds:
            r = self.wallet('shield', json.dumps([fund]))
            txid = r if isinstance(r, str) else r['txid']
            out.append((txid, n0.getrawtransaction(txid)))
        return out

    def run_test(self):
        n0, n1 = self.nodes
        self.wdir = tempfile.mkdtemp(prefix='yewd-yugen-', dir=self.options.tmpdir)
        n0.generate(140)
        assert self.wait(lambda: n0.getbalance() > 10)        # the wallet learns of blocks asynchronously
        dep = self.wallet('depositaddress')
        dep = dep if isinstance(dep, str) else dep['address']

        # A leaf confirmed on both nodes: its nullifiers are spent, and it left no coin.
        [(stale, stale_hex)] = self.leaves(dep, 1)
        blk = n0.generate(1)[0]
        assert stale in n0.getblock(blk)['tx']
        (fresh, fresh_hex), (third, third_hex), (fault, fault_hex), (after, after_hex) = self.leaves(dep, 4)
        self.feed()
        assert_equal(n1.getrawmempool(), [])

        probe = TestNode()
        probe.add_connection(NodeConn('127.0.0.1', p2p_port(1), n1, probe, 'regtest', PROTO))
        NetworkThread().start()
        probe.wait_for_verack()

        # 1. The stale leaf, as an honest peer serves it on the AskFor retry, then a real one.
        probe.send_message(msg_rawtx(bytes.fromhex(stale_hex)))
        probe.sync_with_ping(timeout=120)                    # judged before the ping is answered
        assert stale not in n1.getrawmempool()
        probe.send_message(msg_rawtx(bytes.fromhex(fresh_hex)))
        probe.sync_with_ping(timeout=120)
        assert fresh in n1.getrawmempool(), 'the leaf after a stale one was deferred (back-off)'
        peers = n1.getpeerinfo()
        assert_equal(len(peers), 1)
        assert_equal(peers[0].get('banscore', 0), 0)

        # 2. A helper run that fails is the node's fault, not a verdict: the probe's next leaf is taken.
        open(self.flag, 'w').close()
        probe.send_message(msg_rawtx(bytes.fromhex(fault_hex)))
        probe.sync_with_ping(timeout=120)
        assert fault not in n1.getrawmempool()
        os.remove(self.flag)
        probe.send_message(msg_rawtx(bytes.fromhex(after_hex)))
        probe.sync_with_ping(timeout=120)
        assert after in n1.getrawmempool(), 'the leaf after a helper fault was deferred (back-off)'

        # 3. Guard: a leaf the helper refuses (the last proof byte flipped) still starts the back-off.
        b = bytearray(bytes.fromhex(third_hex))
        b[-1] ^= 0x01
        probe.send_message(msg_rawtx(bytes(b)))
        probe.sync_with_ping(timeout=120)
        assert third not in n1.getrawmempool()
        probe.send_message(msg_rawtx(bytes.fromhex(third_hex)))
        probe.sync_with_ping(timeout=120)
        assert third not in n1.getrawmempool(), 'a judged refusal no longer starts the back-off'
        with open(os.path.join(self.options.tmpdir, 'node1', 'regtest', 'debug.log')) as f:
            log = f.read()
        assert re.search(r'Yugen tx %s from peer=\d+ deferred \(1 refusals in a row\)' % third, log), 'not deferred'


if __name__ == '__main__':
    YugenStaleRelayTest().main()
