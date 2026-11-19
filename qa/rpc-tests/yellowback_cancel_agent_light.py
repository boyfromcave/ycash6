#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The cancel-limit brake run by light seats only (beta4 item 3d, workspace docs/plans/beta4/price-feed.md section 2.3,
done-criteria B-8 and B-9): ``yellowback_cancel_agent.py``'s scenario, unchanged, with every member's agent on
``[backend] kind = "lightwalletd"``.

Each agent holds no node RPC. It reads the chain from two lightwalletd-dd servers on two different nodes (node 6 and
node 2, the "two regions"), signs its attestations, co-signatures and endpoint binding locally from its seat key file
(the member's hot key, the WIF ``dumpprivkey`` prints) under its own guard file, and builds the cancel, the
co-signature carrier and the on-chain "YF" fallback with ``yew-attestor`` (the YEW core), funded from the seat's own
P2PKH coins and sent through ``SendTransaction``. What the parent script asserts is asserted here: the wrong-price
claim cancelled with 1, then 2, then (gossip blocked, on-chain fallback only) 3 co-signatures, each within
CLAIM_DELAY, the leader's takeover, the reorg of the claim's block, and the honest claim left alone.

Needs three binaries, else it SKIPs: the agent (YELLOWBACK_ATTEST_BIN or the crate's target), a lightwalletd-dd with
the light attestor's calls and --yellowback-rate-burst (LIGHTWALLETD_BIN; four seats share one address here,
so the servers get a seat-sized budget, lightwalletd-dd docs/yellowback.md), and yew-attestor (YEW_ATTESTOR_BIN).
"""

import os
import socket
import subprocess
import time

from test_framework.yellowback_util import ATTESTOR_A, POOLS, USER, write_private
from test_framework.yellowback_attest import hot_wif_for
from test_framework.util import rpc_auth_pair, rpc_port
from yellowback_cancel_agent import AGENT_CONF, MEMBERS, YellowbackCancelAgentTest

LIGHT_NODES = (ATTESTOR_A, 2)       # one lightwalletd-dd on each: two servers on two nodes
INDEX_ARGS = ['-experimentalfeatures', '-insightexplorer', '-lightwalletd', '-txindex']
SEAT_COINS = 4                      # confirmed coins per seat: carriers, fees, fallback records
SEAT_COIN_YEC = 3

# The parent's [attest] / [transport] / [cancel] tables, with [backend] in place of [node].
LIGHT_CONF = """[backend]
kind = "lightwalletd"
lightwalletd = [%(endpoints)s]
key_file = "%(key)s"
yew_attestor = "%(yew)s"

""" + AGENT_CONF.split('[attest]', 1)[1].join(['[attest]', ''])


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class YellowbackCancelAgentLightTest(YellowbackCancelAgentTest):

    def __init__(self):
        super().__init__()
        self.lwd_bin = os.environ.get('LIGHTWALLETD_BIN')
        self.yew_bin = os.environ.get('YEW_ATTESTOR_BIN')
        self.lwd = []
        self.endpoints = []
        self.funded = False

    def node_args(self, i, extra=None):
        args = super().node_args(i, extra)
        return args + INDEX_ARGS if i in LIGHT_NODES else args

    def run_test(self):
        for name, path in (('LIGHTWALLETD_BIN', self.lwd_bin), ('YEW_ATTESTOR_BIN', self.yew_bin)):
            if not path or not os.access(path, os.X_OK):
                print('SKIP: %s is not set to an executable' % name)
                return
        try:
            super().run_test()
        finally:
            for p in self.lwd:
                if p.poll() is None:
                    p.terminate()
                    try:
                        p.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        p.kill()

    def start_lightwalletd(self, i):
        user, password = rpc_auth_pair(i)
        grpc, http = free_port(), free_port()
        data = os.path.join(self.workdir, 'lwd-%d' % i)
        os.makedirs(data, exist_ok=True)
        log = open(os.path.join(self.workdir, 'lwd-%d.out' % i), 'a')
        p = subprocess.Popen([self.lwd_bin, '--rpcuser', user, '--rpcpassword', password, '--rpchost', '127.0.0.1',
                              '--rpcport', str(rpc_port(i)), '--no-tls-very-insecure',
                              '--grpc-bind-addr', '127.0.0.1:%d' % grpc, '--http-bind-addr', '127.0.0.1:%d' % http,
                              '--data-dir', data, '--log-file', os.path.join(self.workdir, 'lwd-%d.log' % i),
                              '--yellowback', '--yellowback-rate-burst', '400', '--yellowback-rate-interval', '20ms'],
                             stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        log.close()
        deadline = time.time() + 60
        while True:
            assert p.poll() is None, 'lightwalletd on node %d exited; see %s' % (i, self.workdir)
            try:
                with socket.create_connection(('127.0.0.1', grpc), timeout=2):
                    break
            except OSError:
                assert time.time() < deadline, 'lightwalletd on node %d did not listen' % i
                time.sleep(0.5)
        self.lwd.append(p)
        self.endpoints.append('http://127.0.0.1:%d' % grpc)

    def seat_setup(self):
        """Once, before the first agent starts: two servers, a key file per member, the seats' own coins."""
        for i in LIGHT_NODES:
            self.start_lightwalletd(i)
        user = self.nodes[USER]
        rows = {r['seq']: r for r in user.yed_listattestors()}
        for seq in range(MEMBERS):
            write_private(os.path.join(self.workdir, 'seat-%d.key' % seq), hot_wif_for(user, seq) + '\n')
            for _ in range(SEAT_COINS):
                user.sendtoaddress(rows[seq]['bondKeyAddress'], SEAT_COIN_YEC)
        self.sync_all()
        self.mine(POOLS[0])
        self.sync_all()
        time.sleep(3)                       # the servers ingest the block
        print('   light seats: servers %s on nodes %r; %d x %d YEC on each seat address'
              % (', '.join(self.endpoints), LIGHT_NODES, SEAT_COINS, SEAT_COIN_YEC))
        self.funded = True

    def start_agent(self, seq, delivery='direct'):
        if not self.funded:
            self.seat_setup()
        conf = os.path.join(self.workdir, 'agent-%d.toml' % seq)
        write_private(conf, LIGHT_CONF % {
            'endpoints': ', '.join('"%s"' % e for e in self.endpoints),
            'key': os.path.join(self.workdir, 'seat-%d.key' % seq), 'yew': self.yew_bin,
            'seq': seq, 'ref_lag': 2, 'poll': 1, 'bus': os.path.join(self.workdir, 'bus'),
            'state': self.state_path(seq), 'delivery': delivery,
            'direct_key': os.path.join(self.workdir, 'direct-%d.key' % seq)})
        self.delivery[seq] = delivery
        log = open(os.path.join(self.workdir, 'agent-%d.log' % seq), 'a')
        self.procs[seq] = subprocess.Popen([self.agent, '--conf', conf, '--log-level', 'info', 'attest',
                                            '--mock-price', self.mock_path(seq)],
                                           stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                           start_new_session=True)
        log.close()


if __name__ == '__main__':
    YellowbackCancelAgentLightTest().main()
