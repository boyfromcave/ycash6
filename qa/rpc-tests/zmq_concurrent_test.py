#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

#
# Regression test: the ZMQ publishers are driven from more than one thread
# (UpdatedBlockTip from the thread that activates the chain, SyncTransaction
# from ThreadNotifyWallets) and, when two topics name one address, share one
# PUB socket. libzmq sockets are not thread-safe: two concurrent sends corrupt
# the socket's outgoing pipe and the libzmq io thread aborts the node
# ("Assertion failed: check () (src/msg.cpp)" / "rc == 0 (src/pipe.cpp)"),
# but only while a subscriber is connected (a PUB socket with no subscriber
# never touches a pipe). This test keeps a subscriber attached and makes the
# two publishing threads send as densely as possible against each other:
# one RPC thread invalidates and reconsiders a window of transaction-heavy
# blocks (one hashblock per reconnected block) while ThreadNotifyWallets
# publishes a hashtx for every disconnected, re-added and reconnected
# transaction, and a second RPC thread keeps the mempool busy. The node
# must still answer at the end. Serialization lives in
# CZMQAbstractPublishNotifier::SendMessage (src/zmq/zmqpublishnotifier.cpp).
#

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal, assert_greater_than, start_nodes, get_rpc_proxy, rpc_url,
    bitcoind_processes, PORT_MIN, PORT_RANGE, MAX_NODES, PortSeed,
)

import os
from decimal import Decimal
import struct
import threading
import time
import zmq

# A third port band, next to the framework's p2p and rpc bands, so parallel
# runs with different --portseed values do not share an endpoint.
def zmq_port(n):
    return PORT_MIN + 2 * PORT_RANGE + n + (MAX_NODES * PortSeed.n) % (PORT_RANGE - 1 - MAX_NODES)

# Shape of the load. The window is BLOCKS blocks of TXS_PER_BLOCK wallet
# transactions each; one cycle disconnects and reconnects the whole window.
BLOCKS = 20
TXS_PER_BLOCK = 15
# Wall-clock budget of the stress phase; ZMQ_STRESS_SECONDS overrides it.
DURATION = float(os.environ.get("ZMQ_STRESS_SECONDS", "60"))
# RPC threads churning the window (ZMQ_STRESS_BLOCK_WORKERS overrides it). One
# is the devnet's shape (hashblock from one chain-activating thread, hashtx from
# ThreadNotifyWallets) and already shows the defect; two or more concurrent
# invalidateblock/reconsiderblock callers can instead trip a stock race in
# ActivateBestChain (assert in PruneBlockIndexCandidates, seen on 6.20.0 with
# three), which is not what this test is about.
BLOCK_WORKERS = int(os.environ.get("ZMQ_STRESS_BLOCK_WORKERS", "1"))
# Extra node arguments a line needs (ycash6: '-allowdeprecated=getnewaddress').
EXTRA_NODE_ARGS = ['-allowdeprecated=getnewaddress']


class ZMQConcurrentTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.setup_clean_chain = False

    def setup_nodes(self):
        self.zmq_url = "tcp://127.0.0.1:%d" % zmq_port(0)
        self.zmqContext = zmq.Context()
        self.zmqSubSocket = self.zmqContext.socket(zmq.SUB)
        self.zmqSubSocket.setsockopt(zmq.RCVHWM, 0)
        self.zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashblock")
        self.zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashtx")
        self.zmqSubSocket.connect(self.zmq_url)
        self.counts = {b"hashblock": 0, b"hashtx": 0}
        self.bad_frames = 0
        self.bad_samples = []
        self.stop_drain = threading.Event()
        self.drain = threading.Thread(target=self.drain_loop, daemon=True)
        self.drain.start()
        # Both topics on ONE endpoint, as the devnet and chain-viz use it: the
        # two notifiers then share a single PUB socket.
        return start_nodes(self.num_nodes, self.options.tmpdir, extra_args=[
            ['-zmqpubhashtx=' + self.zmq_url, '-zmqpubhashblock=' + self.zmq_url] + EXTRA_NODE_ARGS,
        ])

    def setup_network(self, split=False):
        self.nodes = self.setup_nodes()
        self.is_network_split = False
        self.sync_all()

    def drain_loop(self):
        poller = zmq.Poller()
        poller.register(self.zmqSubSocket, zmq.POLLIN)
        while not self.stop_drain.is_set():
            if not poller.poll(100):
                continue
            msg = self.zmqSubSocket.recv_multipart()
            if len(msg) != 3 or msg[0] not in self.counts or len(msg[1]) != 32 or len(msg[2]) != 4:
                # Parts of two messages interleaved: the two publishing
                # threads wrote the socket at once.
                self.bad_frames += 1
                if len(self.bad_samples) < 5:
                    self.bad_samples.append([(m[:12], len(m)) for m in msg])
                continue
            struct.unpack('<I', msg[2])
            self.counts[msg[0]] += 1

    def node_alive(self):
        rc = bitcoind_processes[0].poll()
        if rc is not None:
            raise AssertionError("ycashd exited with code %r during the zmq stress (see debug.log and the system crash reports)" % rc)

    def run_test(self):
        node = self.nodes[0]
        addr = node.getnewaddress()

        # Build the window: BLOCKS blocks, each with TXS_PER_BLOCK transactions.
        # Fund one confirmed UTXO per transaction first (one sendmany, so the
        # wallet cannot re-select earlier outputs as inputs), then spend each
        # with its own raw transaction: nothing depends on coin selection.
        total = BLOCKS * TXS_PER_BLOCK
        addrs = [node.getnewaddress() for i in range(total)]
        node.sendmany("", dict((a, Decimal("0.01")) for a in addrs))
        node.generate(1)
        self.sync_all()   # regtest: waits until the wallet has been notified of the block
        utxos = node.listunspent(1, 9999999, addrs)
        assert_equal(len(utxos), total)
        window_txs = 0
        for b in range(BLOCKS):
            for u in utxos[b * TXS_PER_BLOCK:(b + 1) * TXS_PER_BLOCK]:
                raw = node.createrawtransaction([{"txid": u["txid"], "vout": u["vout"]}], {addr: Decimal("0.0099")})
                signed = node.signrawtransaction(raw)
                assert_equal(signed["complete"], True)
                node.sendrawtransaction(signed["hex"])
                window_txs += 1
            node.generate(1)
            self.sync_all()
        tip = node.getbestblockhash()
        base = node.getblockhash(node.getblockcount() - BLOCKS + 1)
        assert_equal(window_txs, total)
        assert_equal(len(node.getblock(tip)["tx"]), TXS_PER_BLOCK + 1)
        print("window: %d blocks, %d transactions" % (BLOCKS, window_txs))

        # The subscriber must really be attached, or the test proves nothing:
        # wait for the window's hashblocks to arrive.
        deadline = time.time() + 30
        while self.counts[b"hashblock"] < BLOCKS and time.time() < deadline:
            time.sleep(0.1)
        assert_greater_than(self.counts[b"hashblock"] + 1, BLOCKS)
        print("subscriber attached: %d hashblock, %d hashtx so far" % (self.counts[b"hashblock"], self.counts[b"hashtx"]))

        errors = []
        stop = threading.Event()
        cycles = [0]
        sends = [0]

        def blocks_worker():
            # UpdatedBlockTip from this RPC thread: one hashblock per block of
            # the window on every reconsiderblock.
            rpc = get_rpc_proxy(rpc_url(0), 0, timeout=120)
            try:
                while not stop.is_set():
                    rpc.invalidateblock(base)
                    rpc.reconsiderblock(base)
                    cycles[0] += 1
            except Exception as e:
                errors.append(("blocks", e))
                stop.set()

        def mempool_worker():
            # Keeps DrainRecentlyAdded non-empty on every ThreadNotifyWallets
            # tick (hashtx from that thread) and the wallet busy.
            rpc = get_rpc_proxy(rpc_url(0), 0, timeout=120)
            try:
                while not stop.is_set():
                    try:
                        rpc.sendtoaddress(addr, 0.0001)
                        sends[0] += 1
                    except Exception as e:
                        # Insufficient funds / mempool conflicts during the
                        # reorg churn are fine; a dead node is not.
                        if "Connection" in str(e) or "connection" in str(e) or "Broken pipe" in str(e):
                            raise
                        time.sleep(0.01)
            except Exception as e:
                errors.append(("mempool", e))
                stop.set()

        workers = [threading.Thread(target=blocks_worker) for i in range(BLOCK_WORKERS)]
        workers.append(threading.Thread(target=mempool_worker))
        for w in workers:
            w.start()
        t_end = time.time() + DURATION
        while time.time() < t_end and not stop.is_set():
            time.sleep(0.5)
            self.node_alive()
        stop.set()
        for w in workers:
            w.join()
        self.node_alive()
        if errors:
            raise AssertionError("worker failed: %r" % (errors,))

        # The node is still here and consistent.
        assert_equal(node.getbestblockhash(), tip)
        # Let the last ThreadNotifyWallets tick drain, then check the stream.
        time.sleep(2)
        self.stop_drain.set()
        self.drain.join()
        print("cycles=%d mempool sends=%d received hashblock=%d hashtx=%d bad frames=%d" % (
            cycles[0], sends[0], self.counts[b"hashblock"], self.counts[b"hashtx"], self.bad_frames))
        assert_greater_than(cycles[0], 0)
        if self.bad_frames:
            print("corrupted frames, first samples (prefix, length) per part: %r" % (self.bad_samples,))
        assert_equal(self.bad_frames, 0)
        # The reconnected blocks were published again (a PUB socket may drop
        # frames at its high-water mark, so only a floor is asserted).
        assert_greater_than(self.counts[b"hashblock"], 2 * BLOCKS)


if __name__ == '__main__':
    ZMQConcurrentTest().main()
