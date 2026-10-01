#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
chain-viz against the node (docs/plans/chain-viz-plan.md C5): the read-only observer's HTTP API
checked against the nodes' own RPCs on a three-node regtest.

Three pool nodes (every one enforcing, signalling, quoting $50), ZMQ ``hashblock``/``hashtx``
published by each on one endpoint (C-F-1), then the ``chain-viz`` binary on ``--nodes`` with
``--record``.  The test then

  a. reads ``/api/health``: the majority tip is ``getbestblockhash`` and all three nodes agree;
  b. mines one block and sees a ``block`` event for it within 3 s (the ZMQ wake, else the 1 s poll);
  c. mints from the wallet (``yed_mint``, the two-step carrier flow -- the TEST mints, chain-viz
     never does) and sees the mint in ``/api/snapshot.mempool.txs[].yb`` as ``type == "mint"``
     before it is mined and in ``/api/yellowback.txs`` with its height after;
  d. forces a reorg (``invalidateblock`` on node 2, three blocks on the parent, the others follow)
     and sees a ``reorg`` event and the orphaned block in ``chain.side``;
  e. rolls the revenue ledger up (``/api/revenue?from=0&to=<tip>&by=payoutKey``, C4) and compares
     ``totals.enforcefee`` with the sum of ``yed_gettxinfo(txid).feeZat`` over the transactions the
     test made, and the ``enforcefee`` rows are those transactions at their payees;
  f. holds chain-viz to the plan's RPC budget (section 7) from ``/api/health.rpcCalls``: per node
     ``getrawmempool`` at most one per poll (+ the ZMQ wakes), ``getblock`` at most once per block
     it learned (the 20-block backfill included), ``yed_gettxinfo`` at most once per Yellowback tx;
  g. checks the session file: line 1 the ``session`` header, one line per event up to
     ``/api/health.seq``.

Needs the chain-viz binary: ``CHAINVIZ_BIN`` names it (the fork's CI builds boyfromcave/chain-viz
and sets it; ``<workspace>/chain-viz/target/release/chain-viz`` is the fallback); without one the
script SKIPs (exit 0 with a message) so the inherited matrix does not break.  chain-viz is
stopped (SIGTERM) on every exit path.

Ports follow ``--portseed`` the way ``contrib/yellowback/devnet/yellowback-devnet`` lays them out
(C-F-3): zmq ``31000 + 12 * (seed % 140) + n``, chain-viz ``32680 + seed % 88``; both below 32768,
where Linux's ephemeral range starts.
"""

import json
import os
import subprocess
import time
import urllib.error
import urllib.request

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    MAX_NODES,
    PortSeed,
    assert_equal,
    connect_nodes_bi,
    rpc_auth_pair,
    rpc_port,
    start_nodes,
    sync_blocks,
    sync_mempools,
)
from test_framework.yellowback_util import (
    ACTIVATION_BLOCKS,
    POOL_WIFS,
    REF_LAG,
    address_of,
    pool_args,
    round_robin_schedule,
    set_quote,
)
from test_framework.yellowback_attest import wallet_mint

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, '..', '..'))
WORKSPACE = os.path.dirname(REPO)
if os.path.basename(WORKSPACE) == 'wt':                      # a worktree: wt/<name>/ -> the workspace
    WORKSPACE = os.path.dirname(WORKSPACE)
NODES = 3
QUOTE_USD = 50
ZMQ_PORT_BASE, ZMQ_SEED_PERIOD = 31000, 140                  # yellowback-devnet's zmq_port()
CHAINVIZ_PORT_BASE, CHAINVIZ_SEED_PERIOD = 32680, 88         # yellowback-devnet's chainviz_port()
BACKFILL = 20                                                # chain-viz walks this many blocks on start
START_TIMEOUT = 30
EVENT_TIMEOUT = 3                                            # (b): a block event within 3 s
MODEL_TIMEOUT = 15                                           # (c)/(d): the 1 s poll plus the enrichment sweep


def find_chainviz():
    """CHAINVIZ_BIN, else the workspace build beside the fork; None means SKIP."""
    override = os.environ.get('CHAINVIZ_BIN')
    if override:
        path = os.path.expanduser(override)
        return path if os.access(path, os.X_OK) else None
    candidate = os.path.join(WORKSPACE, 'chain-viz', 'target', 'release', 'chain-viz')
    return candidate if os.access(candidate, os.X_OK) else None


def zmq_url(n):
    return 'tcp://127.0.0.1:%d' % (ZMQ_PORT_BASE + MAX_NODES * (PortSeed.n % ZMQ_SEED_PERIOD) + n)


def chainviz_port():
    return CHAINVIZ_PORT_BASE + PortSeed.n % CHAINVIZ_SEED_PERIOD


def wait_for(predicate, timeout, what, interval=0.25):
    """Poll ``predicate`` until it returns a truthy value; that value, else AssertionError."""
    deadline = time.time() + timeout
    while True:
        value = predicate()
        if value:
            return value
        if time.time() > deadline:
            raise AssertionError('timed out after %ss waiting for %s' % (timeout, what))
        time.sleep(interval)


# Rule: MINT-1 FEE-1
class YellowbackChainVizTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = NODES
        self.setup_clean_chain = True
        self.chainviz = None
        self.proc = None
        self.started_at = None
        self.start_height = None     # the tip when chain-viz started
        self.yb_txids = []           # the Yellowback transactions this test made
        self.pool_addresses = [address_of(w) for w in POOL_WIFS[:NODES]]

    def setup_network(self, split=False):
        args = [pool_args(self.pool_addresses[i], ['-zmqpubhashblock=%s' % zmq_url(i), '-zmqpubhashtx=%s' % zmq_url(i)])
                for i in range(NODES)]
        self.nodes = start_nodes(NODES, self.options.tmpdir, extra_args=args)
        for i in range(NODES):
            self.nodes[i].importprivkey(POOL_WIFS[i], 'yellowback-payout', False)
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 1, 2)
        connect_nodes_bi(self.nodes, 0, 2)
        self.is_network_split = False
        self.sync_all()

    # the helpers wallet_mint/two_step expect on the test object (yellowback_attest.py)
    def _node(self, n):
        return self.nodes[n] if isinstance(n, int) else n

    def sync_all(self, blocks_only=False):
        sync_blocks(self.nodes)
        if not blocks_only:
            sync_mempools(self.nodes)

    def mine(self, i, n=1):
        hashes = self.nodes[i].generate(n)
        self.sync_all(blocks_only=True)
        return hashes

    # ------------------------------------------------------------------ chain-viz

    def start_chainviz(self):
        urls = ['http://%s:%s@127.0.0.1:%d' % (rpc_auth_pair(i) + (rpc_port(i),)) for i in range(NODES)]
        record = os.path.join(self.options.tmpdir, 'chain-viz')
        os.makedirs(record, exist_ok=True)
        argv = [self.chainviz, '--nodes', ','.join(urls), '--listen', '127.0.0.1:%d' % chainviz_port(),
                '--record', record, '--log', 'debug'] + ['--zmq=%d=%s' % (i, zmq_url(i)) for i in range(NODES)]
        log = open(os.path.join(self.options.tmpdir, 'chain-viz.log'), 'ab')
        print('starting %s' % ' '.join(a.replace(rpc_auth_pair(0)[1], '***') for a in argv))
        self.proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=log)
        self.started_at = time.time()
        self.start_height = self.nodes[0].getblockcount()
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise AssertionError('chain-viz exited %s at start; see %s' % (self.proc.returncode, log.name))
            line = self.proc.stdout.readline().decode('utf-8', 'replace').strip()
            if line.startswith('listening on '):
                self.url = line[len('listening on '):]
                print('chain-viz: %s (record %s, log %s)' % (self.url, record, log.name))
                return record
            if not line:
                time.sleep(0.2)
        raise AssertionError('chain-viz printed no `listening on` line in %d s; see %s' % (START_TIMEOUT, log.name))

    def stop_chainviz(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None

    def api(self, path):
        """GET <url><path> as JSON; None on a 404."""
        try:
            with urllib.request.urlopen(self.url + path, timeout=10) as reply:
                return json.load(reply)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise

    def events(self, kind, since=0):
        return [e for e in self.api('/api/events?since=%d' % since) if e.get('kind') == kind]

    # ------------------------------------------------------------------ the checks

    def check_health(self):
        best = self.nodes[0].getbestblockhash()
        # the head moves inside a node's step and `up` is set after it returns: wait for both
        health = wait_for(lambda: (lambda h: h if h['tip'] and h['tip']['hash'] == best and h['agreeing'] == NODES and h['nodesUp'] == NODES else None)(self.api('/api/health')),
                          MODEL_TIMEOUT, 'health tip %s agreed by %d nodes, all up' % (best[:12], NODES))
        assert_equal(health['ok'], True)
        assert_equal(health['nodes'], NODES)
        assert_equal(health['nodesUp'], NODES)
        assert_equal(health['tip']['height'], self.nodes[0].getblockcount())
        assert_equal(health['chain'], 'regtest')
        print('(a) health: tip %d %s, %d/%d agreeing, seq %d' % (health['tip']['height'], best[:12], health['agreeing'], NODES, health['seq']))
        return health

    def check_block_event(self):
        seq = self.api('/api/health')['seq']
        t0 = time.time()
        block_hash = self.nodes[1].generate(1)[0]
        wait_for(lambda: [e for e in self.events('block', seq) if e['hash'] == block_hash], EVENT_TIMEOUT, 'a block event for %s' % block_hash[:12])
        print('(b) block event for %s after %.2f s' % (block_hash[:12], time.time() - t0))
        self.sync_all(blocks_only=True)

    def mempool_yb(self, txid):
        snap = self.api('/api/snapshot')
        for tx in snap['mempool']['txs']:
            if tx['txid'] == txid and tx.get('yb'):
                return tx['yb']
        return None

    def confirmed_yb(self, txid):
        doc = self.api('/api/yellowback')
        for tx in doc['yellowback']['txs']:
            if tx['txid'] == txid and tx.get('height'):
                return tx
        return None

    def check_mint(self, node_index, cents, lock_blocks):
        node = self.nodes[node_index]
        mint = wallet_mint(self, node, cents, lock_blocks)     # the carrier's block is mined on node 2 by two_step
        txid = mint['txid']
        self.yb_txids.append(txid)
        assert txid in node.getrawmempool(), 'the mint is not in the mempool after the two-step flow'
        yb = wait_for(lambda: self.mempool_yb(txid), MODEL_TIMEOUT, 'the mint %s in /api/snapshot.mempool' % txid[:12])
        assert_equal(yb['type'], 'mint')
        assert_equal(yb.get('wouldBeRejected', False), False)
        print('(c) mint %s: mempool yb.type=%s verdict=%r feeZat=%s' % (txid[:12], yb['type'], yb.get('verdict'), yb.get('feeZat')))
        self.mine(node_index)
        confirmed = wait_for(lambda: self.confirmed_yb(txid), MODEL_TIMEOUT, 'the mint %s in /api/yellowback.txs' % txid[:12])
        info = node.yed_gettxinfo(txid)
        assert_equal(confirmed['height'], info['height'])
        assert_equal(confirmed['type'], 'mint')
        assert_equal(confirmed['feeZat'], info['feeZat'])
        assert_equal(confirmed.get('payee'), info.get('payee'))
        print('(c) mint %s confirmed at %d, feeZat %d, payee %s' % (txid[:12], confirmed['height'], info['feeZat'], info.get('payee')))
        return mint

    def check_reorg(self):
        # a block with no Yellowback transaction is orphaned so the ledger of (e) is not disturbed
        self.mine(0, 2)
        old_tip = self.nodes[2].getbestblockhash()
        seq = self.api('/api/health')['seq']
        self.nodes[2].invalidateblock(old_tip)
        new_hashes = self.nodes[2].generate(3)
        sync_blocks(self.nodes)
        assert_equal(self.nodes[0].getbestblockhash(), new_hashes[-1])
        reorgs = wait_for(lambda: [e for e in self.events('reorg', seq) if e['from'] == old_tip], MODEL_TIMEOUT, 'a reorg event from %s' % old_tip[:12])
        # a poll can land between the three blocks, so `to` is whichever of them the node had
        assert reorgs[0]['to'] in new_hashes, (reorgs[0], new_hashes)
        assert reorgs[0]['depth'] >= 1, reorgs[0]
        side = wait_for(lambda: [b for b in self.api('/api/snapshot')['chain']['side'] if b['hash'] == old_tip], MODEL_TIMEOUT, '%s in chain.side' % old_tip[:12])
        assert side[0]['status'] in ('orphaned', 'side'), side[0]
        print('(d) reorg: %s orphaned (%s), %d reorg event(s) on nodes %s, tip now %s' % (old_tip[:12], side[0]['status'], len(reorgs), sorted(e.get('node') for e in reorgs), new_hashes[-1][:12]))
        self.check_health()

    def check_revenue(self):
        """C4: the ledger rolled up over the whole chain; the enforcement fees it attributes are
        exactly the fees the Yellowback transactions this test made paid (`yed_gettxinfo.feeZat`),
        and every one of them is an `enforcefee` row at the mint's payee."""
        tip = self.nodes[0].getblockcount()
        doc = wait_for(lambda: (lambda d: d if d and d['tip'] and d['tip']['height'] == tip else None)(self.api('/api/revenue?from=0&to=%d&by=payoutKey' % tip)),
                       MODEL_TIMEOUT, '/api/revenue at tip %d' % tip)
        assert_equal((doc['from'], doc['to'], doc['by']), (0, tip, 'payoutKey'))
        infos = {t: self.nodes[0].yed_gettxinfo(t) for t in self.yb_txids}
        expected = sum(i['feeZat'] for i in infos.values())
        totals = doc['totals']
        assert_equal(totals['enforcefee']['zat'], expected)
        assert_equal(totals['ybTxs'], len(self.yb_txids))
        # the ledger holds what the model holds: the BACKFILL below the head at start, that head, and every main-chain block since
        assert_equal(totals['blocks'], tip - self.start_height + BACKFILL + 1)
        fee_rows = [r for r in doc['rows'] if r['kind'] == 'enforcefee']
        assert_equal(sorted((r['txid'], r['zat'], r['payee']) for r in fee_rows),
                     sorted((t, i['feeZat'], i['payee']) for t, i in infos.items()))
        assert_equal(doc['rowsTruncated'], False)
        print('(e) revenue 0..%d by payoutKey: enforcefee %d zat == sum of %d yed_gettxinfo.feeZat; %d groups, %d rows, subsidy %d zat'
              % (tip, totals['enforcefee']['zat'], len(self.yb_txids), len(doc['groups']), len(doc['rows']), totals['subsidy']['zat']))

    def check_budget(self):
        """Plan section 7: per node one ``getrawmempool`` per wake (a poll tick, a ZMQ ``hashblock``, a
        ZMQ ``hashtx`` -- the node publishes one per transaction entering its mempool and one per
        transaction of every connected block, coinbases included), ``getblock`` once per block it
        learned (the backfill of BACKFILL below the head at start, the head itself, every block
        since, the orphaned one) and ``getblocksubsidy`` the same (C4's ledger, once per block),
        ``yed_gettxinfo`` once per Yellowback transaction."""
        health = self.api('/api/health')
        elapsed = time.time() - self.started_at
        node = self.nodes[0]
        tip = node.getblockcount()
        blocks_since = tip - self.start_height + 1                          # + the orphaned block
        txs_since = sum(len(node.getblock(str(h))['tx']) for h in range(self.start_height + 1, tip + 1)) + 1
        mempool_arrivals = 2 * len(self.yb_txids)                           # a carrier and a mint each
        wakes = int(elapsed) + 1 + blocks_since + txs_since + mempool_arrivals
        calls = health['rpcCalls']
        print('(f) rpcCalls after %.0f s, %d blocks and %d txs since start (at most %d wakes): %s'
              % (elapsed, blocks_since, txs_since, wakes, json.dumps(calls, sort_keys=True)))
        for node in map(str, range(NODES)):
            c = calls[node]
            assert c.get('getrawmempool', 0) <= wakes + 2, 'node %s: %d getrawmempool > %d wakes + 2' % (node, c.get('getrawmempool', 0), wakes)
            assert c.get('getblock', 0) <= blocks_since + BACKFILL + 2, 'node %s: %d getblock > %d blocks since start + backfill %d + 2' % (node, c.get('getblock', 0), blocks_since, BACKFILL)
            assert c.get('getblocksubsidy', 0) <= blocks_since + BACKFILL + 2, 'node %s: %d getblocksubsidy > %d blocks since start + backfill %d + 2' % (node, c.get('getblocksubsidy', 0), blocks_since, BACKFILL)
            assert c.get('yed_gettxinfo', 0) <= len(self.yb_txids), 'node %s: %d yed_gettxinfo > %d Yellowback txs' % (node, c.get('yed_gettxinfo', 0), len(self.yb_txids))
        total_txinfo = sum(c.get('yed_gettxinfo', 0) for c in calls.values())
        assert total_txinfo <= len(self.yb_txids), 'yed_gettxinfo asked %d times for %d Yellowback txs (over all nodes)' % (total_txinfo, len(self.yb_txids))

    def check_session(self, record):
        path = os.path.join(record, 'session.jsonl')
        assert os.path.exists(path), path
        seq = self.api('/api/health')['seq']
        def lines():
            with open(path) as f:
                return [json.loads(l) for l in f if l.strip()]
        rows = wait_for(lambda: (lambda r: r if r and r[-1]['seq'] >= seq else None)(lines()), 5, 'the session file to reach seq %d' % seq)
        assert_equal(rows[0]['kind'], 'session')
        assert_equal(rows[0]['version'], 1)
        assert_equal(len(rows), seq - rows[0]['seq'] + 1)
        assert_equal(sorted(r['seq'] for r in rows), list(range(rows[0]['seq'], seq + 1)))
        print('(g) session %s: header seq %d, %d lines up to seq %d' % (path, rows[0]['seq'], len(rows), seq))

    def run_test(self):
        self.chainviz = find_chainviz()
        if not self.chainviz:
            print('SKIP: no chain-viz binary (set CHAINVIZ_BIN, or build <workspace>/chain-viz with cargo build --release)')
            return
        print('chain-viz: %s' % self.chainviz)
        print('activate: every node quotes $%d and the three mine %d blocks round-robin' % (QUOTE_USD, ACTIVATION_BLOCKS))
        for node in self.nodes:
            set_quote(node, QUOTE_USD)
        for i in round_robin_schedule(list(range(NODES)), ACTIVATION_BLOCKS + REF_LAG + 1):
            self.mine(i)
        for node in self.nodes:
            assert_equal(node.yed_getactivation()['status'], 'active')
            assert_equal(node.yed_getstats()['mintingAllowed'], True)
        try:
            record = self.start_chainviz()
            self.check_health()
            self.check_block_event()
            self.check_mint(0, 10700, 48)
            self.check_mint(1, 20000, 96)
            self.check_reorg()
            self.check_revenue()
            self.check_budget()
            self.check_session(record)
        finally:
            self.stop_chainviz()
        print('yellowback_chainviz: health, block event, mint (mempool then confirmed), reorg, revenue, budget and session file agree with the nodes')


if __name__ == '__main__':
    YellowbackChainVizTest().main()
