#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""The quote agent (contrib/yellowback/yellowback-quote) against three pool nodes (plan §5,
Phase 7, L5, M9, N28).

The test writes ``<tmpdir>/quote-<i>.toml`` per pool (``rpc_url`` = the framework's RPC URL of
node ``i`` with its ``rpcuser``/``rpcpassword`` — no cookie — and one ``generic`` source pointing
at nothing) and runs three ``yellowback-quote --conf … --mock-price <file>`` as
``subprocess.Popen`` that ``tearDown`` terminates.  Wall-clock staleness is driven with
``advance_clock`` (``setmocktime``), never ``sleep``; the only waits are polls on the agents'
own cadence (``poll_seconds = 1``) with a deadline.
"""

import atexit
import os
import subprocess
import sys
import time

from test_framework.util import assert_equal, rpc_auth_pair, rpc_port
from test_framework.yellowback_util import (
    POOLS,
    YellowbackTestFramework,
    pool_args,
    wait_yed_healthy,
    yellowback_node_args,
)

CONTRIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'contrib', 'yellowback')
AGENT = os.path.normpath(os.path.join(CONTRIB, 'yellowback-quote'))

QUOTE_MAX_AGE = 120        # -yellowbackquotemaxage on the pools (the devnet's figure, §5 f)
POLL_SECONDS = 1           # the agents' cadence
FAIL_POLLS = 2             # L5: clear after this many failed aggregates

CONF = """# written by yellowback_quote.py for pool node {i}
[node]
rpc_url = "http://127.0.0.1:{port}"
rpc_user = "{user}"
rpc_password = "{password}"
rpc_timeout = 10

[quote]
poll_seconds = {poll}
fail_polls = {fail_polls}
min_sources = 1
min_venues = 1

[[sources]]
name = "nowhere"
kind = "generic"
venue = "nowhere"
url = "http://127.0.0.1:1/never"
path = "price"
"""


class YellowbackQuoteTest(YellowbackTestFramework):

    def __init__(self):
        super().__init__()
        self.agents = {}          # pool index -> Popen
        self.logs = []
        atexit.register(self.tearDown)

    # --- fixture ---------------------------------------------------------

    def node_args(self, i, extra=None):
        if i in POOLS:
            return pool_args(self.pool_addresses[POOLS.index(i)],
                             ['-yellowbackquotemaxage=%d' % QUOTE_MAX_AGE] + list(extra or []),
                             sigma_ref=self.sigma_ref)
        if i == 1:
            return yellowback_node_args(extra, yellowback=False)
        return super().node_args(i, extra)

    def conf_path(self, i):
        return os.path.join(self.options.tmpdir, 'quote-%d.toml' % i)

    def mock_path(self, i):
        return os.path.join(self.options.tmpdir, 'mock-%d' % i)

    def write_conf(self, i, fail_polls=FAIL_POLLS, password=None):
        user, pw = rpc_auth_pair(i)
        with open(self.conf_path(i), 'w') as f:
            f.write(CONF.format(i=i, port=rpc_port(i), user=user, password=password or pw,
                                poll=POLL_SECONDS, fail_polls=fail_polls))

    def write_mock(self, i, usd):
        tmp = self.mock_path(i) + '.tmp'
        with open(tmp, 'w') as f:
            f.write('%s\n' % usd)
        os.replace(tmp, self.mock_path(i))       # atomic: the agent never reads a half-written file

    def agent_command(self, i, mock=True, extra=None):
        cmd = [sys.executable, AGENT, '--conf', self.conf_path(i), '--log-level', 'DEBUG']
        if mock:
            cmd += ['--mock-price', self.mock_path(i)]
        return cmd + list(extra or [])

    def start_agent(self, i, mock=True):
        log = open(os.path.join(self.options.tmpdir, 'quote-%d.log' % i), 'a')
        self.logs.append(log)
        self.agents[i] = subprocess.Popen(self.agent_command(i, mock), stdin=subprocess.DEVNULL,
                                          stdout=log, stderr=subprocess.STDOUT)
        return self.agents[i]

    def stop_agent(self, i):
        p = self.agents.pop(i, None)
        if p is None:
            return None
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        return p.returncode

    def tearDown(self):
        for i in list(self.agents):
            self.stop_agent(i)
        for log in self.logs:
            try:
                log.close()
            except OSError:
                pass
        self.logs = []

    def run_once(self, i, mock=True, extra=None):
        """``yellowback-quote --once``: the exit code."""
        p = subprocess.run(self.agent_command(i, mock, ['--once'] + list(extra or [])),
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
        return p.returncode, p.stderr

    # --- probes ------------------------------------------------------------

    def miner(self, i):
        return self.nodes[i].yed_getinfo()['miner']

    def wait_kind(self, i, kind, timeout=60):
        """Poll ``yed_getinfo.miner.quoteKind`` on node ``i`` until it is ``kind`` (a deadline
        on the agents' own cadence, not a fixed sleep)."""
        deadline = time.time() + timeout
        while True:
            m = self.miner(i)
            if m['quoteKind'] == kind:
                return m
            assert time.time() < deadline, 'node %d quoteKind %r, wanted %r within %ds' % (i, m['quoteKind'], kind, timeout)
            if i in self.agents:
                assert self.agents[i].poll() is None, 'agent %d exited with %r' % (i, self.agents[i].returncode)
            time.sleep(0.2)

    def mine_and_tag(self, i):
        h = self.nodes[i].generate(1)[0]
        self.sync_all(blocks_only=True)
        return self.nodes[i].yed_gettag(h)

    def wait_tag_price(self, i, micro, timeout=30):
        """Mine on pool ``i`` until its tag carries ``micro`` (the agent re-reads the mock every
        poll; each block is one sample of what the node holds)."""
        deadline = time.time() + timeout
        while True:
            tag = self.mine_and_tag(i)
            if tag['found'] and tag.get('priceMicroUsd') == micro:
                return tag
            assert time.time() < deadline, 'pool %d tag %r never carried %d' % (i, tag, micro)
            time.sleep(0.2)

    # --- the test ----------------------------------------------------------

    def run_test(self):
        try:
            self.test()
        finally:
            self.tearDown()

    def test(self):
        nodes = self.nodes
        for i in POOLS:
            wait_yed_healthy(nodes[i])
            assert_equal(self.miner(i)['quoteKind'], 'signal')      # no quote yet, -yellowbacksignal=1
            self.write_conf(i)
            self.write_mock(i, '2.00')

        print('three agents against three pools: tags follow the mock')
# Rule: MINER-1 MINER-2 TAG-1 TAG-2 TAG-3 TAG-5
        for i in POOLS:
            self.start_agent(i)
        for i in POOLS:
            m = self.wait_kind(i, 'quote')
            assert m['quoteAgeSeconds'] is not None and m['quoteAgeSeconds'] <= QUOTE_MAX_AGE
            assert_equal(m['payoutAddress'], self.pool_addresses[POOLS.index(i)])
        for i in POOLS:
            tag = self.mine_and_tag(i)
            assert_equal(tag['found'], True)
            assert_equal(tag['kind'], 'quote')
            assert_equal(tag['priceMicroUsd'], 2_000_000)
            assert_equal(tag['sourceMask'], 0)                       # mock mode publishes mask 0
            assert_equal(tag['signal'], True)
            assert_equal(tag['payoutAddress'], self.pool_addresses[POOLS.index(i)])
        # the stock node and the user node read the same tag (TAG-1 is a byte-level scan)
        tip = nodes[0].getblockcount()
        assert_equal(nodes[0].yed_gettag(str(tip))['priceMicroUsd'], 2_000_000)

        print('the mock changes: the next tags carry the new price')
# Rule: MINER-1 TAG-3
        for i in POOLS:
            self.write_mock(i, '2.50')
        for i in POOLS:
            tag = self.wait_tag_price(i, 2_500_000)
            assert_equal(tag['kind'], 'quote')
        # every enforcing node agrees on the tags it indexed
        for i in POOLS:
            h = nodes[i].getbestblockhash()
            assert_equal(nodes[0].yed_gettag(h), nodes[i].yed_gettag(h))

        print('a stopped agent: its node is signal-only after -yellowbackquotemaxage')
# Rule: MINER-1
        self.advance_clock(1)                                        # the clock is now the mock clock on every node
        assert_equal(self.stop_agent(POOLS[2]), 0)                   # SIGTERM: a clean exit
        m = self.miner(POOLS[2])
        assert_equal(m['quoteKind'], 'quote')                        # the last quote is still fresh
        self.advance_clock(QUOTE_MAX_AGE + 1)
        m = self.miner(POOLS[2])
        assert_equal(m['quoteKind'], 'signal')
        assert m['quoteAgeSeconds'] > QUOTE_MAX_AGE
        tag = self.mine_and_tag(POOLS[2])
        assert_equal(tag['found'], True)
        assert_equal(tag['kind'], 'signal')
        assert_equal(tag['priceMicroUsd'], 0)
        assert_equal(tag['signal'], True)
        # the two live agents re-stamp their quotes at the mock clock within a poll
        for i in POOLS[:2]:
            self.wait_kind(i, 'quote')
            assert_equal(self.mine_and_tag(i)['priceMicroUsd'], 2_500_000)

        print('a source outage below min_sources clears the quote after fail_polls (L5)')
# Rule: MINER-1
        i = POOLS[1]
        assert_equal(self.stop_agent(i), 0)
        assert_equal(self.miner(i)['quoteKind'], 'quote')            # the clock is frozen: the quote stays fresh
        p = self.start_agent(i, mock=False)                          # the real feed: one dead source
        started = time.time()
        m = self.wait_kind(i, 'signal', timeout=60)                  # yed_setquote 0 after two failed polls
        assert time.time() - started < 60
        assert_equal(m['quoteAgeSeconds'], None)
        assert p.poll() is None, 'the daemon exited on a source failure'
        tag = self.mine_and_tag(i)
        assert_equal((tag['kind'], tag['priceMicroUsd']), ('signal', 0))
        assert_equal(self.stop_agent(i), 0)
        with open(os.path.join(self.options.tmpdir, 'quote-%d.log' % i)) as f:
            log = f.read()
        assert 'no aggregate' in log and 'quote cleared' in log, log[-2000:]
        # publishing resumes on the next good aggregate
        self.start_agent(i)
        self.wait_kind(i, 'quote')
        assert_equal(self.mine_and_tag(i)['priceMicroUsd'], 2_500_000)

        print('--once exit codes')
# Rule: MINER-1
        i = POOLS[2]                                                 # its daemon is stopped; the node holds a stale quote
        code, err = self.run_once(i)
        assert_equal(code, 0)                                        # published
        self.wait_kind(i, 'quote', timeout=5)
        os.remove(self.mock_path(i))
        code, err = self.run_once(i)
        assert_equal(code, 1)                                        # an unreadable mock is a failed aggregate: nothing published
        assert 'no aggregate' in err, err
        code, err = self.run_once(i, mock=False)
        assert_equal(code, 1)                                        # the dead source: nothing published, no clear on the first poll
        self.write_mock(i, '3.00')
        self.write_conf(i, password='wrong')
        code, err = self.run_once(i)
        assert_equal(code, 1)                                        # an RPC failure is not a configuration error
        assert 'yed_setquote' in err, err
        with open(self.conf_path(i), 'a') as f:
            f.write('\n[quote]\nbogus = 1\n')
        code, err = self.run_once(i)
        assert_equal(code, 2)                                        # a bad configuration
        self.write_conf(i)
        code, err = self.run_once(i, extra=['--dry-run'])
        assert_equal(code, 0)                                        # an aggregate exists; no RPC
        code, err = self.run_once(i)
        assert_equal(code, 0)
        assert_equal(self.wait_tag_price(i, 3_000_000)['kind'], 'quote')
        assert_equal(self.nodes[0].yed_getinfo()['rejectedBlocks'], 0)


if __name__ == '__main__':
    YellowbackQuoteTest().main()
