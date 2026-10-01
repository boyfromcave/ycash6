#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The real Rust attestor agent against real nodes (v3 plan Phase A4, section 5).

Every other v3 script signs attestations in Python (``test_framework/yellowback_attest.py``,
S9) so that the suite never depends on a Rust toolchain.  This one is the other half of that
bargain and the only place the shipped binary is exercised end to end: three
``yellowback-attest attest`` processes beside the attestor wallets (nodes 6 and 7), publishing
on the ``dir`` transport, and one ``yellowback-attest subscribe`` beside node 0 feeding what it
hears into that node's pool through ``yed_addattestation``.  No relay and no network: the bus is
a directory, the price is a mock file.

What it asserts, in order:

  1. ``attest.poolFresh`` reaches 3 -- one fresh attestation per seated attestor -- within two
     agent polls of the first due tick.  Nothing in the path is stubbed: the agents read the
     mock price, call ``yed_signattestation`` on their own node, write the 74 bytes to the bus,
     and the subscriber pushes them into node 0.
  2. A mint on node 0 with **no** ``bundleHex`` builds its bundle from that pool (the A2/A3
     integration seam) and confirms.
  3. Stopping one agent still leaves ``K_SLACK`` covering: ``poolFresh`` falls to 2 = M_SELECT
     once the stopped attestor's last attestation ages out, and the mint still builds.
  4. Stopping a second refuses the mint with ``missing``, naming the seqs that are short, and
     restarting both recovers.

Because it needs ``cargo build --release`` of ``contrib/yellowback/attest``, it is a nightly
script, not a merge gate: without the binary it SKIPs rather than failing (set
YELLOWBACK_ATTEST_BIN to point at it, or let the CARGO_TARGET_DIR/crate-local search find it).

Nodes: 0 user, 1 stock, 2-4 pools, 5 spare, 6-7 attestor wallets.
"""

import os
import signal
import subprocess
import tempfile
import time
from decimal import Decimal

from test_framework.util import assert_equal, rpc_auth_pair, rpc_port
from test_framework.yellowback_util import (
    ATTESTOR_A, ATTESTOR_B, ATTEST_ARM_MIN, K_SLACK, M_SELECT, POOLS, REF_LAG,
    USER, YellowbackTestFramework, wait_yed_healthy,
)
from test_framework.yellowback_attest import register_and_arm, two_step

# $50, as yellowback_attest_wallet.py uses: a 10000-cent mint then needs ~10 YEC of collateral,
# which node 0 can fund three times over from its 101 coinbases. At $0.50 the same mint wants
# ~1000 YEC and the second step dies with insufficient-yec.
PRICE = Decimal('50')
ATTEST_INTERVAL = 4          # regtest attestInterval: the agent signs every 4 new blocks
POLL_SECONDS = 2
CRATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'contrib', 'yellowback', 'attest')

ATTEST_CONF = """[node]
rpc_url = "http://127.0.0.1:%(port)d"
rpc_user = "%(user)s"
rpc_password = "%(password)s"

[attest]
seq = %(seq)d
every_blocks = %(every)d
fail_polls = 2
ref_lag = %(ref_lag)d
poll_seconds = %(poll)d
min_sources = 1
min_venues = 1

[transport]
kind = "dir"
path = "%(bus)s"

[subscribe]
listattestors_seconds = 5
"""

SUBSCRIBE_CONF = """[node]
rpc_url = "http://127.0.0.1:%(port)d"
rpc_user = "%(user)s"
rpc_password = "%(password)s"

[transport]
kind = "dir"
path = "%(bus)s"

[subscribe]
listattestors_seconds = 5
"""


def find_agent():
    """The yellowback-attest binary, or None.  CARGO_TARGET_DIR is often redirected to a shared
    directory on a developer machine (the A4 incident), so the crate-local target/ is only one
    candidate; YELLOWBACK_ATTEST_BIN overrides the search."""
    override = os.environ.get('YELLOWBACK_ATTEST_BIN')
    if override:
        path = os.path.expanduser(override)
        return path if os.access(path, os.X_OK) else None
    roots = [os.path.join(CRATE, 'target')]
    shared = os.environ.get('CARGO_TARGET_DIR')
    if shared:
        roots.insert(0, os.path.expanduser(shared))
    for root in roots:
        for profile in ('release', 'debug'):
            candidate = os.path.join(root, profile, 'yellowback-attest')
            if os.access(candidate, os.X_OK):
                return candidate
    return None


# Rule: BUNDLE-1 MINT-9 PRICE-2 SNAP
class YellowbackAttestAgentTest(YellowbackTestFramework):
    initial_blocks = 101
    # the attestor wallets join the enforcing half directly, as in yellowback_attest.py
    EDGES = YellowbackTestFramework.EDGES + [(0, 6), (0, 7)]

    def __init__(self):
        super().__init__(num_nodes=8)
        self.agent = None
        self.workdir = None
        self.bus = None
        self.mock = {}          # seq -> mock price file
        self.procs = {}         # name -> Popen

    def node_args(self, i, extra=None):
        return super().node_args(i, ['-debug=yellowback'] + list(extra or []))

    # ------------------------------------------------------------------ agent processes

    def write_mock(self, seq, usd):
        tmp = self.mock[seq] + '.tmp'
        with open(tmp, 'w') as f:
            f.write('%s\n' % usd)
        os.replace(tmp, self.mock[seq])

    def spawn(self, name, argv):
        log = open(os.path.join(self.workdir, '%s.log' % name), 'a')
        self.procs[name] = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log,
                                            stderr=subprocess.STDOUT, start_new_session=True)
        log.close()
        return self.procs[name]

    def start_attestor(self, seq, node):
        """One `attest` process signing as `seq` against node `node`."""
        user, password = rpc_auth_pair(node)
        conf = os.path.join(self.workdir, 'attest-%d.toml' % seq)
        with open(conf, 'w') as f:
            f.write(ATTEST_CONF % {'port': rpc_port(node), 'user': user, 'password': password,
                                   'seq': seq, 'every': ATTEST_INTERVAL, 'ref_lag': REF_LAG,
                                   'poll': POLL_SECONDS, 'bus': self.bus})
        return self.spawn('attest-%d' % seq, [self.agent, '--conf', conf, '--log-level', 'debug',
                                              'attest', '--mock-price', self.mock[seq]])

    def start_subscriber(self, node=USER):
        user, password = rpc_auth_pair(node)
        conf = os.path.join(self.workdir, 'subscribe.toml')
        with open(conf, 'w') as f:
            f.write(SUBSCRIBE_CONF % {'port': rpc_port(node), 'user': user,
                                      'password': password, 'bus': self.bus})
        return self.spawn('subscribe', [self.agent, '--conf', conf, '--log-level', 'debug', 'subscribe'])

    def stop_agent(self, name, timeout=15):
        process = self.procs.pop(name, None)
        if process is None or process.poll() is not None:
            return
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except OSError:
            process.terminate()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=timeout)

    def stop_all_agents(self):
        for name in list(self.procs):
            try:
                self.stop_agent(name)
            except Exception as e:                  # never mask the real failure
                print('stopping %s: %s' % (name, e))

    def print_agent_logs(self, names=None):
        """The CI runner keeps node debug.logs on failure but not the agents' own logs, so a
        stalled wait prints their tails here (the whole of the evidence for a slow signer)."""
        for name in sorted(names or self.procs):
            tail = open(os.path.join(self.workdir, '%s.log' % name)).read()[-2000:]
            print('--- %s.log (tail) ---\n%s' % (name, tail))

    def assert_agents_alive(self, where):
        dead = [name for name, p in self.procs.items() if p.poll() is not None]
        if dead:
            self.print_agent_logs(dead)
            raise AssertionError('agent(s) %s exited during %s' % (', '.join(sorted(dead)), where))

    # ------------------------------------------------------------------ chain helpers

    def attest_info(self, i=USER):
        return self.nodes[i].yed_getinfo()['attest']

    def pools_step(self, n, label=''):
        for k in range(n):
            self.nodes[POOLS[k % len(POOLS)]].generate(1)
            self.sync_all()

    def wait_pool_fresh(self, want, timeout=120, label=''):
        """Wait until node 0's pool holds a fresh attestation from `want` seated attestors.  The
        agents poll every POLL_SECONDS and sign only at a due tick, so this is the 'within two
        polls' bound of the plan measured from a tick, with slack for process scheduling."""
        deadline, seen = time.time() + timeout, None
        while time.time() < deadline:
            self.assert_agents_alive(label or 'wait_pool_fresh')
            seen = self.attest_info()
            if seen['poolFresh'] >= want:
                return seen
            time.sleep(0.5)
        self.print_agent_logs()
        raise AssertionError('poolFresh stayed at %d (wanted %d) for %ds during %s; logs in %s'
                             % (seen['poolFresh'], want, timeout, label, self.workdir))

    def wait_pool_fresh_at_most(self, want, timeout=120, label=''):
        """Wait until poolFresh has fallen to `want` or below: a stopped agent's last attestation
        stays usable until it ages past ATTEST_MAX_AGE, so this mines while it waits."""
        deadline, seen = time.time() + timeout, None
        while time.time() < deadline:
            self.assert_agents_alive(label or 'wait_pool_fresh_at_most')
            seen = self.attest_info()
            if seen['poolFresh'] <= want:
                return seen
            self.pools_step(1)
            time.sleep(0.5)
        raise AssertionError('poolFresh stayed at %d (wanted <= %d) for %ds during %s; logs in %s'
                             % (seen['poolFresh'], want, timeout, label, self.workdir))

    def mint_from_pool(self, cents=10000, lock_blocks=48):
        """A mint with an empty bundleHex: ParseBundleArg maps "" to nullopt, so the wallet takes
        its bundle from the node's own pool -- where the subscriber put the agents' attestations
        (the A2/A3 integration seam).  Every argument before `wait` must be given explicitly:
        two_step appends the wait flag after whatever it is passed, so a short call lands True in
        the bundleHex slot and the node throws on get_str().  Returns two_step's full result
        dict (it is the RPC's, not a txid), whose bundleSeqs name the attestations the agents
        put in the pool.  The main transaction is left in the mempool for the caller to mine."""
        return two_step(self, self.nodes[USER], 'yed_mint', cents, lock_blocks, '', '')

    def assert_minted(self, result, label):
        """The mint built, and it built from the pool: a real txid, pending False, and at least
        M_SELECT attestations in its bundle."""
        assert_equal(result['pending'], False)
        assert result['txid'], 'the mint returned no txid: %r' % result
        assert len(result['bundleSeqs']) >= M_SELECT, \
            '%s: the bundle carries %d attestation(s), below M_SELECT (%d): %r' \
            % (label, len(result['bundleSeqs']), M_SELECT, result)
        self.pools_step(1)
        assert_equal(self.nodes[USER].yed_gettxinfo(result['txid'])['type'], 'mint')
        return result['txid']

    def assert_mint_refused(self, substr):
        try:
            self.mint_from_pool()
        except Exception as e:
            err = getattr(e, 'error', None)
            msg = str(err.get('message', '')) if isinstance(err, dict) else str(e)
            assert substr in msg, 'expected %r in %r' % (substr, msg)
            return msg
        raise AssertionError('the mint was expected to be refused with %r' % substr)

    # ------------------------------------------------------------------

    def run_test(self):
        self.agent = find_agent()
        if self.agent is None:
            print('SKIP: yellowback-attest is not built (cd %s && cargo build --release, '
                  'or set YELLOWBACK_ATTEST_BIN)' % os.path.normpath(CRATE))
            return
        print('agent: %s' % self.agent)
        self.workdir = tempfile.mkdtemp(prefix='yellowback-agent-', dir=self.options.tmpdir)
        self.bus = os.path.join(self.workdir, 'bus')
        os.makedirs(self.bus)
        try:
            self.body()
        finally:
            self.stop_all_agents()

    def body(self):
        nodes = self.nodes
        user = nodes[USER]
        for node in self.enforcing_nodes():
            wait_yed_healthy(node)
        assert_equal(user.yed_getinfo()['rpcversion'], 3)

        print('activation at $%s, then three attestors registered and armed' % PRICE)
        self.activate(POOLS, quote_usd=PRICE)
        self.pools_step(REF_LAG + 1)
        for _ in range(ATTEST_ARM_MIN):
            user.sendtoaddress(nodes[ATTESTOR_A].getnewaddress(), 30)
        self.sync_all()
        self.pools_step(1)
        seqs = register_and_arm(self, n=ATTEST_ARM_MIN)
        assert_equal(len(seqs), ATTEST_ARM_MIN)
        assert_equal(self.attest_info()['status'], 'ARMED')
        # ATTEST_ARM_MIN == N_SLOTS - 2 here, so all three are seated and all three are selected
        # (M_SELECT + K_SLACK == 3): every assertion below is about liveness, never about which
        # attestors the draw happened to pick.
        assert_equal(self.attest_info()['seatedCount'], ATTEST_ARM_MIN)

        # The plan puts the three agents on nodes 6-7.  register_and_arm imports seqs 0-2 into
        # node 6 (ATTESTOR_A); seq 2's hot key is imported into node 7 as well so one agent runs
        # there.  Only one agent ever signs for a seq, which is the rule doc/yellowback-attestor.md
        # states as "one hot key, one node" -- and yed_signattestation's persisted guard (S16) is
        # what makes a second holder survivable rather than an ejection.
        from test_framework.yellowback_attest import hot_wif_for
        nodes[ATTESTOR_B].importprivkey(hot_wif_for(user, seqs[2]), 'yellowback-attestor', False)
        placement = {seqs[0]: ATTESTOR_A, seqs[1]: ATTESTOR_A, seqs[2]: ATTESTOR_B}

        print('starting %d `attest` agents on nodes 6-7 and one `subscribe` beside node 0, dir bus %s'
              % (len(placement), self.bus))
        for seq in seqs:
            self.mock[seq] = os.path.join(self.workdir, 'price-%d' % seq)
            self.write_mock(seq, PRICE)
            self.start_attestor(seq, placement[seq])
        self.start_subscriber(USER)

        print('1. poolFresh reaches %d from the agents alone' % ATTEST_ARM_MIN)
        self.pools_step(ATTEST_INTERVAL + REF_LAG)          # mine into a due tick
        info = self.wait_pool_fresh(ATTEST_ARM_MIN, label='first tick')
        assert_equal(info['status'], 'ARMED')
        assert info['poolSize'] >= ATTEST_ARM_MIN, info
        print('   poolFresh %d, pool holds %d attestation(s)' % (info['poolFresh'], info['poolSize']))

        print('2. a mint with no bundleHex builds from that pool')
        result = self.mint_from_pool()
        txid = self.assert_minted(result, 'all three agents up')
        print('   minted %s from seqs %r at %s micro-USD (source %s)'
              % (txid[:16], result['bundleSeqs'], result['aMint'], result['source']))

        print('3. one agent down: K_SLACK covers, the mint still builds')
        self.stop_agent('attest-%d' % seqs[2])
        info = self.wait_pool_fresh_at_most(ATTEST_ARM_MIN - 1, label='one agent down')
        assert info['poolFresh'] >= M_SELECT, \
            'poolFresh fell to %d with one of %d agents down; K_SLACK (%d) should cover' \
            % (info['poolFresh'], ATTEST_ARM_MIN, K_SLACK)
        self.pools_step(ATTEST_INTERVAL)
        self.wait_pool_fresh(M_SELECT, label='one agent down, next tick')
        txid = self.assert_minted(self.mint_from_pool(), 'one agent down')
        print('   poolFresh %d; minted %s' % (self.attest_info()['poolFresh'], txid[:16]))

        print('4. two agents down: the mint is refused and names the missing seqs')
        self.stop_agent('attest-%d' % seqs[1])
        self.wait_pool_fresh_at_most(M_SELECT - 1, label='two agents down')
        message = self.assert_mint_refused('missing')
        print('   refused: %s' % message)

        print('5. both back: poolFresh recovers and minting resumes')
        self.start_attestor(seqs[1], placement[seqs[1]])
        self.start_attestor(seqs[2], placement[seqs[2]])
        self.pools_step(ATTEST_INTERVAL + REF_LAG)
        self.wait_pool_fresh(ATTEST_ARM_MIN, label='recovery')
        txid = self.assert_minted(self.mint_from_pool(), 'recovery')
        self.assert_agents_alive('recovery')
        print('   recovered: poolFresh %d, minted %s' % (self.attest_info()['poolFresh'], txid[:16]))

        self.checkpoint('end')


if __name__ == '__main__':
    YellowbackAttestAgentTest().main()
