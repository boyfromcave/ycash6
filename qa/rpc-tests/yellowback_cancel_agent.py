#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The cancel-limit design's safety brake, automated (CAN-2 + C4b; owner 2026-10-13: automated before release), with
the shipped Rust agent against real nodes and no human act.

Four ``yellowback-attest attest`` processes, one per attestor-set member (seqs 0-3, all four member keys in node 6's
wallet), run with ``[cancel]`` on (the default): the watcher, the co-signature gossip on the ``dir`` bus's
``cancel/`` topic, and the collector. Their honest price (a mock file each) is $4.00. The pools are captured: they
quote $1.60, and the claim's bundle is signed at $1.60 in Python with the members' keys citing refHeight - 1 (the
stand-in for a captured attestation quantile together with a pool majority, upgrade plan §11's collusion row; not at
the refHeight itself, where the agents' own record would rightly forbid them a contradicting statement, review M-2),
so a class-A vault minted at $4.00 (300 %) reads 120 %, under theta, and the claim is consensus-valid at a false
price. The agents wait one block for spares (spares 4), which opens a window for a reorg.

What it asserts, in order:

  1. A wrong-price claim on vault V1 is cancelled with no RPC from this script but mining: the agents judge it,
     co-sign it (``yed_signcancelcosign``), gossip the co-signatures, one of them drives (``yed_buildcancel``,
     ``set_signcancel``, ``vault_send``) and the cancel confirms before CLAIM_DELAY. ``cancelsRequired`` was 1;
     the cancel's TxLog row counts at least 1 co-signer; the vault is ACTIVE again with ``cancelCount`` 1. Before
     the cancel is sent, the claim's block is invalidated on every node and the claim re-mined (review H-1): no
     agent closes the claim while it is out of the chain, and the agents still cancel it.
  2. The same position is claimed again inside CANCEL_QUIET: ``cancelsRequired`` is 2, and the agents cancel it
     again, the TxLog row counting at least 2 distinct co-signers; ``cancelCount`` 2, ``cancelsRequired`` 3. The
     rota's leader for this claim is stopped before the claim confirms: the next member takes over after
     ``takeover_blocks`` and drives; one cancel is sent per round. The stopped agent restarts on its persisted state.
  3. The price really falls (every agent's mock to $1.60) and an honest claim on vault V2 is left alone: no agent
     co-signs it, nothing spends its intent for CLAIM_DELAY blocks, ``vault_release`` makes it CLAIMED, and every
     agent's persisted state records the verdict ``Honest``.

Needs a build of contrib/yellowback/attest (Rust); without the binary it SKIPs, so it is a nightly script like
yellowback_attest_agent (YELLOWBACK_ATTEST_BIN overrides the search).

Nodes: 0 user (vault owner), 1 stock, 2-4 pools, 5 observer (the claimant), 6 the attestor wallet.
"""

import hashlib
import json
import os
import signal
import subprocess
import tempfile
import time
from decimal import Decimal

from test_framework.util import assert_equal, rpc_auth_pair, rpc_port, sync_blocks, sync_mempools
from test_framework.yellowback_util import (
    ATTESTOR_A, CANCEL_QUIET, CANCEL_SIGNERS_MAX, CLAIM_DELAY, POOLS, REF_LAG, STOCK,
    YellowbackTestFramework, set_quote, usd_to_micro, wait_yed_healthy, write_private,
)
from test_framework.yellowback_attest import (
    ArmedModeMixin, hot_wif_for, offline_bundle_hex, outpoint_selector, register_and_arm, wallet_claim,
)
from yellowback_attest_agent import find_agent

HONEST = Decimal('4.00')        # every agent's price: a class-A vault minted here is at 300 %
CAPTURED = Decimal('1.60')      # the pools' (and the bundle's) price: that vault reads 120 %, under theta 125 %
MEMBERS = 4
POLL_SECONDS = 1
MINE_EVERY = 4.0                # seconds between blocks while the agents work (CLAIM_DELAY is 10 blocks)

AGENT_CONF = """[node]
rpc_url = "http://127.0.0.1:%(port)d"
rpc_user = "%(user)s"
rpc_password = "%(password)s"

[attest]
seq = %(seq)d
every_blocks = 4
fail_polls = 2
ref_lag = %(ref_lag)d
poll_seconds = %(poll)d
heartbeat_blocks = 0
min_sources = 1
min_venues = 1

[transport]
kind = "dir"
path = "%(bus)s"

[cancel]
auto_cosign = true
margin_bps = 500
drive = true
spares = 4
spare_wait_blocks = 1
takeover_blocks = 2
refee_after_blocks = 3
price_tolerance_blocks = 8
state_file = "%(state)s"
"""


class YellowbackCancelAgentTest(ArmedModeMixin, YellowbackTestFramework):
    EDGES = YellowbackTestFramework.EDGES + [(0, 6)]

    def __init__(self):
        super().__init__(num_nodes=7)
        self.agent = None
        self.workdir = None
        self.procs = {}

    @property
    def armed(self):
        return True             # the claim carries a bundle; the members exist

    def sync_all(self, blocks_only=False):
        """Blocks everywhere; mempools among the Yellowback nodes only (the stock node keeps what they refuse)."""
        for g in self.groups():
            nodes = [self.nodes[i] for i in g if self.nodes[i] is not None]
            sync_blocks(nodes)
            if not blocks_only:
                sync_mempools([self.nodes[i] for i in g if self.nodes[i] is not None and i != STOCK])

    # ------------------------------------------------------------------ agents

    def mock_path(self, seq):
        return os.path.join(self.workdir, 'price-%d' % seq)

    def state_path(self, seq):
        return os.path.join(self.workdir, 'cancel-%d.json' % seq)

    def write_mock(self, seq, usd):
        tmp = self.mock_path(seq) + '.tmp'
        with open(tmp, 'w') as f:
            f.write('%s\n' % usd)
        os.replace(tmp, self.mock_path(seq))

    def start_agent(self, seq):
        user, password = rpc_auth_pair(ATTESTOR_A)
        conf = os.path.join(self.workdir, 'agent-%d.toml' % seq)
        write_private(conf, AGENT_CONF % {'port': rpc_port(ATTESTOR_A), 'user': user, 'password': password,
                                          'seq': seq, 'ref_lag': REF_LAG, 'poll': POLL_SECONDS,
                                          'bus': os.path.join(self.workdir, 'bus'), 'state': self.state_path(seq)})
        log = open(os.path.join(self.workdir, 'agent-%d.log' % seq), 'a')
        self.procs[seq] = subprocess.Popen([self.agent, '--conf', conf, '--log-level', 'info', 'attest',
                                            '--mock-price', self.mock_path(seq)],
                                           stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                           start_new_session=True)
        log.close()

    def stop_agents(self):
        for seq, p in list(self.procs.items()):
            if p.poll() is None:
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                except OSError:
                    p.terminate()
                try:
                    p.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    p.kill()
            self.procs.pop(seq, None)

    def agent_logs(self):
        for seq in sorted(self.procs):
            tail = open(os.path.join(self.workdir, 'agent-%d.log' % seq)).read()[-2500:]
            print('--- agent-%d.log (tail) ---\n%s' % (seq, tail))

    def assert_agents_alive(self, where):
        dead = [s for s, p in self.procs.items() if p.poll() is not None]
        if dead:
            self.agent_logs()
            raise AssertionError('agent(s) %r exited during %s' % (dead, where))

    def agent_states(self):
        out = {}
        for seq in range(MEMBERS):
            try:
                with open(self.state_path(seq)) as f:
                    out[seq] = json.load(f)
            except (OSError, ValueError):
                out[seq] = None
        return out

    def log_count(self, needle):
        n = 0
        for seq in range(MEMBERS):
            n += open(os.path.join(self.workdir, 'agent-%d.log' % seq)).read().count(needle)
        return n

    # ------------------------------------------------------------------ chain helpers

    def price(self, usd):
        for i in POOLS:
            set_quote(self.nodes[i], usd)
            self.quotes[i] = (usd, 1)

    @staticmethod
    def leader(members, intent_txid, n=0):
        """The agent's rota (cancel.rs `rank`): members in seq order rotated by SHA-256(txid internal || n LE32);
        rank 0 drives at once, rank r after r x takeover_blocks."""
        d = hashlib.sha256(bytes.fromhex(intent_txid)[::-1] + n.to_bytes(4, 'little')).digest()
        m = sorted(members)
        return m[int.from_bytes(d[:8], 'little') % len(m)]

    def find_cancel(self, intent_txid, heights):
        """The claim_cancel transaction in the blocks at `heights` that spends the claimant intent, or None."""
        node = self.nodes[2]
        for h in heights:
            bh = node.getblockhash(h)
            block = node.getblock(bh)
            for txid in block['tx']:
                raw = node.getrawtransaction(txid, 1, bh)     # with the block: no -txindex needed (6.20.0)
                if any(i.get('txid') == intent_txid and i.get('vout') == 0 for i in raw['vin']):
                    return txid
        return None

    def wait_cancel(self, intent_txid, claim_height, label):
        """Mine a block every MINE_EVERY seconds (never past the claim's release height) while the agents work;
        return the cancel's txid once it confirmed. This script makes no co-signing, building or sending call."""
        deadline_height = claim_height + CLAIM_DELAY - 1
        last = time.time()
        while True:
            self.assert_agents_alive(label)
            tip = self.nodes[2].getblockcount()
            found = self.find_cancel(intent_txid, range(claim_height + 1, tip + 1))
            if found:
                return found
            if time.time() - last >= MINE_EVERY:
                if tip >= deadline_height:
                    self.agent_logs()
                    raise AssertionError('%s: no cancel confirmed by height %d (CLAIM_DELAY); logs in %s'
                                         % (label, tip, self.workdir))
                self.sync_all()
                self.mine(POOLS[tip % len(POOLS)])
                last = time.time()
            time.sleep(0.5)

    def captured_claim(self, claimant, position):
        """The claim, its bundle signed at the captured price by the members' keys, citing refHeight - 1."""
        r = claimant.yed_getinfo()['height']
        bundle = offline_bundle_hex(self, claimant, r, outpoint_selector(position, 0), CAPTURED, cited=r - 1)
        return wallet_claim(self, claimant, position, bundle_hex=bundle)

    def claim_state(self, seq, intent):
        state = self.agent_states()[seq]
        return None if state is None else state['claims'].get(intent)

    def reorg_claim_block(self, claim_txid, at):
        """Review H-1: once every agent co-signed and before the cancel is sent, invalidate the claim's block on every
        node, let the agents see the claim leave CLAIMING, then re-mine it."""
        intent = '%s:0' % claim_txid
        deadline = time.time() + 60
        while not all((self.claim_state(s, intent) or {}).get('own_cosig') for s in range(MEMBERS)):
            assert time.time() < deadline, 'the agents did not co-sign the claim; logs in %s' % self.workdir
            self.assert_agents_alive('reorg: co-signing')
            time.sleep(0.5)
        assert self.nodes[ATTESTOR_A].gettxout(claim_txid, 0, True) is not None, 'a cancel was sent before the reorg'
        block = self.nodes[2].getblockhash(at)
        for n in self.nodes:
            n.invalidateblock(block)
        for n in self.nodes:
            deadline = time.time() + 30
            while n.getblockcount() != at - 1:
                assert time.time() < deadline, 'a node did not roll back'
                time.sleep(0.2)
        time.sleep(4 * POLL_SECONDS)                    # the agents see the claim leave CLAIMING
        for s in range(MEMBERS):
            c = self.claim_state(s, intent)
            assert c is not None and not (isinstance(c['phase'], dict) and 'Closed' in c['phase']), \
                'agent %d closed a claim whose block left the chain: %r' % (s, c and c['phase'])
        self.mine(POOLS[0])                             # the claim (back in the mempools) is mined again
        assert_equal(self.nodes[2].getblockcount(), at)
        assert self.nodes[2].getblockhash(at) != block
        v = self.nodes[2].getrawtransaction(claim_txid, 1, self.nodes[2].getblockhash(at))
        assert_equal(v['txid'], claim_txid)
        print('   reorg: block %d invalidated and the claim re-mined in %s; no agent closed it'
              % (at, self.nodes[2].getblockhash(at)[:16]))

    def claim_and_confirm(self, claimant, position, before_mining=None):
        claimed = self.captured_claim(claimant, position)
        if before_mining is not None:
            before_mining(claimed)
        self.sync_all()
        self.mine(POOLS[1])
        height = self.nodes[2].getblockcount()
        v = self.nodes[2].yed_getvault(position)
        assert_equal(v['status'], 'CLAIMING')
        assert_equal(v['intents'][0]['txid'], claimed['txid'])
        return claimed, height

    # ------------------------------------------------------------------

    def run_test(self):
        self.agent = find_agent()
        if self.agent is None:
            print('SKIP: yellowback-attest is not built (cargo build --release in contrib/yellowback/attest, '
                  'or set YELLOWBACK_ATTEST_BIN)')
            return
        print('agent: %s' % self.agent)
        self.workdir = tempfile.mkdtemp(prefix='yellowback-cancel-agent-', dir=self.options.tmpdir)
        os.makedirs(os.path.join(self.workdir, 'bus'))
        try:
            self.body()
        finally:
            self.stop_agents()

    def body(self):
        nodes = self.nodes
        user, claimant, wallet = nodes[0], nodes[5], nodes[ATTESTOR_A]
        for node in self.enforcing_nodes():
            wait_yed_healthy(node)

        print('activate at $%s; %d attestor-set members, all keys in node %d' % (HONEST, MEMBERS, ATTESTOR_A))
        self.activate(POOLS, quote_usd=HONEST)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        user.sendtoaddress(claimant.getnewaddress(), 5)
        for _ in range(4):                                  # the driver's carriers and fee inputs
            user.sendtoaddress(wallet.getnewaddress(), 5)
        self.sync_all()
        self.mine(POOLS[0])
        seqs = register_and_arm(self, n=MEMBERS)
        assert_equal(seqs, list(range(MEMBERS)))
        for seq in seqs:                                    # seq 3 is not in node 6 by default (node 7 is absent)
            wallet.importprivkey(hot_wif_for(user, seq), 'yellowback-attestor', False)
        # the keys were imported before their SET_JOIN connected: the restore marker is set; the operator states
        # that no other wallet ever signed with them (doc/vault-rpc.md, set_acknowledgerestore)
        wallet.set_acknowledgerestore()
        assert_equal(user.yed_getinfo()['attest']['status'], 'ARMED')

        print('two class-A vaults at $%s (300 %%); the claimant gets 200 YED' % HONEST)
        v1 = self.mint(user, 10000, 48)['txid']
        self.sync_all()
        self.mine(POOLS[0])
        v2 = self.mint(user, 10000, 48)['txid']
        self.sync_all()
        self.mine(POOLS[1])
        user.yed_send(claimant.yed_getnewaddress(), 10000)
        user.yed_send(claimant.yed_getnewaddress(), 10000)
        self.sync_all()
        self.mine(POOLS[2])
        assert_equal(claimant.yed_getbalance()['confirmedCents'], 20000)

        print('%d agents at an honest $%s, the cancel automation on (dir bus %s)' % (MEMBERS, HONEST, self.workdir))
        for seq in seqs:
            self.write_mock(seq, HONEST)
            self.start_agent(seq)
        time.sleep(3)
        self.assert_agents_alive('start')

        print('the pools are captured: they quote $%s, so V1 reads 120 %% and is claimable on chain' % CAPTURED)
        self.price(CAPTURED)
        self.mine_round_robin(POOLS, 34)
        assert_equal(user.yed_getprice()['pClaim'], usd_to_micro(CAPTURED))
        assert_equal(user.yed_getvault(v1)['claimable'], True)
        self.assert_agents_alive('settle')

        # ---------------------------------------------------------------- round 1
        print('1. a wrong-price claim on V1: the agents cancel it with one co-signature required')
        before = user.yed_getvault(v1)
        assert_equal((before['cancelCount'], before['cancelsRequired']), (0, 1))
        claimed, at = self.claim_and_confirm(claimant, v1)
        self.reorg_claim_block(claimed['txid'], at)
        cancel1 = self.wait_cancel(claimed['txid'], at, 'round 1')
        self.sync_all()
        info = nodes[2].yed_gettxinfo(cancel1)
        assert_equal(info['type'], 'claim_cancel')
        assert len(info['bundleSeqs']) >= 1, info
        back = nodes[2].yed_getvault(cancel1)
        assert_equal((back['status'], back['cancelCount'], back['cancelsRequired']), ('ACTIVE', 1, 2))
        q1 = back['cancelQuietUntil']
        print('   cancelled by %s at height %d, co-signers %r' % (cancel1[:16], info['height'], info['bundleSeqs']))
        self.checkpoint('round 1')

        # ---------------------------------------------------------------- round 2
        print('2. the same position claimed again inside CANCEL_QUIET: two co-signatures required, cancelled again;')
        print('   the rota\'s leader for this claim is down before it confirms, so the next member takes over')
        stopped = []

        def stop_leader(claimed):
            seq = self.leader(seqs, claimed['txid'])
            p = self.procs.pop(seq)
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            p.wait(timeout=15)
            stopped.append(seq)
            print('   stopped the leader, seq %d' % seq)

        claimed, at = self.claim_and_confirm(claimant, cancel1, before_mining=stop_leader)
        assert at < q1, 'the second claim must land inside CANCEL_QUIET (%d < %d)' % (at, q1)
        assert_equal(nodes[2].yed_getvault(cancel1)['cancelsRequired'], 2)
        cancel2 = self.wait_cancel(claimed['txid'], at, 'round 2')
        self.sync_all()
        info = nodes[2].yed_gettxinfo(cancel2)
        assert_equal(info['type'], 'claim_cancel')
        assert len(set(info['bundleSeqs'])) >= 2, info
        back = nodes[2].yed_getvault(cancel2)
        assert_equal((back['status'], back['cancelCount'], back['cancelsRequired']),
                     ('ACTIVE', 2, min(3, CANCEL_SIGNERS_MAX)))
        assert back['cancelQuietUntil'] == info['height'] + CANCEL_QUIET
        print('   cancelled by %s at height %d, co-signers %r' % (cancel2[:16], info['height'], info['bundleSeqs']))
        assert_equal(self.log_count('SENT '), 2)        # one driver per round
        assert stopped[0] not in info['bundleSeqs']
        print('   restarting seq %d on its persisted state' % stopped[0])
        self.start_agent(stopped[0])
        self.checkpoint('round 2')

        # ---------------------------------------------------------------- honest
        print('3. the price really falls to $%s: an honest claim on V2 is left alone and released' % CAPTURED)
        for seq in seqs:
            self.write_mock(seq, CAPTURED)
        time.sleep(3)
        for k in range(3):                              # the agents' price history moves to the new price
            self.mine(POOLS[k])
            time.sleep(1.5)
        claimed, at = self.claim_and_confirm(claimant, v2)
        intent = '%s:0' % claimed['txid']
        while nodes[2].getblockcount() < at + CLAIM_DELAY - 1:
            time.sleep(1.5)
            self.assert_agents_alive('honest claim')
            self.sync_all()
            for i in (2, ATTESTOR_A):
                assert nodes[i].gettxout(claimed['txid'], 0, True) is not None, \
                    'something spends the honest claim\'s intent on node %d' % i
            self.mine(POOLS[0])
        self.mine(POOLS[0])
        assert self.find_cancel(claimed['txid'], range(at + 1, nodes[2].getblockcount() + 1)) is None
        claimant.vault_release(intent)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(nodes[2].yed_getvault(v2)['status'], 'CLAIMED')
        time.sleep(2 * POLL_SECONDS + 1)
        states = self.agent_states()
        for seq in seqs:
            c = states[seq]['claims'][intent]
            assert_equal(c['verdict'], 'Honest')
            assert c['own_cosig'] is None, (seq, c)
        assert_equal(self.log_count('SENT '), 2)        # nothing sent for the honest claim
        print('   V2 CLAIMED; every agent judged the claim honest and co-signed nothing')
        self.assert_agents_alive('end')
        self.checkpoint('end')


if __name__ == '__main__':
    YellowbackCancelAgentTest().main()
