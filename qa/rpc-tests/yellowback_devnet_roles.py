#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The role presets of the devnet, end to end (docs/plans/role-based-regtest-plan.md, R7).

This script does not build a network of its own: it drives ``contrib/yellowback/devnet/
yellowback-devnet`` as a subprocess -- ``up --role`` for each preset in turn -- so that what
CI exercises is exactly what the owner runs when walking a scenario.  For each preset it
asserts:

  1. the right seat is **empty** and every other participant is automated: the node map is the
     plan's (revision 3, I-1), and your node holds no registration / payout / quote as the
     preset promises;
  2. the heartbeat advances the chain **without any help from this script**, and only on the
     automated pools (every tag it mines names one of their payout keys);
  3. the simulator's personas each perform their characteristic action at least once over a
     fixed block budget, no persona is failing every action, and -- after a 70 % price shock --
     **the liquidator actually liquidates something**: a persona's vault ends CLAIMED by a
     claim-path spend from the liquidator's wallet, which is the assertion that proves the
     attested price has consequences;
  4. the price walk moves both populations together: the pools' mock price and every automated
     attestor's are byte-equal at every sample; nothing is pinned before the shock, and whatever
     the shock pins clears within one pin window of it;
  5. ``check`` passes before the shock (after it, a halted mint under GLOBAL_RATIO is the correct
     state, and ``check`` says so), the heartbeat is still alive at the end, and the state hash
     agrees across every enforcing node.

It runs with a fixed seed (``--seed``) so a failure is reproducible.  Like
``yellowback_attest_agent.py`` it needs the Rust attestor binary, so it SKIPs without one
(YELLOWBACK_ATTEST_BIN, or the CARGO_TARGET_DIR / crate-local search) and the nightly job
builds the crate first.  Zero C++: contrib/ and qa/ only.

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/yellowback_devnet_roles.py --srcdir=<src> --tmpdir=<dir> --portseed=<n> [--presets user,attestor,pool]

Nodes (every preset): 0 user/funder, 1 stock, 2-4 pools, 5-7 attestors, 8 fourth attestor or
your attestor seat, 9 the simulated population, 10 the simulated liquidator.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from decimal import Decimal

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..'))
DEVNET = os.path.join(REPO, 'contrib', 'yellowback', 'devnet', 'yellowback-devnet')
CRATE = os.path.join(REPO, 'contrib', 'yellowback', 'attest')
sys.path.insert(0, HERE)
from test_framework.authproxy import AuthServiceProxy   # noqa: E402

HEARTBEAT_RATE = 2          # seconds per block: the budget below is measured in blocks
WALK_TICK = 3
SHOCK = '-70%'              # class C (300 %) goes under CLAIM_THRESHOLD (110 %) at -63 %; class A (500 %) does not
EMERGENCY_PERSIST = 4
STOCK, POOLS, ATTESTOR4, POPULATION, LIQUIDATOR = 1, (2, 3, 4), 8, 9, 10
EXPECT = {
    # what each preset promises (plan section 3.1 / 3.2 as built: revision 3, I-1)
    'user':     {'nodes': 11, 'attestors': 4, 'auto_pools': (2, 3, 4), 'seat': 0},
    'attestor': {'nodes': 11, 'attestors': 3, 'auto_pools': (2, 3, 4), 'seat': 8},
    'pool':     {'nodes': 11, 'attestors': 4, 'auto_pools': (2, 3),    'seat': 4},
}
CHARACTERISTIC = {
    # persona -> the action its row in the plan's table promises at least once
    'leveraged': 'mint', 'conservative': 'mint', 'exiter': 'redeem', 'trader': 'send',
    'absentee': 'mint', 'liquidator': 'claim',
}


def find_agent():
    override = os.environ.get('YELLOWBACK_ATTEST_BIN')
    if override:
        p = os.path.expanduser(override)
        return p if os.access(p, os.X_OK) else None
    roots = [os.path.join(CRATE, 'target')]
    if os.environ.get('CARGO_TARGET_DIR'):
        roots.insert(0, os.path.expanduser(os.environ['CARGO_TARGET_DIR']))
    for root in roots:
        for profile in ('release', 'debug'):
            candidate = os.path.join(root, profile, 'yellowback-attest')
            if os.access(candidate, os.X_OK):
                return candidate
    return None


class Failure(Exception):
    pass


def check(condition, message):
    if not condition:
        raise Failure(message)


class Preset:
    def __init__(self, options, role, index, bitcoind, agent):
        self.options, self.role, self.bitcoind, self.agent = options, role, bitcoind, agent
        self.directory = os.path.join(options.tmpdir, 'devnet-%s' % role)
        self.portseed = options.portseed + index * 3 + 100
        self.log = open(os.path.join(options.tmpdir, 'devnet-%s.log' % role), 'a')
        self.state = None
        self.rpc = {}
        self.t0 = time.time()

    def say(self, text):
        print('[%s +%4ds] %s' % (self.role, time.time() - self.t0, text), flush=True)

    def devnet(self, *args, timeout=600):
        """Run one devnet command; stdout and stderr go to the per-preset log."""
        argv = [sys.executable, DEVNET] + list(args) + ['--dir', self.directory]
        env = dict(os.environ, BITCOIND=self.bitcoind, YELLOWBACK_ATTEST_BIN=self.agent)
        self.log.write('\n$ %s\n' % ' '.join(argv)); self.log.flush()
        return subprocess.run(argv, stdout=self.log, stderr=subprocess.STDOUT, env=env, timeout=timeout).returncode

    def devnet_output(self, *args):
        argv = [sys.executable, DEVNET] + list(args) + ['--dir', self.directory]
        env = dict(os.environ, BITCOIND=self.bitcoind, YELLOWBACK_ATTEST_BIN=self.agent)
        return subprocess.run(argv, capture_output=True, text=True, env=env, timeout=120)

    def node(self, i):
        if i not in self.rpc:
            self.rpc[i] = AuthServiceProxy(self.state['rpc'][str(i)]['url'], timeout=120)
        return self.rpc[i]

    def tip(self):
        return self.node(0).getblockcount()

    def stats(self):
        try:
            return json.load(open(os.path.join(self.directory, 'sim-stats.json')))
        except (OSError, ValueError):
            return {'personas': {}}

    def wait_blocks(self, n, label, extra_timeout=60):
        """Wait until the heartbeat has mined n more blocks, never mining here."""
        start, deadline = self.tip(), time.time() + n * HEARTBEAT_RATE * 3 + extra_timeout
        while self.tip() < start + n:
            check(time.time() < deadline, '%s: the heartbeat mined fewer than %d blocks in %ds (see heartbeat.log)' % (label, n, n * HEARTBEAT_RATE * 3 + extra_timeout))
            time.sleep(1)

    def wait_until(self, predicate, blocks, label):
        """Poll predicate() until true, for at most `blocks` heartbeat blocks."""
        start = self.tip()
        while True:
            value = predicate()
            if value:
                return value
            check(self.tip() < start + blocks, '%s: not reached within %d blocks (height %d)' % (label, blocks, self.tip()))
            time.sleep(2)

    # ---------------------------------------------------------------- the five assertions

    def up(self):
        self.say('up --role %s (portseed %d)' % (self.role, self.portseed))
        # With CHAINVIZ_BIN in the environment `up` starts chain-viz on the devnet with --record
        # (chain-viz-plan.md C5); without it, --no-viz keeps a stray workspace build out of the run.
        viz = [] if os.environ.get('CHAINVIZ_BIN') else ['--no-viz']
        rc = self.devnet('up', '--force', '--role', self.role, '--portseed', str(self.portseed), '--seed', str(self.options.seed),
                         '--heartbeat-rate', str(HEARTBEAT_RATE), '--walk-tick', str(WALK_TICK), '--sim-profile', 'fast',
                         '--bitcoind', self.bitcoind, *viz, timeout=1200)
        check(rc == 0, 'up --role %s exited %d (log: %s)' % (self.role, rc, self.log.name))
        self.state = json.load(open(os.path.join(self.directory, 'devnet.json')))
        self.say('up: height %d, session %s' % (self.tip(), os.path.basename(self.state['session'] or '')))

    def assert_seat_empty(self):
        want = EXPECT[self.role]
        state = self.state
        check(state['num_nodes'] == want['nodes'], 'node count %d != %d' % (state['num_nodes'], want['nodes']))
        check(state['seat'] == want['seat'], 'seat node %s != %s' % (state['seat'], want['seat']))
        check(tuple(state['auto_pools']) == want['auto_pools'], 'automated pools %s != %s' % (state['auto_pools'], want['auto_pools']))
        check(state['population'] == POPULATION and state['liquidator'] == LIQUIDATOR, 'population/liquidator nodes are not 9/10')
        attestors = self.node(0).yed_listattestors()
        check(len(attestors) == want['attestors'], '%d attestors registered, expected %d' % (len(attestors), want['attestors']))
        # node 1 is stock: no yed_* at all
        try:
            self.node(STOCK).yed_getinfo()
            raise Failure('the stock node answers yed_getinfo')
        except Failure:
            raise
        except Exception as error:
            check('not found' in str(error).lower() or '-32601' in str(error), 'stock node refused oddly: %s' % error)
        if self.role == 'attestor':
            # your node: funded, running -yellowback, and NOT registered; no agent of yours
            info = self.node(ATTESTOR4).yed_getinfo()
            check(info['attest']['status'] == 'ARMED', 'node8 sees %s, not ARMED' % info['attest']['status'])
            check(self.node(ATTESTOR4).getbalance() >= 12, 'node8 holds %s YEC, expected the bond and change' % self.node(ATTESTOR4).getbalance())
            check('attest-8' not in state['attest_agents'], 'an agent was started on your seat')
            check(str(ATTESTOR4) not in state['attest_seqs'], 'your node has a seq: it was registered for you')
            check(os.path.exists(os.path.join(self.directory, 'attest-8.toml')), 'no agent conf template for your seat')
        if self.role == 'pool':
            miner = self.node(4).yed_getinfo()['miner']
            check(miner['payoutAddress'] is None and miner['quoteKind'] == 'none', 'node4 is not a plain miner: %s' % miner)
            check(4 not in (state['agents'] and {int(k) for k in state['agents']}), 'a quote agent was started for your pool')
            eligible = [r for r in self.node(0).yed_listminers() if r['eligible']]
            check(len(eligible) == 2, '%d pools eligible, expected the 2 automated ones' % len(eligible))
        if self.role == 'user':
            check(self.node(0).getbalance() > 20, 'your wallet (node0) holds %s YEC' % self.node(0).getbalance())
            eligible = [r for r in self.node(0).yed_listminers() if r['eligible']]
            check(len(eligible) == 3, '%d pools eligible, expected 3' % len(eligible))
        self.say('seat empty as promised; node map ok')

    def assert_heartbeat(self):
        auto = {self.state['pool_addresses'][POOLS.index(p)] for p in self.state['auto_pools']}
        start = self.tip()
        self.wait_blocks(6, 'heartbeat')
        end = self.tip()
        payees = set()
        for height in range(start + 1, end + 1):
            tag = self.node(0).yed_gettag(str(height))
            check(tag['found'], 'block %d mined by the heartbeat carries no tag' % height)
            payees.add(tag['payoutAddress'])
        check(payees <= auto, 'the heartbeat mined on a non-automated pool: %s' % (payees - auto))
        check(len(payees) == len(auto), 'the heartbeat did not round-robin: %s of %s' % (payees, auto))
        hb = json.load(open(os.path.join(self.directory, 'heartbeat.json')))
        check(hb['rate'] == HEARTBEAT_RATE, 'heartbeat rate %s' % hb['rate'])
        self.say('heartbeat: %d blocks on %d automated pools, none by this script' % (end - start, len(payees)))

    def assert_walk(self):
        auto = self.state['auto_attestors']
        samples = []
        for _ in range(3):
            time.sleep(WALK_TICK + 1)
            pool = open(os.path.join(self.directory, 'mock-price')).read().strip()
            attest = {a: open(os.path.join(self.directory, 'attest-price-%d' % a)).read().strip() for a in auto}
            for a, value in attest.items():
                check(value == pool, 'the walk let node%d attest $%s while the pools quote $%s' % (a, value, pool))
            samples.append(pool)
        check(len(set(samples)) >= 2, 'the price did not move over three ticks: %s' % samples)
        if self.role == 'attestor':
            seat = open(os.path.join(self.directory, 'attest-price-8')).read().strip()
            check(seat == self.state['price_usd'], 'the walk wrote your attestor\'s price file (%s)' % seat)
        self.say('walk: pools and attestors move together (%s)' % ' -> '.join(samples))

    def assert_personas(self):
        """Every persona's characteristic action, then the liquidation."""
        def acted(name, action):
            return self.stats()['personas'].get(name, {}).get('ok', {}).get(action, 0) >= 1
        for name, action in CHARACTERISTIC.items():
            if action in ('redeem', 'claim'):
                continue
            self.wait_until(lambda: acted(name, action), 60, '%s: %s' % (name, action))
        self.say('personas: every minter has minted and the trader has moved YED')

        # the leveraged minter's first vault: class C, so the claim opens 169 blocks after the mint
        def leveraged_vault():
            vaults = self.stats()['personas'].get('leveraged', {}).get('vaults') or []
            return vaults[0] if vaults else None
        vault = self.wait_until(leveraged_vault, 20, 'leveraged vault')

        def indexed():
            # the persona's wait=true returns once the MINT is broadcast; node 0 indexes it a block later
            try:
                return self.node(0).yed_getvault(vault)
            except Exception:
                return None
        row = self.wait_until(indexed, 10, 'the leveraged vault reaching node 0')
        check(row['termClass'] == 'C', 'the leveraged minter minted class %s' % row['termClass'])
        claim_at = row['claimHeight']
        self.say('leveraged vault %s: class C, %s YED, claim opens at %d (tip %d)' % (vault[:16], Decimal(row['mintedCents']) / 100, claim_at, self.tip()))

        # the exiter's redeem: its class A vault unlocks 48 blocks after the mint
        self.wait_until(lambda: acted('exiter', 'redeem') or acted('conservative', 'redeem'), 90, 'a redeem at maturity')
        self.say('personas: a vault was redeemed at maturity')

        # the shock, timed so the emergency path is what opens the claim (a notice needs the
        # vault ACTIVE and within EMERGENCY_PERSIST of its claim height to be worth posting)
        self.wait_until(lambda: self.tip() >= claim_at - 12, claim_at, 'approach to the claim height')
        before = self.node(0).yed_getprice()['pClaim']
        self.assert_nothing_pinned('before the shock')
        rc = self.devnet('price', '--shock=' + SHOCK)
        check(rc == 0, 'price --shock exited %d' % rc)
        self.say('shock %s applied at height %d (pClaim was %s)' % (SHOCK, self.tip(), before))

        def population_vaults():
            return {v for name, r in self.stats()['personas'].items() if name != 'liquidator' for v in (r.get('vaults') or [])}

        def claimed():
            # any persona's vault: which one goes first depends on the draw of mint heights
            for r in self.node(0).yed_listvaults('CLAIMED', 200, 0):
                if r['txid'] in population_vaults():
                    return r
            return None
        row = self.wait_until(claimed, 60 + EMERGENCY_PERSIST + 30, 'the liquidator claiming a persona\'s vault')
        closing = self.node(0).yed_gettxinfo(row['closingTxid'])
        check(closing['path'] == 'claim', 'the closing transaction is a %s, not a claim' % closing['path'])
        check(closing['claimPath'] in ('a', 'b'), 'claimPath %r' % closing['claimPath'])
        # the tally file is rewritten every five seconds; the chain can show the claim first
        self.wait_until(lambda: acted('liquidator', 'claim'), 10, 'the liquidator persona recording its claim')
        # the collateral went to the liquidator's wallet, not the owner's
        got = self.node(LIQUIDATOR).yed_listtransactions(50, 0)
        check(any(t['txid'] == row['closingTxid'] for t in got), 'the claim is not in the liquidator wallet\'s yed_listtransactions')
        self.say('liquidated: vault %s CLAIMED by clause (%s), %s YED burned, closing %s'
                 % (row['txid'][:16], closing['claimPath'], Decimal(closing['burned']) / 100, row['closingTxid'][:16]))

        # PIN-2 (state.cpp) pins an attestor whose price repeats across bundle rows while pMint
        # moves more than PIN_DELTA over PIN_WINDOW blocks; the shock satisfies the second half
        # by construction, so for one window after it any agent that misses a tick or is dropped
        # by DIVERGE_BPS_ATTEST while its window average catches up reads as pinned -- the rule
        # doing its job, and a race the nightly lost on 2026-09-25 and 2026-09-28 (pool preset,
        # seq 3). The invariant after the shock is that the pin clears once the window has
        # rolled past it; "nothing pinned" itself is asserted above, before the shock.
        window = self.node(0).yed_getinfo()['params']['attest']['pinWindow']
        pinned_after = self.pinned()
        self.wait_until(lambda: not self.pinned(), window + EMERGENCY_PERSIST + 4, 'pinning clearing after the shock (pinned %s)' % (pinned_after,))
        self.say('pinned after the shock: %s; clear by height %d (window %d)' % (pinned_after or 'nothing', self.tip(), window))

        # honesty: no persona is failing every action
        tally = self.stats()['personas']
        loud = [n for n, r in tally.items() if r.get('all_failing')]
        check(not loud, 'persona(s) failing every action: %s' % loud)
        summary = ', '.join('%s %s' % (n, sum(r['ok'].values())) for n, r in sorted(tally.items()))
        self.say('tally (successful actions): %s' % summary)

    def assert_check(self):
        result = self.devnet_output('check')
        check(result.returncode == 0, 'check failed: %s%s' % (result.stdout, result.stderr))
        self.say('check passed')

    def pinned(self):
        price = self.node(0).yed_getprice()
        return (price['pinnedSeqs'] or []) + (price['pinnedKeys'] or [])

    def assert_nothing_pinned(self, when):
        price = self.node(0).yed_getprice()
        check(not price['pinnedSeqs'] and not price['pinnedKeys'], 'something is pinned %s: %s / %s' % (when, price['pinnedSeqs'], price['pinnedKeys']))
        self.say('nothing pinned %s' % when)

    def assert_hash(self):
        # every node is still up: a node that died mid-scenario (F-7: the claimant's node
        # segfaults on the RPC after a clause-(b) claim) is named here rather than surfacing as
        # a connection error from whichever call came next
        down = []
        for i in range(self.state['num_nodes']):
            try:
                self.node(i).getblockcount()
            except Exception:
                down.append(i)
        check(not down, 'node(s) down at the end: %s (see node*/regtest/debug.log and the OS crash reports)' % down)
        hb = json.load(open(os.path.join(self.directory, 'heartbeat.json')))
        check(time.time() - hb['time'] < HEARTBEAT_RATE * 5, 'the heartbeat stopped (last block %d, %ds ago; see heartbeat.log)' % (hb['height'], time.time() - hb['time']))
        enforcing = [i for i in range(self.state['num_nodes']) if i != STOCK]
        # yed_getstatehash answers for a node's tip only, and the heartbeat keeps the tip moving:
        # sample every node and keep the first sample in which they all sit at one height
        at, low = {}, None
        for _ in range(20):
            hashes = {i: self.node(i).yed_getstatehash() for i in enforcing}
            heights = {h['height'] for h in hashes.values()}
            if len(heights) == 1:
                low = heights.pop()
                at = {i: h['statehash'] for i, h in hashes.items()}
                break
            time.sleep(0.5)
        check(low is not None, 'the enforcing nodes were never sampled at one height (heights %s)' % sorted(heights))
        check(len(set(at.values())) == 1, 'state hash disagrees at %d: %s' % (low, at))
        self.say('heartbeat alive; state hash %s… agrees on %d enforcing nodes at %d' % (list(at.values())[0][:12], len(enforcing), low))

    def down(self, keep):
        try:
            session = os.path.join(self.directory, 'chain-viz', 'session.jsonl')
            if os.path.exists(session):
                shutil.copy(session, os.path.join(self.options.tmpdir, 'chain-viz-session-%s.jsonl' % self.role))
                self.say('chain-viz session recorded: %s' % os.path.join(self.options.tmpdir, 'chain-viz-session-%s.jsonl' % self.role))
            self.devnet('down', *([] if keep else ['--wipe']), timeout=300)
        finally:
            self.log.close()

    def run(self):
        self.up()
        self.assert_seat_empty()
        self.assert_heartbeat()
        self.assert_walk()
        self.assert_check()
        self.assert_personas()
        self.assert_hash()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--srcdir', default=os.path.join(REPO, 'src'))
    parser.add_argument('--tmpdir', default=None)
    parser.add_argument('--portseed', type=int, default=os.getpid() % 3000)
    parser.add_argument('--seed', type=int, default=7)
    parser.add_argument('--presets', default='user,attestor,pool')
    parser.add_argument('--nocleanup', action='store_true')
    parser.add_argument('--noshutdown', action='store_true')
    # the runner's other flags, accepted and ignored
    parser.add_argument('--cachedir'); parser.add_argument('--tracerpc', action='store_true'); parser.add_argument('--coveragedir')
    options, _ = parser.parse_known_args()
    bitcoind = os.environ.get('BITCOIND') or os.path.join(options.srcdir, 'ycashd')
    if not os.access(bitcoind, os.X_OK):
        print('ycashd not found at %s' % bitcoind); return 1
    agent = find_agent()
    if agent is None:
        print('SKIP: yellowback-attest is not built (cd %s && cargo build --release, or set YELLOWBACK_ATTEST_BIN)' % os.path.normpath(CRATE))
        return 0
    options.tmpdir = options.tmpdir or os.path.join(os.environ.get('TMPDIR', '/tmp'), 'yellowback-roles-%d' % os.getpid())
    os.makedirs(options.tmpdir, exist_ok=True)
    print('agent: %s; ycashd: %s; tmpdir: %s; seed %d' % (agent, bitcoind, options.tmpdir, options.seed))
    failures = []
    for index, role in enumerate(p.strip() for p in options.presets.split(',') if p.strip()):
        if role not in EXPECT:
            print('unknown preset %s' % role); return 1
        preset = Preset(options, role, index, bitcoind, agent)
        try:
            preset.run()
            print('[%s] PASSED' % role, flush=True)
        except Failure as error:
            failures.append('%s: %s' % (role, error))
            print('[%s] FAILED: %s' % (role, error), flush=True)
            tail = open(preset.log.name).read()[-3000:]
            print('--- %s (tail) ---\n%s' % (preset.log.name, tail), flush=True)
        except Exception as error:
            failures.append('%s: %r' % (role, error))
            print('[%s] ERROR: %r' % (role, error), flush=True)
            import traceback; traceback.print_exc(file=sys.stdout)
        finally:
            if not options.noshutdown:
                preset.down(keep=options.nocleanup or bool(failures))
    if failures:
        print('FAILED: ' + '; '.join(failures))
        return 1
    if not options.nocleanup:
        shutil.rmtree(options.tmpdir, ignore_errors=True)
    print('all presets passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
