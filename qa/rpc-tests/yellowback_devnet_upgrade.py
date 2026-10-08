#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The devnet on the vault upgrade, end to end (docs/plans/yellowback-upgrade-plan.md §4, §5, §15.10):
the core of ``contrib/yellowback/devnet/upgrade-walk`` in CI time.

Like ``yellowback_devnet_roles.py`` this script builds no network of its own: it drives
``yellowback-devnet up --role attestor --no-heartbeat --no-walk --no-sim --no-viz`` as a
subprocess, then ``upgrade-walk --skip clients`` against it, and asserts from the walk's JSON
summary that every step passed:

  members   node 8 joins the YED attestor set (SET_JOIN), matures, heartbeats; node 6, its agent
            stopped, goes DORMANT under S15 and revives with a SET_HEARTBEAT
  mint      mints are the primitive's V template (tag YED, the attestor set, CLAIM_DELAY)
  transfer  yed_send; redeem: owner redeem (selector 2) and a renew
  claim     an underwater claim into a claimant intent, a reorg across it (ACTIVE, then CLAIMING,
            state hashes equal), the release after CLAIM_DELAY (CLAIMED)
  cancel    a wrong-price claim cancelled by one attestor: burn lost, the vault ACTIVE again
  interm    an in-term claim (in-term claims plan): a class-A vault crosses theta in term, a claim
            above theta refused, the claim at theta accepted and released, an owner redeem; SKIPs
            (and passes) on a node whose yed_getinfo.params.inTermClaims is not true
  invalid   an invalid mint refused by every Yellowback mempool, its block rejected by every node
  bridge    the WYEC bridge persona (bridge-sim), both shapes: lock -> mock burn -> intent ->
            release; a rogue intent cancelled by the watcher; owner recovery on a dormant set
  final     one YED state hash on the ten Yellowback nodes, one vault state hash on all eleven

The clients (chain-viz, lightwalletd, yolo) are left to the manual walk (its transcript is
``contrib/yellowback/devnet/upgrade-walk-transcript.txt``). SKIPs without the Rust attestor
binary (YELLOWBACK_ATTEST_BIN, or the CARGO_TARGET_DIR / crate-local search). Zero C++.

    ZCASHD=<ycashd> ../.venv/bin/python -u qa/rpc-tests/yellowback_devnet_upgrade.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..'))
DEVNET = os.path.join(REPO, 'contrib', 'yellowback', 'devnet', 'yellowback-devnet')
WALK = os.path.join(REPO, 'contrib', 'yellowback', 'devnet', 'upgrade-walk')
CRATE = os.path.join(REPO, 'contrib', 'yellowback', 'attest')
STEPS = ('members', 'mint', 'transfer', 'redeem', 'claim', 'cancel', 'interm', 'invalid', 'bridge', 'final')


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--srcdir', default=os.path.join(REPO, 'src'))
    parser.add_argument('--tmpdir', default=None)
    parser.add_argument('--portseed', type=int, default=os.getpid() % 1000)
    parser.add_argument('--nocleanup', '--noshutdown', dest='nocleanup', action='store_true')
    parser.add_argument('--tracerpc', action='store_true')        # accepted for rpc-tests.py; unused
    parser.add_argument('--bridge-shapes', default='guardians,relayer')
    options, _ = parser.parse_known_args()
    tmpdir = options.tmpdir or tempfile.mkdtemp(prefix='yb-devnet-upgrade-')
    os.makedirs(tmpdir, exist_ok=True)
    bitcoind = os.environ.get('ZCASHD') or os.path.join(options.srcdir, 'ycashd')
    agent = find_agent()
    if agent is None:
        print('SKIP: yellowback-attest not built (cd contrib/yellowback/attest && cargo build --release, or YELLOWBACK_ATTEST_BIN)')
        return 0
    if not os.access(bitcoind, os.X_OK):
        print('FAIL: ycashd not found at %s' % bitcoind)
        return 1
    directory = os.path.join(tmpdir, 'devnet')
    log = open(os.path.join(tmpdir, 'devnet.log'), 'a')
    env = dict(os.environ, ZCASHD=bitcoind, YELLOWBACK_ATTEST_BIN=agent)
    t0 = time.time()

    def run(argv, timeout):
        log.write('\n$ %s\n' % ' '.join(argv)); log.flush()
        return subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, env=env, timeout=timeout).returncode

    def say(text):
        print('[+%4ds] %s' % (time.time() - t0, text), flush=True)

    status = 1
    try:
        say('devnet up --role attestor --no-heartbeat --no-walk --no-sim --no-viz (portseed %d)' % options.portseed)
        rc = run([sys.executable, DEVNET, 'up', '--role', 'attestor', '--no-heartbeat', '--no-walk', '--no-sim', '--no-viz',
                  '--seed', '480', '--force', '--dir', directory, '--portseed', str(options.portseed), '--bitcoind', bitcoind], 900)
        if rc != 0:
            print('FAIL: yellowback-devnet up exited %d; see %s/devnet.log' % (rc, tmpdir))
            return 1
        say('up; walking (upgrade-walk --skip clients)')
        summary_path = os.path.join(tmpdir, 'summary.json')
        transcript = os.path.join(tmpdir, 'upgrade-walk-transcript.txt')
        rc = run([sys.executable, WALK, '--dir', directory, '--skip', 'clients', '--transcript', transcript,
                  '--summary', summary_path, '--bridge-shapes', options.bridge_shapes], 1500)
        summary = json.load(open(summary_path)) if os.path.exists(summary_path) else {}
        with open(transcript) as f:
            for line in f:
                if line.startswith(('[', '  PASS', '  FAIL', '  # SKIP', 'WALK')):
                    print('    ' + line.rstrip()[:200])
        failed = [s for s in STEPS if summary.get('steps', {}).get(s) is None]
        if rc != 0 or failed or summary.get('failed'):
            print('FAIL: the walk exited %d; steps not passed: %s; %s (transcript %s)' % (rc, ', '.join(failed) or '-', summary.get('failed'), transcript))
            return 1
        members = summary['steps']['members']
        assert members['revived_at'] > members['dormant_at'], members
        evidence = summary.get('evidence', {})
        for key in ('join_txid', 'heartbeat_txid', 'claim', 'cancel', 'invalid', 'statehash'):
            assert key in evidence, key
        interm = summary['steps']['interm']
        if isinstance(interm, str) and interm.startswith('SKIP'):
            say('interm: %s' % interm)
        else:
            assert evidence.get('interm', {}).get('claim') and evidence['interm'].get('release') and evidence['interm'].get('redeem'), interm
            assert interm['claimedAt'] < interm['claimHeightWouldHaveBeen'], interm
        for shape in options.bridge_shapes.split(','):
            assert evidence.get('bridge_%s_release' % shape, {}).get('release'), shape
            assert evidence.get('bridge_%s_rogue' % shape, {}).get('cancelled'), shape
        say('PASS: every step of the walk passed at height %s (%s s walking)' % (summary.get('height'), summary.get('seconds')))
        status = 0
    finally:
        run([sys.executable, DEVNET, 'down', '--dir', directory] + ([] if options.nocleanup else ['--wipe']), 300)
        if status == 0 and not options.nocleanup and not options.tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
    return status


if __name__ == '__main__':
    sys.exit(main())
