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
  pq        the post-quantum line: SLH-DSA vault owners (a wallet mint; the primitive's vault_lock /
            vault_ownerspend, FN-DSA-512 owners too once Falcon is active), PQ holder transfers, the
            hybrid channel TX_PQCHANNEL
  falcon    TOK-PQ: P2PKH holders refused by the wallet and every mempool, Falcon holders continue; with
            --pqfalconheight N the activation at N and a reorg across it (default: Falcon live with the
            vault upgrade, as mainnet; --no-pqfalcon: the pre-Falcon regime, the step SKIPs)
  claim     an underwater claim into a claimant intent, a reorg across it (ACTIVE, then CLAIMING,
            state hashes equal), the release after CLAIM_DELAY (CLAIMED)
  cancel    a wrong-price claim cancelled by one attestor: burn lost, the vault ACTIVE again
  interm    an in-term claim (in-term claims plan): a class-A vault crosses theta in term, a claim
            above theta refused, the claim at theta accepted and released, the owner's in-term
            redeems (D-IT-15) paying the early-redeem fee, 5 % of the debt at the mint price (IT-9'); SKIPs
            (and passes) on a node whose yed_getinfo.params.inTermClaims is not true
  invalid   an invalid mint refused by every Yellowback mempool, its block rejected by every node
  bridge    the WYEC bridge persona (bridge-sim), both shapes: lock -> mock burn -> intent ->
            release; a rogue intent cancelled by the watcher; owner recovery on a dormant set
  final     one YED and one vault state hash on the ten module nodes, one tip on all eleven; the stock
            node's set state differs from theirs in the attestor set's member lastact alone (07/F-4),
            and every node reports its attestor set (vault_getinfo.attestorsetid, 01/V-7)

After the walk, an independent witness of the set state (07/F-4): two Python VaultModels replay the
chain from the activation height, one with the YED module's liveness hook
(test_framework/vault_module_hook.py, a port of Module::Liveness) and one without; every set and
member of node 0 (a module node) must equal the first's, every one of node 1 (the stock node) the
second's, the models must differ exactly where the nodes do, and the hook must have credited
liveness somewhere on the chain (the walk's heartbeats can re-converge the tip's lastact).

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
STEPS = ('members', 'mint', 'transfer', 'pq', 'redeem', 'claim', 'cancel', 'interm', 'invalid', 'bridge', 'falcon', 'final')


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


def witness(directory, stock_evidence, say):
    """07/F-4: the two-model replay over the walked chain, compared with node 0 (module) and node 1 (stock)."""
    import importlib.machinery
    import importlib.util
    sys.path.insert(0, HERE)
    from test_framework import vault_module_hook as vmh
    from test_framework import yellowback_model as ym
    loader = importlib.machinery.SourceFileLoader('yellowback_devnet', DEVNET)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    dv = importlib.util.module_from_spec(spec)
    loader.exec_module(dv)
    state = dv.load(directory)
    user, stock = dv.rpc(state, 0, timeout=600), dv.rpc(state, 1, timeout=600)
    t0 = time.time()
    params = ym.params_from_getinfo(user.yed_getinfo())
    with_hook, without, tip, credits = vmh.replay_models(user, params)
    assert stock.getbestblockhash() == user.getblockhash(tip), 'the stock node is not at the replayed tip'
    h = tip + 1
    n_user = vmh.compare_set_state(user, with_hook, h)
    n_stock = vmh.compare_set_state(stock, without, h)
    # the models differ where the nodes do: in the attestor set's lastAct, as the walk recorded it
    sid = vmh.set_id_internal(params.attestor_set)
    a, b = with_hook.get_set(sid), without.get_set(sid)
    differ = {k.hex(): (a.members[k].last_act, b.members[k].last_act) for k in a.members if a.members[k].last_act != b.members[k].last_act}
    recorded = {k: (d['module'], d['stock']) for k, d in stock_evidence['lastactDiff'].items()}
    assert differ == recorded, 'the models differ in %r, the nodes (walk evidence) in %r' % (differ, recorded)
    # the hook credited attestation liveness somewhere on the chain (a later heartbeat may re-converge the end state)
    assert credits > 0, 'the walk credited no attestation liveness: the module hook was never exercised'
    say('witness: two VaultModels over [%d, %d] agree with node 0 (%d members, with the module hook: %d credits) and node 1 '
        '(%d members, without); %d lastAct differ at the tip, as on the nodes (%d s)'
        % (with_hook.activation_height, tip, n_user, credits, n_stock, len(differ), time.time() - t0))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--srcdir', default=os.path.join(REPO, 'src'))
    parser.add_argument('--tmpdir', default=None)
    parser.add_argument('--portseed', type=int, default=os.getpid() % 1000)
    parser.add_argument('--nocleanup', '--noshutdown', dest='nocleanup', action='store_true')
    parser.add_argument('--tracerpc', action='store_true')        # accepted for rpc-tests.py; unused
    parser.add_argument('--bridge-shapes', default='guardians,relayer')
    parser.add_argument('--pqfalconheight', type=int, help='up --pqfalconheight N (the walk\'s falcon step activates Falcon at N and reorgs across it)')
    parser.add_argument('--no-pqfalcon', action='store_true', help='up --no-pqfalcon: the pre-Falcon regime')
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
                  '--seed', '480', '--force', '--dir', directory, '--portseed', str(options.portseed), '--bitcoind', bitcoind]
                 + (['--no-pqfalcon'] if options.no_pqfalcon else ['--pqfalconheight', str(options.pqfalconheight)] if options.pqfalconheight is not None else []), 900)
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
            ev = evidence.get('interm', {})
            assert ev.get('claim') and ev.get('release') and ev.get('redeemAboveTheta') and ev.get('redeemUnderTheta'), interm
            assert interm['claimedAt'] < interm['claimHeightWouldHaveBeen'], interm
            assert all(fee > 0 for fee in ev.get('earlyRedeemFeeZat', [])) and len(ev['earlyRedeemFeeZat']) == 2, ev   # IT-9 (the walk checks 5 %)
        for key in ('pq_mint', 'pq_primitive', 'pq_transfer', 'pq_channel'):
            assert key in evidence, key
        # the hybrid channel is closed cooperatively: an SLH-DSA client before Falcon, a Falcon client after it
        # (the framework's optional Falcon signer; without a C compiler the walk only funds it)
        from test_framework import pq as _pq
        channel = evidence['pq_channel']
        if channel.get('client') == 'slh' or _pq.falcon_signer_available():
            assert channel.get('close'), channel
        falcon = summary['steps']['falcon']
        if options.no_pqfalcon:
            assert isinstance(falcon, str) and falcon.startswith('SKIP'), falcon
        else:
            assert evidence.get('falcon', {}).get('falconSend'), falcon
            if options.pqfalconheight is not None:
                assert falcon['activation'] and falcon['reorg'], falcon
                ev = evidence['falcon']
                assert ev['statehashBefore'] and ev['statehashAfter'] and ev['afterReorgP2pkh'], ev
        say('pq: %s; falcon: %s' % (', '.join(sorted(k for k in evidence if k.startswith('pq_'))), falcon))
        for shape in options.bridge_shapes.split(','):
            assert evidence.get('bridge_%s_release' % shape, {}).get('release'), shape
            assert evidence.get('bridge_%s_rogue' % shape, {}).get('cancelled'), shape
        stock = evidence['statehash'].get('stock') or {}
        assert evidence['statehash'].get('attestorSetId') and 'lastactDiff' in stock, evidence['statehash']
        witness(directory, stock, say)
        say('PASS: every step of the walk passed at height %s (%s s walking)' % (summary.get('height'), summary.get('seconds')))
        status = 0
    finally:
        run([sys.executable, DEVNET, 'down', '--dir', directory] + ([] if options.nocleanup else ['--wipe']), 300)
        if status == 0 and not options.nocleanup and not options.tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
    return status


if __name__ == '__main__':
    sys.exit(main())
