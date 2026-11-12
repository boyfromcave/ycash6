#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The mixed-line shard runner (kogany plan section 5 "mixed-regtest"; workspace
docs/plans/kogany/ci-design.md). It reads qa/kogany-mixed-shards.txt and runs one group's scripts,
unchanged, with kogany followers (KOGANY_BIN must be set; test_framework/kogany.py reads the rest
of the KOGANY_* environment).

    kogany_mixed_shards.py check
        the manifest is complete and well formed: every YELLOWBACK_SCRIPTS entry of
        .github/workflows/yellowback-tests.yml is in exactly one group or excluded, every non-direct
        script is an rpc-tests.py entry (rpc-tests.py silently drops a name it does not know),
        every direct script exists, and the harness's peer-count scripts are excluded.
    kogany_mixed_shards.py list [GROUP] [--state report|gate]
        the scripts, one per line (all groups when GROUP is omitted).
    kogany_mixed_shards.py run GROUP --state report|gate [--of MIXED_GROUP] [--jobs N] [--srcdir DIR] [--dry-run]
        runs the group's scripts in that state: rpc-tests.py --fail-on-skip --nozmq --nocleanup, one
        invocation per flag set (KOGANY_MIRROR_INVALIDATE / KOGANY_MEMPOOL), the direct scripts on
        their own; state gate adds KOGANY_STRICT=1. Exit 1 when any invocation failed. A table goes
        to $GITHUB_STEP_SUMMARY when it is set.

The `sidecar` group (kogany plan W9-a) is not a sixth shard of the mixed suite but a second mode
for scripts already in one: the wallet-needing scripts, run with KOGANY_SIDECAR=1 (every node a
kogany plus a ycashd -connect'ed to it, test_framework/kogany.py "The ycash6 test rig"). A sidecar
script must also be in exactly one mixed group; `--of GROUP` runs the sidecar scripts of that mixed
group only (the nightly runs one job per mixed group). Once the sidecar group has entries, every
non-direct mixed-group script is either in it or named by an `excluded:sidecar <script> <reason>` row
(a script that calls no wallet RPC), so a new functional script cannot silently miss the rig and no
count has to be kept anywhere.

The `pair` group (kogany plan S5, column 3 of the W9 matrix) is the third mode for the same
wallet-needing scripts: every node kogany + yewd, no ycashd behind any node (YEWD_BIN with
YEWD_KOGANY; test_framework/kogany.py YewdColumn). Its entries carry no MixedLine flags (there is no
follower to mirror to); YEWD_YCASH6_PEER=1 in the caller's environment runs the mixed variant. It is
the sidecar group less the `excluded:pair <script> <reason>` rows (scripts kept out of column 3 by
decision; they keep their mixed group and sidecar rows), and `check` holds it to that.

Both repositories' CI call this file (ycash6 yellowback-tests.yml `mixed`; kogany's mixed-regtest
leg from a ycash6 checkout at its pin), so the shard lists live in one place.
"""

import argparse
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
MANIFEST = os.path.join(HERE, 'kogany-mixed-shards.txt')
WORKFLOW = os.path.join(REPO, '.github', 'workflows', 'yellowback-tests.yml')
RPC_TESTS = os.path.join(HERE, 'pull-tester', 'rpc-tests.py')
RPC_DIR = os.path.join(HERE, 'rpc-tests')

MIXED_GROUPS = ('node', 'vault', 'yed', 'fees', 'attest')
SIDECAR = 'sidecar'
PAIR = 'pair'
SECOND_MODES = (SIDECAR, PAIR)
GROUPS = MIXED_GROUPS + SECOND_MODES
STATES = ('report', 'gate')
FLAGS = {'mirror': 'KOGANY_MIRROR_INVALIDATE', 'mempool': 'KOGANY_MEMPOOL', 'direct': None}
WAVE = re.compile(r'^W[0-9](-[a-z0-9]+)?$')
# test_framework/kogany.py "Recorded limits": scripts that assert an exact getpeerinfo count.
PEER_COUNT = ('maxuploadtarget', 'nodehandling', 'p2p_ban_pool_value_out_of_range',
              'p2p_nu_peer_management', 'signrawtransaction_offline', 'yellowback_framework_smoke')


class Entry:
    def __init__(self, group, script, state, wave, flags, line):
        self.group, self.script, self.state, self.wave, self.flags, self.line = (
            group, script, state, wave, tuple(flags), line)

    @property
    def direct(self):
        return 'direct' in self.flags


def parse(text):
    """(entries, excluded, errors): ``excluded`` maps a script to its reason (never in a mixed
    shard) and ``(mode, script)`` to the reason of an ``excluded:<mode>`` row (kept out of that
    second mode only; ``mode_excluded``)."""
    entries, excluded, errors = [], {}, []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        f = line.split()
        if f[0].startswith('excluded:'):
            mode = f[0].split(':', 1)[1]
            if mode not in SECOND_MODES:
                errors.append('line %d: %s: only %s are known' % (n, f[0], ', '.join('excluded:' + m for m in SECOND_MODES)))
            elif len(f) < 3:
                errors.append('line %d: %s needs a script and a reason' % (n, f[0]))
            else:
                excluded[(mode, f[1])] = ' '.join(f[2:])
            continue
        if f[0] == 'excluded':
            if len(f) < 3:
                errors.append('line %d: excluded needs a script and a reason' % n)
            else:
                excluded[f[1]] = ' '.join(f[2:])
            continue
        if len(f) < 4:
            errors.append('line %d: want <group> <script> <state> <wave> [flags]' % n)
            continue
        group, script, state, wave, flags = f[0], f[1], f[2], f[3], f[4:]
        if group not in GROUPS:
            errors.append('line %d: unknown group %r (one of %s)' % (n, group, ', '.join(GROUPS)))
        if state not in STATES:
            errors.append('line %d: unknown state %r (report or gate)' % (n, state))
        if not WAVE.match(wave):
            errors.append('line %d: %r is not a wave (W<n> or W<n>-<chunk>)' % (n, wave))
        for fl in flags:
            if fl not in FLAGS:
                errors.append('line %d: unknown flag %r' % (n, fl))
        entries.append(Entry(group, script, state, wave, flags, n))
    return entries, excluded, errors


def mode_excluded(excluded, mode):
    """{script: reason} of the ``excluded:<mode>`` rows."""
    return {k[1]: v for k, v in excluded.items() if isinstance(k, tuple) and k[0] == mode}


def mixed_excluded(excluded):
    """{script: reason} of the plain ``excluded`` rows."""
    return {k: v for k, v in excluded.items() if not isinstance(k, tuple)}


def load(path=MANIFEST):
    with open(path, encoding='utf-8') as fh:
        return parse(fh.read())


def workflow_scripts(path=WORKFLOW):
    with open(path, encoding='utf-8') as fh:
        for line in fh:
            m = re.match(r'^\s+YELLOWBACK_SCRIPTS:\s*(.+?)\s*$', line)
            if m:
                return m.group(1).split()
    raise SystemExit('no YELLOWBACK_SCRIPTS line in %s' % path)


def rpc_tests_names(path=RPC_TESTS):
    with open(path, encoding='utf-8') as fh:
        return set(re.findall(r"'([A-Za-z0-9_]+)\.py", fh.read()))


def check(entries, excluded, yellowback_scripts, known, exists):
    """Problems with the manifest, as a list of strings (empty: fine)."""
    problems = []
    seen = {}
    second = {m: {} for m in SECOND_MODES}
    for e in entries:
        if e.group in SECOND_MODES:
            mode = second[e.group]
            if e.script in mode:
                problems.append('%s listed twice in %s (lines %d and %d)' % (e.script, e.group, mode[e.script], e.line))
            mode[e.script] = e.line
            if e.direct:
                problems.append('%s: a %s entry runs through rpc-tests.py, never direct' % (e.script, e.group))
            elif e.script not in known:
                problems.append('%s is not an rpc-tests.py entry: rpc-tests.py would drop it silently' % e.script)
            continue
        if e.script in seen:
            problems.append('%s listed twice (lines %d and %d)' % (e.script, seen[e.script], e.line))
        seen[e.script] = e.line
        if e.script in excluded:
            problems.append('%s is both in group %s and excluded' % (e.script, e.group))
        if e.direct:
            if not exists(e.script):
                problems.append('%s (direct) has no qa/rpc-tests/%s.py' % (e.script, e.script))
        elif e.script not in known:
            problems.append('%s is not an rpc-tests.py entry: rpc-tests.py would drop it silently '
                            '(register it, or mark it direct)' % e.script)
    for s in yellowback_scripts:
        if s not in seen and s not in excluded:
            problems.append('%s (YELLOWBACK_SCRIPTS) is in no mixed group and not excluded' % s)
    for s in PEER_COUNT:
        if s in seen or any(s in m for m in second.values()):
            problems.append('%s asserts an exact peer count and must be excluded' % s)
    for g, mode in second.items():
        for s in mode:
            if s not in seen:
                problems.append('%s is in %s but in no mixed group' % (s, g))
    # the sidecar group is every non-direct mixed-group script less its excluded:sidecar rows
    no_side = mode_excluded(excluded, SIDECAR)
    for s in no_side:
        if s in second[SIDECAR]:
            problems.append('%s is both in %s and excluded:%s' % (s, SIDECAR, SIDECAR))
        if s not in seen:
            problems.append('%s is excluded:%s but in no mixed group' % (s, SIDECAR))
    if second[SIDECAR]:
        for e in entries:
            if e.group in MIXED_GROUPS and not e.direct and e.script not in second[SIDECAR] and e.script not in no_side:
                problems.append('%s is in mixed group %s but neither in %s nor excluded:%s (no wallet RPC)'
                                % (e.script, e.group, SIDECAR, SIDECAR))
    # the pair group is the sidecar group less its excluded:pair rows
    out = mode_excluded(excluded, PAIR)
    for s in out:
        if s in second[PAIR]:
            problems.append('%s is both in %s and excluded:%s' % (s, PAIR, PAIR))
        if s not in second[SIDECAR]:
            problems.append('%s is excluded:%s but not in %s' % (s, PAIR, SIDECAR))
    if second[PAIR]:
        for s in second[SIDECAR]:
            if s not in second[PAIR] and s not in out:
                problems.append('%s is in %s but neither in %s nor excluded:%s' % (s, SIDECAR, PAIR, PAIR))
        for s in second[PAIR]:
            if s not in second[SIDECAR]:
                problems.append('%s is in %s but not in %s' % (s, PAIR, SIDECAR))
    return problems


def mixed_group_of(entries):
    """{script: its mixed group} (the sidecar entries left out)."""
    return {e.script: e.group for e in entries if e.group not in SECOND_MODES}


def select(entries, group=None, state=None, of=None):
    """The entries of ``group`` in ``state``; ``of`` (sidecar only) keeps those whose script is in that
    mixed group."""
    groups = mixed_group_of(entries) if of else {}
    return [e for e in entries if (group is None or e.group == group) and (state is None or e.state == state)
            and (of is None or groups.get(e.script) == of)]


def partitions(selected):
    """[(env additions, direct?, [scripts])], in a stable order: one rpc-tests.py run per flag set."""
    parts = {}
    for e in selected:
        if e.group == PAIR:
            # column 3 (kogany + yewd): the MixedLine flags have no follower to act on; the run's
            # YEWD_BIN and YEWD_KOGANY name the binaries (test_framework/kogany.py YewdColumn)
            env = ()
        else:
            env = tuple(sorted([FLAGS[f] for f in e.flags if FLAGS[f]] + (['KOGANY_SIDECAR'] if e.group == SIDECAR else [])))
        if e.direct:
            parts.setdefault((env, True, e.script), []).append(e.script)
        else:
            parts.setdefault((env, False, ''), []).append(e.script)
    return [(dict((k, '1') for k in key[0]), key[1], names) for key, names in sorted(parts.items())]


def commands(selected, state, jobs, srcdir, tmpdir):
    out = []
    for env, direct, names in partitions(selected):
        if state == 'gate':
            env['KOGANY_STRICT'] = '1'
        if direct:
            name = names[0]
            cmd = [sys.executable, '-u', os.path.join(RPC_DIR, name + '.py'), '--srcdir=' + srcdir,
                   '--nocleanup', '--tmpdir=' + os.path.join(tmpdir, 'direct-' + name)]
            env.setdefault('ZCASHD', os.path.join(srcdir, 'ycashd'))
        else:
            cmd = [sys.executable, RPC_TESTS, '--fail-on-skip', '-j%d' % jobs, '--nozmq', '--nocleanup'] + names
        out.append((env, cmd, names))
    return out


def summary(group, state, rows):
    lines = ['### mixed %s (%s)' % (group, state), '', '| scripts | environment | result | seconds |',
             '|---|---|---|---|']
    for names, env, rc, secs in rows:
        lines.append('| %s | %s | %s | %d |' % (' '.join(names), ' '.join('%s=%s' % kv for kv in sorted(env.items())) or '-',
                                              'pass' if rc == 0 else 'FAIL (%d)' % rc, secs))
    return '\n'.join(lines) + '\n'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('check')
    lp = sub.add_parser('list')
    lp.add_argument('group', nargs='?', choices=GROUPS)
    lp.add_argument('--state', choices=STATES)
    lp.add_argument('--of', choices=MIXED_GROUPS, help='sidecar, pair: only the scripts of this mixed group')
    rp = sub.add_parser('run')
    rp.add_argument('group', choices=GROUPS)
    rp.add_argument('--state', choices=STATES, required=True)
    rp.add_argument('--of', choices=MIXED_GROUPS, help='sidecar, pair: only the scripts of this mixed group')
    rp.add_argument('--jobs', type=int, default=2)
    rp.add_argument('--srcdir', default=os.path.join(REPO, 'src'))
    rp.add_argument('--dry-run', action='store_true')
    args = ap.parse_args(argv)

    entries, excluded, errors = load()
    if errors:
        for e in errors:
            print('kogany-mixed-shards.txt: ' + e, file=sys.stderr)
        return 1

    if args.cmd == 'check':
        problems = check(entries, excluded, workflow_scripts(), rpc_tests_names(),
                         lambda s: os.path.isfile(os.path.join(RPC_DIR, s + '.py')))
        for p in problems:
            print('kogany-mixed-shards: ' + p, file=sys.stderr)
        if not problems:
            counts = ', '.join('%s %d' % (g, len(select(entries, g))) for g in GROUPS)
            gated = len(select(entries, state='gate'))
            print('kogany-mixed-shards: ok (%s; %d gated, %d excluded, %d excluded from %s)'
                  % (counts, gated, len(mixed_excluded(excluded)), len(mode_excluded(excluded, PAIR)), PAIR))
        return 1 if problems else 0

    if args.cmd == 'list':
        for e in select(entries, args.group, args.state, args.of):
            print(e.script)
        return 0

    if args.of and args.group not in SECOND_MODES:
        print('--of selects within the sidecar and pair groups only', file=sys.stderr)
        return 2
    selected = select(entries, args.group, args.state, args.of)
    if not selected:
        print('mixed %s: no script in state %s' % (args.group, args.state))
        return 0
    if args.group == PAIR and not args.dry_run and not (os.environ.get('YEWD_BIN') and os.environ.get('YEWD_KOGANY')):
        print('pair (column 3) needs YEWD_BIN and YEWD_KOGANY (yewd and zakurad)', file=sys.stderr)
        return 1
    if args.group != PAIR and not args.dry_run and not os.environ.get('KOGANY_BIN'):
        print('KOGANY_BIN is not set: this would be the plain ycash6 run, not a mixed one', file=sys.stderr)
        return 1
    tmpdir = os.environ.get('TMPDIR') or '/tmp'
    rows, failed = [], 0
    for env, cmd, names in commands(selected, args.state, args.jobs, args.srcdir, tmpdir):
        shown = ' '.join('%s=%s' % kv for kv in sorted(env.items()))
        print('mixed %s (%s): %s %s' % (args.group, args.state, shown, ' '.join(cmd)), flush=True)
        if args.dry_run:
            continue
        t0 = time.time()
        rc = subprocess.call(cmd, cwd=REPO, env=dict(os.environ, **env))
        rows.append((names, env, rc, time.time() - t0))
        failed += rc != 0
    if rows and os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as fh:
            fh.write(summary(args.group, args.state, rows))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
