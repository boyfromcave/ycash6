#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""One source for the Yellowback RPC version (beta3 lane "test-harness and release-hygiene").

``YELLOWBACK_RPC_VERSION`` (src/rpc/yellowback.cpp) is what ``yed_getinfo.rpcversion`` reports;
doc/yellowback-rpc-contract.json carries the same number (CI compares the two). Tests and scripts
read the expected version from the contract (``test_framework.yellowback_util.YELLOWBACK_RPC_VERSION``),
never from a literal: every bump (5, 7, 8, 9, 10) left stragglers that still expected the old one.

    qa/yellowback-rpcversion.py version   print the contract's rpcversion, after checking the constant agrees
    qa/yellowback-rpcversion.py check     fail on a literal rpcversion check outside ALLOW (the audit's
                                          `rpcversion` leg); --root <dir> scans another checkout

A literal check is a comparison, assertion, membership test or key/value pair that puts a number
next to ``rpcversion`` (``info['rpcversion'] == 10``, ``assert_equal(x['rpcversion'], 10)``,
``"rpcversion": 10``, ``rpcversion not in ("9", "10")``). Prose that names a version
("rpcversion 7: ownerScheme") is history and is not matched.
"""

import argparse
import json
import os
import re
import subprocess
import sys

CONTRACT = 'doc/yellowback-rpc-contract.json'
CONSTANT_FILE = 'src/rpc/yellowback.cpp'
CONSTANT_RE = re.compile(r'^static const int YELLOWBACK_RPC_VERSION = (\d+);', re.M)

# The files that may state the version as a number, each with its reason.
ALLOW = {
    CONSTANT_FILE: 'the constant itself',
    CONTRACT: 'the contract the tests read',
    'doc/yellowback-rpc.md': 'the contract\'s source document (make spec generates the JSON from it)',
    'doc/yellowback-spec.md': 'the generated specification copy (make spec; its examples name the version of their section)',
    'doc/yellowback-demo-transcript.txt': 'a recorded run (history)',
    'contrib/yellowback/devnet/upgrade-walk-transcript.txt': 'a recorded run (history)',
    'qa/yellowback-rpcversion.py': 'this checker (its patterns)',
    'qa/test_yellowback_rpcversion.py': 'this checker\'s unit test (its samples)',
    'contrib/yellowback/attest/proto/yellowback.proto': 'a byte copy of lightwalletd-dd\'s proto: a field number, not a check',
}
ALLOW_PREFIXES = (
    'doc/release-notes',           # release notes (doc/release-notes.md, doc/release-notes/): what a release told clients
)

_NUM = r'["\']?\d+["\']?'
_KEY = r'rpcversion'
PATTERNS = [
    # info['rpcversion'] == 10, rpcversion != 9, d.get("rpcversion") >= 7
    re.compile(_KEY + r'[\w"\'\]\)#]*\s*(==|!=|>=|<=|<|>)\s*' + _NUM),
    # 10 == info['rpcversion']
    re.compile(r'(^|[^\w.])' + _NUM + r'\s*(==|!=|>=|<=|<|>)\s*[\w.\[\]"\'()]*' + _KEY),
    # assert_equal(x['rpcversion'], 10) / assert_equal(10, x['rpcversion'])
    re.compile(r'assert_equal\([^#]*' + _KEY + r'[^#,]*,\s*' + _NUM + r'\s*\)'),
    re.compile(r'assert_equal\(\s*' + _NUM + r'\s*,[^#]*' + _KEY),
    # "rpcversion": 10 / rpcversion=10 (a JSON or dict literal, a keyword argument)
    re.compile(_KEY + r'["\']?\s*[:=]\s*' + _NUM + r'\b'),
    # rpcversion not in ("5", ..., "10") / in [9, 10]
    re.compile(_KEY + r'[^#\n]*\bin\s*[\(\[\{]\s*' + _NUM),
    # shell: [ "$rpcversion" -eq 10 ]
    re.compile(_KEY + r'["\'}]*\s*-(eq|ne|ge|le|gt|lt)\s*' + _NUM),
]


def literal_checks(text):
    """[(line number, line)] of ``text``'s literal rpcversion checks."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        if _KEY not in low:
            continue
        if any(p.search(low) for p in PATTERNS):
            out.append((n, line))
    return out


def allowed(path):
    return path in ALLOW or path.startswith(ALLOW_PREFIXES)


def tracked_with_key(root):
    """The tracked text files of ``root`` that mention rpcversion (any case)."""
    r = subprocess.run(['git', '-C', root, 'grep', '-l', '-I', '-i', _KEY], capture_output=True, text=True)
    if r.returncode not in (0, 1):
        raise SystemExit('git grep failed in %s: %s' % (root, r.stderr.strip()))
    return [p for p in r.stdout.splitlines() if p]


def check(root):
    """Every literal rpcversion check outside ALLOW: [(path, line number, line)]."""
    bad = []
    for path in tracked_with_key(root):
        if allowed(path):
            continue
        with open(os.path.join(root, path), encoding='utf-8', errors='replace') as f:
            for n, line in literal_checks(f.read()):
                bad.append((path, n, line.strip()))
    return bad


def contract_version(root):
    with open(os.path.join(root, CONTRACT), encoding='utf-8') as f:
        return json.load(f)['rpcversion']


def constant_version(root):
    with open(os.path.join(root, CONSTANT_FILE), encoding='utf-8') as f:
        m = CONSTANT_RE.search(f.read())
    if m is None:
        raise SystemExit('%s: no "static const int YELLOWBACK_RPC_VERSION = <n>;" line' % CONSTANT_FILE)
    return int(m.group(1))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('command', choices=('version', 'check'))
    ap.add_argument('--root', default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    a = ap.parse_args(argv)
    want, have = contract_version(a.root), constant_version(a.root)
    if want != have:
        print('%s says rpcversion %s, %s says %s: regenerate the contract (make spec) or fix the constant'
              % (CONTRACT, want, CONSTANT_FILE, have))
        return 1
    if a.command == 'version':
        print(want)
        return 0
    bad = check(a.root)
    for path, n, line in bad:
        print('%s:%d: a literal rpcversion check: %s' % (path, n, line[:160]))
    if bad:
        print('read the version from %s instead (test_framework.yellowback_util.YELLOWBACK_RPC_VERSION), '
              'or, for a deliberate old-version case, name the file in ALLOW (qa/yellowback-rpcversion.py) '
              'with its reason' % CONTRACT)
        return 1
    print('no literal rpcversion check outside the allow-list (rpcversion %d)' % want)
    return 0


if __name__ == '__main__':
    sys.exit(main())
