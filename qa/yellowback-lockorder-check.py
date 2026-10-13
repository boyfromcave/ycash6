#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Read every debug.log under the given directories, group the DEBUG_LOCKORDER reports, and fail on any
whose inverted pair involves Yellowback -- except the one pair that is provably not a deadlock:
the miner holds cs_yellowback (the TemplateView created right after LOCK2(cs_main, mempool.cs) in
BlockAssembler::CreateNewBlock, miner.cpp) across TestNewBlockAtTipValidity, whose ConnectBlock takes
the script-check queue's ControlMutex (CCheckQueueControl, main.cpp) before the CheckConnect hook
takes cs_yellowback again (re-entrant), while ConnectTip takes ControlMutex before CheckConnect takes
cs_yellowback. Both paths hold cs_main from their first line, so they are mutually exclusive and the
inversion cannot deadlock; the structural fix (drop the TemplateView before the validity check) is
a change in the budgeted miner.cpp, recorded as an open item (role-based plan F-37).
A second pair is new on 6.20.0 and allow-listed on the same proof: the vault-spend and carrier RPCs
(rpc/yellowbackwallet.cpp RunVaultSpend / CarrierStep) hold mempool.cs and cs_yellowback across
CommitTransaction, whose relay takes cs_vNodes then pnode->cs_inventory, while 6.20.0's SendMessages
takes cs_inventory and then mempool.cs (CompareInvMempoolOrder -> CTxMemPool::info, main.cpp
trickle inventory; v4.5.0's SendMessages never took mempool.cs there). The RPC holds cs_main from
LOCK2(cs_main, cs_wallet) and SendMessages proceeds only with its TRY_LOCK(cs_main) taken, so the two
are mutually exclusive. The structural fix (commit after releasing mempool.cs and cs_yellowback, with
cs_main still held) is recorded as an open item.
Every other report is printed and counted; on 6.20.0 the inherited ones are TRY_LOCK pairs in net.cpp
(cs_vNodes / pnode->cs_vRecvMsg / pnode->cs_inventory), which cannot deadlock.

The node must be built with --enable-debug and src/sync.cpp patched by qa/yellowback-lockorder-logonly.sh,
or the first stock report aborts it before any Yellowback code runs (mapping §19 S3).

A report "names Yellowback" when its text matches YELLOWBACK_TOKENS: the overlay's lock names and the
source files of the lock sites (a report lists each held lock as "<name>  <file>:<line>", file relative
to src/). Before audit 07/F-11 the test was the substring 'yellowback' or 'yed_', which the vault
primitive's lock sites (vault/node.cpp, rpc/vault.cpp) never contain, so a vault inversion counted as
inherited and passed. Note that DEBUG_LOCKORDER only tracks the LOCK()-family critical sections:
VaultDB::cs and VaultState::cs are std::mutex under std::lock_guard and never appear in a report.

--selftest feeds synthetic debug.log snippets through the same judge and exits 0 only if each verdict
is the expected one (a vault inversion fails, the F-37 pair is allowed, the stock pair is inherited);
qa/yellowback-audit.sh runs it, so the filter cannot silently regress again."""
import glob, os, re, sys, tempfile

# Why each token is here (audit 07/F-11): 'yellowback' -- src/yellowback/, rpc/yellowback*.cpp and
# cs_yellowback; 'yed_' -- the module's RPC names in a lock name or file; '(^|[\s/])vault/' -- the
# vault primitive's sources (src/vault/*.cpp report as "vault/node.cpp"); 'vault\w*\.cpp' --
# rpc/vault.cpp and any vault-named source elsewhere; 'VaultDB' / 'VaultState' / 'cs_vault' -- a vault
# lock by name, should one become a tracked critical section. Function names (the set_* / vault_* RPC
# frames) never appear in a report, which names only lock variables and file:line, so they are not
# tokens. A token match is printed with each failing report.
YELLOWBACK_TOKENS = re.compile(r'yellowback|yed_|(?:^|[\s/])vault/|vault\w*\.cpp|VaultDB|VaultState|cs_vault')

# 6.20.0 (tracing): "2026-10-01T04:39:06.579246Z  INFO ProcessNewBlock: main:  (1)"
PAY6 = re.compile(r'^\d{4}-\d\d-\d\dT[0-9:.]+Z\s+[A-Z]+\s.*?main: ?(.*)$')
# v4.5.0: "Sep 30 12:00:00.123  INFO main: ..."
PAY4 = re.compile(r'^\S+ \d+ [0-9:.]+ +\w+ [A-Za-z]*:? ?(?:main: )?(.*)$')
ALLOWED = ({'cs_yellowback', 'ControlMutex'}, {'mempool.cs', 'cs_inventory'})

def payload(line):
    m = PAY6.match(line) or PAY4.match(line)
    return m.group(1) if m else ''

def reports(path):
    lines = open(path, errors='replace').read().splitlines()
    for i, l in enumerate(lines):
        if 'POTENTIAL DEADLOCK DETECTED' not in l:
            continue
        blk = []
        for m in lines[i + 1:i + 60]:
            if 'POTENTIAL DEADLOCK DETECTED' in m:
                break
            p = payload(m)
            # another thread's line can interleave with the report; skip it rather than stop
            if p.startswith((' ', 'Previous', 'Current')):
                blk.append(p.rstrip())
        yield blk

def marked(blk):
    """The two locks of the inversion: the lines that follow a (1) / (2) marker."""
    names = set()
    for j, l in enumerate(blk):
        if l.strip() in ('(1)', '(2)') and j + 1 < len(blk):
            words = blk[j + 1].split()
            name = words[0].split('->')[-1].strip('&')
            where = words[1] if len(words) > 1 else ''
            if name == 'mempool.cs' or (name == 'cs' and where.startswith('txmempool.cpp')):
                names.add('mempool.cs')
            else:
                names.add(name.split('.')[-1])
    return names

def under_cs_main(blk):
    """The allow-list proof needs cs_main held in both orders, not just the pair's names."""
    cur = next((j for j, l in enumerate(blk) if l.startswith('Current')), len(blk))
    held = lambda part: any(l.split() and l.split()[0] == 'cs_main' for l in part)
    return held(blk[:cur]) and held(blk[cur:])

def judge(roots):
    """(total, allowed, failing {text: count}, matched token per failing text, inherited {pair: count})."""
    total, allowed, distinct, token, inherited = 0, 0, {}, {}, {}
    for root in roots:
        for f in glob.glob(os.path.join(root, '**', 'debug.log'), recursive=True):
            for blk in reports(f):
                total += 1
                text = '\n'.join(blk)
                pair = marked(blk)
                m = YELLOWBACK_TOKENS.search(text)
                if not m:
                    key = ' / '.join(sorted(pair))
                    inherited[key] = inherited.get(key, 0) + 1
                    continue
                if any(a <= pair for a in ALLOWED) and under_cs_main(blk):
                    allowed += 1
                    continue
                distinct[text] = distinct.get(text, 0) + 1
                token[text] = m.group(0).strip()
    return total, allowed, distinct, token, inherited

def _report(pre, a, b):
    """A synthetic 6.20.0 report: `a` and `b` are (lock, file:line) pairs, (1) and (2)."""
    ts = '2026-10-12T10:00:00.000000Z  INFO main: '
    lines = ['POTENTIAL DEADLOCK DETECTED', 'Previous lock order was:']
    for (lock, where), mark in ((pre, None), (a, '(1)'), (b, '(2)')):
        if mark:
            lines.append(' ' + mark)
        lines.append(' %s  %s' % (lock, where))
    lines.append('Current lock order is:')
    for (lock, where), mark in ((pre, None), (b, '(2)'), (a, '(1)')):
        if mark:
            lines.append(' ' + mark)
        lines.append(' %s  %s' % (lock, where))
    return '\n'.join(ts + l for l in lines) + '\n' + ts + 'UpdateTip: new best=00\n'

SELFTEST = (
    # (name, report, expected verdict: 'fail' | 'allowed' | 'inherited')
    ('vault inversion: mempool.cs (vault/node.cpp) vs cs_wallet (rpc/vault.cpp)',
     _report(('cs_main', 'rpc/vault.cpp:1044'), ('pool.cs', 'vault/node.cpp:218'), ('pwalletMain->cs_wallet', 'rpc/vault.cpp:1044')), 'fail'),
    ('vault lock by name: VaultDB::cs vs cs_main',
     _report(('cs_vNodes', 'net.cpp:1700'), ('cs_main', 'main.cpp:3300'), ('VaultDB::cs', 'db.cpp:143')), 'fail'),
    ('the F-37 pair (cs_yellowback / ControlMutex under cs_main)',
     _report(('cs_main', 'miner.cpp:150'), ('cs_yellowback', 'yellowback/module.cpp:80'), ('ControlMutex', 'checkqueue.h:178')), 'allowed'),
    ('the stock net.cpp TRY_LOCK pair (cs_vNodes / pnode->cs_vRecvMsg)',
     _report(('cs_main', 'main.cpp:4886'), ('cs_vNodes', 'net.cpp:1191'), ('pnode->cs_vRecvMsg', 'net.cpp:1218 (TRY)')), 'inherited'),
)

def selftest():
    ok = True
    with tempfile.TemporaryDirectory() as d:
        for i, (name, text, want) in enumerate(SELFTEST):
            os.makedirs(os.path.join(d, str(i)))
            with open(os.path.join(d, str(i), 'debug.log'), 'w') as f:
                f.write(text)
            total, allowed, distinct, token, _ = judge([os.path.join(d, str(i))])
            got = 'fail' if distinct else 'allowed' if allowed else 'inherited'
            ok = ok and total == 1 and got == want
            print('%s  %s: %s%s' % ('ok  ' if total == 1 and got == want else 'FAIL', name, got,
                                    (' (token %r)' % next(iter(token.values()))) if token else ''))
    print('lockorder-check self-test: %s' % ('passed' if ok else 'FAILED'))
    return 0 if ok else 1

if sys.argv[1:] == ['--selftest']:
    sys.exit(selftest())
roots = sys.argv[1:] or ['.']
total, allowed, distinct, token, inherited = judge(roots)
bad = sum(distinct.values())
print('potential deadlock reports: %d total, %d naming Yellowback allow-listed (cs_yellowback/ControlMutex or mempool.cs/cs_inventory, both under cs_main), %d failing' % (total, allowed, bad))
for key, n in sorted(inherited.items(), key=lambda x: -x[1]):
    print('  inherited (no Yellowback lock or file): x%d %s' % (n, key))
for text, n in sorted(distinct.items(), key=lambda x: -x[1]):
    print('---- x%d (matched %r)\n%s' % (n, token[text], text))
sys.exit(1 if bad else 0)
