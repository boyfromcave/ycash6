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
or the first stock report aborts it before any Yellowback code runs (mapping §19 S3)."""
import glob, os, re, sys

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

roots = sys.argv[1:] or ['.']
total, bad, allowed, distinct, inherited = 0, 0, 0, {}, {}
for root in roots:
    for f in glob.glob(os.path.join(root, '**', 'debug.log'), recursive=True):
        for blk in reports(f):
            total += 1
            text = '\n'.join(blk)
            pair = marked(blk)
            if 'yellowback' not in text and 'yed_' not in text:
                key = ' / '.join(sorted(pair))
                inherited[key] = inherited.get(key, 0) + 1
                continue
            if any(a <= pair for a in ALLOWED) and under_cs_main(blk):
                allowed += 1
                continue
            bad += 1
            distinct[text] = distinct.get(text, 0) + 1
print('potential deadlock reports: %d total, %d naming Yellowback allow-listed (cs_yellowback/ControlMutex or mempool.cs/cs_inventory, both under cs_main), %d failing' % (total, allowed, bad))
for key, n in sorted(inherited.items(), key=lambda x: -x[1]):
    print('  inherited (no Yellowback lock or file): x%d %s' % (n, key))
for text, n in sorted(distinct.items(), key=lambda x: -x[1]):
    print('---- x%d\n%s' % (n, text))
sys.exit(1 if bad else 0)
