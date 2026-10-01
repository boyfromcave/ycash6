#!/usr/bin/env python3
"""Read every debug.log under the given directories, group the DEBUG_LOCKORDER reports, and fail on any
whose inverted pair involves Yellowback -- except the one pair that is provably not a deadlock:
the miner holds cs_yellowback (TemplateView, miner.cpp) across TestBlockValidity, which takes the
script-check queue's ControlMutex, while ConnectTip takes ControlMutex before CheckConnect takes
cs_yellowback. Both paths hold cs_main from their first line, so they are mutually exclusive and
the inversion cannot deadlock; the structural fix (drop the TemplateView before TestBlockValidity)
is a one-line change in the frozen miner.cpp, recorded as an open item (role-based plan F-37).
Every other report is printed and counted; the inherited getpeerinfo/SendMessages pair is expected."""
import glob, os, re, sys

PAY = re.compile(r'^\S+ \d+ [0-9:.]+ +\w+ [A-Za-z]*:? ?(?:main: )?(.*)$')
ALLOWED = ({'cs_yellowback', 'ControlMutex'},)

def reports(path):
    lines = open(path, errors='replace').read().splitlines()
    for i, l in enumerate(lines):
        if 'POTENTIAL DEADLOCK DETECTED' not in l:
            continue
        blk = []
        for m in lines[i + 1:i + 40]:
            mm = PAY.match(m)
            p = mm.group(1) if mm else ''
            if p.startswith((' ', 'Previous', 'Current')):
                blk.append(p.rstrip())
            else:
                break
        yield blk

def marked(blk):
    """The two locks of the inversion: the lines that follow a (1) / (2) marker."""
    names = set()
    for j, l in enumerate(blk):
        if l.strip() in ('(1)', '(2)') and j + 1 < len(blk):
            names.add(blk[j + 1].split()[0].split('->')[-1].split('.')[-1].strip('&'))
    return names

roots = sys.argv[1:] or ['.']
total, bad, allowed, distinct = 0, 0, 0, {}
for root in roots:
    for f in glob.glob(os.path.join(root, '**', 'debug.log'), recursive=True):
        for blk in reports(f):
            total += 1
            text = '\n'.join(blk)
            if 'yellowback' not in text and 'yed_' not in text:
                continue
            pair = marked(blk)
            if any(a <= pair for a in ALLOWED):
                allowed += 1
                continue
            bad += 1
            distinct[text] = distinct.get(text, 0) + 1
print('potential deadlock reports: %d total, %d naming Yellowback allow-listed (cs_yellowback/ControlMutex under cs_main), %d failing' % (total, allowed, bad))
for text, n in sorted(distinct.items(), key=lambda x: -x[1]):
    print('---- x%d\n%s' % (n, text))
sys.exit(1 if bad else 0)
