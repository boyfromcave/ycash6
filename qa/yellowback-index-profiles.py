#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Which node index profiles each functional script runs its nodes under (beta2 list item 17; the
address plan's section 6 defines the profiles). The same file on both node lines.

    qa/yellowback-index-profiles.py NAME...      one line per script, then the profiles covered
    qa/yellowback-index-profiles.py --summary NAME...   only the profiles covered and their counts

    P0 default        no index flag: what a new user and the testnet seeds run
    P1 txindex        -txindex
    P2 insight        -insightexplorer (with -experimentalfeatures, and -txindex)
    P3 lightwalletd   -lightwalletd (with -experimentalfeatures, and -txindex)
    P4 module live    the YED attestor set (-yellowbackattestorset, given by test_framework/yellowback_util.py's
                      yellowback_node_args / activate / activate_yed_late)

A script may state its profiles on a line of its own, which then replaces the detection:
    # index-profiles: P0 P2
Detection is a static read of the script's text (the flags above and the helpers that add them). A
script whose nodes are started with no index flag at all counts as P0; most scripts run several nodes,
so P0 is listed beside another profile only when the script says so. Report only: this prints what CI
ran, it does not gate.

Standard library only (CI runs it with the runner's python3).
"""

import argparse
import os
import re
import sys

PROFILES = ["P0", "P1", "P2", "P3", "P4"]
NAMES = {"P0": "default", "P1": "txindex", "P2": "insight", "P3": "lightwalletd", "P4": "module live"}
DETECT = [
    ("P1", re.compile(r"-txindex\b")),
    ("P2", re.compile(r"-insightexplorer\b")),
    ("P3", re.compile(r"-lightwalletd\b")),
    ("P4", re.compile(r"-yellowbackattestorset\b|\byellowback_node_args\(|\.activate\(|\bactivate_yed_late\(")),
]
DECLARED = re.compile(r"^\s*#\s*index-profiles:\s*(.+?)\s*$", re.M)


def profiles_of(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    m = DECLARED.search(text)
    if m:
        got = [p for p in m.group(1).split() if p in PROFILES]
        bad = [p for p in m.group(1).split() if p not in PROFILES]
        return sorted(set(got)), "declared", bad
    got = {p for p, rx in DETECT if rx.search(text)}
    return sorted(got) or ["P0"], "detected", []


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "rpc-tests"))
    ap.add_argument("names", nargs="+", help="script names, with or without .py and arguments after a space")
    a = ap.parse_args()
    count = {p: 0 for p in PROFILES}
    rc = 0
    rows = []
    for raw in a.names:
        name = raw.split()[0]
        name = name[:-3] if name.endswith(".py") else name
        path = os.path.join(a.dir, name + ".py")
        if not os.path.exists(path):
            print("%s: no such script %s" % (name, path))
            rc = 1
            continue
        got, how, bad = profiles_of(path)
        if bad:
            print("%s: unknown profile(s) in its index-profiles line: %s" % (name, " ".join(bad)))
            rc = 1
        for p in got:
            count[p] += 1
        rows.append((name, got, how))
    if not a.summary:
        width = max([len(r[0]) for r in rows] + [4])
        for name, got, how in rows:
            print("%-*s  %-14s (%s)" % (width, name, " ".join(got), how))
        print()
    print("index profiles covered by these %d scripts:" % len(rows))
    for p in PROFILES:
        print("  %s %-13s %3d script(s)%s" % (p, NAMES[p], count[p], "" if count[p] else "  <- none"))
    return rc


if __name__ == "__main__":
    sys.exit(main())
