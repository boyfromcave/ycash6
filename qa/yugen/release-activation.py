#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""Release guard of the Yugen line (doc/yugen-release.md, "Version guard").

Refuses a tree in which any chain-parameter class of src/chainparams.cpp gives UPGRADE_YUGEN an
activation height. Yugen has no public activation height on this line: known issue K-1 (the
withdrawal classification of spec §13.3.5 is not built) must land on every node line first, and
§13.3.1 forbids activating Yugen with the provisional safety parameters. Regtest and devnets
activate it with -nuparams=59474e30:<h> only, so regtest carries no height either.

Every class that assigns the height must assign NO_ACTIVATION_HEIGHT, and the main, testnet and
regtest classes must each assign it (a class that inherits, such as the testnet profiles, takes its
parent's). Usage: qa/yugen/release-activation.py [<root>]
"""
import os
import re
import sys

root = sys.argv[1] if len(sys.argv) > 1 else "."
path = os.path.join(root, "src", "chainparams.cpp")
with open(path, encoding="utf-8") as fh:
    text = fh.read()

classes = [(m.start(), m.group(1)) for m in re.finditer(r"^class (C\w+Params)\b", text, re.M)]
assign = re.compile(r"vUpgrades\[Consensus::UPGRADE_YUGEN\]\.nActivationHeight\s*=\s*([^;]+);")
problems, seen = [], set()
for m in assign.finditer(text):
    owner = None
    for start, name in classes:
        if start < m.start():
            owner = name
    value = " ".join(m.group(1).split())
    seen.add(owner)
    if value != "Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT":
        problems.append("%s sets UPGRADE_YUGEN's activation height to %s" % (owner, value))
for required in ("CMainParams", "CTestNetParams", "CRegTestParams"):
    if required not in seen:
        problems.append("%s does not set UPGRADE_YUGEN's activation height (expected NO_ACTIVATION_HEIGHT)" % required)
for p in problems:
    print("refusing to release: " + p + " (doc/yugen-release.md, Version guard; K-1)")
if problems:
    sys.exit(1)
print("Yugen: no activation height in %s (%s); regtest and devnets by -nuparams=59474e30:<h> only"
      % (path, ", ".join(sorted(seen))))
