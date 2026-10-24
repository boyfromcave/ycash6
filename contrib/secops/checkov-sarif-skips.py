#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""Drop the reasoned inline Checkov skips from Checkov's SARIF before it goes to code scanning.

Checkov writes a check skipped in the scanned file (`# checkov:skip=<ID>:<reason>`) into its SARIF
as an ordinary warning-level result carrying `suppressions: [{"kind": "inSource", ...}]`. GitHub
code scanning does not act on that property, so every reasoned skip became an open alert
(ycash6 #195-#198). This keeps the SARIF to what Checkov actually failed: a result whose in-source
suppression carries a reason is removed and listed on stdout (the reason stays in the Dockerfile,
next to the code it argues about). A skip without a reason (Checkov records "No comment provided")
is not honoured: its result is kept and the exit status is 1, so the job fails on it.
"""
import json
import sys

NO_REASON = {"", "no comment provided"}


def reasoned(result):
    sups = result.get("suppressions") or []
    return bool(sups) and all(
        s.get("kind") == "inSource" and s.get("justification", "").strip().lower() not in NO_REASON for s in sups)


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: %s <checkov.sarif>  (rewritten in place)" % sys.argv[0])
    path = sys.argv[1]
    with open(path, encoding="utf-8") as f:
        sarif = json.load(f)
    unreasoned = 0
    for run in sarif.get("runs", []):
        kept = []
        for r in run.get("results", []):
            uri = r.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "?")
            if reasoned(r):
                print("skipped in source: %s %s: %s" % (r.get("ruleId"), uri, r["suppressions"][0]["justification"]))
                continue
            if r.get("suppressions"):
                print("::error file=%s::checkov skip of %s without a reason" % (uri, r.get("ruleId")))
                unreasoned += 1
            kept.append(r)
        run["results"] = kept
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
        f.write("\n")
    return 1 if unreasoned else 0


if __name__ == "__main__":
    sys.exit(main())
