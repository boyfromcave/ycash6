#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
# Acceptance name for the cross-line identity check (audit W3-P-2). qa/yellowback-cross-line-trees.py
# still checks the two overlay trees against qa/yellowback-cross-line-allow.txt; this manifest covers
# those trees plus the vectors, qa goldens, pqkey and the spec.

"""Byte identity of the shared Yellowback overlay across the two node lines.

  yellowback-cross-line.py --this-line {dd,y6} --other-ref REV
  yellowback-cross-line.py --this-line {dd,y6} --other-dir DIR --other-rev REV

Reads qa/yellowback-cross-line.manifest from this tree and from the other line.
identical paths must match, a tree must have the same git-tracked path set, and a
shim may differ only at the sha256 pair the manifest pins (column 1 ycash-dd,
column 2 ycash6). Run from the repository root. Python 3 standard library only.
This file is byte-identical on ycash-dd and ycash6.
"""

import argparse
import hashlib
import subprocess
import sys

MANIFEST = "qa/yellowback-cross-line.manifest"
HEX64 = set("0123456789abcdef")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git_out(args):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return proc.returncode, proc.stdout, proc.stderr


def parse_manifest(text):
    entries = []
    errors = []
    seen = set()
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        kind = parts[0]
        if kind == "identical" and len(parts) == 2:
            entry = ("identical", parts[1], None)
        elif kind == "tree" and len(parts) == 2:
            entry = ("tree", parts[1].rstrip("/"), None)
        elif kind == "shim" and len(parts) == 4:
            path, dd, y6 = parts[1], parts[2], parts[3]
            if len(dd) != 64 or len(y6) != 64 or any(c not in HEX64 for c in dd + y6):
                errors.append("manifest:%d: sha256 must be 64 lowercase hex digits" % lineno)
                continue
            if dd == y6:
                errors.append("shim now identical: %s; move it to the tree" % path)
                continue
            entry = ("shim", path, (dd, y6))
        else:
            errors.append("manifest:%d: want 'identical PATH', 'tree DIR' or 'shim PATH <dd> <y6>'" % lineno)
            continue
        if entry[1] in seen:
            errors.append("manifest:%d: duplicate %s" % (lineno, entry[1]))
            continue
        seen.add(entry[1])
        entries.append(entry)
    return entries, errors


def read_this(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError as exc:
        return exc


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--this-line", required=True, choices=("dd", "y6"))
    parser.add_argument("--other-ref")
    parser.add_argument("--other-dir")
    parser.add_argument("--other-rev")
    args = parser.parse_args(argv)
    if args.other_ref and (args.other_dir or args.other_rev):
        parser.error("pass --other-ref or --other-dir with --other-rev, not both")
    if args.other_ref:
        prefix = ["git"]
        rev = args.other_ref
    elif args.other_dir and args.other_rev:
        prefix = ["git", "-C", args.other_dir]
        rev = args.other_rev
    else:
        parser.error("pass --other-ref, or --other-dir and --other-rev")

    this_name = "ycash-dd" if args.this_line == "dd" else "ycash6"
    other_name = "ycash6" if args.this_line == "dd" else "ycash-dd"
    errors = []

    def show(path):
        code, out, err = git_out(prefix + ["show", "%s:%s" % (rev, path)])
        if code != 0:
            detail = err.decode("utf-8", "replace").strip().splitlines()
            return None, (detail[-1] if detail else "git show failed")
        return out, None

    def ls_files(paths):
        code, out, err = git_out(["git", "ls-files", "--"] + paths)
        if code != 0:
            return None, err.decode("utf-8", "replace").strip()
        return [p for p in out.decode("utf-8").splitlines() if p], None

    def ls_tree(paths):
        code, out, err = git_out(prefix + ["ls-tree", "-r", "--name-only", rev, "--"] + paths)
        if code != 0:
            return None, err.decode("utf-8", "replace").strip()
        return [p for p in out.decode("utf-8").splitlines() if p], None

    this_manifest = read_this(MANIFEST)
    if isinstance(this_manifest, OSError):
        print("  error: %s is missing in this tree (%s)" % (MANIFEST, this_manifest))
        return 1
    other_manifest, why = show(MANIFEST)
    if other_manifest is None:
        print("  error: the manifest itself differs (%s missing on the other line: %s)" % (MANIFEST, why))
        return 1
    if this_manifest != other_manifest:
        print("  error: the manifest itself differs")
        return 1
    try:
        text = this_manifest.decode("utf-8")
    except UnicodeDecodeError:
        print("  error: %s is not utf-8" % MANIFEST)
        return 1
    entries, parse_errors = parse_manifest(text)
    errors.extend(parse_errors)
    shims = {path: hashes for kind, path, hashes in entries if kind == "shim"}

    identical_n = 0
    for kind, path, payload in entries:
        if kind == "identical":
            blob = read_this(path)
            if isinstance(blob, OSError):
                errors.append("identical %s: missing on %s (%s)" % (path, this_name, blob))
                continue
            other_blob, why = show(path)
            if other_blob is None:
                errors.append("identical %s: missing on %s (%s)" % (path, other_name, why))
                continue
            if blob != other_blob:
                errors.append("identical %s differs (%s %s, %s %s)" % (
                    path, this_name, sha256(blob), other_name, sha256(other_blob)))
                continue
            identical_n += 1
            print("  identical %s" % path)
        elif kind == "tree":
            here, why = ls_files([path])
            if here is None:
                errors.append("tree %s: git ls-files failed: %s" % (path, why))
                continue
            there, why = ls_tree([path])
            if there is None:
                errors.append("tree %s: git ls-tree failed: %s" % (path, why))
                continue
            here_set, there_set = set(here), set(there)
            only_label = {"dd": "ycash-dd", "y6": "ycash6"}
            for extra in sorted(here_set - there_set):
                errors.append("only on %s: %s" % (only_label[args.this_line], extra))
            for extra in sorted(there_set - here_set):
                errors.append("only on %s: %s" % (only_label["y6" if args.this_line == "dd" else "dd"], extra))
            same = 0
            for rel in sorted(here_set & there_set):
                if rel in shims:
                    continue
                blob = read_this(rel)
                if isinstance(blob, OSError):
                    errors.append("%s: missing in this working tree (%s)" % (rel, blob))
                    continue
                other_blob, why = show(rel)
                if other_blob is None:
                    errors.append("%s: unreadable on the other line (%s)" % (rel, why))
                    continue
                if blob != other_blob:
                    errors.append("identical %s differs (%s %s, %s %s)" % (
                        rel, this_name, sha256(blob), other_name, sha256(other_blob)))
                    continue
                same += 1
            print("  tree %s  %d identical" % (path, same))
        elif kind == "shim":
            want_dd, want_y6 = payload
            blob = read_this(path)
            if isinstance(blob, OSError):
                errors.append("shim %s: missing on %s (%s)" % (path, this_name, blob))
                continue
            other_blob, why = show(path)
            if other_blob is None:
                errors.append("shim %s: missing on %s (%s)" % (path, other_name, why))
                continue
            this_hash, other_hash = sha256(blob), sha256(other_blob)
            if args.this_line == "dd":
                dd_hash, y6_hash = this_hash, other_hash
            else:
                y6_hash, dd_hash = this_hash, other_hash
            if dd_hash == y6_hash or want_dd == want_y6:
                errors.append("shim now identical: %s; move it to the tree" % path)
                continue
            if dd_hash != want_dd or y6_hash != want_y6:
                errors.append("shim drifted: %s (ycash-dd now %s, pinned %s)" % (path, dd_hash, want_dd))
                continue
            print("  shim %s" % path)

    print("  summary: %d identical, %d trees, %d shims" % (
        identical_n, sum(1 for k, _, _ in entries if k == "tree"), len(shims)))
    for msg in errors:
        print("  error: %s" % msg)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
