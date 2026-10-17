#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Byte identity of src/vault and src/yellowback across the two node lines.

  yellowback-cross-line-trees.py --this-line {dd,y6} --other-ref REV
  yellowback-cross-line-trees.py --this-line {dd,y6} --other-dir DIR --other-rev REV

Every git-tracked file under those trees must match the other line. A path in
qa/yellowback-cross-line-allow.txt may differ, and only at the sha256 pair that
file pins (column 2 ycash-dd, column 3 ycash6). The allow-list and this script
must themselves be the same bytes on both lines. Run from the repository root.
Python 3 standard library only. This file is byte-identical on ycash-dd and ycash6.
"""

import argparse
import hashlib
import subprocess
import sys

TREES = ("src/vault", "src/yellowback")
ALLOW = "qa/yellowback-cross-line-allow.txt"
SCRIPT = "qa/yellowback-cross-line-trees.py"
HEX64 = set("0123456789abcdef")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git_out(args):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return proc.returncode, proc.stdout, proc.stderr


def other_cmd(prefix, args):
    return prefix + args


def parse_allow(text):
    """Return (entries, errors). entries maps path to (dd_sha256, y6_sha256)."""
    entries = {}
    errors = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 3:
            errors.append("allow-list:%d: want '<path> <ycash-dd sha256> <ycash6 sha256>'" % lineno)
            continue
        path, dd, y6 = parts
        if path in entries:
            errors.append("allow-list:%d: duplicate %s" % (lineno, path))
            continue
        if not path.startswith("src/vault/") and not path.startswith("src/yellowback/"):
            errors.append("allow-list:%d: %s is outside src/vault and src/yellowback" % (lineno, path))
            continue
        if len(dd) != 64 or len(y6) != 64 or any(c not in HEX64 for c in dd + y6):
            errors.append("allow-list:%d: sha256 must be 64 lowercase hex digits" % lineno)
            continue
        entries[path] = (dd, y6)
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

    errors = []

    def show(path):
        code, out, err = git_out(other_cmd(prefix, ["show", "%s:%s" % (rev, path)]))
        if code != 0:
            detail = err.decode("utf-8", "replace").strip().splitlines()
            tail = detail[-1] if detail else "git show failed"
            return None, tail
        return out, None

    this_script = read_this(SCRIPT)
    if isinstance(this_script, OSError):
        print("  error: %s is missing in this tree (%s)" % (SCRIPT, this_script))
        return 1
    other_script, why = show(SCRIPT)
    if other_script is None:
        print("  error: checker missing on the other line (%s: %s)" % (SCRIPT, why))
        return 1
    if this_script != other_script:
        print("  error: %s differs between the lines" % SCRIPT)
        return 1

    this_allow = read_this(ALLOW)
    if isinstance(this_allow, OSError):
        print("  error: %s is missing in this tree (%s)" % (ALLOW, this_allow))
        return 1
    other_allow, why = show(ALLOW)
    if other_allow is None:
        print("  error: allow-list missing on the other line (%s: %s)" % (ALLOW, why))
        return 1
    if this_allow != other_allow:
        print("  error: %s differs between the lines" % ALLOW)
        return 1

    try:
        allow_text = this_allow.decode("utf-8")
    except UnicodeDecodeError:
        print("  error: %s is not utf-8" % ALLOW)
        return 1
    entries, parse_errors = parse_allow(allow_text)
    for msg in parse_errors:
        errors.append(msg)

    code, listed, err = git_out(["git", "ls-files", "--"] + list(TREES))
    if code != 0:
        print("  error: git ls-files failed: %s" % err.decode("utf-8", "replace").strip())
        return 1
    this_paths = [p for p in listed.decode("utf-8").splitlines() if p]
    code, listed, err = git_out(other_cmd(prefix, ["ls-tree", "-r", "--name-only", rev, "--"] + list(TREES)))
    if code != 0:
        print("  error: git ls-tree failed: %s" % err.decode("utf-8", "replace").strip())
        return 1
    other_paths = [p for p in listed.decode("utf-8").splitlines() if p]
    this_set = set(this_paths)
    other_set = set(other_paths)
    only_this = sorted(this_set - other_set)
    only_other = sorted(other_set - this_set)
    this_name = "ycash-dd" if args.this_line == "dd" else "ycash6"
    other_name = "ycash6" if args.this_line == "dd" else "ycash-dd"
    for path in only_this:
        errors.append("only on %s: %s" % (this_name, path))
    for path in only_other:
        errors.append("only on %s: %s" % (other_name, path))

    identical = 0
    pinned = 0
    for path in sorted(this_set & other_set):
        blob = read_this(path)
        if isinstance(blob, OSError):
            errors.append("%s: missing in this working tree (%s)" % (path, blob))
            continue
        other_blob, why = show(path)
        if other_blob is None:
            errors.append("%s: unreadable on the other line (%s)" % (path, why))
            continue
        this_hash = sha256(blob)
        other_hash = sha256(other_blob)
        if args.this_line == "dd":
            dd_hash, y6_hash = this_hash, other_hash
        else:
            y6_hash, dd_hash = this_hash, other_hash
        if path in entries:
            want_dd, want_y6 = entries[path]
            bad = False
            if want_dd == want_y6 or dd_hash == y6_hash:
                errors.append("shim now identical: %s; remove it from the allow-list" % path)
                bad = True
            if dd_hash != want_dd or y6_hash != want_y6:
                errors.append(
                    "shim drifted: %s (ycash-dd now %s, pinned %s; ycash6 now %s, pinned %s)"
                    % (path, dd_hash, want_dd, y6_hash, want_y6)
                )
                bad = True
            if bad:
                continue
            pinned += 1
            print("  %s  pinned shim" % path)
        else:
            if dd_hash != y6_hash:
                errors.append("unclassified difference: %s (ycash-dd %s, ycash6 %s)" % (path, dd_hash, y6_hash))
                continue
            identical += 1
            print("  %s  %s  identical" % (path, dd_hash))

    for path in sorted(set(entries) - this_set - other_set):
        errors.append("allow-list names %s, which is on neither line" % path)
    for path in sorted(set(entries) & (set(only_this) | set(only_other))):
        errors.append("allow-list names %s, which is not on both lines" % path)

    print("  src/vault src/yellowback: %d identical, %d pinned shims, %d files" % (
        identical, pinned, len(this_set | other_set)))
    for msg in errors:
        print("  error: %s" % msg)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
