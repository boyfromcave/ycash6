#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Unit tests for qa/yellowback-cross-line.py. Two throwaway git repositories."""

import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SCRIPT = os.path.join(HERE, "yellowback-cross-line.py")
MANIFEST = "qa/yellowback-cross-line.manifest"


def git(repo, *args):
    subprocess.run(["git", "-C", repo, *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def write(repo, path, text):
    full = os.path.join(repo, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as fh:
        fh.write(text)


def commit(repo):
    git(repo, "add", "-A")
    git(repo, "-c", "user.email=test@example.com", "-c", "user.name=test",
        "commit", "-q", "-m", "fixture")


def init_pair(root):
    dd, y6 = os.path.join(root, "dd"), os.path.join(root, "y6")
    for repo in (dd, y6):
        os.makedirs(repo)
        git(repo, "init", "-q")
    return dd, y6


def manifest(*lines):
    return "\n".join(lines) + "\n"


def run(repo, other, line):
    proc = subprocess.run(
        ["python3", SCRIPT, "--this-line", line, "--other-dir", other, "--other-rev", "HEAD"],
        cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return proc.returncode, proc.stdout + proc.stderr


class CrossLine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="yb-cross-line-")
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_identical_passes(self):
        dd, y6 = init_pair(self.tmp)
        body = manifest("identical qa/yellowback-cross-line.manifest", "identical src/test/data/pq_vectors.json")
        for repo in (dd, y6):
            write(repo, MANIFEST, body)
            write(repo, "src/test/data/pq_vectors.json", "{}\n")
            commit(repo)
        code, out = run(dd, y6, "dd")
        self.assertEqual(code, 0, out)
        self.assertIn("identical src/test/data/pq_vectors.json", out)

    def test_identical_file_differing_names_the_path(self):
        dd, y6 = init_pair(self.tmp)
        body = manifest("identical qa/yellowback-cross-line.manifest", "identical src/test/data/pq_vectors.json")
        write(dd, MANIFEST, body)
        write(y6, MANIFEST, body)
        write(dd, "src/test/data/pq_vectors.json", "{}\n")
        write(y6, "src/test/data/pq_vectors.json", "{ }\n")
        commit(dd)
        commit(y6)
        code, out = run(dd, y6, "dd")
        self.assertEqual(code, 1, out)
        self.assertIn("identical src/test/data/pq_vectors.json differs", out)

    def test_tree_extra_file_fails(self):
        dd, y6 = init_pair(self.tmp)
        body = manifest("identical qa/yellowback-cross-line.manifest", "tree src/crypto/pq")
        for repo in (dd, y6):
            write(repo, MANIFEST, body)
            write(repo, "src/crypto/pq/a.c", "a\n")
        write(y6, "src/crypto/pq/extra.c", "x\n")
        commit(dd)
        commit(y6)
        code, out = run(dd, y6, "dd")
        self.assertEqual(code, 1, out)
        self.assertIn("only on ycash6: src/crypto/pq/extra.c", out)

    def test_shim_at_pinned_hashes_passes_and_a_drift_fails(self):
        dd, y6 = init_pair(self.tmp)
        write(dd, "src/vault/checker.cpp", "dd\n")
        write(y6, "src/vault/checker.cpp", "y6\n")
        commit(dd)
        commit(y6)
        dd_hash = subprocess.check_output(["sha256sum", os.path.join(dd, "src/vault/checker.cpp")], text=True).split()[0]
        y6_hash = subprocess.check_output(["sha256sum", os.path.join(y6, "src/vault/checker.cpp")], text=True).split()[0]
        body = manifest(
            "identical qa/yellowback-cross-line.manifest",
            "tree src/vault",
            "shim src/vault/checker.cpp %s %s" % (dd_hash, y6_hash),
        )
        for repo in (dd, y6):
            write(repo, MANIFEST, body)
            commit(repo)
        code, out = run(y6, dd, "y6")
        self.assertEqual(code, 0, out)
        self.assertIn("shim src/vault/checker.cpp", out)
        write(y6, "src/vault/checker.cpp", "y6\n# drifted\n")
        commit(y6)
        code, out = run(dd, y6, "dd")
        self.assertEqual(code, 1, out)
        self.assertIn("shim drifted: src/vault/checker.cpp", out)

    def test_shim_that_became_equal_fails(self):
        dd, y6 = init_pair(self.tmp)
        write(dd, "src/vault/db.cpp", "same\n")
        write(y6, "src/vault/db.cpp", "same\n")
        body = manifest(
            "identical qa/yellowback-cross-line.manifest",
            "shim src/vault/db.cpp %s %s" % ("ab" * 32, "cd" * 32),
        )
        for repo in (dd, y6):
            write(repo, MANIFEST, body)
            commit(repo)
        code, out = run(dd, y6, "dd")
        self.assertEqual(code, 1, out)
        self.assertIn("shim now identical: src/vault/db.cpp", out)

    def test_manifest_differing_fails_first(self):
        dd, y6 = init_pair(self.tmp)
        write(dd, MANIFEST, manifest("identical qa/yellowback-cross-line.manifest"))
        write(y6, MANIFEST, manifest("identical qa/yellowback-cross-line.manifest", "identical src/pqkey.h"))
        commit(dd)
        commit(y6)
        code, out = run(dd, y6, "dd")
        self.assertEqual(code, 1, out)
        self.assertIn("the manifest itself differs", out)
        self.assertNotIn("src/pqkey.h", out)

    def test_shipped_manifest_lists_itself_and_the_checker(self):
        with open(os.path.join(HERE, "yellowback-cross-line.manifest"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("identical qa/yellowback-cross-line.manifest", text)
        self.assertIn("identical qa/yellowback-cross-line.py", text)
        for name in (
            "vault_vectors.json", "pq_vectors.json", "pq_wallet_vectors.json",
            "yellowback_golden.json", "yellowback_attest_vectors.json", "yellowback_math_cases.json",
            "yellowback_pq_vectors.json", "pq_acvp_slhdsa.json", "pq_falcon_kat.json",
        ):
            self.assertIn("identical src/test/data/%s" % name, text)
        self.assertIn("tree src/crypto/pq", text)
        self.assertIn("tree src/vault", text)
        self.assertIn("tree src/yellowback", text)
        self.assertEqual(text.count("\nshim "), 11)


if __name__ == "__main__":
    unittest.main()
