#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Throwaway-repo tests for qa/yellowback-cross-line-trees.py (MEDIUM-W3-P-2)."""

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "yellowback-cross-line-trees.py")
GIT = ["git", "-c", "user.name=yellowback-test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false"]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def run_git(repo, *args):
    subprocess.run(GIT + ["-C", repo] + list(args), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def write(repo, path, data):
    full = os.path.join(repo, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as fh:
        fh.write(data)


def commit(repo):
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-q", "--no-verify", "-m", "test")


def seed(repo):
    run_git(repo, "init", "-q")
    os.makedirs(os.path.join(repo, "qa"))
    shutil.copy(SCRIPT, os.path.join(repo, "qa", "yellowback-cross-line-trees.py"))


def check(repo, *extra):
    proc = subprocess.run(
        ["python3", "qa/yellowback-cross-line-trees.py", "--this-line", "dd"] + list(extra),
        cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    return proc.returncode, proc.stdout + proc.stderr


class CrossLineTreesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="yb-cross-line-")
        self.dd = os.path.join(self.tmp, "dd")
        self.y6 = os.path.join(self.tmp, "y6")
        os.makedirs(self.dd)
        os.makedirs(self.y6)
        seed(self.dd)
        seed(self.y6)
        self.same = b"same overlay\n"
        write(self.dd, "src/vault/rule.cpp", self.same)
        write(self.y6, "src/vault/rule.cpp", self.same)
        write(self.dd, "qa/yellowback-cross-line-allow.txt", b"# no shims\n")
        write(self.y6, "qa/yellowback-cross-line-allow.txt", b"# no shims\n")
        commit(self.dd)
        commit(self.y6)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def other(self):
        return ["--other-dir", self.y6, "--other-rev", "HEAD"]

    def test_identical_passes(self):
        code, out = check(self.dd, *self.other())
        self.assertEqual(code, 0, out)
        self.assertIn("src/vault/rule.cpp", out)
        self.assertIn("identical", out)
        self.assertIn("1 identical, 0 pinned shims", out)

    def test_unclassified_difference_fails(self):
        write(self.y6, "src/vault/rule.cpp", b"changed\n")
        commit(self.y6)
        code, out = check(self.dd, *self.other())
        self.assertEqual(code, 1, out)
        self.assertIn("unclassified difference: src/vault/rule.cpp", out)

    def test_extra_file_fails(self):
        write(self.y6, "src/yellowback/only.cpp", b"y6 only\n")
        commit(self.y6)
        code, out = check(self.dd, *self.other())
        self.assertEqual(code, 1, out)
        self.assertIn("only on ycash6: src/yellowback/only.cpp", out)

    def test_pinned_shim_passes(self):
        dd_body = b"dd shim\n"
        y6_body = b"y6 shim\n"
        write(self.dd, "src/vault/shim.cpp", dd_body)
        write(self.y6, "src/vault/shim.cpp", y6_body)
        line = "src/vault/shim.cpp %s %s\n" % (sha256(dd_body), sha256(y6_body))
        write(self.dd, "qa/yellowback-cross-line-allow.txt", line.encode())
        write(self.y6, "qa/yellowback-cross-line-allow.txt", line.encode())
        commit(self.dd)
        commit(self.y6)
        code, out = check(self.dd, *self.other())
        self.assertEqual(code, 0, out)
        self.assertIn("src/vault/shim.cpp  pinned shim", out)
        self.assertIn("1 identical, 1 pinned shims", out)

    def test_shim_drift_fails(self):
        dd_body = b"dd shim\n"
        y6_body = b"y6 shim\n"
        write(self.dd, "src/yellowback/shim.cpp", dd_body)
        write(self.y6, "src/yellowback/shim.cpp", y6_body)
        line = "src/yellowback/shim.cpp %s %s\n" % (sha256(dd_body), sha256(y6_body))
        write(self.dd, "qa/yellowback-cross-line-allow.txt", line.encode())
        write(self.y6, "qa/yellowback-cross-line-allow.txt", line.encode())
        commit(self.dd)
        commit(self.y6)
        write(self.dd, "src/yellowback/shim.cpp", b"dd shim edited\n")
        code, out = check(self.dd, *self.other())
        self.assertEqual(code, 1, out)
        self.assertIn("shim drifted: src/yellowback/shim.cpp", out)

    def test_equal_pin_fails(self):
        body = b"now the same\n"
        digest = sha256(body)
        write(self.dd, "src/vault/shim.cpp", body)
        write(self.y6, "src/vault/shim.cpp", body)
        line = "src/vault/shim.cpp %s %s\n" % (digest, digest)
        write(self.dd, "qa/yellowback-cross-line-allow.txt", line.encode())
        write(self.y6, "qa/yellowback-cross-line-allow.txt", line.encode())
        commit(self.dd)
        commit(self.y6)
        code, out = check(self.dd, *self.other())
        self.assertEqual(code, 1, out)
        self.assertIn("shim now identical: src/vault/shim.cpp", out)

    def test_allow_list_mismatch_fails_first(self):
        write(self.y6, "qa/yellowback-cross-line-allow.txt", b"# different\n")
        commit(self.y6)
        write(self.y6, "src/vault/rule.cpp", b"also changed\n")
        commit(self.y6)
        code, out = check(self.dd, *self.other())
        self.assertEqual(code, 1, out)
        self.assertIn("qa/yellowback-cross-line-allow.txt differs between the lines", out)
        self.assertNotIn("unclassified difference", out)


if __name__ == "__main__":
    unittest.main()
