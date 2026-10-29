#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Unit tests for qa/yellowback-rc-qualify.sh (install, pins) and qa/yellowback-rc-crossline.py (the
argument filter). Testnet plan §5.3. No node runs: the "binaries" are shell stubs."""

import hashlib
import importlib.util
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "yellowback-rc-qualify.sh")
spec = importlib.util.spec_from_file_location("crossline", os.path.join(HERE, "yellowback-rc-crossline.py"))
crossline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(crossline)


def run(*args):
    proc = subprocess.run(["bash", SCRIPT] + list(args), capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


class Install(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rc-qualify-")
        self.addCleanup(shutil.rmtree, self.tmp)
        self.pkgdir = os.path.join(self.tmp, "pkg")
        self.tree = os.path.join(self.tmp, "tree")
        os.makedirs(self.pkgdir)

    def package(self, version="6.22.0-rc1", banner=None, sums=True, tamper=False, missing=None):
        name = "ycashd_v%s_linux_x86_64" % version
        stage = os.path.join(self.tmp, "stage", name)
        os.makedirs(stage)
        for b in ("ycashd", "ycash-cli", "ycash-tx"):
            if b == missing:
                continue
            with open(os.path.join(stage, b), "w", encoding="utf-8") as fh:
                fh.write("#!/bin/sh\necho 'Ycash Daemon version %s'\n" % (banner or "v" + version))
            os.chmod(os.path.join(stage, b), 0o755)
        path = os.path.join(self.pkgdir, name + ".tar.gz")
        with tarfile.open(path, "w:gz") as tar:
            tar.add(stage, arcname=name)
        if sums:
            with open(path, "rb") as fh:
                digest = hashlib.sha256(fh.read()).hexdigest()
            if tamper:
                digest = "0" * 64
            with open(os.path.join(self.pkgdir, "SHA256SUMS"), "w", encoding="utf-8") as fh:
                fh.write("%s  %s\n%s  ycashd_v%s_windows.zip\n" % (digest, name + ".tar.gz", "1" * 64, version))
        return path

    def test_installs_a_checked_package(self):
        self.package()
        code, out = run("install", self.pkgdir, self.tree)
        self.assertEqual(code, 0, out)
        self.assertIn("installed ycashd_v6.22.0-rc1_linux_x86_64.tar.gz", out)
        for b in ("ycashd", "ycash-cli", "ycash-tx"):
            self.assertTrue(os.access(os.path.join(self.tree, "src", b), os.X_OK))

    def test_refuses_a_package_that_does_not_match(self):
        self.package(tamper=True)
        code, out = run("install", self.pkgdir, self.tree)
        self.assertEqual(code, 1, out)
        self.assertIn("does not match SHA256SUMS", out)

    def test_refuses_without_sums_or_with_a_wrong_banner(self):
        self.package(sums=False)
        code, out = run("install", self.pkgdir, self.tree)
        self.assertEqual(code, 1, out)
        self.assertIn("no SHA256SUMS", out)
        shutil.rmtree(self.pkgdir)
        os.makedirs(self.pkgdir)
        shutil.rmtree(os.path.join(self.tmp, "stage"))
        self.package(banner="v6.22.0-rc2")
        code, out = run("install", self.pkgdir, self.tree)
        self.assertEqual(code, 1, out)
        self.assertIn("not v6.22.0-rc1", out)

    def test_refuses_a_package_without_a_binary_or_a_version(self):
        self.package(missing="ycash-tx")
        code, out = run("install", self.pkgdir, self.tree)
        self.assertEqual(code, 1, out)
        self.assertIn("has no ycash-tx", out)
        shutil.rmtree(self.pkgdir)
        os.makedirs(self.pkgdir)
        shutil.rmtree(os.path.join(self.tmp, "stage"))
        self.package(version="6.22.0-rc0")
        code, out = run("install", self.pkgdir, self.tree)
        self.assertEqual(code, 1, out)
        self.assertIn("does not name a release version", out)


class Pins(unittest.TestCase):
    def write(self, text):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        self.addCleanup(os.unlink, path)
        return path

    def test_pin_lines_pass_and_anything_else_fails(self):
        good = "TRAIN_RELEASE_VERSION=6.22.0-rc1\nTRAIN_YOLO_COMMIT=%s\nTRAIN_YCASH_DD_TAG=vault-params/v6.22.0-rc1\n" % ("a" * 40)
        code, out = run("pins", self.write(good))
        self.assertEqual(code, 0, out)
        self.assertEqual(out.splitlines(), good.splitlines())
        for bad in ("TRAIN_X=$(id)\n", "PATH=/tmp\n", "TRAIN_X=a b\n", "TRAIN_X=\n", ""):
            code, out = run("pins", self.write(bad))
            self.assertEqual(code, 1, repr(bad) + out)


class CrossLine(unittest.TestCase):
    def test_chain_args_keep_rules_and_drop_local_ones(self):
        args = ["-nuparams=6d5b7a31:200", "-yellowbackattestorset=" + "ab" * 32, "-pqfalconheight=200",
                "-port=1234", "-rpcport=1235", "-connect=127.0.0.1:1", "-zmqpubhashblock=tcp://x", "-mineraddress=x",
                "-insightexplorer", "-txindex=1", "-nurejectoldversions=false", "-debug=yellowback"]
        self.assertEqual(crossline.chain_args(args), ["-nuparams=6d5b7a31:200", "-yellowbackattestorset=" + "ab" * 32,
                                                      "-pqfalconheight=200", "-nurejectoldversions=false"])


if __name__ == "__main__":
    unittest.main()
