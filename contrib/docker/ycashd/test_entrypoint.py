# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Unit tests of the image entrypoint's YCASHD_BOOTSTRAP (offline; stand-in ycashd and ycash-bootstrap).

    python3 -m unittest contrib/docker/ycashd/test_entrypoint.py

The entrypoint is run with `sh` exactly as the image runs it, with stubs for ycashd, ycash-cli and
ycash-bootstrap first on PATH that record their arguments.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ENTRYPOINT = os.path.join(HERE, "entrypoint.sh")

STUB = """#!/bin/sh
printf '%%s\\n' "$@" > "%(dir)s/%(name)s.args"
%(extra)s
exit 0
"""
# ycash-bootstrap's stand-in creates the network's blocks/ the way a restore would.
BOOTSTRAP_EXTRA = """[ -n "${STUB_BOOTSTRAP_FAIL:-}" ] && exit 1
net=""; dd=""
while [ $# -gt 0 ]; do case "$1" in --network) net=$2; shift 2 ;; --datadir) dd=$2; shift 2 ;; *) shift ;; esac; done
mkdir -p "$dd/$net/blocks" && touch "$dd/$net/blocks/blk00000.dat"
"""


class EntrypointTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="entrypoint-test-")
        self.bin = os.path.join(self.tmp, "bin")
        self.data = os.path.join(self.tmp, "data")
        home = os.path.join(self.tmp, "home")
        os.makedirs(os.path.join(home, ".zcash-params"))
        open(os.path.join(home, ".zcash-params", "sprout-groth16.params"), "w").close()   # the 4.5 line fetches it otherwise
        os.makedirs(self.bin)
        for name, extra in (("ycashd", ""), ("ycash-cli", ""), ("ycash-bootstrap", BOOTSTRAP_EXTRA)):
            path = os.path.join(self.bin, name)
            with open(path, "w") as f:
                f.write(STUB % {"dir": self.tmp, "name": name, "extra": extra})
            os.chmod(path, 0o755)
        self.env = {"PATH": self.bin + ":/usr/bin:/bin", "HOME": home, "YCASHD_DATADIR": self.data,
                    "YCASHD_RPC_USER": "u", "YCASHD_RPC_PASSWORD": "p"}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_entrypoint(self, **env):
        return subprocess.run(["sh", ENTRYPOINT], env=dict(self.env, **env), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def args(self, name):
        path = os.path.join(self.tmp, name + ".args")
        if not os.path.exists(path):
            return None
        with open(path) as f:
            return f.read().splitlines()

    def test_prefix_restore_then_start(self):
        result = self.run_entrypoint(YCASHD_NETWORK="testnet", YCASHD_TESTNET_PROFILE="fast", YCASHD_BOOTSTRAP="prefix",
                                     YCASHD_BOOTSTRAP_ARGS="--require-signature")
        self.assertEqual(result.returncode, 0, result.stdout)
        boot = self.args("ycash-bootstrap")
        for pair in (["--network", "testnet-yb-fast"], ["--datadir", self.data], ["--conf", os.path.join(self.data, "ycash.conf")],
                     ["--source", "prefix"], ["--ycashd", os.path.join(self.bin, "ycashd")], ["--cli", os.path.join(self.bin, "ycash-cli")]):
            self.assertEqual(boot[boot.index(pair[0]) + 1], pair[1], pair)
        self.assertIn("--require-signature", boot)
        self.assertIn("-datadir=%s" % self.data, self.args("ycashd"))
        with open(os.path.join(self.data, "ycash.conf")) as f:
            conf = f.read()
        self.assertIn("testnetprofile=fast", conf)

    def test_a_datadir_with_blocks_is_not_restored_again(self):
        os.makedirs(os.path.join(self.data, "testnet-legacy", "blocks"))
        open(os.path.join(self.data, "testnet-legacy", "blocks", "blk00000.dat"), "w").close()
        result = self.run_entrypoint(YCASHD_NETWORK="testnet", YCASHD_TESTNET_PROFILE="legacy", YCASHD_BOOTSTRAP="prefix")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIsNone(self.args("ycash-bootstrap"))
        self.assertIn("already holds blocks", result.stdout)
        self.assertIsNotNone(self.args("ycashd"))

    def test_a_url_and_regtest(self):
        result = self.run_entrypoint(YCASHD_NETWORK="regtest", YCASHD_VAULT_HEIGHT="5", YCASHD_BOOTSTRAP="https://example.invalid/b/manifest.json")
        self.assertEqual(result.returncode, 0, result.stdout)
        boot = self.args("ycash-bootstrap")
        self.assertEqual(boot[boot.index("--network") + 1], "regtest")
        self.assertEqual(boot[boot.index("--source") + 1], "https://example.invalid/b/manifest.json")

    def test_refusals(self):
        result = self.run_entrypoint(YCASHD_BOOTSTRAP="prefix")             # mainnet: no bundle before N7
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIsNone(self.args("ycashd"))
        result = self.run_entrypoint(YCASHD_NETWORK="testnet", YCASHD_TESTNET_PROFILE="slow", YCASHD_BOOTSTRAP="prefix", STUB_BOOTSTRAP_FAIL="1")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("the node is not started", result.stdout)
        self.assertIsNone(self.args("ycashd"))

    def test_unset_changes_nothing(self):
        result = self.run_entrypoint(YCASHD_NETWORK="testnet", YCASHD_TESTNET_PROFILE="fast")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIsNone(self.args("ycash-bootstrap"))
        self.assertIsNotNone(self.args("ycashd"))


if __name__ == "__main__":
    unittest.main()
