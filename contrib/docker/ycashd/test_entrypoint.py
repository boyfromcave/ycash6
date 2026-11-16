# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Unit tests of the image entrypoint's YCASHD_BOOTSTRAP (offline; stand-in ycashd and ycash-bootstrap).

    python3 -m unittest contrib/docker/ycashd/test_entrypoint.py

The entrypoint is run with `sh` exactly as the image runs it, with stubs for ycashd, ycash-cli and
ycash-bootstrap first on PATH that record their arguments. The file is the same on both node lines;
the line (from this tree's configure.ac) decides what mainnet's YCASHD_BOOTSTRAP must do: restore a
state bundle on ycash6, refuse one on ycash-dd (a mainnet state bundle is a ycash6 datadir).
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ENTRYPOINT = os.path.join(HERE, "entrypoint.sh")
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))


def node_line():
    """ycash6 (6.x) or ycash-dd (4.5), from the tree's configure.ac."""
    with open(os.path.join(ROOT, "configure.ac")) as f:
        major = int(re.search(r"define\(_CLIENT_VERSION_MAJOR, (\d+)\)", f.read()).group(1))
    return "ycash6" if major >= 6 else "ycash-dd"


LINE = node_line()
ON_YCASH6 = unittest.skipUnless(LINE == "ycash6", "ycash6 only: ycash-dd refuses a mainnet state bundle")

STUB = """#!/bin/sh
printf '%%s\\n' "$@" > "%(dir)s/%(name)s.args"
%(extra)s
exit 0
"""
# ycash-bootstrap's stand-in creates the network's blocks/ (mainnet: the datadir's) and, on success,
# <net>/bootstrap.json, the way a restore would.
# STUB_BOOTSTRAP_REFUSE behaves as the import whose node synced past the bundle did (beta3 item 8):
# blocks written, the marker left with the reason, exit 2. STUB_BOOTSTRAP_LEAVE_MARKER exits 0 with it.
BOOTSTRAP_EXTRA = """[ -n "${STUB_BOOTSTRAP_FAIL:-}" ] && exit 1
net=""; dd=""
while [ $# -gt 0 ]; do case "$1" in --network) net=$2; shift 2 ;; --datadir) dd=$2; shift 2 ;; *) shift ;; esac; done
nd="$dd/$net"; [ "$net" = main ] && nd="$dd"
mkdir -p "$nd/blocks" && touch "$nd/blocks/blk00000.dat"
if [ -n "${STUB_BOOTSTRAP_REFUSE:-}${STUB_BOOTSTRAP_LEAVE_MARKER:-}" ]; then
  echo "the restore failed: the node is at 510312, above the bundle's 510247" > "$dd/$net.bootstrap-incomplete"
  [ -n "${STUB_BOOTSTRAP_REFUSE:-}" ] && exit 2
fi
echo '{}' > "$nd/bootstrap.json"
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
            os.chmod(path, 0o700)
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
        open(os.path.join(self.data, "testnet-legacy", "bootstrap.json"), "w").close()      # a restore completed
        result = self.run_entrypoint(YCASHD_NETWORK="testnet", YCASHD_TESTNET_PROFILE="legacy", YCASHD_BOOTSTRAP="prefix")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIsNone(self.args("ycash-bootstrap"))
        self.assertIn("already holds blocks", result.stdout)
        self.assertIsNotNone(self.args("ycashd"))

    def test_blocks_without_a_completed_restore_are_refused(self):
        # A datadir an image before beta3 started on after a failed restore: blocks, no bootstrap.json, no marker.
        os.makedirs(os.path.join(self.data, "testnet-yb-fast", "blocks"))
        open(os.path.join(self.data, "testnet-yb-fast", "blocks", "blk00000.dat"), "w").close()
        env = dict(YCASHD_NETWORK="testnet", YCASHD_TESTNET_PROFILE="fast", YCASHD_BOOTSTRAP="prefix")
        result = self.run_entrypoint(**env)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("no bootstrap.json", result.stdout)
        self.assertIsNone(self.args("ycashd"))
        self.assertIsNone(self.args("ycash-bootstrap"))
        for ok in (dict(env, YCASHD_BOOTSTRAP_ACCEPT_DATADIR="1"), dict(YCASHD_NETWORK="testnet", YCASHD_TESTNET_PROFILE="fast")):
            result = self.run_entrypoint(**ok)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIsNotNone(self.args("ycashd"))
            self.assertIsNone(self.args("ycash-bootstrap"))

    def test_the_mainnet_switch_is_this_lines(self):
        with open(ENTRYPOINT) as f:
            text = f.read()
        self.assertEqual(re.findall(r"^BOOTSTRAP_MAINNET=(\d)$", text, re.M), ["1" if LINE == "ycash6" else "0"])

    @unittest.skipUnless(LINE == "ycash-dd", "ycash-dd only")
    def test_ycash_dd_refuses_a_mainnet_state_bundle(self):
        for value in ("https://snapshots.example.invalid/main-insight/latest/", "prefix"):
            result = self.run_entrypoint(YCASHD_BOOTSTRAP=value)
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertIn("a mainnet snapshot bundle is a ycash6 datadir", result.stdout)
            self.assertIn("use the ycash6 image", result.stdout)
            self.assertIsNone(self.args("ycash-bootstrap"))
            self.assertIsNone(self.args("ycashd"))
        result = self.run_entrypoint()                                       # unset: the node starts and syncs
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIsNotNone(self.args("ycashd"))

    @ON_YCASH6
    def test_mainnet_restores_a_state_bundle(self):
        url = "https://snapshots.example.invalid/main-insight/latest/"
        result = self.run_entrypoint(YCASHD_BOOTSTRAP=url)
        self.assertEqual(result.returncode, 0, result.stdout)
        boot = self.args("ycash-bootstrap")
        self.assertEqual(boot[boot.index("--network") + 1], "main")
        self.assertEqual(boot[boot.index("--source") + 1], url)
        self.assertIn("--state", boot)
        self.assertTrue(os.path.isfile(os.path.join(self.data, "blocks", "blk00000.dat")))
        self.assertIsNotNone(self.args("ycashd"))
        os.remove(os.path.join(self.tmp, "ycash-bootstrap.args"))
        result = self.run_entrypoint(YCASHD_BOOTSTRAP=url)                  # restarted: restored once, recorded
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("already holds blocks", result.stdout)
        self.assertIsNone(self.args("ycash-bootstrap"))

    @ON_YCASH6
    def test_a_failed_mainnet_restore_is_not_started_past(self):
        url = "https://snapshots.example.invalid/main/latest/"
        result = self.run_entrypoint(YCASHD_BOOTSTRAP=url, YCASHD_INSIGHT="0", STUB_BOOTSTRAP_REFUSE="1")
        self.assertEqual(result.returncode, 1, result.stdout)
        marker = os.path.join(self.data, "main.bootstrap-incomplete")
        self.assertTrue(os.path.exists(marker))
        os.remove(os.path.join(self.tmp, "ycash-bootstrap.args"))
        for again in (dict(YCASHD_BOOTSTRAP=url), {}):
            result = self.run_entrypoint(**again)
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertIn(marker, result.stdout)
            self.assertIsNone(self.args("ycashd"))

    def test_a_url_and_regtest(self):
        result = self.run_entrypoint(YCASHD_NETWORK="regtest", YCASHD_VAULT_HEIGHT="5", YCASHD_BOOTSTRAP="https://example.invalid/b/manifest.json")
        self.assertEqual(result.returncode, 0, result.stdout)
        boot = self.args("ycash-bootstrap")
        self.assertEqual(boot[boot.index("--network") + 1], "regtest")
        self.assertEqual(boot[boot.index("--source") + 1], "https://example.invalid/b/manifest.json")

    def test_refusals(self):
        result = self.run_entrypoint(YCASHD_BOOTSTRAP="prefix")             # mainnet: a state bundle only, never the prefix
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("mainnet has no prefix layer" if LINE == "ycash6" else "a ycash6 datadir", result.stdout)
        self.assertIsNone(self.args("ycashd"))
        self.assertIsNone(self.args("ycash-bootstrap"))
        result = self.run_entrypoint(YCASHD_NETWORK="testnet", YCASHD_TESTNET_PROFILE="slow", YCASHD_BOOTSTRAP="prefix", STUB_BOOTSTRAP_FAIL="1")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("the node is not started", result.stdout)
        self.assertIsNone(self.args("ycashd"))

    def test_a_refused_restore_is_not_started_past(self):
        # beta3 item 8: the restore was refused after the import wrote blocks; the restart then saw
        # blocks and started the node on them. The marker stops every later start until it is cleared.
        env = dict(YCASHD_NETWORK="testnet", YCASHD_TESTNET_PROFILE="fast", YCASHD_BOOTSTRAP="prefix")
        result = self.run_entrypoint(STUB_BOOTSTRAP_REFUSE="1", **env)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIsNone(self.args("ycashd"))
        os.remove(os.path.join(self.tmp, "ycash-bootstrap.args"))
        marker = os.path.join(self.data, "testnet-yb-fast.bootstrap-incomplete")
        for again in (env, dict(YCASHD_NETWORK="testnet", YCASHD_TESTNET_PROFILE="fast")):     # restarted, or YCASHD_BOOTSTRAP dropped
            result = self.run_entrypoint(**again)
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertIn(marker, result.stdout)
            self.assertIn("above the bundle's 510247", result.stdout)
            self.assertIsNone(self.args("ycashd"))
            self.assertIsNone(self.args("ycash-bootstrap"))
        os.remove(marker)                                        # the operator clears it: the datadir is used as it is,
        result = self.run_entrypoint(**env)                      # once they say so while YCASHD_BOOTSTRAP is set
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("no bootstrap.json", result.stdout)
        result = self.run_entrypoint(YCASHD_BOOTSTRAP_ACCEPT_DATADIR="1", **env)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIsNotNone(self.args("ycashd"))

    def test_a_marker_after_a_zero_exit_is_not_a_restore(self):
        result = self.run_entrypoint(YCASHD_NETWORK="regtest", YCASHD_BOOTSTRAP="/b", STUB_BOOTSTRAP_LEAVE_MARKER="1")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIsNone(self.args("ycashd"))

    def test_another_networks_marker_does_not_stop_this_one(self):
        os.makedirs(self.data)
        open(os.path.join(self.data, "testnet-yb-slow.bootstrap-incomplete"), "w").close()
        result = self.run_entrypoint(YCASHD_NETWORK="testnet", YCASHD_TESTNET_PROFILE="fast")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIsNotNone(self.args("ycashd"))

    def test_unset_changes_nothing(self):
        result = self.run_entrypoint(YCASHD_NETWORK="testnet", YCASHD_TESTNET_PROFILE="fast")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIsNone(self.args("ycash-bootstrap"))
        self.assertIsNotNone(self.args("ycashd"))


if __name__ == "__main__":
    unittest.main()
