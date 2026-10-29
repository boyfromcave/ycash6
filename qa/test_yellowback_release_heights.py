#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Unit tests for qa/yellowback-release-heights.sh. No tags are pushed."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SCRIPT = os.path.join(HERE, "yellowback-release-heights.sh")
EXTRACT = os.path.join(HERE, "yellowback-vault-params.py")
NO = "Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT"
ATT = "ab" * 32

PARAMS_H = (
    "int pqFalconHeight = NetworkUpgrade::NO_ACTIVATION_HEIGHT;\n"
    "uint32_t nVaultMinSetMaturity = 16128;\n"
)
PARAMS_CPP = """
const Params& MainParams()
{
    static Params p = [] { Params m; m.attestorSetId = uint256S("%s"); return m; }();
    return p;
}
const Params& TestParams()
{
    static Params p = [] { Params t;%s return t; }();
    return p;
}
const Params& TestFastParams()
{
    static Params p = [] { Params f;%s return f; }();
    return p;
}
"""


def set_id(var, att):
    return "" if att is None else ' %s.attestorSetId = uint256S("%s");' % (var, att)
VERSION_H = "static const int PROTOCOL_VERSION = 270200;\nstatic const int MIN_PEER_PROTO_VERSION = 170002;\n"


def klass(cls, height, extra="", proto=270200):
    return """class %s : public CChainParams {
public:
    %s() {
        consensus.vUpgrades[Consensus::UPGRADE_VAULT].nProtocolVersion = %s;
        consensus.vUpgrades[Consensus::UPGRADE_VAULT].nActivationHeight =
            %s;
%s    }
    void Setter(int height) {
        consensus.pqFalconHeight = height;
    }
};
static %s %s;
""" % (cls, cls, proto, height, extra, cls, cls.lower())


def testnet(fast=NO, proto=270200, slow=NO):
    """CTestNetParams and its three profile subclasses (testnet plan Revision 3); legacy unset."""
    out = """class CTestNetParams : public CChainParams {
protected:
    CTestNetParams() {
        consensus.vUpgrades[Consensus::UPGRADE_VAULT].nProtocolVersion = %s;
    }
};
""" % proto
    for cls, height in (("CTestNetFastParams", fast), ("CTestNetSlowParams", slow), ("CTestNetLegacyParams", NO)):
        out += """class %s : public CTestNetParams {
public:
    %s() {
        consensus.vUpgrades[Consensus::UPGRADE_VAULT].nActivationHeight =
            %s;
    }
};
""" % (cls, cls, height)
    return out


def write_tree(root, main_height="3300000", main_extra="        consensus.pqFalconHeight = 0;\n",
               test_height=NO, reg_extra="        consensus.nVaultMinSetMaturity = 2;\n",
               att=ATT, params_h=PARAMS_H, slow_height=NO, fast_att=None, slow_att=None, proto=270200,
               version_h=VERSION_H):
    chain = (klass("CMainParams", main_height, main_extra, proto)
             + testnet(test_height, proto, slow_height)
             + klass("CRegTestParams", NO, reg_extra, proto))
    files = {
        "src/chainparams.cpp": chain,
        "src/consensus/params.h": params_h,
        "src/version.h": version_h,
        "src/yellowback/params.cpp": PARAMS_CPP % (att, set_id("t", slow_att), set_id("f", fast_att)),
    }
    for rel, text in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)


def run(args, cwd=REPO):
    proc = subprocess.run(["bash", SCRIPT] + args, cwd=cwd, capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


class ReleaseHeights(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="yb-release-heights-")
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_ready_tree_passes(self):
        root = os.path.join(self.tmp, "ready")
        write_tree(root)
        code, out = run(["--root", root])
        self.assertEqual(code, 0, out)
        self.assertIn("release heights: ok", out)
        self.assertIn("pqFalconHeight 0", out)
        self.assertIn("nVaultMinSetMaturity 16128", out)

    def test_unset_activation_height_is_refused(self):
        root = os.path.join(self.tmp, "noheight")
        write_tree(root, main_height=NO)
        code, out = run(["--root", root])
        self.assertEqual(code, 1, out)
        self.assertIn("problem: R1: the mainnet UPGRADE_VAULT activation height is unset", out)
        self.assertIn("refusing to release", out)
        warn, warned = run(["--warn", "--root", root])
        self.assertEqual(warn, 0, warned)
        self.assertIn("warning: not a release: continuing", warned)

    def test_unset_falcon_height_is_refused(self):
        root = os.path.join(self.tmp, "nofalcon")
        write_tree(root, main_extra="")
        code, out = run(["--root", root])
        self.assertEqual(code, 1, out)
        self.assertIn("problem: R6: the mainnet pqFalconHeight is unset", out)

    def test_zero_maturity_is_refused(self):
        root = os.path.join(self.tmp, "zeromat")
        write_tree(root, main_extra="        consensus.pqFalconHeight = 0;\n        consensus.nVaultMinSetMaturity = 0;\n")
        code, out = run(["--root", root])
        self.assertEqual(code, 1, out)
        self.assertIn("problem: the mainnet nVaultMinSetMaturity is unset", out)

    def test_missing_maturity_default_fails_closed(self):
        root = os.path.join(self.tmp, "badparse")
        write_tree(root, params_h="int pqFalconHeight = 0;\n")
        code, out = run(["--warn", "--root", root])
        self.assertEqual(code, 2, out)
        self.assertIn("could not extract Vault parameters", out)

    def test_unset_attestor_set_is_still_refused(self):
        root = os.path.join(self.tmp, "noset")
        write_tree(root, att="0" * 64)
        code, out = run(["--root", root])
        self.assertEqual(code, 1, out)
        self.assertIn("problem: R2: the mainnet YED attestor set", out)

    def test_divergence_of_each_guarded_field(self):
        left = os.path.join(self.tmp, "left")
        right = os.path.join(self.tmp, "right")
        write_tree(left)
        write_tree(right, main_height="3300001",
                   main_extra="        consensus.pqFalconHeight = 1;\n",
                   reg_extra="        consensus.nVaultMinSetMaturity = 3;\n")
        other = os.path.join(self.tmp, "right.json")
        ext = subprocess.run(["python3", EXTRACT, "extract", "--root", right],
                             check=True, capture_output=True, text=True)
        with open(other, "w", encoding="utf-8") as fh:
            fh.write(ext.stdout)
        code, out = run(["--root", left, "--other-json", other])
        self.assertEqual(code, 1, out)
        self.assertIn("problem: divergent main.vault_activation_height: 3300000 != 3300001", out)
        self.assertIn("problem: divergent main.pq_falcon_height: 0 != 1", out)
        self.assertIn("problem: divergent regtest.vault_min_set_maturity: 2 != 3", out)

    def test_matching_other_line_passes(self):
        root = os.path.join(self.tmp, "same")
        write_tree(root)
        ext = subprocess.run(["python3", EXTRACT, "extract", "--root", root],
                             check=True, capture_output=True, text=True)
        other = os.path.join(self.tmp, "same.json")
        with open(other, "w", encoding="utf-8") as fh:
            fh.write(ext.stdout)
        code, out = run(["--root", root, "--other-json", other, "--release-version", "6.22.1"])
        self.assertEqual(code, 0, out)
        self.assertIn("release heights: ok", out)

    def test_off_line_version_is_refused_even_when_warning(self):
        code, out = run(["--warn", "--release-version", "6.21.4-rc1"])
        self.assertEqual(code, 1, out)
        self.assertIn("not 6.22.x", out)

    def rc_tree(self, name, **kw):
        """An rc-shaped tree: mainnet unset, testnet-yb-fast launched and named, the Vault-era protocol."""
        root = os.path.join(self.tmp, name)
        args = dict(main_height=NO, att="0" * 64, test_height="510400", fast_att=ATT)
        args.update(kw)
        write_tree(root, **args)
        return root

    def test_rc_tag_needs_no_mainnet_height_or_set(self):
        # Testnet plan §5.1 (T-8): an rc carries the testnet's height and set, mainnet's stay unset.
        root = self.rc_tree("rc")
        code, out = run(["--root", root, "--release-version", "6.22.0-rc1"])
        self.assertEqual(code, 0, out)
        self.assertIn("release stage: rc", out)
        self.assertIn("release heights: ok", out)
        # The same tree is not a final release: R1 and R2 refuse it.
        code, out = run(["--root", root, "--release-version", "6.22.0"])
        self.assertEqual(code, 1, out)
        self.assertIn("problem: R1:", out)
        self.assertIn("problem: R2:", out)
        # No version and no stage is the strictest reading (final).
        code, out = run(["--root", root])
        self.assertEqual(code, 1, out)
        self.assertIn("release stage: final", out)

    def test_rc_tag_needs_the_fast_set(self):
        root = self.rc_tree("rc-noset", fast_att=None)
        code, out = run(["--root", root, "--release-version", "6.22.0-rc1"])
        self.assertEqual(code, 1, out)
        self.assertIn("problem: R7 (rc): testnet-yb-fast needs its activation height and testfast_attestor_set_id", out)

    def test_rc_tag_with_slow_activation_pending(self):
        # T-15: testnet-yb-slow's first rc sets its height; its set is created after the activation.
        root = self.rc_tree("rc-slow", slow_height="520000")
        code, out = run(["--root", root, "--release-version", "6.22.0-rc2"])
        self.assertEqual(code, 0, out)
        self.assertIn("testnet-yb-slow: UPGRADE_VAULT height 520000", out)
        # A set named for slow before it has a height is refused.
        root = self.rc_tree("rc-slow-set", slow_att="cd" * 32)
        code, out = run(["--root", root, "--release-version", "6.22.0-rc2"])
        self.assertEqual(code, 1, out)
        self.assertIn("problem: R7 (rc): testnet-yb-slow names test_attestor_set_id without an activation height", out)

    def test_rc_tag_needs_the_protocol_bump(self):
        old = VERSION_H.replace("270200", "270013")
        root = self.rc_tree("rc-proto", proto=270013, version_h=old)
        code, out = run(["--root", root, "--release-version", "6.22.0-rc1"])
        self.assertEqual(code, 1, out)
        self.assertIn("problem: R3:", out)

    def test_rc_tag_with_only_one_of_mainnet_height_and_set(self):
        root = self.rc_tree("rc-main", main_height="3300000")
        code, out = run(["--root", root, "--release-version", "6.22.0-rc3"])
        self.assertEqual(code, 1, out)
        self.assertIn("problem: R1/R2 (rc):", out)
        root = self.rc_tree("rc-main-both", main_height="3300000", att=ATT)
        code, out = run(["--root", root, "--release-version", "6.22.0-rc3"])
        self.assertEqual(code, 0, out)

    def test_beta_tag_needs_no_heights_sets_or_protocol(self):
        old = VERSION_H.replace("270200", "270013")
        root = os.path.join(self.tmp, "beta")
        write_tree(root, main_height=NO, att="0" * 64, test_height="510400", proto=270013, version_h=old)
        code, out = run(["--root", root, "--release-version", "6.22.0-beta2"])
        self.assertEqual(code, 0, out)
        self.assertIn("release stage: beta", out)
        # The maturity and parity still hold on a beta.
        write_tree(root, main_height=NO, att="0" * 64,
                   main_extra="        consensus.pqFalconHeight = 0;\n        consensus.nVaultMinSetMaturity = 0;\n")
        code, out = run(["--root", root, "--release-version", "6.22.0-beta2"])
        self.assertEqual(code, 1, out)
        self.assertIn("problem: the mainnet nVaultMinSetMaturity is unset", out)

    def test_version_and_stage_must_agree(self):
        root = self.rc_tree("agree")
        code, out = run(["--root", root, "--release-version", "6.22.0-rc1", "--stage", "final"])
        self.assertEqual(code, 1, out)
        self.assertIn("is a rc", out)
        code, out = run(["--root", root, "--stage", "rc"])
        self.assertEqual(code, 0, out)
        for bad in ("6.22.0-rc0", "6.22", "v6.22.0-rc1", "6.22.0-RC1", "6.22.0-rc1-x"):
            code, out = run(["--warn", "--root", root, "--release-version", bad])
            self.assertEqual(code, 1, bad + ": " + out)
            self.assertIn("refusing to release", out)
        code, out = run(["--root", root, "--stage", "gamma"])
        self.assertEqual(code, 1, out)

    def test_current_tree_warns_and_strict_follows_the_height(self):
        warn, warned = run(["--warn"])
        self.assertEqual(warn, 0, warned)
        self.assertNotIn("problem: the mainnet pqFalconHeight is unset", warned)
        self.assertNotIn("problem: the mainnet nVaultMinSetMaturity is unset", warned)
        strict, refused = run([])
        if "R1: the mainnet UPGRADE_VAULT activation height is unset" in warned:
            self.assertEqual(strict, 1, refused)
            self.assertIn("refusing to release", refused)
        else:
            self.assertEqual(strict, 0, refused)
        # A copy of this tree does not diverge from itself.
        mine = os.path.join(self.tmp, "mine.json")
        ext = subprocess.run(["python3", EXTRACT, "extract", "--root", REPO],
                             check=True, capture_output=True, text=True)
        with open(mine, "w", encoding="utf-8") as fh:
            fh.write(ext.stdout)
        code, out = run(["--warn", "--other-json", mine])
        self.assertEqual(code, 0, out)
        self.assertNotIn("divergent", out)
        parsed = json.loads(ext.stdout)
        self.assertEqual(parsed["main"]["pq_falcon_height"], 0)
        self.assertEqual(parsed["main"]["vault_min_set_maturity"], 16128)


if __name__ == "__main__":
    unittest.main()
