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
    static Params p = [] { Params t; return t; }();
    return p;
}
const Params& TestFastParams()
{
    static Params p = [] { Params f; return f; }();
    return p;
}
"""
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


def testnet(fast=NO, proto=270200):
    """CTestNetParams and its three profile subclasses (testnet plan Revision 3); slow and legacy unset."""
    out = """class CTestNetParams : public CChainParams {
protected:
    CTestNetParams() {
        consensus.vUpgrades[Consensus::UPGRADE_VAULT].nProtocolVersion = %s;
    }
};
""" % proto
    for cls, height in (("CTestNetFastParams", fast), ("CTestNetSlowParams", NO), ("CTestNetLegacyParams", NO)):
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
               att=ATT, params_h=PARAMS_H):
    chain = (klass("CMainParams", main_height, main_extra)
             + testnet(test_height)
             + klass("CRegTestParams", NO, reg_extra))
    files = {
        "src/chainparams.cpp": chain,
        "src/consensus/params.h": params_h,
        "src/version.h": VERSION_H,
        "src/yellowback/params.cpp": PARAMS_CPP % att,
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
        code, out = run(["--root", root, "--other-json", other, "--release-version", "6.22.1-rc1"])
        self.assertEqual(code, 0, out)
        self.assertIn("release heights: ok", out)

    def test_off_line_version_is_refused_even_when_warning(self):
        code, out = run(["--warn", "--release-version", "6.21.4"])
        self.assertEqual(code, 1, out)
        self.assertIn("not 6.22.x", out)

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
