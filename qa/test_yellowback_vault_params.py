#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("vp", os.path.join(HERE, "yellowback-vault-params.py"))
vp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vp)

PARAMS_H = "int pqFalconHeight = NetworkUpgrade::NO_ACTIVATION_HEIGHT;\nuint32_t nVaultMinSetMaturity = 16128;\n"
VERSION_H = "static const int PROTOCOL_VERSION = 270013;\nstatic const int MIN_PEER_PROTO_VERSION = 170002;\n"
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


def klass(cls, height, extra=""):
    return """class %s : public CChainParams {
public:
    %s() {
        consensus.vUpgrades[Consensus::UPGRADE_VAULT].nProtocolVersion = 270013;
        consensus.vUpgrades[Consensus::UPGRADE_VAULT].nActivationHeight =
            %s;
%s    }
    void Setter(int height) {
        consensus.pqFalconHeight = height;
    }
};
static %s %s;
""" % (cls, cls, height, extra, cls, cls.lower())


UPGRADES_H = """static const uint32_t SLOW_SHADOW_BRANCH_ID = 0x57a24d5d;
static const uint32_t SLOW_VAULT_BRANCH_ID = 0xe1f1cc08;
static const uint32_t LEGACY_SHADOW_BRANCH_ID = 0x35706728;
"""
UPGRADES_CPP = """const struct NUInfo NetworkUpgradeInfo[Consensus::MAX_NETWORK_UPGRADES] = {
    {
        .nBranchId = 0xc8e71055,
        .strName = "NU6",
    },
    {
        // testnet-yb-slow's
        .nBranchId = SLOW_SHADOW_BRANCH_ID,
        .strName = "Shadow",
    },
    {
        .nBranchId = 0x6d5b7a31,
        .strName = "Vault",
    },
};
"""


def testnet(fast="Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT", slow="Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT",
            legacy="Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT", base_extra="", fast_extra="",
            split="Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT", slow_extra=None, legacy_extra=None, shadow_extra=""):
    """CTestNetParams and testnet-yb-fast (testnet plan Revision 3); CTestNetShadowParams, the mainnet-valued
    base of testnet-yb-slow and testnet-legacy (the shadow-fork plan), and those two."""
    if slow_extra is None:
        slow_extra = ("        consensus.vUpgrades[Consensus::UPGRADE_SHADOW].nBranchId = SLOW_SHADOW_BRANCH_ID;\n"
                      "        consensus.vUpgrades[Consensus::UPGRADE_VAULT].nBranchId = SLOW_VAULT_BRANCH_ID;\n")
    if legacy_extra is None:
        legacy_extra = "        consensus.vUpgrades[Consensus::UPGRADE_SHADOW].nBranchId = LEGACY_SHADOW_BRANCH_ID;\n"
    out = """static const int TESTNET_SHADOW_SPLIT_HEIGHT = %s;
class CTestNetParams : public CChainParams {
protected:
    CTestNetParams() {
        consensus.vUpgrades[Consensus::UPGRADE_VAULT].nProtocolVersion = 270013;
%s    }
};
class CTestNetFastParams : public CTestNetParams {
public:
    CTestNetFastParams() {
        consensus.vUpgrades[Consensus::UPGRADE_VAULT].nActivationHeight =
            %s;
%s    }
};
class CTestNetShadowParams : public CMainParams {
protected:
    CTestNetShadowParams() {
        SetShadowSplitHeight(TESTNET_SHADOW_SPLIT_HEIGHT);
%s    }
    void SetShadowSplitHeight(int nSplitHeight) {
        consensus.vUpgrades[Consensus::UPGRADE_SHADOW].nActivationHeight = nSplitHeight + 1;
    }
};
""" % (split, base_extra, fast, fast_extra, shadow_extra)
    for cls, height, extra in (("CTestNetSlowParams", slow, slow_extra), ("CTestNetLegacyParams", legacy, legacy_extra)):
        out += """class %s : public CTestNetShadowParams {
public:
    %s() {
        consensus.vUpgrades[Consensus::UPGRADE_VAULT].nActivationHeight =
            %s;
%s    }
};
""" % (cls, cls, height, extra)
    return out


def reader(chainparams, att="ab" * 32):
    files = {"src/chainparams.cpp": chainparams, "src/consensus/params.h": PARAMS_H,
             "src/version.h": VERSION_H, "src/yellowback/params.cpp": PARAMS_CPP % att,
             "src/consensus/upgrades.h": UPGRADES_H, "src/consensus/upgrades.cpp": UPGRADES_CPP}
    return files.__getitem__


NO = "Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT"


class VaultParams(unittest.TestCase):
    def test_testnet_before_mainnet_is_not_a_first_match(self):
        cp = testnet(fast="11") + klass("CMainParams", NO) + klass("CRegTestParams", NO, "        consensus.nVaultMinSetMaturity = 2;\n")
        r = vp.extract(reader(cp))
        self.assertEqual(r["main"]["vault_activation_height"], "NO_ACTIVATION_HEIGHT")
        self.assertEqual(r["test"]["fast"]["vault_activation_height"], 11)
        self.assertEqual(r["test"]["slow"]["vault_activation_height"], "NO_ACTIVATION_HEIGHT")
        self.assertEqual(r["test"]["fast"]["vault_protocol_version"], 270013)   # from the shared base
        self.assertEqual(r["regtest"]["vault_min_set_maturity"], 2)
        self.assertEqual(r["main"]["vault_min_set_maturity"], 16128)

    def test_continuation_line_height(self):
        cp = klass("CMainParams", "3300000") + testnet() + klass("CRegTestParams", NO)
        self.assertEqual(vp.extract(reader(cp))["main"]["vault_activation_height"], 3300000)

    def test_regtest_setter_outside_constructor_is_ignored(self):
        cp = klass("CMainParams", NO) + testnet() + klass("CRegTestParams", NO)
        self.assertEqual(vp.extract(reader(cp))["regtest"]["pq_falcon_height"], "NO_ACTIVATION_HEIGHT")

    def test_duplicate_assignment_fails_closed(self):
        dup = "        consensus.vUpgrades[Consensus::UPGRADE_VAULT].nProtocolVersion = 1;\n"
        cp = klass("CMainParams", NO, dup) + testnet() + klass("CRegTestParams", NO)
        with self.assertRaises(vp.ParseError):
            vp.extract(reader(cp))

    def test_missing_class_fails_closed(self):
        with self.assertRaises(vp.ParseError):
            vp.extract(reader(klass("CMainParams", NO)))
        no_slow = testnet().replace("CTestNetSlowParams", "CTestNetMediumParams")
        with self.assertRaises(vp.ParseError):
            vp.extract(reader(klass("CMainParams", NO) + no_slow + klass("CRegTestParams", NO)))

    def test_testnet_profile_reads_base_and_subclass_once(self):
        # A profile value in the subclass, maturity from params.h when neither body assigns it.
        mat = "        consensus.nVaultMinSetMaturity = 48;\n"
        cp = klass("CMainParams", NO) + testnet(fast="510400", fast_extra=mat) + klass("CRegTestParams", NO)
        r = vp.extract(reader(cp))
        self.assertEqual(r["test"]["fast"]["vault_min_set_maturity"], 48)
        self.assertEqual(r["test"]["legacy"]["vault_min_set_maturity"], 16128)
        # The same parameter in the base and a subclass is ambiguous: fail closed.
        cp = klass("CMainParams", NO) + testnet(base_extra=mat, fast_extra=mat) + klass("CRegTestParams", NO)
        with self.assertRaises(vp.ParseError):
            vp.extract(reader(cp))
        height = "        consensus.vUpgrades[Consensus::UPGRADE_VAULT].nActivationHeight = 1;\n"
        cp = klass("CMainParams", NO) + testnet(base_extra=height) + klass("CRegTestParams", NO)
        with self.assertRaises(vp.ParseError):
            vp.extract(reader(cp))

    def test_compare_names_the_field(self):
        base = klass("CMainParams", NO) + testnet() + klass("CRegTestParams", NO)
        a = vp.extract(reader(base))
        b = vp.extract(reader(base.replace("= 270013;", "= 270200;", 1)))
        self.assertEqual(vp.compare(a, a), [])
        # Mainnet's value, which the shadow forks (slow, legacy) inherit.
        self.assertEqual(len(vp.compare(a, b)), 3)
        self.assertIn("main.vault_protocol_version", vp.compare(a, b)[0])
        self.assertIn("test.legacy.vault_protocol_version", vp.compare(a, b)[1])
        self.assertIn("test.slow.vault_protocol_version", vp.compare(a, b)[2])
        d = vp.extract(reader(base.replace("SLOW_VAULT_BRANCH_ID;", "0x6d5b7a31;")))
        self.assertEqual(vp.compare(a, d), ["test.slow.vault_branch_id: 'e1f1cc08' != '6d5b7a31'"])
        c = vp.extract(reader(base, att="cd" * 32))
        self.assertTrue(any("yellowback_params.main_attestor_set_id" in x for x in vp.compare(a, c)))

    def test_min_peer_difference_is_not_compared(self):
        base = klass("CMainParams", NO) + testnet() + klass("CRegTestParams", NO)
        a = vp.extract(reader(base))
        b = dict(a, version=dict(a["version"], MIN_PEER_PROTO_VERSION=270013))
        self.assertEqual(vp.compare(a, b), [])

    def test_real_tree(self):
        root = os.path.join(HERE, "..")

        def read(p):
            with open(os.path.join(root, p), encoding="utf-8") as f:
                return f.read()

        r = vp.extract(read)
        nets = [r["main"], r["regtest"]] + [r["test"][p] for p in ("fast", "slow", "legacy")]
        for net in nets:
            self.assertEqual(net["vault_protocol_version"], r["version"]["PROTOCOL_VERSION"])
        # testnet plan Revision 3: fast 510,400 / 48, slow unset until its first rc / 16,128, legacy never.
        self.assertEqual(r["test"]["fast"]["vault_activation_height"], 510400)
        self.assertEqual(r["test"]["fast"]["vault_min_set_maturity"], 48)
        self.assertEqual(r["test"]["slow"]["vault_min_set_maturity"], 16128)
        self.assertEqual(r["test"]["legacy"]["vault_activation_height"], "NO_ACTIVATION_HEIGHT")
        for p in ("fast", "slow", "legacy"):
            self.assertEqual(r["test"][p]["pq_falcon_height"], 0)
        self.assertEqual(r["main"]["pq_falcon_height"], 0)
        self.assertEqual(r["regtest"]["vault_min_set_maturity"], 2)
        self.assertEqual(r["main"]["vault_min_set_maturity"], 16128)
        # The shadow-fork plan: each network's own branch IDs; mainnet's, fast's and regtest's are global.
        for net in (r["main"], r["regtest"], r["test"]["fast"], r["test"]["legacy"]):
            self.assertEqual(net["vault_branch_id"], "6d5b7a31")
        self.assertEqual(r["test"]["slow"]["vault_branch_id"], "e1f1cc08")
        self.assertEqual(r["test"]["slow"]["shadow_branch_id"], "57a24d5d")
        self.assertEqual(r["test"]["legacy"]["shadow_branch_id"], "35706728")
        self.assertEqual(r["test"]["slow"]["shadow_split_height"], r["test"]["legacy"]["shadow_split_height"])
        self.assertNotIn("shadow_split_height", r["test"]["fast"])
        self.assertNotIn("shadow_split_height", r["main"])

    def test_shadow_profiles_read_mainnet_then_their_own(self):
        # slow and legacy are CMainParams, then CTestNetShadowParams, then their own body; a later body overrides.
        main_extra = "        consensus.pqFalconHeight = 0;\n"
        cp = klass("CMainParams", "3300000", main_extra) + testnet(split="3100000") + klass("CRegTestParams", NO)
        r = vp.extract(reader(cp))
        for p in ("slow", "legacy"):
            self.assertEqual(r["test"][p]["vault_activation_height"], "NO_ACTIVATION_HEIGHT")   # overrides mainnet's
            self.assertEqual(r["test"][p]["vault_protocol_version"], 270013)                   # mainnet's
            self.assertEqual(r["test"][p]["pq_falcon_height"], 0)                              # mainnet's
            self.assertEqual(r["test"][p]["shadow_split_height"], 3100000)
        self.assertEqual(r["main"]["vault_activation_height"], 3300000)
        # A literal split height in the base, and the table's shadow ID when a profile names none.
        cp = (klass("CMainParams", NO) + testnet(legacy_extra="").replace(
            "SetShadowSplitHeight(TESTNET_SHADOW_SPLIT_HEIGHT)", "SetShadowSplitHeight(3200000)") + klass("CRegTestParams", NO))
        r = vp.extract(reader(cp))
        self.assertEqual(r["test"]["legacy"]["shadow_split_height"], 3200000)
        self.assertEqual(r["test"]["legacy"]["shadow_branch_id"], "57a24d5d")
        # Twice in one body is ambiguous: fail closed.
        dup = ("        consensus.vUpgrades[Consensus::UPGRADE_VAULT].nBranchId = SLOW_VAULT_BRANCH_ID;\n" * 2)
        with self.assertRaises(vp.ParseError):
            vp.extract(reader(klass("CMainParams", NO) + testnet(slow_extra=dup) + klass("CRegTestParams", NO)))
        # An unknown branch-ID constant, or no split height at all: fail closed.
        bad = "        consensus.vUpgrades[Consensus::UPGRADE_VAULT].nBranchId = NO_SUCH_BRANCH_ID;\n"
        with self.assertRaises(vp.ParseError):
            vp.extract(reader(klass("CMainParams", NO) + testnet(slow_extra=bad) + klass("CRegTestParams", NO)))
        nosplit = testnet().replace("        SetShadowSplitHeight(TESTNET_SHADOW_SPLIT_HEIGHT);\n", "")
        with self.assertRaises(vp.ParseError):
            vp.extract(reader(klass("CMainParams", NO) + nosplit + klass("CRegTestParams", NO)))

    def test_release_rules_r1_through_r7(self):
        att = "ab" * 32
        doc = {
            "version": {"PROTOCOL_VERSION": 270200, "MIN_PEER_PROTO_VERSION": 170002},
            "main": {"vault_protocol_version": 270200, "vault_activation_height": 3300000,
                     "pq_falcon_height": 0, "vault_min_set_maturity": 16128},
            "test": {p: {"vault_protocol_version": 270200, "vault_activation_height": "NO_ACTIVATION_HEIGHT",
                         "pq_falcon_height": 0, "vault_min_set_maturity": 16128} for p in ("fast", "slow", "legacy")},
            "yellowback_params": {"main_attestor_set_id": att, "test_attestor_set_id": None,
                                  "testfast_attestor_set_id": None},
        }
        # The shadow forks are ready (R8; test_release_rule_r8_shadow_fork).
        doc["main"]["vault_branch_id"] = "6d5b7a31"
        doc["test"]["slow"].update(vault_branch_id="e1f1cc08", shadow_branch_id="57a24d5d", shadow_split_height=3100000)
        doc["test"]["legacy"].update(vault_branch_id="6d5b7a31", shadow_branch_id="35706728", shadow_split_height=3100000)
        self.assertEqual(vp.release_problems(doc), [])
        doc["main"]["vault_activation_height"] = "NO_ACTIVATION_HEIGHT"
        self.assertTrue(any(p.startswith("R1:") for p in vp.release_problems(doc)))
        doc["main"]["vault_activation_height"] = 3300000
        doc["yellowback_params"]["main_attestor_set_id"] = "0" * 64
        self.assertTrue(any(p.startswith("R2:") for p in vp.release_problems(doc)))
        doc["yellowback_params"]["main_attestor_set_id"] = att
        doc["main"]["vault_protocol_version"] = 270013
        self.assertTrue(any(p.startswith("R3:") for p in vp.release_problems(doc)))
        doc["main"]["vault_protocol_version"] = 270200
        doc["version"]["PROTOCOL_VERSION"] = 270013
        self.assertTrue(any(p.startswith("R4:") for p in vp.release_problems(doc)))
        doc["version"]["PROTOCOL_VERSION"] = 270200
        doc["version"]["MIN_PEER_PROTO_VERSION"] = 270200
        self.assertTrue(any(p.startswith("R5:") for p in vp.release_problems(doc)))
        doc["version"]["MIN_PEER_PROTO_VERSION"] = 270013
        doc["main"]["pq_falcon_height"] = 1
        self.assertTrue(any(p.startswith("R6:") for p in vp.release_problems(doc)))
        doc["main"]["pq_falcon_height"] = 0
        # R7 per testnet profile: a Vault height comes with that network's own YED set; legacy never has one.
        doc["test"]["fast"]["vault_activation_height"] = 100
        self.assertTrue(any(p.startswith("R7: testnet-yb-fast") for p in vp.release_problems(doc)))
        doc["yellowback_params"]["test_attestor_set_id"] = att   # slow's set does not serve fast
        self.assertTrue(any(p.startswith("R7: testnet-yb-fast") for p in vp.release_problems(doc)))
        self.assertTrue(any(p.startswith("R7: testnet-yb-slow") for p in vp.release_problems(doc)))
        doc["yellowback_params"]["testfast_attestor_set_id"] = att
        doc["test"]["slow"]["vault_activation_height"] = 200
        self.assertEqual(vp.release_problems(doc), [])
        doc["test"]["legacy"]["vault_activation_height"] = 300
        self.assertTrue(any(p.startswith("R7: testnet-legacy") for p in vp.release_problems(doc)))
        doc["test"]["legacy"]["vault_activation_height"] = "NO_ACTIVATION_HEIGHT"
        self.assertEqual(vp.release_problems(doc), [])

    def test_release_rule_r8_shadow_fork(self):
        att = "ab" * 32
        net = {"vault_protocol_version": 270200, "vault_activation_height": "NO_ACTIVATION_HEIGHT",
               "pq_falcon_height": 0, "vault_min_set_maturity": 16128, "vault_branch_id": "6d5b7a31"}
        doc = {
            "version": {"PROTOCOL_VERSION": 270200, "MIN_PEER_PROTO_VERSION": 170002},
            "main": dict(net, vault_activation_height=3300000),
            "test": {"fast": dict(net),
                     "slow": dict(net, vault_branch_id="e1f1cc08", shadow_branch_id="57a24d5d",
                                  shadow_split_height=3100000),
                     "legacy": dict(net, shadow_branch_id="35706728", shadow_split_height=3100000)},
            "yellowback_params": {"main_attestor_set_id": att, "test_attestor_set_id": None,
                                  "testfast_attestor_set_id": None},
        }
        self.assertEqual(vp.release_problems(doc), [])
        # An unset H_S is "shadow fork not ready", for an rc too.
        doc["test"]["slow"]["shadow_split_height"] = "NO_ACTIVATION_HEIGHT"
        doc["test"]["legacy"]["shadow_split_height"] = "NO_ACTIVATION_HEIGHT"
        problems = vp.release_problems(doc)
        self.assertIn("R8: testnet-yb-slow shadow fork not ready: the split height H_S (TESTNET_SHADOW_SPLIT_HEIGHT) is unset",
                      problems)
        self.assertIn("R8: testnet-legacy shadow fork not ready: the split height H_S (TESTNET_SHADOW_SPLIT_HEIGHT) is unset",
                      problems)
        doc["test"]["slow"]["shadow_split_height"] = doc["test"]["legacy"]["shadow_split_height"] = 3100000
        # slow's Vault under mainnet's ID, or slow and legacy sharing a shadow ID: refused.
        doc["test"]["slow"]["vault_branch_id"] = "6d5b7a31"
        self.assertIn("R8: testnet-yb-slow must activate Vault under a branch ID of its own, not mainnet's",
                      vp.release_problems(doc))
        doc["test"]["slow"]["vault_branch_id"] = "e1f1cc08"
        doc["test"]["legacy"]["shadow_branch_id"] = "57a24d5d"
        self.assertIn("R8: testnet-yb-slow and testnet-legacy must not share a shadow branch ID", vp.release_problems(doc))
        doc["test"]["legacy"]["shadow_branch_id"] = "35706728"
        del doc["test"]["legacy"]["shadow_branch_id"]
        self.assertIn("R8: testnet-legacy must sign after H_S under a branch ID of its own", vp.release_problems(doc))


if __name__ == "__main__":
    unittest.main()
