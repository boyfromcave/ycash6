# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Unit tests of the network profiles (offline, standard library only).

    python3 -m unittest contrib/yellowback/profiles/test_ybprofile.py

Each profile must parse, agree with tomllib where Python has it, and agree with the values this
tree compiles in (src/chainparams.cpp, src/chainparamsbase.cpp, src/yellowback/params.cpp): a
profile is a mirror of the chain parameters for the tools, never a second source of them.
"""

import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE)
import ybprofile  # noqa: E402

try:
    import tomllib
except ImportError:          # Python 3.10
    tomllib = None

CLASSES = {"regtest": "CRegTestParams", "testnet-yb-fast": "CTestNetFastParams",
           "testnet-yb-slow": "CTestNetSlowParams", "testnet-legacy": "CTestNetLegacyParams"}


def read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as f:
        return f.read()


def class_body(source, name):
    """The text of `class <name> ... {` up to the next top-level `};`."""
    m = re.search(r"^class %s\b.*?^};" % name, source, re.S | re.M)
    if not m:
        raise AssertionError("class %s not found" % name)
    return m.group(0)


def magic_of(body):
    found = dict(re.findall(r"pchMessageStart\[(\d)\] = 0x([0-9a-f]{2});", body))
    return "".join(found[str(i)] for i in range(4)) if len(found) == 4 else None


class ParserTest(unittest.TestCase):
    def test_subset(self):
        data = ybprofile.parse('a = "x # y"  # c\nb = 3\n[t]\nc = [1, 2]\nd = ["p", "q"]\ne = true\nf = []\n')
        self.assertEqual(data, {"a": "x # y", "b": 3, "t": {"c": [1, 2], "d": ["p", "q"], "e": True, "f": []}})

    def test_refusals(self):
        for text in ("a = 1\na = 2\n", "[t]\n[t]\n", "a = 1.5\n", "a = [1,\n", "a = 'x'\n", "a\n", "[t.u]\n", 'a = "x\\"y"\n'):
            with self.assertRaises(ybprofile.ProfileError, msg=text):
                ybprofile.parse(text)

    def test_unknown_network(self):
        with self.assertRaises(ybprofile.ProfileError):
            ybprofile.load("testnet")

    def test_entrypoint_names(self):
        self.assertEqual(ybprofile.network_name("testnet", "slow"), "testnet-yb-slow")
        self.assertEqual(ybprofile.network_name("regtest", "fast"), "regtest")
        self.assertIsNone(ybprofile.network_name("testnet", ""))
        self.assertIsNone(ybprofile.network_name("mainnet"))


class ProfileTest(unittest.TestCase):
    def setUp(self):
        self.chainparams = read("src", "chainparams.cpp")
        self.base = read("src", "chainparamsbase.cpp")
        self.yed = read("src", "yellowback", "params.cpp")

    def test_every_profile_parses_and_matches_tomllib(self):
        for network in ybprofile.NETWORKS:
            profile = ybprofile.load(network)
            if tomllib:
                with open(os.path.join(HERE, network + ".toml"), "rb") as f:
                    self.assertEqual(tomllib.load(f), {k: v for k, v in profile.items() if k != "vault_height"}, network)
            for table in ("node", "mining", "heights", "yellowback", "prefix", "seeds", "endpoints"):
                self.assertIsInstance(profile[table], dict, (network, table))
            self.assertEqual(sorted(profile), sorted(ybprofile.load("regtest")), network)   # one schema

    def test_node_values_match_the_compiled_ones(self):
        testnet = class_body(self.chainparams, "CTestNetParams")
        for network, cls in CLASSES.items():
            p, body = ybprofile.load(network), class_body(self.chainparams, cls)
            self.assertEqual(magic_of(body), p["node"]["magic"], network)
            self.assertIn("nDefaultPort = %d;" % p["node"]["p2p_port"], body, network)
            vault = re.search(r"UPGRADE_VAULT\]\.nActivationHeight =\s*([^;]+);", body)
            if network == "regtest":       # a -nuparams flag there: the functional framework's height
                self.assertIn("VAULT_ACTIVATION = %d\n" % p["heights"]["vault"], read("qa", "rpc-tests", "test_framework", "yellowback_util.py"))
            elif p["heights"]["vault"]:
                self.assertEqual(vault.group(1).strip(), str(p["heights"]["vault"]), network)
            elif network != "regtest":
                self.assertIn("NO_ACTIVATION_HEIGHT", vault.group(1), network)
            if network == "regtest":
                self.assertIn('strDataDir = "regtest"', self.base)
                self.assertIn("nRPCPort = %d;" % p["node"]["rpc_port"], class_body(self.base, "CBaseRegTestParams"))
                self.assertIn('hashGenesisBlock == uint256S("0x%s")' % p["node"]["genesis"], body)
                self.assertEqual(p["node"]["args"], ["-regtest"])
                continue
            self.assertIn('(%d, "%s")' % (p["node"]["rpc_port"], p["node"]["datadir"]), self.base, network)
            self.assertEqual(p["node"]["args"], ["-testnet", "-testnetprofile=" + p["testnet_profile"]])
            self.assertIn('strTestnetProfile = "%s"' % p["testnet_profile"], body)
            self.assertIn('hashGenesisBlock == uint256S("0x%s")' % p["node"]["genesis"], testnet)
            self.assertIn("UPGRADE_YCASH].nActivationHeight = %d;" % p["heights"]["ycash_fork"], testnet)
            self.assertIn('(%d, uint256S("0x%s"))' % (p["prefix"]["last_height"], p["prefix"]["last_hash"]), testnet)
            self.assertEqual(p["prefix"]["last_height"] + 1, p["heights"]["ycash_fork"])
            self.assertRegex(testnet, r"\b%d,\s*// \* total number of transactions" % p["prefix"]["chaintx"])
            for item in p["prefix"]["checkpoints"]:
                height, hash_ = item.split(":")
                self.assertRegex(hash_, r"^[0-9a-f]{64}$")
                self.assertIn(hash_, testnet, (network, height))
            n, k = re.search(r"const size_t N = (\d+), K = (\d+);", testnet).groups()
            self.assertEqual(p["mining"]["equihash_prefix"], [int(n), int(k)])
            if p["yellowback"]["set_maturity"]:
                self.assertIn("nVaultMinSetMaturity = %d;" % p["yellowback"]["set_maturity"], body, network)

    def test_yellowback_values_match_the_module(self):
        def value(section, field):
            m = re.search(r"\b\w\.%s\s*=\s*(\d+)" % field, section)
            return int(m.group(1))
        main = self.yed[self.yed.index("void SetCommon"):self.yed.index("void SetTestnet")]
        fast = self.yed[self.yed.index("const Params& TestFastParams()"):]
        fast = fast[:fast.index("return f;")]
        regtest = self.yed[self.yed.index("Params RegtestParams("):]
        for network, section in (("testnet-yb-fast", fast), ("testnet-yb-slow", main), ("regtest", regtest)):
            y = ybprofile.load(network)["yellowback"]
            self.assertTrue(y["enabled"])
            if network != "testnet-yb-fast" or "bondMaturity" in section:
                self.assertEqual(y["set_maturity"], value(section, "bondMaturity"), network)
            livemin = value(section, "attestorLivenessMin") if "attestorLivenessMin" in section else value(main, "attestorLivenessMin")
            self.assertGreaterEqual(y["liveness_window"], livemin, network)
            floor = value(section, "bondMinFloorZat") if "bondMinFloorZat" in section else value(main, "bondMinFloorZat")
            if network == "regtest":
                self.assertEqual(y["house_bond_yec"], value(section, "bondMinCapZat"))
            else:
                self.assertEqual(y["house_bond_yec"], floor, network)
            self.assertLessEqual(y["house_seats"], 15)
        self.assertFalse(ybprofile.load("testnet-legacy")["yellowback"]["enabled"])
        self.assertIsNone(ybprofile.load("testnet-legacy")["vault_height"])
        self.assertIsNone(ybprofile.load("testnet-yb-slow")["vault_height"])
        self.assertEqual(ybprofile.load("testnet-yb-fast")["yellowback"]["house_seats"], 7)   # T-5
        self.assertEqual(ybprofile.load("testnet-yb-slow")["yellowback"]["house_seats"], 3)   # T-5


if __name__ == "__main__":
    unittest.main()
