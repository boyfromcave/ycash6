#!/usr/bin/env python3
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


def reader(chainparams, att="ab" * 32):
    files = {"src/chainparams.cpp": chainparams, "src/consensus/params.h": PARAMS_H,
             "src/version.h": VERSION_H, "src/yellowback/params.cpp": PARAMS_CPP % att}
    return files.__getitem__


NO = "Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT"


class VaultParams(unittest.TestCase):
    def test_testnet_before_mainnet_is_not_a_first_match(self):
        cp = klass("CTestNetParams", "11") + klass("CMainParams", NO) + klass("CRegTestParams", NO, "        consensus.nVaultMinSetMaturity = 2;\n")
        r = vp.extract(reader(cp))
        self.assertEqual(r["main"]["vault_activation_height"], "NO_ACTIVATION_HEIGHT")
        self.assertEqual(r["test"]["vault_activation_height"], 11)
        self.assertEqual(r["regtest"]["vault_min_set_maturity"], 2)
        self.assertEqual(r["main"]["vault_min_set_maturity"], 16128)

    def test_continuation_line_height(self):
        cp = klass("CMainParams", "3300000") + klass("CTestNetParams", NO) + klass("CRegTestParams", NO)
        self.assertEqual(vp.extract(reader(cp))["main"]["vault_activation_height"], 3300000)

    def test_regtest_setter_outside_constructor_is_ignored(self):
        cp = klass("CMainParams", NO) + klass("CTestNetParams", NO) + klass("CRegTestParams", NO)
        self.assertEqual(vp.extract(reader(cp))["regtest"]["pq_falcon_height"], "NO_ACTIVATION_HEIGHT")

    def test_duplicate_assignment_fails_closed(self):
        dup = "        consensus.vUpgrades[Consensus::UPGRADE_VAULT].nProtocolVersion = 1;\n"
        cp = klass("CMainParams", NO, dup) + klass("CTestNetParams", NO) + klass("CRegTestParams", NO)
        with self.assertRaises(vp.ParseError):
            vp.extract(reader(cp))

    def test_missing_class_fails_closed(self):
        with self.assertRaises(vp.ParseError):
            vp.extract(reader(klass("CMainParams", NO)))

    def test_compare_names_the_field(self):
        base = klass("CMainParams", NO) + klass("CTestNetParams", NO) + klass("CRegTestParams", NO)
        a = vp.extract(reader(base))
        b = vp.extract(reader(base.replace("= 270013;", "= 270200;", 1)))
        self.assertEqual(vp.compare(a, a), [])
        self.assertEqual(len(vp.compare(a, b)), 1)
        self.assertIn("main.vault_protocol_version", vp.compare(a, b)[0])
        c = vp.extract(reader(base, att="cd" * 32))
        self.assertTrue(any("yellowback_params.main_attestor_set_id" in x for x in vp.compare(a, c)))

    def test_min_peer_difference_is_not_compared(self):
        base = klass("CMainParams", NO) + klass("CTestNetParams", NO) + klass("CRegTestParams", NO)
        a = vp.extract(reader(base))
        b = dict(a, version=dict(a["version"], MIN_PEER_PROTO_VERSION=270013))
        self.assertEqual(vp.compare(a, b), [])

    def test_real_tree(self):
        root = os.path.join(HERE, "..")

        def read(p):
            with open(os.path.join(root, p), encoding="utf-8") as f:
                return f.read()

        r = vp.extract(read)
        for net in ("main", "test", "regtest"):
            self.assertEqual(r[net]["vault_protocol_version"], r["version"]["PROTOCOL_VERSION"])
        self.assertEqual(r["main"]["pq_falcon_height"], 0)
        self.assertEqual(r["regtest"]["vault_min_set_maturity"], 2)
        self.assertEqual(r["main"]["vault_min_set_maturity"], 16128)


if __name__ == "__main__":
    unittest.main()
