// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Yugen format (doc/yugen-node.md): the spec's transfer vectors decode or are refused as the
// reference does, and a Yugen transaction round-trips byte for byte.

#include <gtest/gtest.h>

#include "hash.h"
#include "primitives/transaction.h"
#include "primitives/yugen.h"
#include "consensus/validation.h"
#include "yugen/leaf.h"
#include "streams.h"
#include "util/strencodings.h"
#include "version.h"

#include <univalue.h>

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <sstream>

TEST(Yugen, TransferVectors) {
    const char* path = std::getenv("YUGEN_TRANSFER_VECTORS");   // yugen-spec d25a89c vectors/transfer.json
    if (!path) GTEST_SKIP() << "YUGEN_TRANSFER_VECTORS not set";
    std::ifstream f(path);
    std::stringstream ss; ss << f.rdbuf();
    UniValue doc;
    ASSERT_TRUE(doc.read(ss.str()));
    const UniValue& v = doc["vectors"];
    int accepted = 0, refused = 0;
    for (size_t i = 0; i < v.size(); i++) {
        const std::string kind = v[i]["kind"].get_str();
        if (kind == "transfer-hash-binds-48") continue;
        auto bytes = ParseHex(v[i]["encoding"].get_str());
        std::string why;
        auto t = yugen::Decode(bytes, why);
        if (kind == "decode-reject") {
            EXPECT_FALSE(t.has_value()) << v[i]["name"].get_str();
            refused++;
        } else {
            ASSERT_TRUE(t.has_value()) << kind << " " << why;
            if (v[i].exists("fee")) EXPECT_EQ(std::to_string(t->Fee()), v[i]["fee"].get_str());
            accepted++;
        }
    }
    EXPECT_EQ(accepted, 13);
    EXPECT_EQ(refused, 16);
}

TEST(Yugen, TransactionRoundTrip) {
    CMutableTransaction mtx;
    mtx.fOverwintered = true;
    mtx.nVersion = SAPLING_TX_VERSION;
    mtx.nVersionGroupId = YUGEN_VERSION_GROUP_ID;
    mtx.nExpiryHeight = 0;
    mtx.yugen.transfer.assign(232, 7);
    mtx.yugen.proofA.assign(1000, 1);
    mtx.yugen.proofB.assign(70000, 2);
    CDataStream s1(SER_NETWORK, PROTOCOL_VERSION);
    s1 << mtx;
    std::vector<unsigned char> b1(s1.begin(), s1.end());
    CTransaction tx;
    s1 >> tx;
    EXPECT_EQ(tx.yugen.transfer, mtx.yugen.transfer);
    EXPECT_EQ(tx.yugen.proofB.size(), 70000u);
    CDataStream s2(SER_NETWORK, PROTOCOL_VERSION);
    s2 << tx;
    EXPECT_EQ(std::vector<unsigned char>(s2.begin(), s2.end()), b1);
    // A Sapling v4 transaction carries no Yugen field.
    mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    CDataStream s3(SER_NETWORK, PROTOCOL_VERSION);
    s3 << mtx;
    EXPECT_EQ(s3.size() + 1 + 232 + 3 + 1000 + 5 + 70000, b1.size());
}

TEST(Yugen, ResolveAnchor) {
    // Activation 4096 as in the reference; block 4100 may use 4096 only.
    EXPECT_EQ(yugen::ResolveAnchor((4096 / 16) & 0xff, 4100, 4096), 4096);
    EXPECT_EQ(yugen::ResolveAnchor((4096 / 16) & 0xff, 4096, 4096), -1);   // h - ha >= 1
    EXPECT_EQ(yugen::ResolveAnchor((4112 / 16) & 0xff, 4200, 4096), 4112);
    EXPECT_EQ(yugen::ResolveAnchor((4096 / 16) & 0xff, 4096 + 97, 4096), -1);   // window 96
}

// Review M-4, decision N-D7: the txid does not cover the proofs; it covers the transfer.
TEST(Yugen, TxidExcludesProofs) {
    CMutableTransaction mtx;
    mtx.fOverwintered = true;
    mtx.nVersion = SAPLING_TX_VERSION;
    mtx.nVersionGroupId = YUGEN_VERSION_GROUP_ID;
    mtx.yugen.transfer.assign(232, 7);
    mtx.yugen.proofA.assign(1000, 1);
    mtx.yugen.proofB.assign(70000, 2);
    CTransaction a(mtx);
    mtx.yugen.proofB.assign(69999, 3);
    CTransaction b(mtx);
    EXPECT_EQ(a.GetHash(), b.GetHash());
    mtx.yugen.proofA.clear();
    mtx.yugen.proofB.clear();
    CTransaction c(mtx);   // the bundle form: the hash of the whole serialization, as before
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << c;
    EXPECT_EQ(c.GetHash(), Hash(ss.begin(), ss.end()));
    EXPECT_EQ(a.GetHash(), c.GetHash());
    mtx.yugen.transfer[5] ^= 1;
    CTransaction d(mtx);
    EXPECT_NE(d.GetHash(), c.GetHash());
}

// Review L-3: |vb| + fee beyond MAX_MONEY is refused by structure, before any value sum.
TEST(Yugen, ValueBalanceRange) {
    auto make = [](int64_t vb) {
        CMutableTransaction mtx;
        mtx.fOverwintered = true;
        mtx.nVersion = SAPLING_TX_VERSION;
        mtx.nVersionGroupId = YUGEN_VERSION_GROUP_ID;
        std::vector<unsigned char> b(yugen::FIXED_LEN, 0);
        b[2] = yugen::VB | yugen::LEAFFEE;
        b[4] = 1;   // nf_1 != nf_2
        uint64_t u = (uint64_t)vb;
        for (int i = 0; i < 8; i++) b.push_back((u >> (8 * i)) & 0xff);
        mtx.yugen.transfer = b;
        mtx.yugen.proofA.assign(1, 1);
        mtx.yugen.proofB.assign(1, 2);
        return CTransaction(mtx);
    };
    const int64_t fee = yugen::BASE_FEE + yugen::LEAF_PROOF_FEE;
    CValidationState s1, s2, s3;
    EXPECT_FALSE(yugen::CheckLeafTransferStructure(make(MAX_MONEY), s1));
    EXPECT_EQ(s1.GetRejectReason(), "bad-yugen-vb-range");
    EXPECT_FALSE(yugen::CheckLeafTransferStructure(make(-MAX_MONEY), s2));
    EXPECT_EQ(s2.GetRejectReason(), "bad-yugen-vb-range");
    EXPECT_TRUE(yugen::CheckLeafTransferStructure(make(MAX_MONEY - fee), s3)) << s3.GetRejectReason();
}

// F-4 (559025d04): the node's PQ script recheck (RecheckPQScripts, run by the miner's template trial and the
// mempool recheck) accepts a Yugen-group v4 transaction (ZIP-243 + hashYugen, N-TX) whose PQ input is correctly
// signed. Before the fix it answered "non-v4 transaction (R-A3)": PQ-funded Yugen deposits were relayed but never
// mined. A bad signature still fails at the script, and a v5 transaction is still refused under R-A3.
#include "chainparams.h"
#include "coins.h"
#include "consensus/upgrades.h"
#include "crypto/pq/scheme.h"
#include "crypto/pq/sign.h"
#include "script/interpreter.h"
#include "vault/node.h"
#include "vault/template.h"
#include "yellowback/params.h"
#include "yellowback/script.h"
#include "yellowback/state.h"
#include "yellowback/view.h"

TEST(Yugen, PQRecheckAcceptsYugenGroup) {
    SelectParams(CBaseChainParams::REGTEST);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_OVERWINTER, 1);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_SAPLING, 1);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_VAULT, 10);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_YUGEN, 16);
    const Consensus::Params& params = Params().GetConsensus();
    const int height = 20;
    const uint32_t branch = CurrentEpochBranchId(height, params);
    ASSERT_EQ(branch, 0x59474e30u);

    const uint8_t SLH = pq::SCHEME_SLH_DSA_SHA2_128S;
    std::vector<unsigned char> pk, sk;
    ASSERT_TRUE(pq::KeyGen(SLH, std::vector<unsigned char>(pq::SeedSize(SLH), 0x5a), pk, sk));
    const uint256 kh = pq::KeyHash(SLH, pk);
    const CScript spk = CScript() << std::vector<unsigned char>(kh.begin(), kh.end()) << (int64_t)SLH << OP_CHECKPQSIG;
    const CAmount amount = 500000;

    CCoinsViewDummy dummy;
    CCoinsViewCache view(&dummy);
    CMutableTransaction fund;
    fund.fOverwintered = true;
    fund.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    fund.nVersion = SAPLING_TX_VERSION;
    fund.vin.resize(1);
    fund.vin[0].prevout = COutPoint(uint256S("03"), 0);
    fund.vout.push_back(CTxOut(amount, spk));
    const CTransaction fundTx(fund);
    view.ModifyCoins(fundTx.GetHash())->FromTx(fundTx, 1);

    auto build = [&](uint32_t group, bool goodSig) {
        CMutableTransaction m;
        m.fOverwintered = true;
        m.nVersionGroupId = group;
        m.nVersion = group == ZIP225_VERSION_GROUP_ID ? ZIP225_TX_VERSION : SAPLING_TX_VERSION;
        if (group == ZIP225_VERSION_GROUP_ID) m.nConsensusBranchId = branch;
        m.nExpiryHeight = 100;
        m.vin.resize(1);
        m.vin[0].prevout = COutPoint(fundTx.GetHash(), 0);
        m.vout.push_back(CTxOut(amount - 30000, CScript() << OP_TRUE));
        if (group == ZIP225_VERSION_GROUP_ID) return CTransaction(m);
        const CTransaction unsigned_(m);
        const PrecomputedTransactionData txdata(unsigned_, {CTxOut(amount, spk)});
        const uint256 sighash = SignatureHash(spk, unsigned_, 0, SIGHASH_ALL, amount, branch, txdata);
        std::vector<unsigned char> sig;
        EXPECT_TRUE(pq::SignWithEntropy(SLH, sk, sighash, {}, sig));
        if (!goodSig) sig[0] ^= 1;
        sig.push_back(SIGHASH_ALL);
        CScript ss;
        for (const auto* d : {&sig, &pk}) {
            size_t n = 0;
            for (size_t i = 0; i < d->size(); i += pq::MAX_CHUNK, n++)
                ss << std::vector<unsigned char>(d->begin() + i, d->begin() + std::min(d->size(), i + pq::MAX_CHUNK));
            ss << (int64_t)n;
        }
        m.vin[0].scriptSig = ss;
        return CTransaction(m);
    };
    const std::string R_A3 = "non-v4 transaction (R-A3)";
    // the Yugen group, signed under the Yugen branch: accepted by the recheck (mempool and template forms)
    EXPECT_EQ(vault::RecheckPQScripts(build(YUGEN_VERSION_GROUP_ID, true), view, height, nullptr, params), std::nullopt);
    EXPECT_EQ(vault::RecheckPQScripts(build(YUGEN_VERSION_GROUP_ID, true), view, height, nullptr, params, true), std::nullopt);
    // the same group with a bad signature: refused by the script, never waved through
    auto bad = vault::RecheckPQScripts(build(YUGEN_VERSION_GROUP_ID, false), view, height, nullptr, params);
    ASSERT_TRUE(bad.has_value());
    EXPECT_NE(*bad, R_A3);
    // a plain Sapling v4 signed under the Yugen branch passes too (unchanged); v5 still refused (R-A3)
    EXPECT_EQ(vault::RecheckPQScripts(build(SAPLING_VERSION_GROUP_ID, true), view, height, nullptr, params), std::nullopt);
    auto v5 = vault::RecheckPQScripts(build(ZIP225_VERSION_GROUP_ID, true), view, height, nullptr, params);
    ASSERT_TRUE(v5.has_value());
    EXPECT_EQ(*v5, R_A3);

    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_YUGEN, Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_VAULT, Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_SAPLING, Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_OVERWINTER, Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT);
    SelectParams(CBaseChainParams::MAIN);
}

// Decision N-D8: a Yugen transaction's kind is read from its transfer bytes (committed by the txid),
// never from the proof fields (not committed): emptying a leaf's proofs or adding one to a bundle
// leaves the kind, and the refusal is body corruption (a replaceable body), not a verdict.
static CMutableTransaction YugenTx(const std::vector<unsigned char>& transfer, size_t proofA, size_t proofB)
{
    CMutableTransaction mtx;
    mtx.fOverwintered = true;
    mtx.nVersion = SAPLING_TX_VERSION;
    mtx.nVersionGroupId = YUGEN_VERSION_GROUP_ID;
    mtx.yugen.transfer = transfer;
    mtx.yugen.proofA.assign(proofA, 1);
    mtx.yugen.proofB.assign(proofB, 2);
    return mtx;
}

static std::vector<unsigned char> MinimalBundle()
{
    // §15.1: bundle_version 0x80 (spec 0.5.3), one anchor entry, an empty payee table, one leaf node
    // of one transfer (k = 1: two 3-byte fields), one 232-byte transfer, the two proof hashes.
    std::vector<unsigned char> b{yugen::BUNDLE_VERSION, 0x01};
    b.insert(b.end(), 129, 0x00);
    b.insert(b.end(), {0x00, 0x00});
    b.insert(b.end(), {0x00, 0x01});
    b.insert(b.end(), 6, 0x00);
    std::vector<unsigned char> t(yugen::FIXED_LEN, 0);
    t[4] = 1;   // nf_1 != nf_2
    b.insert(b.end(), t.begin(), t.end());
    b.insert(b.end(), 64, 0x00);
    return b;
}

TEST(Yugen, KindFromCommittedBytes) {
    // A leaf of fee class 0 begins with 0x00 (a bundle with 0x80 since spec 0.5.3, §15.1).
    std::vector<unsigned char> leaf(yugen::FIXED_LEN, 0);
    leaf[1] = 3;   // anchor slot 3, as n_anchors would read
    leaf[2] = yugen::LEAFFEE;
    leaf[4] = 1;
    const CTransaction honestLeaf(YugenTx(leaf, 10, 10));
    const CTransaction strippedLeaf(YugenTx(leaf, 0, 0));
    EXPECT_FALSE(honestLeaf.IsYugenBundle());
    EXPECT_FALSE(strippedLeaf.IsYugenBundle());
    EXPECT_EQ(honestLeaf.GetHash(), strippedLeaf.GetHash());
    CValidationState s1;
    EXPECT_FALSE(yugen::CheckLeafTransferStructure(strippedLeaf, s1));
    EXPECT_EQ(s1.GetRejectReason(), "bad-yugen-proof-missing");
    EXPECT_TRUE(s1.CorruptionPossible());

    const auto bundle = MinimalBundle();
    const CTransaction honestBundle(YugenTx(bundle, 0, 0));
    const CTransaction paddedBundle(YugenTx(bundle, 1, 0));
    EXPECT_TRUE(honestBundle.IsYugenBundle());
    EXPECT_TRUE(paddedBundle.IsYugenBundle());
    EXPECT_EQ(honestBundle.GetHash(), paddedBundle.GetHash());
    CValidationState s2, s3;
    EXPECT_TRUE(yugen::CheckLeafTransferStructure(honestBundle, s2)) << s2.GetRejectReason();
    EXPECT_FALSE(yugen::CheckLeafTransferStructure(paddedBundle, s3));
    EXPECT_EQ(s3.GetRejectReason(), "bad-yugen-bundle-inline-proofs");
    EXPECT_TRUE(s3.CorruptionPossible());
}

// Spec 0.5.3 §15.1: the kind is the first byte of the Yugen field. 0x80 is a bundle, whatever
// follows (a field that does not parse is a malformed bundle, not a leaf); every other first byte
// is a leaf transfer, including a 0.5.2-format bundle (first byte 0x00) that parses as §15.1.
TEST(Yugen, KindMarkerIsFirstByte) {
    EXPECT_EQ(yugen::BUNDLE_VERSION, 0x80);
    EXPECT_FALSE(yugen::IsBundleEncoding({}));
    for (int first = 0; first < 256; first++) {
        std::vector<unsigned char> b(yugen::FIXED_LEN, 0);
        b[0] = (unsigned char)first;
        EXPECT_EQ(yugen::IsBundleEncoding(b), first == 0x80) << "first byte " << first;
    }
    EXPECT_TRUE(yugen::IsBundleEncoding({0x80}));   // truncated: still a bundle, refused as one

    auto bundle = MinimalBundle();
    std::vector<uint8_t> slots;
    std::vector<yugen::Transfer> ts;
    std::string why;
    EXPECT_TRUE(yugen::IsBundleEncoding(bundle));
    EXPECT_TRUE(yugen::DecodeBundleTransfers(bundle, ts, slots, why)) << why;
    EXPECT_EQ(ts.size(), 1u);

    // The same bytes with the 0.5.2 version byte: a leaf by kind, and no bundle decoder takes them.
    bundle[0] = 0x00;
    EXPECT_FALSE(yugen::IsBundleEncoding(bundle));
    ts.clear(); slots.clear();
    EXPECT_FALSE(yugen::DecodeBundleTransfers(bundle, ts, slots, why));
    EXPECT_EQ(why, "bundle-encoding");
    const CTransaction oldBundle(YugenTx(bundle, 10, 10));
    EXPECT_FALSE(oldBundle.IsYugenBundle());

    // A leaf whose bytes would have parsed as a bundle under the 0.5.2 structural reading stays a
    // leaf: the first byte is its fee class.
    std::vector<unsigned char> leaf(yugen::FIXED_LEN, 0);
    leaf[2] = yugen::LEAFFEE;
    leaf[4] = 1;
    for (uint8_t fc = 0; fc <= 3; fc++) {
        leaf[0] = fc;
        EXPECT_FALSE(CTransaction(YugenTx(leaf, 10, 10)).IsYugenBundle()) << "fee class " << int(fc);
    }
}

// The kind of every spec vector (yugen-spec 0.5.4 77af005: vectors/transfer.json, vectors/bundle.json).
TEST(Yugen, KindOfSpecVectors) {
    const char* tp = std::getenv("YUGEN_TRANSFER_VECTORS");
    const char* bp = std::getenv("YUGEN_BUNDLE_VECTORS");
    if (!tp || !bp) GTEST_SKIP() << "YUGEN_TRANSFER_VECTORS or YUGEN_BUNDLE_VECTORS not set";
    auto load = [](const char* path) {
        std::ifstream f(path);
        std::stringstream ss; ss << f.rdbuf();
        UniValue doc;
        EXPECT_TRUE(doc.read(ss.str()));
        return doc["vectors"];
    };
    int leaves = 0, bundles = 0;
    const UniValue tv = load(tp);
    for (size_t i = 0; i < tv.size(); i++) {
        if (!tv[i].exists("encoding") || tv[i]["kind"].get_str() == "decode-reject") continue;
        auto bytes = ParseHex(tv[i]["encoding"].get_str());
        std::string why;
        if (!yugen::Decode(bytes, why)) continue;
        EXPECT_FALSE(yugen::IsBundleEncoding(bytes)) << "transfer vector " << i;
        leaves++;
    }
    const UniValue bv = load(bp);
    for (size_t i = 0; i < bv.size(); i++) {
        if (bv[i]["kind"].get_str() != "bundle") continue;
        EXPECT_TRUE(yugen::IsBundleEncoding(ParseHex(bv[i]["encoding"].get_str()))) << bv[i]["name"].get_str();
        bundles++;
    }
    EXPECT_EQ(leaves, 13);
    EXPECT_EQ(bundles, 18);
}

// The Yugen signature hash (ZIP-243 with hashYugen after the value balance, doc/yugen-node.md
// N-TX) against an independent vector: the transfer is yugen-spec 0.5.3 (4adaaba; transfer vectors as 0.5.2)
// vectors/transfer.json vector 0; the expected digest was computed with Python's hashlib.blake2b
// from the ZIP-243 field list, not with this code base or the wallet engine.
TEST(Yugen, SighashVector) {
    CMutableTransaction mtx = YugenTx(ParseHex(
        "00e8000015a02ec003d5258de9a0b0a017af7430f81a81253624fa9189c8ce927f6188862f2c0a8dd43404d11be216732bf4bb497555a4d107af"
        "0012e20b81609052634d6506392a06e5bc4158a0f0efbffae268aae06d77105d3590cc616210668919dc5ac2a3fde994c44a5547e3f94e1c29ef"
        "647e3724cf7f338bb95e3d6dcfdd1f0e362611ced8cece9aaa68606cba64bc159564f536142488d804faa2012fcb4c9a4e97e69f0b0fa58db6d5"
        "9965e687f3cf3e08e111251f3f552c2acc7ac4294c38102bf57facb117379b4b2cf3dd50eb2887dbef1373e7778e4f6145b5fa06d86bb479b9c9"),
        100, 200);
    mtx.nExpiryHeight = 100;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(uint256(std::vector<unsigned char>(32, 0x11)), 1);
    const auto p2pkh = [](unsigned char fill) {
        return CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, fill) << OP_EQUALVERIFY << OP_CHECKSIG;
    };
    mtx.vout.push_back(CTxOut(123456789, p2pkh(0x22)));
    const CScript scriptCode = p2pkh(0x33);
    const CAmount amount = 500000000;
    const CTransaction tx(mtx);
    const PrecomputedTransactionData txdata(tx, {CTxOut(amount, scriptCode)});
    const uint256 h = SignatureHash(scriptCode, tx, 0, SIGHASH_ALL, amount, 0x59474E30, txdata);
    EXPECT_EQ(HexStr(h.begin(), h.end()), "2f68e5b3f0946ba3df910dffd73d070b3a666728de53598dff0bef93d14df25f");
    // The proofs are not signed; the transfer is.
    mtx.yugen.proofA.assign(7, 9);
    const CTransaction tx2(mtx);
    EXPECT_EQ(SignatureHash(scriptCode, tx2, 0, SIGHASH_ALL, amount, 0x59474E30,
                            PrecomputedTransactionData(tx2, {CTxOut(amount, scriptCode)})), h);
    mtx.yugen.transfer[100] ^= 1;
    const CTransaction tx3(mtx);
    EXPECT_NE(SignatureHash(scriptCode, tx3, 0, SIGHASH_ALL, amount, 0x59474E30,
                            PrecomputedTransactionData(tx3, {CTxOut(amount, scriptCode)})), h);
}

// Review M-1: a leaf's transaction fields that neither its transfer hash nor a signature covers
// are fixed (doc/yugen-node.md N-D9): without VB, no transparent input or output; without a
// transparent input, nLockTime 0 and nExpiryHeight h_a + ANCHOR_WINDOW (what the wallet engine writes).
#include "main.h"

TEST(Yugen, LeafEnvelopeIsFixed) {
    SelectParams(CBaseChainParams::REGTEST);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_OVERWINTER, 1);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_SAPLING, 1);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_VAULT, 16);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_YUGEN, 32);
    const int h = 70, ha = 64;   // the anchor slot 4 resolves to 64 at 70
    auto leaf = [&](bool vb) {
        std::vector<unsigned char> b(yugen::FIXED_LEN, 0);
        b[1] = (ha / 16) & 0xff;
        b[2] = yugen::LEAFFEE | (vb ? yugen::VB : 0);
        b[4] = 1;
        if (vb) { const int64_t v = 50000; for (int i = 0; i < 8; i++) b.push_back((v >> (8 * i)) & 0xff); }
        CMutableTransaction m = YugenTx(b, 100, 100);
        m.nExpiryHeight = ha + yugen::ANCHOR_WINDOW;
        return m;
    };
    auto reason = [&](const CMutableTransaction& m) {
        CValidationState st;
        ContextualCheckTransaction(CTransaction(m), st, Params(), h, true);
        return st.GetRejectReason();
    };
    const std::set<std::string> envelope{"bad-yugen-leaf-transparent-without-vb", "bad-yugen-leaf-locktime", "bad-yugen-leaf-expiry"};
    CMutableTransaction honest = leaf(false);
    EXPECT_EQ(envelope.count(reason(honest)), 0u) << reason(honest);
    CMutableTransaction m = honest;
    m.vout.push_back(CTxOut(100000, CScript() << OP_TRUE));       // a relay pays itself the fee
    EXPECT_EQ(reason(m), "bad-yugen-leaf-transparent-without-vb");
    m = honest;
    m.vin.resize(1);
    m.vin[0].prevout = COutPoint(uint256S("05"), 0);
    EXPECT_EQ(reason(m), "bad-yugen-leaf-transparent-without-vb");
    m = honest;
    m.nLockTime = 1;
    EXPECT_EQ(reason(m), "bad-yugen-leaf-locktime");
    m = honest;
    m.nExpiryHeight = ha + yugen::ANCHOR_WINDOW + 1;
    EXPECT_EQ(reason(m), "bad-yugen-leaf-expiry");
    // A withdrawal (VB) carries the outputs its transfer hash binds; its envelope is still fixed.
    CMutableTransaction w = leaf(true);
    w.vout.push_back(CTxOut(50000, CScript() << OP_TRUE));
    EXPECT_EQ(envelope.count(reason(w)), 0u) << reason(w);
    w.nExpiryHeight = 0;
    EXPECT_EQ(reason(w), "bad-yugen-leaf-expiry");

    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_YUGEN, Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_VAULT, Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_SAPLING, Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_OVERWINTER, Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT);
    SelectParams(CBaseChainParams::MAIN);
}

// Review (low): bad-yugen-leaf-weight is body-replaceable only when the excess is in the proofs,
// which the txid does not cover; an excess in committed bytes is a verdict. (With each proof within
// its LEAF_PROOF_MAX and the rest within LEAF_BYTES_RESERVE the whole is within LEAF_RESERVE, so the
// proof-side excess is a guard.)
static CScript Filler(size_t n)
{
    const std::vector<unsigned char> b(n, OP_TRUE);
    return CScript(b.begin(), b.end());
}

TEST(Yugen, LeafWeightClass) {
    std::vector<unsigned char> b(yugen::FIXED_LEN, 0);
    b[2] = yugen::LEAFFEE | yugen::VB;
    b[4] = 1;
    const int64_t v = 50000;
    for (int i = 0; i < 8; i++) b.push_back((v >> (8 * i)) & 0xff);
    CMutableTransaction committed = YugenTx(b, 100, 100);
    committed.vout.push_back(CTxOut(50000, Filler(yugen::LEAF_BYTES_RESERVE + 1)));
    CValidationState s1;
    s1.SetMerkleRootChecked(); s1.SetBlockCommitmentsChecked();   // in a block whose body is pinned
    EXPECT_FALSE(yugen::CheckLeafTransferStructure(CTransaction(committed), s1));
    EXPECT_EQ(s1.GetRejectReason(), "bad-yugen-leaf-weight");
    EXPECT_FALSE(s1.CorruptionPossible());
    CMutableTransaction proofs = YugenTx(b, yugen::LEAF_PROOF_MAX_A, yugen::LEAF_PROOF_MAX_B);
    proofs.vout.push_back(CTxOut(50000, Filler(yugen::LEAF_BYTES_RESERVE - 2000)));
    CValidationState s2;
    s2.SetMerkleRootChecked(); s2.SetBlockCommitmentsChecked();
    // both proofs at their limits and committed bytes within the reserve: within W4
    EXPECT_TRUE(yugen::CheckLeafTransferStructure(CTransaction(proofs), s2)) << s2.GetRejectReason();
}

// Review M-2: the global budget of Yugen verifications for peers: a burst of one minute's tokens,
// then one token per 60/n seconds; 0 is no limit.
#include "yugen/state.h"

TEST(Yugen, PeerVerifyBudget) {
    yugen::VerifyBudget b;
    const int64_t t0 = 1000000000;
    int taken = 0;
    for (int i = 0; i < 20; i++) taken += b.Take(t0, 6, 1);
    EXPECT_EQ(taken, 6);
    EXPECT_FALSE(b.Take(t0 + 9 * 1000000, 6, 1));   // 9 s: 0.9 token
    EXPECT_TRUE(b.Take(t0 + 11 * 1000000, 6, 1));   // 11 s: 1.1 tokens
    EXPECT_FALSE(b.Take(t0 + 11 * 1000000, 6, 1));
    taken = 0;
    for (int i = 0; i < 20; i++) taken += b.Take(t0 + 3600 * 1000000LL, 6, 1);   // refilled to the cap, not beyond
    EXPECT_EQ(taken, 6);
    yugen::VerifyBudget unlimited;
    for (int i = 0; i < 100; i++) EXPECT_TRUE(unlimited.Take(t0, 0, 1));
}

// Round 3, finding 3: the budget is shared fairly. A peer flooding junk that reaches the helper takes
// its share of the minute's tokens while another peer waits, and no more: an honest peer asking every
// 20 s (AskFor-paced) gets through. With one global bucket the flood took every token.
TEST(Yugen, PeerVerifyBudgetFairShare) {
    yugen::VerifyBudget b;
    const int64_t t0 = 1000000000, S = 1000000;
    int honest = 0, junk = 0, asked = 0;
    for (int64_t t = 0; t < 600 * S; t += S / 10) {         // ten minutes, the flood asks ten times a second
        junk += b.Take(t0 + t, 6, 1);
        if (t % (20 * S) == 0) { asked++; honest += b.Take(t0 + t, 6, 2); }
    }
    EXPECT_EQ(asked, 30);
    EXPECT_GE(honest, 20);                                   // at least two in three get through
    EXPECT_LE(junk + honest, 6 + 60);                        // the budget itself is unchanged
    yugen::VerifyBudget alone;                               // a lone peer still gets the whole budget
    int taken = 0;
    for (int i = 0; i < 20; i++) taken += alone.Take(t0, 6, 7);
    EXPECT_EQ(taken, 6);
}

// Round 3, finding 3: a repeat offender's back-off doubles (10 s to 10 min) and starts again after a
// quiet 20 min.
TEST(Yugen, RefusalBackoffDoubles) {
    int n = 0;
    int64_t last = 0, t = 1000000000;
    const int64_t S = 1000000;
    std::vector<int64_t> got;
    for (int i = 0; i < 9; i++) { got.push_back((yugen::RefusalBackoff(n, last, t) - t) / S); t += S; }
    EXPECT_EQ(got, (std::vector<int64_t>{10, 20, 40, 80, 160, 320, 600, 600, 600}));
    t += 1201 * S;
    EXPECT_EQ((yugen::RefusalBackoff(n, last, t) - t) / S, 10);
}

// Round 3, finding 1: MAX_BLOCK_SIZE counts the block without its proof sidecar (W3 bounds both, in
// yugen::ConnectBlock), and a block message carries a W3-sized block and sidecar.
#include "main.h"
#include "net.h"
#include "proof_verifier.h"
#include "chainparams.h"
#include "util/system.h"
#include "util/time.h"
#include "consensus/merkle.h"

static CBlock FillerBlock(size_t blockBytes, size_t sidecarBytes)
{
    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vin[0].prevout.SetNull();
    cb.vin[0].scriptSig = CScript() << OP_1 << OP_1;
    cb.vout.resize(1);
    cb.vout[0].nValue = 0;
    CBlock block;
    block.nVersion = 4;
    block.nTime = GetTime();
    block.vtx.push_back(CTransaction(cb));
    const size_t base = ::GetSerializeSize(block, SER_DISK, PROTOCOL_VERSION);
    const std::vector<unsigned char> filler(blockBytes - base - 4, 0x51);
    cb.vout[0].scriptPubKey = CScript(filler.begin(), filler.end());
    block.vtx[0] = CTransaction(cb);
    if (sidecarBytes) block.vYugenProofs.push_back({uint256S("01"), {std::vector<unsigned char>(sidecarBytes, 7), {1}}});
    return block;
}

TEST(Yugen, BlockSizeExcludesSidecar) {
    SelectParams(CBaseChainParams::REGTEST);
    auto verifier = ProofVerifier::Disabled();
    CBlock block = FillerBlock(1990000, 800000);
    ASSERT_GT(::GetSerializeSize(block, SER_DISK, PROTOCOL_VERSION), 1980000u);
    ASSERT_LT(::GetSerializeSize(block, SER_DISK, PROTOCOL_VERSION), (size_t)MAX_BLOCK_SIZE);
    CDataStream net(SER_NETWORK, PROTOCOL_VERSION);
    net << block;
    ASSERT_GT(net.size(), (size_t)MAX_BLOCK_SIZE);           // the message is over 2 MB with the sidecar
    CValidationState state;
    EXPECT_TRUE(CheckBlock(block, state, Params(), verifier, false, false, false)) << state.GetRejectReason();
    CBlock big = FillerBlock(MAX_BLOCK_SIZE + 10, 0);
    CValidationState state2;
    EXPECT_FALSE(CheckBlock(big, state2, Params(), verifier, false, false, false));
    EXPECT_EQ(state2.GetRejectReason(), "bad-blk-length");
    // The message limit carries a block and sidecar at W3, with room for the framing.
    EXPECT_GE((size_t)MAX_PROTOCOL_MESSAGE_LENGTH, yugen::BLOCK_WEIGHT_MAX + 64 * 1024);
    SelectParams(CBaseChainParams::MAIN);
}

// Round 3, findings 2, 4 and 5: yugen::ConnectBlock against a stand-in helper (a shell script that
// answers root, regroot, verify and bundle), at activation 32: block 32 seeds the state, block 33
// is the block under test (its anchor slot 2 is block 32).
namespace {
struct YugenChain {
    fs::path dir;
    CBlock b0, b1;
    uint256 h0, h1;
    CBlockIndex i0, i1, i2;
    static constexpr int ACT = 32;
    explicit YugenChain(const char* verifyMode)
    {
        SelectParams(CBaseChainParams::REGTEST);
        UpdateNetworkUpgradeParameters(Consensus::UPGRADE_YUGEN, ACT);
        dir = fs::temp_directory_path() / fs::unique_path();
        fs::create_directories(dir);
        mapArgs["-datadir"] = dir.string();
        ClearDatadirCache();
        fs::path helper = dir / "fake-helper";
        {
            std::ofstream o(helper.string());
            o << "#!/bin/sh\n"
                 "echo \"$1\" >> \"$YUGEN_FAKE_LOG\"\n"
                 "case \"$1\" in\n"
                 "root) echo \"ROOT " << std::string(96, 'a') << "\" ;;\n"
                 "regroot) echo " << std::string(96, 'b') << " ;;\n"
                 "verify) [ \"$YUGEN_FAKE_VERIFY\" = fail ] && exit 1; echo ACCEPT ;;\n"
                 "bundle) echo \"ACCEPT {\\\"records\\\":[],\\\"stmt\\\":\\\"00\\\",\\\"transfers\\\":[$YUGEN_FAKE_TRANSFERS]}\" ;;\n"
                 "*) exit 1 ;;\n"
                 "esac\n";
        }
        fs::permissions(helper, fs::owner_all);
        mapArgs["-yugenverifier"] = helper.string();
        setenv("YUGEN_FAKE_LOG", (dir / "calls").string().c_str(), 1);
        setenv("YUGEN_FAKE_VERIFY", verifyMode, 1);
        b0 = Block({});
        h0 = b0.GetHash();
        i0.nHeight = ACT - 1;
        i1.nHeight = ACT; i1.pprev = &i0; i1.phashBlock = &h0;
    }
    ~YugenChain()
    {
        mapArgs.erase("-yugenverifier");
        mapArgs.erase("-datadir");
        ClearDatadirCache();
        unsetenv("YUGEN_FAKE_VERIFY");
        unsetenv("YUGEN_FAKE_LOG");
        boost::system::error_code ec;
        fs::remove_all(dir, ec);
        UpdateNetworkUpgradeParameters(Consensus::UPGRADE_YUGEN, Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT);
        SelectParams(CBaseChainParams::MAIN);
    }
    static CBlock Block(const std::vector<CTransaction>& txs)
    {
        CMutableTransaction cb;
        cb.vin.resize(1);
        cb.vin[0].prevout.SetNull();
        cb.vout.resize(1);
        cb.vout[0].nValue = 0;
        CBlock b;
        b.nVersion = 4;
        b.nNonce = uint256S(std::to_string(txs.size()));
        b.vtx.push_back(CTransaction(cb));
        for (const auto& tx : txs) b.vtx.push_back(tx);
        b.hashMerkleRoot = BlockMerkleRoot(b);
        return b;
    }
    // A leaf transfer anchored at block 32: nullifiers (a, b), a deposit of 0.01 YEC.
    static CTransaction Leaf(uint8_t a, uint8_t b, int64_t vb = -1000000)
    {
        std::vector<unsigned char> t(yugen::FIXED_LEN + 8, 0);
        t[1] = (ACT / 16) & 0xff;
        t[2] = yugen::VB;
        t[4] = a;
        t[4 + 32] = b;
        for (int i = 0; i < 8; i++) t[yugen::FIXED_LEN + i] = (uint8_t)((uint64_t)vb >> (8 * i));
        return CTransaction(YugenTx(t, 10, 10));
    }
    bool ConnectSeed()
    {
        CValidationState st;
        yugen::BlockResult res;
        return yugen::ConnectBlock(b0, &i1, Params(), false, st, res, {});
    }
    // Block 33 with these transactions, its body pinned by both commitments as main.cpp pins it.
    bool Connect(const CBlock& b, bool justCheck, CValidationState& st, const yugen::BundleCoinsMap& coins = {})
    {
        h1 = b.GetHash();
        i2.nHeight = ACT + 1; i2.pprev = &i1; i2.phashBlock = &h1;
        st.SetMerkleRootChecked();
        st.SetBlockCommitmentsChecked();
        yugen::BlockResult res;
        return yugen::ConnectBlock(b, &i2, Params(), justCheck, st, res, coins);
    }
    int Calls(const std::string& cmd) const
    {
        std::ifstream f((dir / "calls").string());
        std::string l;
        int n = 0;
        while (std::getline(f, l)) n += l == cmd;
        return n;
    }
};
} // namespace

TEST(Yugen, DoubleSpendBlockIsAVerdict) {
    YugenChain c("accept");
    ASSERT_TRUE(c.ConnectSeed());
    CBlock b = YugenChain::Block({YugenChain::Leaf(1, 2), YugenChain::Leaf(1, 3)});
    CValidationState st;
    EXPECT_FALSE(c.Connect(b, false, st));
    EXPECT_EQ(st.GetRejectReason(), "bad-yugen-nullifier-spent");
    EXPECT_TRUE(st.IsInvalid());
    EXPECT_FALSE(st.CorruptionPossible());                  // marked BLOCK_FAILED_VALID, not refetched
    CValidationState ok;
    EXPECT_TRUE(c.Connect(YugenChain::Block({YugenChain::Leaf(1, 2)}), true, ok)) << ok.GetRejectReason();
}

TEST(Yugen, HelperFailureRetriesAreBounded) {
    YugenChain c("fail");
    ASSERT_TRUE(c.ConnectSeed());
    CBlock b = YugenChain::Block({YugenChain::Leaf(4, 5)});
    std::vector<std::string> reasons;
    std::vector<int> dos;
    for (int i = 0; i < yugen::HELPER_RETRIES_MAX; i++) {
        CValidationState st;
        EXPECT_FALSE(c.Connect(b, false, st));
        EXPECT_TRUE(st.CorruptionPossible());                // never a verdict
        int d = -1;
        st.IsInvalid(d);
        reasons.push_back(st.GetRejectReason());
        dos.push_back(d);
    }
    EXPECT_EQ(reasons.front(), "yugen-verifier-failed");
    EXPECT_EQ(reasons.back(), "yugen-verifier-gave-up");    // and no longer requested
    EXPECT_TRUE(yugen::HelperGaveUp(c.h1));
    EXPECT_EQ(dos.front(), 0);                               // first failure: the node's fault
    EXPECT_EQ(dos[1], yugen::HELPER_SAME_BODY_DOS);          // the same body again: its sender is scored, once
    EXPECT_EQ(dos.back(), 0);
}

// A bundle at block 33 (the minimal bundle anchored at block 32), funded by a leaf deposit before it.
static CTransaction AnchoredBundle(const uint256& h0)
{
    auto b = MinimalBundle();
    b[2] = (YugenChain::ACT / 16) & 0xff;
    std::fill(b.begin() + 3, b.begin() + 3 + 48, 0xaa);
    std::fill(b.begin() + 3 + 48, b.begin() + 3 + 96, 0xbb);
    std::copy(h0.begin(), h0.end(), b.begin() + 3 + 96);
    b[2 + 129 + 2 + 2 + 6 + 4] = 9;                          // nullifiers (9.., 0..) of its one transfer
    return CTransaction(YugenTx(b, 0, 0));
}

TEST(Yugen, BundleTrialWritesNoProofFile) {
    YugenChain c("accept");
    ASSERT_TRUE(c.ConnectSeed());
    CTransaction bundle = AnchoredBundle(c.h0);
    ASSERT_TRUE(bundle.IsYugenBundle());
    CBlock b = YugenChain::Block({YugenChain::Leaf(6, 7), bundle});
    b.vYugenProofs.push_back({bundle.GetHash(), {{1, 2, 3}, {4, 5}}});
    CValidationState st;
    EXPECT_TRUE(c.Connect(b, true, st)) << st.GetRejectReason();
    EXPECT_EQ(c.Calls("bundle"), 1);
    EXPECT_FALSE(fs::exists(GetDataDir() / "yugen" / "proofs" / (bundle.GetHash().GetHex() + ".bin")));
}

TEST(Yugen, BundleCacheKeyHasVerifierOptions) {
    YugenChain c("accept");
    CTransaction bundle = AnchoredBundle(c.h0);
    ASSERT_TRUE(yugen::BundleStatement(bundle, YugenChain::ACT + 1, {true}, Params()).has_value());
    ASSERT_TRUE(yugen::BundleStatement(bundle, YugenChain::ACT + 1, {true}, Params()).has_value());
    EXPECT_EQ(c.Calls("bundle"), 1);                         // cached
    mapArgs["-yugenb2verify"] = "other";
    ASSERT_TRUE(yugen::BundleStatement(bundle, YugenChain::ACT + 1, {true}, Params()).has_value());
    EXPECT_EQ(c.Calls("bundle"), 2);
    mapArgs["-yugenbplan"] = "other";
    ASSERT_TRUE(yugen::BundleStatement(bundle, YugenChain::ACT + 1, {true}, Params()).has_value());
    EXPECT_EQ(c.Calls("bundle"), 3);
    mapArgs.erase("-yugenb2verify");
    mapArgs.erase("-yugenbplan");
}

// Spec 0.5.4 (§15.1, as §7.9 rule 1a): a bundle transaction's lock time is 0 and its expiry height is
// h_a + ANCHOR_WINDOW for its first anchor table entry, so no relay can change its txid.
TEST(Yugen, BundleEnvelopeIsFixed) {
    CMutableTransaction mtx(AnchoredBundle(uint256S("01")));
    const int act = YugenChain::ACT, h = act + 1;
    auto check = [&](const CMutableTransaction& m) {
        CValidationState st;
        bool ok = yugen::CheckLeafEnvelope(CTransaction(m), h, act, st);
        return ok ? std::string("ok") : st.GetRejectReason();
    };
    mtx.nExpiryHeight = act + yugen::ANCHOR_WINDOW;
    EXPECT_EQ(check(mtx), "ok");
    mtx.nLockTime = 1;
    EXPECT_EQ(check(mtx), "bad-yugen-bundle-locktime");
    mtx.nLockTime = 0;
    mtx.nExpiryHeight = 0;
    EXPECT_EQ(check(mtx), "bad-yugen-bundle-expiry");
    mtx.nExpiryHeight = act + yugen::ANCHOR_WINDOW + 1;
    EXPECT_EQ(check(mtx), "bad-yugen-bundle-expiry");
}

// ------------------------------------------------------------------ VB records (spec 0.5.4)

#include "key.h"
#include "script/standard.h"
#include "undo.h"

// A vector number, written as a JSON number or a decimal string.
static uint64_t Num(const UniValue& u) { return u.isNum() ? (uint64_t)u.get_int64() : std::stoull(u.get_str()); }

static UniValue LoadVectors(const char* env)
{
    const char* path = std::getenv(env);
    UniValue doc;
    if (!path) return UniValue(UniValue::VARR);
    std::ifstream f(path);
    std::stringstream ss; ss << f.rdbuf();
    EXPECT_TRUE(doc.read(ss.str())) << path;
    return doc["vectors"];
}

// What the node's own decoding of a bundle field gives, as bundle.json names the errors: "ok" when
// it decodes (the rest of rule B1 is the helper's, yugen-ref Bundle::decode).
static std::string NodeDecode(const std::vector<unsigned char>& b)
{
    std::vector<yugen::Transfer> ts;
    std::vector<uint8_t> slots;
    std::string why;
    if (yugen::DecodeBundleTransfers(b, ts, slots, why)) return "ok";
    static const std::map<std::string, std::string> names{
        {"bundle-truncated", "Truncated"}, {"bundle-vout", "Vout"}, {"bundle-vin", "Vin"},
        {"bundle-withdrawal-sum", "WithdrawalSum"}, {"bundle-canary", "CanaryFlag"},
        {"bundle-transfer-fee-class", "Transfer(FeeClass)"}, {"bundle-transfer-reserved-flag", "Transfer(Flags)"}};
    auto it = names.find(why);
    return it == names.end() ? why : it->second;
}

// Every case of yugen-spec 0.5.4 (77af005) vectors/bundle.json that the node decides: each
// decode-reject the node refuses, with the spec's error wherever the first failure is in a part the
// node decodes (the VB records, the transfers); the rest the node decodes and leaves to the helper,
// listed here by name. Each bundle's record outputs (index, value, script) and expiry height, and the
// deposit sighash of each of its inputs; every envelope case; every deposit-script case.
TEST(Yugen, BundleVectors) {
    const UniValue v = LoadVectors("YUGEN_BUNDLE_VECTORS");
    if (v.empty()) GTEST_SKIP() << "YUGEN_BUNDLE_VECTORS not set";
    // Refused by the helper's B1 only (the node's structural reading decodes them).
    const std::set<std::string> helperOnly{
        "anchors-descending", "anchor-slot-repeated", "anchor-span-above-five", "anchor-unused", "anchor-missing",
        "payee-index-beyond-the-table", "payee-table-not-in-first-use-order", "payee-unused", "payee-twice-in-the-table",
        "payee-empty-script", "one-slot-not-a-template",
        "script-of-24-bytes", "script-of-1-byte", "script-of-64-bytes", "p2pkh-wrong-opcode", "p2sh-wrong-push",
        "pqpkh-scheme-3", "pqpkh-checksig", "merge-script-not-a-template", "funded-canary-nullifier", "depth-six"};
    // Refused by the node's structural reading under its own name (the helper names the spec's error).
    const std::set<std::string> nodeGeneric{
        "version-1", "no-anchors", "seven-anchors", "tree-kind-2", "sub-bundle-of-zero", "sub-bundle-of-5",
        "merge-of-zero", "merge-of-5", "payee-table-missing", "merge-of-one-with-record", "truncated", "trailing-byte",
        "two-inputs-four-records", "payee-count-above-the-maximum", "three-inputs-three-records", "anchor-entry-at-0.3-length"};
    int exact = 0, generic = 0, helper = 0, bundles = 0, inputs = 0, envelopes = 0, scripts = 0;
    for (size_t i = 0; i < v.size(); i++) {
        const UniValue& x = v[i];
        const std::string kind = x["kind"].get_str(), name = x.exists("name") ? x["name"].get_str() : "";
        if (kind == "decode-reject") {
            const std::string got = NodeDecode(ParseHex(x["encoding"].get_str()));
            if (helperOnly.count(name)) { EXPECT_EQ(got, "ok") << name; helper++; }
            else if (nodeGeneric.count(name)) { EXPECT_NE(got, "ok") << name; generic++; }
            else { EXPECT_EQ(got, x["error"].get_str()) << name; exact++; }
        } else if (kind == "bundle") {
            const auto enc = ParseHex(x["encoding"].get_str());
            ASSERT_EQ(NodeDecode(enc), "ok") << name;
            CMutableTransaction m = YugenTx(enc, 0, 0);
            m.nExpiryHeight = (uint32_t)Num(x["expiry_height"]);
            const CTransaction tx(m);
            const int h = (int)Num(x["height"]);
            CValidationState st;
            EXPECT_TRUE(yugen::CheckLeafTransferStructure(tx, st) && yugen::CheckLeafEnvelope(tx, h, 4096, st))
                << name << " " << st.GetRejectReason();
            EXPECT_EQ(yugen::ResolveAnchor(enc[2], h, 4096) + yugen::ANCHOR_WINDOW, (int)m.nExpiryHeight) << name;
            const auto ts = tx.GetYugenTransfers();
            const auto outs = yugen::RecordOutputs(tx, std::vector<bool>(ts.size(), true));
            const UniValue& want = x["outputs"];
            ASSERT_EQ(outs.size(), want.size()) << name;
            for (size_t j = 0; j < want.size(); j++) {
                EXPECT_EQ(Num(want[j]["index"]), j);
                EXPECT_EQ((uint64_t)outs[j].nValue, Num(want[j]["value"])) << name;
                EXPECT_EQ(HexStr(outs[j].scriptPubKey.begin(), outs[j].scriptPubKey.end()), want[j]["script"].get_str()) << name;
            }
            EXPECT_EQ(yugen::RecordOutputs(tx, std::vector<bool>(ts.size(), false)).size(), want.size());   // indices never move
            const UniValue& tv = x["transfers"];
            ASSERT_EQ(tv.size(), ts.size()) << name;
            for (size_t t = 0; t < tv.size(); t++) {
                const UniValue& ins = tv[t]["inputs"];
                ASSERT_EQ(ins.size(), ts[t].vin.size()) << name;
                if (ins.empty()) continue;
                const auto th = ParseHex(tv[t]["transfer_hash"].get_str());
                std::array<uint8_t, 48> h48;
                std::copy(th.begin(), th.end(), h48.begin());
                std::vector<COutPoint> prevouts;
                for (size_t k = 0; k < ins.size(); k++) {
                    const auto txid = ParseHex(ins[k]["txid"].get_str());
                    EXPECT_TRUE(std::equal(txid.begin(), txid.end(), ts[t].vin[k].txid.begin())) << name;
                    EXPECT_EQ(HexStr(ts[t].vin[k].scriptSig), ins[k]["script_sig"].get_str()) << name;
                    prevouts.push_back(COutPoint(uint256(txid), (uint32_t)Num(ins[k]["index"])));
                }
                for (size_t k = 0; k < ins.size(); k++) {
                    const uint256 d = yugen::DepositSighash((uint32_t)Num(x["branch_id"]), (uint8_t)Num(x["network"]), h48, prevouts, k,
                                                            Num(ins[k]["amount"]), ParseHex(ins[k]["script_code"].get_str()));
                    EXPECT_EQ(HexStr(d.begin(), d.end()), ins[k]["sighash"].get_str()) << name << " input " << k;
                    inputs++;
                }
            }
            bundles++;
        } else if (kind == "envelope") {
            const UniValue& f = x["fields"];
            CMutableTransaction m = YugenTx(ParseHex(x["encoding"].get_str()), x["tx"].get_str() == "leaf" ? 10 : 0,
                                            x["tx"].get_str() == "leaf" ? 10 : 0);
            m.vin.resize(Num(f["vin"]));
            m.vout.resize(Num(f["vout"]), CTxOut(1, CScript() << OP_TRUE));
            if (f["shielded"].get_bool()) { m.vJoinSplit.resize(1); m.vJoinSplit[0].proof = libzcash::GrothProof(); }
            m.nLockTime = (uint32_t)Num(f["lock_time"]);
            m.nExpiryHeight = (uint32_t)Num(f["expiry_height"]);
            const CTransaction tx(m);
            const int h = (int)Num(x["height"]);
            CValidationState st;
            bool ok = (!tx.IsYugenBundle() || yugen::CheckLeafTransferStructure(tx, st)) && yugen::CheckLeafEnvelope(tx, h, 4096, st);
            std::string got = "ok";
            if (!ok) {
                const std::string r = st.GetRejectReason();
                got = r.find("transparent") != std::string::npos ? "Transparent" : r.find("shielded") != std::string::npos ? "Shielded" :
                      r.find("locktime") != std::string::npos ? "LockTime" : r.find("expiry") != std::string::npos ? "Expiry" : r;
            }
            // `Anchor`: the anchor resolves at no height; rule B2 (§7.9 rule 2 for a leaf) refuses it instead.
            const std::string want = x["result"].get_str();
            EXPECT_EQ(got, want == "Anchor" ? "ok" : want) << name;
            envelopes++;
        } else if (kind == "deposit-script") {
            EXPECT_EQ(yugen::DepositScriptOk(ParseHex(x["script"].get_str())), x["accepted"].get_bool()) << name;
            scripts++;
        }
    }
    EXPECT_EQ(exact + generic + helper, 52);
    EXPECT_EQ(exact, 15);   // the twelve VB rejections, Transfer(FeeClass) and the two canary flags
    EXPECT_EQ(bundles, 18);
    EXPECT_EQ(inputs, 6);
    EXPECT_EQ(envelopes, 35);
    EXPECT_EQ(scripts, 9);
}

// §15.5 and §15.6 B6 at the node: a bundle of a deposit (one P2PKH coin, change) and a withdrawal at
// block 33 of the YugenChain fixture. ConnectBundleCoins spends the coin and creates the outputs at
// the bundle's txid (indices across records); yugen::ConnectBlock verifies the deposit's script
// against dep_sighash with the helper's transfer hash. A missing coin is a skip (S2) whose outputs
// keep their indices; a P2SH coin, a broken signature or an unbalanced deposit is a failure.
namespace {
struct VbBundle {
    CKey key;
    COutPoint coin{uint256S("c0"), 1};
    CAmount coinValue = 3000000, deposit = 2500000, change = 500000, withdrawal = 400000;
    std::array<uint8_t, 48> th0{}, th1{};
    std::vector<unsigned char> sig;
    CScript wOut;   // the withdrawal record's output script (empty: Spk())
    CScript Spk() const { return GetScriptForDestination(key.GetPubKey().GetID()); }
    static void Compact(std::vector<unsigned char>& b, uint64_t n) { b.push_back((uint8_t)n); }   // n < 253
    static void Le(std::vector<unsigned char>& b, uint64_t v, int n) { for (int i = 0; i < n; i++) b.push_back((v >> (8 * i)) & 0xff); }
    std::vector<unsigned char> Transfer(uint8_t nf, int64_t vb) const
    {
        std::vector<unsigned char> t(yugen::FIXED_LEN, 0);
        t[1] = (YugenChain::ACT / 16) & 0xff;
        t[2] = yugen::VB;
        t[4] = nf;
        t[4 + 32] = nf + 1;
        Le(t, (uint64_t)vb, 8);
        return t;
    }
    std::vector<unsigned char> Field(const uint256& h0, const std::vector<unsigned char>& scriptSig, CAmount dep) const
    {
        std::vector<unsigned char> b{yugen::BUNDLE_VERSION, 0x01, (uint8_t)((YugenChain::ACT / 16) & 0xff)};
        b.insert(b.end(), 48, 0xaa);
        b.insert(b.end(), 48, 0xbb);
        b.insert(b.end(), h0.begin(), h0.end());
        b.insert(b.end(), {0x00, 0x00, 0x00, 0x02});   // empty payee table; a leaf node of two transfers
        b.insert(b.end(), 6, 0x00);
        auto t0 = Transfer(20, -dep);
        b.insert(b.end(), t0.begin(), t0.end());
        const CScript s = Spk();
        Compact(b, 1); Le(b, change, 8); Compact(b, s.size()); b.insert(b.end(), s.begin(), s.end());
        Compact(b, 1); b.insert(b.end(), coin.hash.begin(), coin.hash.end()); Le(b, coin.n, 4);
        Compact(b, scriptSig.size()); b.insert(b.end(), scriptSig.begin(), scriptSig.end());
        auto t1 = Transfer(30, withdrawal);
        b.insert(b.end(), t1.begin(), t1.end());
        const CScript w = wOut.empty() ? s : wOut;
        Compact(b, 1); Le(b, withdrawal, 8); Compact(b, w.size()); b.insert(b.end(), w.begin(), w.end());
        b.insert(b.end(), 64, 0x00);
        return b;
    }
    CTransaction Tx(const uint256& h0, bool goodSig = true, CAmount dep = -1) const
    {
        if (dep < 0) dep = deposit;
        const CScript spk = Spk();
        const uint256 d = yugen::DepositSighash(CurrentEpochBranchId(YugenChain::ACT + 1, Params().GetConsensus()), 2, th0, {coin}, 0,
                                                coinValue, std::vector<unsigned char>(spk.begin(), spk.end()));
        std::vector<unsigned char> s;
        EXPECT_TRUE(key.Sign(d, s));
        s.push_back(SIGHASH_ALL);
        if (!goodSig) s[10] ^= 1;
        const CScript scriptSig = CScript() << s << ToByteVector(key.GetPubKey());
        CMutableTransaction m = YugenTx(Field(h0, std::vector<unsigned char>(scriptSig.begin(), scriptSig.end()), dep), 0, 0);
        m.nExpiryHeight = YugenChain::ACT + yugen::ANCHOR_WINDOW;
        return CTransaction(m);
    }
    VbBundle()
    {
        key = CKey::TestOnlyRandomKey(true);
        th0.fill(0x51);
        th1.fill(0x52);
        setenv("YUGEN_FAKE_TRANSFERS", ("{\"transfer_hash\":\"" + HexStr(th0) + "\"},{\"transfer_hash\":\"" + HexStr(th1) + "\"}").c_str(), 1);
    }
    ~VbBundle() { unsetenv("YUGEN_FAKE_TRANSFERS"); }
};
} // namespace

TEST(Yugen, BundleVbRecordsConnect) {
    YugenChain c("accept");
    ASSERT_TRUE(c.ConnectSeed());
    VbBundle vb;
    CCoinsViewDummy base;
    auto run = [&](const CTransaction& bundle, CCoinsViewCache& view, CTxUndo& undo, yugen::BlockCoins& bc,
                   CAmount& delta, CValidationState& st) {
        c.i2.nHeight = YugenChain::ACT + 1; c.i2.pprev = &c.i1;
        bc.nfs.clear(); bc.bundles.clear();
        const CTransaction leaf = YugenChain::Leaf(1, 2);   // funds the pool before the bundle
        CTxUndo u0;
        EXPECT_TRUE(yugen::ConnectBundleCoins(leaf, view, u0, &c.i2, Params(), SCRIPT_VERIFY_P2SH, bc, delta, st));
        if (!yugen::ConnectBundleCoins(bundle, view, undo, &c.i2, Params(), SCRIPT_VERIFY_P2SH, bc, delta, st)) return false;
        CBlock b = YugenChain::Block({leaf, bundle});
        b.vYugenProofs.push_back({bundle.GetHash(), {{1, 2, 3}, {4, 5}}});
        return c.Connect(b, true, st, bc.bundles);
    };
    auto withCoin = [&](CCoinsViewCache& view, const CScript& spk) {
        CCoinsModifier m = view.ModifyCoins(vb.coin.hash);
        m->nHeight = 1;
        m->vout.resize(vb.coin.n + 1);
        m->vout[vb.coin.n] = CTxOut(vb.coinValue, spk);
    };
    {
        // Applied: the coin is spent, the change (index 0) and the withdrawal (index 1) are created.
        const CTransaction bundle = vb.Tx(c.h0);
        CCoinsViewCache view(&base);
        withCoin(view, vb.Spk());
        CTxUndo undo; yugen::BlockCoins bc; CAmount delta = 0; CValidationState st;
        st.SetMerkleRootChecked(); st.SetBlockCommitmentsChecked();
        EXPECT_TRUE(run(bundle, view, undo, bc, delta, st)) << st.GetRejectReason();
        EXPECT_EQ(bc.bundles[bundle.GetHash()].applied, std::vector<bool>({true, true}));
        EXPECT_FALSE(view.AccessCoins(vb.coin.hash) && view.AccessCoins(vb.coin.hash)->IsAvailable(vb.coin.n));
        const CCoins* outs = view.AccessCoins(bundle.GetHash());
        ASSERT_TRUE(outs && outs->IsAvailable(0) && outs->IsAvailable(1));
        EXPECT_EQ(outs->vout[0].nValue, vb.change);
        EXPECT_EQ(outs->vout[1].nValue, vb.withdrawal);
        EXPECT_EQ(delta, vb.change + vb.withdrawal - vb.coinValue);
        EXPECT_EQ(yugen::UndoMask(undo), std::vector<bool>({true, true}));
        ASSERT_EQ(undo.vprevout.size(), 2u);
        EXPECT_EQ(undo.vprevout[1].txout.nValue, vb.coinValue);
        EXPECT_EQ(yugen::RecordPrevouts(bundle, yugen::UndoMask(undo)), std::vector<COutPoint>({vb.coin}));
        EXPECT_EQ(GetLegacySigOpCount(bundle), 2u);   // two P2PKH record outputs (§15.5)
        // The undo entry survives its serialization.
        CDataStream ss(SER_DISK, CLIENT_VERSION);
        ss << undo;
        CTxUndo back;
        ss >> back;
        EXPECT_EQ(yugen::UndoMask(back), std::vector<bool>({true, true}));
    }
    {
        // S2: no coin. The deposit is skipped, its change is never created, the withdrawal keeps index 1.
        const CTransaction bundle = vb.Tx(c.h0);
        CCoinsViewCache view(&base);
        CTxUndo undo; yugen::BlockCoins bc; CAmount delta = 0; CValidationState st;
        st.SetMerkleRootChecked(); st.SetBlockCommitmentsChecked();
        EXPECT_TRUE(run(bundle, view, undo, bc, delta, st)) << st.GetRejectReason();
        EXPECT_EQ(bc.bundles[bundle.GetHash()].applied, std::vector<bool>({false, true}));
        const CCoins* outs = view.AccessCoins(bundle.GetHash());
        ASSERT_TRUE(outs);
        EXPECT_FALSE(outs->IsAvailable(0));
        EXPECT_TRUE(outs->IsAvailable(1));
        EXPECT_EQ(undo.vprevout.size(), 1u);
    }
    auto refused = [&](const CTransaction& bundle, const CScript& spk) {
        CCoinsViewCache view(&base);
        withCoin(view, spk);
        CTxUndo undo; yugen::BlockCoins bc; CAmount delta = 0; CValidationState st;
        st.SetMerkleRootChecked(); st.SetBlockCommitmentsChecked();
        EXPECT_FALSE(run(bundle, view, undo, bc, delta, st));
        EXPECT_TRUE(st.IsInvalid());
        return st.GetRejectReason();
    };
    EXPECT_EQ(refused(vb.Tx(c.h0), GetScriptForDestination(CScriptID(vb.Spk()))), "bad-yugen-bundle-deposit-coin");
    EXPECT_EQ(refused(vb.Tx(c.h0, false), vb.Spk()), "bad-yugen-bundle-deposit-script");
    EXPECT_EQ(refused(vb.Tx(c.h0, true, vb.deposit - 1), vb.Spk()), "bad-yugen-bundle-deposit-balance");
    {
        // S3 (§13.3.6): a deposit that would take B above cap(h) is skipped: its coin stays unspent, its
        // change is never created; the withdrawal after it applies.
        VbBundle big;
        big.coinValue = (CAmount)yugen::ValueCap(YugenChain::ACT + 1, YugenChain::ACT) + 1000000;
        big.deposit = big.coinValue - big.change;
        const CTransaction bundle = big.Tx(c.h0);
        CCoinsViewCache view(&base);
        {
            CCoinsModifier m = view.ModifyCoins(big.coin.hash);
            m->nHeight = 1;
            m->vout.resize(big.coin.n + 1);
            m->vout[big.coin.n] = CTxOut(big.coinValue, big.Spk());
        }
        CTxUndo undo; yugen::BlockCoins bc; CAmount delta = 0; CValidationState st;
        st.SetMerkleRootChecked(); st.SetBlockCommitmentsChecked();
        EXPECT_TRUE(run(bundle, view, undo, bc, delta, st)) << st.GetRejectReason();
        EXPECT_EQ(bc.bundles[bundle.GetHash()].applied, std::vector<bool>({false, true}));
        ASSERT_TRUE(view.AccessCoins(big.coin.hash));
        EXPECT_TRUE(view.AccessCoins(big.coin.hash)->IsAvailable(big.coin.n));
        const CCoins* outs = view.AccessCoins(bundle.GetHash());
        ASSERT_TRUE(outs);
        EXPECT_FALSE(outs->IsAvailable(0));
        EXPECT_TRUE(outs->IsAvailable(1));
    }
    {
        // §13.3.5, B6: a withdrawal above the window's gross cap K fails the bundle, even where S1 or S2
        // would skip it.
        VbBundle wide;
        wide.withdrawal = (CAmount)yugen::GrossCap(YugenChain::ACT + 1, YugenChain::ACT) + 1;
        EXPECT_EQ(refused(wide.Tx(c.h0), wide.Spk()), "bad-yugen-bundle-withdrawal-above-k");
    }
    {
        // N-D12: a record output the vault primitive or the YED module would read (V- or I-shaped, an act)
        // fails the bundle: neither sees record outputs.
        vault::VaultParams v;
        v.tag = yellowback::YED_TAG;
        v.cancelSetId = uint256S("11");
        v.setId = uint256S("22");
        v.delay = 10;
        v.ownerHeight = 500;
        v.appHeight = 500;
        v.owner = CPQKeyID(pq::SCHEME_SLH_DSA_SHA2_128S, uint256S("33"));
        VbBundle shaped;
        shaped.wOut = vault::BuildVault(v);
        ASSERT_FALSE(shaped.wOut.empty());
        EXPECT_EQ(refused(shaped.Tx(c.h0), shaped.Spk()), "bad-yugen-bundle-record-output");
        v.tag = vault::Tag{{0x4e, 0x59, 0x45, 0x43}};   // an unregistered tag: still a vault
        shaped.wOut = vault::BuildVault(v);
        EXPECT_EQ(refused(shaped.Tx(c.h0), shaped.Spk()), "bad-yugen-bundle-record-output");
    }
}

TEST(Yugen, BundleRecordInputTrackedByModule) {
    // N-D12: a bundle's record input is spent outside tx.vin; the YED module refuses the bundle when the
    // coin is one it tracks (here a token), where a leaf (an ordinary input) spending it burns the YED.
    YugenChain c("accept");   // the chain parameters the bundle is built under
    VbBundle vb;
    const CTransaction bundle = vb.Tx(uint256S("01"));
    EXPECT_EQ(yellowback::YugenRecordInputs(bundle), std::vector<COutPoint>({vb.coin}));
    const yellowback::Params P = yellowback::RegtestParams(1, 15000, 10000, uint256S("aa"));
    {
        yellowback::MemoryStateView view;
        yellowback::State st(view);
        const yellowback::TxOutcome out = yellowback::ProcessTx(st, P, bundle, 10);
        EXPECT_FALSE(out.invalid) << out.log.verdict;   // an untracked coin: nothing for the module
    }
    yellowback::MemoryStateView view;
    yellowback::State st(view);
    yellowback::TokenRecord tok;
    tok.cents = 500;
    tok.nValue = vb.coinValue;
    tok.scriptPubKey = vb.Spk();
    tok.height = 5;
    st.Put(yellowback::keys::Token(vb.coin), tok);
    const yellowback::TxOutcome out = yellowback::ProcessTx(st, P, bundle, 10);
    EXPECT_TRUE(out.invalid);
    EXPECT_EQ(out.log.verdict, yellowback::verdict::YUGEN_BUNDLE_INPUT);
    EXPECT_TRUE(st.GetToken(vb.coin).has_value());   // nothing applied
    // The leaf way: an ordinary input spending the token burns it.
    CMutableTransaction leaf;
    leaf.vin.push_back(CTxIn(vb.coin));
    leaf.vout.push_back(CTxOut(vb.coinValue - 1000, vb.Spk()));
    const yellowback::TxOutcome burned = yellowback::ProcessTx(st, P, CTransaction(leaf), 10);
    EXPECT_FALSE(burned.invalid) << burned.log.verdict;
    EXPECT_EQ(burned.log.verdict, yellowback::verdict::BURNED);
    EXPECT_FALSE(st.GetToken(vb.coin).has_value());
}

TEST(Yugen, LeafValueCapAndGrossCap) {
    // §13.3.6: a leaf deposit that takes B above cap(h) makes the block invalid; §13.3.5: a leaf
    // withdrawal above K is invalid.
    YugenChain c("accept");
    ASSERT_TRUE(c.ConnectSeed());
    const int64_t cap = (int64_t)yugen::ValueCap(YugenChain::ACT + 1, YugenChain::ACT);
    const int64_t K = (int64_t)yugen::GrossCap(YugenChain::ACT + 1, YugenChain::ACT);
    EXPECT_EQ(yugen::ValueCap(YugenChain::ACT, YugenChain::ACT), yugen::RATCHET_C0);
    EXPECT_EQ(cap, (int64_t)(yugen::RATCHET_C0 + yugen::RATCHET_C0 / yugen::RATCHET_P));   // one block on: linear
    EXPECT_EQ(K, (int64_t)yugen::RATCHET_C0 / 8);
    auto reason = [&](const CTransaction& leaf) {
        CValidationState st;
        const bool ok = c.Connect(YugenChain::Block({leaf}), true, st);
        return ok ? std::string("ok") : st.GetRejectReason();
    };
    EXPECT_EQ(reason(YugenChain::Leaf(1, 2, -(cap + 1000000))), "bad-yugen-value-cap");
    EXPECT_EQ(reason(YugenChain::Leaf(1, 2, K + 1)), "bad-yugen-withdrawal-above-k");
    EXPECT_EQ(reason(YugenChain::Leaf(1, 2, -1000000)), "ok");
}

TEST(Yugen, RatchetAndOutflowCapVectors) {
    // safety.json (spec 0.5.4): YUGEN_SAFETY_VECTORS, else next to YUGEN_BUNDLE_VECTORS.
    std::string path;
    if (const char* p = std::getenv("YUGEN_SAFETY_VECTORS")) path = p;
    else if (const char* b = std::getenv("YUGEN_BUNDLE_VECTORS")) path = (fs::path(b).parent_path() / "safety.json").string();
    if (path.empty() || !fs::exists(path)) GTEST_SKIP() << "safety.json not found";
    std::ifstream f(path);
    std::stringstream ss; ss << f.rdbuf();
    UniValue doc;
    ASSERT_TRUE(doc.read(ss.str())) << path;
    const UniValue& v = doc["vectors"];
    auto u64 = [](const UniValue& x) { return (uint64_t)std::stoull(x.get_str()); };
    int ratchet = 0, caps = 0, windows = 0;
    for (size_t i = 0; i < v.size(); i++) {
        const UniValue& x = v[i];
        const std::string kind = x["kind"].get_str();
        if (kind == "ratchet" && x["frozen_at"].isNull()) {
            EXPECT_EQ(yugen::RatchetCap(x["h"].get_int64(), x["h0"].get_int64(), u64(x["c0"]), (uint32_t)x["p"].get_int64(), u64(x["cmax"])),
                      u64(x["cap"])) << i;
            ratchet++;
        } else if (kind == "outflow-caps") {
            EXPECT_EQ(yugen::OutflowK(u64(x["cap_at_window_start"])), u64(x["k"])) << i;
            caps++;
            if (!x["h"].isNull()) {
                const int h = x["h"].get_int(), h0 = x["h0"].get_int();
                EXPECT_EQ(yugen::ValueCap(x["window_start"].get_int(), h0), u64(x["cap_at_window_start"])) << i;
                EXPECT_EQ(yugen::GrossCap(h, h0), u64(x["k"])) << i;
                windows++;
            }
        }
    }
    EXPECT_GT(ratchet, 0);
    EXPECT_GT(caps, 0);
    std::cout << "ratchet " << ratchet << ", outflow caps " << caps << " (" << windows << " with a window)" << std::endl;
}

TEST(Yugen, DecodeRecordManyInputsIsFast) {
    // Review C-1: a deposit record of ~53,000 inputs (~1.96 MB, a full bundle) decodes in milliseconds;
    // the quadratic duplicate scan it replaces took ~725 ms per decode. A repeated prevout is still `Vin`.
    const size_t N = 53000;
    std::vector<unsigned char> b{0x00, 0xfd, (uint8_t)(N & 0xff), (uint8_t)(N >> 8)};   // no outputs; N inputs
    for (size_t i = 0; i < N; i++) {
        std::array<uint8_t, 32> txid{};
        txid[0] = i & 0xff; txid[1] = (i >> 8) & 0xff; txid[2] = (i >> 16) & 0xff;
        b.insert(b.end(), txid.begin(), txid.end());
        b.insert(b.end(), {0x00, 0x00, 0x00, 0x00, 0x00});   // index 0, an empty scriptSig
    }
    auto decode = [](const std::vector<unsigned char>& buf, yugen::Transfer& t, std::string& why) {
        t.valueBalance = -1000;
        size_t o = 0;
        const bool ok = yugen::DecodeRecord(buf, o, t, why);
        return ok && o == buf.size();
    };
    yugen::Transfer t;
    std::string why;
    const auto t0 = std::chrono::steady_clock::now();
    EXPECT_TRUE(decode(b, t, why)) << why;
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    EXPECT_EQ(t.vin.size(), N);
    EXPECT_LT(ms, 200) << "decode of " << N << " inputs took " << ms << " ms";
    // The last input repeats the first: refused, as yugen-ref Bundle::decode refuses it.
    std::copy(b.begin() + 4, b.begin() + 4 + 37, b.end() - 37);
    yugen::Transfer d;
    EXPECT_FALSE(decode(b, d, why));
    EXPECT_EQ(why, "bundle-vin");
    // The same outpoint with another index is a different input.
    b[b.size() - 5] = 1;
    yugen::Transfer e;
    EXPECT_TRUE(decode(b, e, why)) << why;
}
