// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// DORMANT: the vault signing messages under a v5 (ZIP-225 / ZIP-244) transaction, the dormant
// section of the vault spec (workspace docs/spec/vault-signing-message-v5.md; kogany plan K-21,
// option D). No network admits a v5 transaction under Vault (upgrade plan U-26): this test only
// replays src/test/data/vault_v5_dormant_vectors.json, written by
// qa/rpc-tests/test_framework/gen_vault_v5_vectors.py from the corrected test_framework/zip244.py,
// through the node's own ZIP-244 path (SignatureHash -> SIGVERSION_ZIP244 -> the Rust
// sighash_v5.rs) on hand-built transactions, so no node configuration has to schedule Vault and
// NU5 together. The vector file is not in qa/yellowback-cross-line.manifest (ycash6 only).

#include "vault/act.h"
#include "vault/template.h"

#include "core_io.h"
#include "crypto/pq/scheme.h"
#include "key.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "test/data/vault_v5_dormant_vectors.json.h"
#include "test/test_bitcoin.h"
#include "univalue.h"
#include "util/strencodings.h"

#include <boost/test/unit_test.hpp>

using namespace vault;

namespace {

UniValue Vectors()
{
    UniValue doc;
    BOOST_REQUIRE(doc.read(std::string(json_tests::vault_v5_dormant_vectors,
        json_tests::vault_v5_dormant_vectors + sizeof(json_tests::vault_v5_dormant_vectors))));
    return doc;
}

std::vector<unsigned char> Bytes(const UniValue& v) { return ParseHex(v.get_str()); }

CScript Script(const UniValue& v)
{
    std::vector<unsigned char> b = Bytes(v);
    return CScript(b.begin(), b.end());
}

uint256 U256(const UniValue& v)
{
    std::vector<unsigned char> b = Bytes(v);
    BOOST_REQUIRE_EQUAL(b.size(), 32u);
    return uint256(b);
}

std::string Hex(const uint256& u) { return HexStr(u.begin(), u.end()); }
std::string Hex(const CScript& s) { return HexStr(s.begin(), s.end()); }
std::string Hex(const std::vector<unsigned char>& b) { return HexStr(b.begin(), b.end()); }

COutPoint Prevout(const UniValue& v)
{
    std::vector<unsigned char> b = Bytes(v);
    BOOST_REQUIRE_EQUAL(b.size(), 36u);
    uint32_t n = b[32] | (b[33] << 8) | (b[34] << 16) | ((uint32_t)b[35] << 24);
    return COutPoint(uint256(std::vector<unsigned char>(b.begin(), b.begin() + 32)), n);
}

std::vector<CTxOut> PrevOutputs(const UniValue& a)
{
    std::vector<CTxOut> out;
    for (size_t i = 0; i < a.size(); i++) out.emplace_back(a[i]["amount"].get_int64(), Script(a[i]["scriptPubKey"]));
    return out;
}

/** A v5 transaction from the vector: round trip, ZIP-244 txid and auth digest, the branch id it carries. */
CTransaction V5Tx(const UniValue& doc, const UniValue& hex, const std::string& name)
{
    CTransaction tx;
    BOOST_REQUIRE_NO_THROW(DecodeHexTx(tx, hex.get_str()));
    BOOST_CHECK_EQUAL(EncodeHexTx(tx), hex.get_str());
    BOOST_CHECK(tx.fOverwintered && tx.nVersion == 5);
    BOOST_CHECK_EQUAL(tx.nVersionGroupId, (uint32_t)doc["versionGroupId"].get_int64());
    BOOST_REQUIRE(tx.GetConsensusBranchId().has_value());
    BOOST_CHECK_EQUAL(*tx.GetConsensusBranchId(), (uint32_t)doc["branchId"].get_int64());
    return tx;
}

/** The P2PKH fee inputs are signed under ZIP-244 SIGHASH_ALL by the Python framework: the interpreter accepts them. */
void CheckFeeInputs(const CTransaction& tx, const PrecomputedTransactionData& txdata, const std::vector<CTxOut>& prev,
                    uint32_t branch, const std::string& name)
{
    for (unsigned int i = 1; i < tx.vin.size(); i++) {
        TransactionSignatureChecker checker(&tx, txdata, i, prev[i].nValue);
        ScriptError err;
        BOOST_CHECK_MESSAGE(VerifyScript(tx.vin[i].scriptSig, prev[i].scriptPubKey, STANDARD_SCRIPT_VERIFY_FLAGS, checker,
                                         branch, &err), name + ": fee input " + ScriptErrorString(err));
    }
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(vault_v5_dormant_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(set_signature_messages)
{
    UniValue doc = Vectors();
    const uint32_t branch = doc["branchId"].get_int64();
    const UniValue& sp = doc["spends"];
    BOOST_REQUIRE_EQUAL(sp.size(), 2u);
    for (size_t i = 0; i < sp.size(); i++) {
        const std::string name = sp[i]["name"].get_str();
        CTransaction tx = V5Tx(doc, sp[i]["tx"], name);
        BOOST_CHECK_EQUAL(Hex(tx.GetHash()), sp[i]["txid"].get_str());
        BOOST_CHECK_EQUAL(tx.GetHash().GetHex(), sp[i]["txidDisplay"].get_str());
        BOOST_CHECK_EQUAL(Hex(tx.GetAuthDigest()), sp[i]["authDigest"].get_str());
        const unsigned int nIn = sp[i]["nIn"].get_int();
        const std::vector<CTxOut> prev = PrevOutputs(sp[i]["prevOutputs"]);
        const PrecomputedTransactionData txdata(tx, prev);
        const int ht = sp[i]["hashType"].get_int();
        BOOST_CHECK_EQUAL(ht, SIGHASH_ALL | SIGHASH_ANYONECANPAY);
        const uint256 sighash = SignatureHash(prev[nIn].scriptPubKey, tx, nIn, ht, prev[nIn].nValue, branch, txdata);
        BOOST_CHECK_MESSAGE(Hex(sighash) == sp[i]["sighash"].get_str(), name + ": ZIP-244 S(ALL|ANYONECANPAY) " + Hex(sighash));
        BOOST_CHECK(Hex(sighash) != sp[i]["v4Sighash"].get_str());
        const uint256 msg = SetSigMsg(U256(sp[i]["setId"]), sp[i]["role"].get_int(), tx.vin[nIn].prevout, sighash);
        BOOST_CHECK_EQUAL(Hex(msg), sp[i]["setSigMsg"].get_str());
        std::optional<TemplateSpend> ts = ParseTemplateSpend(prev[nIn].scriptPubKey, tx.vin[nIn].scriptSig);
        BOOST_REQUIRE(ts.has_value());
        BOOST_CHECK_EQUAL(ts->selector, sp[i]["role"].get_int());
        BOOST_REQUIRE_EQUAL(ts->sigs.size(), sp[i]["sigs"].size());
        for (size_t j = 0; j < ts->sigs.size(); j++) {
            BOOST_CHECK_EQUAL(Hex(ts->sigs[j]), sp[i]["sigs"][j].get_str());
            CPubKey k;
            BOOST_CHECK(RecoverSig(msg, ts->sigs[j], k));
        }
        CheckFeeInputs(tx, txdata, prev, branch, name);

        // ANYONECANPAY: another fee input of another value; the set's digest is unchanged, the txid is not.
        const UniValue& fr = sp[i]["feeReplaced"];
        CTransaction txr = V5Tx(doc, fr["tx"], name + "/feeReplaced");
        BOOST_CHECK_EQUAL(Hex(txr.GetHash()), fr["txid"].get_str());
        BOOST_CHECK(txr.GetHash() != tx.GetHash());
        const std::vector<CTxOut> prevr = PrevOutputs(fr["prevOutputs"]);
        const PrecomputedTransactionData txdatar(txr, prevr);
        const uint256 shr = SignatureHash(prevr[nIn].scriptPubKey, txr, nIn, ht, prevr[nIn].nValue, branch, txdatar);
        BOOST_CHECK_EQUAL(Hex(shr), fr["sighash"].get_str());
        BOOST_CHECK(shr == sighash);
        CheckFeeInputs(txr, txdatar, prevr, branch, name + "/feeReplaced");
    }
}

BOOST_AUTO_TEST_CASE(owner_pq_messages)
{
    UniValue doc = Vectors();
    const uint32_t branch = doc["branchId"].get_int64();
    const UniValue& sp = doc["ownerSpends"];
    BOOST_REQUIRE_EQUAL(sp.size(), 2u);
    const unsigned int flags = STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_VAULT;
    for (size_t i = 0; i < sp.size(); i++) {
        const std::string name = sp[i]["name"].get_str();
        CTransaction tx = V5Tx(doc, sp[i]["tx"], name);
        BOOST_CHECK_EQUAL(Hex(tx.GetHash()), sp[i]["txid"].get_str());
        BOOST_CHECK_EQUAL(Hex(tx.GetAuthDigest()), sp[i]["authDigest"].get_str());
        const unsigned int nIn = sp[i]["nIn"].get_int();
        const std::vector<CTxOut> prev = PrevOutputs(sp[i]["prevOutputs"]);
        const PrecomputedTransactionData txdata(tx, prev);
        BOOST_CHECK_EQUAL(sp[i]["hashType"].get_int(), SIGHASH_ALL);
        const uint256 sighash = SignatureHash(prev[nIn].scriptPubKey, tx, nIn, SIGHASH_ALL, prev[nIn].nValue, branch, txdata);
        BOOST_CHECK_MESSAGE(Hex(sighash) == sp[i]["sighash"].get_str(), name + ": ZIP-244 S(ALL) " + Hex(sighash));
        // S.2c: SIGHASH_ALL commits to every spent amount, so a different claimed fee-input amount moves it.
        const std::vector<CTxOut> prevx = PrevOutputs(sp[i]["feeAmountChanged"]["prevOutputs"]);
        const PrecomputedTransactionData txdatax(tx, prevx);
        const uint256 shx = SignatureHash(prevx[nIn].scriptPubKey, tx, nIn, SIGHASH_ALL, prevx[nIn].nValue, branch, txdatax);
        BOOST_CHECK_EQUAL(Hex(shx), sp[i]["feeAmountChanged"]["sighash"].get_str());
        BOOST_CHECK(shx != sighash);

        std::optional<TemplateSpend> ts = ParseTemplateSpend(prev[nIn].scriptPubKey, tx.vin[nIn].scriptSig);
        BOOST_REQUIRE(ts.has_value());
        BOOST_CHECK_EQUAL(ts->selector, sp[i]["selector"].get_int());
        const std::vector<std::vector<unsigned char>>& a = ts->sigs;     // <sig_1>..<sig_s> <s> <pk_1>..<pk_p> <p>
        BOOST_REQUIRE(a.size() >= 4 && a.back().size() == 1);
        const size_t p = a.back()[0];
        BOOST_REQUIRE(a.size() >= p + 3 && a[a.size() - 2 - p].size() == 1);
        const size_t s = a[a.size() - 2 - p][0];
        BOOST_REQUIRE_EQUAL(a.size(), s + p + 2);
        std::vector<unsigned char> sig, pk;
        for (size_t j = 0; j < s; j++) sig.insert(sig.end(), a[j].begin(), a[j].end());
        for (size_t j = s + 1; j < s + 1 + p; j++) pk.insert(pk.end(), a[j].begin(), a[j].end());
        BOOST_CHECK_EQUAL(Hex(pk), doc["pqOwner"]["pk"].get_str());
        BOOST_REQUIRE(!sig.empty() && sig.back() == SIGHASH_ALL);
        const std::vector<unsigned char> bare(sig.begin(), sig.end() - 1);
        BOOST_CHECK_MESSAGE(pq::Verify(pq::SCHEME_SLH_DSA_SHA2_128S, pk, bare, sighash), name + ": pq::Verify");
        BOOST_CHECK(!pq::Verify(pq::SCHEME_SLH_DSA_SHA2_128S, pk, bare, shx));
        if (sp[i]["selector"].get_int() == SEL_OWNER) {
            // The whole OWNER branch through the interpreter: OP_CHECKPQSIG reads the ZIP-244 digest.
            TransactionSignatureChecker checker(&tx, txdata, nIn, prev[nIn].nValue);
            ScriptError err;
            BOOST_CHECK_MESSAGE(VerifyScript(tx.vin[nIn].scriptSig, prev[nIn].scriptPubKey, flags, checker, branch, &err),
                                name + ": " + ScriptErrorString(err));
        }
        CheckFeeInputs(tx, txdata, prev, branch, name);
    }
}

BOOST_AUTO_TEST_CASE(act_messages_and_set_id)
{
    UniValue doc = Vectors();
    const UniValue& acts = doc["acts"];
    BOOST_REQUIRE_EQUAL(acts.size(), 1u);
    for (size_t i = 0; i < acts.size(); i++) {
        const std::string name = acts[i]["name"].get_str();
        CTransaction tx = V5Tx(doc, acts[i]["tx"], name);
        BOOST_CHECK_EQUAL(Hex(tx.GetHash()), acts[i]["txid"].get_str());
        const COutPoint po = Prevout(acts[i]["prevout"]);
        BOOST_CHECK(tx.vin[0].prevout == po);
        const uint256 am = ActMsg(Bytes(acts[i]["payload"]), po);
        BOOST_CHECK_EQUAL(Hex(am), acts[i]["actMsg"].get_str());
        BOOST_CHECK_EQUAL(acts[i]["actMsg"].get_str(), acts[i]["actMsgV4"].get_str());
        Act a;
        BOOST_REQUIRE(!DecodeAct(tx.vout[0].scriptPubKey, a).has_value());
        BOOST_REQUIRE_EQUAL(a.sigs.size(), acts[i]["sigs"].size());
        for (size_t j = 0; j < a.sigs.size(); j++) {
            CPubKey k;
            BOOST_CHECK(RecoverSig(am, a.sigs[j], k));
        }
    }
    // setId is the creating transaction's txid: for a v5 SET_CREATE that is the ZIP-244 txid.
    const UniValue& sc = doc["setCreate"];
    CTransaction ctx = V5Tx(doc, sc["tx"], "setCreate");
    BOOST_CHECK_EQUAL(Hex(ctx.GetHash()), sc["setIdV5"].get_str());
    BOOST_CHECK(sc["setIdV5"].get_str() != sc["setIdV4"].get_str());
}

BOOST_AUTO_TEST_SUITE_END()
