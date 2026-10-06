// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The vault primitive's golden vector (docs/plans/yellowback-upgrade-plan.md §15.9):
// src/test/data/vault_vectors.json, written by
// qa/rpc-tests/test_framework/gen_vault_vectors.py from fixed keys by the pure-Python
// implementation (test_framework/vault.py), replayed here against the C++ in src/vault/.
// The JSON is byte-identical on both node lines; its schema is in the generator's
// docstring and in qa/rpc-tests/test_framework/VAULT_VECTORS.md.
//
// ---------------------------------------------------------------------------------------
// C++ API THIS FILE ASSUMES (integration agent: reconcile, then register the file and the
// JSON in src/Makefile.test.include: JSON_TEST_FILES += test/data/vault_vectors.json,
// BITCOIN_TESTS += test/vault_vectors_tests.cpp).
//
// Names below were aligned with the headers of up/up-core-dd a28aff063 (src/vault/
// template.h, act.h); the brief's names map as
//   vault::BuildVault / ParseVault      -> CScript BuildVault(const VaultParams&),
//                                          bool ParseVault(const CScript&, VaultParams&)
//   vault::BuildIntent / ParseIntent    -> same shape with IntentParams
//   vault::EncodeAct / DecodeAct        -> std::vector<unsigned char> EncodePayload(const Act&),
//                                          std::optional<std::string> DecodePayload(P, Act&),
//                                          CScript EncodeAct(const Act&),
//                                          std::optional<std::string> DecodeAct(const CScript&, Act&)
//   vault::ActMsg / SetSigMsg           -> uint256 ActMsg(P, COutPoint), SetSigMsg(setId, role, COutPoint, sighash)
//   vault::RecoverSetSig                -> bool RecoverSig(const uint256&, const std::vector<unsigned char>&, CPubKey&)
// plus BuildBondRedeem / ParseBondRedeem / BondScriptPubKey, ParseTemplateSpend,
// SetCreateBody::Valid().
//
// ASSUMED, NOT IN THOSE HEADERS (core agent adds it under this exact name, A-9 reconciled):
//   bool vault::ActFieldsValid(const vault::Act&)   the context-free field rules of §15.5
//       (SET_CREATE ranges/flags, bondLocktime < 500000000, burn in {0,1}, roles in {1,2},
//       equivocation signature headers 31..34). Python rejects these at decode; if C++
//       rejects them in DecodePayload the call below is never reached for them.
//
// D-1 reconciled 2026-10-05 (plan §15): 1 <= bondMin <= MAX_MONEY; the vector's
// "bond-min-above-max-money" is a stage "field" rejection.
//
// A scratch replay of this JSON against up/up-core-dd a28aff063's objects (2026-10-05, 233
// checks) agreed on every template, intent, bond, selector, act, message, signature
// (CKey::SignCompact == Python) and ZIP-243 sighash, except D-1; and its DecodePayload accepts
// the stage "field" cases join-locktime-500000000, remove-burn-2, equivocation-role-0/-3 and
// equivocation-sig-header-27 (they must then be rejected at rule time).
// ---------------------------------------------------------------------------------------

#include "vault/act.h"
#include "vault/template.h"

#include "core_io.h"
#include "key.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "test/data/vault_vectors.json.h"
#include "test/test_bitcoin.h"
#include "univalue.h"
#include "util/strencodings.h"

#include <boost/test/unit_test.hpp>

using namespace vault;

namespace {

UniValue Vectors()
{
    UniValue doc;
    BOOST_REQUIRE(doc.read(std::string(json_tests::vault_vectors, json_tests::vault_vectors + sizeof(json_tests::vault_vectors))));
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
    return uint256(b); // internal byte order, as the JSON
}

std::string Hex(const uint256& u) { return HexStr(u.begin(), u.end()); }
std::string Hex(const CScript& s) { return HexStr(s.begin(), s.end()); }
std::string Hex(const std::vector<unsigned char>& b) { return HexStr(b.begin(), b.end()); }
std::string Hex(const CPubKey& k) { return HexStr(k.begin(), k.end()); }

Tag TagOf(const UniValue& v)
{
    std::vector<unsigned char> b = Bytes(v);
    BOOST_REQUIRE_EQUAL(b.size(), 4u);
    Tag t;
    std::copy(b.begin(), b.end(), t.begin());
    return t;
}

COutPoint Prevout(const UniValue& v)
{
    std::vector<unsigned char> b = Bytes(v);
    BOOST_REQUIRE_EQUAL(b.size(), 36u);
    uint32_t n = b[32] | (b[33] << 8) | (b[34] << 16) | ((uint32_t)b[35] << 24);
    return COutPoint(uint256(std::vector<unsigned char>(b.begin(), b.begin() + 32)), n);
}

VaultParams VaultOf(const UniValue& p)
{
    VaultParams v;
    v.tag = TagOf(p["tag"]);
    v.setId = U256(p["setId"]);
    v.cancelSetId = U256(p["cancelSetId"]);
    v.delay = p["delay"].get_int64();
    v.ownerHeight = p["ownerHeight"].get_int64();
    v.appHeight = p["appHeight"].get_int64();
    v.ownerKey = CPubKey(Bytes(p["ownerKey"]));
    return v;
}

IntentParams IntentOf(const UniValue& p)
{
    IntentParams i;
    i.tag = TagOf(p["tag"]);
    i.recipientHash = U256(p["recipientHash"]);
    i.vaultHash = U256(p["vaultHash"]);
    i.delay = p["delay"].get_int64();
    i.cancelSetId = U256(p["cancelSetId"]);
    i.setId = U256(p["setId"]);
    i.ownerKey = CPubKey(Bytes(p["ownerKey"]));
    return i;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(vault_vectors_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(constants)
{
    UniValue doc = Vectors();
    BOOST_CHECK_EQUAL(doc["branchId"].get_int64(), 0x6d5b7a31);
    BOOST_CHECK_EQUAL(doc["opcodes"]["CHECKSEQUENCEVERIFY"].get_int(), (int)VAULT_OP_CHECKSEQUENCEVERIFY);
    BOOST_CHECK_EQUAL(doc["opcodes"]["CHECKSETSIG"].get_int(), (int)VAULT_OP_CHECKSETSIG);
    BOOST_CHECK_EQUAL(doc["opcodes"]["CHECKSETDORMANT"].get_int(), (int)VAULT_OP_CHECKSETDORMANT);
}

BOOST_AUTO_TEST_CASE(vault_templates)
{
    UniValue doc = Vectors();
    const UniValue& ok = doc["vaults"];
    for (size_t i = 0; i < ok.size(); i++) {
        const std::string name = ok[i]["name"].get_str();
        VaultParams want = VaultOf(ok[i]["params"]);
        CScript spk = Script(ok[i]["script"]);
        BOOST_CHECK_MESSAGE(Hex(BuildVault(want)) == ok[i]["script"].get_str(), "BuildVault " + name);
        VaultParams got;
        BOOST_CHECK_MESSAGE(ParseVault(spk, got), "ParseVault " + name);
        BOOST_CHECK_MESSAGE(got == want, "ParseVault fields " + name);
        IntentParams ip;
        BOOST_CHECK_MESSAGE(!ParseIntent(spk, ip), "a V is not an I " + name);
    }
    const UniValue& bad = doc["vaultsInvalid"];
    for (size_t i = 0; i < bad.size(); i++) {
        VaultParams got;
        BOOST_CHECK_MESSAGE(!ParseVault(Script(bad[i]["script"]), got), "ParseVault accepted " + bad[i]["name"].get_str());
    }
}

BOOST_AUTO_TEST_CASE(intent_templates)
{
    UniValue doc = Vectors();
    const UniValue& ok = doc["intents"];
    for (size_t i = 0; i < ok.size(); i++) {
        const std::string name = ok[i]["name"].get_str();
        IntentParams want = IntentOf(ok[i]["params"]);
        CScript spk = Script(ok[i]["script"]);
        BOOST_CHECK_MESSAGE(Hex(BuildIntent(want)) == ok[i]["script"].get_str(), "BuildIntent " + name);
        IntentParams got;
        BOOST_REQUIRE_MESSAGE(ParseIntent(spk, got), "ParseIntent " + name);
        BOOST_CHECK(got.tag == want.tag && got.recipientHash == want.recipientHash && got.vaultHash == want.vaultHash &&
                    got.delay == want.delay && got.cancelSetId == want.cancelSetId && got.setId == want.setId &&
                    got.ownerKey == want.ownerKey);
        // recipientHash / vaultHash are single SHA256 of the scripts; IntentFor reproduces the I
        CScript vspk = Script(ok[i]["vaultScript"]);
        CScript rspk = Script(ok[i]["recipientScript"]);
        BOOST_CHECK_EQUAL(Hex(ScriptHash256(rspk)), Hex(want.recipientHash));
        BOOST_CHECK_EQUAL(Hex(ScriptHash256(vspk)), Hex(want.vaultHash));
        VaultParams vp;
        BOOST_REQUIRE(ParseVault(vspk, vp));
        BOOST_CHECK_EQUAL(Hex(BuildIntent(IntentFor(vp, vspk, rspk))), ok[i]["script"].get_str());
    }
    const UniValue& bad = doc["intentsInvalid"];
    for (size_t i = 0; i < bad.size(); i++) {
        IntentParams got;
        BOOST_CHECK_MESSAGE(!ParseIntent(Script(bad[i]["script"]), got), "ParseIntent accepted " + bad[i]["name"].get_str());
    }
}

BOOST_AUTO_TEST_CASE(bond_templates)
{
    UniValue doc = Vectors();
    const UniValue& b = doc["bonds"];
    for (size_t i = 0; i < b.size(); i++) {
        CPubKey key(Bytes(b[i]["memberKey"]));
        uint32_t lt = b[i]["locktime"].get_int64();
        BOOST_CHECK_EQUAL(Hex(BuildBondRedeem(lt, key)), b[i]["redeem"].get_str());
        BOOST_CHECK_EQUAL(Hex(BondScriptPubKey(lt, key)), b[i]["spk"].get_str());
        uint32_t lt2 = 0;
        CPubKey key2;
        BOOST_CHECK(ParseBondRedeem(Script(b[i]["redeem"]), lt2, key2));
        BOOST_CHECK_EQUAL(lt2, lt);
        BOOST_CHECK(key2 == key);
    }
}

BOOST_AUTO_TEST_CASE(selectors)
{
    UniValue doc = Vectors();
    // a V and an I to spend: the selector range depends on the kind (V 1..4, I 1..3)
    CScript vspk = Script(doc["vaults"][0]["script"]);
    CScript ispk = Script(doc["intents"][0]["script"]);
    const UniValue& ok = doc["selectors"];
    for (size_t i = 0; i < ok.size(); i++) {
        const bool isV = ok[i]["kind"].get_str() == "V";
        CScript ss = Script(ok[i]["scriptSig"]);
        std::optional<TemplateSpend> ts = ParseTemplateSpend(isV ? vspk : ispk, ss);
        BOOST_REQUIRE_MESSAGE(ts.has_value(), "selector " + ok[i]["scriptSig"].get_str());
        BOOST_CHECK_EQUAL(ts->selector, ok[i]["selector"].get_int());
        BOOST_CHECK_EQUAL(ts->sigs.size(), (size_t)ok[i]["nArgs"].get_int());
        BOOST_CHECK(ts->kind == (isV ? TemplateKind::VAULT : TemplateKind::INTENT));
    }
    const UniValue& bad = doc["selectorsInvalid"];
    for (size_t i = 0; i < bad.size(); i++) {
        const bool isV = bad[i]["kind"].get_str() == "V";
        BOOST_CHECK_MESSAGE(!ParseTemplateSpend(isV ? vspk : ispk, Script(bad[i]["scriptSig"])).has_value(),
                            "selector accepted: " + bad[i]["reason"].get_str());
    }
}

BOOST_AUTO_TEST_CASE(acts)
{
    UniValue doc = Vectors();
    const UniValue& ok = doc["acts"];
    for (size_t i = 0; i < ok.size(); i++) {
        const std::string name = ok[i]["name"].get_str();
        std::vector<unsigned char> P = Bytes(ok[i]["payload"]);
        Act act;
        std::optional<std::string> err = DecodePayload(P, act);
        BOOST_REQUIRE_MESSAGE(!err, "DecodePayload " + name + ": " + err.value_or(""));
        BOOST_CHECK_EQUAL(act.type, ok[i]["type"].get_int());
        BOOST_CHECK_MESSAGE(Hex(EncodePayload(act)) == ok[i]["payload"].get_str(), "EncodePayload " + name);
        BOOST_CHECK_MESSAGE(Hex(ActMsg(P, Prevout(ok[i]["prevout"]))) == ok[i]["actMsg"].get_str(), "ActMsg " + name);

        // the full OP_RETURN with its signatures, and each signature's recovered key
        Act full;
        CScript script = Script(ok[i]["script"]);
        BOOST_CHECK(IsActOutput(script));
        err = DecodeAct(script, full);
        BOOST_REQUIRE_MESSAGE(!err, "DecodeAct " + name + ": " + err.value_or(""));
        BOOST_CHECK_EQUAL(full.sigs.size(), ok[i]["sigs"].size());
        BOOST_CHECK_MESSAGE(Hex(EncodeAct(full)) == ok[i]["script"].get_str(), "EncodeAct " + name);
        uint256 msg = U256(ok[i]["actMsg"]);
        for (size_t j = 0; j < ok[i]["sigs"].size(); j++) {
            CPubKey k;
            BOOST_CHECK(RecoverSig(msg, Bytes(ok[i]["sigs"][j]), k));
            BOOST_CHECK_EQUAL(Hex(k), ok[i]["recovered"][j].get_str());
        }

        const UniValue& f = ok[i]["fields"];
        switch (act.type) {
        case ACT_SET_CREATE:
            BOOST_CHECK_EQUAL(act.create.seats, f["seats"].get_int());
            BOOST_CHECK_EQUAL(act.create.rateLimitBps, f["rateLimitBps"].get_int());
            BOOST_CHECK_EQUAL(act.create.rateWindow, (uint32_t)f["rateWindow"].get_int64());
            BOOST_CHECK_EQUAL(act.create.bondMin, f["bondMin"].get_int64());
            BOOST_CHECK_EQUAL(act.create.maturity, (uint32_t)f["maturity"].get_int64());
            BOOST_CHECK_EQUAL(Hex(act.create.admitKey), f["admitKey"].get_str());
            BOOST_CHECK(act.create.Valid());
            break;
        case ACT_SET_JOIN:
            BOOST_CHECK_EQUAL(Hex(act.join.setId), f["setId"].get_str());
            BOOST_CHECK_EQUAL(Hex(act.join.memberKey), f["memberKey"].get_str());
            BOOST_CHECK_EQUAL(act.join.bondLocktime, (uint32_t)f["bondLocktime"].get_int64());
            BOOST_CHECK_EQUAL(act.join.bondVout, f["bondVout"].get_int());
            break;
        case ACT_SET_REMOVE:
            BOOST_CHECK_EQUAL(act.remove.burn, f["burn"].get_int());
            break;
        case ACT_SET_EQUIVOCATION: {
            // both signatures recover to the convicted key over their §15.2 messages
            const SetEquivocationBody& e = act.equivocation;
            CPubKey ka, kb;
            BOOST_CHECK(RecoverSig(SetSigMsg(e.setId, e.roleA, e.prevout, e.sighashA), e.sigA, ka));
            BOOST_CHECK(RecoverSig(SetSigMsg(e.setId, e.roleB, e.prevout, e.sighashB), e.sigB, kb));
            BOOST_CHECK_EQUAL(Hex(ka), ok[i]["convicts"].get_str());
            BOOST_CHECK_EQUAL(Hex(kb), ok[i]["convicts"].get_str());
            break;
        }
        default:
            BOOST_CHECK_EQUAL(Hex(act.TargetSet()), f["setId"].get_str());
        }
    }

    const UniValue& bad = doc["actsInvalid"];
    for (size_t i = 0; i < bad.size(); i++) {
        const std::string name = bad[i]["name"].get_str();
        Act act;
        std::optional<std::string> err = DecodePayload(Bytes(bad[i]["payload"]), act);
        if (bad[i]["stage"].get_str() == "decode") {
            BOOST_CHECK_MESSAGE(err.has_value(), "DecodePayload accepted " + name);
        } else {
            BOOST_CHECK_MESSAGE(err.has_value() || !ActFieldsValid(act), "field rule not enforced: " + name);
        }
    }
    const UniValue& sbad = doc["actScriptsInvalid"];
    for (size_t i = 0; i < sbad.size(); i++) {
        Act act;
        BOOST_CHECK_MESSAGE(DecodeAct(Script(sbad[i]["script"]), act).has_value(),
                            "DecodeAct accepted " + sbad[i]["name"].get_str());
    }
}

BOOST_AUTO_TEST_CASE(set_sig_messages)
{
    UniValue doc = Vectors();
    const UniValue& m = doc["setSigMsgs"];
    for (size_t i = 0; i < m.size(); i++) {
        uint256 got = SetSigMsg(U256(m[i]["setId"]), m[i]["role"].get_int(), Prevout(m[i]["prevout"]), U256(m[i]["sighash"]));
        BOOST_CHECK_EQUAL(Hex(got), m[i]["msg"].get_str());
    }
}

BOOST_AUTO_TEST_CASE(recoverable_signatures)
{
    UniValue doc = Vectors();
    const UniValue& s = doc["signatures"];
    for (size_t i = 0; i < s.size(); i++) {
        std::vector<unsigned char> secret = Bytes(s[i]["secret"]);
        CKey key;
        key.Set(secret.begin(), secret.end(), true);
        BOOST_REQUIRE(key.IsValid());
        BOOST_CHECK_EQUAL(Hex(key.GetPubKey()), s[i]["pubkey"].get_str());
        uint256 msg = U256(s[i]["msg"]);
        // libsecp256k1's default RFC 6979 nonce: the Python signature byte for byte
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(key.SignCompact(msg, sig));
        BOOST_CHECK_EQUAL(Hex(sig), s[i]["sig"].get_str());
        std::vector<unsigned char> sig2;
        BOOST_REQUIRE(SignRecoverable(key, msg, sig2));
        BOOST_CHECK_EQUAL(Hex(sig2), s[i]["sig"].get_str());
        CPubKey rec;
        BOOST_CHECK(RecoverSig(msg, Bytes(s[i]["sig"]), rec));
        BOOST_CHECK_EQUAL(Hex(rec), s[i]["pubkey"].get_str());
    }
    const UniValue& bad = doc["signaturesInvalid"];
    for (size_t i = 0; i < bad.size(); i++) {
        CPubKey rec;
        BOOST_CHECK_MESSAGE(!RecoverSig(U256(bad[i]["msg"]), Bytes(bad[i]["sig"]), rec),
                            "RecoverSig accepted " + bad[i]["name"].get_str());
        // the stock non-strict recovery agrees with the vector where it recovers at all
        if (!bad[i]["nonStrictRecovers"].isNull()) {
            CPubKey loose;
            BOOST_CHECK(loose.RecoverCompact(U256(bad[i]["msg"]), Bytes(bad[i]["sig"])));
            BOOST_CHECK_EQUAL(Hex(loose), bad[i]["nonStrictRecovers"].get_str());
        }
    }
}

BOOST_AUTO_TEST_CASE(template_spends)
{
    UniValue doc = Vectors();
    const UniValue& sp = doc["spends"];
    for (size_t i = 0; i < sp.size(); i++) {
        const std::string name = sp[i]["name"].get_str();
        CTransaction tx;
        BOOST_REQUIRE_NO_THROW(DecodeHexTx(tx, sp[i]["tx"].get_str()));
        unsigned int nIn = sp[i]["nIn"].get_int();
        CScript code = Script(sp[i]["scriptCode"]);
        CAmount amount = sp[i]["amount"].get_int64();
        uint32_t branch = sp[i]["branchId"].get_int64();
        // v4 (ZIP-243): the precomputed hashes come from the transaction alone; the previous
        // outputs are only read for v5 (ZIP-244) transactions.
        PrecomputedTransactionData txdata(tx, std::vector<CTxOut>(tx.vin.size(), CTxOut(amount, code)));
        uint256 sighash = SignatureHash(code, tx, nIn, SIGHASH_ALL, amount, branch, txdata);
        BOOST_CHECK_MESSAGE(Hex(sighash) == sp[i]["sighash"].get_str(), "ZIP-243 sighash under the vault branch " + name);
        uint256 msg = SetSigMsg(U256(sp[i]["setId"]), sp[i]["role"].get_int(), tx.vin[nIn].prevout, sighash);
        BOOST_CHECK_EQUAL(Hex(msg), sp[i]["setSigMsg"].get_str());
        BOOST_CHECK_EQUAL(Hex(tx.vin[nIn].scriptSig), sp[i]["scriptSig"].get_str());
        std::optional<TemplateSpend> ts = ParseTemplateSpend(code, tx.vin[nIn].scriptSig);
        BOOST_REQUIRE(ts.has_value());
        BOOST_CHECK_EQUAL(ts->selector, sp[i]["role"].get_int()); // UNLOCK = selector 1 role 1; CANCEL = 2, 2
        BOOST_REQUIRE_EQUAL(ts->sigs.size(), sp[i]["sigs"].size());
        for (size_t j = 0; j < ts->sigs.size(); j++) {
            BOOST_CHECK_EQUAL(Hex(ts->sigs[j]), sp[i]["sigs"][j].get_str());
            CPubKey k;
            BOOST_CHECK(RecoverSig(msg, ts->sigs[j], k));
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
