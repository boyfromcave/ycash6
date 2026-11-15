// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The transparent value pools by address type (beta3 item 2, valuepools.h): the classifier's vectors, each pinned to
// Solver, and the per-block record as the ConnectBlock hook computes and stores it.

#include <gtest/gtest.h>

#include "chain.h"
#include "chainparams.h"
#include "crypto/pq/scheme.h"
#include "fs.h"
#include "pubkey.h"
#include "random.h"
#include "script/script.h"
#include "script/standard.h"
#include "streams.h"
#include "undo.h"
#include "util/strencodings.h"
#include "valuepools.h"
#include "vault/template.h"
#include "yellowback/script.h"

using valuepools::ClassifyTransparentScript;
using valuepools::PoolClass;
using valuepools::Record;

namespace {

CPubKey ServerKey()
{
    // The secp256k1 generator, compressed: a valid point.
    const std::vector<unsigned char> g = ParseHex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    return CPubKey(g.begin(), g.end());
}

uint256 Hash32(unsigned char b)
{
    uint256 h;
    memset(h.begin(), b, 32);
    return h;
}

vault::VaultParams SampleVault(const vault::Tag& tag)
{
    vault::VaultParams v;
    v.tag = tag;
    v.cancelSetId = Hash32(0x11);
    v.setId = Hash32(0x22);
    v.delay = 10;
    v.ownerHeight = 500;
    v.appHeight = 500;
    v.owner = CPQKeyID(pq::SCHEME_SLH_DSA_SHA2_128S, Hash32(0x33));
    return v;
}

vault::IntentParams SampleIntent(const vault::Tag& tag)
{
    vault::IntentParams p;
    p.tag = tag;
    p.recipientHash = Hash32(0x44);
    p.vaultHash = Hash32(0x55);
    p.delay = 10;
    p.cancelSetId = Hash32(0x11);
    p.setId = Hash32(0x22);
    p.owner = CPQKeyID(pq::SCHEME_FN_DSA_512, Hash32(0x66));
    return p;
}

const vault::Tag OTHER_TAG = {{'W', 'Y', 'E', 'C'}};

//! The class Solver's type implies (note §1.2): every type outside the four new shapes is ECC.
PoolClass ClassOfSolverType(txnouttype t)
{
    switch (t) {
        case TX_PQPKH:        return PoolClass::TRANSPARENT_PQ;
        case TX_PQCHANNEL:    return PoolClass::PQ_CHANNEL;
        case TX_VAULT:        return PoolClass::VAULT;
        case TX_VAULT_INTENT: return PoolClass::VAULT_INTENT;
        default:              return PoolClass::TRANSPARENT_ECC;
    }
}

struct Vector {
    const char* name;
    CScript script;
    PoolClass expected;
    uint8_t scheme;
    bool yed;
};

std::vector<Vector> Vectors()
{
    std::vector<Vector> v;
    CKeyID keyId(uint160(ParseHex("0102030405060708090a0b0c0d0e0f1011121314")));
    v.push_back({"p2pkh", GetScriptForDestination(keyId), PoolClass::TRANSPARENT_ECC, 0, false});
    v.push_back({"p2pk", GetScriptForRawPubKey(ServerKey()), PoolClass::TRANSPARENT_ECC, 0, false});
    CScript redeem = GetScriptForRawPubKey(ServerKey());
    v.push_back({"p2sh", GetScriptForDestination(CScriptID(redeem)), PoolClass::TRANSPARENT_ECC, 0, false});
    v.push_back({"multisig", GetScriptForMultisig(1, {ServerKey()}), PoolClass::TRANSPARENT_ECC, 0, false});
    v.push_back({"op_return", CScript() << OP_RETURN << ParseHex("deadbeef"), PoolClass::TRANSPARENT_ECC, 0, false});
    v.push_back({"nonstandard", CScript() << OP_TRUE, PoolClass::TRANSPARENT_ECC, 0, false});
    v.push_back({"empty", CScript(), PoolClass::TRANSPARENT_ECC, 0, false});

    const CPQKeyID slh(pq::SCHEME_SLH_DSA_SHA2_128S, Hash32(0x77));
    const CPQKeyID fn(pq::SCHEME_FN_DSA_512, Hash32(0x78));
    const CScript pq1 = GetScriptForPQKey(slh);
    const CScript pq2 = GetScriptForPQKey(fn);
    v.push_back({"pqpkh scheme 1", pq1, PoolClass::TRANSPARENT_PQ, 1, false});
    v.push_back({"pqpkh scheme 2", pq2, PoolClass::TRANSPARENT_PQ, 2, false});
    // Near misses: 34 and 36 bytes, scheme byte OP_3, a wrong last opcode.
    {
        CScript s34 = CScript() << std::vector<unsigned char>(31, 0x77) << OP_1 << OP_CHECKPQSIG;
        v.push_back({"pq shape 34 bytes", s34, PoolClass::TRANSPARENT_ECC, 0, false});
        CScript s36 = CScript() << std::vector<unsigned char>(33, 0x77) << OP_1 << OP_CHECKPQSIG;
        v.push_back({"pq shape 36 bytes", s36, PoolClass::TRANSPARENT_ECC, 0, false});
        CScript s3(pq1.begin(), pq1.end());
        s3[33] = OP_3;
        v.push_back({"pq scheme OP_3", s3, PoolClass::TRANSPARENT_ECC, 0, false});
        CScript sOp(pq1.begin(), pq1.end());
        sOp[34] = OP_CHECKSIG;
        v.push_back({"pq last opcode CHECKSIG", sOp, PoolClass::TRANSPARENT_ECC, 0, false});
    }

    const CScript channel = GetScriptForPQChannel(fn, ServerKey(), 1000);
    v.push_back({"pq channel", channel, PoolClass::PQ_CHANNEL, 0, false});
    {
        // The same shape with refundHeight 0 (out of range): built by hand, since the builder refuses it.
        CScript bad;
        bad << OP_IF << std::vector<unsigned char>(fn.hash.begin(), fn.hash.end()) << OP_2 << OP_CHECKPQSIG << OP_VERIFY
            << ToByteVector(ServerKey()) << OP_CHECKSIG << OP_ELSE << OP_0 << OP_CHECKLOCKTIMEVERIFY << OP_DROP
            << std::vector<unsigned char>(fn.hash.begin(), fn.hash.end()) << OP_2 << OP_CHECKPQSIG << OP_ENDIF;
        v.push_back({"pq channel bad height", bad, PoolClass::TRANSPARENT_ECC, 0, false});
        CScript flipped(channel.begin(), channel.end());
        flipped[5] ^= 0x01; // a byte of the client hash in the first slot only: the slots differ
        v.push_back({"pq channel slots differ", flipped, PoolClass::TRANSPARENT_ECC, 0, false});
    }

    const CScript vYed = vault::BuildVault(SampleVault(yellowback::YED_TAG));
    const CScript vOther = vault::BuildVault(SampleVault(OTHER_TAG));
    const CScript iYed = vault::BuildIntent(SampleIntent(yellowback::YED_TAG));
    const CScript iOther = vault::BuildIntent(SampleIntent(OTHER_TAG));
    v.push_back({"vault YED", vYed, PoolClass::VAULT, 0, true});
    v.push_back({"vault other tag", vOther, PoolClass::VAULT, 0, false});
    v.push_back({"intent YED", iYed, PoolClass::VAULT_INTENT, 0, true});
    v.push_back({"intent other tag", iOther, PoolClass::VAULT_INTENT, 0, false});
    {
        // One byte flipped: an opcode of the skeleton (OP_2DROP -> OP_NOP) and the owner's scheme byte (-> OP_3).
        CScript f1(vYed.begin(), vYed.end());
        for (size_t i = 0; i < f1.size(); i++) {
            if (f1[i] == OP_2DROP) { f1[i] = OP_NOP; break; }
        }
        v.push_back({"vault opcode flipped", f1, PoolClass::TRANSPARENT_ECC, 0, false});
        CScript f2(vYed.begin(), vYed.end());
        for (size_t i = 0; i + 1 < f2.size(); i++) {
            if (f2[i] == OP_1 && f2[i + 1] == OP_CHECKPQSIG) { f2[i] = OP_3; break; }
        }
        v.push_back({"vault owner scheme OP_3", f2, PoolClass::TRANSPARENT_ECC, 0, false});
        CScript f3(iYed.begin(), iYed.end());
        f3[f3.size() - 1] = OP_NOP;
        v.push_back({"intent last opcode flipped", f3, PoolClass::TRANSPARENT_ECC, 0, false});
        CScript f4(vYed.begin(), vYed.end());
        f4.push_back(OP_NOP);
        v.push_back({"vault one byte longer", f4, PoolClass::TRANSPARENT_ECC, 0, false});
    }
    return v;
}

CTransaction MakeTx(const std::vector<CTxOut>& vout, size_t nInputs, bool coinbase)
{
    CMutableTransaction mtx;
    if (coinbase) {
        mtx.vin.resize(1);
        mtx.vin[0].prevout.SetNull();
        mtx.vin[0].scriptSig = CScript() << OP_1 << OP_1;
    } else {
        for (size_t i = 0; i < nInputs; i++) {
            mtx.vin.push_back(CTxIn(COutPoint(GetRandHash(), i)));
        }
    }
    mtx.vout = vout;
    return CTransaction(mtx);
}

} // namespace

TEST(ValuePools, ClassifierVectorsAgreeWithSolver)
{
    for (const Vector& t : Vectors()) {
        SCOPED_TRACE(t.name);
        ASSERT_FALSE(t.script.empty() && std::string(t.name) != "empty");
        const valuepools::ScriptClass c = ClassifyTransparentScript(t.script);
        EXPECT_EQ((int)c.cls, (int)t.expected);
        EXPECT_EQ(c.pqScheme, t.scheme);
        EXPECT_EQ(c.yed, t.yed);

        txnouttype type;
        std::vector<std::vector<unsigned char>> sol;
        Solver(t.script, type, sol);
        EXPECT_EQ((int)ClassOfSolverType(type), (int)c.cls) << GetTxnOutputType(type);
        if (type == TX_PQPKH) {
            ASSERT_FALSE(sol.empty());
            EXPECT_EQ(sol[0].size(), 1u);
            EXPECT_EQ(sol[0][0], c.pqScheme);
        }
    }
}

TEST(ValuePools, ClassifierAgreesWithSolverOnMutations)
{
    // Every single-byte truncation and every one-byte change of the template vectors: the classifier and Solver
    // agree on each (the copy of MatchPayToPQKeyHash cannot drift from the original).
    for (const Vector& t : Vectors()) {
        if (t.expected == PoolClass::TRANSPARENT_ECC) continue;
        std::vector<CScript> mutants;
        mutants.push_back(CScript(t.script.begin(), t.script.end() - 1));
        for (size_t i = 0; i < t.script.size(); i++) {
            CScript m(t.script.begin(), t.script.end());
            m[i] ^= 0x01;
            mutants.push_back(m);
        }
        for (const CScript& m : mutants) {
            txnouttype type;
            std::vector<std::vector<unsigned char>> sol;
            Solver(m, type, sol);
            EXPECT_EQ((int)ClassOfSolverType(type), (int)ClassifyTransparentScript(m).cls) << t.name << " " << HexStr(m);
        }
    }
}

TEST(ValuePools, RecordSerialization)
{
    Record r;
    r.transparent = 1053104265390951;
    r.pq1 = 1;
    r.pq2 = 2;
    r.channel = 3;
    r.vault = 40;
    r.intent = 50;
    r.vaultYed = 4;
    r.intentYed = 5;
    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << r;
    Record back;
    ss >> back;
    EXPECT_TRUE(back == r);
    EXPECT_EQ(r.TransparentECC(), r.transparent - 1 - 2 - 3 - 40 - 50);

    Record empty;
    CDataStream ss2(SER_DISK, PROTOCOL_VERSION);
    ss2 << empty;
    EXPECT_EQ(ss2.size(), 9u); // a version byte and eight one-byte zero VARINTs
}

TEST(ValuePools, ApplyBlockSumsAndChecksUndo)
{
    const CScript ecc = GetScriptForDestination(CKeyID(uint160(ParseHex("0102030405060708090a0b0c0d0e0f1011121314"))));
    const CScript pq1 = GetScriptForPQKey(CPQKeyID(pq::SCHEME_SLH_DSA_SHA2_128S, Hash32(0x77)));
    const CScript pq2 = GetScriptForPQKey(CPQKeyID(pq::SCHEME_FN_DSA_512, Hash32(0x78)));
    const CScript vYed = vault::BuildVault(SampleVault(yellowback::YED_TAG));
    const CScript iOther = vault::BuildIntent(SampleIntent(OTHER_TAG));

    CBlock b1;
    b1.vtx.push_back(MakeTx({CTxOut(100, ecc), CTxOut(20, pq1), CTxOut(30, pq2), CTxOut(40, vYed), CTxOut(5, iOther)}, 0, true));
    Record r1;
    std::string err;
    ASSERT_TRUE(valuepools::ApplyBlock(Record(), b1, CBlockUndo(), r1, err)) << err;
    EXPECT_EQ(r1.transparent, 195);
    EXPECT_EQ(r1.pq1, 20);
    EXPECT_EQ(r1.pq2, 30);
    EXPECT_EQ(r1.vault, 40);
    EXPECT_EQ(r1.vaultYed, 40);
    EXPECT_EQ(r1.intent, 5);
    EXPECT_EQ(r1.intentYed, 0);
    EXPECT_EQ(r1.TransparentECC(), 100);

    // Block 2 spends the vault and the PQ scheme-2 output into an ECC output and a fee of 1.
    CBlock b2;
    b2.vtx.push_back(MakeTx({CTxOut(1, ecc)}, 0, true));
    b2.vtx.push_back(MakeTx({CTxOut(69, ecc)}, 2, false));
    CBlockUndo u2;
    u2.vtxundo.resize(1);
    u2.vtxundo[0].vprevout.push_back(CTxInUndo(CTxOut(40, vYed)));
    u2.vtxundo[0].vprevout.push_back(CTxInUndo(CTxOut(30, pq2)));
    Record r2;
    ASSERT_TRUE(valuepools::ApplyBlock(r1, b2, u2, r2, err)) << err;
    EXPECT_EQ(r2.transparent, 195 - 70 + 70);
    EXPECT_EQ(r2.pq2, 0);
    EXPECT_EQ(r2.vault, 0);
    EXPECT_EQ(r2.vaultYed, 0);
    EXPECT_EQ(r2.TransparentECC(), 170);

    // Undo data that does not match the block, and a spend the parent does not hold: refused, never thrown.
    CBlockUndo short2 = u2;
    short2.vtxundo[0].vprevout.pop_back();
    EXPECT_FALSE(valuepools::ApplyBlock(r1, b2, short2, r2, err));
    EXPECT_FALSE(valuepools::ApplyBlock(r1, b2, CBlockUndo(), r2, err));
    EXPECT_FALSE(valuepools::ApplyBlock(Record(), b2, u2, r2, err)); // the vault would go negative
}

TEST(ValuePools, HookStoresRecordsAndNeverThrows)
{
    SelectParams(CBaseChainParams::REGTEST);
    const fs::path dir = fs::temp_directory_path() / fs::unique_path("valuepools-%%%%-%%%%");
    valuepools::Open(dir, true);
    ASSERT_TRUE(valuepools::IsOpen());

    const CBlock& genesis = Params().GenesisBlock();
    uint256 hGenesis = genesis.GetHash();
    CBlockIndex iGenesis;
    iGenesis.phashBlock = &hGenesis;
    iGenesis.nHeight = 0;
    const std::optional<Record> rGenesis = valuepools::GetRecord(&iGenesis);
    ASSERT_TRUE(rGenesis.has_value());
    EXPECT_EQ(rGenesis->transparent, genesis.vtx[0].GetValueOut());

    const CScript pq1 = GetScriptForPQKey(CPQKeyID(pq::SCHEME_SLH_DSA_SHA2_128S, Hash32(0x77)));
    CBlock b1;
    b1.vtx.push_back(MakeTx({CTxOut(500, pq1)}, 0, true));
    uint256 h1 = GetRandHash();
    CBlockIndex i1;
    i1.phashBlock = &h1;
    i1.pprev = &iGenesis;
    i1.nHeight = 1;
    valuepools::BlockConnected(b1, CBlockUndo(), &i1);
    std::optional<Record> r1 = valuepools::GetRecord(&i1);
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(r1->pq1, 500);
    EXPECT_EQ(r1->transparent, rGenesis->transparent + 500);

    // A block whose undo data is wrong: no record, nothing thrown, and its child is not covered either.
    CBlock b2;
    b2.vtx.push_back(MakeTx({CTxOut(1, pq1)}, 0, true));
    b2.vtx.push_back(MakeTx({CTxOut(1, pq1)}, 1, false));
    uint256 h2 = GetRandHash();
    CBlockIndex i2;
    i2.phashBlock = &h2;
    i2.pprev = &i1;
    i2.nHeight = 2;
    valuepools::BlockConnected(b2, CBlockUndo(), &i2);
    EXPECT_FALSE(valuepools::GetRecord(&i2).has_value());
    uint256 h3 = GetRandHash();
    CBlockIndex i3;
    i3.phashBlock = &h3;
    i3.pprev = &i2;
    i3.nHeight = 3;
    valuepools::BlockConnected(b1, CBlockUndo(), &i3);
    EXPECT_FALSE(valuepools::GetRecord(&i3).has_value());

    // The JSON: the pools sum to the total, both schemes are listed, YED is the one module.
    UniValue j = valuepools::TransparentPoolsToJSON(&i1, true);
    EXPECT_TRUE(j["monitored"].get_bool());
    EXPECT_EQ(j["transparent"]["valueDeltaZat"].get_int64(), 500);
    CAmount sum = 0;
    for (size_t k = 0; k < j["pools"].size(); k++) sum += j["pools"][k]["chainValueZat"].get_int64();
    EXPECT_EQ(sum, j["transparent"]["chainValueZat"].get_int64());
    EXPECT_EQ(j["pq_by_scheme"].size(), 2u);
    EXPECT_EQ(j["pq_by_scheme"][0]["pqscheme"].get_int(), 1);
    EXPECT_EQ(j["pq_by_scheme"][0]["chainValueZat"].get_int64(), 500);
    EXPECT_EQ(j["vault_by_module"][0]["tag"].get_str(), "59454400");
    UniValue j3 = valuepools::TransparentPoolsToJSON(&i3, true);
    EXPECT_FALSE(j3["monitored"].get_bool());
    EXPECT_FALSE(j3["pools"][0]["monitored"].get_bool());

    // Closed: the hook is a no-op.
    valuepools::Close();
    valuepools::BlockConnected(b1, CBlockUndo(), &i3);
    fs::remove_all(dir);
}
