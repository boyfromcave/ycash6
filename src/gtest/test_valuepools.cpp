// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The transparent value pools by address type (beta3 item 2, valuepools.h): the classifier's vectors, each pinned to
// Solver, and the per-block record as the ConnectBlock hook computes and stores it.

#include <gtest/gtest.h>

#include "chain.h"
#include "chainparams.h"
#include "clientversion.h"
#include "crypto/pq/scheme.h"
#include "fs.h"
#include "main.h"
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

#include <limits>

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

TEST(ValuePools, RecordReadRefusesUnknownVersionAndCorruptTotals)
{
    // An unknown record version does not deserialize, so a store written by a later format reads as "no record".
    uint64_t version2 = 2, version1 = 1, zero = 0, huge = 0xffffffffffffff00ULL;
    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << VARINT(version2);
    for (int i = 0; i < 8; i++) ss << VARINT(zero);
    Record r;
    EXPECT_THROW(ss >> r, std::ios_base::failure);

    // A corrupt total (a VARINT above INT64_MAX reads as a negative amount) is not sane, and a block applied to it is
    // refused rather than computed: no signed overflow, whatever the store or the undo data holds.
    CDataStream ss2(SER_DISK, PROTOCOL_VERSION);
    ss2 << VARINT(version1) << VARINT(huge);
    for (int i = 0; i < 7; i++) ss2 << VARINT(zero);
    Record bad;
    ss2 >> bad;
    EXPECT_FALSE(bad.IsSane());
    std::string err;
    Record out;
    CBlock cb;
    cb.vtx.push_back(MakeTx({CTxOut(1, CScript() << OP_TRUE)}, 0, true));
    EXPECT_FALSE(valuepools::ApplyBlock(bad, cb, CBlockUndo(), out, err));

    // Undo data whose spent value is out of range: refused before it is subtracted.
    Record parent;
    parent.transparent = MAX_MONEY - 10;
    CBlock b;
    b.vtx.push_back(MakeTx({CTxOut(1, CScript() << OP_TRUE)}, 0, true));
    b.vtx.push_back(MakeTx({CTxOut(1, CScript() << OP_TRUE)}, 1, false));
    CBlockUndo u;
    u.vtxundo.resize(1);
    u.vtxundo[0].vprevout.push_back(CTxInUndo(CTxOut(std::numeric_limits<CAmount>::max(), CScript() << OP_TRUE)));
    EXPECT_FALSE(valuepools::ApplyBlock(parent, b, u, out, err));
    EXPECT_NE(err.find("out of range"), std::string::npos) << err;
}

TEST(ValuePools, CompiledSeedIsTheCheckedCheckpoint)
{
    // The 6.20.0 node line seeds mainnet at the chain-supply checkpoint whose claim was checked (no template-shaped
    // output below it); ycash-dd, which has no checkpoint, seeds nothing. Regtest has no seed on either line.
    SelectParams(CBaseChainParams::MAIN);
    const std::optional<valuepools::Seed> seed = valuepools::CompiledSeed(Params());
    if (CLIENT_VERSION_MAJOR >= 6) {
        ASSERT_TRUE(seed.has_value());
        EXPECT_EQ(seed->height, 2800000);
        EXPECT_EQ(seed->hash, uint256S("000003170414909d5104f4a71708eca4e5b545d231c412c2d3e0e3f33874facb"));
        Record expected;
        expected.transparent = 1053104265390951;
        EXPECT_TRUE(seed->record == expected);
    } else {
        EXPECT_FALSE(seed.has_value());
    }
    SelectParams(CBaseChainParams::REGTEST);
    EXPECT_FALSE(valuepools::CompiledSeed(Params()).has_value());
}

namespace {

//! A fake active chain on regtest: the genesis block and `n` blocks whose data and undo data the fill reads through
//! the test hook. Removed from chainActive and mapBlockIndex on destruction.
struct FakeChain {
    std::vector<uint256> hashes;
    std::vector<std::unique_ptr<CBlockIndex>> index;
    std::vector<CBlock> blocks;
    std::vector<CBlockUndo> undos;
    std::vector<Record> expected; //!< ApplyBlock along the chain

    explicit FakeChain(int n)
    {
        const CScript ecc = GetScriptForDestination(CKeyID(uint160(ParseHex("0102030405060708090a0b0c0d0e0f1011121314"))));
        const CScript pq2 = GetScriptForPQKey(CPQKeyID(pq::SCHEME_FN_DSA_512, Hash32(0x79)));
        const CScript v = vault::BuildVault(SampleVault(yellowback::YED_TAG));
        hashes.resize(n + 1);
        hashes[0] = Params().GenesisBlock().GetHash();
        blocks.push_back(Params().GenesisBlock());
        undos.push_back(CBlockUndo());
        Record r0;
        std::string err;
        EXPECT_TRUE(valuepools::ApplyBlock(Record(), blocks[0], undos[0], r0, err)) << err;
        expected.push_back(r0);
        for (int h = 1; h <= n; h++) {
            hashes[h] = GetRandHash();
            CBlock b;
            CBlockUndo u;
            b.vtx.push_back(MakeTx({CTxOut(1000, pq2), CTxOut(300, v)}, 0, true));
            if (h >= 2) {
                // Spend the previous block's PQ and vault outputs into ECC (fee 10).
                b.vtx.push_back(MakeTx({CTxOut(1290, ecc)}, 2, false));
                u.vtxundo.resize(1);
                u.vtxundo[0].vprevout.push_back(CTxInUndo(CTxOut(1000, pq2)));
                u.vtxundo[0].vprevout.push_back(CTxInUndo(CTxOut(300, v)));
            }
            Record r;
            EXPECT_TRUE(valuepools::ApplyBlock(expected.back(), b, u, r, err)) << err;
            blocks.push_back(b);
            undos.push_back(u);
            expected.push_back(r);
        }
        for (int h = 0; h <= n; h++) {
            std::unique_ptr<CBlockIndex> i(new CBlockIndex());
            i->phashBlock = &hashes[h];
            i->nHeight = h;
            i->pprev = h ? index[h - 1].get() : nullptr;
            i->nStatus = BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO;
            i->BuildSkip();
            index.push_back(std::move(i));
        }
        LOCK(cs_main);
        for (int h = 0; h <= n; h++) mapBlockIndex[hashes[h]] = index[h].get();
        chainActive.SetTip(index[n].get());
        std::map<uint256, size_t> byHash;
        for (int h = 0; h <= n; h++) byHash[hashes[h]] = h;
        valuepools::test::SetBlockReader([this, byHash](const CBlockIndex* p, CBlock& block, CBlockUndo& undo) {
            auto it = byHash.find(p->GetBlockHash());
            if (it == byHash.end()) return false;
            block = blocks[it->second];
            undo = undos[it->second];
            return true;
        });
    }
    ~FakeChain()
    {
        LOCK(cs_main);
        chainActive.SetTip(nullptr);
        for (const uint256& h : hashes) mapBlockIndex.erase(h);
        valuepools::test::Reset();
    }
    const CBlockIndex* at(int h) const { return index[h].get(); }
};

bool FillNow(std::string& err)
{
    LOCK(cs_main);
    return valuepools::Fill(Params(), []() { return false; }, err);
}

} // namespace

TEST(ValuePools, FillFromGenesisFromTheSeedAndTheSeedCheck)
{
    SelectParams(CBaseChainParams::REGTEST);
    const fs::path dir = fs::temp_directory_path() / fs::unique_path("valuepools-%%%%-%%%%");
    FakeChain chain(5);
    std::string err;

    // No seed: the fill reads from genesis, and every record equals the computed one.
    valuepools::test::SetSeed(std::nullopt);
    valuepools::Open(dir, true);
    ASSERT_TRUE(FillNow(err)) << err;
    for (int h = 0; h <= 5; h++) {
        std::optional<Record> r = valuepools::GetRecord(chain.at(h));
        ASSERT_TRUE(r.has_value()) << h;
        EXPECT_TRUE(*r == chain.expected[h]) << h;
    }
    EXPECT_EQ(chain.expected[5].pq2, 1000);
    EXPECT_EQ(chain.expected[5].vaultYed, 300);
    // A second start finds the tip covered.
    ASSERT_TRUE(FillNow(err)) << err;

    // A seed at height 3, an empty index, the default -valuepoolsseed: the fill starts at the seed and reads nothing
    // below it.
    valuepools::test::SetSeed(valuepools::Seed{3, chain.hashes[3], chain.expected[3]});
    valuepools::Open(dir, true);
    ASSERT_TRUE(FillNow(err)) << err;
    EXPECT_FALSE(valuepools::GetRecord(chain.at(2)).has_value());
    ASSERT_TRUE(valuepools::GetRecord(chain.at(3)).has_value());
    EXPECT_TRUE(*valuepools::GetRecord(chain.at(5)) == chain.expected[5]);

    // -valuepoolsseed=0 fills from genesis and checks the seed: a match starts...
    mapArgs["-valuepoolsseed"] = "0";
    valuepools::Open(dir, true);
    ASSERT_TRUE(FillNow(err)) << err;
    EXPECT_TRUE(*valuepools::GetRecord(chain.at(2)) == chain.expected[2]);
    EXPECT_TRUE(*valuepools::GetRecord(chain.at(5)) == chain.expected[5]);

    // ...and a mismatch refuses to start, telling the operator to delete the index (which -reindex would not cure).
    Record wrong = chain.expected[3];
    wrong.transparent += 1;
    valuepools::test::SetSeed(valuepools::Seed{3, chain.hashes[3], wrong});
    valuepools::Open(dir, true);
    err.clear();
    EXPECT_FALSE(FillNow(err));
    EXPECT_NE(err.find("delete the directory blocks/valuepools"), std::string::npos) << err;
    EXPECT_NE(err.find("without -valuepoolsseed=0"), std::string::npos) << err;
    EXPECT_TRUE(valuepools::GetRecord(chain.at(2)).has_value());
    EXPECT_FALSE(valuepools::GetRecord(chain.at(3)).has_value());
    mapArgs.erase("-valuepoolsseed");

    valuepools::Close();
    fs::remove_all(dir);
}

TEST(ValuePools, WriteFailureLeavesTheIndexUnmonitoredUntilRestart)
{
    SelectParams(CBaseChainParams::REGTEST);
    const fs::path dir = fs::temp_directory_path() / fs::unique_path("valuepools-%%%%-%%%%");
    FakeChain chain(3);
    std::string err;
    valuepools::test::SetSeed(std::nullopt);

    // A fill whose writes fail: logged, the index closes, the node still starts.
    valuepools::Open(dir, true);
    valuepools::test::SetFailWrites(true);
    ASSERT_TRUE(FillNow(err)) << err;
    EXPECT_FALSE(valuepools::IsOpen());
    EXPECT_FALSE(valuepools::GetRecord(chain.at(3)).has_value());
    valuepools::test::SetFailWrites(false);

    // A fill that succeeds, then a block whose record cannot be written: no record is cached for it, the index
    // closes (every entry "monitored": false), and the next block is not extended from a record never stored.
    valuepools::Open(dir, true);
    ASSERT_TRUE(FillNow(err)) << err;
    ASSERT_TRUE(valuepools::GetRecord(chain.at(3)).has_value());
    const CScript pq1 = GetScriptForPQKey(CPQKeyID(pq::SCHEME_SLH_DSA_SHA2_128S, Hash32(0x7a)));
    CBlock b4;
    b4.vtx.push_back(MakeTx({CTxOut(7, pq1)}, 0, true));
    uint256 h4 = GetRandHash();
    CBlockIndex i4;
    i4.phashBlock = &h4;
    i4.pprev = const_cast<CBlockIndex*>(chain.at(3));
    i4.nHeight = 4;
    valuepools::test::SetFailWrites(true);
    valuepools::BlockConnected(b4, CBlockUndo(), &i4);
    EXPECT_FALSE(valuepools::IsOpen());
    EXPECT_FALSE(valuepools::GetRecord(&i4).has_value());
    EXPECT_FALSE(valuepools::GetRecord(chain.at(3)).has_value());
    EXPECT_FALSE(valuepools::TransparentPoolsToJSON(chain.at(3), false)["monitored"].get_bool());
    valuepools::test::SetFailWrites(false);
    uint256 h5 = GetRandHash();
    CBlockIndex i5;
    i5.phashBlock = &h5;
    i5.pprev = &i4;
    i5.nHeight = 5;
    valuepools::BlockConnected(b4, CBlockUndo(), &i5); // off until restart: a no-op
    EXPECT_FALSE(valuepools::GetRecord(&i5).has_value());

    // The restart: the records written before the failure are there, the failed one is not.
    valuepools::Open(dir, false);
    EXPECT_TRUE(*valuepools::GetRecord(chain.at(3)) == chain.expected[3]);
    EXPECT_FALSE(valuepools::GetRecord(&i4).has_value());

    valuepools::Close();
    fs::remove_all(dir);
}
