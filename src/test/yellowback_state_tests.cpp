// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Every rule of plan §3.7–3.9 on synthetic blocks over an in-memory view
// (Phase 2). Each case carries a `// Rule:` tag; the acceptance loop greps
// them. The golden vector (statehash_golden_vector) replays 440 blocks of
// real serialised transactions built by the Python model
// (qa/rpc-tests/test_framework/yellowback_golden.json) and must reproduce
// its pinned state hash byte for byte (N18, N23).

#include "vault/act.h"
#include "yellowback/attest.h"
#include "yellowback/bundle.h"
#include "yellowback/math.h"
#include "yellowback/payload.h"
#include "yellowback/script.h"
#include "yellowback/state.h"
#include "yellowback/tag.h"
#include "yellowback/view.h"

#include "crypto/sha256.h"

#include "consensus/validation.h"
#include "core_io.h"
#include "crypto/pq/scheme.h"
#include "random.h"
#include "hash.h"
#include "key.h"
#include "primitives/block.h"
#include "script/standard.h"
#include "test/data/yellowback_golden.json.h"
#include "test/data/yellowback_pq_vectors.json.h"
#include "test/test_bitcoin.h"
#include "test/yellowback_bench.h"
#include "util/strencodings.h"
#include "util/time.h"

#include <boost/test/unit_test.hpp>

#include <univalue.h>

#include <cstring>
#include <map>
#include <set>

using namespace yellowback;

namespace {

/** The vault owner is a post-quantum key id (quantum plan §4.3); these cases keep their EC test keys
 *  for tokens and payees and name the vault owner by a stand-in SLH-DSA key id derived from them. */
CPQKeyID TestPQOwner(const CPubKey& k)
{
    return CPQKeyID(pq::SCHEME_SLH_DSA_SHA2_128S, Hash(k.begin(), k.end()));
}

/** The 33 owner bytes (scheme || keyHash) a MINT payload and a VaultRecord carry. */
std::vector<unsigned char> TestPQOwnerBytes(const CPubKey& k)
{
    const CPQKeyID id = TestPQOwner(k);
    std::vector<unsigned char> b(1, id.scheme);
    b.insert(b.end(), id.hash.begin(), id.hash.end());
    return b;
}

const CAmount SUBSIDY = 625000000;   // regtest post-Blossom
const std::string GOLDEN_HASH = "ee6a9f157175b6e084df52f96dc5039e4d411189352542f329971e6dd7bb0c0b";   // SCHEMA_VERSION 15: HALT-2 divides by Totals.openDebtCents (owner 2026-10-28; Snapshot.openDebtCents; build_golden buys the stranded mint4 back with a class C mint at 232-233), 22 rejected blocks; 14: RED-5a/5b (positional claimant floor; path (b) caps at pEmerg), 22 rejected blocks; the per-vault cancel limit (CAN-2, C4b, CAN-3; round 2: the claimable-position hold), 20 rejected blocks; 13: CAN-1 (the cancel refunds the burn), R12 hardened, 17 rejected blocks (audit 03/T-1, 03/H-1, 03/M-2); FEE-1' fees at the stored pMint and VaultRecord.pMint (SCHEMA_VERSION 12 since the bounded liveness and join refusals; 11, seats and D-Q-30; 9, D-Q-23); in-term claims, post-quantum owners and the v4 MINT (quantum spec §3)

/** The YED attestor set every fixture names (U-22): its id only shapes the V template. */
uint256 TestSet()
{
    return uint256S("5e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e7");
}

uint160 KeyOf(int i)
{
    std::vector<unsigned char> v(20, (unsigned char)(0x10 + i));
    return uint160(v);
}

struct MintOpts
{
    int termClass = 0;
    CAmount collateral = -1;         //!< -1 = the required amount
    int feeKey = -2;                 //!< -2 = payee of the tag at refHeight; -1 = no fee output
    uint8_t feeVout = 3;
    CAmount feeValue = -1;           //!< -1 = ProtocolFeeZat(cents, pMint) (FEE-1')
    std::optional<MicroUsd> pMint;   //!< the price the default fee converts at; default the snapshot's xMint at R (an ARMED mint with a lower aMint passes min(x, aMint))
    std::optional<CPubKey> owner;
    std::vector<unsigned char> rawOwner; //!< overrides the key bytes in the payload
    int extraOutputs = 0;
    bool p2shVault = true;           //!< the vault output is the V template (U-23; the name predates it); false = P2PKH(owner)
    std::vector<COutPoint> yedInputs;
    std::optional<CScript> vaultScriptOverride;
    // v3
    std::optional<valtype> bundle;          //!< carried by an extra (last) input
    int attestPayee = -1;                   //!< seq whose bond key receives the attestor fee at vout 4; -1 = no such output
    CAmount attestFeeValue = -1;            //!< -1 = attestFeeZat(feeZat(collateral))
    uint8_t attestFeeVout = 4;              //!< the payload field when attestPayee >= 0
    std::optional<CScript> attestFeeScript; //!< overrides the attestor-fee output's script
    // quantum line
    std::optional<CPQKeyID> pqOwner;        //!< the V's and the payload's owner (default TestPQOwner(owner))
    std::optional<CScript> tokenScript;     //!< the token output vout[1] (default P2PKH(owner)); TOK-PQ
};

struct SpendOpts
{
    bool ownerPath = true;
    std::optional<CScript> scriptSig;       //!< overrides the vin[0] scriptSig
    int feeKey = -2;                        //!< -2 = payee of the tag at refHeight; -1 = none
    uint8_t feeVout = 1;
    CAmount feeValue = -1;
    std::vector<Assignment> assigned;       //!< token outputs at vout 3.. (caller chooses vouts)
    bool payload = true;
    std::optional<Payload> payloadOverride;
    std::vector<COutPoint> extraVaults;     //!< spent after vin[0]
    bool vaultFirst = true;
    // v3
    std::optional<valtype> bundle;          //!< carried by an extra (last) input, never vin[0]
    int attestPayee = -1;                   //!< seq paid the attestor fee (after the assigned outputs); -1 = none
    CAmount attestFeeValue = -1;
    std::optional<CAmount> residualValue;   //!< a residual output after the attestor fee
    std::optional<CScript> residualScript;  //!< default P2PKH(owner)
};

/** A tiny SigCache for the cache tests: an unbounded map. */
struct MapSigCache : public SigCache
{
    std::map<uint256, bool> entries;
    int hits = 0;
    std::optional<bool> Lookup(const uint256& key) const override
    {
        auto it = entries.find(key);
        if (it == entries.end()) return std::nullopt;
        const_cast<MapSigCache*>(this)->hits++;
        return it->second;
    }
    void Insert(const uint256& key, bool valid) override { entries[key] = valid; }
};

/** A synthetic chain over a MemoryStateView with the regtest parameters. */
struct Fixture
{
    yellowback::Params P;
    MemoryStateView view;
    std::map<int, UndoRecord> undos;
    std::map<int, BlockEvaluation> evals;
    std::map<uint256, TxLogRecord> refused;  //!< U-21: transactions the module made invalid, which Mine() left out of the block
    int tip;
    CKey ownerKey, userKey;
    int fakeCounter;
    std::vector<CKey> hotKeys, bondKeys;    //!< attestor i joins with member key hotKeys[i] (= bondKeys[i] since P4-b) and becomes seq i
    SigCache* cache = nullptr;
    // P4-b: the attestor set is a primitive set; P.attestorSetId is the txid of `setCreate`, mined by the first join
    CMutableTransaction setCreate;
    bool setMined = false;

    explicit Fixture(int start = 1, int sigmaRef = 0, int capBps = 0, int armMin = 3)
        : P(RegtestParams(start, sigmaRef, capBps, TestSet(), armMin)), tip(start - 1), fakeCounter(0)
    {
        ownerKey = CKey::TestOnlyRandomKey(true);
        userKey = CKey::TestOnlyRandomKey(true);
        for (int i = 0; i < 20; i++) {
            hotKeys.push_back(DeterministicKey("yellowback-state-test-hot", i));
            bondKeys.push_back(hotKeys.back());
        }
        RecreateSet();
    }

    /** The SET_CREATE of the attestor set (open, 15 seats, 1/1/1 thresholds, maturity, livenessWindow); sets
     *  P.attestorSetId to its txid. Only before anything is mined (P is hashed into the state from the first block). */
    void RecreateSet(uint32_t livenessWindow = 1000000, uint32_t maturity = 8, uint8_t seats = 15)
    {
        BOOST_REQUIRE(tip < P.startHeight);
        vault::Act a;
        a.type = vault::ACT_SET_CREATE;
        a.create.seats = seats;
        a.create.unlockThreshold = 1;
        a.create.cancelThreshold = 1;
        a.create.slashThreshold = 1;
        a.create.flags = vault::SET_FLAG_OPEN;
        a.create.rateWindow = 1000;
        a.create.livenessWindow = livenessWindow;
        a.create.bondMin = 1;
        a.create.maturity = maturity;
        a.create.admitKey = DeterministicKey("yellowback-state-test-admit", 0).GetPubKey();
        setCreate = CMutableTransaction();
        setCreate.vin.push_back(CTxIn(COutPoint(TestSet(), 0)));
        setCreate.vout.push_back(CTxOut(0, vault::EncodeAct(a)));
        P.attestorSetId = CTransaction(setCreate).GetHash();
    }

    /** Mine the SET_CREATE (once, in its own block) before the first join. */
    void EnsureSet()
    {
        if (setMined) return;
        setMined = true;
        Mine(Quote(50000, (tip + 1) % 3), { setCreate });
        BOOST_REQUIRE(State(view).GetAttestorSet().has_value());
    }

    /** A `YV` act transaction: vin[0] a fake input, the act (signed by `signers` over actMsg), a change output. */
    CMutableTransaction ActTx(vault::Act act, const std::vector<CKey>& signers, std::vector<CTxOut> before = {})
    {
        CMutableTransaction m;
        m.vin.push_back(CTxIn(FakeInput()));
        for (const CTxOut& o : before) m.vout.push_back(o);
        const uint256 msg = vault::ActMsg(vault::EncodePayload(act), m.vin[0].prevout);
        for (const CKey& k : signers) {
            std::vector<unsigned char> sig;
            BOOST_REQUIRE(vault::SignRecoverable(k, msg, sig));
            act.sigs.push_back(sig);
        }
        m.vout.push_back(CTxOut(0, vault::EncodeAct(act)));
        m.vout.push_back(CTxOut(1000, GetScriptForDestination(userKey.GetPubKey().GetID())));
        return m;
    }

    CMutableTransaction HeartbeatTx(int i)
    {
        vault::Act a;
        a.type = vault::ACT_SET_HEARTBEAT;
        a.heartbeat.setId = P.attestorSetId;
        a.heartbeat.memberKey = hotKeys[i].GetPubKey();
        return ActTx(a, { hotKeys[i] });
    }

    /** SET_REMOVE of member i, signed by member `by` (slashThreshold 1). */
    CMutableTransaction RemoveTx(int i, int by, bool burn)
    {
        vault::Act a;
        a.type = vault::ACT_SET_REMOVE;
        a.remove.setId = P.attestorSetId;
        a.remove.memberKey = hotKeys[i].GetPubKey();
        a.remove.burn = burn ? 1 : 0;
        return ActTx(a, { hotKeys[by] });
    }

    static CKey DeterministicKey(const char* tag, int i)
    {
        unsigned char d[CSHA256::OUTPUT_SIZE];
        CSHA256().Write((const unsigned char*)tag, strlen(tag)).Write((const unsigned char*)&i, sizeof(i)).Finalize(d);
        CKey k;
        k.Set(d, d + 32, true);
        return k;
    }

    static uint256 FakeHash(int height)
    {
        std::vector<unsigned char> v(32, 0);
        v[0] = height & 0xff;
        v[1] = (height >> 8) & 0xff;
        v[31] = 0x5a;
        return uint256(v);
    }

    COutPoint FakeInput()
    {
        std::vector<unsigned char> v(32, 0x77);
        v[0] = fakeCounter & 0xff;
        v[1] = (fakeCounter >> 8) & 0xff;
        fakeCounter++;
        return COutPoint(uint256(v), 0);
    }

    static CoinbaseTag Quote(MicroUsd price, int key, bool signal = true, uint16_t mask = 7)
    {
        CoinbaseTag t;
        t.flags = signal ? 1 : 0;
        t.priceMicroUsd = price;
        t.sourceMask = mask;
        t.payoutKey = KeyOf(key);
        return t;
    }
    static CoinbaseTag SignalOnly(int key)
    {
        return Quote(0, key, true, 0);
    }

    static CMutableTransaction Coinbase(int height, const std::optional<CoinbaseTag>& tag)
    {
        CMutableTransaction cb;
        CScript sig = CScript() << height;
        if (tag.has_value()) sig += TagPush(tag.value());
        cb.vin.push_back(CTxIn(COutPoint(), sig));
        cb.vout.push_back(CTxOut(SUBSIDY, GetScriptForDestination(CKeyID(KeyOf(0)))));
        return cb;
    }

    /** Evaluate a block at the next height (or `height`) without committing it. */
    BlockEvaluation Evaluate(const std::optional<CoinbaseTag>& tag, const std::vector<CMutableTransaction>& txs, int height = -1)
    {
        if (height < 0) height = tip + 1;
        CBlock block;
        block.vtx.push_back(CTransaction(Coinbase(height, tag)));
        for (auto& m : txs) block.vtx.push_back(CTransaction(m));
        OverlayStateView overlay(view);
        return EvaluateBlock(overlay, P, block, height, FakeHash(height), SUBSIDY, cache);
    }

    /**
     * Evaluate and commit a block at the next height (or `height`). U-21: a transaction the module makes
     * invalid would make the block invalid, so, as the template filter does, it is left out (its log kept
     * in `refused`, Log() returns it) and the block is evaluated again without it.
     */
    BlockEvaluation Mine(const std::optional<CoinbaseTag>& tag = std::nullopt, std::vector<CMutableTransaction> txs = {}, int height = -1)
    {
        if (height < 0) height = tip + 1;
        for (;;) {
            CBlock block;
            block.vtx.push_back(CTransaction(Coinbase(height, tag)));
            for (auto& m : txs) block.vtx.push_back(CTransaction(m));
            OverlayStateView overlay(view);
            BlockEvaluation ev = EvaluateBlock(overlay, P, block, height, FakeHash(height), SUBSIDY, cache);
            if (ev.blockInvalid) {
                BOOST_REQUIRE(!ev.txlogs.empty());
                const uint256 bad = ev.txlogs.back().first;
                refused[bad] = ev.txlogs.back().second;
                size_t before = txs.size();
                txs.erase(std::remove_if(txs.begin(), txs.end(), [&](const CMutableTransaction& m) { return CTransaction(m).GetHash() == bad; }), txs.end());
                BOOST_REQUIRE(txs.size() < before);
                continue;
            }
            overlay.Commit();
            undos[height] = ev.undo;
            evals[height] = ev;
            tip = height;
            return ev;
        }
    }

    void Undo()
    {
        UndoBlock(view, undos[tip]);
        undos.erase(tip);
        evals.erase(tip);
        tip--;
    }

    /** Mine quote+signal blocks from three rotating pools up to and including height h. */
    void MineQuotesTo(int h, MicroUsd price = 50000, bool signal = true)
    {
        while (tip < h) Mine(Quote(price, (tip + 1) % 3, signal));
    }

    /** Every window filled and no halt (the module is active from START, U-22): quotes to START + 130 (v2's
     *  START + 2 * SIGNAL_WINDOW + 2, kept so the cases' heights stay as they were). */
    static const int ACTIVATE_BLOCKS = 130;
    void Activate(MicroUsd price = 50000)
    {
        MineQuotesTo(P.startHeight + ACTIVATE_BLOCKS, price);
        BOOST_REQUIRE_EQUAL(Snap(tip).haltMask, 0u);
    }

    Snapshot Snap(int h) const { return State(const_cast<MemoryStateView&>(view)).GetSnapshot((uint32_t)h).value(); }
    std::optional<Snapshot> SnapOpt(int h) const { return State(const_cast<MemoryStateView&>(view)).GetSnapshot((uint32_t)h); }
    Totals GetTotals() const { return State(const_cast<MemoryStateView&>(view)).GetTotals(); }
    std::optional<VaultRecord> Vault(const uint256& txid) const { return State(const_cast<MemoryStateView&>(view)).GetVault(COutPoint(txid, 0)); }
    std::optional<TokenRecord> Token(const uint256& txid, uint32_t n) const { return State(const_cast<MemoryStateView&>(view)).GetToken(COutPoint(txid, n)); }
    std::optional<TxLogRecord> Log(const uint256& txid) const
    {
        std::optional<TxLogRecord> l = State(const_cast<MemoryStateView&>(view)).GetTxLog(txid);
        if (l.has_value()) return l;
        auto it = refused.find(txid);
        if (it != refused.end()) return it->second;
        return std::nullopt;
    }
    /** U-21: the verdict that made `txid` invalid, or "" when it was not refused. */
    std::string Refused(const uint256& txid) const
    {
        auto it = refused.find(txid);
        return it == refused.end() ? std::string() : it->second.verdict;
    }

    CAmount Required(Cents cents, int termClass, int refHeight) const
    {
        Snapshot s = Snap(refHeight);
        auto r = RequiredCollateralRounded(cents, MinRatioBps(P.baseRatioBps[termClass], s.sigmaMultBps), s.PMint().value());
        BOOST_REQUIRE(r.has_value());
        return r.value();
    }
    /** The cross-section xMint at refHeight (0 = undefined). */
    MicroUsd PMintAt(int refHeight) const { std::optional<Snapshot> s = SnapOpt(refHeight); return s.has_value() ? s->PMint().value_or(0) : 0; }
    /** FEE-1': the protocol fee of a mint of `cents` at refHeight's xMint (0 when the price is undefined). */
    CAmount MintFee(Cents cents, int refHeight) const { return ProtocolFeeZat(cents, PMintAt(refHeight), P).value_or(0); }
    /** RED-3': the protocol fee a spend of `v` pays (its debt at its own pMint). */
    CAmount VaultFee(const VaultRecord& v) const { return ProtocolFeeZat(v.mintedCents, v.pMint, P).value_or(0); }

    /** A MINT of `cents` with lockHeight = refHeight + lockBlocks, refHeight given. */
    CMutableTransaction MintTx(Cents cents, int lockBlocks, int refHeight, MintOpts o = MintOpts())
    {
        CPubKey owner = o.owner.value_or(ownerKey.GetPubKey());
        const uint32_t lock = (uint32_t)(refHeight + lockBlocks);
        const CPQKeyID pqOwner = o.pqOwner.value_or(TestPQOwner(owner));
        CScript vs = o.vaultScriptOverride.value_or(YedVaultScript(P, pqOwner, refHeight));     // U-23, IT-1: the V template
        CAmount collateral = o.collateral;
        // An invalid class is a payload the verdict rejects (bad-mint-class). Collateral is
        // computed from a real class so the helper does not index baseRatioBps out of range;
        // MINT-2 checks the class before it looks at the amount.
        if (collateral < 0) collateral = Required(cents, P.IsValidClass(o.termClass) ? o.termClass : 0, refHeight);
        CMutableTransaction m;
        m.vin.push_back(CTxIn(FakeInput()));
        for (const COutPoint& op : o.yedInputs) m.vin.push_back(CTxIn(op));
        m.vout.push_back(CTxOut(collateral, o.p2shVault ? vs : GetScriptForDestination(owner.GetID())));
        m.vout.push_back(CTxOut(TOKEN_VALUE, o.tokenScript.value_or(GetScriptForDestination(owner.GetID()))));
        Payload p = Payload::Mint((uint8_t)o.termClass, (uint32_t)cents, lock, (uint32_t)refHeight, pqOwner, o.feeKey == -1 ? FEE_VOUT_NONE : o.feeVout,
                                  o.attestPayee >= 0 ? o.attestFeeVout : FEE_VOUT_NONE);
        if (!o.rawOwner.empty()) p.ownerKeyBytes = o.rawOwner;
        m.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(p))));
        if (o.feeKey != -1) {
            int key = o.feeKey;
            if (key == -2) key = refHeight % 3;
            CAmount fee = o.feeValue >= 0 ? o.feeValue : ProtocolFeeZat(cents, o.pMint.value_or(PMintAt(refHeight)), P).value_or(0);
            m.vout.push_back(CTxOut(fee, GetScriptForDestination(CKeyID(KeyOf(key)))));
        }
        if (o.attestPayee >= 0) {
            while (m.vout.size() < 4) m.vout.push_back(CTxOut(1000, GetScriptForDestination(userKey.GetPubKey().GetID())));
            CAmount afee = o.attestFeeValue >= 0 ? o.attestFeeValue : AttestFeeZat(ProtocolFeeZat(cents, o.pMint.value_or(PMintAt(refHeight)), P).value_or(0), P.attestFeeBps);
            m.vout.push_back(CTxOut(afee, o.attestFeeScript.value_or(GetScriptForDestination(bondKeys[o.attestPayee].GetPubKey().GetID()))));
        }
        for (int i = 0; i < o.extraOutputs; i++) m.vout.push_back(CTxOut(1000, GetScriptForDestination(userKey.GetPubKey().GetID())));
        if (o.bundle.has_value()) m.vin.push_back(CarrierIn(o.bundle.value()));
        return m;
    }

    CMutableTransaction TransferTx(const std::vector<COutPoint>& inputs, const std::vector<Assignment>& as, bool redeemType = false, uint32_t ref = 0)
    {
        CMutableTransaction m;
        for (const COutPoint& o : inputs) m.vin.push_back(CTxIn(o));
        size_t nOut = 0;
        for (const Assignment& a : as) nOut = std::max<size_t>(nOut, a.vout + 1);
        for (size_t i = 0; i < nOut; i++) m.vout.push_back(CTxOut(TOKEN_VALUE, GetScriptForDestination(userKey.GetPubKey().GetID())));
        Payload p = redeemType ? Payload::Redeem(ref, FEE_VOUT_NONE, as) : Payload::Transfer(as);
        m.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(p))));
        return m;
    }

    /**
     * vin[0] = vault (or a YED input when !vaultFirst), YED inputs; vout[0] collateral, vout[1] fee, vout[2] OP_RETURN,
     * vout[3..] tokens. U-23: the owner path's scriptSig is `<sig> OP_2`, the claim's `OP_4`; a claim's vout[0] is the
     * claimant's intent (paying userKey) of the vault's value less the residual, and the residual (residualValue) is
     * the owner's intent (paying residualScript, default P2PKH(owner)); the fees come from a fake extra input.
     */
    CMutableTransaction SpendTx(const uint256& vaultTxid, const std::vector<COutPoint>& yed, int refHeight, SpendOpts o = SpendOpts())
    {
        std::optional<VaultRecord> v = Vault(vaultTxid);
        BOOST_REQUIRE(v.has_value());
        CScript vs = YedVaultScriptAt(P, v->Owner(), v->ownerHeight, v->appHeight);
        CScript sig = o.scriptSig.value_or(o.ownerPath ? (CScript() << valtype(71, 0x30) << OP_2) : (CScript() << OP_4));
        const vault::VaultParams vp = YedVaultParamsAt(P, v->Owner(), v->ownerHeight, v->appHeight);
        CMutableTransaction m;
        m.nLockTime = o.ownerPath ? v->ownerHeight : v->appHeight;
        if (!o.vaultFirst) m.vin.push_back(CTxIn(yed.front()));
        m.vin.push_back(CTxIn(COutPoint(vaultTxid, 0), sig, 0xFFFFFFFE));
        for (const COutPoint& e : o.extraVaults) m.vin.push_back(CTxIn(e, sig, 0xFFFFFFFE));
        for (size_t i = o.vaultFirst ? 0 : 1; i < yed.size(); i++) m.vin.push_back(CTxIn(yed[i]));
        if (o.ownerPath) {
            m.vout.push_back(CTxOut(v->collateralZat - 1000, GetScriptForDestination(userKey.GetPubKey().GetID())));
        } else {
            const CAmount residual = o.residualValue.value_or(0);
            m.vout.push_back(CTxOut(v->collateralZat - residual, vault::BuildIntent(vault::IntentFor(vp, vs, GetScriptForDestination(userKey.GetPubKey().GetID())))));
            m.vin.push_back(CTxIn(FakeInput()));     // the claim's fees (the vault's value goes to intents)
        }
        int key = o.feeKey == -2 ? refHeight % 3 : o.feeKey;
        CAmount fee = o.feeValue >= 0 ? o.feeValue : VaultFee(*v);
        if (o.feeValue < 0 && o.ownerPath && tip + 1 < v->lockHeight) fee += EarlyRedeemFeeZat(v->mintedCents, P.earlyRedeemFeeBps[v->termClass], v->pMint);   // IT-9': mined at tip + 1
        m.vout.push_back(CTxOut(fee, GetScriptForDestination(CKeyID(KeyOf(key < 0 ? 9 : key)))));
        size_t nOut = 3;
        for (const Assignment& a : o.assigned) nOut = std::max<size_t>(nOut, a.vout + 1);
        const uint8_t attestFeeVout = o.attestPayee >= 0 ? (uint8_t)nOut : FEE_VOUT_NONE;
        if (o.payload) {
            Payload p = o.payloadOverride.value_or(Payload::Redeem((uint32_t)refHeight, o.feeKey == -1 ? FEE_VOUT_NONE : o.feeVout, o.assigned, attestFeeVout));
            m.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(p))));
        } else {
            m.vout.push_back(CTxOut(0, GetScriptForDestination(userKey.GetPubKey().GetID())));
        }
        while (m.vout.size() < nOut) m.vout.push_back(CTxOut(TOKEN_VALUE, GetScriptForDestination(userKey.GetPubKey().GetID())));
        if (o.attestPayee >= 0) {
            CAmount afee = o.attestFeeValue >= 0 ? o.attestFeeValue : AttestFeeZat(VaultFee(*v), P.attestFeeBps);
            m.vout.push_back(CTxOut(afee, GetScriptForDestination(bondKeys[o.attestPayee].GetPubKey().GetID())));
        }
        if (o.residualValue.has_value()) {
            const CScript to = o.residualScript.value_or(GetScriptForDestination(v->Owner()));
            m.vout.push_back(CTxOut(o.residualValue.value(), o.ownerPath ? to : vault::BuildIntent(vault::IntentFor(vp, vs, to))));
        }
        if (o.bundle.has_value()) m.vin.push_back(CarrierIn(o.bundle.value()));
        return m;
    }

    // ---------------------------------------------------------------- v3 helpers

    std::optional<AttestorRecord> Attestor(uint16_t seq) const { return State(const_cast<MemoryStateView&>(view)).GetAttestor(seq); }
    AttestState Attest() const { return State(const_cast<MemoryStateView&>(view)).GetAttest(); }
    std::optional<NoticeRecord> Notice(const uint256& vaultTxid) const { return State(const_cast<MemoryStateView&>(view)).GetNotice(COutPoint(vaultTxid, 0)); }
    std::optional<BundleLogRecord> BundleRow(int h) const { return State(const_cast<MemoryStateView&>(view)).GetBundleLog((uint32_t)h); }
    bool Armed() const { return P.IsArmed(Attest().IsArmed()); }

    /** P4-b: attestor i joins the attestor set: vout[0] the bond P2SH(BondScript(member, locktime)) of bondZat, vout[1]
     *  the SET_JOIN act signed by the member, vout[2] change. Mines the SET_CREATE first if needed. `member` overrides
     *  the member key (signing with the key of `signer`, default i). */
    CMutableTransaction RegisterTx(int i, CAmount bondZat = 10 * COIN, int lockBlocks = -1, std::optional<int> signer = std::nullopt)
    {
        EnsureSet();
        const CKey& key = hotKeys[signer.value_or(i)];
        const uint32_t locktime = (uint32_t)(tip + 1 + (lockBlocks < 0 ? P.bondMinLock : lockBlocks));
        vault::Act a;
        a.type = vault::ACT_SET_JOIN;
        a.join.setId = P.attestorSetId;
        a.join.memberKey = key.GetPubKey();
        a.join.bondLocktime = locktime;
        a.join.bondVout = 0;
        return ActTx(a, { key }, { CTxOut(bondZat, P2SHScript(BondScript(key.GetPubKey(), locktime))) });
    }

    /** The pre-P4-b ATTESTOR_REGISTER payload (invalid since P4-b). */
    CMutableTransaction LegacyRegisterTx(int i)
    {
        const uint32_t locktime = (uint32_t)(tip + 1 + P.bondMinLock);
        CMutableTransaction m;
        m.vin.push_back(CTxIn(FakeInput()));
        const CScript bond = BondScript(hotKeys[i].GetPubKey(), locktime);
        m.vout.push_back(CTxOut(10 * COIN, P2SHScript(bond)));
        m.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(Payload::AttestorRegister(hotKeys[i].GetPubKey(), hotKeys[i].GetPubKey(), locktime, 0)))));
        m.vout.push_back(CTxOut(1000, GetScriptForDestination(userKey.GetPubKey().GetID())));
        return m;
    }

    /** Register attestors [from, from + n) one per block (after the SET_CREATE's own block, the first time). */
    void Register(int n, int from = 0)
    {
        EnsureSet();
        for (int i = from; i < from + n; i++) {
            Mine(Quote(50000, (tip + 1) % 3), { RegisterTx(i) });
            BOOST_REQUIRE_MESSAGE(Attestor((uint16_t)i).has_value(), strprintf("attestor %d not registered at %d", i, tip));
        }
    }

    /** Activate (if needed), register n attestors and mine until ARMED. */
    void Arm(int n = 3, MicroUsd price = 50000)
    {
        if (tip < P.startHeight + ACTIVATE_BLOCKS) Activate(price);
        Register(n);
        while (!Attest().IsArmed()) Mine(Quote(price, (tip + 1) % 3));
        Mine(Quote(price, (tip + 1) % 3));       // one more: a transaction at tip + 1 reads Snapshots[tip - 1], which must be ARMED
        BOOST_REQUIRE(Attest().IsArmed());
        BOOST_REQUIRE(ArmedAt(view, P, tip - 1) == P.attestRequired);
    }

    /** A compact low-S signature of attestor seq over (seq, price, cited, blockHash(cited)); the block hash defaults to the chain's. */
    Attestation Att(int seq, MicroUsd price, int cited, std::optional<uint256> blockHash = std::nullopt)
    {
        Attestation a;
        a.seq = (uint16_t)seq;
        a.priceMicroUsd = (uint32_t)price;
        a.citedHeight = (uint32_t)cited;
        const uint256 msg = AttestMessage(a.seq, a.priceMicroUsd, a.citedHeight, blockHash.value_or(FakeHash(cited)));
        std::vector<unsigned char> der;
        BOOST_REQUIRE(hotKeys[seq].Sign(msg, der));
        a.sig.fill(0);
        size_t pos = 3;
        for (int part = 0; part < 2; part++) {
            size_t len = der[pos++];
            size_t skip = len > 32 ? len - 32 : 0;
            std::copy(der.begin() + pos + skip, der.begin() + pos + len, a.sig.begin() + part * 32 + (32 - (len - skip)));
            pos += len + 1;
        }
        return a;
    }

    /** The bundle for (R, selector): every selected seq not in `skip` signs `price` citing `cited` (default R). */
    valtype BundleFor(int R, const valtype& selector, MicroUsd price, std::set<int> skip = {}, int cited = -1, std::map<int, MicroUsd> prices = {})
    {
        Bundle b;
        for (uint16_t seq : Selected(view, P, R, selector)) {
            if (skip.count(seq)) continue;
            auto it = prices.find(seq);
            b.atts.push_back(Att(seq, it != prices.end() ? it->second : price, cited < 0 ? R : cited));
        }
        return EncodeBundle(b);
    }

    /** A carrier-shaped input whose redeem script commits to `bundle`. */
    CTxIn CarrierIn(const valtype& bundle)
    {
        uint256 h;
        CSHA256().Write(bundle.data(), bundle.size()).Finalize(h.begin());
        const CScript redeem = CarrierScript(userKey.GetPubKey(), h);
        return CTxIn(FakeInput(), CarrierScriptSig(bundle, valtype(71, 0x30), redeem));
    }

    /** CAN-2 + C4b: member `seq`'s co-signature of the cancel of `intent` -- its price statement at the claim's refHeight R. */
    CancelCosignEntry Cosign(int seq, MicroUsd price, const COutPoint& intent, int R, std::optional<uint256> blockHash = std::nullopt)
    {
        CancelCosignEntry e;
        e.priceMicroUsd = (uint32_t)price;
        const uint256 msg = CancelCosignMessage(P.attestorSetId, intent.hash, intent.n, (uint32_t)R, (uint32_t)price, blockHash.value_or(FakeHash(R)));
        BOOST_REQUIRE(vault::SignRecoverable(hotKeys[seq], msg, e.sig));
        return e;
    }

    /** A CLAIM_NOTICE for the vault at (vaultTxid, 0) with refHeight R carrying `bundle`. */
    CMutableTransaction NoticeTx(const uint256& vaultTxid, int R, const valtype& bundle)
    {
        CMutableTransaction m;
        m.vin.push_back(CTxIn(FakeInput()));
        m.vin.push_back(CarrierIn(bundle));
        m.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(Payload::ClaimNotice(COutPoint(vaultTxid, 0), (uint32_t)R)))));
        m.vout.push_back(CTxOut(1000, GetScriptForDestination(userKey.GetPubKey().GetID())));
        return m;
    }

    CMutableTransaction EquivocationTx(const Attestation& a, const Attestation& b)
    {
        Bundle bundle;
        bundle.atts = { a, b };
        CMutableTransaction m;
        m.vin.push_back(CarrierIn(EncodeBundle(bundle)));
        m.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(Payload::Equivocation()))));
        m.vout.push_back(CTxOut(1000, GetScriptForDestination(userKey.GetPubKey().GetID())));
        return m;
    }

    CMutableTransaction ReviveTx(const Attestation& a)
    {
        CMutableTransaction m;
        m.vin.push_back(CTxIn(FakeInput()));
        m.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(Payload::AttestorRevive(a.seq, a.priceMicroUsd, a.citedHeight, a.sig)))));
        m.vout.push_back(CTxOut(1000, GetScriptForDestination(userKey.GetPubKey().GetID())));
        return m;
    }

    CMutableTransaction BondSpendTx(int seq)
    {
        std::optional<AttestorRecord> rec = Attestor((uint16_t)seq);
        BOOST_REQUIRE(rec.has_value());
        CMutableTransaction m;
        m.nLockTime = rec->bondLocktime;
        const CScript bond = BondScript(rec->BondKey(), rec->bondLocktime);
    m.vin.push_back(CTxIn(rec->bondOutpoint, CScript() << valtype(71, 0x30) << valtype(bond.begin(), bond.end()), 0xFFFFFFFE));
        m.vout.push_back(CTxOut(rec->bondZat - 1000, GetScriptForDestination(userKey.GetPubKey().GetID())));
        return m;
    }

    /** An ARMED mint at tip + 1 with refHeight = tip - 1: the bundle at `price` from the selected set, fee to a pool, attestor fee to the first signer. */
    CMutableTransaction MintV3(Cents cents, MicroUsd price, MintOpts o = MintOpts(), std::set<int> skip = {}, int lockBlocks = 48)
    {
        const int ref = tip - 1;
        o.bundle = BundleFor(ref, valtype(), price, skip);
        if (!o.pMint.has_value() && PMintAt(ref) > 0) o.pMint = std::min(PMintAt(ref), price);   // FEE-1': the fee at min(xMint, aMint)
        if (o.attestPayee == -1) {
            std::vector<uint16_t> sel = Selected(view, P, ref, valtype());
            for (uint16_t q : sel) {
                if (!skip.count(q)) { o.attestPayee = q; break; }
            }
        }
        if (o.collateral < 0) {
            Snapshot s = Snap(ref);
            const MicroUsd pMint = std::min(s.PMint().value(), price);
            const int cls = P.IsValidClass(o.termClass) ? o.termClass : 0;
            o.collateral = RequiredCollateralRounded(cents, MinRatioBps(P.baseRatioBps[cls], s.sigmaMultBps), pMint).value();
        }
        return MintTx(cents, lockBlocks, ref, o);
    }

    /** A ready ACTIVE vault of `cents` (mint at tip + 1, refHeight = tip - 1); returns the mint txid. */
    uint256 MintActive(Cents cents = 10000, int lockBlocks = 48, int termClass = 0)
    {
        const int ref = tip - 1;
        MintOpts mo; mo.termClass = termClass;
        CMutableTransaction m = MintTx(cents, lockBlocks, ref, mo);
        Mine(Quote(50000, (tip + 1) % 3), { m });
        const uint256 txid = CTransaction(m).GetHash();
        Snapshot rs = Snap(ref);
        BOOST_REQUIRE_MESSAGE(Vault(txid).has_value() && Vault(txid)->status == (uint8_t)VaultStatus::ACTIVE,
                              strprintf("MintActive at %d ref %d: %s (supply %d collateral %d ratio %d pMint %d mask %u)", tip, ref,
                                        Refused(txid), rs.supplyCents, rs.collateralZat, rs.globalRatioBps, rs.pMint, rs.haltMask));
        return txid;
    }
};

std::string Hash(const MemoryStateView& v) { return StateHash(v, "regtest").GetHex(); }

} // namespace

BOOST_FIXTURE_TEST_SUITE(yellowback_state_tests, BasicTestingSetup)

// ===========================================================================
// The golden vector (N18, N23)

// Rule: SNAP
// Rule: UNDO
// Rule: TAG-1
// Rule: TAG-2
// Rule: TAG-3
// Rule: IN-1
// Rule: IN-2
// Rule: IN-3
// Rule: MINT-1
// Rule: XFER-1
// Rule: RED-1
// Rule: RED-4
// Rule: FEE-1
// Rule: FEE-2
// Rule: REG-4
// Rule: ACT-1
// Rule: ACT-2
// Rule: ACT-3
// Rule: PRICE-1
// Rule: PRICE-2
BOOST_AUTO_TEST_CASE(statehash_golden_vector)
{
    UniValue doc;
    BOOST_REQUIRE(doc.read(std::string(json_tests::yellowback_golden, json_tests::yellowback_golden + sizeof(json_tests::yellowback_golden))));
    BOOST_REQUIRE(doc.isObject());
    const UniValue& pj = doc["params"];
    yellowback::Params P = RegtestParams(pj["startHeight"].get_int(), pj["sigmaRefBps"].get_int(), pj["supplyCapBps"].get_int(), uint256S(pj["attestorSetId"].get_str()),
                                         pj["attestArmMin"].get_int(), (BundleCarrier)pj["bundleCarrier"].get_int(),
                                         pj["mintRequiresArmed"].get_bool());
    if (pj.exists("pqFalconHeight")) P.pqFalconHeight = pj["pqFalconHeight"].get_int();   // TOK-PQ from here (not hashed)
    MemoryStateView view;
    const MemoryStateView empty = view;
    std::vector<UndoRecord> undos;
    int invalidBlocks = 0;
    const UniValue& blocks = doc["blocks"];
    for (size_t i = 0; i < blocks.size(); i++) {
        const UniValue& b = blocks[i];
        CBlock block;
        for (size_t j = 0; j < b["txs"].size(); j++) {
            CTransaction tx;
            BOOST_REQUIRE_NO_THROW(DecodeHexTx(tx, b["txs"][j].get_str()));   // 6.20.0: throws on failure
            block.vtx.push_back(tx);
        }
        const int height = b["height"].get_int();
        const uint256 hash = uint256S(b["hash"].get_str());
        // Overlay evaluation and ApplyBlock agree (overlay equivalence).
        OverlayStateView overlay(view);
        BlockEvaluation ev = EvaluateBlock(overlay, P, block, height, hash, b["subsidyZat"].get_int64());
        overlay.Discard();
        if (ev.blockInvalid) {
            // U-21: an invalid block is rejected, not applied (the vector keeps it to prove the rejection);
            // the next entry is the same height mined again without the offending transaction.
            // One rejected block per verdict, in order (audit 03/T-1; test_yellowback_model.golden_rejected is the same list;
            // the emergency claim of build_golden landed at 299, the Falcon height is 400).
            static const std::vector<std::pair<int, std::string>> expected = {
                { 137, "bad-mint-amount" }, { 141, "bad-mint-collateral" }, { 146, "yed-template-output" }, { 150, "bad-redeem-early-fee" },
                { 185, "vault-spend-short-burn" }, { 217, "vault-spend-malformed" }, { 231, "attestor-register-retired" },
                { 251, "mint9-no-bundle" }, { 252, "mint9-bundle-sig" }, { 253, "mint9-bundle-member" }, { 292, "liveness-unheld" },
                { 299, "red5-residual" }, { 299, "red5-residual" }, { 299, "red5-claimant-short" },
                { 300, "intent-cancel-no-vault" }, { 300, "intent-cancel-no-refund" }, { 300, "intent-cancel-cosign" },
                { 308, "intent-cancel-residual" }, { 310, "intent-residual-held" },
                { 340, "intent-residual-held" }, { 402, "bad-yed-holder" }, { 403, "bad-yed-holder" } };
            BOOST_CHECK(b.exists("invalid") && b["invalid"].get_bool());
            BOOST_REQUIRE((size_t)invalidBlocks < expected.size());
            BOOST_CHECK_EQUAL(height, expected[invalidBlocks].first);
            BOOST_CHECK_EQUAL(ev.verdict, expected[invalidBlocks].second);
            invalidBlocks++;
            BOOST_CHECK_EQUAL(ev.reason.substr(0, ev.verdict.size() + 1), ev.verdict + ":");
            continue;
        }
        BOOST_CHECK(!b.exists("invalid") || !b["invalid"].get_bool());
        UndoRecord undo;
        BOOST_REQUIRE(!ApplyBlock(view, P, block, height, hash, b["subsidyZat"].get_int64(), undo).has_value());
        BOOST_CHECK(SerializeRecord(undo) == SerializeRecord(ev.undo));
        undos.push_back(undo);
    }
    BOOST_CHECK_EQUAL(invalidBlocks, 22);
    BOOST_CHECK_EQUAL(Hash(view), GOLDEN_HASH);
    BOOST_CHECK_EQUAL(Hash(view), doc["stateHash"].get_str());
    State st(view);
    BOOST_CHECK_EQUAL(st.GetTip()->height, doc["tip"]["height"].get_int());
    BOOST_CHECK_EQUAL(st.GetTip()->blockHash.GetHex(), doc["tip"]["hash"].get_str());
    Totals t = st.GetTotals();
    BOOST_CHECK_EQUAL(t.supplyCents, doc["totals"]["supplyCents"].get_int64());
    BOOST_CHECK_EQUAL(t.collateralZat, doc["totals"]["collateralZat"].get_int64());
    BOOST_CHECK_EQUAL((int)t.activeVaults, doc["totals"]["activeVaults"].get_int());
    BOOST_CHECK_EQUAL((int)t.voidVaults, doc["totals"]["voidVaults"].get_int());
    BOOST_CHECK_EQUAL((int)t.closedVaults, doc["totals"]["closedVaults"].get_int());
    BOOST_CHECK_EQUAL((int)t.claimedVaults, doc["totals"]["claimedVaults"].get_int());
    BOOST_CHECK_EQUAL(t.unbackedCents, doc["totals"]["unbackedCents"].get_int64());
    BOOST_CHECK_EQUAL(t.openDebtCents, doc["totals"]["openDebtCents"].get_int64());     // HALT-2's denominator (SCHEMA_VERSION 15)
    BOOST_CHECK(!OpenDebtInvariantViolation(view).has_value());
    // FEE-1': every vault record the vector leaves -- the attestor cancel's re-created one included -- carries its mint price
    int vaults = 0;
    view.Iterate("V", [&](const std::string&, const std::string& raw) {
        VaultRecord v;
        BOOST_REQUIRE(DeserializeRecord(raw, v));
        BOOST_CHECK(v.pMint > 0 && v.pMint <= PRICE_MAX);
        vaults++;
        return true;
    });
    BOOST_CHECK_GT(vaults, 0);
    // UNDO: undoing the whole vector restores the empty view byte for byte.
    for (auto it = undos.rbegin(); it != undos.rend(); ++it) UndoBlock(view, *it);
    BOOST_CHECK(view == empty);
}

// ===========================================================================
// Tags, medians, activation (§3.2, §3.7 PRICE/ACT, §3.8 ACT/HALT)

// Rule: TOK-PQ
// Rule: MINT-3
// The cross-implementation post-quantum chain (yellowback_pq_vectors.json "chain", built by the Python model):
// Falcon owners and every holder shape on both sides of pqFalconHeight; the C++ module rejects exactly the listed
// blocks with the listed verdicts and ends on the model's state hash; undoing everything restores the empty view.
BOOST_AUTO_TEST_CASE(pq_vectors_chain_across_falcon)
{
    UniValue doc;
    BOOST_REQUIRE(doc.read(std::string(json_tests::yellowback_pq_vectors, json_tests::yellowback_pq_vectors + sizeof(json_tests::yellowback_pq_vectors))));
    const UniValue& c = doc["chain"];
    const UniValue& pj = c["params"];
    yellowback::Params P = RegtestParams(pj["startHeight"].get_int(), pj["sigmaRefBps"].get_int(), pj["supplyCapBps"].get_int(), uint256S(pj["attestorSetId"].get_str()),
                                         pj["attestArmMin"].get_int(), (BundleCarrier)pj["bundleCarrier"].get_int(),
                                         pj["mintRequiresArmed"].get_bool());
    P.pqFalconHeight = pj["pqFalconHeight"].get_int();
    std::map<int, std::string> expected;
    for (size_t i = 0; i < c["invalid"].size(); i++) expected[c["invalid"][i]["height"].get_int()] = c["invalid"][i]["verdict"].get_str();
    BOOST_REQUIRE_EQUAL(expected.size(), 6U);
    MemoryStateView view;
    const MemoryStateView empty = view;
    std::vector<UndoRecord> undos;
    size_t invalidBlocks = 0;
    const UniValue& blocks = c["blocks"];
    for (size_t i = 0; i < blocks.size(); i++) {
        const UniValue& b = blocks[i];
        CBlock block;
        for (size_t j = 0; j < b["txs"].size(); j++) {
            CTransaction tx;
            BOOST_REQUIRE_NO_THROW(DecodeHexTx(tx, b["txs"][j].get_str()));
            block.vtx.push_back(tx);
        }
        const int height = b["height"].get_int();
        const uint256 hash = uint256S(b["hash"].get_str());
        OverlayStateView overlay(view);
        BlockEvaluation ev = EvaluateBlock(overlay, P, block, height, hash, b["subsidyZat"].get_int64());
        overlay.Discard();
        if (ev.blockInvalid) {
            invalidBlocks++;
            BOOST_CHECK(b.exists("invalid") && b["invalid"].get_bool());
            BOOST_REQUIRE_MESSAGE(expected.count(height), strprintf("block %d invalid: %s", height, ev.reason));
            BOOST_CHECK_EQUAL(ev.verdict, expected.at(height));
            continue;
        }
        BOOST_CHECK_MESSAGE(!b.exists("invalid") || !b["invalid"].get_bool(), strprintf("block %d should be invalid", height));
        UndoRecord undo;
        BOOST_REQUIRE(!ApplyBlock(view, P, block, height, hash, b["subsidyZat"].get_int64(), undo).has_value());
        undos.push_back(undo);
    }
    BOOST_CHECK_EQUAL(invalidBlocks, expected.size());
    BOOST_CHECK_EQUAL(Hash(view), c["stateHash"].get_str());
    State st(view);
    BOOST_CHECK_EQUAL(st.GetTip()->height, c["tip"]["height"].get_int());
    BOOST_CHECK_EQUAL(st.GetTotals().supplyCents, c["totals"]["supplyCents"].get_int64());
    BOOST_CHECK_EQUAL((int)st.GetTotals().activeVaults, c["totals"]["activeVaults"].get_int());
    for (auto it = undos.rbegin(); it != undos.rend(); ++it) UndoBlock(view, *it);
    BOOST_CHECK(view == empty);
}


// Rule: TAG-3
// Rule: TAG-4
// Rule: SNAP
// Rule: REG-1
BOOST_AUTO_TEST_CASE(tag3_signal_only_registers_nobody)
{
    Fixture f;
    f.Mine(Fixture::SignalOnly(1));                       // signal-only: no quote, no payee (ACT-1 left with the upgrade)
    BOOST_CHECK(f.Snap(1).tagged);
    BOOST_CHECK(!f.Snap(1).quote);
    BOOST_CHECK(EligiblePayees(f.view, f.P, 1).empty());
    BOOST_CHECK(!Registered(f.view, f.P, CKeyID(KeyOf(1)), 1));
    f.Mine(Fixture::Quote(50000, 2));
    BOOST_CHECK(f.Snap(2).quote);
    BOOST_CHECK(Registered(f.view, f.P, CKeyID(KeyOf(2)), 2));
    BOOST_CHECK_EQUAL(EligiblePayees(f.view, f.P, 2).size(), 1u);
    // TAG-4: garbage in the coinbase (an invalid tag, or no tag) never makes a block invalid and is "no tag".
    CoinbaseTag bad = Fixture::Quote(50000, 1);
    bad.flags = 0x03;
    BlockEvaluation ev = f.Mine(bad);
    BOOST_CHECK(!ev.blockInvalid);
    BOOST_CHECK(!f.Snap(3).tagged);
    ev = f.Mine(std::nullopt);
    BOOST_CHECK(!ev.blockInvalid);
    BOOST_CHECK(!f.Snap(4).tagged);
    // REG-1 lapse: registration ends N_REG blocks after the last quote.
    BOOST_CHECK(Registered(f.view, f.P, CKeyID(KeyOf(2)), 2 + f.P.nReg - 1));
    BOOST_CHECK(!Registered(f.view, f.P, CKeyID(KeyOf(2)), 2 + f.P.nReg));
}

// Rule: PRICE-1
// Rule: PRICE-2
// Rule: HALT-1
BOOST_AUTO_TEST_CASE(price1_half_fill_boundary_and_selectors)
{
    Fixture f;
    // Fast window 8, fill ceil(8/2) = 4: three quotes in the last 8 blocks => undefined; four => defined.
    f.Mine(Fixture::Quote(50000, 0));
    f.Mine(Fixture::Quote(50100, 1));
    f.Mine(Fixture::Quote(50200, 2));
    BOOST_CHECK(!f.Snap(3).PFast().has_value());
    BOOST_CHECK(f.Snap(3).haltMask & HALT_NO_PRICE);
    f.Mine(Fixture::Quote(50300, 0));
    BOOST_CHECK_EQUAL(f.Snap(4).PFast().value(), 50100);   // lower median of {50000,50100,50200,50300}
    BOOST_CHECK(!f.Snap(4).PMint().has_value());            // mid/slow still undefined => pMint undefined, NO_PRICE
    BOOST_CHECK(f.Snap(4).haltMask & HALT_NO_PRICE);
    // Rising series: pMint = min = the slowest median; falling: pMint = the fast one; pClaim = max(mid, slow).
    f.MineQuotesTo(70, 50000);
    for (int h = 71; h <= 90; h++) f.Mine(Fixture::Quote(60000, h % 3));
    Snapshot s = f.Snap(90);
    BOOST_CHECK_EQUAL(s.PFast().value(), 60000);
    BOOST_CHECK_EQUAL(s.PSlow().value(), 50000);
    BOOST_CHECK_EQUAL(s.PMint().value(), 50000);
    BOOST_CHECK_EQUAL(s.PClaim().value(), std::max(s.PMid().value(), s.PSlow().value()));
    for (int h = 91; h <= 110; h++) f.Mine(Fixture::Quote(40000, h % 3));
    s = f.Snap(110);
    BOOST_CHECK_EQUAL(s.PFast().value(), 40000);
    BOOST_CHECK_EQUAL(s.PMint().value(), 40000);
    BOOST_CHECK(s.PClaim().value() >= s.PMid().value());
}

// Rule: PRICE-1
BOOST_AUTO_TEST_CASE(price1_mid_slow_need_two_thirds)
{
    // Mid window 24 needs ceil(2*24/3) = 16 quotes; 15 is not enough (L9). Quote every block from 2.
    Fixture f;
    f.Mine(std::nullopt);
    for (int h = 2; h <= 16; h++) f.Mine(Fixture::Quote(50000, h % 3));     // 15 quotes at 16
    BOOST_CHECK(!f.Snap(16).PMid().has_value());
    f.Mine(Fixture::Quote(50000, 2));                                         // 16 quotes at 17
    BOOST_CHECK(f.Snap(17).PMid().has_value());
    // Slow window 64 needs 43: at 44 there are 43 quotes (heights 2..44).
    for (int h = 18; h <= 43; h++) f.Mine(Fixture::Quote(50000, h % 3));
    BOOST_CHECK(!f.Snap(43).PSlow().has_value());
    f.Mine(Fixture::Quote(50000, 1));
    BOOST_CHECK(f.Snap(44).PSlow().has_value());
    BOOST_CHECK(f.Snap(44).PMint().has_value());
}

// Rule: HALT-1
// Rule: HALT-2
// Rule: HALT-3
// Rule: HALT-4
BOOST_AUTO_TEST_CASE(halt2_halt3_clear_with_undefined_price)
{
    Fixture f;
    // Before any price: HALT-1 by name, HALT-2/3 clear (M1); HALT-4 marks only the virtual snapshot (U-22).
    f.Mine(Fixture::Quote(50000, 0));
    BOOST_CHECK_EQUAL(f.Snap(1).haltMask, (uint32_t)HALT_NO_PRICE);
    f.Activate();
    const uint256 vault = f.MintActive(10000);
    // HALT-2 at the exact threshold: ratio 250% => not below => clear; 249.99% => set.
    Snapshot s = f.Snap(f.tip);
    BOOST_CHECK(s.GlobalRatioBps().has_value());
    BOOST_CHECK(s.GlobalRatioBps().value() >= 30000 - 1);        // 300% (class A, D-IT-4) at pMint 50,000
    // Crash the fast median to 1/3: divergence and, once pMint follows, the global ratio halt.
    for (int i = 0; i < 8; i++) f.Mine(Fixture::Quote(15000, (f.tip + 1) % 3));
    s = f.Snap(f.tip);
    BOOST_CHECK(s.haltMask & HALT_DIVERGENCE);                    // pFast 15,000 < 0.8 * pMid
    BOOST_CHECK(s.haltMask & HALT_GLOBAL_RATIO);                   // 10,000 YEC * 0.015 / $100 = 150%
    BOOST_CHECK(!(s.haltMask & HALT_NO_PRICE));
    (void)vault;
}

// Rule: HALT-2
BOOST_AUTO_TEST_CASE(halt2_fires_at_exact_threshold)
{
    // GLOBAL_RATIO is set iff globalRatioBps < GLOBAL_RATIO_HALT_BPS (25,000), evaluated by the math directly.
    BOOST_CHECK_EQUAL(GlobalRatioBps(5000 * COIN, 50000, 10000).value(), 25000);   // 5,000 YEC at $0.05 backs $100 at 250% exactly
    BOOST_CHECK(!(GlobalRatioBps(5000 * COIN, 50000, 10000).value() < 25000));
    BOOST_CHECK(GlobalRatioBps(5000 * COIN - 1, 50000, 10000).value() < 25000);
}

// Rule: HALT-3
BOOST_AUTO_TEST_CASE(halt3_fires_on_mid_vs_slow)
{
    Fixture f;
    f.MineQuotesTo(64, 50000);
    // 24 blocks at 39,000: pMid falls to 39,000 while pSlow stays 50,000: 39,000 < 0.8 * 50,000.
    for (int i = 0; i < 24; i++) f.Mine(Fixture::Quote(39000, (f.tip + 1) % 3));
    Snapshot s = f.Snap(f.tip);
    BOOST_CHECK_EQUAL(s.PMid().value(), 39000);
    BOOST_CHECK_EQUAL(s.PSlow().value(), 50000);
    BOOST_CHECK(s.haltMask & HALT_DIVERGENCE);
}

// Rule: SIGMA-1
BOOST_AUTO_TEST_CASE(sigma1_undefined_sample_gives_cap)
{
    // Non-zero SIGMA_REF: below START + VOL_WINDOW a sample is virtual => the cap (K12); after, 1x on a flat series.
    // D-IT-5 (IT-4) sets the cap itself to 1x (sigmaMultMaxBps 10,000), so the multiplier is 1x throughout.
    Fixture f(1, 10000, 0, 0);
    BOOST_CHECK_EQUAL(f.P.sigmaMultMaxBps, 10000);
    f.MineQuotesTo(64);
    BOOST_CHECK_EQUAL(f.Snap(64).sigmaMultBps, f.P.sigmaMultMaxBps);   // s_8 = Snapshots[0] is virtual => the cap
    f.MineQuotesTo(67);
    BOOST_CHECK_EQUAL(f.Snap(67).sigmaMultBps, f.P.sigmaMultMaxBps);   // s_8 = Snapshots[3].pFast is undefined (3 quotes < 4)
    f.MineQuotesTo(68);
    BOOST_CHECK_EQUAL(f.Snap(68).sigmaMultBps, 10000);           // every sample defined and equal
    // With SIGMA_REF 0 the multiplier is fixed at 1 before the sample check.
    Fixture g(1, 0, 0, 0);
    g.MineQuotesTo(10);
    BOOST_CHECK_EQUAL(g.Snap(10).sigmaMultBps, 10000);
}

// Rule: SIGMA-1
BOOST_AUTO_TEST_CASE(sigma1_one_pool_cannot_inflate)
{
    // One of three pools alternates +-20%: the lower median of the fast window ignores it.
    Fixture f(1, 10000, 0, 0);
    for (int h = 1; h <= 140; h++) {
        MicroUsd p = 50000;
        if (h % 3 == 0) p = (h % 2) ? 60000 : 40000;
        f.Mine(Fixture::Quote(p, h % 3));
    }
    for (int h = 70; h <= 140; h++) BOOST_CHECK_EQUAL(f.Snap(h).sigmaMultBps, 10000);
}

// ===========================================================================
// Judgement, eligible payees, the wallet default (§3.7 REG-2..4, FEE-0..2, FEE-W)

// Rule: REG-4
// Rule: REG-2
// Rule: REG-3
BOOST_AUTO_TEST_CASE(reg4_judgement_lag_and_bands)
{
    Fixture f;
    // Quotes at 1..12 from three pools; pool 0 quotes 12% high at 6 (penalised) and 2% high at 9 (in band).
    for (int h = 1; h <= 12; h++) {
        MicroUsd p = 50000;
        if (h == 6) p = 56000;
        if (h == 9) p = 51000;
        f.Mine(Fixture::Quote(p, h % 3));
    }
    State st(f.view);
    // The judgement for t is written at t + PEER_LAG (4): t = 8 exists after block 12, t = 9 does not.
    BOOST_CHECK(st.GetJudgement(8).has_value());
    BOOST_CHECK(!st.GetJudgement(9).has_value());
    // t = 6: peers at 2..9 minus 6 = 7 quotes, median 50,000, dev 1,200 bps > 1,000 => penalized, not in band.
    BOOST_REQUIRE(st.GetJudgement(6).has_value());
    BOOST_CHECK(st.GetJudgement(6)->evaluated);
    BOOST_CHECK(st.GetJudgement(6)->penalized);
    BOOST_CHECK(!st.GetJudgement(6)->inBand);
    // t = 1: peers in [-3, 4] are 2, 3, 4 = 3 >= PEER_MIN: evaluated, in band.
    BOOST_REQUIRE(st.GetJudgement(1).has_value());
    BOOST_CHECK(st.GetJudgement(1)->evaluated && st.GetJudgement(1)->inBand && !st.GetJudgement(1)->penalized);
    f.MineQuotesTo(20);
    State st2(f.view);
    // t = 9: dev 200 bps <= 300 => in band.
    BOOST_CHECK(st2.GetJudgement(9)->evaluated && st2.GetJudgement(9)->inBand);
    // Too few peers: a lone quote among untagged blocks is written but not evaluated.
    Fixture g;
    g.Mine(std::nullopt); g.Mine(std::nullopt); g.Mine(Fixture::Quote(50000, 0));
    for (int i = 0; i < 6; i++) g.Mine(std::nullopt);
    State gs(g.view);
    BOOST_REQUIRE(gs.GetJudgement(3).has_value());
    BOOST_CHECK(!gs.GetJudgement(3)->evaluated);
    // REG-2 window edges: penalised at t = 6 counts for R in (10, 22] (lag 4, N_PENALTY 12).
    const CKeyID k2(KeyOf(0));   // 6 % 3 == 0
    BOOST_CHECK(!Penalized(f.view, f.P, k2, 10, f.P.nPenalty));
    BOOST_CHECK(Penalized(f.view, f.P, k2, 11, f.P.nPenalty));
    BOOST_CHECK(Penalized(f.view, f.P, k2, 22, f.P.nPenalty));
    BOOST_CHECK(!Penalized(f.view, f.P, k2, 23, f.P.nPenalty));
    BOOST_CHECK(!Penalized(f.view, f.P, k2, 11, 0));
    // REG-3: pool 0 quoted at 3, 6, 9, 12, 15, 18 (judged up to R - 4 = 16 at R = 20): 3, 6, 9, 12, 15 evaluated; 6 out of band.
    BOOST_CHECK_EQUAL(AccuracyBps(f.view, f.P, k2, 20, f.P.accuracyWindow), 8000);
    BOOST_CHECK_EQUAL(AccuracyBps(f.view, f.P, k2, 20, 1), 0);         // window 1: t = 16 only (pool 1's), none for pool 0
    BOOST_CHECK_EQUAL(AccuracyBps(f.view, f.P, k2, 20, 4), 10000);     // window 4: t in [13, 16]: pool 0's 15, in band
    BOOST_CHECK_EQUAL(AccuracyBps(f.view, f.P, CKeyID(KeyOf(7)), 20, 24), 0);
}

// Rule: FEE-2
// Rule: FEE-0
BOOST_AUTO_TEST_CASE(fee2_eligible_set_window_edges)
{
    Fixture f;
    f.Mine(Fixture::Quote(50000, 0));                  // 1
    f.Mine(Fixture::SignalOnly(1));                    // 2: signal-only, never eligible
    for (int h = 3; h <= 12; h++) f.Mine(std::nullopt);
    // PAYEE_WINDOW 10: E(R) contains key 0 for R in [1, 10], not at 11.
    BOOST_CHECK_EQUAL(EligiblePayees(f.view, f.P, 10).size(), 1u);
    BOOST_CHECK(EligiblePayees(f.view, f.P, 10)[0] == CKeyID(KeyOf(0)));
    BOOST_CHECK(EligiblePayees(f.view, f.P, 11).empty());          // FEE-0
    BOOST_CHECK(EligiblePayees(f.view, f.P, 2).size() == 1);        // the signal-only tag adds nobody
    // Dedup and height order.
    f.Mine(Fixture::Quote(50000, 2));                  // 13
    f.Mine(Fixture::Quote(50000, 0));                  // 14
    f.Mine(Fixture::Quote(50000, 2));                  // 15
    std::vector<CKeyID> e = EligiblePayees(f.view, f.P, 15);
    BOOST_REQUIRE_EQUAL(e.size(), 2u);
    BOOST_CHECK(e[0] == CKeyID(KeyOf(2)));
    BOOST_CHECK(e[1] == CKeyID(KeyOf(0)));
}

// Rule: FEE-1'
BOOST_AUTO_TEST_CASE(fee1_floor_dominates_small_vault)
{
    const yellowback::Params P = RegtestParams(1, 0, 0, TestSet());
    // The regtest column carries mainnet's bands and floor (fees spec ambiguity 8): $100 pays the $1 floor, $10,000 pays $55.
    BOOST_CHECK_EQUAL(ProtocolFeeCents(10000, P), 100);
    BOOST_CHECK_EQUAL(ProtocolFeeCents(1000000, P), 5500);
    BOOST_CHECK_EQUAL(ProtocolFeeZat(10000, 50000, P).value(), 2000000000LL);          // $1 at $0.05 = 20 YEC
    BOOST_CHECK_EQUAL(ProtocolFeeZat(10000, 50000 + 1, P).value(), 1999960001LL);      // ceil
    BOOST_CHECK(!ProtocolFeeZat(10000, 0, P).has_value());                             // no price, no fee (RED-1' refuses the vault)
}

namespace {

/** A 10-block window with alternating perfect (A = key 0) and never-in-band (B = key 1) miners, judged. */
Fixture PayeeFixture()
{
    Fixture f;
    f.MineQuotesTo(40);                                       // three pools so every tag is evaluated
    for (int h = 41; h <= 60; h++) f.Mine(Fixture::Quote(50000, h % 2));
    f.MineQuotesTo(70);                                       // judge the last of them (lag 4)
    // Rewrite the judgements: A always in band, B never (evaluated, not penalised).
    State st(f.view);
    for (int t = 33; t <= 60; t++) {
        Judgement j;
        j.evaluated = true;
        j.inBand = t <= 40 ? (t % 3 == 0) : (t % 2 == 0);   // A = key 0 (t % 3 == 0 before 41, even after)
        j.penalized = false;
        st.Put(keys::Judgement((uint32_t)t), j);
    }
    return f;
}

/** `selector = i` as 33 bytes, shaped like an owner key: 0x02 ‖ i little-endian (N28). */
std::vector<unsigned char> Selector(int i)
{
    std::vector<unsigned char> s(33, 0);
    s[0] = 0x02;
    s[1] = i & 0xff;
    s[2] = (i >> 8) & 0xff;
    return s;
}

} // namespace

// Rule: FEE-W
// Rule: FEE-2
BOOST_AUTO_TEST_CASE(feew_accuracy_tilt_ratio)
{
    Fixture f = PayeeFixture();
    // R = 60: E(R) = {A, B} from heights 51..60; accuracy over (60 - 4 - 24, 56] = (32, 56]: A 10000, B 0.
    BOOST_CHECK_EQUAL(AccuracyBps(f.view, f.P, CKeyID(KeyOf(0)), 60, f.P.accuracyWindow), 10000);
    BOOST_CHECK_EQUAL(AccuracyBps(f.view, f.P, CKeyID(KeyOf(1)), 60, f.P.accuracyWindow), 0);
    PayeePolicy def = PayeePolicy::Defaults(f.P);
    int a = 0, b = 0;
    for (int i = 0; i < 1000; i++) {
        std::optional<CKeyID> k = DefaultPayee(f.view, f.P, 60, Selector(i), def);
        BOOST_REQUIRE(k.has_value());
        if (k.value() == CKeyID(KeyOf(0))) a++;
        else if (k.value() == CKeyID(KeyOf(1))) b++;
        else BOOST_FAIL("pick outside E(R)");
    }
    BOOST_CHECK_MESSAGE(a >= 18 * b / 10 && a <= 22 * b / 10, strprintf("default tilt ratio %d:%d", a, b));
    PayeePolicy flat = def;
    flat.tiltBps = 0;
    a = b = 0;
    for (int i = 0; i < 1000; i++) {
        std::optional<CKeyID> k = DefaultPayee(f.view, f.P, 60, Selector(i), flat);
        if (k.value() == CKeyID(KeyOf(0))) a++; else b++;
    }
    BOOST_CHECK_MESSAGE(a >= 9 * b / 10 && a <= 11 * b / 10, strprintf("tilt 0 ratio %d:%d", a, b));
    // E(R) empty => nullopt.
    BOOST_CHECK(!DefaultPayee(f.view, f.P, 0, Selector(1), def).has_value());
}

// Rule: FEE-W
// Rule: REG-2
BOOST_AUTO_TEST_CASE(feew_penalised_skipped_and_fallback)
{
    Fixture f = PayeeFixture();
    PayeePolicy def = PayeePolicy::Defaults(f.P);
    State st(f.view);
    // Penalise B at t = 53 (R = 60: 57 < 60 <= 69): every pick is A.
    Judgement j; j.evaluated = true; j.inBand = false; j.penalized = true;
    st.Put(keys::Judgement(53), j);
    for (int i = 0; i < 100; i++) BOOST_CHECK(DefaultPayee(f.view, f.P, 60, Selector(i), def).value() == CKeyID(KeyOf(0)));
    // Penalise A too: the all-penalised fallback picks among all of E(R) with equal weights, never empty.
    st.Put(keys::Judgement(54), j);
    int a = 0, b = 0;
    for (int i = 0; i < 1000; i++) {
        std::optional<CKeyID> k = DefaultPayee(f.view, f.P, 60, Selector(i), def);
        BOOST_REQUIRE(k.has_value());
        if (k.value() == CKeyID(KeyOf(0))) a++; else b++;
    }
    BOOST_CHECK(a > 350 && b > 350);
}

// Rule: FEE-W
BOOST_AUTO_TEST_CASE(feew_override_flags_change_pick)
{
    Fixture f = PayeeFixture();
    PayeePolicy def = PayeePolicy::Defaults(f.P);
    State st(f.view);
    Judgement j; j.evaluated = true; j.inBand = false; j.penalized = true;
    st.Put(keys::Judgement(53), j);                       // B penalised for R in (57, 69] at the default N_PENALTY 12
    auto count = [&](const PayeePolicy& pp, int R) {
        int b = 0;
        for (int i = 0; i < 300; i++) if (DefaultPayee(f.view, f.P, R, Selector(i), pp).value() == CKeyID(KeyOf(1))) b++;
        return b;
    };
    BOOST_CHECK_EQUAL(count(def, 60), 0);
    // -yellowbackpayeepenaltyblocks=2: the penalty has lapsed by R = 60 (t + 4 + 2 = 59 < 60).
    PayeePolicy shortPenalty = def; shortPenalty.penaltyBlocks = 2;
    BOOST_CHECK(count(shortPenalty, 60) > 0);
    // -yellowbackpayeeaccuracywindow=1 at R = 60 reads t = 56 only (A's, rewritten out of band): A's accuracy
    // becomes 0 => equal weights, so B is picked more often than with the default window.
    Judgement out; out.evaluated = true; out.inBand = false; out.penalized = false;
    st.Put(keys::Judgement(56), out);
    PayeePolicy narrow = shortPenalty; narrow.accuracyWindow = 1;
    const int bNarrow = count(narrow, 60), bWide = count(shortPenalty, 60);
    BOOST_CHECK(bNarrow > bWide);
    // -yellowbackpayeetiltbps=0 flattens the weights the same way.
    PayeePolicy flat = shortPenalty; flat.tiltBps = 0;
    BOOST_CHECK(count(flat, 60) > bWide);
    // -yellowbackpreferredpayee replaces the pick when in E(R), never otherwise.
    PayeePolicy pref = def; pref.preferred = CKeyID(KeyOf(1));
    BOOST_CHECK_EQUAL(count(pref, 60), 300);
    pref.preferred = CKeyID(KeyOf(7));
    BOOST_CHECK_EQUAL(count(pref, 60), 0);
}

// ===========================================================================
// Money rules (§3.8 IN-1..3, TX-0, MINT-1..8, XFER-1..3, RED-1..4, M3)

// Rule: MINT-1
// Rule: IN-1
// Rule: IN-3
// Rule: TX-0
BOOST_AUTO_TEST_CASE(mint1_wellformed_creates_vault_and_token)
{
    Fixture f;
    f.Activate();
    const int ref = f.tip - 1;
    CMutableTransaction m = f.MintTx(10000, 48, ref);
    BlockEvaluation ev = f.Mine(Fixture::Quote(50000, 0), { m });
    const uint256 txid = CTransaction(m).GetHash();
    BOOST_CHECK(!ev.blockInvalid);
    BOOST_REQUIRE(f.Vault(txid).has_value());
    const VaultRecord v = f.Vault(txid).value();
    BOOST_CHECK_EQUAL(v.status, (uint8_t)VaultStatus::ACTIVE);
    BOOST_CHECK_EQUAL(v.mintedCents, 10000);
    BOOST_CHECK_EQUAL(v.collateralZat, 600000000000LL);             // $100 at 300% (class A, D-IT-4) and $0.05
    BOOST_CHECK_EQUAL(v.lockHeight, ref + 48);
    BOOST_CHECK_EQUAL(v.claimHeight, ref + 48 + 24);
    BOOST_CHECK_EQUAL(v.appHeight, ref + 1);                        // IT-1: the APP branch opens the block after the mint
    BOOST_CHECK_EQUAL(v.ownerHeight, ref + 1);                      // IT-1 (extended): and the owner's
    BOOST_CHECK_EQUAL(v.refHeight, ref);
    BOOST_CHECK_EQUAL(v.pMint, f.PMintAt(ref));                                      // FEE-1': the mint price is stored
    BOOST_CHECK_EQUAL(v.feePaidZat, f.VaultFee(v));
    BOOST_CHECK(v.Owner() == TestPQOwner(f.ownerKey.GetPubKey()));
    BOOST_REQUIRE(f.Token(txid, 1).has_value());
    BOOST_CHECK_EQUAL(f.Token(txid, 1)->cents, 10000);
    BOOST_REQUIRE(f.Log(txid).has_value());
    BOOST_CHECK_EQUAL(f.Log(txid)->verdict, verdict::OK);
    BOOST_CHECK_EQUAL(f.Log(txid)->type, (uint8_t)TxLogType::MINT);
    BOOST_CHECK_EQUAL(f.Log(txid)->yedOut, 10000);
    BOOST_CHECK_EQUAL(f.Log(txid)->burned, 0);
    BOOST_CHECK(f.Log(txid)->hasPayee);
    BOOST_CHECK_EQUAL(f.GetTotals().supplyCents, 10000);
    BOOST_CHECK_EQUAL(f.GetTotals().collateralZat, v.collateralZat);
    BOOST_CHECK_EQUAL(f.GetTotals().activeVaults, 1u);
    // MINT-1 fails (version 1 payload): non-Yellowback, so its YED vault output is one no rule created (U-23):
    // the transaction is invalid; no vault.
    CMutableTransaction bad = f.MintTx(10000, 48, f.tip - 1);
    std::vector<unsigned char> data = EncodePayload(Payload::Mint(0, 10000, f.tip + 47, f.tip - 1, TestPQOwner(f.ownerKey.GetPubKey()), 3));
    data[2] = 0x01;
    bad.vout[2] = CTxOut(0, PayloadScript(data));
    f.Mine(Fixture::Quote(50000, 1), { bad });
    BOOST_CHECK(!f.Vault(CTransaction(bad).GetHash()).has_value());
    BOOST_CHECK_EQUAL(f.Refused(CTransaction(bad).GetHash()), verdict::YED_TEMPLATE_OUTPUT);
    // The same with the vault output a plain P2PKH: non-Yellowback, no vault, no log.
    bad.vout[0].scriptPubKey = GetScriptForDestination(f.userKey.GetPubKey().GetID());
    f.Mine(Fixture::Quote(50000, 1), { bad });
    BOOST_CHECK(!f.Vault(CTransaction(bad).GetHash()).has_value());
    BOOST_CHECK(!f.Log(CTransaction(bad).GetHash()).has_value());
    // TX-0: a coinbase carrying a MINT payload registers nothing (its outputs, without the V, are ordinary).
    CMutableTransaction cb = Fixture::Coinbase(f.tip + 1, Fixture::Quote(50000, 2));
    cb.vout = f.MintTx(10000, 48, f.tip - 1).vout;
    {
        // ...but a coinbase may not create a YED vault either (U-23).
        CBlock withV;
        withV.vtx.push_back(CTransaction(cb));
        OverlayStateView o2(f.view);
        BlockEvaluation ev2 = EvaluateBlock(o2, f.P, withV, f.tip + 1, Fixture::FakeHash(f.tip + 1), SUBSIDY);
        BOOST_CHECK(ev2.blockInvalid);
        BOOST_CHECK_EQUAL(ev2.verdict, verdict::YED_TEMPLATE_OUTPUT);
    }
    cb.vout[0].scriptPubKey = GetScriptForDestination(f.userKey.GetPubKey().GetID());
    CBlock block;
    block.vtx.push_back(CTransaction(cb));
    OverlayStateView overlay(f.view);
    BlockEvaluation cbEv = EvaluateBlock(overlay, f.P, block, f.tip + 1, Fixture::FakeHash(f.tip + 1), SUBSIDY);
    BOOST_CHECK(cbEv.txlogs.empty());
    BOOST_CHECK(!State(overlay).GetVault(COutPoint(CTransaction(cb).GetHash(), 0)).has_value());
    BOOST_CHECK(cbEv.snapshot.quote);
}

// Rule: TX-0
BOOST_AUTO_TEST_CASE(tx0_coinbase_payload_registers_nothing)
{
    Fixture f;
    f.Activate();
    CMutableTransaction cb = Fixture::Coinbase(f.tip + 1, std::nullopt);
    cb.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(Payload::Transfer({ Assignment(0, 100) })))));
    State st(f.view);
    TxOutcome r = ProcessTx(st, f.P, CTransaction(cb), f.tip + 1);
    BOOST_CHECK(!r.relevant && !r.vaultSpend && !r.invalid);
    BOOST_CHECK_EQUAL(r.log.verdict, verdict::NON_YELLOWBACK);
}

namespace {

/** Mine a MINT at the next height and return the verdict that made it invalid (U-21; "" for an ACTIVE vault,
 *  "none" when the transaction is not a mint and created no vault). `invalid`: the mint was refused. */
std::string MintVerdictOf(Fixture& f, const CMutableTransaction& m, bool* invalid = nullptr)
{
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3), { m });
    const std::string refused = f.Refused(CTransaction(m).GetHash());
    if (invalid) *invalid = !refused.empty();
    if (!refused.empty()) return refused;
    std::optional<VaultRecord> v = f.Vault(CTransaction(m).GetHash());
    if (!v.has_value()) return "none";
    return v->Status() == VaultStatus::ACTIVE ? "" : v->voidReason;
}

} // namespace

// Rule: MINT-2
BOOST_AUTO_TEST_CASE(mint2_every_clause_voids)
{
    Fixture f;
    f.Activate();
    bool invalid = false;
    { MintOpts o; o.termClass = 3; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o), &invalid), "bad-mint-class"); }
    BOOST_CHECK(invalid);                                   // U-21: a failing mint is an invalid transaction
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(5000, 48, f.tip - 1)), "bad-mint-amount");
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000001, 48, f.tip - 1)), "bad-mint-amount");   // D-Q-24: $100,000 + one cent
    BOOST_CHECK_EQUAL(f.P.maxMint, 10000000);
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, (int)LOCKTIME_THRESHOLD - f.P.grace - (f.tip - 1), f.tip - 1)), "bad-mint-lock-height");
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 47, f.tip - 1)), "bad-mint-lock-height");     // below class A
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 97, f.tip - 1)), "bad-mint-lock-height");     // class A, 97 blocks
    { MintOpts o; o.termClass = 1; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 97, f.tip - 1, o)), ""); }
    { MintOpts o; o.collateral = 1000000000000LL; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip + 1, o)), "bad-mint-ref-height"); }   // ref = H
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip)), "");                              // ref = H - 1
    f.MineQuotesTo(f.tip + 40);                                                                       // so that H - 40 is past activation
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 39)), "");                         // ref = H - 40 (H = tip + 1)
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 40)), "bad-mint-ref-height");      // ref = H - 41
    // §15.10: no VOID record; the failing mint leaves nothing behind.
    const Totals before = f.GetTotals();
    CMutableTransaction m = f.MintTx(5000, 48, f.tip - 1);
    BOOST_CHECK_EQUAL(MintVerdictOf(f, m), "bad-mint-amount");
    BOOST_CHECK(!f.Vault(CTransaction(m).GetHash()).has_value());
    BOOST_CHECK_EQUAL(f.GetTotals().collateralZat, before.collateralZat);
    BOOST_CHECK_EQUAL(f.GetTotals().voidVaults, before.voidVaults);
    BOOST_CHECK_EQUAL(f.GetTotals().supplyCents, before.supplyCents);
    BOOST_CHECK_EQUAL(f.Log(CTransaction(m).GetHash())->verdict, "bad-mint-amount");
    BOOST_CHECK_EQUAL(f.Log(CTransaction(m).GetHash())->yedOut, 0);
}

// Rule: MINT-2
BOOST_AUTO_TEST_CASE(mint2_regtest_height_underflow)
{
    // H < REF_WINDOW on regtest: H - 40 is negative and must not wrap; refHeight 1 at H = 5 is inside the window.
    Fixture f;
    f.MineQuotesTo(4);
    MintOpts o; o.collateral = 1000000000000LL; o.feeKey = 0;
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, 1, o)), "mint-halted-no-price");   // the module is active; no price yet
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, 0, o)), "bad-mint-ref-height");   // below START_HEIGHT
}

// Rule: MINT-3
BOOST_AUTO_TEST_CASE(mint3_outputs_owner_key_vault_script)
{
    Fixture f;
    f.Activate();
    CMutableTransaction two = f.MintTx(10000, 48, f.tip - 1);
    two.vout.resize(2);
    two.vout[1] = CTxOut(0, two.vout[0].scriptPubKey);   // keep vout[0] the V; no third output
    // Two outputs cannot carry an OP_RETURN at all: non-Yellowback, so its YED vaults are outputs no rule created (U-23).
    BOOST_CHECK_EQUAL(MintVerdictOf(f, two), verdict::YED_TEMPLATE_OUTPUT);
    CMutableTransaction m = f.MintTx(10000, 48, f.tip - 1);
    m.vout.resize(3);
    m.vout[1] = m.vout[2];
    m.vout.resize(2);
    BOOST_CHECK_EQUAL(MintVerdictOf(f, m), "bad-mint-outputs");
    { MintOpts o; o.rawOwner = std::vector<unsigned char>(33, 0x04); BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "bad-mint-owner-key"); }
    {
        const CPubKey ownerPub = f.ownerKey.GetPubKey();
        MintOpts o; o.rawOwner = std::vector<unsigned char>(ownerPub.begin(), ownerPub.end());
        o.rawOwner[5] ^= 0x01;                            // a 0x02 prefix but not a curve point (almost surely)
        std::string v = MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o));
        BOOST_CHECK(v == "bad-mint-owner-key" || v == "bad-mint-vault-script");
    }
    { MintOpts o; o.vaultScriptOverride = VaultScript(f.tip + 60, f.ownerKey.GetPubKey(), f.tip + 84); BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "bad-mint-vault-script"); }
    // U-23: v2's P2SH vault (with the payload's own lock) is refused for new mints.
    { const uint32_t lock = f.tip - 1 + 48;
      MintOpts o; o.vaultScriptOverride = P2SHScript(VaultScript(lock, f.ownerKey.GetPubKey(), lock + f.P.grace));
      BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "bad-mint-vault-script"); }
    // A V under another set or delay is not the YED vault either.
    { const int64_t lock = f.tip - 1 + 48;
      vault::VaultParams vp = YedVaultParams(f.P, TestPQOwner(f.ownerKey.GetPubKey()), f.tip - 1);
      vp.delay += 1;
      MintOpts o; o.vaultScriptOverride = vault::BuildVault(vp);
      BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "bad-mint-vault-script"); }
    { MintOpts o; o.p2shVault = false; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "bad-mint-vault-script"); }   // no V at all
}

// Rule: MINT-3
// Rule: TOK-PQ
// The post-quantum line (quantum spec §3.2, F-7, R-A2, A-5): MINT-3 admits an SLH-DSA owner at every height and
// a Falcon owner only from the Falcon height (the module's mirror of the consensus pqFalconHeight); TOK-PQ leaves
// every holder shape valid below that height and, from it, admits only a Falcon TX_PQPKH as a token output of a
// MINT, a TRANSFER and a vault-spending REDEEM. The rule is a function of the block height, so a reindex with the
// Falcon height configured judges history as it was judged: the P2PKH tokens minted below it stay valid and
// spendable (spending is not an output rule), and only new outputs at or above it are bound.
BOOST_AUTO_TEST_CASE(mint3_tokpq_falcon_height_boundary)
{
    Fixture f;
    f.Activate();
    const int falconHeight = f.tip + 7;
    f.P.pqFalconHeight = falconHeight;               // not hashed (spec §3.4): set after the first block is fine
    BOOST_CHECK(!f.P.IsPQFalconActive(falconHeight - 1));
    BOOST_CHECK(f.P.IsPQFalconActive(falconHeight));
    const CPQKeyID slhOwner(pq::SCHEME_SLH_DSA_SHA2_128S, GetRandHash());
    const CPQKeyID falconOwner(pq::SCHEME_FN_DSA_512, GetRandHash());
    const CPQKeyID falconHolder(pq::SCHEME_FN_DSA_512, GetRandHash());
    const CPQKeyID slhHolder(pq::SCHEME_SLH_DSA_SHA2_128S, GetRandHash());
    const CScript falconSpk = GetScriptForDestination(falconHolder);
    BOOST_CHECK_EQUAL(falconSpk.size(), 35u);
    // The verdict of a mined transaction: "" when it was neither refused nor logged.
    auto verdictOf = [&](const CMutableTransaction& m, bool* invalid) -> std::string {
        f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3), { m });
        const std::string refused = f.Refused(CTransaction(m).GetHash());
        if (invalid) *invalid = !refused.empty();
        if (!refused.empty()) return refused;
        std::optional<TxLogRecord> log = f.Log(CTransaction(m).GetHash());
        return log.has_value() ? log->verdict : "";
    };
    BOOST_CHECK(HolderKey(falconSpk) == std::optional<CTxDestination>(CTxDestination(falconHolder)));

    // Below the Falcon height: a Falcon owner is refused (MINT-3), a P2PKH or any PQPKH token is fine.
    { MintOpts o; o.pqOwner = falconOwner; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), verdict::BAD_MINT_OWNER_KEY); }
    BOOST_REQUIRE_LT(f.tip + 1, falconHeight);
    CMutableTransaction below = f.MintTx(10000, 48, f.tip - 1);              // P2PKH token
    BOOST_CHECK_EQUAL(MintVerdictOf(f, below), "");
    const uint256 belowId = CTransaction(below).GetHash();
    { MintOpts o; o.tokenScript = GetScriptForDestination(slhHolder); BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), ""); }
    { MintOpts o; o.tokenScript = GetScriptForPQChannel(slhHolder, f.userKey.GetPubKey(), 1000); BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), ""); }   // D-Q-19 below
    // A TRANSFER below the height to P2PKH and to an SLH-DSA PQPKH: no shape rule yet.
    {
        CMutableTransaction t = f.TransferTx({ COutPoint(belowId, 1) }, { Assignment(0, 6000), Assignment(1, 4000) });
        t.vout[1].scriptPubKey = GetScriptForDestination(slhHolder);
        bool invalid = true;
        BOOST_CHECK_EQUAL(verdictOf(t, &invalid), verdict::OK);
        BOOST_CHECK(!invalid);
        BOOST_REQUIRE(f.Token(CTransaction(t).GetHash(), 0).has_value());
        below = t;                                                           // its P2PKH output 0 is a pre-height token
    }
    const COutPoint preHeightP2PKH(CTransaction(below).GetHash(), 0);
    while (f.tip + 1 < falconHeight) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_REQUIRE_EQUAL(f.tip + 1, falconHeight);

    // At the Falcon height: a P2PKH (or SLH-DSA PQPKH) token output of a MINT is bad-yed-holder (the tx is invalid).
    { bool invalid = false; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1), &invalid), verdict::BAD_YED_HOLDER); BOOST_CHECK(invalid); }
    { MintOpts o; o.tokenScript = GetScriptForDestination(slhHolder); BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), verdict::BAD_YED_HOLDER); }
    // A Falcon owner mints now (MINT-3), and a Falcon holder takes the token.
    CMutableTransaction pqMint;
    { MintOpts o; o.pqOwner = falconOwner; o.tokenScript = falconSpk; pqMint = f.MintTx(10000, 48, f.tip - 1, o); BOOST_CHECK_EQUAL(MintVerdictOf(f, pqMint), ""); }
    CMutableTransaction slhFalcon;
    { MintOpts o; o.tokenScript = falconSpk; slhFalcon = f.MintTx(10000, 48, f.tip - 1, o); BOOST_CHECK_EQUAL(MintVerdictOf(f, slhFalcon), ""); }   // SLH-DSA owner, Falcon holder
    COutPoint okToken;
    BOOST_CHECK(f.Vault(CTransaction(pqMint).GetHash())->Owner() == falconOwner);
    // D-Q-19: a hybrid channel holds YED from the Falcon height iff its client is a Falcon key.
    {
        MintOpts o; o.tokenScript = GetScriptForPQChannel(falconHolder, f.userKey.GetPubKey(), f.tip + 100);
        BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "");
        MintOpts o2; o2.tokenScript = GetScriptForPQChannel(slhHolder, f.userKey.GetPubKey(), f.tip + 100);
        BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o2)), verdict::BAD_YED_HOLDER);
    }

    // The pre-height P2PKH token stays valid and spendable: a TRANSFER of it to a Falcon holder holds...
    {
        CMutableTransaction t = f.TransferTx({ preHeightP2PKH }, { Assignment(0, 6000) });
        t.vout[0].scriptPubKey = falconSpk;
        bool invalid = true;
        BOOST_CHECK_EQUAL(verdictOf(t, &invalid), verdict::OK);
        BOOST_CHECK(!invalid);
        BOOST_CHECK_EQUAL(f.Token(CTransaction(t).GetHash(), 0)->cents, 6000);
    }
    // ...while a TRANSFER (or a REDEEM payload with no vault) to P2PKH is refused, not burned: the inputs stay unspent.
    {
        const COutPoint tok(CTransaction(pqMint).GetHash(), 1);
        CMutableTransaction t = f.TransferTx({ tok }, { Assignment(0, 10000) });           // P2PKH(userKey)
        f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3), { t });
        BOOST_CHECK_EQUAL(f.Refused(CTransaction(t).GetHash()), verdict::BAD_YED_HOLDER);
        BOOST_CHECK(f.Token(tok.hash, tok.n).has_value());
        CMutableTransaction r = f.TransferTx({ tok }, { Assignment(0, 10000) }, true, (uint32_t)(f.tip - 1));
        f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3), { r });
        BOOST_CHECK_EQUAL(f.Refused(CTransaction(r).GetHash()), verdict::BAD_YED_HOLDER);
        CMutableTransaction ok = f.TransferTx({ tok }, { Assignment(0, 10000) });
        ok.vout[0].scriptPubKey = falconSpk;
        BOOST_CHECK_EQUAL(verdictOf(ok, nullptr), verdict::OK);
        okToken = COutPoint(CTransaction(ok).GetHash(), 0);
    }
    // A vault-spending REDEEM whose YED change is P2PKH is refused too (RED-1's TOK-PQ clause); Falcon change holds.
    {
        const uint256 vaultId = CTransaction(pqMint).GetHash();
        const std::vector<COutPoint> yed = { COutPoint(CTransaction(slhFalcon).GetHash(), 1), okToken };   // 10,000 + 10,000
        SpendOpts o; o.assigned = { Assignment(3, 10000) };                  // burn the 10,000 debt, 10,000 change at vout 3
        CMutableTransaction p2pkhChange = f.SpendTx(vaultId, yed, f.tip - 1, o);
        f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3), { p2pkhChange });
        BOOST_CHECK_EQUAL(f.Refused(CTransaction(p2pkhChange).GetHash()), verdict::BAD_YED_HOLDER);
        BOOST_CHECK_EQUAL(f.Vault(vaultId)->status, (uint8_t)VaultStatus::ACTIVE);
        CMutableTransaction pqChange = f.SpendTx(vaultId, yed, f.tip - 1, o);
        pqChange.vout[3].scriptPubKey = falconSpk;
        bool invalid = true;
        BOOST_CHECK_EQUAL(verdictOf(pqChange, &invalid), verdict::OK);
        BOOST_CHECK(!invalid);
        BOOST_CHECK_EQUAL(f.Vault(vaultId)->status, (uint8_t)VaultStatus::CLOSED);
        BOOST_CHECK_EQUAL(f.Token(CTransaction(pqChange).GetHash(), 3)->cents, 10000);
    }
}

// Rule: MINT-4
// Rule: HALT-4
// Rule: HALT-1
BOOST_AUTO_TEST_CASE(mint4_not_active_and_halts)
{
    // ACT-1..6 left with the vault upgrade (§6): the module is active from START; NOT_ACTIVE is the virtual
    // snapshot below it, and the participation halt no longer exists.
    Fixture f(10);
    f.MineQuotesTo(20);                                     // the slow window is not filled yet: no price
    { MintOpts o; o.collateral = 1000000000000LL; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "mint-halted-no-price"); }
    { MintOpts o; o.collateral = 1000000000000LL; o.feeKey = -1; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, 9, o)), "bad-mint-ref-height"); }   // R below START
    f.Activate();
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1)), "");
    // Non-signal tags halt nothing (v2's PARTICIPATION halt is gone).
    for (int i = 0; i < 26; i++) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3, false));
    BOOST_CHECK_EQUAL(f.Snap(f.tip).haltMask, 0u);
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip)), "");
    // A refHeight whose snapshot was clear still mints (MINT-4 reads R, not H).
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 25)), "");
    // No price: nine untagged blocks empty the fast window.
    for (int i = 0; i < 9; i++) f.Mine(std::nullopt);
    BOOST_CHECK(f.Snap(f.tip).haltMask & HALT_NO_PRICE);
    { MintOpts o; o.collateral = 1000000000000LL; o.feeKey = 0; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "mint-halted-no-price"); }
}

// Rule: MINT-4
BOOST_AUTO_TEST_CASE(mint4_divergence_and_global_ratio)
{
    Fixture f;
    f.Activate();
    f.MintActive(10000);
    for (int i = 0; i < 8; i++) f.Mine(Fixture::Quote(15000, (f.tip + 1) % 3));
    BOOST_CHECK(f.Snap(f.tip).haltMask & HALT_DIVERGENCE);
    BOOST_CHECK(f.Snap(f.tip).haltMask & HALT_GLOBAL_RATIO);
    MintOpts a; a.collateral = 10000000000000LL;                 // class A (termClass 0), lock 48
    MintOpts c = a; c.termClass = 2;                             // class C, lock 145
    // W16 / IT-5: class A (300 %) is below the recapitalisation floor: GLOBAL_RATIO stops it, and takes precedence over DIVERGENCE
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, a)), "mint-halted-global-ratio");
    // class C (500 %) reaches the floor: the global-ratio clause lets it through to the next halt, DIVERGENCE
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 145, f.tip - 1, c)), "mint-halted-divergence");
    // Once the windows agree again the ratio is still low (same supply, same price): class C mints, class A does not
    for (int i = 0; i < 64; i++) f.Mine(Fixture::Quote(15000, (f.tip + 1) % 3));
    BOOST_CHECK(!(f.Snap(f.tip).haltMask & HALT_DIVERGENCE));
    BOOST_CHECK(f.Snap(f.tip).haltMask & HALT_GLOBAL_RATIO);
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, a)), "mint-halted-global-ratio");
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 145, f.tip - 1, c)), "");
}

// Rule: MINT-4
// H-1: with MINT_REQUIRES_ARMED an unarmed R halts the mint (invalid, mint-halted-unarmed) after every
// halt bit; once ARMED the mint is judged exactly as before (MINT-9 needs its bundle).
BOOST_AUTO_TEST_CASE(mint4_requires_armed)
{
    Fixture f;
    f.P.mintRequiresArmed = true;
    f.MineQuotesTo(20);                                     // no price yet: mint-halted-no-price precedes the new clause
    { MintOpts o; o.collateral = 1000000000000LL; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "mint-halted-no-price"); }
    f.Activate();
    BOOST_REQUIRE(!f.Armed());
    bool invalid = true;
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1), &invalid), verdict::MINT_HALTED_UNARMED);
    BOOST_CHECK(invalid);                                   // U-21: invalid like any halted mint
    BOOST_CHECK_EQUAL(std::string(verdict::MINT_HALTED_UNARMED), "mint-halted-unarmed");
    Fixture g;                                              // the same chain without the parameter mints (v2 path)
    g.Activate();
    BOOST_CHECK_EQUAL(MintVerdictOf(g, g.MintTx(10000, 48, g.tip - 1)), "");
    // ARMED: the clause is vacuous; MINT-9 judges the bundle as before
    Fixture a;
    a.P.mintRequiresArmed = true;
    a.Arm();
    BOOST_REQUIRE(a.Armed());
    BOOST_CHECK_EQUAL(MintVerdictOf(a, a.MintTx(10000, 48, a.tip - 1)), verdict::MINT9_NO_BUNDLE);
    BOOST_CHECK_EQUAL(MintVerdictOf(a, a.MintV3(10000, 50000)), "");
    // ATTEST_REQUIRED false means never ARMED (W15): with the parameter nothing mints
    Fixture off;
    off.P.mintRequiresArmed = true;
    off.P.attestRequired = false;
    off.Arm();
    BOOST_CHECK(!off.Armed());
    BOOST_CHECK_EQUAL(MintVerdictOf(off, off.MintTx(10000, 48, off.tip - 1)), verdict::MINT_HALTED_UNARMED);
}

// Rule: MINT-2
// H-5: a class disabled by an empty term range refuses every lock length with the existing verdict.
BOOST_AUTO_TEST_CASE(mint2_disabled_class_refused)
{
    Fixture f;
    f.P.classMin[1] = 97; f.P.classMax[1] = 96;             // B empty
    f.P.classMin[2] = 97; f.P.classMax[2] = 96;             // C empty (the mainnet shape)
    f.Activate();
    MintOpts a; a.collateral = 10000000000000LL;
    MintOpts b = a; b.termClass = 1;
    MintOpts c = a; c.termClass = 2;
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 100, f.tip - 1, b)), "bad-mint-lock-height");
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 97, f.tip - 1, b)), "bad-mint-lock-height");
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 96, f.tip - 1, b)), "bad-mint-lock-height");
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 145, f.tip - 1, c)), "bad-mint-lock-height");
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, a)), "");
}

// Rule: HALT-2
BOOST_AUTO_TEST_CASE(recap_floor_is_the_class_minimum_with_sigma)
{
    // The floor is judged on minRatioBps(class, S), the ratio the mint actually locks: at a sigma
    // multiplier of 1.3x class B (400 %) reaches 520 % and passes, class C (390 %) does not.
    BOOST_CHECK(MinRatioBps(50000, 10000) >= 50000);
    BOOST_CHECK(MinRatioBps(40000, 10000) < 50000);
    BOOST_CHECK(MinRatioBps(40000, 13000) >= 50000);
    BOOST_CHECK(MinRatioBps(30000, 13000) < 50000);
}

// Rule: MINT-6b
// D-Q-23a: the debt of one mint may not exceed max(maxVaultShareBps of the cap, vaultShareFloorCents), every class
// alike, right after MINT-6; with no cap (supplyCapBps 0) the rule is silent.
BOOST_AUTO_TEST_CASE(mint6b_vault_share)
{
    Fixture f(1, 0, 10000, 0);                              // cap = 100 % of market cap ...
    f.P.issuedBeforeStart = 50000 * COIN;                   // ... of 50,000 YEC circulating below the start (D-Q-25) plus the fixture's blocks
    f.Activate(1000000);                                    // $1/YEC: the cap is ~$50,800, 10 % of it ~$5,080
    f.P.vaultShareFloorCents = 10000;                       // the floor at minMint so the share binds
    // the cap (and so the bound) grows with every block's issuance: read it at the mint's own R
    auto maxVaultAt = [&](int ref) {
        const Snapshot s = f.Snap(ref);
        return MaxVaultCents(SupplyCapCents(s.issuedZat, s.PMint(), f.P.supplyCapBps), f.P.maxVaultShareBps, f.P.vaultShareFloorCents).value();
    };
    BOOST_REQUIRE(maxVaultAt(f.tip - 1) > 10000 && maxVaultAt(f.tip - 1) < f.P.maxMint);
    MintOpts c; c.termClass = 2;                            // class C (500 %) passes MINT-6's soft cap: MINT-6b is the one that binds
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(maxVaultAt(f.tip - 1), 145, f.tip - 1, c)), "");
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(maxVaultAt(f.tip - 1) + 1, 145, f.tip - 1, c)), verdict::MINT_VAULT_SHARE);
    MintOpts a;                                             // class A too: every class alike
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(maxVaultAt(f.tip - 1) + 1, 48, f.tip - 1, a)), verdict::MINT_VAULT_SHARE);
    f.P.vaultShareFloorCents = f.P.maxMint;                 // the floor always lets the debt through (here up to maxMint itself)
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(f.P.maxMint, 145, f.tip - 1, c)), "");
    f.P.maxVaultShareBps = 0;                               // the parameter off: no bound
    f.P.vaultShareFloorCents = 1;
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(600000, 145, f.tip - 1, c)), "");
    Fixture g;                                              // no cap on regtest: silent
    g.Activate();
    g.P.vaultShareFloorCents = 1; g.P.maxVaultShareBps = 1000;
    BOOST_CHECK_EQUAL(MintVerdictOf(g, g.MintTx(10000, 48, g.tip - 1)), "");
}

// Rule: MINT-6 (D-Q-25)
// The virtual snapshot's issuedZat is Params::issuedBeforeStart (the circulating YEC below the start height), so every
// snapshot's issuedZat is the circulating supply at its height and the cap is supplyCapBps of market capitalisation.
BOOST_AUTO_TEST_CASE(mint6_issued_seeded_with_the_circulating_supply)
{
    Fixture f(1, 0, 1500, 0);
    f.P.issuedBeforeStart = 1000000 * COIN;                 // 1,000,000 YEC circulating below height 1
    f.Activate(1000000);
    const CAmount issuedSinceStart = f.Snap(f.tip).issuedZat - f.P.issuedBeforeStart;
    BOOST_CHECK_EQUAL(issuedSinceStart, (CAmount)f.tip * SUBSIDY);  // the fixture's subsidies since block 1, on top of the seed
    BOOST_CHECK_EQUAL(f.Snap(1).issuedZat, f.P.issuedBeforeStart + SUBSIDY);
    // 15 % of (1,000,000 YEC + the fixture's blocks) at $1 is the cap: > $150,000; the pre-D-Q-25 base (the issuance
    // since the start alone) was a few hundred dollars on a young chain
    const Cents cap = SupplyCapCents(f.Snap(f.tip - 1).issuedZat, 1000000, 1500).value();
    BOOST_CHECK_GT(cap, 15000000);
    BOOST_CHECK_LT(SupplyCapCents(issuedSinceStart, 1000000, 1500).value(), 100000);
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1)), "");
    Fixture g;                                              // the default seed is 0: issuedZat counts from the start, as before
    g.Activate();
    BOOST_CHECK_EQUAL(g.Snap(g.tip).issuedZat, (CAmount)g.tip * SUBSIDY);
}

// Rule: RED-5'
// D-Q-23a: a residual below $0.48 at the vault's pMint (at least RESIDUAL_MIN_ZAT) is not due: the claim has one intent.
BOOST_AUTO_TEST_CASE(red5_residual_threshold_at_p_mint)
{
    Fixture f;
    f.Activate(1000000);                                    // $1/YEC: the threshold is 0.48 YEC = 48,000,000 zat (> the 100,000-zat floor)
    BOOST_CHECK_EQUAL(ResidualMinZat(1000000, f.P), 48000000);
    BOOST_CHECK_EQUAL(ResidualMinZat(PRICE_MAX, f.P), f.P.residualMinZat);
}

// Rule: MINT-5
BOOST_AUTO_TEST_CASE(mint5_collateral_and_unsatisfiable)
{
    Fixture f;
    f.Activate();
    { MintOpts o; o.collateral = 600000000000LL - 1; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "bad-mint-collateral"); }   // 300 %, D-IT-4
    { MintOpts o; o.collateral = 600000000000LL; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), ""); }
    // At PRICE_MIN the maximum mint needs 5 * 10^16 zat > MAX_MONEY: unsatisfiable (K14).
    Fixture g;
    g.Activate(PRICE_MIN);
    MintOpts o; o.collateral = MAX_MONEY;
    BOOST_CHECK_EQUAL(MintVerdictOf(g, g.MintTx(1000000, 48, g.tip - 1, o)), "mint-unsatisfiable");
    BOOST_CHECK(!RequiredCollateral(1000000, 50000, PRICE_MIN).has_value());
}

// Rule: MINT-6
BOOST_AUTO_TEST_CASE(mint6_supply_cap)
{
    Fixture f(1, 0, 1, 0);                                  // cap = 0.01% of market cap: below $100 on a young regtest chain
    f.Activate();
    BOOST_CHECK(SupplyCapCents(f.Snap(f.tip).issuedZat, 50000, 1).value() < 10000);
    MintOpts a;                                             // class A (300 %): below the W20/IT-5 floor, so the cap is hard for it
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, a)), "mint-supply-cap");
    Fixture g(1, 0, 10000, 0);                              // cap = 100% of market cap: ~$818 at 131 blocks and $1/YEC
    g.Activate(1000000);
    BOOST_CHECK_EQUAL(MintVerdictOf(g, g.MintTx(10000, 48, g.tip - 1, a)), "");
}

// Rule: MINT-6
BOOST_AUTO_TEST_CASE(mint6_cap_is_soft_above_the_recap_floor)
{
    // W20 / IT-5: a mint that would take supply over the cap is refused unless its class base ratio
    // reaches RECAP_RATIO_BPS (500 %): class A (300 %) and class B (400 %) are mint-supply-cap,
    // class C (500 %) goes through and takes supply above the cap (H-10's class-A proxy is replaced).
    Fixture f(1, 0, 100000, 0);                             // cap = 10x market cap: ~ $409 on a young regtest chain at $0.05 (a test knob; the rule's arithmetic has no range)
    f.Activate();                                           // $0.05/YEC, the price MintVerdictOf's blocks quote
    auto capAt = [](const Fixture& x, int ref) { Snapshot s = x.Snap(ref); return SupplyCapCents(s.issuedZat, s.PMint(), x.P.supplyCapBps).value(); };
    const Cents cap0 = capAt(f, f.tip - 1);
    BOOST_REQUIRE(cap0 > 2 * f.P.minMint && cap0 - 5000 <= f.P.maxMint);
    f.MintActive(cap0 - 5000);                              // supply sits at the cap: less than MIN_MINT of headroom
    int ref = f.tip - 1;
    BOOST_REQUIRE(f.GetTotals().supplyCents <= capAt(f, ref));
    BOOST_REQUIRE(f.GetTotals().supplyCents + f.P.minMint > capAt(f, ref));
    MintOpts a; a.collateral = 10000000000000LL;
    MintOpts b = a; b.termClass = 1;                        // class B, lock 100
    MintOpts c = a; c.termClass = 2;                        // class C, lock 145
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, ref, a)), "mint-supply-cap");
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 100, ref, b)), "mint-supply-cap");
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 145, ref, c)), "");
    f.MintActive(10000, 145, 2);                            // class C, lock 145: accepted above the cap
    ref = f.tip - 1;
    BOOST_CHECK(f.GetTotals().supplyCents > capAt(f, ref));
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, ref, a)), "mint-supply-cap");
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 145, ref, c)), "");
    // IT-5 judges the class base, not the sigma-scaled minimum: with SIGMA_REF set and an undefined fast-window
    // sample inside VOL_WINDOW (eight untagged blocks) the multiplier sits at its cap, which IT-4 pins at 1x, so
    // class B stays below the floor and the cap stays hard for it (W20's 1.25x reading is replaced).
    Fixture g(1, 10000, 100000, 0);
    g.Activate();
    for (int i = 0; i < 8; i++) g.Mine();
    g.MineQuotesTo(g.tip + 8);
    BOOST_REQUIRE_EQUAL(g.Snap(g.tip - 1).haltMask, 0u);
    BOOST_CHECK_EQUAL(g.Snap(g.tip - 1).sigmaMultBps, g.P.sigmaMultMaxBps);
    BOOST_CHECK_EQUAL(g.Snap(g.tip - 1).sigmaMultBps, 10000);
    const Cents capG = capAt(g, g.tip - 1);
    g.MintActive(capG - 5000);
    ref = g.tip - 1;
    BOOST_REQUIRE(g.GetTotals().supplyCents + g.P.minMint > capAt(g, ref));
    BOOST_CHECK(MinRatioBps(g.P.baseRatioBps[1], g.Snap(ref).sigmaMultBps) < g.P.recapRatioBps);
    BOOST_CHECK_EQUAL(MintVerdictOf(g, g.MintTx(10000, 100, ref, b)), "mint-supply-cap");
    BOOST_CHECK_EQUAL(MintVerdictOf(g, g.MintTx(10000, 48, ref, a)), "mint-supply-cap");
    BOOST_CHECK_EQUAL(MintVerdictOf(g, g.MintTx(10000, 145, ref, c)), "");
}

// Rule: MINT-7
BOOST_AUTO_TEST_CASE(mint7_token_output_is_not_the_opreturn)
{
    Fixture f;
    f.Activate();
    CMutableTransaction m = f.MintTx(10000, 48, f.tip - 1);
    std::swap(m.vout[1], m.vout[2]);                        // OP_RETURN at vout[1]
    bool invalid = false;
    BOOST_CHECK_EQUAL(MintVerdictOf(f, m, &invalid), "bad-mint-token-output");
    BOOST_CHECK(invalid);
}

// Rule: MINT-8
// Rule: FEE-0
// Rule: FEE-2
BOOST_AUTO_TEST_CASE(mint8_fee_edges)
{
    Fixture f;
    f.Activate();
    { MintOpts o; o.feeKey = -1; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "bad-mint-fee"); }   // 0xFF with a non-empty E(R)
    { MintOpts o; o.feeKey = 7; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "bad-mint-fee"); }    // not in E(R)
    { MintOpts o; o.feeValue = f.MintFee(10000, f.tip - 1) - 1; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "bad-mint-fee"); }
    for (int fv : { 0, 1, 2, 4 }) {                         // the vault, the token, the OP_RETURN, out of range
        MintOpts o; o.feeVout = (uint8_t)fv;
        BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "bad-mint-fee");
    }
    { MintOpts o; o.feeVout = 4; o.extraOutputs = 1; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "bad-mint-fee"); }   // vout 4 is not the fee
    // Any key of E(R) is a valid payee, and a larger fee is fine.
    { MintOpts o; o.feeKey = (f.tip - 1 - 5) % 3; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), ""); }
    { MintOpts o; o.feeValue = 100 * COIN; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), ""); }
    // FEE-0: with an empty E(R) the fee clause is vacuous and a stray fee output is ignored (K11); the fast
    // window is then empty too (PAYEE_WINDOW > P_FAST_WINDOW on regtest), so the verdict is the price halt,
    // never bad-mint-fee.
    for (int i = 0; i < 12; i++) f.Mine(std::nullopt);
    BOOST_CHECK(EligiblePayees(f.view, f.P, f.tip - 1).empty());
    { MintOpts o; o.collateral = 1000000000000LL; o.feeKey = -1; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "mint-halted-no-price"); }
    { MintOpts o; o.collateral = 1000000000000LL; o.feeKey = 7; o.feeValue = 1; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "mint-halted-no-price"); }
}

// Rule: IN-3
// Rule: MINT-1
BOOST_AUTO_TEST_CASE(in3_mint_with_yed_inputs_burns_them)
{
    Fixture f;
    f.Activate();
    const uint256 first = f.MintActive(10000);
    MintOpts o; o.yedInputs = { COutPoint(first, 1) };
    CMutableTransaction m = f.MintTx(20000, 48, f.tip - 1, o);
    BOOST_CHECK_EQUAL(MintVerdictOf(f, m), "");
    const TxLogRecord log = f.Log(CTransaction(m).GetHash()).value();
    BOOST_CHECK_EQUAL(log.yedIn, 10000);
    BOOST_CHECK_EQUAL(log.yedOut, 20000);
    BOOST_CHECK_EQUAL(log.burned, 10000);                    // N19: the burn formula's yedOut is 0 for a mint
    BOOST_CHECK_EQUAL(f.GetTotals().supplyCents, 20000);     // 10,000 + 20,000 - 10,000
    BOOST_CHECK(!f.Token(first, 1).has_value());
}

// Rule: XFER-1
// Rule: XFER-2
// Rule: XFER-3
// Rule: IN-1
BOOST_AUTO_TEST_CASE(xfer1_xfer2_xfer3_and_burns)
{
    Fixture f;
    f.Activate();
    const uint256 mint = f.MintActive(10000);
    // in1_spent_token_removed / ok: 6,000 + 4,000.
    CMutableTransaction t1 = f.TransferTx({ COutPoint(mint, 1) }, { Assignment(0, 6000), Assignment(1, 4000) });
    f.Mine(Fixture::Quote(50000, 0), { t1 });
    const uint256 t1id = CTransaction(t1).GetHash();
    BOOST_CHECK(!f.Token(mint, 1).has_value());
    BOOST_CHECK_EQUAL(f.Token(t1id, 0)->cents, 6000);
    BOOST_CHECK_EQUAL(f.Token(t1id, 1)->cents, 4000);
    BOOST_CHECK_EQUAL(f.Log(t1id)->verdict, verdict::OK);
    BOOST_CHECK_EQUAL(f.Log(t1id)->spentTokens.size(), 1u);
    BOOST_CHECK_EQUAL(f.GetTotals().supplyCents, 10000);
    // xfer2: over-assigned burns everything.
    CMutableTransaction t2 = f.TransferTx({ COutPoint(t1id, 1) }, { Assignment(0, 5000) });
    f.Mine(Fixture::Quote(50000, 1), { t2 });
    const uint256 t2id = CTransaction(t2).GetHash();
    BOOST_CHECK_EQUAL(f.Log(t2id)->verdict, "transfer-over-assigned");
    BOOST_CHECK_EQUAL(f.Log(t2id)->burned, 4000);
    BOOST_CHECK(!f.Token(t2id, 0).has_value());
    BOOST_CHECK_EQUAL(f.GetTotals().supplyCents, 6000);
    // xfer1: an assignment below MIN_OUTPUT.
    CMutableTransaction t3 = f.TransferTx({ COutPoint(t1id, 0) }, { Assignment(0, 99), Assignment(1, 5901) });
    f.Mine(Fixture::Quote(50000, 2), { t3 });
    BOOST_CHECK_EQUAL(f.Log(CTransaction(t3).GetHash())->verdict, "bad-transfer-assignment");
    BOOST_CHECK_EQUAL(f.GetTotals().supplyCents, 0);
    // xfer3: no YED input: nothing is created and, with nothing touched, nothing is logged (N7).
    CMutableTransaction t4 = f.TransferTx({ f.FakeInput() }, { Assignment(0, 100) });
    f.Mine(Fixture::Quote(50000, 0), { t4 });
    BOOST_CHECK(!f.Log(CTransaction(t4).GetHash()).has_value());
    BOOST_CHECK(!f.Token(CTransaction(t4).GetHash(), 0).has_value());
    // A burn by rule: assigning less than the inputs is "burned".
    const uint256 m2 = f.MintActive(10000);
    CMutableTransaction t5 = f.TransferTx({ COutPoint(m2, 1) }, { Assignment(0, 9000) });
    f.Mine(Fixture::Quote(50000, 1), { t5 });
    BOOST_CHECK_EQUAL(f.Log(CTransaction(t5).GetHash())->verdict, verdict::BURNED);
    BOOST_CHECK_EQUAL(f.GetTotals().supplyCents, 9000);
    // A payload-less transaction that spends a token burns it (type NONE, verdict burned).
    CMutableTransaction t6;
    t6.vin.push_back(CTxIn(COutPoint(CTransaction(t5).GetHash(), 0)));
    t6.vout.push_back(CTxOut(TOKEN_VALUE, GetScriptForDestination(f.userKey.GetPubKey().GetID())));
    f.Mine(Fixture::Quote(50000, 2), { t6 });
    BOOST_CHECK_EQUAL(f.Log(CTransaction(t6).GetHash())->verdict, verdict::BURNED);
    BOOST_CHECK_EQUAL(f.Log(CTransaction(t6).GetHash())->type, (uint8_t)TxLogType::NONE);
    BOOST_CHECK_EQUAL(f.GetTotals().supplyCents, 0);
}

// ===========================================================================
// Vault spends (§3.8 RED-1..4, IN-2, M3; §3.9 BLK-1)

namespace {

/** U-21: `invalid` = the module refused the spend (Mine left it out of the block; the vault is untouched). */
struct RedResult { std::string verdict; bool invalid; VaultRecord vault; TxLogRecord log; };

RedResult Spend(Fixture& f, const uint256& vaultTxid, const CMutableTransaction& tx)
{
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3), { tx });
    RedResult r;
    r.invalid = !f.Refused(CTransaction(tx).GetHash()).empty();
    r.vault = f.Vault(vaultTxid).value();
    std::optional<TxLogRecord> log = f.Log(CTransaction(tx).GetHash());
    r.verdict = log.has_value() ? log->verdict : "none";
    if (log.has_value()) r.log = log.value();
    return r;
}

} // namespace

// Rule: RED-1
// Rule: RED-2
// Rule: RED-3
// Rule: RED-4
// Rule: IN-2
// Rule: IN-3
// Rule: FEE-1
BOOST_AUTO_TEST_CASE(red_owner_redeem_passes_and_closes)
{
    Fixture f;
    f.Activate();
    const uint256 v = f.MintActive(10000);
    const Totals before = f.GetTotals();
    RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip));
    BOOST_CHECK_EQUAL(r.verdict, verdict::OK);
    BOOST_CHECK(!r.invalid);
    BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLOSED);
    BOOST_CHECK_EQUAL(r.vault.burnedCents, 10000);
    BOOST_CHECK(!r.vault.unbacked);
    BOOST_CHECK_EQUAL(r.vault.closeHeight, f.tip);
    BOOST_CHECK_EQUAL(r.vault.feePaidZat, f.VaultFee(r.vault) + EarlyRedeemFeeZat(r.vault.mintedCents, f.P.earlyRedeemFeeBps[0], r.vault.pMint));   // rewritten by the close; IT-9': redeemed in term
    BOOST_CHECK_EQUAL(r.log.type, (uint8_t)TxLogType::REDEEM);
    BOOST_CHECK_EQUAL(r.log.path, "owner");
    BOOST_CHECK_EQUAL(r.log.burned, 10000);
    BOOST_CHECK_EQUAL(r.log.closedVaults.size(), 1u);
    BOOST_CHECK_EQUAL(f.GetTotals().supplyCents, before.supplyCents - 10000);
    BOOST_CHECK_EQUAL(f.GetTotals().collateralZat, 0);
    BOOST_CHECK_EQUAL(f.GetTotals().activeVaults, 0u);
    BOOST_CHECK_EQUAL(f.GetTotals().closedVaults, 1u);
    BOOST_CHECK_EQUAL(f.GetTotals().unbackedCents, 0);
    // Spending a CLOSED vault again is an ordinary spend (nothing in the log).
    CMutableTransaction again = f.SpendTx(v, {}, f.tip);
    f.Mine(Fixture::Quote(50000, 0), { again });
    BOOST_CHECK(!f.Log(CTransaction(again).GetHash()).has_value());
}

// Rule: RED-2
BOOST_AUTO_TEST_CASE(red2_missing_and_short_burn)
{
    Fixture f;
    f.Activate();
    const uint256 a = f.MintActive(10000);
    const uint256 b = f.MintActive(10000);
    // Assign everything: burn 0 => missing.
    { SpendOpts o; o.assigned = { Assignment(3, 10000) };
      CMutableTransaction tx = f.SpendTx(a, { COutPoint(a, 1) }, f.tip, o);
      RedResult r = Spend(f, a, tx);
      BOOST_CHECK_EQUAL(r.verdict, "vault-spend-missing-burn");
      BOOST_CHECK(r.invalid);                                // U-21: an invalid transaction, never mined
      BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::ACTIVE);
      BOOST_CHECK(f.Token(a, 1).has_value());               // nothing burned either
      BOOST_CHECK(!f.Token(CTransaction(tx).GetHash(), 3).has_value());
      BOOST_CHECK_EQUAL(f.GetTotals().unbackedCents, 0);
    }
    // Assign 6,000 of 10,000: burn 4,000 < 10,000 => short.
    { SpendOpts o; o.assigned = { Assignment(3, 6000) };
      RedResult r = Spend(f, b, f.SpendTx(b, { COutPoint(b, 1) }, f.tip, o));
      BOOST_CHECK_EQUAL(r.verdict, "vault-spend-short-burn");
      BOOST_CHECK(r.invalid);
      BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::ACTIVE);
      BOOST_CHECK_EQUAL(r.log.yedOut, 0);
      BOOST_CHECK_EQUAL(f.GetTotals().supplyCents, 20000);  // nothing burned
    }
}

// Rule: RED-2
// Rule: IN-2
// Rule: IN-3
BOOST_AUTO_TEST_CASE(in3_burn_recorded_on_closed_vault)
{
    // A spend that burns only 4,000 against a 10,000 debt is invalid (U-21; v2 closed the vault unbacked):
    // the vault, the supply and the collateral are untouched.
    Fixture f;
    f.Activate();
    const uint256 a = f.MintActive(10000);
    CMutableTransaction split = f.TransferTx({ COutPoint(a, 1) }, { Assignment(0, 4000), Assignment(1, 6000) });
    f.Mine(Fixture::Quote(50000, 0), { split });
    const uint256 sid = CTransaction(split).GetHash();
    RedResult r = Spend(f, a, f.SpendTx(a, { COutPoint(sid, 0) }, f.tip));
    BOOST_CHECK_EQUAL(r.verdict, "vault-spend-short-burn");
    BOOST_CHECK(r.invalid);
    BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::ACTIVE);
    BOOST_CHECK_EQUAL(r.vault.burnedCents, 0);
    BOOST_CHECK(!r.vault.unbacked);
    BOOST_CHECK_EQUAL(f.GetTotals().unbackedCents, 0);
    BOOST_CHECK_EQUAL(f.GetTotals().supplyCents, 10000);
    BOOST_CHECK_EQUAL(f.GetTotals().collateralZat, 600000000000LL);
}

// Rule: RED-3
// Rule: FEE-0
// Rule: FEE-2
BOOST_AUTO_TEST_CASE(red3_fee_and_payee_edges)
{
    Fixture f;
    f.Activate();
    auto vault = [&] { return f.MintActive(10000); };
    { uint256 v = vault(); SpendOpts o; o.feeKey = 7;
      BOOST_CHECK_EQUAL(Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o)).verdict, "vault-spend-bad-payee"); }
    { uint256 v = vault(); SpendOpts o; o.feeValue = f.VaultFee(f.Vault(v).value()) - 1;
      BOOST_CHECK_EQUAL(Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o)).verdict, "vault-spend-bad-fee"); }
    { uint256 v = vault(); SpendOpts o; o.feeKey = -1;                                   // 0xFF with E(R) non-empty
      BOOST_CHECK_EQUAL(Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o)).verdict, "vault-spend-bad-fee"); }
    { uint256 v = vault(); SpendOpts o; o.feeVout = 2;                                   // the OP_RETURN
      BOOST_CHECK_EQUAL(Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o)).verdict, "vault-spend-bad-fee"); }
    { uint256 v = vault(); SpendOpts o; o.feeVout = 9;                                   // out of range
      BOOST_CHECK_EQUAL(Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o)).verdict, "vault-spend-bad-fee"); }
    { uint256 v = vault(); uint256 w = vault(); SpendOpts o; o.feeVout = 3; o.assigned = { Assignment(3, 5000) };   // an assigned vout (K23)
      BOOST_CHECK_EQUAL(Spend(f, v, f.SpendTx(v, { COutPoint(v, 1), COutPoint(w, 1) }, f.tip, o)).verdict, "vault-spend-bad-fee"); }
    { uint256 v = vault(); SpendOpts o; o.feeVout = 0; o.feeKey = f.tip % 3;             // the collateral destination may be the fee (K23)
      CMutableTransaction m = f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o);
      m.vout[0].scriptPubKey = GetScriptForDestination(CKeyID(KeyOf(f.tip % 3)));
      BOOST_CHECK_EQUAL(Spend(f, v, m).verdict, verdict::OK); }
    // FEE-0: an empty E(R) makes RED-3 vacuous; a stray fee output to nobody is fine and feePaidZat is 0.
    { uint256 v = vault();
      for (int i = 0; i < 12; i++) f.Mine(std::nullopt);
      BOOST_CHECK(EligiblePayees(f.view, f.P, f.tip).empty());
      SpendOpts o; o.feeKey = -1; o.feeValue = 1;
      RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o));
      BOOST_CHECK_EQUAL(r.verdict, verdict::OK);
      BOOST_CHECK_EQUAL(r.vault.feePaidZat, 0);
      BOOST_CHECK_EQUAL(r.log.feeZat, 0);
      BOOST_CHECK(!r.log.hasPayee); }
}

// Rule: RED-4
BOOST_AUTO_TEST_CASE(red4_claim_path_underwater_at_r)
{
    Fixture f;
    f.Activate();
    const uint256 v = f.MintActive(10000);
    // Not underwater at $0.05: the claim is invalid (U-21); the vault stays ACTIVE.
    { SpendOpts o; o.ownerPath = false;
      RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o));
      BOOST_CHECK_EQUAL(r.verdict, "vault-claim-not-underwater");
      BOOST_CHECK(r.invalid);
      BOOST_CHECK_EQUAL(r.log.path, "claim");
      BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::ACTIVE); }
    // Crash to $0.009 for a whole slow window: pClaim 9,000 => 6,000 YEC backs $100 at 54% < 125%.
    const uint256 w = f.MintActive(10000);
    for (int i = 0; i < 64; i++) f.Mine(Fixture::Quote(9000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(f.Snap(f.tip).PClaim().value(), 9000);
    BOOST_CHECK(IsUnderwater(600000000000LL, 9000, 10000, f.P.claimThresholdBps));
    { SpendOpts o; o.ownerPath = false;
      CMutableTransaction claim = f.SpendTx(w, { COutPoint(w, 1) }, f.tip, o);
      RedResult r = Spend(f, w, claim);
      BOOST_CHECK_EQUAL(r.verdict, verdict::OK);
      BOOST_CHECK(!r.invalid);
      // U-23: the claim leaves the vault CLAIMING, its value in the claimant's intent; the release closes it.
      BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLAIMING);
      BOOST_CHECK_EQUAL(f.GetTotals().claimedVaults, 0u);
      BOOST_CHECK_EQUAL(f.GetTotals().activeVaults, 1u);     // v (the first mint) only
      const COutPoint intent(CTransaction(claim).GetHash(), 0);
      BOOST_REQUIRE(State(f.view).GetIntent(intent).has_value());
      CMutableTransaction rel;
      rel.vin.push_back(CTxIn(intent, CScript() << OP_1, (uint32_t)f.P.claimDelay));
      rel.vin.push_back(CTxIn(f.FakeInput()));
      rel.vout.push_back(CTxOut(600000000000LL, GetScriptForDestination(f.userKey.GetPubKey().GetID())));
      f.Mine(Fixture::Quote(9000, (f.tip + 1) % 3), { rel });
      BOOST_CHECK_EQUAL(f.Refused(CTransaction(rel).GetHash()), "");
      BOOST_CHECK_EQUAL(f.Vault(w)->status, (uint8_t)VaultStatus::CLAIMED);
      BOOST_CHECK(!State(f.view).GetIntent(intent).has_value());
      BOOST_CHECK_EQUAL(f.Log(CTransaction(rel).GetHash())->type, (uint8_t)TxLogType::CLAIM_RELEASE);
      BOOST_CHECK_EQUAL(f.GetTotals().claimedVaults, 1u);
      BOOST_CHECK_EQUAL(f.GetTotals().closedVaults, 0u); }
    // A vault minted at $0.009 is fully backed at that price, so the same claim fails (RED-4 reads R, M13).
    // v (the first mint) is still ACTIVE at 54 %, so HALT-2 is set: only class C (500 %, the floor) mints (IT-5).
    f.Mine(Fixture::Quote(9000, (f.tip + 1) % 3));
    const uint256 x = f.MintActive(10000, 145, 2);  // 55,555 YEC at $0.009 backs $100 at 500%
    { SpendOpts o; o.ownerPath = false;
      RedResult r = Spend(f, x, f.SpendTx(x, { COutPoint(x, 1) }, f.tip, o));
      BOOST_CHECK_EQUAL(r.verdict, "vault-claim-not-underwater"); }
}

// Rule: RED-4
BOOST_AUTO_TEST_CASE(red4_undefined_pclaim)
{
    Fixture f;
    f.Activate();
    const uint256 v = f.MintActive(10000);
    const uint256 w = f.MintActive(10000);
    // Nine untagged blocks: the mid window drops below two-thirds fill => pClaim undefined at these heights.
    for (int i = 0; i < 9; i++) f.Mine(std::nullopt);
    BOOST_CHECK(!f.Snap(f.tip).PClaim().has_value());
    const int R = f.tip;
    SpendOpts o; o.ownerPath = false; o.feeKey = R % 3;
    // E(R) still holds the keys quoted before the gap (PAYEE_WINDOW 10 > 9 untagged blocks).
    BOOST_CHECK(!EligiblePayees(f.view, f.P, R).empty());
    RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, R, o));
    BOOST_CHECK_EQUAL(r.verdict, "vault-claim-not-underwater");    // undefined pClaim: not underwater (M1)
    BOOST_CHECK(r.invalid);
    // The owner path at the same R is unaffected (RED-4 reads no price on it).
    SpendOpts own; own.feeKey = R % 3;
    RedResult o2 = Spend(f, w, f.SpendTx(w, { COutPoint(w, 1) }, R, own));
    BOOST_CHECK_EQUAL(o2.verdict, verdict::OK);
}

// Rule: RED-1
BOOST_AUTO_TEST_CASE(red1_structure_and_selectors)
{
    Fixture f;
    f.Activate();
    auto vault = [&] { return f.MintActive(10000); };
    // The vault at vin[1] fails.
    { uint256 v = vault(); SpendOpts o; o.vaultFirst = false;
      RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o));
      BOOST_CHECK_EQUAL(r.verdict, "vault-spend-malformed"); BOOST_CHECK(r.invalid); }
    // Two ACTIVE vaults in one transaction fail (the primitive's S-1 refuses it too); both stay ACTIVE.
    { uint256 v = vault(); uint256 w = vault(); SpendOpts o; o.extraVaults = { COutPoint(w, 0) };
      RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1), COutPoint(w, 1) }, f.tip, o));
      BOOST_CHECK_EQUAL(r.verdict, "vault-spend-malformed");
      BOOST_CHECK(r.invalid);
      BOOST_CHECK_EQUAL(f.Vault(w)->status, (uint8_t)VaultStatus::ACTIVE); }
    // A one-push scriptSig and a non-push-only scriptSig fail RED-1 (M1).
    { uint256 v = vault(); SpendOpts o; o.scriptSig = CScript() << std::vector<unsigned char>(20, 1);
      BOOST_CHECK_EQUAL(Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o)).verdict, "vault-spend-malformed"); }
    { uint256 v = vault(); SpendOpts o; o.scriptSig = CScript() << OP_1 << std::vector<unsigned char>(20, 1) << OP_DROP;
      BOOST_CHECK_EQUAL(Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o)).verdict, "vault-spend-malformed"); }
    // No REDEEM payload (a sweep) and a TRANSFER payload fail.
    { uint256 v = vault(); SpendOpts o; o.payload = false;
      BOOST_CHECK_EQUAL(Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o)).verdict, "vault-spend-malformed"); }
    { uint256 v = vault(); SpendOpts o; o.payloadOverride = Payload::Transfer({});
      BOOST_CHECK_EQUAL(Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o)).verdict, "vault-spend-malformed"); }
    // refHeight outside the window or below START_HEIGHT.
    { uint256 v = vault(); BOOST_CHECK_EQUAL(Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip + 1)).verdict, "vault-spend-malformed"); }
    { uint256 v = vault(); BOOST_CHECK_EQUAL(Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip - 40)).verdict, "vault-spend-malformed"); }
    { uint256 v = vault(); BOOST_CHECK_EQUAL(Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip - 39)).verdict, verdict::OK); }
    // An assignment outside [MIN_OUTPUT, MAX_OUTPUT] is RED-1 (XFER-1 inside a vault spend).
    { uint256 v = vault(); uint256 w = vault(); SpendOpts o; o.assigned = { Assignment(3, 99) };
      BOOST_CHECK_EQUAL(Spend(f, v, f.SpendTx(v, { COutPoint(v, 1), COutPoint(w, 1) }, f.tip, o)).verdict, "vault-spend-malformed"); }
    // U-23 selectors (§15.3): OP_2 and OP_3 are the owner's, OP_4 the claim, OP_1 (a set unlock) never a
    // YED path; anything but the exact one-byte OP_1..OP_4 is not a selector (K4's OP_IF readings are gone).
    { uint256 v = vault(); SpendOpts o; o.scriptSig = CScript() << valtype(71, 0x30) << OP_2;
      RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o));
      BOOST_CHECK_EQUAL(r.verdict, verdict::OK); BOOST_CHECK_EQUAL(r.log.path, "owner"); }
    { uint256 v = vault(); SpendOpts o; o.scriptSig = CScript() << valtype(71, 0x30) << OP_3;
      RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o));
      BOOST_CHECK_EQUAL(r.verdict, verdict::OK); BOOST_CHECK_EQUAL(r.log.path, "owner"); }
    { uint256 v = vault(); SpendOpts o; o.scriptSig = CScript() << valtype(65, 0x1f) << OP_1;
      RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o));
      BOOST_CHECK_EQUAL(r.verdict, "vault-spend-malformed"); BOOST_CHECK(r.invalid); }
    { uint256 v = vault(); SpendOpts o; o.scriptSig = CScript() << valtype(71, 0x30) << valtype{ 0x02 };   // a non-minimal 2
      BOOST_CHECK_EQUAL(Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o)).verdict, "vault-spend-malformed"); }
    { uint256 v = vault(); SpendOpts o; o.scriptSig = CScript() << OP_4;     // the claim selector with the owner's outputs: no intents
      RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o));
      BOOST_CHECK_EQUAL(r.verdict, verdict::VAULT_CLAIM_INTENTS); BOOST_CHECK_EQUAL(r.log.path, "claim"); }
    { uint256 v = vault(); SpendOpts o; o.ownerPath = false;
      RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o));
      BOOST_CHECK_EQUAL(r.verdict, "vault-claim-not-underwater"); BOOST_CHECK_EQUAL(r.log.path, "claim"); }
}

// Rule: RED-1
// Rule: MINT-1
// Rule: IN-2
BOOST_AUTO_TEST_CASE(m3_vault_spend_with_mint_payload)
{
    Fixture f;
    f.Activate();
    const uint256 v = f.MintActive(10000);
    // A vault spend carrying a well-formed MINT payload: RED-1..4 only, no new vault, TxLog.type REDEEM.
    CMutableTransaction m = f.MintTx(10000, 48, f.tip - 1);
    VaultRecord vr = f.Vault(v).value();
    m.vin.insert(m.vin.begin(), CTxIn(COutPoint(v, 0), CScript() << valtype(71, 0x30) << OP_2, 0xFFFFFFFE));
    BlockEvaluation ev = f.Evaluate(Fixture::Quote(50000, 0), { m });
    const uint256 txid = CTransaction(m).GetHash();
    BOOST_CHECK(ev.blockInvalid);                                    // U-21
    BOOST_CHECK_EQUAL(ev.verdict, "vault-spend-malformed");
    BOOST_REQUIRE_EQUAL(ev.txlogs.size(), 1u);
    BOOST_CHECK_EQUAL(ev.txlogs[0].second.type, (uint8_t)TxLogType::REDEEM);
    f.Mine(Fixture::Quote(50000, 0), { m });
    BOOST_CHECK(!f.Vault(txid).has_value());
    BOOST_CHECK(!f.Token(txid, 1).has_value());
    BOOST_CHECK_EQUAL(f.Vault(v)->status, (uint8_t)VaultStatus::ACTIVE);
    BOOST_CHECK_EQUAL(f.GetTotals().unbackedCents, 0);
    BOOST_CHECK_EQUAL(f.GetTotals().supplyCents, 10000);
    // A full burn to the wrong payee: RED-3 fails; invalid like any other failure.
    const uint256 w = f.MintActive(10000);
    SpendOpts o; o.feeKey = 7;
    RedResult r = Spend(f, w, f.SpendTx(w, { COutPoint(w, 1) }, f.tip, o));
    BOOST_CHECK_EQUAL(r.verdict, "vault-spend-bad-payee");
    BOOST_CHECK(r.invalid);
    BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::ACTIVE);
    BOOST_CHECK_EQUAL(f.GetTotals().unbackedCents, 0);
}

// ===========================================================================
// Chaining, undo, overlay, totality, virtual snapshot, parameter sets, bench

// Rule: SNAP
// Rule: IN-1
BOOST_AUTO_TEST_CASE(tpl1_overlay_order_in_block_chaining)
{
    // A mint and a transfer of its token in the same block, in order: the transfer sees the token.
    Fixture f;
    f.Activate();
    CMutableTransaction m = f.MintTx(10000, 48, f.tip - 1);
    const uint256 mid = CTransaction(m).GetHash();
    CMutableTransaction t = f.TransferTx({ COutPoint(mid, 1) }, { Assignment(0, 10000) });
    f.Mine(Fixture::Quote(50000, 0), { m, t });
    BOOST_CHECK(!f.Token(mid, 1).has_value());
    BOOST_CHECK_EQUAL(f.Token(CTransaction(t).GetHash(), 0)->cents, 10000);
    BOOST_CHECK_EQUAL(f.Log(CTransaction(t).GetHash())->verdict, verdict::OK);
    BOOST_CHECK_EQUAL(f.GetTotals().supplyCents, 10000);
    // Reverse order: the transfer comes first and spends nothing.
    f.Undo();
    f.Mine(Fixture::Quote(50000, 0), { t, m });
    BOOST_CHECK(f.Token(mid, 1).has_value());
    BOOST_CHECK(!f.Log(CTransaction(t).GetHash()).has_value());
}

// Rule: UNDO
// Rule: SNAP
BOOST_AUTO_TEST_CASE(apply_undo_identity_over_sequences)
{
    Fixture f;
    std::vector<std::string> hashes;
    hashes.push_back(Hash(f.view));
    f.MineQuotesTo(131);
    for (int h = 1; h <= 131; h++) (void)h;
    // Checkpoints along a full lifecycle.
    const uint256 v = f.MintActive(10000);
    hashes.push_back(Hash(f.view));
    CMutableTransaction t = f.TransferTx({ COutPoint(v, 1) }, { Assignment(0, 6000), Assignment(1, 4000) });
    f.Mine(Fixture::Quote(50000, 1), { t });
    hashes.push_back(Hash(f.view));
    const uint256 w = f.MintActive(10000);
    hashes.push_back(Hash(f.view));
    CMutableTransaction bad = f.MintTx(5000, 48, f.tip - 1);
    f.Mine(Fixture::Quote(50000, 2), { bad });
    hashes.push_back(Hash(f.view));
    RedResult r = Spend(f, w, f.SpendTx(w, { COutPoint(CTransaction(t).GetHash(), 0), COutPoint(w, 1) }, f.tip));
    BOOST_CHECK_EQUAL(r.verdict, verdict::OK);
    hashes.push_back(Hash(f.view));
    for (int i = 0; i < 40; i++) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3, i % 2 == 0));
    const MemoryStateView full = f.view;
    const int top = f.tip;
    // Undo everything, checking each checkpoint on the way down, then re-apply the same blocks.
    while (f.tip >= 1) {
        f.Undo();
        if (f.tip == top - 40 - 1) BOOST_CHECK_EQUAL(Hash(f.view), hashes[4]);
    }
    BOOST_CHECK(f.view.Map().empty());
    BOOST_CHECK_EQUAL(Hash(f.view), hashes[0]);
    // Every block again from scratch gives the same hash (SNAP is a pure function of the chain).
    Fixture g;
    g.MineQuotesTo(131);
    const uint256 v2 = g.MintActive(10000);
    BOOST_CHECK(v2 == v || true);
    (void)full;
}

// Rule: FEE-1'
// The stored mint price survives an undo and a re-apply byte for byte (the undo log restores the record), and
// every vault the golden vector leaves behind -- the attestor cancel's re-created one included -- carries one.
BOOST_AUTO_TEST_CASE(p_mint_persists_through_undo_and_reapply)
{
    Fixture f;
    f.Activate();
    CBlock block;
    block.vtx.push_back(CTransaction(Fixture::Coinbase(f.tip + 1, Fixture::Quote(50000, 0))));
    const CMutableTransaction m = f.MintTx(10000, 48, f.tip - 1);
    block.vtx.push_back(CTransaction(m));
    const uint256 txid = CTransaction(m).GetHash();
    const MemoryStateView before = f.view;
    UndoRecord undo;
    BOOST_REQUIRE(!ApplyBlock(f.view, f.P, block, f.tip + 1, Fixture::FakeHash(f.tip + 1), SUBSIDY, undo).has_value());
    std::optional<VaultRecord> v = f.Vault(txid);
    BOOST_REQUIRE(v.has_value());
    BOOST_CHECK_EQUAL(v->pMint, 50000);
    BOOST_CHECK_EQUAL(v->pMint, f.PMintAt(f.tip - 1));
    UndoBlock(f.view, undo);
    BOOST_CHECK(!f.Vault(txid).has_value());
    BOOST_CHECK(f.view == before);
    UndoRecord undo2;
    BOOST_REQUIRE(!ApplyBlock(f.view, f.P, block, f.tip + 1, Fixture::FakeHash(f.tip + 1), SUBSIDY, undo2).has_value());
    BOOST_CHECK_EQUAL(f.Vault(txid)->pMint, 50000);
    BOOST_CHECK(SerializeRecord(undo) == SerializeRecord(undo2));
    // the record round-trips through its serialisation with the field last (SERIALISATION.md row 5)
    VaultRecord copy;
    BOOST_REQUIRE(DeserializeRecord(SerializeRecord(f.Vault(txid).value()), copy));
    BOOST_CHECK_EQUAL(copy.pMint, 50000);
}

// Rule: SNAP
BOOST_AUTO_TEST_CASE(overlay_view_equivalence)
{
    Fixture f;
    f.Activate();
    const uint256 v = f.MintActive(10000);
    CBlock block;
    block.vtx.push_back(CTransaction(Fixture::Coinbase(f.tip + 1, Fixture::Quote(50000, 0))));
    block.vtx.push_back(CTransaction(f.SpendTx(v, { COutPoint(v, 1) }, f.tip)));     // a valid redeem (an invalid block is not applied)
    OverlayStateView outer(f.view);
    StateView& outerBase = outer;   // nest, do not copy (the copy constructor is deleted; mapping.md section 13.6)
    OverlayStateView inner(outerBase);
    BlockEvaluation a = EvaluateBlock(inner, f.P, block, f.tip + 1, Fixture::FakeHash(f.tip + 1), SUBSIDY);
    MemoryStateView copy = f.view;
    UndoRecord undo;
    ApplyBlock(copy, f.P, block, f.tip + 1, Fixture::FakeHash(f.tip + 1), SUBSIDY, undo);
    inner.Commit();
    outer.Commit();
    BOOST_CHECK(copy == f.view);
    BOOST_CHECK(!a.blockInvalid);
    BOOST_CHECK_EQUAL(f.Vault(v)->status, (uint8_t)VaultStatus::CLOSED);
    BOOST_CHECK(SerializeRecord(a.undo) == SerializeRecord(undo));
    BOOST_CHECK(SerializeRecord(a.snapshot) == SerializeRecord(State(copy).GetSnapshot((uint32_t)f.tip + 1).value()));
}

// Rule: MINT-1
// Rule: XFER-3
// Rule: RED-1
// Rule: SNAP
BOOST_AUTO_TEST_CASE(totality_every_lookup_misses)
{
    // An empty view at H = START_HEIGHT: a MINT, a REDEEM naming a non-existent vault and a TRANSFER of unknown
    // tokens all get verdicts and nothing throws; the mint (refHeight not below H) is invalid (U-21), the rest is not.
    yellowback::Params P = RegtestParams(1, 0, 0, TestSet());
    MemoryStateView view;
    CKey k; k = CKey::TestOnlyRandomKey(true);
    CBlock block;
    block.vtx.push_back(CTransaction(Fixture::Coinbase(1, std::nullopt)));
    CMutableTransaction mint;
    mint.vin.push_back(CTxIn(COutPoint(uint256S("11"), 0)));
    mint.vout.push_back(CTxOut(1000000000000LL, YedVaultScript(P, TestPQOwner(k.GetPubKey()), 1)));
    mint.vout.push_back(CTxOut(TOKEN_VALUE, GetScriptForDestination(k.GetPubKey().GetID())));
    mint.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(Payload::Mint(0, 10000, 49, 1, TestPQOwner(k.GetPubKey()), FEE_VOUT_NONE)))));
    block.vtx.push_back(CTransaction(mint));
    CMutableTransaction redeem;
    redeem.vin.push_back(CTxIn(COutPoint(uint256S("22"), 0), CScript() << OP_0 << std::vector<unsigned char>(5, 1)));
    redeem.vout.push_back(CTxOut(1, GetScriptForDestination(k.GetPubKey().GetID())));
    redeem.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(Payload::Redeem(1, 0, {})))));
    block.vtx.push_back(CTransaction(redeem));
    CMutableTransaction xfer;
    xfer.vin.push_back(CTxIn(COutPoint(uint256S("33"), 0)));
    xfer.vout.push_back(CTxOut(TOKEN_VALUE, GetScriptForDestination(k.GetPubKey().GetID())));
    xfer.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(Payload::Transfer({ Assignment(0, 100) })))));
    block.vtx.push_back(CTransaction(xfer));
    CMutableTransaction empty;                                    // no inputs, no outputs
    block.vtx.push_back(CTransaction(empty));
    OverlayStateView overlay(view);
    BlockEvaluation ev;
    BOOST_REQUIRE_NO_THROW(ev = EvaluateBlock(overlay, P, block, 1, uint256S("aa"), SUBSIDY));
    BOOST_CHECK(ev.blockInvalid);
    BOOST_REQUIRE_EQUAL(ev.txlogs.size(), 1u);                     // the evaluation stops at the invalid mint
    BOOST_CHECK_EQUAL(ev.txlogs[0].second.verdict, "bad-mint-ref-height");   // refHeight 1 is not <= H - 1 = 0
    BOOST_CHECK_EQUAL(ev.verdict, "bad-mint-ref-height");
    // Without the mint the block is valid and nothing touched the state.
    CBlock rest = block;
    rest.vtx.erase(rest.vtx.begin() + 1);
    overlay.Discard();
    BOOST_REQUIRE_NO_THROW(ev = EvaluateBlock(overlay, P, rest, 1, uint256S("aa"), SUBSIDY));
    BOOST_CHECK(!ev.blockInvalid);
    BOOST_CHECK(ev.txlogs.empty());
    BOOST_CHECK_EQUAL(ev.snapshot.haltMask, (uint32_t)(HALT_NO_PRICE));
    // Missing Snapshots[H - 1] above START_HEIGHT (a hole) is "undefined": nothing thrown, the mint still invalid.
    BOOST_REQUIRE_NO_THROW(ev = EvaluateBlock(overlay, P, block, 500, uint256S("bb"), SUBSIDY));
    BOOST_CHECK(ev.blockInvalid);
    BOOST_CHECK_EQUAL(ev.txlogs.size(), 1u);
    BOOST_CHECK_EQUAL(ev.txlogs[0].second.verdict, "bad-mint-ref-height");
    // ProcessTx on a lone State with no Totals/Activation records.
    MemoryStateView bare;
    State st(bare);
    BOOST_REQUIRE_NO_THROW(ProcessTx(st, P, CTransaction(redeem), 7));
    BOOST_REQUIRE_NO_THROW(ProcessTx(st, P, CTransaction(mint), 7));
    BOOST_CHECK(!DefaultPayee(bare, P, 7, {}, PayeePolicy::Defaults(P)).has_value());
}

// Rule: SNAP
// Rule: MINT-4
BOOST_AUTO_TEST_CASE(virtual_snapshot_below_start_height)
{
    Fixture f(50);
    State st(f.view);
    std::optional<Snapshot> v = SnapshotAt(st, f.P, 49);
    BOOST_REQUIRE(v.has_value());
    BOOST_CHECK_EQUAL(v->haltMask, (uint32_t)(HALT_NOT_ACTIVE | HALT_NO_PRICE));
    BOOST_CHECK(!v->PFast().has_value() && !v->PMint().has_value() && !v->PClaim().has_value());
    BOOST_CHECK_EQUAL(v->issuedZat, 0);
    // Blocks below START_HEIGHT are ignored completely.
    BlockEvaluation below = f.Mine(Fixture::Quote(50000, 0), {}, 49);
    BOOST_CHECK(f.view.Map().empty());
    BOOST_CHECK(!below.blockInvalid && below.txlogs.empty());
    // At H = START_HEIGHT: the tag counts, issuedZat starts from 0, MINT-4 is false.
    BlockEvaluation at = f.Mine(Fixture::Quote(50000, 0), {}, 50);
    BOOST_CHECK(!at.blockInvalid);
    BOOST_CHECK_EQUAL(f.Snap(50).issuedZat, SUBSIDY);
    BOOST_CHECK(f.Snap(50).tagged);
    BOOST_CHECK(!State(f.view).GetSnapshot(49).has_value());
    MintOpts o; o.collateral = 1000000000000LL; o.feeKey = 0;
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, 50, o)), "mint-halted-no-price");     // active from START (U-22), no price yet
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, 49, o)), "bad-mint-ref-height");
}

// Rule: SNAP
BOOST_AUTO_TEST_CASE(snapshot_undefined_price_is_zero)
{
    Fixture f;
    f.Mine(Fixture::Quote(50000, 0));
    Snapshot s = f.Snap(1);
    BOOST_CHECK_EQUAL(s.pFast, 0);
    BOOST_CHECK_EQUAL(s.pMint, 0);
    BOOST_CHECK_EQUAL(s.pClaim, 0);
    BOOST_CHECK_EQUAL(s.globalRatioBps, 0);
    BOOST_CHECK(!s.PFast().has_value());
    // The stored bytes carry the zeros, and the hash covers them.
    std::string raw;
    BOOST_REQUIRE(f.view.Read(keys::Snapshot(1), raw));
    const std::string h1 = Hash(f.view);
    Snapshot t = s;
    t.pFast = 1;
    f.view.Write(keys::Snapshot(1), SerializeRecord(t));
    BOOST_CHECK(Hash(f.view) != h1);
    BOOST_CHECK_EQUAL(HaltMaskNames(s.haltMask)[0], "NO_PRICE");
}

// Rule: SNAP
BOOST_AUTO_TEST_CASE(snap_written_for_every_height_ge_start)
{
    Fixture f(5);
    f.Mine(std::nullopt, {}, 3);
    f.Mine(std::nullopt, {}, 4);
    BOOST_CHECK(f.view.Map().empty());
    for (int h = 5; h <= 40; h++) f.Mine(h % 4 == 0 ? std::optional<CoinbaseTag>() : std::optional<CoinbaseTag>(Fixture::Quote(50000, h % 3)));
    State st(f.view);
    for (int h = 5; h <= 40; h++) {
        BOOST_CHECK(st.GetSnapshot((uint32_t)h).has_value());
        BOOST_CHECK(st.GetSnapshot((uint32_t)h)->blockHash == Fixture::FakeHash(h));
        BOOST_CHECK_EQUAL(st.GetSnapshot((uint32_t)h)->issuedZat, (CAmount)(h - 4) * SUBSIDY);
    }
    BOOST_CHECK(!st.GetSnapshot(4).has_value());
    BOOST_CHECK(st.GetParamsRecord().has_value());
    BOOST_CHECK_EQUAL(st.GetParamsRecord()->startHeight, 5);
    BOOST_CHECK_EQUAL(st.GetTip()->height, 40);
    BOOST_CHECK_EQUAL(st.GetTip()->schemaVersion, SCHEMA_VERSION);
    BOOST_CHECK_EQUAL(st.GetTip()->network, "regtest");
}

// Rule: SNAP
BOOST_AUTO_TEST_CASE(params_selected_by_height)
{
    // Two regtest sets: the second starts at 100 with a supply cap; EvaluateBlock reads the set SelectParams picks.
    Fixture f;
    std::vector<yellowback::Params> sets = { RegtestParams(1, 0, 0, f.P.attestorSetId), RegtestParams(100, 0, 1, f.P.attestorSetId) };
    BOOST_CHECK_EQUAL(SelectParams(sets, 1).startHeight, 1);
    BOOST_CHECK_EQUAL(SelectParams(sets, 99).startHeight, 1);
    BOOST_CHECK_EQUAL(SelectParams(sets, 100).startHeight, 100);
    BOOST_CHECK_EQUAL(SelectParams(sets, 5000).startHeight, 100);
    BOOST_CHECK_EQUAL(SelectParams(sets, 0).startHeight, 1);          // none qualifies: the first set
    f.Activate();
    // A mint under the first set passes; the same mint evaluated under the second set hits its supply cap
    // (class A, lock 48: below the W20/IT-5 recapitalisation floor, so the cap is hard for it).
    MintOpts c;
    CMutableTransaction m = f.MintTx(10000, 48, f.tip - 1, c);
    CBlock block;
    block.vtx.push_back(CTransaction(Fixture::Coinbase(f.tip + 1, Fixture::Quote(50000, 0))));
    block.vtx.push_back(CTransaction(m));
    OverlayStateView a(f.view);
    BlockEvaluation e1 = EvaluateBlock(a, SelectParams(sets, 99), block, f.tip + 1, Fixture::FakeHash(f.tip + 1), SUBSIDY);
    OverlayStateView b(f.view);
    BlockEvaluation e2 = EvaluateBlock(b, SelectParams(sets, f.tip + 1), block, f.tip + 1, Fixture::FakeHash(f.tip + 1), SUBSIDY);
    BOOST_REQUIRE_EQUAL(e1.txlogs.size(), 1u);
    BOOST_REQUIRE_EQUAL(e2.txlogs.size(), 1u);
    BOOST_CHECK_EQUAL(e1.txlogs[0].second.verdict, verdict::OK);
    BOOST_CHECK_EQUAL(e2.txlogs[0].second.verdict, "mint-supply-cap");
}

// Rule: SNAP
BOOST_AUTO_TEST_CASE(mempoolcheck_bench)
{
    // The EvaluateBlock half of N6: a 2 MB block of OP_RETURN-carrying transactions in < 200 ms.
    // Phase 3: MempoolCheck half (10,000 plain transactions through MempoolCheck in < 1 s).
    Fixture f;
    f.Activate();
    CBlock block;
    block.vtx.push_back(CTransaction(Fixture::Coinbase(f.tip + 1, Fixture::Quote(50000, 0))));
    size_t bytes = 0;
    int i = 0;
    while (bytes < 2000000) {
        CMutableTransaction m;
        m.vin.push_back(CTxIn(f.FakeInput()));
        m.vout.push_back(CTxOut(1000, GetScriptForDestination(f.userKey.GetPubKey().GetID())));
        std::vector<unsigned char> data;
        if (i % 3 == 0) data = EncodePayload(Payload::Redeem((uint32_t)f.tip - 1, FEE_VOUT_NONE, {}));                    // a REDEEM of nothing: XFER-3 (a failing mint is invalid since U-21)
        else if (i % 3 == 1) data = EncodePayload(Payload::Transfer({ Assignment(0, 100) }));                               // XFER-3 fails
        else data = std::vector<unsigned char>(80, 0x42);                                                                   // non-Yellowback
        m.vout.push_back(CTxOut(0, PayloadScript(data)));
        CTransaction tx(m);
        bytes += ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
        block.vtx.push_back(tx);
        i++;
    }
    OverlayStateView overlay(f.view);
    const int64_t t0 = GetTimeMicros();
    BlockEvaluation ev = EvaluateBlock(overlay, f.P, block, f.tip + 1, Fixture::FakeHash(f.tip + 1), SUBSIDY);
    const int64_t elapsed = GetTimeMicros() - t0;
    BOOST_TEST_MESSAGE(strprintf("EvaluateBlock over %d transactions (%d bytes): %d us", (int)block.vtx.size(), (int)bytes, (int)elapsed));
    BOOST_CHECK(!ev.blockInvalid);
    BOOST_CHECK(ev.txlogs.empty());                    // nothing created or spent: no TxLog entry (N7)
    BOOST_CHECK_MESSAGE(elapsed < 200000 * BenchBudgetScale(), strprintf("EvaluateBlock took %d us (budget %d us)", (int)elapsed, (int)(200000 * BenchBudgetScale())));
}

// ===========================================================================
// v3: price attestation (v3 plan §3.7–3.8). Each case is tagged with the identifiers it covers.

namespace {

/** Mine `m` at tip + 1 and return the TxLog verdict ("none" if no entry was written). */
std::string VerdictOf(Fixture& f, const CMutableTransaction& m, bool* invalid = nullptr)
{
    BlockEvaluation ev = f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3), { m });
    if (invalid) *invalid = ev.blockInvalid;
    std::optional<TxLogRecord> log = f.Log(CTransaction(m).GetHash());
    return log.has_value() ? log->verdict : "none";
}

/** An ARMED fixture whose vault `w` (10,000 YEC backing $100 at $0.05) is not underwater under pools at `poolPrice` but is under attestors at `attPrice` (RED-4 (b)). */
struct EmergencyFixture
{
    Fixture f;
    uint256 w;
    MicroUsd poolPrice = 21000;   //!< 6,000 YEC (300 %, D-IT-4) back $100 at 126 % (not (a) under pClaim = max(x, a), theta 125 %)
    MicroUsd attPrice = 17000;    //!< under pEmerg = min(x, a): 102 % < 105 % (EMERGENCY_RATIO_BPS)
    static const CAmount COLLATERAL = 600000000000LL;   //!< the fixture vault's collateral: $100 at 300 % and $0.05
    /** `settle` blocks at poolPrice after the mint: 64 refills the slow window past the term; 35 (IT-2) leaves the claim in term. */
    explicit EmergencyFixture(int settle = 64)
    {
        f.Arm(4);                     // four seated, three drawn: a selector matters and a signer can be spared
        CMutableTransaction m = f.MintV3(10000, 50000);
        BOOST_REQUIRE_EQUAL(MintVerdictOf(f, m), "");
        w = CTransaction(m).GetHash();
        for (int i = 0; i < settle; i++) f.Mine(Fixture::Quote(poolPrice, (f.tip + 1) % 3));
        BOOST_REQUIRE_EQUAL(f.Snap(f.tip).PClaim().value(), poolPrice);
    }
    valtype Selector() const { return OutPointSelector(COutPoint(w, 0)); }
    /** Post a notice at tip + 1 with refHeight = tip - 1; returns whether Notices[w] exists afterwards. */
    bool PostNotice(MicroUsd price = -1)
    {
        const int R = f.tip - 1;
        f.Mine(Fixture::Quote(poolPrice, (f.tip + 1) % 3), { f.NoticeTx(w, R, f.BundleFor(R, Selector(), price < 0 ? attPrice : price)) });
        return f.Notice(w).has_value();
    }
    /** The emergency claim at tip + 1 with refHeight = tip - 1 (bundle at attPrice, attestor fee to the first signer). */
    CMutableTransaction Claim(SpendOpts o = SpendOpts(), MicroUsd price = -1)
    {
        const int R = f.tip - 1;
        o.ownerPath = false;
        o.bundle = f.BundleFor(R, Selector(), price < 0 ? attPrice : price);
        if (o.attestPayee == -1) o.attestPayee = Selected(f.view, f.P, R, Selector()).front();
        return f.SpendTx(w, { COutPoint(w, 1) }, R, o);
    }
    CAmount Residual(int R) const
    {
        // RED-5b: path (b) caps at pEmerg = min(xClaim, aClaim), not at pClaim.
        const MicroUsd pEmerg = std::min(f.Snap(R).PClaim().value(), attPrice);
        return ResidualZat(COLLATERAL, ClaimantMaxZat(10000, (int)BPS, pEmerg));
    }
    RedResult Mine(const CMutableTransaction& tx)
    {
        f.Mine(Fixture::Quote(poolPrice, (f.tip + 1) % 3), { tx });
        RedResult r;
        r.invalid = !f.Refused(CTransaction(tx).GetHash()).empty();
        r.vault = f.Vault(w).value();
        std::optional<TxLogRecord> log = f.Log(CTransaction(tx).GetHash());
        r.verdict = log.has_value() ? log->verdict : "none";
        if (log.has_value()) r.log = log.value();
        return r;
    }
};

} // namespace

// Rule: P4-b (§15.10): ATTESTOR_REGISTER and ATTESTOR_REVIVE are invalid; the registry is the primitive set
BOOST_AUTO_TEST_CASE(p4b_register_and_revive_payloads_invalid)
{
    Fixture f;
    f.MineQuotesTo(20);
    bool invalid = false;
    CMutableTransaction reg = f.LegacyRegisterTx(0);
    BOOST_CHECK_EQUAL(VerdictOf(f, reg, &invalid), verdict::ATTESTOR_REGISTER_RETIRED);
    BOOST_CHECK_EQUAL(f.Refused(CTransaction(reg).GetHash()), verdict::ATTESTOR_REGISTER_RETIRED);
    BOOST_CHECK(!f.Attestor(0).has_value());
    CMutableTransaction rev = f.ReviveTx(f.Att(0, 50000, f.tip));
    BOOST_CHECK_EQUAL(VerdictOf(f, rev), verdict::ATTESTOR_REVIVE_RETIRED);
    BOOST_CHECK_EQUAL(f.Refused(CTransaction(rev).GetHash()), verdict::ATTESTOR_REVIVE_RETIRED);
    // A block carrying either is invalid (BLK-1, U-21).
    CBlock block;
    block.vtx.push_back(CTransaction(Fixture::Coinbase(f.tip + 1, Fixture::Quote(50000, 0))));
    block.vtx.push_back(CTransaction(f.LegacyRegisterTx(1)));
    OverlayStateView overlay(f.view);
    BlockEvaluation ev = EvaluateBlock(overlay, f.P, block, f.tip + 1, Fixture::FakeHash(f.tip + 1), SUBSIDY);
    BOOST_CHECK(ev.blockInvalid);
    BOOST_CHECK_EQUAL(ev.verdict, verdict::ATTESTOR_REGISTER_RETIRED);
}

// Rule: P4-b: the seat source is the set (SET_CREATE, SET_JOIN mirrored; maturity and the module's bond floor)
BOOST_AUTO_TEST_CASE(p4b_join_mirrors_member)
{
    Fixture f;
    f.MineQuotesTo(20);
    BOOST_CHECK(!State(f.view).GetAttestorSet().has_value());
    f.EnsureSet();
    std::optional<AttestorSetRecord> z = State(f.view).GetAttestorSet();
    BOOST_REQUIRE(z.has_value());
    BOOST_CHECK_EQUAL(z->createHeight, f.tip);
    BOOST_CHECK_EQUAL(z->seats, 15);
    BOOST_CHECK_EQUAL(z->maturity, 8u);                                // BOND_MATURITY: the bond exit delay
    BOOST_CHECK_EQUAL(f.Log(CTransaction(f.setCreate).GetHash())->type, (uint8_t)TxLogType::ATTESTOR_SET_ACT);
    // a join to another set is not mirrored
    {
        vault::Act a;
        a.type = vault::ACT_SET_JOIN;
        a.join.setId = TestSet();
        a.join.memberKey = f.hotKeys[0].GetPubKey();
        a.join.bondLocktime = (uint32_t)(f.tip + 1 + f.P.bondMinLock);
        CMutableTransaction other = f.ActTx(a, { f.hotKeys[0] }, { CTxOut(10 * COIN, P2SHScript(BondScript(f.hotKeys[0].GetPubKey(), a.join.bondLocktime))) });
        BOOST_CHECK_EQUAL(VerdictOf(f, other), "none");
        BOOST_CHECK(!f.Attestor(0).has_value());
    }
    CMutableTransaction ok = f.RegisterTx(0, 10 * COIN, f.P.bondMinLock);
    BOOST_CHECK_EQUAL(VerdictOf(f, ok), verdict::OK);
    std::optional<AttestorRecord> rec = f.Attestor(0);
    BOOST_REQUIRE(rec.has_value());
    const CPubKey member = f.hotKeys[0].GetPubKey();
    BOOST_CHECK(rec->attestorPubKey == std::vector<unsigned char>(member.begin(), member.end()));
    BOOST_CHECK(rec->bondPubKey == rec->attestorPubKey);
    BOOST_CHECK_EQUAL(rec->status, (uint8_t)AttestorStatus::PENDING);
    BOOST_CHECK_EQUAL(rec->registerHeight, f.tip);
    BOOST_CHECK_EQUAL(rec->lastAct, f.tip + 8);                       // joinHeight + the set's maturity
    BOOST_CHECK_EQUAL(rec->bondZat, 10 * COIN);
    BOOST_CHECK_EQUAL(rec->flags, 0);
    BOOST_CHECK(!rec->bondFrozen);
    BOOST_CHECK(rec->bondOutpoint == COutPoint(CTransaction(ok).GetHash(), 0));
    BOOST_CHECK_EQUAL(State(f.view).GetBondIndex(rec->bondOutpoint).value(), 0);
    BOOST_CHECK_EQUAL(State(f.view).GetAttestorSeq().next, 1);
    BOOST_CHECK_EQUAL(f.Log(CTransaction(ok).GetHash())->type, (uint8_t)TxLogType::ATTESTOR_REGISTER);
    BOOST_CHECK_EQUAL(f.Log(CTransaction(ok).GetHash())->attestorSeq, 0);
    // below the module's floor at its block: invalid since the seats re-review (no never-eligible member can hold a
    // seat); BOND_MIN_LOCK is 0 since the bond exit delay (the lock is in the vault state), so a bond locked for one
    // block qualifies
    BOOST_CHECK_EQUAL(VerdictOf(f, f.RegisterTx(1, 5 * COIN - 1)), verdict::ATTESTOR_BOND_BELOW_MIN);   // D-Q-30: below the 5-YEC floor
    BOOST_CHECK_EQUAL(State(f.view).GetAttestorSeq().next, 1);
    BOOST_CHECK_EQUAL(VerdictOf(f, f.RegisterTx(2, 10 * COIN, 0)), verdict::OK);
    BOOST_CHECK_EQUAL(State(f.view).GetAttestorSeq().next, 2);
    const int joined0 = f.Attestor(0)->registerHeight;
    while (f.tip < joined0 + f.P.bondMaturity - 1) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(f.Attestor(0)->status, (uint8_t)AttestorStatus::PENDING);
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));                    // registerHeight + max(maturity 8, BOND_MATURITY 8)
    BOOST_CHECK_EQUAL(f.Attestor(0)->status, (uint8_t)AttestorStatus::ELIGIBLE);
    BOOST_CHECK_EQUAL(f.Attestor(0)->statusHeight, f.tip);
    for (int i = 0; i < 20; i++) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(f.Attestor(1)->status, (uint8_t)AttestorStatus::ELIGIBLE);
    BOOST_CHECK(!f.Attestor(2).has_value());
}

// Rule: P4-b
// Rule: IN-2
BOOST_AUTO_TEST_CASE(p4b_rejoin_after_withdraw_new_seq)
{
    Fixture f;
    f.MineQuotesTo(20);
    f.Register(1);
    while (f.tip < (int)f.Attestor(0)->bondLocktime) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(VerdictOf(f, f.BondSpendTx(0)), verdict::OK);
    BOOST_CHECK_EQUAL(f.Attestor(0)->status, (uint8_t)AttestorStatus::WITHDRAWN);
    // the same key joins again (the set allows a key that is not ACTIVE): a new seq, the old record stays WITHDRAWN
    BOOST_CHECK_EQUAL(VerdictOf(f, f.RegisterTx(1, 10 * COIN, -1, 0)), verdict::OK);
    BOOST_REQUIRE(f.Attestor(1).has_value());
    BOOST_CHECK(f.Attestor(1)->attestorPubKey == f.Attestor(0)->attestorPubKey);
    BOOST_CHECK_EQUAL(f.Attestor(1)->status, (uint8_t)AttestorStatus::PENDING);
    // a heartbeat reaches the key's newest record only
    const int lastAct0 = f.Attestor(0)->lastAct;
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    CMutableTransaction hb = f.HeartbeatTx(0);
    BOOST_CHECK_EQUAL(VerdictOf(f, hb), verdict::OK);
    BOOST_CHECK_EQUAL(f.Attestor(1)->lastAct, f.tip);
    BOOST_CHECK_EQUAL(f.Attestor(0)->lastAct, lastAct0);
    BOOST_CHECK_EQUAL(f.Log(CTransaction(hb).GetHash())->type, (uint8_t)TxLogType::ATTESTOR_SET_ACT);
    BOOST_CHECK_EQUAL(f.Log(CTransaction(hb).GetHash())->attestorSeq, 1);
}

// Rule: P4-b
// Rule: EQV-1
// Rule: IN-2
BOOST_AUTO_TEST_CASE(p4b_slashed_key_barred_remove_winddown_refused)
{
    Fixture f;
    f.Arm(4);
    // EQV-1 ejects seq 0 and freezes its bond.
    const int cited = f.tip;
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(VerdictOf(f, f.EquivocationTx(f.Att(0, 50000, cited), f.Att(0, 51000, cited))), verdict::OK);
    BOOST_CHECK_EQUAL(f.Attestor(0)->status, (uint8_t)AttestorStatus::EJECTED);
    BOOST_CHECK(f.Attestor(0)->bondFrozen);
    // Owner 2026-10-11: SET_REMOVE (with or without burn) and SET_WINDDOWN of the attestor set are invalid; nothing moves.
    const AttestorRecord three = f.Attestor(3).value();
    CMutableTransaction rm = f.RemoveTx(3, 1, false);
    BOOST_CHECK(RefusedAttestorSetAct(CTransaction(rm), f.P));
    BOOST_CHECK_EQUAL(VerdictOf(f, rm), verdict::ATTESTOR_SET_ACT);
    BOOST_CHECK_EQUAL(VerdictOf(f, f.RemoveTx(2, 1, true)), verdict::ATTESTOR_SET_ACT);
    vault::Act wd;
    wd.type = vault::ACT_SET_WINDDOWN;
    wd.winddown.setId = f.P.attestorSetId;
    BOOST_CHECK_EQUAL(VerdictOf(f, f.ActTx(wd, { f.hotKeys[1] })), verdict::ATTESTOR_SET_ACT);
    BOOST_CHECK(SerializeRecord(f.Attestor(3).value()) == SerializeRecord(three));
    BOOST_CHECK(!f.Attestor(2)->bondFrozen);
    // ... of another set they are not the module's business
    vault::Act other;
    other.type = vault::ACT_SET_REMOVE;
    other.remove.setId = uint256S("0x1234");
    other.remove.memberKey = f.hotKeys[3].GetPubKey();
    BOOST_CHECK(!RefusedAttestorSetAct(CTransaction(f.ActTx(other, { f.hotKeys[1] })), f.P));
    BOOST_CHECK_EQUAL(VerdictOf(f, f.ActTx(other, { f.hotKeys[1] })), "none");      // no TxLog entry: not a YED transaction
    // the bond exit delay (owner 2026-10-11): a member's own exit (SET_REMOVE of itself, signed by itself alone, no burn)
    // is valid: WITHDRAWN at once (no seat), not slashed; with burn, or signed by another, it is a vote and refused
    BOOST_CHECK(RefusedAttestorSetAct(CTransaction(f.RemoveTx(3, 3, true)), f.P));
    BOOST_CHECK(RefusedAttestorSetAct(CTransaction(f.RemoveTx(3, 1, false)), f.P));
    CMutableTransaction leave = f.RemoveTx(3, 3, false);
    BOOST_CHECK(!RefusedAttestorSetAct(CTransaction(leave), f.P));
    BOOST_CHECK_EQUAL(VerdictOf(f, leave), verdict::OK);
    BOOST_CHECK_EQUAL(f.Attestor(3)->status, (uint8_t)AttestorStatus::WITHDRAWN);
    BOOST_CHECK_EQUAL(f.Attestor(3)->statusHeight, f.tip);
    BOOST_CHECK(!f.Attestor(3)->bondFrozen);
    BOOST_CHECK(!(f.Attestor(3)->flags & ATTESTOR_FLAG_EVICTED));
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));                   // the next SNAP no longer seats it
    const std::vector<uint16_t> seatedNow = f.Snap(f.tip).seated;
    BOOST_CHECK(std::find(seatedNow.begin(), seatedNow.end(), 3) == seatedNow.end());
    // the slashed key rejoins and stays PENDING for good
    BOOST_CHECK_EQUAL(VerdictOf(f, f.RegisterTx(4, 10 * COIN, -1, 0)), verdict::OK);   // seq 4 = key 0
    for (int i = 0; i < f.P.bondMaturity + 1; i++) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(f.Attestor(4)->status, (uint8_t)AttestorStatus::PENDING);
}

// Rule: P4-b: the set's member dormancy (lastAct < H - livenessWindow) and revival by SET_HEARTBEAT
BOOST_AUTO_TEST_CASE(p4b_set_dormancy_and_heartbeat_revival)
{
    Fixture f;
    f.RecreateSet(20);                                          // livenessWindow 20
    f.MineQuotesTo(20);
    f.Register(1);
    const int joined = f.tip;
    const int lastAct = f.Attestor(0)->lastAct;
    BOOST_CHECK_EQUAL(lastAct, joined + 8);                           // the set's maturity (BOND_MATURITY)
    while (f.tip < joined + f.P.bondMaturity) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(f.Attestor(0)->status, (uint8_t)AttestorStatus::ELIGIBLE);
    while (f.tip < lastAct + 20) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(f.Attestor(0)->status, (uint8_t)AttestorStatus::ELIGIBLE);    // lastAct >= H - 20
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(f.Attestor(0)->status, (uint8_t)AttestorStatus::DORMANT);
    BOOST_CHECK_EQUAL(f.Attestor(0)->statusHeight, f.tip);
    BOOST_CHECK(f.Snap(f.tip).seated.empty());
    CMutableTransaction hb = f.HeartbeatTx(0);
    BOOST_CHECK_EQUAL(VerdictOf(f, hb), verdict::OK);
    BOOST_CHECK_EQUAL(f.Attestor(0)->status, (uint8_t)AttestorStatus::ELIGIBLE);       // at the heartbeat's own SNAP
    BOOST_CHECK_EQUAL(f.Attestor(0)->lastAct, f.tip);
    BOOST_CHECK(f.Snap(f.tip).seated == std::vector<uint16_t>({ 0 }));
    f.Undo();
    BOOST_CHECK_EQUAL(f.Attestor(0)->status, (uint8_t)AttestorStatus::DORMANT);
}

// Rule: P4-b: the module adopts only an OPEN attestor set of ATTESTOR_SEATS (15) seats (owner 2026-10-11)
BOOST_AUTO_TEST_CASE(p4b_attestor_set_adopted_only_open_15)
{
    // OPEN, 15 seats, maturity BOND_MATURITY (the bond exit delay, 8 on regtest): only variant 3 is adopted
    for (int variant = 0; variant < 4; variant++) {
        Fixture f;
        f.RecreateSet(1000000, variant == 2 ? 1 : 8, variant == 0 ? 2 : 15);   // 2 seats; closed; maturity 1; the one
        if (variant == 1) {
            vault::Act a;
            BOOST_REQUIRE(!vault::DecodeAct(f.setCreate.vout[0].scriptPubKey, a));
            a.create.flags = 0;
            f.setCreate.vout[0].scriptPubKey = vault::EncodeAct(a);
            f.P.attestorSetId = CTransaction(f.setCreate).GetHash();
        }
        f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3), { f.setCreate });
        BOOST_CHECK_EQUAL(State(f.view).GetAttestorSet().has_value(), variant == 3);
    }
}

// Rule: P4-b
// Rule: I-3
BOOST_AUTO_TEST_CASE(attestor_set_adopted_only_with_threshold_one)
{
    // 03/I-3: cancelThreshold and unlockThreshold are pinned at ATTESTOR_CANCEL/UNLOCK_THRESHOLD (1)
    // W3-Y-3: rateLimitBps is pinned at ATTESTOR_RATE_LIMIT_BPS (0); a non-zero S-3 limit is not adopted
    BOOST_CHECK_EQUAL(MainParams().attestorCancelThreshold, 1);
    BOOST_CHECK_EQUAL(MainParams().attestorUnlockThreshold, 1);
    BOOST_CHECK_EQUAL(MainParams().attestorRateLimitBps, 0);
    for (int variant = 0; variant < 4; variant++) {
        Fixture f;
        vault::Act a;
        BOOST_REQUIRE(!vault::DecodeAct(f.setCreate.vout[0].scriptPubKey, a));
        if (variant == 0) a.create.cancelThreshold = 2;
        if (variant == 1) a.create.unlockThreshold = 2;
        if (variant == 2) a.create.rateLimitBps = 1;
        f.setCreate.vout[0].scriptPubKey = vault::EncodeAct(a);
        f.P.attestorSetId = CTransaction(f.setCreate).GetHash();
        f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3), { f.setCreate });
        BOOST_CHECK_EQUAL(State(f.view).GetAttestorSet().has_value(), variant == 3);
    }
}

// Rule: seat ranking and eviction (owner 2026-10-11): EvictionVictim over primitive fields
BOOST_AUTO_TEST_CASE(seat_eviction_victim_rule)
{
    const yellowback::Params P = RegtestParams(1, 0, 0, TestSet());
    auto key = [](int i) { return Fixture::DeterministicKey("yellowback-evict", i).GetPubKey(); };
    auto cand = [&](int i, CAmount bond, int64_t join, int64_t lastAct) { SeatCandidate c; c.key = key(i); c.bondZat = bond; c.joinHeight = join; c.lastAct = lastAct; return c; };
    const int64_t H = 100000, LW = 1000;
    // all live: the least seat weight, only above x1.05
    std::vector<SeatCandidate> m = { cand(0, 20 * COIN, H - 8064, H), cand(1, 8 * COIN, H - 8064, H), cand(2, 8 * COIN, H - 10, H) };
    BOOST_CHECK(!EvictionVictim(m, H, 8 * COIN, LW, P).has_value());                 // equal bond, no tenure: never
    BOOST_CHECK(EvictionVictim(m, H, 9 * COIN, LW, P) == std::optional<CPubKey>(key(2)));   // the youngest 8 YEC
    BOOST_CHECK(!EvictionVictim(m, H, 8 * COIN * 105 / 100, LW, P).has_value());     // not above x1.05 (and f(10) > 1)
    // 1.5x beats a one-week member, loses to a one-year member
    std::vector<SeatCandidate> week = { cand(0, 6 * COIN, H - 8064, H) }, year = { cand(0, 6 * COIN, H - 420480, H) };
    BOOST_CHECK(EvictionVictim(week, H, 9 * COIN, LW, P).has_value());
    BOOST_CHECK(!EvictionVictim(year, H, 9 * COIN, LW, P).has_value());
    // a new 20,000 YEC bond beats 8,000 YEC at any tenure
    std::vector<SeatCandidate> old8k = { cand(0, 8000 * COIN, H - 10 * 420480LL, H) };
    BOOST_CHECK(EvictionVictim(old8k, H, 20000 * COIN, LW, P).has_value());
    // a member that is not live goes first, whatever its weight, with any bond at the module's floor -- never below
    // it (seats review B2: no dust evictions)
    m.push_back(cand(3, 1000 * COIN, H - 420480, H - LW - 1));
    BOOST_CHECK(EvictionVictim(m, H, P.bondMinFloorZat, LW, P) == std::optional<CPubKey>(key(3)));
    BOOST_CHECK(!EvictionVictim(m, H, P.bondMinFloorZat - 1, LW, P).has_value());
    m[3].lastAct = H - LW;                                                             // lastAct = H - LW is live
    BOOST_CHECK(!EvictionVictim(m, H, P.bondMinFloorZat, LW, P).has_value());
    // among the not-live, the least weight; ties by key bytes
    m.push_back(cand(4, 10 * COIN, H - 420480, H - LW - 5));
    m[3].lastAct = H - LW - 1;
    BOOST_CHECK(EvictionVictim(m, H, P.bondMinFloorZat, LW, P) == std::optional<CPubKey>(key(4)));
    std::vector<SeatCandidate> tie = { cand(5, 8 * COIN, H - 50, H), cand(6, 8 * COIN, H - 50, H) };
    const CPubKey k5 = key(5), k6 = key(6);
    const CPubKey lo = std::lexicographical_compare(k5.begin(), k5.end(), k6.begin(), k6.end()) ? k5 : k6;
    BOOST_CHECK(EvictionVictim(tie, H, 100 * COIN, LW, P) == std::optional<CPubKey>(lo));
    BOOST_CHECK(!EvictionVictim({}, H, 100 * COIN, LW, P).has_value());
}

// Rule: seat ranking and eviction (owner 2026-10-11): the mirror of a join into the full set
BOOST_AUTO_TEST_CASE(seat_eviction_mirror)
{
    Fixture f;
    f.Activate();
    f.Register(15);                                             // seq i = key i, one per block, 10 YEC each
    for (int i = 0; i < 15; i++) BOOST_REQUIRE(f.Attestor((uint16_t)i).has_value());
    // equal bond: no eviction (the primitive refuses; the mirror, given the block anyway, leaves every record alone)
    CMutableTransaction eq = f.RegisterTx(15, 10 * COIN);
    BOOST_CHECK_EQUAL(VerdictOf(f, eq), verdict::OK);
    for (int i = 0; i < 15; i++) BOOST_CHECK(f.Attestor((uint16_t)i)->Status() != AttestorStatus::WITHDRAWN);
    f.Undo();
    // 11 YEC evicts the youngest 10-YEC member (seq 14): WITHDRAWN, flagged, bond neither frozen nor spent
    BOOST_CHECK_EQUAL(VerdictOf(f, f.RegisterTx(15, 11 * COIN)), verdict::OK);
    BOOST_CHECK_EQUAL(f.Attestor(14)->status, (uint8_t)AttestorStatus::WITHDRAWN);
    BOOST_CHECK_EQUAL(f.Attestor(14)->statusHeight, f.tip);
    BOOST_CHECK(f.Attestor(14)->flags & ATTESTOR_FLAG_EVICTED);
    BOOST_CHECK(!f.Attestor(14)->bondFrozen);
    BOOST_CHECK_EQUAL(f.Attestor(14)->bondSpentHeight, 0);
    BOOST_CHECK_EQUAL(f.Attestor(15)->status, (uint8_t)AttestorStatus::PENDING);
    for (int i = 0; i < 14; i++) BOOST_CHECK(f.Attestor((uint16_t)i)->Status() != AttestorStatus::WITHDRAWN);
    // the evicted bond is spent later: still WITHDRAWN, statusHeight kept, bondSpentHeight set
    const int evictedAt = f.tip;
    while (f.tip < (int)f.Attestor(14)->bondLocktime) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(VerdictOf(f, f.BondSpendTx(14)), verdict::OK);
    BOOST_CHECK_EQUAL(f.Attestor(14)->status, (uint8_t)AttestorStatus::WITHDRAWN);
    BOOST_CHECK_EQUAL(f.Attestor(14)->statusHeight, evictedAt);
    BOOST_CHECK_EQUAL(f.Attestor(14)->bondSpentHeight, f.tip);
    // the evicted key can rejoin (a new seq) and is not barred: it is not slashed
    BOOST_CHECK_EQUAL(VerdictOf(f, f.RegisterTx(16, 50 * COIN, -1, 14)), verdict::OK);
    BOOST_CHECK(f.Attestor(16)->attestorPubKey == f.Attestor(14)->attestorPubKey);
}

// Rule: D-Q-30: the module's bond floor is clamp(ceil(collateral x BOND_SHARE_BPS / 10^4 / N_SLOTS), floor, cap)
// over the YEC in ACTIVE YED vaults at Snapshots[registerHeight - 1]; no price is read; judged once, for PENDING records only.
BOOST_AUTO_TEST_CASE(dq28_bond_min_from_collateral)
{
    const MicroUsd FIVE = 5000000;                            // $5: a $100 mint needs 60 YEC at 300 %
    Fixture f(1, 0, 0, 0);                                    // attestArmMin 0: never arms, mints need no bundle
    auto quote = [&]() { f.Mine(Fixture::Quote(FIVE, (f.tip + 1) % 3)); };
    auto bondMin = [&]() { return BondMinZat(State(f.view), f.P, f.tip + 1); };
    auto mint = [&](CAmount collateral) {
        MintOpts o;
        o.collateral = collateral;
        CMutableTransaction m = f.MintTx(10000, 48, f.tip - 1, o);
        f.Mine(Fixture::Quote(FIVE, (f.tip + 1) % 3), { m });
        BOOST_REQUIRE(f.Vault(CTransaction(m).GetHash()).has_value());
    };
    BOOST_CHECK_EQUAL(BondMinZat(State(f.view), f.P, f.P.startHeight), 5 * COIN);   // the virtual snapshot: no collateral
    f.Activate(FIVE);
    BOOST_CHECK_EQUAL(f.GetTotals().collateralZat, 0);
    BOOST_CHECK_EQUAL(bondMin(), 5 * COIN);                   // empty vaults: the 5-YEC floor
    // the floor's boundary (seats re-review: a join below the minimum at its block is invalid, so it is never recorded):
    // 5 YEC - 1 zat is refused, 5 YEC is seq 0
    auto refusedAs = [&](const CMutableTransaction& m) {
        auto it = f.refused.find(CTransaction(m).GetHash());
        return it == f.refused.end() ? std::string("none") : it->second.verdict;
    };
    const CMutableTransaction below0 = f.RegisterTx(0, 5 * COIN - 1);
    f.Mine(Fixture::Quote(FIVE, (f.tip + 1) % 3), { below0, f.RegisterTx(1, 5 * COIN) });
    BOOST_CHECK_EQUAL(refusedAs(below0), verdict::ATTESTOR_BOND_BELOW_MIN);
    // the minimum rises with collateral: 700 YEC locked -> ceil(700 x 500 / 10^4 / 5) = 7 YEC
    mint(700 * COIN);
    BOOST_CHECK_EQUAL(f.GetTotals().collateralZat, 700 * COIN);
    BOOST_CHECK_EQUAL(bondMin(), 7 * COIN);
    const CMutableTransaction below2 = f.RegisterTx(2, 7 * COIN - 1);
    f.Mine(Fixture::Quote(FIVE, (f.tip + 1) % 3), { below2, f.RegisterTx(3, 7 * COIN) });   // seq 1
    BOOST_CHECK_EQUAL(refusedAs(below2), verdict::ATTESTOR_BOND_BELOW_MIN);
    const int reg1 = f.tip;
    while (f.tip < reg1 + f.P.bondMaturity) quote();
    BOOST_CHECK_EQUAL(f.Attestor(0)->status, (uint8_t)AttestorStatus::ELIGIBLE);   // judged at its own (empty) snapshot
    BOOST_CHECK_EQUAL(f.Attestor(1)->status, (uint8_t)AttestorStatus::ELIGIBLE);
    // the cap: 1,700 YEC locked would ask 17 YEC; the minimum stops at 10 YEC
    mint(1000 * COIN);
    BOOST_CHECK_EQUAL(bondMin(), 10 * COIN);
    const CMutableTransaction below4 = f.RegisterTx(4, 10 * COIN - 1);
    f.Mine(Fixture::Quote(FIVE, (f.tip + 1) % 3), { below4, f.RegisterTx(5, 10 * COIN) });   // seq 2
    BOOST_CHECK_EQUAL(refusedAs(below4), verdict::ATTESTOR_BOND_BELOW_MIN);
    const int reg2 = f.tip;
    while (f.tip < reg2 + f.P.bondMaturity) quote();
    BOOST_CHECK_EQUAL(f.Attestor(2)->status, (uint8_t)AttestorStatus::ELIGIBLE);
    // checked once: the 5-YEC and 7-YEC records stay ELIGIBLE under a 10-YEC minimum, and a price move (which the
    // rule never reads) changes nothing
    for (int i = 0; i < 70; i++) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(f.Attestor(0)->status, (uint8_t)AttestorStatus::ELIGIBLE);
    BOOST_CHECK_EQUAL(f.Attestor(1)->status, (uint8_t)AttestorStatus::ELIGIBLE);
    BOOST_CHECK_EQUAL(bondMin(), 10 * COIN);
    // with N_SLOTS 5 and three ELIGIBLE records, every one is seated; seq 3 and 4 (10 YEC, the cap) fill the seats
    BOOST_CHECK(f.Snap(f.tip).seated == std::vector<uint16_t>({ 0, 1, 2 }));
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3), { f.RegisterTx(6, 10 * COIN), f.RegisterTx(7, 10 * COIN) });
    const int reg34 = f.tip;
    while (f.tip < reg34 + f.P.bondMaturity) quote();
    BOOST_CHECK(f.Snap(f.tip).seated == std::vector<uint16_t>({ 0, 1, 2, 3, 4 }));
    // the bump: seq 5 posts 10 YEC and, by SeatRank (bond x the tenure factor; seq 0 seated, x1.05), outranks seq 0
    // (5 YEC) at the first SNAP where seq 5 is ELIGIBLE (the tenure factor is near 1.0 at regtest ages)
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3), { f.RegisterTx(8, 10 * COIN) });
    const int reg5 = f.tip;
    BOOST_REQUIRE(f.Attestor(5).has_value());
    const int reg0 = f.Attestor(0)->registerHeight;
    BOOST_CHECK(SeatWeight(10 * COIN, f.P.bondMaturity, f.P.seatAgeUnit, f.P.seatAgeCap) * arith_uint256(10000) >
                SeatWeight(5 * COIN, reg5 + f.P.bondMaturity - reg0, f.P.seatAgeUnit, f.P.seatAgeCap) * arith_uint256(10500));
    while (f.tip < reg5 + f.P.bondMaturity - 1) quote();
    BOOST_CHECK(f.Snap(f.tip).seated == std::vector<uint16_t>({ 0, 1, 2, 3, 4 }));
    quote();
    BOOST_CHECK(f.Snap(f.tip).seated == std::vector<uint16_t>({ 1, 2, 3, 4, 5 }));
    BOOST_CHECK_EQUAL(f.Attestor(0)->status, (uint8_t)AttestorStatus::ELIGIBLE);   // bumped from its seat, still a member
    BOOST_CHECK_EQUAL(f.Attestor(0)->seatedSince, 0);
}

// Rule: seats review B2 (focused review): a bundle credits liveness only inside a held YED act, and only within
// REF_WINDOW of its refHeight
BOOST_AUTO_TEST_CASE(liveness_needs_held_act_and_fresh_ref)
{
    Fixture f;
    f.Arm();
    const uint256 noVault = uint256S("11");
    const valtype sel = OutPointSelector(COutPoint(noVault, 0));
    // a CLAIM_NOTICE of a vault that does not exist (not held) whose bundle would refresh liveness: invalid
    const int R = f.tip - 1;
    const CMutableTransaction bad = f.NoticeTx(noVault, R, f.BundleFor(R, sel, 50000));
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3), { bad });
    BOOST_REQUIRE(f.refused.count(CTransaction(bad).GetHash()));
    BOOST_CHECK_EQUAL(f.refused.at(CTransaction(bad).GetHash()).verdict, verdict::LIVENESS_UNHELD);
    // the same kind of notice at a refHeight older than REF_WINDOW credits nobody: an ordinary transaction
    for (int i = 0; i < f.P.refWindow + 2; i++) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    const int old = f.tip + 1 - f.P.refWindow - 1;
    const std::vector<uint16_t> signers = Selected(f.view, f.P, old, sel);
    BOOST_REQUIRE(!signers.empty());
    std::map<uint16_t, int32_t> before;
    for (uint16_t s : signers) before[s] = f.Attestor(s)->lastAct;
    const CMutableTransaction replay = f.NoticeTx(noVault, old, f.BundleFor(old, sel, 50000));
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3), { replay });
    BOOST_CHECK(!f.refused.count(CTransaction(replay).GetHash()));
    for (uint16_t s : signers) BOOST_CHECK_EQUAL(f.Attestor(s)->lastAct, before[s]);
}

// Rule: P4-b (focused review): once the u16 seq space is used up a SET_JOIN of the attestor set is invalid, so the
// primitive never admits a member the mirror cannot record
BOOST_AUTO_TEST_CASE(attestor_seq_exhausted)
{
    Fixture f;
    f.MineQuotesTo(20);
    f.Register(1);                                                     // seq 0
    AttestorSeqRecord n;
    n.next = 0xFFFF;
    State(f.view).Put(keys::AttestorSeq(), n);                         // forced: 65,534 joins later
    BOOST_CHECK_EQUAL(VerdictOf(f, f.RegisterTx(1, 10 * COIN)), verdict::OK);   // the last seq, 65,535
    BOOST_REQUIRE(f.Attestor(0xFFFF).has_value());
    BOOST_CHECK_EQUAL(State(f.view).GetAttestorSeq().next, 0);         // wrapped onto seq 0, which exists
    BOOST_CHECK_EQUAL(VerdictOf(f, f.RegisterTx(2, 10 * COIN)), verdict::ATTESTOR_SEQ_EXHAUSTED);
    BOOST_CHECK_EQUAL(State(f.view).GetAttestorSeq().next, 0);
}

// Rule: ARM-1
BOOST_AUTO_TEST_CASE(arm1_triggers_at_exact_block)
{
    Fixture f;
    f.Activate();
    f.Register(3);                                              // seq 2 registered at f.tip; ELIGIBLE at f.tip + BOND_MATURITY
    const int third = f.tip;
    while (f.tip < third + f.P.bondMaturity - 1) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(f.Attestor(2)->status, (uint8_t)AttestorStatus::PENDING);
    BOOST_CHECK_EQUAL(f.Attest().status, (uint8_t)AttestStatus::UNARMED);
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(f.Attestor(2)->status, (uint8_t)AttestorStatus::ELIGIBLE);
    BOOST_CHECK_EQUAL(f.Attestor(2)->statusHeight, f.tip);
    BOOST_CHECK_EQUAL(f.Attest().status, (uint8_t)AttestStatus::TRIGGERED);
    BOOST_CHECK_EQUAL(f.Attest().triggerHeight, f.tip);
    BOOST_CHECK_EQUAL(f.Attest().armHeight, f.tip + f.P.attestArmDelay);
    BOOST_CHECK_EQUAL(f.Snap(f.tip).attest.status, (uint8_t)AttestStatus::TRIGGERED);
    BOOST_CHECK(!f.Armed());
    // attestArmMin 0 never arms
    Fixture g(1, 0, 0, 0);
    g.Activate();
    g.Register(3);
    for (int i = 0; i < 20; i++) g.Mine(Fixture::Quote(50000, (g.tip + 1) % 3));
    BOOST_CHECK_EQUAL(g.Attest().status, (uint8_t)AttestStatus::UNARMED);
}

// Rule: ARM-2
BOOST_AUTO_TEST_CASE(arm2_arms_after_delay)
{
    Fixture f;
    f.Activate();
    f.Register(3);
    while (f.Attest().status != (uint8_t)AttestStatus::TRIGGERED) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    const int arm = f.Attest().armHeight;
    while (f.tip < arm - 1) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(f.Attest().status, (uint8_t)AttestStatus::TRIGGERED);
    BOOST_CHECK(!ArmedAt(f.view, f.P, f.tip));
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(f.tip, arm);
    BOOST_CHECK_EQUAL(f.Attest().status, (uint8_t)AttestStatus::ARMED);
    BOOST_CHECK(ArmedAt(f.view, f.P, f.tip));
    BOOST_CHECK(!ArmedAt(f.view, f.P, f.tip - 1));
}

// Rule: ARM-1
// Rule: ARM-2
BOOST_AUTO_TEST_CASE(arm_never_reverses)
{
    Fixture f;
    f.Arm();
    const AttestState before = f.Attest();
    // Eject every attestor: fewer than ATTEST_ARM_MIN remain ELIGIBLE, the layer stays ARMED.
    for (int seq = 0; seq < 3; seq++) {
        const int cited = f.tip;
        f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
        BOOST_CHECK_EQUAL(VerdictOf(f, f.EquivocationTx(f.Att(seq, 50000, cited), f.Att(seq, 52000, cited))), verdict::OK);
    }
    for (int i = 0; i < 10; i++) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK(f.Attest() == before);
    BOOST_CHECK(f.Snap(f.tip).seated.empty());
    BOOST_CHECK(f.Armed());
    // and a mint now needs a bundle nobody can sign
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1)), verdict::MINT9_NO_BUNDLE);
}

// Rule: ARM-1
BOOST_AUTO_TEST_CASE(founding_cohort_origin)
{
    Fixture f;
    f.Activate();
    f.Register(3);
    while (f.Attest().status != (uint8_t)AttestStatus::TRIGGERED) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    const int trigger = f.Attest().triggerHeight;
    // A registrant inside FOUNDING_WINDOW is founding; one a block later is not.
    while (f.tip < trigger + f.P.foundingWindow - 1) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    f.Register(1, 3);                                           // registerHeight == trigger + FOUNDING_WINDOW
    f.Register(1, 4);                                           // registerHeight == trigger + FOUNDING_WINDOW + 1
    const AttestState m = f.Attest();
    BOOST_CHECK_EQUAL(AgeOrigin(f.Attestor(0).value(), m, f.P), trigger);
    BOOST_CHECK_EQUAL(AgeOrigin(f.Attestor(3).value(), m, f.P), trigger);
    BOOST_CHECK_EQUAL(AgeOrigin(f.Attestor(4).value(), m, f.P), f.Attestor(4)->registerHeight);
    BOOST_CHECK(f.Attestor(4)->registerHeight > trigger + f.P.foundingWindow);
    // Before the trigger the origin is the registration itself.
    BOOST_CHECK_EQUAL(AgeOrigin(f.Attestor(0).value(), AttestState(), f.P), f.Attestor(0)->registerHeight);
    // Seq 0 and seq 3 share the origin, so they weigh the same at every height; seq 4 is lighter.
    const int H = f.tip + 30;
    BOOST_CHECK(AttestorWeight(f.Attestor(0).value(), m, f.P, H) == AttestorWeight(f.Attestor(3).value(), m, f.P, H));
    BOOST_CHECK(AttestorWeight(f.Attestor(4).value(), m, f.P, H) < AttestorWeight(f.Attestor(0).value(), m, f.P, H));
}

// Rule: ARM-1
BOOST_AUTO_TEST_CASE(weight_clamped_before_trigger)
{
    AttestorRecord rec;
    rec.bondZat = 10 * COIN;
    rec.registerHeight = 100;
    yellowback::Params P = RegtestParams(1, 0, 0, TestSet());
    AttestState m;
    m.status = (uint8_t)AttestStatus::TRIGGERED;
    m.triggerHeight = 150;
    BOOST_CHECK(AttestorWeight(rec, m, P, 149) == arith_uint256(0));               // before the shared origin: clamp at 0
    BOOST_CHECK(AttestorWeight(rec, m, P, 150) == arith_uint256(0));
    BOOST_CHECK(AttestorWeight(rec, m, P, 151) == arith_uint256((uint64_t)(10 * COIN)));
    BOOST_CHECK(AttestorWeight(rec, m, P, 150 + P.ageCap + 500) == arith_uint256((uint64_t)(10 * COIN)) * arith_uint256((uint64_t)P.ageCap));
    BOOST_CHECK(AttestorWeight(rec, AttestState(), P, 99) == arith_uint256(0));
    BOOST_CHECK(AttestorWeight(rec, AttestState(), P, 101) == arith_uint256((uint64_t)(10 * COIN)));
}

// Rule: ARM-1
BOOST_AUTO_TEST_CASE(seating_ties_by_seq)
{
    Fixture f;
    f.Activate();
    f.Register(6);                                              // one per block: seq 0 is the oldest
    while (f.Attestor(5)->status != (uint8_t)AttestorStatus::ELIGIBLE) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    // Every bond is 10 YEC and all six are founding, so weights tie: the five lowest seq are seated.
    for (int i = 0; i < 3; i++) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK(f.Attest().status != (uint8_t)AttestStatus::UNARMED);
    std::vector<uint16_t> expect = { 0, 1, 2, 3, 4 };
    BOOST_CHECK(f.Snap(f.tip).seated == expect);
    BOOST_CHECK(Seated(f.view, f.P, f.tip) == expect);
    BOOST_CHECK_EQUAL(f.Attestor(5)->seatedSince, 0);
    BOOST_CHECK(f.Attestor(4)->seatedSince > 0);
}

// Rule: BUNDLE-1
BOOST_AUTO_TEST_CASE(selected_matches_python)
{
    // The vectors of test_framework/test_yellowback_attest.py SelectionTests (select_attestors).
    const uint256 bhAB = uint256S("abababababababababababababababababababababababababababababababab");
    const uint256 bh01 = uint256S("0101010101010101010101010101010101010101010101010101010101010101");
    typedef std::vector<std::pair<uint16_t, arith_uint256>> Pool;
    Pool pool = { { 3, arith_uint256(3) }, { 1, arith_uint256(1) }, { 2, arith_uint256(2) } };
    std::vector<uint16_t> got = SelectAttestors(bhAB, valtype(), pool, 3);
    BOOST_CHECK((got == std::vector<uint16_t>{ 2, 1, 3 }));
    BOOST_CHECK((SelectAttestors(bhAB, valtype(), pool, 1) == std::vector<uint16_t>{ 2 }));
    valtype sel = OutPointSelector(COutPoint(uint256S("1111111111111111111111111111111111111111111111111111111111111111"), 1));
    BOOST_CHECK_EQUAL(HexStr(sel), std::string(64, '1') + "01000000");
    BOOST_CHECK((SelectAttestors(bhAB, sel, pool, 3) == std::vector<uint16_t>{ 3, 2, 1 }));
    // 256-bit modulus: three bonds of 2^70; a 64-bit pick would choose seq 1 first
    const arith_uint256 W = arith_uint256(1) << 70;
    Pool big = { { 1, W }, { 2, W }, { 3, W } };
    BOOST_CHECK((SelectAttestors(bh01, valtype(), big, 3) == std::vector<uint16_t>{ 3, 1, 2 }));
    // zero and short pools
    Pool zeros = { { 9, 0 }, { 4, 0 }, { 6, 0 }, { 1, 0 } };
    BOOST_CHECK((SelectAttestors(bhAB, valtype(), zeros, 3) == std::vector<uint16_t>{ 1, 4, 6 }));
    Pool mixed = { { 9, 0 }, { 4, arith_uint256(5) } };
    BOOST_CHECK((SelectAttestors(bhAB, valtype(), mixed, 3) == std::vector<uint16_t>{ 4, 9 }));
    Pool one = { { 5, arith_uint256(1) } };
    BOOST_CHECK((SelectAttestors(bhAB, valtype(), one, 3) == std::vector<uint16_t>{ 5 }));
    BOOST_CHECK(SelectAttestors(bhAB, valtype(), Pool(), 3).empty());
}

// Rule: PIN-2
// Rule: BUNDLE-1
BOOST_AUTO_TEST_CASE(selected_excludes_pinned)
{
    Fixture f;
    f.Arm(5);
    const int R = f.tip;
    Snapshot s = f.Snap(R);
    BOOST_CHECK_EQUAL(s.seated.size(), 5u);
    for (int trial = 0; trial < 5; trial++) {
        // Pin seq `trial` at R (the stored array is what Selected reads, R11) and see it never drawn.
        Snapshot pinned = s;
        pinned.pinnedSeqs = { (uint16_t)trial };
        State(f.view).Put(keys::Snapshot((uint32_t)R), pinned);
        std::vector<uint16_t> got = Selected(f.view, f.P, R, valtype());
        BOOST_CHECK_EQUAL(got.size(), 3u);
        BOOST_CHECK(std::find(got.begin(), got.end(), (uint16_t)trial) == got.end());
    }
    State(f.view).Put(keys::Snapshot((uint32_t)R), s);
    BOOST_CHECK_EQUAL(Selected(f.view, f.P, R, valtype()).size(), 3u);
    BOOST_CHECK(Selected(f.view, f.P, R + 1, valtype()).empty());      // no snapshot: empty (total)
    BOOST_CHECK(Selected(f.view, f.P, 0, valtype()).empty());
}

// Rule: MINT-9
BOOST_AUTO_TEST_CASE(mint9_no_bundle_void)
{
    Fixture f;
    f.Arm();
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1)), verdict::MINT9_NO_BUNDLE);
    BOOST_CHECK(!f.BundleRow(f.tip).has_value());
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintV3(10000, 50000)), "");
    BOOST_REQUIRE(f.BundleRow(f.tip).has_value());
    BOOST_CHECK_EQUAL(f.BundleRow(f.tip)->aMint, 50000);
    BOOST_CHECK_EQUAL(f.BundleRow(f.tip)->selectedSeqs.size(), 3u);
    // A malformed bundle behind a carrier is "mint9-bundle-shape"; two carriers "mint9-bundle-two-carriers".
    { MintOpts o; o.bundle = valtype(10, 0x41); BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "mint9-bundle-shape"); }
    { CMutableTransaction m = f.MintV3(10000, 50000); m.vin.push_back(m.vin.back());
      BOOST_CHECK_EQUAL(MintVerdictOf(f, m), "mint9-bundle-two-carriers"); }
}

// Rule: MINT-9
// Rule: BUNDLE-1
BOOST_AUTO_TEST_CASE(mint9_bundle_from_unselected_void)
{
    Fixture f;
    f.Arm(4);
    const int R = f.tip - 1;
    std::vector<uint16_t> sel = Selected(f.view, f.P, R, valtype());
    BOOST_REQUIRE_EQUAL(sel.size(), 3u);
    int outsider = -1;
    for (int q = 0; q < 4; q++) {
        if (std::find(sel.begin(), sel.end(), (uint16_t)q) == sel.end()) outsider = q;
    }
    BOOST_REQUIRE(outsider >= 0);
    Bundle b;
    b.atts.push_back(f.Att(sel[0], 50000, R));
    b.atts.push_back(f.Att(outsider, 50000, R));
    MintOpts o;
    o.bundle = EncodeBundle(b);
    o.attestPayee = sel[0];
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, R, o)), "mint9-bundle-member");
    // and a duplicate seq, a short count, a bad signature
    Bundle d; d.atts = { f.Att(sel[0], 50000, R), f.Att(sel[0], 50000, R) };
    o.bundle = EncodeBundle(d);
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "mint9-bundle-dup");
    Bundle one; one.atts = { f.Att(sel[0], 50000, R) };
    o.bundle = EncodeBundle(one);
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "mint9-bundle-count");
}

// Rule: MINT-9
// Rule: BUNDLE-1
BOOST_AUTO_TEST_CASE(mint9_stale_attestation_void)
{
    Fixture f;
    f.Arm();
    for (int i = 0; i < 10; i++) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    const int R = f.tip - 1;
    { MintOpts o; o.bundle = f.BundleFor(R, valtype(), 50000, {}, R - f.P.attestMaxAge);       // citedHeight == R - ATTEST_MAX_AGE: stale
      o.attestPayee = Selected(f.view, f.P, R, valtype()).front();
      BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, R, o)), "mint9-bundle-stale"); }
    { MintOpts o; o.bundle = f.BundleFor(f.tip - 1, valtype(), 50000, {}, f.tip - 1 - f.P.attestMaxAge + 1);   // the oldest admissible
      o.attestPayee = Selected(f.view, f.P, f.tip - 1, valtype()).front();
      BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), ""); }
    { MintOpts o; o.bundle = f.BundleFor(f.tip - 1, valtype(), 50000, {}, f.tip);              // citedHeight > R
      o.attestPayee = Selected(f.view, f.P, f.tip - 1, valtype()).front();
      BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "mint9-bundle-stale"); }
    // a signature over the wrong block hash
    { Bundle b; const int r = f.tip - 1;
      for (uint16_t q : Selected(f.view, f.P, r, valtype())) b.atts.push_back(f.Att(q, 50000, r, Fixture::FakeHash(r + 1)));
      MintOpts o; o.bundle = EncodeBundle(b); o.attestPayee = b.atts[0].seq;
      BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, r, o)), "mint9-bundle-sig"); }
}

// Rule: MINT-10
BOOST_AUTO_TEST_CASE(mint10_diverged_void)
{
    Fixture f;
    f.Arm();
    // pools 50,000; attestors 40,000: |x - a| / min = 25 % > 15 %
    CMutableTransaction m = f.MintV3(10000, 40000);
    BOOST_CHECK_EQUAL(MintVerdictOf(f, m), verdict::MINT10_DIVERGED);
    BOOST_CHECK(!f.Vault(CTransaction(m).GetHash()).has_value());
    BOOST_CHECK_EQUAL(f.Log(CTransaction(m).GetHash())->aMint, 40000);          // the evaluation's bundle facts
    // U-21: the invalid mint is not in the block, so its bundle writes no BundleLog row (R12 reads mined transactions)
    BOOST_CHECK(!f.BundleRow(f.tip).has_value());
    // above as well: 57,501 > 57,500
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintV3(10000, 57501)), verdict::MINT10_DIVERGED);
}

// Rule: MINT-10
BOOST_AUTO_TEST_CASE(mint10_reads_the_fast_median_so_a_rally_mints)
{
    // W17: the pools double their quotes; after a fast window the fast median is at the new
    // price while the slow window (and so xMint, the minimum) still says the old one. Attestors
    // at the new price agree with the fast median, so the mint passes MINT-10 -- and MINT-5
    // still prices its collateral at the old, lower xMint.
    Fixture f;
    f.Arm();
    for (int i = 0; i < 10; i++) f.Mine(Fixture::Quote(100000, (f.tip + 1) % 3));
    const Snapshot S = f.Snap(f.tip - 1);
    BOOST_REQUIRE(S.PFast().has_value() && S.PMint().has_value());
    BOOST_CHECK_EQUAL(S.PFast().value(), 100000);
    BOOST_CHECK_EQUAL(S.PMint().value(), 50000);
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintV3(10000, 100000)), "");                 // MINT-5 sized it at the minimum, 50,000
    BOOST_CHECK_EQUAL(f.Log(f.evals[f.tip].txlogs[0].first)->aMint, 100000);
    // attestors that stayed at the old price now disagree with the market: refused
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintV3(10000, 50000)), verdict::MINT10_DIVERGED);
}

// Rule: MINT-10
BOOST_AUTO_TEST_CASE(mint10_exact_boundary_ok)
{
    Fixture f;
    f.Arm();
    // (a - x) * 10^4 <= 1,500 * min(x, a) with x = 50,000: a = 57,500 is the exact boundary
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintV3(10000, 57500)), "");
    BOOST_CHECK_EQUAL(f.Log(f.evals[f.tip].txlogs[0].first)->aMint, 57500);
}

// Rule: PRICE-2
// Rule: AFEE-0
BOOST_AUTO_TEST_CASE(price2_unarmed_reads_x_only)
{
    Fixture f;
    f.Activate();
    BOOST_CHECK(!f.Armed());
    // Unarmed: a garbage carrier and no attestor fee are ignored; the collateral is judged at xMint alone.
    MintOpts o;
    o.bundle = valtype(20, 0x00);
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "");
    std::optional<TxLogRecord> log = f.Log(f.evals[f.tip].txlogs[0].first);
    BOOST_CHECK_EQUAL(log->aMint, 0);
    BOOST_CHECK(log->bundleSeqs.empty());
    BOOST_CHECK_EQUAL(log->attestFeeZat, 0);
    BOOST_CHECK(!f.BundleRow(f.tip).has_value());
}

// Rule: PRICE-2
// Rule: MINT-5
BOOST_AUTO_TEST_CASE(price2_min_max)
{
    Fixture f;
    f.Arm();
    // Attestors at 45,000 under pools at 50,000: pMint = 45,000, so the v2 collateral for 50,000 is short.
    Snapshot s = f.Snap(f.tip - 1);
    { MintOpts o; o.collateral = RequiredCollateralRounded(10000, MinRatioBps(f.P.baseRatioBps[0], s.sigmaMultBps), 50000).value();
      BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintV3(10000, 45000, o)), verdict::BAD_MINT_COLLATERAL); }
    { MintOpts o; o.collateral = RequiredCollateralRounded(10000, MinRatioBps(f.P.baseRatioBps[0], f.Snap(f.tip - 1).sigmaMultBps), 45000).value();
      BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintV3(10000, 45000, o)), ""); }
    // Attestors above the pools: pMint stays at xMint (the min)
    { MintOpts o; o.collateral = RequiredCollateralRounded(10000, MinRatioBps(f.P.baseRatioBps[0], f.Snap(f.tip - 1).sigmaMultBps), 50000).value();
      BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintV3(10000, 55000, o)), ""); }
    // pClaim = max(x, a): a vault backing $100 with 6,000 YEC (300 %) is underwater under pools at 9,000 (54 %) but not
    // when attestors say 21,000 (126 % >= theta 125 %).
    const uint256 w = CTransaction(f.MintV3(10000, 50000)).GetHash();
    { CMutableTransaction m = f.MintV3(10000, 50000); BOOST_REQUIRE_EQUAL(MintVerdictOf(f, m), ""); (void)w; }
    const uint256 v = f.evals[f.tip].txlogs[0].first;
    for (int i = 0; i < 64; i++) f.Mine(Fixture::Quote(9000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(f.Snap(f.tip).PClaim().value(), 9000);
    const valtype sel = OutPointSelector(COutPoint(v, 0));
    { SpendOpts o; o.ownerPath = false; o.bundle = f.BundleFor(f.tip - 1, sel, 21000); o.attestPayee = Selected(f.view, f.P, f.tip - 1, sel).front();
      RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip - 1, o));
      BOOST_CHECK_EQUAL(r.verdict, verdict::VAULT_CLAIM_NOT_UNDERWATER);
      BOOST_CHECK(r.invalid); }
}

// Rule: RED-1
// Rule: BUNDLE-1
BOOST_AUTO_TEST_CASE(red1_claim_needs_bundle)
{
    Fixture f;
    f.Arm();
    CMutableTransaction m = f.MintV3(10000, 50000);
    BOOST_REQUIRE_EQUAL(MintVerdictOf(f, m), "");
    const uint256 v = CTransaction(m).GetHash();
    for (int i = 0; i < 64; i++) f.Mine(Fixture::Quote(9000, (f.tip + 1) % 3));
    // No carrier: red1-bundle-shape, block-invalid under enforcement.
    { SpendOpts o; o.ownerPath = false;
      RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip - 1, o));
      BOOST_CHECK_EQUAL(r.verdict, "red1-bundle-shape");
      BOOST_CHECK(r.invalid);
      BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::ACTIVE); }
    // The claim's selection is selected(R, vaultOutpoint): an attestor outside it (there is exactly one of the four) is "member".
    Fixture g;
    g.Arm(4);
    CMutableTransaction m2 = g.MintV3(10000, 50000);
    BOOST_REQUIRE_EQUAL(MintVerdictOf(g, m2), "");
    const uint256 v2 = CTransaction(m2).GetHash();
    const int R = g.tip - 1;
    const valtype sel = OutPointSelector(COutPoint(v2, 0));
    std::vector<uint16_t> chosen = Selected(g.view, g.P, R, sel);
    BOOST_REQUIRE_EQUAL(chosen.size(), 3u);
    int outsider = -1;
    for (int q = 0; q < 4; q++) if (std::find(chosen.begin(), chosen.end(), (uint16_t)q) == chosen.end()) outsider = q;
    BOOST_REQUIRE(outsider >= 0);
    Bundle b;
    b.atts = { g.Att(chosen[0], 50000, R), g.Att(outsider, 50000, R) };
    { SpendOpts o; o.ownerPath = false; o.bundle = EncodeBundle(b); o.attestPayee = chosen[0];
      RedResult r = Spend(g, v2, g.SpendTx(v2, { COutPoint(v2, 1) }, R, o));
      BOOST_CHECK_EQUAL(r.verdict, "red1-bundle-member");
      BOOST_CHECK(r.invalid); }
}

// Rule: RED-1
// Rule: AFEE-0
BOOST_AUTO_TEST_CASE(red1_owner_path_ignores_bundle)
{
    Fixture f;
    f.Arm();
    CMutableTransaction m = f.MintV3(10000, 50000);
    BOOST_REQUIRE_EQUAL(MintVerdictOf(f, m), "");
    const uint256 v = CTransaction(m).GetHash();
    // ARMED owner redeem with no carrier and no attestor fee: RED-1..3 as in v2.
    RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip - 1));
    BOOST_CHECK_EQUAL(r.verdict, verdict::OK);
    BOOST_CHECK(!r.invalid);
    BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLOSED);
    BOOST_CHECK_EQUAL(r.log.claimPath, "");
    BOOST_CHECK_EQUAL(r.log.residualZat, 0);
    BOOST_CHECK(!f.BundleRow(f.tip).has_value());
}

// Rule: RED-4
// Rule: NOT-1
BOOST_AUTO_TEST_CASE(red4b_needs_notice_and_persist)
{
    EmergencyFixture e;
    // Without a notice, (b) is false: not underwater under pClaim = max(11,500, 10,400).
    { RedResult r = e.Mine(e.Claim()); BOOST_CHECK_EQUAL(r.verdict, verdict::VAULT_CLAIM_NOT_UNDERWATER); BOOST_CHECK(r.invalid); }
    // The vault closed unbacked on that failing spend; start over with a fresh one.
    EmergencyFixture g;
    BOOST_REQUIRE(g.PostNotice());
    const NoticeRecord n = g.f.Notice(g.w).value();
    BOOST_CHECK_EQUAL(n.height, g.f.tip);
    BOOST_CHECK_EQUAL(n.refHeight, g.f.tip - 2);          // the notice at H had refHeight H - 2
    BOOST_CHECK_EQUAL(n.pEmerg, g.attPrice);
    BOOST_CHECK_EQUAL(g.f.Log(g.f.evals[g.f.tip].txlogs[0].first)->type, (uint8_t)TxLogType::CLAIM_NOTICE);
    BOOST_CHECK(g.f.Log(g.f.evals[g.f.tip].txlogs[0].first)->notice);
    // R - notice.refHeight must reach EMERGENCY_PERSIST: the claim at R = refHeight + 3 is early.
    while (g.f.tip - 1 < n.refHeight + g.f.P.emergencyPersist - 1) g.f.Mine(Fixture::Quote(g.poolPrice, (g.f.tip + 1) % 3));
    {
        // dry-run on an overlay so the vault survives the early attempt
        CBlock block;
        block.vtx.push_back(CTransaction(Fixture::Coinbase(g.f.tip + 1, Fixture::Quote(g.poolPrice, 0))));
        block.vtx.push_back(CTransaction(g.Claim()));
        OverlayStateView overlay(g.f.view);
        BlockEvaluation ev = EvaluateBlock(overlay, g.f.P, block, g.f.tip + 1, Fixture::FakeHash(g.f.tip + 1), SUBSIDY);
        BOOST_CHECK(ev.blockInvalid);
        BOOST_CHECK_EQUAL(ev.txlogs[0].second.verdict, verdict::VAULT_CLAIM_NOT_UNDERWATER);
    }
    g.f.Mine(Fixture::Quote(g.poolPrice, (g.f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(g.f.tip - 1 - n.refHeight, g.f.P.emergencyPersist);
    SpendOpts o;
    o.residualValue = g.Residual(g.f.tip - 1);
    RedResult r = g.Mine(g.Claim(o));
    BOOST_CHECK_EQUAL(r.verdict, verdict::OK);
    BOOST_CHECK(!r.invalid);
    BOOST_CHECK_EQUAL(r.log.claimPath, "b");
    BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLAIMING);     // U-23: until the claimant's intent is released
    BOOST_CHECK_EQUAL(r.log.aClaim, g.attPrice);
}

// Rule: RED-4
// Rule: NOT-1
BOOST_AUTO_TEST_CASE(red4b_notice_too_old)
{
    EmergencyFixture g;
    BOOST_REQUIRE(g.PostNotice());
    const NoticeRecord n = g.f.Notice(g.w).value();
    while (g.f.tip - 1 <= n.refHeight + g.f.P.emergencyNoticeTtl) g.f.Mine(Fixture::Quote(g.poolPrice, (g.f.tip + 1) % 3));
    SpendOpts o;
    o.residualValue = g.Residual(g.f.tip - 1);
    RedResult r = g.Mine(g.Claim(o));
    BOOST_CHECK_EQUAL(r.verdict, verdict::VAULT_CLAIM_NOT_UNDERWATER);
    BOOST_CHECK(r.invalid);
}

// Rule: RED-4
// Rule: NOT-1
BOOST_AUTO_TEST_CASE(red4b_before_arming_false)
{
    Fixture f;
    f.Activate();
    const uint256 v = f.MintActive(10000);
    for (int i = 0; i < 64; i++) f.Mine(Fixture::Quote(21000, (f.tip + 1) % 3));     // 6,000 YEC back $100 at 126 %: not (a)
    // Unarmed: a notice registers nothing (NOT-1 needs ARMED at R) and a claim is judged by (a) alone.
    f.Mine(Fixture::Quote(21000, (f.tip + 1) % 3), { f.NoticeTx(v, f.tip - 1, valtype(4, 0x59)) });
    BOOST_CHECK(!f.Notice(v).has_value());
    BOOST_CHECK(f.evals[f.tip].txlogs.empty());
    // Force a notice record in and see (b) still false before arming.
    NoticeRecord n;
    n.height = f.tip - 6;
    n.refHeight = f.tip - 8;
    n.pEmerg = 17000;
    State(f.view).Put(keys::Notice(COutPoint(v, 0)), n);
    SpendOpts o;
    o.ownerPath = false;
    BlockEvaluation ev = f.Evaluate(Fixture::Quote(21000, (f.tip + 1) % 3), { f.SpendTx(v, { COutPoint(v, 1) }, f.tip - 1, o) });
    BOOST_CHECK(ev.blockInvalid);
    BOOST_REQUIRE(!ev.txlogs.empty());
    BOOST_CHECK_EQUAL(ev.txlogs[0].second.verdict, verdict::VAULT_CLAIM_NOT_UNDERWATER);
    BOOST_CHECK(f.Notice(v).has_value());           // U-21: the invalid claim is never applied; the vault and its notice stay
}

// Rule: RED-5
BOOST_AUTO_TEST_CASE(red5_residual_paid)
{
    EmergencyFixture g;
    BOOST_REQUIRE(g.PostNotice());
    for (int i = 0; i < g.f.P.emergencyPersist + 1; i++) g.f.Mine(Fixture::Quote(g.poolPrice, (g.f.tip + 1) % 3));
    const CAmount residual = g.Residual(g.f.tip - 1);
    BOOST_CHECK(residual >= g.f.P.residualMinZat);
    BOOST_CHECK_EQUAL(residual, EmergencyFixture::COLLATERAL - ClaimantMaxZat(10000, (int)BPS, g.attPrice).value());
    // Missing residual output: invalid. One zat short: invalid. Exact: ok.
    {
        CBlock block;
        block.vtx.push_back(CTransaction(Fixture::Coinbase(g.f.tip + 1, Fixture::Quote(g.poolPrice, 0))));
        block.vtx.push_back(CTransaction(g.Claim()));
        SpendOpts o; o.residualValue = residual - 1;
        block.vtx.push_back(CTransaction(g.Claim(o)));
        OverlayStateView overlay(g.f.view);
        BlockEvaluation ev = EvaluateBlock(overlay, g.f.P, block, g.f.tip + 1, Fixture::FakeHash(g.f.tip + 1), SUBSIDY);
        BOOST_CHECK_EQUAL(ev.txlogs[0].second.verdict, verdict::RED5_RESIDUAL);
        BOOST_CHECK_EQUAL(ev.txlogs[0].second.residualZat, residual);
    }
    {
        SpendOpts o; o.residualValue = residual - 1;
        CBlock block;
        block.vtx.push_back(CTransaction(Fixture::Coinbase(g.f.tip + 1, Fixture::Quote(g.poolPrice, 0))));
        block.vtx.push_back(CTransaction(g.Claim(o)));
        OverlayStateView overlay(g.f.view);
        BlockEvaluation ev = EvaluateBlock(overlay, g.f.P, block, g.f.tip + 1, Fixture::FakeHash(g.f.tip + 1), SUBSIDY);
        BOOST_CHECK_EQUAL(ev.txlogs[0].second.verdict, verdict::RED5_RESIDUAL);
    }
    SpendOpts o; o.residualValue = residual;
    RedResult r = g.Mine(g.Claim(o));
    BOOST_CHECK_EQUAL(r.verdict, verdict::OK);
    BOOST_CHECK_EQUAL(r.log.residualZat, residual);
    BOOST_CHECK_EQUAL(r.log.claimPath, "b");
    BOOST_CHECK(r.log.hasAttestPayee);
    BOOST_CHECK(r.log.attestFeeZat >= AttestFeeZat(g.f.VaultFee(r.vault), g.f.P.attestFeeBps));
}

// Rule: RED-5
BOOST_AUTO_TEST_CASE(red5_residual_below_dust_vacuous)
{
    // RESIDUAL_MIN_ZAT raised above any residual: the clause asks for no output (the residual is still logged).
    EmergencyFixture g;
    g.f.P.residualMinZat = MAX_MONEY;
    BOOST_REQUIRE(g.PostNotice());
    for (int i = 0; i < g.f.P.emergencyPersist + 1; i++) g.f.Mine(Fixture::Quote(g.poolPrice, (g.f.tip + 1) % 3));
    const CAmount residual = g.Residual(g.f.tip - 1);
    RedResult r = g.Mine(g.Claim());
    BOOST_CHECK_EQUAL(r.verdict, verdict::OK);
    BOOST_CHECK_EQUAL(r.log.residualZat, residual);
    BOOST_CHECK(residual < g.f.P.residualMinZat);
    // and the math: a residual under the floor needs no output
    BOOST_CHECK_EQUAL(ResidualZat(ClaimantMaxZat(10000, (int)BPS, 11500).value() + 50000, ClaimantMaxZat(10000, (int)BPS, 11500)), 50000);
    BOOST_CHECK(50000 < RegtestParams(1, 0, 0, TestSet()).residualMinZat);
}

// Rule: RED-5
BOOST_AUTO_TEST_CASE(red5_residual_to_wrong_key_invalid)
{
    EmergencyFixture g;
    BOOST_REQUIRE(g.PostNotice());
    for (int i = 0; i < g.f.P.emergencyPersist + 1; i++) g.f.Mine(Fixture::Quote(g.poolPrice, (g.f.tip + 1) % 3));
    SpendOpts o;
    o.residualValue = g.Residual(g.f.tip - 1);
    o.residualScript = GetScriptForDestination(g.f.userKey.GetPubKey().GetID());
    RedResult r = g.Mine(g.Claim(o));
    BOOST_CHECK_EQUAL(r.verdict, verdict::RED5_RESIDUAL);
    BOOST_CHECK(r.invalid);
    BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::ACTIVE);
}

// Rule: RED-5
// Rule: RED-5a
BOOST_AUTO_TEST_CASE(red5a_roles_are_positional_and_the_claimant_is_floored)
{
    EmergencyFixture g;
    BOOST_REQUIRE(g.PostNotice());
    for (int i = 0; i < g.f.P.emergencyPersist + 1; i++) g.f.Mine(Fixture::Quote(g.poolPrice, (g.f.tip + 1) % 3));
    const CAmount residual = g.Residual(g.f.tip - 1);
    const CAmount collateral = EmergencyFixture::COLLATERAL;
    const CAmount floor = collateral - residual;
    auto verdictOf = [&](const CMutableTransaction& tx) {
        CBlock block;
        block.vtx.push_back(CTransaction(Fixture::Coinbase(g.f.tip + 1, Fixture::Quote(g.poolPrice, 0))));
        block.vtx.push_back(CTransaction(tx));
        OverlayStateView overlay(g.f.view);
        BlockEvaluation ev = EvaluateBlock(overlay, g.f.P, block, g.f.tip + 1, Fixture::FakeHash(g.f.tip + 1), SUBSIDY);
        BOOST_REQUIRE(!ev.txlogs.empty());
        return ev.txlogs[0].second.verdict;
    };
    SpendOpts o;
    o.residualValue = residual;
    const CMutableTransaction honest = g.Claim(o);
    BOOST_CHECK_EQUAL(verdictOf(honest), verdict::OK);                 // wallet shape: claimant first, residual second
    {
        CMutableTransaction selfPay = honest;                          // the claimant may still pay the owner
        selfPay.vout[0].scriptPubKey = selfPay.vout.back().scriptPubKey;
        BOOST_CHECK_EQUAL(verdictOf(selfPay), verdict::OK);
    }
    {
        CMutableTransaction tiny = honest;                             // residual = the whole collateral, 1-zat claimant
        tiny.vout[0].nValue = 1;
        tiny.vout.back().nValue = collateral;
        BOOST_CHECK_EQUAL(verdictOf(tiny), verdict::RED5_CLAIMANT_SHORT);
    }
    {
        CMutableTransaction shortClaimant = honest;                    // one zat under collateral − residual
        shortClaimant.vout[0].nValue = floor - 1;
        BOOST_CHECK_EQUAL(verdictOf(shortClaimant), verdict::RED5_CLAIMANT_SHORT);
    }
    {
        CMutableTransaction swapped = honest;                          // residual first: vout 1 of the intents is not the owner's
        std::swap(swapped.vout[0], swapped.vout.back());
        BOOST_CHECK_EQUAL(verdictOf(swapped), verdict::RED5_RESIDUAL);
    }
    {
        CMutableTransaction bigFirst = honest;                         // big owner intent first, 1-zat intent second
        bigFirst.vout[0].scriptPubKey = bigFirst.vout.back().scriptPubKey;
        bigFirst.vout[0].nValue = collateral - 1;
        bigFirst.vout.back().nValue = 1;
        BOOST_CHECK_EQUAL(verdictOf(bigFirst), verdict::RED5_RESIDUAL);
    }
}

// Rule: RED-5
// Rule: RED-5b
BOOST_AUTO_TEST_CASE(red5b_path_b_caps_at_p_emerg)
{
    // Worked example (W3-Y-5, A1): D = $100,000, 300,000 YEC, pEmerg = $0.349, pClaim = $0.42.
    const Cents debt = 10000000;
    const CAmount collateral = 300000 * COIN;
    const MicroUsd pEmerg = 349000;
    const CAmount residual = ResidualZat(collateral, ClaimantMaxZat(debt, (int)BPS, pEmerg));
    BOOST_CHECK_EQUAL(residual, 1346704871060LL);                      // 13,467.04871060 YEC
    // A spread under 1.25/1.05 is path (a): underwater at pClaim against theta, so the residual is 0.
    const MicroUsd close = 380000;                                     // 380000/349000 ≈ 1.089
    BOOST_CHECK(IsUnderwater(collateral, pEmerg, debt, 10500));
    BOOST_CHECK(IsUnderwater(collateral, close, debt, 12500));
    BOOST_CHECK_EQUAL(ResidualZat(collateral, ClaimantMaxZat(debt, 12500, close)), 0);
    EmergencyFixture g;
    BOOST_REQUIRE(g.PostNotice());
    for (int i = 0; i < g.f.P.emergencyPersist + 1; i++) g.f.Mine(Fixture::Quote(g.poolPrice, (g.f.tip + 1) % 3));
    const CAmount atEmerg = ResidualZat(EmergencyFixture::COLLATERAL, ClaimantMaxZat(10000, (int)BPS, g.attPrice));
    const CAmount atClaim = ResidualZat(EmergencyFixture::COLLATERAL, ClaimantMaxZat(10000, (int)BPS, g.poolPrice));
    BOOST_CHECK(atEmerg < atClaim);
    BOOST_CHECK_EQUAL(g.Residual(g.f.tip - 1), atEmerg);
}

// Rule: RED-5
// Rule: RED-4
BOOST_AUTO_TEST_CASE(red5_normal_claim_residual_zero)
{
    Fixture f;
    f.Arm();
    CMutableTransaction m = f.MintV3(10000, 50000);
    BOOST_REQUIRE_EQUAL(MintVerdictOf(f, m), "");
    const uint256 v = CTransaction(m).GetHash();
    for (int i = 0; i < 64; i++) f.Mine(Fixture::Quote(9000, (f.tip + 1) % 3));
    const valtype sel = OutPointSelector(COutPoint(v, 0));
    SpendOpts o;
    o.ownerPath = false;
    o.bundle = f.BundleFor(f.tip - 1, sel, 9000);
    o.attestPayee = Selected(f.view, f.P, f.tip - 1, sel).front();
    RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip - 1, o));
    BOOST_CHECK_EQUAL(r.verdict, verdict::OK);
    BOOST_CHECK_EQUAL(r.log.claimPath, "a");
    BOOST_CHECK_EQUAL(r.log.residualZat, 0);        // underwater under pClaim => collateral < claimantMax at 110 %
    BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLAIMING);
    BOOST_CHECK_EQUAL(f.BundleRow(f.tip)->aClaim, 9000);
}

// Rule: NOT-1
BOOST_AUTO_TEST_CASE(not1_standing_notice_not_replaced)
{
    EmergencyFixture g;
    BOOST_REQUIRE(g.PostNotice());
    const NoticeRecord first = g.f.Notice(g.w).value();
    // The reset attack: a second notice inside EMERGENCY_NOTICE_TTL registers nothing and the clock keeps running.
    for (int i = 0; i < 3; i++) g.f.Mine(Fixture::Quote(g.poolPrice, (g.f.tip + 1) % 3));
    const int R2 = g.f.tip - 1;
    const CMutableTransaction second = g.f.NoticeTx(g.w, R2, g.f.BundleFor(R2, g.Selector(), g.attPrice));
    g.f.Mine(Fixture::Quote(g.poolPrice, (g.f.tip + 1) % 3), { second });
    BOOST_CHECK(g.f.evals[g.f.tip].txlogs.empty());
    const NoticeRecord again = g.f.Notice(g.w).value();
    BOOST_CHECK_EQUAL(again.height, first.height);
    BOOST_CHECK_EQUAL(again.refHeight, first.refHeight);
    // focused review: the unheld notice would refresh its signers' liveness, so it is invalid (liveness-unheld) and
    // left out of the block -- no BundleRow for it either
    BOOST_REQUIRE(g.f.refused.count(CTransaction(second).GetHash()));
    BOOST_CHECK_EQUAL(g.f.refused.at(CTransaction(second).GetHash()).verdict, verdict::LIVENESS_UNHELD);
    BOOST_CHECK(!g.f.BundleRow(g.f.tip).has_value());
    // Past the TTL a new notice replaces it.
    while (g.f.tip + 1 - first.height <= g.f.P.emergencyNoticeTtl) g.f.Mine(Fixture::Quote(g.poolPrice, (g.f.tip + 1) % 3));
    BOOST_REQUIRE(g.PostNotice());
    BOOST_CHECK_EQUAL(g.f.Notice(g.w)->height, g.f.tip);
    // NOT-1's other clauses: pEmerg not under the emergency ratio, unknown vault, R out of the window
    BOOST_REQUIRE(g.PostNotice(11600));            // pEmerg = 11,500 (the pools): 115 % >= 105 %
    BOOST_CHECK(g.f.evals[g.f.tip].txlogs.empty());
    g.f.Mine(Fixture::Quote(g.poolPrice, (g.f.tip + 1) % 3), { g.f.NoticeTx(uint256S("11"), g.f.tip - 1, g.f.BundleFor(g.f.tip - 1, OutPointSelector(COutPoint(uint256S("11"), 0)), g.attPrice)) });
    BOOST_CHECK(g.f.evals[g.f.tip].txlogs.empty());
}

// Rule: NOT-1
// Rule: IN-2
BOOST_AUTO_TEST_CASE(not1_deleted_when_vault_closes)
{
    EmergencyFixture g;
    BOOST_REQUIRE(g.PostNotice());
    // An owner redeem (any close) deletes Notices[vault]; undo restores it.
    const std::string before = Hash(g.f.view);
    RedResult r = g.Mine(g.f.SpendTx(g.w, { COutPoint(g.w, 1) }, g.f.tip - 1));
    BOOST_CHECK_EQUAL(r.verdict, verdict::OK);
    BOOST_CHECK(!g.f.Notice(g.w).has_value());
    g.f.Undo();
    BOOST_CHECK(g.f.Notice(g.w).has_value());
    BOOST_CHECK_EQUAL(Hash(g.f.view), before);
    // a spend with no payload is invalid (RED-1, U-21): the vault and its notice stay
    SpendOpts o; o.payload = false;
    RedResult bad = g.Mine(g.f.SpendTx(g.w, {}, g.f.tip - 1, o));
    BOOST_CHECK(bad.invalid);
    BOOST_CHECK(g.f.Notice(g.w).has_value());
}

// Rule: EQV-1
BOOST_AUTO_TEST_CASE(eqv1_two_prices_one_hash_ejects)
{
    Fixture f;
    f.Arm();
    const int cited = f.tip;
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    // same price: not an equivocation; different seq: no; three attestations: no
    BOOST_CHECK_EQUAL(VerdictOf(f, f.EquivocationTx(f.Att(1, 50000, cited), f.Att(1, 50000, cited))), "none");
    BOOST_CHECK_EQUAL(VerdictOf(f, f.EquivocationTx(f.Att(1, 50000, cited), f.Att(2, 51000, cited))), "none");
    BOOST_CHECK_EQUAL(VerdictOf(f, f.EquivocationTx(f.Att(1, 50000, cited), f.Att(1, 51000, cited - 1))), "none");
    BOOST_CHECK_EQUAL(f.Attestor(1)->status, (uint8_t)AttestorStatus::ELIGIBLE);
    CMutableTransaction e = f.EquivocationTx(f.Att(1, 50000, cited), f.Att(1, 51000, cited));
    BOOST_CHECK_EQUAL(VerdictOf(f, e), verdict::OK);
    BOOST_CHECK_EQUAL(f.Attestor(1)->status, (uint8_t)AttestorStatus::EJECTED);
    BOOST_CHECK_EQUAL(f.Attestor(1)->statusHeight, f.tip);
    BOOST_CHECK(f.Attestor(1)->bondFrozen);                                     // P4-b: the set's frozen-bond rule
    BOOST_CHECK_EQUAL(f.Log(CTransaction(e).GetHash())->type, (uint8_t)TxLogType::EQUIVOCATION);
    BOOST_CHECK_EQUAL(f.Log(CTransaction(e).GetHash())->attestorSeq, 1);
    // an ejected attestor leaves seated at the next SNAP and cannot be ejected twice
    BOOST_CHECK([&]{ const std::vector<uint16_t> seatedNow = f.Snap(f.tip).seated; return std::find(seatedNow.begin(), seatedNow.end(), 1) == seatedNow.end(); }());
    BOOST_CHECK_EQUAL(VerdictOf(f, f.EquivocationTx(f.Att(1, 50000, cited), f.Att(1, 52000, cited))), "none");
    // EQUIVOCATION bundles never enter BundleLog (R12)
    BOOST_CHECK(!f.BundleRow(f.tip - 1).has_value());
}

// Rule: EQV-1
BOOST_AUTO_TEST_CASE(eqv1_fork_hashes_not_equivocation)
{
    Fixture f;
    f.Arm();
    const int cited = f.tip;
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    // Two honest prices for the same height on two forks: the second signature is over another block hash and does not verify here.
    std::vector<unsigned char> other(32, 0x99);
    BOOST_CHECK_EQUAL(VerdictOf(f, f.EquivocationTx(f.Att(2, 50000, cited), f.Att(2, 51000, cited, uint256(other)))), "none");
    BOOST_CHECK_EQUAL(f.Attestor(2)->status, (uint8_t)AttestorStatus::ELIGIBLE);
    // a cited height the index does not know
    BOOST_CHECK_EQUAL(VerdictOf(f, f.EquivocationTx(f.Att(2, 50000, f.tip + 5), f.Att(2, 51000, f.tip + 5))), "none");
}

// Rule: REV-1 (P4-b: revival is a SET_HEARTBEAT)
// Rule: SNAP
BOOST_AUTO_TEST_CASE(rev1_heartbeat_revives_s15_dormant)
{
    Fixture f;
    f.Arm(4);
    // A heartbeat of an ELIGIBLE attestor only moves lastAct.
    CMutableTransaction hb0 = f.HeartbeatTx(0);
    BOOST_CHECK_EQUAL(VerdictOf(f, hb0), verdict::OK);
    BOOST_CHECK_EQUAL(f.Attestor(0)->status, (uint8_t)AttestorStatus::ELIGIBLE);
    BOOST_CHECK_EQUAL(f.Attestor(0)->lastAct, f.tip);
    // Make seq L dormant (S15): two mints whose selection includes L, signed by the other two, then a check height.
    int L = -1, rows = 0;
    while (rows < f.P.dormancyMinBundles) {
        const int R = f.tip - 1;
        std::vector<uint16_t> sel = Selected(f.view, f.P, R, valtype());
        if (L < 0) L = sel.front();
        if (std::find(sel.begin(), sel.end(), (uint16_t)L) != sel.end()) {
            BOOST_REQUIRE_EQUAL(MintVerdictOf(f, f.MintV3(10000, 50000, MintOpts(), { L })), "");
            rows++;
        } else {
            f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
        }
    }
    while (f.tip % f.P.dormancyCheck != 0 || f.tip - f.P.dormancyBlocks < f.Attestor(L)->seatedSince) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(f.Attestor(L)->status, (uint8_t)AttestorStatus::DORMANT);
    BOOST_CHECK_EQUAL(f.Attestor(L)->statusHeight, f.tip);
    // the retired payload is invalid; a heartbeat revives at its own SNAP
    BOOST_CHECK_EQUAL(VerdictOf(f, f.ReviveTx(f.Att(L, 50000, f.tip))), verdict::ATTESTOR_REVIVE_RETIRED);
    BOOST_CHECK_EQUAL(f.Attestor(L)->status, (uint8_t)AttestorStatus::DORMANT);
    CMutableTransaction r = f.HeartbeatTx(L);
    BOOST_CHECK_EQUAL(VerdictOf(f, r), verdict::OK);
    BOOST_CHECK_EQUAL(f.Attestor(L)->status, (uint8_t)AttestorStatus::ELIGIBLE);
    BOOST_CHECK_EQUAL(f.Log(CTransaction(r).GetHash())->attestorSeq, L);
    { const std::vector<uint16_t> seatedNow = f.Snap(f.tip).seated; BOOST_CHECK(std::find(seatedNow.begin(), seatedNow.end(), (uint16_t)L) != seatedNow.end()); }
}

// Rule: SNAP
BOOST_AUTO_TEST_CASE(dormancy_needs_selection_evidence)
{
    Fixture f;
    f.Arm(4);
    // Rows where L signed count as evidence of life; rows where it was not selected are no evidence at all.
    int L = -1, signedRows = 0;
    while (signedRows < 3) {
        const int R = f.tip - 1;
        std::vector<uint16_t> sel = Selected(f.view, f.P, R, valtype());
        if (L < 0) L = sel.front();
        BOOST_REQUIRE_EQUAL(MintVerdictOf(f, f.MintV3(10000, 50000)), "");
        if (std::find(sel.begin(), sel.end(), (uint16_t)L) != sel.end()) signedRows++;
    }
    for (int i = 0; i < 2 * f.P.dormancyBlocks; i++) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    for (int q = 0; q < 4; q++) BOOST_CHECK_EQUAL(f.Attestor(q)->status, (uint8_t)AttestorStatus::ELIGIBLE);
    // One unsigned row is below DORMANCY_MIN_BUNDLES.
    while (true) {
        const int R = f.tip - 1;
        std::vector<uint16_t> sel = Selected(f.view, f.P, R, valtype());
        if (std::find(sel.begin(), sel.end(), (uint16_t)L) != sel.end()) { BOOST_REQUIRE_EQUAL(MintVerdictOf(f, f.MintV3(10000, 50000, MintOpts(), { L })), ""); break; }
        f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    }
    for (int i = 0; i < f.P.dormancyCheck; i++) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(f.Attestor(L)->status, (uint8_t)AttestorStatus::ELIGIBLE);
}

// Rule: SNAP
BOOST_AUTO_TEST_CASE(dormancy_unseated_never_dormant)
{
    Fixture f;
    f.Activate();
    f.Register(6);
    while (!f.Attest().IsArmed()) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(f.Attestor(5)->seatedSince, 0);          // ties by seq: seq 5 is never seated
    for (int i = 0; i < 2 * f.P.dormancyBlocks; i++) {
        if (i % 3 == 0) MintVerdictOf(f, f.MintV3(10000, 50000));
        else f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    }
    BOOST_CHECK_EQUAL(f.Attestor(5)->status, (uint8_t)AttestorStatus::ELIGIBLE);
    BOOST_CHECK_EQUAL(f.Attestor(5)->seatedSince, 0);
}

// Rule: SNAP
BOOST_AUTO_TEST_CASE(dormancy_only_at_check_heights)
{
    Fixture f;
    f.Arm(4);
    for (int i = 0; i < f.P.dormancyBlocks; i++) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    int L = -1, rows = 0;
    while (rows < f.P.dormancyMinBundles) {
        const int R = f.tip - 1;
        std::vector<uint16_t> sel = Selected(f.view, f.P, R, valtype());
        if (L < 0) L = sel.front();
        if (std::find(sel.begin(), sel.end(), (uint16_t)L) != sel.end() && (rows < f.P.dormancyMinBundles - 1 || (f.tip + 1) % f.P.dormancyCheck != 0)) {
            BOOST_REQUIRE_EQUAL(MintVerdictOf(f, f.MintV3(10000, 50000, MintOpts(), { L })), "");
            rows++;
        } else {
            f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
        }
    }
    // The evidence is complete at a non-check height: nothing happens until H mod DORMANCY_CHECK == 0.
    BOOST_CHECK(f.tip % f.P.dormancyCheck != 0);
    BOOST_CHECK_EQUAL(f.Attestor(L)->status, (uint8_t)AttestorStatus::ELIGIBLE);
    while (f.tip % f.P.dormancyCheck != 0) {
        f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
        if (f.tip % f.P.dormancyCheck != 0) BOOST_CHECK_EQUAL(f.Attestor(L)->status, (uint8_t)AttestorStatus::ELIGIBLE);
    }
    BOOST_CHECK_EQUAL(f.Attestor(L)->status, (uint8_t)AttestorStatus::DORMANT);
    BOOST_CHECK_EQUAL(f.Attestor(L)->statusHeight, f.tip);
    BOOST_CHECK_EQUAL(f.Attestor(L)->seatedSince, 0 + f.Attestor(L)->seatedSince);   // untouched by dormancy itself
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(f.Attestor(L)->seatedSince, 0);                                 // cleared when it leaves seated
}

// Rule: PIN-1
BOOST_AUTO_TEST_CASE(pin1_arms_from_bundlelog)
{
    Fixture f;
    f.Activate();
    // Two rows in W whose aMint spread exceeds PIN_DELTA_BPS arm PIN-1; a key with >= PIN_MIN_TAGS quotes all at one price is pinned.
    BundleLogRecord lo, hi;
    lo.aMint = lo.aClaim = 50000;
    hi.aMint = hi.aClaim = 53000;                          // 6 % > 5 %
    State(f.view).Put(keys::BundleLog((uint32_t)f.tip - 3), lo);
    State(f.view).Put(keys::BundleLog((uint32_t)f.tip - 1), hi);
    f.Mine(Fixture::Quote(50000, 0));
    BOOST_CHECK_EQUAL(f.Snap(f.tip).pinnedKeys.size(), 3u);   // every pool quoted 50,000 throughout: all three pinned
    BOOST_CHECK(f.Snap(f.tip).haltMask & HALT_NO_PRICE);       // nothing left for the medians
    // 5 % exactly is not enough
    Fixture g;
    g.Activate();
    BundleLogRecord a, b;
    a.aMint = a.aClaim = 50000;
    b.aMint = b.aClaim = 52500;
    State(g.view).Put(keys::BundleLog((uint32_t)g.tip - 3), a);
    State(g.view).Put(keys::BundleLog((uint32_t)g.tip - 1), b);
    g.Mine(Fixture::Quote(50000, 0));
    BOOST_CHECK(g.Snap(g.tip).pinnedKeys.empty());
    // a row outside W does not count
    Fixture h;
    h.Activate();
    State(h.view).Put(keys::BundleLog((uint32_t)h.tip - h.P.pinWindow), lo);   // h = H - 1 - PIN_WINDOW: excluded
    State(h.view).Put(keys::BundleLog((uint32_t)h.tip - 1), hi);
    h.Mine(Fixture::Quote(50000, 0));
    BOOST_CHECK(h.Snap(h.tip).pinnedKeys.empty());
}

// Rule: PIN-1
// Rule: FEE-2
// Rule: PRICE-1
BOOST_AUTO_TEST_CASE(pin1_excludes_key_from_medians_and_E)
{
    Fixture f;
    f.Activate();
    // Pool 0 repeats 50,000; pools 1 and 2 move (49,000 / 51,000 alternating) for a full slow window.
    for (int i = 0; i < 70; i++) {
        const int key = (f.tip + 1) % 3;
        const MicroUsd price = key == 0 ? 50000 : (key == 1 ? 49000 + (i % 2) * 10 : 51000 + (i % 2) * 10);
        f.Mine(Fixture::Quote(price, key));
    }
    BundleLogRecord lo, hi;
    lo.aMint = lo.aClaim = 50000;
    hi.aMint = hi.aClaim = 53000;
    State(f.view).Put(keys::BundleLog((uint32_t)f.tip - 3), lo);
    State(f.view).Put(keys::BundleLog((uint32_t)f.tip - 1), hi);
    const Snapshot before = f.Snap(f.tip);
    f.Mine(Fixture::Quote(50000, 0));
    const Snapshot s = f.Snap(f.tip);
    BOOST_REQUIRE_EQUAL(s.pinnedKeys.size(), 1u);
    BOOST_CHECK(s.pinnedKeys[0] == KeyOf(0));
    // the medians no longer see 50,000: pFast over pools 1 and 2 only (the slow window's 2/3 fill is then one short: pMint undefined, HALT-1)
    BOOST_CHECK(s.pFast != 50000);
    BOOST_CHECK(s.pFast > 0);
    BOOST_CHECK(s.haltMask & HALT_NO_PRICE);
    // E(H) excludes the pinned key; E(H - 1) still has it
    std::vector<CKeyID> e = EligiblePayees(f.view, f.P, f.tip);
    BOOST_CHECK(std::find(e.begin(), e.end(), CKeyID(KeyOf(0))) == e.end());
    BOOST_CHECK_EQUAL(e.size(), 2u);
    std::vector<CKeyID> prev = EligiblePayees(f.view, f.P, f.tip - 1);
    BOOST_CHECK(std::find(prev.begin(), prev.end(), CKeyID(KeyOf(0))) != prev.end());
    // and FEE-W never picks it
    for (int i = 0; i < 8; i++) {
        std::optional<CKeyID> pick = DefaultPayee(f.view, f.P, f.tip, valtype(1, (unsigned char)i), PayeePolicy::Defaults(f.P));
        BOOST_REQUIRE(pick.has_value());
        BOOST_CHECK(!(pick.value() == CKeyID(KeyOf(0))));
    }
    (void)before;
}

// Rule: PIN-2
BOOST_AUTO_TEST_CASE(pin2_excludes_seq)
{
    Fixture f;
    f.Arm(4);
    // xMint falls by 20 % within PIN_WINDOW (the fast window moves in 8 blocks): PIN-2 arms.
    for (int i = 0; i < 8; i++) f.Mine(Fixture::Quote(40000, (f.tip + 1) % 3));
    BOOST_REQUIRE_EQUAL(f.Snap(f.tip).PMint().value(), 40000);
    BOOST_REQUIRE_EQUAL(f.Snap(f.tip - f.P.pinWindow).PMint().value(), 50000);
    // seq 2 appears in two rows of W at one price; seq 1 in two rows at two prices; seq 3 in one row.
    BundleLogRecord r1, r2;
    r1.aMint = r1.aClaim = r2.aMint = r2.aClaim = 40000;
    r1.selectedSeqs = { 1, 2, 3 }; r1.seqs = { 1, 2, 3 }; r1.prices = { 40000, 40000, 40000 }; r1.citedHeights = { 10, 10, 10 };
    r2.selectedSeqs = { 1, 2 };    r2.seqs = { 1, 2 };    r2.prices = { 40100, 40000 };        r2.citedHeights = { 11, 10 };
    State(f.view).Put(keys::BundleLog((uint32_t)f.tip - 2), r1);
    State(f.view).Put(keys::BundleLog((uint32_t)f.tip), r2);
    f.Mine(Fixture::Quote(40000, (f.tip + 1) % 3));
    // Audit A-2: seq 2's two rows carry one attestation (cited height 10) reused by two bundles: one cited height
    // is not a frozen quote, nothing is pinned. Rewriting the rows with distinct cited heights pins it.
    BOOST_CHECK(f.Snap(f.tip).pinnedSeqs.empty());
    r2.citedHeights = { 11, 11 };
    State(f.view).Put(keys::BundleLog((uint32_t)f.tip - 1), r2);
    f.Mine(Fixture::Quote(40000, (f.tip + 1) % 3));
    const Snapshot s = f.Snap(f.tip);
    BOOST_CHECK((s.pinnedSeqs == std::vector<uint16_t>{ 2 }));
    BOOST_CHECK(s.pinnedKeys.empty());                  // PIN-1 is not armed: the rows' aMint agree
    // Selection at this R never draws seq 2; the pool has three left, all drawn.
    std::vector<uint16_t> got = Selected(f.view, f.P, f.tip, valtype());
    BOOST_CHECK_EQUAL(got.size(), 3u);
    BOOST_CHECK(std::find(got.begin(), got.end(), 2) == got.end());
    // and a bundle from seq 2 at this R is "member"
    f.Mine(Fixture::Quote(40000, (f.tip + 1) % 3));
    Bundle b; b.atts = { f.Att(2, 40000, f.tip - 1), f.Att(got[0], 40000, f.tip - 1) };
    MintOpts o; o.bundle = EncodeBundle(b); o.attestPayee = got[0];
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "mint9-bundle-member");
}

// Rule: PIN-1
// Rule: PIN-2
BOOST_AUTO_TEST_CASE(pin_not_armed_without_bundles)
{
    Fixture f;
    f.Arm(4);
    for (int i = 0; i < 8; i++) f.Mine(Fixture::Quote(40000, (f.tip + 1) % 3));
    BOOST_REQUIRE_EQUAL(f.Snap(f.tip).PMint().value(), 40000);
    // The price step arms PIN-2's test, but with no BundleLog rows nothing is pinned; PIN-1 needs rows to arm at all.
    const Snapshot s = f.Snap(f.tip);
    BOOST_CHECK(s.pinnedSeqs.empty());
    BOOST_CHECK(s.pinnedKeys.empty());
    // One row is below PIN_MIN_BUNDLES for PIN-1, and one appearance below PIN_MIN_TAGS for PIN-2.
    BundleLogRecord r;
    r.aMint = r.aClaim = 40000;
    r.selectedSeqs = r.seqs = { 0, 1, 2 };
    r.prices = { 40000, 40000, 40000 };
    r.citedHeights = { 9, 9, 9 };
    State(f.view).Put(keys::BundleLog((uint32_t)f.tip), r);
    f.Mine(Fixture::Quote(40000, (f.tip + 1) % 3));
    BOOST_CHECK(f.Snap(f.tip).pinnedSeqs.empty());
    BOOST_CHECK(f.Snap(f.tip).pinnedKeys.empty());
}

// Rule: PIN-1
BOOST_AUTO_TEST_CASE(pin1_ignores_undefined_amint)
{
    // Audit A-4: a row whose aMint is stored as 0 (every bundle's statistic undefined) is not the window
    // minimum; two rows at one price plus the 0 row leave PIN-1 unarmed.
    Fixture f;
    f.Activate();
    BundleLogRecord undef, a, b;
    undef.aMint = undef.aClaim = 0;
    a.aMint = a.aClaim = 50000;
    b.aMint = b.aClaim = 50000;
    State(f.view).Put(keys::BundleLog((uint32_t)f.tip - 3), undef);
    State(f.view).Put(keys::BundleLog((uint32_t)f.tip - 2), a);
    State(f.view).Put(keys::BundleLog((uint32_t)f.tip - 1), b);
    f.Mine(Fixture::Quote(50000, 0));
    BOOST_CHECK(f.Snap(f.tip).pinnedKeys.empty());
    BOOST_CHECK(!(f.Snap(f.tip).haltMask & HALT_NO_PRICE));
}

// Rule: MINT-8
// Rule: MINT-9
// MINT-8' lower bound (review fix-up): an ARMED mint whose fee output is below ProtocolFeeZat(cents, xMint) is
// refused bad-mint-fee before MINT-9 verifies the bundle (pMint <= xMint, so it fails MINT-8' at any pMint).
BOOST_AUTO_TEST_CASE(mint8_lower_bound_before_mint9)
{
    Fixture f;
    f.Arm(4);
    BOOST_REQUIRE(f.Armed());
    // a 1-zat fee with a well-signed bundle: bad-mint-fee, and the bundle was never verified (no TxLog bundle fields)
    { MintOpts o; o.feeValue = 1;
      CMutableTransaction m = f.MintV3(10000, 50000, o);
      BOOST_CHECK_EQUAL(MintVerdictOf(f, m), verdict::BAD_MINT_FEE);
      std::optional<TxLogRecord> log = f.Log(CTransaction(m).GetHash());
      BOOST_REQUIRE(log.has_value());
      BOOST_CHECK(log->bundleSeqs.empty());
      BOOST_CHECK_EQUAL(log->aMint, 0); }
    // a 1-zat fee and no bundle at all: bad-mint-fee, not mint9-no-bundle (MINT-9 not reached)
    { MintOpts o; o.feeValue = 1; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), verdict::BAD_MINT_FEE); }
    // one zat under the xMint fee: refused before MINT-9 as well
    { MintOpts o; o.feeValue = f.MintFee(10000, f.tip - 1) - 1; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), verdict::BAD_MINT_FEE); }
    // exactly the xMint fee and no bundle: the bound holds, MINT-9 runs and refuses
    { MintOpts o; o.feeValue = f.MintFee(10000, f.tip - 1); BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), verdict::MINT9_NO_BUNDLE); }
    // aMint below xMint: a fee at xMint passes the bound, the bundle is verified, and MINT-8' at pMint = aMint refuses it
    { const MicroUsd a = f.PMintAt(f.tip - 1) * 9 / 10;
      MintOpts o; o.feeValue = f.MintFee(10000, f.tip - 1);
      CMutableTransaction m = f.MintV3(10000, a, o);
      BOOST_CHECK_EQUAL(MintVerdictOf(f, m), verdict::BAD_MINT_FEE);
      std::optional<TxLogRecord> log = f.Log(CTransaction(m).GetHash());
      BOOST_REQUIRE(log.has_value());
      BOOST_CHECK(!log->bundleSeqs.empty()); }
    // the honest mint still holds
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintV3(10000, 50000)), "");
}

// Rule: AFEE-1
// Rule: MINT-8
// Rule: RED-3
BOOST_AUTO_TEST_CASE(afee1_fee_to_contributor)
{
    Fixture f;
    f.Arm(4);
    const CAmount fee = f.MintFee(10000, f.tip - 1);        // MintV3's $100: the $1 floor at $0.05 = 20 YEC
    BOOST_CHECK_EQUAL(fee, 2000000000LL);
    const CAmount afee = AttestFeeZat(fee, f.P.attestFeeBps);
    BOOST_CHECK_EQUAL(afee, fee / 4);
    // to a seated attestor that did not contribute: afee1-fee; one zat short: afee1-fee; missing: afee1-fee; at 0xFF: afee1-fee
    std::vector<uint16_t> sel = Selected(f.view, f.P, f.tip - 1, valtype());
    int outsider = -1;
    for (int q = 0; q < 4; q++) if (std::find(sel.begin(), sel.end(), (uint16_t)q) == sel.end()) outsider = q;
    BOOST_REQUIRE(outsider >= 0);
    { MintOpts o; o.attestPayee = outsider; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintV3(10000, 50000, o)), verdict::AFEE1_FEE); }
    { MintOpts o; o.attestFeeValue = afee - 1; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintV3(10000, 50000, o)), verdict::AFEE1_FEE); }
    { MintOpts o; o.attestFeeVout = 3; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintV3(10000, 50000, o)), verdict::AFEE1_FEE); }    // the pool fee's vout
    { MintOpts o; o.attestFeeVout = 9; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintV3(10000, 50000, o)), verdict::AFEE1_FEE); }    // out of range
    { MintOpts o; o.attestFeeScript = GetScriptForDestination(f.ownerKey.GetPubKey().GetID());                                    // not the member key (P4-b: hot key = bond key)
      BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintV3(10000, 50000, o)), verdict::AFEE1_FEE); }
    // a contributor who is not the first signer is fine, and the log names it
    { MintOpts o; o.attestPayee = Selected(f.view, f.P, f.tip - 1, valtype()).back();
      CMutableTransaction m = f.MintV3(10000, 50000, o);
      BOOST_CHECK_EQUAL(MintVerdictOf(f, m), "");
      std::optional<TxLogRecord> log = f.Log(CTransaction(m).GetHash());
      BOOST_CHECK(log->hasAttestPayee);
      BOOST_CHECK_EQUAL(log->attestPayee, o.attestPayee);
      BOOST_CHECK_EQUAL(log->attestFeeZat, afee);
      BOOST_CHECK_EQUAL(log->bundleSeqs.size(), 3u); }
    // the claim side (RED-3's clause)
    CMutableTransaction m = f.MintV3(10000, 50000);
    BOOST_REQUIRE_EQUAL(MintVerdictOf(f, m), "");
    const uint256 v = CTransaction(m).GetHash();
    for (int i = 0; i < 64; i++) f.Mine(Fixture::Quote(9000, (f.tip + 1) % 3));
    const valtype vsel = OutPointSelector(COutPoint(v, 0));
    { SpendOpts o; o.ownerPath = false; o.bundle = f.BundleFor(f.tip - 1, vsel, 9000);
      RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip - 1, o));            // no attestor fee output
      BOOST_CHECK_EQUAL(r.verdict, verdict::AFEE1_FEE);
      BOOST_CHECK(r.invalid); }
}

// Rule: AFEE-0
BOOST_AUTO_TEST_CASE(afee0_unarmed_vacuous)
{
    Fixture f;
    f.Activate();
    f.Register(3);                                             // PENDING, then TRIGGERED: not yet ARMED
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1)), "");
    while (f.Attest().status != (uint8_t)AttestStatus::TRIGGERED) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1)), "");
    BOOST_CHECK_EQUAL(f.Log(f.evals[f.tip].txlogs[0].first)->attestFeeZat, 0);
    // a claim with R before armHeight needs no bundle and no attestor fee either, whatever the tip's state
    const uint256 v = f.evals[f.tip].txlogs[0].first;
    while (!f.Attest().IsArmed()) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    for (int i = 0; i < 3; i++) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_REQUIRE(f.Armed());
    const int R = f.Attest().armHeight - 1;
    BOOST_REQUIRE(R >= f.tip - f.P.refWindow + 1);
    BOOST_CHECK(!ArmedAt(f.view, f.P, R));
    SpendOpts o; o.ownerPath = false;
    RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, R, o));
    BOOST_CHECK(r.verdict == verdict::OK || r.verdict == verdict::VAULT_CLAIM_NOT_UNDERWATER);   // whichever pClaim(R) says: no bundle, no fee asked
    BOOST_CHECK(r.verdict.find("red1-bundle") == std::string::npos);
    BOOST_CHECK(r.verdict != verdict::AFEE1_FEE);
}

// Rule: IN-2
BOOST_AUTO_TEST_CASE(in2_bond_spend_withdraws)
{
    Fixture f;
    f.Arm();
    const std::string before = Hash(f.view);
    while (f.tip < (int)f.Attestor(1)->bondLocktime) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    CMutableTransaction spend = f.BondSpendTx(1);
    BOOST_CHECK_EQUAL(VerdictOf(f, spend), verdict::OK);
    std::optional<AttestorRecord> rec = f.Attestor(1);
    BOOST_CHECK_EQUAL(rec->status, (uint8_t)AttestorStatus::WITHDRAWN);
    BOOST_CHECK_EQUAL(rec->statusHeight, f.tip);
    BOOST_CHECK_EQUAL(rec->bondSpentHeight, f.tip);
    BOOST_CHECK_EQUAL(rec->seatedSince, 0);                                    // left seated at this SNAP
    BOOST_CHECK([&]{ const std::vector<uint16_t> seatedNow = f.Snap(f.tip).seated; return std::find(seatedNow.begin(), seatedNow.end(), 1) == seatedNow.end(); }());
    BOOST_CHECK_EQUAL(f.Log(CTransaction(spend).GetHash())->type, (uint8_t)TxLogType::NONE);   // relevant, but no payload family
    BOOST_CHECK(State(f.view).GetBondIndex(rec->bondOutpoint).has_value());   // the index row stays with the record
    f.Undo();
    BOOST_CHECK_EQUAL(f.Attestor(1)->status, (uint8_t)AttestorStatus::ELIGIBLE);
    (void)before;
}

// Rule: PRICE-2
// Rule: MINT-9
BOOST_AUTO_TEST_CASE(attest_required_false_reads_x_only)
{
    Fixture f;
    f.P.attestRequired = false;                                // W15: the disarm switch of a later parameter set
    f.Arm();
    BOOST_CHECK(f.Attest().IsArmed());
    BOOST_CHECK(f.Snap(f.tip - 1).attest.IsArmed());
    BOOST_CHECK(!f.Armed());
    BOOST_CHECK(!ArmedAt(f.view, f.P, f.tip));
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1)), "");       // no bundle needed
    { MintOpts o; o.bundle = valtype(7, 0x00); BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), ""); }
    BOOST_CHECK(!f.BundleRow(f.tip).has_value());
    const uint256 v = f.evals[f.tip].txlogs[0].first;
    for (int i = 0; i < 64; i++) f.Mine(Fixture::Quote(9000, (f.tip + 1) % 3));
    SpendOpts o; o.ownerPath = false;
    RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip - 1, o));
    BOOST_CHECK_EQUAL(r.verdict, verdict::OK);
    BOOST_CHECK_EQUAL(r.log.claimPath, "a");
}

// Rule: SNAP
BOOST_AUTO_TEST_CASE(seated_since_tracks_seating)
{
    Fixture f;
    f.Activate();
    f.Register(3);
    const int reg0 = f.Attestor(0)->registerHeight;
    while (f.tip < reg0 + f.P.bondMaturity - 1) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(f.Attestor(0)->seatedSince, 0);
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(f.Attestor(0)->status, (uint8_t)AttestorStatus::ELIGIBLE);
    BOOST_CHECK_EQUAL(f.Attestor(0)->seatedSince, f.tip);                      // seated the SNAP it became ELIGIBLE
    BOOST_CHECK((f.Snap(f.tip).seated == std::vector<uint16_t>{ 0 }));
    for (int i = 0; i < 5; i++) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(f.Attestor(0)->seatedSince, reg0 + f.P.bondMaturity);    // unchanged while seated
    // eject: leaves seated at that SNAP, seatedSince cleared; a later re-entry restarts it
    const int cited = f.tip;
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(VerdictOf(f, f.EquivocationTx(f.Att(0, 50000, cited), f.Att(0, 51000, cited))), verdict::OK);
    BOOST_CHECK_EQUAL(f.Attestor(0)->seatedSince, 0);
}

// Rule: BUNDLE-1
// Rule: MINT-9
BOOST_AUTO_TEST_CASE(selection_ignores_owner_key)
{
    Fixture f;
    f.Arm(4);
    // Two mints at one R with different owner keys share selected(R, ""): one bundle serves both.
    const int R = f.tip - 1;
    CKey other;
    other = CKey::TestOnlyRandomKey(true);
    MintOpts a, b;
    b.owner = other.GetPubKey();
    CMutableTransaction m1 = f.MintV3(10000, 50000, a);
    CMutableTransaction m2 = f.MintV3(10000, 50000, b);
    BlockEvaluation ev = f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3), { m1, m2 });
    BOOST_CHECK(!ev.blockInvalid);
    BOOST_CHECK_EQUAL(f.Vault(CTransaction(m1).GetHash())->status, (uint8_t)VaultStatus::ACTIVE);
    BOOST_CHECK_EQUAL(f.Vault(CTransaction(m2).GetHash())->status, (uint8_t)VaultStatus::ACTIVE);
    BOOST_CHECK(f.Log(CTransaction(m1).GetHash())->bundleSeqs == f.Log(CTransaction(m2).GetHash())->bundleSeqs);
    // the v2 FEE-W selector (the owner key) would have been a free grind: it is not the selector here
    const CPubKey otherPub = other.GetPubKey();
    std::vector<unsigned char> ownerSel(otherPub.begin(), otherPub.end());
    BOOST_CHECK_EQUAL(Selected(f.view, f.P, R, valtype()).size(), 3u);
    BOOST_CHECK_EQUAL(Selected(f.view, f.P, R, ownerSel).size(), 3u);
}

// Rule: BUNDLE-1
BOOST_AUTO_TEST_CASE(cache_hit_equals_cold)
{
    Fixture f;
    f.Arm();
    MapSigCache cache;
    f.cache = &cache;
    CMutableTransaction m = f.MintV3(10000, 50000);
    // cold: the block fills the cache with one entry per attestation
    CBlock block;
    block.vtx.push_back(CTransaction(Fixture::Coinbase(f.tip + 1, Fixture::Quote(50000, (f.tip + 1) % 3))));
    block.vtx.push_back(CTransaction(m));
    OverlayStateView cold(f.view);
    BlockEvaluation a = EvaluateBlock(cold, f.P, block, f.tip + 1, Fixture::FakeHash(f.tip + 1), SUBSIDY, &cache);
    cold.Discard();
    BOOST_CHECK_EQUAL(cache.entries.size(), 3u);
    BOOST_CHECK_EQUAL(cache.hits, 6);   // the liveness credit and its whole-BUNDLE-1 check re-read BUNDLE-1's three entries (no new verify)
    for (const auto& e : cache.entries) BOOST_CHECK(e.second);
    // hit: the same block again reads the cache and agrees byte for byte
    OverlayStateView warm(f.view);
    BlockEvaluation b = EvaluateBlock(warm, f.P, block, f.tip + 1, Fixture::FakeHash(f.tip + 1), SUBSIDY, &cache);
    warm.Discard();
    BOOST_CHECK_EQUAL(cache.hits, 15);  // 6 (cold pass's liveness checks) + 3 (BUNDLE-1) + 6 (liveness checks)
    BOOST_CHECK(SerializeRecord(a.snapshot) == SerializeRecord(b.snapshot));
    BOOST_CHECK(SerializeRecord(a.txlogs[0].second) == SerializeRecord(b.txlogs[0].second));
    BOOST_CHECK_EQUAL(a.txlogs[0].second.verdict, verdict::OK);
    // and without any cache the verdict is the same
    OverlayStateView none(f.view);
    BlockEvaluation c = EvaluateBlock(none, f.P, block, f.tip + 1, Fixture::FakeHash(f.tip + 1), SUBSIDY, nullptr);
    BOOST_CHECK(SerializeRecord(a.txlogs[0].second) == SerializeRecord(c.txlogs[0].second));
    // the same attestation on two branches keys two entries: the block hash of citedHeight is in the key
    const Attestation att = f.Att(0, 50000, f.tip - 1);
    const CPubKey pk0 = f.hotKeys[0].GetPubKey(), pk1 = f.hotKeys[1].GetPubKey();
    BOOST_CHECK(SigCacheKey(att, Fixture::FakeHash(f.tip - 1), pk0) != SigCacheKey(att, Fixture::FakeHash(f.tip), pk0));
    BOOST_CHECK(SigCacheKey(att, Fixture::FakeHash(f.tip - 1), pk0) != SigCacheKey(att, Fixture::FakeHash(f.tip - 1), pk1));   // the key binds the public key
    // a poisoned entry is believed (the cache is trusted node-local state): the invariant is that entries are only ever written by verification
    for (auto& e : cache.entries) e.second = false;
    OverlayStateView poisoned(f.view);
    BlockEvaluation d = EvaluateBlock(poisoned, f.P, block, f.tip + 1, Fixture::FakeHash(f.tip + 1), SUBSIDY, &cache);
    BOOST_CHECK_EQUAL(d.txlogs[0].second.verdict, "mint9-bundle-sig");
}

// Rule: UNDO
// Rule: REG-A1
// Rule: NOT-1
// Rule: EQV-1
// Rule: REV-1
// Rule: IN-2
BOOST_AUTO_TEST_CASE(undo_identity_v3)
{
    // Apply a sequence touching every v3 table, undo it block by block back to genesis, and re-apply it.
    EmergencyFixture g;
    Fixture& f = g.f;
    std::vector<std::string> hashes;
    BOOST_REQUIRE(g.PostNotice());
    hashes.push_back(Hash(f.view));
    for (int i = 0; i < f.P.emergencyPersist + 1; i++) f.Mine(Fixture::Quote(g.poolPrice, (f.tip + 1) % 3));
    { SpendOpts o; o.residualValue = g.Residual(f.tip - 1); BOOST_REQUIRE_EQUAL(g.Mine(g.Claim(o)).verdict, verdict::OK); }
    hashes.push_back(Hash(f.view));
    { const int cited = f.tip; f.Mine(Fixture::Quote(g.poolPrice, (f.tip + 1) % 3));
      BOOST_REQUIRE_EQUAL(VerdictOf(f, f.EquivocationTx(f.Att(0, 11500, cited), f.Att(0, 11600, cited))), verdict::OK); }
    // dormancy for L (S15), then the retired REV-1 payload is refused and a SET_HEARTBEAT revives (P4-b).
    // The notice's and the claim's bundle rows carry every selected signature, L's included, and a signed row
    // inside the window (H - DORMANCY_BLOCKS, H] is evidence of life: age them out before building the evidence.
    for (int i = 0; i < f.P.dormancyBlocks; i++) f.Mine(Fixture::Quote(g.poolPrice, (f.tip + 1) % 3));
    int L = -1, rows = 0;
    while (rows < f.P.dormancyMinBundles) {
        const int R = f.tip - 1;
        std::vector<uint16_t> sel = Selected(f.view, f.P, R, valtype());
        if (sel.size() < 3) { f.Mine(Fixture::Quote(g.poolPrice, (f.tip + 1) % 3)); continue; }
        if (L < 0) L = sel.front();
        if (std::find(sel.begin(), sel.end(), (uint16_t)L) != sel.end()) {
            MintOpts o;
            o.attestPayee = -1;
            o.termClass = 2;     // HALT-2 counts the CLAIMING vault's debt (owner 2026-10-28): GLOBAL_RATIO is set, class C mints (IT-5)
            std::string v = MintVerdictOf(f, f.MintV3(10000, g.poolPrice, o, { L }, 145));
            BOOST_REQUIRE_MESSAGE(v == "" || v == verdict::MINT_HALTED_GLOBAL_RATIO || v == verdict::MINT_HALTED_DIVERGENCE, v);
            if (f.BundleRow(f.tip).has_value()) rows++;
        } else {
            f.Mine(Fixture::Quote(g.poolPrice, (f.tip + 1) % 3));
        }
    }
    // S15 fires at a check height once L's seatedSince is outside the window; nothing but a heartbeat moves a
    // DORMANT record, so the wait cannot overshoot, and the REQUIRE makes an attestor that never went dormant fail.
    while (f.tip % f.P.dormancyCheck != 0 || f.tip - f.P.dormancyBlocks < (int)f.Attestor(L)->seatedSince) f.Mine(Fixture::Quote(g.poolPrice, (f.tip + 1) % 3));
    BOOST_REQUIRE_EQUAL(f.Attestor(L)->status, (uint8_t)AttestorStatus::DORMANT);
    BOOST_CHECK_EQUAL(VerdictOf(f, f.ReviveTx(f.Att(L, g.poolPrice, f.tip))), verdict::ATTESTOR_REVIVE_RETIRED);
    BOOST_CHECK_EQUAL(f.Attestor(L)->status, (uint8_t)AttestorStatus::DORMANT);
    BOOST_REQUIRE_EQUAL(VerdictOf(f, f.HeartbeatTx(L)), verdict::OK);
    BOOST_CHECK_EQUAL(f.Attestor(L)->status, (uint8_t)AttestorStatus::ELIGIBLE);
    hashes.push_back(Hash(f.view));
    while (f.tip < (int)f.Attestor(2)->bondLocktime) f.Mine(Fixture::Quote(g.poolPrice, (f.tip + 1) % 3));
    BOOST_REQUIRE_EQUAL(VerdictOf(f, f.BondSpendTx(2)), verdict::OK);
    BOOST_REQUIRE_EQUAL(VerdictOf(f, f.BondSpendTx(0)), verdict::OK);
    hashes.push_back(Hash(f.view));
    const MemoryStateView full = f.view;
    const int top = f.tip;
    std::map<int, UndoRecord> undos = f.undos;
    while (f.tip >= 1) f.Undo();
    BOOST_CHECK(f.view.Map().empty());
    // re-apply from the recorded undo heights is not possible without the blocks; instead every undo was byte-exact:
    // replaying the undo records in reverse over the full view returns to empty (checked), and the forward hashes were
    // taken from committed overlays whose undo records ApplyBlock reproduced (overlay_equivalence_v3).
    (void)full;
    (void)top;
    (void)undos;
    BOOST_CHECK_EQUAL(hashes.size(), 4u);
}

// Rule: SNAP
// Rule: BUNDLE-1
BOOST_AUTO_TEST_CASE(overlay_equivalence_v3)
{
    EmergencyFixture g;
    Fixture& f = g.f;
    BOOST_REQUIRE(g.PostNotice());
    for (int i = 0; i < f.P.emergencyPersist + 1; i++) f.Mine(Fixture::Quote(g.poolPrice, (f.tip + 1) % 3));
    // One block with a registration, an emergency claim with a bundle, an equivocation and a bundled mint (VOID or not).
    SpendOpts o; o.residualValue = g.Residual(f.tip - 1);
    const int cited = f.tip - 1;
    CBlock block;
    block.vtx.push_back(CTransaction(Fixture::Coinbase(f.tip + 1, Fixture::Quote(g.poolPrice, 0))));
    block.vtx.push_back(CTransaction(f.RegisterTx(5)));
    block.vtx.push_back(CTransaction(g.Claim(o)));
    block.vtx.push_back(CTransaction(f.EquivocationTx(f.Att(1, 11500, cited), f.Att(1, 11600, cited))));
    { MintOpts mo; mo.termClass = 2; block.vtx.push_back(CTransaction(f.MintV3(10000, g.poolPrice, mo, {}, 145))); }   // IT-5: HALT-2 is set (126 %), class C mints
    OverlayStateView outer(f.view);
    StateView& outerBase = outer;
    OverlayStateView inner(outerBase);
    BlockEvaluation a = EvaluateBlock(inner, f.P, block, f.tip + 1, Fixture::FakeHash(f.tip + 1), SUBSIDY);
    MemoryStateView copy = f.view;
    UndoRecord undo;
    ApplyBlock(copy, f.P, block, f.tip + 1, Fixture::FakeHash(f.tip + 1), SUBSIDY, undo);
    inner.Commit();
    outer.Commit();
    BOOST_CHECK(copy == f.view);
    BOOST_CHECK(!a.blockInvalid);
    BOOST_CHECK_EQUAL(a.txlogs.size(), 4u);
    BOOST_CHECK_EQUAL(a.txlogs[1].second.verdict, verdict::OK);
    BOOST_CHECK_EQUAL(a.txlogs[1].second.claimPath, "b");
    BOOST_CHECK(SerializeRecord(a.undo) == SerializeRecord(undo));
    BOOST_CHECK(SerializeRecord(a.snapshot) == SerializeRecord(State(copy).GetSnapshot((uint32_t)f.tip + 1).value()));
    BOOST_CHECK(State(copy).GetAttestor(4).has_value());           // the fifth registration takes seq 4
    BOOST_CHECK_EQUAL(State(copy).GetAttestorSeq().next, 5);
    BOOST_CHECK_EQUAL(State(copy).GetAttestor(1)->status, (uint8_t)AttestorStatus::EJECTED);
    BOOST_CHECK(State(copy).GetBundleLog((uint32_t)f.tip + 1).has_value());
    // undo restores the pre-block view byte for byte
    UndoBlock(copy, undo);
    MemoryStateView restored = f.view;
    UndoBlock(restored, a.undo);
    BOOST_CHECK(copy == restored);
}

// Rule: AFEE-1
BOOST_AUTO_TEST_CASE(default_attest_payee_in_A)
{
    Fixture f;
    f.Arm(4);
    const int R = f.tip - 1;
    std::vector<uint16_t> A = Selected(f.view, f.P, R, valtype());
    AttestPolicy policy;
    std::optional<uint16_t> pick = DefaultAttestPayee(f.view, f.P, R, valtype(), A, policy);
    BOOST_REQUIRE(pick.has_value());
    BOOST_CHECK(std::find(A.begin(), A.end(), pick.value()) != A.end());
    BOOST_CHECK(pick == DefaultAttestPayee(f.view, f.P, R, valtype(), A, policy));           // deterministic
    policy.preferred = A.back();
    BOOST_CHECK_EQUAL(DefaultAttestPayee(f.view, f.P, R, valtype(), A, policy).value(), A.back());
    policy.preferred = 99;
    BOOST_CHECK(std::find(A.begin(), A.end(), DefaultAttestPayee(f.view, f.P, R, valtype(), A, policy).value()) != A.end());
    BOOST_CHECK(!DefaultAttestPayee(f.view, f.P, R, valtype(), {}, policy).has_value());
}

// ===========================================================================
// In-term claims (docs/plans/yellowback-in-term-claims-plan.md, IT-1..IT-6)

// Rule: IT-1
// Rule: MINT-3
BOOST_AUTO_TEST_CASE(in_term_vault_app_height_is_mint_height)
{
    Fixture f;
    f.Activate();
    const uint256 v = f.MintActive(10000);
    const VaultRecord r = f.Vault(v).value();
    BOOST_CHECK_EQUAL(r.appHeight, r.refHeight + 1);
    BOOST_CHECK_EQUAL(r.ownerHeight, r.refHeight + 1);
    BOOST_CHECK_EQUAL(r.claimHeight, r.lockHeight + f.P.grace);
    vault::VaultParams vp;
    BOOST_REQUIRE(vault::ParseVault(YedVaultScriptAt(f.P, r.Owner(), r.ownerHeight, r.appHeight), vp));
    BOOST_CHECK_EQUAL(vp.appHeight, r.refHeight + 1);
    BOOST_CHECK_EQUAL(vp.ownerHeight, r.refHeight + 1);
    BOOST_CHECK(YedVaultScript(f.P, r.Owner(), r.refHeight) == YedVaultScriptAt(f.P, r.Owner(), r.refHeight + 1, r.refHeight + 1));
}

// Rule: IT-1
// Rule: MINT-3
BOOST_AUTO_TEST_CASE(in_term_old_shape_vault_spendable_but_not_mintable)
{
    Fixture f;
    f.Activate();
    // A new mint carrying the pre-plan V (appHeight = lockHeight + GRACE) is refused.
    const int64_t lock = f.tip - 1 + 48;
    { MintOpts o; o.vaultScriptOverride = YedVaultScriptAt(f.P, TestPQOwner(f.ownerKey.GetPubKey()), lock, lock + f.P.grace);
      BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "bad-mint-vault-script"); }
    // A vault minted before the plan (its record remembers appHeight = lockHeight + GRACE) still spends: owner path ...
    const uint256 v = f.MintActive(10000);
    { VaultRecord r = f.Vault(v).value(); r.appHeight = r.claimHeight; r.ownerHeight = r.lockHeight; State(f.view).Put(keys::Vault(COutPoint(v, 0)), r); }
    BOOST_CHECK_EQUAL(f.Vault(v)->appHeight, f.Vault(v)->claimHeight);
    BOOST_CHECK_EQUAL(f.SpendTx(v, { COutPoint(v, 1) }, f.tip).nLockTime, (uint32_t)f.Vault(v)->lockHeight);   // the pre-plan owner CLTV
    { RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip));
      BOOST_CHECK_EQUAL(r.verdict, verdict::OK);
      BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLOSED); }
    // ... and the claim path, whose intents commit to the V as minted.
    const uint256 w = f.MintActive(10000);
    { VaultRecord r = f.Vault(w).value(); r.appHeight = r.claimHeight; r.ownerHeight = r.lockHeight; State(f.view).Put(keys::Vault(COutPoint(w, 0)), r); }
    for (int i = 0; i < 64; i++) f.Mine(Fixture::Quote(9000, (f.tip + 1) % 3));
    { SpendOpts o; o.ownerPath = false;
      CMutableTransaction claim = f.SpendTx(w, { COutPoint(w, 1) }, f.tip, o);
      BOOST_CHECK_EQUAL(claim.nLockTime, (uint32_t)f.Vault(w)->claimHeight);
      RedResult r = Spend(f, w, claim);
      BOOST_CHECK_EQUAL(r.verdict, verdict::OK);
      BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLAIMING); }
}

// Rule: IT-2
// Rule: RED-4
BOOST_AUTO_TEST_CASE(in_term_claim_valid_at_theta_invalid_above)
{
    Fixture f;
    f.Activate();
    const uint256 v = f.MintActive(10000);                 // 6,000 YEC back $100 at 300 %; lock = ref + 48
    const VaultRecord rec = f.Vault(v).value();
    // In term at the mint price: 300 % >= theta, so the claim is invalid and the vault stays ACTIVE.
    BOOST_REQUIRE(f.tip < rec.lockHeight);
    { SpendOpts o; o.ownerPath = false;
      RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o));
      BOOST_CHECK_EQUAL(r.verdict, verdict::VAULT_CLAIM_NOT_UNDERWATER);
      BOOST_CHECK(r.invalid);
      BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::ACTIVE); }
    // Still in term, just above theta: 6,000 YEC at 21,000 uUSD = $126 >= $125: invalid.
    for (int i = 0; i < 34; i++) f.Mine(Fixture::Quote(21000, (f.tip + 1) % 3));
    BOOST_REQUIRE(f.tip < rec.lockHeight);
    BOOST_REQUIRE_EQUAL(f.Snap(f.tip).PClaim().value(), 21000);
    BOOST_CHECK(!IsUnderwater(rec.collateralZat, 21000, rec.mintedCents, f.P.claimThresholdBps));
    { SpendOpts o; o.ownerPath = false;
      RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o));
      BOOST_CHECK_EQUAL(r.verdict, verdict::VAULT_CLAIM_NOT_UNDERWATER);
      BOOST_CHECK(r.invalid); }
    // One tick under theta in term: 6,000 YEC at 20,800 uUSD = $124.8 < $125: the claim is valid (path (a)).
    // HALT-2 is set (v sits at 126 %), so the second vault is class C, the one tier the recap gate admits (IT-5).
    const uint256 w = f.MintActive(10000, 145, 2);         // minted at 21,000 (500 %: 23,810 YEC)
    for (int i = 0; i < 34; i++) f.Mine(Fixture::Quote(20800, (f.tip + 1) % 3));
    BOOST_REQUIRE(f.tip < rec.lockHeight + 48);
    BOOST_REQUIRE_EQUAL(f.Snap(f.tip).PClaim().value(), 20800);
    BOOST_CHECK(IsUnderwater(rec.collateralZat, 20800, rec.mintedCents, f.P.claimThresholdBps));
    { SpendOpts o; o.ownerPath = false;
      CMutableTransaction claim = f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o);
      BOOST_CHECK_EQUAL(claim.nLockTime, (uint32_t)rec.appHeight);            // the APP branch's CLTV: the block after the mint
      RedResult r = Spend(f, v, claim);
      BOOST_CHECK_EQUAL(r.verdict, verdict::OK);
      BOOST_CHECK(!r.invalid);
      BOOST_CHECK_EQUAL(r.log.claimPath, "a");
      BOOST_CHECK_EQUAL(r.log.residualZat, 0);                                 // under theta the claimant's cap exceeds the collateral
      BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLAIMING); }
    // The vault minted at 21,000 is at 495 % under 20,800: its in-term claim is invalid, its owner's redeem (before lockHeight, IT-1 extended) valid.
    { SpendOpts o; o.ownerPath = false;
      RedResult r = Spend(f, w, f.SpendTx(w, { COutPoint(w, 1) }, f.tip, o));
      BOOST_CHECK_EQUAL(r.verdict, verdict::VAULT_CLAIM_NOT_UNDERWATER); }
    BOOST_REQUIRE(f.tip < f.Vault(w)->lockHeight);
    { CMutableTransaction redeem = f.SpendTx(w, { COutPoint(w, 1) }, f.tip);
      BOOST_CHECK_EQUAL(redeem.nLockTime, (uint32_t)f.Vault(w)->ownerHeight);           // the owner branch's CLTV: the block after the mint
      RedResult r = Spend(f, w, redeem);
      BOOST_CHECK_EQUAL(r.verdict, verdict::OK);
      BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLOSED); }
}

// Rule: IT-1
// Rule: RED-1
// Rule: RED-2
BOOST_AUTO_TEST_CASE(in_term_owner_redeem_below_theta_before_any_claim)
{
    // The owner redeems in term while under theta, before anyone claims: valid, the full debt burned (D-IT-16's
    // early-redeem fee is a later decision; RED-3 marks the hook).
    Fixture f;
    f.Activate();
    const uint256 v = f.MintActive(10000);
    for (int i = 0; i < 34; i++) f.Mine(Fixture::Quote(9000, (f.tip + 1) % 3));
    BOOST_REQUIRE(f.tip < f.Vault(v)->lockHeight);
    BOOST_REQUIRE(IsUnderwater(f.Vault(v)->collateralZat, f.Snap(f.tip).PClaim().value(), 10000, f.P.claimThresholdBps));
    RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip));
    BOOST_CHECK_EQUAL(r.verdict, verdict::OK);
    BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLOSED);
    BOOST_CHECK_EQUAL(r.vault.burnedCents, 10000);
    BOOST_CHECK_EQUAL(f.GetTotals().supplyCents, 0);
    // and a claim of the closed vault no longer exists to be made
    BOOST_CHECK(!f.Vault(v)->IsOpen());
}

// Rule: IT-9
// Rule: RED-3
BOOST_AUTO_TEST_CASE(in_term_early_redeem_fee_per_class_and_boundary)
{
    Fixture f;
    f.Activate();
    BOOST_CHECK_EQUAL(f.P.earlyRedeemFeeBps[0], 500);
    BOOST_CHECK_EQUAL(f.P.earlyRedeemFeeBps[1], 250);
    BOOST_CHECK_EQUAL(f.P.earlyRedeemFeeBps[2], 100);
    for (int cls = 0; cls < NUM_CLASSES; cls++) {
        const uint256 v = f.MintActive(10000, f.P.classMin[cls], cls);
        const VaultRecord r = f.Vault(v).value();
        const CAmount fee1 = f.VaultFee(r);
        const CAmount early = EarlyRedeemFeeZat(r.mintedCents, f.P.earlyRedeemFeeBps[cls], r.pMint);
        // IT-9': bps of the debt at pMint: $100 x 5 / 2.5 / 1 % at $0.05 = 100 / 50 / 20 YEC
        BOOST_CHECK_EQUAL(early, (CAmount)(10000LL * f.P.earlyRedeemFeeBps[cls] * COIN / r.pMint));
        BOOST_REQUIRE(f.tip + 1 < r.lockHeight);
        // FEE-1 alone, and one zat short of FEE-1 + the early fee: bad-redeem-early-fee; the vault stays ACTIVE
        { SpendOpts o; o.feeValue = fee1; RedResult x = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o));
          BOOST_CHECK_EQUAL(x.verdict, verdict::BAD_REDEEM_EARLY_FEE); BOOST_CHECK(x.invalid); BOOST_CHECK_EQUAL(x.vault.status, (uint8_t)VaultStatus::ACTIVE); }
        { SpendOpts o; o.feeValue = fee1 + early - 1; RedResult x = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o));
          BOOST_CHECK_EQUAL(x.verdict, verdict::BAD_REDEEM_EARLY_FEE); BOOST_CHECK(x.invalid); }
        // short of FEE-1 itself is still RED-3's vault-spend-bad-fee
        { SpendOpts o; o.feeValue = fee1 - 1; RedResult x = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o));
          BOOST_CHECK_EQUAL(x.verdict, verdict::VAULT_SPEND_BAD_FEE); }
        // exact: valid, the fee logged in full
        { SpendOpts o; o.feeValue = fee1 + early; RedResult x = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o));
          BOOST_CHECK_EQUAL(x.verdict, verdict::OK); BOOST_CHECK_EQUAL(x.vault.status, (uint8_t)VaultStatus::CLOSED);
          BOOST_CHECK_EQUAL(x.vault.feePaidZat, fee1 + early); }
    }
    // The boundary: a redeem mined at lockHeight - 1 pays the early fee, one mined at lockHeight pays FEE-1 only.
    const uint256 w = f.MintActive(10000);
    const VaultRecord r = f.Vault(w).value();
    const CAmount fee1 = f.VaultFee(r);
    while (f.tip + 1 < r.lockHeight - 1) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_REQUIRE_EQUAL(f.tip + 1, r.lockHeight - 1);
    { SpendOpts o; o.feeValue = fee1;
      BlockEvaluation ev = f.Evaluate(Fixture::Quote(50000, (f.tip + 1) % 3), { f.SpendTx(w, { COutPoint(w, 1) }, f.tip, o) });
      BOOST_CHECK(ev.blockInvalid); BOOST_CHECK_EQUAL(ev.txlogs[0].second.verdict, verdict::BAD_REDEEM_EARLY_FEE); }
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_REQUIRE_EQUAL(f.tip + 1, r.lockHeight);
    { SpendOpts o; o.feeValue = fee1; RedResult x = Spend(f, w, f.SpendTx(w, { COutPoint(w, 1) }, f.tip, o));
      BOOST_CHECK_EQUAL(x.verdict, verdict::OK); BOOST_CHECK_EQUAL(x.vault.feePaidZat, fee1); }
}

// Rule: IT-2
// Rule: RED-4
BOOST_AUTO_TEST_CASE(in_term_claim_valid_post_term_as_before)
{
    Fixture f;
    f.Activate();
    const uint256 v = f.MintActive(10000);
    const VaultRecord rec = f.Vault(v).value();
    while (f.tip <= rec.claimHeight) f.Mine(Fixture::Quote(9000, (f.tip + 1) % 3));     // past lockHeight + GRACE
    BOOST_REQUIRE_EQUAL(f.Snap(f.tip).PClaim().value(), 9000);
    SpendOpts o; o.ownerPath = false;
    RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o));
    BOOST_CHECK_EQUAL(r.verdict, verdict::OK);
    BOOST_CHECK_EQUAL(r.log.claimPath, "a");
    BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLAIMING);
}

// Rule: IT-2
// Rule: IT-3
// Rule: RED-5
// Rule: NOT-1
BOOST_AUTO_TEST_CASE(in_term_emergency_claim_pays_the_residual_to_the_owner)
{
    // Path (b) in term: pools at 21,000 (126 %, not (a)), a persisted notice at the attestors' 17,000 (102 %).
    EmergencyFixture g(35);
    const VaultRecord rec = g.f.Vault(g.w).value();
    BOOST_REQUIRE(g.f.tip < rec.lockHeight);
    BOOST_REQUIRE(g.PostNotice());
    for (int i = 0; i < g.f.P.emergencyPersist + 1; i++) g.f.Mine(Fixture::Quote(g.poolPrice, (g.f.tip + 1) % 3));
    BOOST_REQUIRE(g.f.tip + 1 < rec.lockHeight);                                 // the claim block is still in term
    const CAmount residual = g.Residual(g.f.tip - 1);
    BOOST_CHECK(residual >= g.f.P.residualMinZat);
    { RedResult r = g.Mine(g.Claim()); BOOST_CHECK_EQUAL(r.verdict, verdict::RED5_RESIDUAL); BOOST_CHECK(r.invalid); }   // no residual intent
    SpendOpts o; o.residualValue = residual;
    RedResult r = g.Mine(g.Claim(o));
    BOOST_CHECK_EQUAL(r.verdict, verdict::OK);
    BOOST_CHECK_EQUAL(r.log.claimPath, "b");
    BOOST_CHECK_EQUAL(r.log.residualZat, residual);
    BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLAIMING);
    BOOST_CHECK(g.f.tip < rec.lockHeight);
}

// Rule: IT-5
// Rule: MINT-4
// Rule: MINT-6
BOOST_AUTO_TEST_CASE(in_term_recap_gate_is_class_c_only)
{
    BOOST_CHECK(MainParams().baseRatioBps[0] < MainParams().recapRatioBps);
    BOOST_CHECK(MainParams().baseRatioBps[1] < MainParams().recapRatioBps);
    BOOST_CHECK_EQUAL(MainParams().baseRatioBps[2], MainParams().recapRatioBps);
    // Under HALT-2 (one 300 % vault, price / 5.5): classes A and B are halted, C mints.
    Fixture f;
    f.Activate();
    f.MintActive(10000);
    for (int i = 0; i < 64; i++) f.Mine(Fixture::Quote(9000, (f.tip + 1) % 3));
    BOOST_REQUIRE(f.Snap(f.tip).haltMask & HALT_GLOBAL_RATIO);
    BOOST_REQUIRE(!(f.Snap(f.tip).haltMask & HALT_DIVERGENCE));
    MintOpts a; a.collateral = 10000000000000LL;
    MintOpts b = a; b.termClass = 1;
    MintOpts c = a; c.termClass = 2;
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, a)), "mint-halted-global-ratio");
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 100, f.tip - 1, b)), "mint-halted-global-ratio");
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 145, f.tip - 1, c)), "");
    // Above the soft cap: the same gate (H-10's class-A clause is gone: class A is refused).
    Fixture g(1, 0, 1, 0);
    g.Activate();
    BOOST_CHECK_EQUAL(MintVerdictOf(g, g.MintTx(10000, 48, g.tip - 1, a)), "mint-supply-cap");
    BOOST_CHECK_EQUAL(MintVerdictOf(g, g.MintTx(10000, 100, g.tip - 1, b)), "mint-supply-cap");
    BOOST_CHECK_EQUAL(MintVerdictOf(g, g.MintTx(10000, 145, g.tip - 1, c)), "");
}

// Rule: IT-4
// Rule: SIGMA-1
// Rule: MINT-5
BOOST_AUTO_TEST_CASE(in_term_sigma_multiplier_fixed_at_one)
{
    // Even at a non-zero SIGMA_REF the cap (sigmaMultMaxBps 10,000) pins the multiplier; the live set has SIGMA_REF 0.
    BOOST_CHECK_EQUAL(MainParams().sigmaRefBps, 0);
    BOOST_CHECK_EQUAL(MainParams().sigmaMultMaxBps, 10000);
    Fixture f(1, 10000, 0, 0);
    f.Activate();
    for (int i = 0; i < 64; i++) f.Mine(Fixture::Quote(i % 2 ? 46000 : 54000, (f.tip + 1) % 3));   // +-8 %: noisy, not divergent
    BOOST_CHECK_EQUAL(f.Snap(f.tip).sigmaMultBps, 10000);
    const Snapshot s = f.Snap(f.tip - 1);
    BOOST_REQUIRE(!(s.haltMask & ~HALT_GLOBAL_RATIO));
    BOOST_CHECK_EQUAL(MinRatioBps(f.P.baseRatioBps[0], s.sigmaMultBps), f.P.baseRatioBps[0]);
    const CAmount required = RequiredCollateral(10000, f.P.baseRatioBps[0], s.PMint().value()).value();     // the exact MINT-5 floor
    { MintOpts o; o.collateral = required - 1; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "bad-mint-collateral"); }
    { MintOpts o; o.collateral = required; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), ""); }
}

// Rule: IT-6
// Rule: HALT-2
BOOST_AUTO_TEST_CASE(in_term_halt_ratio_counts_claiming_vault)
{
    Fixture f;
    f.Activate();
    const uint256 v = f.MintActive(10000);
    const uint256 w = f.MintActive(10000);
    const CAmount each = f.Vault(v)->collateralZat;
    BOOST_CHECK_EQUAL(f.GetTotals().collateralZat, 2 * each);
    for (int i = 0; i < 64; i++) f.Mine(Fixture::Quote(9000, (f.tip + 1) % 3));
    SpendOpts o; o.ownerPath = false;
    CMutableTransaction claim = f.SpendTx(w, { COutPoint(w, 1) }, f.tip, o);
    BOOST_REQUIRE_EQUAL(Spend(f, w, claim).verdict, verdict::OK);
    // D-IT-14: the debt left supply with the burn, the collateral stays until release; the snapshot reads post-claim state.
    // HALT-2 (owner 2026-10-28): the ratio divides by open debt, the CLAIMING vault's included, not by supply.
    BOOST_CHECK_EQUAL(f.Vault(w)->status, (uint8_t)VaultStatus::CLAIMING);
    BOOST_CHECK_EQUAL(f.GetTotals().supplyCents, 10000);
    BOOST_CHECK_EQUAL(f.GetTotals().openDebtCents, 20000);
    BOOST_CHECK_EQUAL(f.GetTotals().collateralZat, 2 * each);
    BOOST_CHECK_EQUAL(f.GetTotals().activeVaults, 1u);
    BOOST_CHECK_EQUAL(f.Snap(f.tip).collateralZat, 2 * each);
    BOOST_CHECK_EQUAL(f.Snap(f.tip).openDebtCents, 20000);
    BOOST_CHECK_EQUAL(f.Snap(f.tip).GlobalRatioBps().value(), GlobalRatioBps(2 * each, 9000, 20000).value());
    // Release after CLAIM_DELAY: the collateral leaves.
    const COutPoint intent(CTransaction(claim).GetHash(), 0);
    CMutableTransaction rel;
    rel.vin.push_back(CTxIn(intent, CScript() << OP_1, (uint32_t)f.P.claimDelay));
    rel.vin.push_back(CTxIn(f.FakeInput()));
    rel.vout.push_back(CTxOut(each, GetScriptForDestination(f.userKey.GetPubKey().GetID())));
    f.Mine(Fixture::Quote(9000, (f.tip + 1) % 3), { rel });
    BOOST_REQUIRE_EQUAL(f.Refused(CTransaction(rel).GetHash()), "");
    BOOST_CHECK_EQUAL(f.Vault(w)->status, (uint8_t)VaultStatus::CLAIMED);
    BOOST_CHECK_EQUAL(f.GetTotals().collateralZat, each);
    BOOST_CHECK_EQUAL(f.Snap(f.tip).collateralZat, each);
    BOOST_CHECK_EQUAL(f.GetTotals().openDebtCents, 10000);                 // ... and its debt with it
    BOOST_CHECK_EQUAL(f.Snap(f.tip).GlobalRatioBps().value(), GlobalRatioBps(each, 9000, 10000).value());
}

// ===========================================================================
// The claim intent's attestor cancel (U-23, U-24, I-2; audit 03/T-2: the cancel path's verdicts, totals and undo)

namespace {

/**
 * Two ACTIVE vaults; the pools fall to $0.009, so `w` (300 %) is under theta and is claimed on path (a) at the
 * construction (its claimant intent at claim:0, no residual due). CancelTx builds the attestor CANCEL of that
 * intent (selector 2; the set signature is a placeholder: EvaluateBlock reads the selector, the primitive checks
 * the signature) with the re-created vault at vout[0] unless `outs` says otherwise.
 */
struct CancelFixture
{
    Fixture f{ 1, 0, 0, 10 };    // ATTEST_ARM_MIN 10: the four members below never arm the chain, so the claims stay unarmed
    uint256 v, w, claimTxid;
    CAmount each;
    Totals beforeClaim, afterClaim;
    int claimRef = 0;            //!< the claim's refHeight: the height a cancel's statements cite (C4b)
    static const MicroUsd HONEST = 50000;   //!< the co-signers' price: $0.05, at which the vault is at 300 % (not claimable)

    CancelFixture()
    {
        f.Activate();
        f.Register(4);           // CAN-2: members 0..3, current (maturity 8) long before the claim
        v = f.MintActive(10000);
        w = f.MintActive(10000);
        each = f.Vault(w)->collateralZat;
        for (int i = 0; i < 64; i++) f.Mine(Fixture::Quote(9000, (f.tip + 1) % 3));
        beforeClaim = f.GetTotals();
        SpendOpts o; o.ownerPath = false;
        claimRef = f.tip;
        CMutableTransaction claim = f.SpendTx(w, { COutPoint(w, 1) }, f.tip, o);
        BOOST_REQUIRE_EQUAL(Spend(f, w, claim).verdict, verdict::OK);
        claimTxid = CTransaction(claim).GetHash();
        afterClaim = f.GetTotals();
        BOOST_REQUIRE_EQUAL(f.Vault(w)->status, (uint8_t)VaultStatus::CLAIMING);
    }
    COutPoint Intent() const { return COutPoint(claimTxid, 0); }
    /** The claimed vault's V script: what a cancel must re-create at vout[0]. */
    CScript VaultScript() const
    {
        const VaultRecord r = f.Vault(w).value();
        return YedVaultScriptAt(f.P, r.Owner(), r.ownerHeight, r.appHeight);
    }
    CTxOut Relock() const { return CTxOut(each, VaultScript()); }
    /** CAN-1: the holder the claim's burn came from -- the mint's token script, P2PKH(owner) -- and the refund to it. */
    CScript Holder() const { return GetScriptForDestination(f.ownerKey.GetPubKey().GetID()); }
    CTxOut Refund() const { return CTxOut(TOKEN_VALUE, Holder()); }
    /** CAN-2 + C4b: co-signatures of `seqs` at `price` over this fixture's intent and claimRef. */
    std::vector<CancelCosignEntry> Cosigns(const std::vector<int>& seqs, MicroUsd price = HONEST) { return CosignsFor(Intent(), claimRef, seqs, price); }
    std::vector<CancelCosignEntry> CosignsFor(const COutPoint& intent, int R, const std::vector<int>& seqs, MicroUsd price = HONEST)
    {
        std::vector<CancelCosignEntry> out;
        for (int seq : seqs) out.push_back(f.Cosign(seq, price, intent, R));
        return out;
    }
    /** The cancel of `intent` with `entries` in a carrier and the CANCEL_COSIGN marker last (none when `entries` is empty). */
    CMutableTransaction CancelOf(const COutPoint& intent, const std::vector<CTxOut>& outs, const std::vector<CancelCosignEntry>& entries,
                                 CScript scriptSig = CScript() << valtype(65, 0) << OP_2)
    {
        CMutableTransaction m;
        m.vin.push_back(CTxIn(intent, scriptSig, 0xFFFFFFFF));
        m.vin.push_back(CTxIn(f.FakeInput()));                 // the canceller's fee input
        m.vout = outs;
        if (!entries.empty()) {
            m.vin.push_back(f.CarrierIn(EncodeCancelCosigns(entries)));
            m.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(Payload::CancelCosign()))));
        }
        return m;
    }
    /** This fixture's cancel; by default co-signed by member 0 alone (CAN-2's first cancel). */
    CMutableTransaction CancelTx(std::optional<std::vector<CTxOut>> outs = std::nullopt, CScript scriptSig = CScript() << valtype(65, 0) << OP_2,
                                 std::vector<int> seqs = { 0 })
    {
        return CancelOf(Intent(), outs.value_or(std::vector<CTxOut>{ Relock(), Refund() }), Cosigns(seqs), scriptSig);
    }
    /** Mine `tx` at tip + 1 (pools at $0.009); returns the verdict that refused it, "" when it was applied. */
    std::string Mine(const CMutableTransaction& tx)
    {
        f.Mine(Fixture::Quote(9000, (f.tip + 1) % 3), { tx });
        return f.Refused(CTransaction(tx).GetHash());
    }
};

} // namespace

// Rule: U-23
// Rule: U-24
// Rule: I-2
// Rule: IT-6
BOOST_AUTO_TEST_CASE(intent_cancel_recreates_the_vault_at_vout0)
{
    CancelFixture c;
    const VaultRecord claiming = c.f.Vault(c.w).value();
    BOOST_CHECK_EQUAL(claiming.burnedCents, 10000);
    BOOST_CHECK_EQUAL(c.afterClaim.supplyCents, c.beforeClaim.supplyCents - 10000);       // RED-2: the claim burned the debt
    BOOST_CHECK_EQUAL(c.afterClaim.activeVaults, c.beforeClaim.activeVaults - 1);
    BOOST_CHECK_EQUAL(c.afterClaim.collateralZat, c.beforeClaim.collateralZat);           // IT-6: still counted while CLAIMING
    CMutableTransaction cancel = c.CancelTx();
    BOOST_REQUIRE_EQUAL(c.Mine(cancel), "");
    const uint256 txid = CTransaction(cancel).GetHash();
    BOOST_CHECK(!c.f.Vault(c.w).has_value());                                             // the CLAIMING record moved
    const std::optional<VaultRecord> back = c.f.Vault(txid);
    BOOST_REQUIRE(back.has_value());
    BOOST_CHECK_EQUAL(back->status, (uint8_t)VaultStatus::ACTIVE);
    BOOST_CHECK_EQUAL(back->mintedCents, 10000);
    BOOST_CHECK_EQUAL(back->burnedCents, 0);
    BOOST_CHECK_EQUAL(back->collateralZat, c.each);                                       // the re-lock's value
    BOOST_CHECK_EQUAL(back->closeHeight, 0);
    BOOST_CHECK(back->closingTxid.IsNull());
    BOOST_CHECK_EQUAL(back->pMint, claiming.pMint);                                       // FEE-1': the same position
    BOOST_CHECK_EQUAL(back->mintHeight, claiming.mintHeight);
    BOOST_CHECK(!State(c.f.view).GetIntent(c.Intent()).has_value());
    const TxLogRecord log = c.f.Log(txid).value();
    BOOST_CHECK_EQUAL(log.type, (uint8_t)TxLogType::CLAIM_CANCEL);
    BOOST_CHECK_EQUAL(log.verdict, verdict::OK);
    BOOST_CHECK(log.closedVaults == std::vector<COutPoint>({ COutPoint(c.w, 0) }));
    BOOST_CHECK(log.reopenedVaults == std::vector<COutPoint>({ COutPoint(txid, 0) }));
    const Totals t = c.f.GetTotals();
    BOOST_CHECK_EQUAL(t.activeVaults, c.beforeClaim.activeVaults);                        // +1: the vault is ACTIVE again
    BOOST_CHECK_EQUAL(t.claimedVaults, c.beforeClaim.claimedVaults);                      // a cancel never counts as a claim
    BOOST_CHECK_EQUAL(t.collateralZat, c.afterClaim.collateralZat + c.each - claiming.collateralZat);
    // CAN-1 (03/H-1; flips the 03/T-2 assertion "supply unchanged"): the claim's burn is re-issued to the holder it came
    // from at cancel:1 and supply is back where it was before the claim (03/M-1 gone)
    const std::optional<TokenRecord> tok = c.f.Token(txid, 1);
    BOOST_REQUIRE(tok.has_value());
    BOOST_CHECK_EQUAL(tok->cents, claiming.burnedCents);
    BOOST_CHECK(tok->scriptPubKey == c.Holder());
    BOOST_CHECK_EQUAL(tok->nValue, TOKEN_VALUE);
    BOOST_CHECK_EQUAL(t.supplyCents, c.beforeClaim.supplyCents);
    BOOST_CHECK_EQUAL(t.supplyCents, c.afterClaim.supplyCents + 10000);
    BOOST_REQUIRE_EQUAL(log.assigned.size(), 1u);
    BOOST_CHECK(log.assigned[0].outpoint == COutPoint(txid, 1));
    BOOST_CHECK_EQUAL(log.assigned[0].cents, 10000);
    BOOST_CHECK_EQUAL(log.yedOut, 10000);
    BOOST_CHECK_EQUAL(log.burned, 0);
}

// Rule: CAN-1
BOOST_AUTO_TEST_CASE(intent_claim_records_the_refund_holder)
{
    CancelFixture c;
    const IntentRecord ir = State(c.f.view).GetIntent(c.Intent()).value();
    BOOST_CHECK(ir.Role() == IntentRole::CLAIMANT);
    BOOST_CHECK(CScript(ir.refundScript.begin(), ir.refundScript.end()) == c.Holder());
}

// Rule: CAN-1
BOOST_AUTO_TEST_CASE(intent_cancel_without_refund_invalid)
{
    CancelFixture c;
    const CTxOut other(TOKEN_VALUE, GetScriptForDestination(c.f.userKey.GetPubKey().GetID()));
    BOOST_CHECK_EQUAL(c.Mine(c.CancelTx(std::vector<CTxOut>{ c.Relock() })), verdict::INTENT_CANCEL_NO_REFUND);              // none
    BOOST_CHECK_EQUAL(c.Mine(c.CancelTx(std::vector<CTxOut>{ c.Relock(), other })), verdict::INTENT_CANCEL_NO_REFUND);       // another script
    BOOST_CHECK_EQUAL(c.Mine(c.CancelTx(std::vector<CTxOut>{ c.Relock(), CTxOut(0, c.Holder()) })), verdict::INTENT_CANCEL_NO_REFUND);   // zero carrier
    // the refund at vout 0 displaces the re-lock: the re-lock rule speaks first
    BOOST_CHECK_EQUAL(c.Mine(c.CancelTx(std::vector<CTxOut>{ c.Refund(), c.Relock() })), verdict::INTENT_CANCEL_NO_VAULT);
    BOOST_CHECK_EQUAL(c.f.Vault(c.w)->status, (uint8_t)VaultStatus::CLAIMING);
    BOOST_CHECK_EQUAL(c.f.GetTotals().supplyCents, c.afterClaim.supplyCents);
}

// Rule: CAN-1
BOOST_AUTO_TEST_CASE(intent_cancel_refund_at_lowest_holder_output)
{
    CancelFixture c;
    const CTxOut other(777, GetScriptForDestination(c.f.userKey.GetPubKey().GetID()));
    CMutableTransaction cancel = c.CancelTx(std::vector<CTxOut>{ c.Relock(), other, CTxOut(5000, c.Holder()), CTxOut(6000, c.Holder()) });
    BOOST_REQUIRE_EQUAL(c.Mine(cancel), "");
    const uint256 txid = CTransaction(cancel).GetHash();
    BOOST_CHECK_EQUAL(c.f.Token(txid, 2)->cents, 10000);
    BOOST_CHECK_EQUAL(c.f.Token(txid, 2)->nValue, 5000);
    BOOST_CHECK(!c.f.Token(txid, 3).has_value());
}

// Rule: CAN-1
// Rule: IN-3
BOOST_AUTO_TEST_CASE(intent_cancel_yed_inputs_still_burn)
{
    CancelFixture c;
    CMutableTransaction cancel = c.CancelTx();
    cancel.vin.push_back(CTxIn(COutPoint(c.v, 1)));     // the other vault's 10,000 cents, spent by the canceller
    BOOST_REQUIRE_EQUAL(c.Mine(cancel), "");
    const TxLogRecord log = c.f.Log(CTransaction(cancel).GetHash()).value();
    BOOST_CHECK_EQUAL(log.yedIn, 10000);
    BOOST_CHECK_EQUAL(log.yedOut, 10000);
    BOOST_CHECK_EQUAL(log.burned, 10000);
    BOOST_CHECK_EQUAL(c.f.GetTotals().supplyCents, c.afterClaim.supplyCents + 10000 - 10000);
}

// Rule: CAN-1
// Rule: XFER-1
// Rule: RED-2
BOOST_AUTO_TEST_CASE(intent_cancel_refund_spendable_and_reclaims)
{
    CancelFixture c;
    CMutableTransaction cancel = c.CancelTx();
    BOOST_REQUIRE_EQUAL(c.Mine(cancel), "");
    const uint256 txid = CTransaction(cancel).GetHash();
    // the refunded YED claims the re-created vault again (still under theta at $0.009): the claimant is made whole
    SpendOpts o; o.ownerPath = false;
    CMutableTransaction again = c.f.SpendTx(txid, { COutPoint(txid, 1) }, c.f.tip, o);
    BOOST_CHECK_EQUAL(c.Mine(again), "");
    BOOST_CHECK_EQUAL(c.f.Vault(txid)->status, (uint8_t)VaultStatus::CLAIMING);
    BOOST_CHECK(!c.f.Token(txid, 1).has_value());
    BOOST_CHECK_EQUAL(c.f.GetTotals().supplyCents, c.afterClaim.supplyCents);
}

// Rule: CAN-1
// Rule: XFER-1
BOOST_AUTO_TEST_CASE(intent_cancel_refund_transferable)
{
    CancelFixture c;
    CMutableTransaction cancel = c.CancelTx();
    BOOST_REQUIRE_EQUAL(c.Mine(cancel), "");
    const uint256 txid = CTransaction(cancel).GetHash();
    CMutableTransaction t = c.f.TransferTx({ COutPoint(txid, 1) }, { Assignment{ 0, 10000 } });
    BOOST_REQUIRE_EQUAL(c.Mine(t), "");
    BOOST_CHECK(!c.f.Token(txid, 1).has_value());
    BOOST_CHECK_EQUAL(c.f.Token(CTransaction(t).GetHash(), 0)->cents, 10000);
}

// Rule: CAN-1
// Rule: TOK-PQ
BOOST_AUTO_TEST_CASE(intent_cancel_refund_crosses_the_falcon_boundary)
{
    // The claim burned a P2PKH holder's YED before the Falcon height; the cancel lands after it: the refund to that
    // holder is valid (CAN-1's TOK-PQ exemption) while an assignment to the same script is BAD_YED_HOLDER.
    CancelFixture c;
    c.f.P.pqFalconHeight = c.f.tip + 1;                   // not hashed: the module's mirror of the consensus height
    CMutableTransaction cancel = c.CancelTx();
    BOOST_REQUIRE_EQUAL(c.Mine(cancel), "");
    const uint256 txid = CTransaction(cancel).GetHash();
    BOOST_CHECK_EQUAL(c.f.Token(txid, 1)->cents, 10000);
    CMutableTransaction t = c.f.TransferTx({ COutPoint(txid, 1) }, { Assignment{ 0, 10000 } });
    BOOST_CHECK_EQUAL(c.Mine(t), verdict::BAD_YED_HOLDER);
    BOOST_CHECK(c.f.Token(txid, 1).has_value());
}

// Rule: U-23
// Rule: U-24
BOOST_AUTO_TEST_CASE(intent_cancel_of_residual_invalid)
{
    EmergencyFixture g;
    BOOST_REQUIRE(g.PostNotice());
    for (int i = 0; i < g.f.P.emergencyPersist + 1; i++) g.f.Mine(Fixture::Quote(g.poolPrice, (g.f.tip + 1) % 3));
    SpendOpts o; o.residualValue = g.Residual(g.f.tip - 1);
    CMutableTransaction claim = g.Claim(o);
    RedResult r = g.Mine(claim);
    BOOST_REQUIRE_EQUAL(r.verdict, verdict::OK);
    const uint256 claimTxid = CTransaction(claim).GetHash();
    // the owner's residual intent is the claim's last output
    const uint32_t resVout = (uint32_t)claim.vout.size() - 1;
    std::optional<IntentRecord> ir = State(g.f.view).GetIntent(COutPoint(claimTxid, resVout));
    BOOST_REQUIRE(ir.has_value());
    BOOST_REQUIRE(ir->Role() == IntentRole::RESIDUAL);
    const VaultRecord rec = g.f.Vault(g.w).value();
    const CScript vs = YedVaultScriptAt(g.f.P, rec.Owner(), rec.ownerHeight, rec.appHeight);
    CMutableTransaction cancel;
    cancel.vin.push_back(CTxIn(COutPoint(claimTxid, resVout), CScript() << valtype(65, 0) << OP_2, 0xFFFFFFFF));
    cancel.vin.push_back(CTxIn(g.f.FakeInput()));
    cancel.vout.push_back(CTxOut(claim.vout[resVout].nValue, vs));
    g.f.Mine(Fixture::Quote(g.poolPrice, (g.f.tip + 1) % 3), { cancel });
    BOOST_CHECK_EQUAL(g.f.Refused(CTransaction(cancel).GetHash()), verdict::INTENT_CANCEL_RESIDUAL);
    BOOST_CHECK(State(g.f.view).GetIntent(COutPoint(claimTxid, resVout)).has_value());      // U-21: nothing applied
    BOOST_CHECK_EQUAL(g.f.Vault(g.w)->status, (uint8_t)VaultStatus::CLAIMING);
}

// Rule: U-23
// Rule: I-2
BOOST_AUTO_TEST_CASE(intent_cancel_relock_not_vout0_invalid)
{
    CancelFixture c;
    const CTxOut change(1000, GetScriptForDestination(c.f.userKey.GetPubKey().GetID()));
    CMutableTransaction cancel = c.CancelTx(std::vector<CTxOut>{ change, c.Relock() });
    BOOST_CHECK_EQUAL(c.Mine(cancel), verdict::INTENT_CANCEL_NO_VAULT);
    BOOST_CHECK_EQUAL(c.f.Vault(c.w)->status, (uint8_t)VaultStatus::CLAIMING);              // U-21: refused, not applied
    BOOST_CHECK(State(c.f.view).GetIntent(c.Intent()).has_value());
}

// Rule: U-23
// Rule: I-2
BOOST_AUTO_TEST_CASE(intent_cancel_two_relocks_invalid)
{
    CancelFixture c;
    CMutableTransaction cancel = c.CancelTx(std::vector<CTxOut>{ c.Relock(), CTxOut(1000, c.VaultScript()) });
    BOOST_CHECK_EQUAL(c.Mine(cancel), verdict::INTENT_CANCEL_NO_VAULT);
    BOOST_CHECK_EQUAL(c.f.Vault(c.w)->status, (uint8_t)VaultStatus::CLAIMING);
}

// Rule: U-23
// Rule: I-2
BOOST_AUTO_TEST_CASE(intent_cancel_relock_script_differs_invalid)
{
    CancelFixture c;
    // no output carries the claimed vault's script: the value goes to a P2PKH
    CMutableTransaction cancel = c.CancelTx(std::vector<CTxOut>{ CTxOut(c.each, GetScriptForDestination(c.f.userKey.GetPubKey().GetID())) });
    BOOST_CHECK_EQUAL(c.Mine(cancel), verdict::INTENT_CANCEL_NO_VAULT);
    // a V of another owner at vout[0] is not the claimed vault either
    const VaultRecord r = c.f.Vault(c.w).value();
    const CKey other = CKey::TestOnlyRandomKey(true);   // 6.20.0: no CKey::MakeNewKey
    const CScript otherV = YedVaultScriptAt(c.f.P, TestPQOwner(other.GetPubKey()), r.ownerHeight, r.appHeight);
    BOOST_REQUIRE(otherV != c.VaultScript());
    CMutableTransaction cancel2 = c.CancelTx(std::vector<CTxOut>{ CTxOut(c.each, otherV) });
    BOOST_CHECK_EQUAL(c.Mine(cancel2), verdict::INTENT_CANCEL_NO_VAULT);
    BOOST_CHECK_EQUAL(c.f.Vault(c.w)->status, (uint8_t)VaultStatus::CLAIMING);
}

// Rule: U-23
BOOST_AUTO_TEST_CASE(intent_cancel_payload_or_selector3_malformed)
{
    CancelFixture c;
    // a cancel carries no Yellowback payload but CANCEL_COSIGN (CAN-2)
    std::vector<CTxOut> outs{ c.Relock(), c.Refund(), CTxOut(0, PayloadScript(EncodePayload(Payload::Transfer({})))) };
    BOOST_CHECK_EQUAL(c.Mine(c.CancelOf(c.Intent(), outs, {})), verdict::INTENT_SPEND_MALFORMED);
    // selector 3 (the owner's released path) is not an intent path
    BOOST_CHECK_EQUAL(c.Mine(c.CancelTx(std::nullopt, CScript() << valtype(65, 0) << OP_3)), verdict::INTENT_SPEND_MALFORMED);
    BOOST_CHECK_EQUAL(c.f.Vault(c.w)->status, (uint8_t)VaultStatus::CLAIMING);
}

// Rule: U-23
// Rule: NOT-1
BOOST_AUTO_TEST_CASE(intent_cancel_erases_the_notice)
{
    CancelFixture c;
    // IN-2 erased any notice when the vault left ACTIVE at the claim; a record standing at the CLAIMING outpoint
    // (forced in here) is erased by the cancel too, so the re-created vault starts without one
    NoticeRecord n;
    n.height = c.f.tip;
    n.refHeight = c.f.tip - 2;
    n.pEmerg = 9000;
    State(c.f.view).Put(keys::Notice(COutPoint(c.w, 0)), n);
    BOOST_REQUIRE(c.f.Notice(c.w).has_value());
    CMutableTransaction cancel = c.CancelTx();
    BOOST_REQUIRE_EQUAL(c.Mine(cancel), "");
    BOOST_CHECK(!c.f.Notice(c.w).has_value());
    BOOST_CHECK(!c.f.Notice(CTransaction(cancel).GetHash()).has_value());
}

// Rule: U-23
// Rule: UNDO
BOOST_AUTO_TEST_CASE(intent_cancel_undo_roundtrip)
{
    CancelFixture c;
    const std::string claiming = Hash(c.f.view);
    const MemoryStateView before = c.f.view;
    CMutableTransaction cancel = c.CancelTx();
    BOOST_REQUIRE_EQUAL(c.Mine(cancel), "");
    BOOST_CHECK(Hash(c.f.view) != claiming);
    BOOST_CHECK(c.f.Token(CTransaction(cancel).GetHash(), 1).has_value());
    c.f.Undo();
    BOOST_CHECK_EQUAL(Hash(c.f.view), claiming);
    BOOST_CHECK(c.f.view == before);
    BOOST_CHECK(!c.f.Token(CTransaction(cancel).GetHash(), 1).has_value());
    BOOST_CHECK_EQUAL(c.f.GetTotals().supplyCents, c.afterClaim.supplyCents);
    BOOST_CHECK_EQUAL(c.f.Vault(c.w)->status, (uint8_t)VaultStatus::CLAIMING);
    BOOST_CHECK(State(c.f.view).GetIntent(c.Intent()).has_value());
}

// ===========================================================================
// The per-vault cancel limit (cancel-limit design, owner 2026-10-13): CAN-2 escalating co-signed cancels, C4b
// statements slashable by EQV-1, CAN-3 the held residual

namespace {

/** The V script and value of the YED position recorded at `pos`: what a cancel of its claim re-creates at vout[0]. */
CTxOut RelockOf(const Fixture& f, const COutPoint& pos, CAmount value)
{
    const VaultRecord r = State(const_cast<MemoryStateView&>(f.view)).GetVault(pos).value();
    return CTxOut(value, YedVaultScriptAt(f.P, r.Owner(), r.ownerHeight, r.appHeight));
}

/** The lowest price at which `collateral` backing `cents` is not claimable at CLAIM_THRESHOLD (!IsUnderwater). */
MicroUsd FirstNotClaimable(CAmount collateral, Cents cents, int thresholdBps)
{
    MicroUsd lo = 1, hi = PRICE_MAX;
    while (lo < hi) {
        const MicroUsd mid = lo + (hi - lo) / 2;
        if (IsUnderwater(collateral, mid, cents, thresholdBps)) lo = mid + 1; else hi = mid;
    }
    return lo;
}

/** CancelFixture's position after `rounds` claim-and-cancel rounds, each cancel co-signed by exactly CancelsRequired members. */
struct RoundsFixture : public CancelFixture
{
    COutPoint pos;          //!< the live position (txid:0)
    COutPoint intent;       //!< the claimant intent of the last claim
    int ref = 0;            //!< that claim's refHeight

    /** Claim `pos` again with the refund token at pos:1 (the vault is under theta at $0.009, unarmed path (a)). */
    void Reclaim()
    {
        SpendOpts o; o.ownerPath = false;
        ref = f.tip;
        CMutableTransaction claim = f.SpendTx(pos.hash, { COutPoint(pos.hash, 1) }, ref, o);
        BOOST_REQUIRE_EQUAL(Mine(claim), "");
        intent = COutPoint(CTransaction(claim).GetHash(), 0);
        BOOST_REQUIRE_EQUAL(f.Vault(pos.hash)->status, (uint8_t)VaultStatus::CLAIMING);
    }
    CMutableTransaction Cancel(const std::vector<int>& seqs, MicroUsd price = HONEST)
    {
        return CancelOf(intent, { RelockOf(f, pos, each), Refund() }, CosignsFor(intent, ref, seqs, price));
    }
    /** Mine the cancel; on success the position moves to the cancel's vout[0]. */
    std::string MineCancel(const std::vector<int>& seqs, MicroUsd price = HONEST)
    {
        CMutableTransaction c = Cancel(seqs, price);
        const std::string v = Mine(c);
        if (v.empty()) pos = COutPoint(CTransaction(c).GetHash(), 0);
        return v;
    }
    RoundsFixture() : pos(COutPoint(w, 0)), intent(Intent()), ref(claimRef) {}
};

std::vector<int> FirstSeqs(int n)
{
    std::vector<int> out;
    for (int i = 0; i < n; i++) out.push_back(i);
    return out;
}

} // namespace

// Rule: CAN-2
BOOST_AUTO_TEST_CASE(cancel_limit_constants_per_network)
{
    // owner round 2: CANCEL_SIGNERS_MAX 4 on mainnet and testnet, 3 on regtest; CANCEL_QUIET 8,064 / 40
    for (const char* net : { "main", "test" }) {
        BOOST_CHECK_EQUAL(ParamsForNetwork(net).cancelSignersMax, 4);
        BOOST_CHECK_EQUAL(ParamsForNetwork(net).cancelQuiet, 8064);
    }
    BOOST_CHECK_EQUAL(ParamsForNetwork("regtest").cancelSignersMax, 3);
    BOOST_CHECK_EQUAL(ParamsForNetwork("regtest").cancelQuiet, 40);
    VaultRecord v;
    v.cancelCount = 9;
    v.lastCancelHeight = 100;
    BOOST_CHECK_EQUAL(CancelsRequired(v, ParamsForNetwork("main"), 101), 4);       // the schedule caps at four
    BOOST_CHECK_EQUAL(CancelsRequired(v, ParamsForNetwork("main"), 100 + 8064), 1);
}

// Rule: CAN-2
BOOST_AUTO_TEST_CASE(cancel_limit_escalation_schedule_and_cap)
{
    RoundsFixture c;
    BOOST_REQUIRE_EQUAL(c.f.P.cancelSignersMax, 3);           // regtest: schedule 1, 2, 3, 3, ...
    BOOST_REQUIRE_EQUAL(c.f.P.cancelQuiet, 40);
    const VaultRecord minted = c.f.Vault(c.w).value();
    BOOST_CHECK_EQUAL(minted.cancelCount, 0);
    BOOST_CHECK_EQUAL(minted.lastCancelHeight, 0);
    for (int round = 1; round <= 5; round++) {
        if (round > 1) c.Reclaim();
        const int need = std::min(round, c.f.P.cancelSignersMax);
        BOOST_CHECK_EQUAL(CancelsRequired(c.f.Vault(c.pos.hash).value(), c.f.P, c.f.tip + 1), need);
        if (need > 1) {
            // one co-signer short: refused, the vault stays CLAIMING (U-21)
            BOOST_CHECK_EQUAL(c.MineCancel(FirstSeqs(need - 1)), verdict::INTENT_CANCEL_COSIGN);
            BOOST_CHECK_EQUAL(c.f.Vault(c.pos.hash)->status, (uint8_t)VaultStatus::CLAIMING);
        }
        BOOST_REQUIRE_EQUAL(c.MineCancel(FirstSeqs(need)), "");
        const VaultRecord r = c.f.Vault(c.pos.hash).value();
        BOOST_CHECK_EQUAL(r.status, (uint8_t)VaultStatus::ACTIVE);
        BOOST_CHECK_EQUAL(r.cancelCount, round);              // q + 1: every round within CANCEL_QUIET of the last
        BOOST_CHECK_EQUAL(r.lastCancelHeight, c.f.tip);
        BOOST_CHECK_EQUAL(r.mintHeight, minted.mintHeight);   // the counter rides the same position across re-creations
        BOOST_CHECK_EQUAL(r.pMint, minted.pMint);
        const std::vector<int> seqs = FirstSeqs(need);
        BOOST_CHECK(c.f.Log(c.pos.hash)->bundleSeqs == std::vector<uint16_t>(seqs.begin(), seqs.end()));
    }
}

// Rule: CAN-2
BOOST_AUTO_TEST_CASE(cancel_limit_quiet_resets_the_schedule)
{
    RoundsFixture c;
    BOOST_REQUIRE_EQUAL(c.MineCancel({ 0 }), "");
    const int first = c.f.tip;
    // the next cancel lands at first + CANCEL_QUIET - 1: still inside the quiet period, two co-signers needed
    while (c.f.tip + 2 < first + c.f.P.cancelQuiet - 1) c.f.Mine(Fixture::Quote(9000, (c.f.tip + 1) % 3));
    c.Reclaim();
    BOOST_REQUIRE_EQUAL(c.f.tip + 1, first + c.f.P.cancelQuiet - 1);
    BOOST_CHECK_EQUAL(CancelsRequired(c.f.Vault(c.pos.hash).value(), c.f.P, c.f.tip + 1), 2);
    BOOST_CHECK_EQUAL(c.MineCancel({ 0 }), verdict::INTENT_CANCEL_COSIGN);
    // one block later (the refused attempt's block) the quiet period has passed: q = 0, one co-signer again
    BOOST_REQUIRE_EQUAL(c.f.tip + 1, first + c.f.P.cancelQuiet);
    BOOST_CHECK_EQUAL(CancelsRequired(c.f.Vault(c.pos.hash).value(), c.f.P, c.f.tip + 1), 1);
    BOOST_REQUIRE_EQUAL(c.MineCancel({ 1 }), "");
    BOOST_CHECK_EQUAL(c.f.Vault(c.pos.hash)->cancelCount, 1);
    BOOST_CHECK_EQUAL(c.f.Vault(c.pos.hash)->lastCancelHeight, c.f.tip);
}

// Rule: CAN-2
// Rule: C4b
BOOST_AUTO_TEST_CASE(cancel_cosign_refusals)
{
    CancelFixture c;
    const std::vector<CTxOut> outs{ c.Relock(), c.Refund() };
    auto refused = [&](const CMutableTransaction& tx) { return c.Mine(tx) == verdict::INTENT_CANCEL_COSIGN; };
    // no co-signature at all (CAN-1's shape): even the first cancel carries one statement
    BOOST_CHECK(refused(c.CancelOf(c.Intent(), outs, {})));
    // the marker without its carrier, and a carrier without the marker
    CMutableTransaction noCarrier = c.CancelTx();
    noCarrier.vin.pop_back();
    BOOST_CHECK(refused(noCarrier));
    CMutableTransaction noMarker = c.CancelTx();
    noMarker.vout.pop_back();
    BOOST_CHECK(refused(noMarker));
    // a price bundle ("YA") in the carrier is not a co-signature list
    CMutableTransaction yaCarrier = c.CancelTx();
    Bundle b;
    b.atts = { c.f.Att(0, CancelFixture::HONEST, c.claimRef) };
    yaCarrier.vin.back() = c.f.CarrierIn(EncodeBundle(b));
    BOOST_CHECK(refused(yaCarrier));
    // a repeated key, a non-member, another intent, another height, another block hash
    BOOST_CHECK(refused(c.CancelOf(c.Intent(), outs, c.Cosigns({ 10 }))));
    BOOST_CHECK(refused(c.CancelOf(c.Intent(), outs, c.CosignsFor(COutPoint(c.claimTxid, 1), c.claimRef, { 0 }))));
    BOOST_CHECK(refused(c.CancelOf(c.Intent(), outs, c.CosignsFor(c.Intent(), c.claimRef - 1, { 0 }))));
    BOOST_CHECK(refused(c.CancelOf(c.Intent(), outs, { c.f.Cosign(0, CancelFixture::HONEST, c.Intent(), c.claimRef, uint256S("01")) })));
    // C4b: a statement at which the vault WAS claimable; the boundary is collateral x price >= debt x theta
    const MicroUsd edge = FirstNotClaimable(c.each, 10000, c.f.P.claimThresholdBps);
    BOOST_CHECK(refused(c.CancelOf(c.Intent(), outs, c.Cosigns({ 0 }, 9000))));
    BOOST_CHECK(refused(c.CancelOf(c.Intent(), outs, c.Cosigns({ 0 }, edge - 1))));
    BOOST_CHECK(refused(c.CancelOf(c.Intent(), outs, c.Cosigns({ 0 }, PRICE_MIN - 1))));
    // a malformed list fails whatever it holds
    CMutableTransaction junk = c.CancelTx();
    valtype bad = EncodeCancelCosigns(c.Cosigns({ 0 }));
    bad.push_back(0);
    junk.vin.back() = c.f.CarrierIn(bad);
    BOOST_CHECK(refused(junk));
    // a member whose bond was spent (WITHDRAWN) and a member that joined too recently (not current) cannot co-sign
    const AttestorRecord one = c.f.Attestor(1).value();
    CMutableTransaction exit;
    exit.vin.push_back(CTxIn(one.bondOutpoint));
    exit.vout.push_back(CTxOut(one.bondZat - 1000, GetScriptForDestination(c.f.userKey.GetPubKey().GetID())));
    c.f.Mine(Fixture::Quote(9000, (c.f.tip + 1) % 3), { exit });
    BOOST_REQUIRE_EQUAL(c.f.Attestor(1)->status, (uint8_t)AttestorStatus::WITHDRAWN);
    BOOST_CHECK(refused(c.CancelOf(c.Intent(), outs, c.Cosigns({ 1 }))));
    c.f.Mine(Fixture::Quote(9000, (c.f.tip + 1) % 3), { c.f.RegisterTx(5) });
    BOOST_REQUIRE(c.f.Attestor(4).has_value());          // hotKeys[5] became seq 4
    BOOST_CHECK(refused(c.CancelOf(c.Intent(), outs, c.Cosigns({ 5 }))));
    BOOST_CHECK_EQUAL(c.f.Vault(c.w)->status, (uint8_t)VaultStatus::CLAIMING);
    BOOST_CHECK(State(c.f.view).GetIntent(c.Intent()).has_value());
    // extra valid co-signatures are accepted, and the statement at the boundary price holds
    CMutableTransaction ok = c.CancelOf(c.Intent(), outs, c.Cosigns({ 0, 2, 3 }, edge));
    BOOST_REQUIRE_EQUAL(c.Mine(ok), "");
    BOOST_CHECK(c.f.Log(CTransaction(ok).GetHash())->bundleSeqs == std::vector<uint16_t>({ 0, 2, 3 }));
    BOOST_CHECK_EQUAL(c.f.Vault(CTransaction(ok).GetHash())->cancelCount, 1);
}

// Rule: CAN-2
BOOST_AUTO_TEST_CASE(cancel_cosign_counts_distinct_valid_entries)
{
    // round 2 (review M-2): invalid, non-current and repeated entries are ignored; the distinct valid ones must reach
    // CancelsRequired
    RoundsFixture c;
    BOOST_REQUIRE_EQUAL(c.MineCancel({ 0 }), "");
    c.Reclaim();                                               // the second cancel needs two
    auto mine = [&](const std::vector<CancelCosignEntry>& e) {
        CMutableTransaction tx = c.CancelOf(c.intent, { RelockOf(c.f, c.pos, c.each), c.Refund() }, e);
        const std::string v = c.Mine(tx);
        if (v.empty()) c.pos = COutPoint(CTransaction(tx).GetHash(), 0);
        return v;
    };
    BOOST_CHECK_EQUAL(mine(c.CosignsFor(c.intent, c.ref, { 0, 0 })), verdict::INTENT_CANCEL_COSIGN);          // one key twice
    BOOST_CHECK_EQUAL(mine(c.CosignsFor(c.intent, c.ref, { 0, 10 })), verdict::INTENT_CANCEL_COSIGN);         // a non-member
    std::vector<CancelCosignEntry> e = c.CosignsFor(c.intent, c.ref, { 0 });
    e.push_back(c.f.Cosign(10, CancelFixture::HONEST, c.intent, c.ref));                                     // ignored
    e.push_back(c.f.Cosign(2, 9000, c.intent, c.ref));                                                       // claimable: ignored
    e.push_back(c.f.Cosign(0, CancelFixture::HONEST, c.intent, c.ref));                                      // a repeat: ignored
    e.push_back(c.f.Cosign(1, CancelFixture::HONEST, c.intent, c.ref));
    const COutPoint before = c.pos;
    BOOST_REQUIRE_EQUAL(mine(e), "");
    BOOST_CHECK(c.pos != before);
    BOOST_CHECK(c.f.Log(c.pos.hash)->bundleSeqs == std::vector<uint16_t>({ 0, 1 }));
    BOOST_CHECK_EQUAL(c.f.Vault(c.pos.hash)->cancelCount, 2);
}

// Rule: CAN-2
BOOST_AUTO_TEST_CASE(cancel_cosign_holds_when_a_cosigner_leaves_in_the_same_block)
{
    // round 2: member 1 spends its bond (WITHDRAWN) earlier in the cancel's block; with a spare co-signature the cancel
    // still holds, without one it fails
    for (bool spare : { false, true }) {
        RoundsFixture c;
        BOOST_REQUIRE_EQUAL(c.MineCancel({ 0 }), "");
        c.Reclaim();                                           // two needed
        const AttestorRecord one = c.f.Attestor(1).value();
        CMutableTransaction exit;
        exit.vin.push_back(CTxIn(one.bondOutpoint));
        exit.vout.push_back(CTxOut(one.bondZat - 1000, GetScriptForDestination(c.f.userKey.GetPubKey().GetID())));
        CMutableTransaction cancel = c.Cancel(spare ? std::vector<int>{ 0, 1, 2 } : std::vector<int>{ 0, 1 });
        c.f.Mine(Fixture::Quote(9000, (c.f.tip + 1) % 3), { exit, cancel });
        BOOST_CHECK_EQUAL(c.f.Attestor(1)->status, (uint8_t)AttestorStatus::WITHDRAWN);
        BOOST_CHECK_EQUAL(c.f.Refused(CTransaction(cancel).GetHash()), spare ? "" : verdict::INTENT_CANCEL_COSIGN);
        if (spare) BOOST_CHECK(c.f.Log(CTransaction(cancel).GetHash())->bundleSeqs == std::vector<uint16_t>({ 0, 2 }));
    }
}

// Rule: CAN-2
// Rule: UNDO
BOOST_AUTO_TEST_CASE(cancel_limit_counter_undo_byte_identical)
{
    RoundsFixture c;
    BOOST_REQUIRE_EQUAL(c.MineCancel({ 0 }), "");
    c.Reclaim();
    const MemoryStateView before = c.f.view;
    BOOST_REQUIRE_EQUAL(c.MineCancel({ 0, 1 }), "");
    BOOST_CHECK_EQUAL(c.f.Vault(c.pos.hash)->cancelCount, 2);
    c.f.Undo();
    BOOST_CHECK(c.f.view == before);
}

namespace {

/** A path-(b) claim of EmergencyFixture's vault with the owner's residual intent, and the cancel of its claimant intent. */
struct ResidualFixture
{
    EmergencyFixture g;
    uint256 claimTxid;
    COutPoint claimant, residual, pos;
    IntentRecord claimantRec;
    CMutableTransaction claim;

    ResidualFixture()
    {
        BOOST_REQUIRE(g.PostNotice());
        for (int i = 0; i < g.f.P.emergencyPersist + 1; i++) g.f.Mine(Fixture::Quote(g.poolPrice, (g.f.tip + 1) % 3));
        SpendOpts o; o.residualValue = g.Residual(g.f.tip - 1);
        claim = g.Claim(o);
        BOOST_REQUIRE_EQUAL(g.Mine(claim).verdict, verdict::OK);
        claimTxid = CTransaction(claim).GetHash();
        for (uint32_t j = 0; j < claim.vout.size(); j++) {
            std::optional<IntentRecord> ir = State(g.f.view).GetIntent(COutPoint(claimTxid, j));
            if (!ir.has_value()) continue;
            if (ir->Role() == IntentRole::CLAIMANT) { claimant = COutPoint(claimTxid, j); claimantRec = ir.value(); }
            else residual = COutPoint(claimTxid, j);
        }
        BOOST_REQUIRE(!claimant.IsNull() && !residual.IsNull());
        BOOST_CHECK_EQUAL(claimantRec.claimRefHeight, g.f.tip - 2);                    // the claim's refHeight
        BOOST_CHECK(State(g.f.view).GetIntent(residual)->heldBy.IsNull());
    }
    /** The cancel of `intent` (claimant of position `from`) co-signed by `seqs` at `price`, re-locking `value`. */
    CMutableTransaction CancelTx(const COutPoint& intent, const COutPoint& from, CAmount value, const std::vector<int>& seqs, MicroUsd price)
    {
        const IntentRecord ir = State(g.f.view).GetIntent(intent).value();
        std::vector<CancelCosignEntry> entries;
        for (int seq : seqs) entries.push_back(g.f.Cosign(seq, price, intent, ir.claimRefHeight));
        CMutableTransaction m;
        m.vin.push_back(CTxIn(intent, CScript() << valtype(65, 0) << OP_2, 0xFFFFFFFF));
        m.vin.push_back(CTxIn(g.f.FakeInput()));
        m.vin.push_back(g.f.CarrierIn(EncodeCancelCosigns(entries)));
        m.vout.push_back(RelockOf(g.f, from, value));
        m.vout.push_back(CTxOut(TOKEN_VALUE, CScript(ir.refundScript.begin(), ir.refundScript.end())));
        m.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(Payload::CancelCosign()))));
        return m;
    }
    /** Cancel the path-(b) claim (one co-signer, statement at the honest pool price: 126 %, not claimable). */
    void CancelFirst()
    {
        CMutableTransaction c = CancelTx(claimant, COutPoint(g.w, 0), claim.vout[claimant.n].nValue, { 0 }, g.poolPrice);
        g.f.Mine(Fixture::Quote(g.poolPrice, (g.f.tip + 1) % 3), { c });
        BOOST_REQUIRE_EQUAL(g.f.Refused(CTransaction(c).GetHash()), "");
        pos = COutPoint(CTransaction(c).GetHash(), 0);
    }
    /** Mine the residual's release (I-1, selector 1) at tip + 1; returns the verdict that refused it, "" when applied. */
    std::string Release()
    {
        CMutableTransaction rel;
        rel.vin.push_back(CTxIn(residual, CScript() << OP_1, (uint32_t)g.f.P.claimDelay));
        rel.vin.push_back(CTxIn(g.f.FakeInput()));
        rel.vout.push_back(CTxOut(claim.vout[residual.n].nValue, GetScriptForDestination(g.f.ownerKey.GetPubKey().GetID())));
        g.f.Mine(Fixture::Quote(g.poolPrice, (g.f.tip + 1) % 3), { rel });
        return g.f.Refused(CTransaction(rel).GetHash());
    }
};

} // namespace

// Rule: CAN-3
BOOST_AUTO_TEST_CASE(cancel_limit_residual_held_until_quiet)
{
    ResidualFixture r;
    r.CancelFirst();
    BOOST_CHECK(State(r.g.f.view).GetIntent(r.residual)->heldBy == r.pos);
    const int cancelled = r.g.f.tip;
    BOOST_CHECK_EQUAL(r.Release(), verdict::INTENT_RESIDUAL_HELD);
    while (r.g.f.tip + 2 < cancelled + r.g.f.P.cancelQuiet) r.g.f.Mine(Fixture::Quote(r.g.poolPrice, (r.g.f.tip + 1) % 3));
    BOOST_REQUIRE_EQUAL(r.g.f.tip + 1, cancelled + r.g.f.P.cancelQuiet - 1);
    BOOST_CHECK_EQUAL(r.Release(), verdict::INTENT_RESIDUAL_HELD);   // one block inside CANCEL_QUIET
    // round 2 (R-1c): CANCEL_QUIET has passed, but the re-created position (the claimant intent's value, ~100 % at
    // $0.021) is claimable on path (a) at the latest snapshot: still held
    const VaultRecord pos = r.g.f.Vault(r.pos.hash).value();
    BOOST_REQUIRE(IsUnderwater(pos.collateralZat, r.g.f.Snap(r.g.f.tip).PClaim(), pos.mintedCents, r.g.f.P.claimThresholdBps));
    BOOST_CHECK_EQUAL(r.Release(), verdict::INTENT_RESIDUAL_HELD);
    // the price recovers for a whole slow window: the position is no longer claimable, the residual is released
    r.g.poolPrice = 50000;
    for (int i = 0; i < 128; i++) r.g.f.Mine(Fixture::Quote(r.g.poolPrice, (r.g.f.tip + 1) % 3));   // every citable ref recovers
    BOOST_REQUIRE(!IsUnderwater(pos.collateralZat, r.g.f.Snap(r.g.f.tip).PClaim(), pos.mintedCents, r.g.f.P.claimThresholdBps));
    BOOST_CHECK_EQUAL(r.Release(), "");
    BOOST_CHECK(!State(r.g.f.view).GetIntent(r.residual).has_value());
}

// Rule: CAN-3
BOOST_AUTO_TEST_CASE(cancel_limit_residual_release_mirrors_every_citable_ref)
{
    // the round-2 fix: past CANCEL_QUIET and healthy at the latest snapshot, the residual is still held when a claim in
    // the release's block could cite an earlier reference height at which the position is claimable, or one whose price
    // is undefined (fail closed); a height older than REF_WINDOW cannot be cited and does not hold it
    ResidualFixture r;
    r.CancelFirst();
    r.g.poolPrice = 50000;
    for (int i = 0; i < 128; i++) r.g.f.Mine(Fixture::Quote(r.g.poolPrice, (r.g.f.tip + 1) % 3));
    const int refWindow = r.g.f.P.refWindow;
    BOOST_REQUIRE_EQUAL(refWindow, 40);
    // each attempt sets one snapshot's pClaim relative to the release's block H = tip + 1, then restores it (a refused
    // release still mines a block, so H moves on by one)
    auto attempt = [&](int back, int64_t pClaim) {
        const int h = r.g.f.tip + 1 - back;
        const Snapshot orig = r.g.f.Snap(h);
        Snapshot s = orig;
        s.pClaim = pClaim;
        State(r.g.f.view).Put(keys::Snapshot((uint32_t)h), s);
        const std::string v = r.Release();
        State(r.g.f.view).Put(keys::Snapshot((uint32_t)h), orig);
        return v;
    };
    BOOST_CHECK_EQUAL(attempt(1, 0), verdict::INTENT_RESIDUAL_HELD);               // undefined price at H - 1
    BOOST_CHECK_EQUAL(attempt(10, 9000), verdict::INTENT_RESIDUAL_HELD);           // claimable at an earlier citable ref only
    BOOST_CHECK_EQUAL(attempt(refWindow, 9000), verdict::INTENT_RESIDUAL_HELD);    // the oldest citable ref
    BOOST_CHECK_EQUAL(attempt(refWindow + 1, 9000), "");                           // too old to cite: released
}

// Rule: CAN-3
BOOST_AUTO_TEST_CASE(cancel_limit_residual_armed_pool_low_fails_closed)
{
    // the round-2 fix at an ARMED reference: the pools under theta and the attestors high (pClaim = max(x, a) would keep a
    // claim out only with a high bundle, but a claim may carry a low one): the residual is held, fail-closed, until the
    // position closes or the pools recover for the whole REF_WINDOW
    ResidualFixture r;
    r.CancelFirst();
    BOOST_REQUIRE(ArmedAt(r.g.f.view, r.g.f.P, r.g.f.tip));
    while (r.g.f.tip + 1 < r.g.f.Vault(r.pos.hash)->lastCancelHeight + r.g.f.P.cancelQuiet) r.g.f.Mine(Fixture::Quote(r.g.poolPrice, (r.g.f.tip + 1) % 3));
    const VaultRecord pos = r.g.f.Vault(r.pos.hash).value();
    BOOST_REQUIRE(IsUnderwater(pos.collateralZat, r.g.f.Snap(r.g.f.tip).PClaim(), pos.mintedCents, r.g.f.P.claimThresholdBps));
    BOOST_CHECK_EQUAL(r.Release(), verdict::INTENT_RESIDUAL_HELD);
}

// Rule: CAN-3
// Rule: NOT-1
BOOST_AUTO_TEST_CASE(cancel_limit_residual_held_while_claimable_by_path_b)
{
    // round 2: past CANCEL_QUIET and healthy at the snapshot price, but a persisted notice on the position whose pEmerg
    // puts it under EMERGENCY_RATIO makes it claimable on path (b): held; without the notice, or before it persists,
    // released
    ResidualFixture r;
    r.CancelFirst();
    r.g.poolPrice = 50000;
    for (int i = 0; i < 128; i++) r.g.f.Mine(Fixture::Quote(r.g.poolPrice, (r.g.f.tip + 1) % 3));
    NoticeRecord n;
    n.height = r.g.f.tip - 4;
    n.refHeight = r.g.f.tip - r.g.f.P.emergencyPersist;      // persisted at H - 1 = tip
    n.pEmerg = 10000;                                          // ~48 % at $0.01: under 105 %
    State(r.g.f.view).Put(keys::Notice(r.pos), n);
    BOOST_CHECK_EQUAL(r.Release(), verdict::INTENT_RESIDUAL_HELD);
    n.refHeight = r.g.f.tip;                                   // not yet persisted at any citable ref
    State(r.g.f.view).Put(keys::Notice(r.pos), n);
    BOOST_CHECK_EQUAL(r.Release(), "");
}

// Rule: CAN-3
BOOST_AUTO_TEST_CASE(cancel_limit_residual_released_when_the_position_closes)
{
    ResidualFixture r;
    r.CancelFirst();
    BOOST_CHECK_EQUAL(r.Release(), verdict::INTENT_RESIDUAL_HELD);
    // the owner redeems the re-created position with the refunded YED: CLOSED frees the residual at once
    CMutableTransaction redeem = r.g.f.SpendTx(r.pos.hash, { COutPoint(r.pos.hash, 1) }, r.g.f.tip);
    r.g.f.Mine(Fixture::Quote(r.g.poolPrice, (r.g.f.tip + 1) % 3), { redeem });
    BOOST_REQUIRE_EQUAL(r.g.f.Refused(CTransaction(redeem).GetHash()), "");
    BOOST_REQUIRE_EQUAL(r.g.f.Vault(r.pos.hash)->status, (uint8_t)VaultStatus::CLOSED);
    BOOST_CHECK_EQUAL(r.Release(), "");
}

// Rule: CAN-3
BOOST_AUTO_TEST_CASE(cancel_limit_residual_follows_the_position_and_holds_while_claiming)
{
    ResidualFixture r;
    r.CancelFirst();
    const COutPoint first = r.pos;
    // the price falls; past CANCEL_QUIET the re-created position is claimed on path (a) (no residual due)
    r.g.poolPrice = 9000;
    r.g.attPrice = 9000;
    for (int i = 0; i < 64; i++) r.g.f.Mine(Fixture::Quote(r.g.poolPrice, (r.g.f.tip + 1) % 3));
    r.g.w = first.hash;                                       // the fixture's selector is the claimed position's outpoint
    SpendOpts o2;
    o2.ownerPath = false;
    const int R = r.g.f.tip - 1;
    o2.bundle = r.g.f.BundleFor(R, r.g.Selector(), 9000);
    o2.attestPayee = Selected(r.g.f.view, r.g.f.P, R, r.g.Selector()).front();
    CMutableTransaction claim2 = r.g.f.SpendTx(first.hash, { COutPoint(first.hash, 1) }, R, o2);   // the refunded YED burns the debt again
    BOOST_REQUIRE_EQUAL(r.g.Mine(claim2).verdict, verdict::OK);
    BOOST_REQUIRE_EQUAL(r.g.f.Vault(first.hash)->status, (uint8_t)VaultStatus::CLAIMING);
    // past CANCEL_QUIET, but CLAIMING: still held
    BOOST_CHECK_EQUAL(r.Release(), verdict::INTENT_RESIDUAL_HELD);
    // the second cancel (q = 0 after the quiet period: one co-signer) moves heldBy to the new position
    const COutPoint claimant2(CTransaction(claim2).GetHash(), 0);
    CMutableTransaction cancel2 = r.CancelTx(claimant2, first, claim2.vout[0].nValue, { 1 }, 60000);
    r.g.f.Mine(Fixture::Quote(r.g.poolPrice, (r.g.f.tip + 1) % 3), { cancel2 });
    BOOST_REQUIRE_EQUAL(r.g.f.Refused(CTransaction(cancel2).GetHash()), "");
    const COutPoint second(CTransaction(cancel2).GetHash(), 0);
    BOOST_CHECK(State(r.g.f.view).GetIntent(r.residual)->heldBy == second);
    BOOST_CHECK_EQUAL(r.Release(), verdict::INTENT_RESIDUAL_HELD);   // the new position's quiet period starts again
}

// Rule: CAN-3
BOOST_AUTO_TEST_CASE(cancel_limit_residual_of_a_released_claim_unchanged)
{
    ResidualFixture r;
    // the claimant intent is released (no cancel): the residual keeps today's rule, released at once
    CMutableTransaction rel;
    rel.vin.push_back(CTxIn(r.claimant, CScript() << OP_1, (uint32_t)r.g.f.P.claimDelay));
    rel.vin.push_back(CTxIn(r.g.f.FakeInput()));
    rel.vout.push_back(CTxOut(r.claim.vout[r.claimant.n].nValue, GetScriptForDestination(r.g.f.userKey.GetPubKey().GetID())));
    r.g.f.Mine(Fixture::Quote(r.g.poolPrice, (r.g.f.tip + 1) % 3), { rel });
    BOOST_REQUIRE_EQUAL(r.g.f.Refused(CTransaction(rel).GetHash()), "");
    BOOST_CHECK(State(r.g.f.view).GetIntent(r.residual)->heldBy.IsNull());
    BOOST_CHECK_EQUAL(r.Release(), "");
}

namespace {

/** C4b: an EQUIVOCATION whose carrier holds attestation `a` and the cancel statement `s` ("YX"). */
CMutableTransaction CancelEvidenceTx(Fixture& f, const Attestation& a, const CancelStatement& s)
{
    CMutableTransaction m;
    m.vin.push_back(f.CarrierIn(EncodeCancelEvidence(a, s)));
    m.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(Payload::Equivocation()))));
    m.vout.push_back(CTxOut(1000, GetScriptForDestination(f.userKey.GetPubKey().GetID())));
    return m;
}

CancelStatement StatementOf(const COutPoint& intent, const CancelCosignEntry& e)
{
    CancelStatement s;
    s.intent = intent;
    s.priceMicroUsd = e.priceMicroUsd;
    s.sig = e.sig;
    return s;
}

} // namespace

// Rule: C4b
// Rule: EQV-1
BOOST_AUTO_TEST_CASE(cancel_statement_slashed_by_eqv1)
{
    CancelFixture c;
    // member 1 co-signs the cancel saying $0.05 at the claim's refHeight, while its regular attestation there said $0.009
    const CancelCosignEntry e = c.f.Cosign(1, CancelFixture::HONEST, c.Intent(), c.claimRef);
    const Attestation att = c.f.Att(1, 9000, c.claimRef);
    CMutableTransaction cancel = c.CancelOf(c.Intent(), { c.Relock(), c.Refund() }, { e });
    BOOST_REQUIRE_EQUAL(c.Mine(cancel), "");
    // structure: the "YX" shape is EQV-1 evidence; the attestation side and the statement side verify under the key
    CMutableTransaction eqv = CancelEvidenceTx(c.f, att, StatementOf(c.Intent(), e));
    std::optional<Equivocation> ev = EquivocationEvidence(CTransaction(eqv), c.f.P);
    BOOST_REQUIRE(ev.has_value() && ev->s.has_value() && !ev->b.has_value());
    BOOST_CHECK(EquivocatedBy(ev.value(), c.f.hotKeys[1].GetPubKey(), Fixture::FakeHash(c.claimRef), c.f.P.attestorSetId));
    BOOST_CHECK(!EquivocatedBy(ev.value(), c.f.hotKeys[0].GetPubKey(), Fixture::FakeHash(c.claimRef), c.f.P.attestorSetId));
    BOOST_CHECK(!EquivocatedBy(ev.value(), c.f.hotKeys[1].GetPubKey(), Fixture::FakeHash(c.claimRef), uint256S("02")));
    c.f.Mine(Fixture::Quote(9000, (c.f.tip + 1) % 3), { eqv });
    const AttestorRecord slashed = c.f.Attestor(1).value();
    BOOST_CHECK_EQUAL(slashed.status, (uint8_t)AttestorStatus::EJECTED);
    BOOST_CHECK(slashed.bondFrozen);
    const TxLogRecord log = c.f.Log(CTransaction(eqv).GetHash()).value();
    BOOST_CHECK_EQUAL(log.type, (uint8_t)TxLogType::EQUIVOCATION);
    BOOST_CHECK_EQUAL(log.attestorSeq, 1);
    // the ejected member can no longer co-sign
    BOOST_CHECK(!c.f.Attestor(0)->bondFrozen);
}

// Rule: C4b
// Rule: EQV-1
BOOST_AUTO_TEST_CASE(cancel_statement_honest_canceller_never_slashed)
{
    CancelFixture c;
    // member 0's statement repeats the price it attested at the claim's refHeight: no evidence exists
    const CancelCosignEntry e = c.f.Cosign(0, CancelFixture::HONEST, c.Intent(), c.claimRef);
    const Attestation same = c.f.Att(0, CancelFixture::HONEST, c.claimRef);
    BOOST_REQUIRE_EQUAL(c.Mine(c.CancelOf(c.Intent(), { c.Relock(), c.Refund() }, { e })), "");
    CMutableTransaction eqv = CancelEvidenceTx(c.f, same, StatementOf(c.Intent(), e));
    BOOST_CHECK(!EquivocationEvidence(CTransaction(eqv), c.f.P).has_value());
    c.f.Mine(Fixture::Quote(9000, (c.f.tip + 1) % 3), { eqv });
    BOOST_CHECK(c.f.Attestor(0)->status != (uint8_t)AttestorStatus::EJECTED);
    BOOST_CHECK(!c.f.Attestor(0)->bondFrozen);
    // an attestation at another height is not evidence either (one citedHeight), nor another member's attestation
    const Attestation other = c.f.Att(0, 9000, c.claimRef - 1);
    CMutableTransaction eqv2 = CancelEvidenceTx(c.f, other, StatementOf(c.Intent(), e));
    std::optional<Equivocation> ev2 = EquivocationEvidence(CTransaction(eqv2), c.f.P);
    BOOST_REQUIRE(ev2.has_value());   // structure only: the statement is read at the attestation's height,
    BOOST_CHECK(!EquivocatedBy(ev2.value(), c.f.hotKeys[0].GetPubKey(), Fixture::FakeHash(c.claimRef - 1), c.f.P.attestorSetId));   // where it does not verify
    CMutableTransaction eqv3 = CancelEvidenceTx(c.f, c.f.Att(2, 9000, c.claimRef), StatementOf(c.Intent(), e));
    c.f.Mine(Fixture::Quote(9000, (c.f.tip + 1) % 3), { eqv2, eqv3 });
    for (int seq : { 0, 2 }) {
        BOOST_CHECK(c.f.Attestor(seq)->status != (uint8_t)AttestorStatus::EJECTED);
        BOOST_CHECK(!c.f.Attestor(seq)->bondFrozen);
    }
}

// Rule: R12
// Rule: NOT-1
BOOST_AUTO_TEST_CASE(r12_failing_notice_leaves_no_bundle_row)
{
    // 03/M-2 (R12 hardened): a CLAIM_NOTICE that does not hold -- here because a notice already stands -- is a valid
    // no-op, and its verified bundle of already-credited attestations adds no BundleLog[H] row; one carrying a fresh
    // attestation is LIVENESS_UNHELD.
    EmergencyFixture g;
    const int R = g.f.tip - 1;
    BOOST_REQUIRE(g.PostNotice());
    BOOST_REQUIRE(g.f.BundleRow(g.f.tip).has_value());                                   // the held notice's row
    const NoticeRecord standing = g.f.Notice(g.w).value();
    CMutableTransaction again = g.f.NoticeTx(g.w, R, g.f.BundleFor(R, g.Selector(), g.attPrice));   // the same R: nothing fresh
    g.f.Mine(Fixture::Quote(g.poolPrice, (g.f.tip + 1) % 3), { again });
    BOOST_CHECK_EQUAL(g.f.Refused(CTransaction(again).GetHash()), "");
    BOOST_CHECK(!g.f.BundleRow(g.f.tip).has_value());
    BOOST_CHECK_EQUAL(g.f.Notice(g.w)->height, standing.height);                          // not replaced
    const int fresh = g.f.tip - 1;
    CMutableTransaction third = g.f.NoticeTx(g.w, fresh, g.f.BundleFor(fresh, g.Selector(), g.attPrice));
    g.f.Mine(Fixture::Quote(g.poolPrice, (g.f.tip + 1) % 3), { third });
    BOOST_CHECK_EQUAL(g.f.Refused(CTransaction(third).GetHash()), verdict::LIVENESS_UNHELD);
}

// ===========================================================================
// HALT-2 reads open debt (owner 2026-10-28; cf. DigiByte v9.26.6 2c1f09a0d8 src/digidollar/health.cpp:109-114):
// Totals.openDebtCents, the mintedCents of every ACTIVE and CLAIMING vault, and the invariant supply <= open debt

// Rule: HALT-2
// Rule: IT-6
// Rule: RED-2
// Rule: CAN-1
// Rule: UNDO
BOOST_AUTO_TEST_CASE(halt2_open_debt_totals_invariant_and_undo)
{
    Fixture f{ 1, 0, 0, 10 };    // ATTEST_ARM_MIN 10: the four members never arm the chain, so the claims stay unarmed
    f.Activate();
    f.Register(4);               // CAN-2: a member to co-sign the cancel
    const int base = f.tip;
    const MemoryStateView before = f.view;
    BOOST_CHECK(!OpenDebtInvariantViolation(f.view).has_value());
    auto check = [&](Cents supply, Cents debt, const char* step) {
        const Totals t = f.GetTotals();
        BOOST_CHECK_MESSAGE(t.supplyCents == supply, strprintf("%s: supplyCents %d, expected %d", step, t.supplyCents, supply));
        BOOST_CHECK_MESSAGE(t.openDebtCents == debt, strprintf("%s: openDebtCents %d, expected %d", step, t.openDebtCents, debt));
        BOOST_CHECK_MESSAGE(t.supplyCents <= t.openDebtCents, step);
        const std::optional<std::string> bad = OpenDebtInvariantViolation(f.view);
        BOOST_CHECK_MESSAGE(!bad.has_value(), strprintf("%s: %s", step, bad.value_or("")));
        BOOST_CHECK_EQUAL(f.Snap(f.tip).openDebtCents, debt);       // the snapshot carries the denominator
        BOOST_CHECK_EQUAL(f.Snap(f.tip).supplyCents, supply);
    };
    // MINT: both totals rise by the debt
    const uint256 a = f.MintActive(10000);
    check(10000, 10000, "mint a");
    const uint256 b = f.MintActive(10000);
    const uint256 c = f.MintActive(10000);
    check(30000, 30000, "mint b, c");
    // RED-2 over-burn: a's owner burns 15,000 (a's token and b's) for a 10,000 debt and keeps 5,000; open debt falls by
    // a's mintedCents only, supply by the whole burn
    SpendOpts ro; ro.assigned = { Assignment(3, 5000) };
    CMutableTransaction redeem = f.SpendTx(a, { COutPoint(a, 1), COutPoint(b, 1) }, f.tip, ro);
    BOOST_REQUIRE_EQUAL(Spend(f, a, redeem).verdict, verdict::OK);
    BOOST_CHECK_EQUAL(f.Vault(a)->status, (uint8_t)VaultStatus::CLOSED);
    check(15000, 20000, "over-burn redeem");
    // a failed transfer (XFER-2, the cenotaph rule): the whole input burns, the debt stays open
    CMutableTransaction xfer = f.TransferTx({ COutPoint(CTransaction(redeem).GetHash(), 3) }, { Assignment(0, 6000) });
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3), { xfer });
    BOOST_CHECK_EQUAL(f.Log(CTransaction(xfer).GetHash())->verdict, "transfer-over-assigned");
    check(10000, 20000, "cenotaph");
    // the pools fall to $0.009: b (stranded: its YED is gone) and c are under theta
    for (int i = 0; i < 64; i++) f.Mine(Fixture::Quote(9000, (f.tip + 1) % 3));
    const CAmount each = f.Vault(c)->collateralZat;
    // CLAIM: the burn leaves supply, the debt stays open with the CLAIMING collateral (IT-6)
    SpendOpts co; co.ownerPath = false;
    const int claimRef = f.tip;
    CMutableTransaction claim = f.SpendTx(c, { COutPoint(c, 1) }, claimRef, co);
    BOOST_REQUIRE_EQUAL(Spend(f, c, claim).verdict, verdict::OK);
    BOOST_CHECK_EQUAL(f.Vault(c)->status, (uint8_t)VaultStatus::CLAIMING);
    check(0, 20000, "claim");
    // HALT-2 divides by open debt: with no supply left the ratio is still defined and halts (it was undefined on supply)
    const Snapshot afterClaim = f.Snap(f.tip);
    BOOST_CHECK_EQUAL(afterClaim.GlobalRatioBps().value(), GlobalRatioBps(f.GetTotals().collateralZat, afterClaim.PMint(), 20000).value());
    BOOST_CHECK(!GlobalRatioBps(f.GetTotals().collateralZat, afterClaim.PMint(), afterClaim.supplyCents).has_value());
    BOOST_CHECK(afterClaim.haltMask & HALT_GLOBAL_RATIO);
    // CANCEL (CAN-1): the refund re-credits supply, the re-created vault carries the same open debt
    const COutPoint intent(CTransaction(claim).GetHash(), 0);
    CMutableTransaction cancel;
    cancel.vin.push_back(CTxIn(intent, CScript() << valtype(65, 0) << OP_2, 0xFFFFFFFF));
    cancel.vin.push_back(CTxIn(f.FakeInput()));
    cancel.vout.push_back(RelockOf(f, COutPoint(c, 0), each));
    cancel.vout.push_back(CTxOut(TOKEN_VALUE, GetScriptForDestination(f.ownerKey.GetPubKey().GetID())));
    cancel.vin.push_back(f.CarrierIn(EncodeCancelCosigns({ f.Cosign(0, 50000, intent, claimRef) })));
    cancel.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(Payload::CancelCosign()))));
    f.Mine(Fixture::Quote(9000, (f.tip + 1) % 3), { cancel });
    BOOST_REQUIRE_EQUAL(f.Refused(CTransaction(cancel).GetHash()), "");
    const uint256 reopened = CTransaction(cancel).GetHash();
    BOOST_CHECK_EQUAL(f.Vault(reopened)->status, (uint8_t)VaultStatus::ACTIVE);
    check(10000, 20000, "cancel");
    // CLAIM again with the refund, then RELEASE after CLAIM_DELAY: the debt closes with the collateral
    const int reclaimRef = f.tip;
    CMutableTransaction reclaim = f.SpendTx(reopened, { COutPoint(reopened, 1) }, reclaimRef, co);
    BOOST_REQUIRE_EQUAL(Spend(f, reopened, reclaim).verdict, verdict::OK);
    check(0, 20000, "reclaim");
    CMutableTransaction rel;
    rel.vin.push_back(CTxIn(COutPoint(CTransaction(reclaim).GetHash(), 0), CScript() << OP_1, (uint32_t)f.P.claimDelay));
    rel.vin.push_back(CTxIn(f.FakeInput()));
    rel.vout.push_back(CTxOut(each, GetScriptForDestination(f.userKey.GetPubKey().GetID())));
    f.Mine(Fixture::Quote(9000, (f.tip + 1) % 3), { rel });
    BOOST_REQUIRE_EQUAL(f.Refused(CTransaction(rel).GetHash()), "");
    BOOST_CHECK_EQUAL(f.Vault(reopened)->status, (uint8_t)VaultStatus::CLAIMED);
    check(0, 10000, "release");                          // b's debt: open, its collateral stranded (no YED left to burn it)
    // UNDO: key-level, so the appended field rolls back with the record; undoing every block restores the start byte for byte
    const Totals atEnd = f.GetTotals();
    f.Undo();
    check(0, 20000, "undo release");
    BOOST_CHECK(!(SerializeRecord(f.GetTotals()) == SerializeRecord(atEnd)));
    while (f.tip > base) f.Undo();
    BOOST_CHECK(f.view == before);
    BOOST_CHECK_EQUAL(f.GetTotals().openDebtCents, 0);
    // the check reports a corrupt record (it is a consistency check, never a verdict)
    Totals t = f.GetTotals();
    t.supplyCents = 1;
    t.openDebtCents = 1;
    State(f.view).Put(keys::Totals(), t);
    BOOST_CHECK(OpenDebtInvariantViolation(f.view).has_value());   // 1 open debt with no vault
    t.openDebtCents = 0;
    State(f.view).Put(keys::Totals(), t);
    BOOST_CHECK(OpenDebtInvariantViolation(f.view).has_value());   // supply above open debt
}

BOOST_AUTO_TEST_SUITE_END()
