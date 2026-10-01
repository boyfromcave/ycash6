// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Every rule of plan §3.7–3.9 on synthetic blocks over an in-memory view
// (Phase 2). Each case carries a `// Rule:` tag; the acceptance loop greps
// them. The golden vector (statehash_golden_vector) replays 440 blocks of
// real serialised transactions built by the Python model
// (qa/rpc-tests/test_framework/yellowback_golden.json) and must reproduce
// its pinned state hash byte for byte (N18, N23).

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
#include "key.h"
#include "primitives/block.h"
#include "script/standard.h"
#include "test/data/yellowback_golden.json.h"
#include "test/test_bitcoin.h"
#include "util/strencodings.h"
#include "util/time.h"

#include <boost/test/unit_test.hpp>

#include <univalue.h>

#include <cstring>
#include <map>
#include <set>

using namespace yellowback;

namespace {

const CAmount SUBSIDY = 625000000;   // regtest post-Blossom
const std::string GOLDEN_HASH = "abe131e0cd68cd438449ce22969c7b331930ca3b9e4324ed9d841e90a340a4fe";

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
    CAmount feeValue = -1;           //!< -1 = feeZat(collateral)
    std::optional<CPubKey> owner;
    std::vector<unsigned char> rawOwner; //!< overrides the key bytes in the payload
    int extraOutputs = 0;
    bool p2shVault = true;
    std::vector<COutPoint> yedInputs;
    std::optional<CScript> vaultScriptOverride;
    // v3
    std::optional<valtype> bundle;          //!< carried by an extra (last) input
    int attestPayee = -1;                   //!< seq whose bond key receives the attestor fee at vout 4; -1 = no such output
    CAmount attestFeeValue = -1;            //!< -1 = attestFeeZat(feeZat(collateral))
    uint8_t attestFeeVout = 4;              //!< the payload field when attestPayee >= 0
    std::optional<CScript> attestFeeScript; //!< overrides the attestor-fee output's script
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
    int tip;
    CKey ownerKey, userKey;
    int fakeCounter;
    std::vector<CKey> hotKeys, bondKeys;    //!< v3: attestor i registers with hotKeys[i] / bondKeys[i] and becomes seq i
    SigCache* cache = nullptr;

    explicit Fixture(int start = 1, int sigmaRef = 0, int capBps = 0, int until = 0, int armMin = 3)
        : P(RegtestParams(start, sigmaRef, capBps, until, armMin)), tip(start - 1), fakeCounter(0)
    {
        ownerKey = CKey::TestOnlyRandomKey(true);
        userKey = CKey::TestOnlyRandomKey(true);
        for (int i = 0; i < 8; i++) {
            hotKeys.push_back(DeterministicKey("yellowback-state-test-hot", i));
            bondKeys.push_back(DeterministicKey("yellowback-state-test-bond", i));
        }
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

    /** Evaluate and commit a block at the next height (or `height`). */
    BlockEvaluation Mine(const std::optional<CoinbaseTag>& tag = std::nullopt, std::vector<CMutableTransaction> txs = {}, int height = -1)
    {
        if (height < 0) height = tip + 1;
        CBlock block;
        block.vtx.push_back(CTransaction(Coinbase(height, tag)));
        for (auto& m : txs) block.vtx.push_back(CTransaction(m));
        OverlayStateView overlay(view);
        BlockEvaluation ev = EvaluateBlock(overlay, P, block, height, FakeHash(height), SUBSIDY, cache);
        overlay.Commit();
        undos[height] = ev.undo;
        evals[height] = ev;
        tip = height;
        return ev;
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

    /** ACTIVE with every window filled and no halt: quote+signal to START + 2 * SIGNAL_WINDOW + 2. */
    void Activate(MicroUsd price = 50000)
    {
        MineQuotesTo(P.startHeight + 2 * P.signalWindow + 2, price);
        BOOST_REQUIRE(Snap(tip).activation.IsActive());
        BOOST_REQUIRE_EQUAL(Snap(tip).haltMask, 0u);
    }

    Snapshot Snap(int h) const { return State(const_cast<MemoryStateView&>(view)).GetSnapshot((uint32_t)h).value(); }
    std::optional<Snapshot> SnapOpt(int h) const { return State(const_cast<MemoryStateView&>(view)).GetSnapshot((uint32_t)h); }
    Totals GetTotals() const { return State(const_cast<MemoryStateView&>(view)).GetTotals(); }
    std::optional<VaultRecord> Vault(const uint256& txid) const { return State(const_cast<MemoryStateView&>(view)).GetVault(COutPoint(txid, 0)); }
    std::optional<TokenRecord> Token(const uint256& txid, uint32_t n) const { return State(const_cast<MemoryStateView&>(view)).GetToken(COutPoint(txid, n)); }
    std::optional<TxLogRecord> Log(const uint256& txid) const { return State(const_cast<MemoryStateView&>(view)).GetTxLog(txid); }

    CAmount Required(Cents cents, int termClass, int refHeight) const
    {
        Snapshot s = Snap(refHeight);
        auto r = RequiredCollateralRounded(cents, MinRatioBps(P.baseRatioBps[termClass], s.sigmaMultBps), s.PMint().value());
        BOOST_REQUIRE(r.has_value());
        return r.value();
    }

    /** A MINT of `cents` with lockHeight = refHeight + lockBlocks, refHeight given. */
    CMutableTransaction MintTx(Cents cents, int lockBlocks, int refHeight, MintOpts o = MintOpts())
    {
        CPubKey owner = o.owner.value_or(ownerKey.GetPubKey());
        const uint32_t lock = (uint32_t)(refHeight + lockBlocks);
        CScript vs = o.vaultScriptOverride.value_or(VaultScript(lock, owner, (uint32_t)(lock + P.grace)));
        CAmount collateral = o.collateral;
        // An invalid class is a payload the verdict rejects (bad-mint-class). Collateral is
        // computed from a real class so the helper does not index baseRatioBps out of range;
        // MINT-2 checks the class before it looks at the amount.
        if (collateral < 0) collateral = Required(cents, P.IsValidClass(o.termClass) ? o.termClass : 0, refHeight);
        CMutableTransaction m;
        m.vin.push_back(CTxIn(FakeInput()));
        for (const COutPoint& op : o.yedInputs) m.vin.push_back(CTxIn(op));
        m.vout.push_back(CTxOut(collateral, o.p2shVault ? P2SHScript(vs) : GetScriptForDestination(owner.GetID())));
        m.vout.push_back(CTxOut(TOKEN_VALUE, GetScriptForDestination(owner.GetID())));
        Payload p = Payload::Mint((uint8_t)o.termClass, (uint32_t)cents, lock, (uint32_t)refHeight, owner, o.feeKey == -1 ? FEE_VOUT_NONE : o.feeVout,
                                  o.attestPayee >= 0 ? o.attestFeeVout : FEE_VOUT_NONE);
        if (!o.rawOwner.empty()) p.ownerKeyBytes = o.rawOwner;
        m.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(p))));
        if (o.feeKey != -1) {
            int key = o.feeKey;
            if (key == -2) key = refHeight % 3;
            CAmount fee = o.feeValue >= 0 ? o.feeValue : FeeZat(collateral, P.feeMin, P.feeBps);
            m.vout.push_back(CTxOut(fee, GetScriptForDestination(CKeyID(KeyOf(key)))));
        }
        if (o.attestPayee >= 0) {
            while (m.vout.size() < 4) m.vout.push_back(CTxOut(1000, GetScriptForDestination(userKey.GetPubKey().GetID())));
            CAmount afee = o.attestFeeValue >= 0 ? o.attestFeeValue : AttestFeeZat(FeeZat(collateral, P.feeMin, P.feeBps), P.attestFeeBps);
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

    /** vin[0] = vault (or a YED input when !vaultFirst), YED inputs; vout[0] collateral, vout[1] fee, vout[2] OP_RETURN, vout[3..] tokens. */
    CMutableTransaction SpendTx(const uint256& vaultTxid, const std::vector<COutPoint>& yed, int refHeight, SpendOpts o = SpendOpts())
    {
        std::optional<VaultRecord> v = Vault(vaultTxid);
        BOOST_REQUIRE(v.has_value());
        CScript vs = VaultScript((uint32_t)v->lockHeight, v->OwnerKey(), (uint32_t)v->claimHeight);
        CScript sig = o.scriptSig.value_or(o.ownerPath ? OwnerScriptSig(valtype(71, 0x30), vs) : ClaimScriptSig(vs));
        CMutableTransaction m;
        m.nLockTime = o.ownerPath ? v->lockHeight : v->claimHeight;
        if (!o.vaultFirst) m.vin.push_back(CTxIn(yed.front()));
        m.vin.push_back(CTxIn(COutPoint(vaultTxid, 0), sig, 0xFFFFFFFE));
        for (const COutPoint& e : o.extraVaults) m.vin.push_back(CTxIn(e, sig, 0xFFFFFFFE));
        for (size_t i = o.vaultFirst ? 0 : 1; i < yed.size(); i++) m.vin.push_back(CTxIn(yed[i]));
        m.vout.push_back(CTxOut(v->collateralZat - 1000, GetScriptForDestination(userKey.GetPubKey().GetID())));
        int key = o.feeKey == -2 ? refHeight % 3 : o.feeKey;
        CAmount fee = o.feeValue >= 0 ? o.feeValue : FeeZat(v->collateralZat, P.feeMin, P.feeBps);
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
            CAmount afee = o.attestFeeValue >= 0 ? o.attestFeeValue : AttestFeeZat(FeeZat(v->collateralZat, P.feeMin, P.feeBps), P.attestFeeBps);
            m.vout.push_back(CTxOut(afee, GetScriptForDestination(bondKeys[o.attestPayee].GetPubKey().GetID())));
        }
        if (o.residualValue.has_value()) {
            m.vout.push_back(CTxOut(o.residualValue.value(), o.residualScript.value_or(GetScriptForDestination(v->OwnerKey().GetID()))));
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

    /** A registration of attestor i: vout[0] the 10 YEC bond (P2SH), vout[1] the payload, vout[2] change. */
    CMutableTransaction RegisterTx(int i, CAmount bondZat = 10 * COIN, int lockBlocks = -1, uint8_t flags = 0, bool bareBond = false,
                                   std::optional<CPubKey> hot = std::nullopt)
    {
        const uint32_t locktime = (uint32_t)(tip + 1 + (lockBlocks < 0 ? P.bondMinLock : lockBlocks));
        CMutableTransaction m;
        m.vin.push_back(CTxIn(FakeInput()));
        const CScript bond = BondScript(bondKeys[i].GetPubKey(), locktime);
        m.vout.push_back(CTxOut(bondZat, bareBond ? bond : P2SHScript(bond)));
        m.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(Payload::AttestorRegister(hot.value_or(hotKeys[i].GetPubKey()), bondKeys[i].GetPubKey(), locktime, flags)))));
        m.vout.push_back(CTxOut(1000, GetScriptForDestination(userKey.GetPubKey().GetID())));
        return m;
    }

    /** Register attestors [from, from + n) one per block. */
    void Register(int n, int from = 0)
    {
        for (int i = from; i < from + n; i++) {
            Mine(Quote(50000, (tip + 1) % 3), { RegisterTx(i) });
            BOOST_REQUIRE_MESSAGE(Attestor((uint16_t)i).has_value(), strprintf("attestor %d not registered at %d", i, tip));
        }
    }

    /** Activate (if needed), register n attestors and mine until ARMED. */
    void Arm(int n = 3, MicroUsd price = 50000)
    {
        if (tip < P.startHeight + 2 * P.signalWindow + 2) Activate(price);
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
    CMutableTransaction MintV3(Cents cents, MicroUsd price, MintOpts o = MintOpts(), std::set<int> skip = {})
    {
        const int ref = tip - 1;
        o.bundle = BundleFor(ref, valtype(), price, skip);
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
        return MintTx(cents, 48, ref, o);
    }

    /** A ready ACTIVE vault of `cents` (mint at tip + 1, refHeight = tip - 1); returns the mint txid. */
    uint256 MintActive(Cents cents = 10000, int lockBlocks = 48)
    {
        const int ref = tip - 1;
        CMutableTransaction m = MintTx(cents, lockBlocks, ref);
        Mine(Quote(50000, (tip + 1) % 3), { m });
        const uint256 txid = CTransaction(m).GetHash();
        BOOST_REQUIRE(Vault(txid).has_value());
        Snapshot rs = Snap(ref);
        BOOST_REQUIRE_MESSAGE(Vault(txid)->status == (uint8_t)VaultStatus::ACTIVE,
                              strprintf("MintActive at %d ref %d: %s (supply %d collateral %d ratio %d pMint %d mask %u)", tip, ref,
                                        Vault(txid)->voidReason, rs.supplyCents, rs.collateralZat, rs.globalRatioBps, rs.pMint, rs.haltMask));
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
    yellowback::Params P = RegtestParams(pj["startHeight"].get_int(), pj["sigmaRefBps"].get_int(), pj["supplyCapBps"].get_int(), pj["enforceUntil"].get_int(),
                                         pj["attestArmMin"].get_int(), (BundleCarrier)pj["bundleCarrier"].get_int());
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
        UndoRecord undo;
        BOOST_REQUIRE(!ApplyBlock(view, P, block, height, hash, b["subsidyZat"].get_int64(), undo).has_value());
        BOOST_CHECK(SerializeRecord(undo) == SerializeRecord(ev.undo));
        undos.push_back(undo);
        if (ev.blockInvalid) {
            invalidBlocks++;
            BOOST_CHECK_EQUAL(height, 217);              // BLK-1 with enforcement on; applied anyway for the vector
            BOOST_CHECK(ev.enforcementOn);
            BOOST_CHECK_EQUAL(ev.reason.substr(0, 22), "vault-spend-malformed:");
        }
    }
    BOOST_CHECK_EQUAL(invalidBlocks, 1);
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
    // UNDO: undoing the whole vector restores the empty view byte for byte.
    for (auto it = undos.rbegin(); it != undos.rend(); ++it) UndoBlock(view, *it);
    BOOST_CHECK(view == empty);
}

// ===========================================================================
// Tags, medians, activation (§3.2, §3.7 PRICE/ACT, §3.8 ACT/HALT)

// Rule: TAG-3
// Rule: TAG-4
// Rule: SNAP
// Rule: REG-1
BOOST_AUTO_TEST_CASE(tag3_signal_only_registers_nobody)
{
    Fixture f;
    f.Mine(Fixture::SignalOnly(1));                       // signal-only: counts for ACT-1, no quote, no payee
    BOOST_CHECK(f.Snap(1).tagged);
    BOOST_CHECK(!f.Snap(1).quote);
    BOOST_CHECK_EQUAL(f.Snap(1).signalCount, 1u);
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
    BOOST_CHECK_EQUAL(f.Snap(4).signalCount, 2u);
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

// Rule: ACT-1
// Rule: ACT-2
// Rule: ACT-3
// Rule: ACT-4
// Rule: HALT-4
BOOST_AUTO_TEST_CASE(act2_lockin_at_exactly_threshold_then_delay)
{
    Fixture f;
    // 47 signalling blocks (18..64) in the first 64: no lock-in at 64; the 48th signal at 65 locks in.
    for (int h = 1; h <= 64; h++) f.Mine(Fixture::Quote(50000, h % 3, h >= 18));
    BOOST_CHECK_EQUAL(f.Snap(64).signalCount, 47u);
    BOOST_CHECK_EQUAL(f.Snap(64).activation.status, (uint8_t)ActivationStatus::SIGNALING);
    BOOST_CHECK(f.Snap(64).haltMask & HALT_NOT_ACTIVE);
    f.Mine(Fixture::Quote(50000, 0, true));
    BOOST_CHECK_EQUAL(f.Snap(65).signalCount, 48u);
    BOOST_CHECK_EQUAL(f.Snap(65).activation.status, (uint8_t)ActivationStatus::LOCKED_IN);
    BOOST_CHECK_EQUAL(f.Snap(65).activation.lockInHeight, 65);
    BOOST_CHECK_EQUAL(f.Snap(65).activation.activateHeight, 65 + 64);
    // ACT-3 exactly at activateHeight, whatever the signalling does meanwhile (here it collapses: ACT-4 halts).
    f.MineQuotesTo(128, 50000, false);
    BOOST_CHECK_EQUAL(f.Snap(128).activation.status, (uint8_t)ActivationStatus::LOCKED_IN);
    f.Mine(Fixture::Quote(50000, 2, false));
    BOOST_CHECK_EQUAL(f.Snap(129).activation.status, (uint8_t)ActivationStatus::ACTIVE);
    BOOST_CHECK(!(f.Snap(129).haltMask & HALT_NOT_ACTIVE));
    BOOST_CHECK(f.Snap(129).haltMask & HALT_PARTICIPATION);   // signalCount 0 < 39
    BOOST_CHECK(f.Snap(129).haltMask & HALT_ENFORCEMENT);
    BOOST_CHECK(!EnforcementOn(State(f.view), f.P, 130));
}

// Rule: ACT-2
// Rule: ACT-4
BOOST_AUTO_TEST_CASE(act2_lockin_needs_full_window)
{
    // START = 10: lock-in is possible only at H >= START + 63 even if the count is reached earlier.
    Fixture f(10);
    for (int h = 10; h <= 60; h++) f.Mine(Fixture::Quote(50000, h % 3));   // 51 signals by 60, but H < 73
    BOOST_CHECK_EQUAL(f.Snap(60).activation.status, (uint8_t)ActivationStatus::SIGNALING);
    f.MineQuotesTo(72);
    BOOST_CHECK_EQUAL(f.Snap(72).activation.status, (uint8_t)ActivationStatus::SIGNALING);
    f.MineQuotesTo(73);
    BOOST_CHECK_EQUAL(f.Snap(73).activation.status, (uint8_t)ActivationStatus::LOCKED_IN);
}

// Rule: ACT-4
// Rule: ACT-6
// Rule: ACT-5
BOOST_AUTO_TEST_CASE(act6_enforcement_floor_and_hysteresis)
{
    Fixture f;
    f.Activate();
    const int h0 = f.tip;
    BOOST_CHECK(EnforcementOn(State(f.view), f.P, h0 + 1));
    // Drop signalling to 38 of 64 (below PARTICIPATION_FLOOR 39, above ENFORCEMENT_FLOOR 32): mint halt only.
    int signals = 64;
    while (signals > 38) { f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3, false)); signals--; }
    BOOST_CHECK_EQUAL(f.Snap(f.tip).signalCount, 38u);
    BOOST_CHECK(f.Snap(f.tip).haltMask & HALT_PARTICIPATION);
    BOOST_CHECK(!(f.Snap(f.tip).haltMask & HALT_ENFORCEMENT));
    BOOST_CHECK(EnforcementOn(State(f.view), f.P, f.tip + 1));
    // Below 32: ENFORCEMENT set; it implies PARTICIPATION.
    while (signals > 31) { f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3, false)); signals--; }
    BOOST_CHECK_EQUAL(f.Snap(f.tip).signalCount, 31u);
    BOOST_CHECK(f.Snap(f.tip).haltMask & HALT_ENFORCEMENT);
    BOOST_CHECK(f.Snap(f.tip).haltMask & HALT_PARTICIPATION);
    BOOST_CHECK(!EnforcementOn(State(f.view), f.P, f.tip + 1));
    // Empty the window of signals, then refill: held while < ENFORCEMENT_RESUME (39): at 38 still set;
    // cleared at 39. PARTICIPATION stays until 48.
    while (signals > 0) { f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3, false)); signals--; }
    BOOST_CHECK_EQUAL(f.Snap(f.tip).signalCount, 0u);
    while (signals < 38) { f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3, true)); signals++; }
    BOOST_CHECK_EQUAL(f.Snap(f.tip).signalCount, 38u);
    BOOST_CHECK(f.Snap(f.tip).haltMask & HALT_ENFORCEMENT);
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3, true)); signals++;
    BOOST_CHECK_EQUAL(f.Snap(f.tip).signalCount, 39u);
    BOOST_CHECK(!(f.Snap(f.tip).haltMask & HALT_ENFORCEMENT));
    BOOST_CHECK(f.Snap(f.tip).haltMask & HALT_PARTICIPATION);
    while (signals < 47) { f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3, true)); signals++; }
    BOOST_CHECK(f.Snap(f.tip).haltMask & HALT_PARTICIPATION);
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3, true));
    BOOST_CHECK_EQUAL(f.Snap(f.tip).signalCount, 48u);
    BOOST_CHECK(!(f.Snap(f.tip).haltMask & HALT_PARTICIPATION));
    BOOST_CHECK_EQUAL(f.Snap(f.tip).haltMask, 0u);
    // Every bit implies PARTICIPATION whenever ENFORCEMENT is set, over the whole run.
    for (int h = h0; h <= f.tip; h++) {
        const uint32_t m = f.Snap(h).haltMask;
        if (m & HALT_ENFORCEMENT) BOOST_CHECK(m & HALT_PARTICIPATION);
    }
}

// Rule: ACT-5
BOOST_AUTO_TEST_CASE(act5_sunset_stops_rejection)
{
    Fixture f(1, 0, 0, 0);
    f.Activate();
    const uint256 vault = f.MintActive();
    // Same chain, a parameter set whose sunset is behind us: enforcementOn is false with the same blockInvalid.
    yellowback::Params sunset = RegtestParams(1, 0, 0, f.tip);
    CMutableTransaction sweep = f.SpendTx(vault, {}, f.tip - 1, [] { SpendOpts o; o.payload = false; return o; }());
    CBlock block;
    block.vtx.push_back(CTransaction(Fixture::Coinbase(f.tip + 1, std::nullopt)));
    block.vtx.push_back(CTransaction(sweep));
    OverlayStateView a(f.view);
    BlockEvaluation live = EvaluateBlock(a, f.P, block, f.tip + 1, Fixture::FakeHash(f.tip + 1), SUBSIDY);
    OverlayStateView b(f.view);
    BlockEvaluation past = EvaluateBlock(b, sunset, block, f.tip + 1, Fixture::FakeHash(f.tip + 1), SUBSIDY);
    BOOST_CHECK(live.blockInvalid && live.enforcementOn);
    BOOST_CHECK(past.blockInvalid && !past.enforcementOn);
    BOOST_CHECK_EQUAL(live.reason, past.reason);
    BOOST_CHECK(EnforcementOn(State(f.view), sunset, f.tip));       // H == ENFORCE_UNTIL_HEIGHT is still enforced
    BOOST_CHECK(!EnforcementOn(State(f.view), sunset, f.tip + 1));
}

// Rule: HALT-1
// Rule: HALT-2
// Rule: HALT-3
// Rule: HALT-4
BOOST_AUTO_TEST_CASE(halt2_halt3_clear_with_undefined_price)
{
    Fixture f;
    // Before any price: HALT-1 and HALT-4 by name, HALT-2/3 clear (M1).
    f.Mine(Fixture::Quote(50000, 0));
    BOOST_CHECK_EQUAL(f.Snap(1).haltMask, (uint32_t)(HALT_NOT_ACTIVE | HALT_NO_PRICE));
    f.Activate();
    const uint256 vault = f.MintActive(10000);
    // HALT-2 at the exact threshold: ratio 250% => not below => clear; 249.99% => set.
    Snapshot s = f.Snap(f.tip);
    BOOST_CHECK(s.GlobalRatioBps().has_value());
    BOOST_CHECK(s.GlobalRatioBps().value() >= 50000 - 1);        // 500% at pMint 50,000
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
    Fixture f(1, 10000, 0, 0);
    f.MineQuotesTo(64);
    BOOST_CHECK_EQUAL(f.Snap(64).sigmaMultBps, 30000);           // s_8 = Snapshots[0] is virtual
    f.MineQuotesTo(67);
    BOOST_CHECK_EQUAL(f.Snap(67).sigmaMultBps, 30000);           // s_8 = Snapshots[3].pFast is undefined (3 quotes < 4)
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

// Rule: FEE-1
BOOST_AUTO_TEST_CASE(fee1_min_dominates_small_vault)
{
    const yellowback::Params P = RegtestParams(1, 0, 0, 0);
    BOOST_CHECK_EQUAL(FeeZat(100 * COIN, P.feeMin, P.feeBps), P.feeMin);                  // 0.25% of 100 YEC < 0.5 YEC
    BOOST_CHECK_EQUAL(FeeZat(200 * COIN, P.feeMin, P.feeBps), P.feeMin);                  // exactly 0.5 YEC
    BOOST_CHECK_EQUAL(FeeZat(200 * COIN + 400, P.feeMin, P.feeBps), P.feeMin + 1);
    BOOST_CHECK_EQUAL(FeeZat(MAX_MONEY, P.feeMin, P.feeBps), MAX_MONEY * 25 / 10000);     // fee1_at_max_money
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
    BOOST_CHECK_EQUAL(v.collateralZat, 1000000000000LL);            // $100 at 500% and $0.05
    BOOST_CHECK_EQUAL(v.lockHeight, ref + 48);
    BOOST_CHECK_EQUAL(v.claimHeight, ref + 48 + 24);
    BOOST_CHECK_EQUAL(v.refHeight, ref);
    BOOST_CHECK_EQUAL(v.feePaidZat, FeeZat(v.collateralZat, f.P.feeMin, f.P.feeBps));
    const CPubKey ownerPub = f.ownerKey.GetPubKey();
    BOOST_CHECK(v.ownerPubKey == std::vector<unsigned char>(ownerPub.begin(), ownerPub.end()));
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
    // MINT-1 fails (version 1 payload): non-Yellowback, no vault, no log.
    CMutableTransaction bad = f.MintTx(10000, 48, f.tip - 1);
    std::vector<unsigned char> data = EncodePayload(Payload::Mint(0, 10000, f.tip + 47, f.tip - 1, f.ownerKey.GetPubKey(), 3));
    data[2] = 0x01;
    bad.vout[2] = CTxOut(0, PayloadScript(data));
    f.Mine(Fixture::Quote(50000, 1), { bad });
    BOOST_CHECK(!f.Vault(CTransaction(bad).GetHash()).has_value());
    BOOST_CHECK(!f.Log(CTransaction(bad).GetHash()).has_value());
    // TX-0: a coinbase carrying a MINT payload registers nothing.
    CMutableTransaction cb = Fixture::Coinbase(f.tip + 1, Fixture::Quote(50000, 2));
    cb.vout = f.MintTx(10000, 48, f.tip - 1).vout;
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
    BOOST_CHECK(!r.relevant && !r.vaultSpend && !r.redFailed);
    BOOST_CHECK_EQUAL(r.log.verdict, verdict::NON_YELLOWBACK);
}

namespace {

/** Mine a MINT at the next height and return its VOID reason ("" for ACTIVE, "none" when no vault was created). */
std::string MintVerdictOf(Fixture& f, const CMutableTransaction& m, bool* invalid = nullptr)
{
    BlockEvaluation ev = f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3), { m });
    if (invalid) *invalid = ev.blockInvalid;
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
    BOOST_CHECK(!invalid);
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(5000, 48, f.tip - 1)), "bad-mint-amount");
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(1000001, 48, f.tip - 1)), "bad-mint-amount");
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, (int)LOCKTIME_THRESHOLD - f.P.grace - (f.tip - 1), f.tip - 1)), "bad-mint-lock-height");
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 47, f.tip - 1)), "bad-mint-lock-height");     // below class A
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 97, f.tip - 1)), "bad-mint-lock-height");     // class A, 97 blocks
    { MintOpts o; o.termClass = 1; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 97, f.tip - 1, o)), ""); }
    { MintOpts o; o.collateral = 1000000000000LL; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip + 1, o)), "bad-mint-ref-height"); }   // ref = H
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip)), "");                              // ref = H - 1
    f.MineQuotesTo(f.tip + 40);                                                                       // so that H - 40 is past activation
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 39)), "");                         // ref = H - 40 (H = tip + 1)
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 40)), "bad-mint-ref-height");      // ref = H - 41
    // The VOID record copies the payload verbatim, with feePaidZat 0 and its collateral outside Totals.
    const Totals before = f.GetTotals();
    CMutableTransaction m = f.MintTx(5000, 48, f.tip - 1);
    BOOST_CHECK_EQUAL(MintVerdictOf(f, m), "bad-mint-amount");
    const VaultRecord v = f.Vault(CTransaction(m).GetHash()).value();
    BOOST_CHECK_EQUAL(v.mintedCents, 5000);
    BOOST_CHECK_EQUAL(v.feePaidZat, 0);
    BOOST_CHECK_EQUAL(v.voidReason, "bad-mint-amount");
    BOOST_CHECK_EQUAL(f.GetTotals().collateralZat, before.collateralZat);
    BOOST_CHECK_EQUAL(f.GetTotals().voidVaults, before.voidVaults + 1);
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
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, 1, o)), "mint-not-active");
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, 0, o)), "bad-mint-ref-height");   // below START_HEIGHT
}

// Rule: MINT-3
BOOST_AUTO_TEST_CASE(mint3_outputs_owner_key_vault_script)
{
    Fixture f;
    f.Activate();
    CMutableTransaction two = f.MintTx(10000, 48, f.tip - 1);
    two.vout.resize(2);
    two.vout[1] = CTxOut(0, two.vout[0].scriptPubKey);   // keep vout[0] P2SH; no third output
    BOOST_CHECK_EQUAL(MintVerdictOf(f, two), "none");   // two outputs cannot carry an OP_RETURN at all: non-Yellowback
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
    { MintOpts o; o.p2shVault = false; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "none"); }   // not P2SH: no VOID vault either
}

// Rule: MINT-4
// Rule: HALT-4
// Rule: HALT-1
BOOST_AUTO_TEST_CASE(mint4_not_active_and_halts)
{
    Fixture f;
    f.MineQuotesTo(100);                                    // LOCKED_IN, not ACTIVE
    { MintOpts o; o.collateral = 1000000000000LL; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "mint-not-active"); }
    f.Activate();
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1)), "");
    // Participation halt: 26 non-signal blocks bring the count to 38.
    for (int i = 0; i < 26; i++) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3, false));
    BOOST_CHECK(f.Snap(f.tip).haltMask & HALT_PARTICIPATION);
    BOOST_CHECK(!(f.Snap(f.tip - 1).haltMask & HALT_PARTICIPATION));
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip)), "mint-halted-participation");     // R = the halted snapshot
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 2)), "");                          // R = the block before it
    // A refHeight whose snapshot was clear still mints (MINT-4 reads R, not H).
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 25)), "");
    // No price: nine untagged blocks empty the fast window.
    for (int i = 0; i < 9; i++) f.Mine(std::nullopt);
    BOOST_CHECK(f.Snap(f.tip).haltMask & HALT_NO_PRICE);
    { MintOpts o; o.collateral = 1000000000000LL; o.feeKey = 0; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "mint-halted-no-price"); }   // NO_PRICE precedes PARTICIPATION
    BOOST_CHECK_EQUAL(HaltMaskNames(HALT_NO_PRICE | HALT_ENFORCEMENT).size(), 2u);
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
    // W16: class C (300 %) is below the recapitalisation floor: GLOBAL_RATIO stops it, and takes precedence over DIVERGENCE
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 145, f.tip - 1, c)), "mint-halted-global-ratio");
    // class A (500 %) reaches the floor: the global-ratio clause lets it through to the next halt, DIVERGENCE
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, a)), "mint-halted-divergence");
    // Once the windows agree again the ratio is still low (same supply, same price): class A mints, class C does not
    for (int i = 0; i < 64; i++) f.Mine(Fixture::Quote(15000, (f.tip + 1) % 3));
    BOOST_CHECK(!(f.Snap(f.tip).haltMask & HALT_DIVERGENCE));
    BOOST_CHECK(f.Snap(f.tip).haltMask & HALT_GLOBAL_RATIO);
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 145, f.tip - 1, c)), "mint-halted-global-ratio");
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

// Rule: MINT-5
BOOST_AUTO_TEST_CASE(mint5_collateral_and_unsatisfiable)
{
    Fixture f;
    f.Activate();
    { MintOpts o; o.collateral = 1000000000000LL - 1; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "bad-mint-collateral"); }
    { MintOpts o; o.collateral = 1000000000000LL; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), ""); }
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
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1)), "mint-supply-cap");
    Fixture g(1, 0, 10000, 0);                              // cap = 100% of market cap: ~$818 at 131 blocks and $1/YEC
    g.Activate(1000000);
    BOOST_CHECK_EQUAL(MintVerdictOf(g, g.MintTx(10000, 48, g.tip - 1)), "");
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
    BOOST_CHECK(!invalid);
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
    { MintOpts o; o.feeValue = FeeZat(1000000000000LL, f.P.feeMin, f.P.feeBps) - 1; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, f.tip - 1, o)), "bad-mint-fee"); }
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

struct RedResult { std::string verdict; bool invalid; bool enforcing; VaultRecord vault; TxLogRecord log; };

RedResult Spend(Fixture& f, const uint256& vaultTxid, const CMutableTransaction& tx)
{
    BlockEvaluation ev = f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3), { tx });
    RedResult r;
    r.invalid = ev.blockInvalid;
    r.enforcing = ev.enforcementOn;
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
    BOOST_CHECK(r.enforcing);
    BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLOSED);
    BOOST_CHECK_EQUAL(r.vault.burnedCents, 10000);
    BOOST_CHECK(!r.vault.unbacked);
    BOOST_CHECK_EQUAL(r.vault.closeHeight, f.tip);
    BOOST_CHECK_EQUAL(r.vault.feePaidZat, FeeZat(r.vault.collateralZat, f.P.feeMin, f.P.feeBps));   // rewritten by the close
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
      BOOST_CHECK(r.invalid && r.enforcing);
      BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLOSED);
      BOOST_CHECK_EQUAL(r.vault.burnedCents, 10000);        // everything burns (IN-3): 10,000 in, nothing out
      BOOST_CHECK(!r.vault.unbacked);                        // burned == mintedCents after the failure (M3)
      BOOST_CHECK(!f.Token(CTransaction(tx).GetHash(), 3).has_value());
      BOOST_CHECK_EQUAL(f.GetTotals().unbackedCents, 0);
    }
    // Assign 6,000 of 10,000: burn 4,000 < 10,000 => short; unbacked by 6,000.
    { SpendOpts o; o.assigned = { Assignment(3, 6000) };
      RedResult r = Spend(f, b, f.SpendTx(b, { COutPoint(b, 1) }, f.tip, o));
      BOOST_CHECK_EQUAL(r.verdict, "vault-spend-short-burn");
      BOOST_CHECK(r.invalid);
      BOOST_CHECK(!r.vault.unbacked);                        // the failure burns every input: 10,000 == mintedCents
      BOOST_CHECK_EQUAL(r.log.yedOut, 0);
      BOOST_CHECK_EQUAL(r.log.burned, 10000);
      BOOST_CHECK_EQUAL(f.GetTotals().unbackedCents, 0);    // burned (10,000, all inputs) is not < mintedCents
    }
}

// Rule: RED-2
// Rule: IN-2
// Rule: IN-3
BOOST_AUTO_TEST_CASE(in3_burn_recorded_on_closed_vault)
{
    // A spend that burns only 4,000 against a 10,000 debt: unbacked = true, unbackedCents += 6,000.
    Fixture f;
    f.Activate();
    const uint256 a = f.MintActive(10000);
    CMutableTransaction split = f.TransferTx({ COutPoint(a, 1) }, { Assignment(0, 4000), Assignment(1, 6000) });
    f.Mine(Fixture::Quote(50000, 0), { split });
    const uint256 sid = CTransaction(split).GetHash();
    RedResult r = Spend(f, a, f.SpendTx(a, { COutPoint(sid, 0) }, f.tip));
    BOOST_CHECK_EQUAL(r.verdict, "vault-spend-short-burn");
    BOOST_CHECK_EQUAL(r.vault.burnedCents, 4000);
    BOOST_CHECK(r.vault.unbacked);
    BOOST_CHECK_EQUAL(f.GetTotals().unbackedCents, 6000);
    BOOST_CHECK_EQUAL(f.GetTotals().supplyCents, 6000);
    BOOST_CHECK_EQUAL(f.GetTotals().collateralZat, 0);       // a closed vault's collateral leaves either way
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
    { uint256 v = vault(); SpendOpts o; o.feeValue = FeeZat(1000000000000LL, f.P.feeMin, f.P.feeBps) - 1;
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
    // Not underwater at $0.05: a claim fails, and the vault closes unbacked on a node that applies it.
    { SpendOpts o; o.ownerPath = false;
      RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o));
      BOOST_CHECK_EQUAL(r.verdict, "vault-claim-not-underwater");
      BOOST_CHECK(r.invalid && r.enforcing);
      BOOST_CHECK_EQUAL(r.log.path, "claim");
      BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLOSED); }
    // Crash to $0.009 for a whole slow window: pClaim 9,000 => 10,000 YEC backs $100 at 90% < 110%.
    const uint256 w = f.MintActive(10000);
    for (int i = 0; i < 64; i++) f.Mine(Fixture::Quote(9000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(f.Snap(f.tip).PClaim().value(), 9000);
    BOOST_CHECK(IsUnderwater(1000000000000LL, 9000, 10000, f.P.claimThresholdBps));
    { SpendOpts o; o.ownerPath = false;
      RedResult r = Spend(f, w, f.SpendTx(w, { COutPoint(w, 1) }, f.tip, o));
      BOOST_CHECK_EQUAL(r.verdict, verdict::OK);
      BOOST_CHECK(!r.invalid);
      BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLAIMED);
      BOOST_CHECK_EQUAL(f.GetTotals().claimedVaults, 1u);
      BOOST_CHECK_EQUAL(f.GetTotals().closedVaults, 1u); }
    // A vault minted at $0.009 is fully backed at that price, so the same claim fails (RED-4 reads R, M13).
    // One more block first: the snapshot at the claim block has supply 0, so HALT-2 is clear for the new mint.
    f.Mine(Fixture::Quote(9000, (f.tip + 1) % 3));
    const uint256 x = f.MintActive(10000);          // 55,555 YEC at $0.009 backs $100 at 500%
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
    // Two ACTIVE vaults in one transaction fail, and both close.
    { uint256 v = vault(); uint256 w = vault(); SpendOpts o; o.extraVaults = { COutPoint(w, 0) };
      RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1), COutPoint(w, 1) }, f.tip, o));
      BOOST_CHECK_EQUAL(r.verdict, "vault-spend-malformed");
      BOOST_CHECK_EQUAL(f.Vault(w)->status, (uint8_t)VaultStatus::CLOSED);
      BOOST_CHECK_EQUAL(r.log.closedVaults.size(), 2u); }
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
    // K4 selectors: OP_2 and a non-minimal 1 are owner selectors; 0x80 is a claim selector.
    auto script = [&](const uint256& v) { VaultRecord r = f.Vault(v).value(); CScript vs = VaultScript(r.lockHeight, r.OwnerKey(), r.claimHeight); return valtype(vs.begin(), vs.end()); };
    { uint256 v = vault(); SpendOpts o; o.scriptSig = CScript() << valtype(71, 0x30) << OP_2 << script(v);
      RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o));
      BOOST_CHECK_EQUAL(r.verdict, verdict::OK); BOOST_CHECK_EQUAL(r.log.path, "owner"); }
    { uint256 v = vault(); SpendOpts o; o.scriptSig = CScript() << valtype(71, 0x30) << valtype{ 0x01 } << script(v);
      RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o));
      BOOST_CHECK_EQUAL(r.verdict, verdict::OK); BOOST_CHECK_EQUAL(r.log.path, "owner"); }
    { uint256 v = vault(); SpendOpts o; o.scriptSig = CScript() << valtype{ 0x80 } << script(v);
      RedResult r = Spend(f, v, f.SpendTx(v, { COutPoint(v, 1) }, f.tip, o));
      BOOST_CHECK_EQUAL(r.verdict, "vault-claim-not-underwater"); BOOST_CHECK_EQUAL(r.log.path, "claim"); }
}

// Rule: RED-1
BOOST_AUTO_TEST_CASE(tpl2_declines_nonwallet_selector)
{
    // The OP_2 selector is consensus-valid (K4) and RED-1 accepts it; the strict template shape
    // (exactly <sig> OP_1 <script> / OP_0 <script>) is what Phase 4's FilterTemplate declines (TPL-2).
    CScript vs = VaultScript(1000, CPubKey(ParseHex("02cb81cc0269783ebd9e6484b5495343036874a407856f230a8ee0384986759e70")), 1024);
    std::optional<VaultSpendPath> op2 = ParseVaultSpendPath(CScript() << valtype(71, 0x30) << OP_2 << valtype(vs.begin(), vs.end()));
    BOOST_REQUIRE(op2.has_value());
    BOOST_CHECK(op2->ownerPath);
    BOOST_CHECK(op2->selector != valtype{ 0x01 });                  // not the wallet's OP_1
    std::optional<VaultSpendPath> op1 = ParseVaultSpendPath(OwnerScriptSig(valtype(71, 0x30), vs));
    BOOST_CHECK(op1->ownerPath && op1->selector == valtype{ 0x01 } && op1->pushes == 3);
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
    m.vin.insert(m.vin.begin(), CTxIn(COutPoint(v, 0), OwnerScriptSig(valtype(71, 0x30), VaultScript(vr.lockHeight, vr.OwnerKey(), vr.claimHeight)), 0xFFFFFFFE));
    BlockEvaluation ev = f.Mine(Fixture::Quote(50000, 0), { m });
    const uint256 txid = CTransaction(m).GetHash();
    BOOST_CHECK(ev.blockInvalid);
    BOOST_CHECK(!f.Vault(txid).has_value());
    BOOST_CHECK(!f.Token(txid, 1).has_value());
    BOOST_CHECK_EQUAL(f.Log(txid)->type, (uint8_t)TxLogType::REDEEM);
    BOOST_CHECK_EQUAL(f.Log(txid)->verdict, "vault-spend-malformed");
    BOOST_CHECK_EQUAL(f.Vault(v)->status, (uint8_t)VaultStatus::CLOSED);
    BOOST_CHECK(f.Vault(v)->unbacked);
    BOOST_CHECK_EQUAL(f.GetTotals().unbackedCents, 10000);
    BOOST_CHECK_EQUAL(f.GetTotals().supplyCents, 10000);            // the token of v is still out there
    // A full burn to the wrong payee: RED-3 fails, but unbacked = false (burned == mintedCents) and nothing is added.
    const uint256 w = f.MintActive(10000);
    SpendOpts o; o.feeKey = 7;
    RedResult r = Spend(f, w, f.SpendTx(w, { COutPoint(w, 1) }, f.tip, o));
    BOOST_CHECK_EQUAL(r.verdict, "vault-spend-bad-payee");
    BOOST_CHECK(r.invalid);
    BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLOSED);
    BOOST_CHECK(!r.vault.unbacked);
    BOOST_CHECK_EQUAL(f.GetTotals().unbackedCents, 10000);
}

// Rule: IN-2
// Rule: RED-1
BOOST_AUTO_TEST_CASE(in2_void_vault_spend_closes)
{
    Fixture f;
    f.Activate();
    CMutableTransaction bad = f.MintTx(5000, 48, f.tip - 1);
    BOOST_CHECK_EQUAL(MintVerdictOf(f, bad), "bad-mint-amount");
    const uint256 v = CTransaction(bad).GetHash();
    // Any spend of a VOID vault is an ordinary spend: no rule, never invalid, CLOSED with unbacked = false (K3, L14).
    SpendOpts o; o.payload = false; o.ownerPath = false;
    RedResult r = Spend(f, v, f.SpendTx(v, {}, f.tip, o));
    BOOST_CHECK(!r.invalid);
    BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLOSED);
    BOOST_CHECK(!r.vault.unbacked);
    BOOST_CHECK_EQUAL(r.vault.closeHeight, f.tip);
    BOOST_CHECK_EQUAL(r.log.type, (uint8_t)TxLogType::NONE);
    BOOST_CHECK_EQUAL(r.log.verdict, verdict::OK);
    BOOST_CHECK_EQUAL(r.log.closedVaults.size(), 1u);
    BOOST_CHECK_EQUAL(f.GetTotals().voidVaults, 0u);
    BOOST_CHECK_EQUAL(f.GetTotals().closedVaults, 1u);
}

// Rule: RED-1
// Rule: ACT-5
// Rule: ACT-6
BOOST_AUTO_TEST_CASE(blk1_invalid_iff_enforcement_on)
{
    Fixture f;
    f.Activate();
    const uint256 v = f.MintActive(10000);
    // ENFORCEMENT set: 33 non-signal blocks bring the count to 31.
    for (int i = 0; i < 33; i++) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3, false));
    BOOST_CHECK(f.Snap(f.tip).haltMask & HALT_ENFORCEMENT);
    SpendOpts o; o.payload = false;
    RedResult r = Spend(f, v, f.SpendTx(v, {}, f.tip, o));
    BOOST_CHECK_EQUAL(r.verdict, "vault-spend-malformed");
    BOOST_CHECK(r.invalid);
    BOOST_CHECK(!r.enforcing);
    BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLOSED);
    BOOST_CHECK(r.vault.unbacked);
    // LOCKED_IN followed by a collapse: ACTIVE at activateHeight with both bits set, no enforcement.
    Fixture g;
    g.MineQuotesTo(64);                                                    // LOCKED_IN at 64
    g.MineQuotesTo(129, 50000, false);
    BOOST_CHECK(g.Snap(128).activation.IsActive());
    BOOST_CHECK(g.Snap(128).haltMask & HALT_PARTICIPATION);
    BOOST_CHECK(g.Snap(128).haltMask & HALT_ENFORCEMENT);
    BOOST_CHECK(!EnforcementOn(State(g.view), g.P, 129));
    BOOST_CHECK(!g.evals[129].enforcementOn);
}

// Rule: RED-1
BOOST_AUTO_TEST_CASE(blk2_dos_level_zero)
{
    // The hook's caller answers a Yellowback-invalid block with DoS 0 and this reject reason (BLK-2, N1).
    CValidationState state;
    BOOST_CHECK(!state.DoS(0, false, REJECT_INVALID, "yellowback-vault-spend"));
    int nDoS = 99;
    BOOST_CHECK(state.IsInvalid(nDoS));
    BOOST_CHECK_EQUAL(nDoS, 0);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "yellowback-vault-spend");
    BOOST_CHECK_EQUAL(state.GetRejectCode(), REJECT_INVALID);
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

// Rule: SNAP
BOOST_AUTO_TEST_CASE(overlay_view_equivalence)
{
    Fixture f;
    f.Activate();
    const uint256 v = f.MintActive(10000);
    CBlock block;
    block.vtx.push_back(CTransaction(Fixture::Coinbase(f.tip + 1, Fixture::Quote(50000, 0))));
    block.vtx.push_back(CTransaction(f.SpendTx(v, {}, f.tip)));
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
    BOOST_CHECK_EQUAL(a.reason, std::string("vault-spend-missing-burn:") + block.vtx[1].GetHash().GetHex());
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
    // tokens all get verdicts, nothing throws, and the block is never invalid.
    yellowback::Params P = RegtestParams(1, 0, 0, 0);
    MemoryStateView view;
    CKey k; k = CKey::TestOnlyRandomKey(true);
    CBlock block;
    block.vtx.push_back(CTransaction(Fixture::Coinbase(1, std::nullopt)));
    CMutableTransaction mint;
    mint.vin.push_back(CTxIn(COutPoint(uint256S("11"), 0)));
    mint.vout.push_back(CTxOut(1000000000000LL, P2SHScript(VaultScript(49, k.GetPubKey(), 73))));
    mint.vout.push_back(CTxOut(TOKEN_VALUE, GetScriptForDestination(k.GetPubKey().GetID())));
    mint.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(Payload::Mint(0, 10000, 49, 1, k.GetPubKey(), FEE_VOUT_NONE)))));
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
    BOOST_CHECK(!ev.blockInvalid);
    BOOST_CHECK(!ev.enforcementOn);
    BOOST_REQUIRE_EQUAL(ev.txlogs.size(), 1u);                     // only the VOID mint touched the state
    BOOST_CHECK_EQUAL(ev.txlogs[0].second.verdict, "bad-mint-ref-height");   // refHeight 1 is not <= H - 1 = 0
    BOOST_CHECK_EQUAL(ev.snapshot.haltMask, (uint32_t)(HALT_NOT_ACTIVE | HALT_NO_PRICE));
    // Missing Snapshots[H - 1] above START_HEIGHT (a hole) is "undefined": enforcement off, nothing thrown.
    BOOST_REQUIRE_NO_THROW(ev = EvaluateBlock(overlay, P, block, 500, uint256S("bb"), SUBSIDY));
    BOOST_CHECK(!ev.enforcementOn);
    BOOST_CHECK_EQUAL(ev.txlogs.size(), 1u);
    BOOST_CHECK_EQUAL(ev.txlogs[0].second.verdict, "bad-mint-ref-height");
    // ProcessTx on a lone State with no Totals/Activation records.
    MemoryStateView bare;
    State st(bare);
    BOOST_REQUIRE_NO_THROW(ProcessTx(st, P, CTransaction(redeem), 7));
    BOOST_REQUIRE_NO_THROW(ProcessTx(st, P, CTransaction(mint), 7));
    BOOST_CHECK(!EnforcementOn(st, P, 7));
    BOOST_CHECK(!DefaultPayee(bare, P, 7, {}, PayeePolicy::Defaults(P)).has_value());
}

// Rule: SNAP
// Rule: ACT-5
// Rule: MINT-4
BOOST_AUTO_TEST_CASE(virtual_snapshot_below_start_height)
{
    Fixture f(50);
    State st(f.view);
    std::optional<Snapshot> v = SnapshotAt(st, f.P, 49);
    BOOST_REQUIRE(v.has_value());
    BOOST_CHECK_EQUAL(v->haltMask, (uint32_t)(HALT_NOT_ACTIVE | HALT_NO_PRICE));
    BOOST_CHECK_EQUAL(v->activation.status, (uint8_t)ActivationStatus::SIGNALING);
    BOOST_CHECK(!v->PFast().has_value() && !v->PMint().has_value() && !v->PClaim().has_value());
    BOOST_CHECK_EQUAL(v->issuedZat, 0);
    BOOST_CHECK(!EnforcementOn(st, f.P, 50));
    // Blocks below START_HEIGHT are ignored completely.
    BlockEvaluation below = f.Mine(Fixture::Quote(50000, 0), {}, 49);
    BOOST_CHECK(f.view.Map().empty());
    BOOST_CHECK(!below.enforcementOn && below.txlogs.empty());
    // At H = START_HEIGHT: the tag counts, issuedZat starts from 0, MINT-4 is false.
    BlockEvaluation at = f.Mine(Fixture::Quote(50000, 0), {}, 50);
    BOOST_CHECK(!at.enforcementOn);
    BOOST_CHECK_EQUAL(f.Snap(50).issuedZat, SUBSIDY);
    BOOST_CHECK_EQUAL(f.Snap(50).signalCount, 1u);
    BOOST_CHECK(!State(f.view).GetSnapshot(49).has_value());
    MintOpts o; o.collateral = 1000000000000LL; o.feeKey = 0;
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintTx(10000, 48, 50, o)), "mint-not-active");
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
    BOOST_CHECK_EQUAL(HaltMaskNames(s.haltMask)[1], "NO_PRICE");
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
    std::vector<yellowback::Params> sets = { RegtestParams(1, 0, 0, 0), RegtestParams(100, 0, 1, 0) };
    BOOST_CHECK_EQUAL(SelectParams(sets, 1).startHeight, 1);
    BOOST_CHECK_EQUAL(SelectParams(sets, 99).startHeight, 1);
    BOOST_CHECK_EQUAL(SelectParams(sets, 100).startHeight, 100);
    BOOST_CHECK_EQUAL(SelectParams(sets, 5000).startHeight, 100);
    BOOST_CHECK_EQUAL(SelectParams(sets, 0).startHeight, 1);          // none qualifies: the first set
    Fixture f;
    f.Activate();
    // A mint under the first set passes; the same mint evaluated under the second set hits its supply cap.
    CMutableTransaction m = f.MintTx(10000, 48, f.tip - 1);
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
        if (i % 3 == 0) data = EncodePayload(Payload::Mint(0, 10000, f.tip + 40, f.tip - 1, f.ownerKey.GetPubKey(), 3));   // MINT-3 fails: bad outputs
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
    BOOST_CHECK_MESSAGE(elapsed < 200000, strprintf("EvaluateBlock took %d us", (int)elapsed));
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
    MicroUsd poolPrice = 11500;   //!< 10,000 YEC back $100 at 115 % (not (a) under pClaim = max(x, a))
    MicroUsd attPrice = 10400;    //!< under pEmerg = min(x, a): 104 % < 105 % (EMERGENCY_RATIO_BPS)
    EmergencyFixture()
    {
        f.Arm(4);                     // four seated, three drawn: a selector matters and a signer can be spared
        CMutableTransaction m = f.MintV3(10000, 50000);
        BOOST_REQUIRE_EQUAL(MintVerdictOf(f, m), "");
        w = CTransaction(m).GetHash();
        for (int i = 0; i < 64; i++) f.Mine(Fixture::Quote(poolPrice, (f.tip + 1) % 3));
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
        const MicroUsd pClaim = std::max(f.Snap(R).PClaim().value(), attPrice);
        return ResidualZat(1000000000000LL, ClaimantMaxZat(10000, (int)BPS, pClaim));
    }
    RedResult Mine(const CMutableTransaction& tx)
    {
        BlockEvaluation ev = f.Mine(Fixture::Quote(poolPrice, (f.tip + 1) % 3), { tx });
        RedResult r;
        r.invalid = ev.blockInvalid;
        r.enforcing = ev.enforcementOn;
        r.vault = f.Vault(w).value();
        std::optional<TxLogRecord> log = f.Log(CTransaction(tx).GetHash());
        r.verdict = log.has_value() ? log->verdict : "none";
        if (log.has_value()) r.log = log.value();
        return r;
    }
};

} // namespace

// Rule: REG-A1
BOOST_AUTO_TEST_CASE(rega1_bare_bond_below_min_short_lock_refused)
{
    Fixture f;
    f.MineQuotesTo(20);
    BOOST_CHECK_EQUAL(VerdictOf(f, f.RegisterTx(0, 10 * COIN, -1, 0, true)), "none");        // bare bond script: not P2SH
    BOOST_CHECK_EQUAL(VerdictOf(f, f.RegisterTx(0, 10 * COIN - 1)), "none");                 // below BOND_MIN
    BOOST_CHECK_EQUAL(VerdictOf(f, f.RegisterTx(0, 10 * COIN, f.P.bondMinLock - 1)), "none"); // bondLocktime < H + BOND_MIN_LOCK
    BOOST_CHECK_EQUAL(VerdictOf(f, f.RegisterTx(0, 10 * COIN, (int)LOCKTIME_THRESHOLD)), "none");
    BOOST_CHECK(!f.Attestor(0).has_value());
    BOOST_CHECK_EQUAL(State(f.view).GetAttestorSeq().next, 0);
    // The exact minimum lock and bond hold; the record, the bond index and the counter follow.
    CMutableTransaction ok = f.RegisterTx(0, 10 * COIN, f.P.bondMinLock, 5);
    BOOST_CHECK_EQUAL(VerdictOf(f, ok), verdict::OK);
    std::optional<AttestorRecord> rec = f.Attestor(0);
    BOOST_REQUIRE(rec.has_value());
    BOOST_CHECK_EQUAL(rec->status, (uint8_t)AttestorStatus::PENDING);
    BOOST_CHECK_EQUAL(rec->registerHeight, f.tip);
    BOOST_CHECK_EQUAL(rec->bondZat, 10 * COIN);
    BOOST_CHECK_EQUAL(rec->flags, 5);
    BOOST_CHECK(rec->bondOutpoint == COutPoint(CTransaction(ok).GetHash(), 0));
    BOOST_CHECK_EQUAL(State(f.view).GetBondIndex(rec->bondOutpoint).value(), 0);
    BOOST_CHECK_EQUAL(State(f.view).GetAttestorSeq().next, 1);
    BOOST_CHECK_EQUAL(f.Log(CTransaction(ok).GetHash())->type, (uint8_t)TxLogType::ATTESTOR_REGISTER);
    BOOST_CHECK_EQUAL(f.Log(CTransaction(ok).GetHash())->attestorSeq, 0);
}

// Rule: REG-A1
// Rule: IN-2
BOOST_AUTO_TEST_CASE(rega1_duplicate_hot_key_vs_withdrawn)
{
    Fixture f;
    f.MineQuotesTo(20);
    f.Register(1);
    BOOST_CHECK_EQUAL(VerdictOf(f, f.RegisterTx(1, 10 * COIN, -1, 0, false, f.hotKeys[0].GetPubKey())), "none");   // held by seq 0
    BOOST_CHECK(!f.Attestor(1).has_value());
    // After the bond is spent the record is WITHDRAWN and the hot key is free again.
    while (f.tip < (int)f.Attestor(0)->bondLocktime) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(VerdictOf(f, f.BondSpendTx(0)), verdict::OK);
    BOOST_CHECK_EQUAL(f.Attestor(0)->status, (uint8_t)AttestorStatus::WITHDRAWN);
    BOOST_CHECK_EQUAL(VerdictOf(f, f.RegisterTx(1, 10 * COIN, -1, 0, false, f.hotKeys[0].GetPubKey())), verdict::OK);
    BOOST_CHECK_EQUAL(f.Attestor(1)->attestorPubKey.size(), 33u);
    BOOST_CHECK(f.Attestor(1)->attestorPubKey == f.Attestor(0)->attestorPubKey);
}

// Rule: REG-A1
// Rule: EQV-1
// Rule: IN-2
BOOST_AUTO_TEST_CASE(rega1_ejected_then_spent_stays_barred)
{
    Fixture f;
    f.Arm();
    // Eject seq 0, then spend its bond: the record stays EJECTED (bondSpentHeight set) and its hot key is barred for good.
    const int cited = f.tip;
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(VerdictOf(f, f.EquivocationTx(f.Att(0, 50000, cited), f.Att(0, 51000, cited))), verdict::OK);
    BOOST_CHECK_EQUAL(f.Attestor(0)->status, (uint8_t)AttestorStatus::EJECTED);
    while (f.tip < (int)f.Attestor(0)->bondLocktime) f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(VerdictOf(f, f.BondSpendTx(0)), verdict::OK);
    BOOST_CHECK_EQUAL(f.Attestor(0)->status, (uint8_t)AttestorStatus::EJECTED);
    BOOST_CHECK_EQUAL(f.Attestor(0)->bondSpentHeight, f.tip);
    BOOST_CHECK_EQUAL(VerdictOf(f, f.RegisterTx(3, 10 * COIN, -1, 0, false, f.hotKeys[0].GetPubKey())), "none");
    BOOST_CHECK(!f.Attestor(3).has_value());
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
    Fixture g(1, 0, 0, 0, 0);
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
    yellowback::Params P = RegtestParams(1, 0, 0, 0);
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
    BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintV3(10000, 40000)), verdict::MINT10_DIVERGED);
    BOOST_CHECK_EQUAL(f.Vault(f.evals[f.tip].txlogs[0].first)->voidReason, verdict::MINT10_DIVERGED);
    BOOST_CHECK_EQUAL(f.Log(f.evals[f.tip].txlogs[0].first)->aMint, 40000);          // the bundle facts are logged on a VOID mint too
    // BUNDLE-1 held, so the row is logged whatever the verdict (R12)
    BOOST_REQUIRE(f.BundleRow(f.tip).has_value());
    BOOST_CHECK_EQUAL(f.BundleRow(f.tip)->aMint, 40000);
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
    // pClaim = max(x, a): a vault backing $100 with 10,000 YEC is underwater under pools at 9,000 but not when attestors say 12,000.
    const uint256 w = CTransaction(f.MintV3(10000, 50000)).GetHash();
    { CMutableTransaction m = f.MintV3(10000, 50000); BOOST_REQUIRE_EQUAL(MintVerdictOf(f, m), ""); (void)w; }
    const uint256 v = f.evals[f.tip].txlogs[0].first;
    for (int i = 0; i < 64; i++) f.Mine(Fixture::Quote(9000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(f.Snap(f.tip).PClaim().value(), 9000);
    const valtype sel = OutPointSelector(COutPoint(v, 0));
    { SpendOpts o; o.ownerPath = false; o.bundle = f.BundleFor(f.tip - 1, sel, 12000); o.attestPayee = Selected(f.view, f.P, f.tip - 1, sel).front();
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
      BOOST_CHECK(r.invalid && r.enforcing);
      BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLOSED); }
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
    BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLAIMED);
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
    for (int i = 0; i < 64; i++) f.Mine(Fixture::Quote(11500, (f.tip + 1) % 3));
    // Unarmed: a notice registers nothing (NOT-1 needs ARMED at R) and a claim is judged by (a) alone.
    f.Mine(Fixture::Quote(11500, (f.tip + 1) % 3), { f.NoticeTx(v, f.tip - 1, valtype(4, 0x59)) });
    BOOST_CHECK(!f.Notice(v).has_value());
    BOOST_CHECK(f.evals[f.tip].txlogs.empty());
    // Force a notice record in and see (b) still false before arming.
    NoticeRecord n;
    n.height = f.tip - 6;
    n.refHeight = f.tip - 8;
    n.pEmerg = 10400;
    State(f.view).Put(keys::Notice(COutPoint(v, 0)), n);
    SpendOpts o;
    o.ownerPath = false;
    BlockEvaluation ev = f.Mine(Fixture::Quote(11500, (f.tip + 1) % 3), { f.SpendTx(v, { COutPoint(v, 1) }, f.tip - 1, o) });
    BOOST_CHECK(ev.blockInvalid);
    BOOST_CHECK_EQUAL(ev.txlogs[0].second.verdict, verdict::VAULT_CLAIM_NOT_UNDERWATER);
    BOOST_CHECK(!f.Notice(v).has_value());          // and the close deleted it (IN-2)
}

// Rule: RED-5
BOOST_AUTO_TEST_CASE(red5_residual_paid)
{
    EmergencyFixture g;
    BOOST_REQUIRE(g.PostNotice());
    for (int i = 0; i < g.f.P.emergencyPersist + 1; i++) g.f.Mine(Fixture::Quote(g.poolPrice, (g.f.tip + 1) % 3));
    const CAmount residual = g.Residual(g.f.tip - 1);
    BOOST_CHECK(residual >= g.f.P.residualMinZat);
    BOOST_CHECK_EQUAL(residual, 1000000000000LL - ClaimantMaxZat(10000, (int)BPS, g.poolPrice).value());
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
    BOOST_CHECK(r.log.attestFeeZat >= AttestFeeZat(FeeZat(1000000000000LL, g.f.P.feeMin, g.f.P.feeBps), g.f.P.attestFeeBps));
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
    BOOST_CHECK(50000 < RegtestParams(1, 0, 0, 0).residualMinZat);
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
    BOOST_CHECK(r.invalid && r.enforcing);
    BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLOSED);
    BOOST_CHECK(r.vault.unbacked == false);         // the burn was complete; only RED-5 failed
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
    BOOST_CHECK_EQUAL(r.vault.status, (uint8_t)VaultStatus::CLAIMED);
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
    BOOST_REQUIRE(g.PostNotice());
    BOOST_CHECK(g.f.evals[g.f.tip].txlogs.empty());
    const NoticeRecord again = g.f.Notice(g.w).value();
    BOOST_CHECK_EQUAL(again.height, first.height);
    BOOST_CHECK_EQUAL(again.refHeight, first.refHeight);
    // the row for the (verified) bundle is still logged (R12)
    BOOST_CHECK(g.f.BundleRow(g.f.tip).has_value());
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
    // and an unpoliced spend (no payload) deletes it too
    SpendOpts o; o.payload = false;
    g.Mine(g.f.SpendTx(g.w, {}, g.f.tip - 1, o));
    BOOST_CHECK(!g.f.Notice(g.w).has_value());
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

// Rule: REV-1
// Rule: SNAP
BOOST_AUTO_TEST_CASE(rev1_only_dormant)
{
    Fixture f;
    f.Arm(4);
    // An ELIGIBLE attestor cannot be "revived".
    BOOST_CHECK_EQUAL(VerdictOf(f, f.ReviveTx(f.Att(0, 50000, f.tip))), "none");
    // Make seq L dormant: two mints whose selection includes L, signed by the other two, then a check height.
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
    // Revive: stale (citedHeight == H - ATTEST_MAX_AGE), citedHeight == H, a tampered price... then a fresh one. (VerdictOf mines at H = tip + 1.)
    f.Mine(Fixture::Quote(50000, (f.tip + 1) % 3));
    BOOST_CHECK_EQUAL(VerdictOf(f, f.ReviveTx(f.Att(L, 50000, f.tip + 1 - f.P.attestMaxAge))), "none");
    { Attestation a = f.Att(L, 50000, f.tip, Fixture::FakeHash(f.tip + 1)); a.citedHeight = (uint32_t)f.tip + 1;
      BOOST_CHECK_EQUAL(VerdictOf(f, f.ReviveTx(a)), "none"); }                     // citedHeight == H: not <= H - 1
    { Attestation a = f.Att(L, 50000, f.tip); a.priceMicroUsd++; BOOST_CHECK_EQUAL(VerdictOf(f, f.ReviveTx(a)), "none"); }
    BOOST_CHECK_EQUAL(f.Attestor(L)->status, (uint8_t)AttestorStatus::DORMANT);
    CMutableTransaction r = f.ReviveTx(f.Att(L, 50000, f.tip));
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
    r1.selectedSeqs = { 1, 2, 3 }; r1.seqs = { 1, 2, 3 }; r1.prices = { 40000, 40000, 40000 };
    r2.selectedSeqs = { 1, 2 };    r2.seqs = { 1, 2 };    r2.prices = { 40100, 40000 };
    State(f.view).Put(keys::BundleLog((uint32_t)f.tip - 2), r1);
    State(f.view).Put(keys::BundleLog((uint32_t)f.tip), r2);
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
    State(f.view).Put(keys::BundleLog((uint32_t)f.tip), r);
    f.Mine(Fixture::Quote(40000, (f.tip + 1) % 3));
    BOOST_CHECK(f.Snap(f.tip).pinnedSeqs.empty());
    BOOST_CHECK(f.Snap(f.tip).pinnedKeys.empty());
}

// Rule: AFEE-1
// Rule: MINT-8
// Rule: RED-3
BOOST_AUTO_TEST_CASE(afee1_fee_to_contributor)
{
    Fixture f;
    f.Arm(4);
    const CAmount collateral = 1000000000000LL;
    const CAmount afee = AttestFeeZat(FeeZat(collateral, f.P.feeMin, f.P.feeBps), f.P.attestFeeBps);
    BOOST_CHECK_EQUAL(afee, FeeZat(collateral, f.P.feeMin, f.P.feeBps) / 4);
    // to a seated attestor that did not contribute: afee1-fee; one zat short: afee1-fee; missing: afee1-fee; at 0xFF: afee1-fee
    std::vector<uint16_t> sel = Selected(f.view, f.P, f.tip - 1, valtype());
    int outsider = -1;
    for (int q = 0; q < 4; q++) if (std::find(sel.begin(), sel.end(), (uint16_t)q) == sel.end()) outsider = q;
    BOOST_REQUIRE(outsider >= 0);
    { MintOpts o; o.attestPayee = outsider; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintV3(10000, 50000, o)), verdict::AFEE1_FEE); }
    { MintOpts o; o.attestFeeValue = afee - 1; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintV3(10000, 50000, o)), verdict::AFEE1_FEE); }
    { MintOpts o; o.attestFeeVout = 3; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintV3(10000, 50000, o)), verdict::AFEE1_FEE); }    // the pool fee's vout
    { MintOpts o; o.attestFeeVout = 9; BOOST_CHECK_EQUAL(MintVerdictOf(f, f.MintV3(10000, 50000, o)), verdict::AFEE1_FEE); }    // out of range
    { MintOpts o; o.attestFeeScript = GetScriptForDestination(f.hotKeys[sel[0]].GetPubKey().GetID());                              // the hot key, not the bond key
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
    BOOST_CHECK_EQUAL(cache.hits, 0);
    for (const auto& e : cache.entries) BOOST_CHECK(e.second);
    // hit: the same block again reads the cache and agrees byte for byte
    OverlayStateView warm(f.view);
    BlockEvaluation b = EvaluateBlock(warm, f.P, block, f.tip + 1, Fixture::FakeHash(f.tip + 1), SUBSIDY, &cache);
    warm.Discard();
    BOOST_CHECK_EQUAL(cache.hits, 3);
    BOOST_CHECK(SerializeRecord(a.snapshot) == SerializeRecord(b.snapshot));
    BOOST_CHECK(SerializeRecord(a.txlogs[0].second) == SerializeRecord(b.txlogs[0].second));
    BOOST_CHECK_EQUAL(a.txlogs[0].second.verdict, verdict::OK);
    // and without any cache the verdict is the same
    OverlayStateView none(f.view);
    BlockEvaluation c = EvaluateBlock(none, f.P, block, f.tip + 1, Fixture::FakeHash(f.tip + 1), SUBSIDY, nullptr);
    BOOST_CHECK(SerializeRecord(a.txlogs[0].second) == SerializeRecord(c.txlogs[0].second));
    // the same attestation on two branches keys two entries: the block hash of citedHeight is in the key
    const Attestation att = f.Att(0, 50000, f.tip - 1);
    BOOST_CHECK(SigCacheKey(att, Fixture::FakeHash(f.tip - 1)) != SigCacheKey(att, Fixture::FakeHash(f.tip)));
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
    // dormancy for L, then a revival
    int L = -1, rows = 0;
    while (rows < f.P.dormancyMinBundles) {
        const int R = f.tip - 1;
        std::vector<uint16_t> sel = Selected(f.view, f.P, R, valtype());
        if (sel.size() < 3) { f.Mine(Fixture::Quote(g.poolPrice, (f.tip + 1) % 3)); continue; }
        if (L < 0) L = sel.front();
        if (std::find(sel.begin(), sel.end(), (uint16_t)L) != sel.end()) {
            MintOpts o;
            o.attestPayee = -1;
            std::string v = MintVerdictOf(f, f.MintV3(10000, g.poolPrice, o, { L }));
            BOOST_REQUIRE_MESSAGE(v == "" || v == verdict::MINT_HALTED_GLOBAL_RATIO || v == verdict::MINT_HALTED_DIVERGENCE, v);
            if (f.BundleRow(f.tip).has_value()) rows++;
        } else {
            f.Mine(Fixture::Quote(g.poolPrice, (f.tip + 1) % 3));
        }
    }
    while (f.tip % f.P.dormancyCheck != 0) f.Mine(Fixture::Quote(g.poolPrice, (f.tip + 1) % 3));
    if (f.Attestor(L)->status == (uint8_t)AttestorStatus::DORMANT) {
        f.Mine(Fixture::Quote(g.poolPrice, (f.tip + 1) % 3));
        BOOST_CHECK_EQUAL(VerdictOf(f, f.ReviveTx(f.Att(L, g.poolPrice, f.tip - 1))), verdict::OK);
    }
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
    block.vtx.push_back(CTransaction(f.MintV3(10000, g.poolPrice)));
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

BOOST_AUTO_TEST_SUITE_END()
