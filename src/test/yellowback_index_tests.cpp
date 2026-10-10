// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The synchronous index and its hooks (plan Phase 3, §4.2a, §4.3, §8.4 items
// 3-8): fault injection at each hook (BLK-3), the tip-mismatch guards, the
// K5 null-hash shape of TestBlockValidity, the K6 re-verification no-op, the
// BLK-2 suppressions (kill switch, IBD/reindex, catch-up, the tripped valve,
// the sunset), the ACT-7 work valve with the P1 warning and the P2 bounds,
// MP-1 and the mempool sweep, MINER-1..3, and the MempoolCheck half of the
// N6 benchmark.
//
// The blocks are synthetic: real CBlock objects (whose hashes the index keys
// on) chained through fake CBlockIndex entries that hang off the regtest
// genesis, driven through CheckConnect/CommitConnect/UndoDisconnect exactly
// as ConnectBlock/DisconnectBlock would. chainActive stays at genesis, so a
// fake index is never "contained" (the re-verification case uses a real
// 100-block chain instead). Nothing here starts a node or the network.

#include "vault/act.h"
#include "yellowback/attest.h"
#include "yellowback/bundle.h"
#include "yellowback/index.h"
#include "yellowback/math.h"
#include "yellowback/payload.h"
#include "yellowback/policy.h"
#include "yellowback/script.h"
#include "yellowback/state.h"
#include "yellowback/tag.h"
#include "yellowback/view.h"

#include "chain.h"
#include "chainparams.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "crypto/pq/scheme.h"
#include "hash.h"
#include "key.h"
#include "main.h"
#include "pow.h"
#include "primitives/block.h"
#include "script/standard.h"
#include "test/test_bitcoin.h"
#include "test/yellowback_bench.h"
#include "txdb.h"
#include "txmempool.h"
#include "util/time.h"
#include "warnings.h"

#include <boost/test/unit_test.hpp>

#include <deque>
#include <set>

/** The YED attestor set the regtest parameters of these cases name (U-22). */
static inline uint256 TestSet() { return uint256S("5e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e7"); }

/** P4-b: the attestor set of the live fixtures is a primitive set: this SET_CREATE (open, 15 seats, maturity 1). */
static CMutableTransaction AttestorSetCreate()
{
    vault::Act a;
    a.type = vault::ACT_SET_CREATE;
    a.create.seats = 15;
    a.create.unlockThreshold = 1;
    a.create.cancelThreshold = 1;
    a.create.slashThreshold = 1;
    a.create.flags = vault::SET_FLAG_OPEN;
    a.create.rateWindow = 1000;
    a.create.livenessWindow = 1000000;
    a.create.bondMin = 1;
    a.create.maturity = 1;
    unsigned char d[32];
    memset(d, 0x42, 32);
    CKey admit;
    admit.Set(d, d + 32, true);
    a.create.admitKey = admit.GetPubKey();
    CMutableTransaction m;
    m.vin.push_back(CTxIn(COutPoint(TestSet(), 1)));
    m.vout.push_back(CTxOut(0, vault::EncodeAct(a)));
    return m;
}
static inline uint256 LiveSet() { return CTransaction(AttestorSetCreate()).GetHash(); }

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

uint160 KeyOf(int i)
{
    std::vector<unsigned char> v(20, (unsigned char)(0x10 + i));
    return uint160(v);
}

/**
 * A regtest TestingSetup whose tip is never "in initial block download": the
 * regtest genesis is years old, so nMaxTipAge is raised for the suite (the
 * IsInitialBlockDownload latch then stays false for the process, which is the
 * state every other suite runs in after TestChain100Setup anyway). Also
 * insulates the miner configuration read by the hooks.
 */
struct IndexSetup : public TestingSetup
{
    int64_t savedMaxTipAge;
    IndexSetup() : TestingSetup(CBaseChainParams::REGTEST), savedMaxTipAge(nMaxTipAge)
    {
        nMaxTipAge = 1LL << 40;
    }
    ~IndexSetup()
    {
        nMaxTipAge = savedMaxTipAge;
        // Fake entries a case inserted into mapBlockIndex are erased by the case's MapGuard.
    }
};

/** Inserts fake CBlockIndex entries into mapBlockIndex for a case and erases them again (they are owned by the case). */
struct MapGuard
{
    std::vector<uint256> inserted;
    void Insert(CBlockIndex* idx)
    {
        LOCK(cs_main);
        mapBlockIndex[idx->GetBlockHash()] = idx;
        inserted.push_back(idx->GetBlockHash());
    }
    ~MapGuard()
    {
        LOCK(cs_main);
        for (const uint256& h : inserted) mapBlockIndex.erase(h);
    }
};

/** A synthetic chain: real blocks, fake CBlockIndex entries hanging off the regtest genesis. */
struct Chain
{
    struct Node
    {
        CBlock block;
        uint256 hash;
        std::unique_ptr<CBlockIndex> idx;
    };
    std::deque<Node> nodes;

    CBlockIndex* Tip() { return nodes.empty() ? chainActive.Genesis() : nodes.back().idx.get(); }

    /** Append `block` on `parent` (default: the chain tip); the index entry carries real work arithmetic. */
    Node& Add(const CBlock& block, CBlockIndex* parent = nullptr)
    {
        if (!parent) parent = Tip();
        nodes.emplace_back();
        Node& n = nodes.back();
        n.block = block;
        if (parent->phashBlock) n.block.hashPrevBlock = parent->GetBlockHash();
        n.block.hashMerkleRoot = BlockMerkleRoot(n.block);     // the hash must depend on the transactions
        n.hash = n.block.GetHash();
        // A non-empty Equihash solution, as every real entry holds until written: the valve
        // flushes the block index (TripValve), and CBlockTreeDB::WriteBatchSync re-reads a
        // solution-less entry from disk, which a fake entry never was.
        CBlockHeader solved;
        solved.nSolution.assign(1, 0);
        n.idx.reset(new CBlockIndex(solved));
        n.idx->pprev = parent;
        n.idx->nHeight = parent->nHeight + 1;
        n.idx->phashBlock = &n.hash;
        n.idx->nBits = chainActive.Genesis()->nBits;
        n.idx->nTime = (uint32_t)GetTime();
        n.idx->nChainWork = parent->nChainWork + GetBlockProof(*n.idx);
        n.idx->BuildSkip();
        return n;
    }
};

/** Block and transaction builders (the state fixture's shapes, plan §3.4-3.5) over a live index. */
struct Builder
{
    yellowback::Params P;
    YellowbackIndex& index;
    CKey ownerKey, userKey;
    int fakeCounter;
    std::vector<CKey> hotKeys, bondKeys;    //!< v3: attestor i registers with hotKeys[i] / bondKeys[i] and becomes seq i

    Builder(const yellowback::Params& p, YellowbackIndex& i) : P(p), index(i), fakeCounter(0)
    {
        ownerKey = CKey::TestOnlyRandomKey(true);
        userKey = CKey::TestOnlyRandomKey(true);
        for (int k = 0; k < 6; k++) {
            hotKeys.push_back(DeterministicKey("yellowback-index-test-hot", k));
            bondKeys.push_back(hotKeys.back());     // P4-b: the member key is the bond key
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

    static CMutableTransaction Coinbase(int height, const std::optional<CoinbaseTag>& tag, uint32_t nonce = 0)
    {
        CMutableTransaction cb;
        CScript sig = CScript() << height;
        if (tag.has_value()) sig += TagPush(tag.value());
        if (nonce) sig << nonce;
        cb.vin.push_back(CTxIn(COutPoint(), sig));
        cb.vout.push_back(CTxOut(625000000, GetScriptForDestination(CKeyID(KeyOf(0)))));
        return cb;
    }

    static CBlock Block(int height, const std::optional<CoinbaseTag>& tag, std::vector<CMutableTransaction> txs = {}, uint32_t nonce = 0)
    {
        CBlock block;
        block.nTime = (uint32_t)GetTime();
        block.vtx.push_back(CTransaction(Coinbase(height, tag, nonce)));
        for (auto& m : txs) block.vtx.push_back(CTransaction(m));
        return block;
    }

    Snapshot Snap(int h) const
    {
        LOCK(index.cs_yellowback);
        std::optional<Snapshot> s = State(index.View()).GetSnapshot((uint32_t)h);
        BOOST_REQUIRE(s.has_value());
        return s.value();
    }

    std::optional<VaultRecord> Vault(const uint256& txid) const
    {
        LOCK(index.cs_yellowback);
        return State(index.View()).GetVault(COutPoint(txid, 0));
    }

    CAmount Required(Cents cents, int termClass, int refHeight) const
    {
        Snapshot s = Snap(refHeight);
        auto r = RequiredCollateralRounded(cents, MinRatioBps(P.baseRatioBps[termClass], s.sigmaMultBps), s.PMint().value());
        BOOST_REQUIRE(r.has_value());
        return r.value();
    }

    /** The §3.5 MINT of `cents`, class A, lockHeight = refHeight + lockBlocks, fee to the payee of the tag at refHeight. */
    CMutableTransaction MintTx(Cents cents, int lockBlocks, int refHeight)
    {
        CPubKey owner = ownerKey.GetPubKey();
        const uint32_t lock = (uint32_t)(refHeight + lockBlocks);
        CScript vs = YedVaultScript(P, TestPQOwner(owner), refHeight);           // U-23, IT-1: the V template
        CAmount collateral = Required(cents, 0, refHeight);
        CMutableTransaction m;
        m.vin.push_back(CTxIn(FakeInput()));
        m.vout.push_back(CTxOut(collateral, vs));
        m.vout.push_back(CTxOut(TOKEN_VALUE, GetScriptForDestination(owner.GetID())));
        Payload p = Payload::Mint(0, (uint32_t)cents, lock, (uint32_t)refHeight, TestPQOwner(owner), 3);
        m.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(p))));
        m.vout.push_back(CTxOut(FeeZat(collateral, P.feeMin, P.feeBps), GetScriptForDestination(CKeyID(KeyOf(refHeight % 3)))));
        return m;
    }

    /**
     * A vault spend: the owner path with no burn and no payload (RED-1 fails: vault-spend-malformed)
     * when `wellFormed` is false; with `wellFormed` a REDEEM payload, the fee and the burn of `yed`
     * so that RED-1..4 pass (the burn covers the debt when `yed` carries it).
     */
    CMutableTransaction SpendTx(const uint256& vaultTxid, int refHeight, bool wellFormed, const std::vector<COutPoint>& yed = {}, uint32_t expiry = 0)
    {
        std::optional<VaultRecord> v = Vault(vaultTxid);
        BOOST_REQUIRE(v.has_value());
        CMutableTransaction m;
        m.nLockTime = v->lockHeight;
        m.nExpiryHeight = expiry;
        m.vin.push_back(CTxIn(COutPoint(vaultTxid, 0), CScript() << valtype(71, 0x30) << OP_2, 0xFFFFFFFE));   // U-23: the V's owner selector
        for (const COutPoint& o : yed) m.vin.push_back(CTxIn(o));
        m.vout.push_back(CTxOut(v->collateralZat - 1000, GetScriptForDestination(userKey.GetPubKey().GetID())));
        CAmount fee = FeeZat(v->collateralZat, P.feeMin, P.feeBps);
        if ((int64_t)refHeight + 1 < v->lockHeight) fee += EarlyRedeemFeeZat(v->collateralZat, P.earlyRedeemFeeBps[v->termClass]);   // IT-9: an owner redeem mined before lockHeight
        m.vout.push_back(CTxOut(fee, GetScriptForDestination(CKeyID(KeyOf(refHeight % 3)))));
        if (wellFormed) {
            m.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(Payload::Redeem((uint32_t)refHeight, 1, {})))));
        } else {
            m.vout.push_back(CTxOut(0, GetScriptForDestination(userKey.GetPubKey().GetID())));
        }
        return m;
    }

    // ---------------------------------------------------------------- v3 (the state fixture's shapes over the live index)

    std::optional<AttestorRecord> Attestor(uint16_t seq) const
    {
        LOCK(index.cs_yellowback);
        return State(index.View()).GetAttestor(seq);
    }

    AttestState Attest() const
    {
        LOCK(index.cs_yellowback);
        return State(index.View()).GetAttest();
    }

    /** P4-b: attestor i joins the attestor set at the next height: vout[0] the 10 YEC bond (P2SH), vout[1] the SET_JOIN, change. */
    CMutableTransaction RegisterTx(int i, int nextHeight)
    {
        const uint32_t locktime = (uint32_t)(nextHeight + P.bondMinLock);
        vault::Act a;
        a.type = vault::ACT_SET_JOIN;
        a.join.setId = P.attestorSetId;
        a.join.memberKey = hotKeys[i].GetPubKey();
        a.join.bondLocktime = locktime;
        a.join.bondVout = 0;
        CMutableTransaction m;
        m.vin.push_back(CTxIn(FakeInput()));
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(vault::SignRecoverable(hotKeys[i], vault::ActMsg(vault::EncodePayload(a), m.vin[0].prevout), sig));
        a.sigs.push_back(sig);
        m.vout.push_back(CTxOut(10 * COIN, P2SHScript(BondScript(hotKeys[i].GetPubKey(), locktime))));
        m.vout.push_back(CTxOut(0, vault::EncodeAct(a)));
        m.vout.push_back(CTxOut(1000, GetScriptForDestination(userKey.GetPubKey().GetID())));
        return m;
    }

    /** A compact low-S signature of attestor seq over (seq, price, cited, blockHash), the block hash defaulting to the chain's. */
    Attestation Att(int seq, MicroUsd price, int cited, std::optional<uint256> blockHash = std::nullopt)
    {
        Attestation a;
        a.seq = (uint16_t)seq;
        a.priceMicroUsd = (uint32_t)price;
        a.citedHeight = (uint32_t)cited;
        const uint256 msg = AttestMessage(a.seq, a.priceMicroUsd, a.citedHeight, blockHash.value_or(Snap(cited).blockHash));
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

    std::vector<uint16_t> SelectedAt(int R, const valtype& selector) const
    {
        LOCK(index.cs_yellowback);
        return Selected(index.View(), P, R, selector);
    }

    /** The bundle for (R, selector): every selected seq not in `skip` signs `price` citing `cited` (default R). */
    valtype BundleFor(int R, const valtype& selector, MicroUsd price, std::set<int> skip = {}, int cited = -1)
    {
        Bundle b;
        for (uint16_t seq : SelectedAt(R, selector)) {
            if (skip.count(seq)) continue;
            b.atts.push_back(Att(seq, price, cited < 0 ? R : cited));
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

    /** The first seq of a bundle's attestations (the attestor fee payee). */
    static int FirstSeq(const valtype& bundle)
    {
        std::optional<Bundle> b = DecodeBundle(bundle);
        return b.has_value() && !b->atts.empty() ? (int)b->atts[0].seq : -1;
    }

    /** The §3.5 armed MINT: MintTx plus the carrier and the attestor fee to the bundle's first signer. Collateral at min(xMint, price). */
    CMutableTransaction MintV3(Cents cents, int refHeight, MicroUsd attestPrice, std::optional<valtype> bundleOverride = std::nullopt)
    {
        const valtype bundle = bundleOverride.value_or(BundleFor(refHeight, valtype(), attestPrice));
        CPubKey owner = ownerKey.GetPubKey();
        const uint32_t lock = (uint32_t)(refHeight + 48);
        Snapshot s = Snap(refHeight);
        const MicroUsd pMint = std::min(s.PMint().value(), attestPrice);
        CAmount collateral = RequiredCollateralRounded(cents, MinRatioBps(P.baseRatioBps[0], s.sigmaMultBps), pMint).value();
        CMutableTransaction m;
        m.vin.push_back(CTxIn(FakeInput()));
        m.vout.push_back(CTxOut(collateral, YedVaultScript(P, TestPQOwner(owner), refHeight)));           // U-23, IT-1: the V template
        m.vout.push_back(CTxOut(TOKEN_VALUE, GetScriptForDestination(owner.GetID())));
        const int payee = FirstSeq(bundle);
        Payload p = Payload::Mint(0, (uint32_t)cents, lock, (uint32_t)refHeight, TestPQOwner(owner), 3, payee >= 0 ? 4 : FEE_VOUT_NONE);
        m.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(p))));
        const CAmount fee = FeeZat(collateral, P.feeMin, P.feeBps);
        m.vout.push_back(CTxOut(fee, GetScriptForDestination(CKeyID(KeyOf(refHeight % 3)))));
        if (payee >= 0) m.vout.push_back(CTxOut(AttestFeeZat(fee, P.attestFeeBps), GetScriptForDestination(bondKeys[payee].GetPubKey().GetID())));
        m.vin.push_back(CarrierIn(bundle));
        return m;
    }

    /** A claim-path spend (selector 4, U-23) burning the vault's own token: vout[0] the claimant's intent, [1] fee, [2] payload,
     *  [3] attestor fee, [4] the owner's residual intent when given; the fees from a fake input. */
    CMutableTransaction ClaimTx(const uint256& vaultTxid, int refHeight, const valtype& bundle, std::optional<CAmount> residual)
    {
        std::optional<VaultRecord> v = Vault(vaultTxid);
        BOOST_REQUIRE(v.has_value());
        const CScript vs = YedVaultScriptAt(P, v->Owner(), v->ownerHeight, v->appHeight);
        const vault::VaultParams vp = YedVaultParamsAt(P, v->Owner(), v->ownerHeight, v->appHeight);
        CMutableTransaction m;
        m.nLockTime = v->appHeight;
        m.nExpiryHeight = (uint32_t)(refHeight + P.refWindow);
        m.vin.push_back(CTxIn(COutPoint(vaultTxid, 0), CScript() << OP_4, 0xFFFFFFFE));
        m.vin.push_back(CTxIn(COutPoint(vaultTxid, 1)));
        m.vin.push_back(CTxIn(FakeInput()));
        m.vout.push_back(CTxOut(v->collateralZat - residual.value_or(0), vault::BuildIntent(vault::IntentFor(vp, vs, GetScriptForDestination(userKey.GetPubKey().GetID())))));
        const CAmount fee = FeeZat(v->collateralZat, P.feeMin, P.feeBps);
        m.vout.push_back(CTxOut(fee, GetScriptForDestination(CKeyID(KeyOf(refHeight % 3)))));
        const int payee = FirstSeq(bundle);
        m.vout.push_back(CTxOut(0, PayloadScript(EncodePayload(Payload::Redeem((uint32_t)refHeight, 1, {}, payee >= 0 ? 3 : FEE_VOUT_NONE)))));
        if (payee >= 0) m.vout.push_back(CTxOut(AttestFeeZat(fee, P.attestFeeBps), GetScriptForDestination(bondKeys[payee].GetPubKey().GetID())));
        if (residual.has_value()) m.vout.push_back(CTxOut(residual.value(), vault::BuildIntent(vault::IntentFor(vp, vs, GetScriptForDestination(v->Owner())))));   // the owner's PQPKH (F-3)
        m.vin.push_back(CarrierIn(bundle));
        return m;
    }

    /** A CLAIM_NOTICE for the vault with refHeight R carrying `bundle`. */
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
};

/** ConnectBlock's two calls for one synthetic block; returns CheckConnect's verdict, "bad-yellowback-<verdict>", or
 *  "failure: <why>" for a node failure (ConnectBlock aborts on it); commits only when accepted. */
std::optional<std::string> Connect(YellowbackIndex& index, Chain::Node& n, bool fJustCheck = false)
{
    LOCK(cs_main);
    YellowbackIndex::ConnectCheck c = index.CheckConnect(n.block, n.idx.get(), fJustCheck);
    if (c.failure) return "failure: " + *c.failure;
    if (!c.invalid.has_value() && !fJustCheck) index.CommitConnect(n.block, n.idx.get());
    return c.invalid;
}

int TipHeightOf(YellowbackIndex& index)
{
    LOCK(index.cs_yellowback);
    return index.TipHeight();
}

uint256 HashOf(YellowbackIndex& index)
{
    LOCK(index.cs_yellowback);
    return index.GetStateHash();
}

/**
 * An index over a synthetic chain brought to ACTIVE with one ACTIVE vault
 * (quote+signal tags from three rotating pools to startHeight + 2 *
 * signalWindow + 2, then a mint), the shape every rejection case starts from.
 */
struct Live
{
    yellowback::Params P;
    std::unique_ptr<YellowbackIndex> index;
    std::unique_ptr<Builder> b;
    Chain chain;
    CBlockIndex* tip;      //!< the last accepted block (a rejected block never advances it)
    uint256 vault;
    int vaultRef;
    bool jitter;           //!< v3: pools alternate price and price + 1 so PIN-1 never pins them when attestors move (a pool quoting one price is what PIN-1 pins)

    bool setMined = false;

    explicit Live(const fs::path& dir) : P(RegtestParams(1, 0, 0, LiveSet())), tip(chainActive.Genesis()), jitter(false)
    {
        index.reset(new YellowbackIndex(P, dir, 1 << 20, true));
        BOOST_REQUIRE(index->SyncToChain());
        b.reset(new Builder(P, *index));
        MinerConfig cfg;
        cfg.payoutKey = CKeyID(KeyOf(0));
        index->SetMinerConfig(cfg);
    }

    int Tip() { return tip->nHeight; }

    /** Mine one quote+signal block from pool (height % 3); asserts acceptance. */
    Chain::Node& MineQuote(MicroUsd price = 50000, bool signal = true)
    {
        const int h = Tip() + 1;
        if (jitter) price += (h / 3) % 2;
        Chain::Node& n = chain.Add(Builder::Block(h, Builder::Quote(price, h % 3, signal)), tip);
        BOOST_REQUIRE(!Connect(*index, n).has_value());
        BOOST_REQUIRE_EQUAL(TipHeightOf(*index), h);
        tip = n.idx.get();
        return n;
    }

    void Activate()
    {
        while (Tip() < P.startHeight + 130) MineQuote();          // every window filled (v2's start + 2 * signal window + 2)
        BOOST_REQUIRE_EQUAL(b->Snap(Tip()).haltMask, 0u);
    }

    /** Mint an ACTIVE vault at tip + 1 (refHeight = tip - 1). */
    void MintActive()
    {
        vaultRef = Tip() - 1;
        CMutableTransaction m = b->MintTx(10000, 48, vaultRef);
        const int h = Tip() + 1;
        Chain::Node& n = chain.Add(Builder::Block(h, Builder::Quote(50000, h % 3), { m }), tip);
        BOOST_REQUIRE(!Connect(*index, n).has_value());
        tip = n.idx.get();
        vault = CTransaction(m).GetHash();
        std::optional<VaultRecord> v = b->Vault(vault);
        BOOST_REQUIRE(v.has_value());
        BOOST_REQUIRE_MESSAGE(v->Status() == VaultStatus::ACTIVE, v->voidReason);
    }

    /** A block at tip + 1 carrying a malformed owner-path spend of the vault (BLK-1 fails: RED-1). */
    Chain::Node& BadBlock(uint32_t nonce = 0)
    {
        const int h = Tip() + 1;
        CMutableTransaction s = b->SpendTx(vault, h - 2, false);
        return chain.Add(Builder::Block(h, std::nullopt, { s }, nonce), tip);
    }

    /** Mine one quote block from pool (height % 3) carrying `txs`; asserts acceptance. */
    Chain::Node& MineWith(std::vector<CMutableTransaction> txs, MicroUsd price = 50000)
    {
        const int h = Tip() + 1;
        if (jitter) price += (h / 3) % 2;
        Chain::Node& n = chain.Add(Builder::Block(h, Builder::Quote(price, h % 3), txs), tip);
        BOOST_REQUIRE(!Connect(*index, n).has_value());
        tip = n.idx.get();
        return n;
    }

    /** v3: activate (if needed), register n attestors one per block, mine until ARMED and one more (Snapshots[tip - 1] ARMED). */
    void Arm(int n = 3)
    {
        if (Tip() < P.startHeight + 130) Activate();
        if (!setMined) {
            MineWith({ AttestorSetCreate() });           // P4-b: the attestor set's SET_CREATE
            setMined = true;
        }
        for (int i = 0; i < n; i++) {
            MineWith({ b->RegisterTx(i, Tip() + 1) });
            BOOST_REQUIRE_MESSAGE(b->Attestor((uint16_t)i).has_value(), strprintf("attestor %d not registered at %d", i, Tip()));
        }
        while (!b->Attest().IsArmed()) MineQuote();
        MineQuote();
        BOOST_REQUIRE(b->Attest().IsArmed());
        LOCK(index->cs_yellowback);
        BOOST_REQUIRE(ArmedAt(index->View(), P, Tip() - 1));
    }
};

CBlockHeader HeaderOn(const uint256& prev, uint32_t nonce, uint32_t nBits)
{
    CBlockHeader h;
    h.nVersion = 4;
    h.hashPrevBlock = prev;
    h.nTime = (uint32_t)GetTime();
    h.nBits = nBits;
    std::vector<unsigned char> n(32, 0);
    n[0] = nonce & 0xff;
    n[1] = (nonce >> 8) & 0xff;
    h.nNonce = uint256(n);
    return h;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(yellowback_index_tests, IndexSetup)

// Rule: BLK-3
BOOST_AUTO_TEST_CASE(exception_boundary)
{
    yellowback::Params params = RegtestParams(1, 0, 0, TestSet());
    YellowbackIndex index(params, pathTemp / "yellowback-test", 1 << 20, true);
    BOOST_CHECK(index.SyncToChain());        // chain at genesis (< startHeight): empty and healthy
    BOOST_CHECK(index.IsHealthy());
    {
        LOCK(cs_main);
        LOCK(index.cs_yellowback);
        BOOST_CHECK(!index.GetTip().has_value());
        BOOST_CHECK(index.IsSynced());
    }

    Chain chain;
    Chain::Node& n1 = chain.Add(Builder::Block(1, std::nullopt));

    // Fault injection: an exception in CheckConnect is caught, marks the index unhealthy, does not propagate.
    index.testBeforeApply = [] { throw std::runtime_error("injected fault"); };
    {
        LOCK(cs_main);
        BOOST_CHECK_NO_THROW(index.CheckConnect(n1.block, n1.idx.get(), false));
    }
    BOOST_CHECK(!index.IsHealthy());
    BOOST_CHECK(index.UnhealthyReason().find("injected fault") != std::string::npos);
    // Further deliveries are ignored while unhealthy.
    index.testBeforeApply = nullptr;
    {
        LOCK(cs_main);
        BOOST_CHECK_NO_THROW(index.CheckConnect(n1.block, n1.idx.get(), false));
        BOOST_CHECK(!index.CommitConnect(n1.block, n1.idx.get()));
        BOOST_CHECK(index.MempoolCheckReason(CTransaction()).has_value());    // unhealthy: admits nothing (U-21)
    }
    BOOST_CHECK(!index.IsHealthy());

    // Fresh index: the start block applies (v2 has no genesis anchor; an empty block is a valid start).
    YellowbackIndex index2(params, pathTemp / "yellowback-test2", 1 << 20, true);
    BOOST_CHECK(index2.SyncToChain());
    BOOST_CHECK(!Connect(index2, n1).has_value());
    BOOST_CHECK(index2.IsHealthy());
    {
        LOCK(index2.cs_yellowback);
        BOOST_REQUIRE(index2.GetTip().has_value());
        BOOST_CHECK_EQUAL(index2.GetTip()->height, 1);
        BOOST_CHECK_EQUAL(index2.GetTip()->blockHash.ToString(), n1.hash.ToString());
    }

    // Stop(): later deliveries return at once and change nothing (D2).
    YellowbackIndex index3(params, pathTemp / "yellowback-test3", 1 << 20, true);
    BOOST_CHECK(index3.SyncToChain());
    index3.Stop();
    BOOST_CHECK(index3.IsStopped());
    index3.testBeforeApply = [] { throw std::runtime_error("must not run"); };
    {
        LOCK(cs_main);
        BOOST_CHECK_NO_THROW(index3.CheckConnect(n1.block, n1.idx.get(), false));
    }
    BOOST_CHECK(index3.IsHealthy());

    // A disconnect below startHeight is ignored.
    YellowbackIndex index4(params, pathTemp / "yellowback-test4", 1 << 20, true);
    BOOST_CHECK(index4.SyncToChain());
    {
        LOCK(cs_main);
        BOOST_CHECK(index4.UndoDisconnect(chainActive.Genesis()));
    }
    BOOST_CHECK(index4.IsHealthy());

    // An unconfigured network (startHeight 0, as testnet until its release sets it) refuses to start.
    yellowback::Params unconfigured = MainParams();
    unconfigured.startHeight = 0;
    YellowbackIndex index5(unconfigured, pathTemp / "yellowback-test5", 1 << 20, true);
    BOOST_CHECK(!index5.SyncToChain());
    BOOST_CHECK(!index5.IsHealthy());
}

// Rule: BLK-3
BOOST_AUTO_TEST_CASE(check_storage_fault_accepts_and_sets_unhealthy)
{
    // -yellowbacktestfault=storage:check: the fault fires once in CheckConnect. Since the vault upgrade (U-21) a
    // storage failure is a node failure, never an acceptance: CheckConnect reports it (ConnectBlock aborts) and
    // the index is unhealthy; nothing is committed. (The case keeps its v2 name.)
    Live live(pathTemp / "yb-check-fault");
    live.Activate();
    live.MintActive();
    BOOST_CHECK(!live.index->SetTestFault("storage:check").has_value());
    Chain::Node& bad = live.BadBlock();
    const int hashBefore = TipHeightOf(*live.index);
    BOOST_CHECK_EQUAL(Connect(*live.index, bad).value_or("").substr(0, 8), "failure:");
    BOOST_CHECK(!live.index->IsHealthy());
    BOOST_CHECK(live.index->UnhealthyReason().find("CheckConnect") != std::string::npos);
    BOOST_CHECK_EQUAL(TipHeightOf(*live.index), hashBefore);
    // A bad spec is refused at once (init refuses to start).
    BOOST_CHECK(live.index->SetTestFault("storage:bogus").has_value());
    BOOST_CHECK(live.index->SetTestFault("storage:check:x:y").has_value());
    BOOST_CHECK(live.index->SetTestFault("nonsense").has_value());
}

// Rule: BLK-3
BOOST_AUTO_TEST_CASE(commit_storage_fault_sets_unhealthy)
{
    // storage:commit:<height>: fires only at that height; CommitConnect returns false, the index is
    // unhealthy (ConnectBlock then aborts the node, U-21).
    Live live(pathTemp / "yb-commit-fault");
    live.Activate();
    const int target = live.Tip() + 2;
    BOOST_CHECK(!live.index->SetTestFault(strprintf("storage:commit:%d", target)).has_value());
    live.MineQuote();                                  // tip + 1: not the fault height
    BOOST_CHECK(live.index->IsHealthy());
    const int h = live.Tip() + 1;
    Chain::Node& n = live.chain.Add(Builder::Block(h, Builder::Quote(50000, h % 3)));
    {
        LOCK(cs_main);
        BOOST_CHECK(!live.index->CheckConnect(n.block, n.idx.get(), false).invalid.has_value());
        BOOST_CHECK(!live.index->CommitConnect(n.block, n.idx.get()));
    }
    BOOST_CHECK(!live.index->IsHealthy());
    BOOST_CHECK(live.index->UnhealthyReason().find("CommitConnect") != std::string::npos);
    BOOST_CHECK_EQUAL(TipHeightOf(*live.index), h - 1);   // the batch was discarded
    BOOST_CHECK(!live.index->GetTestFault().armed);        // consumed
}

// Rule: BLK-3
// Rule: UNDO
BOOST_AUTO_TEST_CASE(undo_tip_mismatch_refuses)
{
    Live live(pathTemp / "yb-undo");
    live.Activate();
    Chain::Node& below = live.chain.nodes[live.chain.nodes.size() - 2];
    const uint256 before = HashOf(*live.index);
    {
        LOCK(cs_main);
        // Undo of a block that is not the index tip: refused, unhealthy.
        BOOST_CHECK(!live.index->UndoDisconnect(below.idx.get()));
    }
    BOOST_CHECK(!live.index->IsHealthy());
    BOOST_CHECK(live.index->UnhealthyReason().find("tip-mismatch") != std::string::npos);
    BOOST_CHECK(HashOf(*live.index) == before);

    // A healthy index: undo of the tip succeeds and restores the previous hash; storage:undo fails open.
    Live live2(pathTemp / "yb-undo2");
    live2.Activate();
    const uint256 h1 = HashOf(*live2.index);
    Chain::Node& n = live2.MineQuote();
    {
        LOCK(cs_main);
        BOOST_CHECK(live2.index->UndoDisconnect(n.idx.get()));
    }
    BOOST_CHECK(HashOf(*live2.index) == h1);
    BOOST_CHECK(live2.index->IsHealthy());
    // A sibling of the undone block on the same parent connects (the index tip is the parent again).
    Chain::Node& n2 = live2.chain.Add(Builder::Block(n.idx->nHeight, Builder::Quote(50000, 1), {}, 7), n.idx->pprev);
    BOOST_CHECK(!Connect(*live2.index, n2).has_value());
    BOOST_CHECK(!live2.index->SetTestFault("storage:undo").has_value());
    {
        LOCK(cs_main);
        BOOST_CHECK(!live2.index->UndoDisconnect(n2.idx.get()));
    }
    BOOST_CHECK(!live2.index->IsHealthy());
    BOOST_CHECK(live2.index->UnhealthyReason().find("UndoDisconnect") != std::string::npos);
}

// Rule: BLK-1
// Rule: BLK-2
BOOST_AUTO_TEST_CASE(check_null_hash)
{
    // K5: under TestBlockValidity pindex is indexDummy with a null phashBlock. CheckConnect keys on
    // block.GetHash() and pprev only; fJustCheck never commits (§8.4 item 7).
    Live live(pathTemp / "yb-nullhash");
    live.Activate();
    live.MintActive();
    const uint256 before = HashOf(*live.index);
    const int tipBefore = TipHeightOf(*live.index);

    CBlockIndex dummy;
    dummy.pprev = live.chain.Tip();
    dummy.nHeight = dummy.pprev->nHeight + 1;
    dummy.phashBlock = nullptr;
    CBlock good = Builder::Block(dummy.nHeight, Builder::Quote(50000, 0));
    good.hashMerkleRoot = BlockMerkleRoot(good);
    {
        LOCK(cs_main);
        BOOST_CHECK(!live.index->CheckConnect(good, &dummy, true).invalid.has_value());
    }
    CMutableTransaction s = live.b->SpendTx(live.vault, dummy.nHeight - 2, false);
    CBlock badBlock = Builder::Block(dummy.nHeight, std::nullopt, { s });
    badBlock.hashMerkleRoot = BlockMerkleRoot(badBlock);
    {
        LOCK(cs_main);
        std::optional<std::string> bad = live.index->CheckConnect(badBlock, &dummy, true).invalid;
        BOOST_REQUIRE(bad.has_value());
        BOOST_CHECK(bad->find("vault-spend-malformed") != std::string::npos);
    }
    BOOST_CHECK_EQUAL(TipHeightOf(*live.index), tipBefore);     // never committed
    BOOST_CHECK(HashOf(*live.index) == before);
    BOOST_CHECK(live.index->IsHealthy());
}

// Rule: BLK-1
// Rule: SNAP
BOOST_FIXTURE_TEST_CASE(check_reverify, TestChain100Setup)
{
    // K6: a block already in chainActive (VerifyDB level 4, verifychain) is a silent no-op for both
    // hooks; the tip and the hash are unchanged and the index stays healthy.
    yellowback::Params params = RegtestParams(1, 0, 0, TestSet());
    YellowbackIndex index(params, pathTemp / "yb-reverify", 1 << 20, true);
    BOOST_REQUIRE(index.SyncToChain());
    BOOST_REQUIRE_EQUAL(TipHeightOf(index), 100);
    const uint256 before = HashOf(index);
    for (int h : { 1, 50, 100 }) {
        LOCK(cs_main);
        CBlockIndex* pindex = chainActive[h];
        CBlock block;
        BOOST_REQUIRE(ReadBlockFromDisk(block, pindex, ::Params().GetConsensus()));
        BOOST_CHECK(!index.CheckConnect(block, pindex, false).invalid.has_value());
        BOOST_CHECK(index.CommitConnect(block, pindex));
    }
    BOOST_CHECK_EQUAL(TipHeightOf(index), 100);
    BOOST_CHECK(HashOf(index) == before);
    BOOST_CHECK(index.IsHealthy());
    // The real disconnect of the tip undoes, the re-connect re-applies to the same hash (apply/undo identity).
    {
        LOCK(cs_main);
        CBlockIndex* tip = chainActive[100];
        CBlock block;
        BOOST_REQUIRE(ReadBlockFromDisk(block, tip, ::Params().GetConsensus()));
        BOOST_CHECK(index.UndoDisconnect(tip));
        BOOST_CHECK_EQUAL(TipHeightOf(index), 99);
        // A block whose parent is the tip but which is not in chainActive[100]'s slot: a fake sibling entry.
        CBlockIndex sibling = *tip;
        sibling.phashBlock = tip->phashBlock;
        BOOST_CHECK(!index.CheckConnect(block, &sibling, false).invalid.has_value());
        BOOST_CHECK(index.CommitConnect(block, &sibling));
    }
    BOOST_CHECK_EQUAL(TipHeightOf(index), 100);
    BOOST_CHECK(HashOf(index) == before);
}

// Rule: BLK-3
// Rule: BLK-2
BOOST_AUTO_TEST_CASE(check_unhealthy)
{
    Live live(pathTemp / "yb-unhealthy");
    live.Activate();
    live.MintActive();
    live.index->SetUnhealthy("test");
    Chain::Node& bad = live.BadBlock();
    BOOST_CHECK_EQUAL(Connect(*live.index, bad).value_or("").substr(0, 8), "failure:");   // U-21: unhealthy aborts, never accepts
    BOOST_CHECK(policy::BuildTagScript(*live.index, 0).empty());     // MINER-3: no tag while unhealthy
}

// Rule: BLK-3
BOOST_AUTO_TEST_CASE(check_tip_mismatch)
{
    // A block whose parent is not the index tip (and that is not a re-verification) marks the index
    // unhealthy and is a node failure (U-21); the storage is untouched.
    Live live(pathTemp / "yb-tipmismatch");
    live.Activate();
    Chain::Node& top = live.chain.nodes.back();
    const uint256 before = HashOf(*live.index);
    Chain::Node& stray = live.chain.Add(Builder::Block(top.idx->nHeight, Builder::Quote(50000, 2), {}, 99), top.idx->pprev);
    BOOST_CHECK_EQUAL(Connect(*live.index, stray).value_or("").substr(0, 8), "failure:");
    BOOST_CHECK(!live.index->IsHealthy());
    BOOST_CHECK(live.index->UnhealthyReason().find("tip-mismatch") != std::string::npos);
    BOOST_CHECK(HashOf(*live.index) == before);
    // An empty index refuses a first block that is not at startHeight the same way.
    yellowback::Params p5 = RegtestParams(5, 0, 0, TestSet());
    YellowbackIndex index5(p5, pathTemp / "yb-tipmismatch5", 1 << 20, true);
    BOOST_REQUIRE(index5.SyncToChain());
    {
        LOCK(cs_main);
        BOOST_CHECK(index5.CheckConnect(top.block, top.idx.get(), false).failure.has_value());
    }
    BOOST_CHECK(!index5.IsHealthy());
}

// Rule: MP-1
BOOST_AUTO_TEST_CASE(mempoolcheck_bench)
{
    // The MempoolCheck half of N6: 10,000 plain transactions in under a second (O(inputs) lookups,
    // no SNAP); a well-formed vault spend is admitted, a malformed one refused with its verdict, one
    // without the expiry bound refused with mempool-expiry, a mint never refused; the ConnectTip
    // sweep drops the failing spend and keeps the rest.
    Live live(pathTemp / "yb-mp1");
    live.Activate();
    live.MintActive();
    std::vector<CTransaction> plain;
    for (int i = 0; i < 10000; i++) {
        CMutableTransaction m;
        m.vin.push_back(CTxIn(live.b->FakeInput()));
        m.vin.push_back(CTxIn(live.b->FakeInput()));
        m.vout.push_back(CTxOut(1000 + i, GetScriptForDestination(live.b->userKey.GetPubKey().GetID())));
        plain.push_back(CTransaction(m));
    }
    const int64_t t0 = GetTimeMicros();
    for (const CTransaction& tx : plain) BOOST_CHECK(live.index->MempoolCheck(tx));
    const int64_t elapsed = GetTimeMicros() - t0;
    BOOST_TEST_MESSAGE(strprintf("MempoolCheck over 10000 plain transactions: %d us", (int)elapsed));
    BOOST_CHECK_MESSAGE(elapsed < 1000000 * BenchBudgetScale(), strprintf("MempoolCheck took %d us (budget %d us)", (int)elapsed, (int)(1000000 * BenchBudgetScale())));

    const int ref = live.Tip() - 1;
    CMutableTransaction good = live.b->SpendTx(live.vault, ref, true, { COutPoint(live.vault, 1) }, (uint32_t)(ref + live.P.refWindow));
    CMutableTransaction malformed = live.b->SpendTx(live.vault, ref, false, {}, (uint32_t)(ref + live.P.refWindow));
    CMutableTransaction noExpiry = live.b->SpendTx(live.vault, ref, true, { COutPoint(live.vault, 1) }, 0);
    CMutableTransaction lateExpiry = live.b->SpendTx(live.vault, ref, true, { COutPoint(live.vault, 1) }, (uint32_t)(ref + live.P.refWindow + 1));
    CMutableTransaction mint = live.b->MintTx(10000, 48, ref);
    BOOST_CHECK(live.index->MempoolCheck(CTransaction(good)));
    BOOST_CHECK(!live.index->MempoolCheck(CTransaction(malformed)));
    BOOST_CHECK_EQUAL(live.index->MempoolCheckReason(CTransaction(malformed)).value_or(""), "vault-spend-malformed");
    BOOST_CHECK_EQUAL(live.index->MempoolCheckReason(CTransaction(noExpiry)).value_or(""), "mempool-expiry");
    BOOST_CHECK_EQUAL(live.index->MempoolCheckReason(CTransaction(lateExpiry)).value_or(""), "mempool-expiry");
    BOOST_CHECK(live.index->MempoolCheck(CTransaction(mint)));
    BOOST_CHECK(live.index->MempoolCheck(CTransaction(plain[0])));

    // Audit A-1: a peer streaming distinct garbage vault spends costs this node RED-1..5 per candidate, never a
    // ComputeSnapshot (the 2,016-height windows, the attestor scan). 1,000 distinct malformed spends of the
    // ACTIVE vault in well under the time 1,000 snapshots would take (about 10x the plain-transaction bound).
    std::vector<CTransaction> garbage;
    for (int i = 0; i < 1000; i++) {
        CMutableTransaction g = malformed;
        g.vout[0].nValue = 1000 + i;                       // a distinct txid each (recentRejects filters only identical ones)
        garbage.push_back(CTransaction(g));
    }
    const int64_t g0 = GetTimeMicros();
    for (const CTransaction& tx : garbage) BOOST_CHECK(!live.index->MempoolCheck(tx));
    const int64_t gElapsed = GetTimeMicros() - g0;
    BOOST_TEST_MESSAGE(strprintf("MempoolCheck over 1000 distinct malformed vault spends: %d us", (int)gElapsed));
    BOOST_CHECK(gElapsed < 2000000);

    // The sweep (N5): a pool holding the malformed spend, a plain transaction and the good spend.
    CTxMemPool pool(CFeeRate(0));
    TestMemPoolEntryHelper entry;
    CMutableTransaction plain0(plain[0]);
    pool.addUnchecked(malformed.GetHash(), entry.FromTx(malformed));
    pool.addUnchecked(plain0.GetHash(), entry.FromTx(plain0));
    pool.addUnchecked(good.GetHash(), entry.FromTx(good));
    BOOST_CHECK_EQUAL(pool.size(), 3u);
    {
        LOCK(cs_main);
        live.index->RemoveInvalidVaultSpends(pool);
    }
    BOOST_CHECK_EQUAL(pool.size(), 2u);
    BOOST_CHECK(!pool.exists(malformed.GetHash()));
    BOOST_CHECK(pool.exists(plain0.GetHash()));
    BOOST_CHECK(pool.exists(good.GetHash()));
}

// Rule: MINER-1
BOOST_AUTO_TEST_CASE(coinbase_flags_empty_without_flag)
{
    // Plan §8.4 item 2, the central claim of §1 (a): the two `+ COINBASE_FLAGS` appends in
    // miner.cpp (CreateCoinbaseTransaction :289 and IncrementExtraNonce :788) are the only
    // unguarded behaviour-bearing insertions in the mining path, and without -yellowback they
    // must be byte-level no-ops, so a node without the flag builds the stock coinbase exactly.
    //
    // COINBASE_FLAGS is assigned only at miner.cpp:352, from the module when g_yellowback is
    // non-null and from a default-constructed CScript otherwise; in this binary nothing ever
    // sets the module, which is the without-the-flag configuration.
    BOOST_CHECK(g_yellowback == nullptr);
    BOOST_CHECK(COINBASE_FLAGS.empty());

    // The BIP34 height push changes width at these boundaries (CScriptNum encoding), so the
    // append is checked against each: a wider push must not make the concatenation differ.
    const int heights[] = {1, 16, 17, 127, 128, 65535, 65536, 16777215, 16777216};
    for (int nHeight : heights) {
        const CScript stockCreate = CScript() << nHeight << OP_0;
        const CScript forkCreate = (CScript() << nHeight << OP_0) + COINBASE_FLAGS;
        BOOST_CHECK_MESSAGE(forkCreate == stockCreate,
                            "CreateCoinbaseTransaction scriptSig differs at height " << nHeight);
        BOOST_CHECK_EQUAL(forkCreate.size(), stockCreate.size());

        for (unsigned int nExtraNonce : {0u, 1u, 0xffffu}) {
            const CScript stockIncr = CScript() << nHeight << CScriptNum(nExtraNonce);
            const CScript forkIncr = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
            BOOST_CHECK_MESSAGE(forkIncr == stockIncr,
                                "IncrementExtraNonce scriptSig differs at height " << nHeight);
            // The coinbase length limit of main.cpp:1750 is 100 bytes; the stock form is far
            // below it and the empty append cannot move it.
            BOOST_CHECK(forkIncr.size() <= 100u);
        }
    }

    // An empty COINBASE_FLAGS also carries no tag, so a stock-configured node's coinbase is not
    // merely byte-identical but invisible to the tag reader (TAG-1).
    BOOST_CHECK(!FindTag((CScript() << 200 << OP_0) + COINBASE_FLAGS, 200).has_value());
}

// Rule: MINER-1
// Rule: MINER-2
// Rule: MINER-3
BOOST_AUTO_TEST_CASE(miner_tag_script)
{
    // The tag a template carries: a quote tag while the quote is younger than quoteMaxAge, else nothing
    // (the signal-only tag and the signal bit left with ACT-1, upgrade plan §6); no payout key means no
    // tag; and COINBASE_FLAGS is empty without the index (§8.4 item 2).
    BOOST_CHECK(g_yellowback == nullptr);
    BOOST_CHECK(COINBASE_FLAGS.empty());
    Live live(pathTemp / "yb-miner");
    live.Activate();
    MinerConfig cfg = live.index->GetMinerConfig();
    cfg.quoteMaxAge = 100;
    live.index->SetMinerConfig(cfg);
    live.index->SetQuote(2000000, 5, 1000);
    const int h = live.Tip() + 1;
    {
        CScript s = policy::BuildTagScript(*live.index, 1050);
        std::optional<CoinbaseTag> t = FindTag(CScript() << h << OP_0, h);
        BOOST_CHECK(!t.has_value());
        t = FindTag((CScript() << h << OP_0) + s, h);
        BOOST_REQUIRE(t.has_value());
        BOOST_CHECK(t->IsQuote());
        BOOST_CHECK_EQUAL(t->priceMicroUsd, 2000000u);
        BOOST_CHECK_EQUAL(t->sourceMask, 5);
        BOOST_CHECK(!t->Signal());
        BOOST_CHECK(t->payoutKey == KeyOf(0));
        MinerStatus st = live.index->GetMinerStatus(1050);
        BOOST_CHECK_EQUAL(st.kind, "quote");
        BOOST_CHECK_EQUAL(st.quoteAgeSeconds.value_or(-1), 50);
        BOOST_CHECK(st.registered);                                  // REG-1: KeyOf(0) quoted within N_REG
        BOOST_CHECK(st.eligible);
    }
    {
        // Stale quote: no tag at all.
        BOOST_CHECK(policy::BuildTagScript(*live.index, 1101).empty());
        BOOST_CHECK_EQUAL(live.index->GetMinerStatus(1101).kind, "none");
        // No payout key: no tag (MINER-2).
        cfg.payoutKey = std::nullopt;
        live.index->SetMinerConfig(cfg);
        BOOST_CHECK(policy::BuildTagScript(*live.index, 1050).empty());
        BOOST_CHECK_EQUAL(live.index->GetMinerStatus(1050).kind, "none");
    }
}

// Rule: SNAP
BOOST_FIXTURE_TEST_CASE(params_change_wipes_on_start, TestChain100Setup)
{
    // A node restarted with different hashed parameters (the four regtest values) rebuilds:
    // SyncToChain wipes when the stored Params record differs, so params_mismatch_fails_loudly sees
    // the new record in the hash and index_start_height_above_tip sees no rows below the new start.
    yellowback::Params original = RegtestParams(1, 0, 0, TestSet());
    uint256 h0;
    {
        YellowbackIndex index(original, pathTemp / "yb-params", 1 << 20, true);
        BOOST_REQUIRE(index.SyncToChain());
        BOOST_REQUIRE_EQUAL(TipHeightOf(index), 100);
        h0 = HashOf(index);
    }
    {
        YellowbackIndex reopened(RegtestParams(1, 1, 0, TestSet()), pathTemp / "yb-params", 1 << 20, false);
        BOOST_REQUIRE(reopened.SyncToChain());
        BOOST_CHECK_EQUAL(TipHeightOf(reopened), 100);
        LOCK(reopened.cs_yellowback);
        std::optional<ParamsRecord> rec = State(reopened.View()).GetParamsRecord();
        BOOST_REQUIRE(rec.has_value());
        BOOST_CHECK_EQUAL(rec->sigmaRefBps, 1);
        BOOST_CHECK(reopened.GetStateHash() != h0);
    }
    {
        YellowbackIndex back(RegtestParams(50, 0, 0, TestSet()), pathTemp / "yb-params", 1 << 20, false);
        BOOST_REQUIRE(back.SyncToChain());
        BOOST_CHECK_EQUAL(TipHeightOf(back), 100);
        LOCK(back.cs_yellowback);
        BOOST_CHECK(!State(back.View()).GetSnapshot(49).has_value());   // no rows below the new start
        BOOST_CHECK(State(back.View()).GetSnapshot(50).has_value());
    }
    {
        YellowbackIndex same(original, pathTemp / "yb-params", 1 << 20, false);
        BOOST_REQUIRE(same.SyncToChain());
        BOOST_CHECK(HashOf(same) == h0);
    }
}

// Rule: TPL-1
// Rule: TPL-3
BOOST_AUTO_TEST_CASE(tpl3_template_fault_keeps_block_invalid_spend)
{
    // TPL-1 skips a candidate that would fail BLK-1; -yellowbacktestfault=template keeps exactly
    // one such candidate instead, so the template disagrees with EvaluateBlock -- which is what
    // makes CreateNewBlock's own TestBlockValidity fail (TPL-3: a discrepancy is a bug and throws).
    // A live node cannot reach this state, because MP-1 keeps a block-invalid vault spend out of
    // the mempool, which is why the fault flag exists.
    Live live(pathTemp / "yb-tpl3");
    live.Activate();
    live.MintActive();
    const int h = live.Tip() + 1;
    CMutableTransaction s = live.b->SpendTx(live.vault, h - 2, false);
    const CTransaction tx(s);

    {   // TPL-1: skipped, and the overlay is not advanced
        LOCK(cs_main);   // TemplateView() asserts cs_main, as CreateNewBlock holds it
        yellowback::TemplateView view = live.index->TemplateView();
        BOOST_CHECK(!policy::FilterTemplate(view, tx, h));
    }
    BOOST_REQUIRE(!live.index->SetTestFault("template").has_value());
    {   // the fault keeps it
        LOCK(cs_main);   // TemplateView() asserts cs_main, as CreateNewBlock holds it
        yellowback::TemplateView view = live.index->TemplateView();
        BOOST_CHECK(policy::FilterTemplate(view, tx, h));
    }
    {   // one shot only: the next candidate is skipped again
        LOCK(cs_main);   // TemplateView() asserts cs_main, as CreateNewBlock holds it
        yellowback::TemplateView view = live.index->TemplateView();
        BOOST_CHECK(!policy::FilterTemplate(view, tx, h));
    }
    // and the block that template would have produced is exactly what the hook rejects
    Chain::Node& bad = live.chain.Add(Builder::Block(h, std::nullopt, { s }), live.tip);
    std::optional<std::string> verdict = Connect(*live.index, bad, true);
    BOOST_REQUIRE(verdict.has_value());
    BOOST_CHECK(verdict->find("vault-spend") != std::string::npos);
}

// ---------------------------------------------------------------------------
// v3 (plan Phase A2): the attestation pool, BuildBundle, the W8 cache, the schema rebuild, TPL-2

std::string AddReason(YellowbackIndex& index, const Attestation& a, bool* replaced = nullptr)
{
    std::string reason;
    return index.AddAttestation(a, reason, replaced) ? std::string("ok") : reason.substr(0, reason.find(':'));
}

// Rule: BUNDLE-1
BOOST_AUTO_TEST_CASE(pool_add_replace_freshness_three_per_seq)
{
    // W5 / S4: AddAttestation's five refusals in the contract's order, the newest-three-per-seq
    // bound, `replaced` for a dropped older attestation and for a same-height overwrite, a
    // byte-identical resubmission accepted without replacing, and Freshest over (R - 8, R].
    Live live(pathTemp / "yb-pool");
    live.jitter = true;
    live.Arm();
    YellowbackIndex& index = *live.index;
    Builder& b = *live.b;
    const int tip = live.Tip();
    const int lag = g_yellowbackMintLag, maxAge = live.P.attestMaxAge;

    Attestation unknown = b.Att(0, 50000, tip - 1);
    unknown.seq = 999;
    BOOST_CHECK_EQUAL(AddReason(index, unknown), "attest-unknown-seq");
    BOOST_CHECK_EQUAL(AddReason(index, b.Att(0, 50000, tip - lag - maxAge)), "attest-stale");      // the floor itself is stale
    BOOST_CHECK_EQUAL(AddReason(index, b.Att(0, 50000, tip - lag - maxAge + 1)), "ok");            // one above it is fresh
    Attestation future = b.Att(0, 50000, tip - 1);
    future.citedHeight = (uint32_t)(tip + 1);
    BOOST_CHECK_EQUAL(AddReason(index, future), "attest-stale");
    BOOST_CHECK_EQUAL(AddReason(index, b.Att(0, PRICE_MIN - 1, tip - 1)), "attest-range");
    BOOST_CHECK_EQUAL(AddReason(index, b.Att(0, PRICE_MAX + 1, tip - 1)), "attest-range");
    Attestation flipped = b.Att(0, 50000, tip - 1);
    flipped.sig[5] ^= 0x01;
    BOOST_CHECK_EQUAL(AddReason(index, flipped), "attest-bad-sig");
    std::vector<unsigned char> otherHash(32, 0xab);
    BOOST_CHECK_EQUAL(AddReason(index, b.Att(0, 50000, tip - 1, uint256(otherHash))), "attest-bad-sig");   // signed over another block hash (R9)
    // High-S: negate s (n - s) and expect "bad", never normalised (R17).
    {
        Attestation a = b.Att(0, 50000, tip - 1);
        static const unsigned char N[32] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
                                             0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41 };
        int borrow = 0;
        for (int i = 31; i >= 0; i--) {
            int d = (int)N[i] - (int)a.sig[32 + i] - borrow;
            borrow = d < 0 ? 1 : 0;
            if (d < 0) d += 256;
            a.sig[32 + i] = (unsigned char)d;
        }
        BOOST_CHECK_EQUAL(AddReason(index, a), "attest-bad-sig");
    }

    // Three per seq by citedHeight; the fourth drops the oldest and reports replaced.
    bool replaced = true;
    BOOST_CHECK_EQUAL(AddReason(index, b.Att(1, 50000, tip - 3), &replaced), "ok");
    BOOST_CHECK(!replaced);
    BOOST_CHECK_EQUAL(AddReason(index, b.Att(1, 50000, tip - 2), &replaced), "ok");
    BOOST_CHECK(!replaced);
    BOOST_CHECK_EQUAL(AddReason(index, b.Att(1, 50000, tip - 1), &replaced), "ok");
    BOOST_CHECK(!replaced);
    BOOST_CHECK_EQUAL(AddReason(index, b.Att(1, 50000, tip - 1), &replaced), "ok");    // byte-identical: nothing changes
    BOOST_CHECK(!replaced);
    BOOST_CHECK_EQUAL(AddReason(index, b.Att(1, 50001, tip - 1), &replaced), "ok");    // same height, another price: the newest wins
    BOOST_CHECK(replaced);
    BOOST_CHECK_EQUAL(AddReason(index, b.Att(1, 50000, tip), &replaced), "ok");        // a fourth height: the oldest goes
    BOOST_CHECK(replaced);
    std::vector<PooledAttestation> all = index.PoolAttestations();
    std::vector<int> seq1;
    for (const PooledAttestation& pa : all) if (pa.att.seq == 1) seq1.push_back((int)pa.att.citedHeight);
    BOOST_CHECK((seq1 == std::vector<int>{ tip - 2, tip - 1, tip }));
    BOOST_CHECK_EQUAL(index.PoolSize(), all.size());
    // poolFresh (yed_getinfo / yed_listattestors): a citation a bundle for R could carry, in (R - maxAge, R].
    BOOST_CHECK(index.PoolFreshAt(1, tip));
    BOOST_CHECK(index.PoolFreshAt(1, tip - 2));
    BOOST_CHECK(index.PoolFreshAt(1, tip - 3 + maxAge));                 // tip - 2 is the oldest still inside
    BOOST_CHECK(!index.PoolFreshAt(1, tip + maxAge));                    // (tip, tip + maxAge] holds none: all stale
    // The overstatement: every pooled citation is newer than R - maxAge, yet all lie above R, so a
    // bundle for R has nothing to cite (the old predicate had no upper bound and said fresh).
    BOOST_CHECK(!index.PoolFreshAt(1, tip - 3));
    BOOST_CHECK(!index.PoolFreshAt(5, tip));
    // Freshest: the newest with citedHeight in (R - maxAge, R].
    {
        AttestationPool pool;
        bool r;
        pool.Add(b.Att(2, 1, 10), 0, r);
        pool.Add(b.Att(2, 2, 12), 0, r);
        pool.Add(b.Att(2, 3, 20), 0, r);
        BOOST_CHECK_EQUAL(pool.Freshest(2, 19, 8, 1)->priceMicroUsd, 2u);       // 20 > R; 12 in (11, 19]; 10 not
        BOOST_CHECK_EQUAL(pool.Freshest(2, 20, 8, 1)->priceMicroUsd, 3u);
        BOOST_CHECK(!pool.Freshest(2, 28, 8, 1).has_value());                   // 20 <= 28 - 8
        BOOST_CHECK(!pool.Freshest(2, 20, 8, 21).has_value());                  // below startHeight
        BOOST_CHECK(!pool.Freshest(3, 20, 8, 1).has_value());
    }
    // S4: an EJECTED attestor is refused; a PENDING one (registered, not yet mature) is pooled.
    {
        const Attestation a1 = b.Att(2, 40000, tip - 1), a2 = b.Att(2, 41000, tip - 1);
        live.MineWith({ b.EquivocationTx(a1, a2) });
        BOOST_REQUIRE(b.Attestor(2)->Status() == AttestorStatus::EJECTED);
        BOOST_CHECK_EQUAL(AddReason(index, b.Att(2, 50000, live.Tip() - 1)), "attest-not-eligible");
        live.MineWith({ b.RegisterTx(3, live.Tip() + 1) });
        BOOST_REQUIRE(b.Attestor(3)->Status() == AttestorStatus::PENDING);
        BOOST_CHECK_EQUAL(AddReason(index, b.Att(3, 50000, live.Tip() - 1)), "ok");
    }
}

// Rule: BUNDLE-1
// Rule: MINT-9
BOOST_AUTO_TEST_CASE(buildbundle_missing_set)
{
    // W6 / W9: BuildBundle draws Selected(R, selector), takes the freshest pooled attestation per seq,
    // reports the selected seq without one in `missing` with the contract's message, orders the
    // bundle by seq, and a bundle it builds passes MINT-9 through the state machine.
    Live live(pathTemp / "yb-buildbundle");
    live.jitter = true;
    live.Arm();
    YellowbackIndex& index = *live.index;
    Builder& b = *live.b;
    const int R = live.Tip() - 1;
    const std::vector<uint16_t> selected = b.SelectedAt(R, valtype());
    BOOST_REQUIRE_EQUAL(selected.size(), 3u);                       // M_SELECT + K_SLACK over three seated
    std::string reason;
    BOOST_CHECK(!index.BuildBundle(R, valtype(), reason).has_value());
    BOOST_CHECK_EQUAL(reason, strprintf("bundle-insufficient: 0 of 3 selected attestors have a fresh attestation; missing seq %u,%u,%u", selected[0], selected[1], selected[2]));
    // One attestation: still insufficient (M_SELECT = 2); the message names the two missing in draw order.
    BOOST_CHECK_EQUAL(AddReason(index, b.Att(selected[1], 50000, R)), "ok");
    BuiltBundle one = index.BuildBundleInfo(R, valtype());
    BOOST_CHECK(!one.sufficient);
    BOOST_CHECK((one.missing == std::vector<uint16_t>{ selected[0], selected[2] }));
    BOOST_CHECK((one.seqs == std::vector<uint16_t>{ selected[1] }));
    BOOST_CHECK(!one.aMint.has_value());
    // A stale one for another seq does not count; a fresh one does; the bundle is ascending by seq.
    BOOST_CHECK_EQUAL(AddReason(index, b.Att(selected[0], 49000, R - live.P.attestMaxAge + 1)), "ok");   // fresh for the pool, stale for R? (R - 7 > R - 8: fresh)
    BuiltBundle two = index.BuildBundleInfo(R, valtype());
    BOOST_CHECK(two.sufficient);
    BOOST_CHECK_EQUAL(two.seqs.size(), 2u);
    BOOST_CHECK(two.seqs[0] < two.seqs[1]);
    BOOST_CHECK((two.missing == std::vector<uint16_t>{ selected[2] }));
    BOOST_CHECK(two.aMint.has_value() && two.aClaim.has_value());
    BOOST_CHECK(two.armed);
    // The freshest per seq wins: a newer attestation of selected[1] replaces the older one in the bundle.
    BOOST_CHECK_EQUAL(AddReason(index, b.Att(selected[1], 51000, R)), "ok");           // same height overwrite
    BuiltBundle newer = index.BuildBundleInfo(R, valtype());
    for (const Attestation& a : newer.bundle.atts) if (a.seq == selected[1]) BOOST_CHECK_EQUAL(a.priceMicroUsd, 51000u);
    // One citing R + 1 is outside (R - 8, R] for this R (but fresh for the pool at the tip).
    BOOST_CHECK_EQUAL(AddReason(index, b.Att(selected[2], 50000, R + 1)), "ok");
    BOOST_CHECK((index.BuildBundleInfo(R, valtype()).missing == std::vector<uint16_t>{ selected[2] }));
    BOOST_CHECK_EQUAL(index.BuildBundleInfo(R + 1, valtype()).selected.size(), 3u);
    // A bundle the node built rides a mint that MINT-9 accepts.
    std::optional<Bundle> built = index.BuildBundle(R, valtype(), reason);
    BOOST_REQUIRE(built.has_value());
    CMutableTransaction m = b.MintV3(10000, R, 49000, EncodeBundle(built.value()));   // aMint = 49000: pMint = min(xMint, aMint)
    live.MineWith({ m });
    std::optional<VaultRecord> v = b.Vault(CTransaction(m).GetHash());
    BOOST_REQUIRE(v.has_value());
    BOOST_CHECK_MESSAGE(v->Status() == VaultStatus::ACTIVE, v->voidReason);
    // A selector changes the draw (a different vault outpoint) but never the pool.
    BuiltBundle sel = index.BuildBundleInfo(R, OutPointSelector(COutPoint(CTransaction(m).GetHash(), 0)));
    BOOST_CHECK_EQUAL(sel.selected.size(), 3u);
    // Unarmed heights build too (yed_buildbundle never refuses for arming): R below the arming.
    const int early = live.P.startHeight + 130;
    BuiltBundle unarmed = index.BuildBundleInfo(early, valtype());
    BOOST_CHECK(!unarmed.armed);
    BOOST_CHECK(unarmed.selected.empty());
}

// Rule: BUNDLE-1
// Rule: MP-1
// Rule: RED-1
BOOST_AUTO_TEST_CASE(sigcache_lru_and_hit_equals_cold)
{
    // W8 / R3: the LRU holds 16,384 entries and evicts the oldest; a hit and a cold verification
    // agree (cache_hit_equals_cold) through the index's real cache; MP-1's claim-path RED-1 fills it.
    LruSigCache small(3);
    std::vector<unsigned char> k(32, 0);
    auto key = [&](int i) { k[0] = (unsigned char)i; return uint256(k); };
    small.Insert(key(1), true);
    small.Insert(key(2), false);
    small.Insert(key(3), true);
    BOOST_CHECK_EQUAL(small.Size(), 3u);
    BOOST_CHECK(small.Lookup(key(1)).value());                       // touches 1: 2 is now the oldest
    small.Insert(key(4), true);
    BOOST_CHECK(!small.Lookup(key(2)).has_value());
    BOOST_CHECK(small.Lookup(key(1)).has_value() && small.Lookup(key(3)).has_value() && small.Lookup(key(4)).has_value());
    BOOST_CHECK_EQUAL(small.Hits(), 4u);
    BOOST_CHECK_EQUAL(small.Misses(), 1u);
    LruSigCache full;
    BOOST_CHECK_EQUAL(full.Capacity(), (size_t)SIG_CACHE_ENTRIES);
    for (int i = 0; i < (int)SIG_CACHE_ENTRIES + 1; i++) {
        std::vector<unsigned char> kk(32, 0);
        kk[0] = i & 0xff; kk[1] = (i >> 8) & 0xff; kk[2] = (i >> 16) & 0xff;
        full.Insert(uint256(kk), true);
    }
    BOOST_CHECK_EQUAL(full.Size(), (size_t)SIG_CACHE_ENTRIES);
    BOOST_CHECK(!full.Lookup(uint256(std::vector<unsigned char>(32, 0))).has_value());   // the first one was evicted

    Live live(pathTemp / "yb-sigcache");
    live.jitter = true;
    live.Arm();
    YellowbackIndex& index = *live.index;
    Builder& b = *live.b;
    const int R = live.Tip() - 1;
    CMutableTransaction m = b.MintV3(10000, R, 50000);
    CBlock block = Builder::Block(live.Tip() + 1, Builder::Quote(50000, 0), { m });
    block.hashPrevBlock = live.tip->GetBlockHash();
    block.hashMerkleRoot = BlockMerkleRoot(block);
    // Cold: a fresh verification with no cache; warm: through the index's cache twice.
    BlockEvaluation cold, warm1, warm2;
    {
        LOCK(cs_main);
        LOCK(index.cs_yellowback);
        const uint64_t hitsBefore = index.SigCacheStats().Hits();
        const size_t sizeBefore = index.SigCacheStats().Size();
        { OverlayStateView o(index.MutableView()); cold = EvaluateBlock(o, live.P, block, live.Tip() + 1, block.GetHash(), 0, nullptr); }
        { OverlayStateView o(index.MutableView()); warm1 = EvaluateBlock(o, live.P, block, live.Tip() + 1, block.GetHash(), 0, index.GetSigCache()); }
        BOOST_CHECK_EQUAL(index.SigCacheStats().Size(), sizeBefore + 3);       // three signatures verified once
        { OverlayStateView o(index.MutableView()); warm2 = EvaluateBlock(o, live.P, block, live.Tip() + 1, block.GetHash(), 0, index.GetSigCache()); }
        BOOST_CHECK_EQUAL(index.SigCacheStats().Hits(), hitsBefore + 3);       // all three hit the second time
        BOOST_CHECK_EQUAL(index.SigCacheStats().Size(), sizeBefore + 3);
    }
    BOOST_REQUIRE_EQUAL(cold.txlogs.size(), 1u);
    BOOST_CHECK_EQUAL(cold.txlogs[0].second.verdict, warm1.txlogs[0].second.verdict);
    BOOST_CHECK_EQUAL(cold.txlogs[0].second.verdict, warm2.txlogs[0].second.verdict);
    BOOST_CHECK_EQUAL(cold.txlogs[0].second.verdict, "ok");
    BOOST_CHECK(cold.snapshot.blockHash == warm2.snapshot.blockHash);
    BOOST_CHECK_EQUAL(cold.txlogs[0].second.aMint, warm2.txlogs[0].second.aMint);
    // A wrong signature is cached as invalid and stays invalid on the hit.
    Bundle bad;
    for (uint16_t seq : b.SelectedAt(R, valtype())) {
        Attestation a = b.Att(seq, 50000, R);
        a.sig[10] ^= 1;
        bad.atts.push_back(a);
    }
    CMutableTransaction mBad = b.MintV3(10000, R, 50000, EncodeBundle(bad));
    CBlock blockBad = Builder::Block(live.Tip() + 1, Builder::Quote(50000, 0), { mBad });
    blockBad.hashPrevBlock = live.tip->GetBlockHash();
    blockBad.hashMerkleRoot = BlockMerkleRoot(blockBad);
    {
        LOCK(cs_main);
        LOCK(index.cs_yellowback);
        BlockEvaluation c, w;
        { OverlayStateView o(index.MutableView()); c = EvaluateBlock(o, live.P, blockBad, live.Tip() + 1, blockBad.GetHash(), 0, nullptr); }
        { OverlayStateView o(index.MutableView()); w = EvaluateBlock(o, live.P, blockBad, live.Tip() + 1, blockBad.GetHash(), 0, index.GetSigCache()); }
        { OverlayStateView o(index.MutableView()); w = EvaluateBlock(o, live.P, blockBad, live.Tip() + 1, blockBad.GetHash(), 0, index.GetSigCache()); }
        BOOST_CHECK_EQUAL(c.txlogs[0].second.verdict, "mint9-bundle-sig");
        BOOST_CHECK_EQUAL(w.txlogs[0].second.verdict, "mint9-bundle-sig");
    }
    // The block connects through the hooks (the cache is warm) with the same verdict.
    live.MineWith({ m });
    BOOST_CHECK(b.Vault(CTransaction(m).GetHash())->Status() == VaultStatus::ACTIVE);
    // MP-1: a claim's RED-1 bundle goes through the cache; a claim without a bundle is refused red1-bundle-shape.
    const uint256 vault = CTransaction(m).GetHash();
    const int ref = live.Tip() - 1;
    Bundle empty;
    CMutableTransaction noBundle = b.ClaimTx(vault, ref, EncodeBundle(empty), std::nullopt);
    noBundle.vin.pop_back();                                                       // drop the carrier
    BOOST_CHECK_EQUAL(index.MempoolCheckReason(CTransaction(noBundle)).value_or("admitted"), "red1-bundle-shape");
    const size_t before = index.SigCacheStats().Size();
    CMutableTransaction withBundle = b.ClaimTx(vault, ref, b.BundleFor(ref, OutPointSelector(COutPoint(vault, 0)), 50000), std::nullopt);
    // Not underwater: RED-4 refuses, but RED-1 verified the bundle first and filled the cache.
    BOOST_CHECK_EQUAL(index.MempoolCheckReason(CTransaction(withBundle)).value_or("admitted"), "vault-claim-not-underwater");
    BOOST_CHECK_EQUAL(index.SigCacheStats().Size(), before + 3);
}

// Rule: SNAP
BOOST_FIXTURE_TEST_CASE(schema3_rebuild_flag, TestChain100Setup)
{
    // A v2 index directory (Tip.schemaVersion 2) is wiped and rebuilt from the chain at start with
    // WasRebuilt() set (yed_getinfo.rebuilt); a current directory reopens without it; the same
    // -yellowbacktestfault=schema path the functional test uses reports it too.
    yellowback::Params params = RegtestParams(1, 0, 0, TestSet());
    uint256 h0;
    {
        YellowbackIndex index(params, pathTemp / "yb-schema", 1 << 20, true);
        BOOST_REQUIRE(index.SyncToChain());
        BOOST_CHECK(!index.WasRebuilt());
        h0 = HashOf(index);
        LOCK(index.cs_yellowback);
        TipRecord tip = index.GetTip().value();
        tip.schemaVersion = 2;
        index.MutableView().Write(keys::Tip(), SerializeRecord(tip));
        index.Flush(true);
    }
    {
        YellowbackIndex reopened(params, pathTemp / "yb-schema", 1 << 20, false);
        BOOST_REQUIRE(reopened.SyncToChain());
        BOOST_CHECK(reopened.WasRebuilt());
        BOOST_CHECK_EQUAL(TipHeightOf(reopened), 100);
        BOOST_CHECK(HashOf(reopened) == h0);
        LOCK(reopened.cs_yellowback);
        BOOST_CHECK_EQUAL(reopened.GetTip()->schemaVersion, SCHEMA_VERSION);
    }
    {
        YellowbackIndex same(params, pathTemp / "yb-schema", 1 << 20, false);
        BOOST_REQUIRE(same.SyncToChain());
        BOOST_CHECK(!same.WasRebuilt());
        BOOST_CHECK(HashOf(same) == h0);
    }
    {
        YellowbackIndex faulted(params, pathTemp / "yb-schema", 1 << 20, false);
        BOOST_CHECK(!faulted.SetTestFault("schema").has_value());
        BOOST_REQUIRE(faulted.SyncToChain());
        BOOST_CHECK(faulted.WasRebuilt());
        BOOST_CHECK(HashOf(faulted) == h0);
    }
}

// Rule: TPL-2
// Rule: MINT-9
// Rule: MINT-10
// Rule: RED-5
// Rule: NOT-1
// Rule: RED-4
BOOST_AUTO_TEST_CASE(tpl2_skips_mint9_red5_not1)
{
    // The template follows validity (upgrade plan §6; v3's TPL-2 strict): a MINT failing MINT-9 or MINT-10 and
    // a claim failing RED-5 are invalid and skipped; a CLAIM_NOTICE failing NOT-1 is a valid non-Yellowback
    // transaction and kept; their passing twins are kept. The claim is the
    // emergency path: a 500 %-covered vault, attestors at a fifth of the pools (pEmerg under
    // EMERGENCY_RATIO, pClaim = xClaim above CLAIM_THRESHOLD), a notice, EMERGENCY_PERSIST blocks,
    // then a claim owing RED-5's residual.
    Live live(pathTemp / "yb-tpl2");
    live.jitter = true;
    live.Arm();
    YellowbackIndex& index = *live.index;
    Builder& b = *live.b;
    const int R0 = live.Tip() - 1;
    CMutableTransaction noBundle = b.MintTx(10000, 48, R0);                          // v2 shape: no carrier
    CMutableTransaction diverged = b.MintV3(10000, R0, 100000);                      // attestors at 2x the pools
    CMutableTransaction good = b.MintV3(10000, R0, 50000);
    {
        LOCK(cs_main);   // TemplateView() asserts cs_main, as CreateNewBlock holds it
        yellowback::TemplateView view = index.TemplateView();
        BOOST_CHECK(!policy::FilterTemplate(view, CTransaction(noBundle), live.Tip() + 1));
    }
    {
        LOCK(cs_main);   // TemplateView() asserts cs_main, as CreateNewBlock holds it
        yellowback::TemplateView view = index.TemplateView();
        BOOST_CHECK(!policy::FilterTemplate(view, CTransaction(diverged), live.Tip() + 1));
    }
    {
        LOCK(cs_main);   // TemplateView() asserts cs_main, as CreateNewBlock holds it
        yellowback::TemplateView view = index.TemplateView();
        BOOST_CHECK(policy::FilterTemplate(view, CTransaction(good), live.Tip() + 1));
    }
    live.MineWith({ good });
    const uint256 vault = CTransaction(good).GetHash();
    BOOST_REQUIRE(b.Vault(vault)->Status() == VaultStatus::ACTIVE);
    // NOT-1 fails on a healthy vault (attestors at the pools' price): kept, it registers nothing; holds at a fifth: kept.
    const int R1 = live.Tip() - 1;
    const valtype selector = OutPointSelector(COutPoint(vault, 0));
    CMutableTransaction healthyNotice = b.NoticeTx(vault, R1, b.BundleFor(R1, selector, 50000));
    CMutableTransaction notice = b.NoticeTx(vault, R1, b.BundleFor(R1, selector, 10000));
    {
        LOCK(cs_main);   // TemplateView() asserts cs_main, as CreateNewBlock holds it
        yellowback::TemplateView view = index.TemplateView();
        BOOST_CHECK(policy::FilterTemplate(view, CTransaction(healthyNotice), live.Tip() + 1));
    }
    {
        LOCK(cs_main);   // TemplateView() asserts cs_main, as CreateNewBlock holds it
        yellowback::TemplateView view = index.TemplateView();
        BOOST_CHECK(policy::FilterTemplate(view, CTransaction(notice), live.Tip() + 1));
    }
    live.MineWith({ notice });
    {
        LOCK(index.cs_yellowback);
        std::optional<NoticeRecord> n = State(index.View()).GetNotice(COutPoint(vault, 0));
        BOOST_REQUIRE(n.has_value());
        BOOST_CHECK_EQUAL(n->refHeight, R1);
        BOOST_CHECK_EQUAL(n->pEmerg, 10000);
    }
    // A second notice while one stands is not registered (the reset attack); it is valid, so kept.
    {
        const int R2 = live.Tip() - 1;
        LOCK(cs_main);   // TemplateView() asserts cs_main, as CreateNewBlock holds it
        yellowback::TemplateView view = index.TemplateView();
        BOOST_CHECK(policy::FilterTemplate(view, CTransaction(b.NoticeTx(vault, R2, b.BundleFor(R2, selector, 10000))), live.Tip() + 1));
    }
    // EMERGENCY_PERSIST blocks later a claim opens by clause (b) and owes the residual.
    while (live.Tip() - 1 - R1 < live.P.emergencyPersist) live.MineQuote();
    const int R3 = live.Tip() - 1;
    const valtype claimBundle = b.BundleFor(R3, selector, 10000);
    const VaultRecord v = b.Vault(vault).value();
    const MicroUsd pClaim = std::max<MicroUsd>(b.Snap(R3).PClaim().value(), 10000);      // max(xClaim, aClaim) under clause (b): the margin is 10^4 (R1)
    const CAmount residual = ResidualZat(v.collateralZat, ClaimantMaxZat(v.mintedCents, (int)BPS, pClaim));
    BOOST_REQUIRE(residual >= live.P.residualMinZat);
    CMutableTransaction noResidual = b.ClaimTx(vault, R3, claimBundle, std::nullopt);
    CMutableTransaction shortResidual = b.ClaimTx(vault, R3, claimBundle, residual - 1);
    CMutableTransaction withResidual = b.ClaimTx(vault, R3, claimBundle, residual);
    BOOST_CHECK_EQUAL(index.MempoolCheckReason(CTransaction(noResidual)).value_or("admitted"), "red5-residual");
    BOOST_CHECK_EQUAL(index.MempoolCheckReason(CTransaction(shortResidual)).value_or("admitted"), "red5-residual");
    BOOST_CHECK_EQUAL(index.MempoolCheckReason(CTransaction(withResidual)).value_or("admitted"), "admitted");
    {
        LOCK(cs_main);   // TemplateView() asserts cs_main, as CreateNewBlock holds it
        yellowback::TemplateView view = index.TemplateView();
        BOOST_CHECK(!policy::FilterTemplate(view, CTransaction(noResidual), live.Tip() + 1));
    }
    {
        LOCK(cs_main);   // TemplateView() asserts cs_main, as CreateNewBlock holds it
        yellowback::TemplateView view = index.TemplateView();
        BOOST_CHECK(policy::FilterTemplate(view, CTransaction(withResidual), live.Tip() + 1));
    }
    // And the block carrying the residual-less claim is exactly what the hook rejects (BLK-1 via RED-5).
    Chain::Node& bad = live.chain.Add(Builder::Block(live.Tip() + 1, std::nullopt, { noResidual }), live.tip);
    std::optional<std::string> verdict = Connect(index, bad, true);
    BOOST_REQUIRE(verdict.has_value());
    BOOST_CHECK(verdict->find("red5-residual") != std::string::npos);
    live.MineWith({ withResidual });
    const VaultRecord after = b.Vault(vault).value();
    BOOST_CHECK(after.Status() == VaultStatus::CLAIMING);     // U-23: until its claimant intent is released
    {
        LOCK(index.cs_yellowback);
        State st(index.View());
        std::optional<TxLogRecord> log = st.GetTxLog(CTransaction(withResidual).GetHash());
        BOOST_REQUIRE(log.has_value());
        BOOST_CHECK_EQUAL(log->claimPath, "b");
        BOOST_CHECK_EQUAL(log->residualZat, residual);
        BOOST_CHECK(!st.GetNotice(COutPoint(vault, 0)).has_value());      // IN-2: the record went with the vault
    }
}

BOOST_AUTO_TEST_SUITE_END()
