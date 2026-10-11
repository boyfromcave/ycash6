// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_YELLOWBACK_INDEX_H
#define YCASH_YELLOWBACK_INDEX_H

#include "arith_uint256.h"
#include "fs.h"
#include "pubkey.h"
#include "sync.h"
#include "validationinterface.h"
#include "yellowback/db.h"
#include "yellowback/params.h"
#include "yellowback/state.h"
#include "yellowback/view.h"

#include <atomic>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

class CBlockHeader;
class CBlockIndex;
class CTxMemPool;
class UniValue;
namespace Consensus { struct Params; }

/**
 * The Yellowback index (plan V2, §4.2a, §4.3): the YED module's state kept
 * synchronous with chainActive by three hook calls in main.cpp —
 * CheckConnect in ConnectBlock's post-verification window, CommitConnect
 * after view.SetBestBlock, UndoDisconnect at the end of DisconnectBlock —
 * plus the mempool check in AcceptToMemoryPool and the mempool sweep in
 * ConnectTip. Every hook is called with cs_main held (asserted) and takes
 * cs_yellowback inside.
 *
 * Since the vault upgrade (docs/plans/yellowback-upgrade-plan.md §6, U-21,
 * U-22) the index runs on every node of a network where UPGRADE_VAULT has a
 * height and a YED attestor set is configured, from the activation height,
 * and CheckConnect's verdict is a consensus rejection (DoS 100) with no
 * node-local conjunct: the enforcement flag, the work valve, the rejected
 * set, the IBD and catch-up suppression, the sunset and abandonment are
 * gone. A storage failure is a node failure (the caller aborts), never an
 * acceptance (BLK-3's fail-open is retired with the enforcing minority it
 * protected).
 *
 * DigiByte keeps DigiDollar state in the chainstate itself and rejects in
 * consensus (ref/digibyte/src/validation.cpp); Ycash's chainstate flushes
 * lazily (main.cpp FLUSH_STATE_IF_NEEDED) while this index commits one batch
 * per block, so after a crash the index may be ahead of chainActive and
 * SyncToChain undo-walks back (UNDO_KEEP = 4096, V2; mapping.md §13).
 *
 * Lock order (a recorded decision, N25): cs_main -> cs_wallet -> mempool.cs
 * -> cs_yellowback. RemoveInvalidVaultSpends takes mempool.cs before
 * cs_yellowback; TemplateView holds cs_yellowback inside CreateNewBlock's
 * LOCK2(cs_main, mempool.cs); no RPC may take mempool.cs after cs_yellowback.
 *
 * Node-local bookkeeping that never feeds a rule (§3.10): the quote holder
 * (stamped by the RPC — no clock here, M11) and the payout key.
 */
namespace yellowback {

/** Undo records older than this many blocks below the tip are pruned (V2: 4,096, the crash walk). */
static const int UNDO_KEEP = 4096;

/** The miner-side configuration read only on the miner path (§3.10). The signal flag, the kill switch,
 *  the template policy and -yellowbackrequirehealthy left with the vault upgrade (§6). */
struct MinerConfig
{
    std::optional<CKeyID> payoutKey;   //!< -yellowbackpayoutaddress or a P2PKH -mineraddress (MINER-2); none => no tag
    int64_t quoteMaxAge;               //!< -yellowbackquotemaxage, seconds

    MinerConfig() : quoteMaxAge(1800) {}
};

/** The quote yed_setquote stores (MINER-1). receivedAt is stamped by the RPC. */
struct QuoteHolder
{
    uint64_t priceMicroUsd;   //!< 0 = none
    uint16_t sourceMask;
    int64_t receivedAt;

    QuoteHolder() : priceMicroUsd(0), sourceMask(0), receivedAt(0) {}
};

/** The coinbase scriptSig bytes after its two leading pushes: what COINBASE_FLAGS contributed (getblocktemplate.coinbaseaux.flags, audit A-7). */
CScript CoinbaseFlagsOf(const CScript& coinbaseScriptSig);

/** What the next template's tag would be (yed_getinfo.miner, yed_setquote.nextTag, TemplateInfo). */
struct MinerStatus
{
    std::string kind;                  //!< "quote" | "none" (the signal-only tag left with ACT-1, §6)
    std::optional<CKeyID> payoutKey;
    std::optional<int64_t> quoteAgeSeconds;
    bool registered;                   //!< REG-1 at the tip
    bool eligible;                     //!< in E(tip)

    MinerStatus() : kind("none"), registered(false), eligible(false) {}
};

/** -yellowbacktestfault (regtest only, §4.5): a storage fault at one hook once, a template disagreement once, or a schema mismatch at start. */
struct TestFault
{
    enum Hook { NONE, CHECK, COMMIT, UNDO };
    Hook storageHook;
    std::optional<int> height;        //!< fire at this height only (default: the next call)
    bool armed;                       //!< consumed on the first firing
    bool templateFault;               //!< FilterTemplate keeps one invalid transaction (TestBlockValidity then refuses the template)
    bool schemaMismatch;              //!< SyncToChain treats the stored tip as a foreign SCHEMA_VERSION once (the v3 rebuild path, yellowback_index.py)
    std::optional<int> crashHeight;   //!< CheckConnect flushes, then SIGKILLs the node, before judging this height (yellowback_index.py)

    TestFault() : storageHook(NONE), armed(false), templateFault(false), schemaMismatch(false) {}
};

// ---------------------------------------------------------------------------
// v3: the attestation pool and the verified-signature cache (v3 plan W5, W8, §3.9)

/** One pooled attestation and the index tip at which it arrived (yed_getattestations.receivedHeight). */
struct PooledAttestation
{
    Attestation att;
    int receivedHeight;

    PooledAttestation() : receivedHeight(0) {}
};

/**
 * The node's attestation pool (W5, R14): in memory, non-consensus, fed by yed_addattestation,
 * the newest POOL_PER_SEQ attestations per seq by citedHeight (ceil(ATTEST_MAX_AGE / k) + 1 = 3:
 * at most two signed prices fall in a bundle's window, so three keeps one spare). Empty after a
 * restart until the subscriber refills it. Never a state input: BuildBundle reads it, no rule does.
 */
class AttestationPool
{
public:
    static const size_t POOL_PER_SEQ = 3;

    /**
     * Pool one verified attestation. Returns false for a byte-identical resubmission (nothing
     * changes). `replaced` is set when an older attestation of the seq was dropped to make room
     * or when a different attestation for the same citedHeight was overwritten (the newest wins;
     * the pool is not the equivocation detector).
     */
    bool Add(const Attestation& att, int receivedHeight, bool& replaced);
    /** Every pooled attestation, ascending seq then citedHeight. */
    std::vector<PooledAttestation> All() const;
    /** The newest attestation of `seq` with citedHeight in (R - maxAge, R] and >= startHeight. */
    std::optional<Attestation> Freshest(uint16_t seq, int refHeight, int maxAge, int startHeight) const;
    size_t Size() const;
    void Clear() { bySeq.clear(); }

private:
    std::map<uint16_t, std::vector<PooledAttestation>> bySeq;   //!< each vector ascending by citedHeight
};

/** W8, R3: the cache holds this many verified signatures (16,384 x 33 bytes). */
static const size_t SIG_CACHE_ENTRIES = 16384;

/**
 * The LRU implementation of bundle.h's SigCache, keyed by SHA256(attestation74 || blockHash(citedHeight))
 * -> valid. Node-local, never state: a hit and a cold verification always agree because the key
 * covers every input of the verification. Filled by MP-1, FilterTemplate, ConnectBlock, the dry
 * runs and yed_addattestation, all under cs_yellowback.
 */
class LruSigCache : public SigCache
{
public:
    explicit LruSigCache(size_t capacityIn = SIG_CACHE_ENTRIES) : capacity(capacityIn), hits(0), misses(0) {}
    std::optional<bool> Lookup(const uint256& key) const override;
    void Insert(const uint256& key, bool valid) override;
    size_t Size() const { return entries.size(); }
    size_t Capacity() const { return capacity; }
    uint64_t Hits() const { return hits; }
    uint64_t Misses() const { return misses; }
    void Clear();

private:
    struct Entry
    {
        bool valid;
        std::list<uint256>::iterator pos;
    };
    size_t capacity;
    mutable std::list<uint256> order;              //!< most recently used at the front
    mutable std::map<uint256, Entry> entries;
    mutable uint64_t hits, misses;
};

/** What BuildBundle assembled for (R, selector) (W6, W9; yed_buildbundle's shape). */
struct BuiltBundle
{
    int refHeight;
    std::vector<unsigned char> selector;
    bool armed;                          //!< ArmedAt(R)
    std::vector<uint16_t> selected;      //!< selected(R, selector) in draw order
    std::vector<uint16_t> seqs;          //!< the seq that contributed, ascending (the bundle's order)
    std::vector<uint16_t> missing;       //!< selected seq with no usable attestation, draw order
    Bundle bundle;
    std::optional<MicroUsd> aMint, aClaim;
    size_t mSelect;
    bool sufficient;                     //!< seqs.size() >= mSelect

    BuiltBundle() : refHeight(0), armed(false), mSelect(0), sufficient(false) {}
    /** The contract's message: "bundle-insufficient: <count> of <selected> selected attestors have a fresh attestation; missing seq <a,b,...>". */
    std::string InsufficientMessage() const;
};

class YellowbackIndex;

/**
 * RAII holder of cs_yellowback owning an OverlayStateView over the index at
 * the tip (TPL-1; N25). CreateNewBlock keeps it for the selection loop inside
 * its LOCK2(cs_main, mempool.cs); MempoolCheck and the dry-run RPCs use one
 * per call. The caller holds cs_main for its lifetime.
 */
class TemplateView
{
public:
    explicit TemplateView(YellowbackIndex& index);
    TemplateView(TemplateView&&) = default;
    TemplateView& operator=(TemplateView&&) = default;
    ~TemplateView();

    OverlayStateView& Overlay() { return *overlay; }
    /** The height the template is built for (index tip + 1). */
    int NextHeight() const { return nextHeight; }
    const YellowbackIndex& Index() const { return *index; }
    YellowbackIndex& Index() { return *index; }

private:
    YellowbackIndex* index;
    std::unique_ptr<UniqueLock<CCriticalSection>> lock;   // 6.20.0: CCriticalBlock became UniqueLock
    std::unique_ptr<OverlayStateView> overlay;
    int nextHeight;
};

class YellowbackIndex final : public CValidationInterface
{
public:
    YellowbackIndex(const Params& params, const fs::path& dir, size_t cacheSize, bool fWipe);
    ~YellowbackIndex();

    /**
     * Bring the database in line with chainActive at startup: undo while the
     * stored tip is not in the active chain (covers the index being ahead of
     * an unflushed chainstate after a crash, V2), then apply forward from
     * disk. Wipes and rebuilds when the schema or network differs, an undo
     * record is missing, or the chain is below startHeight. Takes cs_main.
     * Returns false only when the index ends up unhealthy.
     */
    bool SyncToChain();

    /** Make every later hook return at once (shutdown). */
    void Stop();
    /** Commit anything pending and fsync. */
    void Flush(bool fSync);

    mutable CCriticalSection cs_yellowback;

    const Params& GetParams() const { return params; }
    /** The parameter set in force at `height` (§3.1 versioning; one set per release today). */
    const Params& ParamsAt(int height) const { return SelectParams(paramSets, height); }
    bool IsHealthy() const { return healthy; }
    std::string UnhealthyReason() const { return unhealthyReason; }
    bool IsStopped() const { return stopped; }

    /** The stored tip (cs_yellowback). */
    std::optional<TipRecord> GetTip() const;
    /** The stored tip height, -1 when empty (cs_yellowback). */
    int TipHeight() const;
    /**
     * Transitional (V2 made the index synchronous, so this is true whenever the
     * index is healthy and chainActive is at or below startHeight or equal to
     * the stored tip); kept so txbuilder.cpp compiles until Phase 6 drops it.
     */
    bool IsSynced() const;
    /** The state view (cs_yellowback). Nothing but the hooks writes to it; dry runs go through an OverlayStateView. */
    StateView& View() const { return *db; }
    StateView& MutableView() { return *db; }
    uint256 GetStateHash() const;

    /** Mark unhealthy (also used by unit tests to exercise the RPC refusal). */
    void SetUnhealthy(const std::string& reason);

    // ------------------------------------------------------------------ hooks (cs_main held)

    /** The outcome of CheckConnect: a consensus verdict, or a node failure the caller aborts on. */
    struct ConnectCheck
    {
        std::optional<std::string> invalid;   //!< "bad-yellowback-<verdict>" when the block is invalid (DoS 100)
        std::string reason;                   //!< "<verdict>:<txid>" (logs)
        std::optional<std::string> failure;   //!< the index cannot evaluate the block (storage, tip mismatch): AbortNode
    };

    /**
     * ConnectBlock's check (BLK-1, U-21). H = pindex->nHeight. H < startHeight => nothing.
     * chainActive.Contains(pindex) => nothing (a re-verification, K6). Consistency:
     * (indexTip == null && H == startHeight) || indexTip.blockHash == pindex->pprev->GetBlockHash(),
     * else a failure (and the index is marked unhealthy). Always evaluates (cache key
     * {block.GetHash(), indexTipHash, paramsHash}, N9); `invalid` iff blockInvalid -- in initial
     * sync, reindex and import alike. A storage exception is a failure. Never reads
     * pindex->phashBlock (K5: TestBlockValidity's indexDummy has none).
     */
    ConnectCheck CheckConnect(const CBlock& block, const CBlockIndex* pindex, bool fJustCheck);
    /** The commit after view.SetBestBlock (never under fJustCheck): same guards; reuses the cache else re-evaluates; one batch; false => a node failure (the caller aborts). */
    bool CommitConnect(const CBlock& block, const CBlockIndex* pindex);
    /** DisconnectBlock's undo (inside `if (updateIndices)`): guard indexTip.blockHash == pindex->GetBlockHash(); false => a node failure. */
    bool UndoDisconnect(const CBlockIndex* pindex);

    /** ConnectTip's sweep (N5): takes mempool.cs, then cs_yellowback; removes every transaction MempoolCheck now fails, with descendants. */
    void RemoveInvalidVaultSpends(CTxMemPool& pool);
    /**
     * The mempool's ordinary validity check (U-21): ProcessTx at the next height on a discarded
     * overlay of the tip state, for a transaction that has a Yellowback payload, spends a token,
     * vault or claim intent, or creates a YED-tagged template output; true unless it is invalid
     * under the module. A vault spend also needs the expiry bound (nExpiryHeight != 0 and <=
     * refHeight + REF_WINDOW, so it expires before RED-1's window closes). Every refusal is
     * state-dependent (the tip moves), so the caller answers DoS 0.
     */
    bool MempoolCheck(const CTransaction& tx);
    /** MempoolCheck's reason: nullopt = admitted; "mempool-expiry" or the verdict (K7; `mempool-check-failed:<verdict>`). */
    std::optional<std::string> MempoolCheckReason(const CTransaction& tx);

    /** RAII holder of cs_yellowback over an overlay at the tip (caller holds cs_main, and mempool.cs when in CreateNewBlock). */
    yellowback::TemplateView TemplateView();

    // ------------------------------------------------------------------ miner side

    void SetMinerConfig(const MinerConfig& cfg) { miner = cfg; }
    const MinerConfig& GetMinerConfig() const { return miner; }
    void SetPayeePolicy(const PayeePolicy& p) { payeePolicy = p; }
    const PayeePolicy& GetPayeePolicy() const { return payeePolicy; }
    /** yed_setquote: the RPC stamps receivedAt (the only clock, M11). */
    void SetQuote(uint64_t priceMicroUsd, uint16_t sourceMask, int64_t receivedAt);
    /** Bumped by every SetQuote (D-U6): getblocktemplate rebuilds its cached template when it moves. */
    uint64_t QuoteGeneration() const { return quoteGeneration.load(); }
    QuoteHolder GetQuote() const;
    /** What the next template's tag would be, given `now` (cs_yellowback). */
    MinerStatus GetMinerStatus(int64_t now) const;
    /**
     * The getblocktemplate "yellowback" object (§4.4; V26): the tag the template carries
     * (COINBASE_FLAGS as CreateNewBlock set it, decoded), the quote's age, the miner's
     * standing and the index's health. Caller holds cs_main; `now` is the RPC's clock (M11).
     */
    UniValue TemplateInfo(int64_t now) const;
    /** The same, decoded from the coinbase scriptSig of the template actually being served (getblocktemplate
     *  caches a template across calls, so COINBASE_FLAGS may already be newer than it; audit A-7). */
    UniValue TemplateInfo(int64_t now, const CScript& coinbaseScriptSig) const;

    /** Parse -yellowbacktestfault (regtest only); an error string on a bad spec. */
    std::optional<std::string> SetTestFault(const std::string& spec);
    const TestFault& GetTestFault() const { return testFault; }
    /** TPL-3's unit companion: true once after -yellowbacktestfault=template. */
    bool ConsumeTemplateFault();

    // ------------------------------------------------------------------ v3: pool, cache, bundles (W5, W6, W8)

    /**
     * yed_addattestation (S4): verify one attestation against the tip and pool it. In order:
     * attest-unknown-seq (no Attestors record), attest-not-eligible (EJECTED or WITHDRAWN),
     * attest-stale (citedHeight <= tip - REF_LAG - ATTEST_MAX_AGE, above the tip, or below
     * startHeight), attest-range, attest-bad-sig (compact low-S under attestorPubKey(seq) with this
     * chain's blockHash(citedHeight); through the cache, which it fills). `reason` starts with the
     * identifier. `replaced` as AttestationPool::Add. Takes cs_yellowback.
     */
    bool AddAttestation(const Attestation& att, std::string& reason, bool* replaced = nullptr);
    std::vector<PooledAttestation> PoolAttestations() const;
    size_t PoolSize() const;
    /**
     * The contract's poolFresh: the pool holds an attestation of `seq` a bundle for R could cite,
     * citedHeight in (R - ATTEST_MAX_AGE, R] and >= startHeight (Freshest's window, the parameter
     * set at R). A citation above R does not count: it is not usable until R reaches it.
     */
    bool PoolFreshAt(uint16_t seq, int refHeight) const;
    /**
     * The bundle this node would build for (R, selector) (W6, W9): Selected(R, selector), the
     * freshest pooled attestation per selected seq with citedHeight in (R - ATTEST_MAX_AGE, R]
     * whose signature still verifies against the chain's blockHash(citedHeight) (a reorg can
     * invalidate a pooled one), ascending seq in the bundle, the statistic with weights at R.
     * Never refuses: `sufficient` says whether seqs.size() >= M_SELECT. Needs cs_yellowback only.
     */
    BuiltBundle BuildBundleInfo(int refHeight, const std::vector<unsigned char>& selector);
    /** BuildBundleInfo, or nullopt with the contract's bundle-insufficient message in `reason`. */
    std::optional<Bundle> BuildBundle(int refHeight, const std::vector<unsigned char>& selector, std::string& reason);
    /** The W8 cache every evaluation this index runs goes through (also handed to the RPC dry runs). */
    SigCache* GetSigCache() { return &sigCache; }
    const LruSigCache& SigCacheStats() const { return sigCache; }
    /** True for the rest of the session when SyncToChain found a foreign SCHEMA_VERSION and rebuilt (yed_getinfo.rebuilt). */
    bool WasRebuilt() const { return rebuilt; }
    void SetAttestPolicy(const AttestPolicy& p) { attestPolicy = p; }
    const AttestPolicy& GetAttestPolicy() const { return attestPolicy; }

    /**
     * Wallet hooks (plan §4.6, stages ii and iii of coin locking), set by the
     * wallet layer when there is one. Called on the notifier thread without
     * cs_yellowback held; they must not take cs_main.
     */
    std::function<void(const CTransaction&)> onSyncTransaction;
    std::function<void()> onReconcile;
    /** Test only: called at the start of every evaluation (fault injection for the exception boundary, N25). */
    std::function<void()> testBeforeApply;

protected:
    void ChainTip(const CBlockIndex* pindex, const CBlock* pblock, std::optional<MerkleFrontiers> added) override;
    void SyncTransaction(const CTransaction& tx, const CBlock* pblock, const int nHeight) override;

private:
    struct Evaluation
    {
        uint256 blockHash;
        uint256 tipHash;
        uint256 paramsHash;
        BlockEvaluation ev;
        std::map<std::string, std::optional<std::string>> writes;
        bool valid;
        Evaluation() : valid(false) {}
    };

    bool ApplyOne(const CBlock& block, int height, const uint256& hash, std::string& error);
    bool UndoOne(const uint256& hash, std::string& error);
    void Wipe(const std::string& why);
    uint256 ParamsHash(const Params& p) const;
    /** Evaluate (or reuse the cache) for a block on top of the stored tip; fills `cache`. */
    const Evaluation& Evaluate(const CBlock& block, int height, const uint256& tipHash);
    /** The consistency guard shared by CheckConnect and CommitConnect; false => already marked unhealthy. */
    bool TipMatches(const CBlockIndex* pindex, std::optional<TipRecord>& tip, const char* hook);
    void MaybeFault(TestFault::Hook hook, int height);
    std::optional<std::string> MempoolCheckLocked(const CTransaction& tx);
    std::optional<std::string> MempoolCheckInner(const CTransaction& tx);
    bool AddAttestationLocked(const Attestation& att, std::string& reason, bool* replacedOut);
    BuiltBundle BuildBundleInfoLocked(int refHeight, const std::vector<unsigned char>& selector);
    /** Snapshots[h].blockHash, nullopt below startHeight or when the row is missing (cs_yellowback). */
    std::optional<uint256> BlockHashAtLocked(int64_t height) const;
    /** One signature through the cache (cs_yellowback). */
    bool AttestationValidLocked(const Attestation& att, const CPubKey& pk, const uint256& blockHash);

    Params params;
    std::vector<Params> paramSets;
    std::unique_ptr<YellowbackDB> db;
    bool healthy;
    std::string unhealthyReason;
    bool stopped;
    bool rebuilt;

    MinerConfig miner;
    PayeePolicy payeePolicy;
    AttestPolicy attestPolicy;
    QuoteHolder quote;
    std::atomic<uint64_t> quoteGeneration{0};   //!< D-U6: bumped by SetQuote
    TestFault testFault;
    AttestationPool pool;
    LruSigCache sigCache;

    Evaluation cache;
};

/** The node's index, or nullptr where YED is not configured (no UPGRADE_VAULT height or no attestor set, U-22). */
extern YellowbackIndex* g_yellowback;
/** True iff YED is live with this node's network and options (U-22); set in init step 3, before the RPC table and the index. */
extern bool g_yellowbackLive;
/** -yellowbackfee (>= DEFAULT_YELLOWBACK_FEE) and -yellowbackmintlag (REF_LAG). */
extern CAmount g_yellowbackFee;
extern int g_yellowbackMintLag;

/**
 * Build the parameters for the running network (U-22): startHeight is the UPGRADE_VAULT activation
 * height of `consensus` (0 when it has none), attestorSetId the network's (regtest:
 * -yellowbackattestorset=<setid>, mainnet and testnet unset), and on regtest the overrides
 * -yellowbacksigmaref, -yellowbacksupplycapbps, -yellowbackattestarmmin, -yellowbackbundlecarrier,
 * -yellowbackmintrequiresarmed. The result is configured (Params::IsConfigured) iff YED is live on
 * this network. Returns an error string on a misconfiguration (a malformed value, a regtest flag on
 * another network, or a retired flag: -yellowbackstartheight, -yellowbackenforceuntil).
 */
std::optional<std::string> ParamsFromArgs(const std::string& networkId, const Consensus::Params& consensus, Params& out);

/** Quantum spec A-5: the module's mirror of the consensus Falcon activation, Params::pqFalconHeight, such that
 *  Params::IsPQFalconActive(h) == ::IsPQFalconActive(consensus, h) at every h: max(UPGRADE_VAULT height,
 *  pqFalconHeight), -1 (never) when either has no activation height. */
int PQFalconHeightOf(const Consensus::Params& consensus);

} // namespace yellowback

#endif // YCASH_YELLOWBACK_INDEX_H
