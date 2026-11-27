// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Yugen pool state in ycashd (doc/yugen-node.md): the note tree
// (commitments in block order, cm* first), the nullifier set, the pool balance B (§13.3.2
// turnstile) and, per block from activation, the root after it and its undo record. Held in
// memory, saved to <datadir>/yugen/state.dat at each chainstate flush (review M-3) and loaded at
// startup; a block is disconnected from its undo record. Only when the saved state is missing or
// off the active chain is it replayed from blocks (proofs are not re-verified on a replay). Proof verification runs in the helper process
// yugen-leafverify (decision N-D1, doc/yugen-node.md).

#ifndef YCASH_YUGEN_STATE_H
#define YCASH_YUGEN_STATE_H

#include "amount.h"
#include "primitives/block.h"
#include "script/script.h"
#include "uint256.h"

#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

class CBlockIndex;
class CChainParams;
class CCoinsViewCache;
class CTxMemPool;
class CTxUndo;
class CValidationState;
namespace Consensus { struct Params; }

namespace yugen {

typedef std::array<uint8_t, 48> Root;

struct BlockRecord {
    uint64_t treeSizeBefore{0};     // leaves before the block, cm* included
    Root rootAfter{};
    std::vector<std::pair<uint256, std::vector<unsigned char>>> transfers;   // (txid, transfer bytes)
    // Undo data (§13.3.2): the block, the nullifiers it added (never re-derived from the
    // transactions, T-2), the commitments it appended (count) and B before and after it.
    uint256 hash;
    std::vector<std::array<uint8_t, 32>> nfsAdded;
    uint64_t cmsAdded{0};
    CAmount balanceBefore{0};
    CAmount balanceAfter{0};
};

struct PoolState {
    uint256 tip;                                 // hash of the last block applied (null: none)
    int tipHeight{-1};
    std::vector<std::array<uint8_t, 48>> cms;    // applied commitments after cm*
    std::set<std::array<uint8_t, 32>> nullifiers;
    std::map<std::array<uint8_t, 32>, int> nfHeight;
    std::map<int, BlockRecord> blocks;           // from the activation height
    CAmount balance{0};                          // B, the turnstile (§13.3.2); zat
};

// What a Yugen transaction takes from the pool (its transfers' vb + fee, summed; §13.3.2 rule
// one): B changes by minus this when the transaction is applied. 0 for any other transaction.
CAmount PoolDebit(const CTransaction& tx);

// Undo the active chain's tip block (pindex) from the state, if the state is at it. Caller holds cs_main.
// Until EndDisconnect (after chainActive has moved back), Yugen's mempool checks take pindex->pprev
// as the tip, so the block's transactions are resurrected against the state without it.
void DisconnectBlock(const CBlockIndex* pindex);
void EndDisconnect();

// Save the state to <datadir>/yugen/state.dat (atomically). False on an I/O error.
bool Flush();

// The state as of chainActive's tip (rebuilt if needed). Caller holds cs_main.
const PoolState& Current(const CChainParams& params);

// Spec 0.5.4 §15.5, §15.6 B6: the transparent side of a bundle's VB records, decided where the bundle
// stands in its block (S1, S2) by ConnectBundleCoins, or for the pool and templates against the tip's
// coins (MempoolBundleCoins), and read back from a block's undo data on a replay.
struct BundleCoins {
    std::vector<bool> applied;                  // per transfer: not skipped (S1, S2, S3)
    std::vector<std::vector<CTxOut>> spent;     // per transfer: the coins its inputs spent (applied deposits)
    unsigned int flags{0};                      // the script verification flags in force
};
typedef std::map<uint256, BundleCoins> BundleCoinsMap;
// A block's coins pass (main.cpp ConnectBlock): the nullifiers of the Yugen transactions before the
// current one (S1) and each bundle's decision.
struct BlockCoins {
    std::set<std::array<uint8_t, 32>> nfs;
    BundleCoinsMap bundles;
    CAmount debited{0};                         // what the earlier Yugen transfers took from B (S3)
};
// For each Yugen transaction of a block at pindex in block order, after UpdateCoins: a bundle's B6
// failure above K, its S1, S2 and S3 decisions, rule B6's coin and balance checks of each applied deposit, its inputs spent and
// its applied records' outputs created at its txid (indices across all records, §15.5), and `undo`
// (the bundle's CTxUndo) given the applied mask (its first entry, UndoMask) and the spent coins.
// `transparentDelta` changes by the outputs created less the coins spent. The deposit scripts are
// verified by ConnectBlock (they sign the transfer hash, which the helper computes).
// `recorded`: the applied mask this bundle's undo entry holds, when the block is re-verified on the
// active chain (VerifyDB, verifychain): the module's state after the parent is gone then, so a deposit
// the rest of S2 would apply takes its module decision from the mask (N-D12; nothing else does).
// A false return with state.IsError() is a node-local failure (the module's answer is unknown), never
// a verdict on the block.
bool ConnectBundleCoins(const CTransaction& tx, CCoinsViewCache& view, CTxUndo& undo, const CBlockIndex* pindex,
                        const CChainParams& params, unsigned int flags, BlockCoins& bc, CAmount& transparentDelta,
                        CValidationState& state, const std::vector<bool>* recorded = nullptr);
// N-D12: the YED module's answer for a bundle's deposit coins in its state after `pprev`: KNOWN fills
// `tracked` (a token, a vault, an intent, a bond: true); UNKNOWN when the module cannot say (its index is
// stopped, unhealthy, not built yet or not at `pprev`). One call per bundle: one lock, one tip read.
enum class ModuleAnswer { KNOWN, UNKNOWN };
// Set by init.cpp wherever the YED module is live (an attestor set: on a public network a chain
// parameter, so every node of the network or none); unset, the module is inert and tracks nothing.
// ConnectBundleCoins skips a deposit of a tracked coin (S2).
extern ModuleAnswer (*g_moduleTracks)(const std::vector<COutPoint>& outs, const CBlockIndex* pprev, std::vector<bool>& tracked);
// The applied mask a bundle's undo entry records (empty if it records none), and the outputs and
// the outpoints of its applied records (for DisconnectBlock).
std::vector<bool> UndoMask(const CTxUndo& undo);
std::vector<CTxOut> RecordOutputs(const CTransaction& tx, const std::vector<bool>& applied);
std::vector<COutPoint> RecordPrevouts(const CTransaction& tx, const std::vector<bool>& applied);
// §15.5: the digest input k of a deposit signs (dep_sighash), and its coin rule.
uint256 DepositSighash(uint32_t branchId, uint8_t network, const std::array<uint8_t, 48>& transferHash,
                       const std::vector<COutPoint>& prevouts, uint32_t k, uint64_t amount,
                       const std::vector<unsigned char>& scriptCode);

struct BlockResult {
    CAmount skippedFees{0};                              // fees of bundled transfers skipped (§15.6 S1)
    std::vector<std::pair<CAmount, CScript>> run;        // the record run (§13.3.12), coinbase tail
};

// §7.9 rules 2, 3, 5, 6 for every Yugen transaction of a block at pindex (state at pindex->pprev);
// applies the block to the state unless fJustCheck.
// `coins`: the block's coins pass (ConnectBundleCoins); its decisions are the bundles' applied masks.
bool ConnectBlock(const CBlock& block, const CBlockIndex* pindex, const CChainParams& params,
                  bool fJustCheck, CValidationState& state, BlockResult& res, const BundleCoinsMap& coins);

// Round 3: a block whose connect failed in the verifier (not a verdict) HELPER_RETRIES_MAX times is
// no longer requested from peers until a restart (main.cpp FindNextBlocksToDownload); the same body
// failing a second time scores its sender HELPER_SAME_BODY_DOS (once per body).
static const int HELPER_RETRIES_MAX = 5, HELPER_SAME_BODY_DOS = 10;
bool HelperGaveUp(const uint256& block);

// Review M-1: the cheap part (decode, anchors, nullifiers), before inputs and scripts.
bool PreCheckMempoolTx(const CTransaction& tx, const CTxMemPool& pool, const CChainParams& params,
                       CValidationState& state);

// The same rules for a mempool candidate at the next height, plus nullifier conflicts in the pool.
bool CheckMempoolTx(const CTransaction& tx, const CTxMemPool& pool, const CChainParams& params,
                    CValidationState& state);

std::string HexRoot(const Root& r);

// Defaults of the Yugen verification limits (review M-2, M-4).
static const int64_t DEFAULT_MEMPOOL_VERIFY_TIMEOUT = 120;   // s, -yugenmempoolverifytimeout
static const int64_t DEFAULT_PEER_VERIFY_RATE = 6;           // per minute, -yugenpeerverifyrate (0: none)
static const size_t PROOF_CACHE_MAX = 16, BUNDLE_OK_MAX = 4096, REFUSED_CACHE_MAX = 20000;
// The helper's exit code for a verdict (contrib/yugen-leafverify): every other non-zero exit is a failure.
static const int HELPER_EXIT_REJECT = 10;

// Review M-2: a token bucket of `perMinute` tokens, refilled continuously (0: unlimited). Round 3,
// shared fairly: a peer that took its share (perMinute / the peers that asked within the last minute)
// within its last minute takes a token only while one is left for each other peer that waited within
// the last minute.
struct VerifyBudget {
    struct Peer { int64_t windowStart{0}; int used{0}; int64_t lastAsk{0}; int64_t lastWait{0}; };
    double tokens{0};
    int64_t last{0};
    std::map<int64_t, Peer> peers;
    bool Take(int64_t nowMicros, int64_t perMinute, int64_t peer);
};
// Round 3: while alive, Yugen transactions checked for the mempool came from peer `peer` (-1: none)
// and spend the budget in CheckMempoolTx, after the cheap checks, just before the helper.
struct PeerVerifyScope {
    explicit PeerVerifyScope(int64_t peer);
    ~PeerVerifyScope();
    // Whether a candidate in this scope took a token, so reached the helper's judgement. Only such a
    // refusal starts the peer's back-off: one refused by the cheap checks (a nullifier spent at the
    // tip, an anchor) cost no verification, and an honest peer sends one whenever it answers a stale
    // request (a leaf confirmed inside a bundle keeps no coin, so AlreadyHave misses it). A helper
    // failure or timeout after the token counts as a refusal (the peer's proof bytes can cause it); a
    // node-local fault that kept the helper from running on the bytes (a pipe, fork or exec failure, a
    // temp-file write failure: HELPER_NOT_RUN), or one before the helper (the YED module cannot answer,
    // the pool state), does not.
    bool Judged() const;
};
// The reject reason prefix of a helper failure or timeout (a state error, never a verdict on a block).
static const char* const VERIFIER_FAILED = "yugen-verifier-failed";
// Within a VERIFIER_FAILED reason: the helper never ran on the bytes (a node-local fault).
static const char* const HELPER_NOT_RUN = "helper not run: ";
// The longest reason the refusal cache keeps (a helper's answer line is the helper's to choose).
static const size_t REFUSED_REASON_MAX = 200;
// The reject reason of a mempool candidate that found no token: not a refusal (main.cpp asks again).
static const char* const VERIFY_DEFERRED = "yugen-verify-deferred";
// Round 3: the back-off after a peer's refused Yugen transaction: 10 s, doubled per refusal in a row
// up to 10 min; a peer quiet for 20 min starts again at 10 s. Updates the counters; returns the end.
int64_t RefusalBackoff(int& refusals, int64_t& lastRefusal, int64_t nowMicros);
// A mempool candidate refused at this tip with exactly these bytes, proofs included (cheap).
bool KnownRefused(const CTransaction& tx);
// The active tip moved (main.cpp UpdateTip, after ConnectTip or DisconnectTip): the refusal cache is
// emptied. Not on a connect that main.cpp's later checks still reject, nor fJustCheck. Under cs_main.
void TipChanged();

// The bundle proof store: sidecar data kept beside the block files (<datadir>/yugen/proofs).
void PutProofs(const uint256& txid, const std::vector<std::vector<unsigned char>>& proofs);
std::optional<std::vector<std::vector<unsigned char>>> GetProofs(const uint256& txid);
void SaveSidecar(const CBlock& block, int height, const Consensus::Params& consensus);   // at receipt, from UPGRADE_YUGEN
void AttachSidecar(CBlock& block);
void DropSidecar(const uint256& block);   // a body reset (review C-2)
uint64_t TxProofBytes(const CTransaction& tx);
// RPC (yugen_getblockdata): a bundle's root statement bstmt (hex32) in a block at h with the given
// applied mask, through the helper (proofs not checked); nullopt if the helper cannot say.
std::optional<std::string> BundleStatement(const CTransaction& tx, int h, const std::vector<bool>& applied,
                                           const CChainParams& params);

// Review H-2: a pooled Yugen tx that the next block (nextHeight) cannot hold: an anchor out of the
// window, an anchor at or above a disconnected height (disconnectedHeight >= 0), or a spent nullifier.
bool StaleInPool(const CTransaction& tx, int nextHeight, int disconnectedHeight, const CChainParams& params);

// The record run a template at height h owes for its Yugen transactions (all applied).
std::vector<std::pair<CAmount, CScript>> TemplateRecordRun(const std::vector<CTransaction>& vtx, int h,
                                                           const CChainParams& params);

// Whether the -yugenverifier helper runs (checked at startup when Yugen has a height).
bool HelperAvailable();

} // namespace yugen

#endif
