// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "yellowback/index.h"

#include "alert.h"
#include "chain.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "dbwrapper.h"
#include "hash.h"
#include "key_io.h"
#include "main.h"
#include "pow.h"
#include "txmempool.h"
#include "util/system.h"
#include "util/strencodings.h"
#include "warnings.h"
#include "yellowback/payload.h"
#include "yellowback/script.h"
#include "yellowback/state.h"
#include "yellowback/tag.h"

#include <univalue.h>

#include <boost/algorithm/string.hpp>

namespace yellowback {

YellowbackIndex* g_yellowback = nullptr;
CAmount g_yellowbackFee = DEFAULT_YELLOWBACK_FEE;
int g_yellowbackMintLag = DEFAULT_REF_LAG;

// ---------------------------------------------------------------------------
// TemplateView

TemplateView::TemplateView(YellowbackIndex& indexIn)
    : index(&indexIn),
      lock(new UniqueLock<CCriticalSection>(indexIn.cs_yellowback, "cs_yellowback", __FILE__, __LINE__)),
      overlay(new OverlayStateView(indexIn.MutableView())),
      nextHeight(indexIn.TipHeight() + 1)
{
}

TemplateView::~TemplateView() {}

// ---------------------------------------------------------------------------
// Construction, health, storage

YellowbackIndex::YellowbackIndex(const Params& paramsIn, const fs::path& dir, size_t cacheSize, bool fWipe)
    : params(paramsIn), db(new YellowbackDB(dir, cacheSize, false, fWipe)), healthy(true), stopped(false), rebuilt(false),
      payeePolicy(PayeePolicy::Defaults(paramsIn)), valveTripped(false), suppressedBlocks(0), sunsetLogged(false)
{
    paramSets.push_back(paramsIn);
    if (fWipe) LogPrintf("yellowback: index wiped (-reindex-yellowback; Rejected cleared)\n");
    LoadRejected();
}

YellowbackIndex::~YellowbackIndex() {}

void YellowbackIndex::SetUnhealthy(const std::string& reason)
{
    if (healthy) LogPrintf("yellowback: index unhealthy: %s; enforcement off; restart with -reindex-yellowback\n", reason);
    healthy = false;
    unhealthyReason = reason;
    cache.valid = false;
}

void YellowbackIndex::Stop()
{
    LOCK(cs_yellowback);
    stopped = true;
}

void YellowbackIndex::Flush(bool fSync)
{
    LOCK(cs_yellowback);
    db->Commit(fSync);
}

std::optional<TipRecord> YellowbackIndex::GetTip() const
{
    AssertLockHeld(cs_yellowback);
    return State(*db).GetTip();
}

int YellowbackIndex::TipHeight() const
{
    std::optional<TipRecord> tip = GetTip();
    return tip.has_value() ? tip->height : -1;
}

bool YellowbackIndex::IsSynced() const
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_yellowback);
    if (!healthy) return false;
    const CBlockIndex* chainTip = chainActive.Tip();
    std::optional<TipRecord> tip = GetTip();
    if (!chainTip || chainTip->nHeight < params.startHeight) return !tip.has_value();
    return tip.has_value() && tip->blockHash == chainTip->GetBlockHash();
}

uint256 YellowbackIndex::GetStateHash() const
{
    AssertLockHeld(cs_yellowback);
    return StateHash(*db, params.network);
}

void YellowbackIndex::Wipe(const std::string& why)
{
    LogPrintf("yellowback: wiping index (%s)\n", why);
    db->Wipe();
    rejected.clear();
    cache.valid = false;
}

void YellowbackIndex::LoadRejected()
{
    rejected.clear();
    db->Iterate(std::string(1, keys::PREFIX_REJECTED), [&](const std::string& k, const std::string&) {
        if (k.size() == 1 + 32) rejected.insert(uint256(std::vector<unsigned char>(k.begin() + 1, k.end())));
        return true;
    });
    if (!rejected.empty()) LogPrintf("yellowback: %u rejected block(s) on record\n", (unsigned)rejected.size());
}

uint256 YellowbackIndex::ParamsHash(const Params& p) const
{
    const std::string raw = SerializeRecord(ParamsRecord(p));
    return Hash(raw.begin(), raw.end());
}

void YellowbackIndex::MaybeFault(TestFault::Hook hook, int height)
{
    if (!testFault.armed || testFault.storageHook != hook) return;
    if (testFault.height.has_value() && testFault.height.value() != height) return;
    testFault.armed = false;
    LogPrintf("yellowback: -yellowbacktestfault: injecting a storage fault at hook %d height %d\n", (int)hook, height);
    throw dbwrapper_error("injected storage fault (-yellowbacktestfault)");
}

std::optional<std::string> YellowbackIndex::SetTestFault(const std::string& spec)
{
    TestFault f;
    if (spec == "template") {
        f.templateFault = true;
    } else if (spec == "novalve") {
        f.noValve = true;
    } else if (spec == "schema") {
        f.schemaMismatch = true;
    } else if (boost::algorithm::starts_with(spec, "storage:")) {
        std::vector<std::string> parts;
        boost::split(parts, spec, boost::is_any_of(":"));
        if (parts.size() < 2 || parts.size() > 3) return std::string("-yellowbacktestfault: expected storage:<check|commit|undo>[:<height>]");
        if (parts[1] == "check") f.storageHook = TestFault::CHECK;
        else if (parts[1] == "commit") f.storageHook = TestFault::COMMIT;
        else if (parts[1] == "undo") f.storageHook = TestFault::UNDO;
        else return std::string("-yellowbacktestfault: unknown hook '" + parts[1] + "'");
        if (parts.size() == 3) {
            int64_t h = atoi64(parts[2]);
            if (h <= 0 || h > 0x7FFFFFFF) return std::string("-yellowbacktestfault: bad height");
            f.height = (int)h;
        }
        f.armed = true;
    } else {
        return std::string("-yellowbacktestfault: expected storage:<check|commit|undo>[:<height>], template, novalve or schema");
    }
    testFault = f;
    LogPrintf("yellowback: -yellowbacktestfault=%s armed\n", spec);
    return std::nullopt;
}

bool YellowbackIndex::ConsumeTemplateFault()
{
    LOCK(cs_yellowback);
    if (!testFault.templateFault) return false;
    testFault.templateFault = false;
    return true;
}

// ---------------------------------------------------------------------------
// Apply / undo primitives (SyncToChain and the hooks)

bool YellowbackIndex::ApplyOne(const CBlock& block, int height, const uint256& hash, std::string& error)
{
    if (testBeforeApply) testBeforeApply();
    UndoRecord undo;
    // The block subsidy is EvaluateBlock's argument (N22): state.cpp links against nothing in main.cpp.
    const CAmount subsidy = ::Params().GetConsensus().GetBlockSubsidy(height);
    std::optional<std::string> err = ApplyBlock(*db, ParamsAt(height), block, height, hash, subsidy, undo, &sigCache);
    if (err.has_value()) {
        db->Discard();
        error = err.value();
        return false;
    }
    if (height < params.startHeight) return true; // nothing happened
    db->Write(keys::Undo(hash), SerializeRecord(undo));
    int old = height - UNDO_KEEP;
    if (old >= params.startHeight) {
        std::optional<Snapshot> snap = State(*db).GetSnapshot((uint32_t)old);
        if (snap.has_value()) db->Erase(keys::Undo(snap->blockHash));
    }
    if (!db->Commit(false)) {
        error = "database write failed";
        return false;
    }
    LogPrint("yellowback", "applied block %d %s\n", height, hash.ToString());
    return true;
}

bool YellowbackIndex::UndoOne(const uint256& hash, std::string& error)
{
    std::string raw;
    UndoRecord undo;
    if (!db->Read(keys::Undo(hash), raw) || !DeserializeRecord(raw, undo)) {
        error = "undo record missing for " + hash.ToString();
        return false;
    }
    UndoBlock(*db, undo);
    db->Erase(keys::Undo(hash));
    if (!db->Commit(false)) {
        error = "database write failed";
        return false;
    }
    LogPrint("yellowback", "undid block %d %s\n", undo.height, hash.ToString());
    return true;
}

bool YellowbackIndex::SyncToChain()
{
    LOCK(cs_main);
    LOCK(cs_yellowback);
    if (!params.IsConfigured()) {
        SetUnhealthy("yellowback parameters are not configured for this network (no start height)");
        return false;
    }

    std::optional<TipRecord> tip = State(*db).GetTip();
    if (tip.has_value() && (tip->schemaVersion != SCHEMA_VERSION || testFault.schemaMismatch)) {
        // A v1 or v2 index directory (v3 plan §3.6): wipe and rebuild from the chain below, as v2 did for
        // v1; yed_getinfo.rebuilt reports it for the rest of the session.
        LogPrintf("yellowback: index schema %u differs from %u; rebuilding from the chain\n", tip->schemaVersion, SCHEMA_VERSION);
        testFault.schemaMismatch = false;
        rebuilt = true;
        Wipe("schema changed");
        tip = std::nullopt;
    }
    if (tip.has_value() && tip->network != params.network) {
        Wipe("network changed");
        tip = std::nullopt;
    }
    if (tip.has_value()) {
        // The four hashed regtest values (M13) are part of every state; a node restarted with a
        // different set rebuilds rather than carrying rows computed under the old one.
        std::optional<ParamsRecord> stored = State(*db).GetParamsRecord();
        if (stored.has_value() && SerializeRecord(stored.value()) != SerializeRecord(ParamsRecord(params))) {
            Wipe("parameters changed");
            tip = std::nullopt;
        }
    }

    const CBlockIndex* chainTip = chainActive.Tip();
    if (!chainTip || chainTip->nHeight < params.startHeight) {
        if (tip.has_value()) Wipe("chain below start height (reindex?)");
        LogPrintf("yellowback: chain below start height %d; index empty\n", params.startHeight);
        return true;
    }

    // Walk back while the stored tip is not in the active chain (a reorg while offline, or the
    // index ahead of an unflushed chainstate after a crash, V2).
    while (tip.has_value()) {
        const CBlockIndex* pindex = chainActive[tip->height];
        if (pindex && pindex->GetBlockHash() == tip->blockHash) break;
        LogPrintf("yellowback: SyncToChain: undoing block %d %s (not in the active chain)\n", tip->height, tip->blockHash.ToString());
        std::string error;
        if (!UndoOne(tip->blockHash, error)) {
            Wipe(error);
            tip = std::nullopt;
            break;
        }
        tip = State(*db).GetTip();
    }

    int from = tip.has_value() ? tip->height + 1 : params.startHeight;
    if (from <= chainTip->nHeight) {
        LogPrintf("yellowback: syncing index from height %d to %d\n", from, chainTip->nHeight);
    }
    for (int h = from; h <= chainTip->nHeight; h++) {
        const CBlockIndex* pindex = chainActive[h];
        CBlock block;
        if (!ReadBlockFromDisk(block, pindex, ::Params().GetConsensus())) {
            SetUnhealthy(strprintf("failed to read block %d from disk", h));
            return false;
        }
        std::string error;
        if (!ApplyOne(block, h, pindex->GetBlockHash(), error)) {
            SetUnhealthy(error);
            return false;
        }
    }
    db->Commit(true);
    std::optional<TipRecord> finalTip = State(*db).GetTip();
    LogPrintf("yellowback: index at height %d\n", finalTip.has_value() ? finalTip->height : -1);
    return true;
}

// ---------------------------------------------------------------------------
// The ConnectBlock / DisconnectBlock hooks

const YellowbackIndex::Evaluation& YellowbackIndex::Evaluate(const CBlock& block, int height, const uint256& tipHash)
{
    const uint256 blockHash = block.GetHash();
    const Params& p = ParamsAt(height);
    const uint256 ph = ParamsHash(p);
    if (cache.valid && cache.blockHash == blockHash && cache.tipHash == tipHash && cache.paramsHash == ph) return cache;
    if (testBeforeApply) testBeforeApply();
    cache = Evaluation();
    OverlayStateView overlay(*db);
    const CAmount subsidy = ::Params().GetConsensus().GetBlockSubsidy(height);
    cache.ev = EvaluateBlock(overlay, p, block, height, blockHash, subsidy, &sigCache);
    cache.writes = overlay.Pending();
    cache.blockHash = blockHash;
    cache.tipHash = tipHash;
    cache.paramsHash = ph;
    cache.valid = true;
    return cache;
}

bool YellowbackIndex::TipMatches(const CBlockIndex* pindex, std::optional<TipRecord>& tip, const char* hook)
{
    tip = State(*db).GetTip();
    const int h = pindex->nHeight;
    if (!tip.has_value()) {
        if (h == params.startHeight) return true;
        SetUnhealthy(strprintf("tip-mismatch: %s of block %d on an empty index (start height %d)", hook, h, params.startHeight));
        return false;
    }
    // K5: keyed on the parent's hash, never on pindex->phashBlock (null under TestBlockValidity).
    if (pindex->pprev && tip->height == h - 1 && tip->blockHash == pindex->pprev->GetBlockHash()) return true;
    SetUnhealthy(strprintf("tip-mismatch: %s of block %d whose parent is not the index tip (tip %d %s)", hook, h, tip->height, tip->blockHash.ToString()));
    return false;
}

std::optional<std::string> YellowbackIndex::CheckConnect(const CBlock& block, const CBlockIndex* pindex, bool fJustCheck)
{
    AssertLockHeld(cs_main);
    LOCK(cs_yellowback);
    if (stopped || !healthy) return std::nullopt;
    const int h = pindex->nHeight;
    if (h < params.startHeight) return std::nullopt;
    if (chainActive.Contains(pindex)) return std::nullopt;   // K6: a re-verification (VerifyDB, verifychain)
    try {
        MaybeFault(TestFault::CHECK, h);
        std::optional<TipRecord> tip;
        if (!TipMatches(pindex, tip, "check")) return std::nullopt;
        const uint256 tipHash = tip.has_value() ? tip->blockHash : uint256();
        const Evaluation& e = Evaluate(block, h, tipHash);
        if (!e.ev.blockInvalid) return std::nullopt;
        const uint256 blockHash = block.GetHash();
        const std::string reason = e.ev.reason;
        // BLK-2: what to do with an invalid verdict (the only place -yellowbackenforce is read outside the miner path, §3.10).
        if (!e.ev.enforcementOn) {
            LogPrint("yellowback", "block %s at %d fails BLK-1 (%s) but enforcement is off at this height (ACT-5)\n", blockHash.ToString(), h, reason);
            return std::nullopt;
        }
        if (!miner.enforce) {
            LogPrintf("yellowback: block %s at %d fails BLK-1 (%s); accepted (-yellowbackenforce=0)\n", blockHash.ToString(), h, reason);
            return std::nullopt;
        }
        if (valveTripped) {
            LogPrintf("yellowback: block %s at %d fails BLK-1 (%s); accepted (work valve tripped)\n", blockHash.ToString(), h, reason);
            return std::nullopt;
        }
        if (fReindex || fImporting || IsInitialBlockDownload(::Params().GetConsensus())) {
            LogPrintf("yellowback: block %s at %d fails BLK-1 (%s); accepted (initial sync / reindex / import, N2)\n", blockHash.ToString(), h, reason);
            return std::nullopt;
        }
        if (NetworkAlreadyBuiltOn(pindex)) {
            const int ahead = pindexBestHeader ? pindexBestHeader->nHeight - h : 0;
            LogPrintf("yellowback: catch-up: accepted rule-breaking block %s at %d (network %d blocks ahead)\n", blockHash.ToString(), h, ahead);
            suppressedBlocks++;
            return std::nullopt;
        }
        if (!fJustCheck) {
            RejectedRecord r;
            r.height = h;
            r.reason = reason;
            db->Write(keys::Rejected(blockHash), SerializeRecord(r));
            if (!db->Commit(true)) {
                SetUnhealthy("failed to record the rejected block");
                return std::nullopt;
            }
            rejected.insert(blockHash);
            LogPrintf("yellowback: rejecting block %s at %d: %s\n", blockHash.ToString(), h, reason);
        }
        return reason;
    } catch (const std::exception& e) {
        db->Discard();
        SetUnhealthy(std::string("storage failure in CheckConnect: ") + e.what());
        return std::nullopt;
    } catch (...) {
        db->Discard();
        SetUnhealthy("storage failure in CheckConnect");
        return std::nullopt;
    }
}

bool YellowbackIndex::CommitConnect(const CBlock& block, const CBlockIndex* pindex)
{
    AssertLockHeld(cs_main);
    LOCK(cs_yellowback);
    if (stopped || !healthy) return false;
    const int h = pindex->nHeight;
    if (h < params.startHeight) return true;
    if (chainActive.Contains(pindex)) return true;   // K6: VerifyDB level 4 reconnects with a throwaway view
    try {
        MaybeFault(TestFault::COMMIT, h);
        std::optional<TipRecord> tip;
        if (!TipMatches(pindex, tip, "commit")) return false;
        const uint256 tipHash = tip.has_value() ? tip->blockHash : uint256();
        const Evaluation& e = Evaluate(block, h, tipHash);
        for (const auto& kv : e.writes) {
            if (kv.second.has_value()) db->Write(kv.first, kv.second.value());
            else db->Erase(kv.first);
        }
        const uint256 blockHash = block.GetHash();
        db->Write(keys::Undo(blockHash), SerializeRecord(e.ev.undo));
        int old = h - UNDO_KEEP;
        if (old >= params.startHeight) {
            std::optional<Snapshot> snap = State(*db).GetSnapshot((uint32_t)old);
            if (snap.has_value()) db->Erase(keys::Undo(snap->blockHash));
        }
        if (!db->Commit(false)) {
            db->Discard();
            SetUnhealthy("database write failed in CommitConnect");
            return false;
        }
        cache.valid = false;
        LogPrint("yellowback", "applied block %d %s\n", h, blockHash.ToString());
        if (!sunsetLogged && IsSunsetLocked()) {
            sunsetLogged = true;
            LogPrintf("yellowback: enforcement sunset reached at height %d (ENFORCE_UNTIL_HEIGHT %d): upgrade required; this node tags and evaluates but rejects nothing\n", h, params.enforceUntilHeight);
        }
        return true;
    } catch (const std::exception& e) {
        db->Discard();
        SetUnhealthy(std::string("storage failure in CommitConnect: ") + e.what());
        return false;
    } catch (...) {
        db->Discard();
        SetUnhealthy("storage failure in CommitConnect");
        return false;
    }
}

bool YellowbackIndex::UndoDisconnect(const CBlockIndex* pindex)
{
    AssertLockHeld(cs_main);
    LOCK(cs_yellowback);
    if (stopped || !healthy) return false;
    const int h = pindex->nHeight;
    if (h < params.startHeight) return true;
    try {
        MaybeFault(TestFault::UNDO, h);
        std::optional<TipRecord> tip = State(*db).GetTip();
        if (!tip.has_value() || tip->blockHash != pindex->GetBlockHash()) {
            SetUnhealthy(strprintf("tip-mismatch: undo of block %d %s that is not the index tip (%s)", h, pindex->GetBlockHash().ToString(),
                                   tip.has_value() ? strprintf("%d %s", tip->height, tip->blockHash.ToString()) : std::string("empty")));
            return false;
        }
        std::string error;
        if (!UndoOne(pindex->GetBlockHash(), error)) {
            db->Discard();
            SetUnhealthy(error);
            return false;
        }
        cache.valid = false;
        return true;
    } catch (const std::exception& e) {
        db->Discard();
        SetUnhealthy(std::string("storage failure in UndoDisconnect: ") + e.what());
        return false;
    } catch (...) {
        db->Discard();
        SetUnhealthy("storage failure in UndoDisconnect");
        return false;
    }
}

// ---------------------------------------------------------------------------
// BLK-2 descendants, BLK-2 clause 3 and the work valve (ACT-7)

std::optional<uint256> YellowbackIndex::RejectedRootOf(const CBlockIndex* pindex) const
{
    const CBlockIndex* p = pindex;
    while (p) {
        if (p->nStatus & BLOCK_FAILED_VALID) {
            const uint256 h = p->GetBlockHash();
            if (rejected.count(h)) return h;
            return std::nullopt;
        }
        if (!(p->nStatus & BLOCK_FAILED_CHILD)) return std::nullopt;
        p = p->pprev;
    }
    return std::nullopt;
}

bool YellowbackIndex::IsRejectedAncestor(const CBlockIndex* pindexPrev) const
{
    AssertLockHeld(cs_main);
    LOCK(cs_yellowback);
    return RejectedRootOf(pindexPrev).has_value();
}

bool YellowbackIndex::NetworkAlreadyBuiltOn(const CBlockIndex* pindex) const
{
    AssertLockHeld(cs_main);
    const CBlockIndex* tip = chainActive.Tip();
    if (!pindexBestHeader || !tip || !pindex) return false;
    if (pindexBestHeader->GetAncestor(pindex->nHeight) != pindex) return false;
    return pindexBestHeader->nChainWork >= tip->nChainWork + GetBlockProof(*tip) * params.valveBlocks;
}

bool YellowbackIndex::NoteHeaderOnRejectedChain(const CBlockHeader& header)
{
    AssertLockHeld(cs_main);
    LOCK(cs_yellowback);
    if (valveTripped || rejected.empty()) return false;
    const uint256 hash = header.GetHash();
    uint256 root;
    arith_uint256 parentWork;
    uint32_t parentBits;
    std::map<uint256, HeaderNote>::const_iterator note = notes.find(header.hashPrevBlock);
    if (note != notes.end()) {
        root = note->second.root;
        parentWork = note->second.work;
        parentBits = note->second.nBits;
    } else {
        BlockMap::const_iterator mi = mapBlockIndex.find(header.hashPrevBlock);
        if (mi == mapBlockIndex.end()) return false;
        std::optional<uint256> r = RejectedRootOf(mi->second);
        if (!r.has_value()) return false;
        root = r.value();
        parentWork = mi->second->nChainWork;
        parentBits = mi->second->nBits;
    }
    // A descendant of a block this node rejected: answered DoS 0 whatever follows (N1).
    if (notes.count(hash)) return true;
    // P2 bounds: the target within the consensus per-block loosening of its parent's (nPowMaxAdjustDown
    // = 32 %, chainparams.cpp:104) and fewer than VALVE_NOTE_CAP notes on this root.
    bool neg = false, over = false;
    arith_uint256 target, parentTarget;
    target.SetCompact(header.nBits, &neg, &over);
    if (neg || over || target == 0) return true;
    parentTarget.SetCompact(parentBits, &neg, &over);
    if (neg || over || parentTarget == 0) return true;
    if (target > parentTarget / 100 * 132) {
        LogPrint("yellowback", "valve: header %s not noted (target outside the difficulty loosening of its parent)\n", hash.ToString());
        return true;
    }
    if (notesPerRoot[root] >= VALVE_NOTE_CAP) {
        LogPrint("yellowback", "valve: header %s not noted (root %s holds %d notes)\n", hash.ToString(), root.ToString(), VALVE_NOTE_CAP);
        return true;
    }
    CBlockIndex tmp;
    tmp.nBits = header.nBits;
    HeaderNote n;
    n.root = root;
    n.nBits = header.nBits;
    n.work = parentWork + GetBlockProof(tmp);
    notes[hash] = n;
    notesPerRoot[root]++;
    const CBlockIndex* tip = chainActive.Tip();
    if (tip) {
        const arith_uint256 bound = tip->nChainWork + GetBlockProof(*tip) * params.valveBlocks;
        LogPrint("yellowback", "valve: noted header %s on rejected root %s (work %s; trip at %s)\n", hash.ToString(), root.ToString(), n.work.GetHex(), bound.GetHex());
        if (!testFault.noValve && n.work >= bound) TripValve(root);
    }
    return true;
}

void YellowbackIndex::TripValve(const uint256& root)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_yellowback);
    const CBlockIndex* tip = chainActive.Tip();
    const int h = tip ? tip->nHeight : 0;
    valveTripped = true;
    const std::string text = strprintf("Yellowback: work valve tripped at height %d (rejected root %s); enforcement off until restart", h, root.ToString());
    LogPrintf("yellowback: %s\n", text);
    // The V13 ReconsiderBlock loop, right here under the cs_main AcceptBlockHeader holds (ACT-7).
    CValidationState state;
    for (const uint256& hash : rejected) {
        BlockMap::iterator mi = mapBlockIndex.find(hash);
        if (mi == mapBlockIndex.end()) {
            LogPrintf("yellowback: valve: rejected block %s is not in the block index; skipped\n", hash.ToString());
            continue;
        }
        ReconsiderBlock(state, mi->second);
        LogPrintf("yellowback: valve: reconsidered %s\n", hash.ToString());
    }
    // Make the cleared failure flags durable before erasing the records that drive them: 6.20.0
    // keeps never-connected index entries with their FAILED marks across restarts (Ycash
    // 1770fce16), so a crash in between would reload BLOCK_FAILED_VALID with no record left to
    // reconsider it (the startup kill switch's 83e6c1cb2). cs_main is recursive and held;
    // FlushStateToDisk adds only cs_LastBlockFile, whose holders never call into the overlay.
    FlushStateToDisk();
    for (const uint256& hash : rejected) db->Erase(keys::Rejected(hash));
    db->Commit(true);
    rejected.clear();
    notes.clear();
    notesPerRoot.clear();
    // P1: the stock fork warning never fires for refused headers, so the valve raises its own
    // through the same two calls (the timestamp is the tip's block time: no clock in this file).
    SetMiscWarning(text, tip ? tip->GetBlockTime() : 0);
    AlertNotify(text, true);   // 6.20.0: CAlert::Notify became the free function AlertNotify
}

int YellowbackIndex::RejectedCount() const
{
    LOCK(cs_yellowback);
    return (int)rejected.size();
}

std::vector<uint256> YellowbackIndex::RejectedHashes() const
{
    LOCK(cs_yellowback);
    return std::vector<uint256>(rejected.begin(), rejected.end());
}

std::optional<RejectedRecord> YellowbackIndex::GetRejected(const uint256& blockHash) const
{
    LOCK(cs_yellowback);
    return State(*db).GetRejected(blockHash);
}

void YellowbackIndex::ClearRejected()
{
    LOCK(cs_yellowback);
    for (const uint256& hash : rejected) db->Erase(keys::Rejected(hash));
    db->Commit(true);
    rejected.clear();
    notes.clear();
    notesPerRoot.clear();
}

size_t YellowbackIndex::ValveNoteCount() const
{
    LOCK(cs_yellowback);
    return notes.size();
}

bool YellowbackIndex::IsSunsetLocked() const
{
    if (params.enforceUntilHeight <= 0) return false;
    return TipHeight() >= params.enforceUntilHeight;
}

bool YellowbackIndex::IsSunset() const
{
    LOCK(cs_yellowback);
    return IsSunsetLocked();
}

bool YellowbackIndex::IsEnforcing() const
{
    LOCK(cs_yellowback);
    return miner.enforce && healthy && !valveTripped && !IsSunsetLocked();
}

// ---------------------------------------------------------------------------
// Abandonment (L10, L12), MP-1 and the mempool sweep (N5)

bool YellowbackIndex::IsAbandonedLocked() const
{
    State st(*db);
    const int tip = TipHeight();
    if (tip < params.startHeight) return false;
    const int first = tip - params.abandonBlocks + 1;
    if (first < params.startHeight) return false;
    for (int h = tip; h >= first; h--) {
        std::optional<Snapshot> s = st.GetSnapshot((uint32_t)h);
        if (!s.has_value() || !(s->haltMask & HALT_ENFORCEMENT)) return false;
    }
    return true;
}

bool YellowbackIndex::IsAbandoned() const
{
    LOCK(cs_yellowback);
    return IsAbandonedLocked();
}

std::optional<std::string> YellowbackIndex::MempoolCheckLocked(const CTransaction& tx)
{
    AssertLockHeld(cs_yellowback);
    if (stopped || !healthy) return std::nullopt;       // unhealthy: the node enforces nothing (BLK-3)
    if (tx.IsCoinBase()) return std::nullopt;
    State st(*db);
    bool spendsActive = false;
    for (const CTxIn& in : tx.vin) {                    // O(inputs) lookups, no SNAP (N6)
        std::optional<VaultRecord> v = st.GetVault(in.prevout);
        if (v.has_value() && v->Status() == VaultStatus::ACTIVE) { spendsActive = true; break; }
    }
    if (!spendsActive) return std::nullopt;
    if (IsAbandonedLocked()) return std::nullopt;       // L13: a sweep is an ordinary transaction under abandonment
    const int next = TipHeight() + 1;
    const Params& p = ParamsAt(next);
    // RED-1..4 at the next height over the two-transaction pseudo-block (§4.3): EvaluateBlock reads
    // vtx[0] as the coinbase (TAG-1, TX-0). The RED verdict comes first so that a malformed spend is
    // named by its rule (K7: mempool-check-failed:<verdict>), the expiry bound second.
    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vin[0].prevout.SetNull();
    cb.vin[0].scriptSig = CScript() << next;
    CBlock pseudo;
    pseudo.vtx.push_back(CTransaction(cb));
    pseudo.vtx.push_back(tx);
    OverlayStateView overlay(*db);
    BlockEvaluation ev = EvaluateBlock(overlay, p, pseudo, next, uint256(), 0, &sigCache);   // RED-1's bundle fills the W8 cache
    if (ev.blockInvalid) {
        const std::string::size_type colon = ev.reason.find(':');
        return colon == std::string::npos ? ev.reason : ev.reason.substr(0, colon);
    }
    // The MP-1 expiry bound (N5): nExpiryHeight != 0 and <= refHeight + REF_WINDOW, so the spend
    // expires from every mempool (stock nodes enforce expiry) before RED-1's window closes.
    std::optional<FoundPayload> fp = FindPayload(tx);
    int64_t refHeight = -1;
    if (fp.has_value() && fp->payload.type == PayloadType::REDEEM) refHeight = fp->payload.refHeight;
    if (tx.nExpiryHeight == 0 || refHeight < 0 || (int64_t)tx.nExpiryHeight > refHeight + p.refWindow) {
        return std::string("mempool-expiry");
    }
    return std::nullopt;
}

std::optional<std::string> YellowbackIndex::MempoolCheckReason(const CTransaction& tx)
{
    LOCK(cs_yellowback);
    return MempoolCheckLocked(tx);
}

bool YellowbackIndex::MempoolCheck(const CTransaction& tx)
{
    LOCK(cs_yellowback);
    return !MempoolCheckLocked(tx).has_value();
}

void YellowbackIndex::RemoveInvalidVaultSpends(CTxMemPool& pool)
{
    AssertLockHeld(cs_main);
    LOCK(pool.cs);
    LOCK(cs_yellowback);
    if (stopped || !healthy) return;
    std::vector<CTransaction> failing;
    for (CTxMemPool::indexed_transaction_set::const_iterator it = pool.mapTx.begin(); it != pool.mapTx.end(); ++it) {
        const CTransaction& tx = it->GetTx();
        std::optional<std::string> why = MempoolCheckLocked(tx);
        if (why.has_value()) {
            LogPrintf("yellowback: dropping vault spend %s from the mempool at the new tip: %s\n", tx.GetHash().ToString(), why.value());
            failing.push_back(tx);
        }
    }
    for (const CTransaction& tx : failing) {
        std::list<CTransaction> removed;
        pool.remove(tx, removed, true);
    }
}

yellowback::TemplateView YellowbackIndex::TemplateView()
{
    AssertLockHeld(cs_main);
    return yellowback::TemplateView(*this);
}

// ---------------------------------------------------------------------------
// Miner side

void YellowbackIndex::SetQuote(uint64_t priceMicroUsd, uint16_t sourceMask, int64_t receivedAt)
{
    LOCK(cs_yellowback);
    quote.priceMicroUsd = priceMicroUsd;
    quote.sourceMask = sourceMask;
    quote.receivedAt = receivedAt;
}

QuoteHolder YellowbackIndex::GetQuote() const
{
    LOCK(cs_yellowback);
    return quote;
}

MinerStatus YellowbackIndex::GetMinerStatus(int64_t now) const
{
    LOCK(cs_yellowback);
    MinerStatus s;
    s.payoutKey = miner.payoutKey;
    // MINER-1: the signal bit iff -yellowbacksignal and -yellowbackenforce and the valve has not
    // tripped and the tip is not past ENFORCE_UNTIL_HEIGHT (L3, L7, L8).
    s.signal = miner.signal && miner.enforce && !valveTripped && !IsSunsetLocked();
    if (quote.priceMicroUsd != 0) s.quoteAgeSeconds = now - quote.receivedAt;
    if (!healthy || !miner.payoutKey.has_value()) {          // MINER-3, MINER-2
        s.kind = "none";
        s.signal = false;
        return s;
    }
    if (quote.priceMicroUsd != 0 && now - quote.receivedAt <= miner.quoteMaxAge) s.kind = "quote";
    else if (miner.signal) s.kind = "signal";
    else s.kind = "none";
    const int tip = TipHeight();
    if (tip >= params.startHeight) {
        s.registered = Registered(*db, params, miner.payoutKey.value(), tip);
        for (const CKeyID& k : EligiblePayees(*db, params, tip)) {
            if (k == miner.payoutKey.value()) { s.eligible = true; break; }
        }
    }
    return s;
}

UniValue YellowbackIndex::TemplateInfo(int64_t now) const
{
    AssertLockHeld(cs_main);
    const MinerStatus ms = GetMinerStatus(now);
    LOCK(cs_yellowback);
    // The tag the template carries: COINBASE_FLAGS as CreateNewBlock set it (V5, one source of truth),
    // decoded through the same scan a node applies to the mined block (TAG-1..5).
    const int nextHeight = chainActive.Height() + 1;
    const std::optional<CoinbaseTag> tag = COINBASE_FLAGS.empty() ? std::nullopt
                                          : FindTag((CScript() << nextHeight << OP_0) + COINBASE_FLAGS, nextHeight);
    KeyIO keyIO(::Params());
    UniValue o(UniValue::VOBJ);
    o.pushKV("tag", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end()));
    o.pushKV("kind", !tag.has_value() ? "none" : tag->IsQuote() ? "quote" : "signal");
    o.pushKV("priceMicroUsd", tag.has_value() && tag->IsQuote() ? (int64_t)tag->priceMicroUsd : 0);
    o.pushKV("quoteAgeSeconds", ms.quoteAgeSeconds.has_value() ? UniValue(ms.quoteAgeSeconds.value()) : NullUniValue);
    o.pushKV("signal", tag.has_value() && tag->Signal());
    std::optional<CKeyID> payout = tag.has_value() ? std::optional<CKeyID>(CKeyID(tag->payoutKey)) : ms.payoutKey;
    o.pushKV("payoutAddress", payout.has_value() ? UniValue(keyIO.EncodeDestination(CTxDestination(payout.value()))) : NullUniValue);
    o.pushKV("registered", ms.registered);
    o.pushKV("eligible", ms.eligible);
    State st(*db);
    const int tip = TipHeight();
    const std::optional<Snapshot> snap = tip >= 0 ? st.GetSnapshot((uint32_t)tip) : std::nullopt;
    const Activation a = snap.has_value() ? snap->activation : st.GetActivation();
    o.pushKV("activation", a.Status() == ActivationStatus::ACTIVE ? "active" : a.Status() == ActivationStatus::LOCKED_IN ? "locked_in" : "signaling");
    o.pushKV("signalCount", snap.has_value() ? (int64_t)snap->signalCount : 0);
    o.pushKV("enforcing", miner.enforce && healthy && !valveTripped && !IsSunsetLocked());
    o.pushKV("valveTripped", valveTripped);
    o.pushKV("sunset", IsSunsetLocked());
    o.pushKV("healthy", healthy);
    o.pushKV("templatePolicy", miner.templatePolicy);
    return o;
}

// ---------------------------------------------------------------------------
// The CValidationInterface subscriber, reduced to wallet locking (V2)

void YellowbackIndex::ChainTip(const CBlockIndex* pindex, const CBlock* pblock, std::optional<MerkleFrontiers> added)
{
    // The state was applied synchronously in ConnectBlock; here only stage (iii) of coin
    // locking runs after every connected block, outside cs_yellowback and never under cs_main.
    // Nothing is unlocked on disconnect.
    (void)pindex; (void)pblock;
    if (stopped || !added.has_value() || !onReconcile) return;
    try {
        onReconcile();
    } catch (const std::exception& e) {
        LogPrintf("yellowback: reconcile failed: %s\n", e.what());
    } catch (...) {
        LogPrintf("yellowback: reconcile failed\n");
    }
}

void YellowbackIndex::SyncTransaction(const CTransaction& tx, const CBlock* pblock, const int nHeight)
{
    // Stage (ii) of coin locking: pre-lock every output a well-formed payload assigns to a
    // script that is mine, for mempool and block transactions alike. Never touches the state.
    (void)pblock;
    if (stopped || !onSyncTransaction) return;
    if (nHeight < params.startHeight) return;
    try {
        onSyncTransaction(tx);
    } catch (const std::exception& e) {
        LogPrintf("yellowback: SyncTransaction hook failed: %s\n", e.what());
    } catch (...) {
        LogPrintf("yellowback: SyncTransaction hook failed\n");
    }
}

// ---------------------------------------------------------------------------
// v3: the attestation pool, the signature cache and BuildBundle (W5, W6, W8)

bool AttestationPool::Add(const Attestation& att, int receivedHeight, bool& replaced)
{
    replaced = false;
    std::vector<PooledAttestation>& v = bySeq[att.seq];
    for (size_t i = 0; i < v.size(); i++) {
        if (v[i].att.citedHeight != att.citedHeight) continue;
        if (v[i].att == att) return false;                    // byte-identical: nothing changes
        v[i].att = att;                                       // the newest for this height wins
        v[i].receivedHeight = receivedHeight;
        replaced = true;
        return true;
    }
    PooledAttestation p;
    p.att = att;
    p.receivedHeight = receivedHeight;
    std::vector<PooledAttestation>::iterator at = v.begin();
    while (at != v.end() && at->att.citedHeight < att.citedHeight) ++at;
    v.insert(at, p);
    while (v.size() > POOL_PER_SEQ) {                          // drop the oldest by citedHeight
        v.erase(v.begin());
        replaced = true;
    }
    return true;
}

std::vector<PooledAttestation> AttestationPool::All() const
{
    std::vector<PooledAttestation> out;
    for (const auto& kv : bySeq) out.insert(out.end(), kv.second.begin(), kv.second.end());
    return out;
}

std::optional<Attestation> AttestationPool::Freshest(uint16_t seq, int refHeight, int maxAge, int startHeight) const
{
    std::map<uint16_t, std::vector<PooledAttestation>>::const_iterator it = bySeq.find(seq);
    if (it == bySeq.end()) return std::nullopt;
    std::optional<Attestation> best;
    for (const PooledAttestation& p : it->second) {           // ascending citedHeight: the last match is the newest
        const int64_t h = p.att.citedHeight;
        if (h > (int64_t)refHeight || h <= (int64_t)refHeight - maxAge || h < (int64_t)startHeight) continue;
        best = p.att;
    }
    return best;
}

bool AttestationPool::HasNewerThan(uint16_t seq, int64_t minExclusive) const
{
    std::map<uint16_t, std::vector<PooledAttestation>>::const_iterator it = bySeq.find(seq);
    if (it == bySeq.end()) return false;
    for (const PooledAttestation& p : it->second) {
        if ((int64_t)p.att.citedHeight > minExclusive) return true;
    }
    return false;
}

size_t AttestationPool::Size() const
{
    size_t n = 0;
    for (const auto& kv : bySeq) n += kv.second.size();
    return n;
}

std::optional<bool> LruSigCache::Lookup(const uint256& key) const
{
    std::map<uint256, Entry>::iterator it = entries.find(key);
    if (it == entries.end()) {
        misses++;
        return std::nullopt;
    }
    hits++;
    order.splice(order.begin(), order, it->second.pos);       // most recently used
    return it->second.valid;
}

void LruSigCache::Insert(const uint256& key, bool valid)
{
    std::map<uint256, Entry>::iterator it = entries.find(key);
    if (it != entries.end()) {
        it->second.valid = valid;
        order.splice(order.begin(), order, it->second.pos);
        return;
    }
    if (capacity == 0) return;
    while (entries.size() >= capacity && !order.empty()) {
        entries.erase(order.back());
        order.pop_back();
    }
    order.push_front(key);
    Entry e;
    e.valid = valid;
    e.pos = order.begin();
    entries[key] = e;
}

void LruSigCache::Clear()
{
    entries.clear();
    order.clear();
    hits = misses = 0;
}

std::string BuiltBundle::InsufficientMessage() const
{
    std::string m = strprintf("bundle-insufficient: %u of %u selected attestors have a fresh attestation; missing seq ", (unsigned)seqs.size(), (unsigned)selected.size());
    for (size_t i = 0; i < missing.size(); i++) m += (i ? "," : "") + strprintf("%u", (unsigned)missing[i]);
    return m;
}

std::optional<uint256> YellowbackIndex::BlockHashAtLocked(int64_t height) const
{
    AssertLockHeld(cs_yellowback);
    if (height < params.startHeight || height < 0 || height > 0xFFFFFFFFLL) return std::nullopt;
    std::optional<Snapshot> s = State(*db).GetSnapshot((uint32_t)height);
    if (!s.has_value() || s->blockHash.IsNull()) return std::nullopt;
    return s->blockHash;
}

bool YellowbackIndex::AttestationValidLocked(const Attestation& att, const CPubKey& pk, const uint256& blockHash)
{
    AssertLockHeld(cs_yellowback);
    const uint256 key = SigCacheKey(att, blockHash);
    std::optional<bool> cached = sigCache.Lookup(key);
    if (cached.has_value()) return cached.value();
    const bool valid = VerifyCompactSig(pk, AttestMessage(att.seq, att.priceMicroUsd, att.citedHeight, blockHash), att.sig);
    sigCache.Insert(key, valid);
    return valid;
}

bool YellowbackIndex::AddAttestation(const Attestation& att, std::string& reason, bool* replacedOut)
{
    LOCK(cs_yellowback);
    State st(*db);
    const int tip = TipHeight();
    const Params& p = ParamsAt(std::max(tip, 0));
    std::optional<AttestorRecord> rec = st.GetAttestor(att.seq);
    if (!rec.has_value()) {
        reason = strprintf("attest-unknown-seq: no attestor with seq %u", (unsigned)att.seq);
        return false;
    }
    if (rec->Status() == AttestorStatus::EJECTED || rec->Status() == AttestorStatus::WITHDRAWN) {
        reason = strprintf("attest-not-eligible: seq %u is %s", (unsigned)att.seq, AttestorStatusName(rec->Status()));
        return false;
    }
    const int64_t cited = att.citedHeight;
    const int64_t floor = (int64_t)tip - g_yellowbackMintLag - p.attestMaxAge;
    if (cited <= floor || cited > tip || cited < p.startHeight) {
        reason = strprintf("attest-stale: citedHeight %d is not in (%d, %d]", (int)cited, (int)std::max<int64_t>(floor, p.startHeight - 1), tip);
        return false;
    }
    if ((MicroUsd)att.priceMicroUsd < PRICE_MIN || (MicroUsd)att.priceMicroUsd > PRICE_MAX) {
        reason = strprintf("attest-range: priceMicroUsd %u is outside [%d, %d]", (unsigned)att.priceMicroUsd, (int)PRICE_MIN, (int)PRICE_MAX);
        return false;
    }
    std::optional<uint256> blockHash = BlockHashAtLocked(cited);
    if (!blockHash.has_value() || !AttestationValidLocked(att, rec->AttestorKey(), blockHash.value())) {
        reason = strprintf("attest-bad-sig: the signature does not verify under attestorPubKey(%u) for block %d", (unsigned)att.seq, (int)cited);
        return false;
    }
    bool replaced = false;
    pool.Add(att, tip, replaced);
    if (replacedOut) *replacedOut = replaced;
    reason.clear();
    return true;
}

std::vector<PooledAttestation> YellowbackIndex::PoolAttestations() const
{
    LOCK(cs_yellowback);
    return pool.All();
}

size_t YellowbackIndex::PoolSize() const
{
    LOCK(cs_yellowback);
    return pool.Size();
}

bool YellowbackIndex::PoolHasNewerThan(uint16_t seq, int64_t minExclusive) const
{
    LOCK(cs_yellowback);
    return pool.HasNewerThan(seq, minExclusive);
}

BuiltBundle YellowbackIndex::BuildBundleInfo(int refHeight, const std::vector<unsigned char>& selector)
{
    LOCK(cs_yellowback);
    BuiltBundle b;
    b.refHeight = refHeight;
    b.selector = selector;
    const Params& p = ParamsAt(std::max(refHeight, 0));
    b.mSelect = (size_t)std::max(0, p.mSelect);
    b.armed = ArmedAt(*db, p, refHeight);
    b.selected = Selected(*db, p, refHeight, selector);
    State st(*db);
    std::optional<Snapshot> snap = refHeight >= p.startHeight && refHeight >= 0 ? st.GetSnapshot((uint32_t)refHeight) : std::nullopt;
    const AttestState attest = snap.has_value() ? snap->attest : AttestState();
    std::vector<std::pair<uint16_t, Attestation>> chosen;
    for (uint16_t seq : b.selected) {
        std::optional<Attestation> att = pool.Freshest(seq, refHeight, p.attestMaxAge, p.startHeight);
        std::optional<AttestorRecord> rec = att.has_value() ? st.GetAttestor(seq) : std::nullopt;
        std::optional<uint256> blockHash = rec.has_value() ? BlockHashAtLocked(att->citedHeight) : std::nullopt;
        // A pooled attestation was verified at arrival; after a reorg its cited block may carry another hash (R9).
        if (!blockHash.has_value() || !AttestationValidLocked(att.value(), rec->AttestorKey(), blockHash.value())) {
            b.missing.push_back(seq);
            continue;
        }
        chosen.push_back(std::make_pair(seq, att.value()));
    }
    std::sort(chosen.begin(), chosen.end(), [](const std::pair<uint16_t, Attestation>& x, const std::pair<uint16_t, Attestation>& y) { return x.first < y.first; });
    std::vector<arith_uint256> weights;
    for (const auto& c : chosen) {
        b.seqs.push_back(c.first);
        b.bundle.atts.push_back(c.second);
        std::optional<AttestorRecord> rec = st.GetAttestor(c.first);
        weights.push_back(rec.has_value() ? AttestorWeight(rec.value(), attest, p, refHeight) : arith_uint256(0));
    }
    b.sufficient = b.seqs.size() >= b.mSelect && !b.seqs.empty();
    if (b.sufficient) {
        auto stat = BundleStat(b.bundle.atts, weights, b.mSelect, p.qLowBps, p.qHighBps);
        b.aMint = stat.first;
        b.aClaim = stat.second;
    }
    return b;
}

std::optional<Bundle> YellowbackIndex::BuildBundle(int refHeight, const std::vector<unsigned char>& selector, std::string& reason)
{
    BuiltBundle b = BuildBundleInfo(refHeight, selector);
    if (!b.sufficient) {
        reason = b.InsufficientMessage();
        return std::nullopt;
    }
    reason.clear();
    return b.bundle;
}

// ---------------------------------------------------------------------------

std::optional<std::string> ParamsFromArgs(const std::string& networkId, Params& out)
{
    // The six regtest-only flags of §3.1 (M13): -yellowbackstartheight (required), the three v2
    // overrides -yellowbacksigmaref, -yellowbacksupplycapbps, -yellowbackenforceuntil, and v3's
    // -yellowbackattestarmmin, -yellowbackbundlecarrier. Every value is hashed into the state hash
    // so mismatched test nodes fail loudly.
    static const char* const REGTEST_FLAGS[] = { "-yellowbackstartheight", "-yellowbacksigmaref", "-yellowbacksupplycapbps", "-yellowbackenforceuntil",
                                                 "-yellowbackattestarmmin", "-yellowbackbundlecarrier" };
    if (networkId != "regtest") {
        for (const char* f : REGTEST_FLAGS) {
            if (mapArgs.count(f)) return std::string(f) + " is regtest-only";
        }
        out = ParamsForNetwork(networkId);
        return std::nullopt;
    }
    if (!mapArgs.count("-yellowbackstartheight")) return std::string("regtest -yellowback requires -yellowbackstartheight");
    int64_t startHeight = GetArg("-yellowbackstartheight", 0);
    if (startHeight <= 0 || startHeight > 0x7FFFFFFF) return std::string("-yellowbackstartheight must be a positive height");
    int64_t sigmaRef = GetArg("-yellowbacksigmaref", 0);
    if (sigmaRef < 0 || sigmaRef > 0x7FFFFFFF) return std::string("-yellowbacksigmaref must be >= 0");
    int64_t capBps = GetArg("-yellowbacksupplycapbps", 0);
    if (capBps < 0 || capBps > 10000) return std::string("-yellowbacksupplycapbps must be between 0 and 10000");
    int64_t until = GetArg("-yellowbackenforceuntil", 0);
    if (until < 0 || until > 0x7FFFFFFF) return std::string("-yellowbackenforceuntil must be >= 0");
    int64_t armMin = GetArg("-yellowbackattestarmmin", 3);
    if (armMin < 0 || armMin > 0x7FFFFFFF) return std::string("-yellowbackattestarmmin must be >= 0");
    std::optional<BundleCarrier> carrier = ParseBundleCarrier(GetArg("-yellowbackbundlecarrier", "scriptsig"));
    if (!carrier.has_value()) return std::string("-yellowbackbundlecarrier must be scriptsig, opreturn or either");
    out = RegtestParams((int)startHeight, (int)sigmaRef, (int)capBps, (int)until, (int)armMin, carrier.value());
    return std::nullopt;
}

} // namespace yellowback
