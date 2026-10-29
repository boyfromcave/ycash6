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
#include "policy/policy.h"
#include "pow.h"
#include "txmempool.h"
#include "util/system.h"
#include "util/strencodings.h"
#include "warnings.h"
#include "yellowback/payload.h"
#include "yellowback/script.h"
#include "yellowback/state.h"
#include "yellowback/tag.h"
#include "vault/act.h"
#include "vault/template.h"
#include "consensus/params.h"

#include <univalue.h>

#include <algorithm>
#include <csignal>

#include <boost/algorithm/string.hpp>

namespace yellowback {

YellowbackIndex* g_yellowback = nullptr;
bool g_yellowbackLive = false;
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
    : params(paramsIn), db(new YellowbackDB(dir, cacheSize, false, fWipe)), healthy(true), stopped(false), rebuilt(false), interrupted(false),
      payeePolicy(PayeePolicy::Defaults(paramsIn))
{
    paramSets.push_back(paramsIn);
    if (fWipe) LogPrintf("yellowback: index wiped (-reindex-yellowback)\n");
}

YellowbackIndex::~YellowbackIndex() {}

void YellowbackIndex::SetUnhealthy(const std::string& reason)
{
    SetAttestedFeePrice(std::nullopt);      // D-Q-23 (b): no trusted price, the fee fallback applies
    if (healthy) LogPrintf("yellowback: index unhealthy: %s; restart with -reindex-yellowback\n", reason);
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
    cache.valid = false;
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
    } else if (spec == "schema") {
        f.schemaMismatch = true;
    } else if (boost::algorithm::starts_with(spec, "crash:")) {
        int64_t h = atoi64(spec.substr(6));
        if (h <= 0 || h > 0x7FFFFFFF) return std::string("-yellowbacktestfault: bad height");
        f.crashHeight = (int)h;
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
        return std::string("-yellowbacktestfault: expected storage:<check|commit|undo>[:<height>], crash:<height>, template or schema");
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

bool YellowbackIndex::SyncToChain(const std::function<bool()>& interrupt)
{
    LOCK(cs_main);
    LOCK(cs_yellowback);
    if (!params.IsConfigured()) {
        SetUnhealthy("yellowback parameters are not configured for this network (no UPGRADE_VAULT height or no attestor set)");
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
    if (tip.has_value() && State(*db).GetRulesVersion() != RULES_VERSION) {
        // The same records judged under other rules (cf. DigiByte v9.26.7 digidollar_state.h rules_version):
        // the release that changed how stored heights are judged bumped RULES_VERSION, so rebuild.
        LogPrintf("yellowback: index rules version %u differs from %u; rebuilding from the chain\n", State(*db).GetRulesVersion(), RULES_VERSION);
        rebuilt = true;
        Wipe("rules version changed");
        tip = std::nullopt;
    }
    if (tip.has_value() && tip->network != params.network) {
        Wipe("network changed");
        tip = std::nullopt;
    }
    if (tip.has_value()) {
        // The hashed regtest values (M13) are part of every state; a node restarted with a
        // different set rebuilds rather than carrying rows computed under the old one.
        std::optional<ParamsRecord> stored = State(*db).GetParamsRecord();
        if (stored.has_value() && SerializeRecord(stored.value()) != SerializeRecord(ParamsRecord(params))) {
            Wipe("parameters changed");
            tip = std::nullopt;
        }
    }

    // From here on every block the index holds is judged under this binary's rules: stamp them (node-local, unhashed).
    db->Write(keys::RulesVersion(), SerializeRecord(RulesVersionRecord()));
    if (!db->Commit(false)) {
        SetUnhealthy("database write failed (rules version)");
        return false;
    }

    const CBlockIndex* chainTip = chainActive.Tip();
    if (!chainTip || chainTip->nHeight < params.startHeight) {
        if (tip.has_value()) {
            Wipe("chain below start height (reindex?)");
            db->Write(keys::RulesVersion(), SerializeRecord(RulesVersionRecord()));
            db->Commit(false);
        }
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
    if (!tip.has_value()) {
        // A walk-back or a wipe may have erased the stamp with everything else.
        db->Write(keys::RulesVersion(), SerializeRecord(RulesVersionRecord()));
        db->Commit(false);
    }

    int from = tip.has_value() ? tip->height + 1 : params.startHeight;
    if (from <= chainTip->nHeight) {
        LogPrintf("yellowback: syncing index from height %d to %d\n", from, chainTip->nHeight);
    }
    for (int h = from; h <= chainTip->nHeight; h++) {
        // Startup progress and cancellation (cf. DigiByte v9.26.7 b544af7fa3). Fail closed: an interrupted replay
        // is never "synced"; each applied block was committed with its tip, so the next start resumes from there.
        // A stopped index (Stop(), shutdown) is an interruption too, as every hook treats it: fail closed.
        if (stopped || (interrupt && interrupt())) {
            db->Commit(true);
            interrupted = true;
            const std::string reason = strprintf("startup replay interrupted at height %d of %d (shutdown requested); a restart resumes from height %d", h, chainTip->nHeight, h);
            LogPrintf("yellowback: %s\n", reason);
            healthy = false;          // set first so SetUnhealthy does not add its -reindex-yellowback advice: none is needed
            SetUnhealthy(reason);
            return false;
        }
        if (h > from && (h - from) % SYNC_PROGRESS_INTERVAL == 0) {
            LogPrintf("yellowback: syncing index: height %d of %d (%d%%)\n", h, chainTip->nHeight,
                      (int)((int64_t)(h - from) * 100 / std::max(1, chainTip->nHeight - from + 1)));
        }
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
    // The invariant audit (cf. DigiByte v9.26.7 19c8b1c272): saved totals are re-derived from the records, never trusted.
    if (!VerifyIndex().ok) return false;
    PublishFeePrice();
    return true;
}

IndexAudit AuditIndexRecords(const StateView& view)
{
    IndexAudit a;
    State st(const_cast<StateView&>(view));
    if (view.Exists(keys::Totals())) {
        Totals t;
        if (!st.Get(keys::Totals(), t)) a.mismatches.push_back("Totals: the stored record does not deserialize");
        else a.stored = t;
    }
    std::optional<TipRecord> tip = st.GetTip();
    if (tip.has_value()) a.tipHeight = tip->height;

    view.Iterate(std::string(1, 'K'), [&](const std::string& k, const std::string& raw) {
        TokenRecord tok;
        a.tokens++;
        if (!DeserializeRecord(raw, tok)) {
            a.mismatches.push_back(strprintf("Tokens: the record for %s:%u does not deserialize", keys::OutPointHashOf(k).GetHex(), keys::OutPointIndexOf(k)));
        } else if (tok.cents <= 0) {
            a.mismatches.push_back(strprintf("Tokens: %s:%u holds %d cents", keys::OutPointHashOf(k).GetHex(), keys::OutPointIndexOf(k), tok.cents));
        } else {
            a.derived.supplyCents += tok.cents;
        }
        return true;
    });
    view.Iterate(std::string(1, 'V'), [&](const std::string& k, const std::string& raw) {
        VaultRecord v;
        a.vaults++;
        if (!DeserializeRecord(raw, v)) {
            a.mismatches.push_back(strprintf("Vaults: the record for %s:%u does not deserialize", keys::OutPointHashOf(k).GetHex(), keys::OutPointIndexOf(k)));
            return true;
        }
        switch (v.Status()) {
        // HALT-2 (owner 2026-10-28): openDebtCents is the mintedCents of the same ACTIVE and CLAIMING vaults
        case VaultStatus::ACTIVE: a.derived.collateralZat += v.collateralZat; a.derived.openDebtCents += v.mintedCents; a.derived.activeVaults++; break;
        case VaultStatus::CLAIMING: a.derived.collateralZat += v.collateralZat; a.derived.openDebtCents += v.mintedCents; break;   // IT-6: counted until released
        case VaultStatus::VOIDED: a.derived.voidVaults++; break;
        case VaultStatus::CLOSED: a.derived.closedVaults++; break;
        case VaultStatus::CLAIMED: a.derived.claimedVaults++; break;
        default:
            a.mismatches.push_back(strprintf("Vaults: %s:%u has status %u", keys::OutPointHashOf(k).GetHex(), keys::OutPointIndexOf(k), (unsigned)v.status));
        }
        return true;
    });

    auto cmp = [&](const char* field, int64_t stored, int64_t derived) {
        if (stored != derived) a.mismatches.push_back(strprintf("Totals.%s: stored %d, records %d", field, stored, derived));
    };
    cmp("supplyCents", a.stored.supplyCents, a.derived.supplyCents);
    cmp("collateralZat", a.stored.collateralZat, a.derived.collateralZat);
    cmp("activeVaults", a.stored.activeVaults, a.derived.activeVaults);
    cmp("voidVaults", a.stored.voidVaults, a.derived.voidVaults);
    cmp("closedVaults", a.stored.closedVaults, a.derived.closedVaults);
    cmp("claimedVaults", a.stored.claimedVaults, a.derived.claimedVaults);
    cmp("unbackedCents", a.stored.unbackedCents, a.derived.unbackedCents);
    cmp("openDebtCents", a.stored.openDebtCents, a.derived.openDebtCents);
    // HALT-2's invariant (state.h OpenDebtInvariantViolation): every YED is some open vault's debt unless it was burned
    if (a.stored.supplyCents > a.stored.openDebtCents) {
        a.mismatches.push_back(strprintf("Totals: supplyCents %d exceeds openDebtCents %d", a.stored.supplyCents, a.stored.openDebtCents));
    }

    // SNAP copied the tip's totals into its snapshot; the two must still agree.
    if (tip.has_value()) {
        std::optional<Snapshot> snap = st.GetSnapshot((uint32_t)tip->height);
        if (!snap.has_value()) {
            a.mismatches.push_back(strprintf("Snapshots: no snapshot at the tip height %d", tip->height));
        } else {
            if (snap->blockHash != tip->blockHash) a.mismatches.push_back(strprintf("Snapshots[%d].blockHash: %s, tip %s", tip->height, snap->blockHash.GetHex(), tip->blockHash.GetHex()));
            if (snap->supplyCents != a.stored.supplyCents) a.mismatches.push_back(strprintf("Snapshots[%d].supplyCents (tip snapshot): %d, Totals %d", tip->height, snap->supplyCents, a.stored.supplyCents));
            if (snap->collateralZat != a.stored.collateralZat) a.mismatches.push_back(strprintf("Snapshots[%d].collateralZat (tip snapshot): %d, Totals %d", tip->height, snap->collateralZat, a.stored.collateralZat));
            if (snap->openDebtCents != a.stored.openDebtCents) a.mismatches.push_back(strprintf("Snapshots[%d].openDebtCents (tip snapshot): %d, Totals %d", tip->height, snap->openDebtCents, a.stored.openDebtCents));
        }
    }
    a.ok = a.mismatches.empty();
    return a;
}

IndexAudit YellowbackIndex::VerifyIndex()
{
    LOCK(cs_yellowback);
    IndexAudit a = AuditIndexRecords(*db);
    if (a.ok) {
        LogPrintf("yellowback: invariant audit passed at height %d (%u tokens, %u vaults)\n", a.tipHeight.value_or(-1),
                  (unsigned)a.tokens, (unsigned)a.vaults);
        return a;
    }
    for (const std::string& m : a.mismatches) LogPrintf("yellowback: invariant audit: %s\n", m);
    SetUnhealthy(strprintf("invariant audit failed at height %d: %s%s", a.tipHeight.value_or(-1), a.mismatches.front(),
                           a.mismatches.size() > 1 ? strprintf(" (and %u more)", (unsigned)(a.mismatches.size() - 1)) : std::string()));
    return a;
}

void YellowbackIndex::PublishFeePrice()
{
    // D-Q-23 (b), review M-1: the network-fee policy prices its dollars-per-KB targets at the HIGHEST of the index
    // tip's window medians (max(pFast, pMid, pSlow), pClaim-style): the min-of-windows xMint is a collateral price,
    // and under a falling market it would make the wallet overpay the network in YEC. Published when the price is
    // trusted (FeePriceTrusted, index.h; fees spec section 5.1 amendment 2026-10-28, U-27): HALT-1 (no price) and
    // HALT-3 (diverged windows) withhold it, HALT-2 (thin vaults, the price still armed and agreed) does not -- it
    // restricts minting only. Any future halt bit must decide explicitly whether it affects price trust; until it is
    // listed in FEE_PRICE_TRUSTED_HALTS it withholds the price. An untrusted price, no tip, or an unhealthy index =
    // the -pqfeerate fallback. Node policy only: nothing in block validity reads the published price.
    std::optional<int64_t> price;
    if (healthy && !stopped) {
        std::optional<TipRecord> tip = State(*db).GetTip();
        if (tip.has_value() && tip->height >= params.startHeight) {
            std::optional<Snapshot> s = State(*db).GetSnapshot((uint32_t)tip->height);
            if (s.has_value() && FeePriceTrusted(s->haltMask)) {
                for (const std::optional<MicroUsd>& w : { s->PFast(), s->PMid(), s->PSlow() }) {
                    if (w.has_value() && (!price.has_value() || w.value() > price.value())) price = w.value();
                }
            }
        }
    }
    SetAttestedFeePrice(price);
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

YellowbackIndex::ConnectCheck YellowbackIndex::CheckConnect(const CBlock& block, const CBlockIndex* pindex, bool fJustCheck)
{
    AssertLockHeld(cs_main);
    LOCK(cs_yellowback);
    ConnectCheck out;
    // Fail closed: a stopped index (shutdown) cannot evaluate the block, and an empty `out` would
    // be a pass -- a block accepted without the module check. Shutdown() stops every block source
    // before the index, so this is reached only if that order is broken.
    if (stopped) {
        out.failure = "the Yellowback index is stopped (shutdown in progress)";
        return out;
    }
    if (!healthy) {
        out.failure = "the Yellowback index is unhealthy (" + unhealthyReason + "); restart with -reindex-yellowback";
        return out;
    }
    const int h = pindex->nHeight;
    if (h < params.startHeight) return out;
    if (chainActive.Contains(pindex)) return out;   // K6: a re-verification (VerifyDB, verifychain)
    if (!fJustCheck && testFault.crashHeight == h) {
        // A crash holding a stored, unjudged block: make its index entry durable (as a periodic flush
        // would have), then die the way kill -9 does.
        LogPrintf("yellowback: -yellowbacktestfault: crash before judging block %s at %d\n", block.GetHash().ToString(), h);
        FlushStateToDisk();
        raise(SIGKILL);
    }
    try {
        MaybeFault(TestFault::CHECK, h);
        std::optional<TipRecord> tip;
        if (!TipMatches(pindex, tip, "check")) {
            out.failure = unhealthyReason;
            return out;
        }
        const uint256 tipHash = tip.has_value() ? tip->blockHash : uint256();
        const Evaluation& e = Evaluate(block, h, tipHash);
        if (!e.ev.blockInvalid) return out;
        // U-21: a consensus rejection, with no node-local conjunct (no enforcement flag, valve,
        // IBD / reindex / import or catch-up suppression, sunset or abandonment).
        out.invalid = std::string("bad-yellowback-") + e.ev.verdict;
        out.reason = e.ev.reason;
        if (!fJustCheck) LogPrintf("yellowback: block %s at %d is invalid: %s\n", block.GetHash().ToString(), h, e.ev.reason);
        return out;
    } catch (const std::exception& e) {
        db->Discard();
        SetUnhealthy(std::string("storage failure in CheckConnect: ") + e.what());
    } catch (...) {
        db->Discard();
        SetUnhealthy("storage failure in CheckConnect");
    }
    out.failure = unhealthyReason;
    return out;
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
        PublishFeePrice();
        LogPrint("yellowback", "applied block %d %s\n", h, blockHash.ToString());
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
        PublishFeePrice();
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
// The mempool check and the mempool sweep (N5)

std::optional<std::string> YellowbackIndex::MempoolCheckLocked(const CTransaction& tx)
{
    AssertLockHeld(cs_yellowback);
    if (stopped) return std::nullopt;
    if (!healthy) return std::string("yellowback-unhealthy");   // the module cannot be evaluated: admit nothing that touches it
    if (tx.IsCoinBase()) return std::nullopt;
    // The storage boundary on the mempool path (audit A-3): a storage failure refuses the transaction and
    // marks the index unhealthy (the next block then aborts the node) instead of unwinding AcceptToMemoryPool.
    try {
        return MempoolCheckInner(tx);
    } catch (const std::exception& e) {
        SetUnhealthy(std::string("storage failure in MempoolCheck: ") + e.what());
    } catch (...) {
        SetUnhealthy("storage failure in MempoolCheck");
    }
    return std::string("yellowback-unhealthy");
}

std::optional<std::string> YellowbackIndex::MempoolCheckInner(const CTransaction& tx)
{
    AssertLockHeld(cs_yellowback);
    State st(*db);
    const int next = TipHeight() + 1;
    const Params& p = ParamsAt(next);
    if (next < p.startHeight) return std::nullopt;
    // Owner 2026-10-11: a SET_REMOVE or SET_WINDDOWN of the attestor set is invalid (structural; the relevance
    // filter below looks at payloads and YED templates only, and an act is neither)
    if (RefusedAttestorSetAct(tx, p)) return std::string(verdict::ATTESTOR_SET_ACT);
    // Relevance in O(inputs + outputs) (N6): a payload, a token / vault / intent input, or a YED-tagged
    // template output is what the module reads; anything else cannot be invalid under it.
    bool spendsActive = false, relevant = FindPayload(tx).has_value();
    for (const CTxIn& in : tx.vin) {
        std::optional<VaultRecord> v = st.GetVault(in.prevout);
        if (v.has_value() && v->Status() == VaultStatus::ACTIVE) spendsActive = true;
        if (v.has_value() || st.GetToken(in.prevout).has_value() || st.GetIntent(in.prevout).has_value()) relevant = true;
    }
    for (const CTxOut& o : tx.vout) {
        vault::VaultParams vp;
        vault::IntentParams ip;
        if ((vault::ParseVault(o.scriptPubKey, vp) && vp.tag == YED_TAG) || (vault::ParseIntent(o.scriptPubKey, ip) && ip.tag == YED_TAG)) relevant = true;
    }
    // seats re-review: an act on the attestor set (a SET_JOIN may be below BondMinZat: attestor-bond-below-min)
    for (const CTxOut& o : tx.vout) {
        vault::Act act;
        if (vault::IsActOutput(o.scriptPubKey) && !vault::DecodeAct(o.scriptPubKey, act) && act.TargetSet() == p.attestorSetId) relevant = true;
    }
    if (!relevant) return std::nullopt;
    // The module's validity at the next height by ProcessTx on a discarded overlay, exactly as FilterTemplate
    // dry-runs a candidate (policy.cpp): the rules read Snapshots[ref <= H - 1] only, so no SNAP is computed
    // here (N6) and a peer streaming garbage costs this node O(inputs) lookups plus the rule checks, not a
    // ComputeSnapshot per candidate (audit A-1). The verdict comes first so that a malformed transaction is
    // named by its rule (K7: mempool-check-failed:<verdict>), the expiry bound second.
    OverlayStateView overlay(*db);
    State dry(overlay);
    const TxOutcome out = ProcessTx(dry, p, tx, next, &sigCache);   // RED-1's bundle fills the W8 cache
    if (out.invalid) return out.log.verdict;
    if (!spendsActive) return std::nullopt;
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
        std::optional<std::string> why = MempoolCheckLocked(tx);   // its storage boundary (A-3): a failure sets unhealthy
        if (!healthy) return;                                      // the next block aborts the node; nothing to sweep
        if (why.has_value()) {
            LogPrintf("yellowback: dropping %s from the mempool at the new tip: %s\n", tx.GetHash().ToString(), why.value());
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
    ++quoteGeneration;
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
    if (quote.priceMicroUsd != 0) s.quoteAgeSeconds = now - quote.receivedAt;
    if (!healthy || !miner.payoutKey.has_value()) {          // MINER-3, MINER-2
        s.kind = "none";
        return s;
    }
    // MINER-1: a quote tag iff a fresh quote is held (the signal-only tag left with ACT-1, §6)
    s.kind = quote.priceMicroUsd != 0 && now - quote.receivedAt <= miner.quoteMaxAge ? "quote" : "none";
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
    return TemplateInfo(now, (CScript() << (chainActive.Height() + 1) << OP_0) + COINBASE_FLAGS);
}

CScript CoinbaseFlagsOf(const CScript& coinbaseScriptSig)
{
    // Everything after the two leading pushes (`<height> OP_0` as CreateCoinbaseTransaction builds it,
    // `<height> <extranonce>` after IncrementExtraNonce): the bytes COINBASE_FLAGS contributed.
    CScript::const_iterator pc = coinbaseScriptSig.begin();
    opcodetype op;
    for (int i = 0; i < 2; i++) {
        if (!coinbaseScriptSig.GetOp(pc, op)) return CScript();
    }
    return CScript(pc, coinbaseScriptSig.end());
}

UniValue YellowbackIndex::TemplateInfo(int64_t now, const CScript& coinbaseScriptSig) const
{
    AssertLockHeld(cs_main);
    const MinerStatus ms = GetMinerStatus(now);
    LOCK(cs_yellowback);
    // The tag the template carries, decoded from its coinbase through the same scan a node applies to the
    // mined block (TAG-1..5). Not COINBASE_FLAGS: yed_setquote between two getblocktemplate calls changes
    // the global before the cached template is rebuilt (audit A-7).
    const int nextHeight = chainActive.Height() + 1;
    const CScript flags = CoinbaseFlagsOf(coinbaseScriptSig);
    const std::optional<CoinbaseTag> tag = flags.empty() ? std::nullopt : FindTag(coinbaseScriptSig, nextHeight);
    KeyIO keyIO(::Params());
    UniValue o(UniValue::VOBJ);
    o.pushKV("tag", HexStr(flags.begin(), flags.end()));
    o.pushKV("kind", !tag.has_value() ? "none" : tag->IsQuote() ? "quote" : "signal");
    o.pushKV("priceMicroUsd", tag.has_value() && tag->IsQuote() ? (int64_t)tag->priceMicroUsd : 0);
    o.pushKV("quoteAgeSeconds", ms.quoteAgeSeconds.has_value() ? UniValue(ms.quoteAgeSeconds.value()) : NullUniValue);
    std::optional<CKeyID> payout = tag.has_value() ? std::optional<CKeyID>(CKeyID(tag->payoutKey)) : ms.payoutKey;
    o.pushKV("payoutAddress", payout.has_value() ? UniValue(keyIO.EncodeDestination(CTxDestination(payout.value()))) : NullUniValue);
    o.pushKV("registered", ms.registered);
    o.pushKV("eligible", ms.eligible);
    o.pushKV("healthy", healthy);
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

size_t AttestationPool::Size() const
{
    size_t n = 0;
    for (const auto& kv : bySeq) n += kv.second.size();
    return n;
}

std::optional<bool> LruSigCache::Lookup(const uint256& key) const
{
    std::lock_guard<std::mutex> lock(cs);
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
    std::lock_guard<std::mutex> lock(cs);
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
    std::lock_guard<std::mutex> lock(cs);
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
    const uint256 key = SigCacheKey(att, blockHash, pk);
    std::optional<bool> cached = sigCache.Lookup(key);
    if (cached.has_value()) return cached.value();
    const bool valid = VerifyCompactSig(pk, AttestMessage(att.seq, att.priceMicroUsd, att.citedHeight, blockHash), att.sig);
    sigCache.Insert(key, valid);
    return valid;
}

bool YellowbackIndex::AddAttestation(const Attestation& att, std::string& reason, bool* replacedOut)
{
    LOCK(cs_yellowback);
    try {
        return AddAttestationLocked(att, reason, replacedOut);
    } catch (const std::exception& e) {                 // the RPC-facing storage boundary (audit A-3)
        SetUnhealthy(std::string("storage failure in AddAttestation: ") + e.what());
        throw std::runtime_error(std::string("yellowback-unhealthy: ") + unhealthyReason);
    }
}

bool YellowbackIndex::AddAttestationLocked(const Attestation& att, std::string& reason, bool* replacedOut)
{
    AssertLockHeld(cs_yellowback);
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
        reason = strprintf("attest-range: priceMicroUsd %u is outside [%d, %d]", (unsigned)att.priceMicroUsd, PRICE_MIN, PRICE_MAX);
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

bool YellowbackIndex::PoolFreshAt(uint16_t seq, int refHeight) const
{
    LOCK(cs_yellowback);
    const Params& p = ParamsAt(std::max(refHeight, 0));
    return pool.Freshest(seq, refHeight, p.attestMaxAge, p.startHeight).has_value();
}

BuiltBundle YellowbackIndex::BuildBundleInfo(int refHeight, const std::vector<unsigned char>& selector)
{
    LOCK(cs_yellowback);
    try {
        return BuildBundleInfoLocked(refHeight, selector);
    } catch (const std::exception& e) {                 // the RPC-facing storage boundary (audit A-3)
        SetUnhealthy(std::string("storage failure in BuildBundle: ") + e.what());
        throw std::runtime_error(std::string("yellowback-unhealthy: ") + unhealthyReason);
    }
}

BuiltBundle YellowbackIndex::BuildBundleInfoLocked(int refHeight, const std::vector<unsigned char>& selector)
{
    AssertLockHeld(cs_yellowback);
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

int PQFalconHeightOf(const Consensus::Params& consensus)
{
    // ::IsPQFalconActive(consensus, h) = UPGRADE_VAULT active at h && h >= pqFalconHeight (review A m-3): the
    // mirror is the later of the two heights, -1 when either never activates.
    const int vault = consensus.vUpgrades[Consensus::UPGRADE_VAULT].nActivationHeight;
    const int falcon = consensus.pqFalconHeight;
    if (vault == Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT || vault < 0) return -1;
    if (falcon == Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT || falcon < 0) return -1;
    return std::max(vault, falcon);
}

std::optional<std::string> ParamsFromArgs(const std::string& networkId, const std::string& testnetProfile,
                                          const Consensus::Params& consensus, Params& out)
{
    // U-22: START_HEIGHT is the UPGRADE_VAULT activation height and the attestor set is per network
    // (regtest -yellowbackattestorset). The regtest-only overrides of §3.1 (M13) are -yellowbacksigmaref,
    // -yellowbacksupplycapbps, v3's -yellowbackattestarmmin and -yellowbackbundlecarrier, and the hardening
    // plan's -yellowbackmintrequiresarmed (H-1); every value is hashed into the state hash so mismatched
    // test nodes fail loudly.
    static const char* const REGTEST_FLAGS[] = { "-yellowbackattestorset", "-yellowbacksigmaref", "-yellowbacksupplycapbps",
                                                 "-yellowbackattestarmmin", "-yellowbackbundlecarrier", "-yellowbackmintrequiresarmed" };
    // Retired with the vault upgrade (§6): the start is the activation height, and there is no sunset.
    for (const char* f : { "-yellowbackstartheight", "-yellowbackenforceuntil" }) {
        if (mapArgs.count(f)) return std::string(f) + " is retired: YED starts at the UPGRADE_VAULT activation height (-nuparams=6d5b7a31:<h> on regtest)";
    }
    const int startHeight = consensus.vUpgrades[Consensus::UPGRADE_VAULT].nActivationHeight == Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT
                                ? 0 : consensus.vUpgrades[Consensus::UPGRADE_VAULT].nActivationHeight;
    if (networkId != "regtest") {
        for (const char* f : REGTEST_FLAGS) {
            if (mapArgs.count(f)) return std::string(f) + " is regtest-only";
        }
        // testnet plan Revision 3 (T-16): testnet-yb-fast reads the fast column; testnet-yb-slow the testnet
        // column (mainnet's values); testnet-legacy the same, inert (no UPGRADE_VAULT height: startHeight 0).
        if (networkId == "test" && testnetProfile != "fast" && testnetProfile != "slow" && testnetProfile != "legacy")
            return "unknown testnet profile '" + testnetProfile + "' (fast, slow or legacy)";
        out = networkId == "test" && testnetProfile == "fast" ? TestFastParams() : ParamsForNetwork(networkId);
        out.startHeight = out.attestorSetId.IsNull() ? 0 : startHeight;
        out.pqFalconHeight = PQFalconHeightOf(consensus);
        out.issuedBeforeStart = out.startHeight > 0 ? CirculatingSupplyAt(out.startHeight - 1, consensus) : 0;   // D-Q-25
        return std::nullopt;
    }
    uint256 setId;
    if (mapArgs.count("-yellowbackattestorset")) {
        const std::string hex = GetArg("-yellowbackattestorset", "");
        if (hex.size() != 64 || !IsHex(hex)) return std::string("-yellowbackattestorset must be a set id (64 hex characters)");
        setId = uint256S(hex);
        if (setId.IsNull()) return std::string("-yellowbackattestorset must not be zero");
    }
    int64_t sigmaRef = GetArg("-yellowbacksigmaref", 0);
    if (sigmaRef < 0 || sigmaRef > 0x7FFFFFFF) return std::string("-yellowbacksigmaref must be >= 0");
    int64_t capBps = GetArg("-yellowbacksupplycapbps", 0);
    if (capBps < 0 || capBps > 10000) return std::string("-yellowbacksupplycapbps must be between 0 and 10000");
    int64_t armMin = GetArg("-yellowbackattestarmmin", 3);
    if (armMin < 0 || armMin > 0x7FFFFFFF) return std::string("-yellowbackattestarmmin must be >= 0");
    std::optional<BundleCarrier> carrier = ParseBundleCarrier(GetArg("-yellowbackbundlecarrier", "scriptsig"));
    if (!carrier.has_value()) return std::string("-yellowbackbundlecarrier must be scriptsig, opreturn or either");
    const bool requireArmed = GetBoolArg("-yellowbackmintrequiresarmed", false);
    out = RegtestParams(setId.IsNull() ? 0 : startHeight, (int)sigmaRef, (int)capBps, setId, (int)armMin, carrier.value(), requireArmed);
    out.pqFalconHeight = PQFalconHeightOf(consensus);
    out.issuedBeforeStart = out.startHeight > 0 ? CirculatingSupplyAt(out.startHeight - 1, consensus) : 0;   // D-Q-25
    return std::nullopt;
}

CAmount CirculatingSupplyAt(int height, const Consensus::Params& c)
{
    // The sum of GetBlockSubsidy(h) over 1 <= h <= height, in closed form: the two slow-start ramps as arithmetic
    // series, then one product per segment of constant subsidy, whose boundaries are the slow-start end, the Blossom
    // activation and every halving height. The genesis block is excluded (its coinbase is unspendable by construction,
    // and GetBlockSubsidy(0) is 0 on mainnet anyway; getblocksubsidy, which the Python model sums block by block to
    // check this, refuses height 0). The whole subsidy counts (miner plus founders' reward / funding streams: both
    // circulate); nothing is subtracted for lost coins or fees. Equal to Σ GetBlockSubsidy by construction
    // (yellowback_index_tests checks it against the brute-force sum across every boundary).
    if (height < 1) return 0;
    arith_uint256 total = 0;
    const int interval = c.nSubsidySlowStartInterval;
    const int shift = c.SubsidySlowStartShift();
    if (interval > 0) {
        const uint64_t rate = (uint64_t)((CAmount)(12.5 * COIN) / interval);                 // GetBlockSubsidy's integer rate
        // h in [0, shift): rate * h;  h in [shift, interval): rate * (h + 1)
        const int64_t a = std::min(height, shift - 1);                                     // the last ramp-1 height
        if (a >= 0) total += arith_uint256(rate) * arith_uint256((uint64_t)a * (uint64_t)(a + 1) / 2);
        if (height >= shift) {
            const int64_t b = std::min(height, interval - 1);
            const uint64_t n = (uint64_t)(b - shift + 1);                                  // blocks shift..b, each rate * (h + 1)
            total += arith_uint256(rate) * arith_uint256(n * (uint64_t)(shift + 1 + b + 1) / 2);
        }
    }
    int h = std::max(interval, 1);                                                         // the first full-subsidy block (never genesis)
    const int blossom = c.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight;
    while (h <= height) {
        const CAmount subsidy = c.GetBlockSubsidy(h);
        int next = height + 1;                                                             // the segment [h, next)
        const int nextHalving = c.HalvingHeight(h, c.Halving(h) + 1);                      // valid within h's regime
        if (nextHalving > h && nextHalving < next) next = nextHalving;
        if (blossom != Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT && blossom > h && blossom < next) next = blossom;
        if (subsidy == 0) break;                                                           // beyond the 64th halving
        total += arith_uint256((uint64_t)subsidy) * arith_uint256((uint64_t)(next - h));
        h = next;
    }
    return FitsInt64(total) && MoneyRange((CAmount)total.GetLow64()) ? (CAmount)total.GetLow64() : MAX_MONEY;
}

} // namespace yellowback
