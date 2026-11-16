// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "valuepools.h"

#include "chain.h"
#include "chainparams.h"
#include "crypto/pq/scheme.h"
#include "dbwrapper.h"
#include "logging.h"
#include "main.h"
#include "rpc/server.h"
#include "script/script.h"
#include "script/standard.h"
#include "ui_interface.h"
#include "undo.h"
#include "util/strencodings.h"
#include "util/system.h"
#include "util/time.h"
#include "vault/template.h"
#include "yellowback/script.h"

#include <memory>
#include <mutex>

namespace valuepools {

namespace {

//! Keys: 'r' + block hash -> Record (the totals after that block); 'B' -> the hash of the last block written.
const char KEY_RECORD = 'r';
const char KEY_BEST = 'B';

//! Progress is logged every this many blocks of the fill.
const int FILL_LOG_INTERVAL = 10000;
//! The fill writes its records in batches of this many blocks.
const int FILL_BATCH = 1000;

std::mutex cs;                     //!< guards everything below
std::unique_ptr<CDBWrapper> db;    //!< nullptr: the index is off
//! The record most recently written (the tip's, as a rule). The hook sets it only once its batch is written; the
//! fill sets it as it goes, as the parent of the next block, and every failure of the fill resets it with the store.
std::optional<std::pair<uint256, Record>> lastWritten;
std::optional<std::pair<uint256, Record>> genesisRecord; //!< computed once
bool fReportedGap = false;         //!< "not covered" logged once per run

// Test hooks (valuepools::test, gtest only).
std::optional<Seed> testSeed;      //!< replaces CompiledSeed when fTestSeed
bool fTestSeed = false;
std::function<bool(const CBlockIndex*, CBlock&, CBlockUndo&)> testBlockReader; //!< replaces the disk reads of the fill
bool fTestFailWrites = false;      //!< every write throws dbwrapper_error

std::pair<char, uint256> RecordKey(const uint256& hash) { return std::make_pair(KEY_RECORD, hash); }

/**
 * The highest chain-supply checkpoint the seed claim covers (note §4, §9 item 1): no output below it matches a PQ,
 * channel, vault or intent template, so every class but `transparent` is 0 there and `transparent` is the
 * checkpoint's transparent value. The claim is checked by a startup fill from genesis (blocks/valuepools deleted,
 * -valuepoolsseed=0), which logs a match or refuses to start on a mismatch; a sync or -reindex checks it as it
 * passes the seed block and logs either way (a mismatch there leaves the index unmonitored). A checkpoint moved above this height disables the seed
 * (the fill then reads from genesis) until the claim is checked at the new height and this constant raised.
 * Checked at 2,800,000 on 2026-11-15: a fill from genesis on a copy of a mainnet data directory (tip 3,100,949)
 * logged the match.
 */
const int SEED_CHECKED_MAX_HEIGHT = 2800000;

//! The seed the hook and the fill use: the compiled one, or the test hook's.
std::optional<Seed> EffectiveSeed(const CChainParams& chainparams)
{
    if (fTestSeed) return testSeed;
    return CompiledSeed(chainparams);
}

//! caller holds cs; throws dbwrapper_error on a failure (CDBWrapper::WriteBatch never returns false)
void CommitLocked(CDBBatch& batch, bool fSync)
{
    if (fTestFailWrites) throw dbwrapper_error("write failure (test hook)");
    db->WriteBatch(batch, fSync);
}

/**
 * caller holds cs: a write failed. The store is closed and the cache dropped, so every entry says "monitored":
 * false and the hook does nothing (one log line, not one per block) until the node restarts and the fill resumes
 * from the last block whose record was written.
 */
void DisableLocked(const std::string& what)
{
    db.reset();
    lastWritten.reset();
    LogPrintf("valuepools: %s; the transparent pools by type are not monitored until the node restarts\n", what);
}

//! The genesis block's record (it is never passed to ConnectBlock's transaction loop, so it is never stored).
std::optional<Record> GenesisRecord(const uint256& hash)
{
    if (genesisRecord && genesisRecord->first == hash) return genesisRecord->second;
    const CBlock& genesis = Params().GenesisBlock();
    if (genesis.GetHash() != hash) return std::nullopt;
    Record r;
    std::string err;
    if (!ApplyBlock(Record(), genesis, CBlockUndo(), r, err)) {
        LogPrintf("valuepools: the genesis block cannot be classified: %s\n", err);
        return std::nullopt;
    }
    genesisRecord = std::make_pair(hash, r);
    return r;
}

//! caller holds cs
std::optional<Record> ReadRecordLocked(const CBlockIndex* pindex)
{
    if (!pindex) return std::nullopt;
    const uint256 hash = pindex->GetBlockHash();
    if (!pindex->pprev) return GenesisRecord(hash);
    if (!db) return std::nullopt;
    if (lastWritten && lastWritten->first == hash) return lastWritten->second;
    Record r;
    // An unknown version or a record that cannot be read is "no record"; so is a record whose totals leave their
    // range (a corrupt store), so that nothing is ever computed from it.
    if (!db->Read(RecordKey(hash), r)) return std::nullopt;
    if (!r.IsSane()) {
        LogPrintf("valuepools: the record of block %s is out of range; it is treated as missing\n", hash.ToString());
        return std::nullopt;
    }
    return r;
}

enum class StepResult { OK, NO_PARENT, INCONSISTENT, SEED_MISMATCH };

/**
 * The record of `pindex` from its parent's record, checked against the seed when the block is the seed block.
 * Shared by the hook and the fill, so a filled record equals a live one by construction. caller holds cs.
 */
StepResult ComputeLocked(const CBlock& block, const CBlockUndo& blockundo, const CBlockIndex* pindex,
                         const std::optional<Seed>& seed, Record& out, std::string& err)
{
    const std::optional<Record> parent = ReadRecordLocked(pindex->pprev);
    if (!parent) return StepResult::NO_PARENT;
    if (!ApplyBlock(*parent, block, blockundo, out, err)) return StepResult::INCONSISTENT;
    if (seed && pindex->nHeight == seed->height && pindex->GetBlockHash() == seed->hash) {
        if (out != seed->record) {
            err = strprintf("the totals computed at the seed block %d (transparent %d, pq %d+%d, channel %d, vault %d, intent %d) "
                            "differ from the compiled seed (transparent %d)",
                            pindex->nHeight, out.transparent, out.pq1, out.pq2, out.channel, out.vault, out.intent,
                            seed->record.transparent);
            return StepResult::SEED_MISMATCH;
        }
        LogPrintf("valuepools: the compiled seed at height %d matches the totals computed from genesis\n", pindex->nHeight);
    }
    return StepResult::OK;
}

//! caller holds cs: adds the record of `hash` to `batch` and names it the last block written
void WriteLocked(CDBBatch& batch, const uint256& hash, const Record& r)
{
    batch.Write(RecordKey(hash), r);
    batch.Write(KEY_BEST, hash);
}

UniValue Entry(UniValue obj, const std::optional<CAmount>& chainValue, const std::optional<CAmount>& valueDelta)
{
    // The fields of valuePools' entries (rpc/blockchain.cpp ValuePoolDesc), in the same order.
    obj.pushKV("monitored", (bool)chainValue);
    if (chainValue) {
        obj.pushKV("chainValue", ValueFromAmount(*chainValue));
        obj.pushKV("chainValueZat", *chainValue);
    }
    if (valueDelta) {
        obj.pushKV("valueDelta", ValueFromAmount(*valueDelta));
        obj.pushKV("valueDeltaZat", *valueDelta);
    }
    return obj;
}

std::string SchemeName(uint8_t scheme)
{
    // The wallet's names (rpcwallet.cpp PQSchemeName), which the server library cannot link.
    switch (scheme) {
        case pq::SCHEME_SLH_DSA_SHA2_128S: return "SLH-DSA-SHA2-128s";
        case pq::SCHEME_FN_DSA_512:        return "FN-DSA-512";
        default:                           return "unknown";
    }
}

} // namespace

std::optional<Seed> CompiledSeed(const CChainParams& chainparams)
{
    // The network's chain-supply checkpoint, where it names its block (mainnet and the shadow testnets, which share
    // mainnet below their split; regtest's optional checkpoint names none, so regtest and the legacy testnet fill
    // from genesis).
    const int height = chainparams.ChainSupplyCheckpointHeight();
    const uint256 hash = chainparams.ChainSupplyCheckpointBlockHash();
    if (height <= 0 || height > SEED_CHECKED_MAX_HEIGHT || hash.IsNull()) return std::nullopt;
    Seed seed;
    seed.height = height;
    seed.hash = hash;
    seed.record.transparent = chainparams.ChainSupplyCheckpointTransparentValue();
    return seed;
}

ScriptClass ClassifyTransparentScript(const CScript& s)
{
    ScriptClass c;
    // TX_PQPKH: the byte compare of script/standard.cpp MatchPayToPQKeyHash (static there; the unit test pins this
    // copy to Solver), as the wallet's PQSchemeOfScript does.
    if (s.size() == 35 && s[0] == 32 && (s[33] == OP_1 || s[33] == OP_2) && s[34] == OP_CHECKPQSIG) {
        c.cls = PoolClass::TRANSPARENT_PQ;
        c.pqScheme = (uint8_t)CScript::DecodeOP_N((opcodetype)s[33]);
        return c;
    }
    // TX_PQCHANNEL starts with OP_IF; the matcher rebuilds and compares.
    if (!s.empty() && s[0] == OP_IF) {
        PQChannelParams cp;
        if (MatchPQChannel(s, cp)) {
            c.cls = PoolClass::PQ_CHANNEL;
            return c;
        }
    }
    // V and I start with their 4-byte tag push.
    if (s.size() > 5 && s[0] == 4) {
        vault::VaultParams vp;
        if (vault::ParseVault(s, vp)) {
            c.cls = PoolClass::VAULT;
            c.yed = vp.tag == yellowback::YED_TAG;
            return c;
        }
        vault::IntentParams ip;
        if (vault::ParseIntent(s, ip)) {
            c.cls = PoolClass::VAULT_INTENT;
            c.yed = ip.tag == yellowback::YED_TAG;
            return c;
        }
    }
    return c;
}

bool Record::IsSane() const
{
    for (CAmount v : {transparent, pq1, pq2, channel, vault, intent, vaultYed, intentYed}) {
        if (!MoneyRange(v)) return false;
    }
    return vaultYed <= vault && intentYed <= intent && MoneyRange(TransparentECC());
}

bool Record::operator==(const Record& o) const
{
    return transparent == o.transparent && pq1 == o.pq1 && pq2 == o.pq2 && channel == o.channel &&
           vault == o.vault && intent == o.intent && vaultYed == o.vaultYed && intentYed == o.intentYed;
}

void AddOutput(Record& r, const CTxOut& out, int sign)
{
    const CAmount v = sign * out.nValue;
    r.transparent += v;
    const ScriptClass c = ClassifyTransparentScript(out.scriptPubKey);
    switch (c.cls) {
        case PoolClass::TRANSPARENT_PQ:
            if (c.pqScheme == 1) r.pq1 += v; else r.pq2 += v;
            break;
        case PoolClass::PQ_CHANNEL:
            r.channel += v;
            break;
        case PoolClass::VAULT:
            r.vault += v;
            if (c.yed) r.vaultYed += v;
            break;
        case PoolClass::VAULT_INTENT:
            r.intent += v;
            if (c.yed) r.intentYed += v;
            break;
        case PoolClass::TRANSPARENT_ECC:
            break;
    }
}

namespace {
//! Every running total within [-MAX_MONEY, MAX_MONEY]: with each addend in MoneyRange, the next addition cannot
//! overflow, whatever the undo data or a parent record read from disk holds.
bool Bounded(const Record& r)
{
    for (CAmount v : {r.transparent, r.pq1, r.pq2, r.channel, r.vault, r.intent, r.vaultYed, r.intentYed}) {
        if (v < -MAX_MONEY || v > MAX_MONEY) return false;
    }
    return true;
}
} // namespace

bool ApplyBlock(const Record& parent, const CBlock& block, const CBlockUndo& blockundo, Record& out, std::string& err)
{
    if (!parent.IsSane()) {
        err = "the parent's record is out of range";
        return false;
    }
    Record r = parent;
    size_t nUndo = 0;
    for (const CTransaction& tx : block.vtx) {
        if (!tx.IsCoinBase()) {
            if (nUndo >= blockundo.vtxundo.size() || blockundo.vtxundo[nUndo].vprevout.size() != tx.vin.size()) {
                err = strprintf("the undo data does not match transaction %s", tx.GetHash().ToString());
                return false;
            }
            for (const CTxInUndo& spent : blockundo.vtxundo[nUndo].vprevout) {
                if (!MoneyRange(spent.txout.nValue)) {
                    err = strprintf("an output spent by transaction %s is out of range in the undo data", tx.GetHash().ToString());
                    return false;
                }
                AddOutput(r, spent.txout, -1);
                if (!Bounded(r)) {
                    err = strprintf("a total leaves its range at transaction %s", tx.GetHash().ToString());
                    return false;
                }
            }
            nUndo++;
        }
        for (const CTxOut& o : tx.vout) {
            if (!MoneyRange(o.nValue)) {
                err = strprintf("an output of transaction %s is out of range", tx.GetHash().ToString());
                return false;
            }
            AddOutput(r, o, +1);
            if (!Bounded(r)) {
                err = strprintf("a total leaves its range at transaction %s", tx.GetHash().ToString());
                return false;
            }
        }
    }
    if (nUndo != blockundo.vtxundo.size()) {
        err = "the undo data has more transactions than the block";
        return false;
    }
    if (!r.IsSane()) {
        err = strprintf("a total leaves its range (transparent %d, pq %d+%d, channel %d, vault %d (YED %d), intent %d (YED %d))",
                        r.transparent, r.pq1, r.pq2, r.channel, r.vault, r.vaultYed, r.intent, r.intentYed);
        return false;
    }
    out = r;
    return true;
}

void Open(const fs::path& path, bool fWipe)
{
    std::lock_guard<std::mutex> lock(cs);
    lastWritten.reset();
    genesisRecord.reset();
    fReportedGap = false;
    try {
        db.reset(new CDBWrapper(path, 1 << 20, false, fWipe));
    } catch (const std::exception& e) {
        db.reset();
        LogPrintf("valuepools: cannot open %s (%s); the transparent pools by type are not monitored\n", path.string(), e.what());
    }
}

void Close()
{
    std::lock_guard<std::mutex> lock(cs);
    db.reset();
    lastWritten.reset();
}

bool IsOpen()
{
    std::lock_guard<std::mutex> lock(cs);
    return (bool)db;
}

void BlockConnected(const CBlock& block, const CBlockUndo& blockundo, const CBlockIndex* pindex)
{
    // Never throws, asserts or reports to the caller: a block is valid or not before this runs (note §6).
    std::lock_guard<std::mutex> lock(cs);
    try {
        if (!db || !pindex) return;
        Record r;
        std::string err;
        switch (ComputeLocked(block, blockundo, pindex, EffectiveSeed(Params()), r, err)) {
            case StepResult::OK: {
                CDBBatch batch(*db);
                WriteLocked(batch, pindex->GetBlockHash(), r);
                CommitLocked(batch, false);
                // Cached only once written: a record that never reached the store is never extended.
                lastWritten = std::make_pair(pindex->GetBlockHash(), r);
                return;
            }
            case StepResult::NO_PARENT:
                // Not covered (a pruned node that could not fill, or a failure below): nothing to extend.
                if (!fReportedGap) {
                    fReportedGap = true;
                    LogPrintf("valuepools: block %d extends a block the index does not cover; the transparent pools by type "
                              "are not monitored (restart to fill, or -reindex if this node is pruned)\n", pindex->nHeight);
                }
                return;
            case StepResult::INCONSISTENT:
                LogPrintf("valuepools: block %d %s: %s; the blocks after it are not monitored (restart with -reindex)\n",
                          pindex->nHeight, pindex->GetBlockHash().ToString(), err);
                return;
            case StepResult::SEED_MISMATCH:
                // -reindex would only repeat this; a fresh index starts from the seed instead of checking it.
                LogPrintf("valuepools: block %d %s: %s; the blocks after it are not monitored (stop the node and delete "
                          "blocks/valuepools in the data directory: the next start rebuilds the index from the compiled seed)\n",
                          pindex->nHeight, pindex->GetBlockHash().ToString(), err);
                return;
        }
    } catch (const std::exception& e) {
        DisableLocked(strprintf("block %d: %s", pindex ? pindex->nHeight : -1, e.what()));
    } catch (...) {
        DisableLocked(strprintf("block %d: unknown failure", pindex ? pindex->nHeight : -1));
    }
}

bool Fill(const CChainParams& chainparams, const std::function<bool()>& interrupted, std::string& errOut)
{
    AssertLockHeld(cs_main);
    std::lock_guard<std::mutex> lock(cs);
    if (!db) return true;
    const CBlockIndex* tip = chainActive.Tip();
    if (!tip) {
        LogPrintf("valuepools: no active chain yet; nothing to fill\n");
        return true;
    }
    const std::optional<Seed> seed = EffectiveSeed(chainparams);

    try {
        // The start: the last block written, or its nearest ancestor on the active chain (records are keyed by hash,
        // so a record written on a fork that lost is still right for its block); else the seed; else genesis.
        const CBlockIndex* start = nullptr;
        uint256 best;
        if (db->Read(KEY_BEST, best)) {
            BlockMap::const_iterator it = mapBlockIndex.find(best);
            if (it != mapBlockIndex.end()) {
                const CBlockIndex* fork = chainActive.FindFork(it->second);
                if (fork && ReadRecordLocked(fork)) start = fork;
            }
        }
        if (!start && seed && GetBoolArg("-valuepoolsseed", true) && tip->nHeight >= seed->height &&
            chainActive[seed->height]->GetBlockHash() == seed->hash) {
            start = chainActive[seed->height];
            CDBBatch batch(*db);
            WriteLocked(batch, start->GetBlockHash(), seed->record);
            CommitLocked(batch, true);
            lastWritten = std::make_pair(start->GetBlockHash(), seed->record);
            LogPrintf("valuepools: starting from the compiled seed at height %d\n", seed->height);
        }
        if (!start) start = chainActive.Genesis();
        if (start == tip) {
            LogPrintf("valuepools: the index covers the tip (height %d)\n", tip->nHeight);
            return true;
        }

        LogPrintf("valuepools: filling the transparent pools by type from height %d to %d\n", start->nHeight + 1, tip->nHeight);
        // The node waits for the fill: say so in the warm-up status the RPC server answers with (-28) meanwhile.
        uiInterface.InitMessage(strprintf(_("Filling the transparent pools index (height %d of %d)..."), start->nHeight, tip->nHeight));
        const int64_t nStart = GetTimeMillis();
        std::unique_ptr<CDBBatch> batch(new CDBBatch(*db));
        int nBatch = 0;
        for (int h = start->nHeight + 1; h <= tip->nHeight; h++) {
            if (interrupted()) {
                CommitLocked(*batch, true);
                LogPrintf("valuepools: fill interrupted at height %d\n", h);
                return true;
            }
            const CBlockIndex* pindex = chainActive[h];
            CBlock block;
            CBlockUndo blockundo;
            bool fRead = (pindex->nStatus & BLOCK_HAVE_DATA) && (pindex->nStatus & BLOCK_HAVE_UNDO);
            if (fRead) {
                fRead = testBlockReader ? testBlockReader(pindex, block, blockundo)
                                        : ReadBlockFromDisk(block, pindex, chainparams.GetConsensus()) && ReadBlockUndo(blockundo, pindex);
            }
            if (!fRead) {
                CommitLocked(*batch, true);
                LogPrintf("valuepools: the block or undo data of block %d is not available (pruned?); the transparent pools by "
                          "type are not monitored from this height: reindex to enable\n", h);
                return true;
            }
            Record r;
            std::string err;
            switch (ComputeLocked(block, blockundo, pindex, seed, r, err)) {
                case StepResult::OK:
                    break;
                case StepResult::SEED_MISMATCH:
                    CommitLocked(*batch, true);
                    errOut = "valuepools: " + err + ". This may indicate on-disk corruption. Stop the node, delete the directory "
                             "blocks/valuepools in the data directory and start without -valuepoolsseed=0: the index is then "
                             "rebuilt from the compiled seed (a few minutes on mainnet; the chain itself is kept). -reindex "
                             "would repeat this check and fail again.";
                    LogPrintf("%s\n", errOut);
                    return false;
                case StepResult::NO_PARENT:
                case StepResult::INCONSISTENT:
                    CommitLocked(*batch, true);
                    LogPrintf("valuepools: block %d: %s; the transparent pools by type are not monitored from this height "
                              "(restart with -reindex)\n", h, err.empty() ? "no record of its parent" : err);
                    return true;
            }
            WriteLocked(*batch, pindex->GetBlockHash(), r);
            lastWritten = std::make_pair(pindex->GetBlockHash(), r); // the next block's parent; reset if a write fails
            if (++nBatch >= FILL_BATCH) {
                CommitLocked(*batch, false);
                batch.reset(new CDBBatch(*db));
                nBatch = 0;
            }
            if (h % FILL_LOG_INTERVAL == 0) {
                LogPrintf("valuepools: filled to height %d of %d (%ds)\n", h, tip->nHeight, (GetTimeMillis() - nStart) / 1000);
                uiInterface.InitMessage(strprintf(_("Filling the transparent pools index (height %d of %d)..."), h, tip->nHeight));
            }
        }
        CommitLocked(*batch, true);
        LogPrintf("valuepools: filled to the tip (height %d) in %dms\n", tip->nHeight, GetTimeMillis() - nStart);
    } catch (const std::exception& e) {
        DisableLocked(strprintf("fill failed: %s", e.what()));
    } catch (...) {
        DisableLocked("fill failed: unknown failure");
    }
    return true;
}

std::optional<Record> GetRecord(const CBlockIndex* pindex)
{
    try {
        std::lock_guard<std::mutex> lock(cs);
        return ReadRecordLocked(pindex);
    } catch (const std::exception& e) {
        LogPrintf("valuepools: read failed: %s\n", e.what());
        return std::nullopt;
    } catch (...) {
        LogPrintf("valuepools: read failed: unknown failure\n");
        return std::nullopt;
    }
}

UniValue TransparentPoolsToJSON(const CBlockIndex* pindex, bool withDelta)
{
    const std::optional<Record> r = GetRecord(pindex);
    // A delta needs the parent's record too (the genesis block's parent is the empty chain).
    std::optional<Record> parent;
    if (withDelta && r) parent = pindex->pprev ? GetRecord(pindex->pprev) : std::optional<Record>(Record());

    auto value = [&](CAmount (*f)(const Record&)) -> std::optional<CAmount> {
        if (!r) return std::nullopt;
        return f(*r);
    };
    auto delta = [&](CAmount (*f)(const Record&)) -> std::optional<CAmount> {
        if (!r || !parent) return std::nullopt;
        return f(*r) - f(*parent);
    };
    auto withId = [](const char* key, const UniValue& v) {
        UniValue o(UniValue::VOBJ);
        o.pushKV(key, v);
        return o;
    };

    UniValue result(UniValue::VOBJ);
    result.pushKV("monitored", (bool)r);
    {
        CAmount (*f)(const Record&) = [](const Record& x) { return x.transparent; };
        result.pushKV("transparent", Entry(UniValue(UniValue::VOBJ), value(f), delta(f)));
    }

    struct Pool { const char* id; CAmount (*f)(const Record&); };
    const Pool pools[] = {
        {"transparent_ecc", [](const Record& x) { return x.TransparentECC(); }},
        {"transparent_pq",  [](const Record& x) { return x.TransparentPQ(); }},
        {"pq_channel",      [](const Record& x) { return x.channel; }},
        {"vault",           [](const Record& x) { return x.vault; }},
        {"vault_intent",    [](const Record& x) { return x.intent; }},
    };
    UniValue arr(UniValue::VARR);
    for (const Pool& p : pools) arr.push_back(Entry(withId("id", p.id), value(p.f), delta(p.f)));
    result.pushKV("pools", arr);

    // Both schemes always, in the wallet's order (rpcwallet.cpp PQ_BALANCE_SCHEMES).
    struct Scheme { uint8_t scheme; CAmount (*f)(const Record&); };
    const Scheme schemes[] = {
        {pq::SCHEME_SLH_DSA_SHA2_128S, [](const Record& x) { return x.pq1; }},
        {pq::SCHEME_FN_DSA_512,        [](const Record& x) { return x.pq2; }},
    };
    UniValue byScheme(UniValue::VARR);
    for (const Scheme& s : schemes) {
        UniValue o(UniValue::VOBJ);
        o.pushKV("pqscheme", (int)s.scheme);
        o.pushKV("pqschemename", SchemeName(s.scheme));
        byScheme.push_back(Entry(o, value(s.f), delta(s.f)));
    }
    result.pushKV("pq_by_scheme", byScheme);

    // Registered rule modules only (vault/module.h): today YED. Its row is its part of vault plus vault_intent.
    UniValue byModule(UniValue::VARR);
    {
        UniValue o(UniValue::VOBJ);
        o.pushKV("module", "YED");
        o.pushKV("tag", HexStr(yellowback::YED_TAG.begin(), yellowback::YED_TAG.end()));
        CAmount (*f)(const Record&) = [](const Record& x) { return x.vaultYed + x.intentYed; };
        byModule.push_back(Entry(o, value(f), delta(f)));
    }
    result.pushKV("vault_by_module", byModule);
    return result;
}

std::string HelpText(bool withDelta)
{
    const std::string d = withDelta
        ? ", \"valueDelta\": x.xxx, \"valueDeltaZat\": n (the change in this block)"
        : "";
    return
        "  \"transparentPools\": {      (object) the transparent value pool split by address type; the entries are\n"
        "                               disjoint and sum to \"transparent\". Find entries by \"id\", never by position\n"
        "    \"monitored\": xx,          (boolean) false until the node's index covers this block (it is filled once at\n"
        "                               startup; a pruned node that lacks the old block data must -reindex to enable it)\n"
        "    \"transparent\": {\"monitored\": xx, \"chainValue\": x.xxx, \"chainValueZat\": n" + d + "}\n"
        "    \"pools\": [                (array) {\"id\", \"monitored\", \"chainValue\", \"chainValueZat\"" + (withDelta ? ", \"valueDelta\", \"valueDeltaZat\"" : "") + "}, ids:\n"
        "      \"transparent_ecc\"         every other script (P2PKH, P2SH, ...); unlike the wallet's figure of that\n"
        "                               name it excludes the channel and vault classes below\n"
        "      \"transparent_pq\"          post-quantum pay-to-key-hash outputs (TX_PQPKH), YED token outputs included\n"
        "      \"pq_channel\"              post-quantum payment channels\n"
        "      \"vault\", \"vault_intent\"   value locked in vault templates and in their release intents\n"
        "    ],\n"
        "    \"pq_by_scheme\": [         (array) transparent_pq by scheme, both always: {\"pqscheme\": n, \"pqschemename\": \"...\", ...}\n"
        "    ],\n"
        "    \"vault_by_module\": [      (array) a registered rule module's part of vault plus vault_intent: {\"module\": \"YED\", \"tag\": \"59454400\", ...}\n"
        "    ]\n"
        "  },\n";
}

namespace test {
void SetSeed(const std::optional<Seed>& seed)
{
    std::lock_guard<std::mutex> lock(cs);
    testSeed = seed;
    fTestSeed = true;
}

void Reset()
{
    std::lock_guard<std::mutex> lock(cs);
    testSeed.reset();
    fTestSeed = false;
    testBlockReader = nullptr;
    fTestFailWrites = false;
}

void SetBlockReader(std::function<bool(const CBlockIndex*, CBlock&, CBlockUndo&)> reader)
{
    std::lock_guard<std::mutex> lock(cs);
    testBlockReader = std::move(reader);
}

void SetFailWrites(bool fail)
{
    std::lock_guard<std::mutex> lock(cs);
    fTestFailWrites = fail;
}
} // namespace test

} // namespace valuepools
