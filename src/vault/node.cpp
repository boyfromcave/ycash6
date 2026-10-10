// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "vault/node.h"

#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/upgrades.h"
#include "hash.h"
#include "main.h"
#include "policy/policy.h"
#include "primitives/block.h"
#include "script/interpreter.h"
#include "script/standard.h"
#include "txmempool.h"
#include "undo.h"
#include "logging.h"
#include "util/system.h"
#include "vault/act.h"
#include "vault/checker.h"
#include "vault/template.h"

#include <set>

namespace vault {

VaultDB* g_vaultdb = nullptr;

std::shared_ptr<const SetSnapshot> TipSnapshot()
{
    if (!g_vaultdb) return nullptr;
    return std::make_shared<const SetSnapshot>(*g_vaultdb);
}

BlockHashFn AncestorHashes(const CBlockIndex* prev)
{
    return [prev](int64_t h) -> std::optional<uint256> {
        if (!prev || h < 0 || h > prev->nHeight) return std::nullopt;
        const CBlockIndex* p = prev->GetAncestor((int)h);
        if (!p) return std::nullopt;
        return p->GetBlockHash();
    };
}

bool AtParentOf(const CBlockIndex* pindex, const Consensus::Params& params)
{
    if (!g_vaultdb || !pindex) return false;
    uint256 tipHash;
    int64_t tipHeight;
    if (!g_vaultdb->GetTip(tipHash, tipHeight)) {
        return IsActivationHeight(pindex->nHeight, params, Consensus::UPGRADE_VAULT);
    }
    return pindex->pprev && tipHash == pindex->pprev->GetBlockHash();
}

bool ViewCoinAccessor::GetSpentCoin(const COutPoint& prevout, SpentCoin& out) const
{
    const CCoins* coins = view.AccessCoins(prevout.hash);
    if (!coins || !coins->IsAvailable(prevout.n)) return false;
    out.scriptPubKey = coins->vout[prevout.n].scriptPubKey;
    out.value = coins->vout[prevout.n].nValue;
    out.height = coins->nHeight == MEMPOOL_HEIGHT ? mempoolHeight : (int64_t)coins->nHeight;
    return true;
}

bool CoinsFromUndo(const CBlock& block, const CBlockUndo& undo, int64_t height, const KVReader& base, MapCoinAccessor& out)
{
    if (undo.vtxundo.size() + 1 != block.vtx.size()) return false;
    std::set<uint256> inBlock;
    for (size_t i = 0; i < block.vtx.size(); i++) {
        const CTransaction& tx = block.vtx[i];
        if (i > 0) {
            const CTxUndo& txundo = undo.vtxundo[i - 1];
            if (txundo.vprevout.size() != tx.vin.size()) return false;
            for (size_t j = 0; j < tx.vin.size(); j++) {
                const COutPoint& prevout = tx.vin[j].prevout;
                const CTxInUndo& u = txundo.vprevout[j];
                SpentCoin c;
                c.scriptPubKey = u.txout.scriptPubKey;
                c.value = u.txout.nValue;
                if (inBlock.count(prevout.hash)) {
                    c.height = height;
                } else if (u.nHeight != 0) {
                    c.height = u.nHeight;
                } else if (auto rec = GetTemplateOut(base, prevout)) {
                    c.height = rec->height;
                } else {
                    IntentParams ip;
                    if (MatchIntent(c.scriptPubKey, ip) != Shape::NONE) return false;
                    c.height = 0; // not consensus input for anything but an intent
                }
                out.coins[prevout] = c;
            }
        }
        inBlock.insert(tx.GetHash());
    }
    return true;
}

bool HasTemplateInput(const CTransaction& tx, const CCoinsViewCache& view)
{
    if (tx.IsCoinBase()) return false;
    for (const CTxIn& in : tx.vin) {
        const CCoins* coins = view.AccessCoins(in.prevout.hash);
        if (!coins || !coins->IsAvailable(in.prevout.n)) continue;
        const CScript& spk = coins->vout[in.prevout.n].scriptPubKey;
        VaultParams vp;
        IntentParams ip;
        if (MatchVault(spk, vp) != Shape::NONE || MatchIntent(spk, ip) != Shape::NONE) return true;
    }
    return false;
}

bool IsVaultRelevant(const CTransaction& tx, const CCoinsViewCache& view)
{
    for (const CTxOut& o : tx.vout) {
        if (IsActOutput(o.scriptPubKey)) return true;
        VaultParams vp;
        if (MatchVault(o.scriptPubKey, vp) != Shape::NONE) return true;
        IntentParams ip;
        if (MatchIntent(o.scriptPubKey, ip) != Shape::NONE) return true;
    }
    if (tx.IsCoinBase()) return false;
    for (const CTxIn& in : tx.vin) {
        const CCoins* coins = view.AccessCoins(in.prevout.hash);
        if (coins && coins->IsAvailable(in.prevout.n)) {
            const CScript& spk = coins->vout[in.prevout.n].scriptPubKey;
            VaultParams vp;
            if (MatchVault(spk, vp) != Shape::NONE) return true;
            IntentParams ip;
            if (MatchIntent(spk, ip) != Shape::NONE) return true;
        }
        if (g_vaultdb && GetBond(*g_vaultdb, in.prevout)) return true;
    }
    return false;
}

namespace {

/** Spends or creates a V/I-shaped output (the transactions that are invalid before activation
 *  only by policy, and become meaningless again if a reorg drops below it). */
bool TouchesTemplate(const CTransaction& tx, const CCoinsViewCache& view)
{
    for (const CTxOut& o : tx.vout) {
        VaultParams vp;
        IntentParams ip;
        if (MatchVault(o.scriptPubKey, vp) != Shape::NONE || MatchIntent(o.scriptPubKey, ip) != Shape::NONE) return true;
    }
    if (tx.IsCoinBase()) return false;
    for (const CTxIn& in : tx.vin) {
        const CCoins* coins = view.AccessCoins(in.prevout.hash);
        if (!coins || !coins->IsAvailable(in.prevout.n)) continue;
        VaultParams vp;
        IntentParams ip;
        const CScript& spk = coins->vout[in.prevout.n].scriptPubKey;
        if (MatchVault(spk, vp) != Shape::NONE || MatchIntent(spk, ip) != Shape::NONE) return true;
    }
    return false;
}

/** Re-run every input script of `tx` at `height`'s flags when `tx` carries an OP_CHECKPQSIG
 *  (GetPQSigOpCount). Falcon (scheme 0x02) activates at pqFalconHeight with no branch-ID change
 *  (quantum spec R-A2), so the branch-ID eviction of a reorg does not reach a Falcon spend
 *  accepted for the block at pqFalconHeight (review F-1). */
std::optional<std::string> RecheckPQScripts(const CTransaction& tx, const CCoinsViewCache& view, int height,
                                            const std::shared_ptr<const SetSnapshot>& snapshot, const Consensus::Params& params)
{
    if (tx.IsCoinBase() || GetPQSigOpCount(tx, view) == 0) return std::nullopt;
    // 6.20.0: the precomputed data takes every input's coin (a v4 sighash ignores them).
    std::vector<CTxOut> allPrevOutputs;
    for (const CTxIn& in : tx.vin) {
        const CCoins* c = view.AccessCoins(in.prevout.hash);
        allPrevOutputs.push_back(c && c->IsAvailable(in.prevout.n) ? c->vout[in.prevout.n] : CTxOut());
    }
    PrecomputedTransactionData txdata(tx, allPrevOutputs);
    const unsigned int flags = STANDARD_SCRIPT_VERIFY_FLAGS | GetVaultScriptFlags(height, params);
    const uint32_t branch = CurrentEpochBranchId(height, params);
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CCoins* coins = view.AccessCoins(tx.vin[i].prevout.hash);
        if (!coins || !coins->IsAvailable(tx.vin[i].prevout.n)) continue;
        const CTxOut& prev = coins->vout[tx.vin[i].prevout.n];
        ScriptError err = SCRIPT_ERR_OK;
        if (!VerifyScript(tx.vin[i].scriptSig, prev.scriptPubKey, flags,
                          SetSigChecker(&tx, i, prev.nValue, false, txdata, snapshot, height), branch, &err)) {
            return strprintf("input %u: %s", i, ScriptErrorString(err));
        }
    }
    return std::nullopt;
}

} // namespace

std::optional<std::string> RecheckTemplateScripts(const CTransaction& tx, const CCoinsViewCache& view, int height,
                                                  const std::shared_ptr<const SetSnapshot>& snapshot, const Consensus::Params& params)
{
    if (tx.IsCoinBase()) return std::nullopt;
    std::optional<PrecomputedTransactionData> txdata;
    const unsigned int flags = STANDARD_SCRIPT_VERIFY_FLAGS | GetVaultScriptFlags(height, params);
    const uint32_t branch = CurrentEpochBranchId(height, params);
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CCoins* coins = view.AccessCoins(tx.vin[i].prevout.hash);
        if (!coins || !coins->IsAvailable(tx.vin[i].prevout.n)) continue;
        const CTxOut& prev = coins->vout[tx.vin[i].prevout.n];
        VaultParams vp;
        IntentParams ip;
        if (MatchVault(prev.scriptPubKey, vp) == Shape::NONE && MatchIntent(prev.scriptPubKey, ip) == Shape::NONE) continue;
        if (!txdata) {
            // 6.20.0: the precomputed data takes every input's coin (a v4 sighash ignores them).
            std::vector<CTxOut> allPrevOutputs;
            for (const CTxIn& in : tx.vin) {
                const CCoins* c = view.AccessCoins(in.prevout.hash);
                allPrevOutputs.push_back(c && c->IsAvailable(in.prevout.n) ? c->vout[in.prevout.n] : CTxOut());
            }
            txdata.emplace(tx, allPrevOutputs);
        }
        ScriptError err = SCRIPT_ERR_OK;
        if (!VerifyScript(tx.vin[i].scriptSig, prev.scriptPubKey, flags,
                          SetSigChecker(&tx, i, prev.nValue, false, *txdata, snapshot, height), branch, &err)) {
            return strprintf("template input %u: %s", i, ScriptErrorString(err));
        }
    }
    return std::nullopt;
}

void RecheckMempool(CTxMemPool& pool, int nextHeight, const Consensus::Params& params)
{
    AssertLockHeld(cs_main);
    LOCK(pool.cs);
    const bool active = params.NetworkUpgradeActive(nextHeight, Consensus::UPGRADE_VAULT);
    // A reorg has just dropped `nextHeight` below Falcon's height: evict every transaction whose
    // inputs fail at `nextHeight`'s flags (a scheme-0x02 OP_CHECKPQSIG now SCRIPT_ERR_PQ_SCHEME),
    // with its descendants, so neither the mempool nor a block template keeps it (review F-1).
    if (!IsPQFalconActive(params, nextHeight) && IsPQFalconActive(params, nextHeight + 1)) {
        CCoinsViewMemPool viewMemPool(pcoinsTip, pool);
        CCoinsViewCache view(&viewMemPool);
        std::shared_ptr<const SetSnapshot> snapshot = active && g_vaultdb ? TipSnapshot() : nullptr;
        std::vector<CTransaction> failing;
        for (CTxMemPool::indexed_transaction_set::const_iterator it = pool.mapTx.begin(); it != pool.mapTx.end(); ++it) {
            if (std::optional<std::string> why = RecheckPQScripts(it->GetTx(), view, nextHeight, snapshot, params)) {
                LogPrint("vault", "vault: dropping %s from the mempool: Falcon is not active at %d (%s)\n", it->GetTx().GetHash().ToString(), nextHeight, *why);
                failing.push_back(it->GetTx());
            }
        }
        for (const CTransaction& tx : failing) {
            std::list<CTransaction> removed;
            pool.remove(tx, removed, true);
        }
    }
    if (active && !g_vaultdb) return;
    // Below activation there is only something to do right after a reorg dropped the next
    // block below it (the mempool may still hold template spends accepted before).
    const int activation = params.vUpgrades[Consensus::UPGRADE_VAULT].nActivationHeight;
    if (!active && (activation == Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT || nextHeight != activation - 1)) return;
    CCoinsViewMemPool viewMemPool(pcoinsTip, pool);
    CCoinsViewCache view(&viewMemPool);
    std::shared_ptr<const SetSnapshot> snapshot = active ? TipSnapshot() : nullptr;
    ViewCoinAccessor coins(view, nextHeight);

    std::vector<CTransaction> failing;
    for (CTxMemPool::indexed_transaction_set::const_iterator it = pool.mapTx.begin(); it != pool.mapTx.end(); ++it) {
        const CTransaction& tx = it->GetTx();
        if (!active) {
            if (TouchesTemplate(tx, view)) {
                LogPrint("vault", "vault: dropping %s from the mempool: the upgrade is not active at %d\n", tx.GetHash().ToString(), nextHeight);
                failing.push_back(tx);
            }
            continue;
        }
        if (!IsVaultRelevant(tx, view)) continue;
        std::optional<std::string> why = CheckTx(tx, coins, nextHeight, *snapshot, AncestorHashes(chainActive.Tip()));
        if (!why) why = RecheckTemplateScripts(tx, view, nextHeight, snapshot, params);
        if (why) {
            LogPrint("vault", "vault: dropping %s from the mempool at height %d: %s\n", tx.GetHash().ToString(), nextHeight, *why);
            failing.push_back(tx);
        }
    }
    for (const CTransaction& tx : failing) {
        std::list<CTransaction> removed;
        pool.remove(tx, removed, true);
    }
}

TemplateRun::TemplateRun(const VaultDB& db, CCoinsView* tip, CTxMemPool& pool, int heightIn, const Consensus::Params& paramsIn)
    : running(db), memView(tip, pool), view(&memView), coins(view, heightIn),
      snapshot(std::make_shared<const SetSnapshot>(db)), height(heightIn), params(paramsIn)
{
    // The module ejection hook (U-25) reads the template's ancestors: the template's parent is
    // the active tip (the miner holds cs_main for this object's lifetime). A trial copies them.
    running.SetBlockHashes(AncestorHashes(chainActive.Tip()));
}

std::optional<std::string> TemplateRun::Try(const CTransaction& tx)
{
    trial.emplace(running);
    std::optional<std::string> bad = trial->ApplyTx(tx, height, coins);
    if (!bad) bad = RecheckTemplateScripts(tx, view, height, snapshot, params);
    if (bad) trial.reset();
    return bad;
}

void TemplateRun::Commit()
{
    if (!trial) return;
    for (const auto& change : trial->Changes()) {
        if (change.second) running.Put(change.first, *change.second);
        else running.Erase(change.first);
    }
    trial.reset();
}

bool Reconcile(const CChainParams& chainparams, std::string& err)
{
    AssertLockHeld(cs_main);
    if (!g_vaultdb) return true;
    const Consensus::Params& params = chainparams.GetConsensus();
    const int activation = params.vUpgrades[Consensus::UPGRADE_VAULT].nActivationHeight;
    uint256 tipHash;
    int64_t tipHeight;
    const bool haveTip = g_vaultdb->GetTip(tipHash, tipHeight);

    if (activation == Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT) {
        if (haveTip) {
            LogPrintf("vault: the upgrade has no activation height; wiping the set-state database\n");
            g_vaultdb->Wipe();
        }
        return true;
    }

    int64_t start = activation;
    if (haveTip) {
        BlockMap::iterator mi = mapBlockIndex.find(tipHash);
        CBlockIndex* pindex = mi == mapBlockIndex.end() ? nullptr : mi->second;
        if (!pindex) {
            LogPrintf("vault: database tip %s is not in the block index; rebuilding from height %d\n", tipHash.GetHex(), activation);
            g_vaultdb->Wipe();
        } else {
            bool wiped = false;
            while (!chainActive.Contains(pindex)) {
                if (!pindex->pprev || pindex->pprev->nHeight < activation) {
                    g_vaultdb->Wipe();
                    wiped = true;
                    break;
                }
                LogPrintf("vault: disconnecting %s at %d (not on the active chain)\n", pindex->GetBlockHash().GetHex(), pindex->nHeight);
                if (!g_vaultdb->DisconnectBlock(pindex->GetBlockHash(), pindex->pprev->GetBlockHash(), pindex->pprev->nHeight)) {
                    LogPrintf("vault: cannot disconnect %s; rebuilding from height %d\n", pindex->GetBlockHash().GetHex(), activation);
                    g_vaultdb->Wipe();
                    wiped = true;
                    break;
                }
                pindex = pindex->pprev;
            }
            if (!wiped) start = std::max<int64_t>(activation, pindex->nHeight + 1);
        }
    }

    const int tip = chainActive.Height();
    if (start <= tip) LogPrintf("vault: replaying blocks %d..%d into the set-state database\n", start, tip);
    for (int64_t h = start; h <= tip; h++) {
        CBlockIndex* pindex = chainActive[h];
        CBlock block;
        if (!ReadBlockFromDisk(block, pindex, params)) {
            err = strprintf("vault: cannot read block %d from disk", h);
            return false;
        }
        CBlockUndo undo;
        if (!ReadBlockUndo(undo, pindex)) {
            err = strprintf("vault: cannot read the undo data of block %d", h);
            return false;
        }
        MapCoinAccessor coins;
        if (!CoinsFromUndo(block, undo, h, *g_vaultdb, coins)) {
            err = strprintf("vault: block %d's undo data does not give its spent coins", h);
            return false;
        }
        VaultState state(*g_vaultdb);
        state.SetBlockHashes(AncestorHashes(pindex->pprev));
        BlockUndo vundo;
        if (auto bad = state.ApplyBlock(block, h, coins, vundo, pindex)) {
            err = strprintf("vault: block %d on the active chain fails the vault rules on replay (%s)", h, *bad);
            return false;
        }
        if (!g_vaultdb->ConnectBlock(pindex->GetBlockHash(), h, pindex->pprev->GetBlockHash(), state, vundo)) {
            err = strprintf("vault: cannot write block %d to the set-state database", h);
            return false;
        }
    }
    g_vaultdb->Flush();
    return true;
}

uint256 StateHash(const KVReader& kv)
{
    CHashWriter hw(SER_GETHASH, 0);
    for (char prefix : {KEY_BOND, KEY_MEMBER, KEY_SET, KEY_TEMPLATE_OUT}) {
        kv.Iterate(std::string(1, prefix), [&](const std::string& k, const std::string& v) {
            hw << k << v;
            return true;
        });
    }
    return hw.GetHash();
}

} // namespace vault
