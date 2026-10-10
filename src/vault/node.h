// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_VAULT_NODE_H
#define YCASH_VAULT_NODE_H

#include "coins.h"
#include "txmempool.h"
#include "vault/db.h"
#include "vault/state.h"

#include <memory>
#include <optional>
#include <string>

class CBlock;
class CBlockIndex;
class CBlockUndo;
class CChainParams;
class CCoinsViewCache;
class CTransaction;
class CTxMemPool;

namespace Consensus { struct Params; }

/**
 * The node's wiring of the vault primitive (docs/plans/yellowback-upgrade-plan.md §15.6, U-17,
 * U-18): the global set-state database, the coin accessors validation builds, the mempool
 * re-check after a tip change, and the start-up reconciliation. Every node has the database
 * (no flag gates it); it stays empty before UPGRADE_VAULT activates. All functions here
 * require cs_main: the database changes only under it, at block boundaries, after a block's
 * parallel script checks have finished.
 */
namespace vault {

/** <datadir>/vaults/, created in init.cpp for every node (nullptr in contexts without one). */
extern VaultDB* g_vaultdb;

/** An immutable view of the set state at the database's tip (the state after chainActive's tip;
 *  the parent of the next block), or nullptr without a database. */
std::shared_ptr<const SetSnapshot> TipSnapshot();

/** Ancestor hashes of `prev` (inclusive) for the module ejection hook (U-25): heights above
 *  prev's or below 0 read as nullopt. Block index entries live for the process, so the
 *  function may outlive the caller's cs_main section, but it is only called under it. */
BlockHashFn AncestorHashes(const CBlockIndex* prev);

/** True iff the database is at the parent of `pindex`: its tip marker is pindex->pprev, or it has
 *  no tip and pindex is the first block at which UPGRADE_VAULT is active. */
bool AtParentOf(const CBlockIndex* pindex, const Consensus::Params& params);

/** Coins from a CCoinsViewCache; a coin at MEMPOOL_HEIGHT reads as `mempoolHeight`. */
class ViewCoinAccessor : public CoinAccessor
{
public:
    ViewCoinAccessor(const CCoinsViewCache& view, int64_t mempoolHeight) : view(view), mempoolHeight(mempoolHeight) {}
    bool GetSpentCoin(const COutPoint& prevout, SpentCoin& out) const override;

private:
    const CCoinsViewCache& view;
    int64_t mempoolHeight;
};

/** The spent coins of `block` (connected at `height`) from its undo data, for replay. A coin's
 *  height comes from the undo record when it carries one, else from the block itself (a coin
 *  created earlier in the block), else from the template-output index in `base` (the state
 *  before the block); only an intent's height is consensus input (I-2). False if an intent's
 *  height cannot be found. */
bool CoinsFromUndo(const CBlock& block, const CBlockUndo& undo, int64_t height, const KVReader& base, MapCoinAccessor& out);

/** Does `tx` spend a V- or I-shaped coin (inputs read from `view`)? */
bool HasTemplateInput(const CTransaction& tx, const CCoinsViewCache& view);

/** Does `tx` touch the primitive: an act or a V/I-shaped output, an input spending a V/I-shaped
 *  coin, or an input spending an indexed member bond? Inputs are read from `view`. */
bool IsVaultRelevant(const CTransaction& tx, const CCoinsViewCache& view);

/** Re-run the script of every template input of `tx` at `height` against `snapshot` (inputs from
 *  `view`): OP_CHECKSETSIG (current members) and OP_CHECKSETDORMANT (dormancy, wind-down) read set
 *  state, which a tip change moves. nullopt when every template input verifies. Used by
 *  RecheckMempool and, on 6.20.0, by the miner, whose template check (CheckAs::BlockTemplate)
 *  skips scripts. */
std::optional<std::string> RecheckTemplateScripts(const CTransaction& tx, const CCoinsViewCache& view, int height,
                                                  const std::shared_ptr<const SetSnapshot>& snapshot, const Consensus::Params& params);

/** After a tip change (ConnectTip, DisconnectTip): re-run CheckTx for `nextHeight` on every
 *  mempool transaction that touches the primitive, and the scripts of its template inputs
 *  against the new snapshot, and evict failures (set state, I-2 age, membership and dormancy
 *  change with height and with the acts just connected or disconnected). When a reorg has
 *  just dropped `nextHeight` below activation, evicts every transaction that spends or
 *  creates a template output; otherwise a no-op before activation. When a reorg has just
 *  dropped `nextHeight` below Falcon (IsPQFalconActive, no branch-ID change), also re-runs the
 *  inputs of every transaction with an OP_CHECKPQSIG at `nextHeight`'s flags and evicts failures. */
void RecheckMempool(CTxMemPool& pool, int nextHeight, const Consensus::Params& params);

/**
 * The miner's view of the vault rules for one block template (plan §15.6 "Miner"; 6.20.0's
 * BlockAssembler). A running copy of the set state over the database; coins from the tip and
 * the mempool (a mempool coin is an in-block parent there, read at the template's height). Try()
 * applies a candidate's acts and template rules on a child overlay of the running state and
 * re-runs its template inputs' scripts against the tip snapshot (the template check,
 * CheckAs::BlockTemplate, skips scripts; v4.5.0's miner re-ran them per transaction); Commit()
 * merges the last successful trial once nothing else can refuse the candidate. Requires cs_main
 * and pool.cs for its lifetime.
 */
class TemplateRun
{
public:
    TemplateRun(const VaultDB& db, CCoinsView* tip, CTxMemPool& pool, int height, const Consensus::Params& params);
    std::optional<std::string> Try(const CTransaction& tx);
    void Commit();

private:
    VaultState running;
    CCoinsViewMemPool memView;
    CCoinsViewCache view;
    ViewCoinAccessor coins;
    std::shared_ptr<const SetSnapshot> snapshot;
    int height;
    const Consensus::Params& params;
    std::optional<VaultState> trial;
};

/** Start-up reconciliation (U-18): disconnect the database back to chainActive using its own
 *  undo, then replay chainActive's blocks from disk up to the tip. False with `err` set when
 *  the database cannot be brought to the tip (a missing block or undo file). */
bool Reconcile(const CChainParams& chainparams, std::string& err);

/** A digest of every state key ('s', 'm', 'b', 'v') in byte order: equal on two nodes iff
 *  their set state is equal (vault_getinfo "statehash"). */
uint256 StateHash(const KVReader& kv);

} // namespace vault

#endif // YCASH_VAULT_NODE_H
