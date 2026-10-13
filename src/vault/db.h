// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_VAULT_DB_H
#define YCASH_VAULT_DB_H

#include "dbwrapper.h"
#include "fs.h"
#include "uint256.h"
#include "vault/state.h"

#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

/**
 * The set-state database at <datadir>/vaults/ (docs/plans/yellowback-upgrade-plan.md U-18):
 * its own LevelDB, never inside the coins DB. Each connected block commits, in one batch,
 * the block's state changes, its undo record ('u'||blockhash) and the tip marker ('T'), so
 * the DB is always at a block boundary; on start the caller compares the tip marker with the
 * chain tip and replays (or disconnects) blocks to reconcile. Reads are served through a
 * write-through cache and are safe from parallel script-check threads.
 */
namespace vault {

/** Raw-bytes key so LevelDB orders keys by their bytes (no CompactSize length prefix). */
struct RawKey
{
    std::string s;
    RawKey() {}
    explicit RawKey(const std::string& s) : s(s) {}
    template <typename Stream> void Serialize(Stream& st) const { st.write(s.data(), s.size()); }
    template <typename Stream> void Unserialize(Stream& st)
    {
        s.resize(st.size());
        if (!s.empty()) st.read(&s[0], s.size());
    }
};

static const char KEY_TIP = 'T';
static const char KEY_UNDO = 'u';
static const char KEY_VERSION = 'V';

/**
 * The set-state database's format version ('V', u32), written with every connected block. A database
 * with a tip whose version differs (or is absent: version 1) is wiped and rebuilt from the activation
 * height on start (Reconcile). 2: the seats review fixes (owner 2026-10-11 -- bond exitHeight, one unspent
 * bond per key, the liveness hook, D-Q-31) change what replay derives from the same blocks (review A3).
 */
static const uint32_t VAULT_DB_VERSION = 3;   //!< 3: SetRecord.joinCount and MemberRecord.joinOrdinal (seats re-review)

/**
 * Undo records older than this many blocks are pruned on connect (audit 07/F-7), as the Yellowback index
 * prunes its own (yellowback/index.h UNDO_KEEP): connecting block H erases the undo of block H - UNDO_KEEP in
 * the same batch, so after connecting H the undo of H - 4095 .. H is kept (UNDO_KEEP records) and a disconnect
 * of any of those blocks works. A crash-time walk-back in Reconcile that needs an older one finds no undo and
 * takes the wipe + replay from the activation height (07/F-8): time, not soundness — a SIGKILL during a long
 * IBD with a large -dbcache can also take it. A live reorg is bounded far below (MAX_REORG_LENGTH, 99 blocks);
 * an invalidateblock that would disconnect a block below H - 4095 stops the node in DisconnectBlock (AbortNode,
 * as the Yellowback index does) and a plain restart does not recover (it stops again in
 * PruneBlockIndexCandidates, regtest-verified): restart with -reindex, which rebuilds the block index and
 * every database from the block files and forgets the invalidation.
 * No VAULT_DB_VERSION bump: the record set only shrinks; a database written before this keeps its
 * older undo records (never pruned retroactively), which is harmless. Do not bump the version to clean them:
 * a bump replays every node from activation.
 */
static const int UNDO_KEEP = 4096;

class VaultDB : public KVReader
{
public:
    VaultDB(const fs::path& path, size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    bool Read(const std::string& key, std::string& value) const override;
    void Iterate(const std::string& prefix, const std::function<bool(const std::string&, const std::string&)>& fn) const override;

    /** The stored format version (VAULT_DB_VERSION); 1 when the key is absent (a database from before it). */
    uint32_t GetVersion() const;

    /** The block the state is at; false when the DB is empty (no block connected yet). */
    bool GetTip(uint256& hash, int64_t& height) const;

    /** Commit `state` (one block's VaultState over this DB) and `undo` as block `hash` at
     *  `height`. Refused unless the tip is `prevHash` or the DB has no tip yet. `pruneUndoOf`, the
     *  hash of the block UNDO_KEEP below (UndoToPrune, vault/node.h), has its undo record erased in
     *  the same batch. */
    bool ConnectBlock(const uint256& hash, int64_t height, const uint256& prevHash, const VaultState& state, const BlockUndo& undo,
                      const std::optional<uint256>& pruneUndoOf = std::nullopt);
    /** Undo block `hash` (must be the tip) and set the tip to (prevHash, prevHeight). */
    bool DisconnectBlock(const uint256& hash, const uint256& prevHash, int64_t prevHeight);
    bool ReadUndo(const uint256& hash, BlockUndo& undo) const;

    /** fsync everything written so far (shutdown, end of reconciliation). */
    bool Flush();
    /** Delete every key (reindex / start-empty fallback). */
    bool Wipe();

private:
    void CachePut(const std::string& key, const std::optional<std::string>& value) const;

    std::unique_ptr<CDBWrapper> db;
    /** Guards `cache`, `generation` and the write batch (a commit and its cache update are one step under it).
     *  Every consensus reader additionally holds cs_main, which is what orders reads against commits; Read never
     *  caches a value read before a commit, a cache clear or a Wipe (audit 01/V-6). */
    mutable std::mutex cs;
    mutable std::map<std::string, std::optional<std::string>> cache;
    /** Bumped (under cs) by every commit, cache clear and Wipe; Read snapshots it before its LevelDB read and
     *  inserts what it read only if it is unchanged. */
    mutable uint64_t generation = 0;
    static const size_t MAX_CACHE_ENTRIES = 100000;
};

} // namespace vault

#endif // YCASH_VAULT_DB_H
