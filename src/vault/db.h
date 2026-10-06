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

class VaultDB : public KVReader
{
public:
    VaultDB(const fs::path& path, size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    bool Read(const std::string& key, std::string& value) const override;
    void Iterate(const std::string& prefix, const std::function<bool(const std::string&, const std::string&)>& fn) const override;

    /** The block the state is at; false when the DB is empty (no block connected yet). */
    bool GetTip(uint256& hash, int64_t& height) const;

    /** Commit `state` (one block's VaultState over this DB) and `undo` as block `hash` at
     *  `height`. Refused unless the tip is `prevHash` or the DB has no tip yet. */
    bool ConnectBlock(const uint256& hash, int64_t height, const uint256& prevHash, const VaultState& state, const BlockUndo& undo);
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
    mutable std::mutex cs;
    mutable std::map<std::string, std::optional<std::string>> cache;
    static const size_t MAX_CACHE_ENTRIES = 100000;
};

} // namespace vault

#endif // YCASH_VAULT_DB_H
