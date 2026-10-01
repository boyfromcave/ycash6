// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_YELLOWBACK_DB_H
#define YCASH_YELLOWBACK_DB_H

#include "dbwrapper.h"
#include "fs.h"
#include "yellowback/view.h"

#include <map>
#include <memory>
#include <optional>

/**
 * LevelDB-backed StateView under <datadir>/yellowback/ (plan D8), on the same
 * CDBWrapper the chainstate uses. Writes accumulate in a pending map and
 * are committed as one CDBBatch per block (atomic, unsynced during normal
 * operation; fSync on the shutdown flush and at the end of SyncToChain, D8).
 * Reads consult the pending map first so an in-block chain of transactions
 * sees its predecessors.
 */
namespace yellowback {

/** Raw-bytes key so LevelDB's ordering is the byte ordering of our keys (no CompactSize length prefix). */
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

class YellowbackDB : public StateView
{
public:
    YellowbackDB(const fs::path& path, size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    bool Read(const std::string& key, std::string& value) const override;
    void Write(const std::string& key, const std::string& value) override;
    void Erase(const std::string& key) override;
    void Iterate(const std::string& prefix, const std::function<bool(const std::string&, const std::string&)>& fn) const override;

    /** Write the pending changes as one batch. */
    bool Commit(bool fSync = false);
    void Discard() { pending.clear(); }
    bool HasPending() const { return !pending.empty(); }
    /** Force an fsync of everything written so far. */
    bool Sync();
    /** Delete every key (used by -reindex-yellowback and by the start-empty fallbacks). */
    bool Wipe();

private:
    std::unique_ptr<CDBWrapper> db;
    std::map<std::string, std::optional<std::string>> pending;
};

} // namespace yellowback

#endif // YCASH_YELLOWBACK_DB_H
