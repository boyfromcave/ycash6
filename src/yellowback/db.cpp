// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "yellowback/db.h"

namespace yellowback {

YellowbackDB::YellowbackDB(const fs::path& path, size_t nCacheSize, bool fMemory, bool fWipe)
    : db(new CDBWrapper(path, nCacheSize, fMemory, fWipe))
{
}

bool YellowbackDB::Read(const std::string& key, std::string& value) const
{
    auto it = pending.find(key);
    if (it != pending.end()) {
        if (!it->second.has_value()) return false;
        value = it->second.value();
        return true;
    }
    return db->Read(RawKey(key), value);
}

void YellowbackDB::Write(const std::string& key, const std::string& value) { pending[key] = value; }
void YellowbackDB::Erase(const std::string& key) { pending[key] = std::nullopt; }

void YellowbackDB::Iterate(const std::string& prefix, const std::function<bool(const std::string&, const std::string&)>& fn) const
{
    std::map<std::string, std::string> merged;
    {
        std::unique_ptr<CDBIterator> it(db->NewIterator());
        for (it->Seek(RawKey(prefix)); it->Valid(); it->Next()) {
            RawKey k;
            if (!it->GetKey(k)) break;
            if (k.s.compare(0, prefix.size(), prefix) != 0) break;
            std::string v;
            if (!it->GetValue(v)) break;
            merged[k.s] = v;
        }
    }
    for (auto it = pending.lower_bound(prefix); it != pending.end(); ++it) {
        if (it->first.compare(0, prefix.size(), prefix) != 0) break;
        if (it->second.has_value()) merged[it->first] = it->second.value();
        else merged.erase(it->first);
    }
    for (const auto& kv : merged) {
        if (!fn(kv.first, kv.second)) break;
    }
}

bool YellowbackDB::Commit(bool fSync)
{
    if (pending.empty()) return fSync ? db->Sync() : true;
    CDBBatch batch(*db);
    for (const auto& kv : pending) {
        if (kv.second.has_value()) batch.Write(RawKey(kv.first), kv.second.value());
        else batch.Erase(RawKey(kv.first));
    }
    bool ok = db->WriteBatch(batch, fSync);
    pending.clear();
    return ok;
}

bool YellowbackDB::Sync()
{
    return db->Sync();
}

bool YellowbackDB::Wipe()
{
    pending.clear();
    std::vector<std::string> keys;
    {
        std::unique_ptr<CDBIterator> it(db->NewIterator());
        for (it->SeekToFirst(); it->Valid(); it->Next()) {
            RawKey k;
            if (!it->GetKey(k)) break;
            keys.push_back(k.s);
        }
    }
    CDBBatch batch(*db);
    for (const std::string& k : keys) batch.Erase(RawKey(k));
    return db->WriteBatch(batch, true);
}

} // namespace yellowback
