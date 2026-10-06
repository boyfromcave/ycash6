// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "vault/db.h"

#include "streams.h"
#include "logging.h"
#include "version.h"

namespace vault {

namespace {

std::string UndoKey(const uint256& hash)
{
    std::string k(1, KEY_UNDO);
    k.append((const char*)hash.begin(), 32);
    return k;
}

const std::string& TipKey()
{
    static const std::string k(1, KEY_TIP);
    return k;
}

std::string EncodeTip(const uint256& hash, int64_t height)
{
    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << hash << height;
    return std::string(ss.begin(), ss.end());
}

} // namespace

VaultDB::VaultDB(const fs::path& path, size_t nCacheSize, bool fMemory, bool fWipe)
    : db(new CDBWrapper(path, nCacheSize, fMemory, fWipe))
{
}

void VaultDB::CachePut(const std::string& key, const std::optional<std::string>& value) const
{
    // caller holds cs
    if (cache.size() >= MAX_CACHE_ENTRIES) cache.clear();
    cache[key] = value;
}

bool VaultDB::Read(const std::string& key, std::string& value) const
{
    {
        std::lock_guard<std::mutex> lock(cs);
        auto it = cache.find(key);
        if (it != cache.end()) {
            if (!it->second.has_value()) return false;
            value = it->second.value();
            return true;
        }
    }
    std::string v;
    bool found = db->Read(RawKey(key), v);
    std::lock_guard<std::mutex> lock(cs);
    CachePut(key, found ? std::optional<std::string>(v) : std::nullopt);
    if (found) value = v;
    return found;
}

void VaultDB::Iterate(const std::string& prefix, const std::function<bool(const std::string&, const std::string&)>& fn) const
{
    std::unique_ptr<CDBIterator> it(db->NewIterator());
    for (it->Seek(RawKey(prefix)); it->Valid(); it->Next()) {
        RawKey k;
        if (!it->GetKey(k)) break;
        if (k.s.compare(0, prefix.size(), prefix) != 0) break;
        std::string v;
        if (!it->GetValue(v)) break;
        if (!fn(k.s, v)) break;
    }
}

bool VaultDB::GetTip(uint256& hash, int64_t& height) const
{
    std::string v;
    if (!Read(TipKey(), v)) return false;
    try {
        CDataStream ss(v.data(), v.data() + v.size(), SER_DISK, PROTOCOL_VERSION);
        ss >> hash >> height;
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

bool VaultDB::ReadUndo(const uint256& hash, BlockUndo& undo) const
{
    std::string v;
    if (!db->Read(RawKey(UndoKey(hash)), v)) return false;
    try {
        CDataStream ss(v.data(), v.data() + v.size(), SER_DISK, PROTOCOL_VERSION);
        ss >> undo;
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

bool VaultDB::ConnectBlock(const uint256& hash, int64_t height, const uint256& prevHash, const VaultState& state, const BlockUndo& undo)
{
    uint256 tipHash;
    int64_t tipHeight;
    if (GetTip(tipHash, tipHeight) && tipHash != prevHash) {
        LogPrint("vault", "vault: refusing to connect %s at %d: tip is %s, not its parent %s\n",
                 hash.GetHex(), height, tipHash.GetHex(), prevHash.GetHex());
        return false;
    }
    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << undo;
    const std::string undoValue(ss.begin(), ss.end());
    const std::string tipValue = EncodeTip(hash, height);

    CDBBatch batch(*db);
    for (const auto& kv : state.Changes()) {
        if (kv.second.has_value()) batch.Write(RawKey(kv.first), kv.second.value());
        else batch.Erase(RawKey(kv.first));
    }
    batch.Write(RawKey(UndoKey(hash)), undoValue);
    batch.Write(RawKey(TipKey()), tipValue);

    std::lock_guard<std::mutex> lock(cs);
    if (!db->WriteBatch(batch, false)) {
        cache.clear();
        return LogError("vault", "vault: database write failed connecting %s\n", hash.GetHex());
    }
    for (const auto& kv : state.Changes()) CachePut(kv.first, kv.second);
    CachePut(TipKey(), tipValue);
    return true;
}

bool VaultDB::DisconnectBlock(const uint256& hash, const uint256& prevHash, int64_t prevHeight)
{
    uint256 tipHash;
    int64_t tipHeight;
    if (!GetTip(tipHash, tipHeight) || tipHash != hash) {
        LogPrint("vault", "vault: refusing to disconnect %s: not the tip\n", hash.GetHex());
        return false;
    }
    BlockUndo undo;
    if (!ReadUndo(hash, undo)) {
        return LogError("vault", "vault: missing undo for %s\n", hash.GetHex());
    }
    const std::string tipValue = EncodeTip(prevHash, prevHeight);
    CDBBatch batch(*db);
    for (const auto& e : undo.entries) {
        if (e.second.has_value()) batch.Write(RawKey(e.first), e.second.value());
        else batch.Erase(RawKey(e.first));
    }
    batch.Erase(RawKey(UndoKey(hash)));
    batch.Write(RawKey(TipKey()), tipValue);

    std::lock_guard<std::mutex> lock(cs);
    if (!db->WriteBatch(batch, false)) {
        cache.clear();
        return LogError("vault", "vault: database write failed disconnecting %s\n", hash.GetHex());
    }
    for (const auto& e : undo.entries) CachePut(e.first, e.second);
    CachePut(TipKey(), tipValue);
    return true;
}

bool VaultDB::Flush()
{
    return db->Sync();
}

bool VaultDB::Wipe()
{
    std::lock_guard<std::mutex> lock(cs);
    cache.clear();
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

} // namespace vault
