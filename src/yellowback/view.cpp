// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "yellowback/view.h"

#include "clientversion.h"
#include "crypto/sha256.h"
#include "streams.h"

#include <algorithm>

namespace yellowback {

// ---------------------------------------------------------------------------
// MemoryStateView

bool MemoryStateView::Read(const std::string& key, std::string& value) const
{
    auto it = map.find(key);
    if (it == map.end()) return false;
    value = it->second;
    return true;
}

void MemoryStateView::Write(const std::string& key, const std::string& value) { map[key] = value; }
void MemoryStateView::Erase(const std::string& key) { map.erase(key); }

void MemoryStateView::Iterate(const std::string& prefix, const std::function<bool(const std::string&, const std::string&)>& fn) const
{
    for (auto it = map.lower_bound(prefix); it != map.end(); ++it) {
        if (it->first.compare(0, prefix.size(), prefix) != 0) break;
        if (!fn(it->first, it->second)) break;
    }
}

// ---------------------------------------------------------------------------
// OverlayStateView

bool OverlayStateView::Read(const std::string& key, std::string& value) const
{
    auto it = pending.find(key);
    if (it != pending.end()) {
        if (!it->second.has_value()) return false;
        value = it->second.value();
        return true;
    }
    return base.Read(key, value);
}

void OverlayStateView::Write(const std::string& key, const std::string& value) { pending[key] = value; }
void OverlayStateView::Erase(const std::string& key) { pending[key] = std::nullopt; }

void OverlayStateView::Iterate(const std::string& prefix, const std::function<bool(const std::string&, const std::string&)>& fn) const
{
    // Merge the base's keys with the pending overrides, in key order.
    std::map<std::string, std::string> merged;
    base.Iterate(prefix, [&](const std::string& k, const std::string& v) { merged[k] = v; return true; });
    for (auto it = pending.lower_bound(prefix); it != pending.end(); ++it) {
        if (it->first.compare(0, prefix.size(), prefix) != 0) break;
        if (it->second.has_value()) merged[it->first] = it->second.value();
        else merged.erase(it->first);
    }
    for (const auto& kv : merged) {
        if (!fn(kv.first, kv.second)) break;
    }
}

void OverlayStateView::Commit()
{
    for (const auto& kv : pending) {
        if (kv.second.has_value()) base.Write(kv.first, kv.second.value());
        else base.Erase(kv.first);
    }
    pending.clear();
}

// ---------------------------------------------------------------------------
// Keys

namespace keys {

const char PREFIX_UNDO = 'U';
const char PREFIX_REJECTED = 'X';
const char PREFIX_TXLOG = 'L';
const char PREFIX_ATTESTOR = 'A';
const char PREFIX_BUNDLELOG = 'W';
const char PREFIX_NOTICE = 'E';

static std::string U32BE(uint32_t v)
{
    std::string s(4, '\0');
    s[0] = (char)((v >> 24) & 0xff);
    s[1] = (char)((v >> 16) & 0xff);
    s[2] = (char)((v >> 8) & 0xff);
    s[3] = (char)(v & 0xff);
    return s;
}

static std::string OutPointKey(char prefix, const COutPoint& out)
{
    std::string s(1, prefix);
    s.append((const char*)out.hash.begin(), 32);
    s.append(U32BE(out.n));
    return s;
}

static std::string HashKey(char prefix, const uint256& hash)
{
    return std::string(1, prefix) + std::string((const char*)hash.begin(), 32);
}

std::string Tip() { return "T"; }
std::string Tag(uint32_t height) { return "Q" + U32BE(height); }
std::string Judgement(uint32_t height) { return "J" + U32BE(height); }
std::string Activation() { return "C"; }
std::string Vault(const COutPoint& out) { return OutPointKey('V', out); }
std::string Token(const COutPoint& out) { return OutPointKey('K', out); }
std::string TxLog(const uint256& txid) { return HashKey(PREFIX_TXLOG, txid); }
std::string Snapshot(uint32_t height) { return "S" + U32BE(height); }
std::string Totals() { return "G"; }
std::string Rejected(const uint256& blockHash) { return HashKey(PREFIX_REJECTED, blockHash); }
std::string Params() { return "P"; }
std::string Undo(const uint256& blockHash) { return HashKey(PREFIX_UNDO, blockHash); }
std::string Attestor(uint16_t seq)
{
    std::string s(1, PREFIX_ATTESTOR);
    s.push_back((char)((seq >> 8) & 0xff));
    s.push_back((char)(seq & 0xff));
    return s;
}
std::string BondIndex(const COutPoint& out) { return OutPointKey('B', out); }
std::string AttestorSeq() { return "N"; }
std::string Attest() { return "M"; }
std::string BundleLog(uint32_t height) { return std::string(1, PREFIX_BUNDLELOG) + U32BE(height); }
std::string Notice(const COutPoint& out) { return OutPointKey(PREFIX_NOTICE, out); }

uint16_t SeqOf(const std::string& key)
{
    if (key.size() < 3) return 0;
    return (uint16_t)(((uint16_t)(unsigned char)key[1] << 8) | (uint16_t)(unsigned char)key[2]);
}

uint32_t HeightOf(const std::string& key)
{
    if (key.size() < 5) return 0;
    return ((uint32_t)(unsigned char)key[1] << 24) | ((uint32_t)(unsigned char)key[2] << 16) |
           ((uint32_t)(unsigned char)key[3] << 8) | (uint32_t)(unsigned char)key[4];
}

uint256 OutPointHashOf(const std::string& key)
{
    if (key.size() < 33) return uint256();
    return uint256(std::vector<unsigned char>(key.begin() + 1, key.begin() + 33));
}

uint32_t OutPointIndexOf(const std::string& key)
{
    if (key.size() < 37) return 0;
    return ((uint32_t)(unsigned char)key[33] << 24) | ((uint32_t)(unsigned char)key[34] << 16) |
           ((uint32_t)(unsigned char)key[35] << 8) | (uint32_t)(unsigned char)key[36];
}

} // namespace keys

// ---------------------------------------------------------------------------
// Serialization

template <typename T>
std::string SerializeRecord(const T& t)
{
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << t;
    return ss.str();
}

template <typename T>
bool DeserializeRecord(const std::string& s, T& t)
{
    try {
        CDataStream ss(s.data(), s.data() + s.size(), SER_DISK, CLIENT_VERSION);
        ss >> t;
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

// Explicit instantiations for every record type.
#define YB_RECORD(T) \
    template std::string SerializeRecord<T>(const T&); \
    template bool DeserializeRecord<T>(const std::string&, T&);
YB_RECORD(TipRecord)
YB_RECORD(TagRecord)
YB_RECORD(Judgement)
YB_RECORD(Activation)
YB_RECORD(VaultRecord)
YB_RECORD(TokenRecord)
YB_RECORD(TxLogRecord)
YB_RECORD(Totals)
YB_RECORD(Snapshot)
YB_RECORD(RejectedRecord)
YB_RECORD(ParamsRecord)
YB_RECORD(UndoRecord)
YB_RECORD(AttestorRecord)
YB_RECORD(BondIndexRecord)
YB_RECORD(AttestorSeqRecord)
YB_RECORD(AttestState)
YB_RECORD(BundleLogRecord)
YB_RECORD(NoticeRecord)
#undef YB_RECORD

const char* ActivationStatusName(ActivationStatus s)
{
    switch (s) {
    case ActivationStatus::SIGNALING: return "SIGNALING";
    case ActivationStatus::LOCKED_IN: return "LOCKED_IN";
    case ActivationStatus::ACTIVE: return "ACTIVE";
    }
    return "UNKNOWN";
}

const char* VaultStatusName(VaultStatus s)
{
    switch (s) {
    case VaultStatus::ACTIVE: return "ACTIVE";
    case VaultStatus::VOID: return "VOID";
    case VaultStatus::CLOSED: return "CLOSED";
    case VaultStatus::CLAIMED: return "CLAIMED";
    }
    return "UNKNOWN";
}

const char* TxLogTypeName(TxLogType t)
{
    switch (t) {
    case TxLogType::NONE: return "NONE";
    case TxLogType::MINT: return "MINT";
    case TxLogType::TRANSFER: return "TRANSFER";
    case TxLogType::REDEEM: return "REDEEM";
    case TxLogType::ATTESTOR_REGISTER: return "ATTESTOR_REGISTER";
    case TxLogType::CLAIM_NOTICE: return "CLAIM_NOTICE";
    case TxLogType::EQUIVOCATION: return "EQUIVOCATION";
    case TxLogType::ATTESTOR_REVIVE: return "ATTESTOR_REVIVE";
    }
    return "UNKNOWN";
}

const char* AttestorStatusName(AttestorStatus s)
{
    switch (s) {
    case AttestorStatus::PENDING: return "PENDING";
    case AttestorStatus::ELIGIBLE: return "ELIGIBLE";
    case AttestorStatus::DORMANT: return "DORMANT";
    case AttestorStatus::EJECTED: return "EJECTED";
    case AttestorStatus::WITHDRAWN: return "WITHDRAWN";
    }
    return "UNKNOWN";
}

const char* AttestStatusName(AttestStatus s)
{
    switch (s) {
    case AttestStatus::UNARMED: return "UNARMED";
    case AttestStatus::TRIGGERED: return "TRIGGERED";
    case AttestStatus::ARMED: return "ARMED";
    }
    return "UNKNOWN";
}

std::vector<std::string> HaltMaskNames(uint32_t mask)
{
    static const std::pair<uint32_t, const char*> names[] = {
        { HALT_NOT_ACTIVE, "NOT_ACTIVE" }, { HALT_NO_PRICE, "NO_PRICE" }, { HALT_PARTICIPATION, "PARTICIPATION" },
        { HALT_GLOBAL_RATIO, "GLOBAL_RATIO" }, { HALT_DIVERGENCE, "DIVERGENCE" }, { HALT_ENFORCEMENT, "ENFORCEMENT" },
    };
    std::vector<std::string> out;
    for (const auto& n : names) {
        if (mask & n.first) out.push_back(n.second);
    }
    return out;
}

// ---------------------------------------------------------------------------
// State

void State::RecordUndo(const std::string& key)
{
    if (!undo) return;
    for (const UndoEntry& e : undo->entries) {
        if (e.key == key) return; // first pre-image wins
    }
    UndoEntry e;
    e.key = key;
    e.hadValue = view.Read(key, e.value);
    undo->entries.push_back(e);
}

void State::WriteRaw(const std::string& key, const std::string& value)
{
    RecordUndo(key);
    view.Write(key, value);
}

void State::EraseKey(const std::string& key)
{
    RecordUndo(key);
    view.Erase(key);
}

std::optional<TipRecord> State::GetTip() const
{
    TipRecord t;
    if (!Get(keys::Tip(), t)) return std::nullopt;
    return t;
}

std::optional<TagRecord> State::GetTag(uint32_t height) const
{
    TagRecord t;
    if (!Get(keys::Tag(height), t)) return std::nullopt;
    return t;
}

std::optional<Judgement> State::GetJudgement(uint32_t height) const
{
    Judgement j;
    if (!Get(keys::Judgement(height), j)) return std::nullopt;
    return j;
}

Activation State::GetActivation() const
{
    Activation a;
    if (!Get(keys::Activation(), a)) return Activation();
    return a;
}

std::optional<VaultRecord> State::GetVault(const COutPoint& out) const
{
    VaultRecord v;
    if (!Get(keys::Vault(out), v)) return std::nullopt;
    return v;
}

std::optional<TokenRecord> State::GetToken(const COutPoint& out) const
{
    TokenRecord t;
    if (!Get(keys::Token(out), t)) return std::nullopt;
    return t;
}

std::optional<TxLogRecord> State::GetTxLog(const uint256& txid) const
{
    TxLogRecord l;
    if (!Get(keys::TxLog(txid), l)) return std::nullopt;
    return l;
}

std::optional<Snapshot> State::GetSnapshot(uint32_t height) const
{
    Snapshot s;
    if (!Get(keys::Snapshot(height), s)) return std::nullopt;
    return s;
}

Totals State::GetTotals() const
{
    Totals t;
    if (!Get(keys::Totals(), t)) return Totals();
    return t;
}

std::optional<RejectedRecord> State::GetRejected(const uint256& blockHash) const
{
    RejectedRecord r;
    if (!Get(keys::Rejected(blockHash), r)) return std::nullopt;
    return r;
}

std::optional<ParamsRecord> State::GetParamsRecord() const
{
    ParamsRecord p;
    if (!Get(keys::Params(), p)) return std::nullopt;
    return p;
}

std::optional<AttestorRecord> State::GetAttestor(uint16_t seq) const
{
    AttestorRecord a;
    if (!Get(keys::Attestor(seq), a)) return std::nullopt;
    return a;
}

std::optional<uint16_t> State::GetBondIndex(const COutPoint& out) const
{
    BondIndexRecord b;
    if (!Get(keys::BondIndex(out), b)) return std::nullopt;
    return b.seq;
}

AttestorSeqRecord State::GetAttestorSeq() const
{
    AttestorSeqRecord n;
    if (!Get(keys::AttestorSeq(), n)) return AttestorSeqRecord();
    return n;
}

AttestState State::GetAttest() const
{
    AttestState a;
    if (!Get(keys::Attest(), a)) return AttestState();
    return a;
}

std::optional<BundleLogRecord> State::GetBundleLog(uint32_t height) const
{
    BundleLogRecord b;
    if (!Get(keys::BundleLog(height), b)) return std::nullopt;
    return b;
}

std::optional<NoticeRecord> State::GetNotice(const COutPoint& out) const
{
    NoticeRecord n;
    if (!Get(keys::Notice(out), n)) return std::nullopt;
    return n;
}

std::vector<std::pair<uint16_t, AttestorRecord>> State::Attestors() const
{
    std::vector<std::pair<uint16_t, AttestorRecord>> out;
    view.Iterate(std::string(1, keys::PREFIX_ATTESTOR), [&](const std::string& k, const std::string& raw) {
        AttestorRecord a;
        if (k.size() == 3 && DeserializeRecord(raw, a)) out.push_back(std::make_pair(keys::SeqOf(k), a));
        return true;
    });
    return out;
}

uint256 StateHash(const StateView& view, const std::string& network)
{
    CSHA256 hasher;
    auto feed = [&](const std::string& k, const std::string& v) {
        hasher.Write((const unsigned char*)k.data(), k.size());
        hasher.Write((const unsigned char*)v.data(), v.size());
    };
    // Tip first; a zero tip when nothing has been applied yet.
    {
        std::string raw;
        if (!view.Read(keys::Tip(), raw)) {
            TipRecord t;
            t.network = network;
            raw = SerializeRecord(t);
        }
        feed(keys::Tip(), raw);
    }
    // Then the tables in the §3.6 order; each Iterate visits its keys in ascending order,
    // which is ascending height (big-endian keys) or ascending outpoint.
    // v3 appends Attestors (A), AttestorSeq (N), Attest (M), BundleLog (W) and Notices (E); BondIndex (B) is derived.
    for (const char* prefix : { "Q", "J", "C", "V", "K", "G", "S", "P", "A", "N", "M", "W", "E" }) {
        view.Iterate(prefix, [&](const std::string& k, const std::string& v) {
            feed(k, v);
            return true;
        });
    }
    // uint256::GetHex() renders bytes reversed; store the digest reversed so the hex the RPC
    // prints (and the pinned golden hex) is the natural SHA-256 digest order the Python model uses.
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(digest);
    std::vector<unsigned char> reversed(digest, digest + CSHA256::OUTPUT_SIZE);
    std::reverse(reversed.begin(), reversed.end());
    return uint256(reversed);
}

} // namespace yellowback
