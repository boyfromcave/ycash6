// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_VAULT_STATE_H
#define YCASH_VAULT_STATE_H

#include "amount.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "serialize.h"
#include "vault/act.h"
#include "vault/module.h"
#include "vault/template.h"

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

class CBlock;
class CBlockIndex;

/**
 * Signer-set state (docs/plans/yellowback-upgrade-plan.md §15.4) and the rules that move it
 * (§15.5 acts, §15.6 template rules, U-16..U-20).
 *
 * Storage is a byte-ordered key/value space (KVReader): the LevelDB at <datadir>/vaults/
 * (vault/db.h) in the node, MemoryKV in tests. VaultState is a write overlay on such a base:
 * it applies transactions sequentially (U-17) and its Changes() are what a block commits;
 * MakeUndo() records the base's prior value of every changed key, so disconnecting a block
 * restores the state byte for byte. SetSnapshot is the read-only view script evaluation uses
 * (the state after the parent block, U-17).
 *
 * Keys: 's'||setId(32) → SetRecord; 'm'||setId(32)||memberKey(33) → MemberRecord;
 *       'b'||txid(32)||n(u32 LE) → BondRecord (every member bond not yet spent);
 *       'v'||txid(32)||n(u32 LE) → TemplateOutRecord (every unspent V / I output created
 *       from activation: the vault_list index, and the creation height of an intent, which
 *       block undo data does not always carry, for replay on start).
 * Deterministic, integer only; amounts are MoneyRange-checked.
 */
namespace vault {

enum MemberStatus : uint8_t {
    MEMBER_ACTIVE = 0,
    MEMBER_REMOVED = 1,
    MEMBER_EJECTED = 2,
    MEMBER_WITHDRAWN = 3,
};

struct SetRecord
{
    SetCreateBody params;
    int64_t createHeight = 0;
    int64_t windDownHeight = 0; // 0 = none
    CAmount lockedValue = 0;
    int64_t epoch = 0;
    CAmount epochBasis = 0;
    CAmount epochUsed = 0;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(params.seats);
        READWRITE(params.unlockThreshold);
        READWRITE(params.cancelThreshold);
        READWRITE(params.slashThreshold);
        READWRITE(params.flags);
        READWRITE(params.rateLimitBps);
        READWRITE(params.rateWindow);
        READWRITE(params.livenessWindow);
        READWRITE(params.bondMin);
        READWRITE(params.bondLockMin);
        READWRITE(params.maturity);
        READWRITE(params.admitKey);
        READWRITE(createHeight);
        READWRITE(windDownHeight);
        READWRITE(lockedValue);
        READWRITE(epoch);
        READWRITE(epochBasis);
        READWRITE(epochUsed);
    }
};

struct MemberRecord
{
    COutPoint bondOutpoint;
    CAmount bondValue = 0;
    uint32_t bondLocktime = 0;
    int64_t joinHeight = 0;
    int64_t lastAct = 0; // starts at joinHeight + maturity
    uint8_t status = MEMBER_ACTIVE;
    bool bondFrozen = false;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(bondOutpoint);
        READWRITE(bondValue);
        READWRITE(bondLocktime);
        READWRITE(joinHeight);
        READWRITE(lastAct);
        READWRITE(status);
        READWRITE(bondFrozen);
    }
};

/** The bond index: outpoint → its member (the frozen-bond index of §15.4, extended to every
 *  unspent member bond so that a spend can mark the member WITHDRAWN). */
struct BondRecord
{
    SetId setId;
    CPubKey memberKey;
    bool frozen = false;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(setId);
        READWRITE(memberKey);
        READWRITE(frozen);
    }
};

/** An unspent V or I output created from activation (key 'v'). `origin` is the
 *  scriptPubKey of the V an intent was unlocked from (its vaultHash preimage, which a
 *  cancel must recreate); empty for a V. Not consensus input except `height` (I-2). */
struct TemplateOutRecord
{
    uint8_t kind = 0; // 0 = V, 1 = I
    int64_t height = 0;
    CAmount value = 0;
    CScript scriptPubKey;
    CScript origin;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(kind);
        READWRITE(height);
        READWRITE(value);
        READWRITE(*(CScriptBase*)(&scriptPubKey));
        READWRITE(*(CScriptBase*)(&origin));
    }
};

typedef std::vector<std::pair<CPubKey, MemberRecord>> MemberList;

std::string KeySet(const SetId& setId);
std::string KeyMember(const SetId& setId, const CPubKey& key);
std::string KeyMemberPrefix(const SetId& setId);
std::string KeyBond(const COutPoint& outpoint);
std::string KeyTemplateOut(const COutPoint& outpoint);
static const char KEY_SET = 's';
static const char KEY_MEMBER = 'm';
static const char KEY_BOND = 'b';
static const char KEY_TEMPLATE_OUT = 'v';

/** Read-only, byte-ordered key/value space. Implementations must be safe for concurrent reads. */
class KVReader
{
public:
    virtual ~KVReader() {}
    virtual bool Read(const std::string& key, std::string& value) const = 0;
    /** Calls fn(key, value) for every key with this prefix in byte order until fn returns false. */
    virtual void Iterate(const std::string& prefix, const std::function<bool(const std::string&, const std::string&)>& fn) const = 0;
};

/** An in-memory KVReader (tests, and a base for throwaway computations). */
class MemoryKV : public KVReader
{
public:
    std::map<std::string, std::string> data;
    bool Read(const std::string& key, std::string& value) const override;
    void Iterate(const std::string& prefix, const std::function<bool(const std::string&, const std::string&)>& fn) const override;
    void Apply(const std::map<std::string, std::optional<std::string>>& changes);
};

/** Typed reads. A record that fails to deserialize reads as absent. */
std::optional<SetRecord> GetSet(const KVReader& kv, const SetId& setId);
std::optional<MemberRecord> GetMember(const KVReader& kv, const SetId& setId, const CPubKey& key);
MemberList GetMembers(const KVReader& kv, const SetId& setId);
std::optional<BondRecord> GetBond(const KVReader& kv, const COutPoint& outpoint);
std::optional<TemplateOutRecord> GetTemplateOut(const KVReader& kv, const COutPoint& outpoint);
/** Every unspent template output in the index, in key (outpoint) order. */
std::vector<std::pair<COutPoint, TemplateOutRecord>> ListTemplateOuts(const KVReader& kv);
/** Every set id, in key order. */
std::vector<SetId> ListSets(const KVReader& kv);

/** §15.4 predicates over one set's records. */
bool IsCurrent(const SetRecord& s, const MemberRecord& m, int64_t h);
int CountCurrent(const SetRecord& s, const MemberList& members, int64_t h);
int CountActive(const MemberList& members);
bool IsDormant(const SetRecord& s, const MemberList& members, int64_t h);
bool IsReleased(const std::optional<SetRecord>& s, const MemberList& members, int64_t h);
/** floor(basis × bps / 10000) without overflow. */
CAmount RateCap(CAmount basis, uint16_t bps);

/**
 * Immutable view for script evaluation: the state after the parent block, queried at the
 * spending height. Reads go through to `base` and are memoised per set (thread-safe), so
 * the base must not change while the snapshot is in use (the caller holds cs_main across
 * the block's script checks, and the vault DB commits only after them).
 */
class SetSnapshot
{
public:
    explicit SetSnapshot(const KVReader& base) : base(base) {}

    std::optional<SetRecord> GetSet(const SetId& setId) const;
    MemberList GetMembers(const SetId& setId) const;
    bool IsCurrentMember(const SetId& setId, const CPubKey& key, int64_t h) const;
    /** role 1 → unlockThreshold, 2 → cancelThreshold; nullopt for an unknown set or role. */
    std::optional<int> Threshold(const SetId& setId, uint8_t role) const;
    /** False for an unknown set (IsReleased covers it). */
    bool IsDormant(const SetId& setId, int64_t h) const;
    /** Dormant, or wound down for livenessWindow blocks, or unknown (§15.4). */
    bool IsReleased(const SetId& setId, int64_t h) const;
    /** §15.2 steps 2, 3, 5: exactly Threshold(role) 65-byte low-S recoverable signatures over
     *  msg, recovering to distinct current members at h. */
    bool CheckSetSigs(const SetId& setId, uint8_t role, const uint256& msg,
                      const std::vector<std::vector<unsigned char>>& sigs, int64_t h) const;

    const KVReader& Base() const { return base; }

private:
    struct Entry {
        std::optional<SetRecord> rec;
        MemberList members;
    };
    std::shared_ptr<const Entry> Load(const SetId& setId) const;

    const KVReader& base;
    mutable std::mutex cs;
    mutable std::map<SetId, std::shared_ptr<const Entry>> cache;
};

/** The coin an input spends (from the coins view, or from the block's undo data). */
struct SpentCoin
{
    CScript scriptPubKey;
    CAmount value = 0;
    int64_t height = 0;
};

class CoinAccessor
{
public:
    virtual ~CoinAccessor() {}
    /** The coin spent by `prevout`; false if unknown (the transaction is then rejected). */
    virtual bool GetSpentCoin(const COutPoint& prevout, SpentCoin& out) const = 0;
};

/** A map-backed CoinAccessor (tests, the miner's running copy). */
class MapCoinAccessor : public CoinAccessor
{
public:
    std::map<COutPoint, SpentCoin> coins;
    bool GetSpentCoin(const COutPoint& prevout, SpentCoin& out) const override;
};

/** Per-block undo: the base's value of every key the block changed, before the block. */
struct BlockUndo
{
    std::vector<std::pair<std::string, std::optional<std::string>>> entries;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        WriteCompactSize(s, entries.size());
        for (const auto& e : entries) {
            ::Serialize(s, e.first);
            ::Serialize(s, (uint8_t)(e.second.has_value() ? 1 : 0));
            if (e.second.has_value()) ::Serialize(s, e.second.value());
        }
    }
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        entries.clear();
        uint64_t n = ReadCompactSize(s);
        for (uint64_t i = 0; i < n; i++) {
            std::string k;
            uint8_t has = 0;
            ::Unserialize(s, k);
            ::Unserialize(s, has);
            if (has) {
                std::string v;
                ::Unserialize(s, v);
                entries.emplace_back(k, v);
            } else {
                entries.emplace_back(k, std::nullopt);
            }
        }
    }
};

/**
 * A write overlay on a KVReader that applies transactions in block order. Use one
 * VaultState per block (ApplyBlock), or as the miner's running copy over the tip (ApplyTx
 * per candidate, skipping a transaction that fails). Rules apply only where the caller has
 * established that UPGRADE_VAULT is active at `height`.
 */
class VaultState : public KVReader
{
public:
    explicit VaultState(const KVReader& base) : base(base) {}

    bool Read(const std::string& key, std::string& value) const override;
    void Iterate(const std::string& prefix, const std::function<bool(const std::string&, const std::string&)>& fn) const override;

    /** Apply one transaction (§15.5 acts, §15.6 rules, bond spends) at `height`. nullopt on
     *  success; on failure a reject reason and no change to this state. */
    std::optional<std::string> ApplyTx(const CTransaction& tx, int64_t height, const CoinAccessor& coins);

    /** Apply every transaction of the block in order, then each registered module's
     *  CheckBlock. On success `undo` receives MakeUndo(). On failure the state must be
     *  discarded. `pindex` may be null (it is passed through to modules only). */
    std::optional<std::string> ApplyBlock(const CBlock& block, int64_t height, const CoinAccessor& coins,
                                          BlockUndo& undo, const CBlockIndex* pindex = nullptr);

    /** The base's prior value of every key changed in this overlay. */
    BlockUndo MakeUndo() const;
    /** Stage an undo record: every key back to its recorded value. */
    void ApplyUndo(const BlockUndo& undo);

    const std::map<std::string, std::optional<std::string>>& Changes() const { return changes; }
    void Clear() { changes.clear(); }

    /** Ancestor block hashes for the module ejection hook (U-25): the block's own ancestors in
     *  ConnectBlock and replay, the tip's in the mempool and the miner. Unset, no module that
     *  needs a block hash finds anything to eject. */
    void SetBlockHashes(const BlockHashFn& fn) { blockHashes = fn; }

    /** The module ejection hook (U-25) for one module: what ApplyTx runs, after the
     *  transaction's own rules and act, for each registered module. Public so a unit test can
     *  drive the hook with a module that is not in the compile-time table. */
    void ApplyEjectionsOf(const Module& module, const CTransaction& tx, int64_t height);

    void Put(const std::string& key, const std::string& value) { changes[key] = value; }
    void Erase(const std::string& key) { changes[key] = std::nullopt; }

    template <typename T>
    void PutRecord(const std::string& key, const T& rec);

private:
    std::optional<std::string> ApplyTxInner(const CTransaction& tx, int64_t height, const CoinAccessor& coins);
    std::optional<std::string> ApplyAct(const CTransaction& tx, const Act& act, int64_t height);
    void MergeFrom(const VaultState& child);
    void ApplyEjections(const CTransaction& tx, int64_t height);

    const KVReader& base;
    std::map<std::string, std::optional<std::string>> changes;
    BlockHashFn blockHashes;
};

/** Mempool check: would `tx` apply at `height` (tip+1) over the snapshot's base? */
std::optional<std::string> CheckTx(const CTransaction& tx, const CoinAccessor& coins, int64_t height, const SetSnapshot& snapshot,
                                   const BlockHashFn& blockHashes = BlockHashFn());

/** Eject a member and freeze its bond (SET_EQUIVOCATION's effect, §15.5; the module ejection
 *  hook's, U-25): only a member of `setId` whose bond is unspent (indexed) and not frozen.
 *  Returns false (and changes nothing) otherwise. */
bool EjectAndFreeze(VaultState& st, const SetId& setId, const CPubKey& key);

} // namespace vault

#endif // YCASH_VAULT_STATE_H
