// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "vault/state.h"

#include "primitives/block.h"
#include "streams.h"
#include "vault/module.h"
#include "version.h"

#include <set>

namespace vault {

typedef std::vector<unsigned char> valtype;

// ---- keys -------------------------------------------------------------------

std::string KeySet(const SetId& setId)
{
    std::string k(1, KEY_SET);
    k.append((const char*)setId.begin(), 32);
    return k;
}

std::string KeyMemberPrefix(const SetId& setId)
{
    std::string k(1, KEY_MEMBER);
    k.append((const char*)setId.begin(), 32);
    return k;
}

std::string KeyMember(const SetId& setId, const CPubKey& key)
{
    std::string k = KeyMemberPrefix(setId);
    k.append((const char*)key.begin(), key.size());
    return k;
}

std::string KeyBond(const COutPoint& outpoint)
{
    std::string k(1, KEY_BOND);
    k.append((const char*)outpoint.hash.begin(), 32);
    for (int i = 0; i < 4; i++) k.push_back((char)((outpoint.n >> (8 * i)) & 0xff));
    return k;
}

std::string KeyTemplateOut(const COutPoint& outpoint)
{
    std::string k = KeyBond(outpoint);
    k[0] = KEY_TEMPLATE_OUT;
    return k;
}

namespace {

template <typename T>
std::string SerializeRecord(const T& rec)
{
    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << rec;
    return std::string(ss.begin(), ss.end());
}

template <typename T>
bool DeserializeRecord(const std::string& value, T& rec)
{
    try {
        CDataStream ss(value.data(), value.data() + value.size(), SER_DISK, PROTOCOL_VERSION);
        ss >> rec;
        return ss.empty();
    } catch (const std::exception&) {
        return false;
    }
}

template <typename T>
std::optional<T> ReadRecord(const KVReader& kv, const std::string& key)
{
    std::string v;
    if (!kv.Read(key, v)) return std::nullopt;
    T rec;
    if (!DeserializeRecord(v, rec)) return std::nullopt;
    return rec;
}

} // namespace

template <typename T>
void VaultState::PutRecord(const std::string& key, const T& rec)
{
    Put(key, SerializeRecord(rec));
}

// ---- MemoryKV ---------------------------------------------------------------

bool MemoryKV::Read(const std::string& key, std::string& value) const
{
    auto it = data.find(key);
    if (it == data.end()) return false;
    value = it->second;
    return true;
}

void MemoryKV::Iterate(const std::string& prefix, const std::function<bool(const std::string&, const std::string&)>& fn) const
{
    for (auto it = data.lower_bound(prefix); it != data.end(); ++it) {
        if (it->first.compare(0, prefix.size(), prefix) != 0) break;
        if (!fn(it->first, it->second)) break;
    }
}

void MemoryKV::Apply(const std::map<std::string, std::optional<std::string>>& changes)
{
    for (const auto& kv : changes) {
        if (kv.second.has_value()) data[kv.first] = kv.second.value();
        else data.erase(kv.first);
    }
}

// ---- typed reads ------------------------------------------------------------

std::optional<SetRecord> GetSet(const KVReader& kv, const SetId& setId)
{
    return ReadRecord<SetRecord>(kv, KeySet(setId));
}

std::optional<MemberRecord> GetMember(const KVReader& kv, const SetId& setId, const CPubKey& key)
{
    if (key.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE) return std::nullopt;
    return ReadRecord<MemberRecord>(kv, KeyMember(setId, key));
}

MemberList GetMembers(const KVReader& kv, const SetId& setId)
{
    MemberList out;
    const std::string prefix = KeyMemberPrefix(setId);
    kv.Iterate(prefix, [&](const std::string& k, const std::string& v) {
        if (k.size() != prefix.size() + 33) return true;
        MemberRecord m;
        if (!DeserializeRecord(v, m)) return true;
        const unsigned char* p = (const unsigned char*)k.data() + prefix.size();
        out.emplace_back(CPubKey(p, p + 33), m);
        return true;
    });
    return out;
}

std::optional<BondRecord> GetBond(const KVReader& kv, const COutPoint& outpoint)
{
    return ReadRecord<BondRecord>(kv, KeyBond(outpoint));
}

std::optional<TemplateOutRecord> GetTemplateOut(const KVReader& kv, const COutPoint& outpoint)
{
    return ReadRecord<TemplateOutRecord>(kv, KeyTemplateOut(outpoint));
}

std::vector<std::pair<COutPoint, TemplateOutRecord>> ListTemplateOuts(const KVReader& kv)
{
    std::vector<std::pair<COutPoint, TemplateOutRecord>> out;
    kv.Iterate(std::string(1, KEY_TEMPLATE_OUT), [&](const std::string& k, const std::string& v) {
        if (k.size() != 37) return true;
        TemplateOutRecord rec;
        if (!DeserializeRecord(v, rec)) return true;
        COutPoint op;
        std::copy(k.begin() + 1, k.begin() + 33, op.hash.begin());
        op.n = 0;
        for (int i = 0; i < 4; i++) op.n |= (uint32_t)(unsigned char)k[33 + i] << (8 * i);
        out.emplace_back(op, rec);
        return true;
    });
    return out;
}

std::vector<SetId> ListSets(const KVReader& kv)
{
    std::vector<SetId> out;
    kv.Iterate(std::string(1, KEY_SET), [&](const std::string& k, const std::string&) {
        if (k.size() == 33) {
            SetId id;
            std::copy(k.begin() + 1, k.end(), id.begin());
            out.push_back(id);
        }
        return true;
    });
    return out;
}

// ---- §15.4 predicates -------------------------------------------------------

bool IsCurrent(const SetRecord& s, const MemberRecord& m, int64_t h)
{
    return m.status == MEMBER_ACTIVE && h >= m.joinHeight + (int64_t)s.params.maturity;
}

int CountCurrent(const SetRecord& s, const MemberList& members, int64_t h)
{
    int n = 0;
    for (const auto& m : members) n += IsCurrent(s, m.second, h) ? 1 : 0;
    return n;
}

int CountActive(const MemberList& members)
{
    int n = 0;
    for (const auto& m : members) n += m.second.status == MEMBER_ACTIVE ? 1 : 0;
    return n;
}

bool IsDormant(const SetRecord& s, const MemberList& members, int64_t h)
{
    const int64_t since = h - (int64_t)s.params.livenessWindow;
    int live = 0;
    for (const auto& m : members) {
        if (IsCurrent(s, m.second, h) && m.second.lastAct >= since) live++;
    }
    return live < (int)s.params.cancelThreshold;
}

bool IsReleased(const std::optional<SetRecord>& s, const MemberList& members, int64_t h)
{
    if (!s) return true;
    if (IsDormant(*s, members, h)) return true;
    return s->windDownHeight != 0 && h >= s->windDownHeight + (int64_t)s->params.livenessWindow;
}

CAmount RateCap(CAmount basis, uint16_t bps)
{
    if (basis <= 0) return 0;
    return (basis / 10000) * bps + ((basis % 10000) * bps) / 10000;
}

// ---- SetSnapshot ------------------------------------------------------------

std::shared_ptr<const SetSnapshot::Entry> SetSnapshot::Load(const SetId& setId) const
{
    {
        std::lock_guard<std::mutex> lock(cs);
        auto it = cache.find(setId);
        if (it != cache.end()) return it->second;
    }
    auto e = std::make_shared<Entry>();
    e->rec = vault::GetSet(base, setId);
    if (e->rec) e->members = vault::GetMembers(base, setId);
    std::lock_guard<std::mutex> lock(cs);
    auto ins = cache.emplace(setId, e);
    return ins.first->second;
}

std::optional<SetRecord> SetSnapshot::GetSet(const SetId& setId) const { return Load(setId)->rec; }
MemberList SetSnapshot::GetMembers(const SetId& setId) const { return Load(setId)->members; }

bool SetSnapshot::IsCurrentMember(const SetId& setId, const CPubKey& key, int64_t h) const
{
    auto e = Load(setId);
    if (!e->rec) return false;
    for (const auto& m : e->members) {
        if (m.first == key) return IsCurrent(*e->rec, m.second, h);
    }
    return false;
}

std::optional<int> SetSnapshot::Threshold(const SetId& setId, uint8_t role) const
{
    auto e = Load(setId);
    if (!e->rec) return std::nullopt;
    if (role == ROLE_UNLOCK) return (int)e->rec->params.unlockThreshold;
    if (role == ROLE_CANCEL) return (int)e->rec->params.cancelThreshold;
    return std::nullopt;
}

bool SetSnapshot::IsDormant(const SetId& setId, int64_t h) const
{
    auto e = Load(setId);
    if (!e->rec) return false;
    return vault::IsDormant(*e->rec, e->members, h);
}

bool SetSnapshot::IsReleased(const SetId& setId, int64_t h) const
{
    auto e = Load(setId);
    return vault::IsReleased(e->rec, e->members, h);
}

bool SetSnapshot::CheckSetSigs(const SetId& setId, uint8_t role, const uint256& msg,
                               const std::vector<std::vector<unsigned char>>& sigs, int64_t h) const
{
    auto k = Threshold(setId, role);
    if (!k || (size_t)*k != sigs.size()) return false;
    auto e = Load(setId);
    std::set<CPubKey> seen;
    for (const auto& sig : sigs) {
        CPubKey key;
        if (!RecoverSig(msg, sig, key)) return false;
        if (!seen.insert(key).second) return false;
        bool current = false;
        for (const auto& m : e->members) {
            if (m.first == key) { current = IsCurrent(*e->rec, m.second, h); break; }
        }
        if (!current) return false;
    }
    return true;
}

// ---- coins ------------------------------------------------------------------

bool MapCoinAccessor::GetSpentCoin(const COutPoint& prevout, SpentCoin& out) const
{
    auto it = coins.find(prevout);
    if (it == coins.end()) return false;
    out = it->second;
    return true;
}

// ---- VaultState -------------------------------------------------------------

bool VaultState::Read(const std::string& key, std::string& value) const
{
    auto it = changes.find(key);
    if (it != changes.end()) {
        if (!it->second.has_value()) return false;
        value = it->second.value();
        return true;
    }
    return base.Read(key, value);
}

void VaultState::Iterate(const std::string& prefix, const std::function<bool(const std::string&, const std::string&)>& fn) const
{
    std::map<std::string, std::string> merged;
    base.Iterate(prefix, [&](const std::string& k, const std::string& v) {
        merged[k] = v;
        return true;
    });
    for (auto it = changes.lower_bound(prefix); it != changes.end(); ++it) {
        if (it->first.compare(0, prefix.size(), prefix) != 0) break;
        if (it->second.has_value()) merged[it->first] = it->second.value();
        else merged.erase(it->first);
    }
    for (const auto& kv : merged) {
        if (!fn(kv.first, kv.second)) break;
    }
}

void VaultState::MergeFrom(const VaultState& child)
{
    for (const auto& kv : child.changes) changes[kv.first] = kv.second;
}

BlockUndo VaultState::MakeUndo() const
{
    BlockUndo undo;
    for (const auto& kv : changes) {
        std::string v;
        if (base.Read(kv.first, v)) undo.entries.emplace_back(kv.first, v);
        else undo.entries.emplace_back(kv.first, std::nullopt);
    }
    return undo;
}

void VaultState::ApplyUndo(const BlockUndo& undo)
{
    for (const auto& e : undo.entries) changes[e.first] = e.second;
}

std::optional<std::string> VaultState::ApplyTx(const CTransaction& tx, int64_t height, const CoinAccessor& coins)
{
    VaultState child(*this);
    child.blockHashes = blockHashes;
    auto err = child.ApplyTxInner(tx, height, coins);
    if (err) return err;
    MergeFrom(child);
    return std::nullopt;
}

std::optional<std::string> VaultState::ApplyBlock(const CBlock& block, int64_t height, const CoinAccessor& coins,
                                                  BlockUndo& undo, const CBlockIndex* pindex)
{
    for (const CTransaction& tx : block.vtx) {
        if (auto err = ApplyTx(tx, height, coins)) return err;
    }
    ModuleContext ctx;
    ctx.height = height;
    ctx.state = this;
    ctx.blockHashAt = blockHashes;
    for (const auto& entry : Modules()) {
        if (auto err = entry.second->CheckBlock(block, pindex, ctx)) return err;
    }
    undo = MakeUndo();
    return std::nullopt;
}

namespace {

/** Roll the rate epoch (U-20) before any change to lockedValue or use of the epoch fields. */
void RollEpoch(SetRecord& s, int64_t h)
{
    const int64_t e = h / (int64_t)s.params.rateWindow;
    if (e != s.epoch) {
        s.epoch = e;
        s.epochBasis = s.lockedValue;
        s.epochUsed = 0;
    }
}

struct OutClass {
    enum Kind { OTHER, VAULT, INTENT, ACT } kind = OTHER;
    VaultParams v;
    IntentParams i;
};

} // namespace

std::optional<std::string> VaultState::ApplyTxInner(const CTransaction& tx, int64_t h, const CoinAccessor& coins)
{
    const uint256 txid = tx.GetHash();

    // ---- outputs: classify (malformed template shapes are invalid: §15.3, V-1) ----
    std::vector<OutClass> outs(tx.vout.size());
    int actIndex = -1;
    for (size_t o = 0; o < tx.vout.size(); o++) {
        const CScript& spk = tx.vout[o].scriptPubKey;
        if (IsActOutput(spk)) {
            if (actIndex >= 0) return std::string("bad-vault-act-multi");
            actIndex = (int)o;
            outs[o].kind = OutClass::ACT;
            continue;
        }
        Shape vs = MatchVault(spk, outs[o].v);
        if (vs == Shape::MALFORMED) return std::string("bad-txns-vault-malformed");
        if (vs == Shape::MATCH) { outs[o].kind = OutClass::VAULT; continue; }
        Shape is = MatchIntent(spk, outs[o].i);
        if (is == Shape::MALFORMED) return std::string("bad-txns-vault-malformed");
        if (is == Shape::MATCH) outs[o].kind = OutClass::INTENT;
    }

    // ---- inputs: bond spends, the template input (S-1) ----
    std::optional<TemplateSpend> tin;
    size_t tinIndex = 0;
    SpentCoin tcoin;
    if (!tx.IsCoinBase()) {
        for (size_t i = 0; i < tx.vin.size(); i++) {
            const COutPoint& prevout = tx.vin[i].prevout;
            if (auto bond = GetBond(*this, prevout)) {
                if (bond->frozen) return std::string("bad-vault-bond-frozen");
                auto m = GetMember(*this, bond->setId, bond->memberKey);
                if (m && m->status == MEMBER_ACTIVE && m->bondOutpoint == prevout) {
                    m->status = MEMBER_WITHDRAWN;
                    PutRecord(KeyMember(bond->setId, bond->memberKey), *m);
                }
                Erase(KeyBond(prevout));
            }
            SpentCoin c;
            if (!coins.GetSpentCoin(prevout, c)) return std::string("bad-txns-vault-inputs-missing");
            TemplateSpend ts;
            if (ParseVault(c.scriptPubKey, ts.vault)) {
                ts.kind = TemplateKind::VAULT;
            } else if (ParseIntent(c.scriptPubKey, ts.intent)) {
                ts.kind = TemplateKind::INTENT;
            } else {
                continue;
            }
            if (tin) return std::string("bad-txns-vault-multi");
            auto sel = ParseSelector(tx.vin[i].scriptSig, &ts.sigs);
            if (!sel) return std::string("bad-txns-vault-selector");
            if (ts.kind == TemplateKind::INTENT && *sel == SEL_APP) return std::string("bad-txns-vault-selector");
            ts.selector = *sel;
            tin = ts;
            tinIndex = i;
            tcoin = c;
        }
    }

    const bool unlockSpend = tin && tin->kind == TemplateKind::VAULT &&
                             (tin->selector == SEL_UNLOCK || tin->selector == SEL_APP);

    // ---- I-0: intents only from an UNLOCK/APP spend ----
    for (const OutClass& oc : outs) {
        if (oc.kind == OutClass::INTENT && !unlockSpend) return std::string("bad-txns-vault-intent");
    }

    // ---- template input rules ----
    if (tin && tin->kind == TemplateKind::VAULT) {
        const VaultParams& v = tin->vault;
        if (tin->selector == SEL_APP && v.appHeight == 0) return std::string("bad-txns-vault-app"); // S-4
        auto set = GetSet(*this, v.setId);
        if (set) RollEpoch(*set, h);
        if (unlockSpend) {
            // S-2: the vault's value never leaves to ordinary outputs.
            const uint256 vaultHash = ScriptHash256(tcoin.scriptPubKey);
            CAmount sumI = 0, sumRelock = 0;
            for (size_t o = 0; o < outs.size(); o++) {
                const CAmount value = tx.vout[o].nValue;
                if (outs[o].kind == OutClass::INTENT) {
                    const IntentParams& ip = outs[o].i;
                    if (ip.tag != v.tag || ip.setId != v.setId || ip.cancelSetId != v.cancelSetId ||
                        ip.delay != v.delay || ip.owner != v.owner || ip.vaultHash != vaultHash) {
                        return std::string("bad-txns-vault-covenant");
                    }
                    sumI += value;
                    if (!MoneyRange(value) || !MoneyRange(sumI)) return std::string("bad-txns-vault-amount");
                } else if (outs[o].kind == OutClass::VAULT) {
                    if (tx.vout[o].scriptPubKey != tcoin.scriptPubKey) return std::string("bad-txns-vault-covenant");
                    sumRelock += value;
                    if (!MoneyRange(value) || !MoneyRange(sumRelock)) return std::string("bad-txns-vault-amount");
                }
            }
            if (!MoneyRange(sumI + sumRelock) || sumI + sumRelock < tcoin.value) return std::string("bad-txns-vault-value");
            // S-3: the set's rate limit over the current epoch (U-20).
            if (set && set->params.rateLimitBps != 0) {
                const CAmount cap = RateCap(set->epochBasis, set->params.rateLimitBps);
                if (set->epochUsed + sumI > cap) return std::string("bad-txns-vault-rate");
            }
            if (set) set->epochUsed += sumI;
        }
        // S-3 / S-4: the spent vault leaves the set's locked value (every selector).
        if (set) {
            set->lockedValue = set->lockedValue > tcoin.value ? set->lockedValue - tcoin.value : 0;
            PutRecord(KeySet(v.setId), *set);
        }
    } else if (tin && tin->kind == TemplateKind::INTENT) {
        const IntentParams& ip = tin->intent;
        if (tin->selector == SEL_UNLOCK) { // I-1 RELEASE
            bool paid = false;
            for (const CTxOut& out : tx.vout) {
                if (out.nValue >= tcoin.value && ScriptHash256(out.scriptPubKey) == ip.recipientHash) { paid = true; break; }
            }
            if (!paid) return std::string("bad-txns-vault-release");
        } else if (tin->selector == SEL_OWNER) { // I-2 CANCEL
            if (!(h - tcoin.height < ip.delay)) return std::string("bad-txns-vault-cancel");
            bool back = false;
            for (const CTxOut& out : tx.vout) {
                if (out.nValue >= tcoin.value && ScriptHash256(out.scriptPubKey) == ip.vaultHash) { back = true; break; }
            }
            if (!back) return std::string("bad-txns-vault-cancel");
        }
        // I-3 (selector 3): script only.
    }

    // ---- V-1: vault outputs ----
    for (size_t o = 0; o < outs.size(); o++) {
        if (outs[o].kind != OutClass::VAULT) continue;
        const VaultParams& v = outs[o].v;
        auto set = GetSet(*this, v.setId);
        if (!set || set->createHeight >= h) return std::string("bad-txns-vault-noset");
        auto cset = GetSet(*this, v.cancelSetId);
        if (!cset || cset->createHeight >= h) return std::string("bad-txns-vault-noset");
        RollEpoch(*set, h);
        set->lockedValue += tx.vout[o].nValue;
        if (!MoneyRange(tx.vout[o].nValue) || !MoneyRange(set->lockedValue)) return std::string("bad-txns-vault-amount");
        PutRecord(KeySet(v.setId), *set);
    }

    // ---- the template-output index (vault_list; an intent's height for replay) ----
    if (tin) Erase(KeyTemplateOut(tx.vin[tinIndex].prevout));
    for (size_t o = 0; o < outs.size(); o++) {
        if (outs[o].kind != OutClass::VAULT && outs[o].kind != OutClass::INTENT) continue;
        TemplateOutRecord rec;
        rec.kind = outs[o].kind == OutClass::VAULT ? 0 : 1;
        rec.height = h;
        rec.value = tx.vout[o].nValue;
        rec.scriptPubKey = tx.vout[o].scriptPubKey;
        if (outs[o].kind == OutClass::INTENT) rec.origin = tcoin.scriptPubKey;
        PutRecord(KeyTemplateOut(COutPoint(txid, o)), rec);
    }

    // ---- module dispatch (after the primitive rules; a module can only reject) ----
    ModuleContext ctx;
    ctx.height = h;
    ctx.state = this;
    ctx.blockHashAt = blockHashes;
    if (tin) {
        const Tag& tag = tin->kind == TemplateKind::VAULT ? tin->vault.tag : tin->intent.tag;
        if (const Module* mod = FindModule(tag)) {
            if (auto err = mod->ValidateSpend(tx, tinIndex, *tin, ctx)) return err;
        }
    }
    for (size_t o = 0; o < outs.size(); o++) {
        if (outs[o].kind != OutClass::VAULT) continue;
        if (const Module* mod = FindModule(outs[o].v.tag)) {
            if (auto err = mod->ValidateCreate(tx, o, outs[o].v, ctx)) return err;
        }
    }

    // ---- the act ----
    if (actIndex >= 0) {
        Act act;
        if (auto err = DecodeAct(tx.vout[actIndex].scriptPubKey, act)) return err;
        if (auto err = ApplyAct(tx, act, h)) return err;
    }

    // ---- the module ejection hook (U-25): after the transaction's own rules and act ----
    if (!tx.IsCoinBase()) ApplyEjections(tx, h);
    return std::nullopt;
}

// The same effect and condition as SET_EQUIVOCATION's (ApplyAct above), for the module hook.
bool EjectAndFreeze(VaultState& st, const SetId& setId, const CPubKey& key)
{
    auto m = GetMember(st, setId, key);
    if (!m) return false;
    auto b = GetBond(st, m->bondOutpoint);
    if (!b || b->frozen || b->setId != setId || b->memberKey != key) return false;
    m->status = MEMBER_EJECTED;
    m->bondFrozen = true;
    b->frozen = true;
    st.PutRecord(KeyMember(setId, key), *m);
    st.PutRecord(KeyBond(m->bondOutpoint), *b);
    return true;
}

void VaultState::ApplyEjections(const CTransaction& tx, int64_t h)
{
    for (const auto& entry : Modules()) ApplyEjectionsOf(*entry.second, tx, h);
}

void VaultState::ApplyEjectionsOf(const Module& module, const CTransaction& tx, int64_t h)
{
    const std::optional<SetId> governed = module.GovernedSet();
    if (!governed || !GetSet(*this, *governed)) return;
    ModuleContext ctx;
    ctx.height = h;
    ctx.state = this;
    ctx.blockHashAt = blockHashes;
    for (const CPubKey& key : module.Ejections(tx, ctx)) EjectAndFreeze(*this, *governed, key);
}

std::optional<std::string> VaultState::ApplyAct(const CTransaction& tx, const Act& act, int64_t h)
{
    if (tx.IsCoinBase()) return std::string("bad-vault-act-coinbase");
    if (tx.vin.empty()) return std::string("bad-vault-act-novin");

    // A SET_CREATE carrying signatures is a count error, reported as such.
    if (act.type == ACT_SET_CREATE && !act.sigs.empty()) return std::string("bad-vault-act-sigs");
    if (!ActFieldsValid(act)) return std::string("bad-vault-act-params");

    const uint256 msg = ActMsg(EncodePayload(act), tx.vin[0].prevout);
    std::vector<CPubKey> keys;
    for (const auto& sig : act.sigs) {
        CPubKey k;
        if (!RecoverSig(msg, sig, k)) return std::string("bad-vault-act-sig");
        keys.push_back(k);
    }

    // `count` distinct current members of the set among keys[from..], none equal to `exclude`.
    auto cosigners = [&](const SetRecord& s, const MemberList& members, size_t from, size_t count, const CPubKey* exclude) {
        if (keys.size() != from + count) return false;
        std::set<CPubKey> seen;
        for (size_t i = from; i < keys.size(); i++) {
            if (exclude && keys[i] == *exclude) return false;
            if (!seen.insert(keys[i]).second) return false;
            bool current = false;
            for (const auto& m : members) {
                if (m.first == keys[i]) { current = IsCurrent(s, m.second, h); break; }
            }
            if (!current) return false;
        }
        return true;
    };

    switch (act.type) {
    case ACT_SET_CREATE: {
        if (!act.sigs.empty()) return std::string("bad-vault-act-sigs");
        if (!act.create.Valid()) return std::string("bad-vault-act-params");
        const SetId setId = tx.GetHash();
        if (GetSet(*this, setId)) return std::string("bad-vault-act-exists");
        SetRecord s;
        s.params = act.create;
        s.createHeight = h;
        s.epoch = h / (int64_t)s.params.rateWindow;
        PutRecord(KeySet(setId), s);
        return std::nullopt;
    }
    case ACT_SET_JOIN: {
        const SetJoinBody& j = act.join;
        auto s = GetSet(*this, j.setId);
        if (!s || s->createHeight >= h) return std::string("bad-vault-act-noset");
        if (s->windDownHeight != 0) return std::string("bad-vault-act-winddown");
        if (!IsCompressedKey(j.memberKey)) return std::string("bad-vault-act-params");
        if (keys.empty() || keys[0] != j.memberKey) return std::string("bad-vault-act-sig");
        const MemberList members = GetMembers(*this, j.setId);
        if (s->params.IsOpen()) {
            if (keys.size() != 1) return std::string("bad-vault-act-sigs");
        } else if (CountCurrent(*s, members, h) >= (int)s->params.slashThreshold) {
            if (!cosigners(*s, members, 1, s->params.slashThreshold, nullptr)) return std::string("bad-vault-act-sigs");
        } else {
            if (keys.size() != 2 || keys[1] != s->params.admitKey) return std::string("bad-vault-act-sigs");
        }
        if (CountActive(members) >= (int)s->params.seats) return std::string("bad-vault-act-seats");
        auto existing = GetMember(*this, j.setId, j.memberKey);
        if (existing && existing->status == MEMBER_ACTIVE) return std::string("bad-vault-act-join");
        if (j.bondVout >= tx.vout.size()) return std::string("bad-vault-act-bond");
        const CTxOut& bond = tx.vout[j.bondVout];
        const CScript bondSpk = BondScriptPubKey(j.bondLocktime, j.memberKey);
        if (bondSpk.empty() || bond.scriptPubKey != bondSpk) return std::string("bad-vault-act-bond");
        if (!MoneyRange(bond.nValue) || bond.nValue < s->params.bondMin) return std::string("bad-vault-act-bond");
        if ((int64_t)j.bondLocktime < h + (int64_t)s->params.bondLockMin || j.bondLocktime >= 500000000) {
            return std::string("bad-vault-act-bond");
        }
        MemberRecord m;
        m.bondOutpoint = COutPoint(tx.GetHash(), j.bondVout);
        m.bondValue = bond.nValue;
        m.bondLocktime = j.bondLocktime;
        m.joinHeight = h;
        m.lastAct = h + (int64_t)s->params.maturity;
        m.status = MEMBER_ACTIVE;
        m.bondFrozen = false;
        PutRecord(KeyMember(j.setId, j.memberKey), m);
        BondRecord b;
        b.setId = j.setId;
        b.memberKey = j.memberKey;
        b.frozen = false;
        PutRecord(KeyBond(m.bondOutpoint), b);
        return std::nullopt;
    }
    case ACT_SET_HEARTBEAT: {
        const SetHeartbeatBody& hb = act.heartbeat;
        auto s = GetSet(*this, hb.setId);
        if (!s) return std::string("bad-vault-act-noset");
        if (keys.size() != 1) return std::string("bad-vault-act-sigs");
        if (keys[0] != hb.memberKey) return std::string("bad-vault-act-sig");
        auto m = GetMember(*this, hb.setId, hb.memberKey);
        if (!m || !IsCurrent(*s, *m, h)) return std::string("bad-vault-act-heartbeat");
        m->lastAct = h;
        PutRecord(KeyMember(hb.setId, hb.memberKey), *m);
        return std::nullopt;
    }
    case ACT_SET_REMOVE: {
        const SetRemoveBody& r = act.remove;
        if (r.burn > 1) return std::string("bad-vault-act-params");
        auto s = GetSet(*this, r.setId);
        if (!s) return std::string("bad-vault-act-noset");
        auto m = GetMember(*this, r.setId, r.memberKey);
        if (!m || m->status != MEMBER_ACTIVE) return std::string("bad-vault-act-remove");
        const MemberList members = GetMembers(*this, r.setId);
        if (!cosigners(*s, members, 0, s->params.slashThreshold, &r.memberKey)) return std::string("bad-vault-act-sigs");
        m->status = MEMBER_REMOVED;
        if (r.burn) {
            m->bondFrozen = true;
            if (auto b = GetBond(*this, m->bondOutpoint)) {
                b->frozen = true;
                PutRecord(KeyBond(m->bondOutpoint), *b);
            }
        }
        PutRecord(KeyMember(r.setId, r.memberKey), *m);
        return std::nullopt;
    }
    case ACT_SET_EQUIVOCATION: {
        const SetEquivocationBody& e = act.equivocation;
        if (!act.sigs.empty()) return std::string("bad-vault-act-sigs");
        if ((e.roleA != ROLE_UNLOCK && e.roleA != ROLE_CANCEL) || (e.roleB != ROLE_UNLOCK && e.roleB != ROLE_CANCEL)) {
            return std::string("bad-vault-act-params");
        }
        if (e.roleA == e.roleB && e.sighashA == e.sighashB) return std::string("bad-vault-act-equivocation");
        auto s = GetSet(*this, e.setId);
        if (!s) return std::string("bad-vault-act-noset");
        CPubKey ka, kb;
        if (!RecoverSig(SetSigMsg(e.setId, e.roleA, e.prevout, e.sighashA), e.sigA, ka) ||
            !RecoverSig(SetSigMsg(e.setId, e.roleB, e.prevout, e.sighashB), e.sigB, kb) || ka != kb) {
            return std::string("bad-vault-act-equivocation");
        }
        auto m = GetMember(*this, e.setId, ka);
        if (!m) return std::string("bad-vault-act-equivocation");
        auto b = GetBond(*this, m->bondOutpoint);
        if (!b || b->frozen || b->setId != e.setId || b->memberKey != ka) return std::string("bad-vault-act-equivocation");
        m->status = MEMBER_EJECTED;
        m->bondFrozen = true;
        b->frozen = true;
        PutRecord(KeyMember(e.setId, ka), *m);
        PutRecord(KeyBond(m->bondOutpoint), *b);
        return std::nullopt;
    }
    case ACT_SET_WINDDOWN: {
        const SetWindDownBody& w = act.winddown;
        auto s = GetSet(*this, w.setId);
        if (!s) return std::string("bad-vault-act-noset");
        if (s->windDownHeight != 0) return std::string("bad-vault-act-winddown");
        const MemberList members = GetMembers(*this, w.setId);
        if (!cosigners(*s, members, 0, s->params.slashThreshold, nullptr)) return std::string("bad-vault-act-sigs");
        s->windDownHeight = h;
        PutRecord(KeySet(w.setId), *s);
        return std::nullopt;
    }
    default:
        return std::string("bad-vault-act-type");
    }
}

std::optional<std::string> CheckTx(const CTransaction& tx, const CoinAccessor& coins, int64_t height, const SetSnapshot& snapshot,
                                   const BlockHashFn& blockHashes)
{
    VaultState tmp(snapshot.Base());
    tmp.SetBlockHashes(blockHashes);
    return tmp.ApplyTx(tx, height, coins);
}

} // namespace vault
