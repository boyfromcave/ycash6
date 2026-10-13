// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_TEST_VAULT_STATE_FUZZ_HARNESS_H
#define YCASH_TEST_VAULT_STATE_FUZZ_HARNESS_H

// The body of the VaultState fuzz target (src/fuzzing/VaultState/fuzz.cpp), shared with the Boost replay in
// vault_fuzz_tests.cpp so `make check` runs every seed and every found-and-fixed crash without a fuzzing build.
// Header-only, no Boost. Where the Vault target reaches the parsers, this one reaches the state rules
// (docs/plans/yellowback-upgrade-plan.md §15.4-§15.6): VaultState::ApplyTx / ApplyBlock, the undo record and the
// state hash, over a MemoryKV.
//
// Input grammar (every read past the end yields 0, so every byte string is an input):
//   u8 x 7   the base set's SET_CREATE fields: seats (2 + u8 % 6), unlock / cancel / slash thresholds (each
//            1 + u8 % seats), rateLimitBps ((u8 % 251) x 40), one byte w for rateWindow = 1 + w and livenessWindow =
//            1 + (w ^ 0x5a), maturity (u8 % 8); the set is created at height 100, members 0 and 1 join at 101
//   u8       the base vault's delay (1 + u8): one V of 10 YEC on the set at 102 + maturity
//   then items, until the input ends or 24 transactions / 6 blocks: u8 op, then op's fields:
//     0 NEXT     u8 d: close the block, the next one at height h + 1 + d % 64
//     1 CREATE   u8 x 7 SET_CREATE fields (unclamped: invalid ones are rule tests), u8 flags (bit 0 OPEN,
//                bit 1 a stray signature)
//     2 JOIN     u8 set, u8 member key, u8 cosigner mask, u16 bond / 10 zat, u8 locktime ahead, u8 flags
//                (bit 0 the admit key cosigns, bit 1 bondVout off by one, bit 2 sign over another prevout)
//     3 HEARTBEAT u8 set, u8 member key, u8 signer key
//     4 WINDDOWN u8 set, u8 signer mask
//     5 REMOVE   u8 set, u8 target key, u8 burn, u8 signer mask
//     6 LOCK     u8 flags (bits 0-1 tag TEST / YED\0 / BRDG / from the input; bit 2 a second V; bit 3 one byte of
//                the script flipped: a malformed shape; bit 4 cancelSetId another set), u8 set, u16 delay,
//                u8 appHeight, u32 value
//     7 SPEND    u8 template coin, u8 selector (OP_0 .. OP_5), u8 output mask (bit 0 an intent, bit 1 a relock,
//                bit 2 a plain output, bit 3 pay the intent's recipient (spending a V: another V of the set), bit 4
//                pay the intent's V back, bit 5 a
//                second template input, bit 6 a fee input, bit 7 the intent pays key 1 instead of key 0),
//                u32 value
//     8 BOND     u8 bond coin, u8 flags (bit 0 a fee input)
//     9 EQUIV    u8 set, u8 member key, u8 roles, u8 flags (bit 0 the same sighash twice, bit 1 another key's
//                second signature)
// Properties (negative return codes):
//   -1  a refused ApplyTx leaves the running state unchanged (atomicity)
//   -2  every reject reason of the vault rules is one of the known reasons (REASONS below)
//   -3  the block of the transactions the running copy accepted one by one applies as a block (ApplyBlock)
//   -4  ... and its changes are the running copy's
//   -5  determinism: two ApplyBlock of the same block over the same base give the same changes, undo and state hash
//   -6  undo round-trip: the undo record (also after a serialization round-trip) restores the base byte for byte,
//       per block and over every block of the input in reverse
//   -7  set invariants after every block: lockedValue >= 0 and in MoneyRange, equal to the sum of the indexed V
//       outputs of the set; epochUsed and every indexed template value in MoneyRange; every bond names a set
//   -8  S-1: an accepted transaction spends at most one template coin
//   -9  the base (one set, two members, one V) does not build: the harness, not the rules, is wrong
// A thrown exception is the caller's failure (the fuzz target aborts).

#include "amount.h"
#include "key.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "streams.h"
#include "vault/act.h"
#include "vault/node.h"
#include "vault/state.h"
#include "vault/template.h"
#include "version.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace vault_state_fuzz {

using namespace vault;
typedef std::vector<unsigned char> valtype;

/** Every reject reason of src/vault (ApplyTx, ApplyAct, DecodeAct) and of the registered module's hooks. A rule
 *  that adds a reason adds it here (the fuzz target fails on an unknown one, so the list cannot go stale). */
inline bool KnownReason(const std::string& r)
{
    static const std::set<std::string> REASONS = {
        "bad-txns-vault-amount", "bad-txns-vault-app", "bad-txns-vault-cancel", "bad-txns-vault-covenant",
        "bad-txns-vault-inputs-missing", "bad-txns-vault-intent", "bad-txns-vault-malformed", "bad-txns-vault-multi",
        "bad-txns-vault-noset", "bad-txns-vault-rate", "bad-txns-vault-release", "bad-txns-vault-selector",
        "bad-txns-vault-value", "bad-vault-act-bond", "bad-vault-act-coinbase", "bad-vault-act-equivocation",
        "bad-vault-act-exists", "bad-vault-act-heartbeat", "bad-vault-act-join", "bad-vault-act-malformed",
        "bad-vault-act-multi", "bad-vault-act-noset", "bad-vault-act-novin", "bad-vault-act-params",
        "bad-vault-act-remove", "bad-vault-act-seats", "bad-vault-act-sig", "bad-vault-act-sigs", "bad-vault-act-type",
        "bad-vault-act-version", "bad-vault-act-winddown", "bad-vault-bond-frozen", "bad-vault-bond-locked",
        // the YED module (src/yellowback/module.cpp), when its parameters are configured
        "bad-yellowback-attestor-set-act", "bad-yellowback-intent-owner", "bad-yellowback-vault-delay",
        "bad-yellowback-vault-height", "bad-yellowback-vault-set", "bad-yellowback-vault-unlock",
    };
    return REASONS.count(r) != 0;
}

class Reader
{
public:
    explicit Reader(const std::vector<unsigned char>& d) : d(d) {}
    bool Done() const { return pos >= d.size(); }
    uint8_t U8() { return pos < d.size() ? d[pos++] : 0; }
    uint16_t U16() { uint16_t v = U8(); return v | (uint16_t)(U8() << 8); }
    uint32_t U32() { uint32_t v = U16(); return v | ((uint32_t)U16() << 16); }

private:
    const std::vector<unsigned char>& d;
    size_t pos = 0;
};

/** The fixed key pool: eight member keys and the admit key. */
inline const CKey& Key(unsigned i)
{
    static std::vector<CKey> keys;
    if (keys.empty()) {
        for (unsigned char seed = 1; seed <= 9; seed++) {
            CKey k;
            std::vector<unsigned char> secret(32, 0);
            secret[0] = 0x44;
            secret[31] = seed;
            k.Set(secret.begin(), secret.end(), true);
            keys.push_back(k);
        }
    }
    return keys[i % keys.size()];
}
inline const CKey& MemberKey(uint8_t b) { return Key(b % 8); }
inline const CKey& AdmitKey() { return Key(8); }
inline CScript PlainScript(uint8_t b) { return GetScriptForDestination(MemberKey(b).GetPubKey().GetID()); }

/** D-Q-31's floor lifted for the input (the suite's small maturities), restored after. */
struct MaturityGuard {
    uint32_t saved;
    MaturityGuard() : saved(MinSetMaturity()) { SetMinSetMaturity(0); }
    ~MaturityGuard() { SetMinSetMaturity(saved); }
};

/** The world one input drives: the committed base, the coins every accepted transaction created, the lists the
 *  grammar picks from, and the blocks connected so far (for the final disconnect). */
struct World {
    MemoryKV kv;
    MapCoinAccessor coins;
    int64_t h = 100;
    uint32_t fundCounter = 0;
    std::vector<COutPoint> funds, templates, bonds;
    std::vector<SetId> sets;
    std::vector<std::pair<std::map<std::string, std::string>, BlockUndo>> history;

    COutPoint Fund(CAmount value = 10 * COIN)
    {
        uint256 hash;
        ++fundCounter;
        for (int i = 0; i < 4; i++) hash.begin()[i] = (fundCounter >> (8 * i)) & 0xff;
        hash.begin()[31] = 0xf5;
        COutPoint op(hash, 0);
        SpentCoin c;
        c.scriptPubKey = PlainScript(0);
        c.value = value;
        c.height = 1;
        coins.coins[op] = c;
        return op;
    }
    COutPoint TakeFund()
    {
        if (funds.empty()) return Fund();
        COutPoint op = funds.back();
        funds.pop_back();
        return op;
    }
    SetId PickSet(uint8_t b) const { return sets.empty() ? SetId() : sets[b % sets.size()]; }
};

inline CMutableTransaction ActTx(World& w, Act act, const std::vector<CKey>& signers, const std::vector<CTxOut>& extra,
                                 bool wrongPrevout = false)
{
    CMutableTransaction m;
    m.vin.push_back(CTxIn(w.TakeFund(), CScript(), 0xffffffff));
    m.vout = extra;
    const valtype P = EncodePayload(act);
    const uint256 msg = ActMsg(P, wrongPrevout ? COutPoint(m.vin[0].prevout.hash, m.vin[0].prevout.n + 1) : m.vin[0].prevout);
    act.sigs.clear();
    for (const CKey& k : signers) {
        valtype sig;
        if (SignRecoverable(k, msg, sig)) act.sigs.push_back(sig);
    }
    m.vout.push_back(CTxOut(0, EncodeAct(act)));
    return m;
}

inline std::vector<CKey> Signers(uint8_t mask)
{
    std::vector<CKey> out;
    for (unsigned i = 0; i < 8; i++)
        if (mask & (1u << i)) out.push_back(MemberKey(i));
    return out;
}

inline SetCreateBody CreateBody(uint8_t seats, uint8_t ut, uint8_t ct, uint8_t st, uint16_t bps, uint32_t rw, uint32_t lw, uint32_t mat)
{
    SetCreateBody c;
    c.seats = seats;
    c.unlockThreshold = ut;
    c.cancelThreshold = ct;
    c.slashThreshold = st;
    c.flags = SET_FLAG_OPEN;
    c.rateLimitBps = bps;
    c.rateWindow = rw;
    c.livenessWindow = lw;
    c.bondMin = 1000;
    c.bondLockMin = 10;
    c.maturity = mat;
    c.admitKey = AdmitKey().GetPubKey();
    return c;
}

inline VaultParams VaultOf(const SetId& setId, const SetId& cancelSetId, int64_t delay, int64_t appHeight, const Tag& tag)
{
    VaultParams v;
    v.tag = tag;
    v.setId = setId;
    v.cancelSetId = cancelSetId;
    v.delay = delay;
    v.ownerHeight = 100000;
    const CPubKey pk = MemberKey(7).GetPubKey();
    v.owner = CPQKeyID(1, Hash(pk.begin(), pk.end()));
    v.appHeight = appHeight;
    return v;
}

/** -7: the set invariants over a committed state. */
inline int CheckInvariants(const KVReader& kv)
{
    std::map<SetId, CAmount> sumV;
    for (const auto& t : ListTemplateOuts(kv)) {
        if (!MoneyRange(t.second.value)) return -7;
        if (t.second.kind != 0) continue;
        VaultParams vp;
        if (!ParseVault(t.second.scriptPubKey, vp)) return -7;
        sumV[vp.setId] += t.second.value;
        if (!MoneyRange(sumV[vp.setId])) return -7;
    }
    for (const SetId& id : ListSets(kv)) {
        auto s = GetSet(kv, id);
        if (!s) return -7;
        if (s->lockedValue < 0 || !MoneyRange(s->lockedValue)) return -7;
        if (s->epochUsed < 0 || !MoneyRange(s->epochUsed) || !MoneyRange(s->epochBasis)) return -7;
        if (s->lockedValue != sumV[id]) return -7;
        for (const auto& m : GetMembers(kv, id)) {
            if (!MoneyRange(m.second.bondValue) || m.second.joinOrdinal > s->joinCount) return -7;
        }
        sumV.erase(id);
    }
    for (const auto& r : sumV) {
        if (r.second != 0) return -7; // value locked under a set that does not exist
    }
    return 0;
}

inline std::string UndoBytes(const BlockUndo& u)
{
    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << u;
    return std::string(ss.begin(), ss.end());
}

/** Close the block: properties -3 .. -7 over `block` (the accepted transactions) and `running`; commit. */
inline int CloseBlock(World& w, const std::vector<CTransaction>& txs, const VaultState& running)
{
    CBlock block;
    block.vtx = txs;
    VaultState a(w.kv), b(w.kv);
    BlockUndo ua, ub;
    if (a.ApplyBlock(block, w.h, w.coins, ua)) return -3;
    if (a.Changes() != running.Changes()) return -4;
    if (b.ApplyBlock(block, w.h, w.coins, ub)) return -5;
    if (a.Changes() != b.Changes() || UndoBytes(ua) != UndoBytes(ub)) return -5;
    MemoryKV after = w.kv, after2 = w.kv;
    after.Apply(a.Changes());
    after2.Apply(b.Changes());
    if (StateHash(after) != StateHash(after2)) return -5;
    // undo: the record and its serialized copy both restore the base
    BlockUndo decoded;
    {
        const std::string bytes = UndoBytes(ua);
        CDataStream ss(std::vector<char>(bytes.begin(), bytes.end()), SER_DISK, PROTOCOL_VERSION);
        ss >> decoded;
    }
    for (const BlockUndo* u : {&ua, &decoded}) {
        MemoryKV back = after;
        VaultState st(back);
        st.ApplyUndo(*u);
        back.Apply(st.Changes());
        if (back.data != w.kv.data) return -6;
    }
    if (int rc = CheckInvariants(after)) return rc;
    w.history.emplace_back(w.kv.data, ua);
    w.kv = after;
    return 0;
}

/** Note the outputs of an accepted transaction in the coin view and the pick lists; drop its inputs from them. */
inline void Accept(World& w, const CTransaction& tx, int bondVout)
{
    for (const CTxIn& in : tx.vin) {
        for (auto* list : {&w.funds, &w.templates, &w.bonds}) list->erase(std::remove(list->begin(), list->end(), in.prevout), list->end());
    }
    for (size_t o = 0; o < tx.vout.size(); o++) {
        const COutPoint op(tx.GetHash(), o);
        SpentCoin c;
        c.scriptPubKey = tx.vout[o].scriptPubKey;
        c.value = tx.vout[o].nValue;
        c.height = w.h;
        w.coins.coins[op] = c;
        VaultParams vp;
        IntentParams ip;
        if ((int)o == bondVout) w.bonds.push_back(op);
        else if (ParseVault(c.scriptPubKey, vp) || ParseIntent(c.scriptPubKey, ip)) w.templates.push_back(op);
        else if (!IsActOutput(c.scriptPubKey) && c.value > 0) w.funds.push_back(op);
    }
    Act act;
    if (!tx.vout.empty() && !DecodeAct(tx.vout.back().scriptPubKey, act) && act.type == ACT_SET_CREATE) w.sets.push_back(tx.GetHash());
}

/** Build the base: one OPEN set with two matured members (from the input) and one V of 10 YEC. */
inline int BuildBase(World& w, Reader& r)
{
    const uint8_t seats = 2 + r.U8() % 6;
    auto clamp = [&](uint8_t b) { return (uint8_t)(1 + b % seats); };
    const uint8_t ut = clamp(r.U8()), ct = clamp(r.U8()), st = clamp(r.U8());
    const uint16_t bps = (uint16_t)((r.U8() % 251) * 40); // <= MAX_RATE_BPS
    const uint8_t win = r.U8();
    const uint32_t mat = r.U8() % 8;
    const int64_t delay = 1 + r.U8();
    Act create;
    create.type = ACT_SET_CREATE;
    create.create = CreateBody(seats, ut, ct, st, bps, 1 + win, 1 + (uint32_t)(win ^ 0x5a), mat);
    const CTransaction ctx(ActTx(w, create, {}, {}));
    VaultState s0(w.kv);
    if (s0.ApplyTx(ctx, w.h, w.coins)) return -9;
    Accept(w, ctx, -1);
    std::vector<CTransaction> b0{ctx};
    if (int rc = CloseBlock(w, b0, s0)) return rc;
    w.h++;
    const SetId set = ctx.GetHash();
    VaultState s1(w.kv);
    std::vector<CTransaction> b1;
    for (uint8_t i = 0; i < 2; i++) {
        Act join;
        join.type = ACT_SET_JOIN;
        join.join.setId = set;
        join.join.memberKey = MemberKey(i).GetPubKey();
        join.join.bondLocktime = (uint32_t)(w.h + 1000);
        join.join.bondVout = 0;
        const CTransaction jtx(ActTx(w, join, {MemberKey(i)}, {CTxOut(1000, BondScriptPubKey(join.join.bondLocktime, MemberKey(i).GetPubKey()))}));
        if (s1.ApplyTx(jtx, w.h, w.coins)) return -9;
        Accept(w, jtx, 0);
        b1.push_back(jtx);
    }
    if (int rc = CloseBlock(w, b1, s1)) return rc;
    w.h += 1 + mat;
    CMutableTransaction lock;
    lock.vin.push_back(CTxIn(w.TakeFund(), CScript(), 0xffffffff));
    lock.vout.push_back(CTxOut(10 * COIN, BuildVault(VaultOf(set, set, delay, 0, Tag{{'T', 'E', 'S', 'T'}}))));
    const CTransaction ltx(lock);
    VaultState s2(w.kv);
    if (s2.ApplyTx(ltx, w.h, w.coins)) return -9;
    Accept(w, ltx, -1);
    std::vector<CTransaction> b2{ltx};
    if (int rc = CloseBlock(w, b2, s2)) return rc;
    w.h++;
    return 0;
}

/** The next transaction of the grammar; `bondVout` receives a JOIN's bond output index (else -1). */
inline CMutableTransaction NextTx(World& w, Reader& r, uint8_t op, int& bondVout)
{
    bondVout = -1;
    CMutableTransaction m;
    switch (op) {
    case 1: { // CREATE
        Act a;
        a.type = ACT_SET_CREATE;
        const uint8_t seats = r.U8() % 10, ut = r.U8() % 10, ct = r.U8() % 10, st = r.U8() % 10;
        const uint16_t bps = (uint16_t)(r.U8() * 50);
        const uint32_t rw = r.U8(), lw = r.U8();
        const uint8_t flags = r.U8();
        a.create = CreateBody(seats, ut, ct, st, bps, rw, lw, flags >> 4);
        if (!(flags & 1)) a.create.flags = 0;
        return ActTx(w, a, (flags & 2) ? std::vector<CKey>{MemberKey(0)} : std::vector<CKey>{}, {});
    }
    case 2: { // JOIN
        Act a;
        a.type = ACT_SET_JOIN;
        a.join.setId = w.PickSet(r.U8());
        const CKey& member = MemberKey(r.U8());
        a.join.memberKey = member.GetPubKey();
        std::vector<CKey> signers = {member};
        for (const CKey& k : Signers(r.U8())) signers.push_back(k);
        const CAmount bond = (CAmount)r.U16() * 10;
        a.join.bondLocktime = (uint32_t)(w.h + 1 + r.U8() * 8);
        const uint8_t flags = r.U8();
        if (flags & 1) signers = {member, AdmitKey()};
        a.join.bondVout = (flags & 2) ? 1 : 0;
        bondVout = 0;
        return ActTx(w, a, signers, {CTxOut(bond, BondScriptPubKey(a.join.bondLocktime, member.GetPubKey()))}, (flags & 4) != 0);
    }
    case 3: { // HEARTBEAT
        Act a;
        a.type = ACT_SET_HEARTBEAT;
        a.heartbeat.setId = w.PickSet(r.U8());
        a.heartbeat.memberKey = MemberKey(r.U8()).GetPubKey();
        return ActTx(w, a, {MemberKey(r.U8())}, {});
    }
    case 4: { // WINDDOWN
        Act a;
        a.type = ACT_SET_WINDDOWN;
        a.winddown.setId = w.PickSet(r.U8());
        return ActTx(w, a, Signers(r.U8()), {});
    }
    case 5: { // REMOVE
        Act a;
        a.type = ACT_SET_REMOVE;
        a.remove.setId = w.PickSet(r.U8());
        a.remove.memberKey = MemberKey(r.U8()).GetPubKey();
        a.remove.burn = r.U8() % 3;
        return ActTx(w, a, Signers(r.U8()), {});
    }
    case 6: { // LOCK
        const uint8_t flags = r.U8();
        const SetId set = w.PickSet(r.U8());
        const SetId cancelSet = (flags & 16) ? w.PickSet(flags >> 5) : set;
        const int64_t delay = r.U16();
        const int64_t appHeight = r.U8();
        const CAmount value = (CAmount)r.U32();
        Tag tag{{'T', 'E', 'S', 'T'}};
        if ((flags & 3) == 1) tag = Tag{{'Y', 'E', 'D', 0x00}};
        if ((flags & 3) == 2) tag = Tag{{'B', 'R', 'D', 'G'}};
        if ((flags & 3) == 3) tag = Tag{{(unsigned char)delay, (unsigned char)(delay >> 8), (unsigned char)value, 0x01}};
        CScript spk = BuildVault(VaultOf(set, cancelSet, delay, appHeight, tag));
        if (spk.empty()) spk = BuildVault(VaultOf(set, cancelSet, 1 + delay % 65535, appHeight, tag));
        if ((flags & 8) && !spk.empty()) {
            // a V-shaped output outside the template (V-1, MALFORMED): the owner slot's second key hash differs
            // from the first (value & 1 == 0), or else one byte flipped where the input says
            std::vector<unsigned char> bytes(spk.begin(), spk.end());
            VaultParams vp;
            if (!(value & 1) && ParseVault(spk, vp)) {
                const std::vector<unsigned char> owner(vp.owner.hash.begin(), vp.owner.hash.end());
                auto it = std::find_end(bytes.begin(), bytes.end(), owner.begin(), owner.end());
                if (it != bytes.end()) *it ^= 0x01;
            } else {
                bytes[(size_t)value % bytes.size()] ^= 0x01;
            }
            spk = CScript(bytes.begin(), bytes.end());
        }
        m.vin.push_back(CTxIn(w.TakeFund(), CScript(), 0xffffffff));
        m.vout.push_back(CTxOut(value, spk));
        if (flags & 4) m.vout.push_back(CTxOut(value / 2, spk));
        return m;
    }
    case 7: { // SPEND a template coin
        const uint8_t pick = r.U8(), selector = r.U8() % 6, mask = r.U8();
        const CAmount value = (CAmount)r.U32();
        if (w.templates.empty()) return m;
        const COutPoint prevout = w.templates[pick % w.templates.size()];
        SpentCoin coin;
        w.coins.GetSpentCoin(prevout, coin);
        CScript sig;
        sig << valtype(65, 0x20) << CScript::EncodeOP_N(selector);
        m.vin.push_back(CTxIn(prevout, sig, 0xfffffffe));
        VaultParams vp;
        IntentParams ip;
        const bool isV = ParseVault(coin.scriptPubKey, vp), isI = ParseIntent(coin.scriptPubKey, ip);
        if ((mask & 1) && isV) m.vout.push_back(CTxOut(value, BuildIntent(IntentFor(vp, coin.scriptPubKey, PlainScript(mask >> 7)))));
        // output values stay in [0, MAX_MONEY]: no serialized transaction carries others (6.20.0's CTransaction refuses to
        // build one), so the amount rules are reached through sums
        if (mask & 2) m.vout.push_back(CTxOut(std::max<CAmount>(0, coin.value - value), coin.scriptPubKey));
        if (mask & 4) m.vout.push_back(CTxOut(value / 3, PlainScript(mask)));
        if ((mask & 8) && isV) // a V output that is not the spent V (on an unlock: a covenant breach)
            m.vout.push_back(CTxOut(value / 4, BuildVault(VaultOf(vp.setId, vp.cancelSetId, 1 + vp.delay % 65534, vp.appHeight, vp.tag))));
        if ((mask & 8) && isI) {
            // the recipient the intent names is PlainScript(k) for one k of the pool
            for (uint8_t k = 0; k < 8; k++)
                if (ScriptHash256(PlainScript(k)) == ip.recipientHash) m.vout.push_back(CTxOut(coin.value, PlainScript(k)));
        }
        if ((mask & 16) && isI) {
            for (const COutPoint& t : w.templates) {
                SpentCoin tc;
                if (w.coins.GetSpentCoin(t, tc) && ScriptHash256(tc.scriptPubKey) == ip.vaultHash) { m.vout.push_back(CTxOut(coin.value, tc.scriptPubKey)); break; }
            }
            if (m.vout.empty()) {
                // the originating V is spent: re-create it from the intent's fields
                const CScript back = BuildVault(VaultOf(ip.setId, ip.cancelSetId, ip.delay, 0, ip.tag));
                m.vout.push_back(CTxOut(coin.value, back));
            }
        }
        if ((mask & 32) && w.templates.size() > 1) {
            const COutPoint second = w.templates[(pick + 1) % w.templates.size()];
            if (second != prevout) m.vin.push_back(CTxIn(second, CScript() << OP_1, 0xfffffffe));
        }
        if (mask & 64) m.vin.push_back(CTxIn(w.TakeFund(), CScript() << valtype(72, 1), 0xffffffff));
        return m;
    }
    case 8: { // BOND spend
        const uint8_t pick = r.U8(), flags = r.U8();
        if (w.bonds.empty()) return m;
        m.vin.push_back(CTxIn(w.bonds[pick % w.bonds.size()], CScript() << valtype(72, 1), 0xfffffffe));
        if (flags & 1) m.vin.push_back(CTxIn(w.TakeFund(), CScript(), 0xffffffff));
        m.vout.push_back(CTxOut(500, PlainScript(flags)));
        return m;
    }
    case 9: { // EQUIVOCATION
        Act a;
        a.type = ACT_SET_EQUIVOCATION;
        SetEquivocationBody& e = a.equivocation;
        e.setId = w.PickSet(r.U8());
        const CKey& k = MemberKey(r.U8());
        const uint8_t roles = r.U8(), flags = r.U8();
        e.prevout = COutPoint(uint256S("0xe9"), roles);
        e.roleA = 1 + (roles & 1);
        e.roleB = 1 + ((roles >> 1) & 1);
        e.sighashA = uint256S("0xa1");
        e.sighashB = (flags & 1) ? e.sighashA : uint256S("0xb2");
        SignRecoverable(k, SetSigMsg(e.setId, e.roleA, e.prevout, e.sighashA), e.sigA);
        SignRecoverable((flags & 2) ? MemberKey(roles + 1) : k, SetSigMsg(e.setId, e.roleB, e.prevout, e.sighashB), e.sigB);
        return ActTx(w, a, {}, {});
    }
    default:
        return m;
    }
}

/** What one input reached (the replay test checks the corpus reaches the accepting paths). */
struct Stats {
    int accepted = 0, refused = 0, blocks = 0;
    std::set<std::string> reasons;
};

inline int RunVaultState(const std::vector<unsigned char>& data, Stats* stats = nullptr)
{
    MaturityGuard guard;
    Reader r(data);
    World w;
    if (int rc = BuildBase(w, r)) return rc;
    const std::map<std::string, std::string> base = w.kv.data;
    const size_t baseBlocks = w.history.size();

    int ntx = 0, nblocks = 0, rc = 0;
    std::vector<CTransaction> block;
    std::unique_ptr<VaultState> running(new VaultState(w.kv));
    while (!r.Done() && ntx < 24 && nblocks < 6) {
        const uint8_t op = r.U8() % 10;
        if (op == 0) {
            const uint8_t d = r.U8();
            rc = CloseBlock(w, block, *running);
            block.clear();
            nblocks++;
            if (rc) return rc;
            if (stats) stats->blocks++;
            w.h += 1 + d % 64;
            running.reset(new VaultState(w.kv));
            continue;
        }
        int bondVout = -1;
        const CMutableTransaction m = NextTx(w, r, op, bondVout);
        if (m.vin.empty()) continue;
        const CTransaction tx(m);
        ntx++;
        const std::map<std::string, std::optional<std::string>> before = running->Changes();
        const std::optional<std::string> err = running->ApplyTx(tx, w.h, w.coins);
        if (err) {
            if (running->Changes() != before) return -1;
            if (!KnownReason(*err)) return -2;
            if (stats) { stats->refused++; stats->reasons.insert(*err); }
            continue;
        }
        int templateInputs = 0;
        for (const CTxIn& in : tx.vin) {
            SpentCoin c;
            VaultParams vp;
            IntentParams ip;
            if (w.coins.GetSpentCoin(in.prevout, c) && (ParseVault(c.scriptPubKey, vp) || ParseIntent(c.scriptPubKey, ip))) templateInputs++;
        }
        if (templateInputs > 1) return -8;
        Accept(w, tx, bondVout);
        block.push_back(tx);
        if (stats) stats->accepted++;
    }
    if ((rc = CloseBlock(w, block, *running))) return rc;
    if (stats) stats->blocks++;

    // every block of the input, disconnected in reverse, restores its parent's state and finally the base
    MemoryKV kv = w.kv;
    for (size_t i = w.history.size(); i-- > baseBlocks;) {
        VaultState st(kv);
        st.ApplyUndo(w.history[i].second);
        kv.Apply(st.Changes());
        if (kv.data != w.history[i].first) return -6;
    }
    if (kv.data != base) return -6;
    return 0;
}

} // namespace vault_state_fuzz

#endif // YCASH_TEST_VAULT_STATE_FUZZ_HARNESS_H
