// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The vault primitive's RPCs (docs/plans/yellowback-upgrade-plan.md §15.8; documented in
// doc/vault-rpc.md). Read RPCs need only the node; act, lock and spend RPCs keep every key in
// the node wallet (a member key, an admit key or an owner key is a wallet public key) and fund
// fees from the wallet's transparent P2PKH coins. Nothing here is consensus: every transaction
// is checked by AcceptToMemoryPool like any other.

#include "amount.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/upgrades.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "crypto/pq/scheme.h"
#include "key_io.h"
#include "main.h"
#include "net.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "script/interpreter.h"
#include "script/standard.h"
#include "txmempool.h"
#include "uint256.h"
#include "util/moneystr.h"
#include "util/strencodings.h"
#include "vault/act.h"
#include "vault/checker.h"
#include "vault/module.h"
#include "vault/node.h"
#include "vault/state.h"
#include "vault/template.h"
#include "yellowback/address.h"
#include "yellowback/txbuilder.h"

#ifdef ENABLE_WALLET
#include "script/ismine.h"
#include "script/sign.h"
#include "wallet/wallet.h"
#endif

#include <map>
#include <set>

#include <univalue.h>

using namespace vault;

bool EnsureWalletIsAvailable(bool avoidException);

namespace {

/** The flat fee every vault RPC pays (zatoshi), as the conventional transparent fee. */
// VAULT_RPC_FEE (10,000 zat) is policy.h's: the floor of the vault/Yellowback fee cap too
/** Change below this goes to the fee. */
static const CAmount VAULT_RPC_MIN_CHANGE = 1000;

int NextHeight() { return chainActive.Height() + 1; }

uint32_t NextBranchId() { return CurrentEpochBranchId(NextHeight(), Params().GetConsensus()); }

bool ActiveAtNext() { return Params().GetConsensus().NetworkUpgradeActive(NextHeight(), Consensus::UPGRADE_VAULT); }

void EnsureVaultActive()
{
    if (!ActiveAtNext())
        throw JSONRPCError(RPC_MISC_ERROR, strprintf("the vault upgrade is not active at the next block (height %d)", NextHeight()));
}

std::shared_ptr<const SetSnapshot> Snapshot()
{
    auto snap = TipSnapshot();
    if (!snap) throw JSONRPCError(RPC_INTERNAL_ERROR, "the vault database is not available");
    return snap;
}

std::string TagHex(const Tag& t) { return HexStr(t.begin(), t.end()); }

std::string TagText(const Tag& t)
{
    std::string s;
    for (unsigned char c : t) {
        if (c == 0) break;
        s.push_back(c >= 0x20 && c < 0x7f ? (char)c : '?');
    }
    return s;
}

Tag ParseTag(const UniValue& v)
{
    std::string s = v.get_str();
    Tag t{};
    if (s.size() == 8 && IsHex(s)) {
        std::vector<unsigned char> b = ParseHex(s);
        std::copy(b.begin(), b.end(), t.begin());
        return t;
    }
    if (s.empty() || s.size() > 4) throw JSONRPCError(RPC_INVALID_PARAMETER, "tag must be 1-4 ASCII characters (zero-padded) or 8 hex digits");
    std::copy(s.begin(), s.end(), t.begin());
    return t;
}

SetId ParseSetId(const UniValue& v, const std::string& name) { return ParseHashV(v, name); }

CPubKey ParseKey(const UniValue& v, const std::string& name)
{
    std::vector<unsigned char> b = ParseHexV(v, name);
    CPubKey k(b.begin(), b.end());
    if (!IsCompressedKey(k) || !k.IsFullyValid()) throw JSONRPCError(RPC_INVALID_PARAMETER, name + " must be a valid compressed public key");
    return k;
}

/** The `pqkeyid` JSON type (quantum spec §6.2): 66 hex digits scheme || keyHash (the hash's
 *  internal bytes, as pushed in V), scheme registered. */
std::string PQKeyIdHex(const CPQKeyID& id)
{
    std::vector<unsigned char> b(1, id.scheme);
    b.insert(b.end(), id.hash.begin(), id.hash.end());
    return HexStr(b.begin(), b.end());
}

/** A pqkeyid (66 hex), a PQ Yellowback address of this network ("yb…"/"yt…"/"yr…", 53 characters) or a plain-YEC
 *  PQ address ("sq…"/"tq…"/"rq…", D-Q-20). */
CPQKeyID ParsePQKeyId(const UniValue& v, const std::string& name)
{
    const std::string s = v.get_str();
    CPQKeyID id;
    if (s.size() == 66 && IsHex(s)) {
        std::vector<unsigned char> b = ParseHex(s);
        id = CPQKeyID(b[0], uint256(std::vector<unsigned char>(b.begin() + 1, b.end())));
    } else if (!yellowback::DecodeAddress(s, yellowback::ParamsForNetwork(Params().NetworkIDString()), id)) {
        const CTxDestination d = KeyIO(Params()).DecodeDestination(s);
        const CPQKeyID* pq = std::get_if<CPQKeyID>(&d);
        if (!pq) throw JSONRPCError(RPC_INVALID_PARAMETER, name + " must be a pqkeyid (66 hex digits, scheme || keyhash) or a PQ address");
        id = *pq;
    }
    if (!IsOwnerValid(id)) throw JSONRPCError(RPC_INVALID_PARAMETER, name + ": unregistered post-quantum scheme");
    return id;
}

COutPoint ParseOutPoint(const UniValue& v, const std::string& name)
{
    if (v.isObject()) {
        const UniValue& vout = find_value(v.get_obj(), "vout");
        if (!vout.isNum() || vout.get_int() < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, name + ": vout must be a non-negative number");
        return COutPoint(ParseHashO(v, "txid"), (uint32_t)vout.get_int());
    }
    std::string s = v.get_str();
    size_t colon = s.find(':');
    if (colon == std::string::npos) throw JSONRPCError(RPC_INVALID_PARAMETER, name + " must be \"txid:n\" or {\"txid\",\"vout\"}");
    int64_t n = 0;
    if (!ParseInt64(s.substr(colon + 1), &n) || n < 0 || n > 0xffffffffLL) throw JSONRPCError(RPC_INVALID_PARAMETER, name + ": bad output index");
    return COutPoint(ParseHashV(UniValue(s.substr(0, colon)), name), (uint32_t)n);
}

std::string OutPointStr(const COutPoint& o) { return o.hash.GetHex() + ":" + std::to_string(o.n); }

CScript ParseRecipient(const UniValue& o)
{
    const UniValue& addr = find_value(o, "address");
    const UniValue& script = find_value(o, "script");
    if (!addr.isNull() == !script.isNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "a recipient needs exactly one of \"address\" or \"script\"");
    if (!addr.isNull()) {
        KeyIO keyIO(Params());
        CTxDestination dest = keyIO.DecodeDestination(addr.get_str());
        if (!IsValidDestination(dest)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "invalid transparent address: " + addr.get_str());
        return GetScriptForDestination(dest);
    }
    std::vector<unsigned char> b = ParseHexV(script, "script");
    return CScript(b.begin(), b.end());
}

std::string ScriptAddress(const CScript& spk)
{
    CTxDestination dest;
    if (!ExtractDestination(spk, dest)) return "";
    return KeyIO(Params()).EncodeDestination(dest);
}

/** The coin at `out` from the chain tip and the mempool. */
bool GetCoin(const COutPoint& out, CTxOut& txout, int& height)
{
    LOCK(mempool.cs);
    CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
    CCoinsViewCache view(&viewMemPool);
    const CCoins* coins = view.AccessCoins(out.hash);
    if (!coins || !coins->IsAvailable(out.n)) return false;
    txout = coins->vout[out.n];
    height = coins->nHeight == MEMPOOL_HEIGHT ? -1 : (int)coins->nHeight;
    return true;
}

/** 6.20.0: the precomputed sighash data takes every input's coin (built from the chain tip and the
 *  mempool, an unknown coin as an empty output). The placeholders are inert because only a v4
 *  (ZIP-243) sighash ignores them: a non-v4 transaction is refused (quantum spec R-A3). */
PrecomputedTransactionData TxData(const CTransaction& tx)
{
    if (tx.nVersionGroupId != SAPLING_VERSION_GROUP_ID)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "non-v4 transaction (R-A3): the vault opcodes are defined over the ZIP-243 sighash of v4 transactions only");
    std::vector<CTxOut> allPrevOutputs;
    for (const CTxIn& in : tx.vin) {
        CTxOut prev;
        int h;
        if (!GetCoin(in.prevout, prev, h)) prev = CTxOut();
        allPrevOutputs.push_back(prev);
    }
    return PrecomputedTransactionData(tx, allPrevOutputs);
}

UniValue VaultParamsJSON(const VaultParams& p)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("tag", TagHex(p.tag));
    o.pushKV("tagtext", TagText(p.tag));
    o.pushKV("setid", p.setId.GetHex());
    o.pushKV("cancelsetid", p.cancelSetId.GetHex());
    o.pushKV("delay", p.delay);
    o.pushKV("ownerheight", p.ownerHeight);
    o.pushKV("appheight", p.appHeight);
    o.pushKV("owner", PQKeyIdHex(p.owner));
    o.pushKV("ownerscheme", (int)p.owner.scheme);
    return o;
}

UniValue IntentParamsJSON(const IntentParams& p)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("tag", TagHex(p.tag));
    o.pushKV("tagtext", TagText(p.tag));
    o.pushKV("setid", p.setId.GetHex());
    o.pushKV("cancelsetid", p.cancelSetId.GetHex());
    o.pushKV("delay", p.delay);
    o.pushKV("owner", PQKeyIdHex(p.owner));
    o.pushKV("ownerscheme", (int)p.owner.scheme);
    o.pushKV("recipienthash", HexStr(p.recipientHash.begin(), p.recipientHash.end()));
    o.pushKV("vaulthash", HexStr(p.vaultHash.begin(), p.vaultHash.end()));
    return o;
}

const char* StatusName(uint8_t s)
{
    switch (s) {
    case MEMBER_ACTIVE: return "active";
    case MEMBER_REMOVED: return "removed";
    case MEMBER_EJECTED: return "ejected";
    case MEMBER_WITHDRAWN: return "withdrawn";
    }
    return "unknown";
}

const char* ActTypeName(uint8_t t)
{
    switch (t) {
    case ACT_SET_CREATE: return "create";
    case ACT_SET_JOIN: return "join";
    case ACT_SET_HEARTBEAT: return "heartbeat";
    case ACT_SET_REMOVE: return "remove";
    case ACT_SET_EQUIVOCATION: return "equivocation";
    case ACT_SET_WINDDOWN: return "winddown";
    }
    return "unknown";
}

uint8_t ParseActType(const UniValue& v)
{
    if (v.isNum()) return (uint8_t)v.get_int();
    const std::string s = v.get_str();
    for (uint8_t t = ACT_SET_CREATE; t <= ACT_SET_WINDDOWN; t++) {
        if (s == ActTypeName(t) || s == std::string("set_") + ActTypeName(t)) return t;
    }
    throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown act type " + s + " (create, join, heartbeat, remove, equivocation, winddown)");
}

UniValue SetJSON(const SetId& id, const SetRecord& s, const MemberList& members, int64_t h, bool withMembers, const KVReader* kv = nullptr);

#ifdef ENABLE_WALLET
bool WalletHasKey(const CPubKey& k) { return pwalletMain && pwalletMain->HaveKey(k.GetID()); }
#else
bool WalletHasKey(const CPubKey&) { return false; }
#endif
#ifdef ENABLE_WALLET
/** Whether this wallet holds the PQ owner key (quantum plan §4.6). */
bool WalletHasPQKey(const CPQKeyID& id) { return pwalletMain && pwalletMain->HavePQKey(id); }
#else
bool WalletHasPQKey(const CPQKeyID&) { return false; }
#endif

UniValue SetJSON(const SetId& id, const SetRecord& s, const MemberList& members, int64_t h, bool withMembers, const KVReader* kv)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("setid", id.GetHex());
    o.pushKV("height", h);
    o.pushKV("seats", s.params.seats);
    o.pushKV("unlockthreshold", s.params.unlockThreshold);
    o.pushKV("cancelthreshold", s.params.cancelThreshold);
    o.pushKV("slashthreshold", s.params.slashThreshold);
    o.pushKV("open", s.params.IsOpen());
    o.pushKV("ratelimitbps", s.params.rateLimitBps);
    o.pushKV("ratewindow", (int64_t)s.params.rateWindow);
    o.pushKV("livenesswindow", (int64_t)s.params.livenessWindow);
    o.pushKV("bondmin", ValueFromAmount(s.params.bondMin));
    o.pushKV("bondlockmin", (int64_t)s.params.bondLockMin);
    o.pushKV("maturity", (int64_t)s.params.maturity);
    o.pushKV("admitkey", HexStr(s.params.admitKey.begin(), s.params.admitKey.end()));
    o.pushKV("createheight", s.createHeight);
    o.pushKV("winddownheight", s.windDownHeight);
    o.pushKV("lockedvalue", ValueFromAmount(s.lockedValue));
    o.pushKV("epoch", s.epoch);
    o.pushKV("epochbasis", ValueFromAmount(s.epochBasis));
    o.pushKV("epochused", ValueFromAmount(s.epochUsed));
    // The epoch fields as they stand at h (U-20 rolls them lazily on the next change).
    const int64_t e = h / (int64_t)s.params.rateWindow;
    const CAmount basis = e == s.epoch ? s.epochBasis : s.lockedValue;
    const CAmount used = e == s.epoch ? s.epochUsed : 0;
    if (s.params.rateLimitBps != 0) {
        const CAmount cap = RateCap(basis, s.params.rateLimitBps);
        o.pushKV("unlockavailable", ValueFromAmount(cap > used ? cap - used : 0));
    }
    o.pushKV("members", (int)members.size());
    o.pushKV("active", CountActive(members));
    o.pushKV("current", CountCurrent(s, members, h));
    o.pushKV("dormant", IsDormant(s, members, h));
    o.pushKV("released", IsReleased(std::optional<SetRecord>(s), members, h));
    if (withMembers) {
        UniValue arr(UniValue::VARR);
        const int64_t since = h - (int64_t)s.params.livenessWindow;
        for (const auto& m : members) {
            UniValue mo(UniValue::VOBJ);
            mo.pushKV("key", HexStr(m.first.begin(), m.first.end()));
            mo.pushKV("status", StatusName(m.second.status));
            mo.pushKV("current", IsCurrent(s, m.second, h));
            mo.pushKV("live", IsCurrent(s, m.second, h) && m.second.lastAct >= since);
            mo.pushKV("joinheight", m.second.joinHeight);
            mo.pushKV("lastact", m.second.lastAct);
            mo.pushKV("bondoutpoint", OutPointStr(m.second.bondOutpoint));
            mo.pushKV("bondvalue", ValueFromAmount(m.second.bondValue));
            mo.pushKV("bondlocktime", (int64_t)m.second.bondLocktime);
            mo.pushKV("bondfrozen", m.second.bondFrozen);
            // the bond exit delay (seats re-review): when the member's bond is still indexed and its member has left
            if (kv) {
                if (auto b = GetBond(*kv, m.second.bondOutpoint)) {
                    if (b->exitHeight != 0) {
                        mo.pushKV("exitheight", b->exitHeight);
                        mo.pushKV("unlockheight", b->exitHeight + (int64_t)s.params.maturity);
                    }
                }
            }
            mo.pushKV("wallet", WalletHasKey(m.first));
            arr.push_back(mo);
        }
        o.pushKV("memberlist", arr);
    }
    return o;
}

UniValue TemplateOutJSON(const COutPoint& op, const TemplateOutRecord& rec, int64_t next)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("txid", op.hash.GetHex());
    o.pushKV("vout", (int64_t)op.n);
    o.pushKV("outpoint", OutPointStr(op));
    o.pushKV("kind", rec.kind == 0 ? "vault" : "intent");
    o.pushKV("value", ValueFromAmount(rec.value));
    o.pushKV("valuezat", rec.value);
    o.pushKV("height", rec.height);
    o.pushKV("script", HexStr(rec.scriptPubKey.begin(), rec.scriptPubKey.end()));
    VaultParams vp;
    IntentParams ip;
    if (rec.kind == 0 && ParseVault(rec.scriptPubKey, vp)) {
        o.pushKVs(VaultParamsJSON(vp));
        o.pushKV("wallet", WalletHasPQKey(vp.owner));
    } else if (rec.kind == 1 && ParseIntent(rec.scriptPubKey, ip)) {
        o.pushKVs(IntentParamsJSON(ip));
        o.pushKV("matureheight", rec.height + ip.delay);
        o.pushKV("mature", next >= rec.height + ip.delay);
        o.pushKV("cancellable", next - rec.height < ip.delay);
        o.pushKV("origin", HexStr(rec.origin.begin(), rec.origin.end()));
        o.pushKV("wallet", WalletHasPQKey(ip.owner));
    }
    return o;
}

// ---- read RPCs ------------------------------------------------------------------------------

UniValue vault_getinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "vault_getinfo\n"
            "\nThe vault primitive's upgrade and set-state database (docs/vault-rpc.md).\n"
            "\nResult:\n"
            "{\n"
            "  \"branchid\": \"6d5b7a31\",   (string) this network's UPGRADE_VAULT consensus branch ID (testnet-yb-slow: its own)\n"
            "  \"activationheight\": n,    (numeric) -1 when not scheduled\n"
            "  \"active\": true|false,     (boolean) active at the next block\n"
            "  \"height\": n,              (numeric) the chain tip\n"
            "  \"attestorsetid\": \"hex\" | null, (string) the set the registered module governs (the YED attestor set;\n"
            "                             regtest: -yellowbackattestorset), null when none: then the module validates inertly\n"
            "  \"moduleactive\": true|false, (boolean) a registered module governs a set on this node\n"
            "  \"dbtip\": {\"hash\",\"height\"} | null,  the block the set state is at\n"
            "  \"sets\": n, \"vaults\": n, \"intents\": n, \"lockedvalue\": x.xxx,\n"
            "  \"statehash\": \"hex\"        (string) digest of the whole set state\n"
            "}\n"
            + HelpExampleCli("vault_getinfo", "") + HelpExampleRpc("vault_getinfo", ""));
    LOCK(cs_main);
    const Consensus::Params& cp = Params().GetConsensus();
    UniValue o(UniValue::VOBJ);
    o.pushKV("branchid", HexInt(NetworkBranchId(Consensus::UPGRADE_VAULT, cp)));   // the network's own (testnet shadow fork)
    const int act = cp.vUpgrades[Consensus::UPGRADE_VAULT].nActivationHeight;
    o.pushKV("activationheight", act == Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT ? -1 : act);
    o.pushKV("active", ActiveAtNext());
    o.pushKV("height", chainActive.Height());
    // 01/V-7: until P8 makes the attestor set a chain parameter, it is a node parameter on regtest, and a node
    // without it computes another set state (the module's hooks are inert): make the configured set comparable.
    std::optional<SetId> governed;
    for (const auto& entry : Modules()) {
        if ((governed = entry.second->GovernedSet())) break;
    }
    o.pushKV("attestorsetid", governed ? UniValue(governed->GetHex()) : NullUniValue);
    o.pushKV("moduleactive", governed.has_value());
    if (!g_vaultdb) {
        o.pushKV("dbtip", NullUniValue);
        return o;
    }
    uint256 tipHash;
    int64_t tipHeight;
    if (g_vaultdb->GetTip(tipHash, tipHeight)) {
        UniValue t(UniValue::VOBJ);
        t.pushKV("hash", tipHash.GetHex());
        t.pushKV("height", tipHeight);
        o.pushKV("dbtip", t);
    } else {
        o.pushKV("dbtip", NullUniValue);
    }
    o.pushKV("sets", (int)ListSets(*g_vaultdb).size());
    int nv = 0, ni = 0;
    CAmount locked = 0;
    for (const auto& t : ListTemplateOuts(*g_vaultdb)) {
        if (t.second.kind == 0) { nv++; locked += t.second.value; }
        else ni++;
    }
    o.pushKV("vaults", nv);
    o.pushKV("intents", ni);
    o.pushKV("lockedvalue", ValueFromAmount(locked));
    o.pushKV("statehash", StateHash(*g_vaultdb).GetHex());
    return o;
}

UniValue set_list(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "set_list\n"
            "\nEvery signer set, with its parameters and status at the next block (no member list; see set_getinfo).\n"
            + HelpExampleCli("set_list", "") + HelpExampleRpc("set_list", ""));
    LOCK(cs_main);
    auto snap = Snapshot();
    const int64_t h = NextHeight();
    UniValue arr(UniValue::VARR);
    for (const SetId& id : ListSets(snap->Base())) {
        auto s = snap->GetSet(id);
        if (!s) continue;
        arr.push_back(SetJSON(id, *s, snap->GetMembers(id), h, false));
    }
    return arr;
}

UniValue set_getinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "set_getinfo \"setid\" ( height )\n"
            "\nOne signer set: its SET_CREATE parameters, rate fields, members and their status, and whether the set is\n"
            "current / dormant / released, evaluated at `height` (default: the next block) over the state at the tip.\n"
            "\nArguments:\n"
            "1. \"setid\"   (string, required) the txid of the set's SET_CREATE transaction\n"
            "2. height     (numeric, optional) the height to evaluate the §15.4 predicates at\n"
            + HelpExampleCli("set_getinfo", "\"setid\"") + HelpExampleRpc("set_getinfo", "\"setid\", 120"));
    LOCK(cs_main);
    auto snap = Snapshot();
    const SetId id = ParseSetId(params[0], "setid");
    int64_t h = NextHeight();
    if (params.size() > 1 && !params[1].isNull()) {
        h = params[1].get_int64();
        if (h < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "height must be >= 0");
    }
    auto s = snap->GetSet(id);
    if (!s) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "unknown set " + id.GetHex());
    return SetJSON(id, *s, snap->GetMembers(id), h, true, &snap->Base());
}

UniValue vault_list(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "vault_list ( {\"tag\":\"..\",\"setid\":\"..\",\"owner\":\"..\",\"kind\":\"vault|intent\",\"mine\":true} )\n"
            "\nThe unspent vault (V) and intent (I) outputs confirmed since activation, from the vault database's index,\n"
            "optionally filtered by tag, setid (matches setid or cancelsetid), owner (pqkeyid or PQ address), kind, or owner key in this wallet.\n"
            + HelpExampleCli("vault_list", "'{\"setid\":\"..\"}'") + HelpExampleRpc("vault_list", "{}"));
    LOCK(cs_main);
    auto snap = Snapshot();
    std::optional<Tag> tag;
    std::optional<SetId> setId;
    std::optional<CPQKeyID> owner;
    std::optional<int> kind;
    bool mine = false;
    if (params.size() > 0 && !params[0].isNull()) {
        const UniValue& f = params[0].get_obj();
        if (!find_value(f, "tag").isNull()) tag = ParseTag(find_value(f, "tag"));
        if (!find_value(f, "setid").isNull()) setId = ParseSetId(find_value(f, "setid"), "setid");
        if (!find_value(f, "owner").isNull()) owner = ParsePQKeyId(find_value(f, "owner"), "owner");
        if (!find_value(f, "kind").isNull()) {
            const std::string k = find_value(f, "kind").get_str();
            if (k != "vault" && k != "intent") throw JSONRPCError(RPC_INVALID_PARAMETER, "kind must be vault or intent");
            kind = k == "vault" ? 0 : 1;
        }
        if (!find_value(f, "mine").isNull()) mine = find_value(f, "mine").get_bool();
    }
    UniValue arr(UniValue::VARR);
    for (const auto& t : ListTemplateOuts(snap->Base())) {
        VaultParams vp;
        IntentParams ip;
        Tag tt{};
        SetId s1, s2;
        CPQKeyID ok;
        if (t.second.kind == 0 && ParseVault(t.second.scriptPubKey, vp)) {
            tt = vp.tag; s1 = vp.setId; s2 = vp.cancelSetId; ok = vp.owner;
        } else if (t.second.kind == 1 && ParseIntent(t.second.scriptPubKey, ip)) {
            tt = ip.tag; s1 = ip.setId; s2 = ip.cancelSetId; ok = ip.owner;
        } else {
            continue;
        }
        if (kind && *kind != t.second.kind) continue;
        if (tag && *tag != tt) continue;
        if (setId && *setId != s1 && *setId != s2) continue;
        if (owner && *owner != ok) continue;
        if (mine && !WalletHasPQKey(ok)) continue;
        arr.push_back(TemplateOutJSON(t.first, t.second, NextHeight()));
    }
    return arr;
}

UniValue ActJSON(const Act& act, const std::optional<COutPoint>& vin0)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("type", ActTypeName(act.type));
    switch (act.type) {
    case ACT_SET_CREATE: {
        const SetCreateBody& c = act.create;
        o.pushKV("seats", c.seats);
        o.pushKV("unlockthreshold", c.unlockThreshold);
        o.pushKV("cancelthreshold", c.cancelThreshold);
        o.pushKV("slashthreshold", c.slashThreshold);
        o.pushKV("open", c.IsOpen());
        o.pushKV("ratelimitbps", c.rateLimitBps);
        o.pushKV("ratewindow", (int64_t)c.rateWindow);
        o.pushKV("livenesswindow", (int64_t)c.livenessWindow);
        o.pushKV("bondmin", ValueFromAmount(c.bondMin));
        o.pushKV("bondlockmin", (int64_t)c.bondLockMin);
        o.pushKV("maturity", (int64_t)c.maturity);
        o.pushKV("admitkey", HexStr(c.admitKey.begin(), c.admitKey.end()));
        break;
    }
    case ACT_SET_JOIN:
        o.pushKV("setid", act.join.setId.GetHex());
        o.pushKV("memberkey", HexStr(act.join.memberKey.begin(), act.join.memberKey.end()));
        o.pushKV("bondlocktime", (int64_t)act.join.bondLocktime);
        o.pushKV("bondvout", act.join.bondVout);
        break;
    case ACT_SET_HEARTBEAT:
        o.pushKV("setid", act.heartbeat.setId.GetHex());
        o.pushKV("memberkey", HexStr(act.heartbeat.memberKey.begin(), act.heartbeat.memberKey.end()));
        break;
    case ACT_SET_REMOVE:
        o.pushKV("setid", act.remove.setId.GetHex());
        o.pushKV("memberkey", HexStr(act.remove.memberKey.begin(), act.remove.memberKey.end()));
        o.pushKV("burn", act.remove.burn);
        break;
    case ACT_SET_EQUIVOCATION: {
        const SetEquivocationBody& e = act.equivocation;
        o.pushKV("setid", e.setId.GetHex());
        o.pushKV("prevout", OutPointStr(e.prevout));
        o.pushKV("rolea", e.roleA);
        o.pushKV("sighasha", HexStr(e.sighashA.begin(), e.sighashA.end()));
        o.pushKV("siga", HexStr(e.sigA));
        o.pushKV("roleb", e.roleB);
        o.pushKV("sighashb", HexStr(e.sighashB.begin(), e.sighashB.end()));
        o.pushKV("sigb", HexStr(e.sigB));
        break;
    }
    case ACT_SET_WINDDOWN:
        o.pushKV("setid", act.winddown.setId.GetHex());
        break;
    }
    UniValue sigs(UniValue::VARR);
    std::vector<unsigned char> P = EncodePayload(act);
    for (const auto& sig : act.sigs) {
        UniValue so(UniValue::VOBJ);
        so.pushKV("sig", HexStr(sig));
        CPubKey k;
        if (vin0 && RecoverSig(ActMsg(P, *vin0), sig, k)) so.pushKV("key", HexStr(k.begin(), k.end()));
        sigs.push_back(so);
    }
    o.pushKV("signatures", sigs);
    return o;
}

UniValue vault_decodescript(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "vault_decodescript \"hex\"\n"
            "\nDecode a vault primitive script: a vault V or intent I scriptPubKey, a `YV` act OP_RETURN, or a member\n"
            "bond B redeem script. Returns {\"type\": \"vault\"|\"intent\"|\"act\"|\"bond\"|\"none\", ...fields}.\n"
            + HelpExampleCli("vault_decodescript", "\"hex\"") + HelpExampleRpc("vault_decodescript", "\"hex\""));
    std::vector<unsigned char> b = ParseHexV(params[0], "hex");
    CScript s(b.begin(), b.end());
    UniValue o(UniValue::VOBJ);
    VaultParams vp;
    IntentParams ip;
    uint32_t locktime;
    CPubKey key;
    Shape vs = MatchVault(s, vp);
    Shape is = MatchIntent(s, ip);
    if (vs == Shape::MATCH) {
        o.pushKV("type", "vault");
        o.pushKVs(VaultParamsJSON(vp));
    } else if (is == Shape::MATCH) {
        o.pushKV("type", "intent");
        o.pushKVs(IntentParamsJSON(ip));
    } else if (vs == Shape::MALFORMED || is == Shape::MALFORMED) {
        o.pushKV("type", "malformed");
    } else if (IsActOutput(s)) {
        Act act;
        if (auto err = DecodeAct(s, act)) {
            o.pushKV("type", "act");
            o.pushKV("error", *err);
        } else {
            o.pushKV("type", "act");
            // The body's own "type" would duplicate the key; it is "acttype" here.
            UniValue body = ActJSON(act, std::nullopt);
            for (size_t i = 0; i < body.size(); ++i)
                o.pushKV(body.getKeys()[i] == "type" ? "acttype" : body.getKeys()[i], body.getValues()[i]);
            std::vector<unsigned char> P = EncodePayload(act);
            o.pushKV("payload", HexStr(P));
        }
    } else if (ParseBondRedeem(s, locktime, key)) {
        o.pushKV("type", "bond");
        o.pushKV("locktime", (int64_t)locktime);
        o.pushKV("memberkey", HexStr(key.begin(), key.end()));
        CScript p2sh = GetScriptForDestination(CScriptID(s));
        o.pushKV("scriptpubkey", HexStr(p2sh.begin(), p2sh.end()));
        o.pushKV("address", ScriptAddress(p2sh));
    } else {
        o.pushKV("type", "none");
    }
    return o;
}

#ifdef ENABLE_WALLET

// ---- wallet helpers ---------------------------------------------------------------------------

// Recipient scripts this wallet built intents for (vault_buildunlock / vault_app), so that vault_release can find
// a recipient the wallet does not own, and the last UNLOCK / CANCEL built per template outpoint (vault_buildunlock /
// vault_buildcancel), returned byte-identical so members asked twice sign one sighash (sign once,
// SET_EQUIVOCATION): CWallet::mapVaultRecipients / mapVaultBuilds, persisted in the wallet (01/V-2, 07/N-2), so a
// restart keeps them and the builds' fee inputs stay locked.

void EnsureWallet(bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) throw JSONRPCError(RPC_METHOD_NOT_FOUND, "the wallet is disabled");
    EnsureWalletIsUnlocked();
}

CPubKey NewWalletKey()
{
    CPubKey k = pwalletMain->GenerateNewKey(true); // 6.20.0: a fresh external HD key, as getnewaddress
    if (!IsCompressedKey(k)) throw JSONRPCError(RPC_WALLET_ERROR, "the wallet produced an uncompressed key");
    return k;
}

/** The key named by `v` (must be in the wallet), or a new wallet key when `v` is null. */
CPubKey WalletKeyParam(const UniValue& v, const std::string& name)
{
    if (v.isNull()) return NewWalletKey();
    CPubKey k = ParseKey(v, name);
    if (!pwalletMain->HaveKey(k.GetID())) throw JSONRPCError(RPC_WALLET_ERROR, name + " is not a key in this wallet");
    return k;
}

/** The script flags a wallet-signed input is checked under: standard, plus the vault flags of the
 *  next block (OP_CHECKPQSIG is a bad opcode without SCRIPT_VERIFY_VAULT; quantum spec §5.2). */
unsigned int SignFlags() { return STANDARD_SCRIPT_VERIFY_FLAGS | GetVaultScriptFlags(NextHeight(), Params().GetConsensus()); }

/** A new post-quantum key of scheme from this wallet's HD seed (quantum plan §4.6). Scheme 2
 *  (FN-DSA-512) only once Falcon is active at the next block (IsPQFalconActive). */
CPQKeyID NewWalletPQKey(uint8_t scheme)
{
    if (!pq::IsKnownScheme(scheme)) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("unknown post-quantum scheme %d (1 = SLH-DSA-SHA2-128s, 2 = FN-DSA-512)", scheme));
    if (scheme == pq::SCHEME_FN_DSA_512 && !IsPQFalconActive(Params().GetConsensus(), NextHeight()))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "scheme 2 (FN-DSA-512) is not active at the next block");
    CPQKeyID id;
    if (!pwalletMain->GetNewPQKey(scheme, id)) throw JSONRPCError(RPC_WALLET_ERROR, "cannot derive a post-quantum key (the wallet has no HD seed or is locked)");
    return id;
}

/** A vault owner: a pqkeyid (66 hex), a PQ address, or {"scheme": n, "keyhash": "64 hex"} (the hash's
 *  bytes as pushed in V, as in vault_getnewowner). */
CPQKeyID ParsePQOwner(const UniValue& v, const std::string& name)
{
    if (!v.isObject()) return ParsePQKeyId(v, name);
    const UniValue& sc = find_value(v.get_obj(), "scheme");
    if (!sc.isNum()) throw JSONRPCError(RPC_INVALID_PARAMETER, name + ".scheme must be a number");
    std::vector<unsigned char> h = ParseHexV(find_value(v.get_obj(), "keyhash"), name + ".keyhash");
    if (h.size() != 32) throw JSONRPCError(RPC_INVALID_PARAMETER, name + ".keyhash must be 32 bytes (64 hex digits)");
    const int scheme = sc.get_int();
    if (scheme < 0 || scheme > 255) throw JSONRPCError(RPC_INVALID_PARAMETER, name + ": unregistered post-quantum scheme");
    CPQKeyID id((uint8_t)scheme, uint256(h));
    if (!IsOwnerValid(id)) throw JSONRPCError(RPC_INVALID_PARAMETER, name + ": unregistered post-quantum scheme");
    return id;
}

CKey WalletPrivKey(const CPubKey& k)
{
    CKey key;
    if (!pwalletMain->GetKey(k.GetID(), key)) throw JSONRPCError(RPC_WALLET_ERROR, "the wallet has no private key for " + HexStr(k.begin(), k.end()));
    return key;
}

CMutableTransaction NewTx()
{
    CMutableTransaction mtx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), NextHeight(), /* requireV4 */ true);
    mtx.nExpiryHeight = 0; // built here, signed by other nodes, sent later: no expiry
    return mtx;
}

/** How Fund picks coins: LARGEST_FIRST (fewest inputs); SMALL_CHANGE (the smallest single coin that covers the need,
 *  else LARGEST_FIRST: a set-signed build's change output is bound by the set signatures, so whoever re-funds it
 *  (vault_refee) pays it; keep it small). */
enum class FundMode { LARGEST_FIRST, SMALL_CHANGE };

/** This wallet's confirmed, spendable, unlocked P2PKH coins outside `used`, largest first -- each also unspent in the
 *  node's UTXO view (pcoinsTip + mempool, GetCoin): the wallet learns of a block's spends on its own notification
 *  thread, so right after a block it can still count a coin the block spent as unspent (refee-utxo). */
std::vector<std::pair<COutPoint, CAmount>> EligibleCoins(const std::set<COutPoint>& used)
{
    AssertLockHeld(cs_main);
    std::vector<COutput> coins;
    pwalletMain->AvailableCoins(coins, std::nullopt, true, NULL, false, true);
    std::sort(coins.begin(), coins.end(), [](const COutput& a, const COutput& b) { return a.Value() > b.Value(); });
    std::vector<std::pair<COutPoint, CAmount>> eligible;
    for (const COutput& c : coins) {
        if (!c.fSpendable || c.nDepth < 1) continue;
        const CScript& spk = c.tx->vout[c.i].scriptPubKey;
        txnouttype t;
        std::vector<std::vector<unsigned char>> sol;
        if (!Solver(spk, t, sol) || t != TX_PUBKEYHASH) continue;
        COutPoint op(c.tx->GetHash(), c.i);
        if (used.count(op)) continue;
        CTxOut utxo;
        int height;
        if (!GetCoin(op, utxo, height) || height < 0 || utxo != c.tx->vout[c.i]) continue;   // spent, or not confirmed
        eligible.emplace_back(op, c.Value());
    }
    return eligible;
}

/** Add wallet P2PKH inputs (and a change output) so that inputs = outputs + VAULT_RPC_FEE, given
 *  `inputValue` already provided by the transaction's existing inputs. Inputs are locked in the
 *  wallet so a following build does not pick them before this one confirms. */
void Fund(CMutableTransaction& mtx, CAmount inputValue, FundMode mode = FundMode::LARGEST_FIRST)
{
    CAmount out = 0;
    for (const CTxOut& o : mtx.vout) out += o.nValue;
    CAmount needed = out + VAULT_RPC_FEE - inputValue;
    std::set<COutPoint> used;
    for (const CTxIn& in : mtx.vin) used.insert(in.prevout);
    const std::vector<std::pair<COutPoint, CAmount>> eligible = EligibleCoins(used);
    CAmount got = 0;
    std::vector<COutPoint> chosen;
    if (needed > 0 && mode != FundMode::LARGEST_FIRST) {
        // the smallest single coin that covers the need (eligible is sorted largest first)
        for (auto it = eligible.rbegin(); it != eligible.rend(); ++it) {
            if (it->second >= needed) { chosen.push_back(it->first); got = it->second; break; }
        }
    }
    if (chosen.empty()) {
        for (const auto& e : eligible) {
            if (needed <= 0 || got >= needed) break;
            chosen.push_back(e.first);
            got += e.second;
        }
    }
    if (got < needed)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strprintf("insufficient confirmed transparent funds: need %s more", FormatMoney(needed - got)));
    for (const COutPoint& op : chosen) mtx.vin.push_back(CTxIn(op, CScript(), CTxIn::SEQUENCE_FINAL));
    const CAmount change = got - needed;
    if (change >= VAULT_RPC_MIN_CHANGE) {
        CPubKey ck = NewWalletKey();
        mtx.vout.push_back(CTxOut(change, GetScriptForDestination(ck.GetID())));
    }
    for (COutPoint& op : chosen) pwalletMain->LockCoin(op);
}

void RememberRecipient(const uint256& recipientHash, const CScript& dest)
{
    auto it = pwalletMain->mapVaultRecipients.find(recipientHash);
    if (it != pwalletMain->mapVaultRecipients.end() && it->second == dest) return;
    pwalletMain->mapVaultRecipients[recipientHash] = dest;
    if (!CWalletDB(pwalletMain->strWalletFile).WriteVaultRecipient(recipientHash, dest))
        throw JSONRPCError(RPC_WALLET_ERROR, "cannot record the intent's recipient in the wallet");
}

/** OP_CHECKSETSIG's digest of template input idx (01/V-2): SIGHASH_ALL | SIGHASH_ANYONECANPAY, so the fee inputs are
 *  not signed and a re-funded spend has the same sighash. */
uint256 SetSighash(const CMutableTransaction& mtx, size_t idx, const CTxOut& coin)
{
    const CTransaction txc(mtx);
    const PrecomputedTransactionData txdata = TxData(txc);
    return SignatureHash(coin.scriptPubKey, txc, idx, SIGHASH_ALL | SIGHASH_ANYONECANPAY, coin.nValue, NextBranchId(), txdata);
}

/** The fee inputs of a remembered build are unspent: in the chain, the wallet and the mempool. */
bool FeeInputsUnspent(const COutPoint& templ, const CMutableTransaction& c)
{
    for (const CTxIn& in : c.vin) {
        if (in.prevout == templ) continue;
        CTxOut fee;
        int fh;
        if (!GetCoin(in.prevout, fee, fh) || pwalletMain->IsSpent(in.prevout.hash, in.prevout.n, std::nullopt)) return false;
        LOCK(mempool.cs);
        if (mempool.mapNextTx.count(in.prevout)) return false;
    }
    return true;
}

/** Release the locks a build holds on its fee inputs (all inputs but the template input). */
void UnlockBuildInputs(const COutPoint& templ, const CMutableTransaction& c)
{
    for (const CTxIn& in : c.vin) {
        if (in.prevout == templ) continue;
        COutPoint op = in.prevout;
        pwalletMain->UnlockCoin(op);
    }
}

/** Forget the remembered builds whose template coin is gone (spent, or reorged away), releasing their locks. */
void PruneVaultBuilds()
{
    CWalletDB walletdb(pwalletMain->strWalletFile);
    for (auto it = pwalletMain->mapVaultBuilds.begin(); it != pwalletMain->mapVaultBuilds.end();) {
        CTxOut c;
        int h;
        if (GetCoin(it->first, c, h)) { ++it; continue; }
        UnlockBuildInputs(it->first, it->second);
        walletdb.EraseVaultBuild(it->first);
        it = pwalletMain->mapVaultBuilds.erase(it);
    }
}

/** True when this wallet has already added a set signature to a spend of `op` (set_signunlock / set_signcancel).
 *  A later rebuild may still return a different hex, so a caller can show the equivocation refusal, but it must
 *  not forget the fee inputs of the build that was signed: vault_send of that hex still has to sign them. */
bool WalletSignedPrevout(const COutPoint& op)
{
    std::vector<VaultSetSigRecord> recs;
    if (!CWalletDB(pwalletMain->strWalletFile).ListVaultSetSigs(recs)) return false;
    for (const VaultSetSigRecord& r : recs)
        if (r.prevout == op) return true;
    return false;
}

/** Remember the build of `key` (without that input's scriptSig: set signatures are not part of the sighash;
 *  an act's signatures live in its output and are kept). `key` is the template outpoint of a vault spend, or
 *  vin[0] of an act transaction. The wallet record is the existing "vaultbuild" row: dumpwallet / importwallet
 *  carry it and a keys-only salvage keeps it (MEDIUM-W3-07-NEW-1). That row is the hand-off registry, so there
 *  is no second "vaultfeein" record. */
void RememberBuild(const COutPoint& templ, CMutableTransaction mtx)
{
    for (CTxIn& in : mtx.vin)
        if (in.prevout == templ) in.scriptSig = CScript();
    pwalletMain->mapVaultBuilds[templ] = mtx;
    if (!CWalletDB(pwalletMain->strWalletFile).WriteVaultBuild(templ, mtx))
        throw JSONRPCError(RPC_WALLET_ERROR, "cannot record the vault build in the wallet");
}

void SignWalletInputs(CMutableTransaction& mtx);
uint256 Broadcast(const CTransaction& tx);

/** A wallet coin of exactly `value` for a re-funded spend, which can have no change output (its outputs are bound by
 *  the set signatures): an existing confirmed coin within VAULT_RPC_MIN_CHANGE above it, never one of `replacing`
 *  (the inputs being replaced), else a self-send of exactly `value` from this wallet's unspent coins (which may
 *  spend a still-unspent replaced input: the new coin differs from it), broadcast now (the re-funded spend chains on
 *  it in the mempool). Locked. */
COutPoint ExactCoin(CAmount value, const std::set<COutPoint>& exclude, const std::set<COutPoint>& replacing)
{
    std::set<COutPoint> notExact = exclude;
    notExact.insert(replacing.begin(), replacing.end());
    const std::vector<std::pair<COutPoint, CAmount>> eligible = EligibleCoins(notExact);
    for (auto it = eligible.rbegin(); it != eligible.rend(); ++it) {
        if (it->second >= value && it->second < value + VAULT_RPC_MIN_CHANGE) {
            COutPoint op = it->first;
            pwalletMain->LockCoin(op);
            return op;
        }
    }
    CMutableTransaction split = NewTx();
    split.vout.push_back(CTxOut(value, GetScriptForDestination(NewWalletKey().GetID())));
    Fund(split, 0);
    SignWalletInputs(split);
    COutPoint op(Broadcast(CTransaction(split)), 0);
    pwalletMain->LockCoin(op);
    return op;
}

/** Re-fund a set-signed spend (01/V-2): every input but the template input (kept with its scriptSig, moved to index
 *  0) is replaced by one coin of this wallet worth exactly what the outputs need beyond the template coin, plus
 *  VAULT_RPC_FEE; every output stays, so the set signatures stay valid and the sighash is unchanged. The fee is never
 *  taken from the template coin's value (S-2, I-1, I-2). */
std::vector<COutPoint> Refee(CMutableTransaction& mtx, size_t idx, const CTxOut& coin)
{
    const uint256 before = SetSighash(mtx, idx, coin);
    std::vector<COutPoint> old;
    for (size_t i = 0; i < mtx.vin.size(); i++)
        if (i != idx) old.push_back(mtx.vin[i].prevout);
    const CTxIn templ = mtx.vin[idx];
    // The old fee inputs this wallet locked are released first, so a still-unspent one can fund the new input (a split
    // of it, typically): the old transaction is abandoned either way. Re-locked if re-funding fails.
    std::vector<COutPoint> released;
    for (COutPoint op : old) {
        if (pwalletMain->IsLockedCoin(op.hash, op.n)) { pwalletMain->UnlockCoin(op); released.push_back(op); }
    }
    mtx.vin.assign(1, templ);
    CAmount out = 0;
    for (const CTxOut& o : mtx.vout) out += o.nValue;
    const CAmount needed = out + VAULT_RPC_FEE - coin.nValue;
    try {
        if (needed > 0)
            mtx.vin.push_back(CTxIn(ExactCoin(needed, {templ.prevout}, std::set<COutPoint>(old.begin(), old.end())), CScript(), CTxIn::SEQUENCE_FINAL));
    } catch (...) {
        for (COutPoint op : released) pwalletMain->LockCoin(op);
        throw;
    }
    if (SetSighash(mtx, 0, coin) != before)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "re-funding changed the set sighash");
    // Sanity (refee-utxo): every new input unspent in the node's view, none of them a replaced one, and a fee in
    // (0, cap]. Refused otherwise (the new input's lock is released).
    CAmount in = coin.nValue;
    for (size_t i = 1; i < mtx.vin.size(); i++) {
        CTxOut prev;
        int ph;
        const COutPoint& op = mtx.vin[i].prevout;
        if (!GetCoin(op, prev, ph) || std::find(old.begin(), old.end(), op) != old.end()) {
            UnlockBuildInputs(templ.prevout, mtx);
            for (COutPoint r : released) pwalletMain->LockCoin(r);
            throw JSONRPCError(RPC_WALLET_ERROR, "vault_refee: the new fee input " + op.ToString() + " is spent or is a replaced input; nothing was changed");
        }
        in += prev.nValue;
    }
    const CAmount fee = in - CTransaction(mtx).GetValueOut();
    if (fee <= 0 || fee > YedMaxTxFee()) {
        UnlockBuildInputs(templ.prevout, mtx);
        for (COutPoint r : released) pwalletMain->LockCoin(r);
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("vault_refee: the re-funded spend would pay a fee of %s (allowed: above 0, at most %s); nothing was changed",
                                                       FormatMoney(fee), FormatMoney(YedMaxTxFee())));
    }
    std::set<COutPoint> now;
    for (const CTxIn& in : mtx.vin) now.insert(in.prevout);
    for (COutPoint op : old)
        if (!now.count(op)) pwalletMain->UnlockCoin(op);
    return old;
}

/** Sign every input whose coin the wallet can sign (P2PKH and the like); template inputs and
 *  foreign inputs are left as they are. One-shot builders (vault_lock, set_create, vault_release, ...)
 *  use this: the hex never leaves the node. */
void SignWalletInputs(CMutableTransaction& mtx)
{
    const uint32_t branch = NextBranchId();
    for (unsigned int i = 0; i < mtx.vin.size(); i++) {
        CTxOut prev;
        int h;
        if (!GetCoin(mtx.vin[i].prevout, prev, h)) continue;
        VaultParams vp;
        IntentParams ip;
        if (MatchVault(prev.scriptPubKey, vp) != Shape::NONE || MatchIntent(prev.scriptPubKey, ip) != Shape::NONE) continue;
        if (IsMine(*pwalletMain, prev.scriptPubKey) != ISMINE_SPENDABLE) continue;
        if (!SignSignature(*pwalletMain, prev.scriptPubKey, mtx, TxData(CTransaction(mtx)), i, prev.nValue, SIGHASH_ALL, branch, SignFlags()))
            throw JSONRPCError(RPC_WALLET_ERROR, strprintf("cannot sign input %d", i));
    }
}

/** True when `memo` and `mtx` pay the same outputs. Act outputs compare with their signatures cleared:
 *  set_signact rewrites the act output, and a hand-off must still match the build that funded it. */
bool SameHandoffOutputs(const CMutableTransaction& memo, const CMutableTransaction& mtx)
{
    if (memo.vout.size() != mtx.vout.size()) return false;
    for (size_t i = 0; i < memo.vout.size(); i++) {
        const CTxOut& a = memo.vout[i];
        const CTxOut& b = mtx.vout[i];
        if (a.nValue != b.nValue) return false;
        if (IsActOutput(a.scriptPubKey) || IsActOutput(b.scriptPubKey)) {
            if (!IsActOutput(a.scriptPubKey) || !IsActOutput(b.scriptPubKey)) return false;
            Act aa, bb;
            if (DecodeAct(a.scriptPubKey, aa) || DecodeAct(b.scriptPubKey, bb)) return false;
            aa.sigs.clear();
            bb.sigs.clear();
            if (EncodeAct(aa) != EncodeAct(bb)) return false;
        } else if (a.scriptPubKey != b.scriptPubKey) {
            return false;
        }
    }
    return true;
}

/** Optional second argument of vault_send / set_sendact. */
struct HandoffOptions {
    bool dryrun = false;
    std::set<COutPoint> allowinputs;
    bool hasAllowOutflow = false;
    CAmount allowOutflow = 0;
};

HandoffOptions ParseHandoffOptions(const UniValue& params)
{
    HandoffOptions opt;
    if (params.size() < 2 || params[1].isNull()) return opt;
    if (!params[1].isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
    const UniValue& o = params[1].get_obj();
    const UniValue& dry = find_value(o, "dryrun");
    if (!dry.isNull()) {
        if (!dry.isBool()) throw JSONRPCError(RPC_INVALID_PARAMETER, "dryrun must be a boolean");
        opt.dryrun = dry.get_bool();
    }
    const UniValue& allow = find_value(o, "allowinputs");
    if (!allow.isNull()) {
        if (!allow.isArray()) throw JSONRPCError(RPC_INVALID_PARAMETER, "allowinputs must be an array of outpoints");
        for (size_t i = 0; i < allow.size(); i++)
            opt.allowinputs.insert(ParseOutPoint(allow[i], "allowinputs"));
    }
    const UniValue& flow = find_value(o, "allowoutflow");
    if (!flow.isNull()) {
        opt.hasAllowOutflow = true;
        opt.allowOutflow = AmountFromValue(flow);
    }
    return opt;
}

std::string OutputKind(const CScript& spk)
{
    if (IsActOutput(spk)) return "act";
    VaultParams vp;
    IntentParams ip;
    if (MatchVault(spk, vp) != Shape::NONE) return "vault";
    if (MatchIntent(spk, ip) != Shape::NONE) return "intent";
    uint32_t locktime;
    CPubKey key;
    if (ParseBondRedeem(spk, locktime, key)) return "bond";
    return "payment";
}

/** vault_send / set_sendact. A wallet coin is signed only when this wallet's remembered build for
 *  `buildKey` names it for these outputs, unless `allowinputs` names that outpoint. The wallet's net
 *  outflow (those inputs, minus outputs this wallet can spend and a SET_JOIN bond of a member key it
 *  holds) above the fee cap is refused unless `allowoutflow` covers it. `dryrun` returns the preview
 *  and signs nothing; otherwise a refusal throws and a pass signs. */
UniValue HandoffSend(CMutableTransaction& mtx, const COutPoint& buildKey, const HandoffOptions& opt, const UniValue& templ)
{
    auto it = pwalletMain->mapVaultBuilds.find(buildKey);
    const bool same = it != pwalletMain->mapVaultBuilds.end() && SameHandoffOutputs(it->second, mtx);
    std::set<COutPoint> funded;
    if (same)
        for (const CTxIn& in : it->second.vin) funded.insert(in.prevout);

    UniValue sign(UniValue::VARR), foreign(UniValue::VARR);
    CAmount signedIn = 0;
    std::string refuse;
    for (unsigned int i = 0; i < mtx.vin.size(); i++) {
        CTxOut prev;
        int h;
        if (!GetCoin(mtx.vin[i].prevout, prev, h)) continue;
        VaultParams vp;
        IntentParams ip;
        if (MatchVault(prev.scriptPubKey, vp) != Shape::NONE || MatchIntent(prev.scriptPubKey, ip) != Shape::NONE) continue;
        if (IsMine(*pwalletMain, prev.scriptPubKey) != ISMINE_SPENDABLE) continue;
        const bool chosen = same && funded.count(mtx.vin[i].prevout);
        UniValue row(UniValue::VOBJ);
        row.pushKV("vin", (int)i);
        row.pushKV("outpoint", mtx.vin[i].prevout.ToString());
        row.pushKV("amount", ValueFromAmount(prev.nValue));
        if (!chosen) {
            foreign.push_back(row);
            if (!opt.allowinputs.count(mtx.vin[i].prevout) && refuse.empty())
                refuse = strprintf("vault-send-foreign-input: input %d (%s, %s) is this wallet's coin but was not chosen by this wallet for these outputs; nothing was signed",
                                   i, mtx.vin[i].prevout.ToString(), FormatMoney(prev.nValue));
        }
        if (chosen || opt.allowinputs.count(mtx.vin[i].prevout)) {
            sign.push_back(row);
            signedIn += prev.nValue;
        }
    }

    std::set<unsigned int> own;
    UniValue actField(UniValue::VNULL);
    for (unsigned int i = 0; i < mtx.vout.size(); i++) {
        if (IsMine(*pwalletMain, mtx.vout[i].scriptPubKey) == ISMINE_SPENDABLE) own.insert(i);
        if (!actField.isNull() || !IsActOutput(mtx.vout[i].scriptPubKey)) continue;
        Act act;
        if (DecodeAct(mtx.vout[i].scriptPubKey, act)) continue;
        actField = ActJSON(act, mtx.vin.empty() ? std::nullopt : std::optional<COutPoint>(mtx.vin[0].prevout));
        if (act.type == ACT_SET_JOIN && pwalletMain->HaveKey(act.join.memberKey.GetID()) && act.join.bondVout < mtx.vout.size())
            own.insert(act.join.bondVout);
    }
    CAmount ownOut = 0;
    for (unsigned int i : own) ownOut += mtx.vout[i].nValue;
    const CAmount outflow = signedIn - ownOut;
    if (refuse.empty() && outflow > YedMaxTxFee() && !(opt.hasAllowOutflow && opt.allowOutflow >= outflow))
        refuse = strprintf("vault-send-outflow: this wallet would pay %s beyond its own outputs (the fee cap is %s); nothing was signed",
                           FormatMoney(outflow), FormatMoney(YedMaxTxFee()));

    UniValue outputs(UniValue::VARR);
    CAmount in = 0;
    bool allIn = true;
    for (unsigned int i = 0; i < mtx.vin.size(); i++) {
        CTxOut prev;
        int h;
        if (!GetCoin(mtx.vin[i].prevout, prev, h)) { allIn = false; continue; }
        in += prev.nValue;
    }
    for (unsigned int i = 0; i < mtx.vout.size(); i++) {
        UniValue row(UniValue::VOBJ);
        row.pushKV("n", (int)i);
        row.pushKV("amount", ValueFromAmount(mtx.vout[i].nValue));
        const std::string addr = ScriptAddress(mtx.vout[i].scriptPubKey);
        if (!addr.empty()) row.pushKV("address", addr);
        else row.pushKV("script", HexStr(mtx.vout[i].scriptPubKey.begin(), mtx.vout[i].scriptPubKey.end()));
        row.pushKV("mine", own.count(i) != 0);
        row.pushKV("kind", OutputKind(mtx.vout[i].scriptPubKey));
        outputs.push_back(row);
    }
    UniValue preview(UniValue::VOBJ);
    preview.pushKV("template", templ);
    preview.pushKV("act", actField);
    preview.pushKV("sign", sign);
    preview.pushKV("foreign", foreign);
    preview.pushKV("outputs", outputs);
    preview.pushKV("fee", allIn ? UniValue(ValueFromAmount(in - CTransaction(mtx).GetValueOut())) : NullUniValue);
    preview.pushKV("outflow", ValueFromAmount(outflow));
    preview.pushKV("wouldrefuse", refuse.empty() ? NullUniValue : UniValue(refuse));
    if (opt.dryrun) return preview;
    if (!refuse.empty()) throw JSONRPCError(RPC_WALLET_ERROR, refuse);
    SignWalletInputs(mtx);
    return Broadcast(CTransaction(mtx)).GetHex();
}

/** Remember an act build under vin[0], the input its signatures bind. */
void RememberActBuild(const CMutableTransaction& mtx)
{
    if (mtx.vin.empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "an act transaction needs a transparent input (vin[0] is bound by the signatures)");
    RememberBuild(mtx.vin[0].prevout, mtx);
}

uint256 Broadcast(const CTransaction& tx)
{
    // review M-1: submitted below with the absurd-fee check off, so the vault/Yellowback cap is enforced here
    if (std::optional<CAmount> over = YedFeeOverCap(tx))
        throw JSONRPCError(RPC_TRANSACTION_REJECTED, strprintf("absurdly-high-fee: %s exceeds the vault/Yellowback cap %s (-maxtxfee, -yellowbackmaxtxfeeusd, -yellowbackmaxtxfee)",
                                                               FormatMoney(over.value()), FormatMoney(YedMaxTxFee())));
    CValidationState state;
    bool fMissingInputs = false;
    if (!AcceptToMemoryPool(Params(), mempool, state, tx, false, &fMissingInputs, false)) {
        if (state.IsInvalid())
            throw JSONRPCError(RPC_TRANSACTION_REJECTED, strprintf("%i: %s", state.GetRejectCode(), state.GetRejectReason()));
        if (fMissingInputs) throw JSONRPCError(RPC_TRANSACTION_ERROR, "Missing inputs");
        throw JSONRPCError(RPC_TRANSACTION_ERROR, state.GetRejectReason());
    }
    RelayTransaction(tx);
    return tx.GetHash();
}

CMutableTransaction DecodeMutable(const UniValue& v)
{
    CTransaction tx;
    try {
        DecodeHexTx(tx, v.get_str()); // 6.20.0: throws instead of returning false
    } catch (const std::exception&) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }
    return CMutableTransaction(tx);
}

/** The act output of `mtx` (index, decoded act). */
size_t FindAct(const CMutableTransaction& mtx, Act& act)
{
    for (size_t o = 0; o < mtx.vout.size(); o++) {
        if (!IsActOutput(mtx.vout[o].scriptPubKey)) continue;
        if (auto err = DecodeAct(mtx.vout[o].scriptPubKey, act)) throw JSONRPCError(RPC_INVALID_PARAMETER, "the act does not decode: " + *err);
        return o;
    }
    throw JSONRPCError(RPC_INVALID_PARAMETER, "the transaction carries no YV act");
}

/** Act signatures still needed and the keys this wallet can add, appended in place (§15.5's
 *  signature rules). Returns the number still missing after signing. */
int SignActInPlace(CMutableTransaction& mtx, size_t actIndex, Act& act, const SetSnapshot& snap, int& required)
{
    if (mtx.vin.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "an act transaction needs a transparent input (vin[0] is bound by the signatures)");
    const int64_t h = NextHeight();
    const std::vector<unsigned char> P = EncodePayload(act);
    const uint256 msg = ActMsg(P, mtx.vin[0].prevout);
    std::vector<CPubKey> have;
    for (const auto& sig : act.sigs) {
        CPubKey k;
        if (!RecoverSig(msg, sig, k)) throw JSONRPCError(RPC_INVALID_PARAMETER, "an existing act signature does not recover (vin[0] changed?)");
        have.push_back(k);
    }
    auto add = [&](const CPubKey& k) {
        std::vector<unsigned char> sig;
        if (!SignRecoverable(WalletPrivKey(k), msg, sig)) throw JSONRPCError(RPC_WALLET_ERROR, "signing failed");
        act.sigs.push_back(sig);
        have.push_back(k);
    };
    auto has = [&](const CPubKey& k) { return std::find(have.begin(), have.end(), k) != have.end(); };
    // Current members of `setId` whose keys this wallet holds, excluding `exclude`.
    auto cosign = [&](const SetId& setId, size_t from, int count, const CPubKey* exclude) {
        auto s = snap.GetSet(setId);
        if (!s) throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown set " + setId.GetHex());
        for (const auto& m : snap.GetMembers(setId)) {
            if ((int)have.size() >= (int)from + count) break;
            if (!IsCurrent(*s, m.second, h) || has(m.first) || (exclude && m.first == *exclude)) continue;
            if (!pwalletMain->HaveKey(m.first.GetID())) continue;
            add(m.first);
        }
        return (int)from + count - (int)have.size();
    };
    int missing = 0;
    switch (act.type) {
    case ACT_SET_CREATE:
    case ACT_SET_EQUIVOCATION:
        required = 0;
        missing = 0;
        break;
    case ACT_SET_HEARTBEAT:
        required = 1;
        if (have.empty() && pwalletMain->HaveKey(act.heartbeat.memberKey.GetID())) add(act.heartbeat.memberKey);
        missing = have.empty() ? 1 : 0;
        break;
    case ACT_SET_JOIN: {
        const SetJoinBody& j = act.join;
        if (have.empty()) {
            if (!pwalletMain->HaveKey(j.memberKey.GetID())) {
                required = -1;
                return 1; // S_1 must come first, from the member
            }
            add(j.memberKey);
        }
        auto s = snap.GetSet(j.setId);
        if (!s) throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown set " + j.setId.GetHex());
        if (s->params.IsOpen()) {
            required = 1;
            missing = 0;
        } else if (CountCurrent(*s, snap.GetMembers(j.setId), h) >= (int)s->params.slashThreshold) {
            required = 1 + s->params.slashThreshold;
            missing = cosign(j.setId, 1, s->params.slashThreshold, &j.memberKey);
        } else {
            required = 2;
            if (have.size() < 2 && pwalletMain->HaveKey(s->params.admitKey.GetID())) add(s->params.admitKey);
            missing = have.size() >= 2 ? 0 : 1;
        }
        break;
    }
    case ACT_SET_REMOVE: {
        auto s = snap.GetSet(act.remove.setId);
        if (!s) throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown set " + act.remove.setId.GetHex());
        required = s->params.slashThreshold;
        missing = cosign(act.remove.setId, 0, s->params.slashThreshold, &act.remove.memberKey);
        break;
    }
    case ACT_SET_WINDDOWN: {
        auto s = snap.GetSet(act.winddown.setId);
        if (!s) throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown set " + act.winddown.setId.GetHex());
        required = s->params.slashThreshold;
        missing = cosign(act.winddown.setId, 0, s->params.slashThreshold, nullptr);
        break;
    }
    }
    mtx.vout[actIndex].scriptPubKey = EncodeAct(act);
    return missing < 0 ? 0 : missing;
}

UniValue ActResult(const CMutableTransaction& mtx, const Act& act, int missing, int required)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
    o.pushKV("type", ActTypeName(act.type));
    o.pushKV("complete", missing == 0);
    o.pushKV("signatures", (int)act.sigs.size());
    o.pushKV("required", required);
    return o;
}

/** Build an act transaction: `before` outputs, then the act, funded (change last). */
CMutableTransaction BuildActTx(const Act& act, const std::vector<CTxOut>& before)
{
    CMutableTransaction mtx = NewTx();
    for (const CTxOut& o : before) mtx.vout.push_back(o);
    mtx.vout.push_back(CTxOut(0, EncodeAct(act)));
    Fund(mtx, 0);
    return mtx;
}

SetCreateBody ParseCreateParams(const UniValue& p)
{
    const UniValue& o = p.get_obj();
    auto num = [&](const char* k, int64_t def, bool required) -> int64_t {
        const UniValue& v = find_value(o, k);
        if (v.isNull()) {
            if (required) throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("missing ") + k);
            return def;
        }
        return v.get_int64();
    };
    SetCreateBody c;
    c.seats = (uint8_t)num("seats", 0, true);
    c.unlockThreshold = (uint8_t)num("unlockthreshold", 0, true);
    c.cancelThreshold = (uint8_t)num("cancelthreshold", 1, false);
    c.slashThreshold = (uint8_t)num("slashthreshold", c.unlockThreshold, false);
    c.flags = (!find_value(o, "open").isNull() && find_value(o, "open").get_bool()) ? SET_FLAG_OPEN : 0;
    c.rateLimitBps = (uint16_t)num("ratelimitbps", 0, false);
    c.rateWindow = (uint32_t)num("ratewindow", 144, false);
    c.livenessWindow = (uint32_t)num("livenesswindow", 1000, false);
    c.bondMin = find_value(o, "bondmin").isNull() ? COIN : AmountFromValue(find_value(o, "bondmin"));
    c.bondLockMin = (uint32_t)num("bondlockmin", 0, false);
    c.maturity = (uint32_t)num("maturity", MinSetMaturity(), false);   // D-Q-31: at least the network's exit window
    if (c.maturity < MinSetMaturity()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("maturity must be at least %u blocks (D-Q-31)", MinSetMaturity()));
    }
    c.admitKey = WalletKeyParam(find_value(o, "admitkey"), "admitkey");
    if (!c.Valid()) throw JSONRPCError(RPC_INVALID_PARAMETER, "the set parameters are out of range (plan §15.5 row 0x01)");
    return c;
}

/** A key parameter that need not be in this wallet; a new wallet key when null. */
CPubKey KeyParamOrNew(const UniValue& v, const std::string& name)
{
    if (v.isNull()) return NewWalletKey();
    return ParseKey(v, name);
}

uint256 ParseRaw32(const UniValue& v, const std::string& name)
{
    std::vector<unsigned char> b = ParseHexV(v, name);
    if (b.size() != 32) throw JSONRPCError(RPC_INVALID_PARAMETER, name + " must be 32 bytes");
    uint256 r;
    std::copy(b.begin(), b.end(), r.begin());
    return r;
}

std::vector<unsigned char> ParseSig65(const UniValue& v, const std::string& name)
{
    std::vector<unsigned char> b = ParseHexV(v, name);
    if (b.size() != RECOVERABLE_SIG_SIZE) throw JSONRPCError(RPC_INVALID_PARAMETER, name + " must be a 65-byte recoverable signature");
    return b;
}

SetEquivocationBody ParseProof(const UniValue& o)
{
    SetEquivocationBody e;
    e.setId = ParseSetId(find_value(o, "setid"), "setid");
    e.prevout = ParseOutPoint(find_value(o, "prevout"), "prevout");
    e.roleA = (uint8_t)find_value(o, "rolea").get_int();
    e.sighashA = ParseRaw32(find_value(o, "sighasha"), "sighasha");
    e.sigA = ParseSig65(find_value(o, "siga"), "siga");
    e.roleB = (uint8_t)find_value(o, "roleb").get_int();
    e.sighashB = ParseRaw32(find_value(o, "sighashb"), "sighashb");
    e.sigB = ParseSig65(find_value(o, "sigb"), "sigb");
    return e;
}

/** Build the unsigned act of `type` from `p` (vin[0] fixed by funding). */
CMutableTransaction BuildActFromParams(uint8_t type, const UniValue& p, Act& act)
{
    act = Act();
    act.type = type;
    const UniValue& o = p.isNull() ? UniValue(UniValue::VOBJ) : p.get_obj();
    std::vector<CTxOut> before;
    switch (type) {
    case ACT_SET_CREATE:
        act.create = ParseCreateParams(o);
        break;
    case ACT_SET_JOIN: {
        act.join.setId = ParseSetId(find_value(o, "setid"), "setid");
        act.join.memberKey = KeyParamOrNew(find_value(o, "memberkey"), "memberkey");
        const CAmount bond = AmountFromValue(find_value(o, "bondamount"));
        const int64_t lt = find_value(o, "bondlocktime").get_int64();
        if (lt < 1 || lt >= 500000000) throw JSONRPCError(RPC_INVALID_PARAMETER, "bondlocktime must be a height below 500000000");
        act.join.bondLocktime = (uint32_t)lt;
        act.join.bondVout = 0;
        before.push_back(CTxOut(bond, BondScriptPubKey(act.join.bondLocktime, act.join.memberKey)));
        break;
    }
    case ACT_SET_HEARTBEAT:
        act.heartbeat.setId = ParseSetId(find_value(o, "setid"), "setid");
        act.heartbeat.memberKey = ParseKey(find_value(o, "memberkey"), "memberkey");
        break;
    case ACT_SET_REMOVE:
        act.remove.setId = ParseSetId(find_value(o, "setid"), "setid");
        act.remove.memberKey = ParseKey(find_value(o, "memberkey"), "memberkey");
        act.remove.burn = (!find_value(o, "burn").isNull() && find_value(o, "burn").get_bool()) ? 1 : 0;
        break;
    case ACT_SET_EQUIVOCATION:
        act.equivocation = ParseProof(o);
        break;
    case ACT_SET_WINDDOWN:
        act.winddown.setId = ParseSetId(find_value(o, "setid"), "setid");
        break;
    default:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown act type");
    }
    return BuildActTx(act, before);
}

// ---- act RPCs ---------------------------------------------------------------------------------

UniValue set_create(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "set_create {params}\n"
            "\nCreate a signer set (a SET_CREATE act), funded and signed by this wallet, and broadcast it. The set id is\n"
            "the transaction id; the set exists from the next block on.\n"
            "\nArguments:\n"
            "1. params  (object, required)\n"
            "   {\"seats\":n, \"unlockthreshold\":n, \"cancelthreshold\":n (default 1), \"slashthreshold\":n (default unlockthreshold),\n"
            "    \"open\":bool (default false), \"ratelimitbps\":n (default 0 = none), \"ratewindow\":n (default 144),\n"
            "    \"livenesswindow\":n (default 1000), \"bondmin\":amount (default 1), \"bondlockmin\":n (default 0),\n"
            "    \"maturity\":n (default and minimum: the network's exit window, D-Q-31), \"admitkey\":\"hex\" (default: a new wallet key)}\n"
            "\nResult: {\"txid\", \"setid\", \"admitkey\"}\n"
            + HelpExampleCli("set_create", "'{\"seats\":3,\"unlockthreshold\":2,\"cancelthreshold\":1,\"slashthreshold\":2}'")
            + HelpExampleRpc("set_create", "{\"seats\":3,\"unlockthreshold\":2}"));
    EnsureWallet(fHelp);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureVaultActive();
    Act act;
    CMutableTransaction mtx = BuildActFromParams(ACT_SET_CREATE, params[0], act);
    SignWalletInputs(mtx);
    const uint256 txid = Broadcast(CTransaction(mtx));
    UniValue o(UniValue::VOBJ);
    o.pushKV("txid", txid.GetHex());
    o.pushKV("setid", txid.GetHex());
    o.pushKV("admitkey", HexStr(act.create.admitKey.begin(), act.create.admitKey.end()));
    return o;
}

UniValue set_join(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 4)
        throw std::runtime_error(
            "set_join \"setid\" bondamount bondlocktime ( \"memberkey\" )\n"
            "\nJoin a set with a bond P2SH(<bondlocktime> CLTV DROP <memberkey> CHECKSIG) of bondamount. The member's\n"
            "signature is added by this wallet, and the admission signatures it can add (the admit key, or current\n"
            "members' keys once the set has slashthreshold of them). If that completes the act it is broadcast;\n"
            "otherwise the hex is returned for set_signact on the other signers' nodes and set_sendact here. The unbroadcast\n"
            "build is remembered; set_sendact on this node signs only the coins it chose for those outputs.\n"
            "\nArguments:\n"
            "1. \"setid\"      (string, required)\n"
            "2. bondamount   (numeric, required) at least the set's bondmin\n"
            "3. bondlocktime (numeric, required) a height >= next height + bondlockmin\n"
            "4. \"memberkey\"  (string, optional) a wallet public key (default: a new one)\n"
            "\nResult: {\"txid\" (when broadcast), \"hex\", \"complete\", \"signatures\", \"required\", \"memberkey\", \"bondoutpoint\"}\n"
            + HelpExampleCli("set_join", "\"setid\" 1 500") + HelpExampleRpc("set_join", "\"setid\", 1, 500"));
    EnsureWallet(fHelp);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureVaultActive();
    auto snap = Snapshot();
    UniValue p(UniValue::VOBJ);
    p.pushKV("setid", params[0]);
    p.pushKV("bondamount", params[1]);
    p.pushKV("bondlocktime", params[2]);
    if (params.size() > 3 && !params[3].isNull()) {
        WalletKeyParam(params[3], "memberkey");
        p.pushKV("memberkey", params[3]);
    }
    if (!snap->GetSet(ParseSetId(params[0], "setid"))) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "unknown set (it must be confirmed)");
    Act act;
    CMutableTransaction mtx = BuildActFromParams(ACT_SET_JOIN, p, act);
    Act decoded;
    size_t ai = FindAct(mtx, decoded);
    int required = 0;
    int missing = SignActInPlace(mtx, ai, decoded, *snap, required);
    UniValue o(UniValue::VOBJ);
    if (missing == 0) {
        SignWalletInputs(mtx);
        o.pushKV("txid", Broadcast(CTransaction(mtx)).GetHex());
    } else {
        RememberActBuild(mtx);
    }
    o.pushKVs(ActResult(mtx, decoded, missing, required));
    o.pushKV("memberkey", HexStr(act.join.memberKey.begin(), act.join.memberKey.end()));
    o.pushKV("bondoutpoint", OutPointStr(COutPoint(CTransaction(mtx).GetHash(), 0)));
    return o;
}

UniValue set_heartbeat(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "set_heartbeat \"setid\" ( \"memberkey\" )\n"
            "\nBroadcast a SET_HEARTBEAT for a current member key of this wallet (default: the first one), which sets its\n"
            "lastAct to the height it confirms at (the set's liveness, plan §3.7, U-19).\n"
            "\nResult: {\"txid\", \"memberkey\"}\n"
            + HelpExampleCli("set_heartbeat", "\"setid\"") + HelpExampleRpc("set_heartbeat", "\"setid\""));
    EnsureWallet(fHelp);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureVaultActive();
    auto snap = Snapshot();
    const SetId id = ParseSetId(params[0], "setid");
    auto s = snap->GetSet(id);
    if (!s) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "unknown set " + id.GetHex());
    CPubKey key;
    if (params.size() > 1 && !params[1].isNull()) {
        key = WalletKeyParam(params[1], "memberkey");
    } else {
        for (const auto& m : snap->GetMembers(id)) {
            if (IsCurrent(*s, m.second, NextHeight()) && pwalletMain->HaveKey(m.first.GetID())) { key = m.first; break; }
        }
        if (!key.IsValid()) throw JSONRPCError(RPC_WALLET_ERROR, "this wallet holds no current member key of the set");
    }
    Act act;
    act.type = ACT_SET_HEARTBEAT;
    act.heartbeat.setId = id;
    act.heartbeat.memberKey = key;
    CMutableTransaction mtx = BuildActTx(act, {});
    Act decoded;
    size_t ai = FindAct(mtx, decoded);
    int required = 0;
    SignActInPlace(mtx, ai, decoded, *snap, required);
    SignWalletInputs(mtx);
    UniValue o(UniValue::VOBJ);
    o.pushKV("txid", Broadcast(CTransaction(mtx)).GetHex());
    o.pushKV("memberkey", HexStr(key.begin(), key.end()));
    return o;
}

UniValue set_leave(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "set_leave \"setid\" ( \"memberkey\" )\n"
            "\nLeave a set (owner 2026-10-11, the bond exit delay): broadcast the SET_REMOVE of an ACTIVE member key of this\n"
            "wallet (default: the first one), signed by that key alone, without burn. The member is REMOVED from the block it\n"
            "confirms in, and its bond becomes spendable the set's maturity later (bad-vault-bond-locked before).\n"
            "\nResult: {\"txid\", \"memberkey\", \"exitheight\" (the next block), \"bondspendableat\"}\n"
            + HelpExampleCli("set_leave", "\"setid\"") + HelpExampleRpc("set_leave", "\"setid\""));
    EnsureWallet(fHelp);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureVaultActive();
    auto snap = Snapshot();
    const SetId id = ParseSetId(params[0], "setid");
    auto s = snap->GetSet(id);
    if (!s) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "unknown set " + id.GetHex());
    CPubKey key;
    if (params.size() > 1 && !params[1].isNull()) {
        key = WalletKeyParam(params[1], "memberkey");
    } else {
        for (const auto& m : snap->GetMembers(id)) {
            if (m.second.status == MEMBER_ACTIVE && pwalletMain->HaveKey(m.first.GetID())) { key = m.first; break; }
        }
        if (!key.IsValid()) throw JSONRPCError(RPC_WALLET_ERROR, "this wallet holds no active member key of the set");
    }
    Act act;
    act.type = ACT_SET_REMOVE;
    act.remove.setId = id;
    act.remove.memberKey = key;
    act.remove.burn = 0;
    CMutableTransaction mtx = BuildActTx(act, {});
    Act decoded;
    size_t ai = FindAct(mtx, decoded);
    CKey priv;
    if (!pwalletMain->GetKey(key.GetID(), priv)) throw JSONRPCError(RPC_WALLET_ERROR, "the member key is not in this wallet");
    std::vector<unsigned char> sig;
    if (!SignRecoverable(priv, ActMsg(EncodePayload(decoded), mtx.vin[0].prevout), sig)) throw JSONRPCError(RPC_WALLET_ERROR, "signing failed");
    decoded.sigs = { sig };
    mtx.vout[ai].scriptPubKey = EncodeAct(decoded);
    SignWalletInputs(mtx);
    UniValue o(UniValue::VOBJ);
    o.pushKV("txid", Broadcast(CTransaction(mtx)).GetHex());
    o.pushKV("memberkey", HexStr(key.begin(), key.end()));
    o.pushKV("exitheight", NextHeight());
    o.pushKV("bondspendableat", NextHeight() + (int64_t)s->params.maturity);
    return o;
}

UniValue set_buildact(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw std::runtime_error(
            "set_buildact \"type\" {params}\n"
            "\nBuild an act transaction funded by this wallet (inputs unsigned; vin[0], which the act signatures bind, is\n"
            "fixed) carrying no act signatures yet. The build is remembered. Collect signatures with set_signact, then\n"
            "set_sendact on this node, which signs only the coins chosen for these outputs.\n"
            "\nArguments:\n"
            "1. \"type\"   (string, required) create | join | heartbeat | remove | equivocation | winddown\n"
            "2. params   (object, required)\n"
            "   create:       as set_create\n"
            "   join:         {\"setid\", \"bondamount\", \"bondlocktime\", \"memberkey\" (any compressed key; default a new wallet key)}\n"
            "   heartbeat:    {\"setid\", \"memberkey\"}\n"
            "   remove:       {\"setid\", \"memberkey\" (the member removed), \"burn\": bool (default false: bond returned)}\n"
            "   equivocation: as set_equivocation's proof\n"
            "   winddown:     {\"setid\"}\n"
            "\nResult: {\"hex\", \"type\", \"complete\", \"signatures\", \"required\"}\n"
            + HelpExampleCli("set_buildact", "\"remove\" '{\"setid\":\"..\",\"memberkey\":\"..\"}'")
            + HelpExampleRpc("set_buildact", "\"winddown\", {\"setid\":\"..\"}"));
    EnsureWallet(fHelp);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureVaultActive();
    auto snap = Snapshot();
    Act act;
    CMutableTransaction mtx = BuildActFromParams(ParseActType(params[0]), params[1], act);
    int required = 0;
    int missing = 0;
    if (act.type != ACT_SET_CREATE && act.type != ACT_SET_EQUIVOCATION) {
        // Report what is needed without signing anything (set_signact signs).
        auto s = snap->GetSet(act.TargetSet());
        if (!s) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "unknown set " + act.TargetSet().GetHex());
        switch (act.type) {
        case ACT_SET_HEARTBEAT: required = 1; break;
        case ACT_SET_JOIN:
            required = s->params.IsOpen() ? 1 : CountCurrent(*s, snap->GetMembers(act.join.setId), NextHeight()) >= (int)s->params.slashThreshold ? 1 + s->params.slashThreshold : 2;
            break;
        default: required = s->params.slashThreshold; break;
        }
        missing = required;
    }
    RememberActBuild(mtx);
    return ActResult(mtx, act, missing, required);
}

UniValue set_signact(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "set_signact \"hex\" ( \"setid\" )\n"
            "\nAdd this wallet's act signatures to an act transaction: the member's own signature (join, heartbeat), the\n"
            "admit key or current-member co-signatures (join), or current-member signatures (remove, winddown), up to the\n"
            "number the act needs at the next block. The transaction's inputs must not be signed yet (the act output is\n"
            "rewritten; set_sendact signs them).\n"
            "\nArguments:\n"
            "1. \"hex\"    (string, required) the act transaction\n"
            "2. \"setid\"  (string, optional) checked against the act's set\n"
            "\nResult: {\"hex\", \"type\", \"complete\", \"signatures\", \"required\"}\n"
            + HelpExampleCli("set_signact", "\"hex\"") + HelpExampleRpc("set_signact", "\"hex\""));
    EnsureWallet(fHelp);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    auto snap = Snapshot();
    CMutableTransaction mtx = DecodeMutable(params[0]);
    Act act;
    size_t ai = FindAct(mtx, act);
    if (params.size() > 1 && !params[1].isNull() && act.type != ACT_SET_CREATE && ParseSetId(params[1], "setid") != act.TargetSet())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "the act names set " + act.TargetSet().GetHex());
    int required = 0;
    int missing = SignActInPlace(mtx, ai, act, *snap, required);
    return ActResult(mtx, act, missing, required);
}

UniValue set_sendact(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "set_sendact \"hex\" ( {\"dryrun\":bool, \"allowinputs\":[\"txid:n\",...], \"allowoutflow\":n} )\n"
            "\nSign this wallet's inputs of an act transaction this wallet built (set_buildact, or set_join when it\n"
            "returned a hex) and broadcast it. Only coins that build chose are signed, and only for its outputs (act\n"
            "signatures added later still match). Any other spendable coin of this wallet is refused\n"
            "(vault-send-foreign-input) unless allowinputs names it, and nothing is signed. The wallet's net outflow\n"
            "above the fee cap is refused (vault-send-outflow) unless allowoutflow is at least that outflow. A\n"
            "SET_JOIN bond counts as this wallet's when it holds the member key. dryrun returns a preview and does\n"
            "not sign or broadcast.\n"
            "\nResult (dryrun false or omitted): \"txid\"\n"
            "Result (dryrun true): {\"template\":null, \"act\", \"sign\", \"foreign\", \"outputs\", \"fee\", \"outflow\", \"wouldrefuse\"}\n"
            + HelpExampleCli("set_sendact", "\"hex\"") + HelpExampleRpc("set_sendact", "\"hex\""));
    EnsureWallet(fHelp);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    PruneVaultBuilds();
    CMutableTransaction mtx = DecodeMutable(params[0]);
    Act act;
    FindAct(mtx, act);
    if (mtx.vin.empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "an act transaction needs a transparent input (vin[0] is bound by the signatures)");
    return HandoffSend(mtx, mtx.vin[0].prevout, ParseHandoffOptions(params), NullUniValue);
}

UniValue set_equivocation(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "set_equivocation {proof}\n"
            "\nSubmit a SET_EQUIVOCATION proof (anyone may): two set signatures by one member over two different spends of\n"
            "the same outpoint. The member is EJECTED and its bond frozen (plan §3.6).\n"
            "\nArguments:\n"
            "1. proof (object, required) {\"setid\", \"prevout\": \"txid:n\" | {\"txid\",\"vout\"}, \"rolea\": 1|2,\n"
            "         \"sighasha\": \"32 raw bytes hex\", \"siga\": \"65 bytes hex\", \"roleb\", \"sighashb\", \"sigb\"}\n"
            "         (set_signunlock / set_signcancel report each signature's sighash)\n"
            "\nResult: \"txid\"\n"
            + HelpExampleCli("set_equivocation", "'{\"setid\":\"..\",\"prevout\":\"txid:0\",\"rolea\":1,...}'")
            + HelpExampleRpc("set_equivocation", "{...}"));
    EnsureWallet(fHelp);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureVaultActive();
    Act act;
    CMutableTransaction mtx = BuildActFromParams(ACT_SET_EQUIVOCATION, params[0], act);
    SignWalletInputs(mtx);
    return Broadcast(CTransaction(mtx)).GetHex();
}

// ---- vault RPCs -------------------------------------------------------------------------------

UniValue vault_lock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "vault_lock {params}\n"
            "\nLock amount in a vault V (plan §15.3) funded by this wallet, and broadcast it. Both sets must be confirmed.\n"
            "\nArguments:\n"
            "1. params (object, required) {\"tag\": \"4 chars or 8 hex\", \"setid\", \"cancelsetid\" (default setid),\n"
            "        \"delay\": 1..65535, \"ownerheight\": n, \"appheight\": n (default 0 = no APP branch; only on a tag a module governs), \"amount\",\n"
            "        \"owner\": pqkeyid (66 hex, scheme || keyhash), a PQ address or {\"scheme\": n, \"keyhash\": \"64 hex\"}\n"
            "        (default: a new SLH-DSA key of this wallet, as vault_getnewowner)}\n"
            "\nResult: {\"txid\", \"vout\", \"outpoint\", \"script\", \"owner\"}\n"
            + HelpExampleCli("vault_lock", "'{\"tag\":\"TEST\",\"setid\":\"..\",\"delay\":10,\"ownerheight\":1000,\"amount\":5}'")
            + HelpExampleRpc("vault_lock", "{...}"));
    EnsureWallet(fHelp);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureVaultActive();
    auto snap = Snapshot();
    const UniValue& o = params[0].get_obj();
    VaultParams vp;
    vp.tag = ParseTag(find_value(o, "tag"));
    vp.setId = ParseSetId(find_value(o, "setid"), "setid");
    vp.cancelSetId = find_value(o, "cancelsetid").isNull() ? vp.setId : ParseSetId(find_value(o, "cancelsetid"), "cancelsetid");
    vp.delay = find_value(o, "delay").get_int64();
    vp.ownerHeight = find_value(o, "ownerheight").get_int64();
    vp.appHeight = find_value(o, "appheight").isNull() ? 0 : find_value(o, "appheight").get_int64();
    // V-1 (audit 01/V-5): the APP branch has no signer; only a tag a module governs may carry one. Consensus admits
    // any registered tag (V-1); the wallet also requires the module to govern a set on this node (YED\0 without its
    // attestor set is registered but governs nothing: its rules are unconfigured and the branch would be open to all).
    if (vp.appHeight != 0) {
        const vault::Module* mod = vault::FindModule(vp.tag);
        if (!mod || !mod->GovernedSet())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "appheight on a tag no module governs: the APP branch has no signer and only a module with its set may govern it (V-1, bad-txns-vault-app)");
    }
    if (!find_value(o, "ownerkey").isNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "ownerkey-removed: use owner (pqkeyid)");
    // Every vault owner is a post-quantum key (quantum plan §4.3): the named one, or a new SLH-DSA
    // key of this wallet (quantum spec §6.2).
    const bool newOwner = find_value(o, "owner").isNull();
    vp.owner = newOwner ? CPQKeyID(pq::SCHEME_SLH_DSA_SHA2_128S, uint256()) : ParsePQOwner(find_value(o, "owner"), "owner");
    // As relay policy (IsStandardTx): no scheme-2 (FN-DSA-512) owner before Falcon is active at the
    // next block; the owner could not spend it (review A F3).
    if (vp.owner.scheme == pq::SCHEME_FN_DSA_512 && !IsPQFalconActive(Params().GetConsensus(), NextHeight()))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "a scheme-2 (FN-DSA-512) owner before Falcon is active");
    const CAmount amount = AmountFromValue(find_value(o, "amount"));
    if (!VaultParamsValid(vp)) throw JSONRPCError(RPC_INVALID_PARAMETER, "vault parameters out of range (plan §15.3)");
    if (!snap->GetSet(vp.setId) || !snap->GetSet(vp.cancelSetId)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "setid and cancelsetid must be confirmed sets");
    if (newOwner) vp.owner = NewWalletPQKey(pq::SCHEME_SLH_DSA_SHA2_128S);   // drawn once the rest is valid
    CScript spk = BuildVault(vp);
    CMutableTransaction mtx = NewTx();
    mtx.vout.push_back(CTxOut(amount, spk));
    Fund(mtx, 0);
    SignWalletInputs(mtx);
    const uint256 txid = Broadcast(CTransaction(mtx));
    UniValue r(UniValue::VOBJ);
    r.pushKV("txid", txid.GetHex());
    r.pushKV("vout", 0);
    r.pushKV("outpoint", OutPointStr(COutPoint(txid, 0)));
    r.pushKV("script", HexStr(spk.begin(), spk.end()));
    r.pushKV("owner", PQKeyIdHex(vp.owner));
    return r;
}

UniValue vault_getnewowner(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "vault_getnewowner ( scheme )\n"
            "\nA new post-quantum vault owner key of this wallet (quantum plan §4.6; quantum spec ruling C-4), derived from\n"
            "the wallet's HD seed. Pass it as vault_lock's owner (or lock without one: vault_lock draws one itself).\n"
            "\nArguments:\n"
            "1. scheme (numeric, optional, default 1) 1 = SLH-DSA-SHA2-128s; 2 = FN-DSA-512, only once Falcon is active\n"
            "\nResult: {\"scheme\": n, \"keyhash\": \"64 hex (the bytes V pushes)\", \"owner\": pqkeyid (66 hex, scheme || keyhash),\n"
            "         \"address\": \"the PQ Yellowback address (53 characters)\"}\n"
            + HelpExampleCli("vault_getnewowner", "") + HelpExampleRpc("vault_getnewowner", ""));
    EnsureWallet(fHelp);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    int scheme = pq::SCHEME_SLH_DSA_SHA2_128S;
    if (params.size() > 0 && !params[0].isNull()) scheme = params[0].get_int();
    if (scheme < 0 || scheme > 255) throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown post-quantum scheme");
    const CPQKeyID id = NewWalletPQKey((uint8_t)scheme);
    UniValue r(UniValue::VOBJ);
    r.pushKV("scheme", (int)id.scheme);
    r.pushKV("keyhash", HexStr(id.hash.begin(), id.hash.end()));
    r.pushKV("owner", PQKeyIdHex(id));
    r.pushKV("address", yellowback::EncodeAddress(id, yellowback::ParamsForNetwork(Params().NetworkIDString())));
    return r;
}

/** Outputs for an UNLOCK / APP spend of the V at (coin): one intent per recipient, the remainder
 *  re-locked byte-identically (S-2). */
UniValue AddIntents(CMutableTransaction& mtx, const VaultParams& vp, const CTxOut& coin, const UniValue& recipients)
{
    UniValue arr(UniValue::VARR);
    CAmount sum = 0;
    for (size_t i = 0; i < recipients.size(); i++) {
        const UniValue& r = recipients[i].get_obj();
        CScript dest = ParseRecipient(r);
        CAmount amt = AmountFromValue(find_value(r, "amount"));
        sum += amt;
        if (!MoneyRange(sum) || sum > coin.nValue) throw JSONRPCError(RPC_INVALID_PARAMETER, "the recipients' amounts exceed the vault's value");
        IntentParams ip = IntentFor(vp, coin.scriptPubKey, dest);
        RememberRecipient(ip.recipientHash, dest);
        mtx.vout.push_back(CTxOut(amt, BuildIntent(ip)));
        UniValue io(UniValue::VOBJ);
        io.pushKV("vout", (int)mtx.vout.size() - 1);
        io.pushKV("amount", ValueFromAmount(amt));
        io.pushKV("recipient", HexStr(dest.begin(), dest.end()));
        io.pushKV("recipienthash", HexStr(ip.recipientHash.begin(), ip.recipientHash.end()));
        arr.push_back(io);
    }
    if (sum < coin.nValue) mtx.vout.push_back(CTxOut(coin.nValue - sum, coin.scriptPubKey));
    return arr;
}

/** The template input of `mtx`: its index and coin; exactly one (S-1). */
size_t FindTemplateInput(const CMutableTransaction& mtx, CTxOut& coin, int& height, VaultParams& vp, IntentParams& ip, TemplateKind& kind)
{
    std::optional<size_t> found;
    for (size_t i = 0; i < mtx.vin.size(); i++) {
        CTxOut c;
        int h;
        if (!GetCoin(mtx.vin[i].prevout, c, h)) continue;
        VaultParams v;
        IntentParams in;
        if (ParseVault(c.scriptPubKey, v)) {
            kind = TemplateKind::VAULT; vp = v;
        } else if (ParseIntent(c.scriptPubKey, in)) {
            kind = TemplateKind::INTENT; ip = in;
        } else {
            continue;
        }
        if (found) throw JSONRPCError(RPC_INVALID_PARAMETER, "more than one template input (S-1)");
        found = i;
        coin = c;
        height = h;
    }
    if (!found) throw JSONRPCError(RPC_INVALID_PARAMETER, "no unspent vault or intent input");
    return *found;
}

/** Refuse (before anything is recorded or signed) a build the vault rules would not accept at the next block.
 *  The fee inputs are not under the set signature, so a spent one only downgrades the check to the template input. */
void ValidateSetSpend(const CMutableTransaction& mtx, size_t idx, uint8_t role)
{
    if (!ActiveAtNext() || !vault::g_vaultdb) return;
    CMutableTransaction probe(mtx);
    // An unsigned input still has to carry this role's selector, or a cancel is judged as an intent's RELEASE.
    if (probe.vin[idx].scriptSig.empty()) probe.vin[idx].scriptSig = CScript() << (role == ROLE_UNLOCK ? OP_1 : OP_2);
    const int64_t next = NextHeight();
    const auto snapshot = vault::TipSnapshot();
    const int64_t activation = Params().GetConsensus().vUpgrades[Consensus::UPGRADE_VAULT].nActivationHeight;
    LOCK(mempool.cs);
    CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
    CCoinsViewCache view(&viewMemPool);
    vault::ViewCoinAccessor coins(view, next);
    const auto blockHashes = vault::AncestorHashes(chainActive.Tip());
    auto bad = vault::CheckTx(CTransaction(probe), coins, next, *snapshot, blockHashes, activation);
    if (bad && *bad == "bad-txns-vault-inputs-missing" && probe.vin.size() > 1) {
        CMutableTransaction only(probe);
        only.vin = {probe.vin[idx]};
        bad = vault::CheckTx(CTransaction(only), coins, next, *snapshot, blockHashes, activation);
    }
    // bad-txns-vault-rate is epoch-dependent and clears on its own; every other reason is permanent for this build.
    if (bad && *bad != "bad-txns-vault-rate")
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("set-sign-invalid: %s; nothing was recorded or signed", *bad));
}

/** Add this wallet's set signatures (role 1 unlock / 2 cancel of setId) to the template input. */
UniValue SignSetInPlace(CMutableTransaction& mtx, size_t idx, const CTxOut& coin, const SetId& setId, uint8_t role, bool ackRestore)
{
    auto snap = Snapshot();
    const int64_t h = NextHeight();
    auto k = snap->Threshold(setId, role);
    auto s = snap->GetSet(setId);
    if (!k || !s) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "unknown set " + setId.GetHex());
    // OP_CHECKSETSIG's digest (01/V-2): the fee inputs are not signed, so a re-funded build has the same sighash.
    const uint256 sighash = SetSighash(mtx, idx, coin);
    const uint256 msg = SetSigMsg(setId, role, mtx.vin[idx].prevout, sighash);
    std::vector<std::vector<unsigned char>> sigs;
    if (!mtx.vin[idx].scriptSig.empty()) {
        auto sel = ParseSelector(mtx.vin[idx].scriptSig, &sigs);
        if (!sel || *sel != role) throw JSONRPCError(RPC_INVALID_PARAMETER, "the template input's scriptSig is for another branch");
    }
    std::vector<CPubKey> have;
    for (const auto& sig : sigs) {
        CPubKey key;
        if (!RecoverSig(msg, sig, key)) throw JSONRPCError(RPC_INVALID_PARAMETER, "an existing set signature does not verify (the transaction changed?)");
        if (!snap->IsCurrentMember(setId, key, h) || std::find(have.begin(), have.end(), key) != have.end())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "set-sign-invalid: an existing signature is not by a distinct current member of " + setId.GetHex());
        have.push_back(key);
    }
    ValidateSetSpend(mtx, idx, role);
    // Sign once (SET_EQUIVOCATION, plan §15.3): two signatures by one member over the same (setId, prevout)
    // with a different role or sighash eject it and freeze its bond. The wallet records what its members
    // signed before handing any signature out, and refuses a different one; the identical sighash is idempotent.
    const COutPoint& prevout = mtx.vin[idx].prevout;
    CWalletDB walletdb(pwalletMain->strWalletFile);
    bool recorded = false;
    {
        uint8_t prevRole = 0;
        uint256 prevSighash;
        if (walletdb.ReadVaultSetSig(setId, prevout, prevRole, prevSighash)) {
            if (prevRole != role || prevSighash != sighash)
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("set-sign-once: this wallet already signed a different %s (role %d, sighash %s) of %s for set %s; "
                                                               "a second signature is a provable equivocation (SET_EQUIVOCATION ejects the member and freezes its bond). "
                                                               "Collect signatures on the transaction already signed",
                                                               prevRole == ROLE_UNLOCK ? "unlock" : "cancel", (int)prevRole, prevSighash.GetHex(), prevout.ToString(), setId.GetHex()));
            recorded = true;
        }
    }
    for (const auto& m : snap->GetMembers(setId)) {
        if ((int)sigs.size() >= *k) break;
        if (!IsCurrent(*s, m.second, h) || std::find(have.begin(), have.end(), m.first) != have.end()) continue;
        if (!pwalletMain->HaveKey(m.first.GetID())) continue;
        const CKey priv = WalletPrivKey(m.first);      // throws (nothing recorded) when the key is unavailable
        if (!recorded) {
            // 07/F-5: a wallet restored from a seed, or one that imported a member key, may lack the record of a
            // signature its key made elsewhere: refuse until the history is imported (set_importsigned, a dump)
            // or the caller states this key never signed a spend of this outpoint.
            if (!ackRestore && walletdb.ReadVaultSignRestored())
                throw JSONRPCError(RPC_WALLET_ERROR, "set-sign-restored: this wallet was restored or imported a member key and has no sign-once history; "
                                                     "import it with set_importsigned (or a wallet dump) and then set_acknowledgerestore, or pass "
                                                     "{\"acknowledgerestore\": true} if this key has never signed a set spend of " + prevout.ToString());
            if (!walletdb.WriteVaultSetSig(setId, prevout, role, sighash))
                throw JSONRPCError(RPC_WALLET_ERROR, "set-sign-once: cannot record the signature in the wallet; nothing was signed");
            recorded = true;
        }
        std::vector<unsigned char> sig;
        if (!SignRecoverable(priv, msg, sig)) throw JSONRPCError(RPC_WALLET_ERROR, "signing failed");
        sigs.push_back(sig);
        have.push_back(m.first);
    }
    CScript ss;
    for (const auto& sig : sigs) ss << sig;
    ss << (role == ROLE_UNLOCK ? OP_1 : OP_2);
    mtx.vin[idx].scriptSig = ss;
    UniValue o(UniValue::VOBJ);
    o.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
    o.pushKV("complete", (int)sigs.size() == *k);
    o.pushKV("signatures", (int)sigs.size());
    o.pushKV("required", *k);
    o.pushKV("sighash", HexStr(sighash.begin(), sighash.end()));
    UniValue ka(UniValue::VARR);
    for (size_t i = 0; i < sigs.size(); i++) {
        UniValue so(UniValue::VOBJ);
        so.pushKV("key", HexStr(have[i].begin(), have[i].end()));
        so.pushKV("sig", HexStr(sigs[i]));
        ka.push_back(so);
    }
    o.pushKV("setsigs", ka);
    return o;
}

/** set_signunlock / set_signcancel's options: {"acknowledgerestore": true} (07/F-5). */
bool AckRestore(const UniValue& params)
{
    if (params.size() < 2 || params[1].isNull()) return false;
    if (!params[1].isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
    const UniValue& a = find_value(params[1].get_obj(), "acknowledgerestore");
    if (a.isNull()) return false;
    if (!a.isBool()) throw JSONRPCError(RPC_INVALID_PARAMETER, "acknowledgerestore must be a boolean");
    return a.get_bool();
}

UniValue vault_buildunlock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw std::runtime_error(
            "vault_buildunlock \"outpoint\" [{\"address\"|\"script\": .., \"amount\": x}, ...] ( rebuild )\n"
            "\nBuild the UNLOCK spend of a vault: one intent I per recipient (released to it after the vault's delay), the\n"
            "remainder re-locked in a byte-identical vault, the fee from this wallet's inputs (unsigned; never from the\n"
            "vault's value). Collect the set's unlock signatures with set_signunlock on the members' nodes, then vault_send.\n"
            "Call once: the build is remembered in the wallet (across restarts) and returned byte-identical when called again\n"
            "with the same recipients; if its fee inputs were spent meanwhile it is re-funded (vault_refee), keeping its\n"
            "sighash. Other recipients are refused while a build exists: members sign once (a second, different unlock\n"
            "signature is an equivocation). rebuild=true discards the remembered build (only before anyone signed it).\n"
            "\nResult: {\"hex\", \"intents\": [{\"vout\", \"amount\", \"recipient\", \"recipienthash\"}], \"required\", \"sighash\",\n"
            "\"build\" (\"new\", \"reused\" or \"refunded\")}\n"
            + HelpExampleCli("vault_buildunlock", "\"txid:0\" '[{\"address\":\"..\",\"amount\":1}]'")
            + HelpExampleRpc("vault_buildunlock", "\"txid:0\", [{\"address\":\"..\",\"amount\":1}]"));
    EnsureWallet(fHelp);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureVaultActive();
    const COutPoint op = ParseOutPoint(params[0], "outpoint");
    const bool rebuild = params.size() > 2 && !params[2].isNull() && params[2].get_bool();
    CTxOut coin;
    int h;
    VaultParams vp;
    if (!GetCoin(op, coin, h) || !ParseVault(coin.scriptPubKey, vp)) throw JSONRPCError(RPC_INVALID_PARAMETER, "not an unspent vault output");
    PruneVaultBuilds();
    CMutableTransaction mtx = NewTx();
    mtx.vin.push_back(CTxIn(op, CScript(), CTxIn::SEQUENCE_FINAL));
    UniValue intents = AddIntents(mtx, vp, coin, params[1].get_array());
    // 07/N-2: one build per vault outpoint (sign once). The remembered build is returned while its outputs are the
    // requested ones (the intents and the re-lock, then at most the change output); a lost fee input is replaced
    // without changing the sighash (01/V-2).
    std::string build = "new";
    auto memo = pwalletMain->mapVaultBuilds.find(op);
    // rebuild=true discards the remembered build only before this wallet has signed it. After that, the
    // returned hex is a different spend (sign-once refuses it) and the signed build's fee inputs stay recorded.
    const bool keepSigned = memo != pwalletMain->mapVaultBuilds.end() && rebuild && WalletSignedPrevout(op);
    if (memo != pwalletMain->mapVaultBuilds.end() && rebuild) {
        if (!keepSigned) UnlockBuildInputs(op, memo->second);
    } else if (memo != pwalletMain->mapVaultBuilds.end()) {
        const CMutableTransaction& c = memo->second;
        const bool same = c.vin.size() >= 1 && c.vin[0].prevout == op && c.vout.size() >= mtx.vout.size() && c.vout.size() <= mtx.vout.size() + 1 &&
                          std::equal(mtx.vout.begin(), mtx.vout.end(), c.vout.begin());
        if (!same)
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("this wallet already built a different unlock of %s (sighash %s): members sign once, so "
                                                               "collect signatures on that build (call again with its recipients), or pass rebuild=true "
                                                               "if no member has signed it", OutPointStr(op), SetSighash(c, 0, coin).GetHex()));
        mtx = c;
        build = "reused";
        if (!FeeInputsUnspent(op, mtx)) {
            Refee(mtx, 0, coin);
            build = "refunded";
        }
    }
    if (build == "new") Fund(mtx, coin.nValue, FundMode::SMALL_CHANGE);
    if (!keepSigned) RememberBuild(op, mtx);
    auto k = Snapshot()->Threshold(vp.setId, ROLE_UNLOCK);
    const uint256 sighash = SetSighash(mtx, 0, coin);
    UniValue o(UniValue::VOBJ);
    o.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
    o.pushKV("intents", intents);
    o.pushKV("required", k ? *k : 0);
    o.pushKV("sighash", HexStr(sighash.begin(), sighash.end()));
    o.pushKV("build", build);
    return o;
}

UniValue set_signunlock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "set_signunlock \"hex\" ( {\"acknowledgerestore\": true} )\n"
            "\nAdd this wallet's current-member unlock signatures (OP_CHECKSETSIG role 1 of the vault's setid) to a vault\n"
            "UNLOCK spend, up to the set's unlockthreshold. The signatures bind the vault input and every output, not the fee\n"
            "inputs (SIGHASH_ALL|ANYONECANPAY), so build first; a re-funded build (vault_refee) keeps them valid. Sign once:\n"
            "the wallet records (setid, prevout) -> (role, sighash) before signing and refuses a different spend of the\n"
            "prevout. A wallet restored from a seed or that imported a member key refuses (set-sign-restored) a prevout it\n"
            "has no record for until set_acknowledgerestore (after importing its history with set_importsigned), or\n"
            "acknowledgerestore=true states this key never signed a spend of that prevout.\n"
            "\nResult: {\"hex\", \"complete\", \"signatures\", \"required\", \"sighash\", \"setsigs\": [{\"key\",\"sig\"}]}\n"
            + HelpExampleCli("set_signunlock", "\"hex\"") + HelpExampleRpc("set_signunlock", "\"hex\""));
    EnsureWallet(fHelp);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    CMutableTransaction mtx = DecodeMutable(params[0]);
    CTxOut coin;
    int h;
    VaultParams vp;
    IntentParams ip;
    TemplateKind kind;
    size_t idx = FindTemplateInput(mtx, coin, h, vp, ip, kind);
    if (kind != TemplateKind::VAULT) throw JSONRPCError(RPC_INVALID_PARAMETER, "the template input is not a vault");
    return SignSetInPlace(mtx, idx, coin, vp.setId, ROLE_UNLOCK, AckRestore(params));
}

/**
 * The I-2 cancel of `op` (vault_buildcancel, and yed_buildcancel through BuildYedIntentCancel): vout[0] re-creates the
 * originating V with the intent's value, then `extra` (CAN-1's refund for a YED claim intent), then the wallet's fee
 * inputs and change. `yedAllowed` false refuses a YED-tagged intent (its cancel needs the refund output). The build is
 * remembered in the wallet (07/N-2) and returned byte-identical while its outputs are the same (sign once), re-funded
 * with the same sighash when a fee input was spent (01/V-2); `rebuild` discards it. `buildFields` adds "sighash" and
 * "build" to the result (vault_buildcancel's contract; yed_buildcancel's has neither).
 */
UniValue BuildIntentCancel(const COutPoint& op, const std::vector<CTxOut>& extra, bool yedAllowed, bool rebuild, bool buildFields)
{
    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureVaultActive();
    CTxOut coin;
    int h;
    IntentParams ip;
    if (!GetCoin(op, coin, h) || !ParseIntent(coin.scriptPubKey, ip)) throw JSONRPCError(RPC_INVALID_PARAMETER, "not an unspent intent output");
    if (!yedAllowed && ip.tag == yellowback::YED_TAG)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "a YED claim intent is cancelled with yed_buildcancel (its cancel refunds the claim's burn, CAN-1)");
    // The originating V script (the vaultHash preimage the cancel re-creates): from the vault
    // database for a confirmed intent, else from the vault coin its mempool transaction spends
    // (finding (50): a watcher pre-builds and signs the cancel as soon as the intent appears).
    // A mempool intent counts as confirming in the next block, as AcceptToMemoryPool and the
    // mempool re-check treat it (I-2 with coinHeight = tip+1), so the cancel may be its child.
    CScript origin;
    int64_t coinHeight;
    const bool confirmed = h >= 0;
    if (confirmed) {
        auto rec = GetTemplateOut(*g_vaultdb, op);
        if (!rec || rec->origin.empty()) throw JSONRPCError(RPC_INTERNAL_ERROR, "the intent's originating vault script is missing from the vault database");
        origin = rec->origin;
        coinHeight = rec->height;
    } else {
        std::shared_ptr<const CTransaction> parent = mempool.get(op.hash);   // 6.20.0: mempool.get, not lookup
        if (!parent) throw JSONRPCError(RPC_INVALID_PARAMETER, "not an unspent intent output");
        for (const CTxIn& in : parent->vin) {
            CTxOut vcoin;
            int vh;
            VaultParams vp;
            if (GetCoin(in.prevout, vcoin, vh) && ParseVault(vcoin.scriptPubKey, vp) && ScriptHash256(vcoin.scriptPubKey) == ip.vaultHash) {
                origin = vcoin.scriptPubKey;
                break;
            }
        }
        if (origin.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "the mempool intent's originating vault is not among its transaction's inputs");
        coinHeight = NextHeight();
    }
    if (NextHeight() - coinHeight >= ip.delay) throw JSONRPCError(RPC_MISC_ERROR, strprintf("the intent matured at height %d; it can no longer be cancelled", coinHeight + ip.delay));
    // The remembered build, byte-identical (sign once): the same transaction whether the intent was in the mempool
    // or has confirmed since, and across restarts (07/N-2); a lost fee input is replaced without changing the
    // sighash (01/V-2).
    PruneVaultBuilds();
    CMutableTransaction mtx;
    std::string build = "new";
    auto cached = pwalletMain->mapVaultBuilds.find(op);
    bool keepSigned = false;
    if (cached != pwalletMain->mapVaultBuilds.end()) {
        const CMutableTransaction& c = cached->second;
        if (rebuild || c.vin.empty() || c.vin[0].prevout != op || c.vout.size() <= extra.size() || c.vout[0].scriptPubKey != origin ||
            c.vout[0].nValue != coin.nValue || !std::equal(extra.begin(), extra.end(), c.vout.begin() + 1)) {
            keepSigned = WalletSignedPrevout(op);
            if (!keepSigned) UnlockBuildInputs(op, c);
        } else {
            mtx = c;
            build = "reused";
            if (!FeeInputsUnspent(op, mtx)) {
                Refee(mtx, 0, coin);
                build = "refunded";
            }
        }
    }
    if (build == "new") {
        mtx = NewTx();
        mtx.vin.push_back(CTxIn(op, CScript(), CTxIn::SEQUENCE_FINAL));
        mtx.vout.push_back(CTxOut(coin.nValue, origin));
        for (const CTxOut& o : extra) mtx.vout.push_back(o);
        Fund(mtx, coin.nValue, FundMode::SMALL_CHANGE);
    }
    if (!keepSigned) RememberBuild(op, mtx);
    const uint256 sighash = SetSighash(mtx, 0, coin);
    auto k = Snapshot()->Threshold(ip.cancelSetId, ROLE_CANCEL);
    UniValue o(UniValue::VOBJ);
    o.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
    o.pushKV("required", k ? *k : 0);
    o.pushKV("cancelsetid", ip.cancelSetId.GetHex());
    o.pushKV("deadline", coinHeight + ip.delay - 1);
    o.pushKV("intentconfirmed", confirmed);
    if (buildFields) {
        o.pushKV("sighash", HexStr(sighash.begin(), sighash.end()));
        o.pushKV("build", build);
    }
    return o;
}

UniValue vault_buildcancel(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "vault_buildcancel \"intentoutpoint\" ( rebuild )\n"
            "\nBuild the CANCEL spend of an intent before it matures: its value back into the vault it was unlocked from\n"
            "(I-2), fee from this wallet (unsigned; never from the intent's value). Collect the cancel set's signatures with\n"
            "set_signcancel, then vault_send.\n"
            "An intent still in the mempool can be cancelled too: the cancel spends it as a mempool child. Called again for\n"
            "the same intent it returns the same transaction (remembered in the wallet, across restarts); if its fee inputs\n"
            "were spent meanwhile it is re-funded (vault_refee) with the same sighash (members sign once: a second, different\n"
            "cancel signature is an equivocation). rebuild=true discards the remembered build (only before anyone signed it).\n"
            "A YED claim intent (tag YED) is refused: its cancel must also refund the claim's burn (CAN-1), which\n"
            "yed_buildcancel builds.\n"
            "\nResult: {\"hex\", \"required\", \"cancelsetid\", \"deadline\" (the last height a cancel can confirm at; for an\n"
            "unconfirmed intent, if the intent confirms in the next block), \"intentconfirmed\", \"sighash\", \"build\" (\"new\",\n"
            "\"reused\" or \"refunded\")}\n"
            + HelpExampleCli("vault_buildcancel", "\"txid:0\"") + HelpExampleRpc("vault_buildcancel", "\"txid:0\""));
    EnsureWallet(fHelp);
    const bool rebuild = params.size() > 1 && !params[1].isNull() && params[1].get_bool();
    return BuildIntentCancel(ParseOutPoint(params[0], "intentoutpoint"), {}, false, rebuild, true);
}

UniValue set_signcancel(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "set_signcancel \"hex\" ( {\"acknowledgerestore\": true} )\n"
            "\nAdd this wallet's current-member cancel signatures (OP_CHECKSETSIG role 2 of the intent's cancelsetid) to an\n"
            "intent CANCEL spend, up to the cancel set's cancelthreshold. Sign once, acknowledgerestore: as set_signunlock.\n"
            "\nResult: as set_signunlock\n"
            + HelpExampleCli("set_signcancel", "\"hex\"") + HelpExampleRpc("set_signcancel", "\"hex\""));
    EnsureWallet(fHelp);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    CMutableTransaction mtx = DecodeMutable(params[0]);
    CTxOut coin;
    int h;
    VaultParams vp;
    IntentParams ip;
    TemplateKind kind;
    size_t idx = FindTemplateInput(mtx, coin, h, vp, ip, kind);
    if (kind != TemplateKind::INTENT) throw JSONRPCError(RPC_INVALID_PARAMETER, "the template input is not an intent");
    return SignSetInPlace(mtx, idx, coin, ip.cancelSetId, ROLE_CANCEL, AckRestore(params));
}

UniValue vault_refee(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "vault_refee \"hex\"\n"
            "\nRe-fund a vault UNLOCK or CANCEL spend (01/V-2): every input but the vault/intent input is replaced by this\n"
            "wallet's coins; the template input (with any set signatures already on it) and every output stay as they are,\n"
            "so the signatures stay valid: they are over SIGHASH_ALL|ANYONECANPAY, which binds the template input and the\n"
            "outputs, not the fee inputs. Anyone may re-fund. Use it when a fee input of a signed spend was spent elsewhere.\n"
            "The outputs, the builder's change included, are bound, so there can be no new change output: the new input is one\n"
            "coin worth exactly what the outputs need beyond the template coin plus the fee (an existing coin within 1,000\n"
            "zatoshi of it, else a self-send of exactly that amount, broadcast now, that the spend chains on). The fee never\n"
            "comes from the vault's value (S-2, I-1, I-2). The new input is unsigned and locked: vault_send on this node signs it.\n"
            "\nResult: {\"hex\", \"sighash\" (unchanged), \"fee\", \"replaced\": [\"txid:n\", ...]}\n"
            + HelpExampleCli("vault_refee", "\"hex\"") + HelpExampleRpc("vault_refee", "\"hex\""));
    EnsureWallet(fHelp);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureVaultActive();
    CMutableTransaction mtx = DecodeMutable(params[0]);
    CTxOut coin;
    int h;
    VaultParams vp;
    IntentParams ip;
    TemplateKind kind;
    const size_t idx = FindTemplateInput(mtx, coin, h, vp, ip, kind);
    const COutPoint templ = mtx.vin[idx].prevout;
    PruneVaultBuilds();
    const std::vector<COutPoint> replaced = Refee(mtx, idx, coin);
    // Remember this re-fund so vault_send will sign the new fee coin. Same outputs: only the fee
    // inputs moved (01/V-2). Different outputs, and this wallet has not signed the prevout yet:
    // the caller replaced an unsigned build (Hawkeye drops the change output, then re-funds).
    // A signed build with different outputs keeps its fee inputs: vault_send of those bytes
    // still has to sign them.
    auto memo = pwalletMain->mapVaultBuilds.find(templ);
    if (memo == pwalletMain->mapVaultBuilds.end() || memo->second.vout == mtx.vout || !WalletSignedPrevout(templ))
        RememberBuild(templ, mtx);
    CAmount in = coin.nValue;
    for (size_t i = 1; i < mtx.vin.size(); i++) {
        CTxOut prev;
        int ph;
        if (GetCoin(mtx.vin[i].prevout, prev, ph)) in += prev.nValue;
    }
    const uint256 sighash = SetSighash(mtx, 0, coin);
    UniValue o(UniValue::VOBJ);
    o.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
    o.pushKV("sighash", HexStr(sighash.begin(), sighash.end()));
    o.pushKV("fee", ValueFromAmount(in - CTransaction(mtx).GetValueOut()));
    UniValue r(UniValue::VARR);
    for (const COutPoint& op : replaced) r.push_back(OutPointStr(op));
    o.pushKV("replaced", r);
    return o;
}

UniValue SetSigRecordJSON(const VaultSetSigRecord& r)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("setid", r.setId.GetHex());
    o.pushKV("prevout", OutPointStr(r.prevout));
    o.pushKV("role", (int)r.role);
    o.pushKV("sighash", HexStr(r.sighash.begin(), r.sighash.end()));
    return o;
}

UniValue set_listsigned(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "set_listsigned\n"
            "\nThe wallet's set sign-once records (07/F-5): for every (setid, prevout) its member keys signed a spend of, the\n"
            "role (1 unlock, 2 cancel) and the sighash signed. Back them up with wallet.dat (the seed does not carry them);\n"
            "import them on a restored wallet with set_importsigned, then set_acknowledgerestore. dumpwallet / z_exportwallet\n"
            "write them\n"
            "as vaultsetsig= lines, and \"restored\" says whether set_signunlock / set_signcancel refuse (set-sign-restored).\n"
            "\nResult: {\"restored\", \"records\": [{\"setid\", \"prevout\", \"role\", \"sighash\"}]}\n"
            + HelpExampleCli("set_listsigned", "") + HelpExampleRpc("set_listsigned", ""));
    EnsureWallet(fHelp);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    CWalletDB walletdb(pwalletMain->strWalletFile);
    std::vector<VaultSetSigRecord> recs;
    if (!walletdb.ListVaultSetSigs(recs)) throw JSONRPCError(RPC_WALLET_ERROR, "cannot read the sign-once records");
    UniValue arr(UniValue::VARR);
    for (const VaultSetSigRecord& r : recs) arr.push_back(SetSigRecordJSON(r));
    UniValue o(UniValue::VOBJ);
    o.pushKV("restored", walletdb.ReadVaultSignRestored());
    o.pushKV("records", arr);
    return o;
}

UniValue set_importsigned(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "set_importsigned [{\"setid\", \"prevout\", \"role\", \"sighash\"}, ...]\n"
            "\nImport set sign-once records (07/F-5), as set_listsigned printed them on the wallet that signed. A record that\n"
            "differs from one this wallet holds for the same (setid, prevout) refuses the whole import: two signing histories\n"
            "for one key are never merged silently. Identical records are skipped. The import does NOT clear the restore\n"
            "marker (the history may be stale): set_acknowledgerestore does, once the operator has checked it is complete.\n"
            "\nResult: {\"imported\", \"present\"}\n"
            + HelpExampleCli("set_importsigned", "'[{\"setid\":\"..\",\"prevout\":\"txid:0\",\"role\":1,\"sighash\":\"..\"}]'")
            + HelpExampleRpc("set_importsigned", "[{\"setid\":\"..\",\"prevout\":\"txid:0\",\"role\":1,\"sighash\":\"..\"}]"));
    EnsureWallet(fHelp);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    const UniValue& arr = params[0].get_array();
    std::vector<VaultSetSigRecord> recs;
    for (size_t i = 0; i < arr.size(); i++) {
        const UniValue& o = arr[i].get_obj();
        VaultSetSigRecord r;
        r.setId = ParseSetId(find_value(o, "setid"), "setid");
        r.prevout = ParseOutPoint(find_value(o, "prevout"), "prevout");
        const UniValue& role = find_value(o, "role");
        if (!role.isNum() || (role.get_int() != ROLE_UNLOCK && role.get_int() != ROLE_CANCEL))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "role must be 1 (unlock) or 2 (cancel)");
        r.role = (uint8_t)role.get_int();
        r.sighash = ParseRaw32(find_value(o, "sighash"), "sighash");
        recs.push_back(r);
    }
    int added = 0, present = 0;
    std::string conflict;
    if (!ImportVaultSetSigs(*pwalletMain, recs, added, present, conflict))
        throw JSONRPCError(RPC_WALLET_ERROR, conflict);
    UniValue o(UniValue::VOBJ);
    o.pushKV("imported", added);
    o.pushKV("present", present);
    return o;
}

UniValue set_acknowledgerestore(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "set_acknowledgerestore\n"
            "\nClear the restore marker (07/F-5, review S2): the operator confirms that this wallet's sign-once history\n"
            "(set_listsigned) is complete -- every set signature its member keys ever made is recorded here, because no\n"
            "other host, wallet copy or backup has signed with them since the history was taken. set_signunlock /\n"
            "set_signcancel then sign wherever the record allows. Imports never clear the marker. Imported keys that are\n"
            "not yet a set member stay pending: a later SET_JOIN of one sets the marker again.\n"
            "\nResult: {\"restored\" (false), \"pendingkeys\" (imported keys still watched for a SET_JOIN)}\n"
            + HelpExampleCli("set_acknowledgerestore", "") + HelpExampleRpc("set_acknowledgerestore", ""));
    EnsureWallet(fHelp);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    CWalletDB walletdb(pwalletMain->strWalletFile);
    if (walletdb.ReadVaultSignRestored() && !walletdb.EraseVaultSignRestored())
        throw JSONRPCError(RPC_WALLET_ERROR, "cannot clear the vault sign-once restore marker");
    LogPrintf("vault: the operator acknowledged the restore (set_acknowledgerestore): restore marker cleared\n");
    UniValue o(UniValue::VOBJ);
    o.pushKV("restored", walletdb.ReadVaultSignRestored());
    o.pushKV("pendingkeys", (int)pwalletMain->setVaultPendingKeys.size());
    return o;
}

UniValue vault_send(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "vault_send \"hex\" ( {\"dryrun\":bool, \"allowinputs\":[\"txid:n\",...], \"allowoutflow\":n} )\n"
            "\nSign this wallet's (fee) inputs of a vault spend built by vault_buildunlock / vault_buildcancel /\n"
            "yed_buildcancel / vault_app / vault_refee, keeping the template input's scriptSig, and broadcast it.\n"
            "Signs only coins this wallet's remembered build chose for these exact outputs. Any other spendable coin of\n"
            "this wallet is refused (vault-send-foreign-input) unless allowinputs names it, and nothing is signed. The\n"
            "wallet's net outflow above the fee cap is refused (vault-send-outflow) unless allowoutflow is at least\n"
            "that outflow. dryrun returns a preview and does not sign or broadcast.\n"
            "\nResult (dryrun false or omitted): \"txid\"\n"
            "Result (dryrun true): {\"template\", \"act\", \"sign\", \"foreign\", \"outputs\", \"fee\", \"outflow\", \"wouldrefuse\"}\n"
            + HelpExampleCli("vault_send", "\"hex\"") + HelpExampleRpc("vault_send", "\"hex\""));
    EnsureWallet(fHelp);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    PruneVaultBuilds();
    CMutableTransaction mtx = DecodeMutable(params[0]);
    CTxOut coin;
    int h;
    VaultParams vp;
    IntentParams ip;
    TemplateKind kind;
    const size_t idx = FindTemplateInput(mtx, coin, h, vp, ip, kind);
    UniValue templ(UniValue::VOBJ);
    templ.pushKV("outpoint", mtx.vin[idx].prevout.ToString());
    templ.pushKV("kind", kind == TemplateKind::VAULT ? "vault" : "intent");
    const std::optional<uint8_t> sel = ParseSelector(mtx.vin[idx].scriptSig);
    templ.pushKV("selector", sel ? UniValue((int)*sel) : NullUniValue);
    return HandoffSend(mtx, mtx.vin[idx].prevout, ParseHandoffOptions(params), templ);
}

UniValue vault_release(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "vault_release \"intentoutpoint\" ( \"address\"|\"script\" )\n"
            "\nRelease a matured intent to its recipient (RELEASE, selector 1, nSequence = delay; U-15: anyone may). The\n"
            "intent commits only SHA256 of the recipient script, so the recipient is the argument, or a script this node\n"
            "built the intent for, or a P2PKH / P2SH script of this wallet, or the TX_PQPKH script of a post-quantum key\n"
            "this wallet holds (the owner's residual, quantum spec F-3). An address may be sq…/tq…/rq…; a pqkeyid is refused\n"
            "(pass the address or the script). Fee from this wallet.\n"
            "\nResult: \"txid\"\n"
            + HelpExampleCli("vault_release", "\"txid:0\"") + HelpExampleRpc("vault_release", "\"txid:0\", \"address\""));
    EnsureWallet(fHelp);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureVaultActive();
    const COutPoint op = ParseOutPoint(params[0], "intentoutpoint");
    CTxOut coin;
    int h;
    IntentParams ip;
    if (!GetCoin(op, coin, h) || !ParseIntent(coin.scriptPubKey, ip)) throw JSONRPCError(RPC_INVALID_PARAMETER, "not an unspent intent output");
    if (h < 0 || h + ip.delay > NextHeight())
        throw JSONRPCError(RPC_MISC_ERROR, h < 0 ? std::string("the intent is not confirmed") : strprintf("the intent matures at height %d", h + ip.delay));
    std::optional<CScript> dest;
    if (params.size() > 1 && !params[1].isNull()) {
        const std::string a = params[1].get_str();
        KeyIO keyIO(Params());
        CTxDestination d = keyIO.DecodeDestination(a);
        if (IsValidDestination(d)) dest = GetScriptForDestination(d);
        else if (IsHex(a)) { std::vector<unsigned char> b = ParseHex(a); dest = CScript(b.begin(), b.end()); }
        else throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "not an address or a script: " + a);
        // A 33-byte pqkeyid (scheme || keyhash, as vault_list and z_importpqkey print it) is not a script.
        if (ScriptHash256(*dest) != ip.recipientHash && a.size() == 66 && IsHex(a) && pq::IsKnownScheme(ParseHex(a)[0]))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "that looks like a pqkeyid: pass the address or the script, not a pqkeyid");
    } else if (pwalletMain->mapVaultRecipients.count(ip.recipientHash)) {
        dest = pwalletMain->mapVaultRecipients[ip.recipientHash];
    } else {
        for (const CKeyID& id : pwalletMain->GetKeys()) {
            CScript s = GetScriptForDestination(id);
            if (ScriptHash256(s) == ip.recipientHash) { dest = s; break; }
        }
        // The owner's own residual (quantum spec F-3: SHA256(PQPKH(owner))) or any TX_PQPKH recipient whose PQ
        // key this wallet holds, so the owner can release without passing the script (e.g. after a restart).
        if (!dest) {
            for (const CPQKeyID& id : pwalletMain->GetPQKeys()) {
                CScript s = GetScriptForPQKey(id);
                if (ScriptHash256(s) == ip.recipientHash) { dest = s; break; }
            }
        }
    }
    if (!dest) throw JSONRPCError(RPC_INVALID_PARAMETER, "the recipient script is unknown here; pass it");
    if (ScriptHash256(*dest) != ip.recipientHash) throw JSONRPCError(RPC_INVALID_PARAMETER, "that script is not the intent's recipient");
    CMutableTransaction mtx = NewTx();
    mtx.vin.push_back(CTxIn(op, CScript() << OP_1, (uint32_t)ip.delay));
    mtx.vout.push_back(CTxOut(coin.nValue, *dest));
    Fund(mtx, coin.nValue);
    SignWalletInputs(mtx);
    return Broadcast(CTransaction(mtx)).GetHex();
}

UniValue vault_ownerspend(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw std::runtime_error(
            "vault_ownerspend \"outpoint\" \"address\"\n"
            "\nSpend a vault (or intent) with this wallet's owner key to address, less the fee: selector 2 (the OWNER branch,\n"
            "nLockTime = ownerheight) once the next block is past ownerheight, else selector 3 (OWNER-RELEASED) when the set\n"
            "is released (dormant or wound down, plan §3.7). An intent has only selector 3.\n"
            "\nResult: {\"txid\", \"selector\"}\n"
            + HelpExampleCli("vault_ownerspend", "\"txid:0\" \"address\"") + HelpExampleRpc("vault_ownerspend", "\"txid:0\", \"address\""));
    EnsureWallet(fHelp);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureVaultActive();
    const COutPoint op = ParseOutPoint(params[0], "outpoint");
    CTxOut coin;
    int h;
    if (!GetCoin(op, coin, h)) throw JSONRPCError(RPC_INVALID_PARAMETER, "not an unspent output");
    KeyIO keyIO(Params());
    CTxDestination d = keyIO.DecodeDestination(params[1].get_str());
    if (!IsValidDestination(d)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "invalid transparent address");
    auto snap = Snapshot();
    const int64_t next = NextHeight();
    VaultParams vp;
    IntentParams ip;
    CPQKeyID owner;
    int selector = 0;
    CMutableTransaction mtx = NewTx();
    uint32_t seq = CTxIn::SEQUENCE_FINAL;
    if (ParseVault(coin.scriptPubKey, vp)) {
        owner = vp.owner;
        if (next > vp.ownerHeight) {
            selector = SEL_OWNER;
            mtx.nLockTime = (uint32_t)vp.ownerHeight;
            seq = CTxIn::SEQUENCE_FINAL - 1;
        } else if (snap->IsReleased(vp.setId, next)) {
            selector = SEL_RELEASED;
        } else {
            throw JSONRPCError(RPC_MISC_ERROR, strprintf("the owner branch opens at height %d and the set is not released", vp.ownerHeight + 1));
        }
    } else if (ParseIntent(coin.scriptPubKey, ip)) {
        owner = ip.owner;
        if (!snap->IsReleased(ip.setId, next)) throw JSONRPCError(RPC_MISC_ERROR, "the intent's set is not released");
        selector = SEL_RELEASED;
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "not a vault or intent output");
    }
    if (coin.nValue <= VAULT_RPC_FEE) throw JSONRPCError(RPC_INVALID_PARAMETER, "the output does not cover the fee");
    // The owner is a post-quantum key (quantum plan §4.3): the wallet signs with it (scheme-dispatched,
    // quantum spec §1.5) and the fee is max(VAULT_RPC_FEE, the vault/Yellowback $/KB rate x size) capped at
    // YedMaxTxFee() (quantum plan §4.5, D-Q-23 (b): policy.h AttestedFeePolicy; -pqfeerate without a price).
    // 6.20.0: never below the ZIP-317 conventional fee (an SLH-DSA owner scriptSig is ~53 logical actions, ~26.5k zat),
    // so a node with -txunpaidactionlimit=0 relays it (review, q/fees follow-up). Small vault (review L-1, as the YED
    // builder's owner path, yellowback::ClampOwnerNetworkFee): when the priced fee would leave the owner a dust output,
    // it is clamped to max(YedFloorSizeFee(VAULT_RPC_FEE, size), the ZIP-317 conventional fee) instead of eating the vault.
    if (!pwalletMain->HavePQKey(owner)) throw JSONRPCError(RPC_WALLET_ERROR, strprintf("owner %s is not a post-quantum key of this wallet", PQKeyIdHex(owner)));
    mtx.vin.push_back(CTxIn(op, CScript(), seq));
    mtx.vout.push_back(CTxOut(coin.nValue - VAULT_RPC_FEE, GetScriptForDestination(d)));
    const CAmount dust = mtx.vout[0].GetDustThreshold();
    const unsigned int flags = SignFlags();
    const uint32_t branch = NextBranchId();
    CAmount fee = VAULT_RPC_FEE;
    for (int pass = 0; pass < 3; pass++) {
        if (coin.nValue - fee < std::max<CAmount>(dust, 1))
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("the output does not cover the fee %s and a non-dust output", FormatMoney(fee)));
        mtx.vout[0].nValue = coin.nValue - fee;
        ScriptError serror = SCRIPT_ERR_OK;
        const CTransaction txc(mtx);
        PrecomputedTransactionData txdata = TxData(txc);
        const SetSigChecker checker(&txc, 0, coin.nValue, false, txdata, snap, next);   // selector 3 reads the set state
        if (!SignPQOwnerSpend(*pwalletMain, owner, coin.scriptPubKey, mtx, 0, coin.nValue, selector, branch, flags, &serror, &checker))
            throw JSONRPCError(RPC_WALLET_ERROR, strprintf("cannot sign the owner spend (selector %d): %s", selector, ScriptErrorString(serror)));
        const CTransaction signedTx(mtx);
        const size_t size = ::GetSerializeSize(signedTx, SER_NETWORK, PROTOCOL_VERSION);
        const CAmount conventional = signedTx.GetConventionalFee();
        const CAmount floorFee = std::max(YedFloorSizeFee(VAULT_RPC_FEE, size), conventional);
        const CAmount priced = std::max(std::min(YedSizeFee(VAULT_RPC_FEE, size), YedMaxTxFee()), conventional);
        const CAmount sized = yellowback::ClampOwnerNetworkFee(priced, coin.nValue, dust, floorFee);
        if (sized == fee) break;
        fee = sized;   // the size does not change with the output's value: one more pass signs it
    }
    UniValue r(UniValue::VOBJ);
    r.pushKV("txid", Broadcast(CTransaction(mtx)).GetHex());
    r.pushKV("selector", selector);
    return r;
}

UniValue vault_app(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "vault_app \"outpoint\" ( [{\"address\"|\"script\": .., \"amount\": x}, ...] )\n"
            "\nBuild the APP spend (selector 4, nLockTime = appheight) of a vault for a module: the intents and re-lock as\n"
            "vault_buildunlock, fee from this wallet, unsigned. A registered module adds its own outputs / rules; with no\n"
            "module for the tag the primitive alone governs it (S-2, S-3). The build is remembered; vault_send on this\n"
            "node signs only the coins it chose for these outputs.\n"
            "\nResult: {\"hex\", \"intents\"}\n"
            + HelpExampleCli("vault_app", "\"txid:0\" '[{\"address\":\"..\",\"amount\":1}]'")
            + HelpExampleRpc("vault_app", "\"txid:0\", []"));
    EnsureWallet(fHelp);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureVaultActive();
    const COutPoint op = ParseOutPoint(params[0], "outpoint");
    CTxOut coin;
    int h;
    VaultParams vp;
    if (!GetCoin(op, coin, h) || !ParseVault(coin.scriptPubKey, vp)) throw JSONRPCError(RPC_INVALID_PARAMETER, "not an unspent vault output");
    if (vp.appHeight == 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "the vault has no APP branch (appheight 0, S-4)");
    if (NextHeight() <= vp.appHeight) throw JSONRPCError(RPC_MISC_ERROR, strprintf("the APP branch opens at height %d", vp.appHeight + 1));
    CMutableTransaction mtx = NewTx();
    mtx.nLockTime = (uint32_t)vp.appHeight;
    mtx.vin.push_back(CTxIn(op, CScript() << OP_4, CTxIn::SEQUENCE_FINAL - 1));
    UniValue intents = AddIntents(mtx, vp, coin, params.size() > 1 && !params[1].isNull() ? params[1].get_array() : UniValue(UniValue::VARR));
    Fund(mtx, coin.nValue);
    // The same vaultbuild record as an unlock, keyed by the vault. An unlock or cancel memo for this outpoint is left
    // alone (sign once); a previous APP build is replaced.
    auto existing = pwalletMain->mapVaultBuilds.find(op);
    if (existing != pwalletMain->mapVaultBuilds.end()) {
        const CMutableTransaction& prev = existing->second;
        const bool app = !prev.vin.empty() && prev.vin[0].prevout == op && prev.vin[0].nSequence != CTxIn::SEQUENCE_FINAL;
        if (!app) {
            UnlockBuildInputs(op, mtx);
            throw JSONRPCError(RPC_INVALID_PARAMETER, "this wallet already built a different spend of this vault");
        }
        if (prev.vout != mtx.vout) UnlockBuildInputs(op, prev);
    }
    RememberBuild(op, mtx);
    UniValue o(UniValue::VOBJ);
    o.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
    o.pushKV("intents", intents);
    return o;
}

#endif // ENABLE_WALLET

} // namespace

#ifdef ENABLE_WALLET
/** yed_buildcancel (rpc/yellowbackwallet.cpp, CAN-1): the I-2 cancel of a YED claimant intent with its refund output and,
 *  since CAN-2, the CANCEL_COSIGN marker (`extra` follows vout[0] in order). */
UniValue BuildYedIntentCancel(const COutPoint& intent, const std::vector<CTxOut>& extra)
{
    return BuildIntentCancel(intent, extra, true, false, false);
}
#endif

static const CRPCCommand commands[] =
{ //  category   name                   actor (function)       okSafeMode
  //  ---------  ---------------------  ---------------------  ----------
    { "vault",   "vault_getinfo",       &vault_getinfo,        true  },
    { "vault",   "set_list",            &set_list,             true  },
    { "vault",   "set_getinfo",         &set_getinfo,          true  },
    { "vault",   "vault_list",          &vault_list,           true  },
    { "vault",   "vault_decodescript",  &vault_decodescript,   true  },
#ifdef ENABLE_WALLET
    { "vault",   "set_create",          &set_create,           false },
    { "vault",   "set_join",            &set_join,             false },
    { "vault",   "set_heartbeat",       &set_heartbeat,        false },
    { "vault",   "set_leave",           &set_leave,            false },
    { "vault",   "set_buildact",        &set_buildact,         false },
    { "vault",   "set_signact",         &set_signact,          false },
    { "vault",   "set_sendact",         &set_sendact,          false },
    { "vault",   "set_equivocation",    &set_equivocation,     false },
    { "vault",   "vault_lock",          &vault_lock,           false },
    { "vault",   "vault_getnewowner",   &vault_getnewowner,    false },
    { "vault",   "vault_buildunlock",   &vault_buildunlock,    false },
    { "vault",   "set_signunlock",      &set_signunlock,       false },
    { "vault",   "vault_buildcancel",   &vault_buildcancel,    false },
    { "vault",   "set_signcancel",      &set_signcancel,       false },
    { "vault",   "vault_refee",         &vault_refee,          false },
    { "vault",   "set_listsigned",      &set_listsigned,       false },
    { "vault",   "set_importsigned",    &set_importsigned,     false },
    { "vault",   "set_acknowledgerestore", &set_acknowledgerestore, false },
    { "vault",   "vault_send",          &vault_send,           false },
    { "vault",   "vault_release",       &vault_release,        false },
    { "vault",   "vault_ownerspend",    &vault_ownerspend,     false },
    { "vault",   "vault_app",           &vault_app,            false },
#endif
};

void RegisterVaultRPCCommands(CRPCTable& tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
