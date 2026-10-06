// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "vault/act.h"

#include "hash.h"
#include "key.h"

#include <cstring>

namespace vault {

typedef std::vector<unsigned char> valtype;

namespace {

class Writer
{
public:
    valtype b;
    void u8(uint8_t v) { b.push_back(v); }
    void u16(uint16_t v) { for (int i = 0; i < 2; i++) b.push_back((v >> (8 * i)) & 0xff); }
    void u32(uint32_t v) { for (int i = 0; i < 4; i++) b.push_back((v >> (8 * i)) & 0xff); }
    void i64(int64_t v)
    {
        uint64_t u = (uint64_t)v;
        for (int i = 0; i < 8; i++) b.push_back((u >> (8 * i)) & 0xff);
    }
    void bytes(const unsigned char* p, size_t n) { b.insert(b.end(), p, p + n); }
    void u256(const uint256& h) { bytes(h.begin(), 32); }
    void key(const CPubKey& k)
    {
        // A key of the wrong size encodes as 33 zero bytes (never decodes as valid).
        if (k.size() == 33) bytes(k.begin(), 33);
        else b.insert(b.end(), 33, 0);
    }
    void sig(const valtype& s)
    {
        if (s.size() == RECOVERABLE_SIG_SIZE) bytes(s.data(), s.size());
        else b.insert(b.end(), RECOVERABLE_SIG_SIZE, 0);
    }
    void outpoint(const COutPoint& o) { u256(o.hash); u32(o.n); }
};

class Reader
{
    const valtype& b;
    size_t pos;
    bool ok = true;

public:
    Reader(const valtype& b, size_t pos) : b(b), pos(pos) {}
    bool Ok() const { return ok; }
    bool AtEnd() const { return pos == b.size(); }
    const unsigned char* take(size_t n)
    {
        if (!ok || pos > b.size() || b.size() - pos < n) { ok = false; return nullptr; }
        const unsigned char* p = b.data() + pos;
        pos += n;
        return p;
    }
    uint8_t u8() { const unsigned char* p = take(1); return p ? p[0] : 0; }
    uint16_t u16()
    {
        const unsigned char* p = take(2);
        return p ? (uint16_t)(p[0] | ((uint16_t)p[1] << 8)) : 0;
    }
    uint32_t u32()
    {
        const unsigned char* p = take(4);
        if (!p) return 0;
        uint32_t v = 0;
        for (int i = 0; i < 4; i++) v |= (uint32_t)p[i] << (8 * i);
        return v;
    }
    int64_t i64()
    {
        const unsigned char* p = take(8);
        if (!p) return 0;
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
        return (int64_t)v;
    }
    uint256 u256()
    {
        uint256 h;
        const unsigned char* p = take(32);
        if (p) std::memcpy(h.begin(), p, 32);
        return h;
    }
    CPubKey key()
    {
        const unsigned char* p = take(33);
        if (!p) return CPubKey();
        return CPubKey(p, p + 33);
    }
    valtype raw(size_t n)
    {
        const unsigned char* p = take(n);
        if (!p) return valtype();
        return valtype(p, p + n);
    }
    COutPoint outpoint()
    {
        uint256 h = u256();
        uint32_t n = u32();
        return COutPoint(h, n);
    }
};

} // namespace

size_t ActBodySize(uint8_t type)
{
    switch (type) {
    case ACT_SET_CREATE: return 64;
    case ACT_SET_JOIN: return 70;
    case ACT_SET_HEARTBEAT: return 65;
    case ACT_SET_REMOVE: return 66;
    case ACT_SET_EQUIVOCATION: return 264;
    case ACT_SET_WINDDOWN: return 32;
    default: return 0;
    }
}

bool SetCreateBody::Valid() const
{
    if (seats < 1 || seats > MAX_SET_SEATS) return false;
    for (uint8_t t : {unlockThreshold, cancelThreshold, slashThreshold}) {
        if (t < 1 || t > seats) return false;
    }
    if (rateLimitBps > MAX_RATE_BPS) return false;
    if (rateWindow < 1 || rateWindow > MAX_SET_WINDOW) return false;
    if (livenessWindow < 1 || livenessWindow > MAX_SET_WINDOW) return false;
    if (bondMin < 1 || !MoneyRange(bondMin)) return false;
    if (!IsCompressedKey(admitKey)) return false;
    if ((flags & ~SET_FLAG_OPEN) != 0) return false;
    return true;
}

namespace {
bool SigHeaderOk(const std::vector<unsigned char>& sig)
{
    return sig.size() == RECOVERABLE_SIG_SIZE && sig[0] >= 31 && sig[0] <= 34;
}
bool RoleOk(uint8_t role) { return role == 1 || role == 2; }
} // namespace

bool ActFieldsValid(const Act& act)
{
    for (const auto& sig : act.sigs) {
        if (!SigHeaderOk(sig)) return false;
    }
    switch (act.type) {
    case ACT_SET_CREATE:
        return act.create.Valid();
    case ACT_SET_JOIN:
        return IsCompressedKey(act.join.memberKey) && act.join.bondLocktime >= 1 && act.join.bondLocktime < 500000000;
    case ACT_SET_HEARTBEAT:
        return IsCompressedKey(act.heartbeat.memberKey);
    case ACT_SET_REMOVE:
        return IsCompressedKey(act.remove.memberKey) && act.remove.burn <= 1;
    case ACT_SET_EQUIVOCATION:
        return RoleOk(act.equivocation.roleA) && RoleOk(act.equivocation.roleB) &&
               SigHeaderOk(act.equivocation.sigA) && SigHeaderOk(act.equivocation.sigB);
    case ACT_SET_WINDDOWN:
        return true;
    default:
        return false;
    }
}

SetId Act::TargetSet() const
{
    switch (type) {
    case ACT_SET_JOIN: return join.setId;
    case ACT_SET_HEARTBEAT: return heartbeat.setId;
    case ACT_SET_REMOVE: return remove.setId;
    case ACT_SET_EQUIVOCATION: return equivocation.setId;
    case ACT_SET_WINDDOWN: return winddown.setId;
    default: return SetId();
    }
}

bool IsActOutput(const CScript& spk)
{
    if (spk.size() < 1 || spk[0] != OP_RETURN) return false;
    CScript::const_iterator pc = spk.begin() + 1;
    opcodetype op;
    valtype data;
    if (!spk.GetOp(pc, op, data)) return false;
    if (op > OP_PUSHDATA4) return false;
    return data.size() >= 2 && data[0] == ACT_MAGIC_0 && data[1] == ACT_MAGIC_1;
}

std::vector<unsigned char> EncodePayload(const Act& act)
{
    if (ActBodySize(act.type) == 0) return valtype();
    Writer w;
    w.u8(ACT_MAGIC_0);
    w.u8(ACT_MAGIC_1);
    w.u8(ACT_VERSION);
    w.u8(act.type);
    switch (act.type) {
    case ACT_SET_CREATE: {
        const SetCreateBody& c = act.create;
        w.u8(c.seats); w.u8(c.unlockThreshold); w.u8(c.cancelThreshold); w.u8(c.slashThreshold);
        w.u8(c.flags); w.u16(c.rateLimitBps); w.u32(c.rateWindow); w.u32(c.livenessWindow);
        w.i64(c.bondMin); w.u32(c.bondLockMin); w.u32(c.maturity); w.key(c.admitKey);
        break;
    }
    case ACT_SET_JOIN:
        w.u256(act.join.setId); w.key(act.join.memberKey); w.u32(act.join.bondLocktime); w.u8(act.join.bondVout);
        break;
    case ACT_SET_HEARTBEAT:
        w.u256(act.heartbeat.setId); w.key(act.heartbeat.memberKey);
        break;
    case ACT_SET_REMOVE:
        w.u256(act.remove.setId); w.key(act.remove.memberKey); w.u8(act.remove.burn);
        break;
    case ACT_SET_EQUIVOCATION: {
        const SetEquivocationBody& e = act.equivocation;
        w.u256(e.setId); w.outpoint(e.prevout);
        w.u8(e.roleA); w.u256(e.sighashA); w.sig(e.sigA);
        w.u8(e.roleB); w.u256(e.sighashB); w.sig(e.sigB);
        break;
    }
    case ACT_SET_WINDDOWN:
        w.u256(act.winddown.setId);
        break;
    }
    return w.b;
}

CScript EncodeAct(const Act& act)
{
    valtype P = EncodePayload(act);
    if (P.empty()) return CScript();
    CScript s;
    s << OP_RETURN << P;
    for (const valtype& sig : act.sigs) s << sig;
    return s;
}

std::optional<std::string> DecodePayload(const std::vector<unsigned char>& P, Act& out)
{
    if (P.size() < 4 || P[0] != ACT_MAGIC_0 || P[1] != ACT_MAGIC_1) return std::string("bad-vault-act-malformed");
    if (P[2] != ACT_VERSION) return std::string("bad-vault-act-version");
    const uint8_t type = P[3];
    const size_t bodySize = ActBodySize(type);
    if (bodySize == 0) return std::string("bad-vault-act-type");
    if (P.size() != 4 + bodySize) return std::string("bad-vault-act-malformed");

    Act a;
    a.type = type;
    Reader r(P, 4);
    switch (type) {
    case ACT_SET_CREATE: {
        SetCreateBody& c = a.create;
        c.seats = r.u8(); c.unlockThreshold = r.u8(); c.cancelThreshold = r.u8(); c.slashThreshold = r.u8();
        c.flags = r.u8(); c.rateLimitBps = r.u16(); c.rateWindow = r.u32(); c.livenessWindow = r.u32();
        c.bondMin = r.i64(); c.bondLockMin = r.u32(); c.maturity = r.u32(); c.admitKey = r.key();
        break;
    }
    case ACT_SET_JOIN:
        a.join.setId = r.u256(); a.join.memberKey = r.key(); a.join.bondLocktime = r.u32(); a.join.bondVout = r.u8();
        break;
    case ACT_SET_HEARTBEAT:
        a.heartbeat.setId = r.u256(); a.heartbeat.memberKey = r.key();
        break;
    case ACT_SET_REMOVE:
        a.remove.setId = r.u256(); a.remove.memberKey = r.key(); a.remove.burn = r.u8();
        break;
    case ACT_SET_EQUIVOCATION: {
        SetEquivocationBody& e = a.equivocation;
        e.setId = r.u256(); e.prevout = r.outpoint();
        e.roleA = r.u8(); e.sighashA = r.u256(); e.sigA = r.raw(RECOVERABLE_SIG_SIZE);
        e.roleB = r.u8(); e.sighashB = r.u256(); e.sigB = r.raw(RECOVERABLE_SIG_SIZE);
        break;
    }
    case ACT_SET_WINDDOWN:
        a.winddown.setId = r.u256();
        break;
    }
    if (!r.Ok() || !r.AtEnd()) return std::string("bad-vault-act-malformed");
    out = std::move(a);
    return std::nullopt;
}

std::optional<std::string> DecodeAct(const CScript& spk, Act& out)
{
    if (!IsActOutput(spk)) return std::string("bad-vault-act-malformed");
    CScript::const_iterator pc = spk.begin() + 1;
    opcodetype op;
    valtype P;
    if (!spk.GetOp(pc, op, P)) return std::string("bad-vault-act-malformed");
    Act a;
    if (auto err = DecodePayload(P, a)) return err;
    while (pc < spk.end()) {
        valtype sig;
        if (!spk.GetOp(pc, op, sig)) return std::string("bad-vault-act-malformed");
        if (op > OP_PUSHDATA4 || sig.size() != RECOVERABLE_SIG_SIZE) return std::string("bad-vault-act-malformed");
        a.sigs.push_back(std::move(sig));
    }
    // Minimal pushes only: the canonical encoding must reproduce the script byte for byte.
    if (EncodeAct(a) != spk) return std::string("bad-vault-act-malformed");
    out = std::move(a);
    return std::nullopt;
}

uint256 ActMsg(const std::vector<unsigned char>& P, const COutPoint& prevout)
{
    static const char tag[] = "YcashSetAct";
    CHashWriter hw(SER_GETHASH, 0);
    hw.write(tag, 11);
    if (!P.empty()) hw.write((const char*)P.data(), P.size());
    hw.write((const char*)prevout.hash.begin(), 32);
    unsigned char n[4];
    for (int i = 0; i < 4; i++) n[i] = (prevout.n >> (8 * i)) & 0xff;
    hw.write((const char*)n, 4);
    return hw.GetHash();
}

uint256 SetSigMsg(const SetId& setId, uint8_t role, const COutPoint& prevout, const uint256& sighash)
{
    static const char tag[] = "YcashSetSig";
    CHashWriter hw(SER_GETHASH, 0);
    hw.write(tag, 11);
    hw.write((const char*)setId.begin(), 32);
    hw.write((const char*)&role, 1);
    hw.write((const char*)prevout.hash.begin(), 32);
    unsigned char n[4];
    for (int i = 0; i < 4; i++) n[i] = (prevout.n >> (8 * i)) & 0xff;
    hw.write((const char*)n, 4);
    hw.write((const char*)sighash.begin(), 32);
    return hw.GetHash();
}

namespace {
// secp256k1 order / 2, big-endian.
const unsigned char HALF_ORDER[32] = {
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0};
} // namespace

bool RecoverSig(const uint256& msg, const std::vector<unsigned char>& sig, CPubKey& key)
{
    if (sig.size() != RECOVERABLE_SIG_SIZE) return false;
    if (sig[0] < 31 || sig[0] > 34) return false;
    // low S: s <= n/2 (big-endian compare of bytes 33..64)
    if (std::memcmp(sig.data() + 33, HALF_ORDER, 32) > 0) return false;
    CPubKey k;
    if (!k.RecoverCompact(msg, sig)) return false;
    if (!k.IsValid() || !k.IsCompressed()) return false;
    key = k;
    return true;
}

bool SignRecoverable(const CKey& key, const uint256& msg, std::vector<unsigned char>& sig)
{
    if (!key.IsValid() || !key.IsCompressed()) return false;
    std::vector<unsigned char> s;
    if (!key.SignCompact(msg, s)) return false;
    if (s.size() != RECOVERABLE_SIG_SIZE || s[0] < 31 || s[0] > 34) return false;
    sig = s;
    return true;
}

} // namespace vault
