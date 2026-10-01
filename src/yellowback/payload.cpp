// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "yellowback/payload.h"

#include "script/script.h"

#include <algorithm>
#include <set>

namespace yellowback {

namespace {

const size_t KEY_SIZE = CPubKey::COMPRESSED_PUBLIC_KEY_SIZE;                 // 33
const size_t MINT_BODY_SIZE = 1 + 4 + 4 + 4 + KEY_SIZE + 1 + 1;              // 48 (v3: + attestFeeVout)
const size_t REDEEM_HEAD_SIZE = 4 + 1 + 1 + 1;                               // refHeight, feeVout, attestFeeVout, count
const size_t REGISTER_BODY_SIZE = KEY_SIZE + KEY_SIZE + 4 + 1;               // 71
const size_t NOTICE_BODY_SIZE = 32 + 1 + 4;                                  // 37
const size_t REVIVE_BODY_SIZE = 2 + 4 + 4 + COMPACT_SIG_SIZE;                // 74

/** Bounds-checked little-endian reader. Never throws. */
class Reader
{
public:
    explicit Reader(const std::vector<unsigned char>& d) : data(d), pos(0) {}

    bool U8(uint8_t& v)
    {
        if (pos + 1 > data.size()) return false;
        v = data[pos++];
        return true;
    }
    bool U16(uint16_t& v)
    {
        if (pos + 2 > data.size()) return false;
        v = (uint16_t)((uint16_t)data[pos] | ((uint16_t)data[pos + 1] << 8));
        pos += 2;
        return true;
    }
    bool U32(uint32_t& v)
    {
        if (pos + 4 > data.size()) return false;
        v = (uint32_t)data[pos] | ((uint32_t)data[pos + 1] << 8) | ((uint32_t)data[pos + 2] << 16) | ((uint32_t)data[pos + 3] << 24);
        pos += 4;
        return true;
    }
    bool U64(uint64_t& v)
    {
        uint32_t lo, hi;
        if (!U32(lo) || !U32(hi)) return false;
        v = (uint64_t)lo | ((uint64_t)hi << 32);
        return true;
    }
    bool Bytes(size_t n, std::vector<unsigned char>& v)
    {
        if (pos + n > data.size()) return false;
        v.assign(data.begin() + pos, data.begin() + pos + n);
        pos += n;
        return true;
    }
    bool AtEnd() const { return pos == data.size(); }

private:
    const std::vector<unsigned char>& data;
    size_t pos;
};

void PutU16(std::vector<unsigned char>& out, uint16_t v)
{
    out.push_back(v & 0xff);
    out.push_back((v >> 8) & 0xff);
}

void PutU32(std::vector<unsigned char>& out, uint32_t v)
{
    out.push_back(v & 0xff);
    out.push_back((v >> 8) & 0xff);
    out.push_back((v >> 16) & 0xff);
    out.push_back((v >> 24) & 0xff);
}

void PutU64(std::vector<unsigned char>& out, uint64_t v)
{
    PutU32(out, (uint32_t)(v & 0xffffffffULL));
    PutU32(out, (uint32_t)(v >> 32));
}

bool ValidAssignments(const std::vector<Assignment>& assignments, size_t maxCount = MAX_ASSIGNMENTS)
{
    if (assignments.size() > maxCount) return false;
    std::set<uint8_t> seen;
    for (const Assignment& a : assignments) {
        if (a.cents == 0) return false;
        if (!seen.insert(a.vout).second) return false;
    }
    return true;
}

} // namespace

Payload Payload::Mint(uint8_t termClass, uint32_t cents, uint32_t lockHeight, uint32_t refHeight, const CPubKey& owner, uint8_t feeVout,
                      uint8_t attestFeeVout)
{
    Payload p;
    p.type = PayloadType::MINT;
    p.termClass = termClass;
    p.cents = cents;
    p.lockHeight = lockHeight;
    p.refHeight = refHeight;
    p.ownerPubKey = owner;
    p.ownerKeyBytes.assign(owner.begin(), owner.end());
    p.feeVout = feeVout;
    p.attestFeeVout = attestFeeVout;
    return p;
}

Payload Payload::Redeem(uint32_t refHeight, uint8_t feeVout, const std::vector<Assignment>& assignments, uint8_t attestFeeVout)
{
    Payload p;
    p.type = PayloadType::REDEEM;
    p.refHeight = refHeight;
    p.feeVout = feeVout;
    p.attestFeeVout = attestFeeVout;
    p.assignments = assignments;
    return p;
}

Payload Payload::AttestorRegister(const CPubKey& attestorPubKey, const CPubKey& bondPubKey, uint32_t bondLocktime, uint8_t flags)
{
    Payload p;
    p.type = PayloadType::ATTESTOR_REGISTER;
    p.attestorPubKey = attestorPubKey;
    p.attestorKeyBytes.assign(attestorPubKey.begin(), attestorPubKey.end());
    p.bondPubKey = bondPubKey;
    p.bondKeyBytes.assign(bondPubKey.begin(), bondPubKey.end());
    p.bondLocktime = bondLocktime;
    p.flags = flags;
    return p;
}

Payload Payload::ClaimNotice(const uint256& vaultTxid, uint8_t vaultVout, uint32_t refHeight)
{
    Payload p;
    p.type = PayloadType::CLAIM_NOTICE;
    p.vaultTxid = vaultTxid;
    p.vaultVout = vaultVout;
    p.refHeight = refHeight;
    return p;
}

Payload Payload::ClaimNotice(const COutPoint& vault, uint32_t refHeight)
{
    return ClaimNotice(vault.hash, (uint8_t)vault.n, refHeight);
}

Payload Payload::Equivocation()
{
    Payload p;
    p.type = PayloadType::EQUIVOCATION;
    return p;
}

Payload Payload::AttestorRevive(uint16_t seq, uint32_t priceMicroUsd, uint32_t citedHeight, const std::array<unsigned char, COMPACT_SIG_SIZE>& sig)
{
    Payload p;
    p.type = PayloadType::ATTESTOR_REVIVE;
    p.seq = seq;
    p.priceMicroUsd = priceMicroUsd;
    p.citedHeight = citedHeight;
    p.sig = sig;
    return p;
}

Payload Payload::Transfer(const std::vector<Assignment>& assignments)
{
    Payload p;
    p.type = PayloadType::TRANSFER;
    p.assignments = assignments;
    return p;
}

int64_t Payload::AssignedCents() const
{
    int64_t sum = 0;
    for (const Assignment& a : assignments) sum += a.cents;
    return sum;
}

bool operator==(const Payload& a, const Payload& b)
{
    if (a.version != b.version || a.type != b.type) return false;
    switch (a.type) {
    case PayloadType::MINT:
        return a.termClass == b.termClass && a.cents == b.cents && a.lockHeight == b.lockHeight &&
               a.refHeight == b.refHeight && a.ownerKeyBytes == b.ownerKeyBytes && a.feeVout == b.feeVout &&
               a.attestFeeVout == b.attestFeeVout;
    case PayloadType::TRANSFER:
        return a.assignments == b.assignments;
    case PayloadType::REDEEM:
        return a.refHeight == b.refHeight && a.feeVout == b.feeVout && a.attestFeeVout == b.attestFeeVout &&
               a.assignments == b.assignments;
    case PayloadType::ATTESTOR_REGISTER:
        return a.attestorKeyBytes == b.attestorKeyBytes && a.bondKeyBytes == b.bondKeyBytes &&
               a.bondLocktime == b.bondLocktime && a.flags == b.flags;
    case PayloadType::CLAIM_NOTICE:
        return a.vaultTxid == b.vaultTxid && a.vaultVout == b.vaultVout && a.refHeight == b.refHeight;
    case PayloadType::EQUIVOCATION:
        return true;
    case PayloadType::ATTESTOR_REVIVE:
        return a.seq == b.seq && a.priceMicroUsd == b.priceMicroUsd && a.citedHeight == b.citedHeight && a.sig == b.sig;
    }
    return false;
}

namespace {

bool ReadAssignments(Reader& r, uint8_t count, std::vector<Assignment>& out)
{
    for (uint8_t i = 0; i < count; i++) {
        Assignment a;
        if (!r.U8(a.vout) || !r.U32(a.cents)) return false;
        out.push_back(a);
    }
    return true;
}

void PutAssignments(std::vector<unsigned char>& out, const std::vector<Assignment>& assignments)
{
    out.push_back((unsigned char)assignments.size());
    for (const Assignment& a : assignments) {
        out.push_back(a.vout);
        PutU32(out, a.cents);
    }
}

/** Version 3 bodies (v3 plan §3.3). */
bool DecodeBodyV3(Reader& r, uint8_t type, size_t size, Payload& p)
{
    switch (type) {
    case (uint8_t)PayloadType::MINT: {
        if (size != 4 + MINT_BODY_SIZE) return false;
        p.type = PayloadType::MINT;
        if (!r.U8(p.termClass) || !r.U32(p.cents) || !r.U32(p.lockHeight) || !r.U32(p.refHeight) ||
            !r.Bytes(KEY_SIZE, p.ownerKeyBytes) || !r.U8(p.feeVout) || !r.U8(p.attestFeeVout)) return false;
        // Any 33 bytes: the codec fixes the shape, MINT-3 judges the key
        // (bad-mint-owner-key) and a VOID vault records the bytes verbatim.
        p.ownerPubKey.Set(p.ownerKeyBytes.begin(), p.ownerKeyBytes.end());
        return true;
    }
    case (uint8_t)PayloadType::TRANSFER: {
        p.type = PayloadType::TRANSFER;
        uint8_t count;
        if (!r.U8(count)) return false;
        if (count > MAX_ASSIGNMENTS) return false;
        if (size != 5 + 5 * (size_t)count) return false;
        return ReadAssignments(r, count, p.assignments) && ValidAssignments(p.assignments, MAX_ASSIGNMENTS);
    }
    case (uint8_t)PayloadType::REDEEM: {
        p.type = PayloadType::REDEEM;
        uint8_t count;
        if (!r.U32(p.refHeight) || !r.U8(p.feeVout) || !r.U8(p.attestFeeVout) || !r.U8(count)) return false;
        if (count > MAX_REDEEM_ASSIGNMENTS) return false;
        if (size != 4 + REDEEM_HEAD_SIZE + 5 * (size_t)count) return false;
        return ReadAssignments(r, count, p.assignments) && ValidAssignments(p.assignments, MAX_REDEEM_ASSIGNMENTS);
    }
    case (uint8_t)PayloadType::ATTESTOR_REGISTER: {
        if (size != 4 + REGISTER_BODY_SIZE) return false;
        p.type = PayloadType::ATTESTOR_REGISTER;
        if (!r.Bytes(KEY_SIZE, p.attestorKeyBytes) || !r.Bytes(KEY_SIZE, p.bondKeyBytes) ||
            !r.U32(p.bondLocktime) || !r.U8(p.flags)) return false;
        // Any 33 bytes, as the MINT owner key: REG-A1 judges them.
        p.attestorPubKey.Set(p.attestorKeyBytes.begin(), p.attestorKeyBytes.end());
        p.bondPubKey.Set(p.bondKeyBytes.begin(), p.bondKeyBytes.end());
        return true;
    }
    case (uint8_t)PayloadType::CLAIM_NOTICE: {
        if (size != 4 + NOTICE_BODY_SIZE) return false;
        p.type = PayloadType::CLAIM_NOTICE;
        std::vector<unsigned char> txid;
        if (!r.Bytes(32, txid) || !r.U8(p.vaultVout) || !r.U32(p.refHeight)) return false;
        p.vaultTxid = uint256(txid);
        return true;
    }
    case (uint8_t)PayloadType::EQUIVOCATION:
        if (size != 4) return false;
        p.type = PayloadType::EQUIVOCATION;
        return true;
    case (uint8_t)PayloadType::ATTESTOR_REVIVE: {
        if (size != 4 + REVIVE_BODY_SIZE) return false;
        p.type = PayloadType::ATTESTOR_REVIVE;
        std::vector<unsigned char> sig;
        if (!r.U16(p.seq) || !r.U32(p.priceMicroUsd) || !r.U32(p.citedHeight) || !r.Bytes(COMPACT_SIG_SIZE, sig)) return false;
        std::copy(sig.begin(), sig.end(), p.sig.begin());
        return true;
    }
    default:
        return false; // unknown or reserved type (0x04, 0x09-0xFF): forward-compatibility rule, non-Yellowback
    }
}

} // namespace

std::vector<unsigned char> EncodePayload(const Payload& payload)
{
    std::vector<unsigned char> out;
    out.push_back(PAYLOAD_MAGIC_0);
    out.push_back(PAYLOAD_MAGIC_1);
    out.push_back(payload.version);
    out.push_back((unsigned char)payload.type);
    if (payload.version == PAYLOAD_VERSION) {
        switch (payload.type) {
        case PayloadType::MINT:
            if (payload.ownerKeyBytes.size() != KEY_SIZE) return {};
            out.push_back(payload.termClass);
            PutU32(out, payload.cents);
            PutU32(out, payload.lockHeight);
            PutU32(out, payload.refHeight);
            out.insert(out.end(), payload.ownerKeyBytes.begin(), payload.ownerKeyBytes.end());
            out.push_back(payload.feeVout);
            out.push_back(payload.attestFeeVout);
            break;
        case PayloadType::TRANSFER:
            if (!ValidAssignments(payload.assignments, MAX_ASSIGNMENTS)) return {};
            PutAssignments(out, payload.assignments);
            break;
        case PayloadType::REDEEM:
            if (!ValidAssignments(payload.assignments, MAX_REDEEM_ASSIGNMENTS)) return {};
            PutU32(out, payload.refHeight);
            out.push_back(payload.feeVout);
            out.push_back(payload.attestFeeVout);
            PutAssignments(out, payload.assignments);
            break;
        case PayloadType::ATTESTOR_REGISTER:
            if (payload.attestorKeyBytes.size() != KEY_SIZE || payload.bondKeyBytes.size() != KEY_SIZE) return {};
            out.insert(out.end(), payload.attestorKeyBytes.begin(), payload.attestorKeyBytes.end());
            out.insert(out.end(), payload.bondKeyBytes.begin(), payload.bondKeyBytes.end());
            PutU32(out, payload.bondLocktime);
            out.push_back(payload.flags);
            break;
        case PayloadType::CLAIM_NOTICE:
            out.insert(out.end(), payload.vaultTxid.begin(), payload.vaultTxid.end());
            out.push_back(payload.vaultVout);
            PutU32(out, payload.refHeight);
            break;
        case PayloadType::EQUIVOCATION:
            break;
        case PayloadType::ATTESTOR_REVIVE:
            PutU16(out, payload.seq);
            PutU32(out, payload.priceMicroUsd);
            PutU32(out, payload.citedHeight);
            out.insert(out.end(), payload.sig.begin(), payload.sig.end());
            break;
        default:
            return {};
        }
    } else {
        return {};
    }
    if (out.size() > MAX_PAYLOAD) return {};
    return out;
}

bool DecodePayload(const std::vector<unsigned char>& data, Payload& out)
{
    if (data.size() < MIN_PAYLOAD || data.size() > MAX_PAYLOAD) return false;
    if (data[0] != PAYLOAD_MAGIC_0 || data[1] != PAYLOAD_MAGIC_1) return false;

    Reader r(data);
    uint8_t magic0, magic1, version, type;
    r.U8(magic0); r.U8(magic1); r.U8(version); r.U8(type);

    Payload p;
    p.version = version;
    if (version != PAYLOAD_VERSION) return false; // versions 1, 2 and every later version: non-Yellowback (V23)
    if (!DecodeBodyV3(r, type, data.size(), p)) return false;
    if (!r.AtEnd()) return false;
    out = p;
    return true;
}

CScript PayloadScript(const std::vector<unsigned char>& data)
{
    return CScript() << OP_RETURN << data;
}

std::optional<std::vector<unsigned char>> ExtractOpReturnData(const CScript& script)
{
    if (script.size() < 1 || script[0] != OP_RETURN) return std::nullopt;
    CScript::const_iterator pc = script.begin() + 1;
    opcodetype opcode;
    std::vector<unsigned char> data;
    if (!script.GetOp(pc, opcode, data)) return std::nullopt;
    // Only a real data push (OP_PUSHDATA*, or a direct 1..75 byte push) qualifies;
    // OP_0/OP_1..OP_16/OP_1NEGATE and any other opcode return no data.
    if (opcode > OP_PUSHDATA4 || data.empty()) return std::nullopt;
    if (pc != script.end()) return std::nullopt;
    if (data.size() < MIN_PAYLOAD || data.size() > MAX_PAYLOAD) return std::nullopt;
    return data;
}

std::optional<unsigned int> FindOpReturn(const CTransaction& tx)
{
    std::optional<unsigned int> found;
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CScript& s = tx.vout[i].scriptPubKey;
        if (s.size() >= 1 && s[0] == OP_RETURN) {
            if (found.has_value()) return std::nullopt; // more than one => non-Yellowback
            found = i;
        }
    }
    return found;
}

std::optional<FoundPayload> FindPayload(const CTransaction& tx)
{
    auto idx = FindOpReturn(tx);
    if (!idx.has_value()) return std::nullopt;
    auto data = ExtractOpReturnData(tx.vout[idx.value()].scriptPubKey);
    if (!data.has_value()) return std::nullopt;
    FoundPayload fp;
    fp.opReturnIndex = idx.value();
    if (!DecodePayload(data.value(), fp.payload)) return std::nullopt;
    for (const Assignment& a : fp.payload.assignments) {
        if (a.vout >= tx.vout.size()) return std::nullopt;
        if (a.vout == fp.opReturnIndex) return std::nullopt;
    }
    return fp;
}

const char* PayloadTypeName(PayloadType type)
{
    switch (type) {
    case PayloadType::MINT: return "mint";
    case PayloadType::TRANSFER: return "transfer";
    case PayloadType::REDEEM: return "redeem";
    case PayloadType::ATTESTOR_REGISTER: return "register";
    case PayloadType::CLAIM_NOTICE: return "notice";
    case PayloadType::EQUIVOCATION: return "equivocation";
    case PayloadType::ATTESTOR_REVIVE: return "revive";
    }
    return "unknown";
}

} // namespace yellowback
