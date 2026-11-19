// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "yellowback/tag.h"

#include "crypto/pq/scheme.h"

#include <algorithm>

namespace yellowback {

namespace {

/** The direct-push opcode for 36 (v1) or 49 (v2) bytes followed by the magic (TAG-1, P10). */
const unsigned char TAG_PATTERN[5] = { (unsigned char)TAG_SIZE, TAG_MAGIC[0], TAG_MAGIC[1], TAG_MAGIC[2], TAG_MAGIC[3] };
const unsigned char TAG_PATTERN_V2[5] = { (unsigned char)TAG_SIZE_V2, TAG_MAGIC[0], TAG_MAGIC[1], TAG_MAGIC[2], TAG_MAGIC[3] };
const size_t TAG_BODY_SIZE = TAG_SIZE - sizeof(TAG_MAGIC);       // 32: version + body
const size_t TAG_BODY_SIZE_V2 = TAG_SIZE_V2 - sizeof(TAG_MAGIC); // 45

void PutLE(std::vector<unsigned char>& out, uint64_t v, int bytes)
{
    for (int i = 0; i < bytes; i++) out.push_back((unsigned char)((v >> (8 * i)) & 0xff));
}

uint64_t GetLE(const unsigned char* p, int bytes)
{
    uint64_t v = 0;
    for (int i = 0; i < bytes; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

} // namespace

Payee Payee::FromKeyID(const CKeyID& key)
{
    Payee p;
    p.kind = PAYEE_P2PKH;
    std::copy(key.begin(), key.end(), p.hash.begin());
    return p;
}

Payee Payee::FromPQ(const CPQKeyID& id)
{
    Payee p;
    p.kind = id.scheme;
    p.hash = id.hash;
    return p;
}

std::optional<Payee> Payee::FromScript(const CScript& s)
{
    if (s.size() == 25 && s[0] == OP_DUP && s[1] == OP_HASH160 && s[2] == 20 && s[23] == OP_EQUALVERIFY && s[24] == OP_CHECKSIG) {
        return FromKeyID(CKeyID(uint160(std::vector<unsigned char>(s.begin() + 3, s.begin() + 23))));
    }
    // TX_PQPKH exactly: 0x20 <32> OP_1|OP_2 OP_CHECKPQSIG, a known scheme (GetScriptForPQKey's bytes)
    if (s.size() == 35 && s[0] == 0x20 && s[34] == OP_CHECKPQSIG && (s[33] == OP_1 || s[33] == OP_2)) {
        const uint8_t scheme = (uint8_t)CScript::DecodeOP_N((opcodetype)s[33]);
        if (!pq::IsKnownScheme(scheme)) return std::nullopt;
        return FromPQ(CPQKeyID(scheme, uint256(std::vector<unsigned char>(s.begin() + 1, s.begin() + 33))));
    }
    return std::nullopt;
}

std::optional<Payee> Payee::FromDestination(const CTxDestination& dest)
{
    if (const CKeyID* k = std::get_if<CKeyID>(&dest)) return FromKeyID(*k);
    if (const CPQKeyID* q = std::get_if<CPQKeyID>(&dest)) {
        if (pq::IsKnownScheme(q->scheme)) return FromPQ(*q);
    }
    return std::nullopt;
}

bool Payee::IsValid() const
{
    return kind == PAYEE_P2PKH || pq::IsKnownScheme(kind);
}

CKeyID Payee::KeyID() const
{
    return CKeyID(uint160(std::vector<unsigned char>(hash.begin(), hash.begin() + 20)));
}

CPQKeyID Payee::PQKeyID() const
{
    return CPQKeyID(kind, hash);
}

CScript Payee::Script() const
{
    if (IsP2PKH()) return CScript() << OP_DUP << OP_HASH160 << ToByteVector(KeyID()) << OP_EQUALVERIFY << OP_CHECKSIG;
    return GetScriptForPQKey(PQKeyID());
}

CTxDestination Payee::Destination() const
{
    if (IsP2PKH()) return KeyID();
    return PQKeyID();
}

std::string Payee::SchemeName() const
{
    if (kind == pq::SCHEME_SLH_DSA_SHA2_128S) return "slh-dsa-sha2-128s";
    if (kind == pq::SCHEME_FN_DSA_512) return "fn-dsa-512";
    return "p2pkh";
}

CoinbaseTag MakeTag(uint8_t flags, uint64_t priceMicroUsd, uint16_t sourceMask, const Payee& payee)
{
    CoinbaseTag tag;
    tag.version = payee.IsP2PKH() ? TAG_VERSION : TAG_VERSION_V2;
    tag.flags = flags;
    tag.priceMicroUsd = priceMicroUsd;
    tag.sourceMask = sourceMask;
    tag.payee = payee;
    return tag;
}

bool IsValidTag(const CoinbaseTag& tag)
{
    if (tag.version == TAG_VERSION) {
        if (!tag.payee.IsP2PKH()) return false;
    } else if (tag.version == TAG_VERSION_V2) {
        if (tag.payee.IsP2PKH() || !pq::IsKnownScheme(tag.payee.kind)) return false;
    } else {
        return false;
    }
    if ((tag.flags & 0xFE) != 0) return false;
    if (tag.priceMicroUsd == TAG_PRICE_SIGNAL_ONLY) return true;
    return tag.priceMicroUsd >= (uint64_t)PRICE_MIN && tag.priceMicroUsd <= (uint64_t)PRICE_MAX;
}

std::vector<unsigned char> EncodeTag(const CoinbaseTag& tag)
{
    const bool v1 = tag.version == TAG_VERSION;
    std::vector<unsigned char> out;
    out.reserve(v1 ? TAG_SIZE : TAG_SIZE_V2);
    out.insert(out.end(), TAG_MAGIC, TAG_MAGIC + sizeof(TAG_MAGIC));
    out.push_back(tag.version);
    out.push_back(tag.flags);
    PutLE(out, tag.priceMicroUsd, 8);
    PutLE(out, tag.sourceMask, 2);
    if (v1) {
        out.insert(out.end(), tag.payee.hash.begin(), tag.payee.hash.begin() + 20);
    } else {
        out.push_back(tag.payee.kind);
        out.insert(out.end(), tag.payee.hash.begin(), tag.payee.hash.end());
    }
    return out;
}

CScript TagPush(const CoinbaseTag& tag)
{
    // 36 and 49 < OP_PUSHDATA1, so operator<< emits the direct push 0x24 ‖ bytes or 0x31 ‖ bytes.
    return CScript() << EncodeTag(tag);
}

std::optional<CoinbaseTag> FindTag(const CScript& scriptSig, int nHeight)
{
    const CScript prefix = CScript() << nHeight;
    if (scriptSig.size() < prefix.size()) return std::nullopt;
    if (!std::equal(prefix.begin(), prefix.end(), scriptSig.begin())) return std::nullopt;

    const size_t size = scriptSig.size();
    for (size_t i = prefix.size(); i + sizeof(TAG_PATTERN) <= size; i++) {
        const bool v1 = std::equal(TAG_PATTERN, TAG_PATTERN + sizeof(TAG_PATTERN), scriptSig.begin() + i);
        const bool v2 = !v1 && std::equal(TAG_PATTERN_V2, TAG_PATTERN_V2 + sizeof(TAG_PATTERN_V2), scriptSig.begin() + i);
        if (!v1 && !v2) continue;
        // First occurrence of either pattern decides (TAG-5).
        const size_t body = i + sizeof(TAG_PATTERN);
        if (body + (v1 ? TAG_BODY_SIZE : TAG_BODY_SIZE_V2) > size) return std::nullopt;
        const unsigned char* p = &scriptSig[body];
        if (p[0] != (v1 ? TAG_VERSION : TAG_VERSION_V2)) return std::nullopt;
        CoinbaseTag tag;
        tag.version = p[0];
        tag.flags = p[1];
        tag.priceMicroUsd = GetLE(p + 2, 8);
        tag.sourceMask = (uint16_t)GetLE(p + 10, 2);
        if (v1) {
            tag.payee.kind = PAYEE_P2PKH;
            std::copy(p + 12, p + 32, tag.payee.hash.begin());
        } else {
            tag.payee.kind = p[12];
            std::copy(p + 13, p + 45, tag.payee.hash.begin());
        }
        if (!IsValidTag(tag)) return std::nullopt;
        return tag;
    }
    return std::nullopt;
}

} // namespace yellowback
