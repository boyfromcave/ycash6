// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "yellowback/tag.h"

#include <algorithm>

namespace yellowback {

namespace {

/** The direct-push opcode for 36 bytes followed by the magic (TAG-1, P10). */
const unsigned char TAG_PATTERN[5] = { (unsigned char)TAG_SIZE, TAG_MAGIC[0], TAG_MAGIC[1], TAG_MAGIC[2], TAG_MAGIC[3] };
const size_t TAG_BODY_SIZE = TAG_SIZE - sizeof(TAG_MAGIC); // 32: version + body

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

bool IsValidTag(const CoinbaseTag& tag)
{
    if ((tag.flags & 0xFE) != 0) return false;
    if (tag.priceMicroUsd == TAG_PRICE_SIGNAL_ONLY) return true;
    return tag.priceMicroUsd >= (uint64_t)PRICE_MIN && tag.priceMicroUsd <= (uint64_t)PRICE_MAX;
}

std::vector<unsigned char> EncodeTag(const CoinbaseTag& tag)
{
    std::vector<unsigned char> out;
    out.reserve(TAG_SIZE);
    out.insert(out.end(), TAG_MAGIC, TAG_MAGIC + sizeof(TAG_MAGIC));
    out.push_back(TAG_VERSION);
    out.push_back(tag.flags);
    PutLE(out, tag.priceMicroUsd, 8);
    PutLE(out, tag.sourceMask, 2);
    out.insert(out.end(), tag.payoutKey.begin(), tag.payoutKey.end());
    return out;
}

CScript TagPush(const CoinbaseTag& tag)
{
    // 36 < OP_PUSHDATA1, so operator<< emits the direct push 0x24 ‖ bytes.
    return CScript() << EncodeTag(tag);
}

std::optional<CoinbaseTag> FindTag(const CScript& scriptSig, int nHeight)
{
    const CScript prefix = CScript() << nHeight;
    if (scriptSig.size() < prefix.size()) return std::nullopt;
    if (!std::equal(prefix.begin(), prefix.end(), scriptSig.begin())) return std::nullopt;

    const size_t size = scriptSig.size();
    for (size_t i = prefix.size(); i + sizeof(TAG_PATTERN) <= size; i++) {
        if (!std::equal(TAG_PATTERN, TAG_PATTERN + sizeof(TAG_PATTERN), scriptSig.begin() + i)) continue;
        // First occurrence decides (TAG-5).
        const size_t body = i + sizeof(TAG_PATTERN);
        if (body + TAG_BODY_SIZE > size) return std::nullopt;
        const unsigned char* p = &scriptSig[body];
        if (p[0] != TAG_VERSION) return std::nullopt;
        CoinbaseTag tag;
        tag.flags = p[1];
        tag.priceMicroUsd = GetLE(p + 2, 8);
        tag.sourceMask = (uint16_t)GetLE(p + 10, 2);
        tag.payoutKey = uint160(std::vector<unsigned char>(p + 12, p + 32));
        if (!IsValidTag(tag)) return std::nullopt;
        return tag;
    }
    return std::nullopt;
}

} // namespace yellowback
