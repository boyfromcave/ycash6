// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "pqkey.h"

#include "crypto/hmac_sha256.h"
#include "crypto/pq/scheme.h"
#include "crypto/pq/sign.h"
#include "support/cleanse.h"

#include <algorithm>
#include <cassert>
#include <cstring>

bool CPQKey::Set(uint8_t schemeIn, const Secret& seedIn, uint32_t indexIn)
{
    if (!pq::IsKnownScheme(schemeIn) || seedIn.size() != pq::SeedSize(schemeIn)) return false;
    // pq::KeyGen takes plain vectors: copy in and out, and cleanse the copies.
    std::vector<unsigned char> s(seedIn.begin(), seedIn.end()), pkOut, skOut;
    const bool ok = pq::KeyGen(schemeIn, s, pkOut, skOut);
    memory_cleanse(s.data(), s.size());
    if (!ok) {
        if (!skOut.empty()) memory_cleanse(skOut.data(), skOut.size());
        return false;
    }
    scheme = schemeIn;
    index = indexIn;
    seed = seedIn;
    sk.assign(skOut.begin(), skOut.end());
    memory_cleanse(skOut.data(), skOut.size());
    pk.swap(pkOut);
    id = CPQKeyID(scheme, pq::KeyHash(scheme, pk));
    return true;
}

bool CPQKey::Sign(const uint256& hash, std::vector<unsigned char>& sigOut) const
{
    if (!IsValid()) return false;
    std::vector<unsigned char> s(sk.begin(), sk.end());
    const bool ok = pq::Sign(scheme, s, hash, sigOut);
    memory_cleanse(s.data(), s.size());
    return ok;
}

void HKDF_SHA256(const unsigned char* salt, size_t saltLen, const unsigned char* ikm, size_t ikmLen,
                 const unsigned char* info, size_t infoLen, unsigned char* out, size_t outLen)
{
    assert(outLen <= 255 * CHMAC_SHA256::OUTPUT_SIZE);
    static const unsigned char zeros[CHMAC_SHA256::OUTPUT_SIZE] = {0};
    if (saltLen == 0) {
        salt = zeros;
        saltLen = sizeof(zeros);
    }
    unsigned char prk[CHMAC_SHA256::OUTPUT_SIZE];
    CHMAC_SHA256(salt, saltLen).Write(ikm, ikmLen).Finalize(prk);
    unsigned char t[CHMAC_SHA256::OUTPUT_SIZE];
    size_t tLen = 0, done = 0;
    for (unsigned char counter = 1; done < outLen; counter++) {
        CHMAC_SHA256 h(prk, sizeof(prk));
        h.Write(t, tLen).Write(info, infoLen).Write(&counter, 1).Finalize(t);
        tLen = sizeof(t);
        const size_t n = std::min(outLen - done, sizeof(t));
        memcpy(out + done, t, n);
        done += n;
    }
    memory_cleanse(prk, sizeof(prk));
    memory_cleanse(t, sizeof(t));
}

CPQKey::Secret DerivePQSeed(const unsigned char* hdSeed, size_t hdSeedLen, uint8_t scheme, uint32_t index)
{
    std::vector<unsigned char> info(PQ_SEED_INFO, PQ_SEED_INFO + strlen(PQ_SEED_INFO));
    info.push_back(scheme);
    info.push_back((unsigned char)(index >> 24));
    info.push_back((unsigned char)(index >> 16));
    info.push_back((unsigned char)(index >> 8));
    info.push_back((unsigned char)index);
    CPQKey::Secret out(48);
    HKDF_SHA256(nullptr, 0, hdSeed, hdSeedLen, info.data(), info.size(), out.data(), out.size());
    return out;
}
