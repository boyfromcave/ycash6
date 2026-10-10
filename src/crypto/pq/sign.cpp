// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "crypto/pq/sign.h"

#include "crypto/pq/falcon/ycash_falcon.h"
#include "crypto/pq/slhdsa/slh_dsa.h"
#include "random.h"
#include "support/cleanse.h"

namespace pq {

static const size_t SLH_N = 16;           // SLH-DSA-SHA2-128s n
static const size_t SLH_SK = 4 * SLH_N;   // 64
static const size_t FALCON_SEED = 48; // the PQClean/NIST randombytes keygen seed length

size_t SeedSize(uint8_t scheme)
{
    switch (scheme) {
    case SCHEME_SLH_DSA_SHA2_128S: return 3 * SLH_N;
    case SCHEME_FN_DSA_512: return FALCON_SEED;
    default: return 0;
    }
}

size_t SecretKeySize(uint8_t scheme)
{
    switch (scheme) {
    case SCHEME_SLH_DSA_SHA2_128S: return SLH_SK;
    case SCHEME_FN_DSA_512: return YCASH_FALCON512_SECRETKEYBYTES;
    default: return 0;
    }
}

bool KeyGen(uint8_t scheme, const std::vector<unsigned char>& seed,
            std::vector<unsigned char>& pk, std::vector<unsigned char>& sk)
{
    if (!IsKnownScheme(scheme) || seed.size() != SeedSize(scheme)) return false;
    std::vector<unsigned char> pkOut(PubKeySize(scheme)), skOut(SecretKeySize(scheme));
    bool ok = false;
    switch (scheme) {
    case SCHEME_SLH_DSA_SHA2_128S:
        ok = slh_keygen_internal(skOut.data(), pkOut.data(), seed.data(), seed.data() + SLH_N,
                                 seed.data() + 2 * SLH_N, &slh_dsa_sha2_128s) == 0;
        break;
    case SCHEME_FN_DSA_512:
        ok = ycash_falcon512_keygen_from_seed(pkOut.data(), skOut.data(), seed.data(),
                                              seed.size()) == 0;
        break;
    }
    if (!ok) {
        memory_cleanse(skOut.data(), skOut.size());
        return false;
    }
    pk.swap(pkOut);
    if (!sk.empty()) memory_cleanse(sk.data(), sk.size());
    sk.swap(skOut);
    return true;
}

bool SignWithEntropy(uint8_t scheme, const std::vector<unsigned char>& sk, const uint256& msg,
                     const std::vector<unsigned char>& entropy, std::vector<unsigned char>& sig)
{
    if (!IsKnownScheme(scheme) || sk.size() != SecretKeySize(scheme)) return false;
    std::vector<unsigned char> out(SigSize(scheme));
    switch (scheme) {
    case SCHEME_SLH_DSA_SHA2_128S: {
        if (!entropy.empty() && entropy.size() != SLH_N) return false;
        static const uint8_t no_ctx = 0;
        const size_t n = slh_sign(out.data(), msg.begin(), msg.size(), &no_ctx, 0, sk.data(),
                                  entropy.empty() ? nullptr : entropy.data(), &slh_dsa_sha2_128s);
        if (n != out.size()) return false;
        break;
    }
    case SCHEME_FN_DSA_512:
        if (entropy.size() != FALCON_SIGN_ENTROPY_SIZE) return false;
        if (ycash_falcon512_sign(out.data(), msg.begin(), msg.size(), sk.data(), entropy.data(),
                                 entropy.data() + YCASH_FALCON512_NONCEBYTES) != 0) {
            return false;
        }
        break;
    }
    sig.swap(out);
    return true;
}

bool Sign(uint8_t scheme, const std::vector<unsigned char>& sk, const uint256& msg,
          std::vector<unsigned char>& sig)
{
    if (scheme == SCHEME_SLH_DSA_SHA2_128S) {
        return SignWithEntropy(scheme, sk, msg, std::vector<unsigned char>(), sig);
    }
    if (scheme == SCHEME_FN_DSA_512) {
        std::vector<unsigned char> entropy(FALCON_SIGN_ENTROPY_SIZE);
        GetRandBytes(entropy.data(), entropy.size());
        const bool ok = SignWithEntropy(scheme, sk, msg, entropy, sig);
        memory_cleanse(entropy.data(), entropy.size());
        return ok;
    }
    return false;
}

} // namespace pq
