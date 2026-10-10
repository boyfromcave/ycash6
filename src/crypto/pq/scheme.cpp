// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "crypto/pq/scheme.h"

#include "crypto/pq/falcon/ycash_falcon.h"
#include "crypto/pq/slhdsa/slh_dsa.h"
#include "crypto/sha256.h"

namespace pq {

static const size_t SLH_DSA_SHA2_128S_PK = 32;
static const size_t SLH_DSA_SHA2_128S_SIG = 7856;

size_t PubKeySize(uint8_t scheme)
{
    switch (scheme) {
    case SCHEME_SLH_DSA_SHA2_128S: return SLH_DSA_SHA2_128S_PK;
    case SCHEME_FN_DSA_512: return YCASH_FALCON512_PUBLICKEYBYTES;
    default: return 0;
    }
}

size_t SigSize(uint8_t scheme)
{
    switch (scheme) {
    case SCHEME_SLH_DSA_SHA2_128S: return SLH_DSA_SHA2_128S_SIG;
    case SCHEME_FN_DSA_512: return YCASH_FALCON512_SIGBYTES;
    default: return 0;
    }
}

bool IsKnownScheme(uint8_t scheme)
{
    return scheme == SCHEME_SLH_DSA_SHA2_128S || scheme == SCHEME_FN_DSA_512;
}

uint256 KeyHash(uint8_t scheme, const std::vector<unsigned char>& pk)
{
    uint256 out;
    CSHA256().Write(&scheme, 1).Write(pk.data(), pk.size()).Finalize(out.begin());
    return out;
}

bool Verify(uint8_t scheme, const std::vector<unsigned char>& pk,
            const std::vector<unsigned char>& sig, const uint256& msg)
{
    if (!IsKnownScheme(scheme)) return false;
    if (pk.size() != PubKeySize(scheme) || sig.size() != SigSize(scheme)) return false;

    switch (scheme) {
    case SCHEME_SLH_DSA_SHA2_128S: {
        // FIPS 205 Algorithm 24 (slh_verify), pure mode, empty context. The context pointer
        // is never read for a zero length; a valid one is passed so no null pointer reaches
        // a zero-length update.
        static const uint8_t no_ctx = 0;
        return slh_verify(msg.begin(), msg.size(), sig.data(), sig.size(), &no_ctx, 0,
                          pk.data(), &slh_dsa_sha2_128s) == 1;
    }
    case SCHEME_FN_DSA_512:
        return ycash_falcon512_verify(sig.data(), sig.size(), msg.begin(), msg.size(),
                                      pk.data()) == 0;
    default:
        return false;
    }
}

} // namespace pq
