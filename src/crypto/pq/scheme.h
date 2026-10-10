// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The post-quantum scheme registry and verification (consensus).
// docs/plans/yellowback-quantum-plan.md §4.1, §4.2. Verification only: the wallet's
// key generation and signing live in crypto/pq/sign.h and never enter a consensus path.

#ifndef YCASH_CRYPTO_PQ_SCHEME_H
#define YCASH_CRYPTO_PQ_SCHEME_H

#include "uint256.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace pq {

static const uint8_t SCHEME_SLH_DSA_SHA2_128S = 0x01;
static const uint8_t SCHEME_FN_DSA_512        = 0x02;
static const size_t KEYHASH_SIZE = 32;
static const size_t MAX_CHUNK    = 520;           // == MAX_SCRIPT_ELEMENT_SIZE
static const unsigned int SIGOP_COST = 20;

// Sizes WITHOUT the trailing hashtype byte. 0 for an unknown scheme.
size_t PubKeySize(uint8_t scheme);                // 32 | 897
size_t SigSize(uint8_t scheme);                   // 7856 | 666
bool IsKnownScheme(uint8_t scheme);               // 0x01 or 0x02 (activation is the caller's flag)
uint256 KeyHash(uint8_t scheme, const std::vector<unsigned char>& pk);   // SHA256(scheme || pk)
// msg = the 32 bytes of the ZIP-243 sighash in memory order (hash.begin()..hash.end()), exactly the
// bytes CPubKey::Verify is given. SLH-DSA: FIPS 205 pure SLH-DSA, ctx = empty. Falcon: padded-512.
// False for an unknown scheme or a public key / signature of any length but the registry's.
bool Verify(uint8_t scheme, const std::vector<unsigned char>& pk,
            const std::vector<unsigned char>& sig, const uint256& msg);

} // namespace pq

#endif // YCASH_CRYPTO_PQ_SCHEME_H
