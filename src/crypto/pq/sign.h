// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// Post-quantum key generation and signing (wallet side, never consensus).
// docs/plans/yellowback-quantum-plan.md §4.6.

#ifndef YCASH_CRYPTO_PQ_SIGN_H
#define YCASH_CRYPTO_PQ_SIGN_H

#include "crypto/pq/scheme.h"
#include "uint256.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace pq {

// Seed sizes KeyGen accepts: SLH-DSA 48 (SK.seed || SK.prf || PK.seed, 16 bytes each, FIPS 205
// Algorithm 18 slh_keygen_internal); Falcon 48 (absorbed by SHAKE256, which drives PQClean's
// keygen: the bytes PQClean's crypto_sign_keypair reads from randombytes(48), so a NIST KAT
// keygen seed reproduces the KAT key). 0 for an unknown scheme.
size_t SeedSize(uint8_t scheme);
// Secret key sizes: SLH-DSA 64 (SK.seed || SK.prf || PK.seed || PK.root); Falcon 1281 (PQClean).
size_t SecretKeySize(uint8_t scheme);

// Deterministic key generation from a seed of exactly SeedSize(scheme) bytes.
bool KeyGen(uint8_t scheme, const std::vector<unsigned char>& seed,
            std::vector<unsigned char>& pk, std::vector<unsigned char>& sk);

// Sign the 32 bytes of msg (memory order, as pq::Verify reads them). SLH-DSA: FIPS 205 pure,
// empty context, deterministic (opt_rand = PK.seed). Falcon: randomized, 88 bytes from the
// OS RNG (GetRandBytes). sig is SigSize(scheme) bytes, without the hashtype byte.
bool Sign(uint8_t scheme, const std::vector<unsigned char>& sk, const uint256& msg,
          std::vector<unsigned char>& sig);

// Sign with explicit randomness (tests and golden vectors). SLH-DSA: entropy empty
// (deterministic, as Sign) or 16 bytes (FIPS 205 hedged opt_rand). Falcon: exactly 88 bytes,
// the nonce (40) then the sampler seed (48), the order PQClean reads them from randombytes().
bool SignWithEntropy(uint8_t scheme, const std::vector<unsigned char>& sk, const uint256& msg,
                     const std::vector<unsigned char>& entropy, std::vector<unsigned char>& sig);

static const size_t FALCON_SIGN_ENTROPY_SIZE = 88;

} // namespace pq

#endif // YCASH_CRYPTO_PQ_SIGN_H
