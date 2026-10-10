// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_PQKEY_H
#define YCASH_PQKEY_H

#include "script/standard.h"
#include "support/allocators/secure.h"
#include "uint256.h"

#include <cstdint>
#include <vector>

/**
 * A wallet's post-quantum key (docs/plans/yellowback-quantum-plan.md §4.6, quantum spec §2.4):
 * a registered scheme (pq::SCHEME_SLH_DSA_SHA2_128S or pq::SCHEME_FN_DSA_512), the 48-byte
 * keygen seed it was derived from, the public key and the secret key pq::KeyGen makes from the
 * seed. The seed and the secret key live in secure (locked, cleansed) memory. The seed is what the
 * wallet stores (encrypted like every other secret when the wallet is); the secret key is
 * recomputed from it on load. index is the HD derivation index (DerivePQSeed) or
 * PQ_INDEX_NONE for a key that was not derived from this wallet's seed.
 *
 * No public derivation exists for either scheme, so there is no xpub and no watch-only PQ key.
 */
class CPQKey
{
public:
    typedef std::vector<unsigned char, secure_allocator<unsigned char>> Secret;

private:
    uint8_t scheme = 0;
    uint32_t index = 0;
    Secret seed;
    Secret sk;
    std::vector<unsigned char> pk;
    CPQKeyID id;

public:
    static const uint32_t PQ_INDEX_NONE = 0xffffffff;

    CPQKey() {}

    //! Generate the key pair from seed (pq::SeedSize(scheme) bytes). False for an unknown scheme
    //! or a seed of the wrong length.
    bool Set(uint8_t schemeIn, const Secret& seedIn, uint32_t indexIn = PQ_INDEX_NONE);

    bool IsValid() const { return !pk.empty(); }
    uint8_t Scheme() const { return scheme; }
    uint32_t Index() const { return index; }
    const Secret& Seed() const { return seed; }
    const Secret& SecretKey() const { return sk; }
    const std::vector<unsigned char>& PubKey() const { return pk; }

    //! scheme + SHA256(scheme || pk), the TX_PQPKH / vault owner commitment.
    CPQKeyID GetID() const { return id; }

    //! Sign the 32 bytes of hash (memory order, as pq::Verify reads them). The result has no
    //! hashtype byte. SLH-DSA is deterministic, Falcon randomized.
    bool Sign(const uint256& hash, std::vector<unsigned char>& sigOut) const;

    friend bool operator==(const CPQKey& a, const CPQKey& b)
    {
        return a.scheme == b.scheme && a.seed == b.seed && a.pk == b.pk;
    }
};

/** The info string of the PQ seed derivation (DerivePQSeed). */
static const char PQ_SEED_INFO[] = "Ycash PQ key";

/**
 * The keygen seed of the wallet's index-th PQ key of scheme (quantum spec ruling A-12; the same
 * bytes on both node lines, from each line's wallet seed):
 *
 *   seed = HKDF-SHA256(IKM = the wallet's raw HD seed,
 *                      salt = "" (RFC 5869: 32 zero bytes),
 *                      info = "Ycash PQ key" (12 ASCII bytes) || scheme (1 byte) || index (4 bytes, big-endian),
 *                      L = 48)
 *
 * i.e. PRK = HMAC-SHA256(32 zero bytes, IKM); T1 = HMAC-SHA256(PRK, info || 0x01);
 * T2 = HMAC-SHA256(PRK, T1 || info || 0x02); seed = T1 || T2[0..16).
 * 48 bytes for both schemes (SLH-DSA: SK.seed || SK.prf || PK.seed; Falcon: the PQClean keygen
 * DRBG seed, ruling C-8).
 */
CPQKey::Secret DerivePQSeed(const unsigned char* hdSeed, size_t hdSeedLen, uint8_t scheme, uint32_t index);

/** RFC 5869 HKDF-SHA256 (extract then expand), L <= 255 * 32. */
void HKDF_SHA256(const unsigned char* salt, size_t saltLen, const unsigned char* ikm, size_t ikmLen,
                 const unsigned char* info, size_t infoLen, unsigned char* out, size_t outLen);

#endif // YCASH_PQKEY_H
