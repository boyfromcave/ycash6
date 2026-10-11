/*
 * Copyright (c) 2026 The Ycash developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or https://www.opensource.org/licenses/mit-license.php .
 *
 * The Ycash entry points to the vendored PQClean falcon-padded-512/clean
 * code. They replace PQClean's pqclean.c, which draws its randomness from a
 * global randombytes(); here every random input is a parameter, so the
 * caller decides where it comes from (the wallet: the OS RNG; the tests:
 * fixed bytes or the NIST KAT DRBG). Byte formats are PQClean's padded ones:
 *   public key 897 bytes: 0x09 || h (14 bits per coefficient)
 *   secret key 1281 bytes: 0x59 || f || g || F
 *   signature  666 bytes: 0x39 || nonce(40) || compressed s || zero padding
 * See README.md in the parent directory.
 */

#ifndef YCASH_CRYPTO_PQ_FALCON_YCASH_FALCON_H
#define YCASH_CRYPTO_PQ_FALCON_YCASH_FALCON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define YCASH_FALCON512_PUBLICKEYBYTES 897
#define YCASH_FALCON512_SECRETKEYBYTES 1281
#define YCASH_FALCON512_SIGBYTES 666
#define YCASH_FALCON512_NONCEBYTES 40
#define YCASH_FALCON512_SIGN_SEEDBYTES 48

/*
 * Verify a padded Falcon-512 signature (sig, siglen) on (m, mlen) under pk
 * (pk, pklen). The logic of PQClean's crypto_sign_verify / do_verify: integer
 * arithmetic only (vrfy.c, codec.c, common.c, fips202.c). Returns 0 on
 * success, -1 on failure. YCASH LOCAL PATCH (Falcon consensus audit
 * 2026-10-10, F-1): siglen must be exactly YCASH_FALCON512_SIGBYTES and pklen
 * exactly YCASH_FALCON512_PUBLICKEYBYTES, so the unpadded "compact" form
 * PQClean's verifier accepts at its own length is refused here as well as by
 * pq::Verify's gate (two independent length checks on the consensus path).
 */
int ycash_falcon512_verify(const uint8_t *sig, size_t siglen,
                           const uint8_t *m, size_t mlen,
                           const uint8_t *pk, size_t pklen);

/*
 * Key generation from a caller-supplied seed: SHAKE256(seed) drives
 * PQClean's keygen exactly as PQClean's crypto_sign_keypair drives it from
 * randombytes(48) (so a 48-byte seed reproduces the NIST KAT keys).
 * Returns 0 on success, -1 on failure.
 */
int ycash_falcon512_keygen_from_seed(uint8_t *pk, uint8_t *sk,
                                     const uint8_t *seed, size_t seedlen);

/*
 * Signing with caller-supplied randomness: nonce (40 bytes) and the 48-byte
 * seed of the sampler's SHAKE256 RNG, the two values PQClean's do_sign
 * reads from randombytes() in that order. Writes exactly
 * YCASH_FALCON512_SIGBYTES bytes. Returns 0 on success, -1 on failure.
 */
int ycash_falcon512_sign(uint8_t *sig, const uint8_t *m, size_t mlen,
                         const uint8_t *sk, const uint8_t *nonce,
                         const uint8_t *seed);

#ifdef __cplusplus
}
#endif

#endif /* YCASH_CRYPTO_PQ_FALCON_YCASH_FALCON_H */
