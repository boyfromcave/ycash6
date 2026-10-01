// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_YELLOWBACK_ATTEST_H
#define YCASH_YELLOWBACK_ATTEST_H

#include "pubkey.h"
#include "uint256.h"

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

/**
 * Yellowback price attestations (v3 plan §3.8 BUNDLE-1, W3, §4.2a). Pure:
 * no clock, no socket, no GetArg; libsecp256k1 is reached only through
 * VerifyCompactSig (§3.10).
 *
 * Wire form (74 bytes, all integers fixed-width little-endian):
 *     seq u16 | priceMicroUsd u32 | citedHeight u32 | sig 64 (compact r||s)
 *
 * Message (R13): SHA256("YBATTEST1" || seq LE16 || price LE32 || citedHeight LE32 || blockHash),
 * the prefix as 9 ASCII bytes with no length byte, the block hash as the 32
 * internal bytes of the uint256 (begin()..end(), not the displayed reversed
 * hex). 51 bytes hashed once.
 */
namespace yellowback {

static const size_t ATTESTATION_SIZE = 74;

struct Attestation
{
    uint16_t seq;
    uint32_t priceMicroUsd;
    uint32_t citedHeight;
    std::array<unsigned char, 64> sig;

    Attestation() : seq(0), priceMicroUsd(0), citedHeight(0) { sig.fill(0); }
    bool operator==(const Attestation& o) const { return seq == o.seq && priceMicroUsd == o.priceMicroUsd && citedHeight == o.citedHeight && sig == o.sig; }
};

/** The signed message. */
uint256 AttestMessage(uint16_t seq, uint32_t priceMicroUsd, uint32_t citedHeight, const uint256& blockHash);

/**
 * Compact ECDSA verification (W3, R17): secp256k1_ecdsa_signature_parse_compact
 * + secp256k1_ecdsa_verify on a verify-only context of this module. A high-S
 * encoding is rejected, never normalised (two encodings of one signature would
 * be two bundle hashes). Never CPubKey::Verify, which normalises. False for an
 * invalid or uncompressed key.
 */
bool VerifyCompactSig(const CPubKey& pk, const uint256& msg, const std::array<unsigned char, 64>& sig);

/** 74 bytes. */
std::vector<unsigned char> EncodeAttestation(const Attestation& att);

/** nullopt unless exactly 74 bytes. */
std::optional<Attestation> DecodeAttestation(const std::vector<unsigned char>& data);
std::optional<Attestation> DecodeAttestation(const unsigned char* data, size_t size);

} // namespace yellowback

#endif // YCASH_YELLOWBACK_ATTEST_H
