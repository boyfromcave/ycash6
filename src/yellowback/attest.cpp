// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "yellowback/attest.h"

#include "crypto/sha256.h"

#include <secp256k1.h>

#include <cstring>

namespace yellowback {

namespace {

const unsigned char ATTEST_PREFIX[9] = { 'Y', 'B', 'A', 'T', 'T', 'E', 'S', 'T', '1' };

void WriteLE16(unsigned char* p, uint16_t v) { p[0] = v & 0xff; p[1] = (v >> 8) & 0xff; }
void WriteLE32(unsigned char* p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (v >> (8 * i)) & 0xff; }
uint16_t ReadLE16(const unsigned char* p) { return (uint16_t)p[0] | ((uint16_t)p[1] << 8); }
uint32_t ReadLE32(const unsigned char* p) { uint32_t v = 0; for (int i = 3; i >= 0; i--) v = (v << 8) | p[i]; return v; }

/**
 * pubkey.cpp keeps its verify context in an anonymous namespace (pubkey.cpp:14),
 * and neither it nor configure.ac may change (plan, frozen files), so this
 * module owns one verify-only context of its own, created on first use.
 * Never destroyed: it lives as long as the process, like pubkey.cpp's.
 */
const secp256k1_context* VerifyContext()
{
    static const secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    return ctx;
}

} // namespace

uint256 AttestMessage(uint16_t seq, uint32_t priceMicroUsd, uint32_t citedHeight, const uint256& blockHash)
{
    unsigned char buf[9 + 2 + 4 + 4 + 32];
    memcpy(buf, ATTEST_PREFIX, 9);
    WriteLE16(buf + 9, seq);
    WriteLE32(buf + 11, priceMicroUsd);
    WriteLE32(buf + 15, citedHeight);
    memcpy(buf + 19, blockHash.begin(), 32);
    uint256 out;
    CSHA256().Write(buf, sizeof(buf)).Finalize(out.begin());
    return out;
}

bool VerifyCompactSig(const CPubKey& pk, const uint256& msg, const std::array<unsigned char, 64>& sig)
{
    if (!pk.IsValid() || !pk.IsCompressed()) return false;
    const secp256k1_context* ctx = VerifyContext();
    if (!ctx) return false;
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pk.begin(), pk.size())) return false;
    secp256k1_ecdsa_signature s;
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &s, sig.data())) return false;
    // Returns 1 iff the input was not already low-S: that is a rejection, not a repair (R17).
    if (secp256k1_ecdsa_signature_normalize(ctx, nullptr, &s)) return false;
    return secp256k1_ecdsa_verify(ctx, &s, msg.begin(), &pubkey) == 1;
}

std::vector<unsigned char> EncodeAttestation(const Attestation& att)
{
    std::vector<unsigned char> out(ATTESTATION_SIZE);
    WriteLE16(&out[0], att.seq);
    WriteLE32(&out[2], att.priceMicroUsd);
    WriteLE32(&out[6], att.citedHeight);
    memcpy(&out[10], att.sig.data(), 64);
    return out;
}

std::optional<Attestation> DecodeAttestation(const unsigned char* data, size_t size)
{
    if (!data || size != ATTESTATION_SIZE) return std::nullopt;
    Attestation att;
    att.seq = ReadLE16(data);
    att.priceMicroUsd = ReadLE32(data + 2);
    att.citedHeight = ReadLE32(data + 6);
    memcpy(att.sig.data(), data + 10, 64);
    return att;
}

std::optional<Attestation> DecodeAttestation(const std::vector<unsigned char>& data)
{
    return DecodeAttestation(data.empty() ? nullptr : data.data(), data.size());
}

} // namespace yellowback
