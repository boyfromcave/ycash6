// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_YELLOWBACK_PAYLOAD_H
#define YCASH_YELLOWBACK_PAYLOAD_H

#include "primitives/transaction.h"
#include "pubkey.h"
#include "uint256.h"
#include "yellowback/params.h"

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

/**
 * Yellowback payload codec, version 3 (v3 plan §3.3, W14; v2 §3.3 where unchanged).
 *
 *   magic   2 bytes   0x59 0x42 ("YB")
 *   version 1 byte    0x03
 *   type    1 byte    0x01 MINT | 0x02 TRANSFER | 0x03 REDEEM | 0x05 ATTESTOR_REGISTER |
 *                     0x06 CLAIM_NOTICE | 0x07 EQUIVOCATION | 0x08 ATTESTOR_REVIVE
 *   body    per type; total <= 80 bytes; trailing bytes => malformed
 *
 *   MINT               termClass u8, cents u32, lockHeight u32, refHeight u32, ownerPubKey 33,
 *                      feeVout u8, attestFeeVout u8                                            (52)
 *   TRANSFER           count u8, count x (vout u8, cents u32)                                  (5 + 5n, n <= 15)
 *   REDEEM             refHeight u32, feeVout u8, attestFeeVout u8, count u8,
 *                      count x (vout u8, cents u32)                                            (11 + 5n, n <= 13)
 *   ATTESTOR_REGISTER  attestorPubKey 33, bondPubKey 33, bondLocktime u32, flags u8            (75)
 *   CLAIM_NOTICE       vaultTxid 32, vaultVout u8, refHeight u32                               (41)
 *   EQUIVOCATION       (empty; the carrier holds the two attestations)                         (4)
 *   ATTESTOR_REVIVE    seq u16, priceMicroUsd u32, citedHeight u32, sig 64                     (78)
 *
 * Type 0x04, types 0x10-0x1F (the prototype's; 0x10 PRICE retired) and
 * 0x20-0xFF are reserved: unknown type or version => non-Yellowback (the
 * forward-compatibility rule). All multi-byte integers are fixed-width
 * little-endian (no CompactSize, no VARINT). The decoder is a bounds-checked
 * reader over a byte vector; it never uses CDataStream and never throws.
 * feeVout / attestFeeVout = 0xFF mean "no such fee output"; the codec does
 * not range-check either (MINT-8 / RED-3 / AFEE-1 do, K11). The bundle is
 * committed by the carrier's redeem script (§3.4), never by the payload: the
 * OP_RETURN carrier mode's 520-byte tail (W2, unshipped) is not decoded here
 * and the v2 4..80 shape rule stands.
 *
 * DigiByte packs the equivalent information into nVersion bits and an
 * OP_RETURN (ref/digibyte/src/digidollar/txbuilder.cpp:407-418, 807-818);
 * Ycash pins nVersion == 4, so the type lives in the payload (mapping.md §5).
 *
 * The MINT owner key is carried as its 33 raw bytes (`ownerKeyBytes`) as
 * well as a CPubKey: the codec fixes only the shape (33 bytes), MINT-3
 * decides validity (`bad-mint-owner-key`), and a VOID vault records the
 * bytes verbatim so every implementation serialises the same record
 * (SERIALISATION.md §3 C). The ATTESTOR_REGISTER keys are carried the same
 * way (REG-A1 judges them). Versions 1 and 2 are non-Yellowback (V23).
 */
namespace yellowback {

enum class PayloadType : uint8_t {
    MINT              = 0x01,
    TRANSFER          = 0x02,
    REDEEM            = 0x03,
    ATTESTOR_REGISTER = 0x05,
    CLAIM_NOTICE      = 0x06,
    EQUIVOCATION      = 0x07,
    ATTESTOR_REVIVE   = 0x08,
};

/** One (vout, cents) assignment of a TRANSFER or REDEEM body. */
struct Assignment
{
    uint8_t vout;
    uint32_t cents;

    Assignment() : vout(0), cents(0) {}
    Assignment(uint8_t v, uint32_t c) : vout(v), cents(c) {}
    friend bool operator==(const Assignment& a, const Assignment& b) { return a.vout == b.vout && a.cents == b.cents; }
};

/** TRANSFER: 5 + 5*count <= 80 => count <= 15. */
static const size_t MAX_ASSIGNMENTS = 15;
/** REDEEM: 11 + 5*count <= 80 => count <= 13. */
static const size_t MAX_REDEEM_ASSIGNMENTS = 13;
/** ATTESTOR_REVIVE carries a 64-byte compact signature. */
static const size_t COMPACT_SIG_SIZE = 64;

struct Payload
{
    uint8_t version;          //!< PAYLOAD_VERSION (3)
    PayloadType type;

    // MINT
    uint8_t termClass;        //!< 0 = A, 1 = B, 2 = C (V19); any byte decodes, MINT-2 checks it
    uint32_t cents;
    uint32_t lockHeight;
    uint32_t refHeight;       //!< MINT, REDEEM (V11) and CLAIM_NOTICE
    CPubKey ownerPubKey;      //!< from ownerKeyBytes; invalid (size 0) when the bytes are not a key encoding
    std::vector<unsigned char> ownerKeyBytes;   //!< the 33 payload bytes verbatim
    uint8_t feeVout;          //!< MINT and REDEEM; FEE_VOUT_NONE = no fee output
    uint8_t attestFeeVout;    //!< MINT and REDEEM; FEE_VOUT_NONE = no attestor-fee output (AFEE-0)

    // TRANSFER / REDEEM
    std::vector<Assignment> assignments;

    // ATTESTOR_REGISTER (REG-A1)
    CPubKey attestorPubKey;   //!< from attestorKeyBytes, as ownerPubKey from ownerKeyBytes
    std::vector<unsigned char> attestorKeyBytes;
    CPubKey bondPubKey;
    std::vector<unsigned char> bondKeyBytes;
    uint32_t bondLocktime;
    uint8_t flags;

    // CLAIM_NOTICE (NOT-1); refHeight above
    uint256 vaultTxid;        //!< the 32 payload bytes as the uint256's internal bytes (begin()..end())
    uint8_t vaultVout;

    // ATTESTOR_REVIVE (REV-1)
    uint16_t seq;
    uint32_t priceMicroUsd;
    uint32_t citedHeight;
    std::array<unsigned char, COMPACT_SIG_SIZE> sig;

    Payload() : version(PAYLOAD_VERSION), type(PayloadType::MINT), termClass(0), cents(0), lockHeight(0), refHeight(0),
                feeVout(FEE_VOUT_NONE), attestFeeVout(FEE_VOUT_NONE), bondLocktime(0), flags(0), vaultVout(0),
                seq(0), priceMicroUsd(0), citedHeight(0) { sig.fill(0); }

    static Payload Mint(uint8_t termClass, uint32_t cents, uint32_t lockHeight, uint32_t refHeight, const CPubKey& owner, uint8_t feeVout,
                        uint8_t attestFeeVout = FEE_VOUT_NONE);
    static Payload Transfer(const std::vector<Assignment>& assignments);
    static Payload Redeem(uint32_t refHeight, uint8_t feeVout, const std::vector<Assignment>& assignments,
                          uint8_t attestFeeVout = FEE_VOUT_NONE);
    static Payload AttestorRegister(const CPubKey& attestorPubKey, const CPubKey& bondPubKey, uint32_t bondLocktime, uint8_t flags);
    static Payload ClaimNotice(const uint256& vaultTxid, uint8_t vaultVout, uint32_t refHeight);
    static Payload ClaimNotice(const COutPoint& vault, uint32_t refHeight);
    static Payload Equivocation();
    static Payload AttestorRevive(uint16_t seq, uint32_t priceMicroUsd, uint32_t citedHeight, const std::array<unsigned char, COMPACT_SIG_SIZE>& sig);

    /** CLAIM_NOTICE: the vault outpoint (vaultTxid, vaultVout); the §3.7 selector is its 36-byte serialisation (R13). */
    COutPoint VaultOutPoint() const { return COutPoint(vaultTxid, vaultVout); }

    /** Sum of assigned cents (TRANSFER/REDEEM); 0 otherwise. Fits int64 (15 x 2^32). */
    int64_t AssignedCents() const;

    friend bool operator==(const Payload& a, const Payload& b);
};

/** Serialise; the result is the data push of the OP_RETURN output. Empty if the payload is not encodable. */
std::vector<unsigned char> EncodePayload(const Payload& payload);

/**
 * Parse a payload. Returns false for every malformed case of §3.3: bad magic,
 * version or type, short or long body, count > 15 (TRANSFER) / 13 (REDEEM),
 * duplicate vout, cents == 0. The owner and attestor keys are any 33 bytes
 * (MINT-3 / REG-A1 judge them). Range checks that need the transaction (vout
 * exists, vout is not the OP_RETURN) are done by FindPayload. Versions 1 and
 * 2 are non-Yellowback (V23).
 */
bool DecodePayload(const std::vector<unsigned char>& data, Payload& out);

/** Build the OP_RETURN output script for a payload: OP_RETURN <push>. */
CScript PayloadScript(const std::vector<unsigned char>& data);

/**
 * If `script` is exactly `OP_RETURN <one data push>`, return the pushed bytes.
 * Any other shape (no push, two pushes, an OP_N, trailing bytes) => nullopt.
 */
std::optional<std::vector<unsigned char>> ExtractOpReturnData(const CScript& script);

/** Index of the transaction's OP_RETURN output if it has exactly one; nullopt for zero or more than one (§3.2). */
std::optional<unsigned int> FindOpReturn(const CTransaction& tx);

struct FoundPayload
{
    Payload payload;
    unsigned int opReturnIndex;
};

/**
 * The transaction's Yellowback payload, if it has one: exactly one OP_RETURN
 * output, of the required shape, that decodes, whose assigned vouts all exist
 * and none of which is the OP_RETURN itself. Otherwise nullopt: the
 * transaction is non-Yellowback for outputs (inputs still follow IN-1..3).
 */
std::optional<FoundPayload> FindPayload(const CTransaction& tx);

/** Name of a type for RPC output and logs. */
const char* PayloadTypeName(PayloadType type);

} // namespace yellowback

#endif // YCASH_YELLOWBACK_PAYLOAD_H
