// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_YELLOWBACK_BUNDLE_H
#define YCASH_YELLOWBACK_BUNDLE_H

#include "arith_uint256.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "uint256.h"
#include "yellowback/attest.h"
#include "yellowback/math.h"
#include "yellowback/params.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

class CTransaction;

/**
 * Attestation bundles (v3 plan §3.4, §3.8 BUNDLE-1, W2, W8). Pure (§3.10).
 *
 * Wire form: "YA" | version u8 (= 1) | count u8 | count x 74-byte attestation.
 * Six attestations are 448 bytes, inside the 520-byte push (BUNDLE_MAX = 6).
 *
 * Where the bytes come from (W2): under SCRIPTSIG the first push of the one
 * carrier input's scriptSig (script.h ParseCarrierScriptSig), whose SHA256
 * must equal the hash in the carrier's redeem script; under OP_RETURN the
 * payload tail the caller hands in; under EITHER exactly one of the two.
 */
namespace yellowback {

static const uint8_t BUNDLE_VERSION = 1;
static const size_t BUNDLE_HEADER_SIZE = 4;

struct Bundle
{
    uint8_t version;
    std::vector<Attestation> atts;

    Bundle() : version(BUNDLE_VERSION) {}
};

/** "YA" | version | count | attestations. */
std::vector<unsigned char> EncodeBundle(const Bundle& b);

/** nullopt unless magic, version 1, count <= maxCount and the length is exactly 4 + 74 * count. */
// A1: read maxCount's default from Params (BUNDLE_MAX = 6).
std::optional<Bundle> DecodeBundle(const std::vector<unsigned char>& data, size_t maxCount = 6);

/**
 * CAN-2 + C4b (cancel-limit design §2, owner 2026-10-13): the carrier bytes of a cancel's CANCEL_COSIGN payload.
 *
 *   "YC" | version u8 (= 1) | count u8 | count x (priceMicroUsd u32 LE | sig 65)
 *
 * Each entry is one member's co-signature of the cancel and its price statement at the claim's refHeight
 * (attest.h CancelCosignMessage; the key is recovered). 1 <= count <= CANCEL_COSIGN_MAX: seven entries are 487
 * bytes, inside the 520-byte push the carrier's first push is.
 */
static const uint8_t CANCEL_COSIGN_VERSION = 1;
static const size_t CANCEL_COSIGN_ENTRY_SIZE = 4 + 65;
static const size_t CANCEL_COSIGN_MAX = 7;

struct CancelCosignEntry
{
    uint32_t priceMicroUsd;
    std::vector<unsigned char> sig;     //!< 65 bytes, recoverable

    CancelCosignEntry() : priceMicroUsd(0) {}
    bool operator==(const CancelCosignEntry& o) const { return priceMicroUsd == o.priceMicroUsd && sig == o.sig; }
};

/** Empty if count is 0 or above CANCEL_COSIGN_MAX or a signature is not 65 bytes. */
std::vector<unsigned char> EncodeCancelCosigns(const std::vector<CancelCosignEntry>& entries);
/** nullopt unless magic "YC", version 1, 1 <= count <= CANCEL_COSIGN_MAX and the length is exactly 4 + 69 * count. */
std::optional<std::vector<CancelCosignEntry>> DecodeCancelCosigns(const std::vector<unsigned char>& data);

/**
 * C4b: EQV-1's second evidence shape -- one regular attestation and one cancel statement by the same key at the same
 * citedHeight with different prices -- carried as an EQUIVOCATION's carrier bytes:
 *
 *   "YX" | version u8 (= 1) | attestation 74 | intent txid 32 | intent n u32 LE | priceMicroUsd u32 LE | sig 65
 *
 * (182 bytes); the statement's citedHeight is the attestation's.
 */
static const size_t CANCEL_EVIDENCE_SIZE = 3 + 74 + 32 + 4 + 4 + 65;

struct CancelStatement
{
    COutPoint intent;                   //!< the claimant intent the statement co-signed the cancel of
    uint32_t priceMicroUsd;
    std::vector<unsigned char> sig;     //!< 65 bytes, recoverable

    CancelStatement() : priceMicroUsd(0) {}
};

std::vector<unsigned char> EncodeCancelEvidence(const Attestation& a, const CancelStatement& s);
std::optional<std::pair<Attestation, CancelStatement>> DecodeCancelEvidence(const std::vector<unsigned char>& data);

/** Where a bundle rides: params.h BundleCarrier (BUNDLE_CARRIER, W2). */
enum class BundleSource { SCRIPTSIG, OP_RETURN };

/**
 * The bundle bytes of a transaction and where they came from (W2). nullopt with
 * reason "shape" (no source, or both under EITHER), "two-carriers" or "hash"
 * (the carrier's bundle does not hash to its redeem script's commitment). The
 * bytes are not decoded here. skipVin0 excludes a REDEEM's vault input.
 */
std::optional<std::pair<std::vector<unsigned char>, BundleSource>>
ExtractBundle(const CTransaction& tx, BundleCarrier mode, bool skipVin0,
              const std::vector<unsigned char>& payloadTail, std::string* reason = nullptr);

/**
 * The node-local verified-signature cache (W8, R3), keyed by
 * SHA256(attestation74 || blockHash(citedHeight) || pubkey33) -> valid. Implemented in
 * index.cpp; nullptr means no cache. A hit and a cold verification always agree.
 */
class SigCache
{
public:
    virtual ~SigCache() {}
    virtual std::optional<bool> Lookup(const uint256& key) const = 0;
    virtual void Insert(const uint256& key, bool valid) = 0;
};

/** The cache key: SHA256(attestation74 || blockHash(citedHeight) || the 33-byte public key it is verified under). */
uint256 SigCacheKey(const Attestation& att, const uint256& blockHash, const CPubKey& pk);

/** The bounds BUNDLE-1 reads from the parameter set in force at R. */
// A1: fill from Params.
struct BundleLimits
{
    int attestMaxAge;         //!< citedHeight in (R - attestMaxAge, R]
    size_t mSelect;           //!< count >= mSelect
    size_t bundleMax;         //!< count <= bundleMax
    int startHeight;          //!< citedHeight >= startHeight
    MicroUsd priceMin;        //!< price in [priceMin, priceMax]
    MicroUsd priceMax;
};

struct BundleVerdict
{
    bool ok;
    std::string reason;                 //!< first failure: shape, two-carriers, hash, count, member, dup, stale, range, sig
    std::vector<Attestation> C;         //!< the verified attestations, in bundle order (empty unless ok)
    std::optional<MicroUsd> aMint, aClaim;   //!< filled by the caller from BundleStat (needs weights)

    BundleVerdict() : ok(false) {}
};

/**
 * BUNDLE-1 in the W8 order: shape -> hash -> count -> membership/uniqueness ->
 * freshness/range -> signatures. `selected` is Selected(R, selector) (W9),
 * computed by the caller; pubkeyOf(seq) is the attestor's key (nullopt ->
 * "sig"); blockHashAt(height) is the index's block hash (nullopt -> "sig").
 * Every check is total; the first failure names the reason.
 */
BundleVerdict VerifyBundle(const CTransaction& tx, BundleCarrier mode, bool skipVin0,
                           const std::vector<unsigned char>& payloadTail,
                           int R, const std::vector<uint16_t>& selected, const BundleLimits& limits,
                           const std::function<std::optional<CPubKey>(uint16_t)>& pubkeyOf,
                           const std::function<std::optional<uint256>(int)>& blockHashAt,
                           SigCache* cache);

/**
 * The bundle statistic (§3.7): over C with parallel weights, undefined if
 * |C| < mSelect; else sort by price (ties by seq), total = sum of weights,
 * aMint = the price at which the cumulative weight first reaches
 * ceil(qLowBps * total / 10^4), aClaim likewise with qHighBps.
 */
std::pair<std::optional<MicroUsd>, std::optional<MicroUsd>>
BundleStat(const std::vector<Attestation>& C, const std::vector<arith_uint256>& weights, size_t mSelect, int qLowBps, int qHighBps);

} // namespace yellowback

#endif // YCASH_YELLOWBACK_BUNDLE_H
