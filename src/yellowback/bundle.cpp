// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "yellowback/bundle.h"

#include "crypto/sha256.h"
#include "primitives/transaction.h"
#include "yellowback/script.h"

#include <algorithm>
#include <cstring>
#include <set>

namespace yellowback {

namespace {

const unsigned char BUNDLE_MAGIC[2] = { 'Y', 'A' };

uint256 Sha256(const std::vector<unsigned char>& data)
{
    uint256 out;
    CSHA256().Write(data.empty() ? nullptr : data.data(), data.size()).Finalize(out.begin());
    return out;
}

BundleVerdict Fail(const std::string& reason)
{
    BundleVerdict v;
    v.ok = false;
    v.reason = reason;
    return v;
}

} // namespace

std::vector<unsigned char> EncodeBundle(const Bundle& b)
{
    std::vector<unsigned char> out;
    out.reserve(BUNDLE_HEADER_SIZE + ATTESTATION_SIZE * b.atts.size());
    out.push_back(BUNDLE_MAGIC[0]);
    out.push_back(BUNDLE_MAGIC[1]);
    out.push_back(b.version);
    out.push_back((unsigned char)std::min<size_t>(b.atts.size(), 255));
    for (size_t i = 0; i < b.atts.size() && i < 255; i++) {
        std::vector<unsigned char> a = EncodeAttestation(b.atts[i]);
        out.insert(out.end(), a.begin(), a.end());
    }
    return out;
}

std::optional<Bundle> DecodeBundle(const std::vector<unsigned char>& data, size_t maxCount)
{
    if (data.size() < BUNDLE_HEADER_SIZE) return std::nullopt;
    if (data[0] != BUNDLE_MAGIC[0] || data[1] != BUNDLE_MAGIC[1]) return std::nullopt;
    if (data[2] != BUNDLE_VERSION) return std::nullopt;
    const size_t count = data[3];
    if (count > maxCount) return std::nullopt;
    if (data.size() != BUNDLE_HEADER_SIZE + ATTESTATION_SIZE * count) return std::nullopt;
    Bundle b;
    b.version = data[2];
    for (size_t i = 0; i < count; i++) {
        std::optional<Attestation> a = DecodeAttestation(data.data() + BUNDLE_HEADER_SIZE + ATTESTATION_SIZE * i, ATTESTATION_SIZE);
        if (!a) return std::nullopt;
        b.atts.push_back(*a);
    }
    return b;
}

std::optional<std::pair<std::vector<unsigned char>, BundleSource>>
ExtractBundle(const CTransaction& tx, BundleCarrier mode, bool skipVin0,
              const std::vector<unsigned char>& payloadTail, std::string* reason)
{
    const bool wantScriptSig = mode != BundleCarrier::OP_RETURN;
    const bool wantOpReturn = mode != BundleCarrier::SCRIPTSIG;

    std::string carrierReason;
    std::optional<size_t> carrier = wantScriptSig ? FindCarrierInput(tx, skipVin0, &carrierReason) : std::nullopt;
    if (wantScriptSig && !carrier && carrierReason == "two-carriers") {
        if (reason) *reason = carrierReason;
        return std::nullopt;
    }
    const bool haveTail = wantOpReturn && !payloadTail.empty();

    if (carrier && haveTail) {              // EITHER means exactly one
        if (reason) *reason = "shape";
        return std::nullopt;
    }
    if (carrier) {
        std::optional<CarrierSpend> spend = ParseCarrierScriptSig(tx.vin[*carrier].scriptSig);
        if (!spend) {                       // FindCarrierInput just parsed it; stated for totality
            if (reason) *reason = "shape";
            return std::nullopt;
        }
        if (Sha256(spend->bundle) != spend->bundleHash) {
            if (reason) *reason = "hash";
            return std::nullopt;
        }
        return std::make_pair(spend->bundle, BundleSource::SCRIPTSIG);
    }
    if (haveTail) return std::make_pair(payloadTail, BundleSource::OP_RETURN);
    if (reason) *reason = "shape";
    return std::nullopt;
}

uint256 SigCacheKey(const Attestation& att, const uint256& blockHash)
{
    std::vector<unsigned char> pre = EncodeAttestation(att);
    pre.insert(pre.end(), blockHash.begin(), blockHash.end());
    return Sha256(pre);
}

BundleVerdict VerifyBundle(const CTransaction& tx, BundleCarrier mode, bool skipVin0,
                           const std::vector<unsigned char>& payloadTail,
                           int R, const std::vector<uint16_t>& selected, const BundleLimits& limits,
                           const std::function<std::optional<CPubKey>(uint16_t)>& pubkeyOf,
                           const std::function<std::optional<uint256>(int)>& blockHashAt,
                           SigCache* cache)
{
    // 1. shape, 2. hash (the extractor names which).
    std::string reason;
    auto extracted = ExtractBundle(tx, mode, skipVin0, payloadTail, &reason);
    if (!extracted) return Fail(reason.empty() ? "shape" : reason);

    // Well-formed: header, version, exact length. A count above 255 cannot be encoded; a count above
    // bundleMax is "count", so decode with the encoding's own ceiling and range-check below.
    std::optional<Bundle> bundle = DecodeBundle(extracted->first, 255);
    if (!bundle) return Fail("shape");

    // 3. count.
    const size_t count = bundle->atts.size();
    if (count < limits.mSelect || count > limits.bundleMax) return Fail("count");

    // 4. membership and uniqueness.
    std::set<uint16_t> seen;
    for (const Attestation& a : bundle->atts) {
        if (std::find(selected.begin(), selected.end(), a.seq) == selected.end()) return Fail("member");
        if (!seen.insert(a.seq).second) return Fail("dup");
    }

    // 5. freshness and range.
    for (const Attestation& a : bundle->atts) {
        const int64_t h = a.citedHeight;
        if (h > (int64_t)R || h <= (int64_t)R - limits.attestMaxAge || h < (int64_t)limits.startHeight) return Fail("stale");
        const MicroUsd p = a.priceMicroUsd;
        if (p < limits.priceMin || p > limits.priceMax) return Fail("range");
    }

    // 6. signatures, each through the per-attestation cache.
    for (const Attestation& a : bundle->atts) {
        std::optional<uint256> blockHash = blockHashAt ? blockHashAt((int)a.citedHeight) : std::nullopt;
        if (!blockHash) return Fail("sig");
        const uint256 key = SigCacheKey(a, *blockHash);
        std::optional<bool> cached = cache ? cache->Lookup(key) : std::nullopt;
        bool valid;
        if (cached) {
            valid = *cached;
        } else {
            std::optional<CPubKey> pk = pubkeyOf ? pubkeyOf(a.seq) : std::nullopt;
            valid = pk && VerifyCompactSig(*pk, AttestMessage(a.seq, a.priceMicroUsd, a.citedHeight, *blockHash), a.sig);
            if (cache) cache->Insert(key, valid);
        }
        if (!valid) return Fail("sig");
    }

    BundleVerdict v;
    v.ok = true;
    v.C = bundle->atts;
    return v;
}

std::pair<std::optional<MicroUsd>, std::optional<MicroUsd>>
BundleStat(const std::vector<Attestation>& C, const std::vector<arith_uint256>& weights, size_t mSelect, int qLowBps, int qHighBps)
{
    if (C.empty() || C.size() < mSelect || weights.size() != C.size()) return { std::nullopt, std::nullopt };
    if (qLowBps < 0 || qHighBps < 0 || qLowBps > 10000 || qHighBps > 10000) return { std::nullopt, std::nullopt };
    std::vector<size_t> order(C.size());
    for (size_t i = 0; i < order.size(); i++) order[i] = i;
    std::sort(order.begin(), order.end(), [&](size_t a, size_t b) {
        if (C[a].priceMicroUsd != C[b].priceMicroUsd) return C[a].priceMicroUsd < C[b].priceMicroUsd;
        return C[a].seq < C[b].seq;
    });
    // Sorted by (price, seq) here; WeightedQuantile's stable sort keeps that order (math.h).
    std::vector<WeightedPrice> sorted;
    for (size_t i : order) sorted.emplace_back((MicroUsd)C[i].priceMicroUsd, weights[i]);
    return { WeightedQuantile(sorted, qLowBps), WeightedQuantile(sorted, qHighBps) };
}

} // namespace yellowback
