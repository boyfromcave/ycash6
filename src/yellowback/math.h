// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_YELLOWBACK_MATH_H
#define YCASH_YELLOWBACK_MATH_H

#include "amount.h"
#include "arith_uint256.h"
#include "yellowback/params.h"

#include <optional>

#include <algorithm>
#include <cstdint>
#include <vector>

/**
 * Derived quantities of plan §3.7. Integer only, arith_uint256 for every
 * product (Ycash uses no __int128), floor division unless a ceiling is
 * written, "undefined" is std::nullopt (§4.2a). Nothing here reads the chain,
 * the clock or configuration, so every function is callable from a unit test
 * (§3.10). No IssuedZat: the subsidy is EvaluateBlock's argument (N22).
 *
 * DigiByte computes the same quantities in IEEE-754 arithmetic on wall-clock
 * price history (ref/digibyte/src/consensus/volatility.cpp:212-251,
 * digidollar/validation.cpp:1145-1161); here they are pure integer functions
 * of the chain (V17, mapping.md §13). The prototype's DCA/ERR/health tables
 * and RequiredBurn (V20) were deleted in Phase 2.
 */
namespace yellowback {

static const int64_t BPS = 10000;

/** ceil(a / b) for b > 0. */
inline arith_uint256 CeilDiv(const arith_uint256& a, const arith_uint256& b)
{
    return (a + b - arith_uint256(1)) / b;
}

/** True iff a fits in an int64_t. */
inline bool FitsInt64(const arith_uint256& a)
{
    return a.bits() <= 63;
}

// ---------------------------------------------------------------- v2 (§3.7)

/**
 * lowerMedian(S): the element at 0-based index floor((n - 1) / 2) of the
 * ascending sort (the smaller middle value for even n, M1). nullopt if empty.
 */
inline std::optional<MicroUsd> LowerMedian(std::vector<MicroUsd> v)
{
    if (v.empty()) return std::nullopt;
    std::sort(v.begin(), v.end());
    return v[(v.size() - 1) / 2];
}

/** Floor square root of a 256-bit integer (bit-by-bit; the root is < 2^128 so t*t never overflows). */
inline arith_uint256 IsqrtU256(const arith_uint256& x)
{
    arith_uint256 r = 0;
    for (int bit = 127; bit >= 0; bit--) {
        arith_uint256 t = r | (arith_uint256(1) << bit);
        if (t * t <= x) r = t;
    }
    return r;
}

/**
 * SIGMA-1 (V17): the volatility multiplier in basis points from the P_fast
 * series s_0..s_n (s_0 = the newest sample). Returns r_k = |s_k - s_{k+1}| *
 * 10^4 / s_{k+1}, var = sum r_k^2 / n, sigmaAnnualBps = isqrt(var *
 * periodsPerYear), result = clamp(sigmaAnnualBps * 10^4 / sigmaRefBps, 10^4,
 * maxBps). sigmaRefBps == 0 fixes the multiplier at 10^4 (regtest). Any
 * undefined sample, fewer than two samples, or a zero sample gives maxBps
 * (K12: a feed gap yields the cap, never 1x).
 */
inline int SigmaMultBps(const std::vector<std::optional<MicroUsd>>& samples, int sigmaRefBps, int periodsPerYear, int maxBps)
{
    if (sigmaRefBps <= 0) return (int)BPS;
    if (maxBps < BPS) maxBps = (int)BPS;
    if (samples.size() < 2) return maxBps;
    for (const auto& s : samples) {
        if (!s.has_value() || s.value() <= 0) return maxBps;
    }
    const size_t n = samples.size() - 1;
    arith_uint256 sumSq = 0;
    for (size_t k = 0; k < n; k++) {
        const MicroUsd a = samples[k].value(), b = samples[k + 1].value();
        arith_uint256 diff = a >= b ? arith_uint256(a - b) : arith_uint256(b - a);
        arith_uint256 r = diff * arith_uint256(BPS) / arith_uint256(b);
        sumSq += r * r;
    }
    arith_uint256 var = sumSq / arith_uint256(n);
    arith_uint256 sigmaAnnual = IsqrtU256(var * arith_uint256(periodsPerYear > 0 ? periodsPerYear : 0));
    arith_uint256 mult = sigmaAnnual * arith_uint256(BPS) / arith_uint256(sigmaRefBps);
    if (mult >= arith_uint256(maxBps)) return maxBps;
    if (mult <= arith_uint256(BPS)) return (int)BPS;
    return (int)mult.GetLow64();
}

/** minRatioBps(class, S) = baseRatioBps(class) * sigmaMultBps / 10^4 (floor). */
inline int MinRatioBps(int baseRatioBps, int sigmaMultBps)
{
    if (baseRatioBps <= 0 || sigmaMultBps <= 0) return 0;
    return (int)((int64_t)baseRatioBps * (int64_t)sigmaMultBps / BPS);
}

/**
 * requiredZat(cents, class, S) = ceil(cents * minRatioBps * COIN / pMint).
 * nullopt = undefined (non-positive input) or unsatisfiable (> MAX_MONEY, K14).
 */
inline std::optional<CAmount> RequiredCollateral(Cents cents, int minRatioBps, MicroUsd pMint)
{
    if (cents <= 0 || minRatioBps <= 0 || pMint <= 0) return std::nullopt;
    arith_uint256 num = arith_uint256(cents) * arith_uint256(minRatioBps) * arith_uint256(COIN);
    arith_uint256 r = CeilDiv(num, arith_uint256(pMint));
    if (!FitsInt64(r)) return std::nullopt;
    CAmount z = (CAmount)r.GetLow64();
    if (!MoneyRange(z)) return std::nullopt;
    return z;
}

/** Same, rounded up to a multiple of `granularity` zat (the wallet uses 1,000; §3.5). */
inline std::optional<CAmount> RequiredCollateralRounded(Cents cents, int minRatioBps, MicroUsd pMint, CAmount granularity = 1000)
{
    auto r = RequiredCollateral(cents, minRatioBps, pMint);
    if (!r.has_value() || granularity <= 0) return r;
    CAmount z = r.value();
    CAmount rem = z % granularity;
    if (rem != 0) z += granularity - rem;
    if (!MoneyRange(z)) return std::nullopt;
    return z;
}

/** capCents(S) = issuedZat * pMint / (COIN * 10^4); nullopt if the price is undefined. */
inline std::optional<Cents> CapCents(CAmount issuedZat, std::optional<MicroUsd> pMint)
{
    if (!pMint.has_value() || pMint.value() <= 0 || issuedZat < 0) return std::nullopt;
    arith_uint256 c = arith_uint256(issuedZat) * arith_uint256(pMint.value()) / (arith_uint256(COIN) * arith_uint256(BPS));
    if (!FitsInt64(c)) return std::nullopt;
    return (Cents)c.GetLow64();
}

/** supplyCapCents(S) = capCents * capBps / 10^4; capBps == 0 => nullopt (no cap, regtest). */
inline std::optional<Cents> SupplyCapCents(CAmount issuedZat, std::optional<MicroUsd> pMint, int capBps)
{
    if (capBps <= 0) return std::nullopt;
    auto cap = CapCents(issuedZat, pMint);
    if (!cap.has_value()) return std::nullopt;
    arith_uint256 c = arith_uint256(cap.value()) * arith_uint256(capBps) / arith_uint256(BPS);
    if (!FitsInt64(c)) return std::nullopt;
    return (Cents)c.GetLow64();
}

/**
 * globalRatioBps = collateralZat * pMint / (COIN * supplyCents); nullopt when
 * supplyCents == 0 ("no supply", never halts) or the price is undefined.
 */
inline std::optional<int64_t> GlobalRatioBps(CAmount collateralZat, std::optional<MicroUsd> pMint, Cents supplyCents)
{
    if (supplyCents <= 0 || !pMint.has_value() || pMint.value() <= 0 || collateralZat < 0) return std::nullopt;
    arith_uint256 r = arith_uint256(collateralZat) * arith_uint256(pMint.value()) / (arith_uint256(COIN) * arith_uint256(supplyCents));
    if (!FitsInt64(r)) return std::nullopt;
    return (int64_t)r.GetLow64();
}

/**
 * Claimable (RED-4): collateralZat * pClaim < mintedCents * thresholdBps * COIN.
 * false when pClaim is undefined (M1: an undefined price never makes a vault claimable).
 */
inline bool IsUnderwater(CAmount collateralZat, std::optional<MicroUsd> pClaim, Cents mintedCents, int thresholdBps)
{
    if (!pClaim.has_value() || pClaim.value() <= 0) return false;
    if (mintedCents <= 0 || thresholdBps <= 0) return false;
    if (collateralZat < 0) collateralZat = 0;
    arith_uint256 lhs = arith_uint256(collateralZat) * arith_uint256(pClaim.value());
    arith_uint256 rhs = arith_uint256(mintedCents) * arith_uint256(thresholdBps) * arith_uint256(COIN);
    return lhs < rhs;
}

/** FEE-1: feeZat(collateralZat) = max(feeMin, collateralZat * feeBps / 10^4). Never overflows: collateral <= MAX_MONEY. */
inline CAmount FeeZat(CAmount collateralZat, CAmount feeMin, int feeBps)
{
    if (collateralZat < 0) collateralZat = 0;
    if (feeBps < 0) feeBps = 0;
    arith_uint256 f = arith_uint256(collateralZat) * arith_uint256(feeBps) / arith_uint256(BPS);
    CAmount fee = FitsInt64(f) ? (CAmount)f.GetLow64() : MAX_MONEY;
    return std::max(feeMin, fee);
}

// ---------------------------------------------------------------- v3 (v3 plan §3.7)

/**
 * Bond weight: bondZat * clamp(ageBlocks, 0, ageCap) in arith_uint256 (R10:
 * up to 4e17 per bond at AGE_CAP; the sum over a set and the 256-bit pick of
 * W9 stay in arith_uint256). The caller derives ageBlocks = H - ageOrigin
 * (§3.7 "Bond weight"). Negative inputs count as zero.
 */
inline arith_uint256 BondWeight(CAmount bondZat, int64_t ageBlocks, int ageCap)
{
    if (bondZat <= 0 || ageBlocks <= 0 || ageCap <= 0) return arith_uint256(0);
    if (ageBlocks > ageCap) ageBlocks = ageCap;
    return arith_uint256(bondZat) * arith_uint256(ageBlocks);
}

/** One attestation of a verified bundle as the bundle statistic sees it. */
struct WeightedPrice
{
    MicroUsd price;
    arith_uint256 weight;

    WeightedPrice() : price(0), weight(0) {}
    WeightedPrice(MicroUsd p, const arith_uint256& w) : price(p), weight(w) {}
};

/**
 * Bundle statistic (§3.7): over entries sorted by price ascending (ties by
 * seq, the caller's order — a stable sort here only re-establishes the price
 * order), the price at which the cumulative weight first reaches
 * ceil(qBps * total / 10^4). nullopt if there are no entries or the
 * threshold exceeds the total (qBps > 10^4). total == 0 (every weight zero,
 * unreachable after arming) gives the first price: the threshold is 0.
 * The |C| >= M_SELECT precondition is the caller's (BUNDLE-1).
 */
inline std::optional<MicroUsd> WeightedQuantile(std::vector<WeightedPrice> entries, int qBps)
{
    if (entries.empty()) return std::nullopt;
    if (qBps < 0) qBps = 0;
    std::stable_sort(entries.begin(), entries.end(), [](const WeightedPrice& a, const WeightedPrice& b) { return a.price < b.price; });
    arith_uint256 total = 0;
    for (const WeightedPrice& e : entries) total += e.weight;
    const arith_uint256 threshold = CeilDiv(total * arith_uint256(qBps), arith_uint256(BPS));
    arith_uint256 cumulative = 0;
    for (const WeightedPrice& e : entries) {
        cumulative += e.weight;
        if (cumulative >= threshold) return e.price;
    }
    return std::nullopt;
}

/**
 * claimantMaxZat = ceil(mintedCents * marginBps * COIN / pClaim) (R5; §3.7
 * check: $100 at 110 % and 18,333 uUSD => 600,010,909,290 zat ~ 6,000 YEC).
 * marginBps is CLAIM_THRESHOLD_BPS under RED-4(a), 10^4 under (b) only (R1).
 * nullopt = undefined (non-positive input) or > MAX_MONEY, which RED-5 reads
 * as residual 0.
 */
inline std::optional<CAmount> ClaimantMaxZat(Cents mintedCents, int marginBps, MicroUsd pClaim)
{
    if (mintedCents <= 0 || marginBps <= 0 || pClaim <= 0) return std::nullopt;
    arith_uint256 num = arith_uint256(mintedCents) * arith_uint256(marginBps) * arith_uint256(COIN);
    arith_uint256 r = CeilDiv(num, arith_uint256(pClaim));
    if (!FitsInt64(r)) return std::nullopt;
    CAmount z = (CAmount)r.GetLow64();
    if (!MoneyRange(z)) return std::nullopt;
    return z;
}

/** residualZat = max(0, collateralZat - claimantMaxZat); a claimantMax over MAX_MONEY (nullopt) leaves nothing (RED-5). */
inline CAmount ResidualZat(CAmount collateralZat, std::optional<CAmount> claimantMaxZat)
{
    if (!claimantMaxZat.has_value() || collateralZat <= claimantMaxZat.value()) return 0;
    return collateralZat - claimantMaxZat.value();
}

/** attestFeeZat = feeZat * attestFeeBps / 10^4 (floor; AFEE-1). feeZat is FEE-1's, so it never overflows. */
inline CAmount AttestFeeZat(CAmount feeZat, int attestFeeBps)
{
    if (feeZat <= 0 || attestFeeBps <= 0) return 0;
    arith_uint256 f = arith_uint256(feeZat) * arith_uint256(attestFeeBps) / arith_uint256(BPS);
    return FitsInt64(f) ? (CAmount)f.GetLow64() : MAX_MONEY;
}

/** PRICE-2 (revised) when ARMED: the three per-transaction prices. */
struct CombinedPrices
{
    std::optional<MicroUsd> pMint;    //!< min(xMint, aMint)
    std::optional<MicroUsd> pClaim;   //!< max(xClaim, aClaim)
    std::optional<MicroUsd> pEmerg;   //!< min(xClaim, aClaim)
};

/** Each output is undefined if either of its inputs is (§3.7 PRICE-2). Not ARMED: the caller reads x alone. */
inline CombinedPrices PriceCombine(std::optional<MicroUsd> xMint, std::optional<MicroUsd> xClaim,
                                   std::optional<MicroUsd> aMint, std::optional<MicroUsd> aClaim)
{
    CombinedPrices c;
    if (xMint.has_value() && aMint.has_value()) c.pMint = std::min(xMint.value(), aMint.value());
    if (xClaim.has_value() && aClaim.has_value()) {
        c.pClaim = std::max(xClaim.value(), aClaim.value());
        c.pEmerg = std::min(xClaim.value(), aClaim.value());
    }
    return c;
}

} // namespace yellowback


#endif // YCASH_YELLOWBACK_MATH_H
