// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The §3.7 arithmetic: integers and arith_uint256 only, the worked examples
// of the plan as fixtures, the overflow corners of K14 and the V17 regression;
// then the v3 §3.7 quantities (bond weight, the bundle quantile, the claimant
// maximum and residual, the attestor fee, PRICE-2's combination).

#include "yellowback/math.h"
#include "yellowback/params.h"

#include "test/test_bitcoin.h"

#include <limits>

#include <boost/test/unit_test.hpp>

/** The YED attestor set the regtest parameters of these cases name (U-22). */
static inline uint256 TestSet() { return uint256S("5e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e7"); }

using namespace yellowback;

namespace {

std::vector<std::optional<MicroUsd>> Series(size_t n, MicroUsd value)
{
    return std::vector<std::optional<MicroUsd>>(n, value);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(yellowback_math_tests, BasicTestingSetup)

// Rule: PRICE-1
BOOST_AUTO_TEST_CASE(price1_lower_median_is_the_smaller_middle)
{
    BOOST_CHECK(!LowerMedian({}).has_value());
    BOOST_CHECK_EQUAL(LowerMedian({ 5 }).value(), 5);
    BOOST_CHECK_EQUAL(LowerMedian({ 1, 2 }).value(), 1);          // even n: the smaller of the two middle values
    BOOST_CHECK_EQUAL(LowerMedian({ 3, 1, 2 }).value(), 2);       // unsorted input
    BOOST_CHECK_EQUAL(LowerMedian({ 4, 1, 3, 2 }).value(), 2);
    BOOST_CHECK_EQUAL(LowerMedian({ 7, 7, 7, 1 }).value(), 7);
    BOOST_CHECK_EQUAL(LowerMedian({ PRICE_MAX, PRICE_MIN }).value(), PRICE_MIN);
    // 96 alternating quotes: index 47 of the sort is the lower value.
    std::vector<MicroUsd> alt;
    for (int i = 0; i < 96; i++) alt.push_back(i % 2 ? 51000 : 49000);
    BOOST_CHECK_EQUAL(LowerMedian(alt).value(), 49000);
}

// Rule: SIGMA-1
BOOST_AUTO_TEST_CASE(sigma1_isqrt_is_the_floor_root)
{
    BOOST_CHECK(IsqrtU256(0) == arith_uint256(0));
    BOOST_CHECK(IsqrtU256(1) == arith_uint256(1));
    BOOST_CHECK(IsqrtU256(2) == arith_uint256(1));
    BOOST_CHECK(IsqrtU256(3) == arith_uint256(1));
    BOOST_CHECK(IsqrtU256(4) == arith_uint256(2));
    BOOST_CHECK(IsqrtU256(15) == arith_uint256(3));
    BOOST_CHECK(IsqrtU256(16) == arith_uint256(4));
    BOOST_CHECK(IsqrtU256(arith_uint256(1000000) * arith_uint256(1000000)) == arith_uint256(1000000));
    BOOST_CHECK(IsqrtU256(arith_uint256(1000000) * arith_uint256(1000000) - 1) == arith_uint256(999999));
    // K13 / V17 arithmetic check: isqrt(1e4 bps^2 * 420,480) = 64,844 (~6.5e4 bps).
    BOOST_CHECK(IsqrtU256(arith_uint256(10000) * arith_uint256(420480)) == arith_uint256(64844));
    // The top of the range: isqrt(2^256 - 1) = 2^128 - 1, no overflow in t*t.
    arith_uint256 maxv = ~arith_uint256(0);
    arith_uint256 root = IsqrtU256(maxv);
    BOOST_CHECK(root == (arith_uint256(1) << 128) - 1);
    BOOST_CHECK(root * root <= maxv);
}

// Rule: SIGMA-1
// D-IT-5 pins the live multiplier at 1 (MainParams().sigmaRefBps == 0); the formula itself is checked at
// the v2 reference SIGMA_REF_V2 / cap SIGMA_MAX_V2 so a later update that re-enables it still has its vectors.
static const int SIGMA_REF_V2 = 10000;
static const int SIGMA_MAX_V2 = 30000;

BOOST_AUTO_TEST_CASE(sigma1_flat_series_and_worked_example)
{
    Params m = MainParams();
    m.sigmaRefBps = SIGMA_REF_V2;
    m.sigmaMultMaxBps = SIGMA_MAX_V2;
    // Flat: every return is zero, multiplier 1x.
    BOOST_CHECK_EQUAL(SigmaMultBps(Series(43, 50000), m.sigmaRefBps, m.volPeriodsPerYear, m.sigmaMultMaxBps), 10000);
    // One 10 % move among 42 returns: var = 1e6/42 = 23,809; isqrt(23,809 * 8,760) = 14,441 bps => 1.4441x.
    std::vector<std::optional<MicroUsd>> s = Series(43, 50000);
    s[0] = 55000;
    BOOST_CHECK_EQUAL(SigmaMultBps(s, m.sigmaRefBps, m.volPeriodsPerYear, m.sigmaMultMaxBps), 14441);
    // The same move seen from the other side (s_0 lower): |diff| is unsigned, the return is measured against s_{k+1}.
    std::vector<std::optional<MicroUsd>> d = Series(43, 55000);
    d[0] = 50000;   // |50000 - 55000| * 1e4 / 55000 = 909 bps
    BOOST_CHECK_EQUAL(SigmaMultBps(d, m.sigmaRefBps, m.volPeriodsPerYear, m.sigmaMultMaxBps), 13127);
    // Clamp at the cap.
    std::vector<std::optional<MicroUsd>> wild = Series(43, 50000);
    for (size_t i = 0; i < wild.size(); i += 2) wild[i] = 100000;
    BOOST_CHECK_EQUAL(SigmaMultBps(wild, m.sigmaRefBps, m.volPeriodsPerYear, m.sigmaMultMaxBps), m.sigmaMultMaxBps);
    // Below 1x is floored to 1x: a tiny move at a high reference.
    BOOST_CHECK_EQUAL(SigmaMultBps(s, 1000000, m.volPeriodsPerYear, m.sigmaMultMaxBps), 10000);
    // SIGMA_REF_BPS == 0 (regtest default; the live set since D-IT-5) fixes the multiplier whatever the series.
    BOOST_CHECK_EQUAL(SigmaMultBps(wild, 0, m.volPeriodsPerYear, m.sigmaMultMaxBps), 10000);
    BOOST_CHECK_EQUAL(SigmaMultBps({}, 0, m.volPeriodsPerYear, m.sigmaMultMaxBps), 10000);
    // IT-4: with the live set every series, the wild one included, gives 1x; MINT-5's ratio is the class base.
    const Params& live = MainParams();
    BOOST_CHECK_EQUAL(live.sigmaRefBps, 0);
    BOOST_CHECK_EQUAL(SigmaMultBps(wild, live.sigmaRefBps, live.volPeriodsPerYear, live.sigmaMultMaxBps), 10000);
    for (int c = 0; c < NUM_CLASSES; c++) BOOST_CHECK_EQUAL(MinRatioBps(live.baseRatioBps[c], SigmaMultBps(wild, live.sigmaRefBps, live.volPeriodsPerYear, live.sigmaMultMaxBps)), live.baseRatioBps[c]);
}

// Rule: SIGMA-1
// The V17 regression: quotes from different pools alternate +-2 % around a
// flat price. On the raw per-block series the formula reads that as ~3.7x
// volatility (capped at 3x); on the P_fast series (rolling lower medians)
// it is exactly 1x, which is why V17 samples P_fast.
BOOST_AUTO_TEST_CASE(sigma1_cross_pool_noise_is_not_volatility)
{
    Params m = MainParams();
    m.sigmaRefBps = SIGMA_REF_V2;
    m.sigmaMultMaxBps = SIGMA_MAX_V2;
    // 2,016 + 96 raw quotes alternating 49,000 / 51,000 uUSD.
    std::vector<MicroUsd> raw;
    for (int i = 0; i < 2016 + 96; i++) raw.push_back(i % 2 ? 51000 : 49000);
    // P_fast at every VOL_STEP: lower median over the trailing 96 quotes.
    std::vector<std::optional<MicroUsd>> pfast;
    for (int k = 0; k <= m.volWindow / m.volStep; k++) {
        const int end = (int)raw.size() - k * m.volStep;
        std::vector<MicroUsd> window(raw.begin() + end - m.pFastWindow, raw.begin() + end);
        pfast.push_back(LowerMedian(window));
    }
    BOOST_REQUIRE_EQUAL(pfast.size(), 43u);
    BOOST_CHECK_EQUAL(SigmaMultBps(pfast, m.sigmaRefBps, m.volPeriodsPerYear, m.sigmaMultMaxBps), 10000);
    // Contrast: the raw series, sampled per block, hits the cap.
    std::vector<std::optional<MicroUsd>> rawSamples(raw.begin(), raw.begin() + 43);
    BOOST_CHECK_EQUAL(SigmaMultBps(rawSamples, m.sigmaRefBps, m.volPeriodsPerYear, m.sigmaMultMaxBps), m.sigmaMultMaxBps);
}

// Rule: SIGMA-1
// s_43 is exactly at START_HEIGHT when H = START_HEIGHT + VOL_WINDOW: every
// sample defined => a value; one block earlier the oldest sample is below
// START_HEIGHT (undefined) => the cap (K12).
BOOST_AUTO_TEST_CASE(sigma1_first_sample_at_start_height)
{
    Params m = MainParams();
    m.sigmaRefBps = SIGMA_REF_V2;
    m.sigmaMultMaxBps = SIGMA_MAX_V2;
    std::vector<std::optional<MicroUsd>> s = Series(43, 50000);
    BOOST_CHECK_EQUAL(SigmaMultBps(s, m.sigmaRefBps, m.volPeriodsPerYear, m.sigmaMultMaxBps), 10000);
    s[42] = std::nullopt;
    BOOST_CHECK_EQUAL(SigmaMultBps(s, m.sigmaRefBps, m.volPeriodsPerYear, m.sigmaMultMaxBps), m.sigmaMultMaxBps);
    // An undefined sample anywhere (a window that failed its fill) gives the cap too.
    std::vector<std::optional<MicroUsd>> mid = Series(43, 50000);
    mid[20] = std::nullopt;
    BOOST_CHECK_EQUAL(SigmaMultBps(mid, m.sigmaRefBps, m.volPeriodsPerYear, m.sigmaMultMaxBps), m.sigmaMultMaxBps);
    // Fewer than two samples: nothing to return over => the cap, not 1x.
    BOOST_CHECK_EQUAL(SigmaMultBps(Series(1, 50000), m.sigmaRefBps, m.volPeriodsPerYear, m.sigmaMultMaxBps), m.sigmaMultMaxBps);
    BOOST_CHECK_EQUAL(SigmaMultBps({}, m.sigmaRefBps, m.volPeriodsPerYear, m.sigmaMultMaxBps), m.sigmaMultMaxBps);
}

// Rule: MINT-5
BOOST_AUTO_TEST_CASE(mint5_min_ratio_and_required_collateral_worked_example)
{
    BOOST_CHECK_EQUAL(MinRatioBps(50000, 10000), 50000);
    BOOST_CHECK_EQUAL(MinRatioBps(50000, 30000), 150000);
    BOOST_CHECK_EQUAL(MinRatioBps(30000, 14441), 43323);
    BOOST_CHECK_EQUAL(MinRatioBps(0, 10000), 0);

    // §3.7 check: $100 at 300 % and $0.05/YEC => 6e11 zat = 6,000 YEC.
    auto r = RequiredCollateral(10000, 30000, 50000);
    BOOST_REQUIRE(r.has_value());
    BOOST_CHECK_EQUAL(r.value(), 600000000000LL);
    // Ceiling: $1 at 300 % at $0.07 => 4285714285.71.. => 4285714286.
    r = RequiredCollateral(100, 30000, 70000);
    BOOST_REQUIRE(r.has_value());
    BOOST_CHECK_EQUAL(r.value(), 4285714286LL);
    // Rounded up to 1,000 zat for the wallet.
    r = RequiredCollateralRounded(100, 30000, 70000);
    BOOST_REQUIRE(r.has_value());
    BOOST_CHECK_EQUAL(r.value(), 4285715000LL);
    r = RequiredCollateralRounded(10000, 30000, 50000);
    BOOST_CHECK_EQUAL(r.value(), 600000000000LL);   // already a multiple
    // Typed arguments: with four int literals overload resolution picks the retained
    // v1 (cents, ratioPct, dcaBps, price) signature instead — callers pass Cents/MicroUsd/CAmount.
    r = RequiredCollateralRounded((Cents)100, 30000, (MicroUsd)70000, (CAmount)1);
    BOOST_CHECK_EQUAL(r.value(), 4285714286LL);     // granularity 1 = exact
    // Undefined inputs.
    BOOST_CHECK(!RequiredCollateral(0, 30000, 50000).has_value());
    BOOST_CHECK(!RequiredCollateral(10000, 0, 50000).has_value());
    BOOST_CHECK(!RequiredCollateral(10000, 30000, 0).has_value());
}

// Rule: MINT-5
// K14: a $100,000 mint (MAX_MINT, D-Q-24) * 150,000 bps (the v2 worst case) * COIN = 1.5e20 exceeds int64 before
// the division, and at PRICE_MIN the quotient (1.5e18 zat) exceeds MAX_MONEY: "unsatisfiable", never a wrapped
// number. With the live ratios the $100,000 mint is unsatisfiable below the fees spec §2.1 thresholds: class A
// (300 %) under 14,286 uUSD, B (400 %) under 19,048, C (500 %) under 23,810 — more YEC than can exist, not a defect.
BOOST_AUTO_TEST_CASE(mint5_required_collateral_overflow_at_max_mint_and_price_min)
{
    const Params& m = MainParams();
    const Cents bigMint = m.maxMint;
    BOOST_CHECK_EQUAL(bigMint, 10000000);
    BOOST_CHECK_EQUAL(RegtestParams(1, 0, 0, TestSet()).maxMint, bigMint);      // the same on every network (D-Q-24)
    BOOST_CHECK_EQUAL(bigMint, m.maxOutput);                                     // one $100,000 mint is one $100,000 token
    const int worst = MinRatioBps(50000, SIGMA_MAX_V2);     // the v2 worst case (500 % x 3x); the live set's worst is class C's 500 % (D-IT-5)
    BOOST_CHECK_EQUAL(worst, 150000);
    BOOST_CHECK_EQUAL(MinRatioBps(m.baseRatioBps[2], m.sigmaMultMaxBps), 50000);
    BOOST_CHECK(!RequiredCollateral(bigMint, worst, PRICE_MIN).has_value());
    BOOST_CHECK(!RequiredCollateralRounded(bigMint, worst, PRICE_MIN).has_value());
    BOOST_CHECK(!RequiredCollateral(bigMint, m.baseRatioBps[0], PRICE_MIN).has_value());   // class A at PRICE_MIN: 3e17 zat > MAX_MONEY
    // the satisfiability thresholds, exact to the micro-dollar
    BOOST_CHECK(RequiredCollateral(bigMint, 30000, 14286).has_value());
    BOOST_CHECK(!RequiredCollateral(bigMint, 30000, 14285).has_value());
    BOOST_CHECK(RequiredCollateral(bigMint, 40000, 19048).has_value());
    BOOST_CHECK(!RequiredCollateral(bigMint, 40000, 19047).has_value());
    BOOST_CHECK(RequiredCollateral(bigMint, 50000, 23810).has_value());
    BOOST_CHECK(!RequiredCollateral(bigMint, 50000, 23809).has_value());
    // At $0.05 the worst-case mint needs 3e15 zat = 30,000,000 YEC: unsatisfiable; at $0.50, 3,000,000 YEC: satisfiable.
    BOOST_CHECK(!RequiredCollateral(bigMint, worst, 50000).has_value());
    auto r = RequiredCollateral(bigMint, worst, 500000);
    BOOST_REQUIRE(r.has_value());
    BOOST_CHECK_EQUAL(r.value(), 300000000000000LL);
    // Exactly MAX_MONEY is satisfiable; one zat above is not.
    // ratio 10,000 bps at $100/YEC (the pre-D-Q-22 PRICE_MAX): required = cents * 1e4 zat => MAX_MONEY at cents = 2.1e11.
    BOOST_CHECK_EQUAL(RequiredCollateral(210000000000LL, 10000, 100000000).value(), MAX_MONEY);
    BOOST_CHECK(!RequiredCollateral(210000000001LL, 10000, 100000000).has_value());
    // MAX_OUTPUT-sized amounts at $100 are tiny and fine.
    r = RequiredCollateral(m.maxOutput, 30000, 100000000);
    BOOST_REQUIRE(r.has_value());
    BOOST_CHECK_EQUAL(r.value(), 3000 * COIN);   // $100,000 * 300 % / $100 per YEC = 3,000 YEC
}

// Rule: MINT-5
// D-Q-22: PRICE_MAX = UINT32_MAX micro-USD ($4,294.967295). Every product is arith_uint256; the results
// stay in MoneyRange and int64, and the MAX_MONEY boundary is exact.
BOOST_AUTO_TEST_CASE(mint5_required_collateral_at_uint32_price_max)
{
    const Params& m = MainParams();
    BOOST_CHECK_EQUAL(PRICE_MAX, 4294967295LL);
    BOOST_CHECK_EQUAL(PRICE_MAX, (MicroUsd)std::numeric_limits<uint32_t>::max());
    // ceil(cents * 1e12 / PRICE_MAX) <= MAX_MONEY  <=>  cents <= floor(MAX_MONEY * PRICE_MAX / 1e12) = 9,019,431,319,500
    BOOST_CHECK_EQUAL(RequiredCollateral(9019431319500LL, 10000, PRICE_MAX).value(), MAX_MONEY);
    BOOST_CHECK(!RequiredCollateral(9019431319501LL, 10000, PRICE_MAX).has_value());   // 2,100,000,000,000,233 zat > MAX_MONEY
    // MAX_OUTPUT at 300 %: 69.84919312 YEC; the v2 worst ratio on the regtest max mint: 34.92459656 YEC.
    BOOST_CHECK_EQUAL(RequiredCollateral(m.maxOutput, 30000, PRICE_MAX).value(), 6984919312LL);
    BOOST_CHECK_EQUAL(RequiredCollateral(1000000, MinRatioBps(50000, SIGMA_MAX_V2), PRICE_MAX).value(), 3492459656LL);
    // the smallest product rounds up to one zat, never zero
    BOOST_CHECK_EQUAL(RequiredCollateral(1, 1, PRICE_MAX).value(), 1);
    // the 1,000-zat rounding stays in range
    BOOST_CHECK_EQUAL(RequiredCollateralRounded(m.maxOutput, 30000, PRICE_MAX).value(), 6984920000LL);
    // MIN_MINT at 300 % needs 0.0698 YEC here (MINT-5' has no 4 * FEE_MIN floor since D-Q-23: $300 of YEC is the smallest collateral)
    BOOST_CHECK_EQUAL(RequiredCollateral(m.minMint, 30000, PRICE_MAX).value(), 6984920LL);
}

// Rule: MINT-6
BOOST_AUTO_TEST_CASE(mint6_market_cap_and_supply_cap)
{
    const CAmount issued = 1000000 * COIN;   // 1,000,000 YEC issued
    // 1e6 YEC at $0.05 = $50,000 = 5,000,000 cents.
    BOOST_CHECK_EQUAL(CapCents(issued, 50000).value(), 5000000);
    // 15 % of that.
    BOOST_CHECK_EQUAL(SupplyCapCents(issued, 50000, 1500).value(), 750000);
    // Floor division.
    BOOST_CHECK_EQUAL(CapCents(3, 50000).value(), 0);
    BOOST_CHECK_EQUAL(SupplyCapCents(issued, 50000, 1).value(), 500);
    // No cap (regtest 0), undefined price.
    BOOST_CHECK(!SupplyCapCents(issued, 50000, 0).has_value());
    BOOST_CHECK(!CapCents(issued, std::nullopt).has_value());
    BOOST_CHECK(!SupplyCapCents(issued, std::nullopt, 1500).has_value());
    // Full issuance at $100: 2.1e7 YEC * $100 = $2.1e9 = 2.1e11 cents, no overflow.
    BOOST_CHECK_EQUAL(CapCents(MAX_MONEY, 100000000).value(), 210000000000LL);
    // Full issuance at PRICE_MAX (D-Q-22): 2.1e15 * 4,294,967,295 / 1e12 = 9,019,431,319,500 cents; 15 % of it.
    BOOST_CHECK_EQUAL(CapCents(MAX_MONEY, PRICE_MAX).value(), 9019431319500LL);
    BOOST_CHECK_EQUAL(SupplyCapCents(MAX_MONEY, PRICE_MAX, 1500).value(), 1352914697925LL);
}

// Rule: HALT-2
BOOST_AUTO_TEST_CASE(halt2_global_ratio)
{
    // 6,000 YEC backing $100 at $0.05 => 300 %.
    BOOST_CHECK_EQUAL(GlobalRatioBps(600000000000LL, 50000, 10000).value(), 30000);
    // 250 % exactly (the halt threshold) and one cent more of supply below it.
    BOOST_CHECK_EQUAL(GlobalRatioBps(500000000000LL, 50000, 10000).value(), 25000);
    BOOST_CHECK_EQUAL(GlobalRatioBps(500000000000LL, 50000, 10001).value(), 24997);
    // No supply: "no supply", never halts. Undefined price: undefined.
    BOOST_CHECK(!GlobalRatioBps(500000000000LL, 50000, 0).has_value());
    BOOST_CHECK(!GlobalRatioBps(500000000000LL, std::nullopt, 10000).has_value());
    // Everything at the top: MAX_MONEY collateral at $100 backing one cent.
    BOOST_CHECK_EQUAL(GlobalRatioBps(MAX_MONEY, 100000000, 1).value(), 2100000000000000LL);
    // ... and at PRICE_MAX (D-Q-22): 2.1e15 * 4,294,967,295 / 1e8 = 9.02e16 < 2^63, no overflow.
    BOOST_CHECK_EQUAL(GlobalRatioBps(MAX_MONEY, PRICE_MAX, 1).value(), 90194313195000000LL);
}

// Rule: RED-4
BOOST_AUTO_TEST_CASE(red4_underwater_worked_example)
{
    // §3.7 check: 6,000 YEC backing $100 is underwater once pClaim <= 18,333 uUSD.
    const CAmount c = 600000000000LL;
    BOOST_CHECK(IsUnderwater(c, 18333, 10000, 11000));
    BOOST_CHECK(!IsUnderwater(c, 18334, 10000, 11000));
    BOOST_CHECK(IsUnderwater(c, PRICE_MIN, 10000, 11000));
    BOOST_CHECK(!IsUnderwater(c, PRICE_MAX, 10000, 11000));
    // Undefined pClaim: not underwater (M1).
    BOOST_CHECK(!IsUnderwater(c, std::nullopt, 10000, 11000));
    // Zero collateral with any debt is underwater; zero debt never is.
    BOOST_CHECK(IsUnderwater(0, 50000, 1, 11000));
    BOOST_CHECK(!IsUnderwater(0, 50000, 0, 11000));
    // Big numbers: MAX_MONEY * PRICE_MAX vs MAX_MINT * 11,000 * COIN, no overflow.
    BOOST_CHECK(!IsUnderwater(MAX_MONEY, PRICE_MAX, 1000000, 11000));
    // D-Q-22: one zat at PRICE_MAX is worth 0.0043 cents: one cent of debt at 110 % is underwater,
    // and the boundary is exact (collateral * P < cents * bps * COIN, all arith_uint256).
    BOOST_CHECK(IsUnderwater(1, PRICE_MAX, 1, 11000));
    BOOST_CHECK(IsUnderwater(256, PRICE_MAX, 1, 11000));         // 256 * P = 1.0995e12 < 1 * 11,000 * COIN = 1.1e12
    BOOST_CHECK(!IsUnderwater(257, PRICE_MAX, 1, 11000));        // 257 * P = 1.1038e12
}

// Rule: FEE-1'
// D-Q-23: the protocol fee is tiered by the debt (1.0 % of the first $1,000, 0.5 % to $10,000, 0.1 % above), at
// least $1, in cent-bps; the bands and the floor are Params (yb-calibration's), read from the table, not restated.
BOOST_AUTO_TEST_CASE(fee1_bands_and_floor)
{
    const Params& m = MainParams();
    BOOST_CHECK_EQUAL(FEE_BANDS, 3);
    BOOST_CHECK_EQUAL(m.feeBands[0].uptoCents, 100000);  BOOST_CHECK_EQUAL(m.feeBands[0].bps, 100);
    BOOST_CHECK_EQUAL(m.feeBands[1].uptoCents, 1000000); BOOST_CHECK_EQUAL(m.feeBands[1].bps, 50);
    BOOST_CHECK_EQUAL(m.feeBands[2].uptoCents, 0);       BOOST_CHECK_EQUAL(m.feeBands[2].bps, 10);
    BOOST_CHECK_EQUAL(m.feeFloorCents, 100);
    // The floor binds exactly at minMint ($100 x 1 % = $1) and below it; above, the bands.
    BOOST_CHECK_EQUAL(ProtocolFeeUnits(m.minMint, m), 1000000);
    BOOST_CHECK_EQUAL(ProtocolFeeUnits(1, m), 1000000);
    BOOST_CHECK_EQUAL(ProtocolFeeUnits(0, m), 0);
    BOOST_CHECK_EQUAL(ProtocolFeeUnits(-1, m), 0);
    BOOST_CHECK_EQUAL(ProtocolFeeUnits(10001, m), 1000100);                 // one cent over minMint: 1 % of it, over the floor
    // The band edges: $1,000 is all in the first band; $1,000.01 puts one cent in the second.
    BOOST_CHECK_EQUAL(ProtocolFeeUnits(100000, m), 10000000);               // $10
    BOOST_CHECK_EQUAL(ProtocolFeeUnits(100001, m), 10000050);
    BOOST_CHECK_EQUAL(ProtocolFeeUnits(1000000, m), 55000000);              // $10 + $45 = $55
    BOOST_CHECK_EQUAL(ProtocolFeeUnits(1000001, m), 55000010);
    BOOST_CHECK_EQUAL(ProtocolFeeUnits(10000000, m), 145000000);            // $100,000: $145 (0.145 %)
    BOOST_CHECK_EQUAL(ProtocolFeeCents(10000, m), 100);
    BOOST_CHECK_EQUAL(ProtocolFeeCents(100001, m), 1001);                   // ceil to the cent
    BOOST_CHECK_EQUAL(ProtocolFeeCents(1000000, m), 5500);
    BOOST_CHECK_EQUAL(ProtocolFeeCents(10000000, m), 14500);
    // The same bands on every network (fees spec ambiguity 8).
    const Params r = RegtestParams(1, 0, 0, TestSet());
    BOOST_CHECK_EQUAL(ProtocolFeeUnits(1000000, r), ProtocolFeeUnits(1000000, m));
    BOOST_CHECK_EQUAL(r.feeFloorCents, m.feeFloorCents);
    // A table with a zero or negative rate contributes nothing; a bounded last band stops at its edge.
    Params t = m;
    t.feeBands[1].bps = -5;
    BOOST_CHECK_EQUAL(ProtocolFeeUnits(1000000, t), 10000000);
    t.feeBands[2].uptoCents = 2000000;
    BOOST_CHECK_EQUAL(ProtocolFeeUnits(5000000, t), ProtocolFeeUnits(2000000, t));
}

// Rule: FEE-1'
// zat = ceil(units x COIN / pMint): the worked values of the fees spec §1.3 at PRICE_MIN, $0.018 and PRICE_MAX.
BOOST_AUTO_TEST_CASE(fee1_zat_at_the_mint_price)
{
    const Params& m = MainParams();
    BOOST_CHECK_EQUAL(ProtocolFeeZat(10000, PRICE_MIN, m).value(), 1000000000000LL);         // $1 at $0.0001 = 10,000 YEC
    BOOST_CHECK_EQUAL(ProtocolFeeZat(10000, 18000, m).value(), 5555555556LL);                // 55.6 YEC (ceil)
    BOOST_CHECK_EQUAL(ProtocolFeeZat(10000, PRICE_MAX, m).value(), 23284);                   // > dust and > TOKEN_VALUE: never a dust output
    BOOST_CHECK_GT(ProtocolFeeZat(10000, PRICE_MAX, m).value(), TOKEN_VALUE);
    BOOST_CHECK_EQUAL(ProtocolFeeZat(100000, 18000, m).value(), 55555555556LL);
    BOOST_CHECK_EQUAL(ProtocolFeeZat(1000000, 18000, m).value(), 305555555556LL);
    BOOST_CHECK_EQUAL(ProtocolFeeZat(10000000, PRICE_MIN, m).value(), 145000000000000LL);    // 1.45 M YEC: 6.9 % of MAX_MONEY
    BOOST_CHECK(MoneyRange(ProtocolFeeZat(10000000, PRICE_MIN, m).value()));
    BOOST_CHECK_EQUAL(ProtocolFeeZat(10000000, 18000, m).value(), 805555555556LL);
    BOOST_CHECK_EQUAL(ProtocolFeeZat(10000000, PRICE_MAX, m).value(), 3376045);                // ceil(1.45e16 / UINT32_MAX)
    // undefined price: nullopt (RED-1' refuses such a vault); a debt of 0 at any price: the floor
    BOOST_CHECK(!ProtocolFeeZat(10000, 0, m).has_value());
    BOOST_CHECK(!ProtocolFeeZat(10000, -1, m).has_value());
    BOOST_CHECK_EQUAL(ProtocolFeeZat(0, 18000, m).value(), 0);                                 // no debt, no fee (the floor is per debt)
    // MAX_MONEY only for an impossible debt: units x COIN / PRICE_MIN > MAX_MONEY needs units > 2.1e15
    Params t = m;
    t.feeFloorCents = 300000000000LL;   // a $3 B floor
    BOOST_CHECK_EQUAL(ProtocolFeeZat(1, PRICE_MIN, t).value(), MAX_MONEY);
}

// Rule: IT-9'
// The early fee is bps of the debt at pMint (ceil, no floor); K14': protocol + early <= collateral / 50 + 2 zat at any price.
BOOST_AUTO_TEST_CASE(it9_early_fee_of_the_debt_and_k14_bound)
{
    const Params& m = MainParams();
    BOOST_CHECK_EQUAL(EarlyRedeemFeeZat(10000, 500, 50000), 10000000000LL);                  // $5 at $0.05 = 100 YEC
    BOOST_CHECK_EQUAL(EarlyRedeemFeeZat(10000000, 500, 18000), 27777777777778LL);           // $5,000 at $0.018 (ceil)
    BOOST_CHECK_EQUAL(EarlyRedeemFeeZat(10000000, 500, PRICE_MAX), 116415322);
    BOOST_CHECK_EQUAL(EarlyRedeemFeeZat(10000000, 500, PRICE_MIN), MAX_MONEY);             // 5e15 > MAX_MONEY: a vault that cannot exist (§1.6)
    BOOST_CHECK_EQUAL(EarlyRedeemFeeZat(10000, 0, 50000), 0);
    BOOST_CHECK_EQUAL(EarlyRedeemFeeZat(0, 500, 50000), 0);
    BOOST_CHECK_EQUAL(EarlyRedeemFeeZat(10000, 500, 0), 0);
    BOOST_CHECK_EQUAL(EarlyRedeemFeeZat(1, 1, PRICE_MAX), 1);                              // ceil: never zero for a positive product
    for (MicroUsd p : { PRICE_MIN, (MicroUsd)14286, (MicroUsd)18000, (MicroUsd)50000, (MicroUsd)1000000, PRICE_MAX }) {
        for (Cents d : { m.minMint, (Cents)100000, (Cents)1000000, m.maxMint }) {
            for (int cls = 0; cls < NUM_CLASSES; cls++) {
                auto C = RequiredCollateral(d, m.baseRatioBps[cls], p);
                if (!C.has_value()) continue;                                               // unsatisfiable: no such vault (K14)
                const CAmount early = EarlyRedeemFeeZat(d, m.earlyRedeemFeeBps[cls], p);
                const CAmount protocol = ProtocolFeeZat(d, p, m).value();
                BOOST_CHECK_LT(early, MAX_MONEY);
                BOOST_CHECK_LE(protocol + early, C.value() / 50 + 2);                      // K14': every fee is payable from the collateral
            }
        }
    }
    // The satisfiability thresholds at maxMint are mint5_required_collateral_overflow_at_max_mint_and_price_min's.
    BOOST_CHECK_EQUAL(m.maxMint, 10000000);
}

namespace {
/**
 * The class-range invariant, relaxed by H-5 to "contiguous or empty": an empty class
 * (classMin > classMax) is disabled and ignored; the enabled classes, in class order, are
 * non-empty, start at >= 1, and each starts one block after the previous enabled one ends.
 */
bool ClassesContiguousOrEmpty(const Params& p)
{
    int prevMax = -1;
    for (int i = 0; i < NUM_CLASSES; i++) {
        if (!p.IsClassEnabled(i)) continue;
        if (p.classMin[i] < 1) return false;
        if (prevMax >= 0 && p.classMin[i] != prevMax + 1) return false;
        prevMax = p.classMax[i];
    }
    return prevMax >= 0;                                   // at least one class is enabled
}
} // namespace

// Rule: MINT-2
BOOST_AUTO_TEST_CASE(mint2_term_classes_are_contiguous_and_disjoint)
{
    // D-IT-9/D-IT-10 (owner, 2026-10-07): mainnet and testnet enable A 30-90 d, B 91-180 d, C 181-365 d
    // (H-5's disabling of B and C is reversed; A's bounds are unchanged).
    for (const Params* n : { &MainParams(), &TestParams() }) {
        const Params& m = *n;
        BOOST_CHECK_EQUAL(m.ClassForLockBlocks(34559), -1);
        BOOST_CHECK_EQUAL(m.ClassForLockBlocks(34560), 0);
        BOOST_CHECK_EQUAL(m.ClassForLockBlocks(103680), 0);
        BOOST_CHECK_EQUAL(m.ClassForLockBlocks(103681), 1);
        BOOST_CHECK_EQUAL(m.ClassForLockBlocks(207360), 1);
        BOOST_CHECK_EQUAL(m.ClassForLockBlocks(207361), 2);
        BOOST_CHECK_EQUAL(m.ClassForLockBlocks(420480), 2);
        BOOST_CHECK_EQUAL(m.ClassForLockBlocks(420481), -1);
        BOOST_CHECK_EQUAL(m.ClassForLockBlocks(2102400), -1);    // the v2 class C bound is outside every class
        // MINT-2: lock + GRACE stays far below LOCKTIME_THRESHOLD for the longest term at any reachable height
        BOOST_CHECK((int64_t)m.classMax[2] + m.grace + 10000000 < (int64_t)LOCKTIME_THRESHOLD);
        BOOST_CHECK_EQUAL(m.ClassForLockBlocks(0), -1);
        BOOST_CHECK_EQUAL(m.ClassForLockBlocks(-5), -1);
        for (int i = 0; i < NUM_CLASSES; i++) BOOST_CHECK(m.IsClassEnabled(i));
        BOOST_CHECK(ClassesContiguousOrEmpty(m));
        // D-IT-4: the longer the term, the higher the flat ratio
        BOOST_CHECK_EQUAL(m.baseRatioBps[0], 30000);
        BOOST_CHECK_EQUAL(m.baseRatioBps[1], 40000);
        BOOST_CHECK_EQUAL(m.baseRatioBps[2], 50000);
        BOOST_CHECK(m.baseRatioBps[0] < m.baseRatioBps[1] && m.baseRatioBps[1] < m.baseRatioBps[2]);
    }
    Params r = RegtestParams(10, 0, 0, TestSet());
    BOOST_CHECK(ClassesContiguousOrEmpty(r));
    for (int i = 0; i < NUM_CLASSES; i++) BOOST_CHECK(r.IsClassEnabled(i));
    for (int i = 1; i < NUM_CLASSES; i++) BOOST_CHECK_EQUAL(r.classMin[i], r.classMax[i - 1] + 1);
    BOOST_CHECK_EQUAL(r.ClassForLockBlocks(48), 0);
    BOOST_CHECK_EQUAL(r.ClassForLockBlocks(96), 0);
    BOOST_CHECK_EQUAL(r.ClassForLockBlocks(97), 1);
    BOOST_CHECK_EQUAL(r.ClassForLockBlocks(144), 1);
    BOOST_CHECK_EQUAL(r.ClassForLockBlocks(145), 2);
    BOOST_CHECK_EQUAL(r.ClassForLockBlocks(240), 2);
    BOOST_CHECK_EQUAL(r.ClassForLockBlocks(241), -1);
}

// Rule: MINT-2
// H-5: the params invariant is "contiguous or empty"; an empty range disables a class without a schema change.
BOOST_AUTO_TEST_CASE(params_class_ranges_contiguous_or_empty)
{
    Params p = RegtestParams(10, 0, 0, TestSet());                  // A [48, 96], B [97, 144], C [145, 240]
    BOOST_CHECK(ClassesContiguousOrEmpty(p));
    Params noB = p;                                         // B empty: C must then follow A directly
    noB.classMin[1] = 97; noB.classMax[1] = 96;
    BOOST_CHECK(!noB.IsClassEnabled(1));
    BOOST_CHECK(!ClassesContiguousOrEmpty(noB));            // a gap [97, 144] between A and C
    noB.classMin[2] = 97;
    BOOST_CHECK(ClassesContiguousOrEmpty(noB));
    BOOST_CHECK_EQUAL(noB.ClassForLockBlocks(100), 2);
    Params aOnly = p;                                       // the mainnet shape
    aOnly.classMin[1] = aOnly.classMin[2] = 97; aOnly.classMax[1] = aOnly.classMax[2] = 96;
    BOOST_CHECK(ClassesContiguousOrEmpty(aOnly));
    BOOST_CHECK_EQUAL(aOnly.ClassForLockBlocks(96), 0);
    BOOST_CHECK_EQUAL(aOnly.ClassForLockBlocks(97), -1);
    BOOST_CHECK_EQUAL(aOnly.ClassForLockBlocks(240), -1);
    Params overlap = p;                                     // B starting inside A is not contiguous
    overlap.classMin[1] = 96;
    BOOST_CHECK(!ClassesContiguousOrEmpty(overlap));
    Params none = p;                                        // every class empty: nothing can mint
    for (int i = 0; i < NUM_CLASSES; i++) { none.classMin[i] = 2; none.classMax[i] = 1; }
    BOOST_CHECK(!ClassesContiguousOrEmpty(none));
    Params zero = p;                                        // an enabled class starting at 0
    zero.classMin[0] = 0;
    BOOST_CHECK(!ClassesContiguousOrEmpty(zero));
    BOOST_CHECK(!p.IsClassEnabled(-1));
    BOOST_CHECK(!p.IsClassEnabled(NUM_CLASSES));
}

// Rule: HALT-2
// W16 / H-11 / D-IT-11 / D-IT-12: the global-ratio halt sits below the base ratio of every enabled
// class (the hardening plan's §1.4 invariant), and the recapitalisation floor equals class C's base, so
// under a halt or above the cap only the 500 % tier mints (IT-5). W16's "recap = 2 x halt" is given up.
BOOST_AUTO_TEST_CASE(halt2_floor_below_every_enabled_class_ratio)
{
    for (const Params* n : { &MainParams(), &TestParams() }) {
        const Params& m = *n;
        BOOST_CHECK_EQUAL(m.globalRatioHaltBps, 20000);
        BOOST_CHECK_EQUAL(m.recapRatioBps, 50000);
        BOOST_CHECK_EQUAL(m.recapRatioBps, m.baseRatioBps[2]);
        for (int i = 0; i < NUM_CLASSES; i++) {
            if (m.IsClassEnabled(i)) BOOST_CHECK(m.globalRatioHaltBps < m.baseRatioBps[i]);
        }
        BOOST_CHECK(m.baseRatioBps[0] < m.recapRatioBps && m.baseRatioBps[1] < m.recapRatioBps && m.baseRatioBps[2] >= m.recapRatioBps);
    }
    const Params r = RegtestParams(10, 0, 0, TestSet());
    BOOST_CHECK_EQUAL(r.recapRatioBps, r.baseRatioBps[2]);
    for (int i = 0; i < NUM_CLASSES; i++) BOOST_CHECK(r.globalRatioHaltBps < r.baseRatioBps[i]);
}

// The §3.1 table, both columns; the regtest flags land where the plan says.
BOOST_AUTO_TEST_CASE(act5_params_tables)
{
    const Params& m = MainParams();
    BOOST_CHECK_EQUAL(m.network, "main");
    // U-22: YED starts at the UPGRADE_VAULT height with the network's attestor set; neither is set on mainnet yet.
    BOOST_CHECK(!m.IsConfigured());
    BOOST_CHECK_EQUAL(m.startHeight, 0);
    BOOST_CHECK(m.attestorSetId.IsNull());
    BOOST_CHECK_EQUAL(m.claimDelay, 576);                     // CLAIM_DELAY: 12 hours (U-23; owner 2026-10-07)
    BOOST_CHECK_EQUAL(m.pFastWindow, 96);   BOOST_CHECK_EQUAL(m.pFastMinFill, 48);
    BOOST_CHECK_EQUAL(m.pMidWindow, 576);   BOOST_CHECK_EQUAL(m.pMidMinFill, 384);
    BOOST_CHECK_EQUAL(m.pSlowWindow, 2016); BOOST_CHECK_EQUAL(m.pSlowMinFill, 1344);
    BOOST_CHECK_EQUAL(m.nReg, 576);
    BOOST_CHECK_EQUAL(m.nPenalty, 288);
    BOOST_CHECK_EQUAL(m.peerLag, 10);
    BOOST_CHECK_EQUAL(m.peerMin, 5);
    BOOST_CHECK_EQUAL(m.deviationBps, 1000);
    BOOST_CHECK_EQUAL(m.accuracyBandBps, 300);
    BOOST_CHECK_EQUAL(m.accuracyWindow, 576);
    BOOST_CHECK_EQUAL(m.payeeTiltBps, 10000);
    BOOST_CHECK_EQUAL(m.payeeWindow, 100);
    BOOST_CHECK_EQUAL(m.feeFloorCents, 100);                  // FEE-1' (D-Q-23): $1 per action
    BOOST_CHECK_EQUAL(m.feeBands[0].bps, 100);
    BOOST_CHECK_EQUAL(m.earlyRedeemFeeBps[0], 500);           // IT-9'
    BOOST_CHECK_EQUAL(m.earlyRedeemFeeBps[1], 250);
    BOOST_CHECK_EQUAL(m.earlyRedeemFeeBps[2], 100);
    BOOST_CHECK_EQUAL(EarlyRedeemFeeZat(10000, 500, 50000), 10000000000LL);   // 5 % of $100 at $0.05 = 100 YEC
    BOOST_CHECK_EQUAL(EarlyRedeemFeeZat(10000, 0, 50000), 0);
    BOOST_CHECK_EQUAL(m.grace, 34560);
    BOOST_CHECK_EQUAL(m.claimThresholdBps, 12500);            // D-IT-2
    BOOST_CHECK_EQUAL(m.supplyCapBps, 1500);
    BOOST_CHECK_EQUAL(m.globalRatioHaltBps, 20000);           // D-IT-11
    BOOST_CHECK_EQUAL(m.recapRatioBps, 50000);                // D-IT-12
    BOOST_CHECK_EQUAL(m.divergenceBps, 2000);
    BOOST_CHECK_EQUAL(m.volWindow, 2016);
    BOOST_CHECK_EQUAL(m.volStep, 48);
    BOOST_CHECK_EQUAL(m.volPeriodsPerYear, 8760);
    BOOST_CHECK_EQUAL(m.sigmaRefBps, 0);                      // D-IT-5: multiplier pinned at 1
    BOOST_CHECK_EQUAL(m.sigmaMultMaxBps, 10000);
    BOOST_CHECK_EQUAL(m.minMint, 10000);
    BOOST_CHECK_EQUAL(m.maxMint, 10000000);                   // D-Q-24: $100,000 (H-12's $2,500 reversed)
    BOOST_CHECK_EQUAL(m.minOutput, 100);
    BOOST_CHECK_EQUAL(m.maxOutput, 10000000);
    BOOST_CHECK_EQUAL(m.tokenValue, TOKEN_VALUE);
    BOOST_CHECK_EQUAL(m.refWindow, REF_WINDOW);
    BOOST_CHECK_EQUAL(m.volWindow / m.volStep, 42);   // 43 samples, 42 returns
    BOOST_CHECK_EQUAL(TestParams().network, "test");
    BOOST_CHECK_EQUAL(TestParams().grace, 34560);

    Params r = RegtestParams(150, 12345, 700, TestSet());
    BOOST_CHECK_EQUAL(r.network, "regtest");
    BOOST_CHECK(r.IsConfigured());
    BOOST_CHECK_EQUAL(r.startHeight, 150);
    BOOST_CHECK_EQUAL(r.sigmaRefBps, 12345);
    BOOST_CHECK_EQUAL(r.supplyCapBps, 700);
    BOOST_CHECK(r.attestorSetId == TestSet());
    BOOST_CHECK_EQUAL(r.claimDelay, 10);
    BOOST_CHECK_EQUAL(r.pFastWindow, 8);   BOOST_CHECK_EQUAL(r.pFastMinFill, 4);
    BOOST_CHECK_EQUAL(r.pMidWindow, 24);   BOOST_CHECK_EQUAL(r.pMidMinFill, 16);
    BOOST_CHECK_EQUAL(r.pSlowWindow, 64);  BOOST_CHECK_EQUAL(r.pSlowMinFill, 43);
    BOOST_CHECK_EQUAL(r.nReg, 24);
    BOOST_CHECK_EQUAL(r.nPenalty, 12);
    BOOST_CHECK_EQUAL(r.peerLag, 4);
    BOOST_CHECK_EQUAL(r.peerMin, 3);
    BOOST_CHECK_EQUAL(r.accuracyWindow, 24);
    BOOST_CHECK_EQUAL(r.payeeWindow, 10);
    BOOST_CHECK_EQUAL(r.grace, 24);
    BOOST_CHECK_EQUAL(r.volWindow, 64);
    BOOST_CHECK_EQUAL(r.volStep, 8);
    BOOST_CHECK_EQUAL(r.volPeriodsPerYear, 8760);   // K13: equal on every network
    BOOST_CHECK_EQUAL(r.volWindow / r.volStep, 8);
    BOOST_CHECK_EQUAL(r.feeFloorCents, m.feeFloorCents);      // the fee bands and floor are mainnet's everywhere (D-Q-23)
    BOOST_CHECK_EQUAL(r.feeBands[2].bps, m.feeBands[2].bps);
    BOOST_CHECK_EQUAL(r.claimThresholdBps, m.claimThresholdBps);
    // The regtest column keeps the v3 values the hardening plan changed on mainnet (H-11, H-12).
    BOOST_CHECK_EQUAL(r.globalRatioHaltBps, 25000);
    BOOST_CHECK_EQUAL(r.recapRatioBps, 50000);
    BOOST_CHECK_EQUAL(r.maxMint, m.maxMint);                  // D-Q-24: no regtest override
    BOOST_CHECK(!RegtestParams(0, 0, 0, TestSet()).IsConfigured());
    BOOST_CHECK(!RegtestParams(150, 0, 0, uint256()).IsConfigured());   // U-22: no attestor set, no YED
    BOOST_CHECK(!ParamsForNetwork("regtest").IsConfigured());
    BOOST_CHECK_THROW(ParamsForNetwork("nope"), std::runtime_error);
}

// ---------------------------------------------------------------- v3 (v3 plan §3.1, §3.7)

// Rule: ARM-1
// Rule: ARM-2
// The v3 §3.1 rows, both columns, and the two regtest flags.
BOOST_AUTO_TEST_CASE(arm1_v3_params_tables)
{
    const Params& m = MainParams();
    BOOST_CHECK_EQUAL(PAYLOAD_VERSION, 3);
    BOOST_CHECK_EQUAL(PayloadVersion(), 3);
    BOOST_CHECK_EQUAL(m.attestArmMin, 7);                     // H-2 (D-4 had 5)
    BOOST_CHECK_EQUAL(m.mintRequiresArmed, true);             // H-1
    BOOST_CHECK_EQUAL(m.attestArmDelay, 1152);
    BOOST_CHECK_EQUAL(m.attestRequired, true);
    BOOST_CHECK(m.bundleCarrier == BundleCarrier::SCRIPTSIG);
    BOOST_CHECK_EQUAL(m.nSlots, 9);
    BOOST_CHECK_EQUAL(m.mSelect, 4);
    BOOST_CHECK_EQUAL(m.kSlack, 2);
    BOOST_CHECK_EQUAL(m.bundleMax, 6);
    BOOST_CHECK_EQUAL(m.qLowBps, 3333);
    BOOST_CHECK_EQUAL(m.qHighBps, 6667);
    BOOST_CHECK_EQUAL(m.attestMaxAge, 20);
    BOOST_CHECK_EQUAL(m.attestMaxAge, 2 * m.attestInterval);   // R4
    BOOST_CHECK_EQUAL(m.pinWindow, 288);
    BOOST_CHECK_EQUAL(m.pinDeltaBps, 500);
    BOOST_CHECK_EQUAL(m.pinMinTags, 3);
    BOOST_CHECK_EQUAL(m.pinMinBundles, 2);
    BOOST_CHECK_EQUAL(m.divergeBpsAttest, 1500);
    BOOST_CHECK_EQUAL(m.emergencyRatioBps, 10500);
    BOOST_CHECK_EQUAL(m.emergencyPersist, 48);
    BOOST_CHECK_EQUAL(m.emergencyNoticeTtl, 1152);
    BOOST_CHECK_EQUAL(m.residualMinZat, 100000);
    BOOST_CHECK_EQUAL(m.attestFeeBps, 5000);                  // H-4 (D-3 had 2,500)
    BOOST_CHECK_EQUAL(m.bondMinFloorZat, 5000 * COIN);      // D-Q-30
    BOOST_CHECK_EQUAL(m.bondMinCapZat, 20000 * COIN);
    BOOST_CHECK_EQUAL(m.bondShareBps, 500);
    BOOST_CHECK_EQUAL(m.bondMinLock, 0);                     // the bond exit delay (owner 2026-10-11): the lock is in the vault state
    BOOST_CHECK_EQUAL(m.bondMaturity, 16128);
    BOOST_CHECK_EQUAL(m.ageCap, 207360);
    BOOST_CHECK_EQUAL(m.foundingWindow, 8064);
    BOOST_CHECK_EQUAL(m.dormancyBlocks, 16128);
    BOOST_CHECK_EQUAL(m.dormancyMinBundles, 20);
    BOOST_CHECK_EQUAL(m.dormancyCheck, 48);
    BOOST_CHECK_EQUAL(m.carrierValue, 10000);
    BOOST_CHECK_EQUAL(m.attestInterval, 10);
    BOOST_CHECK_EQUAL(m.walletConfirmations, 6);
    BOOST_CHECK_EQUAL(TestParams().attestArmMin, 7);
    BOOST_CHECK_EQUAL(TestParams().mintRequiresArmed, true);
    BOOST_CHECK_EQUAL(TestParams().attestFeeBps, 5000);
    BOOST_CHECK_EQUAL(TestParams().feeFloorCents, 100);
    BOOST_CHECK_EQUAL(TestParams().bondMinCapZat, 20000 * COIN);
    // "ARMED" means both the snapshot status and ATTEST_REQUIRED (W15).
    BOOST_CHECK(m.IsArmed(true));
    BOOST_CHECK(!m.IsArmed(false));
    Params off = m;
    off.attestRequired = false;
    BOOST_CHECK(!off.IsArmed(true));

    Params r = RegtestParams(150, 0, 0, TestSet());   // the two v3 flags default to 3 / scriptsig, H-1's to off
    BOOST_CHECK_EQUAL(r.attestArmMin, 3);
    BOOST_CHECK_EQUAL(r.mintRequiresArmed, false);
    BOOST_CHECK_EQUAL(RegtestParams(150, 0, 0, TestSet(), 3, BundleCarrier::SCRIPTSIG, true).mintRequiresArmed, true);
    BOOST_CHECK_EQUAL(Params().mintRequiresArmed, false);
    BOOST_CHECK(r.bundleCarrier == BundleCarrier::SCRIPTSIG);
    BOOST_CHECK_EQUAL(r.attestArmDelay, 8);
    BOOST_CHECK_EQUAL(r.attestRequired, true);
    BOOST_CHECK_EQUAL(r.nSlots, 5);
    BOOST_CHECK_EQUAL(r.mSelect, 2);
    BOOST_CHECK_EQUAL(r.kSlack, 1);
    BOOST_CHECK_EQUAL(r.bundleMax, 6);
    BOOST_CHECK_EQUAL(r.qLowBps, 3333);
    BOOST_CHECK_EQUAL(r.qHighBps, 6667);
    BOOST_CHECK_EQUAL(r.attestMaxAge, 8);
    BOOST_CHECK_EQUAL(r.attestMaxAge, 2 * r.attestInterval);
    BOOST_CHECK_EQUAL(r.pinWindow, 16);
    BOOST_CHECK_EQUAL(r.pinDeltaBps, 500);
    BOOST_CHECK_EQUAL(r.pinMinTags, 2);
    BOOST_CHECK_EQUAL(r.pinMinBundles, 2);
    BOOST_CHECK_EQUAL(r.divergeBpsAttest, 1500);
    BOOST_CHECK_EQUAL(r.emergencyRatioBps, 10500);
    BOOST_CHECK_EQUAL(r.emergencyPersist, 4);
    BOOST_CHECK_EQUAL(r.emergencyNoticeTtl, 64);
    BOOST_CHECK_EQUAL(r.residualMinZat, 100000);
    BOOST_CHECK_EQUAL(r.attestFeeBps, 2500);
    BOOST_CHECK_EQUAL(r.bondMinFloorZat, COIN * 5 / 2);     // D-Q-30 at 1/2,000 of mainnet
    BOOST_CHECK_EQUAL(r.bondMinCapZat, 10 * COIN);
    BOOST_CHECK_EQUAL(r.bondShareBps, 500);
    BOOST_CHECK_EQUAL(r.bondMinLock, 0);
    BOOST_CHECK_EQUAL(r.bondMaturity, 8);
    BOOST_CHECK_EQUAL(r.ageCap, 64);
    BOOST_CHECK_EQUAL(r.foundingWindow, 16);
    BOOST_CHECK_EQUAL(r.dormancyBlocks, 16);
    BOOST_CHECK_EQUAL(r.dormancyMinBundles, 2);
    BOOST_CHECK_EQUAL(r.dormancyCheck, 4);
    BOOST_CHECK_EQUAL(r.carrierValue, 10000);
    BOOST_CHECK_EQUAL(r.attestInterval, 4);
    BOOST_CHECK_EQUAL(r.walletConfirmations, 1);
    // The flags land: 0 = never arms; every carrier spelling parses.
    Params never = RegtestParams(150, 0, 0, TestSet(), 0, BundleCarrier::EITHER);
    BOOST_CHECK_EQUAL(never.attestArmMin, 0);
    BOOST_CHECK(never.bundleCarrier == BundleCarrier::EITHER);
    BOOST_CHECK(RegtestParams(1, 0, 0, TestSet(), 7, BundleCarrier::OP_RETURN).bundleCarrier == BundleCarrier::OP_RETURN);
    BOOST_CHECK(ParseBundleCarrier("scriptsig").value() == BundleCarrier::SCRIPTSIG);
    BOOST_CHECK(ParseBundleCarrier("opreturn").value() == BundleCarrier::OP_RETURN);
    BOOST_CHECK(ParseBundleCarrier("either").value() == BundleCarrier::EITHER);
    BOOST_CHECK(!ParseBundleCarrier("").has_value());
    BOOST_CHECK(!ParseBundleCarrier("ScriptSig").has_value());
    BOOST_CHECK(!ParseBundleCarrier("op_return").has_value());
    for (BundleCarrier c : { BundleCarrier::SCRIPTSIG, BundleCarrier::OP_RETURN, BundleCarrier::EITHER }) {
        BOOST_CHECK(ParseBundleCarrier(BundleCarrierName(c)).value() == c);
    }
    BOOST_CHECK_EQUAL(std::string(BundleCarrierName(BundleCarrier::SCRIPTSIG)), "scriptsig");
    // The default-constructed set is unconfigured but not disarmable by accident.
    BOOST_CHECK_EQUAL(Params().attestRequired, true);
    BOOST_CHECK(Params().bundleCarrier == BundleCarrier::SCRIPTSIG);
}

// Rule: D-Q-30
// The bond minimum from vault collateral: clamp(ceil(collateral x bondShareBps / (10^4 x N_SLOTS)), floor, cap).
BOOST_AUTO_TEST_CASE(dq28_bond_min_from_collateral)
{
    const Params& m = MainParams();
    const Params r = RegtestParams(1, 0, 0, TestSet());
    // mainnet (N_SLOTS 9): the floor binds to 900,000 YEC, the cap from 3.6 M YEC
    BOOST_CHECK_EQUAL(BondMinFromCollateralZat(0, m), 5000 * COIN);
    BOOST_CHECK_EQUAL(BondMinFromCollateralZat(-1, m), 5000 * COIN);
    BOOST_CHECK_EQUAL(BondMinFromCollateralZat(100000 * COIN, m), 5000 * COIN);
    BOOST_CHECK_EQUAL(BondMinFromCollateralZat(900000 * COIN, m), 5000 * COIN);
    BOOST_CHECK_EQUAL(BondMinFromCollateralZat(900000 * COIN + 1, m), 5000 * COIN + 1);       // ceil
    BOOST_CHECK_EQUAL(BondMinFromCollateralZat(1800000 * COIN, m), 10000 * COIN);
    BOOST_CHECK_EQUAL(BondMinFromCollateralZat(2700000 * COIN, m), 15000 * COIN);
    BOOST_CHECK_EQUAL(BondMinFromCollateralZat(3600000 * COIN - 1, m), 20000 * COIN);       // ceil reaches the cap
    BOOST_CHECK_EQUAL(BondMinFromCollateralZat(3600000 * COIN - 180, m), 20000 * COIN - 1);
    BOOST_CHECK_EQUAL(BondMinFromCollateralZat(3600000 * COIN, m), 20000 * COIN);
    BOOST_CHECK_EQUAL(BondMinFromCollateralZat(10000000 * COIN, m), 20000 * COIN);
    BOOST_CHECK_EQUAL(BondMinFromCollateralZat(MAX_MONEY, m), 20000 * COIN);
    BOOST_CHECK_EQUAL(BondMinFromCollateralZat(std::numeric_limits<int64_t>::max(), m), 20000 * COIN);
    // regtest (N_SLOTS 5, 2.5 / 10 YEC): the floor to 250 YEC, the cap from 1,000 YEC
    BOOST_CHECK_EQUAL(BondMinFromCollateralZat(0, r), COIN * 5 / 2);
    BOOST_CHECK_EQUAL(BondMinFromCollateralZat(250 * COIN, r), COIN * 5 / 2);
    BOOST_CHECK_EQUAL(BondMinFromCollateralZat(300 * COIN, r), 3 * COIN);
    BOOST_CHECK_EQUAL(BondMinFromCollateralZat(1000 * COIN, r), 10 * COIN);
    BOOST_CHECK_EQUAL(BondMinFromCollateralZat(1300 * COIN, r), 10 * COIN);
    // degenerate parameters: no slots gives the cap; a share of 0 gives the floor
    Params z = m;
    z.nSlots = 0;
    BOOST_CHECK_EQUAL(BondMinFromCollateralZat(0, z), 20000 * COIN);
    z = m;
    z.bondShareBps = 0;
    BOOST_CHECK_EQUAL(BondMinFromCollateralZat(MAX_MONEY, z), 5000 * COIN);
    // review A2: SNAP skips the snapshot when the bond is outside [floor, cap]; the minimum never leaves that interval
    for (const Params* q : { &m, &r }) {
        for (CAmount c : { (CAmount)-1, (CAmount)0, (CAmount)1, 250 * COIN, 900000 * COIN, 900000 * COIN + 1, 2000000 * COIN,
                           3600000 * COIN, MAX_MONEY, std::numeric_limits<int64_t>::max() }) {
            const CAmount v = BondMinFromCollateralZat(c, *q);
            BOOST_CHECK(v >= q->bondMinFloorZat && v <= q->bondMinCapZat);
        }
    }
}

// Rule: BUNDLE-1
// weight = bondZat * clamp(age, 0, AGE_CAP), in arith_uint256 (R10).
BOOST_AUTO_TEST_CASE(bundle1_bond_weight_clamps_age)
{
    const Params& m = MainParams();
    BOOST_CHECK(BondWeight(m.bondMinCapZat, 0, m.ageCap) == arith_uint256(0));
    BOOST_CHECK(BondWeight(m.bondMinCapZat, -5, m.ageCap) == arith_uint256(0));
    BOOST_CHECK(BondWeight(m.bondMinCapZat, 1, m.ageCap) == arith_uint256(m.bondMinCapZat));
    BOOST_CHECK(BondWeight(m.bondMinCapZat, 100, m.ageCap) == arith_uint256(m.bondMinCapZat) * arith_uint256(100));
    BOOST_CHECK(BondWeight(m.bondMinCapZat, m.ageCap, m.ageCap) == arith_uint256(m.bondMinCapZat) * arith_uint256(m.ageCap));
    BOOST_CHECK(BondWeight(m.bondMinCapZat, m.ageCap + 1, m.ageCap) == BondWeight(m.bondMinCapZat, m.ageCap, m.ageCap));
    BOOST_CHECK(BondWeight(m.bondMinCapZat, 1000000000LL, m.ageCap) == BondWeight(m.bondMinCapZat, m.ageCap, m.ageCap));
    // R10: 20,000 YEC at AGE_CAP is 4.1e17 -- past 2^58, so a 64-bit sum over nine slots would be at risk.
    BOOST_CHECK(BondWeight(m.bondMinCapZat, m.ageCap, m.ageCap) == arith_uint256(414720000000000000ULL));
    BOOST_CHECK(BondWeight(MAX_MONEY, m.ageCap, m.ageCap) == arith_uint256(MAX_MONEY) * arith_uint256(m.ageCap));
    BOOST_CHECK(!FitsInt64(BondWeight(MAX_MONEY, m.ageCap, m.ageCap) * arith_uint256(9)));
    // Degenerate inputs: zero, never a throw.
    BOOST_CHECK(BondWeight(0, 10, m.ageCap) == arith_uint256(0));
    BOOST_CHECK(BondWeight(-1, 10, m.ageCap) == arith_uint256(0));
    BOOST_CHECK(BondWeight(m.bondMinCapZat, 10, 0) == arith_uint256(0));
    // Regtest: 10 YEC, cap 64.
    Params r = RegtestParams(1, 0, 0, TestSet());
    BOOST_CHECK(BondWeight(r.bondMinCapZat, 100, r.ageCap) == arith_uint256(10 * COIN) * arith_uint256(64));
}

// Rule: seat ranking and eviction (owner 2026-10-11)
// Log2Q16 is exact integer log2 in Q16; SeatAgeFactorQ16 runs 1.0 .. 1.9 (65,536 .. 124,518) over SEAT_AGE_CAP.
BOOST_AUTO_TEST_CASE(seat_weight_log_tenure_factor)
{
    BOOST_CHECK_EQUAL(Log2Q16(0), 0u);
    BOOST_CHECK_EQUAL(Log2Q16(1), 0u);
    BOOST_CHECK_EQUAL(Log2Q16(2), 65536u);
    BOOST_CHECK_EQUAL(Log2Q16(1024), 10u << 16);
    BOOST_CHECK_EQUAL(Log2Q16(3), 103872u);                    // 1.58496 x 65536 = 103,872.7: truncated
    BOOST_CHECK_EQUAL(Log2Q16((uint64_t)1 << 40), 40u << 16);
    BOOST_CHECK_EQUAL(Log2Q16(UINT64_MAX), (63u << 16) | 0xFFFFu);
    for (uint64_t x = 1; x < 5000; x++) BOOST_CHECK(Log2Q16(x + 1) >= Log2Q16(x));   // monotone

    const Params& m = MainParams();
    const int64_t u = m.seatAgeUnit, cap = m.seatAgeCap;
    BOOST_CHECK_EQUAL(u, 1152);
    BOOST_CHECK_EQUAL(cap, 420480);
    BOOST_CHECK_EQUAL(SeatAgeFactorQ16(0, u, cap), 65536u);
    BOOST_CHECK_EQUAL(SeatAgeFactorQ16(-10, u, cap), 65536u);
    BOOST_CHECK_EQUAL(SeatAgeFactorQ16(cap, u, cap), 65536u + 58982u);       // floor(0.9 x 65536): x1.9
    BOOST_CHECK_EQUAL(SeatAgeFactorQ16(cap * 3, u, cap), 65536u + 58982u);   // clamped at the cap
    BOOST_CHECK_EQUAL(SeatAgeFactorQ16(1152, u, cap), 72462u);               // one day: lg 2 = 1 of lg 366
    BOOST_CHECK_EQUAL(SeatAgeFactorQ16(8064, u, cap), 86314u);               // one week: lg 8 = 3 of lg 366, x1.317
    BOOST_CHECK_EQUAL(SeatAgeFactorQ16(210240, u, cap), 117619u);            // half a year
    BOOST_CHECK_EQUAL(SeatAgeFactorQ16(100, 0, cap), 65536u);                // degenerate: 1.0
    BOOST_CHECK_EQUAL(SeatAgeFactorQ16(100, u, 0), 65536u);
    for (int64_t a = 0; a < 20000; a += 7) BOOST_CHECK(SeatAgeFactorQ16(a + 7, u, cap) >= SeatAgeFactorQ16(a, u, cap));

    // 8,000 YEC at one week weighs 10,536.4 YEC; a new 20,000 YEC bond beats 8,000 YEC at any tenure, even with the margin
    BOOST_CHECK(SeatWeight(8000 * COIN, 8064, u, cap) == arith_uint256((uint64_t)(8000 * COIN)) * arith_uint256(86314));
    BOOST_CHECK(SeatWeight(8000 * COIN, 8064, u, cap) / arith_uint256(65536) == arith_uint256((uint64_t)1053637695312ULL));
    BOOST_CHECK(SeatWeight(20000 * COIN, 0, u, cap) * arith_uint256(10000) > SeatWeight(8000 * COIN, cap, u, cap) * arith_uint256(10500));
    // 1.5x the bond beats a one-week member (by more than EVICT_MARGIN) and loses to a one-year member
    BOOST_CHECK(SeatWeight(3000 * COIN, 0, u, cap) * arith_uint256(10000) > SeatWeight(2000 * COIN, 8064, u, cap) * arith_uint256(10500));
    BOOST_CHECK(SeatWeight(3000 * COIN, 0, u, cap) < SeatWeight(2000 * COIN, cap, u, cap));
    // MAX_MONEY x 1.9 fits arith_uint256 with room (and not int64): the comparison is never truncated
    BOOST_CHECK(!FitsInt64(SeatWeight(MAX_MONEY, cap, u, cap)));
    BOOST_CHECK(SeatWeight(0, 10, u, cap) == arith_uint256(0));
    BOOST_CHECK(SeatWeight(-1, 10, u, cap) == arith_uint256(0));
    // regtest carries the mainnet values (only the bonds are scaled)
    Params r = RegtestParams(1, 0, 0, TestSet());
    BOOST_CHECK_EQUAL(r.seatAgeUnit, 1152);
    BOOST_CHECK_EQUAL(r.seatAgeCap, 420480);
    BOOST_CHECK_EQUAL(r.seatMarginBps, 500);
    BOOST_CHECK_EQUAL(r.evictMarginBps, 500);
    BOOST_CHECK_EQUAL(r.attestorSeats, 15);
    BOOST_CHECK_EQUAL(r.attestorLivenessMin, 16);                        // seats review B3 at regtest scale
    BOOST_CHECK_EQUAL(TestParams().attestorLivenessMin, 1152);           // one day
}

// Rule: PRICE-2
// Rule: BUNDLE-1
// The bundle statistic: the price at which cumulative weight first reaches
// ceil(q * total / 10^4), over the price-ascending order.
BOOST_AUTO_TEST_CASE(price2_weighted_quantile_thresholds)
{
    const Params& m = MainParams();
    const arith_uint256 W(1000);
    // Single entry: both quantiles are its price.
    BOOST_CHECK_EQUAL(WeightedQuantile({ WeightedPrice(50000, W) }, m.qLowBps).value(), 50000);
    BOOST_CHECK_EQUAL(WeightedQuantile({ WeightedPrice(50000, W) }, m.qHighBps).value(), 50000);
    BOOST_CHECK_EQUAL(WeightedQuantile({ WeightedPrice(50000, W) }, 0).value(), 50000);
    BOOST_CHECK_EQUAL(WeightedQuantile({ WeightedPrice(50000, W) }, 10000).value(), 50000);
    // Empty: undefined. Over 10^4: the threshold exceeds the total, undefined.
    BOOST_CHECK(!WeightedQuantile({}, m.qLowBps).has_value());
    BOOST_CHECK(!WeightedQuantile({ WeightedPrice(50000, W) }, 10001).has_value());
    // Equal weights, four prices: total 4000; low threshold ceil(3333*4000/1e4) = 1334 -> the 2nd; high ceil(2666.8) = 2667 -> the 3rd.
    std::vector<WeightedPrice> four = { WeightedPrice(10, W), WeightedPrice(20, W), WeightedPrice(30, W), WeightedPrice(40, W) };
    BOOST_CHECK_EQUAL(WeightedQuantile(four, m.qLowBps).value(), 20);
    BOOST_CHECK_EQUAL(WeightedQuantile(four, m.qHighBps).value(), 30);
    // Unsorted input is put into price order first (the caller's tie order is kept).
    std::vector<WeightedPrice> shuffled = { WeightedPrice(40, W), WeightedPrice(10, W), WeightedPrice(30, W), WeightedPrice(20, W) };
    BOOST_CHECK_EQUAL(WeightedQuantile(shuffled, m.qLowBps).value(), 20);
    BOOST_CHECK_EQUAL(WeightedQuantile(shuffled, m.qHighBps).value(), 30);
    // Exact threshold: three equal weights, q = 3333 -> ceil(0.9999) = 1 -> the first; q = 3334 -> ceil(1.0002) = 2 -> the second.
    std::vector<WeightedPrice> three = { WeightedPrice(10, arith_uint256(1)), WeightedPrice(20, arith_uint256(1)), WeightedPrice(30, arith_uint256(1)) };
    BOOST_CHECK_EQUAL(WeightedQuantile(three, 3333).value(), 10);
    BOOST_CHECK_EQUAL(WeightedQuantile(three, 3334).value(), 20);
    BOOST_CHECK_EQUAL(WeightedQuantile(three, 6666).value(), 20);
    BOOST_CHECK_EQUAL(WeightedQuantile(three, 6667).value(), 30);
    BOOST_CHECK_EQUAL(WeightedQuantile(three, 10000).value(), 30);
    // Cumulative weight exactly equal to the threshold counts ("first >="): weights 1, 1 at q = 5000 -> threshold 1 -> the first.
    std::vector<WeightedPrice> two = { WeightedPrice(10, arith_uint256(1)), WeightedPrice(20, arith_uint256(1)) };
    BOOST_CHECK_EQUAL(WeightedQuantile(two, 5000).value(), 10);
    BOOST_CHECK_EQUAL(WeightedQuantile(two, 5001).value(), 20);
    // Weights 3, 1 with q = 7500: threshold exactly 3 -> the first; 7501 -> ceil(3.0004) = 4 -> the second.
    std::vector<WeightedPrice> heavyLow = { WeightedPrice(10, arith_uint256(3)), WeightedPrice(20, arith_uint256(1)) };
    BOOST_CHECK_EQUAL(WeightedQuantile(heavyLow, 7500).value(), 10);
    BOOST_CHECK_EQUAL(WeightedQuantile(heavyLow, 7501).value(), 20);
    // A dominant weight pulls both quantiles to its price.
    std::vector<WeightedPrice> whale = { WeightedPrice(10, arith_uint256(1)), WeightedPrice(20, arith_uint256(100)), WeightedPrice(30, arith_uint256(1)) };
    BOOST_CHECK_EQUAL(WeightedQuantile(whale, m.qLowBps).value(), 20);
    BOOST_CHECK_EQUAL(WeightedQuantile(whale, m.qHighBps).value(), 20);
    // Ties in price: the answer is the price, whichever tied entry crosses the threshold.
    std::vector<WeightedPrice> tied = { WeightedPrice(10, W), WeightedPrice(20, W), WeightedPrice(20, W), WeightedPrice(20, W), WeightedPrice(30, W) };
    BOOST_CHECK_EQUAL(WeightedQuantile(tied, m.qLowBps).value(), 20);
    BOOST_CHECK_EQUAL(WeightedQuantile(tied, m.qHighBps).value(), 20);
    BOOST_CHECK_EQUAL(WeightedQuantile(tied, 2000).value(), 10);      // threshold 1000: the first alone
    BOOST_CHECK_EQUAL(WeightedQuantile(tied, 8001).value(), 30);      // threshold 4001: past the three 20s
    // Zero-weight entries never move the cumulative sum; a zero total gives the first price (threshold 0).
    std::vector<WeightedPrice> zeros = { WeightedPrice(10, arith_uint256(0)), WeightedPrice(20, arith_uint256(1)) };
    BOOST_CHECK_EQUAL(WeightedQuantile(zeros, m.qLowBps).value(), 20);
    std::vector<WeightedPrice> allZero = { WeightedPrice(30, arith_uint256(0)), WeightedPrice(10, arith_uint256(0)) };
    BOOST_CHECK_EQUAL(WeightedQuantile(allZero, m.qLowBps).value(), 10);
    // 256-bit weights (R10): six bonds at AGE_CAP, no overflow in total * qBps.
    std::vector<WeightedPrice> big;
    for (int i = 0; i < 6; i++) big.push_back(WeightedPrice(10 * (i + 1), BondWeight(MAX_MONEY, m.ageCap, m.ageCap)));
    BOOST_CHECK_EQUAL(WeightedQuantile(big, m.qLowBps).value(), 20);   // ceil(3333*6/1e4) = 2 -> the 2nd
    BOOST_CHECK_EQUAL(WeightedQuantile(big, m.qHighBps).value(), 50);  // ceil(6667*6/1e4) = 5 -> the 5th
    // Negative q is read as 0.
    BOOST_CHECK_EQUAL(WeightedQuantile(four, -1).value(), 10);
}

// Rule: RED-5
// claimantMaxZat = ceil(mintedCents * marginBps * COIN / pClaim); residual = max(0, collateral - that).
BOOST_AUTO_TEST_CASE(red5_claimant_max_and_residual_worked_example)
{
    const Params& m = MainParams();
    // §3.7 check at theta 125 % (D-IT-2): $100 and 18,333 uUSD => 1.25e16 / 18,333 = 681,830,578,737.8.. => 681,830,578,738 zat ~ 6,818 YEC.
    BOOST_CHECK_EQUAL(m.claimThresholdBps, 12500);
    auto c = ClaimantMaxZat(10000, m.claimThresholdBps, 18333);
    BOOST_REQUIRE(c.has_value());
    BOOST_CHECK_EQUAL(c.value(), 681830578738LL);
    BOOST_CHECK_EQUAL(c.value() / COIN, 6818);
    // The v2 worked example at 110 %: 1.1e16 / 18,333 = 600,010,909,289.6.. => 600,010,909,290 zat ~ 6,000 YEC.
    BOOST_CHECK_EQUAL(ClaimantMaxZat(10000, 11000, 18333).value(), 600010909290LL);
    // Clause (b): margin 10^4, exactly the debt at the adverse price (R1).
    c = ClaimantMaxZat(10000, 10000, 18333);
    BOOST_REQUIRE(c.has_value());
    BOOST_CHECK_EQUAL(c.value(), 545464462991LL);
    // A vault at exactly the 125 % threshold: collateral * pClaim == minted * 12,500 * COIN, so the claimant takes it all, residual 0.
    // $100 minted, pClaim 20,000 uUSD: threshold collateral = 1e4 * 12,500 * 1e8 / 20,000 = 6.25e11 zat (6,250 YEC) exactly.
    const CAmount atThreshold = 625000000000LL;
    BOOST_CHECK(!IsUnderwater(atThreshold, 20000, 10000, m.claimThresholdBps));   // RED-4(a): strictly below, so not (yet) claimable
    BOOST_CHECK(IsUnderwater(atThreshold - 1, 20000, 10000, m.claimThresholdBps));
    c = ClaimantMaxZat(10000, m.claimThresholdBps, 20000);
    BOOST_REQUIRE(c.has_value());
    BOOST_CHECK_EQUAL(c.value(), atThreshold);
    BOOST_CHECK_EQUAL(ResidualZat(atThreshold, c), 0);
    BOOST_CHECK_EQUAL(ResidualZat(atThreshold - 1, c), 0);          // underwater by a zat: still nothing back
    BOOST_CHECK_EQUAL(ResidualZat(atThreshold + 1, c), 1);
    BOOST_CHECK_EQUAL(ResidualZat(atThreshold + m.residualMinZat, c), m.residualMinZat);
    // The worked vault (6,000 YEC) claimed at 18,333: the 125 % share (6,818 YEC) exceeds the collateral => 0.
    BOOST_CHECK_EQUAL(ResidualZat(600000000000LL, ClaimantMaxZat(10000, m.claimThresholdBps, 18333)), 0);
    // Claimed at a price above the threshold price (say 30,000 uUSD, a forced early liquidation under (b) only, margin 10^4):
    // claimant max = 1e4 * 1e4 * 1e8 / 30,000 = 333,333,333,334 zat; residual = 6e11 - that.
    c = ClaimantMaxZat(10000, 10000, 30000);
    BOOST_REQUIRE(c.has_value());
    BOOST_CHECK_EQUAL(c.value(), 333333333334LL);
    BOOST_CHECK_EQUAL(ResidualZat(600000000000LL, c), 266666666666LL);
    // Ceiling, not floor: $1 at 110 % and 70,000 uUSD = 1,571,428,571.4.. => 1,571,428,572.
    BOOST_CHECK_EQUAL(ClaimantMaxZat(100, 11000, 70000).value(), 1571428572LL);
    // Undefined inputs.
    BOOST_CHECK(!ClaimantMaxZat(0, 11000, 18333).has_value());
    BOOST_CHECK(!ClaimantMaxZat(10000, 0, 18333).has_value());
    BOOST_CHECK(!ClaimantMaxZat(10000, 11000, 0).has_value());
    BOOST_CHECK(!ClaimantMaxZat(-1, 11000, 18333).has_value());
    // Undefined claimant max (pClaim undefined or the overflow below) => residual 0, never a throw.
    BOOST_CHECK_EQUAL(ResidualZat(600000000000LL, std::nullopt), 0);
    BOOST_CHECK_EQUAL(ResidualZat(0, ClaimantMaxZat(10000, 11000, 18333)), 0);
    BOOST_CHECK_EQUAL(ResidualZat(-5, ClaimantMaxZat(10000, 11000, 18333)), 0);
}

// Rule: RED-5
// Overflow at PRICE_MIN: MAX_MINT ($100,000, D-Q-24) * 12,500 * COIN / 100 = 1.25e17 zat > MAX_MONEY => nullopt (residual 0), never a wrapped number.
BOOST_AUTO_TEST_CASE(red5_claimant_max_overflow_at_price_min)
{
    const Params& m = MainParams();
    BOOST_CHECK(!ClaimantMaxZat(m.maxMint, m.claimThresholdBps, PRICE_MIN).has_value());
    BOOST_CHECK(!ClaimantMaxZat(m.maxMint, 10000, PRICE_MIN).has_value());
    BOOST_CHECK_EQUAL(ResidualZat(MAX_MONEY, ClaimantMaxZat(m.maxMint, m.claimThresholdBps, PRICE_MIN)), 0);
    // The minimum mint at PRICE_MIN still fits: 1e4 * 12,500 * 1e8 / 100 = 1.25e14 zat = 1,250,000 YEC < MAX_MONEY.
    auto c = ClaimantMaxZat(m.minMint, m.claimThresholdBps, PRICE_MIN);
    BOOST_REQUIRE(c.has_value());
    BOOST_CHECK_EQUAL(c.value(), 125000000000000LL);
    // Exactly MAX_MONEY is representable; one zat more is not. margin 10^4 at $100: cents * 1e4 zat => MAX_MONEY at 2.1e11 cents.
    BOOST_CHECK_EQUAL(ClaimantMaxZat(210000000000LL, 10000, 100000000).value(), MAX_MONEY);
    BOOST_CHECK(!ClaimantMaxZat(210000000001LL, 10000, 100000000).has_value());
    // The product itself passes int64 before the division (1e6 * 11,000 * 1e8 = 1.1e18 fits; 1e7 cents would not): still exact.
    BOOST_CHECK_EQUAL(ClaimantMaxZat(m.maxOutput, m.claimThresholdBps, 100000000).value(), 125000000000LL);   // $100,000 at 125 % / $100 per YEC = 1,250 YEC
    // D-Q-22, at PRICE_MAX: the same boundary moves to 9,019,431,319,500 cents; $100,000 at 125 % is 29.10383047 YEC.
    BOOST_CHECK_EQUAL(ClaimantMaxZat(9019431319500LL, 10000, PRICE_MAX).value(), MAX_MONEY);
    BOOST_CHECK(!ClaimantMaxZat(9019431319501LL, 10000, PRICE_MAX).has_value());
    BOOST_CHECK_EQUAL(ClaimantMaxZat(m.maxOutput, m.claimThresholdBps, PRICE_MAX).value(), 2910383047LL);
}

// Rule: RED-5'
// D-Q-23a: the residual threshold is $0.48 at the vault's mint price, never below RESIDUAL_MIN_ZAT.
BOOST_AUTO_TEST_CASE(red5_residual_threshold_in_dollars)
{
    const Params& m = MainParams();
    BOOST_CHECK_EQUAL(m.residualMinCents, 48);
    BOOST_CHECK_EQUAL(m.residualMinZat, 100000);
    BOOST_CHECK_EQUAL(ResidualMinZat(18000, m), 2666666667LL);                   // $0.48 at $0.018 = 26.67 YEC (ceil)
    BOOST_CHECK_EQUAL(ResidualMinZat(50000, m), 960000000LL);                    // 9.6 YEC at $0.05
    BOOST_CHECK_EQUAL(ResidualMinZat(PRICE_MAX, m), m.residualMinZat);           // $0.48 at $4,294.97 = 11,176 zat < the floor: the floor binds
    BOOST_CHECK_EQUAL(ResidualMinZat(480000000, m), 100000);                     // exactly $0.48 x 10^12 / 4.8e8 = the floor
    BOOST_CHECK_EQUAL(ResidualMinZat(479999999, m), 100001);                     // one µUSD below: ceil, above the floor
    BOOST_CHECK_EQUAL(ResidualMinZat(0, m), m.residualMinZat);                   // no price: the floor
    BOOST_CHECK_EQUAL(ResidualMinZat(PRICE_MIN, m), 480000000000LL);             // 4,800 YEC at $0.0001, in MoneyRange
    Params t = m;
    t.residualMinCents = 0;
    BOOST_CHECK_EQUAL(ResidualMinZat(18000, t), m.residualMinZat);
}

// Rule: MINT-6b
// D-Q-23a: one mint's debt <= max(maxVaultShareBps of the MINT-6 cap, vaultShareFloorCents); no cap, no bound.
BOOST_AUTO_TEST_CASE(mint6b_max_vault_cents)
{
    const Params& m = MainParams();
    BOOST_CHECK_EQUAL(m.maxVaultShareBps, 1000);
    BOOST_CHECK_EQUAL(m.vaultShareFloorCents, 1000000);
    BOOST_CHECK(!MaxVaultCents(std::nullopt, m.maxVaultShareBps, m.vaultShareFloorCents).has_value());
    BOOST_CHECK(!MaxVaultCents(100000000, 0, m.vaultShareFloorCents).has_value());
    BOOST_CHECK_EQUAL(MaxVaultCents(100000000, m.maxVaultShareBps, m.vaultShareFloorCents).value(), 10000000);     // 10 % of a $1 M cap
    BOOST_CHECK_EQUAL(MaxVaultCents(5000000, m.maxVaultShareBps, m.vaultShareFloorCents).value(), 1000000);        // the $10,000 floor
    BOOST_CHECK_EQUAL(MaxVaultCents(10000000, m.maxVaultShareBps, m.vaultShareFloorCents).value(), 1000000);       // exactly at the floor
    BOOST_CHECK_EQUAL(MaxVaultCents(10000010, m.maxVaultShareBps, m.vaultShareFloorCents).value(), 1000001);
    BOOST_CHECK_EQUAL(MaxVaultCents(0, m.maxVaultShareBps, m.vaultShareFloorCents).value(), 1000000);
    // the largest cap that fits int64 (MAX_MONEY x PRICE_MAX / (COIN x 10^4)) stays in range
    BOOST_CHECK_EQUAL(MaxVaultCents(CapCents(MAX_MONEY, PRICE_MAX).value(), m.maxVaultShareBps, m.vaultShareFloorCents).value(), 901943131950LL);
}

// Rule: AFEE-1
// attestFeeZat = feeZat * ATTEST_FEE_BPS / 10^4 (floor), out of FEE-1's fee.
BOOST_AUTO_TEST_CASE(afee1_attestor_fee_is_half_of_the_pool_fee)
{
    const Params& m = MainParams();
    // The worked vault ($100 at $0.05, 5,000 bps): the $1 floor = 20 YEC to the pool and 10 YEC to the attestor.
    const CAmount fee = ProtocolFeeZat(10000, 50000, m).value();
    BOOST_CHECK_EQUAL(fee, 20 * COIN);
    BOOST_CHECK_EQUAL(AttestFeeZat(fee, m.attestFeeBps), 10 * COIN);
    // $10,000 at $0.018: $55 = 305,555,555,556 zat => half, floored.
    BOOST_CHECK_EQUAL(AttestFeeZat(ProtocolFeeZat(1000000, 18000, m).value(), m.attestFeeBps), 152777777778LL);
    // Floor.
    BOOST_CHECK_EQUAL(AttestFeeZat(1, m.attestFeeBps), 0);
    BOOST_CHECK_EQUAL(AttestFeeZat(3, m.attestFeeBps), 1);
    BOOST_CHECK_EQUAL(AttestFeeZat(7, m.attestFeeBps), 3);
    // The regtest column keeps D-3's quarter: 15 YEC => 3.75 YEC, 7 zat => 1.
    BOOST_CHECK_EQUAL(AttestFeeZat(15 * COIN, RegtestParams(1, 0, 0, TestSet()).attestFeeBps), 375000000);
    BOOST_CHECK_EQUAL(AttestFeeZat(7, RegtestParams(1, 0, 0, TestSet()).attestFeeBps), 1);
    // Degenerate: zero or negative inputs give 0; 10^4 bps is the whole fee; MAX_MONEY does not overflow.
    BOOST_CHECK_EQUAL(AttestFeeZat(0, m.attestFeeBps), 0);
    BOOST_CHECK_EQUAL(AttestFeeZat(-1, m.attestFeeBps), 0);
    BOOST_CHECK_EQUAL(AttestFeeZat(fee, 0), 0);
    BOOST_CHECK_EQUAL(AttestFeeZat(fee, 10000), fee);
    BOOST_CHECK_EQUAL(AttestFeeZat(MAX_MONEY, m.attestFeeBps), MAX_MONEY / 2);
    BOOST_CHECK_EQUAL(AttestFeeZat(MAX_MONEY, 10000), MAX_MONEY);
}

// Rule: PRICE-2
// pMint = min(xMint, aMint), pClaim = max(xClaim, aClaim), pEmerg = min(xClaim, aClaim); each undefined if any input is.
BOOST_AUTO_TEST_CASE(price2_combine_takes_the_conservative_side)
{
    CombinedPrices c = PriceCombine(50000, 52000, 48000, 55000);
    BOOST_CHECK_EQUAL(c.pMint.value(), 48000);
    BOOST_CHECK_EQUAL(c.pClaim.value(), 55000);
    BOOST_CHECK_EQUAL(c.pEmerg.value(), 52000);
    // The other way round.
    c = PriceCombine(48000, 55000, 50000, 52000);
    BOOST_CHECK_EQUAL(c.pMint.value(), 48000);
    BOOST_CHECK_EQUAL(c.pClaim.value(), 55000);
    BOOST_CHECK_EQUAL(c.pEmerg.value(), 52000);
    // Equal inputs.
    c = PriceCombine(50000, 50000, 50000, 50000);
    BOOST_CHECK_EQUAL(c.pMint.value(), 50000);
    BOOST_CHECK_EQUAL(c.pClaim.value(), 50000);
    BOOST_CHECK_EQUAL(c.pEmerg.value(), 50000);
    // Each input undefined in turn: only the outputs that read it become undefined.
    c = PriceCombine(std::nullopt, 52000, 48000, 55000);
    BOOST_CHECK(!c.pMint.has_value());
    BOOST_CHECK_EQUAL(c.pClaim.value(), 55000);
    BOOST_CHECK_EQUAL(c.pEmerg.value(), 52000);
    c = PriceCombine(50000, std::nullopt, 48000, 55000);
    BOOST_CHECK_EQUAL(c.pMint.value(), 48000);
    BOOST_CHECK(!c.pClaim.has_value());
    BOOST_CHECK(!c.pEmerg.has_value());
    c = PriceCombine(50000, 52000, std::nullopt, 55000);
    BOOST_CHECK(!c.pMint.has_value());
    BOOST_CHECK_EQUAL(c.pClaim.value(), 55000);
    BOOST_CHECK_EQUAL(c.pEmerg.value(), 52000);
    c = PriceCombine(50000, 52000, 48000, std::nullopt);
    BOOST_CHECK_EQUAL(c.pMint.value(), 48000);
    BOOST_CHECK(!c.pClaim.has_value());
    BOOST_CHECK(!c.pEmerg.has_value());
    c = PriceCombine(std::nullopt, std::nullopt, std::nullopt, std::nullopt);
    BOOST_CHECK(!c.pMint.has_value());
    BOOST_CHECK(!c.pClaim.has_value());
    BOOST_CHECK(!c.pEmerg.has_value());
    BOOST_CHECK(!CombinedPrices().pMint.has_value());
    // The bounds survive: PRICE_MIN and PRICE_MAX on either side.
    c = PriceCombine(PRICE_MIN, PRICE_MAX, PRICE_MAX, PRICE_MIN);
    BOOST_CHECK_EQUAL(c.pMint.value(), PRICE_MIN);
    BOOST_CHECK_EQUAL(c.pClaim.value(), PRICE_MAX);
    BOOST_CHECK_EQUAL(c.pEmerg.value(), PRICE_MIN);
    // D-Q-22: SIGMA-1 across the whole range (r = (PRICE_MAX - PRICE_MIN) * 1e4 / PRICE_MIN = 4.29e11, squared in
    // arith_uint256) gives the cap, never a wrapped value; HALT-3's int64 products stay below 4.3e13.
    BOOST_CHECK_EQUAL(SigmaMultBps({ PRICE_MAX, PRICE_MIN, PRICE_MAX }, 10000, 1152, 30000), 30000);
    BOOST_CHECK_EQUAL(SigmaMultBps({ PRICE_MAX, PRICE_MAX }, 10000, 1152, 30000), 10000);
}

BOOST_AUTO_TEST_SUITE_END()
