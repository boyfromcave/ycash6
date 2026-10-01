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

#include <boost/test/unit_test.hpp>

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
BOOST_AUTO_TEST_CASE(sigma1_flat_series_and_worked_example)
{
    const Params& m = MainParams();
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
    // SIGMA_REF_BPS == 0 (regtest default) fixes the multiplier whatever the series.
    BOOST_CHECK_EQUAL(SigmaMultBps(wild, 0, m.volPeriodsPerYear, m.sigmaMultMaxBps), 10000);
    BOOST_CHECK_EQUAL(SigmaMultBps({}, 0, m.volPeriodsPerYear, m.sigmaMultMaxBps), 10000);
}

// Rule: SIGMA-1
// The V17 regression: quotes from different pools alternate +-2 % around a
// flat price. On the raw per-block series the formula reads that as ~3.7x
// volatility (capped at 3x); on the P_fast series (rolling lower medians)
// it is exactly 1x, which is why V17 samples P_fast.
BOOST_AUTO_TEST_CASE(sigma1_cross_pool_noise_is_not_volatility)
{
    const Params& m = MainParams();
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
    const Params& m = MainParams();
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
// K14: class A at the 3x cap is 150,000 bps; MAX_MINT * 150,000 * COIN = 1.5e19
// exceeds int64 before the division, and at PRICE_MIN the quotient (1.5e17 zat)
// exceeds MAX_MONEY: "unsatisfiable", never a wrapped number.
BOOST_AUTO_TEST_CASE(mint5_required_collateral_overflow_at_max_mint_and_price_min)
{
    const Params& m = MainParams();
    const int worst = MinRatioBps(m.baseRatioBps[0], m.sigmaMultMaxBps);
    BOOST_CHECK_EQUAL(worst, 150000);
    BOOST_CHECK(!RequiredCollateral(m.maxMint, worst, PRICE_MIN).has_value());
    BOOST_CHECK(!RequiredCollateralRounded(m.maxMint, worst, PRICE_MIN).has_value());
    // At $0.05 the same mint needs 3e14 zat = 3,000,000 YEC: satisfiable (< MAX_MONEY).
    auto r = RequiredCollateral(m.maxMint, worst, 50000);
    BOOST_REQUIRE(r.has_value());
    BOOST_CHECK_EQUAL(r.value(), 300000000000000LL);
    // Exactly MAX_MONEY is satisfiable; one zat above is not.
    // ratio 10,000 bps at PRICE_MAX ($100/YEC): required = cents * 1e4 zat => MAX_MONEY at cents = 2.1e11.
    BOOST_CHECK_EQUAL(RequiredCollateral(210000000000LL, 10000, PRICE_MAX).value(), MAX_MONEY);
    BOOST_CHECK(!RequiredCollateral(210000000001LL, 10000, PRICE_MAX).has_value());
    // MAX_OUTPUT-sized amounts at PRICE_MAX are tiny and fine.
    r = RequiredCollateral(m.maxOutput, 30000, PRICE_MAX);
    BOOST_REQUIRE(r.has_value());
    BOOST_CHECK_EQUAL(r.value(), 3000 * COIN);   // $100,000 * 300 % / $100 per YEC = 3,000 YEC
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
    // Full issuance at PRICE_MAX: 2.1e7 YEC * $100 = $2.1e9 = 2.1e11 cents, no overflow.
    BOOST_CHECK_EQUAL(CapCents(MAX_MONEY, PRICE_MAX).value(), 210000000000LL);
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
    // Everything at the top: MAX_MONEY collateral at PRICE_MAX backing one cent.
    BOOST_CHECK_EQUAL(GlobalRatioBps(MAX_MONEY, PRICE_MAX, 1).value(), 2100000000000000LL);
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
}

// Rule: FEE-1
BOOST_AUTO_TEST_CASE(fee1_min_dominates_small_vault)
{
    const Params& m = MainParams();
    // 25 bps of 200 YEC is exactly FEE_MIN; below 200 YEC the minimum applies.
    BOOST_CHECK_EQUAL(FeeZat(199 * COIN, m.feeMin, m.feeBps), m.feeMin);
    BOOST_CHECK_EQUAL(FeeZat(200 * COIN, m.feeMin, m.feeBps), m.feeMin);
    BOOST_CHECK_EQUAL(FeeZat(200 * COIN - 1, m.feeMin, m.feeBps), m.feeMin);
    BOOST_CHECK_EQUAL(FeeZat(201 * COIN, m.feeMin, m.feeBps), 50250000);
    BOOST_CHECK_EQUAL(FeeZat(1, m.feeMin, m.feeBps), m.feeMin);
    BOOST_CHECK_EQUAL(FeeZat(0, m.feeMin, m.feeBps), m.feeMin);
    // 6,000 YEC (the worked vault) pays 15 YEC.
    BOOST_CHECK_EQUAL(FeeZat(6000 * COIN, m.feeMin, m.feeBps), 15 * COIN);
}

// Rule: FEE-1
BOOST_AUTO_TEST_CASE(fee1_at_max_money)
{
    const Params& m = MainParams();
    BOOST_CHECK_EQUAL(FeeZat(MAX_MONEY, m.feeMin, m.feeBps), 5250000000000LL);   // 52,500 YEC, no overflow
    BOOST_CHECK(MoneyRange(FeeZat(MAX_MONEY, m.feeMin, m.feeBps)));
    BOOST_CHECK_EQUAL(FeeZat(MAX_MONEY, m.feeMin, 10000), MAX_MONEY);
}

// Rule: MINT-2
BOOST_AUTO_TEST_CASE(mint2_term_classes_are_contiguous_and_disjoint)
{
    const Params& m = MainParams();
    BOOST_CHECK_EQUAL(m.ClassForLockBlocks(34559), -1);
    BOOST_CHECK_EQUAL(m.ClassForLockBlocks(34560), 0);
    BOOST_CHECK_EQUAL(m.ClassForLockBlocks(103680), 0);
    BOOST_CHECK_EQUAL(m.ClassForLockBlocks(103681), 1);
    BOOST_CHECK_EQUAL(m.ClassForLockBlocks(420480), 1);
    BOOST_CHECK_EQUAL(m.ClassForLockBlocks(420481), 2);
    BOOST_CHECK_EQUAL(m.ClassForLockBlocks(2102400), 2);
    BOOST_CHECK_EQUAL(m.ClassForLockBlocks(2102401), -1);
    BOOST_CHECK_EQUAL(m.ClassForLockBlocks(0), -1);
    BOOST_CHECK_EQUAL(m.ClassForLockBlocks(-5), -1);
    for (int i = 1; i < NUM_CLASSES; i++) BOOST_CHECK_EQUAL(m.classMin[i], m.classMax[i - 1] + 1);
    BOOST_CHECK_EQUAL(m.baseRatioBps[0], 50000);
    BOOST_CHECK_EQUAL(m.baseRatioBps[1], 40000);
    BOOST_CHECK_EQUAL(m.baseRatioBps[2], 30000);
    BOOST_CHECK_EQUAL(m.classMax[2], 5 * BLOCKS_PER_YEAR);   // MAX_LOCK = 5 y (V19)
    Params r = RegtestParams(10, 0, 0, 0);
    BOOST_CHECK_EQUAL(r.ClassForLockBlocks(48), 0);
    BOOST_CHECK_EQUAL(r.ClassForLockBlocks(96), 0);
    BOOST_CHECK_EQUAL(r.ClassForLockBlocks(97), 1);
    BOOST_CHECK_EQUAL(r.ClassForLockBlocks(144), 1);
    BOOST_CHECK_EQUAL(r.ClassForLockBlocks(145), 2);
    BOOST_CHECK_EQUAL(r.ClassForLockBlocks(240), 2);
    BOOST_CHECK_EQUAL(r.ClassForLockBlocks(241), -1);
}

// Rule: ACT-5
// The §3.1 table, both columns; the four regtest flags land where the plan says.
BOOST_AUTO_TEST_CASE(act5_params_tables)
{
    const Params& m = MainParams();
    BOOST_CHECK_EQUAL(m.network, "main");
    BOOST_CHECK(!m.IsConfigured());   // startHeight is set per release
    BOOST_CHECK_EQUAL(m.pFastWindow, 96);   BOOST_CHECK_EQUAL(m.pFastMinFill, 48);
    BOOST_CHECK_EQUAL(m.pMidWindow, 576);   BOOST_CHECK_EQUAL(m.pMidMinFill, 384);
    BOOST_CHECK_EQUAL(m.pSlowWindow, 2016); BOOST_CHECK_EQUAL(m.pSlowMinFill, 1344);
    BOOST_CHECK_EQUAL(m.signalWindow, 2016);
    BOOST_CHECK_EQUAL(m.activationThreshold, 1512);
    BOOST_CHECK_EQUAL(m.participationFloor, 1210);
    BOOST_CHECK_EQUAL(m.activationDelay, 2016);
    BOOST_CHECK_EQUAL(m.enforcementFloor, 1008);
    BOOST_CHECK_EQUAL(m.enforcementResume, 1210);
    BOOST_CHECK_EQUAL(m.valveBlocks, 6);
    BOOST_CHECK_EQUAL(m.abandonBlocks, 2 * m.signalWindow);
    BOOST_CHECK_EQUAL(m.nReg, 576);
    BOOST_CHECK_EQUAL(m.nPenalty, 288);
    BOOST_CHECK_EQUAL(m.peerLag, 10);
    BOOST_CHECK_EQUAL(m.peerMin, 5);
    BOOST_CHECK_EQUAL(m.deviationBps, 1000);
    BOOST_CHECK_EQUAL(m.accuracyBandBps, 300);
    BOOST_CHECK_EQUAL(m.accuracyWindow, 576);
    BOOST_CHECK_EQUAL(m.payeeTiltBps, 10000);
    BOOST_CHECK_EQUAL(m.payeeWindow, 100);
    BOOST_CHECK_EQUAL(m.feeMin, 50000000);
    BOOST_CHECK_EQUAL(m.feeBps, 25);
    BOOST_CHECK_EQUAL(m.grace, 34560);
    BOOST_CHECK_EQUAL(m.claimThresholdBps, 11000);
    BOOST_CHECK_EQUAL(m.supplyCapBps, 1500);
    BOOST_CHECK_EQUAL(m.globalRatioHaltBps, 25000);
    BOOST_CHECK_EQUAL(m.divergenceBps, 2000);
    BOOST_CHECK_EQUAL(m.volWindow, 2016);
    BOOST_CHECK_EQUAL(m.volStep, 48);
    BOOST_CHECK_EQUAL(m.volPeriodsPerYear, 8760);
    BOOST_CHECK_EQUAL(m.sigmaRefBps, 10000);
    BOOST_CHECK_EQUAL(m.sigmaMultMaxBps, 30000);
    BOOST_CHECK_EQUAL(m.minMint, 10000);
    BOOST_CHECK_EQUAL(m.maxMint, 1000000);
    BOOST_CHECK_EQUAL(m.minOutput, 100);
    BOOST_CHECK_EQUAL(m.maxOutput, 10000000);
    BOOST_CHECK_EQUAL(m.tokenValue, TOKEN_VALUE);
    BOOST_CHECK_EQUAL(m.refWindow, REF_WINDOW);
    BOOST_CHECK_EQUAL(m.enforceUntilHeight, 0);
    BOOST_CHECK_EQUAL(m.volWindow / m.volStep, 42);   // 43 samples, 42 returns
    BOOST_CHECK_EQUAL(TestParams().network, "test");
    BOOST_CHECK_EQUAL(TestParams().grace, 34560);

    Params r = RegtestParams(150, 12345, 700, 9000);
    BOOST_CHECK_EQUAL(r.network, "regtest");
    BOOST_CHECK(r.IsConfigured());
    BOOST_CHECK_EQUAL(r.startHeight, 150);
    BOOST_CHECK_EQUAL(r.sigmaRefBps, 12345);
    BOOST_CHECK_EQUAL(r.supplyCapBps, 700);
    BOOST_CHECK_EQUAL(r.enforceUntilHeight, 9000);
    BOOST_CHECK_EQUAL(r.pFastWindow, 8);   BOOST_CHECK_EQUAL(r.pFastMinFill, 4);
    BOOST_CHECK_EQUAL(r.pMidWindow, 24);   BOOST_CHECK_EQUAL(r.pMidMinFill, 16);
    BOOST_CHECK_EQUAL(r.pSlowWindow, 64);  BOOST_CHECK_EQUAL(r.pSlowMinFill, 43);
    BOOST_CHECK_EQUAL(r.signalWindow, 64);
    BOOST_CHECK_EQUAL(r.activationThreshold, 48);
    BOOST_CHECK_EQUAL(r.participationFloor, 39);
    BOOST_CHECK_EQUAL(r.activationDelay, 64);
    BOOST_CHECK_EQUAL(r.enforcementFloor, 32);
    BOOST_CHECK_EQUAL(r.enforcementResume, 39);
    BOOST_CHECK_EQUAL(r.valveBlocks, 6);
    BOOST_CHECK_EQUAL(r.abandonBlocks, 128);
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
    BOOST_CHECK_EQUAL(r.feeMin, m.feeMin);
    BOOST_CHECK_EQUAL(r.claimThresholdBps, m.claimThresholdBps);
    BOOST_CHECK(!RegtestParams(0, 0, 0, 0).IsConfigured());
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
    BOOST_CHECK_EQUAL(m.attestArmMin, 5);
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
    BOOST_CHECK_EQUAL(m.attestFeeBps, 2500);
    BOOST_CHECK_EQUAL(m.bondMin, 20000 * COIN);
    BOOST_CHECK_EQUAL(m.bondMinLock, 420480);
    BOOST_CHECK_EQUAL(m.bondMinLock, BLOCKS_PER_YEAR);
    BOOST_CHECK_EQUAL(m.bondMaturity, 16128);
    BOOST_CHECK_EQUAL(m.ageCap, 207360);
    BOOST_CHECK_EQUAL(m.foundingWindow, 8064);
    BOOST_CHECK_EQUAL(m.dormancyBlocks, 16128);
    BOOST_CHECK_EQUAL(m.dormancyMinBundles, 20);
    BOOST_CHECK_EQUAL(m.dormancyCheck, 48);
    BOOST_CHECK_EQUAL(m.carrierValue, 10000);
    BOOST_CHECK_EQUAL(m.attestInterval, 10);
    BOOST_CHECK_EQUAL(m.walletConfirmations, 6);
    BOOST_CHECK_EQUAL(TestParams().attestArmMin, 5);
    BOOST_CHECK_EQUAL(TestParams().bondMin, 20000 * COIN);
    // "ARMED" means both the snapshot status and ATTEST_REQUIRED (W15).
    BOOST_CHECK(m.IsArmed(true));
    BOOST_CHECK(!m.IsArmed(false));
    Params off = m;
    off.attestRequired = false;
    BOOST_CHECK(!off.IsArmed(true));

    Params r = RegtestParams(150, 0, 0, 0);   // the two v3 flags default to 3 / scriptsig
    BOOST_CHECK_EQUAL(r.attestArmMin, 3);
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
    BOOST_CHECK_EQUAL(r.bondMin, 10 * COIN);
    BOOST_CHECK_EQUAL(r.bondMinLock, 200);
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
    Params never = RegtestParams(150, 0, 0, 0, 0, BundleCarrier::EITHER);
    BOOST_CHECK_EQUAL(never.attestArmMin, 0);
    BOOST_CHECK(never.bundleCarrier == BundleCarrier::EITHER);
    BOOST_CHECK(RegtestParams(1, 0, 0, 0, 7, BundleCarrier::OP_RETURN).bundleCarrier == BundleCarrier::OP_RETURN);
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

// Rule: BUNDLE-1
// weight = bondZat * clamp(age, 0, AGE_CAP), in arith_uint256 (R10).
BOOST_AUTO_TEST_CASE(bundle1_bond_weight_clamps_age)
{
    const Params& m = MainParams();
    BOOST_CHECK(BondWeight(m.bondMin, 0, m.ageCap) == arith_uint256(0));
    BOOST_CHECK(BondWeight(m.bondMin, -5, m.ageCap) == arith_uint256(0));
    BOOST_CHECK(BondWeight(m.bondMin, 1, m.ageCap) == arith_uint256(m.bondMin));
    BOOST_CHECK(BondWeight(m.bondMin, 100, m.ageCap) == arith_uint256(m.bondMin) * arith_uint256(100));
    BOOST_CHECK(BondWeight(m.bondMin, m.ageCap, m.ageCap) == arith_uint256(m.bondMin) * arith_uint256(m.ageCap));
    BOOST_CHECK(BondWeight(m.bondMin, m.ageCap + 1, m.ageCap) == BondWeight(m.bondMin, m.ageCap, m.ageCap));
    BOOST_CHECK(BondWeight(m.bondMin, 1000000000LL, m.ageCap) == BondWeight(m.bondMin, m.ageCap, m.ageCap));
    // R10: 20,000 YEC at AGE_CAP is 4.1e17 -- past 2^58, so a 64-bit sum over nine slots would be at risk.
    BOOST_CHECK(BondWeight(m.bondMin, m.ageCap, m.ageCap) == arith_uint256(414720000000000000ULL));
    BOOST_CHECK(BondWeight(MAX_MONEY, m.ageCap, m.ageCap) == arith_uint256(MAX_MONEY) * arith_uint256(m.ageCap));
    BOOST_CHECK(!FitsInt64(BondWeight(MAX_MONEY, m.ageCap, m.ageCap) * arith_uint256(9)));
    // Degenerate inputs: zero, never a throw.
    BOOST_CHECK(BondWeight(0, 10, m.ageCap) == arith_uint256(0));
    BOOST_CHECK(BondWeight(-1, 10, m.ageCap) == arith_uint256(0));
    BOOST_CHECK(BondWeight(m.bondMin, 10, 0) == arith_uint256(0));
    // Regtest: 10 YEC, cap 64.
    Params r = RegtestParams(1, 0, 0, 0);
    BOOST_CHECK(BondWeight(r.bondMin, 100, r.ageCap) == arith_uint256(10 * COIN) * arith_uint256(64));
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
    // §3.7 check: $100 at 110 % and 18,333 uUSD => 1.1e16 / 18,333 = 600,010,909,289.6.. => 600,010,909,290 zat ~ 6,000 YEC.
    auto c = ClaimantMaxZat(10000, m.claimThresholdBps, 18333);
    BOOST_REQUIRE(c.has_value());
    BOOST_CHECK_EQUAL(c.value(), 600010909290LL);
    BOOST_CHECK_EQUAL(c.value() / COIN, 6000);
    // Clause (b): margin 10^4, exactly the debt at the adverse price (R1).
    c = ClaimantMaxZat(10000, 10000, 18333);
    BOOST_REQUIRE(c.has_value());
    BOOST_CHECK_EQUAL(c.value(), 545464462991LL);
    // A vault at exactly the 110 % threshold: collateral * pClaim == minted * 11,000 * COIN, so the claimant takes it all, residual 0.
    // $100 minted, pClaim 20,000 uUSD: threshold collateral = 1e4 * 11,000 * 1e8 / 20,000 = 5.5e11 zat (5,500 YEC) exactly.
    const CAmount atThreshold = 550000000000LL;
    BOOST_CHECK(!IsUnderwater(atThreshold, 20000, 10000, m.claimThresholdBps));   // RED-4(a): strictly below, so not (yet) claimable
    BOOST_CHECK(IsUnderwater(atThreshold - 1, 20000, 10000, m.claimThresholdBps));
    c = ClaimantMaxZat(10000, m.claimThresholdBps, 20000);
    BOOST_REQUIRE(c.has_value());
    BOOST_CHECK_EQUAL(c.value(), atThreshold);
    BOOST_CHECK_EQUAL(ResidualZat(atThreshold, c), 0);
    BOOST_CHECK_EQUAL(ResidualZat(atThreshold - 1, c), 0);          // underwater by a zat: still nothing back
    BOOST_CHECK_EQUAL(ResidualZat(atThreshold + 1, c), 1);
    BOOST_CHECK_EQUAL(ResidualZat(atThreshold + m.residualMinZat, c), m.residualMinZat);
    // The worked vault (6,000 YEC) claimed at 18,333: the 110 % share (6,000.1 YEC) exceeds the collateral => 0.
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
// Overflow at PRICE_MIN: MAX_MINT * 11,000 * COIN / 100 = 1.1e16 zat > MAX_MONEY => nullopt (residual 0), never a wrapped number.
BOOST_AUTO_TEST_CASE(red5_claimant_max_overflow_at_price_min)
{
    const Params& m = MainParams();
    BOOST_CHECK(!ClaimantMaxZat(m.maxMint, m.claimThresholdBps, PRICE_MIN).has_value());
    BOOST_CHECK(!ClaimantMaxZat(m.maxMint, 10000, PRICE_MIN).has_value());
    BOOST_CHECK_EQUAL(ResidualZat(MAX_MONEY, ClaimantMaxZat(m.maxMint, m.claimThresholdBps, PRICE_MIN)), 0);
    // The minimum mint at PRICE_MIN still fits: 1e4 * 11,000 * 1e8 / 100 = 1.1e14 zat = 1,100,000 YEC < MAX_MONEY.
    auto c = ClaimantMaxZat(m.minMint, m.claimThresholdBps, PRICE_MIN);
    BOOST_REQUIRE(c.has_value());
    BOOST_CHECK_EQUAL(c.value(), 110000000000000LL);
    // Exactly MAX_MONEY is representable; one zat more is not. margin 10^4 at PRICE_MAX: cents * 1e4 zat => MAX_MONEY at 2.1e11 cents.
    BOOST_CHECK_EQUAL(ClaimantMaxZat(210000000000LL, 10000, PRICE_MAX).value(), MAX_MONEY);
    BOOST_CHECK(!ClaimantMaxZat(210000000001LL, 10000, PRICE_MAX).has_value());
    // The product itself passes int64 before the division (1e6 * 11,000 * 1e8 = 1.1e18 fits; 1e7 cents would not): still exact.
    BOOST_CHECK_EQUAL(ClaimantMaxZat(m.maxOutput, m.claimThresholdBps, PRICE_MAX).value(), 110000000000LL);   // $100,000 at 110 % / $100 per YEC = 1,100 YEC
}

// Rule: AFEE-1
// attestFeeZat = feeZat * ATTEST_FEE_BPS / 10^4 (floor), out of FEE-1's fee.
BOOST_AUTO_TEST_CASE(afee1_attestor_fee_is_a_quarter_of_the_pool_fee)
{
    const Params& m = MainParams();
    // The worked vault: 6,000 YEC pays 15 YEC to the pool and 3.75 YEC to the attestor.
    const CAmount fee = FeeZat(6000 * COIN, m.feeMin, m.feeBps);
    BOOST_CHECK_EQUAL(fee, 15 * COIN);
    BOOST_CHECK_EQUAL(AttestFeeZat(fee, m.attestFeeBps), 375000000);
    // The minimum fee: 0.5 YEC => 0.125 YEC.
    BOOST_CHECK_EQUAL(AttestFeeZat(m.feeMin, m.attestFeeBps), 12500000);
    // Floor.
    BOOST_CHECK_EQUAL(AttestFeeZat(3, m.attestFeeBps), 0);
    BOOST_CHECK_EQUAL(AttestFeeZat(4, m.attestFeeBps), 1);
    BOOST_CHECK_EQUAL(AttestFeeZat(7, m.attestFeeBps), 1);
    // Degenerate: zero or negative inputs give 0; 10^4 bps is the whole fee; MAX_MONEY does not overflow.
    BOOST_CHECK_EQUAL(AttestFeeZat(0, m.attestFeeBps), 0);
    BOOST_CHECK_EQUAL(AttestFeeZat(-1, m.attestFeeBps), 0);
    BOOST_CHECK_EQUAL(AttestFeeZat(fee, 0), 0);
    BOOST_CHECK_EQUAL(AttestFeeZat(fee, 10000), fee);
    BOOST_CHECK_EQUAL(AttestFeeZat(MAX_MONEY, m.attestFeeBps), MAX_MONEY / 4);
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
}

BOOST_AUTO_TEST_SUITE_END()
