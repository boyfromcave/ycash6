#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The YED module's arithmetic, re-derived from the spec text in exact rationals (audit 03/T-3).

yellowback_model.py's money functions mirror src/yellowback/math.h clause for clause (the same u256 wraps,
the same ceil_div), so a misreading of the spec shared by both cannot surface in the model-vs-C++ golden.
This file writes every formula a second way: in ``fractions.Fraction``, in the units the spec states them in
(dollars, dollars per YEC, ratios), straight from the spec prose -- never from the integer form either
implementation uses -- and then rounds once, in the direction the spec names:

  MINT-5    required collateral       ceil   (the owner pays up)             doc/yellowback-spec.md "Required collateral"
  FEE-1'    protocol fee (zat)         ceil   (the owner pays up)             quantum fees spec section 1.3, "Rounding rule"
            protocol fee (cents)       ceil
  IT-9'     early-redeem fee           ceil   (the owner pays up), no floor
  AFEE-1    attestor share             floor  (the payee rounds down)
  RED-5     claimant maximum           ceil   (the spec's own rounding, R5); undefined above MAX_MONEY
            residual                   max(0, collateral - claimant max)
  RED-5'    residual threshold         max(RESIDUAL_MIN_ZAT, ceil of RESIDUAL_MIN_CENTS at the price)
  HALT-2    global ratio (bps)         floor  (the ratio rounds against the system: halts sooner)
  MINT-6    market cap, supply cap     floor  (the cap rounds against the minter)
  RED-4     underwater                 strict "<" on exact values (equality is not underwater)

For a seeded sample (random.Random(0), 10^5 draws per function over the full money / cents / price ranges
plus the boundaries 0, 1, MAX_MONEY, 2^63 - 1, PRICE_MIN, PRICE_MAX) the model's integer function must equal
the rational result exactly.  ``--write-cases`` writes src/test/data/yellowback_math_cases.json -- rows
computed by THIS file's rationals, not by the model -- which yellowback_math_tests.cpp's
``math_spec_rational_cases`` replays against math.h, so the C++ is held to the same independent numbers.

Run from qa/rpc-tests:

    ../../../../.venv/bin/python -m unittest test_framework.test_yellowback_math_spec -v

Every test case is tagged ``# Rule: <ID>`` on the line before it (plan N36).
"""

import json
import math
import os
import random
import sys
import unittest
from fractions import Fraction as F

if __package__ in (None, ''):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from test_framework import yellowback_model as ym
else:
    from . import yellowback_model as ym

CASES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'src', 'test', 'data',
                          'yellowback_math_cases.json')

# --- units, from the spec's text (not imported from the model) --------------------------------------
ZAT_PER_YEC = 10 ** 8                 # COIN
MAX_MONEY = 21_000_000 * ZAT_PER_YEC
CENTS_PER_DOLLAR = 100
MICRO_PER_DOLLAR = 10 ** 6            # prices are micro-USD per YEC
BPS_PER_ONE = 10 ** 4
PRICE_MIN = 100
PRICE_MAX = 4_294_967_295            # D-Q-22: UINT32_MAX micro-USD
INT64_MAX = 2 ** 63 - 1
# FEE-1' (quantum fees spec 1.1): "first $1,000 at 1.0 %, $1,000-$10,000 at 0.5 %, above at 0.1 %", "$1 per action"
FEE_BANDS_USD = ((F(1_000), F(1, 100)), (F(10_000), F(5, 1_000)), (None, F(1, 1_000)))
FEE_FLOOR_USD = F(1)
RESIDUAL_MIN_ZAT = 100_000            # RED-5
RESIDUAL_MIN_USD = F(48, 100)         # RED-5' (D-Q-23a): $0.48

N_DRAWS = int(os.environ.get('YB_MATH_SPEC_DRAWS', '100000'))


def dollars(cents):
    return F(cents, CENTS_PER_DOLLAR)


def usd_per_yec(micro):
    return F(micro, MICRO_PER_DOLLAR)


def ratio(bps):
    return F(bps, BPS_PER_ONE)


def yec_to_zat(yec):
    return yec * ZAT_PER_YEC


def zat_value_usd(zat, micro):
    """The dollar value of ``zat`` at ``micro`` micro-USD per YEC."""
    return F(zat, ZAT_PER_YEC) * usd_per_yec(micro)


def ceil(q):
    return math.ceil(q)


def floor(q):
    return math.floor(q)


# --- the spec's formulas as rationals ----------------------------------------------------------------

def spec_required_zat(cents, min_ratio_bps, price):
    """MINT-5: the collateral worth ``min_ratio`` x the debt at the price, in zat, rounded up; undefined without
    a price and unsatisfiable above MAX_MONEY (K14)."""
    if price <= 0:
        return None
    exact = yec_to_zat(dollars(cents) * ratio(min_ratio_bps) / usd_per_yec(price))
    z = ceil(exact)
    return None if z > MAX_MONEY else z


def spec_fee_usd(debt_cents):
    """FEE-1': the banded fee in dollars, at least $1 (a debt of 0 pays nothing)."""
    if debt_cents <= 0:
        return F(0)
    debt, lo, fee = dollars(debt_cents), F(0), F(0)
    for upto, rate in FEE_BANDS_USD:
        hi = debt if upto is None else min(debt, upto)
        if hi <= lo:
            break
        fee += (hi - lo) * rate
        if upto is None:
            break
        lo = upto
    return max(fee, FEE_FLOOR_USD)


def spec_protocol_fee_cents(debt_cents):
    return ceil(spec_fee_usd(debt_cents) * CENTS_PER_DOLLAR)


def spec_protocol_fee_zat(debt_cents, price):
    """FEE-1': the YEC worth of the dollar fee at the vault's mint price, rounded up to the zat; MAX_MONEY when
    it does not fit."""
    if price <= 0:
        return None
    z = ceil(yec_to_zat(spec_fee_usd(debt_cents) / usd_per_yec(price)))
    return min(z, MAX_MONEY)


def spec_early_redeem_fee_zat(debt_cents, fee_bps, price):
    """IT-9': bps of the debt at the mint price, rounded up, no floor; 0 when there is nothing to charge."""
    if debt_cents <= 0 or fee_bps <= 0 or price <= 0:
        return 0
    z = ceil(yec_to_zat(dollars(debt_cents) * ratio(fee_bps) / usd_per_yec(price)))
    return min(z, MAX_MONEY)


def spec_attest_fee_zat(fee_zat, attest_fee_bps):
    """AFEE-1: the attestors' share of the protocol fee, rounded down (the payee never rounds up)."""
    if fee_zat <= 0 or attest_fee_bps <= 0:
        return 0
    return floor(fee_zat * ratio(attest_fee_bps))


def spec_claimant_max_zat(minted_cents, margin_bps, price):
    """RED-5: the debt x margin at the claim price, in zat, rounded up (R5); undefined above MAX_MONEY."""
    if minted_cents <= 0 or margin_bps <= 0 or price <= 0:
        return None
    z = ceil(yec_to_zat(dollars(minted_cents) * ratio(margin_bps) / usd_per_yec(price)))
    return z if z <= MAX_MONEY else None


def spec_residual_zat(collateral_zat, claimant_max):
    if claimant_max is None:
        return 0
    return max(0, collateral_zat - claimant_max)


def spec_residual_min_zat(price):
    """RED-5': max(RESIDUAL_MIN_ZAT, $0.48 at the price rounded up); the zat floor alone without a price or
    when the dollar term does not fit."""
    if price <= 0:
        return RESIDUAL_MIN_ZAT
    z = ceil(yec_to_zat(RESIDUAL_MIN_USD / usd_per_yec(price)))
    return RESIDUAL_MIN_ZAT if z > MAX_MONEY else max(RESIDUAL_MIN_ZAT, z)


def spec_global_ratio_bps(collateral_zat, price, supply_cents):
    """HALT-2: the collateral's dollar value over the supply's, in bps, rounded down; undefined with no supply."""
    if price <= 0 or supply_cents <= 0:
        return None
    return floor(zat_value_usd(collateral_zat, price) / dollars(supply_cents) * BPS_PER_ONE)


def spec_cap_cents(issued_zat, price):
    """MINT-6: the market cap in cents, rounded down."""
    if price <= 0:
        return None
    return floor(zat_value_usd(issued_zat, price) * CENTS_PER_DOLLAR)


def spec_supply_cap_cents(issued_zat, price, cap_bps):
    if cap_bps == 0:
        return None
    c = spec_cap_cents(issued_zat, price)
    return None if c is None else floor(c * ratio(cap_bps))


def spec_is_underwater(collateral_zat, price, minted_cents, threshold_bps):
    """RED-4 / Claimable: the collateral's value is strictly below threshold x the debt; no price, not underwater."""
    if price is None or price <= 0:
        return False
    return zat_value_usd(collateral_zat, price) < dollars(minted_cents) * ratio(threshold_bps)


# --- sampling ---------------------------------------------------------------------------------------

def _pick(rng, lo, hi, edges):
    """A draw in [lo, hi]: a boundary one time in eight, else uniform -- on a log scale half the time, so small and
    large magnitudes are both covered."""
    r = rng.random()
    if r < 0.125:
        e = [x for x in edges if lo <= x <= hi]
        if e:
            return rng.choice(e)
    if r < 0.5625 and hi > 1:
        return min(hi, max(lo, int(2 ** rng.uniform(0, math.log2(hi)))))
    return rng.randint(lo, hi)


MONEY_EDGES = (0, 1, 999, 1000, MAX_MONEY - 1, MAX_MONEY)
CENTS_EDGES = (0, 1, 99, 100, 10_000, 100_000, 100_001, 1_000_000, 1_000_001, 10_000_000)
PRICE_EDGES = (1, 2, PRICE_MIN, 18_333, 50_000, 1_985_000, PRICE_MAX - 1, PRICE_MAX)
BPS_EDGES = (0, 1, 9_999, 10_000, 10_500, 11_000, 12_500, 30_000, 40_000, 50_000, 150_000)


def money(rng):
    return _pick(rng, 0, MAX_MONEY, MONEY_EDGES)


def cents(rng):
    return _pick(rng, 0, 10_000_000, CENTS_EDGES)


def wide_cents(rng):
    return _pick(rng, 0, INT64_MAX // 10 ** 12, CENTS_EDGES + (2 ** 40,))


def price(rng):
    return _pick(rng, 1, PRICE_MAX, PRICE_EDGES)


def bps(rng, hi=200_000):
    return _pick(rng, 0, hi, BPS_EDGES)


class MathSpecTests(unittest.TestCase):
    """The model's integer arithmetic equals the spec's rationals rounded the way the spec says."""

    P = ym.Params.regtest(1)

    def agree(self, name, model_fn, spec_fn, draw, n=None):
        """Run ``n`` seeded draws; returns the first disagreement (args, model, spec) or None."""
        rng = random.Random(0)
        for _ in range(N_DRAWS if n is None else n):
            args = draw(rng)
            m, s = model_fn(*args), spec_fn(*args)
            if m != s:
                return args, m, s
        return None

    def check(self, name, model_fn, spec_fn, draw):
        bad = self.agree(name, model_fn, spec_fn, draw)
        self.assertIsNone(bad, '%s: model %r != spec %r at %r' % (name, bad and bad[1], bad and bad[2], bad and bad[0]))

    def test_fee_parameters_are_the_specs(self):
        """The regtest/mainnet fee table the model runs with is the spec's dollar table (one table on every network)."""
        p = self.P
        bands = []
        for (upto, bps_), (u_usd, rate) in zip(p.fee_bands, FEE_BANDS_USD):
            bands.append((upto == 0) == (u_usd is None) and (u_usd is None or dollars(upto) == u_usd) and ratio(bps_) == rate)
        self.assertEqual(bands, [True, True, True])
        self.assertEqual(dollars(p.fee_floor_cents), FEE_FLOOR_USD)
        self.assertEqual((p.residual_min_zat, dollars(p.residual_min_cents)), (RESIDUAL_MIN_ZAT, RESIDUAL_MIN_USD))

    # Rule: MINT-5
    def test_required_collateral(self):
        self.check('required_zat', ym.required_zat, spec_required_zat, lambda r: (cents(r), bps(r), price(r)))
        # worked example (spec "Required collateral"): $100 at 300 % and $0.05/YEC is 6,000 YEC
        self.assertEqual(spec_required_zat(10_000, 30_000, 50_000), 6_000 * ZAT_PER_YEC)

    # Rule: FEE-1
    def test_protocol_fee(self):
        p = self.P
        self.check('protocol_fee_zat', lambda d, pr: ym.protocol_fee_zat(d, pr, p), spec_protocol_fee_zat,
                   lambda r: (wide_cents(r) if r.random() < 0.1 else cents(r), price(r)))
        self.check('protocol_fee_cents', lambda d: ym.protocol_fee_cents(d, p), spec_protocol_fee_cents, lambda r: (cents(r),))
        # worked values (quantum fees spec 1.3): $100 pays the $1 floor, $1,000 pays $10, $10,000 pays $55
        self.assertEqual([spec_protocol_fee_cents(c) for c in (10_000, 100_000, 1_000_000)], [100, 1_000, 5_500])
        self.assertEqual(spec_protocol_fee_zat(10_000, 18_000), 5_555_555_556)

    # Rule: IT-9
    def test_early_redeem_fee(self):
        self.check('early_redeem_fee_zat', ym.early_redeem_fee_zat, spec_early_redeem_fee_zat,
                   lambda r: (cents(r), bps(r, 1_000), price(r)))

    # Rule: AFEE-1
    def test_attest_fee(self):
        self.check('attest_fee_zat', ym.attest_fee_zat, spec_attest_fee_zat, lambda r: (money(r), bps(r, 10_000)))

    # Rule: RED-5
    def test_claimant_max_and_residual(self):
        self.check('claimant_max_zat', ym.claimant_max_zat, spec_claimant_max_zat, lambda r: (cents(r), bps(r), price(r)))

        def both(fn_max, fn_res):
            return lambda c, m, b, pr: fn_res(c, fn_max(m, b, pr))
        self.check('residual_zat', both(ym.claimant_max_zat, ym.residual_zat), both(spec_claimant_max_zat, spec_residual_zat),
                   lambda r: (money(r), cents(r), bps(r), price(r)))
        self.check('residual_min_zat', lambda pr: ym.residual_min_zat(pr, self.P), spec_residual_min_zat, lambda r: (price(r),))
        # v2's worked example: $100 at 110 % and 18,333 micro-USD is ~6,000 YEC
        self.assertEqual(spec_claimant_max_zat(10_000, 11_000, 18_333), 600_010_909_290)   # 1.1e16 / 18,333 = 600,010,909,289.2, rounded up

    # Rule: HALT-2
    def test_global_ratio(self):
        self.check('global_ratio_bps', ym.global_ratio_bps, spec_global_ratio_bps,
                   lambda r: (money(r), price(r), wide_cents(r) if r.random() < 0.3 else cents(r)))

    # Rule: MINT-6
    def test_caps(self):
        self.check('cap_cents', ym.cap_cents, spec_cap_cents, lambda r: (money(r), price(r)))
        self.check('supply_cap_cents', ym.supply_cap_cents, spec_supply_cap_cents, lambda r: (money(r), price(r), bps(r, 10_000)))

    # Rule: RED-4
    def test_underwater_strict(self):
        self.check('is_underwater', ym.is_underwater, spec_is_underwater, lambda r: (money(r), price(r), cents(r), bps(r)))
        # the boundary itself is not underwater: 6,000 YEC at $0.0183333.. would be exactly 110 % of $100; equality
        # needs collateral x price == debt x threshold x 10^4, e.g. 10^11 zat at 110,000 micro-USD vs $100 at 110 %
        self.assertFalse(spec_is_underwater(10 ** 11, 110_000, 10_000, 11_000))
        self.assertFalse(ym.is_underwater(10 ** 11, 110_000, 10_000, 11_000))
        self.assertTrue(ym.is_underwater(10 ** 11 - 1, 110_000, 10_000, 11_000))
        self.assertFalse(ym.is_underwater(10 ** 11, None, 10_000, 11_000))

    def test_rounding_directions(self):
        """The direction, not just the value: what an owner pays is never below the exact amount, what a payee is
        given never above it."""
        rng = random.Random(1)
        for _ in range(2_000):
            c, b, pr = cents(rng), bps(rng), price(rng)
            req = ym.required_zat(c, b, pr)
            if req is not None:
                self.assertGreaterEqual(req, yec_to_zat(dollars(c) * ratio(b) / usd_per_yec(pr)))
            fee = ym.protocol_fee_zat(c, pr, self.P)
            if fee is not None and fee < MAX_MONEY:
                self.assertGreaterEqual(fee, yec_to_zat(spec_fee_usd(c) / usd_per_yec(pr)))
                self.assertLessEqual(ym.attest_fee_zat(fee, 5_000), fee * F(1, 2))
            ratio_bps = ym.global_ratio_bps(money(rng), pr, c)
            if ratio_bps is not None:
                self.assertGreaterEqual(ratio_bps, 0)

    def test_an_off_by_one_is_caught(self):
        """The suite would fail on a wrong rounding: floor in place of MINT-5's ceil disagrees within the sample."""
        def floor_required(c, b, pr):
            if pr <= 0:
                return None
            z = floor(yec_to_zat(dollars(c) * ratio(b) / usd_per_yec(pr)))
            return None if z > MAX_MONEY else z
        self.assertIsNotNone(self.agree('required_zat (floor)', ym.required_zat, floor_required,
                                        lambda r: (cents(r), bps(r), price(r)), n=1_000))

        def ceil_ratio(col, pr, s):
            if pr <= 0 or s <= 0:
                return None
            return ceil(zat_value_usd(col, pr) / dollars(s) * BPS_PER_ONE)
        self.assertIsNotNone(self.agree('global_ratio_bps (ceil)', ym.global_ratio_bps, ceil_ratio,
                                        lambda r: (money(r), price(r), cents(r)), n=1_000))

    def test_cases_file_is_the_rationals(self):
        """src/test/data/yellowback_math_cases.json is this file's output byte for byte (the C++ replays it)."""
        with open(CASES_PATH) as f:
            committed = f.read()
        self.assertEqual(committed, cases_text())


# --- the C++ hand-case file ---------------------------------------------------------------------------

def _case(fn, args, expect):
    return {'fn': fn, 'args': list(args), 'expect': expect}


def cases():
    """~60 rows: the worked examples, the rounding boundaries and the overflow corners, each computed by the
    rationals above (the C++ replays them through math.h; the first ten are checked by hand in the PR).

    Out of the consensus domain the two implementations differ by convention, and the rows stay inside it:
    math.h's RequiredCollateral is nullopt ("undefined") for cents <= 0 or a ratio <= 0, where the spec's
    formula and the model give 0 -- unreachable, since MINT-2 bounds cents >= MIN_MINT and every class ratio
    is positive (finding recorded with audit 03/T-3; no rule changes)."""
    rows = []
    for c, b, pr in ((10_000, 30_000, 50_000), (10_000, 30_000, 18_333), (1, 1, PRICE_MAX), (10_000_000, 150_000, PRICE_MIN),
                     (10_000_000, 150_000, 1), (12_345, 40_000, 1_985_000), (100, 10_000, 1), (99, 30_000, 50_000),
                     (10_000, 50_000, 3), (7, 30_001, 7)):
        rows.append(_case('RequiredCollateral', (c, b, pr), spec_required_zat(c, b, pr)))
    for d, pr in ((10_000, 18_000), (100_000, 18_000), (1_000_000, 18_000), (10_000_000, 18_000), (10_000, PRICE_MIN),
                  (100_001, 1_985_000), (1_000_001, PRICE_MAX), (1, 400_000), (0, 400_000), (10_000_000, 1)):
        rows.append(_case('ProtocolFeeZat', (d, pr), spec_protocol_fee_zat(d, pr)))
    for d in (0, 1, 9_999, 10_000, 100_000, 100_001, 1_000_000, 1_000_001, 10_000_000):
        rows.append(_case('ProtocolFeeCents', (d,), spec_protocol_fee_cents(d)))
    for d, b, pr in ((10_000, 500, 50_000), (10_000, 250, 18_333), (10_000, 100, PRICE_MAX), (10_000_000, 500, 1), (1, 1, PRICE_MAX)):
        rows.append(_case('EarlyRedeemFeeZat', (d, b, pr), spec_early_redeem_fee_zat(d, b, pr)))
    for fee, b in ((503_778_338, 5_000), (1, 5_000), (3, 5_000), (MAX_MONEY, 5_000), (10_001, 2_500)):
        rows.append(_case('AttestFeeZat', (fee, b), spec_attest_fee_zat(fee, b)))
    for m, b, pr in ((10_000, 11_000, 18_333), (10_000, 10_000, 17_000), (10_000_000, 12_500, 1), (1, 10_000, PRICE_MAX), (10_000, 12_500, 3_000)):
        rows.append(_case('ClaimantMaxZat', (m, b, pr), spec_claimant_max_zat(m, b, pr)))
    for pr in (1, PRICE_MIN, 50_000, 480_000, 480_001, PRICE_MAX):
        rows.append(_case('ResidualMinZat', (pr,), spec_residual_min_zat(pr)))
    for col, pr, s in ((600_000_000_000, 50_000, 10_000), (1, 1, 1), (MAX_MONEY, PRICE_MAX, 1), (6 * 10 ** 11, 18_333, 10_000), (999, 3, 7)):
        rows.append(_case('GlobalRatioBps', (col, pr, s), spec_global_ratio_bps(col, pr, s)))
    for issued, pr, b in ((MAX_MONEY, 50_000, 1_500), (12_345_678 * ZAT_PER_YEC, 400_000, 1_500), (1, 1, 10_000)):
        rows.append(_case('CapCents', (issued, pr), spec_cap_cents(issued, pr)))
        rows.append(_case('SupplyCapCents', (issued, pr, b), spec_supply_cap_cents(issued, pr, b)))
    for col, pr, m, b in ((10 ** 11, 110_000, 10_000, 11_000), (10 ** 11 - 1, 110_000, 10_000, 11_000), (6 * 10 ** 11, 18_333, 10_000, 11_000),
                          (6 * 10 ** 11, 18_334, 10_000, 11_000), (0, 1, 1, 1), (MAX_MONEY, PRICE_MAX, 10_000_000, 150_000)):
        rows.append(_case('IsUnderwater', (col, pr, m, b), spec_is_underwater(col, pr, m, b)))
    return rows


def cases_text():
    doc = {'description': 'YED module arithmetic cases computed in exact rationals from the spec text by '
                          'qa/rpc-tests/test_framework/test_yellowback_math_spec.py (audit 03/T-3), never by the model; '
                          'yellowback_math_tests.cpp math_spec_rational_cases replays them through math.h. '
                          'null = undefined (no price, no supply, or above MAX_MONEY where the spec says so).',
           'cases': cases()}
    return json.dumps(doc, indent=1) + '\n'


if __name__ == '__main__':
    if '--write-cases' in sys.argv:
        with open(CASES_PATH, 'w') as f:
            f.write(cases_text())
        print('wrote %s: %d cases' % (os.path.normpath(CASES_PATH), len(cases())))
    else:
        unittest.main()
