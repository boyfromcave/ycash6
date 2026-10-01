#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
yellowback_model.py -- a second, independent implementation of the Yellowback
v2 protocol (docs/plans/yellowback-v2-development-plan.md section 3) in pure
Python, used as the cross-implementation check of the node (plan N23, P8).

It re-implements, from the plan text alone and with Python integers only:

  section 3.2  the coinbase tag decoder            (TAG-1..5)          find_tag()
  section 3.3  the payload codec                   (MINT/TRANSFER/REDEEM) decode_payload(), tx_payload()
  section 3.4  the vault script and path detection                      vault_script(), spend_path()
  section 3.6  the state tables and the state hash (N18)                YellowbackModel.state_hash()
  section 3.7  the snapshot arithmetic             (PRICE, SIGMA, ACT, HALT, REG-4, FEE-1/2)
  section 3.8  the money rules                     (IN-1..3, TX-0, MINT-1..8, XFER-1..3, RED-1..4)
  section 3.9  BLK-1 (blockInvalid + enforcementOn per block; the model never rejects)

The model is fed block by block (``feed_block``) with ``getblock <hash> 2``-style
transaction dicts and maintains Tags, Judgements, Activation, Vaults, Tokens,
TxLog, Totals and Snapshots.  ``assert_model_matches(node)`` rebuilds it from a
live node and compares it with the node's RPC answers.

Arithmetic conventions (section 3.7, M1): every quantity is a non-negative
integer; every division is floor division unless written ceil; ``isqrt`` is the
floor square root; ``lower_median`` is the element at index (n-1)//2 of the
sorted values; the products that section 3.7 computes in ``arith_uint256`` are
reduced modulo 2**256 (``u256``) so an overflow, should one ever occur, is
reproduced rather than hidden.  Totality (section 3.8): a rule whose input is
undefined (``None``) is false.

Every serialisation choice that section 3.6 leaves open is written down in
SERIALISATION.md next to this file; the C++ implementation must make the same
choices for the state hash to agree.

Only the standard library is used.  Nothing here imports mininode (it needs
asyncore, gone in Python 3.12) or talks to a node except assert_model_matches.
"""

import hashlib
import json
import math
import struct
from collections import OrderedDict
from decimal import Decimal

# ---------------------------------------------------------------------------
# Units and protocol constants (section 3.1)

COIN = 10 ** 8
MAX_MONEY = 21_000_000 * COIN          # ref/ycash/src/amount.h
BPS = 10_000
LOCKTIME_THRESHOLD = 500_000_000       # ref/ycash/src/script/script.h
BLOCKS_PER_HOUR = 48
BLOCKS_PER_DAY = 1_152
BLOCKS_PER_YEAR = 420_480

TAG_MAGIC = b'YED!'
TAG_VERSION = 1
TAG_SIZE = 36
TAG_PATTERN = b'\x24' + TAG_MAGIC      # direct-push opcode 0x24 (36) followed by the magic (P10)

PAYLOAD_MAGIC = b'YB'
PAYLOAD_VERSION = 3
PAYLOAD_MINT = 0x01
PAYLOAD_TRANSFER = 0x02
PAYLOAD_REDEEM = 0x03
# v3 types (v3 plan section 3.3).  Decoded by name; no rule evaluates them yet (A1): a transaction
# carrying one is handled exactly as the C++ handles it today -- through the TRANSFER/REDEEM path
# with no assignments, so it touches no token and writes no TxLog unless it spends YED.
PAYLOAD_ATTESTOR_REGISTER = 0x05
PAYLOAD_CLAIM_NOTICE = 0x06
PAYLOAD_EQUIVOCATION = 0x07
PAYLOAD_ATTESTOR_REVIVE = 0x08
PAYLOAD_TYPE_NAMES = {PAYLOAD_MINT: 'MINT', PAYLOAD_TRANSFER: 'TRANSFER', PAYLOAD_REDEEM: 'REDEEM',
                      PAYLOAD_ATTESTOR_REGISTER: 'ATTESTOR_REGISTER', PAYLOAD_CLAIM_NOTICE: 'CLAIM_NOTICE',
                      PAYLOAD_EQUIVOCATION: 'EQUIVOCATION', PAYLOAD_ATTESTOR_REVIVE: 'ATTESTOR_REVIVE'}
# BUNDLE_CARRIER (v3 plan section 3.1, W2), the params.h enum order
CARRIER_SCRIPTSIG, CARRIER_OP_RETURN, CARRIER_EITHER = 0, 1, 2
CARRIER_NAMES = {CARRIER_SCRIPTSIG: 'scriptsig', CARRIER_OP_RETURN: 'opreturn', CARRIER_EITHER: 'either'}
MAX_PAYLOAD = 80
FEE_VOUT_NONE = 0xFF

# Activation.status, declaration order (section 3.6)
SIGNALING, LOCKED_IN, ACTIVE = 0, 1, 2
ACTIVATION_NAMES = {SIGNALING: 'SIGNALING', LOCKED_IN: 'LOCKED_IN', ACTIVE: 'ACTIVE'}

# Vaults.status, declaration order (section 3.6)
V_ACTIVE, V_VOID, V_CLOSED, V_CLAIMED = 0, 1, 2, 3
VAULT_STATUS_NAMES = {V_ACTIVE: 'ACTIVE', V_VOID: 'VOID', V_CLOSED: 'CLOSED', V_CLAIMED: 'CLAIMED'}

# Attestors.status, declaration order (v3 plan section 3.6)
A_PENDING, A_ELIGIBLE, A_DORMANT, A_EJECTED, A_WITHDRAWN = 0, 1, 2, 3, 4
ATTESTOR_STATUS_NAMES = {A_PENDING: 'PENDING', A_ELIGIBLE: 'ELIGIBLE', A_DORMANT: 'DORMANT',
                         A_EJECTED: 'EJECTED', A_WITHDRAWN: 'WITHDRAWN'}
# Attest.status (ARM-1/2), declaration order
UNARMED, TRIGGERED, ARMED = 0, 1, 2
ATTEST_NAMES = {UNARMED: 'UNARMED', TRIGGERED: 'TRIGGERED', ARMED: 'ARMED'}
# TxLog.type names (view.h TxLogType)
TXLOG_TYPE_NAMES = {PAYLOAD_MINT: 'MINT', PAYLOAD_TRANSFER: 'TRANSFER', PAYLOAD_REDEEM: 'REDEEM',
                    PAYLOAD_ATTESTOR_REGISTER: 'ATTESTOR_REGISTER', PAYLOAD_CLAIM_NOTICE: 'CLAIM_NOTICE',
                    PAYLOAD_EQUIVOCATION: 'EQUIVOCATION', PAYLOAD_ATTESTOR_REVIVE: 'ATTESTOR_REVIVE'}

# haltMask bits, declaration order (section 3.6)
HALT_NOT_ACTIVE = 1 << 0
HALT_NO_PRICE = 1 << 1
HALT_PARTICIPATION = 1 << 2
HALT_GLOBAL_RATIO = 1 << 3
HALT_DIVERGENCE = 1 << 4
HALT_ENFORCEMENT = 1 << 5
HALT_NAMES = OrderedDict([
    (HALT_NOT_ACTIVE, 'NOT_ACTIVE'),
    (HALT_NO_PRICE, 'NO_PRICE'),
    (HALT_PARTICIPATION, 'PARTICIPATION'),
    (HALT_GLOBAL_RATIO, 'GLOBAL_RATIO'),
    (HALT_DIVERGENCE, 'DIVERGENCE'),
    (HALT_ENFORCEMENT, 'ENFORCEMENT'),
])

# Script opcodes
OP_0 = 0x00
OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4e
OP_1NEGATE = 0x4f
OP_RESERVED = 0x50
OP_1 = 0x51
OP_16 = 0x60
OP_RETURN = 0x6a
OP_IF = 0x63
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_DROP = 0x75
OP_DUP = 0x76
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_HASH160 = 0xa9
OP_CHECKSIG = 0xac
OP_CHECKLOCKTIMEVERIFY = 0xb1

SAPLING_TX_VERSION = 4
SAPLING_VERSION_GROUP_ID = 0x892F2085

# Verdict strings (section 4.2a)
VERDICT_OK = 'ok'
VERDICT_BURNED = 'burned'


class Params(object):
    """Every value a rule reads (section 3.1).  Build with Params.regtest(...) or Params.mainnet(...)."""

    # The "hashed" record (section 3.6 Params): startHeight, sigmaRefBps, supplyCapBps, enforceUntil,
    # and with v3 attestArmMin (u32) and bundleCarrier (u8) (M13).

    def __init__(self, network, start_height, sigma_ref_bps, supply_cap_bps, enforce_until,
                 p_fast_window, p_mid_window, p_slow_window,
                 signal_window, activation_threshold, participation_floor, activation_delay,
                 enforcement_floor, enforcement_resume, valve_blocks, abandon_blocks,
                 n_reg, n_penalty, peer_lag, peer_min, deviation_bps, accuracy_band_bps,
                 accuracy_window, payee_tilt_bps, payee_window, fee_min, fee_bps, grace,
                 claim_threshold_bps, global_ratio_halt_bps, divergence_bps,
                 class_min, class_max, base_ratio_bps, vol_window, vol_step,
                 vol_periods_per_year, sigma_mult_max_bps, min_mint, max_mint, min_output,
                 max_output, token_value, yellowback_fee, ref_window, ref_lag,
                 price_min=100, price_max=100_000_000, attest_arm_min=5, bundle_carrier=CARRIER_SCRIPTSIG,
                 attest=None,
                 recap_ratio_bps=50_000):
        self.network = network
        self.start_height = start_height
        self.sigma_ref_bps = sigma_ref_bps
        self.supply_cap_bps = supply_cap_bps
        self.enforce_until = enforce_until
        self.p_fast_window = p_fast_window
        self.p_mid_window = p_mid_window
        self.p_slow_window = p_slow_window
        self.signal_window = signal_window
        self.activation_threshold = activation_threshold
        self.participation_floor = participation_floor
        self.activation_delay = activation_delay
        self.enforcement_floor = enforcement_floor
        self.enforcement_resume = enforcement_resume
        self.valve_blocks = valve_blocks
        self.abandon_blocks = abandon_blocks
        self.n_reg = n_reg
        self.n_penalty = n_penalty
        self.peer_lag = peer_lag
        self.peer_min = peer_min
        self.deviation_bps = deviation_bps
        self.accuracy_band_bps = accuracy_band_bps
        self.accuracy_window = accuracy_window
        self.payee_tilt_bps = payee_tilt_bps
        self.payee_window = payee_window
        self.fee_min = fee_min
        self.fee_bps = fee_bps
        self.grace = grace
        self.claim_threshold_bps = claim_threshold_bps
        self.global_ratio_halt_bps = global_ratio_halt_bps
        self.recap_ratio_bps = recap_ratio_bps          # W16: under HALT-2 a mint needs min_ratio_bps(class) >= this
        self.divergence_bps = divergence_bps
        self.class_min = list(class_min)
        self.class_max = list(class_max)
        self.base_ratio_bps = list(base_ratio_bps)
        self.vol_window = vol_window
        self.vol_step = vol_step
        self.vol_periods_per_year = vol_periods_per_year
        self.sigma_mult_max_bps = sigma_mult_max_bps
        self.min_mint = min_mint
        self.max_mint = max_mint
        self.min_output = min_output
        self.max_output = max_output
        self.token_value = token_value
        self.yellowback_fee = yellowback_fee
        self.ref_window = ref_window
        self.ref_lag = ref_lag
        self.price_min = price_min
        self.price_max = price_max
        self.attest_arm_min = attest_arm_min
        self.bundle_carrier = bundle_carrier
        # v3 plan section 3.1 (the mainnet column unless `attest` overrides; regtest() passes its column)
        a = dict(attest_arm_delay=1_152, attest_required=True, n_slots=9, m_select=4, k_slack=2, bundle_max=6,
                 q_low_bps=3_333, q_high_bps=6_667, attest_max_age=20, pin_window=288, pin_delta_bps=500,
                 pin_min_tags=3, pin_min_bundles=2, diverge_bps_attest=1_500, emergency_ratio_bps=10_500,
                 emergency_persist=48, emergency_notice_ttl=1_152, residual_min_zat=100_000, attest_fee_bps=2_500,
                 bond_min=20_000 * COIN, bond_min_lock=420_480, bond_maturity=16_128, age_cap=207_360,
                 founding_window=8_064, dormancy_blocks=16_128, dormancy_min_bundles=20, dormancy_check=48)
        a.update(attest or {})
        for k, v in a.items():
            setattr(self, k, v)

    # The regtest column of v3 plan section 3.1 (yellowback_util.py carries the same numbers for the scripts)
    REGTEST_ATTEST = dict(attest_arm_delay=8, attest_required=True, n_slots=5, m_select=2, k_slack=1, bundle_max=6,
                          q_low_bps=3_333, q_high_bps=6_667, attest_max_age=8, pin_window=16, pin_delta_bps=500,
                          pin_min_tags=2, pin_min_bundles=2, diverge_bps_attest=1_500, emergency_ratio_bps=10_500,
                          emergency_persist=4, emergency_notice_ttl=64, residual_min_zat=100_000, attest_fee_bps=2_500,
                          bond_min=10 * COIN, bond_min_lock=200, bond_maturity=8, age_cap=64, founding_window=16,
                          dormancy_blocks=16, dormancy_min_bundles=2, dormancy_check=4)

    def is_armed(self, snapshot_status):
        """"ARMED" as every v3 rule reads it: the snapshot's Attest.status and ATTEST_REQUIRED (W15)."""
        return bool(self.attest_required) and snapshot_status == ARMED

    # WINDOW_MIN_FILL (section 3.1, L9): fast ceil(W/2); mid and slow ceil(2W/3)
    @property
    def min_fill_fast(self):
        return ceil_div(self.p_fast_window, 2)

    @property
    def min_fill_mid(self):
        return ceil_div(2 * self.p_mid_window, 3)

    @property
    def min_fill_slow(self):
        return ceil_div(2 * self.p_slow_window, 3)

    def class_range(self, term_class):
        """classRange(termClass) as (lo, hi) with lo <= d <= hi, or None for an invalid class."""
        if term_class not in (0, 1, 2):
            return None
        return (self.class_min[term_class], self.class_max[term_class])

    @classmethod
    def regtest(cls, start_height, sigma_ref_bps=0, supply_cap_bps=0, enforce_until=0, attest_arm_min=3,
                bundle_carrier=CARRIER_SCRIPTSIG):
        return cls(
            network='regtest', start_height=start_height, sigma_ref_bps=sigma_ref_bps,
            supply_cap_bps=supply_cap_bps, enforce_until=enforce_until,
            attest_arm_min=attest_arm_min, bundle_carrier=bundle_carrier,
            p_fast_window=8, p_mid_window=24, p_slow_window=64,
            signal_window=64, activation_threshold=48, participation_floor=39, activation_delay=64,
            enforcement_floor=32, enforcement_resume=39, valve_blocks=6, abandon_blocks=128,
            n_reg=24, n_penalty=12, peer_lag=4, peer_min=3, deviation_bps=1000, accuracy_band_bps=300,
            accuracy_window=24, payee_tilt_bps=10_000, payee_window=10,
            fee_min=50_000_000, fee_bps=25, grace=24, claim_threshold_bps=11_000,
            global_ratio_halt_bps=25_000, divergence_bps=2_000,
            # class A [48, 96], B (96, 144], C (144, 240]  (section 3.1 regtest column)
            class_min=[48, 97, 145], class_max=[96, 144, 240], base_ratio_bps=[50_000, 40_000, 30_000],
            vol_window=64, vol_step=8, vol_periods_per_year=8_760, sigma_mult_max_bps=30_000,
            min_mint=10_000, max_mint=1_000_000, min_output=100, max_output=10_000_000,
            token_value=10_000, yellowback_fee=1_000, ref_window=40, ref_lag=2, attest=cls.REGTEST_ATTEST)

    @classmethod
    def mainnet(cls, start_height, enforce_until, network='main'):
        return cls(
            network=network, start_height=start_height, sigma_ref_bps=10_000,
            supply_cap_bps=1_500, enforce_until=enforce_until,
            p_fast_window=96, p_mid_window=576, p_slow_window=2_016,
            signal_window=2_016, activation_threshold=1_512, participation_floor=1_210, activation_delay=2_016,
            enforcement_floor=1_008, enforcement_resume=1_210, valve_blocks=6, abandon_blocks=4_032,
            n_reg=576, n_penalty=288, peer_lag=10, peer_min=5, deviation_bps=1000, accuracy_band_bps=300,
            accuracy_window=576, payee_tilt_bps=10_000, payee_window=100,
            fee_min=50_000_000, fee_bps=25, grace=34_560, claim_threshold_bps=11_000,
            global_ratio_halt_bps=25_000, divergence_bps=2_000,
            # class A [34,560, 103,680], B (103,680, 420,480], C (420,480, 2,102,400]
            class_min=[34_560, 103_681, 420_481], class_max=[103_680, 420_480, 2_102_400],
            base_ratio_bps=[50_000, 40_000, 30_000],
            vol_window=2_016, vol_step=48, vol_periods_per_year=8_760, sigma_mult_max_bps=30_000,
            min_mint=10_000, max_mint=1_000_000, min_output=100, max_output=10_000_000,
            token_value=10_000, yellowback_fee=1_000, ref_window=40, ref_lag=2)


def params_from_getinfo(info):
    """Params from a ``yed_getinfo`` result (section 4.5): the hashed values from ``params`` (the four
    v2 ones plus v3's ``attest.armMin`` and ``attest.carrierMode``), everything else from the
    network's compiled-in table (the regtest table for regtest)."""
    p = info['params']
    network = info.get('network', 'regtest')
    attest = p.get('attest', {})
    carrier = {v: k for k, v in CARRIER_NAMES.items()}[attest.get('carrierMode', 'scriptsig')]
    if network == 'regtest':
        params = Params.regtest(int(p['startHeight']),
                                sigma_ref_bps=int(p.get('sigmaRefBps', 0)),
                                supply_cap_bps=int(p.get('supplyCapBps', 0)),
                                enforce_until=int(p.get('enforceUntilHeight', 0) or 0),
                                attest_arm_min=int(attest.get('armMin', 3)),
                                bundle_carrier=carrier)
    else:
        params = Params.mainnet(int(p['startHeight']), int(p.get('enforceUntilHeight', 0) or 0),
                                network=network)
        params.sigma_ref_bps = int(p.get('sigmaRefBps', params.sigma_ref_bps))
        params.supply_cap_bps = int(p.get('supplyCapBps', params.supply_cap_bps))
    return params


# ---------------------------------------------------------------------------
# Arithmetic helpers (section 3.7 conventions)

U256_MASK = (1 << 256) - 1


def u256(x):
    """arith_uint256 wrap-around: every product/sum section 3.7 computes in arith_uint256."""
    return x & U256_MASK


def ceil_div(a, b):
    return -((-a) // b)


def isqrt(x):
    return math.isqrt(x)


def lower_median(values):
    """lowerMedian(S): the element at 0-based index floor((n-1)/2) of the sorted values; None if empty."""
    if not values:
        return None
    s = sorted(values)
    return s[(len(s) - 1) // 2]


def clamp(x, lo, hi):
    return lo if x < lo else hi if x > hi else x


def sigma_mult_bps(samples, sigma_ref_bps, periods_per_year, max_bps):
    """SIGMA-1.  samples = [s_0, s_1, ..., s_n] (n returns); any None => max_bps (K12);
    sigma_ref_bps == 0 => 10,000 (regtest: multiplier fixed at 1)."""
    if sigma_ref_bps == 0:
        return BPS
    if any(s is None for s in samples):
        return max_bps
    n = len(samples) - 1
    if n <= 0:
        return max_bps
    acc = 0
    for k in range(n):
        a, b = samples[k], samples[k + 1]
        r = u256(abs(a - b) * BPS) // b          # b >= PRICE_MIN > 0
        acc = u256(acc + u256(r * r))
    var = acc // n
    sigma_annual = isqrt(u256(var * periods_per_year))
    return clamp(u256(sigma_annual * BPS) // sigma_ref_bps, BPS, max_bps)


def min_ratio_bps(base_ratio_bps, sigma_mult):
    return (base_ratio_bps * sigma_mult) // BPS


def required_zat(cents, min_ratio, p_mint):
    """requiredZat = ceil(cents * minRatioBps * COIN / pMint); None when unsatisfiable (> MAX_MONEY, K14)
    or when pMint is undefined."""
    if p_mint is None or p_mint <= 0:
        return None
    q = ceil_div(u256(cents * min_ratio * COIN), p_mint)
    if q > MAX_MONEY:
        return None
    return q


def cap_cents(issued_zat, p_mint):
    if p_mint is None:
        return None
    return u256(issued_zat * p_mint) // (COIN * BPS)


def supply_cap_cents(issued_zat, p_mint, cap_bps):
    if cap_bps == 0:
        return None
    c = cap_cents(issued_zat, p_mint)
    if c is None:
        return None
    return u256(c * cap_bps) // BPS


def global_ratio_bps(collateral_zat, p_mint, supply_cents):
    if p_mint is None or supply_cents <= 0:
        return None
    return u256(collateral_zat * p_mint) // (COIN * supply_cents)


def is_underwater(collateral_zat, p_claim, minted_cents, threshold_bps):
    if p_claim is None:
        return False
    return u256(collateral_zat * p_claim) < u256(minted_cents * threshold_bps * COIN)


def attest_fee_zat(fee, attest_fee_bps):
    """attestFeeZat = feeZat * ATTEST_FEE_BPS / 10^4 (floor; AFEE-1)."""
    if fee <= 0 or attest_fee_bps <= 0:
        return 0
    return (fee * attest_fee_bps) // BPS


def claimant_max_zat(minted_cents, margin_bps, p_claim):
    """ceil(mintedCents * marginBps * COIN / pClaim) (R5); None if undefined or over MAX_MONEY."""
    if minted_cents <= 0 or margin_bps <= 0 or p_claim is None or p_claim <= 0:
        return None
    z = ceil_div(minted_cents * margin_bps * COIN, p_claim)
    return z if z <= MAX_MONEY else None


def residual_zat(collateral_zat, claimant_max):
    """max(0, collateralZat - claimantMaxZat); nothing when claimantMax is undefined (RED-5)."""
    if claimant_max is None or collateral_zat <= claimant_max:
        return 0
    return collateral_zat - claimant_max


def fee_zat(collateral_zat, fee_min, fee_bps):
    return max(fee_min, (collateral_zat * fee_bps) // BPS)


# ---------------------------------------------------------------------------
# Hashing, base58, secp256k1 key validity

def sha256(b):
    return hashlib.sha256(b).digest()


def hash256(b):
    return sha256(sha256(b))


def _ripemd160_py(msg):
    """Pure-Python RIPEMD-160, used only when hashlib lacks it."""
    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    f = [lambda x, y, z: x ^ y ^ z,
         lambda x, y, z: (x & y) | (~x & z),
         lambda x, y, z: (x | ~y) ^ z,
         lambda x, y, z: (x & z) | (y & ~z),
         lambda x, y, z: x ^ (y | ~z)]
    K = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    KK = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
    R = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
         7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
         3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
         1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
         4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
    RR = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
          6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
          15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
          8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
          12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
    S = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
         7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
         11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
         11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
         9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
    SS = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
          9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
          9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
          15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
          8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    ml = len(msg)
    msg = msg + b'\x80' + b'\x00' * ((55 - ml) % 64) + struct.pack('<Q', ml * 8)
    for off in range(0, len(msg), 64):
        X = list(struct.unpack('<16I', msg[off:off + 64]))
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            rnd = j // 16
            t = (rol((al + f[rnd](bl, cl, dl) + X[R[j]] + K[rnd]) & 0xFFFFFFFF, S[j]) + el) & 0xFFFFFFFF
            al, el, dl, cl, bl = el, dl, rol(cl, 10), bl, t
            t = (rol((ar + f[4 - rnd](br, cr, dr) + X[RR[j]] + KK[rnd]) & 0xFFFFFFFF, SS[j]) + er) & 0xFFFFFFFF
            ar, er, dr, cr, br = er, dr, rol(cr, 10), br, t
        t = (h[1] + cl + dr) & 0xFFFFFFFF
        h[1] = (h[2] + dl + er) & 0xFFFFFFFF
        h[2] = (h[3] + el + ar) & 0xFFFFFFFF
        h[3] = (h[4] + al + br) & 0xFFFFFFFF
        h[4] = (h[0] + bl + cr) & 0xFFFFFFFF
        h[0] = t
    return struct.pack('<5I', *h)


def ripemd160(b):
    try:
        return hashlib.new('ripemd160', b).digest()
    except ValueError:
        return _ripemd160_py(b)


def hash160(b):
    return ripemd160(sha256(b))


_B58 = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def base58check_encode(payload):
    data = payload + hash256(payload)[:4]
    n = int.from_bytes(data, 'big')
    out = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        out.append(_B58[r])
    for c in data:
        if c == 0:
            out.append(_B58[0])
        else:
            break
    return bytes(reversed(out)).decode('ascii')


def base58check_decode(s):
    """Returns the payload (version bytes + body) or None on a bad checksum / character."""
    n = 0
    for ch in s.encode('ascii'):
        idx = _B58.find(bytes([ch]))
        if idx < 0:
            return None
        n = n * 58 + idx
    body = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''
    pad = 0
    for ch in s:
        if ch == '1':
            pad += 1
        else:
            break
    data = b'\x00' * pad + body
    if len(data) < 4 or hash256(data[:-4])[:4] != data[-4:]:
        return None
    return data[:-4]


def address_key_hash(addr):
    """The trailing 20 bytes of a Base58Check address (any version), or None."""
    payload = base58check_decode(addr)
    if payload is None or len(payload) < 20:
        return None
    return payload[-20:]


_SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


def is_valid_compressed_pubkey(b):
    """CPubKey::IsFullyValid for a 33-byte compressed key: prefix 02/03, x < p, x^3 + 7 a square."""
    if len(b) != 33 or b[0] not in (2, 3):
        return False
    x = int.from_bytes(b[1:], 'big')
    if x >= _SECP_P:
        return False
    rhs = (pow(x, 3, _SECP_P) + 7) % _SECP_P
    y = pow(rhs, (_SECP_P + 1) // 4, _SECP_P)
    return (y * y) % _SECP_P == rhs


# ---------------------------------------------------------------------------
# Script helpers (section 3.4)

def script_num(n):
    """CScriptNum::serialize (minimal, little-endian, sign bit)."""
    if n == 0:
        return b''
    neg = n < 0
    a = abs(n)
    out = bytearray()
    while a:
        out.append(a & 0xFF)
        a >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if neg else 0x00)
    elif neg:
        out[-1] |= 0x80
    return bytes(out)


def push(data):
    """CScript << std::vector<unsigned char>: the canonical push for the length."""
    n = len(data)
    if n < OP_PUSHDATA1:
        return bytes([n]) + data
    if n <= 0xFF:
        return bytes([OP_PUSHDATA1, n]) + data
    if n <= 0xFFFF:
        return bytes([OP_PUSHDATA2]) + struct.pack('<H', n) + data
    return bytes([OP_PUSHDATA4]) + struct.pack('<I', n) + data


def push_int(n):
    """CScript << int64_t: OP_0, OP_1NEGATE, OP_1..OP_16 or a CScriptNum push."""
    if n == 0:
        return bytes([OP_0])
    if n == -1:
        return bytes([OP_1NEGATE])
    if 1 <= n <= 16:
        return bytes([OP_1 + n - 1])
    return push(script_num(n))


def height_prefix(height):
    """The BIP34 height push ``CScript() << nHeight`` (ref/ycash/src/main.cpp:4477)."""
    return push_int(height)


def vault_script(lock_height, owner_pubkey, claim_height):
    return (bytes([OP_IF]) + push_int(lock_height) + bytes([OP_CHECKLOCKTIMEVERIFY, OP_DROP])
            + push(owner_pubkey) + bytes([OP_CHECKSIG, OP_ELSE]) + push_int(claim_height)
            + bytes([OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_1, OP_ENDIF]))


def p2sh_script(redeem_script):
    return bytes([OP_HASH160, 20]) + hash160(redeem_script) + bytes([OP_EQUAL])


def p2pkh_script(key_hash):
    return bytes([OP_DUP, OP_HASH160, 20]) + key_hash + bytes([OP_EQUALVERIFY, OP_CHECKSIG])


def is_p2sh(spk):
    return len(spk) == 23 and spk[0] == OP_HASH160 and spk[1] == 20 and spk[22] == OP_EQUAL


def p2sh_hash(spk):
    return spk[2:22] if is_p2sh(spk) else None


def p2pkh_key(spk):
    """The 20-byte key hash of a P2PKH scriptPubKey, or None."""
    if (len(spk) == 25 and spk[0] == OP_DUP and spk[1] == OP_HASH160 and spk[2] == 20
            and spk[23] == OP_EQUALVERIFY and spk[24] == OP_CHECKSIG):
        return spk[3:23]
    return None


def parse_pushes(script):
    """The pushed values of a push-only script (CScript::IsPushOnly: every opcode <= OP_16),
    or None if the script is not push-only or is truncated.  OP_RESERVED (0x50) is counted as
    push-only by IsPushOnly but pushes nothing and fails evaluation; this reader treats it as
    not push-only (the conservative reading; see SERIALISATION.md, ambiguity list)."""
    pushes = []
    i, n = 0, len(script)
    while i < n:
        op = script[i]
        i += 1
        if op <= 0x4b:
            size = op
        elif op == OP_PUSHDATA1:
            if i + 1 > n:
                return None
            size = script[i]
            i += 1
        elif op == OP_PUSHDATA2:
            if i + 2 > n:
                return None
            size = struct.unpack('<H', script[i:i + 2])[0]
            i += 2
        elif op == OP_PUSHDATA4:
            if i + 4 > n:
                return None
            size = struct.unpack('<I', script[i:i + 4])[0]
            i += 4
        elif op == OP_1NEGATE:
            pushes.append(b'\x81')
            continue
        elif OP_1 <= op <= OP_16:
            pushes.append(bytes([op - OP_1 + 1]))
            continue
        else:
            return None
        if i + size > n:
            return None
        pushes.append(bytes(script[i:i + size]))
        i += size
    return pushes


def cast_to_bool(v):
    """CastToBool: false for empty and for negative zero (0x80 with all other bytes zero)."""
    for i, c in enumerate(v):
        if c != 0:
            if i == len(v) - 1 and c == 0x80:
                return False
            return True
    return False


def spend_path(script_sig):
    """Path detection (section 3.4): the selector is the push before the redeem-script push.
    Returns 'owner', 'claim', or None when the scriptSig is not push-only / has < 2 pushes (RED-1 fails)."""
    pushes = parse_pushes(script_sig)
    if pushes is None or len(pushes) < 2:
        return None
    return 'owner' if cast_to_bool(pushes[-2]) else 'claim'


def script_single_push(script):
    """If ``script`` is exactly ``OP_RETURN <one push>`` return the pushed data, else None.
    Any GetOp-valid push encoding is accepted (the canonical one is what the wallet writes)."""
    if len(script) < 2 or script[0] != OP_RETURN:
        return None
    pushes = parse_pushes(script[1:])
    if pushes is None or len(pushes) != 1:
        return None
    # parse_pushes accepts OP_1..OP_16 / OP_1NEGATE as pushes; those are not "a push of 4..80 bytes"
    op = script[1]
    if not (1 <= op <= OP_PUSHDATA4):
        return None
    return pushes[0]


# ---------------------------------------------------------------------------
# section 3.2  Coinbase tag codec

class Tag(object):
    __slots__ = ('version', 'flags', 'price_micro_usd', 'source_mask', 'payout_key')

    def __init__(self, version, flags, price_micro_usd, source_mask, payout_key):
        self.version = version
        self.flags = flags
        self.price_micro_usd = price_micro_usd
        self.source_mask = source_mask
        self.payout_key = payout_key

    @property
    def signal(self):
        return bool(self.flags & 1)

    @property
    def is_quote(self):
        return self.price_micro_usd > 0

    @property
    def kind(self):
        return 'quote' if self.is_quote else 'signal'

    def __eq__(self, other):
        return isinstance(other, Tag) and self.as_tuple() == other.as_tuple()

    def as_tuple(self):
        return (self.version, self.flags, self.price_micro_usd, self.source_mask, self.payout_key)

    def __repr__(self):
        return 'Tag(v=%d flags=%d price=%d mask=%d key=%s)' % (
            self.version, self.flags, self.price_micro_usd, self.source_mask, self.payout_key.hex())


def encode_tag(flags, price_micro_usd, source_mask, payout_key, version=TAG_VERSION):
    """The 36-byte tag body."""
    assert len(payout_key) == 20
    return (TAG_MAGIC + bytes([version & 0xFF, flags & 0xFF]) + struct.pack('<Q', price_micro_usd)
            + struct.pack('<H', source_mask) + payout_key)


def tag_push(flags, price_micro_usd, source_mask, payout_key, version=TAG_VERSION):
    """``0x24 || 36 bytes`` (what a miner appends to the coinbase scriptSig after the height push)."""
    return b'\x24' + encode_tag(flags, price_micro_usd, source_mask, payout_key, version)


def tag_is_valid(tag, params):
    """TAG-2."""
    return (tag.version == TAG_VERSION and (tag.flags & 0xFE) == 0
            and (tag.price_micro_usd == 0
                 or params.price_min <= tag.price_micro_usd <= params.price_max))


def find_tag(script_sig, height, params):
    """TAG-1..5: skip ``CScript() << height``, find the first ``24 59 45 44 21``, read the 32 bytes
    after it, apply TAG-2.  Returns a valid Tag or None (invalid tag == no tag; never scans past
    the first occurrence, TAG-5)."""
    prefix = height_prefix(height)
    if len(script_sig) < len(prefix):
        return None
    rest = bytes(script_sig[len(prefix):])
    pos = rest.find(TAG_PATTERN)
    if pos < 0:
        return None
    body = rest[pos + len(TAG_PATTERN):pos + len(TAG_PATTERN) + 32]
    if len(body) < 32:
        return None
    version = body[0]
    flags = body[1]
    price = struct.unpack('<Q', body[2:10])[0]
    mask = struct.unpack('<H', body[10:12])[0]
    key = body[12:32]
    tag = Tag(version, flags, price, mask, key)
    if not tag_is_valid(tag, params):
        return None
    return tag


# ---------------------------------------------------------------------------
# section 3.3  Payload codec

class Payload(object):
    """A well-formed payload.  type in PAYLOAD_TYPE_NAMES."""
    __slots__ = ('type', 'term_class', 'cents', 'lock_height', 'ref_height', 'owner_pubkey',
                 'fee_vout', 'attest_fee_vout', 'assignments',
                 'attestor_pubkey', 'bond_pubkey', 'bond_locktime', 'flags',
                 'vault_txid', 'vault_vout', 'seq', 'price_micro_usd', 'cited_height', 'sig')

    def __init__(self, type_):
        self.type = type_
        self.term_class = None
        self.cents = None
        self.lock_height = None
        self.ref_height = None
        self.owner_pubkey = None
        self.fee_vout = None
        self.attest_fee_vout = None
        self.assignments = []      # list of (vout, cents)
        # ATTESTOR_REGISTER
        self.attestor_pubkey = None
        self.bond_pubkey = None
        self.bond_locktime = None
        self.flags = None
        # CLAIM_NOTICE (vault_txid is display-order hex, as everywhere in the model)
        self.vault_txid = None
        self.vault_vout = None
        # ATTESTOR_REVIVE
        self.seq = None
        self.price_micro_usd = None
        self.cited_height = None
        self.sig = None

    @property
    def type_name(self):
        return PAYLOAD_TYPE_NAMES[self.type]


def encode_mint(term_class, cents, lock_height, ref_height, owner_pubkey, fee_vout, attest_fee_vout=FEE_VOUT_NONE):
    assert len(owner_pubkey) == 33
    return (PAYLOAD_MAGIC + bytes([PAYLOAD_VERSION, PAYLOAD_MINT, term_class & 0xFF])
            + struct.pack('<III', cents, lock_height, ref_height) + owner_pubkey
            + bytes([fee_vout & 0xFF, attest_fee_vout & 0xFF]))


def encode_transfer(assignments):
    out = PAYLOAD_MAGIC + bytes([PAYLOAD_VERSION, PAYLOAD_TRANSFER, len(assignments)])
    for vout, cents in assignments:
        out += bytes([vout & 0xFF]) + struct.pack('<I', cents)
    return out


def encode_redeem(ref_height, fee_vout, assignments, attest_fee_vout=FEE_VOUT_NONE):
    out = (PAYLOAD_MAGIC + bytes([PAYLOAD_VERSION, PAYLOAD_REDEEM]) + struct.pack('<I', ref_height)
           + bytes([fee_vout & 0xFF, attest_fee_vout & 0xFF, len(assignments)]))
    for vout, cents in assignments:
        out += bytes([vout & 0xFF]) + struct.pack('<I', cents)
    return out


def decode_payload(data, n_vout=None, opret_index=None):
    """Decode a payload body (the data of the OP_RETURN push).  Returns a Payload, or None when the
    body is malformed or of an unknown type/version (non-Yellowback).  With ``n_vout`` and
    ``opret_index`` the assignment checks of section 3.3 (vout in range, no duplicate, not the
    OP_RETURN, cents != 0) are applied too; without them only the byte-level shape is checked."""
    if len(data) < 4 or len(data) > MAX_PAYLOAD:
        return None
    if data[0:2] != PAYLOAD_MAGIC or data[2] != PAYLOAD_VERSION:
        return None
    t = data[3]
    body = data[4:]
    if t == PAYLOAD_MINT:
        if len(body) != 48:
            return None
        p = Payload(PAYLOAD_MINT)
        p.term_class = body[0]
        p.cents, p.lock_height, p.ref_height = struct.unpack('<III', body[1:13])
        p.owner_pubkey = bytes(body[13:46])
        p.fee_vout = body[46]
        p.attest_fee_vout = body[47]
        return p
    if t == PAYLOAD_ATTESTOR_REGISTER:
        if len(body) != 71:
            return None
        p = Payload(t)
        p.attestor_pubkey = bytes(body[0:33])
        p.bond_pubkey = bytes(body[33:66])
        p.bond_locktime = struct.unpack('<I', body[66:70])[0]
        p.flags = body[70]
        return p
    if t == PAYLOAD_CLAIM_NOTICE:
        if len(body) != 37:
            return None
        p = Payload(t)
        p.vault_txid = bytes(body[0:32])[::-1].hex()
        p.vault_vout = body[32]
        p.ref_height = struct.unpack('<I', body[33:37])[0]
        return p
    if t == PAYLOAD_EQUIVOCATION:
        if len(body) != 0:
            return None
        return Payload(t)
    if t == PAYLOAD_ATTESTOR_REVIVE:
        if len(body) != 74:
            return None
        p = Payload(t)
        p.seq, p.price_micro_usd, p.cited_height = struct.unpack('<HII', body[0:10])
        p.sig = bytes(body[10:74])
        return p
    if t == PAYLOAD_TRANSFER:
        if len(body) < 1:
            return None
        count = body[0]
        if len(body) != 1 + 5 * count:
            return None
        p = Payload(PAYLOAD_TRANSFER)
        rest = body[1:]
    elif t == PAYLOAD_REDEEM:
        if len(body) < 7:
            return None
        p = Payload(PAYLOAD_REDEEM)
        p.ref_height = struct.unpack('<I', body[0:4])[0]
        p.fee_vout = body[4]
        p.attest_fee_vout = body[5]
        count = body[6]
        if len(body) != 7 + 5 * count:
            return None
        rest = body[7:]
    else:
        return None
    seen = set()
    for i in range(count):
        vout = rest[5 * i]
        cents = struct.unpack('<I', rest[5 * i + 1:5 * i + 5])[0]
        if cents == 0 or vout in seen:
            return None
        if n_vout is not None and vout >= n_vout:
            return None
        if opret_index is not None and vout == opret_index:
            return None
        seen.add(vout)
        p.assignments.append((vout, cents))
    return p


def tx_payload(vout_scripts):
    """The payload of a transaction given its scriptPubKeys: (Payload, opReturnIndex) when the
    transaction has exactly one OP_RETURN output of the section 3.3 shape carrying a well-formed
    payload, else (None, opReturnIndex-or-None) -- a non-Yellowback transaction."""
    opret = [i for i, s in enumerate(vout_scripts) if len(s) >= 1 and s[0] == OP_RETURN]
    if len(opret) != 1:
        return None, None
    idx = opret[0]
    data = script_single_push(vout_scripts[idx])
    if data is None:
        return None, idx
    return decode_payload(data, n_vout=len(vout_scripts), opret_index=idx), idx


# ---------------------------------------------------------------------------
# Transactions: the model's normalised shape, getblock-2 JSON and raw hex

class TxIn(object):
    __slots__ = ('prev_txid', 'prev_n', 'script_sig', 'sequence')

    def __init__(self, prev_txid, prev_n, script_sig, sequence=0xFFFFFFFF):
        self.prev_txid = prev_txid      # display-order hex, or None for a coinbase input
        self.prev_n = prev_n
        self.script_sig = script_sig    # bytes
        self.sequence = sequence


class TxOut(object):
    __slots__ = ('value', 'script')

    def __init__(self, value, script):
        self.value = value              # zat
        self.script = script            # bytes


class Tx(object):
    """A transaction as the model reads it: txid (display-order hex), transparent inputs, outputs."""
    __slots__ = ('txid', 'vin', 'vout', 'lock_time', 'expiry_height')

    def __init__(self, txid, vin, vout, lock_time=0, expiry_height=0):
        self.txid = txid
        self.vin = vin
        self.vout = vout
        self.lock_time = lock_time
        self.expiry_height = expiry_height

    @property
    def is_coinbase(self):
        return len(self.vin) == 1 and self.vin[0].prev_txid is None


def _zat(out):
    if 'valueZat' in out:
        return int(out['valueZat'])
    if 'valueSat' in out:
        return int(out['valueSat'])
    return int((Decimal(str(out['value'])) * COIN).to_integral_value())


def tx_from_json(d):
    """From a ``getblock <hash> 2`` / ``getrawtransaction <txid> 1`` transaction object."""
    vin = []
    for i in d['vin']:
        if 'coinbase' in i:
            vin.append(TxIn(None, 0xFFFFFFFF, bytes.fromhex(i['coinbase']), int(i.get('sequence', 0xFFFFFFFF))))
        else:
            vin.append(TxIn(i['txid'], int(i['vout']), bytes.fromhex(i['scriptSig']['hex']),
                            int(i.get('sequence', 0xFFFFFFFF))))
    vout = [TxOut(_zat(o), bytes.fromhex(o['scriptPubKey']['hex'])) for o in d['vout']]
    return Tx(d['txid'], vin, vout, int(d.get('locktime', 0)), int(d.get('expiryheight', 0)))


def _read_compact(b, i):
    n = b[i]
    i += 1
    if n < 253:
        return n, i
    if n == 253:
        return struct.unpack('<H', b[i:i + 2])[0], i + 2
    if n == 254:
        return struct.unpack('<I', b[i:i + 4])[0], i + 4
    return struct.unpack('<Q', b[i:i + 8])[0], i + 8


def _compact(n):
    if n < 253:
        return bytes([n])
    if n < 0x10000:
        return b'\xfd' + struct.pack('<H', n)
    if n < 0x100000000:
        return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)


def tx_from_hex(h):
    """Parse a raw v4 (Sapling) or pre-Overwinter transaction; shielded components are skipped
    (TX-0).  Only what the model reads is kept."""
    b = bytes.fromhex(h)
    txid = hash256(b)[::-1].hex()
    header = struct.unpack('<I', b[0:4])[0]
    overwintered = bool(header >> 31)
    version = header & 0x7FFFFFFF
    i = 4
    if overwintered:
        i += 4  # nVersionGroupId
    n, i = _read_compact(b, i)
    vin = []
    for _ in range(n):
        prev = b[i:i + 32][::-1].hex()
        pn = struct.unpack('<I', b[i + 32:i + 36])[0]
        i += 36
        sl, i = _read_compact(b, i)
        ss = b[i:i + sl]
        i += sl
        seq = struct.unpack('<I', b[i:i + 4])[0]
        i += 4
        is_cb = prev == '00' * 32 and pn == 0xFFFFFFFF
        vin.append(TxIn(None if is_cb else prev, pn, ss, seq))
    n, i = _read_compact(b, i)
    vout = []
    for _ in range(n):
        val = struct.unpack('<q', b[i:i + 8])[0]
        i += 8
        sl, i = _read_compact(b, i)
        vout.append(TxOut(val, b[i:i + sl]))
        i += sl
    lock_time = struct.unpack('<I', b[i:i + 4])[0]
    i += 4
    expiry = 0
    if overwintered:
        expiry = struct.unpack('<I', b[i:i + 4])[0]
        i += 4
    # the rest (valueBalance, shielded spends/outputs, joinsplits, signatures) is ignored
    _ = version
    return Tx(txid, vin, vout, lock_time, expiry)


def serialize_tx_v4(vin, vout, lock_time=0, expiry_height=0):
    """A transparent-only Sapling (v4) transaction: what the wallet builds on every network today.
    vin: [(prev_txid_hex or None, n, script_sig_bytes, sequence)], vout: [(value, script)]."""
    r = struct.pack('<I', (1 << 31) | SAPLING_TX_VERSION) + struct.pack('<I', SAPLING_VERSION_GROUP_ID)
    r += _compact(len(vin))
    for prev, n, ss, seq in vin:
        r += (bytes(32) if prev is None else bytes.fromhex(prev)[::-1]) + struct.pack('<I', n)
        r += _compact(len(ss)) + ss + struct.pack('<I', seq)
    r += _compact(len(vout))
    for val, s in vout:
        r += struct.pack('<q', val) + _compact(len(s)) + s
    r += struct.pack('<I', lock_time) + struct.pack('<I', expiry_height)
    r += struct.pack('<q', 0)       # valueBalance
    r += _compact(0) + _compact(0)  # vShieldedSpend, vShieldedOutput
    r += _compact(0)                # vJoinSplit
    return r


# ---------------------------------------------------------------------------
# Regtest subsidy schedule (ref/ycash/src/main.cpp GetBlockSubsidy, consensus/params.cpp Halving)

def regtest_subsidy(height, blossom_height=1):
    """GetBlockSubsidy on regtest: slow start 0, pre-Blossom halving 144, post 288, Blossom at
    ``blossom_height`` (the functional tests activate every upgrade at 1)."""
    n = 125 * COIN // 10
    if blossom_height is not None and height >= blossom_height:
        scaled = (blossom_height * 2) + (height - blossom_height)
        halvings = scaled // 288
        if halvings >= 64:
            return 0
        return (n // 2) >> halvings
    halvings = height // 144
    if halvings >= 64:
        return 0
    return n >> halvings


# ---------------------------------------------------------------------------
# The state (section 3.6)

class TagRecord(object):
    __slots__ = ('payout_key', 'price_micro_usd', 'signal', 'source_mask')

    def __init__(self, payout_key, price_micro_usd, signal, source_mask):
        self.payout_key = payout_key
        self.price_micro_usd = price_micro_usd
        self.signal = signal
        self.source_mask = source_mask

    @property
    def is_quote(self):
        return self.price_micro_usd > 0


class Judgement(object):
    __slots__ = ('evaluated', 'in_band', 'penalized')

    def __init__(self, evaluated=False, in_band=False, penalized=False):
        self.evaluated = evaluated
        self.in_band = in_band
        self.penalized = penalized


class Activation(object):
    __slots__ = ('status', 'lock_in_height', 'activate_height')

    def __init__(self, status=SIGNALING, lock_in_height=0, activate_height=0):
        self.status = status
        self.lock_in_height = lock_in_height
        self.activate_height = activate_height

    def copy(self):
        return Activation(self.status, self.lock_in_height, self.activate_height)

    def as_dict(self):
        return {'status': ACTIVATION_NAMES[self.status], 'lockInHeight': self.lock_in_height,
                'activateHeight': self.activate_height}


class Vault(object):
    __slots__ = ('owner_pubkey', 'term_class', 'lock_height', 'claim_height', 'collateral_zat',
                 'minted_cents', 'mint_height', 'ref_height', 'status', 'void_reason',
                 'close_height', 'closing_txid', 'burned_cents', 'fee_paid_zat', 'unbacked')

    def __init__(self):
        self.owner_pubkey = b''
        self.term_class = 0
        self.lock_height = 0
        self.claim_height = 0
        self.collateral_zat = 0
        self.minted_cents = 0
        self.mint_height = 0
        self.ref_height = 0
        self.status = V_VOID
        self.void_reason = ''
        self.close_height = 0
        self.closing_txid = None      # display-order hex or None
        self.burned_cents = 0
        self.fee_paid_zat = 0
        self.unbacked = False

    def as_dict(self, outpoint):
        return {'txid': outpoint[0], 'vout': outpoint[1], 'status': VAULT_STATUS_NAMES[self.status],
                'ownerPubKey': self.owner_pubkey.hex(), 'termClass': 'ABC'[self.term_class] if self.term_class < 3 else self.term_class,
                'lockHeight': self.lock_height, 'claimHeight': self.claim_height,
                'collateralZat': self.collateral_zat, 'mintedCents': self.minted_cents,
                'mintHeight': self.mint_height, 'refHeight': self.ref_height,
                'feePaidZat': self.fee_paid_zat, 'closeHeight': self.close_height,
                'closingTxid': self.closing_txid, 'burnedCents': self.burned_cents,
                'unbacked': self.unbacked, 'voidReason': self.void_reason}


class Token(object):
    __slots__ = ('cents', 'n_value', 'script_pub_key', 'height')

    def __init__(self, cents, n_value, script_pub_key, height):
        self.cents = cents
        self.n_value = n_value
        self.script_pub_key = script_pub_key
        self.height = height


class TxLogRecord(object):
    __slots__ = ('height', 'type', 'path', 'verdict', 'yed_in', 'yed_out', 'burned', 'fee_zat',
                 'payee', 'assigned', 'spent_tokens', 'closed_vaults',
                 'a_mint', 'a_claim', 'bundle_seqs', 'attest_fee_zat', 'attest_payee', 'residual_zat',
                 'claim_path', 'notice', 'attestor_seq')

    def __init__(self, height):
        self.height = height
        self.type = 'NONE'
        self.path = ''
        self.verdict = VERDICT_OK
        self.yed_in = 0
        self.yed_out = 0
        self.burned = 0
        self.fee_zat = 0
        self.payee = None           # 20-byte key hash or None
        self.assigned = []          # [(vout, cents)]
        self.spent_tokens = []      # [(txid, n)]
        self.closed_vaults = []     # [(txid, n)]
        # v3 (section 3.6 TxLog; history, never hashed)
        self.a_mint = None
        self.a_claim = None
        self.bundle_seqs = []       # A, bundle order
        self.attest_fee_zat = 0
        self.attest_payee = None    # seq or None
        self.residual_zat = 0
        self.claim_path = ''        # 'a' | 'b' | ''
        self.notice = False
        self.attestor_seq = None    # REG-A1 assigned / EQV-1 ejected / REV-1 revived

    def as_dict(self, txid):
        return {'txid': txid, 'height': self.height, 'type': self.type, 'path': self.path,
                'verdict': self.verdict, 'yedIn': self.yed_in, 'yedOut': self.yed_out,
                'burned': self.burned, 'feeZat': self.fee_zat,
                'payee': self.payee.hex() if self.payee else None,
                'assigned': [{'vout': v, 'cents': c} for v, c in self.assigned],
                'spentTokens': ['%s:%d' % op for op in self.spent_tokens],
                'closedVaults': ['%s:%d' % op for op in self.closed_vaults],
                'aMint': self.a_mint, 'aClaim': self.a_claim, 'bundleSeqs': list(self.bundle_seqs),
                'attestFeeZat': self.attest_fee_zat, 'attestPayee': self.attest_payee,
                'residualZat': self.residual_zat, 'claimPath': self.claim_path, 'notice': self.notice,
                'attestorSeq': self.attestor_seq}


class Totals(object):
    __slots__ = ('supply_cents', 'collateral_zat', 'active_vaults', 'void_vaults', 'closed_vaults',
                 'claimed_vaults', 'unbacked_cents')

    def __init__(self):
        self.supply_cents = 0
        self.collateral_zat = 0
        self.active_vaults = 0
        self.void_vaults = 0
        self.closed_vaults = 0
        self.claimed_vaults = 0
        self.unbacked_cents = 0

    def as_dict(self):
        return {'supplyCents': self.supply_cents, 'collateralZat': self.collateral_zat,
                'activeVaults': self.active_vaults, 'voidVaults': self.void_vaults,
                'closedVaults': self.closed_vaults, 'claimedVaults': self.claimed_vaults,
                'unbackedCents': self.unbacked_cents}


class AttestorRecord(object):
    """Attestors[seq] (v3 plan section 3.6, REG-A1)."""
    __slots__ = ('attestor_pubkey', 'bond_pubkey', 'bond_outpoint', 'bond_zat', 'bond_locktime', 'flags',
                 'register_height', 'status', 'status_height', 'bond_spent_height', 'seated_since')

    def __init__(self):
        self.attestor_pubkey = b''
        self.bond_pubkey = b''
        self.bond_outpoint = None     # (txid display hex, n)
        self.bond_zat = 0
        self.bond_locktime = 0
        self.flags = 0
        self.register_height = 0
        self.status = A_PENDING
        self.status_height = 0
        self.bond_spent_height = 0
        self.seated_since = 0

    def as_dict(self, seq):
        return {'seq': seq, 'attestorPubKey': self.attestor_pubkey.hex(), 'bondPubKey': self.bond_pubkey.hex(),
                'bondOutpoint': {'txid': self.bond_outpoint[0], 'vout': self.bond_outpoint[1]},
                'bondZat': self.bond_zat, 'bondLocktime': self.bond_locktime, 'flags': self.flags,
                'registerHeight': self.register_height, 'status': ATTESTOR_STATUS_NAMES[self.status],
                'statusHeight': self.status_height,
                'bondSpentHeight': self.bond_spent_height or None, 'seatedSince': self.seated_since or None}


class AttestState(object):
    """The carried Attest record (ARM-1/2); copied into every snapshot."""
    __slots__ = ('status', 'trigger_height', 'arm_height')

    def __init__(self, status=UNARMED, trigger_height=0, arm_height=0):
        self.status = status
        self.trigger_height = trigger_height
        self.arm_height = arm_height

    def copy(self):
        return AttestState(self.status, self.trigger_height, self.arm_height)

    def as_dict(self):
        return {'status': ATTEST_NAMES[self.status], 'triggerHeight': self.trigger_height, 'armHeight': self.arm_height}


class BundleLogRecord(object):
    """BundleLog[height] (R12): the lowerMedian statistics over the height's verified MINT / REDEEM /
    CLAIM_NOTICE bundles, the sorted union of their selected sets and the sorted, deduplicated union of
    their (seq, price) pairs as two parallel arrays."""
    __slots__ = ('a_mint', 'a_claim', 'selected_seqs', 'seqs', 'prices')

    def __init__(self):
        self.a_mint = None
        self.a_claim = None
        self.selected_seqs = []
        self.seqs = []
        self.prices = []


class NoticeRecord(object):
    """Notices[vaultOutpoint] (NOT-1)."""
    __slots__ = ('height', 'ref_height', 'p_emerg')

    def __init__(self, height, ref_height, p_emerg):
        self.height = height
        self.ref_height = ref_height
        self.p_emerg = p_emerg


class Snapshot(object):
    __slots__ = ('block_hash', 'tagged', 'quote', 'signal_count', 'activation', 'p_fast', 'p_mid',
                 'p_slow', 'p_mint', 'p_claim', 'sigma_mult_bps', 'issued_zat', 'supply_cents',
                 'collateral_zat', 'global_ratio_bps', 'halt_mask', 'virtual',
                 'attest', 'seated', 'pinned_keys', 'pinned_seqs')

    def __init__(self):
        self.block_hash = '00' * 32
        self.tagged = False
        self.quote = False
        self.signal_count = 0
        self.activation = Activation()
        self.p_fast = None
        self.p_mid = None
        self.p_slow = None
        self.p_mint = None
        self.p_claim = None
        self.sigma_mult_bps = BPS
        self.issued_zat = 0
        self.supply_cents = 0
        self.collateral_zat = 0
        self.global_ratio_bps = None
        self.halt_mask = 0
        self.virtual = False
        # v3: p_mint / p_claim above are the cross-section medians (xMint / xClaim); the PRICE-2
        # combination with a bundle is per transaction and never stored.
        self.attest = AttestState()
        self.seated = []          # sorted seq
        self.pinned_keys = []     # sorted 20-byte key hashes (PIN-1)
        self.pinned_seqs = []     # sorted seq (PIN-2)

    @classmethod
    def virtual_snapshot(cls):
        """The virtual snapshot below START_HEIGHT (section 3.6)."""
        s = cls()
        s.halt_mask = HALT_NOT_ACTIVE | HALT_NO_PRICE
        s.virtual = True
        return s

    def halt_names(self):
        return [name for bit, name in HALT_NAMES.items() if self.halt_mask & bit]

    def as_dict(self, height):
        return {'height': height, 'blockHash': self.block_hash, 'tagged': self.tagged, 'quote': self.quote,
                'signalCount': self.signal_count, 'activation': self.activation.as_dict(),
                'pFast': self.p_fast, 'pMid': self.p_mid, 'pSlow': self.p_slow,
                'pMint': self.p_mint, 'pClaim': self.p_claim, 'sigmaMultBps': self.sigma_mult_bps,
                'issuedZat': self.issued_zat, 'supplyCents': self.supply_cents,
                'collateralZat': self.collateral_zat, 'globalRatioBps': self.global_ratio_bps,
                'haltMask': self.halt_names(), 'xMint': self.p_mint, 'xClaim': self.p_claim,
                'attest': self.attest.as_dict(), 'seated': list(self.seated),
                'pinnedKeys': [k.hex() for k in self.pinned_keys], 'pinnedSeqs': list(self.pinned_seqs)}


class BlockVerdict(object):
    __slots__ = ('height', 'block_hash', 'block_invalid', 'enforcement_on', 'reason')

    def __init__(self, height, block_hash, block_invalid, enforcement_on, reason):
        self.height = height
        self.block_hash = block_hash
        self.block_invalid = block_invalid
        self.enforcement_on = enforcement_on
        self.reason = reason

    @property
    def rejected(self):
        """What BLK-2 clause 1 would do on an enforcing node outside IBD (ACT-7/L11 aside)."""
        return self.block_invalid and self.enforcement_on


# ---------------------------------------------------------------------------
# Serialisation for the state hash (section 3.6, SERIALISATION.md)

def _u8(v):
    return struct.pack('<B', v & 0xFF)


def _u16(v):
    return struct.pack('<H', v)


def _u32(v):
    return struct.pack('<I', v)


def _i32(v):
    return struct.pack('<i', v)


def _i64(v):
    return struct.pack('<q', v)


def _u64(v):
    return struct.pack('<Q', v)


def _u32be(v):
    return struct.pack('>I', v)


def _bool(v):
    return _u8(1 if v else 0)


def _str(s):
    b = s.encode('utf-8')
    return _compact(len(b)) + b


def _bytes(b):
    return _compact(len(b)) + bytes(b)


def _hash(hex_display):
    """uint256 raw bytes: the internal byte order (the display hex reversed)."""
    if not hex_display:
        return bytes(32)
    return bytes.fromhex(hex_display)[::-1]


def _outpoint_key(prefix, outpoint):
    return prefix + _hash(outpoint[0]) + _u32be(outpoint[1])


def _price(v):
    return _i64(0 if v is None else v)


def _ser_activation(a):
    return _u8(a.status) + _i32(a.lock_in_height) + _i32(a.activate_height)


def _u16_vec(v):
    return _compact(len(v)) + b''.join(_u16(x) for x in v)


def _i64_vec(v):
    return _compact(len(v)) + b''.join(_i64(x) for x in v)


def _ser_attest(a):
    return _u8(a.status) + _i32(a.trigger_height) + _i32(a.arm_height)


def _ser_snapshot(s):
    return (_hash(s.block_hash) + _bool(s.tagged) + _bool(s.quote) + _u32(s.signal_count)
            + _ser_activation(s.activation) + _price(s.p_fast) + _price(s.p_mid) + _price(s.p_slow)
            + _price(s.p_mint) + _price(s.p_claim) + _i32(s.sigma_mult_bps) + _i64(s.issued_zat)
            + _i64(s.supply_cents) + _i64(s.collateral_zat)
            + _i64(0 if s.global_ratio_bps is None else s.global_ratio_bps) + _u32(s.halt_mask)
            + _ser_attest(s.attest) + _u16_vec(s.seated)
            + _compact(len(s.pinned_keys)) + b''.join(bytes(k) for k in s.pinned_keys) + _u16_vec(s.pinned_seqs))


def _ser_attestor(a):
    return (_bytes(a.attestor_pubkey) + _bytes(a.bond_pubkey) + _hash(a.bond_outpoint[0]) + _u32(a.bond_outpoint[1])
            + _i64(a.bond_zat) + _u32(a.bond_locktime) + _u8(a.flags) + _i32(a.register_height) + _u8(a.status)
            + _i32(a.status_height) + _i32(a.bond_spent_height) + _i32(a.seated_since))


def _ser_bundle_log(b):
    return _price(b.a_mint) + _price(b.a_claim) + _u16_vec(b.selected_seqs) + _u16_vec(b.seqs) + _i64_vec(b.prices)


def _ser_notice(n):
    return _i32(n.height) + _i32(n.ref_height) + _i64(n.p_emerg)


def _ser_vault(v):
    return (_bytes(v.owner_pubkey) + _u8(v.term_class) + _i32(v.lock_height) + _i32(v.claim_height)
            + _i64(v.collateral_zat) + _i64(v.minted_cents) + _i32(v.mint_height) + _i32(v.ref_height)
            + _u8(v.status) + _str(v.void_reason) + _i32(v.close_height) + _hash(v.closing_txid)
            + _i64(v.burned_cents) + _i64(v.fee_paid_zat) + _bool(v.unbacked))


def _ser_token(t):
    return _i64(t.cents) + _i64(t.n_value) + _bytes(t.script_pub_key) + _i32(t.height)


def _ser_totals(t):
    return (_i64(t.supply_cents) + _i64(t.collateral_zat) + _u32(t.active_vaults) + _u32(t.void_vaults)
            + _u32(t.closed_vaults) + _u32(t.claimed_vaults) + _i64(t.unbacked_cents))


def _outpoint_sort_key(op):
    return (_hash(op[0]), op[1])


# ---------------------------------------------------------------------------
# The model

class YellowbackModel(object):
    """Section 3 as a state machine fed block by block.  See the module docstring."""

    SCHEMA_VERSION = 3

    def __init__(self, params, issued_before_start=0):
        self.params = params
        self.tip_height = -1
        self.tip_hash = None
        self.tags = {}            # height -> TagRecord
        self.judgements = {}      # height -> Judgement
        self.activation = Activation()
        self.vaults = {}          # (txid, n) -> Vault
        self.tokens = {}          # (txid, n) -> Token
        self.txlog = OrderedDict()  # txid -> TxLogRecord
        self.totals = Totals()
        self.snapshots = {}       # height -> Snapshot
        self.blocks = {}          # height -> BlockVerdict
        # v3 tables (section 3.6)
        self.attestors = {}       # seq -> AttestorRecord
        self.bond_index = {}      # (txid, n) -> seq (derived; not hashed)
        self.attestor_seq = 0     # AttestorSeq.next
        self.attest = AttestState()
        self.bundle_log = {}      # height -> BundleLogRecord
        self.notices = {}         # (txid, n) -> NoticeRecord
        self._bundle_acc = None   # the BundleLog[H] accumulator of the block being fed (R12)
        # issuedZat is carried from the previous snapshot; the virtual snapshot below START_HEIGHT
        # carries ``issued_before_start`` (default 0 = the sum over [START_HEIGHT, H]; see SERIALISATION.md)
        self._issued_below_start = issued_before_start

    # -- lookups ------------------------------------------------------------

    def snapshot(self, height):
        """Snapshots[height]: the virtual snapshot below START_HEIGHT, None when above the tip."""
        if height < self.params.start_height:
            s = Snapshot.virtual_snapshot()
            s.issued_zat = self._issued_below_start
            return s
        return self.snapshots.get(height)

    def txinfo(self, txid):
        rec = self.txlog.get(txid)
        return None if rec is None else rec.as_dict(txid)

    def vault(self, outpoint):
        v = self.vaults.get(outpoint)
        return None if v is None else v.as_dict(outpoint)

    def vault_list(self, status=None):
        rows = []
        for op in sorted(self.vaults, key=_outpoint_sort_key):
            v = self.vaults[op]
            if status is None or VAULT_STATUS_NAMES[v.status] == status.upper():
                rows.append(v.as_dict(op))
        return rows

    vaults_list = vault_list

    def stats(self):
        """The yed_getstats shape (section 4.5) at the tip."""
        s = self.snapshot(self.tip_height) if self.tip_height >= self.params.start_height else None
        d = {'height': self.tip_height}
        d.update(self.totals.as_dict())
        if s is None:
            s = Snapshot.virtual_snapshot()
        d.update({'issuedZat': s.issued_zat, 'pFast': s.p_fast, 'pMid': s.p_mid, 'pSlow': s.p_slow,
                  'pMint': s.p_mint, 'pClaim': s.p_claim, 'sigmaMultBps': s.sigma_mult_bps,
                  'globalRatioBps': s.global_ratio_bps,
                  'supplyCapCents': supply_cap_cents(s.issued_zat, s.p_mint, self.params.supply_cap_bps),
                  'haltMask': s.halt_names(), 'mintingAllowed': s.activation.status == ACTIVE and s.halt_mask == 0})
        return d

    def block_verdict(self, height):
        return self.blocks.get(height)

    def enforcement_on(self, height):
        """ACT-5 at height H, read from Snapshots[H - 1]."""
        prev = self.snapshot(height - 1)
        if prev is None or prev.virtual:
            return False
        if prev.activation.status != ACTIVE or (prev.halt_mask & HALT_ENFORCEMENT):
            return False
        if self.params.enforce_until and height > self.params.enforce_until:
            return False
        return True

    def is_abandoned(self):
        """The section 4.6 predicate (L10, L12): ENFORCEMENT set continuously for ABANDON_BLOCKS at the tip."""
        n = self.params.abandon_blocks
        if self.tip_height - n + 1 < self.params.start_height:
            return False
        for h in range(self.tip_height - n + 1, self.tip_height + 1):
            s = self.snapshots.get(h)
            if s is None or not (s.halt_mask & HALT_ENFORCEMENT):
                return False
        return True

    # -- section 3.7 derived quantities ------------------------------------

    def _quote_prices(self, lo, hi, excluded=()):
        """priceMicroUsd of the quote tags with lo < h <= hi, skipping the keys in `excluded` (PIN-1)."""
        out = []
        for h in range(max(lo + 1, self.params.start_height), hi + 1):
            t = self.tags.get(h)
            if t is not None and t.is_quote and t.payout_key not in excluded:
                out.append(t.price_micro_usd)
        return out

    def median(self, window, min_fill, height, excluded=()):
        vals = self._quote_prices(height - window, height, excluded)
        if len(vals) < min_fill:
            return None
        return lower_median(vals)

    def signal_count(self, height):
        n = 0
        for h in range(max(height - self.params.signal_window + 1, self.params.start_height), height + 1):
            t = self.tags.get(h)
            if t is not None and t.signal:
                n += 1
        return n

    def eligible_payees(self, ref_height):
        """E(R): the payoutKeys of the quote tags at h in (R - PAYEE_WINDOW, R], height order, deduplicated,
        minus Snapshots[R].pinnedKeys (PIN-1)."""
        s = self.snapshots.get(ref_height)
        pinned = s.pinned_keys if s is not None else []
        keys = []
        for h in range(max(ref_height - self.params.payee_window + 1, self.params.start_height), ref_height + 1):
            t = self.tags.get(h)
            if t is not None and t.is_quote and t.payout_key not in keys and t.payout_key not in pinned:
                keys.append(t.payout_key)
        return keys

    # -- v3 section 3.7: arming, weight, seating, selection, BUNDLE-1 ----------

    def armed_at(self, ref_height):
        """"ARMED" for a transaction with refHeight R: Snapshots[R].attest and ATTEST_REQUIRED (W15)."""
        s = self.snapshot(ref_height)
        return s is not None and not s.virtual and self.params.is_armed(s.attest.status)

    def block_hash_at(self, height):
        """blockHash(h) as the overlay knows it (Snapshots[h].blockHash), None below START_HEIGHT or above the tip."""
        s = self.snapshots.get(height)
        return None if s is None else s.block_hash

    def age_origin(self, rec, attest):
        p = self.params
        if attest.status != UNARMED and rec.register_height <= attest.trigger_height + p.founding_window:
            return attest.trigger_height
        return rec.register_height

    def weight(self, rec, attest, height):
        """weight(seq, H) = bondZat * clamp(H - ageOrigin, 0, AGE_CAP)."""
        return rec.bond_zat * clamp(height - self.age_origin(rec, attest), 0, self.params.age_cap)

    def seated(self, height, attest=None):
        """The N_SLOTS ELIGIBLE seq of greatest weight(seq, H), ties by seq; ascending."""
        attest = self.attest if attest is None else attest
        ranked = sorted(((-self.weight(r, attest, height), seq) for seq, r in self.attestors.items() if r.status == A_ELIGIBLE))
        return sorted(seq for _w, seq in ranked[:self.params.n_slots])

    def selected(self, ref_height, selector):
        """selected(R, selector) (W9) over the stored seated minus pinnedSeqs of Snapshots[R]."""
        from . import yellowback_attest as ya
        s = self.snapshots.get(ref_height)
        if s is None:
            return []
        pool = [(seq, self.weight(self.attestors[seq], s.attest, ref_height))
                for seq in s.seated if seq not in s.pinned_seqs and seq in self.attestors]
        return ya.select_attestors(s.block_hash, selector, pool, self.params.m_select, self.params.k_slack)

    def _find_carrier(self, tx, skip_vin0):
        """(vin index, pushes) of the one carrier-shaped input, or (None, reason)."""
        from . import yellowback_attest as ya
        found = None
        for i, vin in enumerate(tx.vin):
            if skip_vin0 and i == 0:
                continue
            pushes = parse_pushes(vin.script_sig)
            if pushes is None or len(pushes) != 3 or ya.parse_carrier_script(pushes[2]) is None:
                continue
            if found is not None:
                return None, 'two-carriers'
            found = (i, pushes)
        if found is None:
            return None, 'shape'
        return found, ''

    def verify_bundle(self, tx, ref_height, selector, skip_vin0):
        """BUNDLE-1 (W8 order) plus the bundle statistic under weight(s, R).  Returns a dict with
        ok, reason, carrier_present, atts [(seq, price, cited)], selected, a_mint, a_claim."""
        from . import yellowback_attest as ya
        p = self.params
        out = {'ok': False, 'reason': '', 'carrier_present': False, 'atts': [], 'selected': [], 'a_mint': None, 'a_claim': None}
        if p.bundle_carrier == CARRIER_OP_RETURN:        # the OP_RETURN tail is unshipped: never a bundle
            out['reason'] = 'shape'
            return out
        found, why = self._find_carrier(tx, skip_vin0)
        out['carrier_present'] = found is not None or why == 'two-carriers'
        if found is None:
            out['reason'] = why
            return out
        _i, pushes = found
        bundle = pushes[0]
        _pk, h = ya.parse_carrier_script(pushes[2])
        if sha256(bundle) != h:
            out['reason'] = 'hash'
            return out
        atts = ya.decode_bundle(bundle)
        if atts is None:
            out['reason'] = 'shape'
            return out
        if not (p.m_select <= len(atts) <= p.bundle_max):
            out['reason'] = 'count'
            return out
        selected = self.selected(ref_height, selector)
        out['selected'] = selected
        parsed = [ya.parse_attestation(a) for a in atts]
        seen = set()
        for seq, _price, _cited, _r, _s in parsed:
            if seq not in selected:
                out['reason'] = 'member'
                return out
            if seq in seen:
                out['reason'] = 'dup'
                return out
            seen.add(seq)
        for _seq, price, cited, _r, _s in parsed:
            if not (ref_height - p.attest_max_age < cited <= ref_height) or cited < p.start_height:
                out['reason'] = 'stale'
                return out
            if not (p.price_min <= price <= p.price_max):
                out['reason'] = 'range'
                return out
        for att, (seq, _price, cited, _r, _s) in zip(atts, parsed):
            bh = self.block_hash_at(cited)
            rec = self.attestors.get(seq)
            if bh is None or rec is None or not ya.verify_attestation(rec.attestor_pubkey, att, bh):
                out['reason'] = 'sig'
                return out
        s = self.snapshots[ref_height]
        rows = [((seq, price), self.weight(self.attestors[seq], s.attest, ref_height)) for seq, price, _c, _r, _s in parsed]
        stat = ya.bundle_stat(rows, p.q_low_bps, p.q_high_bps, p.m_select)
        out['ok'] = True
        out['atts'] = [(seq, price, cited) for seq, price, cited, _r, _s in parsed]
        if stat is not None:
            out['a_mint'], out['a_claim'] = stat
        return out

    def _bundle(self, tx, ref_height, selector, skip_vin0):
        """verify_bundle, recorded into the BundleLog[H] accumulator when BUNDLE-1 held (R12)."""
        b = self.verify_bundle(tx, ref_height, selector, skip_vin0)
        if b['ok'] and self._bundle_acc is not None:
            acc = self._bundle_acc
            if b['a_mint'] is not None:
                acc['a_mints'].append(b['a_mint'])
            if b['a_claim'] is not None:
                acc['a_claims'].append(b['a_claim'])
            acc['selected'].update(b['selected'])
            acc['pairs'].update((seq, price) for seq, price, _c in b['atts'])
            acc['any'] = True
        return b

    def _attest_fee_ok(self, tx, attest_fee_vout, A, excluded, attest_fee_zat):
        """AFEE-1: the seq whose P2PKH(bondPubKey) vout[attestFeeVout] pays, or None."""
        if attest_fee_vout == FEE_VOUT_NONE or attest_fee_vout >= len(tx.vout) or attest_fee_vout in excluded:
            return None
        key = p2pkh_key(tx.vout[attest_fee_vout].script)
        if key is None or tx.vout[attest_fee_vout].value < attest_fee_zat:
            return None
        for seq in A:
            rec = self.attestors.get(seq)
            if rec is not None and hash160(rec.bond_pubkey) == key:
                return seq
        return None

    def registered(self, key, ref_height):
        for h in range(max(ref_height - self.params.n_reg + 1, self.params.start_height), ref_height + 1):
            t = self.tags.get(h)
            if t is not None and t.is_quote and t.payout_key == key:
                return True
        return False

    def penalized(self, key, ref_height, n_penalty=None):
        n_penalty = self.params.n_penalty if n_penalty is None else n_penalty
        lag = self.params.peer_lag
        for t, tag in self.tags.items():
            if tag.is_quote and tag.payout_key == key and t + lag < ref_height <= t + lag + n_penalty:
                j = self.judgements.get(t)
                if j is not None and j.penalized:
                    return True
        return False

    def accuracy_bps(self, key, ref_height, accuracy_window=None):
        w = self.params.accuracy_window if accuracy_window is None else accuracy_window
        lag = self.params.peer_lag
        quoted = in_band = 0
        for t in range(ref_height - lag - w + 1, ref_height - lag + 1):
            tag = self.tags.get(t)
            j = self.judgements.get(t)
            if tag is not None and tag.is_quote and tag.payout_key == key and j is not None and j.evaluated:
                quoted += 1
                if j.in_band:
                    in_band += 1
        return (BPS * in_band) // quoted if quoted else 0

    def _judge(self, height):
        """REG-4 for the quote tag at t = H - PEER_LAG."""
        lag = self.params.peer_lag
        t = height - lag
        tag = self.tags.get(t)
        if t < self.params.start_height or tag is None or not tag.is_quote:
            return
        peers = []
        for h in range(t - lag, t + lag):
            if h == t:
                continue
            p = self.tags.get(h)
            if p is not None and p.is_quote:
                peers.append(p.price_micro_usd)
        j = Judgement()
        if len(peers) >= self.params.peer_min:
            m = lower_median(peers)
            dev = (abs(tag.price_micro_usd - m) * BPS) // m
            j.evaluated = True
            j.in_band = dev <= self.params.accuracy_band_bps
            j.penalized = dev > self.params.deviation_bps
        self.judgements[t] = j

    def _sigma(self, height, p_fast_now):
        p = self.params
        samples = [p_fast_now]
        for k in range(1, p.vol_window // p.vol_step + 1):
            s = self.snapshot(height - k * p.vol_step)
            samples.append(None if (s is None or s.virtual) else s.p_fast)
        return sigma_mult_bps(samples, p.sigma_ref_bps, p.vol_periods_per_year, p.sigma_mult_max_bps)

    # -- feeding ------------------------------------------------------------

    def feed_block_json(self, block, subsidy_zat):
        """Feed a ``getblock <hash> 2`` result."""
        txs = [tx_from_json(t) if isinstance(t, dict) else t for t in block['tx']]
        cb = txs[0].vin[0].script_sig.hex()
        return self.feed_block(int(block['height']), block['hash'], cb, subsidy_zat, txs[1:])

    def feed_block(self, height, block_hash, coinbase_scriptsig_hex, subsidy_zat, txs):
        """Apply one block.  ``txs`` are the non-coinbase transactions as getblock-2 dicts or Tx
        objects (a leading coinbase Tx is skipped).  Returns the BlockVerdict (None below START_HEIGHT)."""
        p = self.params
        if self.tip_height >= 0 and height != self.tip_height + 1:
            raise ValueError('block %d fed after tip %d: blocks must arrive in order (no reorg support)' % (height, self.tip_height))
        if height < p.start_height:
            # Blocks below START_HEIGHT are ignored completely (section 3.8); only the tip moves on.
            self.tip_height = height
            return None
        txs = [tx_from_json(t) if isinstance(t, dict) else t for t in txs]
        txs = [t for t in txs if not t.is_coinbase]

        # TAG-1..5
        tag = find_tag(bytes.fromhex(coinbase_scriptsig_hex), height, p)
        if tag is not None:
            self.tags[height] = TagRecord(tag.payout_key, tag.price_micro_usd, tag.signal, tag.source_mask)

        enforcing = self.enforcement_on(height)
        block_invalid = False
        reason = ''
        self._bundle_acc = {'any': False, 'a_mints': [], 'a_claims': [], 'selected': set(), 'pairs': set()}
        for tx in txs:
            failed = self._apply_tx(tx, height)
            if failed and not block_invalid:
                block_invalid = True
                reason = '%s:%s' % (failed, tx.txid)

        # BundleLog[H] (R12), before SNAP: dormancy reads the row of H
        acc, self._bundle_acc = self._bundle_acc, None
        if acc['any']:
            row = BundleLogRecord()
            row.a_mint = lower_median(acc['a_mints']) if acc['a_mints'] else None
            row.a_claim = lower_median(acc['a_claims']) if acc['a_claims'] else None
            row.selected_seqs = sorted(acc['selected'])
            pairs = sorted(acc['pairs'])
            row.seqs = [sq for sq, _pr in pairs]
            row.prices = [pr for _sq, pr in pairs]
            self.bundle_log[height] = row

        # SNAP
        self._snap(height, block_hash, subsidy_zat, tag)
        self.tip_height = height
        self.tip_hash = block_hash
        verdict = BlockVerdict(height, block_hash, block_invalid, enforcing, reason)
        self.blocks[height] = verdict
        return verdict

    def _snap(self, height, block_hash, subsidy_zat, tag):
        p = self.params
        self._judge(height)
        # ACT-1..3
        count = self.signal_count(height)
        a = self.activation
        if a.status == SIGNALING and height >= p.start_height + p.signal_window - 1 and count >= p.activation_threshold:
            a.status = LOCKED_IN
            a.lock_in_height = height
            a.activate_height = height + p.activation_delay
        if a.status == LOCKED_IN and height >= a.activate_height:
            a.status = ACTIVE
        s = Snapshot()
        s.block_hash = block_hash
        s.tagged = tag is not None
        s.quote = tag is not None and tag.is_quote
        s.signal_count = count
        s.activation = a.copy()
        # ---- v3 (section 3.8 SNAP): maturity, ARM-1/2, PIN-1/2, seating; dormancy after the halts
        for r in self.attestors.values():                                      # maturity
            if r.status == A_PENDING and height >= r.register_height + p.bond_maturity:
                r.status = A_ELIGIBLE
                r.status_height = height
        eligible_count = sum(1 for r in self.attestors.values() if r.status == A_ELIGIBLE)
        m = self.attest                                                        # ARM-1/2
        if m.status == UNARMED and p.attest_arm_min > 0 and eligible_count >= p.attest_arm_min:
            m.status = TRIGGERED
            m.trigger_height = height
            m.arm_height = height + p.attest_arm_delay
        if m.status == TRIGGERED and height >= m.arm_height:
            m.status = ARMED
        s.attest = m.copy()
        window = [self.bundle_log[h] for h in range(max(height - p.pin_window, p.start_height), height)
                  if h in self.bundle_log]                                    # W = (H - 1 - PIN_WINDOW, H - 1]
        if len(window) >= max(1, p.pin_min_bundles):                          # PIN-1
            a_lo = min(r.a_mint for r in window)
            a_hi = max(r.a_mint for r in window)
            if (a_hi - a_lo) * BPS > p.pin_delta_bps * a_lo:
                per_key = {}
                for h in range(max(height - p.pin_window, p.start_height), height):
                    t = self.tags.get(h)
                    if t is not None and t.is_quote:
                        per_key.setdefault(t.payout_key, []).append(t.price_micro_usd)
                s.pinned_keys = sorted(k for k, prices in per_key.items()
                                       if len(prices) >= max(1, p.pin_min_tags) and len(set(prices)) == 1)
        s1 = self.snapshot(height - 1)                                         # PIN-2
        s0 = self.snapshot(height - 1 - p.pin_window)
        x1 = None if (s1 is None or s1.virtual) else s1.p_mint
        x0 = None if (s0 is None or s0.virtual) else s0.p_mint
        if x1 is not None and x0 is not None and abs(x1 - x0) * BPS > p.pin_delta_bps * min(x1, x0):
            rows_of, prices_of = {}, {}
            for row in window:
                for seq, price in set(zip(row.seqs, row.prices)):
                    prices_of.setdefault(seq, set()).add(price)
                for seq in set(row.seqs):
                    rows_of[seq] = rows_of.get(seq, 0) + 1
            s.pinned_seqs = sorted(seq for seq, n in rows_of.items() if n >= max(1, p.pin_min_tags) and len(prices_of[seq]) == 1)
        s.seated = self.seated(height, m)                                      # seating
        for seq, r in self.attestors.items():
            if seq in s.seated and r.seated_since == 0:
                r.seated_since = height
            if seq not in s.seated and r.seated_since != 0:
                r.seated_since = 0
        s.p_fast = self.median(p.p_fast_window, p.min_fill_fast, height, s.pinned_keys)
        s.p_mid = self.median(p.p_mid_window, p.min_fill_mid, height, s.pinned_keys)
        s.p_slow = self.median(p.p_slow_window, p.min_fill_slow, height, s.pinned_keys)
        if None not in (s.p_fast, s.p_mid, s.p_slow):
            s.p_mint = min(s.p_fast, s.p_mid, s.p_slow)
        if None not in (s.p_mid, s.p_slow):
            s.p_claim = max(s.p_mid, s.p_slow)
        s.sigma_mult_bps = self._sigma(height, s.p_fast)
        prev = self.snapshot(height - 1)
        s.issued_zat = prev.issued_zat + subsidy_zat
        s.supply_cents = self.totals.supply_cents
        s.collateral_zat = self.totals.collateral_zat
        s.global_ratio_bps = global_ratio_bps(s.collateral_zat, s.p_mint, s.supply_cents)
        # HALT-1..4, ACT-4, ACT-6
        mask = 0
        if a.status != ACTIVE:
            mask |= HALT_NOT_ACTIVE
        if s.p_mint is None:
            mask |= HALT_NO_PRICE
        if s.p_mint is not None and s.supply_cents > 0 and s.global_ratio_bps < p.global_ratio_halt_bps:
            mask |= HALT_GLOBAL_RATIO
        if None not in (s.p_fast, s.p_mid, s.p_slow):
            if (s.p_fast * BPS < (BPS - p.divergence_bps) * s.p_mid
                    or s.p_mid * BPS < (BPS - p.divergence_bps) * s.p_slow):
                mask |= HALT_DIVERGENCE
        part = bool(prev.halt_mask & HALT_PARTICIPATION)
        if part:
            part = count < p.activation_threshold
        if a.status == ACTIVE and count < p.participation_floor:
            part = True
        if part:
            mask |= HALT_PARTICIPATION
        enf = bool(prev.halt_mask & HALT_ENFORCEMENT)
        if enf:
            enf = count < p.enforcement_resume
        if a.status == ACTIVE and count < p.enforcement_floor:
            enf = True
        if enf:
            mask |= HALT_ENFORCEMENT
        s.halt_mask = mask
        # dormancy (S15): only at H mod DORMANCY_CHECK == 0, with seatedSince and the BundleLog window (H - DORMANCY_BLOCKS, H]
        if p.dormancy_check > 0 and height % p.dormancy_check == 0:
            rows = [self.bundle_log[h] for h in range(max(height - p.dormancy_blocks + 1, p.start_height), height + 1)
                    if h in self.bundle_log]
            for seq, r in self.attestors.items():
                if r.status != A_ELIGIBLE or r.seated_since == 0 or r.seated_since > height - p.dormancy_blocks:
                    continue
                selected_rows = [row for row in rows if seq in row.selected_seqs]
                if len(selected_rows) >= max(1, p.dormancy_min_bundles) and not any(seq in row.seqs for row in selected_rows):
                    r.status = A_DORMANT
                    r.status_height = height
        self.snapshots[height] = s

    # -- section 3.8 ---------------------------------------------------------

    def _apply_tx(self, tx, height):
        """IN-1..3, TX-0, MINT/XFER/RED.  Returns the failing RED verdict (BLK-1 condition) or None."""
        rec = TxLogRecord(height)
        outpoints = [(i.prev_txid, i.prev_n) for i in tx.vin]
        # IN-1
        yed_in = 0
        for op in outpoints:
            t = self.tokens.pop(op, None)
            if t is not None:
                yed_in += t.cents
                rec.spent_tokens.append(op)
        rec.yed_in = yed_in
        # IN-2 (amended): a bond spend withdraws the attestor unless EJECTED; the record stays
        bond_spent = False
        for op in outpoints:
            seq = self.bond_index.get(op)
            if seq is None:
                continue
            a = self.attestors[seq]
            if a.bond_spent_height:
                continue
            if a.status != A_EJECTED:
                a.status = A_WITHDRAWN
                a.status_height = height
            a.bond_spent_height = height
            bond_spent = True
        active_spent = [op for op in outpoints if op in self.vaults and self.vaults[op].status == V_ACTIVE]
        void_spent = [op for op in outpoints if op in self.vaults and self.vaults[op].status == V_VOID]
        scripts = [o.script for o in tx.vout]
        payload, opret = tx_payload(scripts)

        failing = None
        touched = bool(rec.spent_tokens) or bool(active_spent) or bool(void_spent) or bond_spent
        if active_spent:
            # M3: RED-1..4 only, whatever the payload
            rec.type = 'REDEEM'
            failing = self._apply_vault_spend(tx, height, rec, payload, opret, active_spent, outpoints, yed_in)
            touched = True
        elif payload is not None and payload.type == PAYLOAD_MINT:
            rec.type = 'MINT'
            created = self._apply_mint(tx, height, rec, payload, opret)
            touched = touched or created
        elif payload is not None and payload.type in (PAYLOAD_TRANSFER, PAYLOAD_REDEEM):
            rec.type = 'TRANSFER' if payload.type == PAYLOAD_TRANSFER else 'REDEEM'
            self._apply_transfer(tx, height, rec, payload, yed_in)
        else:
            # The v3 types (REG-A1, NOT-1, EQV-1, REV-1): a holding rule writes its table and a TxLog
            # entry; a failing one is non-Yellowback for outputs, like a transaction with no payload.
            held = False
            if payload is not None:
                rec.type = TXLOG_TYPE_NAMES[payload.type]
                if payload.type == PAYLOAD_ATTESTOR_REGISTER:
                    held = self._apply_register(tx, height, rec, payload)
                elif payload.type == PAYLOAD_CLAIM_NOTICE:
                    held = self._apply_notice(tx, height, rec, payload)
                elif payload.type == PAYLOAD_EQUIVOCATION:
                    held = self._apply_equivocation(tx, height, rec)
                elif payload.type == PAYLOAD_ATTESTOR_REVIVE:
                    held = self._apply_revive(tx, height, rec, payload)
            if held:
                touched = True
            else:
                rec.type = 'NONE'
                if yed_in > 0:
                    rec.verdict = VERDICT_BURNED

        # IN-2 for VOID vaults: an ordinary spend that closes them (K3)
        for op in void_spent:
            v = self.vaults[op]
            v.status = V_CLOSED
            v.close_height = height
            v.closing_txid = tx.txid
            v.unbacked = False
            self.totals.void_vaults -= 1
            self.totals.closed_vaults += 1
            rec.closed_vaults.append(op)

        # IN-3 (for a MINT the burn formula's yedOut is 0, N19; _apply_mint set rec.yed_out = cents separately)
        burn_out = 0 if rec.type == 'MINT' else rec.yed_out
        burned = yed_in - burn_out
        rec.burned = burned
        self.totals.supply_cents -= burned
        for op in rec.closed_vaults:
            self.vaults[op].burned_cents = burned
        if rec.type == 'REDEEM' and active_spent:
            for op in active_spent:
                v = self.vaults[op]
                if v.status == V_CLOSED and failing is not None:
                    v.unbacked = burned < v.minted_cents
                    self.totals.unbacked_cents += max(0, v.minted_cents - burned)
                self.notices.pop(op, None)         # IN-2: the vault left ACTIVE
        if touched:
            self.txlog[tx.txid] = rec
        return failing

    def _attestation_valid(self, att, pubkey33, block_hash):
        from . import yellowback_attest as ya
        return ya.verify_attestation(pubkey33, att, block_hash)

    def _apply_register(self, tx, height, rec, pl):
        """REG-A1 (proposal section 5.2; bondOutpoint = txid:0)."""
        from . import yellowback_attest as ya
        p = self.params
        if not (is_valid_compressed_pubkey(pl.attestor_pubkey) and is_valid_compressed_pubkey(pl.bond_pubkey)):
            return False
        if not tx.vout:
            return False
        if not (height + p.bond_min_lock <= pl.bond_locktime < LOCKTIME_THRESHOLD):
            return False
        if tx.vout[0].script != p2sh_script(ya.bond_script(pl.bond_pubkey, pl.bond_locktime)):
            return False
        if tx.vout[0].value < p.bond_min:
            return False
        for a in self.attestors.values():
            if a.attestor_pubkey == pl.attestor_pubkey and a.status != A_WITHDRAWN:
                return False
        seq = self.attestor_seq
        if seq in self.attestors:
            return False
        a = AttestorRecord()
        a.attestor_pubkey = pl.attestor_pubkey
        a.bond_pubkey = pl.bond_pubkey
        a.bond_outpoint = (tx.txid, 0)
        a.bond_zat = tx.vout[0].value
        a.bond_locktime = pl.bond_locktime
        a.flags = pl.flags
        a.register_height = height
        a.status = A_PENDING
        a.status_height = height
        self.attestors[seq] = a
        self.bond_index[(tx.txid, 0)] = seq
        self.attestor_seq = (seq + 1) & 0xFFFF
        rec.attestor_seq = seq
        return True

    def _apply_notice(self, tx, height, rec, pl):
        """NOT-1."""
        from . import yellowback_attest as ya
        p = self.params
        op = (pl.vault_txid, pl.vault_vout)
        v = self.vaults.get(op)
        if v is None or v.status != V_ACTIVE:
            return False
        r = pl.ref_height
        if not (height - p.ref_window <= r <= height - 1) or r < p.start_height:
            return False
        if not self.armed_at(r):
            return False
        b = self._bundle(tx, r, ya.outpoint_selector(op[0], op[1]), False)
        if not b['ok']:
            return False
        s = self.snapshots[r]
        if s.p_claim is None or b['a_claim'] is None:
            return False
        p_emerg = min(s.p_claim, b['a_claim'])
        if not is_underwater(v.collateral_zat, p_emerg, v.minted_cents, p.emergency_ratio_bps):
            return False
        standing = self.notices.get(op)
        if standing is not None and height - standing.height <= p.emergency_notice_ttl:
            return False
        self.notices[op] = NoticeRecord(height, r, p_emerg)
        rec.a_mint, rec.a_claim = b['a_mint'], b['a_claim']
        rec.bundle_seqs = [seq for seq, _p, _c in b['atts']]
        rec.notice = True
        return True

    def _apply_equivocation(self, tx, height, rec):
        """EQV-1."""
        from . import yellowback_attest as ya
        p = self.params
        if p.bundle_carrier == CARRIER_OP_RETURN:
            return False
        found, _why = self._find_carrier(tx, False)
        if found is None:
            return False
        _i, pushes = found
        _pk, h = ya.parse_carrier_script(pushes[2])
        if sha256(pushes[0]) != h:
            return False
        atts = ya.decode_bundle(pushes[0])
        if atts is None or len(atts) != 2:
            return False
        a, b = ya.parse_attestation(atts[0]), ya.parse_attestation(atts[1])
        if a[0] != b[0] or a[2] != b[2] or a[1] == b[1]:
            return False
        r = self.attestors.get(a[0])
        if r is None or r.status in (A_WITHDRAWN, A_EJECTED):
            return False
        bh = self.block_hash_at(a[2])
        if bh is None or a[2] < p.start_height:
            return False
        if not (self._attestation_valid(atts[0], r.attestor_pubkey, bh) and self._attestation_valid(atts[1], r.attestor_pubkey, bh)):
            return False
        r.status = A_EJECTED
        r.status_height = height
        rec.attestor_seq = a[0]
        rec.bundle_seqs = [a[0]]
        return True

    def _apply_revive(self, tx, height, rec, pl):
        """REV-1."""
        p = self.params
        r = self.attestors.get(pl.seq)
        if r is None or r.status != A_DORMANT:
            return False
        if not (height - p.attest_max_age < pl.cited_height <= height - 1):
            return False
        bh = self.block_hash_at(pl.cited_height)
        if bh is None:
            return False
        att = struct.pack('<HII', pl.seq, pl.price_micro_usd, pl.cited_height) + pl.sig
        if not self._attestation_valid(att, r.attestor_pubkey, bh):
            return False
        r.status = A_ELIGIBLE
        r.status_height = height
        rec.attestor_seq = pl.seq
        return True

    def _apply_mint(self, tx, height, rec, pl, opret):
        """MINT-1..10.  Returns True when a Vaults entry was created (ACTIVE or VOID)."""
        p = self.params
        facts = {}
        verdict = self._mint_verdict(tx, height, pl, opret, facts)
        b = facts.get('bundle')
        if b is not None and b['ok']:
            rec.a_mint, rec.a_claim = b['a_mint'], b['a_claim']
            rec.bundle_seqs = [seq for seq, _p, _c in b['atts']]
        vout0 = tx.vout[0] if tx.vout else None
        if verdict == VERDICT_OK:
            v = Vault()
            v.owner_pubkey = pl.owner_pubkey
            v.term_class = pl.term_class
            v.lock_height = pl.lock_height
            v.claim_height = pl.lock_height + p.grace
            v.collateral_zat = vout0.value
            v.minted_cents = pl.cents
            v.mint_height = height
            v.ref_height = pl.ref_height
            v.status = V_ACTIVE
            fee_applies = bool(self.eligible_payees(pl.ref_height))
            if fee_applies:
                v.fee_paid_zat = tx.vout[pl.fee_vout].value
                rec.fee_zat = v.fee_paid_zat
                rec.payee = p2pkh_key(tx.vout[pl.fee_vout].script)
            if facts.get('attest_payee') is not None:
                rec.attest_fee_zat = tx.vout[pl.attest_fee_vout].value
                rec.attest_payee = facts['attest_payee']
            self.vaults[(tx.txid, 0)] = v
            self.tokens[(tx.txid, 1)] = Token(pl.cents, tx.vout[1].value, tx.vout[1].script, height)
            self.totals.supply_cents += pl.cents
            self.totals.collateral_zat += vout0.value
            self.totals.active_vaults += 1
            rec.yed_out = pl.cents
            rec.assigned = [(1, pl.cents)]
            rec.verdict = VERDICT_OK
            return True
        rec.verdict = verdict
        rec.yed_out = 0
        if vout0 is not None and is_p2sh(vout0.script):
            v = Vault()
            v.owner_pubkey = pl.owner_pubkey
            v.term_class = pl.term_class
            v.lock_height = pl.lock_height
            v.claim_height = pl.lock_height + p.grace
            v.collateral_zat = vout0.value
            v.minted_cents = pl.cents
            v.mint_height = height
            v.ref_height = pl.ref_height
            v.status = V_VOID
            v.void_reason = verdict
            self.vaults[(tx.txid, 0)] = v
            self.totals.void_vaults += 1
            return True
        return False

    def _mint_verdict(self, tx, height, pl, opret, facts):
        """Not ARMED at R: the v2 order MINT-2..8 exactly.  ARMED: MINT-2, 3, 4, 6, 7, 8, then MINT-9,
        AFEE-1, MINT-5 (with the combined pMint), MINT-10 (v3 plan R15)."""
        p = self.params
        # MINT-2 (signed arithmetic)
        rng = p.class_range(pl.term_class)
        if rng is None:
            return 'bad-mint-class'
        if not (p.min_mint <= pl.cents <= p.max_mint):
            return 'bad-mint-amount'
        if not (pl.lock_height + p.grace < LOCKTIME_THRESHOLD):
            return 'bad-mint-lock-height'
        if not (height - p.ref_window <= pl.ref_height <= height - 1) or pl.ref_height < p.start_height:
            return 'bad-mint-ref-height'
        if not (pl.lock_height > pl.ref_height) or not (rng[0] <= pl.lock_height - pl.ref_height <= rng[1]):
            return 'bad-mint-lock-height'
        # MINT-3
        if len(tx.vout) < 3:
            return 'bad-mint-outputs'
        if not is_valid_compressed_pubkey(pl.owner_pubkey):
            return 'bad-mint-owner-key'
        expected = p2sh_script(vault_script(pl.lock_height, pl.owner_pubkey, pl.lock_height + p.grace))
        if tx.vout[0].script != expected:
            return 'bad-mint-vault-script'
        # MINT-4
        s = self.snapshot(pl.ref_height)
        if s is None or s.virtual or s.activation.status != ACTIVE:
            return 'mint-not-active'
        if s.halt_mask & HALT_NOT_ACTIVE:
            return 'mint-not-active'
        if s.halt_mask & HALT_NO_PRICE:
            return 'mint-halted-no-price'
        if s.halt_mask & (HALT_PARTICIPATION | HALT_ENFORCEMENT):
            return 'mint-halted-participation'
        # HALT-2 (amended, W16): the global-ratio halt stops only a mint whose own minimum
        # ratio is below the recapitalisation floor
        if (s.halt_mask & HALT_GLOBAL_RATIO) and min_ratio_bps(p.base_ratio_bps[pl.term_class], s.sigma_mult_bps) < p.recap_ratio_bps:
            return 'mint-halted-global-ratio'
        if s.halt_mask & HALT_DIVERGENCE:
            return 'mint-halted-divergence'
        if (s.halt_mask & ~HALT_GLOBAL_RATIO) != 0:
            return 'mint-not-active'
        armed = self.armed_at(pl.ref_height)
        x_mint = s.p_mint

        def mint5(p_mint):
            if p_mint is None:
                return 'mint-halted-no-price'
            req = required_zat(pl.cents, min_ratio_bps(p.base_ratio_bps[pl.term_class], s.sigma_mult_bps), p_mint)
            if req is None:
                return 'mint-unsatisfiable'
            if tx.vout[0].value < req or tx.vout[0].value < 4 * p.fee_min:
                return 'bad-mint-collateral'
            return None

        # MINT-5 at its v2 position when not ARMED (pMint = xMint)
        if not armed:
            v = mint5(x_mint)
            if v is not None:
                return v
        # MINT-6 (the cap reads the cross-section xMint: it precedes MINT-9)
        cap = supply_cap_cents(s.issued_zat, x_mint, p.supply_cap_bps)
        if cap is not None and self.totals.supply_cents + pl.cents > cap:
            return 'mint-supply-cap'
        # MINT-7
        if opret == 1:
            return 'bad-mint-token-output'
        # MINT-8
        eligible = self.eligible_payees(pl.ref_height)
        if eligible:
            fv = pl.fee_vout
            if fv == FEE_VOUT_NONE or fv >= len(tx.vout) or fv in (0, 1, opret):
                return 'bad-mint-fee'
            key = p2pkh_key(tx.vout[fv].script)
            if key is None or key not in eligible:
                return 'bad-mint-fee'
            if tx.vout[fv].value < fee_zat(tx.vout[0].value, p.fee_min, p.fee_bps):
                return 'bad-mint-fee'
        if not armed:
            return VERDICT_OK
        # MINT-9 (ARMED at R: BUNDLE-1 with the empty selector; aMint defined)
        if True:
            b = self._bundle(tx, pl.ref_height, b'', False)
            facts['bundle'] = b
            if not b['ok']:
                return 'mint9-no-bundle' if not b['carrier_present'] else 'mint9-bundle-' + b['reason']
            if b['a_mint'] is None:
                return 'mint9-bundle-stat'
            # AFEE-1 (MINT-8's attestor-fee clause)
            attest_fee = attest_fee_zat(fee_zat(tx.vout[0].value, p.fee_min, p.fee_bps), p.attest_fee_bps)
            A = [seq for seq, _p, _c in b['atts']]
            payee = self._attest_fee_ok(tx, pl.attest_fee_vout, A, {0, 1, opret, pl.fee_vout}, attest_fee)
            if payee is None:
                return 'afee1-fee'
            facts['attest_payee'] = payee
            # PRICE-2 (revised)
            p_mint = None if x_mint is None else min(x_mint, b['a_mint'])
        # MINT-5 (ARMED: after MINT-9, with the combined pMint)
        v = mint5(p_mint)
        if v is not None:
            return v
        # MINT-10 (amended W17): the agreement test reads the pools' fast median, not the
        # min-of-windows x_mint that MINT-5 prices collateral at
        a = facts['bundle']['a_mint']
        fast = s.p_fast if s.p_fast is not None else x_mint
        if abs(fast - a) * BPS > p.diverge_bps_attest * min(fast, a):
            return 'mint10-diverged'
        return VERDICT_OK

    def _apply_transfer(self, tx, height, rec, pl, yed_in):
        """XFER-1..3 for a TRANSFER or a REDEEM payload that spends no ACTIVE vault."""
        p = self.params
        total = sum(c for _, c in pl.assignments)
        verdict = VERDICT_OK
        for _, cents in pl.assignments:
            if not (p.min_output <= cents <= p.max_output):
                verdict = 'bad-transfer-assignment'
                break
        if verdict == VERDICT_OK and total > yed_in:
            verdict = 'transfer-over-assigned'
        if verdict == VERDICT_OK and yed_in <= 0:
            verdict = 'transfer-no-yed-input'
        if verdict != VERDICT_OK:
            rec.verdict = verdict
            rec.yed_out = 0
            return
        for vout, cents in pl.assignments:
            self.tokens[(tx.txid, vout)] = Token(cents, tx.vout[vout].value, tx.vout[vout].script, height)
        rec.assigned = list(pl.assignments)
        rec.yed_out = total
        rec.verdict = VERDICT_BURNED if total < yed_in else VERDICT_OK

    def _apply_vault_spend(self, tx, height, rec, pl, opret, active_spent, outpoints, yed_in):
        """RED-1..4 over a transaction that spends at least one ACTIVE vault.  Returns the failing
        verdict or None; applies IN-2 either way."""
        path = spend_path(tx.vin[0].script_sig)
        rec.path = path or ''
        facts = {}
        verdict = self._red_verdict(tx, height, pl, opret, active_spent, outpoints, path, yed_in, facts)
        b = facts.get('bundle')
        if b is not None and b['ok']:
            rec.a_mint, rec.a_claim = b['a_mint'], b['a_claim']
            rec.bundle_seqs = [seq for seq, _p, _c in b['atts']]
        rec.residual_zat = facts.get('residual_zat', 0)
        rec.claim_path = facts.get('claim_path', '')
        vault_op = outpoints[0]
        if verdict == VERDICT_OK:
            v = self.vaults[vault_op]
            total = sum(c for _, c in pl.assignments)
            for vout, cents in pl.assignments:
                self.tokens[(tx.txid, vout)] = Token(cents, tx.vout[vout].value, tx.vout[vout].script, height)
            rec.assigned = list(pl.assignments)
            rec.yed_out = total
            rec.verdict = VERDICT_OK
            v.status = V_CLOSED if path == 'owner' else V_CLAIMED
            v.close_height = height
            v.closing_txid = tx.txid
            v.unbacked = False
            # feePaidZat is rewritten by the close: the fee this spend paid (0 under FEE-0); see SERIALISATION.md
            v.fee_paid_zat = 0
            if self.eligible_payees(pl.ref_height):
                v.fee_paid_zat = tx.vout[pl.fee_vout].value
                rec.fee_zat = v.fee_paid_zat
                rec.payee = p2pkh_key(tx.vout[pl.fee_vout].script)
            if facts.get('attest_payee') is not None:
                rec.attest_fee_zat = tx.vout[pl.attest_fee_vout].value
                rec.attest_payee = facts['attest_payee']
            self.totals.collateral_zat -= v.collateral_zat
            self.totals.active_vaults -= 1
            if path == 'owner':
                self.totals.closed_vaults += 1
            else:
                self.totals.claimed_vaults += 1
            rec.closed_vaults.append(vault_op)
            return None
        rec.verdict = verdict
        rec.yed_out = 0
        for op in active_spent:
            v = self.vaults[op]
            v.status = V_CLOSED
            v.close_height = height
            v.closing_txid = tx.txid
            self.totals.collateral_zat -= v.collateral_zat
            self.totals.active_vaults -= 1
            self.totals.closed_vaults += 1
            rec.closed_vaults.append(op)
        return verdict

    def _red_verdict(self, tx, height, pl, opret, active_spent, outpoints, path, yed_in, facts):
        p = self.params
        # RED-1
        if outpoints[0] not in active_spent or len(active_spent) != 1:
            return 'vault-spend-malformed'
        if path is None:
            return 'vault-spend-malformed'
        if pl is None or pl.type != PAYLOAD_REDEEM:
            return 'vault-spend-malformed'
        if not (height - p.ref_window <= pl.ref_height <= height - 1) or pl.ref_height < p.start_height:
            return 'vault-spend-malformed'
        for _, cents in pl.assignments:
            if not (p.min_output <= cents <= p.max_output):
                return 'vault-spend-malformed'
        vault = self.vaults[outpoints[0]]
        claim = path == 'claim'
        armed = claim and self.armed_at(pl.ref_height)      # the owner path reads no bundle
        # RED-1 (amended): the claim path needs BUNDLE-1 with selector = vaultOutpoint when ARMED
        from . import yellowback_attest as ya
        if armed:
            b = self._bundle(tx, pl.ref_height, ya.outpoint_selector(outpoints[0][0], outpoints[0][1]), True)
            facts['bundle'] = b
            if not b['ok']:
                return 'red1-bundle-' + b['reason']
            if b['a_claim'] is None:
                return 'red1-bundle-stat'
        # RED-2
        total = sum(c for _, c in pl.assignments)
        burn = yed_in - total
        if burn < vault.minted_cents:
            return 'vault-spend-missing-burn' if burn <= 0 else 'vault-spend-short-burn'
        # RED-3
        eligible = self.eligible_payees(pl.ref_height)
        assigned_vouts = [v for v, _ in pl.assignments]
        if eligible:
            fv = pl.fee_vout
            if fv == FEE_VOUT_NONE or fv >= len(tx.vout) or fv == opret or fv in assigned_vouts:
                return 'vault-spend-bad-fee'
            key = p2pkh_key(tx.vout[fv].script)
            if key is None or key not in eligible:
                return 'vault-spend-bad-payee'
            if tx.vout[fv].value < fee_zat(vault.collateral_zat, p.fee_min, p.fee_bps):
                return 'vault-spend-bad-fee'
        # AFEE-1 (RED-3's attestor-fee clause)
        if armed:
            attest_fee = attest_fee_zat(fee_zat(vault.collateral_zat, p.fee_min, p.fee_bps), p.attest_fee_bps)
            A = [seq for seq, _p, _c in facts['bundle']['atts']]
            payee = self._attest_fee_ok(tx, pl.attest_fee_vout, A, set(assigned_vouts) | {0, 1, opret, pl.fee_vout}, attest_fee)
            if payee is None:
                return 'afee1-fee'
            facts['attest_payee'] = payee
        # RED-4 (amended) and RED-5
        if claim:
            s = self.snapshot(pl.ref_height)
            x_claim = None if (s is None or s.virtual) else s.p_claim
            p_claim, p_emerg = x_claim, None
            if armed:
                a_claim = facts['bundle']['a_claim']
                if x_claim is not None:
                    p_claim, p_emerg = max(x_claim, a_claim), min(x_claim, a_claim)
                else:
                    p_claim = None
            if is_underwater(vault.collateral_zat, p_claim, vault.minted_cents, p.claim_threshold_bps):
                facts['claim_path'] = 'a'
            else:
                notice = self.notices.get(outpoints[0]) if armed else None       # (b) is false before arming
                persisted = notice is not None and p.emergency_persist <= pl.ref_height - notice.ref_height <= p.emergency_notice_ttl
                if not persisted or not is_underwater(vault.collateral_zat, p_emerg, vault.minted_cents, p.emergency_ratio_bps):
                    return 'vault-claim-not-underwater'
                facts['claim_path'] = 'b'
            # RED-5
            if p_claim is None:
                return 'red5-residual'
            margin = p.claim_threshold_bps if facts['claim_path'] == 'a' else BPS
            residual = residual_zat(vault.collateral_zat, claimant_max_zat(vault.minted_cents, margin, p_claim))
            facts['residual_zat'] = residual
            if residual >= p.residual_min_zat:
                owner = hash160(vault.owner_pubkey)
                paid = False
                for j, o in enumerate(tx.vout):
                    if j in (opret, pl.fee_vout, pl.attest_fee_vout) or j in assigned_vouts:
                        continue
                    if p2pkh_key(o.script) == owner and o.value >= residual:
                        paid = True
                        break
                if not paid:
                    return 'red5-residual'
        return VERDICT_OK

    # -- state hash (section 3.6) --------------------------------------------

    def state_hash_preimage(self):
        p = self.params
        out = bytearray()
        out += b'T' + _i32(max(self.tip_height, 0)) + _hash(self.tip_hash) + _u32(self.SCHEMA_VERSION) + _str(p.network)
        for h in sorted(self.tags):
            t = self.tags[h]
            out += b'Q' + _u32be(h) + t.payout_key + _u64(t.price_micro_usd) + _bool(t.signal) + _u16(t.source_mask)
        for h in sorted(self.judgements):
            j = self.judgements[h]
            out += b'J' + _u32be(h) + _bool(j.evaluated) + _bool(j.in_band) + _bool(j.penalized)
        out += b'C' + _ser_activation(self.activation)
        for op in sorted(self.vaults, key=_outpoint_sort_key):
            out += _outpoint_key(b'V', op) + _ser_vault(self.vaults[op])
        for op in sorted(self.tokens, key=_outpoint_sort_key):
            out += _outpoint_key(b'K', op) + _ser_token(self.tokens[op])
        out += b'G' + _ser_totals(self.totals)
        for h in sorted(self.snapshots):
            out += b'S' + _u32be(h) + _ser_snapshot(self.snapshots[h])
        out += (b'P' + _i32(p.start_height) + _i32(p.sigma_ref_bps) + _i32(p.supply_cap_bps) + _i32(p.enforce_until)
                + _u32(p.attest_arm_min) + _u8(p.bundle_carrier))
        # v3 (section 3.6 state-hash order): Attestors by seq, AttestorSeq, Attest, BundleLog by height, Notices by outpoint
        for seq in sorted(self.attestors):
            out += b'A' + struct.pack('>H', seq) + _ser_attestor(self.attestors[seq])
        out += b'N' + _u16(self.attestor_seq)
        out += b'M' + _ser_attest(self.attest)
        for h in sorted(self.bundle_log):
            out += b'W' + _u32be(h) + _ser_bundle_log(self.bundle_log[h])
        for op in sorted(self.notices, key=_outpoint_sort_key):
            out += _outpoint_key(b'E', op) + _ser_notice(self.notices[op])
        return bytes(out)

    def state_hash(self):
        return sha256(self.state_hash_preimage()).hex()


# ---------------------------------------------------------------------------
# Live-node comparison (section 6.0 item 4, section 7)

class ModelMismatch(AssertionError):
    pass


def _norm_status(s):
    return str(s).replace('_', '').replace('-', '').lower()


def _norm_outpoint(x):
    if isinstance(x, dict):
        return '%s:%d' % (x['txid'], int(x['vout']))
    return str(x)


def _price_eq(model_v, rpc_v):
    # M1: the index stores an undefined quantity as 0 and the RPC renders a stored 0 as null, so
    # a defined value of exactly 0 (a global ratio with no collateral left) is indistinguishable
    # from undefined on the wire; both directions are accepted.
    if model_v is None or model_v == 0:
        return rpc_v is None or int(rpc_v) == 0
    return rpc_v is not None and int(rpc_v) == model_v


def _key_of(rpc_payee):
    """A payee as the RPC renders it: an address (decoded to its key hash), a hex key, or None."""
    if rpc_payee in (None, ''):
        return None
    if isinstance(rpc_payee, str) and len(rpc_payee) == 40:
        try:
            return bytes.fromhex(rpc_payee)
        except ValueError:
            pass
    return address_key_hash(str(rpc_payee))


def _check(cond, what, height=None, extra=''):
    if not cond:
        where = '' if height is None else ' at height %d' % height
        raise ModelMismatch('model mismatch%s: %s %s' % (where, what, extra))


def subsidy_from_rpc(node, height):
    """GetBlockSubsidy(height) = miner + founders + every funding stream of ``getblocksubsidy``."""
    r = node.getblocksubsidy(height)
    total = Decimal(str(r.get('miner', 0))) + Decimal(str(r.get('founders', 0)))
    for fs in r.get('fundingstreams', []) or []:
        total += Decimal(str(fs.get('value', 0)))
    return int((total * COIN).to_integral_value())


def model_transaction(model, tx, height):
    """The accounting half as one call (P8): apply one non-coinbase transaction (a ``getblock 2``
    dict or a Tx) to ``model`` at ``height`` per section 3.8 (IN-1..3, TX-0, MINT-1..8, XFER-1..3,
    RED-1..4) and return ``(txlog_record_or_None, failing_red_verdict_or_None)``.  ``feed_block``
    does exactly this for every transaction of a block before the SNAP; this entry point lets a
    test model one transaction against an in-block state without a block."""
    t = tx_from_json(tx) if isinstance(tx, dict) else tx
    if t.is_coinbase:
        return None, None
    failing = model._apply_tx(t, height)
    return model.txlog.get(t.txid), failing


def build_model_from_node(node, params=None, check_tags=True):
    """Rebuild the model from a live node over [0, tip] via getblockcount/getblockhash/getblock 2."""
    if params is None:
        params = params_from_getinfo(node.yed_getinfo())
    model = YellowbackModel(params)
    tip = node.getblockcount()
    for h in range(0, tip + 1):
        bh = node.getblockhash(h)
        blk = node.getblock(bh, 2)
        subsidy = subsidy_from_rpc(node, h) if h >= params.start_height else 0
        if check_tags and h >= params.start_height:
            cb = blk['tx'][0]['vin'][0]['coinbase']
            tag = find_tag(bytes.fromhex(cb), h, params)
            rpc = node.yed_gettag(str(h))
            _check(bool(rpc.get('found')) == (tag is not None), 'yed_gettag.found', h, repr(rpc))
            if tag is not None:
                _check(_norm_status(rpc.get('kind')) in (tag.kind, tag.kind + 'only', tag.kind + 'tag'),
                       'yed_gettag.kind', h, repr(rpc))
                _check(bool(rpc.get('signal')) == tag.signal, 'yed_gettag.signal', h)
                _check(int(rpc.get('priceMicroUsd', 0)) == tag.price_micro_usd, 'yed_gettag.priceMicroUsd', h)
                _check(int(rpc.get('sourceMask', 0)) == tag.source_mask, 'yed_gettag.sourceMask', h)
                _check(_key_of(rpc.get('payoutAddress')) == tag.payout_key, 'yed_gettag.payoutAddress', h)
        model.feed_block_json(blk, subsidy)
    return model


def compare_history(model, node):
    """Every yed_gethistory field for every height in [START_HEIGHT, tip]."""
    start = model.params.start_height
    tip = model.tip_height
    rows = []
    h = start
    while h <= tip:
        to = min(h + 2015, tip)
        rows.extend(node.yed_gethistory(h, to))
        h = to + 1
    _check(len(rows) == max(0, tip - start + 1), 'yed_gethistory row count', extra='%d rows for [%d, %d]' % (len(rows), start, tip))
    for row in rows:
        h = int(row['height'])
        s = model.snapshots.get(h)
        _check(s is not None, 'snapshot missing in model', h)
        _check(row['blockHash'] == s.block_hash, 'blockHash', h)
        _check(bool(row['tagged']) == s.tagged, 'tagged', h)
        _check(bool(row['quote']) == s.quote, 'quote', h)
        _check(int(row['signalCount']) == s.signal_count, 'signalCount', h)
        act = row['activation']
        if isinstance(act, dict):
            _check(_norm_status(act['status']) == _norm_status(ACTIVATION_NAMES[s.activation.status]), 'activation.status', h, repr(act))
            _check(int(act.get('lockInHeight', 0)) == s.activation.lock_in_height, 'activation.lockInHeight', h)
            _check(int(act.get('activateHeight', 0)) == s.activation.activate_height, 'activation.activateHeight', h)
        else:
            _check(_norm_status(act) == _norm_status(ACTIVATION_NAMES[s.activation.status]), 'activation', h, repr(act))
        for name, val in (('pFast', s.p_fast), ('pMid', s.p_mid), ('pSlow', s.p_slow), ('pMint', s.p_mint), ('pClaim', s.p_claim)):
            _check(_price_eq(val, row.get(name)), name, h, 'model=%r rpc=%r' % (val, row.get(name)))
        _check(int(row['sigmaMultBps']) == s.sigma_mult_bps, 'sigmaMultBps', h, 'model=%r rpc=%r' % (s.sigma_mult_bps, row['sigmaMultBps']))
        _check(int(row['issuedZat']) == s.issued_zat, 'issuedZat', h, 'model=%r rpc=%r' % (s.issued_zat, row['issuedZat']))
        _check(int(row['supplyCents']) == s.supply_cents, 'supplyCents', h)
        _check(int(row['collateralZat']) == s.collateral_zat, 'collateralZat', h)
        _check(_price_eq(s.global_ratio_bps, row.get('globalRatioBps')), 'globalRatioBps', h)
        rpc_mask = row.get('haltMask', [])
        if isinstance(rpc_mask, int):
            _check(rpc_mask == s.halt_mask, 'haltMask', h)
        else:
            _check(set(str(x).upper() for x in rpc_mask) == set(s.halt_names()), 'haltMask', h, 'model=%r rpc=%r' % (s.halt_names(), rpc_mask))


# The contract's type strings for the model's v3 TxLog types (doc/yellowback-rpc.md, Conventions).
_RPC_TYPE = {'ATTESTOR_REGISTER': 'register', 'CLAIM_NOTICE': 'notice', 'EQUIVOCATION': 'equivocation', 'ATTESTOR_REVIVE': 'revive'}


def compare_txinfo(model, node):
    for txid, rec in model.txlog.items():
        info = node.yed_gettxinfo(txid)
        _check(int(info['height']) == rec.height, 'yed_gettxinfo.height', extra=txid)
        want_type = _RPC_TYPE.get(str(rec.type), str(rec.type))
        _check(_norm_status(info['type']) == _norm_status(want_type), 'yed_gettxinfo.type', rec.height, '%s model=%s rpc=%s' % (txid, rec.type, info['type']))
        _check(_norm_status(info.get('path') or '') == _norm_status(rec.path), 'yed_gettxinfo.path', rec.height, txid)
        _check(info['verdict'] == rec.verdict, 'yed_gettxinfo.verdict', rec.height, '%s model=%s rpc=%s' % (txid, rec.verdict, info['verdict']))
        _check(int(info['yedIn']) == rec.yed_in, 'yed_gettxinfo.yedIn', rec.height, txid)
        _check(int(info['yedOut']) == rec.yed_out, 'yed_gettxinfo.yedOut', rec.height, txid)
        _check(int(info['burned']) == rec.burned, 'yed_gettxinfo.burned', rec.height, txid)
        _check(int(info.get('feeZat', 0)) == rec.fee_zat, 'yed_gettxinfo.feeZat', rec.height, txid)
        _check(_key_of(info.get('payee')) == rec.payee, 'yed_gettxinfo.payee', rec.height, txid)
        got = sorted((int(a['vout']), int(a['cents'])) for a in info.get('assigned', []))
        _check(got == sorted(rec.assigned), 'yed_gettxinfo.assigned', rec.height, txid)
        got = sorted(_norm_outpoint(x) for x in info.get('spentTokens', []))
        _check(got == sorted('%s:%d' % op for op in rec.spent_tokens), 'yed_gettxinfo.spentTokens', rec.height, txid)
        got = sorted(_norm_outpoint(x) for x in info.get('closedVaults', []))
        _check(got == sorted('%s:%d' % op for op in rec.closed_vaults), 'yed_gettxinfo.closedVaults', rec.height, txid)
        # v3 (contract: the TxLog additions)
        _check(_price_eq(rec.a_mint, info.get('aMint')), 'yed_gettxinfo.aMint', rec.height, '%s model=%r rpc=%r' % (txid, rec.a_mint, info.get('aMint')))
        _check(_price_eq(rec.a_claim, info.get('aClaim')), 'yed_gettxinfo.aClaim', rec.height, '%s model=%r rpc=%r' % (txid, rec.a_claim, info.get('aClaim')))
        _check(sorted(int(x) for x in info.get('bundleSeqs', [])) == sorted(rec.bundle_seqs), 'yed_gettxinfo.bundleSeqs', rec.height, txid)
        _check(int(info.get('attestFeeZat', 0)) == rec.attest_fee_zat, 'yed_gettxinfo.attestFeeZat', rec.height, txid)
        want_payee = None
        if rec.attest_payee is not None and rec.attest_payee in model.attestors:
            want_payee = hash160(model.attestors[rec.attest_payee].bond_pubkey)
        _check(_key_of(info.get('attestPayee')) == want_payee, 'yed_gettxinfo.attestPayee', rec.height, '%s model=%r rpc=%r' % (txid, rec.attest_payee, info.get('attestPayee')))
        _check(int(info.get('residualZat', 0)) == rec.residual_zat, 'yed_gettxinfo.residualZat', rec.height, '%s model=%r rpc=%r' % (txid, rec.residual_zat, info.get('residualZat')))
        _check((info.get('claimPath') or '') == rec.claim_path, 'yed_gettxinfo.claimPath', rec.height, txid)
        _check(bool(info.get('notice', False)) == rec.notice, 'yed_gettxinfo.notice', rec.height, txid)
        if _RPC_TYPE.get(str(rec.type), str(rec.type)) == 'register':
            _check(int(info.get('seq', -1)) == rec.attestor_seq, 'yed_gettxinfo.seq', rec.height, txid)


def compare_attestors(model, node):
    """Every yed_listattestors field the Attestors record holds (v3 section 3.6), plus seated /
    pinned / weight against the tip snapshot."""
    rows = {int(r['seq']): r for r in node.yed_listattestors()}
    _check(set(rows) == set(model.attestors), 'yed_listattestors set', extra='model=%r rpc=%r' % (sorted(model.attestors), sorted(rows)))
    tip = model.tip_height
    snap = model.snapshots.get(tip)
    for seq, rec in model.attestors.items():
        r = rows[seq]
        _check(str(r['attestorPubKey']).lower() == rec.attestor_pubkey.hex(), 'attestor.attestorPubKey', extra=str(seq))
        _check(_key_of(r.get('bondKeyAddress')) == hash160(rec.bond_pubkey), 'attestor.bondKeyAddress', extra=str(seq))
        _check(_norm_outpoint(r['bondOutpoint']) == '%s:%d' % rec.bond_outpoint, 'attestor.bondOutpoint', extra=str(seq))
        for name, val in (('bondZat', rec.bond_zat), ('bondLocktime', rec.bond_locktime), ('registerHeight', rec.register_height),
                          ('statusHeight', rec.status_height)):
            _check(int(r[name]) == val, 'attestor.%s' % name, extra='%d model=%r rpc=%r' % (seq, val, r[name]))
        _check(_norm_status(r['status']) == _norm_status(ATTESTOR_STATUS_NAMES[rec.status]), 'attestor.status', extra='%d model=%s rpc=%s' % (seq, ATTESTOR_STATUS_NAMES[rec.status], r['status']))
        flags = r['flags']
        _check(int(flags['tier']) == (rec.flags & 3) and bool(flags['pool']) == bool(rec.flags & 4), 'attestor.flags', extra=str(seq))
        _check((r.get('bondSpentHeight') or 0) == rec.bond_spent_height, 'attestor.bondSpentHeight', extra=str(seq))
        _check((r.get('seatedSince') or 0) == rec.seated_since, 'attestor.seatedSince', extra='%d model=%r rpc=%r' % (seq, rec.seated_since, r.get('seatedSince')))
        if snap is not None:
            _check(bool(r['seated']) == (seq in snap.seated), 'attestor.seated', tip, str(seq))
            _check(bool(r['pinned']) == (seq in snap.pinned_seqs), 'attestor.pinned', tip, str(seq))
            _check(int(r['weight']) == model.weight(rec, snap.attest, tip), 'attestor.weight', tip, '%d model=%r rpc=%r' % (seq, model.weight(rec, snap.attest, tip), r['weight']))


def compare_attest_history(model, node):
    """The v3 snapshot fields yed_gethistory does not carry, through yed_getprice(h) for every
    height in [START_HEIGHT, tip]: attest (status, triggerHeight, armHeight), seated, pinnedKeys,
    pinnedSeqs and the xMint / xClaim twins."""
    for h in range(model.params.start_height, model.tip_height + 1):
        s = model.snapshots.get(h)
        _check(s is not None, 'snapshot missing in model', h)
        row = node.yed_getprice(h)
        _check(_norm_status(row['attestStatus']) == _norm_status(ATTEST_NAMES[s.attest.status]), 'yed_getprice.attestStatus', h, repr(row.get('attestStatus')))
        _check(bool(row['armed']) == model.params.is_armed(s.attest.status), 'yed_getprice.armed', h)
        _check([int(x) for x in row['seated']] == list(s.seated), 'yed_getprice.seated', h, 'model=%r rpc=%r' % (s.seated, row['seated']))
        _check(sorted(_key_of(k) for k in row['pinnedKeys']) == sorted(s.pinned_keys), 'yed_getprice.pinnedKeys', h, 'model=%r rpc=%r' % ([k.hex() for k in s.pinned_keys], row['pinnedKeys']))
        _check([int(x) for x in row['pinnedSeqs']] == list(s.pinned_seqs), 'yed_getprice.pinnedSeqs', h, 'model=%r rpc=%r' % (s.pinned_seqs, row['pinnedSeqs']))
        _check(_price_eq(s.p_mint, row.get('xMint')) and _price_eq(s.p_claim, row.get('xClaim')), 'yed_getprice.xMint/xClaim', h)
    info = node.yed_getinfo()['attest']
    tip = model.snapshots.get(model.tip_height)
    if tip is not None:
        _check(_norm_status(info['status']) == _norm_status(ATTEST_NAMES[tip.attest.status]), 'yed_getinfo.attest.status')
        _check(int(info['triggerHeight']) == tip.attest.trigger_height and int(info['armHeight']) == tip.attest.arm_height, 'yed_getinfo.attest heights')
        _check(int(info['seatedCount']) == len(tip.seated), 'yed_getinfo.attest.seatedCount')


def compare_notices(model, node):
    """yed_getnotice for every ACTIVE vault against the Notices table (v3 section 3.6)."""
    for op, v in model.vaults.items():
        if VAULT_STATUS_NAMES[v.status] != 'ACTIVE':
            continue
        r = node.yed_getnotice(op[0])
        n = model.notices.get(op)
        _check(bool(r['found']) == (n is not None), 'yed_getnotice.found', extra='%s:%d model=%r rpc=%r' % (op[0], op[1], n is not None, r))
        if n is not None:
            _check(int(r['height']) == n.height and int(r['refHeight']) == n.ref_height, 'yed_getnotice heights', extra='%s:%d' % op)
            _check(int(r['pEmerg']) == n.p_emerg, 'yed_getnotice.pEmerg', extra='%s:%d model=%r rpc=%r' % (op[0], op[1], n.p_emerg, r['pEmerg']))
            _check(int(r['emergencyOpenAt']) == n.ref_height + model.params.emergency_persist, 'yed_getnotice.emergencyOpenAt', extra='%s:%d' % op)


def compare_vaults(model, node):
    rows = []
    skip = 0
    while True:
        page = node.yed_listvaults('', 1000, skip)
        if not page:
            break
        rows.extend(page)
        skip += len(page)
        if len(page) < 1000:
            break
    by_op = {(r['txid'], int(r.get('vout', 0))): r for r in rows}
    _check(set(by_op) == set(model.vaults), 'yed_listvaults set', extra='model=%r rpc=%r' % (sorted(model.vaults), sorted(by_op)))
    for op, v in model.vaults.items():
        r = by_op[op]
        _check(_norm_status(r['status']) == _norm_status(VAULT_STATUS_NAMES[v.status]), 'vault.status', v.mint_height, '%s:%d' % op)
        _check(str(r['ownerPubKey']).lower() == v.owner_pubkey.hex(), 'vault.ownerPubKey', v.mint_height, '%s:%d' % op)
        tc = r.get('termClass')
        _check(tc in (v.term_class, 'ABC'[v.term_class] if v.term_class < 3 else None), 'vault.termClass', v.mint_height, '%s:%d' % op)
        for name, val in (('lockHeight', v.lock_height), ('claimHeight', v.claim_height), ('collateralZat', v.collateral_zat),
                          ('mintedCents', v.minted_cents), ('mintHeight', v.mint_height), ('refHeight', v.ref_height),
                          ('feePaidZat', v.fee_paid_zat), ('closeHeight', v.close_height), ('burnedCents', v.burned_cents)):
            if name in r and r[name] is not None:
                _check(int(r[name]) == val, 'vault.%s' % name, v.mint_height, '%s:%d model=%r rpc=%r' % (op[0], op[1], val, r[name]))
        _check(bool(r.get('unbacked', False)) == v.unbacked, 'vault.unbacked', v.mint_height, '%s:%d' % op)
        _check((r.get('voidReason') or '') == v.void_reason, 'vault.voidReason', v.mint_height, '%s:%d' % op)
        if v.closing_txid is not None:
            _check(r.get('closingTxid') == v.closing_txid, 'vault.closingTxid', v.mint_height, '%s:%d' % op)


def compare_stats(model, node):
    st = node.yed_getstats()
    m = model.stats()
    for name in ('height', 'supplyCents', 'collateralZat', 'activeVaults', 'voidVaults', 'closedVaults',
                 'claimedVaults', 'unbackedCents', 'issuedZat', 'sigmaMultBps'):
        _check(int(st[name]) == m[name], 'yed_getstats.%s' % name, extra='model=%r rpc=%r' % (m[name], st[name]))
    for name in ('pFast', 'pMid', 'pSlow', 'pMint', 'pClaim', 'globalRatioBps', 'supplyCapCents'):
        _check(_price_eq(m[name], st.get(name)), 'yed_getstats.%s' % name, extra='model=%r rpc=%r' % (m[name], st.get(name)))
    _check(set(str(x).upper() for x in st.get('haltMask', [])) == set(m['haltMask']), 'yed_getstats.haltMask')
    _check(bool(st.get('mintingAllowed')) == m['mintingAllowed'], 'yed_getstats.mintingAllowed')


def assert_model_matches(node, full=False, params=None):
    """Rebuild the model from ``node`` and compare it with the node's answers: every
    ``yed_gethistory`` row (always) and, with ``full=True``, ``yed_gettxinfo`` for every
    Yellowback-relevant transaction, ``yed_listvaults``, ``yed_getstats`` and the state hash.
    Raises ModelMismatch (an AssertionError) naming the first differing field.  Returns the model."""
    model = build_model_from_node(node, params)
    compare_history(model, node)
    if full:
        compare_txinfo(model, node)
        compare_vaults(model, node)
        compare_stats(model, node)
        compare_attestors(model, node)
        compare_attest_history(model, node)
        compare_notices(model, node)
        rpc_hash = node.yed_getstatehash()
        if isinstance(rpc_hash, dict):
            rpc_hash = rpc_hash.get('hash') or rpc_hash.get('statehash') or rpc_hash.get('stateHash')
        _check(str(rpc_hash).lower() == model.state_hash(), 'yed_getstatehash', extra='model=%s rpc=%s' % (model.state_hash(), rpc_hash))
    return model


# ---------------------------------------------------------------------------
# Golden vector replay (qa/rpc-tests/test_framework/yellowback_golden.json)

def replay_golden(doc):
    """Feed the blocks of a golden document (see test_yellowback_model.py for the generator)
    and return the model.  Each block is {height, hash, subsidyZat, txs: [raw hex...]} with
    txs[0] the coinbase."""
    p = doc['params']
    params = Params.regtest(int(p['startHeight']), int(p['sigmaRefBps']), int(p['supplyCapBps']), int(p['enforceUntil']),
                            int(p.get('attestArmMin', 3)), int(p.get('bundleCarrier', CARRIER_SCRIPTSIG)))
    model = YellowbackModel(params)
    for b in doc['blocks']:
        txs = [tx_from_hex(h) for h in b['txs']]
        model.feed_block(int(b['height']), b['hash'], txs[0].vin[0].script_sig.hex(), int(b['subsidyZat']), txs[1:])
    return model


def load_golden(path):
    with open(path) as f:
        return json.load(f)
