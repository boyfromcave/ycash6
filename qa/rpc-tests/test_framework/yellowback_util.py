#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Shared helpers for the Yellowback v2 functional tests (plan section 6.0 item 4, N28).

Everything a Yellowback script needs that the inherited framework lacks:

- ``YellowbackTestFramework``: six nodes in the standard topology (section 6.0 item 2) — node 0
  the user wallet, node 1 the stock node / stock miner / adversary, nodes 2-4 the pools, node 5 a
  non-enforcing observer — connected as a star on node 1 plus 2<->3<->4 (and 0<->2, see
  ``setup_network``), with ``split_network``/``join_network`` done by ``disconnectnode``/``addnode``
  and never a restart (K19), ``sync_all`` over six nodes, ``mine``, ``mine_round_robin``,
  ``activate``, ``checkpoint``, ``kill9``, ``restart``, ``advance_clock``, ``stock_binary``.
- the v2 regtest constants of section 3.1, so no test hard-codes them.
- ``yellowback_node_args`` / ``pool_args`` / ``POOL_WIFS`` / ``address_of``.
- the raw builders: ``build_mint_tx`` (the section 3.5 MINT; the only mint builder Phases 3-5
  have, N26), ``build_vault_spend_raw`` (owner- or claim-path spends signed here with the ZIP-243
  ``SignatureHash`` and ``CECKey``, K18) and ``mine_block_raw`` (a Python-assembled block solved
  with the framework's regtest Equihash solver and handed to ``submitblock``).
- the assertions: ``assert_same_statehash``, ``assert_best_hash``, ``assert_rejected``,
  ``assert_banscore_zero``, ``wait_yed_healthy``, ``snapshot_ledger``, ``assert_model_matches``
  (from ``yellowback_model``), ``assert_start_raises_init_error`` (inherited).

The Python model (``yellowback_model.py``) is the single home of the tag/payload codecs and the
script builders; this file imports them rather than re-implementing them.

The ``mininode`` module is used for ``CTransaction``/``CBlock`` (it imports under the workspace
venv's Python 3.13 only because the venv carries the ``asyncore`` backport package; see
docs/mapping.md section 13.2).  The owner-path signer loads libcrypto through ``ctypes``; on macOS
export ``DYLD_LIBRARY_PATH="$(brew --prefix openssl@3)/lib"`` (section 6.0 item 0).  Both are
imported lazily so that importing this module never needs either.

The section at the bottom marked "v1 (retired at Phase 6)" keeps the federation-era helpers the
four v1 wallet-flow scripts and the v1 ``yellowback_index.py``/``yellowback_reorg_stress.py``
still import; nothing new may use them.
"""

import hashlib
import os
import signal
import time
from decimal import Decimal


def _point_ctypes_at_a_real_openssl():
    """``test_framework/key.py`` resolves its library with
    ``ctypes.util.find_library('ssl')``; on macOS that answers ``/usr/lib/libssl.dylib``, the
    SIP-protected LibreSSL shim, whose ``ECDSA_sign`` aborts the interpreter (SIGABRT, exit
    134).  Plan section 6.0 item 0 works around it with ``DYLD_LIBRARY_PATH``, but SIP *strips*
    every ``DYLD_*`` variable from the environment of a protected binary, and
    ``#!/usr/bin/env python3`` — the shebang ``qa/pull-tester/rpc-tests.py`` execs every script
    through (``:353``) — is exactly such a binary.  So the variable reaches a script run as
    ``python3 qa/rpc-tests/<script>.py`` and never one run through the suite runner.

    Resolving the path here, before anything imports ``key``, makes both invocations work and
    leaves the inherited ``key.py`` untouched.  No effect off Darwin or without a real OpenSSL."""
    import ctypes.util
    import glob
    import platform
    if platform.system() != 'Darwin':
        return
    search = [d for d in os.environ.get('DYLD_LIBRARY_PATH', '').split(':') if d]
    search += ['/opt/homebrew/opt/openssl@3/lib', '/usr/local/opt/openssl@3/lib']
    found = None
    for directory in search:
        matches = sorted(glob.glob(os.path.join(directory, 'libcrypto*.dylib')))
        if matches:
            found = matches[0]
            break
    if found is None:
        return
    original = ctypes.util.find_library

    def find_library(name):
        # key.py asks for 'ssl' but calls only libcrypto symbols (BN_*, EC_*, ECDSA_*).
        return found if name in ('ssl', 'crypto') else original(name)

    ctypes.util.find_library = find_library


_point_ctypes_at_a_real_openssl()

from .test_framework import BitcoinTestFramework
from .util import (
    assert_equal,
    assert_greater_than,
    assert_start_raises_init_error,
    bitcoind_processes,
    bytes_to_hex_str,
    connect_nodes_bi,
    hex_str_to_bytes,
    nuparams,
    p2p_port,
    start_node,
    start_nodes,
    stop_node,
    sync_blocks,
    sync_mempools,
)
from . import yellowback_model as ym
from .yellowback_model import assert_model_matches  # noqa: F401  (re-exported, section 7)

__all__ = [
    'YellowbackTestFramework', 'yellowback_node_args', 'pool_args', 'POOL_WIFS', 'address_of',
    'wif_to_secret', 'set_quote', 'round_robin_schedule', 'build_mint_tx', 'vault_from_mint',
    'build_vault_spend_raw', 'template_coinbase', 'mine_block_raw', 'assert_same_statehash',
    'assert_best_hash', 'assert_rejected', 'assert_banscore_zero', 'wait_yed_healthy',
    'snapshot_ledger', 'format_ledger', 'assert_model_matches', 'assert_start_raises_init_error',
    'restart_with_yellowback', 'sync_all_nodes', 'node_pubkey', 'term_class_of', 'fee_zat',
    'mint_vault_raw', 'redeem_vault_raw', 'malformed_vault_spend', 'mine_rejected_block',
    'wait_for_rejection', 'debug_log_contains',
]

# ---------------------------------------------------------------------------
# Network upgrades (ref/ycash/src/consensus/upgrades.cpp); util.py carries Zcash's ids (plan B6)

OVERWINTER_BRANCH_ID = 0x5ba81b19
SAPLING_BRANCH_ID = 0x76b809bb
YCASH_BRANCH_ID = 0x374d694f
YCASH_BLOSSOM_BRANCH_ID = 0x8e471bd6
YCASH_HEARTWOOD_BRANCH_ID = 0x66314da3
YCASH_CANOPY_BRANCH_ID = 0x19bd2d2f

# start_node already passes Overwinter and Sapling at height 1 (util.py:358-361); regtest
# activates nothing by itself (ref/ycash/src/chainparams.cpp:576-604).  Six -nuparams in all.
YCASH_UPGRADE_ARGS = [
    nuparams(YCASH_BRANCH_ID, 1),
    nuparams(YCASH_BLOSSOM_BRANCH_ID, 1),
    nuparams(YCASH_HEARTWOOD_BRANCH_ID, 1),
    nuparams(YCASH_CANOPY_BRANCH_ID, 1),
]

# With every upgrade active from height 1 the epoch of every block a test mines is Canopy's, so
# CurrentEpochBranchId(chainActive.Height() + 1) — the branch id the owner signature binds
# (section 3.4) — is this on every node.
SIGNING_BRANCH_ID = YCASH_CANOPY_BRANCH_ID

# ---------------------------------------------------------------------------
# Section 3.1, the regtest column.  Names follow the plan; values are protocol on regtest and
# compiled into RegtestParams (no flag changes them except the four M13 overrides).

COIN = 10 ** 8
CENT = 1                       # YED amounts are integer US cents
MICRO_USD = 1                  # prices are integer micro-USD per YEC; 1_000_000 = $1.00
BPS = 10_000
BLOCKS_PER_HOUR = 48
BLOCKS_PER_DAY = 1_152
BLOCKS_PER_YEAR = 420_480

START_HEIGHT = 1               # -yellowbackstartheight on every node (the same value, item 4)
TAG_MAGIC = ym.TAG_MAGIC
TAG_VERSION = ym.TAG_VERSION
TAG_SIZE = ym.TAG_SIZE
PRICE_MIN = 100
PRICE_MAX = 100_000_000
P_FAST_WINDOW = 8
P_MID_WINDOW = 24
P_SLOW_WINDOW = 64
MIN_FILL = (4, 16, 43)         # WINDOW_MIN_FILL: fast ceil(W/2); mid, slow ceil(2W/3) (V16, L9)
REF_WINDOW = 40
REF_LAG = 2
SIGNAL_WINDOW = 64
ACTIVATION_THRESHOLD = 48
PARTICIPATION_FLOOR = 39
ACTIVATION_DELAY = 64
ENFORCEMENT_FLOOR = 32
ENFORCEMENT_RESUME = 39
VALVE_BLOCKS = 6
VALVE_NOTE_CAP = 64
ABANDON_BLOCKS = 128
N_REG = 24
N_PENALTY = 12
PEER_LAG = 4
PEER_MIN = 3
DEVIATION_BPS = 1_000
ACCURACY_BAND_BPS = 300
ACCURACY_WINDOW = 24
PAYEE_TILT_BPS = 10_000
PAYEE_WINDOW = 10
FEE_MIN = 50_000_000           # enforcement fee floor, zat (0.5 YEC)
FEE_BPS = 25
GRACE = 24
CLAIM_THRESHOLD_BPS = 11_000
GLOBAL_RATIO_HALT_BPS = 25_000
DIVERGENCE_BPS = 2_000
# term classes: (minBlocks, maxBlocks, baseRatioBps); the class follows from lockBlocks (V19)
CLASS_RANGES = {'A': (48, 96, 50_000), 'B': (97, 144, 40_000), 'C': (145, 240, 30_000)}
MAX_LOCK = 240
VOL_WINDOW = 64
VOL_STEP = 8
VOL_PERIODS_PER_YEAR = 8_760
SIGMA_REF_BPS = 10_000         # mainnet; regtest takes -yellowbacksigmaref (0 = multiplier 1)
SIGMA_MULT_MAX_BPS = 30_000
MIN_MINT = 10_000
MAX_MINT = 1_000_000
MIN_OUTPUT = 100
MAX_OUTPUT = 10_000_000
TOKEN_VALUE = 10_000           # zat carried by every YED output
YELLOWBACK_FEE = 1_000         # the network fee, zat (distinct from the enforcement fee)
MAX_PAYLOAD = 80
UNDO_KEEP = 4_096
FEE_VOUT_NONE = ym.FEE_VOUT_NONE

# --- v3 (price attestation) regtest values, plan v3 section 3.1; policy rows marked ---------
PAYLOAD_VERSION_V3 = 3
ATTEST_ARM_MIN = 3
ATTEST_ARM_DELAY = 8
N_SLOTS = 5
M_SELECT = 2
K_SLACK = 1
BUNDLE_MAX = 6
Q_LOW_BPS = 3_333
Q_HIGH_BPS = 6_667
ATTEST_MAX_AGE = 8             # = 2 * ATTEST_K
PIN_WINDOW = 16
PIN_DELTA_BPS = 500
PIN_MIN_TAGS = 2
PIN_MIN_BUNDLES = 2
DIVERGE_BPS_ATTEST = 1_500
EMERGENCY_RATIO_BPS = 10_500
EMERGENCY_PERSIST = 4
EMERGENCY_NOTICE_TTL = 64
RESIDUAL_MIN_ZAT = 100_000
ATTEST_FEE_BPS = 2_500
BOND_MIN_ZAT = 10 * COIN
BOND_MIN_LOCK = 200
BOND_MATURITY = 8
AGE_CAP = 64
FOUNDING_WINDOW = 16
DORMANCY_BLOCKS = 16
DORMANCY_MIN_BUNDLES = 2
DORMANCY_CHECK = 4
CARRIER_VALUE = 10_000         # wallet policy
ATTEST_K = 4                   # agent policy: signing interval in blocks

# the blocks activate() mines: one signal window, the activation delay, and the block after
ACTIVATION_BLOCKS = SIGNAL_WINDOW + ACTIVATION_DELAY + 1     # 129

# regtest address bytes (ref/ycash/src/chainparams.cpp:613-615)
REGTEST_PUBKEY_ADDRESS = b'\x1c\x95'
REGTEST_SCRIPT_ADDRESS = b'\x1c\x2a'
REGTEST_SECRET_KEY = b'\xef'

# ---------------------------------------------------------------------------
# Standard topology (section 6.0 item 2)

USER = 0
STOCK = 1
POOLS = [2, 3, 4]
OBSERVER = 5
ENFORCING = [0, 2, 3, 4]
# v3 (plan v3 section 6.0 item 2): the two attestor wallets, present only with num_nodes=8
ATTESTOR_A = 6
ATTESTOR_B = 7
ENFORCING_V3 = ENFORCING + [ATTESTOR_A, ATTESTOR_B]

# Three fixed regtest keys for the pools' payout addresses: a pool needs its address *before* it
# starts, so the WIF is imported after start (no two-phase restart).  Secrets are
# sha256(b'yellowback-regtest-pool-<i>'); addresses are P2PKH of the compressed key.
POOL_WIFS = [
    'cQ9RpTGKp1NqLABAMv7xVV6RK6ZWhsx7ZcJgArRdD8MBa75kTEEE',
    'cQFGkN4XoV9snA1N1sxTKnX1fA5w9DCwu5Uao8tHgHtJTAcjdT4W',
    'cTa9Ej6rWau4VyxUQLEonn1DS27HzAZgoqSHz2soDp998gBHhXe8',
]


def yellowback_node_args(extra=None, yellowback=True, sigma_ref=0, start_height=START_HEIGHT, genesis=None):
    """Arguments for one node: the six -nuparams at height 1 (four here, two from start_node)
    and, with ``yellowback``, ``-experimentalfeatures -yellowback -yellowbackstartheight=<h>
    -yellowbacksigmaref=<sigma_ref>`` (0 fixes the sigma multiplier at 1; pass ``sigma_ref=None``
    in a test about sigma to leave the node's default).  ``genesis`` is the v1 scripts' federation
    genesis dict (retired at Phase 6): with it the v1 arguments are produced instead."""
    args = list(YCASH_UPGRADE_ARGS)
    if yellowback and genesis is not None:
        args += ['-experimentalfeatures', '-yellowback'] + genesis_args(genesis)
    elif yellowback:
        args += ['-experimentalfeatures', '-yellowback', '-yellowbackstartheight=%d' % start_height]
        if sigma_ref is not None:
            args += ['-yellowbacksigmaref=%d' % sigma_ref]
    if extra:
        args += list(extra)
    return args


def pool_args(payout_addr, extra=None, **kw):
    """A pool: enforcing, signalling, tagging every block it mines with ``payout_addr``."""
    return yellowback_node_args(['-yellowbackpayoutaddress=%s' % payout_addr, '-yellowbacksignal=1']
                                + list(extra or []), **kw)


def observer_args(extra=None, **kw):
    """The non-enforcing observer (records ``unbacked``)."""
    return yellowback_node_args(['-yellowbackenforce=0'] + list(extra or []), **kw)


# ---------------------------------------------------------------------------
# Keys and addresses (the framework has no base58 decoder; the model has the codec)

_B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SECP256K1_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def wif_to_secret(wif):
    """Decode a WIF private key to its 32 secret bytes."""
    n = 0
    for c in wif:
        n = n * 58 + _B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    raw = b'\x00' * (len(wif) - len(wif.lstrip('1'))) + raw
    body, check = raw[:-4], raw[-4:]
    assert_equal(hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4], check)
    secret = body[1:]                                   # the version byte
    if len(secret) == 33 and secret[-1] == 1:
        secret = secret[:-1]                            # the compressed-key marker
    assert_equal(len(secret), 32)
    return secret


def secret_to_wif(secret, compressed=True, version=REGTEST_SECRET_KEY):
    return ym.base58check_encode(version + secret + (b'\x01' if compressed else b''))


def _ec_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _SECP256K1_P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0]) * pow(2 * p[1], _SECP256K1_P - 2, _SECP256K1_P) % _SECP256K1_P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], _SECP256K1_P - 2, _SECP256K1_P) % _SECP256K1_P
    x = (lam * lam - p[0] - q[0]) % _SECP256K1_P
    return (x, (lam * (p[0] - x) - p[1]) % _SECP256K1_P)


def secret_to_pubkey(secret):
    """The 33-byte compressed public key of a secret (pure Python, so address_of() needs no
    libcrypto at node start)."""
    k = int.from_bytes(secret, 'big')
    assert 0 < k < _SECP256K1_N
    r, a = None, _SECP256K1_G
    while k:
        if k & 1:
            r = _ec_add(r, a)
        a = _ec_add(a, a)
        k >>= 1
    return bytes([2 + (r[1] & 1)]) + r[0].to_bytes(32, 'big')


def pubkey_to_address(pubkey, version=REGTEST_PUBKEY_ADDRESS):
    return ym.base58check_encode(version + ym.hash160(pubkey))


def address_of(wif, version=REGTEST_PUBKEY_ADDRESS):
    """The P2PKH address of a compressed WIF (regtest unless ``version`` says otherwise)."""
    return pubkey_to_address(secret_to_pubkey(wif_to_secret(wif)), version)


def node_pubkey(node):
    """A fresh compressed public key from the node's wallet (hex)."""
    addr = node.getnewaddress()
    pubkey = node.validateaddress(addr)['pubkey']
    assert_equal(len(pubkey), 66)
    return pubkey


def _low_s(der):
    """Re-encode a DER signature with a low S (STANDARD_SCRIPT_VERIFY_FLAGS include LOW_S)."""
    assert der[0] == 0x30 and der[2] == 0x02
    rlen = der[3]
    r = der[4:4 + rlen]
    assert der[4 + rlen] == 0x02
    slen = der[5 + rlen]
    s = int.from_bytes(der[6 + rlen:6 + rlen + slen], 'big')
    if s > _SECP256K1_N // 2:
        s = _SECP256K1_N - s
    sb = s.to_bytes((s.bit_length() + 7) // 8, 'big')
    if sb[0] & 0x80:
        sb = b'\x00' + sb
    body = b'\x02' + bytes([len(r)]) + r + b'\x02' + bytes([len(sb)]) + sb
    return b'\x30' + bytes([len(body)]) + body


# ---------------------------------------------------------------------------
# Small protocol arithmetic every test needs (section 3.1 / 3.7)

def term_class_of(lock_blocks):
    """'A' | 'B' | 'C' for a lockBlocks inside a class, else None (mint-bad-lock)."""
    for name, (lo, hi, _ratio) in CLASS_RANGES.items():
        if lo <= lock_blocks <= hi:
            return name
    return None


def fee_zat(collateral_zat):
    """FEE-1: the enforcement fee for a collateral (max(FEE_MIN, collateral * FEE_BPS / BPS))."""
    return ym.fee_zat(collateral_zat, FEE_MIN, FEE_BPS)


def usd_to_micro(usd):
    return int((Decimal(str(usd)) * 1_000_000).to_integral_value())


def set_quote(node, usd, source_mask=1):
    """``yed_setquote`` with a dollar price (``usd`` may be a str/Decimal/float; 0 clears)."""
    return node.yed_setquote(usd_to_micro(usd), source_mask)


def round_robin_schedule(pools, n, shares=None):
    """Which of ``pools`` mines each of ``n`` blocks.  Equal shares by default; with ``shares``
    (weights, one per pool) the counts are apportioned by largest remainder so they sum to ``n``
    exactly, and the blocks are interleaved by largest deficit so every prefix of the schedule is
    as close to the target ratio as integers allow."""
    pools = list(pools)
    if shares is None:
        return [pools[i % len(pools)] for i in range(n)]
    assert len(shares) == len(pools) and all(s >= 0 for s in shares) and sum(shares) > 0
    total = sum(shares)
    quotas = [Decimal(n) * Decimal(s) / Decimal(total) for s in shares]
    counts = [int(q) for q in quotas]
    remainders = sorted(range(len(pools)), key=lambda i: (quotas[i] - counts[i], -i), reverse=True)
    for i in remainders[:n - sum(counts)]:
        counts[i] += 1
    schedule = []
    mined = [0] * len(pools)
    for step in range(1, n + 1):
        open_ = [i for i in range(len(pools)) if mined[i] < counts[i]]
        i = max(open_, key=lambda i: (Decimal(counts[i]) * step / n - mined[i], -i))
        mined[i] += 1
        schedule.append(pools[i])
    assert mined == counts
    return schedule


# ---------------------------------------------------------------------------
# The framework

class YellowbackTestFramework(BitcoinTestFramework):
    """Six nodes in the standard topology.  Subclasses override ``run_test``; a subclass that
    overrides ``add_options`` or ``node_args`` calls the base first.

    Class attributes a subclass may set: ``yellowback_enabled`` (False starts every node as a
    stock node — the smoke test against a v1 binary), ``sigma_ref`` (the -yellowbacksigmaref
    value, 0 by default; None leaves the node default), ``initial_blocks`` (mined by node 0 from
    genesis before ``run_test``; 0 for none)."""

    yellowback_enabled = True
    sigma_ref = 0
    # The framework's cached 200-block chain is built with Overwinter and Sapling only
    # (util.py:262-268); with Heartwood at height 1 its headers fail LoadBlockIndex ("block index
    # inconsistency ... hashLightClientRoot != hashChainHistoryRoot"), so every Yellowback script
    # starts from genesis and node 0 mines ``initial_blocks`` (one coinbase matures) before
    # ``run_test`` (docs/mapping.md section 13.2).  Every node is therefore in IBD only until that
    # first block (P12).
    initial_blocks = 101

    def __init__(self, num_nodes=6):
        super().__init__()
        self.num_nodes = num_nodes        # v3 scripts pass 8 (nodes 6-7 the attestor wallets)
        self.setup_clean_chain = True
        self.is_network_split = False
        self.mock_time = None
        self.pool_addresses = [address_of(w) for w in POOL_WIFS]
        self.quotes = {}          # node index -> (usd, source_mask): re-applied by restart()

    # --- options ---------------------------------------------------------

    def add_options(self, parser):
        parser.add_option('--stock-binary', dest='stock_binary', default=os.getenv('REF_YCASHD') or None,
                          help='ycashd binary for node 1, the stock node (default: $REF_YCASHD, else BITCOIND)')

    def stock_binary(self):
        """The path from --stock-binary / REF_YCASHD, or None for the fork binary (P9)."""
        return getattr(self.options, 'stock_binary', None) or None

    # --- node arguments and start --------------------------------------------

    def node_args(self, i, extra=None):
        """Role-based arguments for node ``i`` (section 6.0 item 2)."""
        kw = {'sigma_ref': self.sigma_ref}
        if not self.yellowback_enabled or i == STOCK:
            return yellowback_node_args(extra, yellowback=False)
        if i in POOLS:
            return pool_args(self.pool_addresses[POOLS.index(i)], extra, **kw)
        if i == OBSERVER:
            return observer_args(extra, **kw)
        return yellowback_node_args(extra, **kw)

    def node_binaries(self):
        binaries = [None] * self.num_nodes
        binaries[STOCK] = self.stock_binary()
        return binaries

    def setup_nodes(self):
        nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                            extra_args=[self.node_args(i) for i in range(self.num_nodes)],
                            binary=self.node_binaries())
        self.import_pool_keys(nodes)
        return nodes

    def import_pool_keys(self, nodes):
        """``importprivkey`` each pool's fixed WIF on its node (after start; no rescan needed —
        nothing has paid the address yet)."""
        for k, i in enumerate(POOLS):
            if i < len(nodes) and nodes[i] is not None:
                nodes[i].importprivkey(POOL_WIFS[k], 'yellowback-payout', False)
                assert_equal(nodes[i].validateaddress(self.pool_addresses[k])['ismine'], True)

    # --- topology --------------------------------------------------------

    # star on node 1 (the stock miner's blocks reach every node), 2<->3<->4 between the pools,
    # and 0<->2 so the enforcing half {0, 2, 3, 4} stays connected while split (see the note
    # in docs/mapping.md section 13.2: the plan's star alone would isolate node 0 during a split)
    # nodes 6-7 (v3, when present) join the star on node 1 and the enforcing half of a split
    EDGES = [(1, 0), (1, 2), (1, 3), (1, 4), (1, 5), (2, 3), (3, 4), (0, 2), (1, 6), (1, 7)]
    SPLIT_HALVES = ([0, 2, 3, 4, 6, 7], [1, 5])

    def setup_network(self, split=False):
        self.nodes = self.setup_nodes()
        self.is_network_split = False
        self.setup_node_count = len(self.nodes)
        self.connect_all()
        if self.initial_blocks and self.nodes[USER].getblockcount() == 0:
            self.nodes[USER].generate(self.initial_blocks)
        if split:
            self.split_network()
        else:
            self.sync_all()

    def live_edges(self):
        """``EDGES`` restricted to nodes this run actually started.  ``EDGES`` declares the
        eight-node v3 topology, including the attestor slots 6-7, but a v2 script runs the
        six-node one -- iterating the declaration raw indexes ``self.nodes`` out of range.
        Every edge walk goes through here; ``EDGES`` is the declaration, never the iterand."""
        n = len(self.nodes)
        return [(a, b) for a, b in self.EDGES if a < n and b < n]

    def connect_all(self):
        for a, b in self.live_edges():
            connect_nodes_bi(self.nodes, a, b)

    def _cross_edges(self):
        a, b = self.SPLIT_HALVES
        return [(x, y) for x, y in self.live_edges() if (x in a and y in b) or (x in b and y in a)]

    def split_network(self, timeout=30):
        """Disconnect {1, 5} from {0, 2, 3, 4} with ``disconnectnode`` (rpc/net.cpp:220); no
        restart.  Both directions of every crossing edge are outbound ``addnode onetry``
        connections named ``127.0.0.1:<p2p port>``, so each side disconnects its own."""
        assert not self.is_network_split
        for x, y in self._cross_edges():
            self._disconnect_pair(x, y)
        deadline = time.time() + timeout
        for x, y in self._cross_edges():
            while self._connected(x, y) or self._connected(y, x):
                assert time.time() < deadline, 'nodes %d and %d did not disconnect' % (x, y)
                time.sleep(0.1)
        self.is_network_split = True

    def _disconnect_pair(self, x, y):
        for src, dst in ((x, y), (y, x)):
            try:
                self.nodes[src].disconnectnode('127.0.0.1:%d' % p2p_port(dst))
            except Exception as e:  # already gone (a node that was kill9'd, say)
                msg = str(getattr(e, 'error', {}).get('message', e) if isinstance(getattr(e, 'error', None), dict) else e)
                if 'not' not in msg.lower():
                    raise

    def _connected(self, x, y):
        addr = '127.0.0.1:%d' % p2p_port(y)
        return any(p['addr'] == addr for p in self.nodes[x].getpeerinfo())

    def join_network(self, blocks_only=True):
        """Reconnect the star.  Mempools rarely agree across a reorg join (an undone transaction
        is resurrected on one side only), so by default only blocks are synced."""
        assert self.is_network_split
        for x, y in self._cross_edges():
            connect_nodes_bi(self.nodes, x, y)
        self.is_network_split = False
        self.sync_all(blocks_only=blocks_only)

    def groups(self):
        """The connected groups of node indices given the split state.  A node a script appends
        after setup (yellowback_index.py's fresh node 6, wired to STOCK alone) belongs to no half:
        SPLIT_HALVES names the attestor slots 6-7 only when the topology started with them, and the
        script syncs a late node itself."""
        if self.is_network_split:
            n = min(len(self.nodes), getattr(self, 'setup_node_count', len(self.nodes)))
            return [[i for i in g if i < n] for g in self.SPLIT_HALVES]
        return [list(range(len(self.nodes)))]

    def sync_all(self, blocks_only=False):
        for g in self.groups():
            nodes = [self.nodes[i] for i in g if self.nodes[i] is not None]
            sync_blocks(nodes)
            if not blocks_only:
                sync_mempools(nodes)

    def enforcing_nodes(self):
        return [self.nodes[i] for i in ENFORCING_V3 if i < len(self.nodes)]

    # --- quotes --------------------------------------------------------------

    def quote(self, i, usd, source_mask=1):
        """``yed_setquote`` on node ``i`` and remember it: the quote lives in the node's memory
        (V6: the agent pushes it, nothing persists it), so ``restart`` re-applies it the way a
        pool's quote agent would within a minute."""
        self.quotes[i] = (usd, source_mask)
        return set_quote(self.nodes[i], usd, source_mask)

    # --- mining ------------------------------------------------------------

    def _node(self, n):
        return self.nodes[n] if isinstance(n, int) else n

    def mine(self, node, n=1, blocks_only=False):
        """``generate`` on ``node`` (index or proxy) then ``sync_all``; returns the hashes."""
        hashes = self._node(node).generate(n)
        self.sync_all(blocks_only=blocks_only)
        return hashes

    def mine_round_robin(self, pools, n, shares=None):
        """Mine ``n`` blocks, one at a time, over ``pools`` (indices) per ``round_robin_schedule``;
        blocks are synced (within the connected group) after each so every block builds on the
        last.  Returns the list of (miner index, block hash)."""
        out = []
        for i in round_robin_schedule(pools, n, shares):
            h = self.nodes[i].generate(1)[0]
            self.sync_all(blocks_only=True)
            out.append((i, h))
        self.last_round_robin = out
        return out

    def activate(self, pools=None, stock=None, quote_usd=None):
        """Mine ``ACTIVATION_BLOCKS`` (129) round-robin over ``pools`` (plus ``stock`` in the
        rotation when given) and assert ``yed_getactivation.status == "active"`` on every
        enforcing node.  With ``quote_usd`` every pool quotes that price first so the windows fill
        as the chain grows.  A caller that then mints mines ``REF_LAG + 1`` more blocks so
        ``Snapshots[tip - REF_LAG]`` is ACTIVE (K16).  The first fresh block also takes every
        node out of the cached chain's IBD (P12)."""
        pools = list(POOLS if pools is None else pools)
        if quote_usd is not None:
            for i in pools:
                self.quote(i, quote_usd)
        miners = pools + ([stock] if stock is not None else [])
        blocks = self.mine_round_robin(miners, ACTIVATION_BLOCKS)
        self.sync_all(blocks_only=True)
        for node in self.enforcing_nodes():
            assert_equal(node.yed_getactivation()['status'], 'active')
        return blocks

    # --- assertions ----------------------------------------------------------

    def checkpoint(self, label=''):
        """``sync_all`` + equal state hashes on the enforcing nodes + one best hash (N35); node 5
        is compared only when it is on the same chain."""
        self.sync_all(blocks_only=True)
        enforcing = self.enforcing_nodes()
        assert_best_hash(enforcing, label)
        h = assert_same_statehash(enforcing, label)
        if not self.is_network_split and self.nodes[OBSERVER].getbestblockhash() == enforcing[0].getbestblockhash():
            assert_same_statehash([enforcing[0], self.nodes[OBSERVER]], label)
        return h

    def snapshot_ledger(self, label='', nodes=None):
        rows = snapshot_ledger(self.nodes if nodes is None else nodes)
        if label:
            print(format_ledger(label, rows))
        return rows

    # --- process control -----------------------------------------------------

    def kill9(self, i):
        """SIGKILL node ``i`` (no clean shutdown, nothing flushed) and reap it; the RPC proxy is
        replaced by None until ``restart``."""
        p = bitcoind_processes.pop(i)
        os.kill(p.pid, signal.SIGKILL)
        p.wait()
        self.nodes[i] = None

    def restart(self, i, extra=None, timewait=None):
        """Stop (if running) and restart node ``i`` with its role arguments plus ``extra``, then
        reconnect its edges of the current topology."""
        if self.nodes[i] is not None:
            stop_node(self.nodes[i], i)
        self.nodes[i] = start_node(i, self.options.tmpdir, self.node_args(i, extra),
                                   binary=self.node_binaries()[i], timewait=timewait)
        if i in POOLS:
            self.import_pool_keys(self.nodes)
        if self.mock_time is not None:
            self.nodes[i].setmocktime(self.mock_time)
        if i in self.quotes:
            usd, source_mask = self.quotes[i]
            try:
                set_quote(self.nodes[i], usd, source_mask)
            except Exception:
                pass          # a node restarted without a payout address (MINER-2) holds no quote
        self.reconnect(i)
        return self.nodes[i]

    def reconnect(self, i):
        cross = self._cross_edges() if self.is_network_split else []
        for a, b in self.live_edges():
            if i in (a, b) and (a, b) not in cross \
                    and self.nodes[a] is not None and self.nodes[b] is not None:
                connect_nodes_bi(self.nodes, a, b)

    def advance_clock(self, seconds):
        """``setmocktime`` on every node (rpc/misc.cpp:1202); never ``sleep`` for a wall-clock
        case (P12).  The first call starts from now."""
        if self.mock_time is None:
            self.mock_time = int(time.time())
        self.mock_time += int(seconds)
        for node in self.nodes:
            if node is not None:
                node.setmocktime(self.mock_time)
        return self.mock_time


# ---------------------------------------------------------------------------
# Assertions and probes (module level: they take node proxies)

def _statehash(node):
    r = node.yed_getstatehash()
    if isinstance(r, dict):
        return r.get('statehash') or r.get('hash') or r.get('stateHash')
    return r


def assert_same_statehash(nodes, label=''):
    hashes = [_statehash(n) for n in nodes]
    assert_equal(hashes, [hashes[0]] * len(hashes), 'state hashes differ %s' % label)
    return hashes[0]


def assert_best_hash(nodes, label=''):
    tips = [n.getbestblockhash() for n in nodes]
    assert_equal(tips, [tips[0]] * len(tips), 'best hashes differ %s' % label)
    return tips[0]


def assert_rejected(node, blockhash):
    """The node rejected ``blockhash`` under BLK-1: it counts in ``rejectedBlocks`` and sits off
    the active chain (``confirmations == -1``)."""
    info = node.yed_getinfo()
    assert_greater_than(info['rejectedBlocks'], 0)
    assert_equal(node.getblock(blockhash)['confirmations'], -1)


def assert_banscore_zero(nodes):
    for node in nodes:
        for peer in node.getpeerinfo():
            assert_equal(peer['banscore'], 0)


def wait_yed_healthy(node, timeout=30):
    """Poll until the index is healthy and at the chain tip; returns ``yed_getinfo``."""
    deadline = time.time() + timeout
    while True:
        info = node.yed_getinfo()
        if info['healthy'] and info['height'] == node.getblockcount():
            return info
        assert time.time() < deadline, 'index not healthy at the tip within %ds: %r' % (timeout, info)
        time.sleep(0.1)


def snapshot_ledger(nodes):
    """The rc1 hash ledger: one row per node, ``{node, height, blockhash, statehash}``
    (``statehash`` None for a node without the module)."""
    rows = []
    for i, n in enumerate(nodes):
        if n is None:
            continue
        row = {'node': i, 'height': n.getblockcount(), 'blockhash': n.getbestblockhash(), 'statehash': None}
        try:
            row['statehash'] = _statehash(n)
        except Exception:
            pass
        rows.append(row)
    return rows


def format_ledger(label, rows):
    lines = ['| %s | node | height | block | state hash |' % label, '|---|---|---|---|---|']
    for r in rows:
        lines.append('| | %d | %d | %s | %s |' % (r['node'], r['height'], r['blockhash'], r['statehash'] or '-'))
    return '\n'.join(lines)


def sync_all_nodes(nodes):
    sync_blocks(nodes)
    sync_mempools(nodes)


def restart_with_yellowback(test, node_indices, extra=None, yellowback_indices=None):
    """Stop and restart the given nodes of a ``YellowbackTestFramework`` (``extra`` a list, or a
    dict index -> list); nodes not in ``yellowback_indices`` (default: all of them) restart as
    stock nodes.  Reconnects each per the topology."""
    if yellowback_indices is None:
        yellowback_indices = node_indices
    for i in node_indices:
        if test.nodes[i] is not None:
            stop_node(test.nodes[i], i)
            test.nodes[i] = None
    for i in node_indices:
        per_node = extra.get(i) if isinstance(extra, dict) else extra
        if i in yellowback_indices:
            test.restart(i, per_node)
        else:
            test.nodes[i] = start_node(i, test.options.tmpdir, yellowback_node_args(per_node, yellowback=False),
                                       binary=test.node_binaries()[i])
            test.reconnect(i)


# ---------------------------------------------------------------------------
# Raw builders (section 3.5; N26, K18)

def _spk_of_address(addr):
    return ym.p2pkh_script(ym.address_key_hash(addr))


def _select_funding(node, needed):
    """Confirmed transparent P2PKH inputs of the node, largest first, never a YED token output
    (exactly TOKEN_VALUE) and never a P2SH output (a vault)."""
    utxos = [u for u in node.listunspent(1)
             if int(Decimal(str(u['amount'])) * COIN) != TOKEN_VALUE
             and not ym.is_p2sh(hex_str_to_bytes(u['scriptPubKey']))]
    utxos.sort(key=lambda u: Decimal(str(u['amount'])), reverse=True)
    chosen, total = [], 0
    for u in utxos:
        chosen.append(u)
        total += int(Decimal(str(u['amount'])) * COIN)
        if total >= needed:
            break
    assert total >= needed, 'insufficient YEC to hand-build the transaction (%d < %d zat)' % (total, needed)
    return chosen, total


def build_mint_tx(node, cents, lock_blocks, ref_height, collateral_zat, fee_addr=None, owner_pubkey=None,
                  fee_zat_override=None, term_class=None, expiry=None):
    """The raw MINT of section 3.5, funded from ``node``'s confirmed transparent coins and signed
    with ``signrawtransaction``.  Outputs: vault ``vout[0]`` (P2SH of the vault script,
    ``collateral_zat`` — from ``yed_estimatecollateral``), token ``vout[1]`` (P2PKH of the owner
    key, ``TOKEN_VALUE``), payload ``vout[2]`` (``feeVout = 3`` when ``fee_addr`` — from
    ``yed_getfeepayee`` — else ``0xFF``), fee ``vout[3]`` (``fee_zat(collateral)`` unless
    ``fee_zat_override``; absent without ``fee_addr``), then YEC change (``vout[4]`` with a fee
    output, ``vout[3]`` without).  ``lockHeight = ref_height + lock_blocks``, ``claimHeight =
    lockHeight + GRACE``, ``nExpiryHeight = ref_height + REF_WINDOW`` unless ``expiry``.
    ``term_class`` follows from ``lock_blocks`` unless given (adversarial payloads).
    Returns ``(hex, owner_pubkey_hex)``."""
    if owner_pubkey is None:
        owner_pubkey = node_pubkey(node)
    owner = hex_str_to_bytes(owner_pubkey)
    assert_equal(len(owner), 33)
    if term_class is None:
        term_class = term_class_of(lock_blocks)
        assert term_class is not None, 'lock_blocks %d is outside every class (pass term_class= to build it anyway)' % lock_blocks
    class_index = 'ABC'.index(term_class) if isinstance(term_class, str) else int(term_class)
    lock_height = ref_height + lock_blocks
    claim_height = lock_height + GRACE
    vault = ym.vault_script(lock_height, owner, claim_height)
    fee_vout = 3 if fee_addr else FEE_VOUT_NONE
    payload = ym.encode_mint(class_index, cents, lock_height, ref_height, owner, fee_vout)
    vout = [
        (collateral_zat, ym.p2sh_script(vault)),
        (TOKEN_VALUE, ym.p2pkh_script(ym.hash160(owner))),
        (0, bytes([ym.OP_RETURN]) + ym.push(payload)),
    ]
    enforcement_fee = 0
    if fee_addr:
        enforcement_fee = fee_zat(collateral_zat) if fee_zat_override is None else fee_zat_override
        vout.append((enforcement_fee, _spk_of_address(fee_addr)))
    needed = collateral_zat + TOKEN_VALUE + enforcement_fee + YELLOWBACK_FEE
    utxos, total = _select_funding(node, needed)
    if total - needed > 0:
        vout.append((total - needed, _spk_of_address(node.getnewaddress())))
    vin = [(u['txid'], u['vout'], b'', 0xFFFFFFFF) for u in utxos]
    raw = ym.serialize_tx_v4(vin, vout, 0, ref_height + REF_WINDOW if expiry is None else expiry)
    signed = node.signrawtransaction(bytes_to_hex_str(raw))
    assert_equal(signed['complete'], True)
    return signed['hex'], owner_pubkey


def vault_from_mint(mint_hex, lock_blocks, ref_height, owner_pubkey):
    """The ``vault`` dict ``build_vault_spend_raw`` takes (the ``yed_getvault`` shape), derived
    from a ``build_mint_tx`` result without the index: ``{txid, vout, collateralZat, lockHeight,
    claimHeight, ownerPubKey, ownerAddress, refHeight}``."""
    tx = ym.tx_from_hex(mint_hex)
    owner = hex_str_to_bytes(owner_pubkey)
    lock_height = ref_height + lock_blocks
    return {'txid': tx.txid, 'vout': 0, 'collateralZat': tx.vout[0].value, 'lockHeight': lock_height,
            'claimHeight': lock_height + GRACE, 'ownerPubKey': owner_pubkey,
            'ownerAddress': pubkey_to_address(owner), 'refHeight': ref_height}


def _outpoint(o):
    if isinstance(o, dict):
        return o['txid'], int(o['vout'])
    if isinstance(o, str):
        txid, n = o.split(':')
        return txid, int(n)
    return o[0], int(o[1])


def build_vault_spend_raw(node, vault, path, burn_inputs, payload=None, fee=None, expiry=None,
                          to=None, ref_height=None, extra_outputs=None, owner_wif=None,
                          branch_id=SIGNING_BRANCH_ID, selector=None, carrier=None, carrier_wif=None,
                          charge_extra=False, extra_vin=None, value_adjust=0):
    """A vault spend assembled here (section 3.4/3.5), the adversarial builder for every
    "without a burn" case (K18) and, with ``payload=encode_redeem(...)`` and ``fee=(addr, zat)``,
    the *correct* spends too.

    ``vault``: a ``yed_getvault`` result or ``vault_from_mint`` dict.  ``path``: ``'owner'``
    (scriptSig ``<ownerSig> OP_1 <vaultScript>``, signed in Python with the owner key from
    ``dumpprivkey`` — or ``owner_wif`` — over the ZIP-243 sighash with the vault's value and
    ``branch_id``; ``nLockTime = lockHeight``) or ``'claim'`` (``OP_0 <vaultScript>``, unsigned;
    ``nLockTime = claimHeight``).  ``vin[0].nSequence = 0xFFFFFFFE``.  ``burn_inputs``: YED token
    outpoints of ``node``'s wallet (``'txid:n'``, ``(txid, n)`` or dicts), spent as ``vin[1..]``
    and signed by ``signrawtransaction``; ``[]`` for no burn.  Outputs: ``vout[0]`` the
    collateral plus the burned tokens' value minus ``YELLOWBACK_FEE`` and the enforcement fee to
    ``to`` (default a fresh address of ``node``); ``vout[1]`` the enforcement fee when ``fee``
    (so a REDEEM payload names ``feeVout = 1``); then ``extra_outputs`` (``[(zat, script)]``,
    e.g. YED change); then the ``OP_RETURN`` ``payload`` if any.  ``nExpiryHeight = expiry`` if
    given, else ``ref_height + REF_WINDOW`` with ``ref_height`` defaulting to the vault's
    ``refHeight`` when known, else ``getblockcount() - REF_LAG``.  ``selector`` overrides the
    path push (K4 tests).  **v3:** ``carrier`` (a ``build_carrier_tx`` dict, confirmed) is
    spent as the last input, signed by ``spend_carrier`` after the wallet signs the burns, and
    its ``CARRIER_VALUE`` joins ``vout[0]``; with ``charge_extra`` the values of
    ``extra_outputs`` (the attestor fee, RED-5's residual) come out of ``vout[0]`` too.
    Alternatively ``extra_vin`` (``[(txid, n, sequence)]``) appends unsigned inputs after the
    burns and ``value_adjust`` is added to ``vout[0]`` verbatim.  Returns the hex."""
    assert path in ('owner', 'claim')
    owner = hex_str_to_bytes(vault['ownerPubKey'])
    lock_height, claim_height = int(vault['lockHeight']), int(vault['claimHeight'])
    collateral = int(vault['collateralZat'])
    script = ym.vault_script(lock_height, owner, claim_height)
    burns = [_outpoint(o) for o in burn_inputs]
    enforcement_fee = int(fee[1]) if fee else 0
    value = collateral + TOKEN_VALUE * len(burns) - YELLOWBACK_FEE - enforcement_fee + int(value_adjust)
    if carrier is not None:
        value += CARRIER_VALUE
    if charge_extra:
        value -= sum(int(v) for v, _s in (extra_outputs or []))
    assert value > 0, 'the vault does not cover the fees'
    dest = to or node.getnewaddress()
    vout = [(value, _spk_of_address(dest))]
    if fee:
        vout.append((enforcement_fee, _spk_of_address(fee[0])))
    for v, s in (extra_outputs or []):
        vout.append((int(v), bytes(s)))
    if payload is not None:
        vout.append((0, bytes([ym.OP_RETURN]) + ym.push(bytes(payload))))
    if expiry is None:
        if ref_height is None:
            ref_height = vault.get('refHeight')
            if ref_height is None:
                ref_height = node.getblockcount() - REF_LAG
        expiry = int(ref_height) + REF_WINDOW
    lock_time = lock_height if path == 'owner' else claim_height
    vin = [(vault['txid'], int(vault['vout']), b'', 0xFFFFFFFE)] + [(t, n, b'', 0xFFFFFFFF) for t, n in burns]
    if carrier is not None:
        vin.append((carrier['txid'], int(carrier['vout']), b'', 0xFFFFFFFF))
    vin += [(t, n, b'', seq) for t, n, seq in (extra_vin or [])]
    raw = ym.serialize_tx_v4(vin, vout, lock_time, expiry)
    if burns:
        # the wallet signs the token inputs; it cannot solve OP_IF and leaves vin[0] empty
        raw = hex_str_to_bytes(node.signrawtransaction(bytes_to_hex_str(raw))['hex'])
    if carrier is not None:
        from . import yellowback_attest as ya
        raw = hex_str_to_bytes(ya.spend_carrier(node, bytes_to_hex_str(raw), len(vin) - 1, carrier, carrier_wif, branch_id))
    from io import BytesIO
    from .mininode import CTransaction
    from .script import CScript, SIGHASH_ALL, SignatureHash
    tx = CTransaction()
    tx.deserialize(BytesIO(raw))
    if path == 'owner':
        from .key import CECKey
        # yed_getvault's ownerAddress is the ye/yt/yr rendering (§3.1); the wallet knows the key by
        # its P2PKH address, so derive that from the owner key rather than trust the field.
        wif = owner_wif or node.dumpprivkey(pubkey_to_address(owner))
        key = CECKey()
        key.set_secretbytes(wif_to_secret(wif))
        key.set_compressed(True)
        assert_equal(key.get_pubkey(), owner)
        sighash = SignatureHash(CScript(script), tx, 0, SIGHASH_ALL, collateral, branch_id)[0]
        sig = _low_s(key.sign(sighash)) + bytes([SIGHASH_ALL])
        sel = bytes([ym.OP_1]) if selector is None else selector
        tx.vin[0].scriptSig = ym.push(sig) + sel + ym.push(script)
    else:
        sel = bytes([ym.OP_0]) if selector is None else selector
        tx.vin[0].scriptSig = sel + ym.push(script)
    return bytes_to_hex_str(tx.serialize())


def template_coinbase(node):
    """``(coinbase CTransaction, getblocktemplate result)`` for the next block on ``node``'s tip;
    edit the coinbase (its scriptSig for a forged tag, ``vout[0].nValue`` for a wrong subsidy)
    and pass it to ``mine_block_raw(coinbase=...)``.  The template's coinbase value includes the
    fees of the template's own transactions; those are removed here so the coinbase claims the
    subsidy alone (``bad-cb-amount`` polices only an excess).  ``getblocktemplate`` refuses
    without a peer or during IBD (rpc/mining.cpp:556-559): mine one fresh block first (P12)."""
    from io import BytesIO
    from .mininode import CTransaction
    gbt = node.getblocktemplate()
    cb = CTransaction()
    cb.deserialize(BytesIO(hex_str_to_bytes(gbt['coinbasetxn']['data'])))
    cb.vout[0].nValue -= sum(int(t.get('fee', 0)) for t in gbt.get('transactions', []))
    return cb, gbt


def mine_block_raw(node, txs, coinbase=None, gbt=None, n_time=None):
    """Assemble a block of ``txs`` (hex strings or ``CTransaction``s) on ``node``'s tip in
    Python (``mininode.CBlock``; header fields from ``getblocktemplate``; ``coinbase`` from
    ``template_coinbase`` unless given), solve regtest Equihash (n=48, k=5; seconds), and
    ``submitblock``.  Returns ``(result, blockhash)``: ``None`` / ``'duplicate'`` for accept,
    ``'yellowback-vault-spend'`` / ``'bad-cb-amount'`` and the like for reject."""
    from io import BytesIO
    from .mininode import CBlock, CTransaction
    if coinbase is None or gbt is None:
        cb, tpl = template_coinbase(node)
        coinbase = coinbase or cb
        gbt = gbt or tpl
    block = CBlock()
    block.nVersion = gbt['version']
    block.hashPrevBlock = int(gbt['previousblockhash'], 16)
    block.hashFinalSaplingRoot = int(gbt['finalsaplingroothash'], 16)
    block.nTime = gbt['curtime'] if n_time is None else n_time
    block.nBits = int(gbt['bits'], 16)
    block.vtx = [coinbase]
    for t in txs:
        if isinstance(t, str):
            tx = CTransaction()
            tx.deserialize(BytesIO(hex_str_to_bytes(t)))
            t = tx
        block.vtx.append(t)
    block.hashMerkleRoot = block.calc_merkle_root()
    block.solve()
    result = node.submitblock(bytes_to_hex_str(block.serialize()))
    return result, '%064x' % block.sha256


# ---------------------------------------------------------------------------
# Phase 3 drivers over the raw builders (N26): a vault from build_mint_tx, a rule-breaking spend
# from build_vault_spend_raw mined by the stock node, and the assertions around a rejection.

TX_EXPIRING_SOON_THRESHOLD = 3     # ref/ycash/src/consensus/consensus.h; a mempool refuses a closer expiry


def mint_vault_raw(test, user, pool, cents=10_000, lock_blocks=48, fee=True):
    """Mint an ACTIVE vault from ``user``'s coins with ``build_mint_tx`` (collateral from
    ``yed_estimatecollateral``, the fee payee from ``yed_getfeepayee``), broadcast it with
    ``sendrawtransaction`` on ``user`` and mine it on ``pool``.  Returns ``(txid, yed_getvault)``."""
    est = user.yed_estimatecollateral(cents, lock_blocks)
    ref = int(est['refHeight'])
    fee_addr = None
    if fee:
        fee_addr = user.yed_getfeepayee(ref, int(est['requiredZat']))['default']['payoutAddress']
    hex_, _owner = build_mint_tx(user, cents, lock_blocks, ref, int(est['requiredZat']), fee_addr=fee_addr)
    txid = user.sendrawtransaction(hex_)
    test.sync_all()
    test.mine(pool)
    vault = user.yed_getvault(txid)
    assert_equal(vault['status'], 'ACTIVE')
    return txid, vault


def redeem_vault_raw(test, user, pool, vault, token_outpoints):
    """The correct owner-path redemption of ``vault`` (RED-1..4: the REDEEM payload with
    ``feeVout = 1``, the FEE-1 fee to the FEE-W payee, the burn of ``token_outpoints``), broadcast
    with ``sendrawtransaction`` on ``user`` (MP-1 admits it) and mined on ``pool``.  Returns the
    txid."""
    ref = user.getblockcount() - REF_LAG
    payee = user.yed_getfeepayee(ref, int(vault['collateralZat']))
    payload = ym.encode_redeem(ref, 1, [])
    hex_ = build_vault_spend_raw(user, vault, 'owner', token_outpoints, payload=payload,
                                 fee=(payee['default']['payoutAddress'], int(payee['feeZat'])),
                                 ref_height=ref)
    check = user.yed_validaterawtransaction(hex_)
    assert_equal(check['blockValid'], True)
    assert_equal(check['wouldBeRejected'], False)
    txid = user.sendrawtransaction(hex_)
    test.sync_all()
    test.mine(pool)
    return txid


def malformed_vault_spend(user, vault, next_height):
    """An owner-path spend with no burn and no payload: fails RED-1 (``vault-spend-malformed``)
    on an enforcing node, an ordinary transaction to a stock node.  Expires at ``next_height +
    TX_EXPIRING_SOON_THRESHOLD`` so it leaves every mempool a few blocks later."""
    return build_vault_spend_raw(user, vault, 'owner', [], expiry=next_height + TX_EXPIRING_SOON_THRESHOLD)


def mine_rejected_block(test, user, vault, stock=None):
    """The stock node mines a block carrying a malformed spend of ``vault`` (which must be past
    its lockHeight).  Returns ``(blockhash, txid)``; the caller asserts the rejection."""
    stock = test.nodes[STOCK] if stock is None else stock
    hex_ = malformed_vault_spend(user, vault, stock.getblockcount() + 1)
    txid = stock.sendrawtransaction(hex_)
    blockhash = stock.generate(1)[0]
    assert txid in [t['txid'] if isinstance(t, dict) else t for t in stock.getblock(blockhash)['tx']]
    return blockhash, txid


def wait_for_rejection(nodes, blockhash, timeout=30):
    """Until every node in ``nodes`` holds ``blockhash`` off its active chain with a rejection on
    record (``assert_rejected``)."""
    deadline = time.time() + timeout
    for node in nodes:
        while True:
            try:
                if node.getblock(blockhash)['confirmations'] == -1 and node.yed_getinfo()['rejectedBlocks'] > 0:
                    break
            except Exception:
                pass
            assert time.time() < deadline, 'block %s was not rejected within %ds' % (blockhash, timeout)
            time.sleep(0.1)
        assert_rejected(node, blockhash)


def debug_log_contains(tmpdir, i, needle):
    """True iff node ``i``'s regtest debug.log contains ``needle``."""
    path = os.path.join(tmpdir, 'node%d' % i, 'regtest', 'debug.log')
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        return needle in f.read()


# ---------------------------------------------------------------------------
# --- v1 (retired at Phase 6) -------------------------------------------------
# The federation prototype's helpers, kept only so the v1 scripts (yellowback_lifecycle.py,
# yellowback_void_mint.py, yellowback_wallet_restore.py, yellowback_sapling.py and the not yet
# rewritten yellowback_index.py / yellowback_reorg_stress.py) still import until Phase 3/6
# rewrite them.  Phase 2 removes the four flows from CI.  Nothing v2 may use any of these.

MINT_WINDOW = 40               # v1 name of REF_WINDOW
PRICE_MAX_AGE = 48             # v1 PRICE staleness; no v2 equivalent
DEFAULT_MINT_EVAL_LAG = 2      # v1 name of REF_LAG

_PUBKEY_ADDR = {}   # pubkey hex -> address, so cosign_and_submit can dumpprivkey it


def genesis_args(genesis):
    return [
        '-yellowbackstartheight=%d' % genesis['height'],
        '-yellowbackgenesisanchor=%s:%d' % (genesis['txid'], genesis['vout']),
        '-yellowbackgenesisroster=%s' % genesis['script'],
    ]


def assert_yed_synced(nodes):
    """After sync_blocks the index is healthy and at the chain tip on every -yellowback node.
    (v1 read a `synced` field; v2's yed_getinfo reports `healthy` and `height` instead.)"""
    sync_blocks(nodes)
    for node in nodes:
        info = node.yed_getinfo()
        assert_equal(info['healthy'], True, "index unhealthy: " + info['unhealthyReason'])
        assert_equal(info['height'], node.getblockcount())


def wait_yed_synced(node, timeout=30):
    """Poll until the index is healthy and at the chain tip (the v1 name of wait_yed_healthy)."""
    wait_yed_healthy(node, timeout)


def make_regtest_roster(signer_nodes, k, extra_pubkeys=None):
    """v1: a k-of-n roster from one key per signer node, registered with addmultisigaddress."""
    pubkeys = []
    for n in signer_nodes:
        addr = n.getnewaddress()
        pub = n.validateaddress(addr)['pubkey']
        _PUBKEY_ADDR[pub] = addr
        pubkeys.append(pub)
    pubkeys += list(extra_pubkeys or [])
    pubkeys = sorted(pubkeys, key=lambda h: bytes.fromhex(h))
    address = None
    for n in signer_nodes:
        a = n.addmultisigaddress(k, pubkeys)
        if address is None:
            address = a
        assert_equal(a, address)
    script = signer_nodes[0].validateaddress(address)['hex']
    return {'k': k, 'n': len(pubkeys), 'pubkeys': pubkeys, 'script': script, 'address': address}


def fund_genesis_anchor(funder, roster, amount=Decimal('1.0')):
    """v1: pay the roster's P2SH address and mine one block; returns the genesis dict."""
    txid = funder.sendtoaddress(roster['address'], amount)
    funder.generate(1)
    height = funder.getblockcount()
    raw = funder.decoderawtransaction(funder.gettransaction(txid)['hex'])
    vout = None
    for out in raw['vout']:
        if out['scriptPubKey'].get('addresses') == [roster['address']]:
            vout = out['n']
    assert vout is not None
    return {'txid': txid, 'vout': vout, 'height': height, 'script': roster['script'],
            'address': roster['address'], 'k': roster['k'], 'pubkeys': roster['pubkeys']}


def build_price_tx(node, price, refill=None, rotate_script=None):
    """v1: the unsigned PRICE (or ROTATION) transaction spending the anchor."""
    from .mininode import COutPoint, CTransaction, CTxIn, CTxOut
    from .script import CScript, OP_RETURN
    a = node.yed_getinfo()['anchor']
    assert a['valid'], 'anchor custody is broken'
    txid, vout, value = a['txid'], a['vout'], a['valueZat']
    spk = hex_str_to_bytes(node.validateaddress(a['address'])['scriptPubKey'])
    unconfirmed = False
    for _ in range(100):
        spender = None
        for mtxid in node.getrawmempool():
            raw = node.getrawtransaction(mtxid, 1)
            if any(v.get('txid') == txid and v.get('vout') == vout for v in raw['vin']):
                spender = raw
                break
        if spender is None:
            break
        txid, vout, value = spender['txid'], 0, int(spender['vout'][0]['value'] * 100000000)
        spk = hex_str_to_bytes(spender['vout'][0]['scriptPubKey']['hex'])
        unconfirmed = True
    tx = CTransaction()
    tx.vin.append(CTxIn(COutPoint(int(txid, 16), vout)))
    refill_value = 0
    if refill:
        rtxid, rn = refill.split(':')
        out = node.gettxout(rtxid, int(rn))
        assert out is not None, 'refill outpoint is not a confirmed unspent output'
        refill_value = int(out['value'] * 100000000)
        tx.vin.append(CTxIn(COutPoint(int(rtxid, 16), int(rn))))
    new_value = value + refill_value - YELLOWBACK_FEE
    assert new_value > 0, 'anchor value does not cover the fee'
    if rotate_script is not None:
        p2sh = node.decodescript(rotate_script)['p2sh']
        spk = hex_str_to_bytes(node.validateaddress(p2sh)['scriptPubKey'])
    tx.vout.append(CTxOut(new_value, CScript(spk)))
    if rotate_script is None:
        payload = bytes([0x59, 0x42, 0x01, 0x10]) + int(price).to_bytes(8, 'little')
        tx.vout.append(CTxOut(0, CScript([OP_RETURN, payload])))
    tx.nExpiryHeight = node.getblockcount() + 1 + MINT_WINDOW
    return {'hex': bytes_to_hex_str(tx.serialize()),
            'anchor': {'txid': txid, 'vout': vout, 'valueZat': value, 'unconfirmed': unconfirmed},
            'refillValueZat': refill_value, 'newAnchorValueZat': new_value, 'feeZat': YELLOWBACK_FEE}


def publish_price(builder, signers, price, refill=None, rotate_script=None, prevtxs=None):
    """v1: build, k-sign and broadcast the PRICE transaction; returns the txid."""
    built = build_price_tx(builder, price, refill=refill, rotate_script=rotate_script)
    unsigned = built['hex']
    partials = []
    for s in signers:
        if prevtxs is not None:
            r = s.signrawtransaction(unsigned, prevtxs)
        else:
            r = s.signrawtransaction(unsigned)
        partials.append(r['hex'])
    if len(partials) == 1:
        merged = signers[0].signrawtransaction(partials[0], prevtxs if prevtxs is not None else [])
    else:
        merged = signers[0].signrawtransaction(''.join(partials), prevtxs if prevtxs is not None else [])
    assert_equal(merged['complete'], True)
    return builder.sendrawtransaction(merged['hex'])


def build_mint_tx_v1(node, cents, tier, lock_height, eval_height, collateral_zat, owner_pubkey=None, roster_script_hex=None):
    """v1: the federation MINT (vault = CLTV + owner + roster multisig; version-1 payload)."""
    from .mininode import COutPoint, CTransaction, CTxIn, CTxOut
    from .script import CScript, OP_NOP2, OP_CHECKSIGVERIFY, OP_DROP, OP_RETURN
    OP_CHECKLOCKTIMEVERIFY = OP_NOP2
    if owner_pubkey is None:
        owner_pubkey = node.validateaddress(node.getnewaddress())['pubkey']
    assert roster_script_hex is not None, 'pass the roster script (genesis["script"])'
    owner = hex_str_to_bytes(owner_pubkey)
    vault = CScript(bytes(CScript([lock_height, OP_CHECKLOCKTIMEVERIFY, OP_DROP, owner, OP_CHECKSIGVERIFY])) + hex_str_to_bytes(roster_script_hex))
    p2sh = node.decodescript(bytes_to_hex_str(bytes(vault)))['p2sh']
    vault_spk = hex_str_to_bytes(node.validateaddress(p2sh)['scriptPubKey'])
    token_spk = hex_str_to_bytes(node.validateaddress(node.getnewaddress())['scriptPubKey'])
    payload = (bytes([0x59, 0x42, 0x01, 0x01, tier]) + int(cents).to_bytes(4, 'little') +
               int(lock_height).to_bytes(4, 'little') + int(eval_height).to_bytes(4, 'little') + owner)
    needed = collateral_zat + TOKEN_VALUE + YELLOWBACK_FEE
    utxos = sorted([u for u in node.listunspent(1)], key=lambda u: u['amount'])
    tx = CTransaction()
    total = 0
    for u in utxos:
        tx.vin.append(CTxIn(COutPoint(int(u['txid'], 16), u['vout'])))
        total += int(u['amount'] * 100000000)
        if total >= needed:
            break
    assert total >= needed, 'insufficient YEC to hand-build the mint'
    tx.vout.append(CTxOut(collateral_zat, CScript(vault_spk)))
    tx.vout.append(CTxOut(TOKEN_VALUE, CScript(token_spk)))
    tx.vout.append(CTxOut(0, CScript([OP_RETURN, payload])))
    if total - needed > 0:
        change_spk = hex_str_to_bytes(node.validateaddress(node.getnewaddress())['scriptPubKey'])
        tx.vout.append(CTxOut(total - needed, CScript(change_spk)))
    tx.nExpiryHeight = node.getblockcount() + 40
    signed = node.signrawtransaction(bytes_to_hex_str(tx.serialize()))
    assert_equal(signed['complete'], True)
    return signed['hex'], owner_pubkey


def cosign_and_submit(owner_node, signer_nodes, redeem_hex):
    """v1: complete an owner-signed yed_redeem with the roster signatures, then broadcast."""
    from io import BytesIO
    from .key import CECKey
    from .mininode import CTransaction
    from .script import CScript, SIGHASH_ALL, SignatureHash
    tx = CTransaction()
    tx.deserialize(BytesIO(hex_str_to_bytes(redeem_hex)))
    pushes = list(CScript(tx.vin[0].scriptSig))        # OP_0 <ownerSig> <vaultScript>
    assert_equal(len(pushes), 3)
    owner_sig, vault_script = pushes[1], pushes[2]
    keys = [p for p in CScript(vault_script) if isinstance(p, bytes) and len(p) == 33]
    roster_keys = keys[1:]                              # keys[0] is the owner
    vault = owner_node.yed_getvault('%064x' % tx.vin[0].prevout.hash)
    sighash = SignatureHash(CScript(vault_script), tx, 0, SIGHASH_ALL, vault['collateralZat'], YCASH_CANOPY_BRANCH_ID)[0]
    sigs = {}
    for n in signer_nodes:
        for i, pub in enumerate(roster_keys):
            addr = _PUBKEY_ADDR.get(bytes_to_hex_str(pub))
            if addr is None or i in sigs or not n.validateaddress(addr)['ismine']:
                continue
            k = CECKey()
            k.set_secretbytes(wif_to_secret(n.dumpprivkey(addr)))
            k.set_compressed(True)
            assert_equal(bytes_to_hex_str(k.get_pubkey()), bytes_to_hex_str(pub))
            sigs[i] = _low_s(k.sign(sighash)) + bytes([SIGHASH_ALL])
            break
    assert sigs, 'no signer node holds a roster key of this vault'
    tx.vin[0].scriptSig = CScript([b''] + [sigs[i] for i in sorted(sigs)] + [owner_sig, vault_script])
    return owner_node.sendrawtransaction(bytes_to_hex_str(tx.serialize()))
