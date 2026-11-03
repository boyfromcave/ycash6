#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The mixed-line harness: kogany (``koganyd``) followers inside the unchanged ycash6 regtest scripts.

Kogany plan K-18 (a), W1-Y7 (harness part), W2-d, W4-e; plan section 4.2 rule 4 (the three-way
cross-line invariant) and section 5 ("The mixed-line harness").  Nothing here changes a script:
the framework starts the followers, and the sync and verdict hooks run inside the existing
``sync_blocks`` / ``sync_mempools`` / ``start_node`` / ``mine_block_raw`` / ``assert_rejected``.
With ``KOGANY_BIN`` unset every entry point is inert, so a run without it is the plain ycash6
regression (CI runs both, so a kogany failure never hides as a C++ failure).

Environment
-----------

``KOGANY_BIN``            path to ``koganyd`` (kogany).  Unset: no follower, every hook a no-op.
``KOGANY_FOLLOWERS``      followers to start (default 1).  Slot k uses ``tmpdir/kogany<k>`` and the
                          ports ``kogany_p2p_port(k)`` / ``kogany_rpc_port(k)`` (a range of their own,
                          never one of ycashd's).
``KOGANY_PEER``           the ycashd node index each follower peers with and is compared against
                          (default: the script's ``SCRIPT_PEER`` row, else the framework's ``kogany_peer``
                          attribute; ``BitcoinTestFramework`` says 1 when it has two nodes or more,
                          ``YellowbackTestFramework`` says 0).
``KOGANY_LIVE``           comma list of chunks whose pending key-table rows are emitted as keys
                          (e.g. ``W1-Y1,W2-b`` once kogany parses ``Ycash`` / ``Vault``), added to
                          ``DEFAULT_LIVE`` (``W5-f``: the ``[yellowback]`` rows); ``!<chunk>`` turns a
                          default chunk off (``KOGANY_LIVE=!W5-f`` for a kogany without W5-f).
``KOGANY_STRICT``         1: a missing kogany RPC, an unmapped reject reason or an unclassified kogany
                          reject fails the run instead of being skipped with a note (default 0).
``KOGANY_MEMPOOL``        1: assert ``getrawmempool`` set equality at every mempool sync point and
                          compare transaction verdicts (default 0, until W6 lands kogany's policy).
``KOGANY_SYNC_TIMEOUT``   seconds a follower may take to reach the peer's tip (default 120).
``KOGANY_TX_TIMEOUT``     seconds ``offer_tx`` waits for kogany's ``sendrawtransaction`` (default 10): Zakura
                          waits up to six minutes for a missing input, and no answer is compared as
                          ``reject-state`` (ycashd's "Missing inputs").
``KOGANY_MIRROR_INVALIDATE``  1: mirror a script's ``invalidateblock``/``reconsiderblock`` on the peer
                          to the followers at sync points (``MixedLine._mirror``; default 0).
``KOGANY_PRUNED``         1: the followers run Zakura's Pruned storage mode (pruning assessment KP-2):
                          ``[state.storage_mode.pruned] tx_retention = KOGANY_PRUNE_RETENTION`` in their
                          ``koganyd.toml``; every sync point also asserts the follower reports
                          ``getblockchaininfo.pruned`` with a ``pruneheight`` (default 0).
``KOGANY_PRUNE_RETENTION``  the followers' ``tx_retention`` under ``KOGANY_PRUNED=1`` (default 1001,
                          Zakura's regtest floor ``MAX_BLOCK_REORG_HEIGHT + 1``; a smaller value makes
                          koganyd refuse to start).
``KOGANY_ARGS``           extra ``koganyd`` arguments, whitespace-separated, placed before ``start``.
``KOGANY_LOG``            ``tracing.filter`` for the followers (default ``info``).
``KOGANY_STATS_FILE``     a file the run appends one JSON line to when the followers stop: the
                          script, the counters (sync points, statehash points, verdicts, verdict
                          classes, mempool points) and the notes (rpc-tests.py prints a passing
                          script's output nowhere; W9-b's results table reads this).
``YEWD_BIN``              path to ``yewd`` (the parity sidecar, plan section 3b): every node becomes a
                          ycashd ``-disablewallet`` backend plus a yewd in front of it on the node's
                          RPC port (``start_yewd_pair``; contract: yew/yewd/README.md "Harness mode").
                          Independent of ``KOGANY_BIN``.
``KOGANY_SIDECAR``        1 (with ``KOGANY_BIN``): the ycash6 test rig of W9-a (K-3 as amended): node i is
                          kogany i on ``p2p_port(i)`` plus ycashd i with ``-connect`` to it and
                          ``-listen=0`` on ``rpc_port(i)`` (``start_sidecar``; "The ycash6 test rig"
                          below).  No peer follower is started; each kogany is compared with its own
                          ycashd at every sync point.
``KOGANY_SIDECAR_RELAY``      0 turns off the rig's background re-announcement (``RigRelay``; default on).
``KOGANY_SIDECAR_PUMP_AFTER``  seconds a lagging rig kogany gets before the harness feeds it its own
                          ycashd's blocks by ``submitblock`` (default 5; ``MixedLine._pump``, finding
                          W9-a/F-1).

Framework API (for W2-d, W4-e, W5-f, W6 and the S track)
--------------------------------------------------------

``current()``                         the run's ``MixedLine`` (inert when ``KOGANY_BIN`` is unset).
``MixedLine.active``                  True when followers run.
``MixedLine.followers``               the ``KoganyNode`` list (``.rpc`` is a JSON-RPC proxy).
``MixedLine.sync_point(conns, label)``  tip + ``vault_getinfo`` (``branchid`` always; ``statehash``,
                                      ``dbtip`` and the counts once kogany serves a ``statehash``; the
                                      upgrade fields as a note) + ``yed_getstatehash`` equality (called
                                      by every ``sync_blocks``; W4-e).
``MixedLine.mempool_point(conns)``    ``getrawmempool`` set equality (``KOGANY_MEMPOOL=1``).
``MixedLine.offer_block(hex, cxx_result, label)``  submit a block to every follower, compare classes.
``MixedLine.offer_tx(hex, cxx_error, label)``      the same for ``sendrawtransaction``.
``classify_cxx_block(result)`` / ``classify_cxx_tx(error)`` / ``classify_kogany_block(result,
proposal)`` / ``classify_kogany_tx(error)`` / ``classify_kogany_text(path, text)``  verdict classes;
                                      ``REJECT_CODE_MAP`` (ycashd) / ``KOGANY_REASON_MAP`` (kogany,
                                      W4-e) are the tables; ``offer_block`` asks kogany's proposal mode
                                      first for a reason behind a bare ``rejected``.
``koganyd_config(args, slot, peer_p2p_ports, datadir)``  ycashd arguments -> (config dict, notes);
``render_toml(config, notes)``        the ``koganyd.toml`` text; ``KOGANYD_KEY_TABLE`` /
                                      ``NU_BRANCH_TABLE`` are the map.
``start_sidecar(i, dirname, args)`` / ``sidecar_ycashd_args`` / ``sidecar_kogany_config`` /
``sidecar_enabled`` / ``SIDECAR_NODES``  the KOGANY_SIDECAR rig (util.start_node calls start_sidecar).
``MixedLine.sync_wait(conns, waited)``  util._sync_blocks hook: the rig's feed of a lagging kogany.
``MixedLine.mempool_wait(conns, waited)``  util._sync_mempools hook: the rig's transaction feed (W9-a/F-3).
``MixedLine.sync_failed(kind, conns)``  util hook before a failed sync raises: the rig's per-pair state.
``start_yewd_pair(i, datadir, ycashd, args)`` / ``yewd_pair_argv`` / ``split_yewd_args`` /
``yewd_backend_rpc_port(i)`` / ``YEWD_BACKENDS``  the YEWD_BIN pair (util.start_node calls it).

Under ``YEWD_BIN`` util's ``fullyNotified`` wait is skipped for the pair nodes only (``util.YEWD_PAIRS``:
their backend runs ``-disablewallet`` and never reports it; a plain ycashd node of the same run keeps
the wait, finding F-S3-1; ``YEWD_FULLY_NOTIFIED=1`` restores it once yewd answers it), and yewd's output
goes to ``node<i>/yewd.log`` (rpc-tests.py fails a script with stderr output).

Recorded limits (plan section 5): kogany does not mine (K-16; its regtest checks the solution
shape only); ``split_network`` uses ``disconnectnode``, which kogany lacks, so a follower stays on
its peer's side of a split; Zakura has no mock clock, so ``mock_clock`` scripts run the followers
on the real clock; a follower is one extra peer of its peer node, so the six scripts that assert
an exact ``getpeerinfo`` count (maxuploadtarget, nodehandling, p2p_ban_pool_value_out_of_range,
p2p_nu_peer_management, signrawtransaction_offline, yellowback_framework_smoke) stay off the mixed
shard list; a script's ``invalidateblock`` reaches only the ycashd node it calls, so the follower keeps the
invalidated branch unless ``KOGANY_MIRROR_INVALIDATE=1`` (Zakura serves
``invalidateblock``/``reconsiderblock``; whether a wave's shard turns it on is W2-d's choice).
In the rig (``KOGANY_SIDECAR=1``) the same limits hold per node: every ycashd has one more peer (its own
kogany), a script's ``invalidateblock`` reaches the ycashd only (the mirror works per pair), a ``kill9``
leaves the node's kogany running, and the blocks a ycashd mines under ``mock_clock`` reach the others only
if kogany's real clock accepts their time.
"""

import atexit
import shutil
import json
import threading
import os
import re
import socket
import subprocess
import sys
import time
from base64 import b64encode
from decimal import Decimal
from http.client import HTTPConnection
from urllib.parse import urlparse

from .authproxy import JSONRPCException
from . import util
from .util import MAX_NODES, PORT_MIN, PORT_RANGE, PortSeed, p2p_port, rpc_port


# ---------------------------------------------------------------------------
# Ports: kogany slot k never takes one of ycashd's (p2p_port/rpc_port cover PORT_MIN..PORT_MIN +
# 2*PORT_RANGE); the three kogany ranges sit above them, with the same per-seed offset, shifted by
# MAX_NODES + 1 inside their band: yellowback_stratum puts yolo's stratum and status ports at
# 21000 / 26000 + the same offset + its cell index (the 2*/3*PORT_RANGE bands), so an unshifted
# slot 0 took cell 0's stratum port ("Address already in use", W9-b).

def _offset():
    return (MAX_NODES * PortSeed.n) % (PORT_RANGE - 1 - MAX_NODES)


# The 2 and 3 PORT_RANGEs these had are yellowback_stratum.py's stratum and status ports (21000 / 26000
# + the seed offset + index), so kogany 0's RPC took yolo's status port (finding W9-a/F-5).  The RPC
# range (bound in both modes) is now 5 PORT_RANGEs (36000+, below macOS's ephemeral 49152; it was
# the unused yewd_rpc_port reservation, which moves to 8): a first move to 51000+ lost a run to an
# ephemeral port.  The P2P range (bound by the follower mode only; the rig listens on p2p_port) is 7.

def kogany_p2p_port(k):
    assert 0 <= k <= MAX_NODES
    return PORT_MIN + 7 * PORT_RANGE + k + _offset()


def kogany_rpc_port(k):
    assert 0 <= k <= MAX_NODES
    return PORT_MIN + 5 * PORT_RANGE + k + _offset()


def kogany_v2_port(k):
    """Zakura's native (QUIC) listener: off under ``p2p_stack = "legacy"`` (K-11), given a port of
    its own anyway so a default that binds it never collides with another slot."""
    assert 0 <= k <= MAX_NODES
    return PORT_MIN + 4 * PORT_RANGE + k + _offset()


# ---------------------------------------------------------------------------
# The ycashd-argument -> koganyd.toml map.
#
# status: 'live'           emitted as a key today;
#         'derived'        not copied: the follower gets its own value (its own port, its own dir);
#         'pending:<chunk>' the kogany key does not exist yet; recorded as a comment in the toml
#                          (koganyd's config is serde deny_unknown_fields, so an early key would
#                          refuse to start).  KOGANY_LIVE=<chunk> emits it;
#         'live:<chunk>'   emitted as a key while <chunk> is live, which it is by default
#                          (DEFAULT_LIVE); KOGANY_LIVE=!<chunk> turns it back into a comment;
#         'ignored'        C++-only or wallet-only; no kogany meaning for a follower.

NU_BRANCH_TABLE = {
    # branch id: (ConfiguredActivationHeights key, status, note)
    0x5ba81b19: ('Overwinter', 'live', 'testnet.rs:549 ConfiguredActivationHeights (PascalCase)'),
    0x76b809bb: ('Sapling', 'live', ''),
    0x374d694f: ('Ycash', 'pending:W1-Y1', 'NetworkUpgrade::Ycash (W1-Y0/Y1); key name fixed by W1-Y1'),
    # Ycash's Blossom/Heartwood/Canopy occupy Zakura's slots: the variants are unconditional and the
    # branch-id values are gated by the ycash feature (plan W1-Y0, section 2.3)
    0x8e471bd6: ('Blossom', 'live', 'Ycash Blossom id; the Blossom slot under feature ycash'),
    0x66314da3: ('Heartwood', 'live', 'Ycash Heartwood id'),
    0x19bd2d2f: ('Canopy', 'live', 'Ycash Canopy id'),
    0x6d5b7a31: ('Vault', 'pending:W2-b', 'NetworkUpgrade::Vault between Canopy and Nu5 (K-6); W2-b adds the key'),
    # Zcash's own ids, for a script that names them (dormant on Ycash)
    0x2bb40e60: ('Blossom', 'live', 'Zcash Blossom id'),
    0xf5b9230b: ('Heartwood', 'live', 'Zcash Heartwood id'),
    0xe9ff75a6: ('Canopy', 'live', 'Zcash Canopy id'),
    0xc2d6d0b4: ('NU5', 'live', 'Zcash NU5 id (Ycash: NO_ACTIVATION_HEIGHT)'),
    0xc8e71055: ('NU6', 'live', 'Zcash NU6 id'),
    # Ycash's reserved NU5..NU6.2 ids (network_upgrade.rs:324-327); kogany refuses them with Vault
    # at init with ycashd's R-A3 text (error.rs:67)
    0xf919a198: ('NU5', 'live', 'Ycash NU5 id (K-7, reserved)'),
    0x4dec4df0: ('NU6.1', 'live', 'NU6.1 id'),
    0x5437f330: ('NU6.2', 'live', 'NU6.2 id'),
}

KOGANYD_KEY_TABLE = [
    # (ycashd argument or ycash.conf key, status, koganyd.toml key, note)
    ('regtest=1 (ycash.conf)', 'live', 'network.network = {regtest = true, params = {...}}',
     'the Regtest form (zakura-network config.rs:1035-1072); Ycash regtest selection is W1-Y1\'s'),
    ('-nuparams=<branch>:<h>', 'live', 'network.network.params.activation_heights.<NU>',
     'per NU_BRANCH_TABLE; Overwinter/Sapling at 1 come from util.start_node itself'),
    ('port (ycash.conf)', 'derived', 'network.listen_addr', '127.0.0.1:kogany_p2p_port(k)'),
    ('rpcport (ycash.conf)', 'derived', 'rpc.listen_addr', '127.0.0.1:kogany_rpc_port(k)'),
    ('rpcuser / rpcpassword', 'live', 'rpc.enable_cookie_auth = false',
     'Zakura has cookie auth only; a localhost regtest follower runs without auth'),
    ('-addnode / -connect (peer)', 'live', 'network.initial_testnet_peers',
     'Regtest keeps localhost peers only (config.rs:427-432); the peer also addnodes the follower'),
    ('-datadir', 'derived', 'state.cache_dir, network.cache_dir, network.identity_dir, rpc.cookie_dir',
     'tmpdir/kogany<k>'),
    ('(v2 overlay)', 'live', 'network.p2p_stack = "legacy"', 'K-11: the native Zakura stack stays off'),
    ('(one connection)', 'live', 'network.max_connections_per_ip = 1',
     'Zakura\'s default, written out: every node is on 127.0.0.1, so the limit is what keeps a follower to '
     'its one peer (a rig that peers kogany with two ycashd nodes on one IP must raise it: the W1-Y5 trap)'),
    ('(mempool)', 'live', 'mempool.debug_enable_at_height = 0', 'regtest mempool from genesis'),
    ('-yellowbackattestorset=<setid>', 'live:W5-f', 'yellowback.attestor_set',
     'node 0\'s YED attestor set (hex, display order; W5-e key), live with W5-f\'s module registration '
     '(KOGANY_LIVE default-on; KOGANY_LIVE=!W5-f writes it as a note again)'),
    ('-yellowbacksigmaref=<bps>', 'live:W5-f', 'yellowback.sigma_ref', 'int (W5-e key, regtest only)'),
    ('-yellowbacksupplycapbps=<bps>', 'live:W5-f', 'yellowback.supply_cap_bps', 'int (W5-e)'),
    ('-yellowbackattestarmmin=<n>', 'live:W5-f', 'yellowback.attest_arm_min', 'int, default 3 (W5-e)'),
    ('-yellowbackbundlecarrier=<c>', 'live:W5-f', 'yellowback.bundle_carrier',
     '"scriptsig" / "opreturn" / "either" (W5-e)'),
    ('-yellowbackmintrequiresarmed=<0|1>', 'live:W5-f', 'yellowback.mint_requires_armed', 'bool (W5-e)'),
    ('(the YED start height)', 'derived', None, 'always the Vault activation height on kogany (W5-e)'),
    ('-pqfalconheight=<h>', 'live', 'network.network.params.activation_heights.pq_falcon_height',
     'the regtest Falcon height (kogany ConfiguredActivationHeights::pq_falcon, finding W3-c/F-1 resolved); '
     'not an upgrade: no branch id, 0 is valid'),
    ('-pqfalcon=<0|1>', 'live', 'network.network.params.activation_heights.pq_falcon_height',
     'ycashd\'s shorthand: -pqfalcon=1 is -pqfalconheight=0 (init.cpp); -pqfalcon=0 sets nothing'),
    ('-acceptnonstdtxn=<0|1>', 'live', 'mempool.accept_non_standard', 'bool (W1-Y9)'),
    ('-txunpaidactionlimit=<n>', 'live', 'mempool.tx_unpaid_action_limit', 'int (W1-Y9)'),
    ('-datacarriersize=<n>', 'live', 'mempool.max_datacarrier_bytes', 'int (W1-Y9)'),
    # W6-b: ycashd's fee policy and Yellowback wallet options, each in the option's integer unit
    # (crates/zakurad/src/components/mempool/config.rs); a value finer than the unit is refused
    ('-pqfeerate=<YEC/kB>', 'live', 'mempool.pq_fee_rate', 'zatoshis per 1,000 bytes (YEC x 1e8; W6-b)'),
    ('-pqfeeusdperkb=<$>', 'live', 'mempool.pq_fee_usd_per_kb_micro', 'micro-USD per kB ($ x 1e6; W6-b)'),
    ('-yellowbackfeeusdperkb=<$>', 'live', 'mempool.yellowback_fee_usd_per_kb_micro', 'micro-USD per kB ($ x 1e6; W6-b)'),
    ('-yellowbackmaxtxfeeusd=<$>', 'live', 'mempool.yellowback_max_tx_fee_usd_micro', 'micro-USD ($ x 1e6; W6-b)'),
    ('-yellowbackmaxtxfee=<YEC>', 'live', 'mempool.yellowback_max_tx_fee', 'zatoshis (YEC x 1e8; W6-b)'),
    ('-maxtxfee=<YEC>', 'live', 'mempool.max_tx_fee', 'zatoshis (YEC x 1e8; W6-b)'),
    ('-yellowbackfee=<zat>', 'live', 'mempool.yellowback_fee', 'zatoshis, as given (W6-b)'),
    ('-yellowbackmintlag=<n>', 'live', 'mempool.yellowback_mint_lag', 'blocks (W6-b)'),
    ('-yellowbackpayoutaddress=<addr>', 'live', 'mining.yellowback_payout_address', 'str: the YED payout key (pool tag)'),
    ('-yellowbackpayoutdefault=<0|1>', 'live', 'mining.yellowback_payout_default',
     'bool (F-S5-9): whether a P2PKH miner address is also the YED payout key (ycashd MINER-2); '
     'the H8 harness turns it off for a live pair that names no payout address'),
    ('-yellowbacktestfault=<spec>', 'live', 'yellowback.test_fault',
     'str, as given: ycashd\'s regtest fault injection (yellowback/index.cpp SetTestFault); kogany takes '
     'storage:<check|commit>[:<h>] and crash:<h>, and refuses undo, template and schema; written only when a '
     'script passes it'),
    ('-yellowbacksignal', 'ignored', None, 'retired with the vault upgrade; ycashd logs and ignores it (init.cpp)'),
    ('-feepolicy=<p>', 'ignored', None, 'wallet funding policy only (no relay or mempool meaning)'),
    ('-blockunpaidactionlimit=<n>', 'live', 'mining.block_unpaid_action_limit',
     'int: the template\'s unpaid-action limit (zakura-rpc config/mining.rs; a pair backend mines, '
     'yellowback_fee\'s pools run 0 for the PQ owner spend); a follower never mines (K-16)'),
    ('-mempoolevictionmemoryminutes=<n>', 'live', 'mempool.eviction_memory_time', 'minutes, as "<n>m"'),
    ('-mempooltxcostlimit=<n>', 'live', 'mempool.tx_cost_limit', 'int'),
    ('-mocktime=<t>', 'ignored', None, 'Zakura has no mock clock: followers run on the real clock'),
    ('-exportdir', 'ignored', None, 'wallet (dumpwallet)'),
    ('-keypool', 'ignored', None, 'wallet'),
    ('-discover', 'ignored', None, 'regtest followers never advertise'),
    ('-rest', 'ignored', None, 'no REST interface in Zakura'),
    ('-i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025', 'ignored', None, 'ycashd banner'),
    ('-debug / -printtoconsole / showmetrics / listenonion / clockoffset', 'ignored', None, 'C++ logging and UI'),
    ('-listen / -whitelist / -maxconnections', 'ignored', None, 'follower P2P is fixed by the harness'),
]

# Arguments that carry consensus meaning but have no row yet: the generator refuses them, so an
# unmapped consensus flag is never silently dropped (a new -yellowback* flag needs a row).
_IGNORED_PREFIXES = ('-exportdir', '-keypool', '-discover', '-rest', '-i-am-aware', '-debug',
                     '-printtoconsole', '-showmetrics', '-listenonion', '-clockoffset', '-mocktime',
                     '-listen', '-whitelist', '-maxconnections',
                     '-addnode', '-connect', '-datadir', '-port', '-rpcport', '-rpcuser', '-rpcpassword',
                     '-regtest', '-blocknotify', '-txindex', '-insightexplorer', '-lightwalletd',
                     '-experimentalfeatures', '-allowdeprecated', '-paytxfee', '-minrelaytxfee',
                     '-limitancestor', '-walletnotify', '-wallet', '-mineraddress',
                     '-equihashsolver', '-gen', '-genproclimit', '-checkmempool', '-checkblockindex',
                     '-stopatheight', '-reindex', '-prune', '-dbcache', '-par', '-timeout',
                     '-orchardwallet', '-nuparams',
                     # wallet, RPC transport and C++-only plumbing (no follower meaning)
                     '-developerencryptwallet', '-mnemonicfile', '-rescan', '-salvagewallet', '-sendchangeback',
                     '-migration', '-consolidation', '-deletetx', '-keeptx', '-zmqpub', '-proxy', '-onion',
                     '-noonion', '-nolisten', '-rpcallowip', '-rpcbind', '-rpccookiefile', '-rpcconnect',
                     '-bdbcache', '-anchorconfirmations', '-txexpirydelta', '-preferredtxversion',
                     '-printpriority', '-maxorphantx', '-regtestwalletsetbestchaineveryblock',
                     '-disablewallet', '-yellowbacksignal', '-feepolicy')
# -yellowbacksignal is retired (ycashd logs and ignores it).
# Deliberately absent (UnmappedArgument when KOGANY_BIN is set, so a kogany run never silently
# drops a rule): -nurejectoldversions, -regtestshieldcoinbase, -regtestprotectcoinbase,
# -regtestenablezip209, -reindex-yellowback, and the retired -yellowbackenforce /
# -yellowbackstartheight flags.
# Matched by the exact name (a prefix would swallow every -yellowback* row): -yellowback, which
# ycashd accepts and ignores, -yellowback=0 only acknowledging a leftover index (init.cpp:436;
# yellowback_hardening h6).
_IGNORED_NAMES = frozenset({'-yellowback'})
def _bool01(v):
    # a bare -flag is ycashd's -flag=1 (GetBoolArg; yellowback_mint_armed passes
    # -yellowbackmintrequiresarmed alone)
    if v not in ('', '0', '1'):
        raise UnmappedArgument('a 0/1 flag has the value %r' % v)
    return v != '0'


def _scaled(scale, what):
    """A decimal option value (ycashd's ParseMoney / a dollar amount) as an exact integer in units of
    1/scale; a value finer than the unit, or negative, is refused rather than rounded."""
    def conv(v):
        try:
            d = Decimal(v)
        except Exception:
            raise UnmappedArgument('%s: not a number: %r' % (what, v))
        n = d * scale
        if not d.is_finite() or n != n.to_integral_value() or n < 0:
            raise UnmappedArgument('%s: %r is not a whole number of 1/%d' % (what, v, scale))
        return int(n)
    return conv


_YEC = _scaled(100000000, 'YEC amount')
_USD = _scaled(1000000, 'USD amount')

# Rows tied to a chunk: (chunk, config path, converter).  Emitted while the chunk is live.
_PENDING_FLAGS = {
    '-yellowbackattestorset': ('W5-f', ('yellowback', 'attestor_set'), str),
    '-yellowbacksigmaref': ('W5-f', ('yellowback', 'sigma_ref'), int),
    '-yellowbacksupplycapbps': ('W5-f', ('yellowback', 'supply_cap_bps'), int),
    '-yellowbackattestarmmin': ('W5-f', ('yellowback', 'attest_arm_min'), int),
    '-yellowbackbundlecarrier': ('W5-f', ('yellowback', 'bundle_carrier'), str),
    '-yellowbackmintrequiresarmed': ('W5-f', ('yellowback', 'mint_requires_armed'), _bool01),
}

# The Falcon height (W3-c/F-1): a key of the regtest activation heights, though not an upgrade
# (kogany `ConfiguredActivationHeights::pq_falcon`, toml `pq_falcon_height`).  None: nothing to carry.
FALCON_KEY = 'pq_falcon_height'
class KoganyInitError(Exception):
    """An argument ycashd refuses at init (InitError) that has no koganyd.toml form to carry
    the bad value: the pair reports it as a backend init failure with ycashd's text."""


def _falcon_height(v):
    # ycashd init.cpp:1474: a decimal block height, >= 0, fitting an int
    if not re.fullmatch(r'[0-9]+', v) or int(v) > 0x7fffffff:
        raise KoganyInitError('-pqfalconheight must be a block height (>= 0).')
    return int(v)


_FALCON_FLAGS = {
    '-pqfalconheight': _falcon_height,
    '-pqfalcon': lambda v: 0 if _bool01(v) else None,
}

# Chunks live unless KOGANY_LIVE names them with a '!' (W5-f: the module registration landed, so a
# follower takes the YED attestor set and the [yellowback] parameters).
DEFAULT_LIVE = frozenset({'W1-Y1', 'W2-b', 'W5-f'})

# Rows live today: (config path, converter).
_LIVE_FLAGS = {
    '-acceptnonstdtxn': (('mempool', 'accept_non_standard'), _bool01),
    '-txunpaidactionlimit': (('mempool', 'tx_unpaid_action_limit'), int),
    '-datacarriersize': (('mempool', 'max_datacarrier_bytes'), int),
    # W6-b (crates/zakurad/src/components/mempool/config.rs): the option's integer unit
    '-pqfeerate': (('mempool', 'pq_fee_rate'), _YEC),
    '-pqfeeusdperkb': (('mempool', 'pq_fee_usd_per_kb_micro'), _USD),
    '-yellowbackfeeusdperkb': (('mempool', 'yellowback_fee_usd_per_kb_micro'), _USD),
    '-yellowbackmaxtxfeeusd': (('mempool', 'yellowback_max_tx_fee_usd_micro'), _USD),
    '-yellowbackmaxtxfee': (('mempool', 'yellowback_max_tx_fee'), _YEC),
    '-maxtxfee': (('mempool', 'max_tx_fee'), _YEC),
    '-yellowbackfee': (('mempool', 'yellowback_fee'), int),
    '-yellowbackmintlag': (('mempool', 'yellowback_mint_lag'), int),
    '-blockunpaidactionlimit': (('mining', 'block_unpaid_action_limit'), int),
    '-yellowbackpayoutdefault': (('mining', 'yellowback_payout_default'), _bool01),
    '-yellowbacktestfault': (('yellowback', 'test_fault'), str),
    '-mempooltxcostlimit': (('mempool', 'tx_cost_limit'), int),
    '-mempoolevictionmemoryminutes': (('mempool', 'eviction_memory_time'), lambda v: '%dm' % int(v)),
    '-yellowbackpayoutaddress': (('mining', 'yellowback_payout_address'), str),
}


class UnmappedArgument(ValueError):
    pass


def _live_chunks(live=None):
    """The live chunks: an explicit ``live`` list as given; otherwise ``DEFAULT_LIVE`` plus
    ``KOGANY_LIVE``'s chunks, less any it names as ``!<chunk>``."""
    if live is not None:
        return frozenset(live)
    named = [c.strip() for c in os.getenv('KOGANY_LIVE', '').split(',') if c.strip()]
    off = {c[1:] for c in named if c.startswith('!')}
    return frozenset((DEFAULT_LIVE | {c for c in named if not c.startswith('!')}) - off)


def _set(cfg, path, value):
    d = cfg
    for p in path[:-1]:
        d = d.setdefault(p, {})
    d[path[-1]] = value


def koganyd_config(args, slot, peer_p2p_ports, datadir, live=None, log_filter=None):
    """Map one ycashd argument list (the peer's: ``util.start_node``'s own ``-nuparams`` for
    Overwinter/Sapling plus the script's) to a ``koganyd`` config for follower ``slot``.

    Returns ``(config, notes)``: ``config`` the nested dict ``render_toml`` writes, ``notes`` the
    pending and ignored arguments (comments in the toml).  ``live`` (default ``KOGANY_LIVE``) names
    the chunks whose pending rows are emitted.  Raises ``UnmappedArgument`` for an argument with
    no row, and for a branch id ``NU_BRANCH_TABLE`` does not know."""
    live = _live_chunks(live)
    notes = []
    heights = {}
    cfg = {}
    for a in args:
        if not a.startswith('-'):
            raise UnmappedArgument('not an option: %r' % a)
        name, _, value = a.partition('=')
        if name == '-nuparams':
            branch_hex, _, h = value.partition(':')
            branch = int(branch_hex, 16)
            if branch not in NU_BRANCH_TABLE:
                raise UnmappedArgument('-nuparams branch %s has no NU_BRANCH_TABLE row' % branch_hex)
            key, status, _note = NU_BRANCH_TABLE[branch]
            if status == 'live' or status.split(':', 1)[1] in live:
                heights[key] = int(h)
            else:
                notes.append('%s: %s -> activation_heights.%s = %s' % (status, a, key, h))
            continue
        if name in _FALCON_FLAGS:
            value = _FALCON_FLAGS[name](value)
            if value is not None:
                heights[FALCON_KEY] = value
            continue
        if name in _LIVE_FLAGS:
            path, conv = _LIVE_FLAGS[name]
            _set(cfg, path, conv(value))
            continue
        if name in _PENDING_FLAGS:
            chunk, path, conv = _PENDING_FLAGS[name]
            if conv(value) is None:
                continue                  # an "off" form (-pqfalcon=0): nothing to carry
            if chunk in live:
                _set(cfg, path, conv(value))
            else:
                notes.append('pending:%s: %s -> %s = %s' % (chunk, a, '.'.join(path), value))
            continue
        if name in _IGNORED_NAMES:
            notes.append('ignored: %s' % a)
            continue
        if name.startswith(_IGNORED_PREFIXES) or name.startswith('-yellowbackpayout'):
            if name.startswith('-mocktime'):
                notes.append('ignored: %s' % a)
            continue
        if name.startswith('-yellowback') or name.startswith('-vault') or name.startswith('-pq'):
            raise UnmappedArgument('%s carries Yellowback/vault meaning and has no KOGANYD_KEY_TABLE row' % name)
        raise UnmappedArgument('%s has no KOGANYD_KEY_TABLE row' % name)

    # Zakura keeps one upgrade per height, the later variant winning (testnet.rs:924-929), and
    # refuses a map out of order; ycashd's regtest puts every Ycash upgrade at 1, which is the
    # same chain either way (Canopy rules from 1).  Order the keys as ConfiguredActivationHeights.
    order = ['Overwinter', 'Sapling', 'Ycash', 'Blossom', 'Heartwood', 'Canopy', 'Vault', 'NU5', 'NU6',
             'NU6.1', 'NU6.2', FALCON_KEY]
    ordered = {k: heights[k] for k in order if k in heights}

    root = os.path.abspath(datadir)
    net = {
        'listen_addr': '127.0.0.1:%d' % kogany_p2p_port(slot),
        'initial_testnet_peers': ['127.0.0.1:%d' % p for p in peer_p2p_ports],
        'p2p_stack': 'legacy',
        'max_connections_per_ip': 1,
        'cache_dir': os.path.join(root, 'network'),
        'identity_dir': os.path.join(root, 'identity'),
        'network': {'regtest': True, 'params': {'activation_heights': ordered}},
        'zakura': {'listen_addr': '127.0.0.1:%d' % kogany_v2_port(slot)},
    }
    base = {
        'network': net,
        'rpc': {'listen_addr': '127.0.0.1:%d' % kogany_rpc_port(slot),
                'enable_cookie_auth': False,
                'cookie_dir': os.path.join(root, 'rpc')},
        'state': {'cache_dir': os.path.join(root, 'state'), 'ephemeral': False},
        'mempool': {'debug_enable_at_height': 0},
        'mining': {'internal_miner': False},
        'tracing': {'use_color': False, 'filter': log_filter or os.getenv('KOGANY_LOG', 'info')},
    }
    for k, v in cfg.items():          # live pending sections (yellowback)
        base.setdefault(k, {}).update(v)
    retention = pruned_retention()
    if retention is not None:
        base['state']['storage_mode'] = {'pruned': {'tx_retention': retention}}
    return base, notes


# Zakura's regtest retention floor (zakura-state constants.rs min_pruning_retention:
# MAX_BLOCK_REORG_HEIGHT + 1).
REGTEST_PRUNE_FLOOR = 1001


def pruned_retention(env=None):
    """``KOGANY_PRUNE_RETENTION`` (default ``REGTEST_PRUNE_FLOOR``) when ``KOGANY_PRUNED=1``, else
    None (the followers run Archive, Zakura's default)."""
    env = os.environ if env is None else env
    if env.get('KOGANY_PRUNED', '0') != '1':
        return None
    return int(env.get('KOGANY_PRUNE_RETENTION', str(REGTEST_PRUNE_FLOOR)))


def _toml_value(v):
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v)          # a JSON string is a valid TOML basic string
    if isinstance(v, (list, tuple)):
        return '[' + ', '.join(_toml_value(x) for x in v) + ']'
    raise TypeError('no TOML form for %r' % (v,))


def _key(k):
    return k if all(c.isalnum() or c in '_-' for c in k) else json.dumps(k)


# The names before kogany's daemon became ``koganyd`` (kogany dd834da8b), for scripts written
# against them.
zakurad_config = koganyd_config
ZAKURAD_KEY_TABLE = KOGANYD_KEY_TABLE


def render_toml(config, notes=()):
    """The ``koganyd.toml`` text: scalar keys first, then each sub-table by its dotted header;
    ``notes`` become leading comments (the pending and ignored ycashd arguments)."""
    out = ['# koganyd.toml generated by qa/rpc-tests/test_framework/kogany.py (mixed-line harness)']
    out += ['# %s' % n for n in notes]

    def table(path, d):
        scalars = [(k, v) for k, v in d.items() if not isinstance(v, dict) and v is not None]
        subs = [(k, v) for k, v in d.items() if isinstance(v, dict)]
        if path and (scalars or not subs):
            out.append('')
            out.append('[%s]' % '.'.join(_key(p) for p in path))
        for k, v in scalars:
            out.append('%s = %s' % (_key(k), _toml_value(v)))
        for k, v in subs:
            table(path + [k], v)

    table([], config)
    return '\n'.join(out) + '\n'


# ---------------------------------------------------------------------------
# Verdict classes (plan section 4.2 rule 4 (iii)): reject strings differ by design, so blocks and
# transactions are compared by class.  The map below is the harness's table.

ACCEPT = 'accept'
REJECT_CONSENSUS = 'reject-consensus'      # DoS 100 (and the byte-level DoS 10, see below)
REJECT_STATE = 'reject-state'              # DoS 0: depends on the node's tip or set state
REJECT_POLICY = 'reject-policy'            # relay policy (0x40-0x42, duplicates, expiry)
REJECT_UNCLASSIFIED = 'reject-unclassified'  # kogany rejected with a text no KOGANY_REASON_MAP row names
REJECT_CLASSES = (REJECT_CONSENSUS, REJECT_STATE, REJECT_POLICY)

# ycashd reject codes (src/consensus/validation.h:34-41)
REJECT_MALFORMED, REJECT_INVALID, REJECT_OBSOLETE, REJECT_DUPLICATE = 0x01, 0x10, 0x11, 0x12
REJECT_NONSTANDARD, REJECT_DUST, REJECT_INSUFFICIENTFEE, REJECT_CHECKPOINT = 0x40, 0x41, 0x42, 0x43

# (path, reason or 'prefix*', class, DoS, source).  path: 'block' (submitblock result) or 'tx'
# (sendrawtransaction).  First match wins; the defaults after the table apply otherwise.
REJECT_CODE_MAP = [
    # --- blocks: submitblock's result string (rpc/mining.cpp BIP22 results)
    ('block', 'duplicate', ACCEPT, None, 'already have it, valid'),
    ('block', 'duplicate-inconclusive', ACCEPT, None, 'already have it, not on the best chain'),
    ('block', 'inconclusive', ACCEPT, None, 'valid, not (yet) on the best chain'),
    ('block', 'duplicate-invalid', REJECT_CONSENSUS, 100, 'already known invalid'),
    ('block', 'time-too-new', REJECT_STATE, 0, 'main.cpp ContextualCheckBlockHeader: clock-dependent'),
    ('block', 'bad-prevblk', REJECT_STATE, 0, 'unknown parent'),
    ('block', 'bad-txns-vault-timelock', REJECT_CONSENSUS, 100, 'main.cpp:905 (fMempool ? 0 : 100)'),
    ('block', '*', REJECT_CONSENSUS, 100, 'ConnectBlock vault/yellowback (main.cpp:4351) and CheckBlock'),
    # --- transactions: "<code>: <reason>" (rpc/rawtransaction.cpp:1359) or a bare message
    ('tx', 'tx-expiring-soon*', REJECT_POLICY, 0, 'rawtransaction.cpp:1312'),
    ('tx', 'Missing inputs', REJECT_STATE, 0, 'RPC_TRANSACTION_ERROR (orphan)'),
    ('tx', 'transaction already in block chain', REJECT_POLICY, 0, 'RPC_TRANSACTION_ALREADY_IN_CHAIN'),
    ('tx', 'txn-already-in-mempool', REJECT_POLICY, 0, 'main.cpp AcceptToMemoryPool'),
    ('tx', 'txn-already-known', REJECT_POLICY, 0, ''),
    ('tx', 'txn-mempool-conflict', REJECT_POLICY, 0, ''),
    ('tx', 'bad-txns-inputs-spent', REJECT_STATE, 0, ''),
    ('tx', 'bad-txns-nonstandard-inputs', REJECT_POLICY, 0, ''),
    ('tx', 'bad-txns-too-many-sigops', REJECT_POLICY, 0, ''),
    ('tx', 'non-final', REJECT_STATE, 0, ''),
    ('tx', 'too-long-mempool-chain', REJECT_POLICY, 0, ''),
    ('tx', 'bad-txns-vault-timelock', REJECT_STATE, 0, 'main.cpp:905 (fMempool ? 0 : 100)'),
    ('tx', 'non-BIP68-final', REJECT_POLICY, 0, 'main.cpp:907 REJECT_NONSTANDARD (the code says policy too)'),
    ('tx', 'bad-yellowback-*', REJECT_STATE, 0, 'main.cpp:2260 (module verdict in the mempool)'),
    ('tx', 'bad-txns-vault-*', REJECT_STATE, 0, 'main.cpp:2200 vault::CheckTx in the mempool: DoS 0 (10 for a '
     'byte-level act failure, still not a proof against the tip)'),
    ('tx', 'bad-vault-*', REJECT_STATE, 0, 'main.cpp:2200 vault::CheckTx act reasons (bad-vault-act-*, -bond-*)'),
    ('tx', 'mandatory-script-verify-flag-failed (OP_CHECKSETSIG or OP_CHECKSETDORMANT failed)', REJECT_STATE, 0,
     'main.cpp:2229 a template input failing on the set state (DoS 0)'),
    ('tx', 'mandatory-script-verify-flag-failed*', REJECT_CONSENSUS, 100, 'main.cpp:3092 ContextualCheckInputs'),
    ('tx', 'non-mandatory-script-verify-flag*', REJECT_POLICY, 0, 'main.cpp:3087 (REJECT_NONSTANDARD)'),
    ('tx', 'bad-txns-premature-spend-of-coinbase', REJECT_STATE, 0, 'main.cpp:2957 state.Invalid (DoS 0)'),
    ('tx', 'bad-txns-coinbase-spend-has-transparent-outputs', REJECT_STATE, 0, 'main.cpp:2967 state.Invalid'),
    ('tx', 'bad-txns-no-sink-of-funds', REJECT_CONSENSUS, 10, 'DoS 10'),
    ('tx', 'bad-txns-no-source-of-funds', REJECT_CONSENSUS, 10, 'DoS 10'),
    ('tx', 'bad-txns-prevout-null', REJECT_CONSENSUS, 10, 'DoS 10'),
    ('tx', 'bad-txns-*', REJECT_CONSENSUS, 100, 'CheckTransaction / ContextualCheckTransaction'),
    ('tx', 'bad-sapling-bundle-authorization', REJECT_CONSENSUS, 100, ''),
    ('tx', 'bad-orchard-bundle-authorization', REJECT_CONSENSUS, 100, ''),
    ('tx', 'bad-vault-tx-version-group-id', REJECT_CONSENSUS, 100, 'main.cpp:1225'),
    ('tx', 'coinbase', REJECT_CONSENSUS, 100, ''),
]
# A code-16 mempool reason outside the table is REJECT_STATE, reported as unmapped (KOGANY_STRICT
# fails it) so the table grows instead of guessing.

# Kogany's side (plan R-21, W4-e): Zakura's errors carry no DoS score and say other words, so the
# rows below map kogany's texts to a class.  Rows: (path, regex, class, source), searched in order
# (``re.search``), first match wins; no row matches -> REJECT_UNCLASSIFIED (a note; KOGANY_STRICT
# fails it).  ``CXX`` as the class: the text carries ycash6's own reason (kogany's rule ports keep
# the C++ string, W3-d / W4-b / W4-d), captured as group 1 and classified by REJECT_CODE_MAP on the
# same path, so those rows agree with ycashd by construction.
#
# path 'tx':       the ``sendrawtransaction`` error message (MempoolError / TransactionError /
#                  ValidateContextError Display, behind "failed to validate tx: ..., error: ").
# path 'block':    the ``submitblock`` result ('rejected' is all Zakura says, R-21).
# path 'proposal': the ``getblocktemplate`` proposal-mode answer for the same block, asked first
#                  (BlockProposalResponse::rejected: the verifier error's Debug text in kebab case);
#                  it refines a 'rejected' when a row names it.
#
# Rows marked "unverified" name a kogany text no run has produced yet (W4-d ``check::vault`` is in
# flight on kc/snapshot-hook): they are written from the source and checked when that lands.
CXX = 'cxx'
CXX_CODE = 'cxx-code'   # the row's group(1) is a whole ycashd "<code>: <reason>" (classify_cxx_tx)

KOGANY_REASON_MAP = [
    # --- transactions: duplicates (ycashd answers the txid of a transaction its mempool holds)
    ('tx', r'already exists in mempool', ACCEPT,
     'MempoolError::InMempool; ycashd rawtransaction.cpp:1341-1344 re-relays and answers the txid (W1-Y9)'),
    ('tx', r'already queued for download', ACCEPT, 'MempoolError::AlreadyQueued: the same transaction in flight'),
    # --- the ported Ycash rules that keep ycash6's reason string
    ('tx', r'non-BIP68-final in the mempool', REJECT_POLICY,
     'W3-d ValidateContextError::UnsatisfiedSequenceLock; ycashd 64: non-BIP68-final (main.cpp:907)'),
    ('tx', r'\((bad-txns-vault-timelock)\)', CXX, 'W3-d ValidateContextError::VaultTimeLock (main.cpp:905, DoS 0 here)'),
    ('tx', r'vault rule violation[^:]*: (bad-[a-z0-9-]+)', CXX,
     'W4-d TransactionError::VaultRejected (the mempool\'s vault::CheckTx: "vault rule violation in the mempool '
     'at Height(h): bad-...") and ValidateContextError::VaultRejected ("... in block <hash> at Height(h): '
     'bad-...") -- verified on vault_primitive (KOGANY_MEMPOOL=1)'),
    ('tx', r'(?<![a-z0-9-])(bad-(?:txns-vault|vault|yellowback)-[a-z0-9-]+)', CXX,
     'W4-b VaultReject::reason() / a module reason anywhere in the text (a fallback: W4-d\'s texts match the row '
     'above)'),
    # --- relay policy (ycashd REJECT_NONSTANDARD / REJECT_INSUFFICIENTFEE / tx-expiring-soon)
    ('tx', r'transaction is non-standard|did not pass standard validation|non-standard (transparent )?inputs|'
           r'non-push-only scriptSig|byte scriptSig, above the', REJECT_POLICY,
     'MempoolError::NonStandardTransaction, TransactionError::NonStandard* (W1-Y9: every storage-time rule)'),
    ('tx', r'ZIP-317 transaction rules', REJECT_POLICY,
     'TransactionError::Zip317: the Ycash relay fee rides it (ycashd 66: min relay fee not met)'),
    ('tx', r'locked until after block (height|time)|lock time on best chain', REJECT_POLICY,
     'TransactionError::LockedUntilAfter* / ValidateMempoolLockTimeError (ycashd 64: non-final)'),
    ('tx', r'greater than its expiry|reached transaction expiry|expiring soon', REJECT_POLICY,
     'TransactionError::ExpiredTransaction, ExactTipRejectionError::Expired (ycashd tx-expiring-soon)'),
    ('tx', r'another transaction in the mempool has already spent', REJECT_POLICY,
     'SameEffectsTipRejectionError::SpendConflict (ycashd 258: txn-mempool-conflict)'),
    ('tx', r'mempool is full|evicted from the full mempool|depends on more than|dependency group', REJECT_POLICY,
     'mempool capacity and package limits (ycashd too-long-mempool-chain, mempool full)'),
    ('tx', r'was committed to the best chain', REJECT_POLICY,
     'SameEffectsChainRejectionError::Mined (ycashd -27 transaction already in block chain)'),
    # --- state: depends on this node's tip
    ('tx', r'could not find transparent input UTXO|spends missing outputs', REJECT_STATE,
     'TransactionError::TransparentInputNotFound, MissingOutput (ycashd -25 Missing inputs)'),
    ('tx', r'inputs were spent, or nullifiers were revealed, in the best chain', REJECT_STATE,
     'SameEffectsChainRejectionError::DuplicateSpend (ycashd Missing inputs / bad-txns-inputs-spent)'),
    ('tx', r'immature transparent coinbase spend', REJECT_STATE,
     'ImmatureTransparentCoinbaseSpend (ycashd bad-txns-premature-spend-of-coinbase, state.Invalid)'),
    ('tx', r'unshielded transparent coinbase spend', REJECT_STATE,
     'UnshieldedTransparentCoinbaseSpend (ycashd bad-txns-coinbase-spend-has-transparent-outputs, state.Invalid)'),
    ('tx', r'mempool is disabled', REJECT_STATE, 'MempoolError::Disabled: kogany is not at the tip yet'),
    # --- consensus
    ('tx', r'could not calculate the transaction fee', REJECT_POLICY,
     'TransactionError::IncorrectFee: outputs above inputs. ycashd\'s mempool checks the relay fee on the '
     'negative fee first (main.cpp AcceptToMemoryPool: 66: min relay fee not met) before CheckTxInputs '
     '(bad-txns-in-belowout), so the mempool class is policy'),
    ('tx', r'transparent double-spend|spent twice|duplicate nullifier', REJECT_CONSENSUS,
     'TransactionError::Duplicate* (ycashd 16: bad-txns-inputs-duplicate)'),
    ('tx', r'could not verify a transparent script: .*OP_CHECKSETSIG or OP_CHECKSETDORMANT failed', REJECT_STATE,
     'W3-c/W4-d: a set opcode failing on the tip\'s set state (zcash_script SetSig error); ycashd re-runs the '
     'template input and answers DoS 0 (main.cpp:2229, VaultTemplateFailsOnSetState). Text-level: kogany '
     'scores it like any script failure until W6 (BanV5AndLater: never for the v4 vault spends)'),
    ('tx', r'could not verify a transparent script', REJECT_CONSENSUS,
     'TransactionError::Script (ycashd mandatory-script-verify-flag-failed, DoS 100). A vault template input '
     'failing on the set state is DoS 0 in ycashd (main.cpp:2229) and has no kogany equivalent before W6: '
     'that pair differs by class (recorded)'),
    ('tx', r'[Dd]eserializ|failed to fill whole buffer|io error|TX decode failed|parse|decode', REJECT_CONSENSUS,
     'LegacyCode::Deserialization -22 (ycashd TX decode failed / 16: bad-txns-oversize)'),
    ('tx', r'did not pass consensus validation|could not contextually validate', REJECT_CONSENSUS,
     'any other verifier or contextual error: a consensus rule (W1-Y9)'),
    # --- blocks: the proposal's text refines the bare 'rejected'
    ('proposal', r'vaultrejected-reason-(bad-[a-z0-9-]+?)-height-', CXX,
     'W4-d ValidateContextError::VaultRejected Debug in kebab case ("block-source-validateproposal-vaultrejected-'
     'reason-bad-vault-act-params-height-height-204-hash-...") -- verified on vault_primitive'),
    ('proposal', r'vaulttimelock', REJECT_CONSENSUS, 'W3-d VaultTimeLock in a block (main.cpp:905, DoS 100)'),
    ('proposal', r'unsatisfiedsequencelock', REJECT_CONSENSUS, 'W3-d UnsatisfiedSequenceLock (bad-txns-nonfinal)'),
    ('proposal', r'subsidy-invalidminerfees', REJECT_CONSENSUS,
     'zakura-consensus block/check.rs SubsidyError::InvalidMinerFees, a coinbase paying more than the subsidy '
     'and fees ("block-source-block-source-transaction-subsidy-invalidminerfees"); ycashd bad-cb-amount '
     '(main.cpp:4328-4331, DoS 100)'),
    ('proposal', r'too-?far-?in-?(the-?)?future|time-?too-?new', REJECT_STATE,
     'the header time rule (ycashd time-too-new, clock-dependent)'),
    ('block', r'^rejected$', REJECT_CONSENSUS,
     'SubmitBlockErrorResponse::Rejected: an invalid block (ycashd invalid / bad-*, DoS 100)'),
    # --- W7-e (kogany zakura-rpc ycash_reject.rs): kogany answers in ycashd's own words, so the last
    #     rows hand the text to REJECT_CODE_MAP: a BIP 22 reason from submitblock, a "<code>: <reason>"
    #     from sendrawtransaction (the code decides policy, as classify_cxx_tx does)
    ('block', r'^(?!rejected$)([a-z][a-z0-9-]*)$', CXX,
     'W7-e: submitblock answers ycashd\'s BIP 22 reason (bad-cb-amount, bad-txns-..., ...)'),
    ('tx', r'^([0-9]+: [A-Za-z][A-Za-z0-9_-]*)', CXX_CODE,
     'W7-e: sendrawtransaction answers ycashd\'s "<code>: <reason>" (-26)'),
]

def _match(pattern, reason):
    return reason.startswith(pattern[:-1]) if pattern.endswith('*') else reason == pattern


def _lookup(path, reason):
    for p, pattern, cls, dos, _src in REJECT_CODE_MAP:
        if p == path and pattern != '*' and _match(pattern, reason):
            return cls, dos
    for p, pattern, cls, dos, _src in REJECT_CODE_MAP:
        if p == path and pattern == '*':
            return cls, dos
    return None


def classify_cxx_block(result):
    """ycashd ``submitblock`` result -> class.  ``None`` is an accept."""
    if result is None:
        return ACCEPT
    return _lookup('block', str(result))[0]


def _split_code(message):
    head, sep, rest = message.partition(': ')
    if sep and head.isdigit():
        return int(head), rest.split(',')[0].strip()
    return None, message.strip()


def classify_cxx_tx(error, unmapped=None):
    """ycashd ``sendrawtransaction`` outcome -> class.  ``error`` is ``None`` (accepted), a
    ``JSONRPCException`` or its ``error`` dict.  ``unmapped`` (a list) collects reasons the table
    does not name."""
    if error is None:
        return ACCEPT
    err = getattr(error, 'error', error)
    message = err.get('message', '') if isinstance(err, dict) else str(err)
    code, reason = _split_code(message)
    if code in (REJECT_NONSTANDARD, REJECT_DUST, REJECT_INSUFFICIENTFEE, REJECT_DUPLICATE):
        return REJECT_POLICY
    hit = _lookup_tx(reason)
    if hit is not None:
        return hit
    if unmapped is not None:
        unmapped.append(message)
    return REJECT_STATE


def _lookup_tx(reason):
    for p, pattern, cls, _dos, _src in REJECT_CODE_MAP:
        if p == 'tx' and _match(pattern, reason):
            return cls
    return None


def _cxx_class(path, reason):
    """The class REJECT_CODE_MAP gives ycash6's ``reason`` on ``path`` (``tx`` or ``block``)."""
    if path == 'tx':
        hit = _lookup_tx(reason)
        return hit if hit is not None else REJECT_STATE
    return _lookup('block', reason)[0]


def classify_kogany_text(path, text):
    """``(class, row)`` for a kogany text on ``path`` ('tx', 'block' or 'proposal'); ``(None,
    None)`` when no row names it."""
    for p, pattern, cls, src in KOGANY_REASON_MAP:
        if p != path:
            continue
        m = re.search(pattern, text)
        if m is None:
            continue
        if cls == CXX:
            return _cxx_class('block' if path == 'proposal' else path, m.group(1)), (p, pattern, src)
        if cls == CXX_CODE:
            return classify_cxx_tx({'message': m.group(1)}), (p, pattern, src)
        return cls, (p, pattern, src)
    return None, None


def classify_kogany_block(result, proposal=None):
    """Zakura ``submitblock``: null on success, else one of ``rejected``, ``duplicate``,
    ``duplicate-inconclusive``, ``inconclusive`` (zakura-rpc SubmitBlockErrorResponse).
    ``proposal`` is the ``getblocktemplate`` proposal-mode answer for the same block (a string
    when the verifier refused it): a 'proposal' row naming it refines a ``rejected``."""
    if result is None or result in ('duplicate', 'duplicate-inconclusive', 'inconclusive'):
        return ACCEPT
    if isinstance(proposal, str) and proposal:
        cls, _row = classify_kogany_text('proposal', proposal)
        if cls is not None:
            return cls
    cls, _row = classify_kogany_text('block', str(result))
    return REJECT_UNCLASSIFIED if cls is None else cls


def _message(error):
    err = getattr(error, 'error', error)
    return err.get('message', '') if isinstance(err, dict) else str(err)


def classify_kogany_tx(error):
    """Zakura ``sendrawtransaction``: ``None`` (accepted), a ``JSONRPCException`` or its
    ``error`` dict."""
    if error is None:
        return ACCEPT
    cls, _row = classify_kogany_text('tx', _message(error))
    return REJECT_UNCLASSIFIED if cls is None else cls


def same_class(cxx, kog, strict=False):
    """True when the two verdicts agree.  ``REJECT_UNCLASSIFIED`` matches any reject class
    unless ``strict`` (kogany reports no score yet)."""
    if cxx == kog:
        return True
    return (not strict) and kog == REJECT_UNCLASSIFIED and cxx in REJECT_CLASSES


# ---------------------------------------------------------------------------
# The parity sidecar (plan section 3b, rev 3: yewd inside yew).  YEWD_BIN turns node i into
# backend i + yewd i (the contract: yew/yewd/README.md "Harness mode"): yewd listens on
# rpc_port(i) with node<i>/ycash.conf's credentials, so scripts keep talking to rpc_url(i); the
# backend, a ycashd -disablewallet, gets node<i>/backend, cookie auth, its own RPC port
# (yewd_backend_rpc_port(i)) and the node's P2P port, so connect_nodes_bi / disconnectnode work.
# util.start_node calls start_yewd_pair; util.stop_node / wait_bitcoinds wait for the backend too.
# The kogany backend (a yewd in front of a kogany slot, plan S1+) takes the same hook once kogany
# follows Ycash regtest: the backend line below becomes the koganyd start.

YEWD_WALLET_ARGS = ('-keypool', '-exportdir', '-paytxfee', '-mintxfee', '-txconfirmtarget', '-walletnotify',
                    '-spendzeroconfchange', '-rescan', '-wallet', '-salvagewallet', '-mnemonicfile')
YEWD_BACKENDS = {}        # node index -> the backend's subprocess.Popen


def yewd_rpc_port(k):
    """Reserved (a yewd that listens beside, not instead of, a node); unused by the pair mode."""
    assert 0 <= k <= MAX_NODES
    return PORT_MIN + 8 * PORT_RANGE + k + _offset()


def yewd_backend_rpc_port(i):
    assert 0 <= i <= MAX_NODES
    return PORT_MIN + 6 * PORT_RANGE + i + _offset()


def split_yewd_args(args):
    """(backend args, yewd wallet args) from one node's arguments; -mocktime, -disablewallet, -pqfeerate and -pqfalcon[height] go
    to both (a -disablewallet pair is the node alone: yewd forwards and serves no wallet method)."""
    backend, wallet = [], []
    for a in args:
        name = a.split('=', 1)[0]
        if name in ('-mocktime', '-disablewallet', '-pqfeerate', '-pqfalconheight', '-pqfalcon'):
            backend.append(a)
            wallet.append(a)
        elif name in YEWD_WALLET_ARGS:
            wallet.append(a)
        else:
            backend.append(a)
    return backend, wallet


def yewd_pair_argv(yewd_bin, ycashd_bin, datadir, i, args):
    """The two command lines (backend, yewd) for node ``i`` in ``datadir`` (= node<i>)."""
    backend_dir = os.path.join(datadir, 'backend')
    b_args, w_args = split_yewd_args(args)
    backend = [ycashd_bin, '-datadir=' + backend_dir, '-disablewallet'] + \
        [a for a in b_args if not a.startswith('-datadir=')]
    yewd = [yewd_bin, '-datadir=' + datadir, '-conf=ycash.conf', '-regtest',
            '-backendrpcport=%d' % yewd_backend_rpc_port(i),
            '-backendrpccookiefile=' + os.path.join(backend_dir, 'regtest', '.cookie'),
            '-stopbackend'] + w_args
    return backend, yewd


def start_yewd_pair(i, datadir, ycashd_bin, args, stderr=None, timeout=120):
    """Start backend i, wait for its RPC (raising util's "node i exited" message if it dies, so
    ``assert_start_raises_init_error`` still works), then yewd i.  Returns yewd's Popen.

    H8 (yew/yewd/README.md "Harness mode"): the pair's wallet is created first (``yewd -initwallet``)
    and the backend mines to its coinbase address (``yewd_coinbase_address``, finding F-S4-1).  The
    backend is a ycashd -disablewallet, or kogany under YEWD_KOGANY (column 3)."""
    backend_dir = os.path.join(datadir, 'backend')
    os.makedirs(backend_dir, exist_ok=True)
    yewd_bin = os.environ['YEWD_BIN']
    if not _REAPER[0]:
        _REAPER[0] = True
        atexit.register(_reap_pairs)
    coinbase = None
    nowallet = any(a == '-disablewallet' or a == '-disablewallet=1' for a in args)
    if os.getenv('YEWD_H8', '1') == '1' and not nowallet:
        coinbase = yewd_coinbase_address(args, yewd_init_wallet(yewd_bin, datadir, args), bool(yewd_kogany_bin()))
        args = yewd_h8_args(args, coinbase)
    b_argv, y_argv = yewd_pair_argv(yewd_bin, ycashd_bin, datadir, i, args)
    YEWD_PAIR_STOCK[i] = not any(a.startswith('-yellowbackattestorset=') for a in args)
    kogany_bin = yewd_kogany_bin()
    if kogany_bin:
        YewdColumn.ensure(os.path.dirname(os.path.abspath(datadir)))
        b_args, _w = split_yewd_args(args)
        try:
            backend, cookie = _start_kogany_backend(i, datadir, b_args, coinbase, stderr)
        except KoganyInitError as e:
            if stderr is not None:
                stderr.write(('Error: %s\n' % e).encode('utf8'))
                stderr.flush()
            raise Exception('%s node %d exited with status 1 during initialization (zakurad backend: %s)'
                            % (util.zcashd_binary(), i, e))
        y_argv = [a for a in y_argv if not a.startswith('-backendrpccookiefile=')] + [
            '-backendrpccookiefile=' + cookie,
            '-backendindexer=127.0.0.1:%d' % yewd_backend_indexer_port(i)]
        YEWD_KOGANY_PAIRS.add(i)
        what = 'zakurad'
    else:
        with open(os.path.join(backend_dir, 'ycash.conf'), 'w', encoding='utf8') as f:
            f.write('regtest=1\nshowmetrics=0\nlistenonion=0\nport=%d\nrpcport=%d\n'
                    % (p2p_port(i), yewd_backend_rpc_port(i)))
        backend = subprocess.Popen(b_argv, stderr=stderr)
        cookie = os.path.join(backend_dir, 'regtest', '.cookie')
        YEWD_KOGANY_PAIRS.discard(i)
        what = util.zcashd_binary()
    YEWD_BACKENDS[i] = backend
    rpc = KoganyRPC('http://127.0.0.1:%d/' % yewd_backend_rpc_port(i), cookie=cookie)
    deadline = time.time() + timeout
    while True:
        if backend.poll() is not None:
            YEWD_BACKENDS.pop(i, None)
            # util's message shape (ZCASHD path) for either backend, so assert_start_raises_init_error
            # matches; kogany's init error went to the caller's stderr (_start_kogany_backend)
            raise Exception('%s node %d exited with status %i during initialization (%s backend)'
                            % (util.zcashd_binary(), i, backend.returncode, what))
        had_cookie = os.path.exists(cookie)
        try:
            rpc.getblockcount()
            break
        except JSONRPCException as e:
            # kogany answers "No blocks in state" until it has committed its genesis block
            if not (_backend_warming_up(e, had_cookie)
                    or kogany_bin and 'No blocks in state' in str(e.error.get('message', ''))):
                raise
        except OSError:
            pass
        assert time.time() < deadline, 'yewd backend %d did not come up' % i
        time.sleep(0.25)
    # yewd reports ignored options on stderr; rpc-tests.py fails a script with any stderr output,
    # so yewd's own stream goes to node<i>/yewd.log unless the caller captures stderr itself
    out = stderr if stderr is not None else open(os.path.join(datadir, 'yewd.log'), 'ab')
    return subprocess.Popen(y_argv, stdout=out if stderr is None else None, stderr=out)


_REAPER = [False]


def _reap_pairs():
    """At exit: a pair or backend still running (a script that crashed between its nodes' start and
    stop_nodes, e.g. stop_nodes on a None entry) is killed, so no orphan outlives the run."""
    for p in list(util.bitcoind_processes.values()) + list(YEWD_BACKENDS.values()):
        try:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(20)
                except subprocess.TimeoutExpired:
                    p.kill()
        except Exception:
            pass


def _unauthorized(e):
    """KoganyRPC's error for an HTTP 401 (an empty, non-JSON body)."""
    err = getattr(e, 'error', None) or {}
    return err.get('code') == -342 and 'non-JSON response 401' in str(err.get('message', ''))


def _backend_warming_up(e, had_cookie):
    """A backend start error that means "not yet": -28 (warming up), or a 401 to a request sent
    before the backend had written its cookie (it listens first; finding F-S2-9).  A 401 to a request
    that carried the cookie is a real authentication failure."""
    err = getattr(e, 'error', None) or {}
    return err.get('code') == -28 or (_unauthorized(e) and not had_cookie)


def wait_yewd_backend(i, timeout=60):
    """After yewd i was stopped (``-stopbackend`` stops the backend): reap the backend."""
    p = YEWD_BACKENDS.pop(i, None)
    if p is None:
        return
    try:
        p.wait(timeout)
    except subprocess.TimeoutExpired:
        p.terminate()
        p.wait()


def kill_yewd_backend(i):
    p = YEWD_BACKENDS.pop(i, None)
    if p is not None and p.poll() is None:
        p.kill()
        p.wait()


# ---------------------------------------------------------------------------
# Column 3 of the W9 matrix (plan section 3b S5): kogany + yewd.  YEWD_KOGANY=<zakurad> with
# YEWD_BIN turns node i into kogany i + yewd i -- no ycashd behind any node:
#
#   kogany i   a zakurad in node<i>/backend, configured from node i's arguments (zakurad_config,
#              slot i), P2P on p2p_port(i) (the node's address: connect_nodes and the scripts'
#              topology carry over), RPC with cookie auth on yewd_backend_rpc_port(i), the indexer
#              gRPC listener on yewd_backend_indexer_port(i) (yewd's wake-up streams, H3/H4), and
#              mining.miner_address = the pair's coinbase address (H8);
#   yewd i     on rpc_port(i) as in the ycash6-backend mode, with -backendindexer.
#
# YEWD_YCASH6_PEER=1 is the mixed variant: one more node, a ycashd -disablewallet that dials pair
# YEWD_PEER (default 0) and nothing else (-connect, -listen=0), judges every block and transaction
# that reaches it, and is compared with every pair at every sync point (vault_getinfo.statehash,
# yed_getstatehash, the tip).  kogany never solves Equihash (K-16) and its regtest `generate` makes
# shape-only blocks a ycashd refuses, so in the mixed variant (or with YEWD_SOLVE=1) a pair's
# `generate` is answered by the harness: kogany's getblocktemplate (through yewd), the framework's
# (48,5) solver (equihash.py, as kogany's W8-c kogany_mines.py), submitblock through yewd.
# Without the peer the pairs' state hashes are still compared with each other at every sync point.

YEWD_COLUMN = [None]        # the run's YewdColumn (column 3), created at the first pair start


def yewd_kogany_bin(env=None):
    env = os.environ if env is None else env
    return env.get('YEWD_KOGANY') or None


def yewd_backend_indexer_port(i):
    """The kogany backend's indexer gRPC port: kogany_rpc_port's range (36000+, below the ephemeral
    ports), which no follower binds in column 3 (MixedLine is inert there)."""
    return kogany_rpc_port(i)


def yewd_init_wallet(yewd_bin, datadir, args=()):
    """H8: create (or open) pair i's wallet before its backend starts: (its transparent coinbase
    address, its Sapling coinbase address or None for a yewd that prints none).  The node's
    -mnemonicfile / -wallet reach -initwallet too: the wallet it creates is the one the node opens
    (a seed-only restore, F-S5-17)."""
    wallet = [a for a in args if a.startswith(('-mnemonicfile=', '-wallet='))]
    out = json.loads(subprocess.check_output([yewd_bin, '-datadir=' + datadir, '-conf=ycash.conf', '-regtest',
                                              '-initwallet'] + wallet))
    return out['mineaddress'], out.get('saplingaddress')


def yewd_coinbase_address(args, mineaddress, kogany_backend=False):
    """F-S4-1, F-S5-9: the coinbase address the pair's backend mines to (``mineaddress`` is
    ``yewd_init_wallet``'s pair), or None.  A node's -mineraddress/-minetolocalwallet give way to the
    wallet's own transparent address.  Both lines take a P2PKH miner address as the default YED
    payout key (ycashd MINER-2, init.cpp; kogany W5-f, start.rs set_payout_address), which a ycashd
    wallet node mining to its keypool never has (yellowback_rpc_contract.py's no-payout-address).
    F-S5-9: a Yellowback-live node (-yellowbackattestorset) that names no -yellowbackpayoutaddress
    still mines to the wallet's transparent address, with the payout default off
    (``yewd_h8_args``: ycashd -yellowbackpayoutdefault=0, kogany mining.yellowback_payout_default),
    so its miner address names no YED payout key, as the script's keypool-mining node does."""
    taddr = mineaddress[0] if isinstance(mineaddress, tuple) else mineaddress
    # a pair that names -yellowbackpayoutaddress still mines to its wallet (mining to the payout
    # address instead left the wallet without the coinbase the scripts spend before importing the
    # pool keys, yellowback_chainviz.py); its tag names the script's payee (mining.yellowback_payout_address)
    return taddr


def yewd_h8_args(args, coinbase):
    """The backend's arguments with the H8 coinbase address in place of the script's.  A
    Yellowback-live node that names no payout address takes no payout default from it either
    (F-S5-9, ``yewd_coinbase_address``)."""
    args = [a for a in args if not a.startswith(('-mineraddress=', '-minetolocalwallet'))]
    if coinbase is not None:
        args += ['-mineraddress=%s' % coinbase, '-minetolocalwallet=0']
        live = any(a.startswith('-yellowbackattestorset=') for a in args)
        named = any(a.startswith(('-yellowbackpayoutaddress=', '-yellowbackpayoutdefault')) for a in args)
        if live and not named:
            args += ['-yellowbackpayoutdefault=0']
    return args


def yewd_kogany_config(args, i, backend_dir, coinbase, live=None):
    """kogany i's config as a pair backend (column 3)."""
    cfg, notes = zakurad_config([a for a in args if not a.startswith(('-mineraddress=', '-minetolocalwallet'))],
                                i, [], backend_dir, live=live)
    net = cfg['network']
    net['listen_addr'] = '127.0.0.1:%d' % p2p_port(i)
    net['initial_testnet_peers'] = []
    net['max_connections_per_ip'] = SIDECAR_MAX_CONNS_PER_IP
    rpc = cfg['rpc']
    rpc['listen_addr'] = '127.0.0.1:%d' % yewd_backend_rpc_port(i)
    rpc['enable_cookie_auth'] = True
    rpc['indexer_listen_addr'] = '127.0.0.1:%d' % yewd_backend_indexer_port(i)
    if coinbase is not None:
        cfg['mining']['miner_address'] = coinbase
    return cfg, notes


def _kogany_vault_wipe(datadir, backend_dir):
    """ycashd's vault state DB is ``node<i>/regtest/vaults`` (U-18); kogany's vault column family
    lives inside its state DB, so a pair keeps an empty ``regtest/vaults`` stand-in.  A script that
    deleted it (``wipe_vaults=True``) means "rebuild the vault state from the blocks": the backend's
    state dir is deleted and kogany resyncs the chain from its peer."""
    marker = os.path.join(datadir, 'regtest', 'vaults')
    seen = os.path.join(backend_dir, '.vaults-standin')
    state = os.path.join(backend_dir, 'state')
    if os.path.exists(seen) and not os.path.isdir(marker) and os.path.isdir(state):
        shutil.rmtree(state)
    os.makedirs(marker, exist_ok=True)
    open(seen, 'w').close()


def _start_kogany_backend(i, datadir, b_args, coinbase, stderr):
    backend_dir = os.path.join(datadir, 'backend')
    cfg, notes = yewd_kogany_config(b_args, i, backend_dir, coinbase)
    conf = os.path.join(backend_dir, 'zakurad.toml')
    with open(conf, 'w', encoding='utf8') as f:
        f.write(render_toml(cfg, notes))
    _kogany_vault_wipe(datadir, backend_dir)
    log = stderr if stderr is not None else open(os.path.join(backend_dir, 'zakurad.log'), 'ab')
    argv = [yewd_kogany_bin(), '-c', conf] + os.getenv('KOGANY_ARGS', '').split() + ['start']
    return subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT if stderr is None else stderr), \
        os.path.join(backend_dir, 'rpc', '.cookie')


# --- the solved generate (mixed variant) -------------------------------------------------

EQUIHASH_N, EQUIHASH_K = 48, 5       # Ycash regtest (ycash6 src/chainparams.cpp)


def _compact_size(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    return b'\xfe' + n.to_bytes(4, 'little')


def _sha256d(b):
    import hashlib
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def solve_template(t, max_nonces=100000):
    """A kogany getblocktemplate answer as a solved (48,5) block, hex (kogany_mines.py's steps)."""
    import hashlib
    from .equihash import gbp_basic, gbp_validate, zcash_person
    n, k = EQUIHASH_N, EQUIHASH_K
    prefix = (int(t['version']).to_bytes(4, 'little')
              + bytes.fromhex(t['previousblockhash'])[::-1]
              + bytes.fromhex(t['defaultroots']['merkleroot'])[::-1]
              + bytes.fromhex(t['blockcommitmentshash'])[::-1]
              + int(t['curtime']).to_bytes(4, 'little')
              + int(t['bits'], 16).to_bytes(4, 'little'))
    target = int(t['target'], 16)
    base = hashlib.blake2b(digest_size=(512 // n) * n // 8, person=zcash_person(n, k))
    base.update(prefix)
    start = int.from_bytes(os.urandom(4), 'little') << 32
    for nonce_n in range(start, start + max_nonces):
        nonce = nonce_n.to_bytes(32, 'little')
        digest = base.copy()
        digest.update(nonce)
        for soln in gbp_basic(digest, n, k):
            if not gbp_validate(digest, soln, n, k):
                continue
            header = prefix + nonce + _compact_size(len(soln)) + soln
            if int.from_bytes(_sha256d(header), 'little') <= target:
                txs = [t['coinbasetxn']['data']] + [tx['data'] for tx in t['transactions']]
                return (header + _compact_size(len(txs))).hex() + ''.join(txs), _sha256d(header)[::-1].hex()
    raise AssertionError('no (48,5) solution under the template target in %d nonces' % max_nonces)


# F-S5-18: kogany's regtest template pays no founders' reward, which ycashd's regtest requires
# before the Ycash upgrade (main.cpp ContextualCheckBlock "cb-no-founders-reward": 20 % of the
# subsidy to GetFoundersRewardScriptAtHeight through GetLastFoundersRewardBlockHeight); a pair's
# cache chain (yewd_build_cache: the framework's regtest without -nuparams) is all such blocks, so
# the mixed variant's ycash6 peer refused its block 1.  Until kogany builds (and checks) that
# output, the harness's solved generate adds it: the amount is the peer's own getblocksubsidy
# 'founders', the script the regtest founders' address (ycash6 src/chainparams.cpp regtest
# vFoundersRewardAddress, one P2SH address), the miner output pays that much less, and the merkle
# root is recomputed.  With the Ycash upgrade active (the peer's schedule, kogany_regtest_schedule)
# the same output is ycashd's YDF payment, required below nYdfMandateEndHeight only.  Counted as
# founders_added; a template that already pays it is left as is.
REGTEST_FOUNDERS_ADDRESS = 't2FwcEhFdNXuFMv1tcYwaBJtYVtMj8b1uTg'
REGTEST_YDF_MANDATE_END = 5          # ycash6 src/chainparams.cpp regtest nYdfMandateEndHeight


def _founders_script():
    from .yellowback_model import base58check_decode
    payload = base58check_decode(REGTEST_FOUNDERS_ADDRESS)
    return b'\xa9\x14' + payload[2:22] + b'\x87'


def _read_compact(b, o):
    n = b[o]
    if n < 0xfd:
        return n, o + 1
    if n == 0xfd:
        return int.from_bytes(b[o + 1:o + 3], 'little'), o + 3
    if n == 0xfe:
        return int.from_bytes(b[o + 1:o + 5], 'little'), o + 5
    return int.from_bytes(b[o + 1:o + 9], 'little'), o + 9


def _coinbase_with_output(raw, script, value):
    """The coinbase ``raw`` (v1..v4) with an output (``script``, ``value``) appended and ``value``
    taken from its first output."""
    header = int.from_bytes(raw[0:4], 'little')
    o = 8 if header & 0x80000000 else 4                    # fOverwintered: nVersionGroupId follows
    n_in, o = _read_compact(raw, o)
    for _ in range(n_in):
        o += 36
        ln, o = _read_compact(raw, o)
        o += ln + 4
    vout_at = o
    n_out, o = _read_compact(raw, o)
    outs = []
    for _ in range(n_out):
        v = int.from_bytes(raw[o:o + 8], 'little')
        ln, p = _read_compact(raw, o + 8)
        outs.append([v, raw[p:p + ln]])
        o = p + ln
    rest = raw[o:]
    assert outs and outs[0][0] > value, 'the coinbase cannot pay the founders reward: %r' % outs
    outs[0][0] -= value
    outs.append([value, script])
    body = _compact_size(len(outs)) + b''.join(
        v.to_bytes(8, 'little') + _compact_size(len(sc)) + sc for v, sc in outs)
    return raw[:vout_at] + body + rest


def _merkle_root(txids):
    """txids: internal byte order."""
    level = list(txids)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_sha256d(level[k] + level[k + 1]) for k in range(0, len(level), 2)]
    return level[0]


def with_founders_reward(t, peer_rpc):
    """``t`` (a kogany template) paying the founders' reward the ycash6 peer requires at its
    height, or ``t`` itself (none due, or already paid); (template, added)."""
    raw = bytes.fromhex(t['coinbasetxn']['data'])
    if peer_rpc is None or int.from_bytes(raw[0:4], 'little') & 0x7fffffff >= 5:
        return t, False                                    # a v5 coinbase also moves the auth data root
    height = int(t['height'])
    try:
        ycash = peer_rpc.getblockchaininfo().get('upgrades', {}).get('374d694f', {}).get('activationheight')
        if ycash is not None and ycash <= height and height >= REGTEST_YDF_MANDATE_END:
            return t, False                                # past the mandate the YDF output is optional
        due = Decimal(str(peer_rpc.getblocksubsidy(height).get('founders', 0)))
    except JSONRPCException:
        return t, False
    zat = int(due * 100000000)
    if zat <= 0:
        return t, False
    script = _founders_script()
    if script in raw:
        return t, False
    cb = _coinbase_with_output(raw, script, zat)
    txids = [_sha256d(cb)] + [bytes.fromhex(x['hash'])[::-1] for x in t['transactions']]
    t = dict(t)
    t['coinbasetxn'] = dict(t['coinbasetxn'], data=cb.hex(), hash=_sha256d(cb)[::-1].hex())
    t['defaultroots'] = dict(t['defaultroots'], merkleroot=_merkle_root(txids)[::-1].hex())
    return t, True


def kogany_regtest_schedule(args):
    """F-S5-18: ``args`` with the network upgrades kogany's regtest activates without being told.
    Zakura's ``ConfiguredActivationHeights::for_regtest`` (zakura-chain
    parameters/network/testnet.rs) puts an unset Blossom at the Sapling height, Heartwood at
    Blossom's and Canopy at Heartwood's (Zakura validates no pre-Canopy rules), while ycashd's
    regtest leaves them unset: the framework's start_node names only Overwinter and Sapling, so a
    pair's cache chain is mined under Canopy rules (6.25 subsidy, no founders' reward,
    blockcommitments the chain-history root) that a plain ycashd refuses at block 1.  The mixed
    variant's ycash6 peer judges the chain kogany actually runs, so it is given the same schedule
    (Ycash's own Blossom/Heartwood/Canopy ids; ycashd puts its Ycash upgrade with them).  What
    ycashd's Ycash rules add on top (the YDF output below the mandate end) the solved generate adds
    (with_founders_reward)."""
    heights = {}
    for a in args:
        if a.startswith('-nuparams='):
            b, _, h = a.split('=', 1)[1].partition(':')
            key = NU_BRANCH_TABLE.get(int(b, 16), (None,))[0]
            if key is not None:
                heights[key] = int(h)
    if 'Sapling' not in heights:
        return list(args)
    out = list(args)
    prev = heights['Sapling']
    for key, branch in (('Blossom', 0x8e471bd6), ('Heartwood', 0x66314da3), ('Canopy', 0x19bd2d2f)):
        if key not in heights:
            heights[key] = prev
            out.append('-nuparams=%x:%d' % (branch, prev))
        prev = heights[key]
    return out


class SolvingProxy:
    """A pair node's RPC proxy whose ``generate`` mines solved blocks from kogany's templates
    (the mixed variant: a ycashd peer checks (48,5)).  Everything else is the proxy's."""

    def __init__(self, inner, i):
        self.__dict__['_inner'] = inner
        self.__dict__['_i'] = i

    def __getattr__(self, name):
        if name == 'generate':
            return self._generate
        return getattr(self._inner, name)

    def __setattr__(self, name, value):
        setattr(self._inner, name, value)

    def _generate(self, n, *rest):
        hashes = []
        col = YEWD_COLUMN[0]
        peer = col.rpc if col is not None and col.alive() else None
        for _ in range(int(n)):
            t, added = with_founders_reward(self._inner.getblocktemplate(), peer)
            if added:
                col.stats['founders_added'] += 1
            block, h = solve_template(t)
            r = self._inner.submitblock(block)
            if r is not None:
                raise JSONRPCException({'code': -1, 'message': 'generate: kogany refused its own solved template: %r' % (r,)})
            hashes.append(h)
        if col is not None:
            col.stats['solved_blocks'] += len(hashes)
        return hashes


# --- the column ------------------------------------------------------------------------------

class YewdColumn:
    """Column 3's cross-checks: the pairs' state hashes at every sync point, and the optional
    ycash6 peer (YEWD_YCASH6_PEER=1)."""

    def __init__(self, tmpdir, env=None):
        env = os.environ if env is None else env
        self.tmpdir = tmpdir
        self.peer = int(env.get('YEWD_PEER', '0'))
        self.with_peer = env.get('YEWD_YCASH6_PEER', '0') == '1'
        self.solve = self.with_peer or env.get('YEWD_SOLVE', '0') == '1'
        self.sync_timeout = float(env.get('KOGANY_SYNC_TIMEOUT', '120'))
        self.ycashd = None
        self.ycashd_args = None
        self.rpc = None
        self.k = 'ycash6-peer'
        self.stats = {'sync_points': 0, 'statehash_vault': 0, 'statehash_yed': 0, 'peer_points': 0,
                      'solved_blocks': 0, 'mempool_points': 0, 'fed_txs': 0, 'fed_pair_txs': 0,
                      'peer_mirrored': 0, 'founders_added': 0}
        self.feed_after = float(env.get('YEWD_PEER_FEED_AFTER', '5'))
        self._notes = set()
        self.datadir = os.path.join(tmpdir, 'ycash6peer')

    def note(self, msg):
        if msg not in self._notes:
            self._notes.add(msg)
            print('yewd column: ' + msg)

    @classmethod
    def ensure(cls, tmpdir):
        if YEWD_COLUMN[0] is None:
            col = cls(tmpdir)
            YEWD_COLUMN[0] = col
            util.MIXED_HOOKS['start'] = col.on_node_start
            util.MIXED_HOOKS['sync_blocks'] = col.sync_point
            util.MIXED_HOOKS['sync_mempools'] = col.mempool_point
            util.MIXED_HOOKS['sync_failed'] = col.sync_failed
            util.MIXED_HOOKS['mempool_wait'] = col.mempool_wait
            atexit.register(col.stop)
            print('yewd column: kogany + yewd pairs (%s)%s' % (yewd_kogany_bin(), (
                '; ycash6 peer dials pair %d, generate solved by the harness' % col.peer) if col.with_peer else ''))
        return YEWD_COLUMN[0]

    # the ycash6 peer
    def on_node_start(self, i, args, proxy):
        if not self.with_peer or i != self.peer:
            return
        b_args, _w = split_yewd_args(args)
        want = [a for a in b_args if not a.startswith(('-datadir=', '-mineraddress=', '-minetolocalwallet',
                                                       '-connect=', '-addnode=', '-listen=', '-port=',
                                                       '-rpcport='))]
        want = kogany_regtest_schedule(want)
        if self.ycashd is not None and self.ycashd.poll() is None and want == self.ycashd_args:
            return
        self.stop_peer()
        self.ycashd_args = want
        os.makedirs(self.datadir, exist_ok=True)
        with open(os.path.join(self.datadir, 'ycash.conf'), 'w', encoding='utf8') as f:
            f.write('regtest=1\nshowmetrics=0\nlistenonion=0\nrpcport=%d\n' % kogany_v2_port(MAX_NODES))
        argv = [util.zcashd_binary(), '-datadir=' + self.datadir, '-disablewallet', '-listen=0',
                '-port=%d' % sidecar_dead_port(MAX_NODES), '-connect=127.0.0.1:%d' % p2p_port(self.peer)] + want
        log = open(os.path.join(self.datadir, 'stderr.log'), 'ab')
        self.ycashd = subprocess.Popen(argv, stdout=log, stderr=log)
        cookie = os.path.join(self.datadir, 'regtest', '.cookie')
        self.rpc = KoganyRPC('http://127.0.0.1:%d/' % kogany_v2_port(MAX_NODES), cookie=cookie)
        deadline = time.time() + 120
        while True:
            if self.ycashd.poll() is not None:
                raise AssertionError('the ycash6 peer exited at start (%s)' % self.datadir)
            had = os.path.exists(cookie)
            try:
                self.rpc.getblockcount()
                break
            except JSONRPCException as e:
                if not _backend_warming_up(e, had):
                    raise
            except OSError:
                pass
            assert time.time() < deadline, 'the ycash6 peer did not come up'
            time.sleep(0.25)

    def alive(self):
        return self.ycashd is not None and self.ycashd.poll() is None

    def stop_peer(self):
        if self.ycashd is None:
            return
        if self.ycashd.poll() is None:
            try:
                self.rpc.stop()
            except Exception:
                self.ycashd.terminate()
            try:
                self.ycashd.wait(60)
            except subprocess.TimeoutExpired:
                self.ycashd.kill()
                self.ycashd.wait()
        self.ycashd = None

    def stop(self):
        self.stop_peer()
        print('yewd column: stopped; %s' % ', '.join('%s=%d' % kv for kv in sorted(self.stats.items())))
        path = os.getenv('KOGANY_STATS_FILE')
        if path:
            with open(path, 'a', encoding='utf-8') as fh:
                fh.write(json.dumps({'script': os.path.basename(sys.argv[0]), 'pid': os.getpid(), 'column': 3,
                                     'stats': dict(self.stats), 'notes': sorted(self._notes)}, sort_keys=True) + '\n')

    # sync points
    def _statehashes(self, c):
        try:
            v = c.vault_getinfo().get('statehash')
        except JSONRPCException:
            v = None
        try:
            y = c.yed_getstatehash()
            y = _field(y, 'statehash') if not isinstance(y, dict) else (y.get('statehash'), y.get('height'), y.get('blockhash'))
        except JSONRPCException:
            y = None
        return v, y

    def sync_point(self, conns):
        conns = list(conns)
        if not conns:
            return
        self.stats['sync_points'] += 1
        tip = conns[0].getbestblockhash()
        hashes = [self._statehashes(c) for c in conns]
        # a node that does not serve the read (a stock node: Yellowback not live there) is skipped,
        # as MixedLine skips a peer that does not serve it; a stock pair that serves vault_getinfo
        # is skipped for the vault statehash too (a stock node's differs after a YED mint, on both
        # lines: it does not run the Yellowback module's vault rows)
        stock = [YEWD_PAIR_STOCK.get(_pair_index(c), False) for c in conns]
        vaults = [h[0] for h, st in zip(hashes, stock) if h[0] is not None and not st]
        yeds = [h[1] for h in hashes if h[1] is not None]
        if len(set(map(str, vaults))) > 1:
            raise AssertionError('yewd column: vault_getinfo.statehash differs between pairs at %s: %s' % (tip, vaults))
        if len(set(map(str, yeds))) > 1:
            raise AssertionError('yewd column: yed_getstatehash differs between pairs at %s: %s' % (tip, yeds))
        vaults = vaults[:1] or [None]
        yeds = yeds[:1] or [None]
        if vaults[0] is not None:
            self.stats['statehash_vault'] += 1
        if yeds[0] is not None:
            self.stats['statehash_yed'] += 1
        if not self.with_peer or not any(_port_of(c) == rpc_port(self.peer) for c in conns):
            return
        if not self.alive():
            raise AssertionError('the ycash6 peer exited (see %s)' % self.datadir)
        deadline = time.time() + self.sync_timeout
        mirror_at = time.time() + self.feed_after
        while True:
            try:
                got = self.rpc.getbestblockhash()
            except (OSError, JSONRPCException):
                got = None
            if got == tip:
                break
            if got is not None and time.time() > mirror_at:
                self._mirror(conns[0], tip, got)
                mirror_at = time.time() + self.feed_after
            if time.time() > deadline:
                raise AssertionError('the ycash6 peer did not reach the pairs\' tip %s (height %d): at %s '
                                     '(a block kogany accepted and ycashd refused? see %s/regtest/debug.log)'
                                     % (tip, conns[0].getblockcount(), got, self.datadir))
            time.sleep(0.2)
        v, y = self._statehashes(self.rpc)
        if YEWD_PAIR_STOCK.get(self.peer, False):
            v = None                                       # the peer runs pair YEWD_PEER's (stock) rules
        if v is not None and vaults[0] is not None and str(v) != str(vaults[0]):
            raise AssertionError('yewd column: vault_getinfo.statehash at %s: pairs (kogany) %s, ycash6 peer %s'
                                 % (tip, vaults[0], v))
        if y is not None and yeds[0] is not None and str(y) != str(yeds[0]):
            raise AssertionError('yewd column: yed_getstatehash at %s: pairs (kogany) %s, ycash6 peer %s'
                                 % (tip, yeds[0], y))
        self.stats['peer_points'] += 1

    def _mirror(self, pair, tip, got):
        """A script's invalidateblock/reconsiderblock reaches only the pairs it names (the rig's and the
        followers' limit, KOGANY_MIRROR_INVALIDATE): the peer reconsiders the pairs' tip if it holds it
        as invalid, and invalidates its own branch above the fork with the pairs' chain."""
        try:
            self.rpc.getblockheader(tip)
            self.rpc.reconsiderblock(tip)
            self.stats['peer_mirrored'] += 1
        except JSONRPCException:
            pass
        h = got
        first = None
        for _ in range(500):
            try:
                hdr = self.rpc.getblockheader(h)
            except JSONRPCException:
                return
            try:
                on_pairs = pair.getblockhash(hdr['height']) == h
            except JSONRPCException:
                on_pairs = False
            if on_pairs:
                break
            first = h
            h = hdr.get('previousblockhash')
            if h is None:
                return
        if first is not None:
            try:
                self.rpc.invalidateblock(first)
                self.stats['peer_mirrored'] += 1
            except JSONRPCException:
                pass

    def mempool_point(self, conns):
        """The ycash6 peer's mempool holds every pair's (each transaction a sidecar built, judged by
        ycashd: §4.3 rule 3), within the sync timeout."""
        if not self.with_peer or not self.alive():
            return
        conns = list(conns)
        if not any(_port_of(c) == rpc_port(self.peer) for c in conns):
            return
        want = set(conns[0].getrawmempool())
        deadline = time.time() + self.sync_timeout
        feed_at = time.time() + self.feed_after
        while True:
            got = set(self.rpc.getrawmempool())
            if want <= got:
                break
            if time.time() > feed_at:
                # kogany's transaction gossip to the ycashd peer is not reliable (W9-a/F-3, the rig's
                # feed): what the peer still lacks is offered to it directly, so ycashd judges every
                # transaction a pair holds; a refusal is a cross-line divergence
                self._feed(conns[0], sorted(want - got))
                feed_at = deadline + 1
            if time.time() > deadline:
                raise AssertionError('the ycash6 peer lacks %d mempool transaction(s) of the pairs: %s '
                                     '(see %s/regtest/debug.log)'
                                     % (len(want - got), sorted(want - got)[:4], self.datadir))
            time.sleep(0.2)
        self.stats['mempool_points'] += 1

    def _feed(self, pair, txids):
        """Offer the pairs' mempool transactions the peer lacks, parents first (a refusal of one
        that is not a missing parent fails the run)."""
        hexes = {}
        for t in txids:
            try:
                hexes[t] = pair.getrawtransaction(t)
            except JSONRPCException:
                continue                                # mined or evicted meanwhile
        for _ in range(len(hexes) + 1):
            left = {}
            for t, h in hexes.items():
                try:
                    self.rpc.sendrawtransaction(h, True)
                    self.stats['fed_txs'] += 1
                except JSONRPCException as e:
                    msg = str(e.error.get('message', ''))
                    if 'already in' in msg or 'txn-already' in msg:
                        continue
                    if 'Missing inputs' in msg or 'missing-inputs' in msg:
                        left[t] = h
                        continue
                    raise AssertionError('the ycash6 peer refuses %s, which kogany holds in its mempool: %s'
                                         % (t, msg))
            if not left or len(left) == len(hexes):
                break
            hexes = left

    def mempool_wait(self, conns, waited):
        """util._sync_mempools hook: kogany's transaction gossip between koganys is not reliable (the
        rig's finding W9-a/F-3, F-S5-16): after ``feed_after`` x 2 seconds a pair that lacks a
        transaction another pair holds is offered it by sendrawtransaction (through its yewd); a
        refusal is a divergence between two koganys and fails the run.  Once per sync."""
        if waited < 2 * self.feed_after or waited >= 2 * self.feed_after + 0.5:
            return
        pools = [set(c.getrawmempool()) for c in conns]
        union = set().union(*pools)
        for c, pool in zip(conns, pools):
            for t in sorted(union - pool):
                holder = next(x for x, p in zip(conns, pools) if t in p)
                try:
                    h = holder.getrawtransaction(t)
                except JSONRPCException:
                    continue
                try:
                    c.sendrawtransaction(h, True)
                    self.stats['fed_pair_txs'] += 1
                except JSONRPCException as e:
                    msg = str(e.error.get('message', ''))
                    if 'already' in msg or 'Missing inputs' in msg or 'missing-inputs' in msg:
                        continue
                    raise AssertionError('pair at port %s refuses %s, which another pair holds: %s'
                                         % (_port_of(c), t, msg))

    def sync_failed(self, kind, conns):
        for c in conns:
            try:
                print('yewd column: %s failed; node at port %s: tip %s height %s mempool %d'
                      % (kind, _port_of(c), c.getbestblockhash(), c.getblockcount(), len(c.getrawmempool())))
            except Exception as e:
                print('yewd column: %s failed; node at port %s: %r' % (kind, _port_of(c), e))
        if self.alive():
            print('yewd column: ycash6 peer tip %s height %s' % (self.rpc.getbestblockhash(), self.rpc.getblockcount()))


def _pair_index(conn):
    """The node index whose rpc_port ``conn`` talks to, or None."""
    port = _port_of(conn)
    for i in range(MAX_NODES):
        if port == rpc_port(i):
            return i
    return None


def _port_of(conn):
    try:
        return urlparse(conn.url).port
    except Exception:
        return None


def yewd_wrap_proxy(i, proxy):
    """util.start_node hook: in column 3 with the harness's solved generate, the pair's proxy."""
    col = YEWD_COLUMN[0]
    if col is not None and col.solve and i in YEWD_KOGANY_PAIRS:
        return SolvingProxy(proxy, i)
    return proxy


YEWD_KOGANY_PAIRS = set()
# node index -> the pair runs Yellowback-off (a "stock" node: no -yellowbackattestorset).  Its vault
# statehash is not the enforcing nodes' after a YED mint, on either line, so it is not compared.
YEWD_PAIR_STOCK = {}


def yewd_build_cache(test_dir, num_nodes):
    """``initialize_chain``'s 'current' cache under YEWD_BIN: the cache's 200-block chain (each of
    the first four nodes mines 25 blocks twice in turn, so each holds 25 mature and 25 immature
    coinbases) mined in ``test_dir`` by the run's own pairs, which are then stopped; the script
    starts them again on that chain and those wallets.  The block times are the node's clock rather
    than the cache's mocked past (kogany has no mock clock for its templates)."""
    n = max(num_nodes, 4)
    for i in range(num_nodes, n):
        util.initialize_datadir(test_dir, i)
    rpcs = []
    try:
        for i in range(n):
            rpcs.append(util.start_node(i, test_dir))
        for i in range(1, n):
            util.connect_nodes_bi(rpcs, 0, i)
        for _ in range(2):
            for peer in range(4):
                rpcs[peer].generate(25)
                util.sync_blocks(rpcs)
    finally:
        # a failure here leaves the framework without self.nodes: stop the pairs, or its
        # wait_bitcoinds waits for them forever
        util.stop_nodes(rpcs)
        util.wait_bitcoinds()
    for i in range(num_nodes, n):
        import shutil
        shutil.rmtree(os.path.join(test_dir, 'node%d' % i), ignore_errors=True)


# ---------------------------------------------------------------------------
# The ycash6 test rig (kogany plan W9-a; K-3 as amended: the rig, not the product).
# KOGANY_SIDECAR=1 with KOGANY_BIN turns node i into kogany i + ycashd i:
#
#   kogany i   a koganyd in tmpdir/kogany<i>, configured from node i's own arguments, listening for
#              P2P on p2p_port(i) (the node's address, so a script's connect_nodes(a, b) reaches
#              kogany b) and serving its RPC on kogany_rpc_port(i);
#   ycashd i   the unchanged ycashd with -connect=127.0.0.1:p2p_port(i) -listen=0, serving the wallet
#              RPCs (and every other RPC) on rpc_port(i), so the scripts keep talking to it.
#
# What connect= needs (R-10): a plain ycashd, no valargroup-style build.  -connect makes kogany i
# the node's only automatic peer and -listen=0 means no peer ever dials the ycashd, so every block
# and transaction a ycashd receives comes from a kogany, which relays only what it validated.
# The ycashd still validates everything itself (it is a full node following kogany's chain): that
# double validation is the point of the rig, a two-line differential at every hop.  A script's
# connect_nodes(a, b) is ycashd a's addnode to p2p_port(b) = kogany b, which -connect does not
# block (addnode is an RPC, not an automatic connection); so ycashd a peers with kogany a and
# kogany b, and the script's topology (and split_network's disconnectnode) carries over with a
# kogany at every node address.  Each kogany therefore takes several inbound connections from
# 127.0.0.1: max_connections_per_ip is raised to SIDECAR_MAX_CONNS_PER_IP (Zakura's default 1
# would refuse the second; the W1-Y5 trap).  The ycashd mines (generate): kogany does not mine on
# regtest (K-16), so a script's block reaches the other nodes only through a kogany that accepted
# it.  Unlike valargroup's production sidecar, the rig keeps addnode, generate and submitblock:
# the scripts need them.  The kogany outlives a ycashd restart (a restart with a changed kogany
# config restarts it), so a script's stop_node/start_node leaves the chain where kogany holds it.

SIDECAR_MAX_CONNS_PER_IP = 16
SIDECAR_NODES = {}        # node index -> KoganyNode (KOGANY_SIDECAR=1)
SIDECAR_REFUSED = {}      # node index -> why kogany i refused its config at the last start


def sidecar_enabled(env=None):
    """True when the run is in the test-rig mode (KOGANY_SIDECAR=1 and KOGANY_BIN set)."""
    env = os.environ if env is None else env
    return env.get('KOGANY_SIDECAR', '0') == '1' and bool(env.get('KOGANY_BIN'))


def sidecar_dead_port(i):
    """The port ycashd i advertises in the rig (``-port``): nothing listens on it."""
    assert 0 <= i <= MAX_NODES
    return PORT_MIN + 9 * PORT_RANGE + i + _offset()


def sidecar_ycashd_args(i, args):
    """ycashd i's arguments in the rig: the script's, then -connect to kogany i, -listen=0 and a
    -port nothing listens on (the last value of a repeated option wins, so a script's own -listen is
    overridden).  The port matters (finding W9-a/F-2): a ycashd's version message advertises
    127.0.0.1:<its -port>, ycash.conf's port is p2p_port(i) = kogany i's listener, and Zakura's
    crawler dials what its peers advertise, so with the conf's port every kogany learned every
    other kogany's address and they meshed, which a network split cannot cut (kogany has no
    disconnectnode)."""
    return list(args) + ['-connect=127.0.0.1:%d' % p2p_port(i), '-listen=0', '-port=%d' % sidecar_dead_port(i)]


def sidecar_kogany_config(args, i, datadir, live=None):
    """kogany i's config from node i's ycashd arguments: ``koganyd_config`` for slot i, then
    listening on p2p_port(i), no initial peers (the ycashds dial it), and room for one inbound
    connection per ycashd from 127.0.0.1."""
    cfg, notes = koganyd_config(args, i, [], datadir, live=live)
    net = cfg['network']
    net['listen_addr'] = '127.0.0.1:%d' % p2p_port(i)
    net['initial_testnet_peers'] = []
    net['max_connections_per_ip'] = SIDECAR_MAX_CONNS_PER_IP
    return cfg, notes


def start_sidecar(i, dirname, args):
    """``util.start_node`` hook (KOGANY_SIDECAR=1), called before ycashd i starts: start kogany i
    (or keep it running when its config is unchanged; restart it otherwise) and return ycashd i's
    arguments.  ``args`` are node i's arguments without the binary."""
    mixed = current()
    k = SIDECAR_NODES.get(i)
    if k is None:
        k = KoganyNode(i, dirname, os.environ['KOGANY_BIN'], mixed.extra_args or os.getenv('KOGANY_ARGS', '').split())
    config, notes = sidecar_kogany_config(args, i, k.datadir)
    SIDECAR_REFUSED.pop(i, None)
    if not k.alive() or config != k.config:
        k.stop()
        k.write_config(config, notes)
        try:
            k.start()
        except AssertionError as e:
            # kogany refused this config at start: an agreement if ycashd i refuses it too (a script's
            # assert_start_raises_init_error), a divergence if ycashd i starts (sidecar_started)
            SIDECAR_REFUSED[i] = str(e)
            k.config = None
    SIDECAR_NODES[i] = k
    if k not in mixed.followers:
        mixed.followers.append(k)
    return sidecar_ycashd_args(i, args)


class RigRelay(threading.Thread):
    """The rig's background re-announcement (finding W9-a/F-3), for the waits a script does itself
    (``wait_for_mempool`` with its own timeout, chain-viz's snapshot) and that no harness hook sees.
    Every ``period`` seconds, per node: a transaction ycashd i has held for ``age`` seconds that
    kogany i lacks goes to kogany i's ``sendrawtransaction``; one kogany i has held that long and
    ycashd i lacks goes to ycashd i.  Pair-local, so a split's halves never exchange anything; kogany
    then gossips what it took to its own peers, which is the re-announcement Zakura never makes.
    Its own connections (one per call), never the script's.  ``KOGANY_SIDECAR_RELAY=0`` turns it off."""

    def __init__(self, mixed, period=2.0, age=4.0):
        super().__init__(name='kogany-rig-relay', daemon=True)
        self.mixed, self.period, self.age = mixed, period, age
        self.halt = threading.Event()
        self.seen = {}                # (node, direction, txid) -> first time seen missing

    def run(self):
        while not self.halt.wait(self.period):
            try:
                self.round(time.time())
            except Exception as e:     # never let the helper kill a run; the sync checks still judge
                print('kogany rig relay: %r' % (e,))

    def round(self, now):
        missing = set()
        for i, k in list(SIDECAR_NODES.items()):
            if not k.alive() or i not in util.bitcoind_processes:
                continue
            y = util.get_rpc_proxy(util.rpc_url(i), i, timeout=10)
            try:
                have_y, have_k = set(y.getrawmempool()), set(k.rpc.getrawmempool())
            except (OSError, JSONRPCException):
                continue
            for direction, txids in (('k', have_y - have_k), ('y', have_k - have_y)):
                for txid in txids:
                    key = (i, direction, txid)
                    missing.add(key)
                    first = self.seen.setdefault(key, now)
                    if now - first < self.age:
                        continue
                    try:
                        if direction == 'k':
                            k.rpc.with_timeout(self.mixed.tx_timeout).sendrawtransaction(y.getrawtransaction(txid))
                            self.mixed.stats['relayed_txs_kogany'] = self.mixed.stats.get('relayed_txs_kogany', 0) + 1
                        else:
                            y.sendrawtransaction(k.rpc.getrawtransaction(txid))
                            self.mixed.stats['relayed_txs_ycashd'] = self.mixed.stats.get('relayed_txs_ycashd', 0) + 1
                    except (OSError, JSONRPCException):
                        pass           # refused, mined or evicted meanwhile: retried next round if still missing
        self.seen = {key: t for key, t in self.seen.items() if key in missing}

    def stop(self):
        self.halt.set()
        if self.is_alive():
            self.join(10)


def sidecar_started(i):
    """``util.start_node`` hook after ycashd i answered: kogany i must have taken the same config."""
    msg = SIDECAR_REFUSED.pop(i, None)
    if msg is not None:
        raise AssertionError('kogany %d refused a config ycashd %d accepts: %s' % (i, i, msg))


def stop_sidecars():
    for k in list(SIDECAR_NODES.values()):
        k.stop()
    SIDECAR_NODES.clear()


# ---------------------------------------------------------------------------
# A small JSON-RPC client: Zakura answers JSON-RPC 2.0 (no "error" key on success) and needs no
# Basic auth with cookie auth off, neither of which AuthServiceProxy handles.

class KoganyRPC:
    def __init__(self, url, timeout=60, name=None, cookie=None):
        self._url = url
        self._timeout = timeout
        self._name = name
        self._cookie = cookie
        self._id = 0

    def __getattr__(self, name):
        if name.startswith('__') and name.endswith('__'):
            raise AttributeError(name)
        return KoganyRPC(self._url, self._timeout, name, self._cookie)

    def with_timeout(self, timeout):
        """The same endpoint with another socket timeout (seconds)."""
        return KoganyRPC(self._url, timeout, self._name, self._cookie)

    @property
    def url(self):
        return self._url

    def __call__(self, *args):
        self._id += 1
        body = json.dumps({'jsonrpc': '1.0', 'id': self._id, 'method': self._name, 'params': list(args)},
                          default=lambda o: str(o) if isinstance(o, Decimal) else o)
        u = urlparse(self._url)
        headers = {'Content-Type': 'application/json'}
        if self._cookie and os.path.exists(self._cookie):
            with open(self._cookie) as f:
                headers['Authorization'] = 'Basic ' + b64encode(f.read().strip().encode()).decode()
        conn = HTTPConnection(u.hostname, u.port, timeout=self._timeout)
        try:
            conn.request('POST', u.path or '/', body, headers)
            resp = conn.getresponse()
            data = resp.read().decode('utf8')
        finally:
            conn.close()
        try:
            r = json.loads(data, parse_float=Decimal)
        except ValueError:
            raise JSONRPCException({'code': -342, 'message': 'non-JSON response %d: %s' % (resp.status, data[:200])})
        if r.get('error') is not None:
            raise JSONRPCException(r['error'])
        if 'result' not in r:
            raise JSONRPCException({'code': -343, 'message': 'missing JSON-RPC result'})
        return r['result']


METHOD_NOT_FOUND = -32601


def _missing(e):
    err = getattr(e, 'error', {}) or {}
    return isinstance(err, dict) and (err.get('code') == METHOD_NOT_FOUND
                                      or 'not found' in str(err.get('message', '')).lower()
                                      and 'method' in str(err.get('message', '')).lower())


# ---------------------------------------------------------------------------

class KoganyNode:
    """One ``koganyd`` follower process in ``tmpdir/kogany<k>``."""

    def __init__(self, k, tmpdir, binary, extra_args=()):
        self.k = k
        self.binary = binary
        self.extra_args = list(extra_args)
        self.datadir = os.path.join(tmpdir, 'kogany%d' % k)
        self.conf = os.path.join(self.datadir, 'koganyd.toml')
        self.process = None
        self.config = None
        self.rpc = KoganyRPC('http://127.0.0.1:%d/' % kogany_rpc_port(k),
                             cookie=os.path.join(self.datadir, 'rpc', '.cookie'))

    def write_config(self, config, notes):
        os.makedirs(self.datadir, exist_ok=True)
        with open(self.conf, 'w', encoding='utf8') as f:
            f.write(render_toml(config, notes))
        self.config = config

    def start(self, timeout=90):
        # a port another process holds (a long-running node on this machine, another run's node) is
        # reported as that, not as the garbage its listener answers (yellowback_chainviz once hit a
        # mainnet node's P2P listener on 127.0.0.1:28833 as the follower's RPC port)
        for what, port in (('p2p', kogany_p2p_port(self.k)), ('rpc', kogany_rpc_port(self.k))):
            probe = socket.socket()
            try:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind(('127.0.0.1', port))
            except OSError as e:
                raise AssertionError('kogany %d: its %s port 127.0.0.1:%d is taken by another process (%s); '
                                     'rerun with another --portseed' % (self.k, what, port, e))
            finally:
                probe.close()
        log = open(os.path.join(self.datadir, 'koganyd.log'), 'ab')
        argv = [self.binary, '-c', self.conf] + self.extra_args + ['start']
        self.process = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)
        deadline = time.time() + timeout
        while True:
            if self.process.poll() is not None:
                raise AssertionError('kogany %d (%s) exited with %s during start; see %s'
                                     % (self.k, self.binary, self.process.returncode,
                                        os.path.join(self.datadir, 'koganyd.log')))
            try:
                self.rpc.getblockcount()
                return
            except (OSError, JSONRPCException):
                pass
            assert time.time() < deadline, 'kogany %d: RPC did not come up within %ds' % (self.k, timeout)
            time.sleep(0.25)

    def alive(self):
        return self.process is not None and self.process.poll() is None

    def stop(self, timeout=60):
        if self.process is None:
            return
        if self.process.poll() is None:
            try:
                self.rpc.stop()
            except Exception:
                self.process.terminate()
            try:
                self.process.wait(timeout)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.process = None


# The peer a script's follower takes when KOGANY_PEER is unset, for the scripts whose default
# peer cannot carry it (W9-b; the scripts stay unchanged, the shard runner sets no per-script env):
#   vault_activation_restart  node 1 is the Sapling case (Sapling at 10, nothing else: a chain kogany
#                             cannot follow); node 3 is the Vault activation invalidated at its height
#                             (W2-d ran it with KOGANY_PEER=2|3|5)
#   vault_primitive           VaultHarness.assert_connected counts node 1's getpeerinfo exactly (2):
#                             a follower of node 1 is a third peer; node 0's count is never asserted
KOGANY_SUBVER = re.compile(r'/(kogany|Zakura|zakura)[:/]')   # zakurad's user agent (/kogany:1.7.0/)

SCRIPT_PEER = {
    'vault_activation_restart': 3,
    'vault_primitive': 0,
}


class MixedLine:
    """The run's kogany followers and the cross-line assertions.  ``from_env`` returns an inert
    instance when ``KOGANY_BIN`` is unset: every method is then a no-op."""

    def __init__(self, binary=None, followers=1, peer=None, strict=False, mempool=False,
                 sync_timeout=120, extra_args=(), yewd=None, mirror_invalidate=False,
                 tx_timeout=10, sidecar=False, pump_after=5.0):
        self.binary = binary
        self.sidecar = bool(sidecar and binary)   # KOGANY_SIDECAR=1: the W9-a test rig
        self.n_followers = followers
        self.peer = peer
        self.strict = strict
        self.mempool = mempool
        self.sync_timeout = sync_timeout
        self.extra_args = list(extra_args)
        self.yewd = yewd
        self.connect_settle = 5.0
        self.connect_retry = 60.0     # a restarted peer: seconds of re-dials (_connect)
        self.mirror_invalidate = mirror_invalidate
        self.tx_timeout = tx_timeout
        self.mirrored = {}
        self.followers = []
        self.relay = None             # the rig's RigRelay thread
        self.tmpdir = None
        self.peer_args = None
        self._notes = set()
        self.unmapped = []
        self.kogany_unmapped = []
        self.offered = set()
        self.script_invalidates = False   # the script's source calls invalidateblock/reconsiderblock
        self.stats = {'sync_points': 0, 'statehash_vault': 0, 'statehash_yed': 0, 'mempool_points': 0,
                      'verdicts': 0, 'verdict_classes': 0}
        if self.sidecar:
            self.stats.update({'pumped_blocks': 0, 'pump_rounds': 0, 'fed_txs_kogany': 0, 'fed_txs_ycashd': 0})
        self.pump_after = pump_after          # the rig: seconds a lagging kogany gets before the feed
        self.tx_feed_after = 2 * pump_after   # the rig: seconds a mempool gap gets before the tx feed
        self.pump_batch = 200

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        binary = env.get('KOGANY_BIN') or None
        peer = env.get('KOGANY_PEER')
        return cls(binary=binary,
                   followers=int(env.get('KOGANY_FOLLOWERS', '1')),
                   peer=int(peer) if peer not in (None, '') else None,
                   strict=env.get('KOGANY_STRICT', '0') == '1',
                   mempool=env.get('KOGANY_MEMPOOL', '0') == '1',
                   sync_timeout=float(env.get('KOGANY_SYNC_TIMEOUT', '120')),
                   extra_args=env.get('KOGANY_ARGS', '').split(),
                   yewd=env.get('YEWD_BIN') or None,
                   mirror_invalidate=env.get('KOGANY_MIRROR_INVALIDATE', '0') == '1',
                   tx_timeout=float(env.get('KOGANY_TX_TIMEOUT', '10')),
                   sidecar=env.get('KOGANY_SIDECAR', '0') == '1',
                   pump_after=float(env.get('KOGANY_SIDECAR_PUMP_AFTER', '5')))

    @property
    def enabled(self):
        return self.binary is not None

    @property
    def active(self):
        return bool(self.followers)

    def note(self, msg):
        """Print a skip note once per run (fails under KOGANY_STRICT)."""
        if self.strict:
            raise AssertionError('kogany (strict): ' + msg)
        if msg not in self._notes:
            self._notes.add(msg)
            print('kogany: ' + msg)

    # --- lifecycle -----------------------------------------------------------

    def configure(self, test):
        """Called by ``BitcoinTestFramework.main`` once the options are parsed."""
        self.tmpdir = test.options.tmpdir
        self.script_invalidates = _calls_invalidate(type(test))
        if self.peer is None:
            self.peer = SCRIPT_PEER.get(os.path.splitext(os.path.basename(sys.argv[0]))[0])
        if self.peer is None:
            self.peer = getattr(test, 'kogany_peer', None)
            if self.peer is None:
                self.peer = 1 if getattr(test, 'num_nodes', 1) > 1 else 0
        _register(self)

    def on_node_start(self, i, args, proxy):
        """``util.start_node`` hook: remember the peer's arguments; on a restart of the peer,
        restart a follower whose config changed and re-make the connection."""
        if not self.enabled or self.sidecar or i != self.peer:
            return              # the rig starts kogany i itself, before ycashd i (start_sidecar)
        self.peer_args = list(args)
        for f in self.followers:
            config, notes = self._config_for(f)
            if config != f.config:
                f.stop()
                f.write_config(config, notes)
                f.start()
                self._connect(proxy, f)
            else:
                if self.mirror_invalidate:
                    self._mirror_restart(proxy, f)
                # the follower kept running: its getpeerinfo may still list the connection to the
                # peer's previous process (a SIGKILL'd peer, vault_primitive section J), so the
                # restarted peer is asked instead
                self._connect(proxy, f, restart=True)

    def attach(self, test):
        """Called after ``setup_network``: start the followers against the peer and wait for them
        to reach its tip."""
        if not self.enabled:
            return
        if not test.nodes and not getattr(test, 'num_nodes', 0):
            # a run without nodes (create_cache.py, which rpc-tests.py runs first under -j > 1):
            # nothing to follow
            return
        if self.sidecar:
            print('kogany: test rig, %d kogany + ycashd pair(s) (%s)' % (len(SIDECAR_NODES), self.binary))
            self.sync_point(list(test.nodes), 'attach')
            if os.getenv('KOGANY_SIDECAR_RELAY', '1') == '1':
                self.relay = RigRelay(self)
                self.relay.start()
            return
        assert test.nodes and self.peer < len(test.nodes), 'KOGANY_PEER %s is not a node of this run' % self.peer
        if self.peer_args is None:
            raise AssertionError('kogany: the peer node %d was not started through util.start_node' % self.peer)
        for k in range(self.n_followers):
            f = KoganyNode(k, self.tmpdir, self.binary, self.extra_args)
            config, notes = self._config_for(f)
            f.write_config(config, notes)
            f.start()
            self.followers.append(f)
            self._connect(test.nodes[self.peer], f)
        print('kogany: %d follower(s) of node %d (%s)' % (len(self.followers), self.peer, self.binary))
        self.sync_point([test.nodes[self.peer]], 'attach')

    def stop(self):
        if self.relay is not None:
            self.relay.stop()
            self.relay = None
        for f in self.followers:
            f.stop()
        SIDECAR_NODES.clear()
        if self.followers:
            print('kogany: stopped; %s' % ', '.join('%s=%d' % kv for kv in sorted(self.stats.items())))
            path = os.getenv('KOGANY_STATS_FILE')
            if path:
                with open(path, 'a', encoding='utf-8') as fh:
                    fh.write(json.dumps({'script': os.path.basename(sys.argv[0]), 'pid': os.getpid(),
                                         'stats': dict(self.stats), 'mirrored': len(self.mirrored), 'notes': sorted(self._notes),
                                         'unmapped': sorted(set(self.unmapped)),
                                         'kogany_unmapped': sorted(set(self.kogany_unmapped))},
                                        sort_keys=True) + '\n')
        self.followers = []
        if self.unmapped:
            print('kogany: unmapped ycashd reject reasons (add REJECT_CODE_MAP rows): %s'
                  % sorted(set(self.unmapped)))
        if self.kogany_unmapped:
            print('kogany: unmapped kogany reject texts (add KOGANY_REASON_MAP rows): %s'
                  % sorted(set(self.kogany_unmapped)))
        hint = self.invalidate_hint()
        if hint:
            print('kogany: ' + hint)

    INVALIDATE_HINT = ('this script calls invalidateblock/reconsiderblock and KOGANY_MIRROR_INVALIDATE is off: '
                       'the call reaches only the ycashd node it names, so a follower keeps the invalidated '
                       'branch (a sync point times out on it); rerun with KOGANY_MIRROR_INVALIDATE=1 to mirror it')

    def invalidate_hint(self):
        """The mixed-run summary's hint (mirroring stays opt-in): set when the script's source calls
        ``invalidateblock``/``reconsiderblock`` and ``KOGANY_MIRROR_INVALIDATE`` is off."""
        if self.enabled and self.script_invalidates and not self.mirror_invalidate:
            return self.INVALIDATE_HINT
        return None

    def _config_for(self, f):
        return koganyd_config(self.peer_args, f.k, [p2p_port(self.peer)], f.datadir)

    def _connect(self, proxy, f, settle=None, restart=False):
        """One connection per follower: the follower dials the peer (``initial_testnet_peers``);
        only when it still has no peer after ``settle`` seconds (a peer restart, say) does the peer
        ``addnode <follower> onetry``.  Never two: a script that counts ``getpeerinfo`` sees one
        extra peer per follower, not two (recorded)."""
        addr = '127.0.0.1:%d' % kogany_p2p_port(f.k)
        deadline = time.time() + (self.connect_settle if settle is None else settle)
        while True:
            try:
                if restart:
                    # the restarted peer's own view: a follower peer per follower (all followers
                    # share the one peer)
                    if sum(1 for p in proxy.getpeerinfo() if KOGANY_SUBVER.search(p.get('subver', ''))) \
                            >= len(self.followers):
                        return
                elif f.rpc.getpeerinfo():
                    return
            except (OSError, JSONRPCException):
                pass
            if time.time() > deadline:
                break
            time.sleep(0.25)
        try:
            if not any(p.get('addr') == addr for p in proxy.getpeerinfo()):
                proxy.addnode(addr, 'onetry')
        except JSONRPCException:
            pass
        if restart:
            # the follower may still count the dead connection of the peer's previous process
            # against max_connections_per_ip = 1 and refuse the first dial (yellowback_wallet_restore:
            # encryptwallet restarts node 0 twice in a row): dial again until the peer sees it
            retry = time.time() + self.connect_retry
            while time.time() < retry:
                time.sleep(2)
                try:
                    peers = proxy.getpeerinfo()
                    if sum(1 for p in peers if KOGANY_SUBVER.search(p.get('subver', ''))) >= len(self.followers):
                        return
                    if not any(p.get('addr') == addr for p in peers):
                        proxy.addnode(addr, 'onetry')
                except (OSError, JSONRPCException):
                    pass

    def _pairs(self, conns):
        """[(ycashd connection, kogany)] a sync point compares: every follower against the peer, or,
        in the rig, each connection whose node has a kogany against that kogany."""
        if self.sidecar:
            out = []
            for c in conns:
                i = _node_index(c)
                if i is not None and i in SIDECAR_NODES:
                    out.append((c, SIDECAR_NODES[i]))
            return out
        ref = self._peer_conn(conns)
        return [] if ref is None else [(ref, f) for f in self.followers]

    def _peer_conn(self, conns):
        port = rpc_port(self.peer)
        for c in conns:
            try:
                if urlparse(c.url).port == port:
                    return c
            except Exception:
                continue
        return None

    # --- sync points (rule 4 (ii)) ------------------------------------------------

    def sync_point(self, conns, label=''):
        """Every follower reaches the peer's tip; then ``vault_getinfo.statehash`` and
        ``yed_getstatehash`` equal the peer's (each skipped, with a note, while kogany lacks the
        RPC or the peer does not serve it).  A no-op unless the peer is among ``conns``."""
        if not self.active:
            return
        pairs = self._pairs(conns)
        if not pairs:
            return
        self.stats['sync_points'] += 1
        for ref, f in pairs:
            tip = ref.getbestblockhash()
            if not f.alive():
                raise AssertionError('kogany %d exited (see %s/koganyd.log)' % (f.k, f.datadir))
            if self.sidecar:
                self._check_isolated(f)
            else:
                self._connect(ref, f)
            deadline = time.time() + self.sync_timeout
            while True:
                try:
                    got = f.rpc.getbestblockhash()
                except (OSError, JSONRPCException):
                    got = None
                if got == tip:
                    break
                if self.mirror_invalidate and got is not None:
                    self._mirror(ref, f, got)
                if self.sidecar and got is not None and time.time() > deadline - self.sync_timeout + self.pump_after:
                    self._pump(ref, f, got)
                if time.time() > deadline:
                    hint = self.invalidate_hint()
                    raise AssertionError('kogany %d did not reach the peer tip %s (height %d) %s: at %s%s'
                                         % (f.k, tip, ref.getblockcount(), label, got,
                                            ('; ' + hint) if hint else ''))
                time.sleep(0.2)
            self._compare_statehash(ref, f, label)

    def _mirror_restart(self, ref, f):
        """KOGANY_MIRROR_INVALIDATE=1, at a restart of the peer, before the follower reconnects: a
        restart can erase a branch the script invalidated (vault_activation_restart: "the restart is
        clean and erases the branch"), which getchaintips no longer shows, and the follower, still
        on it, would serve it back to the peer the script keeps isolated. Invalidate on the
        follower the first block of its chain the restarted peer does not know; reconsider a
        mirrored block the peer's active chain holds again."""
        self._mirror_reconsider(ref, f)
        try:
            h, child = f.rpc.getbestblockhash(), None
            while True:
                try:
                    ref.getblockheader(h)
                    break                                   # the peer knows it: the common chain
                except JSONRPCException as e:
                    if e.error.get('code') != -5:
                        return
                child = h
                h = f.rpc.getblock(h, 1)['previousblockhash']
            if child is not None:
                f.rpc.invalidateblock(child)
                self.mirrored.setdefault(f.k, []).append(child)
                print('kogany %d: mirrored the restart\'s erase: invalidateblock %s' % (f.k, child[:16]))
        except (JSONRPCException, KeyError, OSError):
            pass

    def _check_isolated(self, f):
        """The rig's topology: a kogany's only peers are ycashds that dialed it.  An outbound
        connection is a kogany-to-kogany link the script's topology does not have (and its
        split_network cannot cut): fail (finding W9-a/F-2)."""
        try:
            peers = f.rpc.getpeerinfo()
        except (OSError, JSONRPCException):
            return
        out = [p.get('addr') for p in peers if p.get('inbound') is False]
        if out:
            raise AssertionError('kogany %d has outbound peer(s) %s: the rig leaked a kogany-to-kogany link'
                                 % (f.k, out))

    def sync_failed(self, kind, conns):
        """``util`` hook before a failed sync_blocks/sync_mempools raises: in the rig, print every
        pair's tip, mempool and kogany peers, so a relay gap names the hop that dropped it."""
        if not (self.sidecar and self.active):
            return
        print('kogany rig: %s sync failed; per node (ycashd | kogany):' % kind)
        for ref, f in self._pairs(conns):
            try:
                y = (ref.getblockcount(), ref.getbestblockhash()[:12], sorted(ref.getrawmempool()))
                k = (f.rpc.getblockcount(), f.rpc.getbestblockhash()[:12], sorted(f.rpc.getrawmempool()))
                peers = sorted(p.get('addr') for p in f.rpc.getpeerinfo())
            except Exception as e:
                print('  node %d: %r' % (f.k, e))
                continue
            print('  node %d: ycashd %d %s mempool %s | kogany %d %s mempool %s peers %s'
                  % (f.k, y[0], y[1], [h[:12] for h in y[2]], k[0], k[1], [h[:12] for h in k[2]], peers))

    def mempool_wait(self, conns, waited):
        """``util._sync_mempools`` hook, called while the ycashds' mempools still differ: in the rig,
        after ``tx_feed_after`` seconds, close the relay gaps (finding W9-a/F-3).  Zakura gossips a
        transaction once, to the peers ready at that instant, and never re-announces it; a ycashd
        re-announces a wallet transaction only on its rebroadcast timer (minutes).  So a single missed
        announcement leaves a ycashd without a transaction its kogany holds, or a kogany without one
        the group holds.  The feed: a transaction of the sync group missing from kogany i goes to
        kogany i's ``sendrawtransaction`` (kogany validates it and gossips it again); one kogany i holds
        that ycashd i lacks goes to ycashd i from kogany i's mempool (it came from a kogany).  A
        kogany refusal is printed, never fatal here: the sync itself still has to converge."""
        if not (self.sidecar and self.active) or waited < self.tx_feed_after:
            return
        pairs = self._pairs(conns)
        group = {}
        for ref, _f in pairs:
            for txid in ref.getrawmempool():
                group.setdefault(txid, ref)
        for ref, f in pairs:
            try:
                have_y = set(ref.getrawmempool())
                have_k = set(f.rpc.getrawmempool())
            except (OSError, JSONRPCException):
                continue
            for txid, src in group.items():
                if txid in have_k:
                    continue
                try:
                    f.rpc.with_timeout(self.tx_timeout).sendrawtransaction(src.getrawtransaction(txid))
                    self.stats['fed_txs_kogany'] += 1
                except (OSError, JSONRPCException) as e:
                    print('kogany %d: the rig fed %s, refused: %s' % (f.k, txid[:16], _message(e)[:120]))
            for txid in have_k - have_y:
                try:
                    ref.sendrawtransaction(f.rpc.getrawtransaction(txid))
                    self.stats['fed_txs_ycashd'] += 1
                except (OSError, JSONRPCException):
                    pass                    # mined, evicted or a conflict meanwhile: the next round sees it

    def sync_wait(self, conns, waited):
        """``util._sync_blocks`` hook, called while the ycashds' tips still differ: in the rig, after
        ``pump_after`` seconds, feed each lagging kogany the blocks its own ycashd holds (``_pump``),
        then the blocks of the highest ycashd of the sync group: a ycashd and its kogany that both lag
        (a node whose only other link is to a kogany that gossiped the blocks while the ycashd's
        connection was not ready, and whose ycashd then never asks again) are otherwise stuck.  A
        kogany may refuse another node's block (that node can run other rules, the stock node
        without the attestor set), so only its own ycashd's blocks are a divergence."""
        if not (self.sidecar and self.active) or waited < self.pump_after:
            return
        pairs = self._pairs(conns)
        best = None
        try:
            best = max(conns, key=lambda c: c.getblockcount())
        except (OSError, JSONRPCException, ValueError):
            pass
        for ref, f in pairs:
            for src in (ref, best):
                if src is None:
                    continue
                try:
                    got = f.rpc.getbestblockhash()
                except (OSError, JSONRPCException):
                    break
                self._pump(src, f, got, own=src is ref)

    def _pump(self, ref, f, got, own=True):
        """The rig's feed (finding W9-a/F-1): kogany i is behind ycashd i on ycashd i's active chain, so
        submit the missing blocks (up to ``pump_batch``) from ycashd i to kogany i's ``submitblock``,
        which fully validates each one; kogany then relays them to the other ycashds by P2P.

        Why: zcashd never answers a ``getdata`` for a block it lacks (no ``notfound`` for blocks), and
        Zakura's syncer routes block requests to any ready peer, so a kogany whose other ycashd peers
        lag waits ``BLOCK_DOWNLOAD_TIMEOUT`` (20 s) per misrouted request when one ycashd mines a burst
        (a 101-block ``generate`` took over a minute).  The steady state (one block, gossiped by
        ``inv``) needs no feed.  A block kogany refuses here is a cross-line divergence: ycashd i holds
        it in its active chain.  ``KOGANY_SIDECAR_PUMP_AFTER`` (default 5 s) is the grace before the
        feed; a large value turns it off."""
        try:
            tip = ref.getbestblockhash()
            if got == tip:
                return
            ref_height = ref.getblockcount()
            k_height = f.rpc.getblockcount()
            h = min(k_height, ref_height)
            while h > 0 and f.rpc.getblockhash(h) != ref.getblockhash(h):
                h -= 1                     # kogany on another branch: feed from the common ancestor
        except (OSError, JSONRPCException):
            return
        if ref_height <= h:
            return                         # kogany is ahead or on a longer branch: nothing to feed
        self.stats['pump_rounds'] += 1
        for height in range(h + 1, min(ref_height, h + self.pump_batch) + 1):
            block_hex = ref.getblock(ref.getblockhash(height), 0)
            try:
                result = f.rpc.submitblock(block_hex)
            except JSONRPCException as e:
                result = _message(e)
            if classify_kogany_block(result) != ACCEPT:
                if not own:            # another node's rules may differ: its own ycashd decides
                    print('kogany %d: the rig fed block %d of another node, refused (%s)' % (f.k, height, result))
                    return
                raise AssertionError('kogany %d refused block %d of ycashd %d\'s active chain: %s'
                                     % (f.k, height, f.k, result))
            self.stats['pumped_blocks'] += 1
            if not own:
                self.stats['pumped_blocks_cross'] = self.stats.get('pumped_blocks_cross', 0) + 1

    def _mirror_reconsider(self, ref, f):
        for h in list(self.mirrored.get(f.k, [])):
            try:
                if ref.getblock(h)['confirmations'] >= 0:
                    f.rpc.reconsiderblock(h)
                    self.mirrored[f.k].remove(h)
                    print('kogany %d: mirrored reconsiderblock %s' % (f.k, h[:16]))
            except JSONRPCException:
                pass

    def _mirror(self, ref, f, got):
        """KOGANY_MIRROR_INVALIDATE=1: a script's ``invalidateblock`` / ``reconsiderblock`` reach
        only the ycashd node it calls.  When the follower's tip is a tip the peer holds as
        ``invalid`` (getchaintips), invalidate on the follower the first block of that branch off
        the peer's active chain; reconsider it once the peer's active chain contains it again.
        Opt-in: getchaintips cannot tell a script's invalidateblock from a validation reject, so
        mirroring could hide a block kogany wrongly accepts (verdict checks still run)."""
        self._mirror_reconsider(ref, f)
        try:
            if not any(t['hash'] == got and t['status'] == 'invalid' for t in ref.getchaintips()):
                return
            h, child = got, None
            while ref.getblock(h)['confirmations'] < 0:
                child = h
                h = f.rpc.getblock(h, 1)['previousblockhash']
            if child is not None:
                f.rpc.invalidateblock(child)
                self.mirrored.setdefault(f.k, []).append(child)
                print('kogany %d: mirrored invalidateblock %s' % (f.k, child[:16]))
        except (JSONRPCException, KeyError):
            pass

    # vault_getinfo fields compared once kogany serves the set state (a ``statehash``): the counts
    # and the database tip are the statehash's coarse witnesses, so a difference names what drifted.
    VAULT_STATE_FIELDS = ('statehash', 'dbtip', 'sets', 'vaults', 'intents', 'lockedvalue')
    # Compared whenever kogany answers; a difference is a note (fatal under KOGANY_STRICT) until the
    # read RPCs serve the live parameters (W7: the W7-a prototype answers -1 / false).
    VAULT_UPGRADE_FIELDS = ('activationheight', 'active', 'height')

    def _compare_statehash(self, ref, f, label):
        self._compare_vault(ref, f, label)
        self._compare_yed(ref, f, label)
        self._check_pruned(f, label)

    def _check_pruned(self, f, label):
        """KOGANY_PRUNED=1: the follower is a pruned node (``getblockchaininfo.pruned``, with a
        ``pruneheight``, as ycashd reports it); the highest ``pruneheight`` seen is in the stats."""
        if pruned_retention() is None:
            return
        info = f.rpc.getblockchaininfo()
        if info.get('pruned') is not True or 'pruneheight' not in info:
            raise AssertionError('kogany %d: KOGANY_PRUNED=1 but getblockchaininfo says pruned=%r pruneheight=%r %s'
                                 % (f.k, info.get('pruned'), info.get('pruneheight'), label))
        self.stats['pruned_checks'] = self.stats.get('pruned_checks', 0) + 1
        self.stats['pruneheight'] = max(self.stats.get('pruneheight', 0), info['pruneheight'])

    def _compare_vault(self, ref, f, label):
        """Rule 4 (ii) for the primitive: ``vault_getinfo`` at a sync point.  ``branchid`` always;
        the set state (``VAULT_STATE_FIELDS``) once kogany answers a ``statehash`` (W4-d's live
        state; skipped with a note before); the upgrade fields as a note."""
        try:
            want = ref.vault_getinfo()
        except JSONRPCException:
            return                        # the peer does not serve it here
        try:
            got = f.rpc.vault_getinfo()
        except JSONRPCException as e:
            if _missing(e):
                self.note('vault_getinfo not served yet; statehash_vault equality skipped')
                return
            raise
        if got.get('branchid') != want.get('branchid'):
            raise AssertionError('kogany %d: vault_getinfo.branchid differs %s: ycashd %s, kogany %s'
                                 % (f.k, label, want.get('branchid'), got.get('branchid')))
        for key in self.VAULT_UPGRADE_FIELDS:
            if key in got and got.get(key) != want.get(key):
                self.note('vault_getinfo.%s differs (ycashd %s, kogany %s): the read RPC does not serve the '
                          'live upgrade parameters yet (W7)' % (key, want.get(key), got.get(key)))
        if got.get('statehash') is None:
            if want.get('statehash') is not None:
                self.note('vault_getinfo served without statehash yet (W4-d); statehash_vault equality skipped')
            return
        diffs = ['%s: ycashd %s, kogany %s' % (key, want.get(key), got.get(key))
                 for key in self.VAULT_STATE_FIELDS if _norm(got.get(key)) != _norm(want.get(key))]
        if diffs:
            raise AssertionError('kogany %d: vault_getinfo differs %s at %s: %s'
                                 % (f.k, label, ref.getbestblockhash(), '; '.join(diffs)))
        self.stats['statehash_vault'] += 1

    def _compare_yed(self, ref, f, label):
        """Rule 4 (ii) for the module: ``yed_getstatehash`` (the index height, block and hash)."""
        try:
            want = ref.yed_getstatehash()
        except JSONRPCException:
            return                        # the peer does not serve it here (Yellowback not live)
        try:
            got = f.rpc.yed_getstatehash()
        except JSONRPCException as e:
            if _missing(e) or e.error.get('code') in (-1, -32603):
                self.note('yed_getstatehash not served yet (%s); statehash_yed equality skipped'
                          % str(e.error.get('message', ''))[:80])
                return
            raise
        if _field(got, 'statehash') is None:
            self.note('yed_getstatehash served without statehash yet; statehash_yed equality skipped')
            return
        diffs = ['%s: ycashd %s, kogany %s' % (key, want.get(key), got.get(key))
                 for key in ('statehash', 'height', 'blockhash')
                 if isinstance(got, dict) and key in got and _norm(got.get(key)) != _norm(want.get(key))]
        if not isinstance(got, dict) and _field(got, 'statehash') != _field(want, 'statehash'):
            diffs.append('statehash: ycashd %s, kogany %s' % (_field(want, 'statehash'), got))
        if diffs:
            raise AssertionError('kogany %d: yed_getstatehash differs %s: %s' % (f.k, label, '; '.join(diffs)))
        self.stats['statehash_yed'] += 1

    def mempool_point(self, conns):
        """``getrawmempool`` set equality with the peer (``KOGANY_MEMPOOL=1``)."""
        if not (self.active and self.mempool):
            return
        pairs = self._pairs(conns)
        if not pairs:
            return
        self.stats['mempool_points'] += 1
        for ref, f in pairs:
            start = time.time()
            deadline = start + self.sync_timeout
            while True:
                want = set(ref.getrawmempool())
                got = set(f.rpc.getrawmempool())
                if got == want:
                    break
                if self.sidecar:
                    self.mempool_wait([ref], time.time() - start)   # the rig's feed, pair by pair
                if time.time() > deadline:
                    raise AssertionError('kogany %d mempool differs: only ycashd %s, only kogany %s%s'
                                         % (f.k, sorted(want - got), sorted(got - want),
                                            self._offer_missing(ref, f, want - got)))
                time.sleep(0.25)

    def _offer_missing(self, ref, f, txids):
        """The diagnosis of a mempool difference: each transaction only ycashd holds, offered to
        the follower with sendrawtransaction, and its answer (the set check has failed already)."""
        out = []
        for txid in sorted(txids):
            try:
                raw = ref.getrawtransaction(txid)
                f.rpc.with_timeout(self.tx_timeout + 5).sendrawtransaction(raw)
                out.append('%s: accepted when offered directly (a relay difference)' % txid[:16])
            except JSONRPCException as e:
                out.append('%s: %s' % (txid[:16], _message(e)))
            except Exception as e:   # a timeout: kogany waits for a missing input
                out.append('%s: %s' % (txid[:16], e))
        return ('; offered to kogany: ' + '; '.join(out)) if out else ''

    # --- verdicts (rule 4 (iii)) ---------------------------------------------------

    def _wait_parent(self, f, prev, timeout=30):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if f.rpc.getbestblockhash() == prev:
                    return True
                f.rpc.getblock(prev, 0)   # known (a side branch): good enough to offer a child
                return True
            except (OSError, JSONRPCException):
                time.sleep(0.2)
        return False

    def _judges(self, node):
        """The koganys whose verdict is compared with ``node``'s: every follower, or in the rig the
        kogany of ``node`` alone (each kogany is configured from its own ycashd, so the stock node's
        kogany, without the attestor set, accepts what the enforcing ycashds reject -- as the stock
        ycashd does).  A rig call without ``node`` keeps every kogany."""
        if not self.sidecar or node is None:
            return list(self.followers)
        i = _node_index(node)
        return [SIDECAR_NODES[i]] if i in SIDECAR_NODES else []

    def offer_block(self, block_hex, cxx_result, label='', node=None):
        """Submit ``block_hex`` to every follower and assert the verdict class equals ycashd's
        ``cxx_result`` (its ``submitblock`` result; ``node`` the ycashd that gave it, which in the rig
        picks the kogany that judges).  Returns the classes, or None when inert."""
        if not self.active:
            return None
        raw = bytes.fromhex(block_hex)
        prev = raw[4:36][::-1].hex()
        cxx = classify_cxx_block(cxx_result)
        out = []
        for f in self._judges(node):
            if not self._wait_parent(f, prev):
                self.note('block offered on a parent kogany %d does not have; verdict skipped' % f.k)
                continue
            proposal = self._proposal(f, block_hex)
            try:
                result = f.rpc.submitblock(block_hex)
                kog = classify_kogany_block(result, proposal)
                text = '%s (proposal: %s)' % (result, proposal)
            except JSONRPCException as e:
                kog, text = REJECT_UNCLASSIFIED, _message(e)   # an RPC error is a reject without a class
            if kog == REJECT_UNCLASSIFIED:
                self.kogany_unmapped.append('block: ' + text)
            self._assert_same(cxx, kog, 'block', label, cxx_result, text)
            out.append(kog)
        return cxx, out

    def _proposal(self, f, block_hex):
        """The follower's ``getblocktemplate`` proposal-mode answer for ``block_hex``: ``None``
        (valid), the verifier's refusal text, or ``None`` when the mode is unavailable (a
        follower not yet synced answers an error; the bare submitblock result then decides)."""
        try:
            r = f.rpc.getblocktemplate({'mode': 'proposal', 'data': block_hex})
        except (OSError, JSONRPCException):
            return None
        return r if isinstance(r, str) else None

    def offer_tx(self, tx_hex, cxx_error, label='', node=None):
        """The transaction path (``KOGANY_MEMPOOL=1``): ``cxx_error`` is None when ycashd accepted
        ``tx_hex``, else its ``JSONRPCException`` (``node`` as for ``offer_block``)."""
        if not (self.active and self.mempool):
            return None
        cxx = classify_cxx_tx(cxx_error, self.unmapped)
        out = []
        for f in self._judges(node):
            text = ''
            try:
                f.rpc.with_timeout(self.tx_timeout).sendrawtransaction(tx_hex)
                kog = ACCEPT
            except socket.timeout:
                # Zakura's verifier waits for a missing input to appear (UTXO_LOOKUP_TIMEOUT, six
                # minutes, zakura-consensus transaction.rs:59) instead of answering ycashd's
                # "Missing inputs" at once: no answer is that wait, a tip-dependent verdict.
                kog = REJECT_STATE
                text = 'no answer within %ss: kogany waits for a missing input' % self.tx_timeout
                self.note('kogany holds a transaction waiting for a missing input (no answer within %ss); '
                          'compared as reject-state' % self.tx_timeout)
            except JSONRPCException as e:
                kog, text = classify_kogany_tx(e), _message(e)
                if kog == REJECT_UNCLASSIFIED:
                    self.kogany_unmapped.append('tx: ' + text)
            self._assert_same(cxx, kog, 'tx', label, cxx_error, text)
            out.append(kog)
        return cxx, out

    def on_block_rejected(self, node, blockhash):
        """``assert_rejected`` hook: offer the block ycashd holds as invalid to the followers."""
        key = (blockhash, _node_index(node)) if self.sidecar else blockhash   # the rig: once per node's kogany
        if not self.active or key in self.offered:
            return
        self.offered.add(key)
        try:
            block_hex = node.getblock(blockhash, 0)
        except JSONRPCException:
            self.note('a rejected block without data on the ycashd node; verdict skipped')
            return
        self.offer_block(block_hex, 'invalid', 'assert_rejected %s' % blockhash, node=node)

    def _assert_same(self, cxx, kog, path, label, detail, kogany_text=''):
        self.stats['verdicts'] += 1
        if same_class(cxx, kog, self.strict):
            if kog == REJECT_UNCLASSIFIED:
                self.note('kogany %s reject text no KOGANY_REASON_MAP row names (%s); compared accept/reject '
                          'only' % (path, kogany_text[:160]))
            else:
                self.stats['verdict_classes'] += 1
            return
        raise AssertionError('verdict class differs (%s) %s: ycashd %s (%s), kogany %s (%s)'
                             % (path, label, cxx, detail, kog, kogany_text))


def _node_index(conn):
    """The node index whose rpc_port ``conn``'s URL names (None when none does)."""
    try:
        port = urlparse(conn.url).port
    except Exception:
        return None
    for i in range(MAX_NODES):
        if rpc_port(i) == port:
            return i
    return None


_INVALIDATE_CALL = re.compile(r'\.(invalidateblock|reconsiderblock)\s*\(')


def _calls_invalidate(cls):
    """True when the source of the module defining ``cls`` (the script) calls
    ``invalidateblock``/``reconsiderblock`` (False when the source cannot be read)."""
    mod = sys.modules.get(getattr(cls, '__module__', ''), None)
    path = getattr(mod, '__file__', None)
    if not path:
        return False
    try:
        with open(path, encoding='utf8') as f:
            return bool(_INVALIDATE_CALL.search(f.read()))
    except OSError:
        return False


def _field(r, key):
    if isinstance(r, dict):
        return r.get(key) or r.get('stateHash')
    return r


def _norm(v):
    """A JSON value as both nodes' answers compare: amounts as Decimal, objects field by field."""
    if isinstance(v, dict):
        return {k: _norm(x) for k, x in v.items()}
    if isinstance(v, float):
        return Decimal(str(v))
    if isinstance(v, (int, Decimal)) and not isinstance(v, bool):
        return Decimal(v)
    return v


# ---------------------------------------------------------------------------
# The run's instance and the util hooks.

_CURRENT = [MixedLine()]


def current():
    """The run's ``MixedLine`` (an inert one before ``BitcoinTestFramework.main`` configures it)."""
    return _CURRENT[0]


def _register(mixed):
    _CURRENT[0] = mixed
    util.MIXED_HOOKS['start'] = mixed.on_node_start
    util.MIXED_HOOKS['sync_blocks'] = mixed.sync_point
    util.MIXED_HOOKS['sync_mempools'] = mixed.mempool_point
    util.MIXED_HOOKS['sync_wait'] = mixed.sync_wait
    util.MIXED_HOOKS['mempool_wait'] = mixed.mempool_wait
    util.MIXED_HOOKS['sync_failed'] = mixed.sync_failed
    atexit.register(mixed.stop)


def describe():
    """The key table, for ``kogany_mixed_smoke.py --describe`` and review."""
    lines = ['ycashd argument -> koganyd.toml (status)']
    for arg, status, key, note in KOGANYD_KEY_TABLE:
        lines.append('  %-38s %-14s %s%s' % (arg, status, key or '-', ('  # ' + note) if note else ''))
    lines.append('branch id -> activation_heights key (status)')
    for b, (key, status, note) in sorted(NU_BRANCH_TABLE.items()):
        lines.append('  %08x  %-10s %-14s %s' % (b, key, status, note))
    return '\n'.join(lines)


if __name__ == '__main__':
    print(describe())
    sys.exit(0)
