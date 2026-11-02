#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The mixed-line harness: kogany (``zakurad``) followers inside the unchanged ycash6 regtest scripts.

Kogany plan K-18 (a), W1-Y7 (harness part), W2-d, W4-e; plan section 4.2 rule 4 (the three-way
cross-line invariant) and section 5 ("The mixed-line harness").  Nothing here changes a script:
the framework starts the followers, and the sync and verdict hooks run inside the existing
``sync_blocks`` / ``sync_mempools`` / ``start_node`` / ``mine_block_raw`` / ``assert_rejected``.
With ``KOGANY_BIN`` unset every entry point is inert, so a run without it is the plain ycash6
regression (CI runs both, so a kogany failure never hides as a C++ failure).

Environment
-----------

``KOGANY_BIN``            path to ``zakurad`` (kogany).  Unset: no follower, every hook a no-op.
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
``KOGANY_ARGS``           extra ``zakurad`` arguments, whitespace-separated, placed before ``start``.
``KOGANY_LOG``            ``tracing.filter`` for the followers (default ``info``).
``KOGANY_STATS_FILE``     a file the run appends one JSON line to when the followers stop: the
                          script, the counters (sync points, statehash points, verdicts, verdict
                          classes, mempool points) and the notes (rpc-tests.py prints a passing
                          script's output nowhere; W9-b's results table reads this).
``YEWD_BIN``              path to ``yewd`` (the parity sidecar, plan section 3b): every node becomes a
                          ycashd ``-disablewallet`` backend plus a yewd in front of it on the node's
                          RPC port (``start_yewd_pair``; contract: yew/yewd/README.md "Harness mode").
                          Independent of ``KOGANY_BIN``.

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
``zakurad_config(args, slot, peer_p2p_ports, datadir)``  ycashd arguments -> (config dict, notes);
``render_toml(config, notes)``        the ``zakurad.toml`` text; ``ZAKURAD_KEY_TABLE`` /
                                      ``NU_BRANCH_TABLE`` are the map.
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
"""

import atexit
import json
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
# 2*PORT_RANGE); the three kogany ranges sit above them, with the same per-seed offset.

def _offset():
    return (MAX_NODES * PortSeed.n) % (PORT_RANGE - 1 - MAX_NODES)


def kogany_p2p_port(k):
    assert 0 <= k <= MAX_NODES
    return PORT_MIN + 2 * PORT_RANGE + k + _offset()


def kogany_rpc_port(k):
    assert 0 <= k <= MAX_NODES
    return PORT_MIN + 3 * PORT_RANGE + k + _offset()


def kogany_v2_port(k):
    """Zakura's native (QUIC) listener: off under ``p2p_stack = "legacy"`` (K-11), given a port of
    its own anyway so a default that binds it never collides with another slot."""
    assert 0 <= k <= MAX_NODES
    return PORT_MIN + 4 * PORT_RANGE + k + _offset()


# ---------------------------------------------------------------------------
# The ycashd-argument -> zakurad.toml map.
#
# status: 'live'           emitted as a key today;
#         'derived'        not copied: the follower gets its own value (its own port, its own dir);
#         'pending:<chunk>' the kogany key does not exist yet; recorded as a comment in the toml
#                          (zakurad's config is serde deny_unknown_fields, so an early key would
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
}

ZAKURAD_KEY_TABLE = [
    # (ycashd argument or ycash.conf key, status, zakurad.toml key, note)
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
    ('-pqfalconheight=<h>', 'pending:W3-c', 'kogany.pq_falcon_height',
     'Falcon activation; kogany has no key yet (finding W3-c/F-1, open)'),
    ('-pqfalcon=<0|1>', 'pending:W3-c', 'kogany.pq_falcon_height',
     '1 = -pqfalconheight=0 (Falcon from the vault activation); same open finding W3-c/F-1'),
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
    ('-yellowbackpayoutaddress=<addr>', 'ignored', None, 'followers never mine (K-16); W8 maps the pool tag'),
    ('-yellowbacktestfault=<spec>', 'ignored', None,
     'gap: ycashd\'s regtest fault injection (yellowback/index.cpp SetTestFault: storage/crash/template/schema); '
     'kogany\'s [yellowback] has no fault key, so a follower never injects one'),
    ('-yellowbacksignal', 'ignored', None, 'retired with the vault upgrade; ycashd logs and ignores it (init.cpp)'),
    ('-feepolicy=<p>', 'ignored', None, 'wallet funding policy only (no relay or mempool meaning)'),
    ('-blockunpaidactionlimit=<n>', 'ignored', None, 'block template policy; followers never mine (K-16)'),
    ('-mempoolevictionmemoryminutes=<n>', 'ignored', None, 'gap: no row for mempool.eviction_memory_time yet; '
     'a follower keeps Zakura\'s default'),
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
                     '-listen', '-whitelist', '-maxconnections', '-yellowbackpayoutaddress',
                     '-addnode', '-connect', '-datadir', '-port', '-rpcport', '-rpcuser', '-rpcpassword',
                     '-regtest', '-blocknotify', '-txindex', '-insightexplorer', '-lightwalletd',
                     '-experimentalfeatures', '-allowdeprecated', '-paytxfee', '-minrelaytxfee',
                     '-mempooltxcostlimit', '-limitancestor', '-walletnotify', '-wallet', '-mineraddress',
                     '-equihashsolver', '-gen', '-genproclimit', '-checkmempool', '-checkblockindex',
                     '-stopatheight', '-reindex', '-prune', '-dbcache', '-par', '-timeout',
                     '-orchardwallet', '-nuparams',
                     # wallet, RPC transport and C++-only plumbing (no follower meaning)
                     '-developerencryptwallet', '-mnemonicfile', '-rescan', '-salvagewallet', '-sendchangeback',
                     '-migration', '-consolidation', '-deletetx', '-keeptx', '-zmqpub', '-proxy', '-onion',
                     '-noonion', '-nolisten', '-rpcallowip', '-rpcbind', '-rpccookiefile', '-rpcconnect',
                     '-bdbcache', '-anchorconfirmations', '-txexpirydelta', '-preferredtxversion',
                     '-printpriority', '-maxorphantx', '-regtestwalletsetbestchaineveryblock',
                     '-disablewallet', '-yellowbacktestfault', '-yellowbacksignal', '-feepolicy',
                     '-blockunpaidactionlimit', '-mempoolevictionmemoryminutes')
# -yellowbacktestfault is a gap, not a no-op: ycashd injects a storage/crash/template/schema fault
# (src/yellowback/index.cpp SetTestFault) and kogany has no fault key, so a follower of a faulted
# peer runs unfaulted.  -yellowbacksignal is retired (ycashd logs and ignores it).
# Deliberately absent (UnmappedArgument when KOGANY_BIN is set, so a kogany run never silently
# drops a rule): -nurejectoldversions, -regtestshieldcoinbase, -regtestprotectcoinbase,
# -regtestenablezip209, -reindex-yellowback, and the retired -yellowback / -yellowbackenforce /
# -yellowbackstartheight flags.
def _bool01(v):
    if v not in ('0', '1'):
        raise UnmappedArgument('a 0/1 flag has the value %r' % v)
    return v == '1'


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
    '-pqfalconheight': ('W3-c', ('kogany', 'pq_falcon_height'), int),
    # -pqfalcon=1 is ycashd's -pqfalconheight=0 (Falcon from the vault activation); -pqfalcon=0, none
    '-pqfalcon': ('W3-c', ('kogany', 'pq_falcon_height'), lambda v: 0 if v in ('', '1') else -1),
}

# Chunks live unless KOGANY_LIVE names them with a '!' (W5-f: the module registration landed, so a
# follower takes the YED attestor set and the [yellowback] parameters).
DEFAULT_LIVE = frozenset({'W5-f'})

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


def zakurad_config(args, slot, peer_p2p_ports, datadir, live=None, log_filter=None):
    """Map one ycashd argument list (the peer's: ``util.start_node``'s own ``-nuparams`` for
    Overwinter/Sapling plus the script's) to a ``zakurad`` config for follower ``slot``.

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
        if name in _LIVE_FLAGS:
            path, conv = _LIVE_FLAGS[name]
            _set(cfg, path, conv(value))
            continue
        if name in _PENDING_FLAGS:
            chunk, path, conv = _PENDING_FLAGS[name]
            if chunk in live:
                _set(cfg, path, conv(value))
            else:
                notes.append('pending:%s: %s -> %s = %s' % (chunk, a, '.'.join(path), value))
            continue
        if name.startswith(_IGNORED_PREFIXES) or name.startswith('-yellowbackpayout'):
            if name.startswith(('-mocktime', '-yellowbackpayoutaddress', '-yellowbacktestfault',
                                '-mempoolevictionmemoryminutes')):
                notes.append('ignored: %s' % a)
            continue
        if name.startswith('-yellowback') or name.startswith('-vault') or name.startswith('-pq'):
            raise UnmappedArgument('%s carries Yellowback/vault meaning and has no ZAKURAD_KEY_TABLE row' % name)
        raise UnmappedArgument('%s has no ZAKURAD_KEY_TABLE row' % name)

    # Zakura keeps one upgrade per height, the later variant winning (testnet.rs:924-929), and
    # refuses a map out of order; ycashd's regtest puts every Ycash upgrade at 1, which is the
    # same chain either way (Canopy rules from 1).  Order the keys as ConfiguredActivationHeights.
    order = ['Overwinter', 'Sapling', 'Ycash', 'Blossom', 'Heartwood', 'Canopy', 'Vault', 'NU5', 'NU6']
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
    for k, v in cfg.items():          # live pending sections (yellowback, kogany)
        base.setdefault(k, {}).update(v)
    return base, notes


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


def render_toml(config, notes=()):
    """The ``zakurad.toml`` text: scalar keys first, then each sub-table by its dotted header;
    ``notes`` become leading comments (the pending and ignored ycashd arguments)."""
    out = ['# zakurad.toml generated by qa/rpc-tests/test_framework/kogany.py (mixed-line harness)']
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
# follows Ycash regtest: the backend line below becomes the zakurad start.

YEWD_WALLET_ARGS = ('-keypool', '-exportdir', '-paytxfee', '-mintxfee', '-txconfirmtarget', '-walletnotify',
                    '-spendzeroconfchange', '-rescan', '-wallet')
YEWD_BACKENDS = {}        # node index -> the backend's subprocess.Popen


def yewd_rpc_port(k):
    """Reserved (a yewd that listens beside, not instead of, a node); unused by the pair mode."""
    assert 0 <= k <= MAX_NODES
    return PORT_MIN + 5 * PORT_RANGE + k + _offset()


def yewd_backend_rpc_port(i):
    assert 0 <= i <= MAX_NODES
    return PORT_MIN + 6 * PORT_RANGE + i + _offset()


def split_yewd_args(args):
    """(backend args, yewd wallet args) from one node's arguments; -mocktime goes to both."""
    backend, wallet = [], []
    for a in args:
        name = a.split('=', 1)[0]
        if name == '-mocktime':
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
    ``assert_start_raises_init_error`` still works), then yewd i.  Returns yewd's Popen."""
    backend_dir = os.path.join(datadir, 'backend')
    os.makedirs(backend_dir, exist_ok=True)
    with open(os.path.join(backend_dir, 'ycash.conf'), 'w', encoding='utf8') as f:
        f.write('regtest=1\nshowmetrics=0\nlistenonion=0\nport=%d\nrpcport=%d\n'
                % (p2p_port(i), yewd_backend_rpc_port(i)))
    b_argv, y_argv = yewd_pair_argv(os.environ['YEWD_BIN'], ycashd_bin, datadir, i, args)
    backend = subprocess.Popen(b_argv, stderr=stderr)
    YEWD_BACKENDS[i] = backend
    cookie = os.path.join(backend_dir, 'regtest', '.cookie')
    rpc = KoganyRPC('http://127.0.0.1:%d/' % yewd_backend_rpc_port(i), cookie=cookie)
    deadline = time.time() + timeout
    while True:
        if backend.poll() is not None:
            YEWD_BACKENDS.pop(i, None)
            raise Exception('%s node %d exited with status %i during initialization'
                            % (util.zcashd_binary(), i, backend.returncode))
        had_cookie = os.path.exists(cookie)
        try:
            rpc.getblockcount()
            break
        except JSONRPCException as e:
            if not _backend_warming_up(e, had_cookie):
                raise
        except OSError:
            pass
        assert time.time() < deadline, 'yewd backend %d did not come up' % i
        time.sleep(0.25)
    # yewd reports ignored options on stderr; rpc-tests.py fails a script with any stderr output,
    # so yewd's own stream goes to node<i>/yewd.log unless the caller captures stderr itself
    out = stderr if stderr is not None else open(os.path.join(datadir, 'yewd.log'), 'ab')
    return subprocess.Popen(y_argv, stdout=out if stderr is None else None, stderr=out)


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
    """One ``zakurad`` follower process in ``tmpdir/kogany<k>``."""

    def __init__(self, k, tmpdir, binary, extra_args=()):
        self.k = k
        self.binary = binary
        self.extra_args = list(extra_args)
        self.datadir = os.path.join(tmpdir, 'kogany%d' % k)
        self.conf = os.path.join(self.datadir, 'zakurad.toml')
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
        log = open(os.path.join(self.datadir, 'zakurad.log'), 'ab')
        argv = [self.binary, '-c', self.conf] + self.extra_args + ['start']
        self.process = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)
        deadline = time.time() + timeout
        while True:
            if self.process.poll() is not None:
                raise AssertionError('kogany %d (%s) exited with %s during start; see %s'
                                     % (self.k, self.binary, self.process.returncode,
                                        os.path.join(self.datadir, 'zakurad.log')))
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
SCRIPT_PEER = {
    'vault_activation_restart': 3,
    'vault_primitive': 0,
}


class MixedLine:
    """The run's kogany followers and the cross-line assertions.  ``from_env`` returns an inert
    instance when ``KOGANY_BIN`` is unset: every method is then a no-op."""

    def __init__(self, binary=None, followers=1, peer=None, strict=False, mempool=False,
                 sync_timeout=120, extra_args=(), yewd=None, mirror_invalidate=False,
                 tx_timeout=10):
        self.binary = binary
        self.n_followers = followers
        self.peer = peer
        self.strict = strict
        self.mempool = mempool
        self.sync_timeout = sync_timeout
        self.extra_args = list(extra_args)
        self.yewd = yewd
        self.connect_settle = 5.0
        self.mirror_invalidate = mirror_invalidate
        self.tx_timeout = tx_timeout
        self.mirrored = {}
        self.followers = []
        self.tmpdir = None
        self.peer_args = None
        self._notes = set()
        self.unmapped = []
        self.kogany_unmapped = []
        self.offered = set()
        self.script_invalidates = False   # the script's source calls invalidateblock/reconsiderblock
        self.stats = {'sync_points': 0, 'statehash_vault': 0, 'statehash_yed': 0, 'mempool_points': 0,
                      'verdicts': 0, 'verdict_classes': 0}

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
                   tx_timeout=float(env.get('KOGANY_TX_TIMEOUT', '10')))

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
        if not self.enabled or i != self.peer:
            return
        self.peer_args = list(args)
        for f in self.followers:
            config, notes = self._config_for(f)
            if config != f.config:
                f.stop()
                f.write_config(config, notes)
                f.start()
            self._connect(proxy, f)

    def attach(self, test):
        """Called after ``setup_network``: start the followers against the peer and wait for them
        to reach its tip."""
        if not self.enabled:
            return
        if not test.nodes and not getattr(test, 'num_nodes', 0):
            # a run without nodes (create_cache.py, which rpc-tests.py runs first under -j > 1):
            # nothing to follow
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
        for f in self.followers:
            f.stop()
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
        return zakurad_config(self.peer_args, f.k, [p2p_port(self.peer)], f.datadir)

    def _connect(self, proxy, f, settle=None):
        """One connection per follower: the follower dials the peer (``initial_testnet_peers``);
        only when it still has no peer after ``settle`` seconds (a peer restart, say) does the peer
        ``addnode <follower> onetry``.  Never two: a script that counts ``getpeerinfo`` sees one
        extra peer per follower, not two (recorded)."""
        addr = '127.0.0.1:%d' % kogany_p2p_port(f.k)
        deadline = time.time() + (self.connect_settle if settle is None else settle)
        while True:
            try:
                if f.rpc.getpeerinfo():
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
        ref = self._peer_conn(conns)
        if ref is None:
            return
        self.stats['sync_points'] += 1
        tip = ref.getbestblockhash()
        for f in self.followers:
            if not f.alive():
                raise AssertionError('kogany %d exited (see %s/zakurad.log)' % (f.k, f.datadir))
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
                if time.time() > deadline:
                    hint = self.invalidate_hint()
                    raise AssertionError('kogany %d did not reach the peer tip %s (height %d) %s: at %s%s'
                                         % (f.k, tip, ref.getblockcount(), label, got,
                                            ('; ' + hint) if hint else ''))
                time.sleep(0.2)
            self._compare_statehash(ref, f, label)

    def _mirror(self, ref, f, got):
        """KOGANY_MIRROR_INVALIDATE=1: a script's ``invalidateblock`` / ``reconsiderblock`` reach
        only the ycashd node it calls.  When the follower's tip is a tip the peer holds as
        ``invalid`` (getchaintips), invalidate on the follower the first block of that branch off
        the peer's active chain; reconsider it once the peer's active chain contains it again.
        Opt-in: getchaintips cannot tell a script's invalidateblock from a validation reject, so
        mirroring could hide a block kogany wrongly accepts (verdict checks still run)."""
        for h in list(self.mirrored.get(f.k, [])):
            try:
                if ref.getblock(h)['confirmations'] >= 0:
                    f.rpc.reconsiderblock(h)
                    self.mirrored[f.k].remove(h)
                    print('kogany %d: mirrored reconsiderblock %s' % (f.k, h[:16]))
            except JSONRPCException:
                pass
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
        ref = self._peer_conn(conns)
        if ref is None:
            return
        self.stats['mempool_points'] += 1
        want = set(ref.getrawmempool())
        for f in self.followers:
            deadline = time.time() + self.sync_timeout
            while True:
                got = set(f.rpc.getrawmempool())
                if got == want:
                    break
                if time.time() > deadline:
                    raise AssertionError('kogany %d mempool differs: only ycashd %s, only kogany %s'
                                         % (f.k, sorted(want - got), sorted(got - want)))
                time.sleep(0.25)

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

    def offer_block(self, block_hex, cxx_result, label=''):
        """Submit ``block_hex`` to every follower and assert the verdict class equals ycashd's
        ``cxx_result`` (its ``submitblock`` result).  Returns the classes, or None when inert."""
        if not self.active:
            return None
        raw = bytes.fromhex(block_hex)
        prev = raw[4:36][::-1].hex()
        cxx = classify_cxx_block(cxx_result)
        out = []
        for f in self.followers:
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

    def offer_tx(self, tx_hex, cxx_error, label=''):
        """The transaction path (``KOGANY_MEMPOOL=1``): ``cxx_error`` is None when ycashd accepted
        ``tx_hex``, else its ``JSONRPCException``."""
        if not (self.active and self.mempool):
            return None
        cxx = classify_cxx_tx(cxx_error, self.unmapped)
        out = []
        for f in self.followers:
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
        if not self.active or blockhash in self.offered:
            return
        self.offered.add(blockhash)
        try:
            block_hex = node.getblock(blockhash, 0)
        except JSONRPCException:
            self.note('a rejected block without data on the ycashd node; verdict skipped')
            return
        self.offer_block(block_hex, 'invalid', 'assert_rejected %s' % blockhash)

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
    atexit.register(mixed.stop)


def describe():
    """The key table, for ``kogany_mixed_smoke.py --describe`` and review."""
    lines = ['ycashd argument -> zakurad.toml (status)']
    for arg, status, key, note in ZAKURAD_KEY_TABLE:
        lines.append('  %-38s %-14s %s%s' % (arg, status, key or '-', ('  # ' + note) if note else ''))
    lines.append('branch id -> activation_heights key (status)')
    for b, (key, status, note) in sorted(NU_BRANCH_TABLE.items()):
        lines.append('  %08x  %-10s %-14s %s' % (b, key, status, note))
    return '\n'.join(lines)


if __name__ == '__main__':
    print(describe())
    sys.exit(0)
