#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
A stand-in "zakurad" for testing the mixed-line harness itself (test_framework/kogany.py) before
kogany can follow Ycash regtest (W1).  Point KOGANY_BIN at this file: it takes zakurad's command
line (``-c <zakurad.toml> [args] start``), reads the generated config, and execs a ycashd
(``$ZCASHD``) configured from it -- the follower's own P2P/RPC ports, cookie auth in the config's
``rpc.cookie_dir``, ``initial_testnet_peers`` as ``-addnode``, and each activation height back
to its ``-nuparams``.  Run it with ``KOGANY_LIVE=W1-Y1,W2-b,W5-f,W5-c,W3-c`` so the pending rows
(the Ycash and Vault heights, the attestor set) are emitted: real zakurad refuses those keys
until the chunks land, the stand-in needs them.

It proves the harness paths -- process start/stop, the JSON-RPC client, sync points, state-hash
and verdict-class comparison, restart on a peer's changed arguments -- never kogany.  Needs
Python 3.11+ (tomllib).
"""

import os
import sys

try:
    import tomllib
except ImportError:            # pragma: no cover
    sys.exit('kogany_standin.py needs Python 3.11+ (tomllib)')

BRANCH_OF = {
    'Overwinter': '5ba81b19', 'Sapling': '76b809bb', 'Ycash': '374d694f', 'Blossom': '8e471bd6',
    'Heartwood': '66314da3', 'Canopy': '19bd2d2f', 'Vault': '6d5b7a31',
}


def main(argv):
    if '-c' not in argv or argv[-1] != 'start':
        sys.exit('usage: kogany_standin.py -c <zakurad.toml> [args] start')
    conf = argv[argv.index('-c') + 1]
    with open(conf, 'rb') as f:
        cfg = tomllib.load(f)
    root = os.path.join(os.path.dirname(os.path.abspath(conf)), 'standin')
    os.makedirs(root, exist_ok=True)
    net, rpc = cfg['network'], cfg['rpc']
    p2p = net['listen_addr'].rsplit(':', 1)[1]
    rpcport = rpc['listen_addr'].rsplit(':', 1)[1]
    with open(os.path.join(root, 'ycash.conf'), 'w') as f:
        f.write('regtest=1\nshowmetrics=0\nlistenonion=0\nport=%s\nrpcport=%s\n' % (p2p, rpcport))
    os.makedirs(rpc['cookie_dir'], exist_ok=True)
    args = [os.getenv('ZCASHD', 'ycashd'), '-datadir=' + root, '-discover=0', '-keypool=1',
            '-rpccookiefile=' + os.path.join(rpc['cookie_dir'], '.cookie'),
            '-i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025']
    for nu, h in net['network']['params']['activation_heights'].items():
        if nu not in BRANCH_OF:
            sys.exit('kogany_standin.py: no branch id for %s' % nu)
        args.append('-nuparams=%s:%d' % (BRANCH_OF[nu], h))
    for peer in net.get('initial_testnet_peers', []):
        args.append('-addnode=' + peer)
    yb = cfg.get('yellowback', {})
    if 'attestor_set' in yb:
        args.append('-yellowbackattestorset=%s' % yb['attestor_set'])
    if 'sigma_ref' in yb:
        args.append('-yellowbacksigmaref=%d' % yb['sigma_ref'])
    if 'pq_falcon_height' in cfg.get('kogany', {}):
        args.append('-pqfalconheight=%d' % cfg['kogany']['pq_falcon_height'])
    os.execv(args[0], args)


if __name__ == '__main__':
    main(sys.argv[1:])
