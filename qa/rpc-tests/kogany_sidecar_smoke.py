#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Smoke test of the ycash6 test rig (kogany plan W9-a; K-3 as amended): KOGANY_SIDECAR=1 with
KOGANY_BIN makes every node a kogany zakurad plus a ycashd -connect'ed to it with -listen=0
(test_framework/kogany.py "The ycash6 test rig").  The scripts talk to the ycashd wallets while
every block and transaction between nodes passes through a kogany:

    KOGANY_SIDECAR=1 KOGANY_BIN=$WS/wt/.bin/kc-w9-sidecar/zakurad KOGANY_STRICT=1 \\
        ZCASHD=$BIN/ycashd ../../../.venv/bin/python -u kogany_sidecar_smoke.py --srcdir=$BIN

It checks the rig's topology (each ycashd's peers are koganys only, each kogany has its ycashd as
an inbound peer), a transparent wallet payment relayed through the koganys (mempools on both
lines, then the block), and a YED wallet mint and send (the module's state hashes equal at every
sync point).  Without KOGANY_SIDECAR it runs the same wallet flow on plain ycashd nodes.  Not in
any manifest (a harness smoke, like kogany_mixed_smoke).
"""

import time
from decimal import Decimal

from test_framework import kogany
from test_framework.util import assert_equal, p2p_port
from test_framework.yellowback_attest import wallet_mint
from test_framework.yellowback_util import POOLS, REF_LAG, STOCK, USER, YellowbackTestFramework


class KoganySidecarSmokeTest(YellowbackTestFramework):

    def check_topology(self):
        mixed = kogany.current()
        node_ports = {p2p_port(j): j for j in range(len(self.nodes))}
        for i, node in enumerate(self.nodes):
            peers = node.getpeerinfo()
            ports = sorted(int(p['addr'].rsplit(':', 1)[1]) for p in peers)
            assert all(not p['inbound'] for p in peers), 'ycashd %d has an inbound peer: %s' % (i, peers)
            assert all(port in node_ports for port in ports), 'ycashd %d peers off the rig: %s' % (i, ports)
            assert p2p_port(i) in ports, 'ycashd %d is not connected to its kogany' % i
            k = kogany.SIDECAR_NODES[i]
            assert k.alive()
            assert len(k.rpc.getpeerinfo()) >= 1, 'kogany %d has no peer' % i
            print('rig: ycashd %d -> koganys %s' % (i, [node_ports[p] for p in ports]))
        assert mixed.sidecar and mixed.active

    def mempools(self, txid, timeout=60):
        """Every ycashd holds ``txid`` (it reached them only through koganys), and every kogany's
        mempool takes it within ``timeout`` (Zakura downloads an advertised transaction on its own
        schedule, so a kogany may trail the ycashds it relayed to)."""
        for i, node in enumerate(self.nodes):
            assert txid in node.getrawmempool(), 'ycashd %d lacks %s' % (i, txid)
        if not kogany.sidecar_enabled():
            return
        deadline = time.time() + timeout
        for i in range(len(self.nodes)):
            k = kogany.SIDECAR_NODES[i]
            while txid not in k.rpc.getrawmempool():
                assert time.time() < deadline, 'kogany %d lacks %s' % (i, txid)
                time.sleep(0.25)

    def run_test(self):
        rig = kogany.sidecar_enabled()
        print('test rig: %s' % rig)
        if rig:
            self.check_topology()

        user, stock = self.nodes[USER], self.nodes[STOCK]
        addr = stock.getnewaddress()
        txid = user.sendtoaddress(addr, 2)
        self.sync_all()                                  # mempools converge through the koganys
        self.mempools(txid)
        self.mine(POOLS[0])
        assert_equal(stock.getreceivedbyaddress(addr), Decimal('2'))
        print('wallet: %s paid 2 YEC user -> stock through the rig' % txid[:16])

        self.activate(quote_usd=50)
        self.mine(POOLS[0], REF_LAG + 1)
        mint = wallet_mint(self, user, 10000, 48)
        self.sync_all()
        self.mempools(mint['txid'])
        self.mine(POOLS[1])
        assert_equal(user.yed_getvault(mint['txid'])['status'], 'ACTIVE')
        assert_equal(user.yed_getbalance()['confirmedCents'], 10000)
        send = user.yed_send(user.yed_getnewaddress(), 4000)
        assert_equal(send['changeCents'], 6000)
        self.sync_all()
        self.mine(POOLS[2])
        self.checkpoint('sidecar smoke')
        print('YED: minted 100.00 YED (%s), sent 40.00 YED to self' % mint['txid'][:16])

        if rig:
            self.check_topology()
            stats = kogany.current().stats
            print('rig stats: %s' % stats)
            assert stats['sync_points'] > 0 and stats['statehash_yed'] > 0, stats


if __name__ == '__main__':
    KoganySidecarSmokeTest().main()
