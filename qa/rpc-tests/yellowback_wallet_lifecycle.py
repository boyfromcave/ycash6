#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Transparent v2 wallet lifecycle: mint, send, and owner-path redeem; then the bound on
concurrent wait=true carrier waits (audit C-2)."""

import threading
import time

from test_framework.util import assert_equal, get_rpc_proxy, rpc_url
from test_framework.yellowback_attest import wallet_mint
from test_framework.yellowback_util import (
    POOLS,
    REF_LAG,
    YellowbackTestFramework,
)


class YellowbackWalletLifecycleTest(YellowbackTestFramework):

    def run_test(self):
        nodes = self.nodes
        self.activate(quote_usd=50)
        self.mine(POOLS[0], REF_LAG + 1)

        mint = wallet_mint(self, nodes[0], 10000, 48)   # v3: the carrier step (W7)
        assert_equal(mint['termClass'], 'A')
        assert_equal(mint['fundedFrom'], 'transparent')
        assert mint['feeZat'] > 0
        assert mint['payee'] in self.pool_addresses
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(nodes[0].yed_getvault(mint['txid'])['status'], 'ACTIVE')
        assert_equal(nodes[0].yed_getbalance()['confirmedCents'], 10000)

        send = nodes[0].yed_send(nodes[0].yed_getnewaddress(), 4000)
        assert_equal(send['changeCents'], 6000)
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(nodes[0].yed_getbalance()['confirmedCents'], 10000)

        lock_height = mint['lockHeight']
        blocks = lock_height - nodes[0].getblockcount()
        if blocks > 0:
            self.mine_round_robin(POOLS, blocks)
        redeem = nodes[0].yed_redeem(mint['txid'])
        assert_equal(redeem['burnedCents'], 10000)
        assert redeem['feeZat'] > 0
        assert redeem['payee'] in self.pool_addresses
        self.sync_all()
        self.mine(POOLS[2])
        assert_equal(nodes[0].yed_getvault(mint['txid'])['status'], 'CLOSED')
        assert_equal(nodes[0].yed_getbalance()['confirmedCents'], 0)
        self.checkpoint('transparent wallet lifecycle')

        print('audit C-2: at most half of -rpcthreads (4 -> 2) wait=true calls wait for a carrier at once')
        before = set(nodes[0].getrawmempool())
        results, errors = [], []

        def mint_waiting():
            proxy = get_rpc_proxy(rpc_url(0), 0, timeout=300)     # a private connection per thread
            try:
                results.append(proxy.yed_mint(10000, 48, '', '', True))
            except Exception as e:                                  # surfaced below
                errors.append(str(e))
        threads = [threading.Thread(target=mint_waiting, daemon=True) for _ in range(2)]
        for t in threads:
            t.start()
        deadline = time.time() + 60
        while len(set(nodes[0].getrawmempool()) - before) < 2 and time.time() < deadline:
            time.sleep(0.1)
        assert_equal(len(set(nodes[0].getrawmempool()) - before), 2)   # both carriers are out, both calls are waiting
        try:
            nodes[0].yed_mint(10000, 48, '', '', True)
            raise AssertionError('a third wait=true call was not refused')
        except Exception as e:
            assert 'carrier-wait-busy' in str(e), str(e)
        assert_equal(len(set(nodes[0].getrawmempool()) - before), 2)   # the refusal built nothing
        pend = nodes[0].yed_mint(10000, 48, '', '', False)             # wait=false takes no slot
        assert_equal(pend['pending'], True)
        self.sync_all()
        self.mine(POOLS[0])                                            # the carriers confirm; the waiters complete
        for t in threads:
            t.join(timeout=120)
        assert_equal(errors, [])
        assert_equal([r['pending'] for r in results], [False, False])
        self.sync_all()
        self.mine(POOLS[1])
        for r in results:
            assert_equal(nodes[0].yed_getvault(r['txid'])['status'], 'ACTIVE')
        self.checkpoint('carrier wait slots')


if __name__ == '__main__':
    YellowbackWalletLifecycleTest().main()