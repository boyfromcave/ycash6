#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
#
# Review (q/fees, reviewer B's reproduction): the wallet's own committed transactions survive a restart even when
# the price-dependent fee cap they were built under has moved. ReacceptWalletTransactions skips the -maxtxfee
# absurd-fee check for a post-quantum or Yellowback transaction whose fee is within the absolute ceiling
# -yellowbackmaxtxfee (policy.h OwnTxFeeWithinCeiling):
#
#   - a P2PKH-funded mint (no PQ input; size-priced since review A-2) paying above -maxtxfee is still in the
#     node's own mempool after a restart (it was dropped as "absurd" before the fix);
#   - a plain post-quantum send committed under a raised dollar cap (above -maxtxfee) is still in the mempool after
#     a restart whose cap is back at -maxtxfee (the cap moved, as under a halt or a price rise);
#   - -yellowbackmaxtxfee below the flat fees is refused at init.
#
#     BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/yellowback_fees_reaccept.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>

from decimal import Decimal

from test_framework.util import assert_equal, assert_greater_than, assert_start_raises_init_error, stop_node
from test_framework.yellowback_util import COIN, POOLS, REF_LAG, USER, YellowbackTestFramework
from test_framework.yellowback_attest import ArmedModeMixin

PRICE = Decimal('2500')
LOW_MAXTXFEE = '-maxtxfee=0.00005'   # 5,000 zat: stands in for 0.1 YEC at a realistic $0.30/YEC price


class YellowbackFeesReacceptTest(ArmedModeMixin, YellowbackTestFramework):

    def fee_of(self, node, txid):
        raw = node.getrawtransaction(txid, 1)
        spent = sum(node.getrawtransaction(v['txid'], 1)['vout'][v['vout']]['valueZat'] for v in raw['vin'])
        return spent - sum(o['valueZat'] for o in raw['vout'])

    def run_test(self):
        user = self.nodes[USER]
        self.activate(POOLS, quote_usd=PRICE)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        addr = user.getnewaddress()
        for i in POOLS:
            bal = self.nodes[i].getbalance()
            if bal > 2:
                self.nodes[i].sendtoaddress(addr, bal - 1)
        self.sync_all()
        self.mine(POOLS[0])

        print('a P2PKH-funded mint above -maxtxfee survives a restart in the own mempool')
        user = self.restart(USER, [LOW_MAXTXFEE])
        self.sync_all(blocks_only=True)
        m = self.mint(user, 10000, 48)
        fee = self.fee_of(user, m['txid'])
        assert_greater_than(fee, 5000)
        assert m['txid'] in user.getrawmempool()
        user = self.restart(USER, [LOW_MAXTXFEE])
        assert m['txid'] in user.getrawmempool(), 'the wallet dropped its own mint at reaccept'
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(user.yed_getvault(m['txid'])['status'], 'ACTIVE')

        print('a plain PQ send committed under a raised cap survives a restart whose cap is back at -maxtxfee')
        # $50/KB at $2,500 = 0.02 YEC/KB: an SLH-DSA spend (~8.9 KB) is ~0.18 YEC, above -maxtxfee (0.1), within $1,000
        user = self.restart(USER, ['-pqfeeusdperkb=50', '-yellowbackmaxtxfeeusd=1000'])
        self.sync_all(blocks_only=True)
        pq_addr = user.getnewaddress('', 'pqslh')
        user.sendtoaddress(pq_addr, 5)
        self.sync_all()
        self.mine(POOLS[2])
        locked = [{'txid': u['txid'], 'vout': u['vout']} for u in user.listunspent(0) if u.get('address') != pq_addr]
        user.lockunspent(False, locked)
        txid = user.sendtoaddress(user.getnewaddress(), 1)
        user.lockunspent(True, locked)
        fee = self.fee_of(user, txid)
        assert_greater_than(fee, 10000000)                       # above the default -maxtxfee
        assert_greater_than(10 * COIN, fee)                     # within the 10-YEC ceiling
        assert txid in user.getrawmempool()
        user = self.restart(USER, [])                            # the cap is max(0.1 YEC, $2 at $2,500) = 0.1 YEC now
        assert_equal(user.yed_getinfo()['params']['fees']['network']['yellowback']['maxTxFeeZat'], 10000000)
        assert txid in user.getrawmempool(), 'the wallet dropped its own PQ send at reaccept'
        self.sync_all()
        self.mine(POOLS[0])
        assert_greater_than(user.gettransaction(txid)['confirmations'], 0)

        print('-yellowbackmaxtxfee below the flat fees is refused at init')
        stop_node(self.nodes[USER], USER)
        self.nodes[USER] = None
        assert_start_raises_init_error(USER, self.options.tmpdir, self.node_args(USER, ['-yellowbackmaxtxfee=0.00009']),
                                       '-yellowbackmaxtxfee must be at least')
        user = self.restart(USER, [])
        self.sync_all(blocks_only=True)


if __name__ == '__main__':
    YellowbackFeesReacceptTest().main()
