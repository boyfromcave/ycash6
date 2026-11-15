#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The development-fund (YDF) donation is opt-in: -ydf defaults to 0 (beta3 item 4), the same on both node lines.

Regtest with the Ycash upgrade at height 1; the YDF mandate ends at 5 (src/chainparams.cpp, regtest
nYdfMandateEndHeight). Node 0 runs with the default, node 1 with -ydf=5.

- The mandate period is unchanged: blocks 1 to 4, mined by either node, carry the fund output of exactly
  subsidy / 20 (an output to an address the miner's wallet does not own), and getblocksubsidy reports 5 % on both
  nodes, whatever -ydf says.
- Past the mandate, node 0 (default) mines a coinbase with one output that pays the subsidy plus every fee in full;
  getblocksubsidy reports founders 0 on it.
- Past the mandate, node 1 (-ydf=5) pays the fund subsidy * 5 / 100 and itself the rest of the subsidy plus every
  fee; getblocksubsidy reports 5 % on it.
- Each node accepts the other's blocks (sync_blocks): validity does not depend on -ydf.

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/ycash_ydf_default.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>

One file on both C++ lines (ycash-dd: BITCOIND=, ycash6: ZCASHD=).
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes_bi,
    start_nodes,
    sync_blocks,
    sync_mempools,
)
from test_framework.yellowback_util import YCASH_UPGRADE_ARGS

REGTEST_YDF_MANDATE_END = 5                                        # src/chainparams.cpp regtest nYdfMandateEndHeight
COIN = 100000000


def zat(x):
    return int(Decimal(str(x)) * COIN)


def addresses(vout):
    spk = vout['scriptPubKey']
    if 'addresses' in spk:
        return spk['addresses']
    return [spk['address']] if 'address' in spk else []


class YdfDefaultTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True   # v4.5.0 harness
        self.cache_behavior = 'clean'   # 6.20.0 harness (each harness ignores the other's)

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, extra_args=[
            list(YCASH_UPGRADE_ARGS),
            list(YCASH_UPGRADE_ARGS) + ['-ydf=5'],
        ])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def subsidy(self, height):
        """The block subsidy in zat (miner + founders, which does not depend on -ydf), and each node's founders."""
        rs = [n.getblocksubsidy(height) for n in self.nodes]
        for r in rs:
            assert not r.get('fundingstreams'), r   # Ycash has no funding streams
        totals = set(zat(r['miner']) + zat(r['founders']) for r in rs)
        assert_equal(len(totals), 1)
        return totals.pop(), [zat(r['founders']) for r in rs]

    def mine(self, i, n=1):
        """Node i mines n blocks; both nodes must accept them. The coinbases, oldest first."""
        hashes = self.nodes[i].generate(n)
        sync_blocks(self.nodes)
        out = []
        for h in hashes:
            for node in self.nodes:
                assert_equal(node.getbestblockhash(), hashes[-1])
            blk = self.nodes[(i + 1) % 2].getblock(h, 2)   # read back on the other node
            out.append((blk['height'], blk['tx'][0]))
        return out

    def split(self, i, cb):
        """(fund output in zat or None, list of node i's own outputs in zat): an output to an address node i's
        wallet does not own is the fund's (the YDF address rotates, src/chainparams.cpp vYcashFoundersRewardAddress)."""
        fund, rest = None, []
        for v in cb['vout']:
            amount = int(v['valueZat']) if 'valueZat' in v else zat(v['value'])
            [addr] = addresses(v)
            if not self.nodes[i].validateaddress(addr)['ismine']:
                assert fund is None, cb
                fund = amount
            else:
                rest.append(amount)
        return fund, rest

    def run_test(self):
        # ---- the mandate period: 5 % whatever -ydf says ----------------------------------------------------------
        for i in (0, 0, 1, 1):
            [(height, cb)] = self.mine(i)
            assert height < REGTEST_YDF_MANDATE_END
            total, founders = self.subsidy(height)
            assert_equal(founders, [total // 20, total // 20])
            fund, rest = self.split(i, cb)
            assert_equal(fund, total // 20)
            assert_equal(rest, [total - total // 20])
            print('mandate: block %d by node %d pays the fund %d of %d' % (height, i, fund, total))

        # ---- past the mandate: getblocksubsidy follows each node's -ydf -----------------------------------------
        h = REGTEST_YDF_MANDATE_END
        total, founders = self.subsidy(h)
        assert_equal(founders, [0, total * 5 // 100])

        # node 0 (default): no fund output; past the mandate on every block it mines
        cbs = self.mine(0, 101)
        for height, cb in cbs:
            assert height >= REGTEST_YDF_MANDATE_END
            total, _ = self.subsidy(height)
            assert_equal(self.split(0, cb), (None, [total]))

        # ---- fees: each miner keeps every fee --------------------------------------------------------------------
        for i in (0, 1):
            txid = self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 1)
            sync_mempools(self.nodes)
            fee = zat(self.nodes[i].getrawmempool(True)[txid]['fee'])
            assert fee > 0
            [(height, cb)] = self.mine(i)
            total, founders = self.subsidy(height)
            fund, rest = self.split(i, cb)
            if i == 0:
                assert_equal((fund, rest), (None, [total + fee]))
                assert_equal(founders[0], 0)
            else:
                assert_equal(fund, total * 5 // 100)
                assert_equal(rest, [total - total * 5 // 100 + fee])
                assert_equal(founders[1], total * 5 // 100)
            assert_equal(self.nodes[i].getrawmempool(), [])
            print('past mandate: block %d by node %d pays the fund %s, the miner %s (fee %d)' % (height, i, fund, rest, fee))


if __name__ == '__main__':
    YdfDefaultTest().main()
