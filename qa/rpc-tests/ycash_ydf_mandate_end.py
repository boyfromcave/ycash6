#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The YDF mandate's end as a consensus boundary (beta3 item 5), the same on both node lines.

Item 5 gives the fast testnet profile its own nYdfMandateEndHeight (src/chainparams.cpp
TESTNET_FAST_YDF_MANDATE_END_HEIGHT). A functional test cannot select that profile on a chain it can mine
(it is testnet, with testnet's genesis and history), so this script exercises the same rule, the same code
path (ContextualCheckBlock and the miner's SetFoundersRewardAndGetMinerValue read GetYdfMandateEndHeight()
whatever the network), at regtest's end height. The fast profile's value itself is checked by the unit test
testnet_params_tests/testnet_ydf_mandate_end_heights.

The end height E is read from the node, not hard-coded: the first height whose getblocksubsidy reports no
founders' share on a node with the default -ydf (0, beta3 item 4).

- At E - 1 a block whose coinbase lacks the fund output is rejected (cb-no-founders-reward);
  the node's own template, which pays it, is accepted and both nodes follow it.
- At E the node's own miner (default -ydf) mines a block with no fund output, and both nodes accept it.
- At E + 1 a block that still pays the fund output is accepted: the rule is "required below E", never
  "forbidden from E".

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/ycash_ydf_mandate_end.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>

One file on both C++ lines (ycash-dd: BITCOIND=, ycash6: ZCASHD=).
"""

import copy
from decimal import Decimal

from test_framework.mininode import CTxOut
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes_bi,
    start_nodes,
    sync_blocks,
)
from test_framework.yellowback_util import YCASH_UPGRADE_ARGS, mine_block_raw, template_coinbase

COIN = 100000000


def zat(x):
    return int(Decimal(str(x)) * COIN)


class YdfMandateEndTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True   # v4.5.0 harness
        self.cache_behavior = 'clean'   # 6.20.0 harness (each harness ignores the other's)

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 extra_args=[list(YCASH_UPGRADE_ARGS)] * self.num_nodes)
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def mandate_end(self):
        """The first height with no founders' share at the default -ydf, from the node's own parameters."""
        n = self.nodes[0]
        for h in range(1, 1000):
            if zat(n.getblocksubsidy(h)['founders']) == 0:
                assert h > 2, 'the mandate must cover at least the first two blocks for this test'
                return h
        raise AssertionError('no mandate end below height 1000')

    def submit(self, coinbase, gbt):
        coinbase.rehash()
        result, blockhash = mine_block_raw(self.nodes[0], [], coinbase=coinbase, gbt=gbt)
        return result, blockhash

    def tips(self):
        return [n.getbestblockhash() for n in self.nodes]

    def run_test(self):
        n0, n1 = self.nodes
        end = self.mandate_end()
        print('mandate end height (from getblocksubsidy): %d' % end)

        # The node's own blocks up to E - 2 (each pays the fund, ycash_ydf_default.py checks the amounts).
        n0.generate(end - 2)
        sync_blocks(self.nodes)
        assert_equal(n0.getblockcount(), end - 2)

        # ---- E - 1: the fund output is still required ---------------------------------------------------------
        cb, gbt = template_coinbase(n0)
        assert_equal(gbt['height'], end - 1)
        subsidy = zat(n0.getblocksubsidy(end - 1)['miner']) + zat(n0.getblocksubsidy(end - 1)['founders'])
        assert_equal(len(cb.vout), 2)
        assert_equal(cb.vout[1].nValue, subsidy // 20)
        fund_script = cb.vout[1].scriptPubKey

        without = copy.deepcopy(cb)
        del without.vout[1]                      # the miner keeps 95 %: no excess, only the missing output
        result, _ = self.submit(without, gbt)
        assert_equal(result, 'cb-no-founders-reward')
        assert_equal(n0.getblockcount(), end - 2)

        result, blockhash = self.submit(cb, gbt)
        assert result in (None, 'duplicate'), result
        sync_blocks(self.nodes)
        assert_equal(self.tips(), [blockhash, blockhash])
        print('height %d: without the fund output rejected, with it accepted' % (end - 1))

        # ---- E: the miner's own block (default -ydf) has no fund output and is valid ----------------------
        [h] = n0.generate(1)
        sync_blocks(self.nodes)
        assert_equal(self.tips(), [h, h])
        blk = n1.getblock(h, 2)
        assert_equal(blk['height'], end)
        assert_equal(len(blk['tx'][0]['vout']), 1)
        subsidy = zat(n0.getblocksubsidy(end)['miner'])
        assert_equal(zat(blk['tx'][0]['vout'][0]['value']), subsidy)
        print('height %d: the miner pays no fund output, accepted by both nodes' % end)

        # ---- E + 1: a block that still pays the fund output is valid --------------------------------------------
        cb, gbt = template_coinbase(n0)
        assert_equal(gbt['height'], end + 1)
        assert_equal(len(cb.vout), 1)
        donation = cb.vout[0].nValue // 20
        cb.vout[0].nValue -= donation
        cb.vout.append(CTxOut(donation, fund_script))
        result, blockhash = self.submit(cb, gbt)
        assert result in (None, 'duplicate'), result
        sync_blocks(self.nodes)
        assert_equal(self.tips(), [blockhash, blockhash])
        assert_equal(len(n1.getblock(blockhash, 2)['tx'][0]['vout']), 2)
        print('height %d: a block that still pays the fund output accepted by both nodes' % (end + 1))


if __name__ == '__main__':
    YdfMandateEndTest().main()
