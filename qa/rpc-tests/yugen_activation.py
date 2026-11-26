#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Yugen activation on regtest (doc/yugen-node.md: activation).

- -nuparams=59474e30:<h> without a Vault height at or below h is refused at startup.
- With Vault at 16 and Yugen at 32: yugen_getinfo reports rpcversion 12, branch id 0x59474e30 and
  "active" for the next block from height 31; getblockchaininfo shows Yugen pending, then active,
  and the chain tip's consensus branch is 59474e30 from height 32.
"""


from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID,
    assert_equal,
    assert_start_raises_init_error,
    nuparams,
    start_nodes,
    stop_nodes,
    wait_bitcoinds,
)
from test_framework.yellowback_util import YCASH_UPGRADE_ARGS, YELLOWBACK_RPC_VERSION
from test_framework.yugen_util import yugen_helper

YUGEN_BRANCH_ID = 0x59474E30
VAULT_H = 16
YUGEN_H = 32
# yugen-leafverify as the build installs it in src/; override with YUGEN_LEAFVERIFY.
VERIFIER = '-yugenverifier=' + yugen_helper('YUGEN_LEAFVERIFY', 'yugen-leafverify')


class YugenActivationTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_network(self, split=False):
        self.args = list(YCASH_UPGRADE_ARGS) + [nuparams(VAULT_BRANCH_ID, VAULT_H), nuparams(YUGEN_BRANCH_ID, YUGEN_H), VERIFIER]
        self.nodes = start_nodes(1, self.options.tmpdir, [self.args])
        self.is_network_split = False

    def run_test(self):
        node = self.nodes[0]
        info = node.yugen_getinfo()
        assert_equal(info["rpcversion"], YELLOWBACK_RPC_VERSION)
        assert_equal(info['branch_id'], YUGEN_BRANCH_ID)
        assert_equal(info['activation_height'], YUGEN_H)
        assert_equal(info['network'], 2)
        assert_equal(info['active'], False)

        bci = node.getblockchaininfo()
        assert_equal(bci['upgrades']['59474e30']['name'], 'Yugen')
        assert_equal(bci['upgrades']['59474e30']['status'], 'pending')

        node.generate(YUGEN_H - 2)
        assert_equal(node.yugen_getinfo()['active'], False)
        assert_equal(node.getblockchaininfo()['consensus']['nextblock'], '6d5b7a31')
        node.generate(1)
        assert_equal(node.yugen_getinfo()['active'], True)
        assert_equal(node.getblockchaininfo()['consensus']['nextblock'], '59474e30')
        node.generate(1)
        bci = node.getblockchaininfo()
        assert_equal(bci['blocks'], YUGEN_H)
        assert_equal(bci['consensus']['chaintip'], '59474e30')
        assert_equal(bci['upgrades']['59474e30']['status'], 'active')
        # The tree holds cm* alone from the activation block (spec §13.2); the root is the helper's.
        info = node.yugen_getinfo()
        assert_equal(info['tree_size'], 1)
        assert_equal(node.yugen_getanchor(YUGEN_H)['root'], info['root'])
        assert_equal(node.yugen_getblockdata(YUGEN_H)['transfers'], [])

        # Yugen without Vault at or below it is refused.
        stop_nodes(self.nodes)
        wait_bitcoinds()
        self.nodes = []
        assert_start_raises_init_error(0, self.options.tmpdir,
            list(YCASH_UPGRADE_ARGS) + [nuparams(YUGEN_BRANCH_ID, YUGEN_H), VERIFIER],
            "The Yugen upgrade requires Vault active at or below its height")
        assert_start_raises_init_error(0, self.options.tmpdir,
            list(YCASH_UPGRADE_ARGS) + [nuparams(VAULT_BRANCH_ID, 40), nuparams(YUGEN_BRANCH_ID, YUGEN_H), VERIFIER],
            "The Yugen upgrade requires Vault active at or below its height")


if __name__ == '__main__':
    YugenActivationTest().main()
