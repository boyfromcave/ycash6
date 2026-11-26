#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
A node with a Yugen height but no -yugenprover (no Yugen account) behaves as stock (doc/yugen-node.md N-A1):

- z_listunspent: an empty address array and a non-array filter fail as before; a yq... string is not
  taken as a Yugen address (stock: not a valid Ycash address).
- importwallet / z_importwallet: a yugenseed= line is stored in wallet.dat (S1: a backup never depends on
  -yugenprover), the rest of the file imports; the node's own dump then carries the seed; another seed is
  refused; a later start with -yugenprover uses the stored seed (its dump and its account state).
- listtransactions: from/count paging as before (no Yugen rows).
The last step starts node 1 with the engine (YEWD_YUGEN); no proofs: fits in ordinary memory.
"""

import json
import os

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID, assert_equal, nuparams, start_node, start_nodes, stop_node, sync_blocks,
)
from test_framework.yellowback_util import YCASH_UPGRADE_ARGS
from test_framework.yugen_util import yugen_helper

YUGEN_BRANCH_ID = 0x59474E30
LEAFVERIFY = yugen_helper('YUGEN_LEAFVERIFY', 'yugen-leafverify')
WALLET = yugen_helper('YEWD_YUGEN', 'yewd-yugen')
SEED = 'ab' * 32
ARGS = list(YCASH_UPGRADE_ARGS) + [nuparams(VAULT_BRANCH_ID, 16), nuparams(YUGEN_BRANCH_ID, 32),
                                   '-yugenverifier=' + LEAFVERIFY]


def raises(msg, f, *a):
    try:
        f(*a)
    except JSONRPCException as e:
        assert msg in e.error['message'], e.error['message']
        return
    raise AssertionError('no error, expected: ' + msg)


class YugenWalletStockTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self, split=False):
        args = ARGS + ['-exportdir=' + os.path.join(self.options.tmpdir, 'export')]
        self.nodes = start_nodes(2, self.options.tmpdir, [args] * 2)
        self.is_network_split = False

    def run_test(self):
        n0, n1 = self.nodes
        n0.generate(110)
        sync_blocks([n0])    # the wallet learns of blocks asynchronously: wait until it has them

        # z_listunspent filters, as stock
        raises('addresses array is empty', n0.z_listunspent, 0, 9999999, False, [])
        raises('Expected type array', n0.z_listunspent, 0, 9999999, False, 'notanarray')
        raises('not a valid Ycash address: yqrfnotanaddress', n0.z_listunspent, 0, 9999999, False, ['yqrfnotanaddress'])
        lu = n0.z_listunspent(0)
        assert all(r.get('pool') != 'yugen' for r in lu)
        print('z_listunspent: 3 stock errors (empty array, non-array, yq... not an address); %d rows, none yugen' % len(lu))

        # importwallet with a yugenseed line: stored in wallet.dat although this node runs no Yugen engine (S1)
        t = n0.getnewaddress()
        n0.sendtoaddress(t, 1)
        n0.generate(1)
        sync_blocks([n0])
        dump = os.path.join(self.options.tmpdir, 'export', 'withyugen')
        n0.z_exportwallet('withyugen')
        assert 'yugenseed=' not in open(dump).read(), 'a node without a Yugen seed writes no Yugen seed line'
        with open(dump, 'a') as f:
            f.write('yugenseed=%s # yugenaddr=\n' % SEED)
        n1.importwallet(dump)
        assert n1.validateaddress(t)['ismine']
        n1.z_importwallet(dump)                       # the same seed again: accepted
        n1.z_exportwallet('n1dump')
        d1 = open(os.path.join(self.options.tmpdir, 'export', 'n1dump')).read()
        assert ('yugenseed=%s' % SEED) in d1, 'the dump of a node without -yugenprover carries the imported seed'
        other = os.path.join(self.options.tmpdir, 'export', 'otherseed')
        with open(other, 'w') as f:
            f.write('yugenseed=%s # yugenaddr=\n' % ('cd' * 32))
        raises('another seed exists', n1.importwallet, other)
        print('importwallet + z_importwallet on a node without -yugenprover: seed stored, dumped back, another seed refused; %s ismine' % t)

        # a later start with the engine uses the stored seed
        stop_node(n1, 1)
        args1 = ARGS + ['-exportdir=' + os.path.join(self.options.tmpdir, 'export'), '-yugenprover=' + WALLET]
        self.nodes[1] = n1 = start_node(1, self.options.tmpdir, args1)
        state = os.path.join(self.options.tmpdir, 'node1', 'regtest', 'yugenwallet', 'wallet.json')
        assert not os.path.exists(state)
        a = n1.z_getnewaddress('yugen')
        assert a.startswith('yq'), a
        assert os.path.exists(state) and 'seed' not in json.load(open(state)), 'account state made from the stored seed, holding no seed'
        n1.z_exportwallet('n1dump2')
        d2 = open(os.path.join(self.options.tmpdir, 'export', 'n1dump2')).read()
        assert ('yugenseed=%s # yugenaddr=%s' % (SEED, a)) in d2, [l[:30] for l in d2.splitlines() if 'yugen' in l]
        print('restart with -yugenprover: account %s... from the stored seed; dump carries the same seed' % a[:24])

        # listtransactions paging, as stock
        lt = n0.listtransactions('*', 1000)
        assert_equal(n0.listtransactions('*', 3), lt[-3:])
        assert_equal(n0.listtransactions('*', 3, 2), lt[-5:-2])
        assert all(r.get('pool') != 'yugen' for r in lt)
        assert len(lt) >= 5, len(lt)
        print('listtransactions: paging checked on %d rows (count 3; count 3 from 2), none yugen' % len(lt))


if __name__ == '__main__':
    YugenWalletStockTest().main()
