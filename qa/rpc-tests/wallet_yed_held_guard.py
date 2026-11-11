#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""The wallet-side "has held YED" guard (beta2 item 32).

A wallet that has held YED, or issued a YED holder key, carries a write-once "yedheld" record in
wallet.dat (getwalletinfo.yed_held). H6 refuses a datadir that holds a Yellowback index where
Yellowback is not live; this guard covers the wallet that arrives without one (a copied wallet.dat,
a fresh datadir): there is no index to rebuild its YED coin locks from, so start-up refuses it
unless -yellowback=0 (H6's acknowledgement) is given, and then warns that its YED is unprotected.

The same file runs on ycash-dd and ycash6."""

import os
import shutil
import tempfile

from test_framework.util import (assert_equal, assert_start_raises_init_error, bitcoind_processes,
                                 initialize_datadir, start_node, stop_node)
from test_framework import yellowback_model as ym
from test_framework.yellowback_attest import wallet_mint
from test_framework.yellowback_util import (
    POOLS,
    REF_LAG,
    YellowbackTestFramework,
)

REFUSAL = ('This wallet has held YED, but Yellowback is not live with these options, so its YED outputs cannot be '
           'locked. Start with the network\'s attestor set (regtest -yellowbackattestorset) to keep those outputs '
           'locked, or with -yellowback=0 to acknowledge that they are spendable as plain YEC.')
WARNING = ('Warning: This wallet has held YED and Yellowback is not live (-yellowback=0): its YED outputs are not '
           'locked, and any send that spends one destroys the YED it carries.')
H6_REFUSAL = 'This datadir holds a Yellowback index, so this wallet may hold YED'

USER = 0          # mints
HOLDER = 3        # issues a holder key (yed_getnewaddress) and never holds a token
RECEIVER = 4      # receives YED at an address drawn with plain getnewaddress
UNTOUCHED = 5     # never touches YED
FRESH = 6         # a fresh datadir the copied wallets are started in (no Yellowback index)


def held(node):
    return node.getwalletinfo()['yed_held']


def fresh_held(node):
    """getwalletinfo on the fresh node: 6.20.0 refuses wallet reads during initial block download
    ("disabled while reindexing"), so one block first takes the isolated node out of it."""
    node.generate(1)
    return held(node)


class WalletYedHeldGuardTest(YellowbackTestFramework):

    def run_test(self):
        nodes = self.nodes
        self.activate(quote_usd=50)
        self.mine(POOLS[0], REF_LAG + 1)
        for i in (USER, HOLDER, RECEIVER, UNTOUCHED):
            assert_equal(held(nodes[i]), False)

        print('a holder key marks the wallet')
        nodes[HOLDER].yed_getnewaddress()
        assert_equal(held(nodes[HOLDER]), True)

        print('minting marks the wallet')
        wallet_mint(self, nodes[USER], 10000, 48)
        assert_equal(held(nodes[USER]), True)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(nodes[USER].yed_getbalance()['confirmedCents'], 10000)

        print('receiving YED marks the wallet (an address drawn with getnewaddress, no holder key issued)')
        taddr = nodes[RECEIVER].getnewaddress()
        assert_equal(held(nodes[RECEIVER]), False)
        version = ym.base58check_decode(nodes[USER].yed_getnewaddress('p2pkh'))[:-20]
        yaddr = ym.base58check_encode(version + ym.base58check_decode(taddr)[-20:])
        nodes[USER].yed_send(yaddr, 1000)
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(nodes[RECEIVER].yed_getbalance()['confirmedCents'], 1000)
        assert_equal(held(nodes[RECEIVER]), True)
        assert_equal(held(nodes[UNTOUCHED]), False)

        print('the marker survives a restart, -rescan and -zapwallettxes')
        self.restart(USER)
        assert_equal(held(self.nodes[USER]), True)
        self.restart(USER, ['-rescan'])
        assert_equal(held(self.nodes[USER]), True)
        self.restart(RECEIVER, ['-zapwallettxes=1'])
        assert_equal(held(self.nodes[RECEIVER]), True)
        assert_equal(held(self.nodes[UNTOUCHED]), False)

        self.copied_wallets()
        self.checkpoint('has-held-YED guard')

    def wallet_copy(self, i):
        name = 'walletnode%d' % i                       # backupwallet writes into -exportdir (node_args)
        self.nodes[i].backupwallet(name)
        return os.path.join(self.options.tmpdir, 'export', name)

    def start_fresh(self, wallet, args, stderr=None):
        """A fresh datadir (no Yellowback index, no blocks) holding a copy of ``wallet``."""
        datadir = os.path.join(self.options.tmpdir, 'node%d' % FRESH)
        if os.path.isdir(datadir):
            shutil.rmtree(datadir)
        initialize_datadir(self.options.tmpdir, FRESH)
        os.makedirs(os.path.join(datadir, 'regtest'))
        shutil.copyfile(wallet, os.path.join(datadir, 'regtest', 'wallet.dat'))
        assert not os.path.exists(os.path.join(datadir, 'regtest', 'yellowback'))
        return start_node(FRESH, self.options.tmpdir, args, stderr=stderr) if stderr is not None else None

    def copied_wallets(self):
        # The arguments of a node that does not have Yellowback live: the vault upgrade without the
        # attestor set (an old configuration, a missing set), as H6's test starts one.
        base = [a for a in self.node_args(UNTOUCHED) if not a.startswith('-yellowback') and a != '-experimentalfeatures']
        marked = {i: self.wallet_copy(i) for i in (USER, HOLDER, RECEIVER)}
        unmarked = self.wallet_copy(UNTOUCHED)

        for i, wallet in sorted(marked.items()):
            print('a marked wallet (node %d) in a fresh datadir where Yellowback is not live: start-up refused' % i)
            self.start_fresh(wallet, base)
            assert_start_raises_init_error(FRESH, self.options.tmpdir, base, REFUSAL)
            if FRESH in bitcoind_processes:
                del bitcoind_processes[FRESH]

        print('-yellowback=0 acknowledges it: the node starts, warns, and reports the marker')
        with tempfile.SpooledTemporaryFile(max_size=2**16) as err:
            node = self.start_fresh(marked[USER], base + ['-yellowback=0'], stderr=err)
            assert_equal(fresh_held(node), True)
            stop_node(node, FRESH)
            err.seek(0)
            assert_equal(err.read().decode('utf-8').strip(), WARNING)
        debug_log = os.path.join(self.options.tmpdir, 'node%d' % FRESH, 'regtest', 'debug.log')
        with open(debug_log, encoding='utf-8', errors='replace') as f:
            assert WARNING in f.read()

        print('an unmarked wallet starts in the same place without the acknowledgement')
        with tempfile.SpooledTemporaryFile(max_size=2**16) as err:
            node = self.start_fresh(unmarked, base, stderr=err)
            assert_equal(fresh_held(node), False)
            stop_node(node, FRESH)
            err.seek(0)
            assert_equal(err.read().decode('utf-8').strip(), '')

        print('H6 is unchanged: a datadir with an index and no attestor set still refuses with its own message')
        stop_node(self.nodes[UNTOUCHED], UNTOUCHED)
        self.nodes[UNTOUCHED] = None
        assert_start_raises_init_error(UNTOUCHED, self.options.tmpdir, base, H6_REFUSAL)
        if UNTOUCHED in bitcoind_processes:
            del bitcoind_processes[UNTOUCHED]
        self.nodes[UNTOUCHED] = start_node(UNTOUCHED, self.options.tmpdir, self.node_args(UNTOUCHED))
        self.reconnect(UNTOUCHED)


if __name__ == '__main__':
    WalletYedHeldGuardTest().main()
