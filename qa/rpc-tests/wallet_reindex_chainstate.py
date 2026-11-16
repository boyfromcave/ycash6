#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
-reindex-chainstate on a node WITH a wallet (the default), after a clean stop and after an unclean one (SIGKILL after
blocks the block index had not yet written): the node must not stop at the assert in init.cpp
ThreadStartWalletNotifier (`pindexFork != nullptr`: the chainstate is emptied, so the active chain is empty while the
notifier first looks), and the wallet must end up synced: the same balances as before (transparent and Sapling), a
payment received after the reindex counted too, and a Sapling spend from a note held before the reindexes confirms
(its witness is intact). The notifier logs when it starts waiting for the chain and when it resumes (both lines or
neither: neither when the import is already close enough at its first look). Last, -reindex-chainstate with -rescan (or -zapwallettxes, which implies it) is refused at startup: -rescan would clear the
note witness cache with no scan to rebuild it, leaving notes at or below the wallet's last saved block unspendable.

    ZCASHD=<ycashd> .venv/bin/python -u qa/rpc-tests/wallet_reindex_chainstate.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

import os
import signal
import time
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_start_raises_init_error,
    bitcoind_processes,
    connect_nodes_bi,
    start_node,
    stop_node,
    wait_and_assert_operationid_status,
    z_sendmany_opid,
)

ARGS = ['-allowdeprecated=getnewaddress', '-allowdeprecated=z_getnewaddress']


class WalletReindexChainstateTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 2

    def setup_network(self, split=False):
        self.nodes = [start_node(i, self.options.tmpdir, ARGS) for i in range(2)]
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def balances(self, i):
        b = self.nodes[i].z_gettotalbalance(1)
        return tuple(Decimal(b[k]) for k in ('transparent', 'private', 'total'))

    def pay(self, amount):
        """node 0 pays node 1 `amount` in a mined block; both nodes see it."""
        self.nodes[0].sendtoaddress(self.addr1, amount)
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_all()

    def debug_log(self, i):
        with open(os.path.join(self.options.tmpdir, 'node%d' % i, 'regtest', 'debug.log'), encoding='utf-8',
                  errors='replace') as f:
            return f.read()

    def restart1(self, kill, extra=()):
        if kill:
            p = bitcoind_processes.pop(1)
            os.kill(p.pid, signal.SIGKILL)
            p.wait()
        else:
            stop_node(self.nodes[1], 1)
        logged = len(self.debug_log(1))
        self.nodes[1] = start_node(1, self.options.tmpdir, ARGS + ['-reindex-chainstate'] + list(extra))
        connect_nodes_bi(self.nodes, 0, 1)
        deadline = time.time() + 120
        while self.nodes[1].getbestblockhash() != self.nodes[0].getbestblockhash():
            assert time.time() < deadline, 'node 1 did not catch up after -reindex-chainstate'
            time.sleep(0.25)
        # The notifier logs when it starts waiting for the chain and when it resumes: both lines or neither. Neither is
        # logged when the import was already within 100 blocks of the wallet's block at the notifier's first look (a
        # race with ThreadImport, decided by the runner's speed). The chain has caught up by now, so a first look that
        # waited has already logged its line. The outcome (no assert, balances, the spend) is checked either way.
        if 'Wallet notifier: waiting for the active chain' in self.debug_log(1)[logged:]:
            self.waited += 1
            deadline = time.time() + 60
            while 'Wallet notifier: the active chain is within 100 blocks' not in self.debug_log(1)[logged:]:
                assert time.time() < deadline, 'a "waiting" log line without the "notifying the wallet" one'
                time.sleep(0.5)
        else:
            assert 'Wallet notifier: the active chain is within 100 blocks' not in self.debug_log(1)[logged:], \
                'a "notifying the wallet" log line without the "waiting" one'
        self.restarts += 1

    def check(self, label, expected):
        # the wallet notifier catches up after the chain does
        deadline = time.time() + 60
        while self.balances(1) != expected and time.time() < deadline:
            time.sleep(0.5)
        assert_equal(self.balances(1), expected)
        assert_equal(self.balances(0), self.before0)
        print('    ok   %s: balances unchanged' % label)

    def sapling_spend(self, label):
        """node 1 spends from its Sapling note (which needs an intact witness); the spend confirms."""
        n0, n1 = self.nodes
        before = self.balances(1)
        opid = z_sendmany_opid(n1, self.z1, [(n0.getnewaddress(), Decimal('1'))])
        txid = wait_and_assert_operationid_status(n1, opid, timeout=300)
        self.sync_all()
        n0.generate(1)
        self.sync_all()
        assert n1.gettransaction(txid)['confirmations'] >= 1, 'the Sapling spend did not confirm'
        after = self.balances(1)
        assert after[1] <= before[1] - Decimal('1'), (before, after)
        self.before0 = self.balances(0)
        print('    ok   %s: a Sapling spend from the note confirms (%s)' % (label, txid))

    def run_test(self):
        n0, n1 = self.nodes
        self.waited = self.restarts = 0
        self.addr1 = n1.getnewaddress()
        # a Sapling note for node 1, held before any reindex
        self.z1 = n1.z_getnewaddress('sapling')
        t0 = n0.getnewaddress()
        n0.sendtoaddress(t0, 6)
        self.sync_all()
        n0.generate(1)
        self.sync_all()
        wait_and_assert_operationid_status(n0, z_sendmany_opid(n0, t0, [(self.z1, Decimal('5'))]), timeout=300)
        self.sync_all()
        n0.generate(1)
        self.sync_all()
        self.pay(Decimal('7'))
        self.before0, before1 = self.balances(0), self.balances(1)
        assert_equal(before1[1], Decimal('5'))

        print('A. a clean stop, then -reindex-chainstate')
        self.restart1(kill=False)
        self.check('after -reindex-chainstate', before1)

        print('B. an unclean stop (SIGKILL), then -reindex-chainstate')
        self.pay(Decimal('3'))
        self.before0, before1 = self.balances(0), self.balances(1)
        self.restart1(kill=True)
        self.check('after the unclean stop and -reindex-chainstate', before1)

        print('C. the wallet still follows the chain')
        self.pay(Decimal('2'))
        t, p, total = self.balances(1)
        assert_equal(t, before1[0] + Decimal('2'))
        print('    ok   a payment after the reindex is counted')

        print('D. the Sapling witnesses survived: a spend from the note held before the reindexes')
        self.sapling_spend('after two -reindex-chainstate starts')

        print('E. -reindex-chainstate with -rescan (or a flag implying it) is refused at startup')
        # -rescan would clear the wallet's note witness cache while the chain is still empty (no scan runs), and the
        # notifier resumes from the wallet's last saved block: notes mined at or below it would lose their witnesses
        # for good ("Missing witness"), and a disconnected block would stop the node at DecrementNoteWitnesses' assert.
        stop_node(self.nodes[1], 1)
        msg = '-reindex-chainstate and -rescan cannot be used together'
        for extra in (['-rescan'], ['-zapwallettxes=1']):
            assert_start_raises_init_error(1, self.options.tmpdir, ARGS + ['-reindex-chainstate'] + extra, msg)
            print('    ok   -reindex-chainstate %s: refused' % ' '.join(extra))
        # each separately still starts; the wallet is intact and can spend its Sapling note
        self.nodes[1] = start_node(1, self.options.tmpdir, ARGS + ['-rescan'])
        connect_nodes_bi(self.nodes, 0, 1)
        self.sync_all()
        self.sapling_spend('after the refused starts and a -rescan start')
        print('    the notifier waited (both log lines) at %d of %d -reindex-chainstate starts' % (self.waited, self.restarts))
        print('wallet_reindex_chainstate OK')


if __name__ == '__main__':
    WalletReindexChainstateTest().main()
