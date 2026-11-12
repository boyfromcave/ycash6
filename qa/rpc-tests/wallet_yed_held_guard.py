#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""The wallet-side "has held YED" guard (beta2 item 32).

A wallet that has held YED, or issued a YED holder key, carries a write-once "yedheld" record in
wallet.dat (getwalletinfo.yed_held). H6 refuses a datadir that holds a Yellowback index where
Yellowback is not live; this guard covers the wallet that arrives without one (a copied wallet.dat,
a fresh datadir): there is no index to rebuild its YED coin locks from, so start-up refuses it
unless -yellowback=0 (H6's acknowledgement) is given, and then warns that its YED is unprotected: on
stderr and in the log at start-up, in getinfo "errors" for the life of the process, and as
getwalletinfo.yed_unlocked.

The same file runs on ycash-dd and ycash6."""

import os
import shutil
import tempfile
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.util import (assert_equal, assert_start_raises_init_error, bitcoind_processes,
                                 initialize_datadir, start_node, stop_node,
                                 wait_and_assert_operationid_status, z_sendmany_opid)
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
MISC_WARNING = WARNING[len('Warning: '):]     # getinfo "errors" carries the text without the prefix
H6_REFUSAL = 'This datadir holds a Yellowback index, so this wallet may hold YED'

USER = 0          # mints
HOLDER = 3        # issues a holder key (yed_getnewaddress) and never holds a token
RECEIVER = 4      # receives YED at an address drawn with plain getnewaddress
UNTOUCHED = 5     # never touches YED (until the post-quantum receive at the end)
IMPORTER = POOLS[0]   # node 2: imports a key that holds YED (at the end)
FRESH = 6         # a fresh datadir the copied wallets are started in (no Yellowback index)


def held(node):
    return node.getwalletinfo()['yed_held']


def unlocked(node):
    return node.getwalletinfo()['yed_unlocked']


def yed_form(node, plain):
    """The YED form of one of node's plain-YEC addresses: the version bytes of a YED address of the same
    kind (t… -> p2pkh, rq… -> pq), the rest of the plain address unchanged."""
    raw = ym.base58check_decode(plain)
    if len(raw) == 22:                       # P2PKH: 2 version bytes + the key hash
        version = ym.base58check_decode(node.yed_getnewaddress('p2pkh'))[:-20]
    else:                                    # post-quantum: 2 version bytes + scheme + the key id
        version = ym.base58check_decode(node.yed_getnewaddress('pq'))[:2]
    return ym.base58check_encode(version + raw[len(version):])


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
        for i in (USER, HOLDER, RECEIVER, UNTOUCHED, IMPORTER):
            assert_equal(held(nodes[i]), False)
            assert_equal(unlocked(nodes[i]), False)

        print('a holder key marks the wallet')
        nodes[HOLDER].yed_getnewaddress()
        assert_equal(held(nodes[HOLDER]), True)

        print('minting marks the wallet')
        wallet_mint(self, nodes[USER], 10000, 48)
        assert_equal(held(nodes[USER]), True)
        assert_equal(unlocked(nodes[USER]), False)        # marked, and Yellowback is live here
        assert_equal(nodes[USER].getinfo()['errors'] == MISC_WARNING, False)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(nodes[USER].yed_getbalance()['confirmedCents'], 10000)

        print('receiving YED marks the wallet (an address drawn with getnewaddress, no holder key issued)')
        taddr = nodes[RECEIVER].getnewaddress()
        assert_equal(held(nodes[RECEIVER]), False)
        unmarked_receiver = self.wallet_copy(RECEIVER, 'walletnode%dunmarked' % RECEIVER)
        self.receiver_taddr, self.unmarked_receiver = taddr, unmarked_receiver
        nodes[USER].yed_send(yed_form(nodes[USER], taddr), 1000)
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
        self.more_marker_paths(unmarked_receiver)
        self.checkpoint('has-held-YED guard')
        self.unmarked_guard()
        self.burn_guard()

    def wallet_copy(self, i, name=None):
        name = name or 'walletnode%d' % i               # backupwallet writes into -exportdir (node_args)
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
            # the acknowledgement may sit in the config file: the warning stays visible over RPC
            assert_equal(node.getinfo()['errors'], MISC_WARNING)
            assert_equal(unlocked(node), True)
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
            assert_equal(unlocked(node), False)
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

    def more_marker_paths(self, unmarked_receiver):
        nodes = self.nodes
        user = nodes[USER]

        print('YED received at an imported key marks the wallet (the import hook)')
        taddr = user.getnewaddress()
        user.yed_send(yed_form(user, taddr), 500)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(held(nodes[IMPORTER]), False)
        nodes[IMPORTER].importprivkey(user.dumpprivkey(taddr))
        assert_equal(nodes[IMPORTER].yed_getbalance()['confirmedCents'], 500)
        assert_equal(held(nodes[IMPORTER]), True)

        print('YED received at a post-quantum key marks the wallet (a plain getnewaddress "pq" key, no holder key issued)')
        rq = nodes[UNTOUCHED].getnewaddress('', 'pq')
        assert_equal(held(nodes[UNTOUCHED]), False)
        user.yed_send(yed_form(user, rq), 700)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(nodes[UNTOUCHED].yed_getbalance()['confirmedCents'], 700)
        assert_equal(held(nodes[UNTOUCHED]), True)
        assert_equal(unlocked(nodes[UNTOUCHED]), False)

        print('a wallet with the same keys, taken before the YED arrived, re-derives the marker by -rescan where Yellowback is live')
        stop_node(nodes[RECEIVER], RECEIVER)
        self.nodes[RECEIVER] = None
        shutil.copyfile(unmarked_receiver, os.path.join(self.options.tmpdir, 'node%d' % RECEIVER, 'regtest', 'wallet.dat'))
        self.restart(RECEIVER, ['-rescan'])
        assert_equal(self.nodes[RECEIVER].yed_getbalance()['confirmedCents'], 1000)
        assert_equal(held(self.nodes[RECEIVER]), True)

    def unmarked_guard(self):
        """Where Yellowback is not live, no coin-selecting send spends an output whose own payload gives it YED,
        whether or not the wallet carries the "yedheld" mark. The unmarked case is the seed restore where Yellowback
        is not live (no attestor set): the restored wallet holds the YED output and has no mark. Built here without a
        restore: the receiver's wallet copy taken before its YED arrived, rescanned on a copy of the chain with no
        Yellowback index and no attestor set (no -yellowback=0 needed: the wallet is unmarked)."""
        user = self.nodes[USER]
        taddr = self.receiver_taddr
        print('not live, unmarked wallet holding YED: no coin-selecting send spends its YED output')
        user.sendtoaddress(taddr, 1)                  # a plain coin beside the token at the same address
        self.sync_all()
        self.mine(POOLS[0])
        stop_node(user, USER)
        self.nodes[USER] = None
        datadir = os.path.join(self.options.tmpdir, 'node%d' % FRESH)
        if os.path.isdir(datadir):
            shutil.rmtree(datadir)
        shutil.copytree(os.path.join(self.options.tmpdir, 'node%d' % USER), datadir)
        shutil.rmtree(os.path.join(datadir, 'regtest', 'yellowback'))
        shutil.copyfile(self.unmarked_receiver, os.path.join(datadir, 'regtest', 'wallet.dat'))
        initialize_datadir(self.options.tmpdir, FRESH)     # this slot's own ports, not the copied node's
        self.restart(USER)
        base = [a for a in self.node_args(UNTOUCHED) if not a.startswith('-yellowback') and a != '-experimentalfeatures']
        node = start_node(FRESH, self.options.tmpdir, base + ['-rescan'])
        try:
            assert_equal(held(node), False)                # the state a seed restore leaves (SEED-BASE step 6, B)
            assert_equal(unlocked(node), False)
            here = node.listunspent(1, 9999999, [taddr])
            token = [c for c in here if c['amount'] == Decimal('0.0001')]
            plain = [c for c in here if c['amount'] == Decimal('1')]
            assert_equal((len(here), len(token), len(plain)), (2, 1, 1))
            token, plain = token[0], plain[0]
            outpoint = {'txid': token['txid'], 'vout': token['vout']}
            # only the token and the plain coin beside it stay selectable: 1 YEC and its 0.0001 fee need both
            others = [{'txid': c['txid'], 'vout': c['vout']} for c in node.listunspent(0, 9999999)
                      if (c['txid'], c['vout']) not in ((token['txid'], token['vout']), (plain['txid'], plain['vout']))]
            if others:
                assert node.lockunspent(False, others)
            to = node.getnewaddress()

            def token_unspent():
                assert_equal([c for c in node.listunspent(0, 9999999, [taddr])
                              if (c['txid'], c['vout']) == (token['txid'], token['vout'])], [token])
                assert_equal(node.getrawmempool(), [])

            for name, call in (('sendtoaddress', lambda: node.sendtoaddress(to, 1)),
                               ('sendmany', lambda: node.sendmany('', {to: 1})),
                               ('fundrawtransaction', lambda: node.fundrawtransaction(node.createrawtransaction([], {to: 1})))):
                print('  %s: insufficient funds without the token (before: it spent the token)' % name)
                try:
                    call()
                    raise AssertionError('%s spent the YED output as plain YEC' % name)
                except JSONRPCException as e:
                    assert 'Insufficient funds' in e.error['message'], e.error['message']
                token_unspent()

            print('  z_sendmany from the address: refused, naming the token')
            refusal = ('refusing to spend an output that carries YED as plain YEC while Yellowback is not live: %s:%d '
                       '(its YED would burn; to destroy it deliberately, name the outpoint in a raw transaction)'
                       % (token['txid'], token['vout']))
            try:
                wait_and_assert_operationid_status(node, z_sendmany_opid(node, taddr, [(to, Decimal('1'))]), 'failed', refusal)
            except JSONRPCException as e:
                assert_equal(e.error['message'], refusal)
            token_unspent()

            print('  vault funding (set_create) with only the token selectable: insufficient funds')
            assert node.lockunspent(False, [{'txid': plain['txid'], 'vout': plain['vout']}])
            try:
                node.set_create({'seats': 1, 'unlockthreshold': 1, 'maturity': 2})
                raise AssertionError('set_create funded its fee from the YED output')
            except JSONRPCException as e:
                assert 'insufficient confirmed transparent funds' in e.error['message'], e.error['message']
            token_unspent()
            assert node.lockunspent(True, [{'txid': plain['txid'], 'vout': plain['vout']}])

            print('  fundrawtransaction that names the token: the deliberate act stays possible')
            funded = node.fundrawtransaction(node.createrawtransaction([outpoint], {to: Decimal('0.5')}))
            assert outpoint in [{'txid': i['txid'], 'vout': i['vout']} for i in node.decoderawtransaction(funded['hex'])['vin']]

            print('  z_mergetoaddress from the address: merges the plain coin, leaves the token')
            try:
                merge = node.z_mergetoaddress([taddr], node.z_getnewaddress('sapling'))
            except JSONRPCException as e:
                merge = None
                print('  (z_mergetoaddress not available on this node: %s)' % e.error['message'])
            if merge is not None:
                assert_equal(merge['mergingUTXOs'], 1)
                wait_and_assert_operationid_status(node, merge['opid'])
                assert_equal([c for c in node.listunspent(0, 9999999, [taddr])], [token])
        finally:
            stop_node(node, FRESH)

    def burn_guard(self):
        """beta2 item 9: with -yellowback=0 a marked wallet has no YED coin locks, yet no coin-selecting send spends
        an output its payload gives YED; a raw transaction that names the outpoint (the second, explicit act) can."""
        user = self.nodes[USER]
        print('-yellowback=0: a send that selects coins never spends an output that carries YED')
        taddr = user.getnewaddress()
        user.yed_send(yed_form(user, taddr), 300)
        user.sendtoaddress(taddr, 1)
        self.sync_all()
        self.mine(POOLS[0])
        # the same chain and wallet without the Yellowback index: a copy of the stopped node's datadir
        stop_node(user, USER)
        self.nodes[USER] = None
        datadir = os.path.join(self.options.tmpdir, 'node%d' % FRESH)
        if os.path.isdir(datadir):
            shutil.rmtree(datadir)
        shutil.copytree(os.path.join(self.options.tmpdir, 'node%d' % USER), datadir)
        shutil.rmtree(os.path.join(datadir, 'regtest', 'yellowback'))
        initialize_datadir(self.options.tmpdir, FRESH)     # this slot's own ports, not the copied node's
        self.restart(USER)
        base = [a for a in self.node_args(UNTOUCHED) if not a.startswith('-yellowback') and a != '-experimentalfeatures']
        with tempfile.SpooledTemporaryFile(max_size=2**16) as err:
            node = start_node(FRESH, self.options.tmpdir, base + ['-yellowback=0'], stderr=err)
            assert_equal(unlocked(node), True)
            coins = node.listunspent(1, 9999999, [taddr])
            token = [c for c in coins if c['amount'] == Decimal('0.0001')]
            assert_equal(len(token), 1)
            token = token[0]
            refusal = ('refusing to spend an output that carries YED as plain YEC while Yellowback is not live: %s:%d '
                       '(its YED would burn; to destroy it deliberately, name the outpoint in a raw transaction)'
                       % (token['txid'], token['vout']))
            to = node.getnewaddress()
            # 1 YEC and the fee need the token's 0.0001 too: refused, naming it (before the fix: the YED burned)
            try:
                wait_and_assert_operationid_status(node, z_sendmany_opid(node, taddr, [(to, Decimal('1'))]), 'failed', refusal)
            except JSONRPCException as e:
                assert_equal(e.error['message'], refusal)
            assert_equal(len(node.listunspent(1, 9999999, [taddr])), 2)

            print('-yellowback=0: a raw transaction that names the outpoint destroys its YED deliberately')
            plain = [c for c in coins if c['amount'] == Decimal('1')][0]
            raw = node.createrawtransaction([{'txid': token['txid'], 'vout': token['vout']},
                                             {'txid': plain['txid'], 'vout': plain['vout']}], {to: Decimal('1')})
            signed = node.signrawtransaction(raw)
            assert_equal(signed['complete'], True)
            txid = node.sendrawtransaction(signed['hex'])
            assert txid in node.getrawmempool()
            stop_node(node, FRESH)


if __name__ == '__main__':
    WalletYedHeldGuardTest().main()
