#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
-rescan and a legacy Yugen seed (doc/yugen-node.md N-A5; review blocker 1): a state file of an earlier
version holding an imported (non-mnemonic) seed, started with -rescan, must move the seed into wallet.dat
before the chain state is cleared; the funds stay spendable. With an encrypted (locked) wallet the rescan is
refused and the file keeps the seed; after an unlock the rescan runs.

The original module docstring of yugen_wallet_encrypted.py follows for the shared helpers.

0. N-A2 vector: node 0's wallet is made from the BIP 39 phrase "abandon x11 about"; its Yugen seed (the
   dump's yugenseed line) is the vector yewd's signer and yewd-yugen also test.
1. Migration: an account state file of an earlier version (a "seed" field) on node 1; encryptwallet moves
   the seed into the encrypted wallet; after the restart the state file holds no seed (0600) and nothing
   under the data directory holds the seed in hex or raw; unlocked, the dump gives it back.
2. Node 0: a deposit, then encryptwallet. Locked: z_getbalance / z_gettotalbalance answer from the last
   state; z_sendmany from the account is refused with the wallet-locked error (-13). Unlocked: a
   withdrawal is sent. No seed anywhere under the data directory.
3. Restore from z_exportwallet (state removed), then two sends from the restored account (spec §5.6:
   the dummy rule survives a restore).

Env: ZCASHD, YEWD_YUGEN, YUGEN_SENDBUILD, YUGEN_LEAFVERIFY, HOSTD (as yugen_wallet.py). Proves 4 leaf
transfers: need more than 6 GB and up to 20 GB of memory.
"""

import json
import os
import shutil
import stat
import subprocess
import time
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID, assert_equal, bitcoind_processes, connect_nodes_bi, nuparams, rpc_auth_pair, rpc_port,
    assert_start_raises_init_error, start_node, start_nodes, stop_node, sync_blocks, sync_mempools,
)
from yugen_wallet_encrypted import YugenWalletEncryptedTest
from test_framework.yellowback_util import YCASH_UPGRADE_ARGS
from test_framework.yugen_util import yugen_helper

YUGEN_BRANCH_ID = 0x59474E30
HERE = os.path.dirname(os.path.abspath(__file__))
CLONES = os.environ.get('YUGEN_CLONES', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..'))  # the sibling checkouts
WALLET = yugen_helper('YEWD_YUGEN', 'yewd-yugen')
SENDBUILD = yugen_helper('YUGEN_SENDBUILD', 'yugen-sendbuild')
LEAFVERIFY = yugen_helper('YUGEN_LEAFVERIFY', 'yugen-leafverify')
HOSTD = os.environ.get('HOSTD', CLONES + '/lightwalletd-dd/yugen/target/release/yugen-hostd')
HOST_PORTS = [33410, 33411]
HOSTS = ','.join('127.0.0.1:%d' % p for p in HOST_PORTS)
ARGS = list(YCASH_UPGRADE_ARGS) + [
    nuparams(VAULT_BRANCH_ID, 16), nuparams(YUGEN_BRANCH_ID, 32), '-yugenverifier=' + LEAFVERIFY,
    '-yugenbuilder=' + SENDBUILD, '-yugenprover=' + WALLET, '-yugenhosts=' + HOSTS, '-yugensyncdelay=0',
    '-experimentalfeatures', '-developerencryptwallet', '-debug=yugen']
FEE = 100000 + 155600
PHRASE = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
# N-A2: BLAKE2b-256(personal "Ycash_YugenSeed_", BIP 39 seed of PHRASE, empty passphrase)
VECTOR = '3a3287aac7b77e6a5e1a1fd4931a267e6ee3f1b874f60513a5ba4fe0eafd538c'
LEGACY = '7e' * 32        # node 1's seed from an earlier version's state file
PASS = 'yugen-pass'


def zat(x):
    return int((Decimal(x) * 100000000).to_integral_value())


def assert_no_seed(datadir, seed_hex):
    raw = bytes.fromhex(seed_hex)
    for root, _, files in os.walk(datadir):
        for f in files:
            p = os.path.join(root, f)
            try:
                b = open(p, 'rb').read()
            except OSError:
                continue
            assert seed_hex.encode() not in b.lower(), '%s holds the seed hex' % p
            assert raw not in b, '%s holds the seed bytes' % p
            assert PHRASE.encode() not in b, '%s holds the phrase' % p
    sf = os.path.join(datadir, 'regtest', 'yugenwallet', 'wallet.json')
    if os.path.exists(sf):
        assert_equal(stat.S_IMODE(os.stat(sf).st_mode), 0o600)
        assert 'seed' not in json.load(open(sf)), sf



IMPORTED = '5c' * 32


class YugenWalletRescanTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.hosts = []

    def node_args(self, i):
        return ARGS + ['-exportdir=' + os.path.join(self.options.tmpdir, 'export')]

    def setup_network(self, split=False):
        self.nodes = start_nodes(2, self.options.tmpdir, [self.node_args(0), self.node_args(1)])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        for i, port in enumerate(HOST_PORTS):
            d = os.path.join(self.options.tmpdir, 'host%d' % i)
            os.makedirs(d, exist_ok=True)
            u, p = rpc_auth_pair(i)
            log = open(os.path.join(d, 'out.log'), 'w')
            self.hosts.append(subprocess.Popen(
                [HOSTD, '-id=H%d' % i, '-datadir=' + d, '-listen=127.0.0.1:%d' % port,
                 '-node=127.0.0.1:%d' % rpc_port(i), '-rpcuser=' + u, '-rpcpassword=' + p, '-network=regtest',
                 '-poll_ms=300'], stdout=log, stderr=subprocess.STDOUT))

    def restart(self, i, extra=()):
        self.nodes[i] = start_node(i, self.options.tmpdir, self.node_args(i) + list(extra))
        connect_nodes_bi(self.nodes, 0, 1)
        return self.nodes[i]

    def datadir(self, i):
        return os.path.join(self.options.tmpdir, 'node%d' % i)

    def ydir(self, i):
        return os.path.join(self.datadir(i), 'regtest', 'yugenwallet')

    def mine(self, n=1):
        sync_mempools(self.nodes)
        self.nodes[0].generate(n)
        sync_blocks(self.nodes, wait=0.2)
        time.sleep(0.5)

    wait_op = YugenWalletEncryptedTest.wait_op
    seed_line = YugenWalletEncryptedTest.seed_line

    def anchored(self, node, addr, want, timeout=600):
        t0 = time.time()
        while time.time() - t0 < timeout:
            if zat(node.z_getbalance(addr)) >= want:
                return
            time.sleep(2)
            self.mine(1)
        raise AssertionError('spendable %d at %s' % (want, addr))

    def run_test(self):
        try:
            self.body()
        finally:
            for h in self.hosts:
                h.terminate()
                try:
                    h.wait(10)
                except subprocess.TimeoutExpired:
                    h.kill()

    def write_legacy(self, i, state):
        os.makedirs(self.ydir(i), exist_ok=True)
        with open(os.path.join(self.ydir(i), 'wallet.json'), 'w') as f:
            json.dump(state, f)

    def body(self):
        n0, n1 = self.nodes
        self.mine(140)
        # node 1: an account from an imported seed (not derived from its mnemonic), funded
        imp = os.path.join(self.options.tmpdir, 'export', 'imported')
        os.makedirs(os.path.dirname(imp), exist_ok=True)
        with open(imp, 'w') as f:
            f.write('yugenseed=%s\n' % IMPORTED)
        n1.z_importwallet(imp)
        a = n1.z_getnewaddress('yugen')
        a1 = n1.z_getnewaddress('yugen', {'onetime': True})
        t0 = n0.getnewaddress()
        n0.sendtoaddress(t0, 10)
        self.mine(1)
        self.wait_op(n0, n0.z_sendmany(t0, [{'address': a1, 'amount': 5}], 1))
        self.mine(1)
        self.anchored(n1, a, zat(5))
        print('1 node 1: imported seed account funded: %s' % a)

        # an earlier version's state file: the seed in wallet.json, none in wallet.dat (node 1's wallet.dat is
        # replaced by a fresh one; the account files move with the seed added)
        stop_node(n1, 1)
        state = json.load(open(os.path.join(self.ydir(1), 'wallet.json')))
        state['seed'] = IMPORTED
        state.pop('seed_fp', None)
        addrs = open(os.path.join(self.ydir(1), 'ycashd-addresses.txt')).read()
        for f in os.listdir(os.path.join(self.datadir(1), 'regtest')):
            p = os.path.join(self.datadir(1), 'regtest', f)
            if f in ('wallet.dat', 'database', 'yugenwallet'):
                shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
        self.write_legacy(1, state)
        with open(os.path.join(self.ydir(1), 'ycashd-addresses.txt'), 'w') as f:
            f.write(addrs)
        n1 = self.restart(1, ['-rescan'])
        sf = os.path.join(self.ydir(1), 'wallet.json')
        assert 'seed' not in json.load(open(sf)), 'the state file still holds the seed'
        assert_equal(self.seed_line(n1, 'afterrescan'), [IMPORTED])
        self.anchored(n1, a, zat(5))
        t1 = n0.getnewaddress()
        w = self.wait_op(n1, n1.z_sendmany(a, [{'address': t1, 'amount': Decimal('0.5')}]))
        self.mine(1)
        assert_equal(zat(n0.getreceivedbyaddress(t1, 0)), zat('0.5'))
        print('2 -rescan with a legacy imported seed: seed in wallet.dat, spend %s' % w['txid'])

        # S4: a state file with another seed than the wallet's: the recovery text says so (not "unlock")
        stop_node(n1, 1)
        good = json.load(open(sf))
        bad = dict(good)
        bad['seed'] = '5a' * 32
        self.write_legacy(1, bad)
        assert_start_raises_init_error(1, self.options.tmpdir, self.node_args(1) + ['-rescan'], "not the wallet's Yugen seed")
        self.write_legacy(1, good)
        n1 = self.restart(1)
        print('2b -rescan refused: another seed than the wallet, recovery text names it')

        # encrypted and locked: -rescan with a legacy seed is refused; the file keeps the seed
        n1.encryptwallet(PASS)
        bitcoind_processes[1].wait()
        st = json.load(open(sf))
        st['seed'] = IMPORTED
        self.write_legacy(1, st)
        assert_start_raises_init_error(1, self.options.tmpdir, self.node_args(1) + ['-rescan'], 'unlock the wallet once (walletpassphrase)')
        assert_equal(json.load(open(sf)).get('seed'), IMPORTED)
        n1 = self.restart(1)
        n1.walletpassphrase(PASS, 600)
        assert 'seed' not in json.load(open(sf))
        stop_node(n1, 1)
        n1 = self.restart(1, ['-rescan'])
        n1.walletpassphrase(PASS, 600)
        assert_equal(self.seed_line(n1, 'afterlocked'), [IMPORTED])
        print('3 locked: -rescan refused, the seed kept; unlocked: migrated, -rescan ok')

        # S4: the recovery text names the cause: a state file with another seed is not a locked wallet
        stop_node(n1, 1)
        good = json.load(open(sf))
        bad = dict(good)
        bad['seed'] = 'zz' * 32
        self.write_legacy(1, bad)
        assert_start_raises_init_error(1, self.options.tmpdir, self.node_args(1) + ['-rescan'], 'cannot be read')
        self.write_legacy(1, good)
        n1 = self.restart(1)
        n1.walletpassphrase(PASS, 600)
        print('3b -rescan refused with per-cause recovery text (malformed seed)')

        # a dump never silently omits the seed of an existing account: no seed available -> error
        stop_node(n1, 1)
        for f in ('wallet.dat', 'database'):
            p = os.path.join(self.datadir(1), 'regtest', f)
            if os.path.isdir(p):
                shutil.rmtree(p)
            elif os.path.exists(p):
                os.remove(p)
        n1 = self.restart(1)
        try:
            n1.z_exportwallet('noseed')
            raise AssertionError('a dump without the Yugen seed of an existing account must fail')
        except JSONRPCException as e:
            assert 'seed' in e.error['message'], e.error
            assert 'retry when the Yugen engine is idle' not in e.error['message'], e.error
            assert 'restore it (importwallet)' in e.error['message'], e.error
        assert not os.path.exists(os.path.join(self.options.tmpdir, 'export', 'noseed'))
        print('4 z_exportwallet refuses a dump that would omit the Yugen seed')


if __name__ == '__main__':
    YugenWalletRescanTest().main()
