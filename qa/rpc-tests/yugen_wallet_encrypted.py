#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The Yugen account seed at rest (doc/yugen-node.md N-A5): the seed lives in wallet.dat only, under the
wallet's encryption, and reaches the engine per call on fd 3.

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
    start_node, start_nodes, stop_node, sync_blocks, sync_mempools,
)
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


class YugenWalletEncryptedTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.hosts = []

    def node_args(self, i):
        a = ARGS + ['-exportdir=' + os.path.join(self.options.tmpdir, 'export')]
        return a + ['-mnemonicfile=' + self.phrase_file] if i == 0 else a

    def setup_network(self, split=False):
        self.phrase_file = os.path.join(self.options.tmpdir, 'phrase.txt')
        with open(self.phrase_file, 'w') as f:
            f.write(PHRASE + '\n')
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

    def encrypt(self, i):
        self.nodes[i].encryptwallet(PASS)
        bitcoind_processes[i].wait()
        return self.restart(i)

    def datadir(self, i):
        return os.path.join(self.options.tmpdir, 'node%d' % i)

    def mine(self, n=1):
        sync_mempools(self.nodes)
        self.nodes[0].generate(n)
        sync_blocks(self.nodes, wait=0.2)
        time.sleep(0.5)

    def wait_op(self, node, opid, timeout=1800):
        t0 = time.time()
        while time.time() - t0 < timeout:
            st = node.z_getoperationstatus([opid])[0]
            if st['status'] == 'success':
                return node.z_getoperationresult([opid])[0]['result']
            if st['status'] in ('failed', 'cancelled'):
                raise AssertionError('operation %s: %s' % (opid, st.get('error')))
            time.sleep(2)
        raise AssertionError('operation %s timed out' % opid)

    def anchored(self, node, addr, want, timeout=600):
        t0 = time.time()
        while time.time() - t0 < timeout:
            if zat(node.z_getbalance(addr)) >= want:
                return
            time.sleep(2)
            self.mine(1)
        raise AssertionError('spendable %d at %s' % (want, addr))

    def seed_line(self, node, name):
        txt = open(node.z_exportwallet(name)).read()
        return [l.split('=', 1)[1].split()[0] for l in txt.splitlines() if l.startswith('yugenseed=')]

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

    def body(self):
        n0, n1 = self.nodes
        self.mine(140)

        # 0. N-A2 vector
        a = n0.z_getnewaddress('yugen')
        a1 = n0.z_getnewaddress('yugen', {'onetime': True})
        assert_equal(self.seed_line(n0, 'na2'), [VECTOR])
        sf0 = os.path.join(self.datadir(0), 'regtest', 'yugenwallet', 'wallet.json')
        assert 'seed' not in json.load(open(sf0)) and stat.S_IMODE(os.stat(sf0).st_mode) == 0o600
        print('0 N-A2 vector ok; the state file holds no seed')

        # 1. migration of an earlier version's state file by encryptwallet
        ydir1 = os.path.join(self.datadir(1), 'regtest', 'yugenwallet')
        os.makedirs(ydir1, exist_ok=True)
        legacy = {'seed': LEGACY, 'network': 2, 'scanned': None, 'leaves': [], 'sizes': {}, 'requests': [],
                  'next_change': 0, 'otag_counters': {}, 'dummy_counter': 0, 'notes': [], 'deposit_utxos': []}
        with open(os.path.join(ydir1, 'wallet.json'), 'w') as f:
            json.dump(legacy, f)
        os.chmod(os.path.join(ydir1, 'wallet.json'), 0o644)
        n1 = self.encrypt(1)
        assert_no_seed(self.datadir(1), LEGACY)
        try:
            n1.z_getnewaddress('yugen')
            raise AssertionError('locked: a new Yugen address needs the seed')
        except JSONRPCException as e:
            assert_equal(e.error['code'], -13)
        n1.walletpassphrase(PASS, 600)
        b = n1.z_getnewaddress('yugen')
        assert_equal(self.seed_line(n1, 'migrated'), [LEGACY])
        n1.walletlock()
        assert_no_seed(self.datadir(1), LEGACY)
        print('1 encryptwallet migrated the state file seed into wallet.dat: %s' % b)

        # 2. deposit, encrypt, locked reads, refused spend, unlocked spend
        t0 = n0.getnewaddress()
        n0.sendtoaddress(t0, 10)
        self.mine(1)
        self.wait_op(n0, n0.z_sendmany(t0, [{'address': a1, 'amount': 5}], 1))
        self.mine(1)
        self.anchored(n0, a, zat(5))
        n0 = self.encrypt(0)
        assert_no_seed(self.datadir(0), VECTOR)
        assert_equal(zat(n0.z_getbalance(a)), zat(5))
        assert_equal(zat(n0.z_gettotalbalance()['yugen']), zat(5))
        n1.walletpassphrase(PASS, 7200)
        t1 = n1.getnewaddress()
        try:
            n0.z_sendmany(a, [{'address': t1, 'amount': Decimal('0.5')}])
            raise AssertionError('locked: a Yugen spend must be refused')
        except JSONRPCException as e:
            assert_equal(e.error['code'], -13)
            assert 'walletpassphrase' in e.error['message'], e.error
        print('2 locked: balance 5 read, spend refused (-13)')
        n0.walletpassphrase(PASS, 3600)
        w = self.wait_op(n0, n0.z_sendmany(a, [{'address': t1, 'amount': Decimal('0.5')}]))
        self.mine(1)
        assert_equal(zat(n1.getreceivedbyaddress(t1, 0)), zat('0.5'))
        a_now = zat(5) - zat('0.5') - FEE
        self.anchored(n0, a, a_now)
        n0.walletlock()
        assert_equal(zat(n0.z_getbalance(a)), a_now)
        assert_no_seed(self.datadir(0), VECTOR)
        print('2 unlocked: withdrawal %s; locked again, balance %d; no seed on disk' % (w['txid'], a_now))

        # 3. restore from the dump, then two sends
        n0.walletpassphrase(PASS, 3600)
        dump = n0.z_exportwallet('yugenbackup')
        stop_node(n0, 0)
        shutil.rmtree(os.path.join(self.datadir(0), 'regtest', 'yugenwallet'))
        n0 = self.restart(0)
        n0.walletpassphrase(PASS, 3600)
        n0.z_importwallet(dump)
        assert_equal(n0.z_getnewaddress('yugen'), a)
        self.anchored(n0, a, a_now)
        for k in range(2):
            amt = Decimal('0.2')
            r = self.wait_op(n0, n0.z_sendmany(a, [{'address': t1, 'amount': amt}]))
            self.mine(1)
            a_now -= zat(amt) + FEE
            self.anchored(n0, a, a_now)
            print('3 restored send %d: %s' % (k + 1, r['txid']))
        assert_equal(zat(n1.getreceivedbyaddress(t1, 0)), zat('0.9'))
        n0.walletlock()
        assert_no_seed(self.datadir(0), VECTOR)
        print('3 restore + two sends ok; no seed on disk')


if __name__ == '__main__':
    YugenWalletEncryptedTest().main()
