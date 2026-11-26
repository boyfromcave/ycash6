#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The ycashd wallet's Yugen account (doc/yugen-node.md N-A1..N-A4) on regtest: two ycashd nodes with
wallets, each with a Yugen account, and two mailbox hosts (yugen-hostd, HOSTD).

1. Keys and addresses: z_getnewaddress "yugen" gives the default short address (yqrf, decision Y-15),
   the same on every call; {"onetime": true} the one-time form; z_listaddresses lists them.
2. Receiving: a deposit from node 0's transparent coins to the account's one-time address (on-chain
   request); a payment from account A to account B's short address with a memo, which A queues until
   the scheduled sync resolves it and B finds through the two hosts at its scheduled sync.
3. Balances and history: z_getbalance, z_gettotalbalance ("yugen"), z_listunspent ("pool": "yugen"),
   z_listreceivedbyaddress (memoStr), listtransactions and gettransaction; pending before the anchor,
   spendable after. Spending from the account with z_sendmany: Yugen -> Yugen (above), Yugen ->
   transparent (withdrawal through the turnstile) and Yugen -> Sapling (withdrawal + hop), one call each.
4. Backup: z_exportwallet writes the yugenseed line; with the account's state removed, z_importwallet
   restores it and the chain scan and host sync rebuild the balance; z_getnewaddress "yugen" returns the
   same address; a restart with -rescan rebuilds the same balance.

YW_PART=sapling-backup skips 2b and the withdrawal (a run on a 30-minute limit cannot hold all of it; the
full run proves 4 transfers and exceeds it on this machine).
Env: ZCASHD, YEWD_YUGEN (yewd-yugen), YUGEN_SENDBUILD, YUGEN_LEAFVERIFY, HOSTD. Proves 4 leaf transfers
(both systems each): need more than 6 GB and up to 20 GB of memory.
"""

import os
import shutil
import subprocess
import time
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID, assert_equal, connect_nodes_bi, nuparams, rpc_auth_pair, rpc_port,
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
HOST_PORTS = [33400, 33401]
HOSTS = ','.join('127.0.0.1:%d' % p for p in HOST_PORTS)
ARGS = list(YCASH_UPGRADE_ARGS) + [
    nuparams(VAULT_BRANCH_ID, 16), nuparams(YUGEN_BRANCH_ID, 32), '-yugenverifier=' + LEAFVERIFY,
    '-yugenbuilder=' + SENDBUILD, '-yugenprover=' + WALLET, '-yugenhosts=' + HOSTS, '-yugensyncdelay=0',
    '-experimentalfeatures', '-debug=yugen']
FEE = 100000 + 155600     # BASE_FEE + LEAF_PROOF_FEE (spec 0.5.2 §2)
HOP_FEE = 1000            # Y-W9 / N-A3


def zat(x):
    return int((Decimal(x) * 100000000).to_integral_value())


class YugenWalletTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.hosts = []

    def setup_network(self, split=False):
        global ARGS
        ARGS = ARGS + ['-exportdir=' + os.path.join(self.options.tmpdir, 'export')]
        self.nodes = start_nodes(2, self.options.tmpdir, [ARGS] * 2)
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

    def stop_hosts(self):
        for h in self.hosts:
            h.terminate()
            try:
                h.wait(10)
            except subprocess.TimeoutExpired:
                h.kill()

    def mine(self, n=1):
        sync_mempools(self.nodes)
        self.nodes[0].generate(n)
        sync_blocks(self.nodes, wait=0.2)
        time.sleep(0.5)            # the hosts index new blocks (poll 300 ms)

    def mine_to(self, h):
        if self.nodes[0].getblockcount() < h:
            self.mine(h - self.nodes[0].getblockcount())

    def next_boundary(self):
        return (self.nodes[0].getblockcount() // 16 + 1) * 16

    def wait_for(self, what, f, timeout=900, mine_every=None):
        t0 = time.time()
        while time.time() - t0 < timeout:
            v = f()
            if v:
                return v
            time.sleep(2)
            if mine_every:
                self.mine(1)
        raise AssertionError('timed out waiting for ' + what)

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

    def anchored(self, node, addr, want):
        """Mines until `addr`'s spendable balance reaches `want` (the note under the wallet's anchor)."""
        def ok():
            return zat(node.z_getbalance(addr)) >= want
        return self.wait_for('spendable %d at %s' % (want, addr), ok, timeout=600, mine_every=True)

    def run_test(self):
        n0, n1 = self.nodes
        try:
            self.body(n0, n1)
        finally:
            self.stop_hosts()

    def body(self, n0, n1):
        self.mine(140)

        # 1. addresses
        a = n0.z_getnewaddress('yugen')
        assert a.startswith('yqrf'), a
        assert_equal(n0.z_getnewaddress('yugen'), a)
        a1 = n0.z_getnewaddress('yugen', {'onetime': True})
        assert a1.startswith('yqrf') and a1 != a and len(a1) > len(a), a1
        b = n1.z_getnewaddress('yugen')
        assert b.startswith('yqrf') and b != a
        assert a in n0.z_listaddresses() and a1 in n0.z_listaddresses()
        assert_equal(n0.z_gettotalbalance()['yugen'], '0.00')
        print('1 addresses: %s / one-time %d chars' % (a, len(a1)))

        # 2a. deposit: node 0's transparent coins -> the account's one-time address (z_sendmany, N-S1)
        t0 = n0.getnewaddress()
        n0.sendtoaddress(t0, 10)
        self.mine(1)
        dep = self.wait_op(n0, n0.z_sendmany(t0, [{'address': a1, 'amount': 5}], 1))
        dtx = dep['txid']
        self.mine(1)
        # pending until the note is under the wallet's anchor
        assert_equal(zat(n0.z_getbalance(a, 0)), zat(5))
        self.anchored(n0, a, zat(5))
        tb = n0.z_gettotalbalance()
        assert_equal(zat(tb['yugen']), zat(5))
        assert zat(tb['total']) == zat(tb['transparent']) + zat(tb['private']) + zat(5)
        u = [r for r in n0.z_listunspent(0) if r.get('pool') == 'yugen']
        assert_equal(len(u), 1)
        assert_equal(u[0]['txid'], dtx)
        assert u[0]['spendable']
        assert_equal(n0.z_listunspent(0, 9999999, False, [a]), u)
        lt = [r for r in n0.listtransactions('*', 100) if r.get('pool') == 'yugen']
        assert any(r['txid'] == dtx and r['category'] == 'receive' and zat(r['amount']) == zat(5) for r in lt), lt
        assert_equal(n0.gettransaction(dtx)['yugen']['amountZat'], zat(5))
        # 6: Yugen rows are merged by confirmations, then paged by from/count
        full = n0.listtransactions('*', 1000)
        assert_equal(n0.listtransactions('*', 3), full[-3:])
        assert_equal(n0.listtransactions('*', 3, 2), full[-5:-2])
        confs = [r['confirmations'] for r in full if 'confirmations' in r]
        assert confs == sorted(confs, reverse=True), confs
        assert len(n0.listtransactions('*', 1)) == 1
        print('2a deposit %s: balance 5, listings ok' % dtx)

        a_now = zat(5)
        if os.environ.get('YW_PART') != 'sapling-backup':
            a_now = self.part_b(n0, n1, a, b)
        self.part_c(n0, n1, a, a_now)

    def part_b(self, n0, n1, a, b):
        # 2b + 3. A -> B's short address with a memo: queued (pending) until the scheduled sync resolves it
        memo = 'yugen wallet memo'
        op = n0.z_sendmany(a, [{'address': b, 'amount': 1, 'memo': memo.encode().hex()}])
        st = n0.z_getoperationstatus([op])[0]
        print('2b A -> B queued: status %s' % st['status'])
        self.mine_to(self.next_boundary())
        sent = self.wait_op(n0, op)
        atx = sent['txid']
        self.mine(1)
        # B finds it through the hosts at its own scheduled sync (the next boundary after the block)
        self.mine_to(self.next_boundary())

        def b_has():
            rows = n1.z_listreceivedbyaddress(b, 0)
            return [r for r in rows if r['txid'] == atx]
        rows = self.wait_for('B receives through the hosts', b_has, timeout=600, mine_every=True)
        assert_equal(rows[0].get('memoStr'), memo)
        assert_equal(zat(rows[0]['amount']), zat(1))
        self.anchored(n1, b, zat(1))
        assert_equal(zat(n1.z_gettotalbalance()['yugen']), zat(1))
        a_after = zat(5) - zat(1) - FEE
        self.anchored(n0, a, a_after)
        assert_equal(zat(n0.z_getbalance(a)), a_after)
        lt = [r for r in n0.listtransactions('*', 100) if r.get('pool') == 'yugen' and r['txid'] == atx]
        assert any(r['category'] == 'send' and zat(r['amount']) == -zat(1) for r in lt), lt
        print('2b A -> B %s with memo: ok' % atx)

        # 3. withdrawal A -> transparent (turnstile)
        t1 = n1.getnewaddress()
        pool0 = n0.yugen_getinfo()['pool_balance_zat']
        w = self.wait_op(n0, n0.z_sendmany(a, [{'address': t1, 'amount': Decimal('0.5')}]))
        self.mine(1)
        assert_equal(zat(n1.getreceivedbyaddress(t1, 0)), zat('0.5'))
        assert_equal(n0.yugen_getinfo()['pool_balance_zat'], pool0 - zat('0.5') - FEE)
        print('3 withdrawal %s: ok' % w['txid'])

        return a_after - zat('0.5') - FEE

    def part_c(self, n0, n1, a, a_now):
        # 3. Yugen -> Sapling in one call (withdraw + hop)
        z1 = n1.z_getnewaddress('sapling')
        self.anchored(n0, a, a_now)
        r = self.wait_op(n0, n0.z_sendmany(a, [{'address': z1, 'amount': Decimal('0.3'), 'memo': b'to sapling'.hex()}]))
        assert r['withdraw_txid'] and r['sapling_txid']
        # node 0 mines both (the Sapling leg spends the unconfirmed withdrawal; node 1 may not relay the chain)
        assert r['withdraw_txid'] in n0.getrawmempool() and r['sapling_txid'] in n0.getrawmempool()
        n0.generate(1)
        sync_blocks(self.nodes)
        self.mine(1)
        assert_equal(zat(n1.z_getbalance(z1, 0)), zat('0.3'))
        a_now -= zat('0.3') + HOP_FEE + FEE
        self.anchored(n0, a, a_now)
        print('3 Yugen -> Sapling %s: ok; A balance %d' % (r['sapling_txid'], a_now))

        # 4. backup and restore
        dump = n0.z_exportwallet('yugenbackup')
        txt = open(dump).read()
        assert 'yugenseed=' in txt
        print('dump line:', [l[:40] for l in txt.splitlines() if 'yugen' in l])
        stop_node(n0, 0)
        ydir = os.path.join(self.options.tmpdir, 'node0', 'regtest', 'yugenwallet')
        shutil.rmtree(ydir)
        self.nodes[0] = n0 = start_node(0, self.options.tmpdir, ARGS)
        connect_nodes_bi(self.nodes, 0, 1)
        assert 'yugen' in n0.z_gettotalbalance() and n0.z_gettotalbalance()['yugen'] == '0.00'
        n0.z_importwallet(dump)
        assert_equal(n0.z_getnewaddress('yugen'), a)      # same seed, same address
        self.mine_to(self.next_boundary())
        self.anchored(n0, a, a_now)
        assert_equal(zat(n0.z_getbalance(a)), a_now)
        print('4 restore from z_exportwallet: balance %d rebuilt' % a_now)

        stop_node(n0, 0)
        self.nodes[0] = n0 = start_node(0, self.options.tmpdir, ARGS + ['-rescan'])
        connect_nodes_bi(self.nodes, 0, 1)
        self.mine_to(self.next_boundary())
        self.anchored(n0, a, a_now)
        assert_equal(zat(n0.z_getbalance(a)), a_now)
        print('4 -rescan: balance %d rebuilt' % a_now)


if __name__ == '__main__':
    YugenWalletTest().main()
