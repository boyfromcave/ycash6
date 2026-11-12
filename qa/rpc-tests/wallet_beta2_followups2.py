#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Beta2 wallet follow-ups, second round (one script, byte-identical on ycash-dd and ycash6):

- lock lifetime (audit L-1): a vault lock the mempool accepted, funded by default (Fund), "from" a transparent
  address or "from" a post-quantum address, holds no coin lock: the wallet counts its inputs as spent by an
  unconfirmed transaction (neither listed unspent nor locked) until it is mined; a lock "from" a Sapling address (the
  one shape with an expiry) holds no note lock either: its note is spent while the lock waits and, when the lock
  expires unmined on a node that saw no block with it, the note funds a new lock; a coin locked with lockunspent
  stays locked throughout;
- z_validateaddress answers for a post-quantum address (audit L-4) with validateaddress's post-quantum fields, for
  this wallet's key and another wallet's, and still refuses the pre-D-9 text; a Sapling address is answered as before;
- z_sendmany from a post-quantum address with an explicit fee above the post-quantum cap and above the sum of the
  outputs gets the cap message on both lines (audit L-5);
- yed_mint's preflight (YEW-FIX item 5): a wallet that cannot fund the whole mint (collateral, fees, the carrier) is
  refused before anything is broadcast, for the default source, a transparent "from" and a Sapling "from"; with
  enough at the transparent address the mint goes through; a post-quantum "from" is refused as before;
- the YEC inputs of an accepted carrier that then expires unmined are handed back without a further YED build (L-1
  for the Yellowback wallet's locks).

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/wallet_beta2_followups2.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

import re
import time
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID,
    SHIELDING_SEND_FEE,
    assert_equal,
    connect_nodes_bi,
    nuparams,
    start_nodes,
    sync_blocks,
    sync_mempools,
    wait_and_assert_operationid_status,
)
from test_framework.pq_address import decode_pq_address, encode_legacy_pq_address
from test_framework.yellowback_util import activate_yed_late, mint_to_fresh_holder

ACTIVATION = 205
FALCON = 225
DELAY = 5
EXPIRY_BLOCKS = 25          # past the default expiry of a Sapling-funded lock (next block + 20)
CARRIER_EXPIRY_BLOCKS = 45  # past a carrier's expiry (R + REF_WINDOW 40)
MINT_CENTS = 1000000        # a collateral no wallet of the run can cover from the drained node
SMALL_CENTS = 10000
LOCK_BLOCKS = 48


def assert_raises_rpc(code, substr, fn, *args):
    try:
        fn(*args)
    except JSONRPCException as e:
        assert substr in e.error['message'], 'expected %r in %r' % (substr, e.error['message'])
        if code is not None:
            assert_equal(e.error['code'], code)
        return e.error['message']
    raise AssertionError('expected an RPC error containing %r' % substr)


def zat(x):
    return int((Decimal(x) * 100000000).to_integral_value())


def outpoints(entries):
    return {(e['txid'], e['vout']) for e in entries}


def wait_until(predicate, what, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.25)
    raise AssertionError('timed out waiting for: ' + what)


class WalletBeta2Followups2Test(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 3
        self.setup_clean_chain = False

    def node_args(self, i):
        return [nuparams(VAULT_BRANCH_ID, ACTIVATION), '-pqfalconheight=%d' % FALCON, '-debug=vault'] + \
            getattr(self, 'yed_args', {}).get(i, [])

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 extra_args=[self.node_args(i) for i in range(self.num_nodes)])
        self.connect_all()
        self.is_network_split = False
        self.sync_all()

    def connect_all(self):
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 1, 2)
        connect_nodes_bi(self.nodes, 0, 2)

    def isolate(self, i):
        """Disconnect node i from every peer (the others stay connected)."""
        for p in self.nodes[i].getpeerinfo():
            self.nodes[i].disconnectnode(p['addr'])
        wait_until(lambda: self.nodes[i].getpeerinfo() == [], 'node %d without peers' % i)

    def rejoin(self, i):
        for j in range(self.num_nodes):
            if j != i:
                connect_nodes_bi(self.nodes, i, j)
        sync_blocks(self.nodes)

    def mine(self, n=1, miner=0):
        self.sync_all()
        hashes = self.nodes[miner].generate(n)
        self.sync_all()
        return hashes

    def params(self, amount, source=None):
        p = {'tag': 'TEST', 'setid': self.setid, 'delay': DELAY, 'ownerheight': self.nodes[0].getblockcount() + 1000,
             'amount': amount}
        if source is not None:
            p['from'] = source
        return p

    def inputs_of(self, node, txid):
        return {(i['txid'], i['vout']) for i in node.getrawtransaction(txid, 1)['vin']}

    def run_test(self):
        n0, n1, n2 = self.nodes
        print('activation; a released set')
        self.mine(ACTIVATION - n0.getblockcount())
        self.setid = n0.set_create({'seats': 3, 'unlockthreshold': 2, 'cancelthreshold': 1, 'slashthreshold': 2,
                                    'maturity': 2, 'livenesswindow': 50, 'bondmin': 1, 'ratewindow': 20})['setid']
        self.mine(1)
        assert_equal(n0.set_getinfo(self.setid)['released'], True)
        self.validate_pq()
        self.lock_lifetime()
        self.pq_fee_cap()
        print('YED live on every node')
        activate_yed_late(self, [0, 1], ((0, 1), (1, 2), (0, 2)))
        self.mint_preflight()
        self.carrier_lock_lifetime()

    def validate_pq(self):
        """Audit L-4: z_validateaddress answers for a post-quantum address as validateaddress does."""
        print('z_validateaddress: post-quantum addresses (L-4)')
        n0, n1 = self.nodes[0], self.nodes[1]
        own = n0.getnewaddress('', 'pqslh')
        foreign = n1.getnewaddress('', 'pqslh')
        for addr, mine in ((own, True), (foreign, False)):
            v = n0.validateaddress(addr)
            z = n0.z_validateaddress(addr)
            assert_equal(z['isvalid'], True)
            assert_equal(z['address'], addr)
            assert 'pq' in (z.get('type'), z.get('address_type')), z
            assert_equal(z['ismine'], mine)
            for k in ('pqscheme', 'pqschemename', 'pqkeyhash'):
                assert_equal(z[k], v[k])
            assert_equal(z['pqscheme'], 1)
        # the pre-D-9 text of the same key stays invalid (D-9)
        _, _, scheme, keyhash = decode_pq_address(own)
        assert_equal(n0.z_validateaddress(encode_legacy_pq_address(scheme, keyhash)), {'isvalid': False})
        # Sapling: answered as before (sapling fields, ismine)
        zaddr = n0.z_getnewaddress('sapling')
        z = n0.z_validateaddress(zaddr)
        assert_equal(z['isvalid'], True)
        assert 'sapling' in (z.get('type'), z.get('address_type')), z
        assert_equal(z['ismine'], True)
        assert 'diversifier' in z and 'pqscheme' not in z, z
        assert_equal(n0.z_validateaddress('nonsense'), {'isvalid': False})

    def lock_lifetime(self):
        """Audit L-1: an accepted lock holds no coin or note lock; its inputs come back when it expires unmined."""
        print('lock lifetime (L-1): fund the sources')
        n0, n1 = self.nodes[0], self.nodes[1]
        ecc = n0.getnewaddress()
        pq = n0.getnewaddress('', 'pqslh')
        zaddr = n0.z_getnewaddress('sapling')
        shield_from = n0.getnewaddress()
        kept = n0.getnewaddress()
        n0.sendtoaddress(ecc, 10)
        n0.sendtoaddress(pq, 10)
        n0.sendtoaddress(kept, 3)
        n0.sendtoaddress(shield_from, Decimal('10.0001'))
        self.mine(1)
        opid = n0.z_sendmany(shield_from, [{'address': zaddr, 'amount': Decimal('10')}], 1, SHIELDING_SEND_FEE)
        wait_and_assert_operationid_status(n0, opid)
        self.mine(1)
        assert_equal(n0.z_getbalance(zaddr), Decimal('10'))
        # a coin the user locks stays locked through everything below
        kept_op = [(u['txid'], u['vout']) for u in n0.listunspent(1, 9999999, [kept])]
        assert_equal(len(kept_op), 1)
        n0.lockunspent(False, [{'txid': kept_op[0][0], 'vout': kept_op[0][1]}])
        locked_before = outpoints(n0.listlockunspent())
        assert kept_op[0] in locked_before

        print('locks from a transparent, a post-quantum and the default source: no coin stays locked')
        sources = {'ecc': ecc, 'pq': pq, 'default': None}
        txids = {}
        for name in ('ecc', 'pq', 'default'):
            txids[name] = n0.vault_lock(self.params(Decimal('1'), sources[name]))['txid']
            assert txids[name] in n0.getrawmempool()
            ins = self.inputs_of(n0, txids[name])
            assert ins, name
            assert_equal(outpoints(n0.listlockunspent()), locked_before)   # no lock: before, the inputs stayed locked
            assert not (ins & outpoints(n0.listunspent(0))), name          # spent by an unconfirmed wallet transaction
            assert_equal(n0.gettransaction(txids[name])['confirmations'], 0)
        self.mine(1)
        for name in ('ecc', 'pq', 'default'):
            assert_equal(n0.gettransaction(txids[name])['confirmations'], 1)
        assert_equal(outpoints(n0.listlockunspent()), locked_before)

        print('a Sapling lock (default expiry) on an isolated node 0: its note is spent while it waits, back once it expires')
        self.isolate(0)
        ztx = n0.vault_lock(self.params(Decimal('1'), zaddr))['txid']
        assert ztx in n0.getrawmempool()
        assert_equal(n0.z_getbalance(zaddr, 0), Decimal('0'))   # the note is spent by the unconfirmed lock
        assert_equal(n0.getrawtransaction(ztx, 1)['vin'], [])
        n1.generate(EXPIRY_BLOCKS)                                  # node 1 mines without it
        self.rejoin(0)
        wait_until(lambda: ztx not in n0.getrawmempool(), 'the Sapling lock expires')
        wait_until(lambda: n0.z_getbalance(zaddr) == Decimal('10'), 'the Sapling note is unspent again')
        assert_equal(outpoints(n0.listlockunspent()), locked_before)
        print('the note funds a lock again (before: it stayed locked until a restart)')
        again = n0.vault_lock(self.params(Decimal('9.99'), zaddr))['txid']
        self.mine(1)
        assert_equal(n0.gettransaction(again)['confirmations'], 1)
        assert_equal(outpoints(n0.listlockunspent()), locked_before)
        n0.lockunspent(True, [{'txid': kept_op[0][0], 'vout': kept_op[0][1]}])

    def pq_fee_cap(self):
        """Audit L-5: the post-quantum cap message comes first on both lines."""
        print('z_sendmany from a post-quantum address, fee above the cap and above the outputs (L-5)')
        n0 = self.nodes[0]
        pq = n0.getnewaddress('', 'pqslh')
        n0.sendtoaddress(pq, 2)
        self.mine(1)
        msg = assert_raises_rpc(-8, 'cap on a post-quantum spend', n0.z_sendmany, pq,
                                [{'address': n0.getnewaddress(), 'amount': Decimal('0.1')}], 1, Decimal('5'))
        assert msg.startswith('Fee 5.00 is above the '), msg

    def mint_preflight(self):
        """YEW-FIX item 5: the whole mint is funded before its carrier is broadcast."""
        print('yed_mint preflight: an underfunded wallet broadcasts nothing')
        n0, n2 = self.nodes[0], self.nodes[2]
        coll = n2.yed_estimatecollateral(MINT_CENTS, LOCK_BLOCKS)['requiredZatFloored']
        assert coll > zat(100), coll
        bal = n2.getbalance()
        if bal > 0:
            n2.sendtoaddress(n0.getnewaddress(), bal, '', '', True)
        self.mine(1)
        a = n2.getnewaddress()
        z = n2.z_getnewaddress('sapling')
        shield_from = n0.getnewaddress()
        n0.sendtoaddress(a, 2)
        n0.sendtoaddress(shield_from, Decimal('2.0001'))
        self.mine(1)
        opid = n0.z_sendmany(shield_from, [{'address': z, 'amount': Decimal('2')}], 1, SHIELDING_SEND_FEE)
        wait_and_assert_operationid_status(n0, opid)
        self.mine(1)
        assert_equal(n2.z_getbalance(z), Decimal('2'))
        assert zat(n2.getbalance()) < coll
        locks = n2.listlockunspent()
        for src in ('', a, z):
            msg = assert_raises_rpc(-4, 'insufficient-yec: the mint needs', n2.yed_mint, MINT_CENTS, LOCK_BLOCKS, src, '', False)
            assert 'nothing was sent' in msg, msg
            # review LOW-1: the headline names the amount the dry selection checked (its trailing "need" figure)
            assert_equal(re.search(r'the mint needs ([0-9.]+) YEC', msg).group(1), re.search(r'nothing was sent: need ([0-9.]+),', msg).group(1))
            assert_equal(n2.getrawmempool(), [])
            assert_equal(n2.listlockunspent(), locks)
        assert_raises_rpc(None, 'bad-address: from', n2.yed_mint, MINT_CENTS, LOCK_BLOCKS, n2.getnewaddress('', 'pq'), '', False)
        assert_equal(n2.getrawmempool(), [])

        print('with enough at the transparent address the mint goes through')
        small = n2.yed_estimatecollateral(SMALL_CENTS, LOCK_BLOCKS)['requiredZatFloored']
        n0.sendtoaddress(a, Decimal(small) / 100000000 + 1)
        self.mine(1)
        res = n2.yed_mint(SMALL_CENTS, LOCK_BLOCKS, a, '', False)
        assert_equal(res['pending'], True)
        self.mine(1)
        wait_until(lambda: len(self.nodes[2].getrawmempool()) == 1, 'the MINT on the confirmed carrier')
        self.mine(1)
        wait_until(lambda: self.nodes[2].yed_getbalance()['confirmedCents'] == SMALL_CENTS, 'the minted YED')
        # the default source of a well-funded wallet passes the check too
        mint_to_fresh_holder(self.nodes, 0, 1)

    def carrier_lock_lifetime(self):
        """The YEC inputs of a carrier that expires unmined are handed back without another YED build."""
        print('a carrier expires unmined: its YEC inputs come back')
        n0, n1, n2 = self.nodes
        b = n2.getnewaddress()
        small = n2.yed_estimatecollateral(SMALL_CENTS, LOCK_BLOCKS)['requiredZatFloored']
        n0.sendtoaddress(b, Decimal(small) / 100000000 + 1)
        self.mine(1)
        coin = outpoints(n2.listunspent(1, 9999999, [b]))
        assert_equal(len(coin), 1)
        self.isolate(2)
        res = n2.yed_mint(SMALL_CENTS, LOCK_BLOCKS, b, '', False)
        assert_equal(res['pending'], True)
        carrier = res['carrierTxid']
        assert_equal(self.inputs_of(n2, carrier), coin)
        n1.generate(CARRIER_EXPIRY_BLOCKS)
        self.rejoin(2)
        wait_until(lambda: carrier not in self.nodes[2].getrawmempool(), 'the carrier leaves the mempool')
        wait_until(lambda: outpoints(self.nodes[2].listunspent(1, 9999999, [b])) == coin,
                   'the carrier input is spendable again', timeout=20)
        assert not (coin & outpoints(n2.listlockunspent()))


if __name__ == '__main__':
    WalletBeta2Followups2Test().main()
