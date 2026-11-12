#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
vault_lock's funding address "from" (beta2 address-interop plan, decision D-3; doc/vault-rpc.md, vault_lock):

- a lock funded from each source type of this wallet: a transparent P2PKH address, a post-quantum address of
  scheme 1 (SLH-DSA, before Falcon) and of scheme 2 (FN-DSA-512, after Falcon), and a Sapling address. For each:
  the inputs are that address's only (Sapling: notes, no transparent input), change returns to the same address
  (D-4; Sapling: one change note), the fee (10,000 zat for P2PKH; for a PQ input max(10,000, the PQ rate x size,
  the ZIP-317 conventional fee); for Sapling max(10,000, the ZIP-317 conventional fee)), the transaction is in a
  second node's mempool before it is mined, and the V is listed once mined;
- one reorg across the block that holds the PQ and Sapling locks (invalidateblock on every node, a new block): the
  locks return to the mempool and are mined again, the V outputs and the source balances are as before;
- the vault's later life from each lock: the owner spend (selector 3, a released set) of the P2PKH-, FN-DSA- and
  default-funded V; an unlock (selector 1, a one-member set) of the SLH-DSA- and Sapling-funded V into an intent,
  then its release after the delay;
- change below dust joins the fee; a PQ source whose coins would cross the input caps (400 coins / 75,000 bytes) is
  refused with its coins left unlocked and a smaller lock from it then works; a three-note Sapling lock and the
  20-note limit;
- refusals: not a string, not an address, a wallet PQ key in its pre-D-9 text (D-9), a Yellowback yr… address,
  another wallet's address, watch-only transparent and Sapling addresses, a scheme-2 address before Falcon, empty transparent / PQ / Sapling addresses, a coinbase-only
  address where coinbase must be shielded (-regtestshieldcoinbase), a locked wallet (P2PKH and Sapling "from");
- the default (no "from") is unchanged: funded from transparent P2PKH coins with change to a new address.

No address string or prefix is written here: every address comes from the node (the PQ encoding may change).

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/vault_lock_from.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID,
    assert_equal,
    bitcoind_processes,
    connect_nodes_bi,
    ONE_NOTE_SAPLING_OUTPUTS,
    SHIELDING_SEND_FEE,
    lockunspent_true,
    nuparams,
    start_node,
    start_nodes,
    stop_node,
    sync_blocks,
    sync_mempools,
    wait_and_assert_operationid_status,
)
from test_framework.pq_address import decode_pq_address, encode_legacy_pq_address
from test_framework.yellowback_util import activate_yed_late, conventional_fee, mint_to_fresh_holder

ACTIVATION = 205
FALCON = 225
DELAY = 5
VAULT_RPC_FEE = 10000
SLH_PQPKH_SCRIPTSIG = 7938       # quantum spec §2.1
PASS = 'lock-from-pass'
UNLOCK_ACK = 'I understand this burns YED'


def assert_raises_rpc(code, substr, fn, *args):
    try:
        fn(*args)
    except JSONRPCException as e:
        assert substr in e.error['message'], 'expected %r in %r' % (substr, e.error['message'])
        assert_equal(e.error['code'], code)
        return e.error['message']
    raise AssertionError('expected an RPC error containing %r' % substr)


def zat(x):
    return int((Decimal(x) * 100000000).to_integral_value())


class VaultLockFromTest(BitcoinTestFramework):

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

    def restart(self, i, extra=()):
        stop_node(self.nodes[i], i)
        self.nodes[i] = start_node(i, self.options.tmpdir, self.node_args(i) + list(extra))
        for j in range(self.num_nodes):
            if j != i:
                connect_nodes_bi(self.nodes, i, j)
        sync_blocks(self.nodes)

    def mine(self, n=1):
        self.sync_all()
        hashes = self.nodes[0].generate(n)
        self.sync_all()
        return hashes

    def params(self, amount, source=None, setid=None):
        p = {'tag': 'TEST', 'setid': setid or self.setid, 'delay': DELAY, 'ownerheight': self.nodes[0].getblockcount() + 1000,
             'amount': amount}
        if source is not None:
            p['from'] = source
        return p

    def prevout_scripts(self, tx):
        n0 = self.nodes[0]
        return [n0.getrawtransaction(i['txid'], 1)['vout'][i['vout']]['scriptPubKey']['hex'] for i in tx['vin']]

    def fee_of(self, tx):
        n0 = self.nodes[0]
        ins = sum(zat(n0.getrawtransaction(i['txid'], 1)['vout'][i['vout']]['value']) for i in tx['vin'])
        return ins + zat(tx.get('valueBalance', 0)) - sum(zat(o['value']) for o in tx['vout'])

    def in_second_mempool(self, txid):
        sync_mempools(self.nodes)
        assert txid in self.nodes[1].getrawmempool(), txid
        assert txid in self.nodes[2].getrawmempool(), txid

    def check_transparent_lock(self, r, source, amount, pq):
        """A lock funded from transparent or PQ `source`: inputs only its coins, change back to it, the fee."""
        n0 = self.nodes[0]
        spk = n0.validateaddress(source)['scriptPubKey']
        tx = n0.getrawtransaction(r['txid'], 1)
        assert_equal(r['vout'], 0)
        assert_equal(tx['vout'][0]['scriptPubKey']['hex'], r['script'])
        assert_equal(zat(tx['vout'][0]['value']), zat(amount))
        assert tx['vin'], tx
        assert_equal(set(self.prevout_scripts(tx)), {spk})
        assert_equal(len(tx['vout']), 2)                             # the V and the change
        assert_equal(tx['vout'][1]['scriptPubKey']['hex'], spk)      # D-4: change back to the source
        assert_equal(tx.get('vShieldedSpend', []), [])
        fee = self.fee_of(tx)
        if pq:
            floor = max(VAULT_RPC_FEE, conventional_fee(tx))
            assert fee >= floor, (fee, floor)
            assert fee < zat('0.01'), fee
        else:
            assert_equal(fee, VAULT_RPC_FEE)
        return tx, fee

    def run_test(self):
        n0, n1, n2 = self.nodes

        print('activation; a set with no members (released: the owner spend opens at once)')
        self.mine(ACTIVATION - n0.getblockcount())
        assert_equal(n0.vault_getinfo()['active'], True)
        self.setid = n0.set_create({'seats': 3, 'unlockthreshold': 2, 'cancelthreshold': 1, 'slashthreshold': 2,
                                    'maturity': 2, 'livenesswindow': 50, 'bondmin': 1, 'ratewindow': 20})['setid']
        self.mine(1)
        assert_equal(n0.set_getinfo(self.setid)['released'], True)
        print('a one-member set of node 0 (unlock threshold 1) for the release path (selector 1)')
        self.mset = n0.set_create({'seats': 1, 'unlockthreshold': 1, 'maturity': 2})['setid']
        self.mine(1)
        assert n0.set_join(self.mset, 1, n0.getblockcount() + 500)['complete']
        self.mine(2)
        assert_equal(n0.set_getinfo(self.mset)['released'], False)

        print('fund the sources: a P2PKH address, an SLH-DSA PQ address, a Sapling address')
        ecc = n0.getnewaddress()
        pq1 = n0.getnewaddress('', 'pqslh')
        assert_equal(n0.validateaddress(pq1)['pqscheme'], 1)
        zaddr = n0.z_getnewaddress('sapling')
        shield_from = n0.getnewaddress()
        n0.sendtoaddress(ecc, 10)
        n0.sendtoaddress(pq1, 10)
        n0.sendtoaddress(shield_from, Decimal('10.0001'))
        self.mine(1)
        opid = n0.z_sendmany(shield_from, [{'address': zaddr, 'amount': Decimal('10')}], 1, SHIELDING_SEND_FEE)
        wait_and_assert_operationid_status(n0, opid)
        self.mine(1)
        assert_equal(n0.z_getbalance(zaddr), Decimal('10'))
        # a scheme-2 key imported before Falcon (its address comes from the node)
        falcon_imported = n0.z_importpqkey('2:' + 'a7' * 48, False)['address']

        print('refusals')
        assert_raises_rpc(-8, 'from must be an address string', n0.vault_lock, self.params(1, 123))
        assert_raises_rpc(-5, 'bad-address: from: not a transparent P2PKH, post-quantum or Sapling address of this network',
                          n0.vault_lock, self.params(1, 'nonsense'))
        assert_raises_rpc(-5, 'bad-address: from: not a transparent P2PKH', n0.vault_lock,
                          self.params(1, n0.vault_getnewowner()['address']))    # the Yellowback form names an owner, not coins
        assert_raises_rpc(-5, 'from: not an address of this wallet', n0.vault_lock, self.params(1, n1.getnewaddress()))
        assert_raises_rpc(-5, 'from: not an address of this wallet', n0.vault_lock, self.params(1, n1.getnewaddress('', 'pqslh')))
        assert_raises_rpc(-5, 'from: not an address of this wallet', n0.vault_lock, self.params(1, n1.z_getnewaddress('sapling')))
        watch = n1.getnewaddress()
        n0.importaddress(watch, '', False)
        assert_raises_rpc(-4, 'from: a watch-only address of this wallet', n0.vault_lock, self.params(1, watch))
        zwatch = n1.z_getnewaddress('sapling')
        n0.z_importviewingkey(n1.z_exportviewingkey(zwatch), 'no')
        assert_raises_rpc(-4, 'from: a watch-only address of this wallet', n0.vault_lock, self.params(1, zwatch))
        assert n0.getblockcount() + 1 < FALCON
        assert_raises_rpc(-5, 'from: an FN-DSA-512 (scheme 2) address cannot be spent before Falcon is active at the next block',
                          n0.vault_lock, self.params(1, falcon_imported))
        empty = n0.getnewaddress()
        assert_raises_rpc(-6, 'insufficient confirmed funds at %s: need 1.0001 more' % empty, n0.vault_lock, self.params(1, empty))
        slh_empty = n0.getnewaddress('', 'pqslh')
        assert_raises_rpc(-6, 'insufficient confirmed funds at', n0.vault_lock, self.params(1, slh_empty))
        # D-9 clean cut: the same wallet key in its pre-D-9 text is not an address of this network
        _, _, scheme, keyhash = decode_pq_address(slh_empty)
        assert_raises_rpc(-5, 'bad-address: from: not a transparent P2PKH, post-quantum or Sapling address of this network',
                          n0.vault_lock, self.params(1, encode_legacy_pq_address(scheme, keyhash)))
        empty_z = n0.z_getnewaddress('sapling')
        assert_raises_rpc(-6, 'insufficient-yec: need 1.0001, have 0.00 in confirmed Sapling notes at %s' % empty_z,
                          n0.vault_lock, self.params(1, empty_z))
        assert_raises_rpc(-6, 'insufficient confirmed funds at', n0.vault_lock, self.params(20, ecc))   # more than it holds

        print('lock from the P2PKH address')
        r_ecc = n0.vault_lock(self.params(3, ecc))
        self.check_transparent_lock(r_ecc, ecc, 3, False)
        self.in_second_mempool(r_ecc['txid'])
        self.mine(1)
        assert_equal(zat(n0.getreceivedbyaddress(ecc, 0)), zat(10) + zat(7) - VAULT_RPC_FEE)   # 10 in, 10 - 3 - fee back

        print('lock from the SLH-DSA post-quantum address (before Falcon)')
        r_pq1 = n0.vault_lock(self.params(2, pq1, self.mset))
        tx_pq1, fee_pq1 = self.check_transparent_lock(r_pq1, pq1, 2, True)
        assert_equal(len(tx_pq1['vin'][0]['scriptSig']['hex']) // 2, SLH_PQPKH_SCRIPTSIG)
        self.in_second_mempool(r_pq1['txid'])

        print('lock from the Sapling address')
        z_before = n0.z_getbalance(zaddr)
        r_z = n0.vault_lock(self.params(4, zaddr, self.mset))
        tx_z = n0.getrawtransaction(r_z['txid'], 1)
        assert_equal(tx_z['vin'], [])
        assert_equal(len(tx_z['vout']), 1)
        assert_equal(tx_z['vout'][0]['scriptPubKey']['hex'], r_z['script'])
        assert_equal(len(tx_z['vShieldedSpend']), 1)
        assert_equal(len(tx_z['vShieldedOutput']), ONE_NOTE_SAPLING_OUTPUTS)                # the change note
        fee_z = self.fee_of(tx_z)
        assert_equal(fee_z, max(VAULT_RPC_FEE, conventional_fee(tx_z)))
        assert_equal(zat(tx_z['valueBalance']), zat(4) + fee_z)
        self.in_second_mempool(r_z['txid'])

        print('mine the PQ and Sapling locks, then reorg across that block')
        block = self.mine(1)[0]
        assert_equal(n0.getblock(block)['tx'][1:].count(r_pq1['txid']) + n0.getblock(block)['tx'][1:].count(r_z['txid']), 2)
        z_after = z_before - Decimal(zat(4) + fee_z) / 100000000
        assert_equal(n0.z_getbalance(zaddr), z_after)
        listed = {v['outpoint'] for v in n0.vault_list({'kind': 'vault'})}
        assert {r_ecc['outpoint'], r_pq1['outpoint'], r_z['outpoint']} <= listed
        for node in self.nodes:
            node.invalidateblock(block)
        for txid in (r_pq1['txid'], r_z['txid']):
            assert txid in n0.getrawmempool(), txid
        assert r_z['outpoint'] not in {v['outpoint'] for v in n0.vault_list({'kind': 'vault'})}
        n0.generate(1)
        sync_blocks(self.nodes)
        assert n0.getbestblockhash() != block
        for node in self.nodes:
            got = {v['outpoint'] for v in node.vault_list({'kind': 'vault'})}
            assert {r_ecc['outpoint'], r_pq1['outpoint'], r_z['outpoint']} <= got, node
        assert_equal(n0.z_getbalance(zaddr), z_after)
        assert_equal(n0.gettransaction(r_pq1['txid'])['confirmations'], 1)
        assert_equal(n0.gettransaction(r_z['txid'])['confirmations'], 1)

        print('after Falcon: lock from a wallet FN-DSA-512 address')
        self.mine(max(0, FALCON - n0.getblockcount()))
        pq2 = n0.getnewaddress('', 'pq')
        assert_equal(n0.validateaddress(pq2)['pqscheme'], 2)
        n0.sendtoaddress(pq2, 5)
        self.mine(1)
        r_pq2 = n0.vault_lock(self.params(1, pq2))
        tx_pq2, _ = self.check_transparent_lock(r_pq2, pq2, 1, True)
        self.in_second_mempool(r_pq2['txid'])
        self.mine(1)

        print('the default (no "from") is unchanged: P2PKH coins, change to a new address')
        r_def = n0.vault_lock(self.params(1))
        tx_def = n0.getrawtransaction(r_def['txid'], 1)
        assert_equal(self.fee_of(tx_def), VAULT_RPC_FEE)
        for s in self.prevout_scripts(tx_def):
            assert s.startswith('76a914') and s.endswith('88ac'), s
        self.mine(1)

        print('the later life of each V: the owner spend (selector 3) of the vaults of the released set')
        dest = n0.getnewaddress()
        for r in (r_ecc, r_pq2, r_def):
            sp = n0.vault_ownerspend(r['outpoint'], dest)
            assert_equal(sp['selector'], 3)
            self.in_second_mempool(sp['txid'])
        self.mine(1)
        for r in (r_ecc, r_pq2, r_def):
            assert_equal(n0.gettxout(r['txid'], 0), None)

        print('the PQ- and Sapling-funded vaults of the member set: unlock (selector 1) into an intent, then release')
        payee = n1.getnewaddress()
        intents = []
        for r, amt in ((r_pq1, 1), (r_z, 3)):
            bu = n0.vault_buildunlock(r['outpoint'], [{'address': payee, 'amount': amt}])
            signed = n0.set_signunlock(bu['hex'])
            utx = n0.vault_send(signed['hex'])
            self.in_second_mempool(utx)
            intents.append('%s:%d' % (utx, bu['intents'][0]['vout']))
        self.mine(1)
        for r in (r_pq1, r_z):
            assert_equal(n0.gettxout(r['txid'], 0), None)
        assert_raises_rpc(-1, 'matures at height', n0.vault_release, intents[0])
        self.mine(DELAY)
        before = n1.getreceivedbyaddress(payee)
        for op in intents:
            self.in_second_mempool(n0.vault_release(op))
        self.mine(1)
        assert_equal(n1.getreceivedbyaddress(payee) - before, Decimal('4'))

        print('change below dust joins the fee (P2PKH)')
        dusty = n0.getnewaddress()
        n0.sendtoaddress(dusty, Decimal('1.00010500'))
        self.mine(1)
        r_d = n0.vault_lock(self.params(1, dusty))
        tx_d = n0.getrawtransaction(r_d['txid'], 1)
        assert_equal(len(tx_d['vout']), 1)
        assert_equal(self.fee_of(tx_d), VAULT_RPC_FEE + 500)
        self.mine(1)

        print('a PQ source whose coins would cross the input caps: refused, coins left free, a smaller lock works')
        many = n0.getnewaddress('', 'pqslh')
        for _ in range(10):
            n0.sendtoaddress(many, 1)
        self.mine(1)
        locked_before = n0.listlockunspent()
        assert_raises_rpc(-4, 'from: too-many-coins: covering 9.5001 at %s' % many, n0.vault_lock, self.params(Decimal('9.5'), many))
        assert_equal(n0.listlockunspent(), locked_before)
        r_many = n0.vault_lock(self.params(2, many))
        tx_many = n0.getrawtransaction(r_many['txid'], 1)
        assert_equal(len(tx_many['vin']), 3)
        assert self.fee_of(tx_many) >= max(VAULT_RPC_FEE, conventional_fee(tx_many))
        self.in_second_mempool(r_many['txid'])
        self.mine(1)

        print('a multi-note Sapling lock, and the 20-note limit')
        zmulti = n0.z_getnewaddress('sapling')
        feeders = [n0.getnewaddress() for _ in range(21)]
        n0.sendmany('', {a: Decimal('0.1001') for a in feeders})
        self.mine(1)
        for a in feeders:
            opid = n0.z_sendmany(a, [{'address': zmulti, 'amount': Decimal('0.1')}], 1, SHIELDING_SEND_FEE)
            wait_and_assert_operationid_status(n0, opid)
        self.mine(1)
        assert_equal(n0.z_getbalance(zmulti), Decimal('2.1'))
        assert_raises_rpc(-6, 'too-many-notes: the transaction would spend 21 Sapling notes (limit 20)',
                          n0.vault_lock, self.params(Decimal('2.05'), zmulti))
        r_multi = n0.vault_lock(self.params(Decimal('0.25'), zmulti))
        tx_multi = n0.getrawtransaction(r_multi['txid'], 1)
        assert_equal(len(tx_multi['vShieldedSpend']), 3)
        assert_equal(self.fee_of(tx_multi), max(VAULT_RPC_FEE, conventional_fee(tx_multi)))
        self.in_second_mempool(r_multi['txid'])
        self.mine(1)
        assert_equal(n0.z_getbalance(zmulti), Decimal('2.1') - Decimal('0.25') - Decimal(self.fee_of(tx_multi)) / 100000000)

        self.token_protection()

        print('a coinbase-only address where coinbase must be shielded')
        mature = [u for u in n0.listunspent() if u['generated'] and u['confirmations'] > 100]
        by_addr = {}
        for u in n0.listunspent(0):
            by_addr.setdefault(u.get('address'), []).append(u['generated'])
        cb_addr = [u['address'] for u in mature if all(by_addr[u['address']])][0]
        self.restart(0, ['-regtestshieldcoinbase'])
        n0 = self.nodes[0]
        msg = assert_raises_rpc(-6, 'insufficient confirmed funds at %s' % cb_addr, n0.vault_lock, self.params(1, cb_addr))
        assert 'of coinbase outputs must be shielded first: z_shieldcoinbase' in msg, msg

        print('a locked wallet')
        enc = ['-experimentalfeatures', '-developerencryptwallet']
        self.restart(2, enc)
        n2 = self.nodes[2]
        own2 = n2.getnewaddress()
        own2z = n2.z_getnewaddress('sapling')
        n2.encryptwallet(PASS)
        bitcoind_processes[2].wait()
        self.nodes[2] = start_node(2, self.options.tmpdir, self.node_args(2) + enc)
        n2 = self.nodes[2]
        assert_raises_rpc(-13, 'walletpassphrase', n2.vault_lock, self.params(1, own2))
        assert_raises_rpc(-13, 'walletpassphrase', n2.vault_lock, self.params(1, own2z))
        print('ok')

    def token_protection(self):
        """A YED token at a post-quantum holder key never funds a lock as plain YEC. The Yellowback wallet layer locks
        every token output (consensus would accept a plain spend of one and burn its YED): vault_lock "from" the
        holder key of a fresh mint (a Falcon key; it holds nothing but the token) finds no coins, with the locks in
        place and after `lockunspent true`; with the lock removed on purpose (yed_unlockcoin) the second check
        refuses the outpoint by name while the key holds nothing else, and once the key also holds plain YEC the lock
        is funded from those coins without the token."""
        print('token protection: YED live on every node, a mint to a fresh Falcon holder key')
        activate_yed_late(self, [0, 1], ((0, 1), (1, 2), (0, 2)))
        n0 = self.nodes[0]
        assert n0.getblockcount() + 1 >= FALCON
        _, op, key = mint_to_fresh_holder(self.nodes, 0, 1)
        assert_equal(n0.validateaddress(key)['pqscheme'], 2)
        assert_equal(n0.getreceivedbyaddress(key, 0), Decimal('0.0001'))      # the token only (10,000 zat)
        before = n0.yed_getbalance()['confirmedCents']
        outpoint = {'txid': op[0], 'vout': op[1]}
        for unlock_all in (False, True):
            if unlock_all:
                lockunspent_true(n0)
            assert outpoint in n0.listlockunspent()
            for amount in (Decimal('0.5'), 1):
                assert_raises_rpc(-6, 'insufficient confirmed funds at %s' % key, n0.vault_lock, self.params(amount, key))
            assert outpoint in n0.listlockunspent()
            assert_equal(n0.yed_getbalance()['confirmedCents'], before)
        r = n0.yed_unlockcoin(op[0], op[1], UNLOCK_ACK)
        assert_equal((r['wasYellowbackLocked'], r['cents']), (True, before))
        assert outpoint not in n0.listlockunspent()
        msg = assert_raises_rpc(-4, 'from: refusing to spend a Yellowback outpoint as plain YEC: %s:%d' % op,
                                n0.vault_lock, self.params(1, key))
        # review M-1: the hint names the call that locks it again (`lockunspent true` would not)
        assert_equal(msg, 'from: refusing to spend a Yellowback outpoint as plain YEC: %s:%d' % op +
                     ' (its YED would burn; lock it again with yed_lockcoins)')
        # audit L-ii: the key also holds plain YEC; with its token unlocked the lock is funded from the plain coins
        # alone (signed once, with no lock held: audit A-M1), and the token is left alone
        n0.sendtoaddress(key, Decimal('2'))
        self.mine(1)
        r = n0.vault_lock(self.params(1, key))
        assert op not in [(i['txid'], i['vout']) for i in n0.getrawtransaction(r['txid'], 1)['vin']]
        self.mine(1)
        n0.yed_lockcoins()
        assert outpoint in n0.listlockunspent()
        assert_equal(n0.yed_getbalance()['confirmedCents'], before)
        assert_equal(n0.gettxout(op[0], op[1])['value'], Decimal('0.0001'))


if __name__ == '__main__':
    VaultLockFromTest().main()
