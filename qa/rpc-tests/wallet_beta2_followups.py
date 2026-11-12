#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Wallet follow-ups found during beta2 (wt list items 21, 41, 44), one case each:

- topup_balance (review L-6 / LOW-3): a payment to a post-quantum key that only a later lookahead top-up makes this
  wallet's. The transaction that pays it is already in the wallet (it also pays an ECC address of the wallet) and its
  credit is cached; a second payment, to the last key of the lookahead, moves the lookahead past the first key. After
  that, getbalance (cached) == getwalletinfo.balance (fresh) == balance_ecc + balance_pq.
- vault_funding (list item 21b): the vault RPCs' default funding (Fund) (i) never selects a coinbase output where
  coinbase must be shielded (refused up front, naming z_shieldcoinbase), (ii) prices the fee from the size, never
  below 10,000 zat, (iii) releases the coins it locked when the broadcast is refused.
- note_locks (list item 21c): a yed_mint funded from a Sapling address locks the notes it selected while its proofs
  run with no lock held, so a z_sendmany from the same address meanwhile is refused for want of notes (it used to
  select the same note, and one of the two failed late).
- ecc_send (audit M-1, list item 21d, review L-4): sendtoaddress / sendmany select ordinary (ECC) coins only; with
  too few of them and post-quantum coins in the wallet they are refused, naming the PQ value and z_sendmany; an
  ECC send's inputs and change are ECC and leave the post-quantum balance as it was. fundrawtransaction adds ECC coins
  only (review LOW-1); a post-quantum input the transaction names stays.
- vault_funding (iv) (review LOW-4): a vault RPC that fails after its funding (set_buildact of an unknown set) releases
  the coins it locked in that call, and never a coin locked with lockunspent.
- allowinputs_guard (audit L-3): vault_send / set_sendact never sign a YED token named in allowinputs.
- asof_cache (review LOW-8, 6.x only): getbalance asOfHeight leaves the cached credit alone, so a later getbalance
  equals getwalletinfo.balance.

Node 0 runs on a fresh wallet file (no coinbase of its own); node 1 mines and pays. The keys ahead of node 0's
lookahead are issued by a copy of node 0's wallet taken before any post-quantum key was issued (same HD seed).

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/wallet_beta2_followups.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>

One file on both C++ lines (ycash-dd: BITCOIND=, ycash6: ZCASHD=).
"""

import os
import re
import shutil
import threading
import time
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID,
    assert_equal,
    connect_nodes_bi,
    get_rpc_proxy,
    nuparams,
    rpc_url,
    start_node,
    start_nodes,
    stop_node,
    sync_blocks,
    sync_mempools,
    wait_and_assert_operationid_status,
    z_sendmany_opid,
    z_sendmany_wait,
)
from test_framework.yellowback_util import MIN_MINT, activate_yed_late

ACTIVATION = 210
PQ_KEY_LOOKAHEAD = 20      # src/wallet/wallet.h


def D(x):
    return Decimal(str(x))


def assert_raises_rpc(substr, fn, *args):
    try:
        fn(*args)
    except JSONRPCException as e:
        assert substr in e.error['message'], 'expected %r in %r' % (substr, e.error['message'])
        return e.error['message']
    raise AssertionError('expected an RPC error containing %r' % substr)


class WalletBeta2FollowupsTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = False

    def node_args(self, i, wallet='followups.dat', extra=()):
        a = [nuparams(VAULT_BRANCH_ID, ACTIVATION), '-pqfalcon=1']
        if i == 0:
            a += ['-wallet=%s' % wallet, '-exportdir=%s' % os.path.join(self.options.tmpdir, 'export0')]
        return a + getattr(self, 'yed_args', {}).get(i, []) + list(extra)

    def restart(self, i, wallet='followups.dat', extra=()):
        stop_node(self.nodes[i], i)
        self.nodes[i] = start_node(i, self.options.tmpdir, self.node_args(i, wallet, extra))
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)

    def setup_network(self, split=False):
        os.makedirs(os.path.join(self.options.tmpdir, 'export0'), exist_ok=True)
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 extra_args=[self.node_args(i) for i in range(self.num_nodes)])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def mine(self, n=1):
        self.sync_all()
        self.nodes[1].generate(n)
        self.sync_all()

    def balances(self, node):
        """getbalance, getwalletinfo.balance and its split; asserts they agree. getbalance is read first: it reads the
        transactions' cached credit, which getwalletinfo's fresh count would rewrite."""
        cached = D(node.getbalance())
        w = node.getwalletinfo()
        total, ecc, pq = D(w['balance']), D(w['balance_ecc']), D(w['balance_pq'])
        assert_equal(total, ecc + pq)
        assert_equal(cached, total)
        return total, ecc, pq

    # ---- item 1: the lookahead top-up and the balance cache ------------------------------------------------------

    def topup_balance(self):
        n0, n1 = self.nodes
        print('topup_balance: a key beyond the lookahead, made this wallet\'s by a top-up after its payment arrived')
        regtest = os.path.join(self.options.tmpdir, 'node0', 'regtest')
        n0.backupwallet('followupsseed')             # the HD seed and the lookahead, no PQ key issued yet
        backup = os.path.join(self.options.tmpdir, 'export0', 'followupsseed')
        shutil.copyfile(backup, os.path.join(regtest, 'followups-ahead.dat'))
        self.restart(0, 'followups-ahead.dat')
        ahead = [self.nodes[0].getnewaddress('', 'pq') for _ in range(PQ_KEY_LOOKAHEAD + 1)]
        self.restart(0)
        n0 = self.nodes[0]
        for a in ahead[:PQ_KEY_LOOKAHEAD]:
            assert n0.validateaddress(a)['ismine'], 'expected %s in the lookahead' % a
        beyond = ahead[PQ_KEY_LOOKAHEAD]
        assert not n0.validateaddress(beyond)['ismine']

        ecc = n0.getnewaddress()
        tx1 = n1.sendmany('', {ecc: 1, beyond: 2})
        self.mine()
        assert_equal(self.balances(n0), (D(1), D(1), D(0)))   # the credit of that transaction is cached now

        # The second payment must not spend the first one's change: spending an output of a wallet transaction marks
        # that transaction dirty (MarkAffectedTransactionsDirty), which would hide the stale cache.
        change1 = [{'txid': u['txid'], 'vout': u['vout']} for u in n1.listunspent(0) if u['txid'] == tx1]
        n1.lockunspent(False, change1)
        n1.sendtoaddress(ahead[PQ_KEY_LOOKAHEAD - 1], 3)    # marks the last key used: the lookahead moves past `beyond`
        n1.lockunspent(True, change1)
        self.mine()
        assert n0.validateaddress(beyond)['ismine']
        assert_equal(self.balances(n0), (D(6), D(1), D(5)))
        self.restart(0)
        assert_equal(self.balances(self.nodes[0]), (D(6), D(1), D(5)))

    # ---- item 2: the vault RPCs' default funding (Fund) -----------------------------------------------------------

    def fee_of(self, node, txid):
        tx = node.getrawtransaction(txid, 1)
        ins = sum(D(node.getrawtransaction(i['txid'], 1)['vout'][i['vout']]['value']) for i in tx['vin'])
        return tx, ins - sum(D(o['value']) for o in tx['vout'])

    def unspent_locked(self):
        """Node 0's locked coins that are still unspent (Fund's locks on coins a broadcast spent stay listed)."""
        n0 = self.nodes[0]
        return [c for c in n0.listlockunspent() if n0.gettxout(c['txid'], c['vout'], True) is not None]

    def vault_funding(self):
        print('vault_funding: the default funding of the vault RPCs (Fund)')
        self.restart(0, 'fund.dat', ['-regtestshieldcoinbase'])
        n0, n1 = self.nodes
        set_params = {'seats': 1, 'unlockthreshold': 1, 'maturity': 2}
        n0.generate(101)                              # node 0's own coinbase, mature; nothing else in this wallet
        self.sync_all()
        assert_equal(n0.listlockunspent(), [])
        print('(i) coinbase is never a fee coin where it must be shielded: refused up front, nothing locked')
        msg = assert_raises_rpc('insufficient confirmed transparent funds', n0.set_create, set_params)
        assert 'of coinbase outputs must be shielded first: z_shieldcoinbase' in msg, msg
        assert_equal(n0.listlockunspent(), [])

        print('(ii) the fee follows the size: max(10,000 zat, the relay fee, the ZIP-317 conventional fee)')
        # a second fresh wallet, without -regtestshieldcoinbase (node 1's payments spend coinbase: node 0 relays them)
        self.restart(0, 'fund2.dat')
        n0 = self.nodes[0]
        small = [n0.getnewaddress() for _ in range(25)]
        n1.sendmany('', {a: Decimal('0.01') for a in small})
        self.mine()
        setid = n0.set_create(set_params)['setid']   # one input: the 10,000 zat floor, as before
        _, fee = self.fee_of(n0, setid)
        assert_equal(fee, Decimal('0.0001'))
        self.mine()
        lock = {'tag': 'TEST', 'setid': setid, 'delay': 10, 'ownerheight': n0.getblockcount() + 1000,
                'amount': Decimal('0.2')}
        txid = n0.vault_lock(lock)['txid']
        tx, fee = self.fee_of(n0, txid)
        n_in = len(tx['vin'])
        assert n_in > 20, n_in
        assert_equal(fee, Decimal(500 * n_in) / 10**8)   # ZIP-317: one action per 150-byte P2PKH input, 500 zat each
        self.mine()
        assert_equal(self.unspent_locked(), [])

        print('(iii) a refused broadcast leaves the coins it selected unlocked')
        self.restart(0, 'fund2.dat', ['-maxtxfee=0.0001'])   # the vault/Yellowback cap falls to 10,000 zat
        n0 = self.nodes[0]
        n1.sendmany('', {a: Decimal('0.01') for a in small})
        self.mine()
        lock['ownerheight'] = n0.getblockcount() + 1000
        assert_raises_rpc('absurdly-high-fee', n0.vault_lock, lock)
        assert_equal(self.unspent_locked(), [])
        lock['amount'] = Decimal('0.001')           # one input: within the cap, and the coins are still free to use
        n0.vault_lock(lock)
        self.mine()

        print('(iv) any failure after the funding releases what it locked in that call, and nothing else (review LOW-4)')
        mine = n0.listunspent()[0]
        user_lock = {'txid': mine['txid'], 'vout': mine['vout']}
        assert n0.lockunspent(False, [user_lock])
        assert_raises_rpc('unknown set', n0.set_buildact, 'winddown', {'setid': '11' * 32})   # funded, then refused
        assert_equal(self.unspent_locked(), [user_lock])
        assert n0.lockunspent(True, [user_lock])
        self.restart(0)

    # ---- item 3: yed_mint holds its Sapling notes ----------------------------------------------------------------

    def note_locks(self):
        print('note_locks: Yellowback live; a yed_mint from a Sapling address and a z_sendmany from it at the same time')
        self.nodes[1].sendtoaddress(self.nodes[0].getnewaddress(), 1)   # set_create (the attestor set) funds from node 0
        self.mine()
        activate_yed_late(self, [1], ((0, 1),))
        n0, n1 = self.nodes
        taddr, z = n0.getnewaddress(), n0.z_getnewaddress('sapling')
        n1.sendtoaddress(taddr, 21)
        self.mine()
        z_sendmany_wait(n0, taddr, [{'address': z, 'amount': 20}])   # one note of 20 YEC
        self.mine()
        result = {}

        def mint():
            try:
                rpc = get_rpc_proxy(rpc_url(0), 0, timeout=600)
                result['mint'] = rpc.yed_mint(MIN_MINT, 48, z, '', False)
            except Exception as e:
                result['error'] = e

        t = threading.Thread(target=mint)
        t.start()
        time.sleep(0.3)
        assert t.is_alive(), 'yed_mint returned before the second call: %r' % result   # still proving
        err = None
        try:
            z_sendmany_wait(n0, z, [{'address': taddr, 'amount': 1}])
        except (JSONRPCException, AssertionError) as e:
            err = e.error['message'] if isinstance(e, JSONRPCException) else str(e)
        t.join()
        assert 'error' not in result, result
        assert_equal(result['mint']['pending'], True)
        assert err is not None and 'nsufficient' in err, err   # the note was held by yed_mint, not selected twice
        sync_mempools(self.nodes)
        assert result['mint']['carrierTxid'] in n1.getrawmempool()
        self.mine(2)                                  # the carrier, then the MINT the wallet commits on it
        self.mine()

    # ---- audit L-3: vault_send's allowinputs never signs a Yellowback outpoint ----------------------------------------

    def allowinputs_guard(self):
        print('allowinputs_guard: a coin vault_send signs because allowinputs names it is never a YED token (audit L-3)')
        n0 = self.nodes[0]
        tokens = n0.yed_listunspent()
        for _ in range(20):                           # the MINT is committed on its carrier a few blocks later
            if tokens:
                break
            self.mine()
            tokens = n0.yed_listunspent()
        assert_equal(len(tokens), 1)                  # the token of the MINT above (the MINT's vault is its vout 0)
        token = tokens[0]
        assert n0.gettxout(token['txid'], 0) is not None
        tok_value = D(n0.gettxout(token['txid'], token['vout'])['value'])
        spend = n0.createrawtransaction([{'txid': token['txid'], 'vout': 0},
                                         {'txid': token['txid'], 'vout': token['vout']}],
                                        {n0.getnewaddress(): tok_value})
        named = {'allowinputs': ['%s:%d' % (token['txid'], token['vout'])]}
        refusal = ('refusing to spend a Yellowback outpoint as plain YEC: %s:%d (its YED would burn; lock it again with '
                   'yed_lockcoins)' % (token['txid'], token['vout']))
        preview = n0.vault_send(spend, {'allowinputs': named['allowinputs'], 'dryrun': True})
        assert_equal(preview['wouldrefuse'], refusal)
        assert_equal(assert_raises_rpc(refusal, n0.vault_send, spend, named), refusal)
        assert n0.gettxout(token['txid'], token['vout']) is not None

    # ---- item 4 / 11: the stock sends spend ECC coins only ----------------------------------------------------------

    PQ_REFUSAL = re.compile(r'^Insufficient funds in ordinary transparent addresses; this wallet also holds ([0-9.]+) YEC at '
                            r'post-quantum addresses: send from one with z_sendmany, which returns the change to it$')

    def ecc_send(self):
        print('ecc_send: sendtoaddress / sendmany spend ECC coins only')
        n0, n1 = self.nodes
        slh = n0.getnewaddress('', 'pqslh')
        for _ in range(6):
            n1.sendtoaddress(slh, Decimal('0.5'))
        n1.sendtoaddress(n0.getnewaddress(), 2)
        self.mine()
        pq_before = D(n0.getwalletinfo()['balance_pq'])
        unspent = n0.listunspent()
        types = {u['address']: n0.validateaddress(u['address']) for u in unspent}
        pq_free = sum(D(u['amount']) for u in unspent if 'pqscheme' in types[u['address']])
        ecc_free = sum(D(u['amount']) for u in unspent if 'pqscheme' not in types[u['address']])
        assert pq_free >= 3, pq_free
        own = n0.getnewaddress()
        for call in (lambda: n0.sendtoaddress(own, ecc_free + 1), lambda: n0.sendmany('', {own: ecc_free + 1})):
            try:
                call()
                raise AssertionError('expected the ECC-only refusal')
            except JSONRPCException as e:
                m = self.PQ_REFUSAL.match(e.error['message'])
                assert m, e.error['message']
                assert_equal(D(m.group(1)), pq_free)
        assert_equal(D(n0.getwalletinfo()['balance_pq']), pq_before)
        print('fundrawtransaction adds ECC coins only; a post-quantum input the transaction names stays (review LOW-1)')
        try:
            n0.fundrawtransaction(n0.createrawtransaction([], {own: ecc_free + 1}))
            raise AssertionError('expected the ECC-only refusal')
        except JSONRPCException as e:
            m = self.PQ_REFUSAL.match(e.error['message'])
            assert m, e.error['message']
            assert_equal(D(m.group(1)), pq_free)
        pq_coin = [u for u in unspent if 'pqscheme' in types[u['address']]][0]
        raw = n0.createrawtransaction([{'txid': pq_coin['txid'], 'vout': pq_coin['vout']}], {own: Decimal('0.4')})
        funded = n0.decoderawtransaction(n0.fundrawtransaction(raw)['hex'])
        assert_equal((funded['vin'][0]['txid'], funded['vin'][0]['vout']), (pq_coin['txid'], pq_coin['vout']))
        for i in funded['vin'][1:]:
            prev = n0.getrawtransaction(i['txid'], 1)['vout'][i['vout']]['scriptPubKey']
            assert_equal(prev['type'], 'pubkeyhash')
        print('an ECC send: ECC inputs, ECC change, the post-quantum balance unchanged')
        txid = n0.sendtoaddress(n1.getnewaddress(), 1)
        tx = n0.getrawtransaction(txid, 1)
        for i in tx['vin']:
            prev = n0.getrawtransaction(i['txid'], 1)['vout'][i['vout']]['scriptPubKey']
            assert_equal(prev['type'], 'pubkeyhash')
        for o in tx['vout']:
            assert_equal(o['scriptPubKey']['type'], 'pubkeyhash')
        self.mine()
        assert_equal(D(n0.getwalletinfo()['balance_pq']), pq_before)

    # ---- review LOW-8: getbalance asOfHeight and the cached credit (6.x; ycash-dd has no asOfHeight) ------------------

    def asof_cache(self):
        n0, n1 = self.nodes
        if 'asOfHeight' not in n0.help('getbalance'):
            print('asof_cache: getbalance takes no asOfHeight on this line; nothing to check')
            return
        print('asof_cache: getbalance asOfHeight neither reads nor writes the cached credit (review LOW-8)')
        a = n0.getnewaddress()
        n1.sendtoaddress(a, 2)
        self.mine()
        h = n0.getblockcount()
        wait_and_assert_operationid_status(n0, z_sendmany_opid(n0, a, [(n1.getnewaddress(), Decimal('1.9'))]))
        self.mine()
        n0.getbalance('*', 1, False, False, h)        # the 2 YEC coin was unspent at h
        now = D(n0.getbalance())                       # read before getwalletinfo, which rewrites the cache
        assert_equal(now, D(n0.getwalletinfo()['balance']))

    def run_test(self):
        self.mine(ACTIVATION - self.nodes[0].getblockcount())
        self.topup_balance()
        self.vault_funding()
        self.note_locks()
        self.allowinputs_guard()
        self.ecc_send()
        self.asof_cache()


if __name__ == '__main__':
    WalletBeta2FollowupsTest().main()
