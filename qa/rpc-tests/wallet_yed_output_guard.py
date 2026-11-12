#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Every kind of output the Yellowback module gives YED, against every coin-selecting send of the wallet
(review WALLET-FOLLOW-REVIEW-2 CRITICAL-1, lane WALLET-FOLLOW-5).

The module writes YED to a transaction output in four rules (src/yellowback/state.cpp): a MINT's token (vout 1), the
assignments of a TRANSFER, the assignments of a REDEEM (with or without a vault spent), and a claim cancel's refund
(CAN-1), which no payload field names. The wallet recognises them from the transaction alone
(yellowback::PayloadYedOutputs): where Yellowback is not live, and for a transaction the index has not judged.

Rows produced here, on the run of yellowback_cancel_limit.py up to the cancel:
  - a MINT token, a claim cancel's refund token (and the cancel's YEC change, which the wallet counts conservatively),
    a TRANSFER's assignment to a post-quantum (rq...) address and its YED change;
  - live, unconfirmed: each is pre-locked; for the refund, sendtoaddress and z_sendmany (minconf 0) do not spend it
    (before the fix both did);
  - not live, an unmarked wallet that imported the keys (the state a seed restore leaves): the MINT token and the refund;
    not live, the marked wallet with -yellowback=0: the TRANSFER rows. For each: sendtoaddress, sendmany,
    fundrawtransaction, z_sendmany from the address and from ANY_TADDR, vault fee funding (set_create, vault_lock),
    vault_lock "from" the address, then z_mergetoaddress from the address, never spend it;
  - the conservative case: the cancel's own YEC change is refused by z_sendmany and spent by a raw transaction that
    names it (the explicit path; fundrawtransaction naming it too);
  - review 3 MEDIUM-2: sendrawtransaction without allowyedburn refuses a raw spend of an UNCONFIRMED (pre-locked) YED
    output: the claim cancel's refund (amount unknown before its block is judged) and a TRANSFER's assignment (counted at
    the payload's figure); before, both were accepted and the YED burned;
  - review 3 MEDIUM-1: live, a third party's plain payment to this wallet in a transaction that carries a copied
    CANCEL_COSIGN payload and spends no intent (made here from this wallet's own coin): pre-locked while unconfirmed, released once its block is judged (it
    touched no Yellowback state), and spendable by sendtoaddress, also after a restart (before: locked for good, and
    after a restart every send that selected it was refused).
  - review WALLET-STACK LOW-1: a payment carrying a TRANSFER payload that assigns its two outputs to this wallet, mined
    BELOW the Yellowback start height (the index never evaluates that block, so no output in it is YED): once Yellowback
    is live it is not locked, sendtoaddress spends one output and sendrawtransaction without allowyedburn spends the other
    (before: never judged, so refused by every send for good and refused raw without allowyedburn).

The same file runs on ycash-dd and ycash6."""

import os
import shutil
import time
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.util import (assert_equal, initialize_datadir, start_node, stop_node, z_mergetoaddress_call,
                                 z_sendmany_opid)
from test_framework.yellowback_util import P_MID_WINDOW, POOLS, REF_LAG, VAULT_ACTIVATION, yed_params, usd_to_micro
from test_framework.yellowback_model import encode_transfer
from test_framework.yellowback_attest import ATTESTOR_WIFS, register_and_arm, wallet_claim, wallet_notice

import yellowback_cancel_limit as base
from wallet_yed_held_guard import yed_form

USER = 0
FRESH = 6
NOT_LIVE = 'refusing to spend an output that may carry YED as plain YEC while Yellowback is not live: '


def op_key(o):
    return '%s:%d' % (o[0], o[1])


class WalletYedOutputGuardTest(base.YellowbackCancelLimitTest):

    def create_attestor_set(self):
        """Before the set exists (and below the start height), mine the LOW-1 payment first."""
        if getattr(self, 'prestart', None) is None and self.nodes[USER].getblockcount() < VAULT_ACTIVATION - 1:
            self.prestart = self.prestart_payload_payment()
        return super().create_attestor_set()

    def run_test(self):
        nodes = self.nodes
        user = nodes[USER]
        self.current_quote = base.PRICE
        self.activate(POOLS, quote_usd=base.PRICE)
        self.prestart_payment_spendable()
        user = nodes[USER]
        self.mine_round_robin(POOLS, REF_LAG + 1)
        register_and_arm(self)
        for wif in ATTESTOR_WIFS[:3]:
            user.importprivkey(wif, 'yellowback-attestor', False)
        vault = base.wallet_mint_armed(self, user)['txid']
        self.sync_all()
        self.mine(POOLS[0])

        print('live, unconfirmed: a second MINT\'s token is pre-locked')
        second = base.wallet_mint_armed(self, user)['txid']
        self.wait_locked(user, [(second, 1)], 'the unconfirmed mint token')
        self.sync_all()
        self.mine(POOLS[0])

        print('the run of yellowback_cancel_limit.py up to the claim of the first vault')
        self.price(base.POOL_LOW)
        self.mine_round_robin(POOLS, 66)
        wallet_notice(self, user, vault, prices=base.ATTESTED)
        self.sync_all()
        self.mine(POOLS[0])
        self.mine_round_robin(POOLS, yed_params().emergency_persist + 1)
        self.price(Decimal('16.90'))
        self.mine_round_robin(POOLS, P_MID_WINDOW + REF_LAG)
        wallet_claim(self, user, vault, prices=base.ATTESTED)
        self.sync_all()
        self.mine(POOLS[1])
        self.price(base.POOL_LOW)
        rows = dict((x['role'], x) for x in user.yed_getvault(vault)['intents'])
        claimant = '%s:%d' % (rows['claimant']['txid'], rows['claimant']['vout'])
        cos = user.yed_signcancelcosign(claimant, usd_to_micro(base.ATTESTED))
        built = user.yed_buildcancel(claimant, [cos['cosig']])
        signed = user.set_signcancel(built['hex'], {'acknowledgerestore': True})
        cancel = user.vault_send(signed['hex'])
        ctx = user.getrawtransaction(cancel, 1)
        refund = (cancel, 1)                          # yed_buildcancel's shape: the vault at 0, the refund at 1
        assert ctx['vout'][1]['valueZat'] > 0

        print('live, unconfirmed: the claim cancel\'s refund is pre-locked and no send spends it (before: both did)')
        self.wait_locked(user, [refund], 'the unconfirmed refund')
        self.live_unconfirmed_refund(user, refund, ctx['vout'][1]['scriptPubKey']['addresses'][0])
        print('live, unconfirmed: sendrawtransaction without allowyedburn refuses a raw spend of the refund (MEDIUM-2)')
        msg = self.raw_spend_refused(user, refund)
        assert 'has not judged yet and whose payload may give them YED (%s:%d)' % (refund[0], refund[1]) in msg, msg
        self.sync_all()
        self.mine(POOLS[2])
        info = user.yed_gettxinfo(cancel)
        assert_equal((info['type'], [a['vout'] for a in info['assigned']]), ('claim_cancel', [1]))
        mint_tokens = [(c['txid'], c['vout']) for c in user.yed_listunspent() if c['txid'] in (vault, second)]
        assert_equal(len(mint_tokens), 1)             # the claim burned one of the two mint tokens
        change = [o for o in ctx['vout'] if o['n'] >= 2 and o['valueZat'] > 0 and o['scriptPubKey']['type'] == 'pubkeyhash']
        assert_equal(len(change), 1)
        change = ((cancel, change[0]['n']), change[0]['scriptPubKey']['addresses'][0], change[0]['value'])

        self.copied_payload_payment(ctx)
        user = self.nodes[USER]
        self.not_live_unmarked(user, [('MINT token', mint_tokens[0]), ('claim cancel refund', refund)], change)
        self.transfer_rows()

    # ---- helpers

    def locked(self, node):
        return [(l['txid'], l['vout']) for l in node.listlockunspent()]

    def wait_locked(self, node, outs, what):
        """The pre-lock (stage ii) runs on the wallet's notification thread: wait for it."""
        for _ in range(60):
            if all(o in self.locked(node) for o in outs):
                return
            time.sleep(0.5)
        raise AssertionError('%s is not locked: %s' % (what, [op_key(o) for o in outs]))

    def unlock_all(self, node):
        """Unlock what isolate locked (never a lock that was there before it)."""
        mine = getattr(self, '_isolated', [])
        if mine:
            assert node.lockunspent(True, mine)
        self._isolated = []

    def isolate(self, node, keep):
        """Lock every coin but `keep` (outpoints); unlock what an earlier isolate locked first."""
        self.unlock_all(node)
        before = self.locked(node)
        others = [{'txid': c['txid'], 'vout': c['vout']} for c in node.listunspent(0, 9999999)
                  if (c['txid'], c['vout']) not in keep and (c['txid'], c['vout']) not in before]
        if others:
            assert node.lockunspent(False, others)
        self._isolated = others

    def refused(self, node, fn, asyn=False):
        """Call fn, which must fail; return the message (an async operation's error included)."""
        try:
            r = fn()
        except JSONRPCException as e:
            return e.error['message']
        if not asyn:
            raise AssertionError('the call succeeded: %s' % (r,))
        for _ in range(240):
            st = node.z_getoperationstatus([r])[0]
            if st['status'] not in ('queued', 'executing'):
                break
            time.sleep(0.5)
        assert st['status'] == 'failed', st
        return st['error']['message']

    def assert_unspent(self, node, o, what):
        assert node.gettxout(o[0], o[1], True) is not None, '%s spent %s' % (what, op_key(o))

    def copy_node(self, i):
        """Stop node i and copy its datadir into the FRESH slot without its Yellowback index; node i restarts."""
        stop_node(self.nodes[i], i)
        self.nodes[i] = None
        datadir = os.path.join(self.options.tmpdir, 'node%d' % FRESH)
        if os.path.isdir(datadir):
            shutil.rmtree(datadir)
        shutil.copytree(os.path.join(self.options.tmpdir, 'node%d' % i), datadir)
        shutil.rmtree(os.path.join(datadir, 'regtest', 'yellowback'))
        initialize_datadir(self.options.tmpdir, FRESH)     # this slot's own ports, not the copied node's
        self.restart(i)
        return datadir

    def not_live_args(self):
        return [a for a in self.node_args(5) if not a.startswith('-yellowback') and a != '-experimentalfeatures']

    def live_unconfirmed_refund(self, node, refund, addr):
        coins = [c for c in node.listunspent(1, 9999999) if Decimal(c['amount']) >= 1]
        plain = sorted(coins, key=lambda c: c['amount'])[0]
        self.isolate(node, [refund, (plain['txid'], plain['vout'])])
        to = node.getnewaddress()
        mempool = sorted(node.getrawmempool())
        msg = self.refused(node, lambda: node.sendtoaddress(to, plain['amount']))
        print('  sendtoaddress: %s' % msg)
        assert 'Insufficient funds' in msg, msg
        msg = self.refused(node, lambda: z_sendmany_opid(node, addr, [(to, Decimal('0.00005'))], minconf=0), True)
        print('  z_sendmany from the refund address, minconf 0: %s' % msg)
        assert_equal(sorted(node.getrawmempool()), mempool)
        self.assert_unspent(node, refund, 'a live send')
        self.unlock_all(node)
        assert refund in self.locked(node)

    def raw_spend_refused(self, node, o):
        """A raw transaction spending `o` (and a plain coin for the fee) without allowyedburn: refused, nothing sent."""
        val = Decimal(node.getrawtransaction(o[0], 1)['vout'][o[1]]['value'])
        fee = sorted([c for c in node.listunspent(1, 9999999) if Decimal(c['amount']) >= 1
                      and c['scriptPubKey'].startswith('76a914')], key=lambda c: c['amount'])[0]
        raw = node.createrawtransaction([{'txid': o[0], 'vout': o[1]}, {'txid': fee['txid'], 'vout': fee['vout']}],
                                        {node.getnewaddress(): val + Decimal(fee['amount']) - Decimal('0.0001')})
        signed = node.signrawtransaction(raw)
        assert_equal(signed['complete'], True)
        mempool = sorted(node.getrawmempool())
        msg = self.refused(node, lambda: node.sendrawtransaction(signed['hex']))
        print('  sendrawtransaction: %s' % msg)
        assert msg.startswith('yed-burn-refused: ') and msg.endswith('Pass allowyedburn = true to send it anyway.'), msg
        assert_equal(sorted(node.getrawmempool()), mempool)
        self.assert_unspent(node, o, 'sendrawtransaction')
        return msg

    def prestart_payload_payment(self):
        """LOW-1: a plain payment to this wallet whose transaction carries a TRANSFER payload assigning both payment
        outputs, mined below the start height (before Yellowback is live). Returns the two outpoints."""
        user = self.nodes[USER]
        coin = sorted([c for c in user.listunspent(1, 9999999) if Decimal(c['amount']) >= Decimal('3')],
                      key=lambda c: c['amount'])[0]
        a, b, dummy = user.getnewaddress(), user.getnewaddress(), user.getnewaddress()
        raw = user.createrawtransaction([{'txid': coin['txid'], 'vout': coin['vout']}],
                                        {a: Decimal('1'), b: Decimal('1'), dummy: Decimal('0.00012345'),
                                         user.getnewaddress(): Decimal(coin['amount']) - Decimal('2.001')},
                                        0, 0)            # no expiry: the default is capped below the vault upgrade, which is too soon
        dec = user.decoderawtransaction(raw)
        va = [o['n'] for o in dec['vout'] if a in o['scriptPubKey'].get('addresses', [])][0]
        vb = [o['n'] for o in dec['vout'] if b in o['scriptPubKey'].get('addresses', [])][0]
        dspk = [o for o in dec['vout'] if o['valueZat'] == 12345][0]['scriptPubKey']['hex']
        old = '3930000000000000' + '19' + dspk
        payload = encode_transfer([(va, 1000), (vb, 1000)])
        assert raw.count(old) == 1 and len(payload) < 0x4c
        raw = raw.replace(old, '0000000000000000' + ('%02x' % (len(payload) + 2)) + '6a' + ('%02x' % len(payload)) + payload.hex())
        txid = user.sendrawtransaction(user.signrawtransaction(raw)['hex'])
        self.sync_all()
        self.mine(USER, blocks_only=True)
        height = user.getblock(user.getrawtransaction(txid, 1)['blockhash'])['height']
        print('LOW-1: a payment carrying a TRANSFER payload mined at height %d, below the start height %d' % (height, VAULT_ACTIVATION))
        assert height < VAULT_ACTIVATION, height
        return [(txid, va), (txid, vb)]

    def prestart_payment_spendable(self):
        """LOW-1, once Yellowback is live: the below-start payment is judged with no YED."""
        print('live: the payment carrying a payload mined below the start height is plain YEC (LOW-1)')
        user = self.nodes[USER]
        first, second = self.prestart
        for _ in range(60):                           # a pre-lock, if any, is released on the completion thread
            if first not in self.locked(user) and second not in self.locked(user):
                break
            time.sleep(0.5)
        assert first not in self.locked(user) and second not in self.locked(user), 'the below-start payment is still locked'
        plain = sorted([c for c in user.listunspent(1, 9999999) if Decimal(c['amount']) >= Decimal('1')
                        and c['scriptPubKey'].startswith('76a914') and (c['txid'], c['vout']) not in self.prestart],
                       key=lambda c: c['amount'])[0]
        self.isolate(user, [first, (plain['txid'], plain['vout'])])
        sent = user.sendtoaddress(user.getnewaddress(), Decimal(plain['amount']) + Decimal('0.5'))
        spent = [(i['txid'], i['vout']) for i in user.getrawtransaction(sent, 1)['vin']]
        assert first in spent, (first, spent)
        self.unlock_all(user)
        raw = user.createrawtransaction([{'txid': second[0], 'vout': second[1]}], {user.getnewaddress(): Decimal('0.9999')})
        signed = user.signrawtransaction(raw)
        assert_equal(signed['complete'], True)
        user.sendrawtransaction(signed['hex'])          # no allowyedburn: nothing of it is YED
        self.sync_all()
        self.mine(POOLS[0])
        self.sync_all()

    def copied_payload_payment(self, cancel_ctx):
        """MEDIUM-1: a plain payment to this wallet in a transaction carrying a copied CANCEL_COSIGN payload (no intent
        spent) is NON_YELLOWBACK: once its block is judged nothing of it is YED."""
        print('live: a payment carrying a copied CANCEL_COSIGN payload (MEDIUM-1)')
        user = payer = self.nodes[USER]           # the reviewer's probe pays from the same wallet (its change is listed too)
        opret = [o for o in cancel_ctx['vout'] if o['scriptPubKey']['hex'].startswith('6a')][0]['scriptPubKey']['hex']
        coin = sorted([c for c in payer.listunspent(1, 9999999) if Decimal(c['amount']) >= Decimal('1.5')
                       and c['scriptPubKey'].startswith('76a914')], key=lambda c: c['amount'])[0]
        victim = user.getnewaddress()
        dummy = payer.getnewaddress()
        raw = payer.createrawtransaction([{'txid': coin['txid'], 'vout': coin['vout']}],
                                         {victim: Decimal('1'), dummy: Decimal('0.00012345'),
                                          payer.getnewaddress(): Decimal(coin['amount']) - Decimal('1.001')})
        dspk = [o for o in payer.decoderawtransaction(raw)['vout'] if o['valueZat'] == 12345][0]['scriptPubKey']['hex']
        old = '3930000000000000' + '19' + dspk
        assert raw.count(old) == 1 and len(opret) // 2 < 0xfd
        raw = raw.replace(old, '0000000000000000' + ('%02x' % (len(opret) // 2)) + opret)
        dec = payer.decoderawtransaction(raw)
        vn = [o['n'] for o in dec['vout'] if victim in o['scriptPubKey'].get('addresses', [])][0]
        g = payer.sendrawtransaction(payer.signrawtransaction(raw)['hex'])
        grief = (g, vn)
        self.sync_all()
        self.wait_locked(user, [grief], 'the unconfirmed copied-payload payment (conservative until judged)')
        self.mine(POOLS[0])
        self.sync_all()
        try:
            info = user.yed_gettxinfo(g)
        except JSONRPCException as e:
            info = e.error['message']
        print('  yed_gettxinfo after its block: %s' % (info,))
        for _ in range(60):                           # ReleaseJudgedUntouched runs on the wallet's completion thread
            if grief not in self.locked(user):
                break
            time.sleep(0.5)
        assert grief not in self.locked(user), 'the judged, untouched payment %s is still locked' % op_key(grief)
        print('  released once judged; after a restart a send that needs it spends it')
        self.restart(USER)
        user = self.nodes[USER]
        assert grief not in self.locked(user)
        plain = sorted([c for c in user.listunspent(1, 9999999) if Decimal(c['amount']) >= Decimal('1')
                        and c['scriptPubKey'].startswith('76a914') and (c['txid'], c['vout']) != grief],
                       key=lambda c: c['amount'])[0]
        self.isolate(user, [grief, (plain['txid'], plain['vout'])])
        want = Decimal(plain['amount']) + Decimal('0.5')
        sent = user.sendtoaddress(user.getnewaddress(), want)
        spent = [(i['txid'], i['vout']) for i in user.getrawtransaction(sent, 1)['vin']]
        assert grief in spent, (grief, spent)
        self.unlock_all(user)
        self.sync_all()
        self.mine(POOLS[0])
        self.sync_all()

    def check_row(self, node, what, o, addr, ecc):
        """Every coin-selecting send against output `o` at `addr`, with a 1 YEC plain coin beside it there."""
        plain = [c for c in node.listunspent(0, 9999999, [addr]) if c['amount'] == Decimal('1')]
        assert len(plain) >= 1, 'no plain coin at %s' % addr
        p = (plain[0]['txid'], plain[0]['vout'])
        to = node.getnewaddress()
        zaddr = node.z_getnewaddress('sapling')
        named = NOT_LIVE + op_key(o)
        params = lambda **kw: dict({'tag': 'TEST', 'setid': self.attestor_set, 'delay': 10,
                                    'ownerheight': node.getblockcount() + 1000, 'amount': Decimal('0.99995')}, **kw)
        print('%s %s at %s' % (what, op_key(o), addr))
        self.isolate(node, [o, p])
        for name, fn in (('sendtoaddress', lambda: node.sendtoaddress(to, 1)),
                         ('sendmany', lambda: node.sendmany('', {to: 1})),
                         ('fundrawtransaction', lambda: node.fundrawtransaction(node.createrawtransaction([], {to: 1})))):
            msg = self.refused(node, fn)
            print('  %s: %s' % (name, msg))
            if ecc:      # LOW-4: the stock refusal says why getbalance and listunspent count more
                assert 'Insufficient funds' in msg and op_key(o) in msg and 'may carry YED' in msg, msg
            self.assert_unspent(node, o, name)
        msg = self.refused(node, lambda: z_sendmany_opid(node, addr, [(to, Decimal('1'))]), True)
        print('  z_sendmany from the address: %s' % msg)
        assert named in msg, msg
        self.assert_unspent(node, o, 'z_sendmany')
        msg = self.refused(node, lambda: z_sendmany_opid(node, 'ANY_TADDR', [(zaddr, Decimal('1'))]), True)
        print('  z_sendmany ANY_TADDR: %s' % msg)
        if ecc:
            assert named in msg, msg
        self.assert_unspent(node, o, 'z_sendmany ANY_TADDR')
        msg = self.refused(node, lambda: node.vault_lock(params(**{'from': addr})))
        print('  vault_lock "from" the address: %s' % msg)
        assert named in msg, msg
        self.assert_unspent(node, o, 'vault_lock from')
        self.isolate(node, [o])
        for name, fn in (('set_create', lambda: node.set_create({'seats': 1, 'unlockthreshold': 1, 'maturity': 2})),
                         ('vault_lock (fee funding)', lambda: node.vault_lock(params()))):
            msg = self.refused(node, fn)
            print('  %s, only the output selectable: %s' % (name, msg))
            if ecc:
                assert named in msg, msg
            self.assert_unspent(node, o, name)
        self.isolate(node, [o, p])
        try:
            merge = z_mergetoaddress_call(node, [addr], zaddr)
        except JSONRPCException as e:
            merge = None
            print('  z_mergetoaddress: %s' % e.error['message'])
        if merge is not None:
            print('  z_mergetoaddress from the address: merges %d coin(s)' % merge['mergingUTXOs'])
            assert_equal(merge['mergingUTXOs'], 1)
            for _ in range(240):
                st = node.z_getoperationstatus([merge['opid']])[0]
                if st['status'] not in ('queued', 'executing'):
                    break
                time.sleep(0.5)
        self.assert_unspent(node, o, 'z_mergetoaddress')
        self.unlock_all(node)

    def not_live_unmarked(self, user, rows, change):
        """Not live, an unmarked wallet holding the outputs (it imported their keys: the state a seed restore leaves)."""
        addrs = []
        for _, o in rows:
            a = user.getrawtransaction(o[0], 1)['vout'][o[1]]['scriptPubKey']['addresses'][0]
            if a not in addrs:
                addrs.append(a)
        for a in addrs:
            user.sendtoaddress(a, 1)
        self.sync_all()
        self.mine(POOLS[0])
        keys = [user.dumpprivkey(a) for a in addrs + [change[1]]]
        datadir = self.copy_node(USER)
        os.remove(os.path.join(datadir, 'regtest', 'wallet.dat'))
        node = start_node(FRESH, self.options.tmpdir, self.not_live_args())
        try:
            for i, k in enumerate(keys):
                node.importprivkey(k, '', i == len(keys) - 1)
            node.generate(1)                          # out of initial block download (6.20.0 refuses wallet reads in it)
            assert_equal(node.getwalletinfo()['yed_held'], False)
            print('not live, unmarked wallet that imported the keys')
            for what, o in rows:
                a = node.getrawtransaction(o[0], 1)['vout'][o[1]]['scriptPubKey']['addresses'][0]
                self.check_row(node, what, o, a, True)

            c, caddr, cvalue = change
            print('the cancel\'s YEC change %s is counted conservatively: z_sendmany refuses it' % op_key(c))
            self.isolate(node, [c])
            msg = self.refused(node, lambda: z_sendmany_opid(node, caddr, [(node.getnewaddress(), Decimal('0.001'))]), True)
            assert NOT_LIVE + op_key(c) in msg, msg
            print('  fundrawtransaction naming it, and a raw transaction naming it, spend it (the explicit path)')
            to = node.getnewaddress()
            funded = node.fundrawtransaction(node.createrawtransaction([{'txid': c[0], 'vout': c[1]}], {to: Decimal('0.001')}))
            assert {'txid': c[0], 'vout': c[1]} in [{'txid': i['txid'], 'vout': i['vout']} for i in node.decoderawtransaction(funded['hex'])['vin']]
            raw = node.createrawtransaction([{'txid': c[0], 'vout': c[1]}], {to: Decimal(cvalue) - Decimal('0.0001')})
            signed = node.signrawtransaction(raw)
            assert_equal(signed['complete'], True)
            assert node.sendrawtransaction(signed['hex']) in node.getrawmempool()
            self.unlock_all(node)
        finally:
            stop_node(node, FRESH)

    def transfer_rows(self):
        """TRANSFER rows: an assignment to a post-quantum address of this wallet and the YED change."""
        user = self.nodes[USER]
        rq = user.getnewaddress('', 'pq')
        print('live, unconfirmed: a TRANSFER\'s assignments are pre-locked')
        t = user.yed_send(yed_form(user, rq), 2500)
        t = t['txid'] if isinstance(t, dict) else t
        for _ in range(60):                           # stage (i)/(ii) locks, the latter on the notification thread
            locked = [o for o in self.locked(user) if o[0] == t]
            if len(locked) >= 2:
                break
            time.sleep(0.5)
        print('live, unconfirmed: sendrawtransaction without allowyedburn refuses a raw spend of an assignment (MEDIUM-2)')
        msg = self.raw_spend_refused(user, locked[0])
        assert ('%s:%d (not judged yet)' % locked[0]) in msg and 'cents of YED would be destroyed' in msg, msg
        self.sync_all()
        self.mine(POOLS[0])
        assigned = [a['vout'] for a in user.yed_gettxinfo(t)['assigned']]
        assert_equal(len(assigned), 2)
        for n in assigned:
            assert (t, n) in locked, 'the unconfirmed TRANSFER output %d was not locked' % n
        tx = user.getrawtransaction(t, 1)
        rows = []
        for n in assigned:
            spk = tx['vout'][n]['scriptPubKey']
            a = (spk.get('addresses') or [''])[0] or rq
            ecc = spk['type'] == 'pubkeyhash'
            rows.append(('TRANSFER %s' % ('to rq' if a == rq else 'YED change'), (t, n), a, ecc))
            user.sendtoaddress(a, 1)
        self.sync_all()
        self.mine(POOLS[0])
        self.copy_node(USER)
        node = start_node(FRESH, self.options.tmpdir, self.not_live_args() + ['-yellowback=0'])
        try:
            node.generate(1)
            print('not live, the marked wallet with -yellowback=0')
            for what, o, a, ecc in rows:
                self.check_row(node, what, o, a, ecc)
        finally:
            stop_node(node, FRESH)


if __name__ == '__main__':
    WalletYedOutputGuardTest().main()
