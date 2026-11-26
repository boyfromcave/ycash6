#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The spend matrix with RYG status: every sender type x every recipient type, with and without a memo, on regtest
with Vault and Yugen active (spec 0.5.2, yugen-spec tag spec-0.5.2).

Senders: ECC (P2PKH), Sapling, PQ SLH-DSA (rqs), PQ Falcon / FN-DSA-512 (rqf), Yugen (yewd-yugen, YEWD_YUGEN; the
Yugen -> Sapling cells through yewd's one-call `yugen_send`, YEWD_BIN, node 3 = ycashd -disablewallet + yewd).
Recipients: the same four, the Yugen address (decisions Y-13..Y-15, `yqrf1...`) in its reusable form (static address only,
"Yugen-static") and its one-time form (static address + payment request, "Yugen-request"). No mailbox hosts run
here, so the static part is the full static address (the short form is covered by the m3 walk). With a memo, a
one-time address is paid at its static part with the memo (UX-1 P-3), not refused.

Per cell: build, broadcast, relay, mine; the recipient sees the amount (and the memo text); the sender's balance
falls by amount + fee and the fee is the fixed fee of its shape. A recipient that cannot carry a memo (transparent,
Yugen request: spec §9.2 "A memo needs a static address") must be refused with a clear error.

Status: GREEN passes; YELLOW passes by a documented two-step route, or is not implemented (cited); RED fails.
Writes qa/rpc-tests/spend_matrix_status.md (or SPEND_MATRIX_OUT) and prints the table.

    ZCASHD=<ycashd> YEWD_YUGEN=<yewd-yugen> python -u qa/rpc-tests/spend_matrix.py --srcdir=src --tmpdir=<dir>

Parts (each fits one 30-minute run): SPEND_MATRIX_PART=1 (ECC, Sapling), 2 (PQ-SLH, PQ-Falcon), 3 (Yugen via yewd-yugen /
yewd), 4 (Yugen-ycashd); or SPEND_MATRIX_SENDERS=<comma list>. Every part runs against all seven recipients.
"""

import json
import os
import subprocess
import tempfile
import time
import traceback
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    LONE_SAPLING_OUTPUT_ACTIONS, VAULT_BRANCH_ID, assert_equal, connect_nodes_bi, nuparams, rpc_auth_pair,
    rpc_port, start_node, start_nodes, sync_blocks, sync_mempools, wait_and_assert_operationid_status,
)
from test_framework.yellowback_util import YCASH_UPGRADE_ARGS
from test_framework.yugen_util import yugen_helper

YUGEN_BRANCH_ID = 0x59474E30
VAULT_H, FALCON_H, YUGEN_H = 16, 20, 32
HERE = os.path.dirname(os.path.abspath(__file__))
VERIFIER = '-yugenverifier=' + yugen_helper('YUGEN_LEAFVERIFY', 'yugen-leafverify')
WALLET = yugen_helper('YEWD_YUGEN', 'yewd-yugen')
OUT = os.environ.get('SPEND_MATRIX_OUT', os.path.join(HERE, 'spend_matrix_status.md'))
BUILDER = '-yugenbuilder=' + yugen_helper('YUGEN_SENDBUILD', 'yugen-sendbuild')
YEWD_BIN = os.environ.get('YEWD_BIN', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'yew', 'yewd', 'target', 'release', 'yewd'))  # a sibling yew checkout
os.environ.pop('YEWD_BIN', None)     # only node 3 is a yewd pair (start_nodes below)
YEWD = 3
ARGS = list(YCASH_UPGRADE_ARGS) + [nuparams(VAULT_BRANCH_ID, VAULT_H), nuparams(YUGEN_BRANCH_ID, YUGEN_H),
                                   '-pqfalconheight=%d' % FALCON_H, VERIFIER, BUILDER, '-yugenprover=' + WALLET,
                                   '-debug=yugen']

DEFAULT_FEE = 1000          # the line's default fee for a shape without a PQ input
FEE_SLH, FEE_FN, FEE_SAPLING_OUT = 27000, 5500, 500     # wallet_address_matrix.py: fixed fees of one PQ input
YUGEN_FEE = 100000 + 155600                             # BASE_FEE + LEAF_PROOF_FEE (spec 0.5.2 §2, §16.1)
ANCHOR_GRID, ANCHOR_MIN_DEPTH = 16, 3                   # spec §8.3 wallet rule

ECC, SAP, SLH, FN, YS, YR = 'ECC', 'Sapling', 'PQ-SLH', 'PQ-Falcon', 'Yugen-static', 'Yugen-request'
YC = 'Yugen-ycashd'         # the ycashd wallet's own Yugen account (doc/yugen-node.md N-A1): node 0 sends, node 1 receives
SENDERS = (ECC, SAP, SLH, FN, 'Yugen', YC)
RECIPIENTS = (ECC, SAP, SLH, FN, YS, YR, YC)
MEMO_OK = (SAP, YS, YR, YC)
HOP_FEE = 1000              # Yugen -> Sapling hop (Y-W9, N-A3)
TADDR_MEMO_ERR = 'Memos cannot be sent to transparent addresses'
# Split into parts that each fit one 30-minute run: SPEND_MATRIX_PART=1..4 (or SPEND_MATRIX_SENDERS=a,b; empty = all)
PARTS = {'1': (ECC, SAP), '2': (SLH, FN), '3': ('Yugen',), '4': (YC,)}
_part = os.environ.get('SPEND_MATRIX_PART', '')
_snd = PARTS[_part] if _part else tuple(x for x in os.environ.get('SPEND_MATRIX_SENDERS', '').split(',') if x)
assert all(x in SENDERS for x in _snd), _snd
RUN_SENDERS = _snd or SENDERS

TRANSPARENT = (ECC, SLH, FN)


def zat(x):
    return int((Decimal(x) * 100000000).to_integral_value())


def coins(z):
    return Decimal(z) / 100000000


class Skip(Exception):
    """A cell this build cannot exercise, with its documented reason (YELLOW)."""


class SpendMatrixTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = True

    def setup_network(self, split=False):
        # node 0 sends, node 1 receives, node 2 mines, node 3 is the yewd pair (Yugen -> Sapling, one call)
        self.nodes = start_nodes(3, self.options.tmpdir, [ARGS] * 3)
        yargs = [a for a in ARGS if not a.startswith(('-yugenbuilder=', '-yugenprover='))]
        os.environ['YEWD_BIN'] = YEWD_BIN
        try:
            self.nodes.append(start_node(YEWD, self.options.tmpdir, yargs))
        finally:
            os.environ.pop('YEWD_BIN', None)
        for a, b in ((0, 1), (1, 2), (0, 2), (3, 2), (3, 0)):
            connect_nodes_bi(self.nodes, a, b)
        self.is_network_split = False

    # --- Yugen wallet (yewd-yugen CLI) ---
    def ywallet(self, name, node, *args, ok=True):
        u, p = rpc_auth_pair(node)
        seed = {'A': '11', 'B': '22'}[name] * 32
        cmd = [WALLET, '-network=regtest', '-node=127.0.0.1:%d' % rpc_port(node), '-rpcuser=' + u,
               '-rpcpassword=' + p, '-datadir=' + self.wdir[name], '-seedfd=3'] + list(args)
        # the engine takes the seed only on an inherited descriptor (N-A5): hex and a newline on fd 3
        r, w = os.pipe()
        os.write(w, (seed + '\n').encode())
        os.close(w)
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, pass_fds=(3,),
                                 preexec_fn=lambda: os.dup2(r, 3))
        finally:
            os.close(r)
        if not ok:
            return out
        assert out.returncode == 0, ('yewd-yugen', args[:1], out.stdout[-500:], out.stderr[-1500:])
        return json.loads(out.stdout)

    def ybalance(self, name, node):
        return Decimal(str(self.ywallet(name, node, 'getbalance')))

    # --- chain ---
    def mine(self, n=1):
        sync_mempools(self.nodes)
        b = self.nodes[2].generate(n)
        sync_blocks(self.nodes)
        return b

    def mine_to_anchor(self, h):
        """Mine until the wallet anchor (spec §8.3) is above height h, so a note mined at h is spendable."""
        while (self.nodes[2].getblockcount() - ANCHOR_MIN_DEPTH) // ANCHOR_GRID * ANCHOR_GRID <= h:
            self.mine(1)

    def total(self, node):
        t = sum(Decimal(u['amount']) for u in node.listunspent(0))
        return t + sum(Decimal(u['amount']) for u in node.z_listunspent(0))

    def fee_of(self, node, txid):
        raw = node.getrawtransaction(txid, 1)
        vin = 0
        for i in raw['vin']:
            prev = node.getrawtransaction(i['txid'], 1)
            vin += zat(prev['vout'][i['vout']]['value'])
        return vin + zat(raw.get('valueBalance', 0)) - sum(zat(o['value']) for o in raw['vout'])

    def expected_fee(self, s, d):
        if s in (SLH, FN):
            return (FEE_SLH if s == SLH else FEE_FN) + (FEE_SAPLING_OUT * LONE_SAPLING_OUTPUT_ACTIONS if d == SAP else 0)
        return DEFAULT_FEE

    def zsend(self, s, to, amount, memo=None):
        r = {'address': to, 'amount': amount}
        if memo is not None:
            r['memo'] = memo.encode().hex()
        opid = self.nodes[0].z_sendmany(self.src[s], [r], 1, None, 'AllowFullyTransparent')
        return wait_and_assert_operationid_status(self.nodes[0], opid)

    def received(self, d, addr):
        n1 = self.nodes[1]
        if d == SAP:
            return Decimal(n1.z_getbalance(addr))
        return n1.getreceivedbyaddress(addr)

    # --- cells ---
    def node_cell(self, s, d, memo, amount):
        n0, n1 = self.nodes[0], self.nodes[1]
        to = self.dst[d]
        if memo is not None and d not in MEMO_OK:
            try:
                self.zsend(s, to, amount, memo)
            except (JSONRPCException, AssertionError) as e:
                msg = e.error['message'] if isinstance(e, JSONRPCException) else str(e)
                assert TADDR_MEMO_ERR in msg, msg
                return 'refused: "%s"' % TADDR_MEMO_ERR
            raise AssertionError('memo to a transparent recipient accepted')
        before_s, before_r = self.total(n0), self.received(d, to)
        txid = self.zsend(s, to, amount, memo)
        sync_mempools(self.nodes)
        assert txid in n1.getrawmempool(), 'not relayed'
        fee = self.fee_of(n0, txid)
        assert_equal(fee, self.expected_fee(s, d))
        self.mine(1)
        assert_equal(n0.gettransaction(txid)['confirmations'], 1)
        assert_equal(self.received(d, to) - before_r, amount)
        assert_equal(before_s - self.total(n0), amount + coins(fee))
        if d == SAP:
            got = [o for o in n1.z_listreceivedbyaddress(to) if o['txid'] == txid]
            assert_equal(len(got), 1)
            m = bytes.fromhex(got[0]['memo'])
            if memo is None:
                assert m[0] == 0xf6 and not any(m[1:]), 'empty memo expected'
            else:
                assert_equal(m.rstrip(b'\0').decode(), memo)
        return 'fee %d zat' % fee

    def deposit_two_step(self, s, amount):
        """Step 1: z_sendmany to the recipient wallet's deposit address; step 2: the recipient shields it (§7.9 rule 4)."""
        n0 = self.nodes[0]
        before_s, before_y = self.total(n0), self.ybalance('B', 1)
        fund = self.zsend(s, self.ydeposit['B'], amount)
        fee1 = self.fee_of(n0, fund)
        assert_equal(fee1, self.expected_fee(s, ECC))
        self.mine(1)
        assert_equal(before_s - self.total(n0), amount + coins(fee1))
        sh = self.ywallet('B', 1, 'shield', json.dumps([fund]))
        assert_equal(zat(sh['fee']), YUGEN_FEE)
        sync_mempools(self.nodes)
        assert sh['txid'] in self.nodes[2].getrawmempool(), 'shield not relayed'
        h = self.mine(1)[0]
        assert sh['txid'] in self.nodes[2].getblock(h)['tx']
        self.mine_to_anchor(self.nodes[2].getblockcount())
        assert_equal(self.ybalance('B', 1) - before_y, amount - coins(YUGEN_FEE))
        return 'two-step: z_sendmany to the deposit taddr (fee %d) + shield (fee %d)' % (fee1, YUGEN_FEE)

    def yugen_to_request(self, memo, amount):
        """Leaf send to B's one-time Yugen address (static + request). Without a memo the request is paid; with a
        memo the wallet pays the static part with the memo (UX-1 P-3), and B shows the memo."""
        req = self.ywallet('B', 1, 'newaddress')
        assert req.startswith('yqrf1'), req[:20]
        ba, bb = self.ybalance('A', 0), self.ybalance('B', 1)
        r = self.ywallet('A', 0, 'send', json.dumps([req, float(amount)] + ([memo] if memo is not None else [])))
        assert_equal(zat(r['fee']), YUGEN_FEE)
        sync_mempools(self.nodes)
        assert r['txid'] in self.nodes[1].getrawmempool(), 'not relayed'
        h = self.mine(1)[0]
        assert r['txid'] in self.nodes[2].getblock(h)['tx']
        self.mine_to_anchor(self.nodes[2].getblockcount())
        assert_equal(self.ybalance('B', 1) - bb, amount)
        assert_equal(ba - self.ybalance('A', 0), amount + coins(YUGEN_FEE))
        if memo is not None:
            self.check_static_memo(r['txid'], memo)
            return 'leaf send to the one-time address, static part with the memo (P-3), memo shown, fee %d zat' % YUGEN_FEE
        return 'leaf send to the one-time address, request paid, fee %d zat' % YUGEN_FEE

    def ybnote(self, name, node, txid):
        got = [n for n in self.ywallet(name, node, 'listreceived') if n['txid'] == txid]
        assert_equal(len(got), 1)
        return got[0]

    def check_static_memo(self, txid, memo):
        n = self.ybnote('B', 1, txid)
        assert n['applied'], n
        assert_equal(n.get('memo'), memo)

    def yugen_to_static(self, memo, amount):
        """Leaf send from wallet A to wallet B's static address 0 (§12.1), note package (§10), memo shown by B."""
        to = self.ystatic['B']
        ba, bb = self.ybalance('A', 0), self.ybalance('B', 1)
        args = [to, float(amount)] + ([memo] if memo is not None else [])
        r = self.ywallet('A', 0, 'send', json.dumps(args))
        assert_equal(zat(r['fee']), YUGEN_FEE)
        sync_mempools(self.nodes)
        assert r['txid'] in self.nodes[1].getrawmempool(), 'not relayed'
        h = self.mine(1)[0]
        assert r['txid'] in self.nodes[2].getblock(h)['tx']
        self.mine_to_anchor(self.nodes[2].getblockcount())
        assert_equal(self.ybalance('B', 1) - bb, amount)
        assert_equal(ba - self.ybalance('A', 0), amount + coins(YUGEN_FEE))
        self.check_static_memo(r['txid'], memo)
        return 'leaf send to static address, package %s, fee %d zat' % ('2184 B (memo)' if memo else '1672 B', YUGEN_FEE)

    def deposit_to_static(self, s, memo, amount):
        """Step 1: z_sendmany to the sender's Yugen deposit address (wallet A); step 2: A's deposit transfer
        pays B's static address directly, with the memo in the package (§7.9 rule 4, §10)."""
        n0 = self.nodes[0]
        before_s, before_y = self.total(n0), self.ybalance('B', 1)
        fund = self.zsend(s, self.ydeposit['A'], amount)
        fee1 = self.fee_of(n0, fund)
        assert_equal(fee1, self.expected_fee(s, ECC))
        self.mine(1)
        sh = self.ywallet('A', 0, 'shield', json.dumps([fund, self.ystatic['B']] + ([memo] if memo is not None else [])))
        assert_equal(zat(sh['fee']), YUGEN_FEE)
        sync_mempools(self.nodes)
        assert sh['txid'] in self.nodes[2].getrawmempool(), 'shield not relayed'
        h = self.mine(1)[0]
        assert sh['txid'] in self.nodes[2].getblock(h)['tx']
        self.mine_to_anchor(self.nodes[2].getblockcount())
        assert_equal(before_s - self.total(n0), amount + coins(fee1))
        assert_equal(self.ybalance('B', 1) - before_y, amount - coins(YUGEN_FEE))
        self.check_static_memo(sh['txid'], memo)
        return 'two-step: z_sendmany to the deposit taddr (fee %d) + deposit to the static address (fee %d)%s' % (
            fee1, YUGEN_FEE, ', memo shown' if memo else '')

    def zsend_yugen(self, s, d, memo, amount):
        """ONE z_sendmany to a Yugen address (decision Y-9b): from a transparent coin one deposit-shape Yugen
        transaction signed by the coins' own keys; from Sapling the wallet's own fresh-address hop, then the
        deposit, under one operation id."""
        n0, n1 = self.nodes[0], self.nodes[1]
        to = self.ystatic['B'] if d == YS else self.ywallet('B', 1, 'newaddress')
        assert to.startswith('yqrf1'), to[:20]
        before_s, before_y = self.total(n0), self.ybalance('B', 1)
        txid = self.zsend(s, to, amount, memo)
        sync_mempools(self.nodes)
        assert txid in n1.getrawmempool(), 'not relayed'
        raw = n0.getrawtransaction(txid, 1)
        assert_equal(raw['versiongroupid'], '59474e47')
        hop = 0
        for i in raw['vin']:
            prev = n0.getrawtransaction(i['txid'], 1)
            pa = prev['vout'][i['vout']]['scriptPubKey'].get('addresses', [None])[0]
            if s == SAP:
                # the wallet's own hop: a fresh address, used once, its coin spent whole (no change)
                assert_equal(len(raw['vin']), 1)
                assert_equal(len(raw['vout']), 0)
                assert_equal(len(prev['vShieldedSpend']) > 0, True)
                assert_equal(zat(prev['vout'][i['vout']]['value']), zat(amount) + YUGEN_FEE)
                assert_equal(n0.getreceivedbyaddress(pa, 0), amount + coins(YUGEN_FEE))
                hop = self.fee_of(n0, i['txid'])
                assert_equal(hop, DEFAULT_FEE)
            else:
                assert_equal(pa, self.src[s])
        if s != SAP:
            assert_equal(self.fee_of(n0, txid), zat(amount) + YUGEN_FEE)     # the amount enters the pool
        h = self.mine(1)[0]
        assert txid in self.nodes[2].getblock(h)['tx']
        self.mine_to_anchor(self.nodes[2].getblockcount())
        assert_equal(before_s - self.total(n0), amount + coins(YUGEN_FEE + hop))
        assert_equal(self.ybalance('B', 1) - before_y, amount)
        paid_static = d == YS or memo is not None      # P-3: a memo is carried by the static part
        if paid_static:
            self.check_static_memo(txid, memo)
        return 'one z_sendmany: %sdeposit to the %s (%d input(s)), fee %d zat%s' % (
            'Sapling -> fresh own taddr (fee %d) -> ' % hop if s == SAP else '',
            'static address' if d == YS else ('one-time address, static part (P-3)' if memo else 'one-time address, request'),
            len(raw['vin']), YUGEN_FEE, ', memo shown' if memo else '')

    def withdraw(self, to, amount):
        ba = self.ybalance('A', 0)
        r = self.ywallet('A', 0, 'withdraw', json.dumps([to, float(amount)]))
        assert_equal(zat(r['fee']), YUGEN_FEE)
        sync_mempools(self.nodes)
        assert r['txid'] in self.nodes[1].getrawmempool(), 'not relayed'
        h = self.mine(1)[0]
        assert r['txid'] in self.nodes[2].getblock(h)['tx']
        self.mine_to_anchor(self.nodes[2].getblockcount())
        assert_equal(ba - self.ybalance('A', 0), amount + coins(YUGEN_FEE))
        return r

    def yugen_to_transparent(self, d, memo, amount):
        to = self.dst[d]
        if memo is not None:
            out = self.ywallet('A', 0, 'withdraw', json.dumps([to, float(amount), memo]), ok=False)
            if out.returncode != 0 and 'memo' in (out.stdout + out.stderr).lower():
                return 'refused: ' + json.loads(out.stdout)['error'][:110]
            if out.returncode == 0:
                self.mine(1)
                raise AssertionError('withdrawal with a memo accepted (memo dropped): ' + out.stdout.strip()[:100])
            raise AssertionError('refused without naming the memo: ' + (out.stdout + out.stderr).strip()[:160])
        before = self.received(d, to)
        r = self.withdraw(to, amount)
        assert_equal(self.received(d, to) - before, amount)
        raw = self.nodes[1].getrawtransaction(r['txid'], 1)
        assert_equal(raw['vout'][0]['scriptPubKey']['hex'], self.nodes[1].validateaddress(to)['scriptPubKey'])
        return 'withdrawal (note + dummy, value_balance +%d), fee %d zat' % (zat(amount), YUGEN_FEE)

    def yewd_fund(self, amount):
        """yewd's own Yugen wallet: coins from node 0 to its transparent wallet, then yugen_shield to itself."""
        y = self.nodes[YEWD]
        own = y.yugen_getaddress()
        t = y.getnewaddress()
        self.nodes[0].sendtoaddress(t, amount + coins(YUGEN_FEE) + Decimal('0.001'))
        self.mine(1)
        y.yugen_shield(own, float(amount))
        h = self.nodes[2].getblockcount() + 1
        self.mine(1)
        self.mine_to_anchor(h)

    def yugen_to_sapling(self, memo, amount):
        """ONE call on yewd (decision Y-9b, decision Y-W9): yugen_send to a Sapling address withdraws amount + hop fee to
        a fresh own transparent address (never shown) and sends amount from it to Sapling with the memo, under the
        next block's branch (Y-W11). Both transactions are mined; the recipient sees the amount and the memo."""
        n1, y = self.nodes[1], self.nodes[YEWD]
        to = self.dst[SAP]
        need = amount + coins(YUGEN_FEE + DEFAULT_FEE)
        if Decimal(str(y.yugen_getbalance())) < need:
            self.yewd_fund(Decimal(2))
        assert_equal(int(y.getblockchaininfo()['consensus']['nextblock'], 16), YUGEN_BRANCH_ID)
        bal0 = Decimal(str(y.yugen_getbalance()))
        before = self.received(SAP, to)
        opts = {'route': 'leaf'}
        if memo is not None:
            opts['memo'] = memo
        r = y.yugen_send(to, float(amount), opts)
        assert_equal(r['operation'], 'yugen-to-sapling')
        try:
            sync_mempools(self.nodes)
        except AssertionError:
            pools = [set(n.getrawmempool()) for n in self.nodes]
            extra = set.union(*pools) - pools[2]
            why = []
            for t in extra:
                src = next(n for n, p in zip(self.nodes, pools) if t in p)
                try:
                    self.nodes[2].sendrawtransaction(src.getrawtransaction(t))
                    why.append('%s: accepted on resubmit' % t[:16])
                except JSONRPCException as e:
                    why.append('%s: %s' % (t[:16], e.error['message']))
            if extra and all('accepted on resubmit' in w for w in why):
                # valid but not relayed by yewd's backend (the unconfirmed child of the withdrawal): YELLOW, not GREEN
                sync_mempools(self.nodes)
                self.mine(1)
                self.mine_to_anchor(self.nodes[2].getblockcount())
                raise Skip('one yewd yugen_send built both legs, but the Sapling leg (child of the unconfirmed '
                           'withdrawal) was not relayed by the yewd backend; valid on resubmit (%s)' % '; '.join(why))
            raise AssertionError('mempools differ (%s; withdraw %s, sapling %s): %s' % (
                [len(p) for p in pools], r['withdraw_txid'][:16], r['sapling_txid'][:16], '; '.join(why)))
        mp = self.nodes[2].getrawmempool()
        assert r['withdraw_txid'] in mp and r['sapling_txid'] in mp, 'not relayed'
        h = self.mine(1)[0]
        tx = self.nodes[2].getblock(h)['tx']
        assert r['withdraw_txid'] in tx and r['sapling_txid'] in tx, 'not mined in one block'
        self.mine_to_anchor(self.nodes[2].getblockcount())
        assert_equal(self.received(SAP, to) - before, amount)
        assert_equal(zat(r['fee']), YUGEN_FEE + DEFAULT_FEE)
        assert_equal(bal0 - Decimal(str(y.yugen_getbalance())), amount + coins(YUGEN_FEE + DEFAULT_FEE))
        got = [o for o in n1.z_listreceivedbyaddress(to) if o['txid'] == r['sapling_txid']]
        assert_equal(len(got), 1)
        m = bytes.fromhex(got[0]['memo'])
        if memo is not None:
            assert_equal(m.rstrip(b'\0').decode(), memo)
        else:
            assert m[0] == 0xf6 and not any(m[1:]), 'empty memo expected'
        return 'one yewd yugen_send: withdraw (fee %d) + Sapling (fee %d) in one operation%s' % (
            YUGEN_FEE, DEFAULT_FEE, ', memo shown' if memo else '')

    # --- the ycashd wallet's Yugen account (N-A1..N-A3) ---
    def yc_received(self, txid):
        return [r for r in self.nodes[1].z_listreceivedbyaddress(self.yc_dst, 0) if r['txid'] == txid]

    def yc_balance(self, node, addr):
        return zat(node.z_getbalance(addr, 0))

    def ycashd_from(self, d, memo, amount):
        """ONE z_sendmany from node 0's Yugen account to any recipient."""
        n0, n1 = self.nodes[0], self.nodes[1]
        r = {'amount': amount}
        if memo is not None:
            r['memo'] = memo.encode().hex()
        if d in TRANSPARENT:
            r['address'] = self.dst[d]
            if memo is not None:
                try:
                    n0.z_sendmany(self.yc_src, [r])
                except JSONRPCException as e:
                    assert 'memo' in e.error['message'], e.error['message']
                    return 'refused: ' + e.error['message'][:100]
                raise AssertionError('memo to a transparent recipient accepted')
        elif d == SAP:
            r['address'] = self.dst[SAP]
        elif d == YS:
            r['address'] = self.ystatic['B']
        elif d == YR:
            r['address'] = self.ywallet('B', 1, 'newaddress')
        else:
            r['address'] = self.yc_dst
        before = self.yc_balance(n0, self.yc_src)
        before_r = self.ybalance('B', 1) if d in (YS, YR) else (self.received(d, r['address']) if d != YC else None)
        res = self.wait_result(n0, n0.z_sendmany(self.yc_src, [r]))
        txid = res['txid']
        self.mine(2)
        self.mine_to_anchor(self.nodes[2].getblockcount())
        hop = HOP_FEE if d == SAP else 0
        assert_equal(before - self.yc_balance(n0, self.yc_src), zat(amount) + YUGEN_FEE + hop)
        if d in TRANSPARENT or d == SAP:
            assert_equal(self.received(d, r['address']) - before_r, amount)
        elif d in (YS, YR):
            assert_equal(self.ybalance('B', 1) - before_r, amount)
            if d == YS or memo is not None:
                self.check_static_memo(txid, memo)
        else:
            got = self.yc_received(txid)
            assert_equal(len(got), 1)
            assert_equal(zat(got[0]['amount']), zat(amount))
            assert_equal(got[0].get('memoStr'), memo)
        if d == SAP and memo is not None:
            got = [o for o in n1.z_listreceivedbyaddress(r['address']) if o['txid'] == txid]
            assert_equal(bytes.fromhex(got[0]['memo']).rstrip(b'\0').decode(), memo)
        return 'one z_sendmany from the ycashd Yugen account%s, fee %d zat' % (
            ' (withdrawal + hop %s)' % res.get('withdraw_txid', '')[:8] if d == SAP else '', YUGEN_FEE + hop)

    def wait_result(self, node, opid):
        for _ in range(1800):
            st = node.z_getoperationstatus([opid])[0]
            if st['status'] == 'success':
                return node.z_getoperationresult([opid])[0]['result']
            if st['status'] in ('failed', 'cancelled'):
                raise AssertionError(st.get('error'))
            time.sleep(1)
        raise AssertionError('operation timed out')

    def to_ycashd(self, s, memo, amount):
        """Any sender to node 1's Yugen account (its address, full form: no hosts in this matrix)."""
        n1 = self.nodes[1]
        before = self.yc_balance(n1, self.yc_dst)
        if s == 'Yugen':
            args = [self.yc_dst, float(amount)] + ([memo] if memo else [])
            txid = self.ywallet('A', 0, 'send', json.dumps(args))['txid']
        else:
            txid = self.zsend(s, self.yc_dst, amount, memo)
        self.mine(1)
        self.mine_to_anchor(self.nodes[2].getblockcount())
        got = self.yc_received(txid)
        assert_equal(len(got), 1)
        assert_equal(self.yc_balance(n1, self.yc_dst) - before, zat(amount))
        assert_equal(got[0].get('memoStr'), memo)
        return 'received by the ycashd Yugen account (z_listreceivedbyaddress%s)' % (', memo shown' if memo else '')

    def cell(self, s, d, memo, amount):
        if s == YC:
            return self.ycashd_from(d, memo, amount), False
        if d == YC:
            return self.to_ycashd(s, memo, amount), False
        if s == 'Yugen':
            if d == YR:
                return self.yugen_to_request(memo, amount), False
            if d == YS:
                return self.yugen_to_static(memo, amount), False
            if d == SAP:
                return self.yugen_to_sapling(memo, amount), False
            return self.yugen_to_transparent(d, memo, amount), False
        if d in (YS, YR):
            return self.zsend_yugen(s, d, memo, amount), False
        return self.node_cell(s, d, memo, amount), False

    def run_test(self):
        n0, n1, n2 = self.nodes[:3]
        n0.generate(110)
        self.mine(110)              # every node-0 coinbase mature; node 2 mines from here on
        self.wdir = {k: tempfile.mkdtemp(prefix='yewd-%s-' % k, dir=self.options.tmpdir) for k in 'AB'}
        self.src = {ECC: n0.getnewaddress(), SAP: n0.z_getnewaddress('sapling'),
                    SLH: n0.getnewaddress('', 'pqslh'), FN: n0.getnewaddress('', 'pq')}
        self.dst = {ECC: n1.getnewaddress(), SAP: n1.z_getnewaddress('sapling'),
                    SLH: n1.getnewaddress('', 'pqslh'), FN: n1.getnewaddress('', 'pq')}
        for k in (SLH, FN):
            assert_equal(n0.validateaddress(self.src[k])['pqscheme'], {SLH: 1, FN: 2}[k])
        # the reusable Yugen address (static part only; full form, no hosts here)
        self.ystatic = {k: self.ywallet(k, i, 'getaddress') for k, i in (('A', 0), ('B', 1))}
        self.ydeposit = {k: (lambda a: a if isinstance(a, str) else a['address'])(
            self.ywallet(k, i, 'depositaddress')) for k, i in (('A', 0), ('B', 1))}

        print('fund node 0: twelve 2-YEC coins at ECC, four at each PQ address, four 2-YEC Sapling notes; Yugen wallet A')
        fund = n0.getnewaddress()
        for _ in range(4):
            n0.sendtoaddress(fund, 3)
            for k in (ECC, SLH, FN):
                n0.sendtoaddress(self.src[k], 2)
        for _ in range(8):          # ECC change goes to a fresh key, so each ECC send takes a whole coin
            n0.sendtoaddress(self.src[ECC], 2)
        ya = n0.sendtoaddress(self.ydeposit['A'], 10)
        self.mine(1)
        for _ in range(4):
            wait_and_assert_operationid_status(n0, n0.z_sendmany(fund, [{'address': self.src[SAP], 'amount': 2}], 1, None, 'AllowFullyTransparent'))
        sh = self.ywallet('A', 0, 'shield', json.dumps([ya]))
        h = n2.getblockcount() + 1
        self.mine(1)
        self.mine_to_anchor(h)
        assert_equal(self.ybalance('A', 0), Decimal(10) - coins(YUGEN_FEE))
        print('  Yugen wallet A shielded %s (%s)' % (sh['amount'], sh['txid']))

        # the ycashd wallet's own Yugen accounts (N-A1): node 0 sends from its account, node 1 receives in its own
        self.yc_src = n0.z_getnewaddress('yugen')
        self.yc_dst = n1.z_getnewaddress('yugen')
        t = n0.getnewaddress()
        n0.sendtoaddress(t, 12)
        self.mine(1)
        wait_and_assert_operationid_status(n0, n0.z_sendmany(t, [{'address': self.yc_src, 'amount': 10}], 1))
        h = n2.getblockcount() + 1
        self.mine(1)
        self.mine_to_anchor(h)
        assert_equal(zat(n0.z_getbalance(self.yc_src)), zat(10))
        print('  ycashd Yugen account %s funded with 10' % self.yc_src[:20])

        rows = []
        amount = Decimal('0.10')
        for s in RUN_SENDERS:
            for d in RECIPIENTS:
                for memo in (None, 'spend matrix: %s to %s' % (s, d)):
                    amount += Decimal('0.01')
                    tag = 'memo' if memo else 'none'
                    try:
                        note, two_step = self.cell(s, d, memo, amount)
                        st = 'YELLOW' if two_step else 'GREEN'
                    except Skip as e:
                        st, note = 'YELLOW', str(e)
                    except Exception as e:
                        st = 'RED'
                        note = '%s: %s' % (type(e).__name__, str(e).replace('\n', ' ')[:300])
                        traceback.print_exc()
                    if s in ('Yugen', YC) or d in (YR, YC):
                        self.mine_to_anchor(n2.getblockcount())   # Yugen change/notes spendable next cell
                    rows.append((s, d, tag, st, note))
                    print('  %-9s -> %-13s %-4s %-6s %s' % (s, d, tag, st, note))
        self.write(rows)
        assert not any(r[3] == 'RED' for r in rows), 'RED cells: see %s' % OUT

    def write(self, rows):
        c = {k: sum(1 for r in rows if r[3] == k) for k in ('GREEN', 'YELLOW', 'RED')}
        lines = ['# Spend matrix status', '',
                 'Regtest, Vault at %d, Falcon at %d, Yugen at %d; ycashd %s; yewd-yugen %s.' % (
                     VAULT_H, FALCON_H, YUGEN_H, os.environ.get('MATRIX_YCASHD_REV', '?'), os.environ.get('MATRIX_YEW_REV', '?')),
                 'Spec 0.5.2 (yugen-spec tag spec-0.5.2). Generated by qa/rpc-tests/spend_matrix.py; senders: %s.' % (
                     ', '.join(RUN_SENDERS)), '',
                 '**GREEN %d, YELLOW %d, RED %d** (of %d)' % (c['GREEN'], c['YELLOW'], c['RED'], len(rows)), '',
                 '| From | To | Memo | Status | Detail |', '|---|---|---|---|---|']
        lines += ['| %s | %s | %s | %s | %s |' % (s, d, m, st, n.replace('|', '/')) for s, d, m, st, n in rows]
        text = '\n'.join(lines) + '\n'
        with open(OUT, 'w') as f:
            f.write(text)
        print(text)


if __name__ == '__main__':
    SpendMatrixTest().main()
