#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The address matrix (beta2 address interoperability plan §6, decisions D-2, D-4, D-6): plain YEC moves between every
address type with the documented call, z_sendmany (and z_mergetoaddress), on one script that runs unchanged on both
C++ node lines.

Address types: ECC (transparent P2PKH), Sapling, and post-quantum (TX_PQPKH) in both schemes, FN-DSA-512 (scheme 2)
and SLH-DSA-SHA2-128s (scheme 1). The scheme of a PQ address is read from validateaddress (pqscheme); no address or
prefix is hard-coded (the prefixes change under D-9).

- sources ECC, Sapling, PQ FN-DSA, PQ SLH-DSA x destinations ECC, Sapling, PQ FN-DSA, PQ SLH-DSA (16 cells), plus a
  multi-recipient send mixing all four types from a PQ source and from a Sapling source. For every transaction:
  accepted to the mempool of a second node, mined, its fee pinned to a fixed number for its shape (computed here from
  the ZIP-317 sizes of an SLH-DSA input, 7,981 bytes = 54 logical actions = 27,000 zat, and an FN-DSA input, 1,620
  bytes = 11 actions = 5,500 zat, +500 per Sapling output (6.x: +1,000 for a lone one, which its Sapling builder pads
  to two); 1,000 zat without a PQ input, the default on both lines), change from a PQ source back
  to that address (D-4) and from a Sapling source a Sapling note, balances and listings right on both wallets; one
  reorg across the block, then the same checks; then every output the receiver got is spent (each receiving address
  is emptied with z_mergetoaddress);
- z_mergetoaddress: PQ -> PQ, PQ + ECC -> Sapling, Sapling -> PQ, P2SH multisig + PQ -> ECC, and the per-transaction
  PQ input cap (100: the merge takes 100 and reports the rest);
- change below the PQ dust threshold goes to the fee; a send that needs more than 100 PQ inputs is refused;
- refusals: before the vault upgrade, an FN-DSA address before Falcon, an amount below the PQ dust threshold, an
  explicit fee below what a PQ spend needs, a PQ address of another wallet, insufficient PQ funds, a locked wallet,
  and an ECC source holding only coinbase paying a PQ address (coinbase is never selected for a transparent recipient);
- on 6.x (PRIVACY_POLICY) the privacy policy each PQ shape needs (D-5);
- YED token protection, last: Yellowback goes live on nodes 0-2 (node 3 stops); a YED token on a fresh Falcon holder
  key (a mint) and on a fresh holder key of a wallet that holds nothing else transparent (a transfer): z_sendmany from
  the key to Sapling, ECC and both PQ schemes, z_mergetoaddress of the key and the wildcard merges all fail as from an
  empty address, the token stays in listlockunspent, also after `lockunspent true`, and yed_getbalance never moves;
  with the coin lock removed on purpose (yed_unlockcoin) the wallet's second check refuses the outpoint by name
  ("refusing to spend a Yellowback outpoint as plain YEC: <txid>:<n>") on every path that can select a Falcon coin
  (z_sendmany and z_mergetoaddress from the key, sendtoaddress, sendmany), also for an unconfirmed token at minconf 0,
  and spends a holder key's plain coins without its token. (An ECC-key token, which only a mint before Falcon makes,
  and the ECC and ANY_TADDR paths: wallet_yed_ecc_token.py.)

Node profile P0 (no index) for the matrix: every check uses the wallet calls only. The line differences (ycash-dd
v4.5.0, ycash6 6.x) sit behind the test_framework/util.py line helpers, so this file is byte-identical on both lines.

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/wallet_address_matrix.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

import time
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    COINBASE_ONLY_TRANSPARENT_REFUSAL,
    LONE_SAPLING_OUTPUT_ACTIONS,
    PRIVACY_POLICY,
    VAULT_BRANCH_ID,
    Z_MERGE_NOTE_DEPTH,
    assert_equal,
    bitcoind_processes,
    connect_nodes_bi,
    lockunspent_true,
    get_coinbase_address,
    nuparams,
    start_node,
    start_nodes,
    stop_node,
    sync_blocks,
    sync_mempools,
    wait_and_assert_operationid_status,
    z_mergetoaddress_call,
    z_sendmany_opid,
)
from test_framework.yellowback_attest import wait_for_spender
from test_framework.yellowback_util import MIN_MINT, activate_yed_late, mint_to_fresh_holder

ACTIVATION = 210        # the vault upgrade (UPGRADE_VAULT)
FALCON = 220            # -pqfalconheight: FN-DSA-512 admitted from here
DEFAULT_FEE = 1000      # policy/fees.h (ycash-dd); ycash6's -feepolicy=peroutput default for these shapes
# Fixed fees of fixed shapes (ZIP-317: 500 zat x max(2, ceil(vin bytes / 150), ceil(vout bytes / 34)) + Sapling outputs;
# an input is outpoint 36 + compact size + scriptSig + sequence 4: SLH-DSA 7,938-byte scriptSig = 7,981 bytes,
# FN-DSA 1,577-byte scriptSig = 1,620 bytes, P2PKH ~148 bytes). -pqfeerate x size (100 zat/kB) is far below these.
FEE_SLH = 27000         # one SLH-DSA input: ceil(7981 / 150) = 54 actions
FEE_FN = 5500           # one FN-DSA input: ceil(1620 / 150) = 11 actions
FEE_SAPLING_OUT = 500   # one Sapling output: one more action
PQ_CAP = 100            # MAX_PQ_INPUTS_PER_TX
ECC, SAP, FN, SLH = 'ECC', 'Sapling', 'PQ-FN-DSA', 'PQ-SLH-DSA'
KINDS = (ECC, SAP, FN, SLH)

LOCKED = 'Please enter the wallet passphrase with walletpassphrase first'
NO_PQ_UTXOS = 'Insufficient transparent funds, no UTXOs found for taddr from address.'
NO_MERGE_FUNDS = 'Could not find any funds to merge.'
YED_REFUSED = 'refusing to spend a Yellowback outpoint as plain YEC: '
UNLOCK_ACK = 'I understand this burns YED'


def zat(x):
    return int((Decimal(x) * 100000000).to_integral_value())


def coins(z):
    return Decimal(z) / 100000000


def assert_raises_rpc(substr, fn, *args):
    try:
        fn(*args)
    except JSONRPCException as e:
        assert substr in e.error['message'], 'expected %r in %r' % (substr, e.error['message'])
        return e.error['message']
    raise AssertionError('expected an RPC error containing %r' % substr)


class WalletAddressMatrixTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = True

    def node_args(self, i):
        a = [nuparams(VAULT_BRANCH_ID, ACTIVATION), '-pqfalconheight=%d' % FALCON]
        if i == 3:
            a += ['-experimentalfeatures', '-developerencryptwallet']
        return a + getattr(self, 'yed_args', {}).get(i, [])

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 extra_args=[self.node_args(i) for i in range(self.num_nodes)])
        for a, b in ((0, 1), (1, 2), (0, 2), (2, 3)):
            connect_nodes_bi(self.nodes, a, b)
        self.is_network_split = False
        self.sync_all()

    # --- line differences (ycash-dd v4.5.0 / ycash6 6.x): behind the test_framework/util.py line helpers, so this file
    # is byte-identical on both lines (z_sendmany_opid, z_mergetoaddress_call, PRIVACY_POLICY,
    # LONE_SAPLING_OUTPUT_ACTIONS, Z_MERGE_NOTE_DEPTH, COINBASE_ONLY_TRANSPARENT_REFUSAL) ---

    def zsend(self, node, src, recipients, fee=None):
        """z_sendmany with the documented arguments (on 6.x the privacy policy a transparent party needs, D-5)."""
        return z_sendmany_opid(node, src, recipients, 1, fee)

    def zsend_ok(self, node, src, recipients, fee=None):
        return wait_and_assert_operationid_status(node, self.zsend(node, src, recipients, fee))

    def zsend_fails(self, node, src, recipients, substr, fee=None):
        opid = self.zsend(node, src, recipients, fee)
        res = None
        for _ in range(300):
            r = node.z_getoperationresult([opid])
            if r:
                res = r[0]
                break
            time.sleep(1)
        assert res is not None, 'timeout'
        assert_equal(res['status'], 'failed')
        assert substr in res['error']['message'], (substr, res['error']['message'])

    # --- helpers ---

    def mine(self, n=1):
        self.sync_all()
        blocks = self.nodes[2].generate(n)
        self.sync_all()
        return blocks

    def kind_of(self, node, addr):
        v = node.validateaddress(addr)
        if v.get('isvalid') and 'pqscheme' in v:
            return {2: FN, 1: SLH}[v['pqscheme']]
        if v.get('isvalid'):
            return ECC
        assert node.z_validateaddress(addr)['isvalid'], addr
        return SAP

    def spk(self, node, addr):
        return node.validateaddress(addr)['scriptPubKey']

    def fee_of(self, node, txid):
        """The network fee of a wallet transaction still in the mempool: inputs (from the wallet) - outputs."""
        raw = node.getrawtransaction(txid, 1)
        vin = 0
        for i in raw['vin']:
            prev = node.decoderawtransaction(node.gettransaction(i['txid'])['hex'])
            vin += zat(prev['vout'][i['vout']]['value'])
        vout = sum(zat(o['value']) for o in raw['vout'])
        return vin + zat(raw.get('valueBalance', 0)) - vout, raw

    def has_pq_input(self, node, raw):
        for i in raw['vin']:
            prev = node.decoderawtransaction(node.gettransaction(i['txid'])['hex'])
            if prev['vout'][i['vout']]['scriptPubKey']['type'] == 'pqpubkeyhash':
                return True
        return False

    def check_sent(self, node, txid, src, expected=None):
        """Mempool of a second node, the fee (a fixed number for a PQ shape; the line's default otherwise), D-4 change."""
        sync_mempools(self.nodes[:3])
        assert txid in self.nodes[2].getrawmempool(), txid
        fee, raw = self.fee_of(node, txid)
        pq = self.has_pq_input(node, raw)
        assert_equal(pq, expected is not None)
        assert_equal(fee, expected if pq else DEFAULT_FEE)      # both lines: v4.5.0 DEFAULT_FEE, 6.x -feepolicy=peroutput
        if src is not None and self.kind_of(node, src) in (FN, SLH):
            assert pq, txid
            src_spk = self.spk(node, src)
            mine_spks = [o['scriptPubKey']['hex'] for o in raw['vout'] if node.validateaddress(o['scriptPubKey']['addresses'][0])['ismine']]
            assert all(s == src_spk for s in mine_spks), (txid, mine_spks)
        if src is not None and self.kind_of(node, src) == SAP:
            assert all(not node.validateaddress(o['scriptPubKey']['addresses'][0])['ismine'] for o in raw['vout']), txid
        return fee

    def received(self, node, addr):
        if self.kind_of(node, addr) == SAP:
            return Decimal(node.z_getbalance(addr))
        return node.getreceivedbyaddress(addr)

    def unspent(self, node, addr):
        if self.kind_of(node, addr) == SAP:
            return sum(Decimal(u['amount']) for u in node.z_listunspent(1, 9999999, False, [addr]))
        return sum(u['amount'] for u in node.listunspent(1, 9999999, [addr]))

    def run_test(self):
        n0, n1, n2, n3 = self.nodes
        n0.generate(120)          # node 0 (the sender) holds mature coinbase; node 2 mines from here on
        self.mine(ACTIVATION + 1 - n0.getblockcount())

        print('addresses of every type on the sender (node 0) and the receiver (node 1)')
        src = {ECC: n0.getnewaddress(), SAP: n0.z_getnewaddress('sapling'), SLH: n0.getnewaddress('', 'pqslh')}
        dst = {ECC: n1.getnewaddress(), SAP: n1.z_getnewaddress('sapling'), SLH: n1.getnewaddress('', 'pqslh')}
        locked_pq = n3.getnewaddress('', 'pqslh')

        # Each refusal rewinds node 0 a few blocks with invalidateblock (fewer than six, or safe mode answers).
        print('refusals before the vault upgrade')
        h_vault = n0.getblockhash(ACTIVATION - 1)
        n0.invalidateblock(h_vault)
        assert n0.getblockcount() + 1 < ACTIVATION
        assert_raises_rpc('post-quantum addresses can be paid only once the vault upgrade is active',
                          self.zsend, n0, src[ECC], [(dst[SLH], 1)])
        assert_raises_rpc('post-quantum addresses can be spent from only once the vault upgrade is active',
                          self.zsend, n0, src[SLH], [(dst[ECC], 1)])
        assert_raises_rpc('can be spent from only once the vault upgrade is active', z_mergetoaddress_call, n0, [src[SLH]], dst[ECC])
        n0.reconsiderblock(h_vault)
        sync_blocks(self.nodes)

        self.mine(FALCON + 2 - n0.getblockcount())
        src[FN] = n0.getnewaddress('', 'pq')      # FN-DSA-512 once Falcon is active at the next block
        dst[FN] = n1.getnewaddress('', 'pq')
        for k in KINDS:
            assert_equal(self.kind_of(n0, src[k]), k)
            assert_equal(self.kind_of(n1, dst[k]), k)

        print('refusals before Falcon')
        h_falcon = n0.getblockhash(FALCON - 2)
        n0.invalidateblock(h_falcon)
        assert n0.getblockcount() + 1 < FALCON
        assert_raises_rpc('FN-DSA-512 (scheme 2) post-quantum address can be paid only once Falcon is active',
                          self.zsend, n0, src[ECC], [(dst[FN], 1)])
        assert_raises_rpc('FN-DSA-512 (scheme 2) post-quantum address can be spent from only once Falcon is active',
                          self.zsend, n0, src[FN], [(dst[ECC], 1)])
        assert_raises_rpc('can be spent from only once Falcon is active', z_mergetoaddress_call, n0, [src[FN]], dst[ECC])
        n0.reconsiderblock(h_falcon)
        sync_blocks(self.nodes)

        print('fund node 0: five 1-YEC coins at ECC and at each PQ address, five 1-YEC Sapling notes')
        fund = n0.getnewaddress()
        for _ in range(5):
            n0.sendtoaddress(fund, 2)
            for k in (ECC, FN, SLH):
                n0.sendtoaddress(src[k], 1)
        self.mine(1)
        for _ in range(5):
            self.zsend_ok(n0, fund, [(src[SAP], 1)])
        self.mine(1)
        for k in KINDS:
            assert_equal(self.unspent(n0, src[k]), Decimal(5))

        print('refusals: PQ dust, an explicit fee below a PQ spend, another wallet\'s PQ address, a coinbase-only ECC source, a locked wallet')
        assert_raises_rpc('below the dust threshold', self.zsend, n0, src[ECC], [(dst[SLH], Decimal('0.00001'))])
        assert_raises_rpc('below the dust threshold', self.zsend, n0, src[SAP], [(dst[FN], Decimal('0.00000100'))])
        self.zsend_fails(n0, src[SLH], [(dst[ECC], Decimal('0.1'))], 'Fee 0.0001 is below the', Decimal('0.0001'))
        assert_raises_rpc('From address does not belong to this node, post-quantum key not found.',
                          self.zsend, n0, dst[SLH], [(src[ECC], Decimal('0.1'))])
        assert_raises_rpc('From address does not belong to this node, post-quantum key not found.',
                          z_mergetoaddress_call, n0, [dst[FN]], src[ECC])
        cb = get_coinbase_address(n0)
        self.zsend_fails(n0, cb, [(dst[SLH], 1)], COINBASE_ONLY_TRANSPARENT_REFUSAL)
        n3.encryptwallet('matrix-pass')
        bitcoind_processes[3].wait()
        self.nodes[3] = n3 = start_node(3, self.options.tmpdir, self.node_args(3))
        connect_nodes_bi(self.nodes, 2, 3)
        assert_raises_rpc(LOCKED, self.zsend, n3, locked_pq, [(dst[ECC], 1)])
        assert_raises_rpc(LOCKED, z_mergetoaddress_call, n3, [locked_pq], dst[ECC])

        print('the matrix: 16 cells and two mixed sends, all with the documented call (z_sendmany)')
        expect_in = {k: Decimal(0) for k in KINDS}        # receiver totals per destination
        expect_left = {k: Decimal(5) for k in KINDS}      # sender totals per source (PQ and Sapling: change returns)
        sent = []                                         # (txid, source kind)
        amount = Decimal('0.10')
        for s in KINDS:
            for d in KINDS:
                amount += Decimal('0.01')
                txid = self.zsend_ok(n0, src[s], [(dst[d], amount)])
                fee = self.check_sent(n0, txid, src[s], self.pq_fee(s, d == SAP))
                expect_in[d] += amount
                expect_left[s] -= amount + coins(fee)
                sent.append((txid, s))
                print('  %-10s -> %-10s %s fee %d' % (s, d, amount, fee))
        for s in (SLH, SAP):
            mixed = [(dst[d], Decimal('0.05')) for d in KINDS]
            txid = self.zsend_ok(n0, src[s], mixed)
            fee = self.check_sent(n0, txid, src[s], self.pq_fee(s, True))
            for d in KINDS:
                expect_in[d] += Decimal('0.05')
            expect_left[s] -= Decimal('0.20') + coins(fee)
            sent.append((txid, s))
            print('  %-10s -> all four  0.05 each, fee %d' % (s, fee))

        def check_balances(label):
            print('  balances and listings (%s)' % label)
            for k in KINDS:
                assert_equal(self.received(n1, dst[k]), expect_in[k])
                assert_equal(self.unspent(n1, dst[k]), expect_in[k])
                if k != ECC:   # ECC change goes to a fresh key (-sendchangeback off)
                    assert_equal(self.unspent(n0, src[k]), expect_left[k])
            for txid, s in sent:
                assert_equal(n0.gettransaction(txid)['confirmations'], 1)
                assert_equal(n1.gettransaction(txid)['confirmations'], 1)
            listed = {t['txid'] for t in n1.listtransactions('*', 1000)}
            for txid, s in sent:
                raw = n0.decoderawtransaction(n0.gettransaction(txid)['hex'])
                if any(o['scriptPubKey'].get('addresses', [None])[0] in (dst[ECC], dst[FN], dst[SLH]) for o in raw['vout']):
                    assert txid in listed, txid
            zlisted = {r['txid'] for r in n1.z_listreceivedbyaddress(dst[SAP])}
            assert_equal(len(zlisted), 6)

        print('mine the matrix')
        block = self.mine(1)[0]
        check_balances('mined')

        print('one reorg across the matrix block: every transaction returns to the mempool and is mined again')
        for n in self.nodes:
            n.invalidateblock(block)
        for txid, _ in sent:
            assert txid in n2.getrawmempool(), txid
        block2 = self.mine(1)[0]
        assert block2 != block
        for txid, _ in sent:
            assert_equal(n0.gettransaction(txid)['blockhash'], block2)
        check_balances('after the reorg')

        print('every output node 1 received is spent: each receiving address emptied with z_mergetoaddress')
        back = n0.getnewaddress()
        if Z_MERGE_NOTE_DEPTH > 1:
            self.mine(Z_MERGE_NOTE_DEPTH - 1)      # 6.x merges a note only at nAnchorConfirmations deep
        # six outputs at each address (four cells + two mixed sends): the fees of six inputs of each kind
        merge_fee = {ECC: None, SAP: None, FN: 500 * -(-6 * 1620 // 150), SLH: 500 * -(-6 * 7981 // 150)}
        total_back = Decimal(0)
        for d in KINDS:
            r = z_mergetoaddress_call(n1, [dst[d]] if d != SAP else ['ANY_SAPLING'], back)
            assert_equal(r['mergingUTXOs'] + r['mergingNotes'], 6)
            txid = wait_and_assert_operationid_status(n1, r['opid'])
            fee = self.check_sent(n1, txid, None, merge_fee[d])
            total_back += expect_in[d] - coins(fee)
        self.mine(1)
        for d in KINDS:
            assert_equal(self.unspent(n1, dst[d]), 0)
        assert_equal(n0.getreceivedbyaddress(back), total_back)

        print('z_mergetoaddress: PQ -> PQ, PQ + ECC -> Sapling, Sapling -> PQ')
        merged_pq = n0.getnewaddress('', 'pqslh')
        r = z_mergetoaddress_call(n0, [src[FN]], merged_pq)
        assert_equal(r['mergingUTXOs'], 5)                # one unspent original and four D-4 change outputs
        txid = wait_and_assert_operationid_status(n0, r['opid'])
        fee = self.check_sent(n0, txid, None, 500 * -(-5 * 1620 // 150))
        assert_equal(coins(fee), Decimal(r['mergingTransparentValue']) - n0.getrawtransaction(txid, 1)['vout'][0]['value'])
        self.mine(1)
        assert_equal(self.unspent(n0, src[FN]), 0)
        assert_raises_rpc('Fee 0.0001 is below the', z_mergetoaddress_call, n0, [merged_pq], dst[ECC], Decimal('0.0001'))
        r = z_mergetoaddress_call(n0, [src[SLH], src[ECC]], src[SAP])
        assert_equal(r['mergingUTXOs'], 6)                # five SLH-DSA change outputs and one ECC coin
        txid = wait_and_assert_operationid_status(n0, r['opid'])
        self.check_sent(n0, txid, None, 500 * (-(-(5 * 7981 + 148) // 150) + LONE_SAPLING_OUTPUT_ACTIONS))
        self.mine(1)
        assert_equal(self.unspent(n0, src[SLH]), 0)
        merged_fn = n0.getnewaddress('', 'pq')
        r = z_mergetoaddress_call(n0, ['ANY_SAPLING'], merged_fn)
        txid = wait_and_assert_operationid_status(n0, r['opid'])
        fee = self.check_sent(n0, txid, None)
        self.mine(1)
        assert_equal(self.unspent(n0, merged_fn), Decimal(r['mergingShieldedValue']) - coins(fee))
        txid = self.zsend_ok(n0, merged_fn, [(dst[SAP], Decimal('0.5'))])
        self.check_sent(n0, txid, merged_fn, FEE_FN + FEE_SAPLING_OUT * LONE_SAPLING_OUTPUT_ACTIONS)
        self.mine(1)

        print('z_mergetoaddress: a P2SH multisig coin and a PQ coin in one merge (the policy sigops of both)')
        k1, k2 = n0.getnewaddress(), n0.getnewaddress()
        msig = n0.addmultisigaddress(2, [n0.validateaddress(k1)['pubkey'], n0.validateaddress(k2)['pubkey']])
        pq_one = n0.getnewaddress('', 'pqslh')
        n0.sendtoaddress(msig, 1)
        n0.sendtoaddress(pq_one, 1)
        self.mine(1)
        r = z_mergetoaddress_call(n0, [msig, pq_one], back)
        assert_equal(r['mergingUTXOs'], 2)
        txid = wait_and_assert_operationid_status(n0, r['opid'])
        # vin: 7,981 (SLH-DSA) + ~260 (2-of-2 P2SH: OP_0, two signatures, the 71-byte redeem script) = 55 actions
        self.check_sent(n0, txid, None, 27500)
        self.mine(1)

        print('PQ change below the dust threshold goes to the fee')
        dust_src = n0.getnewaddress('', 'pqslh')
        n0.sendtoaddress(dust_src, 1)
        self.mine(1)
        txid = self.zsend_ok(n0, dust_src, [(n1.getnewaddress(), Decimal(1) - coins(FEE_SLH + 500))])
        assert_equal(len(n0.getrawtransaction(txid, 1)['vout']), 1)     # no change output
        self.check_sent(n0, txid, dust_src, FEE_SLH + 500)                # the 500-zat dust is part of the fee
        self.mine(1)
        assert_equal(self.unspent(n0, dust_src), 0)

        print('insufficient PQ funds; more than %d PQ inputs (send refused, merge takes %d and reports the rest)' % (PQ_CAP, PQ_CAP))
        small = n0.getnewaddress('', 'pq')
        self.zsend_fails(n0, small, [(back, Decimal('0.1'))], 'Insufficient transparent funds, no UTXOs found')
        small_spk = self.spk(n0, small)
        held = []    # locked while funding, or sendtoaddress would select them again (it spends PQ coins too)
        for i in range(PQ_CAP + 10):
            txid = n0.sendtoaddress(small, Decimal('0.001'))
            vout = [o['n'] for o in n0.getrawtransaction(txid, 1)['vout'] if o['scriptPubKey']['hex'] == small_spk][0]
            held.append({'txid': txid, 'vout': vout})
            n0.lockunspent(False, [held[-1]])
            if i % 20 == 19:
                self.mine(1)
        self.mine(1)
        n0.lockunspent(True, held)
        assert_equal(self.unspent(n0, small), Decimal('0.110'))
        self.zsend_fails(n0, small, [(back, Decimal('0.2'))], 'Insufficient transparent funds, have 0.11')
        self.zsend_fails(n0, small, [(back, Decimal('0.1'))],
                         'This send needs %d post-quantum inputs, more than the %d one transaction may carry' % (PQ_CAP + 1, PQ_CAP))
        cap_fee = 500 * -(-PQ_CAP * 1620 // 150)       # 1,080 actions: 0.0054 YEC, given explicitly (limit 0 needs a fee)
        r = z_mergetoaddress_call(n0, [small], merged_fn, coins(cap_fee), 0)
        assert_equal((r['mergingUTXOs'], r['remainingUTXOs']), (PQ_CAP, 10))
        txid = wait_and_assert_operationid_status(n0, r['opid'])
        self.check_sent(n0, txid, None, cap_fee)
        self.mine(1)
        assert_equal(len(n0.listunspent(1, 9999999, [small])), 10)

        if PRIVACY_POLICY:
            self.check_privacy_policy(n0, n1)
        self.token_protection(back)

    def token_protection(self, back):
        """A YED token is never spent as plain YEC by the wallet's own coin selection.

        The Yellowback wallet layer locks every token output; consensus would accept a plain spend of one and burn its
        YED. Node 0 mints (each token on a fresh Falcon holder key) and sends node 1 a token on a fresh Falcon holder
        key; node 1's wallet then holds nothing else transparent. (From the Falcon height every YED output is at a
        Falcon key, so no ECC-key token exists here; ANY_TADDR, which selects ECC coins only, is checked against an
        ECC-key token in wallet_yed_ecc_token.py. The wildcard merges here show only that they never take a
        post-quantum coin.)

        - Locks in place, and again after `lockunspent true` (which re-applies them): z_sendmany from either key, the
          merges of either key and the wildcard merges all fail as from an empty address.
        - A lock removed on purpose (yed_unlockcoin): the wallet's second check refuses the outpoint by name on every
          path that can select a Falcon coin: z_sendmany from the key, z_mergetoaddress of the key (with and without
          ANY_SAPLING), sendtoaddress and sendmany (CreateTransaction); ANY_TADDR still finds nothing.
        - An unconfirmed token (a MINT in the mempool), its lock removed: z_sendmany ... minconf 0 from its holder key
          is refused by the payload check.
        - A holder key that also holds plain YEC, its token unlocked: z_sendmany and z_mergetoaddress spend the plain
          coins and leave the token alone.
        The token outputs stay unspent and yed_getbalance never moves."""
        n0, n1, n2, n3 = self.nodes
        print('token protection: YED on nodes 0-2 (node 3 stops), mints to fresh Falcon holder keys')
        # empty node 1 (the dust case paid it a coin, the Sapling -> PQ case a note) so the wildcards find nothing else
        wait_and_assert_operationid_status(n1, z_mergetoaddress_call(n1, ['ANY_TADDR', 'ANY_SAPLING'], back)['opid'])
        self.mine(1)
        # and of coinbase (z_mergetoaddress never merges it; 6.x leaves node 1 the cached chain's mature coinbase)
        while [u for u in n1.listunspent(1) if u.get('generated')]:
            wait_and_assert_operationid_status(n1, n1.z_shieldcoinbase('*', n0.z_getnewaddress('sapling'))['opid'])
            self.mine(1)
        stop_node(n3, 3)
        self.nodes = self.nodes[:3]
        self.num_nodes = 3
        activate_yed_late(self, [0, 2], ((0, 1), (1, 2), (0, 2)))
        n0, n1, n2 = self.nodes
        mints = [mint_to_fresh_holder(self.nodes, 0, 2) for _ in range(2)]
        n0.yed_send(n1.yed_getnewaddress(), 10000)               # a Falcon holder key (the default from Falcon)
        self.mine(1)
        assert_equal(n1.yed_getbalance()['confirmedCents'], 10000)
        mine0 = [(c['txid'], c['vout']) for c in n0.yed_listunspent()]
        assert_equal(len(mine0), 1)
        held = {0: [m for m in mints if m[1] == mine0[0]][0][1:]}
        tok_value = Decimal('0.0001')                            # TOKEN_VALUE, 10,000 zat
        ys = n1.yed_listunspent()
        assert_equal(len(ys), 1)
        out1 = (ys[0]['txid'], ys[0]['vout'])
        held[1] = (out1, n1.getrawtransaction(out1[0], 1)['vout'][out1[1]]['scriptPubKey']['addresses'][0])
        assert_equal(n1.listunspent(0), [])                     # node 1: nothing transparent but the (locked) token
        assert_equal(n1.z_listunspent(0), [])

        def yed_balances():
            return (n0.yed_getbalance()['confirmedCents'], n1.yed_getbalance()['confirmedCents'])

        before = yed_balances()

        def assert_all_refused(node, key, outpoint, sub_send, sub_merge, wildcards):
            assert_equal(node.getreceivedbyaddress(key, 0), tok_value)      # the key never received anything else
            for d in (node.z_getnewaddress('sapling'), node.getnewaddress(), node.getnewaddress('', 'pq'),
                      node.getnewaddress('', 'pqslh')):
                self.zsend_fails(node, key, [(d, Decimal('0.001'))], sub_send)
            assert_raises_rpc(sub_merge, z_mergetoaddress_call, node, [key], back)
            for w in wildcards:
                assert_raises_rpc(NO_MERGE_FUNDS, z_mergetoaddress_call, node, w, back)
            assert_equal(yed_balances(), before)

        def locked(node, outpoint):
            return {'txid': outpoint[0], 'vout': outpoint[1]} in node.listlockunspent()

        wild = [['ANY_TADDR'], ['ANY_TADDR', 'ANY_SAPLING'], [held[1][1], 'ANY_SAPLING']]
        for unlock_all in (False, True):
            print('  token keys: every spend refused as from an empty address (%s)' %
                  ('after lockunspent true' if unlock_all else 'locks in place'))
            for i, node in ((0, n0), (1, n1)):
                if unlock_all:
                    lockunspent_true(node)
                assert locked(node, held[i][0]), (i, held[i][0], node.listlockunspent())
                assert_equal(self.kind_of(node, held[i][1]), FN)
                assert_all_refused(node, held[i][1], held[i][0], NO_PQ_UTXOS, NO_MERGE_FUNDS, wild if i == 1 else [])
                assert locked(node, held[i][0])

        print('  the lock removed on purpose (yed_unlockcoin): the second check refuses the outpoint by name')
        op, key = held[1]
        r = n1.yed_unlockcoin(op[0], op[1], UNLOCK_ACK)
        assert_equal((r['wasYellowbackLocked'], r['cents']), (True, 10000))
        assert not locked(n1, op)
        named = YED_REFUSED + '%s:%d' % op
        for d in (n1.z_getnewaddress('sapling'), n1.getnewaddress(), n1.getnewaddress('', 'pq')):
            self.zsend_fails(n1, key, [(d, Decimal('0.001'))], named)
        assert_raises_rpc(named, z_mergetoaddress_call, n1, [key], back)
        assert_raises_rpc(named, z_mergetoaddress_call, n1, [key, 'ANY_SAPLING'], back)
        assert_raises_rpc(NO_MERGE_FUNDS, z_mergetoaddress_call, n1, ['ANY_TADDR'], back)   # ECC coins only
        pay = n0.getnewaddress()
        # sendtoaddress / sendmany select ECC coins only (beta2, audit M-1): the Falcon token is never theirs to pick
        ecc_only = 'Insufficient funds in ordinary transparent addresses; this wallet also holds '
        assert_raises_rpc(ecc_only, n1.sendtoaddress, pay, Decimal('0.00001'))
        assert_raises_rpc(ecc_only, n1.sendmany, '', {pay: Decimal('0.00001')})
        n1.yed_lockcoins()
        assert locked(n1, op)
        assert_equal(yed_balances(), before)
        assert_equal(n1.gettxout(op[0], op[1])['value'], tok_value)          # the token output is unspent

        print('  an unconfirmed token, its lock removed: z_sendmany minconf 0 is refused by the payload check')
        res = n0.yed_mint(MIN_MINT, 48, '', '', False)
        sync_mempools(self.nodes)
        n2.generate(1)                                                        # the carrier only
        sync_blocks(self.nodes)
        mint_txid = wait_for_spender(n0, res['carrierTxid'])
        mtx = n0.getrawtransaction(mint_txid, 1)
        assert 'confirmations' not in mtx or mtx['confirmations'] == 0
        pending_key = mtx['vout'][1]['scriptPubKey']['addresses'][0]
        assert locked(n0, (mint_txid, 1))
        n0.yed_unlockcoin(mint_txid, 1, UNLOCK_ACK)
        assert not locked(n0, (mint_txid, 1))
        opid = z_sendmany_opid(n0, pending_key, [(n0.z_getnewaddress('sapling'), Decimal('0.00001'))], 0)
        r = None
        for _ in range(300):
            r = n0.z_getoperationresult([opid])
            if r:
                break
            time.sleep(1)
        assert_equal(r[0]['status'], 'failed')
        assert YED_REFUSED + '%s:1' % mint_txid in r[0]['error']['message'], r[0]['error']['message']
        n0.yed_lockcoins()
        self.mine(1)

        print('  a holder key that also holds plain YEC, its token unlocked: the plain coins are spent, the token is not')
        n0.sendtoaddress(key, Decimal('0.01'))
        self.mine(1)
        n1.yed_unlockcoin(op[0], op[1], UNLOCK_ACK)
        txid = self.zsend_ok(n1, key, [(n1.z_getnewaddress('sapling'), Decimal('0.001'))])
        assert op not in [(i['txid'], i['vout']) for i in n1.getrawtransaction(txid, 1)['vin']]
        self.mine(1)
        r = z_mergetoaddress_call(n1, [key], back)
        txid = wait_and_assert_operationid_status(n1, r['opid'])
        assert op not in [(i['txid'], i['vout']) for i in n1.getrawtransaction(txid, 1)['vin']]
        self.mine(1)
        n1.yed_lockcoins()
        assert_equal(n1.gettxout(op[0], op[1])['value'], tok_value)
        assert_equal(yed_balances()[1], before[1])

    def check_privacy_policy(self, n0, n1):
        """PRIVACY_POLICY lines only (6.x, D-5; ycash-dd has none): a PQ party is a transparent party. PQ -> Sapling without
        change needs AllowRevealedSenders; with the D-4 change (a transparent output) the policy an ECC source with
        transparent change needs, AllowFullyTransparent; Sapling -> PQ needs AllowRevealedRecipients. Also the
        sender's listing of a PQ-source send: the payment is a send of its amount, the D-4 change nets to zero."""
        def fails(src, recipients, policy, substr):
            opid = n0.z_sendmany(src, [{'address': a, 'amount': v} for a, v in recipients], 1, None, policy)
            res = None
            for _ in range(300):
                r = n0.z_getoperationresult([opid])
                if r:
                    res = r[0]
                    break
                time.sleep(1)
            assert res is not None, 'timeout'
            assert_equal(res['status'], 'failed')
            assert substr in res['error']['message'], (substr, res['error']['message'])

        def ok(src, recipients, policy):
            opid = n0.z_sendmany(src, [{'address': a, 'amount': v} for a, v in recipients], 1, None, policy)
            return wait_and_assert_operationid_status(n0, opid)

        print('6.x privacy policy (D-5) with a PQ party')
        zq = n0.z_getnewaddress('sapling')
        pq5 = n0.getnewaddress('', 'pq')
        n0.sendtoaddress(pq5, 1)
        self.mine(1)
        fee = FEE_FN + FEE_SAPLING_OUT * LONE_SAPLING_OUTPUT_ACTIONS
        exact = Decimal(1) - coins(fee)       # no change
        fails(pq5, [(zq, exact)], 'AllowRevealedRecipients', 'Select AllowRevealedSenders or weaker')
        txid = ok(pq5, [(zq, exact)], 'AllowRevealedSenders')
        self.check_sent(n0, txid, pq5, fee)
        self.mine(1)
        assert_equal(Decimal(n0.z_getbalance(zq)), exact)
        n0.sendtoaddress(pq5, 1)
        self.mine(1)
        fails(pq5, [(zq, Decimal('0.5'))], 'AllowRevealedSenders', 'Select AllowFullyTransparent or weaker')
        fails(zq, [(pq5, Decimal('0.25'))], 'AllowRevealedAmounts', 'transparent recipients')
        txid = ok(zq, [(pq5, Decimal('0.25'))], 'AllowRevealedRecipients')
        self.check_sent(n0, txid, None)    # pays this wallet's own PQ address
        self.mine(1)
        assert_equal(self.unspent(n0, pq5), Decimal('1.25'))

        print('6.x: the sender\'s listing of a PQ-source send (D-4 change back to the source)')
        to = n1.getnewaddress()
        txid = self.zsend_ok(n0, pq5, [(to, Decimal('0.3'))])
        self.check_sent(n0, txid, pq5, FEE_FN)
        self.mine(1)
        tx = n0.gettransaction(txid)
        assert_equal((tx['amount'], tx['fee']), (Decimal('-0.3'), -coins(FEE_FN)))
        entries = [t for t in n0.listtransactions('*', 1000) if t['txid'] == txid]
        assert [t for t in entries if t['category'] == 'send' and t['address'] == to and t['amount'] == Decimal('-0.3')], entries
        assert_equal(sum(t['amount'] for t in entries), Decimal('-0.3'))
        assert_equal(self.unspent(n0, pq5), Decimal('1.25') - Decimal('0.3') - coins(FEE_FN))

    def pq_fee(self, s, sapling_out):
        """The fixed fee of a one-input send from a source of kind s (None: no PQ input, the line's default)."""
        if s not in (FN, SLH):
            return None
        return (FEE_SLH if s == SLH else FEE_FN) + (FEE_SAPLING_OUT * LONE_SAPLING_OUTPUT_ACTIONS if sapling_out else 0)


if __name__ == '__main__':
    WalletAddressMatrixTest().main()
