#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
getcoinbasetemplatefor (beta3 item 3): a coinbase for a payout address and a block template the caller names.

A pool keeps the stock getblocktemplate reply and asks the node for a coinbase that pays one miner. This test plays
the pool: every block below is made of the STOCK template's header fields and transactions and the coinbase the call
returned, and is given to submitblock (or, where several coinbases compete for one height, to getblocktemplate's
proposal mode, which validates a block without proof of work).

THE AMOUNT. For every address kind the test computes, from the chain alone,

    amount = subsidy(height) - fund + fees          fees = the sum of the named transactions' mempool fees

and requires the call's answer, the coinbase's outputs and the mined block to show exactly that number
(assert_paid_exactly). `fund` is the development-fund output of this node's own coinbase: subsidy / 20 inside the
mandate (regtest: below height 5) whatever -ydf says, subsidy * ydf / 100 after it (-ydf defaults to 0: no output).

Regtest ladder: Ycash and Blossom at 1, Heartwood and Canopy at 3, Vault and FN-DSA-512 at 4, so the heights 2 to 4
(inside the mandate) also show which address kind may be paid in a coinbase from which height.

  node 0   the pool's node, default -ydf (0)
  node 1   a pool node with -ydf=5
  node 2   the miners' wallet: it owns the payout addresses and never mines

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/getcoinbasetemplatefor.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>

One file on both C++ lines (ycash-dd: BITCOIND=, ycash6: ZCASHD=).
"""

import threading
import time
from decimal import Decimal
from io import BytesIO

from test_framework.authproxy import JSONRPCException
from test_framework.mininode import CBlock, CTransaction, CTxOut
from test_framework.pq_address import FN_DSA, SLH_DSA, encode_pq_address
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    bytes_to_hex_str,
    connect_nodes_bi,
    get_rpc_proxy,
    hex_str_to_bytes,
    nuparams,
    rpc_url,
    start_nodes,
    sync_blocks,
    sync_mempools,
)
from test_framework.yellowback_model import base58check_encode, sha256
from test_framework.yellowback_util import (
    VAULT_BRANCH_ID,
    YCASH_BLOSSOM_BRANCH_ID,
    YCASH_BRANCH_ID,
    YCASH_CANOPY_BRANCH_ID,
    YCASH_HEARTWOOD_BRANCH_ID,
)

COIN = 100000000
YDF_MANDATE_END = 5          # src/chainparams.cpp, regtest nYdfMandateEndHeight
HEARTWOOD = 3                # a Sapling address may be paid in a coinbase from here
VAULT = 4                    # a post-quantum address may be paid in a coinbase from here
MAX_BLOCK_SIZE = 2000000     # src/consensus/consensus.h
MAX_BLOCK_SIGOPS = 20000
REGTEST_HEADER_SIZE = 140 + 1 + 36   # the header and its Equihash (48,5) solution with the length byte

P2PKH, P2SH, SAPLING, PQ_FN, PQ_SLH = 'p2pkh', 'p2sh', 'sapling', 'pq FN-DSA-512', 'pq SLH-DSA-SHA2-128s'
ADDRESSTYPE = {P2PKH: 'p2pkh', P2SH: 'p2sh', SAPLING: 'sapling', PQ_FN: 'pq', PQ_SLH: 'pq'}

STALE_TIP = 'template-stale: previousblockhash is not the tip'
BAD_TEMPLATE = 'template must be an object with exactly the keys previousblockhash and txids'


def zat(x):
    return int(Decimal(str(x)) * COIN)


def reference(gbt):
    """What the pool sends back to name the template it holds: nothing but these two things."""
    return {'previousblockhash': gbt['previousblockhash'], 'txids': [t['hash'] for t in gbt['transactions']]}


def block_from(gbt, coinbase_hex, txs=None, solve=True):
    """The block a pool would build: the stock template's header fields and transactions, and coinbase_hex."""
    block = CBlock()
    block.nVersion = gbt['version']
    block.hashPrevBlock = int(gbt['previousblockhash'], 16)
    # the header's fourth field: hashFinalSaplingRoot in the v4.5.0 harness, hashBlockCommitments in the 6.20.0 one
    block.hashFinalSaplingRoot = block.hashBlockCommitments = int(gbt['finalsaplingroothash'], 16)
    block.nTime = gbt['curtime']
    block.nBits = int(gbt['bits'], 16)
    for h in [coinbase_hex] + ([t['data'] for t in gbt['transactions']] if txs is None else txs):
        tx = CTransaction()
        tx.deserialize(BytesIO(hex_str_to_bytes(h)))
        assert_equal(bytes_to_hex_str(tx.serialize()), h)     # the harness carries every transaction byte for byte
        block.vtx.append(tx)
    block.hashMerkleRoot = block.calc_merkle_root()
    if solve:
        block.solve()
    return block


def assert_rpc_error(code, message, fn, *args):
    """fn(*args) must fail with exactly this code and this message."""
    try:
        fn(*args)
    except JSONRPCException as e:
        assert_equal((e.error['code'], e.error['message']), (code, message))
        return
    raise AssertionError('expected RPC error %d %r' % (code, message))


class GetCoinbaseTemplateForTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 3
        self.setup_clean_chain = True   # v4.5.0 harness
        self.cache_behavior = 'clean'   # 6.20.0 harness (each harness ignores the other's)

    def setup_network(self, split=False):
        common = [
            nuparams(YCASH_BRANCH_ID, 1),
            nuparams(YCASH_BLOSSOM_BRANCH_ID, 1),
            nuparams(YCASH_HEARTWOOD_BRANCH_ID, HEARTWOOD),
            nuparams(YCASH_CANOPY_BRANCH_ID, HEARTWOOD),
            nuparams(VAULT_BRANCH_ID, VAULT),
            '-pqfalconheight=%d' % VAULT,
        ]
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 extra_args=[common, common + ['-ydf=5'], common])
        for a, b in ((0, 1), (0, 2), (1, 2)):
            connect_nodes_bi(self.nodes, a, b)
        self.is_network_split = False
        self.sync_all()
        self.ydf = [0, 5, 0]            # each node's -ydf

    # ---- what the test knows without asking the call --------------------------------------------------------------

    def subsidy(self, height):
        """The block subsidy at height in zat: getblocksubsidy's miner plus founders, which no -ydf changes."""
        r = self.nodes[2].getblocksubsidy(height)
        assert not r.get('fundingstreams'), r          # Ycash has no funding streams
        return zat(r['miner']) + zat(r['founders'])

    def fund(self, i, height):
        """The development-fund output node i's own coinbase carries at height, in zat."""
        if height < YDF_MANDATE_END:
            return self.subsidy(height) // 20                       # required by consensus, whatever -ydf says
        return self.subsidy(height) * self.ydf[i] // 100            # the operator's optional share (default 0)

    def mempool_fees(self, i, txids):
        """The sum of the fees of txids in zat, from node i's mempool."""
        pool = self.nodes[i].getrawmempool(True)
        return sum(zat(pool[txid]['fee']) for txid in txids)

    def script_of(self, address):
        return self.nodes[2].validateaddress(address)['scriptPubKey']

    def stock_fund_output(self, i, gbt):
        """(value in zat, script hex) of the fund output of node i's stock coinbase, or None when it has none. Node i
        mines to a transparent address of its wallet, so its coinbase is [the miner's output, the fund output]."""
        vout = self.nodes[i].decoderawtransaction(gbt['coinbasetxn']['data'])['vout']
        assert len(vout) in (1, 2), vout
        return (vout[1]['valueZat'], vout[1]['scriptPubKey']['hex']) if len(vout) == 2 else None

    # ---- the amount ---------------------------------------------------------------------------------------------

    def assert_paid_exactly(self, i, kind, address, gbt, res):
        """The call's answer `res` (for `address`, on node i's stock template `gbt`) pays the address exactly
        subsidy - fund + fees, and carries the fund output of the node's own coinbase, if it has one."""
        height = gbt['height']
        txids = [t['hash'] for t in gbt['transactions']]

        subsidy = self.subsidy(height)
        fund = self.fund(i, height)
        fees = self.mempool_fees(i, txids)
        amount = subsidy - fund + fees                              # <-- what the miner must receive

        assert_equal(fees, sum(t['fee'] for t in gbt['transactions']))   # the template prints the same fees
        assert_equal(res['subsidy'], subsidy)
        assert_equal(res['fund'], fund)
        assert_equal(res['fundrule'], 'mandated' if height < YDF_MANDATE_END else 'optional' if self.ydf[i] else 'none')
        assert_equal(res['fees'], fees)
        assert_equal(res['amount'], amount)
        assert_equal(res['txcount'], len(txids))
        assert_equal(res['height'], height)
        assert_equal(res['previousblockhash'], gbt['previousblockhash'])
        assert_equal(res['addresstype'], ADDRESSTYPE[kind])

        # the fund output is the stock coinbase's own: same value, same script (None when there is none)
        stock_fund = self.stock_fund_output(i, gbt)
        assert_equal(stock_fund[0] if stock_fund else 0, fund)

        cb = self.nodes[i].decoderawtransaction(res['data'])
        assert_equal(cb['txid'], res['hash'])
        outs = [(v['valueZat'], v['scriptPubKey']['hex']) for v in cb['vout']]
        fund_outs = [stock_fund] if stock_fund else []
        if kind == SAPLING:
            # one Sapling output worth `amount` (the value leaves the transparent side), and only the fund output
            assert_equal(len(cb['vShieldedOutput']), 1)
            assert_equal(cb['valueBalanceZat'], -amount)
            assert_equal(outs, fund_outs)
        else:
            # vout[0] pays the address `amount`; then only the fund output
            assert_equal(len(cb.get('vShieldedOutput', [])), 0)
            assert_equal(outs, [(amount, self.script_of(address))] + fund_outs)

        # nothing else: the coinbase's total is the subsidy plus the fees, to the zatoshi
        assert_equal(sum(v for v, _ in outs) - cb.get('valueBalanceZat', 0), subsidy + fees)
        # and it is what the stock coinbase pays in total
        stock = self.nodes[i].decoderawtransaction(gbt['coinbasetxn']['data'])
        assert_equal(sum(v['valueZat'] for v in stock['vout']), subsidy + fees)

        # the scriptSig is <height> OP_0 <flags>, as the node's own coinbase
        assert_equal(res['flags'], gbt.get('coinbaseaux', {}).get('flags', ''))
        assert_equal(cb['vin'][0]['coinbase'], stock['vin'][0]['coinbase'])
        return amount

    def proposal_ok(self, i, gbt, res):
        """The block of the stock template and this coinbase is valid (proposal mode: everything but proof of work)."""
        block = block_from(gbt, res['data'], solve=False)
        assert_equal(self.nodes[i].getblocktemplate({'mode': 'proposal', 'data': bytes_to_hex_str(block.serialize())}), None)

    def submit(self, i, kind, address, gbt, res, amount):
        """Mine the block of the stock template and this coinbase on node i; every node accepts it; the address was
        paid `amount` in it."""
        block = block_from(gbt, res['data'])
        assert_equal(self.nodes[i].submitblock(bytes_to_hex_str(block.serialize())), None)
        blockhash = '%064x' % block.sha256
        sync_blocks(self.nodes)
        for node in self.nodes:
            assert_equal(node.getbestblockhash(), blockhash)
        mined = self.nodes[2].getblock(blockhash, 2)                     # read back on the miners' node
        assert_equal(mined['height'], gbt['height'])
        assert_equal([t['txid'] for t in mined['tx']], [res['hash']] + [t['hash'] for t in gbt['transactions']])
        cb = mined['tx'][0]
        if kind == SAPLING:
            # the receiving wallet holds one note of exactly `amount` from this coinbase
            notes = [n for n in self.nodes[2].z_listunspent(1, 9999999, False, [address]) if n['txid'] == res['hash']]
            assert_equal(len(notes), 1)
            assert_equal(zat(notes[0]['amount']), amount)
        else:
            assert_equal((cb['vout'][0]['valueZat'], cb['vout'][0]['scriptPubKey']['hex']), (amount, self.script_of(address)))
        print('height %d, node %d (-ydf=%d), %s: paid %d = subsidy %d - fund %d + fees %d (%d transactions)' % (
            gbt['height'], i, self.ydf[i], kind, amount, res['subsidy'], res['fund'], res['fees'], res['txcount']))
        return blockhash

    def call(self, i, address, gbt):
        return self.nodes[i].getcoinbasetemplatefor(address, reference(gbt))

    def pay_fees(self, n=2):
        """n fee-paying transactions from node 0's wallet, in every mempool. Sent before the next template is asked
        for, so that the template (rebuilt at once on a new tip) carries them."""
        txids = [self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), Decimal('0.1') * (k + 1)) for k in range(n)]
        sync_mempools(self.nodes)
        return txids

    # ---- the test ----------------------------------------------------------------------------------------------

    def run_test(self):
        n0, n1, n2 = self.nodes
        addr = {
            P2PKH: n2.getnewaddress(),
            P2SH: base58check_encode(bytes([0x1C, 0x2A]) + sha256(b'getcoinbasetemplatefor')[:20]),   # regtest SCRIPT_ADDRESS
            SAPLING: n2.z_getnewaddress('sapling'),
            # post-quantum addresses from a key hash (a wallet makes them only once Vault is active; see below)
            PQ_FN: encode_pq_address(FN_DSA, sha256(b'getcoinbasetemplatefor fn')),
            PQ_SLH: encode_pq_address(SLH_DSA, sha256(b'getcoinbasetemplatefor slh')),
        }
        assert addr[PQ_FN].startswith('rqf') and addr[PQ_SLH].startswith('rqs')

        # ================= inside the mandate (heights 2 to 4): the fund output is there =================
        # at the genesis block the node is in initial block download and refuses, as getblocktemplate does
        genesis = {'previousblockhash': n0.getbestblockhash(), 'txids': []}
        assert_rpc_error(-10, 'Ycash is downloading blocks...', n0.getcoinbasetemplatefor, addr[P2PKH], genesis)
        assert_rpc_error(-10, 'Ycash is downloading blocks...', n0.getblocktemplate)
        n0.generate(1)                                   # height 1: the nodes leave initial block download
        sync_blocks(self.nodes)
        payable_from = {P2PKH: 0, P2SH: 0, SAPLING: HEARTWOOD, PQ_FN: VAULT, PQ_SLH: VAULT}
        submit_kind = {2: P2SH, 3: SAPLING, 4: PQ_FN}
        for height in (2, 3, 4):
            assert height < YDF_MANDATE_END
            for i in (0, 1):                             # -ydf makes no difference here
                gbt = self.nodes[i].getblocktemplate()
                assert_equal((gbt['height'], gbt['transactions']), (height, []))
                to_submit = None
                for kind in (P2PKH, P2SH, SAPLING, PQ_FN, PQ_SLH):
                    if height < payable_from[kind]:
                        assert_rpc_error(-5, 'Address type cannot receive a coinbase at height %d: %s' % (height, ADDRESSTYPE[kind]),
                                         self.call, i, addr[kind], gbt)
                        continue
                    res = self.call(i, addr[kind], gbt)
                    amount = self.assert_paid_exactly(i, kind, addr[kind], gbt, res)
                    assert_equal((res['fund'], res['fundrule']), (self.subsidy(height) // 20, 'mandated'))   # on both nodes
                    assert_equal(amount, self.subsidy(height) - self.subsidy(height) // 20)
                    self.proposal_ok(i, gbt, res)
                    if kind == submit_kind[height]:
                        to_submit = (kind, res, amount)
                if i == 1:                               # one of them becomes the block at this height
                    kind, res, amount = to_submit
                    self.submit(i, kind, addr[kind], gbt, res, amount)
        assert_equal(n0.getblockcount(), 4)

        # ================= past the mandate, with fee-paying transactions =================
        n0.generate(110)                                 # node 0 can spend its first coinbases
        sync_blocks(self.nodes)
        # addresses of the miners' wallet for the post-quantum kinds too (FN-DSA-512 is its default 'pq' type)
        addr[PQ_FN] = n2.getnewaddress('', 'pq')
        addr[PQ_SLH] = n2.getnewaddress('', 'pqslh')
        assert addr[PQ_FN].startswith('rqf') and addr[PQ_SLH].startswith('rqs')

        timings = {}
        for i in (0, 1):
            for kind in (P2PKH, P2SH, SAPLING, PQ_FN, PQ_SLH):
                txids = self.pay_fees()
                gbt = self.nodes[i].getblocktemplate()
                height = gbt['height']
                assert height >= YDF_MANDATE_END
                assert_equal(sorted(t['hash'] for t in gbt['transactions']), sorted(txids))
                assert all(t['fee'] > 0 for t in gbt['transactions'])

                t0 = time.time()
                res = self.call(i, addr[kind], gbt)
                timings.setdefault(kind, []).append(time.time() - t0)
                amount = self.assert_paid_exactly(i, kind, addr[kind], gbt, res)
                fees = sum(t['fee'] for t in gbt['transactions'])
                if i == 0:
                    # default -ydf: the miner is paid in full, and the coinbase has no fund output
                    assert_equal((res['fund'], res['fundrule'], amount), (0, 'none', self.subsidy(height) + fees))
                else:
                    # -ydf=5: the fund gets 5 % of the subsidy, the miner 95 % of the subsidy and every fee
                    assert_equal((res['fund'], res['fundrule']), (self.subsidy(height) * 5 // 100, 'optional'))
                    assert_equal(amount, self.subsidy(height) - self.subsidy(height) * 5 // 100 + fees)

                # a second call with the same arguments gives a valid coinbase too (a Sapling one differs in its
                # randomness; the others are the same bytes)
                again = self.call(i, addr[kind], gbt)
                assert_equal(self.assert_paid_exactly(i, kind, addr[kind], gbt, again), amount)
                assert_equal(again['data'] == res['data'], kind != SAPLING)
                self.proposal_ok(i, gbt, again)

                # the stock template is what it was (the call rebuilt nothing): everything but the clock
                after = self.nodes[i].getblocktemplate()
                assert_equal({k: v for k, v in after.items() if k != 'curtime'}, {k: v for k, v in gbt.items() if k != 'curtime'})

                self.submit(i, kind, addr[kind], gbt, res, amount)
                assert_equal(self.nodes[i].getrawmempool(), [])

        # an empty template past the mandate: the subsidy alone (node 0), 95 % of it (node 1)
        for i in (0, 1):
            gbt = self.nodes[i].getblocktemplate()
            assert_equal(gbt['transactions'], [])
            res = self.call(i, addr[SAPLING], gbt)
            amount = self.assert_paid_exactly(i, SAPLING, addr[SAPLING], gbt, res)
            assert_equal(amount, self.subsidy(gbt['height']) * (100 - self.ydf[i]) // 100)
            self.submit(i, SAPLING, addr[SAPLING], gbt, res, amount)

        self.stock_template_is_untouched()
        self.refusals(addr)
        self.parallel_calls(addr)
        self.block_limits(addr)

        for kind in (P2PKH, P2SH, SAPLING, PQ_FN, PQ_SLH):
            ts = sorted(timings[kind])
            print('time of one call, %s: %.1f ms and %.1f ms' % (kind, ts[0] * 1000, ts[-1] * 1000))

    def stock_template_is_untouched(self):
        """getblocktemplate answers byte for byte the same before and after a series of calls (same tip, same
        mempool, same second), longpollid included."""
        n0, n2 = self.nodes[0], self.nodes[2]
        self.pay_fees(3)
        addresses = [n2.getnewaddress(), n2.z_getnewaddress('sapling'), n2.getnewaddress('', 'pqslh')]
        assert_equal(len(n0.getblocktemplate()['transactions']), 3)
        for attempt in range(30):
            before = n0.getblocktemplate()
            for a in addresses:
                n0.getcoinbasetemplatefor(a, reference(before))
            after = n0.getblocktemplate()
            assert_equal(after['longpollid'], before['longpollid'])
            assert_equal({k: v for k, v in after.items() if k != 'curtime'}, {k: v for k, v in before.items() if k != 'curtime'})
            if after['curtime'] == before['curtime']:        # the same second: the whole reply
                assert_equal(after, before)
                break
        else:
            raise AssertionError('no two templates within one second')
        print('getblocktemplate is identical before and after the calls (attempt %d)' % (attempt + 1))

    def refusals(self, addr):
        """The errors of the contract: code and message, each exactly."""
        n0, n2 = self.nodes[0], self.nodes[2]
        gbt = n0.getblocktemplate()
        ref = reference(gbt)
        txid = ref['txids'][0]
        a = addr[P2PKH]
        f = n0.getcoinbasetemplatefor

        # no way to ask for an amount: any key but the two is refused, and there is no third parameter
        for extra in ({'amount': 1}, {'fees': 0}, {'coinbasevalue': 1}):
            assert_rpc_error(-8, BAD_TEMPLATE, f, a, dict(ref, **extra))
        try:
            f(a, ref, 1)
            raise AssertionError('a third parameter was accepted')
        except JSONRPCException as e:
            assert e.error['code'] in (-1, -32602), e.error      # each line's usual usage error (not in the contract)
        # the shape of the reference
        for bad in ({'previousblockhash': ref['previousblockhash']}, {'txids': []}, {}, [], 'x', 1,
                    {'previousblockhash': ref['previousblockhash'], 'amount': 1}):
            assert_rpc_error(-8, BAD_TEMPLATE, f, a, bad)
        for bad in ('00', ref['previousblockhash'][:-1], ref['previousblockhash'][:-1] + 'g', 1):
            assert_rpc_error(-8, 'previousblockhash must be 64 hex characters', f, a, dict(ref, previousblockhash=bad))
        for bad in ('x', {}, ['00'], [txid, 1], [txid[:-1] + 'z']):
            assert_rpc_error(-8, 'txids must be an array of strings of 64 hex characters', f, a, dict(ref, txids=bad))
        assert_rpc_error(-8, 'txids has more than 50000 entries', f, a, dict(ref, txids=['%064x' % k for k in range(50001)]))
        assert_rpc_error(-8, 'txids names a transaction twice: ' + txid, f, a, dict(ref, txids=ref['txids'] + [txid]))
        # upper-case hex is the same reference
        up = f(a, {'previousblockhash': ref['previousblockhash'].upper(), 'txids': [t.upper() for t in ref['txids']]})
        assert_equal((up['previousblockhash'], up['fees']), (ref['previousblockhash'], sum(t['fee'] for t in gbt['transactions'])))

        # the address
        yed_address = encode_pq_address(FN_DSA, bytes(32), coin='yed')
        for bad in ('', 'x', a[:-1], 1, yed_address):
            assert_rpc_error(-5, 'Invalid address', f, bad, ref)
        sprout = base58check_encode(bytes([0x16, 0x52]) + bytes(64))            # regtest ZCPAYMENT_ADDRESS
        assert_rpc_error(-5, 'Address type cannot receive a coinbase: sprout', f, sprout, ref)

        # the order of the checks: the shape of the reference before the address, the address before the tip
        assert_rpc_error(-8, BAD_TEMPLATE, f, 'x', {})
        stale = dict(ref, previousblockhash='%064x' % 1)
        assert_rpc_error(-5, 'Invalid address', f, 'x', stale)

        # stale: a previous block that is not the tip; a transaction this node's mempool does not hold
        assert_rpc_error(-1, STALE_TIP, f, a, stale)
        unknown = '%064x' % 2
        assert_rpc_error(-1, 'template-stale: transaction is not in the mempool: ' + unknown, f, a, dict(ref, txids=[txid, unknown]))
        assert_rpc_error(-1, 'template-stale: transaction is not in the mempool: ' + unknown, f, a, dict(ref, txids=[unknown, unknown]))

        # the reference goes stale when the tip moves, and the old transactions have then left the mempool
        res = f(a, ref)
        self.proposal_ok(0, gbt, res)
        n0.generate(1)
        sync_blocks(self.nodes)
        assert_equal(n0.getrawmempool(), [])
        assert_rpc_error(-1, STALE_TIP, f, a, ref)
        assert_rpc_error(-1, STALE_TIP, f, addr[SAPLING], ref)
        new_tip = n0.getbestblockhash()
        assert_rpc_error(-1, 'template-stale: transaction is not in the mempool: ' + txid, f, a,
                         {'previousblockhash': new_tip, 'txids': ref['txids'][:1]})
        # and the old coinbase is no longer part of a valid block
        stale_block = block_from(gbt, res['data'], solve=False)
        assert_equal(n0.getblocktemplate({'mode': 'proposal', 'data': bytes_to_hex_str(stale_block.serialize())}),
                     'inconclusive-not-best-prevblk')
        print('refusals: as the contract')

    def parallel_calls(self, addr):
        """Several Sapling calls at once while the node answers getblockcount (three calls, so that one of the node's
        four RPC threads stays free and the printed latency is that of cs_main, not of the thread pool): all succeed
        and all are valid."""
        n0, n2 = self.nodes[0], self.nodes[2]
        self.pay_fees(2)
        gbt = n0.getblocktemplate()
        zaddrs = [n2.z_getnewaddress('sapling') for _ in range(3)]
        results, errors = {}, []

        def worker(z):
            try:
                results[z] = get_rpc_proxy(rpc_url(0), 0).getcoinbasetemplatefor(z, reference(gbt))
            except Exception as e:              # reported below, on the main thread
                errors.append(repr(e))

        threads = [threading.Thread(target=worker, args=(z,)) for z in zaddrs]
        t0 = time.time()
        for t in threads:
            t.start()
        slowest = 0.0
        while any(t.is_alive() for t in threads):
            t1 = time.time()
            n0.getblockcount()
            slowest = max(slowest, time.time() - t1)
            time.sleep(0.02)
        for t in threads:
            t.join()
        elapsed = time.time() - t0
        assert_equal(errors, [])
        assert_equal(len(set(r['data'] for r in results.values())), len(zaddrs))
        for z in zaddrs:
            self.assert_paid_exactly(0, SAPLING, z, gbt, results[z])
            self.proposal_ok(0, gbt, results[z])
        z = zaddrs[0]
        self.submit(0, SAPLING, z, gbt, results[z], results[z]['amount'])
        print('%d Sapling calls at once: %.0f ms in all; the slowest getblockcount meanwhile %.0f ms' % (
            len(zaddrs), elapsed * 1000, slowest * 1000))

    def big_transaction(self, utxo, script, n_outputs, fee):
        """A signed transaction of node 0 spending utxo into n_outputs outputs of `script`."""
        n0 = self.nodes[0]
        raw = n0.createrawtransaction([{'txid': utxo['txid'], 'vout': utxo['vout']}], {n0.getnewaddress(): 1})
        tx = CTransaction()
        tx.deserialize(BytesIO(hex_str_to_bytes(raw)))
        value = (zat(utxo['amount']) - fee) // n_outputs
        tx.vout = [CTxOut(value, script) for _ in range(n_outputs)]
        tx.vout[0].nValue += zat(utxo['amount']) - fee - value * n_outputs
        signed = n0.signrawtransaction(bytes_to_hex_str(tx.serialize()))
        assert signed['complete']
        return signed['hex']

    def block_limits(self, addr):
        """A set of transactions that leaves room for a transparent coinbase but not for a Sapling one is refused for
        the Sapling address (coinbase-does-not-fit), and so is a set over the signature-operation limit."""
        n0 = self.nodes[0]
        f = n0.getcoinbasetemplatefor
        assert_equal(n0.getrawmempool(), [])
        n_utxos, fee = 29, 20000000                       # 0.2 per transaction: above the conventional fee of 3,000 outputs
        n0.sendmany('', {n0.getnewaddress(): Decimal('0.6') for _ in range(n_utxos)})
        n0.generate(1)
        sync_blocks(self.nodes)
        utxos = [u for u in n0.listunspent(1) if u['amount'] == Decimal('0.6')]
        assert_equal(len(utxos), n_utxos)
        p2sh = bytes([0xa9, 0x14]) + bytes(20) + bytes([0x87])                       # no legacy signature operation
        p2pkh = bytes([0x76, 0xa9, 0x14]) + bytes(20) + bytes([0x88, 0xac])          # one each

        gbt = n0.getblocktemplate()
        assert_equal(gbt['transactions'], [])
        ref = reference(gbt)
        size = {kind: len(f(addr[kind], ref)['data']) // 2 for kind in (P2PKH, SAPLING)}
        assert size[SAPLING] > size[P2PKH] + 900

        # --- signature operations: 7 transactions of 2,900 P2PKH outputs are 20,300 ---
        sigop_txs = [self.big_transaction(utxos.pop(), p2pkh, 2900, fee) for _ in range(7)]
        sigop_ids = [n0.sendrawtransaction(h, True) for h in sigop_txs]
        ref_sigops = dict(ref, txids=sigop_ids)
        assert_rpc_error(-1, 'coinbase-does-not-fit: sigops %d exceed %d' % (7 * 2900 + 1, MAX_BLOCK_SIGOPS), f, addr[P2PKH], ref_sigops)
        assert_rpc_error(-1, 'coinbase-does-not-fit: sigops %d exceed %d' % (7 * 2900, MAX_BLOCK_SIGOPS), f, addr[SAPLING], ref_sigops)
        ok = f(addr[P2PKH], dict(ref, txids=sigop_ids[:6]))            # 17,401 fit
        assert_equal(ok['txcount'], 6)

        # --- size: 22 transactions of P2SH outputs, the last one cut so that the block has room for the P2PKH
        #     coinbase and not for the Sapling one ---
        size_txs = [self.big_transaction(utxos.pop(), p2sh, 3000, fee) for _ in range(20)]
        room = MAX_BLOCK_SIZE - REGTEST_HEADER_SIZE - 1 - sum(len(h) // 2 for h in size_txs)   # 1: the transaction count
        last_two = room - (size[P2PKH] + size[SAPLING]) // 2            # between the two coinbase sizes
        size_txs.append(self.big_transaction(utxos.pop(), p2sh, 1500, fee))
        probe = len(self.big_transaction(utxos[-1], p2sh, 1, fee)) // 2
        n_last = 1 + (last_two - len(size_txs[-1]) // 2 - probe) // 32  # an output of this script is 32 bytes
        assert 1 <= n_last <= 3000, n_last
        size_txs.append(self.big_transaction(utxos.pop(), p2sh, n_last, fee))
        size_ids = [n0.sendrawtransaction(h, True) for h in size_txs]
        txs_size = sum(len(h) // 2 for h in size_txs)
        block_size = {kind: REGTEST_HEADER_SIZE + 1 + size[kind] + txs_size for kind in (P2PKH, SAPLING)}
        assert block_size[P2PKH] <= MAX_BLOCK_SIZE < block_size[SAPLING], block_size

        ref_size = dict(ref, txids=size_ids)
        assert_rpc_error(-1, 'coinbase-does-not-fit: block size %d exceeds %d' % (block_size[SAPLING], MAX_BLOCK_SIZE),
                         f, addr[SAPLING], ref_size)
        res = f(addr[P2PKH], ref_size)
        fees = self.mempool_fees(0, size_ids)
        assert_equal(fees, 22 * fee)
        assert_equal((res['fees'], res['amount']), (fees, self.subsidy(gbt['height']) + fees))
        # the transparent one does fit: the block of exactly these transactions is accepted, just under the limit
        block = block_from(gbt, res['data'], txs=size_txs)
        assert_equal(len(block.serialize()), block_size[P2PKH])
        assert_equal(n0.submitblock(bytes_to_hex_str(block.serialize())), None)
        assert_equal(n0.getbestblockhash(), '%064x' % block.sha256)
        sync_blocks(self.nodes, timeout=120)
        cb = self.nodes[2].getblock('%064x' % block.sha256, 2)['tx'][0]
        assert_equal((cb['vout'][0]['valueZat'], cb['vout'][0]['scriptPubKey']['hex']),
                     (self.subsidy(gbt['height']) + fees, self.script_of(addr[P2PKH])))
        print('block limits: a block of %d bytes accepted with the P2PKH coinbase; the Sapling coinbase (%d bytes) refused' % (
            block_size[P2PKH], block_size[SAPLING]))


if __name__ == '__main__':
    GetCoinbaseTemplateForTest().main()
