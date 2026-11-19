#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
z_shieldcoinbase from a post-quantum address (beta4 item 7a), as yewd serves it (yew #57).

A pool may pay a block reward to a post-quantum address (getcoinbasetemplatefor). z_shieldcoinbase names that address
as its fromaddress and moves the address's MATURE coinbase to one Sapling address:

  - the amount is the coins less the fee, so there is no change and no transparent output;
  - the coins are taken largest first, up to `limit` (default 50; 0 = as many as one transaction carries, at most 100
    post-quantum inputs, within the standard sigops); remainingUTXOs / remainingValue count the mature coinbase left;
  - the fee is the fee of the exact-amount z_sendmany that selects the same coins (the one z_sendmany's refusal names);
    an explicit fee below it is refused, above it is paid;
  - z_getoperationstatus names the method z_shieldcoinbase;
  - refusals (yewd's codes and words): nothing mature -6 "Could not find any coinbase funds to shield." with the immature
    tail; a transparent or post-quantum toaddress -25 "Cannot shield coinbase output to a p2pkh|p2sh|post-quantum
    address."; an unknown toaddress -8; an address the wallet does not hold -5 (z_sendmany's); a negative limit -8.
  - "*" still takes ECC coinbase only; when the wallet's only coinbase is at post-quantum addresses its refusal says
    that naming the address shields it.

Two nodes with -regtestshieldcoinbase: node 0 is the pool (getblocktemplate + getcoinbasetemplatefor + submitblock),
node 1 the miner's wallet.

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/wallet_pq_shieldcoinbase.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>

One file on both C++ lines (ycash-dd: BITCOIND=, ycash6: ZCASHD=).
"""

import re
import time
from decimal import Decimal
from io import BytesIO

from test_framework.authproxy import JSONRPCException
from test_framework.mininode import CBlock, CTransaction
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    bytes_to_hex_str,
    connect_nodes_bi,
    hex_str_to_bytes,
    nuparams,
    start_nodes,
    sync_blocks,
    sync_mempools,
    wait_and_assert_operationid_status,
    z_sendmany_opid,
)
from test_framework.yellowback_util import (
    VAULT_BRANCH_ID,
    YCASH_BLOSSOM_BRANCH_ID,
    YCASH_BRANCH_ID,
    YCASH_CANOPY_BRANCH_ID,
    YCASH_HEARTWOOD_BRANCH_ID,
)

COIN = 100000000
MATURE_AT = 101
NOTHING = 'Could not find any coinbase funds to shield.'
IMMATURE_TAIL = (' The address holds %s YEC of immature mining rewards (coinbase); a mining reward can be shielded after '
                 '101 confirmations, the first of these in %d more block%s.')
SHIELD_PQ_COINBASE = (' The wallet holds %s YEC of mining rewards (coinbase) at post-quantum addresses, which z_shieldcoinbase '
                      'shields only from the address that holds them: name that address as fromaddress, and they move to one '
                      'Sapling address at the exact amount, with no change.')
COINBASE_NOTE = re.compile(
    r' The address holds ([0-9.]+) YEC of mining rewards \(coinbase\), which can only be sent to a shielded \(Sapling\) '
    r'address, with no change: send exactly ([0-9.]+) to one Sapling address \(the ([0-9.]+) of rewards less the fee '
    r'([0-9.]+)\)\.')
FEE_BELOW = re.compile(r'^Fee ([0-9.]+) is below the ([0-9.]+) this post-quantum spend needs$')


def zat(x):
    return int(Decimal(str(x)) * COIN)


def yec(z):
    return Decimal(z) / COIN


def money(z):
    s = '%d.%08d' % (z // COIN, z % COIN)
    s = s.rstrip('0')
    return s + '0' * max(0, 2 - len(s.split('.')[1]))


def block_from(gbt, coinbase_hex):
    block = CBlock()
    block.nVersion = gbt['version']
    block.hashPrevBlock = int(gbt['previousblockhash'], 16)
    block.hashFinalSaplingRoot = block.hashBlockCommitments = int(gbt['finalsaplingroothash'], 16)
    block.nTime = gbt['curtime']
    block.nBits = int(gbt['bits'], 16)
    for h in [coinbase_hex] + [t['data'] for t in gbt['transactions']]:
        tx = CTransaction()
        tx.deserialize(BytesIO(hex_str_to_bytes(h)))
        block.vtx.append(tx)
    block.hashMerkleRoot = block.calc_merkle_root()
    block.solve()
    return block


class WalletPQShieldCoinbaseTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True   # v4.5.0 harness
        self.cache_behavior = 'clean'   # 6.20.0 harness

    def setup_network(self, split=False):
        args = [
            nuparams(YCASH_BRANCH_ID, 1),
            nuparams(YCASH_BLOSSOM_BRANCH_ID, 1),
            nuparams(YCASH_HEARTWOOD_BRANCH_ID, 3),
            nuparams(YCASH_CANOPY_BRANCH_ID, 3),
            nuparams(VAULT_BRANCH_ID, 4),
            '-pqfalconheight=4',
            '-regtestshieldcoinbase',
        ]
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, extra_args=[args, args])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False

    def sync(self):
        sync_blocks(self.nodes)
        sync_mempools(self.nodes)

    def mine(self, n=1):
        self.sync()
        self.pool.generate(n)
        self.sync()
        time.sleep(1)

    def mine_to(self, height):
        n = height - self.pool.getblockcount()
        if n > 0:
            self.mine(n)

    def pool_block(self, address):
        self.sync()
        gbt = self.pool.getblocktemplate()
        ref = {'previousblockhash': gbt['previousblockhash'], 'txids': [t['hash'] for t in gbt['transactions']]}
        res = self.pool.getcoinbasetemplatefor(address, ref)
        assert_equal(res['fund'], 0)
        block = block_from(gbt, res['data'])
        assert_equal(self.pool.submitblock(bytes_to_hex_str(block.serialize())), None)
        self.sync()
        return res['hash'], res['amount'], gbt['height']

    def error(self, *args):
        try:
            self.wallet.z_shieldcoinbase(*args)
        except JSONRPCException as e:
            return e.error['code'], e.error['message']
        raise AssertionError('z_shieldcoinbase%r did not fail' % (args,))

    def hint(self, src, held):
        """The exact amount and fee z_sendmany's refusal names for the address's mature coinbase (`held` zat)."""
        t = self.wallet.getnewaddress()
        try:
            opid = z_sendmany_opid(self.wallet, src, [(t, Decimal('1'))], 1, None)
        except JSONRPCException as e:
            error = e.error
        else:
            error = None
            for _ in range(300):
                results = self.wallet.z_getoperationresult([opid])
                if results:
                    assert_equal(results[0]['status'], 'failed')
                    error = results[0]['error']
                    break
                time.sleep(0.2)
            assert error is not None, 'operation timed out'
        m = COINBASE_NOTE.search(error['message'])
        assert m, error
        assert_equal(zat(m.group(1)), held)
        return zat(m.group(2)), zat(m.group(4))

    def shielded(self, res, z, opid_expect_fee):
        """Wait for the operation, check its method, the transaction's shape and the Sapling note. Returns the txid."""
        status = self.wallet.z_getoperationstatus([res['opid']])
        assert_equal(status[0]['method'], 'z_shieldcoinbase')
        txid = wait_and_assert_operationid_status(self.wallet, res['opid'])
        tx = self.wallet.decoderawtransaction(self.wallet.gettransaction(txid)['hex'])
        assert_equal(len(tx['vout']), 0)                        # no transparent output: no change
        assert_equal(len(tx['vin']), res['shieldingUTXOs'])
        assert_equal(self.wallet.listlockunspent(), [])
        self.mine()
        notes = [n for n in self.wallet.z_listunspent(1, 9999999, False, [z]) if n['txid'] == txid]
        assert_equal(len(notes), 1)
        assert_equal(zat(notes[0]['amount']), zat(res['shieldingValue']) - opid_expect_fee)
        return txid

    def run_test(self):
        self.pool, self.wallet = self.nodes[0], self.nodes[1]
        w = self.wallet
        self.mine_to(5)
        fn = w.getnewaddress('', 'pq')
        slh = w.getnewaddress('', 'pqslh')
        z = w.z_getnewaddress('sapling')
        z2 = w.z_getnewaddress('sapling')
        t = w.getnewaddress()
        foreign = self.pool.getnewaddress('', 'pq')

        print('the pool pays three rewards to the FN-DSA address and one to the SLH-DSA address')
        fn_a, fn_b, fn_c = self.pool_block(fn), self.pool_block(fn), self.pool_block(fn)    # heights 6, 7, 8
        slh_a = self.pool_block(slh)                                                       # height 9
        reward = fn_a[1]

        print('immature: -6 with the immature tail')
        left = MATURE_AT - w.gettransaction(fn_a[0])['confirmations']
        assert_equal(self.error(fn, z), (-6, NOTHING + IMMATURE_TAIL % (money(3 * reward), left, 's')))
        self.mine_to(fn_a[2] + MATURE_AT - 2)
        assert_equal(self.error(fn, z), (-6, NOTHING + IMMATURE_TAIL % (money(3 * reward), 1, '')))

        print('refusals that do not depend on the coins')
        assert_equal(self.error(fn, t), (-25, 'Cannot shield coinbase output to a p2pkh address.'))
        assert_equal(self.error(fn, slh), (-25, 'Cannot shield coinbase output to a post-quantum address.'))
        assert_equal(self.error(fn, 'nonsense'), (-8, 'Invalid parameter, unknown address format: nonsense'))
        assert_equal(self.error(foreign, z), (-5, 'From address does not belong to this node, post-quantum key not found.'))
        assert_equal(self.error(fn, z, Decimal('0.0001'), -1), (-8, 'Limit on maximum number of utxos cannot be negative'))

        print('one reward is mature: the fee is the one z_sendmany names for it')
        self.mine()
        assert_equal(w.gettransaction(fn_a[0])['confirmations'], MATURE_AT)
        send, fee = self.hint(fn, reward)
        assert_equal(send, reward - fee)
        code, message = self.error(fn, z, yec(fee - 1))
        assert_equal(code, -8)
        m = FEE_BELOW.match(message)
        assert m and zat(m.group(2)) == fee, message
        res = w.z_shieldcoinbase(fn, z)
        assert_equal((res['shieldingUTXOs'], zat(res['shieldingValue'])), (1, reward))
        assert_equal((res['remainingUTXOs'], zat(res['remainingValue'])), (0, 0))
        self.shielded(res, z, fee)
        assert_equal(zat(w.z_getbalance(z)), send)

        print('two more mature: limit 1 takes one and counts the other as remaining; an explicit fee above is paid')
        self.mine(2)
        send2, fee2 = self.hint(fn, 2 * reward)
        res = w.z_shieldcoinbase(fn, z2, yec(fee2 + 1000), 1)
        assert_equal((res['shieldingUTXOs'], zat(res['shieldingValue'])), (1, reward))
        assert_equal((res['remainingUTXOs'], zat(res['remainingValue'])), (1, reward))
        self.shielded(res, z2, fee2 + 1000)
        res = w.z_shieldcoinbase(fn, z2, yec(fee), 0)          # the fee of one Falcon input, explicit
        assert_equal((res['shieldingUTXOs'], res['remainingUTXOs']), (1, 0))
        self.shielded(res, z2, fee)
        assert_equal(self.error(fn, z), (-6, NOTHING))

        print('SLH-DSA: the larger signature, its own fee')
        self.mine_to(slh_a[2] + MATURE_AT - 1)
        send_s, fee_s = self.hint(slh, reward)
        assert fee_s > fee, (fee_s, fee)
        res = w.z_shieldcoinbase(slh, z)
        self.shielded(res, z, fee_s)

        print('"*" never takes a post-quantum coinbase, and says how to shield it')
        self.pool_block(fn)
        self.mine(MATURE_AT)
        code, message = self.error('*', z)
        assert message.endswith(SHIELD_PQ_COINBASE % money(reward)), message
        res = w.z_shieldcoinbase(fn, z, yec(fee), 0)
        self.shielded(res, z, fee)

        print('the shielded rewards spend on')
        before = zat(w.z_getbalance(z))
        wait_and_assert_operationid_status(w, z_sendmany_opid(w, z, [(t, Decimal('5'))], 1, None))
        self.mine()
        assert_equal(zat(w.getreceivedbyaddress(t)), zat('5'))
        assert zat(w.z_getbalance(z)) < before - zat('5')


if __name__ == '__main__':
    WalletPQShieldCoinbaseTest().main()
