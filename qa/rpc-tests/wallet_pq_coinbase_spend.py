#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
A post-quantum miner shields its coinbase (beta3).

A pool may pay a block reward straight to a post-quantum address (getcoinbasetemplatefor). Where coinbase must be
shielded (mainnet, the testnets, regtest with -regtestshieldcoinbase) a transaction that spends a transparent coinbase
has no transparent output, so the miner's only way out is a send to shielded recipients with no change. z_sendmany from
the post-quantum address builds exactly that:

  THE RULE (the wallet's, the same on every network, as z_sendmany treats the coinbase of an ECC address):
    1. the address's ordinary coins are used first, as before (change returns to the address);
    2. its MATURE coinbase (101 confirmations) joins the candidates only when every recipient is shielded and the
       ordinary coins do not cover the amount and the fee;
    3. a selection that holds a coinbase coin makes no change: the amount must be the selected coins less the fee,
       and the refusal names that amount;
    4. with a transparent or post-quantum recipient the coinbase is never selected, and the refusal says what the
       address holds in coinbase; immature coinbase is named the same way.

Every refusal below is the wallet's (the RPC or its operation), never the mempool's.

Two separate two-node networks run the same steps, one with -regtestshieldcoinbase and one without:

  node 0, node 2   the pool's node: stock getblocktemplate + getcoinbasetemplatefor + submitblock
  node 1, node 3   the miner's wallet: it owns the payout addresses and never mines

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/wallet_pq_coinbase_spend.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>

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
MATURE_AT = 101              # confirmations at which the wallet spends a coinbase output (COINBASE_MATURITY + 1)
INSUFFICIENT, WALLET_ERROR, INVALID_PARAMETER = -6, -4, -8

NO_UTXOS = 'Insufficient transparent funds, no UTXOs found for taddr from address.'
COINBASE_NOTE = ' The address holds %s of coinbase funds, which can only be sent to shielded recipients, with no change.'
IMMATURE_NOTE = ' The address holds %s of immature coinbase funds, which can be spent after 101 confirmations.'
CHANGE_REFUSAL = re.compile(
    r'^When shielding coinbase funds, the wallet does not allow any change\. The proposed transaction would result in '
    r'([0-9.]+) in change\. To spend the selected coins, send exactly ([0-9.]+) to shielded recipients '
    r'\(the ([0-9.]+) selected less the fee ([0-9.]+)\)\.$')
HAVE_NEED = re.compile(r'^Insufficient transparent funds, have ([0-9.]+), need ([0-9.]+)\.(.*)$')
FEE_BELOW = re.compile(r'^Fee ([0-9.]+) is below the ([0-9.]+) this post-quantum spend needs$')


def zat(x):
    return int(Decimal(str(x)) * COIN)


def yec(z):
    return Decimal(z) / COIN


def money(z):
    """FormatMoney: at least two decimals, no other trailing zeros."""
    s = '%d.%08d' % (z // COIN, z % COIN)
    s = s.rstrip('0')
    return s + '0' * max(0, 2 - len(s.split('.')[1]))


def block_from(gbt, coinbase_hex):
    """The block a pool builds: the stock template's header fields and transactions, and the coinbase it was given."""
    block = CBlock()
    block.nVersion = gbt['version']
    block.hashPrevBlock = int(gbt['previousblockhash'], 16)
    # the header's fourth field: hashFinalSaplingRoot in the v4.5.0 harness, hashBlockCommitments in the 6.20.0 one
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


class WalletPQCoinbaseSpendTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = True   # v4.5.0 harness
        self.cache_behavior = 'clean'   # 6.20.0 harness (each harness ignores the other's)

    def setup_network(self, split=False):
        common = [
            nuparams(YCASH_BRANCH_ID, 1),
            nuparams(YCASH_BLOSSOM_BRANCH_ID, 1),
            nuparams(YCASH_HEARTWOOD_BRANCH_ID, 3),
            nuparams(YCASH_CANOPY_BRANCH_ID, 3),
            nuparams(VAULT_BRANCH_ID, 4),
            '-pqfalconheight=4',
        ]
        shield = common + ['-regtestshieldcoinbase']
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, extra_args=[shield, shield, common, common])
        connect_nodes_bi(self.nodes, 0, 1)      # the network where coinbase must be shielded
        connect_nodes_bi(self.nodes, 2, 3)      # the network where it need not be
        self.is_network_split = False

    # ---- helpers (self.pool, self.wallet: the pair under test) ---------------------------------------------------

    def sync(self):
        sync_blocks([self.pool, self.wallet])
        sync_mempools([self.pool, self.wallet])

    def mine(self, n=1):
        """n blocks on the pool's node (its own coinbase), every pending transaction with the first."""
        self.sync()
        self.pool.generate(n)
        self.sync()
        time.sleep(1)               # the wallet's balances follow the tip a moment later

    def mine_to(self, height):
        n = height - self.pool.getblockcount()
        assert n >= 0, (height, self.pool.getblockcount())
        if n:
            self.mine(n)

    def pool_block(self, address):
        """One block paying its whole reward to `address`, as a pool makes it. Returns (coinbase txid, zat, height)."""
        self.sync()
        gbt = self.pool.getblocktemplate()
        ref = {'previousblockhash': gbt['previousblockhash'], 'txids': [t['hash'] for t in gbt['transactions']]}
        res = self.pool.getcoinbasetemplatefor(address, ref)
        assert_equal(res['fund'], 0)            # past the fund mandate, -ydf 0: the miner is paid in full
        assert_equal(res['amount'], res['subsidy'] + res['fees'])
        block = block_from(gbt, res['data'])
        assert_equal(self.pool.submitblock(bytes_to_hex_str(block.serialize())), None)
        self.sync()
        assert_equal(self.wallet.getbestblockhash(), '%064x' % block.sha256)
        return res['hash'], res['amount'], gbt['height']

    def unspent(self, address):
        """[(txid, zat, generated)] of the address, as listunspent shows it."""
        return sorted((u['txid'], zat(u['amount']), u['generated']) for u in self.wallet.listunspent(1, 9999999, [address]))

    def wait_balance(self, fn, expected):
        for _ in range(100):
            got = fn()
            if got == expected:
                return
            time.sleep(0.1)
        assert_equal(got, expected)

    def refused(self, src, outs, code, fee=None):
        """z_sendmany src -> outs is refused by the wallet (the RPC itself or its operation) with `code`; nothing
        reaches the mempool. Returns the message."""
        before = sorted(self.wallet.getrawmempool())
        try:
            opid = z_sendmany_opid(self.wallet, src, outs, 1, fee)
        except JSONRPCException as e:
            error = e.error
        else:
            result = None
            for _ in range(300):
                results = self.wallet.z_getoperationresult([opid])
                if results:
                    result = results[0]
                    break
                time.sleep(0.2)
            assert result is not None, 'operation timed out'
            assert_equal(result['status'], 'failed')
            error = result['error']
        assert_equal(error['code'], code)
        assert_equal(sorted(self.wallet.getrawmempool()), before)
        assert 'bad-txns' not in error['message'] and 'CommitTransaction' not in error['message'], error
        return error['message']

    def send(self, src, outs, fee=None):
        """z_sendmany src -> outs succeeds. Returns (txid, the decoded transaction) once the pool's mempool has it."""
        txid = wait_and_assert_operationid_status(self.wallet, z_sendmany_opid(self.wallet, src, outs, 1, fee))
        self.sync()
        assert txid in self.pool.getrawmempool(), txid
        return txid, self.wallet.decoderawtransaction(self.wallet.gettransaction(txid)['hex'])

    def value_of(self, tx):
        """(inputs in zat, fee in zat) of a decoded wallet transaction with transparent inputs only."""
        value_in = 0
        for vin in tx['vin']:
            parent = self.wallet.decoderawtransaction(self.wallet.gettransaction(vin['txid'])['hex'])
            value_in += parent['vout'][vin['vout']]['valueZat']
        return value_in, value_in - sum(v['valueZat'] for v in tx['vout']) + tx['valueBalanceZat']

    def change_refusal(self, src, outs, selected, sent, fee=None):
        """The send selects coinbase and would leave change: the wallet refuses it and names the one amount that
        spends the `selected` zat. Returns (that amount, the fee) in zat."""
        message = self.refused(src, outs, WALLET_ERROR, fee)
        m = CHANGE_REFUSAL.match(message)
        assert m, message
        print('  ' + message)
        change, exact, have, fee_named = (zat(g) for g in m.groups())
        assert_equal(have, selected)
        assert fee_named > 0
        if fee is not None:
            assert_equal(fee_named, zat(fee))
        assert_equal(exact, selected - fee_named)
        assert_equal(change, selected - sent - fee_named)
        assert_equal(m.group(2), money(exact))      # the amount is printed as the wallet prints every amount
        return exact, fee_named

    # ---- the steps -------------------------------------------------------------------------------------------

    def run_pair(self, pool, wallet, shield):
        self.pool, self.wallet = pool, wallet
        print('==== coinbase must be shielded: %s ====' % shield)
        self.mine_to(5)         # Vault and FN-DSA-512 are active and the development-fund mandate has ended

        z = wallet.z_getnewaddress('sapling')           # where the miner shields to
        z2 = wallet.z_getnewaddress('sapling')
        z_src = wallet.z_getnewaddress('sapling')       # funds an ordinary post-quantum coin
        t = wallet.getnewaddress()
        fn = wallet.getnewaddress('', 'pq')
        slh = wallet.getnewaddress('', 'pqslh')
        mix = wallet.getnewaddress('', 'pq')            # will hold a coinbase coin and an ordinary coin
        other = wallet.getnewaddress('', 'pqslh')
        prefix = fn[:2]
        assert fn.startswith(prefix + 'f') and slh.startswith(prefix + 's'), (fn, slh)

        print('the pool pays seven block rewards: FN-DSA x2, SLH-DSA x2, the mixed address, Sapling x2')
        fn_a, fn_b = self.pool_block(fn), self.pool_block(fn)            # heights 6, 7
        slh_a, slh_b = self.pool_block(slh), self.pool_block(slh)        # heights 8, 9
        mix_cb = self.pool_block(mix)                                     # height 10
        self.pool_block(z_src)
        self.pool_block(z_src)
        assert_equal([c[2] for c in (fn_a, fn_b, slh_a, slh_b, mix_cb)], [6, 7, 8, 9, 10])
        reward = fn_a[1]
        for c in (fn_b, slh_a, slh_b, mix_cb):
            assert_equal(c[1], reward)

        print('before maturity: nothing is reported spendable, and the refusal says why')
        info = wallet.getwalletinfo()
        assert_equal(zat(info['balance_pq']), 0)
        assert_equal(zat(info['balance']), 0)
        assert_equal(zat(info['immature_balance']), 5 * reward)
        assert_equal(zat(wallet.z_gettotalbalance()['transparent_pq']), 0)
        for a in (fn, slh, mix):
            assert_equal(self.unspent(a), [])
            assert_equal(zat(wallet.z_getbalance(a)), 0)
        for a, held in ((fn, 2 * reward), (slh, 2 * reward), (mix, reward)):
            for outs in ([(z, yec(reward) - 1)], [(t, Decimal('1'))]):
                assert_equal(self.refused(a, outs, INSUFFICIENT), NO_UTXOS + IMMATURE_NOTE % money(held))

        print('an ordinary coin for the mixed address (from a Sapling coinbase note)')
        ordinary = zat('2')
        fund_txid = wait_and_assert_operationid_status(wallet, z_sendmany_opid(wallet, z_src, [(mix, yec(ordinary))]))
        self.mine()
        assert_equal(self.unspent(mix), [(fund_txid, ordinary, False)])

        print('100 confirmations are not enough; 101 are')
        self.mine_to(fn_a[2] + MATURE_AT - 2)
        assert_equal(wallet.gettransaction(fn_a[0])['confirmations'], MATURE_AT - 1)
        assert_equal(self.unspent(fn), [])
        assert_equal(self.refused(fn, [(z, yec(reward) - 1)], INSUFFICIENT), NO_UTXOS + IMMATURE_NOTE % money(2 * reward))
        self.mine()
        assert_equal(wallet.gettransaction(fn_a[0])['confirmations'], MATURE_AT)
        assert_equal(self.unspent(fn), [(fn_a[0], reward, True)])
        assert_equal(zat(wallet.z_getbalance(fn)), reward)
        info = wallet.getwalletinfo()
        assert_equal(zat(info['balance_pq']), reward + ordinary)
        assert_equal(zat(info['immature_balance']), 4 * reward)

        print('FN-DSA: a transparent or post-quantum recipient never gets coinbase')
        note = COINBASE_NOTE % money(reward) + IMMATURE_NOTE % money(reward)
        for outs in ([(t, Decimal('1'))], [(other, Decimal('1'))], [(z, Decimal('1')), (t, Decimal('1'))],
                     [(fn, Decimal('1'))]):
            assert_equal(self.refused(fn, outs, INSUFFICIENT), NO_UTXOS + note)

        print('FN-DSA: change is refused, and the refusal names the amount to send')
        exact, fee = self.change_refusal(fn, [(z, Decimal('1'))], reward, zat('1'))
        # one zatoshi more than the selected coins hold: the next coinbase is immature
        m = HAVE_NEED.match(self.refused(fn, [(z, yec(exact + 1))], INSUFFICIENT))
        assert m and zat(m.group(1)) == reward, m
        assert_equal(m.group(3), IMMATURE_NOTE % money(reward))

        print('FN-DSA: the reward less the fee goes to Sapling')
        txid, tx = self.send(fn, [(z, yec(exact))])
        assert_equal([(i['txid'], i['vout']) for i in tx['vin']], [(fn_a[0], 0)])
        assert_equal(tx['vout'], [])
        assert len(tx['vShieldedOutput']) >= 1
        assert_equal(self.value_of(tx), (reward, fee))
        self.mine()
        assert_equal(wallet.gettransaction(txid)['confirmations'], 1)
        shielded = exact
        self.wait_balance(lambda: zat(wallet.z_getbalance(z)), shielded)
        assert_equal(shielded, reward - fee)

        print('FN-DSA: the second reward, to two shielded recipients with an explicit fee')
        assert_equal(self.unspent(fn), [(fn_b[0], reward, True)])       # 101 confirmations with the block just mined
        m = FEE_BELOW.match(self.refused(fn, [(z, yec(reward) - 1)], INVALID_PARAMETER, Decimal('0.00001')))
        assert m and zat(m.group(1)) == 1000 and zat(m.group(2)) > 1000, m
        paid = 2 * fee                                                   # a fee above the minimum is the caller's choice
        exact2, _ = self.change_refusal(fn, [(z, Decimal('1')), (z2, Decimal('1'))], reward, zat('2'), yec(paid))
        txid, tx = self.send(fn, [(z, yec(exact2) - 2), (z2, Decimal('2'))], yec(paid))
        assert_equal(tx['vout'], [])
        assert_equal(self.value_of(tx), (reward, paid))
        self.mine()
        shielded += exact2 - zat('2')
        self.wait_balance(lambda: zat(wallet.z_getbalance(z)), shielded)
        self.wait_balance(lambda: zat(wallet.z_getbalance(z2)), zat('2'))
        assert_equal(self.unspent(fn), [])
        assert_equal(zat(wallet.z_getbalance(fn)), 0)
        assert_equal(self.refused(fn, [(z, Decimal('1'))], INSUFFICIENT), NO_UTXOS)

        print('SLH-DSA: two rewards in one send')
        self.mine_to(slh_b[2] + MATURE_AT - 1)
        assert_equal(self.unspent(slh), sorted([(slh_a[0], reward, True), (slh_b[0], reward, True)]))
        assert_equal(self.refused(slh, [(t, Decimal('1'))], INSUFFICIENT), NO_UTXOS + COINBASE_NOTE % money(2 * reward))
        one, fee_one = self.change_refusal(slh, [(z, Decimal('1'))], reward, zat('1'))
        both, fee_both = self.change_refusal(slh, [(z, yec(reward))], 2 * reward, reward)
        assert fee_both > fee_one > fee, (fee_both, fee_one, fee)       # each SLH-DSA input is priced on its size
        txid, tx = self.send(slh, [(z, yec(both))])
        assert_equal(sorted((i['txid'], i['vout']) for i in tx['vin']), sorted([(slh_a[0], 0), (slh_b[0], 0)]))
        assert_equal(tx['vout'], [])
        assert_equal(self.value_of(tx), (2 * reward, fee_both))
        self.mine()
        assert_equal(wallet.gettransaction(txid)['confirmations'], 1)
        shielded += both
        self.wait_balance(lambda: zat(wallet.z_getbalance(z)), shielded)
        assert_equal(self.unspent(slh), [])
        assert_equal(zat(wallet.z_getbalance(slh)), 0)

        print('a mixed address: ordinary coins first, with change; coinbase only to shielded recipients')
        self.mine_to(mix_cb[2] + MATURE_AT - 1)
        assert_equal(self.unspent(mix), sorted([(fund_txid, ordinary, False), (mix_cb[0], reward, True)]))
        # a transparent recipient: the ordinary coin pays, its change returns to the address
        txid, tx = self.send(mix, [(t, Decimal('0.5'))])
        assert_equal([(i['txid'], i['vout']) for i in tx['vin']], [self.unspent_outpoint(fund_txid, mix)])
        self.mine()
        left = [u for u in self.unspent(mix) if not u[2]]
        assert_equal(len(left), 1)
        assert_equal(left[0][0], txid)
        # a shielded recipient the ordinary coin covers: still the ordinary coin, still with change
        txid2, tx = self.send(mix, [(z2, Decimal('0.5'))])
        assert_equal([i['txid'] for i in tx['vin']], [txid])
        assert_equal(len(tx['vout']), 1)                                 # the change, back to the address
        self.mine()
        left = [u for u in self.unspent(mix) if not u[2]]
        assert_equal([u[0] for u in left], [txid2])
        rest = left[0][1]
        assert 0 < rest < zat('1'), rest
        assert_equal(self.unspent(mix), sorted([(txid2, rest, False), (mix_cb[0], reward, True)]))
        # a transparent recipient the ordinary coin does not cover: the coinbase is not used
        m = HAVE_NEED.match(self.refused(mix, [(t, Decimal('3'))], INSUFFICIENT))
        assert m and zat(m.group(1)) == rest, m
        assert_equal(m.group(3), COINBASE_NOTE % money(reward))
        assert_equal(self.refused(mix, [(z, Decimal('3')), (other, Decimal('1'))], INSUFFICIENT)[-len(COINBASE_NOTE % money(reward)):],
                     COINBASE_NOTE % money(reward))
        # a shielded recipient the ordinary coin does not cover: the coinbase joins, and then there is no change
        self.change_refusal(mix, [(z, Decimal('3'))], reward, zat('3'))                 # the coinbase coin alone
        total, fee_mixed = self.change_refusal(mix, [(z, yec(reward))], reward + rest, reward)
        # one zatoshi short of that amount is not change: what is below the dust threshold goes to the fee
        txid, tx = self.send(mix, [(z, yec(total - 1))])
        assert_equal(sorted((i['txid'], i['vout']) for i in tx['vin']),
                     sorted([(mix_cb[0], 0), self.unspent_outpoint(txid2, mix)]))
        assert_equal(tx['vout'], [])
        assert_equal(self.value_of(tx), (reward + rest, fee_mixed + 1))
        self.mine()
        assert_equal(wallet.gettransaction(txid)['confirmations'], 1)
        shielded += total - 1
        self.wait_balance(lambda: zat(wallet.z_getbalance(z)), shielded)
        assert_equal(self.unspent(mix), [])

        print('nothing is left at a post-quantum address')
        info = wallet.getwalletinfo()
        assert_equal(zat(info['balance_pq']), 0)
        assert_equal(zat(info['immature_balance']), 0)
        assert_equal(zat(wallet.z_gettotalbalance()['transparent_pq']), 0)
        for a in (fn, slh, mix):
            assert_equal(zat(wallet.z_getbalance(a)), 0)

    def unspent_outpoint(self, txid, address):
        """(txid, n) of the output of wallet transaction `txid` that pays `address`."""
        script = self.wallet.validateaddress(address)['scriptPubKey']
        tx = self.wallet.decoderawtransaction(self.wallet.gettransaction(txid)['hex'])
        outs = [v['n'] for v in tx['vout'] if v['scriptPubKey']['hex'] == script]
        assert_equal(len(outs), 1)
        return (txid, outs[0])

    def run_test(self):
        self.run_pair(self.nodes[0], self.nodes[1], True)
        self.run_pair(self.nodes[2], self.nodes[3], False)


if __name__ == '__main__':
    WalletPQCoinbaseSpendTest().main()
