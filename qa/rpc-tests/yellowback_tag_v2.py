#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Tag v2: a post-quantum payout key (workspace docs/plans/beta4/price-feed.md section 4.3, section 4.5).

Three pools quote side by side: POOLS[0] with its P2PKH payout address (tag v1), POOLS[1] with an FN-DSA-512 address
(-yellowbackpayoutaddress=rqf..., tag v2) and POOLS[2] with an SLH-DSA-SHA2-128s one (rqs..., tag v2).

- D-1: a block of the rqf pool carries a 49-byte v2 tag (0x31 || YED! || 0x02 ...); yed_gettag reports version 2,
  payoutScheme "fn-dsa-512" and payoutAddress rqf...; the same for rqs... and "slh-dsa-sha2-128s"; the P2PKH pool's
  tag stays v1 ("p2pkh"), 36 bytes.
- D-4: with v1 and v2 tags in the payee window yed_getfeepayee lists both kinds, and wallet mints paying either kind
  (-yellowbackpreferredpayee=rqf..., then the P2PKH pool) are accepted.
- D-3 (the wallet half): the mint's fee output is the 35-byte TX_PQPKH of the eligible v2 payee.
- D-5: the post-quantum fee output is spent at one confirmation, with z_sendmany, to a transparent address.
- D-9: rpcversion 11 (read from the contract, qa/yellowback-rpcversion.py). The Python model replays the chain
  and agrees with every yed_gettag (version, payoutScheme,
  payoutAddress) and the state hash.

Rule: TAG-1 TAG-2 MINT-8 FEE-2 MINER-2
"""

from decimal import Decimal

from test_framework.util import assert_equal, wait_and_assert_operationid_status, z_sendmany_opid
from test_framework.yellowback_attest import wallet_mint
from test_framework.yellowback_util import (
    POOLS,
    REF_LAG,
    USER,
    YELLOWBACK_RPC_VERSION,
    YellowbackTestFramework,
)
from test_framework import yellowback_model as ym


class YellowbackTagV2Test(YellowbackTestFramework):

    def __init__(self):
        super().__init__()
        self.pq_payout = {}            # pool index -> its post-quantum payout address (tag v2)
        self.preferred = None          # the user's -yellowbackpreferredpayee

    def node_args(self, i, extra=None):
        args = super().node_args(i, extra)
        if i in self.pq_payout:
            args = [a for a in args if not a.startswith('-yellowbackpayoutaddress=')]
            args.append('-yellowbackpayoutaddress=%s' % self.pq_payout[i])
        if i == USER and self.preferred:
            args.append('-yellowbackpreferredpayee=%s' % self.preferred)
        if not any(a.startswith('-pqfalconheight') for a in args):
            args.append('-pqfalconheight=0')       # FN-DSA from the vault activation, as on mainnet (D-Q-2)
        return args

    def coinbase_scriptsig(self, node, height):
        blk = node.getblock(node.getblockhash(height), 2)
        return bytes.fromhex(blk['tx'][0]['vin'][0]['coinbase'])

    def check_tag(self, node, height, version, scheme, address):
        tag = node.yed_gettag(str(height))
        assert_equal((tag['found'], tag['kind'], tag['version'], tag['payoutScheme'], tag['payoutAddress']),
                     (True, 'quote', version, scheme, address))
        ss = self.coinbase_scriptsig(node, height)
        if version == 2:
            i = ss.find(b'\x31YED!\x02')
            assert i > 0, ss.hex()
            body = ss[i + 1:i + 50]
            assert_equal(len(body), 49)                                          # the 49-byte v2 tag
            assert_equal(body[16], {'fn-dsa-512': 2, 'slh-dsa-sha2-128s': 1}[scheme])
            assert_equal(ym.address_payee(address), body[16:49])                 # payoutScheme || payoutHash
            assert ss.find(b'\x24YED!') < 0
        else:
            i = ss.find(b'\x24YED!\x01')
            assert i > 0, ss.hex()
            assert_equal(len(ss[i + 1:i + 37]), 36)
            assert ss.find(b'\x31YED!') < 0
        return tag

    def run_test(self):
        nodes = self.nodes
        user = nodes[USER]
        fn_pool, slh_pool = POOLS[1], POOLS[2]

        print('D-9: rpcversion is the contract\'s (11 since tag v2)')
        assert_equal(user.yed_getinfo()['rpcversion'], YELLOWBACK_RPC_VERSION)

        print('give two pools post-quantum payout addresses (rqf..., rqs...) from their own wallets')
        fn_addr = nodes[fn_pool].getnewaddress('pq')          # FN-DSA-512: Falcon is active (-pqfalconheight=0)
        slh_addr = nodes[slh_pool].getnewaddress('pqslh')     # SLH-DSA-SHA2-128s
        assert fn_addr.startswith('rqf') and slh_addr.startswith('rqs'), (fn_addr, slh_addr)
        self.pq_payout = {fn_pool: fn_addr, slh_pool: slh_addr}
        for i in (fn_pool, slh_pool):
            self.restart(i)
        p2pkh_addr = self.pool_addresses[0]
        self.activate(quote_usd=50)
        assert_equal(nodes[fn_pool].yed_getinfo()['miner']['payoutAddress'], fn_addr)
        assert_equal(nodes[slh_pool].yed_getinfo()['miner']['payoutAddress'], slh_addr)

        print('D-1: each pool mines a block; v2 tags for rqf/rqs, v1 for P2PKH')
        expect = {POOLS[0]: (1, 'p2pkh', p2pkh_addr), fn_pool: (2, 'fn-dsa-512', fn_addr), slh_pool: (2, 'slh-dsa-sha2-128s', slh_addr)}
        for i in POOLS:
            self.mine(i, blocks_only=True)
            h = user.getblockcount()
            self.check_tag(user, h, *expect[i])
        self.mine_round_robin(POOLS, REF_LAG + 1)

        print('D-4: v1 and v2 payees in the window; yed_getfeepayee lists both kinds')
        ref = user.getblockcount()
        payee = user.yed_getfeepayee(ref)
        assert_equal(set(payee['eligible']), {p2pkh_addr, fn_addr, slh_addr})
        listed = {r['payoutAddress'] for r in user.yed_listminers()}
        assert_equal(listed, {p2pkh_addr, fn_addr, slh_addr})

        print('D-3/D-4: a wallet mint paying the FN-DSA payee (-yellowbackpreferredpayee=rqf...)')
        self.preferred = fn_addr
        user = self.restart(USER)
        assert_equal(user.yed_getinfo()['params']['policy']['preferredPayee'], fn_addr)
        mint = wallet_mint(self, user, 10000, 48)
        assert_equal(mint['payee'], fn_addr)
        raw = user.getrawtransaction(mint['txid'], 1)
        fee_script = ym.payee_script(ym.address_payee(fn_addr))
        assert_equal(len(fee_script), 35)                                               # 0x20 <hash> OP_2 OP_CHECKPQSIG
        fee_out = [o for o in raw['vout'] if o['scriptPubKey']['hex'] == fee_script.hex()]
        assert_equal(len(fee_out), 1)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(user.yed_getvault(mint['txid'])['status'], 'ACTIVE')
        assert_equal(user.yed_gettxinfo(mint['txid'])['payee'], fn_addr)

        print('D-5: the post-quantum fee output is spent at one confirmation, with z_sendmany, to a transparent address')
        pool = nodes[fn_pool]
        coins = [u for u in pool.listunspent(1, 9999999, [fn_addr]) if u['txid'] == mint['txid']]
        assert_equal(len(coins), 1)
        assert_equal(coins[0]['confirmations'], 1)
        assert_equal(int(round(coins[0]['amount'] * 100000000)), mint['feeZat'])
        dest = nodes[POOLS[0]].getnewaddress()
        amount = (Decimal(mint['feeZat']) / Decimal(100000000) / 2).quantize(Decimal('0.00000001'))
        spend = wait_and_assert_operationid_status(pool, z_sendmany_opid(pool, fn_addr, [(dest, amount)], 1))
        tx = pool.getrawtransaction(spend, 1)
        assert (mint['txid'], coins[0]['vout']) in {(i['txid'], i['vout']) for i in tx['vin']}
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(nodes[POOLS[0]].getreceivedbyaddress(dest), amount)

        print('D-4: a wallet mint paying the P2PKH payee from the same mixed window')
        self.preferred = p2pkh_addr
        user = self.restart(USER)
        mint2 = wallet_mint(self, user, 10000, 48)
        assert_equal(mint2['payee'], p2pkh_addr)
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(user.yed_getvault(mint2['txid'])['status'], 'ACTIVE')
        assert_equal(user.yed_gettxinfo(mint2['txid'])['payee'], p2pkh_addr)

        print('the Python model agrees: every yed_gettag (version, payoutScheme, payoutAddress) and the state hash')
        ym.assert_model_matches(user)
        self.checkpoint('tag v2')


if __name__ == '__main__':
    YellowbackTagV2Test().main()
