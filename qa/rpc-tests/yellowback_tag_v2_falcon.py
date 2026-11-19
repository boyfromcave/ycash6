#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Tag v2 before Falcon: an FN-DSA-512 payee is policy-gated on the Falcon height (beta4 P1 follow-up).

Regtest with -pqfalconheight=FALCON, later than the vault activation (VAULT_ACTIVATION), on every node. Policy only:
a v2 FN-DSA tag and an FN-DSA fee output stay valid at every height; what changes is what this node does.

- init: -yellowbackpayoutaddress=rqf... and -yellowbackpreferredpayee=rqf... are refused while Falcon is not active
  at the next block; an rqs... (SLH-DSA) payout address is accepted and its pool mines v2 SLH-DSA tags.
- the wallet's draw: with a (foreign, hand-built) v2 FN-DSA quote tag in the payee window before Falcon, E(R) lists
  the FN-DSA payee, yet yed_getfeepayee's default never picks it for any selector, and a wallet mint pays another
  payee.
- from the Falcon height the rqf... payout address is accepted at init, its pool mines v2 FN-DSA tags, and the draw
  picks the FN-DSA payee again.
- the Python model replays the chain and agrees with the state hash.

Rule: FEE-W MINER-2 TAG-1
"""

import os
from io import BytesIO

from test_framework.mininode import CBlock, CTransaction
from test_framework.pq_address import FN_DSA, encode_pq_address
from test_framework.util import assert_equal, assert_start_raises_init_error, bytes_to_hex_str, hex_str_to_bytes, stop_node
from test_framework.yellowback_attest import wallet_mint
from test_framework.yellowback_util import (
    POOLS,
    REF_LAG,
    USER,
    VAULT_ACTIVATION,
    YellowbackTestFramework,
    usd_to_micro,
)
from test_framework import yellowback_model as ym

FALCON = 230                    # -pqfalconheight: well after the activation window (VAULT_ACTIVATION + 70)
REFUSED = 'an FN-DSA-512 address is refused before Falcon is active'


class YellowbackTagV2FalconTest(YellowbackTestFramework):

    def __init__(self):
        super().__init__()
        self.pq_payout = {}            # pool index -> its post-quantum payout address

    def node_args(self, i, extra=None):
        args = super().node_args(i, extra)
        if i in self.pq_payout:
            args = [a for a in args if not a.startswith('-yellowbackpayoutaddress=')]
            args.append('-yellowbackpayoutaddress=%s' % self.pq_payout[i])
        args = [a for a in args if not a.startswith('-pqfalcon')]
        return args + ['-pqfalconheight=%d' % FALCON]     # a consensus parameter: every node, the stock one too

    def refused_at_init(self, i, extra):
        stop_node(self.nodes[i], i)
        self.nodes[i] = None
        assert_start_raises_init_error(i, self.options.tmpdir, self.node_args(i) + extra, REFUSED)
        return self.restart(i)

    def mine_foreign_fn_tag(self, i, payee):
        """A block from pool ``i``'s template whose coinbase carries a v2 FN-DSA quote tag for ``payee`` in place of
        the pool's own tag (what another implementation's miner may publish: a valid tag at every height)."""
        node = self.nodes[i]
        gbt = node.getblocktemplate()
        cb = CTransaction()
        cb.deserialize(BytesIO(hex_str_to_bytes(gbt['coinbasetxn']['data'])))
        ss = cb.vin[0].scriptSig
        at = ss.find(b'\x24YED!\x01')
        assert at > 0, ss.hex()
        cb.vin[0].scriptSig = ss[:at] + ym.tag_push_for_payee(0, usd_to_micro(50), 1, payee) + ss[at + 37:]
        block = CBlock()
        block.nVersion = gbt['version']
        block.hashPrevBlock = int(gbt['previousblockhash'], 16)
        # the header's fourth field: hashFinalSaplingRoot in the v4.5.0 harness, hashBlockCommitments in the 6.20.0 one
        block.hashFinalSaplingRoot = block.hashBlockCommitments = int(gbt['finalsaplingroothash'], 16)
        block.nTime = gbt['curtime']
        block.nBits = int(gbt['bits'], 16)
        block.vtx.append(cb)
        for t in gbt['transactions']:
            tx = CTransaction()
            tx.deserialize(BytesIO(hex_str_to_bytes(t['data'])))
            block.vtx.append(tx)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        assert_equal(node.submitblock(bytes_to_hex_str(block.serialize())), None)
        self.sync_all(blocks_only=True)
        return node.getblockcount()

    def defaults(self, node, ref, n=40):
        return {node.yed_getfeepayee(ref, '%064x' % s)['default']['payoutAddress'] for s in range(n)}

    def run_test(self):
        nodes = self.nodes
        user = nodes[USER]
        fn_pool, slh_pool = POOLS[1], POOLS[2]
        assert FALCON > VAULT_ACTIVATION
        fn_addr = encode_pq_address(FN_DSA, os.urandom(32))
        assert fn_addr.startswith('rqf'), fn_addr
        fn_payee = ym.address_payee(fn_addr)

        print('init before Falcon: -yellowbackpayoutaddress=rqf... and -yellowbackpreferredpayee=rqf... are refused')
        self.refused_at_init(fn_pool, ['-yellowbackpayoutaddress=%s' % fn_addr])
        user = self.refused_at_init(USER, ['-yellowbackpreferredpayee=%s' % fn_addr])

        print('an rqs... (SLH-DSA) payout address is accepted before Falcon')
        slh_addr = nodes[slh_pool].getnewaddress('pqslh')
        assert slh_addr.startswith('rqs'), slh_addr
        self.pq_payout = {slh_pool: slh_addr}
        self.restart(slh_pool)
        assert_equal(nodes[slh_pool].yed_getinfo()['miner']['payoutAddress'], slh_addr)
        self.activate(quote_usd=50)
        self.mine(slh_pool, blocks_only=True)
        tag = user.yed_gettag(str(user.getblockcount()))
        assert_equal((tag['version'], tag['payoutScheme'], tag['payoutAddress']), (2, 'slh-dsa-sha2-128s', slh_addr))

        print('a foreign v2 FN-DSA tag before Falcon: E(R) lists it, the wallet\'s draw never picks it')
        h = self.mine_foreign_fn_tag(POOLS[0], fn_payee)
        tag = user.yed_gettag(str(h))
        assert_equal((tag['version'], tag['payoutScheme'], tag['payoutAddress']), (2, 'fn-dsa-512', fn_addr))
        self.mine_round_robin([POOLS[0], slh_pool], REF_LAG)
        assert user.getblockcount() + 1 < FALCON, user.getblockcount()
        ref = user.getblockcount() - REF_LAG
        assert fn_addr in user.yed_getfeepayee(ref)['eligible']
        picks = self.defaults(user, ref)
        assert fn_addr not in picks, picks
        mint = wallet_mint(self, user, 10000, 48)
        assert mint['payee'] != fn_addr, mint
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(user.yed_getvault(mint['txid'])['status'], 'ACTIVE')

        print('from the Falcon height: rqf... is accepted at init, its pool mines v2 FN-DSA tags, the draw picks it')
        while user.getblockcount() + 1 < FALCON:
            self.mine_round_robin([POOLS[0], slh_pool], min(10, FALCON - 1 - user.getblockcount()))
        self.pq_payout[fn_pool] = fn_addr
        self.restart(fn_pool)
        assert_equal(nodes[fn_pool].yed_getinfo()['miner']['payoutAddress'], fn_addr)
        self.mine_round_robin([fn_pool, POOLS[0], slh_pool], 6)
        fn_tags = [x for x in range(FALCON, user.getblockcount() + 1) if user.yed_gettag(str(x)).get('payoutScheme') == 'fn-dsa-512']
        assert fn_tags, 'no FN-DSA tag after Falcon'
        ref = user.getblockcount() - REF_LAG
        picks = self.defaults(user, ref)
        assert fn_addr in picks, picks

        print('the Python model agrees (state hash)')
        ym.assert_model_matches(user)
        self.checkpoint('tag v2 falcon')


if __name__ == '__main__':
    YellowbackTagV2FalconTest().main()
