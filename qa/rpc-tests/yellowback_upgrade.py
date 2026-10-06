#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Ycash Yellowback (YED) on the vault primitive, end to end (docs/plans/yellowback-upgrade-plan.md
§5, §15.10, U-21..U-24), through the RPCs:

- activation: UPGRADE_VAULT at ACTIVATION; before an attestor set is configured no yed_* RPC
  exists; the attestor set is created with set_create (open, cancel threshold 1) and joined by
  node 1; the nodes restart with -yellowbackattestorset=<setid> and Yellowback is live from the
  activation height (yed_getactivation: status active);
- mint: yed_mint's vault output is the primitive's V template (tag YED, the attestor set as both
  sets, delay CLAIM_DELAY, ownerHeight = lockHeight, appHeight = lockHeight + GRACE);
- the owner's redeem (selector 2) after lockHeight closes the vault;
- an underwater claim (yed_claim, selector 4) moves the vault into a claimant intent (CLAIMING);
  vault_release is refused before CLAIM_DELAY and pays the claimant after it (CLAIMED);
- a reorg across the claim: the vault is ACTIVE again with no intent, and CLAIMING again after
  the reconsider, with one state hash on every node;
- a wrong-price claim cancelled by the attestor set (vault_buildcancel + set_signcancel on the
  member's node + vault_send): the collateral is back in a byte-identical vault, the position is
  ACTIVE at the cancel's output 0 and the claimant's burn is not refunded (U-24);
- an invalid mint (a $50 mint) is refused by the mempool (bad-yellowback-bad-mint-amount) and a
  block carrying it, built on node 3 (YED not configured there), is rejected by every
  Yellowback node with that reason; node 0 bans node 3 for relaying it (DoS 100).

    ZCASHD=<ycashd> ../.venv/bin/python -u qa/rpc-tests/yellowback_upgrade.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

import os
import time
from io import BytesIO

from test_framework.authproxy import JSONRPCException
from test_framework.mininode import CBlock, CTransaction
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID,
    assert_equal,
    bytes_to_hex_str,
    connect_nodes_bi,
    hex_str_to_bytes,
    nuparams,
    start_node,
    start_nodes,
    stop_node,
    sync_blocks,
    sync_mempools,
)
from test_framework.yellowback_attest import wait_for_spender
from test_framework.yellowback_util import YCASH_UPGRADE_ARGS
from test_framework import yellowback_model as ym

ACTIVATION = 130
CLAIM_DELAY = 10
GRACE = 24
REF_LAG = 2
PRICE = 50_000_000        # $50 / YEC: a $100 mint at 500 % locks 10 YEC
CRASH = 5_000_000         # $5 / YEC: 10 YEC back $50 < $110 (underwater)


def assert_raises_rpc(substr, fn, *args):
    try:
        fn(*args)
    except JSONRPCException as e:
        assert substr in e.error['message'], 'expected %r in %r' % (substr, e.error['message'])
        return e.error['message']
    raise AssertionError('expected an RPC error containing %r' % substr)


class YellowbackUpgradeTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.cache_behavior = 'clean'   # 6.20.0 harness: replaces setup_clean_chain
        self.set_id = None
        self.payout = None

    def node_args_for(self, i):
        a = list(YCASH_UPGRADE_ARGS) + [nuparams(VAULT_BRANCH_ID, ACTIVATION), '-debug=yellowback', '-debug=vault']
        if self.set_id is not None and i < 3:      # node 3 never learns the attestor set: Yellowback is off there
            a.append('-yellowbackattestorset=%s' % self.set_id)
            if i == 0:
                a.append('-yellowbackpayoutaddress=%s' % self.payout)
        return a

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, extra_args=[self.node_args_for(i) for i in range(self.num_nodes)])
        self.connect()
        self.is_network_split = False

    def connect(self):
        for a, b in ((0, 1), (1, 2), (0, 2), (0, 3)):
            connect_nodes_bi(self.nodes, a, b)

    def yb(self):
        return self.nodes[:3]

    def sync(self, nodes=None):
        nodes = nodes or self.yb()
        sync_blocks(nodes)
        sync_mempools(nodes)

    def mine(self, n=1, node=0):
        self.sync()
        hashes = self.nodes[node].generate(n)
        self.sync()
        return hashes

    def restart_all(self):
        for i in range(self.num_nodes):
            stop_node(self.nodes[i], i)
        for i in range(self.num_nodes):
            self.nodes[i] = start_node(i, self.options.tmpdir, self.node_args_for(i))
        self.connect()
        self.sync(self.nodes)

    def two_step(self, node, method, *args):
        """A yed_mint / yed_claim with wait=false: the carrier first, then the main transaction after one block."""
        res = getattr(node, method)(*args, '', False)
        assert_equal(res['pending'], True)
        self.mine()
        txid = wait_for_spender(node, res['carrierTxid'])
        self.sync()
        return res, txid

    def statehashes(self):
        return [n.yed_getstatehash()['statehash'] for n in self.yb()]

    def assert_one_state(self, label):
        self.sync()
        hashes = set(self.statehashes())
        assert len(hashes) == 1, '%s: state hashes differ: %r' % (label, hashes)
        return hashes.pop()

    def run_test(self):
        n0, n1, n2, n3 = self.nodes
        n0.generate(120)
        self.sync(self.nodes)
        for n in (n1, n2):
            n0.sendtoaddress(n.getnewaddress(), 6)
        self.mine()

        print('before the attestor set: no yed_* RPC; the vault upgrade activates at %d' % ACTIVATION)
        assert_raises_rpc('Method not found', n0.yed_getinfo)
        self.mine(ACTIVATION - n0.getblockcount())
        assert_equal(n0.vault_getinfo()['active'], True)
        created = n0.set_create({'seats': 3, 'unlockthreshold': 1, 'cancelthreshold': 1, 'slashthreshold': 1,
                                 'open': True, 'maturity': 2})
        self.mine()
        self.set_id = created['setid']
        joined = n1.set_join(self.set_id, 1, n0.getblockcount() + 300)
        assert 'txid' in joined, joined
        self.mine(3)
        info = n0.set_getinfo(self.set_id)
        assert_equal((info['members'], info['current']), (1, 1))

        print('the nodes learn the attestor set: Yellowback is live from the activation height (U-22)')
        self.payout = n0.getnewaddress()
        self.restart_all()
        for n in self.yb():
            act = n.yed_getactivation()
            assert_equal(act['status'], 'active')
            assert_equal(act['activationHeight'], ACTIVATION)
            assert_equal(act['attestorSetId'], self.set_id)
            assert_equal(act['claimDelay'], CLAIM_DELAY)
            gi = n.yed_getinfo()
            assert_equal(gi['rpcversion'], 5)
            assert_equal(gi['startHeight'], ACTIVATION)
            for gone in ('enforcing', 'valveTripped', 'sunset', 'rejectedBlocks', 'abandoned', 'activation'):
                assert gone not in gi, gone
        assert_raises_rpc('Method not found', n3.yed_getinfo)
        n0.yed_setquote(PRICE, 1)
        self.mine(70)
        assert_equal(n0.yed_getstats()['mintingAllowed'], True)
        self.assert_one_state('live')

        print('mint: the vault output is the V template, tag YED (U-23)')
        _res, mint_a = self.two_step(n0, 'yed_mint', 10_000, 48, '')
        self.mine()
        va = n0.yed_getvault(mint_a)
        assert_equal(va['status'], 'ACTIVE')
        raw = n0.getrawtransaction(mint_a, 1)
        spk = raw['vout'][0]['scriptPubKey']['hex']
        assert_equal(va['scriptPubKey'], spk)
        dec = n0.vault_decodescript(spk)
        assert_equal(dec['type'], 'vault')
        assert_equal(dec["tag"], "59454400")
        assert_equal(dec['setid'], self.set_id)
        assert_equal(dec['cancelsetid'], self.set_id)
        assert_equal(dec['delay'], CLAIM_DELAY)
        assert_equal(dec['ownerheight'], va['lockHeight'])
        assert_equal(dec['appheight'], va['lockHeight'] + GRACE)
        assert_equal(va['claimHeight'], va['lockHeight'] + GRACE)
        supply = n0.yed_getstats()['supplyCents']
        assert_equal(supply, 10_000)
        self.assert_one_state('mint A')

        print('the owner redeems after lockHeight (selector 2): CLOSED')
        assert_raises_rpc('vault-locked', n0.yed_redeem, mint_a)
        self.mine(va['lockHeight'] - n0.getblockcount())
        red = n0.yed_redeem(mint_a)
        self.mine()
        assert_equal(n0.yed_getvault(mint_a)['status'], 'CLOSED')
        tx = n0.getrawtransaction(red['txid'], 1)
        assert tx['vin'][0]['scriptSig']['hex'].endswith('52'), tx['vin'][0]['scriptSig']      # ... OP_2
        assert_equal(n0.yed_getstats()['supplyCents'], 0)

        print('two more vaults, their YED sent to the claimants (nodes 1 and 2)')
        _res, mint_b = self.two_step(n0, 'yed_mint', 10_000, 48, '')
        self.mine()
        _res, mint_c = self.two_step(n0, 'yed_mint', 10_000, 48, '')
        self.mine()
        spk_c = n0.getrawtransaction(mint_c, 1)['vout'][0]['scriptPubKey']['hex']
        for claimant in (n1, n2):
            n0.yed_send(claimant.yed_getnewaddress(), 10_000)
            self.mine()
            n0.sendtoaddress(claimant.getnewaddress(), 5)
        self.mine()
        assert_equal(n1.yed_getbalance()['confirmedCents'], 10_000)
        assert_equal(n2.yed_getbalance()['confirmedCents'], 10_000)

        print('the price falls to $5 for a whole slow window; the claim path opens')
        n0.yed_setquote(CRASH, 1)
        vb = n0.yed_getvault(mint_b)
        self.mine(max(70, vb['claimHeight'] - n0.getblockcount()))
        assert n0.yed_getvault(mint_b)['claimable']

        print('an underwater claim (selector 4) moves the vault into a claimant intent: CLAIMING')
        _res, claim_b = self.two_step(n1, 'yed_claim', mint_b, '')
        claim_block = self.mine()[0]
        vb = n1.yed_getvault(mint_b)
        assert_equal(vb['status'], 'CLAIMING')
        assert_equal([(i['txid'], i['vout'], i['role']) for i in vb['intents']], [(claim_b, 0, 'claimant')])
        craw = n1.getrawtransaction(claim_b, 1)
        assert craw['vin'][0]['scriptSig']['hex'] == '54', craw['vin'][0]['scriptSig']    # OP_4
        idec = n1.vault_decodescript(craw['vout'][0]['scriptPubKey']['hex'])
        assert_equal(idec['type'], 'intent')
        assert_equal(idec["tag"], "59454400")
        assert_equal(craw['vout'][0]['valueZat'], vb['collateralZat'])                   # the whole vault (S-2)
        assert_equal(n0.yed_getstats()['supplyCents'], 10_000)                          # the claim burned its 10,000
        claiming = self.assert_one_state('claim B')

        print('a reorg across the claim: ACTIVE again, then CLAIMING again')
        for n in self.yb():
            n.invalidateblock(claim_block)
        for n in self.yb():
            assert_equal(n.yed_getvault(mint_b)['status'], 'ACTIVE')
            assert 'intents' not in n.yed_getvault(mint_b)
        for n in self.yb():
            n.reconsiderblock(claim_block)
        self.sync()
        for n in self.yb():
            assert_equal(n.yed_getvault(mint_b)['status'], 'CLAIMING')
        assert_equal(self.assert_one_state('reconsidered'), claiming)

        print('the release waits CLAIM_DELAY, then pays the claimant: CLAIMED')
        assert_raises_rpc('matures at height', n1.vault_release, '%s:0' % claim_b)
        self.mine(CLAIM_DELAY - 1)
        rel = n1.vault_release('%s:0' % claim_b)
        # yed_validaterawtransaction verifies scripts under the vault flags at tip + 1: the RELEASE's CSV passes
        assert_equal(n1.yed_validaterawtransaction(n1.getrawtransaction(rel))['valid'], True)
        self.mine()
        assert_equal(n0.yed_getvault(mint_b)['status'], 'CLAIMED')
        assert rel in n1.getblock(n1.getbestblockhash())['tx']
        self.assert_one_state('release B')

        print('a wrong-price claim cancelled by the attestor set: the same position ACTIVE, the burn kept (U-24)')
        _res, claim_c = self.two_step(n2, 'yed_claim', mint_c, '')
        self.mine()
        assert_equal(n0.yed_getvault(mint_c)['status'], 'CLAIMING')
        before = n0.yed_getstats()
        built = n2.vault_buildcancel('%s:0' % claim_c)
        signed = n1.set_signcancel(built['hex'])
        assert_equal(signed['complete'], True)
        cancel = n2.vault_send(signed['hex'])                                     # vault_send signs the fee inputs
        assert_equal(n2.yed_validaterawtransaction(n2.getrawtransaction(cancel))['valid'], True)   # OP_CHECKSETSIG at the tip set state
        self.mine()
        assert_raises_rpc('', n0.yed_getvault, mint_c)                          # the record moved to the re-created vault
        vc = n0.yed_getvault(cancel)
        assert_equal(vc['status'], 'ACTIVE')
        assert_equal(vc['mintedCents'], 10_000)
        assert_equal(vc['scriptPubKey'], spk_c)
        assert_equal(n0.getrawtransaction(cancel, 1)['vout'][0]['scriptPubKey']['hex'], spk_c)     # byte-identical
        after = n0.yed_getstats()
        assert_equal(after['supplyCents'], before['supplyCents'])               # the claim burned the YED; the cancel refunds nothing
        assert_equal(after['supplyCents'], 0)
        assert_equal(after['activeVaults'], before['activeVaults'] + 1)
        log = n0.yed_gettxinfo(cancel)
        assert_equal(log['type'], 'claim_cancel')
        self.assert_one_state('cancel C')

        print('an invalid mint: refused by the mempool, and the block carrying it rejected by every Yellowback node')
        bad = self.bad_mint(n0)
        assert_raises_rpc('bad-yellowback-bad-mint-amount', n0.sendrawtransaction, bad)
        tip = n0.getbestblockhash()
        block = self.block_on(n3, bad)
        assert_equal(n3.submitblock(block), None)                                # YED is off on node 3: accepted there
        for n in (n1, n2):
            assert_equal(n.submitblock(block), 'bad-yellowback-bad-mint-amount')
        # node 3 relays it to node 0, which scores the relayer 100 (DoS 100; a local peer is disconnected, not banned)
        log = os.path.join(self.options.tmpdir, 'node0', 'regtest', 'debug.log')
        deadline = time.time() + 30
        found = False
        while time.time() < deadline and not found:
            with open(log, encoding='utf-8', errors='replace') as f:
                text = f.read()
            found = 'is invalid: bad-mint-amount' in text and '(0 -> 100) BAN THRESHOLD EXCEEDED' in text
            time.sleep(0.2)
        assert found, 'node 0 did not score the relayer of the invalid block 100'
        for n in self.yb():
            assert_equal(n.getbestblockhash(), tip)

    def bad_mint(self, node):
        """A $50 mint (MINT-2: bad-mint-amount) on the YED V, signed by ``node``'s wallet."""
        params = ym.Params.regtest(ACTIVATION, attestor_set=self.set_id)
        owner = hex_str_to_bytes(node.validateaddress(node.getnewaddress())['pubkey'])
        ref = node.getblockcount() - REF_LAG
        lock = ref + 48
        coin = [u for u in node.listunspent() if u['amount'] > 2][0]
        vouts = [(1 * ym.COIN, ym.yed_vault_script(params, owner, lock)),
                 (10_000, ym.p2pkh_script(ym.hash160(owner))),
                 (0, bytes([ym.OP_RETURN]) + ym.push(ym.encode_mint(0, 5_000, lock, ref, owner, ym.FEE_VOUT_NONE))),
                 (int(coin['amount'] * ym.COIN) - 1 * ym.COIN - 10_000 - 10_000, ym.p2pkh_script(ym.hash160(owner)))]
        raw = ym.serialize_tx_v4([(coin['txid'], coin['vout'], b'', 0xFFFFFFFF)], vouts, 0, ref + 40).hex()
        signed = node.signrawtransaction(raw)
        assert signed['complete'], signed
        return signed['hex']

    def block_on(self, node, tx_hex):
        """A block on ``node``'s tip carrying ``tx_hex`` (solved in Python), as hex."""
        gbt = node.getblocktemplate()
        cb = CTransaction()
        cb.deserialize(BytesIO(hex_str_to_bytes(gbt['coinbasetxn']['data'])))
        cb.vout[0].nValue -= sum(int(t.get('fee', 0)) for t in gbt.get('transactions', []))
        block = CBlock()
        block.nVersion = gbt['version']
        block.hashPrevBlock = int(gbt['previousblockhash'], 16)
        block.hashBlockCommitments = int(gbt['finalsaplingroothash'], 16)   # 6.20.0 mininode name (yellowback_util.mine_block_raw)
        block.nTime = gbt['curtime']
        block.nBits = int(gbt['bits'], 16)
        tx = CTransaction()
        tx.deserialize(BytesIO(hex_str_to_bytes(tx_hex)))
        block.vtx = [cb, tx]
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        return bytes_to_hex_str(block.serialize())


if __name__ == '__main__':
    YellowbackUpgradeTest().main()
