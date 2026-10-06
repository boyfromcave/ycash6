#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
MINT_REQUIRES_ARMED (hardening plan H-1) on regtest: every Yellowback node runs with
-yellowbackmintrequiresarmed, the value mainnet and testnet compile in. After activation and
before the attestation layer arms, yed_getinfo reports mintRequiresArmed, yed_getstats shows no
mintable class, yed_mint refuses with mintpol-unarmed and a hand-built mint (mined in a block
assembled in Python: TPL-2 keeps a VOID mint out of every template) confirms VOID with
mint-halted-unarmed on every enforcing node, with one state hash. Then the layer arms
(register_and_arm), the classes open again and a wallet mint with its bundle confirms ACTIVE.
The Python model replays the chain with the flag (it is a hashed regtest value, M13).

Nodes: 0 user, 1 stock, 2-4 pools, 5 observer.
"""

from test_framework.util import assert_equal
from test_framework.yellowback_util import (
    POOLS,
    REF_LAG,
    STOCK,
    YellowbackTestFramework,
    assert_same_statehash,
    build_mint_tx,
    mine_block_raw,
    wait_yed_healthy,
)
from test_framework.yellowback_attest import ArmedModeMixin, register_and_arm

CENTS, LOCK = 10_000, 48


def assert_rpc_error(substr, fn, *args):
    try:
        fn(*args)
    except Exception as e:
        assert substr in str(e), 'expected %r in %r' % (substr, str(e))
        return str(e)
    raise AssertionError('expected an error containing %r' % substr)


# Rule: MINT-4 MINTPOL-1
class YellowbackMintArmedTest(ArmedModeMixin, YellowbackTestFramework):

    initial_blocks = 101

    def node_args(self, i, extra=None):
        if i != STOCK:
            extra = list(extra or []) + ['-yellowbackmintrequiresarmed']
        return super().node_args(i, extra)

    def run_test(self):
        nodes = self.nodes
        user = nodes[0]
        for node in self.enforcing_nodes():
            wait_yed_healthy(node)
            assert_equal(node.yed_getinfo()['mintRequiresArmed'], True)

        print('activate at $50; the layer is UNARMED')
        self.activate(POOLS, quote_usd=50)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        for node in self.enforcing_nodes():
            info, stats = node.yed_getinfo(), node.yed_getstats()
            assert_equal((info['activation']['status'], info['attest']['armed']), ('active', False))
            assert_equal((stats['haltMask'], stats['mintingAllowed'], stats['mintableClasses']), ([], False, []))

        print('mintpol-unarmed: the wallet refuses an unarmed mint (MINTPOL-1, H-1)')
        assert_rpc_error('mintpol-unarmed', user.yed_mint, CENTS, LOCK)

        print('mint-halted-unarmed: a hand-built unarmed mint confirms VOID on every enforcing node (MINT-4)')
        est = user.yed_estimatecollateral(CENTS, LOCK)
        ref, required = int(est['refHeight']), int(est['requiredZat'])
        assert_equal(est['armed'], False)
        fee_addr = user.yed_getfeepayee(ref, required)['default']['payoutAddress']
        hex_, _owner = build_mint_tx(user, CENTS, LOCK, ref, required, fee_addr=fee_addr)
        txid = user.decoderawtransaction(hex_)['txid']
        result, _ = mine_block_raw(nodes[POOLS[0]], [hex_])
        assert result is None, result
        self.sync_all(blocks_only=True)
        for node in self.enforcing_nodes():
            v = node.yed_getvault(txid)
            assert_equal((v['status'], v['voidReason']), ('VOID', 'mint-halted-unarmed'))
            assert_equal(node.yed_gettxinfo(txid)['verdict'], 'mint-halted-unarmed')
            assert_equal(node.yed_getstats()['supplyCents'], 0)
        assert_same_statehash(self.enforcing_nodes(), 'void unarmed mint')

        print('arm the layer: the classes open and a wallet mint with its bundle is ACTIVE')
        self.options.armed = True
        register_and_arm(self)
        self.mine_round_robin(POOLS, REF_LAG)
        for node in self.enforcing_nodes():
            stats = node.yed_getstats()
            assert_equal(node.yed_getinfo()['attest']['armed'], True)
            assert_equal((stats['mintingAllowed'], stats['mintableClasses']), (True, ['A', 'B', 'C']))
        r = self.mint(user, CENTS, LOCK)
        self.mine(POOLS[1])
        minted = r['txid']
        for node in self.enforcing_nodes():
            assert_equal(node.yed_getvault(minted)['status'], 'ACTIVE')
        assert_equal(user.yed_getstats()['supplyCents'], CENTS)
        assert_same_statehash(self.enforcing_nodes(), 'armed mint')
        self.model_check(nodes[2])


if __name__ == '__main__':
    YellowbackMintArmedTest().main()
