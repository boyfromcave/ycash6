#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
A reorg across the UPGRADE_VAULT activation block itself, with vault and YED state on the chain
(cf. DigiByte v9.26.7's thaw-day node-matrix and reference-reorg functional tests, which rewind a
follower below the activation height):

  - the standard setup activates the vault upgrade at VAULT_ACTIVATION, creates the YED attestor set
    in the block after it, fills the price windows, and the user mints a vault;
  - every node invalidates block VAULT_ACTIVATION - 1, so the tip is two blocks below the activation
    and the next block is a pre-Vault one: the vault database and the YED index are back to the
    empty pre-activation state on every node (no set, no vault, no supply, one state hash);
  - the stock node mines a different branch across the activation (a different activation block),
    a new signer set is created there, and the nodes agree on the new state (vault database, YED);
  - every node reconsiders the old branch, which has more work: the reorg crosses the activation
    the other way and every node is back at exactly the state it recorded before (YED state hash,
    vault-database state hash, yed_getstats, the user's position), and the vault redeems;
  - the Python model over the whole chain at the end.

Nodes: 0 user, 1 stock, 2-4 pools, 5 observer.
"""

import time

from test_framework.util import (
    assert_equal,
    assert_greater_than,
    sync_blocks,
)
from test_framework.yellowback_util import (
    ENFORCING,
    OBSERVER,
    POOLS,
    REF_LAG,
    STOCK,
    USER,
    ATTESTOR_SET_SPEC,
    VAULT_ACTIVATION,
    YellowbackTestFramework,
    assert_best_hash,
    assert_same_statehash,
)
from test_framework.yellowback_attest import ArmedModeMixin

YB = ENFORCING + [OBSERVER]          # the nodes the YED module runs on (node 1 has no attestor set)


def rpc_error(fn, *args):
    try:
        fn(*args)
    except Exception as e:
        err = getattr(e, 'error', None)
        return str(err.get('message', '')) if isinstance(err, dict) else str(e)
    raise AssertionError('expected an RPC error from %r%r' % (fn, args))


def wait_healthy(node, timeout=60):
    """yed_getinfo().healthy, below the start height as well (wait_yed_healthy also wants the index height)."""
    deadline = time.time() + timeout
    while True:
        info = node.yed_getinfo()
        if info['healthy']:
            return info
        assert time.time() < deadline, 'index not healthy within %ds: %r' % (timeout, info)
        time.sleep(0.1)


def vault_db(node):
    info = node.vault_getinfo()
    return {k: info[k] for k in ('dbtip', 'sets', 'vaults', 'intents', 'lockedvalue', 'statehash')}


def position_rows(node):
    return sorted((p['txid'], p['status'], p['mintedCents'], p['collateralZat'], p['refHeight'], p['lockHeight'])
                  for p in node.yed_listpositions())


# Rule: UNDO SNAP
class YellowbackActivationReorgTest(ArmedModeMixin, YellowbackTestFramework):

    def snapshot(self, i):
        n = self.nodes[i]
        wait_healthy(n)
        return {'tip': n.getbestblockhash(), 'statehash': n.yed_getstatehash()['statehash'],
                'stats': n.yed_getstats(), 'vaultdb': vault_db(n)}

    def assert_agree(self, label):
        """One tip, one YED state hash and one vault-database state on every YED node."""
        nodes = [self.nodes[i] for i in YB]
        sync_blocks(self.nodes)
        for n in nodes:
            wait_healthy(n)
        assert_best_hash(self.nodes, label)
        assert_same_statehash(nodes, label)
        dbs = [vault_db(n) for n in nodes]
        assert_equal(dbs, [dbs[0]] * len(dbs), 'vault databases differ %s' % label)
        stats = [n.yed_getstats() for n in nodes]
        assert_equal(stats, [stats[0]] * len(stats), 'yed_getstats differ %s' % label)
        return dbs[0], stats[0]

    def run_test(self):
        nodes = self.nodes
        user, stock = nodes[USER], nodes[STOCK]
        setid = self.attestor_set
        set_tx = user.gettransaction(setid)
        set_height = user.getblock(set_tx['blockhash'])['height']
        assert_greater_than(set_height, VAULT_ACTIVATION - 1)       # the set is created at or after the activation
        old_activation_block = user.getblockhash(VAULT_ACTIVATION)

        print('activate at $50, mint a vault above the activation')
        self.activate(POOLS, quote_usd=50)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        self.arm()
        mint = self.mint(user, 10000, 48)
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(user.yed_getvault(mint['txid'])['status'], 'ACTIVE')
        assert_equal(nodes[2].yed_getstats()['supplyCents'], 10000)
        self.checkpoint('the mint')
        before = {i: self.snapshot(i) for i in YB}
        before_positions = position_rows(user)
        assert_equal(len(before_positions), 1)
        old_tip = user.getbestblockhash()
        old_height = user.getblockcount()
        for i in YB:
            assert_equal(before[i]['vaultdb']['sets'], 1)

# Rule: UNDO
        print('below_activation: every node invalidates block %d; the tip is %d, the next block pre-Vault'
              % (VAULT_ACTIVATION - 1, VAULT_ACTIVATION - 2))
        fork = user.getblockhash(VAULT_ACTIVATION - 1)
        for n in nodes:
            n.invalidateblock(fork)
        for n in nodes:
            assert_equal(n.getblockcount(), VAULT_ACTIVATION - 2)
        for i in YB:
            n = nodes[i]
            info = n.vault_getinfo()
            assert_equal(info['active'], False)                       # the next block is below the activation
            assert_equal((info['sets'], info['vaults'], info['intents']), (0, 0, 0))
            assert 'unknown set' in rpc_error(n.set_getinfo, setid)
            stats = n.yed_getstats()
            assert_equal((stats['supplyCents'], stats['activeVaults'], stats['collateralZat']), (0, 0, 0))
            assert 'vault-not-found' in rpc_error(n.yed_getvault, mint['txid'])
            assert mint['txid'] not in n.getrawmempool()               # signed for the Vault branch: evicted
            assert setid not in n.getrawmempool()
        assert_equal(position_rows(user), [])
        assert_equal(user.yed_getbalance()['confirmedCents'], 0)
        self.assert_agree('below the activation')

        # No restart here: on ycash-dd (not ycash6) a node restarted while it holds the invalidated branch
        # across the activation aborts in CheckBlockIndex (-checkblockindex, "nNodes == forward.size()")
        # after the stock RewindBlockIndex; reported with the DigiByte v9.26.7 review, not worked around.

# Rule: UNDO SNAP
        print('new_branch_across_activation: the stock node mines a different activation block; a new set is created on it')
        refresh = getattr(self, 'refresh_peer_views', None)
        if refresh is not None:
            refresh()                                                 # 6.20.0: peers still point at the invalid branch
        stock.generate(2)
        sync_blocks(nodes)
        assert_equal(user.getblockcount(), VAULT_ACTIVATION)
        assert user.getblockhash(VAULT_ACTIVATION) != old_activation_block
        assert_equal(user.vault_getinfo()['active'], True)            # the next block is a Vault one
        # A fresh SET_CREATE, not the old one re-sent: re-sending the old one was not deterministic (on ycash6
        # CI it was not mined and the wallet reported it at confirmations -1).
        # The YED module stays inert on this branch (its attestor set is the old one); the vault database
        # records the new set on every node.
        new_set = user.set_create(dict(ATTESTOR_SET_SPEC))['setid']
        assert new_set != setid
        self.sync_all()
        self.mine(POOLS[0])
        self.mine_round_robin(POOLS, 6)
        db, stats = self.assert_agree('on the new branch')
        assert_equal((db['vaults'], db['intents']), (0, 0))
        assert_equal((stats['supplyCents'], stats['activeVaults']), (0, 0))
        for i in YB:
            nodes[i].set_getinfo(new_set)
            assert 'vault-not-found' in rpc_error(nodes[i].yed_getvault, mint['txid'])
        assert_equal(position_rows(user), [])
        new_tip = user.getbestblockhash()
        assert_greater_than(old_height, user.getblockcount())        # the old branch still has more work

# Rule: UNDO
        print('back_across_activation: every node reconsiders the old branch; the state is the one recorded before')
        for n in nodes:
            n.reconsiderblock(fork)
        sync_blocks(nodes)
        for n in nodes:
            assert_equal(n.getbestblockhash(), old_tip)
            assert n.getblock(new_tip)['confirmations'] < 0
        for i in YB:
            assert_equal(self.snapshot(i), before[i])
        assert_equal(position_rows(user), before_positions)
        assert_equal(user.yed_getvault(mint['txid'])['status'], 'ACTIVE')
        self.checkpoint('back on the old branch')

        print('  the restored vault redeems; the model over the whole chain')
        redeemed = user.yed_redeem(mint['txid'])
        assert_equal(redeemed['burnedCents'], 10000)
        self.sync_all()
        self.mine(POOLS[2])
        assert_equal(nodes[2].yed_getvault(mint['txid'])['status'], 'CLOSED')
        self.checkpoint('after the redeem')
        self.model_check(nodes[2])


if __name__ == '__main__':
    YellowbackActivationReorgTest().main()
