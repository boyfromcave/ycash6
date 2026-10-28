#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
A mint and a YED transfer that spends its token, disconnected and reconnected together, then
restarts (cf. DigiByte v9.26.7 cfc01a24b4, its transfer-ancestor reorg wallet test, and the
saved-totals checks of 19c8b1c272):

  - mint M (the two-step wallet mint; its block b1), then T = yed_send of part of M's token to the
    observer (its block b2);
  - mint_and_transfer_disconnected: every node invalidates b1, so M and T leave the chain together:
    the YED state hash, yed_getstats, the owner's positions and both wallets' confirmed YED are what
    they were before M confirmed, on every node;
  - reconnected_together: every node reconsiders b1, so b1 and b2 reconnect in one reorg: every node
    is back at exactly the state it recorded after T;
  - startup_totals_match: a clean restart (user, observer, a pool), a kill -9 restart and a
    -reindex-yellowback rebuild (a pool) each come back with the same yed_getstats (the saved
    totals: supply, collateral, vault counts) and the same state hash as before, so the totals the
    index saved agree with a recount from the records and the blocks;
  - different_branch: b1 is invalidated again and the pools mine a different branch from the
    mempool; M confirms again, T confirms after it (re-sent by the wallet when the reorg dropped it),
    and the positions and balances are the same as on the first branch, one state hash everywhere;
  - the Python model over the whole chain at the end.

Nodes: 0 user, 1 stock, 2-4 pools, 5 observer.
"""

from test_framework.util import (
    assert_equal,
    sync_blocks,
    sync_mempools,
)
from test_framework.yellowback_util import (
    ENFORCING,
    OBSERVER,
    POOLS,
    REF_LAG,
    USER,
    YellowbackTestFramework,
    assert_best_hash,
    assert_same_statehash,
    wait_yed_healthy,
)
from test_framework.yellowback_attest import ArmedModeMixin

YB = ENFORCING + [OBSERVER]
SENT = 2500


def position_rows(node):
    return sorted((p['txid'], p['status'], p['mintedCents'], p['collateralZat'], p['refHeight'], p['lockHeight'])
                  for p in node.yed_listpositions())


def coin_rows(node):
    return sorted(c['cents'] for c in node.yed_listunspent())


def stats_without_height(stats):
    return {k: v for k, v in stats.items() if k != 'height'}


# Rule: UNDO XFER-1
class YellowbackReorgRestartTest(ArmedModeMixin, YellowbackTestFramework):

    def sync_all(self, blocks_only=False):
        """Blocks everywhere; mempools among the YED nodes only: the stock node keeps a transfer the
        module drops while its parent mint is unconfirmed."""
        for g in self.groups():
            sync_blocks([self.nodes[i] for i in g if self.nodes[i] is not None])
            if not blocks_only:
                sync_mempools([self.nodes[i] for i in g if self.nodes[i] is not None and i in YB])

    def ledger(self, i):
        n = self.nodes[i]
        wait_yed_healthy(n, timeout=120)
        row = {'tip': n.getbestblockhash(), 'statehash': n.yed_getstatehash()['statehash'], 'stats': n.yed_getstats()}
        if i in (USER, OBSERVER):
            row['confirmedCents'] = n.yed_getbalance()['confirmedCents']
            row['positions'] = position_rows(n)
            row['coins'] = coin_rows(n)
        return row

    def ledgers(self):
        sync_blocks(self.nodes)
        rows = {i: self.ledger(i) for i in YB}
        assert_best_hash(self.nodes)
        assert_same_statehash([self.nodes[i] for i in YB])
        stats = [rows[i]['stats'] for i in YB]
        assert_equal(stats, [stats[0]] * len(stats))
        return rows

    def run_test(self):
        nodes = self.nodes
        user, observer = nodes[USER], nodes[OBSERVER]

        print('activate at $50 and fill the price windows')
        self.activate(POOLS, quote_usd=50)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        self.arm()

# Rule: MINT-1 XFER-1 XFER-2
        print('mint M, then T: a YED transfer spending M\'s token')
        mint = self.mint(user, 10000, 48)              # the carrier's block is mined; M waits in the mempool
        self.sync_all()
        pre = self.ledgers()
        assert_equal(pre[USER]['confirmedCents'], 0)
        b1 = self.mine(POOLS[1])[0]
        assert_equal(user.yed_getvault(mint['txid'])['status'], 'ACTIVE')
        sent = user.yed_send(observer.yed_getnewaddress(), SENT)
        raw = user.getrawtransaction(sent['txid'], 1)
        assert (mint['txid'], 1) in [(v['txid'], v['vout']) for v in raw['vin']], 'T does not spend M\'s token'
        self.sync_all()
        b2 = self.mine(POOLS[2])[0]
        post = self.ledgers()
        assert_equal(post[USER]['confirmedCents'], 10000 - SENT)
        assert_equal(post[OBSERVER]['confirmedCents'], SENT)
        assert_equal([r[0] for r in post[USER]['positions']], [mint['txid']])
        assert_equal(post[2]['stats']['supplyCents'], 10000)
        self.checkpoint('after T')

# Rule: UNDO
        print('mint_and_transfer_disconnected: every node invalidates b1; M and T leave the chain together')
        for n in nodes:
            n.invalidateblock(b1)
        now = self.ledgers()
        for i in YB:
            assert_equal(now[i], pre[i])                           # exactly the state before M confirmed
        for i in YB:
            assert 'vault-not-found' in str(self.rpc_error(nodes[i].yed_getvault, mint['txid']))
        assert mint['txid'] in user.getrawmempool()               # M is back in the mempool
        t_in_pool = sent['txid'] in user.getrawmempool()
        print('  T after the disconnect: %s' % ('in the mempool' if t_in_pool else 'dropped from the mempool'))

# Rule: UNDO
        print('reconnected_together: every node reconsiders b1; b1 and b2 reconnect in one reorg')
        for n in nodes:
            n.reconsiderblock(b1)
        now = self.ledgers()
        for i in YB:
            assert_equal(now[i], post[i])
        assert_equal(user.getblock(b2)['confirmations'], 1)
        for i in YB:
            pool = nodes[i].getrawmempool()
            assert mint['txid'] not in pool and sent['txid'] not in pool
        self.checkpoint('reconnected')

        print('startup_totals_match: restarts compare yed_getstats and the state hash with what was saved')
        for i in (USER, OBSERVER, POOLS[0]):
            self.restart(i)
        now = self.ledgers()
        for i in YB:
            assert_equal(now[i], post[i])
        self.kill9(POOLS[1])                                      # nothing flushed: the undo walk / replay runs
        self.restart(POOLS[1])
        now = self.ledgers()
        assert_equal(now[POOLS[1]], post[POOLS[1]])
        self.restart(POOLS[2], ['-reindex-yellowback'])            # the totals recounted from the blocks
        wait_yed_healthy(nodes[POOLS[2]], timeout=180)
        now = self.ledgers()
        assert_equal(now[POOLS[2]], post[POOLS[2]])
        self.restart(POOLS[2])
        self.checkpoint('after the restarts')

# Rule: UNDO MINT-2
        print('different_branch: b1 is invalidated again; the pools mine M and T on a new branch')
        for n in nodes:
            n.invalidateblock(b1)
        now = self.ledgers()
        for i in YB:
            assert_equal(now[i], pre[i])
        refresh = getattr(self, 'refresh_peer_views', None)
        if refresh is not None:
            refresh()                                             # 6.20.0: peers still point at the invalid branch
        assert mint['txid'] in user.getrawmempool()
        self.sync_all()
        nb1 = self.mine(POOLS[0])[0]
        assert nb1 != b1
        assert mint['txid'] in [t if isinstance(t, str) else t['txid'] for t in user.getblock(nb1)['tx']]
        assert_equal(user.yed_getvault(mint['txid'])['status'], 'ACTIVE')
        assert_equal(nodes[2].yed_getstats()['supplyCents'], 10000)
        if user.gettransaction(sent['txid'])['confirmations'] < 1 and sent['txid'] not in user.getrawmempool():
            # The module dropped T while M was unconfirmed (its input was no YED coin of the index yet).
            # The owner's position and the index agree meanwhile; a restart re-accepts the wallet's T.
            print('  T was dropped with its parent; M confirmed alone; the wallet re-accepts T at a restart')
            assert_equal([r[0] for r in position_rows(user) if r[1] == 'ACTIVE'], [mint['txid']])
            self.restart(USER)
            wait_yed_healthy(user, timeout=120)
            assert sent['txid'] in user.getrawmempool(), 'the wallet did not re-accept T after M confirmed'
        self.sync_all()
        if user.gettransaction(sent['txid'])['confirmations'] < 1:
            self.mine(POOLS[1])
        assert_equal(user.gettransaction(sent['txid'])['confirmations'] >= 1, True)
        now = self.ledgers()
        for i in (USER, OBSERVER):
            for k in ('confirmedCents', 'positions', 'coins'):
                assert_equal(now[i][k], post[i][k])
        for i in YB:
            assert_equal(stats_without_height(now[i]['stats']), stats_without_height(post[i]['stats']))
        self.checkpoint('on the new branch')
        for i in (USER, OBSERVER):
            self.restart(i)
        later = self.ledgers()
        for i in YB:
            assert_equal(later[i], now[i])

        print('the Python model over the whole chain')
        self.model_check(nodes[2])
        self.model_check(observer)

    def rpc_error(self, fn, *args):
        try:
            fn(*args)
        except Exception as e:
            err = getattr(e, 'error', None)
            return str(err.get('message', '')) if isinstance(err, dict) else str(e)
        raise AssertionError('expected an RPC error from %r%r' % (fn, args))


if __name__ == '__main__':
    YellowbackReorgRestartTest().main()
