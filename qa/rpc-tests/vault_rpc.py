#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The vault primitive's set_* / vault_* RPCs end to end, on three nodes, through the RPCs only
(docs/plans/yellowback-upgrade-plan.md §15.8; doc/vault-rpc.md):

- activation (-nuparams=6d5b7a31:<h>) on a clean chain with the six Ycash upgrades through Canopy
  at height 1, as every Yellowback test on 6.20.0 (YCASH_UPGRADE_ARGS; regtest keeps Equihash
  (48,5) under them), each node mining its own funds first, using `generate` only;
- set_create (3 seats, unlock 2, cancel 1, slash 2, closed) on node 0, which holds the admit key;
  joins from the three nodes (node 0's completes in its own wallet; nodes 1 and 2 collect the
  admit signature with set_signact on node 0 and broadcast with set_sendact), maturity, heartbeats;
- vault_lock; an unlock into an intent via vault_buildunlock + set_signunlock on two nodes +
  vault_send; vault_release refused before the delay and accepted after it;
- a second unlock cancelled by one node (vault_buildcancel + set_signcancel + vault_send), its
  value back in a byte-identical vault; the cancel is built and signed while the intent is still in
  the mempool (finding (50)) and broadcast after it confirms;
- a third unlock whose cancel is accepted as the intent's mempool child, both confirming in one block;
- the owner spend after ownerHeight (selector 2): the owner is a post-quantum (SLH-DSA) key
  (quantum plan §4.3) named to vault_lock as a pqkeyid; until the node wallet holds PQ keys (Q5)
  vault_ownerspend refuses and the test signs with test_framework/pq.py;
- a reorg across a set act (invalidateblock / reconsiderblock on every node): the state hash and
  set_getinfo return to the earlier state and back again, identically on every node;
- restarts: one node restarted as it is, one with its vaults/ directory deleted (rebuilt by the
  start-up replay); both report the same state hash as the others.

    ZCASHD=<ycashd> ../.venv/bin/python -u qa/rpc-tests/vault_rpc.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

import os
import shutil
from decimal import Decimal

from test_framework import vault as vlt
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID,
    assert_equal,
    connect_nodes_bi,
    nuparams,
    start_node,
    start_nodes,
    stop_node,
    sync_blocks,
)
from test_framework.yellowback_util import YCASH_UPGRADE_ARGS

ACTIVATION = 205
DELAY = 5
OWNER = vlt.pq_owner_secret('vault-rpc-owner')        # SLH-DSA (quantum plan §4.3)
OWNER_ID = vlt.pq_owner_of(OWNER).hex()               # pqkeyid: scheme || keyHash


def assert_raises_rpc(substr, fn, *args):
    try:
        fn(*args)
    except JSONRPCException as e:
        assert substr in e.error['message'], 'expected %r in %r' % (substr, e.error['message'])
        return e.error['message']
    raise AssertionError('expected an RPC error containing %r' % substr)


class VaultRpcTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 3
        # 6.20.0: the 200-block cache is built without the Ycash upgrades the harness activates
        # at height 1, so the chain starts clean and each node mines its own funds.
        self.cache_behavior = 'clean'

    def node_args(self):
        return YCASH_UPGRADE_ARGS + [nuparams(VAULT_BRANCH_ID, ACTIVATION), '-debug=vault']

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, extra_args=[self.node_args()] * self.num_nodes)
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 1, 2)
        connect_nodes_bi(self.nodes, 0, 2)
        self.is_network_split = False
        self.sync_all()

    def mine(self, n=1, node=0):
        self.sync_all()
        hashes = self.nodes[node].generate(n)
        self.sync_all()
        return hashes

    def hashes(self):
        return [n.vault_getinfo()['statehash'] for n in self.nodes]

    def assert_consistent(self):
        h = self.hashes()
        assert_equal(len(set(h)), 1)
        tips = [n.vault_getinfo()['dbtip'] for n in self.nodes]
        assert all(t == tips[0] for t in tips), tips
        return h[0]

    @staticmethod
    def members(info):
        """The member list without the per-wallet field."""
        return [{k: v for k, v in m.items() if k != 'wallet'} for m in info['memberlist']]

    def restart(self, i, wipe_vaults=False):
        stop_node(self.nodes[i], i)
        if wipe_vaults:
            shutil.rmtree(os.path.join(self.options.tmpdir, 'node%d' % i, 'regtest', 'vaults'))
        self.nodes[i] = start_node(i, self.options.tmpdir, self.node_args())
        for j in range(self.num_nodes):
            if j != i:
                connect_nodes_bi(self.nodes, i, j)
        sync_blocks(self.nodes)

    def run_test(self):
        n0, n1, n2 = self.nodes

        # ---- activation ----
        info = n0.vault_getinfo()
        assert_equal(info['branchid'], '6d5b7a31')
        assert_equal(info['activationheight'], ACTIVATION)
        assert_equal(info['active'], False)
        assert_raises_rpc('not active', n0.set_create, {'seats': 3, 'unlockthreshold': 2})
        for node in (n1, n2, n0):   # every wallet gets mature transparent coinbases
            self.mine(10, node=self.nodes.index(node))
        self.mine(ACTIVATION - 1 - n0.getblockcount())
        assert_equal(n0.vault_getinfo()['active'], True)
        empty = self.assert_consistent()
        assert_equal(n0.vault_getinfo()['dbtip'], None)
        self.mine(1)
        assert_equal(n0.vault_getinfo()['dbtip']['height'], ACTIVATION)
        assert_equal(self.assert_consistent(), empty)

        # ---- set_create ----
        r = n0.set_create({'seats': 3, 'unlockthreshold': 2, 'cancelthreshold': 1, 'slashthreshold': 2,
                           'maturity': 2, 'livenesswindow': 50, 'bondmin': 1, 'ratewindow': 20})
        setid = r['setid']
        self.mine(1)
        assert_equal([s['setid'] for s in n1.set_list()], [setid])
        info = n2.set_getinfo(setid)
        assert_equal((info['seats'], info['unlockthreshold'], info['cancelthreshold'], info['slashthreshold']), (3, 2, 1, 2))
        assert_equal(info['open'], False)
        assert_equal(info['members'], 0)
        assert_equal(info['dormant'], True)
        assert_equal(info['released'], True)

        # ---- joins ----
        lock = n0.getblockcount() + 500
        j0 = n0.set_join(setid, 1, lock)
        assert_equal(j0['complete'], True)   # node 0 holds the admit key
        assert 'txid' in j0
        keys = [j0['memberkey']]
        for node in (n1, n2):
            j = node.set_join(setid, 1, lock)
            assert_equal(j['complete'], False)
            assert_equal(j['signatures'], 1)
            assert_equal(j['required'], 2)
            assert 'txid' not in j
            # A wallet without the admit key adds nothing.
            same = n2.set_signact(j['hex']) if node is n1 else n1.set_signact(j['hex'])
            assert_equal(same['complete'], False)
            signed = n0.set_signact(j['hex'], setid)
            assert_equal(signed['complete'], True)
            assert_equal(signed['signatures'], 2)
            node.set_sendact(signed['hex'])
            keys.append(j['memberkey'])
        self.mine(1)
        info = n0.set_getinfo(setid)
        assert_equal(info['members'], 3)
        assert_equal(info['active'], 3)
        assert_equal(info['current'], 0)              # maturity 2
        self.mine(2)
        info = n0.set_getinfo(setid)
        assert_equal(info['current'], 3)
        assert_equal(info['dormant'], False)
        assert_equal(sorted(m['key'] for m in info['memberlist']), sorted(keys))
        # Each node's wallet holds exactly its own member key.
        for i, node in enumerate(self.nodes):
            mine = [m['key'] for m in node.set_getinfo(setid)['memberlist'] if m['wallet']]
            assert_equal(mine, [keys[i]])
        # A fourth join exceeds the seats.
        j = n0.set_join(setid, 1, lock)
        assert_equal(j['complete'], False)   # now needs slashthreshold current members
        assert_equal(j['required'], 3)
        signed = n1.set_signact(n0.set_signact(j['hex'])['hex'])
        assert_equal(signed['complete'], True)
        assert_raises_rpc('bad-vault-act-seats', n0.set_sendact, signed['hex'])

        # ---- heartbeats ----
        for node in self.nodes:
            node.set_heartbeat(setid)
        self.mine(1)
        hb = n0.getblockcount()
        info = n1.set_getinfo(setid)
        assert all(m['lastact'] == hb and m['live'] for m in info['memberlist']), info['memberlist']

        # ---- vault_lock ----
        owner_height = n0.getblockcount() + 40
        assert_raises_rpc('ownerkey-removed', n0.vault_lock, {'tag': 'TEST', 'setid': setid, 'delay': DELAY,
                          'ownerheight': owner_height, 'amount': 10, 'ownerkey': '02' + '11' * 32})
        assert_raises_rpc('owner (pqkeyid or PQ address) is required', n0.vault_lock,
                          {'tag': 'TEST', 'setid': setid, 'delay': DELAY, 'ownerheight': owner_height, 'amount': 10})
        lk = n0.vault_lock({'tag': 'TEST', 'setid': setid, 'delay': DELAY, 'ownerheight': owner_height, 'amount': 10,
                            'owner': OWNER_ID})
        assert_equal(lk['owner'], OWNER_ID)
        self.mine(1)
        vaults = n1.vault_list({'kind': 'vault'})
        assert_equal(len(vaults), 1)
        v = vaults[0]
        assert_equal(v['outpoint'], lk['outpoint'])
        assert_equal(v['tagtext'], 'TEST')
        assert_equal(v['value'], Decimal('10'))
        assert_equal(v['owner'], OWNER_ID)
        assert_equal(v['ownerscheme'], 1)
        assert_equal(n0.vault_list({'owner': OWNER_ID})[0]['outpoint'], lk['outpoint'])
        assert_equal(n1.vault_list({'owner': '01' + '00' * 32}), [])
        assert_equal(n0.vault_list({'mine': True}), [])      # the wallet holds no PQ keys yet (Q5)
        assert_equal(n2.set_getinfo(setid)['lockedvalue'], Decimal('10'))
        dec = n2.vault_decodescript(lk['script'])
        assert_equal(dec['type'], 'vault')
        assert_equal(dec['ownerheight'], owner_height)

        # ---- unlock -> intent -> release ----
        addr2 = n2.getnewaddress()
        bu = n0.vault_buildunlock(lk['outpoint'], [{'address': addr2, 'amount': 4}])
        assert_equal(bu['required'], 2)
        s1 = n1.set_signunlock(bu['hex'])
        assert_equal((s1['complete'], s1['signatures']), (False, 1))
        s0 = n0.set_signunlock(bu['hex'])          # independent first signature on node 0
        assert_equal(s0['signatures'], 1)
        s2 = n2.set_signunlock(s1['hex'])
        assert_equal((s2['complete'], s2['signatures']), (True, 2))
        assert_equal(n0.set_signunlock(s2['hex'])['signatures'], 2)   # already complete: unchanged
        assert_raises_rpc('', n0.vault_send, s1['hex'])                # one signature is not enough
        unlock_txid = n0.vault_send(s2['hex'])
        self.mine(1)
        intent_op = '%s:%d' % (unlock_txid, bu['intents'][0]['vout'])
        intents = n0.vault_list({'kind': 'intent'})
        assert_equal([i['outpoint'] for i in intents], [intent_op])
        assert_equal(intents[0]['mature'], False)
        relock = n0.vault_list({'kind': 'vault'})
        assert_equal(len(relock), 1)
        assert_equal(relock[0]['value'], Decimal('6'))
        assert_equal(relock[0]['script'], lk['script'])
        assert_raises_rpc('matures at height', n2.vault_release, intent_op)
        self.mine(DELAY - 1)
        bal = n2.getreceivedbyaddress(addr2)
        n2.vault_release(intent_op)
        self.mine(1)
        assert_equal(n2.getreceivedbyaddress(addr2) - bal, Decimal('4'))
        assert_equal(n0.vault_list({'kind': 'intent'}), [])

        # ---- a second unlock, cancelled by one node ----
        addr1 = n1.getnewaddress()
        bu = n0.vault_buildunlock(relock[0]['outpoint'], [{'address': addr1, 'amount': 2}])
        signed = n1.set_signunlock(n0.set_signunlock(bu['hex'])['hex'])
        assert_equal(signed['complete'], True)
        # sign once (SET_EQUIVOCATION): a different unlock of the same vault is refused by both signers,
        # also after a restart; re-signing the identical transaction is idempotent
        bu_other = n0.vault_buildunlock(relock[0]['outpoint'], [{'address': addr1, 'amount': 3}])
        assert_raises_rpc('set-sign-once', n1.set_signunlock, bu_other['hex'])
        assert_raises_rpc('set-sign-once', n0.set_signunlock, bu_other['hex'])
        assert_equal(n1.set_signunlock(n0.set_signunlock(bu['hex'])['hex'])['hex'], signed['hex'])
        self.restart(1)
        n1 = self.nodes[1]
        assert_raises_rpc('set-sign-once', n1.set_signunlock, bu_other['hex'])
        assert_equal(n1.set_signunlock(n0.set_signunlock(bu['hex'])['hex'])['hex'], signed['hex'])
        assert_raises_rpc('', n1.vault_send, signed['hex'])   # node 1 cannot sign node 0's fee inputs
        txid = n0.vault_send(signed['hex'])
        intent_op = '%s:%d' % (txid, bu['intents'][0]['vout'])
        # Finding (50): a watcher pre-builds and signs the cancel while the intent is in the mempool.
        self.sync_all()
        pre = n2.vault_buildcancel(intent_op)
        assert_equal(pre['intentconfirmed'], False)
        assert_equal(pre['deadline'], n2.getblockcount() + DELAY)    # if the intent confirms in the next block
        assert_equal(pre['required'], 1)
        pre_signed = n2.set_signcancel(pre['hex'])
        assert_equal(pre_signed['complete'], True)
        self.mine(1)
        assert_equal(n2.set_getinfo(setid)['lockedvalue'], Decimal('4'))
        bc = n2.vault_buildcancel(intent_op)
        assert_equal(bc['intentconfirmed'], True)
        assert_equal(bc['deadline'], pre['deadline'])
        assert_equal(bc['cancelsetid'], pre['cancelsetid'])
        assert_equal(bc['required'], 1)
        # The rebuild after confirmation is byte-identical to the mempool build (one sighash to sign);
        # sign once: another cancel of the same intent is refused, re-signing the same one is idempotent.
        assert_equal(bc['hex'], pre['hex'])
        assert_equal(n2.vault_buildcancel(intent_op)['hex'], bc['hex'])
        other = bc['hex'][:-38] + '01000000' + bc['hex'][-30:]               # the same cancel with nLockTime 1: another sighash
        assert other != bc['hex']
        assert_raises_rpc('set-sign-once', n2.set_signcancel, other)
        assert_equal(n2.set_signcancel(bc['hex'])['hex'], pre_signed['hex'])
        # The cancel signed before the intent was mined is still valid after it.
        cancel_txid = n2.vault_send(pre_signed['hex'])
        self.mine(1)
        vaults = sorted(n1.vault_list({'kind': 'vault'}), key=lambda x: x['value'])
        assert_equal([x['value'] for x in vaults], [Decimal('2'), Decimal('4')])
        assert_equal(vaults[0]['outpoint'], cancel_txid + ':0')
        assert all(x['script'] == lk['script'] for x in vaults)
        assert_equal(n0.vault_list({'kind': 'intent'}), [])
        assert_equal(n0.set_getinfo(setid)['lockedvalue'], Decimal('6'))
        assert_raises_rpc('not an unspent intent', n2.vault_release, intent_op)

        # ---- owner spend after ownerHeight ----
        assert_raises_rpc('owner branch opens', n0.vault_ownerspend, vaults[0]['outpoint'], n0.getnewaddress())
        self.mine(owner_height - n0.getblockcount())
        dest = n0.getnewaddress()
        assert_raises_rpc('not yet supported', n0.vault_ownerspend, vaults[0]['outpoint'], dest)
        txid_, n_ = vaults[0]['outpoint'].split(':')
        spk = bytes.fromhex(vaults[0]['script'])
        dest_spk = bytes.fromhex(n0.validateaddress(dest)['scriptPubKey'])
        otx = vlt.build_owner_spend_tx((txid_, int(n_)), spk, int(vaults[0]['valuezat']), OWNER, dest_spk, vlt.SEL_OWNER,
                                     lock_time=owner_height)
        assert_equal(len(otx.vin[0].scriptSig), 7939)
        n0.sendrawtransaction(vlt.tx_hex(otx))
        self.mine(1)
        assert_equal(n0.getreceivedbyaddress(dest), Decimal('2') - Decimal('0.0001'))
        assert_equal(len(n0.vault_list({'kind': 'vault'})), 1)
        assert_equal(n0.set_getinfo(setid)['lockedvalue'], Decimal('4'))

        # ---- a cancel accepted as the mempool child of an unconfirmed intent ----
        # AcceptToMemoryPool counts a mempool parent as confirming in the next block (coinHeight =
        # tip+1, so I-2's h - coinHeight = 0 < delay); both then confirm in one block.
        [v4] = n0.vault_list({'kind': 'vault'})
        bu = n0.vault_buildunlock(v4['outpoint'], [{'address': addr1, 'amount': 1}])
        txid = n0.vault_send(n1.set_signunlock(n0.set_signunlock(bu['hex'])['hex'])['hex'])
        intent_op = '%s:%d' % (txid, bu['intents'][0]['vout'])
        self.sync_all()
        sc = n1.set_signcancel(n1.vault_buildcancel(intent_op)['hex'])
        assert_equal(sc['complete'], True)
        child = n1.vault_send(sc['hex'])
        self.sync_all()
        for node in self.nodes:
            assert_equal(sorted(node.getrawmempool()), sorted([txid, child]))
        [blk] = self.mine(1)
        assert_equal(sorted(n0.getblock(blk)['tx'][1:]), sorted([txid, child]))
        assert_equal(n0.vault_list({'kind': 'intent'}), [])
        assert_equal(sorted(x['value'] for x in n2.vault_list({'kind': 'vault'})), [Decimal('1'), Decimal('3')])
        assert_equal(n0.set_getinfo(setid)['lockedvalue'], Decimal('4'))
        assert_raises_rpc('not an unspent intent', n1.vault_buildcancel, intent_op)

        # ---- a reorg across a set act ----
        before = self.assert_consistent()
        info_before = n0.set_getinfo(setid)
        n1.set_heartbeat(setid)
        [blk] = self.mine(1)
        after = self.assert_consistent()
        assert after != before
        info_after = n0.set_getinfo(setid)
        assert_equal(info_after['height'], info_before['height'] + 1)
        for node in self.nodes:
            node.invalidateblock(blk)
        assert_equal(self.hashes(), [before] * 3)
        for node in self.nodes:
            got = node.set_getinfo(setid, info_before['height'])
            assert_equal(self.members(got), self.members(info_before))
        for node in self.nodes:
            node.reconsiderblock(blk)
        sync_blocks(self.nodes)
        assert_equal(self.hashes(), [after] * 3)
        assert_equal(self.members(n2.set_getinfo(setid, info_after['height'])), self.members(info_after))
        assert self.members(info_after) != self.members(info_before)

        # ---- restarts: reconciliation ----
        self.mine(1)
        state = self.assert_consistent()
        self.restart(1)
        assert_equal(self.assert_consistent(), state)
        self.restart(2, wipe_vaults=True)
        assert_equal(self.assert_consistent(), state)
        with open(os.path.join(self.options.tmpdir, 'node2', 'regtest', 'debug.log'), encoding='utf-8', errors='replace') as f:
            assert 'vault: replaying blocks %d..' % ACTIVATION in f.read()
        assert_equal(n0.vault_getinfo()['dbtip'], self.nodes[2].vault_getinfo()['dbtip'])
        # The rebuilt node keeps validating: one more act and block.
        self.nodes[2].set_heartbeat(setid)
        self.mine(1)
        assert self.assert_consistent() != state
        info = self.nodes[2].vault_getinfo()
        assert_equal((info['sets'], info['vaults'], info['intents']), (1, 2, 0))


if __name__ == '__main__':
    VaultRpcTest().main()
