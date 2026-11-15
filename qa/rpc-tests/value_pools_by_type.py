#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The chain's transparent value pools by address type (beta3 item 2; workspace docs/plans/beta3/value-pools.md §5):
the `transparentPools` field of getblock and getblockchaininfo, on both node lines (this script is byte-identical
on ycash-dd and ycash6, qa/yellowback-cross-line.manifest).

Two nodes on regtest with -nuparams=6d5b7a31:200 (test_framework/vault_harness.py). The scenario creates and spends
every class: P2PKH (the wallet), P2SH, TX_PQPKH in both schemes (scheme 1 spent with an SLH-DSA signature), a hybrid
PQ channel (spent by its refund path), a YED-tagged vault (APP into a YED-tagged intent, then RELEASE), a vault under
another tag, and OP_RETURN with value. The YED-tagged templates are made with the primitive's builders, as vault_pq.py
does, without the Yellowback overlay: the index classifies scripts, so `yed_*` state is not needed to reach these
classes (the collateralZat relation, note §1.2, is therefore not observed here).

Every check is against the test's own model, which classifies each output by the node's scriptPubKey "type"
(Solver) and its template tag, reads spent outputs from the blocks it has already seen, and keeps running totals:

1. sum, at every height (getblock h 1): the five pools sum to "transparent", pq_by_scheme sums to transparent_pq,
   vault_by_module's YED row is the YED-tagged part of vault plus vault_intent, every value is >= 0, every entry
   equals the model, and each valueDelta is the record minus the parent's record;
2. the old figures: valuePools keeps its ids, order and entry fields (and, where the line has a transparent entry,
   "transparent" equals it at every height); at the tip, "transparent" equals gettxoutsetinfo's total_amount plus
   the unspendable outputs (OP_RETURN, genesis);
3. vault cross-check at the tip: "vault" equals vault_getinfo.lockedvalue, exactly;
4. reorg: invalidateblock on a block that spends a vault and creates PQ outputs gives the parent's figures,
   reconsiderblock restores them, and a competing fork with a different spend set gives that fork's figures;
5. restart, fill and reindex: a restart, a restart with blocks/valuepools deleted (the startup fill: the migration
   test, no old binary needed) and -reindex each give identical records at every height;
6. a node without the undo data (a pruned node, simulated by moving the undo file aside; -checklevel=1 so the
   block-database check does not read it): "monitored": false and the log line, then the fill once the data is back.

    ZCASHD=<ycashd> (BITCOIND=<ycashd> on v4.5.0) .venv/bin/python -u qa/rpc-tests/value_pools_by_type.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

import os
import shutil
import time
from decimal import Decimal

from test_framework.util import assert_equal, connect_nodes_bi, start_node, stop_node, sync_blocks
from test_framework import pq
from test_framework import vault as v
from test_framework import yellowback_model as ym
from test_framework.vault_harness import COIN, FEE, OWNER, OWNER_KEY, VaultTestBase

POOL_IDS = ['transparent_ecc', 'transparent_pq', 'pq_channel', 'vault', 'vault_intent']
ENTRY_KEYS = ['monitored', 'chainValue', 'chainValueZat']
DELTA_KEYS = ['valueDelta', 'valueDeltaZat']
YED_TAG_HEX = '59454400'
P2SH_REDEEM = bytes([0x51])  # OP_TRUE


def zat(x):
    return int(Decimal(x) * 100000000)


def p2sh_spk(redeem):
    return bytes([0xa9, 0x14]) + v.hash160(redeem) + bytes([0x87])


class Totals(object):
    """The model: running totals by class, from the blocks of one chain."""

    KEYS = ['transparent', 'transparent_ecc', 'transparent_pq', 'pq1', 'pq2', 'pq_channel', 'vault', 'vault_intent',
            'yed', 'unspendable']

    def __init__(self, other=None):
        self.t = dict(other.t) if other else {k: 0 for k in self.KEYS}

    def add(self, out, sign, unspendable=False):
        value = out['valueZat'] * sign
        spk = out['scriptPubKey']
        typ, hex_ = spk.get('type', 'nonstandard'), spk['hex']
        self.t['transparent'] += value
        if typ == 'pqpubkeyhash':
            self.t['transparent_pq'] += value
            self.t['pq%d' % (int(hex_[66:68], 16) - 0x50)] += value
        elif typ == 'pqchannel':
            self.t['pq_channel'] += value
        elif typ in ('vault', 'vaultintent'):
            self.t['vault' if typ == 'vault' else 'vault_intent'] += value
            if hex_.startswith('04' + YED_TAG_HEX):
                self.t['yed'] += value
        else:
            self.t['transparent_ecc'] += value
        if unspendable or typ == 'nulldata':
            self.t['unspendable'] += value


class ValuePoolsByTypeTest(VaultTestBase):

    def __init__(self):
        super().__init__()
        self.blocks = {}   # block hash -> getblock(hash, 2)
        self.outs = {}     # txid -> {n: vout}

    # ------------------------------------------------------------------ the model

    def block2(self, node, bh):
        if bh not in self.blocks:
            self.blocks[bh] = node.getblock(bh, 2)
            for tx in self.blocks[bh]['tx']:
                self.outs[tx['txid']] = {o['n']: o for o in tx['vout']}
        return self.blocks[bh]

    def model_table(self, node):
        """{height: (hash, Totals after the block)} along node's active chain."""
        table, totals = {}, Totals()
        for h in range(node.getblockcount() + 1):
            bh = node.getblockhash(h)
            blk = self.block2(node, bh)
            for tx in blk['tx']:
                for i in tx['vin']:
                    if 'coinbase' not in i:
                        totals.add(self.outs[i['txid']][i['vout']], -1)
                for o in tx['vout']:
                    totals.add(o, +1, unspendable=(h == 0))
            table[h] = (bh, Totals(totals))
        return table

    def record_table(self, node):
        """{height: transparentPools of getblock} along node's active chain."""
        return {h: node.getblock(node.getblockhash(h))['transparentPools'] for h in range(node.getblockcount() + 1)}

    # ------------------------------------------------------------------ checks

    def check_entry(self, e, value, delta, keys_before):
        assert_equal(list(e.keys()), keys_before + ENTRY_KEYS + (DELTA_KEYS if delta is not None else []))
        assert_equal(e['monitored'], True)
        assert_equal(e['chainValueZat'], value)
        assert_equal(e['chainValue'], Decimal(value) / 100000000)
        assert e['chainValueZat'] >= 0, e
        if delta is not None:
            assert_equal(e['valueDeltaZat'], delta)
            assert_equal(e['valueDelta'], Decimal(delta) / 100000000)

    def check_pools(self, tp, t, parent):
        """One transparentPools object against the model's totals `t` (and `parent` for the deltas, or None)."""
        def d(key):
            return None if parent is None else t.t[key] - parent.t[key]
        assert_equal(list(tp.keys()), ['monitored', 'transparent', 'pools', 'pq_by_scheme', 'vault_by_module'])
        assert_equal(tp['monitored'], True)
        self.check_entry(tp['transparent'], t.t['transparent'], d('transparent'), [])
        assert_equal([p['id'] for p in tp['pools']], POOL_IDS)
        for p in tp['pools']:
            self.check_entry(p, t.t[p['id']], d(p['id']), ['id'])
        assert_equal(sum(p['chainValueZat'] for p in tp['pools']), tp['transparent']['chainValueZat'])
        if parent is not None:
            assert_equal(sum(p['valueDeltaZat'] for p in tp['pools']), tp['transparent']['valueDeltaZat'])
        assert_equal([(s['pqscheme'], s['pqschemename']) for s in tp['pq_by_scheme']],
                     [(1, 'SLH-DSA-SHA2-128s'), (2, 'FN-DSA-512')])
        for s in tp['pq_by_scheme']:
            self.check_entry(s, t.t['pq%d' % s['pqscheme']], d('pq%d' % s['pqscheme']), ['pqscheme', 'pqschemename'])
        assert_equal(sum(s['chainValueZat'] for s in tp['pq_by_scheme']), tp['pools'][1]['chainValueZat'])
        assert_equal([(m['module'], m['tag']) for m in tp['vault_by_module']], [('YED', YED_TAG_HEX)])
        self.check_entry(tp['vault_by_module'][0], t.t['yed'], d('yed'), ['module', 'tag'])

    def check_value_pools(self, vp, transparent_zat):
        """valuePools as before this change: the line's ids in its order, the fields of ValuePoolDesc."""
        ids = [p['id'] for p in vp]
        assert ids in (['sprout', 'sapling'], ['transparent', 'sprout', 'sapling', 'orchard']), ids
        for p in vp:
            keys = list(p.keys())
            assert keys in (['id', 'monitored'], ['id', 'monitored'] + ENTRY_KEYS[1:],
                            ['id', 'monitored'] + ENTRY_KEYS[1:] + DELTA_KEYS), keys
        if ids[0] == 'transparent':
            assert_equal(vp[0]['chainValueZat'], transparent_zat)

    def check_chain(self, node, label):
        """Checks 1-3 at every height of node's active chain."""
        table = self.model_table(node)
        prev = None
        for h in sorted(table):
            bh, t = table[h]
            b = node.getblock(bh)
            self.check_pools(b['transparentPools'], t, prev if prev is not None else Totals())
            self.check_value_pools(b['valuePools'], t.t['transparent'])
            prev = t
        tip_t = table[max(table)][1]
        info = node.getblockchaininfo()
        self.check_pools(info['transparentPools'], tip_t, None)
        self.check_value_pools(info['valuePools'], tip_t.t['transparent'])
        utxo = zat(node.gettxoutsetinfo()['total_amount'])
        assert_equal(utxo + tip_t.t['unspendable'], tip_t.t['transparent'])
        assert_equal(zat(node.vault_getinfo()['lockedvalue']), tip_t.t['vault'])
        print('    ok   %s: %d heights, transparent %d zat (ecc %d, pq %d+%d, channel %d, vault %d, intent %d, YED %d)' % (
            label, len(table), tip_t.t['transparent'], tip_t.t['transparent_ecc'], tip_t.t['pq1'], tip_t.t['pq2'],
            tip_t.t['pq_channel'], tip_t.t['vault'], tip_t.t['vault_intent'], tip_t.t['yed']))
        return table

    # ------------------------------------------------------------------ restarts

    def debug_log(self, i=0):
        with open(os.path.join(self.datadir(i), 'debug.log'), encoding='utf-8', errors='replace') as f:
            return f.read()

    def restart0(self, extra=(), wipe_index=False, before_start=None, wait_sync=True):
        stop_node(self.nodes[0], 0)
        if wipe_index:
            path = os.path.join(self.datadir(0), 'blocks', 'valuepools')
            assert os.path.isdir(path), 'no value pools index at %s' % path
            shutil.rmtree(path)
        if before_start:
            before_start()
        # a fresh debug.log per start, so a log check sees this start only
        os.rename(os.path.join(self.datadir(0), 'debug.log'), os.path.join(self.datadir(0), 'debug.log.%d' % time.time()))
        self.nodes[0] = start_node(0, self.options.tmpdir, self.node_args(0) + list(extra))
        connect_nodes_bi(self.nodes, 0, 1)
        if wait_sync:
            deadline = time.time() + 120
            while self.nodes[0].getbestblockhash() != self.nodes[1].getbestblockhash():
                assert time.time() < deadline, 'node 0 did not resync after restart'
                time.sleep(0.25)

    # ------------------------------------------------------------------ scenario

    def run_test(self):
        self.start_vault(coins=30)
        self.check_chain(self.node, 'before any new class')
        self.section_classes()
        self.section_reorg()
        self.section_restart()
        self.section_pruned()
        self.check_chain(self.nodes[1], 'node 1')
        print('value_pools_by_type OK')

    def section_classes(self):
        print('A. create and spend every class')
        # A set for the vault templates (as vault_pq.py).
        self.sid, admit = self.create_set('P', seats=1, unlock_threshold=1, cancel_threshold=1, slash_threshold=1,
                                          liveness_window=1000, maturity=2)
        member = v.fixed_secret('P-member')
        self.join(self.sid, member, [admit], 'JOIN P')
        self.mine(3)
        self.heartbeat(self.sid, [member], 'HEARTBEAT P')
        self.mine()

        pk = bytes(OWNER)[32:64]
        self.pq1_spk = pq.pqpkh_script_of(pq.SCHEME_SLH_DSA_SHA2_128S, pk)
        self.pq2_spk = pq.pqpkh_script(pq.SCHEME_FN_DSA_512, v.sha256(b'value-pools-pq2'))
        self.refund_height = self.tip() + 6
        self.chan_spk = ym.pqchannel_script(OWNER_KEY, v.pubkey_of(v.fixed_secret('value-pools-server')), self.refund_height)
        opret = bytes([0x6a, 0x04]) + b'pool'
        fund = self.accept(self.wallet_tx_hex([(COIN, self.pq1_spk), (COIN, self.pq2_spk), (COIN, self.chan_spk),
                                                (COIN, p2sh_spk(P2SH_REDEEM)), (COIN // 10, opret)]),
                           'pay TX_PQPKH (both schemes), a channel, P2SH and OP_RETURN with value')
        types = [o['scriptPubKey']['type'] for o in self.node.getrawtransaction(fund, 1)['vout'][:5]]
        assert_equal(types, ['pqpubkeyhash', 'pqpubkeyhash', 'pqchannel', 'scripthash', 'nulldata'])
        self.vpY = self.vparams(self.sid, owner_height=self.tip() + 400, app_height=self.tip() + 3, tag=b'YED\x00')
        self.vpY2 = self.vparams(self.sid, owner_height=self.tip() + 400, app_height=self.tip() + 3, tag=b'YED\x00', delay=7)
        self.vpT = self.vparams(self.sid, owner_height=self.tip() + 400)
        self.vY = self.lock(self.vpY, 2 * COIN, 'lock a YED-tagged V')
        self.vY2 = self.lock(self.vpY2, 2 * COIN, 'lock a second YED-tagged V (spent in the reorg section)')
        self.vT = self.lock(self.vpT, 3 * COIN, 'lock a V under the tag TEST')
        self.mine()
        self.check_chain(self.node, 'every class created')

        self.mine_to(max(self.vpY.app_height, self.refund_height))
        # APP: the YED V into a YED-tagged intent
        rspk = self.change_spk()
        fee_vin, change = v.node_fee_inputs(self.node)
        app = v.build_app_tx(self.vY, self.vpY, 2 * COIN, [(rspk, 2 * COIN)], fee_vin, change)
        app_txid = self.accept(v.node_sign(self.node, app, app.vin[0].scriptSig), 'APP: the YED V into an intent')
        self.ip = v.intent_for(self.vpY, rspk)
        self.rspk = rspk
        # TX_PQPKH scheme 1, spent with SLH-DSA
        tx = v.make_tx([(fund, 0, v.SEQUENCE_FINAL)], [(COIN - FEE, self.change_spk())])
        tx.vin[0].scriptSig = pq.pq_scriptsig_from_pushes(
            pq.pq_sign_input(tx, 0, self.pq1_spk, COIN, v.VAULT_BRANCH_ID, OWNER))
        self.accept(v.tx_hex(tx), 'spend the scheme-1 TX_PQPKH output')
        # the channel, by its refund path (the client alone after refundHeight)
        tx = v.make_tx([(fund, 2, v.SEQUENCE_FINAL - 1)], [(COIN - FEE, self.change_spk())], lock_time=self.refund_height)
        tx.vin[0].scriptSig = pq.pq_scriptsig_from_pushes(
            pq.pq_sign_input(tx, 0, self.chan_spk, COIN, v.VAULT_BRANCH_ID, OWNER), extra=bytes([0x00]))
        self.accept(v.tx_hex(tx), 'spend the channel by its refund path')
        # P2SH (redeem script OP_TRUE)
        tx = v.make_tx([(fund, 3, v.SEQUENCE_FINAL)], [(COIN - FEE, self.change_spk())])
        tx.vin[0].scriptSig = bytes([len(P2SH_REDEEM)]) + P2SH_REDEEM
        self.accept(v.tx_hex(tx), 'spend the P2SH output')
        self.mine()
        self.mine(self.vpY.delay)
        self.accept(self.release_hex((app_txid, 0), self.ip, 2 * COIN, rspk), 'RELEASE the YED intent')
        self.mine()
        self.check_chain(self.node, 'every class spent')

    def section_reorg(self):
        print('B. reorg: invalidate, reconsider, a competing fork')
        rspk = self.change_spk()
        fee_vin, change = v.node_fee_inputs(self.node)
        app = v.build_app_tx(self.vY2, self.vpY2, 2 * COIN, [(rspk, 2 * COIN)], fee_vin, change)
        app_hex = v.node_sign(self.node, app, app.vin[0].scriptSig)
        self.lock_inputs(app_hex)
        pq_hex = self.wallet_tx_hex([(COIN, self.pq1_spk), (2 * COIN, self.pq2_spk)])
        self.lock_inputs(pq_hex)
        parent = self.node.getbestblockhash()
        b = self.mine_raw([app_hex, pq_hex], 'a block that spends a vault and creates PQ outputs')
        tp_parent = self.node.getblock(parent)['transparentPools']
        tp_b = self.node.getblock(b)['transparentPools']
        assert_equal(tp_b['pools'][3]['valueDeltaZat'], -2 * COIN)
        assert_equal(tp_b['pools'][4]['valueDeltaZat'], 2 * COIN)
        assert_equal(tp_b['pools'][1]['valueDeltaZat'], 3 * COIN)
        self.check_chain(self.node, 'with the block')

        def strip(tp):
            out = dict(tp)
            for k in ('transparent',):
                out[k] = {x: y for x, y in tp[k].items() if x not in DELTA_KEYS}
            for k in ('pools', 'pq_by_scheme', 'vault_by_module'):
                out[k] = [{x: y for x, y in e.items() if x not in DELTA_KEYS} for e in tp[k]]
            return out

        self.node.invalidateblock(b)
        assert_equal(self.node.getbestblockhash(), parent)
        assert_equal(self.node.getblockchaininfo()['transparentPools'], strip(tp_parent))
        assert_equal(zat(self.node.vault_getinfo()['lockedvalue']), tp_parent['pools'][3]['chainValueZat'])
        print('    ok   invalidateblock: the tip figures are the parent\'s')
        self.node.reconsiderblock(b)
        assert_equal(self.node.getbestblockhash(), b)
        assert_equal(self.node.getblockchaininfo()['transparentPools'], strip(tp_b))
        print('    ok   reconsiderblock: the block\'s figures again')

        # A competing fork: node 0 drops b and mines two blocks with a different spend set; node 1 (still on b) follows.
        self.node.invalidateblock(b)
        self.sync_model()
        other_hex = self.wallet_tx_hex([(COIN // 2, self.pq2_spk)])
        f1 = self.mine_raw([other_hex], 'the fork: a different spend set', sync=False)
        f2 = self.mine_raw([], 'the fork: one more block', sync=False)
        sync_blocks(self.nodes)
        assert_equal(self.nodes[1].getbestblockhash(), f2)
        tp_f1 = self.node.getblock(f1)['transparentPools']
        assert_equal(tp_f1['pools'][3]['valueDeltaZat'], 0)
        assert_equal(tp_f1['pq_by_scheme'][1]['valueDeltaZat'], COIN // 2)
        # b's own record is unchanged: records are kept by block hash
        assert_equal(self.node.getblock(b)['transparentPools'], tp_b)
        self.node.reconsiderblock(b)
        assert_equal(self.node.getbestblockhash(), f2)
        self.check_chain(self.node, 'the fork, node 0')
        self.check_chain(self.nodes[1], 'the fork, node 1 (reorganised from b)')
        self.mine()  # the mempool's vault spend and PQ payment confirm on the fork
        self.check_chain(self.node, 'after the fork')

    def section_restart(self):
        print('C. restart, fill, reindex')
        self.table = self.record_table(self.node)
        self.vp_table = {h: self.node.getblock(self.node.getblockhash(h))['valuePools'] for h in self.table}
        self.restart0()
        assert_equal(self.record_table(self.node), self.table)
        assert 'valuepools: the index covers the tip' in self.debug_log(), 'no "covers the tip" log line'
        print('    ok   a restart: identical records')
        self.restart0(wipe_index=True)
        assert_equal(self.record_table(self.node), self.table)
        assert 'valuepools: filled to the tip (height %d)' % max(self.table) in self.debug_log(), 'no fill log line'
        print('    ok   blocks/valuepools deleted: the startup fill rebuilds identical records')
        self.restart0(extra=['-reindex'])
        assert_equal(self.record_table(self.node), self.table)
        assert_equal({h: self.node.getblock(self.node.getblockhash(h))['valuePools'] for h in self.table}, self.vp_table)
        print('    ok   -reindex: identical records, valuePools unchanged')
        self.check_chain(self.node, 'after -reindex')

    def section_pruned(self):
        print('D. a node without the undo data (pruned): not monitored, then filled once the data is back')
        blocks = os.path.join(self.datadir(0), 'blocks')
        rev, aside = os.path.join(blocks, 'rev00000.dat'), os.path.join(self.options.tmpdir, 'rev00000.dat.aside')
        self.restart0(extra=['-checklevel=1'], wipe_index=True, before_start=lambda: shutil.move(rev, aside))
        info = self.node.getblockchaininfo()['transparentPools']
        assert_equal(info['monitored'], False)
        assert_equal([p['monitored'] for p in info['pools']], [False] * 5)
        assert 'chainValue' not in info['transparent']
        assert_equal(self.node.getblock(self.node.getblockhash(1))['transparentPools']['monitored'], False)
        assert 'the transparent pools by type are not monitored from this height: reindex to enable' in self.debug_log(), \
            'no "reindex to enable" log line'
        print('    ok   monitored: false, and the log says reindex to enable')
        self.restart0(before_start=lambda: shutil.move(aside, rev))
        assert_equal(self.record_table(self.node), self.table)
        print('    ok   the undo data back: the fill gives identical records')


if __name__ == '__main__':
    ValuePoolsByTypeTest().main()
