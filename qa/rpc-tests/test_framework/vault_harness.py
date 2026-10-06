#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The shared harness of the raw-transaction vault suites (``vault_primitive.py``,
``vault_slashing.py``, ``vault_bridge.py``; docs/plans/yellowback-upgrade-plan.md §15.9).

Every transaction is built with ``test_framework/vault.py`` and stock RPCs only
(``listunspent`` / ``signrawtransaction`` for fee inputs, ``sendrawtransaction``, ``generate``,
``submitblock`` through ``mine_block_raw``, ``getblock``); the ``set_*`` / ``vault_*`` RPCs are
never called.  Every answer the node gives is cross-checked against ``VaultModel``, which is fed
each block the node connects (``sync_model``) and disconnects on a reorg:

- ``accept(hex)``: the model predicts acceptance at tip + 1, the node's mempool accepts;
- ``reject(hex, node_reason, model_reason)``: the model predicts ``model_reason``, the node's
  ``sendrawtransaction`` fails with ``node_reason`` in its message;
- ``block_reject(hexes, node_reason, model_reason)``: the same transactions in a block built in
  Python and submitted with ``submitblock``; the block is refused and the tip does not move.

The node reports a template rule as its C++ reason (``src/vault/state.cpp``), a script failure
as the interpreter's message (``ScriptErrorString``), a BIP68 lock as ``non-BIP68-final``
(mempool) / ``bad-txns-nonfinal`` (block).  The model's reasons are its own codes; each
assertion names both.

Nodes run with the Ycash upgrade arguments (``YCASH_UPGRADE_ARGS``) so blocks past regtest's
first halving can be mined (plan §15.5 finding (18)), and ``-nuparams=6d5b7a31:ACTIVATION``.
"""

import os
import shutil
import signal
import time
from decimal import Decimal
from io import BytesIO

from .authproxy import JSONRPCException
from .mininode import CBlock
from .test_framework import BitcoinTestFramework
from .util import (
    VAULT_BRANCH_ID,
    assert_equal,
    bitcoind_processes,
    connect_nodes_bi,
    hex_str_to_bytes,
    nuparams,
    start_node,
    start_nodes,
    stop_node,
    sync_blocks,
)
from . import vault as v
from .yellowback_util import YCASH_UPGRADE_ARGS, mine_block_raw

ACTIVATION = 200
COIN = v.COIN
FEE = v.VAULT_FEE

# The node's reasons (C++), named once.
SCRIPT_SETSIG = 'OP_CHECKSETSIG or OP_CHECKSETDORMANT failed'
SCRIPT_VERIFY = 'Script failed an OP_VERIFY operation'
SCRIPT_LOCKTIME = 'Locktime requirement not satisfied'
SCRIPT_FALSE = 'Script evaluated without error but finished with a false/empty top stack element'
MEMPOOL_BIP68 = 'non-BIP68-final'
BLOCK_NONFINAL = 'bad-txns-nonfinal'
MEMPOOL_NONFINAL = 'non-final'

OWNER = v.fixed_secret('vault-functional-owner')
OWNER_KEY = v.pubkey_of(OWNER)
OUTSIDER = v.fixed_secret('vault-functional-outsider')


def tx_from_hex(h):
    return v.tx_from_hex(h)


def txid_of(hex_):
    return v.tx_txid(v.tx_from_hex(hex_))


def _has_reason(msg, reason):
    """``reason`` is a substring, or a tuple of acceptable substrings (where the C++ order of
    the template rules and the script check is not fixed by §15)."""
    reasons = reason if isinstance(reason, tuple) else (reason,)
    return any(r in msg for r in reasons)


def secrets(label, n):
    return [v.fixed_secret('%s-%d' % (label, i)) for i in range(n)]


class VaultTestBase(BitcoinTestFramework):
    """Two connected nodes (``getblocktemplate`` and ``submitblock`` need a peer); node 0 mines,
    builds and broadcasts, node 1 follows."""

    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.cache_behavior = 'clean'   # 6.20.0 harness: replaces setup_clean_chain

    def node_args(self, i):
        return list(YCASH_UPGRADE_ARGS) + [nuparams(VAULT_BRANCH_ID, ACTIVATION)]

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 extra_args=[self.node_args(i) for i in range(self.num_nodes)])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    # ------------------------------------------------------------------ chain + model

    @property
    def node(self):
        return self.nodes[0]

    def tip(self):
        return self.node.getblockcount()

    def start_vault(self, coins=40, coin_value=Decimal('2')):
        """Mine past activation, split the wallet into ``coins`` P2PKH coins (fee and funding
        inputs for hand-built transactions), and start the model at the activation height."""
        self.model = v.VaultModel(activation_height=ACTIVATION)
        self.model_hashes = {}
        self.node.generate(ACTIVATION - 5)
        sync_blocks(self.nodes)
        assert_equal(self.node.getblockchaininfo()['upgrades']['6d5b7a31']['status'], 'pending')
        self.mine_to(ACTIVATION + 1)
        assert_equal(self.node.getblockchaininfo()['upgrades']['6d5b7a31']['status'], 'active')
        self.split_coins(coins, coin_value)

    def split_coins(self, n, value):
        outs = {}
        for _ in range(n):
            outs[self.node.getnewaddress()] = value
        self.node.sendmany('', outs)
        self.mine()

    def sync_model(self):
        """Disconnect the model down to the fork point with node 0's chain, then connect node
        0's blocks; every block the node accepted must apply in the model too."""
        node = self.node
        tip = node.getblockcount()
        while self.model.tip >= ACTIVATION and (
                self.model.tip > tip or node.getblockhash(self.model.tip) != self.model_hashes[self.model.tip]):
            del self.model_hashes[self.model.tip]
            self.model.disconnect_block()
        for h in range(self.model.tip + 1, tip + 1):
            bh = node.getblockhash(h)
            blk = CBlock()
            blk.deserialize(BytesIO(hex_str_to_bytes(node.getblock(bh, 0))))
            r = self.model.connect_block(h, blk.vtx)
            assert r is None, 'the node connected block %d (%s) but the model rejects tx %d: %s' % (h, bh, r[0], r[1])
            self.model_hashes[h] = bh

    def mine(self, n=1):
        hashes = self.node.generate(n)
        sync_blocks(self.nodes)
        self.sync_model()
        return hashes

    def mine_to(self, height):
        t = self.tip()
        assert t <= height, (t, height)
        if height > t:
            self.mine(height - t)

    def mine_raw(self, hexes, label='', sync=True):
        """A Python-built block of exactly ``hexes`` (not the mempool) on node 0; must be
        accepted.  Returns the block hash.  ``sync=False`` for a fork block node 1 does not
        switch to (yet)."""
        result, bh = mine_block_raw(self.node, hexes)
        assert result in (None, 'duplicate'), '%s: block refused (%s)' % (label, result)
        if sync:
            sync_blocks(self.nodes)
        self.sync_model()
        return bh

    def in_block(self, txid, bh):
        return txid in self.node.getblock(bh)['tx']

    def mempool(self):
        return set(self.node.getrawmempool())

    def confirmations(self, txid):
        try:
            return self.node.getrawtransaction(txid, 1).get('confirmations', 0)
        except JSONRPCException:
            return None

    def lock_inputs(self, hex_):
        """``lockunspent`` the inputs of a transaction built but not (yet) sent, so the next
        builder does not pick the same coins."""
        t = tx_from_hex(hex_)
        self.node.lockunspent(False, [{'txid': '%064x' % i.prevout.hash, 'vout': i.prevout.n} for i in t.vin])

    def assert_evicted(self, txid, label):
        """The mempool no longer holds ``txid`` (a re-check on ConnectTip / DisconnectTip
        removed it, plan §15.6)."""
        assert txid not in self.mempool(), label

    def assert_connected(self, label, settle=6):
        """After ``settle`` seconds (relay), node 1 still has both connections to node 0: a
        transaction valid on node 0's tip but not on node 1's must not get node 0 disconnected
        (a set-state-dependent script failure is not misbehaviour: the state differs by tip)."""
        time.sleep(settle)
        n = len(self.nodes[1].getpeerinfo())
        assert n == 2, '%s: node 1 has %d connections to node 0, expected 2' % (label, n)
        print('    ok   %s' % label)

    def wait_in_mempool(self, txid, i, label, timeout=30):
        deadline = time.time() + timeout
        while txid not in self.nodes[i].getrawmempool():
            assert time.time() < deadline, label
            time.sleep(0.25)
        print('    ok   %s' % label)

    # ------------------------------------------------------------------ assertions

    def accept(self, hex_, label):
        r = self.model.check_tx(tx_from_hex(hex_))
        assert r is None, '%s: the model predicts rejection (%s)' % (label, r)
        try:
            txid = v.node_send(self.node, hex_)
        except JSONRPCException as e:
            raise AssertionError('%s: the node refused (%s); the model accepts' % (label, e.error['message']))
        print('    ok   %s' % label)
        return txid

    def reject(self, hex_, node_reason, model_reason, label):
        r = self.model.check_tx(tx_from_hex(hex_))
        assert r == model_reason, '%s: the model predicts %r, expected %r' % (label, r, model_reason)
        try:
            self.node.sendrawtransaction(hex_)
        except JSONRPCException as e:
            msg = e.error['message']
            assert _has_reason(msg, node_reason), '%s: expected %r in the node\'s reason %r' % (label, node_reason, msg)
            print('    no   %s (%s)' % (label, msg))
            return msg
        raise AssertionError('%s: the node accepted; the model predicts %r' % (label, model_reason))

    def block_reject(self, hexes, node_reason, model_reason, label):
        txs = [tx_from_hex(h) for h in hexes]
        r = self.model.connect_block(self.model.tip + 1, txs)
        if r is None:
            self.model.disconnect_block()
            raise AssertionError('%s: the model accepts the block' % label)
        assert r[1] == model_reason, '%s: the model predicts %r, expected %r' % (label, r[1], model_reason)
        tip = self.node.getbestblockhash()
        result, _bh = mine_block_raw(self.node, hexes)
        assert result not in (None, 'duplicate'), '%s: the node accepted the block' % label
        assert _has_reason(str(result), node_reason), '%s: expected %r in submitblock\'s %r' % (label, node_reason, result)
        assert_equal(self.node.getbestblockhash(), tip)
        print('    no   %s [block] (%s)' % (label, result))
        return result

    def reject_both(self, hex_, node_reason, model_reason, label, block_reason=None):
        self.reject(hex_, node_reason, model_reason, label)
        self.block_reject([hex_], block_reason or node_reason, model_reason, label)

    # ------------------------------------------------------------------ builders

    def fund(self, needed):
        return v.node_funding(self.node, needed)

    def change_spk(self):
        return v.node_spk(self.node)

    def act_hex(self, act, signers=(), outputs_before=()):
        return v.node_act_tx(self.node, act, signers, outputs_before)

    def raw_act_hex(self, payload, sigs_for=(), extra_sigs=(), outputs_before=()):
        """An act transaction from raw payload bytes (malformed-act tests): signatures by
        ``sigs_for`` over its actMsg, plus ``extra_sigs`` verbatim."""
        need = sum(val for val, _ in outputs_before) + FEE
        vin, total = self.fund(need)
        msg = v.act_msg(payload, vin[0][0], vin[0][1])
        sigs = [v.sign_recoverable(s, msg) for s in sigs_for] + list(extra_sigs)
        vout = list(outputs_before) + [(0, v.act_script(payload, sigs))]
        if total > need:
            vout.append((total - need, self.change_spk()))
        return v.node_sign(self.node, v.make_tx(vin, vout))

    def create_set_hex(self, admit_secret, **kw):
        d = dict(seats=3, unlock_threshold=2, cancel_threshold=1, slash_threshold=2, rate_window=1000,
                 liveness_window=1000, bond_min=COIN, bond_lock_min=20, maturity=3)
        d.update(kw)
        act = v.act_set_create(admit_key=v.pubkey_of(admit_secret), **d)
        hex_, sid = v.node_set_create(self.node, act)
        return hex_, sid

    def create_set(self, label, mine=True, **kw):
        admit = v.fixed_secret(label + '-admit')
        hex_, sid = self.create_set_hex(admit, **kw)
        self.accept(hex_, 'SET_CREATE %s' % label)
        if mine:
            self.mine()
        return sid, admit

    def join_hex(self, sid, secret, admit_secrets, bond=COIN, locktime=None):
        if locktime is None:
            s = self.model.get_set(sid)
            locktime = self.tip() + 1 + (s.p['bondLockMin'] if s else 20) + 30
        return v.node_set_join(self.node, sid, secret, bond, locktime, admit_secrets), locktime

    def join(self, sid, secret, admit_secrets, label, bond=COIN, locktime=None):
        hex_, lt = self.join_hex(sid, secret, admit_secrets, bond, locktime)
        txid = self.accept(hex_, label)
        return {'outpoint': (txid, 0), 'value': bond, 'locktime': lt, 'secret': secret}

    def heartbeat_hex(self, sid, secret):
        return self.act_hex(v.act_set_heartbeat(sid, v.pubkey_of(secret)), [secret])

    def heartbeat(self, sid, secret_list, label='heartbeat'):
        return [self.accept(self.heartbeat_hex(sid, s), '%s %d' % (label, i)) for i, s in enumerate(secret_list)]

    def vparams(self, sid, cancel_sid=None, delay=5, owner_height=None, app_height=0, tag=b'TEST', owner_key=OWNER_KEY):
        return v.VaultParams(tag, sid, cancel_sid or sid, delay,
                             owner_height if owner_height is not None else self.tip() + 500, app_height, owner_key)

    def lock_hex(self, vp, amount, extra_vout=()):
        need = amount + FEE + sum(val for val, _ in extra_vout)
        vin, total = self.fund(need)
        change = (total - need, self.change_spk()) if total > need else None
        return v.node_sign(self.node, v.build_lock_tx(vin, vp, amount, change, extra_vout))

    def lock(self, vp, amount, label='lock', extra_vout=()):
        txid = self.accept(self.lock_hex(vp, amount, extra_vout), label)
        return (txid, 0)

    def unlock_hex(self, outpoint, vp, value, recipients, signers, relock=0, branch_id=VAULT_BRANCH_ID, change_extra=None):
        """UNLOCK: ``recipients`` [(spk, value)] become intents; ``relock`` re-locks; the fee
        from a wallet coin.  ``change_extra`` (value, spk) adds an ordinary output paid from the
        fee coin (``None``) -- covenant tests."""
        fee_vin, change = v.node_fee_inputs(self.node)
        tx = v.build_unlock_tx(outpoint, vp, value, recipients, relock, fee_vin, change, (), branch_id)
        if change_extra is not None:
            tx.vout.append(v.CTxOut(change_extra[0], change_extra[1]))
            tx.vout[-2].nValue -= change_extra[0]
        sigs = v.set_sigs_for(tx, 0, v.vault_script(vp), value, vp.set_id, v.ROLE_UNLOCK, signers, branch_id)
        return v.node_sign(self.node, tx, v.vault_unlock_scriptsig(sigs))

    def unlock_tx(self, outpoint, vp, value, recipients, relock=0):
        """An unsigned UNLOCK with a wallet fee input (edit its outputs, then ``setsig_hex``)."""
        fee_vin, change = v.node_fee_inputs(self.node)
        return v.build_unlock_tx(outpoint, vp, value, recipients, relock, fee_vin, change)

    def setsig_hex(self, tx, spk, value, set_id, role, signers, selector, branch_id=VAULT_BRANCH_ID, n_in=0):
        """Sign input ``n_in`` (a V or I of ``value``) with set signatures of ``role`` by
        ``signers`` and the selector opcode; the wallet signs the other inputs."""
        sigs = v.set_sigs_for(tx, n_in, spk, value, set_id, role, signers, branch_id)
        script_sig = b''.join(v.push(s) for s in sigs) + bytes([v.OP_1 + selector - 1])
        return v.node_sign(self.node, tx, script_sig, n_in)

    def wallet_tx_hex(self, vout, extra_value=0):
        """Ordinary inputs from the wallet paying ``vout`` [(value, spk)] plus change."""
        need = sum(val for val, _ in vout) + FEE + extra_value
        vin, total = self.fund(need)
        outs = list(vout)
        if total > need:
            outs.append((total - need, self.change_spk()))
        return v.node_sign(self.node, v.make_tx(vin, outs))

    def release_hex(self, ioutpoint, ip, value, recipient_spk, sequence=None):
        fee_vin, change = v.node_fee_inputs(self.node)
        tx = v.build_release_tx(ioutpoint, ip, value, recipient_spk, fee_vin, change)
        if sequence is not None:
            tx.vin[0].nSequence = sequence
        return v.node_sign(self.node, tx, tx.vin[0].scriptSig)

    def cancel_hex(self, ioutpoint, ip, value, vp, signers):
        return v.node_cancel(self.node, ioutpoint, ip, value, vp, signers)

    def owner_hex(self, outpoint, spk, value, selector, lock_time=0, secret=OWNER, dest=None):
        tx = v.build_owner_spend_tx(outpoint, spk, value, secret, dest or self.change_spk(), selector, lock_time)
        return v.tx_hex(tx)

    def bond_spend_hex(self, bond, dest=None):
        tx = v.build_bond_spend_tx(bond['outpoint'], bond['secret'], bond['value'], bond['locktime'],
                                   dest or self.change_spk())
        return v.tx_hex(tx)

    # ------------------------------------------------------------------ model queries

    def released(self, sid, h=None):
        return self.model.is_released(sid, self.tip() + 1 if h is None else h)

    def dormant(self, sid, h=None):
        return self.model.is_dormant(sid, self.tip() + 1 if h is None else h)

    def info(self, sid):
        return self.model.set_info(sid)

    # ------------------------------------------------------------------ restarts

    def datadir(self, i):
        return os.path.join(self.options.tmpdir, 'node%d' % i, 'regtest')

    def restart_node0(self, kill=False, wipe_vaults=False, extra=()):
        """Stop node 0 (cleanly, or SIGKILL), optionally delete ``<datadir>/vaults/`` (the set
        state DB, U-18), start it again and reconnect."""
        if kill:
            p = bitcoind_processes.pop(0)
            os.kill(p.pid, signal.SIGKILL)
            p.wait()
        else:
            stop_node(self.nodes[0], 0)
        if wipe_vaults:
            path = os.path.join(self.datadir(0), 'vaults')
            assert os.path.isdir(path), 'no vault state DB at %s' % path
            shutil.rmtree(path)
        self.nodes[0] = start_node(0, self.options.tmpdir, self.node_args(0) + list(extra))
        connect_nodes_bi(self.nodes, 0, 1)
        deadline = time.time() + 60
        while self.nodes[0].getbestblockhash() != self.nodes[1].getbestblockhash():
            assert time.time() < deadline, 'node 0 did not resync after restart'
            time.sleep(0.25)
