#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The mempool's DoS score for transactions that spend a V or I (audit 07/F-1; main.cpp
IsVaultSetStateFailure). A template input's OP_CHECKSETSIG / OP_CHECKSETDORMANT read the set state at
the receiving node's tip, which the relaying peer's tip need not share, so a failure that depends on
it scores 0. Every other script failure on such a transaction keeps the stock score (100, the peer is
disconnected, as for the same signature on a TX_PQPKH or P2PKH spend, doc/yellowback-pq-dos.md §3).
A mininode peer relays each transaction to node 0:

a. a V owner spend (selector 2) with a garbage SLH-DSA signature                 -> 100, disconnected
a'. the same with a scheme-2 (Falcon) owner                                        -> 100, disconnected
b. a P2PKH input with a wrong ECDSA signature beside a V input                     -> 100, disconnected
c. an UNLOCK (selector 1) with a set signature by a non-member                     -> 0 (SCRIPT_ERR_SETSIG)
d. an OWNER-RELEASED spend (selector 3) of a V whose set is not released           -> 0 (OP_VERIFY after
   OP_CHECKSETDORMANT)
e. an UNLOCK signed by a member whose JOIN is on the peer's tip but not on this node's (the
   original justification: the set state differs by tip)                        -> 0 (SCRIPT_ERR_SETSIG)
f. a garbage SLH-DSA signature on a TX_PQCHANNEL input (fails with SCRIPT_ERR_VERIFY) beside a V input
   with selector 3 and nothing else (review of 07/F-1). The template input is checked alone first:
   - while the set is not released it fails its own dormancy OP_VERIFY -> 0, and the node logs that
     verdict for input 1, so the channel's PQ signature was never verified;
   - once the set is released it fails for a reason of its own (no owner signature), the stock checks
     run, and the channel's garbage signature scores                              -> 100, disconnected
g. an honest OWNER-RELEASED spend relayed from a tip where the set is released, one block ahead of
   this node                                                                      -> 0, then accepted

    ZCASHD=<ycashd> ../.venv/bin/python -u qa/rpc-tests/vault_dos.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

import os
import time
from io import BytesIO

from test_framework.authproxy import JSONRPCException
from test_framework.mininode import CTransaction, NetworkThread, NodeConn, msg_tx, mininode_lock
from test_framework.util import assert_equal, p2p_port
from test_framework import pq
from test_framework import vault as v
from test_framework import yellowback_model as ym
from test_framework.vault_harness import (
    ACTIVATION,
    COIN,
    FEE,
    OUTSIDER,
    OWNER,
    SCRIPT_SETSIG,
    SCRIPT_VERIFY,
    VaultTestBase,
)
from test_framework.yellowback_util import wif_to_secret
from tx_expiry_helper import TestNode

PROTO = 270200          # UPGRADE_VAULT's nProtocolVersion
OP_1, OP_2, OP_3 = 0x51, 0x52, 0x53
MANDATORY = 'mandatory-script-verify-flag-failed'


class VaultDoSTest(VaultTestBase):

    def node_args(self, i):
        return super().node_args(i) + ['-pqfalconheight=%d' % ACTIVATION]

    def run_test(self):
        self.start_vault(coins=20)
        node = self.node
        sid, admit = self.create_set('D', seats=2, unlock_threshold=1, cancel_threshold=1, slash_threshold=1,
                                     liveness_window=30, maturity=2)
        member = v.fixed_secret('D-member')
        self.join(sid, member, [admit], 'JOIN D')
        self.mine(3)
        self.heartbeat(sid, [member], 'HEARTBEAT D')
        self.mine()
        assert not self.released(sid)

        oh = self.tip() + 2
        slh_pk = bytes(OWNER)[32:64]
        falcon_pk = os.urandom(pq.pubkey_size(pq.SCHEME_FN_DSA_512))   # shape only: the signature is garbage anyway
        falcon_owner = v.pq_owner_id(pq.SCHEME_FN_DSA_512, falcon_pk)
        vp = self.vparams(sid, owner_height=oh)
        vp_falcon = self.vparams(sid, owner_height=oh, owner=falcon_owner)
        vo = self.lock(vp, COIN, 'lock V (SLH-DSA owner, ownerHeight tip + 2)')
        vf = self.lock(vp_falcon, COIN, 'lock V (Falcon owner)')
        vo2 = self.lock(vp, COIN, 'lock a second V (SLH-DSA owner)')
        self.mine(2)
        assert self.tip() >= oh

        def owner_tx(outpoint, owner_pk, scheme, selector, lock_time):
            garbage = os.urandom(pq.sig_size(scheme)) + bytes([pq.SIGHASH_ALL])
            seq = v.SEQUENCE_FINAL - 1 if selector == OP_2 else v.SEQUENCE_FINAL
            tx = v.make_tx([(outpoint[0], outpoint[1], seq)], [(COIN - FEE, self.change_spk())], lock_time)
            tx.vin[0].scriptSig = pq.pq_scriptsig(owner_pk, garbage, extra=bytes([selector]))
            return v.tx_hex(tx)

        print('a. V owner spend (selector 2), garbage SLH-DSA signature')
        a = owner_tx(vo, slh_pk, pq.SCHEME_SLH_DSA_SHA2_128S, OP_2, oh)
        assert len(v.tx_from_hex(a).vin[0].scriptSig) > 7900
        self.rpc_reject(a, MANDATORY)
        self.relay(a, 'garbage SLH-DSA owner signature', banned=True)

        print("a'. V owner spend (selector 2), garbage Falcon signature")
        af = owner_tx(vf, falcon_pk, pq.SCHEME_FN_DSA_512, OP_2, oh)
        self.rpc_reject(af, MANDATORY)
        self.relay(af, 'garbage Falcon owner signature', banned=True)

        print('b. a wrong ECDSA signature on a P2PKH input beside a V input')
        u = node.listunspent()[0]
        secret = wif_to_secret(node.dumpprivkey(u['address']))
        tx = v.make_tx([(u['txid'], u['vout'], v.SEQUENCE_FINAL), (vo[0], vo[1], v.SEQUENCE_FINAL - 1)],
                       [(int(u['amount'] * COIN) + COIN - FEE, self.change_spk())], oh)
        wrong = v.ecdsa_sign_der(secret, os.urandom(32)) + bytes([v.SIGHASH_ALL])
        tx.vin[0].scriptSig = v.push(wrong) + v.push(v.pubkey_of(secret))
        tx.vin[1].scriptSig = pq.pq_scriptsig(slh_pk, os.urandom(pq.sig_size(1)) + b'\x01', extra=bytes([OP_2]))
        b = v.tx_hex(tx)
        self.rpc_reject(b, MANDATORY)
        self.relay(b, 'wrong ECDSA signature on a sibling P2PKH input', banned=True)

        print('c. UNLOCK (selector 1) signed by a non-member')
        c = self.unlock_hex(vo, vp, COIN, [(self.change_spk(), COIN)], [OUTSIDER])
        self.rpc_reject(c, SCRIPT_SETSIG)
        self.relay(c, 'bad set signature (SCRIPT_ERR_SETSIG)', banned=False)

        print('d. OWNER-RELEASED (selector 3) while the set is not released')
        d = owner_tx(vo, slh_pk, pq.SCHEME_SLH_DSA_SHA2_128S, OP_3, 0)
        self.rpc_reject(d, SCRIPT_VERIFY)
        self.relay(d, 'OWNER-RELEASED before the set is released (OP_CHECKSETDORMANT false)', banned=False)

        print("e. UNLOCK signed by a member whose JOIN this node's tip lacks")
        m2 = v.fixed_secret('D-member-2')
        self.join(sid, m2, [member], 'JOIN D m2 (admitted by the member)')
        x = self.mine()[0]
        self.mine(3)
        e = self.unlock_hex(vo, vp, COIN, [(self.change_spk(), COIN)], [m2])
        assert self.model.check_tx(v.tx_from_hex(e)) is None, 'the unlock must be valid with the JOIN'
        node.invalidateblock(x)                    # node 0 now stands where a peer without the JOIN would
        self.sync_model()
        self.rpc_reject(e, SCRIPT_SETSIG)
        self.relay(e, 'set signature by a member unknown at this tip', banned=False)
        node.reconsiderblock(x)
        self.sync_all()
        self.sync_model()

        print('f. a garbage SLH-DSA signature on a TX_PQCHANNEL input beside an OP_3 V input (review of 07/F-1)')
        # The channel's cooperative branch is <client slot> OP_CHECKPQSIG OP_VERIFY: a garbage signature
        # fails with SCRIPT_ERR_VERIFY after a full verification. The V input (selector 3, nothing else)
        # comes second, where the stock loop never reaches it; it must not lend that failure a DoS 0.
        server = v.fixed_secret('vault_dos channel server')
        chan_spk = ym.pqchannel_script(v.pq_owner_of(OWNER), v.pubkey_of(server), self.tip() + 500)
        chan_txid = self.accept(self.wallet_tx_hex([(COIN, chan_spk)]), 'fund a TX_PQCHANNEL output')
        self.mine()
        chan_n = [i for i, o in enumerate(v.tx_from_hex(node.getrawtransaction(chan_txid)).vout)
                  if o.scriptPubKey == chan_spk][0]
        tx = v.make_tx([(chan_txid, chan_n, v.SEQUENCE_FINAL), (vo2[0], vo2[1], v.SEQUENCE_FINAL)],
                       [(2 * COIN - FEE, self.change_spk())])
        garbage = os.urandom(pq.sig_size(pq.SCHEME_SLH_DSA_SHA2_128S)) + bytes([pq.SIGHASH_ALL])
        tx.vin[0].scriptSig = (v.push(v.ecdsa_sign_der(server, os.urandom(32)) + bytes([v.SIGHASH_ALL]))
                               + pq.pq_scriptsig(slh_pk, garbage, extra=bytes([OP_1])))
        tx.vin[1].scriptSig = bytes([OP_3])
        f = v.tx_hex(tx)
        assert not self.released(sid)
        self.rpc_reject(f, SCRIPT_VERIFY)
        off = os.path.getsize(os.path.join(self.datadir(0), 'debug.log'))
        self.relay(f, 'the same, set not released: the V input alone fails its dormancy check', banned=False)
        verdict = 'vault: %s input 1: %s' % (v.tx_txid(v.tx_from_hex(f)), SCRIPT_VERIFY)
        assert any(verdict in ln for ln in self.log_since(off)), 'no %r verdict in the log' % verdict
        print('    ok   the verdict is the template input\'s own (input 1): the channel signature was not verified')

        print('g. an honest OWNER-RELEASED spend relayed from a tip where the set is released')
        deadline = self.tip() + 200
        while not self.released(sid):
            assert self.tip() < deadline, 'the set never became released'
            self.mine()
        last = node.getbestblockhash()
        g = self.owner_hex(vo, v.vault_script(vp), COIN, v.SEL_OWNER_RELEASED)
        assert self.model.check_tx(v.tx_from_hex(g)) is None, 'the OWNER-RELEASED spend must be valid on the released tip'
        node.invalidateblock(last)                 # node 0 stands one block short of the release
        self.sync_model()
        assert not self.released(sid)
        self.rpc_reject(g, SCRIPT_VERIFY)
        self.relay(g, 'OWNER-RELEASED valid on the peer\'s tip, not yet on ours', banned=False)
        node.reconsiderblock(last)
        self.sync_all()
        self.sync_model()
        assert self.released(sid)
        self.relay(f, 'garbage PQ-channel signature beside an OP_3 V input, set released', banned=True)
        self.accept(g, 'the same OWNER-RELEASED spend once this node has the block')
        self.mine()

        # the other V coins were never spent
        for out in (vf, vo2):
            assert node.gettxout(out[0], out[1]) is not None
        print('vault_dos OK')

    # ------------------------------------------------------------------ helpers

    def rpc_reject(self, hex_, reason):
        try:
            self.node.sendrawtransaction(hex_)
        except JSONRPCException as e:
            assert reason in e.error['message'], 'expected %r in %r' % (reason, e.error['message'])
            return
        raise AssertionError('the node accepted a transaction it must refuse')

    def mininode_peer(self):
        peers = [p for p in self.node.getpeerinfo() if 'mininode' in p.get('subver', '')]
        assert len(peers) <= 1, peers
        return peers[0] if peers else None

    def log_since(self, off):
        with open(os.path.join(self.datadir(0), 'debug.log'), 'rb') as f:
            f.seek(off)
            return f.read().decode('utf-8', 'replace').splitlines()

    def relay(self, hex_, label, banned):
        """A fresh mininode peer sends ``hex_`` as a ``tx`` message: ``banned`` -> Misbehaving 100 and
        disconnected (127.0.0.1 is a local peer, so not banned); else banscore 0 and still connected."""
        log = os.path.join(self.datadir(0), 'debug.log')
        off = os.path.getsize(log)
        tn = TestNode()
        conn = NodeConn('127.0.0.1', p2p_port(0), self.node, tn, 'regtest', PROTO)
        tn.add_connection(conn)
        NetworkThread().start()
        tn.wait_for_verack()
        deadline = time.time() + 30
        while self.mininode_peer() is None:
            assert time.time() < deadline, 'the mininode peer did not appear'
            time.sleep(0.1)
        assert_equal(self.mininode_peer()['banscore'], 0)
        tx = CTransaction()
        tx.deserialize(BytesIO(bytes.fromhex(hex_)))
        tx.calc_sha256()
        tn.send_message(msg_tx(tx))
        deadline = time.time() + 60
        while True:
            with mininode_lock:
                rej = getattr(conn, 'rejectMessage', None)
            if rej is not None:
                break
            assert time.time() < deadline, '%s: no reject message' % label
            time.sleep(0.1)
        assert_equal(rej.data, tx.sha256)
        if banned:
            while self.mininode_peer() is not None:
                assert time.time() < deadline, '%s: the peer was not disconnected' % label
                time.sleep(0.1)
            lines = [ln for ln in self.log_since(off) if 'Misbehaving' in ln]
            assert any('(0 -> 100)' in ln for ln in lines), '%s: no Misbehaving 0 -> 100 line in %r' % (label, lines)
            print('    ok   %s: Misbehaving 0 -> 100, disconnected (reject %r)' % (label, rej.reason))
        else:
            tn.sync_with_ping()
            peer = self.mininode_peer()
            assert peer is not None, '%s: the peer was disconnected' % label
            assert_equal(peer['banscore'], 0)
            assert not [ln for ln in self.log_since(off) if 'Misbehaving' in ln], label
            print('    ok   %s: banscore 0, still connected (reject %r)' % (label, rej.reason))
            conn.disconnect_node()
            while self.mininode_peer() is not None:
                assert time.time() < deadline, '%s: the peer did not go away' % label
                time.sleep(0.1)
        assert tx.hash not in self.node.getrawmempool()


if __name__ == '__main__':
    VaultDoSTest().main()
