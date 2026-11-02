#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Unit tests for the mixed-line harness (kogany.py) that need no node: the ycashd-argument ->
zakurad.toml generator, the verdict-class tables, the port ranges and the restart-on-change hook.

    cd qa/rpc-tests && ../../../.venv/bin/python -m unittest test_framework.test_kogany -v

Python 3.11+ (tomllib parses the generated file back).
"""

import os
import sys
import tomllib
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))

from test_framework import kogany as kg                                   # noqa: E402
from test_framework import util                                           # noqa: E402
from test_framework.authproxy import JSONRPCException                     # noqa: E402

START = ['-keypool=1', '-discover=0', '-rest', '-i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025',
         '-nuparams=5ba81b19:1', '-nuparams=76b809bb:1']
YCASH = ['-nuparams=374d694f:1', '-nuparams=8e471bd6:1', '-nuparams=66314da3:1', '-nuparams=19bd2d2f:1']
VAULT = ['-nuparams=6d5b7a31:103']
SETID = 'ab' * 32


class TomlGeneratorTest(unittest.TestCase):

    def setUp(self):
        util.PortSeed.n = 4242

    def gen(self, extra=(), live=(), slot=0, peers=(13000,)):
        cfg, notes = kg.zakurad_config(START + YCASH + VAULT + list(extra), slot, list(peers), '/tmp/k%d' % slot, live=live)
        return cfg, notes, tomllib.loads(kg.render_toml(cfg, notes))

    def test_round_trip(self):
        cfg, _notes, parsed = self.gen()
        self.assertEqual(parsed, cfg)

    def test_regtest_form_and_heights(self):
        _cfg, notes, t = self.gen()
        nw = t['network']['network']
        self.assertIs(nw['regtest'], True)
        h = nw['params']['activation_heights']
        self.assertEqual(h, {'Overwinter': 1, 'Sapling': 1, 'Blossom': 1, 'Heartwood': 1, 'Canopy': 1})
        self.assertEqual(list(h), ['Overwinter', 'Sapling', 'Blossom', 'Heartwood', 'Canopy'])
        self.assertIn('pending:W1-Y1: -nuparams=374d694f:1 -> activation_heights.Ycash = 1', notes)
        self.assertIn('pending:W2-b: -nuparams=6d5b7a31:103 -> activation_heights.Vault = 103', notes)

    def test_live_chunks_emit_pending_keys_in_order(self):
        _cfg, notes, t = self.gen(['-yellowbackattestorset=' + SETID, '-yellowbacksigmaref=0', '-pqfalconheight=0'],
                                  live=('W1-Y1', 'W2-b', 'W5-f', 'W5-c', 'W3-c'))
        h = t['network']['network']['params']['activation_heights']
        self.assertEqual(list(h), ['Overwinter', 'Sapling', 'Ycash', 'Blossom', 'Heartwood', 'Canopy', 'Vault'])
        self.assertEqual(h['Vault'], 103)
        self.assertEqual(t['yellowback'], {'attestor_set': SETID, 'sigma_ref': 0})
        self.assertEqual(t['kogany'], {'pq_falcon_height': 0})
        self.assertEqual(notes, [])

    def test_env_live(self):
        os.environ['KOGANY_LIVE'] = 'W2-b'
        try:
            cfg, _ = kg.zakurad_config(START + VAULT, 0, [1], '/tmp/k')
        finally:
            del os.environ['KOGANY_LIVE']
        self.assertEqual(cfg['network']['network']['params']['activation_heights']['Vault'], 103)

    def test_pending_yellowback_flags_are_notes(self):
        _cfg, notes, t = self.gen(['-yellowbackattestorset=' + SETID, '-yellowbacksigmaref=0',
                                   '-yellowbackpayoutaddress=tmXYZ', '-mocktime=1700000000', '-exportdir=/x'])
        self.assertNotIn('yellowback', t)
        self.assertIn('pending:W5-f: -yellowbackattestorset=%s -> yellowback.attestor_set = %s' % (SETID, SETID), notes)
        self.assertIn('ignored: -yellowbackpayoutaddress=tmXYZ', notes)
        self.assertIn('ignored: -mocktime=1700000000', notes)

    def test_unmapped_arguments_refused(self):
        for bad in (['-yellowbacknewflag=1'], ['-vaultsomething=1'], ['-nuparams=deadbeef:5'], ['-frobnicate'], ['x']):
            with self.assertRaises(kg.UnmappedArgument, msg=bad):
                kg.zakurad_config(START + bad, 0, [1], '/tmp/k', live=())

    def test_ports_and_dirs(self):
        _cfg, _notes, t = self.gen(slot=2, peers=(13001, 13002))
        self.assertEqual(t['network']['listen_addr'], '127.0.0.1:%d' % kg.kogany_p2p_port(2))
        self.assertEqual(t['rpc']['listen_addr'], '127.0.0.1:%d' % kg.kogany_rpc_port(2))
        self.assertEqual(t['network']['zakura']['listen_addr'], '127.0.0.1:%d' % kg.kogany_v2_port(2))
        self.assertEqual(t['network']['initial_testnet_peers'], ['127.0.0.1:13001', '127.0.0.1:13002'])
        self.assertEqual(t['network']['p2p_stack'], 'legacy')
        self.assertIs(t['rpc']['enable_cookie_auth'], False)
        self.assertEqual(t['state']['cache_dir'], '/tmp/k2/state')
        self.assertEqual(t['mempool']['debug_enable_at_height'], 0)

    def test_port_ranges_disjoint(self):
        for seed in (0, 1, 4242, 99999):
            util.PortSeed.n = seed
            cxx = {util.p2p_port(i) for i in range(util.MAX_NODES + 1)} | {util.rpc_port(i) for i in range(util.MAX_NODES + 1)}
            kog = set()
            for k in range(util.MAX_NODES + 1):
                kog |= {kg.kogany_p2p_port(k), kg.kogany_rpc_port(k), kg.kogany_v2_port(k), kg.yewd_rpc_port(k)}
            self.assertFalse(cxx & kog)
            self.assertEqual(len(kog), 4 * (util.MAX_NODES + 1))
            self.assertLess(max(kog), 65536)

    def test_toml_quoting(self):
        text = kg.render_toml({'a': {'s': 'x"y\\z', 'l': ['p', 'q'], 'b': False, 'n': None}}, ['note'])
        self.assertTrue(text.startswith('# zakurad.toml'))
        self.assertIn('# note', text)
        self.assertEqual(tomllib.loads(text), {'a': {'s': 'x"y\\z', 'l': ['p', 'q'], 'b': False}})

    def test_key_table_covers_every_pending_flag(self):
        rows = ' '.join(r[0] for r in kg.ZAKURAD_KEY_TABLE)
        for flag in kg._PENDING_FLAGS:
            self.assertIn(flag, rows)
        self.assertIn('ycashd argument', kg.describe())


def rpc_error(message, code=-26):
    return JSONRPCException({'code': code, 'message': message})


class VerdictClassTest(unittest.TestCase):

    def test_blocks(self):
        self.assertEqual(kg.classify_cxx_block(None), kg.ACCEPT)
        for r in ('duplicate', 'inconclusive', 'duplicate-inconclusive'):
            self.assertEqual(kg.classify_cxx_block(r), kg.ACCEPT)
        for r in ('bad-cb-amount', 'duplicate-invalid', 'bad-txns-vault-timelock', 'yellowback-vault-spend', 'invalid'):
            self.assertEqual(kg.classify_cxx_block(r), kg.REJECT_CONSENSUS, r)
        self.assertEqual(kg.classify_cxx_block('time-too-new'), kg.REJECT_STATE)

    def test_transactions(self):
        cases = [
            (None, kg.ACCEPT),
            (rpc_error('66: min relay fee not met'), kg.REJECT_POLICY),
            (rpc_error('64: dust'), kg.REJECT_POLICY),
            (rpc_error('258: txn-mempool-conflict'), kg.REJECT_POLICY),
            (rpc_error('16: bad-txns-inputs-duplicate'), kg.REJECT_CONSENSUS),
            (rpc_error('16: bad-txns-prevout-null'), kg.REJECT_CONSENSUS),
            (rpc_error('16: bad-txns-vault-timelock'), kg.REJECT_STATE),
            (rpc_error('16: bad-yellowback-redeem-burn'), kg.REJECT_STATE),
            (rpc_error('Missing inputs', -25), kg.REJECT_STATE),
            (rpc_error('transaction already in block chain', -27), kg.REJECT_POLICY),
            (rpc_error('tx-expiring-soon: expiryheight is 5 but should be at least 7'), kg.REJECT_POLICY),
            (rpc_error('16: bad-txns-in-belowout, absurdly high fees x, 5 > 4'), kg.REJECT_CONSENSUS),
        ]
        for err, want in cases:
            unmapped = []
            self.assertEqual(kg.classify_cxx_tx(err, unmapped), want, err and err.error)
            self.assertEqual(unmapped, [])
        unmapped = []
        self.assertEqual(kg.classify_cxx_tx(rpc_error('16: set-act-unknown'), unmapped), kg.REJECT_STATE)
        self.assertEqual(unmapped, ['16: set-act-unknown'])

    def test_kogany_side(self):
        self.assertEqual(kg.classify_kogany_block(None), kg.ACCEPT)
        self.assertEqual(kg.classify_kogany_block('duplicate'), kg.ACCEPT)
        self.assertEqual(kg.classify_kogany_block('rejected'), kg.REJECT_UNCLASSIFIED)
        self.assertEqual(kg.classify_kogany_tx(rpc_error('anything')), kg.REJECT_UNCLASSIFIED)

    def test_same_class(self):
        self.assertTrue(kg.same_class(kg.ACCEPT, kg.ACCEPT))
        self.assertFalse(kg.same_class(kg.ACCEPT, kg.REJECT_UNCLASSIFIED))
        self.assertFalse(kg.same_class(kg.REJECT_CONSENSUS, kg.ACCEPT))
        self.assertFalse(kg.same_class(kg.REJECT_STATE, kg.REJECT_POLICY))
        for c in kg.REJECT_CLASSES:
            self.assertTrue(kg.same_class(c, kg.REJECT_UNCLASSIFIED))
            self.assertFalse(kg.same_class(c, kg.REJECT_UNCLASSIFIED, strict=True))

    def test_map_rows_well_formed(self):
        for path, pattern, cls, dos, _src in kg.REJECT_CODE_MAP:
            self.assertIn(path, ('block', 'tx'))
            self.assertIn(cls, (kg.ACCEPT,) + kg.REJECT_CLASSES)
            self.assertTrue(pattern)
            if cls == kg.REJECT_CONSENSUS:
                self.assertIn(dos, (10, 100))


class FakeFollower:
    def __init__(self, k):
        self.k = k
        self.datadir = '/tmp/fake%d' % k
        self.config = None
        self.events = []
        self.rpc = self

    def getpeerinfo(self):
        return []

    def write_config(self, config, notes):
        self.config = config
        self.events.append('write')

    def start(self):
        self.events.append('start')

    def stop(self):
        self.events.append('stop')


class FakePeer:
    def __init__(self):
        self.added = []

    def getpeerinfo(self):
        return []

    def addnode(self, addr, how):
        self.added.append((addr, how))


class YewdPairTest(unittest.TestCase):

    def test_argv(self):
        util.PortSeed.n = 3
        os.environ.pop('YEWD_BIN', None)
        backend, yewd = kg.yewd_pair_argv('/y/yewd', '/b/ycashd', '/t/node2', 2,
                                          ['-keypool=1', '-discover=0', '-mocktime=5', '-exportdir=/e',
                                           '-nuparams=6d5b7a31:103', '-debug=net'])
        self.assertEqual(backend, ['/b/ycashd', '-datadir=/t/node2/backend', '-disablewallet', '-discover=0',
                                   '-mocktime=5', '-nuparams=6d5b7a31:103', '-debug=net'])
        self.assertEqual(yewd, ['/y/yewd', '-datadir=/t/node2', '-conf=ycash.conf', '-regtest',
                                '-backendrpcport=%d' % kg.yewd_backend_rpc_port(2),
                                '-backendrpccookiefile=/t/node2/backend/regtest/.cookie', '-stopbackend',
                                '-keypool=1', '-mocktime=5', '-exportdir=/e'])
        cxx = {util.rpc_port(i) for i in range(util.MAX_NODES + 1)} | {util.p2p_port(i) for i in range(util.MAX_NODES + 1)}
        self.assertNotIn(kg.yewd_backend_rpc_port(2), cxx)
        self.assertNotIn(kg.yewd_backend_rpc_port(2), {kg.kogany_rpc_port(k) for k in range(9)})


class MixedLineHookTest(unittest.TestCase):

    def setUp(self):
        util.PortSeed.n = 7

    def test_inert(self):
        m = kg.MixedLine.from_env({})
        self.assertFalse(m.enabled)
        self.assertFalse(m.active)
        self.assertIsNone(m.offer_block('00', None))
        self.assertIsNone(m.offer_tx('00', None))
        m.sync_point([object()])
        m.mempool_point([object()])
        m.on_node_start(0, ['-x'], None)      # an unmapped argument is never looked at when inert

    def test_from_env(self):
        m = kg.MixedLine.from_env({'KOGANY_BIN': '/bin/z', 'KOGANY_FOLLOWERS': '2', 'KOGANY_PEER': '3',
                                   'KOGANY_STRICT': '1', 'KOGANY_MEMPOOL': '1', 'KOGANY_ARGS': '-v  -q'})
        self.assertEqual((m.binary, m.n_followers, m.peer, m.strict, m.mempool, m.extra_args),
                         ('/bin/z', 2, 3, True, True, ['-v', '-q']))

    def test_restart_only_on_a_changed_live_config(self):
        m = kg.MixedLine(binary='/bin/z', peer=0)
        m.connect_settle = 0
        f = FakeFollower(0)
        m.followers = [f]
        peer = FakePeer()
        m.on_node_start(0, START + YCASH + VAULT, peer)
        self.assertEqual(f.events, ['stop', 'write', 'start'])
        f.events = []
        m.on_node_start(0, START + YCASH + VAULT + ['-yellowbackattestorset=' + SETID], peer)
        self.assertEqual(f.events, [])            # pending row: a note, not a key -> no restart
        m.on_node_start(1, START + ['-frobnicate'], peer)   # not the peer: ignored
        self.assertEqual(f.events, [])
        self.assertEqual(peer.added, [('127.0.0.1:%d' % kg.kogany_p2p_port(0), 'onetry')] * 2)

    def test_strict_note_fails(self):
        m = kg.MixedLine(binary='/bin/z', strict=True)
        with self.assertRaises(AssertionError):
            m.note('x')


if __name__ == '__main__':
    unittest.main()
