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
import re
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
                                  live=('W1-Y1', 'W2-b', 'W5-f', 'W5-e', 'W3-c'))
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

    def test_w5e_rows_live_with_w5f_and_mempool_rows(self):
        yed = ['-yellowbackattestorset=' + SETID, '-yellowbacksigmaref=7', '-yellowbacksupplycapbps=500',
               '-yellowbackattestarmmin=2', '-yellowbackbundlecarrier=either', '-yellowbackmintrequiresarmed=1']
        pool = ['-acceptnonstdtxn=0', '-txunpaidactionlimit=0', '-datacarriersize=1200']
        _cfg, notes, t = self.gen(yed + pool, live=('W5-f',))
        self.assertEqual(t['yellowback'], {'attestor_set': SETID, 'sigma_ref': 7, 'supply_cap_bps': 500,
                                           'attest_arm_min': 2, 'bundle_carrier': 'either',
                                           'mint_requires_armed': True})
        self.assertEqual(t['mempool'], {'debug_enable_at_height': 0, 'accept_non_standard': False,
                                        'tx_unpaid_action_limit': 0, 'max_datacarrier_bytes': 1200})
        self.assertFalse(any('W5' in n for n in notes), notes)
        _cfg, notes, t = self.gen(yed)
        self.assertNotIn('yellowback', t)
        self.assertEqual(len([n for n in notes if n.startswith('pending:W5-f')]), 6)
        with self.assertRaises(kg.UnmappedArgument):
            self.gen(['-acceptnonstdtxn=yes'])

    def test_w5f_default_on_from_env(self):
        args = START + VAULT + ['-yellowbackattestorset=' + SETID, '-yellowbackattestarmmin=1']
        saved = os.environ.pop('KOGANY_LIVE', None)
        try:
            for env, on in ((None, True), ('W1-Y1,W2-b', True), ('!W5-f', False), ('W2-b, !W5-f', False)):
                if env is None:
                    os.environ.pop('KOGANY_LIVE', None)
                else:
                    os.environ['KOGANY_LIVE'] = env
                cfg, notes = kg.zakurad_config(args, 0, [1], '/tmp/k')
                if on:
                    self.assertEqual(cfg['yellowback'], {'attestor_set': SETID, 'attest_arm_min': 1}, env)
                else:
                    self.assertNotIn('yellowback', cfg, env)
                    self.assertEqual(len([n for n in notes if n.startswith('pending:W5-f')]), 2, env)
            self.assertEqual(kg._live_chunks(()), frozenset())        # an explicit list is taken as given
        finally:
            os.environ.pop('KOGANY_LIVE', None)
            if saved is not None:
                os.environ['KOGANY_LIVE'] = saved

    # W6-b: (flag value, toml key, integer) -- the option's integer unit
    W6B_ROWS = [
        ('-pqfeerate=0.000002', 'pq_fee_rate', 200),
        ('-pqfeeusdperkb=0.05', 'pq_fee_usd_per_kb_micro', 50000),
        ('-yellowbackfeeusdperkb=0.05', 'yellowback_fee_usd_per_kb_micro', 50000),
        ('-yellowbackmaxtxfeeusd=2', 'yellowback_max_tx_fee_usd_micro', 2000000),
        ('-yellowbackmaxtxfee=10', 'yellowback_max_tx_fee', 1000000000),
        ('-maxtxfee=0.02', 'max_tx_fee', 2000000),
        ('-yellowbackfee=1000', 'yellowback_fee', 1000),
        ('-yellowbackmintlag=2', 'yellowback_mint_lag', 2),
    ]

    def test_w6b_fee_rows(self):
        for flag, key, want in self.W6B_ROWS:
            _cfg, notes, t = self.gen([flag], live=())
            self.assertEqual(t['mempool'][key], want, flag)
            self.assertIsInstance(t['mempool'][key], int, flag)
            self.assertEqual(notes[2:], [], flag)          # the Ycash / Vault height notes only
        _cfg, _notes, t = self.gen([f for f, _k, _w in self.W6B_ROWS], live=())
        self.assertEqual({k: t['mempool'][k] for _f, k, _w in self.W6B_ROWS}, {k: w for _f, k, w in self.W6B_ROWS})
        # -yellowbackmaxtxfee is not swallowed by the -yellowbackmaxtxfeeusd row, nor the reverse
        _cfg, _notes, t = self.gen(['-yellowbackmaxtxfee=0.5', '-yellowbackmaxtxfeeusd=0.5'], live=())
        self.assertEqual((t['mempool']['yellowback_max_tx_fee'], t['mempool']['yellowback_max_tx_fee_usd_micro']),
                         (50000000, 500000))
        for bad in ('-maxtxfee=0.000000001', '-pqfeeusdperkb=0.0000001', '-pqfeerate=abc', '-maxtxfee=-1',
                    '-yellowbackfee=1.5', '-yellowbackmintlag=x'):
            with self.assertRaises((kg.UnmappedArgument, ValueError), msg=bad):
                self.gen([bad], live=())

    def test_txunpaidactionlimit_row(self):
        _cfg, _notes, t = self.gen(['-txunpaidactionlimit=50'], live=())
        self.assertEqual(t['mempool']['tx_unpaid_action_limit'], 50)

    def test_ignored_rows(self):
        _cfg, notes, t = self.gen(['-yellowbacktestfault=storage:commit', '-yellowbacksignal=0', '-feepolicy=zip317',
                                   '-blockunpaidactionlimit=0', '-mempoolevictionmemoryminutes=1'], live=())
        self.assertNotIn('yellowback', t)
        self.assertEqual(set(t['mempool']), {'debug_enable_at_height'})
        self.assertIn('ignored: -yellowbacktestfault=storage:commit', notes)      # the recorded gap
        self.assertIn('ignored: -mempoolevictionmemoryminutes=1', notes)
        rows = {r[0].split('=')[0]: r for r in kg.ZAKURAD_KEY_TABLE}
        self.assertIn('gap', rows['-yellowbacktestfault'][3])
        for flag in ('-yellowbacksignal', '-feepolicy', '-blockunpaidactionlimit', '-mempoolevictionmemoryminutes'):
            self.assertEqual(rows[flag][1], 'ignored', flag)

    def test_every_live_flag_has_a_table_row(self):
        rows = ' '.join(r[0] for r in kg.ZAKURAD_KEY_TABLE)
        keys = ' '.join(r[2] or '' for r in kg.ZAKURAD_KEY_TABLE)
        for flag, (path, _conv) in kg._LIVE_FLAGS.items():
            self.assertIn(flag, rows)
            self.assertIn('.'.join(path), keys)

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
        self.assertEqual(kg.classify_kogany_block('rejected'), kg.REJECT_CONSENSUS)
        self.assertEqual(kg.classify_kogany_block('something-new'), kg.REJECT_UNCLASSIFIED)
        self.assertEqual(kg.classify_kogany_tx(rpc_error('anything')), kg.REJECT_UNCLASSIFIED)

    # kogany's texts as zakurad answers them (W1-Y9 run of mempool_ycash_parity.py, 2026-11-01, and
    # the Display strings of the W3-d / W4-d errors), each with ycashd's class for the same case.
    KOGANY_TEXTS = [
        ('failed to validate tx: transaction::Hash("private"), error: transaction did not pass consensus '
         'validation: failed to verify ZIP-317 transaction rules, transaction was not inserted to mempool: '
         'Transaction fee is below the minimum fee rate', kg.REJECT_POLICY, '66: min relay fee not met'),
        ('io error: failed to fill whole buffer', kg.REJECT_CONSENSUS, '16: bad-txns-oversize'),
        ('transaction is non-standard', kg.REJECT_POLICY, '64: bad-txns-too-many-sigops'),
        ('failed to validate tx: transaction::Hash("private"), error: transaction did not pass consensus '
         'validation: transaction must not be mined at a block Height(202) greater than its expiry Height(201), '
         'failing transaction', kg.REJECT_POLICY, 'tx-expiring-soon: expiryheight is 201 but should be at least 205'),
        ('failed to validate tx: transaction::Hash("private"), error: transaction did not pass consensus '
         'validation: transaction is locked until after block height 202', kg.REJECT_POLICY, '64: non-final'),
        ('transaction already exists in mempool', kg.ACCEPT, None),
        ('failed to validate tx: transaction::Hash("private"), error: transaction did not pass consensus '
         'validation: could not find transparent input UTXO in the best chain or mempool', kg.REJECT_STATE,
         'Missing inputs'),
        ('failed to validate tx: transaction::Hash("private"), error: transaction did not pass consensus '
         'validation: could not contextually validate transaction on best chain: time-based relative lock-time: '
         'input 0 has nSequence 0x00400005 with BIP68\'s type flag set, which the Vault upgrade makes invalid '
         '(bad-txns-vault-timelock)', kg.REJECT_STATE, '16: bad-txns-vault-timelock'),
        ('failed to validate tx: transaction::Hash("private"), error: transaction did not pass consensus '
         'validation: could not contextually validate transaction on best chain: unsatisfied relative lock-time: '
         'a spend at Height(210) is invalid before Height(215) (bad-txns-nonfinal; non-BIP68-final in the '
         'mempool)', kg.REJECT_POLICY, '64: non-BIP68-final'),
        ('failed to validate tx: transaction::Hash("private"), error: transaction did not pass consensus '
         'validation: could not contextually validate transaction on best chain: vault rule violation in block '
         '00ab at Height(230): bad-txns-vault-covenant', kg.REJECT_STATE, '16: bad-txns-vault-covenant'),
        ('vault rule violation in block 00ab at Height(230): bad-vault-act-sigs', kg.REJECT_STATE,
         '16: bad-vault-act-sigs'),
        ('transaction did not pass consensus validation: bad-yellowback-redeem-burn', kg.REJECT_STATE,
         '16: bad-yellowback-redeem-burn'),
        ('transaction did not pass consensus validation: transparent double-spend: OutPoint { .. } is spent twice',
         kg.REJECT_CONSENSUS, '16: bad-txns-inputs-duplicate'),
        ('transaction rejected because another transaction in the mempool has already spent some of its inputs',
         kg.REJECT_POLICY, '258: txn-mempool-conflict'),
        ('any transaction with the same effects will be rejected from the mempool until a chain reset: '
         'transaction was committed to the best chain', kg.REJECT_POLICY, 'transaction already in block chain'),
        ('failed to validate tx: transaction::Hash("private"), error: transaction did not pass consensus '
         'validation: could not verify a transparent script: script failed to verify', kg.REJECT_CONSENSUS,
         '16: mandatory-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation)'),
        ('transaction did not pass consensus validation: immature transparent coinbase spend: attempt to spend '
         'OutPoint at Height(5)', kg.REJECT_STATE, '16: bad-txns-premature-spend-of-coinbase'),
    ]

    def test_kogany_texts_agree_with_ycashd(self):
        for text, want, cxx in self.KOGANY_TEXTS:
            self.assertEqual(kg.classify_kogany_tx(rpc_error(text)), want, text)
            if cxx is not None:
                unmapped = []
                self.assertEqual(kg.classify_cxx_tx(rpc_error(cxx), unmapped), want, cxx)
                self.assertEqual(unmapped, [], cxx)

    def test_w4d_vault_rejected_texts(self):
        # kogany's own texts, as vault_primitive (KOGANY_MEMPOOL=1) produced them
        tx = ('failed to validate tx: transaction::Hash("private"), error: vault rule violation in the mempool '
              'at Height(204): bad-txns-vault-noset')
        cls, row = kg.classify_kogany_text('tx', tx)
        self.assertEqual((cls, row[2].split()[0]), (kg.REJECT_STATE, 'W4-d'))
        self.assertEqual(kg.classify_cxx_tx(rpc_error('16: bad-txns-vault-noset'), []), kg.REJECT_STATE)
        block = 'vault rule violation in block 005cf604 at Height(204): bad-vault-act-params'
        self.assertEqual(kg.classify_kogany_text('tx', block)[0], kg.REJECT_STATE)
        proposal = ('block-source-validateproposal-vaultrejected-reason-bad-vault-act-params-height-height-204-'
                    'hash-block-hash-005cf604fd85f58c0d02a22e46896c87d80115eef2153a294ce38d3309829130')
        self.assertEqual(kg.classify_kogany_block('rejected', proposal), kg.REJECT_CONSENSUS)
        m = re.search(kg.KOGANY_REASON_MAP[[r[1] for r in kg.KOGANY_REASON_MAP].index(
            r'vaultrejected-reason-(bad-[a-z0-9-]+?)-height-')][1], proposal)
        self.assertEqual(m.group(1), 'bad-vault-act-params')
        # a set opcode failing on the set state: state, as ycashd's main.cpp:2229
        script = ('failed to validate tx: transaction::Hash("private"), error: transaction did not pass consensus '
                  'validation: could not verify a transparent script: PubKey script failed: during interpretation: '
                  'OP_CHECKSETSIG or OP_CHECKSETDORMANT failed')
        self.assertEqual(kg.classify_kogany_tx(rpc_error(script)), kg.REJECT_STATE)

    def test_cxx_rows_carry_ycash6_reason(self):
        cls, row = kg.classify_kogany_text('tx', 'x (bad-txns-vault-timelock) y')
        self.assertEqual((cls, row[2].split()[0]), (kg.REJECT_STATE, 'W3-d'))
        # the same reason in a block is consensus, through the proposal text
        proposal = 'vaultrejected-reason-bad-txns-vault-covenant-height-height-230-hash-hash-00ab'
        self.assertEqual(kg.classify_kogany_block('rejected', proposal), kg.REJECT_CONSENSUS)
        self.assertEqual(kg.classify_kogany_block('rejected', 'time-too-far-in-the-future'), kg.REJECT_STATE)
        self.assertEqual(kg.classify_cxx_block('time-too-new'), kg.REJECT_STATE)
        # a proposal no row names leaves the bare 'rejected'
        self.assertEqual(kg.classify_kogany_block('rejected', 'something-else'), kg.REJECT_CONSENSUS)
        self.assertEqual(kg.classify_kogany_block(None, 'ignored-when-accepted'), kg.ACCEPT)

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
        for path, pattern, cls, src in kg.KOGANY_REASON_MAP:
            self.assertIn(path, ('block', 'tx', 'proposal'))
            self.assertIn(cls, (kg.ACCEPT, kg.CXX) + kg.REJECT_CLASSES)
            self.assertTrue(src)
            rx = re.compile(pattern)
            if cls == kg.CXX:
                self.assertEqual(rx.groups, 1, pattern)


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


class AuthProxyContentTypeTest(unittest.TestCase):
    """authproxy accepts a media type with parameters (Zakura: application/json; charset=utf-8)."""

    def response(self, content_type):
        from test_framework.authproxy import AuthServiceProxy

        class Resp:
            status, reason = 200, 'OK'

            def getheader(self, name):
                return content_type

            def read(self):
                return b'{"result": 7, "error": null, "id": 1}'

        class Conn:
            timeout = 5

            def getresponse(self):
                return Resp()

        return AuthServiceProxy('http://u:p@127.0.0.1:1', connection=Conn())._get_response()

    def test_media_type_parameters(self):
        for ct in ('application/json', 'application/json; charset=utf-8', 'Application/JSON;charset=UTF-8'):
            self.assertEqual(self.response(ct)['result'], 7, ct)
        for ct in ('text/html', None, 'application/jsonx'):
            with self.assertRaises(JSONRPCException, msg=ct):
                self.response(ct)


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


class FakeConn:
    """A ycashd connection whose fullyNotified stays False (a pair backend, or a lagging wallet)."""

    def __init__(self, i, notified=False):
        self.url = 'http://u:p@127.0.0.1:%d' % util.rpc_port(i)
        self.notified = notified
        self.calls = 0

    def getbestblockhash(self):
        return 'aa' * 32

    def getrawmempool(self):
        return []

    def getblockchaininfo(self):
        self.calls += 1
        return {'fullyNotified': self.notified}

    getmempoolinfo = getblockchaininfo


class YewdNotifiedTest(unittest.TestCase):
    """F-S3-1: the fullyNotified wait is skipped for pair nodes only."""

    def setUp(self):
        util.PortSeed.n = 11
        self.saved = set(util.YEWD_PAIRS), os.environ.pop('YEWD_FULLY_NOTIFIED', None)
        util.YEWD_PAIRS.clear()

    def tearDown(self):
        util.YEWD_PAIRS.clear()
        util.YEWD_PAIRS.update(self.saved[0])
        if self.saved[1] is not None:
            os.environ['YEWD_FULLY_NOTIFIED'] = self.saved[1]

    def test_pairs_only(self):
        util.YEWD_PAIRS.add(0)
        pair, plain = FakeConn(0), FakeConn(1, notified=True)
        self.assertTrue(util._sync_blocks([pair, plain], wait=0.01, timeout=1))
        self.assertTrue(util._sync_mempools([pair, plain], wait=0.01, timeout=1))
        self.assertEqual(pair.calls, 0)
        self.assertEqual(plain.calls, 2)

    def test_plain_node_keeps_its_wait(self):
        util.YEWD_PAIRS.add(0)
        lagging = FakeConn(1, notified=False)          # a plain ycashd whose wallet lags
        with self.assertRaises(AssertionError):
            util._sync_blocks([FakeConn(0), lagging], wait=0.01, timeout=0.05)
        self.assertGreater(lagging.calls, 0)

    def test_no_pairs_no_skip(self):
        with self.assertRaises(AssertionError):
            util._sync_blocks([FakeConn(0)], wait=0.01, timeout=0.05)

    def test_fully_notified_env_restores_the_wait(self):
        util.YEWD_PAIRS.add(0)
        os.environ['YEWD_FULLY_NOTIFIED'] = '1'
        try:
            with self.assertRaises(AssertionError):
                util._sync_blocks([FakeConn(0)], wait=0.01, timeout=0.05)
        finally:
            del os.environ['YEWD_FULLY_NOTIFIED']


class YewdWarmupTest(unittest.TestCase):
    """F-S2-9: a 401 before the backend wrote its cookie is warm-up; with the cookie it is a failure."""

    E401 = JSONRPCException({'code': -342, 'message': 'non-JSON response 401: '})

    def test_classification(self):
        self.assertTrue(kg._backend_warming_up(self.E401, had_cookie=False))
        self.assertFalse(kg._backend_warming_up(self.E401, had_cookie=True))
        self.assertTrue(kg._backend_warming_up(JSONRPCException({'code': -28, 'message': 'Loading'}), True))
        self.assertFalse(kg._backend_warming_up(JSONRPCException({'code': -342, 'message': 'non-JSON response 500: x'}), False))
        self.assertFalse(kg._backend_warming_up(JSONRPCException({'code': -1, 'message': 'x'}), False))

    def test_start_retries_a_401_until_the_cookie(self):
        import tempfile
        from unittest import mock
        util.PortSeed.n = 13
        tmp = tempfile.mkdtemp()
        datadir = os.path.join(tmp, 'node0')
        cookie = os.path.join(datadir, 'backend', 'regtest', '.cookie')
        calls = []

        def fake_call(rpc, *args):
            calls.append(os.path.exists(cookie))
            if not os.path.exists(cookie):
                if len(calls) == 2:          # the backend writes its cookie after the second 401
                    os.makedirs(os.path.dirname(cookie), exist_ok=True)
                    with open(cookie, 'w') as f:
                        f.write('__cookie__:x')
                raise self.E401
            return 0

        class Proc:
            returncode = None
            def poll(self):
                return None

        os.environ['YEWD_BIN'] = '/y/yewd'
        try:
            with mock.patch.object(kg.subprocess, 'Popen', side_effect=lambda *a, **k: Proc()), \
                    mock.patch.object(kg.KoganyRPC, '__call__', fake_call), \
                    mock.patch.object(kg.time, 'sleep', lambda s: None):
                kg.start_yewd_pair(0, datadir, '/b/ycashd', [], stderr=None, timeout=5)
                self.assertEqual(calls, [False, False, True])
                # a 401 with the cookie in place is an authentication failure, not a warm-up
                with mock.patch.object(kg.KoganyRPC, '__call__', side_effect=self.E401):
                    with self.assertRaises(JSONRPCException):
                        kg.start_yewd_pair(0, datadir, '/b/ycashd', [], stderr=None, timeout=5)
        finally:
            del os.environ['YEWD_BIN']
            kg.YEWD_BACKENDS.clear()
            import shutil
            shutil.rmtree(tmp)


class FakeRPC:
    """A node answering fixed vault_getinfo / yed_getstatehash results (or raising)."""

    def __init__(self, vault=None, yed=None):
        self.vault, self.yed = vault, yed

    def _answer(self, v):
        if isinstance(v, Exception):
            raise v
        return v

    def vault_getinfo(self):
        return self._answer(self.vault)

    def yed_getstatehash(self):
        return self._answer(self.yed)

    def getbestblockhash(self):
        return 'aa' * 32


class FakeStateFollower:
    k = 0

    def __init__(self, rpc):
        self.rpc = rpc


VINFO = {'branchid': '6d5b7a31', 'activationheight': 200, 'active': True, 'height': 210, 'attestorsetid': None,
         'moduleactive': False, 'dbtip': {'hash': 'aa' * 32, 'height': 210}, 'sets': 1, 'vaults': 1, 'intents': 0,
         'lockedvalue': kg.Decimal('25.00000000'), 'statehash': 'cd' * 32}
MISSING = JSONRPCException({'code': -32601, 'message': 'Method not found'})


class SyncPointTest(unittest.TestCase):

    def run_point(self, ref, kog, strict=False):
        m = kg.MixedLine(binary='/bin/z', strict=strict)
        m._compare_statehash(ref, FakeStateFollower(kog), 'test')
        return m

    def test_equal_state_counts(self):
        kog = dict(VINFO, lockedvalue=25)              # an integer amount compares as a Decimal
        m = self.run_point(FakeRPC(VINFO, MISSING), FakeRPC(kog, MISSING))
        self.assertEqual(m.stats['statehash_vault'], 1)
        self.assertEqual(m.stats['statehash_yed'], 0)

    def test_no_statehash_yet_is_skipped(self):
        w7a = {'branchid': '6d5b7a31', 'activationheight': -1, 'active': False, 'height': 210, 'dbtip': None}
        m = self.run_point(FakeRPC(VINFO, MISSING), FakeRPC(w7a, MISSING))
        self.assertEqual(m.stats['statehash_vault'], 0)
        self.assertTrue(any('W4-d' in n for n in m._notes))
        self.assertTrue(any('activationheight' in n for n in m._notes))
        with self.assertRaises(AssertionError):           # the W7 note is fatal under KOGANY_STRICT
            self.run_point(FakeRPC(VINFO, MISSING), FakeRPC(w7a, MISSING), strict=True)

    def test_state_difference_fails(self):
        for key, value in (('statehash', 'ce' * 32), ('dbtip', {'hash': 'bb' * 32, 'height': 210}),
                           ('vaults', 2), ('lockedvalue', kg.Decimal('24'))):
            with self.assertRaises(AssertionError) as cm:
                self.run_point(FakeRPC(VINFO, MISSING), FakeRPC(dict(VINFO, **{key: value}), MISSING))
            self.assertIn(key, str(cm.exception))

    def test_branch_id_always_compared(self):
        with self.assertRaises(AssertionError):
            self.run_point(FakeRPC(VINFO, MISSING), FakeRPC(dict(VINFO, branchid='00000000', statehash=None), MISSING))

    def test_kogany_without_the_method(self):
        m = self.run_point(FakeRPC(VINFO, MISSING), FakeRPC(MISSING, MISSING))
        self.assertEqual(m.stats['statehash_vault'], 0)
        self.assertTrue(any('not served' in n for n in m._notes))

    def test_yed_statehash(self):
        yed = {'height': 210, 'blockhash': 'aa' * 32, 'statehash': 'ef' * 32}
        m = self.run_point(FakeRPC(VINFO, yed), FakeRPC(VINFO, dict(yed)))
        self.assertEqual(m.stats['statehash_yed'], 1)
        with self.assertRaises(AssertionError):
            self.run_point(FakeRPC(VINFO, yed), FakeRPC(VINFO, dict(yed, statehash='ee' * 32)))
        unavailable = JSONRPCException({'code': -32603, 'message': 'the YED index is not available'})
        m = self.run_point(FakeRPC(VINFO, yed), FakeRPC(VINFO, unavailable))
        self.assertEqual(m.stats['statehash_yed'], 0)


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
        saved = os.environ.pop('KOGANY_LIVE', None)
        try:
            m.on_node_start(0, START + YCASH + VAULT + ['-pqfalconheight=5'], peer)
            self.assertEqual(f.events, [])        # pending row (W3-c): a note, not a key -> no restart
            m.on_node_start(0, START + YCASH + VAULT + ['-yellowbackattestorset=' + SETID], peer)
            self.assertEqual(f.events, ['stop', 'write', 'start'])   # W5-f is live by default: a key
            self.assertEqual(f.config['yellowback'], {'attestor_set': SETID})
            f.events = []
        finally:
            if saved is not None:
                os.environ['KOGANY_LIVE'] = saved
        m.on_node_start(1, START + ['-frobnicate'], peer)   # not the peer: ignored
        self.assertEqual(f.events, [])
        self.assertEqual(peer.added, [('127.0.0.1:%d' % kg.kogany_p2p_port(0), 'onetry')] * 3)

    def test_invalidate_hint(self):
        class Script:                              # a class defined here: this file names the calls
            pass
        self.assertTrue(kg._calls_invalidate(Script))
        self.assertFalse(kg._calls_invalidate(int))
        m = kg.MixedLine(binary='/bin/z')
        m.script_invalidates = kg._calls_invalidate(Script)
        self.assertIn('KOGANY_MIRROR_INVALIDATE=1', m.invalidate_hint())
        m.mirror_invalidate = True
        self.assertIsNone(m.invalidate_hint())
        m = kg.MixedLine(binary='/bin/z')
        self.assertIsNone(m.invalidate_hint())  # a script without the calls: no hint
        inert = kg.MixedLine()
        inert.script_invalidates = True
        self.assertIsNone(inert.invalidate_hint())
        m = kg.MixedLine(binary='/bin/z')
        m.script_invalidates = True
        from io import StringIO
        from contextlib import redirect_stdout
        out = StringIO()
        with redirect_stdout(out):
            m.stop()
        self.assertIn('KOGANY_MIRROR_INVALIDATE', out.getvalue())

    # the source this file must contain for test_invalidate_hint: node.invalidateblock(h)

    def test_strict_note_fails(self):
        m = kg.MixedLine(binary='/bin/z', strict=True)
        with self.assertRaises(AssertionError):
            m.note('x')


class FakeChain:
    """A node's active chain for the rig's feed: ``blocks`` is the list of hashes from height 0."""

    def __init__(self, blocks, k=0, verdict=None):
        self.blocks = list(blocks)
        self.k = k
        self.submitted = []
        self.verdict = verdict           # submitblock's answer (None: accepted)
        self.rpc = self
        self.datadir = '/tmp/fake%d' % k

    def getbestblockhash(self):
        return self.blocks[-1]

    def getblockcount(self):
        return len(self.blocks) - 1

    def getblockhash(self, h):
        return self.blocks[h]

    def getblock(self, h, verbosity=1):
        return 'raw-' + h

    def submitblock(self, block_hex):
        self.submitted.append(block_hex)
        if self.verdict is None:
            self.blocks.append(block_hex[4:])
        return self.verdict


class FakeKogany(FakeFollower):
    """A KoganyNode stand-in for start_sidecar (alive between start and stop)."""

    started = []

    def __init__(self, k, tmpdir, binary, extra_args=()):
        super().__init__(k)
        self.datadir = os.path.join(tmpdir, 'kogany%d' % k)
        self.running = False
        FakeKogany.started.append(k)

    def alive(self):
        return self.running

    def start(self):
        super().start()
        self.running = True

    def stop(self):
        super().stop()
        self.running = False


class SidecarRigTest(unittest.TestCase):
    """KOGANY_SIDECAR=1: the W9-a test rig (kogany i + a ycashd -connect'ed to it on node i)."""

    def setUp(self):
        util.PortSeed.n = 11
        self.saved_env = {k: os.environ.get(k) for k in ('KOGANY_SIDECAR', 'KOGANY_BIN', 'KOGANY_ARGS')}
        self.saved_node = kg.KoganyNode
        kg.SIDECAR_NODES.clear()

    def tearDown(self):
        for k, v in self.saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        kg.KoganyNode = self.saved_node
        kg.SIDECAR_NODES.clear()
        kg._CURRENT[0] = kg.MixedLine()

    def test_enabled_needs_both(self):
        self.assertTrue(kg.sidecar_enabled({'KOGANY_SIDECAR': '1', 'KOGANY_BIN': '/bin/z'}))
        self.assertFalse(kg.sidecar_enabled({'KOGANY_SIDECAR': '1'}))
        self.assertFalse(kg.sidecar_enabled({'KOGANY_SIDECAR': '0', 'KOGANY_BIN': '/bin/z'}))
        self.assertFalse(kg.sidecar_enabled({'KOGANY_BIN': '/bin/z'}))
        m = kg.MixedLine.from_env({'KOGANY_SIDECAR': '1', 'KOGANY_BIN': '/bin/z', 'KOGANY_SIDECAR_PUMP_AFTER': '9'})
        self.assertTrue(m.sidecar)
        self.assertEqual(m.pump_after, 9.0)
        self.assertIn('pumped_blocks', m.stats)
        self.assertFalse(kg.MixedLine.from_env({'KOGANY_SIDECAR': '1'}).sidecar)   # no binary: inert
        self.assertFalse(kg.MixedLine.from_env({'KOGANY_BIN': '/bin/z'}).sidecar)

    def test_ycashd_args(self):
        args = kg.sidecar_ycashd_args(3, ['-listen=1', '-debug=net'])
        self.assertEqual(args, ['-listen=1', '-debug=net', '-connect=127.0.0.1:%d' % util.p2p_port(3), '-listen=0',
                                '-port=%d' % kg.sidecar_dead_port(3)])
        used = ({util.p2p_port(i) for i in range(util.MAX_NODES + 1)} | {util.rpc_port(i) for i in range(util.MAX_NODES + 1)}
                | {f(k) for f in (kg.kogany_p2p_port, kg.kogany_rpc_port, kg.kogany_v2_port, kg.yewd_rpc_port,
                                  kg.yewd_backend_rpc_port) for k in range(util.MAX_NODES + 1)})
        dead = {kg.sidecar_dead_port(i) for i in range(util.MAX_NODES + 1)}
        self.assertEqual(dead & used, set())
        self.assertLess(max(dead), 65536)

    def test_isolation_check(self):
        m = kg.MixedLine(binary='/bin/z', sidecar=True)
        k = FakeChain(['g'])
        k.getpeerinfo = lambda: [{'addr': '127.0.0.1:1', 'inbound': True}]
        m._check_isolated(k)
        k.getpeerinfo = lambda: [{'addr': '127.0.0.1:1', 'inbound': True}, {'addr': '127.0.0.1:2', 'inbound': False}]
        with self.assertRaises(AssertionError):
            m._check_isolated(k)

    def test_kogany_config(self):
        cfg, _notes = kg.sidecar_kogany_config(START + YCASH + VAULT, 2, '/tmp/k2', live=('W1-Y1', 'W2-b'))
        net = cfg['network']
        self.assertEqual(net['listen_addr'], '127.0.0.1:%d' % util.p2p_port(2))
        self.assertEqual(net['initial_testnet_peers'], [])
        self.assertEqual(net['max_connections_per_ip'], kg.SIDECAR_MAX_CONNS_PER_IP)
        self.assertGreater(kg.SIDECAR_MAX_CONNS_PER_IP, util.MAX_NODES)   # one inbound per ycashd on 127.0.0.1
        self.assertEqual(net['p2p_stack'], 'legacy')
        self.assertEqual(net['network']['params']['activation_heights']['Vault'], 103)
        self.assertEqual(cfg['rpc']['listen_addr'], '127.0.0.1:%d' % kg.kogany_rpc_port(2))
        # the rig's own -connect/-listen in the arguments are ignored rows, never refused
        cfg2, _ = kg.sidecar_kogany_config(kg.sidecar_ycashd_args(2, START), 2, '/tmp/k2', live=())
        self.assertEqual(cfg2['network']['listen_addr'], net['listen_addr'])
        tomllib.loads(kg.render_toml(cfg, _notes))

    def test_start_sidecar_keeps_or_restarts(self):
        os.environ.update({'KOGANY_SIDECAR': '1', 'KOGANY_BIN': '/bin/z'})
        os.environ.pop('KOGANY_ARGS', None)
        kg.KoganyNode = FakeKogany
        FakeKogany.started = []
        m = kg.MixedLine.from_env()
        kg._CURRENT[0] = m
        args = kg.start_sidecar(1, '/tmp/run', START + YCASH)
        self.assertEqual(args[-3:], ['-connect=127.0.0.1:%d' % util.p2p_port(1), '-listen=0', '-port=%d' % kg.sidecar_dead_port(1)])
        k = kg.SIDECAR_NODES[1]
        self.assertEqual(k.datadir, '/tmp/run/kogany1')
        self.assertEqual(k.events, ['stop', 'write', 'start'])
        self.assertEqual(m.followers, [k])
        self.assertTrue(m.active)
        k.events = []
        kg.start_sidecar(1, '/tmp/run', START + YCASH + ['-keypool=5'])       # a wallet option: kept running
        self.assertEqual(k.events, [])
        kg.start_sidecar(1, '/tmp/run', START + YCASH + VAULT + ['-acceptnonstdtxn=1'])   # a kogany key: restart
        self.assertEqual(k.events, ['stop', 'write', 'start'])
        self.assertEqual(k.config['mempool']['accept_non_standard'], True)
        k.running = False                                                       # died: started again
        k.events = []
        kg.start_sidecar(1, '/tmp/run', START + YCASH + VAULT + ['-acceptnonstdtxn=1'])
        self.assertEqual(k.events, ['stop', 'write', 'start'])
        self.assertEqual(FakeKogany.started, [1])                               # one KoganyNode per node
        self.assertEqual(m.followers, [k])

    def test_on_node_start_and_pairs(self):
        m = kg.MixedLine(binary='/bin/z', sidecar=True)
        m.on_node_start(0, ['-frobnicate'], None)        # the rig never maps a peer's arguments here
        self.assertIsNone(m.peer_args)
        a, b = FakeChain(['g'], 0), FakeChain(['g'], 2)
        kg.SIDECAR_NODES.update({0: a, 2: b})
        c0, c1, c2 = FakeConn(0), FakeConn(1), FakeConn(2)
        self.assertEqual(m._pairs([c0, c1, c2]), [(c0, a), (c2, b)])   # node 1 has no kogany: skipped
        self.assertEqual(m._pairs([c1]), [])

    def test_pump_feeds_from_the_common_ancestor(self):
        m = kg.MixedLine(binary='/bin/z', sidecar=True)
        ref = FakeChain(['g', 'a1', 'a2', 'a3', 'a4'])
        kog = FakeChain(['g', 'a1', 'x2'])               # on a side branch from height 2
        m._pump(ref, kog, kog.getbestblockhash())
        self.assertEqual(kog.submitted, ['raw-a2', 'raw-a3', 'raw-a4'])
        self.assertEqual((m.stats['pumped_blocks'], m.stats['pump_rounds']), (3, 1))
        m._pump(ref, kog, ref.getbestblockhash())        # at the tip: nothing
        ahead = FakeChain(['g', 'a1', 'a2', 'a3', 'a4', 'a5'])
        m._pump(ref, ahead, ahead.getbestblockhash())     # kogany ahead: nothing to feed
        self.assertEqual(ahead.submitted, [])
        m.pump_batch = 2
        kog = FakeChain(['g'])
        m._pump(ref, kog, 'g')
        self.assertEqual(kog.submitted, ['raw-a1', 'raw-a2'])
        for verdict in ('duplicate', 'inconclusive'):
            m._pump(ref, FakeChain(['g'], verdict=verdict), 'g')

    def test_judges(self):
        m = kg.MixedLine(binary='/bin/z', sidecar=True)
        a, b = FakeChain(['g'], 0), FakeChain(['g'], 1)
        kg.SIDECAR_NODES.update({0: a, 1: b})
        m.followers = [a, b]
        self.assertEqual(m._judges(FakeConn(1)), [b])          # the node's own kogany judges its verdict
        self.assertEqual(m._judges(FakeConn(4)), [])           # a node without a kogany: nobody
        self.assertEqual(m._judges(None), [a, b])              # no node named: every kogany
        plain = kg.MixedLine(binary='/bin/z')
        plain.followers = [a]
        self.assertEqual(plain._judges(FakeConn(1)), [a])      # the follower mode ignores the node

    def test_pump_refusal_is_a_divergence(self):
        m = kg.MixedLine(binary='/bin/z', sidecar=True)
        with self.assertRaises(AssertionError) as cm:
            m._pump(FakeChain(['g', 'a1']), FakeChain(['g'], verdict='rejected'), 'g')
        self.assertIn('refused block 1', str(cm.exception))

    def test_sync_wait_grace(self):
        m = kg.MixedLine(binary='/bin/z', sidecar=True, pump_after=5)
        ref, kog = FakeChain(['g', 'a1']), FakeChain(['g'], 0)
        ref.url = FakeConn(0).url
        kg.SIDECAR_NODES[0] = kog
        m.followers = [kog]
        m.sync_wait([ref], 1)
        self.assertEqual(kog.submitted, [])
        m.sync_wait([ref], 5)
        self.assertEqual(kog.submitted, ['raw-a1'])
        plain = kg.MixedLine(binary='/bin/z')               # the follower mode never feeds
        plain.followers = [kog]
        plain.sync_wait([ref], 60)
        self.assertEqual(kog.submitted, ['raw-a1'])

    def test_register_installs_the_wait_hook(self):
        m = kg.MixedLine(binary='/bin/z', sidecar=True)
        saved = dict(util.MIXED_HOOKS)
        try:
            kg._register(m)
            self.assertEqual(util.MIXED_HOOKS['sync_wait'], m.sync_wait)
        finally:
            util.MIXED_HOOKS.clear()
            util.MIXED_HOOKS.update(saved)


if __name__ == '__main__':
    unittest.main()
