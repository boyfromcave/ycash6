#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The vault RPC contract (doc/vault-rpc-contract.json, generated from doc/vault-rpc.md by
qa/vault-rpc-contract.py; upgrade plan finding (47)): every set_* / vault_* command's live answer
is checked against its documented result shape (every documented field present unless optional,
nothing undocumented, every value of its documented type and unit: amounts in YEC decimals,
*zat fields in zatoshi), and every documented error reason is provoked and checked for its code.

One node, one set (1 seat, every threshold 1), a second empty set for the "no member" cases:
joins, heartbeats through set_heartbeat and through set_buildact / set_signact / set_sendact,
each set_buildact type, vault_lock (with and without an APP branch), unlock -> intent ->
release, a cancel built and signed (not sent), the APP spend through vault_app + vault_send, an
equivocation proof from two set_signunlock answers over one outpoint, and the owner spend that
the ejection's dormancy opens (selector 3).

    ZCASHD=<ycashd> ../.venv/bin/python -u qa/rpc-tests/vault_rpc_contract.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import VAULT_BRANCH_ID, assert_equal, nuparams, start_nodes
from test_framework import vault
from test_framework.vault import bond_script
from test_framework.yellowback_util import pubkey_to_address, wif_to_secret
from test_framework.vault_contract import Contract
from test_framework.yellowback_util import YCASH_UPGRADE_ARGS

ACTIVATION = 205
DELAY = 3


class VaultRpcContractTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        # 6.20.0: the 200-block cache is built without the Ycash upgrades the harness activates at
        # height 1, so the chain starts clean (the node mines its own funds on the way to activation).
        self.cache_behavior = 'clean'

    def setup_network(self, split=False):
        self.nodes = start_nodes(1, self.options.tmpdir, extra_args=[YCASH_UPGRADE_ARGS + [nuparams(VAULT_BRANCH_ID, ACTIVATION), '-debug=vault']])
        self.is_network_split = False

    def run_test(self):
        n = self.nodes[0]
        c = Contract()
        mine = n.generate

        # ---- before activation ----
        info = c.call(n, 'vault_getinfo')
        assert_equal(info['active'], False)
        c.error('is not active at the next block', n, 'set_create', {'seats': 1, 'unlockthreshold': 1})
        mine(ACTIVATION - n.getblockcount())

        # ---- sets ----
        c.error('the set parameters are out of range', n, 'set_create', {'seats': 16, 'unlockthreshold': 1})
        r = c.call(n, 'set_create', {'seats': 1, 'unlockthreshold': 1, 'cancelthreshold': 1, 'slashthreshold': 1,
                                     'maturity': 1, 'livenesswindow': 100, 'bondmin': Decimal('0.5')})
        setid = r['setid']
        empty = c.call(n, 'set_create', {'seats': 2, 'unlockthreshold': 1, 'ratelimitbps': 5000, 'ratewindow': 10})['setid']
        mine(1)
        sets = c.call(n, 'set_list')
        assert_equal(sorted(s['setid'] for s in sets), sorted([setid, empty]))
        info = c.call(n, 'set_getinfo', setid)
        assert 'unlockavailable' not in info              # not rate limited
        assert_equal(info['bondmin'], Decimal('0.5'))     # YEC, not zatoshi
        rated = c.call(n, 'set_getinfo', empty, n.getblockcount() + 1)
        assert_equal(rated['unlockavailable'], Decimal('0'))
        c.error('unknown set', n, 'set_getinfo', '00' * 32)
        c.error('this wallet holds no current member key of the set', n, 'set_heartbeat', empty)

        lock = n.getblockcount() + 500
        j = c.call(n, 'set_join', setid, 1, lock)
        assert_equal(j['complete'], True)
        key = j['memberkey']
        mine(2)
        c.error('bad-vault-act-seats', n, 'set_join', setid, 1, lock)
        c.call(n, 'set_heartbeat', setid)
        mine(1)

        # ---- set_buildact / set_signact / set_sendact ----
        hb = c.call(n, 'set_buildact', 'heartbeat', {'setid': setid, 'memberkey': key})
        assert_equal((hb['type'], hb['complete'], hb['signatures'], hb['required']), ('heartbeat', False, 0, 1))
        hb = c.call(n, 'set_signact', hb['hex'], setid)
        assert_equal(hb['complete'], True)
        hb_txid = c.call(n, 'set_sendact', hb['hex'])
        for typ, params in (('create', {'seats': 1, 'unlockthreshold': 1}),
                            ('join', {'setid': setid, 'bondamount': 1, 'bondlocktime': lock}),
                            ('remove', {'setid': setid, 'memberkey': key, 'burn': False}),
                            ('winddown', {'setid': empty})):
            assert_equal(c.call(n, 'set_buildact', typ, params)['type'], typ)
        c.error('unknown act type', n, 'set_buildact', 'bogus', {})
        mine(1)

        # ---- vault_lock, vault_list, vault_decodescript ----
        h = n.getblockcount()
        c.error('vault parameters out of range', n, 'vault_lock',
                {'tag': 'TEST', 'setid': setid, 'delay': 0, 'ownerheight': h + 100, 'amount': 1})
        lk = c.call(n, 'vault_lock', {'tag': 'TEST', 'setid': setid, 'delay': DELAY, 'ownerheight': h + 200, 'amount': 5})
        app_height = h + 12
        lk_app = c.call(n, 'vault_lock', {'tag': 'TEST', 'setid': setid, 'delay': DELAY, 'ownerheight': h + 200,
                                          'appheight': app_height, 'amount': 2})
        mine(1)
        vaults = c.call(n, 'vault_list', {'kind': 'vault'})
        assert_equal(sorted(v['valuezat'] for v in vaults), [200000000, 500000000])
        c.error('kind must be vault or intent', n, 'vault_list', {'kind': 'coin'})
        assert_equal(c.call(n, 'vault_decodescript', lk['script'])['type'], 'vault')
        assert_equal(c.call(n, 'vault_decodescript', '51')['type'], 'none')
        act_spk = [o['scriptPubKey']['hex'] for o in n.getrawtransaction(hb_txid, 1)['vout'] if o['scriptPubKey']['hex'].startswith('6a')][0]
        dec = c.call(n, 'vault_decodescript', act_spk)
        assert_equal((dec['type'], dec['acttype']), ('act', 'heartbeat'))
        bond = c.call(n, 'vault_decodescript', bond_script(bytes.fromhex(key), lock).hex())
        assert_equal((bond['type'], bond['locktime']), ('bond', lock))

        # ---- unlock -> intent; cancel built; release ----
        addr = n.getnewaddress()
        c.error("the recipients' amounts exceed the vault's value", n, 'vault_buildunlock', lk['outpoint'], [{'address': addr, 'amount': 6}])
        bu = c.call(n, 'vault_buildunlock', lk['outpoint'], [{'address': addr, 'amount': 2}])
        c.error('the transaction carries no YV act', n, 'set_signact', bu['hex'])
        c.error('the template input is not an intent', n, 'set_signcancel', bu['hex'])
        su = c.call(n, 'set_signunlock', bu['hex'])
        assert_equal(su['complete'], True)
        txid = c.call(n, 'vault_send', su['hex'])
        intent_op = '%s:%d' % (txid, bu['intents'][0]['vout'])
        mine(1)
        intents = c.call(n, 'vault_list', {'kind': 'intent'})
        assert_equal([i['outpoint'] for i in intents], [intent_op])
        assert_equal(c.call(n, 'vault_decodescript', intents[0]['script'])['type'], 'intent')
        bc = c.call(n, 'vault_buildcancel', intent_op)
        assert_equal(bc['intentconfirmed'], True)
        c.error('the template input is not a vault', n, 'set_signunlock', bc['hex'])
        assert_equal(c.call(n, 'set_signcancel', bc['hex'])['complete'], True)
        c.error('matures at height', n, 'vault_release', intent_op)
        mine(DELAY)
        c.error('can no longer be cancelled', n, 'vault_buildcancel', intent_op)
        c.call(n, 'vault_release', intent_op)
        mine(1)
        c.error('not an unspent intent output', n, 'vault_buildcancel', intent_op)
        c.error('not an unspent vault output', n, 'vault_buildunlock', lk['outpoint'], [{'address': addr, 'amount': 1}])
        relock = [v for v in c.call(n, 'vault_list', {'kind': 'vault'}) if v['valuezat'] == 300000000][0]['outpoint']

        # ---- the APP branch ----
        c.error('has no APP branch', n, 'vault_app', relock)
        assert n.getblockcount() + 1 <= app_height
        c.error('the APP branch opens at height', n, 'vault_app', lk_app['outpoint'])
        mine(app_height - n.getblockcount())
        ap = c.call(n, 'vault_app', lk_app['outpoint'], [{'address': addr, 'amount': 1}])
        c.call(n, 'vault_send', ap['hex'])
        mine(1)

        # ---- equivocation, then the owner spend its dormancy opens ----
        c.error('owner branch opens at height', n, 'vault_ownerspend', relock, addr)
        a = c.call(n, 'set_signunlock', c.call(n, 'vault_buildunlock', relock, [{'address': addr, 'amount': 1}])['hex'])
        bu_b = c.call(n, 'vault_buildunlock', relock, [{'address': addr, 'amount': 2}])
        c.error('set-sign-once', n, 'set_signunlock', bu_b['hex'])         # the wallet never equivocates (sign once)
        # The second signature, made outside the wallet with the member's key (as a faulty or malicious signer would).
        tx_b = vault.tx_from_hex(bu_b['hex'])
        coin = n.gettxout(relock.split(':')[0], int(relock.split(':')[1]))
        sh_b = vault.template_sighash(tx_b, 0, bytes.fromhex(coin['scriptPubKey']['hex']), int(coin['value'] * 100000000))
        secret = wif_to_secret(n.dumpprivkey(pubkey_to_address(bytes.fromhex(key))))
        msg_b = vault.set_sig_msg(bytes.fromhex(setid)[::-1], 1, relock.split(':')[0], int(relock.split(':')[1]), sh_b)
        sig_b = vault.sign_recoverable(secret, msg_b)
        sh_a = vault.template_sighash(vault.tx_from_hex(a['hex']), 0, bytes.fromhex(coin['scriptPubKey']['hex']), int(coin['value'] * 100000000))
        assert_equal(sh_a.hex(), a['sighash'])                              # the framework's sighash is the node's
        assert_equal(vault.recover_compact(bytes.fromhex(a['setsigs'][0]['sig']),
                                           vault.set_sig_msg(bytes.fromhex(setid)[::-1], 1, relock.split(':')[0], int(relock.split(':')[1]), sh_a)).hex(), key)
        sighash_b = sh_b.hex()
        assert a['sighash'] != sighash_b
        proof = {'setid': setid, 'prevout': relock, 'rolea': 1, 'sighasha': a['sighash'], 'siga': a['setsigs'][0]['sig'],
                 'roleb': 1, 'sighashb': sighash_b, 'sigb': sig_b.hex()}
        c.call(n, 'set_equivocation', proof)
        mine(1)
        info = c.call(n, 'set_getinfo', setid)
        assert_equal(info['memberlist'][0]['status'], 'ejected')
        assert_equal(info['released'], True)
        assert_equal(c.call(n, 'vault_ownerspend', relock, addr)['selector'], 3)
        mine(1)
        assert_equal(c.call(n, 'vault_getinfo')['active'], True)

        c.assert_complete()


if __name__ == '__main__':
    VaultRpcContractTest().main()
