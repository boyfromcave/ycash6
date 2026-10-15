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
the ejection's dormancy opens (selector 3): owners are post-quantum keys (quantum plan §4.3); a
vault with an external owner (a pqkeyid) is refused by vault_ownerspend and signed with
test_framework/pq.py, one with a wallet owner (vault_lock's default, vault_getnewowner) is spent by
vault_ownerspend.

    ZCASHD=<ycashd> ../.venv/bin/python -u qa/rpc-tests/vault_rpc_contract.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import VAULT_BRANCH_ID, assert_equal, connect_nodes_bi, nuparams, start_nodes, sync_blocks
from test_framework import vault
from test_framework.vault import bond_script
from test_framework.yellowback_util import pubkey_to_address, wif_to_secret
from test_framework.vault_contract import Contract
from test_framework.yellowback_util import YCASH_UPGRADE_ARGS

OWNER = vault.pq_owner_secret('vault-rpc-contract-owner')   # SLH-DSA
OWNER_ID = vault.pq_owner_of(OWNER).hex()

ACTIVATION = 205
DELAY = 3


class VaultRpcContractTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        # 6.20.0: the 200-block cache is built without the Ycash upgrades the harness activates at
        # height 1, so the chain starts clean (the node mines its own funds on the way to activation).
        self.cache_behavior = 'clean'

    def setup_network(self, split=False):
        # node 1 stands for a second host that imports node 0's member key (07/F-5: the restore marker)
        self.nodes = start_nodes(2, self.options.tmpdir, extra_args=[YCASH_UPGRADE_ARGS + [nuparams(VAULT_BRANCH_ID, ACTIVATION), '-debug=vault']] * 2)
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

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
                                     'maturity': 2, 'livenesswindow': 100, 'bondmin': Decimal('0.5')})
        setid = r['setid']
        # D-Q-31 (audit 07/F-9): set_create refuses a maturity below the network's minimum (2 on regtest) ...
        try:
            n.set_create({'seats': 1, 'unlockthreshold': 1, 'maturity': vault.MIN_SET_MATURITY_REGTEST - 1})
            raise AssertionError('set_create accepted maturity 1')
        except JSONRPCException as e:
            assert_equal(e.error['code'], -8)   # RPC_INVALID_PARAMETER
            assert 'maturity must be at least %d blocks' % vault.MIN_SET_MATURITY_REGTEST in e.error['message'], e.error
        # ... and, given none, uses it (checked on `empty` below).
        empty = c.call(n, 'set_create', {'seats': 2, 'unlockthreshold': 1, 'ratelimitbps': 5000, 'ratewindow': 10})['setid']
        mine(1)
        assert_equal(c.call(n, 'set_getinfo', empty)['maturity'], vault.MIN_SET_MATURITY_REGTEST)
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
                {'tag': 'TEST', 'setid': setid, 'delay': 0, 'ownerheight': h + 100, 'amount': 1, 'owner': OWNER_ID})
        c.error('ownerkey-removed', n, 'vault_lock', {'tag': 'TEST', 'setid': setid, 'delay': DELAY, 'ownerheight': h + 200,
                                                      'amount': 5, 'ownerkey': '02' + '11' * 32})
        c.error('unknown post-quantum scheme', n, 'vault_getnewowner', 3)
        own = c.call(n, 'vault_getnewowner')
        assert_equal(own['owner'], '01' + own['keyhash'])
        c.error('a scheme-2 (FN-DSA-512) owner before Falcon is active', n, 'vault_lock',
                {'tag': 'TEST', 'setid': setid, 'delay': DELAY, 'ownerheight': h + 200, 'amount': 5, 'owner': '02' + '11' * 32})
        c.error('unregistered post-quantum scheme', n, 'vault_lock',
                {'tag': 'TEST', 'setid': setid, 'delay': DELAY, 'ownerheight': h + 200, 'amount': 5, 'owner': '03' + '11' * 32})
        lk = c.call(n, 'vault_lock', {'tag': 'TEST', 'setid': setid, 'delay': DELAY, 'ownerheight': h + 200, 'amount': 5,
                                      'owner': OWNER_ID})
        app_height = h + 12
        c.error('appheight on a tag no module governs', n, 'vault_lock',
                {'tag': 'TEST', 'setid': setid, 'delay': DELAY, 'ownerheight': h + 200, 'appheight': app_height, 'amount': 2})
        # YED\0 is registered but governs no set on this node (no attestor set): the wallet refuses too
        c.error('appheight on a tag no module governs', n, 'vault_lock',
                {'tag': '59454400', 'setid': setid, 'delay': DELAY, 'ownerheight': h + 200, 'appheight': app_height, 'amount': 2})
        # The APP vault for vault_app below, built raw (consensus admits an APP branch on the registered YED\0, V-1;
        # this test's node has no attestor set, so nothing governs it -- the residual the wallet refuses to build).
        app_owner = c.call(n, 'vault_getnewowner')['owner']          # a wallet owner (vault_ownerspend below)
        app_vp = vault.VaultParams(b'YED\x00', bytes.fromhex(setid)[::-1], bytes.fromhex(setid)[::-1], DELAY, h + 200,
                                   app_height, bytes.fromhex(app_owner))
        fund, total = vault.node_funding(n, 2 * vault.COIN + vault.VAULT_FEE)
        change = (total - 2 * vault.COIN - vault.VAULT_FEE, vault.node_spk(n))
        app_txid = vault.node_send(n, vault.node_sign(n, vault.build_lock_tx(fund, app_vp, 2 * vault.COIN, change)))
        lk_app = {'outpoint': '%s:0' % app_txid, 'owner': app_owner}
        assert_equal(c.call(n, 'vault_decodescript', vault.vault_script(app_vp).hex())['setid'], setid)
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
        assert_equal(bu['build'], 'new')
        assert_equal(c.call(n, 'vault_buildunlock', lk['outpoint'], [{'address': addr, 'amount': 2}])['hex'], bu['hex'])   # call once (07/N-2)
        c.error('already built a different unlock', n, 'vault_buildunlock', lk['outpoint'], [{'address': addr, 'amount': 1}])
        c.error('the transaction carries no YV act', n, 'set_signact', bu['hex'])
        c.error('the template input is not an intent', n, 'set_signcancel', bu['hex'])
        su = c.call(n, 'set_signunlock', bu['hex'])
        assert_equal(su['complete'], True)
        assert_equal(su['sighash'], bu['sighash'])
        rf = c.call(n, 'vault_refee', su['hex'])                     # 01/V-2: new fee input, same signatures
        assert_equal(rf['sighash'], su['sighash'])
        assert_equal(len(rf['replaced']), 1)
        txid = c.call(n, 'vault_send', rf['hex'])
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
        c.error('set-sign-invalid', n, 'set_signcancel', bc['hex'])        # signed in time; refused once matured
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
        bu_a = c.call(n, 'vault_buildunlock', relock, [{'address': addr, 'amount': 1}])
        a = c.call(n, 'set_signunlock', bu_a['hex'])
        bu_b = c.call(n, 'vault_buildunlock', relock, [{'address': addr, 'amount': 2}], True)   # rebuild after signing: the hazard
        c.error('set-sign-once', n, 'set_signunlock', bu_b['hex'])         # the wallet never equivocates (sign once)
        # 07/F-5: a second host that imports the member key has no sign-once history: it refuses until it imports one
        m = self.nodes[1]
        sync_blocks(self.nodes)
        m.importprivkey(n.dumpprivkey(pubkey_to_address(bytes.fromhex(key))), '', False)
        assert_equal(c.call(m, 'set_listsigned')['restored'], True)
        c.error('set-sign-restored', m, 'set_signunlock', bu_b['hex'])
        listed = c.call(n, 'set_listsigned')
        assert_equal(listed['restored'], False)
        assert {'setid': setid, 'prevout': relock, 'role': 1, 'sighash': a['sighash']} in listed['records'], listed
        assert_equal(c.call(m, 'set_importsigned', []), {'imported': 0, 'present': 0})
        assert_equal(c.call(m, 'set_listsigned')['restored'], True)          # an empty import clears nothing (S2)
        imp = c.call(m, 'set_importsigned', listed['records'])
        assert_equal((imp['imported'], imp['present']), (len(listed['records']), 0))
        assert_equal(c.call(m, 'set_listsigned')['restored'], True)          # nor does a real one: it may be stale
        assert_equal(c.call(m, 'set_acknowledgerestore')['restored'], False) # only the operator's acknowledgement
        c.error('set-sign-once', m, 'set_signunlock', bu_b['hex'])         # now the real guard
        assert_equal(c.call(m, 'set_signunlock', bu_a['hex'])['sighash'], a['sighash'])   # identical: idempotent
        conflict = dict(listed['records'][-1], sighash='00' * 32)
        c.error('set-sign-once', m, 'set_importsigned', [conflict])        # two histories are never merged
        # The second signature, made outside the wallet with the member's key (as a faulty or malicious signer would).
        tx_b = vault.tx_from_hex(bu_b['hex'])
        coin = n.gettxout(relock.split(':')[0], int(relock.split(':')[1]))
        sh_b = vault.set_sighash(tx_b, 0, bytes.fromhex(coin['scriptPubKey']['hex']), int(coin['value'] * 100000000))
        secret = wif_to_secret(n.dumpprivkey(pubkey_to_address(bytes.fromhex(key))))
        msg_b = vault.set_sig_msg(bytes.fromhex(setid)[::-1], 1, relock.split(':')[0], int(relock.split(':')[1]), sh_b)
        sig_b = vault.sign_recoverable(secret, msg_b)
        sh_a = vault.set_sighash(vault.tx_from_hex(a['hex']), 0, bytes.fromhex(coin['scriptPubKey']['hex']), int(coin['value'] * 100000000))
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
        c.error('not a post-quantum key of this wallet', n, 'vault_ownerspend', relock, addr)
        coin = n.gettxout(relock.split(':')[0], int(relock.split(':')[1]))
        otx = vault.build_owner_spend_tx((relock.split(':')[0], int(relock.split(':')[1])),
                                         bytes.fromhex(coin['scriptPubKey']['hex']), int(coin['value'] * 100000000), OWNER,
                                         bytes.fromhex(n.validateaddress(addr)['scriptPubKey']), vault.SEL_OWNER_RELEASED)
        n.sendrawtransaction(vault.tx_hex(otx))
        mine(1)
        assert_equal(n.gettxout(relock.split(':')[0], int(relock.split(':')[1])), None)
        # the APP spend's re-lock keeps the wallet owner: vault_ownerspend signs it (selector 3)
        rest = c.call(n, 'vault_list', {'owner': lk_app['owner'], 'kind': 'vault'})
        assert_equal(len(rest), 1)
        assert_equal(rest[0]['wallet'], True)
        assert_equal(c.call(n, 'vault_ownerspend', rest[0]['outpoint'], addr)['selector'], 3)
        mine(1)
        assert_equal(c.call(n, 'vault_getinfo')['active'], True)

        # ---- set_leave (the bond exit delay, owner 2026-10-11): a member's own SET_REMOVE ----
        lset = c.call(n, 'set_create', {'seats': 1, 'unlockthreshold': 1, 'maturity': 2})['setid']
        mine(1)
        lj = c.call(n, 'set_join', lset, 1, n.getblockcount() + 1)
        mine(1)
        lv = c.call(n, 'set_leave', lset)
        assert_equal((lv['memberkey'], lv['bondspendableat'] - lv['exitheight']), (lj['memberkey'], 2))
        mine(1)
        assert_equal(c.call(n, 'set_getinfo', lset)['memberlist'][0]['status'], 'removed')

        c.assert_complete()


if __name__ == '__main__':
    VaultRpcContractTest().main()
