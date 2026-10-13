#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The post-quantum key lookahead (review B I-2; 6.20.0 1b023d1d6, ycash-dd c308ea44c): a wallet restored from the
same seed re-finds the PQ keys issued after it was saved; quantum review F-1 (ycash-dd 90f175ca1).

6.20.0 has no RPC that restores a wallet from its recovery phrase (z_exportwallet prints recovery_phrase as a
comment; z_importwallet/importwallet import keys, never the seed), so, as on ycash-dd, the restore is the
wallet.dat backup taken before any PQ key was issued: it holds the mnemonic seed and the lookahead
(PQ_KEY_LOOKAHEAD = 20 keys of each scheme, derived when the wallet was created), nothing more -- exactly what
a wallet re-created from the phrase holds before it rescans.

- node 1 backs up its wallet, then issues 31 SLH-DSA owners and 26 Falcon keys;
- node 0 locks vaults owned by SLH-DSA keys 2 and 30 and pays TX_PQPKH outputs to SLH-DSA key 15 and Falcon
  keys 5 and 24, each in its own block in that order (30 and 24 lie beyond the backup's lookahead: they are
  found only because the rescan marks 15 and 5 used and tops the lookahead up before it reaches them);
- node 2 starts on the backup with -rescan: vault_list flags both vaults as its own, listunspent holds the
  three PQPKH coins, and its next vault_getnewowner of each scheme is the index after the highest key seen
  on chain (SLH-DSA 31, node 1's next; Falcon 25, issued by node 1 but never used), and it signs the owner
  spend of vault 30;
- importwallet of another seed's pqseed lines at index 1000 and 0xfffffffe leaves the issued index alone
  (quantum review F-1: the keys are stored with PQ_INDEX_NONE).
- the set sign-once record follows wallet.dat, not the seed (07/F-5): node 1, a member, signs an unlock;
  (a) its backup on node 2 re-signs the identical hex and refuses a different build (set-sign-once);
  (b) a wallet restored from node 1's seed (-mnemonicfile) carries the restore marker: after importing the member key it
  refuses (set-sign-restored), acknowledgerestore overrides it for a vault the key never signed, and after
  set_importsigned of node 1's set_listsigned the refusal is set-sign-once and the identical hex signs; neither
  an empty import, a stale dump nor the full history clears the marker: only set_acknowledgerestore does (S2);
  (c) z_exportwallet writes the vaultsetsig= lines, z_importwallet on a fresh wallet restores them (the marker
  stays set), and a conflicting line aborts the import;
  (d) a key imported before it is a set member is pending: its SET_JOIN, when it connects, sets the marker (S3).

    ZCASHD=<ycashd> ../.venv/bin/python -u qa/rpc-tests/vault_pq_wallet_restore.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

import os
import shutil
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.pq import pqpkh_script
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
from test_framework.yellowback_util import pubkey_to_address

ACTIVATION = 205
DELAY = 5
SLH, FALCON = 1, 2
SLH_ISSUED, FALCON_ISSUED = 31, 26
SEED_FLAG = '-mnemonicfile'   # the seed-only restore (ycash-dd -hdseedfile, 6.20.0 -mnemonicfile)


def assert_raises_rpc(substr, fn, *args):
    try:
        fn(*args)
    except JSONRPCException as e:
        assert substr in e.error['message'], 'expected %r in %r' % (substr, e.error['message'])
        return
    raise AssertionError('expected an RPC error containing %r' % substr)


class VaultPQWalletRestoreTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 3
        self.setup_clean_chain = False

    def node_args(self, i):
        return [nuparams(VAULT_BRANCH_ID, ACTIVATION), '-pqfalcon=1', '-debug=vault',
                '-exportdir=%s' % os.path.join(self.options.tmpdir, 'export')]

    def setup_network(self, split=False):
        os.makedirs(os.path.join(self.options.tmpdir, 'export'), exist_ok=True)
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 extra_args=[self.node_args(i) for i in range(self.num_nodes)])
        self.connect_all()
        self.is_network_split = False
        self.sync_all()

    def connect_all(self):
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 1, 2)
        connect_nodes_bi(self.nodes, 0, 2)

    def mine(self, n=1):
        self.sync_all()
        self.nodes[0].generate(n)
        self.sync_all()

    def pay_pqpkh(self, key, value=2):
        """A TX_PQPKH output of `value` YEC from node 0 to `key` (a vault_getnewowner result)."""
        n0 = self.nodes[0]
        spk = pqpkh_script(key['scheme'], bytes.fromhex(key['keyhash'])).hex()
        placeholder = n0.getnewaddress()
        raw = n0.createrawtransaction([], {placeholder: value})
        p2pkh = n0.validateaddress(placeholder)['scriptPubKey']
        raw = raw.replace('19' + p2pkh, '23' + spk)
        txid = n0.sendrawtransaction(n0.signrawtransaction(n0.fundrawtransaction(raw)['hex'])['hex'])
        self.mine(1)
        vout = [o for o in n0.getrawtransaction(txid, 1)['vout'] if o['scriptPubKey']['hex'] == spk][0]['n']
        return (txid, vout)

    def lock(self, setid, owner_height, key):
        r = self.nodes[0].vault_lock({'tag': 'TEST', 'setid': setid, 'delay': DELAY, 'ownerheight': owner_height,
                                      'amount': 2, 'owner': key['owner']})
        self.mine(1)
        return r['outpoint']

    def run_test(self):
        n0, n1 = self.nodes[0], self.nodes[1]

        print('activation')
        self.mine(ACTIVATION - n0.getblockcount())
        assert_equal(n0.vault_getinfo()['active'], True)

        print('node 1 backs up its wallet before it issues any PQ key')
        n1.backupwallet('node1beforepq')
        backup = os.path.join(self.options.tmpdir, 'export', 'node1beforepq')

        print('node 1 issues %d SLH-DSA and %d Falcon keys' % (SLH_ISSUED, FALCON_ISSUED))
        slh = [n1.vault_getnewowner(SLH) for _ in range(SLH_ISSUED)]
        fal = [n1.vault_getnewowner(FALCON) for _ in range(FALCON_ISSUED)]
        assert_equal(len({k['owner'] for k in slh + fal}), SLH_ISSUED + FALCON_ISSUED)

        print('node 0 uses SLH-DSA keys 2, 15, 30 and Falcon keys 5, 24, in that order')
        setid = n0.set_create({'seats': 3, 'unlockthreshold': 2, 'cancelthreshold': 1, 'slashthreshold': 2,
                               'maturity': 2, 'livenesswindow': 50, 'bondmin': 1, 'ratewindow': 20})['setid']
        self.mine(1)
        assert_equal(n0.set_getinfo(setid)['released'], True)       # no members: the owner-released branch is open
        h = n0.getblockcount()
        v2 = self.lock(setid, h + 1000, slh[2])
        c15 = self.pay_pqpkh(slh[15])
        f5 = self.pay_pqpkh(fal[5])
        v30 = self.lock(setid, h + 1000, slh[30])
        f24 = self.pay_pqpkh(fal[24])
        mine1 = {r['outpoint']: r['wallet'] for r in n1.vault_list({'setid': setid})}
        assert_equal((mine1[v2], mine1[v30]), (True, True))

        print('node 2 restores node 1\'s backup (HD seed + lookahead) and rescans')
        stop_node(self.nodes[2], 2)
        shutil.copyfile(backup, os.path.join(self.options.tmpdir, 'node2', 'regtest', 'wallet.dat'))
        self.nodes[2] = start_node(2, self.options.tmpdir, self.node_args(2) + ['-rescan'])
        self.connect_all()
        sync_blocks(self.nodes)
        n2 = self.nodes[2]

        mine2 = {r['outpoint']: r['wallet'] for r in n2.vault_list({'setid': setid})}
        assert_equal((mine2[v2], mine2[v30]), (True, True))           # both owners re-found, 30 beyond the backup's lookahead
        held = {(u['txid'], u['vout']): u for u in n2.listunspent()}
        for coin in (c15, f5, f24):
            assert coin in held, 'restored wallet misses PQPKH coin %s:%d' % coin
            assert_equal(held[coin]['spendable'], True)

        print('the issued index moved past every key seen on chain: none of them is handed out again')
        # SLH-DSA: the last key node 1 issued (30) is on chain, so both wallets issue 31 next. Falcon: node 1
        # issued 25 but never used it, so the restored wallet (which only knows 24 was used) issues 25 next --
        # the lookahead restores every key seen on chain, not the issued-but-unused tail.
        nxt1 = n1.vault_getnewowner(SLH)
        nxt2 = n2.vault_getnewowner(SLH)
        assert_equal(nxt2['owner'], nxt1['owner'])
        assert nxt2['owner'] not in {k['owner'] for k in slh}
        assert_equal(n2.vault_getnewowner(FALCON)['owner'], fal[25]['owner'])
        assert_equal(n2.vault_getnewowner(FALCON)['owner'], n1.vault_getnewowner(FALCON)['owner'])   # index 26

        print('importwallet of another seed\'s keys at index 1000 and 0xfffffffe moves nothing (quantum review F-1)')
        dump = os.path.join(self.options.tmpdir, 'export', 'foreignpq')
        with open(dump, 'w') as f:
            f.write('# foreign post-quantum keys\n')
            for index, fill in ((1000, 'a1'), (0xfffffffe, 'b2')):
                f.write('pqseed=1:%d:%s 2026-10-10T00:00:00Z # foreign\n' % (index, fill * 48))
        before = n2.vault_getnewowner(SLH)
        n2.importwallet(dump)
        after = n2.vault_getnewowner(SLH)                              # still issuing: the index is one past before's
        n1.vault_getnewowner(SLH)
        assert_equal(after['owner'], n1.vault_getnewowner(SLH)['owner'])
        assert before['owner'] != after['owner']

        print('the restored wallet signs the owner spend of the vault beyond the lookahead')
        r = n2.vault_ownerspend(v30, n2.getnewaddress())
        assert_equal(r['selector'], 3)
        self.mine(1)
        assert n2.getrawtransaction(r['txid'], 1)['confirmations'] >= 1
        self.sign_once_restore()
        print('ok')

    def restart_node2(self, extra=(), wallet=None, wipe=False):
        """Restart node 2: on a copy of `wallet`, on a new wallet (wipe), or as it is."""
        stop_node(self.nodes[2], 2)
        path = os.path.join(self.options.tmpdir, 'node2', 'regtest', 'wallet.dat')
        if wallet is not None:
            shutil.copyfile(wallet, path)
        elif wipe:
            os.remove(path)
        self.nodes[2] = start_node(2, self.options.tmpdir, self.node_args(2) + list(extra))
        self.connect_all()
        sync_blocks(self.nodes)
        return self.nodes[2]

    def sign_once_restore(self):
        n0, n1 = self.nodes[0], self.nodes[1]
        export_dir = os.path.join(self.options.tmpdir, 'export')
        print('07/F-5: node 1 joins a set (unlock 1) and signs an unlock of vault A')
        sid = n0.set_create({'seats': 2, 'unlockthreshold': 1, 'cancelthreshold': 1, 'slashthreshold': 1,
                             'maturity': 2, 'livenesswindow': 500, 'bondmin': 1})['setid']
        self.mine(1)
        j = n1.set_join(sid, 1, n0.getblockcount() + 1000)
        n1.set_sendact(n0.set_signact(j['hex'], sid)['hex'])
        self.mine(3)
        assert_equal(n0.set_getinfo(sid)['current'], 1)
        member_addr = pubkey_to_address(bytes.fromhex(j['memberkey']))
        owner = n0.vault_getnewowner(SLH)
        h = n0.getblockcount()
        va = self.lock(sid, h + 1000, owner)
        vb = self.lock(sid, h + 1000, owner)
        addr = n0.getnewaddress()
        stale = n1.z_exportwallet('n1stale')      # a dump taken before the member signed: its history is stale
        bu = n1.vault_buildunlock(va, [{'address': addr, 'amount': 1}])
        signed = n1.set_signunlock(bu['hex'])
        assert_equal((signed['complete'], signed['sighash']), (True, bu['sighash']))
        bu2 = n1.vault_buildunlock(va, [{'address': addr, 'amount': Decimal('0.5')}], True)   # a different build
        assert bu2['sighash'] != bu['sighash']
        assert_raises_rpc('set-sign-once', n1.set_signunlock, bu2['hex'])
        record = {'setid': sid, 'prevout': va, 'role': 1, 'sighash': bu['sighash']}
        listed = n1.set_listsigned()
        assert_equal(listed, {'restored': False, 'records': [record]})

        print('(a) the backup taken after signing carries the record')
        n1.backupwallet('signonce')
        n2 = self.restart_node2(wallet=os.path.join(export_dir, 'signonce'))
        assert_equal(n2.set_listsigned(), listed)
        assert_equal(n2.set_signunlock(bu['hex'])['sighash'], bu['sighash'])   # identical: idempotent
        assert_raises_rpc('set-sign-once', n2.set_signunlock, bu2['hex'])

        print('(b) a seed-only restore carries no record: the restore marker refuses until it is imported')
        export = n1.z_exportwallet('n1signonce')
        n2 = self.restart_node2(extra=['%s=%s' % (SEED_FLAG, export)], wipe=True)
        assert_equal(n2.set_listsigned(), {'restored': True, 'records': []})
        n2.importprivkey(n1.dumpprivkey(member_addr), '', False)
        assert_raises_rpc('set-sign-restored', n2.set_signunlock, bu2['hex'])
        assert_raises_rpc('set-sign-restored', n2.set_signunlock, bu['hex'])
        # the operator's override, for a vault this key never signed
        bub = n1.vault_buildunlock(vb, [{'address': addr, 'amount': 1}])
        acked = n2.set_signunlock(bub['hex'], {'acknowledgerestore': True})
        assert_equal(acked['complete'], True)
        assert_equal(n2.set_listsigned()['restored'], True)                  # the override does not clear it
        # review S2: no import clears the marker -- not an empty one, not a stale dump, not the full history
        assert_equal(n2.set_importsigned([]), {'imported': 0, 'present': 0})
        n2.z_importwallet(stale)
        assert_equal(n2.set_listsigned()['restored'], True)
        assert_raises_rpc('set-sign-restored', n2.set_signunlock, bu2['hex'])
        imp = n2.set_importsigned(listed['records'])
        assert_equal((imp['imported'], imp['present']), (1, 0))
        assert_equal(n2.set_listsigned()['restored'], True)
        assert_raises_rpc('set-sign-once', n2.set_signunlock, bu2['hex'])   # the record is the real guard
        assert_equal(n2.set_signunlock(bu['hex'])['sighash'], bu['sighash'])
        assert_equal(n2.set_importsigned(listed['records']), {'imported': 0, 'present': 1})
        assert_equal(n2.set_acknowledgerestore()['restored'], False)        # only the operator clears it
        assert_equal(n2.set_listsigned()['restored'], False)

        print('(c) the wallet dump carries the record; a fresh wallet imports it; a conflict aborts')
        dump = n1.z_exportwallet('n1signoncedump')
        with open(dump, encoding='utf-8') as f:
            text = f.read()
        txid, n = va.split(':')
        line = 'vaultsetsig=%s:%s:%s:1:%s' % (sid, txid, n, bu['sighash'])
        assert line in text, 'the dump lacks %s' % line
        assert 'vaultsetsigs=1 ' in text
        assert 'vaultbuild=%s:%s:' % (txid, n) in text
        n2 = self.restart_node2(wipe=True)
        n2.z_importwallet(dump)
        got = n2.set_listsigned()
        assert_equal(got, {'restored': True, 'records': [record]})          # the member key came in: marked (S2)
        assert_raises_rpc('set-sign-once', n2.set_signunlock, bu2['hex'])
        conflict = os.path.join(export_dir, 'conflict')
        with open(conflict, 'w') as f:
            f.write('vaultsetsigs=1 # records\n')
            f.write('vaultsetsig=%s:%s:%s:1:%s # conflicting\n' % (sid, txid, n, '00' * 32))
        assert_raises_rpc('set-sign-once', n2.z_importwallet, conflict)
        assert_equal(n2.set_listsigned(), got)

        print('(d) a key imported before it is a member: its SET_JOIN, once connected, sets the marker (S3)')
        n2.set_acknowledgerestore()
        new_addr = n0.getnewaddress()
        new_key = n0.validateaddress(new_addr)['pubkey']
        n2.importprivkey(n0.dumpprivkey(new_addr), '', False)
        assert_equal(n2.set_listsigned()['restored'], False)                 # not a member yet: pending
        assert_equal(n2.set_acknowledgerestore()['pendingkeys'] >= 1, True)
        jn = n0.set_join(sid, 1, n0.getblockcount() + 1000, new_key)
        if not jn['complete']:                     # a set with a current member admits by its signature
            n0.set_sendact(n1.set_signact(jn['hex'], sid)['hex'])
        self.mine(1)
        assert_equal(n2.set_listsigned()['restored'], True)


if __name__ == '__main__':
    VaultPQWalletRestoreTest().main()
