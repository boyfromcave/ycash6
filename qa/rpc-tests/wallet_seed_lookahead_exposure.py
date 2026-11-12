#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""What an encrypted, locked wallet file reveals about the legacy transparent account (review 3 H-1, 6.x only).

An intermediate build stored the legacy account's extended public key (chain code and public key, record
"legacytaccountpub") in clear so that a locked wallet could watch its transparent lookahead. With a copy of the file
and ONE exported transparent private key, non-hardened BIP32 algebra gives the account private key and every legacy
transparent key, past and future; the file alone gives every future address and the legacy shielding outgoing viewing
keys (AccountPubKey::GetOVKsForShielding hashes exactly that chain code and public key).

This release stores only the KEY IDs of the lookahead ("legacytlookahead"). The test derives the account key, both
chain keys and their chain codes independently from the recovery phrase (BIP39, BIP32, m/44'/coin'/0x7FFFFFFF'),
checks that derivation against the node's own addresses, then takes the encrypted, locked wallet file and the database
directory, as a thief with one dumpprivkey output would have them, and shows:
- no file holds the record "legacytaccountpub", nor the chain code or the compressed public key of the account or of
  either chain: so neither a parent key nor another child key can be computed from the leaked key, and no OVK;
- the file does hold the next -keypool + 1 key IDs of each chain, and only key IDs (what the addresses would reveal).

What is read: wallet.dat and every file of the database directory (database/, the Berkeley DB log) copied WHILE the
node runs with the wallet locked (a clean shutdown removes database/, so a copy after it would check nothing; the test
requires the log to hold the public key of a key issued in that session), then wallet.dat again after the clean
stop. Not checked: the log of a node that crashed, free pages left by a record an intermediate build wrote and this
release erased (no raw-byte assertion: this build never writes the record), and backups or copies made elsewhere.

Run: ZCASHD=<ycashd> .venv/bin/python -u qa/rpc-tests/wallet_seed_lookahead_exposure.py --tmpdir=<dir> --portseed=<n>
"""

import hashlib
import hmac
import os
import unicodedata

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    bitcoind_processes,
    start_node,
    stop_node,
)

KEYPOOL = 5
PASSPHRASE = 'exposure-pass'
REGTEST_COIN_TYPE = 1
LEGACY_ACCOUNT = 0x7FFFFFFF
HARDENED = 0x80000000

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def point_mul(k, pt=G):
    r = None
    while k:
        if k & 1:
            r = point_add(r, pt)
        pt = point_add(pt, pt)
        k >>= 1
    return r


def ser_p(pt):
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, 'big')


def hash160(b):
    return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()


def b58_payload(s):
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return raw[:-4]


def ckd_priv(k, c, i):
    """BIP32 private child derivation: (key, chain code) of child i."""
    if i >= HARDENED:
        data = b'\x00' + k.to_bytes(32, 'big') + i.to_bytes(4, 'big')
    else:
        data = ser_p(point_mul(k)) + i.to_bytes(4, 'big')
    h = hmac.new(c, data, hashlib.sha512).digest()
    return (int.from_bytes(h[:32], 'big') + k) % N, h[32:]


class WalletSeedLookaheadExposureTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.setup_clean_chain = True

    def node_args(self):
        return ['-keypool=%d' % KEYPOOL, '-exportdir=%s' % self.options.tmpdir,
                '-experimentalfeatures', '-developerencryptwallet']

    def setup_network(self, split=False):
        self.nodes = [start_node(0, self.options.tmpdir, self.node_args())]
        self.is_network_split = False

    def account_from_phrase(self, phrase):
        """(account key, account chain code), and per chain (key, chain code), from the recovery phrase."""
        seed = hashlib.pbkdf2_hmac('sha512', unicodedata.normalize('NFKD', phrase).encode(),
                                   b'mnemonic', 2048)
        h = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
        k, c = int.from_bytes(h[:32], 'big'), h[32:]
        for i in (44, REGTEST_COIN_TYPE, LEGACY_ACCOUNT):
            k, c = ckd_priv(k, c, i + HARDENED)
        chains = {ch: ckd_priv(k, c, ch) for ch in (0, 1)}
        return (k, c), chains

    def run_test(self):
        n = self.nodes[0]
        n.generate(1)
        first = n.getnewaddress()
        dump = os.path.join(self.options.tmpdir, n.z_exportwallet('exposure'))
        phrase = None
        with open(dump, encoding='utf8') as f:
            for line in f:
                if line.startswith('# - recovery_phrase="'):
                    phrase = line.split('"')[1]
        assert phrase is not None
        (k_acct, c_acct), chains = self.account_from_phrase(phrase)
        K_acct = point_mul(k_acct)

        print('the derivation from the phrase gives the node\'s own addresses')
        k_ext, c_ext = chains[0]
        k1, _ = ckd_priv(k_ext, c_ext, 1)    # external index 0 is the key the new wallet issued for itself
        assert_equal(hash160(ser_p(point_mul(k1))), b58_payload(first)[-20:])

        print('encrypted and locked: the wallet file and the database log, as a thief would copy them')
        n.encryptwallet(PASSPHRASE)
        bitcoind_processes[0].wait()
        n = self.nodes[0] = start_node(0, self.options.tmpdir, self.node_args())
        n.walletpassphrase(PASSPHRASE, 600)
        issued = [n.getnewaddress() for _ in range(3)] + [n.getrawchangeaddress() for _ in range(2)]
        leaked = n.dumpprivkey(issued[1])     # the ONE key the thief has (external index 3)
        k_leak, _ = ckd_priv(k_ext, c_ext, 3)
        assert_equal(int.from_bytes(b58_payload(leaked)[-33:-1], 'big'), k_leak)
        info = n.getwalletinfo()
        n.walletlock()
        datadir = os.path.join(self.options.tmpdir, 'node0', 'regtest')
        walletfile = os.path.join(datadir, 'wallet.dat')
        dbdir = os.path.join(datadir, 'database')
        # copied while the node runs: a clean shutdown removes database/ (the log holds every record inserted; a
        # replaced record is logged as a byte diff)
        logs = [os.path.join(dbdir, x) for x in sorted(os.listdir(dbdir)) if x.startswith('log.')]
        blobs = {path + ' (running)': open(path, 'rb').read() for path in [walletfile] + logs}
        # the log holds this session's records (the ckey record of the first key issued since the restart carries its
        # public key), so the leg below can fail
        k_issued, _ = ckd_priv(k_ext, c_ext, 2)
        assert any(ser_p(point_mul(k_issued)) in blobs[path + ' (running)'] for path in logs), 'no database log to read'
        stop_node(n, 0)
        assert not os.path.isdir(dbdir) or not os.listdir(dbdir)   # why the log is read above
        wallet = open(walletfile, 'rb').read()
        blobs[walletfile + ' (stopped)'] = wallet

        print('no record and no bytes of the account\'s or a chain\'s extended public key, in any file')
        secrets = {'account chain code': c_acct, 'account public key': ser_p(K_acct)}
        for ch, (k, c) in chains.items():
            secrets['chain %d chain code' % ch] = c
            secrets['chain %d public key' % ch] = ser_p(point_mul(k))
        for path, data in blobs.items():
            assert b'legacytaccountpub' not in data, path
            for name, value in secrets.items():
                assert value not in data, '%s holds the %s' % (path, name)

        print('the file holds the key IDs of the next -keypool + 1 addresses of each chain: what the addresses reveal')
        assert b'legacytlookahead' in wallet
        counter = 5   # external indices 0, 1 (first) and 2..4 (issued) are issued
        next_ext = []
        for i in range(counter, counter + KEYPOOL + 1):
            k, _ = ckd_priv(k_ext, c_ext, i)
            next_ext.append(hash160(ser_p(point_mul(k))))
        for kid in next_ext:
            assert kid in wallet
        k_past, _ = ckd_priv(k_ext, c_ext, counter + KEYPOOL + 1)
        assert hash160(ser_p(point_mul(k_past))) not in wallet   # nothing beyond the window
        assert info['lookahead_incomplete'] is False

        self.nodes[0] = start_node(0, self.options.tmpdir, self.node_args())


if __name__ == '__main__':
    WalletSeedLookaheadExposureTest().main()
