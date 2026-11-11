#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
getnewaddress argument shapes (beta2 item 10): the address type may come first (getnewaddress pq | pqslh | p2pkh),
as yed_getnewaddress takes it, and the old shape getnewaddress "" <type> keeps working. A type name was never a
valid account (AccountFromValue accepts only ""), so no call that worked before changes meaning; every other first
argument is refused as before.

No address text or prefix is hard-coded: the kind of each address is read back with validateaddress.

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/wallet_getnewaddress_type.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import VAULT_BRANCH_ID, assert_equal, nuparams, start_nodes

ACTIVATION = 205
SLH, FN = 1, 2


def assert_raises_rpc(substr, fn, *args):
    try:
        fn(*args)
    except JSONRPCException as e:
        assert substr in e.error['message'], 'expected %r in %r' % (substr, e.error['message'])
        return e.error['message']
    raise AssertionError('expected an RPC error containing %r' % substr)


class WalletGetNewAddressTypeTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.setup_clean_chain = False

    def setup_network(self, split=False):
        self.nodes = start_nodes(1, self.options.tmpdir, extra_args=[[nuparams(VAULT_BRANCH_ID, ACTIVATION), '-pqfalcon=1']])
        self.is_network_split = False

    def kind(self, addr):
        v = self.nodes[0].validateaddress(addr)
        assert v['isvalid'] and v['ismine'], v
        assert addr in self.nodes[0].getaddressesbyaccount(''), addr
        return v.get('pqscheme', 'ecc')

    def run_test(self):
        n0 = self.nodes[0]
        print('before the vault upgrade: a PQ type is refused in either position')
        assert n0.getblockcount() + 1 < ACTIVATION
        for args in (('pq',), ('pqslh',), ('', 'pq')):
            assert_raises_rpc('vault upgrade', n0.getnewaddress, *args)
        n0.generate(ACTIVATION - n0.getblockcount())

        print('the type first, and the old "" + type shape')
        cases = [((), 'ecc'), (('',), 'ecc'), (('p2pkh',), 'ecc'), (('', 'p2pkh'), 'ecc'),
                 (('pq',), FN), (('', 'pq'), FN), (('pqslh',), SLH), (('', 'pqslh'), SLH),
                 (('pq', None), FN), (('', None), 'ecc')]
        seen = set()
        for args, want in cases:
            a = n0.getnewaddress(*args)
            assert_equal((args, self.kind(a)), (args, want))
            assert a not in seen
            seen.add(a)

        print('refusals: unchanged for an account name, new for a type given twice')
        assert_raises_rpc('Accounts are unsupported', n0.getnewaddress, 'savings')
        assert_raises_rpc('Accounts are unsupported', n0.getnewaddress, 'savings', 'pq')
        assert_raises_rpc('Accounts are unsupported', n0.getnewaddress, 'bogus')
        # the type names are lower case; another case is refused with an error that names them
        for bad in ('PQ', 'Pq', 'PQSLH', 'P2PKH'):
            assert_raises_rpc('the first argument is the address type, "p2pkh", "pq" or "pqslh" (lower case)', n0.getnewaddress, bad)
        assert_raises_rpc('type must be', n0.getnewaddress, '', 'PQ')
        assert_raises_rpc('type must be', n0.getnewaddress, '', 'bogus')
        assert_raises_rpc('the address type is given first, so there is no second argument', n0.getnewaddress, 'pq', 'pq')
        assert_raises_rpc('the address type is given first, so there is no second argument', n0.getnewaddress, 'p2pkh', '')


if __name__ == '__main__':
    WalletGetNewAddressTypeTest().main()
