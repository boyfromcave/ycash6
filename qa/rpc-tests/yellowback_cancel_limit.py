#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The held residual of a cancelled claim (CAN-3; the cancel-limit design and the owner's round-2 decision, 2026-10-13)
on regtest, as the R-1c attack would play it: an owner who also holds an attestor seat.

  - arm three attestors; node 0 (the user) mints a class-A vault (300 % at $50) and holds the member keys;
  - the pools fall to $10.20 while the attestors attest $22: pClaim = max = $22 keeps the vault above theta (132 %),
    pEmerg = min = $10.20 puts it under EMERGENCY_RATIO (61 %);
  - the owner posts a CLAIM_NOTICE, waits EMERGENCY_PERSIST and claims its OWN vault by path (b): a claimant intent
    (to itself) and the owner's residual intent (RED-5);
  - with its seat it co-signs and cancels the claimant intent (yed_signcancelcosign at $22, yed_buildcancel,
    set_signcancel, vault_send): the burn comes back (CAN-1), the vault reopens at the claimant intent's value, and the
    residual intent is held by the re-created position (yed_getvault.heldResiduals);
  - vault_release of the residual is refused (intent-residual-held) inside CANCEL_QUIET, and still after it, because
    the position (~45 % at the pools' $10.20) is claimable at the latest snapshot (round 2): the extraction R-1c is closed;
  - the owner redeems the position (CLOSED): only then is the residual released.
  - assert_model_matches over the whole chain.

Nodes: 0 user (owner and attestor seat 0), 1 stock, 2-4 pools, 5 observer.
"""

from decimal import Decimal

from test_framework.util import assert_equal, assert_greater_than, sync_blocks, sync_mempools
from test_framework.yellowback_util import (
    CANCEL_QUIET,
    CLAIM_DELAY,
    POOLS,
    REF_LAG,
    STOCK,
    YellowbackTestFramework,
    assert_best_hash,
    assert_same_statehash,
    set_quote,
    usd_to_micro,
    yed_params,
)
from test_framework.yellowback_attest import (
    ATTESTOR_WIFS,
    ArmedModeMixin,
    register_and_arm,
    wallet_claim,
    wallet_notice,
)

OVERLAY = [0, 2, 3, 4, 5]
PRICE = Decimal('50')
POOL_LOW = Decimal('10.20')
ATTESTED = Decimal('22')


def assert_rpc_error(substr, fn, *args):
    try:
        fn(*args)
    except Exception as e:
        assert substr in str(e), 'expected %r in %r' % (substr, str(e))
        return str(e)
    raise AssertionError('expected an error containing %r' % substr)


class YellowbackCancelLimitTest(ArmedModeMixin, YellowbackTestFramework):

    @property
    def armed(self):
        return True                                            # always armed: path (b) needs bundles

    def sync_all(self, blocks_only=False):
        for g in self.groups():
            nodes = [self.nodes[i] for i in g if self.nodes[i] is not None]
            sync_blocks(nodes)
            if not blocks_only:
                sync_mempools([self.nodes[i] for i in g if self.nodes[i] is not None and i != STOCK])

    def price(self, usd):
        for i in POOLS:
            set_quote(self.nodes[i], usd)

    def mine_to(self, height):
        n = height - self.nodes[0].getblockcount()
        if n > 0:
            self.mine_round_robin(POOLS, n)

    def run_test(self):
        nodes = self.nodes
        user = nodes[0]
        self.current_quote = PRICE

        print('activate at $%s; arm three attestors; the owner holds the seats\' keys' % PRICE)
        self.activate(POOLS, quote_usd=PRICE)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        register_and_arm(self)
        for wif in ATTESTOR_WIFS[:3]:                          # the owner's seat(s): the member keys in its wallet
            user.importprivkey(wif, 'yellowback-attestor', False)

# Rule: MINT-1
        print('the owner mints $100 at 300 % (class A)')
        mint = wallet_mint_armed(self, user)
        vault = mint['txid']
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(user.yed_getvault(vault)['status'], 'ACTIVE')

# Rule: NOT-1 RED-4
        print('the pools fall to $%s, the attestors say $%s: not claimable on path (a), under EMERGENCY_RATIO on (b)' % (POOL_LOW, ATTESTED))
        self.price(POOL_LOW)
        self.mine_round_robin(POOLS, 66)
        assert_equal(user.yed_getprice()['pClaim'], usd_to_micro(POOL_LOW))
        wallet_notice(self, user, vault, prices=ATTESTED)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(user.yed_getvault(vault)['noticed'], True)
        self.mine_round_robin(POOLS, yed_params().emergency_persist + 1)

# Rule: RED-4 RED-5
        print('the owner claims its own vault by path (b): a claimant intent and its residual intent')
        claimed = wallet_claim(self, user, vault, prices=ATTESTED)
        assert_equal(claimed['claimPath'], 'b')
        assert_greater_than(claimed['residualZat'], 0)
        self.sync_all()
        self.mine(POOLS[1])
        claim_height = user.getblockcount()
        claiming = user.yed_getvault(vault)
        rows = dict((x['role'], x) for x in claiming['intents'])
        claimant = '%s:%d' % (rows['claimant']['txid'], rows['claimant']['vout'])
        residual = '%s:%d' % (rows['residual']['txid'], rows['residual']['vout'])

# Rule: CAN-2 C4b CAN-3
        print("with its seat the owner cancels the claimant intent: the burn back, the residual held by the re-created position")
        cos = user.yed_signcancelcosign(claimant, usd_to_micro(ATTESTED))
        built = user.yed_buildcancel(claimant, [cos['cosig']])
        assert_equal((built['cancelsRequired'], built['cosigners']), (1, [cos['seq']]))
        signed = user.set_signcancel(built['hex'], {'acknowledgerestore': True})
        assert_equal(signed['complete'], True)
        cancel = user.vault_send(signed['hex'])
        self.sync_all()
        self.mine(POOLS[2])
        cancelled = user.getblockcount()
        for i in OVERLAY:
            pos = nodes[i].yed_getvault(cancel)
            assert_equal((pos['status'], pos['cancelCount']), ('ACTIVE', 1))
            assert_equal(pos['heldResiduals'], [{'txid': rows['residual']['txid'], 'vout': rows['residual']['vout']}])
            # a listed row of the re-created position carries the cancel limit as yed_getvault does (a claimant's view)
            listed = [r for r in nodes[i].yed_listclaimable() if r['vault'] == '%s:0' % cancel]
            assert_equal(len(listed), 1)
            assert_equal((listed[0]['cancelCount'], listed[0]['cancelsRequired'], listed[0]['cancelQuietUntil']),
                         (pos['cancelCount'], pos['cancelsRequired'], pos['cancelQuietUntil']))
            assert_equal(listed[0]['cancelsRequired'], 2)       # a second cancel inside CANCEL_QUIET needs two co-signers
        self.mine_to(claim_height + CLAIM_DELAY)                  # the residual intent has matured (BIP68)

        print('the residual is held inside CANCEL_QUIET')
        assert_rpc_error('intent-residual-held', user.vault_release, residual)

        print('after CANCEL_QUIET the position is claimable at the snapshot at $%s: still held (round 2, R-1c)' % POOL_LOW)
        self.mine_to(cancelled + CANCEL_QUIET + 1)
        pos = user.yed_getvault(cancel)
        assert pos['claimable'] or pos['underwaterAt'] > usd_to_micro(POOL_LOW), pos
        assert_rpc_error('intent-residual-held', user.vault_release, residual)
        for i in OVERLAY:
            assert_equal(len(nodes[i].yed_getvault(cancel)['heldResiduals']), 1)

# Rule: CAN-3
        print('the owner redeems the position (CLOSED): only now is the residual released')
        redeem = user.yed_redeem(cancel)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(user.yed_getvault(cancel)['status'], 'CLOSED')
        assert 'txid' in redeem or redeem, redeem
        released = user.vault_release(residual)
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(nodes[2].yed_gettxinfo(released)['type'], 'claim_release')
        for i in OVERLAY:
            assert 'heldResiduals' not in nodes[i].yed_getvault(cancel)
        self.checkpoint('residual released after the close')

        print('the Python model over the whole chain (P8)')
        self.model_check(nodes[0])
        self.sync_all(blocks_only=True)
        assert_best_hash(self.enforcing_nodes(), 'end')
        assert_same_statehash(self.enforcing_nodes(), 'end')


def wallet_mint_armed(test, node):
    """A $100 class-A mint (48 blocks) with the bundle at the pools' price."""
    return test.mint(node, 10000, 48)


if __name__ == '__main__':
    YellowbackCancelLimitTest().main()
