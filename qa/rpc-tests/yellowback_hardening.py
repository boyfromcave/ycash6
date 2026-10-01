#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Phase 8 wallet hardening (H1-H12): the floor-aware selector through the RPCs
(yed_estimatesend, the structured change-floor refusal, the H4 sub-dollar burn),
and the three guards that keep YED from becoming plain YEC by accident -
lockunspent (H5), the startup check (H6) and sendrawtransaction (H7).

Written before the code it exercises (H12)."""

import os
from decimal import Decimal

from test_framework.util import (assert_equal, assert_start_raises_init_error, start_node,
                                 stop_node, bitcoind_processes)
from test_framework.yellowback_attest import wallet_mint
from test_framework.yellowback_util import (
    MIN_OUTPUT,
    POOLS,
    REF_LAG,
    TOKEN_VALUE,
    YELLOWBACK_FEE,
    YellowbackTestFramework,
)

COIN = 10 ** 8
UNLOCK_ACK = 'I understand this burns YED'


def assert_rpc_error(substr, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except Exception as e:
        assert substr in str(e), 'expected %r in %r' % (substr, str(e))
        return str(e)
    raise AssertionError('expected an error containing %r' % substr)


class YellowbackHardeningTest(YellowbackTestFramework):

    def run_test(self):
        nodes = self.nodes
        user = nodes[0]
        self.activate(quote_usd=50)
        self.mine(POOLS[0], REF_LAG + 1)

        # One $100.00 position: the coin set that makes the change floor bite.
        mint = wallet_mint(self, user, 10000, 48)     # v3: the carrier step (W7)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(user.yed_getbalance()['confirmedCents'], 10000)

        self.h1_h2_h3_selector(user)
        self.h5_lockunspent(user, mint)
        self.h10_getinfo(user)

        # A second position of $100.50, so that after H7 burns the first coin the only YED left
        # cannot pay the first vault's $100.00 debt without a 50-cent remainder (H4).
        mint_b = wallet_mint(self, user, 10050, 48)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(user.yed_getvault(mint_b['txid'])['status'], 'ACTIVE')
        assert_equal(user.yed_getbalance()['confirmedCents'], 20050)

        self.h7_sendrawtransaction(user)
        self.h4_redeem_burns_the_remainder(user, mint)
        self.h6_startup_without_yellowback()
        self.checkpoint('wallet hardening H1-H12')

    # ------------------------------------------------------------------ H1/H2/H3
    def h1_h2_h3_selector(self, user):
# Rule: H1
        print('h1_single_coin_with_valid_change: $40.00 out of one $100.00 coin')
        est = user.yed_estimatesend(4000)
        assert_equal(est['workable'], True)
        assert_equal(est['stage'], 'single')
        assert_equal(est['changeCents'], 6000)
        assert_equal(est['selectedCents'], 10000)
        assert_equal(est['spendableCents'], 10000)
        assert_equal(len(est['inputs']), 1)
        assert_equal(est['error'], '')
        assert_equal(est['alternatives'], None)

# Rule: H1
        print('h1_exact_match: the whole coin, change 0')
        exact = user.yed_estimatesend(10000)
        assert_equal(exact['stage'], 'exact')
        assert_equal(exact['changeCents'], 0)
        assert_equal(exact['workable'], True)

# Rule: H2
        print('h2_change_floor_is_structured: $99.50 out of one $100.00 coin is unworkable')
        band = user.yed_estimatesend(9950)
        assert_equal(band['workable'], False)
        assert_equal(band['stage'], 'none')
        assert_equal(band['error'], 'change-floor')
        assert_equal(band['inputs'], [])
        assert_equal(band['changeCents'], 0)
        assert_equal(band['alternatives']['below'], 9900)
        assert_equal(band['alternatives']['above'], 10000)
        msg = assert_rpc_error('change-floor', user.yed_send, user.yed_getnewaddress(), 9950)
        # the grammar the GUI reads (doc/yellowback-rpc.md, Error identifiers)
        assert 'nearest workable amounts: below 9900, above 10000' in msg, msg

# Rule: H2
        print('h2_the_alternatives_really_work: both nearest amounts build')
        assert_equal(user.yed_estimatesend(9900)['workable'], True)
        assert_equal(user.yed_estimatesend(10000)['workable'], True)

# Rule: H1
        print('h1_estimatesend_is_a_dry_run: nothing signed, nothing locked, nothing sent')
        before = user.yed_listunspent()
        user.yed_estimatesend({user.yed_getnewaddress(): 4000})
        assert_equal(user.yed_listunspent(), before)
        assert_equal(user.getrawmempool(), [])

# Rule: H1
        print('h1_estimatesend_takes_the_recipients_object')
        obj = user.yed_estimatesend({user.yed_getnewaddress(): 2000, user.yed_getnewaddress(): 2000})
        assert_equal(obj['recipients'], 2)
        assert_equal(obj['amountCents'], 4000)
        assert_equal(obj['workable'], True)
        print('h1_estimatesend_never_refuses_for_the_amount: it reports instead')
        poor = user.yed_estimatesend(5000000)
        assert_equal(poor['workable'], False)
        assert_equal(poor['error'], 'insufficient-yed')
        assert_equal(poor['stage'], 'none')

    # ------------------------------------------------------------------ H5
    def h5_lockunspent(self, user, mint):
        token = {'txid': mint['txid'], 'vout': 1}
        locked = [{'txid': l['txid'], 'vout': l['vout']} for l in user.listlockunspent()]
        assert token in locked

# Rule: H5
        print('h5_lockunspent_refuses_a_yellowback_outpoint')
        assert_rpc_error('yed-locked-outpoint', user.lockunspent, True, [token])
        assert token in [{'txid': l['txid'], 'vout': l['vout']} for l in user.listlockunspent()]

# Rule: H5
        print('h5_lockunspent_false_may_still_lock_a_yellowback_outpoint')
        # H5 guards *unlocking* only: unlocking exposes the coin to automatic selection and would
        # burn its YED, while locking one is harmless and is what the overlay itself does. Guarding
        # both directions broke every raw-builder script that locks its own inputs
        # (yellowback_mining.py's send_locked), and the help text has always said "cannot be
        # unlocked here" — so the direction is pinned here.
        user.lockunspent(False, [token])
        assert token in [{'txid': l['txid'], 'vout': l['vout']} for l in user.listlockunspent()]
        plain = None
        for u in user.listunspent():
            cand = {'txid': u['txid'], 'vout': u['vout']}
            if cand not in [{'txid': l['txid'], 'vout': l['vout']} for l in user.listlockunspent()]:
                plain = cand
                break
        assert plain is not None, 'no unlocked plain YEC output to check the ordinary path with'
        user.lockunspent(False, [plain])          # an ordinary coin still locks
        assert plain in [{'txid': l['txid'], 'vout': l['vout']} for l in user.listlockunspent()]
        user.lockunspent(True, [plain])           # and still unlocks, since it holds no YED
        assert plain not in [{'txid': l['txid'], 'vout': l['vout']} for l in user.listlockunspent()]

# Rule: H5
        print('h5_lockunspent_true_reapplies_the_locks')
        user.lockunspent(True)
        assert token in [{'txid': l['txid'], 'vout': l['vout']} for l in user.listlockunspent()]

# Rule: H5
        print('h5_yed_unlockcoin_is_the_escape_hatch, and needs the exact acknowledgement')
        assert_rpc_error('unlock-acknowledgement-missing', user.yed_unlockcoin, mint['txid'], 1, 'ok')
        out = user.yed_unlockcoin(mint['txid'], 1, UNLOCK_ACK)
        assert_equal(out['unlocked'], True)
        assert_equal(out['wasYellowbackLocked'], True)
        assert_equal(out['cents'], 10000)
        assert token not in [{'txid': l['txid'], 'vout': l['vout']} for l in user.listlockunspent()]

# Rule: H5
        print('h5_the_lock_comes_back_with_yed_lockcoins')
        user.yed_lockcoins()
        assert token in [{'txid': l['txid'], 'vout': l['vout']} for l in user.listlockunspent()]
        # an outpoint the layer does not hold unlocks without complaint
        assert_equal(user.yed_unlockcoin(mint['txid'], 0, UNLOCK_ACK)['wasYellowbackLocked'], False)

    # ------------------------------------------------------------------ H10
    def h10_getinfo(self, user):
# Rule: H10
        print('h10_getinfo_reports_the_locks')
        info = user.yed_getinfo()
        assert_equal(info['protectedByIndex'], True)
        assert_equal(info['lockedOutputs'], len(user.yed_listunspent()))
        assert info['lockedOutputs'] >= 1

    # ------------------------------------------------------------------ H7
    def h7_sendrawtransaction(self, user):
        coin = [c for c in user.yed_listunspent() if c['cents'] == 10000][0]
        raw = user.createrawtransaction([{'txid': coin['txid'], 'vout': coin['vout']}],
                                        {user.getnewaddress(): Decimal(TOKEN_VALUE - YELLOWBACK_FEE) / COIN})
        signed = user.signrawtransaction(raw)['hex']

# Rule: H7
        print('h7_sendrawtransaction_refuses_a_burn_of_my_own_yed')
        assert_rpc_error('yed-burn-refused', user.sendrawtransaction, signed)
        assert_rpc_error('yed-burn-refused', user.sendrawtransaction, signed, False)
        assert_equal(user.getrawmempool(), [])

# Rule: H7
        print('h7_allowyedburn_sends_it_anyway')
        txid = user.sendrawtransaction(signed, False, True)
        assert txid in user.getrawmempool()
        self.sync_all()
        self.mine(POOLS[1])
        info = user.yed_gettxinfo(txid)
        assert_equal(info['verdict'], 'burned')
        assert_equal(info['burned'], 10000)
        assert_equal(user.yed_getbalance()['confirmedCents'], 10050)

# Rule: H7
        print('h7_an_ordinary_transaction_is_untouched')
        plain = user.sendtoaddress(user.getnewaddress(), Decimal('1.0'))
        assert plain in user.getrawmempool()
        self.sync_all()
        self.mine(POOLS[1])

    # ------------------------------------------------------------------ H4
    def h4_redeem_burns_the_remainder(self, user, mint):
# Rule: H4
        print('h4_redeem_burns_a_sub_dollar_remainder: $100.00 of debt paid from one $100.50 coin')
        blocks = mint['lockHeight'] - user.getblockcount()
        if blocks > 0:
            self.mine_round_robin(POOLS, blocks)
        assert_equal([c['cents'] for c in user.yed_listunspent()], [10050])
        # a TRANSFER of the same amount is refused rather than burned (H2)
        assert_rpc_error('change-floor', user.yed_send, user.yed_getnewaddress(), 10000)
        redeem = user.yed_redeem(mint['txid'])
        assert_equal(redeem['burnedCents'], 10000)
        assert_equal(redeem['extraBurnCents'], 50)
        assert redeem['extraBurnCents'] < MIN_OUTPUT
        self.sync_all()
        self.mine(POOLS[2])
        assert_equal(user.yed_getvault(mint['txid'])['status'], 'CLOSED')
        assert_equal(user.yed_getbalance()['confirmedCents'], 0)
        info = user.yed_gettxinfo(redeem['txid'])
        assert_equal(info['yedIn'], 10050)
        assert_equal(info['burned'], 10050)

    # ------------------------------------------------------------------ H6
    def h6_startup_without_yellowback(self):
# Rule: H6
        print('h6_a_datadir_with_an_index_refuses_to_start_without_-yellowback')
        i = 0
        stop_node(self.nodes[i], i)
        self.nodes[i] = None
        datadir = os.path.join(self.options.tmpdir, 'node' + str(i))
        assert os.path.isdir(os.path.join(datadir, 'regtest', 'yellowback'))

        # the six -nuparams the framework passes, minus -yellowback: init must refuse.
        #
        # assert_start_raises_init_error, not a bare start_node in a try/except, for two reasons.
        # It captures the refused node's stderr into a temporary file: a bare start_node lets the
        # refusal reach this script's stderr, and rpc-tests.py marks any script that writes to
        # stderr as failed — so the case reported "Tests successful" and the suite still called it
        # a failure, visible only under the suite runner and not when the script is run directly.
        # And it asserts *why* init refused: checking only that startup failed would pass just as
        # happily if the node had died of a port clash or a slow start under load.
        base = [a for a in self.node_args(i) if not a.startswith('-yellowback') and a != '-experimentalfeatures']
        assert_start_raises_init_error(
            i, self.options.tmpdir, base,
            'This datadir holds a Yellowback index, so this wallet may hold YED')
        if i in bitcoind_processes:
            del bitcoind_processes[i]

# Rule: H6
        print('h6_-yellowback=0_is_the_acknowledgement')
        node = start_node(i, self.options.tmpdir, base + ['-yellowback=0'])
        assert_equal(node.getblockcount() >= 0, True)
        stop_node(node, i)

        # back to the normal role arguments so the framework can finish
        self.nodes[i] = start_node(i, self.options.tmpdir, self.node_args(i))
        self.reconnect(i)


if __name__ == '__main__':
    YellowbackHardeningTest().main()
