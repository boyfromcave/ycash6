#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The v3 wallet RPCs on the eight-node regtest (v3 plan Phase A3, section 4.5 wallet context,
section 4.6): yed_registerattestor on the attestor wallets (nodes 6-7) beside raw registrations,
yed_signattestation with its persisted equivocation guard (S16, across a restart), the two-step
mint (W7: carrier, then MINT; wait=True with a helper thread mining the carrier's block, and
wait=False completed by the wallet's own thread), the Sapling-funded mint (the carrier its one
transparent input), the armed refusals (bundle-insufficient, bundle-malformed, mint10-diverged
before any transaction), a carrier orphaned by a restart and swept by yed_sweepcarriers after its
window, the normal claim (clause a) and the emergency claim (yed_claimnotice, EMERGENCY_PERSIST,
clause b with the RED-5 residual to the owner, to a ys1... address with the residual transparent),
yed_reportequivocation, dormancy and yed_revive, yed_withdrawbond before and after the locktime
(from a wallet that imported the bond key), and that no stock command ever spends a carrier or a
bond.

Nodes: 0 user, 1 stock, 2-4 pools, 5 claimant, 6-7 attestor wallets.

Until Phase A2 lands, the node has no yed_listattestors / yed_getselection / attest.status:
seq, the arming heights and the selection are derived offline (test_framework/yellowback_attest.py,
REGISTRY) by registering one attestor per block and counting; the wallet's own bundle verdicts
(bundle-insufficient names the BUNDLE-1 reason) are the check that the derivation agrees with the
node.
"""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.util import assert_equal, assert_greater_than, bytes_to_hex_str, hex_str_to_bytes, wait_and_assert_operationid_status
from test_framework.yellowback_util import (
    ATTESTOR_A, ATTESTOR_B, BOND_MIN_LOCK, CARRIER_VALUE, COIN, EMERGENCY_PERSIST, POOLS, REF_LAG, REF_WINDOW,
    TOKEN_VALUE, YELLOWBACK_FEE, YellowbackTestFramework, assert_same_statehash, pubkey_to_address, set_quote,
    usd_to_micro, DORMANCY_CHECK, K_SLACK, M_SELECT, P_FAST_WINDOW,
)
from test_framework.yellowback_attest import (
    REGISTRY, arming_state, decode_bundle, note_attestor_status, offline_bundle, offline_bundle_hex, offline_selection,
    outpoint_selector, register_and_arm, register_wallet_attestor, sign_attestation, two_step_pending, verify_attestation,
    wallet_claim, wallet_mint, wallet_notice, wallet_report_equivocation, hot_secret_for, model_check,
)


def feed_pool(test, node, ref_height, selector, prices):
    """The offline bundle's attestations (wallet-signed for the wallet-registered seqs) fed one by
    one into ``node``'s pool through ``yed_addattestation``."""
    bundle, _selected = offline_bundle(test, node, ref_height, selector, prices)
    return [node.yed_addattestation(bytes_to_hex_str(att)) for att in decode_bundle(bundle)]


def assert_rpc_error(substr, fn, *args):
    try:
        fn(*args)
    except Exception as e:
        assert substr in str(e), 'expected %r in %r' % (substr, str(e))
        return str(e)
    raise AssertionError('expected an error containing %r' % substr)


def node_selection(test, node, r):
    """The node's own selected(R, "") read back through the wallet: a bundle with at most one
    signer never reaches the carrier step, and the bundle-insufficient message names the count
    and the missing seqs ('<n> of <m> selected attestors have a fresh attestation; missing seq
    a,b'). The stand-in for yed_getselection until Phase A2; the assertion that the offline
    selection agrees with the node's."""
    import re
    probe = min(seq for seq, a in REGISTRY['attestors'].items() if a['status'] == 'ELIGIBLE' and a.get('secret') is not None)
    bundle_hex = offline_bundle_hex(test, node, r, b'', {probe: 49})
    try:
        node.yed_mint(10000, 48, '', bundle_hex)
    except Exception as e:
        m = re.search(r'(\d+) of (\d+) selected attestors have a fresh attestation; missing seq ([0-9,]+|none)', str(e))
        assert m, str(e)
        missing = [] if m.group(3) == 'none' else [int(x) for x in m.group(3).split(',')]
        have = [probe] if m.group(1) == '1' else []
        return sorted(missing + have)
    raise AssertionError('a one-signer bundle was accepted')


class YellowbackAttestWalletTest(YellowbackTestFramework):

    def __init__(self):
        super().__init__(num_nodes=8)

    def price(self, usd):
        for i in POOLS:
            set_quote(self.nodes[i], usd)

    def run_test(self):
        nodes = self.nodes
        user, claimant, wa, wb = nodes[0], nodes[5], nodes[ATTESTOR_A], nodes[ATTESTOR_B]
        print('activate at $50; fund the claimant and the attestor wallets')
        self.activate(POOLS, quote_usd=50)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        for node in (claimant, wa, wb):
            user.sendtoaddress(node.getnewaddress(), 40)
        self.sync_all()
        self.mine(POOLS[0])
        bond_key_addr = {}

# Rule: REG-A1
        print('yed_registerattestor on nodes 6 and 7 (refusals first), one per block: seq 0 and 1')
        assert_rpc_error('bond-below-min', wa.yed_registerattestor, 9, BOND_MIN_LOCK)
        assert_rpc_error('lock-below-min', wa.yed_registerattestor, 10, BOND_MIN_LOCK - 1)
        reg = {}
        for node, name in ((wa, 'A'), (wb, 'B')):
            res, seq = register_wallet_attestor(self, node, 10, BOND_MIN_LOCK, 0)
            reg[seq] = res
            assert_equal(res['seq'], None)
            assert_equal(res['bondZat'], 10 * COIN)
            assert_equal(res['flags'], {'tier': 0, 'pool': False})
            raw = node.getrawtransaction(res['txid'], 1)
            assert_equal(raw['vout'][0]['valueZat'], 10 * COIN)
            assert_equal(raw['vout'][0]['scriptPubKey']['addresses'], [res['bondAddress']])
            assert_equal(res['bondOutpoint'], {'txid': res['txid'], 'vout': 0})
            payload = node.yed_decodepayload(raw['vout'][1]['scriptPubKey']['hex'][4:])
            assert_equal((payload['valid'], payload['type']), (True, 'register'))
            # the record the raw path produces is a function of the payload and vout[0]: same keys, locktime, bond address
            assert_equal(payload['register']['attestorPubKey'], res['attestorPubKey'])
            assert_equal(payload['register']['bondLocktime'], res['bondLocktime'])
            assert_equal(payload['register']['bondAddress'], res['bondAddress'])
            assert_equal(payload['register']['flags'], res['flags'])
            assert_equal(pubkey_to_address(hex_str_to_bytes(payload['register']['bondPubKey'])), res['bondKeyAddress'])
            assert_equal(res['bondLocktime'], node.getblockcount() + BOND_MIN_LOCK)     # tip + 1 + lockBlocks at build time
            # the same record the raw path would produce: the bond key address is the P2PKH of the payload's bondPubKey
            assert_equal(node.validateaddress(res['bondKeyAddress'])['ismine'], True)
            assert_equal(node.validateaddress(res['bondAddress'])['ismine'], False)      # the bond is not IsMine (R6)
            bond_key_addr[seq] = res['bondKeyAddress']
            print('  %s registered as seq %d in block %d' % (name, seq, node.getblockcount()))
        assert_same_statehash(self.enforcing_nodes(), 'wallet registrations')

# Rule: S16
        print('yed_signattestation: the hot key signs; the persisted guard refuses a second price for one height')
        cited = wa.getblockcount() - REF_LAG
        signed = wa.yed_signattestation(0, usd_to_micro(50), cited)
        assert_equal((signed['seq'], signed['citedHeight'], signed['reused'], signed['priceMicroUsd']), (0, cited, False, usd_to_micro(50)))
        att0 = hex_str_to_bytes(signed['hex'])
        assert_equal(len(att0), 74)
        assert verify_attestation(hex_str_to_bytes(reg[0]['attestorPubKey']), att0, wa.getblockhash(cited))
        again = wa.yed_signattestation(0, usd_to_micro(50), cited)
        assert_equal((again['reused'], again['hex']), (True, signed['hex']))
        assert_rpc_error('equivocation-guard: seq 0 already signed %d for height %d' % (usd_to_micro(50), cited),
                         wa.yed_signattestation, 0, usd_to_micro(51), cited)
        assert_rpc_error('attest-key-not-held', claimant.yed_signattestation, 0, usd_to_micro(50))
        assert_rpc_error('attest-unknown-seq', wa.yed_signattestation, 99, usd_to_micro(50))
        assert_rpc_error('attest-range', wa.yed_signattestation, 0, 1)
        assert_rpc_error('attest-stale', wa.yed_signattestation, 0, usd_to_micro(50), wa.getblockcount() + 1)
        print('  the guard survives a restart of node 6 (attest-signed.dat)')
        self.restart(ATTESTOR_A)
        wa = nodes[ATTESTOR_A]
        self.sync_all(blocks_only=True)
        assert_rpc_error('equivocation-guard', wa.yed_signattestation, 0, usd_to_micro(52), cited)
        assert_equal(wa.yed_signattestation(0, usd_to_micro(50), cited)['reused'], True)

# Rule: MINT-1 W7
        print('an unarmed two-step mint: the carrier is still created and spent as vin[last]')
        assert_equal(arming_state(user)['status'], 'UNARMED')
        sweep0 = user.yed_sweepcarriers()
        assert_equal((sweep0['count'], sweep0['outstanding'], sweep0['txid']), (0, 0, ''))
        m0 = wallet_mint(self, user, 10000, 48)
        assert_equal((m0['pending'], m0['aMint'], m0['bundleSeqs'], m0['attestFeeZat'], m0['attestPayee']), (False, None, [], 0, None))
        assert_equal(m0['source'], 'x')
        raw0 = user.getrawtransaction(m0['txid'], 1)
        assert_equal(raw0['vin'][-1]['txid'], m0['carrierTxid'])
        carrier0 = user.getrawtransaction(m0['carrierTxid'], 1)
        assert_equal((carrier0['vout'][0]['valueZat'], carrier0['vout'][0]['scriptPubKey']['type']), (CARRIER_VALUE, 'scripthash'))
        assert_equal(carrier0['expiryheight'], m0['refHeight'] + REF_WINDOW)
        assert_equal(raw0['expiryheight'], m0['refHeight'] + REF_WINDOW)
        assert_equal(len(raw0['vout']), 5)                                     # vault, token, payload, pool fee, change
        self.mine(POOLS[1])
        assert_equal(user.yed_getvault(m0['txid'])['status'], 'ACTIVE')
        assert_equal(user.yed_sweepcarriers()['outstanding'], 0)               # spent carriers are forgotten

# Rule: ARM-1 ARM-2
        print('three raw registrations (seq 2-4, one per block) arm the layer by block counting')
        seqs = register_and_arm(self, n=3)
        assert_equal(seqs, [2, 3, 4])
        state = arming_state(user)
        assert_equal(state['status'], 'ARMED')
        print('  triggered at %d, armed at %d, tip %d' % (state['trigger'], state['arm'], user.getblockcount()))
        assert_same_statehash(self.enforcing_nodes(), 'armed')
        r = user.yed_getinfo()['height'] - REF_LAG
        assert_equal(node_selection(self, user, r), sorted(offline_selection(user, r, b'')))   # the derivation agrees with the node

# Rule: MINT-9 MINT-10 BUNDLE-1
        print('armed refusals: no bundle, a malformed bundle, and attestors 2x the pools (refused before any transaction)')
        msg = assert_rpc_error('bundle-insufficient', user.yed_mint, 10000, 48)      # the empty pool: nothing to build from
        assert '0 of %d selected attestors have a fresh attestation; missing seq' % (M_SELECT + K_SLACK) in msg, msg
        assert_rpc_error('bundle-malformed', user.yed_mint, 10000, 48, '', 'zz')
        assert_rpc_error('bundle-malformed', user.yed_mint, 10000, 48, '', '5941ff00')
        r = user.yed_getinfo()['height'] - REF_LAG
        far = offline_bundle_hex(self, user, r, b'', 99)
        assert_rpc_error('mint10-diverged', user.yed_mint, 10000, 48, '', far)
        self.mine(POOLS[0])          # a wallet-held key signs one price per height (S16): the next bundle cites a new R
        r = user.yed_getinfo()['height'] - REF_LAG
        short = offline_bundle_hex(self, user, r, b'', {offline_selection(user, r, b'')[0]: 49})   # one signer < M_SELECT
        assert_rpc_error('bundle-insufficient', user.yed_mint, 10000, 48, '', short)
        assert_rpc_error('selected attestors have a fresh attestation; missing seq', user.yed_mint, 10000, 48, '', short)
        assert_equal(user.yed_sweepcarriers()['outstanding'], 0)               # nothing was built
        assert_equal(user.getrawmempool(), [])
        self.mine(POOLS[1])


# Rule: W6 BUNDLE-1
        print('mint_from_pool: one attestor fed, bundle-insufficient from the pool names the missing seqs; feed_all, then yed_mint with no bundleHex')
        r = user.yed_getinfo()['height'] - REF_LAG
        sel = sorted(offline_selection(user, r, b''))
        feed_pool(self, user, r, b'', {sel[0]: 49})
        msg = assert_rpc_error('bundle-insufficient', user.yed_mint, 10000, 48)
        assert '1 of %d selected attestors have a fresh attestation; missing seq ' % len(sel) in msg, msg
        assert_equal(sorted(int(x) for x in msg.split('missing seq ')[1].split(',')), sel[1:])
        assert_equal(user.yed_sweepcarriers()['outstanding'], 0)
        feed_pool(self, user, r, b'', {s: 49 for s in sel[1:]})
        m0 = wallet_mint(self, user, 10000, 48, bundle_hex='')                  # '' = the node's pool
        assert_equal((m0['pending'], sorted(m0['bundleSeqs'])), (False, sel))
        assert_greater_than(m0['aMint'], usd_to_micro(49) - 1)
        assert_greater_than(usd_to_micro(50), m0['aMint'])
        assert_equal(m0['pMint'], m0['aMint'])
        raw0 = user.getrawtransaction(m0['txid'], 1)
        assert_equal(raw0['vin'][-1]['txid'], m0['carrierTxid'])
        self.mine(POOLS[2])
        assert_equal(user.yed_gettxinfo(m0['txid'])['verdict'], 'ok')
        assert_equal(user.yed_getvault(m0['txid'])['status'], 'ACTIVE')
        assert_same_statehash(self.enforcing_nodes(), 'pool-path mint')

# Rule: MINT-5 MINT-9 AFEE-1 AFEE-W PRICE-2 W7
        print('an armed mint (wait=True): two transactions one block apart, both fees, bundleSeqs, pMint = aMint')
        est = user.yed_estimatecollateral(10700, 48, usd_to_micro(50))     # the override: the pool holds only the last R's selection
        m1 = wallet_mint(self, user, 10700, 48, prices=49)
        assert_equal(m1['pending'], False)
        assert_equal(len(m1['bundleSeqs']), 3)                                  # M_SELECT + K_SLACK all signed
        assert_greater_than(m1['aMint'], usd_to_micro(49) - 1)
        assert_greater_than(usd_to_micro(50), m1['aMint'])
        assert_equal((m1['xMint'], m1['pMint'], m1['source']), (usd_to_micro(50), m1['aMint'], 'a'))
        assert_greater_than(m1['collateralZat'], est['requiredZat'])          # sized at the lower combined price
        assert_equal(m1['attestFeeZat'], m1['feeZat'] * 2500 // 10000)
        # the bond key addresses of the bundle's seqs, from the chain: the raw registrations share one block,
        # so which fixed key became seq 2, 3 or 4 is the block's transaction order, never `seq - 2`
        payable = {rec['bondKeyAddress'] for rec in user.yed_listattestors() if int(rec['seq']) in m1['bundleSeqs']}
        for s in (0, 1):
            assert_equal(bond_key_addr[s], next(rec['bondKeyAddress'] for rec in user.yed_listattestors() if int(rec['seq']) == s))
        assert m1['attestPayee'] in payable, (m1['attestPayee'], payable)
        raw1 = user.getrawtransaction(m1['txid'], 1)
        assert_equal(raw1['vin'][-1]['txid'], m1['carrierTxid'])
        assert_equal(raw1['vout'][3]['scriptPubKey']['addresses'], [m1['payee']])
        assert_equal(raw1['vout'][4]['scriptPubKey']['addresses'], [m1['attestPayee']])
        assert_equal(raw1['vout'][4]['valueZat'], m1['attestFeeZat'])
        payload1 = user.yed_decodepayload(raw1['vout'][2]['scriptPubKey']['hex'][4:])
        assert_equal((payload1['feeVout'], payload1['attestFeeVout'], payload1['refHeight']), (3, 4, m1['refHeight']))
        carrier1 = user.getrawtransaction(m1['carrierTxid'], 1)
        assert_equal(carrier1['confirmations'], 1)
        assert_equal(len(carrier1['vout'][0]['scriptPubKey']['hex']), 46)      # P2SH
        self.mine(POOLS[2])
        v1 = user.yed_getvault(m1['txid'])
        assert_equal((v1['status'], v1['refHeight'], v1['feePaidZat']), ('ACTIVE', m1['refHeight'], m1['feeZat']))
        assert_equal(user.yed_gettxinfo(m1['txid'])['verdict'], 'ok')
        assert_equal(user.yed_getbalance()['confirmedCents'], 30700)
        assert_same_statehash(self.enforcing_nodes(), 'armed mint')

# Rule: W7
        print('wait=False: the pending shape, then the wallet completes on the next block')
        r = user.yed_getinfo()['height'] - REF_LAG
        pending, txid2 = two_step_pending(self, user, 'yed_mint', 10000, 48, '', offline_bundle_hex(self, user, r, b'', 49))
        assert_equal((pending['pending'], pending['txid'], pending['refHeight'], pending['collateralZat']), (True, '', r, 0))
        assert_equal(len(pending['bundleSeqs']), 3)
        assert txid2 in user.getrawmempool()
        assert_equal(user.getrawtransaction(txid2, 1)['vin'][-1]['txid'], pending['carrierTxid'])
        self.mine(POOLS[0])
        assert_equal(user.yed_getvault(txid2)['status'], 'ACTIVE')
        assert_equal(user.yed_sweepcarriers()['outstanding'], 0)

# Rule: MINT-1 W7
        print('a Sapling-funded armed mint: the carrier is funded from ys1... and is the mint\'s only transparent input')
        ys = user.z_getnewaddress('sapling')
        taddr = user.getnewaddress()
        user.sendtoaddress(taddr, Decimal('30.001'))
        self.sync_all()
        self.mine(POOLS[1])
        opid = user.z_sendmany(taddr, [{'address': ys, 'amount': Decimal('30')}], 1, Decimal('0.0001'))
        wait_and_assert_operationid_status(user, opid)
        self.sync_all()
        self.mine(POOLS[2])
        z_before = user.z_getbalance(ys)
        # The note was mined one block ago; on some runs the wallet has not built its witness yet and the
        # builder answers with its designed refusal, "missing witness for a Sapling note; retry after the next
        # block" (txbuilder.cpp). Do what it says, at most three times, and record how many blocks it took.
        for attempt in range(3):
            try:
                mz = wallet_mint(self, user, 10000, 48, ys, prices=49)
                break
            except JSONRPCException as e:
                if 'missing witness' not in e.error['message'] or attempt == 2:
                    raise
                print('  no witness for the Sapling note yet (attempt %d): mining one block and retrying' % (attempt + 1))
                self.mine(POOLS[2])
        assert_equal(mz['fundedFrom'], 'sapling')
        rawz = user.getrawtransaction(mz['txid'], 1)
        assert_equal(len(rawz['vin']), 1)
        assert_equal(rawz['vin'][0]['txid'], mz['carrierTxid'])
        assert_greater_than(len(rawz['vShieldedSpend']), 0)
        carrierz = user.getrawtransaction(mz['carrierTxid'], 1)
        assert_equal(carrierz['vin'], [])
        assert_greater_than(len(carrierz['vShieldedSpend']), 0)
        self.mine(POOLS[0])
        assert_equal(user.yed_getvault(mz['txid'])['status'], 'ACTIVE')
        spent = 2 * YELLOWBACK_FEE + mz['collateralZat'] + TOKEN_VALUE + mz['feeZat'] + mz['attestFeeZat']
        assert_equal(user.z_getbalance(ys), z_before - Decimal(spent) / COIN)

# Rule: W7
        print('a carrier orphaned by a restart survives in carriers.dat and is swept once its window lapses')
        r = user.yed_getinfo()['height'] - REF_LAG
        orphan = user.yed_mint(10000, 48, '', offline_bundle_hex(self, user, r, b'', 49), False)
        assert_equal(orphan['pending'], True)
        self.sync_all()
        self.restart(0)                                  # the pending completion lived in memory; the carrier record did not
        user = nodes[0]
        self.sync_all()
        self.mine(POOLS[1])                              # the carrier confirms; nobody completes the mint
        assert_equal(user.yed_sweepcarriers(), {'txid': '', 'count': 0, 'reclaimedZat': 0, 'outstanding': 1})
        assert_equal(user.gettxout(orphan['carrierTxid'], 0)['value'], Decimal(CARRIER_VALUE) / COIN)
        self.mine_round_robin(POOLS, REF_WINDOW)
        swept = user.yed_sweepcarriers()
        assert_equal((swept['count'], swept['reclaimedZat'], swept['outstanding']), (1, CARRIER_VALUE - YELLOWBACK_FEE, 0))
        rawsw = user.getrawtransaction(swept['txid'], 1)
        assert_equal([v['txid'] for v in rawsw['vin']], [orphan['carrierTxid']])
        self.sync_all()
        self.mine(POOLS[2])
        assert_equal(user.gettxout(orphan['carrierTxid'], 0), None)
        assert_equal(user.yed_sweepcarriers()['outstanding'], 0)

# Rule: EQV-1
        print('yed_reportequivocation: two prices from seq 2 for one height eject it')
        cited = user.getblockcount() - REF_LAG
        secret2 = hot_secret_for(user, 2)
        a = sign_attestation(secret2, 2, usd_to_micro(49), cited, user.getblockhash(cited))
        b = sign_attestation(secret2, 2, usd_to_micro(60), cited, user.getblockhash(cited))
        assert_rpc_error('not-equivocation: the prices are equal', claimant.yed_reportequivocation, bytes_to_hex_str(a), bytes_to_hex_str(a))
        assert_rpc_error('attest-malformed', claimant.yed_reportequivocation, 'abcd', bytes_to_hex_str(a))
        eq = wallet_report_equivocation(self, claimant, bytes_to_hex_str(a), bytes_to_hex_str(b))
        assert_equal((eq['seq'], eq['citedHeight'], eq['priceA'], eq['priceB'], eq['pending']), (2, cited, usd_to_micro(49), usd_to_micro(60), False))
        raweq = claimant.getrawtransaction(eq['txid'], 1)
        assert_equal(raweq['vin'][-1]['txid'], eq['carrierTxid'])
        self.mine(POOLS[0])
        note_attestor_status(2, 'EJECTED')
        assert_rpc_error('not-equivocation: seq 2 is EJECTED', claimant.yed_reportequivocation, bytes_to_hex_str(a), bytes_to_hex_str(b))
        assert_same_statehash(self.enforcing_nodes(), 'ejection')
        print('  a mint after the ejection: the selection no longer includes seq 2 and the bundle still verifies')
        self.mine_round_robin(POOLS, 2)
        m3 = wallet_mint(self, user, 10000, 48, prices=49)
        assert 2 not in m3['bundleSeqs'], m3['bundleSeqs']
        self.mine(POOLS[1])
        assert_equal(user.yed_getvault(m3['txid'])['status'], 'ACTIVE')

# Rule: REV-1
        print('dormancy and yed_revive: seq 1 (node 7) never signs; two selecting bundles in one window make it DORMANT')
        assert_rpc_error('not-dormant', wb.yed_revive, 1, usd_to_micro(49))
        assert_rpc_error('not-dormant', wa.yed_revive, 1, usd_to_micro(49))     # the status is judged before the key
        # two bundles selecting seq 1 without its signature, both inside one DORMANCY_BLOCKS window —
        # and no row in that window where it signed: the mint after the ejection carried its
        # attestation, so let a whole window pass first
        self.mine_round_robin(POOLS, 16)
        rows = []
        tries = 0
        while len(rows) < 2 and tries < 24:
            r = user.yed_getinfo()['height'] - REF_LAG
            sel = sorted(offline_selection(user, r, b''))
            assert_equal(node_selection(self, user, r), sel)
            if 1 in sel:
                prices = {s: 49 for s in offline_selection(user, r, b'') if s != 1}
                mm = wallet_mint(self, user, 10000, 48, prices=prices)
                assert 1 not in mm['bundleSeqs']
                self.mine(POOLS[tries % 3])
                rows.append(user.getblockcount())
                if len(rows) == 2 and rows[1] - rows[0] > 10:
                    rows = rows[1:]
            else:
                self.mine(POOLS[tries % 3])
            tries += 1
        assert_equal(len(rows), 2)
        for h in rows:
            assert_equal([t['verdict'] for t in [user.yed_gettxinfo(m) for m in user.getblock(user.getblockhash(h))['tx'][1:] if user.yed_gettxinfo(m)['type'] == 'mint']], ['ok'])
        # the dormancy pass runs at H % DORMANCY_CHECK == 0 and reads the last DORMANCY_BLOCKS rows
        while user.getblockcount() % DORMANCY_CHECK != 0:
            self.mine(POOLS[0])
        check_height = user.getblockcount()
        print('  selecting rows at %s, dormancy check at %d, seq 1 registered at %d' % (rows, check_height, REGISTRY['attestors'][1]['register']))
        # SNAP seats before it judges dormancy (§3.8 order), so Snapshots[H].seated still holds the
        # newly DORMANT seq; from H + 1 on it is gone — read the selection at R = H + 1.
        self.mine_round_robin(POOLS, 3)
        r = user.yed_getinfo()['height'] - REF_LAG
        assert_equal(r, check_height + 1)
        note_attestor_status(1, 'DORMANT')                       # a DORMANT seq leaves seated(R): the node's selection shows it
        assert_equal(node_selection(self, user, r), sorted(offline_selection(user, r, b'')))
        assert_rpc_error('attest-key-not-held', wa.yed_revive, 1, usd_to_micro(49))   # DORMANT now, but node 6 has no key for seq 1
        revived = wb.yed_revive(1, usd_to_micro(49))
        assert_equal((revived['seq'], revived['citedHeight']), (1, wb.getblockcount() - REF_LAG))
        assert_equal(len(hex_str_to_bytes(revived['hex'])), 74)
        assert_equal(wb.yed_signattestation(1, usd_to_micro(49), revived['citedHeight'])['reused'], True)   # the same guard
        self.sync_all()
        self.mine(POOLS[2])
        note_attestor_status(1, 'ELIGIBLE')
        assert_rpc_error('not-dormant', wb.yed_revive, 1, usd_to_micro(49))
        assert_same_statehash(self.enforcing_nodes(), 'revival')
        self.mine_round_robin(POOLS, REF_LAG)                    # the next R sees seq 1 seated again

# Rule: RED-1 RED-3 RED-4 RED-5 NOT-1 AFEE-1
        print('claims: vaults V1 (normal) and V2 (emergency) minted at $50, the claimant funded with YED')
        v1 = wallet_mint(self, user, 10000, 48, prices=49)
        self.mine(POOLS[0])
        v2 = wallet_mint(self, user, 10000, 48, prices=49)
        self.mine(POOLS[1])
        user.yed_send(claimant.yed_getnewaddress(), 10000)
        self.sync_all()
        self.mine(POOLS[2])
        user.yed_send(claimant.yed_getnewaddress(), 10000)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(claimant.yed_getbalance()['confirmedCents'], 20000)
        claim_height = max(user.yed_getvault(v1['txid'])['claimHeight'], user.yed_getvault(v2['txid'])['claimHeight'])
        print('  pools fall to $10.20 over the slow window; both vaults reach claimHeight %d' % claim_height)
        self.price('10.20')
        self.mine_round_robin(POOLS, max(64, claim_height - user.getblockcount()) + REF_LAG)
        assert_equal(user.yed_getprice()['pClaim'], usd_to_micro('10.20'))
        assert_equal(user.yed_getvault(v1['txid'])['claimable'], True)         # 5 x 100 / 49 YEC at $10.20 < 110 %

        # attested prices within one BundleLog window stay within PIN_DELTA_BPS of each other ($10.50 here, $11 for V2):
        # a wider spread arms PIN-1 and pins every pool key quoting one constant price, leaving no xClaim
        print('  V1: the normal claim (clause a) with attestors at $10.50: attestor fee, no residual, carrier never vin[0]')
        c1 = wallet_claim(self, claimant, v1['txid'], prices='10.50')
        assert_equal((c1['pending'], c1['claimPath'], c1['residualZat'], c1['burnedCents']), (False, 'a', 0, 10000))
        assert_equal((c1['xClaim'], c1['pClaim'], c1['pEmerg']), (usd_to_micro('10.20'), c1['aClaim'], None))   # pClaim = max(x, a)
        assert_greater_than(c1['aClaim'], c1['xClaim'])
        assert_equal(c1['attestFeeZat'], c1['feeZat'] * 2500 // 10000)
        rawc1 = claimant.getrawtransaction(c1['txid'], 1)
        assert_equal(rawc1['vin'][0]['txid'], v1['txid'])
        assert_equal(rawc1['vin'][-1]['txid'], c1['carrierTxid'])
        assert_equal(rawc1['vout'][0]['valueZat'], c1['collateralOut'])
        assert_equal(rawc1['vout'][1]['valueZat'], c1['feeZat'])
        afee = [o for o in rawc1['vout'] if o['valueZat'] == c1['attestFeeZat'] and o['scriptPubKey']['addresses'] == [c1['attestPayee']]]
        assert_equal(len(afee), 1)
        vault1 = user.yed_getvault(v1['txid'])
        assert_equal(c1['collateralOut'], vault1['collateralZat'] + CARRIER_VALUE + TOKEN_VALUE - YELLOWBACK_FEE - c1['feeZat'] - c1['attestFeeZat'])
        assert_equal(user.yed_validaterawtransaction(rawc1['hex'])['verdict'], 'ok')
        self.mine(POOLS[1])
        assert_equal(user.yed_getvault(v1['txid'])['status'], 'CLAIMED')
        info1 = user.yed_gettxinfo(c1['txid'])
        assert_equal((info1['verdict'], info1['path']), ('ok', 'claim'))

        print('  V2: not claimable under the combined pClaim with attestors at $11, but under EMERGENCY_RATIO at pEmerg')
        # canNotice is judged with the bundle this node would build (EstimateClaim): with an empty
        # pool the cross-section alone reads clause (a) at $10.20, so feed the user's pool at $11 first
        feed_pool(self, user, user.yed_getinfo()['height'], outpoint_selector(v2['txid'], 0), 11)
        pos = {p['txid']: p for p in user.yed_listpositions('ACTIVE')}
        assert_equal((pos[v2['txid']]['noticed'], pos[v2['txid']]['noticeHeight'], pos[v2['txid']]['emergencyOpenAt']), (False, None, None))
        assert_equal((pos[v2['txid']]['canNotice'], pos[v2['txid']]['canClaim']), (True, False))
        assert_rpc_error('claim-not-underwater', claimant.yed_claim, v2['txid'], '',
                         offline_bundle_hex(self, claimant, claimant.yed_getinfo()['height'], outpoint_selector(v2['txid'], 0), 11))
        notice = wallet_notice(self, claimant, v2['txid'], prices=11)
        assert_equal((notice['pending'], notice['vault'], notice['emergencyOpenAt']), (False, v2['txid'] + ':0', notice['refHeight'] + EMERGENCY_PERSIST))
        assert_equal(notice['xClaim'], usd_to_micro('10.20'))
        assert_equal(notice['pEmerg'], usd_to_micro('10.20'))                   # min(xClaim, aClaim)
        assert_greater_than(notice['aClaim'], notice['xClaim'])
        rawn = claimant.getrawtransaction(notice['txid'], 1)
        assert_equal(rawn['vin'][-1]['txid'], notice['carrierTxid'])
        assert_equal(claimant.yed_decodepayload(rawn['vout'][0]['scriptPubKey']['hex'][4:])['type'], 'notice')
        self.mine(POOLS[2])
        notice_height = user.getblockcount()
        pos = {p['txid']: p for p in user.yed_listpositions('ACTIVE')}
        assert_equal((pos[v2['txid']]['noticed'], pos[v2['txid']]['noticeHeight'], pos[v2['txid']]['emergencyOpenAt'], pos[v2['txid']]['canNotice']),
                     (True, notice_height, notice['refHeight'] + EMERGENCY_PERSIST, False))
        assert_rpc_error('notice-standing', claimant.yed_claimnotice, v2['txid'],
                         offline_bundle_hex(self, claimant, claimant.yed_getinfo()['height'], outpoint_selector(v2['txid'], 0), 11))
        print('  before EMERGENCY_PERSIST the claim is refused; after it clause (b) opens with the residual to the owner')
        assert_rpc_error('claim-not-underwater', claimant.yed_claim, v2['txid'], '',
                         offline_bundle_hex(self, claimant, claimant.yed_getinfo()['height'], outpoint_selector(v2['txid'], 0), 11))
        self.mine_round_robin(POOLS, notice['refHeight'] + EMERGENCY_PERSIST - user.getblockcount())
        assert_equal([p['canClaim'] for p in claimant.yed_listpositions()], [])   # not the claimant's vault
        owner_addr = user.yed_getvault(v2['txid'])['ownerAddress']
        owner_t = user.validateaddress(user.yed_validateaddress(owner_addr)['transparentAddress'])['address']
        yec_owner_before = user.getbalance()
        zs = claimant.z_getnewaddress('sapling')
        c2 = wallet_claim(self, claimant, v2['txid'], zs, prices=11)
        assert_equal((c2['claimPath'], c2['to'], c2['burnedCents']), ('b', zs, 10000))
        # F-7 (regtest plan section 8.1; v3 plan 6.2 D-R-1): the claim spends a vault this wallet never
        # held. The inherited CommitTransaction indexes mapWallet by every input's txid and used to leave a
        # blank entry under the vault's id; the first trust walk over the unconfirmed claim (getbalance,
        # any AvailableCoins) then read that entry's empty vout and the node segfaulted. The claim is
        # still unconfirmed here, which is exactly when the walk happens.
        assert_rpc_error('non-wallet', claimant.gettransaction, v2['txid'])
        claimant.getbalance()
        claimant.yed_listunspent()
        assert 'blockhash' not in claimant.getrawtransaction(c2['txid'], 1)     # still unconfirmed: the walk above was the real one
        assert_equal(c2['pEmerg'], usd_to_micro('10.20'))
        assert_equal(c2['pClaim'], c2['aClaim'])
        vault2 = user.yed_getvault(v2['txid'])
        expected_residual = vault2['collateralZat'] - (10000 * 10000 * COIN + c2['pClaim'] - 1) // c2['pClaim']
        assert_equal(c2['residualZat'], expected_residual)
        assert_greater_than(c2['residualZat'], 100000)
        rawc2 = claimant.getrawtransaction(c2['txid'], 1)
        assert_equal(len(rawc2['vShieldedOutput']), 1)
        residual_out = [o for o in rawc2['vout'] if o['scriptPubKey'].get('addresses') == [owner_t]]
        assert_equal(len(residual_out), 1)
        assert_equal(residual_out[0]['valueZat'], c2['residualZat'])
        assert_equal(rawc2['vin'][-1]['txid'], c2['carrierTxid'])
        assert_equal(c2['collateralOut'], vault2['collateralZat'] + CARRIER_VALUE + TOKEN_VALUE - YELLOWBACK_FEE - c2['feeZat'] - c2['attestFeeZat'] - c2['residualZat'])
        self.mine(POOLS[0])
        vault2 = user.yed_getvault(v2['txid'])
        assert_equal(vault2['status'], 'CLAIMED')
        assert_greater_than(user.getbalance() + Decimal('0.00000001'), yec_owner_before + Decimal(c2['residualZat']) / COIN)
        assert_equal(claimant.z_getbalance(zs), Decimal(c2['collateralOut']) / COIN)
        assert_equal(claimant.yed_getbalance()['confirmedCents'], 0)
        assert_same_statehash(self.enforcing_nodes(), 'claims')

# Rule: IN-2 R6
        print('the bond: never spent by sendtoaddress; withdrawable after the locktime from a wallet that imported the bond key')
        assert_equal([u for u in wa.listunspent(0) if u['scriptPubKey'].startswith('a914')], [])
        wa.sendtoaddress(user.getnewaddress(), Decimal(str(wa.getbalance())) - Decimal('0.01'))
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(wa.gettxout(reg[0]['txid'], 0)['value'], Decimal(10))
        assert_rpc_error('bond-locked', wa.yed_withdrawbond, 0)
        assert_rpc_error('attest-key-not-held', wb.yed_withdrawbond, 0)
        assert_rpc_error('attest-unknown-seq', wa.yed_withdrawbond, 77)
        claimant.importprivkey(wa.dumpprivkey(reg[0]['bondKeyAddress']), 'restored-bond', True)     # -rescan in place (R6: found through Attestors)
        assert_equal(claimant.validateaddress(reg[0]['bondKeyAddress'])['ismine'], True)
        assert_rpc_error('bond-locked', claimant.yed_withdrawbond, 0)
        self.mine_round_robin(POOLS, reg[0]['bondLocktime'] - user.getblockcount())
        wd = claimant.yed_withdrawbond(0)
        assert_equal((wd['seq'], wd['bondZat'], wd['bondOut']), (0, 10 * COIN, 10 * COIN - YELLOWBACK_FEE))
        rawwd = claimant.getrawtransaction(wd['txid'], 1)
        assert_equal((rawwd['vin'][0]['txid'], rawwd['vin'][0]['vout'], rawwd['locktime']), (reg[0]['txid'], 0, reg[0]['bondLocktime']))
        assert_equal(rawwd['vout'][0]['scriptPubKey']['addresses'], [wd['to']])
        self.sync_all()
        self.mine(POOLS[2])
        note_attestor_status(0, 'WITHDRAWN')
        assert_equal(wa.gettxout(reg[0]['txid'], 0), None)
        assert_rpc_error('bond-spent', wa.yed_withdrawbond, 0)
        assert_rpc_error('bond-spent', claimant.yed_withdrawbond, 0)
        assert_same_statehash(self.enforcing_nodes(), 'withdrawal')

# Rule: MINT-10 MINT-5 PRICE-2
        print('W17: a rally -- pools jump to $90; after a fast window the attestors agree with the fast median, the mint goes through, priced at the lagging minimum')
        self.price(90)                                                          # ($100 is PRICE_MAX itself, which yed_signattestation refuses)
        self.mine_round_robin(POOLS, P_FAST_WINDOW + REF_LAG)
        pr = user.yed_getprice()
        assert abs(pr['pFast'] - usd_to_micro(90)) < usd_to_micro(1), pr        # the pools' quotes carry a small per-pool jitter
        assert_greater_than(usd_to_micro(80), pr['pMint'])                      # the slow window still remembers the old price
        rally = wallet_mint(self, user, 10000, 48, prices=90)                   # the offline bundle at $90: agreeing with pFast, not with xMint
        assert_equal((rally['pending'], rally['source']), (False, 'x'))
        assert abs(rally['aMint'] - usd_to_micro(90)) < usd_to_micro(1), rally   # the offline bundle follows the jittered quotes
        assert_equal(rally['pMint'], rally['xMint'])                            # MINT-5 at the conservative minimum
        assert_greater_than(rally['aMint'], rally['pMint'])
        self.mine(POOLS[2])
        assert_equal(user.yed_getvault(rally['txid'])['status'], 'ACTIVE')
        assert_same_statehash(self.enforcing_nodes(), 'rally')

        print('the Python model over the whole chain')
        model_check(nodes[2], full=True)
        self.checkpoint('end')


if __name__ == '__main__':
    YellowbackAttestWalletTest().main()
