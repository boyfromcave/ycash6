#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Phase 4 (plan section 6, Phase 4; section 3.9 TPL-1..3, MP-1, MINER-1..3; section 4.4):
tag emission, getblocktemplate fields and the pool path, invalid tags, the coinbase payload
(TX-0), quote staleness, the template policies, MP-1 and the ConnectTip sweep."""

import time

from test_framework.authproxy import JSONRPCException
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_start_raises_init_error,
    bytes_to_hex_str,
    hex_str_to_bytes,
    start_node,
    stop_node,
    sync_mempools,
)
from test_framework.yellowback_util import (
    POOLS,
    PRICE_MAX,
    REF_LAG,
    REF_WINDOW,
    STOCK,
    TOKEN_VALUE,
    YELLOWBACK_FEE,
    YellowbackTestFramework,
    _select_funding,
    assert_best_hash,
    assert_same_statehash,
    build_mint_tx,
    build_vault_spend_raw,
    fee_zat,
    mine_block_raw,
    set_quote,
    template_coinbase,
    vault_from_mint,
    wait_yed_healthy,
    yellowback_node_args,
    ym,
)

# The v4.5.0 getblocktemplate key set (ref/ycash/src/rpc/mining.cpp:754-781 with coinbasetxn = true).
V450_GBT_KEYS = sorted([
    'capabilities', 'version', 'previousblockhash', 'lightclientroothash', 'finalsaplingroothash',
    'transactions', 'coinbasetxn', 'longpollid', 'target', 'mintime', 'mutable', 'noncerange',
    'sigoplimit', 'sizelimit', 'curtime', 'bits', 'height',
])
V450_MUTABLE = ['time', 'transactions', 'prevblock']
PRICE = 2_000_000       # $2.00
CENTS = 10_000          # $100
LOCK = 48               # class A minimum


def rpc_error(substr, fn, *args):
    try:
        fn(*args)
    except JSONRPCException as e:
        assert substr in e.error['message'], 'expected %r in %r' % (substr, e.error['message'])
        return e.error['message']
    raise AssertionError('expected an RPC error containing %r' % substr)


def gbt_hashes(gbt):
    return [t['hash'] for t in gbt['transactions']]


def send_locked(node, hex_):
    """``sendrawtransaction`` then lock the inputs: the wallet's ``listunspent`` does not see a raw
    transaction's inputs as spent, so the next hand-built one would pick the same coin."""
    txid = node.sendrawtransaction(hex_)
    node.lockunspent(False, [{'txid': i.prev_txid, 'vout': i.prev_n} for i in ym.tx_from_hex(hex_).vin])
    return txid


def wait_for_mempool(node, txid, present=True, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if (txid in node.getrawmempool()) == present:
            return
        time.sleep(0.2)
    raise AssertionError('%s %s in mempool after %ds' % (txid, 'not' if present else 'still', timeout))


class YellowbackMiningTest(YellowbackTestFramework):
    """# Rule: MINER-1 MINER-2 MINER-3 TPL-1 TPL-2 MP-1 TAG-1 TAG-2 TAG-4 TX-0 UNDO RED-2 RED-3 FEE-2 XFER-2"""

    initial_blocks = 220     # node 0 funds four hand-built mints of ~250 YEC each (2 YEC/USD, class A 500 %)

    def setup_helpers(self):
        self.pool_key = [ym.address_key_hash(a) for a in self.pool_addresses]

    def pool(self, i):
        """The pool node ``i`` (2..4) and its payout address."""
        return self.nodes[i], self.pool_addresses[POOLS.index(i)]

    def requote(self, pools=None):
        for i in (POOLS if pools is None else pools):
            set_quote(self.nodes[i], '2.00')

    def start_custom(self, i, args):
        """Start node ``i`` (stopped) with ``args`` instead of its role arguments; reconnect."""
        self.nodes[i] = start_node(i, self.options.tmpdir, args, binary=self.node_binaries()[i])
        if self.mock_time is not None:
            self.nodes[i].setmocktime(self.mock_time)
        self.reconnect(i)

    def assert_tag(self, ref, kind, payout=None, price=None, signal=None):
        tag = self.nodes[0].yed_gettag(str(ref))
        if kind == 'none':
            assert_equal(tag['found'], False)
            return tag
        assert_equal(tag['found'], True)
        assert_equal(tag['kind'], kind)
        if payout is not None:
            assert_equal(tag['payoutAddress'], payout)
        if price is not None:
            assert_equal(tag['priceMicroUsd'], price)
        if signal is not None:
            assert_equal(tag['signal'], signal)
        return tag

    # ------------------------------------------------------------------ the cases

    def gbt_shape_without_flag(self):
        # Rule: MINER-1
        # N10: a node without -yellowback answers getblocktemplate with v4.5.0's exact key set.
        print('gbt_shape_without_flag')
        gbt = self.nodes[STOCK].getblocktemplate()
        assert_equal(sorted(gbt.keys()), V450_GBT_KEYS)
        assert 'yellowback' not in gbt
        assert 'coinbaseaux' not in gbt
        assert_equal(gbt['mutable'], V450_MUTABLE)

    def tag_in_generate_blocks(self):
        # Rule: MINER-1 MINER-2 TAG-1
        print('a pool\'s generate block carries the tag')
        self.requote()
        for i in POOLS:
            node, addr = self.pool(i)
            h = self.mine(i)[0]
            tag = self.assert_tag(h, 'quote', payout=addr, price=PRICE, signal=True)
            assert_equal(tag['sourceMask'], 1)
            assert_equal(self.nodes[0].getblock(h)['height'], node.getblockcount())
        self.checkpoint('tagged generate blocks')

    def gbt_fields(self):
        # Rule: MINER-1 TAG-1
        # V26: coinbaseaux.flags = the tag push, mutable has coinbase/append, coinbasetxn carries it, the yellowback object.
        print('getblocktemplate fields on a pool')
        node, addr = self.pool(2)
        gbt = node.getblocktemplate()
        flags = gbt['coinbaseaux']['flags']
        expected = ym.tag_push(1, PRICE, 1, self.pool_key[0])
        assert_equal(flags, bytes_to_hex_str(expected))
        assert_equal(len(hex_str_to_bytes(flags)), 37)
        assert_equal(flags[:10], '2459454421')
        assert 'coinbase/append' in gbt['mutable']
        assert_equal(gbt['mutable'][:3], V450_MUTABLE)
        cb = ym.tx_from_hex(gbt['coinbasetxn']['data'])
        script_sig = cb.vin[0].script_sig
        assert script_sig.startswith(ym.height_prefix(gbt['height']))
        assert script_sig.endswith(expected)
        yb = gbt['yellowback']
        assert_equal(yb['tag'], flags)
        assert_equal(yb['kind'], 'quote')
        assert_equal(yb['priceMicroUsd'], PRICE)
        assert_equal(yb['signal'], True)
        assert_equal(yb['payoutAddress'], addr)
        assert_greater_than(yb['quoteAgeSeconds'] + 1, 0)
        assert_equal(yb['registered'], True)
        assert_equal(yb['eligible'], True)
        assert_equal(yb['activation'], 'signaling')
        assert_equal(type(yb['signalCount']), int)
        assert_equal(yb['enforcing'], True)
        assert_equal(yb['valveTripped'], False)
        assert_equal(yb['sunset'], False)
        assert_equal(yb['healthy'], True)
        assert_equal(yb['templatePolicy'], 'strict')
        assert_equal(sorted(yb.keys()), sorted([
            'tag', 'kind', 'priceMicroUsd', 'quoteAgeSeconds', 'signal', 'payoutAddress', 'registered',
            'eligible', 'activation', 'signalCount', 'enforcing', 'valveTripped', 'sunset', 'healthy',
            'templatePolicy']))

    def pool_path_end_to_end(self):
        # Rule: MINER-1 TAG-1
        # V26: a pool that assembles its own coinbase appends coinbaseaux.flags (BIP 22); submitblock accepts, the tag is read.
        print('the pool path: Python coinbase rebuild + coinbaseaux.flags + submitblock')
        node, addr = self.pool(3)
        cb, gbt = template_coinbase(node)
        flags = hex_str_to_bytes(gbt['coinbaseaux']['flags'])
        extranonce = ym.push(b'pool')
        cb.vin[0].scriptSig = ym.height_prefix(gbt['height']) + extranonce + flags
        result, bh = mine_block_raw(node, [], coinbase=cb, gbt=gbt)
        assert_equal(result, None)
        self.sync_all(blocks_only=True)
        assert_best_hash(self.nodes)
        assert_equal(self.nodes[0].getbestblockhash(), bh)
        self.assert_tag(bh, 'quote', payout=addr, price=PRICE, signal=True)
        mined = self.nodes[0].getblock(bh, 2)['tx'][0]
        assert bytes_to_hex_str(extranonce) in mined['vin'][0]['coinbase']
        self.checkpoint('pool path')

    def tag2_invalid_tag_is_no_tag(self):
        # Rule: TAG-2 TAG-4 UNDO
        print('tag2_invalid_tag_is_no_tag')
        stock = self.nodes[STOCK]
        bad_tags = [
            ('version 2', ym.tag_push(1, PRICE, 1, self.pool_key[0], version=2)),
            ('flags 0x02', ym.tag_push(0x02, PRICE, 1, self.pool_key[0])),
            ('price PRICE_MAX + 1', ym.tag_push(1, PRICE_MAX + 1, 1, self.pool_key[0])),
        ]
        for label, bad in bad_tags:
            cb, gbt = template_coinbase(stock)
            cb.vin[0].scriptSig = ym.height_prefix(gbt['height']) + ym.push(b'x') + bad
            before = {i: self.nodes[i].yed_getstatehash()['statehash'] for i in POOLS}
            result, bh = mine_block_raw(stock, [], coinbase=cb, gbt=gbt)
            assert_equal(result, None)
            self.sync_all(blocks_only=True)
            assert_best_hash(self.nodes, label)
            h = self.nodes[0].getblockcount()
            assert_equal(self.nodes[0].getblockhash(h), bh)
            self.assert_tag(bh, 'none')
            assert_equal(self.nodes[0].yed_getprice(h)['tag']['found'], False)
            assert_equal(self.nodes[0].yed_gethistory(h, h)[0]['tagged'], False)
            assert_same_statehash(self.enforcing_nodes(), label)
        # the last one orphaned by nodes 2-4: Tags unchanged, the undo restores the pre-block state
        for i in POOLS:
            self.nodes[i].invalidateblock(bh)
            assert_equal(self.nodes[i].getblockcount(), h - 1)
            assert_equal(self.nodes[i].yed_getstatehash()['statehash'], before[i])
        for i in POOLS:
            self.nodes[i].reconsiderblock(bh)
        self.sync_all(blocks_only=True)
        assert_best_hash(self.nodes)
        assert_same_statehash(self.enforcing_nodes(), 'after reconsider')
        self.assert_tag(bh, 'none')

    def tx0_coinbase_payload_registers_nothing(self):
        # Rule: TX-0
        print('tx0_coinbase_payload_registers_nothing')
        from test_framework.mininode import CTxOut
        node, addr = self.pool(2)
        cb, gbt = template_coinbase(node)
        owner = hex_str_to_bytes(node.validateaddress(node.getnewaddress())['pubkey'])
        payload = ym.encode_mint(0, CENTS, gbt['height'] + LOCK, gbt['height'] - REF_LAG, owner, 0xFF)
        cb.vout.insert(1, CTxOut(0, bytes([ym.OP_RETURN]) + ym.push(payload)))
        cb.rehash()
        before = self.nodes[0].yed_getstats()
        result, bh = mine_block_raw(node, [], coinbase=cb, gbt=gbt)
        assert_equal(result, None)
        self.sync_all(blocks_only=True)
        assert_best_hash(self.nodes)
        cb_txid = self.nodes[0].getblock(bh)['tx'][0]
        assert_equal(cb_txid, cb.hash)
        rpc_error('tx-not-found', self.nodes[0].yed_gettxinfo, cb_txid)
        after = self.nodes[0].yed_getstats()
        for k in ('supplyCents', 'collateralZat', 'activeVaults', 'voidVaults', 'closedVaults', 'unbackedCents'):
            assert_equal(after[k], before[k])
        self.assert_tag(bh, 'quote', payout=addr)      # the scriptSig was untouched
        self.checkpoint('coinbase payload')

    def quote_staleness_signal_only(self):
        # Rule: MINER-1
        # P12: the clock advances by setmocktime, never sleep; default -yellowbackquotemaxage is 1800 s.
        print('a quote older than -yellowbackquotemaxage gives a signal-only tag')
        node, addr = self.pool(2)
        set_quote(node, '2.00')
        assert_equal(node.getblocktemplate()['yellowback']['kind'], 'quote')
        self.advance_clock(1801)
        h = self.mine(2)[0]
        self.assert_tag(h, 'signal', payout=addr, price=0, signal=True)
        yb = node.getblocktemplate()['yellowback']
        assert_equal(yb['kind'], 'signal')
        assert_equal(yb['priceMicroUsd'], 0)
        assert_greater_than(yb['quoteAgeSeconds'], 1800)
        assert_equal(yb['tag'], bytes_to_hex_str(ym.tag_push(1, 0, 0, self.pool_key[0])))
        self.requote()
        h = self.mine(2)[0]
        self.assert_tag(h, 'quote', payout=addr, price=PRICE)

    def setquote_zero_signal_only(self):
        # Rule: MINER-1
        print('yed_setquote 0 gives a signal-only tag')
        node, addr = self.pool(3)
        r = set_quote(node, 0)
        assert_equal(r['priceMicroUsd'], 0)
        assert_equal(r['nextTag']['kind'], 'signal')
        yb = node.getblocktemplate()['yellowback']
        assert_equal(yb['kind'], 'signal')
        assert_equal(yb['quoteAgeSeconds'], None)
        h = self.mine(3)[0]
        self.assert_tag(h, 'signal', payout=addr, price=0, signal=True)
        set_quote(node, '2.00')
        h = self.mine(3)[0]
        self.assert_tag(h, 'quote', payout=addr, price=PRICE)

    def no_signal_no_quote_no_tag(self):
        # Rule: MINER-1
        print('-yellowbacksignal=0 and no quote: no tag')
        self.restart(4, ['-yellowbacksignal=0'])
        node, addr = self.pool(4)
        gbt = node.getblocktemplate()
        assert_equal(gbt['coinbaseaux']['flags'], '')
        assert_equal(gbt['yellowback']['kind'], 'none')
        assert_equal(gbt['yellowback']['tag'], '')
        assert_equal(gbt['yellowback']['signal'], False)
        assert_equal(gbt['yellowback']['payoutAddress'], addr)
        h = self.mine(4)[0]
        self.assert_tag(h, 'none')
        # the signal bit alone (no quote) is a signal-only tag
        self.restart(4)
        h = self.mine(4)[0]
        self.assert_tag(h, 'signal', payout=addr, price=0, signal=True)
        set_quote(node, '2.00')

    def unhealthy_index_no_tag(self):
        # Rule: MINER-3
        # K24: -yellowbackrequirehealthy makes getblocktemplate refuse while unhealthy.
        print('an unhealthy index emits no tag; -yellowbackrequirehealthy refuses templates')
        self.restart(4, ['-yellowbacktestfault=storage:commit', '-yellowbackrequirehealthy'])
        node, addr = self.pool(4)
        set_quote(node, '2.00')
        assert_equal(node.getblocktemplate()['yellowback']['healthy'], True)
        h = self.mine(4)[0]                      # the commit fault fires; the block still connects
        assert_equal(node.yed_getinfo()['healthy'], False)
        self.assert_tag(h, 'quote', payout=addr)  # built while the index was still healthy
        rpc_error('yellowback-unhealthy', node.getblocktemplate)
        h = self.mine(4)[0]
        self.assert_tag(h, 'none')
        assert_best_hash(self.nodes)
        self.restart(4, ['-reindex-yellowback'])
        wait_yed_healthy(node)
        set_quote(node, '2.00')
        h = self.mine(4)[0]
        self.assert_tag(h, 'quote', payout=addr)
        assert_equal(node.getblocktemplate()['yellowback']['healthy'], True)
        self.checkpoint('after -reindex-yellowback')

    def miner2_default_from_mineraddress(self):
        # Rule: MINER-2
        print('miner2_default_from_mineraddress')
        node = self.nodes[2]
        taddr = node.getnewaddress()
        zaddr = node.z_getnewaddress('sapling')
        stop_node(node, 2)
        self.start_custom(2, yellowback_node_args(['-mineraddress=%s' % taddr, '-yellowbacksignal=1'], sigma_ref=0))
        node = self.nodes[2]
        assert_equal(set_quote(node, '2.00')['nextTag']['payoutAddress'], taddr)
        assert_equal(node.getblocktemplate()['yellowback']['payoutAddress'], taddr)
        h = self.mine(2)[0]
        self.assert_tag(h, 'quote', payout=taddr, price=PRICE)
        stop_node(node, 2)
        self.start_custom(2, yellowback_node_args(['-mineraddress=%s' % zaddr, '-yellowbacksignal=1'], sigma_ref=0))
        node = self.nodes[2]
        rpc_error('no-payout-address', set_quote, node, '2.00')
        yb = node.getblocktemplate()['yellowback']
        assert_equal(yb['kind'], 'none')
        assert_equal(yb['payoutAddress'], None)
        h = self.mine(2)[0]
        self.assert_tag(h, 'none')
        stop_node(node, 2)
        self.nodes[2] = None

    def miner2_non_p2pkh_refused(self):
        # Rule: MINER-2
        print('miner2_non_p2pkh_refused')
        p2sh = self.nodes[0].addmultisigaddress(1, [self.nodes[0].getnewaddress()])
        assert ym.is_p2sh(_spk(self.nodes[0], p2sh))
        assert_start_raises_init_error(2, self.options.tmpdir,
                                       yellowback_node_args(['-yellowbackpayoutaddress=%s' % p2sh], sigma_ref=0),
                                       '-yellowbackpayoutaddress must be a transparent P2PKH address')
        self.restart(2)
        set_quote(self.nodes[2], '2.00')
        h = self.mine(2)[0]
        self.assert_tag(h, 'quote', payout=self.pool_addresses[0])

    # ------------------------------------------------------------------ after activation

    def mint_inputs(self):
        node = self.nodes[0]
        tip = node.getblockcount()
        ref = tip - REF_LAG
        est = node.yed_estimatecollateral(CENTS, LOCK)
        assert_equal(est['refHeight'], ref)
        required = est['requiredZat']
        payee = node.yed_getfeepayee(ref, required)['default']['payoutAddress']
        return ref, required, payee

    def build_transfer(self, node, tokens, assignments, prevtxs):
        """A TRANSFER spending ``tokens`` (outpoints) with ``assignments`` [(cents)] to fresh
        addresses of ``node``; funded and signed by the wallet (``prevtxs`` for token inputs)."""
        vout = [(TOKEN_VALUE, _spk(node, node.getnewaddress())) for _ in assignments]
        vout.append((0, bytes([ym.OP_RETURN]) + ym.push(ym.encode_transfer(list(enumerate(assignments))))))
        needed = TOKEN_VALUE * len(assignments) + YELLOWBACK_FEE - TOKEN_VALUE * len(tokens)
        utxos, total = _select_funding(node, max(needed, 1))
        if total - needed > 0:
            vout.append((total - needed, _spk(node, node.getnewaddress())))
        vin = [(t, n, b'', 0xFFFFFFFF) for t, n in tokens] + [(u['txid'], u['vout'], b'', 0xFFFFFFFF) for u in utxos]
        raw = ym.serialize_tx_v4(vin, vout, 0, node.getblockcount() + REF_WINDOW)
        signed = node.signrawtransaction(bytes_to_hex_str(raw), prevtxs)
        assert_equal(signed['complete'], True)
        return signed['hex']

    def template_policy_strict_vs_consensus(self):
        # Rule: TPL-2 MINT-5 XFER-2
        # V14: strict leaves a VOID-bound mint and a would-burn transfer in the mempool and out of the block; consensus includes them.
        print('template policy: strict vs consensus')
        user = self.nodes[0]
        ref, required, payee = self.mint_inputs()
        void_hex, _ = build_mint_tx(user, CENTS, LOCK, ref, required // 2, fee_addr=payee)
        void_txid = send_locked(user, void_hex)                # MP-1 never refuses a mint
        a_hex, a_owner = build_mint_tx(user, CENTS, LOCK, ref, required, fee_addr=payee)
        a_txid = send_locked(user, a_hex)
        c_hex, c_owner = build_mint_tx(user, CENTS, LOCK, ref, required, fee_addr=payee)
        c_txid = send_locked(user, c_hex)
        self.vault_a = vault_from_mint(a_hex, LOCK, ref, a_owner)
        self.vault_c = vault_from_mint(c_hex, LOCK, ref, c_owner)
        self.sync_all()
        assert_equal(user.yed_validaterawtransaction(void_hex)['wouldBeRejected'], False)
        in_tpl = gbt_hashes(self.nodes[2].getblocktemplate())
        assert a_txid in in_tpl and c_txid in in_tpl
        assert void_txid not in in_tpl
        h = self.mine(2)[0]                                     # strict
        mined = user.getblock(h)['tx']
        assert a_txid in mined and c_txid in mined and void_txid not in mined
        assert void_txid in user.getrawmempool() and void_txid in self.nodes[2].getrawmempool()
        assert_equal(user.yed_gettxinfo(a_txid)['verdict'], 'ok')
        assert_equal(user.yed_getvault(a_txid)['status'], 'ACTIVE')
        # a would-burn TRANSFER of vault A's token: 4,000 of 10,000 cents assigned, 6,000 burn
        token_a = (a_txid, 1)
        prev = [{'txid': a_txid, 'vout': 1, 'scriptPubKey': bytes_to_hex_str(ym.p2pkh_script(ym.hash160(hex_str_to_bytes(a_owner)))),
                 'amount': TOKEN_VALUE / 1e8}]
        burn_hex = self.build_transfer(user, [token_a], [4_000], prev)
        burn_txid = send_locked(user, burn_hex)
        self.sync_all()
        in_tpl = gbt_hashes(self.nodes[2].getblocktemplate())
        assert burn_txid not in in_tpl and void_txid not in in_tpl
        h = self.mine(2)[0]
        mined = user.getblock(h)['tx']
        assert burn_txid not in mined and void_txid not in mined
        # consensus policy on pool 3 (its mempool restarts empty: resend both)
        self.restart(3, ['-yellowbacktemplatepolicy=consensus'])
        pool3 = self.nodes[3]
        set_quote(pool3, '2.00')
        assert_equal(pool3.sendrawtransaction(void_hex), void_txid)
        assert_equal(pool3.sendrawtransaction(burn_hex), burn_txid)
        gbt = pool3.getblocktemplate()
        assert_equal(gbt['yellowback']['templatePolicy'], 'consensus')
        in_tpl = gbt_hashes(gbt)
        assert void_txid in in_tpl and burn_txid in in_tpl
        h = self.mine(3)[0]
        mined = user.getblock(h)['tx']
        assert void_txid in mined and burn_txid in mined
        assert_equal(user.yed_gettxinfo(void_txid)['verdict'], 'bad-mint-collateral')
        assert_equal(user.yed_getvault(void_txid)['status'], 'VOID')
        info = user.yed_gettxinfo(burn_txid)
        assert_equal(info['verdict'], 'burned')
        assert_equal(info['burned'], 6_000)
        assert_equal(info['yedOut'], 4_000)
        user.lockunspent(True)
        self.checkpoint('consensus template mined')

    def tpl1_template_includes_chained_mint_transfer(self):
        # Rule: TPL-1 XFER-1
        print('tpl1_template_includes_chained_mint_transfer')
        user = self.nodes[0]
        ref, required, payee = self.mint_inputs()
        b_hex, b_owner = build_mint_tx(user, CENTS, LOCK, ref, required, fee_addr=payee)
        b_txid = send_locked(user, b_hex)
        self.vault_b = vault_from_mint(b_hex, LOCK, ref, b_owner)
        prev = [{'txid': b_txid, 'vout': 1, 'scriptPubKey': bytes_to_hex_str(ym.p2pkh_script(ym.hash160(hex_str_to_bytes(b_owner)))),
                 'amount': TOKEN_VALUE / 1e8}]
        t_hex = self.build_transfer(user, [(b_txid, 1)], [CENTS], prev)
        t_txid = send_locked(user, t_hex)
        self.token_b = (t_txid, 0)
        self.sync_all()
        gbt = self.nodes[2].getblocktemplate()
        in_tpl = gbt_hashes(gbt)
        assert b_txid in in_tpl and t_txid in in_tpl
        assert_greater_than(in_tpl.index(t_txid), in_tpl.index(b_txid))
        assert_equal([t for t in gbt['transactions'] if t['hash'] == t_txid][0]['depends'], [in_tpl.index(b_txid) + 1])
        h = self.mine(2)[0]
        mined = user.getblock(h)['tx']
        assert b_txid in mined and t_txid in mined
        assert_equal(user.yed_gettxinfo(b_txid)['verdict'], 'ok')
        info = user.yed_gettxinfo(t_txid)
        assert_equal(info['verdict'], 'ok')
        assert_equal(info['yedOut'], CENTS)
        assert_equal(info['burned'], 0)
        user.lockunspent(True)
        self.checkpoint('chained mint + transfer')

    def redeem_payload(self, ref, fee_vout=1):
        return ym.encode_redeem(ref, fee_vout, [])

    def live_vault(self, built):
        """``yed_getvault`` for a ``vault_from_mint`` dict, with the P2PKH owner address the
        signer needs (the RPC's ``ownerAddress`` is the Yellowback ``ye...`` form, D10)."""
        v = dict(self.nodes[0].yed_getvault(built['txid']))
        v['ownerAddress'] = built['ownerAddress']
        return v

    def block_invalid_vault_spend(self):
        # Rule: TPL-1 MP-1 RED-2
        print('a block-invalid vault spend: never in a template, refused by MP-1, accepted by the stock node')
        user, stock = self.nodes[0], self.nodes[STOCK]
        tip = user.getblockcount()
        ref = tip - REF_LAG
        vault = self.live_vault(self.vault_a)
        assert_equal(vault['status'], 'ACTIVE')
        assert_greater_than(tip + 1, vault['lockHeight'])
        collateral = int(vault['collateralZat'])
        payee = user.yed_getfeepayee(ref, collateral)['default']['payoutAddress']
        expiry = tip + 4                                        # past the stock node's expiring-soon threshold (3)
        bad_hex = build_vault_spend_raw(user, vault, 'owner', [], payload=self.redeem_payload(ref),
                                        fee=(payee, fee_zat(collateral)), expiry=expiry)
        v = user.yed_validaterawtransaction(bad_hex)
        assert_equal(v['wouldBeRejected'], True)
        rpc_error('yellowback-vault-spend', user.sendrawtransaction, bad_hex)
        bad_txid = stock.sendrawtransaction(bad_hex)           # script-valid: the stock node relays it
        wait_for_mempool(stock, bad_txid)
        time.sleep(2)                                           # relay to the pools is refused by MP-1
        for i in POOLS:
            assert bad_txid not in self.nodes[i].getrawmempool()
            assert bad_txid not in gbt_hashes(self.nodes[i].getblocktemplate())
        assert_equal(self.nodes[3].getblocktemplate()['yellowback']['templatePolicy'], 'consensus')
        self.mine_round_robin(POOLS, 5)                         # the stock node drops it at expiry + 1
        wait_for_mempool(stock, bad_txid, present=False)
        self.checkpoint('block-invalid spend expired')

    def mp1_expiry_required(self):
        # Rule: MP-1 TPL-2
        # N5: nExpiryHeight = 0 is refused; refHeight + REF_WINDOW is admitted and dropped by removeExpired.
        print('mp1_expiry_required')
        user, stock = self.nodes[0], self.nodes[STOCK]
        vault = self.live_vault(self.vault_b)
        assert_equal(vault['status'], 'ACTIVE')
        collateral = int(vault['collateralZat'])
        tip = user.getblockcount()
        ref = tip - REF_LAG
        payee = user.yed_getfeepayee(ref, collateral)['default']['payoutAddress']
        fee = (payee, fee_zat(collateral))
        no_expiry = build_vault_spend_raw(user, vault, 'owner', [self.token_b], payload=self.redeem_payload(ref), fee=fee, expiry=0)
        assert_equal(user.yed_validaterawtransaction(no_expiry)['wouldBeRejected'], True)
        rpc_error('yellowback-vault-spend', user.sendrawtransaction, no_expiry)
        for i in POOLS:
            rpc_error('yellowback-vault-spend', self.nodes[i].sendrawtransaction, no_expiry)
        # back to strict on pool 3 before the admitted spend sits in every mempool
        self.restart(3)
        set_quote(self.nodes[3], '2.00')
        # a valid spend with the bound: admitted everywhere; its OP_2 selector (K4: an owner selector
        # consensus accepts) is not the wallet's shape, so strict templates leave it (TPL-2) and it
        # sits in the mempools until removeExpired drops it
        tip = user.getblockcount()
        ref = tip - REF_LAG
        expiry = ref + REF_WINDOW
        payee = user.yed_getfeepayee(ref, collateral)['default']['payoutAddress']
        fee = (payee, fee_zat(collateral))
        ok_hex = build_vault_spend_raw(user, vault, 'owner', [self.token_b], payload=self.redeem_payload(ref), fee=fee,
                                       expiry=expiry, selector=b"\x52")  # OP_2
        assert_equal(user.yed_validaterawtransaction(ok_hex)['wouldBeRejected'], False)
        ok_txid = user.sendrawtransaction(ok_hex)
        sync_mempools(self.nodes)
        for i in POOLS:
            assert ok_txid in self.nodes[i].getrawmempool()
            assert ok_txid not in gbt_hashes(self.nodes[i].getblocktemplate())
        self.mine_round_robin(POOLS, expiry - 1 - user.getblockcount())
        assert_equal(user.getblockcount(), expiry - 1)
        for node in self.nodes:
            assert ok_txid in node.getrawmempool()
        # tip = expiry: the enforcing nodes' ConnectTip sweep drops it first (at the next height
        # RED-1's window has closed, N5); tip = expiry + 1: the stock node's removeExpired
        self.mine_round_robin(POOLS, 1)
        for node in self.enforcing_nodes():
            wait_for_mempool(node, ok_txid, present=False)
        assert ok_txid in stock.getrawmempool()
        self.mine_round_robin(POOLS, 1)
        for node in self.nodes:
            wait_for_mempool(node, ok_txid, present=False)
        rpc_error('expir', stock.sendrawtransaction, ok_hex)
        rpc_error('expir', user.sendrawtransaction, ok_hex)
        assert_equal(user.yed_getvault(self.vault_b['txid'])['status'], 'ACTIVE')
        self.checkpoint('expired spend gone')

    def mp1_reorg_reevaluates_mempool(self):
        # Rule: MP-1 RED-3 FEE-2
        # The fee2 shape: the payee's only tag in the window is block R; a stock block replaces R.
        print('mp1_reorg_reevaluates_mempool')
        user, stock, pool2 = self.nodes[0], self.nodes[STOCK], self.nodes[2]
        self.mine_round_robin([2, 3], 10)
        r_hash = self.mine(4)[0]
        tip = user.getblockcount()
        ref = tip                                                # R = the tip: pool 4's only tag in [R-9, R]
        vault = self.live_vault(self.vault_c)
        assert_equal(vault['status'], 'ACTIVE')
        collateral = int(vault['collateralZat'])
        eligible = user.yed_getfeepayee(ref, collateral)['eligible']
        payee4 = self.pool_addresses[POOLS.index(4)]
        assert payee4 in eligible
        assert self.pool_addresses[0] in eligible
        token_c = (self.vault_c['txid'], 1)
        # the competing chain is built behind a split so the stock node never holds the spend
        # (it would mine it into block R', where refHeight = R fails RED-1: Phase 5's business)
        self.split_network()
        stock.invalidateblock(r_hash)
        assert_equal(stock.getblockcount(), tip - 1)
        stock.generate(2)
        spend_hex = build_vault_spend_raw(user, vault, 'owner', [token_c], payload=self.redeem_payload(ref),
                                          fee=(payee4, fee_zat(collateral)), expiry=ref + REF_WINDOW)
        assert_equal(pool2.yed_validaterawtransaction(spend_hex)['wouldBeRejected'], False)
        spend_txid = pool2.sendrawtransaction(spend_hex)
        assert spend_txid in pool2.getrawmempool()
        assert spend_txid in gbt_hashes(pool2.getblocktemplate())
        # the reorg: the stock node's two untagged blocks replace block R
        self.join_network()
        assert_best_hash(self.nodes)
        assert_equal(user.getblockcount(), tip + 1)
        assert_equal(user.getblock(r_hash)['confirmations'], -1)
        self.assert_tag(str(ref), 'none')
        assert payee4 not in user.yed_getfeepayee(ref, collateral)['eligible']
        wait_for_mempool(pool2, spend_txid, present=False)      # the ConnectTip sweep
        assert spend_txid not in user.getrawmempool()
        assert spend_txid not in gbt_hashes(pool2.getblocktemplate())
        assert_equal(pool2.yed_validaterawtransaction(spend_hex)['wouldBeRejected'], True)
        rpc_error('yellowback-vault-spend', pool2.sendrawtransaction, spend_hex)
        assert_equal(user.yed_getvault(self.vault_c['txid'])['status'], 'ACTIVE')
        self.checkpoint('after the reorg')

    # ------------------------------------------------------------------ run

    def run_test(self):
        self.setup_helpers()
        for node in self.enforcing_nodes():
            wait_yed_healthy(node)
        self.gbt_shape_without_flag()
        self.tag_in_generate_blocks()
        self.gbt_fields()
        self.pool_path_end_to_end()
        self.tag2_invalid_tag_is_no_tag()
        self.tx0_coinbase_payload_registers_nothing()
        self.quote_staleness_signal_only()
        self.setquote_zero_signal_only()
        self.no_signal_no_quote_no_tag()
        self.unhealthy_index_no_tag()
        self.miner2_default_from_mineraddress()
        self.miner2_non_p2pkh_refused()

        print('activation')
        self.activate(quote_usd='2.00')
        self.mine(2, REF_LAG + 1)
        self.checkpoint('active')
        self.template_policy_strict_vs_consensus()
        self.tpl1_template_includes_chained_mint_transfer()
        print('the locks pass')
        self.mine_round_robin(POOLS, LOCK + 2)
        self.checkpoint('locks passed')
        self.block_invalid_vault_spend()
        self.mp1_expiry_required()
        self.mp1_reorg_reevaluates_mempool()
        self.gbt_shape_without_flag()


def _spk(node, addr):
    return hex_str_to_bytes(node.validateaddress(addr)['scriptPubKey'])


if __name__ == '__main__':
    YellowbackMiningTest().main()
