#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
vault_upgrade.py: the UPGRADE_VAULT network upgrade's consensus plumbing
(docs/plans/yellowback-upgrade-plan.md §15.1, §15.2, §15.9).

Two nodes on regtest with the six upgrades through Canopy at height 1 (as every Yellowback test)
and Vault (branch ID 0x6d5b7a31) at ACT.  Checked on both sides of the activation:

- the upgrade itself: getblockchaininfo, the epoch's branch ID, the ZIP-221 history tree reset
  at ACT with V1 leaves under the Vault branch ID (Ycash activates Vault without NU5);
- signing: the wallet sends transparently and through Sapling (the Rust builder takes the branch
  ID) in the activation block and after it; a transaction signed in Python with the old
  (Canopy) branch ID is accepted before and rejected after as old-consensus-branch-id, and the
  same transaction signed with VAULT_BRANCH_ID is accepted after;
- OP_CHECKSEQUENCEVERIFY (0xb2): OP_NOP3 before (non-standard, valid in a block), BIP112 after;
- BIP68: not enforced before; height-based relative locks from ACT in the mempool (tip+1) and in
  blocks, mempool parents counted at tip+1, the time flag (bit 22) invalid, eviction on reorg;
- OP_CHECKSETSIG (0xc0) / OP_CHECKSETDORMANT (0xc1): bad opcodes before, evaluated after.
"""

from io import BytesIO
from decimal import Decimal

from test_framework.yellowback_util import (  # first: points ctypes at a real OpenSSL for key.py
    YCASH_UPGRADE_ARGS,
    YCASH_CANOPY_BRANCH_ID,
    _low_s,
    mine_block_raw,
    wif_to_secret,
)
from test_framework import yellowback_model as ym
from test_framework.flyclient import ZcashMMRNode, append, make_root_commitment
from test_framework.key import CECKey
from test_framework.mininode import CBlockHeader, CTransaction
from test_framework.script import (
    CScript,
    OP_1,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSETDORMANT,
    OP_CHECKSETSIG,
    OP_DROP,
    SIGHASH_ALL,
    SignatureHash,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID,
    assert_equal,
    bytes_to_hex_str,
    connect_nodes_bi,
    hex_str_to_bytes,
    nuparams,
    start_nodes,
    sync_blocks,
    wait_and_assert_operationid_status,
)
from test_framework.authproxy import JSONRPCException

ACT = 130          # Vault activation height
COIN = 10 ** 8
FEE = 10000
NULL_FIELD = '00' * 32
SEQ_TYPE_FLAG = 1 << 22


class VaultUpgradeTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.cache_behavior = 'clean'

    def setup_nodes(self):
        args = YCASH_UPGRADE_ARGS + [nuparams(VAULT_BRANCH_ID, ACT), '-txindex']
        return start_nodes(self.num_nodes, self.options.tmpdir, extra_args=[args] * self.num_nodes)

    def setup_network(self, split=False):
        self.nodes = self.setup_nodes()
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    # ---------------------------------------------------------------- helpers

    def mine(self, n=1):
        self.nodes[0].generate(n)
        sync_blocks(self.nodes)

    def fund_script(self, script, amount=Decimal('1')):
        """Pay `amount` to the bare script `script` from node 0 and confirm it; returns the coin
        (txid, n, value_zat, height)."""
        n0 = self.nodes[0]
        addr = n0.decodescript(bytes_to_hex_str(script))['p2sh']
        txid = n0.sendtoaddress(addr, amount)
        spk = n0.validateaddress(addr)['scriptPubKey']
        self.mine()
        tx = n0.getrawtransaction(txid, 1)
        n = [o['n'] for o in tx['vout'] if o['scriptPubKey']['hex'] == spk][0]
        return (txid, n, int(amount * COIN), n0.getblockcount())

    def fund_unconfirmed(self, script, amount=Decimal('1')):
        n0 = self.nodes[0]
        addr = n0.decodescript(bytes_to_hex_str(script))['p2sh']
        txid = n0.sendtoaddress(addr, amount)
        spk = n0.validateaddress(addr)['scriptPubKey']
        tx = n0.getrawtransaction(txid, 1)
        n = [o['n'] for o in tx['vout'] if o['scriptPubKey']['hex'] == spk][0]
        return (txid, n, int(amount * COIN), None)

    def spend_p2sh(self, coin, redeem, seq, prefix=b''):
        """A v4 transaction spending P2SH `coin` with scriptSig `prefix || push(redeem)`."""
        txid, n, value, _h = coin
        dest = self.nodes[1].validateaddress(self.nodes[1].getnewaddress())['scriptPubKey']
        raw = ym.serialize_tx_v4([(txid, n, prefix + ym.push(redeem), seq)],
                                 [(value - FEE, hex_str_to_bytes(dest))])
        return bytes_to_hex_str(raw)

    def spend_p2pkh_signed(self, branch_id):
        """A wallet UTXO of node 0 spent by a transaction assembled and signed here, over the
        ZIP-243 sighash bound to `branch_id`.  Returns (hex, utxo)."""
        n0 = self.nodes[0]
        utxo = [u for u in n0.listunspent(1) if u['spendable'] and u['amount'] > 1][0]
        value = int(utxo['amount'] * COIN)
        spk = hex_str_to_bytes(utxo['scriptPubKey'])
        dest = n0.validateaddress(self.nodes[1].getnewaddress())['scriptPubKey']
        raw = ym.serialize_tx_v4([(utxo['txid'], utxo['vout'], b'', 0xffffffff)],
                                 [(value - FEE, hex_str_to_bytes(dest))])
        tx = CTransaction()
        tx.deserialize(BytesIO(raw))
        key = CECKey()
        key.set_secretbytes(wif_to_secret(n0.dumpprivkey(utxo['address'])))
        key.set_compressed(True)
        sighash = SignatureHash(CScript(spk), tx, 0, SIGHASH_ALL, value, branch_id)[0]
        sig = _low_s(key.sign(sighash)) + bytes([SIGHASH_ALL])
        tx.vin[0].scriptSig = ym.push(sig) + ym.push(key.get_pubkey())
        return bytes_to_hex_str(tx.serialize()), utxo

    def assert_mempool_rejects(self, raw, reason):
        try:
            self.nodes[0].sendrawtransaction(raw)
        except JSONRPCException as e:
            assert reason in e.error['message'], (reason, e.error['message'])
            return
        raise AssertionError('mempool accepted a transaction it should reject (%s)' % reason)

    def assert_block_rejects(self, raw, reason=None):
        tip = self.nodes[0].getbestblockhash()
        result, _h = mine_block_raw(self.nodes[0], [raw])
        assert result is not None, 'block with the transaction was accepted'
        if reason is not None:
            assert reason in result, (reason, result)
        assert_equal(self.nodes[0].getbestblockhash(), tip)

    def assert_block_accepts(self, raw):
        result, blockhash = mine_block_raw(self.nodes[0], [raw])
        assert result is None, result
        assert_equal(self.nodes[0].getbestblockhash(), blockhash)
        sync_blocks(self.nodes)

    def history_leaf(self, height, branch_id):
        n0 = self.nodes[0]
        header = CBlockHeader()
        header.deserialize(BytesIO(hex_str_to_bytes(n0.getblock(str(height), 0))))
        blk = n0.getblock(str(height))
        sapling_root = hex_str_to_bytes(blk['finalsaplingroot'])[::-1]
        sapling_tx = 0     # ConnectBlock counts transactions with a Sapling bundle
        for txid in blk['tx']:
            d = n0.getrawtransaction(txid, 1)
            if d.get('vShieldedSpend') or d.get('vShieldedOutput'):
                sapling_tx += 1
        return ZcashMMRNode.from_block(header, height, sapling_root, sapling_tx, branch_id, None)

    # ---------------------------------------------------------------- the test

    def run_test(self):
        n0, n1 = self.nodes
        self.mine(110)

        info = n0.getblockchaininfo()
        vault = info['upgrades']['%08x' % VAULT_BRANCH_ID]
        assert_equal(vault['name'], 'Vault')
        assert_equal(vault['activationheight'], ACT)
        assert_equal(vault['status'], 'pending')
        assert_equal(info['consensus']['nextblock'], '%08x' % YCASH_CANOPY_BRANCH_ID)
        # -nuparams for Vault alone must not back-fill NU5..NU6.2 (Ycash activates it without them).
        for nu in ('f919a198', 'c8e71055', '4dec4df0', '5437f330'):
            assert nu not in info['upgrades'], nu

        csv5 = CScript([5, OP_CHECKSEQUENCEVERIFY, OP_DROP, OP_1])
        anyone = CScript([OP_1])
        dormant = CScript([bytes(32), OP_CHECKSETDORMANT, OP_DROP, OP_1])
        setsig = CScript([bytes([31]) + bytes(64), bytes(32), OP_1, OP_CHECKSETSIG])

        print('before Vault: OP_CHECKSEQUENCEVERIFY is OP_NOP3 (non-standard, valid in a block)')
        coin = self.fund_script(csv5)
        raw = self.spend_p2sh(coin, csv5, 0)
        self.assert_mempool_rejects(raw, 'non-mandatory-script-verify-flag')
        self.assert_block_accepts(raw)

        print('before Vault: BIP68 is not enforced')
        coin = self.fund_script(anyone)
        txid = n0.sendrawtransaction(self.spend_p2sh(coin, anyone, 100))
        coin = self.fund_script(anyone)
        txid2 = n0.sendrawtransaction(self.spend_p2sh(coin, anyone, SEQ_TYPE_FLAG | 1))
        self.mine()
        assert n0.getrawtransaction(txid, 1)['confirmations'] >= 1
        assert n0.getrawtransaction(txid2, 1)['confirmations'] >= 1

        print('before Vault: 0xc0 and 0xc1 are bad opcodes')
        coin_dormant = self.fund_script(dormant)
        coin_setsig = self.fund_script(setsig)
        for coin, script in ((coin_dormant, dormant), (coin_setsig, setsig)):
            raw = self.spend_p2sh(coin, script, 0xffffffff)
            self.assert_mempool_rejects(raw, 'Opcode missing or not understood')
            self.assert_block_rejects(raw)

        print('before Vault: a transaction signed with the Canopy branch ID is valid')
        raw, _u = self.spend_p2pkh_signed(YCASH_CANOPY_BRANCH_ID)
        n0.sendrawtransaction(raw)
        self.mine()

        # Coins for the after-activation checks, old enough for any relative lock used below.
        coin_csv = self.fund_script(csv5)
        coin_csv_seq = self.fund_script(csv5)
        coin_csv_disable = self.fund_script(csv5)
        zaddr = n0.z_getnewaddress('sapling')
        taddr = n0.getnewaddress()
        n0.sendtoaddress(taddr, Decimal('10.001'))
        self.mine()
        opid = n0.z_sendmany(taddr, [{'address': zaddr, 'amount': Decimal('10')}], 1, None)
        wait_and_assert_operationid_status(n0, opid)
        self.mine()
        assert_equal(n0.z_getbalance(zaddr), Decimal('10'))

        print('the activation block carries wallet transactions signed with the Vault branch ID')
        self.mine(ACT - 1 - n0.getblockcount())
        assert_equal(n0.getblockcount(), ACT - 1)
        assert_equal(n0.getblockchaininfo()['consensus']['nextblock'], '%08x' % VAULT_BRANCH_ID)
        t_dest = n1.getnewaddress()
        wtx = n0.sendtoaddress(t_dest, Decimal('2'))
        opid = n0.z_sendmany(zaddr, [{'address': n1.getnewaddress(), 'amount': Decimal('3')}], 1, None,
                             'AllowRevealedRecipients')
        ztx = wait_and_assert_operationid_status(n0, opid)
        self.sync_all()
        self.mine()
        assert_equal(n0.getblockcount(), ACT)
        for t in (wtx, ztx):
            assert_equal(n0.getrawtransaction(t, 1)['height'], ACT)
        info = n0.getblockchaininfo()
        assert_equal(info['upgrades']['%08x' % VAULT_BRANCH_ID]['status'], 'active')
        assert_equal(info['consensus']['chaintip'], '%08x' % VAULT_BRANCH_ID)

        print('after Vault: the wallet signs transparently and through Sapling')
        wtx = n0.sendtoaddress(n1.getnewaddress(), Decimal('1'))
        opid = n0.z_sendmany(zaddr, [{'address': n1.z_getnewaddress('sapling'), 'amount': Decimal('1')}], 1, None)
        ztx = wait_and_assert_operationid_status(n0, opid)
        self.sync_all()
        self.mine()
        for t in (wtx, ztx):
            assert_equal(n0.getrawtransaction(t, 1)['height'], ACT + 1)
        assert n0.z_getbalance(zaddr) < Decimal('6')

        print('after Vault: the history tree restarts at ACT with V1 leaves under the Vault branch ID')
        # Block ACT still commits the Canopy epoch's tree (blocks 1..ACT-1); ACT + 1 the new one.
        assert n0.getblock(str(ACT))['chainhistoryroot'] != NULL_FIELD
        root = self.history_leaf(ACT, VAULT_BRANCH_ID)
        assert_equal(n0.getblock(str(ACT + 1))['chainhistoryroot'],
                     bytes_to_hex_str(make_root_commitment(root)[::-1]))
        self.mine()
        root = append(root, self.history_leaf(ACT + 1, VAULT_BRANCH_ID))
        assert_equal(n0.getblock(str(ACT + 2))['chainhistoryroot'],
                     bytes_to_hex_str(make_root_commitment(root)[::-1]))

        print('after Vault: the Canopy branch ID is old-consensus-branch-id, the Vault one valid')
        raw, _u = self.spend_p2pkh_signed(YCASH_CANOPY_BRANCH_ID)
        self.assert_mempool_rejects(raw, 'old-consensus-branch-id (Expected %08x, found %08x)'
                                    % (VAULT_BRANCH_ID, YCASH_CANOPY_BRANCH_ID))
        self.assert_block_rejects(raw)
        raw, _u = self.spend_p2pkh_signed(VAULT_BRANCH_ID)
        n0.sendrawtransaction(raw)
        self.mine()
        assert_equal(n0.getrawmempool(), [])

        print('after Vault: OP_CHECKSEQUENCEVERIFY is BIP112')
        raw = self.spend_p2sh(coin_csv, csv5, 0)
        self.assert_mempool_rejects(raw, 'mandatory-script-verify-flag-failed (Locktime requirement not satisfied)')
        self.assert_block_rejects(raw)
        raw = self.spend_p2sh(coin_csv, csv5, 4)
        self.assert_mempool_rejects(raw, 'Locktime requirement not satisfied')
        raw = self.spend_p2sh(coin_csv_disable, csv5, 0xffffffff)
        self.assert_mempool_rejects(raw, 'Locktime requirement not satisfied')
        self.assert_block_rejects(raw)
        n0.sendrawtransaction(self.spend_p2sh(coin_csv, csv5, 5))
        # bits outside the type flag and the low 16 are ignored by CSV and BIP68 alike
        self.assert_block_accepts(self.spend_p2sh(coin_csv_seq, csv5, (1 << 16) | 7))

        print('after Vault: BIP68 relative locks, height-based')
        coin = self.fund_script(anyone)               # confirmed at p = tip
        raw = self.spend_p2sh(coin, anyone, 3)        # spendable at p + 3
        self.assert_mempool_rejects(raw, 'non-BIP68-final')
        self.assert_block_rejects(raw, 'bad-txns-nonfinal')
        self.mine()                                   # next block p + 2
        self.assert_mempool_rejects(raw, 'non-BIP68-final')
        self.assert_block_rejects(raw, 'bad-txns-nonfinal')
        self.mine()                                   # next block p + 3
        n0.sendrawtransaction(raw)
        self.mine()

        # CSV plus BIP68: a fresh CSV coin needs 5 blocks of age as well as nSequence >= 5.
        coin = self.fund_script(csv5)
        raw = self.spend_p2sh(coin, csv5, 5)
        self.assert_mempool_rejects(raw, 'non-BIP68-final')
        self.mine(3)
        self.assert_mempool_rejects(raw, 'non-BIP68-final')
        self.mine()
        n0.sendrawtransaction(raw)
        self.mine()

        # The time flag (bit 22) with the disable bit clear makes a transaction invalid.
        coin = self.fund_script(anyone)
        self.mine(3)
        raw = self.spend_p2sh(coin, anyone, SEQ_TYPE_FLAG | 1)
        self.assert_mempool_rejects(raw, 'bad-txns-vault-timelock')
        self.assert_block_rejects(raw, 'bad-txns-vault-timelock')
        n0.sendrawtransaction(self.spend_p2sh(coin, anyone, (1 << 31) | SEQ_TYPE_FLAG | 1))
        self.mine()

        # A mempool parent counts at tip + 1: lock 0 chains, lock 1 waits.
        parent = self.fund_unconfirmed(anyone)
        self.assert_mempool_rejects(self.spend_p2sh(parent, anyone, 1), 'non-BIP68-final')
        child = n0.sendrawtransaction(self.spend_p2sh(parent, anyone, 0))
        self.mine()
        assert_equal(n0.getrawtransaction(child, 1)['confirmations'], 1)

        print('after Vault: 0xc0 and 0xc1 are evaluated')
        n0.sendrawtransaction(self.spend_p2sh(coin_dormant, dormant, 0xffffffff))
        raw = self.spend_p2sh(coin_setsig, setsig, 0xffffffff)
        self.assert_mempool_rejects(raw, 'OP_CHECKSETSIG or OP_CHECKSETDORMANT failed')
        self.assert_block_rejects(raw)
        self.mine()
        assert_equal(n0.getrawmempool(), [])

        print('after Vault: a reorg evicts a transaction whose relative lock no longer holds')
        coin = self.fund_script(anyone)               # confirmed at p
        self.mine()                                   # tip p + 1
        raw = self.spend_p2sh(coin, anyone, 2)        # spendable at p + 2 = tip + 1
        locked = n0.sendrawtransaction(raw)
        assert locked in n0.getrawmempool()
        tip = n0.getbestblockhash()
        n0.invalidateblock(tip)                       # tip p: the next block p + 1 < p + 2
        assert locked not in n0.getrawmempool()
        n0.reconsiderblock(tip)
        assert_equal(n0.getbestblockhash(), tip)
        n0.sendrawtransaction(raw)
        assert locked in n0.getrawmempool()
        self.mine()
        assert_equal(n0.getrawtransaction(locked, 1)['confirmations'], 1)
        sync_blocks(self.nodes)


if __name__ == '__main__':
    VaultUpgradeTest().main()
