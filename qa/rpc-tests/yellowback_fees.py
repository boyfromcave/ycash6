#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
#
# The fee structure of quantum plan D-Q-23 Option D, D-Q-23a, D-Q-24 and D-Q-25 (docs/plans/
# yellowback-quantum-fees-spec.md), end to end on regtest, unarmed (the price is the pools' cross-section):
#
#   - yed_getinfo rpcversion 8: params.fees (the bands, the floor, the network $/KB policy at the tip price),
#     params.maxMintCents, params.supplyCap (D-Q-25: the circulating supply equals the node's own subsidy sum);
#   - yed_estimatefee at every band edge and the $1 floor;
#   - mints of $100, $1,000.01, $10,000.01 and $100,000 (MINT-2', at a price that satisfies K14): each pays
#     FEE-1' of its debt at the mint price it stores (vault.pMint), the attestor share is 0 unarmed;
#   - an owner redeem after lockHeight (RED-3': the protocol fee at pMint) and one in term (IT-9': the early
#     fee of the DEBT at pMint, earlyRedeemFeeCents), a short early fee refused everywhere;
#   - the shock: -70 % and +70 % between mint and redeem leave the fee fixed in YEC (struck at pMint);
#   - the claimant pays the protocol fee of the vault it closes and no early fee;
#   - the network fee of a PQ-owner redeem: the Yellowback $/KB rate (its 5,000 zat/KB floor at a high price),
#     the dollar cap max(-maxtxfee, $2 at the price) accepted by the wallet's own mempool, and the -pqfeerate
#     fallback once the price feed stops (FEE-0 then skips the protocol fee too).
#
# Rule: FEE-1' RED-3' IT-9' AFEE-1' MINT-2' MINT-5' MINT-8' D-Q-23 D-Q-24 D-Q-25

from decimal import Decimal

from test_framework.util import assert_equal, assert_greater_than
from test_framework.yellowback_util import (
    BPS,
    COIN,
    MAX_MINT,
    PAYEE_WINDOW,
    POOLS,
    REF_LAG,
    STOCK,
    USER,
    YELLOWBACK_FEE,
    YellowbackTestFramework,
    protocol_fee_cents,
    protocol_fee_zat,
    set_quote,
    usd_to_micro,
    vault_early_redeem_fee_zat,
    vault_fee_zat,
)
from test_framework.yellowback_attest import ArmedModeMixin, wallet_claim
from test_framework import yellowback_model as ym

PRICE = Decimal('2500')          # $2,500/YEC: a $100,000 class-A vault needs 120 YEC (K14 satisfied); +70 % stays below PRICE_MAX
DOWN = PRICE * Decimal('0.3')    # -70 %
UP = PRICE * Decimal('1.7')      # +70 % = $4,250 < $4,294.97
CLAIMANT = 5
TERMS = {'A': 48, 'B': 97, 'C': 145}
FLOOR_ZAT_PER_KB = 5000          # policy.h DEFAULT_ATTESTED_FEE_FLOOR_PER_KB (D-Q-23a)
PLAIN_USD = 20000                # $0.02/KB
YED_USD = 50000                  # $0.05/KB
CAP_USD = 2000000                # $2
MAX_TX_FEE = 10000000            # -maxtxfee default 0.1 YEC
PQ_SPEND_INPUT = 7981            # PQSpendInputSize(SLH-DSA): the builder's size estimate for the owner input


def assert_rpc_error(substr, fn, *args):
    try:
        fn(*args)
    except Exception as e:
        assert substr in str(e), 'expected %r in %r' % (substr, str(e))
        return
    raise AssertionError('expected an error containing %r' % substr)


def rate_zat_per_kb(usd_micro, price_micro, floor=FLOOR_ZAT_PER_KB):
    """policy.cpp AttestedRateZatPerKB: max(floor, ceil(usd x COIN / price))."""
    return max(floor, -(-usd_micro * COIN // price_micro))


def network_fee_of(node, txid):
    """The fee a transaction paid: its inputs minus its outputs."""
    raw = node.getrawtransaction(txid, 1)
    spent = sum(node.getrawtransaction(v['txid'], 1)['vout'][v['vout']]['valueZat'] for v in raw['vin'])
    return spent - sum(o['valueZat'] for o in raw['vout']), raw


def estimated_bytes(raw):
    """YedNetworkFee's size estimate: every PQ input at PQSpendInputSize, every other input at 150, 1,000 more."""
    pq = sum(1 for v in raw['vin'] if len(v['scriptSig']['hex']) // 2 > 7000)
    return 1000 + 150 * (len(raw['vin']) - pq) + PQ_SPEND_INPUT * pq


class YellowbackFeesTest(ArmedModeMixin, YellowbackTestFramework):

    def price(self, usd):
        for i in POOLS:
            set_quote(self.nodes[i], usd)

    def settle(self, usd, n=34):
        """Quote ``usd`` on every pool and mine enough round-robin blocks for every window's median to move."""
        self.price(usd)
        self.mine_round_robin(POOLS, n)
        assert_equal(self.nodes[USER].yed_getprice()['pMint'], usd_to_micro(usd))

    def fund_user(self, need_yec):
        """Move the pools' matured coinbases to the user until it holds ``need_yec``."""
        user = self.nodes[USER]
        addr = user.getnewaddress()
        for i in POOLS:
            if user.getbalance() >= need_yec:
                break
            bal = self.nodes[i].getbalance()
            if bal > 2:
                self.nodes[i].sendtoaddress(addr, bal - 1)
                self.sync_all()
                self.mine(POOLS[0])
        assert_greater_than(user.getbalance(), need_yec - 1)

    def run_test(self):
        nodes = self.nodes
        user, stock, claimant = nodes[USER], nodes[STOCK], nodes[CLAIMANT]
        assert not self.armed, 'this suite is the unarmed fee structure (the armed path is yellowback_attest / _pq)'

        print('activate at $%s' % PRICE)
        self.activate(POOLS, quote_usd=PRICE)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        p_mint = usd_to_micro(PRICE)
        assert_equal(user.yed_getprice()['pMint'], p_mint)

        print('yed_getinfo rpcversion 8: params.fees, maxMintCents, supplyCap')
        info = user.yed_getinfo()
        params = info['params']
        assert_equal(info['rpcversion'], 8)
        assert 'feeMinZat' not in params and 'feeBps' not in params
        assert_equal(params['maxMintCents'], MAX_MINT)
        fees = params['fees']
        assert_equal(fees['protocol']['bands'], [{'uptoCents': 100000, 'bps': 100}, {'uptoCents': 1000000, 'bps': 50}, {'uptoCents': None, 'bps': 10}])
        assert_equal((fees['protocol']['floorCents'], fees['protocol']['attestFeeBps'], fees['protocol']['priceSource']), (100, params['attest']['attestFeeBps'], 'pMint'))
        assert_equal(fees['earlyRedeemFeeBps'], [500, 250, 100])
        net = fees['network']
        assert_equal((net['priceSource'], net['priceMicroUsd']), ('tip', p_mint))
        assert_equal(net['plain'], {'usdPerKBMicro': PLAIN_USD, 'zatPerKB': rate_zat_per_kb(PLAIN_USD, p_mint)})
        assert_equal(net['plain']['zatPerKB'], params['pq']['feeRateZatPerKB'])                 # rpcversion-7 clients keep working
        assert_equal(net['yellowback']['zatPerKB'], rate_zat_per_kb(YED_USD, p_mint))
        assert_equal(net['yellowback']['zatPerKB'], FLOOR_ZAT_PER_KB)                            # $0.05/KB at $2,500 = 2,000 zat/KB: the floor binds
        assert_equal((net['yellowback']['maxTxFeeUsdMicro'], net['yellowback']['maxTxFeeZat']), (CAP_USD, max(MAX_TX_FEE, rate_zat_per_kb(CAP_USD, p_mint, 0))))
        assert_equal((net['floorZatPerKB'], net['fallbackZatPerKB'], net['flatZat'], net['maxTxFeeZat']), (FLOOR_ZAT_PER_KB, 100, YELLOWBACK_FEE, MAX_TX_FEE))
        cap = params['supplyCap']
        tip = user.getblockcount()
        circulating = sum(ym.subsidy_from_rpc(user, h) for h in range(1, tip + 1))                  # D-Q-25: the subsidy sum (genesis excluded)
        assert_equal((cap['circulatingZat'], cap['priceMicroUsd'], cap['capCents']), (circulating, p_mint, None))   # no cap on regtest
        assert_equal(cap['issuedBeforeStartZat'], sum(ym.subsidy_from_rpc(user, h) for h in range(1, params['startHeight'])))
        assert_equal((cap['maxVaultShareBps'], cap['vaultShareFloorCents'], cap['maxVaultCents']), (1000, 1000000, None))
        self.checkpoint('rpcversion 8')

        print('yed_estimatefee: the bands, the floor, the price')
        for cents, fee_cents in ((10000, 100), (10001, 101), (100000, 1000), (100001, 1001), (1000000, 5500), (1000001, 5501), (MAX_MINT, 14500)):
            est = user.yed_estimatefee(cents)
            assert_equal((est['feeCents'], est['pMint'], est['feeZat']), (fee_cents, p_mint, protocol_fee_zat(cents, p_mint)))
            assert_equal(est['feeCents'], protocol_fee_cents(cents))
            assert_equal(est['attestFeeZat'], est['feeZat'] * params['attest']['attestFeeBps'] // BPS)
        assert_equal(user.yed_estimatefee(10000, 18000)['feeZat'], 5555555556)                       # the spec's worked value
        assert_equal(user.yed_estimatefee(MAX_MINT, 100)['feeZat'], 145 * 10 ** 12)                  # at PRICE_MIN: in MoneyRange
        assert_equal(user.yed_estimatefee(10000, 4294967295)['feeZat'], 23284)                        # at PRICE_MAX: above dust
        assert_rpc_error('priceMicroUsd must be between', user.yed_estimatefee, 10000, 99)
        assert_rpc_error('priceMicroUsd must be between', user.yed_estimatefee, 10000, 4294967296)
        assert_rpc_error('mintedCents out of range', user.yed_estimatefee, -1)

        print('mints of $100, $1,000.01, $10,000.01 and $100,000: FEE-1\' of the debt at the stored pMint')
        self.fund_user(140)
        mints = {}
        for cents, lock in ((10000, TERMS['A']), (100001, TERMS['A']), (1000001, TERMS['A']), (MAX_MINT, TERMS['A'])):
            est = user.yed_estimatecollateral(cents, lock)
            assert_equal((est['pMint'], est['requiredZatFloored']), (p_mint, est['requiredZat']))            # MINT-5': no 4 x FEE_MIN floor
            assert_equal((est['protocolFeeCents'], est['protocolFeeZat']), (protocol_fee_cents(cents), protocol_fee_zat(cents, p_mint)))
            m = self.mint(user, cents, lock)
            self.sync_all()
            self.mine(POOLS[cents % 3])
            v = user.yed_getvault(m['txid'])
            assert_equal((v['status'], v['pMint'], v['mintedCents']), ('ACTIVE', p_mint, cents))
            assert_equal((m['feeZat'], m['attestFeeZat'], v['feePaidZat']), (protocol_fee_zat(cents, p_mint), 0, protocol_fee_zat(cents, p_mint)))
            assert_equal(m['feeZat'], vault_fee_zat(v))
            mints[cents] = m
        assert_equal(mints[MAX_MINT]['collateralZat'], user.yed_estimatecollateral(MAX_MINT, TERMS['A'], p_mint)['requiredZat'])
        assert_rpc_error('cents must be between 10000 and 10000000', user.yed_estimatecollateral, MAX_MINT + 1, TERMS['A'])   # MINT-2'
        assert_rpc_error('mint-unsatisfiable', user.yed_estimatecollateral, MAX_MINT, TERMS['A'], 14285)    # class A below 14,286 uUSD (K14)
        assert user.yed_estimatecollateral(MAX_MINT, TERMS['A'], 14286)['requiredZat'] <= 21000000 * COIN
        # the $100,000 fee is $145: 0.145 % of the debt, far below the 1 % of the first $1,000 (a falling effective rate)
        assert_equal(mints[MAX_MINT]['feeZat'] * 10000 // (MAX_MINT * 10 ** 12 // p_mint), 14)
        self.checkpoint('four mints')

        print('an owner redeem in term pays the early fee of the DEBT at pMint (IT-9\'), short by one zat: bad-redeem-early-fee')
        v1 = user.yed_getvault(mints[100001]['txid'])
        est = user.yed_estimateredeem(mints[100001]['txid'])
        early = vault_early_redeem_fee_zat(v1)
        assert_equal(early, -(-100001 * 500 * COIN // p_mint))                                        # 5 % of $1,000.01 at $2,500, ceil
        assert_equal((est['early'], est['pMint'], est['protocolFeeCents'], est['protocolFeeZat'], est['earlyRedeemFeeBps'], est['earlyRedeemFeeCents'], est['earlyRedeemFeeZat'], est['feeZat']),
                     (True, p_mint, 1001, vault_fee_zat(v1), 500, 5001, early, vault_fee_zat(v1) + early))
        redeemed = user.yed_redeem(mints[100001]['txid'])
        assert_equal((redeemed['burnedCents'], redeemed['earlyRedeemFeeZat'], redeemed['feeZat']), (100001, early, vault_fee_zat(v1) + early))
        self.sync_all()
        self.mine(POOLS[1])
        closed = user.yed_getvault(mints[100001]['txid'])
        assert_equal((closed['status'], closed['feePaidZat'], closed['pMint']), ('CLOSED', vault_fee_zat(v1) + early, p_mint))
        net_fee, raw = network_fee_of(user, redeemed['txid'])
        print('  the network fee of that PQ-owner redeem: the Yellowback rate (the floor at $2,500) x the estimated size')
        yed_rate = user.yed_getinfo()['params']['fees']['network']['yellowback']['zatPerKB']
        assert_equal(yed_rate, FLOOR_ZAT_PER_KB)
        assert_equal(net_fee, max(YELLOWBACK_FEE, min(yed_rate * estimated_bytes(raw) // 1000, max(MAX_TX_FEE, rate_zat_per_kb(CAP_USD, p_mint, 0)))))
        assert_greater_than(net_fee, YELLOWBACK_FEE)
        self.checkpoint('early redeem')

        print('the shock: -70 % then +70 % between mint and redeem; the fee stays fixed at pMint')
        v10k = user.yed_getvault(mints[1000001]['txid'])
        self.settle(DOWN)
        est = user.yed_estimateredeem(mints[1000001]['txid'])
        assert_equal((est['pMint'], est['protocolFeeZat']), (p_mint, vault_fee_zat(v10k)))
        assert_equal(user.yed_estimatefee(1000001)['pMint'], usd_to_micro(DOWN))                     # a new mint would strike at the new price
        assert_greater_than(user.yed_estimatefee(1000001)['feeZat'], vault_fee_zat(v10k))             # ... and pay more YEC for the same dollars
        self.settle(UP)
        assert_equal(user.yed_getprice()['pMint'], usd_to_micro(UP))
        est = user.yed_estimateredeem(mints[1000001]['txid'])
        assert_equal((est['pMint'], est['protocolFeeZat']), (p_mint, vault_fee_zat(v10k)))
        while user.getblockcount() + 1 < v10k['lockHeight']:
            self.mine(POOLS[2])
        redeemed = user.yed_redeem(mints[1000001]['txid'])
        assert_equal((redeemed['earlyRedeemFeeZat'], redeemed['feeZat']), (0, vault_fee_zat(v10k)))  # at lockHeight: the protocol fee alone, at pMint
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(user.yed_getvault(mints[1000001]['txid'])['feePaidZat'], vault_fee_zat(v10k))
        self.checkpoint('shock')

        print('the claimant pays the protocol fee of the vault it closes (RED-3\'), never an early fee')
        self.settle(DOWN)                                                                             # $100,000 at 300 % of $2,500 is at 90 % of $750: under theta
        vbig = user.yed_getvault(mints[MAX_MINT]['txid'])
        assert_equal(vbig['claimable'], True)
        row = {x['vault']: x for x in claimant.yed_listclaimable()}[mints[MAX_MINT]['txid'] + ':0']
        assert_equal((row['pMint'], row['feeZat']), (p_mint, vault_fee_zat(vbig)))
        user.yed_send(claimant.yed_getnewaddress(), MAX_MINT)                                         # the claimant needs the debt
        self.sync_all()
        self.mine(POOLS[1])
        self.fund_claimant = claimant.getbalance()
        if claimant.getbalance() < 2:
            user.sendtoaddress(claimant.getnewaddress(), 2)                                           # the claim's fees come from the claimant's YEC
            self.sync_all()
            self.mine(POOLS[2])
        claimed = wallet_claim(self, claimant, mints[MAX_MINT]['txid'])
        assert_equal((claimed['feeZat'], claimed['earlyRedeemFeeZat'], claimed['attestFeeZat']), (vault_fee_zat(vbig), 0, 0))
        self.sync_all()
        self.mine(POOLS[0])
        c = user.yed_getvault(mints[MAX_MINT]['txid'])
        assert_equal((c['status'], c['feePaidZat'], c['pMint']), ('CLAIMING', vault_fee_zat(vbig), p_mint))
        self.checkpoint('claim')

        print('the dollar cap: -yellowbackfeeusdperkb=100 -maxtxfee=0.02 -yellowbackmaxtxfeeusd=20 -> max(0.02 YEC, $20 at $750) accepted by the wallet\'s own mempool')
        # ($2 at $750 is 266,667 zat, below -maxtxfee: the default dollar cap binds only below $100/YEC, so the cap is raised to $20 here)
        self.restart(USER, ['-yellowbackfeeusdperkb=100', '-maxtxfee=0.02', '-yellowbackmaxtxfeeusd=20'])
        self.sync_all(blocks_only=True)
        p_now = usd_to_micro(DOWN)
        net = user.yed_getinfo()['params']['fees']['network']
        assert_equal(net['yellowback']['zatPerKB'], rate_zat_per_kb(100 * 10 ** 6, p_now))
        cap_zat = max(2000000, rate_zat_per_kb(20 * 10 ** 6, p_now, 0))
        assert_equal((net['yellowback']['maxTxFeeUsdMicro'], net['yellowback']['maxTxFeeZat']), (20 * 10 ** 6, cap_zat))
        assert_greater_than(cap_zat, 2000000)                                                         # $20 at $750 = 0.0267 YEC > -maxtxfee 0.02
        v100 = user.yed_getvault(mints[10000]['txid'])
        while user.getblockcount() + 1 < v100['lockHeight']:
            self.mine(POOLS[1])
        redeemed = user.yed_redeem(mints[10000]['txid'])
        net_fee, raw = network_fee_of(user, redeemed['txid'])
        assert_equal(net_fee, cap_zat)                                                                # rate x size far above: capped at the dollar cap, not refused
        self.sync_all()
        self.mine(POOLS[2])
        assert_equal(user.yed_getvault(mints[10000]['txid'])['status'], 'CLOSED')
        self.restart(USER, [])
        self.sync_all(blocks_only=True)
        self.checkpoint('dollar cap')

        print('the price feed stops: the network fee falls back to -pqfeerate; FEE-0 skips the protocol fee (and the early fee)')
        m = self.mint(user, 10000, TERMS['C'])          # class C: the only class that mints under HALT-2 (the claimed vault dragged the global ratio down)
        self.sync_all()
        self.mine(POOLS[0])
        vlast = user.yed_getvault(m['txid'])
        for i in POOLS:
            self.nodes[i].yed_setquote(0, 0)                                                          # clears the quote: signal-only tags
        stock.generate(PAYEE_WINDOW + 1)
        self.sync_all(blocks_only=True)
        net = user.yed_getinfo()['params']['fees']['network']
        assert_equal((net['priceSource'], net['priceMicroUsd'], net['plain']['zatPerKB'], net['yellowback']['zatPerKB'], net['yellowback']['maxTxFeeZat']),
                     ('fallback', None, 100, 100, MAX_TX_FEE))
        assert_equal(user.yed_getinfo()['params']['pq']['feeRateZatPerKB'], 100)
        assert_rpc_error('fee-no-eligible-payee', user.yed_getfeepayee, user.getblockcount())
        est = user.yed_estimateredeem(m['txid'])
        assert_equal((est['pMint'], est['protocolFeeZat'], est['feeZat'], est['payee']), (vlast['pMint'], 0, 0, None))
        redeemed = user.yed_redeem(m['txid'])
        assert_equal((redeemed['feeZat'], redeemed['payee']), (0, None))
        net_fee, raw = network_fee_of(user, redeemed['txid'])
        assert_equal(net_fee, max(YELLOWBACK_FEE, 100 * estimated_bytes(raw) // 1000))                 # -pqfeerate's 100 zat/kB: the flat fee
        self.sync_all()
        stock.generate(1)
        self.sync_all(blocks_only=True)
        assert_equal((user.yed_getvault(m['txid'])['status'], user.yed_getvault(m['txid'])['feePaidZat']), ('CLOSED', 0))
        self.checkpoint('fallback and FEE-0')


if __name__ == '__main__':
    YellowbackFeesTest().main()
