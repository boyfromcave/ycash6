// Copyright (c) 2016 The Bitcoin Core developers
// Copyright (c) 2018-2023 The Zcash developers
// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_WALLET_RPCWALLET_H
#define BITCOIN_WALLET_RPCWALLET_H

#include "amount.h"
#include "script/standard.h"

class CRPCTable;

void RegisterWalletRPCCommands(CRPCTable &tableRPC);

/**
 * Refuse (RPC_INVALID_ADDRESS_OR_KEY) a payment to a post-quantum destination (sq…/tq…/rq…, D-Q-20) that the
 * next block could not accept as standard: a TX_PQPKH output before UPGRADE_VAULT is active at the next block,
 * or a scheme-2 (FN-DSA-512) one before IsPQFalconActive (quantum spec A-1). No-op for any other destination.
 * Needs cs_main.
 */
void EnsurePQRecipientPayable(const CTxDestination& dest);

/**
 * beta2 D-2, D-6 (reverses quantum spec A-15): refuse a post-quantum from address of z_sendmany / z_mergetoaddress
 * that this wallet cannot spend now: before UPGRADE_VAULT is active at the next block, a scheme-2 (FN-DSA-512)
 * one before IsPQFalconActive, a key this wallet does not hold, or a locked wallet. No-op for any other
 * destination. Needs cs_main and pwalletMain->cs_wallet.
 */
void EnsurePQSourceSpendable(const CTxDestination& dest);

/**
 * Refuse (RPC_INVALID_PARAMETER) an amount to a post-quantum destination below its dust threshold, priced on the
 * real spend size of its scheme (GetPQDustThreshold), before a transaction is built. No-op for any other destination.
 */
void EnsurePQAmountNotDust(const CTxDestination& dest, CAmount amount);

#endif //BITCOIN_WALLET_RPCWALLET_H
