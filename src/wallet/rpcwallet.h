// Copyright (c) 2016 The Bitcoin Core developers
// Copyright (c) 2018-2023 The Zcash developers
// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_WALLET_RPCWALLET_H
#define BITCOIN_WALLET_RPCWALLET_H

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

#endif //BITCOIN_WALLET_RPCWALLET_H
