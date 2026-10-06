// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018-2023 The Zcash developers
// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_RPC_REGISTER_H
#define BITCOIN_RPC_REGISTER_H

/** These are in one header file to avoid creating tons of single-function
 * headers for everything under src/rpc/ */
class CRPCTable;

/** Register block chain RPC commands */
void RegisterBlockchainRPCCommands(CRPCTable &tableRPC);
/** Register P2P networking RPC commands */
void RegisterNetRPCCommands(CRPCTable &tableRPC);
/** Register miscellaneous RPC commands */
void RegisterMiscRPCCommands(CRPCTable &tableRPC);
/** Register mining RPC commands */
void RegisterMiningRPCCommands(CRPCTable &tableRPC);
/** Register raw transaction RPC commands */
void RegisterRawTransactionRPCCommands(CRPCTable &tableRPC);
/** Register atomic swap RPC commands (gated by -experimentalfeatures -atomicswaps) */
void RegisterAtomicSwapRPCCommands(CRPCTable &tableRPC);
/** Register Yellowback node-context RPC commands */
void RegisterYellowbackRPCCommands(CRPCTable &tableRPC);
/** Register Yellowback wallet-context RPC commands (ENABLE_WALLET) */
void RegisterYellowbackWalletRPCCommands(CRPCTable &tableRPC);
/** Register the vault primitive's set_* / vault_* RPC commands (docs/vault-rpc.md) */
void RegisterVaultRPCCommands(CRPCTable &tableRPC);

static inline void RegisterAllCoreRPCCommands(CRPCTable &tableRPC)
{
    RegisterBlockchainRPCCommands(tableRPC);
    RegisterNetRPCCommands(tableRPC);
    RegisterMiscRPCCommands(tableRPC);
    RegisterMiningRPCCommands(tableRPC);
    RegisterRawTransactionRPCCommands(tableRPC);
    RegisterAtomicSwapRPCCommands(tableRPC);
    RegisterYellowbackRPCCommands(tableRPC);
    RegisterVaultRPCCommands(tableRPC);
}

#endif // BITCOIN_RPC_REGISTER_H
