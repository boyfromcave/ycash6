// Copyright (c) 2025-2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "amount.h"
#include "consensus/upgrades.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "experimental_features.h"
#include "init.h"
#include "key_io.h"
#include "keystore.h"
#include "main.h"
#include "net.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "script/atomicswap.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/sign.h"
#include "script/standard.h"
#include "sync.h"
#include "uint256.h"
#include "util/moneystr.h"
#include "util/strencodings.h"
#include "util/time.h"
#ifdef ENABLE_WALLET
#include "wallet/rpcwallet.h"
#include "wallet/wallet.h"
#endif

#include <stdint.h>
#include <univalue.h>

using namespace std;

// Function declaration for function implemented in wallet/rpcwallet.cpp
bool EnsureWalletIsAvailable(bool avoidException);

// Gate for the -experimentalfeatures -atomicswaps RPCs. Must be a no-op when
// fHelp is set: `help` invokes every RPC with fHelp=true and a throw here
// would abort the whole help command.
static void EnsureAtomicSwapsEnabled(bool fHelp)
{
    if (fHelp) return;
    if (!fExperimentalAtomicSwaps) {
        throw JSONRPCError(RPC_METHOD_NOT_FOUND,
                           "Atomic swaps are an experimental feature. Start ycashd with "
                           "`-experimentalfeatures -atomicswaps` and the wallet enabled "
                           "(do not use -disablewallet) to enable.");
    }
}

// Helper: build PrecomputedTransactionData for a single-input claim/refund tx
// where the input spends exactly one HTLC output.
static PrecomputedTransactionData PrecomputeForHtlcSpend(
        const CTransaction& tx,
        const CTxOut& spentOutput)
{
    std::vector<CTxOut> allPrevOuts;
    allPrevOuts.push_back(spentOutput);
    return PrecomputedTransactionData(tx, allPrevOuts);
}

// ---------------------------------------------------------------------------
// Live swap-status resolution.
//
// The authoritative state of a swap is a pure function of chain data:
//   - contract UTXO still unspent           -> OPEN
//   - spent, spending scriptSig has secret  -> CLAIMED (secret recoverable)
//   - spent, no secret in scriptSig         -> REFUNDED
//   - spent but spender not locatable       -> UNKNOWN (txindex-limited)
//
// We therefore derive status on demand instead of trusting the stored
// CAtomicSwapInfo.status field (which is only a cache hint -- it can drift
// across reorgs / restarts / out-of-band spends). Resolution order for the
// spending transaction is wallet -> mempool -> GetTransaction (txindex or
// still-in-a-known-block), so the common case (we are a swap party, the
// claim/refund tx is in our own wallet) needs no txindex at all.
// ---------------------------------------------------------------------------

enum SwapChainStatus {
    SWAPCHAIN_OPEN,      // contract UTXO unspent
    SWAPCHAIN_CLAIMED,   // spent via the claim path; secret revealed
    SWAPCHAIN_REFUNDED,  // spent via the refund path
    SWAPCHAIN_UNKNOWN,   // spent, but the spending tx could not be located
};

struct SwapResolution {
    SwapChainStatus status = SWAPCHAIN_UNKNOWN;
    uint256 spendTxid;
    std::vector<unsigned char> secret;  // populated iff CLAIMED and extractable
    bool spendConfirmed = false;
    int spendHeight = -1;               // -1 if unconfirmed / unknown
};

// Look for a wallet transaction that spends COutPoint(contractTxid, vout).
// Returns true and fills txOut on success. Caller holds cs_main + cs_wallet.
static bool FindSpenderInWallet(
        const uint256& contractTxid, uint32_t vout, CTransaction& txOut)
{
    if (!pwalletMain) return false;
    for (const auto& [wtxid, wtx] : pwalletMain->mapWallet) {
        for (const CTxIn& in : wtx.vin) {
            if (in.prevout.hash == contractTxid && in.prevout.n == vout) {
                txOut = (CTransaction)wtx;
                return true;
            }
        }
    }
    return false;
}

static SwapResolution ResolveSwapStatus(const CAtomicSwapInfo& swap)
{
    AssertLockHeld(cs_main);

    SwapResolution res;

    // 1. Is the contract output still unspent?
    const CCoins* coins = pcoinsTip ? pcoinsTip->AccessCoins(swap.contractTxid) : nullptr;
    if (coins != nullptr && coins->IsAvailable(swap.contractVout)) {
        res.status = SWAPCHAIN_OPEN;
        return res;
    }

    // 2. Spent (or contract tx itself unknown to the UTXO set). Find the spender.
    CTransaction spendTx;
    bool found = false;

    // 2a. Our own wallet -- the common case for a swap party.
    if (pwalletMain) {
        LOCK(pwalletMain->cs_wallet);
        found = FindSpenderInWallet(swap.contractTxid, swap.contractVout, spendTx);
    }

    // 2b. Mempool.
    if (!found) {
        LOCK(mempool.cs);
        auto it = mempool.mapNextTx.find(COutPoint(swap.contractTxid, swap.contractVout));
        if (it != mempool.mapNextTx.end()) {
            auto ptx = mempool.get(it->second.ptx->GetHash());
            if (ptx) {
                spendTx = *ptx;
                found = true;
            }
        }
    }

    // 2c. GetTransaction: succeeds for a historical spend only if -txindex is
    // on (or the tx is in a block we can still read). This is the path that
    // degrades on a pruned/no-txindex node.
    if (!found) {
        // We do not know the spending txid yet, only the spent outpoint.
        // Without txindex there is no outpoint->spender map for historical
        // spends, so this case stays UNKNOWN. If the stored hint recorded a
        // spendTxid (e.g. claimswap/refundswap ran here earlier), try it.
        if (!swap.spendTxid.IsNull()) {
            uint256 blockHash;
            if (GetTransaction(swap.spendTxid, spendTx, Params().GetConsensus(), blockHash, true)) {
                found = true;
            }
        }
    }

    if (!found) {
        res.status = SWAPCHAIN_UNKNOWN;
        return res;
    }

    res.spendTxid = spendTx.GetHash();

    // Confirmation depth of the spend.
    {
        uint256 blockHash;
        CTransaction tmp;
        if (GetTransaction(res.spendTxid, tmp, Params().GetConsensus(), blockHash, true)
            && !blockHash.IsNull()) {
            auto bi = mapBlockIndex.find(blockHash);
            if (bi != mapBlockIndex.end() && bi->second) {
                res.spendConfirmed = true;
                res.spendHeight = bi->second->nHeight;
            }
        }
    }

    // 3. Classify: which input spent our contract outpoint, and does its
    // scriptSig carry a secret (claim) or not (refund)?
    for (const CTxIn& in : spendTx.vin) {
        if (in.prevout.hash == swap.contractTxid && in.prevout.n == swap.contractVout) {
            std::vector<unsigned char> secret;
            if (ExtractAtomicSwapSecret(in.scriptSig, secret)) {
                res.status = SWAPCHAIN_CLAIMED;
                res.secret = secret;
            } else {
                res.status = SWAPCHAIN_REFUNDED;
            }
            return res;
        }
    }

    // Spender located but no matching input (shouldn't happen) -> unknown.
    res.status = SWAPCHAIN_UNKNOWN;
    return res;
}

static std::string SwapChainStatusString(SwapChainStatus s)
{
    switch (s) {
        case SWAPCHAIN_OPEN:     return "open";
        case SWAPCHAIN_CLAIMED:  return "claimed";
        case SWAPCHAIN_REFUNDED: return "refunded";
        default:                 return "unknown";
    }
}

UniValue initiateswap(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 4 || params.size() > 5)
        throw runtime_error(
            "initiateswap \"fundingaddress\" \"recipientaddress\" amount locktime ( \"secret\" )\n"
            "\nInitiate an atomic swap by creating an HTLC contract.\n"
            "Locks funds claimable by the recipient with the secret, or refundable\n"
            "by the initiator after the locktime expires.\n"
            "\nArguments:\n"
            "1. \"fundingaddress\"    (string, required) Existing wallet address with sufficient balance\n"
            "2. \"recipientaddress\"  (string, required) The Ycash address of the recipient\n"
            "3. amount              (numeric, required) The amount in YEC to lock\n"
            "4. locktime            (numeric, required) Absolute locktime (block height < 500000000 or Unix timestamp >= 500000000)\n"
            "5. \"secret\"            (string, optional) 32-byte secret in hex (generated if not provided)\n"
            "\nResult:\n"
            "{\n"
            "  \"contract\": \"hex\",\n"
            "  \"contractP2SH\": \"address\",\n"
            "  \"contractTxid\": \"hex\",\n"
            "  \"contractVout\": n,\n"
            "  \"secret\": \"hex\",\n"
            "  \"secretHash\": \"hex\",\n"
            "  \"refundLocktime\": n\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("initiateswap", "\"s1kTb43xroRcuscGeiajocxn3PkRhZ9eRNw\" \"s1bHiHvZu5x8yprHJbAYZtEYgfHKCdUTmkP\" 1.0 1500000")
            + HelpExampleRpc("initiateswap", "\"s1kTb43xroRcuscGeiajocxn3PkRhZ9eRNw\", \"s1bHiHvZu5x8yprHJbAYZtEYgfHKCdUTmkP\", 1.0, 1500000")
        );

    EnsureAtomicSwapsEnabled(fHelp);
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    LOCK2(cs_main, pwalletMain->cs_wallet);
    KeyIO keyIO(Params());

    // Parse funding address
    CTxDestination fundingDest = keyIO.DecodeDestination(params[0].get_str());
    if (!IsValidDestination(fundingDest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid funding address");
    }
    if (!IsKeyDestination(fundingDest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Funding address must be a P2PKH address");
    }
    CKeyID fundingKeyID = std::get<CKeyID>(fundingDest);
    if (IsMine(*pwalletMain, fundingKeyID) == ISMINE_NO) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Funding address does not belong to this wallet");
    }

    // Parse recipient address
    CTxDestination recipientDest = keyIO.DecodeDestination(params[1].get_str());
    if (!IsValidDestination(recipientDest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid recipient address");
    }
    if (!IsKeyDestination(recipientDest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Recipient address must be a P2PKH address");
    }
    CKeyID recipientKeyID = std::get<CKeyID>(recipientDest);

    // Parse amount
    CAmount nAmount = AmountFromValue(params[2]);
    if (nAmount <= 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Amount must be positive");
    }

    // Validate funding-address balance.
    // better-ycash's GetAddressBalances takes an asOfHeight; nullopt = current.
    std::map<CTxDestination, CAmount> addressBalances = pwalletMain->GetAddressBalances(std::nullopt);
    CAmount fundingBalance = 0;
    if (addressBalances.count(fundingDest)) {
        fundingBalance = addressBalances[fundingDest];
    }
    if (fundingBalance < nAmount) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
            strprintf("Funding address has insufficient balance. Required: %s, Available: %s",
                      FormatMoney(nAmount), FormatMoney(fundingBalance)));
    }

    // Parse locktime
    int64_t lockTime = params[3].get_int64();
    if (lockTime <= 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Locktime must be positive");
    }

    // Generate or parse secret
    vector<unsigned char> secret;
    if (params.size() > 4 && !params[4].isNull()) {
        string secretHex = params[4].get_str();
        if (!IsHex(secretHex)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Secret must be hex encoded");
        }
        secret = ParseHex(secretHex);
        if (secret.size() != 32) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Secret must be 32 bytes");
        }
    } else {
        secret = GenerateAtomicSwapSecret();
    }

    uint160 secretHash = Hash160(secret);
    CKeyID initiatorKeyID = fundingKeyID;

    AtomicSwapContract contract(secretHash, recipientKeyID, initiatorKeyID, lockTime);
    string error;
    if (!ValidateAtomicSwapContract(contract, chainActive.Height(), error)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, error);
    }

    CScript redeemScript = BuildAtomicSwapScript(contract);
    CScriptID scriptID(redeemScript);
    CTxDestination contractDest(scriptID);
    string contractAddress = keyIO.EncodeDestination(contractDest);

    // Build a CRecipient list and let CreateTransaction handle coin selection.
    CScript scriptPubKey = GetScriptForDestination(scriptID);
    vector<CRecipient> vecSend;
    CRecipient recipient = { scriptPubKey, nAmount, false };
    vecSend.push_back(recipient);

    CWalletTx wtx;
    CReserveKey reservekey(pwalletMain);
    CAmount nFeeRequired;
    int nChangePosRet = -1;
    string strError;
    if (!pwalletMain->CreateTransaction(vecSend, wtx, reservekey, nFeeRequired, nChangePosRet, strError)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    // better-ycash's CommitTransaction takes a CValidationState by reference
    // and the reservekey wrapped via std::ref().
    CValidationState state;
    if (!pwalletMain->CommitTransaction(wtx, std::ref(reservekey), state)) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "Error: The transaction was rejected: " + state.GetRejectReason());
    }

    // Find the output that paid into the HTLC.
    uint32_t vout = 0;
    bool foundVout = false;
    for (uint32_t i = 0; i < wtx.vout.size(); i++) {
        if (wtx.vout[i].scriptPubKey == scriptPubKey && wtx.vout[i].nValue == nAmount) {
            vout = i;
            foundVout = true;
            break;
        }
    }
    if (!foundVout) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Could not locate contract output in funded transaction");
    }

    CAtomicSwapInfo swapInfo(
        wtx.GetHash(),
        vout,
        redeemScript,
        nAmount,
        contract,
        ROLE_INITIATOR
    );
    swapInfo.secret = secret;
    swapInfo.secretKnown = true;
    if (!pwalletMain->AddAtomicSwap(swapInfo)) {
        LogPrintf("Warning: Failed to persist atomic swap to wallet: %s\n", swapInfo.GetSwapId());
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("contract", HexStr(redeemScript.begin(), redeemScript.end()));
    result.pushKV("contractP2SH", contractAddress);
    result.pushKV("contractTxid", wtx.GetHash().GetHex());
    result.pushKV("contractVout", (int)vout);
    result.pushKV("secret", HexStr(secret.begin(), secret.end()));
    result.pushKV("secretHash", secretHash.GetHex());
    result.pushKV("refundLocktime", lockTime);
    if (lockTime >= LOCKTIME_THRESHOLD) {
        result.pushKV("refundLocktimeFormatted", DateTimeStrFormat("%Y-%m-%d %H:%M:%S UTC", lockTime));
    }
    return result;
}

UniValue initiateswapfromhash(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 5)
        throw runtime_error(
            "initiateswapfromhash \"fundingaddress\" \"recipientaddress\" amount locktime \"secrethash\"\n"
            "\nInitiate an atomic swap using a known secret hash (when the counterparty generated the secret).\n"
            "\nArguments:\n"
            "1. \"fundingaddress\"    (string, required) Existing wallet address with sufficient balance\n"
            "2. \"recipientaddress\"  (string, required) The Ycash address of the recipient\n"
            "3. amount              (numeric, required) The amount in YEC to lock\n"
            "4. locktime            (numeric, required) Absolute locktime (block height < 500000000 or Unix timestamp >= 500000000)\n"
            "5. \"secrethash\"        (string, required) 20-byte HASH160 of the secret, in hex\n"
            "\nExamples:\n"
            + HelpExampleCli("initiateswapfromhash", "\"s1kTb43xroRcuscGeiajocxn3PkRhZ9eRNw\" \"s1bHiHvZu5x8yprHJbAYZtEYgfHKCdUTmkP\" 1.0 1500000 \"a1b2c3...\"")
        );

    EnsureAtomicSwapsEnabled(fHelp);
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    LOCK2(cs_main, pwalletMain->cs_wallet);
    KeyIO keyIO(Params());

    CTxDestination fundingDest = keyIO.DecodeDestination(params[0].get_str());
    if (!IsValidDestination(fundingDest) || !IsKeyDestination(fundingDest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-P2PKH funding address");
    }
    CKeyID fundingKeyID = std::get<CKeyID>(fundingDest);
    if (IsMine(*pwalletMain, fundingKeyID) == ISMINE_NO) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Funding address does not belong to this wallet");
    }

    CTxDestination recipientDest = keyIO.DecodeDestination(params[1].get_str());
    if (!IsValidDestination(recipientDest) || !IsKeyDestination(recipientDest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-P2PKH recipient address");
    }
    CKeyID recipientKeyID = std::get<CKeyID>(recipientDest);

    CAmount nAmount = AmountFromValue(params[2]);
    if (nAmount <= 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Amount must be positive");
    }

    std::map<CTxDestination, CAmount> addressBalances = pwalletMain->GetAddressBalances(std::nullopt);
    CAmount fundingBalance = addressBalances.count(fundingDest) ? addressBalances[fundingDest] : 0;
    if (fundingBalance < nAmount) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
            strprintf("Funding address has insufficient balance. Required: %s, Available: %s",
                      FormatMoney(nAmount), FormatMoney(fundingBalance)));
    }

    int64_t lockTime = params[3].get_int64();
    if (lockTime <= 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Locktime must be positive");
    }

    string secretHashHex = params[4].get_str();
    if (!IsHex(secretHashHex)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Secret hash must be hex encoded");
    }
    vector<unsigned char> secretHashBytes = ParseHex(secretHashHex);
    if (secretHashBytes.size() != 20) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Secret hash must be exactly 20 bytes (HASH160)");
    }
    uint160 secretHash(secretHashBytes);
    CKeyID initiatorKeyID = fundingKeyID;

    AtomicSwapContract contract(secretHash, recipientKeyID, initiatorKeyID, lockTime);
    string error;
    if (!ValidateAtomicSwapContract(contract, chainActive.Height(), error)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, error);
    }

    CScript redeemScript = BuildAtomicSwapScript(contract);
    CScriptID scriptID(redeemScript);
    string contractAddress = keyIO.EncodeDestination(CTxDestination(scriptID));

    CScript scriptPubKey = GetScriptForDestination(scriptID);
    vector<CRecipient> vecSend;
    CRecipient recipient = { scriptPubKey, nAmount, false };
    vecSend.push_back(recipient);

    CWalletTx wtx;
    CReserveKey reservekey(pwalletMain);
    CAmount nFeeRequired;
    int nChangePosRet = -1;
    string strError;
    if (!pwalletMain->CreateTransaction(vecSend, wtx, reservekey, nFeeRequired, nChangePosRet, strError)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    CValidationState state;
    if (!pwalletMain->CommitTransaction(wtx, std::ref(reservekey), state)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Transaction rejected: " + state.GetRejectReason());
    }

    uint32_t vout = 0;
    bool foundVout = false;
    for (uint32_t i = 0; i < wtx.vout.size(); i++) {
        if (wtx.vout[i].scriptPubKey == scriptPubKey && wtx.vout[i].nValue == nAmount) {
            vout = i;
            foundVout = true;
            break;
        }
    }
    if (!foundVout) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Could not locate contract output in funded transaction");
    }

    // No secret known on this side (this is the "hash-only" flavour).
    CAtomicSwapInfo swapInfo(wtx.GetHash(), vout, redeemScript, nAmount, contract, ROLE_INITIATOR);
    if (!pwalletMain->AddAtomicSwap(swapInfo)) {
        LogPrintf("Warning: Failed to persist atomic swap to wallet: %s\n", swapInfo.GetSwapId());
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("contract", HexStr(redeemScript.begin(), redeemScript.end()));
    result.pushKV("contractP2SH", contractAddress);
    result.pushKV("contractTxid", wtx.GetHash().GetHex());
    result.pushKV("contractVout", (int)vout);
    result.pushKV("secretHash", secretHash.GetHex());
    result.pushKV("refundLocktime", lockTime);
    if (lockTime >= LOCKTIME_THRESHOLD) {
        result.pushKV("refundLocktimeFormatted", DateTimeStrFormat("%Y-%m-%d %H:%M:%S UTC", lockTime));
    }
    return result;
}

UniValue auditswap(const UniValue& params, bool fHelp)
{
    EnsureAtomicSwapsEnabled(fHelp);
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "auditswap \"contract\" \"contracttxid\" vout\n"
            "\nAudit an atomic swap contract: verify it parses, locate the funded output,\n"
            "and return the contract parameters.\n"
            "\nArguments:\n"
            "1. \"contract\"        (string, required) The HTLC redeem script in hex\n"
            "2. \"contracttxid\"    (string, required) The funding transaction ID\n"
            "3. vout              (numeric, required) The funded output index\n"
        );

    LOCK(cs_main);

    string contractHex = params[0].get_str();
    if (!IsHex(contractHex)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Contract must be hex encoded");
    }
    vector<unsigned char> contractData = ParseHex(contractHex);
    CScript redeemScript(contractData.begin(), contractData.end());

    AtomicSwapContract contract;
    if (!ExtractAtomicSwapContract(redeemScript, contract)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid atomic swap contract");
    }

    uint256 txid;
    txid.SetHex(params[1].get_str());
    uint32_t vout = params[2].get_int();

    CTransaction tx;
    uint256 blockHash;
    if (!GetTransaction(txid, tx, Params().GetConsensus(), blockHash, true)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not found");
    }
    if (vout >= tx.vout.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Output index out of range");
    }
    if (!VerifyAtomicSwapOutput(tx.vout[vout], redeemScript)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Output does not match contract");
    }

    KeyIO keyIO(Params());
    CScriptID scriptID(redeemScript);
    bool locktimeReached = (contract.lockTime < LOCKTIME_THRESHOLD)
        ? (chainActive.Height() >= contract.lockTime)
        : (GetTime() >= contract.lockTime);

    UniValue result(UniValue::VOBJ);
    result.pushKV("contractP2SH", keyIO.EncodeDestination(CTxDestination(scriptID)));
    result.pushKV("contractValue", ValueFromAmount(tx.vout[vout].nValue));
    result.pushKV("recipientAddress", keyIO.EncodeDestination(CTxDestination(contract.recipientPubKeyHash)));
    result.pushKV("initiatorAddress", keyIO.EncodeDestination(CTxDestination(contract.initiatorPubKeyHash)));
    result.pushKV("secretHash", contract.secretHash.GetHex());
    result.pushKV("refundLocktime", contract.lockTime);
    if (contract.lockTime >= LOCKTIME_THRESHOLD) {
        result.pushKV("refundLocktimeFormatted",
                      DateTimeStrFormat("%Y-%m-%d %H:%M:%S UTC", contract.lockTime));
    }
    result.pushKV("locktimeReached", locktimeReached);
    return result;
}

UniValue claimswap(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 4 || params.size() > 5)
        throw runtime_error(
            "claimswap \"contract\" \"contracttxid\" vout \"secret\" ( \"recipientaddress\" )\n"
            "\nClaim funds from an atomic swap by revealing the secret.\n"
            "\nArguments:\n"
            "1. \"contract\"            (string, required) The HTLC redeem script in hex\n"
            "2. \"contracttxid\"        (string, required) The contract transaction ID\n"
            "3. vout                  (numeric, required) The contract output index\n"
            "4. \"secret\"              (string, required) The 32-byte secret in hex\n"
            "5. \"recipientaddress\"    (string, optional) The address to receive claimed funds (defaults to the contract's recipient)\n"
        );

    EnsureAtomicSwapsEnabled(fHelp);
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string contractHex = params[0].get_str();
    if (!IsHex(contractHex)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Contract must be hex encoded");
    }
    vector<unsigned char> contractData = ParseHex(contractHex);
    CScript redeemScript(contractData.begin(), contractData.end());

    AtomicSwapContract contract;
    if (!ExtractAtomicSwapContract(redeemScript, contract)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid atomic swap contract");
    }

    uint256 txid;
    txid.SetHex(params[1].get_str());
    uint32_t vout = params[2].get_int();

    string secretHex = params[3].get_str();
    if (!IsHex(secretHex)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Secret must be hex encoded");
    }
    vector<unsigned char> secret = ParseHex(secretHex);
    if (secret.size() != 32) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Secret must be 32 bytes");
    }
    if (Hash160(secret) != contract.secretHash) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Secret does not match contract hash");
    }

    CKey recipientKey;
    if (!pwalletMain->GetKey(contract.recipientPubKeyHash, recipientKey)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Recipient private key not found in wallet");
    }

    CTransaction contractTx;
    uint256 blockHash;
    if (!GetTransaction(txid, contractTx, Params().GetConsensus(), blockHash, true)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Contract transaction not found");
    }
    if (vout >= contractTx.vout.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Output index out of range");
    }
    if (!VerifyAtomicSwapOutput(contractTx.vout[vout], redeemScript)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Output does not match contract");
    }

    // Destination for claimed funds (default: recipient's own pubkey hash).
    CTxDestination claimDest;
    KeyIO keyIO(Params());
    if (params.size() > 4 && !params[4].isNull()) {
        claimDest = keyIO.DecodeDestination(params[4].get_str());
        if (!IsValidDestination(claimDest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid recipient address");
        }
        EnsurePQRecipientPayable(claimDest);   // an sq… address is a TX_PQPKH output (vault upgrade, Falcon for scheme 2)
    } else {
        claimDest = CTxDestination(contract.recipientPubKeyHash);
    }

    CMutableTransaction mtx;
    mtx.nVersion = SAPLING_TX_VERSION;
    mtx.fOverwintered = true;
    mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    mtx.nExpiryHeight = chainActive.Height() + 20;

    mtx.vin.push_back(CTxIn(COutPoint(txid, vout), CScript(),
                            std::numeric_limits<unsigned int>::max()));

    CAmount inputAmount = contractTx.vout[vout].nValue;
    const CAmount fee = 10000;
    CAmount outputAmount = inputAmount - fee;
    if (outputAmount <= 0) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Contract value too small to pay fee");
    }
    mtx.vout.push_back(CTxOut(outputAmount, GetScriptForDestination(claimDest)));

    CTransaction txConst(mtx);
    auto consensusBranchId = CurrentEpochBranchId(chainActive.Height(), Params().GetConsensus());
    PrecomputedTransactionData txdata = PrecomputeForHtlcSpend(txConst, contractTx.vout[vout]);
    uint256 hash = SignatureHash(redeemScript, txConst, 0, SIGHASH_ALL, inputAmount, consensusBranchId, txdata);

    vector<unsigned char> vchSig;
    if (!recipientKey.Sign(hash, vchSig)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign transaction");
    }
    vchSig.push_back((unsigned char)SIGHASH_ALL);

    CPubKey recipientPubKey = recipientKey.GetPubKey();
    vector<unsigned char> vchPubKey(recipientPubKey.begin(), recipientPubKey.end());
    mtx.vin[0].scriptSig = BuildAtomicSwapClaimScript(secret, vchSig, vchPubKey, redeemScript);

    CTransaction claimTx(mtx);
    CValidationState state;
    bool fMissingInputs = false;
    if (!AcceptToMemoryPool(Params(), mempool, state, claimTx, false, &fMissingInputs, true)) {
        if (state.IsInvalid()) {
            throw JSONRPCError(RPC_TRANSACTION_REJECTED,
                strprintf("%i: %s", state.GetRejectCode(), state.GetRejectReason()));
        }
        if (fMissingInputs) {
            throw JSONRPCError(RPC_TRANSACTION_ERROR, "Missing inputs");
        }
        throw JSONRPCError(RPC_TRANSACTION_ERROR, state.GetRejectReason());
    }
    RelayTransaction(claimTx);

    // Update or create swap record.
    std::string swapId = txid.GetHex() + ":" + std::to_string(vout);
    CAtomicSwapInfo swapInfo;
    if (pwalletMain->GetAtomicSwap(swapId, swapInfo)) {
        swapInfo.status = SWAP_CLAIMED;
        swapInfo.completedTime = GetTime();
        swapInfo.spendTxid = claimTx.GetHash();
        if (!swapInfo.secretKnown) {
            swapInfo.secret = secret;
            swapInfo.secretKnown = true;
        }
        pwalletMain->UpdateAtomicSwap(swapInfo);
    } else {
        // Participant claiming for the first time: record if any party is ours.
        bool isOurs = (IsMine(*pwalletMain, contract.recipientPubKeyHash) != ISMINE_NO) ||
                      (IsMine(*pwalletMain, contract.initiatorPubKeyHash) != ISMINE_NO);
        if (isOurs) {
            CAtomicSwapInfo newSwap(txid, vout, redeemScript, inputAmount, contract, ROLE_PARTICIPANT);
            newSwap.status = SWAP_CLAIMED;
            newSwap.completedTime = GetTime();
            newSwap.spendTxid = claimTx.GetHash();
            newSwap.secret = secret;
            newSwap.secretKnown = true;
            pwalletMain->AddAtomicSwap(newSwap);
        }
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", claimTx.GetHash().GetHex());
    result.pushKV("hex", EncodeHexTx(claimTx));
    return result;
}

UniValue refundswap(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 4)
        throw runtime_error(
            "refundswap \"contract\" \"contracttxid\" vout ( \"refundaddress\" )\n"
            "\nRefund an atomic swap after the locktime has expired.\n"
            "\nArguments:\n"
            "1. \"contract\"         (string, required) The HTLC redeem script in hex\n"
            "2. \"contracttxid\"     (string, required) The contract transaction ID\n"
            "3. vout               (numeric, required) The contract output index\n"
            "4. \"refundaddress\"    (string, optional) Address to send refunded funds to (default: the contract's initiator)\n"
        );

    EnsureAtomicSwapsEnabled(fHelp);
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string contractHex = params[0].get_str();
    if (!IsHex(contractHex)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Contract must be hex encoded");
    }
    vector<unsigned char> contractData = ParseHex(contractHex);
    CScript redeemScript(contractData.begin(), contractData.end());

    AtomicSwapContract contract;
    if (!ExtractAtomicSwapContract(redeemScript, contract)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid atomic swap contract");
    }

    bool locktimeReached = (contract.lockTime < LOCKTIME_THRESHOLD)
        ? (chainActive.Height() >= contract.lockTime)
        : (GetTime() >= contract.lockTime);
    if (!locktimeReached) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "Locktime has not been reached yet. Current: " +
            (contract.lockTime < LOCKTIME_THRESHOLD
                ? std::to_string(chainActive.Height())
                : std::to_string(GetTime())) +
            ", Required: " + std::to_string(contract.lockTime));
    }

    uint256 txid;
    txid.SetHex(params[1].get_str());
    uint32_t vout = params[2].get_int();

    CKey initiatorKey;
    if (!pwalletMain->GetKey(contract.initiatorPubKeyHash, initiatorKey)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Initiator private key not found in wallet");
    }
    CPubKey initiatorPubKey = initiatorKey.GetPubKey();

    CTransaction contractTx;
    uint256 blockHash;
    if (!GetTransaction(txid, contractTx, Params().GetConsensus(), blockHash, true)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Contract transaction not found");
    }
    if (vout >= contractTx.vout.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Output index out of range");
    }
    if (!VerifyAtomicSwapOutput(contractTx.vout[vout], redeemScript)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Output does not match contract");
    }

    CTxDestination refundDest;
    KeyIO keyIO(Params());
    if (params.size() > 3 && !params[3].isNull()) {
        refundDest = keyIO.DecodeDestination(params[3].get_str());
        if (!IsValidDestination(refundDest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid refund address");
        }
        EnsurePQRecipientPayable(refundDest);   // an sq… address is a TX_PQPKH output (vault upgrade, Falcon for scheme 2)
    } else {
        refundDest = CTxDestination(contract.initiatorPubKeyHash);
    }

    CMutableTransaction mtx;
    mtx.nVersion = SAPLING_TX_VERSION;
    mtx.fOverwintered = true;
    mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    mtx.nExpiryHeight = chainActive.Height() + 20;
    mtx.nLockTime = contract.lockTime; // Required for CLTV
    // nSequence < UINT_MAX so nLockTime is honoured.
    mtx.vin.push_back(CTxIn(COutPoint(txid, vout), CScript(),
                            std::numeric_limits<unsigned int>::max() - 1));

    CAmount inputAmount = contractTx.vout[vout].nValue;
    const CAmount fee = 10000;
    CAmount outputAmount = inputAmount - fee;
    if (outputAmount <= 0) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Contract value too small to pay fee");
    }
    mtx.vout.push_back(CTxOut(outputAmount, GetScriptForDestination(refundDest)));

    CTransaction txConst(mtx);
    auto consensusBranchId = CurrentEpochBranchId(chainActive.Height(), Params().GetConsensus());
    PrecomputedTransactionData txdata = PrecomputeForHtlcSpend(txConst, contractTx.vout[vout]);
    uint256 hash = SignatureHash(redeemScript, txConst, 0, SIGHASH_ALL, inputAmount, consensusBranchId, txdata);

    vector<unsigned char> vchSig;
    if (!initiatorKey.Sign(hash, vchSig)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign transaction");
    }
    vchSig.push_back((unsigned char)SIGHASH_ALL);

    vector<unsigned char> initiatorPubKeyVec(initiatorPubKey.begin(), initiatorPubKey.end());
    mtx.vin[0].scriptSig = BuildAtomicSwapRefundScript(vchSig, initiatorPubKeyVec, redeemScript);

    CTransaction refundTx(mtx);
    CValidationState state;
    bool fMissingInputs = false;
    if (!AcceptToMemoryPool(Params(), mempool, state, refundTx, false, &fMissingInputs, true)) {
        if (state.IsInvalid()) {
            throw JSONRPCError(RPC_TRANSACTION_REJECTED,
                strprintf("%i: %s", state.GetRejectCode(), state.GetRejectReason()));
        }
        if (fMissingInputs) {
            throw JSONRPCError(RPC_TRANSACTION_ERROR, "Missing inputs");
        }
        throw JSONRPCError(RPC_TRANSACTION_ERROR, state.GetRejectReason());
    }
    RelayTransaction(refundTx);

    std::string swapId = txid.GetHex() + ":" + std::to_string(vout);
    CAtomicSwapInfo swapInfo;
    if (pwalletMain->GetAtomicSwap(swapId, swapInfo)) {
        swapInfo.status = SWAP_REFUNDED;
        swapInfo.completedTime = GetTime();
        swapInfo.spendTxid = refundTx.GetHash();
        pwalletMain->UpdateAtomicSwap(swapInfo);
    } else {
        LogPrintf("Warning: Refunding swap not found in database: %s\n", swapId);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", refundTx.GetHash().GetHex());
    result.pushKV("hex", EncodeHexTx(refundTx));
    return result;
}

UniValue participateswap(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 4 || params.size() > 5)
        throw runtime_error(
            "participateswap \"contract\" \"contracttxid\" vout \"counterpartyaddress\" ( \"label\" )\n"
            "\nRegister interest in an existing on-chain HTLC as a participant. Does not\n"
            "fund anything; just records the contract so monitorswap / claimswap can find it.\n"
            "\nArguments:\n"
            "1. \"contract\"              (string, required) The HTLC redeem script in hex\n"
            "2. \"contracttxid\"          (string, required) The contract transaction ID\n"
            "3. vout                     (numeric, required) The contract output index\n"
            "4. \"counterpartyaddress\"   (string, required) Counterparty (typically the initiator) -- recorded as metadata\n"
            "5. \"label\"                 (string, optional) User-defined label\n"
        );

    EnsureAtomicSwapsEnabled(fHelp);
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string contractHex = params[0].get_str();
    if (!IsHex(contractHex)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Contract must be hex encoded");
    }
    vector<unsigned char> contractData = ParseHex(contractHex);
    CScript redeemScript(contractData.begin(), contractData.end());

    AtomicSwapContract contract;
    if (!ExtractAtomicSwapContract(redeemScript, contract)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid atomic swap contract");
    }

    uint256 txid;
    txid.SetHex(params[1].get_str());
    uint32_t vout = params[2].get_int();

    string counterparty = params[3].get_str();
    string label;
    if (params.size() > 4) {
        label = params[4].get_str();
    }

    CTransaction tx;
    uint256 blockHash;
    if (!GetTransaction(txid, tx, Params().GetConsensus(), blockHash, true)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not found");
    }
    if (vout >= tx.vout.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Output index out of range");
    }
    if (!VerifyAtomicSwapOutput(tx.vout[vout], redeemScript)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Output does not match contract");
    }

    CAmount amount = tx.vout[vout].nValue;
    CAtomicSwapInfo swapInfo(txid, vout, redeemScript, amount, contract, ROLE_PARTICIPANT);
    swapInfo.label = label;
    swapInfo.counterparty = counterparty;
    if (!pwalletMain->AddAtomicSwap(swapInfo)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to register swap in wallet");
    }

    KeyIO keyIO(Params());
    UniValue result(UniValue::VOBJ);
    result.pushKV("swapId", swapInfo.GetSwapId());
    result.pushKV("status", "participated");
    result.pushKV("contractTxid", txid.GetHex());
    result.pushKV("contractVout", (int)vout);
    result.pushKV("amount", ValueFromAmount(amount));
    result.pushKV("recipientAddress", keyIO.EncodeDestination(CTxDestination(contract.recipientPubKeyHash)));
    result.pushKV("initiatorAddress", keyIO.EncodeDestination(CTxDestination(contract.initiatorPubKeyHash)));
    result.pushKV("secretHash", contract.secretHash.GetHex());
    if (!label.empty()) {
        result.pushKV("label", label);
    }
    return result;
}

UniValue getswapsecret(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getswapsecret \"swapid\"\n"
            "\nReveal the secret preimage for a swap that we know it for (because we\n"
            "initiated, or we observed a claim).\n"
            "\nArguments:\n"
            "1. \"swapid\"  (string, required) \"<contractTxid>:<vout>\"\n"
        );

    EnsureAtomicSwapsEnabled(fHelp);
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    LOCK(cs_main);

    std::string swapId = params[0].get_str();
    CAtomicSwapInfo swapInfo;
    if (!pwalletMain->GetAtomicSwap(swapId, swapInfo)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Swap not found: " + swapId);
    }

    // The secret is recoverable two ways: it was stored when *we* generated
    // it (initiator with initiateswap), or it was revealed on-chain by a
    // claim and we read it back out of the spending tx. Prefer the live
    // chain reading so this works even for a participant who never had the
    // secret stored locally.
    std::vector<unsigned char> secret;
    if (swapInfo.secretKnown && !swapInfo.secret.empty()) {
        secret = swapInfo.secret;
    } else {
        SwapResolution res = ResolveSwapStatus(swapInfo);
        if (res.status == SWAPCHAIN_CLAIMED && !res.secret.empty()) {
            secret = res.secret;
        }
    }

    if (secret.empty()) {
        throw JSONRPCError(RPC_WALLET_ERROR,
            "Secret is not known for this swap (not generated locally and no "
            "on-chain claim has revealed it, or the claim could not be located "
            "-- a pruned node without -txindex cannot resolve historical claims).");
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("secret", HexStr(secret.begin(), secret.end()));
    result.pushKV("secretHash", swapInfo.contract.secretHash.GetHex());
    result.pushKV("known", true);
    return result;
}

UniValue deleteswap(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "deleteswap \"swapid\"\n"
            "\nDelete an atomic swap record from the wallet. CANNOT BE UNDONE.\n"
            "Does NOT broadcast or interact with the chain.\n"
            "\nArguments:\n"
            "1. \"swapid\"  (string, required) \"<contractTxid>:<vout>\"\n"
        );

    EnsureAtomicSwapsEnabled(fHelp);
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    LOCK2(cs_main, pwalletMain->cs_wallet);
    std::string swapId = params[0].get_str();
    CAtomicSwapInfo swapInfo;
    if (!pwalletMain->GetAtomicSwap(swapId, swapInfo)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Swap not found: " + swapId);
    }
    if (!pwalletMain->EraseAtomicSwap(swapId)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to delete swap: " + swapId);
    }
    UniValue result(UniValue::VOBJ);
    result.pushKV("deleted", true);
    result.pushKV("swapId", swapId);
    return result;
}

// Helper: format a duration in seconds as a human-readable string.
static std::string HumanReadableDuration(int64_t seconds)
{
    int days = seconds / 86400;
    int hours = (seconds % 86400) / 3600;
    int minutes = (seconds % 3600) / 60;
    int secs = seconds % 60;
    if (days > 0) {
        return strprintf("%d day%s, %d hour%s", days, (days != 1 ? "s" : ""),
                         hours, (hours != 1 ? "s" : ""));
    } else if (hours > 0) {
        return strprintf("%d hour%s, %d minute%s", hours, (hours != 1 ? "s" : ""),
                         minutes, (minutes != 1 ? "s" : ""));
    } else if (minutes > 0) {
        return strprintf("%d minute%s, %d second%s", minutes, (minutes != 1 ? "s" : ""),
                         secs, (secs != 1 ? "s" : ""));
    }
    return strprintf("%d second%s", secs, (secs != 1 ? "s" : ""));
}

UniValue listatomicswaps(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "listatomicswaps ( \"status\" )\n"
            "\nList atomic swap records in the wallet, optionally filtered by status.\n"
            "\nArguments:\n"
            "1. \"status\"  (string, optional) One of: initiated, participated, claimed, refunded, expired, abandoned\n"
        );

    EnsureAtomicSwapsEnabled(fHelp);
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    LOCK(cs_main);

    std::string filterStatus;
    if (params.size() > 0) {
        filterStatus = params[0].get_str();
    }

    std::vector<CAtomicSwapInfo> swaps = pwalletMain->ListAtomicSwaps();
    KeyIO keyIO(Params());

    UniValue result(UniValue::VARR);
    for (const auto& swap : swaps) {
        // Derive authoritative status from chain; filter on that, not the
        // stored hint.
        SwapResolution res = ResolveSwapStatus(swap);
        std::string chainStatus = SwapChainStatusString(res.status);
        if (!filterStatus.empty() && chainStatus != filterStatus) {
            continue;
        }
        const bool isOpen = (res.status == SWAPCHAIN_OPEN);

        UniValue swapObj(UniValue::VOBJ);
        swapObj.pushKV("swapId", swap.GetSwapId());
        swapObj.pushKV("contractTxid", swap.contractTxid.GetHex());
        swapObj.pushKV("contractVout", (int)swap.contractVout);
        swapObj.pushKV("amount", ValueFromAmount(swap.amount));
        swapObj.pushKV("role", swap.GetRoleString());
        swapObj.pushKV("status", chainStatus);
        swapObj.pushKV("storedStatusHint", swap.GetStatusString());
        swapObj.pushKV("initiatedTime", swap.initiatedTime);
        if (swap.initiatedTime > 0) {
            swapObj.pushKV("initiatedTimeFormatted",
                           DateTimeStrFormat("%Y-%m-%d %H:%M:%S UTC", swap.initiatedTime));
        }
        swapObj.pushKV("completedTime", swap.completedTime);
        if (swap.completedTime > 0) {
            swapObj.pushKV("completedTimeFormatted",
                           DateTimeStrFormat("%Y-%m-%d %H:%M:%S UTC", swap.completedTime));
        }
        swapObj.pushKV("secretHash", swap.contract.secretHash.GetHex());
        swapObj.pushKV("secretKnown", swap.secretKnown);
        swapObj.pushKV("contract", HexStr(swap.redeemScript.begin(), swap.redeemScript.end()));
        swapObj.pushKV("recipientAddress",
                       keyIO.EncodeDestination(CTxDestination(swap.contract.recipientPubKeyHash)));
        swapObj.pushKV("initiatorAddress",
                       keyIO.EncodeDestination(CTxDestination(swap.contract.initiatorPubKeyHash)));
        swapObj.pushKV("locktime", swap.contract.lockTime);
        if (swap.contract.lockTime >= LOCKTIME_THRESHOLD) {
            swapObj.pushKV("locktimeFormatted",
                           DateTimeStrFormat("%Y-%m-%d %H:%M:%S UTC", swap.contract.lockTime));
        }

        if (isOpen) {
            int64_t timeUntilExpiry = 0;
            bool hasExpired = false;
            if (swap.contract.lockTime < LOCKTIME_THRESHOLD) {
                int currentHeight = chainActive.Height();
                if (currentHeight >= swap.contract.lockTime) {
                    hasExpired = true;
                } else {
                    timeUntilExpiry = (swap.contract.lockTime - currentHeight) * 150;
                }
            } else {
                int64_t currentTime = GetTime();
                if (currentTime >= swap.contract.lockTime) {
                    hasExpired = true;
                } else {
                    timeUntilExpiry = swap.contract.lockTime - currentTime;
                }
            }
            if (!hasExpired && timeUntilExpiry > 0) {
                swapObj.pushKV("timeUntilExpiry", HumanReadableDuration(timeUntilExpiry));
                swapObj.pushKV("secondsUntilExpiry", timeUntilExpiry);
            }
        }

        if (res.status == SWAPCHAIN_CLAIMED || res.status == SWAPCHAIN_REFUNDED) {
            swapObj.pushKV("spendTxid", res.spendTxid.GetHex());
            swapObj.pushKV("spendConfirmed", res.spendConfirmed);
            if (res.spendConfirmed) {
                swapObj.pushKV("spendBlockHeight", res.spendHeight);
            } else {
                swapObj.pushKV("spendStatus", "pending in mempool");
            }
            if (res.status == SWAPCHAIN_CLAIMED && !res.secret.empty()) {
                swapObj.pushKV("revealedSecret",
                               HexStr(res.secret.begin(), res.secret.end()));
            }
        } else if (res.status == SWAPCHAIN_UNKNOWN) {
            swapObj.pushKV("note",
                "spent but spending tx not locatable (pruned / no -txindex)");
        }

        if (!swap.label.empty()) {
            swapObj.pushKV("label", swap.label);
        }
        if (!swap.counterparty.empty()) {
            swapObj.pushKV("counterparty", swap.counterparty);
        }
        result.push_back(swapObj);
    }
    return result;
}

UniValue monitorswap(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "monitorswap \"swapid\"\n"
            "\nReturn the current observed status of a single swap, including time-until-expiry\n"
            "and information about the spending transaction (if any).\n"
            "\nArguments:\n"
            "1. \"swapid\"  (string, required) \"<contractTxid>:<vout>\"\n"
        );

    EnsureAtomicSwapsEnabled(fHelp);
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    LOCK(cs_main);

    std::string swapId = params[0].get_str();
    CAtomicSwapInfo swapInfo;
    if (!pwalletMain->GetAtomicSwap(swapId, swapInfo)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Swap not found: " + swapId);
    }
    const AtomicSwapContract& contract = swapInfo.contract;

    // Authoritative status comes from chain, not the stored hint.
    SwapResolution res = ResolveSwapStatus(swapInfo);
    const bool isOpen = (res.status == SWAPCHAIN_OPEN);

    bool locktimeReached = (contract.lockTime < LOCKTIME_THRESHOLD)
        ? (chainActive.Height() >= contract.lockTime)
        : (GetTime() >= contract.lockTime);

    int64_t timeUntilExpiry = 0;
    bool hasExpired = false;
    if (isOpen) {
        if (contract.lockTime < LOCKTIME_THRESHOLD) {
            int currentHeight = chainActive.Height();
            if (currentHeight >= contract.lockTime) {
                hasExpired = true;
            } else {
                timeUntilExpiry = (contract.lockTime - currentHeight) * 150;
            }
        } else {
            int64_t currentTime = GetTime();
            if (currentTime >= contract.lockTime) {
                hasExpired = true;
            } else {
                timeUntilExpiry = contract.lockTime - currentTime;
            }
        }
    }

    // The initiator should refund an still-open, past-locktime contract.
    // The recipient should claim an open contract while they have the secret.
    bool requiresAction = false;
    if (isOpen && locktimeReached && swapInfo.role == ROLE_INITIATOR) {
        requiresAction = true;
    } else if (isOpen && !locktimeReached && swapInfo.role == ROLE_PARTICIPANT &&
               swapInfo.secretKnown) {
        requiresAction = true;
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("swapId", swapInfo.GetSwapId());
    // status is now the chain-derived value; the wallet's stored
    // status string is reported separately as a hint for debugging.
    result.pushKV("status", SwapChainStatusString(res.status));
    result.pushKV("storedStatusHint", swapInfo.GetStatusString());
    result.pushKV("role", swapInfo.GetRoleString());
    result.pushKV("contractTxid", swapInfo.contractTxid.GetHex());
    result.pushKV("contractVout", (int)swapInfo.contractVout);
    result.pushKV("amount", ValueFromAmount(swapInfo.amount));
    result.pushKV("secretHash", contract.secretHash.GetHex());
    result.pushKV("locktime", contract.lockTime);
    if (contract.lockTime >= LOCKTIME_THRESHOLD) {
        result.pushKV("locktimeFormatted",
                      DateTimeStrFormat("%Y-%m-%d %H:%M:%S UTC", contract.lockTime));
    }
    result.pushKV("locktimeReached", locktimeReached);
    if (isOpen && !hasExpired && timeUntilExpiry > 0) {
        result.pushKV("timeUntilExpiry", HumanReadableDuration(timeUntilExpiry));
        result.pushKV("secondsUntilExpiry", timeUntilExpiry);
    }
    if (res.status == SWAPCHAIN_CLAIMED || res.status == SWAPCHAIN_REFUNDED) {
        result.pushKV("spendTxid", res.spendTxid.GetHex());
        result.pushKV("spendConfirmed", res.spendConfirmed);
        if (res.spendConfirmed) {
            result.pushKV("spendBlockHeight", res.spendHeight);
            result.pushKV("spendStatus", "confirmed");
        } else {
            result.pushKV("spendStatus", "pending in mempool");
        }
        if (res.status == SWAPCHAIN_CLAIMED && !res.secret.empty()) {
            result.pushKV("revealedSecret", HexStr(res.secret.begin(), res.secret.end()));
        }
    } else if (res.status == SWAPCHAIN_UNKNOWN) {
        result.pushKV("note",
            "Contract output is spent but the spending transaction could not "
            "be located. On a pruned node without -txindex, historical "
            "third-party claims/refunds are not resolvable.");
    }
    result.pushKV("isExpired", hasExpired);
    result.pushKV("requiresAction", requiresAction);
    return result;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor                    okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "atomicswap",         "initiateswap",           &initiateswap,           false },
    { "atomicswap",         "initiateswapfromhash",   &initiateswapfromhash,   false },
    { "atomicswap",         "auditswap",              &auditswap,              true  },
    { "atomicswap",         "participateswap",        &participateswap,        false },
    { "atomicswap",         "claimswap",              &claimswap,              false },
    { "atomicswap",         "refundswap",             &refundswap,             false },
    { "atomicswap",         "listatomicswaps",        &listatomicswaps,        true  },
    { "atomicswap",         "getswapsecret",          &getswapsecret,          false },
    { "atomicswap",         "deleteswap",             &deleteswap,             false },
    { "atomicswap",         "monitorswap",            &monitorswap,            true  },
};

void RegisterAtomicSwapRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++) {
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
    }
}
