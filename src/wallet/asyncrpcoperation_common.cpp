// Copyright (c) 2019-2023 The Zcash developers
// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "asyncrpcoperation_common.h"

#include "chainparams.h"
#include "consensus/upgrades.h"
#include "core_io.h"
#include "crypto/pq/scheme.h"
#include "init.h"
#include "main.h"
#include "policy/policy.h"
#include "rpc/protocol.h"
#include "rpc/server.h"
#include "script/sign.h"
#include "script/standard.h"
#include "util/moneystr.h"
#include "zip317.h"

extern UniValue signrawtransaction(const UniValue& params, bool fHelp);

// This is only a helper for tests.
std::pair<CTransaction, UniValue> SignSendRawTransaction(UniValue obj, std::optional<std::reference_wrapper<CReserveKey>> reservekey, bool testmode) {
    // Sign the raw transaction
    UniValue rawtxnValue = find_value(obj, "rawtxn");
    if (rawtxnValue.isNull()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Missing hex data for raw transaction");
    }
    std::string rawtxn = rawtxnValue.get_str();

    UniValue params = UniValue(UniValue::VARR);
    params.push_back(rawtxn);
    UniValue signResultValue = signrawtransaction(params, false);
    UniValue signResultObject = signResultValue.get_obj();
    UniValue completeValue = find_value(signResultObject, "complete");
    bool complete = completeValue.get_bool();
    if (!complete) {
        // TODO: #1366 Maybe get "errors" and print array vErrors into a string
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Failed to sign transaction");
    }

    UniValue hexValue = find_value(signResultObject, "hex");
    if (hexValue.isNull()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Missing hex data for signed transaction");
    }
    std::string signedtxn = hexValue.get_str();
    CDataStream stream(ParseHex(signedtxn), SER_NETWORK, PROTOCOL_VERSION);
    CTransaction tx;
    stream >> tx;

    // Recipient mappings are not available when sending a raw transaction.
    std::vector<RecipientMapping> recipientMappings;
    UniValue sendResult = SendTransaction(tx, recipientMappings, reservekey, testmode);

    return std::make_pair(tx, sendResult);
}

void ThrowInputSelectionError(
        const InputSelectionError& err,
        const ZTXOSelector& selector,
        const TransactionStrategy& strategy)
{
    examine(err, match {
        [&](const AddressResolutionError& err) {
            switch (err) {
                case AddressResolutionError::SproutRecipientsNotSupported:
                    throw JSONRPCError(
                        RPC_INVALID_PARAMETER,
                        "Sending funds into the Sprout pool is no longer supported.");
                case AddressResolutionError::TransparentRecipientNotAllowed:
                    throw JSONRPCError(
                        RPC_INVALID_PARAMETER,
                        "This transaction would have transparent recipients, which is not "
                        "enabled by default because it will publicly reveal transaction "
                        "recipients and amounts. THIS MAY AFFECT YOUR PRIVACY. Resubmit "
                        "with the `privacyPolicy` parameter set to `AllowRevealedRecipients` "
                        "or weaker if you wish to allow this transaction to proceed anyway.");
                case AddressResolutionError::TransparentChangeNotAllowed:
                    throw JSONRPCError(
                        RPC_INVALID_PARAMETER,
                        "This transaction would have transparent change, which is not "
                        "enabled by default because it will publicly reveal the change "
                        "address and amounts. THIS MAY AFFECT YOUR PRIVACY. Resubmit "
                        "with the `privacyPolicy` parameter set to `AllowRevealedRecipients` "
                        "or weaker if you wish to allow this transaction to proceed anyway.");
                case AddressResolutionError::RevealingSaplingAmountNotAllowed:
                    throw JSONRPCError(
                        RPC_INVALID_PARAMETER,
                        "Could not send to the Sapling shielded pool without spending non-Sapling "
                        "funds, which would reveal transaction amounts. THIS MAY AFFECT YOUR "
                        "PRIVACY. Resubmit with the `privacyPolicy` parameter set to "
                        "`AllowRevealedAmounts` or weaker if you wish to allow this transaction to "
                        "proceed anyway.");
                case AddressResolutionError::CouldNotResolveReceiver:
                    throw JSONRPCError(
                        RPC_INVALID_PARAMETER,
                        strprintf("Could not send to an Orchard-only receiver %s.",
                                  strategy.AllowRevealedAmounts()
                                  ? strprintf("despite a lax privacy policy, because %s",
                                              selector.SelectsSprout()
                                              ? "you are sending from the Sprout pool and there is "
                                                "no transaction version that supports both Sprout "
                                                "and Orchard"
                                              : "NU5 has not been activated yet")
                                  : "without spending non-Orchard funds, which would reveal "
                                    "transaction amounts. THIS MAY AFFECT YOUR PRIVACY. Resubmit "
                                    "with the `privacyPolicy` parameter set to "
                                    "`AllowRevealedAmounts` or weaker if you wish to allow this "
                                    "transaction to proceed anyway"));
                case AddressResolutionError::TransparentReceiverNotAllowed:
                    throw JSONRPCError(
                        RPC_INVALID_PARAMETER,
                        "This transaction would send to a transparent receiver of a unified "
                        "address, which is not enabled by default because it will publicly reveal "
                        "transaction recipients and amounts. THIS MAY AFFECT YOUR PRIVACY. "
                        "Resubmit with the `privacyPolicy` parameter set to "
                        "`AllowRevealedRecipients` or weaker if you wish to allow this transaction "
                        "to proceed anyway.");
                case AddressResolutionError::RevealingReceiverAmountsNotAllowed:
                    throw JSONRPCError(
                        RPC_INVALID_PARAMETER,
                        "Could not send to a shielded receiver of a unified address without "
                        "spending funds from a different pool, which would reveal transaction "
                        "amounts. THIS MAY AFFECT YOUR PRIVACY. Resubmit with the `privacyPolicy` "
                        "parameter set to `AllowRevealedAmounts` or weaker if you wish to allow "
                        "this transaction to proceed anyway.");
                default:
                    assert(false);
            }
        },
        [&](const InvalidFundsError& err) {
            bool suggestLinkingAddresses =
                !strategy.AllowLinkingAccountAddresses()
                && examine(selector.GetPattern(), match {
                    [](const libzcash::UnifiedAddress&) { return true; },
                    [](const AccountZTXOPattern&) { return true; },
                    [](const auto&) { return false; },
                });
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf(
                    "Insufficient funds: have %s, %s",
                    FormatMoney(err.available),
                    examine(err.reason, match {
                        [](const PhantomChangeError& qce) {
                            return strprintf(
                                    "need %s more to surpass the dust threshold and avoid being "
                                    "forced to over-pay the fee. Alternatively, you could specify "
                                    "a fee of %s to allow overpayment of the conventional fee and "
                                    "have this transaction proceed.",
                                    FormatMoney(qce.dustThreshold),
                                    FormatMoney(qce.finalFee));
                        },
                        [](const InsufficientFundsError& ife) {
                            return strprintf("need %s", FormatMoney(ife.required));
                        },
                        // TODO: Add the fee here, so we can suggest specifying an explicit fee (see
                        //       `PhantomChangeError`).
                        [](const DustThresholdError& dte) {
                            return strprintf(
                                    "need %s more to avoid creating invalid change output %s (dust threshold is %s)",
                                    FormatMoney(dte.dustThreshold - dte.changeAmount),
                                    FormatMoney(dte.changeAmount),
                                    FormatMoney(dte.dustThreshold));
                        }
                    }))
                    + (selector.TransparentCoinbasePolicy() == TransparentCoinbasePolicy::Disallow
                       ? "; note that coinbase outputs will not be selected if you specify "
                         "ANY_TADDR, any transparent recipients are included, or if the "
                         "`privacyPolicy` parameter is not set to `AllowRevealedSenders` or weaker"
                       : "")
                    + (suggestLinkingAddresses
                       ? ". (This transaction may require selecting transparent coins that were sent "
                         "to multiple addresses, which is not enabled by default because it would "
                         "create a public link between those addresses. THIS MAY AFFECT YOUR PRIVACY. "
                         "Resubmit with the `privacyPolicy` parameter set to "
                         "`AllowLinkingAccountAddresses` or weaker if you wish to allow this "
                         "transaction to proceed anyway.)"
                       : "."));
        },
        [](const ChangeNotAllowedError& err) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                strprintf(
                    "When shielding coinbase funds, the wallet does not allow any change. "
                    "The proposed transaction would result in %s in change.",
                    FormatMoney(err.available - err.required)));
        },
        [](const InvalidFeeError& err) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf(
                    "The provided fee, %s, is invalid. Fees must be non-negative, and no greater "
                    "than the total amount of YEC that will ever be available.",
                    DisplayMoney(err.fixedFee),
                    DisplayMoney(MAX_MONEY)));
        },
        [](const AbsurdFeeError& err) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf(
                    "Fee %s is greater than %d times the conventional fee for this tx (which is "
                    "%s). There is no prioritisation benefit to a fee this large (see "
                    "https://zips.z.cash/zip-0317#recommended-algorithm-for-block-template-construction), "
                    "and it likely indicates a mistake in setting the fee.",
                    FormatMoney(err.fixedFee),
                    WEIGHT_RATIO_CAP,
                    FormatMoney(err.conventionalFee)));
        },
        [](const MaxFeeError& err) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf(
                    "Fee (%s) is greater than the maximum fee allowed by this instance (%s). Run "
                    "ycashd with `-maxtxfee` to adjust this limit.",
                    DisplayMoney(err.fixedFee),
                    DisplayMoney(maxTxFee)));
        },
        [](const ExcessOrchardActionsError& err) {
            std::string side;
            switch (err.side) {
                case ActionSide::Input:
                    side = "inputs";
                    break;
                case ActionSide::Output:
                    side = "outputs";
                    break;
                case ActionSide::Both:
                    side = "actions";
                    break;
            };
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf(
                    "Including %u Orchard %s would exceed the current limit "
                    "of %u notes, which exists to prevent memory exhaustion. Restart with "
                    "`-orchardactionlimit=N` where N >= %u to allow the wallet to attempt "
                    "to construct this transaction.",
                    err.orchardNotes,
                    side,
                    err.maxNotes,
                    err.orchardNotes));
        }
    });
}

bool IsPQKeyScript(const CScript& scriptPubKey)
{
    txnouttype type;
    std::vector<std::vector<unsigned char>> vSolutions;
    return Solver(scriptPubKey, type, vSolutions) && type == TX_PQPKH;
}

CTransaction PQFeeShape(int nHeight, const std::vector<std::pair<CScript, CAmount>>& tIns,
                        const std::vector<CTxOut>& tOuts, size_t saplingSpends, size_t saplingOutputs)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(pwalletMain->cs_wallet);
    const Consensus::Params& consensus = Params().GetConsensus();
    // A vault-era transaction is v4 (the Vault upgrade is v4-only), as TransactionBuilder makes it.
    CMutableTransaction mtx = CreateNewContextualCMutableTransaction(consensus, nHeight, true);
    const uint32_t branchId = CurrentEpochBranchId(nHeight, consensus);
    const unsigned int flags = STANDARD_SCRIPT_VERIFY_FLAGS | GetVaultScriptFlags(nHeight, consensus);
    mtx.vin.resize(tIns.size());
    for (size_t i = 0; i < tIns.size(); i++) {
        SignatureData sigdata;
        if (!ProduceSignature(DummySignatureCreator(pwalletMain), tIns[i].first, sigdata, branchId, flags))
            throw JSONRPCError(RPC_WALLET_ERROR, "Cannot size a transparent input of this transaction");
        UpdateTransaction(mtx, i, sigdata);
    }
    mtx.vout = tOuts;
    if (saplingSpends > 0 || saplingOutputs > 0) {
        mtx.saplingBundle = sapling::test_only_invalid_bundle(saplingSpends, saplingOutputs, 0);
    }
    return CTransaction(mtx);
}

CAmount PQBuilderFee(CAmount base, const CTransaction& tx)
{
    const size_t nBytes = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
    return std::max(std::min(std::max(base, PQSizeFee(LEGACY_DEFAULT_FEE, nBytes)), PQMaxTxFee()),
                    tx.GetConventionalFee());
}

unsigned int PolicySigOps(const CTransaction& shape, const std::vector<CScript>& prevScripts)
{
    assert(prevScripts.size() == shape.vin.size());
    unsigned int n = GetLegacySigOpCount(shape);
    for (size_t i = 0; i < shape.vin.size(); i++) {
        if (prevScripts[i].IsPayToScriptHash())
            n += prevScripts[i].GetSigOpCount(shape.vin[i].scriptSig);
        n += GetPQSigOpCount(prevScripts[i]);
    }
    return n;
}

void EnsurePQShapeStandard(const CTransaction& shape, const std::vector<CScript>& prevScripts, size_t nPQInputs)
{
    if (nPQInputs > MAX_PQ_INPUTS_PER_TX) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf(
            "This send needs %d post-quantum inputs, more than the %d one transaction may carry; "
            "combine the address's coins first with z_mergetoaddress", nPQInputs, MAX_PQ_INPUTS_PER_TX));
    }
    const unsigned int sigops = PolicySigOps(shape, prevScripts);
    if (sigops > MAX_STANDARD_TX_SIGOPS) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf(
            "This transaction needs %u signature operations, more than the %u a standard transaction allows; "
            "spend fewer inputs", sigops, MAX_STANDARD_TX_SIGOPS));
    }
}

static void CheckPQInputsStillValid(const std::vector<PQBuilderInput>& ins, uint32_t branchId, unsigned int vaultFlags)
{
    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureWalletIsUnlocked();
    const Consensus::Params& consensus = Params().GetConsensus();
    const int next = chainActive.Height() + 1;
    if (CurrentEpochBranchId(next, consensus) != branchId || GetVaultScriptFlags(next, consensus) != vaultFlags) {
        throw JSONRPCError(RPC_WALLET_ERROR,
            "The next block's rules changed while this transaction was built (a reorg or a network upgrade); send it again");
    }
    for (const PQBuilderInput& in : ins) {
        if (pwalletMain->IsSpent(in.outpoint.hash, in.outpoint.n, std::nullopt)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "A post-quantum input was spent while this transaction was built; send it again");
        }
    }
}

void SignPQBuilderInputs(CMutableTransaction& mtx, const std::vector<PQBuilderInput>& ins,
                         const std::vector<CTxOut>& spentOutputs, int nHeight)
{
    if (ins.empty()) return;
    AssertLockNotHeld(cs_main);
    AssertLockNotHeld(pwalletMain->cs_wallet);
    const Consensus::Params& consensus = Params().GetConsensus();
    const uint32_t branchId = CurrentEpochBranchId(nHeight, consensus);
    const unsigned int vaultFlags = GetVaultScriptFlags(nHeight, consensus);
    const unsigned int flags = STANDARD_SCRIPT_VERIFY_FLAGS | vaultFlags;
    if (spentOutputs.size() != mtx.vin.size())
        throw JSONRPCError(RPC_WALLET_ERROR, "Post-quantum input does not match the built transaction");

    CheckPQInputsStillValid(ins, branchId, vaultFlags);
    // No global lock from here: the key comes from the keystore under cs_KeyStore, the signature is made and
    // verified (ProduceSignature) with nothing else held.
    const CTransaction txConst(mtx);
    const PrecomputedTransactionData txdata(txConst, spentOutputs);
    for (const PQBuilderInput& in : ins) {
        if (in.nIn >= mtx.vin.size() || mtx.vin[in.nIn].prevout != in.outpoint || !IsPQKeyScript(in.scriptPubKey) ||
            spentOutputs[in.nIn].scriptPubKey != in.scriptPubKey || spentOutputs[in.nIn].nValue != in.value)
            throw JSONRPCError(RPC_WALLET_ERROR, "Post-quantum input does not match the built transaction");
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(pwalletMain, &txConst, txdata, in.nIn, in.value, SIGHASH_ALL),
                              in.scriptPubKey, sigdata, branchId, flags))
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign a post-quantum input");
        UpdateTransaction(mtx, in.nIn, sigdata);
    }
    CheckPQInputsStillValid(ins, branchId, vaultFlags);
}

bool SpendsPQCoin(const SpendableInputs& spendable)
{
    return std::any_of(spendable.utxos.begin(), spendable.utxos.end(), [](const COutput& o) {
        return IsPQKeyScript(o.tx->vout[o.i].scriptPubKey);
    });
}

void EnsurePQFeeWithinCap(CAmount fee)
{
    const CAmount cap = PQMaxTxFee();
    if (fee > cap) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
            "Fee %s is above the %s cap on a post-quantum spend (-maxtxfee, or $2 at the attested price, at most -yellowbackmaxtxfee)",
            FormatMoney(fee), FormatMoney(cap)));
    }
}

std::string EraseRefusedPQSend(CWallet& wallet, const uint256& txid)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(wallet.cs_wallet);
    if (!wallet.mapWallet.count(txid)) return "";
    if (mempool.exists(txid)) {
        // Accepted after all (relay follows acceptance): never erase a transaction that may already be relayed.
        LogPrintf("SendPQTransaction: %s is in the mempool although its commit reported an error; kept\n", txid.ToString());
        return strprintf("Transaction %s is in the mempool although its commit reported an error; it is kept in the "
                         "wallet and will be relayed: do not send it again", txid.GetHex());
    }
    LogPrintf("SendPQTransaction: erasing %s, recorded by CommitTransaction and refused by the mempool\n", txid.ToString());
    // Review H-1: the shared erase drops every index naming the transaction (its spends above all), not only the
    // mapWallet entry, so that sending again from the same coins in this process is safe.
    if (!wallet.EraseUnbroadcastTx(txid)) {
        // Kept in mapWallet too, so the wallet shows what its file holds (and a restart would submit).
        LogPrintf("ERROR: SendPQTransaction: could not erase %s from the wallet file\n", txid.ToString());
        return strprintf("The mempool refused transaction %s, but it could not be erased from the wallet file: the "
                         "wallet still holds this unbroadcast transaction and may submit it at the next start; check "
                         "it with gettransaction before you send again", txid.GetHex());
    }
    return "";
}

UniValue SendPQTransaction(
        const CTransaction& tx,
        const std::vector<ResolvedPayment>& recipients,
        bool testmode)
{
    if (testmode) return SendTransaction(tx, recipients, std::nullopt, testmode);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    if (std::optional<CAmount> over = YedFeeOverCap(tx)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf(
            "The post-quantum fee cap fell to %s while this transaction was signed, below its fee %s; nothing was sent, send it again",
            FormatMoney(PQMaxTxFee()), FormatMoney(over.value())));
    }
    const uint256 txid = tx.GetHash();
    const bool known = pwalletMain->mapWallet.count(txid) != 0;
    try {
        return SendTransaction(tx, recipients, std::nullopt, testmode);
    } catch (...) {
        // CommitTransaction records the transaction before the mempool judges it; a refused one must not stay at
        // depth -1, where a restart's ReacceptWalletTransactions would submit it (by its own fee rule) after the
        // caller was told it failed and may have sent again.
        if (!known) {
            const std::string kept = EraseRefusedPQSend(*pwalletMain, txid);
            if (!kept.empty()) throw JSONRPCError(RPC_WALLET_ERROR, kept);
        }
        throw;
    }
}

std::string DropYellowbackCoins(std::vector<COutput>& coins, bool strict)
{
    std::vector<COutPoint> candidates;
    for (const COutput& c : coins) candidates.emplace_back(c.tx->GetHash(), c.i);
    std::vector<COutPoint> refused;
    const std::string refusal = YellowbackInputRefusal(candidates, strict, &refused);
    if (refusal.empty()) return "";
    if (refused.empty()) throw JSONRPCError(RPC_WALLET_ERROR, refusal);     // the unhealthy-index refusal
    coins.erase(std::remove_if(coins.begin(), coins.end(), [&](const COutput& c) {
        return std::find(refused.begin(), refused.end(), COutPoint(c.tx->GetHash(), c.i)) != refused.end();
    }), coins.end());
    return refusal;
}

CAmount PQInputMarginalFee(uint8_t scheme)
{
    const size_t n = PQSpendInputSize(scheme);
    return std::max(PlainPQFeeRate().GetFee(n), MARGINAL_FEE * (CAmount)((n + P2PKH_STANDARD_INPUT_SIZE - 1) / P2PKH_STANDARD_INPUT_SIZE));
}
