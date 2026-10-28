// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

/**
 * Yellowback wallet-context RPCs (plan §4.5, §4.6; doc/yellowback-rpc.md is
 * the contract): addresses, balances, mint, send, redeem (incl. the VOID
 * release, L14), claim, positions, history, lock maintenance. (yed_sweep, the
 * L10 abandonment sweep, left with the vault upgrade: upgrade plan §6.)
 * Lock order: cs_main -> cs_wallet -> mempool.cs -> cs_yellowback (§4.3, N25).
 * No RPC here may take mempool.cs after cs_yellowback: CreateNewBlock takes
 * them in that order (TemplateView inside LOCK2(cs_main, mempool.cs)) and so
 * does RemoveInvalidVaultSpends on the ConnectTip path.
 *
 * Every refusal carries a stable identifier as the first token of its
 * message (M8): the builders throw std::runtime_error("<identifier>: …") and
 * ThrowBuildError maps the identifier to RPC_INVALID_PARAMETER (a bad
 * argument), RPC_WALLET_ERROR (funds, locking) or RPC_VERIFY_REJECTED (a rule).
 *
 * K7: yed_mint / yed_redeem / yed_claim run the index's MempoolCheck (the
 * MP-1 predicate) before CommitTransaction, which records the transaction
 * before it tries the mempool (wallet.cpp:5725, 5743) and must therefore
 * never be reached by a transaction MP-1 would refuse.
 */

#include "chainparams.h"
#include "coins.h"
#include "core_io.h"
#include "crypto/pq/scheme.h"
#include "experimental_features.h"
#include "httpserver.h"
#include "init.h"
#include "key_io.h"
#include "main.h"
#include "rpc/protocol.h"
#include "rpc/server.h"
#include "rpc/yellowbackrpc.h"
#include "script/standard.h"
#include "txmempool.h"
#include "vault/act.h"
#include "util/moneystr.h"
#include "util/strencodings.h"
#include "wallet/wallet.h"
#include "yellowback/address.h"
#include "yellowback/attest.h"
#include "yellowback/bundle.h"
#include "yellowback/index.h"
#include "yellowback/math.h"
#include "yellowback/payload.h"
#include "yellowback/policy.h"
#include "yellowback/script.h"
#include "yellowback/state.h"
#include "yellowback/txbuilder.h"
#include "yellowback/wallet.h"

#include <univalue.h>

#include <algorithm>
#include <cstring>
#include <functional>

using namespace yellowback;

void EnsureWalletIsUnlocked();

namespace {

const char* const UNLOCK_ACKNOWLEDGEMENT = "I understand this burns YED";
/** The address-book purpose of a yed_getnewaddress key (N8): what yed_listaddresses includeEmpty lists. */
const char* const YED_RECEIVE_PURPOSE = "yellowback-receive";

YellowbackWallet& EnsureYW()
{
    if (!g_yellowbackLive || !g_yellowback) {
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (Yellowback is not active: the vault upgrade or the YED attestor set is not configured on this network)");
    }
    if (!pwalletMain || !g_yellowbackWallet) throw JSONRPCError(RPC_WALLET_ERROR, "wallet is disabled");
    return *g_yellowbackWallet;
}

void EnsureHealthy(const YellowbackIndex& index)
{
    if (!index.IsHealthy()) {
        throw JSONRPCError(RPC_MISC_ERROR, "yellowback-unhealthy: " + index.UnhealthyReason() + "; restart with -reindex-yellowback");
    }
}

int IndexHeight(const YellowbackIndex& index)
{
    std::optional<TipRecord> tip = index.GetTip();
    return tip.has_value() ? tip->height : -1;
}

bool StartsWith(const std::string& s, const char* prefix)
{
    return s.compare(0, strlen(prefix), prefix) == 0;
}

/** Map a builder failure to the RPC error code its identifier belongs to (doc/yellowback-rpc.md, Error identifiers). */
[[noreturn]] void ThrowBuildError(const std::runtime_error& e)
{
    const std::string msg = e.what();
    static const char* const RULE[] = { "mintpol-", "mint-unsatisfiable", "vault-locked", "claim-not-yet", "claim-not-underwater",
                                        "mempool-check-failed", "intent-", "yed-template-",
                                        // v3 (contract: RPC_VERIFY_REJECTED unless stated), incl. the dry run's verdict strings
                                        "bundle-insufficient", "mint9-", "mint10-", "red1-", "red5-", "afee1-", "notice-standing", "notice-not-underwater",
                                        "bond-below-min", "lock-below-min", "bond-locked", "bond-spent", "not-dormant", "not-equivocation",
                                        "attest-unknown-seq", "attest-key-not-held", "attest-range", "attest-stale", "equivocation-guard",
                                        "carrier-lapsed", "carrier-unconfirmed", "register-refused", "bad-mint-", "vault-spend-", "vault-claim-",
                                        "mint-not-active", "mint-halted-", "mint-supply-cap", "mint-vault-share", "mint-dry-run", nullptr };
    static const char* const PARAM[] = { "mint-bad-lock", "bad-mint-amount", "bad-xfer-amount", "vault-not-found", "vault-not-active",
                                         "vault-not-owned", "not-a-yellowback-address", "bad-address",
                                         "bundle-malformed", "attest-malformed", "carrier-selector", nullptr };
    // collateral-above-max, claim-out-below-min (audit F-1) and claim-burn-above-max (H-9.3) are caller bounds, not rules:
    // RPC_WALLET_ERROR below.
    for (const char* const* p = RULE; *p; p++) if (StartsWith(msg, *p)) throw JSONRPCError(RPC_VERIFY_REJECTED, msg);
    for (const char* const* p = PARAM; *p; p++) if (StartsWith(msg, *p)) throw JSONRPCError(RPC_INVALID_PARAMETER, msg);
    throw JSONRPCError(RPC_WALLET_ERROR, msg);
}

/**
 * Commit a built transaction through the wallet: stage-(i) locks first (§4.6), then
 * YellowbackWallet::Commit (CommitTransaction plus the removal of the blank entries the inherited
 * commit leaves under the ids of inputs this wallet never held -- a claim's vault, a restored
 * attestor's bond; regtest plan F-7).
 */
uint256 Commit(YellowbackWallet& yw, const BuiltTx& built, CReserveKey* reservekey)
{
    yw.LockOwn(built.ownYedOutputs);
    CWalletTx wtx(pwalletMain, CTransaction(built.tx));
    std::optional<std::reference_wrapper<CReserveKey>> rk;
    if (reservekey) rk = std::ref(*reservekey);
    if (!yw.Commit(wtx, rk)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "transaction commit failed: the transaction was rejected by the mempool");
    }
    return wtx.GetHash();
}

/**
 * K7: refuse with `mempool-check-failed:<verdict>` unless the index's MP-1 predicate admits the
 * transaction — MempoolCheckReason, the very predicate AcceptToMemoryPool applies (the expiry
 * bound and RED-1..4 over the one-transaction pseudo-block at tip + 1). cs_main held.
 */
void MempoolGate(YellowbackIndex& index, const CTransaction& tx)
{
    std::optional<std::string> why = index.MempoolCheckReason(tx);
    if (!why.has_value()) return;
    throw JSONRPCError(RPC_VERIFY_REJECTED, "mempool-check-failed:" + why.value() + ": an enforcing miner would refuse this vault spend (MP-1)");
}

/**
 * N1 (cf. DigiByte v9.26.7 00136af6, the pending redemption told apart before coin selection): refuse a second
 * spend of a vault the mempool already holds a spend of, instead of asking for more YED (`insufficient-yed`) or
 * failing the commit as a mempool conflict. mempool.cs held.
 */
std::string VaultSpendPendingError(const COutPoint& vault)
{
    const std::optional<uint256> spender = MempoolSpenderOf(vault);
    if (!spender.has_value()) return "";
    return strprintf("vault-spend-pending: the vault %s already has a spend in the mempool (%s); wait for it to confirm or expire",
                     vault.ToString(), spender->GetHex());
}

void RefuseVaultSpendPending(const COutPoint& vault)
{
    const std::string error = VaultSpendPendingError(vault);
    if (!error.empty()) throw JSONRPCError(RPC_WALLET_ERROR, error);
}

CScript ParseYedAddress(const std::string& s, const yellowback::Params& params)
{
    // Either form (quantum spec §4): a 35-character P2PKH yb… or a 53-character post-quantum yb… (TX_PQPKH).
    CTxDestination dest;
    if (!DecodeAddress(s, params, dest)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "not-a-yellowback-address: expected a Yellowback address of this network (prefix '" + EncodeAddress(CKeyID(), params).substr(0, 2) + "')");
    }
    return GetScriptForDestination(dest);
}

std::string ScriptToYedAddress(const CScript& s, const yellowback::Params& params)
{
    const std::optional<CTxDestination> dest = HolderKey(s);       // P2PKH or TX_PQPKH (quantum plan §4.4)
    if (!dest.has_value()) return "";
    if (const CKeyID* id = std::get_if<CKeyID>(&dest.value())) return EncodeAddress(*id, params);
    if (const CPQKeyID* pq = std::get_if<CPQKeyID>(&dest.value())) return EncodeAddress(*pq, params);
    return "";
}

/** A payee key hash as the P2PKH address (s1…/sm…), null when there is none (contract, Conventions). */
UniValue PayeeToJSON(const std::optional<CKeyID>& payee)
{
    if (!payee.has_value()) return NullUniValue;
    KeyIO keyIO(::Params());
    return UniValue(keyIO.EncodeDestination(CTxDestination(payee.value())));
}

UniValue PayeeToJSON(bool hasPayee, const uint160& payee)
{
    return PayeeToJSON(hasPayee ? std::optional<CKeyID>(CKeyID(payee)) : std::nullopt);
}

std::string ClassName(uint8_t termClass)
{
    return termClass < NUM_CLASSES ? std::string(1, (char)('A' + termClass)) : std::to_string((int)termClass);
}

/** The pClaim below which the vault is underwater: ceil(mintedCents * thresholdBps * COIN / collateralZat); nullopt for a VOID vault. */
std::optional<int64_t> UnderwaterAt(const VaultRecord& v, const yellowback::Params& p)
{
    if (v.mintedCents <= 0 || v.collateralZat <= 0 || v.Status() == VaultStatus::VOIDED) return std::nullopt;
    arith_uint256 rhs = arith_uint256(v.mintedCents) * arith_uint256(p.claimThresholdBps) * arith_uint256(COIN);
    arith_uint256 at = CeilDiv(rhs, arith_uint256(v.collateralZat));
    if (!FitsInt64(at)) return std::nullopt;
    return (int64_t)at.GetLow64();
}

/**
 * The yed_getvault row (contract): the Vaults record plus claimable / underwaterAt.
 * Mirrors VaultToJSON in rpc/yellowback.cpp (Phase 3) field for field; `claimable` is the
 * caller's EstimateClaim verdict (RED-4 by either clause), as VaultToJSON reads it.
 */
UniValue VaultRow(const COutPoint& out, const VaultRecord& v, const yellowback::Params& p, bool claimable, int64_t nextHeight)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("txid", out.hash.GetHex());
    o.pushKV("vout", (int64_t)out.n);
    o.pushKV("status", VaultStatusName(v.Status()));
    // rpcversion 7 (quantum spec §6.2): the post-quantum owner as scheme and key hash (the bytes the V pushes);
    // ownerPubKey and ownerKeyId are gone (no public key is on chain).
    const CPQKeyID owner = v.Owner();
    o.pushKV("ownerScheme", (int)owner.scheme);
    o.pushKV("ownerHash", HexStr(owner.hash.begin(), owner.hash.end()));
    o.pushKV("ownerAddress", EncodeAddress(owner, p));        // the PQ owner's address ("" when unregistered)
    o.pushKV("termClass", ClassName(v.termClass));
    o.pushKV("lockHeight", (int64_t)v.lockHeight);
    o.pushKV("claimHeight", (int64_t)v.claimHeight);
    o.pushKV("collateralZat", v.collateralZat);
    o.pushKV("collateral", ValueFromAmount(v.collateralZat));
    o.pushKV("mintedCents", v.mintedCents);
    o.pushKV("mintHeight", v.mintHeight);
    o.pushKV("refHeight", v.refHeight);
    o.pushKV("feePaidZat", v.feePaidZat);
    o.pushKV("pMint", v.pMint);                                // rpcversion 8 (D-Q-23): the mint price every fee of this vault converts at
    o.pushKV("closeHeight", v.IsOpen() ? NullUniValue : UniValue(v.closeHeight));
    o.pushKV("closingTxid", v.IsOpen() ? "" : v.closingTxid.GetHex());
    o.pushKV("burnedCents", v.burnedCents);
    o.pushKV("unbacked", v.unbacked);
    // the cancel-limit design (CAN-2), as yed_getvault: recent cancels, the co-signers a cancel at nextHeight needs, the quiet end
    o.pushKV("cancelCount", (int)v.cancelCount);
    o.pushKV("cancelsRequired", CancelsRequired(v, p, nextHeight));
    o.pushKV("cancelQuietUntil", v.lastCancelHeight > 0 ? UniValue((int64_t)v.lastCancelHeight + p.cancelQuiet) : NullUniValue);
    o.pushKV("claimable", claimable);
    std::optional<int64_t> at = UnderwaterAt(v, p);
    o.pushKV("underwaterAt", at.has_value() ? UniValue(at.value()) : NullUniValue);
    o.pushKV("voidReason", v.voidReason);
    const CScript spk = YedVaultScriptAt(p, v.Owner(), v.ownerHeight, v.appHeight);       // U-23: the V template, as minted
    o.pushKV("scriptPubKey", HexStr(spk.begin(), spk.end()));
    return o;
}

/** A CLAIMING vault's claim intents (U-23), as VaultToJSON in rpc/yellowback.cpp lists them under "intents". */
UniValue ClaimIntentsJSON(YellowbackIndex& index, const COutPoint& out, const yellowback::Params& p)
{
    UniValue intents(UniValue::VARR);
    index.View().Iterate(std::string(1, 'I'), [&](const std::string& k, const std::string& raw) {
        IntentRecord ir;
        if (k.size() == 37 && DeserializeRecord(raw, ir) && ir.vault == out) {
            UniValue e(UniValue::VOBJ);
            e.pushKV("txid", keys::OutPointHashOf(k).GetHex());
            e.pushKV("vout", (int64_t)keys::OutPointIndexOf(k));
            e.pushKV("role", ir.Role() == IntentRole::CLAIMANT ? "claimant" : "residual");
            e.pushKV("height", ir.height);
            e.pushKV("releaseHeight", (int64_t)ir.height + p.claimDelay);
            intents.push_back(e);
        }
        return true;
    });
    return intents;
}

/**
 * Build, sign and commit a vault spend (yed_redeem / yed_claim). The Sapling shape
 * releases every lock for the proving step, then re-locks to sign (§4.6). `gate` runs the K7
 * MempoolCheck before CommitTransaction.
 */
BuiltTx RunVaultSpend(YellowbackWallet& yw, std::function<BuiltTx()> build, bool ownerPath, bool gate, uint256& txid)
{
    YellowbackIndex& index = *yw.Index();
    BuiltTx built;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        EnsureWalletIsUnlocked();
        LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
        LOCK(index.cs_yellowback);
        EnsureHealthy(index);
        try {
            built = build();
            if (!built.NeedsProving()) SignVaultSpend(built, *pwalletMain, SignerBranchId(), ownerPath);
        } catch (const std::runtime_error& e) {
            ThrowBuildError(e);
        }
        if (!built.NeedsProving()) {
            if (gate) MempoolGate(index, CTransaction(built.tx));
            txid = Commit(yw, built, nullptr);
            return built;
        }
    }
    // Sapling shape: prove the collateral note with no lock held, then re-lock to sign the vault
    // and YED inputs (scriptSigs are outside the ZIP-243 digest).
    try {
        FinishSapling(built);
    } catch (const std::runtime_error& e) {
        throw JSONRPCError(RPC_WALLET_ERROR, e.what());
    }
    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureWalletIsUnlocked();
    LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
    LOCK(index.cs_yellowback);
    EnsureHealthy(index);
    try {
        SignVaultSpend(built, *pwalletMain, SignerBranchId(), ownerPath);
    } catch (const std::runtime_error& e) {
        ThrowBuildError(e);
    }
    if (gate) MempoolGate(index, CTransaction(built.tx));
    txid = Commit(yw, built, nullptr);
    return built;
}

UniValue SpendResult(const uint256& txid, const BuiltTx& built)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("txid", txid.GetHex());
    // H4: burnedCents stays the vault's debt; the sub-dollar remainder is reported beside it
    // (the transaction burns burnedCents + extraBurnCents, which RED-2 allows: burn >= debt).
    o.pushKV("burnedCents", built.burnCents - built.extraBurnCents);
    o.pushKV("feeZat", built.feeZat);
    o.pushKV("earlyRedeemFeeZat", built.earlyRedeemFeeZat);   // IT-9: the part of feeZat a redeem before lockHeight adds
    o.pushKV("payee", PayeeToJSON(built.payee));
    o.pushKV("collateralOut", built.collateralOut);
    o.pushKV("to", built.collateralTo);
    o.pushKV("extraBurnCents", built.extraBurnCents);   // H4: 0 unless the selector had to burn a sub-dollar remainder
    return o;
}

/**
 * IT-9: what an owner redeem of `v` confirming at tip + 1 (the earliest block it can reach, the builder's
 * reading) pays on top of FEE-1, and the FEE-1 payee it would pay it to. 0 for a vault that is not ACTIVE, at
 * or past lockHeight, for a class without a fee, and under FEE-0 (no eligible payee: the rule charges neither).
 */
CAmount EarlyRedeemFeeAt(const YellowbackIndex& index, const COutPoint& out, const VaultRecord& v, int tip, std::optional<CKeyID>& payee)
{
    const yellowback::Params& p = index.GetParams();
    payee = DefaultPayee(index.View(), p, tip, OutPointSelector(out), index.GetPayeePolicy());
    if (v.Status() != VaultStatus::ACTIVE || !payee.has_value() || !p.IsValidClass(v.termClass)) return 0;
    if ((int64_t)tip + 1 >= (int64_t)v.lockHeight) return 0;
    return EarlyRedeemFeeZat(v.mintedCents, p.earlyRedeemFeeBps[v.termClass], v.pMint);   // IT-9': of the debt at the mint price
}

// ---------------------------------------------------------------- v3: the two-step flow (W7), shared pieces

UniValue PriceOrNull(const std::optional<MicroUsd>& p) { return p.has_value() ? UniValue(p.value()) : NullUniValue; }

UniValue SeqsToJSON(const std::vector<uint16_t>& seqs)
{
    UniValue arr(UniValue::VARR);
    for (uint16_t q : seqs) arr.push_back((int)q);
    return arr;
}

/** bundleHex: absent / null / "" => nullopt (the pool path); else the bytes (`bundle-malformed` for bad hex). */
std::optional<std::vector<unsigned char>> ParseBundleArg(const UniValue& params, size_t idx)
{
    if (params.size() <= idx || params[idx].isNull()) return std::nullopt;
    const std::string hex = params[idx].get_str();
    if (hex.empty()) return std::nullopt;
    if (!IsHex(hex)) throw JSONRPCError(RPC_INVALID_PARAMETER, "bundle-malformed: bundleHex is not hex");
    return ParseHex(hex);
}

bool ParseWaitArg(const UniValue& params, size_t idx)
{
    if (params.size() <= idx || params[idx].isNull()) return true;
    if (params[idx].isBool()) return params[idx].get_bool();
    if (params[idx].isStr()) return params[idx].get_str() != "false" && params[idx].get_str() != "0";
    return params[idx].get_int() != 0;
}

/** An optional zatoshi bound (audit F-1): absent / null => 0 (none); else an integer in [0, MAX_MONEY]. */
CAmount ParseZatBoundArg(const UniValue& params, size_t idx, const char* name)
{
    if (params.size() <= idx || params[idx].isNull()) return 0;
    if (!params[idx].isNum()) throw JSONRPCError(RPC_INVALID_PARAMETER, std::string(name) + " must be a number (zatoshi)");
    const int64_t v = params[idx].get_int64();
    if (v < 0 || v > MAX_MONEY) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be between 0 and %d", name, MAX_MONEY));
    return v;
}

/** An optional cents bound (hardening H-9.3): absent / null => 0 (none); else an integer in [0, MAX_MONEY]. */
int64_t ParseCentsBoundArg(const UniValue& params, size_t idx, const char* name)
{
    if (params.size() <= idx || params[idx].isNull()) return 0;
    if (!params[idx].isNum()) throw JSONRPCError(RPC_INVALID_PARAMETER, std::string(name) + " must be a number (cents)");
    const int64_t v = params[idx].get_int64();
    if (v < 0 || v > MAX_MONEY) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be between 0 and %d", name, MAX_MONEY));
    return v;
}

Attestation ParseAttestationArg(const UniValue& v, const char* what)
{
    if (!v.isStr() || !IsHex(v.get_str())) throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("attest-malformed: ") + what + " is not 74 bytes of hex");
    std::optional<Attestation> a = DecodeAttestation(ParseHex(v.get_str()));
    if (!a.has_value()) throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("attest-malformed: ") + what + " is not 74 bytes of hex");
    return a.value();
}

/**
 * N3 (cf. DigiByte v9.26.7 38895edb, a mint saved before it is sent): the carrier record goes to carriers.dat before
 * the carrier is committed, so a carrier that reaches the network can always be swept back; `carrier-record-failed`
 * when the file cannot be written (nothing is sent), and the record is dropped again when the commit fails.
 */
void CommitCarrier(YellowbackWallet& yw, const BuiltTx& built, CReserveKey& reservekey)
{
    std::string error;
    if (!yw.CommitWithCarrierRecord(built.carrier.value(), [&]() { Commit(yw, built, &reservekey); return true; }, error)) {
        throw JSONRPCError(RPC_WALLET_ERROR, error);
    }
}

/** The carrier step: build, (prove,) persist the carrier record, then commit; returns its record. */
CarrierRecord CarrierStep(YellowbackWallet& yw, const std::vector<unsigned char>& bundle, int refHeight,
                          const std::vector<unsigned char>& selector, const std::string& from)
{
    YellowbackIndex& index = *yw.Index();
    CReserveKey reservekey(pwalletMain);
    BuiltTx built;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        EnsureWalletIsUnlocked();
        LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
        LOCK(index.cs_yellowback);
        EnsureHealthy(index);
        try {
            built = BuildCarrier(yw, bundle, refHeight, selector, reservekey, from);
        } catch (const std::runtime_error& e) {
            ThrowBuildError(e);
        }
        if (!built.NeedsProving()) {
            CommitCarrier(yw, built, reservekey);
            return built.carrier.value();
        }
    }
    try {
        FinishSapling(built);
    } catch (const std::runtime_error& e) {
        throw JSONRPCError(RPC_WALLET_ERROR, e.what());
    }
    LOCK2(cs_main, pwalletMain->cs_wallet);
    CommitCarrier(yw, built, reservekey);
    return built.carrier.value();
}

/**
 * Is the carrier a confirmed unspent coin that the wallet, too, has seen in a block? Both are
 * needed: the block connects before the notifier thread tells the wallet, and until then the
 * carrier's own funding input still looks unspent to AvailableCoins (its spender has depth -1).
 * A carrier funded from a Sapling address also needs its change note witnessed: the notifier
 * syncs the block's transactions (depth 1) before ChainTip increments the witnesses, and the
 * main transaction spends that note (6.20.0 widens the window between the two; mapping §19).
 */
bool CarrierConfirmed(const COutPoint& out)
{
    LOCK2(cs_main, pwalletMain->cs_wallet);
    const CCoins* c = pcoinsTip->AccessCoins(out.hash);
    if (!(c && c->IsAvailable(out.n))) return false;
    std::map<uint256, CWalletTx>::const_iterator it = pwalletMain->mapWallet.find(out.hash);
    if (it == pwalletMain->mapWallet.end()) return true;
    if (it->second.GetDepthInMainChain(std::nullopt) < 1) return false;
    for (const auto& nd : it->second.mapSaplingNoteData) {
        if (nd.second.witnesses.empty()) return false;
    }
    return true;
}

/**
 * Audit C-2: a wait=true call holds its HTTP worker for up to -yellowbackcarriertimeout seconds,
 * so at most half of -rpcthreads (at least one) may wait at once; the slot is taken BEFORE the
 * carrier is built, so a refusal (`carrier-wait-busy`) costs nothing and leaves nothing outstanding.
 */
int g_carrierWaiters = 0;
CCriticalSection cs_carrierWaiters;

struct CarrierWaitSlot
{
    bool held;
    explicit CarrierWaitSlot(bool wait) : held(false)
    {
        if (!wait) return;
        const int cap = std::max<int>(1, (int)GetArg("-rpcthreads", DEFAULT_HTTP_THREADS) / 2);
        LOCK(cs_carrierWaiters);
        if (g_carrierWaiters >= cap) {
            throw JSONRPCError(RPC_WALLET_ERROR, strprintf("carrier-wait-busy: %d wait=true calls are already waiting for a carrier (the limit is half of -rpcthreads); retry, or pass wait=false", g_carrierWaiters));
        }
        g_carrierWaiters++;
        held = true;
    }
    ~CarrierWaitSlot()
    {
        if (!held) return;
        LOCK(cs_carrierWaiters);
        g_carrierWaiters--;
    }
};

/** wait=true: block, releasing every lock, until the carrier confirms (-yellowbackcarriertimeout seconds, default 600, at most 3600). */
void WaitForCarrier(const CarrierRecord& c)
{
    const int64_t timeoutMs = std::min<int64_t>(3600, std::max<int64_t>(1, GetArg("-yellowbackcarriertimeout", 600))) * 1000;
    const int64_t start = GetTimeMillis();
    while (!CarrierConfirmed(c.outpoint)) {
        if (ShutdownRequested()) throw JSONRPCError(RPC_WALLET_ERROR, "carrier-wait-aborted: shutting down; the carrier " + c.outpoint.ToString() + " stays outstanding (yed_sweepcarriers)");
        if (GetTimeMillis() - start > timeoutMs) {
            throw JSONRPCError(RPC_WALLET_ERROR, strprintf("carrier-timeout: the carrier %s did not confirm within %d s; it stays outstanding and is swept once its window lapses",
                                                            c.outpoint.ToString(), timeoutMs / 1000));
        }
        MilliSleep(200);
    }
}

/** The zero-valued main-transaction fields of a pending two-step result (contract, Conventions). */
void PushPendingCommon(UniValue& o, const CarrierRecord& c, bool pending)
{
    o.pushKV("carrierTxid", c.outpoint.hash.GetHex());
    o.pushKV("pending", pending);
    o.pushKV("refHeight", (int64_t)c.refHeight);
}

/** Complete a MINT on a confirmed carrier: build, sign, dry-run, gate, commit; forget the carrier. */
UniValue CompleteMint(YellowbackWallet& yw, Cents cents, int lockBlocks, const std::string& from, const CarrierRecord& carrier, CAmount maxCollateralZat)
{
    YellowbackIndex& index = *yw.Index();
    BuiltTx built;
    CReserveKey reservekey(pwalletMain);
    uint256 txid;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        EnsureWalletIsUnlocked();
        {
            LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
            LOCK(index.cs_yellowback);
            EnsureHealthy(index);
            try {
                built = BuildMint(yw, cents, lockBlocks, reservekey, from, carrier, maxCollateralZat);
            } catch (const std::runtime_error& e) {
                ThrowBuildError(e);
            }
            if (!built.NeedsProving()) MempoolGate(index, CTransaction(built.tx));   // K7 (trivially true for a mint)
        }
        if (!built.NeedsProving()) {
            txid = Commit(yw, built, &reservekey);
            yw.SpendCarrier(carrier.outpoint);
        }
    }
    if (built.NeedsProving()) {
        // Sapling shape (§4.6): the spend proofs take seconds; no lock is held while they are made.
        try {
            FinishSapling(built);
        } catch (const std::runtime_error& e) {
            throw JSONRPCError(RPC_WALLET_ERROR, e.what());
        }
        LOCK2(cs_main, pwalletMain->cs_wallet);
        {
            LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
            LOCK(index.cs_yellowback);
            EnsureHealthy(index);
            try {
                SignBuiltInputs(built, *pwalletMain, SignerBranchId());   // the carrier: scriptSigs are outside the ZIP-243 digest
                DryRunBuilt(yw, built);                                    // MINT-1..10 with the bundle
            } catch (const std::runtime_error& e) {
                ThrowBuildError(e);
            }
            MempoolGate(index, CTransaction(built.tx));
        }
        txid = Commit(yw, built, &reservekey);
        yw.SpendCarrier(carrier.outpoint);
    }
    UniValue o(UniValue::VOBJ);
    o.pushKV("txid", txid.GetHex());
    o.pushKV("vault", txid.GetHex() + ":0");
    o.pushKV("ownerAddress", EncodeAddress(built.owner, yw.Index()->GetParams()));   // rpcversion 7: the fresh SLH-DSA owner (quantum spec §6.2)
    o.pushKV("termClass", ClassName((uint8_t)built.termClass));
    o.pushKV("lockHeight", (int64_t)built.lockHeight);
    o.pushKV("claimHeight", (int64_t)built.claimHeight);
    o.pushKV("collateralZat", built.collateralZat);
    o.pushKV("feeZat", built.feeZat);
    o.pushKV("payee", PayeeToJSON(built.payee));
    o.pushKV("fundedFrom", built.fundedFrom);
    o.pushKV("warning", built.warning);
    PushPendingCommon(o, carrier, false);
    o.pushKV("xMint", PriceOrNull(built.xMint));
    o.pushKV("aMint", PriceOrNull(built.aMint));
    o.pushKV("pMint", PriceOrNull(built.pMint));
    o.pushKV("source", built.source);
    o.pushKV("bundleSeqs", SeqsToJSON(built.bundleSeqs));
    o.pushKV("attestFeeZat", built.attestFeeZat);
    o.pushKV("attestPayee", PayeeToJSON(built.attestPayeeKey));
    return o;
}

UniValue ClaimResult(const uint256& txid, const BuiltTx& built, const CarrierRecord& carrier)
{
    UniValue o = SpendResult(txid, built);
    PushPendingCommon(o, carrier, false);
    o.pushKV("xClaim", PriceOrNull(built.xClaim));
    o.pushKV("aClaim", PriceOrNull(built.aClaim));
    o.pushKV("pClaim", PriceOrNull(built.pClaim));
    o.pushKV("pEmerg", built.claimPath == "b" ? PriceOrNull(built.pEmerg) : NullUniValue);
    o.pushKV("claimPath", built.claimPath);
    o.pushKV("bundleSeqs", SeqsToJSON(built.bundleSeqs));
    o.pushKV("attestFeeZat", built.attestFeeZat);
    o.pushKV("attestPayee", PayeeToJSON(built.attestPayeeKey));
    o.pushKV("residualZat", built.residualZat);
    return o;
}

BuiltTx RunVaultSpend(YellowbackWallet& yw, std::function<BuiltTx()> build, bool ownerPath, bool gate, uint256& txid);

UniValue CompleteClaim(YellowbackWallet& yw, const uint256& vaultTxid, const std::string& to, const CarrierRecord& carrier, CAmount minOutZat,
                       int64_t maxBurnCents)
{
    uint256 txid;
    BuiltTx built = RunVaultSpend(yw, [&]() {
        RefuseVaultSpendPending(COutPoint(vaultTxid, 0));   // N1: before coin selection
        return BuildClaim(yw, vaultTxid, to, carrier, minOutZat, maxBurnCents);
    }, false, true, txid);
    yw.SpendCarrier(carrier.outpoint);
    return ClaimResult(txid, built, carrier);
}

/** A carrier-bearing transaction with no Sapling shape (NOTICE, EQUIVOCATION): build under the locks, commit, forget the carrier. */
BuiltTx CompleteSimple(YellowbackWallet& yw, std::function<BuiltTx(CReserveKey&)> build, const CarrierRecord& carrier, uint256& txid)
{
    YellowbackIndex& index = *yw.Index();
    CReserveKey reservekey(pwalletMain);
    BuiltTx built;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureWalletIsUnlocked();
    {
        LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
        LOCK(index.cs_yellowback);
        EnsureHealthy(index);
        try {
            built = build(reservekey);
        } catch (const std::runtime_error& e) {
            ThrowBuildError(e);
        }
    }
    txid = Commit(yw, built, &reservekey);
    yw.SpendCarrier(carrier.outpoint);
    return built;
}

UniValue CompleteNotice(YellowbackWallet& yw, const uint256& vaultTxid, const CarrierRecord& carrier)
{
    uint256 txid;
    BuiltTx built = CompleteSimple(yw, [&](CReserveKey& rk) { return BuildClaimNotice(yw, vaultTxid, rk, carrier); }, carrier, txid);
    UniValue o(UniValue::VOBJ);
    o.pushKV("txid", txid.GetHex());
    PushPendingCommon(o, carrier, false);
    o.pushKV("vault", vaultTxid.GetHex() + ":0");
    o.pushKV("xClaim", PriceOrNull(built.xClaim));
    o.pushKV("aClaim", PriceOrNull(built.aClaim));
    o.pushKV("pEmerg", PriceOrNull(built.pEmerg));
    o.pushKV("bundleSeqs", SeqsToJSON(built.bundleSeqs));
    o.pushKV("emergencyOpenAt", (int64_t)built.emergencyOpenAt);
    return o;
}

UniValue CompleteEquivocation(YellowbackWallet& yw, const Attestation& a, const Attestation& b, const CarrierRecord& carrier)
{
    uint256 txid;
    CompleteSimple(yw, [&](CReserveKey& rk) { return BuildEquivocation(yw, a, b, rk, carrier); }, carrier, txid);
    UniValue o(UniValue::VOBJ);
    o.pushKV("txid", txid.GetHex());
    PushPendingCommon(o, carrier, false);
    o.pushKV("seq", (int)a.seq);
    o.pushKV("citedHeight", (int64_t)a.citedHeight);
    o.pushKV("priceA", (int64_t)a.priceMicroUsd);
    o.pushKV("priceB", (int64_t)b.priceMicroUsd);
    return o;
}

/**
 * wait=false (§4.6): hand the completion to the wallet's completion thread. It runs after every
 * applied block; a lapsed carrier is abandoned to yed_sweepcarriers; any refusal is logged and
 * the carrier likewise left outstanding (the sweep reclaims it once its window lapses).
 */
void SchedulePending(YellowbackWallet& yw, const CarrierRecord& carrier, std::function<UniValue()> complete, const char* what)
{
    yw.AddPendingCompletion(carrier.outpoint, [=]() -> bool {
        int tip;
        {
            LOCK(cs_main);
            tip = chainActive.Height();
        }
        if (carrier.Lapsed(tip)) {
            LogPrintf("yellowback: pending %s on carrier %s lapsed unconfirmed at height %d; yed_sweepcarriers reclaims it\n", what, carrier.outpoint.ToString(), tip);
            return true;
        }
        if (!CarrierConfirmed(carrier.outpoint)) return false;
        try {
            UniValue r = complete();
            LogPrintf("yellowback: pending %s completed on carrier %s: %s\n", what, carrier.outpoint.ToString(), r["txid"].get_str());
        } catch (const UniValue& e) {
            LogPrintf("yellowback: pending %s on carrier %s refused: %s\n", what, carrier.outpoint.ToString(), e.write());
        } catch (const std::exception& e) {
            LogPrintf("yellowback: pending %s on carrier %s failed: %s\n", what, carrier.outpoint.ToString(), e.what());
        }
        return true;
    });
}

} // namespace

UniValue yed_getnewaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw std::runtime_error(
            "yed_getnewaddress ( \"type\" \"label\" )\n\nA fresh Yellowback (YED) address of this wallet. The default follows the holder policy\n"
            "(quantum spec A-13): a P2PKH address from the keypool (added to the address book) until Falcon is active, a\n"
            "post-quantum FN-DSA-512 address (53 characters) once it is.\n"
            "\nArguments:\n"
            "1. \"type\" (string, optional) \"p2pkh\"; \"pq\" (a post-quantum holder key: FN-DSA-512 once Falcon is active,\n"
            "   SLH-DSA-SHA2-128s before); \"pqowner\" (an SLH-DSA-SHA2-128s key, as vault_getnewowner); null or \"\" = the default\n"
            "2. \"label\" (string, optional, default \"\") stored in the wallet's address book with the address (so it travels\n"
            "   with wallet.dat; yed_listaddresses reports it); not for \"pqowner\", whose key stays out of the address book\n");
    YellowbackWallet& yw = EnsureYW();
    LOCK2(cs_main, pwalletMain->cs_wallet);
    const bool falcon = IsPQFalconActive(::Params().GetConsensus(), chainActive.Height() + 1);
    std::string type = params.size() > 0 && !params[0].isNull() ? params[0].get_str() : "";
    if (type.empty()) type = falcon ? "pq" : "p2pkh";
    const std::string label = params.size() > 1 && !params[1].isNull() ? params[1].get_str() : "";
    if (type == "pqowner" && !label.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "a \"pqowner\" key stays out of the address book, so it takes no label");
    if (type == "pq" || type == "pqowner") {
        // PQ keys come from the HD seed (quantum plan §4.6). A holder key ("pq") goes into the address book under
        // its plain-YEC form (sq…, D-Q-20), as a P2PKH holder does, so the YEC its token outputs carry is not taken
        // for change; an owner key ("pqowner") receives no coins and stays out of it.
        EnsureWalletIsUnlocked();
        const uint8_t scheme = type == "pq" && falcon ? pq::SCHEME_FN_DSA_512 : pq::SCHEME_SLH_DSA_SHA2_128S;
        CPQKeyID id;
        if (!pwalletMain->GetNewPQKey(scheme, id)) throw JSONRPCError(RPC_WALLET_ERROR, "cannot derive a post-quantum key (the wallet has no HD seed or is locked)");
        if (type == "pq") pwalletMain->SetAddressBook(id, label, YED_RECEIVE_PURPOSE);
        return EncodeAddress(id, yw.Index()->GetParams());
    }
    if (type != "p2pkh") throw JSONRPCError(RPC_INVALID_PARAMETER, "type must be \"p2pkh\", \"pq\" or \"pqowner\"");
    // 6.20.0: no keypool draw; a fresh HD key, exactly as stock getnewaddress (needs an unlocked wallet).
    EnsureWalletIsUnlocked();
    CPubKey key = pwalletMain->GenerateNewKey(true);
    pwalletMain->SetAddressBook(key.GetID(), label, YED_RECEIVE_PURPOSE);
    return EncodeAddress(key.GetID(), yw.Index()->GetParams());
}

UniValue yed_validateaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "yed_validateaddress \"address\"\n\nDecode a Yellowback address; reports whether it is mine. Never throws for a bad address:\n"
            "isvalid is false and reason is \"not-a-yellowback-address\".\n");
    YellowbackWallet& yw = EnsureYW();
    UniValue o(UniValue::VOBJ);
    CTxDestination dest;
    bool valid = DecodeAddress(params[0].get_str(), yw.Index()->GetParams(), dest);
    o.pushKV("isvalid", valid);
    if (valid) {
        LOCK(pwalletMain->cs_wallet);
        o.pushKV("address", params[0].get_str());
        if (const CKeyID* id = std::get_if<CKeyID>(&dest)) {
            o.pushKV("type", "p2pkh");
            o.pushKV("keyid", id->GetHex());
            o.pushKV("ismine", pwalletMain->HaveKey(*id));
            KeyIO keyIO(::Params());
            o.pushKV("transparentAddress", keyIO.EncodeDestination(*id));
        } else if (const CPQKeyID* pq = std::get_if<CPQKeyID>(&dest)) {
            // quantum spec §4: a 53-character PQ address; keyid is the pqkeyid (scheme || keyHash, 66 hex), and
            // transparentAddress is the plain-YEC PQ form of the same key (sq…/tq…/rq…, D-Q-20).
            std::vector<unsigned char> raw(1, pq->scheme);
            raw.insert(raw.end(), pq->hash.begin(), pq->hash.end());
            o.pushKV("type", "pq");
            o.pushKV("keyid", HexStr(raw));
            o.pushKV("pqscheme", (int)pq->scheme);
            o.pushKV("ismine", pwalletMain->HavePQKey(*pq));
            o.pushKV("transparentAddress", KeyIO(::Params()).EncodeDestination(*pq));
        }
    }
    o.pushKV("reason", valid ? "" : "not-a-yellowback-address");
    return o;
}

UniValue yed_getbalance(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "yed_getbalance\n\nConfirmed YED (from the index) and unconfirmed YED (mempool transactions that would assign YED to this wallet).\n"
            "spendableCents is confirmedCents less the YED this wallet's own unconfirmed transactions already spend: what\n"
            "yed_send, yed_redeem and yed_claim can use now (their change returns in unconfirmedCents).\n"
            "Result: { \"confirmedCents\": n, \"spendableCents\": n, \"unconfirmedCents\": n, \"height\": n }\n");
    YellowbackWallet& yw = EnsureYW();
    YellowbackIndex& index = *yw.Index();
    LOCK2(cs_main, pwalletMain->cs_wallet);
    LOCK(mempool.cs);              // §4.3 lock order: mempool.cs before cs_yellowback
    LOCK(index.cs_yellowback);
    EnsureHealthy(index);
    int64_t confirmed = yw.ConfirmedCents();
    int64_t unconfirmed = 0;
    for (const auto& entry : mempool.mapTx) {
        const CTransaction& tx = entry.GetTx();
        std::optional<FoundPayload> fp = FindPayload(tx);
        if (!fp.has_value()) continue;
        if (fp->payload.type == PayloadType::MINT) {
            if (tx.vout.size() > 1 && yw.IsMineScript(tx.vout[1].scriptPubKey)) unconfirmed += fp->payload.cents;
        } else if (fp->payload.type == PayloadType::TRANSFER || fp->payload.type == PayloadType::REDEEM) {
            for (const Assignment& a : fp->payload.assignments) {
                if (yw.IsMineScript(tx.vout[a.vout].scriptPubKey)) unconfirmed += a.cents;
            }
        }
    }
    UniValue o(UniValue::VOBJ);
    o.pushKV("confirmedCents", confirmed);
    o.pushKV("spendableCents", yw.SpendableCents());   // N2 (cf. DigiByte v9.26.7 75d82a6e): what the selectors can spend now
    o.pushKV("unconfirmedCents", unconfirmed);
    o.pushKV("height", IndexHeight(index));
    return o;
}

UniValue yed_listunspent(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error("yed_listunspent\n\nYED outputs that are mine, with whether each is spent by an unconfirmed transaction and whether it is locked.\n");
    YellowbackWallet& yw = EnsureYW();
    YellowbackIndex& index = *yw.Index();
    LOCK2(cs_main, pwalletMain->cs_wallet);
    LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
    LOCK(index.cs_yellowback);
    EnsureHealthy(index);
    UniValue arr(UniValue::VARR);
    for (const YedCoin& c : yw.AllCoins()) {
        UniValue o(UniValue::VOBJ);
        o.pushKV("txid", c.outpoint.hash.GetHex());
        o.pushKV("vout", (int64_t)c.outpoint.n);
        o.pushKV("cents", c.token.cents);
        o.pushKV("valueZat", c.token.nValue);
        o.pushKV("address", ScriptToYedAddress(c.token.scriptPubKey, index.GetParams()));
        o.pushKV("height", c.token.height);
        o.pushKV("confirmations", IndexHeight(index) - c.token.height + 1);
        o.pushKV("spentUnconfirmed", pwalletMain->IsSpent(c.outpoint.hash, c.outpoint.n, std::nullopt));
        o.pushKV("locked", pwalletMain->IsLockedCoin(c.outpoint.hash, c.outpoint.n));
        arr.push_back(o);
    }
    return arr;
}

UniValue yed_mint(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 6)
        throw std::runtime_error(
            "yed_mint cents lockBlocks ( \"from\" \"bundleHex\" wait maxCollateralZat )\n"
            "\nMint YED: locks the required YEC collateral in a vault for lockBlocks blocks (the term class follows) and creates the YED.\n"
            "The collateral requirement, the enforcement fee and its payee are fixed at the reference height (index tip minus the\n"
            "mint lag) and known before signing. Back up wallet.dat afterwards: the vault owner is a fresh post-quantum (SLH-DSA)\n"
            "wallet key (quantum plan §4.3), the YED goes to a fresh holder key (P2PKH; a Falcon key from the Falcon height).\n"
            "v3 (W7): two transactions — the carrier funding transaction first (carrierTxid; its redeem script commits to the\n"
            "attestation bundle), then the MINT after one confirmation, spending the carrier as its last input. Before commit the\n"
            "wallet dry-runs MINT-1..10 with the bundle and refuses naming the rule.\n"
            "\nArguments:\n"
            "1. cents       (numeric, required) amount of YED to mint, in cents\n"
            "2. lockBlocks  (numeric, required) lock length in blocks (class A, B or C by range)\n"
            "3. \"from\"      (string, optional) fund the collateral from this address: an s1... address (its confirmed\n"
            "               outputs only) or a ys1... address (its Sapling notes, spent in the same transaction; the change\n"
            "               returns to it). Default: any confirmed transparent output of the wallet.\n"
            "4. \"bundleHex\" (string, optional) the attestation bundle to commit to (\"\" = the node's pool)\n"
            "5. wait        (boolean, optional, default true) block until the MINT is committed; false returns after the\n"
            "               carrier broadcast with pending = true and the wallet finishes on the next block\n"
            "6. maxCollateralZat (numeric, optional, default 0 = no bound) refuse (collateral-above-max) before anything is\n"
            "               signed when the collateral vout[0] would exceed this many zatoshi; judged at preflight and again\n"
            "               when the MINT is built on the confirmed carrier (then the carrier lapses and is swept)\n"
            "\nwait=false and restarts: the pending completion lives in memory only. If the node restarts before the\n"
            "carrier confirms, nobody builds the MINT: the carrier (CARRIER_VALUE plus its fee) stays outstanding in\n"
            "carriers.dat until its window (REF_WINDOW blocks past refHeight) lapses and yed_sweepcarriers (also run at\n"
            "startup) reclaims it. Call yed_mint again after the restart; no YED was issued and no collateral was locked.\n"
            "At most half of -rpcthreads wait=true calls may wait at once (carrier-wait-busy otherwise).\n"
            "\nResult: { \"txid\", \"vault\", \"ownerAddress\", \"termClass\", \"lockHeight\", \"claimHeight\", \"collateralZat\", \"feeZat\", \"payee\", \"fundedFrom\",\n"
            "          \"warning\", \"carrierTxid\", \"pending\", \"refHeight\", \"xMint\", \"aMint\", \"pMint\", \"source\", \"bundleSeqs\", \"attestFeeZat\", \"attestPayee\" }\n");
    YellowbackWallet& yw = EnsureYW();
    YellowbackIndex& index = *yw.Index();
    int64_t cents = params[0].get_int64();
    int lockBlocks = params[1].get_int();
    const std::string from = params.size() > 2 && !params[2].isNull() ? params[2].get_str() : "";
    const std::optional<std::vector<unsigned char>> bundleArg = ParseBundleArg(params, 3);
    const bool wait = ParseWaitArg(params, 4);
    const CAmount maxCollateralZat = ParseZatBoundArg(params, 5, "maxCollateralZat");
    CarrierWaitSlot slot(wait);    // C-2: refused here, before any transaction, when too many calls already wait

    // Preflight (before any transaction): MINTPOL-1, the bundle verdict at R, MINT-10 and the collateral bound.
    MintPreflight pf;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        EnsureWalletIsUnlocked();
        LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
        LOCK(index.cs_yellowback);
        EnsureHealthy(index);
        try {
            pf = PreflightMint(yw, cents, lockBlocks, bundleArg, from, maxCollateralZat);
        } catch (const std::runtime_error& e) {
            ThrowBuildError(e);
        }
    }
    const CarrierRecord carrier = CarrierStep(yw, pf.bundle, pf.refHeight, std::vector<unsigned char>(), from);
    if (!wait) {
        SchedulePending(yw, carrier, [=, &yw]() { return CompleteMint(yw, cents, lockBlocks, from, carrier, maxCollateralZat); }, "mint");
        UniValue o(UniValue::VOBJ);
        o.pushKV("txid", "");
        o.pushKV("vault", "");
        o.pushKV("ownerAddress", "");
        o.pushKV("termClass", "");
        o.pushKV("lockHeight", 0);
        o.pushKV("claimHeight", 0);
        o.pushKV("collateralZat", 0);
        o.pushKV("feeZat", 0);
        o.pushKV("payee", NullUniValue);
        o.pushKV("fundedFrom", "");
        o.pushKV("warning", "");
        PushPendingCommon(o, carrier, true);
        o.pushKV("xMint", PriceOrNull(pf.xMint));
        o.pushKV("aMint", PriceOrNull(pf.aMint));
        o.pushKV("pMint", PriceOrNull(pf.pMint));
        o.pushKV("source", pf.source);
        o.pushKV("bundleSeqs", SeqsToJSON(pf.bundleSeqs));
        o.pushKV("attestFeeZat", 0);
        o.pushKV("attestPayee", NullUniValue);
        return o;
    }
    WaitForCarrier(carrier);
    return CompleteMint(yw, cents, lockBlocks, from, carrier, maxCollateralZat);
}

static UniValue DoSend(YellowbackWallet& yw, const std::vector<std::pair<CScript, int64_t>>& recipients)
{
    YellowbackIndex& index = *yw.Index();
    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureWalletIsUnlocked();
    BuiltTx built;
    CReserveKey reservekey(pwalletMain);
    {
        LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
        LOCK(index.cs_yellowback);
        EnsureHealthy(index);
        try {
            built = BuildTransfer(yw, recipients, reservekey);
        } catch (const std::runtime_error& e) {
            ThrowBuildError(e);
        }
    }
    uint256 txid = Commit(yw, built, &reservekey);
    UniValue o(UniValue::VOBJ);
    o.pushKV("txid", txid.GetHex());
    o.pushKV("changeCents", built.changeCents);
    o.pushKV("expiryHeight", (int64_t)built.tx.nExpiryHeight);
    return o;
}

UniValue yed_send(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw std::runtime_error("yed_send \"yedaddress\" cents\n\nSend YED to a Yellowback address. Refuses other addresses (not-a-yellowback-address) and change below $1.00 (change-floor).\n"
            "From the Falcon height (yed_getinfo.params.pq) YED goes to post-quantum (Falcon) holders only (TOK-PQ, bad-yed-holder).\n"
            "A YED transaction built before that height with a P2PKH token output and still unconfirmed when the tip reaches\n"
            "Falcon height - 1 is evicted from the mempool (it would be invalid in the next block): rebuild it.\n"
            "YED cannot pay the network fee: it is paid in YEC from this wallet's confirmed transparent coins (insufficient-yec\n"
            "without them); yed_estimatesend quotes it as networkFeeZat.\n");
    YellowbackWallet& yw = EnsureYW();
    CScript dest = ParseYedAddress(params[0].get_str(), yw.Index()->GetParams());
    int64_t cents = params[1].get_int64();
    return DoSend(yw, { { dest, cents } });
}

UniValue yed_sendmany(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error("yed_sendmany {\"yedaddress\":cents,...}\n\nSend YED to up to 14 Yellowback addresses in one transaction.\n");
    YellowbackWallet& yw = EnsureYW();
    UniValue obj = params[0].get_obj();
    std::vector<std::pair<CScript, int64_t>> recipients;
    for (const std::string& name : obj.getKeys()) {
        recipients.push_back({ ParseYedAddress(name, yw.Index()->GetParams()), obj[name].get_int64() });
    }
    return DoSend(yw, recipients);
}

UniValue yed_redeem(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "yed_redeem \"vaultTxid\" ( \"to\" )\n"
            "\nRedeem an own vault in one step (V24). ACTIVE: burns exactly the vault's debt from this wallet's YED, pays the\n"
            "enforcement fee to an eligible pool and sends the rest of the collateral to \"to\"; refused unless an enforcing\n"
            "miner would accept it (mempool-check-failed:<verdict>). VOID: releases the collateral with no burn, no fee and\n"
            "no payload (L14). An ACTIVE vault redeems at any height after its mint (IT-1); before lockHeight the\n"
            "early-redeem fee earlyRedeemFeeBps[class] of the debt at the mint price is added to the pool fee (IT-9') -- quote it\n"
            "first with yed_estimateredeem. A VOID release needs the tip at its owner height (vault-locked). Refused\n"
            "(vault-spend-pending) while a spend of the vault is already in the mempool.\n"
            "\nArguments:\n"
            "1. \"vaultTxid\"  (string, required) the mint transaction id (the vault is its output 0)\n"
            "2. \"to\"         (string, optional) where the collateral goes: an s1... address, or a ys1... address\n"
            "                  (paid as a Sapling output). Default: a fresh transparent address of this wallet.\n"
            "\nResult: { \"txid\", \"burnedCents\", \"feeZat\", \"earlyRedeemFeeZat\", \"payee\", \"collateralOut\", \"to\",\n"
            "          \"extraBurnCents\" }  (feeZat includes earlyRedeemFeeZat)\n");
    YellowbackWallet& yw = EnsureYW();
    uint256 vaultTxid = ParseHashV(params[0], "vaultTxid");
    const std::string to = params.size() > 1 ? params[1].get_str() : "";
    uint256 txid;
    // The VOID release spends no ACTIVE vault, so the K7 gate is a no-op for it; gate both alike.
    BuiltTx built = RunVaultSpend(yw, [&]() {
        RefuseVaultSpendPending(COutPoint(vaultTxid, 0));   // N1: before coin selection
        return BuildRedeem(yw, vaultTxid, to);
    }, true, true, txid);
    return SpendResult(txid, built);
}

UniValue yed_estimateredeem(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "yed_estimateredeem \"vaultTxid\"\n"
            "\nQuote of yed_redeem for an own vault (IT-9): the burn, the pool fee and, before lockHeight, the early-redeem\n"
            "fee a redeem confirming in the next block pays, and whether yed_redeem would go ahead now. Signs nothing,\n"
            "locks nothing, commits nothing; never refuses for the vault's state (error says why a redeem would: canRedeem is\n"
            "judged on spendable YED, yed_getbalance.spendableCents, and is false with vault-spend-pending while a spend of\n"
            "the vault is in the mempool).\n"
            "\nArguments:\n"
            "1. \"vaultTxid\"  (string, required) the mint transaction id (the vault is its output 0)\n"
            "\nResult: { \"vault\", \"status\", \"termClass\", \"lockHeight\", \"height\", \"early\", \"burnedCents\",\n"
            "          \"collateralZat\", \"pMint\", \"protocolFeeCents\", \"protocolFeeZat\", \"feeZat\", \"earlyRedeemFeeBps\",\n"
            "          \"earlyRedeemFeeCents\", \"earlyRedeemFeeZat\", \"payee\", \"canRedeem\", \"error\" }  (rpcversion 8: the fees in dollars at pMint)\n");
    YellowbackWallet& yw = EnsureYW();
    YellowbackIndex& index = *yw.Index();
    const uint256 vaultTxid = ParseHashV(params[0], "vaultTxid");
    const COutPoint out(vaultTxid, 0);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
    LOCK(index.cs_yellowback);
    EnsureHealthy(index);
    State st(index.View());
    const yellowback::Params& p = index.GetParams();
    std::optional<VaultRecord> rec = st.GetVault(out);
    if (!rec.has_value()) throw JSONRPCError(RPC_INVALID_PARAMETER, "vault-not-found: no vault at " + out.ToString());
    const VaultRecord& v = rec.value();
    const int tip = IndexHeight(index);
    const bool active = v.Status() == VaultStatus::ACTIVE;
    std::optional<CKeyID> payee;
    const CAmount early = EarlyRedeemFeeAt(index, out, v, tip, payee);
    // FEE-1 on the ACTIVE redeem (FEE-0 without an eligible payee); a VOID release pays nothing (L14).
    const CAmount fee1 = active && payee.has_value() ? ProtocolFeeZat(v.mintedCents, v.pMint, p).value_or(MAX_MONEY) : 0;   // FEE-1' at the vault's pMint
    std::string error;
    if (!v.IsOpen()) error = strprintf("vault-not-active: the vault is %s", VaultStatusName(v.Status()));
    else if (!yw.IsMineVault(v)) error = "vault-not-owned: the vault owner key is not in this wallet";
    else if ((int64_t)tip < (int64_t)v.ownerHeight) error = strprintf("vault-locked: the vault is locked until height %d (tip %d)", v.ownerHeight, tip);   // BuildRedeem's test
    else if (!VaultSpendPendingError(out).empty()) error = VaultSpendPendingError(out);   // N1: yed_redeem's check, before selection
    else if (active && yw.SpendableCents() < v.mintedCents) {
        // N2: judged on the spendable YED (what the selector can use), not the confirmed figure
        error = strprintf("insufficient-yed: the redeem burns %d cents; the wallet can spend %d now (%d confirmed)", v.mintedCents, yw.SpendableCents(), yw.ConfirmedCents());
    }
    UniValue o(UniValue::VOBJ);
    o.pushKV("vault", strprintf("%s:%u", out.hash.GetHex(), out.n));
    o.pushKV("status", VaultStatusName(v.Status()));
    o.pushKV("termClass", ClassName(v.termClass));
    o.pushKV("lockHeight", (int64_t)v.lockHeight);
    o.pushKV("height", (int64_t)tip + 1);                       // the block the quote is for
    o.pushKV("early", active && (int64_t)tip + 1 < (int64_t)v.lockHeight);
    o.pushKV("burnedCents", active ? v.mintedCents : (int64_t)0);
    o.pushKV("collateralZat", v.collateralZat);
    o.pushKV("pMint", v.pMint);                                 // rpcversion 8: the price every fee below is struck at
    o.pushKV("protocolFeeCents", active && payee.has_value() ? ProtocolFeeCents(v.mintedCents, p) : (Cents)0);   // 0 under FEE-0: not charged
    o.pushKV("protocolFeeZat", fee1);                           // 0 under FEE-0 or on a release
    o.pushKV("feeZat", fee1 + early);                           // as yed_redeem's feeZat: FEE-1' plus the early-redeem fee
    o.pushKV("earlyRedeemFeeBps", p.IsValidClass(v.termClass) ? p.earlyRedeemFeeBps[v.termClass] : 0);
    // IT-9' in dollars: ceil(debt x bps / 10^4) cents, what a wallet shows (0 when no early fee is due)
    o.pushKV("earlyRedeemFeeCents", early > 0 && p.IsValidClass(v.termClass) ? (v.mintedCents * p.earlyRedeemFeeBps[v.termClass] + BPS - 1) / BPS : (Cents)0);
    o.pushKV("earlyRedeemFeeZat", early);
    o.pushKV("payee", active ? PayeeToJSON(payee) : NullUniValue);
    o.pushKV("canRedeem", error.empty());
    o.pushKV("error", error);
    return o;
}

UniValue yed_claim(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 6)
        throw std::runtime_error(
            "yed_claim \"vaultTxid\" ( \"to\" \"bundleHex\" wait minOutZat maxBurnCents )\n"
            "\nClaim somebody's underwater vault (yed_listclaimable): the claim-path spend at or past claimHeight, burning the\n"
            "vault's debt from this wallet's YED, paying the enforcement fee from the collateral and the rest to \"to\".\n"
            "Refused unless an enforcing miner would accept it (mempool-check-failed:<verdict>). v3: the carrier step first\n"
            "(selector = the vault outpoint), the attestor fee when armed, and the RED-5 residual to the vault owner when due;\n"
            "claimPath is the RED-4 clause that opened the claim (\"a\" combined price, \"b\" the emergency notice).\n"
            "Refused (vault-spend-pending) while a spend of the vault is already in the mempool, before the carrier step.\n"
            "\nArguments: as yed_redeem, then \"bundleHex\" and wait as yed_mint, then minOutZat (numeric, optional, default 0 =\n"
            "no bound): refuse (claim-out-below-min) before anything is signed when the collateral reaching \"to\" (the\n"
            "collateral less the enforcement fee, the attestor fee and the RED-5 residual) would be below this many zatoshi,\n"
            "then maxBurnCents (numeric, optional, default 0 = no bound): refuse (claim-burn-above-max) before anything is\n"
            "signed when the YED the claim burns (the vault's debt plus any sub-dollar remainder) would exceed this many cents.\n"
            "Result: yed_redeem's fields plus { \"carrierTxid\", \"pending\", \"refHeight\", \"xClaim\", \"aClaim\", \"pClaim\", \"pEmerg\", \"claimPath\",\n"
            "        \"bundleSeqs\", \"attestFeeZat\", \"attestPayee\", \"residualZat\" }\n");
    YellowbackWallet& yw = EnsureYW();
    YellowbackIndex& index = *yw.Index();
    uint256 vaultTxid = ParseHashV(params[0], "vaultTxid");
    const std::string to = params.size() > 1 && !params[1].isNull() ? params[1].get_str() : "";
    const std::optional<std::vector<unsigned char>> bundleArg = ParseBundleArg(params, 2);
    const bool wait = ParseWaitArg(params, 3);
    const CAmount minOutZat = ParseZatBoundArg(params, 4, "minOutZat");
    const int64_t maxBurnCents = ParseCentsBoundArg(params, 5, "maxBurnCents");
    CarrierWaitSlot slot(wait);    // C-2
    ClaimPreflight pf;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        EnsureWalletIsUnlocked();
        LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
        LOCK(index.cs_yellowback);
        EnsureHealthy(index);
        RefuseVaultSpendPending(COutPoint(vaultTxid, 0));   // N1: before the carrier and any coin selection
        try {
            pf = PreflightClaim(yw, vaultTxid, bundleArg, minOutZat, maxBurnCents);
        } catch (const std::runtime_error& e) {
            ThrowBuildError(e);
        }
    }
    const CarrierRecord carrier = CarrierStep(yw, pf.bundle, pf.refHeight, pf.selector, "");
    if (!wait) {
        SchedulePending(yw, carrier, [=, &yw]() { return CompleteClaim(yw, vaultTxid, to, carrier, minOutZat, maxBurnCents); }, "claim");
        UniValue o(UniValue::VOBJ);
        o.pushKV("txid", "");
        o.pushKV("burnedCents", 0);
        o.pushKV("feeZat", 0);
        o.pushKV("payee", NullUniValue);
        o.pushKV("collateralOut", 0);
        o.pushKV("to", to);
        o.pushKV("extraBurnCents", 0);
        PushPendingCommon(o, carrier, true);
        o.pushKV("xClaim", PriceOrNull(pf.xClaim));
        o.pushKV("aClaim", PriceOrNull(pf.aClaim));
        o.pushKV("pClaim", PriceOrNull(pf.pClaim));
        o.pushKV("pEmerg", pf.claimPath == "b" ? PriceOrNull(pf.pEmerg) : NullUniValue);
        o.pushKV("claimPath", pf.claimPath);
        o.pushKV("bundleSeqs", SeqsToJSON(pf.bundleSeqs));
        o.pushKV("attestFeeZat", 0);
        o.pushKV("attestPayee", NullUniValue);
        o.pushKV("residualZat", pf.residualZat);
        return o;
    }
    WaitForCarrier(carrier);
    return CompleteClaim(yw, vaultTxid, to, carrier, minOutZat, maxBurnCents);
}

UniValue yed_claimnotice(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw std::runtime_error(
            "yed_claimnotice \"vaultTxid\" ( \"bundleHex\" wait )\n"
            "\nStep 1 of the emergency claim (NOT-1): the carrier step (selector = the vault outpoint), then a transaction of own\n"
            "YEC plus the carrier carrying the CLAIM_NOTICE payload. Anyone may post a notice; it needs YEC, no YED. Refused\n"
            "with notice-standing, notice-not-underwater, bundle-insufficient, bundle-malformed.\n"
            "\nResult: { \"txid\", \"carrierTxid\", \"pending\", \"vault\", \"refHeight\", \"xClaim\", \"aClaim\", \"pEmerg\", \"bundleSeqs\", \"emergencyOpenAt\" }\n");
    YellowbackWallet& yw = EnsureYW();
    YellowbackIndex& index = *yw.Index();
    uint256 vaultTxid = ParseHashV(params[0], "vaultTxid");
    const std::optional<std::vector<unsigned char>> bundleArg = ParseBundleArg(params, 1);
    const bool wait = ParseWaitArg(params, 2);
    CarrierWaitSlot slot(wait);    // C-2
    NoticePreflight pf;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        EnsureWalletIsUnlocked();
        LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
        LOCK(index.cs_yellowback);
        EnsureHealthy(index);
        try {
            pf = PreflightNotice(yw, vaultTxid, bundleArg);
        } catch (const std::runtime_error& e) {
            ThrowBuildError(e);
        }
    }
    const CarrierRecord carrier = CarrierStep(yw, pf.bundle, pf.refHeight, pf.selector, "");
    if (!wait) {
        SchedulePending(yw, carrier, [=, &yw]() { return CompleteNotice(yw, vaultTxid, carrier); }, "notice");
        UniValue o(UniValue::VOBJ);
        o.pushKV("txid", "");
        PushPendingCommon(o, carrier, true);
        o.pushKV("vault", vaultTxid.GetHex() + ":0");
        o.pushKV("xClaim", PriceOrNull(pf.xClaim));
        o.pushKV("aClaim", PriceOrNull(pf.aClaim));
        o.pushKV("pEmerg", PriceOrNull(pf.pEmerg));
        o.pushKV("bundleSeqs", SeqsToJSON(pf.bundleSeqs));
        o.pushKV("emergencyOpenAt", (int64_t)pf.emergencyOpenAt);
        return o;
    }
    WaitForCarrier(carrier);
    return CompleteNotice(yw, vaultTxid, carrier);
}

UniValue yed_sweepcarriers(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "yed_sweepcarriers\n"
            "\nReclaim every outstanding carrier of this wallet (carriers.dat, W7) whose window has lapsed into one output to a\n"
            "fresh own address. Also run at startup. Never refuses for nothing to do.\n"
            "\nResult: { \"txid\", \"count\", \"reclaimedZat\", \"outstanding\" }\n");
    YellowbackWallet& yw = EnsureYW();
    YellowbackIndex& index = *yw.Index();
    UniValue o(UniValue::VOBJ);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    const int tip = chainActive.Height();
    std::vector<CarrierRecord> lapsed = yw.LapsedCarriers(tip);
    size_t count = 0;
    CAmount reclaimed = 0;
    std::string txid;
    if (!lapsed.empty()) {
        EnsureWalletIsUnlocked();
        BuiltTx built;
        bool nothing = false;
        {
            LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
            LOCK(index.cs_yellowback);
            EnsureHealthy(index);
            try {
                built = BuildSweepCarriers(yw, lapsed);
            } catch (const std::runtime_error& e) {
                if (!StartsWith(e.what(), "nothing-to-sweep")) ThrowBuildError(e);
                nothing = true;
            }
        }
        if (!nothing) {
            txid = Commit(yw, built, nullptr).GetHex();
            count = built.sweptCarriers;
            reclaimed = built.collateralOut;
            for (const CarrierRecord& c : built.sweptRecords) yw.SpendCarrier(c.outpoint);
        }
        // A lapsed record whose outpoint is already spent (its main transaction did confirm) is forgotten either way.
        for (const CarrierRecord& c : lapsed) {
            const CCoins* coins = pcoinsTip->AccessCoins(c.outpoint.hash);
            if (!(coins && coins->IsAvailable(c.outpoint.n))) yw.SpendCarrier(c.outpoint);
        }
    }
    o.pushKV("txid", txid);
    o.pushKV("count", (int64_t)count);
    o.pushKV("reclaimedZat", reclaimed);
    o.pushKV("outstanding", (int64_t)(yw.OutstandingCarriers().size()));
    return o;
}

UniValue yed_registerattestor(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw std::runtime_error(
            "yed_registerattestor bondYec lockBlocks ( flags )\n"
            "\nJoin the YED attestor set (P4-b: the attestor registry is the vault primitive's set attestorSetId) with a fresh\n"
            "wallet key as the member key: set_join attestorSetId bondYec (tip + 1 + lockBlocks). vout[0] is the bond\n"
            "P2SH(<bondLocktime> CLTV DROP <memberKey> CHECKSIG); the member key signs price attestations and receives the\n"
            "attestor fee, so back up wallet.dat. seq is null until the join confirms (yed_listattestors). Refused with\n"
            "bond-below-min, lock-below-min (the module's floor: yed_getinfo params.attest.bondMinZat, D-Q-30, and BOND_MIN_LOCK) and yellowback-no-attestor-set; a set\n"
            "that is not open needs admission signatures (register-needs-admission: finish with set_signact / set_sendact).\n"
            "The minimum follows the YEC locked in YED vaults at the snapshot before the join's block (D-Q-30), so post headroom: a\n"
            "bond within 10% of params.attest.bondMinZat (and below bondMinCapZat) returns warning \"bond-near-min\"; if vault\n"
            "collateral grows before it confirms, the join becomes invalid (attestor-bond-below-min) and is not mined.\n"
            "\nArguments:\n"
            "1. bondYec     (numeric, required) the bond in YEC (>= the module's bondMinZat at the next block and the set's bondmin)\n"
            "2. lockBlocks  (numeric, required) >= BOND_MIN_LOCK and the set's bondlockmin; bondLocktime = tip + 1 + lockBlocks\n"
            "3. flags       (numeric, optional, default 0) accepted for compatibility and ignored (no longer recorded)\n"
            "\nResult: { \"txid\", \"seq\", \"attestorPubKey\", \"bondAddress\", \"bondKeyAddress\", \"bondOutpoint\", \"bondZat\", \"bondLocktime\", \"flags\", \"maturesAt\", \"warning\" }\n");
    YellowbackWallet& yw = EnsureYW();
    YellowbackIndex& index = *yw.Index();
    const CAmount bondZat = AmountFromValue(params[0]);
    const int lockBlocks = params[1].get_int();
    const int flagsArg = params.size() > 2 && !params[2].isNull() ? params[2].get_int() : 0;
    if (flagsArg < 0 || flagsArg > 255) throw JSONRPCError(RPC_INVALID_PARAMETER, "flags must be a byte");
    uint256 setId;
    int64_t locktime = 0;
    int maturesAt = 0;
    std::string warning;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        EnsureWalletIsUnlocked();
        LOCK(index.cs_yellowback);
        EnsureHealthy(index);
        const yellowback::Params& p = index.GetParams();
        if (p.attestorSetId.IsNull()) throw JSONRPCError(RPC_VERIFY_REJECTED, "yellowback-no-attestor-set: this network has no YED attestor set");
        // D-Q-30: the module's floor for a join in the next block (the vault collateral of the tip's snapshot); a join mined
        // later is judged at its own block, so collateral growth in between makes it invalid (attestor-bond-below-min)
        const CAmount bondMin = BondMinZat(State(index.View()), p, (int64_t)IndexHeight(index) + 1);   // the index tip, as yed_getinfo
        if (bondZat < bondMin) throw JSONRPCError(RPC_VERIFY_REJECTED, strprintf("bond-below-min: the bond must be at least %s YEC", FormatMoney(bondMin)));
        // D-Q-30 review B2 (policy): the join is judged at the snapshot before its own block, so a bond within 10 % of
        // today's minimum can fall short if vault collateral grows before it confirms and then is never mined.
        // The cap (bondMinCapZat) always qualifies.
        if (bondZat < p.bondMinCapZat && bondZat < bondMin + bondMin / 10) {
            warning = strprintf("bond-near-min: %s YEC is within 10 %% of the minimum for the next block (%s YEC); if YED vault collateral "
                                "grows before the join confirms it becomes invalid and is not mined. Post at least %s YEC (+10 %%), or %s YEC, "
                                "which always qualifies", FormatMoney(bondZat), FormatMoney(bondMin),
                                FormatMoney(std::min(p.bondMinCapZat, bondMin + bondMin / 10)), FormatMoney(p.bondMinCapZat));
        }
        if (lockBlocks < p.bondMinLock) throw JSONRPCError(RPC_VERIFY_REJECTED, strprintf("lock-below-min: the lock must be at least %d blocks", p.bondMinLock));
        locktime = (int64_t)chainActive.Height() + 1 + lockBlocks;
        if (locktime >= (int64_t)LOCKTIME_THRESHOLD) throw JSONRPCError(RPC_VERIFY_REJECTED, "lock-below-min: bondLocktime reaches LOCKTIME_THRESHOLD");
        setId = p.attestorSetId;
        State st(index.View());
        std::optional<AttestorSetRecord> z = st.GetAttestorSet();
        maturesAt = chainActive.Height() + 1 + (int)std::max<int64_t>(z.has_value() ? (int64_t)z->maturity : 0, p.bondMaturity);
    }
    // set_join takes cs_main, the wallet and (through the mempool) cs_yellowback itself: called with none held (N25)
    UniValue jp(UniValue::VARR);
    jp.push_back(setId.GetHex());
    jp.push_back(ValueFromAmount(bondZat));
    jp.push_back(locktime);
    const UniValue joined = tableRPC.execute("set_join", jp);
    if (!find_value(joined, "complete").get_bool()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "register-needs-admission: the attestor set is not open; collect the admission signatures with set_signact and send with set_sendact: "
                           + find_value(joined, "hex").get_str());
    }
    const std::string memberHex = find_value(joined, "memberkey").get_str();
    const std::vector<unsigned char> memberBytes = ParseHex(memberHex);
    const CPubKey member(memberBytes.begin(), memberBytes.end());
    const std::string txid = find_value(joined, "txid").get_str();
    KeyIO keyIO(::Params());
    UniValue o(UniValue::VOBJ);
    o.pushKV("txid", txid);
    o.pushKV("seq", NullUniValue);
    o.pushKV("attestorPubKey", memberHex);
    o.pushKV("bondAddress", keyIO.EncodeDestination(CTxDestination(CScriptID(BondScript(member, (uint32_t)locktime)))));
    o.pushKV("bondKeyAddress", keyIO.EncodeDestination(CTxDestination(member.GetID())));
    UniValue op(UniValue::VOBJ);
    op.pushKV("txid", txid);
    op.pushKV("vout", 0);
    o.pushKV("bondOutpoint", op);
    o.pushKV("bondZat", bondZat);
    o.pushKV("bondLocktime", locktime);
    UniValue fl(UniValue::VOBJ);
    fl.pushKV("tier", 0);
    fl.pushKV("pool", false);
    o.pushKV("flags", fl);
    o.pushKV("maturesAt", (int64_t)maturesAt);
    o.pushKV("warning", warning);
    return o;
}

UniValue yed_withdrawbond(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "yed_withdrawbond seq ( \"to\" )\n"
            "\nSpend the bond of an attestor whose bondPubKey this wallet holds (nLockTime = bondLocktime, the CLTV path), signed\n"
            "by hand. The bond exit delay (owner 2026-10-11): only a WITHDRAWN record (it left with set_leave, or was evicted) whose\n"
            "bond is not frozen, from statusHeight + the set's maturity (BOND_MATURITY); bond-locked before.\n"
            "Refused with attest-unknown-seq, attest-key-not-held, bond-locked, bond-spent, bad-address.\n"
            "\nResult: { \"txid\", \"seq\", \"bondZat\", \"bondOut\", \"to\" }\n");
    YellowbackWallet& yw = EnsureYW();
    const int seqArg = params[0].get_int();
    if (seqArg < 0 || seqArg > 65535) throw JSONRPCError(RPC_INVALID_PARAMETER, "seq must be a u16");
    const std::string to = params.size() > 1 && !params[1].isNull() ? params[1].get_str() : "";
    YellowbackIndex& index = *yw.Index();
    BuiltTx built;
    uint256 txid;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        EnsureWalletIsUnlocked();
        {
            LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
            LOCK(index.cs_yellowback);
            EnsureHealthy(index);
            try {
                built = BuildWithdrawBond(yw, (uint16_t)seqArg, to);
            } catch (const std::runtime_error& e) {
                ThrowBuildError(e);
            }
        }
        if (!built.NeedsProving()) txid = Commit(yw, built, nullptr);
    }
    if (built.NeedsProving()) {
        try {
            FinishSapling(built);
        } catch (const std::runtime_error& e) {
            throw JSONRPCError(RPC_WALLET_ERROR, e.what());
        }
        LOCK2(cs_main, pwalletMain->cs_wallet);
        EnsureWalletIsUnlocked();
        try {
            SignBuiltInputs(built, *pwalletMain, SignerBranchId());
        } catch (const std::runtime_error& e) {
            ThrowBuildError(e);
        }
        txid = Commit(yw, built, nullptr);
    }
    UniValue o(UniValue::VOBJ);
    o.pushKV("txid", txid.GetHex());
    o.pushKV("seq", (int)built.seq);
    o.pushKV("bondZat", built.bondZat);
    o.pushKV("bondOut", built.collateralOut);
    o.pushKV("to", built.collateralTo);
    return o;
}

UniValue yed_revive(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw std::runtime_error(
            "yed_revive seq priceMicroUsd\n"
            "\nRevive a DORMANT attestor whose member key this wallet holds (P4-b: a SET_HEARTBEAT of the member key to the\n"
            "attestor set; ATTESTOR_REVIVE is invalid). Also signs one attestation for citedHeight = tip - REF_LAG through the\n"
            "equivocation guard and returns it (feed it with yed_addattestation). The record is ELIGIBLE again at the SNAP of\n"
            "the heartbeat's block. Refused with attest-unknown-seq, not-dormant, attest-key-not-held, attest-range,\n"
            "equivocation-guard.\n"
            "\nResult: { \"txid\", \"seq\", \"citedHeight\", \"priceMicroUsd\", \"hex\" }\n");
    YellowbackWallet& yw = EnsureYW();
    YellowbackIndex& index = *yw.Index();
    const int seqArg = params[0].get_int();
    if (seqArg < 0 || seqArg > 65535) throw JSONRPCError(RPC_INVALID_PARAMETER, "seq must be a u16");
    const int64_t price = params[1].get_int64();
    BuiltTx built;
    uint256 setId;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        EnsureWalletIsUnlocked();
        {
            LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
            LOCK(index.cs_yellowback);
            EnsureHealthy(index);
            try {
                built = BuildRevive(yw, (uint16_t)seqArg, price);
            } catch (const std::runtime_error& e) {
                ThrowBuildError(e);
            }
            setId = index.GetParams().attestorSetId;
        }
    }
    UniValue hp(UniValue::VARR);
    hp.push_back(setId.GetHex());
    hp.push_back(HexStr(built.attestorPubKey.begin(), built.attestorPubKey.end()));
    const UniValue hb = tableRPC.execute("set_heartbeat", hp);
    const std::vector<unsigned char> att = EncodeAttestation(built.attestation);
    UniValue o(UniValue::VOBJ);
    o.pushKV("txid", find_value(hb, "txid").get_str());
    o.pushKV("seq", (int)built.seq);
    o.pushKV("citedHeight", (int64_t)built.attestation.citedHeight);
    o.pushKV("priceMicroUsd", (int64_t)built.attestation.priceMicroUsd);
    o.pushKV("hex", HexStr(att.begin(), att.end()));
    return o;
}

UniValue yed_reportequivocation(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw std::runtime_error(
            "yed_reportequivocation \"attestationHexA\" \"attestationHexB\" ( wait )\n"
            "\nReport two attestations of one attestor for one height at two prices (EQV-1): the carrier step with a bundle of\n"
            "exactly the two, then a transaction carrying the EQUIVOCATION payload. The attestor is EJECTED when it confirms.\n"
            "Refused with not-equivocation (the message says which condition fails), attest-malformed.\n"
            "\nResult: { \"txid\", \"carrierTxid\", \"pending\", \"refHeight\", \"seq\", \"citedHeight\", \"priceA\", \"priceB\" }\n");
    YellowbackWallet& yw = EnsureYW();
    YellowbackIndex& index = *yw.Index();
    const Attestation a = ParseAttestationArg(params[0], "attestationHexA");
    const Attestation b = ParseAttestationArg(params[1], "attestationHexB");
    const bool wait = ParseWaitArg(params, 2);
    CarrierWaitSlot slot(wait);    // C-2
    int refHeight = 0;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        EnsureWalletIsUnlocked();
        LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
        LOCK(index.cs_yellowback);
        EnsureHealthy(index);
        try {
            CheckEquivocation(yw, a, b);
        } catch (const std::runtime_error& e) {
            ThrowBuildError(e);
        }
        refHeight = IndexHeight(index) - g_yellowbackMintLag;
    }
    Bundle bundle;
    bundle.atts = { a, b };
    const CarrierRecord carrier = CarrierStep(yw, EncodeBundle(bundle), refHeight, std::vector<unsigned char>(), "");
    if (!wait) {
        SchedulePending(yw, carrier, [=, &yw]() { return CompleteEquivocation(yw, a, b, carrier); }, "equivocation");
        UniValue o(UniValue::VOBJ);
        o.pushKV("txid", "");
        PushPendingCommon(o, carrier, true);
        o.pushKV("seq", (int)a.seq);
        o.pushKV("citedHeight", (int64_t)a.citedHeight);
        o.pushKV("priceA", (int64_t)a.priceMicroUsd);
        o.pushKV("priceB", (int64_t)b.priceMicroUsd);
        return o;
    }
    WaitForCarrier(carrier);
    return CompleteEquivocation(yw, a, b, carrier);
}

UniValue yed_signattestation(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw std::runtime_error(
            "yed_signattestation seq priceMicroUsd ( citedHeight )\n"
            "\nSign one 74-byte attestation with the attestor hot key held in this wallet (the agent's RPC; the key never leaves the\n"
            "node). Equivocation guard (S16): <datadir>/yellowback/attest-signed.dat records every (seq, citedHeight, price, sig)\n"
            "ever signed, fsynced before returning; the same price again returns the recorded signature with reused = true, a\n"
            "different price is refused with equivocation-guard. citedHeight defaults to tip - REF_LAG. Refused with\n"
            "attest-unknown-seq, attest-key-not-held, attest-range, attest-stale, equivocation-guard.\n"
            "\nResult: { \"hex\", \"seq\", \"priceMicroUsd\", \"citedHeight\", \"reused\" }\n");
    YellowbackWallet& yw = EnsureYW();
    YellowbackIndex& index = *yw.Index();
    const int seqArg = params[0].get_int();
    if (seqArg < 0 || seqArg > 65535) throw JSONRPCError(RPC_INVALID_PARAMETER, "seq must be a u16");
    const int64_t price = params[1].get_int64();
    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureWalletIsUnlocked();
    LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
    LOCK(index.cs_yellowback);
    EnsureHealthy(index);
    const int cited = params.size() > 2 && !params[2].isNull() ? params[2].get_int() : IndexHeight(index) - g_yellowbackMintLag;
    bool reused = false;
    Attestation a;
    try {
        a = SignAttestationGuarded(yw, (uint16_t)seqArg, price, cited, reused);
    } catch (const std::runtime_error& e) {
        ThrowBuildError(e);
    }
    const std::vector<unsigned char> att = EncodeAttestation(a);
    UniValue o(UniValue::VOBJ);
    o.pushKV("hex", HexStr(att.begin(), att.end()));
    o.pushKV("seq", (int)a.seq);
    o.pushKV("priceMicroUsd", (int64_t)a.priceMicroUsd);
    o.pushKV("citedHeight", (int64_t)a.citedHeight);
    o.pushKV("reused", reused);
    return o;
}

UniValue yed_listpositions(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "yed_listpositions ( \"status\" )\n"
            "\nThis wallet's vaults (owner key held): every yed_getvault field plus canRedeem (ACTIVE or VOID at or past\n"
            "the owner height: from the block after the mint, IT-1; for VOID the release), canClaim (claimable and the\n"
            "wallet holds the debt) and earlyRedeemFeeZat (what a redeem now adds to the pool fee before lockHeight, IT-9).\n"
            "spendPending is true while a mempool transaction spends the vault (spendTxid, present only then); canRedeem and\n"
            "canClaim are false while it is. canClaim reads the spendable YED (yed_getbalance.spendableCents).\n");
    YellowbackWallet& yw = EnsureYW();
    YellowbackIndex& index = *yw.Index();
    std::string status = params.size() > 0 && !params[0].isNull() ? params[0].get_str() : "";
    LOCK2(cs_main, pwalletMain->cs_wallet);
    LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
    LOCK(index.cs_yellowback);
    EnsureHealthy(index);
    State st(index.View());
    const yellowback::Params& p = index.GetParams();
    const int h = IndexHeight(index);
    const int64_t balance = yw.SpendableCents();     // N2: what a claim's selector can use now
    // v3: claimable by either RED-4 clause and canNotice under this node's pEmerg come from the
    // same estimate yed_listclaimable and yed_getvault read (yellowback::rpc::EstimateClaim).
    UniValue arr(UniValue::VARR);
    index.View().Iterate("V", [&](const std::string& k, const std::string& raw) {
        VaultRecord v;
        if (!DeserializeRecord(raw, v)) return true;
        if (!yw.IsMineVault(v)) return true;
        if (!status.empty() && status != VaultStatusName(v.Status())) return true;
        const COutPoint out(keys::OutPointHashOf(k), keys::OutPointIndexOf(k));
        const yellowback::rpc::ClaimEstimate est = yellowback::rpc::EstimateClaim(index, out, v, h);
        UniValue o = VaultRow(out, v, p, est.claimable, (int64_t)h + 1);
        if (v.Status() == VaultStatus::CLAIMING) o.pushKV("intents", ClaimIntentsJSON(index, out, p));   // as yed_getvault (U-23)
        const bool active = v.Status() == VaultStatus::ACTIVE;
        std::optional<NoticeRecord> notice = active ? st.GetNotice(out) : std::nullopt;
        const bool noticed = notice.has_value();
        o.pushKV("noticed", noticed);
        o.pushKV("noticeHeight", noticed ? UniValue((int64_t)notice->height) : NullUniValue);
        o.pushKV("emergencyOpenAt", noticed ? UniValue((int64_t)notice->refHeight + p.emergencyPersist) : NullUniValue);
        const bool pendingSpend = yellowback::rpc::PushSpendPending(o, out).has_value();   // N1
        o.pushKV("canRedeem", v.IsOpen() && h >= v.ownerHeight && !pendingSpend);     // IT-1 (extended): in term too
        std::optional<CKeyID> payee;
        o.pushKV("earlyRedeemFeeZat", EarlyRedeemFeeAt(index, out, v, h, payee));   // IT-9: what a redeem now adds to the fee
        o.pushKV("canClaim", est.claimable && balance >= v.mintedCents && !pendingSpend);
        o.pushKV("canNotice", est.canNotice);
        arr.push_back(o);
        return true;
    });
    return arr;
}

UniValue yed_listtransactions(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw std::runtime_error(
            "yed_listtransactions ( count skip )\n"
            "\nThis wallet's Yellowback history from the index, newest first: type is mint, send, receive, burn, redeem,\n"
            "claim (this wallet claimed, incl. its own vault), claimed (an own vault was claimed), claim_release / claim_cancel\n"
            "(the intent of this wallet's claim released / cancelled), claim_released / claim_cancelled (the same, on an own\n"
            "vault someone else claimed), sweep (an own vault swept), carrier (an own carrier its main transaction has not\n"
            "completed: pending, lapsed or swept; plan A6), plus\n"
            "own transactions with a payload that expired unmined (\"expired\": true, verdict \"expired\", typed by the payload:\n"
            "mint, send, redeem, claim, register, notice, equivocation, revive, cancel). time is the block time (UTC seconds;\n"
            "null without a block). A two-step action's rows share carrierTxid and mainTxid (\"\" on other rows); carrierOutcome\n"
            "is pending, completed (the main transaction spent the carrier), lapsed (its window passed) or swept.\n");
    YellowbackWallet& yw = EnsureYW();
    YellowbackIndex& index = *yw.Index();
    int count = params.size() > 0 && !params[0].isNull() ? params[0].get_int() : 100;
    int skip = params.size() > 1 && !params[1].isNull() ? params[1].get_int() : 0;
    // C-6, as yed_listvaults / yed_listtokens: a negative skip would wrap in the size_t loop below.
    if (count < 0 || skip < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "count and skip must be >= 0");
    LOCK2(cs_main, pwalletMain->cs_wallet);
    LOCK(mempool.cs);              // §4.3 lock order: mempool.cs (mempool.exists below) before cs_yellowback
    LOCK(index.cs_yellowback);
    EnsureHealthy(index);
    State st(index.View());
    const int h = IndexHeight(index);
    const int chainTip = chainActive.Height();
    // N7: the block time of a row's height (UTC seconds), null without a block on the active chain
    auto blockTime = [&](int height) -> UniValue {
        if (height < 0 || height > chainTip || chainActive[height] == nullptr) return NullUniValue;
        return UniValue(chainActive[height]->GetBlockTime());
    };
    // Plan A6: this wallet's carriers and what spent them. A carrier input is recognised by its scriptSig's shape
    // (ParseCarrierScriptSig); a spender with a payload is the main transaction, one without is a sweep. A live
    // spender (confirmed or in the mempool) decides the outcome; `main` is the main transaction, live or not (an
    // expired one still names the action).
    struct CarrierUse { uint256 main; bool mainLive = false; bool live = false; bool livePayload = false; };
    std::map<COutPoint, CarrierUse> carrierSpends;
    std::map<uint256, COutPoint> carrierOf;          // a main transaction -> the carrier it spends
    for (const auto& kv : pwalletMain->mapWallet) {
        const CWalletTx& wtx = kv.second;
        bool hasCarrier = false;
        for (const CTxIn& in : wtx.vin) if (ParseCarrierScriptSig(in.scriptSig).has_value()) hasCarrier = true;
        if (!hasCarrier) continue;
        const int depth = wtx.GetDepthInMainChain(std::nullopt);
        const bool live = depth > 0 || (depth == 0 && mempool.exists(kv.first));
        const bool payload = FindPayload(wtx).has_value();
        for (const CTxIn& in : wtx.vin) {
            if (!ParseCarrierScriptSig(in.scriptSig).has_value()) continue;
            CarrierUse& u = carrierSpends[in.prevout];
            if (payload) {
                carrierOf[kv.first] = in.prevout;
                if (u.main.IsNull() || (live && !u.mainLive)) { u.main = kv.first; u.mainLive = live; }
            }
            if (live) { u.live = true; u.livePayload = payload; }
        }
    }
    for (const CarrierRecord& c : yw.OutstandingCarriers()) carrierSpends.insert(std::make_pair(c.outpoint, CarrierUse()));
    auto carrierOutcome = [&](const COutPoint& c) -> std::string {
        const CarrierUse& u = carrierSpends[c];
        std::map<uint256, CWalletTx>::const_iterator f = pwalletMain->mapWallet.find(c.hash);
        const uint32_t expiry = f != pwalletMain->mapWallet.end() ? f->second.nExpiryHeight : 0;
        return CarrierOutcome(u.live, u.livePayload, chainTip, expiry);
    };
    // The A6 fields of a row: a two-step main transaction names its carrier and itself; other rows carry "".
    auto pushCarrierFields = [&](UniValue& o, const uint256& txid) {
        std::map<uint256, COutPoint>::const_iterator c = carrierOf.find(txid);
        o.pushKV("carrierTxid", c != carrierOf.end() ? c->second.hash.GetHex() : std::string());
        o.pushKV("mainTxid", c != carrierOf.end() ? txid.GetHex() : std::string());
        o.pushKV("carrierOutcome", c != carrierOf.end() ? carrierOutcome(c->second) : std::string());
    };

    // U-23 pre-pass: the vaults this wallet claimed (a claim's TxLog names the vault in closedVaults and
    // the burn in spentTokens; its release / cancel names the same vault), and where each cancel
    // re-created a vault (a cancelled vault's record moves to the re-created outpoint).
    std::set<COutPoint> claimedByMe;
    std::map<COutPoint, COutPoint> reopenedAt;
    index.View().Iterate("L", [&](const std::string& k, const std::string& raw) {
        TxLogRecord l;
        if (!DeserializeRecord(raw, l)) return true;
        if (l.Type() == TxLogType::REDEEM && l.verdict == verdict::OK && l.path == "claim") {
            bool burnedMine = false;
            for (const AssignedOutput& a : l.spentTokens) if (yw.IsMineScript(a.scriptPubKey)) burnedMine = true;
            if (burnedMine) for (const COutPoint& c : l.closedVaults) claimedByMe.insert(c);
        }
        if (l.Type() == TxLogType::CLAIM_CANCEL && l.closedVaults.size() == 1 && l.reopenedVaults.size() == 1)
            reopenedAt[l.closedVaults[0]] = l.reopenedVaults[0];
        return true;
    });
    // The vault record of `c`, following cancels to the re-created vault (the same position, the same owner).
    auto vaultOf = [&](COutPoint c) -> std::optional<VaultRecord> {
        for (size_t hops = 0; hops <= reopenedAt.size(); hops++) {
            std::optional<VaultRecord> v = st.GetVault(c);
            if (v.has_value()) return v;
            auto it = reopenedAt.find(c);
            if (it == reopenedAt.end()) return std::nullopt;
            c = it->second;
        }
        return std::nullopt;
    };

    struct Row { int height; UniValue o; };
    std::vector<Row> rows;
    index.View().Iterate("L", [&](const std::string& k, const std::string& raw) {
        TxLogRecord l;
        if (!DeserializeRecord(raw, l)) return true;
        const uint256 txid = keys::OutPointHashOf(k);
        int64_t received = 0, spent = 0;
        bool closedMine = false, unbacked = false;
        for (const AssignedOutput& a : l.assigned) if (yw.IsMineScript(a.scriptPubKey)) received += a.cents;
        for (const AssignedOutput& a : l.spentTokens) if (yw.IsMineScript(a.scriptPubKey)) spent += a.cents;
        for (const COutPoint& c : l.closedVaults) {
            std::optional<VaultRecord> v = vaultOf(c);
            if (v.has_value() && yw.IsMineVault(v.value())) {
                closedMine = true;
                if (v->unbacked) unbacked = true;
            }
        }
        bool mintMine = false;
        if (l.Type() == TxLogType::MINT) {
            std::optional<VaultRecord> v = st.GetVault(COutPoint(txid, 0));
            mintMine = v.has_value() && yw.IsMineVault(v.value());
        }
        const bool intentSpend = l.Type() == TxLogType::CLAIM_RELEASE || l.Type() == TxLogType::CLAIM_CANCEL;
        bool claimantMine = false;
        for (const COutPoint& c : l.closedVaults) if (claimedByMe.count(c)) claimantMine = true;
        if (received == 0 && spent == 0 && !closedMine && !mintMine && !(intentSpend && claimantMine)) return true;
        std::string type;
        int64_t amount = received - spent;
        const bool ok = l.verdict == verdict::OK;
        std::string path = l.path;
        if (l.Type() == TxLogType::MINT) { type = "mint"; }
        else if (intentSpend) {
            // U-23: the claimant's intent released (CLAIMED) or cancelled by the attestor set (the vault
            // ACTIVE again); the claimant's view wins when this wallet claimed its own vault. A release moves no
            // YED (the claim burned it); a cancel re-issues the burn to the holder it came from (CAN-1), so the
            // claimant's amountCents is that refund (received); path is the claim's.
            const bool release = l.Type() == TxLogType::CLAIM_RELEASE;
            type = claimantMine ? (release ? "claim_release" : "claim_cancel") : (release ? "claim_released" : "claim_cancelled");
            path = "claim";
        }
        else if (l.Type() == TxLogType::REDEEM && ok && l.path == "claim" && spent > 0) { type = "claim"; }   // incl. a claim of an own vault
        else if (closedMine) {
            if (ok) type = l.path == "claim" ? "claimed" : "redeem";
            else type = l.path == "owner" ? "sweep" : "claimed";
        }
        else if (spent > 0 && l.burned > 0 && l.yedOut == received) { type = "burn"; }   // nothing left this wallet but the burn
        else if (spent > 0) { type = "send"; }        // incl. an own-to-own transfer (amountCents 0)
        else { type = "receive"; }
        UniValue o(UniValue::VOBJ);
        o.pushKV("txid", txid.GetHex());
        o.pushKV("height", l.height);
        o.pushKV("confirmations", h - l.height + 1);
        o.pushKV("type", type);
        o.pushKV("verdict", l.verdict);
        o.pushKV("path", path);
        o.pushKV("yedIn", l.yedIn);
        o.pushKV("yedOut", l.yedOut);
        o.pushKV("burned", l.burned);
        o.pushKV("amountCents", amount);
        o.pushKV("feeZat", l.feeZat);
        o.pushKV("payee", PayeeToJSON(l.hasPayee, l.payee));
        o.pushKV("unbacked", unbacked);
        o.pushKV("expired", false);
        o.pushKV("time", blockTime(l.height));
        pushCarrierFields(o, txid);
        rows.push_back({ l.height, o });
        return true;
    });
    // Wallet transactions with a payload that are in neither the index nor the mempool and are past their expiry (§4.6).
    for (const auto& kv : pwalletMain->mapWallet) {
        const CWalletTx& wtx = kv.second;
        std::optional<FoundPayload> fp = FindPayload(wtx);
        if (!fp.has_value()) continue;
        if (st.GetTxLog(kv.first).has_value() || mempool.exists(kv.first)) continue;
        if (wtx.nExpiryHeight == 0 || (int64_t)wtx.nExpiryHeight > (int64_t)chainActive.Height()) continue;
        if (wtx.GetDepthInMainChain(std::nullopt) > 0) continue;
        // N7 (cf. DigiByte v9.26.7 77a5b156): typed by the payload; a REDEEM payload on a vault this wallet does not own is a claim
        bool foreignVault = false;
        if (fp->payload.type == PayloadType::REDEEM && !wtx.vin.empty()) {
            std::optional<VaultRecord> v = st.GetVault(wtx.vin[0].prevout);
            foreignVault = v.has_value() && !yw.IsMineVault(v.value());
        }
        UniValue o(UniValue::VOBJ);
        o.pushKV("txid", kv.first.GetHex());
        o.pushKV("height", -1);
        o.pushKV("confirmations", 0);
        o.pushKV("type", ExpiredRowType((uint8_t)fp->payload.type, foreignVault));
        o.pushKV("verdict", "expired");
        o.pushKV("path", "");
        o.pushKV("yedIn", 0);
        o.pushKV("yedOut", 0);
        o.pushKV("burned", 0);
        o.pushKV("amountCents", 0);
        o.pushKV("feeZat", 0);
        o.pushKV("payee", NullUniValue);
        o.pushKV("unbacked", false);
        o.pushKV("expired", true);
        o.pushKV("time", NullUniValue);
        pushCarrierFields(o, kv.first);
        rows.push_back({ (int)wtx.nExpiryHeight, o });
    }
    // Plan A6: a row for each own carrier whose main transaction did not complete it (pending, lapsed or swept;
    // outstanding in carriers.dat or spent by an own transaction), so a two-step action that never completed still
    // shows, across restarts. A completed carrier has no row of its own: its main transaction's row names it.
    for (const auto& cs : carrierSpends) {
        const COutPoint& c = cs.first;
        std::map<uint256, CWalletTx>::const_iterator f = pwalletMain->mapWallet.find(c.hash);
        if (f == pwalletMain->mapWallet.end()) continue;
        const std::string outcome = carrierOutcome(c);
        if (outcome == "completed") continue;
        const CWalletTx& wtx = f->second;
        const int depth = wtx.GetDepthInMainChain(std::nullopt);
        const int height = depth > 0 ? chainTip - depth + 1 : -1;
        const int sortKey = depth > 0 ? height : (depth == 0 && mempool.exists(c.hash) ? chainTip + 1 : (int)wtx.nExpiryHeight);
        UniValue o(UniValue::VOBJ);
        o.pushKV("txid", c.hash.GetHex());
        o.pushKV("height", height);
        o.pushKV("confirmations", depth > 0 ? depth : 0);
        o.pushKV("type", "carrier");
        o.pushKV("verdict", "");
        o.pushKV("path", "");
        o.pushKV("yedIn", 0);
        o.pushKV("yedOut", 0);
        o.pushKV("burned", 0);
        o.pushKV("amountCents", 0);
        o.pushKV("feeZat", 0);
        o.pushKV("payee", NullUniValue);
        o.pushKV("unbacked", false);
        o.pushKV("expired", false);
        o.pushKV("time", depth > 0 ? blockTime(height) : NullUniValue);
        o.pushKV("carrierTxid", c.hash.GetHex());
        o.pushKV("mainTxid", cs.second.main.IsNull() ? std::string() : cs.second.main.GetHex());
        o.pushKV("carrierOutcome", outcome);
        rows.push_back({ sortKey, o });
    }
    std::stable_sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) { return a.height > b.height; });
    UniValue arr(UniValue::VARR);
    for (size_t i = skip; i < rows.size() && (int)arr.size() < count; i++) arr.push_back(rows[i].o);
    return arr;
}

// N8: cf. DigiByte v9.26.7 src/rpc/digidollar.cpp listdigidollaraddresses (5539554c, b3cb2482): labels, per-address
// activity and the unused receive addresses.
UniValue yed_listaddresses(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "yed_listaddresses ( includeEmpty )\n"
            "\nThis wallet's Yellowback (YED) addresses: every address that holds YED or appears in the history, with its\n"
            "address-book label, the confirmed YED it holds, how many\n"
            "indexed transactions moved YED to or from it and the block time of the last one. Sorted by address.\n"
            "\nArguments:\n"
            "1. includeEmpty (boolean, optional, default false) also list the unused addresses yed_getnewaddress issued\n"
            "\nResult: [ { \"address\", \"label\", \"confirmedCents\", \"txCount\", \"lastUsed\" } ]  (lastUsed: UTC seconds, null when unused)\n");
    YellowbackWallet& yw = EnsureYW();
    YellowbackIndex& index = *yw.Index();
    const bool includeEmpty = params.size() > 0 && !params[0].isNull() && params[0].get_bool();
    LOCK2(cs_main, pwalletMain->cs_wallet);
    LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
    LOCK(index.cs_yellowback);
    EnsureHealthy(index);
    const yellowback::Params& p = index.GetParams();
    struct Entry { int64_t cents = 0; int64_t txCount = 0; int lastHeight = -1; };
    std::map<CScript, Entry> byScript;
    for (const YedCoin& c : yw.AllCoins()) byScript[c.token.scriptPubKey].cents += c.token.cents;
    index.View().Iterate("L", [&](const std::string& k, const std::string& raw) {
        TxLogRecord l;
        if (!DeserializeRecord(raw, l)) return true;
        std::set<CScript> touched;
        for (const AssignedOutput& a : l.assigned) if (yw.IsMineScript(a.scriptPubKey)) touched.insert(a.scriptPubKey);
        for (const AssignedOutput& a : l.spentTokens) if (yw.IsMineScript(a.scriptPubKey)) touched.insert(a.scriptPubKey);
        for (const CScript& s : touched) {
            Entry& e = byScript[s];
            e.txCount++;
            e.lastHeight = std::max(e.lastHeight, (int)l.height);
        }
        return true;
    });
    if (includeEmpty) {
        for (const auto& ab : pwalletMain->mapAddressBook) {
            if (ab.second.purpose != YED_RECEIVE_PURPOSE) continue;
            if (!std::get_if<CKeyID>(&ab.first) && !std::get_if<CPQKeyID>(&ab.first)) continue;
            byScript.insert(std::make_pair(GetScriptForDestination(ab.first), Entry()));
        }
    }
    const int chainTip = chainActive.Height();
    std::map<std::string, UniValue> out;             // sorted by address
    for (const auto& kv : byScript) {
        const std::string address = ScriptToYedAddress(kv.first, p);
        if (address.empty()) continue;
        const std::optional<CTxDestination> dest = HolderKey(kv.first);
        std::string label;
        if (dest.has_value()) {
            std::map<CTxDestination, CAddressBookData>::const_iterator ab = pwalletMain->mapAddressBook.find(dest.value());
            if (ab != pwalletMain->mapAddressBook.end()) label = ab->second.name;
        }
        const Entry& e = kv.second;
        UniValue o(UniValue::VOBJ);
        o.pushKV("address", address);
        o.pushKV("label", label);
        o.pushKV("confirmedCents", e.cents);
        o.pushKV("txCount", e.txCount);
        const bool timed = e.lastHeight >= 0 && e.lastHeight <= chainTip && chainActive[e.lastHeight] != nullptr;
        o.pushKV("lastUsed", timed ? UniValue(chainActive[e.lastHeight]->GetBlockTime()) : NullUniValue);
        out[address] = o;
    }
    UniValue arr(UniValue::VARR);
    for (const auto& kv : out) arr.push_back(kv.second);
    return arr;
}

UniValue yed_lockcoins(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error("yed_lockcoins\n\nRe-run Yellowback coin locking against the index (maintenance). Returns the outpoints locked.\n");
    YellowbackWallet& yw = EnsureYW();
    yw.Reconcile();
    UniValue arr(UniValue::VARR);
    for (const COutPoint& o : yw.Locked()) {
        UniValue e(UniValue::VOBJ);
        e.pushKV("txid", o.hash.GetHex());
        e.pushKV("vout", (int64_t)o.n);
        arr.push_back(e);
    }
    return arr;
}

UniValue yed_estimatesend(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "yed_estimatesend {\"yedaddress\":cents,...}|cents\n"
            "\nDry run of yed_send / yed_sendmany (H3): the YED inputs the floor-aware selector would spend, the change it\n"
            "would leave and, when the amount cannot be sent without change below the minimum output, the nearest workable\n"
            "amounts below and above it. Signs nothing, locks nothing, commits nothing, and never refuses for the amount.\n"
            "\nArguments:\n"
            "1. recipients  (object or numeric, required) {\"yedaddress\": cents, ...} as yed_sendmany, or just the total cents\n"
            "\nResult: { \"amountCents\", \"recipients\", \"workable\", \"stage\", \"inputs\": [{\"txid\",\"vout\",\"cents\"}],\n"
            "          \"selectedCents\", \"changeCents\", \"spendableCents\", \"networkFeeZat\", \"error\", \"alternatives\" }\n"
            "networkFeeZat is the YEC network fee the send pays (YED cannot pay it), priced on the selected YED inputs as yed_send\n"
            "prices it (a post-quantum YEC funding coin can raise it); null when the amount is not workable.\n");
    YellowbackWallet& yw = EnsureYW();
    YellowbackIndex& index = *yw.Index();
    int64_t amount = 0;
    size_t recipients = 1;
    if (params[0].isObject()) {
        const UniValue& obj = params[0].get_obj();
        const std::vector<std::string> keys = obj.getKeys();
        if (keys.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "no recipients");
        if (keys.size() > MAX_ASSIGNMENTS - 1) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("at most %u recipients per transaction", (unsigned)(MAX_ASSIGNMENTS - 1)));
        const yellowback::Params& p0 = index.GetParams();
        for (const std::string& name : keys) {
            ParseYedAddress(name, p0);                            // the same address check yed_sendmany applies
            const int64_t one = obj[name].get_int64();
            if (one < p0.minOutput || one > p0.maxOutput) {        // C-10: each amount before the sum (BuildTransfer's order)
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("bad-xfer-amount: each amount must be between %d and %d cents", p0.minOutput, p0.maxOutput));
            }
            amount += one;
        }
        recipients = keys.size();
    } else {
        amount = params[0].get_int64();
    }
    LOCK2(cs_main, pwalletMain->cs_wallet);
    LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
    LOCK(index.cs_yellowback);
    EnsureHealthy(index);
    const yellowback::Params& p = index.GetParams();
    if (amount < p.minOutput || amount > p.maxOutput) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("bad-xfer-amount: each amount must be between %d and %d cents", p.minOutput, p.maxOutput));
    }
    SendEstimate e = EstimateTransfer(yw, amount, recipients);
    UniValue o(UniValue::VOBJ);
    o.pushKV("amountCents", e.amountCents);
    o.pushKV("recipients", (int64_t)e.recipients);
    o.pushKV("workable", e.workable);
    o.pushKV("stage", e.stage);
    UniValue arr(UniValue::VARR);
    for (const YedCoin& c : e.inputs) {
        UniValue i(UniValue::VOBJ);
        i.pushKV("txid", c.outpoint.hash.GetHex());
        i.pushKV("vout", (int64_t)c.outpoint.n);
        i.pushKV("cents", c.token.cents);
        arr.push_back(i);
    }
    o.pushKV("inputs", arr);
    o.pushKV("selectedCents", e.selectedCents);
    o.pushKV("changeCents", e.changeCents);
    o.pushKV("spendableCents", e.spendableCents);
    o.pushKV("networkFeeZat", e.networkFeeZat.has_value() ? UniValue(e.networkFeeZat.value()) : NullUniValue);   // N6
    o.pushKV("error", e.error);
    if (e.workable) {
        o.pushKV("alternatives", NullUniValue);
    } else {
        UniValue alt(UniValue::VOBJ);
        alt.pushKV("below", e.below.has_value() ? UniValue(e.below.value()) : NullUniValue);
        alt.pushKV("above", e.above.has_value() ? UniValue(e.above.value()) : NullUniValue);
        o.pushKV("alternatives", alt);
    }
    return o;
}

UniValue yed_unlockcoin(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw std::runtime_error(
            std::string("yed_unlockcoin \"txid\" n \"acknowledgement\"\n"
            "\nUnlock one Yellowback-held outpoint (H5): the deliberate escape hatch, since lockunspent refuses to unlock one.\n"
            "The YED it carries is burned by the first transaction that spends it outside the overlay, and the next\n"
            "yed_lockcoins, reconciliation or restart locks it again.\n"
            "\nArguments:\n"
            "1. \"txid\"             (string, required)\n"
            "2. n                   (numeric, required) the output index\n"
            "3. \"acknowledgement\"  (string, required) exactly \"") + UNLOCK_ACKNOWLEDGEMENT + "\"\n"
            "\nResult: { \"txid\", \"vout\", \"unlocked\", \"wasYellowbackLocked\", \"cents\" }\n");
    YellowbackWallet& yw = EnsureYW();
    YellowbackIndex& index = *yw.Index();
    const uint256 txid = ParseHashV(params[0], "txid");
    const int n = params[1].get_int();
    if (n < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "vout must not be negative");
    if (params[2].get_str() != UNLOCK_ACKNOWLEDGEMENT) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("unlock-acknowledgement-missing: the third argument must be exactly \"") + UNLOCK_ACKNOWLEDGEMENT + "\"");
    }
    const COutPoint out(txid, (uint32_t)n);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    int64_t cents = 0;
    {
        LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
        LOCK(index.cs_yellowback);
        if (index.IsHealthy()) {
            std::optional<TokenRecord> t = State(index.View()).GetToken(out);
            if (t.has_value()) cents = t->cents;
        }
    }
    const bool was = yw.ReleaseLock(out);
    UniValue o(UniValue::VOBJ);
    o.pushKV("txid", txid.GetHex());
    o.pushKV("vout", (int64_t)n);
    o.pushKV("unlocked", true);
    o.pushKV("wasYellowbackLocked", was);
    o.pushKV("cents", cents);
    return o;
}

/** The CLAIM a cancel of `op` answers (CAN-2 + C4b, wallet side): the claim's refHeight R and the vault record a cancel
 *  is judged against (the CLAIMING record for a confirmed claim; the ACTIVE one a mempool claim spends). cs_main,
 *  mempool.cs and cs_yellowback held. Throws the RPC errors yed_buildcancel documents. */
struct CancelTarget
{
    int refHeight = 0;
    VaultRecord vault;
    bool confirmed = false;
};

CancelTarget CancelTargetOf(const State& st, const COutPoint& op)
{
    CancelTarget t;
    if (std::optional<IntentRecord> ir = st.GetIntent(op)) {
        if (ir->Role() != IntentRole::CLAIMANT) throw JSONRPCError(RPC_INVALID_PARAMETER, "the owner's residual intent is never cancelled (intent-cancel-residual)");
        std::optional<VaultRecord> v = st.GetVault(ir->vault);
        if (!v || v->Status() != VaultStatus::CLAIMING) throw JSONRPCError(RPC_INVALID_PARAMETER, "the intent's vault is not CLAIMING");
        t.refHeight = ir->claimRefHeight;
        t.vault = v.value();
        t.confirmed = true;
        return t;
    }
    std::shared_ptr<const CTransaction> claimp = mempool.get(op.hash);   // 6.20.0: mempool.get, not lookup
    vault::IntentParams ip;
    if (!claimp || op.n >= claimp->vout.size() || !vault::ParseIntent(claimp->vout[op.n].scriptPubKey, ip) || !(ip.tag == YED_TAG)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "not a YED claim intent (confirmed in the index or in the mempool)");
    }
    const CTransaction& claim = *claimp;
    std::optional<FoundPayload> fp = FindPayload(claim);
    std::optional<VaultRecord> v = claim.vin.empty() ? std::nullopt : st.GetVault(claim.vin[0].prevout);
    if (!fp.has_value() || fp->payload.type != PayloadType::REDEEM || !v.has_value() || v->Status() != VaultStatus::ACTIVE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "not a YED claim intent (confirmed in the index or in the mempool)");
    }
    t.refHeight = (int)fp->payload.refHeight;
    t.vault = v.value();
    return t;
}

/** The seq of `key` when it is a current member of the attestor set at `height` on the index's mirror (state.cpp
 *  CurrentMemberSeq, the primitive's IsCurrent), else nullopt. */
std::optional<uint16_t> CurrentMember(const State& st, const CPubKey& key, int64_t height)
{
    std::optional<AttestorSetRecord> set = st.GetAttestorSet();
    if (!set.has_value()) return std::nullopt;
    std::optional<std::pair<uint16_t, AttestorRecord>> found;
    for (const auto& r : st.Attestors()) {
        if (r.second.AttestorKey() == key) found = r;
    }
    if (!found.has_value()) return std::nullopt;
    const AttestorRecord& rec = found->second;
    if (rec.Status() == AttestorStatus::EJECTED || rec.Status() == AttestorStatus::WITHDRAWN || rec.bondSpentHeight != 0 || rec.Frozen()) return std::nullopt;
    if (height < (int64_t)rec.registerHeight + (int64_t)set->maturity) return std::nullopt;
    return found->first;
}

/** The 69-byte co-signature entry (price LE32 || sig65), as yed_signcancelcosign returns it and yed_buildcancel takes it. */
std::vector<unsigned char> CosignEntryBytes(const CancelCosignEntry& e)
{
    const std::vector<unsigned char> blob = EncodeCancelCosigns({ e });
    return std::vector<unsigned char>(blob.begin() + 4, blob.end());
}

UniValue yed_signcancelcosign(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw std::runtime_error(
            "yed_signcancelcosign \"intentoutpoint\" ( priceMicroUsd seq )\n"
            "\nCo-sign the attestor CANCEL of a YED claimant intent with the attestor member key held in this wallet (CAN-2 + C4b,\n"
            "the cancel-limit design): one 65-byte recoverable signature over (attestor set, intent, the claim's refHeight R,\n"
            "priceMicroUsd, blockHash(R)) -- the member's co-signature AND its signed price statement at R. A member whose regular\n"
            "attestation at R carries another price is slashable by EQV-1, so the price is locked through the equivocation guard\n"
            "(S16, yed_signattestation's): the default is the price this key already signed for R; a different price is refused\n"
            "(equivocation-guard); with no prior signature the price must be given and is recorded for R. The price must say the\n"
            "vault was NOT claimable (collateral x price >= debt x CLAIM_THRESHOLD), else cancel-statement-claimable. seq defaults to\n"
            "the first current member whose key this wallet holds. Hand the result's cosig to whoever builds the cancel\n"
            "(yed_buildcancel's cosigs).\n"
            "\nResult: { \"cosig\" (hex, 69 bytes), \"seq\", \"priceMicroUsd\", \"citedHeight\", \"reused\" }\n"
            + HelpExampleCli("yed_signcancelcosign", "\"txid:0\" 50000") + HelpExampleRpc("yed_signcancelcosign", "\"txid:0\", 50000"));
    YellowbackWallet& yw = EnsureYW();
    YellowbackIndex& index = *yw.Index();
    const std::string s = params[0].get_str();
    const size_t colon = s.find(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 >= s.size()) throw JSONRPCError(RPC_INVALID_PARAMETER, "intentoutpoint must be \"txid:n\"");
    int32_t nIntent = 0;
    if (!ParseInt32(s.substr(colon + 1), &nIntent) || nIntent < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "intentoutpoint must be \"txid:n\"");
    const COutPoint op(ParseHashV(UniValue(s.substr(0, colon)), "intentoutpoint"), (uint32_t)nIntent);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureWalletIsUnlocked();
    LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
    LOCK(index.cs_yellowback);
    EnsureHealthy(index);
    State st(index.View());
    const yellowback::Params& p = index.GetParams();
    const CancelTarget t = CancelTargetOf(st, op);
    // review A L-5 (design A-6): co-sign only a CONFIRMED claim -- a template spend's txid is malleable until it confirms
    if (!t.confirmed) throw JSONRPCError(RPC_MISC_ERROR, "claim-unconfirmed: co-sign the cancel once the claim has confirmed (its txid is malleable until then; re-sign after a reorg that re-mines it)");
    const int64_t next = (int64_t)IndexHeight(index) + 1;
    std::optional<uint16_t> seq;
    if (params.size() > 2 && !params[2].isNull()) {
        const int a = params[2].get_int();
        if (a < 0 || a > 65535) throw JSONRPCError(RPC_INVALID_PARAMETER, "seq must be a u16");
        seq = (uint16_t)a;
    } else {
        for (const auto& r : st.Attestors()) {
            if (pwalletMain->HaveKey(r.second.AttestorKey().GetID()) && CurrentMember(st, r.second.AttestorKey(), next) == r.first) { seq = r.first; break; }
        }
        if (!seq.has_value()) throw JSONRPCError(RPC_INVALID_PARAMETER, "attest-key-not-held: this wallet holds no current member key of the attestor set");
    }
    std::optional<AttestorRecord> rec = st.GetAttestor(seq.value());
    if (!rec.has_value()) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("attest-unknown-seq: no attestor with seq %u", (unsigned)seq.value()));
    if (CurrentMember(st, rec->AttestorKey(), next) != seq) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("attest-not-eligible: seq %u is not a current member of the attestor set", (unsigned)seq.value()));
    std::optional<Snapshot> snap = st.GetSnapshot((uint32_t)t.refHeight);
    if (!snap.has_value()) throw JSONRPCError(RPC_MISC_ERROR, strprintf("the claim's refHeight %d is not indexed", t.refHeight));
    // review A L-4: one block-hash source -- the index's Snapshots[R].blockHash (what consensus verifies against); the
    // guard below is keyed on the active chain's hash, so the two must agree (they do whenever the index is at the tip)
    const uint256 blockHash = snap->blockHash;
    const CBlockIndex* atR = (t.refHeight >= 0 && t.refHeight <= chainActive.Height()) ? chainActive[t.refHeight] : nullptr;
    if (!atR || atR->GetBlockHash() != blockHash)
        throw JSONRPCError(RPC_MISC_ERROR, "the Yellowback index and the active chain disagree at the claim's refHeight; retry when the index has caught up");
    // review A L-3 / B6: the guard is looked up by KEY, not by seq -- EQV-1 binds a statement to the key, so an attestation
    // this key signed at R under any seq (a member that left and rejoined with the same hot key) fixes the price
    std::optional<SignedAttestation> prior;
    for (const auto& r : st.Attestors()) {
        if (r.second.AttestorKey() != rec->AttestorKey()) continue;
        std::optional<SignedAttestation> one = yw.LookupSigned(r.first, (uint32_t)t.refHeight, blockHash);
        if (!one.has_value()) continue;
        if (prior.has_value() && prior->priceMicroUsd != one->priceMicroUsd)
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("equivocation-guard: this key already signed two prices for height %d", t.refHeight));
        prior = one;
    }
    int64_t price = 0;
    if (params.size() > 1 && !params[1].isNull()) {
        price = params[1].get_int64();
        if (prior.has_value() && prior->priceMicroUsd != (uint32_t)price)
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("equivocation-guard: seq %u already signed %u for height %d", (unsigned)prior->seq, prior->priceMicroUsd, t.refHeight));
    } else {
        if (!prior.has_value()) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("price-required: this key signed no price for the claim's refHeight %d; pass priceMicroUsd", t.refHeight));
        price = prior->priceMicroUsd;
    }
    if (price < PRICE_MIN || price > PRICE_MAX) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("attest-range: priceMicroUsd must be in [%d, %d]", PRICE_MIN, PRICE_MAX));
    if (IsUnderwater(t.vault.collateralZat, (MicroUsd)price, t.vault.mintedCents, p.claimThresholdBps))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("cancel-statement-claimable: at %d micro-USD the vault was claimable at refHeight %d; a cancel co-signature states it was not", price, t.refHeight));
    bool reused = false;
    try {
        SignAttestationGuarded(yw, seq.value(), price, t.refHeight, reused);   // S16: lock this key's price for R
    } catch (const std::runtime_error& e) {
        ThrowBuildError(e);
    }
    CKey key;
    if (!pwalletMain->GetKey(rec->AttestorKey().GetID(), key)) throw JSONRPCError(RPC_INVALID_PARAMETER, "attest-key-not-held: the member key is not in this wallet");
    CancelCosignEntry e;
    e.priceMicroUsd = (uint32_t)price;
    if (!vault::SignRecoverable(key, CancelCosignMessage(p.attestorSetId, op.hash, op.n, (uint32_t)t.refHeight, (uint32_t)price, blockHash), e.sig))
        throw JSONRPCError(RPC_WALLET_ERROR, "the co-signature failed");
    const std::vector<unsigned char> bytes = CosignEntryBytes(e);
    UniValue o(UniValue::VOBJ);
    o.pushKV("cosig", HexStr(bytes.begin(), bytes.end()));
    o.pushKV("seq", (int)seq.value());
    o.pushKV("priceMicroUsd", price);
    o.pushKV("citedHeight", t.refHeight);
    o.pushKV("reused", reused);
    return o;
}

UniValue yed_buildcancel(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "yed_buildcancel \"intentoutpoint\" ( [\"cosig\",...] )\n"
            "\nBuild the attestor CANCEL of a YED claimant intent before it matures (U-23, CAN-1): vault_buildcancel's\n"
            "transaction -- the claimed vault re-created at vout[0] -- with the refund of the claim's burn at vout[1], a token\n"
            "carrier paying the holder the burned YED came from (yed_getvault.refundHolder), then this wallet's fee inputs and\n"
            "change (unsigned). Collect the attestor set's signature with set_signcancel, then vault_send. A cancel without\n"
            "the refund is invalid (intent-cancel-no-refund), which is why vault_buildcancel refuses a YED intent. A claim\n"
            "still in the mempool can be cancelled too once all its inputs are confirmed (the holder and the burn are read from\n"
            "them; refused while one is unconfirmed or the index lags the tip). The whole burn goes to the holder of the\n"
            "claim's lowest-index YED input. Called again for\n"
            "the same intent it returns the same transaction while its fee inputs are unspent (members sign once).\n"
            "CAN-2 + C4b (the cancel-limit design): the cancel must also carry at least cancelsRequired co-signatures\n"
            "(yed_getvault.cancelsRequired: 1 for a vault's first cancel, one more for each cancel within CANCEL_QUIET, at most\n"
            "CANCEL_SIGNERS_MAX), each a distinct current member's yed_signcancelcosign result. With fewer it is refused\n"
            "(cancel-cosign-needed, naming how many). With enough, a carrier holding them is broadcast (CARRIER_VALUE) and the\n"
            "cancel spends it as its last input, signed (the CANCEL_COSIGN marker is the last output, so the set signature's\n"
            "SIGHASH_ALL|ANYONECANPAY digest is the same whatever co-signatures arrive: members still sign once). Collect more\n"
            "than required when you can: consensus counts the distinct valid entries and ignores the rest, so spares keep the\n"
            "cancel valid when a co-signer leaves before it confirms or a reorg adds an earlier cancel. An entry this RPC can\n"
            "already see would not count (malformed, another intent, a repeat, not a current member, a price out of range or\n"
            "claimable) is dropped and named in warnings; the call is refused only when fewer than cancelsRequired remain.\n"
            "\nResult: vault_buildcancel's {\"hex\", \"required\", \"cancelsetid\", \"deadline\", \"intentconfirmed\"} plus\n"
            "\"refund\": {\"vout\": 1, \"script\" (hex), \"cents\" (the claim's whole burn, re-issued to that script)},\n"
            "\"cancelsRequired\", \"cosigners\" (seqs, carrier order), \"carrierTxid\", \"warnings\" (optional: the dropped entries)\n"
            + HelpExampleCli("yed_buildcancel", "\"txid:0\"") + HelpExampleRpc("yed_buildcancel", "\"txid:0\""));
    YellowbackWallet& yw = EnsureYW();
    YellowbackIndex& index = *yw.Index();
    const std::string s = params[0].get_str();
    const size_t colon = s.find(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 >= s.size()) throw JSONRPCError(RPC_INVALID_PARAMETER, "intentoutpoint must be \"txid:n\"");
    int32_t nIntent = 0;
    if (!ParseInt32(s.substr(colon + 1), &nIntent) || nIntent < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "intentoutpoint must be \"txid:n\"");
    const COutPoint op(ParseHashV(UniValue(s.substr(0, colon)), "intentoutpoint"), (uint32_t)nIntent);
    std::vector<unsigned char> holder;
    Cents cents = 0;
    std::vector<CancelCosignEntry> entries;
    std::vector<uint16_t> cosigners;
    std::vector<std::string> warnings;
    int required = 0;
    int carrierRef = 0;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        LOCK(mempool.cs);              // lock order (N25): mempool.cs before cs_yellowback
        LOCK(index.cs_yellowback);
        EnsureHealthy(index);
        State st(index.View());
        if (std::optional<IntentRecord> ir = st.GetIntent(op)) {
            if (ir->Role() != IntentRole::CLAIMANT) throw JSONRPCError(RPC_INVALID_PARAMETER, "the owner's residual intent is never cancelled (intent-cancel-residual)");
            std::optional<VaultRecord> v = st.GetVault(ir->vault);
            if (!v || v->Status() != VaultStatus::CLAIMING) throw JSONRPCError(RPC_INVALID_PARAMETER, "the intent's vault is not CLAIMING");
            holder = ir->refundScript;
            cents = v->burnedCents;
        } else {
            // A claim still in the mempool: CAN-1's holder is the token at its lowest-index YED input, the refund its burn.
            std::shared_ptr<const CTransaction> claimp = mempool.get(op.hash);   // 6.20.0: mempool.get, not lookup
            vault::IntentParams ip;
            if (!claimp || op.n >= claimp->vout.size() || !vault::ParseIntent(claimp->vout[op.n].scriptPubKey, ip) ||
                !(ip.tag == YED_TAG)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "not a YED claim intent (confirmed in the index or in the mempool)");
            }
            const CTransaction& claim = *claimp;
            // The index holds only confirmed tokens: a YED input created by a mempool transaction would be invisible
            // here, and the lowest-index YED input -- the holder consensus records -- could be misread, so the RPC would
            // hand out a cancel that fails intent-cancel-no-refund (and a member's sign-once slot with it). Refuse until
            // every input of the claim is confirmed and the index is at the chain tip; then GetToken sees exactly the
            // tokens consensus will see, in vin order, and yedIn - assigned is the burn it will record.
            for (const CTxIn& in : claim.vin) {
                if (mempool.exists(in.prevout.hash))
                    throw JSONRPCError(RPC_MISC_ERROR, "the mempool claim spends an unconfirmed output: its refund holder is known once its inputs confirm (or once the claim does)");
            }
            if (IndexHeight(index) != chainActive.Height())
                throw JSONRPCError(RPC_MISC_ERROR, "the Yellowback index is behind the chain tip; retry when it has caught up");
            Cents yedIn = 0;
            for (const CTxIn& in : claim.vin) {
                if (std::optional<TokenRecord> t = st.GetToken(in.prevout)) {
                    if (holder.empty()) holder.assign(t->scriptPubKey.begin(), t->scriptPubKey.end());
                    yedIn += t->cents;
                }
            }
            std::optional<FoundPayload> fp = FindPayload(claim);
            cents = yedIn - (fp.has_value() ? fp->payload.AssignedCents() : 0);
        }
        if (holder.empty() || cents <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "the claim recorded no refund holder");
        // CAN-2 + C4b: the co-signatures, checked as state.cpp's CancelCosignsHold will at tip + 1 (wallet side)
        const yellowback::Params& p = index.GetParams();
        const CancelTarget t = CancelTargetOf(st, op);
        const int64_t next = (int64_t)IndexHeight(index) + 1;
        required = CancelsRequired(t.vault, p, next);
        std::optional<Snapshot> snap = st.GetSnapshot((uint32_t)t.refHeight);
        if (!snap.has_value()) throw JSONRPCError(RPC_MISC_ERROR, strprintf("the claim's refHeight %d is not indexed", t.refHeight));
        std::set<CPubKey> seen;
        const UniValue cos = params.size() > 1 && !params[1].isNull() ? params[1].get_array() : UniValue(UniValue::VARR);
        // round 2 (coordinator): an entry that would not count is dropped with a warning naming it and why; the call is
        // refused only when fewer than cancelsRequired remain
        auto drop = [&](size_t i, const std::string& why) { warnings.push_back(strprintf("cosigs[%u] dropped: %s", (unsigned)i, why)); };
        for (size_t i = 0; i < cos.size(); i++) {
            const std::string h = cos[i].isStr() ? cos[i].get_str() : std::string();
            std::optional<std::vector<CancelCosignEntry>> one;
            if (IsHex(h)) {
                std::vector<unsigned char> blob{ 'Y', 'C', CANCEL_COSIGN_VERSION, 1 };
                const std::vector<unsigned char> b = ParseHex(h);
                blob.insert(blob.end(), b.begin(), b.end());
                one = DecodeCancelCosigns(blob);
            }
            if (!one.has_value()) { drop(i, "cancel-cosign-malformed: not a 69-byte co-signature"); continue; }
            const CancelCosignEntry& e = one->front();
            CPubKey key;
            const uint256 msg = CancelCosignMessage(p.attestorSetId, op.hash, op.n, (uint32_t)t.refHeight, e.priceMicroUsd, snap->blockHash);
            if (!vault::RecoverSig(msg, e.sig, key)) { drop(i, "cancel-cosign-malformed: does not sign this intent's cancel"); continue; }
            if (seen.count(key)) { drop(i, strprintf("a repeat of key %s", HexStr(key.begin(), key.end()))); continue; }
            std::optional<uint16_t> seq = CurrentMember(st, key, next);
            if (!seq.has_value()) {
                drop(i, strprintf("cancel-cosign-not-member: key %s is not a current member of the attestor set at height %d", HexStr(key.begin(), key.end()), (int)next));
                continue;
            }
            if ((MicroUsd)e.priceMicroUsd < PRICE_MIN || (MicroUsd)e.priceMicroUsd > PRICE_MAX) {
                drop(i, strprintf("attest-range: seq %u states %u micro-USD, outside [%d, %d]", (unsigned)seq.value(), e.priceMicroUsd, PRICE_MIN, PRICE_MAX));
                continue;
            }
            if (IsUnderwater(t.vault.collateralZat, (MicroUsd)e.priceMicroUsd, t.vault.mintedCents, p.claimThresholdBps)) {
                drop(i, strprintf("cancel-statement-claimable: seq %u states %u micro-USD, at which the vault was claimable at refHeight %d",
                                  (unsigned)seq.value(), e.priceMicroUsd, t.refHeight));
                continue;
            }
            if (entries.size() >= CANCEL_COSIGN_MAX) { drop(i, strprintf("beyond the carrier's %u entries", (unsigned)CANCEL_COSIGN_MAX)); continue; }
            seen.insert(key);
            entries.push_back(e);
            cosigners.push_back(seq.value());
        }
        if ((int)entries.size() < required) {
            std::string why;
            for (const std::string& w : warnings) why += "; " + w;
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("cancel-cosign-needed: this cancel needs %d co-signature(s) of distinct current members (cancelsRequired), %d valid given (yed_signcancelcosign)%s",
                                                                required, (int)entries.size(), why));
        }
        carrierRef = IndexHeight(index);
    }
    // the cancel itself first (its fee inputs chosen and locked by the sign-once build memo), then the carrier
    const CScript to(holder.begin(), holder.end());
    UniValue o = BuildYedIntentCancel(op, { CTxOut(index.GetParams().tokenValue, to), CTxOut(0, PayloadScript(EncodePayload(Payload::CancelCosign()))) });
    // the carrier holding the co-signatures (broadcast now; the cancel spends it as a mempool child). An outstanding
    // carrier of this wallet with exactly these bytes is reused, so the same co-signatures give the same transaction
    // (sign once; the carrier signature is deterministic)
    const std::vector<unsigned char> blob = EncodeCancelCosigns(entries);
    std::optional<CarrierRecord> reuse;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        for (const CarrierRecord& c : yw.OutstandingCarriers()) {
            if (c.bundle != blob || !c.selector.empty()) continue;
            const CCoins* coins = pcoinsTip->AccessCoins(c.outpoint.hash);
            const bool unspentInChain = coins && coins->IsAvailable(c.outpoint.n);
            const bool inMempool = mempool.exists(c.outpoint.hash);
            bool spentInMempool = false;
            {
                LOCK(mempool.cs);
                spentInMempool = mempool.mapNextTx.count(c.outpoint) > 0;
            }
            if ((unspentInChain || inMempool) && !spentInMempool) { reuse = c; break; }
        }
    }
    const CarrierRecord carrier = reuse.has_value() ? reuse.value() : CarrierStep(yw, blob, carrierRef, std::vector<unsigned char>(), "");
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        CTransaction built;
        try {
            DecodeHexTx(built, o["hex"].get_str());      // 6.20.0: throws instead of returning false
        } catch (const std::exception&) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "the cancel does not decode");
        }
        CMutableTransaction mtx(built);
        mtx.vin.push_back(CTxIn(carrier.outpoint, CScript(), CTxIn::SEQUENCE_FINAL));
        try {
            SignCarrierInput(mtx, (unsigned int)mtx.vin.size() - 1, carrier, *pwalletMain, SignerBranchId());
        } catch (const std::runtime_error& e) {
            ThrowBuildError(e);
        }
        o.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
    }
    UniValue r(UniValue::VOBJ);
    r.pushKV("vout", 1);
    r.pushKV("script", HexStr(to.begin(), to.end()));
    r.pushKV("cents", cents);
    o.pushKV("refund", r);
    o.pushKV("cancelsRequired", required);
    UniValue cs(UniValue::VARR);
    for (uint16_t q : cosigners) cs.push_back((int)q);
    o.pushKV("cosigners", cs);
    o.pushKV("carrierTxid", carrier.outpoint.hash.GetHex());
    if (!warnings.empty()) {
        UniValue w(UniValue::VARR);
        for (const std::string& x : warnings) w.push_back(x);
        o.pushKV("warnings", w);
    }
    return o;
}

static const CRPCCommand commands[] =
{ //  category     name                    actor (function)        okSafeMode
  //  -----------  ----------------------  ----------------------  ----------
    { "yellowback", "yed_getnewaddress",    &yed_getnewaddress,     true  },
    { "yellowback", "yed_validateaddress",  &yed_validateaddress,   true  },
    { "yellowback", "yed_getbalance",       &yed_getbalance,        false },
    { "yellowback", "yed_listunspent",      &yed_listunspent,       false },
    { "yellowback", "yed_mint",             &yed_mint,              false },
    { "yellowback", "yed_send",             &yed_send,              false },
    { "yellowback", "yed_sendmany",         &yed_sendmany,          false },
    { "yellowback", "yed_redeem",           &yed_redeem,            false },
    { "yellowback", "yed_claim",            &yed_claim,             false },
    { "yellowback", "yed_listpositions",    &yed_listpositions,     false },
    { "yellowback", "yed_listtransactions", &yed_listtransactions,  false },
    { "yellowback", "yed_listaddresses",    &yed_listaddresses,     false },   // N8
    { "yellowback", "yed_lockcoins",        &yed_lockcoins,         false },
    { "yellowback", "yed_estimatesend",     &yed_estimatesend,      false },
    { "yellowback", "yed_estimateredeem",   &yed_estimateredeem,    false },   // IT-9
    { "yellowback", "yed_unlockcoin",       &yed_unlockcoin,        false },
    { "yellowback", "yed_buildcancel",      &yed_buildcancel,       false },   // CAN-1 (03/H-1), CAN-2 (cosigs)
    { "yellowback", "yed_signcancelcosign", &yed_signcancelcosign,  false },   // CAN-2 + C4b (the cancel-limit design)
    // v3 (plan §4.5)
    { "yellowback", "yed_claimnotice",      &yed_claimnotice,       false },
    { "yellowback", "yed_sweepcarriers",    &yed_sweepcarriers,     false },
    { "yellowback", "yed_registerattestor", &yed_registerattestor,  false },
    { "yellowback", "yed_withdrawbond",     &yed_withdrawbond,      false },
    { "yellowback", "yed_revive",           &yed_revive,            false },
    { "yellowback", "yed_reportequivocation", &yed_reportequivocation, false },
    { "yellowback", "yed_signattestation",  &yed_signattestation,   false },
};

void RegisterYellowbackWalletRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
