// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_YELLOWBACK_TXBUILDER_H
#define YCASH_YELLOWBACK_TXBUILDER_H

#include "amount.h"
#include "coins.h"
#include "key.h"
#include "keystore.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "transaction_builder.h"
#include "yellowback/script.h"
#include "yellowback/state.h"
#include "yellowback/wallet.h"

#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

class CReserveKey;

/**
 * Yellowback v2 transaction builder (plan §3.5, §4.2a, §4.6). Built by hand
 * from public CWallet primitives, as z_sendmany and the atomic-swap RPCs do:
 * CreateNewContextualCMutableTransaction for version/group/expiry, a flat
 * network fee (YELLOWBACK_FEE), smallest-first confirmed inputs, SignSignature
 * for P2PKH inputs and a manual ZIP-243 sighash for the vault input
 * (SignVaultSpend). Every Build* requires cs_main, cs_wallet and
 * cs_yellowback held by the caller, in that order. Failures throw
 * std::runtime_error whose message begins with a stable identifier of
 * doc/yellowback-rpc.md (`insufficient-yed`, `change-floor`, `vault-locked`,
 * …); the RPC layer maps the identifier to an RPC error code.
 *
 * Two layers: the pure shape functions (MintOutputs, PlanVaultSpend,
 * SignVaultSpend) take explicit inputs and are unit-tested without a wallet
 * (yellowback_txbuilder_tests.cpp); the Build* functions select coins,
 * draw keys and choose the payee from the wallet and the index.
 *
 * Sapling shapes (§4.6): a mint funded from a ys1… address and a vault
 * spend paying its collateral to one are assembled in Ycash's
 * TransactionBuilder (proofs, binding signature) and returned unbuilt in
 * BuiltTx::builder. The caller runs FinishSapling() with NO lock held (one
 * spend proof per note, seconds each), then re-locks: a mint is complete, a
 * vault spend still needs SignVaultSpend(). ZIP-243 never covers a
 * scriptSig, so signing the transparent inputs after Build() keeps the
 * binding signature valid (the transaction_builder extension, mapping §13.5).
 *
 * DigiByte's builder (ref/digibyte/src/digidollar/txbuilder.cpp) assembles
 * Taproot vaults and signs BIP341 sighashes; here the vault is the P2SH
 * OP_IF script of §3.4 and the owner signature is ZIP-243 over the vault
 * script, the vault's nValue and the epoch branch id (mapping §13.1).
 */
namespace yellowback {

/** What a BuiltTx is (the RPC that made it; the wallet's own view). */
enum class BuiltKind { MINT, TRANSFER, REDEEM, RELEASE, CLAIM, SWEEP,
                       // v3 (plan §3.5)
                       CARRIER, NOTICE, REGISTER, WITHDRAW, REVIVE, EQUIVOCATION, SWEEP_CARRIERS };

struct BuiltTx
{
    CMutableTransaction tx;
    BuiltKind kind;
    std::vector<COutPoint> ownYedOutputs;   //!< outputs to lock before CommitTransaction (stage i)
    std::set<COutPoint> yedInputs;          //!< YED outpoints consumed
    CPubKey freshKey;                       //!< the key drawn for this transaction (owner / token / collateral / change)
    std::string warning;                    //!< MINT: the keypool-low nag ("" if none)
    // Sapling shape: set by BuildMint/BuildRedeem/BuildClaim/BuildSweep, consumed by FinishSapling
    std::optional<TransactionBuilder> builder;
    std::string fundedFrom;                 //!< MINT: "transparent" | "sapling"
    std::string collateralTo;               //!< vault spends: the destination address as given or drawn

    // Common (§4.2a: refHeight, feeZat, payee, termClass, claimHeight, path)
    int refHeight;                          //!< R = indexTip - REF_LAG
    CAmount feeZat;                         //!< the enforcement fee paid (0 under FEE-0, for a release and a sweep)
    std::optional<CKeyID> payee;            //!< the fee output's key hash (nullopt = no fee output)
    int feeVout;                            //!< index of the fee output, -1 if none
    int termClass;                          //!< 0/1/2 = A/B/C
    uint32_t lockHeight;
    uint32_t claimHeight;
    std::string path;                       //!< "owner" | "claim" | "" (vault spends only)

    // MINT
    CAmount collateralZat;                  //!< vout[0].nValue of the mint

    // Vault spends (REDEEM / RELEASE / CLAIM / SWEEP)
    CAmount collateralOut;                  //!< zat paid to the destination
    int64_t burnCents;                      //!< YED burned (the debt for REDEEM/CLAIM, 0 otherwise)
    int64_t changeCents;                    //!< YED change (TRANSFER / REDEEM / CLAIM)
    int64_t extraBurnCents;                 //!< H4: sub-dollar remainder burned on top of the debt (REDEEM / CLAIM), else 0
    int changeVout;                         //!< index of the YED change output, -1 if none
    CScript vaultScript;                    //!< signing material for SignVaultSpend
    CAmount vaultValue;
    CPubKey ownerPubKey;
    std::vector<std::pair<CScript, CAmount>> yedPrevs;     //!< scriptPubKey/value of vin[1..] (YED inputs)

    // v3 (plan §3.5, §4.5): the carrier and what the bundle decided
    std::optional<CarrierRecord> carrier;   //!< the carrier this transaction spends (MINT / CLAIM / NOTICE / EQUIVOCATION); CARRIER: the record to persist
    int carrierVin;                         //!< index of the carrier input, -1 if none
    bool armed;                             //!< ArmedAt(R): the bundle was read
    std::vector<uint16_t> bundleSeqs;       //!< the verified attestations' seqs (A)
    std::optional<MicroUsd> xMint, aMint, pMint, xClaim, aClaim, pClaim, pEmerg;
    std::string source;                     //!< MINT: "x" | "a" (which price bound pMint)
    std::optional<uint16_t> attestPayee;    //!< AFEE-W's seq, nullopt under AFEE-0
    std::optional<CKeyID> attestPayeeKey;   //!< its bondPubKey hash (the bondKeyAddress paid)
    CAmount attestFeeZat;                   //!< 0 under AFEE-0
    int attestFeeVout;                      //!< -1 if none
    CAmount residualZat;                    //!< CLAIM: RED-5's residual paid to the owner (0 when none due)
    int residualVout;
    std::string claimPath;                  //!< CLAIM: "a" | "b"
    int emergencyOpenAt;                    //!< NOTICE: R + EMERGENCY_PERSIST
    // REGISTER / WITHDRAW / REVIVE / EQUIVOCATION
    uint16_t seq;
    CPubKey attestorPubKey, bondPubKey;
    CScript bondScript;
    int bondVin;                            //!< WITHDRAW: the bond input (0), -1 otherwise
    CAmount bondZat;
    uint32_t bondLocktime;
    uint8_t flags;
    Attestation attestation;                //!< REVIVE: the attestation signed; EQUIVOCATION: attA
    Attestation attestationB;               //!< EQUIVOCATION: attB
    size_t sweptCarriers;                   //!< SWEEP_CARRIERS: inputs
    std::vector<CarrierRecord> sweptRecords;    //!< SWEEP_CARRIERS: the carriers spent
    std::vector<CarrierRecord> staleRecords;    //!< SWEEP_CARRIERS: lapsed records whose outpoint is already spent (to forget)

    BuiltTx() : kind(BuiltKind::TRANSFER), refHeight(0), feeZat(0), feeVout(-1), termClass(0), lockHeight(0), claimHeight(0),
                collateralZat(0), collateralOut(0), burnCents(0), changeCents(0), extraBurnCents(0), changeVout(-1), vaultValue(0),
                carrierVin(-1), armed(false), attestFeeZat(0), attestFeeVout(-1), residualZat(0), residualVout(-1), emergencyOpenAt(0),
                seq(0), bondVin(-1), bondZat(0), bondLocktime(0), flags(0), sweptCarriers(0) {}
    bool NeedsProving() const { return builder.has_value(); }
    bool IsVaultSpend() const { return kind == BuiltKind::REDEEM || kind == BuiltKind::RELEASE || kind == BuiltKind::CLAIM || kind == BuiltKind::SWEEP; }
};

// ---------------------------------------------------------------- pure shapes (§3.5; no wallet, no chain)

/** The MINT's fixed inputs. */
struct MintShape
{
    Cents cents;
    int termClass;
    uint32_t lockHeight;
    uint32_t claimHeight;                   //!< lockHeight + GRACE
    int refHeight;
    CPubKey owner;                          //!< vault ownerPubKey and the token output's key
    CAmount collateralZat;                  //!< vout[0].nValue (>= requiredZat, >= 4 * FEE_MIN, rounded)
    std::optional<CKeyID> payee;            //!< nullopt under FEE-0: no fee output, feeVout = 0xFF
    CAmount feeZat;                         //!< FeeZat(collateralZat)
    std::optional<CKeyID> attestPayee;      //!< v3 AFEE-1: P2PKH(bondPubKey(s)) of attestFeeZat after the pool fee; nullopt under AFEE-0
    CAmount attestFeeZat;

    MintShape() : cents(0), termClass(0), lockHeight(0), claimHeight(0), refHeight(0), collateralZat(0), feeZat(0), attestFeeZat(0) {}
};

/**
 * vout[0] P2SH(vaultScript), vout[1] P2PKH(owner) TOKEN_VALUE, vout[2] OP_RETURN MINT
 * payload (feeVout = 3 or 0xFF), vout[3] P2PKH(payee) feeZat when there is a payee, then
 * (v3) P2PKH(attestPayee) attestFeeZat when there is one (vout[4] with both fees, vout[3]
 * under FEE-0). `feeVout` / `attestFeeVout` receive the index or -1. Throws on an unencodable shape.
 */
std::vector<CTxOut> MintOutputs(const MintShape& shape, int& feeVout, int* attestFeeVout = nullptr);

/** A vault spend's fixed inputs (REDEEM, CLAIM, the VOID release and the SWEEP). */
struct VaultSpendShape
{
    COutPoint vaultOut;
    CScript vaultScript;
    CAmount vaultValue;
    uint32_t lockHeight;
    uint32_t claimHeight;
    bool ownerPath;                         //!< owner scriptSig + nLockTime = lockHeight; else claim scriptSig + claimHeight
    bool withPayload;                       //!< REDEEM/CLAIM: burn + payload + fee; false = release/sweep (no burn, no fee, no payload)
    int refHeight;                          //!< REDEEM payload refHeight
    std::optional<CKeyID> payee;            //!< nullopt under FEE-0 (and always for a release/sweep)
    CAmount feeZat;
    std::vector<YedCoin> yedInputs;         //!< vin[1..]
    Cents changeCents;                      //!< 0 = no YED change output
    CScript changeScript;                   //!< the YED change P2PKH when changeCents > 0
    std::optional<CScript> collateralScript;//!< nullopt = a Sapling destination (the caller adds the note)
    CAmount networkFee;                     //!< YELLOWBACK_FEE
    // v3 (claim path when ARMED)
    std::optional<CKeyID> attestPayee;      //!< AFEE-1: P2PKH(bondPubKey(s)) of attestFeeZat; nullopt under AFEE-0
    CAmount attestFeeZat;
    CAmount residualZat;                    //!< RED-5: > 0 => an output P2PKH(ownerPubKey) of residualZat
    CPubKey ownerPubKey;                    //!< the residual's payee
    CAmount carrierValue;                   //!< CARRIER_VALUE when a carrier input is present (its value joins the inputs), else 0

    VaultSpendShape() : vaultValue(0), lockHeight(0), claimHeight(0), ownerPath(true), withPayload(true), refHeight(0), feeZat(0),
                        changeCents(0), networkFee(0), attestFeeZat(0), residualZat(0), carrierValue(0) {}
};

/** The transparent half of a vault spend, applied to a CMutableTransaction or a TransactionBuilder. */
struct VaultSpendPlan
{
    std::vector<CTxIn> vin;                 //!< vin[0] the vault (nSequence 0xFFFFFFFE), then the YED inputs
    std::vector<CTxOut> vout;               //!< transparent outputs in §3.5 order (without the Sapling collateral note)
    CAmount collateralOut;                  //!< to the destination (transparent vout[0] or the Sapling note)
    uint32_t nLockTime;
    int feeVout;                            //!< -1 if none
    int changeVout;                         //!< -1 if none
    int64_t burnCents;                      //!< yedIn - changeCents
    int attestFeeVout;                      //!< v3: -1 if none
    int residualVout;                       //!< v3: -1 if none

    VaultSpendPlan() : collateralOut(0), nLockTime(0), feeVout(-1), changeVout(-1), burnCents(0), attestFeeVout(-1), residualVout(-1) {}
};

/**
 * Transparent destination: vout[0] collateral, [fee], [YED change], [attestor fee], [residual],
 * payload — v2's order with the v3 outputs before the payload; when the attestor fee would land at
 * index 1 (no pool fee, no change) the payload moves before it, since AFEE-1 excludes vout[1].
 * Sapling destination: [YED change] at vout[0], [payload], [fee], [attestor fee], [residual] (S11) —
 * the fee outputs and the residual are always transparent and the *Vout fields name them
 * wherever they land (M13). Release/sweep: one collateral output (transparent) or none (Sapling).
 * collateralOut = vaultValue + carrierValue + Σ yed nValue - networkFee - feeZat - attestFeeZat -
 * residualZat - TOKEN_VALUE × change outputs; throws `vault-value-too-small` if that is not positive.
 */
VaultSpendPlan PlanVaultSpend(const VaultSpendShape& shape);

/**
 * Owner path: sign vin[0] with the vault owner's key over the vault script, the vault's nValue and
 * `branchId` (ZIP-243 binds both, mapping §13.1) and set `<sig> OP_1 <script>`; claim path: set
 * `OP_0 <script>`. Then SignSignature every YED input (out.yedPrevs) with the same branch id. The
 * keystore must hold the owner key (owner path) and the YED keys. Sapling shape: FinishSapling()
 * first. Fills out.ownYedOutputs with the change output. A CWallet is a CKeyStore.
 */
void SignVaultSpend(BuiltTx& out, const CKeyStore& keystore, uint32_t branchId, bool ownerPath);

// ---------------------------------------------------------------- v3 pure pieces (§3.4, §3.5)

/**
 * Sign input `nIn` of `mtx` as the carrier `c` (W7, R2): ZIP-243 SignatureHash with scriptCode =
 * CarrierScript(c.pk, SHA256(c.bundle)) and amount CARRIER_VALUE under `branchId`, then the
 * push-only scriptSig `<bundle> <sig> <carrierScript>`. The keystore must hold c.pk's key.
 */
void SignCarrierInput(CMutableTransaction& mtx, unsigned int nIn, const CarrierRecord& c, const CKeyStore& keystore, uint32_t branchId);

/** SHA256 of the bundle bytes (the carrier script's commitment). */
uint256 BundleHash(const std::vector<unsigned char>& bundle);

/** The carrier funding output: P2SH(CarrierScript(pk, SHA256(bundle))) of `value`. */
CTxOut CarrierOutput(const CPubKey& pk, const std::vector<unsigned char>& bundle, CAmount value);

/**
 * Sign input `nIn` as the bond (§3.5 ATTESTOR withdrawal): ZIP-243 over BondScript(pk, locktime) with the
 * bond's value; scriptSig `<sig> <bondScript>`; the caller sets nLockTime = locktime and nSequence != final.
 */
void SignBondInput(CMutableTransaction& mtx, unsigned int nIn, const CPubKey& pk, uint32_t locktime, CAmount value,
                   const CKeyStore& keystore, uint32_t branchId);

/**
 * The wallet's dry run (§4.6): EvaluateBlock over the one-transaction pseudo-block at `height`
 * (MempoolCheck's shape) on an overlay of `view` — MINT-1..10 for a MINT, RED-1..5 for a vault
 * spend, NOT-1 / EQV-1 / REV-1 / REG-A1 for the v3 types. Returns the transaction's TxLog record
 * (verdict OK on success) or nullopt when the evaluation wrote nothing for it (a NOTICE, an
 * EQUIVOCATION or a REVIVE that failed its rule is non-Yellowback and leaves no record). Pure.
 */
std::optional<TxLogRecord> DryRun(StateView& view, const Params& params, const CTransaction& tx, int height, SigCache* cache = nullptr);

/**
 * BUNDLE-1 for explicit bundle bytes at (R, selector): the bundle is wrapped in a one-input
 * skeleton transaction whose carrier scriptSig carries it, then VerifyTxBundle. `selected`
 * receives selected(R, selector). Pure.
 */
BundleVerdict VerifyBundleBytes(const StateView& view, const Params& params, const std::vector<unsigned char>& bundle,
                                int refHeight, const std::vector<unsigned char>& selector, std::vector<uint16_t>* selected = nullptr);

// ---------------------------------------------------------------- wallet builders (cs_main, cs_wallet, cs_yellowback)

/**
 * v3: what the carrier step needs to know before it spends anything (yed_mint's preflight): R,
 * whether R is armed, the bundle verdict and the prices. Refuses `bundle-insufficient`,
 * `bundle-malformed`, `mint10-diverged` and the MINTPOL-1 identifiers BEFORE any transaction is
 * built. Unarmed: the bundle is ignored (the carrier is still created, one code path).
 */
struct MintPreflight
{
    int refHeight;
    bool armed;
    std::vector<unsigned char> bundle;      //!< the bytes the carrier will commit to (empty when unarmed)
    std::vector<uint16_t> bundleSeqs;
    std::optional<MicroUsd> xMint, aMint, pMint;
    std::string source;
    MintPreflight() : refHeight(0), armed(false) {}
};
MintPreflight PreflightMint(YellowbackWallet& yw, Cents cents, int lockBlocks, const std::optional<std::vector<unsigned char>>& bundle,
                            const std::string& from = "");

/** v3: the claim's preflight: R = index tip, the bundle verdict at (R, vault outpoint), RED-4 by clause and the residual. */
struct ClaimPreflight
{
    int refHeight;
    bool armed;
    std::vector<unsigned char> bundle;
    std::vector<unsigned char> selector;
    std::vector<uint16_t> bundleSeqs;
    std::optional<MicroUsd> xClaim, aClaim, pClaim, pEmerg, xMint, aMint;
    std::string claimPath;                  //!< "a" | "b"
    CAmount residualZat;
    ClaimPreflight() : refHeight(0), armed(false), residualZat(0) {}
};
ClaimPreflight PreflightClaim(YellowbackWallet& yw, const uint256& vaultTxid, const std::optional<std::vector<unsigned char>>& bundle);

/** v3: the notice's preflight (NOT-1 at R = index tip): `notice-standing`, `notice-not-underwater`, `bundle-insufficient`. */
struct NoticePreflight
{
    int refHeight;
    std::vector<unsigned char> bundle;
    std::vector<unsigned char> selector;
    std::vector<uint16_t> bundleSeqs;
    std::optional<MicroUsd> xClaim, aClaim, pEmerg;
    int emergencyOpenAt;
    NoticePreflight() : refHeight(0), emergencyOpenAt(0) {}
};
NoticePreflight PreflightNotice(YellowbackWallet& yw, const uint256& vaultTxid, const std::optional<std::vector<unsigned char>>& bundle);

/**
 * v3, the carrier step (W7): one output P2SH(CarrierScript(freshKey, SHA256(bundle))) of
 * CARRIER_VALUE with nExpiryHeight = R + REF_WINDOW, funded from confirmed transparent YEC
 * (`from` "" or an s1… address) or from a ys1… address (Sapling shape; FinishSapling first).
 * out.carrier holds the record to persist once the txid is known (RecordCarrier); for the
 * Sapling shape the outpoint is filled by FinishSapling().
 */
BuiltTx BuildCarrier(YellowbackWallet& yw, const std::vector<unsigned char>& bundle, int refHeight,
                     const std::vector<unsigned char>& selector, CReserveKey& reservekey, const std::string& from = "");

/**
 * The §3.5 MINT of `cents` YED locked for `lockBlocks` (the class follows, V19) at R =
 * carrier.refHeight, after the MINTPOL-1 gate, spending the confirmed `carrier` as vin[last]
 * (the only transparent input when `from` is Sapling) and, when ARMED at R and A ≠ ∅, paying
 * the attestor fee to AFEE-W's bondPubKey. `from`: "" = any confirmed transparent output; an
 * s1… address = that address's outputs only; a ys1… address = its Sapling notes (Sapling shape).
 * The transparent shape is signed and dry-run (MINT-1..10) here; the Sapling shape after
 * FinishSapling() via SignBuiltCarrier() + DryRunBuilt().
 */
BuiltTx BuildMint(YellowbackWallet& yw, Cents cents, int lockBlocks, CReserveKey& reservekey, const std::string& from,
                  const CarrierRecord& carrier);

/** recipients: P2PKH script -> cents. At most 14 recipients (one assignment slot is kept for change). */
BuiltTx BuildTransfer(YellowbackWallet& yw, const std::vector<std::pair<CScript, int64_t>>& recipients, CReserveKey& reservekey);

/**
 * ACTIVE vault: the owner-path REDEEM (burn = the debt, fee output, payload). VOID vault: the
 * §3.5 VOID RELEASE (owner path, no burn, no fee, no payload; L14). `to`: "" = a fresh
 * transparent key; an s1… address; a ys1… address (Sapling shape). Returned UNSIGNED: call
 * FinishSapling() first for the Sapling shape (no lock held), then SignVaultSpend(…, true).
 */
BuiltTx BuildRedeem(YellowbackWallet& yw, const uint256& vaultTxid, const std::string& to = "");

/**
 * The claim-path spend of somebody's underwater ACTIVE vault from this wallet's YED, spending the
 * confirmed `carrier` (never vin[0]) with the attestor fee and the RED-5 residual when due.
 * Unsigned; SignVaultSpend(…, false) signs the vault, the YED inputs and the carrier.
 */
BuiltTx BuildClaim(YellowbackWallet& yw, const uint256& vaultTxid, const std::string& to, const CarrierRecord& carrier);

/** v3 CLAIM_NOTICE (§3.5): confirmed YEC inputs plus the carrier; the 0x06 payload and change. Signed. */
BuiltTx BuildClaimNotice(YellowbackWallet& yw, const uint256& vaultTxid, CReserveKey& reservekey, const CarrierRecord& carrier);

/** v3 ATTESTOR_REGISTER (§3.5): vout[0] the bond P2SH of bondZat, vout[1] the 0x05 payload, change; two fresh keys. Signed. */
BuiltTx BuildRegisterAttestor(YellowbackWallet& yw, CAmount bondZat, int lockBlocks, uint8_t flags, CReserveKey& reservekey);

/** v3 bond withdrawal: the bond input signed by hand, nLockTime = bondLocktime, to `to` ("" = a fresh own address; s1…; ys1… Sapling shape). */
BuiltTx BuildWithdrawBond(YellowbackWallet& yw, uint16_t seq, const std::string& to = "");

/**
 * v3 ATTESTOR_REVIVE (§3.5): one attestation for citedHeight = tip - REF_LAG signed with the hot key
 * through the signing guard (S16), payload 0x08, funded from confirmed YEC, change. Signed.
 */
BuiltTx BuildRevive(YellowbackWallet& yw, uint16_t seq, MicroUsd priceMicroUsd, CReserveKey& reservekey);

/** v3 EQUIVOCATION (§3.5): the carrier (whose bundle is exactly {a, b}) plus YEC; payload 0x07; change. Signed. EQV-1 is checked by CheckEquivocation first. */
BuiltTx BuildEquivocation(YellowbackWallet& yw, const Attestation& a, const Attestation& b, CReserveKey& reservekey, const CarrierRecord& carrier);

/** EQV-1's conditions for two attestations on this chain; throws `not-equivocation: <which>` (cs_yellowback held). */
void CheckEquivocation(YellowbackWallet& yw, const Attestation& a, const Attestation& b);

/** v3: every lapsed carrier swept into one output to a fresh own key (yed_sweepcarriers). Throws `nothing-to-sweep` when there is none. Signed. */
BuiltTx BuildSweepCarriers(YellowbackWallet& yw, const std::vector<CarrierRecord>& lapsed);

/**
 * Sign one attestation with the hot key of `seq` through the persisted guard (S16): a recorded
 * signature at the same price is returned with reused = true; a different price refuses with
 * `equivocation-guard`. Refuses `attest-unknown-seq`, `attest-key-not-held`, `attest-range`,
 * `attest-stale`. cs_main, cs_wallet and cs_yellowback held.
 */
Attestation SignAttestationGuarded(YellowbackWallet& yw, uint16_t seq, MicroUsd priceMicroUsd, int citedHeight, bool& reused);

/** After FinishSapling(): sign the carrier input of a Sapling-shaped MINT / CARRIER-less shapes and the bond input of a Sapling-paid withdrawal (scriptSigs are outside the ZIP-243 digest). */
void SignBuiltInputs(BuiltTx& out, const CKeyStore& keystore, uint32_t branchId);

/** The dry run of a built transaction against the live index (an overlay); throws `<verdict>: …` on refusal. cs_yellowback held. */
void DryRunBuilt(YellowbackWallet& yw, const BuiltTx& out);

/** The §3.5 SWEEP of an own ACTIVE vault (L10): owner path, no burn, no fee, no payload. The caller checks IsAbandoned(). Unsigned. */
BuiltTx BuildSweep(YellowbackWallet& yw, const uint256& vaultTxid, const std::string& to = "");

/** Sapling shape: run TransactionBuilder::Build() (proofs, binding signature). No lock may be held. */
void FinishSapling(BuiltTx& out);

/**
 * SignerBranchId() and VerifyAllInputs() stay in policy.h (libbitcoin_server): the node-context
 * yed_validaterawtransaction uses them and cannot link the wallet library (mapping §13.5).
 */

/* OutPointSelector (the FEE-W / W9 selector of a vault spend) is declared in state.h since v3. */

/**
 * The dry run of yed_send / yed_sendmany (H3, yed_estimatesend): the same floor-aware selection
 * over the same coins, with nothing signed, locked or committed. `recipients` only shapes the
 * argument checks (at most MAX_ASSIGNMENTS - 1); the selection depends on the total alone.
 * Requires cs_main, cs_wallet and cs_yellowback, like every Build*.
 */
struct SendEstimate
{
    int64_t amountCents;
    size_t recipients;
    bool workable;
    std::string stage;                  //!< "exact" | "single" | "greedy" | "search" | "none"
    std::vector<YedCoin> inputs;        //!< empty when !workable
    int64_t selectedCents;
    int64_t changeCents;
    int64_t spendableCents;             //!< the wallet's confirmed, unspent YED
    std::string error;                  //!< "" | "insufficient-yed" | "change-floor" | "too-many-inputs"
    std::optional<int64_t> below;       //!< H2 alternatives, only when !workable
    std::optional<int64_t> above;

    SendEstimate() : amountCents(0), recipients(0), workable(false), stage("none"), selectedCents(0),
                     changeCents(0), spendableCents(0) {}
};

SendEstimate EstimateTransfer(YellowbackWallet& yw, int64_t amountCents, size_t recipients);

/** The largest YED input count the builders accept (H11: 250 P2PKH inputs ≈ 37 kB). */
static const size_t MAX_YED_INPUTS = 250;

/** CARRIER_VALUE (v3 §3.1, wallet policy on every network; Params::carrierValue carries the same value). */
static const CAmount CARRIER_VALUE = 10000;

} // namespace yellowback

#endif // YCASH_YELLOWBACK_TXBUILDER_H
