// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_YELLOWBACK_SCRIPT_H
#define YCASH_YELLOWBACK_SCRIPT_H

#include "pubkey.h"
#include "script/script.h"
#include "script/standard.h"
#include "vault/template.h"
#include "yellowback/params.h"

#include <string>
#include <vector>

#include <optional>

class CTransaction;

/**
 * Yellowback scripts (plan §3.4, V7). Existing opcodes only.
 *
 * Vault script (redeem script of the P2SH collateral output):
 *     OP_IF
 *       <lockHeight> OP_CHECKLOCKTIMEVERIFY OP_DROP <ownerPubKey> OP_CHECKSIG
 *     OP_ELSE
 *       <claimHeight> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_TRUE
 *     OP_ENDIF
 * with claimHeight = lockHeight + GRACE. Owner-path scriptSig
 * `<ownerSig> OP_1 <vaultScript>`, claim-path scriptSig `OP_0 <vaultScript>`;
 * both leave exactly one element (CLEANSTACK) and are minimal pushes
 * (MINIMALDATA). 51-53 bytes, one sigop.
 *
 * DigiByte's vault is a P2TR two-leaf MAST with DD opcodes
 * (ref/digibyte/src/digidollar/scripts.h:112); Ycash has no Taproot, no
 * MINIMALIF and no spare opcode semantics (mapping.md §2, §13), so the two
 * leaves become the two OP_IF branches and the burn-on-release invariant is
 * enforced by miners on the spending transaction (RED-1..4), not by script.
 * The claim path is anyone-can-spend at the base layer and safe only under
 * enforcement (V7).
 *
 * The federation prototype's k-of-n multisig helpers were deleted in Phase 3
 * (§4.2); IsCompressedKey, P2SHScript and ExtractRedeemScript remain.
 */
namespace yellowback {

typedef std::vector<unsigned char> valtype;

// ---------------------------------------------------------------- v2 (§3.4)

/** The vault redeem script. Empty if lockHeight/claimHeight are not in [1, LOCKTIME_THRESHOLD), claimHeight <= lockHeight, or the key is not compressed. */
CScript VaultScript(uint32_t lockHeight, const CPubKey& owner, uint32_t claimHeight);

/** Parse a v2 vault script back into its parts; false for anything but the exact template with minimal pushes. */
bool ParseVaultScript(const CScript& script, uint32_t& lockHeight, CPubKey& owner, uint32_t& claimHeight);

/** `<ownerSig> OP_1 <vaultScript>`. The signature carries its hashtype byte. */
CScript OwnerScriptSig(const valtype& ownerSig, const CScript& vaultScript);

/** `OP_0 <vaultScript>`. */
CScript ClaimScriptSig(const CScript& vaultScript);

/** The path a vault spend takes, as OP_IF would evaluate its selector (K4). */
struct VaultSpendPath
{
    bool ownerPath;           //!< CastToBool(selector): true = owner branch, false = claim branch
    valtype selector;         //!< the push immediately before the redeem script (empty for OP_0; the number for OP_1..OP_16)
    CScript vaultScript;      //!< the last push
    valtype ownerSig;         //!< the push before the selector, if any (empty otherwise)
    size_t pushes;            //!< number of pushes in the scriptSig
};

/**
 * Path detection for RED-4. Consensus verifies vaults with P2SH | CLTV only
 * (ref/ycash/src/main.cpp:2931), so the selector is anything OP_IF accepts:
 * `OP_2` or a non-minimal `1` is an owner selector, `0x80` (negative zero) a
 * claim selector. nullopt iff the scriptSig is not push-only or has fewer
 * than two pushes (RED-1, M1). Whether the shape is exactly the wallet's
 * `<sig> OP_1 <script>` / `OP_0 <script>` is strict-template policy (TPL-2),
 * not decided here.
 */
std::optional<VaultSpendPath> ParseVaultSpendPath(const CScript& scriptSig);

// ---------------------------------------------------------------- the vault upgrade (U-23)

/**
 * Since UPGRADE_VAULT the collateral of a mint is the primitive's vault template V
 * (vault/template.h, docs/plans/yellowback-upgrade-plan.md §15.3, §15.10) with
 *     tag = YED_TAG, setId = cancelSetId = attestorSetId, delay = CLAIM_DELAY,
 *     ownerHeight = appHeight = refHeight + 1, owner = the payload's owner (a CPQKeyID, quantum plan §4.3).
 * The owner redeems with selector 2 (or 3 once the attestor set is released), the claim is
 * selector 4 into intents, and the v2 P2SH VaultScript above is refused for new mints (MINT-3).
 *
 * In-term claims (docs/plans/yellowback-in-term-claims-plan.md IT-1): the APP branch is open from
 * the first block after the mint and RED-4's threshold test decides a claim's validity at every
 * height. A V built before the plan carries appHeight = lockHeight + GRACE; its spends are still
 * YED spends (the record remembers its appHeight), new mints with that shape are refused.
 */
extern const vault::Tag YED_TAG;
/**
 * The V parameters of a mint's vault (U-23, IT-1 as extended 2026-10-07): ownerHeight = appHeight = refHeight + 1,
 * so the owner's redeem (selector 2) and the claim (selector 4) are both open from the block after the mint; the
 * payload's lockHeight is record-keeping (the term, for the class and the fee) and no longer a CLTV.
 */
vault::VaultParams YedVaultParams(const Params& p, const CPQKeyID& owner, int64_t refHeight);
/** BuildVault(YedVaultParams(...)); empty when a field is out of range (the caller's MINT-2/3 then fails). */
CScript YedVaultScript(const Params& p, const CPQKeyID& owner, int64_t refHeight);
/** The V of an existing vault record, whatever its heights (a pre-plan vault has ownerHeight = lockHeight, appHeight = lockHeight + GRACE). */
vault::VaultParams YedVaultParamsAt(const Params& p, const CPQKeyID& owner, int64_t ownerHeight, int64_t appHeight);
CScript YedVaultScriptAt(const Params& p, const CPQKeyID& owner, int64_t ownerHeight, int64_t appHeight);
/** The 33 owner bytes of a MINT payload / vault record read as scheme || keyHash (quantum spec §3.1, §3.4);
 *  scheme 0 (no owner) when the size is not 33. */
CPQKeyID OwnerFromBytes(const std::vector<unsigned char>& bytes);

/**
 * HolderKey (quantum plan §4.4, spec §3.5): the destination of a YED holder script, the 25-byte P2PKH
 * (a CKeyID), the 35-byte TX_PQPKH `20 <keyHash:32> OP_1|OP_2 OP_CHECKPQSIG` (a CPQKeyID, exact match as
 * Solver's, spec §2.1) or a TX_PQCHANNEL (its client's CPQKeyID, D-Q-19); nullopt for any other script. The wallet and the index read it (balances,
 * yed_listtokens); the fee payees stay P2PKH (D-Q-5) and the rules read HolderKey only through TOK-PQ.
 */
std::optional<CTxDestination> HolderKey(const CScript& script);

/**
 * TOK-PQ (quantum spec F-7, D-Q-19): below the Falcon height (Params::IsPQFalconActive, the A-5 mirror) any
 * script may hold YED, as before; from it, a YED token output must be a TX_PQPKH of scheme 0x02 (FN-DSA-512)
 * or a TX_PQCHANNEL whose client is scheme 0x02.
 */
bool HolderAllowed(const Params& p, int64_t height, const CScript& script);

// ---------------------------------------------------------------- v3 (§3.4): carrier and bond

/**
 * The carrier redeem script (v3 plan §3.4, W7, R2):
 *     OP_SWAP OP_SHA256 <bundleHash 32> OP_EQUALVERIFY <pk 33> OP_CHECKSIG      (71 bytes: 1+1+33+1+34+1;
 *     the plan's "72" miscounts)
 * spent by the push-only scriptSig `<bundle> <sig> <carrierScript>`. The
 * bundle push is covered by no signature; the redeem script is (it is the
 * scriptCode of the input's sighash) and is pinned by the P2SH hash of the
 * funding output, so SHA256(bundle) is committed before the carrier exists.
 * Empty if the key is not compressed.
 */
CScript CarrierScript(const CPubKey& pk, const uint256& bundleHash);

static const size_t CARRIER_SCRIPT_SIZE = 71;

/** The exact 71-byte carrier template; optionally returns its parts. */
bool IsCarrierScript(const CScript& script, CPubKey* pk = nullptr, uint256* bundleHash = nullptr);

/** `<bundle> <sig> <carrierScript>`. */
CScript CarrierScriptSig(const valtype& bundle, const valtype& sig, const CScript& carrierScript);

struct CarrierSpend
{
    valtype bundle;           //!< the first push (the bundle bytes, <= MAX_SCRIPT_ELEMENT_SIZE under consensus)
    valtype sig;              //!< the second push (a DER signature with its hashtype byte)
    CPubKey pk;               //!< from the redeem script
    uint256 bundleHash;       //!< from the redeem script
    CScript carrierScript;    //!< the third push
};

/**
 * Carrier identification by shape (§3.4): exactly three pushes, the third a
 * 71-byte script matching CarrierScript(., .). Nothing else is looked at;
 * whether SHA256(bundle) equals bundleHash is the extractor's job (BUNDLE-1
 * `hash`). nullopt for any other scriptSig.
 */
std::optional<CarrierSpend> ParseCarrierScriptSig(const CScript& scriptSig);

/**
 * The index of the transaction's one carrier-shaped input, skipping vin[0]
 * when asked (a REDEEM's vault input is never considered). nullopt with
 * reason "shape" if there is none and "two-carriers" if there are two or
 * more (BUNDLE-1). Total.
 */
std::optional<size_t> FindCarrierInput(const CTransaction& tx, bool skipVin0, std::string* reason = nullptr);

/**
 * The attestor bond redeem script (§3.4): the vault owner path without the
 * claim branch,
 *     <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <pk 33> OP_CHECKSIG
 * Empty if locktime is not in [1, LOCKTIME_THRESHOLD) or the key is not compressed.
 */
CScript BondScript(const CPubKey& pk, uint32_t locktime);

/** Parse a bond script back into its parts; false for anything but the exact template with minimal pushes. */
bool ParseBondScript(const CScript& script, CPubKey& pk, uint32_t& locktime);

// ---------------------------------------------------------------- shared helpers

/** True iff the key is a 33-byte compressed encoding (plan D7). */
bool IsCompressedKey(const CPubKey& key);

/** P2SH scriptPubKey for a redeem script. */
CScript P2SHScript(const CScript& redeemScript);

/** The last push of a P2SH scriptSig, i.e. the redeem script. False if the scriptSig is not push-only or empty. */
bool ExtractRedeemScript(const CScript& scriptSig, CScript& redeemScript);

} // namespace yellowback

#endif // YCASH_YELLOWBACK_SCRIPT_H
