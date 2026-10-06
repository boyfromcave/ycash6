// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_VAULT_TEMPLATE_H
#define YCASH_VAULT_TEMPLATE_H

#include "pubkey.h"
#include "script/script.h"
#include "uint256.h"

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

/**
 * The vault primitive's script templates (docs/plans/yellowback-upgrade-plan.md §15.3):
 * the vault V, the intent I (both bare scriptPubKeys, U-12) and the member bond B (a
 * P2SH redeem script, as v3's attestor bond). Builders emit the exact byte shapes with
 * minimal pushes; parsers accept only those shapes (parse, rebuild, compare bytes).
 */
namespace vault {

/** A set's id: the txid of its SET_CREATE transaction, pushed as its 32 internal bytes. */
typedef uint256 SetId;
/** A 4-byte application tag (§3.8). */
typedef std::array<unsigned char, 4> Tag;

/** The two new opcodes (§15.2, U-10). script/script.h names them once the
 *  interpreter change lands; the template layer only needs their bytes. */
static const opcodetype VAULT_OP_CHECKSETSIG = (opcodetype)0xc0;
static const opcodetype VAULT_OP_CHECKSETDORMANT = (opcodetype)0xc1;
/** BIP112's own byte (OP_NOP3). */
static const opcodetype VAULT_OP_CHECKSEQUENCEVERIFY = OP_NOP3;

/** OP_CHECKSETSIG roles (U-13). */
static const uint8_t ROLE_UNLOCK = 1;
static const uint8_t ROLE_CANCEL = 2;

/** Selectors (§15.3): the last push of a template input's scriptSig. */
static const uint8_t SEL_UNLOCK = 1;   // V: set unlock     I: RELEASE
static const uint8_t SEL_OWNER = 2;    // V: owner at height I: CANCEL
static const uint8_t SEL_RELEASED = 3; // V and I: owner when the set is released
static const uint8_t SEL_APP = 4;      // V only: APP branch

/** Field ranges (§15.3). */
static const int64_t MIN_DELAY = 1;
static const int64_t MAX_DELAY = 65535;
static const int64_t MAX_TEMPLATE_HEIGHT = 499999999;

struct VaultParams
{
    Tag tag{};
    SetId cancelSetId;
    int64_t delay = 0;
    SetId setId;
    int64_t ownerHeight = 0;
    CPubKey ownerKey;
    int64_t appHeight = 0;

    bool operator==(const VaultParams& o) const
    {
        return tag == o.tag && cancelSetId == o.cancelSetId && delay == o.delay && setId == o.setId &&
               ownerHeight == o.ownerHeight && ownerKey == o.ownerKey && appHeight == o.appHeight;
    }
};

struct IntentParams
{
    Tag tag{};
    uint256 recipientHash; // SHA256(recipient scriptPubKey)
    uint256 vaultHash;     // SHA256(originating V scriptPubKey)
    int64_t delay = 0;
    SetId cancelSetId;
    SetId setId;
    CPubKey ownerKey;
};

enum class TemplateKind { VAULT, INTENT };

/** A template input as parsed from the spent coin's scriptPubKey and the input's scriptSig.
 *  `vault` is meaningful when kind == VAULT, `intent` when kind == INTENT. */
struct TemplateSpend
{
    TemplateKind kind = TemplateKind::VAULT;
    uint8_t selector = 0;
    VaultParams vault;
    IntentParams intent;
    /** Every scriptSig push before the selector (set or owner signatures). */
    std::vector<std::vector<unsigned char>> sigs;
};

/** Result of matching a scriptPubKey against a template. MALFORMED means the opcode
 *  skeleton matches but a push is non-minimal or a field is out of range (§15.3: "a
 *  V-shaped output outside them is not a template, rule V-1 then rejects it"). */
enum class Shape { NONE, MATCH, MALFORMED };

/** 33 bytes with a 0x02/0x03 header (no curve check; §15.3 "compressed"). */
bool IsCompressedKeyBytes(const std::vector<unsigned char>& key);
inline bool IsCompressedKey(const CPubKey& key) { return IsCompressedKeyBytes(std::vector<unsigned char>(key.begin(), key.end())); }

/** Range-checks the fields. */
bool VaultParamsValid(const VaultParams& p);
bool IntentParamsValid(const IntentParams& p);

/** Build V / I. Returns an empty script when the parameters are out of range. */
CScript BuildVault(const VaultParams& p);
CScript BuildIntent(const IntentParams& p);

/** Parse V / I: true only for the exact byte shape with in-range fields. */
bool ParseVault(const CScript& spk, VaultParams& out);
bool ParseIntent(const CScript& spk, IntentParams& out);
Shape MatchVault(const CScript& spk, VaultParams& out);
Shape MatchIntent(const CScript& spk, IntentParams& out);

/** The intent a V's UNLOCK/APP spend may create paying `recipientScript` (S-2). */
IntentParams IntentFor(const VaultParams& v, const CScript& vaultSpk, const CScript& recipientScript);

/** SHA256 (single) of a script's bytes, as recipientHash / vaultHash. */
uint256 ScriptHash256(const CScript& script);

/** Bond B redeem script: <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <memberKey:33> OP_CHECKSIG.
 *  Empty when locktime is not in 1..499999999 or the key is not compressed. */
CScript BuildBondRedeem(uint32_t locktime, const CPubKey& memberKey);
bool ParseBondRedeem(const CScript& redeem, uint32_t& locktime, CPubKey& memberKey);
/** P2SH(B(memberKey, locktime)); empty if B is. */
CScript BondScriptPubKey(uint32_t locktime, const CPubKey& memberKey);

/** The selector of a template input: the scriptSig must be push-only and its last push
 *  must be OP_1..OP_4 exactly. `pushes` (optional) receives every push before it. */
std::optional<uint8_t> ParseSelector(const CScript& scriptSig, std::vector<std::vector<unsigned char>>* pushes = nullptr);

/** Parse a template input from the spent scriptPubKey and the input's scriptSig.
 *  nullopt when the coin is not a template (MATCH) or the scriptSig does not parse. */
std::optional<TemplateSpend> ParseTemplateSpend(const CScript& spentSpk, const CScript& scriptSig);

} // namespace vault

#endif // YCASH_VAULT_TEMPLATE_H
