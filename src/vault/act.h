// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_VAULT_ACT_H
#define YCASH_VAULT_ACT_H

#include "amount.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/script.h"
#include "uint256.h"
#include "vault/template.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class CKey;

/**
 * The `YV` OP_RETURN act codec (docs/plans/yellowback-upgrade-plan.md §15.5) and the two
 * signed messages (actMsg, §15.5; setSigMsg, §15.2 step 4). Decoding is bounds-checked
 * and never throws; Encode(Decode(x)) == x is required, so pushes are minimal.
 *
 *   OP_RETURN <P> [<S_1> ... <S_n>]
 *   P = "YV" || 0x01 || type u8 || body      (integers little-endian, fixed width)
 *   S_i = 65-byte recoverable compact signature over actMsg
 */
namespace vault {

static const unsigned char ACT_MAGIC_0 = 0x59; // 'Y'
static const unsigned char ACT_MAGIC_1 = 0x56; // 'V'
static const unsigned char ACT_VERSION = 0x01;

enum ActType : uint8_t {
    ACT_SET_CREATE = 0x01,
    ACT_SET_JOIN = 0x02,
    ACT_SET_HEARTBEAT = 0x03,
    ACT_SET_REMOVE = 0x04,
    ACT_SET_EQUIVOCATION = 0x05,
    ACT_SET_WINDDOWN = 0x06,
};

/** Fixed body sizes per type (§15.5). */
size_t ActBodySize(uint8_t type);

static const uint8_t SET_FLAG_OPEN = 0x01;
static const unsigned int MAX_SET_SEATS = 15;
static const uint32_t MAX_SET_WINDOW = 1048576;
static const uint16_t MAX_RATE_BPS = 10000;
static const size_t RECOVERABLE_SIG_SIZE = 65;

/** SET_CREATE body (64 bytes). These are the set's parameters, stored in its SetRecord. */
struct SetCreateBody
{
    uint8_t seats = 0;
    uint8_t unlockThreshold = 0;
    uint8_t cancelThreshold = 0;
    uint8_t slashThreshold = 0;
    uint8_t flags = 0;
    uint16_t rateLimitBps = 0;
    uint32_t rateWindow = 0;
    uint32_t livenessWindow = 0;
    int64_t bondMin = 0;
    uint32_t bondLockMin = 0;
    uint32_t maturity = 0;
    CPubKey admitKey;

    bool IsOpen() const { return (flags & SET_FLAG_OPEN) != 0; }
    /** The SET_CREATE parameter rules (§15.5 row 0x01). */
    bool Valid() const;
};

struct SetJoinBody
{
    SetId setId;
    CPubKey memberKey;
    uint32_t bondLocktime = 0;
    uint8_t bondVout = 0;
};

struct SetHeartbeatBody
{
    SetId setId;
    CPubKey memberKey;
};

struct SetRemoveBody
{
    SetId setId;
    CPubKey memberKey;
    uint8_t burn = 0;
};

struct SetEquivocationBody
{
    SetId setId;
    COutPoint prevout;
    uint8_t roleA = 0;
    uint256 sighashA;
    std::vector<unsigned char> sigA; // 65
    uint8_t roleB = 0;
    uint256 sighashB;
    std::vector<unsigned char> sigB; // 65
};

struct SetWindDownBody
{
    SetId setId;
};

/** A decoded act. Exactly the body selected by `type` is meaningful. */
struct Act
{
    uint8_t type = 0;
    SetCreateBody create;
    SetJoinBody join;
    SetHeartbeatBody heartbeat;
    SetRemoveBody remove;
    SetEquivocationBody equivocation;
    SetWindDownBody winddown;
    /** The signatures S_1..S_n, each 65 bytes. */
    std::vector<std::vector<unsigned char>> sigs;

    /** The setId the act names (the txid for SET_CREATE is not known here: null). */
    SetId TargetSet() const;
};

/** True when the scriptPubKey is OP_RETURN followed by a push whose data starts "YV". */
bool IsActOutput(const CScript& spk);

/** P = "YV" || version || type || body. Empty if the type is unknown. */
std::vector<unsigned char> EncodePayload(const Act& act);
/** The full OP_RETURN script: OP_RETURN <P> <S_1>...<S_n>. Empty if the type is unknown. */
CScript EncodeAct(const Act& act);

/** The context-free field rules of §15.5 that the decoder does not apply: SET_CREATE
 *  parameter ranges (SetCreateBody::Valid), compressed keys, JOIN bondLocktime in
 *  1..499999999, REMOVE burn in {0,1}, EQUIVOCATION roles in {1,2}, and every signature
 *  header (S_i, sigA, sigB) in 31..34. Rejected at rule time as bad-vault-act-params. */
bool ActFieldsValid(const Act& act);

/** Decode a `YV` output. nullopt on success; otherwise a reject reason:
 *  bad-vault-act-malformed, bad-vault-act-version, bad-vault-act-type. */
std::optional<std::string> DecodeAct(const CScript& spk, Act& out);
/** Decode only the payload P (no signatures). */
std::optional<std::string> DecodePayload(const std::vector<unsigned char>& P, Act& out);

/** actMsg = SHA256d("YcashSetAct" || P || prevout(36)). */
uint256 ActMsg(const std::vector<unsigned char>& P, const COutPoint& prevout);
/** setSigMsg = SHA256d("YcashSetSig" || setId(32) || role(1) || prevout(36) || sighash(32)). */
uint256 SetSigMsg(const SetId& setId, uint8_t role, const COutPoint& prevout, const uint256& sighash);

/** A 65-byte recoverable signature: header 31..34 (compressed), low S. On success the
 *  recovered compressed key is written to `key`. Never throws. */
bool RecoverSig(const uint256& msg, const std::vector<unsigned char>& sig, CPubKey& key);
/** Sign `msg` with a compressed key (header 31..34, low S as libsecp256k1 emits). */
bool SignRecoverable(const CKey& key, const uint256& msg, std::vector<unsigned char>& sig);

} // namespace vault

#endif // YCASH_VAULT_ACT_H
