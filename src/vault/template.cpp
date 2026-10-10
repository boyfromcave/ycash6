// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "vault/template.h"

#include "crypto/pq/scheme.h"
#include "crypto/sha256.h"
#include "script/standard.h"

namespace vault {

typedef std::vector<unsigned char> valtype;

namespace {

struct Tok {
    opcodetype op;
    valtype data;
};

/** Split a script into opcodes; false on a truncated push. */
bool Tokenize(const CScript& script, std::vector<Tok>& out)
{
    out.clear();
    CScript::const_iterator pc = script.begin();
    while (pc < script.end()) {
        Tok t;
        if (!script.GetOp(pc, t.op, t.data)) return false;
        out.push_back(std::move(t));
    }
    return true;
}

bool IsPushTok(const Tok& t)
{
    return t.op <= OP_16 && t.op != OP_RESERVED;
}

/** Decode a pushed script number (≤ 5 bytes, any encoding; minimality is checked by
 *  the rebuild-and-compare step). */
bool TokNum(const Tok& t, int64_t& n)
{
    if (t.op == OP_0) { n = 0; return true; }
    if (t.op == OP_1NEGATE) { n = -1; return true; }
    if (t.op >= OP_1 && t.op <= OP_16) { n = (int64_t)t.op - (int64_t)OP_1 + 1; return true; }
    if (t.op > OP_PUSHDATA4) return false;
    if (t.data.size() > 5) return false;
    if (t.data.empty()) { n = 0; return true; }
    uint64_t r = 0;
    for (size_t i = 0; i < t.data.size(); i++) r |= (uint64_t)t.data[i] << (8 * i);
    if (t.data.back() & 0x80) {
        r &= ~((uint64_t)0x80 << (8 * (t.data.size() - 1)));
        n = -(int64_t)r;
    } else {
        n = (int64_t)r;
    }
    return true;
}

bool TokBytes(const Tok& t, size_t size, valtype& out)
{
    if (t.op > OP_PUSHDATA4 || t.data.size() != size) return false;
    out = t.data;
    return true;
}

bool TokU256(const Tok& t, uint256& out)
{
    valtype d;
    if (!TokBytes(t, 32, d)) return false;
    out = uint256(d);
    return true;
}

bool TokKey(const Tok& t, CPubKey& out)
{
    valtype d;
    if (!TokBytes(t, 33, d)) return false;
    out = CPubKey(d);
    return true;
}

/** The owner slot <ownerHash:32> <schemeId>: the hash is exactly 32 bytes, the scheme a number
 *  (OP_1/OP_2 after the rebuild compare) in the registry. */
bool TokOwner(const Tok& hashTok, const Tok& schemeTok, CPQKeyID& out)
{
    uint256 h;
    int64_t scheme;
    if (!TokU256(hashTok, h) || !TokNum(schemeTok, scheme)) return false;
    if (scheme < 0 || scheme > 255 || !pq::IsKnownScheme((uint8_t)scheme)) return false;
    out = CPQKeyID((uint8_t)scheme, h);
    return true;
}

bool TokTag(const Tok& t, Tag& out)
{
    valtype d;
    if (!TokBytes(t, 4, d)) return false;
    std::copy(d.begin(), d.end(), out.begin());
    return true;
}

const int F = -1; // a field (any push)

const std::vector<int>& VaultSkeleton()
{
    static const std::vector<int> s = {
        F, F, F, OP_2DROP, OP_DROP,                                                        // 0..4
        OP_DUP, OP_1, OP_EQUAL, OP_IF,                                                     // 5..8
        OP_DROP, F, OP_1, VAULT_OP_CHECKSETSIG,                                            // 9..12   setId@10
        OP_ELSE, OP_DUP, OP_2, OP_EQUAL, OP_IF,                                            // 13..17
        OP_DROP, F, OP_CHECKLOCKTIMEVERIFY, OP_DROP, F, F, VAULT_OP_CHECKPQSIG,            // 18..24  ownerHeight@19 ownerHash@22 scheme@23
        OP_ELSE, OP_DUP, OP_3, OP_EQUAL, OP_IF,                                            // 25..29
        OP_DROP, F, VAULT_OP_CHECKSETDORMANT, OP_VERIFY, F, F, VAULT_OP_CHECKPQSIG,        // 30..36  setId@31 ownerHash@34 scheme@35
        OP_ELSE, OP_4, OP_EQUALVERIFY, F, OP_CHECKLOCKTIMEVERIFY,                          // 37..41  appHeight@40
        OP_ENDIF, OP_ENDIF, OP_ENDIF};                                                     // 42..44
    return s;
}

const std::vector<int>& IntentSkeleton()
{
    static const std::vector<int> s = {
        F, F, F, OP_2DROP, OP_DROP,                                                        // 0..4 tag recipientHash vaultHash
        OP_DUP, OP_1, OP_EQUAL, OP_IF,                                                     // 5..8
        OP_DROP, F, VAULT_OP_CHECKSEQUENCEVERIFY,                                          // 9..11   delay@10
        OP_ELSE, OP_DUP, OP_2, OP_EQUAL, OP_IF,                                            // 12..16
        OP_DROP, F, OP_2, VAULT_OP_CHECKSETSIG,                                            // 17..20  cancelSetId@18
        OP_ELSE, OP_3, OP_EQUALVERIFY, F, VAULT_OP_CHECKSETDORMANT, OP_VERIFY,             // 21..26  setId@24
        F, F, VAULT_OP_CHECKPQSIG,                                                         // 27..29  ownerHash@27 scheme@28
        OP_ENDIF, OP_ENDIF};                                                               // 30..31
    return s;
}

bool MatchSkeleton(const CScript& spk, const std::vector<int>& skel, std::vector<Tok>& toks)
{
    if (!Tokenize(spk, toks)) return false;
    if (toks.size() != skel.size()) return false;
    for (size_t i = 0; i < skel.size(); i++) {
        if (skel[i] == F) {
            if (!IsPushTok(toks[i])) return false;
        } else if ((int)toks[i].op != skel[i]) {
            return false;
        }
    }
    return true;
}

} // namespace

bool IsCompressedKeyBytes(const std::vector<unsigned char>& key)
{
    return key.size() == CPubKey::COMPRESSED_PUBLIC_KEY_SIZE && (key[0] == 0x02 || key[0] == 0x03);
}

bool IsOwnerValid(const CPQKeyID& owner)
{
    return pq::IsKnownScheme(owner.scheme);
}

bool VaultParamsValid(const VaultParams& p)
{
    return p.delay >= MIN_DELAY && p.delay <= MAX_DELAY &&
           p.ownerHeight >= 1 && p.ownerHeight <= MAX_TEMPLATE_HEIGHT &&
           p.appHeight >= 0 && p.appHeight <= MAX_TEMPLATE_HEIGHT &&
           IsOwnerValid(p.owner);
}

bool IntentParamsValid(const IntentParams& p)
{
    return p.delay >= MIN_DELAY && p.delay <= MAX_DELAY && IsOwnerValid(p.owner);
}

CScript BuildVault(const VaultParams& p)
{
    if (!VaultParamsValid(p)) return CScript();
    const valtype tag(p.tag.begin(), p.tag.end());
    const valtype setId(p.setId.begin(), p.setId.end());
    const valtype cancelSetId(p.cancelSetId.begin(), p.cancelSetId.end());
    const valtype ownerHash(p.owner.hash.begin(), p.owner.hash.end());
    const int64_t scheme = p.owner.scheme;
    CScript s;
    s << tag << cancelSetId << p.delay << OP_2DROP << OP_DROP;
    s << OP_DUP << OP_1 << OP_EQUAL << OP_IF;
    s << OP_DROP << setId << OP_1 << VAULT_OP_CHECKSETSIG;
    s << OP_ELSE << OP_DUP << OP_2 << OP_EQUAL << OP_IF;
    s << OP_DROP << p.ownerHeight << OP_CHECKLOCKTIMEVERIFY << OP_DROP << ownerHash << scheme << VAULT_OP_CHECKPQSIG;
    s << OP_ELSE << OP_DUP << OP_3 << OP_EQUAL << OP_IF;
    s << OP_DROP << setId << VAULT_OP_CHECKSETDORMANT << OP_VERIFY << ownerHash << scheme << VAULT_OP_CHECKPQSIG;
    s << OP_ELSE;
    s << OP_4 << OP_EQUALVERIFY << p.appHeight << OP_CHECKLOCKTIMEVERIFY;
    s << OP_ENDIF << OP_ENDIF << OP_ENDIF;
    return s;
}

CScript BuildIntent(const IntentParams& p)
{
    if (!IntentParamsValid(p)) return CScript();
    const valtype tag(p.tag.begin(), p.tag.end());
    const valtype rh(p.recipientHash.begin(), p.recipientHash.end());
    const valtype vh(p.vaultHash.begin(), p.vaultHash.end());
    const valtype setId(p.setId.begin(), p.setId.end());
    const valtype cancelSetId(p.cancelSetId.begin(), p.cancelSetId.end());
    const valtype ownerHash(p.owner.hash.begin(), p.owner.hash.end());
    const int64_t scheme = p.owner.scheme;
    CScript s;
    s << tag << rh << vh << OP_2DROP << OP_DROP;
    s << OP_DUP << OP_1 << OP_EQUAL << OP_IF;
    s << OP_DROP << p.delay << VAULT_OP_CHECKSEQUENCEVERIFY;
    s << OP_ELSE << OP_DUP << OP_2 << OP_EQUAL << OP_IF;
    s << OP_DROP << cancelSetId << OP_2 << VAULT_OP_CHECKSETSIG;
    s << OP_ELSE;
    s << OP_3 << OP_EQUALVERIFY << setId << VAULT_OP_CHECKSETDORMANT << OP_VERIFY << ownerHash << scheme << VAULT_OP_CHECKPQSIG;
    s << OP_ENDIF << OP_ENDIF;
    return s;
}

Shape MatchVault(const CScript& spk, VaultParams& out)
{
    std::vector<Tok> t;
    if (!MatchSkeleton(spk, VaultSkeleton(), t)) return Shape::NONE;
    VaultParams p;
    SetId setId2;
    CPQKeyID owner2;
    if (!TokTag(t[0], p.tag) || !TokU256(t[1], p.cancelSetId) || !TokNum(t[2], p.delay) ||
        !TokU256(t[10], p.setId) || !TokNum(t[19], p.ownerHeight) || !TokOwner(t[22], t[23], p.owner) ||
        !TokU256(t[31], setId2) || !TokOwner(t[34], t[35], owner2) || !TokNum(t[40], p.appHeight)) {
        return Shape::MALFORMED;
    }
    if (setId2 != p.setId || owner2 != p.owner) return Shape::MALFORMED;
    if (!VaultParamsValid(p)) return Shape::MALFORMED;
    if (BuildVault(p) != spk) return Shape::MALFORMED; // non-minimal push somewhere
    out = p;
    return Shape::MATCH;
}

Shape MatchIntent(const CScript& spk, IntentParams& out)
{
    std::vector<Tok> t;
    if (!MatchSkeleton(spk, IntentSkeleton(), t)) return Shape::NONE;
    IntentParams p;
    if (!TokTag(t[0], p.tag) || !TokU256(t[1], p.recipientHash) || !TokU256(t[2], p.vaultHash) ||
        !TokNum(t[10], p.delay) || !TokU256(t[18], p.cancelSetId) || !TokU256(t[24], p.setId) ||
        !TokOwner(t[27], t[28], p.owner)) {
        return Shape::MALFORMED;
    }
    if (!IntentParamsValid(p)) return Shape::MALFORMED;
    if (BuildIntent(p) != spk) return Shape::MALFORMED;
    out = p;
    return Shape::MATCH;
}

bool ParseVault(const CScript& spk, VaultParams& out)
{
    return MatchVault(spk, out) == Shape::MATCH;
}

bool ParseIntent(const CScript& spk, IntentParams& out)
{
    return MatchIntent(spk, out) == Shape::MATCH;
}

uint256 ScriptHash256(const CScript& script)
{
    uint256 h;
    CSHA256().Write(script.empty() ? nullptr : &script[0], script.size()).Finalize(h.begin());
    return h;
}

IntentParams IntentFor(const VaultParams& v, const CScript& vaultSpk, const CScript& recipientScript)
{
    IntentParams i;
    i.tag = v.tag;
    i.recipientHash = ScriptHash256(recipientScript);
    i.vaultHash = ScriptHash256(vaultSpk);
    i.delay = v.delay;
    i.cancelSetId = v.cancelSetId;
    i.setId = v.setId;
    i.owner = v.owner;
    return i;
}

CScript BuildBondRedeem(uint32_t locktime, const CPubKey& memberKey)
{
    if (locktime == 0 || (int64_t)locktime > MAX_TEMPLATE_HEIGHT) return CScript();
    if (!IsCompressedKey(memberKey)) return CScript();
    CScript s;
    s << (int64_t)locktime << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
    s << valtype(memberKey.begin(), memberKey.end()) << OP_CHECKSIG;
    return s;
}

bool ParseBondRedeem(const CScript& redeem, uint32_t& locktime, CPubKey& memberKey)
{
    std::vector<Tok> t;
    if (!Tokenize(redeem, t) || t.size() != 5) return false;
    int64_t lt;
    CPubKey key;
    if (!IsPushTok(t[0]) || !TokNum(t[0], lt)) return false;
    if (t[1].op != OP_CHECKLOCKTIMEVERIFY || t[2].op != OP_DROP || t[4].op != OP_CHECKSIG) return false;
    if (!TokKey(t[3], key)) return false;
    if (lt < 1 || lt > MAX_TEMPLATE_HEIGHT) return false;
    if (BuildBondRedeem((uint32_t)lt, key) != redeem) return false;
    locktime = (uint32_t)lt;
    memberKey = key;
    return true;
}

CScript BondScriptPubKey(uint32_t locktime, const CPubKey& memberKey)
{
    CScript redeem = BuildBondRedeem(locktime, memberKey);
    if (redeem.empty()) return CScript();
    return GetScriptForDestination(CScriptID(redeem));
}

std::optional<uint8_t> ParseSelector(const CScript& scriptSig, std::vector<std::vector<unsigned char>>* pushes)
{
    if (scriptSig.empty() || !scriptSig.IsPushOnly()) return std::nullopt;
    std::vector<Tok> t;
    if (!Tokenize(scriptSig, t) || t.empty()) return std::nullopt;
    const Tok& last = t.back();
    if (last.op < OP_1 || last.op > OP_4) return std::nullopt;
    if (pushes) {
        pushes->clear();
        for (size_t i = 0; i + 1 < t.size(); i++) {
            if (t[i].op >= OP_1 && t[i].op <= OP_16) {
                pushes->push_back(valtype(1, (unsigned char)(t[i].op - OP_1 + 1)));
            } else if (t[i].op == OP_1NEGATE) {
                pushes->push_back(valtype(1, 0x81));
            } else {
                pushes->push_back(t[i].data);
            }
        }
    }
    return (uint8_t)(last.op - OP_1 + 1);
}

std::optional<TemplateSpend> ParseTemplateSpend(const CScript& spentSpk, const CScript& scriptSig)
{
    TemplateSpend ts;
    if (ParseVault(spentSpk, ts.vault)) {
        ts.kind = TemplateKind::VAULT;
    } else if (ParseIntent(spentSpk, ts.intent)) {
        ts.kind = TemplateKind::INTENT;
    } else {
        return std::nullopt;
    }
    auto sel = ParseSelector(scriptSig, &ts.sigs);
    if (!sel) return std::nullopt;
    if (ts.kind == TemplateKind::INTENT && *sel == SEL_APP) return std::nullopt;
    ts.selector = *sel;
    return ts;
}

} // namespace vault
