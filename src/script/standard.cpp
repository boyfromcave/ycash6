// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2018-2023 The Zcash developers
// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "script/standard.h"

#include "crypto/pq/scheme.h"
#include "pubkey.h"
#include "script/script.h"
#include "util/system.h"
#include "util/strencodings.h"
#include "vault/template.h"


using namespace std;

typedef vector<unsigned char> valtype;

bool fAcceptDatacarrier = DEFAULT_ACCEPT_DATACARRIER;
unsigned nMaxDatacarrierBytes = MAX_OP_RETURN_RELAY;

CScriptID::CScriptID(const CScript& in) : uint160(Hash160(in.begin(), in.end())) {}

const char* GetTxnOutputType(txnouttype t)
{
    switch (t)
    {
    case TX_NONSTANDARD: return "nonstandard";
    case TX_PUBKEY: return "pubkey";
    case TX_PUBKEYHASH: return "pubkeyhash";
    case TX_SCRIPTHASH: return "scripthash";
    case TX_MULTISIG: return "multisig";
    case TX_NULL_DATA: return "nulldata";
    case TX_VAULT: return "vault";
    case TX_VAULT_INTENT: return "vaultintent";
    case TX_PQPKH: return "pqpubkeyhash";
    case TX_PQCHANNEL: return "pqchannel";
    }
    return NULL;
}

static bool MatchPayToPubkey(const CScript& script, valtype& pubkey)
{
    if (script.size() == CPubKey::PUBLIC_KEY_SIZE + 2 && script[0] == CPubKey::PUBLIC_KEY_SIZE && script.back() == OP_CHECKSIG) {
        pubkey = valtype(script.begin() + 1, script.begin() + CPubKey::PUBLIC_KEY_SIZE + 1);
        return CPubKey::ValidSize(pubkey);
    }
    if (script.size() == CPubKey::COMPRESSED_PUBLIC_KEY_SIZE + 2 && script[0] == CPubKey::COMPRESSED_PUBLIC_KEY_SIZE && script.back() == OP_CHECKSIG) {
        pubkey = valtype(script.begin() + 1, script.begin() + CPubKey::COMPRESSED_PUBLIC_KEY_SIZE + 1);
        return CPubKey::ValidSize(pubkey);
    }
    return false;
}

static bool MatchPayToPubkeyHash(const CScript& script, valtype& pubkeyhash)
{
    if (script.size() == 25 && script[0] == OP_DUP && script[1] == OP_HASH160 && script[2] == 20 && script[23] == OP_EQUALVERIFY && script[24] == OP_CHECKSIG) {
        pubkeyhash = valtype(script.begin () + 3, script.begin() + 23);
        return true;
    }
    return false;
}

/** TX_PQPKH (quantum spec §2.1): exactly 0x20 <keyHash:32> OP_1|OP_2 OP_CHECKPQSIG, 35 bytes. */
static bool MatchPayToPQKeyHash(const CScript& script, uint8_t& scheme, valtype& keyhash)
{
    if (script.size() == 35 && script[0] == 32 && (script[33] == OP_1 || script[33] == OP_2) && script[34] == OP_CHECKPQSIG) {
        scheme = (uint8_t)CScript::DecodeOP_N((opcodetype)script[33]);
        keyhash = valtype(script.begin() + 1, script.begin() + 33);
        return true;
    }
    return false;
}

/** Test for "small positive integer" script opcodes - OP_1 through OP_16. */
static constexpr bool IsSmallInteger(opcodetype opcode)
{
    return opcode >= OP_1 && opcode <= OP_16;
}

static bool MatchMultisig(const CScript& script, unsigned int& required, std::vector<valtype>& pubkeys)
{
    opcodetype opcode;
    valtype data;
    CScript::const_iterator it = script.begin();
    if (script.size() < 1 || script.back() != OP_CHECKMULTISIG) return false;

    if (!script.GetOp(it, opcode, data) || !IsSmallInteger(opcode)) return false;
    required = CScript::DecodeOP_N(opcode);
    while (script.GetOp(it, opcode, data) && CPubKey::ValidSize(data)) {
        pubkeys.emplace_back(std::move(data));
    }
    if (!IsSmallInteger(opcode)) return false;
    unsigned int keys = CScript::DecodeOP_N(opcode);
    if (pubkeys.size() != keys || keys < required) return false;
    return (it + 1 == script.end());
}

bool Solver(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<std::vector<unsigned char> >& vSolutionsRet)
{
    vSolutionsRet.clear();

    // Shortcut for pay-to-script-hash, which are more constrained than the other types:
    // it is always OP_HASH160 20 [20 byte hash] OP_EQUAL
    if (scriptPubKey.IsPayToScriptHash())
    {
        typeRet = TX_SCRIPTHASH;
        vector<unsigned char> hashBytes(scriptPubKey.begin()+2, scriptPubKey.begin()+22);
        vSolutionsRet.push_back(hashBytes);
        return true;
    }

    // Provably prunable, data-carrying output
    //
    // So long as script passes the IsUnspendable() test and all but the first
    // byte passes the IsPushOnly() test we don't care what exactly is in the
    // script.
    if (scriptPubKey.size() >= 1 && scriptPubKey[0] == OP_RETURN && scriptPubKey.IsPushOnly(scriptPubKey.begin()+1)) {
        typeRet = TX_NULL_DATA;
        return true;
    }

    std::vector<unsigned char> data;
    if (MatchPayToPubkey(scriptPubKey, data)) {
        typeRet = TX_PUBKEY;
        vSolutionsRet.push_back(std::move(data));
        return true;
    }

    if (MatchPayToPubkeyHash(scriptPubKey, data)) {
        typeRet = TX_PUBKEYHASH;
        vSolutionsRet.push_back(std::move(data));
        return true;
    }

    unsigned int required;
    std::vector<std::vector<unsigned char>> keys;
    if (MatchMultisig(scriptPubKey, required, keys)) {
        typeRet = TX_MULTISIG;
        vSolutionsRet.push_back({static_cast<unsigned char>(required)}); // safe as required is in range 1..16
        vSolutionsRet.insert(vSolutionsRet.end(), keys.begin(), keys.end());
        vSolutionsRet.push_back({static_cast<unsigned char>(keys.size())}); // safe as size is in range 1..16
        return true;
    }

    uint8_t pqScheme;
    if (MatchPayToPQKeyHash(scriptPubKey, pqScheme, data)) {
        typeRet = TX_PQPKH;
        vSolutionsRet.push_back({pqScheme});
        vSolutionsRet.push_back(std::move(data));
        return true;
    }

    // The hybrid channel (quantum spec D-Q-19): {client scheme || hash (33), server key (33), refundHeight (script number)}.
    {
        PQChannelParams cp;
        if (MatchPQChannel(scriptPubKey, cp)) {
            typeRet = TX_PQCHANNEL;
            valtype client(1, cp.client.scheme);
            client.insert(client.end(), cp.client.hash.begin(), cp.client.hash.end());
            vSolutionsRet.push_back(client);
            vSolutionsRet.push_back(valtype(cp.server.begin(), cp.server.end()));
            vSolutionsRet.push_back(CScriptNum(cp.refundHeight).getvch());
            return true;
        }
    }

    // The vault primitive's templates (plan §15.3): exact shapes only, no solutions.
    {
        vault::VaultParams vp;
        if (vault::ParseVault(scriptPubKey, vp)) {
            typeRet = TX_VAULT;
            return true;
        }
        vault::IntentParams ip;
        if (vault::ParseIntent(scriptPubKey, ip)) {
            typeRet = TX_VAULT_INTENT;
            return true;
        }
    }

    vSolutionsRet.clear();
    typeRet = TX_NONSTANDARD;
    return false;
}

int ScriptSigArgsExpected(txnouttype t, const std::vector<std::vector<unsigned char> >& vSolutions)
{
    switch (t)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
    case TX_VAULT:        // variable: checked by the vault rules (S-1), see AreInputsStandard
    case TX_VAULT_INTENT:
    case TX_PQPKH:        // variable (s + p + 2 pushes per scheme): checked in AreInputsStandard
    case TX_PQCHANNEL:    // variable (s + p + 4 cooperative, s + p + 3 refund): checked in AreInputsStandard
        return -1;
    case TX_PUBKEY:
        return 1;
    case TX_PUBKEYHASH:
        return 2;
    case TX_MULTISIG:
        if (vSolutions.size() < 1 || vSolutions[0].size() < 1)
            return -1;
        return vSolutions[0][0] + 1;
    case TX_SCRIPTHASH:
        return 1; // doesn't include args needed by the script
    }
    return -1;
}

bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet)
{
    vector<valtype> vSolutions;
    txnouttype whichType;
    if (!Solver(scriptPubKey, whichType, vSolutions))
        return false;

    if (whichType == TX_PUBKEY)
    {
        CPubKey pubKey(vSolutions[0]);
        if (!pubKey.IsValid())
            return false;

        addressRet = pubKey.GetID();
        return true;
    }
    else if (whichType == TX_PUBKEYHASH)
    {
        addressRet = CKeyID(uint160(vSolutions[0]));
        return true;
    }
    else if (whichType == TX_SCRIPTHASH)
    {
        addressRet = CScriptID(uint160(vSolutions[0]));
        return true;
    }
    else if (whichType == TX_PQPKH)
    {
        addressRet = CPQKeyID(vSolutions[0][0], uint256(vSolutions[1]));
        return true;
    }
    // Multisig txns have more than one address...
    return false;
}

bool ExtractDestinations(const CScript& scriptPubKey, txnouttype& typeRet, vector<CTxDestination>& addressRet, int& nRequiredRet)
{
    addressRet.clear();
    typeRet = TX_NONSTANDARD;
    vector<valtype> vSolutions;
    if (!Solver(scriptPubKey, typeRet, vSolutions))
        return false;
    if (typeRet == TX_NULL_DATA){
        // This is data, not addresses
        return false;
    }

    if (typeRet == TX_MULTISIG)
    {
        nRequiredRet = vSolutions.front()[0];
        for (unsigned int i = 1; i < vSolutions.size()-1; i++)
        {
            CPubKey pubKey(vSolutions[i]);
            if (!pubKey.IsValid())
                continue;

            CTxDestination address = pubKey.GetID();
            addressRet.push_back(address);
        }

        if (addressRet.empty())
            return false;
    }
    else
    {
        nRequiredRet = 1;
        CTxDestination address;
        if (!ExtractDestination(scriptPubKey, address))
           return false;
        addressRet.push_back(address);
    }

    return true;
}

namespace
{
class CScriptVisitor
{
private:
    CScript *script;
public:
    CScriptVisitor(CScript *scriptin) { script = scriptin; }

    bool operator()(const CNoDestination &dest) const {
        script->clear();
        return false;
    }

    bool operator()(const CKeyID &keyID) const {
        script->clear();
        *script << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
        return true;
    }

    bool operator()(const CScriptID &scriptID) const {
        script->clear();
        *script << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
        return true;
    }

    bool operator()(const CPQKeyID &id) const {
        *script = GetScriptForPQKey(id);
        return !script->empty();
    }
};
}

CScript GetScriptForDestination(const CTxDestination& dest)
{
    CScript script;

    std::visit(CScriptVisitor(&script), dest);
    return script;
}

CScript GetScriptForRawPubKey(const CPubKey& pubKey)
{
    return CScript() << std::vector<unsigned char>(pubKey.begin(), pubKey.end()) << OP_CHECKSIG;
}

CScript GetScriptForPQKey(const CPQKeyID& id)
{
    if (!pq::IsKnownScheme(id.scheme)) return CScript();   // registered schemes only (review A F6)
    return CScript() << ToByteVector(id.hash) << CScript::EncodeOP_N(id.scheme) << OP_CHECKPQSIG;
}

CScript GetScriptForPQChannel(const CPQKeyID& client, const CPubKey& server, int64_t refundHeight)
{
    if (!pq::IsKnownScheme(client.scheme)) return CScript();
    if (!server.IsValid() || !server.IsCompressed()) return CScript();
    if (refundHeight < 1 || refundHeight >= LOCKTIME_THRESHOLD) return CScript();
    return CScript() << OP_IF << ToByteVector(client.hash) << CScript::EncodeOP_N(client.scheme) << OP_CHECKPQSIG << OP_VERIFY
                     << ToByteVector(server) << OP_CHECKSIG
                     << OP_ELSE << refundHeight << OP_CHECKLOCKTIMEVERIFY << OP_DROP
                     << ToByteVector(client.hash) << CScript::EncodeOP_N(client.scheme) << OP_CHECKPQSIG
                     << OP_ENDIF;
}

bool MatchPQChannel(const CScript& script, PQChannelParams& out)
{
    // Cheap pre-checks, then decode the four fields by token and require the rebuilt script byte for byte
    // (minimal pushes, identical client slots).
    // 111 bytes + the refundHeight push (1..6): 112..117 bytes
    if (script.size() < 112 || script.size() > 117 || script[0] != OP_IF || script.back() != OP_ENDIF)
        return false;
    std::vector<std::pair<opcodetype, valtype>> ops;
    CScript::const_iterator pc = script.begin();
    while (pc < script.end()) {
        opcodetype op;
        valtype data;
        if (!script.GetOp(pc, op, data)) return false;
        ops.emplace_back(op, data);
        if (ops.size() > 15) return false;
    }
    if (ops.size() != 15) return false;
    if (ops[1].second.size() != 32 || ops[5].second.size() != 33) return false;
    const opcodetype schemeOp = ops[2].first;
    if (schemeOp != OP_1 && schemeOp != OP_2) return false;
    int64_t refund;
    if (ops[8].first >= OP_1 && ops[8].first <= OP_16) {
        refund = CScript::DecodeOP_N(ops[8].first);
    } else if (ops[8].first <= OP_PUSHDATA4 && !ops[8].second.empty() && ops[8].second.size() <= 5) {
        try {
            refund = CScriptNum(ops[8].second, true, 5).getint();
        } catch (const scriptnum_error&) {
            return false;
        }
    } else {
        return false;
    }
    PQChannelParams cp;
    cp.client = CPQKeyID((uint8_t)CScript::DecodeOP_N(schemeOp), uint256(ops[1].second));
    cp.server = CPubKey(ops[5].second.begin(), ops[5].second.end());
    cp.refundHeight = refund;
    if (!cp.server.IsFullyValid()) return false;
    const CScript rebuilt = GetScriptForPQChannel(cp.client, cp.server, cp.refundHeight);
    if (rebuilt.empty() || rebuilt != script) return false;
    out = cp;
    return true;
}

CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey>& keys)
{
    CScript script;

    script << CScript::EncodeOP_N(nRequired);
    for (const CPubKey& key : keys)
        script << ToByteVector(key);
    script << CScript::EncodeOP_N(keys.size()) << OP_CHECKMULTISIG;
    return script;
}

bool IsValidDestination(const CTxDestination& dest) {
    return !std::holds_alternative<CNoDestination>(dest);
}

bool IsKeyDestination(const CTxDestination& dest) {
    return std::holds_alternative<CKeyID>(dest);
}

bool IsScriptDestination(const CTxDestination& dest) {
    return std::holds_alternative<CScriptID>(dest);
}

bool IsPQKeyDestination(const CTxDestination& dest) {
    return std::holds_alternative<CPQKeyID>(dest);
}

// insightexplorer
CTxDestination DestFromAddressHash(int scriptType, uint160& addressHash)
{
    switch (scriptType) {
    case CScript::P2PKH:
        return CTxDestination(CKeyID(addressHash));
    case CScript::P2SH:
        return CTxDestination(CScriptID(addressHash));
    default:
        // This probably won't ever happen, because it would mean that
        // the addressindex contains a type (say, 3) that we (currently)
        // don't recognize; maybe we "dropped support" for it?
        return CNoDestination();
    }
}
