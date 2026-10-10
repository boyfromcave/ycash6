// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// NOTE: This file is intended to be customised by the end user, and includes only local node policy logic

#include "policy/policy.h"

#include "crypto/pq/scheme.h"
#include "main.h"
#include "primitives/transaction.h"
#include "tinyformat.h"
#include "util/system.h"
#include "util/strencodings.h"
#include "vault/act.h"
#include "vault/template.h"

CAmount PerSaplingOutputFees(const CTransaction& tx)
{
    // Ycash anti-spam mempool fee floor scaled by Sapling output count.
    // Originally introduced in ycash-official to mitigate the 2022 Zcash
    // many-shielded-outputs spam attack; ported here to run alongside the
    // ZIP 317 unpaid-action rule.
    //
    // Within the grace range (<= DEFAULT_EXEMPT_SAPLING_OUTPUTS outputs),
    // the floor is a single DEFAULT_PER_SAPLING_OUTPUT_FEE; beyond that,
    // each additional output adds DEFAULT_PER_SAPLING_OUTPUT_FEE.
    const unsigned int nTotalSaplingOutputs = tx.GetSaplingOutputsCount();

    if (nTotalSaplingOutputs == 0) {
        return 0;
    }

    if (nTotalSaplingOutputs <= DEFAULT_EXEMPT_SAPLING_OUTPUTS) {
        return DEFAULT_PER_SAPLING_OUTPUT_FEE;
    }

    return (nTotalSaplingOutputs - DEFAULT_EXEMPT_SAPLING_OUTPUTS) * DEFAULT_PER_SAPLING_OUTPUT_FEE;
}


    /**
     * Check transaction inputs to mitigate two
     * potential denial-of-service attacks:
     * 
     * 1. scriptSigs with extra data stuffed into them,
     *    not consumed by scriptPubKey (or P2SH script)
     * 2. P2SH scripts with very many expensive
     *    CHECKSIG/CHECKMULTISIG operations
     *
     * Check transaction inputs, and make sure any
     * pay-to-script-hash transactions are evaluating IsStandard scripts
     * 
     * Why bother? To avoid denial-of-service attacks; an attacker
     * can submit a standard HASH... OP_EQUAL transaction,
     * which will get accepted into blocks. The redemption
     * script can be anything; an attacker could use a very
     * expensive-to-check-upon-redemption script like:
     *   DUP CHECKSIG DROP ... repeated 100 times... OP_1
     */

bool IsStandard(const CScript& scriptPubKey, txnouttype& whichType)
{
    std::vector<std::vector<unsigned char> > vSolutions;
    if (!Solver(scriptPubKey, whichType, vSolutions))
        return false;

    if (whichType == TX_MULTISIG)
    {
        unsigned char m = vSolutions.front()[0];
        unsigned char n = vSolutions.back()[0];
        // Support up to x-of-3 multisig txns as standard
        if (n < 1 || n > 3)
            return false;
        if (m < 1 || m > n)
            return false;
    } else if (whichType == TX_NULL_DATA &&
               (!GetBoolArg("-datacarrier", true) || scriptPubKey.size() > nMaxDatacarrierBytes))
          return false;

    return whichType != TX_NONSTANDARD;
}

bool IsStandardTx(const CTransaction& tx, std::string& reason, const CChainParams& chainparams, const int nHeight)
{
    bool overwinterActive = chainparams.GetConsensus().NetworkUpgradeActive(nHeight,  Consensus::UPGRADE_OVERWINTER);
    bool saplingActive = chainparams.GetConsensus().NetworkUpgradeActive(nHeight, Consensus::UPGRADE_SAPLING);
    bool nu5Active = chainparams.GetConsensus().NetworkUpgradeActive(nHeight, Consensus::UPGRADE_NU5);

    if (nu5Active) {
        // NU5 standard rules apply
        if (tx.nVersion > CTransaction::NU5_MAX_CURRENT_VERSION || tx.nVersion < CTransaction::NU5_MIN_CURRENT_VERSION) {
            reason = "nu5-version";
            return false;
        }
    } else if (saplingActive) {
        // Sapling standard rules apply
        if (tx.nVersion > CTransaction::SAPLING_MAX_CURRENT_VERSION || tx.nVersion < CTransaction::SAPLING_MIN_CURRENT_VERSION) {
            reason = "sapling-version";
            return false;
        }
    } else if (overwinterActive) {
        // Overwinter standard rules apply
        if (tx.nVersion > CTransaction::OVERWINTER_MAX_CURRENT_VERSION || tx.nVersion < CTransaction::OVERWINTER_MIN_CURRENT_VERSION) {
            reason = "overwinter-version";
            return false;
        }
    } else {
        // Sprout standard rules apply
        if (tx.nVersion > CTransaction::SPROUT_MAX_CURRENT_VERSION || tx.nVersion < CTransaction::SPROUT_MIN_CURRENT_VERSION) {
            reason = "version";
            return false;
        }
    }

    // UPGRADE_VAULT (plan §15.3, §15.5): the V and I templates are standard, and a `YV` act
    // OP_RETURN may carry up to MAX_VAULT_ACT_BYTES, only where the upgrade is active.
    const bool vaultActive = chainparams.GetConsensus().NetworkUpgradeActive(nHeight, Consensus::UPGRADE_VAULT);

    for (const CTxIn& txin : tx.vin)
    {
        // Biggest 'standard' txin is a 15-of-15 P2SH multisig with compressed
        // keys. (remember the 520 byte limit on redeemScript size) That works
        // out to a (15*(33+1))+3=513 byte redeemScript, 513+1+15*(73+1)+3=1627
        // bytes of scriptSig, which we round off to 1650 bytes for some minor
        // future-proofing. That's also enough to spend a 20-of-20
        // CHECKMULTISIG scriptPubKey, though such a scriptPubKey is not
        // considered standard)
        //
        // Once UPGRADE_VAULT is active a post-quantum spend (TX_PQPKH, a V/I owner) may carry up to
        // MAX_STANDARD_PQ_SCRIPTSIG; IsStandardTx has no prevouts, so AreInputsStandard re-checks
        // MAX_STANDARD_SCRIPTSIG for every other input (quantum spec §2.3, F-6).
        if (txin.scriptSig.size() > (vaultActive ? MAX_STANDARD_PQ_SCRIPTSIG : MAX_STANDARD_SCRIPTSIG)) {
            reason = "scriptsig-size";
            return false;
        }
        if (!txin.scriptSig.IsPushOnly()) {
            reason = "scriptsig-not-pushonly";
            return false;
        }
    }

    const bool falconActive = IsPQFalconActive(chainparams.GetConsensus(), nHeight);

    unsigned int nDataOut = 0;
    txnouttype whichType;
    for (const CTxOut& txout : tx.vout) {
        if (vaultActive && fAcceptDatacarrier && vault::IsActOutput(txout.scriptPubKey) &&
            txout.scriptPubKey.size() <= MAX_VAULT_ACT_BYTES && txout.scriptPubKey.IsPushOnly(txout.scriptPubKey.begin() + 1)) {
            nDataOut++;
            continue;
        }
        if (!::IsStandard(txout.scriptPubKey, whichType)) {
            reason = "scriptpubkey";
            return false;
        }
        if ((whichType == TX_VAULT || whichType == TX_VAULT_INTENT || whichType == TX_PQPKH) && !vaultActive) {
            reason = "scriptpubkey";
            return false;
        }
        // No new scheme-2 (FN-DSA-512) PQPKH, V or I output before Falcon is active (quantum spec A-1):
        // the interpreter would refuse its owner/holder spend.
        if (!falconActive) {
            const std::optional<uint8_t> scheme = PQScriptScheme(txout.scriptPubKey, whichType);
            if (scheme && *scheme == pq::SCHEME_FN_DSA_512) {
                reason = "scriptpubkey";
                return false;
            }
        }

        if (whichType == TX_NULL_DATA)
            nDataOut++;
        else if ((whichType == TX_MULTISIG) && (!fIsBareMultisigStd)) {
            reason = "bare-multisig";
            return false;
        } else if (txout.IsDust()) {
            reason = "dust";
            return false;
        }
    }

    // only one OP_RETURN txout is permitted
    if (nDataOut > 1) {
        reason = "multi-op-return";
        return false;
    }

    return true;
}

bool AreInputsStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs, uint32_t consensusBranchId)
{
    if (tx.IsCoinBase())
        return true; // Coinbases don't use vin normally

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const CTxOut& prev = mapInputs.GetOutputFor(tx.vin[i]);

        std::vector<std::vector<unsigned char> > vSolutions;
        txnouttype whichType;
        // get the scriptPubKey corresponding to this input:
        const CScript& prevScript = prev.scriptPubKey;
        if (!Solver(prevScript, whichType, vSolutions))
            return false;
        // Post-quantum spends may carry MAX_STANDARD_PQ_SCRIPTSIG, every other input
        // MAX_STANDARD_SCRIPTSIG (IsStandardTx admits the larger bound without prevouts; F-6).
        const bool pqSpend = whichType == TX_PQPKH || whichType == TX_VAULT || whichType == TX_VAULT_INTENT;
        if (tx.vin[i].scriptSig.size() > (pqSpend ? MAX_STANDARD_PQ_SCRIPTSIG : MAX_STANDARD_SCRIPTSIG))
            return false;
        // A template input's scriptSig (push-only, IsStandardTx) is checked by the vault rules (S-1).
        if (whichType == TX_VAULT || whichType == TX_VAULT_INTENT)
            continue;
        if (whichType == TX_PQPKH) {
            // <sig_1>..<sig_s> <s> <pk_1>..<pk_p> <p>: exactly s + p + 2 pushes for the scheme (A-14).
            const uint8_t scheme = vSolutions[0][0];
            const size_t sigLen = pq::SigSize(scheme) + 1, pkLen = pq::PubKeySize(scheme);
            if (sigLen == 1 || pkLen == 0)
                return false;
            const size_t s = (sigLen + pq::MAX_CHUNK - 1) / pq::MAX_CHUNK, p = (pkLen + pq::MAX_CHUNK - 1) / pq::MAX_CHUNK;
            std::vector<std::vector<unsigned char> > stack;
            if (!EvalScript(stack, tx.vin[i].scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), consensusBranchId))
                return false;
            if (stack.size() != s + p + 2)
                return false;
            continue;
        }
        int nArgsExpected = ScriptSigArgsExpected(whichType, vSolutions);
        if (nArgsExpected < 0)
            return false;

        // Transactions with extra stuff in their scriptSigs are
        // non-standard. Note that this EvalScript() call will
        // be quick, because if there are any operations
        // beside "push data" in the scriptSig
        // IsStandardTx() will have already returned false
        // and this method isn't called.
        std::vector<std::vector<unsigned char> > stack;
        if (!EvalScript(stack, tx.vin[i].scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), consensusBranchId))
            return false;

        if (whichType == TX_SCRIPTHASH)
        {
            if (stack.empty())
                return false;
            CScript subscript(stack.back().begin(), stack.back().end());
            std::vector<std::vector<unsigned char> > vSolutions2;
            txnouttype whichType2;
            if (Solver(subscript, whichType2, vSolutions2))
            {
                int tmpExpected = ScriptSigArgsExpected(whichType2, vSolutions2);
                if (tmpExpected < 0)
                    return false;
                nArgsExpected += tmpExpected;
            }
            else
            {
                // Any other Script with less than 15 sigops OK:
                unsigned int sigops = subscript.GetSigOpCount(true);
                // ... OP_CHECKPQSIG's 20 policy sigops included (quantum spec R-B2), so a redeem
                // script that holds one is non-standard:
                sigops += GetPQSigOpCount(subscript);
                // ... extra data left on the stack after execution is OK, too:
                return (sigops <= MAX_P2SH_SIGOPS);
            }
        }

        if (stack.size() != (unsigned int)nArgsExpected)
            return false;
    }

    return true;
}

std::optional<uint8_t> PQScriptScheme(const CScript& scriptPubKey, txnouttype whichType)
{
    if (whichType == TX_PQPKH) {
        CTxDestination dest;
        if (ExtractDestination(scriptPubKey, dest) && IsPQKeyDestination(dest))
            return std::get<CPQKeyID>(dest).scheme;
        return std::nullopt;
    }
    if (whichType == TX_VAULT) {
        vault::VaultParams vp;
        if (vault::ParseVault(scriptPubKey, vp))
            return vp.owner.scheme;
    }
    if (whichType == TX_VAULT_INTENT) {
        vault::IntentParams ip;
        if (vault::ParseIntent(scriptPubKey, ip))
            return ip.owner.scheme;
    }
    return std::nullopt;
}

unsigned int GetPQSigOpCount(const CScript& script)
{
    unsigned int n = 0;
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    while (pc < script.end() && script.GetOp(pc, opcode)) {
        if (opcode == OP_CHECKPQSIG)
            n += pq::SIGOP_COST;
    }
    return n;
}

unsigned int GetPQSigOpCount(const CTransaction& tx, const CCoinsViewCache& mapInputs)
{
    if (tx.IsCoinBase())
        return 0;
    unsigned int n = 0;
    for (const CTxIn& txin : tx.vin) {
        const CScript& prevScript = mapInputs.GetOutputFor(txin).scriptPubKey;
        n += GetPQSigOpCount(txin.scriptSig) + GetPQSigOpCount(prevScript);
        if (prevScript.IsPayToScriptHash()) {
            // the redeem script is the scriptSig's last push (as CScript::GetSigOpCount(scriptSig))
            CScript::const_iterator pc = txin.scriptSig.begin();
            opcodetype opcode;
            std::vector<unsigned char> data;
            bool pushOnly = true;
            while (pc < txin.scriptSig.end()) {
                if (!txin.scriptSig.GetOp(pc, opcode, data) || opcode > OP_16) {
                    pushOnly = false;
                    break;
                }
            }
            if (pushOnly)
                n += GetPQSigOpCount(CScript(data.begin(), data.end()));
        }
    }
    return n;
}
