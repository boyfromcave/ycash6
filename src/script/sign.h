// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2017-2023 The Zcash developers
// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_SCRIPT_SIGN_H
#define BITCOIN_SCRIPT_SIGN_H

#include "script/interpreter.h"

class CKeyID;
class CKeyStore;
struct CPQKeyID;
class CScript;
class CTransaction;

struct CMutableTransaction;

/** Virtual base class for signature creators. */
class BaseSignatureCreator {
protected:
    const CKeyStore* keystore;

public:
    BaseSignatureCreator(const CKeyStore* keystoreIn) : keystore(keystoreIn) {}
    const CKeyStore& KeyStore() const { return *keystore; };
    virtual ~BaseSignatureCreator() {}
    virtual const BaseSignatureChecker& Checker() const =0;

    /** Create a singular (non-script) signature. */
    virtual bool CreateSig(std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, uint32_t consensusBranchId) const =0;

    /** Create a post-quantum signature (with its hashtype byte) by the key id and return that key's
     *  public key: the two values an OP_CHECKPQSIG input carries (quantum plan §4.2). */
    virtual bool CreatePQSig(std::vector<unsigned char>& vchSig, std::vector<unsigned char>& vchPubKey, const CPQKeyID& id, const CScript& scriptCode, uint32_t consensusBranchId) const { return false; }
};

/** A signature creator for transactions. */
class TransactionSignatureCreator : public BaseSignatureCreator {
    const CTransaction* txTo;
    const PrecomputedTransactionData& txToData;
    unsigned int nIn;
    int nHashType;
    CAmount amount;
    const TransactionSignatureChecker checker;

public:
    TransactionSignatureCreator(const CKeyStore* keystoreIn, const CTransaction* txToIn, const PrecomputedTransactionData& txToDataIn, unsigned int nInIn, const CAmount& amountIn, int nHashTypeIn=SIGHASH_ALL);
    const BaseSignatureChecker& Checker() const { return checker; }
    bool CreateSig(std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, uint32_t consensusBranchId) const;
    bool CreatePQSig(std::vector<unsigned char>& vchSig, std::vector<unsigned char>& vchPubKey, const CPQKeyID& id, const CScript& scriptCode, uint32_t consensusBranchId) const;
};

class MutableTransactionSignatureCreator : public TransactionSignatureCreator {
    CTransaction tx;

public:
    MutableTransactionSignatureCreator(const CKeyStore* keystoreIn, const CMutableTransaction* txToIn, const PrecomputedTransactionData& txdataIn, unsigned int nInIn, const CAmount& amount, int nHashTypeIn) : TransactionSignatureCreator(keystoreIn, &tx, txdataIn, nInIn, amount, nHashTypeIn), tx(*txToIn) {}
};

/** A signature creator that just produces 72-byte empty signatures, and post-quantum signatures of
 *  the scheme's exact size (zeros, SIGHASH_ALL) with the keystore's public key, so that a dummy
 *  scriptSig has the signed one's size. A PQ key the keystore does not hold cannot be dummy-signed
 *  (its public key is unknown, so the key hash check fails). */
class DummySignatureCreator : public BaseSignatureCreator {
public:
    DummySignatureCreator(const CKeyStore* keystoreIn) : BaseSignatureCreator(keystoreIn) {}
    const BaseSignatureChecker& Checker() const;
    bool CreateSig(std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, uint32_t consensusBranchId) const;
    bool CreatePQSig(std::vector<unsigned char>& vchSig, std::vector<unsigned char>& vchPubKey, const CPQKeyID& id, const CScript& scriptCode, uint32_t consensusBranchId) const;
};

struct SignatureData {
    CScript scriptSig;

    SignatureData() {}
    explicit SignatureData(const CScript& script) : scriptSig(script) {}
};

/** Produce a script signature using a generic signature creator. */
bool ProduceSignature(const BaseSignatureCreator& creator, const CScript& scriptPubKey, SignatureData& sigdata, uint32_t consensusBranchId);
/** As above, testing the solution under verifyFlags in place of STANDARD_SCRIPT_VERIFY_FLAGS. A
 *  TX_PQPKH input needs the vault flags of the block it goes into (STANDARD_SCRIPT_VERIFY_FLAGS |
 *  GetVaultScriptFlags(tip + 1)), or OP_CHECKPQSIG is a bad opcode (quantum spec §5.2). */
bool ProduceSignature(const BaseSignatureCreator& creator, const CScript& scriptPubKey, SignatureData& sigdata, uint32_t consensusBranchId, unsigned int verifyFlags);

/** Whether spending scriptPubKey carries a post-quantum signature: TX_PQPKH, or a vault V/I template
 *  (whose owner paths do). Such a transaction is priced by size (quantum plan §4.5). */
bool IsPQInputScript(const CScript& scriptPubKey);

/** The scriptSig pushes of an OP_CHECKPQSIG (quantum plan §4.2): sig_1..sig_s s pk_1..pk_p p, each
 *  chunk but the last 520 bytes, s and p as one-byte numbers (PushAll / the caller encodes them
 *  OP_1..OP_16). vchSig carries its hashtype byte. */
std::vector<std::vector<unsigned char>> PQScriptSigPushes(const std::vector<unsigned char>& vchSig, const std::vector<unsigned char>& vchPubKey);
/** The pushes as a script, minimal encodings (s and p as OP_n). */
CScript PQScriptSig(const std::vector<unsigned char>& vchSig, const std::vector<unsigned char>& vchPubKey);

/**
 * Sign the owner path of a vault template input (quantum spec §1.5): selector 2 (V OWNER) or 3
 * (V or I OWNER-RELEASED) of the V/I scriptPubKey templateScript at txTo.vin[nIn], with the
 * keystore's PQ key owner. Sets that input's scriptSig to <sig chunks> <s> <pk chunks> <p> <selector>
 * (SIGHASH_ALL) and verifies it under verifyFlags (pass STANDARD_SCRIPT_VERIFY_FLAGS |
 * GetVaultScriptFlags(tip + 1)). The caller sets nLockTime / nSequence first (selector 2 needs
 * nLockTime >= ownerHeight and a non-final sequence). False, with serror set when the script
 * fails, if the key is missing (or locked) or the signature does not verify.
 * checker: the checker the result is verified with; null = a TransactionSignatureChecker, which
 * answers no set state, so selector 3 (OP_CHECKSETDORMANT) needs the caller's vault::SetSigChecker
 * (built over txTo as it stands: scriptSigs do not enter the sighash).
 */
bool SignPQOwnerSpend(const CKeyStore& keystore, const CPQKeyID& owner, const CScript& templateScript,
                      CMutableTransaction& txTo, unsigned int nIn, const CAmount& amount, int selector,
                      uint32_t consensusBranchId, unsigned int verifyFlags, ScriptError* serror = nullptr,
                      const BaseSignatureChecker* checker = nullptr);

/** Produce a script signature for a transaction. */
bool SignSignature(
    const CKeyStore &keystore,
    const CScript& fromPubKey,
    CMutableTransaction& txTo,
    const PrecomputedTransactionData& txToData,
    unsigned int nIn,
    const CAmount& amount,
    int nHashType,
    uint32_t consensusBranchId);
/** As above, testing the solution under verifyFlags (see ProduceSignature). */
bool SignSignature(
    const CKeyStore &keystore,
    const CScript& fromPubKey,
    CMutableTransaction& txTo,
    const PrecomputedTransactionData& txToData,
    unsigned int nIn,
    const CAmount& amount,
    int nHashType,
    uint32_t consensusBranchId,
    unsigned int verifyFlags);
bool SignSignature(
    const CKeyStore& keystore,
    const CTransaction& txFrom,
    CMutableTransaction& txTo,
    const PrecomputedTransactionData& txToData,
    unsigned int nIn,
    int nHashType,
    uint32_t consensusBranchId);

/** Combine two script signatures using a generic signature checker, intelligently, possibly with OP_0 placeholders. */
SignatureData CombineSignatures(
    const CScript& scriptPubKey,
    const BaseSignatureChecker& checker,
    const SignatureData& scriptSig1,
    const SignatureData& scriptSig2,
    uint32_t consensusBranchId);

/** Extract signature data from a transaction, and insert it. */
SignatureData DataFromTransaction(const CMutableTransaction& tx, unsigned int nIn);
void UpdateTransaction(CMutableTransaction& tx, unsigned int nIn, const SignatureData& data);

#endif // BITCOIN_SCRIPT_SIGN_H
