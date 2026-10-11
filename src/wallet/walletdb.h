// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Copyright (c) 2016-2023 The Zcash developers
// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_WALLET_WALLETDB_H
#define BITCOIN_WALLET_WALLETDB_H

#include "amount.h"
#include "wallet/db.h"
#include "key.h"
#include "keystore.h"
#include "zcash/Address.hpp"
#include "zcash/address/zip32.h"

#include <list>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

static const bool DEFAULT_FLUSHWALLET = true;

struct CBlockLocator;
class CAtomicSwapInfo;
class CKeyPool;
class CMasterKey;
class CScript;
class CWallet;
class CWalletTx;
class uint160;
class uint256;

/** Error statuses for the wallet database */
enum DBErrors
{
    DB_LOAD_OK,
    DB_CORRUPT,
    DB_NONCRITICAL_ERROR,
    DB_TOO_NEW,
    DB_LOAD_FAIL,
    DB_NEED_REWRITE,
    DB_WRONG_NETWORK,
};

/* hd chain metadata */
class CHDChain
{
private:
    int nVersion;
    uint256 seedFp;
    int64_t nCreateTime; // 0 means unknown
    uint32_t accountCounter;
    uint32_t legacyTKeyExternalCounter;
    uint32_t legacyTKeyInternalCounter;
    uint32_t legacySaplingKeyCounter;
    bool mnemonicSeedBackupConfirmed;

    CHDChain() { SetNull(); }

    void SetNull()
    {
        nVersion = CHDChain::CURRENT_VERSION;
        seedFp.SetNull();
        nCreateTime = 0;
        accountCounter = 0;
        legacyTKeyExternalCounter = 0;
        legacyTKeyInternalCounter = 0;
        legacySaplingKeyCounter = 0;
        mnemonicSeedBackupConfirmed = false;
    }
public:
    static const int VERSION_HD_BASE = 1;
    static const int CURRENT_VERSION = VERSION_HD_BASE;

    CHDChain(uint256 seedFpIn, int64_t nCreateTimeIn): nVersion(CHDChain::CURRENT_VERSION), seedFp(seedFpIn), nCreateTime(nCreateTimeIn), accountCounter(0), legacyTKeyExternalCounter(0), legacyTKeyInternalCounter(0), legacySaplingKeyCounter(0), mnemonicSeedBackupConfirmed(false) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nVersion);
        READWRITE(seedFp);
        READWRITE(nCreateTime);
        READWRITE(accountCounter);
        READWRITE(legacyTKeyExternalCounter);
        READWRITE(legacyTKeyInternalCounter);
        READWRITE(legacySaplingKeyCounter);
        READWRITE(mnemonicSeedBackupConfirmed);
    }

    template <typename Stream>
    static CHDChain Read(Stream& stream) {
        CHDChain chain;
        stream >> chain;
        return chain;
    }

    const uint256 GetSeedFingerprint() const {
        return seedFp;
    }

    uint32_t GetAccountCounter() const {
        return accountCounter;
    }

    /** Increments the account counter by 1 and returns it. Returns std::nullopt
     *  if the increment operation would cause an overflow. */
    std::optional<uint32_t> IncrementAccountCounter() {
        auto newAccountCounter = accountCounter + 1;
        if (newAccountCounter >= libzcash::ZCASH_LEGACY_ACCOUNT) {
            return std::nullopt;
        } else {
            accountCounter = newAccountCounter;
            return newAccountCounter;
        }
    }

    uint32_t GetLegacyTKeyCounter(bool external) {
        return external ? legacyTKeyExternalCounter : legacyTKeyInternalCounter;
    }

    void IncrementLegacyTKeyCounter(bool external) {
        if (external) {
            legacyTKeyExternalCounter += 1;
        } else {
            legacyTKeyInternalCounter += 1;
        }
    }

    uint32_t GetLegacySaplingKeyCounter() const {
        return legacySaplingKeyCounter;
    }

    void IncrementLegacySaplingKeyCounter() {
        legacySaplingKeyCounter += 1;
    }

    void SetMnemonicSeedBackupConfirmed() {
        mnemonicSeedBackupConfirmed = true;
    }

    bool IsMnemonicSeedBackupConfirmed() {
        return mnemonicSeedBackupConfirmed;
    }
};

class CKeyMetadata
{
public:
    static const int VERSION_BASIC=1;
    static const int VERSION_WITH_HDDATA=10;
    static const int CURRENT_VERSION=VERSION_WITH_HDDATA;
    int nVersion;
    int64_t nCreateTime; // 0 means unknown
    std::string hdKeypath; //optional HD/zip32 keypath
    uint256 seedFp;

    CKeyMetadata()
    {
        SetNull();
    }
    CKeyMetadata(int64_t nCreateTime_)
    {
        SetNull();
        nCreateTime = nCreateTime_;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(nCreateTime);
        if (this->nVersion >= VERSION_WITH_HDDATA)
        {
            READWRITE(hdKeypath);
            READWRITE(seedFp);
        }
    }

    void SetNull()
    {
        nVersion = CKeyMetadata::CURRENT_VERSION;
        nCreateTime = 0;
        hdKeypath.clear();
        seedFp.SetNull();
    }
};

class ZcashdUnifiedAccountMetadata {
private:
    libzcash::SeedFingerprint seedFp;
    uint32_t bip44CoinType;
    libzcash::AccountId accountId;
    libzcash::UFVKId ufvkId;

    ZcashdUnifiedAccountMetadata() {}
public:
    ZcashdUnifiedAccountMetadata(
            libzcash::SeedFingerprint seedFp,
            uint32_t bip44CoinType,
            libzcash::AccountId accountId,
            libzcash::UFVKId ufvkId):
            seedFp(seedFp), bip44CoinType(bip44CoinType), accountId(accountId), ufvkId(ufvkId) {}

    /** Returns the fingerprint of the HD seed used to generate this key. */
    const libzcash::SeedFingerprint& GetSeedFingerprint() const {
        return seedFp;
    }
    /** Returns the ZIP 32 account id for which this key was generated. */
    uint32_t GetBip44CoinType() const {
        return bip44CoinType;
    }
    /** Returns the ZIP 32 account id for which this key was generated. */
    libzcash::AccountId GetAccountId() const {
        return accountId;
    }
    /** Returns the fingerprint of the ufvk this key was generated. */
    const libzcash::UFVKId& GetKeyID() const {
        return ufvkId;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(seedFp);
        READWRITE(bip44CoinType);
        READWRITE(accountId);
        READWRITE(ufvkId);
    }

    template <typename Stream>
    static ZcashdUnifiedAccountMetadata Read(Stream& stream) {
        ZcashdUnifiedAccountMetadata meta;
        stream >> meta;
        return meta;
    }
};

class ZcashdUnifiedAddressMetadata;

// Serialization wrapper for reading and writing ReceiverType
// in CompactSize format.
class ReceiverTypeSer {
private:
    libzcash::ReceiverType t;

    friend class ZcashdUnifiedAddressMetadata;
public:
    ReceiverTypeSer() {} // for serialization only
    ReceiverTypeSer(libzcash::ReceiverType t): t(t) {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        WriteCompactSize<Stream>(s, (uint64_t) t);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        t = (libzcash::ReceiverType) ReadCompactSize<Stream>(s);
    }
};

class ZcashdUnifiedAddressMetadata {
private:
    libzcash::UFVKId ufvkId;
    libzcash::diversifier_index_t diversifierIndex;
    std::set<libzcash::ReceiverType> receiverTypes;

    ZcashdUnifiedAddressMetadata() {}
public:
    ZcashdUnifiedAddressMetadata(
            libzcash::UFVKId ufvkId,
            libzcash::diversifier_index_t diversifierIndex,
            std::set<libzcash::ReceiverType> receiverTypes):
            ufvkId(ufvkId), diversifierIndex(diversifierIndex), receiverTypes(receiverTypes) {}

    libzcash::UFVKId GetKeyID() const {
        return ufvkId;
    }
    libzcash::diversifier_index_t GetDiversifierIndex() const {
        return diversifierIndex;
    }
    const std::set<libzcash::ReceiverType>& GetReceiverTypes() const {
        return receiverTypes;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(ufvkId);
        READWRITE(diversifierIndex);
        if (ser_action.ForRead()) {
            std::vector<ReceiverTypeSer> serReceiverTypes;
            READWRITE(serReceiverTypes);
            receiverTypes.clear();
            for (ReceiverTypeSer r : serReceiverTypes)
                receiverTypes.insert(r.t);
        } else {
            std::vector<ReceiverTypeSer> serReceiverTypes;
            for (libzcash::ReceiverType r : receiverTypes)
                serReceiverTypes.push_back(ReceiverTypeSer(r));
            READWRITE(serReceiverTypes);
        }
    }

    template <typename Stream>
    static ZcashdUnifiedAddressMetadata Read(Stream& stream) {
        ZcashdUnifiedAddressMetadata meta;
        stream >> meta;
        return meta;
    }

    friend inline bool operator==(const ZcashdUnifiedAddressMetadata& a, const ZcashdUnifiedAddressMetadata& b) {
        return
            a.ufvkId == b.ufvkId &&
            a.diversifierIndex == b.diversifierIndex &&
            a.receiverTypes == b.receiverTypes;
    }
};

// Serialization wrapper for reading and writing RecipientAddress
// as a pair of typecode and address bytes, similar to how unified address
// receivers are written (but excluding the unknown receiver case)
class CSerializeRecipientAddress {
    libzcash::RecipientAddress recipient;
    libzcash::ReceiverType typecode;
    CSerializeRecipientAddress() {} // for serialization only

    public:
        CSerializeRecipientAddress(libzcash::RecipientAddress recipient): recipient(recipient) {}

        template<typename Stream>
        void Serialize(Stream& s) const {
            examine(recipient, match {
                [&](const CKeyID& keyId) {
                    ReceiverTypeSer(libzcash::ReceiverType::P2PKH).Serialize(s);
                    s << keyId;
                },
                [&](const CScriptID& scriptId) {
                    ReceiverTypeSer(libzcash::ReceiverType::P2SH).Serialize(s);
                    s << scriptId;
                },
                [&](const libzcash::SaplingPaymentAddress& saplingAddr) {
                    ReceiverTypeSer(libzcash::ReceiverType::Sapling).Serialize(s);
                    s << saplingAddr;
                },
                [&](const libzcash::OrchardRawAddress& orchardAddr) {
                    ReceiverTypeSer(libzcash::ReceiverType::Orchard).Serialize(s);
                    s << orchardAddr;
                }
            });
        }

        template<typename Stream>
        void Unserialize(Stream& s) {
            // This cast is fine because ZIP 316 uses CompactSize serialization including the
            // size limit, which means it is at most a uint32_t.
            typecode = (libzcash::ReceiverType) ReadCompactSize(s);
            switch (typecode) {
                case libzcash::ReceiverType::P2PKH: {
                    CKeyID key;
                    s >> key;
                    recipient = key;
                    break;
                }
                case libzcash::ReceiverType::P2SH: {
                    CScriptID script;
                    s >> script;
                    recipient = script;
                    break;
                }
                case libzcash::ReceiverType::Sapling: {
                    libzcash::SaplingPaymentAddress saplingAddr;
                    s >> saplingAddr;
                    recipient = saplingAddr;
                    break;
                }
                case libzcash::ReceiverType::Orchard: {
                    auto orchardAddr = libzcash::OrchardRawAddress::Read(s);
                    recipient = orchardAddr;
                    break;
                }
            }
        }

        template <typename Stream>
        static libzcash::RecipientAddress Read(Stream& stream) {
            CSerializeRecipientAddress csr;
            stream >> csr;
            return csr.recipient;
        }
};

/**
 * The value of a "pqkey" (plain) or "cpqkey" (encrypted) record, keyed by the CPQKeyID
 * (quantum plan §4.6, quantum spec §2.4): the HD index (DerivePQSeed), the public key, the 48-byte
 * keygen seed (plain, or encrypted under the master key like a "ckey" secret, IV = the key id's
 * hash) and the creation time. The secret key is recomputed from the seed on load and checked
 * against the id and the stored public key.
 */
class CPQKeyRecord
{
public:
    static const int CURRENT_VERSION = 1;
    int nVersion = CURRENT_VERSION;
    uint32_t index = CPQKey::PQ_INDEX_NONE;
    std::vector<unsigned char> pk;
    CPQKey::Secret secret;
    int64_t nCreateTime = 0;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nVersion);
        READWRITE(index);
        READWRITE(pk);
        READWRITE(secret);
        READWRITE(nCreateTime);
    }
};

/** Access to the wallet database */
class CWalletDB : public CDB
{
public:
    CWalletDB(const std::string& strFilename, const char* pszMode = "r+", bool fFlushOnClose = true) : CDB(strFilename, pszMode, fFlushOnClose)
    {
    }

    bool WriteName(const std::string& strAddress, const std::string& strName);
    bool EraseName(const std::string& strAddress);

    bool WritePurpose(const std::string& strAddress, const std::string& purpose);
    bool ErasePurpose(const std::string& strAddress);

    bool WriteTx(const CWalletTx& wtx);
    bool EraseTx(uint256 hash);

    // Tombstone log of wtxids purged by DeleteWalletTransactions.
    bool WriteExTx(uint256 hash);
    bool EraseExTx(uint256 hash);

    // Atomic-swap records, keyed by swap-id ("<contractTxid>:<vout>").
    bool WriteAtomicSwap(const std::string& swapId, const CAtomicSwapInfo& swapInfo);
    bool ReadAtomicSwap(const std::string& swapId, CAtomicSwapInfo& swapInfo);
    bool EraseAtomicSwap(const std::string& swapId);

    // Vault set signatures this wallet made (sign-once guard, plan §15 SET_EQUIVOCATION): per
    // (setId, prevout), the role and sighash the wallet's members signed. Read on demand, never loaded.
    bool WriteVaultSetSig(const uint256& setId, const COutPoint& prevout, uint8_t role, const uint256& sighash);
    bool ReadVaultSetSig(const uint256& setId, const COutPoint& prevout, uint8_t& role, uint256& sighash);

    bool WriteKey(const CPubKey& vchPubKey, const CPrivKey& vchPrivKey, const CKeyMetadata &keyMeta);
    bool WriteCryptedKey(const CPubKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret, const CKeyMetadata &keyMeta);
    bool WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey);

    //! Post-quantum keys: "pqkey" (plain seed) and "cpqkey" (encrypted seed, which erases "pqkey").
    bool WritePQKey(const CPQKeyID& id, const CPQKeyRecord& rec);
    bool WriteCryptedPQKey(const CPQKeyID& id, const CPQKeyRecord& rec);
    //! 6.20.0 (review B I-2): "pqissued", the next PQ key index to issue per scheme.
    bool WritePQIssued(uint8_t scheme, uint32_t next);

    bool WriteCScript(const uint160& hash, const CScript& redeemScript);

    bool WriteWatchOnly(const CScript &script);
    bool EraseWatchOnly(const CScript &script);

    bool WriteBestBlock(const CBlockLocator& locator);
    bool ReadBestBlock(CBlockLocator& locator);

    bool WriteOrderPosNext(int64_t nOrderPosNext);

    bool WriteDefaultKey(const CPubKey& vchPubKey);

    bool WriteWitnessCacheSize(int64_t nWitnessCacheSize);

    bool ReadPool(int64_t nPool, CKeyPool& keypool);
    bool WritePool(int64_t nPool, const CKeyPool& keypool);
    bool ErasePool(int64_t nPool);

    bool WriteMinVersion(int nVersion);

    bool WriteRecipientMapping(const uint256& txid, const libzcash::RecipientAddress& address, const libzcash::UnifiedAddress& ua);

    /// Write destination data key,value tuple to database
    bool WriteDestData(const std::string &address, const std::string &key, const std::string &value);
    /// Erase destination data tuple from wallet database
    bool EraseDestData(const std::string &address, const std::string &key);

    DBErrors LoadWallet(CWallet* pwallet);
    DBErrors FindWalletTxToZap(CWallet* pwallet, std::vector<uint256>& vTxHash, std::vector<CWalletTx>& vWtx);
    DBErrors ZapWalletTx(CWallet* pwallet, std::vector<CWalletTx>& vWtx);
    static bool Recover(CDBEnv& dbenv, const std::string& filename, bool fOnlyKeys);
    static bool Recover(CDBEnv& dbenv, const std::string& filename);

    bool WriteNetworkInfo(const std::string& networkId);
    bool WriteMnemonicSeed(const MnemonicSeed& seed);
    bool WriteCryptedMnemonicSeed(const uint256& seedFp, const std::vector<unsigned char>& vchCryptedSecret);
    bool WriteMnemonicHDChain(const CHDChain& chain);
    bool WriteHasExternalImports(bool value);

    /// Write spending key to wallet database, where key is payment address and value is spending key.
    bool WriteZKey(const libzcash::SproutPaymentAddress& addr, const libzcash::SproutSpendingKey& key, const CKeyMetadata &keyMeta);
    bool WriteSaplingZKey(const libzcash::SaplingIncomingViewingKey &ivk,
                          const libzcash::SaplingExtendedSpendingKey &key,
                          const CKeyMetadata  &keyMeta);
    bool WriteSaplingPaymentAddress(const libzcash::SaplingPaymentAddress &addr,
                                    const libzcash::SaplingIncomingViewingKey &ivk);
    bool WriteCryptedZKey(const libzcash::SproutPaymentAddress & addr,
                          const libzcash::ReceivingKey & rk,
                          const std::vector<unsigned char>& vchCryptedSecret,
                          const CKeyMetadata &keyMeta);
    bool WriteCryptedSaplingZKey(const libzcash::SaplingExtendedFullViewingKey &extfvk,
                          const std::vector<unsigned char>& vchCryptedSecret,
                          const CKeyMetadata &keyMeta);

    bool WriteSproutViewingKey(const libzcash::SproutViewingKey &vk);
    bool EraseSproutViewingKey(const libzcash::SproutViewingKey &vk);
    bool WriteSaplingExtendedFullViewingKey(const libzcash::SaplingExtendedFullViewingKey &extfvk);
    bool EraseSaplingExtendedFullViewingKey(const libzcash::SaplingExtendedFullViewingKey &extfvk);

    /// Orchard support.
    bool WriteOrchardWitnesses(const OrchardWallet& wallet);

    /// Unified key support.

    bool WriteUnifiedAccountMetadata(const ZcashdUnifiedAccountMetadata& keymeta);
    bool WriteUnifiedFullViewingKey(const libzcash::UnifiedFullViewingKey& ufvk);
    bool WriteUnifiedAddressMetadata(const ZcashdUnifiedAddressMetadata& addrmeta);

    static void IncrementUpdateCounter();
    static unsigned int GetUpdateCounter();
private:
    CWalletDB(const CWalletDB&);
    void operator=(const CWalletDB&);

};

bool BackupWallet(const CWallet& wallet, const std::string& strDest);
void ThreadFlushWalletDB(const std::string& strFile);

#endif // BITCOIN_WALLET_WALLETDB_H
