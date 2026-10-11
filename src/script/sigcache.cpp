// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2018-2023 The Zcash developers
// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "sigcache.h"

#include "crypto/common.h"
#include "crypto/sha256.h"
#include "memusage.h"
#include "pubkey.h"
#include "random.h"
#include "uint256.h"
#include "util/system.h"

#include "cuckoocache.h"
#include <boost/thread.hpp>

#include <atomic>

namespace {
/**
 * Valid signature cache, to avoid doing expensive ECDSA signature checking
 * twice for every transaction (once when accepted into memory pool, and
 * again when accepted into the block chain)
 */
class CSignatureCache
{
private:
     //! Entries are SHA256(nonce || signature hash || public key || signature):
    uint256 nonce;
    //! Post-quantum (OP_CHECKPQSIG) entries share the set and its size bound but use a second,
    //! independent nonce, so a PQ preimage and an ECDSA preimage differ in their first 32 bytes
    //! and no PQ entry can equal an ECDSA entry (short of a SHA256 collision). They are
    //! SHA256(pqNonce || scheme || signature hash || len(public key) || public key ||
    //! len(signature) || signature), lengths as 4-byte little-endian: the whole input of
    //! pq::Verify, so an entry vouches for exactly one (scheme, key, signature, message).
    uint256 pqNonce;
    typedef CuckooCache::cache<uint256, SignatureCacheHasher> map_type;
    map_type setValid;
    boost::shared_mutex cs_sigcache;

public:
    CSignatureCache()
    {
        GetRandBytes(nonce.begin(), 32);
        GetRandBytes(pqNonce.begin(), 32);
    }

    void
    ComputeEntry(uint256& entry, const uint256 &hash, const std::vector<unsigned char>& vchSig, const CPubKey& pubkey)
    {
        CSHA256().Write(nonce.begin(), 32).Write(hash.begin(), 32).Write(&pubkey[0], pubkey.size()).Write(&vchSig[0], vchSig.size()).Finalize(entry.begin());
    }

    void
    ComputePQEntry(uint256& entry, uint8_t scheme, const uint256 &hash, const std::vector<unsigned char>& vchSig, const std::vector<unsigned char>& pk)
    {
        unsigned char pkLen[4], sigLen[4];
        WriteLE32(pkLen, (uint32_t)pk.size());
        WriteLE32(sigLen, (uint32_t)vchSig.size());
        CSHA256().Write(pqNonce.begin(), 32).Write(&scheme, 1).Write(hash.begin(), 32).Write(pkLen, 4).Write(pk.data(), pk.size()).Write(sigLen, 4).Write(vchSig.data(), vchSig.size()).Finalize(entry.begin());
    }

    bool
    Get(const uint256& entry, const bool erase)
    {
        boost::shared_lock<boost::shared_mutex> lock(cs_sigcache);
        return setValid.contains(entry, erase);
    }

    void Set(uint256& entry)
    {
        boost::unique_lock<boost::shared_mutex> lock(cs_sigcache);
        setValid.insert(entry);
    }
    uint32_t setup_bytes(size_t n)
    {
        return setValid.setup_bytes(n);
    }
};

/* In previous versions of this code, signatureCache was a local static variable
 * in CachingTransactionSignatureChecker::VerifySignature.  We initialize
 * signatureCache outside of VerifySignature to avoid the atomic operation per
 * call overhead associated with local static variables even though
 * signatureCache could be made local to VerifySignature.
*/
static CSignatureCache signatureCache;
static std::atomic<uint64_t> pqSigCacheHits{0};
}

// To be called once in AppInit2/TestingSetup to initialize the signatureCache
void InitSignatureCache(size_t nMaxCacheSize)
{
    if (nMaxCacheSize <= 0) return;
    size_t nElems = signatureCache.setup_bytes(nMaxCacheSize);
    LogPrintf("Using %zu MiB out of %zu requested for signature cache, able to store %zu elements\n",
            (nElems*sizeof(uint256)) >>20, nMaxCacheSize>>20, nElems);
}

bool CachingTransactionSignatureChecker::VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& pubkey, const uint256& sighash) const
{
    uint256 entry;
    signatureCache.ComputeEntry(entry, sighash, vchSig, pubkey);
    if (signatureCache.Get(entry, !store))
        return true;
    if (!TransactionSignatureChecker::VerifySignature(vchSig, pubkey, sighash))
        return false;
    if (store)
        signatureCache.Set(entry);
    return true;
}

bool CachingTransactionSignatureChecker::VerifyPQSignature(uint8_t scheme, const std::vector<unsigned char>& vchSig, const std::vector<unsigned char>& vchPubKey, const uint256& sighash) const
{
    // As VerifySignature: a hit is a verification that already succeeded on these exact bytes;
    // only a success is stored, and only when the caller allows it (store).
    uint256 entry;
    signatureCache.ComputePQEntry(entry, scheme, sighash, vchSig, vchPubKey);
    if (signatureCache.Get(entry, !store)) {
        pqSigCacheHits.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    if (!TransactionSignatureChecker::VerifyPQSignature(scheme, vchSig, vchPubKey, sighash))
        return false;
    if (store)
        signatureCache.Set(entry);
    return true;
}

uint64_t GetPQSigCacheHits()
{
    return pqSigCacheHits.load(std::memory_order_relaxed);
}
