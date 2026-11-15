// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_VALUEPOOLS_H
#define YCASH_VALUEPOOLS_H

#include "amount.h"
#include "fs.h"
#include "serialize.h"
#include "uint256.h"

#include <functional>
#include <ios>
#include <optional>
#include <string>

#include <univalue.h>

class CBlock;
class CBlockIndex;
class CBlockUndo;
class CChainParams;
class CScript;
class CTxOut;

/**
 * The transparent value pools by address type (beta3 item 2, workspace docs/plans/beta3/value-pools.md).
 *
 * A node-side index, never a validity rule: one record per block hash holds the chain totals after that
 * block, split by the class of each output script (ClassifyTransparentScript). It is written by one call
 * in ConnectBlock, after every check has passed and the undo data is written (BlockConnected), and filled
 * once at startup from the block and undo files a node already has (Fill). BlockConnected returns nothing
 * and takes no validation state: a failure is logged and the index stops covering the blocks after it
 * (their entries say "monitored": false). The store is a LevelDB at <datadir>/blocks/valuepools/, wiped by
 * -reindex; chain.h, txdb.cpp and the block-index disk format are unchanged.
 */
namespace valuepools {

/** The class of a transparent output script; the first match in this order wins (note §1.2). */
enum class PoolClass : uint8_t {
    TRANSPARENT_PQ,  //!< TX_PQPKH: exactly 0x20 <keyHash:32> OP_1|OP_2 OP_CHECKPQSIG
    PQ_CHANNEL,      //!< TX_PQCHANNEL (MatchPQChannel)
    VAULT,           //!< TX_VAULT (vault::ParseVault)
    VAULT_INTENT,    //!< TX_VAULT_INTENT (vault::ParseIntent)
    TRANSPARENT_ECC, //!< everything else: P2PKH, P2PK, P2SH, multisig, OP_RETURN, nonstandard
};

struct ScriptClass {
    PoolClass cls = PoolClass::TRANSPARENT_ECC;
    uint8_t pqScheme = 0; //!< TRANSPARENT_PQ: the scheme byte (1 or 2); 0 otherwise
    bool yed = false;     //!< VAULT or VAULT_INTENT whose template tag is the YED module's
};

/** The class of `script`. Pure, byte-level: the same answer on every node, whatever its options. */
ScriptClass ClassifyTransparentScript(const CScript& script);

/** The chain totals after one block, in zatoshis. transparent_ecc is derived (transparent minus the rest). */
struct Record {
    CAmount transparent = 0;
    CAmount pq1 = 0;       //!< transparent_pq, scheme 1 (SLH-DSA-SHA2-128s)
    CAmount pq2 = 0;       //!< transparent_pq, scheme 2 (FN-DSA-512)
    CAmount channel = 0;   //!< pq_channel
    CAmount vault = 0;     //!< vault
    CAmount intent = 0;    //!< vault_intent
    CAmount vaultYed = 0;  //!< the YED module's part of vault
    CAmount intentYed = 0; //!< the YED module's part of vault_intent

    CAmount TransparentPQ() const { return pq1 + pq2; }
    CAmount TransparentECC() const { return transparent - pq1 - pq2 - channel - vault - intent; }
    /** Every stored amount and the derived ECC amount is non-negative and within MAX_MONEY. */
    bool IsSane() const;
    bool operator==(const Record& o) const;
    bool operator!=(const Record& o) const { return !(*this == o); }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        uint64_t version = 1;
        READWRITE(VARINT(version));
        if (ser_action.ForRead() && version != 1) throw std::ios_base::failure("valuepools: unknown record version");
        uint64_t v[8] = {(uint64_t)transparent, (uint64_t)pq1, (uint64_t)pq2, (uint64_t)channel,
                         (uint64_t)vault, (uint64_t)intent, (uint64_t)vaultYed, (uint64_t)intentYed};
        for (int i = 0; i < 8; i++) READWRITE(VARINT(v[i]));
        if (ser_action.ForRead()) {
            transparent = (CAmount)v[0]; pq1 = (CAmount)v[1]; pq2 = (CAmount)v[2]; channel = (CAmount)v[3];
            vault = (CAmount)v[4]; intent = (CAmount)v[5]; vaultYed = (CAmount)v[6]; intentYed = (CAmount)v[7];
        }
    }
};

/** A compiled seed: the chain totals at a block of the network's history (note §4). */
struct Seed {
    int height = 0;
    uint256 hash;
    Record record;
};

/**
 * The network's compiled seed, or nullopt. ycash-dd has none: every network fills from genesis. The 6.20.0 node line
 * seeds mainnet and the shadow testnets at the chain-supply checkpoint (height 2,800,000); regtest has none.
 */
std::optional<Seed> CompiledSeed(const CChainParams& chainparams);

/** Adds (sign = +1) or removes (sign = -1) one output to its class. */
void AddOutput(Record& r, const CTxOut& out, int sign);

/**
 * The record after `block`, from its parent's record, the block's outputs and the spent outputs in its undo
 * data (`blockundo` is unused for a block without inputs, e.g. the genesis block). False, with `err`, when the
 * undo data does not match the block or a total leaves its range.
 */
bool ApplyBlock(const Record& parent, const CBlock& block, const CBlockUndo& blockundo, Record& out, std::string& err);

/** Opens the store at <datadir>/blocks/valuepools/ (wiped when `fWipe`). A failure is logged; the index is then off. */
void Open(const fs::path& path, bool fWipe);
/** Closes the store (shutdown). */
void Close();
/** True when the store is open. */
bool IsOpen();

/**
 * THE HOOK (main.cpp ConnectBlock, after `if (fJustCheck) return true;` and after the undo data is written):
 * writes the record of `pindex`. Never throws, never asserts, never touches validation state.
 */
void BlockConnected(const CBlock& block, const CBlockUndo& blockundo, const CBlockIndex* pindex);

/**
 * The startup fill (init.cpp, after the block index and the vault database are loaded, before the node connects a
 * block; the caller holds cs_main): walks the active chain from the last block the index covers (or the seed, or
 * genesis) to the tip, reading each block and its undo data and storing what BlockConnected would have stored.
 * Returns false, with `err`, only when the index contradicts a compiled seed (the node then refuses to start: delete
 * blocks/valuepools to rebuild the index from the seed); every other failure (a pruned block, a read or write error)
 * is logged and leaves the remaining blocks unmonitored. Progress goes to the log and to the RPC warm-up status.
 */
bool Fill(const CChainParams& chainparams, const std::function<bool()>& interrupted, std::string& err);

/** The record of a block, or nullopt when the index does not cover it. The genesis block's is computed. */
std::optional<Record> GetRecord(const CBlockIndex* pindex);

/** The `transparentPools` object of getblockchaininfo (withDelta = false) and getblock (withDelta = true). */
UniValue TransparentPoolsToJSON(const CBlockIndex* pindex, bool withDelta);

/** The help text of `transparentPools`, indented for getblock / getblockchaininfo. */
std::string HelpText(bool withDelta);

/** Test hooks, for the gtests only (regtest has no checkpoint, and a disk that fails cannot be staged). */
namespace test {
/** Replaces CompiledSeed for the hook and the fill (nullopt: no seed). */
void SetSeed(const std::optional<Seed>& seed);
/** Restores CompiledSeed, the disk reads and writes that succeed. */
void Reset();
/** Replaces the fill's reads of a block and its undo data (the nStatus checks stay). */
void SetBlockReader(std::function<bool(const CBlockIndex*, CBlock&, CBlockUndo&)> reader);
/** Every write of the store throws dbwrapper_error, as a full or failing disk does. */
void SetFailWrites(bool fail);
} // namespace test

} // namespace valuepools

#endif // YCASH_VALUEPOOLS_H
