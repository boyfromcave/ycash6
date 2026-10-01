// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef YCASH_YELLOWBACK_WALLET_H
#define YCASH_YELLOWBACK_WALLET_H

#include "amount.h"
#include "primitives/transaction.h"
#include "sync.h"
#include "yellowback/index.h"
#include "yellowback/view.h"

#include <array>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <thread>
#include <vector>

class CWallet;
class CWalletTx;
class CReserveKey;

/**
 * The Yellowback wallet layer (plan §4.5): ownership, three-stage coin
 * locking (B4, C3), balances and positions. Uses only the public CWallet
 * API; nothing is written to wallet.dat. Zero lines in src/wallet/.
 *
 * Lock order: cs_main -> cs_wallet -> cs_yellowback. The notifier-thread
 * hooks (PreLock, Reconcile) take cs_yellowback, release it, then take
 * cs_wallet; they never take cs_main.
 */
namespace yellowback {

struct YedCoin
{
    COutPoint outpoint;
    TokenRecord token;
};

/**
 * An outstanding carrier of this wallet (v3 plan W7, R6): the funding output
 * P2SH(CarrierScript(pk, SHA256(bundle))) of CARRIER_VALUE that a MINT / CLAIM /
 * CLAIM_NOTICE / EQUIVOCATION spends. Persisted in <datadir>/yellowback/carriers.dat
 * (never wallet.dat; the carrier is not IsMine, R6) so a carrier whose main
 * transaction never confirmed can be swept back after its window lapses. The key
 * `pk` is an ordinary keypool key of the wallet, so the sweep can sign after a
 * restart; the bundle is needed because the redeem script demands a push that
 * hashes to its commitment.
 */
struct CarrierRecord
{
    COutPoint outpoint;
    int32_t refHeight;                        //!< R fixed at the carrier step; the main transaction's refHeight
    std::vector<unsigned char> selector;      //!< empty (MINT) or the 36-byte vault outpoint (CLAIM / NOTICE); empty for EQUIVOCATION
    std::vector<unsigned char> bundle;        //!< the bundle committed by the redeem script (may be empty before arming)
    CPubKey pk;                               //!< the carrier key (held by the wallet)
    int32_t createdHeight;                    //!< chain height when the carrier was broadcast

    CarrierRecord() : refHeight(0), createdHeight(0) {}

    /** The window has lapsed: tip > R + REF_WINDOW (both transactions expired together). */
    bool Lapsed(int tipHeight) const { return (int64_t)tipHeight > (int64_t)refHeight + REF_WINDOW; }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(outpoint);
        READWRITE(refHeight);
        READWRITE(selector);
        READWRITE(bundle);
        READWRITE(pk);
        READWRITE(createdHeight);
    }
};

/** One line of the signing guard <datadir>/yellowback/attest-signed.dat (S16): what this node signed for (seq, citedHeight). */
struct SignedAttestation
{
    uint16_t seq;
    uint32_t citedHeight;
    uint32_t priceMicroUsd;
    std::array<unsigned char, 64> sig;

    SignedAttestation() : seq(0), citedHeight(0), priceMicroUsd(0) { sig.fill(0); }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(seq);
        READWRITE(citedHeight);
        READWRITE(priceMicroUsd);
        READWRITE(FLATDATA(sig));
    }
};

class YellowbackWallet
{
public:
    YellowbackWallet(CWallet* wallet, YellowbackIndex* index);

    /** Register the index hooks (stage ii and iii of coin locking). */
    void Attach();

    // ---- ownership
    bool IsMineScript(const CScript& scriptPubKey) const;
    bool IsMineVault(const VaultRecord& v) const;

    // ---- coins and balances (cs_wallet and cs_yellowback held by the caller)
    /** Confirmed YED outputs that are mine and not spent by an unconfirmed wallet transaction. */
    std::vector<YedCoin> SpendableCoins() const;
    /** Every YED output that is mine (for listing). */
    std::vector<YedCoin> AllCoins() const;
    int64_t ConfirmedCents() const;

    // ---- committing
    /**
     * CWallet::CommitTransaction, then remove the blank wallet entries it leaves behind. The
     * inherited commit "notifies that old coins are spent" with `mapWallet[txin.prevout.hash]`
     * (src/wallet/wallet.cpp, frozen), which is safe upstream because a wallet only ever spends
     * its own coins, and wrong for a claim (the vault output belongs to the vault owner) or a
     * bond withdrawal after a restore: the operator[] inserts a default CWalletTx -- no inputs,
     * no outputs, depth -1 -- under a transaction id the wallet never held. The next
     * CWalletTx::IsTrusted over the unconfirmed spend then reads `parent->vout[n]` of that entry
     * and the node dies (regtest plan F-7). Inputs absent from mapWallet before the commit are
     * erased again after it; nothing else about them exists (never AddToWallet'ed, never on disk).
     */
    bool Commit(CWalletTx& wtx, std::optional<std::reference_wrapper<CReserveKey>> reservekey);

    // ---- locking
    /** Stage (i): lock the given outpoints before CommitTransaction (cs_wallet). */
    void LockOwn(const std::vector<COutPoint>& outs);
    /** Stage (ii): pre-lock every output a well-formed payload assigns to a script that is mine. */
    void PreLock(const CTransaction& tx);
    /** Stage (iii): reconcile locks against the index after every applied block and at startup. */
    void Reconcile();
    /** Outpoints this layer has locked. */
    std::set<COutPoint> Locked() const;
    /** How many (H10: yed_getinfo.lockedOutputs). */
    size_t LockedCount() const;
    /** True iff this layer holds `out` locked — what lockunspent refuses to undo (H5). */
    bool IsYellowbackLocked(const COutPoint& out) const;
    /**
     * H5: give one outpoint back to plain YEC coin selection (yed_unlockcoin). Returns whether
     * this layer held it. The YED it carries burns if it is then spent outside the overlay, and
     * the next Reconcile() locks it again.
     */
    bool ReleaseLock(const COutPoint& out);
    /** H5: re-apply every lock this layer holds, after `lockunspent true` unlocked everything. */
    void ReapplyLocks();

    CWallet* Wallet() const { return wallet; }
    YellowbackIndex* Index() const { return index; }

    // ---- v3: carriers (W7). All take cs_wallet themselves; the file is rewritten and fsynced on every change.
    /** Persist a carrier the wallet just broadcast. */
    void RecordCarrier(const CarrierRecord& c);
    /** Forget a carrier whose spending transaction was committed (or swept). */
    void SpendCarrier(const COutPoint& out);
    std::optional<CarrierRecord> GetCarrier(const COutPoint& out) const;
    /** Every recorded carrier, oldest first. */
    std::vector<CarrierRecord> OutstandingCarriers() const;
    /** The outstanding carriers whose window has lapsed at `tipHeight` (the sweep's input set). */
    std::vector<CarrierRecord> LapsedCarriers(int tipHeight) const;
    /** <datadir>/yellowback/carriers.dat */
    static fs::path CarriersFile();

    // ---- v3: bonds (R6). Attestors records whose bondPubKey this wallet holds; cs_yellowback held by the caller.
    std::vector<std::pair<uint16_t, AttestorRecord>> Bonds() const;
    /** The attestor hot keys this wallet holds: every Attestors record whose attestorPubKey it has (cs_yellowback held by the caller). */
    std::vector<std::pair<uint16_t, AttestorRecord>> HotKeys() const;

    // ---- v3: the signing guard (S16). In memory and in <datadir>/yellowback/attest-signed.dat (append, fsync before returning).
    std::optional<SignedAttestation> LookupSigned(uint16_t seq, uint32_t citedHeight) const;
    /** Append and fsync; false when the write failed (the caller then returns nothing). */
    bool RecordSigned(const SignedAttestation& rec);
    static fs::path SignedFile();

    // ---- v3: the two-step flow under wait=false (§4.6). A completion runs on the wallet's own
    // completion thread (never the notifier thread, which may not take cs_main) after every
    // applied block and every second; it returns true once it is finished (or has given up).
    void AddPendingCompletion(const COutPoint& carrier, std::function<bool()> complete);
    size_t PendingCompletions() const;
    /** The startup sweep and the completion thread's idle work: set by the RPC layer; runs under no lock of ours. */
    std::function<void()> onIdle;
    /** Stop the completion thread (idempotent; the destructor does the same). */
    void StopThread();
    ~YellowbackWallet();

private:
    void CompletionLoop();
    void StartupSweep();
    void LoadCarriers();
    bool SaveCarriers() const;
    void LoadSigned();

    CWallet* wallet;
    YellowbackIndex* index;
    std::set<COutPoint> ourLocks; //!< cs_wallet
    std::vector<CarrierRecord> carriers;                                           //!< cs_wallet
    std::map<std::pair<uint16_t, uint32_t>, SignedAttestation> signedGuard;         //!< cs_wallet
    std::map<COutPoint, std::function<bool()>> pending;                            //!< pendingMutex
    mutable std::mutex pendingMutex;
    std::condition_variable pendingCv;
    std::atomic<bool> stopThread;
    bool wake;
    bool startupSweepDone;
    std::thread thread;
};

/**
 * H7: does this raw transaction destroy YED that belongs to this wallet? True when it spends a
 * `Tokens` outpoint the wallet owns and carries no payload assigning cents to any output — the
 * state machine then burns those cents. `reason` is filled with a human sentence naming the
 * outpoints and the cents at stake. False without -yellowback, without a wallet, while the index
 * is unhealthy, and for any transaction that spends none of this wallet's YED. Takes
 * cs_yellowback and cs_wallet itself; the caller holds cs_main (sendrawtransaction does).
 */
bool YedBurnedByRawTransaction(const CTransaction& tx, std::string& reason);

/** The wallet layer, or nullptr without a wallet or without -yellowback. */
extern YellowbackWallet* g_yellowbackWallet;

} // namespace yellowback

#endif // YCASH_YELLOWBACK_WALLET_H
