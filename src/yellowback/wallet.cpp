// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "yellowback/wallet.h"

#include "init.h"
#include "script/ismine.h"
#include "streams.h"
#include "util/system.h"
#include "wallet/wallet.h"
#include "main.h"
#include "yellowback/payload.h"
#include "yellowback/state.h"
#include "yellowback/txbuilder.h"

#include <algorithm>
#include <chrono>
#include <set>
#include <cstdio>
#include <cstring>

namespace yellowback {

YellowbackWallet* g_yellowbackWallet = nullptr;

YellowbackWallet::YellowbackWallet(CWallet* wallet, YellowbackIndex* index) : wallet(wallet), index(index), stopThread(false), wake(false), startupSweepDone(false) {}

YellowbackWallet::~YellowbackWallet()
{
    StopThread();
}

void YellowbackWallet::Attach()
{
    index->onSyncTransaction = [this](const CTransaction& tx) { PreLock(tx); };
    index->onReconcile = [this]() {
        Reconcile();
        // Wake the completion thread (W7 wait=false, the startup sweep): the notifier thread itself
        // may not take cs_main (validationinterface.cpp), so the work runs elsewhere.
        {
            std::lock_guard<std::mutex> g(pendingMutex);
            wake = true;
        }
        pendingCv.notify_all();
    };
    LoadCarriers();
    LoadSigned();
    // The startup sweep (contract: yed_sweepcarriers "also run at startup"): once, after IBD, for lapsed carriers only.
    onIdle = [this]() { StartupSweep(); };
    if (!thread.joinable()) thread = std::thread([this]() { CompletionLoop(); });
}

void YellowbackWallet::StartupSweep()
{
    if (startupSweepDone) return;
    if (!index->IsHealthy() || IsInitialBlockDownload(::Params().GetConsensus())) return;
    int tip;
    {
        LOCK(cs_main);
        tip = chainActive.Height();
    }
    std::vector<CarrierRecord> lapsed = LapsedCarriers(tip);
    startupSweepDone = true;   // one attempt per start; yed_sweepcarriers is the manual path
    if (lapsed.empty()) return;
    LOCK2(cs_main, wallet->cs_wallet);
    if (wallet->IsLocked()) {
        LogPrintf("yellowback: %u lapsed carrier(s) outstanding; the wallet is locked, run yed_sweepcarriers after walletpassphrase\n", lapsed.size());
        return;
    }
    LOCK(index->cs_yellowback);
    try {
        BuiltTx b = BuildSweepCarriers(*this, lapsed);
        CWalletTx wtx(wallet, CTransaction(b.tx));
        if (Commit(wtx, std::nullopt)) {
            for (const CarrierRecord& c : b.sweptRecords) SpendCarrier(c.outpoint);
            LogPrintf("yellowback: startup sweep reclaimed %u lapsed carrier(s) in %s\n", b.sweptRecords.size(), wtx.GetHash().ToString());
        }
        for (const CarrierRecord& c : b.staleRecords) SpendCarrier(c.outpoint);
    } catch (const std::exception& e) {
        LogPrintf("yellowback: startup sweep skipped: %s\n", e.what());
    }
}

bool YellowbackWallet::Commit(CWalletTx& wtx, std::optional<std::reference_wrapper<CReserveKey>> reservekey)
{
    std::set<uint256> foreign;
    {
        LOCK(wallet->cs_wallet);
        for (const CTxIn& in : wtx.vin) {
            if (!wallet->mapWallet.count(in.prevout.hash)) foreign.insert(in.prevout.hash);
        }
    }
    CValidationState state;   // 6.20.0: CommitTransaction reports the mempool rejection here (and logs it)
    const bool ok = wallet->CommitTransaction(wtx, reservekey, state);
    if (!foreign.empty()) {
        LOCK(wallet->cs_wallet);
        for (const uint256& hash : foreign) {
            std::map<uint256, CWalletTx>::iterator it = wallet->mapWallet.find(hash);
            // Only the blank the inherited commit made: a real transaction has inputs or outputs.
            if (it != wallet->mapWallet.end() && it->second.vin.empty() && it->second.vout.empty()) wallet->mapWallet.erase(it);
        }
    }
    return ok;
}

// ---------------------------------------------------------------- v3: the files under <datadir>/yellowback (W7, S16)

namespace {

/** Write `data` to `path` atomically: a temporary beside it, fsync, rename. */
bool WriteFileSynced(const fs::path& path, const std::vector<unsigned char>& data)
{
    TryCreateDirectory(path.parent_path());
    const fs::path tmp = path.string() + ".tmp";
    FILE* f = fopen(tmp.string().c_str(), "wb");
    if (!f) return false;
    bool ok = data.empty() || fwrite(data.data(), 1, data.size(), f) == data.size();
    FileCommit(f);   // fflush + fsync
    fclose(f);
    if (!ok) return false;
    return RenameOver(tmp, path);
}

bool ReadWholeFile(const fs::path& path, std::vector<unsigned char>& out)
{
    out.clear();
    if (!fs::exists(path)) return false;
    FILE* f = fopen(path.string().c_str(), "rb");
    if (!f) return false;
    unsigned char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) out.insert(out.end(), buf, buf + n);
    fclose(f);
    return true;
}

const unsigned char CARRIERS_MAGIC[4] = { 'Y', 'B', 'C', 1 };
const unsigned char SIGNED_MAGIC[4] = { 'Y', 'B', 'S', 1 };

} // namespace

fs::path YellowbackWallet::CarriersFile() { return GetDataDir() / "yellowback" / "carriers.dat"; }
fs::path YellowbackWallet::SignedFile() { return GetDataDir() / "yellowback" / "attest-signed.dat"; }

void YellowbackWallet::LoadCarriers()
{
    std::vector<unsigned char> raw;
    if (!ReadWholeFile(CarriersFile(), raw)) return;
    try {
        CDataStream ss(raw, SER_DISK, CLIENT_VERSION);
        unsigned char magic[4];
        ss.read((char*)magic, 4);
        if (memcmp(magic, CARRIERS_MAGIC, 4) != 0) throw std::runtime_error("bad magic");
        std::vector<CarrierRecord> loaded;
        ss >> loaded;
        LOCK(wallet->cs_wallet);
        carriers = loaded;
        LogPrintf("yellowback: %u outstanding carrier(s) loaded from %s\n", carriers.size(), CarriersFile().string());
    } catch (const std::exception& e) {
        LogPrintf("yellowback: cannot read %s (%s); outstanding carriers are forgotten (W7)\n", CarriersFile().string(), e.what());
    }
}

bool YellowbackWallet::SaveCarriers() const
{
    AssertLockHeld(wallet->cs_wallet);
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss.write((const char*)CARRIERS_MAGIC, 4);
    ss << carriers;
    return WriteFileSynced(CarriersFile(), std::vector<unsigned char>(ss.begin(), ss.end()));
}

void YellowbackWallet::RecordCarrier(const CarrierRecord& c)
{
    LOCK(wallet->cs_wallet);
    for (CarrierRecord& e : carriers) {
        if (e.outpoint == c.outpoint) { e = c; SaveCarriers(); return; }
    }
    carriers.push_back(c);
    if (!SaveCarriers()) LogPrintf("yellowback: WARNING: cannot write %s; carrier %s would be lost on restart\n", CarriersFile().string(), c.outpoint.ToString());
}

void YellowbackWallet::SpendCarrier(const COutPoint& out)
{
    LOCK(wallet->cs_wallet);
    const size_t before = carriers.size();
    carriers.erase(std::remove_if(carriers.begin(), carriers.end(), [&](const CarrierRecord& c) { return c.outpoint == out; }), carriers.end());
    if (carriers.size() != before) SaveCarriers();
}

std::optional<CarrierRecord> YellowbackWallet::GetCarrier(const COutPoint& out) const
{
    LOCK(wallet->cs_wallet);
    for (const CarrierRecord& c : carriers) if (c.outpoint == out) return c;
    return std::nullopt;
}

std::vector<CarrierRecord> YellowbackWallet::OutstandingCarriers() const
{
    LOCK(wallet->cs_wallet);
    return carriers;
}

std::vector<CarrierRecord> YellowbackWallet::LapsedCarriers(int tipHeight) const
{
    std::vector<CarrierRecord> out;
    for (const CarrierRecord& c : OutstandingCarriers()) if (c.Lapsed(tipHeight)) out.push_back(c);
    return out;
}

std::vector<std::pair<uint16_t, AttestorRecord>> YellowbackWallet::Bonds() const
{
    // Lock order (N25): the caller holds cs_wallet before cs_yellowback; neither is taken here.
    AssertLockHeld(wallet->cs_wallet);
    AssertLockHeld(index->cs_yellowback);
    std::vector<std::pair<uint16_t, AttestorRecord>> out;
    for (const auto& kv : State(index->View()).Attestors()) {
        const CPubKey k = kv.second.BondKey();
        if (k.IsValid() && wallet->HaveKey(k.GetID())) out.push_back(kv);
    }
    return out;
}

std::vector<std::pair<uint16_t, AttestorRecord>> YellowbackWallet::HotKeys() const
{
    // Lock order (N25): the caller holds cs_wallet before cs_yellowback; neither is taken here.
    AssertLockHeld(wallet->cs_wallet);
    AssertLockHeld(index->cs_yellowback);
    std::vector<std::pair<uint16_t, AttestorRecord>> out;
    for (const auto& kv : State(index->View()).Attestors()) {
        const CPubKey k = kv.second.AttestorKey();
        if (k.IsValid() && wallet->HaveKey(k.GetID())) out.push_back(kv);
    }
    return out;
}

void YellowbackWallet::LoadSigned()
{
    std::vector<unsigned char> raw;
    if (!ReadWholeFile(SignedFile(), raw)) return;
    try {
        CDataStream ss(raw, SER_DISK, CLIENT_VERSION);
        unsigned char magic[4];
        ss.read((char*)magic, 4);
        if (memcmp(magic, SIGNED_MAGIC, 4) != 0) throw std::runtime_error("bad magic");
        LOCK(wallet->cs_wallet);
        while (!ss.empty()) {
            SignedAttestation r;
            ss >> r;
            signedGuard[std::make_pair(r.seq, r.citedHeight)] = r;
        }
        LogPrintf("yellowback: %u signed attestation(s) loaded from %s (S16)\n", signedGuard.size(), SignedFile().string());
    } catch (const std::exception& e) {
        // A torn tail keeps what was read before it: the guard never loses an earlier line.
        LogPrintf("yellowback: %s is damaged (%s); the signing guard keeps %u line(s)\n", SignedFile().string(), e.what(), signedGuard.size());
    }
}

std::optional<SignedAttestation> YellowbackWallet::LookupSigned(uint16_t seq, uint32_t citedHeight) const
{
    LOCK(wallet->cs_wallet);
    auto it = signedGuard.find(std::make_pair(seq, citedHeight));
    if (it == signedGuard.end()) return std::nullopt;
    return it->second;
}

bool YellowbackWallet::RecordSigned(const SignedAttestation& rec)
{
    LOCK(wallet->cs_wallet);
    const fs::path path = SignedFile();
    TryCreateDirectory(path.parent_path());
    const bool fresh = !fs::exists(path);
    FILE* f = fopen(path.string().c_str(), "ab");
    if (!f) return false;
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    if (fresh) ss.write((const char*)SIGNED_MAGIC, 4);
    ss << rec;
    bool ok = fwrite(&ss[0], 1, ss.size(), f) == ss.size();
    FileCommit(f);   // fsync before the RPC returns (S16)
    fclose(f);
    if (!ok) return false;
    signedGuard[std::make_pair(rec.seq, rec.citedHeight)] = rec;
    return true;
}

// ---------------------------------------------------------------- v3: the completion thread (W7 wait=false, the startup sweep)

void YellowbackWallet::AddPendingCompletion(const COutPoint& carrier, std::function<bool()> complete)
{
    std::lock_guard<std::mutex> g(pendingMutex);
    pending[carrier] = complete;
}

size_t YellowbackWallet::PendingCompletions() const
{
    std::lock_guard<std::mutex> g(pendingMutex);
    return pending.size();
}

void YellowbackWallet::StopThread()
{
    stopThread = true;
    pendingCv.notify_all();
    if (thread.joinable() && thread.get_id() != std::this_thread::get_id()) thread.join();
}

void YellowbackWallet::CompletionLoop()
{
    RenameThread("yellowback-wallet");
    while (!stopThread) {
        {
            std::unique_lock<std::mutex> lk(pendingMutex);
            pendingCv.wait_for(lk, std::chrono::milliseconds(1000), [this]() { return wake || stopThread.load(); });
            wake = false;
        }
        if (stopThread || ShutdownRequested() || index->IsStopped()) break;
        // Snapshot the pending set, run each completion outside pendingMutex (a completion takes
        // cs_main, cs_wallet and cs_yellowback itself), then drop the finished ones.
        std::vector<std::pair<COutPoint, std::function<bool()>>> work;
        {
            std::lock_guard<std::mutex> g(pendingMutex);
            for (const auto& kv : pending) work.push_back(kv);
        }
        for (const auto& kv : work) {
            bool done = false;
            try {
                done = kv.second();
            } catch (const std::exception& e) {
                LogPrintf("yellowback: pending completion for carrier %s failed: %s\n", kv.first.ToString(), e.what());
                done = true;
            } catch (...) {
                LogPrintf("yellowback: pending completion for carrier %s failed\n", kv.first.ToString());
                done = true;
            }
            if (done) {
                std::lock_guard<std::mutex> g(pendingMutex);
                pending.erase(kv.first);
            }
            if (stopThread) return;
        }
        if (onIdle) {
            try {
                onIdle();
            } catch (const std::exception& e) {
                LogPrintf("yellowback: wallet idle work failed: %s\n", e.what());
            } catch (...) {
                LogPrintf("yellowback: wallet idle work failed\n");
            }
        }
    }
}

bool YellowbackWallet::IsMineScript(const CScript& scriptPubKey) const
{
    return (::IsMine(*wallet, scriptPubKey) & ISMINE_SPENDABLE) != 0;
}

bool YellowbackWallet::IsMineVault(const VaultRecord& v) const
{
    const CPubKey owner = v.OwnerKey();
    return owner.IsValid() && wallet->HaveKey(owner.GetID());
}

std::vector<YedCoin> YellowbackWallet::AllCoins() const
{
    AssertLockHeld(index->cs_yellowback);
    std::vector<YedCoin> out;
    index->View().Iterate("K", [&](const std::string& k, const std::string& raw) {
        TokenRecord t;
        if (!DeserializeRecord(raw, t)) return true;
        if (!IsMineScript(t.scriptPubKey)) return true;
        YedCoin c;
        c.outpoint = COutPoint(uint256(std::vector<unsigned char>(k.begin() + 1, k.begin() + 33)),
                               ((uint32_t)(unsigned char)k[33] << 24) | ((uint32_t)(unsigned char)k[34] << 16) |
                               ((uint32_t)(unsigned char)k[35] << 8) | (uint32_t)(unsigned char)k[36]);
        c.token = t;
        out.push_back(c);
        return true;
    });
    return out;
}

std::vector<YedCoin> YellowbackWallet::SpendableCoins() const
{
    AssertLockHeld(wallet->cs_wallet);
    std::vector<YedCoin> out;
    for (const YedCoin& c : AllCoins()) {
        if (wallet->IsSpent(c.outpoint.hash, c.outpoint.n, std::nullopt)) continue; // spent by one of our unconfirmed transactions (D3)
        out.push_back(c);
    }
    return out;
}

int64_t YellowbackWallet::ConfirmedCents() const
{
    int64_t sum = 0;
    for (const YedCoin& c : AllCoins()) sum += c.token.cents;
    return sum;
}

void YellowbackWallet::LockOwn(const std::vector<COutPoint>& outs)
{
    LOCK(wallet->cs_wallet);
    for (COutPoint o : outs) {
        wallet->LockCoin(o);
        ourLocks.insert(o);
    }
}

void YellowbackWallet::PreLock(const CTransaction& tx)
{
    std::optional<FoundPayload> fp = FindPayload(tx);
    if (!fp.has_value()) return;
    std::vector<COutPoint> mine;
    const uint256 txid = tx.GetHash();
    if (fp->payload.type == PayloadType::MINT) {
        if (tx.vout.size() > 1 && IsMineScript(tx.vout[1].scriptPubKey)) mine.push_back(COutPoint(txid, 1));
    } else if (fp->payload.type == PayloadType::TRANSFER || fp->payload.type == PayloadType::REDEEM) {
        for (const Assignment& a : fp->payload.assignments) {
            if (IsMineScript(tx.vout[a.vout].scriptPubKey)) mine.push_back(COutPoint(txid, a.vout));
        }
    }
    if (!mine.empty()) {
        LogPrint("yellowback", "pre-locking %u output(s) of %s\n", mine.size(), txid.ToString());
        LockOwn(mine);
    }
}

void YellowbackWallet::Reconcile()
{
    // Collect under cs_yellowback, then act under cs_wallet (B15). Lock order (N25): cs_wallet is
    // never taken under cs_yellowback, so the copy of ourLocks comes first.
    std::set<COutPoint> tokensMine;
    std::set<COutPoint> release;
    int tipHeight = -1;
    std::set<COutPoint> ours;
    {
        LOCK(wallet->cs_wallet);
        ours = ourLocks;
    }
    {
        LOCK(index->cs_yellowback);
        if (!index->IsHealthy()) return;
        State st(index->View());
        std::optional<TipRecord> tip = st.GetTip();
        if (tip.has_value()) tipHeight = tip->height;
        for (const YedCoin& c : AllCoins()) tokensMine.insert(c.outpoint);
        for (const COutPoint& o : ours) {
            if (tokensMine.count(o)) continue;
            // Release only when the outpoint's transaction is confirmed in the index and assigned it no cents
            // (a VOID mint's token output, a spent token, an output that turned out non-Yellowback); never on
            // disconnect (C3). Unconfirmed or expired transactions keep their (harmless) lock.
            if (st.GetTxLog(o.hash).has_value()) release.insert(o);
        }
    }
    {
        LOCK(wallet->cs_wallet);
        for (COutPoint o : tokensMine) {
            if (!wallet->IsLockedCoin(o.hash, o.n)) wallet->LockCoin(o);
            ourLocks.insert(o);
        }
        for (COutPoint o : release) {
            wallet->UnlockCoin(o);
            ourLocks.erase(o);
        }
    }
}

size_t YellowbackWallet::LockedCount() const
{
    LOCK(wallet->cs_wallet);
    return ourLocks.size();
}

bool YellowbackWallet::IsYellowbackLocked(const COutPoint& out) const
{
    LOCK(wallet->cs_wallet);
    return ourLocks.count(out) != 0;
}

bool YellowbackWallet::ReleaseLock(const COutPoint& out)
{
    LOCK(wallet->cs_wallet);
    const bool was = ourLocks.erase(out) != 0;
    COutPoint o = out;
    wallet->UnlockCoin(o);
    return was;
}

void YellowbackWallet::ReapplyLocks()
{
    LOCK(wallet->cs_wallet);
    for (COutPoint o : ourLocks) {
        if (!wallet->IsLockedCoin(o.hash, o.n)) wallet->LockCoin(o);
    }
}

std::set<COutPoint> YellowbackWallet::Locked() const
{
    LOCK(wallet->cs_wallet);
    return ourLocks;
}

bool YedBurnedByRawTransaction(const CTransaction& tx, std::string& reason)
{
    if (!g_yellowbackWallet) return false;
    YellowbackWallet& yw = *g_yellowbackWallet;
    YellowbackIndex* index = yw.Index();
    if (!index) return false;

    // A payload that assigns cents to an output reassigns the YED; a REDEEM's burn is its own
    // rule (RED-2) and its change assignment is an assignment like any other. No payload at all,
    // or a payload with no assignments, means the YED simply disappears.
    // A REDEEM payload (a vault spend: a redemption, a claim) is overlay business and is judged
    // by MP-1, never here — its burn is the rule, not an accident. A TRANSFER payload reassigns
    // the YED unless it assigns nothing at all. Everything else (no payload, an unreadable one, a
    // MINT payload) leaves the spent cents with nowhere to go: the state machine burns them.
    std::optional<FoundPayload> fp = FindPayload(tx);
    if (fp.has_value() && fp->payload.type == PayloadType::REDEEM) return false;
    if (fp.has_value() && fp->payload.type == PayloadType::TRANSFER && !fp->payload.assignments.empty()) return false;

    int64_t cents = 0;
    std::string outpoints;
    {
        LOCK(yw.Wallet()->cs_wallet);           // lock order (N25): cs_wallet before cs_yellowback
        LOCK(index->cs_yellowback);
        if (!index->IsHealthy()) return false;
        State st(index->View());
        for (const CTxIn& in : tx.vin) {
            std::optional<TokenRecord> t = st.GetToken(in.prevout);
            if (!t.has_value()) continue;
            if (!yw.IsMineScript(t->scriptPubKey)) continue;
            cents += t->cents;
            if (!outpoints.empty()) outpoints += ", ";
            outpoints += in.prevout.ToString();
        }
    }
    if (cents <= 0) return false;
    reason = strprintf("this transaction spends %d cents of this wallet's YED (%s) and its payload reassigns none of it,"
                       " so that YED would be destroyed.", cents, outpoints);
    return true;
}

} // namespace yellowback
