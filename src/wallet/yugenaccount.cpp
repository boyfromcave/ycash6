// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "wallet/yugenaccount.h"
#include "yugen/spawn.h"

#include "chainparams.h"
#include "chainparamsbase.h"
#include "consensus/upgrades.h"
#include "hash.h"
#include "init.h"
#include "main.h"
#include "random.h"
#include "rpc/protocol.h"
#include "util/system.h"
#include "util/strencodings.h"
#include "util/time.h"
#include "core_io.h"
#include "rpc/server.h"
#include "wallet/wallet.h"
#include "support/allocators/secure.h"
#include "support/cleanse.h"

#include <boost/thread.hpp>

#include <fcntl.h>
#include <cmath>
#include <fstream>
#include <map>
#include <set>
#include <mutex>
#include <poll.h>
#include <signal.h>
#include <sstream>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace yugenwallet {

namespace {
std::mutex engineMutex;   // one engine process at a time: they share wallet.json
std::mutex addrMutex;

fs::path Dir() { return GetDataDir() / "yugenwallet"; }
fs::path StoreFile() { return Dir() / "wallet.json"; }
fs::path AddrFile() { return Dir() / "ycashd-addresses.txt"; }

std::string Binary()
{
    std::string b = GetArg("-yugenwallet", "");
    return b.empty() ? GetArg("-yugenprover", "") : b;
}

std::string NetworkName()
{
    const std::string n = Params().NetworkIDString();
    return n == "main" ? "main" : n == "test" ? "testnet" : "regtest";
}

// Runs argv without a shell; returns stdout; kills the process group at the deadline.
// With `seed`, the child reads it from fd 3 as hex followed by '\n' (the engine reads to the newline, never to end
// of file): a pipe created close-on-exec (pipe2, or pipe + FD_CLOEXEC under SpawnMutex, which every fork of this
// node holds), so no other child inherits it; the child's dup2 onto 3 clears the flag on its copy only, and the
// child closes every other descriptor from 4 up (doc/yugen-node.md N-A5).
std::string RunProcess(const std::vector<std::string>& argv, int64_t timeoutSecs, int& status, bool& timedOut,
                       const CKeyingMaterial* seed = nullptr)
{
    std::vector<char*> cargv;
    for (auto& a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
    cargv.push_back(nullptr);
    const long maxfd = OpenFdLimit();
    int fd[2] = {-1, -1};
    int sp[2] = {-1, -1};
    pid_t pid;
    {
        std::lock_guard<std::mutex> sg(SpawnMutex());
        if (!PipeCloexec(fd)) throw JSONRPCError(RPC_WALLET_ERROR, "Yugen: pipe failed");
        if (seed != nullptr) {
            if (!PipeCloexec(sp)) { close(fd[0]); close(fd[1]); throw JSONRPCError(RPC_WALLET_ERROR, "Yugen: pipe failed"); }
            static const char hexd[] = "0123456789abcdef";
            SecureString h;
            for (unsigned char c : *seed) { h.push_back(hexd[c >> 4]); h.push_back(hexd[c & 15]); }
            h.push_back('\n');
            // 65 to 129 bytes: well inside the pipe buffer, so the write never blocks
            const bool ok = write(sp[1], h.data(), h.size()) == (ssize_t)h.size();
            close(sp[1]);
            if (!ok) { close(sp[0]); close(fd[0]); close(fd[1]); throw JSONRPCError(RPC_WALLET_ERROR, "Yugen: seed pipe failed"); }
        }
        pid = fork();
    }
    if (pid < 0) { close(fd[0]); close(fd[1]); if (sp[0] >= 0) close(sp[0]); throw JSONRPCError(RPC_WALLET_ERROR, "Yugen: fork failed"); }
    if (pid == 0) {
        setpgid(0, 0);
        dup2(fd[1], 1);
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) { dup2(devnull, 0); dup2(devnull, 2); }
        int first = 3;
        if (sp[0] >= 0) {
            if (sp[0] == 3) fcntl(3, F_SETFD, 0); else dup2(sp[0], 3);
            first = 4;
        }
        CloseFdsFrom(first, maxfd);
        execve(cargv[0], cargv.data(), environ);
        _exit(127);
    }
    if (sp[0] >= 0) close(sp[0]);
    setpgid(pid, pid);  // also in the parent, so kill(-pid) reaches the group whichever runs first
    close(fd[1]);
    std::string out;
    const int64_t deadline = GetTimeMillis() + 1000 * timeoutSecs;
    timedOut = false;
    char buf[65536];
    for (;;) {
        int64_t left = deadline - GetTimeMillis();
        if (left <= 0 || ShutdownRequested()) { timedOut = true; break; }
        struct pollfd pf{fd[0], POLLIN, 0};
        int n = poll(&pf, 1, (int)std::min<int64_t>(left, 1000));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) break;
        if (n == 0) continue;
        ssize_t k = read(fd[0], buf, sizeof(buf));
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) break;
        out.append(buf, k);
    }
    close(fd[0]);
    status = 0;
    if (!timedOut) {
        // stdout closed: wait for the exit, still bounded by the deadline
        for (;;) {
            pid_t w = waitpid(pid, &status, WNOHANG);
            if (w == pid) return out;
            if (w < 0 && errno != EINTR) return out;
            if (GetTimeMillis() >= deadline || ShutdownRequested()) { timedOut = true; break; }
            MilliSleep(50);
        }
    }
    kill(-pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return out;
}

} // namespace


namespace {
std::vector<std::string> ReadLines(const fs::path& p)
{
    std::vector<std::string> v;
    std::ifstream f(p.string());
    std::string l;
    while (std::getline(f, l)) if (!l.empty()) v.push_back(l);
    return v;
}
} // namespace

bool Configured()
{
    if (Binary().empty() || pwalletMain == nullptr) return false;
    return Params().GetConsensus().vUpgrades[Consensus::UPGRADE_YUGEN].nActivationHeight !=
           Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
}

bool Exists()
{
    return Configured() && fs::exists(StoreFile());
}

bool LooksLikeYugenAddress(const std::string& s)
{
    return s.size() > 3 && s.compare(0, 2, "yq") == 0;
}

std::optional<std::vector<unsigned char>> DerivedSeed()
{
    if (pwalletMain == nullptr) return std::nullopt;
    LOCK(pwalletMain->cs_wallet);
    auto ms = pwalletMain->GetMnemonicSeed();
    if (!ms.has_value()) return std::nullopt;
    auto raw = ms.value().RawSeed();
    // N-A2: BLAKE2b-256, personalisation "Ycash_YugenSeed_", over the BIP 39 seed bytes (64).
    CBLAKE2bWriter w(SER_GETHASH, 0, (const unsigned char*)"Ycash_YugenSeed_");
    w.write((const char*)raw.data(), raw.size());
    uint256 h = w.GetHash();
    return std::vector<unsigned char>(h.begin(), h.end());
}

// fsync, and on macOS F_FULLFSYNC (fsync there leaves the data in the drive's cache).
static int FullSync(int fd)
{
#ifdef __APPLE__
    if (fcntl(fd, F_FULLFSYNC) == 0) return 0;
#endif
    return fsync(fd);
}

static void CleanseStr(const std::string& t)
{
    if (!t.empty()) memory_cleanse(const_cast<char*>(t.data()), t.size());
}

// Constant-time equality of two seeds (no early exit on the first differing byte).
static bool SeedEqual(const CKeyingMaterial& a, const CKeyingMaterial& b)
{
    if (a.size() != b.size()) return false;
    unsigned char d = 0;
    for (size_t i = 0; i < a.size(); i++) d |= a[i] ^ b[i];
    return d == 0;
}

// Hex (64 to 128 characters) into a seed; no plain copy.
static bool SeedFromHex(const char* h, size_t n, CKeyingMaterial& out)
{
    if (n < 64 || n > 128 || n % 2) return false;
    out.assign(n / 2, 0);
    for (size_t i = 0; i < n; i++) {
        const signed char v = HexDigit(h[i]);
        if (v < 0) { memory_cleanse(out.data(), out.size()); out.clear(); return false; }
        out[i / 2] = (unsigned char)((out[i / 2] << 4) | v);
    }
    return true;
}

// The state file read through a secure buffer; a legacy "seed" in the returned value is cleansed by the caller
// (CleanseStr) once used (N-A5).
static UniValue ReadStoreSecure()
{
    UniValue v;
    int fd = open(StoreFile().string().c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return UniValue(UniValue::VOBJ);
    SecureString buf;
    char b[4096];
    for (;;) {
        ssize_t k = read(fd, b, sizeof(b));
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) break;
        buf.append(b, k);
    }
    memory_cleanse(b, sizeof(b));
    close(fd);
    if (!v.read(buf.data(), buf.size()) || !v.isObject()) return UniValue(UniValue::VOBJ);
    return v;
}

static UniValue ReadStore()
{
    // wallet.json is replaced by an atomic rename, so it is read without the engine mutex (no lock waits on a send)
    UniValue v;
    std::ifstream f(StoreFile().string());
    std::stringstream ss;
    ss << f.rdbuf();
    if (!v.read(ss.str()) || !v.isObject()) return UniValue(UniValue::VOBJ);
    return v;
}

// Writes `text` to `p` atomically with mode 0600 (temporary file, full sync, rename, directory sync). With
// `scrubOld` the file being replaced held a seed (N-A5): it is opened first (O_NOFOLLOW, a regular file only),
// the new file is renamed over it and the directory synced, and only then is the old inode, still open here,
// overwritten with zeros and synced, so a crash leaves either the old file whole or the new one in place.
static void WritePrivate(const fs::path& p, const std::string& text, bool scrubOld)
{
    fs::create_directories(p.parent_path());
    chmod(p.parent_path().string().c_str(), 0700);
    int of = -1;
    if (scrubOld) {
        of = open(p.string().c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
        struct stat sb;
        // only a regular file with a single link is zeroed (another link would be a different file's content)
        if (of >= 0 && (fstat(of, &sb) != 0 || !S_ISREG(sb.st_mode) || sb.st_nlink != 1)) {
            LogPrintf("Yugen account: %s is not a single-link regular file; the old content is not overwritten\n", p.string());
            close(of);
            of = -1;
        }
    }
    const fs::path tmp = p.string() + ".tmp";
    unlink(tmp.string().c_str());
    int fd = open(tmp.string().c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0 || fchmod(fd, 0600) != 0 || write(fd, text.data(), text.size()) != (ssize_t)text.size() || FullSync(fd) != 0) {
        if (fd >= 0) close(fd);
        if (of >= 0) close(of);
        unlink(tmp.string().c_str());
        throw JSONRPCError(RPC_WALLET_ERROR, "Yugen account: cannot write the account state");
    }
    close(fd);
    if (rename(tmp.string().c_str(), p.string().c_str()) != 0) {
        if (of >= 0) close(of);
        unlink(tmp.string().c_str());
        throw JSONRPCError(RPC_WALLET_ERROR, "Yugen account: cannot replace the account state");
    }
    int dfd = open(p.parent_path().string().c_str(), O_RDONLY | O_CLOEXEC);
    if (dfd >= 0) { FullSync(dfd); close(dfd); }
    if (of >= 0) {
        struct stat sb;
        if (fstat(of, &sb) == 0 && sb.st_size > 0) {
            std::vector<char> z((size_t)sb.st_size, 0);
            if (pwrite(of, z.data(), z.size(), 0) != (ssize_t)z.size()) LogPrintf("Yugen account: could not overwrite the old %s\n", p.string());
            FullSync(of);
        }
        close(of);
    }
}

static std::string FingerprintHex(const CKeyingMaterial& seed)
{
    const uint256 fp = CCryptoKeyStore::YugenSeedFingerprint(seed);
    return HexStr(fp.begin(), fp.end());  // byte order of the engine's seed_fingerprint
}

// A new account state: no seed (N-A5), only the seed's fingerprint, mode 0600 (the engine's Store, yewd/yugen
// wallet/src/store.rs).
static void WriteNewStore(const CKeyingMaterial& seed)
{
    const std::string n = NetworkName();
    UniValue o(UniValue::VOBJ);
    o.pushKV("seed_fp", FingerprintHex(seed));
    o.pushKV("network", n == "main" ? 0 : n == "testnet" ? 1 : 2);
    o.pushKV("scanned", NullUniValue);
    o.pushKV("leaves", UniValue(UniValue::VARR));
    o.pushKV("sizes", UniValue(UniValue::VOBJ));
    o.pushKV("requests", UniValue(UniValue::VARR));
    // next_change cannot be recovered from the seed; a random start in [2^24, 2^31) keeps a restored account
    // off the change indices it used before (N-A4). Dummy nullifiers need no such start: the engine skips a
    // dummy counter whose nullifier is on chain (spec §5.6).
    const int64_t start = (1LL << 24) + (int64_t)GetRand((1ULL << 31) - (1ULL << 24));
    o.pushKV("next_change", start);
    o.pushKV("otag_counters", UniValue(UniValue::VOBJ));
    o.pushKV("notes", UniValue(UniValue::VARR));
    o.pushKV("deposit_utxos", UniValue(UniValue::VARR));
    WritePrivate(StoreFile(), o.write(1), false);
}

static bool WalletLocked()
{
    return pwalletMain != nullptr && pwalletMain->IsCrypted() && pwalletMain->IsLocked();
}

[[noreturn]] static void ThrowUnlockNeeded()
{
    throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
}

// N-A5 migration: a state file written before seeds left it holds "seed". The seed moves into wallet.dat (encrypted
// under the master key when the wallet is encrypted); only once the record is read back from disk (YugenSeedDurable)
// is the file rewritten without it, the old content overwritten. Needs an unlocked wallet when encrypted; returns
// false (nothing changed, the file keeps the seed) otherwise.
static bool MigrateLegacyLocked(std::string& err)
{
    if (!fs::exists(StoreFile())) return true;
    UniValue v = ReadStoreSecure();
    const UniValue& h = find_value(v, "seed");
    if (!h.isStr()) return true;
    struct Cleanse { const UniValue& u; ~Cleanse() { CleanseStr(u.get_str()); } } cleanse{h};
    CKeyingMaterial legacy;
    if (!SeedFromHex(h.get_str().data(), h.get_str().size(), legacy)) { err = "the Yugen account state holds a malformed seed"; return false; }
    if (pwalletMain->HaveYugenSeed()) {
        auto held = pwalletMain->GetYugenSeed();
        if (!held.has_value()) { err = "the wallet is locked"; return false; }
        if (!SeedEqual(held.value(), legacy)) { err = "the Yugen account state holds another seed than the wallet"; return false; }
    } else if (!pwalletMain->SetYugenSeed(legacy)) {
        err = WalletLocked() ? "the wallet is locked" : "cannot store the Yugen seed in the wallet";
        return false;
    }
    if (!pwalletMain->YugenSeedDurable()) { err = "the Yugen seed could not be confirmed on disk in wallet.dat; the state file keeps it"; return false; }
    UniValue o(UniValue::VOBJ);
    for (const std::string& k : v.getKeys()) if (k != "seed") o.pushKV(k, find_value(v, k));
    if (find_value(o, "seed_fp").isNull()) o.pushKV("seed_fp", FingerprintHex(legacy));
    WritePrivate(StoreFile(), o.write(1), true);
    LogPrintf("Yugen account: the seed moved from %s into the wallet; the file no longer holds it\n", StoreFile().string());
    return true;
}

// The state file still holds a legacy seed in plain text (it has not moved into the wallet yet).
static bool LegacySeedPresent()
{
    if (!fs::exists(StoreFile())) return false;
    UniValue v = ReadStoreSecure();
    const UniValue& h = find_value(v, "seed");
    if (!h.isStr()) return false;
    CleanseStr(h.get_str());
    return true;
}

static void WarnLegacyWhileLocked()
{
    if (WalletLocked() && LegacySeedPresent())
        LogPrintf("Yugen account: WARNING: %s still holds the Yugen seed in plain text while the wallet is encrypted and "
                  "locked; unlock the wallet (walletpassphrase) to move it into the encrypted wallet\n", StoreFile().string());
}

// The account seed for one engine call. Creates the account (N-A2 seed into the wallet) when none exists.
static CKeyingMaterial AccountSeed(const std::string& seedOverrideHex)
{
    std::string err;
    if (!MigrateLegacyLocked(err)) {
        if (WalletLocked()) ThrowUnlockNeeded();
        throw JSONRPCError(RPC_WALLET_ERROR, "Yugen account: " + err);
    }
    if (pwalletMain->HaveYugenSeed()) {
        auto s = pwalletMain->GetYugenSeed();
        if (!s.has_value()) ThrowUnlockNeeded();
        if (!fs::exists(StoreFile())) {
            // no account state yet: a seed stored by a node without -yugenprover, or a new account whose
            // durability check failed; it is used only once the record is confirmed on disk
            if (!pwalletMain->YugenSeedDurable())
                throw JSONRPCError(RPC_WALLET_ERROR, "Yugen account: the Yugen seed could not be confirmed on disk in wallet.dat");
            WriteNewStore(s.value());
        }
        return s.value();
    }
    if (fs::exists(StoreFile()))
        throw JSONRPCError(RPC_WALLET_ERROR, "Yugen account: the wallet holds no Yugen seed for the existing account state; restore it (importwallet)");
    CKeyingMaterial seed;
    if (!seedOverrideHex.empty()) {
        if (!SeedFromHex(seedOverrideHex.data(), seedOverrideHex.size(), seed)) throw JSONRPCError(RPC_INVALID_PARAMETER, "Yugen account: bad seed");
    } else {
        if (WalletLocked()) ThrowUnlockNeeded();
        auto d = DerivedSeed();
        if (!d.has_value()) throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Yugen account: the wallet is locked or has no mnemonic seed; unlock it to create the Yugen account");
        seed.assign(d->begin(), d->end());
        memory_cleanse(d->data(), d->size());
    }
    if (!pwalletMain->SetYugenSeed(seed)) {
        if (WalletLocked()) ThrowUnlockNeeded();
        throw JSONRPCError(RPC_WALLET_ERROR, "Yugen account: cannot store the Yugen seed in the wallet");
    }
    if (!pwalletMain->YugenSeedDurable()) throw JSONRPCError(RPC_WALLET_ERROR, "Yugen account: the Yugen seed could not be confirmed on disk in wallet.dat");
    WriteNewStore(seed);
    return seed;
}

static UniValue CallLocked(const std::string& method, const UniValue& params, int64_t timeoutSecs,
                           const std::string& seedOverride)
{
    if (!Configured()) throw JSONRPCError(RPC_WALLET_ERROR, "Yugen account: set -yugenprover (or -yugenwallet) to the yewd-yugen binary; Yugen needs a height");
    fs::create_directories(Dir());
    std::vector<std::string> argv{Binary(), "-datadir=" + Dir().string(), "-network=" + NetworkName(),
                                  strprintf("-node=127.0.0.1:%d", GetArg("-rpcport", BaseParams().RPCPort()))};
    // No secret on the command line (it is visible to every local user): rpcuser/rpcpassword go to the engine
    // in a 0600 cookie-format file removed after the call; the node's own cookie file otherwise.
    fs::path credFile;
    if (mapArgs.count("-rpcpassword") && !GetArg("-rpcpassword", "").empty()) {
        credFile = Dir() / strprintf(".rpccred-%s", GetRandHash().GetHex().substr(0, 16));
        int cfd = open(credFile.string().c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (cfd < 0) throw JSONRPCError(RPC_WALLET_ERROR, "Yugen account: cannot write the engine's credential file");
        const std::string c = GetArg("-rpcuser", "") + ":" + GetArg("-rpcpassword", "");
        const bool ok = write(cfd, c.data(), c.size()) == (ssize_t)c.size();
        close(cfd);
        if (!ok) { fs::remove(credFile); throw JSONRPCError(RPC_WALLET_ERROR, "Yugen account: cannot write the engine's credential file"); }
        argv.push_back("-rpccookiefile=" + credFile.string());
    } else {
        fs::path c(GetArg("-rpccookiefile", ".cookie"));
        if (!c.is_absolute()) c = GetDataDir() / c;
        argv.push_back("-rpccookiefile=" + c.string());
    }
    if (!GetArg("-yugenhosts", "").empty()) argv.push_back("-yugenhosts=" + GetArg("-yugenhosts", ""));
    // N-A5: the seed lives in wallet.dat only; the engine gets it per call on fd 3, never argv, env or a file.
    CKeyingMaterial seed;
    try {
        seed = AccountSeed(seedOverride);
    } catch (...) {
        if (!credFile.empty()) fs::remove(credFile);
        throw;
    }
    argv.push_back("-seedfd=3");
    argv.push_back(method);
    argv.push_back(params.write());
    if (timeoutSecs <= 0) timeoutSecs = GetArg("-yugenprovetimeout", 1800);
    int status = 0;
    bool timedOut = false;
    std::string out;
    try {
        out = RunProcess(argv, timeoutSecs, status, timedOut, &seed);
    } catch (...) {
        if (!credFile.empty()) fs::remove(credFile);
        throw;
    }
    if (!credFile.empty()) fs::remove(credFile);
    if (timedOut) throw JSONRPCError(RPC_WALLET_ERROR, "Yugen account: the wallet engine timed out (-yugenprovetimeout) or the node is shutting down");
    UniValue v;
    std::string line = out.substr(0, out.find('\n'));
    if (!v.read(line))
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Yugen account: the wallet engine failed (exit %d; is -yugenprover the yewd-yugen binary?)",
                                                       WIFEXITED(status) ? WEXITSTATUS(status) : -1));
    if (v.isObject() && !find_value(v, "error").isNull() && find_value(v, "error").isStr())
        throw JSONRPCError(RPC_WALLET_ERROR, "Yugen: " + find_value(v, "error").get_str());
    if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0))
        throw JSONRPCError(RPC_WALLET_ERROR, "Yugen account: the wallet engine failed");
    return v;
}

UniValue Call(const std::string& method, const UniValue& params, int64_t timeoutSecs)
{
    std::lock_guard<std::mutex> g(engineMutex);
    return CallLocked(method, params, timeoutSecs, "");
}

UniValue State(bool scan)
{
    // Read paths never wait behind a running engine call (a sync or a proof, up to -yugenprovetimeout): when
    // the engine is busy the state file is read as it stands (atomic renames keep it whole).
    // A locked wallet has no seed to scan with: the state as of the last unlocked call is read (it holds no secret).
    if (scan && !WalletLocked()) {
        std::unique_lock<std::mutex> g(engineMutex, std::try_to_lock);
        if (g.owns_lock()) CallLocked("syncstatus", UniValue(UniValue::VARR), 0, "");
    }
    return ReadStore();
}

std::vector<std::string> Addresses()
{
    std::lock_guard<std::mutex> g(addrMutex);
    return ReadLines(AddrFile());
}

bool IsOwnAddress(const std::string& s)
{
    for (const auto& a : Addresses()) if (a == s) return true;
    return false;
}

std::string NewAddress(bool onetime)
{
    UniValue p(UniValue::VARR);
    UniValue o(UniValue::VOBJ);
    o.pushKV("onetime", onetime);
    p.push_back(o);
    UniValue a = Call("getaddress", p);
    if (!a.isStr()) throw JSONRPCError(RPC_WALLET_ERROR, "Yugen account: getaddress returned no address");
    std::lock_guard<std::mutex> g(addrMutex);
    auto have = ReadLines(AddrFile());
    if (std::find(have.begin(), have.end(), a.get_str()) == have.end()) {
        const std::string line = a.get_str() + "\n";
        int fd = open(AddrFile().string().c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (fd < 0) throw JSONRPCError(RPC_WALLET_ERROR, "Yugen account: cannot write the address file");
        const bool ok = write(fd, line.data(), line.size()) == (ssize_t)line.size() && fsync(fd) == 0;
        close(fd);
        if (!ok) throw JSONRPCError(RPC_WALLET_ERROR, "Yugen account: cannot write the address file");
    }
    return a.get_str();
}

static SecureString HexOf(const CKeyingMaterial& s)
{
    static const char hexd[] = "0123456789abcdef";
    SecureString h;
    h.reserve(s.size() * 2);
    for (unsigned char c : s) { h.push_back(hexd[c >> 4]); h.push_back(hexd[c & 15]); }
    return h;
}

SecureString SeedHex()
{
    if (pwalletMain == nullptr) return SecureString();
    // A seed held in wallet.dat is dumped whether or not this node runs Yugen (-yugenprover): a backup never
    // depends on the node's configuration.
    if (!Configured()) {
        if (!pwalletMain->HaveYugenSeed()) return SecureString();
        auto s = pwalletMain->GetYugenSeed();
        if (!s.has_value()) {
            if (WalletLocked()) ThrowUnlockNeeded();
            throw JSONRPCError(RPC_WALLET_ERROR, "Yugen account: the wallet holds a Yugen seed that cannot be read; the backup would not restore it");
        }
        return HexOf(s.value());
    }
    // callers hold cs_main/cs_wallet, which a running engine's RPC callbacks need: never wait for the engine here
    std::unique_lock<std::mutex> g(engineMutex, std::try_to_lock);
    std::string err;
    if (g.owns_lock()) MigrateLegacyLocked(err);
    const bool account = fs::exists(StoreFile());
    if (!pwalletMain->HaveYugenSeed() && !account) return SecureString();  // no Yugen account
    auto s = pwalletMain->GetYugenSeed();
    // a backup that silently leaves out the seed of an existing account loses its funds: refuse instead
    if (!s.has_value()) {
        if (WalletLocked()) ThrowUnlockNeeded();
        std::string why;
        if (!err.empty()) why = err;
        else if (!g.owns_lock()) why = "the Yugen engine is busy; retry when the Yugen engine is idle";
        else why = "the wallet holds no Yugen seed for the existing account state; restore it (importwallet)";
        throw JSONRPCError(RPC_WALLET_ERROR, "Yugen account: the account exists but its seed is not available (" + why +
                                             "); the backup would not restore it");
    }
    return HexOf(s.value());
}

// A seed into wallet.dat without the engine (a node without -yugenprover): kept for a later Yugen start.
static bool StoreSeedOnly(const CKeyingMaterial& given, std::string& err)
{
    if (WalletLocked()) { err = "the wallet is locked"; return false; }
    if (pwalletMain->HaveYugenSeed()) {
        auto held = pwalletMain->GetYugenSeed();
        if (held.has_value() && SeedEqual(held.value(), given)) return true;
        err = "a Yugen account with another seed exists in this wallet";
        return false;
    }
    if (!pwalletMain->SetYugenSeed(given)) { err = "cannot store the Yugen seed in the wallet"; return false; }
    if (!pwalletMain->YugenSeedDurable()) { err = "the Yugen seed could not be confirmed on disk in wallet.dat"; return false; }
    LogPrintf("Yugen account: seed stored in the wallet (this node has no -yugenprover; a Yugen-configured start uses it)\n");
    return true;
}

bool RestoreSeed(const SecureString& seedHex, std::string& err)
{
    CKeyingMaterial given;
    if (!SeedFromHex(seedHex.data(), seedHex.size(), given)) { err = strprintf("bad Yugen seed (%d hex characters, need 64 to 128)", seedHex.size()); return false; }
    if (pwalletMain == nullptr) { err = "no wallet"; return false; }
    if (!Configured()) return StoreSeedOnly(given, err);
    std::unique_lock<std::mutex> g(engineMutex, std::try_to_lock);
    if (!g.owns_lock()) { err = "the Yugen engine is busy; retry"; return false; }
    if (!MigrateLegacyLocked(err)) return false;
    if (WalletLocked()) { err = "the wallet is locked"; return false; }
    if (pwalletMain->HaveYugenSeed()) {
        auto held = pwalletMain->GetYugenSeed();
        if (held.has_value() && SeedEqual(held.value(), given)) {
            if (!fs::exists(StoreFile())) WriteNewStore(given);
            return true;
        }
        err = "a Yugen account with another seed exists in this wallet";
        return false;
    }
    if (fs::exists(StoreFile())) {
        const UniValue fp = find_value(ReadStore(), "seed_fp");
        if (!fp.isStr() || fp.get_str() != FingerprintHex(given)) { err = "a Yugen account with another seed exists in this wallet"; return false; }
    }
    if (!pwalletMain->SetYugenSeed(given)) { err = "cannot store the Yugen seed in the wallet"; return false; }
    if (!pwalletMain->YugenSeedDurable()) { err = "the Yugen seed could not be confirmed on disk in wallet.dat"; return false; }
    if (!fs::exists(StoreFile())) WriteNewStore(given);
    return true;
}

bool MigrateLegacySeed(std::string& err)
{
    if (!Configured()) return true;
    // never waits for a running engine (its RPC callbacks need the locks callers may hold)
    std::unique_lock<std::mutex> g(engineMutex, std::try_to_lock);
    if (!g.owns_lock()) { err = "the Yugen engine is busy; retry"; return false; }
    if (MigrateLegacyLocked(err)) return true;
    WarnLegacyWhileLocked();
    return false;
}

bool Locked()
{
    return WalletLocked();
}

bool ResetChainState(std::string& err)
{
    std::lock_guard<std::mutex> g(engineMutex);
    if (!fs::exists(StoreFile())) return true;
    // A seed left in the state file by an earlier version moves into wallet.dat first; if it cannot (a locked
    // wallet), the rescan is refused and the file is left as it is: the seed is never dropped here (N-A5).
    if (!MigrateLegacyLocked(err)) return false;
    UniValue v = ReadStoreSecure();
    if (!v.isObject() || v.getKeys().empty()) return true;
    // keep: seed (never dropped here), network, issued requests, the counters (never reused), paid requests,
    // resolved addresses and queued sends; forget everything the chain and the hosts give back.
    UniValue o(UniValue::VOBJ);
    for (const std::string& k : v.getKeys()) {
        if (k == "scanned" || k == "host_synced") o.pushKV(k, NullUniValue);
        else if (k == "leaves" || k == "notes" || k == "deposit_utxos") o.pushKV(k, UniValue(UniValue::VARR));
        else if (k == "sizes") o.pushKV(k, UniValue(UniValue::VOBJ));
        else o.pushKV(k, find_value(v, k));
    }
    if (v.exists("seed")) { CleanseStr(find_value(v, "seed").get_str()); err = "the account state still holds a seed"; return false; }
    WritePrivate(StoreFile(), o.write(1), false);
    LogPrintf("Yugen account: chain state cleared for a rescan\n");
    return true;
}

std::string RescanRecovery(const std::string& err)
{
    const std::string pre = "The account state file of an earlier version still holds the Yugen seed, which must move into the wallet first: ";
    if (err.find("locked") != std::string::npos)
        return pre + "start without -rescan, unlock the wallet once (walletpassphrase), then restart with -rescan.";
    if (err.find("another seed") != std::string::npos)
        return "The seed in the account state file is not the wallet's Yugen seed: keep both files, move the yugenwallet "
               "directory aside only after backing it up (it holds that seed), and restore the account whose funds you need "
               "with importwallet.";
    if (err.find("malformed") != std::string::npos)
        return "The seed in the account state file cannot be read: restore the Yugen account from a wallet backup "
               "(importwallet) after moving the yugenwallet directory aside; do not delete it.";
    if (err.find("on disk") != std::string::npos || err.find("cannot store") != std::string::npos)
        return pre + "wallet.dat could not be written and confirmed on disk; check the disk (space, permissions, errors) and "
               "restart; the state file keeps the seed until then.";
    return pre + "start without -rescan and check debug.log, then restart with -rescan.";
}

static const int64_t LEAF_FEE = 100000 + 155600;  // BASE_FEE + LEAF_PROOF_FEE (spec 0.5.2 §2, §16.1)

static int Tip()
{
    LOCK(cs_main);
    return chainActive.Height();
}

static std::string MemoText(const UniValue& memoHex)
{
    if (!memoHex.isStr()) return "";
    auto b = ParseHex(memoHex.get_str());
    while (!b.empty() && b.back() == 0) b.pop_back();
    return std::string(b.begin(), b.end());
}

static bool IsChangeKind(const UniValue& n) { return n["d"].isStr() && n["d"].get_str().compare(0, 2, "02") == 0; }

UniValue NoteRows(bool unspentOnly, int minconf, bool includeChange)
{
    UniValue st = State(true);
    const UniValue& notes = find_value(st, "notes");
    const int tip = Tip();
    // spec §8.3: the wallet's anchor (tip - 3, down to the grid); a note at or below it is spendable
    const int ha = tip < 3 ? -1 : (tip - 3) / 16 * 16;
    const auto addrs = Addresses();
    const std::string addr = addrs.empty() ? "" : addrs.front();
    std::set<std::string> spentIn;
    if (notes.isArray())
        for (const auto& n : notes.getValues()) if (n["spent_in"].isStr()) spentIn.insert(n["spent_in"].get_str());
    UniValue out(UniValue::VARR);
    LogPrint("yugen", "Yugen account: %d notes in state (%s), tip %d\n", notes.isArray() ? (int)notes.size() : -1, StoreFile().string(), tip);
    if (!notes.isArray()) return out;
    for (const auto& n : notes.getValues()) {
        const bool spent = n["spent_in"].isStr();
        const bool change = IsChangeKind(n) && spentIn.count(n["txid"].get_str());
        const int64_t v = n["v"].get_int64();
        const int height = n["height"].get_int();
        const int conf = height > 0 ? tip - height + 1 : 0;
        if (unspentOnly && (spent || v == 0)) continue;
        if (!includeChange && change) continue;
        if (conf < minconf) continue;
        UniValue r(UniValue::VOBJ);
        r.pushKV("txid", n["txid"]);
        r.pushKV("pool", "yugen");
        r.pushKV("outindex", n["pos"]);
        r.pushKV("confirmations", conf);
        r.pushKV("blockheight", height);
        r.pushKV("spendable", !spent && n["applied"].isTrue() && n["pending"].isNull() && height <= ha);
        r.pushKV("address", addr);
        r.pushKV("amount", ValueFromAmount(v));
        r.pushKV("amountZat", v);
        r.pushKV("memo", n["memo"].isStr() ? n["memo"].get_str() : "f6");
        const std::string mt = MemoText(n["memo"]);
        if (!mt.empty()) r.pushKV("memoStr", mt);
        r.pushKV("change", change);
        if (!unspentOnly) r.pushKV("spent", spent);
        r.pushKV("pending", !n["pending"].isNull());
        out.push_back(r);
    }
    return out;
}

Balances GetBalances()
{
    // From the engine's state after a chain scan (any engine version with `syncstatus`), by the rule of the
    // engine's `balances`: spendable = applied, not pending, unspent, at or below the wallet anchor.
    Balances r;
    const UniValue rows = NoteRows(true, 0, true);
    for (const auto& n : rows.getValues()) {
        const int64_t v = n["amountZat"].get_int64();
        if (n["spendable"].isTrue()) r.spendable += v;
        else if (!n["pending"].isTrue()) r.pending += v;
    }
    const UniValue st = ReadStore();
    const UniValue& ps = find_value(st, "pending_sends");
    if (ps.isArray())
        for (const auto& p : ps.getValues())
            if (p["state"].getValStr() == "waiting") r.outgoing += p["amount"].get_int64();
    return r;
}

UniValue TxRows()
{
    UniValue st = State(true);
    const UniValue& notes = find_value(st, "notes");
    UniValue out(UniValue::VARR);
    if (!notes.isArray()) return out;
    const int tip = Tip();
    const auto addrs = Addresses();
    const std::string addr = addrs.empty() ? "" : addrs.front();
    std::map<std::string, int64_t> spentSum, changeSum;
    std::map<std::string, int> txHeight;
    std::vector<std::string> order;
    for (const auto& n : notes.getValues()) {
        txHeight[n["txid"].get_str()] = n["height"].get_int();
        if (n["spent_in"].isStr()) {
            const std::string t = n["spent_in"].get_str();
            if (!spentSum.count(t)) order.push_back(t);
            spentSum[t] += n["v"].get_int64();
        }
    }
    for (const auto& n : notes.getValues()) {
        const std::string t = n["txid"].get_str();
        const int64_t v = n["v"].get_int64();
        const int h = n["height"].get_int();
        if (spentSum.count(t) && IsChangeKind(n)) { changeSum[t] += v; continue; }
        if (v == 0) continue;
        UniValue r(UniValue::VOBJ);
        r.pushKV("pool", "yugen");
        r.pushKV("address", addr);
        r.pushKV("category", "receive");
        r.pushKV("amount", ValueFromAmount(v));
        r.pushKV("amountZat", v);
        r.pushKV("txid", t);
        r.pushKV("confirmations", h > 0 ? tip - h + 1 : 0);
        r.pushKV("blockheight", h);
        const std::string mt = MemoText(n["memo"]);
        if (!mt.empty()) r.pushKV("memoStr", mt);
        out.push_back(r);
    }
    for (const auto& t : order) {
        const int64_t sent = spentSum[t] - changeSum[t] - LEAF_FEE;
        const int h = txHeight.count(t) ? txHeight[t] : 0;
        UniValue r(UniValue::VOBJ);
        r.pushKV("pool", "yugen");
        r.pushKV("address", addr);
        r.pushKV("category", "send");
        r.pushKV("amount", ValueFromAmount(-sent));
        r.pushKV("amountZat", -sent);
        r.pushKV("fee", ValueFromAmount(-LEAF_FEE));
        r.pushKV("txid", t);
        r.pushKV("confirmations", h > 0 ? tip - h + 1 : 0);
        r.pushKV("blockheight", h);
        out.push_back(r);
    }
    return out;
}

UniValue TxDetail(const std::string& txid)
{
    UniValue rows = TxRows();
    UniValue d(UniValue::VARR);
    int64_t amount = 0;
    int conf = 0;
    for (const auto& r : rows.getValues()) {
        if (r["txid"].get_str() != txid) continue;
        amount += r["amountZat"].get_int64();
        conf = r["confirmations"].get_int();
        d.push_back(r);
    }
    if (d.empty()) return NullUniValue;
    UniValue o(UniValue::VOBJ);
    o.pushKV("txid", txid);
    o.pushKV("pool", "yugen");
    o.pushKV("amount", ValueFromAmount(amount));
    o.pushKV("amountZat", amount);
    o.pushKV("confirmations", conf);
    o.pushKV("status", conf > 0 ? "mined" : "waiting");
    o.pushKV("details", d);
    return o;
}

void ThreadScheduledSync()
{
    RenameThread("zcash-yugensync");
    std::optional<int> done;
    const int64_t maxDelay = GetArg("-yugensyncdelay", 60);
    int64_t nextWarn = 0;
    try {
        for (;;) {
            MilliSleep(2000);
            if (!Configured() || !fs::exists(StoreFile())) continue;
            if (WalletLocked()) {  // no seed while locked: the sync waits for walletpassphrase
                if (GetTime() >= nextWarn) { WarnLegacyWhileLocked(); nextWarn = GetTime() + 3600; }
                continue;
            }
            int h;
            {
                LOCK(cs_main);
                h = chainActive.Height();
            }
            const int b = h / 16 * 16;
            if (done.has_value() && done.value() >= b) continue;
            // decision Y-16: a delay drawn afresh from [0, 60] s after the boundary block
            if (maxDelay > 0) MilliSleep(1000 * (int64_t)GetRand(maxDelay + 1));
            try {
                UniValue r = Call("sync", UniValue(UniValue::VARR));
                if (find_value(r, "retry").isTrue()) continue;
                done = b;
                if (find_value(r, "session").isTrue())
                    LogPrintf("Yugen account: scheduled sync at boundary %d: %s\n", b, r.write());
            } catch (const UniValue& e) {
                LogPrintf("Yugen account: scheduled sync at boundary %d failed: %s\n", b, find_value(e, "message").getValStr());
            } catch (const std::exception& e) {
                LogPrintf("Yugen account: scheduled sync at boundary %d failed: %s\n", b, e.what());
            }
        }
    } catch (const boost::thread_interrupted&) {
        throw;
    }
}

} // namespace yugenwallet
