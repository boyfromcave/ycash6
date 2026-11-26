// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "yugen/state.h"
#include "yugen/spawn.h"

#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/upgrades.h"
#include "consensus/validation.h"
#include "crypto/pq/scheme.h"
#include "hash.h"
#include "main.h"
#include "primitives/yugen.h"
#include "pubkey.h"
#include "script/interpreter.h"
#include "streams.h"
#include "txmempool.h"
#include "undo.h"
#include "util/strencodings.h"
#include "util/system.h"
#include "util/time.h"
#include "vault/act.h"
#include "vault/template.h"
#include "version.h"

#include <univalue.h>

#include <algorithm>
#include <cstdio>
#include <deque>
#include <fstream>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

extern "C" {
#include "crypto/pq/falcon/fips202.h"
}

namespace yugen {

struct HelperResult {
    enum Kind { FAIL, OK, REJECT } kind{FAIL};
    std::string line;
    std::string all;
    // A bundle REJECT only: the helper had confirmed both proofs hash to the committed hashes (review H-1).
    bool proofsBound{false};
};

// Review M-2: the helper timeout while a mempool candidate is checked (-yugenmempoolverifytimeout).
static int64_t g_timeoutOverride = 0;
struct MempoolTimeout {
    MempoolTimeout() { g_timeoutOverride = GetArg("-yugenmempoolverifytimeout", DEFAULT_MEMPOOL_VERIFY_TIMEOUT); }
    ~MempoolTimeout() { g_timeoutOverride = 0; }
};

// A bounded set, oldest out first (review M-4).
template <typename K, typename V>
struct BoundedMap {
    size_t max;
    std::map<K, V> map;
    std::deque<K> order;
    explicit BoundedMap(size_t m) : max(m) {}
    void put(const K& k, const V& v)
    {
        if (map.insert_or_assign(k, v).second) order.push_back(k);
        while (order.size() > max) { map.erase(order.front()); order.pop_front(); }
    }
    const V* get(const K& k) const { auto it = map.find(k); return it == map.end() ? nullptr : &it->second; }
    void erase(const K& k)
    {
        if (map.erase(k)) order.erase(std::find(order.begin(), order.end(), k));
    }
};

// Round 3: verifier failures per block hash and per body (block hash and sidecar), bounded.
static BoundedMap<uint256, int> g_helperFailures(1000), g_helperBodyFailures(1000);

static PoolState g_state;
// Between yugen::DisconnectBlock and EndDisconnect (DisconnectTip resurrects the block's
// transactions before chainActive moves back): the block the state is at, used as the tip.
static const CBlockIndex* g_tipOverride = nullptr;
static const CBlockIndex* ChainTip() { return g_tipOverride ? g_tipOverride : chainActive.Tip(); }
// SHA-256d of request documents that verified; bounded, oldest out first (review L-2).
static std::set<uint256> g_verified;
static std::deque<uint256> g_verifiedOrder;
static const size_t VERIFIED_MAX = 50000;
static std::optional<Root> g_rootCanaryOnly;
static std::optional<std::string> g_regRoot;

std::string HexRoot(const Root& r) { return HexStr(r.begin(), r.end()); }

static std::string Helper() { return GetArg("-yugenverifier", "yugen-leafverify"); }

static fs::path TmpDir()
{
    fs::path d = GetDataDir() / "yugen-tmp";
    fs::create_directories(d);
    return d;
}

// Runs the helper without a shell (fork/execv), reading stdout with a deadline of
// -yugenverifytimeout seconds (default 600; a System B root verification loads ~9.6 GB of
// verifying systems), -yugenmempoolverifytimeout for a mempool candidate. Exit 0 = OK; exit 10
// with a "REJECT " line = REJECT (a verdict on the input); anything else, including exit 1 (a Rust
// `main` returning `Err`), 101 (a panic), a timeout, a signal or a missing binary, = FAIL (a fault
// of this node, never a verdict: reviews H-1, H-2, M-2). It runs under cs_main, as all block
// validation here does.
static HelperResult RunHelper(const std::vector<std::string>& args)
{
    HelperResult r;
    std::vector<std::string> argv{Helper()};
    argv.insert(argv.end(), args.begin(), args.end());
    std::vector<char*> cargv;
    for (auto& a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
    cargv.push_back(nullptr);
    const long maxfd = OpenFdLimit();
    int fd[2];
    pid_t pid;
    {
        std::lock_guard<std::mutex> sg(SpawnMutex());  // no other child inherits this pipe (N-A5)
        if (!PipeCloexec(fd)) { r.line = "pipe failed"; return r; }
        pid = fork();
    }
    if (pid < 0) { close(fd[0]); close(fd[1]); r.line = "fork failed"; return r; }
    if (pid == 0) {
        setpgid(0, 0);
        dup2(fd[1], 1);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) dup2(devnull, 2);
        CloseFdsFrom(3, maxfd);
        execve(cargv[0], cargv.data(), environ);
        _exit(127);
    }
    close(fd[1]);
    // Round 3: at connect time a leaf proof check (and the registry root) gets the timeout it already
    // gets as a mempool candidate (at least 120 s, at most -yugenverifytimeout), since relay depends on
    // it anyway; a bundle (System B root verification) and the note-tree root keep the full timeout.
    int64_t timeout = GetArg("-yugenverifytimeout", 600);
    if (g_timeoutOverride > 0) timeout = g_timeoutOverride;
    else if (!args.empty() && (args[0] == "verify" || args[0] == "regroot"))
        timeout = std::min(timeout, std::max<int64_t>(GetArg("-yugenmempoolverifytimeout", DEFAULT_MEMPOOL_VERIFY_TIMEOUT), 120));
    const int64_t deadline = GetTimeMillis() + 1000 * timeout;
    bool timedOut = false;
    char buf[4096];
    for (;;) {
        int64_t left = deadline - GetTimeMillis();
        if (left <= 0) { timedOut = true; break; }
        struct pollfd p{fd[0], POLLIN, 0};
        int n = poll(&p, 1, (int)std::min<int64_t>(left, 1000));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) break;
        if (n == 0) continue;
        ssize_t k = read(fd[0], buf, sizeof(buf));
        if (k <= 0) break;
        r.all.append(buf, k);
    }
    close(fd[0]);
    if (timedOut) kill(-pid, SIGKILL);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    size_t nl = r.all.find('\n');
    r.line = r.all.substr(0, nl);
    if (timedOut) { r.line = "timeout"; return r; }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) r.kind = HelperResult::OK;
    else if (WIFEXITED(status) && WEXITSTATUS(status) == HELPER_EXIT_REJECT && r.line.rfind("REJECT ", 0) == 0) r.kind = HelperResult::REJECT;
    if (r.kind != HelperResult::OK) LogPrint("yugen", "yugen: helper %s: exit %d: %s\n", args.empty() ? "" : args[0],
                                             WIFEXITED(status) ? WEXITSTATUS(status) : -1, r.line.substr(0, 200));
    return r;
}

static Root ParseRoot(const std::string& hex)
{
    Root r{};
    auto b = ParseHex(hex);
    if (b.size() != 48) throw std::runtime_error("yugen: helper returned no 48-byte root: '" + hex + "' (is -yugenverifier set?)");
    std::copy(b.begin(), b.end(), r.begin());
    return r;
}

// The note-tree root through the helper: the whole commitment list, one helper run (open: the
// review's incremental frontier, doc/yugen-node.md M-4). Run only when a block is applied for good
// or replayed, never for a trial (mempool candidate, template, fJustCheck), whose root nothing reads.
static Root ComputeRoot(const std::vector<std::array<uint8_t, 48>>& cms)
{
    if (cms.empty() && g_rootCanaryOnly) return *g_rootCanaryOnly;
    fs::path p = TmpDir() / "cms.txt";
    {
        std::ofstream o(p.string());
        for (const auto& c : cms) o << HexStr(c.begin(), c.end()) << "\n";
    }
    auto hr = RunHelper({"root", p.string()});
    const std::string& out = hr.line;
    size_t sp = out.find(' ');
    if (hr.kind != HelperResult::OK || sp == std::string::npos) throw std::runtime_error("yugen: root helper failed: " + out);
    Root r = ParseRoot(out.substr(sp + 1));
    if (cms.empty()) g_rootCanaryOnly = r;
    return r;
}

static std::string RegRoot()
{
    if (!g_regRoot) {
        auto hr = RunHelper({"regroot"});
        if (hr.kind != HelperResult::OK || hr.line.size() != 96) throw std::runtime_error("yugen: regroot helper failed");
        g_regRoot = hr.line;
    }
    return *g_regRoot;
}

bool HelperAvailable()
{
    try { RegRoot(); return true; } catch (const std::exception&) { return false; }
}

static int ActivationHeight(const CChainParams& params)
{
    return params.GetConsensus().vUpgrades[Consensus::UPGRADE_YUGEN].nActivationHeight;
}

static int NetworkByte(const CChainParams& params)
{
    return params.NetworkIDString() == CBaseChainParams::MAIN ? 0 : params.NetworkIDString() == CBaseChainParams::REGTEST ? 2 : 1;
}

// §7.9 rules 5 and 6 through the helper.
static HelperResult VerifyProofs(const CTransaction& tx, const Transfer& t, int h, int ha,
                                               const Root& anchorRoot, const uint256& anchorHash,
                                               const CChainParams& params)
{
    CDataStream vout(SER_NETWORK, PROTOCOL_VERSION);
    vout << tx.vout;
    const auto& consensus = params.GetConsensus();
    int net = NetworkByte(params);
    std::string doc = strprintf(
        "{\"branch_id\":%u,\"network\":%d,\"anchor_height\":%d,\"anchor_root\":\"%s\",\"anchor_block_hash\":\"%s\","
        "\"reg_root\":\"%s\",\"vout\":\"%s\",\"auth_mode\":0,\"transfer\":\"%s\",\"proof_a\":\"%s\",\"proof_b\":\"%s\"}",
        CurrentEpochBranchId(h, consensus), net, ha, HexRoot(anchorRoot), HexStr(anchorHash.begin(), anchorHash.end()),
        RegRoot(), HexStr(vout.begin(), vout.end()), HexStr(tx.yugen.transfer), HexStr(tx.yugen.proofA), HexStr(tx.yugen.proofB));
    uint256 key = Hash(doc.begin(), doc.end());
    if (g_verified.count(key)) return HelperResult{HelperResult::OK, "ACCEPT", ""};
    fs::path p = TmpDir() / (key.GetHex() + ".json");
    {
        std::ofstream o(p.string());
        o << doc;
    }
    int64_t t0 = GetTimeMillis();
    auto hr = RunHelper({"verify", p.string()});
    fs::remove(p);
    LogPrint("yugen", "yugen: verify %s: %s (%d ms)\n", tx.GetHash().ToString(), hr.line, GetTimeMillis() - t0);
    if (hr.kind == HelperResult::OK && hr.line != "ACCEPT") hr.kind = HelperResult::FAIL;
    if (hr.kind == HelperResult::OK && g_verified.insert(key).second) {
        g_verifiedOrder.push_back(key);
        while (g_verifiedOrder.size() > VERIFIED_MAX) { g_verified.erase(g_verifiedOrder.front()); g_verifiedOrder.pop_front(); }
    }
    return hr;
}

// ------------------------------------------------------------------ proof store (sidecar data)

// An in-memory cache of the proof store (bounded, review M-4); the files are the store.
static BoundedMap<uint256, std::vector<std::vector<unsigned char>>> g_proofs(PROOF_CACHE_MAX);

static fs::path ProofPath(const uint256& txid) { return GetDataDir() / "yugen" / "proofs" / (txid.GetHex() + ".bin"); }

static std::optional<std::vector<std::vector<unsigned char>>> ReadProofFile(const fs::path& path)
{
    CAutoFile f(fsbridge::fopen(path, "rb"), SER_DISK, CLIENT_VERSION);
    if (f.IsNull()) return std::nullopt;
    std::vector<std::vector<unsigned char>> v;
    try { f >> v; } catch (const std::exception&) { return std::nullopt; }
    return v;
}

void PutProofs(const uint256& txid, const std::vector<std::vector<unsigned char>>& proofs)
{
    if (const auto* p = g_proofs.get(txid); p && *p == proofs) return;
    g_proofs.put(txid, proofs);
    // Round 3: a file that already holds these proofs is not written again.
    if (auto onDisk = ReadProofFile(ProofPath(txid)); onDisk && *onDisk == proofs) return;
    fs::create_directories(ProofPath(txid).parent_path());
    CAutoFile f(fsbridge::fopen(ProofPath(txid), "wb"), SER_DISK, CLIENT_VERSION);
    if (!f.IsNull()) f << proofs;
}

std::optional<std::vector<std::vector<unsigned char>>> GetProofs(const uint256& txid)
{
    if (const auto* p = g_proofs.get(txid)) return *p;
    CAutoFile f(fsbridge::fopen(ProofPath(txid), "rb"), SER_DISK, CLIENT_VERSION);
    if (f.IsNull()) return std::nullopt;
    std::vector<std::vector<unsigned char>> v;
    try { f >> v; } catch (const std::exception&) { return std::nullopt; }
    g_proofs.put(txid, v);
    return v;
}

static fs::path SidecarPath(const uint256& block) { return GetDataDir() / "yugen" / "proofs" / ("blk-" + block.GetHex() + ".bin"); }

void DropSidecar(const uint256& block)
{
    boost::system::error_code ec;
    fs::remove(SidecarPath(block), ec);
}

// The sidecar's structure against its block: one entry per bundle transaction of the block at most,
// each with two proofs. (Which proofs they are is checked by their hashes when the block connects.)
static bool SidecarFits(const CBlock& block)
{
    std::set<uint256> bundles, seen;
    for (const auto& tx : block.vtx) if (tx.IsYugenBundle()) bundles.insert(tx.GetHash());
    for (const auto& e : block.vYugenProofs)
        if (!bundles.count(e.txid) || !seen.insert(e.txid).second || e.proofs.size() != 2) return false;
    return true;
}

void SaveSidecar(const CBlock& block, int height, const Consensus::Params& consensus)
{
    // Before UPGRADE_YUGEN a block has no sidecar: trailing bytes are never stored or re-served.
    if (!consensus.NetworkUpgradeActive(height, Consensus::UPGRADE_YUGEN)) return;
    // Review C-2: the copy being stored replaces whatever an earlier copy of this block left (a body
    // reset deletes it too, DropSidecar); a copy without a sidecar leaves none.
    DropSidecar(block.GetHash());
    if (block.vYugenProofs.empty()) return;
    fs::create_directories(SidecarPath(block.GetHash()).parent_path());
    CAutoFile f(fsbridge::fopen(SidecarPath(block.GetHash()), "wb"), SER_DISK, CLIENT_VERSION);
    if (!f.IsNull()) f << block.vYugenProofs;
}

static std::optional<std::vector<YugenProofEntry>> ReadSidecarFile(const uint256& block)
{
    CAutoFile f(fsbridge::fopen(SidecarPath(block), "rb"), SER_DISK, CLIENT_VERSION);
    if (f.IsNull()) return std::nullopt;
    std::vector<YugenProofEntry> v;
    try { f >> v; } catch (const std::exception&) { return std::nullopt; }
    return v;
}

void AttachSidecar(CBlock& block)
{
    block.vYugenProofs.clear();
    {
        CAutoFile f(fsbridge::fopen(SidecarPath(block.GetHash()), "rb"), SER_DISK, CLIENT_VERSION);
        if (!f.IsNull()) {
            // Low (review): a stored sidecar is preferred only when it fits the block; else the proof store.
            try { f >> block.vYugenProofs; } catch (const std::exception&) { block.vYugenProofs.clear(); }
            if (!block.vYugenProofs.empty() && SidecarFits(block)) return;
            block.vYugenProofs.clear();
        }
    }
    for (const auto& tx : block.vtx) {
        if (!tx.IsYugenBundle()) continue;
        if (auto p = GetProofs(tx.GetHash())) block.vYugenProofs.push_back({tx.GetHash(), *p});
    }
}

uint64_t TxProofBytes(const CTransaction& tx)
{
    if (!tx.IsYugenBundle()) return 0;
    uint64_t n = 0;
    if (auto p = GetProofs(tx.GetHash())) for (const auto& x : *p) n += x.size();
    return n;
}

// ------------------------------------------------------------------ bundles (§15.6)

struct AnchorEntry { uint8_t slot; Root root; Root reg; uint256 blockHash; };

static std::vector<AnchorEntry> BundleAnchors(const CTransaction& tx)
{
    std::vector<AnchorEntry> out;
    const auto& b = tx.yugen.transfer;
    if (b.size() < 2) return out;
    for (size_t i = 0, o = 2; i < b[1] && o + 129 <= b.size(); i++, o += 129) {
        AnchorEntry e;
        e.slot = b[o];
        std::copy(b.begin() + o + 1, b.begin() + o + 49, e.root.begin());
        std::copy(b.begin() + o + 49, b.begin() + o + 97, e.reg.begin());
        std::copy(b.begin() + o + 97, b.begin() + o + 129, e.blockHash.begin());
        out.push_back(e);
    }
    return out;
}

struct Pay {
    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> records;   // claimed, preorder
    std::string stmt;                                                       // bstmt hex
    std::vector<std::array<uint8_t, 48>> hashes;                            // transfer hashes, list order (§7.3)
};

// ------------------------------------------------------------------ VB records (§15.1, §15.5; spec 0.5.4)

// §3: H_dom over `parts` (SHAKE256 after the 4-byte prefix "Yg" 0x00 id), 32 bytes; Hvar prefixes LE64(len).
static uint256 YugenHash(uint8_t dom, const std::vector<std::vector<unsigned char>>& parts)
{
    shake256incctx c;
    shake256_inc_init(&c);
    const uint8_t prefix[4] = {'Y', 'g', 0x00, dom};
    shake256_inc_absorb(&c, prefix, 4);
    for (const auto& p : parts) shake256_inc_absorb(&c, p.data(), p.size());
    shake256_inc_finalize(&c);
    uint256 out;
    shake256_inc_squeeze(out.begin(), 32, &c);
    shake256_inc_ctx_release(&c);
    return out;
}
static std::vector<unsigned char> LE(uint64_t v, size_t n)
{
    std::vector<unsigned char> b(n);
    for (size_t i = 0; i < n; i++) b[i] = (v >> (8 * i)) & 0xff;
    return b;
}
static uint256 YugenHashVar(uint8_t dom, const std::vector<unsigned char>& data) { return YugenHash(dom, {LE(data.size(), 8), data}); }
static const uint8_t DOM_DEP_PREVOUTS = 0x87, DOM_DEP_SCRIPT = 0x88, DOM_DEP_SIG = 0x89;

uint256 DepositSighash(uint32_t branchId, uint8_t network, const std::array<uint8_t, 48>& transferHash,
                       const std::vector<COutPoint>& prevouts, uint32_t k, uint64_t amount,
                       const std::vector<unsigned char>& scriptCode)
{
    auto outpoint = [](const COutPoint& p) {
        std::vector<unsigned char> b(p.hash.begin(), p.hash.end());
        auto n = LE(p.n, 4);
        b.insert(b.end(), n.begin(), n.end());
        return b;
    };
    std::vector<unsigned char> all;
    for (const auto& p : prevouts) { auto b = outpoint(p); all.insert(all.end(), b.begin(), b.end()); }
    const uint256 ph = YugenHashVar(DOM_DEP_PREVOUTS, all), sh = YugenHashVar(DOM_DEP_SCRIPT, scriptCode);
    return YugenHash(DOM_DEP_SIG, {LE(branchId, 4), {network}, std::vector<unsigned char>(transferHash.begin(), transferHash.end()),
                                   std::vector<unsigned char>(ph.begin(), ph.end()), LE(k, 4), outpoint(prevouts[k]), LE(amount, 8),
                                   std::vector<unsigned char>(sh.begin(), sh.end())});
}

// §15.5: input k of a deposit, verified by the interpreter with every signature check signing
// dep_sighash under hash type SIGHASH_ALL only; sequence 0xffffffff and lock time 0, so
// CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY fail; the vault opcodes see no set.
class DepositSignatureChecker : public BaseSignatureChecker
{
    uint8_t network;
    const std::array<uint8_t, 48>& transferHash;
    const std::vector<COutPoint>& prevouts;
    uint32_t k;
    uint64_t amount;
    bool Digest(std::vector<unsigned char>& sig, const CScript& scriptCode, uint32_t branchId, uint256& out) const
    {
        if (sig.empty() || sig.back() != SIGHASH_ALL) return false;
        sig.pop_back();
        out = DepositSighash(branchId, network, transferHash, prevouts, k, amount,
                             std::vector<unsigned char>(scriptCode.begin(), scriptCode.end()));
        return true;
    }
public:
    DepositSignatureChecker(uint8_t networkIn, const std::array<uint8_t, 48>& th, const std::vector<COutPoint>& p, uint32_t kIn, uint64_t a)
        : network(networkIn), transferHash(th), prevouts(p), k(kIn), amount(a) {}
    bool CheckSig(const std::vector<unsigned char>& sigIn, const std::vector<unsigned char>& pubKey, const CScript& scriptCode,
                  uint32_t branchId) const override
    {
        CPubKey pk(pubKey);
        std::vector<unsigned char> sig(sigIn);
        uint256 d;
        return pk.IsValid() && Digest(sig, scriptCode, branchId, d) && pk.Verify(d, sig);
    }
    bool CheckPQSig(uint8_t scheme, const std::vector<unsigned char>& sigIn, const std::vector<unsigned char>& pubKey,
                    const CScript& scriptCode, uint32_t branchId) const override
    {
        std::vector<unsigned char> sig(sigIn);
        uint256 d;
        return Digest(sig, scriptCode, branchId, d) && pq::Verify(scheme, pubKey, sig, d);
    }
};

std::vector<bool> UndoMask(const CTxUndo& undo)
{
    std::vector<bool> m;
    if (undo.vprevout.empty()) return m;
    const CScript& s = undo.vprevout[0].txout.scriptPubKey;
    if (s.empty() || s[0] != OP_RETURN) return m;
    for (auto it = s.begin() + 1; it != s.end(); ++it) m.push_back(*it != 0);
    return m;
}

std::vector<CTxOut> RecordOutputs(const CTransaction& tx, const std::vector<bool>& applied)
{
    std::vector<CTxOut> out;
    const auto ts = tx.GetYugenTransfers();
    for (size_t i = 0; i < ts.size(); i++)
        for (const auto& o : ts[i].vout)
            out.push_back(i < applied.size() && applied[i] ? CTxOut((CAmount)o.value, CScript(o.script.begin(), o.script.end())) : CTxOut());
    return out;
}

static COutPoint Prevout(const RecordIn& in)
{
    uint256 h;
    std::copy(in.txid.begin(), in.txid.end(), h.begin());
    return COutPoint(h, in.index);
}

std::vector<COutPoint> RecordPrevouts(const CTransaction& tx, const std::vector<bool>& applied)
{
    std::vector<COutPoint> out;
    const auto ts = tx.GetYugenTransfers();
    for (size_t i = 0; i < ts.size() && i < applied.size(); i++)
        if (applied[i]) for (const auto& in : ts[i].vin) out.push_back(Prevout(in));
    return out;
}

// The script flags in force at height h (main.cpp ConnectBlock's).
static unsigned int ConsensusScriptFlags(int h, const Consensus::Params& consensus)
{
    return SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | GetVaultScriptFlags(h, consensus);
}

static bool Ensure(const CBlockIndex* pindex, const CChainParams& params, std::string& err);

// The transfer's own failures of the bundle, skipped or not, as pure functions of the transfer (the reject
// reason, or nullptr): B6 first, a withdrawal above the window's gross cap K (§13.3.5); then N-D12, a
// record output the vault primitive or the YED module would read (an act, a V- or I-shaped script):
// neither sees record outputs, so it pays by a leaf. ConnectBundleCoins's pre-scan and its loop both
// decide by this one function, so the deposits the module is asked about are exactly those the loop
// can reach.
static const char* BundleFailure(const Transfer& t, uint64_t K)
{
    if (t.valueBalance > 0 && (uint64_t)t.valueBalance > K) return "bad-yugen-bundle-withdrawal-above-k";
    for (const auto& o : t.vout) {
        const CScript spk(o.script.begin(), o.script.end());
        vault::VaultParams vp;
        vault::IntentParams ip;
        if (vault::IsActOutput(spk) || vault::MatchVault(spk, vp) != vault::Shape::NONE || vault::MatchIntent(spk, ip) != vault::Shape::NONE)
            return "bad-yugen-bundle-record-output";
    }
    return nullptr;
}

ModuleAnswer (*g_moduleTracks)(const std::vector<COutPoint>& outs, const CBlockIndex* pprev, std::vector<bool>& tracked) = nullptr;

bool ConnectBundleCoins(const CTransaction& tx, CCoinsViewCache& view, CTxUndo& undo, const CBlockIndex* pindex,
                        const CChainParams& params, unsigned int flags, BlockCoins& bc, CAmount& transparentDelta,
                        CValidationState& state, const std::vector<bool>* recorded)
{
    if (!tx.IsYugen()) return true;
    const auto ts = tx.GetYugenTransfers();
    if (!tx.IsYugenBundle()) {
        for (const auto& t : ts) { for (const auto& nf : t.nf) bc.nfs.insert(nf); bc.debited += t.TransparentDelta(); }
        return true;
    }
    std::string err;
    // A refused field (CheckLeafTransferStructure) or a state fault: ConnectBlock reports it.
    if (ts.empty() || !Ensure(pindex->pprev, params, err)) return true;
    const int h = pindex->nHeight;
    const int act = ActivationHeight(params);
    const uint64_t K = GrossCap(h, act), cap = ValueCap(h, act);
    BundleCoins& out = bc.bundles[tx.GetHash()];
    out = BundleCoins();
    out.flags = flags;
    // N-D12: the module's answer for the deposit coins, asked once (one lock, one tip read). Only a deposit
    // that can reach the module's test below is asked: one before the first transfer that fails the bundle
    // (B6's K, a record output: pure functions of the transfer), whose nullifiers are unspent and whose every
    // coin exists, is unspent, mature and older than this block in the view as it stands. The loop only
    // spends coins and adds nullifiers, so a deposit left out here is skipped (or never reached) below
    // whatever the module says, and the decisions are those of asking for every coin; a peer's deposits of
    // missing outpoints cost a coins lookup each, not four module lookups.
    const size_t NOT_ASKED = (size_t)-1;
    std::vector<COutPoint> asked;
    std::vector<size_t> askedAt(ts.size(), NOT_ASKED);   // a deposit's first coin's position in `asked`
    for (size_t j = 0; j < ts.size(); j++) {
        const auto& t = ts[j];
        if (BundleFailure(t, K)) break;
        if (t.valueBalance >= 0) continue;
        bool eligible = true;
        for (const auto& nf : t.nf) if (g_state.nullifiers.count(nf) || bc.nfs.count(nf)) eligible = false;
        for (size_t k = 0; eligible && k < t.vin.size(); k++) {
            const COutPoint p = Prevout(t.vin[k]);
            const CCoins* c = view.AccessCoins(p.hash);
            if (!c || !c->IsAvailable(p.n) || (c->IsCoinBase() && h - c->nHeight < COINBASE_MATURITY) || c->nHeight >= h) eligible = false;
        }
        if (!eligible) continue;
        askedAt[j] = asked.size();
        for (const auto& in : t.vin) asked.push_back(Prevout(in));
    }
    std::vector<bool> tracked(asked.size(), false);
    ModuleAnswer answer = ModuleAnswer::KNOWN;
    if (g_moduleTracks && !asked.empty()) answer = g_moduleTracks(asked, pindex->pprev, tracked);
    if (answer == ModuleAnswer::KNOWN && tracked.size() != asked.size()) answer = ModuleAnswer::UNKNOWN;
    std::vector<CTxInUndo> spent;
    for (size_t j = 0; j < ts.size(); j++) {
        const auto& t = ts[j];
        // B6's K and N-D12's record outputs fail the bundle, skipped or not (BundleFailure).
        if (const char* why = BundleFailure(t, K)) return state.DoS(100, false, REJECT_INVALID, why);
        // S1: a nullifier spent on chain, earlier in the block or earlier in this bundle.
        bool skip = false;
        for (const auto& nf : t.nf) if (g_state.nullifiers.count(nf) || bc.nfs.count(nf)) skip = true;
        // S2: a deposit input that is not an unspent output spendable at h (on this line: coinbase maturity);
        // N-D12: or one created in this block, or one the YED module tracks after the parent (a token, a
        // vault, an intent, a bond: the module reads tx.vin only). A coin of this block is skipped whatever
        // it is, so the module's state at the parent decides every other coin exactly.
        if (!skip && t.valueBalance < 0) {
            bool moduleAsked = false;
            for (size_t k = 0; k < t.vin.size(); k++) {
                const COutPoint p = Prevout(t.vin[k]);
                const CCoins* c = view.AccessCoins(p.hash);
                if (!c || !c->IsAvailable(p.n) || (c->IsCoinBase() && h - c->nHeight < COINBASE_MATURITY)) { skip = true; break; }
                if (c->nHeight >= h) { skip = true; break; }
                if (answer == ModuleAnswer::KNOWN) { if (askedAt[j] != NOT_ASKED && tracked[askedAt[j] + k]) { skip = true; break; } }
                else moduleAsked = true;
            }
            // The module could not answer: a re-verified active-chain block takes the decision its undo
            // entry recorded (every other S2 cause is re-decided above, so a skip recorded here was the
            // module's); anything else is a local failure, never a verdict on the block.
            if (!skip && moduleAsked) {
                if (recorded == nullptr || j >= recorded->size())
                    return state.Error("yugen-module-unknown: the YED module cannot say which deposit coins it tracks (its index is stopped, unhealthy or not at the parent)");
                skip = !(*recorded)[j];
            }
        }
        // S3: a deposit that would take B above cap(h) (§13.3.6), B as the earlier transfers left it.
        if (!skip && t.valueBalance < 0 && g_state.balance - bc.debited - t.TransparentDelta() > (CAmount)cap) skip = true;
        out.applied.push_back(!skip);
        out.spent.emplace_back();
        if (skip) continue;
        bc.debited += t.TransparentDelta();
        for (const auto& nf : t.nf) bc.nfs.insert(nf);
        if (t.valueBalance >= 0) continue;
        // B6, a deposit: each coin P2PKH or TX_PQPKH (§15.5), the values balancing exactly; then spent.
        unsigned __int128 in = 0, owed = (unsigned __int128)(uint64_t)(-t.valueBalance);
        for (const auto& o : t.vout) owed += o.value;
        for (const auto& i : t.vin) {
            const COutPoint p = Prevout(i);
            CCoinsModifier coins = view.ModifyCoins(p.hash);
            const CTxOut prev = coins->vout[p.n];
            if (!DepositScriptOk(std::vector<unsigned char>(prev.scriptPubKey.begin(), prev.scriptPubKey.end())))
                return state.DoS(100, false, REJECT_INVALID, "bad-yugen-bundle-deposit-coin");
            in += (uint64_t)prev.nValue;
            out.spent.back().push_back(prev);
            CTxInUndo u(prev);
            coins->Spend(p.n);
            if (coins->vout.size() == 0) { u.nHeight = coins->nHeight; u.fCoinBase = coins->fCoinBase; u.nVersion = coins->nVersion; }
            spent.push_back(u);
            transparentDelta -= prev.nValue;
        }
        if (in != owed) return state.DoS(100, false, REJECT_INVALID, "bad-yugen-bundle-deposit-balance");
    }
    // §15.5: the outputs at the bundle's txid, indexed across every record in list order; a skipped
    // transfer's are never created (null).
    std::vector<CTxOut> outs = RecordOutputs(tx, out.applied);
    for (const auto& o : outs) if (!o.IsNull()) transparentDelta += o.nValue;
    {
        CCoinsModifier c = view.ModifyCoins(tx.GetHash());
        c->fCoinBase = false;
        c->nVersion = tx.nVersion;
        c->nHeight = h;
        c->vout = outs;
        c->ClearUnspendable();
    }
    // B9: the applied mask (an OP_RETURN entry of one byte per transfer), then the coins spent.
    std::vector<unsigned char> m{OP_RETURN};
    for (bool a : out.applied) m.push_back(a ? 1 : 0);
    undo.vprevout.clear();
    undo.vprevout.push_back(CTxInUndo(CTxOut(0, CScript(m.begin(), m.end()))));
    undo.vprevout.insert(undo.vprevout.end(), spent.begin(), spent.end());
    return true;
}

// The decisions for Yugen transactions against the tip's coins (a mempool candidate, a template), in
// the order given: spends within the list are seen by later entries; nothing is written.
static bool CoinsAtTip(const std::vector<CTransaction>& vtx, const CBlockIndex* tip, const CChainParams& params,
                       BundleCoinsMap& out, CValidationState& state)
{
    CCoinsViewCache view(pcoinsTip);
    CBlockIndex next;
    next.pprev = const_cast<CBlockIndex*>(tip);
    next.nHeight = tip->nHeight + 1;
    BlockCoins bc;
    const unsigned int flags = ConsensusScriptFlags(next.nHeight, params.GetConsensus());
    for (const auto& tx : vtx) {
        CTxUndo undo;
        CAmount d = 0;
        if (!ConnectBundleCoins(tx, view, undo, &next, params, flags, bc, d, state)) return false;
    }
    out = std::move(bc.bundles);
    return true;
}

// TEST-ONLY stub bundle proofs: regtest only, whatever the startup checks (init.cpp refuses the
// option elsewhere too).
static bool StubProofs()
{
    return Params().NetworkIDString() == CBaseChainParams::REGTEST && GetBoolArg("-yugenteststubproofs", false);
}

// B1, B3 to B5 (and B8's pay for the applied mask) through the helper. `applied` empty: all
// applied, proofs checked; else proofs not checked (they were, for the same bytes) and the pay is
// for the mask. Cached by everything but the height (the resolved anchor heights stand for it).
static BoundedMap<uint256, Pay> g_bundleOk(BUNDLE_OK_MAX);   // bounded (review M-4)

static HelperResult BundleHelper(const CTransaction& tx, const std::vector<std::vector<unsigned char>>& proofs,
                                 int h, const std::vector<int>& anchorHeights, const std::vector<bool>& applied,
                                 const CChainParams& params, Pay& pay)
{
    const auto& consensus = params.GetConsensus();
    std::string mask;
    for (size_t i = 0; i < applied.size(); i++) mask += std::string(i ? "," : "") + (applied[i] ? "true" : "false");
    // Round 3: the verifier configuration (-yugenb2verify, -yugenbplan) is part of the context.
    std::string key_doc = strprintf("%s|%s|%s|%u|%d|%d|%d|%s|%s|%s",
        HexStr(tx.yugen.transfer), HexStr(proofs[0]), HexStr(proofs[1]), CurrentEpochBranchId(h, consensus),
        NetworkByte(params), ActivationHeight(params), StubProofs(), mask, GetArg("-yugenb2verify", ""),
        GetArg("-yugenbplan", ""));
    for (int ha : anchorHeights) key_doc += strprintf("|%d", ha);
    uint256 key = Hash(key_doc.begin(), key_doc.end());
    // A bundle verified once (mempool, template) is not verified again when its block connects: the key
    // is the bundle's committed bytes (roots, block hashes, proof hashes), both proofs and the context.
    if (const Pay* p = g_bundleOk.get(key)) {
        LogPrint("yugen", "yugen: bundle %s: verified before (cached)\n", tx.GetHash().ToString());
        pay = *p;
        return {HelperResult::OK, "ACCEPT", ""};
    }
    std::string doc = strprintf(
        "{\"bundle\":\"%s\",\"proof_a\":\"%s\",\"proof_b\":\"%s\",\"branch_id\":%u,\"network\":%d,\"height\":%d,"
        "\"activation\":%d,\"mode\":0,\"stub\":%s,\"check_proofs\":%s,\"b2verify\":\"%s\",\"b_plan\":\"%s\"%s}",
        HexStr(tx.yugen.transfer), HexStr(proofs[0]), HexStr(proofs[1]), CurrentEpochBranchId(h, consensus),
        NetworkByte(params), h, ActivationHeight(params), StubProofs() ? "true" : "false", applied.empty() ? "true" : "false",
        GetArg("-yugenb2verify", ""), GetArg("-yugenbplan", ""), applied.empty() ? "" : ",\"applied\":[" + mask + "]");
    fs::path p = TmpDir() / (key.GetHex() + ".json");
    { std::ofstream o(p.string()); o << doc; }
    int64_t t0 = GetTimeMillis();
    auto hr = RunHelper({"bundle", p.string()});
    fs::remove(p);
    LogPrint("yugen", "yugen: bundle %s: %s (%d ms)\n", tx.GetHash().ToString(), hr.line.substr(0, 120), GetTimeMillis() - t0);
    if (hr.kind == HelperResult::REJECT) {
        // `REJECT {"proofs_bound":b,"reason":r}`: a verdict on the block only when bound (review H-1).
        UniValue rj;
        hr.proofsBound = rj.read(hr.line.substr(7)) && rj.isObject() && rj["proofs_bound"].isBool() && rj["proofs_bound"].get_bool();
    }
    if (hr.kind != HelperResult::OK) return hr;
    UniValue v;
    if (hr.line.rfind("ACCEPT ", 0) != 0 || !v.read(hr.line.substr(7)) || !v["records"].isArray()) {
        hr.kind = HelperResult::FAIL;
        return hr;
    }
    pay.records.clear();
    for (const auto& r : v["records"].getValues())
        pay.records.emplace_back(ParseHex(r["script"].get_str()), (uint64_t)r["pay"].get_int64());
    if (v["stmt"].isStr()) pay.stmt = v["stmt"].get_str();
    pay.hashes.clear();
    if (v["transfers"].isArray())
        for (const auto& t : v["transfers"].getValues()) {
            const auto th = t["transfer_hash"].isStr() ? ParseHex(t["transfer_hash"].get_str()) : std::vector<unsigned char>();
            if (th.size() != 48) { pay.hashes.clear(); break; }
            pay.hashes.emplace_back();
            std::copy(th.begin(), th.end(), pay.hashes.back().begin());
        }
    g_bundleOk.put(key, pay);
    return hr;
}

std::optional<std::string> BundleStatement(const CTransaction& tx, int h, const std::vector<bool>& applied,
                                           const CChainParams& params)
{
    // RPC only (B-RPC-2): bstmt through the helper with proofs unchecked (they were when the block
    // connected); the mask is always given, so the cached entry is never mistaken for a proof check.
    if (!tx.IsYugenBundle() || applied.empty()) return std::nullopt;
    int act = ActivationHeight(params);
    std::vector<int> heights;
    for (const auto& e : BundleAnchors(tx)) heights.push_back(ResolveAnchor(e.slot, h, act));
    std::vector<std::vector<unsigned char>> proofs{{}, {}};
    if (auto p = GetProofs(tx.GetHash()); p && p->size() == 2) proofs = *p;
    Pay pay;
    auto hr = BundleHelper(tx, proofs, h, heights, applied, params, pay);
    if (hr.kind != HelperResult::OK || pay.stmt.empty()) return std::nullopt;
    return pay.stmt;
}

// Applies a block's Yugen transfers to `s` (at height h, parent pprev). verify=false on a rebuild
// (proofs, sidecar, weight and coinbase were checked when the block was first connected).
// `res` gets the fees of transfers skipped under §15.6 S1 and the record run.
// `coins`: each bundle's S1/S2 decisions where it stands (ConnectBundleCoins, CoinsAtTip, or a replayed
// block's undo data), and with verify the coins its applied deposits spent.
static bool ApplyBlockInner(PoolState& s, BlockRecord& rec, const CBlock& block, int h, const CBlockIndex* pprev,
                            const CChainParams& params, bool verify, bool trial, CValidationState& state, BlockResult* res,
                            const BundleCoinsMap& coins)
{
    const int act = ActivationHeight(params);
    const uint64_t K = GrossCap(h, act), cap = ValueCap(h, act);   // §13.3.5, §13.3.6
    rec.treeSizeBefore = (h == act ? 0 : 1) + s.cms.size();
    rec.hash = block.GetHash();
    rec.balanceBefore = s.balance;
    size_t before = s.cms.size();
    // §13.3.2 turnstile: B after each transaction stays in [0, MAX_MONEY]. Version 0 seeds B with
    // CANARY_VALUE at activation; the funded canary is not built on this line (§13.2), so B starts
    // at 0 and withdrawals are bounded by deposits (decision N-D6, doc/yugen-node.md).
    auto debit = [&](CAmount d) {
        CAmount nb = s.balance - d;
        if (nb < 0 || nb > MAX_MONEY) return false;
        s.balance = nb;
        return true;
    };
    std::set<std::array<uint8_t, 32>> blockNfs;
    std::vector<Pay> pays;                     // per bundle, block order
    uint64_t w5Weight = 0, w5Bytes = 0, sidecarBytes = 0;
    size_t sidecarUsed = 0;
    auto fail = [&](const std::string& why) {
        return state.Error("yugen-verifier-failed: " + why);   // never a verdict on the block (review H-1)
    };
    for (const CTransaction& tx : block.vtx) {
        if (!tx.IsYugen()) continue;
        if (tx.IsYugenBundle()) {
            std::vector<Transfer> ts;
            std::vector<uint8_t> slots;
            std::vector<std::vector<unsigned char>> raw;
            std::string why;
            if (!DecodeBundleTransfers(tx.yugen.transfer, ts, slots, why, &raw) || ts.empty())
                return state.DoS(100, false, REJECT_INVALID, "bad-yugen-" + why);
            // B2: every table slot resolves at h and names this chain's roots and block hash.
            std::vector<int> heights;
            for (const auto& e : BundleAnchors(tx)) {
                int ha = ResolveAnchor(e.slot, h, act);
                if (ha < 0 || !s.blocks.count(ha)) return state.DoS(100, false, REJECT_INVALID, "bad-yugen-bundle-anchor");
                const CBlockIndex* ai = pprev->GetAncestor(ha);
                if (!ai || e.root != s.blocks.at(ha).rootAfter || HexStr(e.reg.begin(), e.reg.end()) != RegRoot() ||
                    e.blockHash != ai->GetBlockHash())
                    return state.DoS(100, false, REJECT_INVALID, "bad-yugen-bundle-anchor-root");
                heights.push_back(ha);
            }
            // B6: a withdrawal above K fails the bundle; S1 here; a deposit's S2 and S3 as decided where
            // the bundle stands (`coins`), which must agree with S1 for every transfer and with S3 for
            // every applied deposit. B7.
            for (const auto& t : ts)
                if (t.valueBalance > 0 && (uint64_t)t.valueBalance > K)
                    return state.DoS(100, false, REJECT_INVALID, "bad-yugen-bundle-withdrawal-above-k");
            const auto bcIt = coins.find(tx.GetHash());
            const BundleCoins* bc = bcIt == coins.end() ? nullptr : &bcIt->second;
            if (bc && bc->applied.size() != ts.size()) return state.Error("yugen-bundle-coins: mask length");
            std::vector<bool> applied;
            for (size_t i = 0; i < ts.size(); i++) {
                const Transfer& t = ts[i];
                bool skip = false;
                for (const auto& nf : t.nf) if (s.nullifiers.count(nf) || blockNfs.count(nf)) skip = true;
                if (!skip && t.valueBalance < 0) {
                    if (!bc) return state.Error("yugen-bundle-coins: no decision for a deposit");
                    skip = !bc->applied[i];
                }
                if (bc && bc->applied[i] == skip) return state.Error("yugen-bundle-coins: S1 differs");
                applied.push_back(!skip);
                if (skip) { if (res) res->skippedFees += (CAmount)t.Fee(); continue; }
                for (const auto& nf : t.nf) { blockNfs.insert(nf); s.nullifiers.insert(nf); s.nfHeight[nf] = h; rec.nfsAdded.push_back(nf); }
                for (const auto& cm : t.cm) s.cms.push_back(cm);
                if (!debit(t.TransparentDelta())) return state.DoS(100, false, REJECT_INVALID, "bad-yugen-turnstile");
                if (t.valueBalance < 0 && s.balance > (CAmount)cap) return state.Error("yugen-bundle-coins: S3 differs");
            }
            if (std::find(applied.begin(), applied.end(), true) == applied.end())
                return state.DoS(100, false, REJECT_INVALID, "bad-yugen-bundle-none-applied");
            if (verify) {
                // B5 and §16.2 W1: the sidecar holds this bundle's two proofs (block data, else the proof store).
                std::vector<std::vector<unsigned char>> proofs;
                auto it = std::find_if(block.vYugenProofs.begin(), block.vYugenProofs.end(),
                                       [&](const YugenProofEntry& e) { return e.txid == tx.GetHash(); });
                if (it != block.vYugenProofs.end()) { proofs = it->proofs; sidecarUsed++; }
                else if (auto p = GetProofs(tx.GetHash())) proofs = *p;
                // The sidecar is bound to the block only through the proof hashes in the transactions,
                // so a missing, malformed or substituted proof is body-replaceable, never a verdict on
                // the block (BodyCorruption::Possible).
                else return state.DoS(10, false, REJECT_INVALID, "bad-yugen-bundle-proofs-missing", BodyCorruption::Possible);
                if (proofs.size() != 2) return state.DoS(100, false, REJECT_INVALID, "bad-yugen-bundle-proof-count", BodyCorruption::Possible);
                for (const auto& p : proofs)
                    if (p.empty() || p.size() > PROOF_BYTES_MAX) return state.DoS(100, false, REJECT_INVALID, "bad-yugen-proof-too-long", BodyCorruption::Possible);
                Pay pay;
                auto hr = BundleHelper(tx, proofs, h, heights, {}, params, pay);
                if (hr.kind == HelperResult::FAIL) return fail(hr.line);
                // Review H-1: a refusal is a verdict on the block only when the helper had confirmed
                // that these are the proofs the bundle commits to; any other refusal may be a relay's
                // substitution of sidecar data (body-replaceable).
                if (hr.kind == HelperResult::REJECT && !hr.proofsBound)
                    return state.DoS(100, error("yugen: bundle %s: %s", tx.GetHash().ToString(), hr.line), REJECT_INVALID,
                                     "bad-yugen-bundle-proof-unbound", BodyCorruption::Possible);
                if (hr.kind == HelperResult::REJECT)
                    return state.DoS(100, error("yugen: bundle %s: %s", tx.GetHash().ToString(), hr.line), REJECT_INVALID, "bad-yugen-bundle-proof");
                // B6: script verification of every input of each applied deposit (§15.5), signing the
                // transfer hash the helper computed (B3), against the coins the inputs spent.
                const auto hashes = pay.hashes;
                for (size_t i = 0; i < ts.size(); i++) {
                    if (!applied[i] || ts[i].valueBalance >= 0) continue;
                    if (hashes.size() != ts.size()) return fail("no transfer hashes from the helper");
                    if (bc->spent[i].size() != ts[i].vin.size()) return state.Error("yugen-bundle-coins: spent coins");
                    std::vector<COutPoint> prevouts;
                    for (const auto& in : ts[i].vin) prevouts.push_back(Prevout(in));
                    const unsigned int flags = bc->flags | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_LOW_S |
                                               SCRIPT_VERIFY_SIGPUSHONLY | SCRIPT_VERIFY_MINIMALDATA | SCRIPT_VERIFY_CLEANSTACK;
                    for (uint32_t k = 0; k < prevouts.size(); k++) {
                        const CTxOut& coin = bc->spent[i][k];
                        DepositSignatureChecker checker(NetworkByte(params), hashes[i], prevouts, k, (uint64_t)coin.nValue);
                        ScriptError err;
                        const CScript sig(ts[i].vin[k].scriptSig.begin(), ts[i].vin[k].scriptSig.end());
                        if (!VerifyScript(sig, coin.scriptPubKey, flags, checker, CurrentEpochBranchId(h, params.GetConsensus()), &err))
                            return state.DoS(100, error("yugen: bundle %s: deposit %u input %u: %s", tx.GetHash().ToString(), i, k,
                                                        ScriptErrorString(err)), REJECT_INVALID, "bad-yugen-bundle-deposit-script");
                    }
                }
                if (std::find(applied.begin(), applied.end(), false) != applied.end()) {
                    hr = BundleHelper(tx, proofs, h, heights, applied, params, pay);
                    if (hr.kind != HelperResult::OK) return fail(hr.line);
                }
                if (!trial) PutProofs(tx.GetHash(), proofs);   // round 3: a trial's proofs came from the store
                pays.push_back(pay);
                uint64_t pb = proofs[0].size() + proofs[1].size();
                uint64_t tb = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
                sidecarBytes += pb;
                w5Weight += tb + pb;
                w5Bytes += tb;
            }
            for (size_t i = 0; i < ts.size(); i++) if (applied[i]) rec.transfers.emplace_back(tx.GetHash(), raw[i]);
            continue;
        }
        std::string why;
        auto t = Decode(tx.yugen.transfer, why);
        if (!t) return state.DoS(100, false, REJECT_INVALID, "bad-yugen-transfer-" + why);
        int ha = ResolveAnchor(t->anchorSlot, h, act);
        if (ha < 0 || !s.blocks.count(ha)) return state.DoS(100, false, REJECT_INVALID, "bad-yugen-anchor");
        for (const auto& nf : t->nf) {
            if (s.nullifiers.count(nf) || blockNfs.count(nf))
                return state.DoS(100, false, REJECT_INVALID, "bad-yugen-nullifier-spent");
            blockNfs.insert(nf);
        }
        // §13.3.5: a withdrawal above the window's gross cap K is invalid.
        if (t->valueBalance > 0 && (uint64_t)t->valueBalance > K)
            return state.DoS(100, false, REJECT_INVALID, "bad-yugen-withdrawal-above-k");
        if (!debit(t->TransparentDelta())) return state.DoS(100, false, REJECT_INVALID, "bad-yugen-turnstile");
        // §13.3.6: a deposit that takes B above cap(h) makes the block invalid.
        if (t->valueBalance < 0 && s.balance > (CAmount)cap) return state.DoS(100, false, REJECT_INVALID, "bad-yugen-value-cap");
        if (verify) {
            const CBlockIndex* anchorIndex = pprev->GetAncestor(ha);
            if (!anchorIndex) return state.DoS(100, false, REJECT_INVALID, "bad-yugen-anchor");
            auto hr = VerifyProofs(tx, *t, h, ha, s.blocks.at(ha).rootAfter, anchorIndex->GetBlockHash(), params);
            if (hr.kind == HelperResult::FAIL) return fail(hr.line);
            if (hr.kind == HelperResult::REJECT)
                return state.DoS(100, error("yugen: %s: %s", tx.GetHash().ToString(), hr.line), REJECT_INVALID, "bad-yugen-proof",
                                 BodyCorruption::Possible);   // the proofs are outside the txid (N-D7)
        }
        for (const auto& nf : t->nf) { s.nullifiers.insert(nf); s.nfHeight[nf] = h; rec.nfsAdded.push_back(nf); }
        for (const auto& cm : t->cm) s.cms.push_back(cm);
        rec.transfers.emplace_back(tx.GetHash(), tx.yugen.transfer);
    }
    if (verify) {
        if (sidecarUsed != block.vYugenProofs.size())
            return state.DoS(100, false, REJECT_INVALID, "bad-yugen-sidecar-entry", BodyCorruption::Possible);
        // §13.3.3/§13.3.12: the record run, scripts in first-paid order, P_s summed. (The fee-outflow
        // scaling p/x of §13.3.5 is not applied: the fee budget is not implemented on this line.)
        std::vector<std::pair<std::vector<unsigned char>, uint64_t>> run;
        for (const auto& pay : pays)
            for (const auto& rp : pay.records) {
                const auto& script = rp.first;
                const uint64_t v = rp.second;
                if (v == 0) continue;
                auto it = std::find_if(run.begin(), run.end(), [&](const auto& x) { return x.first == script; });
                if (it != run.end()) it->second += v; else run.emplace_back(script, v);
            }
        if (run.size() > 5460) return state.DoS(100, false, REJECT_INVALID, "bad-yugen-record-run-count");
        uint64_t runBytes = 0;
        for (const auto& r : run) runBytes += 9 + r.first.size();
        // §16.2 W3 and W5 (W2 is the stock MAX_BLOCK_SIZE).
        uint64_t blockBytes = ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION);
        // Leaf proofs and the sidecar are outside the txids, so an over-weight body is replaceable (N-D8).
        if (blockBytes + sidecarBytes > BLOCK_WEIGHT_MAX)
            return state.DoS(100, false, REJECT_INVALID, "bad-yugen-block-weight", BodyCorruption::Possible);
        if (w5Weight + runBytes > BLOCK_WEIGHT_MAX - LEAF_RESERVE || w5Bytes + runBytes > BLOCK_BYTES_MAX - LEAF_BYTES_RESERVE)
            return state.DoS(100, false, REJECT_INVALID, "bad-yugen-bundle-weight-w5");
        if (!block.vtx.empty() && block.vtx[0].IsCoinBase()) {
            const auto& vout = block.vtx[0].vout;
            if (vout.size() < run.size()) return state.DoS(100, false, REJECT_INVALID, "bad-yugen-coinbase-records-missing");
            for (size_t i = 0; i < run.size(); i++) {
                const CTxOut& o = vout[vout.size() - run.size() + i];
                if (std::vector<unsigned char>(o.scriptPubKey.begin(), o.scriptPubKey.end()) != run[i].first ||
                    o.nValue != (CAmount)run[i].second)
                    return state.DoS(100, false, REJECT_INVALID, "bad-yugen-coinbase-record-output");
            }
        }
        if (res) for (const auto& r : run) res->run.emplace_back((CAmount)r.second, CScript(r.first.begin(), r.first.end()));
    }
    if (trial) {
        rec.rootAfter = Root{};   // a trial is undone at once; no anchor reads its own block's root (review M-4)
    } else if (h == act || s.cms.size() != before) {
        rec.rootAfter = ComputeRoot(s.cms);
    } else {
        rec.rootAfter = s.blocks.at(h - 1).rootAfter;
    }
    rec.cmsAdded = s.cms.size() - before;
    rec.balanceAfter = s.balance;
    return true;
}

// Round 3: the proof store keeps a bundle's proofs in a file of their own only while its block may
// still leave the chain; once the block at `h` is MAX_REORG_LENGTH deep, the files of its bundles
// whose proofs the block's sidecar file holds are removed (AttachSidecar and GetProofs' callers then
// read the sidecar file, or find nothing, as for any pruned data).
static void PruneProofStore(int h)
{
    auto it = g_state.blocks.find(h);
    if (it == g_state.blocks.end() || it->second.transfers.empty()) return;
    auto sidecar = ReadSidecarFile(it->second.hash);
    if (!sidecar) return;
    for (const auto& e : *sidecar) {
        boost::system::error_code ec;
        if (fs::remove(ProofPath(e.txid), ec)) LogPrint("yugen", "yugen: proofs of %s pruned (in block %d's sidecar)\n", e.txid.ToString(), h);
    }
}

// ApplyBlockInner, all or nothing: on a refusal or an exception `s` is as it was.
static bool ApplyBlock(PoolState& s, const CBlock& block, int h, const CBlockIndex* pprev,
                       const CChainParams& params, bool verify, CValidationState& state, const BundleCoinsMap& coins,
                       BlockResult* res = nullptr, bool trial = false)
{
    BlockRecord rec;
    const size_t before = s.cms.size();
    const CAmount balanceBefore = s.balance;
    bool ok = false;
    try {
        ok = ApplyBlockInner(s, rec, block, h, pprev, params, verify, trial, state, res, coins);
    } catch (...) {
        for (const auto& nf : rec.nfsAdded) { s.nullifiers.erase(nf); s.nfHeight.erase(nf); }
        s.cms.resize(before);
        s.balance = balanceBefore;
        throw;
    }
    if (!ok) {
        for (const auto& nf : rec.nfsAdded) { s.nullifiers.erase(nf); s.nfHeight.erase(nf); }
        s.cms.resize(before);
        s.balance = balanceBefore;
        return false;
    }
    s.blocks[h] = std::move(rec);
    s.tip = block.GetHash();
    s.tipHeight = h;
    return true;
}

// Reverses the last block of `s` from its undo record (§13.3.2: exactly what the record lists).
static bool UndoTip(PoolState& s)
{
    if (s.blocks.empty()) return false;
    auto it = std::prev(s.blocks.end());
    const BlockRecord& rec = it->second;
    if (rec.hash != s.tip || rec.cmsAdded > s.cms.size()) return false;
    for (const auto& nf : rec.nfsAdded) { s.nullifiers.erase(nf); s.nfHeight.erase(nf); }
    s.cms.resize(s.cms.size() - rec.cmsAdded);
    s.balance = rec.balanceBefore;
    s.blocks.erase(it);
    if (s.blocks.empty()) { s = PoolState(); return true; }
    s.tip = s.blocks.rbegin()->second.hash;
    s.tipHeight = s.blocks.rbegin()->first;
    return true;
}

// Review M-3: the state file. Format: magic "YGST", version, then the state, then SHA-256d of
// everything before it.
static const uint32_t STATE_MAGIC = 0x54534759, STATE_VERSION = 1;
static fs::path StatePath() { return GetDataDir() / "yugen" / "state.dat"; }
static bool g_loaded = false;

template <typename Stream>
static void SerState(Stream& ss, const PoolState& s)
{
    ss << STATE_MAGIC << STATE_VERSION << s.tip << s.tipHeight << s.balance << s.cms << s.nullifiers << s.nfHeight;
    ss << (uint64_t)s.blocks.size();
    for (const auto& [h, r] : s.blocks)
        ss << h << r.treeSizeBefore << r.rootAfter << r.transfers << r.hash << r.nfsAdded << r.cmsAdded
           << r.balanceBefore << r.balanceAfter;
}

bool Flush()
{
    // Before the state is first loaded or built in this process, the file stands as it is.
    if (!g_loaded && g_state.tipHeight < 0) return true;
    try {
        CDataStream ss(SER_DISK, CLIENT_VERSION);
        SerState(ss, g_state);
        uint256 sum = Hash(ss.begin(), ss.end());
        ss << sum;
        fs::create_directories(StatePath().parent_path());
        fs::path tmp = StatePath().string() + ".new";
        FILE* f = fsbridge::fopen(tmp, "wb");
        if (!f) return false;
        bool ok = fwrite(ss.data(), 1, ss.size(), f) == ss.size();
        if (ok) FileCommit(f);
        fclose(f);
        return ok && RenameOver(tmp, StatePath());
    } catch (const std::exception& e) {
        LogPrintf("yugen: state save failed: %s\n", e.what());
        return false;
    }
}

static bool Load(PoolState& out)
{
    std::ifstream in(StatePath().string(), std::ios::binary);
    if (!in) {
        LogPrint("yugen", "yugen: no state file %s\n", StatePath().string());
        return false;
    }
    std::vector<char> buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (buf.size() < 40) return false;
    try {
        uint256 want = Hash(buf.begin(), buf.end() - 32);
        if (memcmp(want.begin(), buf.data() + buf.size() - 32, 32) != 0) {
            LogPrintf("yugen: %s: checksum mismatch, ignored\n", StatePath().string());
            return false;
        }
        CDataStream ss(SER_DISK, CLIENT_VERSION);
        ss.write(buf.data(), buf.size() - 32);
        uint32_t magic, version;
        ss >> magic >> version;
        if (magic != STATE_MAGIC || version != STATE_VERSION) {
            LogPrintf("yugen: %s: unknown format, ignored\n", StatePath().string());
            return false;
        }
        PoolState s;
        ss >> s.tip >> s.tipHeight >> s.balance >> s.cms >> s.nullifiers >> s.nfHeight;
        uint64_t n;
        ss >> n;
        for (uint64_t i = 0; i < n; i++) {
            int h;
            BlockRecord r;
            ss >> h >> r.treeSizeBefore >> r.rootAfter >> r.transfers >> r.hash >> r.nfsAdded >> r.cmsAdded
               >> r.balanceBefore >> r.balanceAfter;
            s.blocks.emplace(h, std::move(r));
        }
        out = std::move(s);
        return true;
    } catch (const std::exception& e) {
        LogPrintf("yugen: %s: unreadable (%s), ignored\n", StatePath().string(), e.what());
        return false;
    }
}

static bool OnChain(const PoolState& s, const CBlockIndex* pindex)
{
    if (s.tipHeight < 0 || s.tipHeight > pindex->nHeight) return false;
    const CBlockIndex* a = pindex->GetAncestor(s.tipHeight);
    return a && a->GetBlockHash() == s.tip;
}

// Brings g_state to `pindex` (the state after it): loads the saved state once, undoes blocks
// that left the chain from their records, and replays only blocks the state lacks. Never throws;
// on failure the state is cleared (the next call replays from activation) and `err` says why.
static bool Ensure(const CBlockIndex* pindex, const CChainParams& params, std::string& err)
{
    const int act = ActivationHeight(params);
    if (pindex == nullptr || act == Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT || pindex->nHeight < act) {
        g_state = PoolState();
        return true;
    }
    if (g_state.tip == pindex->GetBlockHash()) return true;
    if (!g_loaded) {
        g_loaded = true;
        PoolState f;
        if (Load(f)) {
            g_state = std::move(f);
            LogPrintf("yugen: state loaded at height %d\n", g_state.tipHeight);
        }
    }
    while (g_state.tipHeight >= 0 && !OnChain(g_state, pindex))
        if (!UndoTip(g_state)) g_state = PoolState();
    const int from = g_state.tipHeight < 0 ? act : g_state.tipHeight + 1;
    if (from <= pindex->nHeight)
        LogPrint("yugen", "yugen: replaying blocks %d to %d\n", from, pindex->nHeight);
    try {
        for (int h = from; h <= pindex->nHeight; h++) {
            const CBlockIndex* bi = pindex->GetAncestor(h);
            CBlock block;
            if (!ReadBlockFromDisk(block, bi, params.GetConsensus())) {
                err = "cannot read block " + std::to_string(h);
                g_state = PoolState();
                return false;
            }
            // Each bundle's applied mask, from the block's undo data (B9; ConnectBundleCoins wrote it).
            BundleCoinsMap coins;
            CBlockUndo undo;
            if (std::any_of(block.vtx.begin(), block.vtx.end(), [](const CTransaction& tx) { return tx.IsYugenBundle(); }) &&
                ReadBlockUndo(undo, bi) && undo.vtxundo.size() + 1 == block.vtx.size())
                for (size_t i = 1; i < block.vtx.size(); i++)
                    if (block.vtx[i].IsYugenBundle() && !UndoMask(undo.vtxundo[i - 1]).empty())
                        coins[block.vtx[i].GetHash()].applied = UndoMask(undo.vtxundo[i - 1]);
            CValidationState st;
            if (!ApplyBlock(g_state, block, h, bi->pprev, params, false, st, coins)) {
                err = "replay failed at " + std::to_string(h) + ": " + st.GetRejectReason();
                g_state = PoolState();
                return false;
            }
        }
    } catch (const std::exception& e) {
        err = e.what();
        g_state = PoolState();
        return false;
    }
    return true;
}

const PoolState& Current(const CChainParams& params)
{
    std::string err;
    if (!Ensure(ChainTip(), params, err)) LogPrintf("yugen: state unavailable: %s\n", err);
    return g_state;
}

void DisconnectBlock(const CBlockIndex* pindex)
{
    if (g_state.tip == pindex->GetBlockHash() && !UndoTip(g_state)) g_state = PoolState();
    g_tipOverride = pindex->pprev;
}

void EndDisconnect() { g_tipOverride = nullptr; }

CAmount PoolDebit(const CTransaction& tx)
{
    CAmount d = 0;
    for (const auto& t : tx.GetYugenTransfers()) d += t.TransparentDelta();
    return d;
}

// Applies `block` to g_state and undoes it again (a check without a copy of the state).
// `nfs` gets the number of nullifiers the block added.
static bool Trial(const CBlock& block, int h, const CBlockIndex* pprev, const CChainParams& params,
                  CValidationState& state, BlockResult* res, const BundleCoinsMap& coins, size_t* nfs = nullptr)
{
    try {
        if (!ApplyBlock(g_state, block, h, pprev, params, true, state, coins, res, true)) return false;
    } catch (const std::exception& e) {
        return state.Error(std::string("yugen-state: ") + e.what());
    }
    if (nfs) *nfs = g_state.blocks.rbegin()->second.nfsAdded.size();
    if (!UndoTip(g_state)) g_state = PoolState();
    return true;
}

bool ConnectBlock(const CBlock& block, const CBlockIndex* pindex, const CChainParams& params,
                  bool fJustCheck, CValidationState& state, BlockResult& res, const BundleCoinsMap& coins)
{
    g_tipOverride = nullptr;
    if (!params.GetConsensus().NetworkUpgradeActive(pindex->nHeight, Consensus::UPGRADE_YUGEN)) return true;
    std::string err;
    // Inherits the body-commitment flags main.cpp set (CheckBlock, CheckBlockBodyAuthCommitment), so
    // that a Default refusal (a spent nullifier, the turnstile, an anchor, a bound bundle proof) is a
    // verdict on a pinned body and the block is marked failed, not refetched forever.
    CValidationState inner = state;
    bool ok;
    // Review M-3: a state fault is this node's, never a verdict on the block.
    if (!Ensure(pindex->pprev, params, err)) {
        ok = inner.Error("yugen-state-unavailable: " + err);
    } else if (fJustCheck) {
        ok = Trial(block, pindex->nHeight, pindex->pprev, params, inner, &res, coins);
    } else {
        // Applied in place; ApplyBlock leaves the state as it was on a refusal or an exception.
        try {
            ok = ApplyBlock(g_state, block, pindex->nHeight, pindex->pprev, params, true, inner, coins, &res);
        } catch (const std::exception& e) {
            ok = inner.Error(std::string("yugen-state: ") + e.what());
        }
    }
    // block.GetHash(), not pindex's: a template's index (TestBlockValidity) has no hash.
    const uint256 hash = (!ok && inner.IsError()) || (ok && !fJustCheck) ? block.GetHash() : uint256();
    if (!ok && inner.IsError()) {
        // Reviews H-1, H-2: a fault of this node (helper failure, panic, timeout, out of memory, a
        // state fault) is never a verdict. The block is not marked invalid and its body is reset
        // (BodyCorruption::Possible), so the block is fetched again, from any peer, and checked again;
        // a stalled connect would otherwise never retry. Round 3: at most HELPER_RETRIES_MAX times per
        // block hash, then the block is no longer requested (HelperGaveUp) until a restart; the same
        // body (sidecar included) failing a second time scores its sender HELPER_SAME_BODY_DOS, once.
        const int n = g_helperFailures.get(hash) ? *g_helperFailures.get(hash) + 1 : 1;
        g_helperFailures.put(hash, n);
        CHashWriter hw(SER_GETHASH, 0);
        hw << hash << block.vYugenProofs;
        const uint256 body = hw.GetHash();
        const int same = g_helperBodyFailures.get(body) ? *g_helperBodyFailures.get(body) + 1 : 1;
        g_helperBodyFailures.put(body, same);
        const int dos = same == 2 ? HELPER_SAME_BODY_DOS : 0;   // once a body: a broken local helper bans no one
        if (n >= HELPER_RETRIES_MAX) {
            LogPrintf("yugen: block %s at %d not connected after %d verifier failures (%s); no longer requested "
                      "until restart: check -yugenverifier\n", hash.ToString(), pindex->nHeight, n, inner.GetRejectReason());
            return state.DoS(dos, false, REJECT_INVALID, "yugen-verifier-gave-up", BodyCorruption::Possible);
        }
        LogPrintf("yugen: block %s at %d not connected, will retry (%d of %d): %s\n", hash.ToString(),
                  pindex->nHeight, n, HELPER_RETRIES_MAX, inner.GetRejectReason());
        return state.DoS(dos, false, REJECT_INVALID, "yugen-verifier-failed", BodyCorruption::Possible);
    }
    if (ok && !fJustCheck) {
        g_helperFailures.erase(hash);
        PruneProofStore(pindex->nHeight - (int)MAX_REORG_LENGTH);
    }
    if (!ok) state = inner;
    return ok;
}

bool HelperGaveUp(const uint256& block)
{
    const int* n = g_helperFailures.get(block);
    return n && *n >= HELPER_RETRIES_MAX;
}

// Lead decision (a): a bundle supersedes a pool leaf transfer it carries. True when `leaf` is a
// leaf (not a bundle) and each of its transfers appears, field for field, among the bundle's.
// Mempool policy only; AcceptToMemoryPool evicts the leaf (removeConflicts) before adding the bundle.
static bool SameTransfer(const Transfer& a, const Transfer& b)
{
    return a.feeClass == b.feeClass && a.anchorSlot == b.anchorSlot && a.flags == b.flags && a.nf == b.nf &&
           a.cm == b.cm && a.valueBalance == b.valueBalance;
}
static bool BundleCoversLeaf(const std::vector<Transfer>& bundle, const CTransaction& leaf)
{
    if (!leaf.IsYugen() || leaf.IsYugenBundle()) return false;
    auto lt = leaf.GetYugenTransfers();
    if (lt.empty()) return false;
    for (const auto& t : lt)
        if (std::none_of(bundle.begin(), bundle.end(), [&](const Transfer& b) { return SameTransfer(t, b); })) return false;
    return true;
}

// Review M-1: decode, anchors and nullifiers (chain and the pool's map), no helper.
bool PreCheckMempoolTx(const CTransaction& tx, const CTxMemPool& pool, const CChainParams& params,
                       CValidationState& state)
{
    // §15.5: a coin a pooled bundle's deposit spends is not spent by another pooled transaction.
    for (const CTxIn& in : tx.vin)
        if (pool.yugenDepositTx(in.prevout)) return state.Invalid(false, REJECT_DUPLICATE, "bad-yugen-bundle-deposit-in-mempool");
    if (!tx.IsYugen()) return true;
    const CBlockIndex* tip = ChainTip();
    std::string err;
    if (!Ensure(tip, params, err)) return state.DoS(0, false, REJECT_INVALID, "yugen-state-unavailable");
    const int h = tip->nHeight + 1, act = ActivationHeight(params);
    auto ts = tx.GetYugenTransfers();
    if (ts.empty()) return state.DoS(100, false, REJECT_INVALID, "bad-yugen-transfer");
    std::vector<uint8_t> slots;
    if (tx.IsYugenBundle()) for (const auto& e : BundleAnchors(tx)) slots.push_back(e.slot);
    else slots.push_back(ts[0].anchorSlot);
    for (uint8_t slot : slots) {
        int ha = ResolveAnchor(slot, h, act);
        if (ha < 0 || !g_state.blocks.count(ha)) return state.DoS(0, false, REJECT_INVALID, "bad-yugen-anchor");
    }
    for (const auto& t : ts)
        for (const auto& nf : t.nf) {
            if (g_state.nullifiers.count(nf)) return state.DoS(0, false, REJECT_INVALID, "bad-yugen-nullifier-spent");
            const CTransaction* c = pool.yugenNullifierTx(nf);
            if (c && !(tx.IsYugenBundle() && BundleCoversLeaf(ts, *c)))
                return state.Invalid(false, REJECT_DUPLICATE, "bad-yugen-nullifier-in-mempool");
        }
    // A bundle's deposit coins: not spent in the pool, except by a leaf the bundle supersedes.
    for (const auto& t : ts)
        for (const auto& in : t.vin) {
            const COutPoint p = Prevout(in);
            const CTransaction* c = pool.spenderOf(p);
            const CTransaction* d = pool.yugenDepositTx(p);
            if ((c && !BundleCoversLeaf(ts, *c)) || (d && *d != tx))
                return state.Invalid(false, REJECT_DUPLICATE, "bad-yugen-bundle-deposit-in-mempool");
        }
    if (tx.IsYugenBundle() && !GetProofs(tx.GetHash()))
        return state.DoS(0, false, REJECT_INVALID, "bad-yugen-bundle-proofs-missing");
    return true;
}

// Review item (4): refusals of mempool candidates by everything they carry, proofs included, and
// the tip they were judged at, so that one copy replayed from many peers is judged once per tip.
static BoundedMap<uint256, std::string> g_refused(REFUSED_CACHE_MAX);

static uint256 RefusalKey(const CTransaction& tx, const std::vector<std::vector<unsigned char>>* proofs)
{
    CHashWriter hw(SER_GETHASH, 0);
    const CBlockIndex* tip = ChainTip();
    hw << (tip ? tip->GetBlockHash() : uint256()) << tx.GetHash() << tx.GetWTxId().ToBytes() << tx.yugen.proofA << tx.yugen.proofB;
    if (proofs) hw << *proofs;
    return hw.GetHash();
}

static std::optional<uint256> CandidateKey(const CTransaction& tx)
{
    if (!tx.IsYugen()) return std::nullopt;
    std::optional<std::vector<std::vector<unsigned char>>> p;
    if (tx.IsYugenBundle()) p = GetProofs(tx.GetHash());
    return RefusalKey(tx, p ? &*p : nullptr);
}

bool KnownRefused(const CTransaction& tx)
{
    auto k = CandidateKey(tx);
    return k && g_refused.get(*k);
}

bool VerifyBudget::Take(int64_t nowMicros, int64_t perMinute, int64_t peer)
{
    if (perMinute <= 0) return true;
    static const int64_t MINUTE = 60 * 1000000;
    const double cap = (double)perMinute;
    if (last == 0) tokens = cap;
    else tokens = std::min(cap, tokens + cap * (double)(nowMicros - last) / 60e6);
    last = nowMicros;
    for (auto it = peers.begin(); it != peers.end();)
        it = nowMicros - it->second.lastAsk > MINUTE ? peers.erase(it) : std::next(it);
    Peer& me = peers[peer];
    me.lastAsk = nowMicros;
    if (nowMicros - me.windowStart > MINUTE) { me.windowStart = nowMicros; me.used = 0; }
    // A peer over its share takes a token only while one is left for each other peer that waited.
    int waiting = 0;
    for (const auto& [id, p] : peers)
        if (id != peer && p.lastWait != 0 && nowMicros - p.lastWait <= MINUTE) waiting++;
    const double share = std::max(1.0, cap / (double)peers.size());
    if (tokens < 1.0 || (me.used >= share && tokens < 1.0 + waiting)) {
        me.lastWait = nowMicros;
        return false;
    }
    tokens -= 1.0;
    me.used++;
    return true;
}

static VerifyBudget g_peerBudget;
static int64_t g_scopePeer = -1;
static bool g_scopeJudged = false;

PeerVerifyScope::PeerVerifyScope(int64_t peer) { g_scopePeer = peer; g_scopeJudged = false; }
PeerVerifyScope::~PeerVerifyScope() { g_scopePeer = -1; g_scopeJudged = false; }
bool PeerVerifyScope::Judged() const { return g_scopeJudged; }

int64_t RefusalBackoff(int& refusals, int64_t& lastRefusal, int64_t nowMicros)
{
    static const int64_t BASE = 10 * 1000000, MAX = 600 * 1000000;
    if (lastRefusal != 0 && nowMicros - lastRefusal > 2 * MAX) refusals = 0;
    refusals = std::min(refusals + 1, 30);
    lastRefusal = nowMicros;
    int64_t b = BASE;
    for (int i = 1; i < refusals && b < MAX; i++) b *= 2;
    return nowMicros + std::min(b, MAX);
}

// The full rules for the next block (helper included), run just before the pool accepts the tx.
// Every refusal here is DoS 0 (review M-3): each depends on the state at the tip (anchors, the
// nullifier set, the turnstile, and the proofs, which verify against the anchor's root and block
// hash), which a peer on another tip need not share; the structure was judged (DoS 100) before. A
// helper failure is DoS 0 too, and is not remembered (review H-1); a refusal is (item 4).
bool CheckMempoolTx(const CTransaction& tx, const CTxMemPool& pool, const CChainParams& params,
                    CValidationState& state)
{
    if (!tx.IsYugen()) return true;
    const CBlockIndex* tip = ChainTip();
    std::string err;
    if (!Ensure(tip, params, err)) return state.DoS(0, false, REJECT_INVALID, "yugen-state-unavailable");
    CBlock one;
    one.vtx.push_back(tx);
    if (tx.IsYugenBundle()) {
        auto p = GetProofs(tx.GetHash());
        if (!p) return state.DoS(0, false, REJECT_INVALID, "bad-yugen-bundle-proofs-missing");
        one.vYugenProofs.push_back({tx.GetHash(), *p});
    }
    const uint256 key = RefusalKey(tx, tx.IsYugenBundle() ? &one.vYugenProofs[0].proofs : nullptr);
    if (const std::string* why = g_refused.get(key)) return state.DoS(0, false, REJECT_INVALID, *why);
    // Round 3: a candidate from a peer spends a token of the shared budget here, after the cheap checks
    // (CheckTransaction, the structure, PreCheckMempoolTx, inputs and scripts) and the refusal cache.
    if (g_scopePeer >= 0 && !g_peerBudget.Take(GetTimeMicros(), GetArg("-yugenpeerverifyrate", DEFAULT_PEER_VERIFY_RATE), g_scopePeer))
        return state.DoS(0, false, REJECT_INVALID, VERIFY_DEFERRED, BodyCorruption::Possible);
    if (g_scopePeer >= 0) g_scopeJudged = true;
    size_t nfs = 0;
    MempoolTimeout shortTimeout;   // review M-2
    CValidationState inner;
    BundleCoinsMap coins;
    if (!CoinsAtTip({tx}, tip, params, coins, inner)) return state.DoS(0, false, REJECT_INVALID, inner.GetRejectReason());
    if (!Trial(one, tip->nHeight + 1, tip, params, inner, nullptr, coins, &nfs)) {
        if (!inner.IsError()) g_refused.put(key, inner.GetRejectReason());
        return state.DoS(0, false, REJECT_INVALID, inner.GetRejectReason());
    }
    if (tx.IsYugenBundle() && nfs != 2 * tx.GetYugenTransfers().size())
        return state.DoS(0, false, REJECT_INVALID, "bad-yugen-bundle-skips");   // every transfer must apply in the pool
    return true;
}

bool StaleInPool(const CTransaction& tx, int nextHeight, int disconnectedHeight, const CChainParams& params)
{
    if (!tx.IsYugen()) return false;
    const int act = ActivationHeight(params);
    const PoolState& st = Current(params);
    auto ts = tx.GetYugenTransfers();
    if (ts.empty()) return true;
    std::vector<uint8_t> slots;
    if (tx.IsYugenBundle()) for (const auto& e : BundleAnchors(tx)) slots.push_back(e.slot);
    else slots.push_back(ts[0].anchorSlot);
    for (uint8_t slot : slots) {
        int ha = ResolveAnchor(slot, nextHeight, act);
        if (ha < 0) return true;
        if (disconnectedHeight >= 0 && ha >= disconnectedHeight) return true;   // the anchor block left the chain
    }
    for (const auto& t : ts) for (const auto& nf : t.nf) if (st.nullifiers.count(nf)) return true;
    // §15.6 S2: a deposit whose coin the next block cannot spend would be skipped (the pool takes only
    // bundles whose every transfer applies).
    for (const auto& t : ts)
        for (const auto& in : t.vin) {
            const COutPoint p = Prevout(in);
            const CCoins* c = pcoinsTip->AccessCoins(p.hash);
            if (!c || !c->IsAvailable(p.n) || (c->IsCoinBase() && nextHeight - c->nHeight < COINBASE_MATURITY)) return true;
        }
    // §13.3.2: after a reorganisation the pool may no longer hold what the transaction takes.
    CAmount nb = st.balance - PoolDebit(tx);
    if (!tx.IsYugenBundle() && PoolDebit(tx) < 0 && nb > (CAmount)ValueCap(nextHeight, act)) return true;   // §13.3.6
    return nb < 0 || nb > MAX_MONEY;
}

std::vector<std::pair<CAmount, CScript>> TemplateRecordRun(const std::vector<CTransaction>& vtx, int h,
                                                           const CChainParams& params)
{
    std::vector<std::pair<CAmount, CScript>> run;
    if (!params.GetConsensus().NetworkUpgradeActive(h, Consensus::UPGRADE_YUGEN)) return run;
    const CBlockIndex* tip = ChainTip();
    std::string err;
    if (!Ensure(tip, params, err)) return run;
    CBlock b;
    CMutableTransaction cb;
    b.vtx.push_back(CTransaction(cb));   // no coinbase check (not a coinbase)
    for (const auto& tx : vtx) if (tx.IsYugen()) b.vtx.push_back(tx);
    AttachSidecar(b);
    CValidationState st;
    BlockResult res;
    BundleCoinsMap coins;
    if (CoinsAtTip(std::vector<CTransaction>(b.vtx.begin() + 1, b.vtx.end()), tip, params, coins, st) &&
        Trial(b, h, tip, params, st, &res, coins)) {
        for (const auto& r : res.run) run.push_back(r);
    } else {
        LogPrintf("yugen: template record run: %s\n", st.GetRejectReason());
    }
    return run;
}

} // namespace yugen
