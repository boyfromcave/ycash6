// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2016-2023 The Zcash developers
// Copyright (c) 2019-present The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "chain.h"
#include "core_io.h"
#include "crypto/pq/scheme.h"
#include "crypto/pq/sign.h"
#include "deprecation.h"
#include "key_io.h"
#include "rpc/server.h"
#include "init.h"
#include "main.h"
#include "pqkey.h"
#include "script/script.h"
#include "script/standard.h"
#include "support/cleanse.h"
#include "sync.h"
#include "util/system.h"
#include "util/match.h"
#include "util/time.h"
#include "wallet.h"
#include "yellowback/address.h"
#include "yellowback/params.h"
#include "yellowback/wallet.h"

#include <cerrno>
#include <cstring>
#include <fstream>
#include <optional>
#include <stdint.h>
#include <variant>

#include <boost/algorithm/string.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <univalue.h>

using namespace std;

void EnsureWalletIsUnlocked();
bool EnsureWalletIsAvailable(bool avoidException);

UniValue importwallet_impl(const UniValue& params, bool fImportZKeys);
static void WriteWalletDumpToFile(const fs::path& exportfilepath);
void MaybeAutoExportAfterImport(const std::string& method);


std::string static EncodeDumpTime(int64_t nTime) {
    return DateTimeStrFormat("%Y-%m-%dT%H:%M:%SZ", nTime);
}

int64_t static DecodeDumpTime(const std::string &str) {
    static const boost::posix_time::ptime epoch = boost::posix_time::from_time_t(0);
    static const std::locale loc(std::locale::classic(),
        new boost::posix_time::time_input_facet("%Y-%m-%dT%H:%M:%SZ"));
    std::istringstream iss(str);
    iss.imbue(loc);
    boost::posix_time::ptime ptime(boost::date_time::not_a_date_time);
    iss >> ptime;
    if (ptime.is_not_a_date_time())
        return 0;
    return (ptime - epoch).total_seconds();
}

std::string static EncodeDumpString(const std::string &str) {
    std::stringstream ret;
    for (unsigned char c : str) {
        if (c <= 32 || c >= 128 || c == '%') {
            ret << '%' << HexStr(&c, &c + 1);
        } else {
            ret << c;
        }
    }
    return ret.str();
}

std::string DecodeDumpString(const std::string &str) {
    std::stringstream ret;
    for (unsigned int pos = 0; pos < str.length(); pos++) {
        unsigned char c = str[pos];
        if (c == '%' && pos+2 < str.length()) {
            c = (((str[pos+1]>>6)*9+((str[pos+1]-'0')&15)) << 4) |
                ((str[pos+2]>>6)*9+((str[pos+2]-'0')&15));
            pos += 2;
        }
        ret << c;
    }
    return ret.str();
}

/**
 * H8 (Phase 8): after an import and its rescan, YED that has just become mine must be locked
 * before anything can spend it as plain YEC. Declared *before* the LOCK2 of each import RPC so
 * that its destructor runs after cs_wallet is released — Reconcile() takes cs_yellowback and
 * cs_wallet one after the other, never nested (N25, the comment inside Reconcile), exactly as
 * yed_lockcoins calls it, and must not be entered holding cs_wallet.
 */
struct YellowbackReconcileOnExit
{
    ~YellowbackReconcileOnExit()
    {
        if (yellowback::g_yellowbackWallet) yellowback::g_yellowbackWallet->Reconcile();
    }
};

/** The outcome of ImportPQKeySeed. */
enum class PQImport { BAD, PRESENT, ADDED, FAILED };

/**
 * Import the post-quantum key of scheme made from seed (CPQKey::Set), the one place importwallet's "pqseed=" lines
 * and z_importpqkey store a PQ key. index is the HD index the key claims (PQ_INDEX_NONE when unknown); quantum review
 * F-1: a key that is not this wallet's own derivation at that index is stored with PQ_INDEX_NONE, so it never moves
 * the issued index. A key already held is marked used (6.20.0 (review B I-2)) and reported PRESENT. Needs cs_wallet, unlocked.
 */
static PQImport ImportPQKeySeed(int64_t scheme, int64_t index, const CPQKey::Secret& seed, int64_t nTime, CPQKeyID& idOut)
{
    AssertLockHeld(pwalletMain->cs_wallet);
    CPQKey pqkey;
    if (scheme < 0 || scheme > 255 || index < 0 || index > (int64_t)CPQKey::PQ_INDEX_NONE ||
        !pqkey.Set((uint8_t)scheme, seed, (uint32_t)index))
        return PQImport::BAD;
    if (!pwalletMain->IsOwnPQKey(pqkey) && !pqkey.Set(pqkey.Scheme(), seed, CPQKey::PQ_INDEX_NONE))
        return PQImport::BAD;
    idOut = pqkey.GetID();
    if (pwalletMain->HavePQKey(pqkey.GetID())) {
        pwalletMain->MarkPQKeyUsed(pqkey.GetID());   // 6.20.0 (review B I-2): never issued again
        return PQImport::PRESENT;
    }
    if (!pwalletMain->AddPQKeyWithTime(pqkey, nTime))
        return PQImport::FAILED;
    pwalletMain->MarkPQKeyUsed(pqkey.GetID());       // 6.20.0 (review B I-2): an imported key of this seed is in use
    return PQImport::ADDED;
}

UniValue importprivkey(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "importprivkey \"zcashprivkey\" ( \"label\" rescan )\n"
            "\nAdds a private key (as returned by dumpprivkey) to your wallet.\n"
            "\nArguments:\n"
            "1. \"zcashprivkey\"   (string, required) The private key (see dumpprivkey)\n"
            "2. \"label\"            (string, optional, default=\"\") An optional label\n"
            "3. rescan               (boolean, optional, default=true) Rescan the wallet for transactions\n"
            "\nNote: This call can take a long time to complete if rescan is true.\n"
            "\nExamples:\n"
            "\nDump a private key\n"
            + HelpExampleCli("dumpprivkey", "\"myaddress\"") +
            "\nImport the private key with rescan\n"
            + HelpExampleCli("importprivkey", "\"mykey\"") +
            "\nImport using a label and without rescan\n"
            + HelpExampleCli("importprivkey", "\"mykey\" \"testing\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("importprivkey", "\"mykey\", \"testing\", false")
        );

    if (fPruneMode)
        throw JSONRPCError(RPC_WALLET_ERROR, "Importing keys is disabled in pruned mode");

    YellowbackReconcileOnExit yellowbackReconcile;   // H8: lock imported YED once the wallet lock is gone
    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    string strSecret = params[0].get_str();
    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

    const auto& chainparams = Params();
    KeyIO keyIO(chainparams);

    CKey key = keyIO.DecodeSecret(strSecret);
    if (!key.IsValid()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key encoding");

    CPubKey pubkey = key.GetPubKey();
    assert(key.VerifyPubKey(pubkey));
    CKeyID vchAddress = pubkey.GetID();
    {
        pwalletMain->MarkDirty();
        pwalletMain->SetAddressBook(vchAddress, strLabel, "receive");

        // Don't throw error in case a key is already there
        if (pwalletMain->HaveKey(vchAddress)) {
            return keyIO.EncodeDestination(vchAddress);
        }

        pwalletMain->mapKeyMetadata[vchAddress].nCreateTime = 1;

        if (!pwalletMain->AddKeyPubKey(key, pubkey))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");
        // 07/F-5: an imported vault set member key brings no sign-once history; set_signunlock/set_signcancel refuse
        // until it is imported (set_importsigned) or the call acknowledges the restore.
        if (!MarkVaultKeyImported(*pwalletMain, pubkey))
            throw JSONRPCError(RPC_WALLET_ERROR, "cannot write the vault sign-once restore marker");

        // whenever a key is imported, we need to scan the whole chain
        pwalletMain->nTimeFirstKey = 1; // 0 would be considered 'no value'

        // Imported key is not derived from the mnemonic seed; mark the wallet
        // so getwalletinfo reports a partial-backup warning.
        pwalletMain->SetHasExternalImports();
        MaybeAutoExportAfterImport("importprivkey");

        if (fRescan) {
            pwalletMain->ScanForWalletTransactions(chainActive.Genesis(), true, false);
        }
    }

    return keyIO.EncodeDestination(vchAddress);
}

void ImportAddress(const CTxDestination& dest, const string& strLabel);
void ImportScript(const CScript& script, const string& strLabel, bool isRedeemScript)
{
    if (!isRedeemScript && ::IsMine(*pwalletMain, script) == ISMINE_SPENDABLE)
        throw JSONRPCError(RPC_WALLET_ERROR, "The wallet already contains the private key for this address or script");

    pwalletMain->MarkDirty();

    if (!pwalletMain->HaveWatchOnly(script) && !pwalletMain->AddWatchOnly(script))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding address to wallet");

    if (isRedeemScript) {
        const CScriptID id(script);
        if (!pwalletMain->HaveCScript(id) && !pwalletMain->AddCScript(script)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding p2sh redeemScript to wallet");
        }
        ImportAddress(id, strLabel);
    } else {
        CTxDestination destination;
        if (ExtractDestination(script, destination)) {
            pwalletMain->SetAddressBook(destination, strLabel, "receive");
        }
    }
}

void ImportAddress(const CTxDestination& dest, const string& strLabel)
{
    CScript script = GetScriptForDestination(dest);
    ImportScript(script, strLabel, false);
    // add to address book or update label
    if (IsValidDestination(dest))
        pwalletMain->SetAddressBook(dest, strLabel, "receive");
}

UniValue importaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 4)
        throw runtime_error(
            "importaddress \"address\" ( \"label\" rescan p2sh )\n"
            "\nAdds a script (in hex) or address that can be watched as if it were in your wallet but cannot be used to spend.\n"
            "\nArguments:\n"
            "1. \"script\"           (string, required) The hex-encoded script (or address)\n"
            "2. \"label\"            (string, optional, default=\"\") An optional label\n"
            "3. rescan               (boolean, optional, default=true) Rescan the wallet for transactions\n"
            "4. p2sh                 (boolean, optional, default=false) Add the P2SH version of the script as well\n"
            "\nNote: This call can take a long time to complete if rescan is true.\n"
            "If you have the full public key, you should call importpubkey instead of this.\n"
            "\nNote: If you import a non-standard raw script in hex form, outputs sending to it will be treated\n"
            "as change, and not show up in many RPCs.\n"
            "\nExamples:\n"
            "\nImport a script with rescan\n"
            + HelpExampleCli("importaddress", "\"myscript\"") +
            "\nImport using a label without rescan\n"
            + HelpExampleCli("importaddress", "\"myscript\" \"testing\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("importaddress", "\"myscript\", \"testing\", false")
        );

    if (fPruneMode)
        throw JSONRPCError(RPC_WALLET_ERROR, "Importing addresses is disabled in pruned mode");

    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

    // Whether to import a p2sh version, too
    bool fP2SH = false;
    if (params.size() > 3)
        fP2SH = params[3].get_bool();

    YellowbackReconcileOnExit yellowbackReconcile;   // H8: lock imported YED once the wallet lock is gone
    LOCK2(cs_main, pwalletMain->cs_wallet);

    const auto& chainparams = Params();
    KeyIO keyIO(chainparams);
    CTxDestination dest = keyIO.DecodeDestination(params[0].get_str());
    if (IsValidDestination(dest)) {
        if (fP2SH) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot use the p2sh flag with an address - use a script instead");
        }
        ImportAddress(dest, strLabel);
    } else if (IsHex(params[0].get_str())) {
        std::vector<unsigned char> data(ParseHex(params[0].get_str()));
        ImportScript(CScript(data.begin(), data.end()), strLabel, fP2SH);
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Ycash address or script");
    }

    if (fRescan)
    {
        pwalletMain->ScanForWalletTransactions(chainActive.Genesis(), true, false);
        pwalletMain->ReacceptWalletTransactions();
    }

    return NullUniValue;
}

UniValue importpubkey(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 4)
        throw runtime_error(
            "importpubkey \"pubkey\" ( \"label\" rescan )\n"
            "\nAdds a public key (in hex) that can be watched as if it were in your wallet but cannot be used to spend.\n"
            "\nArguments:\n"
            "1. \"pubkey\"           (string, required) The hex-encoded public key\n"
            "2. \"label\"            (string, optional, default=\"\") An optional label\n"
            "3. rescan               (boolean, optional, default=true) Rescan the wallet for transactions\n"
            "\nNote: This call can take a long time to complete if rescan is true.\n"
            "\nExamples:\n"
            "\nImport a public key with rescan\n"
            + HelpExampleCli("importpubkey", "\"mypubkey\"") +
            "\nImport using a label without rescan\n"
            + HelpExampleCli("importpubkey", "\"mypubkey\" \"testing\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("importpubkey", "\"mypubkey\", \"testing\", false")
        );

    if (fPruneMode)
        throw JSONRPCError(RPC_WALLET_ERROR, "Importing public keys is disabled in pruned mode");

    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

    if (!IsHex(params[0].get_str()))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pubkey must be a hex string");
    std::vector<unsigned char> data(ParseHex(params[0].get_str()));
    CPubKey pubKey(data.begin(), data.end());
    if (!pubKey.IsFullyValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pubkey is not a valid public key");

    LOCK2(cs_main, pwalletMain->cs_wallet);

    ImportAddress(pubKey.GetID(), strLabel);
    ImportScript(GetScriptForRawPubKey(pubKey), strLabel, false);

    if (fRescan)
    {
        pwalletMain->ScanForWalletTransactions(chainActive.Genesis(), true, false);
        pwalletMain->ReacceptWalletTransactions();
    }

    return NullUniValue;
}


UniValue z_importwallet(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "z_importwallet \"filename\"\n"
            "\nImports taddr and zaddr keys from a wallet export file (see z_exportwallet).\n"
            "\nArguments:\n"
            "1. \"filename\"    (string, required) The wallet file\n"
            "\nExamples:\n"
            "\nDump the wallet\n"
            + HelpExampleCli("z_exportwallet", "\"nameofbackup\"") +
            "\nImport the wallet\n"
            + HelpExampleCli("z_importwallet", "\"path/to/exportdir/nameofbackup\"") +
            "\nImport using the json rpc call\n"
            + HelpExampleRpc("z_importwallet", "\"path/to/exportdir/nameofbackup\"")
        );

	return importwallet_impl(params, true);
}

UniValue z_importpqkey(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "z_importpqkey \"pqseed\" ( rescan \"label\" )\n"
            "\nAdds one post-quantum key to the wallet from its 48-byte keygen seed (e.g. a vault owner or holder key made\n"
            "by another wallet such as YEW). The public key is re-derived from the seed. A key this wallet derives from its\n"
            "own HD seed keeps its index; any other key is stored without one (it never moves the wallet's issued index).\n"
            "The key's plain-YEC address (sq…/tq…/rq…) goes into the address book.\n"
            "\nArguments:\n"
            "1. \"pqseed\"     (string, required) \"<scheme>:<seed hex>\", or dumpwallet's \"<scheme>:<index>:<seed hex>\"\n"
            "                (an optional \"pqseed=\" prefix is accepted), or a dump's whole \"pqseed=… # owner=… addr=… yecaddr=…\"\n"
            "                line. scheme 1 = SLH-DSA-SHA2-128s, 2 = FN-DSA-512. Both schemes take a 48-byte seed and the\n"
            "                scheme decides the key: the same seed under the other scheme is another key with another\n"
            "                address, so check the returned address is the one you expect. A whole dump line is checked:\n"
            "                when its owner=, addr= or yecaddr= does not name the seed's key, nothing is imported.\n"
            "2. rescan       (boolean, optional, default=true) Rescan the chain for the key's transactions\n"
            "3. \"label\"      (string, optional, default=\"\") The address book label\n"
            "\nResult:\n"
            "{ \"scheme\": n, \"keyhash\": \"hex\", \"pqkeyid\": \"hex (scheme || keyhash)\", \"address\": \"sq…\",\n"
            "  \"index\": n|null (the HD index when the key is this wallet's own), \"added\": true|false (false: already held) }\n"
            "\nExamples:\n"
            + HelpExampleCli("z_importpqkey", "\"1:<96 hex digits>\"")
            + HelpExampleCli("z_importpqkey", "\"1:<96 hex digits>\" false")
            + HelpExampleRpc("z_importpqkey", "\"1:<96 hex digits>\", true")
        );

    if (fPruneMode)
        throw JSONRPCError(RPC_WALLET_ERROR, "Importing keys is disabled in pruned mode");

    YellowbackReconcileOnExit yellowbackReconcile;   // H8: lock imported YED once the wallet lock is gone
    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    // Review B-3: a dump's whole line ("pqseed=<s>:<i>:<seed> <time> # owner=<id> addr=<ye…> yecaddr=<sq…>") is accepted;
    // its owner=/addr=/yecaddr= fields must name the key the seed makes under the line's scheme.
    std::vector<std::string> words;
    {
        std::string line = params[0].get_str();
        boost::algorithm::trim(line);
        boost::split(words, line, boost::is_any_of(" \t"), boost::token_compress_on);
        memory_cleanse(&line[0], line.size());
    }
    std::string arg = words[0];
    if (boost::algorithm::starts_with(arg, "pqseed="))
        arg = arg.substr(7);
    std::map<std::string, std::string> expect;   // owner / addr / yecaddr
    for (size_t i = 1; i < words.size(); i++) {
        for (const char* k : {"owner=", "addr=", "yecaddr="}) {
            if (boost::algorithm::starts_with(words[i], k))
                expect[std::string(k, strlen(k) - 1)] = words[i].substr(strlen(k));
        }
    }
    std::vector<std::string> f;
    boost::split(f, arg, boost::is_any_of(":"));
    int64_t scheme = 0, index = CPQKey::PQ_INDEX_NONE;
    if ((f.size() != 2 && f.size() != 3) || !ParseInt64(f[0], &scheme) || (f.size() == 3 && !ParseInt64(f[1], &index)))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "pqseed must be \"<scheme>:<seed hex>\" or \"<scheme>:<index>:<seed hex>\"");
    if (scheme < 0 || scheme > 255 || !pq::IsKnownScheme((uint8_t)scheme))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown post-quantum scheme (1 = SLH-DSA-SHA2-128s, 2 = FN-DSA-512)");
    const std::string& hex = f.back();
    if (!IsHex(hex) || hex.size() != 2 * pq::SeedSize((uint8_t)scheme))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("the seed must be %u bytes of hex", (unsigned)pq::SeedSize((uint8_t)scheme)));
    std::vector<unsigned char> seedBytes = ParseHex(hex);
    const CPQKey::Secret seed(seedBytes.begin(), seedBytes.end());
    memory_cleanse(seedBytes.data(), seedBytes.size());
    for (std::string& w : words) memory_cleanse(&w[0], w.size());
    for (std::string& w : f) memory_cleanse(&w[0], w.size());
    memory_cleanse(&arg[0], arg.size());

    if (!expect.empty()) {
        CPQKey probe;
        if (!probe.Set((uint8_t)scheme, seed, CPQKey::PQ_INDEX_NONE))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid post-quantum key seed or index");
        const CPQKeyID pid = probe.GetID();
        std::vector<unsigned char> pidBytes(1, pid.scheme);
        pidBytes.insert(pidBytes.end(), pid.hash.begin(), pid.hash.end());
        const std::map<std::string, std::string> have = {
            {"owner", HexStr(pidBytes)},
            {"addr", yellowback::EncodeAddress(pid, yellowback::ParamsForNetwork(Params().NetworkIDString()))},
            {"yecaddr", KeyIO(Params()).EncodeDestination(pid)}};
        for (const auto& e : expect) {
            if (e.second != have.at(e.first))
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf(
                    "the line's %s=%s does not match the key its seed makes under scheme %d (%s); nothing imported",
                    e.first, e.second, (int)scheme, have.at("yecaddr")));
        }
    }

    const bool fRescan = params.size() > 1 && !params[1].isNull() ? params[1].get_bool() : true;
    const std::string strLabel = params.size() > 2 && !params[2].isNull() ? params[2].get_str() : "";

    CPQKeyID id;
    const PQImport r = ImportPQKeySeed(scheme, index, seed, 1, id);   // creation time 1: the key's age is unknown
    if (r == PQImport::BAD)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid post-quantum key seed or index");
    if (r == PQImport::FAILED)
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding the post-quantum key to the wallet");
    pwalletMain->SetAddressBook(id, strLabel, "receive");

    std::vector<unsigned char> pk;
    uint32_t storedIndex = CPQKey::PQ_INDEX_NONE;
    pwalletMain->GetPQKeyInfo(id, pk, storedIndex);
    if (r == PQImport::ADDED && storedIndex == CPQKey::PQ_INDEX_NONE) {
        // 6.20.0: a key not derived from the mnemonic seed; getwalletinfo reports a partial-backup warning.
        pwalletMain->SetHasExternalImports();
        MaybeAutoExportAfterImport("z_importpqkey");
    }

    if (r == PQImport::ADDED && fRescan) {
        pwalletMain->MarkDirty();
        pwalletMain->ScanForWalletTransactions(chainActive.Genesis(), true, false);
        pwalletMain->ReacceptWalletTransactions();
    }
    std::vector<unsigned char> raw(1, id.scheme);
    raw.insert(raw.end(), id.hash.begin(), id.hash.end());
    UniValue o(UniValue::VOBJ);
    o.pushKV("scheme", (int)id.scheme);
    o.pushKV("keyhash", HexStr(id.hash.begin(), id.hash.end()));
    o.pushKV("pqkeyid", HexStr(raw));
    o.pushKV("address", KeyIO(Params()).EncodeDestination(id));
    o.pushKV("index", storedIndex == CPQKey::PQ_INDEX_NONE ? UniValue() : UniValue((int64_t)storedIndex));
    o.pushKV("added", r == PQImport::ADDED);
    return o;
}

UniValue importwallet(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "importwallet \"filename\"\n"
            "\nImports taddr keys from a wallet dump file (see z_exportwallet).\n"
            "\nArguments:\n"
            "1. \"filename\"    (string, required) The wallet file\n"
            "\nExamples:\n"
            "\nDump the wallet\n"
            + HelpExampleCli("z_exportwallet", "\"nameofbackup\"") +
            "\nImport the wallet\n"
            + HelpExampleCli("importwallet", "\"path/to/exportdir/nameofbackup\"") +
            "\nImport using the json rpc call\n"
            + HelpExampleRpc("importwallet", "\"path/to/exportdir/nameofbackup\"")
        );

	return importwallet_impl(params, false);
}

/** A dump's vaultbuild= transaction (07/F-5); false when it does not decode. */
static bool DecodeVaultBuildHex(CTransaction& tx, const std::string& hex)
{
    try {
        DecodeHexTx(tx, hex);   // 6.20.0: throws instead of returning false
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

UniValue importwallet_impl(const UniValue& params, bool fImportZKeys)
{
    if (fPruneMode)
        throw JSONRPCError(RPC_WALLET_ERROR, "Importing wallets is disabled in pruned mode");

    YellowbackReconcileOnExit yellowbackReconcile;   // H8 (6.20.0 port: importwallet imports spending keys and rescans, as importprivkey does)
    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    ifstream file;
    // Binary mode: keep tellg/seekg byte offsets consistent regardless of the
    // file's line endings. In text mode on Windows, CRLF translation desyncs
    // the read position and corrupts parsed lines. CR is stripped per line below.
    file.open(params[0].get_str().c_str(), std::ios::in | std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        int err = errno;
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Cannot open wallet dump file %s: %s",
                      params[0].get_str(), std::strerror(err)));
    }

    int64_t nTimeBegin = chainActive.Tip()->GetBlockTime();

    bool fGood = true;

    int64_t nFilesize = std::max((int64_t)1, (int64_t)file.tellg());
    file.seekg(0, file.beg);

    bool fVaultMarkFailed = false;                  // MarkVaultKeyImported could not write (07/F-5)
    std::vector<VaultSetSigRecord> vVaultSetSigs;

    const auto& chainparams = Params();
    KeyIO keyIO(chainparams);

    pwalletMain->ShowProgress(_("Importing..."), 0); // show progress dialog in GUI
    int64_t nBytesRead = 0;
    while (file.good()) {
        pwalletMain->ShowProgress("", std::max(1, std::min(99, (int)(((double)nBytesRead / (double)nFilesize) * 100))));
        std::string line;
        std::getline(file, line);
        nBytesRead += (int64_t)line.size() + 1; // +1 for the consumed newline
        // The file may have been written with CRLF line endings (e.g. produced
        // on Windows). We open in binary mode for consistent tellg/seekg byte
        // offsets, so strip any trailing CR that getline leaves behind.
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty() || line[0] == '#')
            continue;

        std::vector<std::string> vstr;
        boost::split(vstr, line, boost::is_any_of(" "));

        // The vault set sign-once history and the wallet's remembered vault builds (07/F-5, 01/V-2): dumpwallet's
        // "vaultsetsigs=<n>", "vaultsetsig=<setid>:<txid>:<n>:<role>:<sighash>", "vaultbuild=<txid>:<n>:<hex>" and
        // "vaultrecipient=<hash>:<script hex>" lines. Older nodes skip them.
        if (boost::algorithm::starts_with(vstr[0], "vaultsetsigs=")) {
            continue;                               // informative only: an import never clears the restore marker (S2)
        }
        if (boost::algorithm::starts_with(vstr[0], "vaultsetsig=")) {
            std::vector<std::string> f;
            boost::split(f, vstr[0].substr(12), boost::is_any_of(":"));
            int64_t n = 0, role = 0;
            if (f.size() != 5 || !IsHex(f[0]) || f[0].size() != 64 || !IsHex(f[1]) || f[1].size() != 64 || !ParseInt64(f[2], &n) ||
                n < 0 || n > 0xffffffffLL || !ParseInt64(f[3], &role) || role < 1 || role > 2 || !IsHex(f[4]) || f[4].size() != 64)
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "malformed vaultsetsig line: " + vstr[0]);
            VaultSetSigRecord r;
            r.setId = uint256S(f[0]);
            r.prevout = COutPoint(uint256S(f[1]), (uint32_t)n);
            r.role = (uint8_t)role;
            const std::vector<unsigned char> sh = ParseHex(f[4]);
            r.sighash = uint256(sh);
            vVaultSetSigs.push_back(r);
            continue;
        }
        if (boost::algorithm::starts_with(vstr[0], "vaultbuild=")) {
            std::vector<std::string> f;
            boost::split(f, vstr[0].substr(11), boost::is_any_of(":"));
            int64_t n = 0;
            CTransaction tx;
            if (f.size() != 3 || !IsHex(f[0]) || f[0].size() != 64 || !ParseInt64(f[1], &n) || n < 0 || n > 0xffffffffLL || !DecodeVaultBuildHex(tx, f[2])) {
                fGood = false;
                continue;
            }
            const COutPoint templ(uint256S(f[0]), (uint32_t)n);
            if (!pwalletMain->mapVaultBuilds.count(templ)) {
                const CMutableTransaction mtx(tx);
                if (!CWalletDB(pwalletMain->strWalletFile).WriteVaultBuild(templ, mtx)) fGood = false;
                else pwalletMain->LoadVaultBuild(templ, mtx);
            }
            continue;
        }
        if (boost::algorithm::starts_with(vstr[0], "vaultrecipient=")) {
            std::vector<std::string> f;
            boost::split(f, vstr[0].substr(15), boost::is_any_of(":"));
            if (f.size() != 2 || !IsHex(f[0]) || f[0].size() != 64 || !IsHex(f[1])) {
                fGood = false;
                continue;
            }
            const uint256 h = uint256S(f[0]);
            const std::vector<unsigned char> b = ParseHex(f[1]);
            const CScript script(b.begin(), b.end());
            if (!pwalletMain->mapVaultRecipients.count(h)) {
                if (!CWalletDB(pwalletMain->strWalletFile).WriteVaultRecipient(h, script)) fGood = false;
                else pwalletMain->mapVaultRecipients[h] = script;
            }
            continue;
        }
        if (vstr.size() < 2)
            continue;

        // Let's see if the address is a valid Zcash spending key
        if (fImportZKeys) {
            auto spendingkey = keyIO.DecodeSpendingKey(vstr[0]);
            int64_t nTime = DecodeDumpTime(vstr[1]);
            // Only include hdKeypath and seedFpStr if we have both
            std::optional<std::string> hdKeypath = (vstr.size() > 3) ? std::optional<std::string>(vstr[2]) : std::nullopt;
            std::optional<std::string> seedFpStr = (vstr.size() > 3) ? std::optional<std::string>(vstr[3]) : std::nullopt;
            if (spendingkey.has_value()) {
                auto addResult = std::visit(
                    AddSpendingKeyToWallet(pwalletMain, chainparams.GetConsensus(), nTime, hdKeypath, seedFpStr, true, true), spendingkey.value());
                if (addResult == KeyAlreadyExists){
                    LogPrint("zrpc", "Skipping import of zaddr (key already present)\n");
                } else if (addResult == KeyNotAdded) {
                    // Something went wrong
                    fGood = false;
                }
                continue;
            } else {
                LogPrint("zrpc", "Importing detected an error: invalid spending key. Trying as a transparent key...\n");
                // Not a valid spending key, so carry on and see if it's a Zcash style t-address.
            }
        }

        // A post-quantum key (dumpwallet's "pqseed=<scheme>:<index>:<seed hex>", quantum plan §4.6).
        if (boost::algorithm::starts_with(vstr[0], "pqseed=")) {
            std::vector<std::string> f;
            boost::split(f, vstr[0].substr(7), boost::is_any_of(":"));
            if (f.size() != 3 || !IsHex(f[2])) {
                fGood = false;
                continue;
            }
            std::vector<unsigned char> seedBytes = ParseHex(f[2]);
            const CPQKey::Secret seed(seedBytes.begin(), seedBytes.end());
            memory_cleanse(seedBytes.data(), seedBytes.size());
            int64_t scheme = 0, index = 0;
            if (!ParseInt64(f[0], &scheme) || !ParseInt64(f[1], &index)) {
                fGood = false;
                continue;
            }
            // Quantum review F-1: the dump's index belongs to the seed the key came from (ImportPQKeySeed).
            const int64_t nTime = DecodeDumpTime(vstr[1]);
            CPQKeyID id;
            const PQImport r = ImportPQKeySeed(scheme, index, seed, nTime, id);
            if (r == PQImport::PRESENT) {
                LogPrintf("Skipping import of a post-quantum key (key already present)\n");
            } else if (r == PQImport::ADDED) {
                nTimeBegin = std::min(nTimeBegin, nTime);
            } else {
                fGood = false;
            }
            continue;
        }

        CKey key = keyIO.DecodeSecret(vstr[0]);
        if (!key.IsValid())
            continue;
        CPubKey pubkey = key.GetPubKey();
        assert(key.VerifyPubKey(pubkey));
        CKeyID keyid = pubkey.GetID();
        if (pwalletMain->HaveKey(keyid)) {
            LogPrintf("Skipping import of %s (key already present)\n", keyIO.EncodeDestination(keyid));
            continue;
        }
        int64_t nTime = DecodeDumpTime(vstr[1]);
        std::string strLabel;
        bool fLabel = true;
        for (unsigned int nStr = 2; nStr < vstr.size(); nStr++) {
            if (boost::algorithm::starts_with(vstr[nStr], "#"))
                break;
            if (vstr[nStr] == "change=1")
                fLabel = false;
            if (vstr[nStr] == "reserve=1")
                fLabel = false;
            if (boost::algorithm::starts_with(vstr[nStr], "label=")) {
                strLabel = DecodeDumpString(vstr[nStr].substr(6));
                fLabel = true;
            }
        }
        LogPrintf("Importing %s...\n", keyIO.EncodeDestination(keyid));
        if (!pwalletMain->AddKeyPubKey(key, pubkey)) {
            fGood = false;
            continue;
        }
        if (!MarkVaultKeyImported(*pwalletMain, pubkey)) fVaultMarkFailed = true;
        pwalletMain->mapKeyMetadata[keyid].nCreateTime = nTime;
        if (fLabel)
            pwalletMain->SetAddressBook(keyid, strLabel, "receive");
        nTimeBegin = std::min(nTimeBegin, nTime);
    }
    file.close();
    pwalletMain->ShowProgress("", 100); // hide progress dialog in GUI

    // 07/F-5: the set sign-once history. A record that conflicts with this wallet's refuses the import (two signing
    // histories for one key are never merged). An imported member key sets the restore marker (MarkVaultKeyImported,
    // above); importing a history never clears it -- the dump may be stale (review S2): set_acknowledgerestore does.
    {
        int added = 0, present = 0;
        std::string conflict;
        if (!ImportVaultSetSigs(*pwalletMain, vVaultSetSigs, added, present, conflict))
            throw JSONRPCError(RPC_WALLET_ERROR, conflict);
        if (fVaultMarkFailed)
            throw JSONRPCError(RPC_WALLET_ERROR, "cannot write the vault sign-once restore marker");
        if (added || present) LogPrintf("Imported %d vault set sign-once records (%d already present)\n", added, present);
    }

    CBlockIndex *pindex = chainActive.Tip();
    while (pindex && pindex->pprev && pindex->GetBlockTime() > nTimeBegin - TIMESTAMP_WINDOW) {
        pindex = pindex->pprev;
    }

    if (!pwalletMain->nTimeFirstKey || nTimeBegin < pwalletMain->nTimeFirstKey)
        pwalletMain->nTimeFirstKey = nTimeBegin;

    LogPrintf("Rescanning last %i blocks\n", chainActive.Height() - pindex->nHeight + 1);
    pwalletMain->ScanForWalletTransactions(pindex, false, false);
    pwalletMain->MarkDirty();

    // Imported wallet dump typically contains keys that did not originate from
    // this wallet's mnemonic seed; mark the wallet so getwalletinfo reports
    // a partial-backup warning. Cheap to over-report (the flag is sticky).
    pwalletMain->SetHasExternalImports();
    MaybeAutoExportAfterImport("importwallet");

    if (!fGood)
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding some keys to wallet");

    return NullUniValue;
}

UniValue dumpprivkey(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "dumpprivkey \"t-addr\"\n"
            "\nReveals the private key corresponding to 't-addr'.\n"
            "Then the importprivkey can be used with this output\n"
            "\nArguments:\n"
            "1. \"t-addr\"   (string, required) The transparent address for the private key\n"
            "\nResult:\n"
            "\"key\"         (string) The private key\n"
            "\nExamples:\n"
            + HelpExampleCli("dumpprivkey", "\"myaddress\"")
            + HelpExampleCli("importprivkey", "\"mykey\"")
            + HelpExampleRpc("dumpprivkey", "\"myaddress\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    KeyIO keyIO(Params());

    std::string strAddress = params[0].get_str();
    CTxDestination dest = keyIO.DecodeDestination(strAddress);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Ycash address");
    }
    if (IsPQKeyDestination(dest)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "A post-quantum address has no WIF key; dumpwallet / z_exportwallet write its pqseed line");
    }
    const CKeyID *keyID = std::get_if<CKeyID>(&dest);
    if (!keyID) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    }
    CKey vchSecret;
    if (!pwalletMain->GetKey(*keyID, vchSecret)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    }
    return keyIO.EncodeSecret(vchSecret);
}


UniValue dumpwallet(const UniValue& params, bool fHelp)
{
    throw JSONRPCError(RPC_METHOD_NOT_FOUND, "dumpwallet has been removed. Use z_exportwallet instead.");
}

// Writes a complete z_exportwallet-format dump of pwalletMain to `exportfilepath`.
// Callers must hold cs_main and pwalletMain->cs_wallet, and must have unlocked
// the wallet beforehand. Throws JSONRPCError on filesystem failure.
static void WriteWalletDumpToFile(const fs::path& exportfilepath)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(pwalletMain->cs_wallet);

    ofstream file;
    file.open(exportfilepath.string().c_str());
    if (!file.is_open()) {
        int err = errno;
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Cannot open wallet dump file %s: %s",
                      exportfilepath.string(), std::strerror(err)));
    }

    std::map<CKeyID, int64_t> mapKeyBirth;
    std::set<CKeyID> setKeyPool;
    pwalletMain->GetKeyBirthTimes(mapKeyBirth);
    pwalletMain->GetAllReserveKeys(setKeyPool);

    // sort time/key pairs
    std::vector<std::pair<int64_t, CKeyID> > vKeyBirth;
    for (auto it = mapKeyBirth.begin(); it != mapKeyBirth.end(); it++) {
        vKeyBirth.push_back(std::make_pair(it->second, it->first));
    }
    mapKeyBirth.clear();
    std::sort(vKeyBirth.begin(), vKeyBirth.end());

    KeyIO keyIO(Params());

    file << strprintf("# Wallet dump created by Ycash %s\n", CLIENT_BUILD);
    file << strprintf("# * Created on %s\n", EncodeDumpTime(GetTime()));
    file << strprintf("# * Best block at time of backup was %i (%s),\n", chainActive.Height(), chainActive.Tip()->GetBlockHash().ToString());
    file << strprintf("#   mined on %s\n", EncodeDumpTime(chainActive.Tip()->GetBlockTime()));

    std::optional<MnemonicSeed> hdSeed = pwalletMain->GetMnemonicSeed();
    if (hdSeed.has_value()) {
        auto mSeed = hdSeed.value();
        file << strprintf(
                "# Emergency Recovery Information:\n"
                "# - recovery_phrase=\"%s\"\n"
                "# - language=%s\n"
                "# - fingerprint=%s\n",
                mSeed.GetMnemonic(),
                MnemonicSeed::LanguageName(mSeed.GetLanguage()),
                mSeed.Fingerprint().GetHex()
                );
    }

    std::optional<HDSeed> legacySeed = pwalletMain->GetLegacyHDSeed();
    if (legacySeed.has_value()) {
        auto rawSeed = legacySeed.value().RawSeed();
        file << strprintf(
                "# Legacy HD Seed:\n"
                "# - seed=%s\n"
                "# - fingerprint=%s\n",
                HexStr(rawSeed.begin(), rawSeed.end()),
                legacySeed.value().Fingerprint().GetHex()
                );
    }

    if (pwalletMain->HasExternalImports()) {
        file << "#\n";
        file << "# WARNING: This wallet contains imported keys that are NOT derived\n";
        file << "#   from the recovery phrase / HD seed above. Restoring from the\n";
        file << "#   recovery phrase ALONE will NOT recover funds held at those\n";
        file << "#   imported addresses. Keep this full dump file (or the imported\n";
        file << "#   private keys) backed up separately.\n";
    }

    file << "\n";
    for (auto it = vKeyBirth.begin(); it != vKeyBirth.end(); it++) {
        const CKeyID &keyid = it->second;
        std::string strTime = EncodeDumpTime(it->first);
        std::string strAddr = keyIO.EncodeDestination(keyid);
        CKey key;
        if (pwalletMain->GetKey(keyid, key)) {
            CKeyMetadata keyMeta = pwalletMain->mapKeyMetadata[keyid];
            file << strprintf("%s %s ", keyIO.EncodeSecret(key), strTime);
            if (pwalletMain->mapAddressBook.count(keyid)) {
                file << strprintf("label=%s", EncodeDumpString(pwalletMain->mapAddressBook[keyid].name));
            } else if (setKeyPool.count(keyid)) {
                file << "reserve=1";
            } else {
                file << "change=1";
            }
            file << strprintf(" # addr=%s", strAddr);
            if (!(keyMeta.hdKeypath.empty() || keyMeta.seedFp.IsNull())) {
                file << strprintf(" hdkeypath=%s seedfp=%s", keyMeta.hdKeypath, keyMeta.seedFp.GetHex());
            }
            file << "\n";
        }
    }
    file << "\n";

    // Post-quantum keys (quantum plan §4.6): the 48-byte keygen seed and the HD index; importwallet
    // (and z_importwallet) re-create the key pair from the seed. Older nodes skip these lines.
    {
        const yellowback::Params& yp = yellowback::ParamsForNetwork(Params().NetworkIDString());
        file << "# Post-quantum keys (pqseed=<scheme>:<index>:<seed>)\n";
        for (const CPQKeyID& id : pwalletMain->GetPQKeys()) {
            CPQKey pqkey;
            if (!pwalletMain->GetPQKey(id, pqkey))
                continue;
            const CPQKey::Secret& seed = pqkey.Seed();
            const int64_t nTime = pwalletMain->mapPQKeyCreateTime.count(id) ? pwalletMain->mapPQKeyCreateTime[id] : 0;
            std::vector<unsigned char> idBytes(1, id.scheme);
            idBytes.insert(idBytes.end(), id.hash.begin(), id.hash.end());
            file << strprintf("pqseed=%d:%u:%s %s # owner=%s addr=%s yecaddr=%s\n", (int)id.scheme, pqkey.Index(),
                              HexStr(seed.begin(), seed.end()), EncodeDumpTime(nTime),
                              HexStr(idBytes.begin(), idBytes.end()), yellowback::EncodeAddress(id, yp),
                              keyIO.EncodeDestination(id));   // the plain-YEC sq…/tq…/rq… form (D-Q-20)
        }
        file << "\n";
    }

    // The vault set sign-once history (07/F-5) and the remembered vault builds (01/V-2): a seed does not carry them,
    // and a restored member key that signs a different spend of an outpoint it already signed is slashed. Older
    // nodes skip these lines.
    {
        CWalletDB walletdb(pwalletMain->strWalletFile);
        std::vector<VaultSetSigRecord> recs;
        if (!walletdb.ListVaultSetSigs(recs))
            throw JSONRPCError(RPC_WALLET_ERROR, "cannot read the vault set sign-once records");
        file << "# Vault set sign-once history (vaultsetsig=<setid>:<txid>:<n>:<role>:<sighash>); import it before a restored\n";
        file << "# member key signs (doc/vault-rpc.md, \"Sign once\")\n";
        file << strprintf("vaultsetsigs=%u # records\n", (unsigned)recs.size());
        for (const VaultSetSigRecord& r : recs)
            file << strprintf("vaultsetsig=%s:%s:%u:%d:%s # %s\n", r.setId.GetHex(), r.prevout.hash.GetHex(), r.prevout.n, (int)r.role,
                              HexStr(r.sighash.begin(), r.sighash.end()), r.role == 1 ? "unlock" : "cancel");
        for (const auto& b : pwalletMain->mapVaultBuilds)
            file << strprintf("vaultbuild=%s:%u:%s # remembered vault build\n", b.first.hash.GetHex(), b.first.n, EncodeHexTx(CTransaction(b.second)));
        for (const auto& rcp : pwalletMain->mapVaultRecipients)
            file << strprintf("vaultrecipient=%s:%s # intent recipient\n", rcp.first.GetHex(), HexStr(rcp.second.begin(), rcp.second.end()));
        file << "\n";
    }

    std::set<libzcash::SproutPaymentAddress> sproutAddresses;
    pwalletMain->GetSproutPaymentAddresses(sproutAddresses);
    file << "\n";
    file << "# Zkeys\n";
    file << "\n";
    for (auto addr : sproutAddresses) {
        libzcash::SproutSpendingKey key;
        if (pwalletMain->GetSproutSpendingKey(addr, key)) {
            std::string strTime = EncodeDumpTime(pwalletMain->mapSproutZKeyMetadata[addr].nCreateTime);
            file << strprintf("%s %s # zaddr=%s\n", keyIO.EncodeSpendingKey(key), strTime, keyIO.EncodePaymentAddress(addr));
        }
    }
    std::set<libzcash::SaplingPaymentAddress> saplingAddresses;
    pwalletMain->GetSaplingPaymentAddresses(saplingAddresses);
    file << "\n";
    file << "# Sapling keys\n";
    file << "\n";
    for (auto addr : saplingAddresses) {
        libzcash::SaplingExtendedSpendingKey extsk;
        if (pwalletMain->GetSaplingExtendedSpendingKey(addr, extsk)) {
            auto ivk = extsk.expsk.full_viewing_key().in_viewing_key();
            CKeyMetadata keyMeta = pwalletMain->mapSaplingZKeyMetadata[ivk];
            std::string strTime = EncodeDumpTime(keyMeta.nCreateTime);
            file << strprintf("%s %s", keyIO.EncodeSpendingKey(extsk), strTime);
            // Keys imported with z_importkey do not have zip32 metadata
            if (!(keyMeta.hdKeypath.empty() || keyMeta.seedFp.IsNull())) {
                file << strprintf(" %s %s", keyMeta.hdKeypath, keyMeta.seedFp.GetHex());
            }
            file << strprintf(" # zaddr=%s\n", keyIO.EncodePaymentAddress(addr));
        }
    }
    file << "\n";

    file << "# End of dump\n";
    file.close();
}

// If -autoexportafterimport is enabled and -exportdir is configured, write a
// fresh wallet dump into the export dir. Called from import RPCs *after* the
// new key has been added (so the dump captures it). Best-effort: failures are
// logged but do not propagate, since the import itself has already succeeded.
//
// The caller must hold cs_main and pwalletMain->cs_wallet. The dump filename
// is `autoexport-<utc-timestamp>-<method>.dat`.
void MaybeAutoExportAfterImport(const std::string& method)
{
    if (!GetBoolArg("-autoexportafterimport", false)) {
        return;
    }

    fs::path exportdir;
    try {
        exportdir = GetExportDir();
    } catch (const std::runtime_error& e) {
        LogPrintf("MaybeAutoExportAfterImport: GetExportDir failed: %s\n", e.what());
        return;
    }
    if (exportdir.empty()) {
        LogPrintf("MaybeAutoExportAfterImport: -autoexportafterimport is set but "
                  "-exportdir is not configured; skipping auto-export.\n");
        return;
    }

    // Build filename: autoexport-YYYYMMDDTHHMMSSZ-<method>.dat. Use a
    // filesystem-safe basic ISO 8601 (no colons / dashes) so the file is
    // portable across Windows.
    fs::path target = exportdir / strprintf("autoexport-%s-%s.dat",
                                            DateTimeStrFormat("%Y%m%dT%H%M%SZ", GetTime()),
                                            method);
    if (fs::exists(target)) {
        LogPrintf("MaybeAutoExportAfterImport: %s already exists; skipping.\n",
                  target.string());
        return;
    }

    try {
        WriteWalletDumpToFile(target);
        LogPrintf("MaybeAutoExportAfterImport: wallet snapshot written to %s\n",
                  target.string());
    } catch (const std::exception& e) {
        LogPrintf("MaybeAutoExportAfterImport: failed to write %s: %s\n",
                  target.string(), e.what());
    }
}

UniValue z_exportwallet(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "z_exportwallet \"filename\"\n"
            "\nExports all wallet keys, for taddr and zaddr, in a human-readable format.  Overwriting an existing file is not permitted.\n"
            "\nArguments:\n"
            "1. \"filename\"    (string, required) The filename, saved in folder set by zcashd -exportdir option\n"
            "\nResult:\n"
            "\"path\"           (string) The full path of the destination file\n"
            "\nExamples:\n"
            + HelpExampleCli("z_exportwallet", "\"test\"")
            + HelpExampleRpc("z_exportwallet", "\"test\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    fs::path exportdir;
    try {
        exportdir = GetExportDir();
    } catch (const std::runtime_error& e) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, e.what());
    }
    if (exportdir.empty()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot export wallet until the zcashd -exportdir option has been set");
    }
    std::string unclean = params[0].get_str();
    std::string clean = SanitizeFilename(unclean);
    if (clean.compare(unclean) != 0) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Filename is invalid as only alphanumeric characters are allowed.  Try '%s' instead.", clean));
    }
    fs::path exportfilepath = exportdir / clean;

    if (fs::exists(exportfilepath)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot overwrite existing file " + exportfilepath.string());
    }

    WriteWalletDumpToFile(exportfilepath);
    return exportfilepath.string();
}


UniValue z_importkey(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "z_importkey \"zkey\" ( rescan startHeight )\n"
            "\nAdds a zkey (as returned by z_exportkey) to your wallet."
            "\nImport of Orchard keys is not supported.\n"
            "\nArguments:\n"
            "1. \"zkey\"             (string, required) The zkey (see z_exportkey)\n"
            "2. rescan             (string, optional, default=\"whenkeyisnew\") Rescan the wallet for transactions - can be \"yes\", \"no\" or \"whenkeyisnew\"\n"
            "3. startHeight        (numeric, optional, default=0) Block height to start rescan from\n"
            "\nNote: This call can take a long time to complete if rescan is true.\n"
            "\nResult:\n"
            "{\n"
            "  \"address_type\" : \"xxxx\",                 (string) \"sprout\" or \"sapling\"\n"
            "  \"type\" : \"xxxx\",                         (string) \"sprout\" or \"sapling\" (DEPRECATED, legacy attribute)\n"
            "  \"address\" : \"address|DefaultAddress\",    (string) The address corresponding to the spending key (for Sapling, this is the default address).\n"
            "}\n"
            "\nExamples:\n"
            "\nExport a zkey\n"
            + HelpExampleCli("z_exportkey", "\"myaddress\"") +
            "\nImport the zkey with rescan\n"
            + HelpExampleCli("z_importkey", "\"mykey\"") +
            "\nImport the zkey with partial rescan\n"
            + HelpExampleCli("z_importkey", "\"mykey\" whenkeyisnew 30000") +
            "\nRe-import the zkey with longer partial rescan\n"
            + HelpExampleCli("z_importkey", "\"mykey\" yes 20000") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("z_importkey", "\"mykey\", \"no\"")
        );

    if (fPruneMode)
        throw JSONRPCError(RPC_WALLET_ERROR, "Importing keys is disabled in pruned mode");

    YellowbackReconcileOnExit yellowbackReconcile;   // H8: lock imported YED once the wallet lock is gone
    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    // Whether to perform rescan after import
    bool fRescan = true;
    bool fIgnoreExistingKey = true;
    if (params.size() > 1) {
        auto rescan = params[1].get_str();
        if (rescan.compare("whenkeyisnew") != 0) {
            fIgnoreExistingKey = false;
            if (rescan.compare("yes") == 0) {
                fRescan = true;
            } else if (rescan.compare("no") == 0) {
                fRescan = false;
            } else {
                // Handle older API
                UniValue jVal;
                if (!jVal.read(std::string("[")+rescan+std::string("]")) ||
                    !jVal.isArray() || jVal.size()!=1 || !jVal[0].isBool()) {
                    throw JSONRPCError(
                        RPC_INVALID_PARAMETER,
                        "rescan must be \"yes\", \"no\" or \"whenkeyisnew\"");
                }
                fRescan = jVal[0].getBool();
            }
        }
    }

    // Height to rescan from
    int nRescanHeight = 0;
    if (params.size() > 2)
        nRescanHeight = params[2].get_int();
    if (nRescanHeight < 0 || nRescanHeight > chainActive.Height()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");
    }

    const auto& chainparams = Params();
    KeyIO keyIO(chainparams);
    string strSecret = params[0].get_str();
    auto spendingkey = keyIO.DecodeSpendingKey(strSecret);
    if (!spendingkey.has_value()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid spending key");
    }

    auto addrInfo = std::visit(libzcash::AddressInfoFromSpendingKey{}, spendingkey.value());
    UniValue result(UniValue::VOBJ);
    result.pushKV("address_type", addrInfo.first);
    if (fEnableAddrTypeField) {
        result.pushKV("type", addrInfo.first); //deprecated
    }
    result.pushKV("address", keyIO.EncodePaymentAddress(addrInfo.second));

    // Sapling support
    auto addResult = std::visit(AddSpendingKeyToWallet(pwalletMain, chainparams.GetConsensus()), spendingkey.value());
    if (addResult == KeyAlreadyExists && fIgnoreExistingKey) {
        return result;
    }
    pwalletMain->MarkDirty();
    if (addResult == KeyNotAdded) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding spending key to wallet");
    }

    // whenever a key is imported, we need to scan the whole chain
    pwalletMain->nTimeFirstKey = 1; // 0 would be considered 'no value'

    // Imported key is not derived from the mnemonic seed; mark the wallet
    // so getwalletinfo reports a partial-backup warning.
    pwalletMain->SetHasExternalImports();
    MaybeAutoExportAfterImport("z_importkey");

    // We want to scan for transactions and notes
    if (fRescan) {
        pwalletMain->ScanForWalletTransactions(chainActive[nRescanHeight], true, false);
    }

    return result;
}

UniValue z_importviewingkey(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "z_importviewingkey \"vkey\" ( rescan startHeight )\n"
            "\nAdds a viewing key (as returned by z_exportviewingkey) to your wallet.\n"
            "\nArguments:\n"
            "1. \"vkey\"             (string, required) The viewing key (see z_exportviewingkey)\n"
            "2. rescan             (string, optional, default=\"whenkeyisnew\") Rescan the wallet for transactions - can be \"yes\", \"no\" or \"whenkeyisnew\"\n"
            "3. startHeight        (numeric, optional, default=0) Block height to start rescan from\n"
            "\nNote: This call can take a long time to complete if rescan is true. Import of Unified viewing keys is not yet supported.\n"
            "\nResult:\n"
            "{\n"
            "  \"address_type\" : \"xxxx\",                 (string) \"sprout\" or \"sapling\"\n"
            "  \"type\" : \"xxxx\",                         (string) \"sprout\" or \"sapling\" (DEPRECATED, legacy attribute)\n"
            "  \"address\" : \"address|DefaultAddress\",    (string) The address corresponding to the viewing key (for Sapling, this is the default address).\n"
            "}\n"
            "\nExamples:\n"
            "\nImport a viewing key\n"
            + HelpExampleCli("z_importviewingkey", "\"vkey\"") +
            "\nImport the viewing key without rescan\n"
            + HelpExampleCli("z_importviewingkey", "\"vkey\", no") +
            "\nImport the viewing key with partial rescan\n"
            + HelpExampleCli("z_importviewingkey", "\"vkey\" whenkeyisnew 30000") +
            "\nRe-import the viewing key with longer partial rescan\n"
            + HelpExampleCli("z_importviewingkey", "\"vkey\" yes 20000") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("z_importviewingkey", "\"vkey\", \"no\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    // Whether to perform rescan after import
    bool fRescan = true;
    bool fIgnoreExistingKey = true;
    if (params.size() > 1) {
        auto rescan = params[1].get_str();
        if (rescan.compare("whenkeyisnew") != 0) {
            fIgnoreExistingKey = false;
            if (rescan.compare("no") == 0) {
                fRescan = false;
            } else if (rescan.compare("yes") != 0) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    "rescan must be \"yes\", \"no\" or \"whenkeyisnew\"");
            }
        }
    }

    // Height to rescan from
    int nRescanHeight = 0;
    if (params.size() > 2) {
        nRescanHeight = params[2].get_int();
    }
    if (nRescanHeight < 0 || nRescanHeight > chainActive.Height()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");
    }

    const auto& chainparams = Params();
    KeyIO keyIO(chainparams);
    string strVKey = params[0].get_str();
    auto viewingkey = keyIO.DecodeViewingKey(strVKey);
    if (!viewingkey.has_value()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid viewing key");
    }

    auto addrInfo = std::visit(libzcash::AddressInfoFromViewingKey(chainparams), viewingkey.value());
    UniValue result(UniValue::VOBJ);
    const string strAddress = keyIO.EncodePaymentAddress(addrInfo.second);
    result.pushKV("address_type", addrInfo.first);
    if (fEnableAddrTypeField) {
        result.pushKV("type", addrInfo.first); //deprecated
    }
    result.pushKV("address", strAddress);

    auto addResult = std::visit(AddViewingKeyToWallet(pwalletMain, true), viewingkey.value());
    if (addResult == SpendingKeyExists) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            "The wallet already contains the private key for this viewing key (address: " + strAddress + ")");
    } else if (addResult == KeyAlreadyExists && fIgnoreExistingKey) {
        return result;
    }
    pwalletMain->MarkDirty();
    if (addResult == KeyNotAdded) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding viewing key to wallet");
    }

    // We want to scan for transactions and notes
    if (fRescan) {
        pwalletMain->ScanForWalletTransactions(chainActive[nRescanHeight], true, false);
    }

    return result;
}

UniValue z_exportkey(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "z_exportkey \"zaddr\"\n"
            "\nReveals the zkey corresponding to 'zaddr'.\n"
            "Then the z_importkey can be used with this output\n"
            "\nArguments:\n"
            "1. \"zaddr\"   (string, required) The zaddr for the private key\n"
            "\nResult:\n"
            "\"key\"                  (string) The private key\n"
            "\nExamples:\n"
            + HelpExampleCli("z_exportkey", "\"myaddress\"")
            + HelpExampleCli("z_importkey", "\"mykey\"")
            + HelpExampleRpc("z_exportkey", "\"myaddress\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();

    KeyIO keyIO(Params());
    auto address = keyIO.DecodePaymentAddress(strAddress);
    if (!address.has_value()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid zaddr");
    }

    std::string result = examine(address.value(), match {
        [&](const CKeyID& addr) {
            CKey key;
            if (pwalletMain->GetKey(addr, key)) {
                return keyIO.EncodeSecret(key);
            } else {
                throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not hold the private key for this address.");
            }
        },
        [&](const CScriptID& addr) {
            CScript redeemScript;
            if (pwalletMain->GetCScript(addr, redeemScript)) {
                return FormatScript(redeemScript);
            } else {
                throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not hold the redeem script for this P2SH address.");
            }
        },
        [&](const libzcash::SproutPaymentAddress& addr) {
            libzcash::SproutSpendingKey key;
            if (pwalletMain->GetSproutSpendingKey(addr, key)) {
                return keyIO.EncodeSpendingKey(key);
            } else {
                throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not hold the private spending key for this Sprout address");
            }
        },
        [&](const libzcash::SaplingPaymentAddress& addr) {
            libzcash::SaplingExtendedSpendingKey extsk;
            if (pwalletMain->GetSaplingExtendedSpendingKey(addr, extsk)) {
                return keyIO.EncodeSpendingKey(extsk);
            } else {
                throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not hold the private spending key for this Sapling address");
            }
        },
        [&](const libzcash::UnifiedAddress& ua) {
            throw JSONRPCError(
                    RPC_WALLET_ERROR,
                    "No serialized form is defined for unified spending keys. "
                    "Use the emergency recovery phrase for this wallet for backup purposes instead.");
            return std::string(); //unreachable, here to make the compiler happy
        }
    });
    return result;
}

UniValue z_exportviewingkey(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "z_exportviewingkey \"zaddr\"\n"
            "\nReturns the full viewing key corresponding to 'zaddr' in the format specified by\n"
            "https://zips.z.cash/protocol/protocol.pdf#addressandkeyencoding.\n"
            "z_importviewingkey can be used to import Sprout and Sapling exported in this format;\n"
            "import of unified viewing keys is not yet supported.\n"
            "\nArguments:\n"
            "1. \"zaddr\"   (string, required) The zaddr for the viewing key\n"
            "\nResult:\n"
            "\"vkey\"                  (string) The viewing key\n"
            "\nExamples:\n"
            + HelpExampleCli("z_exportviewingkey", "\"myaddress\"")
            + HelpExampleRpc("z_exportviewingkey", "\"myaddress\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();

    KeyIO keyIO(Params());
    auto address = keyIO.DecodePaymentAddress(strAddress);
    if (!address.has_value()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid zaddr");
    }

    auto vk = std::visit(GetViewingKeyForPaymentAddress(pwalletMain), address.value());
    if (vk) {
        return keyIO.EncodeViewingKey(vk.value());
    } else {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not hold private key or viewing key for this zaddr");
    }
}

// ---------------------------------------------------------------------------
// z_exportivk / z_importivk: Sapling incoming-viewing-key codec.
//
// Ported from ycash-official. Closes the round-trip asymmetry where
// z_exportviewingkey emits a full viewing key ("zviews...") but the smaller
// incoming-viewing-key ("zivks...") form was inaccessible from RPC. Used by
// YecWallet (Qt GUI) and exchange tooling that monitors shielded deposits
// via IVK-only keys.
//
// Operates on Sapling addresses only. Unified viewing keys have their own
// import/export path; Sprout viewing keys go through z_exportviewingkey
// (Sprout viewing keys carry the ivk inline anyway).
// ---------------------------------------------------------------------------

UniValue z_exportivk(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "z_exportivk \"zaddr\"\n"
            "\nReveals the Sapling incoming viewing key corresponding to 'zaddr'.\n"
            "Use z_importivk to re-import the resulting key.\n"
            "\nArguments:\n"
            "1. \"zaddr\"   (string, required) The Sapling zaddr for the viewing key\n"
            "\nResult:\n"
            "\"ivk\"        (string) The bech32-encoded Sapling incoming viewing key (\"zivks...\")\n"
            "\nExamples:\n"
            + HelpExampleCli("z_exportivk", "\"ys1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlknghgfflq\"")
            + HelpExampleRpc("z_exportivk", "\"ys1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlknghgfflq\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();
    const auto& chainparams = Params();
    KeyIO keyIO(chainparams);

    auto address = keyIO.DecodePaymentAddress(strAddress);
    if (!address.has_value()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid zaddr");
    }
    auto saplingAddr = std::get_if<libzcash::SaplingPaymentAddress>(&address.value());
    if (saplingAddr == nullptr) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "z_exportivk requires a Sapling address. For Sprout, use z_exportviewingkey.");
    }

    libzcash::SaplingIncomingViewingKey ivk;
    if (!pwalletMain->GetSaplingIncomingViewingKey(*saplingAddr, ivk)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not hold incoming viewing key for this zaddr");
    }
    return keyIO.EncodeIVK(ivk);
}

UniValue z_importivk(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "z_importivk \"ivk\" \"zaddr\" ( rescan startHeight )\n"
            "\nAdds a Sapling incoming viewing key (as returned by z_exportivk) to the wallet.\n"
            "Because the ivk alone is insufficient to recover the corresponding payment\n"
            "address, the zaddr that the key belongs to must be passed explicitly.\n"
            "\nArguments:\n"
            "1. \"ivk\"             (string, required) The incoming viewing key (\"zivks...\")\n"
            "2. \"zaddr\"           (string, required) The Sapling zaddr the ivk belongs to.\n"
            "3. rescan             (string, optional, default=\"whenkeyisnew\") Rescan the wallet for transactions - \"yes\", \"no\" or \"whenkeyisnew\"\n"
            "4. startHeight        (numeric, optional, default=0) Block height to start the rescan from\n"
            "\nResult:\n"
            "{\n"
            "  \"address\": \"...\"   (string) The Sapling zaddr the ivk was imported for\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("z_importivk", "\"zivks...\" \"ys1...\" no")
            + HelpExampleRpc("z_importivk", "\"zivks...\", \"ys1...\"")
        );

    if (fPruneMode)
        throw JSONRPCError(RPC_WALLET_ERROR, "Importing keys is disabled in pruned mode");

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    bool fRescan = true;
    bool fIgnoreExistingKey = true;
    if (params.size() > 2 && !params[2].isNull()) {
        auto rescan = params[2].get_str();
        if (rescan.compare("whenkeyisnew") != 0) {
            fIgnoreExistingKey = false;
            if (rescan.compare("yes") == 0) {
                fRescan = true;
            } else if (rescan.compare("no") == 0) {
                fRescan = false;
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "rescan must be \"yes\", \"no\" or \"whenkeyisnew\"");
            }
        }
    }

    int nRescanHeight = 0;
    if (params.size() > 3 && !params[3].isNull()) {
        nRescanHeight = params[3].get_int();
        if (nRescanHeight < 0 || nRescanHeight > chainActive.Height()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");
        }
    }

    const auto& chainparams = Params();
    KeyIO keyIO(chainparams);

    auto ivkOpt = keyIO.DecodeIVK(params[0].get_str());
    if (!ivkOpt.has_value()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Sapling incoming viewing key");
    }
    auto address = keyIO.DecodePaymentAddress(params[1].get_str());
    if (!address.has_value()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid zaddr");
    }
    auto saplingAddr = std::get_if<libzcash::SaplingPaymentAddress>(&address.value());
    if (saplingAddr == nullptr) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "z_importivk requires a Sapling address.");
    }

    // Confirm the supplied ivk actually corresponds to the supplied zaddr.
    // SaplingIncomingViewingKey::address(diversifier) returns the zaddr for a
    // given diversifier, but here we have the address and want to verify the
    // ivk produces it. Cheapest correct check: round-trip via the keystore's
    // own derivation -- if the wallet successfully stores the (ivk, addr)
    // pair, addresses-by-ivk lookup will find it. For an unverified pair we
    // accept on faith: an ivk + addr mismatch makes the key useless but isn't
    // a security risk (no spend authority involved).
    libzcash::SaplingIncomingViewingKey ivk = ivkOpt.value();

    bool keyAlreadyPresent = pwalletMain->HaveSaplingIncomingViewingKey(*saplingAddr);
    if (keyAlreadyPresent && fIgnoreExistingKey) {
        UniValue result(UniValue::VOBJ);
        result.pushKV("address", keyIO.EncodePaymentAddress(*saplingAddr));
        return result;
    }

    if (!pwalletMain->AddSaplingPaymentAddress(ivk, *saplingAddr)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding Sapling incoming viewing key to wallet");
    }
    pwalletMain->MarkDirty();
    pwalletMain->nTimeFirstKey = 1;

    // Imported viewing keys have no spending capability and so do not degrade
    // the recovery-phrase backup the way an imported spending key would. We
    // intentionally do NOT call SetHasExternalImports() or
    // MaybeAutoExportAfterImport() here.

    if (fRescan) {
        pwalletMain->ScanForWalletTransactions(chainActive[nRescanHeight], true, false);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("address", keyIO.EncodePaymentAddress(*saplingAddr));
    return result;
}

// ---------------------------------------------------------------------------
// Diversified Sapling addresses.
//
// Ported from ycash-official b9f0860fb (2021). A Sapling spending key can
// derive many unlinkable payment addresses that all share one IVK/FVK
// (different ZIP-32 diversifier indices). This is the pre-unified-address
// mechanism for "many receive addresses, one key" -- the exact need a
// per-user-deposit-address exchange has. Upstream Zcash deleted these RPCs
// in favour of unified-address accounts, but those are NU5-gated and Ycash
// does not expose them, so on Ycash this is the only working option.
//
// Modernized vs. the 2021 original:
//   * No hand-rolled arith_uint88 loop. better-ycash's diversifier_index_t
//     has succ() (nullopt on 88-bit overflow) so the iteration is naturally
//     bounded -- the unbounded `while(true)` in the original is gone.
//   * GetSaplingExtendedSpendingKey(addr, ...) replaces the
//     GetSpendingKeyForPaymentAddress visitor + std::get dance.
//   * AddSaplingPaymentAddress(ivk, addr) is the renamed
//     AddSaplingIncomingViewingKey.
// ---------------------------------------------------------------------------

UniValue z_getalldiversifiedaddresses(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "z_getalldiversifiedaddresses \"zaddr\"\n"
            "\nReturns every Sapling address in the wallet that shares the same\n"
            "spending key (IVK/FVK) as the given address -- i.e. all of its peer\n"
            "diversified addresses.\n"
            "\nArguments:\n"
            "1. \"zaddr\"   (string, required) A Sapling address held by the wallet\n"
            "\nResult:\n"
            "[\n"
            "  \"zaddr\"   (string) a peer diversified Sapling address\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("z_getalldiversifiedaddresses", "\"ys1...\"")
            + HelpExampleRpc("z_getalldiversifiedaddresses", "\"ys1...\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    KeyIO keyIO(Params());
    auto decoded = keyIO.DecodePaymentAddress(params[0].get_str());
    if (!decoded.has_value()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid zaddr");
    }
    auto inSapling = std::get_if<libzcash::SaplingPaymentAddress>(&decoded.value());
    if (inSapling == nullptr) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "z_getalldiversifiedaddresses requires a Sapling address");
    }

    libzcash::SaplingIncomingViewingKey inIvk;
    libzcash::SaplingExtendedFullViewingKey inXfvk;
    if (!pwalletMain->GetSaplingIncomingViewingKey(*inSapling, inIvk) ||
        !pwalletMain->GetSaplingFullViewingKey(inIvk, inXfvk)) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "Wallet does not hold the viewing key for this zaddr");
    }

    UniValue ret(UniValue::VARR);
    std::set<libzcash::SaplingPaymentAddress> addresses;
    pwalletMain->GetSaplingPaymentAddresses(addresses);
    for (const auto& addr : addresses) {
        libzcash::SaplingIncomingViewingKey ivk;
        libzcash::SaplingExtendedFullViewingKey xfvk;
        if (pwalletMain->GetSaplingIncomingViewingKey(addr, ivk) &&
            pwalletMain->GetSaplingFullViewingKey(ivk, xfvk) &&
            ivk == inIvk && xfvk == inXfvk) {
            ret.push_back(keyIO.EncodePaymentAddress(addr));
        }
    }
    return ret;
}

UniValue z_getnewdiversifiedaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "z_getnewdiversifiedaddress \"zaddr\"\n"
            "\nDerives and adds to the wallet a new Sapling address that shares the\n"
            "same spending key as the given address (a new diversified address).\n"
            "\nArguments:\n"
            "1. \"zaddr\"   (string, required) An existing Sapling address in the wallet\n"
            "\nResult:\n"
            "\"zaddr\"      (string) the newly derived diversified Sapling address\n"
            "\nExamples:\n"
            + HelpExampleCli("z_getnewdiversifiedaddress", "\"ys1...\"")
            + HelpExampleRpc("z_getnewdiversifiedaddress", "\"ys1...\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureWalletIsUnlocked();

    KeyIO keyIO(Params());
    auto decoded = keyIO.DecodePaymentAddress(params[0].get_str());
    if (!decoded.has_value()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid zaddr");
    }
    auto inSapling = std::get_if<libzcash::SaplingPaymentAddress>(&decoded.value());
    if (inSapling == nullptr) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "z_getnewdiversifiedaddress requires a Sapling address");
    }

    libzcash::SaplingExtendedSpendingKey espk;
    if (!pwalletMain->GetSaplingExtendedSpendingKey(*inSapling, espk)) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "Wallet does not hold the spending key for this zaddr");
    }

    auto xfvk = espk.ToXFVK();

    // Walk diversifier indices from the one after this address's own
    // diversifier, skipping (a) indices that produce no valid address and
    // (b) addresses already in the wallet, until we mint a fresh one.
    // diversifier_index_t::succ() returns nullopt on 88-bit overflow, so the
    // loop is bounded -- no unbounded while(true) like the 2021 original.
    libzcash::diversifier_index_t j(0);
    {
        // Start the search just past the input address's own diversifier so
        // we don't re-test indices we already know are taken by it.
        auto dec = xfvk.DecryptDiversifier(*inSapling);
        if (dec.has_value()) {
            auto next = dec.value().first.succ();
            if (next.has_value()) {
                j = next.value();
            }
        }
    }

    while (true) {
        auto maybeAddr = xfvk.Address(j);
        if (maybeAddr.has_value()) {
            const libzcash::SaplingPaymentAddress& addr = maybeAddr.value();
            libzcash::PaymentAddress pa(addr);
            if (!std::visit(PaymentAddressBelongsToWallet(pwalletMain), pa)) {
                if (!pwalletMain->AddSaplingPaymentAddress(
                        espk.expsk.full_viewing_key().in_viewing_key(), addr)) {
                    throw JSONRPCError(RPC_WALLET_ERROR,
                                       "Failed to add diversified address to wallet");
                }
                return keyIO.EncodePaymentAddress(addr);
            }
        }
        auto next = j.succ();
        if (!next.has_value()) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                               "Diversifier space exhausted; no new address could be derived");
        }
        j = next.value();
    }
}
