// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The argument table (src/rpc/common.h) against the registered RPC methods.
//
// Both ycash-cli (src/rpc/client.cpp, "Unknown RPC method") and the server
// (src/rpc/server.cpp, "Parameters for <method> not found") look every call up
// in rpcCvtTable, so a registered method without a row cannot be called at all.
// 6.22.0-beta1 shipped getunconfirmedbalance that way (beta2 list item 12, a
// defect inherited from the 6.20.0 baseline). This suite fails on any such gap,
// in either direction.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "rpc/common.h"
#include "rpc/register.h"
#include "rpc/server.h"
#include "wallet/test/wallet_test_fixture.h"
#include "yellowback/index.h"

#include "test/test_util.h"

#include <boost/test/unit_test.hpp>

#include <map>
#include <set>
#include <string>

namespace {

// Registered methods that deliberately have no row, with the reason. Each one
// is unreachable through ycash-cli and the JSON-RPC server, by design.
const std::map<std::string, std::string> REGISTERED_WITHOUT_ROW = {
    // Upstream zcashd removed dumpwallet (265145145, "Remove `dumpwallet` RPC
    // method") and left the handler as a tombstone that points to
    // z_exportwallet; it was never given a row, so callers get "Unknown RPC
    // method" (cli) or the internal "Parameters ... not found" error (server)
    // instead of the tombstone's message. Ycash keeps the method removed and
    // documents z_exportwallet; the qa framework notes "6.20.0: no dumpwallet".
    // Behaviour is kept as shipped; recorded in the 6.20.0 upstream defect
    // report (section 3.9).
    {"dumpwallet", "removed upstream; tombstone handler, no row (use z_exportwallet)"},
};

// Rows whose method is registered only in some build configurations. The
// commands tables have one conditional block outside the wallet (this suite is
// compiled only with ENABLE_WALLET, which covers vault.cpp's wallet block):
// src/rpc/mining.cpp registers getgenerate / setgenerate / generate only
// under ENABLE_MINING (configure --disable-mining).
const std::set<std::string> ROWS_NOT_REGISTERED_IN_THIS_BUILD = {
#ifndef ENABLE_MINING
    "getgenerate", "setgenerate", "generate",
#endif
};

// Sets yellowback::g_yellowbackLive for one scope and restores it on every
// exit, so a throwing registration cannot leave it set for later suites.
class ScopedYellowbackLive {
    const bool saved;
public:
    ScopedYellowbackLive() : saved(yellowback::g_yellowbackLive) { yellowback::g_yellowbackLive = true; }
    ~ScopedYellowbackLive() { yellowback::g_yellowbackLive = saved; }
    ScopedYellowbackLive(const ScopedYellowbackLive&) = delete;
    ScopedYellowbackLive& operator=(const ScopedYellowbackLive&) = delete;
};

// Every method the node can register: the core and wallet sets already in
// tableRPC, plus the Yellowback sets, which init registers only where
// Yellowback is live (src/init.cpp) and so are absent from the test fixture.
std::set<std::string> AllRegisteredMethods()
{
    std::set<std::string> names;
    for (const auto& name : tableRPC.listCommands()) names.insert(name);

    CRPCTable yellowbackTable;
    {
        ScopedYellowbackLive live;
        RegisterYellowbackRPCCommands(yellowbackTable);
        RegisterYellowbackWalletRPCCommands(yellowbackTable);
    }
    for (const auto& name : yellowbackTable.listCommands()) names.insert(name);
    return names;
}

// The arguments a method's help signature (its first help line) names: {required, optional}. A quoted string, an
// object or an array is one argument; everything inside "( ... )" is optional. "..." (more of the same) is not counted.
// Rows whose count differs from a help signature that is abbreviated or out of date (the help is wrong, not the row:
// each call takes what its row says). Kept so that a new mismatch fails; each is a help defect to fix on its own. Empty
// since WALLET-FOLLOW-4 item 5 fixed the seven help lines that omitted an optional argument (getnewaddress,
// signrawtransaction, stop, yed_getbalance, yed_listunspent, z_listoperationids, zcbenchmark) and the parser learned
// that an angle-bracket placeholder with spaces (prioritisetransaction's <priority delta>) is one argument.
const std::map<std::string, std::string> HELP_SIGNATURE_DIFFERS = {};

std::pair<size_t, size_t> HelpArgumentCounts(const std::string& line)
{
    size_t required = 0, optional = 0;
    int parens = 0, depth = 0;
    bool quoted = false, angled = false, inToken = false, first = true;
    for (size_t i = 0; i < line.size(); i++) {
        const char c = line[i];
        if (quoted) {
            if (c == '\\') i++;
            else if (c == '"') quoted = false;
            continue;
        }
        if (angled) {                                                       // <priority delta>: one placeholder
            if (c == '>') angled = false;
            continue;
        }
        if (depth == 0) {
            if (c == ' ' || c == '\t') { inToken = false; continue; }
            if (c == '(') { parens++; inToken = false; continue; }
            if (c == ')') { parens--; inToken = false; continue; }
            if (!inToken) {
                inToken = true;
                if (first) first = false;                                   // the method name
                else if (line.compare(i, 3, "...") != 0) (parens > 0 ? optional : required)++;
            }
        }
        if (c == '{' || c == '[') depth++;
        else if (c == '}' || c == ']') depth--;
        else if (c == '"') quoted = true;
        else if (c == '<' && depth == 0) angled = true;
    }
    return {required, optional};
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(rpc_table_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(every_registered_method_has_a_table_row)
{
    const auto registered = AllRegisteredMethods();
    // Sanity: the sets this suite depends on are really registered.
    BOOST_REQUIRE(registered.count("getblockcount"));
    BOOST_REQUIRE(registered.count("z_sendmany"));
    BOOST_REQUIRE(registered.count("vault_lock"));
    BOOST_REQUIRE(registered.count("yed_getbalance"));

    for (const auto& name : registered) {
        if (REGISTERED_WITHOUT_ROW.count(name)) {
            BOOST_CHECK_MESSAGE(rpcCvtTable.count(name) == 0,
                name + " is allowlisted as having no row but has one; drop it from REGISTERED_WITHOUT_ROW");
            continue;
        }
        BOOST_CHECK_MESSAGE(rpcCvtTable.count(name) == 1,
            name + " is registered but has no row in src/rpc/common.h, so it cannot be called");
    }
}

BOOST_AUTO_TEST_CASE(every_table_row_names_a_registered_method)
{
    const auto registered = AllRegisteredMethods();
    for (const auto& [name, spec] : rpcCvtTable) {
        if (ROWS_NOT_REGISTERED_IN_THIS_BUILD.count(name)) {
            BOOST_CHECK_MESSAGE(registered.count(name) == 0,
                name + " is listed as not registered in this build but is registered");
            continue;
        }
        BOOST_CHECK_MESSAGE(registered.count(name) == 1,
            name + " has a row in src/rpc/common.h but no registered method");
    }
    for (const auto& [name, reason] : REGISTERED_WITHOUT_ROW) {
        BOOST_CHECK_MESSAGE(registered.count(name) == 1,
            name + " is allowlisted but no longer registered; drop it from REGISTERED_WITHOUT_ROW");
    }
}

BOOST_AUTO_TEST_CASE(getunconfirmedbalance_is_callable)
{
    // CallRPC converts the arguments through the client's table lookup, the
    // step that failed with "Unknown RPC method" on 6.22.0-beta1.
    UniValue result;
    BOOST_CHECK_NO_THROW(result = CallRPC("getunconfirmedbalance"));
    BOOST_CHECK(result.isNum());
    BOOST_CHECK_THROW(CallRPC("getunconfirmedbalance 1"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(walletconfirmbackup_takes_acknowledge_imports)
{
    // The row was {{s}, {}}, so the server refused the optional second argument ("Too many parameters") and a wallet
    // with imported keys under -walletrequirebackup could never confirm its backup (beta2 item 14).
    try {
        CallRPC("walletconfirmbackup abandon true");
    } catch (const std::runtime_error& e) {
        BOOST_CHECK_MESSAGE(std::string(e.what()).find("parameters for method") == std::string::npos, e.what());
    }
}

BOOST_AUTO_TEST_CASE(table_counts_match_help_signatures)
{
    // The row's required and optional counts against the arguments the method's help signature names, for the
    // methods whose help this parser reads (beta2 item 14: walletconfirmbackup's row had no optional argument).
    CRPCTable yellowbackTable;
    {
        ScopedYellowbackLive live;
        RegisterYellowbackRPCCommands(yellowbackTable);
        RegisterYellowbackWalletRPCCommands(yellowbackTable);
    }
    size_t checked = 0;
    for (const auto& [name, spec] : rpcCvtTable) {
        const CRPCCommand* cmd = tableRPC[name];
        if (!cmd) cmd = yellowbackTable[name];
        if (!cmd) continue;
        std::string help;
        try {
            cmd->actor(UniValue(UniValue::VARR), true);
        } catch (const std::exception& e) {
            help = e.what();
        }
        const std::string line = help.substr(0, help.find('\n'));
        if (line.compare(0, name.size() + 1, name + " ") != 0 && line != name) continue;   // no signature line
        if (HELP_SIGNATURE_DIFFERS.count(name)) continue;
        const auto counts = HelpArgumentCounts(line);
        const size_t rowTotal = spec.first.size() + spec.second.size();
        BOOST_CHECK_MESSAGE(counts.first + counts.second == rowTotal,
            name + ": help names " + std::to_string(counts.first) + "+" + std::to_string(counts.second) +
            " arguments, the row " + std::to_string(spec.first.size()) + "+" + std::to_string(spec.second.size()) + ": " + line);
        checked++;
    }
    BOOST_CHECK(checked > 100);
}

BOOST_AUTO_TEST_SUITE_END()
