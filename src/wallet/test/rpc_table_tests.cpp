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

// Every method the node can register: the core and wallet sets already in
// tableRPC, plus the Yellowback sets, which init registers only where
// Yellowback is live (src/init.cpp) and so are absent from the test fixture.
std::set<std::string> AllRegisteredMethods()
{
    std::set<std::string> names;
    for (const auto& name : tableRPC.listCommands()) names.insert(name);

    CRPCTable yellowbackTable;
    const bool wasLive = yellowback::g_yellowbackLive;
    yellowback::g_yellowbackLive = true;
    RegisterYellowbackRPCCommands(yellowbackTable);
    RegisterYellowbackWalletRPCCommands(yellowbackTable);
    yellowback::g_yellowbackLive = wasLive;
    for (const auto& name : yellowbackTable.listCommands()) names.insert(name);
    return names;
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

BOOST_AUTO_TEST_SUITE_END()
