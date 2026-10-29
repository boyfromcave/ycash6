// Copyright (c) 2014 The Bitcoin Core developers
// Copyright (c) 2016-2023 The Zcash developers
// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_CHAINPARAMSBASE_H
#define BITCOIN_CHAINPARAMSBASE_H

#include <string>
#include <vector>

/**
 * CBaseChainParams defines the base parameters (shared between bitcoin-cli and bitcoind)
 * of a given instance of the Bitcoin system.
 */
class CBaseChainParams
{
public:
    /** BIP70 chain name strings (main, test or regtest) */
    static const std::string MAIN;
    static const std::string TESTNET;
    static const std::string REGTEST;
    /**
     * The compiled-in testnet profiles (-testnetprofile, testnet plan Revision 3, T-14). All three are
     * chain "test" (NetworkIDString); they differ in datadir, ports, magic and the Vault timing.
     */
    static const std::string TESTNET_FAST;
    static const std::string TESTNET_SLOW;
    static const std::string TESTNET_LEGACY;

    const std::string& DataDir() const { return strDataDir; }
    int RPCPort() const { return nRPCPort; }

protected:
    CBaseChainParams() {}

    int nRPCPort = 0;
    std::string strDataDir;
};

/**
 * Append the help messages for the chainparams options to the
 * parameter string.
 */
void AppendParamsHelpMessages(std::string& strUsage, bool debugHelp=true);

/**
 * Return the currently selected parameters. This won't change after app
 * startup, except for unit tests.
 */
const CBaseChainParams& BaseParams();

/** Sets the params returned by Params() to those for the given network. */
void SelectBaseParams(const std::string& chain);

/**
 * Looks for -regtest, -testnet and returns the appropriate BIP70 chain name.
 * With -testnet it also reads -testnetprofile, which is then required, and selects that profile
 * (SelectTestnetProfile); -testnetprofile without -testnet is refused.
 * @throws std::runtime_error on an invalid combination, or a missing or unknown testnet profile.
 * @return CBaseChainParams::MAIN by default.
 */
std::string ChainNameFromCommandLine();

/**
 * Selects the testnet profile (fast, slow or legacy) that SelectBaseParams and SelectParams use for
 * CBaseChainParams::TESTNET; call it before them. Until a profile is selected it is fast (unit tests).
 * @throws std::runtime_error on an unknown profile.
 */
void SelectTestnetProfile(const std::string& profile);

/** The selected testnet profile (CBaseChainParams::TESTNET_FAST, _SLOW or _LEGACY). */
const std::string& SelectedTestnetProfile();

/**
 * Return true if SelectBaseParamsFromCommandLine() has been called to select
 * a network.
 */
bool AreBaseParamsConfigured();

#endif // BITCOIN_CHAINPARAMSBASE_H
