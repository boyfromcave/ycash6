// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2016-2023 The Zcash developers
// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "chainparamsbase.h"

#include "tinyformat.h"
#include "util/system.h"

#include <assert.h>

const std::string CBaseChainParams::MAIN = "main";
const std::string CBaseChainParams::TESTNET = "test";
const std::string CBaseChainParams::REGTEST = "regtest";
const std::string CBaseChainParams::TESTNET_FAST = "fast";
const std::string CBaseChainParams::TESTNET_SLOW = "slow";
const std::string CBaseChainParams::TESTNET_LEGACY = "legacy";

void AppendParamsHelpMessages(std::string& strUsage, bool debugHelp)
{
    strUsage += HelpMessageGroup(_("Chain selection options:"));
    strUsage += HelpMessageOpt("-testnet", _("Use the test chain"));
    strUsage += HelpMessageOpt("-testnetprofile=<profile>", _("Testnet profile, required with -testnet: fast, slow or legacy"));
    if (debugHelp) {
        strUsage += HelpMessageOpt("-regtest", "Enter regression test mode, which uses a special chain in which blocks can be solved instantly. "
                                   "This is intended for regression testing tools and app development.");
    }
}

/**
 * Main network
 */
class CBaseMainParams : public CBaseChainParams
{
public:
    CBaseMainParams()
    {
        nRPCPort = 8832;
    }
};
static CBaseMainParams mainParams;

/**
 * Testnet: three compiled-in profiles of the re-forked testnet (testnet plan Revision 3, T-14), each with
 * its own datadir and RPC port (P2P port and magic in chainparams.cpp). A new directory name per profile,
 * so a leftover testnet3, which holds the old Ycash testnet branch, is never opened (its blocks would
 * abort the node), and no two profiles share a datadir.
 */
class CBaseTestNetParams : public CBaseChainParams
{
public:
    CBaseTestNetParams(int rpcPort, const std::string& dataDir)
    {
        nRPCPort = rpcPort;
        strDataDir = dataDir;
    }
};
static CBaseTestNetParams testNetFastParams(18832, "testnet-yb-fast");
static CBaseTestNetParams testNetSlowParams(18932, "testnet-yb-slow");
static CBaseTestNetParams testNetLegacyParams(19032, "testnet-legacy");

/*
 * Regression test
 */
class CBaseRegTestParams : public CBaseChainParams
{
public:
    CBaseRegTestParams()
    {
        nRPCPort = 18832;
        strDataDir = "regtest";
    }
};
static CBaseRegTestParams regTestParams;

/*
 * Unit test
 */
class CBaseUnitTestParams : public CBaseMainParams
{
public:
    CBaseUnitTestParams()
    {
        strDataDir = "unittest";
    }
};
static CBaseUnitTestParams unitTestParams;

static CBaseChainParams* pCurrentBaseParams = 0;
static std::string strTestnetProfile = "fast";

const CBaseChainParams& BaseParams()
{
    assert(pCurrentBaseParams);
    return *pCurrentBaseParams;
}

void SelectBaseParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        pCurrentBaseParams = &mainParams;
    else if (chain == CBaseChainParams::TESTNET && strTestnetProfile == CBaseChainParams::TESTNET_FAST)
        pCurrentBaseParams = &testNetFastParams;
    else if (chain == CBaseChainParams::TESTNET && strTestnetProfile == CBaseChainParams::TESTNET_SLOW)
        pCurrentBaseParams = &testNetSlowParams;
    else if (chain == CBaseChainParams::TESTNET && strTestnetProfile == CBaseChainParams::TESTNET_LEGACY)
        pCurrentBaseParams = &testNetLegacyParams;
    else if (chain == CBaseChainParams::REGTEST)
        pCurrentBaseParams = &regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

std::string ChainNameFromCommandLine()
{
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest)
        throw std::runtime_error("Invalid combination of -regtest and -testnet.");
    // testnet plan Revision 3 (T-14): -testnet names one of three networks, so the profile is required
    // and never defaulted; a typo stops here instead of starting a fourth chain.
    const bool fProfile = mapArgs.count("-testnetprofile") > 0;
    if (fProfile && !fTestNet)
        throw std::runtime_error("-testnetprofile requires -testnet.");
    if (fRegTest)
        return CBaseChainParams::REGTEST;
    if (fTestNet) {
        if (!fProfile)
            throw std::runtime_error("-testnet requires -testnetprofile=<profile>: fast, slow or legacy.");
        SelectTestnetProfile(GetArg("-testnetprofile", ""));
        return CBaseChainParams::TESTNET;
    }
    return CBaseChainParams::MAIN;
}

void SelectTestnetProfile(const std::string& profile)
{
    if (profile != CBaseChainParams::TESTNET_FAST && profile != CBaseChainParams::TESTNET_SLOW &&
        profile != CBaseChainParams::TESTNET_LEGACY)
        throw std::runtime_error(strprintf("Unknown -testnetprofile '%s': fast, slow or legacy.", profile));
    strTestnetProfile = profile;
}

const std::string& SelectedTestnetProfile()
{
    return strTestnetProfile;
}

bool AreBaseParamsConfigured()
{
    return pCurrentBaseParams != NULL;
}
