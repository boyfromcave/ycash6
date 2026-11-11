// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "yellowback/address.h"

#include "base58.h"
#include "key_io.h"

namespace yellowback {

std::string EncodeAddress(const CKeyID& keyID, const Params& params)
{
    std::vector<unsigned char> data = params.addressVersion;
    data.insert(data.end(), keyID.begin(), keyID.end());
    return EncodeBase58Check(data);
}

bool DecodeAddress(const std::string& str, const Params& params, CKeyID& keyID)
{
    std::vector<unsigned char> data;
    if (!DecodeBase58Check(str, data)) return false;
    const std::vector<unsigned char>& ver = params.addressVersion;
    if (ver.empty() || data.size() != ver.size() + 20) return false;
    if (!std::equal(ver.begin(), ver.end(), data.begin())) return false;
    keyID = CKeyID(uint160(std::vector<unsigned char>(data.begin() + ver.size(), data.end())));
    return true;
}

bool IsValidAddress(const std::string& str, const Params& params)
{
    CKeyID id;
    return DecodeAddress(str, params, id);
}

std::string EncodeAddress(const CPQKeyID& id, const Params& params)
{
    return EncodePQAddress(id, params.pqAddressVersions);
}

bool DecodeAddress(const std::string& str, const Params& params, CPQKeyID& id)
{
    return DecodePQAddress(str, params.pqAddressVersions, id);
}

bool DecodeAddress(const std::string& str, const Params& params, CTxDestination& dest)
{
    CKeyID keyID;
    if (DecodeAddress(str, params, keyID)) {
        dest = keyID;
        return true;
    }
    CPQKeyID pq;
    if (DecodeAddress(str, params, pq)) {
        dest = pq;
        return true;
    }
    return false;
}

} // namespace yellowback
