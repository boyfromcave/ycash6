// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "yellowback/address.h"

#include "base58.h"
#include "crypto/pq/scheme.h"

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
    if (!pq::IsKnownScheme(id.scheme)) return {};
    std::vector<unsigned char> data = params.pqAddressVersion;
    data.push_back(id.scheme);
    data.insert(data.end(), id.hash.begin(), id.hash.end());
    return EncodeBase58Check(data);
}

bool DecodeAddress(const std::string& str, const Params& params, CPQKeyID& id)
{
    std::vector<unsigned char> data;
    if (!DecodeBase58Check(str, data)) return false;
    const std::vector<unsigned char>& ver = params.pqAddressVersion;
    if (ver.empty() || data.size() != ver.size() + 1 + 32) return false;
    if (!std::equal(ver.begin(), ver.end(), data.begin())) return false;
    const uint8_t scheme = data[ver.size()];
    if (!pq::IsKnownScheme(scheme)) return false;
    id = CPQKeyID(scheme, uint256(std::vector<unsigned char>(data.begin() + ver.size() + 1, data.end())));
    return true;
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
