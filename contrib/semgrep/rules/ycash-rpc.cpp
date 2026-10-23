// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .
//
// Semgrep rule tests for ycash-rpc.yaml (`contrib/semgrep/scan.py --test`). Not compiled.

UniValue unchecked_list(const UniValue& params, bool fHelp)
{
    // ruleid: ycash.rpc.int-param-without-range-check
    int count = params.size() > 0 && !params[0].isNull() ? params[0].get_int() : 100;
    // ruleid: ycash.rpc.int-param-without-range-check
    int skip = params.size() > 1 && !params[1].isNull() ? params[1].get_int() : 0;
    UniValue arr(UniValue::VARR);
    for (size_t i = skip; i < rows.size() && (int)arr.size() < count; i++) arr.push_back(rows[i]);
    return arr;
}

UniValue unchecked_vout(const UniValue& params, bool fHelp)
{
    // ruleid: ycash.rpc.int-param-without-range-check
    uint32_t vout = params[2].get_int();
    return tx.vout[vout].nValue;
}

UniValue checked_list(const UniValue& params, bool fHelp)
{
    // ok: ycash.rpc.int-param-without-range-check
    const int count = params.size() > 0 && !params[0].isNull() ? params[0].get_int() : 100;
    // ok: ycash.rpc.int-param-without-range-check
    const int skip = params.size() > 1 && !params[1].isNull() ? params[1].get_int() : 0;
    if (count < 0 || skip < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "count and skip must be >= 0");
    return List(count, skip);
}

UniValue checked_vout(const UniValue& params, bool fHelp)
{
    // ok: ycash.rpc.int-param-without-range-check
    uint32_t vout = params[2].get_int();
    LOCK(cs_main);
    if (vout >= tx.vout.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "vout out of range");
    }
    return tx.vout[vout].nValue;
}

UniValue checked_price(const UniValue& params, bool fHelp)
{
    // ok: ycash.rpc.int-param-without-range-check
    const int64_t price = params[0].get_int64();
    if (price != 0 && (price < PRICE_MIN || price > PRICE_MAX)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "quote-out-of-range");
    }
    return price;
}

namespace yellowback {

int64_t IntegerRatio(int64_t a, int64_t b)
{
    // ok: ycash.yellowback.floating-point
    const arith_uint256 q = arith_uint256(a) * arith_uint256(BPS) / arith_uint256(b);
    return (int64_t)q.GetLow64();
}

int64_t FloatRatio(int64_t a, int64_t b)
{
    // ruleid: ycash.yellowback.floating-point
    double r = (double)a / b;
    // ruleid: ycash.yellowback.floating-point
    return (int64_t)(std::sqrt(r) * BPS);
}

int64_t PriceArg(const UniValue& v)
{
    // ruleid: ycash.yellowback.floating-point
    return (int64_t)(v.get_real() * 1000000);
}

} // namespace yellowback
