// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2019-present The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_POLICY_POLICY_H
#define BITCOIN_POLICY_POLICY_H

#include "amount.h"
#include "consensus/consensus.h"
#include "script/interpreter.h"
#include "script/standard.h"

#include <optional>
#include <string>

class CChainParams;
class CCoinsViewCache;
class CTransaction;
class CFeeRate;
class CTxOut;
namespace Consensus { struct Params; }
namespace vault { class SetSnapshot; }

// Ycash per-Sapling-output mempool fee floor (anti-spam policy, see policy.cpp).
static const CAmount DEFAULT_PER_SAPLING_OUTPUT_FEE = 1000;
static const unsigned int DEFAULT_EXEMPT_SAPLING_OUTPUTS = 50;

/**
 * Minimum fee, in yoshis, that a transaction must pay to be accepted to the
 * mempool under the Ycash per-Sapling-output anti-spam policy. Ported from
 * ycash-official; runs alongside (and independently of) the ZIP 317 unpaid
 * action limit in AcceptToMemoryPool.
 */
CAmount PerSaplingOutputFees(const CTransaction& tx);

/** Default for -blockmaxsize, which controls the maximum block size the mining code will create **/
static const unsigned int DEFAULT_BLOCK_MAX_SIZE = MAX_BLOCK_SIZE;

/** Maximum number of signature check operations in an IsStandard() P2SH script */
static const unsigned int MAX_P2SH_SIGOPS = 15;
/** The maximum number of sigops we're willing to relay/mine in a single tx */
static const unsigned int MAX_STANDARD_TX_SIGOPS = MAX_BLOCK_SIGOPS/5;
/** The largest `YV` act OP_RETURN scriptPubKey relayed once UPGRADE_VAULT is active (plan §15.5). */
static const unsigned int MAX_VAULT_ACT_BYTES = 1200;
/** The largest standard scriptSig of an input spending TX_PQPKH or a vault template once UPGRADE_VAULT
 *  is active (quantum spec §0, §2.3, F-6): an SLH-DSA spend is 7,939 bytes. */
static const unsigned int MAX_STANDARD_PQ_SCRIPTSIG = 9000;
/** The largest standard scriptSig of every other input (Bitcoin's 15-of-15 P2SH multisig bound). */
static const unsigned int MAX_STANDARD_SCRIPTSIG = 1650;
/**
 * Standard script verification flags that standard transactions will comply
 * with. However scripts violating these flags may still be present in valid
 * blocks and we must accept those blocks.
 */
static const unsigned int STANDARD_SCRIPT_VERIFY_FLAGS = MANDATORY_SCRIPT_VERIFY_FLAGS |
                                                         // SCRIPT_VERIFY_DERSIG is always enforced
                                                         SCRIPT_VERIFY_STRICTENC |
                                                         SCRIPT_VERIFY_MINIMALDATA |
                                                         SCRIPT_VERIFY_NULLDUMMY |
                                                         SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
                                                         SCRIPT_VERIFY_CLEANSTACK |
                                                         SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
                                                         SCRIPT_VERIFY_LOW_S;

/** For convenience, standard but not mandatory verify flags. */
static const unsigned int STANDARD_NOT_MANDATORY_VERIFY_FLAGS = STANDARD_SCRIPT_VERIFY_FLAGS & ~MANDATORY_SCRIPT_VERIFY_FLAGS;

/**
 * The rate used to calculate the dust threshold, in yoshis per 1000 bytes.
 * This will effectively be multiplied by 3 (it is necessary to express it this
 * way to ensure that rounding will be calculated the same as before #6542).
 *
 * Bitcoin Core added the concept of "dust" in bitcoin/bitcoin#2577. At that
 * point the dust threshold rate was tied to three times the minRelayTxFee rate,
 * with the motivation that if you'd pay more than a third of the minimum relay
 * fee to spend something, it should be considered dust. This was implemented
 * as a standard rule rejecting dust outputs.
 *
 * This motivation will not apply after ZIP 317 block construction is implemented:
 * at that point the ZIP 317 marginal fee will be 5000 zats per logical action,
 * but the dust threshold rate will still be 300 zats per 1000 bytes. Those costs
 * would only coincide if the marginal size per logical action were
 * 5000/300 * 1000 ~= 16667 bytes, and in practice the marginal size for any
 * kind of input is much smaller than that.
 *
 * However, to avoid interoperability problems (older wallets creating transactions
 * that newer nodes will reject because they view the outputs as dust), we will have
 * to coordinate any increase in the dust threshold carefully.
 *
 * More history: in Zcash the minRelayTxFee rate was 5000 zats/1000 bytes at launch,
 * changed to 1000 zats/1000 bytes in zcashd v1.0.3 and to 100 zats/1000 bytes in
 * zcashd v1.0.7-1 (#2141). The relaying problem for shielded transactions (#1969)
 * that prompted the latter change was fixed more thoroughly by the addition of
 * `CFeeRate::GetFeeForRelay` in #4916, ensuring that a transaction paying
 * `LEGACY_DEFAULT_FEE` can always be relayed. At the same time the default fee was
 * set to 1000 zats, per ZIP 313.
 *
 * #6542 changed relaying policy to be more strict about enforcing minRelayTxFee.
 * It also allowed `-minrelaytxfee=0`, which we were using to avoid some test
 * breakage. But if the dust threshold rate were still set to three times the
 * minRelayTxFee rate, then setting `-minrelaytxfee=0` would have the side effect
 * of setting the dust threshold to zero, which is not intended.
 *
 * Bitcoin Core took a different approach to disentangling the dust threshold from
 * the relay threshold, adding a `-dustrelayfee` option (bitcoin/bitcoin#9380).
 * We don't want to do that because it is likely that we will change the dust policy
 * again, and adding a user-visible config option might conflict with that. Also,
 * it isn't a good idea for the dust threshold rate to be configurable per node;
 * it's a standard rule parameter and should only be changed with network-wide
 * coordination (if it is increased then wallets have to change before nodes, and
 * vice versa if it is decreased). So for now we set it to a constant that matches
 * the behaviour before #6542.
 */
static const unsigned int ONE_THIRD_DUST_THRESHOLD_RATE = 100;

// Sanity check the magic numbers when we change them
static_assert(DEFAULT_BLOCK_MAX_SIZE <= MAX_BLOCK_SIZE);

bool IsStandard(const CScript& scriptPubKey, txnouttype& whichType);

/**
 * The post-quantum owner/holder scheme of a TX_PQPKH, V or I scriptPubKey (quantum spec §1, §2), or
 * nullopt for any other script.
 */
std::optional<uint8_t> PQScriptScheme(const CScript& scriptPubKey, txnouttype whichType);

/** The serialized size of the input that spends a TX_PQPKH output of `scheme` (outpoint, sequence and
 *  the chunked scriptSig: SLH-DSA 7,938 + 43 bytes, Falcon 1,577 + 43); 0 for an unknown scheme. */
size_t PQSpendInputSize(uint8_t scheme);

/** The dust threshold of a TX_PQPKH output, priced with its real spend size (review A F8); any other
 *  output's CTxOut::GetDustThreshold. */
CAmount GetPQDustThreshold(const CTxOut& txout, const CFeeRate& minRelayTxFee);
    /**
     * Check for standard transaction types
     * @return True if all outputs (scriptPubKeys) use only standard transaction forms
     */
bool IsStandardTx(const CTransaction& tx, std::string& reason, const CChainParams& chainparams, int nHeight = 0);
    /**
     * Check for standard transaction types
     * @param[in] mapInputs    Map of previous transactions that have outputs we're spending
     * @param[in] vaultSnapshot  The set state at the tip (UPGRADE_VAULT), for the exact signature count of a
     *                           set-signed template input; null = only the signature size is checked (audit 01/V-4)
     * @return True if all inputs (scriptSigs) use only standard transaction forms
     */
bool AreInputsStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs, uint32_t consensusBranchId,
                       const vault::SetSnapshot* vaultSnapshot = nullptr);

/**
 * Policy sigops of OP_CHECKPQSIG (docs/plans/yellowback-quantum-plan.md §4.1, D-Q-7):
 * pq::SIGOP_COST for each OP_CHECKPQSIG in what a spend executes (each input's scriptSig, its
 * previous output's scriptPubKey and, for P2SH, the redeem script). Not a consensus count
 * (CScript::GetSigOpCount does not see 0xc2, as it does not see OP_CHECKSETSIG); the mempool and
 * the block template add it to their sigop budgets (getblocktemplate's per-transaction "sigops"
 * includes it), and AreInputsStandard to a P2SH redeem script's (R-B2).
 */
unsigned int GetPQSigOpCount(const CTransaction& tx, const CCoinsViewCache& mapInputs);
/** The same count over one script: pq::SIGOP_COST per OP_CHECKPQSIG opcode (not inside pushes). */
unsigned int GetPQSigOpCount(const CScript& script);

/**
 * The fallback fee rate wallets charge a transaction that spends a post-quantum input (TX_PQPKH, or a
 * V/I owner path), -pqfeerate (quantum plan §4.5): 1x the per-kB relay floor (-minrelaytxfee) by
 * default. Since D-Q-23 (b) it is the rate used only while no attested price exists (below the
 * Yellowback start height, under HALT_NO_PRICE or HALT_DIVERGENCE, with no index): with a price the rates below are
 * dollars per KB. Not a relay or consensus rule: relay stays minRelayTxFee per byte.
 */
extern CFeeRate pqFeeRate;

/**
 * The network fee policy of post-quantum and Yellowback transactions (quantum plan D-Q-23 (b), the
 * yb-calibration adjustments D-Q-23a; policy only, nothing in consensus): wallets target dollars per
 * KB at the attested price -- the HIGHEST of the index tip's window medians (max(pFast, pMid, pSlow),
 * pClaim-style, so a depressed min-of-windows never makes the wallet overpay in YEC; review M-1), and
 * none while the price is not trusted at the tip (HALT-1 or HALT-3; HALT-2 alone still publishes it, fees spec
 * section 5.1 amendment 2026-10-28: yellowback::FeePriceTrusted) -- bounded below by max(floorZatPerKB, -pqfeerate) (review
 * A-7) and, for the vault/Yellowback paths, above by min(max(-maxtxfee, yedMaxTxFeeUsdMicro at the
 * price), -yellowbackmaxtxfee) (review M-1: an absolute YEC ceiling). Every number is a parameter (one
 * place here; yed_getinfo.params.fees.network reports them). A transaction with a PQ input takes the
 * plain rate; one built by the YED builder or a vault_* RPC the Yellowback rate; nothing else is touched.
 */
struct AttestedFeePolicy
{
    int64_t plainUsdPerKBMicro;        //!< -pqfeeusdperkb: 20,000 uUSD/KB ($0.02); 0 = off (the -pqfeerate behaviour)
    int64_t yedUsdPerKBMicro;          //!< -yellowbackfeeusdperkb: 50,000 uUSD/KB ($0.05); 0 = off
    CAmount floorZatPerKB;             //!< DEFAULT_ATTESTED_FEE_FLOOR_PER_KB: with -pqfeerate, the rate never goes below max(this, -pqfeerate) (D-Q-23a: 5,000 zat/KB)
    int64_t yedMaxTxFeeUsdMicro;       //!< -yellowbackmaxtxfeeusd: the vault/Yellowback cap is max(-maxtxfee, this at the price); 2,000,000 ($2)
    CAmount yedMaxTxFeeZat;            //!< -yellowbackmaxtxfee: the absolute YEC ceiling of that cap (10 YEC)
    CAmount minCapZat;                 //!< the cap never goes below the flat fees it must admit: max(-yellowbackfee, VAULT_RPC_FEE), set at init
};
/** The flat fee of the vault_* / set_* RPCs (rpc/vault.cpp); the floor of the vault/Yellowback cap. */
static const CAmount VAULT_RPC_FEE = 10000;
static const int64_t DEFAULT_PQ_FEE_USD_PER_KB_MICRO = 20000;
static const int64_t DEFAULT_YED_FEE_USD_PER_KB_MICRO = 50000;
static const CAmount DEFAULT_ATTESTED_FEE_FLOOR_PER_KB = 5000;
static const int64_t DEFAULT_YED_MAX_TX_FEE_USD_MICRO = 2000000;
static const CAmount DEFAULT_YED_MAX_TX_FEE = 10 * COIN;
/** The least -yellowbackmaxtxfee may be (q/fees review): above the fees the wallet must pay. The largest single-PQ-input
 *  spend, an SLH-DSA vault owner spend (a 7,939-byte scriptSig), has a ZIP-317 conventional fee of ~26,500 zat (53
 *  logical actions x 500); a YED owner spend adds token, carrier and payload actions (~30,000-35,000 zat). 100,000 zat
 *  (200 logical actions, 0.001 YEC) is ~3x that, so a lowered ceiling never caps a fee below what relay demands. */
static const CAmount MIN_YED_MAX_TX_FEE = 100000;
static_assert(MIN_YED_MAX_TX_FEE >= VAULT_RPC_FEE, "the ceiling's floor admits the vault RPCs' flat fee");
/** The parameters, set once at init (and by unit tests) before any reader runs. The price is not here: see AttestedFeePrice(). */
extern AttestedFeePolicy attestedFeePolicy;

/** max(floorZatPerKB, ceil(usdPerKBMicro x COIN / priceMicroUsd)): the zat/KB rate of a dollar target at a price. */
CAmount AttestedRateZatPerKB(int64_t usdPerKBMicro, int64_t priceMicroUsd, CAmount floorZatPerKB);
/** The Yellowback index publishes the tip price here (nullopt when undefined: the fallback -pqfeerate applies).
 *  An atomic value (review N-3): readers need no lock (the wallet, the RPC threads, the index under cs_main). */
void SetAttestedFeePrice(std::optional<int64_t> priceMicroUsd);
/** The attested price in force, nullopt = the fallback. */
std::optional<int64_t> AttestedFeePrice();
/** The rate in force for a transaction with a PQ input / for a vault or Yellowback transaction (zat/KB). */
CFeeRate PlainPQFeeRate();
CFeeRate YedFeeRate();
/** The floor rate with a price: max(floorZatPerKB, -pqfeerate) (review A-7: -pqfeerate stays a floor). */
CAmount AttestedFeeFloorPerKB();
/** The cap of a vault/Yellowback transaction's size-priced fee: min(max(-maxtxfee, yedMaxTxFeeUsdMicro at the price),
 *  -yellowbackmaxtxfee); min(-maxtxfee, -yellowbackmaxtxfee) without a price; never below minCapZat (review, so a low
 *  -maxtxfee cannot block a flat-fee vault RPC or Yellowback transaction). */
CAmount YedMaxTxFee();
/** The cap of a plain post-quantum transaction's size-priced fee (owner D-Q-26, 2026-10-11): the same cap as the
 *  vault/Yellowback paths, YedMaxTxFee() -- min(max(-maxtxfee, $2 at the price), -yellowbackmaxtxfee). */
CAmount PQMaxTxFee();

/** max(floor, PlainPQFeeRate() x nBytes): the fee of a transaction of nBytes with a PQ input (ycash-dd:
 *  floor = DEFAULT_FEE for the wallet). */
CAmount PQSizeFee(CAmount floor, size_t nBytes);
/** max(floor, YedFeeRate() x nBytes): the same for a vault or Yellowback transaction (floor = g_yellowbackFee, VAULT_RPC_FEE). */
CAmount YedSizeFee(CAmount floor, size_t nBytes);
/** max(flat, the floor rate x nBytes): the least a vault/Yellowback transaction pays (review L-1: the owner-path
 *  fee of a vault smaller than its dollar-priced fee; the floor rate with a price, -pqfeerate without one). */
CAmount YedFloorSizeFee(CAmount flat, size_t nBytes);
/** Review M-1: the network fee of `tx` (its inputs from the chain tip and the mempool) when it exceeds YedMaxTxFee(),
 *  nullopt when it does not or its inputs are unknown. The vault/Yellowback broadcast paths submit with the mempool's
 *  absurd-fee check off (their cap may exceed -maxtxfee), so they enforce this cap themselves. cs_main held. */
std::optional<CAmount> YedFeeOverCap(const CTransaction& tx);
/** D-Q-26: true when `tx` spends a post-quantum input (IsPQInputScript, inputs from the tip + mempool view) and its
 *  network fee is within PQMaxTxFee(): the wallet then submits its own transaction without the -maxtxfee absurd-fee
 *  check (sendrawtransaction from outside keeps -maxtxfee unless allowhighfees). cs_main held. */
bool PQFeeWithinCap(const CTransaction& tx);
/** Review (reaccept): true when `tx` is a post-quantum or Yellowback/vault transaction (a PQ input, a vault or intent
 *  input or output, or a YED payload) whose network fee is within the ABSOLUTE ceiling -yellowbackmaxtxfee, whatever the
 *  price says now: a transaction the wallet already committed is not re-judged against a price-dependent cap that has
 *  since moved (ReacceptWalletTransactions). cs_main held. */
bool OwnTxFeeWithinCeiling(const CTransaction& tx);

#endif // BITCOIN_POLICY_POLICY_H
