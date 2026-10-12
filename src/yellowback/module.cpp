// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "yellowback/module.h"

#include "vault/state.h"
#include "yellowback/script.h"
#include "yellowback/state.h"

#include <memory>
#include <mutex>

namespace yellowback {

namespace {

std::mutex cs_module;
std::shared_ptr<const Params> g_moduleParams;   // null = off (the primitive alone governs YED vaults)

std::shared_ptr<const Params> CurrentParams()
{
    std::lock_guard<std::mutex> lock(cs_module);
    return g_moduleParams;
}

/** The parameter set in force at `height`, chosen as the index's mirror chooses it (SelectParams over the sets the
 *  module holds, YellowbackIndex::ParamsAt): a release that adds a set at a later start height changes both alike
 *  (final review B-2). Today the module and the index each hold the one set init configured. */
std::shared_ptr<const Params> ParamsAtHeight(int64_t height)
{
    std::shared_ptr<const Params> p = CurrentParams();
    if (!p) return p;
    const std::vector<Params> sets{ *p };
    return std::make_shared<const Params>(SelectParams(sets, (int)std::max<int64_t>(0, std::min<int64_t>(height, 0x7FFFFFFF))));
}

/** The attestor set when it has the shape the module adopts (ApplySetAct, state.cpp): OPEN, ATTESTOR_SEATS seats,
 *  maturity BOND_MATURITY, livenessWindow >= ATTESTOR_LIVENESS_MIN; else nullopt (the module's mirror has no set). */
std::optional<vault::SetRecord> AdoptedSet(const Params& p, const vault::ModuleContext& ctx)
{
    if (!ctx.state) return std::nullopt;
    std::optional<vault::SetRecord> s = vault::GetSet(*ctx.state, p.attestorSetId);
    if (!s || !s->params.IsOpen() || (int)s->params.seats != p.attestorSeats ||
        (int64_t)s->params.maturity != (int64_t)p.bondMaturity ||
        (int64_t)s->params.livenessWindow < (int64_t)p.attestorLivenessMin) return std::nullopt;
    return s;
}

} // namespace

void SetModuleParams(const Params& p)
{
    std::lock_guard<std::mutex> lock(cs_module);
    if (p.IsConfigured()) g_moduleParams = std::make_shared<const Params>(p);
    else g_moduleParams.reset();
}

void ClearModuleParams()
{
    std::lock_guard<std::mutex> lock(cs_module);
    g_moduleParams.reset();
}

std::optional<std::string> Module::ValidateCreate(const CTransaction& tx, size_t vout, const vault::VaultParams& v, const vault::ModuleContext& ctx) const
{
    std::shared_ptr<const Params> p = CurrentParams();
    if (!p) return std::nullopt;
    // U-23: the only shape a YED vault has (whether a mint or a cancel created it is EvaluateBlock's YED_TEMPLATE_OUTPUT).
    if (v.setId != p->attestorSetId || v.cancelSetId != p->attestorSetId) return std::string("bad-yellowback-vault-set");
    if (v.delay != p->claimDelay) return std::string("bad-yellowback-vault-delay");
    // IT-1: the APP branch is open (appHeight >= 1) and no later than the pre-plan lockHeight + GRACE; MINT-3 pins
    // a new mint's exact value (refHeight + 1) and a cancel re-creates the byte-identical V, so this is a bound only.
    if (v.appHeight < 1 || v.appHeight > v.ownerHeight + p->grace) return std::string("bad-yellowback-vault-height");
    return std::nullopt;
}

std::optional<std::string> Module::ValidateSpend(const CTransaction& tx, size_t vin, const vault::TemplateSpend& spend, const vault::ModuleContext& ctx) const
{
    std::shared_ptr<const Params> p = CurrentParams();
    if (!p) return std::nullopt;
    if (spend.kind == vault::TemplateKind::VAULT && spend.selector == vault::SEL_UNLOCK) return std::string("bad-yellowback-vault-unlock");
    if (spend.kind == vault::TemplateKind::INTENT && spend.selector == vault::SEL_RELEASED) return std::string("bad-yellowback-intent-owner");
    return std::nullopt;
}

std::optional<vault::SetId> Module::GovernedSet() const
{
    std::shared_ptr<const Params> p = CurrentParams();
    if (!p) return std::nullopt;
    return p->attestorSetId;
}

std::vector<CPubKey> Module::Ejections(const CTransaction& tx, const vault::ModuleContext& ctx) const
{
    std::shared_ptr<const Params> p = CurrentParams();
    if (!p || !ctx.state || !ctx.blockHashAt) return {};
    std::optional<std::pair<Attestation, Attestation>> e = EquivocationEvidence(tx, *p);
    if (!e || (int64_t)e->first.citedHeight >= ctx.height) return {};
    std::optional<uint256> blockHash = ctx.blockHashAt((int64_t)e->first.citedHeight);
    if (!blockHash) return {};
    for (const auto& m : vault::GetMembers(*ctx.state, p->attestorSetId)) {
        std::optional<vault::BondRecord> b = vault::GetBond(*ctx.state, m.second.bondOutpoint);
        if (!b || b->frozen) continue;
        if (EquivocatedBy(e.value(), m.first, blockHash.value())) return { m.first };
    }
    return {};
}

std::optional<std::string> Module::CheckBlock(const CBlock& block, const CBlockIndex* pindex, const vault::ModuleContext& ctx) const
{
    std::shared_ptr<const Params> p = CurrentParams();
    if (!p) return std::nullopt;
    for (const CTransaction& tx : block.vtx) {
        if (RefusedAttestorSetAct(tx, *p)) return std::string("bad-yellowback-attestor-set-act");
    }
    return std::nullopt;
}

std::optional<CPubKey> Module::Displace(const CTransaction& tx, const vault::SetJoinBody& join, const vault::ModuleContext& ctx) const
{
    std::shared_ptr<const Params> p = CurrentParams();
    if (!p || !ctx.state || join.setId != p->attestorSetId || join.bondVout >= tx.vout.size()) return std::nullopt;
    std::optional<vault::SetRecord> s = AdoptedSet(*p, ctx);
    if (!s) return std::nullopt;   // a set the module does not adopt
    std::vector<SeatCandidate> members;
    for (const auto& m : vault::GetMembers(*ctx.state, join.setId)) {
        if (m.second.status != vault::MEMBER_ACTIVE || m.second.bondFrozen) continue;
        std::optional<vault::BondRecord> b = vault::GetBond(*ctx.state, m.second.bondOutpoint);
        if (!b || b->frozen) continue;
        SeatCandidate c;
        c.key = m.first;
        c.bondZat = m.second.bondValue;
        c.joinHeight = m.second.joinHeight;
        c.lastAct = m.second.lastAct;
        members.push_back(c);
    }
    return EvictionVictim(members, ctx.height, tx.vout[join.bondVout].nValue, (int64_t)s->params.livenessWindow, *p);
}

std::vector<std::pair<CPubKey, int64_t>> Module::Liveness(const CTransaction& tx, const vault::ModuleContext& ctx) const
{
    std::shared_ptr<const Params> p = ParamsAtHeight(ctx.height);   // as the mirror's ParamsAt(height)
    if (!p || !ctx.state || !ctx.blockHashAt || !AdoptedSet(*p, ctx)) return {};
    const vault::MemberList all = vault::GetMembers(*ctx.state, p->attestorSetId);
    // seq -> the member whose join ordinal is seq + 1 (the module numbers the set's joins from 0, one seq per SET_JOIN)
    auto liveMember = [&](uint16_t seq) -> std::optional<std::pair<CPubKey, int64_t>> {
        for (const auto& m : all) {
            if (m.second.joinOrdinal != (uint32_t)seq + 1) continue;
            if (m.second.status != vault::MEMBER_ACTIVE || m.second.bondFrozen) return std::nullopt;
            std::optional<vault::BondRecord> b = vault::GetBond(*ctx.state, m.second.bondOutpoint);
            if (!b || b->frozen) return std::nullopt;
            return std::make_pair(m.first, m.second.lastAct);
        }
        return std::nullopt;
    };
    std::vector<std::pair<CPubKey, int64_t>> out;
    // the node's index cache (focused review): BUNDLE-1 already verified these signatures under the same keys
    SigCache* cache = static_cast<SigCache*>(ctx.moduleCache);
    for (const auto& sc : AttestationLiveness(tx, *p, ctx.height, liveMember, [&](int64_t h) { return ctx.blockHashAt(h); }, cache)) {
        out.push_back({ liveMember(sc.first)->first, sc.second });
    }
    return out;
}

const vault::Module* RegisteredModule()
{
    static const Module instance;
    return &instance;
}

} // namespace yellowback
