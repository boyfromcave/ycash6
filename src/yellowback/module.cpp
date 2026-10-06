// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "yellowback/module.h"

#include "yellowback/script.h"

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
    if (v.appHeight != v.ownerHeight + p->grace) return std::string("bad-yellowback-vault-height");
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

const vault::Module* RegisteredModule()
{
    static const Module instance;
    return &instance;
}

} // namespace yellowback
