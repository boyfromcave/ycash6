// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "vault/module.h"

namespace vault {

const std::vector<std::pair<Tag, const Module*>>& Modules()
{
    // P2: no module is registered. P4 adds { {'Y','E','D',0x00}, &yed_module }.
    static const std::vector<std::pair<Tag, const Module*>> table;
    return table;
}

const Module* FindModule(const std::array<unsigned char, 4>& tag)
{
    for (const auto& entry : Modules()) {
        if (entry.first == tag) return entry.second;
    }
    return nullptr;
}

} // namespace vault
