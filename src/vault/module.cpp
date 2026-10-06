// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "vault/module.h"

#include "yellowback/module.h"
#include "yellowback/script.h"

namespace vault {

const std::vector<std::pair<Tag, const Module*>>& Modules()
{
    // The compile-time table (§3.8, §15.7): adding a module is a network upgrade. P4 registers YED
    // (yellowback/module.h; its code lives in src/yellowback/, the same library, so the table names
    // it directly and there is no registration call at run time). `WYEC` is never registered (§4).
    static const std::vector<std::pair<Tag, const Module*>> table = {
        { yellowback::YED_TAG, yellowback::RegisteredModule() },
    };
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
