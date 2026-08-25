// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Rennie Allen

#pragma once

#include "miri_common/MiriTypes.h"
#include "miri_common/PeImage.h"

#include <filesystem>
#include <string>
#include <vector>

namespace miri
{

struct SymbolFilters
{
    std::vector<std::wstring> includePatterns;
    std::vector<std::wstring> excludePatterns;
    std::size_t maxFunctions{0};
};

struct SymbolEnumerationReport
{
    bool diaCompiled{false};
    bool diaLoaded{false};
    std::size_t dbghelpPublicNames{0};
    std::size_t dbghelpDecoratedPublicNames{0};
    std::size_t diaPublicNames{0};
    std::size_t diaDecoratedPublicNames{0};
    std::size_t publicNameMatches{0};
    std::size_t finalDecoratedNames{0};
};

bool EnumeratePdbFunctions(const std::filesystem::path& exePath,
                           const std::filesystem::path& pdbPath,
                           const PeImageInfo& image,
                           const SymbolFilters& filters,
                           bool collectMangledNames,
                           std::vector<FunctionSymbol>& symbols,
                           SymbolEnumerationReport& report,
                           std::string& error);

} // namespace miri
