#pragma once

#include "miri_common/MiriTypes.h"
#include "miri_common/PeImage.h"

#include <filesystem>
#include <string>
#include <vector>

namespace miri {

struct SymbolFilters {
    std::vector<std::wstring> includePatterns;
    std::vector<std::wstring> excludePatterns;
    std::size_t maxFunctions = 0;
};

bool EnumeratePdbFunctions(const std::filesystem::path& exePath,
                           const std::filesystem::path& pdbPath,
                           const PeImageInfo& image,
                           const SymbolFilters& filters,
                           std::vector<FunctionSymbol>& symbols,
                           std::string& error);

} // namespace miri
