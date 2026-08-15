#include "miri_common/Symbols.h"

#include "miri_common/StringUtil.h"

#include <algorithm>
#include <regex>
#include <sstream>
#include <unordered_set>

#include <DbgHelp.h>
#include <windows.h>

namespace miri
{
namespace
{

struct CompiledFilters
{
    std::vector<std::wregex> include;
    std::vector<std::wregex> exclude;
};

bool CompileFilters(const SymbolFilters& filters, CompiledFilters& compiled, std::string& error)
{
    try
{
        for (const auto& pattern : filters.includePatterns)
{
            compiled.include.emplace_back(pattern, std::regex::ECMAScript);
        }
        for (const auto& pattern : filters.excludePatterns)
{
            compiled.exclude.emplace_back(pattern, std::regex::ECMAScript);
        }
    } catch (const std::regex_error& exception)
{
        error = std::string("invalid symbol regex: ") + exception.what();
        return false;
    }
    return true;
}

bool MatchesFilters(const std::wstring& name, const CompiledFilters& filters)
{
    bool included = filters.include.empty();
    for (const auto& pattern : filters.include)
{
        if (std::regex_search(name, pattern))
{
            included = true;
            break;
        }
    }

    if (!included)
{
        return false;
    }

    for (const auto& pattern : filters.exclude)
{
        if (std::regex_search(name, pattern))
{
            return false;
        }
    }

    return true;
}

std::wstring BuildSymbolSearchPath(const std::filesystem::path& exePath,
                                   const std::filesystem::path& pdbPath)
{
    std::wstring searchPath;

    const auto appendUnique = [&searchPath](const std::filesystem::path& path) {
        if (path.empty())
{
            return;
        }
        if (!searchPath.empty())
{
            searchPath.push_back(L';');
        }
        searchPath += path.wstring();
    };

    appendUnique(pdbPath.parent_path());
    if (exePath.parent_path() != pdbPath.parent_path())
{
        appendUnique(exePath.parent_path());
    }
    appendUnique(std::filesystem::current_path());
    return searchPath;
}

class SymbolSession
{
public:
    SymbolSession() = default;
    SymbolSession(const SymbolSession&) = delete;
    SymbolSession& operator=(const SymbolSession&) = delete;

    ~SymbolSession()
    {
        if (initialized_)
{
            SymCleanup(process_);
        }
    }

    bool Initialize(const std::wstring& searchPath, std::string& error)
    {
        process_ = GetCurrentProcess();
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES |
                      SYMOPT_FAIL_CRITICAL_ERRORS);

        if (!SymInitializeW(process_, searchPath.c_str(), FALSE))
{
            error = "SymInitializeW failed: " + LastWin32ErrorMessage();
            return false;
        }

        initialized_ = true;
        return true;
    }

    HANDLE Process() const { return process_; }

private:
    HANDLE process_ = nullptr;
    bool initialized_ = false;
};

struct EnumContext
{
    const PeImageInfo* image = nullptr;
    const CompiledFilters* filters = nullptr;
    std::uint64_t moduleBase = 0;
    std::size_t maxFunctions = 0;
    std::vector<FunctionSymbol>* symbols = nullptr;
};

// DIA SymTagEnum values; some SDKs do not expose these through DbgHelp.h.
constexpr ULONG kSymTagFunction = 5;
constexpr ULONG kSymTagThunk = 27;

BOOL CALLBACK EnumSymbolCallback(PSYMBOL_INFOW symbol, ULONG symbolSize, PVOID userContext)
{
    auto* context = static_cast<EnumContext*>(userContext);
    if (context == nullptr || symbol == nullptr || context->symbols == nullptr)
{
        return FALSE;
    }

    const bool isFunction = (symbol->Flags & SYMFLAG_FUNCTION) != 0 ||
                            symbol->Tag == kSymTagFunction ||
                            symbol->Tag == kSymTagThunk;
    if (!isFunction || symbol->Address < context->moduleBase)
{
        return TRUE;
    }

    const std::uint64_t rawRva = symbol->Address - context->moduleBase;
    if (rawRva > UINT32_MAX)
{
        return TRUE;
    }

    const auto rva = static_cast<std::uint32_t>(rawRva);
    if (!context->image->IsExecutableRva(rva))
{
        return TRUE;
    }

    std::wstring name(symbol->Name, symbol->NameLen);
    if (name.empty() || !MatchesFilters(name, *context->filters))
{
        return TRUE;
    }

    FunctionSymbol function;
    function.name = std::move(name);
    function.rva = rva;
    function.size = symbol->Size != 0 ? symbol->Size : symbolSize;
    function.flags = symbol->Flags;
    function.tag = symbol->Tag;
    context->symbols->push_back(std::move(function));

    if (context->maxFunctions != 0 && context->symbols->size() >= context->maxFunctions)
{
        return FALSE;
    }

    return TRUE;
}

DWORD64 LoadModuleWithFallback(HANDLE process,
                               const std::filesystem::path& exePath,
                               const std::filesystem::path& pdbPath,
                               const PeImageInfo& image)
{
    DWORD64 moduleBase = SymLoadModuleExW(process, nullptr, exePath.wstring().c_str(), nullptr,
                                          image.imageBase, image.sizeOfImage, nullptr, 0);
    if (moduleBase != 0)
{
        return moduleBase;
    }

    return SymLoadModuleExW(process, nullptr, pdbPath.wstring().c_str(), nullptr,
                            image.imageBase, image.sizeOfImage, nullptr, 0);
}

} // namespace

bool EnumeratePdbFunctions(const std::filesystem::path& exePath,
                           const std::filesystem::path& pdbPath,
                           const PeImageInfo& image,
                           const SymbolFilters& filters,
                           std::vector<FunctionSymbol>& symbols,
                           std::string& error)
{
    CompiledFilters compiledFilters;
    if (!CompileFilters(filters, compiledFilters, error))
{
        return false;
    }

    SymbolSession session;
    const std::wstring searchPath = BuildSymbolSearchPath(exePath, pdbPath);
    if (!session.Initialize(searchPath, error))
{
        return false;
    }

    const DWORD64 moduleBase = LoadModuleWithFallback(session.Process(), exePath, pdbPath, image);
    if (moduleBase == 0)
{
        error = "SymLoadModuleExW failed for executable and PDB: " + LastWin32ErrorMessage();
        return false;
    }

    std::vector<FunctionSymbol> enumerated;
    EnumContext context;
    context.image = &image;
    context.filters = &compiledFilters;
    context.moduleBase = moduleBase;
    context.maxFunctions = filters.maxFunctions;
    context.symbols = &enumerated;

    SetLastError(ERROR_SUCCESS);
    const BOOL ok = SymEnumSymbolsW(session.Process(), moduleBase, L"*", EnumSymbolCallback,
                                    &context);
    if (!ok && GetLastError() != ERROR_SUCCESS)
{
        error = "SymEnumSymbolsW failed: " + LastWin32ErrorMessage();
        return false;
    }

    std::sort(enumerated.begin(), enumerated.end(),
              [](const FunctionSymbol& left, const FunctionSymbol& right) {
                  if (left.rva != right.rva)
{
                      return left.rva < right.rva;
                  }
                  return left.name < right.name;
              });

    symbols = std::move(enumerated);
    return true;
}

} // namespace miri
