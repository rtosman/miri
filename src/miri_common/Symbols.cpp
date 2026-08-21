#include "miri_common/Symbols.h"

#include "miri_common/StringUtil.h"

#include <algorithm>
#include <regex>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include <windows.h>
#include <DbgHelp.h>

#if MIRI_HAS_DIA
#include <dia2.h>
#include <oleauto.h>
#endif

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
    } 
    catch (const std::regex_error& exception)
    {
        error = std::string("invalid symbol regex: ") + exception.what();
        return false;
    }
    
    return true;
}

bool MatchesFilters(const std::wstring& name, const CompiledFilters& filters)
{
    bool included{filters.include.empty()};
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

    const auto appendUnique{
        [&searchPath](const std::filesystem::path& path) 
    {
        if (path.empty())
        {
            return;
        }
        if (!searchPath.empty())
        {
            searchPath.push_back(L';');
        }
        searchPath += path.wstring();
    }};

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
        SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_FAIL_CRITICAL_ERRORS);

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
    HANDLE process_{nullptr};
    bool initialized_{false};
};

struct EnumContext
{
    const PeImageInfo* image{nullptr};
    const CompiledFilters* filters{nullptr};
    std::uint64_t moduleBase{0};
    std::size_t maxFunctions{0};
    std::vector<FunctionSymbol>* symbols{nullptr};
};

// DIA SymTagEnum values; some SDKs do not expose these through DbgHelp.h.
constexpr ULONG kSymTagFunction{5};
constexpr ULONG kSymTagThunk{27};

struct DecoratedPublicName
{
    std::wstring undecoratedName;
    std::wstring decoratedName;
};

using DecoratedNameMap = std::unordered_map<std::uint32_t, std::vector<DecoratedPublicName>>;

struct PublicEnumContext
{
    const PeImageInfo* image{nullptr};
    std::uint64_t moduleBase{0};
    DecoratedNameMap* decoratedNames{nullptr};
    std::size_t* publicNames{nullptr};
    std::size_t* decoratedPublicNames{nullptr};
};

std::wstring SymbolInfoName(PSYMBOL_INFOW symbol)
{
    if (symbol == nullptr || symbol->Name == nullptr)
    {
        return {};
    }

    std::size_t nameLength{symbol->NameLen};
    while (nameLength > 0 && symbol->Name[nameLength - 1] == L'\0')
    {
        --nameLength;
    }

    return std::wstring(symbol->Name, nameLength);
}

std::wstring UndecorateSymbolName(const std::wstring& name)
{
    if (name.empty())
    {
        return {};
    }

    std::wstring undecorated(4096, L'\0');
    const DWORD length{UnDecorateSymbolNameW(name.c_str(), undecorated.data(),
                                            static_cast<DWORD>(undecorated.size()),
                                            UNDNAME_NAME_ONLY)};
    if (length == 0)
    {
        return name;
    }

    undecorated.resize(length);
    return undecorated;
}

bool LooksDecorated(const std::wstring& name)
{
    return !name.empty() &&
           (name.front() == L'?' || name.find(L"@@") != std::wstring::npos);
}

bool PreferDecoratedName(const std::wstring& candidate, const std::wstring& existing)
{
    const bool candidateDecorated{LooksDecorated(candidate)};
    const bool existingDecorated{LooksDecorated(existing)};
    if (candidateDecorated != existingDecorated)
    {
        return candidateDecorated;
    }

    return candidate.size() > existing.size();
}

bool AddDecoratedPublicName(DecoratedNameMap& decoratedNames,
                            std::uint32_t rva,
                            std::wstring name)
{
    if (name.empty())
    {
        return false;
    }

    std::wstring undecoratedName{UndecorateSymbolName(name)};
    if (undecoratedName.empty())
    {
        return false;
    }

    auto& names{decoratedNames[rva]};
    for (auto& existingName : names)
    {
        if (existingName.undecoratedName == undecoratedName)
        {
            if (PreferDecoratedName(name, existingName.decoratedName))
            {
                existingName.decoratedName = std::move(name);
            }
            return true;
        }
    }

    names.push_back(DecoratedPublicName{std::move(undecoratedName), std::move(name)});
    return true;
}

#if MIRI_HAS_DIA
template <typename T>
class ComPtr
{
public:
    ComPtr() = default;
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;

    ~ComPtr()
    {
        Reset();
    }

    T* Get() const
    {
        return ptr_;
    }

    T** Put()
    {
        Reset();
        return &ptr_;
    }

    T* operator->() const
    {
        return ptr_;
    }

    explicit operator bool() const
    {
        return ptr_ != nullptr;
    }

    void Reset()
    {
        if (ptr_ != nullptr)
        {
            ptr_->Release();
            ptr_ = nullptr;
        }
    }

private:
    T* ptr_{nullptr};
};

class BstrString
{
public:
    BstrString() = default;
    BstrString(const BstrString&) = delete;
    BstrString& operator=(const BstrString&) = delete;

    ~BstrString()
    {
        Reset();
    }

    BSTR* Put()
    {
        Reset();
        return &value_;
    }

    std::wstring ToWideString() const
    {
        if (value_ == nullptr)
        {
            return {};
        }

        return std::wstring(value_, SysStringLen(value_));
    }

private:
    void Reset()
    {
        if (value_ != nullptr)
        {
            SysFreeString(value_);
            value_ = nullptr;
        }
    }

    BSTR value_{nullptr};
};

class ComInitialization
{
public:
    ComInitialization()
    {
        hr_ = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        initialized_ = SUCCEEDED(hr_);
    }

    ComInitialization(const ComInitialization&) = delete;
    ComInitialization& operator=(const ComInitialization&) = delete;

    ~ComInitialization()
    {
        if (initialized_)
        {
            CoUninitialize();
        }
    }

    bool CanUseCom() const
    {
        return SUCCEEDED(hr_) || hr_ == RPC_E_CHANGED_MODE;
    }

private:
    HRESULT hr_{E_FAIL};
    bool initialized_{false};
};

class DiaLibrary
{
public:
    DiaLibrary() = default;
    DiaLibrary(const DiaLibrary&) = delete;
    DiaLibrary& operator=(const DiaLibrary&) = delete;

    ~DiaLibrary()
    {
        if (handle_ != nullptr)
        {
            FreeLibrary(handle_);
        }
    }

    void Attach(HMODULE handle)
    {
        if (handle_ != nullptr)
        {
            FreeLibrary(handle_);
        }
        handle_ = handle;
    }

private:
    HMODULE handle_{nullptr};
};

void AppendDiaDllCandidate(std::vector<std::filesystem::path>& candidates,
                           const std::filesystem::path& candidate)
{
    if (candidate.empty())
    {
        return;
    }

    candidates.push_back(candidate);
}

void AppendDiaDllFromEnvironment(std::vector<std::filesystem::path>& candidates,
                                 const wchar_t* variableName)
{
    const DWORD requiredLength{GetEnvironmentVariableW(variableName, nullptr, 0)};
    if (requiredLength == 0)
    {
        return;
    }

    std::wstring value(requiredLength, L'\0');
    const DWORD actualLength{
        GetEnvironmentVariableW(variableName, value.data(), requiredLength)};
    if (actualLength == 0 || actualLength >= requiredLength)
    {
        return;
    }

    value.resize(actualLength);
    std::filesystem::path path{value};
    if (path.extension() == L".dll")
    {
        AppendDiaDllCandidate(candidates, path);
        return;
    }

    AppendDiaDllCandidate(candidates, path / L"msdia140.dll");
    AppendDiaDllCandidate(candidates, path / L"DIA SDK" / L"bin" / L"amd64" /
                                          L"msdia140.dll");
}

void AppendDiaDllFromExecutableDirectory(std::vector<std::filesystem::path>& candidates)
{
    std::wstring modulePath(MAX_PATH, L'\0');
    const DWORD length{
        GetModuleFileNameW(nullptr, modulePath.data(), static_cast<DWORD>(modulePath.size()))};
    if (length == 0 || length >= modulePath.size())
    {
        return;
    }

    modulePath.resize(length);
    AppendDiaDllCandidate(candidates,
                          std::filesystem::path{modulePath}.parent_path() / L"msdia140.dll");
}

std::vector<std::filesystem::path> BuildDiaDllCandidates()
{
    std::vector<std::filesystem::path> candidates;
    AppendDiaDllFromEnvironment(candidates, L"MIRI_DIA_DLL_PATH");
    AppendDiaDllFromEnvironment(candidates, L"VSINSTALLDIR");
    AppendDiaDllFromExecutableDirectory(candidates);
    AppendDiaDllCandidate(candidates, L"msdia140.dll");
    AppendDiaDllCandidate(candidates,
                          L"E:\\Program Files\\Microsoft Visual Studio\\18\\Community\\DIA SDK\\bin\\amd64\\msdia140.dll");
    AppendDiaDllCandidate(candidates,
                          L"E:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\DIA SDK\\bin\\amd64\\msdia140.dll");
    AppendDiaDllCandidate(candidates,
                          L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\DIA SDK\\bin\\amd64\\msdia140.dll");
    AppendDiaDllCandidate(candidates,
                          L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\DIA SDK\\bin\\amd64\\msdia140.dll");
    AppendDiaDllCandidate(candidates,
                          L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\DIA SDK\\bin\\amd64\\msdia140.dll");
    return candidates;
}

HMODULE TryLoadDiaDll(const std::filesystem::path& dllPath)
{
    if (dllPath.empty())
    {
        return nullptr;
    }

    if (!dllPath.has_parent_path())
    {
        return LoadLibraryW(dllPath.wstring().c_str());
    }

    std::error_code ignored;
    if (!std::filesystem::exists(dllPath, ignored))
    {
        return nullptr;
    }

    return LoadLibraryExW(dllPath.wstring().c_str(), nullptr,
                          LOAD_LIBRARY_SEARCH_DEFAULT_DIRS |
                              LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR);
}

bool CreateDiaDataSourceFromDll(ComPtr<IDiaDataSource>& dataSource, DiaLibrary& diaLibrary)
{
    using DllGetClassObjectFn = HRESULT(STDAPICALLTYPE*)(REFCLSID, REFIID, LPVOID*);

    for (const auto& candidate : BuildDiaDllCandidates())
    {
        HMODULE module{TryLoadDiaDll(candidate)};
        if (module == nullptr)
        {
            continue;
        }

        auto* getClassObject{
            reinterpret_cast<DllGetClassObjectFn>(GetProcAddress(module, "DllGetClassObject"))};
        if (getClassObject == nullptr)
        {
            FreeLibrary(module);
            continue;
        }

        ComPtr<IClassFactory> classFactory;
        HRESULT hr{getClassObject(CLSID_DiaSource, __uuidof(IClassFactory),
                                  reinterpret_cast<void**>(classFactory.Put()))};
        if (SUCCEEDED(hr))
        {
            hr = classFactory->CreateInstance(
                nullptr, __uuidof(IDiaDataSource), reinterpret_cast<void**>(dataSource.Put()));
        }

        if (SUCCEEDED(hr) && dataSource)
        {
            diaLibrary.Attach(module);
            return true;
        }

        FreeLibrary(module);
    }

    return false;
}

bool CreateDiaDataSource(ComPtr<IDiaDataSource>& dataSource, DiaLibrary& diaLibrary)
{
    HRESULT hr{CoCreateInstance(CLSID_DiaSource, nullptr, CLSCTX_INPROC_SERVER,
                                __uuidof(IDiaDataSource),
                                reinterpret_cast<void**>(dataSource.Put()))};
    if (SUCCEEDED(hr) && dataSource)
    {
        return true;
    }

    return CreateDiaDataSourceFromDll(dataSource, diaLibrary);
}

void LoadDecoratedPublicNamesFromDia(const std::filesystem::path& pdbPath,
                                     const PeImageInfo& image,
                                     DecoratedNameMap& decoratedNames,
                                     SymbolEnumerationReport& report)
{
    report.diaCompiled = true;

    ComInitialization com;
    if (!com.CanUseCom())
    {
        return;
    }

    DiaLibrary diaLibrary;
    ComPtr<IDiaDataSource> dataSource;
    if (!CreateDiaDataSource(dataSource, diaLibrary))
    {
        return;
    }
    report.diaLoaded = true;

    const HRESULT loadResult{dataSource->loadDataFromPdb(pdbPath.wstring().c_str())};
    if (FAILED(loadResult))
    {
        return;
    }

    ComPtr<IDiaSession> session;
    if (FAILED(dataSource->openSession(session.Put())))
    {
        return;
    }

    ComPtr<IDiaSymbol> globalScope;
    if (FAILED(session->get_globalScope(globalScope.Put())))
    {
        return;
    }

    ComPtr<IDiaEnumSymbols> publicSymbols;
    if (FAILED(session->findChildren(globalScope.Get(), SymTagPublicSymbol, nullptr, 0,
                                     publicSymbols.Put())))
    {
        return;
    }

    for (;;)
    {
        ComPtr<IDiaSymbol> symbol;
        ULONG fetched{0};
        const HRESULT nextResult{publicSymbols->Next(1, symbol.Put(), &fetched)};
        if (FAILED(nextResult) || fetched == 0)
        {
            break;
        }

        BOOL isCode{FALSE};
        BOOL isFunction{FALSE};
        if ((FAILED(symbol->get_code(&isCode)) || !isCode) &&
            (FAILED(symbol->get_function(&isFunction)) || !isFunction))
        {
            continue;
        }

        DWORD rva{0};
        if (FAILED(symbol->get_relativeVirtualAddress(&rva)) || !image.IsExecutableRva(rva))
        {
            continue;
        }

        BstrString name;
        if (FAILED(symbol->get_name(name.Put())))
        {
            continue;
        }

        std::wstring publicName{name.ToWideString()};
        const bool decorated{LooksDecorated(publicName)};
        if (AddDecoratedPublicName(decoratedNames, rva, std::move(publicName)))
        {
            ++report.diaPublicNames;
            if (decorated)
            {
                ++report.diaDecoratedPublicNames;
            }
        }
    }
}
#else
void LoadDecoratedPublicNamesFromDia(const std::filesystem::path&,
                                     const PeImageInfo&,
                                     DecoratedNameMap&,
                                     SymbolEnumerationReport&)
{
}
#endif

BOOL CALLBACK PublicSymbolCallback(PSYMBOL_INFOW symbol, ULONG, PVOID userContext)
{
    auto* context{static_cast<PublicEnumContext*>(userContext)};
    if (context == nullptr || symbol == nullptr || context->decoratedNames == nullptr)
    {
        return FALSE;
    }

    if (symbol->Address < context->moduleBase)
    {
        return TRUE;
    }

    const std::uint64_t rawRva{symbol->Address - context->moduleBase};
    if (rawRva > UINT32_MAX)
    {
        return TRUE;
    }

    const auto rva{static_cast<std::uint32_t>(rawRva)};
    if (!context->image->IsExecutableRva(rva))
    {
        return TRUE;
    }

    std::wstring name{SymbolInfoName(symbol)};
    const bool decorated{LooksDecorated(name)};
    if (AddDecoratedPublicName(*context->decoratedNames, rva, std::move(name)))
    {
        if (context->publicNames != nullptr)
        {
            ++*context->publicNames;
        }
        if (decorated && context->decoratedPublicNames != nullptr)
        {
            ++*context->decoratedPublicNames;
        }
    }

    return TRUE;
}

void LoadDecoratedPublicNamesFromDbgHelp(HANDLE process,
                                         std::uint64_t moduleBase,
                                         const PeImageInfo& image,
                                         DecoratedNameMap& decoratedNames,
                                         SymbolEnumerationReport& report)
{
    const DWORD savedOptions{SymGetOptions()};
    const DWORD publicOptions{(savedOptions | SYMOPT_PUBLICS_ONLY) & ~SYMOPT_UNDNAME};
    SymSetOptions(publicOptions);

    PublicEnumContext context;
    context.image = &image;
    context.moduleBase = moduleBase;
    context.decoratedNames = &decoratedNames;
    context.publicNames = &report.dbghelpPublicNames;
    context.decoratedPublicNames = &report.dbghelpDecoratedPublicNames;

    SetLastError(ERROR_SUCCESS);
    SymEnumSymbolsW(process, moduleBase, L"*", PublicSymbolCallback, &context);
    SymSetOptions(savedOptions);
}

void ApplyDecoratedPublicNames(std::vector<FunctionSymbol>& symbols,
                               const DecoratedNameMap& decoratedNames,
                               SymbolEnumerationReport& report)
{
    if (decoratedNames.empty())
    {
        return;
    }

    for (auto& symbol : symbols)
    {
        const auto decorated{decoratedNames.find(symbol.rva)};
        if (decorated == decoratedNames.end())
        {
            continue;
        }

        const auto& names{decorated->second};
        const auto nameMatch{std::find_if(names.begin(), names.end(),
                                          [&symbol](const DecoratedPublicName& publicName)
                                          {
                                              return publicName.undecoratedName == symbol.name;
                                          })};
        if (nameMatch != names.end())
        {
            symbol.mangledName = nameMatch->decoratedName;
            ++report.publicNameMatches;
        }
        else if (names.size() == 1)
        {
            symbol.mangledName = names.front().decoratedName;
            ++report.publicNameMatches;
        }

        if (LooksDecorated(symbol.mangledName))
        {
            ++report.finalDecoratedNames;
        }
    }
}

BOOL CALLBACK EnumSymbolCallback(PSYMBOL_INFOW symbol, ULONG symbolSize, PVOID userContext)
{
    auto* context{static_cast<EnumContext*>(userContext)};
    if (context == nullptr || symbol == nullptr || context->symbols == nullptr)
    {
        return FALSE;
    }

    const bool isFunction{(symbol->Flags & SYMFLAG_FUNCTION) != 0 ||
                            symbol->Tag == kSymTagFunction ||
                            symbol->Tag == kSymTagThunk};
    if (!isFunction || symbol->Address < context->moduleBase)
    {
        return TRUE;
    }

    const std::uint64_t rawRva{symbol->Address - context->moduleBase};
    if (rawRva > UINT32_MAX)
    {
        return TRUE;
    }

    const auto rva{static_cast<std::uint32_t>(rawRva)};
    if (!context->image->IsExecutableRva(rva))
    {
        return TRUE;
    }

    std::wstring mangledName{SymbolInfoName(symbol)};
    std::wstring name{UndecorateSymbolName(mangledName)};
    if (name.empty() || !MatchesFilters(name, *context->filters))
    {
        return TRUE;
    }

    FunctionSymbol function;
    function.name = std::move(name);
    function.mangledName = std::move(mangledName);
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
    DWORD64 moduleBase{SymLoadModuleExW(process, nullptr, exePath.wstring().c_str(), nullptr,
                                          image.imageBase, image.sizeOfImage, nullptr, 0)};
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
                           bool collectMangledNames,
                           std::vector<FunctionSymbol>& symbols,
                           SymbolEnumerationReport& report,
                           std::string& error)
{
    report = SymbolEnumerationReport{};

    CompiledFilters compiledFilters;
    if (!CompileFilters(filters, compiledFilters, error))
    {
        return false;
    }

    SymbolSession session;
    const std::wstring searchPath{BuildSymbolSearchPath(exePath, pdbPath)};
    if (!session.Initialize(searchPath, error))
    {
        return false;
    }

    const DWORD64 moduleBase{LoadModuleWithFallback(session.Process(), exePath, pdbPath, image)};
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
    const BOOL ok{SymEnumSymbolsW(session.Process(), moduleBase, L"*", EnumSymbolCallback,
                                    &context)};
    if (!ok && GetLastError() != ERROR_SUCCESS)
    {
        error = "SymEnumSymbolsW failed: " + LastWin32ErrorMessage();
        return false;
    }

    if (collectMangledNames)
    {
        DecoratedNameMap decoratedNames;
        LoadDecoratedPublicNamesFromDbgHelp(session.Process(), moduleBase, image, decoratedNames,
                                           report);
        LoadDecoratedPublicNamesFromDia(pdbPath, image, decoratedNames, report);
        ApplyDecoratedPublicNames(enumerated, decoratedNames, report);
    }

    report.finalDecoratedNames =
        static_cast<std::size_t>(std::count_if(enumerated.begin(), enumerated.end(),
                                               [](const FunctionSymbol& symbol)
                                               {
                                                   return LooksDecorated(symbol.mangledName);
                                               }));

    std::sort(enumerated.begin(), enumerated.end(),
              [](const FunctionSymbol& left, const FunctionSymbol& right) 
              {
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
