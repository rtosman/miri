// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Rennie Allen

#include "miri_common/Config.h"
#include "miri_common/MiriTypes.h"
#include "miri_common/PeImage.h"
#include "miri_common/RemotePatch.h"
#include "miri_common/StringUtil.h"
#include "miri_common/Symbols.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <windows.h>
#include <DbgHelp.h>
#include <tlhelp32.h>

namespace
{

using miri::FunctionSymbol;
using miri::PeImageInfo;
using miri::PatchOptions;
using miri::RunConfig;
using miri::SymbolFilters;

struct ProcessHandles
{
    PROCESS_INFORMATION info{};

    ~ProcessHandles()
    {
        if (info.hThread != nullptr)
        {
            CloseHandle(info.hThread);
        }

        if (info.hProcess != nullptr)
        {
            CloseHandle(info.hProcess);
        }
    }
};

struct OwnedHandle
{
    HANDLE handle{nullptr};

    OwnedHandle() = default;
    explicit OwnedHandle(HANDLE value) : handle(value) {}
    OwnedHandle(const OwnedHandle&) = delete;
    OwnedHandle& operator=(const OwnedHandle&) = delete;
    OwnedHandle(OwnedHandle&& other) noexcept : handle(other.handle)
    {
        other.handle = nullptr;
    }

    OwnedHandle& operator=(OwnedHandle&& other) noexcept
    {
        if (this != &other)
        {
            Reset(other.handle);
            other.handle = nullptr;
        }
        return *this;
    }

    ~OwnedHandle()
    {
        Reset();
    }

    void Reset(HANDLE value = nullptr)
    {
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(handle);
        }
        handle = value;
    }

    HANDLE Get() const
    {
        return handle;
    }

    bool IsValid() const
    {
        return handle != nullptr && handle != INVALID_HANDLE_VALUE;
    }
};

struct CommandLineOptions
{
    bool attach{false};
    bool verbose{false};
    bool includeMangled{false};
    DWORD pid{0};
    std::filesystem::path exePath;
    std::filesystem::path pdbPath;
    std::filesystem::path configPath;
};

void PrintUsage()
{
    std::wcerr << L"usage:\n"
               << L"  miri-run [-v|--verbose] [--mangled] <target.exe> <target.pdb> [config.json]\n"
               << L"  miri-run [-v|--verbose] [--mangled] --pid <pid> [target.pdb] [config.json]\n"
               << L"  miri-run [-v|--verbose] [--mangled] --attach <pid> [target.pdb] [config.json]\n";
}

std::filesystem::path AbsolutePath(const std::filesystem::path& path)
{
    std::error_code ignored;
    return std::filesystem::absolute(path, ignored);
}

std::filesystem::path ResolvePath(const std::filesystem::path& path,
                                  const std::filesystem::path& base)
{
    if (path.empty() || path.is_absolute())
    {
        return path;
    }
    return AbsolutePath(base / path);
}

std::wstring ToLower(std::wstring value)
{
    std::transform(value.begin(), value.end(), value.begin(),
                   [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
    return value;
}

bool IsJsonPath(const std::filesystem::path& path)
{
    return ToLower(path.extension().wstring()) == L".json";
}

bool IsVerboseSwitch(std::wstring_view argument)
{
    return argument == L"-v" || argument == L"--verbose";
}

bool IsMangledSwitch(std::wstring_view argument)
{
    return argument == L"--mangled";
}

std::filesystem::path DefaultPdbPath(const std::filesystem::path& exePath)
{
    std::filesystem::path pdbPath{exePath};
    pdbPath.replace_extension(L".pdb");
    return pdbPath;
}

bool ParsePid(std::wstring_view text, DWORD& pid)
{
    if (text.empty())
    {
        return false;
    }

    std::wstring owned(text);
    wchar_t* end{nullptr};
    errno = 0;
    const unsigned long long value{std::wcstoull(owned.c_str(), &end, 10)};
    if (errno == ERANGE || end == owned.c_str() || *end != L'\0' || value == 0 ||
        value > std::numeric_limits<DWORD>::max()) {
        return false;
    }

    pid = static_cast<DWORD>(value);
    return true;
}

bool ParseCommandLine(int argc, wchar_t** argv, CommandLineOptions& options)
{
    std::vector<wchar_t*> arguments;
    arguments.reserve(static_cast<std::size_t>(argc));
    arguments.push_back(argv[0]);
    for (int index{1}; index < argc; ++index)
    {
        if (IsVerboseSwitch(argv[index]))
        {
            options.verbose = true;
            continue;
        }
        if (IsMangledSwitch(argv[index]))
        {
            options.includeMangled = true;
            continue;
        }
        arguments.push_back(argv[index]);
    }

    const int filteredArgc{static_cast<int>(arguments.size())};
    wchar_t** filteredArgv{arguments.data()};

    if (filteredArgc >= 2)
    {
        const std::wstring_view command{filteredArgv[1]};
        if (command == L"--pid" || command == L"--attach")
        {
            if (filteredArgc < 3 || filteredArgc > 5)
            {
                return false;
            }
            if (!ParsePid(filteredArgv[2], options.pid))
            {
                std::wcerr << L"invalid pid: " << filteredArgv[2] << L"\n";
                return false;
            }

            options.attach = true;
            if (filteredArgc >= 4)
            {
                const std::filesystem::path first{AbsolutePath(filteredArgv[3])};
                if (filteredArgc == 4 && IsJsonPath(first))
                {
                    options.configPath = first;
                }
                else
                {
                    options.pdbPath = first;
                }
            }
            if (filteredArgc == 5)
            {
                options.configPath = AbsolutePath(filteredArgv[4]);
            }
            return true;
        }
    }

    if (filteredArgc < 3 || filteredArgc > 4)
    {
        return false;
    }

    options.exePath = AbsolutePath(filteredArgv[1]);
    options.pdbPath = AbsolutePath(filteredArgv[2]);
    if (filteredArgc == 4)
    {
        options.configPath = AbsolutePath(filteredArgv[3]);
    }

    return true;
}

bool QueryProcessImagePath(DWORD pid, std::filesystem::path& exePath, std::string& error)
{
    OwnedHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process.IsValid())
    {
        error = "OpenProcess failed for pid " + std::to_string(pid) + ": " +
                miri::LastWin32ErrorMessage();
        return false;
    }

    std::wstring buffer(32768, L'\0');
    DWORD length{static_cast<DWORD>(buffer.size())};
    if (!QueryFullProcessImageNameW(process.Get(), 0, buffer.data(), &length))
    {
        error = "QueryFullProcessImageNameW failed for pid " + std::to_string(pid) + ": " +
                miri::LastWin32ErrorMessage();
        return false;
    }

    buffer.resize(length);
    exePath = AbsolutePath(buffer);
    return true;
}

bool FindMainModuleBase(DWORD pid, std::uint64_t& imageBase, std::string& error)
{
    OwnedHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
    if (!snapshot.IsValid())
    {
        error = "CreateToolhelp32Snapshot failed for pid " + std::to_string(pid) + ": " +
                miri::LastWin32ErrorMessage();
        return false;
    }

    MODULEENTRY32W module{};
    module.dwSize = sizeof(module);
    if (!Module32FirstW(snapshot.Get(), &module))
    {
        error = "Module32FirstW failed for pid " + std::to_string(pid) + ": " +
                miri::LastWin32ErrorMessage();
        return false;
    }

    imageBase = reinterpret_cast<std::uint64_t>(module.modBaseAddr);
    return true;
}

void AppendSymbolSearchPath(std::wstring& searchPath, const std::wstring& path)
{
    if (path.empty())
    {
        return;
    }
    if (!searchPath.empty())
    {
        searchPath.push_back(L';');
    }
    searchPath += path;
}

void AppendSymbolSearchPath(std::wstring& searchPath, const std::filesystem::path& path)
{
    if (!path.empty())
    {
        AppendSymbolSearchPath(searchPath, path.wstring());
    }
}

std::wstring ReadEnvironmentVariable(const wchar_t* name)
{
    const DWORD required{GetEnvironmentVariableW(name, nullptr, 0)};
    if (required == 0)
    {
        return {};
    }

    std::wstring value(required, L'\0');
    const DWORD written{GetEnvironmentVariableW(name, value.data(), required)};
    if (written == 0)
    {
        return {};
    }

    value.resize(written);
    return value;
}

std::wstring BuildStackSymbolSearchPath(const std::filesystem::path& exePath,
                                        const std::filesystem::path& pdbPath)
{
    std::wstring searchPath;
    AppendSymbolSearchPath(searchPath, pdbPath.parent_path());
    if (exePath.parent_path() != pdbPath.parent_path())
    {
        AppendSymbolSearchPath(searchPath, exePath.parent_path());
    }
    AppendSymbolSearchPath(searchPath, std::filesystem::current_path());
    AppendSymbolSearchPath(searchPath, ReadEnvironmentVariable(L"_NT_SYMBOL_PATH"));
    AppendSymbolSearchPath(searchPath, ReadEnvironmentVariable(L"_NT_ALT_SYMBOL_PATH"));
    return searchPath;
}

class DebugThreadRegistry
{
public:
    void Add(DWORD threadId, HANDLE thread)
    {
        if (thread != nullptr && thread != INVALID_HANDLE_VALUE)
        {
            threads_[threadId] = thread;
        }
    }

    void Remove(DWORD threadId)
    {
        threads_.erase(threadId);
    }

    HANDLE Get(DWORD threadId) const
    {
        const auto it{threads_.find(threadId)};
        if (it == threads_.end())
        {
            return nullptr;
        }
        return it->second;
    }

private:
    std::unordered_map<DWORD, HANDLE> threads_;
};

class StackPrinter
{
public:
    struct CapturedStack
    {
        bool valid{false};
        std::vector<std::string> lines;
    };

    StackPrinter() = default;
    StackPrinter(const StackPrinter&) = delete;
    StackPrinter& operator=(const StackPrinter&) = delete;

    ~StackPrinter()
    {
        if (initialized_)
        {
            SymCleanup(process_);
        }
    }

    bool Initialize(HANDLE process,
                    const std::filesystem::path& exePath,
                    const std::filesystem::path& pdbPath,
                    std::string& error)
    {
        process_ = process;
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES |
                      SYMOPT_FAIL_CRITICAL_ERRORS);

        const std::wstring searchPath{BuildStackSymbolSearchPath(exePath, pdbPath)};
        if (!SymInitializeW(process_, searchPath.empty() ? nullptr : searchPath.c_str(), FALSE))
        {
            error = "SymInitializeW for stack capture failed: " + miri::LastWin32ErrorMessage();
            return false;
        }

        initialized_ = true;
        return true;
    }

    bool PrintStack(const std::string& reason,
                    DWORD pid,
                    DWORD threadId,
                    HANDLE thread,
                    bool useEntryReturnAddress = false)
    {
        std::cerr << "\ntermination callstack: " << reason << "\n";
        std::cerr << "  pid " << pid << ", tid " << threadId << "\n";

        CapturedStack stack{CaptureStack(thread, useEntryReturnAddress)};
        for (const auto& line : stack.lines)
        {
            std::cerr << line << "\n";
        }
        return stack.valid;
    }

    CapturedStack CaptureStack(HANDLE thread, bool useEntryReturnAddress = false)
    {
        CapturedStack captured;

        if (!initialized_)
        {
            captured.lines.push_back("  unavailable: symbol session was not initialized");
            return captured;
        }
        if (thread == nullptr || thread == INVALID_HANDLE_VALUE)
        {
            captured.lines.push_back("  unavailable: no thread handle for debug event thread");
            return captured;
        }

        CONTEXT context{};
        context.ContextFlags = CONTEXT_ALL;
        if (!GetThreadContext(thread, &context))
        {
            captured.lines.push_back("  unavailable: GetThreadContext failed: " +
                                     miri::LastWin32ErrorMessage());
            return captured;
        }

        SymRefreshModuleList(process_);

        STACKFRAME64 frame{};
        frame.AddrPC.Offset = context.Rip;
        frame.AddrPC.Mode = AddrModeFlat;
        frame.AddrFrame.Offset = context.Rbp;
        frame.AddrFrame.Mode = AddrModeFlat;
        frame.AddrStack.Offset = context.Rsp;
        frame.AddrStack.Mode = AddrModeFlat;

        constexpr DWORD kMaxFrames{64};
        DWORD printedFrames{0};
        for (DWORD frameIndex{0}; frameIndex < kMaxFrames; ++frameIndex)
        {
            if (frame.AddrPC.Offset == 0)
            {
                break;
            }

            captured.lines.push_back("  #" + std::to_string(frameIndex) + " " +
                                     FormatSymbol(frame.AddrPC.Offset));
            printedFrames = frameIndex + 1;

            const DWORD64 previousPc{frame.AddrPC.Offset};
            if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, process_, thread, &frame, &context,
                             nullptr, SymFunctionTableAccess64, SymGetModuleBase64, nullptr)) {
                break;
            }
            if (frame.AddrPC.Offset == previousPc)
            {
                break;
            }
        }

        if (useEntryReturnAddress && printedFrames <= 1)
        {
            AppendEntryReturnStack(context, thread, printedFrames, kMaxFrames, captured.lines);
        }

        captured.valid = !captured.lines.empty();
        return captured;
    }

private:
    void AppendEntryReturnStack(const CONTEXT& interruptedContext,
                               HANDLE thread,
                               DWORD& printedFrames,
                               DWORD maxFrames,
                               std::vector<std::string>& lines)
    {
        DWORD64 returnAddress{0};
        SIZE_T bytesRead{0};
        auto* remoteStack{reinterpret_cast<void*>(
            static_cast<std::uintptr_t>(interruptedContext.Rsp))};
        if (!ReadProcessMemory(process_, remoteStack, &returnAddress, sizeof(returnAddress),
                               &bytesRead) ||
            bytesRead != sizeof(returnAddress) || returnAddress == 0) {
            return;
        }

        lines.push_back("  #" + std::to_string(printedFrames) + " " +
                        FormatSymbol(returnAddress) + " (return address)");
        ++printedFrames;

        CONTEXT callerContext{interruptedContext};
        callerContext.Rip = returnAddress;
        callerContext.Rsp = interruptedContext.Rsp + sizeof(DWORD64);

        STACKFRAME64 callerFrame{};
        callerFrame.AddrPC.Offset = callerContext.Rip;
        callerFrame.AddrPC.Mode = AddrModeFlat;
        callerFrame.AddrFrame.Offset = callerContext.Rbp;
        callerFrame.AddrFrame.Mode = AddrModeFlat;
        callerFrame.AddrStack.Offset = callerContext.Rsp;
        callerFrame.AddrStack.Mode = AddrModeFlat;

        while (printedFrames < maxFrames)
        {
            const DWORD64 previousPc{callerFrame.AddrPC.Offset};
            if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, process_, thread, &callerFrame,
                             &callerContext, nullptr, SymFunctionTableAccess64,
                             SymGetModuleBase64, nullptr)) {
                break;
            }

            if (callerFrame.AddrPC.Offset == 0 || callerFrame.AddrPC.Offset == previousPc)
            {
                break;
            }

            lines.push_back("  #" + std::to_string(printedFrames) + " " +
                            FormatSymbol(callerFrame.AddrPC.Offset));
            ++printedFrames;
        }
    }

    std::string FormatSymbol(DWORD64 address)
    {
        IMAGEHLP_MODULEW64 module{};
        module.SizeOfStruct = sizeof(module);
        const bool haveModule{SymGetModuleInfoW64(process_, address, &module) == TRUE};

        std::string moduleName;
        if (haveModule && module.ModuleName[0] != L'\0')
        {
            moduleName = miri::WideToUtf8(module.ModuleName);
        }

        constexpr DWORD kMaxSymbolName{1024};
        std::vector<std::uint8_t> storage(sizeof(SYMBOL_INFOW) +
                                          kMaxSymbolName * sizeof(wchar_t));
        auto* symbol{reinterpret_cast<SYMBOL_INFOW*>(storage.data())};
        symbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
        symbol->MaxNameLen = kMaxSymbolName;

        DWORD64 displacement{0};
        std::string result;
        if (!moduleName.empty())
        {
            result += moduleName;
            result += '!';
        }

        if (SymFromAddrW(process_, address, &displacement, symbol))
        {
            result += miri::WideToUtf8(std::wstring(symbol->Name, symbol->NameLen));
            if (displacement != 0)
            {
                result += '+';
                result += miri::Hex64(displacement);
            }
        }
        else
        if (haveModule)
        {
            result += '+';
            result += miri::Hex64(address - module.BaseOfImage);
        }
        else
        {
            result += miri::Hex64(address);
        }

        result += " [";
        result += miri::Hex64(address);
        result += ']';

        IMAGEHLP_LINEW64 line{};
        line.SizeOfStruct = sizeof(line);
        DWORD lineDisplacement{0};
        if (SymGetLineFromAddrW64(process_, address, &lineDisplacement, &line) &&
            line.FileName != nullptr)
        {
            result += " (";
            result += miri::WideToUtf8(line.FileName);
            result += ':';
            result += std::to_string(line.LineNumber);
            result += ')';
        }

        return result;
    }

    HANDLE process_{nullptr};
    bool initialized_{false};
};

struct TerminationApiDefinition
{
    const wchar_t* moduleName{nullptr};
    const char* exportName{nullptr};
    const char* displayName{nullptr};
};

constexpr std::array<TerminationApiDefinition, 15> kTerminationApis{{
    {L"kernel32.dll", "ExitProcess", "kernel32!ExitProcess"},
    {L"kernel32.dll", "TerminateProcess", "kernel32!TerminateProcess"},
    {L"kernelbase.dll", "ExitProcess", "kernelbase!ExitProcess"},
    {L"kernelbase.dll", "TerminateProcess", "kernelbase!TerminateProcess"},
    {L"ntdll.dll", "RtlExitUserProcess", "ntdll!RtlExitUserProcess"},
    {L"ntdll.dll", "NtTerminateProcess", "ntdll!NtTerminateProcess"},
    {L"ucrtbase.dll", "exit", "ucrtbase!exit"},
    {L"ucrtbase.dll", "_exit", "ucrtbase!_exit"},
    {L"ucrtbase.dll", "_Exit", "ucrtbase!_Exit"},
    {L"ucrtbase.dll", "quick_exit", "ucrtbase!quick_exit"},
    {L"ucrtbase.dll", "abort", "ucrtbase!abort"},
    {L"ucrtbased.dll", "exit", "ucrtbased!exit"},
    {L"ucrtbased.dll", "_exit", "ucrtbased!_exit"},
    {L"ucrtbased.dll", "_Exit", "ucrtbased!_Exit"},
    {L"ucrtbased.dll", "abort", "ucrtbased!abort"},
}};

bool WriteProcessByte(HANDLE process,
                      std::uint64_t address,
                      BYTE value,
                      BYTE* originalValue,
                      std::string& error)
{
    auto* remoteAddress{reinterpret_cast<void*>(static_cast<std::uintptr_t>(address))};

    DWORD oldProtect{0};
    if (!VirtualProtectEx(process, remoteAddress, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        error = "VirtualProtectEx failed at " + miri::Hex64(address) + ": " +
                miri::LastWin32ErrorMessage();
        return false;
    }

    const auto restoreProtection{[&]() {
        DWORD ignored{0};
        VirtualProtectEx(process, remoteAddress, 1, oldProtect, &ignored);
    }};

    if (originalValue != nullptr)
    {
        SIZE_T bytesRead{0};
        if (!ReadProcessMemory(process, remoteAddress, originalValue, 1, &bytesRead) ||
            bytesRead != 1) {
            error = "ReadProcessMemory failed at " + miri::Hex64(address) + ": " +
                    miri::LastWin32ErrorMessage();
            restoreProtection();
            return false;
        }
    }

    SIZE_T bytesWritten{0};
    if (!WriteProcessMemory(process, remoteAddress, &value, 1, &bytesWritten) ||
        bytesWritten != 1) {
        error = "WriteProcessMemory failed at " + miri::Hex64(address) + ": " +
                miri::LastWin32ErrorMessage();
        restoreProtection();
        return false;
    }

    FlushInstructionCache(process, remoteAddress, 1);
    restoreProtection();
    return true;
}

class TerminationBreakpointManager
{
public:
    void InstallFromLoadedModules(HANDLE process, DWORD pid)
    {
        OwnedHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                                      pid));
        if (!snapshot.IsValid())
        {
            return;
        }

        MODULEENTRY32W module{};
        module.dwSize = sizeof(module);
        if (!Module32FirstW(snapshot.Get(), &module))
        {
            return;
        }

        do
        {
            const auto moduleBase{reinterpret_cast<std::uint64_t>(module.modBaseAddr)};
            TryInstallForModule(process, module.szModule, moduleBase);
        } while (Module32NextW(snapshot.Get(), &module));
    }

    bool HandleException(const DEBUG_EVENT& event,
                         HANDLE process,
                         HANDLE thread,
                         StackPrinter& stackPrinter,
                         bool& printedTerminationStack,
                         DWORD& continueStatus)
    {
        const auto& exception{event.u.Exception.ExceptionRecord};
        const DWORD exceptionCode{exception.ExceptionCode};

        if (exceptionCode == EXCEPTION_SINGLE_STEP)
        {
            const auto stepping{singleStepThreads_.find(event.dwThreadId)};
            if (stepping == singleStepThreads_.end())
            {
                return false;
            }

            ReinstallBreakpoint(process, stepping->second);
            singleStepThreads_.erase(stepping);
            continueStatus = DBG_CONTINUE;
            return true;
        }

        if (exceptionCode != EXCEPTION_BREAKPOINT)
        {
            return false;
        }

        const auto exceptionAddress{reinterpret_cast<std::uint64_t>(exception.ExceptionAddress)};
        const auto breakpoint{breakpoints_.find(exceptionAddress)};
        if (breakpoint == breakpoints_.end())
        {
            return false;
        }

        if (!printedTerminationStack)
        {
            std::string reason{"termination API "};
            reason += breakpoint->second.displayName;
            reason += " hit";
            printedTerminationStack =
                stackPrinter.PrintStack(reason, event.dwProcessId, event.dwThreadId, thread,
                                        true);
        }

        std::string error;
        if (!WriteProcessByte(process, breakpoint->second.address,
                              breakpoint->second.originalByte, nullptr, error)) {
            std::cerr << "failed to restore termination breakpoint at "
                      << miri::Hex64(breakpoint->second.address) << ": " << error << "\n";
            continueStatus = DBG_CONTINUE;
            return true;
        }
        breakpoint->second.enabled = false;

        CONTEXT context{};
        context.ContextFlags = CONTEXT_ALL;
        if (!GetThreadContext(thread, &context))
        {
            std::cerr << "failed to read context after termination breakpoint: "
                      << miri::LastWin32ErrorMessage() << "\n";
            continueStatus = DBG_CONTINUE;
            return true;
        }

        context.Rip = breakpoint->second.address;
        context.EFlags |= 0x100;
        if (!SetThreadContext(thread, &context))
        {
            std::cerr << "failed to set context after termination breakpoint: "
                      << miri::LastWin32ErrorMessage() << "\n";
            continueStatus = DBG_CONTINUE;
            return true;
        }

        singleStepThreads_[event.dwThreadId] = breakpoint->second.address;
        continueStatus = DBG_CONTINUE;
        return true;
    }

private:
    struct Breakpoint
    {
        std::uint64_t address{0};
        BYTE originalByte{0};
        const char* displayName{nullptr};
        bool enabled{false};
    };

    void TryInstallForModule(HANDLE process,
                             const std::wstring& moduleName,
                             std::uint64_t remoteModuleBase)
    {
        if (remoteModuleBase == 0)
        {
            return;
        }

        const std::wstring baseName{ToLower(std::filesystem::path(moduleName).filename().wstring())};
        for (const auto& api : kTerminationApis)
        {
            if (baseName != ToLower(api.moduleName))
            {
                continue;
            }

            const std::uint64_t remoteAddress{ResolveRemoteExport(api, remoteModuleBase)};
            if (remoteAddress == 0 || breakpoints_.find(remoteAddress) != breakpoints_.end())
            {
                continue;
            }

            BYTE originalByte{0};
            std::string error;
            if (!WriteProcessByte(process, remoteAddress, 0xCC, &originalByte, error))
            {
                std::cerr << "failed to install termination breakpoint for "
                          << api.displayName << ": " << error << "\n";
                continue;
            }

            Breakpoint breakpoint;
            breakpoint.address = remoteAddress;
            breakpoint.originalByte = originalByte;
            breakpoint.displayName = api.displayName;
            breakpoint.enabled = true;
            breakpoints_[remoteAddress] = breakpoint;
        }
    }

    std::uint64_t ResolveRemoteExport(const TerminationApiDefinition& api,
                                      std::uint64_t remoteModuleBase)
    {
        HMODULE localModule{GetModuleHandleW(api.moduleName)};
        if (localModule == nullptr)
        {
            localModule = LoadLibraryW(api.moduleName);
        }
        if (localModule == nullptr)
        {
            return 0;
        }

        FARPROC localExport{GetProcAddress(localModule, api.exportName)};
        if (localExport == nullptr)
        {
            return 0;
        }

        MEMORY_BASIC_INFORMATION memoryInfo{};
        if (VirtualQuery(reinterpret_cast<void*>(localExport), &memoryInfo,
                         sizeof(memoryInfo)) == 0 ||
            memoryInfo.AllocationBase != localModule) {
            return 0;
        }

        const auto localBase{reinterpret_cast<std::uint64_t>(localModule)};
        const auto localAddress{reinterpret_cast<std::uint64_t>(localExport)};
        return remoteModuleBase + (localAddress - localBase);
    }

    void ReinstallBreakpoint(HANDLE process, std::uint64_t address)
    {
        const auto breakpoint{breakpoints_.find(address)};
        if (breakpoint == breakpoints_.end() || breakpoint->second.enabled)
        {
            return;
        }

        std::string error;
        if (!WriteProcessByte(process, address, 0xCC, nullptr, error))
        {
            std::cerr << "failed to reinstall termination breakpoint at "
                      << miri::Hex64(address) << ": " << error << "\n";
            return;
        }
        breakpoint->second.enabled = true;
    }

    std::unordered_map<std::uint64_t, Breakpoint> breakpoints_;
    std::unordered_map<DWORD, std::uint64_t> singleStepThreads_;
};

OwnedHandle OpenDebugThread(DWORD threadId, DWORD desiredAccess)
{
    return OwnedHandle(OpenThread(desiredAccess, FALSE, threadId));
}

HANDLE ResolveDebugThread(const DebugThreadRegistry& threads,
                          DWORD threadId,
                          DWORD desiredAccess,
                          OwnedHandle& openedThread)
{
    HANDLE thread{threads.Get(threadId)};
    if (thread != nullptr && thread != INVALID_HANDLE_VALUE)
    {
        return thread;
    }

    openedThread = OpenDebugThread(threadId, desiredAccess);
    return openedThread.Get();
}

struct ExceptionSnapshot
{
    bool have{false};
    DWORD pid{0};
    DWORD threadId{0};
    DWORD code{0};
    bool firstChance{false};
    std::uint64_t address{0};
    std::vector<std::uint64_t> parameters;
    std::vector<std::string> stackLines;
};

bool IsDebuggerInternalException(DWORD code)
{
    return code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP;
}

std::string ExceptionCodeName(DWORD code)
{
    switch (code)
    {
    case EXCEPTION_ACCESS_VIOLATION:
        return "EXCEPTION_ACCESS_VIOLATION";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
    case EXCEPTION_DATATYPE_MISALIGNMENT:
        return "EXCEPTION_DATATYPE_MISALIGNMENT";
    case EXCEPTION_FLT_DENORMAL_OPERAND:
        return "EXCEPTION_FLT_DENORMAL_OPERAND";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
        return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
    case EXCEPTION_FLT_INEXACT_RESULT:
        return "EXCEPTION_FLT_INEXACT_RESULT";
    case EXCEPTION_FLT_INVALID_OPERATION:
        return "EXCEPTION_FLT_INVALID_OPERATION";
    case EXCEPTION_FLT_OVERFLOW:
        return "EXCEPTION_FLT_OVERFLOW";
    case EXCEPTION_FLT_STACK_CHECK:
        return "EXCEPTION_FLT_STACK_CHECK";
    case EXCEPTION_FLT_UNDERFLOW:
        return "EXCEPTION_FLT_UNDERFLOW";
    case EXCEPTION_ILLEGAL_INSTRUCTION:
        return "EXCEPTION_ILLEGAL_INSTRUCTION";
    case EXCEPTION_IN_PAGE_ERROR:
        return "EXCEPTION_IN_PAGE_ERROR";
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
        return "EXCEPTION_INT_DIVIDE_BY_ZERO";
    case EXCEPTION_INT_OVERFLOW:
        return "EXCEPTION_INT_OVERFLOW";
    case EXCEPTION_INVALID_DISPOSITION:
        return "EXCEPTION_INVALID_DISPOSITION";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION:
        return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
    case EXCEPTION_PRIV_INSTRUCTION:
        return "EXCEPTION_PRIV_INSTRUCTION";
    case EXCEPTION_STACK_OVERFLOW:
        return "EXCEPTION_STACK_OVERFLOW";
    default:
        return "exception";
    }
}

void RememberExceptionSnapshot(const DEBUG_EVENT& event,
                               HANDLE thread,
                               StackPrinter& stackPrinter,
                               ExceptionSnapshot& snapshot)
{
    const auto& exception{event.u.Exception};
    const DWORD code{exception.ExceptionRecord.ExceptionCode};
    if (IsDebuggerInternalException(code))
    {
        return;
    }

    snapshot = {};
    snapshot.have = true;
    snapshot.pid = event.dwProcessId;
    snapshot.threadId = event.dwThreadId;
    snapshot.code = code;
    snapshot.firstChance = exception.dwFirstChance != 0;
    snapshot.address = reinterpret_cast<std::uint64_t>(
        exception.ExceptionRecord.ExceptionAddress);

    const DWORD parameterCount{std::min<DWORD>(exception.ExceptionRecord.NumberParameters,
                        EXCEPTION_MAXIMUM_PARAMETERS)};
    snapshot.parameters.reserve(parameterCount);
    for (DWORD index{0}; index < parameterCount; ++index)
    {
        snapshot.parameters.push_back(static_cast<std::uint64_t>(
            exception.ExceptionRecord.ExceptionInformation[index]));
    }

    snapshot.stackLines = stackPrinter.CaptureStack(thread).lines;
}

void PrintLastExceptionSnapshot(const ExceptionSnapshot& snapshot)
{
    if (!snapshot.have)
    {
        std::cerr << "\nlast non-breakpoint exception before termination: none observed\n";
        return;
    }

    std::cerr << "\nlast non-breakpoint exception before termination:\n";
    std::cerr << "  " << ExceptionCodeName(snapshot.code) << " "
              << miri::Hex64(snapshot.code) << " at "
              << miri::Hex64(snapshot.address) << "\n";
    std::cerr << "  pid " << snapshot.pid << ", tid " << snapshot.threadId
              << ", " << (snapshot.firstChance ? "first" : "second") << " chance\n";

    if (snapshot.code == EXCEPTION_ACCESS_VIOLATION && snapshot.parameters.size() >= 2)
    {
        const std::uint64_t operation{snapshot.parameters[0]};
        const char* operationName{"access"};
        if (operation == 0)
        {
            operationName = "read";
        }
        else
        if (operation == 1)
        {
            operationName = "write";
        }
        else
        if (operation == 8)
        {
            operationName = "execute";
        }
        std::cerr << "  access violation attempted " << operationName << " at "
                  << miri::Hex64(snapshot.parameters[1]) << "\n";
    }

    if (!snapshot.parameters.empty())
    {
        std::cerr << "  parameters:";
        for (const std::uint64_t parameter : snapshot.parameters)
        {
            std::cerr << ' ' << miri::Hex64(parameter);
        }
        std::cerr << "\n";
    }

    for (const auto& line : snapshot.stackLines)
    {
        std::cerr << line << "\n";
    }
}

bool PrintSecondChanceExceptionStack(const DEBUG_EVENT& event,
                                     HANDLE thread,
                                     StackPrinter& stackPrinter)
{
    const auto& exception{event.u.Exception};
    const DWORD exceptionCode{exception.ExceptionRecord.ExceptionCode};
    if (exception.dwFirstChance != 0 || exceptionCode == EXCEPTION_BREAKPOINT ||
        exceptionCode == EXCEPTION_SINGLE_STEP) {
        return false;
    }

    std::string reason{"second-chance exception "};
    reason += miri::Hex64(exceptionCode);
    reason += " at ";
    reason += miri::Hex64(reinterpret_cast<std::uint64_t>(
        exception.ExceptionRecord.ExceptionAddress));
    return stackPrinter.PrintStack(reason, event.dwProcessId, event.dwThreadId, thread);
}

bool PrintExitEventStack(const DEBUG_EVENT& event,
                         const DebugThreadRegistry& threads,
                         StackPrinter& stackPrinter)
{
    OwnedHandle openedThread;
    HANDLE thread{ResolveDebugThread(threads, event.dwThreadId,
                                       THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                                       openedThread)};

    std::string reason{"process exit debug event, exit code "};
    reason += miri::Hex64(event.u.ExitProcess.dwExitCode);
    reason += " (subject-side stack may already be gone)";
    return stackPrinter.PrintStack(reason, event.dwProcessId, event.dwThreadId, thread);
}

bool WriteCsvReport(const std::filesystem::path& outputPath,
                    const miri::InstrumentationResult& instrumentation,
                    const std::vector<std::uint64_t>& counters,
                    bool includeMangled,
                    std::string& error)
{
    std::ofstream output(outputPath, std::ios::binary);
    if (!output)
    {
        error = "failed to open report for writing: " + miri::WideToUtf8(outputPath.wstring());
        return false;
    }

    output << "symbol,";
    if (includeMangled)
    {
        output << "mangled,";
    }
    output << "rva,remote_address,counter_index,count,status,stolen_bytes\n";
    for (const auto& record : instrumentation.records)
    {
        std::uint64_t count{0};
        if (record.patched && record.counterIndex < counters.size())
        {
            count = counters[record.counterIndex];
        }

        output << miri::CsvEscape(miri::WideToUtf8(record.function.name)) << ',';
        if (includeMangled)
        {
            output << miri::CsvEscape(miri::WideToUtf8(record.function.mangledName)) << ',';
        }
        output << miri::Hex64(record.function.rva) << ','
               << miri::Hex64(record.remoteAddress) << ',';
        if (record.patched)
        {
            output << record.counterIndex;
        }
        output << ',' << count << ','
               << miri::CsvEscape(record.status) << ','
               << record.stolenLength << '\n';
    }

    return true;
}

std::size_t CountPatchedSites(const miri::InstrumentationResult& instrumentation)
{
    std::set<std::uint32_t> indices;
    for (const auto& record : instrumentation.records)
    {
        if (record.patched)
        {
            indices.insert(record.counterIndex);
        }
    }
    return indices.size();
}

void CloseDebugFileHandle(const DEBUG_EVENT& event)
{
    if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT &&
        event.u.CreateProcessInfo.hFile != nullptr) {
        CloseHandle(event.u.CreateProcessInfo.hFile);
    }
    else
    if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT &&
               event.u.LoadDll.hFile != nullptr) {
        CloseHandle(event.u.LoadDll.hFile);
    }
}

DWORD ContinueStatusForException(const DEBUG_EVENT& event)
{
    const DWORD code{event.u.Exception.ExceptionRecord.ExceptionCode};
    if (code == EXCEPTION_BREAKPOINT)
    {
        return DBG_CONTINUE;
    }

    return DBG_EXCEPTION_NOT_HANDLED;
}

bool LaunchAndProfile(const std::filesystem::path& exePath,
                      const std::filesystem::path& pdbPath,
                      const RunConfig& config,
                      const PeImageInfo& image,
                      const std::vector<FunctionSymbol>& symbols,
                      const PatchOptions& patchOptions,
                      const std::filesystem::path& outputPath,
                      bool includeMangled)
{
    ProcessHandles child;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);

    std::wstring commandLine{miri::BuildCommandLine(exePath, config.arguments, config.rawArguments)};
    std::wstring applicationName{exePath.wstring()};
    std::wstring workingDirectory{config.workingDirectory.wstring()};

    const DWORD creationFlags{DEBUG_ONLY_THIS_PROCESS};
    if (!CreateProcessW(applicationName.c_str(), commandLine.data(), nullptr, nullptr, FALSE,
                        creationFlags, nullptr,
                        workingDirectory.empty() ? nullptr : workingDirectory.c_str(),
                        &startup, &child.info)) {
        std::cerr << "CreateProcessW failed: " << miri::LastWin32ErrorMessage() << "\n";
        return false;
    }

    DebugSetProcessKillOnExit(FALSE);

    StackPrinter stackPrinter;
    std::string stackError;
    if (!stackPrinter.Initialize(child.info.hProcess, exePath, pdbPath, stackError))
    {
        std::cerr << stackError << "\n";
    }

    DebugThreadRegistry debugThreads;
    TerminationBreakpointManager terminationBreakpoints;
    miri::InstrumentationResult instrumentation;
    bool instrumented{false};
    bool wroteReport{false};
    bool printedTerminationStack{false};
    bool printedLastException{false};
    ExceptionSnapshot lastException;
    DWORD exitCode{0};

    for (;;)
    {
        DEBUG_EVENT event{};
        if (!WaitForDebugEvent(&event, INFINITE))
        {
            std::cerr << "WaitForDebugEvent failed: " << miri::LastWin32ErrorMessage() << "\n";
            return false;
        }

        DWORD continueStatus{DBG_CONTINUE};
        if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && !instrumented)
        {
            debugThreads.Add(event.dwThreadId, event.u.CreateProcessInfo.hThread);
            CloseDebugFileHandle(event);
            const auto remoteImageBase{reinterpret_cast<std::uint64_t>(event.u.CreateProcessInfo.lpBaseOfImage)};

            std::string patchError;
            if (!miri::InstrumentProcess(child.info.hProcess, remoteImageBase, image, symbols,
                                         patchOptions, instrumentation, patchError))
            {
                std::cerr << "instrumentation failed: " << patchError << "\n";
                TerminateProcess(child.info.hProcess, 1);
                ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
                return false;
            }

            instrumented = true;
            std::cerr << "patched " << CountPatchedSites(instrumentation) << " of "
                      << instrumentation.counterCount << " planned function sites\n";

            terminationBreakpoints.InstallFromLoadedModules(child.info.hProcess,
                                                            event.dwProcessId);

            ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
            continue;
        }

        switch (event.dwDebugEventCode)
        {
        case CREATE_PROCESS_DEBUG_EVENT:
            debugThreads.Add(event.dwThreadId, event.u.CreateProcessInfo.hThread);
            terminationBreakpoints.InstallFromLoadedModules(child.info.hProcess,
                                                            event.dwProcessId);
            CloseDebugFileHandle(event);
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            debugThreads.Add(event.dwThreadId, event.u.CreateThread.hThread);
            break;
        case EXIT_THREAD_DEBUG_EVENT:
            debugThreads.Remove(event.dwThreadId);
            break;
        case LOAD_DLL_DEBUG_EVENT:
            terminationBreakpoints.InstallFromLoadedModules(child.info.hProcess,
                                                            event.dwProcessId);
            CloseDebugFileHandle(event);
            break;
        case EXCEPTION_DEBUG_EVENT:
        {
            OwnedHandle openedThread;
            HANDLE thread{ResolveDebugThread(debugThreads, event.dwThreadId,
                                               THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                                   THREAD_QUERY_INFORMATION,
                                               openedThread)};
            if (terminationBreakpoints.HandleException(event, child.info.hProcess, thread,
                                                       stackPrinter, printedTerminationStack,
                                                       continueStatus))
            {
                if (printedTerminationStack && !printedLastException)
                {
                    PrintLastExceptionSnapshot(lastException);
                    printedLastException = true;
                }
                break;
            }
            RememberExceptionSnapshot(event, thread, stackPrinter, lastException);
            if (PrintSecondChanceExceptionStack(event, thread, stackPrinter))
            {
                printedTerminationStack = true;
            }
            continueStatus = ContinueStatusForException(event);
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT:
        {
            exitCode = event.u.ExitProcess.dwExitCode;
            if (!printedTerminationStack)
            {
                printedTerminationStack =
                    PrintExitEventStack(event, debugThreads, stackPrinter);
            }
            if (!printedLastException)
            {
                PrintLastExceptionSnapshot(lastException);
                printedLastException = true;
            }

            std::vector<std::uint64_t> counters;
            std::string counterError;
            if (!miri::ReadCounters(child.info.hProcess, instrumentation, counters, counterError))
            {
                std::cerr << "counter collection failed: " << counterError << "\n";
            }

            std::string reportError;
            if (!WriteCsvReport(outputPath, instrumentation, counters, includeMangled,
                                reportError))
            {
                std::cerr << "report write failed: " << reportError << "\n";
            }
            else
            {
                wroteReport = true;
            }
            break;
        }
        default:
            break;
        }

        ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continueStatus);

        if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
        {
            break;
        }
    }

    std::cerr << "target exited with code " << exitCode << "\n";
    if (wroteReport)
    {
        std::cerr << "wrote report: " << miri::WideToUtf8(outputPath.wstring()) << "\n";
    }

    return wroteReport;
}

bool AttachAndProfile(DWORD pid,
                      const std::filesystem::path& exePath,
                      const std::filesystem::path& pdbPath,
                      const PeImageInfo& image,
                      const std::vector<FunctionSymbol>& symbols,
                      const PatchOptions& patchOptions,
                      const std::filesystem::path& outputPath,
                      bool includeMangled)
{
    const DWORD processAccess{PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION |
                                PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
                                SYNCHRONIZE};
    OwnedHandle process(OpenProcess(processAccess, FALSE, pid));
    if (!process.IsValid())
    {
        std::cerr << "OpenProcess failed for pid " << pid << ": "
                  << miri::LastWin32ErrorMessage() << "\n";
        return false;
    }

    if (!DebugActiveProcess(pid))
    {
        std::cerr << "DebugActiveProcess failed for pid " << pid << ": "
                  << miri::LastWin32ErrorMessage() << "\n";
        return false;
    }

    DebugSetProcessKillOnExit(FALSE);

    StackPrinter stackPrinter;
    std::string stackError;
    if (!stackPrinter.Initialize(process.Get(), exePath, pdbPath, stackError))
    {
        std::cerr << stackError << "\n";
    }

    DebugThreadRegistry debugThreads;
    TerminationBreakpointManager terminationBreakpoints;
    miri::InstrumentationResult instrumentation;
    bool instrumented{false};
    bool wroteReport{false};
    bool printedTerminationStack{false};
    bool printedLastException{false};
    ExceptionSnapshot lastException;
    DWORD exitCode{0};

    for (;;)
    {
        DEBUG_EVENT event{};
        if (!WaitForDebugEvent(&event, INFINITE))
        {
            std::cerr << "WaitForDebugEvent failed: " << miri::LastWin32ErrorMessage() << "\n";
            DebugActiveProcessStop(pid);
            return false;
        }

        DWORD continueStatus{DBG_CONTINUE};

        if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && !instrumented)
        {
            debugThreads.Add(event.dwThreadId, event.u.CreateProcessInfo.hThread);
            CloseDebugFileHandle(event);
            std::uint64_t remoteImageBase{reinterpret_cast<std::uint64_t>(event.u.CreateProcessInfo.lpBaseOfImage)};
            if (remoteImageBase == 0)
            {
                std::string moduleError;
                if (!FindMainModuleBase(pid, remoteImageBase, moduleError))
                {
                    std::cerr << moduleError << "\n";
                    ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
                    DebugActiveProcessStop(pid);
                    return false;
                }
            }

            std::cerr << "attached to pid " << pid << "\n";
            std::cerr << "scanning and patching planned function sites\n";

            std::string patchError;
            if (!miri::InstrumentProcess(process.Get(), remoteImageBase, image, symbols,
                                         patchOptions, instrumentation, patchError))
            {
                std::cerr << "instrumentation failed: " << patchError << "\n";
                ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
                DebugActiveProcessStop(pid);
                return false;
            }

            instrumented = true;
            std::cerr << "patched " << CountPatchedSites(instrumentation) << " of "
                      << instrumentation.counterCount << " planned function sites\n";
            std::cerr << "waiting for target exit to collect counters\n";

            terminationBreakpoints.InstallFromLoadedModules(process.Get(), event.dwProcessId);

            ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
            continue;
        }

        switch (event.dwDebugEventCode)
        {
        case CREATE_PROCESS_DEBUG_EVENT:
            debugThreads.Add(event.dwThreadId, event.u.CreateProcessInfo.hThread);
            terminationBreakpoints.InstallFromLoadedModules(process.Get(), event.dwProcessId);
            CloseDebugFileHandle(event);
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            debugThreads.Add(event.dwThreadId, event.u.CreateThread.hThread);
            break;
        case EXIT_THREAD_DEBUG_EVENT:
            debugThreads.Remove(event.dwThreadId);
            break;
        case LOAD_DLL_DEBUG_EVENT:
            terminationBreakpoints.InstallFromLoadedModules(process.Get(), event.dwProcessId);
            CloseDebugFileHandle(event);
            break;
        case EXCEPTION_DEBUG_EVENT:
        {
            OwnedHandle openedThread;
            HANDLE thread{ResolveDebugThread(debugThreads, event.dwThreadId,
                                               THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                                   THREAD_QUERY_INFORMATION,
                                               openedThread)};
            if (terminationBreakpoints.HandleException(event, process.Get(), thread,
                                                       stackPrinter, printedTerminationStack,
                                                       continueStatus))
            {
                if (printedTerminationStack && !printedLastException)
                {
                    PrintLastExceptionSnapshot(lastException);
                    printedLastException = true;
                }
                break;
            }
            RememberExceptionSnapshot(event, thread, stackPrinter, lastException);
            if (PrintSecondChanceExceptionStack(event, thread, stackPrinter))
            {
                printedTerminationStack = true;
            }
            continueStatus = ContinueStatusForException(event);
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT:
        {
            exitCode = event.u.ExitProcess.dwExitCode;
            if (!printedTerminationStack)
            {
                printedTerminationStack =
                    PrintExitEventStack(event, debugThreads, stackPrinter);
            }
            if (!printedLastException)
            {
                PrintLastExceptionSnapshot(lastException);
                printedLastException = true;
            }

            if (!instrumented)
            {
                std::cerr << "target exited before instrumentation completed\n";
                break;
            }

            std::vector<std::uint64_t> counters;
            std::string counterError;
            if (!miri::ReadCounters(process.Get(), instrumentation, counters, counterError))
            {
                std::cerr << "counter collection failed: " << counterError << "\n";
            }

            std::string reportError;
            if (!WriteCsvReport(outputPath, instrumentation, counters, includeMangled,
                                reportError))
            {
                std::cerr << "report write failed: " << reportError << "\n";
            }
            else
            {
                wroteReport = true;
            }
            break;
        }
        default:
            break;
        }

        ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continueStatus);

        if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
        {
            break;
        }
    }

    std::cerr << "target exited with code " << exitCode << "\n";
    if (wroteReport)
    {
        std::cerr << "wrote report: " << miri::WideToUtf8(outputPath.wstring()) << "\n";
    }

    return wroteReport;
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    CommandLineOptions options;
    if (!ParseCommandLine(argc, argv, options))
    {
        PrintUsage();
        return 2;
    }

    if (options.attach)
    {
        std::string processError;
        if (!QueryProcessImagePath(options.pid, options.exePath, processError))
        {
            std::cerr << processError << "\n";
            return 2;
        }
        if (options.pdbPath.empty())
        {
            options.pdbPath = DefaultPdbPath(options.exePath);
        }
    }

    const std::filesystem::path exePath{options.exePath};
    const std::filesystem::path pdbPath{options.pdbPath};

    if (!std::filesystem::exists(exePath))
    {
        std::wcerr << L"target executable does not exist: " << exePath.wstring() << L"\n";
        return 2;
    }
    if (!std::filesystem::exists(pdbPath))
    {
        std::wcerr << L"target PDB does not exist: " << pdbPath.wstring() << L"\n";
        return 2;
    }

    RunConfig config;
    config.outputPath = miri::DefaultReportPath(exePath);
    config.workingDirectory = exePath.parent_path();

    std::filesystem::path configPath;
    if (!options.configPath.empty())
    {
        configPath = options.configPath;
    }
    else
    {
        configPath = miri::FindDefaultConfigPath(exePath);
    }

    if (!configPath.empty())
    {
        RunConfig loaded{config};
        std::string configError;
        if (!miri::LoadRunConfig(configPath, loaded, configError))
        {
            std::cerr << configError << "\n";
            return 2;
        }

        const std::filesystem::path configBase{configPath.parent_path()};
        loaded.workingDirectory = ResolvePath(loaded.workingDirectory, configBase);
        loaded.outputPath = ResolvePath(loaded.outputPath, configBase);
        config = std::move(loaded);
    }

    if (config.outputPath.empty())
    {
        config.outputPath = miri::DefaultReportPath(exePath);
    }

    PeImageInfo image;
    std::string imageError;
    if (!miri::LoadPeImageInfo(exePath, image, imageError))
    {
        std::cerr << imageError << "\n";
        return 2;
    }

    if (!image.is64 || image.machine != IMAGE_FILE_MACHINE_AMD64)
    {
        std::cerr << "miri-run currently supports Windows x64 PE targets only\n";
        return 2;
    }

    SymbolFilters filters;
    filters.includePatterns = config.includePatterns;
    filters.excludePatterns = config.excludePatterns;

    std::vector<FunctionSymbol> symbols;
    miri::SymbolEnumerationReport symbolReport;
    std::string symbolError;
    if (!miri::EnumeratePdbFunctions(exePath, pdbPath, image, filters,
                                     options.includeMangled, symbols, symbolReport,
                                     symbolError))
    {
        std::cerr << symbolError << "\n";
        return 2;
    }

    if (symbols.empty())
    {
        std::cerr << "no function symbols were found in executable sections\n";
        return 2;
    }

    PatchOptions patchOptions;
    patchOptions.atomicCounters = config.atomicCounters;
    patchOptions.verbose = options.verbose;
    patchOptions.maxFunctions = config.maxFunctions;

    std::cerr << "found " << symbols.size() << " function symbols\n";
    if (options.verbose && options.includeMangled)
    {
        std::cerr << "mangled symbol lookup: dbghelp publics "
                  << symbolReport.dbghelpDecoratedPublicNames << "/"
                  << symbolReport.dbghelpPublicNames << " decorated, DIA "
                  << (symbolReport.diaCompiled ? "enabled" : "not built") << "/"
                  << (symbolReport.diaLoaded ? "loaded" : "not loaded") << ", "
                  << symbolReport.diaDecoratedPublicNames << "/"
                  << symbolReport.diaPublicNames << " decorated, matched "
                  << symbolReport.publicNameMatches << ", final decorated "
                  << symbolReport.finalDecoratedNames << "/" << symbols.size() << "\n";
    }
    if (options.attach)
    {
        return AttachAndProfile(options.pid, exePath, pdbPath, image, symbols, patchOptions,
                                config.outputPath, options.includeMangled) ? 0 : 1;
    }

    return LaunchAndProfile(exePath, pdbPath, config, image, symbols, patchOptions,
                            config.outputPath, options.includeMangled) ? 0 : 1;
}
