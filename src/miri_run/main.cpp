#include "miri_common/Config.h"
#include "miri_common/MiriTypes.h"
#include "miri_common/PeImage.h"
#include "miri_common/RemotePatch.h"
#include "miri_common/StringUtil.h"
#include "miri_common/Symbols.h"

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <tlhelp32.h>
#include <windows.h>

namespace
{

using miri::FunctionSymbol;
using miri::PeImageInfo;
using miri::PatchOptions;
using miri::RunConfig;
using miri::SymbolFilters;

struct ProcessHandles
{
    PROCESS_INFORMATION info = {};

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
    HANDLE handle = nullptr;

    OwnedHandle() = default;
    explicit OwnedHandle(HANDLE value) : handle(value) {}
    OwnedHandle(const OwnedHandle&) = delete;
    OwnedHandle& operator=(const OwnedHandle&) = delete;

    ~OwnedHandle()
    {
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE)
{
            CloseHandle(handle);
        }
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
    bool attach = false;
    bool verbose = false;
    DWORD pid = 0;
    std::filesystem::path exePath;
    std::filesystem::path pdbPath;
    std::filesystem::path configPath;
};

void PrintUsage()
{
    std::wcerr << L"usage:\n"
               << L"  miri-run [-v|--verbose] <target.exe> <target.pdb> [config.json]\n"
               << L"  miri-run [-v|--verbose] --pid <pid> [target.pdb] [config.json]\n"
               << L"  miri-run [-v|--verbose] --attach <pid> [target.pdb] [config.json]\n";
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

std::filesystem::path DefaultPdbPath(const std::filesystem::path& exePath)
{
    std::filesystem::path pdbPath = exePath;
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
    wchar_t* end = nullptr;
    errno = 0;
    const unsigned long long value = std::wcstoull(owned.c_str(), &end, 10);
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
    for (int index = 1; index < argc; ++index)
    {
        if (IsVerboseSwitch(argv[index]))
        {
            options.verbose = true;
            continue;
        }
        arguments.push_back(argv[index]);
    }

    const int filteredArgc = static_cast<int>(arguments.size());
    wchar_t** filteredArgv = arguments.data();

    if (filteredArgc >= 2)
{
        const std::wstring_view command = filteredArgv[1];
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
                const std::filesystem::path first = AbsolutePath(filteredArgv[3]);
                if (filteredArgc == 4 && IsJsonPath(first))
{
                    options.configPath = first;
                } else
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
    DWORD length = static_cast<DWORD>(buffer.size());
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

    MODULEENTRY32W module = {};
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

bool WriteCsvReport(const std::filesystem::path& outputPath,
                    const miri::InstrumentationResult& instrumentation,
                    const std::vector<std::uint64_t>& counters,
                    std::string& error)
{
    std::ofstream output(outputPath, std::ios::binary);
    if (!output)
{
        error = "failed to open report for writing: " + miri::WideToUtf8(outputPath.wstring());
        return false;
    }

    output << "symbol,rva,remote_address,counter_index,count,status,stolen_bytes\n";
    for (const auto& record : instrumentation.records)
{
        std::uint64_t count = 0;
        if (record.patched && record.counterIndex < counters.size())
{
            count = counters[record.counterIndex];
        }

        output << miri::CsvEscape(miri::WideToUtf8(record.function.name)) << ','
               << miri::Hex64(record.function.rva) << ','
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
    } else if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT &&
               event.u.LoadDll.hFile != nullptr) {
        CloseHandle(event.u.LoadDll.hFile);
    }
}

DWORD ContinueStatusForException(const DEBUG_EVENT& event)
{
    const DWORD code = event.u.Exception.ExceptionRecord.ExceptionCode;
    if (code == EXCEPTION_BREAKPOINT)
{
        return DBG_CONTINUE;
    }
    return DBG_EXCEPTION_NOT_HANDLED;
}

bool LaunchAndProfile(const std::filesystem::path& exePath,
                      const RunConfig& config,
                      const PeImageInfo& image,
                      const std::vector<FunctionSymbol>& symbols,
                      const PatchOptions& patchOptions,
                      const std::filesystem::path& outputPath)
{
    ProcessHandles child;
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);

    std::wstring commandLine =
        miri::BuildCommandLine(exePath, config.arguments, config.rawArguments);
    std::wstring applicationName = exePath.wstring();
    std::wstring workingDirectory = config.workingDirectory.wstring();

    const DWORD creationFlags = DEBUG_ONLY_THIS_PROCESS;
    if (!CreateProcessW(applicationName.c_str(), commandLine.data(), nullptr, nullptr, FALSE,
                        creationFlags, nullptr,
                        workingDirectory.empty() ? nullptr : workingDirectory.c_str(),
                        &startup, &child.info)) {
        std::cerr << "CreateProcessW failed: " << miri::LastWin32ErrorMessage() << "\n";
        return false;
    }

    DebugSetProcessKillOnExit(FALSE);

    miri::InstrumentationResult instrumentation;
    bool instrumented = false;
    bool wroteReport = false;
    DWORD exitCode = 0;

    for (;;)
{
        DEBUG_EVENT event = {};
        if (!WaitForDebugEvent(&event, INFINITE))
{
            std::cerr << "WaitForDebugEvent failed: " << miri::LastWin32ErrorMessage() << "\n";
            return false;
        }

        DWORD continueStatus = DBG_CONTINUE;

        if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && !instrumented)
{
            CloseDebugFileHandle(event);
            const auto remoteImageBase =
                reinterpret_cast<std::uint64_t>(event.u.CreateProcessInfo.lpBaseOfImage);

            std::string patchError;
            if (!miri::InstrumentProcess(child.info.hProcess, remoteImageBase, image, symbols,
                                         patchOptions, instrumentation, patchError)) {
                std::cerr << "instrumentation failed: " << patchError << "\n";
                TerminateProcess(child.info.hProcess, 1);
                ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
                return false;
            }

            instrumented = true;
            std::cerr << "patched " << CountPatchedSites(instrumentation) << " of "
                      << instrumentation.counterCount << " planned function sites\n";

            ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
            continue;
        }

        switch (event.dwDebugEventCode)
{
        case CREATE_PROCESS_DEBUG_EVENT:
        case LOAD_DLL_DEBUG_EVENT:
            CloseDebugFileHandle(event);
            break;
        case EXCEPTION_DEBUG_EVENT:
            continueStatus = ContinueStatusForException(event);
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
{
            exitCode = event.u.ExitProcess.dwExitCode;
            std::vector<std::uint64_t> counters;
            std::string counterError;
            if (!miri::ReadCounters(child.info.hProcess, instrumentation, counters, counterError))
{
                std::cerr << "counter collection failed: " << counterError << "\n";
            }

            std::string reportError;
            if (!WriteCsvReport(outputPath, instrumentation, counters, reportError))
{
                std::cerr << "report write failed: " << reportError << "\n";
            } else
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
                      const PeImageInfo& image,
                      const std::vector<FunctionSymbol>& symbols,
                      const PatchOptions& patchOptions,
                      const std::filesystem::path& outputPath)
{
    const DWORD processAccess = PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION |
                                PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
                                SYNCHRONIZE;
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

    miri::InstrumentationResult instrumentation;
    bool instrumented = false;
    bool wroteReport = false;
    DWORD exitCode = 0;

    for (;;)
{
        DEBUG_EVENT event = {};
        if (!WaitForDebugEvent(&event, INFINITE))
{
            std::cerr << "WaitForDebugEvent failed: " << miri::LastWin32ErrorMessage() << "\n";
            DebugActiveProcessStop(pid);
            return false;
        }

        DWORD continueStatus = DBG_CONTINUE;

        if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && !instrumented)
{
            CloseDebugFileHandle(event);
            std::uint64_t remoteImageBase =
                reinterpret_cast<std::uint64_t>(event.u.CreateProcessInfo.lpBaseOfImage);
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
                                         patchOptions, instrumentation, patchError)) {
                std::cerr << "instrumentation failed: " << patchError << "\n";
                ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
                DebugActiveProcessStop(pid);
                return false;
            }

            instrumented = true;
            std::cerr << "patched " << CountPatchedSites(instrumentation) << " of "
                      << instrumentation.counterCount << " planned function sites\n";
            std::cerr << "waiting for target exit to collect counters\n";

            ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
            continue;
        }

        switch (event.dwDebugEventCode)
{
        case CREATE_PROCESS_DEBUG_EVENT:
        case LOAD_DLL_DEBUG_EVENT:
            CloseDebugFileHandle(event);
            break;
        case EXCEPTION_DEBUG_EVENT:
            continueStatus = ContinueStatusForException(event);
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
{
            exitCode = event.u.ExitProcess.dwExitCode;
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
            if (!WriteCsvReport(outputPath, instrumentation, counters, reportError))
{
                std::cerr << "report write failed: " << reportError << "\n";
            } else
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

    const std::filesystem::path exePath = options.exePath;
    const std::filesystem::path pdbPath = options.pdbPath;

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
    } else
{
        configPath = miri::FindDefaultConfigPath(exePath);
    }

    if (!configPath.empty())
{
        RunConfig loaded = config;
        std::string configError;
        if (!miri::LoadRunConfig(configPath, loaded, configError))
{
            std::cerr << configError << "\n";
            return 2;
        }

        const std::filesystem::path configBase = configPath.parent_path();
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
    std::string symbolError;
    if (!miri::EnumeratePdbFunctions(exePath, pdbPath, image, filters, symbols, symbolError))
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
    if (options.attach)
{
        return AttachAndProfile(options.pid, image, symbols, patchOptions, config.outputPath) ? 0 : 1;
    }

    return LaunchAndProfile(exePath, config, image, symbols, patchOptions, config.outputPath) ? 0 : 1;
}
