#include "miri_common/Config.h"
#include "miri_common/MiriTypes.h"
#include "miri_common/PeImage.h"
#include "miri_common/RemotePatch.h"
#include "miri_common/StringUtil.h"
#include "miri_common/Symbols.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#include <windows.h>

namespace {

using miri::FunctionSymbol;
using miri::PeImageInfo;
using miri::PatchOptions;
using miri::RunConfig;
using miri::SymbolFilters;

struct ProcessHandles {
    PROCESS_INFORMATION info = {};

    ~ProcessHandles()
    {
        if (info.hThread != nullptr) {
            CloseHandle(info.hThread);
        }
        if (info.hProcess != nullptr) {
            CloseHandle(info.hProcess);
        }
    }
};

void PrintUsage()
{
    std::wcerr << L"usage: miri-run <target.exe> <target.pdb> [config.json]\n";
}

std::filesystem::path AbsolutePath(const std::filesystem::path& path)
{
    std::error_code ignored;
    return std::filesystem::absolute(path, ignored);
}

std::filesystem::path ResolvePath(const std::filesystem::path& path,
                                  const std::filesystem::path& base)
{
    if (path.empty() || path.is_absolute()) {
        return path;
    }
    return AbsolutePath(base / path);
}

bool WriteCsvReport(const std::filesystem::path& outputPath,
                    const miri::InstrumentationResult& instrumentation,
                    const std::vector<std::uint64_t>& counters,
                    std::string& error)
{
    std::ofstream output(outputPath, std::ios::binary);
    if (!output) {
        error = "failed to open report for writing: " + miri::WideToUtf8(outputPath.wstring());
        return false;
    }

    output << "symbol,rva,remote_address,counter_index,count,status,stolen_bytes\n";
    for (const auto& record : instrumentation.records) {
        std::uint64_t count = 0;
        if (record.patched && record.counterIndex < counters.size()) {
            count = counters[record.counterIndex];
        }

        output << miri::CsvEscape(miri::WideToUtf8(record.function.name)) << ','
               << miri::Hex64(record.function.rva) << ','
               << miri::Hex64(record.remoteAddress) << ',';
        if (record.patched) {
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
    for (const auto& record : instrumentation.records) {
        if (record.patched) {
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
    if (code == EXCEPTION_BREAKPOINT) {
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

    const DWORD creationFlags = CREATE_SUSPENDED | DEBUG_ONLY_THIS_PROCESS;
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
    bool resumedPrimaryThread = false;
    bool wroteReport = false;
    DWORD exitCode = 0;

    for (;;) {
        DEBUG_EVENT event = {};
        if (!WaitForDebugEvent(&event, INFINITE)) {
            std::cerr << "WaitForDebugEvent failed: " << miri::LastWin32ErrorMessage() << "\n";
            return false;
        }

        DWORD continueStatus = DBG_CONTINUE;

        if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && !instrumented) {
            CloseDebugFileHandle(event);
            const auto remoteImageBase =
                reinterpret_cast<std::uint64_t>(event.u.CreateProcessInfo.lpBaseOfImage);

            std::string patchError;
            if (!miri::InstrumentProcess(child.info.hProcess, remoteImageBase, image, symbols,
                                         patchOptions, instrumentation, patchError)) {
                std::cerr << "instrumentation failed: " << patchError << "\n";
                TerminateProcess(child.info.hProcess, 1);
                ResumeThread(child.info.hThread);
                ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
                return false;
            }

            instrumented = true;
            if (!resumedPrimaryThread) {
                ResumeThread(child.info.hThread);
                resumedPrimaryThread = true;
            }

            std::cerr << "patched " << CountPatchedSites(instrumentation) << " of "
                      << instrumentation.counterCount << " planned function sites\n";

            ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
            continue;
        }

        switch (event.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
        case LOAD_DLL_DEBUG_EVENT:
            CloseDebugFileHandle(event);
            break;
        case EXCEPTION_DEBUG_EVENT:
            continueStatus = ContinueStatusForException(event);
            break;
        case EXIT_PROCESS_DEBUG_EVENT: {
            exitCode = event.u.ExitProcess.dwExitCode;
            std::vector<std::uint64_t> counters;
            std::string counterError;
            if (!miri::ReadCounters(child.info.hProcess, instrumentation, counters, counterError)) {
                std::cerr << "counter collection failed: " << counterError << "\n";
            }

            std::string reportError;
            if (!WriteCsvReport(outputPath, instrumentation, counters, reportError)) {
                std::cerr << "report write failed: " << reportError << "\n";
            } else {
                wroteReport = true;
            }
            break;
        }
        default:
            break;
        }

        ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continueStatus);

        if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            break;
        }
    }

    std::cerr << "target exited with code " << exitCode << "\n";
    if (wroteReport) {
        std::cerr << "wrote report: " << miri::WideToUtf8(outputPath.wstring()) << "\n";
    }

    return wroteReport;
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    if (argc < 3 || argc > 4) {
        PrintUsage();
        return 2;
    }

    const std::filesystem::path exePath = AbsolutePath(argv[1]);
    const std::filesystem::path pdbPath = AbsolutePath(argv[2]);

    if (!std::filesystem::exists(exePath)) {
        std::wcerr << L"target executable does not exist: " << exePath.wstring() << L"\n";
        return 2;
    }
    if (!std::filesystem::exists(pdbPath)) {
        std::wcerr << L"target PDB does not exist: " << pdbPath.wstring() << L"\n";
        return 2;
    }

    RunConfig config;
    config.outputPath = miri::DefaultReportPath(exePath);
    config.workingDirectory = exePath.parent_path();

    std::filesystem::path configPath;
    if (argc == 4) {
        configPath = AbsolutePath(argv[3]);
    } else {
        configPath = miri::FindDefaultConfigPath(exePath);
    }

    if (!configPath.empty()) {
        RunConfig loaded = config;
        std::string configError;
        if (!miri::LoadRunConfig(configPath, loaded, configError)) {
            std::cerr << configError << "\n";
            return 2;
        }

        const std::filesystem::path configBase = configPath.parent_path();
        loaded.workingDirectory = ResolvePath(loaded.workingDirectory, configBase);
        loaded.outputPath = ResolvePath(loaded.outputPath, configBase);
        config = std::move(loaded);
    }

    if (config.outputPath.empty()) {
        config.outputPath = miri::DefaultReportPath(exePath);
    }

    PeImageInfo image;
    std::string imageError;
    if (!miri::LoadPeImageInfo(exePath, image, imageError)) {
        std::cerr << imageError << "\n";
        return 2;
    }

    if (!image.is64 || image.machine != IMAGE_FILE_MACHINE_AMD64) {
        std::cerr << "miri-run currently supports Windows x64 PE targets only\n";
        return 2;
    }

    SymbolFilters filters;
    filters.includePatterns = config.includePatterns;
    filters.excludePatterns = config.excludePatterns;

    std::vector<FunctionSymbol> symbols;
    std::string symbolError;
    if (!miri::EnumeratePdbFunctions(exePath, pdbPath, image, filters, symbols, symbolError)) {
        std::cerr << symbolError << "\n";
        return 2;
    }

    if (symbols.empty()) {
        std::cerr << "no function symbols were found in executable sections\n";
        return 2;
    }

    PatchOptions patchOptions;
    patchOptions.atomicCounters = config.atomicCounters;
    patchOptions.maxFunctions = config.maxFunctions;

    std::cerr << "found " << symbols.size() << " function symbols\n";
    return LaunchAndProfile(exePath, config, image, symbols, patchOptions, config.outputPath) ? 0 : 1;
}
