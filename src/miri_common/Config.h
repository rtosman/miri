// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Rennie Allen

#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace miri
{

struct RunConfig
{
    std::vector<std::wstring> arguments;
    std::wstring rawArguments;
    std::filesystem::path workingDirectory;
    std::filesystem::path outputPath;
    std::vector<std::wstring> includePatterns;
    std::vector<std::wstring> excludePatterns;
    bool atomicCounters{false};
    std::size_t maxFunctions{0};
};

std::filesystem::path FindDefaultConfigPath(const std::filesystem::path& exePath);
bool LoadRunConfig(const std::filesystem::path& configPath, RunConfig& config, std::string& error);
std::filesystem::path DefaultReportPath(const std::filesystem::path& exePath);

} // namespace miri
