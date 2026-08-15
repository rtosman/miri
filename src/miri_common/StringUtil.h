#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include <windows.h>

namespace miri
{

std::wstring Utf8ToWide(std::string_view value);
std::string WideToUtf8(std::wstring_view value);
std::string Win32ErrorMessage(DWORD error);
std::string LastWin32ErrorMessage();

std::wstring QuoteCommandLineArgument(std::wstring_view argument);
std::wstring BuildCommandLine(const std::filesystem::path& exePath,
                              const std::vector<std::wstring>& arguments,
                              std::wstring_view rawArguments);

std::string Hex64(std::uint64_t value);
std::string CsvEscape(std::string_view value);
std::string HtmlEscape(std::string_view value);

} // namespace miri
