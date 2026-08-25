// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Rennie Allen

#include "miri_common/StringUtil.h"

#include <iomanip>
#include <sstream>

namespace miri
{

std::wstring Utf8ToWide(std::string_view value)
{
    if (value.empty())
    {
        return {};
    }

    const int required{MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                                             static_cast<int>(value.size()), nullptr, 0)};
    if (required <= 0)
    {
        return {};
    }

    std::wstring output(static_cast<std::size_t>(required), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
                        output.data(), required);
    return output;
}

std::string WideToUtf8(std::wstring_view value)
{
    if (value.empty())
    {
        return {};
    }

    const int required{WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                                             nullptr, 0, nullptr, nullptr)};
    if (required <= 0)
    {
        return {};
    }

    std::string output(static_cast<std::size_t>(required), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), output.data(),
                        required, nullptr, nullptr);
    return output;
}

std::string Win32ErrorMessage(DWORD error)
{
    LPWSTR buffer{nullptr};
    const DWORD flags{FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS};
    const DWORD length{FormatMessageW(flags, nullptr, error, 0, reinterpret_cast<LPWSTR>(&buffer),
                                        0, nullptr)};

    std::wstring wide;
    if (length > 0 && buffer != nullptr)
    {
        wide.assign(buffer, length);
        while (!wide.empty() && (wide.back() == L'\r' || wide.back() == L'\n'))
{
            wide.pop_back();
        }
    }

    if (buffer != nullptr)
    {
        LocalFree(buffer);
    }

    if (wide.empty())
    {
        std::ostringstream stream;
        stream << "Win32 error " << error;
        return stream.str();
    }

    return WideToUtf8(wide);
}

std::string LastWin32ErrorMessage()
{
    return Win32ErrorMessage(GetLastError());
}

std::wstring QuoteCommandLineArgument(std::wstring_view argument)
{
    if (argument.empty())
    {
        return L"\"\"";
    }

    bool needsQuotes{false};
    for (const wchar_t ch : argument)
    {
        if (ch == L' ' || ch == L'\t' || ch == L'\n' || ch == L'\v' || ch == L'"')
        {
            needsQuotes = true;
            break;
        }
    }

    if (!needsQuotes)
    {
        return std::wstring(argument);
    }

    std::wstring result;
    result.push_back(L'"');
    std::size_t backslashes{0};

    for (const wchar_t ch : argument)
    {
        if (ch == L'\\')
        {
            ++backslashes;
            continue;
        }

        if (ch == L'"')
        {
            result.append(backslashes * 2 + 1, L'\\');
            result.push_back(ch);
            backslashes = 0;
            continue;
        }

        if (backslashes != 0)
        {
            result.append(backslashes, L'\\');
            backslashes = 0;
        }
        result.push_back(ch);
    }

    if (backslashes != 0)
    {
        result.append(backslashes * 2, L'\\');
    }

    result.push_back(L'"');
    return result;
}

std::wstring BuildCommandLine(const std::filesystem::path& exePath,
                              const std::vector<std::wstring>& arguments,
                              std::wstring_view rawArguments)
{
    std::wstring commandLine{QuoteCommandLineArgument(exePath.wstring())};
    for (const auto& argument : arguments)
    {
        commandLine.push_back(L' ');
        commandLine += QuoteCommandLineArgument(argument);
    }

    if (!rawArguments.empty())
    {
        commandLine.push_back(L' ');
        commandLine.append(rawArguments);
    }

    return commandLine;
}

std::string Hex64(std::uint64_t value)
{
    std::ostringstream stream;
    stream << "0x" << std::hex << std::uppercase << value;
    return stream.str();
}

std::string CsvEscape(std::string_view value)
{
    bool quote{false};
    for (const char ch : value)
    {
        if (ch == '"' || ch == ',' || ch == '\n' || ch == '\r')
        {
            quote = true;
            break;
        }
    }

    if (!quote)
    {
        return std::string(value);
    }

    std::string output;
    output.push_back('"');
    for (const char ch : value)
    {
        if (ch == '"')
        {
            output.push_back('"');
        }
        output.push_back(ch);
    }
    output.push_back('"');
    return output;
}

std::string HtmlEscape(std::string_view value)
{
    std::string output;
    output.reserve(value.size());
    for (const char ch : value)
    {
        switch (ch)
        {
        case '&':
            output += "&amp;";
            break;
        case '<':
            output += "&lt;";
            break;
        case '>':
            output += "&gt;";
            break;
        case '"':
            output += "&quot;";
            break;
        case '\'':
            output += "&#39;";
            break;
        default:
            output.push_back(ch);
            break;
        }
    }
    return output;
}

} // namespace miri
