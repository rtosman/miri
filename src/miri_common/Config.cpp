#include "miri_common/Config.h"

#include "miri_common/StringUtil.h"

#include <fstream>
#include <optional>
#include <regex>
#include <sstream>

namespace miri {
namespace {

std::string ReadTextFile(const std::filesystem::path& path, std::string& error)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        error = "failed to open config file: " + WideToUtf8(path.wstring());
        return {};
    }

    std::ostringstream buffer;
    buffer << file.rdbuf();
    std::string text = buffer.str();
    if (text.size() >= 3 && static_cast<unsigned char>(text[0]) == 0xEF &&
        static_cast<unsigned char>(text[1]) == 0xBB &&
        static_cast<unsigned char>(text[2]) == 0xBF) {
        text.erase(0, 3);
    }
    return text;
}

std::string EscapeRegexKey(std::string_view key)
{
    std::string escaped;
    for (const char ch : key) {
        if (std::string_view(R"(\.^$|()[]{}*+?)").find(ch) != std::string_view::npos) {
            escaped.push_back('\\');
        }
        escaped.push_back(ch);
    }
    return escaped;
}

std::string UnescapeJsonString(std::string_view input)
{
    std::string output;
    output.reserve(input.size());

    for (std::size_t i = 0; i < input.size(); ++i) {
        const char ch = input[i];
        if (ch != '\\' || i + 1 >= input.size()) {
            output.push_back(ch);
            continue;
        }

        const char escaped = input[++i];
        switch (escaped) {
        case '"':
        case '\\':
        case '/':
            output.push_back(escaped);
            break;
        case 'b':
            output.push_back('\b');
            break;
        case 'f':
            output.push_back('\f');
            break;
        case 'n':
            output.push_back('\n');
            break;
        case 'r':
            output.push_back('\r');
            break;
        case 't':
            output.push_back('\t');
            break;
        default:
            output.push_back(escaped);
            break;
        }
    }

    return output;
}

std::optional<std::string> ExtractString(const std::string& text, std::string_view key)
{
    const std::regex pattern("\"" + EscapeRegexKey(key) + R"json("\s*:\s*"((?:\\.|[^"\\])*)")json",
                             std::regex::ECMAScript);
    std::smatch match;
    if (!std::regex_search(text, match, pattern)) {
        return std::nullopt;
    }
    return UnescapeJsonString(match[1].str());
}

std::optional<bool> ExtractBool(const std::string& text, std::string_view key)
{
    const std::regex pattern("\"" + EscapeRegexKey(key) + R"("\s*:\s*(true|false))",
                             std::regex::ECMAScript | std::regex::icase);
    std::smatch match;
    if (!std::regex_search(text, match, pattern)) {
        return std::nullopt;
    }
    return match[1].str() == "true" || match[1].str() == "TRUE" || match[1].str() == "True";
}

std::optional<std::size_t> ExtractSize(const std::string& text, std::string_view key)
{
    const std::regex pattern("\"" + EscapeRegexKey(key) + R"("\s*:\s*([0-9]+))",
                             std::regex::ECMAScript);
    std::smatch match;
    if (!std::regex_search(text, match, pattern)) {
        return std::nullopt;
    }

    try {
        return static_cast<std::size_t>(std::stoull(match[1].str()));
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::pair<std::size_t, std::size_t>> FindArrayBounds(const std::string& text,
                                                                   std::string_view key)
{
    const std::regex pattern("\"" + EscapeRegexKey(key) + R"("\s*:\s*\[)",
                             std::regex::ECMAScript);
    std::smatch match;
    if (!std::regex_search(text, match, pattern)) {
        return std::nullopt;
    }

    std::size_t pos = static_cast<std::size_t>(match.position(0) + match.length(0));
    const std::size_t begin = pos;
    bool inString = false;
    bool escaped = false;
    int depth = 1;

    for (; pos < text.size(); ++pos) {
        const char ch = text[pos];
        if (inString) {
            if (escaped) {
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                inString = false;
            }
            continue;
        }

        if (ch == '"') {
            inString = true;
        } else if (ch == '[') {
            ++depth;
        } else if (ch == ']') {
            --depth;
            if (depth == 0) {
                return std::make_pair(begin, pos);
            }
        }
    }

    return std::nullopt;
}

std::vector<std::string> ExtractStringArray(const std::string& text, std::string_view key)
{
    std::vector<std::string> values;
    const auto bounds = FindArrayBounds(text, key);
    if (!bounds) {
        return values;
    }

    const std::string body = text.substr(bounds->first, bounds->second - bounds->first);
    const std::regex stringPattern(R"json("((?:\\.|[^"\\])*)")json", std::regex::ECMAScript);
    for (auto it = std::sregex_iterator(body.begin(), body.end(), stringPattern);
         it != std::sregex_iterator(); ++it) {
        values.push_back(UnescapeJsonString((*it)[1].str()));
    }

    return values;
}

std::vector<std::wstring> WidenAll(const std::vector<std::string>& values)
{
    std::vector<std::wstring> wide;
    wide.reserve(values.size());
    for (const auto& value : values) {
        wide.push_back(Utf8ToWide(value));
    }
    return wide;
}

} // namespace

std::filesystem::path DefaultReportPath(const std::filesystem::path& exePath)
{
    return exePath.wstring() + L".miri.csv";
}

std::filesystem::path FindDefaultConfigPath(const std::filesystem::path& exePath)
{
    const std::filesystem::path first = exePath.wstring() + L".miri.json";
    if (std::filesystem::exists(first)) {
        return first;
    }

    std::filesystem::path second = exePath;
    second.replace_extension(L".miri.json");
    if (std::filesystem::exists(second)) {
        return second;
    }

    return {};
}

bool LoadRunConfig(const std::filesystem::path& configPath, RunConfig& config, std::string& error)
{
    const std::string text = ReadTextFile(configPath, error);
    if (!error.empty()) {
        return false;
    }

    const auto argumentArray = ExtractStringArray(text, "arguments");
    if (!argumentArray.empty()) {
        config.arguments = WidenAll(argumentArray);
    } else if (const auto arguments = ExtractString(text, "arguments")) {
        config.rawArguments = Utf8ToWide(*arguments);
    }

    if (const auto rawArguments = ExtractString(text, "argumentsRaw")) {
        config.rawArguments = Utf8ToWide(*rawArguments);
    }

    if (const auto workingDirectory = ExtractString(text, "workingDirectory")) {
        config.workingDirectory = Utf8ToWide(*workingDirectory);
    }

    if (const auto outputPath = ExtractString(text, "outputPath")) {
        config.outputPath = Utf8ToWide(*outputPath);
    }

    config.includePatterns = WidenAll(ExtractStringArray(text, "include"));
    config.excludePatterns = WidenAll(ExtractStringArray(text, "exclude"));

    if (const auto atomicCounters = ExtractBool(text, "atomicCounters")) {
        config.atomicCounters = *atomicCounters;
    }

    if (const auto maxFunctions = ExtractSize(text, "maxFunctions")) {
        config.maxFunctions = *maxFunctions;
    }

    return true;
}

} // namespace miri
