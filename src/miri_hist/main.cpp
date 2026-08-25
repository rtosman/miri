// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Rennie Allen

#include "miri_common/StringUtil.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace
{

struct Options
{
    std::filesystem::path reportPath;
    std::filesystem::path htmlPath;
    std::size_t top{50};
    bool includeZero{false};
};

struct Row
{
    std::string symbol;
    std::string rva;
    std::uint64_t count{0};
    std::string status;
};

void PrintUsage()
{
    std::wcerr << L"usage: miri-hist <report.csv> [--top N] [--html out.html] [--include-zero]\n";
}

std::vector<std::string> ParseCsvLine(std::string_view line)
{
    std::vector<std::string> fields;
    std::string field;
    bool inQuotes{false};

    for (std::size_t i{0}; i < line.size(); ++i)
    {
        const char ch{line[i]};
        if (inQuotes)
        {
            if (ch == '"' && i + 1 < line.size() && line[i + 1] == '"')
            {
                field.push_back('"');
                ++i;
            } 
            else 
            if (ch == '"')
            {
                inQuotes = false;
            } 
            else
            {
                field.push_back(ch);
            }
            continue;
        }

        if (ch == '"')
        {
            inQuotes = true;
        } 
        else 
        if (ch == ',')
        {
            fields.push_back(std::move(field));
            field.clear();
        } 
        else
        {
            field.push_back(ch);
        }
    }

    fields.push_back(std::move(field));
    return fields;
}

bool ParseOptions(int argc, wchar_t** argv, Options& options)
{
    if (argc < 2)
{
        return false;
    }

    options.reportPath = std::filesystem::absolute(argv[1]);

    for (int i{2}; i < argc; ++i)
    {
        const std::wstring arg{argv[i]};
        if (arg == L"--include-zero")
        {
            options.includeZero = true;
        } 
        else 
        if (arg == L"--top" && i + 1 < argc)
        {
            try
            {
                options.top = static_cast<std::size_t>(std::stoull(argv[++i]));
            } 
            catch (...)
            {
                return false;
            }
        } 
        else 
        if (arg == L"--html" && i + 1 < argc)
        {
            options.htmlPath = std::filesystem::absolute(argv[++i]);
        } 
        else
        {
            return false;
        }
    }

    return true;
}

bool LoadRows(const std::filesystem::path& reportPath, std::vector<Row>& rows, std::string& error)
{
    std::ifstream input(reportPath, std::ios::binary);
    if (!input)
    {
        error = "failed to open report: " + miri::WideToUtf8(reportPath.wstring());
        return false;
    }

    std::string line;
    if (!std::getline(input, line))
    {
        error = "report is empty";
        return false;
    }

    const auto header{ParseCsvLine(line)};
    std::map<std::string, std::size_t> columns;
    for (std::size_t index{0}; index < header.size(); ++index)
    {
        columns[header[index]] = index;
    }

    const auto findColumn{[&columns](const std::string& name) -> std::size_t 
        {
            const auto it{columns.find(name)};
            return it == columns.end() ? SIZE_MAX : it->second;
        }};

    const std::size_t symbolColumn{findColumn("symbol")};
    const std::size_t rvaColumn{findColumn("rva")};
    const std::size_t countColumn{findColumn("count")};
    const std::size_t statusColumn{findColumn("status")};
    if (symbolColumn == SIZE_MAX || rvaColumn == SIZE_MAX || countColumn == SIZE_MAX ||
        statusColumn == SIZE_MAX) 
    {
        error = "report is missing one or more required columns";
        return false;
    }

    while (std::getline(input, line))
    {
        if (!line.empty() && line.back() == '\r')
        {
            line.pop_back();
        }

        const auto fields{ParseCsvLine(line)};
        if (fields.size() <= std::max(
            {symbolColumn, rvaColumn, countColumn, statusColumn})) 
        {
            continue;
        }

        Row row;
        row.symbol = fields[symbolColumn];
        row.rva = fields[rvaColumn];
        row.status = fields[statusColumn];
        try
        {
            row.count = std::stoull(fields[countColumn]);
        } 
        catch (...)
        {
            row.count = 0;
        }
        rows.push_back(std::move(row));
    }

    return true;
}

std::vector<Row> SelectRows(std::vector<Row> rows, const Options& options)
{
    rows.erase(std::remove_if(rows.begin(), rows.end(),
                              [&options](const Row& row) {
                                  if (row.status != "patched")
{
                                      return true;
                                  }
                                  return !options.includeZero && row.count == 0;
                              }),
               rows.end());

    std::sort(rows.begin(), rows.end(), [](const Row& left, const Row& right) {
        if (left.count != right.count)
{
            return left.count > right.count;
        }
        return left.symbol < right.symbol;
    });

    if (options.top != 0 && rows.size() > options.top)
{
        rows.resize(options.top);
    }

    return rows;
}

void PrintHistogram(const std::vector<Row>& rows)
{
    if (rows.empty())
{
        std::cout << "no matching patched rows with non-zero counts\n";
        return;
    }

    const std::uint64_t maxCount{rows.front().count};
    constexpr std::size_t barWidth{56};

    for (const auto& row : rows)
{
        const std::size_t width{maxCount == 0
                                      ? 0
                                      : static_cast<std::size_t>(
                                            (row.count * barWidth + maxCount - 1) / maxCount)};
        std::cout << std::setw(12) << row.count << " | ";
        for (std::size_t i{0}; i < width; ++i)
{
            std::cout << '#';
        }
        std::cout << " " << row.symbol << " (" << row.rva << ")\n";
    }
}

bool WriteHtml(const std::filesystem::path& htmlPath, const std::vector<Row>& rows,
               std::string& error)
{
    std::ofstream output(htmlPath, std::ios::binary);
    if (!output)
{
        error = "failed to open HTML output: " + miri::WideToUtf8(htmlPath.wstring());
        return false;
    }

    const std::uint64_t maxCount{rows.empty() ? 0 : rows.front().count};

    output << "<!doctype html>\n<html lang=\"en\">\n<head>\n"
           << "<meta charset=\"utf-8\">\n"
           << "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
           << "<title>miri histogram</title>\n"
           << "<style>\n"
           << "body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#202124;background:#fafafa;}\n"
           << "h1{font-size:22px;margin:0 0 18px;}\n"
           << ".row{display:grid;grid-template-columns:120px minmax(120px,1fr) minmax(220px,2fr);gap:12px;align-items:center;margin:7px 0;}\n"
           << ".count{text-align:right;font-variant-numeric:tabular-nums;color:#4b5563;}\n"
           << ".bar{height:18px;background:#d9e6d2;border-radius:3px;position:relative;overflow:hidden;}\n"
           << ".fill{height:100%;background:#31745b;}\n"
           << ".symbol{font-family:Consolas,monospace;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}\n"
           << "</style>\n</head>\n<body>\n<h1>miri function call histogram</h1>\n";

    for (const auto& row : rows)
{
        const double percent{maxCount == 0 ? 0.0 : (100.0 * static_cast<double>(row.count)) /
                                                   static_cast<double>(maxCount)};
        output << "<div class=\"row\"><div class=\"count\">" << row.count
               << "</div><div class=\"bar\"><div class=\"fill\" style=\"width:"
               << std::fixed << std::setprecision(2) << percent
               << "%\"></div></div><div class=\"symbol\" title=\""
               << miri::HtmlEscape(row.symbol) << "\">"
               << miri::HtmlEscape(row.symbol) << " <span style=\"color:#6b7280\">"
               << miri::HtmlEscape(row.rva) << "</span></div></div>\n";
    }

    output << "</body>\n</html>\n";
    return true;
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    Options options;
    if (!ParseOptions(argc, argv, options))
{
        PrintUsage();
        return 2;
    }

    std::vector<Row> rows;
    std::string error;
    if (!LoadRows(options.reportPath, rows, error))
{
        std::cerr << error << "\n";
        return 2;
    }

    const std::vector<Row> selected{SelectRows(std::move(rows), options)};
    PrintHistogram(selected);

    if (!options.htmlPath.empty())
{
        std::string htmlError;
        if (!WriteHtml(options.htmlPath, selected, htmlError))
{
            std::cerr << htmlError << "\n";
            return 1;
        }
        std::cerr << "wrote HTML histogram: " << miri::WideToUtf8(options.htmlPath.wstring()) << "\n";
    }

    return 0;
}
