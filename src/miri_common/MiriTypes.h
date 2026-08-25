// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Rennie Allen

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace miri
{

struct FunctionSymbol
{
    std::wstring name;
    std::wstring mangledName;
    std::uint32_t rva{0};
    std::uint32_t size{0};
    std::uint32_t flags{0};
    std::uint32_t tag{0};
};

struct PatchResult
{
    FunctionSymbol function;
    bool patched{false};
    std::uint32_t patchOffset{0};
    std::uint32_t stolenLength{0};
    std::uint64_t remoteAddress{0};
    std::uint64_t stubAddress{0};
    std::uint64_t counterAddress{0};
    std::uint32_t counterIndex{UINT32_MAX};
    std::string status;
};

struct CounterBlock
{
    std::uint64_t remoteAddress{0};
    std::size_t counterIndex{0};
    std::size_t counterCount{0};
};

struct InstrumentationResult
{
    std::vector<PatchResult> records;
    std::uint64_t stubBase{0};
    std::size_t stubBytes{0};
    std::uint64_t counterBase{0};
    std::size_t counterCount{0};
    std::size_t counterBytes{0};
    std::vector<CounterBlock> counterBlocks;
};

struct PatchOptions
{
    bool atomicCounters{false};
    bool verbose{false};
    std::size_t maxFunctions{0};
};

} // namespace miri
