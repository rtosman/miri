// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Rennie Allen

#pragma once

#include "miri_common/MiriTypes.h"
#include "miri_common/PeImage.h"

#include <string>
#include <vector>

#include <windows.h>

namespace miri
{

bool InstrumentProcess(HANDLE process,
                       std::uint64_t remoteImageBase,
                       const PeImageInfo& image,
                       const std::vector<FunctionSymbol>& functions,
                       const PatchOptions& options,
                       InstrumentationResult& result,
                       std::string& error);

bool ReadCounters(HANDLE process,
                  const InstrumentationResult& instrumentation,
                  std::vector<std::uint64_t>& counters,
                  std::string& error);

} // namespace miri
