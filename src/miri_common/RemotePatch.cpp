#include "miri_common/RemotePatch.h"

#include "miri_common/StringUtil.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <map>
#include <sstream>

namespace miri {
namespace {

constexpr std::size_t kPatchBytes = 5;
constexpr std::size_t kMaxCopiedBytes = 32;
constexpr std::size_t kStubStride = 96;
constexpr std::uint64_t kRel32Window = 0x7FFF0000ull;
constexpr std::uint8_t kEndbr64[] = {0xF3, 0x0F, 0x1E, 0xFA};

struct DecodedInstruction {
    std::size_t length = 0;
    bool invalid = false;
    bool ripRelative = false;
    bool controlFlow = false;
    bool terminal = false;
    const char* reason = "";
};

struct PatchSite {
    std::uint32_t rva = 0;
    std::vector<FunctionSymbol> symbols;
    std::uint64_t remoteAddress = 0;
    std::uint32_t patchOffset = 0;
    std::uint32_t stolenLength = 0;
    std::array<std::uint8_t, kMaxCopiedBytes> stolen = {};
    bool patchable = false;
    std::string status;
    std::uint64_t stubAddress = 0;
    std::uint64_t counterAddress = 0;
    std::uint32_t counterIndex = UINT32_MAX;
};

std::uint64_t AlignDown(std::uint64_t value, std::uint64_t alignment)
{
    return value & ~(alignment - 1);
}

std::uint64_t AlignUp(std::uint64_t value, std::uint64_t alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}

bool FitsRel32(std::uint64_t sourceNext, std::uint64_t destination)
{
    const auto delta = static_cast<std::int64_t>(destination) -
                       static_cast<std::int64_t>(sourceNext);
    return delta >= std::numeric_limits<std::int32_t>::min() &&
           delta <= std::numeric_limits<std::int32_t>::max();
}

std::int32_t Rel32(std::uint64_t sourceNext, std::uint64_t destination)
{
    return static_cast<std::int32_t>(static_cast<std::int64_t>(destination) -
                                    static_cast<std::int64_t>(sourceNext));
}

void AppendU8(std::vector<std::uint8_t>& code, std::uint8_t value)
{
    code.push_back(value);
}

void AppendI32(std::vector<std::uint8_t>& code, std::int32_t value)
{
    const auto raw = static_cast<std::uint32_t>(value);
    code.push_back(static_cast<std::uint8_t>(raw & 0xFF));
    code.push_back(static_cast<std::uint8_t>((raw >> 8) & 0xFF));
    code.push_back(static_cast<std::uint8_t>((raw >> 16) & 0xFF));
    code.push_back(static_cast<std::uint8_t>((raw >> 24) & 0xFF));
}

bool IsPrefix(std::uint8_t byte)
{
    switch (byte) {
    case 0xF0:
    case 0xF2:
    case 0xF3:
    case 0x2E:
    case 0x36:
    case 0x3E:
    case 0x26:
    case 0x64:
    case 0x65:
    case 0x66:
    case 0x67:
        return true;
    default:
        return byte >= 0x40 && byte <= 0x4F;
    }
}

bool IsBinaryModRmOpcode(std::uint8_t opcode)
{
    switch (opcode) {
    case 0x00:
    case 0x01:
    case 0x02:
    case 0x03:
    case 0x08:
    case 0x09:
    case 0x0A:
    case 0x0B:
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13:
    case 0x18:
    case 0x19:
    case 0x1A:
    case 0x1B:
    case 0x20:
    case 0x21:
    case 0x22:
    case 0x23:
    case 0x28:
    case 0x29:
    case 0x2A:
    case 0x2B:
    case 0x30:
    case 0x31:
    case 0x32:
    case 0x33:
    case 0x38:
    case 0x39:
    case 0x3A:
    case 0x3B:
        return true;
    default:
        return false;
    }
}

std::size_t OperandImmediateSize(bool operand16)
{
    return operand16 ? 2u : 4u;
}

bool ParseModRm(const std::uint8_t* code,
                std::size_t max,
                std::size_t& index,
                bool& ripRelative,
                std::uint8_t& reg)
{
    if (index >= max) {
        return false;
    }

    const std::uint8_t modrm = code[index++];
    const std::uint8_t mod = (modrm >> 6) & 0x03;
    reg = (modrm >> 3) & 0x07;
    const std::uint8_t rm = modrm & 0x07;

    if (mod != 3 && rm == 4) {
        if (index >= max) {
            return false;
        }
        const std::uint8_t sib = code[index++];
        const std::uint8_t base = sib & 0x07;
        if (mod == 0 && base == 5) {
            if (index + 4 > max) {
                return false;
            }
            index += 4;
        }
    } else if (mod == 0 && rm == 5) {
        if (index + 4 > max) {
            return false;
        }
        index += 4;
        ripRelative = true;
    }

    if (mod == 1) {
        if (index + 1 > max) {
            return false;
        }
        index += 1;
    } else if (mod == 2) {
        if (index + 4 > max) {
            return false;
        }
        index += 4;
    }

    return true;
}

DecodedInstruction DecodeX64Instruction(const std::uint8_t* code, std::size_t max)
{
    DecodedInstruction decoded;
    if (max == 0) {
        decoded.invalid = true;
        decoded.reason = "truncated instruction";
        return decoded;
    }

    std::size_t index = 0;
    bool rexW = false;
    bool operand16 = false;
    bool addressOverride = false;

    while (index < max && IsPrefix(code[index])) {
        const std::uint8_t prefix = code[index++];
        if (prefix == 0x66) {
            operand16 = true;
        } else if (prefix == 0x67) {
            addressOverride = true;
        } else if (prefix >= 0x40 && prefix <= 0x4F) {
            rexW = (prefix & 0x08) != 0;
        }
    }

    if (addressOverride) {
        decoded.invalid = true;
        decoded.reason = "address-size override is unsupported";
        return decoded;
    }

    if (index >= max) {
        decoded.invalid = true;
        decoded.reason = "truncated opcode";
        return decoded;
    }

    const std::uint8_t opcode = code[index++];
    bool modRm = false;
    std::size_t immediate = 0;
    bool groupF6F7 = false;
    bool groupFF = false;

    if (opcode == 0x0F) {
        if (index >= max) {
            decoded.invalid = true;
            decoded.reason = "truncated two-byte opcode";
            return decoded;
        }

        const std::uint8_t opcode2 = code[index++];
        if (opcode2 >= 0x80 && opcode2 <= 0x8F) {
            decoded.controlFlow = true;
            immediate = 4;
        } else {
            switch (opcode2) {
            case 0x01:
            case 0x10:
            case 0x11:
            case 0x12:
            case 0x13:
            case 0x14:
            case 0x15:
            case 0x16:
            case 0x17:
            case 0x1E:
            case 0x1F:
            case 0x28:
            case 0x29:
            case 0x2A:
            case 0x2B:
            case 0x2C:
            case 0x2D:
            case 0x2E:
            case 0x2F:
            case 0x40:
            case 0x41:
            case 0x42:
            case 0x43:
            case 0x44:
            case 0x45:
            case 0x46:
            case 0x47:
            case 0x48:
            case 0x49:
            case 0x4A:
            case 0x4B:
            case 0x4C:
            case 0x4D:
            case 0x4E:
            case 0x4F:
            case 0x50:
            case 0x51:
            case 0x52:
            case 0x53:
            case 0x54:
            case 0x55:
            case 0x56:
            case 0x57:
            case 0x58:
            case 0x59:
            case 0x5A:
            case 0x5B:
            case 0x5C:
            case 0x5D:
            case 0x5E:
            case 0x5F:
            case 0x60:
            case 0x61:
            case 0x62:
            case 0x63:
            case 0x64:
            case 0x65:
            case 0x66:
            case 0x67:
            case 0x68:
            case 0x69:
            case 0x6A:
            case 0x6B:
            case 0x6C:
            case 0x6D:
            case 0x6E:
            case 0x6F:
            case 0x90:
            case 0x91:
            case 0x92:
            case 0x93:
            case 0x94:
            case 0x95:
            case 0x96:
            case 0x97:
            case 0x98:
            case 0x99:
            case 0x9A:
            case 0x9B:
            case 0x9C:
            case 0x9D:
            case 0x9E:
            case 0x9F:
            case 0xA3:
            case 0xAB:
            case 0xAE:
            case 0xAF:
            case 0xB0:
            case 0xB1:
            case 0xB2:
            case 0xB3:
            case 0xB4:
            case 0xB5:
            case 0xB6:
            case 0xB7:
            case 0xBC:
            case 0xBD:
            case 0xBE:
            case 0xBF:
            case 0xC0:
            case 0xC1:
            case 0xC2:
            case 0xC3:
            case 0xC4:
            case 0xC5:
            case 0xC6:
            case 0xC7:
                modRm = true;
                break;
            case 0x70:
                modRm = true;
                immediate = 1;
                break;
            case 0x71:
            case 0x72:
            case 0x73:
            case 0xA4:
            case 0xAC:
            case 0xBA:
                modRm = true;
                immediate = 1;
                break;
            case 0x05:
            case 0x31:
            case 0xA2:
                break;
            default:
                decoded.invalid = true;
                decoded.reason = "unsupported two-byte opcode";
                return decoded;
            }
        }
    } else if (opcode >= 0x70 && opcode <= 0x7F) {
        decoded.controlFlow = true;
        immediate = 1;
    } else if (opcode >= 0xB0 && opcode <= 0xB7) {
        immediate = 1;
    } else if (opcode >= 0xB8 && opcode <= 0xBF) {
        immediate = rexW ? 8u : OperandImmediateSize(operand16);
    } else if (IsBinaryModRmOpcode(opcode)) {
        modRm = true;
    } else {
        switch (opcode) {
        case 0x04:
        case 0x0C:
        case 0x14:
        case 0x1C:
        case 0x24:
        case 0x2C:
        case 0x34:
        case 0x3C:
            immediate = 1;
            break;
        case 0x05:
        case 0x0D:
        case 0x15:
        case 0x1D:
        case 0x25:
        case 0x2D:
        case 0x35:
        case 0x3D:
            immediate = OperandImmediateSize(operand16);
            break;
        case 0x50:
        case 0x51:
        case 0x52:
        case 0x53:
        case 0x54:
        case 0x55:
        case 0x56:
        case 0x57:
        case 0x58:
        case 0x59:
        case 0x5A:
        case 0x5B:
        case 0x5C:
        case 0x5D:
        case 0x5E:
        case 0x5F:
        case 0x90:
        case 0x91:
        case 0x92:
        case 0x93:
        case 0x94:
        case 0x95:
        case 0x96:
        case 0x97:
        case 0x98:
        case 0x99:
        case 0x9A:
        case 0x9B:
        case 0x9C:
        case 0x9D:
        case 0x9E:
        case 0x9F:
        case 0xC9:
            break;
        case 0x63:
        case 0x69:
        case 0x6B:
        case 0x80:
        case 0x81:
        case 0x82:
        case 0x83:
        case 0x84:
        case 0x85:
        case 0x86:
        case 0x87:
        case 0x88:
        case 0x89:
        case 0x8A:
        case 0x8B:
        case 0x8C:
        case 0x8D:
        case 0x8E:
        case 0x8F:
        case 0xC0:
        case 0xC1:
        case 0xC6:
        case 0xC7:
        case 0xD0:
        case 0xD1:
        case 0xD2:
        case 0xD3:
        case 0xF6:
        case 0xF7:
        case 0xFE:
        case 0xFF:
            modRm = true;
            break;
        case 0x68:
            immediate = OperandImmediateSize(operand16);
            break;
        case 0x6A:
            immediate = 1;
            break;
        case 0xA8:
            immediate = 1;
            break;
        case 0xA9:
            immediate = OperandImmediateSize(operand16);
            break;
        case 0xC2:
        case 0xCA:
            decoded.terminal = true;
            immediate = 2;
            break;
        case 0xC3:
        case 0xCB:
            decoded.terminal = true;
            break;
        case 0xC8:
            immediate = 3;
            break;
        case 0xCD:
            decoded.terminal = true;
            immediate = 1;
            break;
        case 0xCC:
        case 0xCE:
        case 0xCF:
            decoded.terminal = true;
            break;
        case 0xE0:
        case 0xE1:
        case 0xE2:
        case 0xE3:
            decoded.controlFlow = true;
            immediate = 1;
            break;
        case 0xE8:
        case 0xE9:
            decoded.controlFlow = true;
            immediate = 4;
            break;
        case 0xEB:
            decoded.controlFlow = true;
            immediate = 1;
            break;
        default:
            decoded.invalid = true;
            decoded.reason = "unsupported opcode";
            return decoded;
        }

        if (opcode == 0x69) {
            immediate = OperandImmediateSize(operand16);
        } else if (opcode == 0x6B || opcode == 0x80 || opcode == 0x82 ||
                   opcode == 0x83 || opcode == 0xC0 || opcode == 0xC1 ||
                   opcode == 0xC6) {
            immediate = 1;
        } else if (opcode == 0x81 || opcode == 0xC7) {
            immediate = OperandImmediateSize(operand16);
        } else if (opcode == 0xF6 || opcode == 0xF7) {
            groupF6F7 = true;
        } else if (opcode == 0xFF) {
            groupFF = true;
        }
    }

    std::uint8_t modRmReg = 0;
    if (modRm) {
        if (!ParseModRm(code, max, index, decoded.ripRelative, modRmReg)) {
            decoded.invalid = true;
            decoded.reason = "truncated ModRM";
            return decoded;
        }

        if (groupF6F7 && modRmReg <= 1) {
            immediate = opcode == 0xF6 ? 1u : OperandImmediateSize(operand16);
        }

        if (groupFF && modRmReg >= 2 && modRmReg <= 5) {
            decoded.controlFlow = true;
        }
    }

    if (index + immediate > max) {
        decoded.invalid = true;
        decoded.reason = "truncated immediate";
        return decoded;
    }
    index += immediate;

    if (index == 0 || index > 15) {
        decoded.invalid = true;
        decoded.reason = "invalid instruction length";
        return decoded;
    }

    decoded.length = index;
    return decoded;
}

bool ReadRemote(HANDLE process, std::uint64_t address, void* buffer, std::size_t size,
                std::string& error)
{
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address), buffer, size, &bytesRead) ||
        bytesRead != size) {
        error = "ReadProcessMemory failed at " + Hex64(address) + ": " + LastWin32ErrorMessage();
        return false;
    }
    return true;
}

bool WriteRemote(HANDLE process, std::uint64_t address, const void* buffer, std::size_t size,
                 std::string& error)
{
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(process, reinterpret_cast<LPVOID>(address), buffer, size,
                            &bytesWritten) ||
        bytesWritten != size) {
        error = "WriteProcessMemory failed at " + Hex64(address) + ": " + LastWin32ErrorMessage();
        return false;
    }
    return true;
}

bool AnalyzePatchSite(const std::array<std::uint8_t, kMaxCopiedBytes>& bytes,
                      std::uint32_t functionSize,
                      PatchSite& site)
{
    std::size_t patchOffset = 0;
    if (std::memcmp(bytes.data(), kEndbr64, sizeof(kEndbr64)) == 0) {
        patchOffset = sizeof(kEndbr64);
    }

    if (functionSize != 0 && functionSize <= patchOffset) {
        site.status = "skipped: function body is too small";
        return false;
    }

    std::size_t stolen = 0;
    while (stolen < kPatchBytes) {
        if (patchOffset + stolen >= bytes.size()) {
            site.status = "skipped: function entry is truncated";
            return false;
        }

        const auto decoded = DecodeX64Instruction(bytes.data() + patchOffset + stolen,
                                                  bytes.size() - patchOffset - stolen);
        if (decoded.invalid) {
            site.status = std::string("skipped: ") + decoded.reason;
            return false;
        }
        if (decoded.ripRelative) {
            site.status = "skipped: RIP-relative instruction in patch window";
            return false;
        }
        if (decoded.controlFlow) {
            site.status = "skipped: control-flow instruction in patch window";
            return false;
        }
        if (decoded.terminal) {
            site.status = "skipped: terminal instruction in patch window";
            return false;
        }

        stolen += decoded.length;
        if (stolen > kMaxCopiedBytes) {
            site.status = "skipped: patch window is too large";
            return false;
        }

        if (functionSize != 0 && patchOffset + stolen > functionSize) {
            site.status = "skipped: function body is smaller than patch window";
            return false;
        }
    }

    site.patchOffset = static_cast<std::uint32_t>(patchOffset);
    site.stolenLength = static_cast<std::uint32_t>(stolen);
    std::memcpy(site.stolen.data(), bytes.data() + patchOffset, stolen);
    site.patchable = true;
    site.status = "planned";
    return true;
}

std::vector<PatchSite> BuildSites(HANDLE process,
                                  std::uint64_t remoteImageBase,
                                  const std::vector<FunctionSymbol>& functions,
                                  std::string& error)
{
    std::map<std::uint32_t, PatchSite> grouped;
    for (const auto& function : functions) {
        auto& site = grouped[function.rva];
        site.rva = function.rva;
        site.remoteAddress = remoteImageBase + function.rva;
        site.symbols.push_back(function);
    }

    std::vector<PatchSite> sites;
    sites.reserve(grouped.size());

    for (auto& [rva, site] : grouped) {
        std::array<std::uint8_t, kMaxCopiedBytes> bytes = {};
        std::string readError;
        if (!ReadRemote(process, site.remoteAddress, bytes.data(), bytes.size(), readError)) {
            site.patchable = false;
            site.status = "skipped: " + readError;
        } else {
            const std::uint32_t size = site.symbols.empty() ? 0 : site.symbols.front().size;
            AnalyzePatchSite(bytes, size, site);
        }

        sites.push_back(std::move(site));
    }

    (void)error;
    return sites;
}

std::uint64_t AllocateNear(HANDLE process, std::uint64_t nearAddress, std::size_t size)
{
    SYSTEM_INFO systemInfo = {};
    GetSystemInfo(&systemInfo);

    const std::uint64_t granularity = systemInfo.dwAllocationGranularity;
    const std::uint64_t alignedSize = AlignUp(size, systemInfo.dwPageSize);
    const std::uint64_t base = AlignDown(nearAddress, granularity);

    for (std::uint64_t offset = 0; offset <= kRel32Window; offset += granularity) {
        const std::uint64_t candidates[] = {
            base + offset,
            base > offset ? base - offset : 0,
        };

        for (const std::uint64_t candidate : candidates) {
            if (candidate < 0x10000) {
                continue;
            }

            void* memory = VirtualAllocEx(process, reinterpret_cast<LPVOID>(candidate),
                                          static_cast<SIZE_T>(alignedSize),
                                          MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (memory != nullptr) {
                return reinterpret_cast<std::uint64_t>(memory);
            }
        }
    }

    return 0;
}

bool BuildStub(const PatchSite& site, bool atomicCounters, std::vector<std::uint8_t>& stub,
               std::string& error)
{
    stub.clear();
    stub.reserve(kStubStride);

    AppendU8(stub, 0x9C); // pushfq

    const std::uint64_t incStart = site.stubAddress + stub.size();
    const std::size_t incLength = atomicCounters ? 7u : 6u;
    const std::uint64_t incNext = incStart + incLength;
    if (!FitsRel32(incNext, site.counterAddress)) {
        error = "counter is outside RIP-relative range";
        return false;
    }

    if (atomicCounters) {
        AppendU8(stub, 0xF0); // lock
    }
    AppendU8(stub, 0xFF);
    AppendU8(stub, 0x05); // inc qword ptr [rip + disp32]
    AppendI32(stub, Rel32(incNext, site.counterAddress));

    AppendU8(stub, 0x9D); // popfq

    stub.insert(stub.end(), site.stolen.begin(), site.stolen.begin() + site.stolenLength);

    const std::uint64_t jumpBackStart = site.stubAddress + stub.size();
    const std::uint64_t jumpBackNext = jumpBackStart + kPatchBytes;
    const std::uint64_t jumpBackTarget =
        site.remoteAddress + site.patchOffset + site.stolenLength;
    if (!FitsRel32(jumpBackNext, jumpBackTarget)) {
        error = "jump back target is outside rel32 range";
        return false;
    }

    AppendU8(stub, 0xE9);
    AppendI32(stub, Rel32(jumpBackNext, jumpBackTarget));

    if (stub.size() > kStubStride) {
        error = "stub exceeded reserved stride";
        return false;
    }

    return true;
}

bool PatchEntryPoint(HANDLE process, const PatchSite& site, std::string& error)
{
    const std::uint64_t patchAddress = site.remoteAddress + site.patchOffset;
    const std::uint64_t patchNext = patchAddress + kPatchBytes;
    if (!FitsRel32(patchNext, site.stubAddress)) {
        error = "stub is outside entry-point rel32 range";
        return false;
    }

    std::vector<std::uint8_t> patch(site.stolenLength, 0x90);
    patch[0] = 0xE9;
    const std::int32_t relative = Rel32(patchNext, site.stubAddress);
    std::memcpy(patch.data() + 1, &relative, sizeof(relative));

    DWORD oldProtect = 0;
    if (!VirtualProtectEx(process, reinterpret_cast<LPVOID>(patchAddress), patch.size(),
                          PAGE_EXECUTE_READWRITE, &oldProtect)) {
        error = "VirtualProtectEx failed at " + Hex64(patchAddress) + ": " +
                LastWin32ErrorMessage();
        return false;
    }

    const bool wrote = WriteRemote(process, patchAddress, patch.data(), patch.size(), error);

    DWORD ignored = 0;
    VirtualProtectEx(process, reinterpret_cast<LPVOID>(patchAddress), patch.size(), oldProtect,
                     &ignored);
    FlushInstructionCache(process, reinterpret_cast<LPCVOID>(patchAddress), patch.size());

    return wrote;
}

void AddRecordsForSite(const PatchSite& site, InstrumentationResult& result)
{
    for (const auto& symbol : site.symbols) {
        PatchResult record;
        record.function = symbol;
        record.patched = site.patchable && site.status == "patched";
        record.patchOffset = site.patchOffset;
        record.stolenLength = site.stolenLength;
        record.remoteAddress = site.remoteAddress;
        record.stubAddress = site.stubAddress;
        record.counterAddress = site.counterAddress;
        record.counterIndex = site.counterIndex;
        record.status = site.status;
        result.records.push_back(std::move(record));
    }
}

} // namespace

bool InstrumentProcess(HANDLE process,
                       std::uint64_t remoteImageBase,
                       const PeImageInfo& image,
                       const std::vector<FunctionSymbol>& functions,
                       const PatchOptions& options,
                       InstrumentationResult& result,
                       std::string& error)
{
    (void)image;
    result = {};

    std::vector<PatchSite> sites = BuildSites(process, remoteImageBase, functions, error);
    std::vector<PatchSite*> patchable;
    patchable.reserve(sites.size());

    for (auto& site : sites) {
        if (!site.patchable) {
            continue;
        }
        if (options.maxFunctions != 0 && patchable.size() >= options.maxFunctions) {
            site.patchable = false;
            site.status = "skipped: maxFunctions reached";
            continue;
        }
        patchable.push_back(&site);
    }

    if (!patchable.empty()) {
        SYSTEM_INFO systemInfo = {};
        GetSystemInfo(&systemInfo);
        const std::size_t pageSize = systemInfo.dwPageSize;
        const std::size_t stubCapacity = static_cast<std::size_t>(
            AlignUp(patchable.size() * kStubStride, pageSize));
        const std::size_t counterCapacity = static_cast<std::size_t>(
            AlignUp(patchable.size() * sizeof(std::uint64_t), pageSize));
        const std::size_t allocationSize = stubCapacity + counterCapacity;

        const std::uint64_t allocation = AllocateNear(process, remoteImageBase, allocationSize);
        if (allocation == 0) {
            error = "failed to allocate trampoline/counter memory near image base";
            return false;
        }

        result.stubBase = allocation;
        result.stubBytes = stubCapacity;
        result.counterBase = allocation + stubCapacity;
        result.counterCount = patchable.size();
        result.counterBytes = patchable.size() * sizeof(std::uint64_t);

        for (std::size_t index = 0; index < patchable.size(); ++index) {
            PatchSite& site = *patchable[index];
            site.stubAddress = result.stubBase + index * kStubStride;
            site.counterAddress = result.counterBase + index * sizeof(std::uint64_t);
            site.counterIndex = static_cast<std::uint32_t>(index);

            std::vector<std::uint8_t> stub;
            std::string stubError;
            if (!BuildStub(site, options.atomicCounters, stub, stubError)) {
                site.patchable = false;
                site.status = "skipped: " + stubError;
                continue;
            }

            std::string writeError;
            if (!WriteRemote(process, site.stubAddress, stub.data(), stub.size(), writeError)) {
                site.patchable = false;
                site.status = "skipped: " + writeError;
                continue;
            }

            std::string patchError;
            if (!PatchEntryPoint(process, site, patchError)) {
                site.patchable = false;
                site.status = "skipped: " + patchError;
                continue;
            }

            site.status = "patched";
        }

        DWORD oldProtect = 0;
        if (!VirtualProtectEx(process, reinterpret_cast<LPVOID>(result.stubBase), stubCapacity,
                              PAGE_EXECUTE_READ, &oldProtect)) {
            error = "failed to protect trampoline pages: " + LastWin32ErrorMessage();
            return false;
        }
        if (!VirtualProtectEx(process, reinterpret_cast<LPVOID>(result.counterBase),
                              counterCapacity, PAGE_READWRITE, &oldProtect)) {
            error = "failed to protect counter pages: " + LastWin32ErrorMessage();
            return false;
        }
    }

    for (const auto& site : sites) {
        AddRecordsForSite(site, result);
    }

    std::sort(result.records.begin(), result.records.end(),
              [](const PatchResult& left, const PatchResult& right) {
                  if (left.function.rva != right.function.rva) {
                      return left.function.rva < right.function.rva;
                  }
                  return left.function.name < right.function.name;
              });

    return true;
}

bool ReadCounters(HANDLE process,
                  const InstrumentationResult& instrumentation,
                  std::vector<std::uint64_t>& counters,
                  std::string& error)
{
    counters.assign(instrumentation.counterCount, 0);
    if (instrumentation.counterCount == 0) {
        return true;
    }

    return ReadRemote(process, instrumentation.counterBase, counters.data(),
                      instrumentation.counterCount * sizeof(std::uint64_t), error);
}

} // namespace miri
