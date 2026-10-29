// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Rennie Allen

#include "miri_common/RemotePatch.h"

#include "miri_common/StringUtil.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <future>
#include <iostream>
#include <limits>
#include <mutex>
#include <sstream>
#include <thread>
#include <tlhelp32.h>

namespace miri
{
namespace
{

constexpr std::size_t kNearPatchBytes{5};
constexpr std::size_t kAbsolutePatchBytes{14};
constexpr std::size_t kMaxCopiedBytes{32};
constexpr std::size_t kMaxAnalyzeBytes{128};
constexpr std::size_t kStubStride{96};
constexpr std::size_t kDefaultPatchSitesPerAllocation{4096};
constexpr std::size_t kHookPatchTaskSize{10 * 1000};
constexpr std::uint64_t kRel32Window{0x7FFF0000ull};
constexpr std::uint8_t kEndbr64[]{0xF3, 0x0F, 0x1E, 0xFA};

struct DecodedInstruction
{
    std::size_t length{0};
    bool invalid{false};
    bool ripRelative{false};
    bool controlFlow{false};
    bool relativeControlFlow{false};
    bool terminal{false};
    std::int64_t relativeTargetOffset{0};
    const char* reason{""};
};

struct PatchSite
{
    std::uint32_t rva{0};
    std::vector<FunctionSymbol> symbols;
    std::uint64_t remoteAddress{0};
    std::uint32_t patchOffset{0};
    std::uint32_t stolenLength{0};
    std::uint32_t nearStolenLength{0};
    std::uint32_t absoluteStolenLength{0};
    std::array<std::uint8_t, kMaxCopiedBytes> stolen{};
    bool patchable{false};
    bool absolutePatchable{false};
    bool useAbsolutePatch{false};
    std::string status;
    std::string absoluteStatus;
    std::uint64_t stubAddress{0};
    std::uint64_t counterAddress{0};
    std::uint32_t counterIndex{UINT32_MAX};
};

struct PatchAllocation
{
    std::uint64_t base{0};
    std::uint64_t stubBase{0};
    std::size_t stubCapacity{0};
    std::uint64_t counterBase{0};
    std::size_t counterCapacity{0};
    std::size_t siteCapacity{0};
};

struct RemoteSectionBytes
{
    std::uint32_t rva{0};
    std::uint32_t size{0};
    std::vector<std::uint8_t> bytes;
    bool readable{false};
    std::string error;
};

struct ProtectedRegion
{
    std::uint64_t address{0};
    std::size_t size{0};
    DWORD oldProtect{0};
};

// The caller must hold a debug event, which keeps every target thread stopped.
bool CollectStoppedInstructionPointers(HANDLE process, std::vector<std::uint64_t>& addresses,
                                       std::string& error)
{
    addresses.clear();
    const DWORD pid{GetProcessId(process)};
    if (pid == 0)
    {
        error = "GetProcessId failed: " + LastWin32ErrorMessage();
        return false;
    }
    HANDLE snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)};
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        error = "thread snapshot failed: " + LastWin32ErrorMessage();
        return false;
    }
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    BOOL haveEntry{Thread32First(snapshot, &entry)};
    while (haveEntry)
    {
        if (entry.th32OwnerProcessID == pid)
        {
            HANDLE thread{OpenThread(THREAD_GET_CONTEXT, FALSE, entry.th32ThreadID)};
            CONTEXT context{};
            context.ContextFlags = CONTEXT_CONTROL;
            const bool captured{thread != nullptr && GetThreadContext(thread, &context)};
            if (!captured)
            {
                error = "cannot read stopped thread " + std::to_string(entry.th32ThreadID) +
                        " before patching: " + LastWin32ErrorMessage();
            }
            if (thread != nullptr) CloseHandle(thread);
            if (!captured)
            {
                CloseHandle(snapshot);
                return false;
            }
            addresses.push_back(context.Rip);
        }
        haveEntry = Thread32Next(snapshot, &entry);
    }
    const DWORD enumerationError{GetLastError()};
    CloseHandle(snapshot);
    if (enumerationError != ERROR_NO_MORE_FILES || addresses.empty())
    {
        error = "could not enumerate all stopped target threads (error " +
                std::to_string(enumerationError) + ")";
        return false;
    }
    std::sort(addresses.begin(), addresses.end());
    return true;
}

void ExcludeActivePatchSites(std::vector<PatchSite>& sites,
                             const std::vector<std::uint64_t>& sortedInstructionPointers)
{
    for (auto& site : sites)
    {
        if (!site.patchable) continue;
        const std::uint64_t begin{site.remoteAddress + site.patchOffset};
        // Reserve the largest possible window, including absolute fallback.
        const std::uint64_t length{std::max(site.nearStolenLength,
                                          site.absoluteStolenLength)};
        const auto next{std::upper_bound(sortedInstructionPointers.begin(),
                                         sortedInstructionPointers.end(), begin)};
        if (next != sortedInstructionPointers.end() && *next - begin < length)
        {
            site.patchable = false;
            site.status = "skipped: stopped thread instruction pointer " + Hex64(*next) +
                          " is inside patch window";
        }
    }
}

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
    const auto delta{static_cast<std::int64_t>(destination) -
                       static_cast<std::int64_t>(sourceNext)};
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
    const auto raw{static_cast<std::uint32_t>(value)};
    code.push_back(static_cast<std::uint8_t>(raw & 0xFF));
    code.push_back(static_cast<std::uint8_t>((raw >> 8) & 0xFF));
    code.push_back(static_cast<std::uint8_t>((raw >> 16) & 0xFF));
    code.push_back(static_cast<std::uint8_t>((raw >> 24) & 0xFF));
}

void AppendU64(std::vector<std::uint8_t>& code, std::uint64_t value)
{
    for (int shift{0}; shift < 64; shift += 8)
    {
        code.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFF));
    }
}

void AppendAbsoluteJump(std::vector<std::uint8_t>& code, std::uint64_t destination)
{
    AppendU8(code, 0xFF);
    AppendU8(code, 0x25);
    AppendI32(code, 0);
    AppendU64(code, destination);
}

bool IsPrefix(std::uint8_t byte)
{
    switch (byte)
    {
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
    switch (opcode)
    {
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
    if (index >= max)
    {
        return false;
    }

    const std::uint8_t modrm{code[index++]};
    const std::uint8_t mod{static_cast<std::uint8_t>((modrm >> 6) & 0x03)};
    reg = static_cast<std::uint8_t>((modrm >> 3) & 0x07);
    const std::uint8_t rm{static_cast<std::uint8_t>(modrm & 0x07)};

    if (mod != 3 && rm == 4)
    {
        if (index >= max)
        {
            return false;
        }
        const std::uint8_t sib{code[index++]};
        const std::uint8_t base{static_cast<std::uint8_t>(sib & 0x07)};
        if (mod == 0 && base == 5)
        {
            if (index + 4 > max)
            {
                return false;
            }
            index += 4;
        }
    } 
    else 
    if (mod == 0 && rm == 5)
    {
        if (index + 4 > max)
        {
            return false;
        }
        index += 4;
        ripRelative = true;
    }

    if (mod == 1)
    {
        if (index + 1 > max)
        {
            return false;
        }
        index += 1;
    } 
    else 
    if (mod == 2)
    {
        if (index + 4 > max)
        {
            return false;
        }
        index += 4;
    }

    return true;
}

DecodedInstruction DecodeX64Instruction(const std::uint8_t* code, std::size_t max)
{
    DecodedInstruction decoded;
    if (max == 0)
    {
        decoded.invalid = true;
        decoded.reason = "truncated instruction";
        return decoded;
    }

    std::size_t index{0};
    bool rexW{false};
    bool operand16{false};
    bool addressOverride{false};

    while (index < max && IsPrefix(code[index]))
{
        const std::uint8_t prefix{code[index++]};
        if (prefix == 0x66)
        {
            operand16 = true;
        } 
        else 
        if (prefix == 0x67)
        {
            addressOverride = true;
        } 
        else 
        if (prefix >= 0x40 && prefix <= 0x4F)
        {
            rexW = (prefix & 0x08) != 0;
        }
    }

    if (addressOverride)
    {
        decoded.invalid = true;
        decoded.reason = "address-size override is unsupported";
        return decoded;
    }

    if (index >= max)
    {
        decoded.invalid = true;
        decoded.reason = "truncated opcode";
        return decoded;
    }

    const std::uint8_t opcode{code[index++]};
    bool modRm{false};
    std::size_t immediate{0};
    bool groupF6F7{false};
    bool groupFF{false};

    if (opcode == 0x0F)
    {
        if (index >= max)
        {
            decoded.invalid = true;
            decoded.reason = "truncated two-byte opcode";
            return decoded;
        }

        const std::uint8_t opcode2{code[index++]};
        if (opcode2 >= 0x80 && opcode2 <= 0x8F)
        {
            decoded.controlFlow = true;
            decoded.relativeControlFlow = true;
            immediate = 4;
        } 
        else
        {
            switch (opcode2)
            {
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
            case 0xC3:
            case 0xC7:
                modRm = true;
                break;
            // SIMD compare, insert/extract and shuffle instructions carry an
            // imm8 after ModRM/SIB/displacement. Omitting it can split the
            // instruction and consume the trampoline's jump as the immediate.
            case 0xC2:
            case 0xC4:
            case 0xC5:
            case 0xC6:
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
    }
    else
    if (opcode >= 0x70 && opcode <= 0x7F)
    {
        decoded.controlFlow = true;
        decoded.relativeControlFlow = true;
        immediate = 1;
    }
    else
    if (opcode >= 0xB0 && opcode <= 0xB7)
    {
        immediate = 1;
    }
    else
    if (opcode >= 0xB8 && opcode <= 0xBF)
    {
        immediate = rexW ? 8u : OperandImmediateSize(operand16);
    }
    else
    if (IsBinaryModRmOpcode(opcode))
    {
        modRm = true;
    }
    else
    {
        switch (opcode)
        {
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
            decoded.relativeControlFlow = true;
            immediate = 1;
            break;
        case 0xE8:
        case 0xE9:
            decoded.controlFlow = true;
            decoded.relativeControlFlow = true;
            immediate = 4;
            break;
        case 0xEB:
            decoded.controlFlow = true;
            decoded.relativeControlFlow = true;
            immediate = 1;
            break;
        default:
            decoded.invalid = true;
            decoded.reason = "unsupported opcode";
            return decoded;
        }

        if (opcode == 0x69)
        {
            immediate = OperandImmediateSize(operand16);
        }
        else
        if (opcode == 0x6B || opcode == 0x80 || opcode == 0x82 ||
                   opcode == 0x83 || opcode == 0xC0 || opcode == 0xC1 ||
                   opcode == 0xC6) {
            immediate = 1;
        }
        else
        if (opcode == 0x81 || opcode == 0xC7)
        {
            immediate = OperandImmediateSize(operand16);
        }
        else
        if (opcode == 0xF6 || opcode == 0xF7)
        {
            groupF6F7 = true;
        }
        else
        if (opcode == 0xFF)
        {
            groupFF = true;
        }
    }

    std::uint8_t modRmReg{0};
    if (modRm)
    {
        if (!ParseModRm(code, max, index, decoded.ripRelative, modRmReg))
        {
            decoded.invalid = true;
            decoded.reason = "truncated ModRM";
            return decoded;
        }

        if (groupF6F7 && modRmReg <= 1)
        {
            immediate = opcode == 0xF6 ? 1u : OperandImmediateSize(operand16);
        }

        if (groupFF && modRmReg >= 2 && modRmReg <= 5)
        {
            decoded.controlFlow = true;
        }
    }

    if (index + immediate > max)
    {
        decoded.invalid = true;
        decoded.reason = "truncated immediate";
        return decoded;
    }

    const std::size_t immediateOffset{index};
    index += immediate;

    if (index == 0 || index > 15)
    {
        decoded.invalid = true;
        decoded.reason = "invalid instruction length";
        return decoded;
    }

    decoded.length = index;
    if (decoded.relativeControlFlow)
    {
        std::int64_t displacement{0};
        if (immediate == 1)
        {
            displacement = static_cast<std::int8_t>(code[immediateOffset]);
        }
        else
        if (immediate == 4)
        {
            std::int32_t value{0};
            std::memcpy(&value, code + immediateOffset, sizeof(value));
            displacement = value;
        }
        else
        {
            decoded.relativeControlFlow = false;
        }
        decoded.relativeTargetOffset = static_cast<std::int64_t>(decoded.length) + displacement;
    }
    return decoded;
}

bool ReadRemote(HANDLE process, std::uint64_t address, void* buffer, std::size_t size,
                std::string& error)
{
    SIZE_T bytesRead{0};
    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address), buffer, size, &bytesRead) ||
        bytesRead != size)
    {
        error = "ReadProcessMemory failed at " + Hex64(address) + ": " + LastWin32ErrorMessage();
        return false;
    }
    return true;
}

bool WriteRemote(HANDLE process, std::uint64_t address, const void* buffer, std::size_t size,
                 std::string& error)
{
    SIZE_T bytesWritten{0};
    if (!WriteProcessMemory(process, reinterpret_cast<LPVOID>(address), buffer, size,
                            &bytesWritten) ||
        bytesWritten != size)
    {
        error = "WriteProcessMemory failed at " + Hex64(address) + ": " + LastWin32ErrorMessage();
        return false;
    }
    return true;
}

std::size_t WorkerCountFor(std::size_t itemCount, std::size_t minItemsPerWorker)
{
    if (itemCount == 0)
    {
        return 1;
    }

    const unsigned hardware{std::thread::hardware_concurrency()};
    const std::size_t maxWorkers{hardware == 0 ? 4 : hardware};
    return std::max<std::size_t>(
        1, std::min(maxWorkers, (itemCount + minItemsPerWorker - 1) / minItemsPerWorker));
}

void LogStdout(bool verbose, const std::string& line)
{
    if (!verbose)
    {
        return;
    }
    std::cout << line << std::endl;
}

bool AnalyzePatchSite(const std::array<std::uint8_t, kMaxAnalyzeBytes>& bytes,
                      std::uint32_t functionSize,
                      PatchSite& site);

std::vector<RemoteSectionBytes> ReadExecutableSections(HANDLE process,
                                                       std::uint64_t remoteImageBase,
                                                       const PeImageInfo& image)
{
    std::vector<RemoteSectionBytes> sections;
    for (const auto& section : image.sections)
    {
        if ((section.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
        {
            continue;
        }

        const std::uint32_t size{std::max(section.virtualSize, section.rawSize)};
        if (size == 0)
        {
            continue;
        }

        RemoteSectionBytes remoteSection;
        remoteSection.rva = section.virtualAddress;
        remoteSection.size = size;
        remoteSection.bytes.resize(size);
        remoteSection.readable = ReadRemote(process,
                                            remoteImageBase + section.virtualAddress,
                                            remoteSection.bytes.data(),
                                            remoteSection.bytes.size(),
                                            remoteSection.error);
        if (!remoteSection.readable)
        {
            remoteSection.bytes.clear();
        }
        sections.push_back(std::move(remoteSection));
    }
    return sections;
}

const RemoteSectionBytes* FindSectionBytes(const std::vector<RemoteSectionBytes>& sections,
                                           std::uint32_t rva,
                                           std::size_t size)
{
    for (const auto& section : sections)
    {
        const std::uint64_t begin{section.rva};
        const std::uint64_t end{begin + section.size};
        if (rva >= begin && static_cast<std::uint64_t>(rva) + size <= end)
        {
            return &section;
        }
    }

    return nullptr;
}

void LoadPatchWindow(HANDLE process,
                     const std::vector<RemoteSectionBytes>& sections,
                     PatchSite& site)
{
    std::array<std::uint8_t, kMaxAnalyzeBytes> bytes{};
    const RemoteSectionBytes* section{FindSectionBytes(sections, site.rva, bytes.size())};
    if (section != nullptr && section->readable)
    {
        const std::size_t offset{site.rva - section->rva};
        std::memcpy(bytes.data(), section->bytes.data() + offset, bytes.size());
        const std::uint32_t size{site.symbols.empty() ? 0 : site.symbols.front().size};
        AnalyzePatchSite(bytes, size, site);
        return;
    }

    std::string readError;
    if (!ReadRemote(process, site.remoteAddress, bytes.data(), bytes.size(), readError))
    {
        site.patchable = false;
        if (section != nullptr && !section->error.empty())
        {
            site.status = "skipped: section bulk read failed and " + readError;
        } else
        {
            site.status = "skipped: " + readError;
        }

        return;
    }

    const std::uint32_t size{site.symbols.empty() ? 0 : site.symbols.front().size};
    AnalyzePatchSite(bytes, size, site);
}

void AnalyzeSites(HANDLE process,
                  const std::vector<RemoteSectionBytes>& sections,
                  std::vector<PatchSite>& sites)
{
    if (sites.empty())
    {
        return;
    }

    const std::size_t minSitesPerWorker{4096};
    const std::size_t workerCount{WorkerCountFor(sites.size(), minSitesPerWorker)};

    if (workerCount == 1)
    {
        for (auto& site : sites)
        {
            LoadPatchWindow(process, sections, site);
        }

        return;
    }

    std::vector<std::future<void>> workers;
    workers.reserve(workerCount);
    for (std::size_t worker{0}; worker < workerCount; ++worker)
{
        const std::size_t begin{worker * sites.size() / workerCount};
        const std::size_t end{(worker + 1) * sites.size() / workerCount};
        workers.push_back(std::async(std::launch::async, [process, &sections, &sites, begin, end]
        {
            for (std::size_t index{begin}; index < end; ++index)
            {
                LoadPatchWindow(process, sections, sites[index]);
            }
        }));
    }

    for (auto& worker : workers)
    {
        worker.get();
    }
}

bool AnalyzePatchWindow(const std::array<std::uint8_t, kMaxAnalyzeBytes>& bytes,
                        std::uint32_t functionSize,
                        std::size_t patchOffset,
                        std::size_t requiredBytes,
                        std::size_t& stolen,
                        std::string& status)
{
    if (functionSize != 0 && functionSize <= patchOffset)
    {
        status = "function body is too small";
        return false;
    }

    stolen = 0;
    while (stolen < requiredBytes)
    {
        if (patchOffset + stolen >= bytes.size())
        {
            status = "function entry is truncated";
            return false;
        }

        const auto decoded{DecodeX64Instruction(bytes.data() + patchOffset + stolen,
                                                  bytes.size() - patchOffset - stolen)};
        if (decoded.invalid)
        {
            status = decoded.reason;
            return false;
        }

        if (decoded.ripRelative)
        {
            status = "RIP-relative instruction in patch window";
            return false;
        }
        if (decoded.controlFlow)
        {
            status = "control-flow instruction in patch window";
            return false;
        }
        if (decoded.terminal)
        {
            status = "terminal instruction in patch window";
            return false;
        }

        stolen += decoded.length;
        if (stolen > kMaxCopiedBytes)
        {
            status = "patch window is too large";
            return false;
        }

        if (functionSize != 0 && patchOffset + stolen > functionSize)
        {
            status = "function body is smaller than patch window";
            return false;
        }
    }

    return true;
}

bool HasDirectBranchIntoPatchWindow(const std::array<std::uint8_t, kMaxAnalyzeBytes>& bytes,
                                    std::uint32_t functionSize,
                                    std::size_t patchOffset,
                                    std::size_t stolen,
                                    std::string& status)
{
    if (functionSize == 0 || stolen == 0)
    {
        return false;
    }

    const std::size_t patchBegin{patchOffset};
    const std::size_t patchEnd{patchOffset + stolen};
    const std::size_t scanEnd{std::min<std::size_t>(functionSize, bytes.size())};
    if (patchEnd >= scanEnd)
    {
        return false;
    }

    std::size_t offset{patchEnd};
    while (offset < scanEnd)
    {
        const auto decoded{DecodeX64Instruction(bytes.data() + offset, scanEnd - offset)};
        if (decoded.invalid || decoded.length == 0)
        {
            return false;
        }

        if (decoded.relativeControlFlow)
        {
            const std::int64_t target{static_cast<std::int64_t>(offset) + decoded.relativeTargetOffset};
            if (target >= static_cast<std::int64_t>(patchBegin) &&
                target < static_cast<std::int64_t>(patchEnd)) {
                std::ostringstream stream;
                stream << "direct branch at +" << Hex64(offset)
                       << " targets overwritten patch bytes at +"
                       << Hex64(static_cast<std::uint64_t>(target));
                status = stream.str();
                return true;
            }
        }

        if (decoded.terminal)
        {
            break;
        }

        offset += decoded.length;
    }

    return false;
}

bool AnalyzePatchSite(const std::array<std::uint8_t, kMaxAnalyzeBytes>& bytes,
                      std::uint32_t functionSize,
                      PatchSite& site)
{
    std::size_t patchOffset{0};
    if (std::memcmp(bytes.data(), kEndbr64, sizeof(kEndbr64)) == 0)
    {
        patchOffset = sizeof(kEndbr64);
    }

    std::size_t nearStolen{0};
    std::string nearStatus;
    if (!AnalyzePatchWindow(bytes, functionSize, patchOffset, kNearPatchBytes, nearStolen,
                            nearStatus)) {
        site.status = "skipped: " + nearStatus;
        return false;
    }
    if (HasDirectBranchIntoPatchWindow(bytes, functionSize, patchOffset, nearStolen,
                                       nearStatus)) {
        site.status = "skipped: " + nearStatus;
        return false;
    }

    std::size_t absoluteStolen{0};
    std::string absoluteStatus;
    if (AnalyzePatchWindow(bytes, functionSize, patchOffset, kAbsolutePatchBytes, absoluteStolen,
                           absoluteStatus)) {
        if (HasDirectBranchIntoPatchWindow(bytes, functionSize, patchOffset, absoluteStolen,
                                           absoluteStatus)) {
            site.absoluteStatus = absoluteStatus;
        }
        else
        {
            site.absolutePatchable = true;
            site.absoluteStolenLength = static_cast<std::uint32_t>(absoluteStolen);
        }
    }
    else
    {
        site.absoluteStatus = absoluteStatus;
    }

    site.patchOffset = static_cast<std::uint32_t>(patchOffset);
    site.nearStolenLength = static_cast<std::uint32_t>(nearStolen);
    site.stolenLength = site.nearStolenLength;
    const std::size_t copied{std::min(bytes.size() - patchOffset, site.stolen.size())};
    std::memcpy(site.stolen.data(), bytes.data() + patchOffset, copied);
    site.patchable = true;
    site.status = "planned";
    return true;
}

std::vector<PatchSite> BuildSites(HANDLE process,
                                  std::uint64_t remoteImageBase,
                                  const PeImageInfo& image,
                                  const std::vector<FunctionSymbol>& functions,
                                  bool verbose,
                                  std::string& error)
{
    {
        std::ostringstream line;
        line << "miri: building patch sites from " << functions.size() << " function symbols";
        LogStdout(verbose, line.str());
    }

    std::vector<PatchSite> sites;
    sites.reserve(functions.size());

    for (std::size_t index{0}; index < functions.size();)
    {
        const std::uint32_t rva{functions[index].rva};
        PatchSite site;
        site.rva = rva;
        site.remoteAddress = remoteImageBase + rva;

        do
        {
            site.symbols.push_back(functions[index]);
            ++index;
        } while (index < functions.size() && functions[index].rva == rva);

        sites.push_back(std::move(site));
    }

    {
        std::ostringstream line;
        line << "miri: grouped symbols into " << sites.size() << " unique patch sites";
        LogStdout(verbose, line.str());
    }

    LogStdout(verbose, "miri: reading executable sections for bulk analysis");
    const std::vector<RemoteSectionBytes> sections{ReadExecutableSections(process, remoteImageBase, image)};
    {
        std::size_t readableSections{0};
        std::size_t readableBytes{0};
        for (const auto& section : sections)
        {
            if (section.readable)
            {
                ++readableSections;
                readableBytes += section.bytes.size();
            }
        }

        std::ostringstream line;
        line << "miri: read " << readableSections << "/" << sections.size()
             << " executable sections (" << readableBytes << " bytes)";
        LogStdout(verbose, line.str());
    }

    LogStdout(verbose, "miri: analyzing patch windows");
    AnalyzeSites(process, sections, sites);
    LogStdout(verbose, "miri: finished analyzing patch windows");

    for (const auto& section : sections)
    {
        if (!section.readable)
        {
            error = section.error;
            break;
        }
    }

    return sites;
}

std::uint64_t AllocateNear(HANDLE process, std::uint64_t nearAddress, std::size_t size)
{
    SYSTEM_INFO systemInfo{};
    GetSystemInfo(&systemInfo);

    const std::uint64_t granularity{systemInfo.dwAllocationGranularity};
    const std::uint64_t alignedSize{AlignUp(size, systemInfo.dwPageSize)};
    const std::uint64_t minAddress{reinterpret_cast<std::uint64_t>(systemInfo.lpMinimumApplicationAddress)};
    const std::uint64_t maxAddress{reinterpret_cast<std::uint64_t>(systemInfo.lpMaximumApplicationAddress)};
    const std::uint64_t lower{nearAddress > kRel32Window ?
        std::max(minAddress, nearAddress - kRel32Window) :
        minAddress};
    const std::uint64_t upper{nearAddress > maxAddress - kRel32Window ?
        maxAddress :
        std::min(maxAddress, nearAddress + kRel32Window)};

    std::uint64_t address{lower};
    while (address < upper)
    {
        MEMORY_BASIC_INFORMATION info{};
        const SIZE_T queried{VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &info,
                                              sizeof(info))};
        if (queried == 0)
        {
            address = AlignUp(address + granularity, granularity);
            continue;
        }

        const std::uint64_t regionBase{reinterpret_cast<std::uint64_t>(info.BaseAddress)};
        const std::uint64_t regionEnd{regionBase + info.RegionSize};
        const std::uint64_t nextAddress{regionEnd > address ? regionEnd : address + granularity};

        if (info.State == MEM_FREE)
        {
            const std::uint64_t freeBegin{std::max(regionBase, lower)};
            const std::uint64_t freeEnd{std::min(regionEnd, upper)};
            std::uint64_t candidate{AlignUp(freeBegin, granularity)};
            while (candidate < freeEnd && alignedSize <= freeEnd - candidate)
        {
                if (FitsRel32(nearAddress + kNearPatchBytes, candidate))
                {
                    void* memory{VirtualAllocEx(process, reinterpret_cast<LPVOID>(candidate),
                                                  static_cast<SIZE_T>(alignedSize),
                                                  MEM_RESERVE | MEM_COMMIT,
                                                  PAGE_EXECUTE_READWRITE)};
                    if (memory != nullptr)
                    {
                        return reinterpret_cast<std::uint64_t>(memory);
                    }
                }

                candidate += granularity;
            }
        }

        address = nextAddress;
    }

    return 0;
}

std::uint64_t AllocateAnywhere(HANDLE process, std::size_t size)
{
    void* memory{VirtualAllocEx(process, nullptr, static_cast<SIZE_T>(size),
                                  MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    return reinterpret_cast<std::uint64_t>(memory);
}

bool AllocatePatchBlock(HANDLE process,
                        std::uint64_t nearAddress,
                        std::size_t requestedSites,
                        std::size_t pageSize,
                        bool requireNear,
                        PatchAllocation& allocation)
{
    for (std::size_t siteCapacity{requestedSites}; siteCapacity != 0;)
    {
        const std::size_t stubCapacity{static_cast<std::size_t>(AlignUp(siteCapacity * kStubStride, pageSize))};
        const std::size_t counterCapacity{static_cast<std::size_t>(
            AlignUp(siteCapacity * sizeof(std::uint64_t), pageSize))};
        const std::size_t allocationSize{stubCapacity + counterCapacity};

        const std::uint64_t base{requireNear ?
            AllocateNear(process, nearAddress, allocationSize) :
            AllocateAnywhere(process, allocationSize)};
        if (base != 0)
        {
            allocation.base = base;
            allocation.stubBase = base;
            allocation.stubCapacity = stubCapacity;
            allocation.counterBase = base + stubCapacity;
            allocation.counterCapacity = counterCapacity;
            allocation.siteCapacity = siteCapacity;
            return true;
        }

        if (siteCapacity == 1)
        {
            break;
        }
        siteCapacity /= 2;
    }

    allocation = {};
    return false;
}

bool BuildStub(const PatchSite& site, bool atomicCounters, std::vector<std::uint8_t>& stub,
               std::string& error)
{
    stub.clear();
    stub.reserve(kStubStride);

    AppendU8(stub, 0x9C); // pushfq

    const std::uint64_t incStart{site.stubAddress + stub.size()};
    const std::size_t incLength{atomicCounters ? 7u : 6u};
    const std::uint64_t incNext{incStart + incLength};
    if (!FitsRel32(incNext, site.counterAddress))
    {
        error = "counter is outside RIP-relative range";
        return false;
    }

    if (atomicCounters)
    {
        AppendU8(stub, 0xF0); // lock
    }
    AppendU8(stub, 0xFF);
    AppendU8(stub, 0x05); // inc qword ptr [rip + disp32]
    AppendI32(stub, Rel32(incNext, site.counterAddress));

    AppendU8(stub, 0x9D); // popfq

    stub.insert(stub.end(), site.stolen.begin(), site.stolen.begin() + site.stolenLength);

    const std::uint64_t jumpBackStart{site.stubAddress + stub.size()};
    const std::uint64_t jumpBackNext{jumpBackStart + kNearPatchBytes};
    const std::uint64_t jumpBackTarget{site.remoteAddress + site.patchOffset + site.stolenLength};
    if (FitsRel32(jumpBackNext, jumpBackTarget))
    {
        AppendU8(stub, 0xE9);
        AppendI32(stub, Rel32(jumpBackNext, jumpBackTarget));
    }
    else
    {
        AppendAbsoluteJump(stub, jumpBackTarget);
    }

    if (stub.size() > kStubStride)
    {
        error = "stub exceeded reserved stride";
        return false;
    }

    return true;
}

bool BuildEntryPatch(const PatchSite& site,
                     std::array<std::uint8_t, kMaxCopiedBytes>& patch,
                     std::size_t& patchSize,
                     std::string& error)
{
    patch.fill(0x90);
    patchSize = site.stolenLength;
    if (patchSize == 0 || patchSize > patch.size())
    {
        error = "invalid patch size";
        return false;
    }

    if (site.useAbsolutePatch)
    {
        if (site.stolenLength < kAbsolutePatchBytes)
        {
            error = "absolute patch window is too small";
            return false;
        }

        patch[0] = 0xFF;
        patch[1] = 0x25;
        const std::int32_t displacement{0};
        std::memcpy(patch.data() + 2, &displacement, sizeof(displacement));
        std::memcpy(patch.data() + 6, &site.stubAddress, sizeof(site.stubAddress));
    }
    else
    {
        if (site.stolenLength < kNearPatchBytes)
        {
            error = "near patch window is too small";
            return false;
        }

        const std::uint64_t patchAddress{site.remoteAddress + site.patchOffset};
        const std::uint64_t patchNext{patchAddress + kNearPatchBytes};
        if (!FitsRel32(patchNext, site.stubAddress))
        {
            error = "stub is outside entry-point rel32 range";
            return false;
        }

        patch[0] = 0xE9;
        const std::int32_t relative{Rel32(patchNext, site.stubAddress)};
        std::memcpy(patch.data() + 1, &relative, sizeof(relative));
    }

    return true;
}

bool PatchEntryPoint(HANDLE process, const PatchSite& site, std::string& error)
{
    std::array<std::uint8_t, kMaxCopiedBytes> patch{};
    std::size_t patchSize{0};
    if (!BuildEntryPatch(site, patch, patchSize, error))
    {
        return false;
    }

    const std::uint64_t patchAddress{site.remoteAddress + site.patchOffset};
    return WriteRemote(process, patchAddress, patch.data(), patchSize, error);
}

void MarkNearAllocationFallbackUnavailable(PatchSite& site)
{
    site.patchable = false;
    site.status =
        "skipped: failed to allocate nearby trampoline/counter memory; "
        "14-byte fallback unavailable";
    if (!site.absoluteStatus.empty())
    {
        site.status += ": " + site.absoluteStatus;
    }
}

void RestoreProtectedRegions(HANDLE process, const std::vector<ProtectedRegion>& regions);

bool ProtectExecutableSections(HANDLE process,
                               std::uint64_t remoteImageBase,
                               const PeImageInfo& image,
                               std::vector<ProtectedRegion>& regions,
                               std::string& error)
{
    regions.clear();
    for (const auto& section : image.sections)
    {
        if ((section.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
        {
            continue;
        }

        const std::uint32_t size{std::max(section.virtualSize, section.rawSize)};
        if (size == 0)
        {
            continue;
        }

        ProtectedRegion region;
        region.address = remoteImageBase + section.virtualAddress;
        region.size = size;
        if (!VirtualProtectEx(process, reinterpret_cast<LPVOID>(region.address), region.size,
                              PAGE_EXECUTE_READWRITE, &region.oldProtect)) {
            error = "VirtualProtectEx failed for executable section at " +
                    Hex64(region.address) + ": " + LastWin32ErrorMessage();
            RestoreProtectedRegions(process, regions);
            regions.clear();
            return false;
        }
        regions.push_back(region);
    }

    return true;
}

void RestoreProtectedRegions(HANDLE process, const std::vector<ProtectedRegion>& regions)
{
    for (auto it{regions.rbegin()}; it != regions.rend(); ++it)
    {
        DWORD ignored{0};
        VirtualProtectEx(process, reinterpret_cast<LPVOID>(it->address), it->size,
                         it->oldProtect, &ignored);
    }
}

void PatchEntryPointsQueued(HANDLE process, std::vector<PatchSite*>& sites, bool verbose)
{
    std::vector<PatchSite*> workSites;
    workSites.reserve(sites.size());

    std::uint64_t previousEnd{0};
    for (PatchSite* site : sites)
    {
        if (site == nullptr || !site->patchable)
        {
            continue;
        }

        const std::uint64_t patchBegin{site->remoteAddress + site->patchOffset};
        const std::uint64_t patchEnd{patchBegin + site->stolenLength};
        if (patchBegin < previousEnd)
        {
            site->patchable = false;
            site->status = "skipped: patch window overlaps previous patch";
            continue;
        }
        previousEnd = patchEnd;
        workSites.push_back(site);
    }

    const std::size_t taskCount{(workSites.size() + kHookPatchTaskSize - 1) / kHookPatchTaskSize};
    if (taskCount == 0)
    {
        LogStdout(verbose, "miri: patch queue empty; no hook tasks to run");
        return;
    }

    const std::size_t workerCount{WorkerCountFor(workSites.size(), kHookPatchTaskSize)};
    std::atomic<std::size_t> nextTask{0};
    std::mutex logMutex;

    auto logLine{[&](const std::string& line)
    {
        if (!verbose)
        {
            return;
        }
        std::lock_guard<std::mutex> lock(logMutex);
        std::cout << line << std::endl;
    }};

    {
        std::ostringstream line;
        line << "miri: patch queue has " << workSites.size() << " hooks in "
             << taskCount << " patch tasks of up to " << kHookPatchTaskSize
             << " hooks; starting " << workerCount << " workers";
        logLine(line.str());
    }

    auto runWorker{[&](std::size_t workerIndex)
    {
        std::size_t completedTasks{0};
        std::size_t attemptedHooks{0};
        std::size_t patchedHooks{0};
        std::size_t failedHooks{0};

        {
            std::ostringstream line;
            line << "miri: patch worker " << workerIndex
                 << " starting; queue has " << taskCount << " patch tasks";
            logLine(line.str());
        }

        for (;;)
        {
            const std::size_t task{nextTask.fetch_add(1, std::memory_order_relaxed)};
            if (task >= taskCount)
            {
                break;
            }

            const std::size_t begin{task * kHookPatchTaskSize};
            const std::size_t end{std::min(workSites.size(), begin + kHookPatchTaskSize)};
            {
                std::ostringstream line;
                line << "miri: patch worker " << workerIndex << " starting task "
                     << (task + 1) << "/" << taskCount << " with "
                     << (end - begin) << " hooks";
                logLine(line.str());
            }

            std::size_t taskPatched{0};
            std::size_t taskFailed{0};
            for (std::size_t index{begin}; index < end; ++index)
            {
                PatchSite& site{*workSites[index]};
                std::string patchError;
                if (!PatchEntryPoint(process, site, patchError))
                {
                    site.patchable = false;
                    site.status = "skipped: " + patchError;
                    ++taskFailed;
                    continue;
                }
                site.status = "patched";
                ++taskPatched;
            }

            ++completedTasks;
            attemptedHooks += end - begin;
            patchedHooks += taskPatched;
            failedHooks += taskFailed;

            {
                std::ostringstream line;
                line << "miri: patch worker " << workerIndex << " finished task "
                     << (task + 1) << "/" << taskCount << "; patched "
                     << taskPatched << ", failed " << taskFailed;
                logLine(line.str());
            }
        }

        {
            std::ostringstream line;
            line << "miri: patch worker " << workerIndex << " finished; completed "
                 << completedTasks << " tasks, attempted " << attemptedHooks
                 << " hooks, patched " << patchedHooks << ", failed " << failedHooks;
            logLine(line.str());
        }
    }};

    std::vector<std::future<void>> workers;
    workers.reserve(workerCount);
    for (std::size_t worker{0}; worker < workerCount; ++worker)
    {
        workers.push_back(std::async(std::launch::async, runWorker, worker));
    }

    for (auto& worker : workers)
    {
        worker.get();
    }

    LogStdout(verbose, "miri: patch queue finished");
}

void AddRecordsForSite(const PatchSite& site, InstrumentationResult& result)
{
    for (const auto& symbol : site.symbols)
    {
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
    result = {};

    const bool verbose{options.verbose};
    std::vector<std::uint64_t> stoppedInstructionPointers;
    if (!CollectStoppedInstructionPointers(process, stoppedInstructionPointers, error))
    {
        return false;
    }
    std::vector<PatchSite> sites{BuildSites(process, remoteImageBase, image, functions, verbose, error)};
    ExcludeActivePatchSites(sites, stoppedInstructionPointers);
    LogStdout(verbose, "miri: collecting patchable sites");
    std::vector<PatchSite*> patchable;
    patchable.reserve(sites.size());

    for (auto& site : sites)
    {
        if (!site.patchable)
        {
            continue;
        }
        if (options.maxFunctions != 0 && patchable.size() >= options.maxFunctions)
        {
            site.patchable = false;
            site.status = "skipped: maxFunctions reached";
            continue;
        }
        patchable.push_back(&site);
    }

    {
        std::ostringstream line;
        line << "miri: collected " << patchable.size() << " patchable sites";
        LogStdout(verbose, line.str());
    }

    if (!patchable.empty())
    {
        SYSTEM_INFO systemInfo{};
        GetSystemInfo(&systemInfo);
        const std::size_t pageSize{systemInfo.dwPageSize};
        result.counterCount = patchable.size();

        std::vector<ProtectedRegion> protectedRegions;
        LogStdout(verbose, "miri: making executable sections writable");
        if (!ProtectExecutableSections(process, remoteImageBase, image, protectedRegions, error))
        {
            return false;
        }

        {
            std::ostringstream line;
            line << "miri: made " << protectedRegions.size()
                 << " executable sections writable";
            LogStdout(verbose, line.str());
        }

        std::vector<PatchSite*> readyPatchSites;
        readyPatchSites.reserve(patchable.size());

        std::size_t nextSite{0};
        std::size_t nextCounterIndex{0};
        std::size_t allocationBlock{0};
        while (nextSite < patchable.size())
        {
            ++allocationBlock;
            const std::size_t blockStart{nextSite};
            const std::size_t remaining{patchable.size() - nextSite};
            const std::size_t requestedSites{std::min(remaining, kDefaultPatchSitesPerAllocation)};

            {
                std::ostringstream line;
                line << "miri: preparing allocation block " << allocationBlock
                     << " at patchable index " << nextSite << "; requesting "
                     << requestedSites << " sites, " << remaining << " remaining";
                LogStdout(verbose, line.str());
            }

            PatchAllocation allocation;
            bool useAbsolutePatch{false};
            std::vector<PatchSite*> blockSites;
            blockSites.reserve(requestedSites);

            if (AllocatePatchBlock(process, patchable[blockStart]->remoteAddress, requestedSites,
                                   pageSize, true, allocation)) {
                for (std::size_t index{0}; index < allocation.siteCapacity; ++index)
                {
                    blockSites.push_back(patchable[blockStart + index]);
                }
                nextSite += allocation.siteCapacity;
            }
            else
            {
                {
                    std::ostringstream line;
                    line << "miri: nearby allocation failed for block " << allocationBlock
                         << "; checking 14-byte fallback span";
                    LogStdout(verbose, line.str());
                }

                std::size_t skippedSites{0};
                for (std::size_t index{0}; index < requestedSites; ++index)
                {
                    PatchSite* site{patchable[blockStart + index]};
                    if (site->absolutePatchable)
                    {
                        blockSites.push_back(site);
                    } else
                    {
                        MarkNearAllocationFallbackUnavailable(*site);
                        ++skippedSites;
                    }
                }
                nextSite += requestedSites;

                if (skippedSites != 0)
                {
                    std::ostringstream line;
                    line << "miri: block " << allocationBlock << " skipping "
                         << skippedSites
                         << " sites without 14-byte fallback after near allocation failed";
                    LogStdout(verbose, line.str());
                }

                if (blockSites.empty())
                {
                    continue;
                }

                {
                    std::ostringstream line;
                    line << "miri: block " << allocationBlock << " can use absolute fallback for "
                         << blockSites.size() << " sparse sites";
                    LogStdout(verbose, line.str());
                }

                if (!AllocatePatchBlock(process, 0, blockSites.size(), pageSize, false, allocation))
                {
                    for (PatchSite* site : blockSites)
                    {
                        site->patchable = false;
                        site->status = "skipped: failed to allocate trampoline/counter memory";
                    }
                    continue;
                }
                useAbsolutePatch = true;

                if (allocation.siteCapacity < blockSites.size())
                {
                    for (std::size_t index{allocation.siteCapacity}; index < blockSites.size();
                         ++index)
                    {
                        blockSites[index]->patchable = false;
                        blockSites[index]->status =
                            "skipped: failed to allocate enough trampoline/counter memory";
                    }
                    blockSites.resize(allocation.siteCapacity);
                }
            }

            if (blockSites.empty())
            {
                continue;
            }

            const std::size_t blockSiteCount{blockSites.size()};
            {
                std::ostringstream line;
                line << "miri: allocation block " << allocationBlock << " reserved "
                     << blockSiteCount << " sites using "
                     << (useAbsolutePatch ? "absolute" : "near") << " patch stubs";
                if (allocation.siteCapacity != blockSiteCount)
                {
                    line << " (" << allocation.siteCapacity << " capacity)";
                }
                LogStdout(verbose, line.str());
            }

            if (result.stubBase == 0)
            {
                result.stubBase = allocation.stubBase;
            }
            if (result.counterBase == 0)
            {
                result.counterBase = allocation.counterBase;
            }
            result.stubBytes += allocation.stubCapacity;
            result.counterBytes += blockSiteCount * sizeof(std::uint64_t);
            result.counterBlocks.push_back(
                {allocation.counterBase, nextCounterIndex, blockSiteCount});

            {
                std::ostringstream line;
                line << "miri: building stubs for allocation block " << allocationBlock;
                LogStdout(verbose, line.str());
            }

            std::vector<std::uint8_t> stubBytes(blockSiteCount * kStubStride, 0);
            for (std::size_t index{0}; index < blockSiteCount; ++index)
            {
                PatchSite& site{*blockSites[index]};
                site.stubAddress = allocation.stubBase + index * kStubStride;
                site.counterAddress = allocation.counterBase + index * sizeof(std::uint64_t);
                site.counterIndex = static_cast<std::uint32_t>(nextCounterIndex + index);
                site.useAbsolutePatch = useAbsolutePatch;
                site.stolenLength =
                    useAbsolutePatch ? site.absoluteStolenLength : site.nearStolenLength;

                const std::uint64_t patchAddress{site.remoteAddress + site.patchOffset};
                if (!site.useAbsolutePatch &&
                    !FitsRel32(patchAddress + kNearPatchBytes, site.stubAddress)) {
                    if (!site.absolutePatchable)
                    {
                        site.patchable = false;
                        site.status =
                            "skipped: nearby trampoline is outside rel32 range; "
                            "14-byte fallback unavailable";
                        if (!site.absoluteStatus.empty())
                        {
                            site.status += ": " + site.absoluteStatus;
                        }
                        continue;
                    }

                    site.useAbsolutePatch = true;
                    site.stolenLength = site.absoluteStolenLength;
                }

                std::vector<std::uint8_t> stub;
                std::string stubError;
                if (!BuildStub(site, options.atomicCounters, stub, stubError))
                {
                    site.patchable = false;
                    site.status = "skipped: " + stubError;
                    continue;
                }

                std::memcpy(stubBytes.data() + index * kStubStride, stub.data(), stub.size());
            }

            std::string writeError;
            {
                std::ostringstream line;
                line << "miri: writing stub block " << allocationBlock << " ("
                     << stubBytes.size() << " bytes)";
                LogStdout(verbose, line.str());
            }
            if (!WriteRemote(process, allocation.stubBase, stubBytes.data(), stubBytes.size(),
                             writeError))
            {
                for (PatchSite* site : blockSites)
                {
                    if (site->patchable)
                    {
                        site->patchable = false;
                        site->status = "skipped: " + writeError;
                    }
                }
                nextCounterIndex += blockSiteCount;
                continue;
            }

            DWORD oldProtect{0};
            {
                std::ostringstream line;
                line << "miri: finalizing trampoline/counter protections for block "
                     << allocationBlock;
                LogStdout(verbose, line.str());
            }
            if (!VirtualProtectEx(process, reinterpret_cast<LPVOID>(allocation.stubBase),
                                  allocation.stubCapacity, PAGE_EXECUTE_READ, &oldProtect)) {
                error = "failed to protect trampoline pages: " + LastWin32ErrorMessage();
                RestoreProtectedRegions(process, protectedRegions);
                return false;
            }
            if (!VirtualProtectEx(process, reinterpret_cast<LPVOID>(allocation.counterBase),
                                  allocation.counterCapacity, PAGE_READWRITE, &oldProtect)) {
                error = "failed to protect counter pages: " + LastWin32ErrorMessage();
                RestoreProtectedRegions(process, protectedRegions);
                return false;
            }

            for (PatchSite* site : blockSites)
            {
                if (site->patchable)
                {
                    readyPatchSites.push_back(site);
                }
            }
            {
                std::ostringstream line;
                line << "miri: allocation block " << allocationBlock
                     << " ready; total queued hooks so far " << readyPatchSites.size();
                LogStdout(verbose, line.str());
            }
            nextCounterIndex += blockSiteCount;
        }

        {
            std::ostringstream line;
            line << "miri: finished preparing " << readyPatchSites.size()
                 << " hooks for patch queue";
            LogStdout(verbose, line.str());
        }
        PatchEntryPointsQueued(process, readyPatchSites, verbose);
        LogStdout(verbose, "miri: flushing instruction cache");
        FlushInstructionCache(process, reinterpret_cast<LPCVOID>(remoteImageBase),
                              image.sizeOfImage);
        LogStdout(verbose, "miri: restoring executable section protections");
        RestoreProtectedRegions(process, protectedRegions);
    }

    for (const auto& site : sites)
    {
        AddRecordsForSite(site, result);
    }

    std::sort(result.records.begin(), result.records.end(),
              [](const PatchResult& left, const PatchResult& right) {
                  if (left.function.rva != right.function.rva)
                    {
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
    if (instrumentation.counterCount == 0)
    {
        return true;
    }

    for (const auto& block : instrumentation.counterBlocks)
    {
        if (block.counterCount == 0)
        {
            continue;
        }
        if (block.counterIndex > counters.size() ||
            block.counterCount > counters.size() - block.counterIndex) {
            error = "counter block exceeds instrumentation counter table";
            return false;
        }

        if (!ReadRemote(process, block.remoteAddress, counters.data() + block.counterIndex,
                        block.counterCount * sizeof(std::uint64_t), error)) {
            return false;
        }
    }

    return true;
}

} // namespace miri
