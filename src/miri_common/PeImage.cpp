#include "miri_common/PeImage.h"

#include "miri_common/StringUtil.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <sstream>
#include <vector>

#include <windows.h>

namespace miri
{
namespace
{

template <typename T>
const T* ReadStruct(const std::vector<std::uint8_t>& bytes, std::size_t offset)
{
    if (offset > bytes.size() || sizeof(T) > bytes.size() - offset)
{
        return nullptr;
    }
    return reinterpret_cast<const T*>(bytes.data() + offset);
}

std::string SectionName(const IMAGE_SECTION_HEADER& section)
{
    char name[9] = {};
    std::memcpy(name, section.Name, 8);
    return name;
}

} // namespace

bool PeImageInfo::IsExecutableRva(std::uint32_t rva) const
{
    for (const auto& section : sections)
{
        const std::uint32_t size = std::max(section.virtualSize, section.rawSize);
        if (size == 0)
{
            continue;
        }

        const std::uint64_t begin = section.virtualAddress;
        const std::uint64_t end = begin + size;
        if (rva >= begin && rva < end &&
            (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
            return true;
        }
    }
    return false;
}

bool LoadPeImageInfo(const std::filesystem::path& imagePath, PeImageInfo& info, std::string& error)
{
    std::ifstream file(imagePath, std::ios::binary);
    if (!file)
{
        error = "failed to open image: " + WideToUtf8(imagePath.wstring());
        return false;
    }

    std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(file)),
                                    std::istreambuf_iterator<char>());
    if (bytes.size() < sizeof(IMAGE_DOS_HEADER))
{
        error = "image is too small to be a PE file";
        return false;
    }

    const auto* dos = ReadStruct<IMAGE_DOS_HEADER>(bytes, 0);
    if (dos == nullptr || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0)
{
        error = "image does not have a valid DOS header";
        return false;
    }

    const std::size_t ntOffset = static_cast<std::size_t>(dos->e_lfanew);
    const auto* signature = ReadStruct<DWORD>(bytes, ntOffset);
    if (signature == nullptr || *signature != IMAGE_NT_SIGNATURE)
{
        error = "image does not have a valid NT header";
        return false;
    }

    const auto* fileHeader =
        ReadStruct<IMAGE_FILE_HEADER>(bytes, ntOffset + sizeof(DWORD));
    if (fileHeader == nullptr)
{
        error = "image NT file header is truncated";
        return false;
    }

    const std::size_t optionalOffset = ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    const auto* magic = ReadStruct<WORD>(bytes, optionalOffset);
    if (magic == nullptr)
{
        error = "image optional header is truncated";
        return false;
    }

    PeImageInfo parsed;
    parsed.machine = fileHeader->Machine;

    if (*magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
{
        const auto* optional = ReadStruct<IMAGE_OPTIONAL_HEADER64>(bytes, optionalOffset);
        if (optional == nullptr)
{
            error = "image PE32+ optional header is truncated";
            return false;
        }
        parsed.is64 = true;
        parsed.imageBase = optional->ImageBase;
        parsed.sizeOfImage = optional->SizeOfImage;
    } else if (*magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
{
        const auto* optional = ReadStruct<IMAGE_OPTIONAL_HEADER32>(bytes, optionalOffset);
        if (optional == nullptr)
{
            error = "image PE32 optional header is truncated";
            return false;
        }
        parsed.is64 = false;
        parsed.imageBase = optional->ImageBase;
        parsed.sizeOfImage = optional->SizeOfImage;
    } else
{
        error = "image optional header has an unknown magic";
        return false;
    }

    const std::size_t sectionOffset = optionalOffset + fileHeader->SizeOfOptionalHeader;
    for (WORD i = 0; i < fileHeader->NumberOfSections; ++i)
{
        const auto* section = ReadStruct<IMAGE_SECTION_HEADER>(
            bytes, sectionOffset + static_cast<std::size_t>(i) * sizeof(IMAGE_SECTION_HEADER));
        if (section == nullptr)
{
            error = "image section table is truncated";
            return false;
        }

        PeSection parsedSection;
        parsedSection.name = SectionName(*section);
        parsedSection.virtualAddress = section->VirtualAddress;
        parsedSection.virtualSize = section->Misc.VirtualSize;
        parsedSection.rawSize = section->SizeOfRawData;
        parsedSection.characteristics = section->Characteristics;
        parsed.sections.push_back(parsedSection);
    }

    info = std::move(parsed);
    return true;
}

} // namespace miri
