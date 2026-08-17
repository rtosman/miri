#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace miri
{

struct PeSection
{
    std::string name;
    std::uint32_t virtualAddress{0};
    std::uint32_t virtualSize{0};
    std::uint32_t rawSize{0};
    std::uint32_t characteristics{0};
};

struct PeImageInfo
{
    bool is64{false};
    std::uint16_t machine{0};
    std::uint64_t imageBase{0};
    std::uint32_t sizeOfImage{0};
    std::vector<PeSection> sections;

    bool IsExecutableRva(std::uint32_t rva) const;
};

bool LoadPeImageInfo(const std::filesystem::path& imagePath, PeImageInfo& info, std::string& error);

} // namespace miri
