// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Rennie Allen

// Exercise the actual private decoder and emitter without adding a public API.
#include "../src/miri_common/RemotePatch.cpp"

#include <stdexcept>

namespace
{

void Require(bool condition, const std::string& message)
{
    if (!condition)
    {
        throw std::runtime_error(message);
    }
}

void TestImmediateInstructions()
{
    struct TestCase
    {
        const char* name;
        std::vector<std::uint8_t> bytes;
    };
    const TestCase cases[]{
        {"shufps", {0x0F, 0xC6, 0xC0, 0x1B}},
        {"shufpd", {0x66, 0x0F, 0xC6, 0xC0, 0x01}},
        {"cmpps", {0x0F, 0xC2, 0xC1, 0x00}},
        {"cmppd", {0x66, 0x0F, 0xC2, 0xC1, 0x01}},
        {"cmpss", {0xF3, 0x0F, 0xC2, 0xC1, 0x02}},
        {"cmpsd", {0xF2, 0x0F, 0xC2, 0xC1, 0x03}},
        {"pinsrw mmx", {0x0F, 0xC4, 0xC0, 0x02}},
        {"pinsrw xmm", {0x66, 0x0F, 0xC4, 0xC0, 0x02}},
        {"pextrw mmx", {0x0F, 0xC5, 0xC0, 0x02}},
        {"pextrw xmm", {0x66, 0x0F, 0xC5, 0xC0, 0x02}},
        {"shufps disp8", {0x0F, 0xC6, 0x41, 0x10, 0x1B}},
        {"shufps SIB disp32", {0x0F, 0xC6, 0x84, 0x91, 0x10, 0, 0, 0, 0x1B}},
        {"shufps extended register", {0x45, 0x0F, 0xC6, 0xC1, 0x1B}},
        {"pshufd existing imm8", {0x66, 0x0F, 0x70, 0xC1, 0x1B}}
    };
    for (const auto& test : cases)
    {
        const auto decoded{miri::DecodeX64Instruction(test.bytes.data(), test.bytes.size())};
        Require(!decoded.invalid && decoded.length == test.bytes.size(),
                std::string(test.name) + " decoded length " + std::to_string(decoded.length) +
                    ", expected " + std::to_string(test.bytes.size()));
        const auto truncated{miri::DecodeX64Instruction(test.bytes.data(), test.bytes.size() - 1)};
        Require(truncated.invalid, std::string(test.name) + " accepted a missing immediate");
    }
}

void TestPatchBoundaries()
{
    for (const std::size_t required : {miri::kNearPatchBytes, miri::kAbsolutePatchBytes})
    {
        std::array<std::uint8_t, miri::kMaxAnalyzeBytes> bytes;
        bytes.fill(0x90);
        // The immediate is just beyond the requested patch window. It must be copied too.
        const auto offset{required - 3};
        bytes[offset] = 0x0F;
        bytes[offset + 1] = 0xC6;
        bytes[offset + 2] = 0xC0;
        bytes[offset + 3] = 0x1B;
        std::size_t stolen{0};
        std::string error;
        Require(miri::AnalyzePatchWindow(bytes, 64, 0, required, stolen, error), error);
        Require(stolen == required + 1, "patch splits SHUFPS before its immediate");
        Require(!miri::AnalyzePatchWindow(bytes, static_cast<std::uint32_t>(required),
                                         0, required, stolen, error),
                "patch accepted a function ending inside SHUFPS");
    }

    const std::uint8_t ripRelative[]{0x0F, 0xC6, 0x05, 0, 0, 0, 0, 0x1B};
    const auto decoded{miri::DecodeX64Instruction(ripRelative, sizeof(ripRelative))};
    Require(!decoded.invalid && decoded.ripRelative && decoded.length == sizeof(ripRelative),
            "RIP-relative SHUFPS must remain identifiable for rejection");
}

void TestAbsoluteJumpBack()
{
    miri::PatchSite site;
    site.remoteAddress = 0x7FF6C8370000;
    site.stubAddress = 0x7FF644324300;
    site.counterAddress = site.stubAddress + 4096;
    site.stolenLength = 15;
    site.stolen.fill(0x90);
    std::vector<std::uint8_t> stub;
    std::string error;
    Require(miri::BuildStub(site, false, stub, error), error);
    const auto jumpOffset{8 + site.stolenLength};
    Require(stub.size() == jumpOffset + 14 && stub[jumpOffset] == 0xFF &&
                stub[jumpOffset + 1] == 0x25, "far jump-back must use an absolute jump");
    std::uint64_t destination{0};
    std::memcpy(&destination, stub.data() + jumpOffset + 6, sizeof(destination));
    Require(destination == site.remoteAddress + site.stolenLength,
            "absolute jump-back destination changed");
}

void TestStoppedThreadPatchWindows()
{
    // ScheduleCall prologue from the reported attach crash. +6 is push rdi in
    // the original code, and the first address byte in a 14-byte absolute jump.
    const std::uint8_t prologue[]{
        0x48, 0x89, 0x5C, 0x24, 0x18, // mov [rsp+18h], rbx
        0x55, 0x57,                   // push rbp; push rdi
        0x41, 0x54, 0x41, 0x55, 0x41, 0x57, // push r12; r13; r15
        0x48, 0x83, 0xEC, 0x40        // sub rsp, 40h
    };
    std::array<std::uint8_t, miri::kMaxAnalyzeBytes> bytes{};
    std::copy(std::begin(prologue), std::end(prologue), bytes.begin());
    miri::PatchSite original;
    original.remoteAddress = 0x145759BA0;
    Require(miri::AnalyzePatchSite(bytes, sizeof(prologue), original),
            "ScheduleCall prologue was rejected");
    Require(original.nearStolenLength == 5 && original.absoluteStolenLength == 17,
            "ScheduleCall patch spans changed");
    for (const auto offset : {1u, 5u, 6u, 7u, 13u, 16u})
    {
        std::vector<miri::PatchSite> sites{original};
        miri::ExcludeActivePatchSites(sites, {original.remoteAddress + offset});
        Require(!sites[0].patchable && sites[0].status.find("stopped thread") != std::string::npos,
                "stopped RIP inside absolute fallback window was allowed");
    }
    for (const auto offset : {0u, 17u, 18u})
    {
        std::vector<miri::PatchSite> sites{original};
        miri::ExcludeActivePatchSites(sites, {original.remoteAddress + offset});
        Require(sites[0].patchable, "safe patch boundary was rejected");
    }
    std::vector<miri::PatchSite> sites{original};
    miri::ExcludeActivePatchSites(sites,
        {original.remoteAddress - 100, original.remoteAddress, original.remoteAddress + 6});
    Require(!sites[0].patchable, "another thread at entry hid the interior RIP");
    sites = {original};
    sites[0].patchOffset = 4; // ENDBR64 is preserved ahead of a patch.
    miri::ExcludeActivePatchSites(sites, {original.remoteAddress + 3});
    Require(sites[0].patchable, "preserved entry bytes were treated as overwritten");
    miri::ExcludeActivePatchSites(sites, {original.remoteAddress + 10});
    Require(!sites[0].patchable, "patchOffset was omitted from stopped RIP check");
}

void TestExecutedTrampoline(bool absolute, bool atomic)
{
    // Own all executable memory in this test process; never attach to another process.
    auto* memory{static_cast<std::uint8_t*>(VirtualAlloc(
        nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))};
    Require(memory != nullptr, "could not allocate test code");
    struct Allocation
    {
        void* address;
        ~Allocation() { VirtualFree(address, 0, MEM_RELEASE); }
    } allocation{memory};

    std::array<std::uint8_t, miri::kMaxAnalyzeBytes> bytes;
    bytes.fill(0x90);
    bytes[0] = 0x0F; bytes[1] = 0x10; bytes[2] = 0x01; // movups xmm0, [rcx]
    const std::size_t shuffleOffset{absolute ? 11u : 3u};
    const std::uint8_t tail[]{
        0x0F, 0xC6, 0xC0, 0x1B, // shufps xmm0, xmm0, 0x1b: reverse lanes
        0x0F, 0x11, 0x02,       // movups [rdx], xmm0
        0xC3                    // ret
    };
    std::copy(std::begin(tail), std::end(tail), bytes.begin() + shuffleOffset);
    std::memcpy(memory, bytes.data(), bytes.size());

    miri::PatchSite site;
    site.remoteAddress = reinterpret_cast<std::uint64_t>(memory);
    site.stubAddress = site.remoteAddress + 256;
    site.counterAddress = site.remoteAddress + 512;
    Require(miri::AnalyzePatchSite(bytes, static_cast<std::uint32_t>(shuffleOffset + sizeof(tail)),
                                  site), "test function was rejected");
    Require(!absolute || site.absolutePatchable, "absolute patch was rejected");
    site.useAbsolutePatch = absolute;
    site.stolenLength = absolute ? site.absoluteStolenLength : site.nearStolenLength;
    Require(site.stolenLength == shuffleOffset + 4, "execution would split SHUFPS");

    std::vector<std::uint8_t> stub;
    std::string error;
    Require(miri::BuildStub(site, atomic, stub, error), error);
    std::memcpy(memory + 256, stub.data(), stub.size());
    std::array<std::uint8_t, miri::kMaxCopiedBytes> patch;
    std::size_t patchSize{0};
    Require(miri::BuildEntryPatch(site, patch, patchSize, error), error);
    std::memcpy(memory, patch.data(), patchSize);
    FlushInstructionCache(GetCurrentProcess(), memory, 4096);

    using Function = void (*)(const float*, float*);
    const auto function{reinterpret_cast<Function>(memory)};
    const float input[]{1, 2, 3, 4};
    float output[4]{};
    for (int call{0}; call < 3; ++call)
    {
        function(input, output);
        for (int lane{0}; lane < 4; ++lane)
        {
            Require(output[lane] == input[3 - lane], "trampoline changed SIMD results");
        }
    }
    Require(*reinterpret_cast<std::uint64_t*>(memory + 512) == 3,
            "trampoline did not count each call");
}

} // namespace

int main()
{
    try
    {
        TestImmediateInstructions();
        TestPatchBoundaries();
        TestAbsoluteJumpBack();
        TestStoppedThreadPatchWindows();
        for (bool absolute : {false, true})
        {
            for (bool atomic : {false, true})
            {
                TestExecutedTrampoline(absolute, atomic);
            }
        }
        std::cout << "All decoder, patch-boundary, and executable trampoline tests passed.\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
