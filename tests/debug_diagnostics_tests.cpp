// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Rennie Allen
#define wmain MiriRunMain
#include "../src/miri_run/main.cpp"
#undef wmain

#include <stdexcept>

namespace
{
void RequireDiagnostic(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

DWORD WINAPI StackWorker(void* ready)
{
    SetEvent(static_cast<HANDLE>(ready));
    Sleep(30000);
    return 0;
}

void TestFaultDetails()
{
    std::array<BYTE, 96> entry{};
    std::array<BYTE, 96> stub{};
    entry[6] = 0x48;
    entry[7] = 0x8B;
    stub[0] = 0x9C;
    CONTEXT context{};
    context.Rip = reinterpret_cast<DWORD64>(entry.data() + 6);
    context.Rcx = 0xFFFFFFFFFFFFFFFFull;
    miri::InstrumentationResult instrumentation;
    miri::PatchResult record;
    record.remoteAddress = reinterpret_cast<std::uint64_t>(entry.data());
    record.stubAddress = reinterpret_cast<std::uint64_t>(stub.data());
    record.function.name = L"SyntheticScheduleCall";
    record.patched = true;
    record.status = "patched";
    record.stolenLength = 6;
    instrumentation.records.push_back(record);
    const auto details{CaptureFaultDetails(GetCurrentProcess(), context, context.Rip,
                                           instrumentation)};
    std::string text;
    for (const auto& line : details) text += line + '\n';
    RequireDiagnostic(text.find("RCX=" + miri::Hex64(context.Rcx)) != std::string::npos,
                      "fault register value missing");
    RequireDiagnostic(text.find(": 48 8B") != std::string::npos,
                      "fault instruction bytes missing");
    RequireDiagnostic(text.find("SyntheticScheduleCall") != std::string::npos &&
                      text.find("stolen bytes=6") != std::string::npos,
                      "matching patch metadata missing");
    RequireDiagnostic(text.find("trampoline bytes at " + miri::Hex64(record.stubAddress) +
                                ": 9C") != std::string::npos,
                      "trampoline bytes missing");
    instrumentation.records.clear();
    const auto withoutSite{CaptureFaultDetails(GetCurrentProcess(), context, context.Rip,
                                               instrumentation)};
    RequireDiagnostic(withoutSite.size() == 7, "missing patch table lost fault details");
    RequireDiagnostic(CaptureCodeBytes(GetCurrentProcess(), 0, 32, "invalid")
                          .find("unavailable") != std::string::npos,
                      "unreadable code was not reported");
}
}

int main()
{
    try
    {
        TestFaultDetails();
        StackPrinter printer;
        ExceptionHistory history;
        DEBUG_EVENT event{};
        event.dwProcessId = 1;
        event.dwThreadId = 10;
        event.u.Exception.dwFirstChance = 1;
        event.u.Exception.ExceptionRecord.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
        RememberExceptionSnapshot(event, nullptr, printer, history);
        event.dwThreadId = 20;
        event.u.Exception.ExceptionRecord.ExceptionCode = 0x406D1388;
        RememberExceptionSnapshot(event, nullptr, printer, history);
        RequireDiagnostic(history.latest.threadId == 10,
                          "thread naming replaced the fault snapshot");
        event.u.Exception.ExceptionRecord.ExceptionCode = EXCEPTION_INT_DIVIDE_BY_ZERO;
        RememberExceptionSnapshot(event, nullptr, printer, history);
        RequireDiagnostic(history.ForThread(10).code == EXCEPTION_ACCESS_VIOLATION,
                          "another thread replaced the terminating thread's exception");
        RequireDiagnostic(history.ForThread(30).threadId == 20,
                          "missing thread did not fall back to the latest exception");
        event.u.Exception.dwFirstChance = 0;
        event.u.Exception.ExceptionRecord.ExceptionCode = 0x406D1388;
        RememberExceptionSnapshot(event, nullptr, printer, history);
        RequireDiagnostic(history.latest.code == 0x406D1388,
                          "second-chance thread naming exception was discarded");

        wchar_t path[MAX_PATH]{};
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        std::string error;
        RequireDiagnostic(printer.Initialize(GetCurrentProcess(), path, path, error),
                          error.c_str());
        OwnedHandle ready(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        OwnedHandle worker(CreateThread(nullptr, 0, StackWorker, ready.Get(), 0, nullptr));
        RequireDiagnostic(worker.IsValid(), "CreateThread failed");
        WaitForSingleObject(ready.Get(), INFINITE);
        RequireDiagnostic(SuspendThread(worker.Get()) != static_cast<DWORD>(-1),
                          "SuspendThread failed");
        const auto stack{printer.CaptureStack(worker.Get())};
        ResumeThread(worker.Get());
        for (const auto& line : stack.lines) std::cout << line << '\n';
        RequireDiagnostic(stack.valid && stack.lines.size() > 2,
                          "stack walk stopped before reaching callers");
        std::cout << "diagnostic regression tests passed\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
