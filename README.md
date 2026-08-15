# miri

`miri` is a Windows x64 runtime instrumentation profiler prototype. It launches a target executable under the Windows debugger API, reads function symbols from the matching PDB with DbgHelp, patches safe function entry points with a near jump to injected counter stubs, and collects the counter table before the debuggee is allowed to finish exiting.

## Build

```powershell
premake5 vs2022
& 'E:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe' `
  E:\miri-build\projects\miri.sln /p:Configuration=Release /p:Platform=x64 /m
```

By default, `premake5.lua` writes generated Visual Studio files and compiler output to `E:\miri-build` to avoid filling the source drive. Set `MIRI_BUILD_ROOT` before running Premake to choose a different build volume.

The workspace builds two tools:

- `miri-run.exe`: launcher, instrumenter, and report collector.
- `miri-hist.exe`: CSV histogram viewer with optional HTML output.

## Usage

```powershell
E:\miri-build\bin\Release\miri-run.exe C:\path\app.exe C:\path\app.pdb
E:\miri-build\bin\Release\miri-run.exe --pid 1234 C:\path\app.pdb
E:\miri-build\bin\Release\miri-hist.exe C:\path\app.exe.miri.csv --top 50 --html E:\miri-build\histogram.html
```

`miri-run` accepts an optional JSON configuration file. If it is omitted, the launcher looks for `<exe>.miri.json` and then `<exe-stem>.miri.json`.

To instrument a process that is already running, pass `--pid <pid>` or `--attach <pid>`. The executable path is read from the process, and the PDB defaults to `<exe-stem>.pdb` when omitted:

```powershell
E:\miri-build\bin\Release\miri-run.exe --pid 1234
E:\miri-build\bin\Release\miri-run.exe --pid 1234 C:\symbols\app.pdb C:\work\app.miri.json
```

Attach mode keeps `miri-run` attached as the debugger until the target exits, then reads the counters and writes the CSV report.

Example:

```json
{
  "arguments": ["--input", "scene.json"],
  "workingDirectory": "C:\\work\\app",
  "outputPath": "C:\\work\\app\\miri-report.csv",
  "include": [".*"],
  "exclude": ["^std::", "^__"],
  "atomicCounters": false,
  "maxFunctions": 0
}
```

`arguments` is the preferred form because each item is quoted correctly for the target process. `argumentsRaw` is also supported when a target needs an exact command line tail.

## Report

The CSV report contains one row per PDB function symbol:

```text
symbol,rva,remote_address,counter_index,count,status,stolen_bytes
```

Rows with `status=patched` were instrumented. Rows with a `skipped:` status were left untouched and explain why.

## Runtime Design

The launcher creates the target suspended with `DEBUG_ONLY_THIS_PROCESS`, waits for the initial `CREATE_PROCESS_DEBUG_EVENT`, and patches the main executable before the initial thread is resumed. Each patched entry point receives a five-byte `jmp rel32` to a nearby trampoline. The trampoline increments that function's counter, executes the copied entry instructions, and jumps back to the original function body.

The counter/stub block is allocated inside the target with `VirtualAllocEx` near the image base so both the entry jump and the RIP-relative counter increment stay within x64 `rel32` range. After stubs are written, stub pages are set executable/read-only and counter pages are left read/write.

When `EXIT_PROCESS_DEBUG_EVENT` arrives, Windows has suspended the debuggee for the debugger. `miri-run` reads the counter table at that point, writes the CSV, then calls `ContinueDebugEvent` so the process can finish unloading.

## Current Limits

This first implementation is intentionally conservative:

- Windows x64 targets only.
- Main executable instrumentation only; DLL instrumentation can be added by handling `LOAD_DLL_DEBUG_EVENT`.
- Function entries with RIP-relative instructions, relative control flow, unsupported opcodes, or too-short bodies in the patch window are skipped.
- Non-atomic counters are the default for speed. Set `"atomicCounters": true` for exact increments across threads at higher cost.
- PDB enumeration uses DbgHelp, so the target PDB must match the executable and be discoverable through the supplied path.
