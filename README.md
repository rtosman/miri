# miri user guide

`miri` is a Windows x64 runtime instrumentation profiler. It uses the Windows
debugger API to run or attach to a target process, reads function symbols from a
matching PDB, patches safe function entry points, counts calls, and writes a CSV
report when the target exits.

The repo builds two command line tools:

- `miri-run.exe`: instruments a target and writes the CSV report.
- `miri-hist.exe`: reads a `miri-run` CSV report and prints a histogram, with
  optional HTML output.

## Requirements

- Windows x64 target executable.
- Matching PDB for the target executable.
- Permission to debug the target process.
- No other invasive debugger attached to the target. Windows allows only one
  invasive debugger at a time.

`miri-run` currently instruments the main executable image, not every loaded DLL.

## Build

By default, generated Visual Studio projects and build output go under
`E:\miri-build`.

```powershell
premake5 --file=E:\Users\Rennie Allen\source\repos\miri\premake5.lua vs2022
& 'E:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe' `
  E:\miri-build\projects\miri.sln /p:Configuration=Release /p:Platform=x64 /m
```

Set `MIRI_BUILD_ROOT` before running Premake to choose a different build
directory.

If the DIA SDK is found, the build enables extra decorated-symbol lookup for
`--mangled`. You can point Premake at a specific DIA SDK with
`MIRI_DIA_SDK_DIR`.

## miri-run

### Launch a target

```powershell
E:\miri-build\bin\Release\miri-run.exe [--verbose] [--mangled] <target.exe> <target.pdb> [config.json]
```

Example:

```powershell
E:\miri-build\bin\Release\miri-run.exe `
  C:\games\Example\Game.exe `
  C:\games\Example\Game.pdb `
  C:\work\game.miri.json
```

`miri-run` launches the target under the debugger, instruments safe function
entry points before the initial thread runs, waits for process exit, reads the
counters, and writes the report.

### Attach to a running target

```powershell
E:\miri-build\bin\Release\miri-run.exe [--verbose] [--mangled] --pid <pid> [target.pdb] [config.json]
E:\miri-build\bin\Release\miri-run.exe [--verbose] [--mangled] --attach <pid> [target.pdb] [config.json]
```

`--pid` and `--attach` are synonyms. In attach mode, `miri-run` queries the
target executable path from the process. If the PDB path is omitted, it uses
`<target-exe-stem>.pdb` next to the executable.

If you pass one optional argument after the PID and it ends in `.json`,
`miri-run` treats it as the config file. Otherwise it treats it as the PDB path.

Examples:

```powershell
E:\miri-build\bin\Release\miri-run.exe --pid 1234
E:\miri-build\bin\Release\miri-run.exe --pid 1234 C:\symbols\Game.pdb
E:\miri-build\bin\Release\miri-run.exe --pid 1234 C:\symbols\Game.pdb C:\work\game.miri.json
E:\miri-build\bin\Release\miri-run.exe --pid 1234 C:\work\game.miri.json
```

`miri-run` remains attached as the debugger until the target exits. During that
time, tools such as WinDbg cannot also attach invasively.

### Command line switches

| Switch | Meaning |
| --- | --- |
| `-v`, `--verbose` | Print detailed patching progress and diagnostics. |
| `--mangled` | Add a `mangled` column after `symbol` in the CSV report. |
| `--pid <pid>` | Attach to a running process by process ID. |
| `--attach <pid>` | Same as `--pid <pid>`. |

The `symbol` column is the friendly/demangled name used for filtering and
display. With `--mangled`, `miri-run` tries to recover decorated names from
public/linker symbols. Some PDB private function records do not contain a
decorated spelling; those rows fall back to the same value as `symbol`.

Use `--verbose --mangled` to see decorated-symbol coverage:

```text
mangled symbol lookup: dbghelp publics 149/245 decorated, DIA enabled/loaded, 149/245 decorated, matched 184, final decorated 129/294
```

## Configuration files

The config file is optional. If you do not pass one, `miri-run` looks next to the
target executable for:

1. `<target.exe>.miri.json`
2. `<target-stem>.miri.json`

For example, for `Game.exe`, the default config names are `Game.exe.miri.json`
and `Game.miri.json`.

Relative paths in `workingDirectory` and `outputPath` are resolved relative to
the config file directory.

Example:

```json
{
  "arguments": ["--level", "arena01", "--profile"],
  "workingDirectory": "C:\\games\\Example",
  "outputPath": "C:\\work\\game.miri.csv",
  "include": ["^Game::", "^BCEngine::"],
  "exclude": ["^std::", "^__"],
  "atomicCounters": false,
  "maxFunctions": 0
}
```

Supported keys:

| Key | Type | Meaning |
| --- | --- | --- |
| `arguments` | array of strings | Preferred target command line arguments. Each item is quoted safely. |
| `arguments` | string | Raw target command line tail. Supported for compatibility. |
| `argumentsRaw` | string | Exact target command line tail. Use only when array quoting is not suitable. |
| `workingDirectory` | string | Working directory for launched targets. Defaults to the target executable directory. |
| `outputPath` | string | CSV report path. Defaults to `<target.exe>.miri.csv`. |
| `include` | array of strings | ECMAScript regexes. If set, only matching friendly symbols are considered. |
| `exclude` | array of strings | ECMAScript regexes. Matching friendly symbols are excluded. |
| `atomicCounters` | bool | Use atomic increments. Slower, but safer for heavily multi-threaded hot paths. |
| `maxFunctions` | number | Maximum number of patchable sites to instrument. `0` means no limit. |

Filters apply to the friendly `symbol` name, not the `mangled` name.

## CSV report

Without `--mangled`, the report header is:

```text
symbol,rva,remote_address,counter_index,count,status,stolen_bytes
```

With `--mangled`, the report header is:

```text
symbol,mangled,rva,remote_address,counter_index,count,status,stolen_bytes
```

Column meanings:

| Column | Meaning |
| --- | --- |
| `symbol` | Friendly/demangled function name. |
| `mangled` | Decorated symbol name when available. Only present with `--mangled`. |
| `rva` | Function RVA in the target executable. |
| `remote_address` | Function address in the running target process. |
| `counter_index` | Counter table index for patched rows. Empty for skipped rows. |
| `count` | Number of observed calls. |
| `status` | `patched` or a `skipped:` reason. |
| `stolen_bytes` | Number of original entry bytes copied into the trampoline. |

Rows with `status=patched` were instrumented. Rows with `skipped:` were left
alone. Common skip reasons include RIP-relative instructions, control flow in
the patch window, too-small function bodies, overlapping patch windows, or
failure to allocate nearby trampoline memory.

When the target exits, `miri-run` also prints the process exit code. It attempts
to print a termination callstack when it sees termination APIs or a final
debugger exit event.

## miri-hist

`miri-hist` reads a `miri-run` CSV report and prints a sorted call-count
histogram.

```powershell
E:\miri-build\bin\Release\miri-hist.exe <report.csv> [--top N] [--html out.html] [--include-zero]
```

Examples:

```powershell
E:\miri-build\bin\Release\miri-hist.exe C:\work\game.miri.csv
E:\miri-build\bin\Release\miri-hist.exe C:\work\game.miri.csv --top 100
E:\miri-build\bin\Release\miri-hist.exe C:\work\game.miri.csv --top 100 --html C:\work\game-hotspots.html
E:\miri-build\bin\Release\miri-hist.exe C:\work\game.miri.csv --include-zero
```

Options:

| Option | Meaning |
| --- | --- |
| `--top N` | Show at most `N` rows. Defaults to `50`. Use `0` for no limit. |
| `--html out.html` | Also write an HTML histogram. |
| `--include-zero` | Include patched functions with a zero count. |

`miri-hist` only uses rows with `status=patched`. By default it hides zero-count
functions. It reads columns by name, so it works with reports produced with or
without `--mangled`.

## Typical workflow

1. Create a focused config file with include/exclude filters.
2. Run the target with `miri-run`.
3. Inspect the CSV for skipped statuses and total coverage.
4. Use `miri-hist` to find hot functions.
5. Tighten filters or rerun with `atomicCounters` if thread contention matters.

Example:

```powershell
E:\miri-build\bin\Release\miri-run.exe --verbose --mangled `
  C:\games\Example\Game.exe `
  C:\symbols\Game.pdb `
  C:\work\game.miri.json

E:\miri-build\bin\Release\miri-hist.exe `
  C:\work\game.miri.csv `
  --top 100 `
  --html C:\work\game-hotspots.html
```

## Troubleshooting

`Could not attach` or `already being debugged`

The target already has an invasive debugger attached. Close the other debugger,
or run `miri-run` without trying to attach another debugger at the same time.

`target PDB does not exist`

Pass the PDB path explicitly, or place the matching PDB next to the executable.

Many rows are skipped

This is expected for some binaries. `miri-run` is conservative and only patches
entry windows it can safely copy and resume from.

Mangled column equals symbol for some rows

The PDB may not contain a decorated public record for that function. In that
case `miri-run` falls back to the friendly function name for the `mangled`
column.

Counts look lower than expected

Only successfully patched functions are counted. Check `status` in the CSV and
try narrower include filters if too many patchable sites are competing for
nearby trampoline memory.
