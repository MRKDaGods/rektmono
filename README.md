# rektmono

External Mono/.NET assembly interception for Unity applications on x64 Windows — no DLL injection required.

rektmono hooks Mono's internal image-loading functions from outside the target process, giving you full control over every .NET assembly as it loads. The entire patching pipeline runs externally through thread hijacking and remote code execution; nothing is ever injected into the target's address space.

## How it works

The core idea is straightforward: launch the target process suspended, set up inline hooks on Mono's assembly loading path from the outside, then resume. When Unity initializes Mono and starts loading assemblies like `mscorlib.dll` or game-specific DLLs, the hooks fire and you can read, modify, or replace the assembly bytes before they reach the runtime.

### The patching flow

1. The target process is created suspended via `CreateProcessA` with `CREATE_SUSPENDED`, before any Mono initialization happens.

2. A `RemoteRuntimeData` structure is allocated in the target. This contains a WinAPI vtable (function pointers to `LoadLibraryA`, `GetProcAddress`, file I/O, etc.), a trampoline map for calling original functions from hooks, and a scratch buffer. System DLLs like kernel32 share the same base address across processes (ASLR is per-boot, not per-process), so the local function pointers are valid in the target.

3. `mono-2.0-bdwgc.dll` is loaded in the target via a remote `LoadLibraryA` call. The exported function `mono_image_open_from_data_with_name` is resolved through `GetProcAddress`. The internal function `do_mono_image_open` (not exported) is found by pattern scanning the mono binary in remote memory.

4. Hook functions are compiled locally as "persistent remote functions." Before being written to the target, the framework patches two things:
   - A placeholder address (`0xD1EAF1F1EE50AA67`) embedded as a `movabs` is replaced with the actual `RemoteRuntimeData` address.
   - Any `LEA [rip+disp]` instructions referencing local `.rdata` strings are rewritten — the strings are allocated remotely and the displacements are recalculated.

5. Standard 14-byte inline detours (`jmp QWORD PTR [rip]; <addr>`) are placed on both Mono functions. The overwritten prologues are backed up into trampolines so the hooks can call the originals. Instruction boundaries are respected using length disassembly (`nmd_assembly`) to avoid splitting instructions.

6. The process is resumed. Every assembly load now goes through the hooks, where you can intercept the file path or raw bytes, apply transformations (XOR decryption, bytecode rewriting, full replacement, etc.), and forward the result to the original loader.

### Remote code execution

All remote function calls use the same thread hijacking pattern:
- Suspend the main thread, save its context
- Allocate a small execution context in the target (shellcode + function + args)
- Set `RIP` to the shellcode, resume the thread
- The shellcode calls the function, writes the return value, then sets a completion flag (`0xD1EAF1F1`) and spins
- The host polls the flag via `ReadProcessMemory`, restores the original thread context, and resumes

The shellcode itself is a fixed 75-byte x64 stub that handles stack alignment, shadow space, the call, and the completion signal.

## Projects

| Project | What it does |
|---|---|
| `injectionless` | The core engine — external Mono hooking without injection |
| `loader` | Manual-mapping DLL injector with PE relocation fixup and import resolution |
| `helloworld` | Minimal test DLL payload (`MessageBoxA` on attach) |
| `config_gen` | C# tool that generates base64-encoded loader configs |

### Backend abstraction

The memory access layer (`backend/`) abstracts process operations behind a common interface. Currently only the usermode backend (Win32 API wrappers) is implemented. The kernel backend stub exists for future driver-based memory access.

## Building

Requires Visual Studio with the C++ desktop workload.

Open `rektmono.slnx` and build in Release x64. The target process path and mono DLL location are hardcoded in `injectionless/main.cpp` — edit `TARGET_PROC_DIR`, `TARGET_PROC_NAME`, and `MONO_RELV_PATH` to point at your Unity application before building. The default target is a local Unity project using the standard `MonoBleedingEdge/EmbedRuntime/mono-2.0-bdwgc.dll` layout.

The `loader` project was the original approach — a manual-mapping DLL injector that loads a payload into the target to hook Mono from inside the process. `injectionless` supersedes it by achieving the same result entirely externally, without any injection. The loader and its supporting projects (`helloworld`, `config_gen`) are kept for reference.

## Limitations

- x64 only (the shellcode and hooking logic are architecture-specific)
- Usermode backend is susceptible to anti-cheat kernel protections
- The target must use Mono (not IL2CPP)
- Currently assumes the target isn't already running or has a standard Mono embed layout
