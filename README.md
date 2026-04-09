# PolyEngine — Polymorphic PE Packer 📦

**PolyEngine** is a research-grade, evasive PE packer designed for CTF challenges and low-level Windows security education. It focuses on bypassing EDR and AV heuristics through a layered stack of in-memory execution and obfuscation techniques.

This is a side project I've been working on for some time. I have used Claude Code to implement and correct some of techniques I wanted to implement in my own PE packer. There's a lot of comments on functions and what they do, since it was a big learning experience for me and Claude does this flawlessly (I'm bad at it). I hope it helps some people to learn some Windows internals or with bypassing some AVs and static detections from more advanced solutions when you tackle those ProLabs 🏯. 

🔥 Big thank you to [MalDevAcademy](https://maldevacademy.com/) for all the materials to create it and inspiration.

🌩 Thanks to [vx-underground](https://x.com/vxunderground) for inspiration via some goofy tweet with silly cat.

> **Disclaimer:** This tool is intended exclusively for authorized security testing, CTF competitions and educational use. Usage against systems without explicit permission is prohibited. The author assumes no liability for misuse.

---

## Usage

Build order: **Stub first, then Builder** (Builder embeds `stub.bin` into `.rsrc`).

Ensure `stub.bin` is in the same directory as `Builder.exe`.

```
Builder.exe <input> <output> [OPTIONS]

  <input>   Target PE (.exe/.dll) or raw shellcode (.bin)
            Payload type is auto-detected from the MZ header — no flag needed.
  <output>  Output executable

Loader:
  --stub <path>              Path to stub.bin  [default: ./stub.bin]
  --preset PRINT|MEDIA|NETWORK|RANDOM
                             Module stomping DLL preset  [default: PRINT]
  --overload                 Module overloading instead of stomping
                             (NtCreateSection/NtMapViewOfSection, not in PEB LDR)
  --keep-alive               ExitThread(0) instead of ExitProcess
                             (required for C2 implants that spawn their own threads)

Payload  (PE/DLL only, silently ignored for shellcode):
  --export <name>            DLL export to invoke after DllMain
  --arg <string>             Argument passed to the export  [max 127 chars]

Evasion  (all ON by default):
  --spoof-name <exe>         Process name for PEB spoof  [default: random from pool]
                             Pool: RuntimeBroker.exe SgrmBroker.exe WmiPrvSE.exe
                                   SearchIndexer.exe taskhostw.exe spoolsv.exe
                                   wlrmdr.exe WMPDMC.exe hvix64.exe
  --exec-ctrl-name <name>    Semaphore name for exec-ctrl check  [default: wuauctl]
                             (max 31 chars)
  --sleep-fwd-ms <ms>        Sleep duration for sleep-fwd check  [default: 500]
                             Detection threshold: 90% of <ms> elapsed
  --uptime-min <minutes>     Uptime threshold for uptime check  [default: 2]
  --hammer-s <seconds>       API-hammer delay duration  [default: 3]
  --disable <token,token...>  Disable one or more features (comma-separated, repeatable)

  OPSEC tokens:
    etw         EtwEventWrite patch (ETW telemetry suppression)
    spoofing    Call-stack spoofing (VEH/HWBP)
    peb         PEB path/cmdline spoof
    tls         TLS anti-debug callback (patches stub.bin before embedding)

  Sandbox/debug check tokens:
    hammer      API-hammer timing delay (VirtualAlloc/Free loop)
    debugger    Debugger detection (PEB flags / NtQueryInformationProcess)
    api-emu     API emulation probe (RtlComputeCrc32 identity check)
    exec-ctrl   Execution-control semaphore (re-execution detection)
    sleep-fwd   Sleep-forwarding detection (timing)
    uptime      System uptime check
    cpu         CPU count check (< 2 logical cores)
    screen      Screen resolution check (<= 1024 px width)
    files       Recent-files count check (< 5 RecentDocs subkeys)
    all         Disable every token listed above

Examples:
  Builder.exe implant.exe     packed.exe
  Builder.exe shellcode.bin   packed.exe --keep-alive
  Builder.exe beacon.dll      packed.exe --export Start --keep-alive
  Builder.exe payload.dll     packed.exe --export Execute --arg "calc.exe"
  Builder.exe implant.exe     packed.exe --preset NETWORK --disable etw,tls
  Builder.exe implant.exe     packed.exe --overload --hammer-s 5 --uptime-min 5
  Builder.exe implant.exe     packed.exe --exec-ctrl-name MyMutex --sleep-fwd-ms 1000
```

---

## Build

**Visual Studio 2022 (MSVC v143), Release|x64 only.** Open `PolyEngine.sln`.

Build order matters:
1. **Stub** project → produces `x64/Release/stub.bin` (raw binary, no PE headers)
2. **Builder** project → produces `x64/Release/Builder.exe`

`stub.bin` is a raw binary (linker entry point only). Builder reads it from disk and embeds it into the output `.rsrc` section.

MASM custom build steps are configured in `Stub.vcxproj` (`HellsHall.asm`) and in the Engine projects (`DecryptorStub.asm`). No CMake, no Makefile.

**To add a new API hash:** compute `Djb2HashA("ApiName")` (same algorithm as in `ApiHashing.cpp`), add a `g_Hash_*` global in `ApiHashing.h`, initialize it in `ApiHashing_InitHashes()`.

---

## Architecture Overview

PolyEngine consists of three separate components that together implement a **pack → encrypt → inject** pipeline:

```
Builder.exe
  ├── reads target PE or raw shellcode (.bin)
  ├── LZNT1 compress
  ├── CompoundEncrypt (inner cipher: XOR+ROL+ADD+XOR, per-build key)
  ├── MutationEngine → unique polymorphic ASM decryptor per build
  ├── CryptGenRandom → per-build XTEA key salt + DLL preset indices
  ├── XTEA-CTR encrypt (outer layer)
  └── embed into stub.bin .rsrc → Output.exe

Output.exe (= stub.bin + .rsrc payload)
  ├── ApiHashing_InitHashes()          — resolve all APIs by Djb2 hash
  ├── GetPayloadFromResource()         — parse .rsrc 280-byte metadata block
  │                                      (before evasion: reads opsecFlags / EVASION_FLAG_NO_* bits)
  ├── Evasion_HammerDelay()            — burn real wall-clock time via VirtualAlloc/Free loop
  ├── Evasion_RunChecks()              — sandbox + debugger detection (8 checks, configurable)
  ├── Syscalls_Init()                  — map \KnownDlls\ntdll, extract SSNs, copy clean trampoline
  ├── InitNtApi()                      — bind NT API pointers to HellsHall syscall wrappers
  ├── VehSpoof_Init()                  — install HWBP/VEH call stack spoofer on HellsHallSyscall
  ├── Opsec_PatchEtw()                 — patch EtwEventWrite → xor eax,eax; ret (ETW bypass)
  ├── Xtea_DeriveKey(key, salt)        — reconstruct per-build XTEA key
  ├── Xtea_Crypt()                     — decrypt outer XTEA layer
  ├── Opsec_SpoofPeb()                 — mask process name, path, cmdline, debug/heap flags in PEB
  ├── ModuleStomp_Alloc()              — hijack .text section of benign DLL, save original bytes
  │   or ModuleOverload_Alloc()        — (--overload) NtCreateSection+NtMapViewOfSection, not in PEB LDR
  ├── copy decryptor stub → stomped .text (RW), flip RW→RX via HellsHall
  ├── call decryptor (RCX = payload pointer in separate RW buffer) — no RWX ever
  ├── flip stomped .text RX→RW, decompress LZNT1, wipe + restore original .text bytes → RX
  └── RunPE() (PE payload) or NtProtect RW→RX + direct call (shellcode payload)
```

---

## Evasion Techniques

### Indirect Syscalls — HellsHall

All sensitive NT operations (`NtProtectVirtualMemory`, `NtAllocateVirtualMemory`, etc.) go through indirect syscalls rather than the hooked user-mode stubs in the process ntdll:

1. At startup, `Syscalls_Init()` manually maps `\KnownDlls\ntdll.dll` (the clean, pre-hook image from the KnownDlls section object) using a bootstrap "dirty" trampoline.
2. SSNs are extracted from the clean image using **RVA-ordering** (HellsGate/FreshyCalls variant): all `Zw*` export RVAs are sorted; sorted index == SSN. Hook-agnostic by design — works even if a hook changes function prologues.
3. A `syscall; ret` (0F 05 C3) trampoline is located inside the clean mapping, copied into a **private RW allocation**, then hardened to `PAGE_EXECUTE_READ`. The mapped view is then discarded. `g_CleanTrampoline` points to this private copy — process memory shows no secondary ntdll mapping.
4. All syscalls jump to `g_CleanTrampoline` — EDR hooks in the process ntdll are never called.

### HWBP Call Stack Spoofing — VehSpoof

EDRs monitor the thread call stack at the moment a syscall fires to verify the caller chain looks legitimate. PolyEngine defeats this:

1. `VehSpoof_Init()` sets a hardware breakpoint (`Dr0`) on the `HellsHallSyscall` stub.
2. When the CPU hits the breakpoint it raises `EXCEPTION_SINGLE_STEP`, caught by the installed VEH handler.
3. The handler walks the stack, replaces the return address with a pointer into a legitimate Windows DLL frame, and stores the real return in a thread-local slot.
4. The syscall fires — the kernel sees a call stack anchored in a known DLL, not unbacked memory.
5. On return, the VEH fires again and restores the real return address.
6. `VehSpoof_Cleanup()` removes the HWBP and VEH handler before handing over to the payload.

### Module Stomping / Module Overloading

Instead of `VirtualAlloc(RWX)`, the polymorphic decryptor executes inside the `.text` section of a legitimately loaded Windows DLL. No RWX memory is ever allocated.

**Stomping (default — `LoadLibraryW`, DLL appears in PEB LDR):**

1. `ModuleStomp_Alloc()` iterates the three DLLs selected by `--preset`. DLL indices are stored in `.rsrc` and resolved from `g_DllPool` at runtime.
2. The first DLL with an executable section large enough for the decryptor stub is chosen.
3. Original `.text` bytes are saved to a private `RW` buffer before touching the section.
4. The decryptor stub (only) is copied into the stomped region. The payload blob stays in a **separate** `RW` allocation (`pEncryptedPayload`).
5. `NtProtect RW → RX`: the stomped region becomes executable. The payload allocation remains `RW` — decryptor receives its address in `RCX` (Windows x64 ABI first argument).
6. Decryptor runs, decrypts `pEncryptedPayload` in-place. `NtProtect RX → RW` immediately after return.
7. Region is wiped, original bytes are restored, section is set back to `PAGE_EXECUTE_READ`.

**Overloading (`--overload` — `NtCreateSection(SEC_IMAGE)` + `NtMapViewOfSection`, NOT in PEB LDR):**

- Same save/restore pattern and no-RWX invariant as stomping.
- DLL is mapped directly from the raw file handle — never appears in `PEB.Ldr`, defeating tools that enumerate loaded modules.
- After use: `NtUnmapViewOfSection` discards COW private pages, removing all evidence of the write.

**Result in both cases:** memory region is `MEM_IMAGE` backed by the DLL's file on disk — memory scanners see a legitimate image mapping, not an anonymous `VirtualAlloc` region.

### Polymorphic Decryptor — MutationEngine

Each build produces a unique 34-byte x64 ASM decryptor stub, never identical to any prior build:

- **NOP insertion** — random NOP/junk instructions between functional instructions
- **Register swapping** — functional registers randomly reassigned across equivalent sets
- **Instruction substitution** — each step emitted in one of three semantically equivalent variants (e.g. `xor al, k` / `sub al, ~k+1` / `not al; and al, k; or al, k^ff`)
- **Block permutation** — independent blocks reordered via Fisher-Yates shuffle

The CompoundEncrypt cipher (XOR→ROL→ADD→XOR on each byte) maps cleanly to the four-instruction decryptor template. The MutationEngine emits a different variant combination for each of the three steps, making static signature matching of the decryptor loop infeasible.

### Encryption Stack

| Layer | Algorithm | Key source |
|---|---|---|
| Outer | XTEA-CTR (128-bit) | Stack-constructed base XOR per-build `CryptGenRandom` salt |
| Inner | CompoundEncrypt (XOR+ROL+ADD+XOR) | Per-build `__rdtsc`-seeded compound key, embedded in decryptor stub |

**Outer XTEA key derivation** (`Xtea_DeriveKey`): the 128-bit key is built at runtime from arithmetic on irrational-number constants (φ, √2, √3, √5, √10 scaled to 32 bits). No contiguous 16-byte key blob exists in the binary. The final key is `derived_base XOR key_salt`, where `key_salt` is 16 bytes of `CryptGenRandom` output stored in `.rsrc` — every build produces a unique keystream.

**Dynamic magic (no static YARA anchor):** the `.rsrc` metadata block ends with `magic = key_salt[0]^key_salt[1]^key_salt[2]^key_salt[3]`. The Stub locates the block by scanning backwards and verifying this invariant — no `0xDEADBEEF` or other fixed constant exists for a YARA rule to anchor on.

### TLS Callback Anti-Debug

The Windows Loader invokes TLS callbacks from `.CRT$XLB` **before `AddressOfEntryPoint`** receives control — before any payload is in memory. At that moment the environment is probed with zero external API dependencies (only CPU intrinsics and direct PEB reads):

| Check | PEB / Heap field | Detection condition |
|---|---|---|
| BeingDebugged | `PEB+0x002` | any Win32 debugger attached |
| NtGlobalFlag | `PEB+0xBC` (x64) | bits `0x70` set by ntdll under a debugger |
| Heap Flags | `ProcessHeap+0x70` (x64) | value != 2 (HEAP_GROWABLE) |
| Heap ForceFlags | `ProcessHeap+0x74` (x64) | value != 0 |

On detection: `__fastfail(FAST_FAIL_FATAL_APP_EXIT)` — bypasses all user-mode exception handlers (VEH, SEH, UnhandledExceptionFilter). WER records `STATUS_STACK_BUFFER_OVERRUN (c0000409)`, indistinguishable from a legitimate memory-safety crash.

Can be disabled at build time with `--disable tls`. Builder patches a 5-byte marker in `stub.bin` to neutralize the callback before embedding.

### ETW Patching

`Opsec_PatchEtw()` writes a 3-byte no-op to the first bytes of `EtwEventWrite` in the process ntdll:

```asm
; After patch:
33 C0    xor eax, eax   ; return STATUS_SUCCESS (0)
C3       ret
```

Applied through `NtProtectVirtualMemory` (via HellsHall + VehSpoof). A separate `pPage` variable holds the base address for `NtProtect` (the kernel may round it to a page boundary); `pEtw` is preserved for the actual byte write.

### PEB Spoofing

`Opsec_SpoofPeb()` rewrites:
- `PEB.ImageBaseFileName` — process name shown by Process Hacker, etc.
- `PEB.ImagePathName` and `PEB.CommandLine` — full path visible in process listings
- `PEB.BeingDebugged = 0`, `PEB.NtGlobalFlag = 0` — anti-debug flags
- `ProcessHeap.Flags = 2`, `ProcessHeap.ForceFlags = 0` — heap debug flags

The spoof filename is set via `--spoof-name`. If omitted, Builder picks randomly from a pool of 9 common System32 processes (`RuntimeBroker.exe`, `SgrmBroker.exe`, `WmiPrvSE.exe`, `SearchIndexer.exe`, `taskhostw.exe`, `spoolsv.exe`, `wlrmdr.exe`, `WMPDMC.exe`, `hvix64.exe`) using `CryptGenRandom`.

### Sandbox & Anti-Analysis Checks

`Evasion_RunChecks()` runs before any syscall initialization and uses only the Win32 API layer. Checks are individually toggleable via `--disable`.

**Hard checks** — a single positive triggers immediate exit:

| Check | Method | What it detects |
|---|---|---|
| `debugger` | `PEB.BeingDebugged`, `PEB.NtGlobalFlag`, `ProcessHeap` flags, `NtQueryInformationProcess(ProcessDebugPort)` | Win32 debugger attached |
| `api-emu` | `RtlComputeCrc32(seed, NULL, 0)` — must equal seed | API emulation that returns wrong results |
| `exec-ctrl` | Named semaphore (`wuauctl` by default, configurable) — `ERROR_ALREADY_EXISTS` | Second execution of the sample |
| `sleep-fwd` | `Sleep(ms)` + `GetTickCount64` delta, threshold = 90% of `ms` | Sandbox that fast-forwards `Sleep` calls |

**Soft checks** — 2 or more positives required to exit (reduces false positives):

| Check | Threshold | What it detects |
|---|---|---|
| `uptime` | system uptime < N minutes (default: 2) | Freshly spawned sandbox VM |
| `cpu` | logical processor count < 2 | Low-spec sandbox |
| `screen` | screen width ≤ 1024 px | 800×600 / 1024×768 sandbox resolutions |
| `files` | `HKCU\...\Explorer\RecentDocs` subkey count < 5 | Clean / fake user profile |

**Timing delay:**

`Evasion_HammerDelay()` burns real wall-clock time via `VirtualAlloc/VirtualFree` pairs timed by `GetTickCount64`. The duration is configurable via `--hammer-s` (default: 3 seconds). Sandbox time-accelerators cannot fast-forward allocator round-trips, making this effective against sleep-fast-forward evasion that bypasses the `sleep-fwd` check.

### API Hashing — Djb2

All Windows API names are replaced at compile time with precomputed Djb2 hashes stored as `g_Hash_*` globals. `GetProcAddressH()` walks the export directory and hashes each exported name until a match is found — no plaintext API string appears in the import table or `.data`.

---

## .rsrc Metadata Block Layout

Resource ID 101 (`RT_RCDATA`) contains the XTEA-encrypted blob followed by a **280-byte metadata block**. The Stub locates the block by scanning backwards from the end of the resource (up to 128 bytes, tolerating `UpdateResource` alignment padding) and verifying `magic == XOR(key_salt[0..3])`.

```
[XTEA-encrypted blob]
[key_salt        : 16 bytes]  per-build random XTEA salt (4 x DWORD)
[dll_idx0        :  1 byte ]  index into g_DllPool (module stomping target 1)
[dll_idx1        :  1 byte ]  index into g_DllPool (module stomping target 2)
[dll_idx2        :  1 byte ]  index into g_DllPool (module stomping target 3)
[pad             :  1 byte ]  alignment (0x00)
[origSize        :  4 bytes]  original decompressed PE size (ULONG)
[stubSize        :  4 bytes]  mutated ASM decryptor size (DWORD)
[blobSize        :  4 bytes]  XTEA blob size (DWORD)
[exportHash      :  4 bytes]  fixed-seed Djb2 hash of DLL export to invoke; 0 = none
[exportArg       : 128 bytes] null-terminated export argument string (zero-padded)
[spoof_exe       :  64 bytes] ASCII filename for PEB spoof (zero-padded)
[semaphore_name  :  32 bytes] exec-ctrl semaphore name; empty = default "wuauctl" (zero-padded)
[sleep_fwd_ms    :  4 bytes]  sleep-fwd check duration (ms); 0 = default 500
[uptime_min      :  4 bytes]  uptime threshold (minutes); 0 = default 2
[hammer_ms       :  4 bytes]  API-hammer delay (ms); 0 = default 3000
[flags           :  4 bytes]  OPSEC_FLAG_* + EVASION_FLAG_* bitmask
[magic           :  4 bytes]  key_salt[0]^key_salt[1]^key_salt[2]^key_salt[3]
──────────────────────────────
Total: 280 bytes
```

No fixed value exists anywhere in the block — every field is either random (key_salt, magic) or build-specific. YARA cannot anchor on a static byte sequence.

---

## Module Stomping DLL Pool

Builder `--preset` selects 3 DLL indices stored in `.rsrc`. Stub resolves names from `g_DllPool` at runtime — no DLL name appears in the payload or metadata.

| Index | DLL | Group |
|---|---|---|
| 0 | xpsservices.dll | PRINT |
| 1 | msi.dll | PRINT |
| 2 | dbghelp.dll | PRINT |
| 3 | winmm.dll | MEDIA |
| 4 | dxgi.dll | MEDIA |
| 5 | oleaut32.dll | MEDIA |
| 6 | winhttp.dll | NETWORK |
| 7 | wtsapi32.dll | NETWORK |
| 8 | wlanapi.dll | NETWORK |
| 9 | bcrypt.dll | CRYPTO |

Builder verifies at build time that at least one of the three selected DLLs has an executable section large enough for the payload blob, and warns if none qualify.

---

## Project Structure

```
PolyEngine/
├── Builder/
│   └── Builder.cpp          — CLI parser, orchestration, CryptGenRandom salt/indices
├── Engine/                  — shared between Builder and Stub (compiled into both)
│   ├── Compression.c/h      — LZNT1 compress (Builder) / decompress (Stub) wrappers
│   ├── Crypto.c/h           — CompoundEncrypt inner cipher (XOR+ROL+ADD+XOR)
│   ├── MutationEngine.c/h   — polymorphic ASM decryptor generator
│   ├── NtApi.c/h            — NT API pointer table definitions
│   ├── OpsecFlags.h         — OPSEC_FLAG_* + EVASION_FLAG_* + PAYLOAD_FLAG_* bitmask definitions
│   ├── PeBuilder.c/h        — PAYLOAD_METADATA struct + .rsrc injection (BeginUpdateResource)
│   ├── RunPE.c/h            — in-process PE mapping (IAT fix, relocs, DllMain / EXE EP)
│   └── Xtea.c/h             — XTEA-CTR block cipher + irrational-constant key derivation
└── Stub/                    — CRT-free runtime executor
    ├── Stub.cpp             — EntryPoint, orchestrates all stages
    ├── ApiHashing.cpp/h     — Djb2 hash cache, GetProcAddressH, GetModuleHandleH
    ├── Common.c/h           — custom_memcpy/memset/memcmp (no CRT)
    ├── Evasion.cpp/h        — sandbox + debugger detection (HammerDelay + RunChecks)
    ├── HellsHall.asm        — indirect syscall dispatcher (SetSyscallParams + trampoline jump)
    ├── ModuleStomping.c/h   — g_DllPool[10], ModuleStomp_Alloc, ModuleOverload_Alloc
    ├── Opsec.c/h            — ETW patch, PEB spoofing
    ├── Payload.c/h          — .rsrc parsing, GetPayloadFromResource, DecompressPayload
    ├── StubNtApi.c          — SYSCALL_WRAPPER macro, Sys_Nt* wrappers, InitNtApi
    ├── Structs.h            — NT struct definitions (no Windows DDK dependency)
    ├── Syscalls.c/h         — KnownDlls ntdll mapping, RVA-order SSN extraction, clean trampoline
    ├── TlsCallback.c        — pre-EntryPoint anti-debug (PEB/heap flags, __fastfail)
    └── VehSpoof.c/h         — HWBP/VEH call stack spoofing
```

---

## Dependencies

- Windows 10/11 x64 target
- Visual Studio 2022 (MSVC v143) — no external libraries
- Stub: zero CRT dependency (`/NODEFAULTLIB`), no `malloc`/`free`, no `<string.h>`

---

**Maintained by: Razz** | Built for opsec-conscious security research and fun

*Assistance in implementation done with Claude Code*

---

## License

[MIT](LICENSE) — authorized use only. See `LICENSE` for the full disclaimer.
