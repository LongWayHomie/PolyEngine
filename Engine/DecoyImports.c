#include "DecoyImports.h"
#include <stdio.h>
#include <string.h>
#include <wincrypt.h>

#pragma comment(lib, "Advapi32.lib")

/* Pool of innocuous kernel32 exports — the same set every minimal MSVC GUI
 * binary drags in through CRT init.  5-8 are picked at random per build. */
static const char* kDecoyFuncPool[] = {
    "GetSystemTimeAsFileTime",
    "GetCurrentProcessId",
    "GetCurrentThreadId",
    "QueryPerformanceCounter",
    "GetSystemInfo",
    "GetTickCount64",
    "Sleep",
    "GetCurrentProcess",
    "GetProcessHeap",
    "GetLastError",
    "SetLastError",
    "GetACP",
};
#define DECOY_POOL_SIZE 12

static DWORD DecoyAlignUp(DWORD v, DWORD a) { return (v + a - 1) & ~(a - 1); }

BOOL DecoyImports_Apply(BYTE** ppImage, DWORD* pImageSize) {
    BYTE*  pBase    = *ppImage;
    DWORD  fileSize = *pImageSize;

    if (fileSize < 0x400) return FALSE;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    if ((DWORD)pDos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > fileSize) return FALSE;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    if (pNt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return FALSE;

    /* Already has imports — nothing to decoy. */
    if (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
        return TRUE;

    /* Refuse to append past a certificate table (file-offset based, at EOF). */
    if (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress)
        return FALSE;

    DWORD secAlign  = pNt->OptionalHeader.SectionAlignment;
    DWORD fileAlign = pNt->OptionalHeader.FileAlignment;
    WORD  nSec      = pNt->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER pSecs = IMAGE_FIRST_SECTION(pNt);

    /* Room for one more section header?  It must fit before the first
     * section's raw data and inside SizeOfHeaders. */
    DWORD firstRaw = 0xFFFFFFFF;
    for (WORD s = 0; s < nSec; s++) {
        if (pSecs[s].PointerToRawData && pSecs[s].PointerToRawData < firstRaw)
            firstRaw = pSecs[s].PointerToRawData;
    }
    DWORD hdrLimit = pNt->OptionalHeader.SizeOfHeaders;
    if (firstRaw < hdrLimit) hdrLimit = firstRaw;
    if ((DWORD)((BYTE*)(pSecs + nSec + 1) - pBase) > hdrLimit) return FALSE;

    /* Pick 5-8 unique functions (partial Fisher-Yates on an index array). */
    BYTE idx[DECOY_POOL_SIZE];
    for (int i = 0; i < DECOY_POOL_SIZE; i++) idx[i] = (BYTE)i;

    DWORD nFuncs = 6;
    {
        HCRYPTPROV hProv = 0;
        BYTE rnd[16] = { 0 };
        if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) &&
            CryptGenRandom(hProv, sizeof(rnd), rnd)) {
            nFuncs = 5 + (rnd[15] % 4);
            for (DWORD i = 0; i < nFuncs; i++) {
                DWORD j = i + (rnd[i] % (DECOY_POOL_SIZE - (DWORD)i));
                BYTE t = idx[i]; idx[i] = idx[j]; idx[j] = t;
            }
        }
        if (hProv) CryptReleaseContext(hProv, 0);
    }

    /* Lay out the section content:
     *   [2 descriptors][INT thunks][IAT thunks][hint/name strings]["kernel32.dll"] */
    BYTE   content[1024];
    memset(content, 0, sizeof(content));

    DWORD nThunk  = nFuncs + 1;                 /* +1 null terminator */
    DWORD offINT  = 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    DWORD offIAT  = offINT + nThunk * sizeof(ULONGLONG);
    DWORD cur     = offIAT + nThunk * sizeof(ULONGLONG);

    DWORD nameRva[8];
    for (DWORD i = 0; i < nFuncs; i++) {
        const char* fn = kDecoyFuncPool[idx[i]];
        size_t len = strlen(fn);
        nameRva[i] = cur;
        cur += sizeof(WORD);                    /* hint = 0 */
        memcpy(content + cur, fn, len + 1);
        cur += (DWORD)len + 1;
        if (cur & 1) cur++;                     /* hint/name entries are WORD-aligned */
    }
    DWORD offDllName = cur;
    memcpy(content + cur, "kernel32.dll", sizeof("kernel32.dll"));
    cur += sizeof("kernel32.dll");
    DWORD contentSize = cur;

    /* New section geometry. */
    PIMAGE_SECTION_HEADER pLast  = &pSecs[nSec - 1];
    DWORD newVA      = DecoyAlignUp(pLast->VirtualAddress + pLast->Misc.VirtualSize, secAlign);
    DWORD newRaw     = DecoyAlignUp(fileSize, fileAlign);
    DWORD newRawSize = DecoyAlignUp(contentSize, fileAlign);

    /* Grow the image; HeapReAlloc + HEAP_ZERO_MEMORY zeroes the new range
     * (file-alignment padding between old EOF and newRaw included). */
    BYTE* pNew = (BYTE*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                    pBase, newRaw + newRawSize);
    if (!pNew) return FALSE;

    /* Re-parse after realloc. */
    pBase = pNew;
    pDos  = (PIMAGE_DOS_HEADER)pBase;
    pNt   = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    pSecs = IMAGE_FIRST_SECTION(pNt);

    /* Fill descriptors + thunk arrays (RVA = newVA + content offset). */
    PIMAGE_IMPORT_DESCRIPTOR pDesc = (PIMAGE_IMPORT_DESCRIPTOR)(content);
    pDesc[0].OriginalFirstThunk = newVA + offINT;
    pDesc[0].TimeDateStamp      = 0;
    pDesc[0].ForwarderChain     = 0;
    pDesc[0].Name               = newVA + offDllName;
    pDesc[0].FirstThunk         = newVA + offIAT;
    /* pDesc[1] stays zeroed — terminator. */

    ULONGLONG* pINT = (ULONGLONG*)(content + offINT);
    ULONGLONG* pIAT = (ULONGLONG*)(content + offIAT);
    for (DWORD i = 0; i < nFuncs; i++) {
        pINT[i] = (ULONGLONG)(newVA + nameRva[i]);
        pIAT[i] = pINT[i];   /* loader overwrites IAT with resolved addresses */
    }

    memcpy(pBase + newRaw, content, contentSize);

    /* Section header. */
    PIMAGE_SECTION_HEADER pNewSec = &pSecs[nSec];
    memset(pNewSec, 0, sizeof(IMAGE_SECTION_HEADER));
    memcpy(pNewSec->Name, ".idata", 6);
    pNewSec->Misc.VirtualSize = contentSize;
    pNewSec->VirtualAddress   = newVA;
    pNewSec->SizeOfRawData    = newRawSize;
    pNewSec->PointerToRawData = newRaw;
    pNewSec->Characteristics  = IMAGE_SCN_CNT_INITIALIZED_DATA |
                                IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    pNt->FileHeader.NumberOfSections = nSec + 1;
    pNt->OptionalHeader.SizeOfImage  = DecoyAlignUp(newVA + contentSize, secAlign);
    pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = newVA;
    pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size           = 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress    = newVA + offIAT;
    pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size              = nThunk * sizeof(ULONGLONG);

    *ppImage    = pBase;
    *pImageSize = newRaw + newRawSize;

    printf("[+] Decoy import directory: .idata (%lu kernel32 imports, RVA 0x%08lX)\n",
           nFuncs, newVA);
    return TRUE;
}
