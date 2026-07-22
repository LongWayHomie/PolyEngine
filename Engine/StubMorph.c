#include "StubMorph.h"
#include <stdio.h>
#include <string.h>
#include <wincrypt.h>

#pragma comment(lib, "Advapi32.lib")

/* Island markers — must match Stub/PolyIslands.c ("PLY" + A0/AF).
 * Consumed at pack time only: every tag is overwritten with random bytes
 * after its pad is filled, so no PLY pattern survives into the output PE. */
static const BYTE kIslBeg[4] = { 0x50, 0x4C, 0x59, 0xA0 };
static const BYTE kIslEnd[4] = { 0x50, 0x4C, 0x59, 0xAF };

/* Section-name profiles — coherent naming styles observed in real x64 PEs,
 * matched by original section name.  Random 8-char names are a packer
 * heuristic (UPX-style); plausible toolchain names are not.  Profile 0
 * keeps the original MSVC names.  Sections absent from the map are left
 * alone; critical sections (.rsrc/.reloc/.tls/.CRT) are never touched. */
static const char* const kSecOriginals[4] = { ".text", ".rdata", ".data", ".pdata" };
static const char* const kSecProfiles[][4] = {
    { ".text", ".rdata", ".data",  ".pdata"  },   /* MSVC (no rename) */
    { ".text", ".rdata", ".data",  ".xdata"  },   /* MinGW/GCC        */
    { "CODE",  ".rdata", "DATA",   ".pdata"  },   /* Delphi-style     */
    { ".text", ".ndata", ".data",  ".pdata"  },   /* NSIS-style       */
};
#define PROFILE_N 4

static BOOL Morph_Rand(BYTE* out, DWORD n) {
    HCRYPTPROV h = 0;
    BOOL ok = FALSE;
    if (CryptAcquireContextA(&h, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        ok = CryptGenRandom(h, n, out);
        CryptReleaseContext(h, 0);
    }
    return ok;
}

static DWORD Morph_U32(void) {
    BYTE b[4] = { 0 };
    if (!Morph_Rand(b, 4)) return GetTickCount();
    return (DWORD)b[0] | ((DWORD)b[1] << 8) | ((DWORD)b[2] << 16) | ((DWORD)b[3] << 24);
}

static void Morph_FillRandom(BYTE* p, DWORD len) {
    if (Morph_Rand(p, len)) return;
    /* CNG fallback: LCG stream — only used when CryptGenRandom is unavailable */
    DWORD x = GetTickCount() ^ 0x9E3779B9u;
    for (DWORD i = 0; i < len; i++) {
        x = x * 1664525u + 1013904223u;
        p[i] = (BYTE)(x >> 24);
    }
}

/* PE timestamps of real software are build times from the recent past.
 * A fully random DWORD lands anywhere up to year 2106 — future dates are
 * a known heuristic flag.  Draw from [now-5y, now] instead. */
static DWORD Morph_PlausibleTimestamp(void) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart  = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    DWORD now = (DWORD)((u.QuadPart - 116444736000000000ULL) / 10000000ULL);
    const DWORD span = 5u * 365u * 24u * 60u * 60u;
    return now - (Morph_U32() % span);
}

static BOOL Morph_IsCriticalSection(const char name[8]) {
    if (memcmp(name, ".rsrc", 5) == 0) return TRUE;
    if (memcmp(name, ".reloc", 6) == 0) return TRUE;
    if (memcmp(name, ".tls", 4) == 0) return TRUE;
    if (memcmp(name, ".CRT", 4) == 0) return TRUE;
    return FALSE;
}

static int Morph_RenameSections(PIMAGE_SECTION_HEADER pSec, WORD nSec, int profile) {
    int nRenamed = 0;
    for (WORD s = 0; s < nSec; s++) {
        char name[9] = { 0 };
        memcpy(name, pSec[s].Name, 8);
        if (Morph_IsCriticalSection(name)) continue;
        for (int k = 0; k < 4; k++) {
            if (strncmp(name, kSecOriginals[k], 8) != 0) continue;
            const char* to = kSecProfiles[profile][k];
            if (strncmp(name, to, 8) == 0) break;   /* profile keeps this name */
            memset(pSec[s].Name, 0, 8);
            memcpy(pSec[s].Name, to, strlen(to));
            nRenamed++;
            break;
        }
    }
    return nRenamed;
}

static int Morph_Islands(BYTE* p, DWORD size) {
    int nMorphed = 0;
    for (DWORD i = 0; i + 6 < size; i++) {
        if (p[i] != kIslBeg[0] || p[i + 1] != kIslBeg[1] ||
            p[i + 2] != kIslBeg[2] || p[i + 3] != kIslBeg[3])
            continue;

        WORD id = (WORD)p[i + 4] | ((WORD)p[i + 5] << 8);
        DWORD padStart = i + 6;

        for (DWORD j = padStart; j + 6 <= size; j++) {
            if (p[j] != kIslEnd[0] || p[j + 1] != kIslEnd[1] ||
                p[j + 2] != kIslEnd[2] || p[j + 3] != kIslEnd[3])
                continue;
            WORD idEnd = (WORD)p[j + 4] | ((WORD)p[j + 5] << 8);
            if (idEnd != id) continue;

            DWORD padLen = j - padStart;
            if (padLen > 0 && padLen < 4096) {
                Morph_FillRandom(p + padStart, padLen);
                /* Tags are pack-time scaffolding — randomize them so the
                 * PLY pattern never reaches the output PE.  Runtime only
                 * XORs these bytes (PolyIslands_Touch); values are dead. */
                Morph_FillRandom(p + i, 6);
                Morph_FillRandom(p + j, 6);
                nMorphed++;
            }
            i = j + 5;
            break;
        }
    }
    return nMorphed;
}

BOOL StubMorph_Apply(BYTE* pPe, DWORD peSize) {
    if (!pPe || peSize < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64))
        return FALSE;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pPe;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    if ((DWORD)pDos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > peSize) return FALSE;

    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pPe + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    if (pNt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        printf("[!] StubMorph: only x64 PE supported — skipped\n");
        return TRUE;
    }

    DWORD ts = Morph_PlausibleTimestamp();
    pNt->FileHeader.TimeDateStamp = ts;

    WORD nSec = pNt->FileHeader.NumberOfSections;
    DWORD secOff = (DWORD)pDos->e_lfanew + 4u + (DWORD)sizeof(IMAGE_FILE_HEADER)
                 + pNt->FileHeader.SizeOfOptionalHeader;
    if (secOff + nSec * (DWORD)sizeof(IMAGE_SECTION_HEADER) > peSize) return FALSE;

    int profile = (int)(Morph_U32() % PROFILE_N);
    int nRenamed = Morph_RenameSections((PIMAGE_SECTION_HEADER)(pPe + secOff), nSec, profile);

    IMAGE_DATA_DIRECTORY* pDbg =
        &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (pDbg->VirtualAddress && pDbg->Size) {
        pDbg->VirtualAddress = 0;
        pDbg->Size = 0;
    }

    pNt->OptionalHeader.CheckSum = 0;

    int nIsl = Morph_Islands(pPe, peSize);

    printf("[+] StubMorph: TimeDateStamp=0x%08X  section_profile=%d  sections_renamed=%d  islands=%d\n",
           ts, profile, nRenamed, nIsl);
    return TRUE;
}
