#include "StubMorph.h"
#include <stdio.h>
#include <string.h>
#include <wincrypt.h>

#pragma comment(lib, "Advapi32.lib")

/* Island markers — must match Stub/PolyIslands.c ("PLY" + A0/AF) */
static const BYTE kIslBeg[4] = { 0x50, 0x4C, 0x59, 0xA0 };
static const BYTE kIslEnd[4] = { 0x50, 0x4C, 0x59, 0xAF };

static const BYTE kNop1[] = { 0x90 };
static const BYTE kNop2[] = { 0x66, 0x90 };
static const BYTE kNop3[] = { 0x0F, 0x1F, 0x00 };
static const BYTE kNop4[] = { 0x0F, 0x1F, 0x40, 0x00 };
static const BYTE kNop5[] = { 0x0F, 0x1F, 0x44, 0x00, 0x00 };

static const BYTE* const kNops[] = { kNop1, kNop2, kNop3, kNop4, kNop5 };
static const int kNopLens[] = { 1, 2, 3, 4, 5 };
#define NOP_N 5

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

static void Morph_FillNops(BYTE* p, DWORD len) {
    DWORD off = 0;
    while (off < len) {
        BYTE rb = 0;
        Morph_Rand(&rb, 1);
        int vi = (int)(rb % NOP_N);
        int nl = kNopLens[vi];
        if ((DWORD)nl > len - off) {
            while (off < len) p[off++] = 0x90;
            break;
        }
        memcpy(p + off, kNops[vi], (size_t)nl);
        off += (DWORD)nl;
    }
}

static BOOL Morph_IsCriticalSection(const char name[8]) {
    if (memcmp(name, ".rsrc", 5) == 0) return TRUE;
    if (memcmp(name, ".reloc", 6) == 0) return TRUE;
    if (memcmp(name, ".tls", 4) == 0) return TRUE;
    if (memcmp(name, ".CRT", 4) == 0) return TRUE;
    return FALSE;
}

static void Morph_RandomSectionName(char out[8]) {
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    BYTE rnd[8];
    Morph_Rand(rnd, 8);
    out[0] = '.';
    for (int i = 1; i < 8; i++)
        out[i] = alphabet[rnd[i] % (sizeof(alphabet) - 1)];
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
                Morph_FillNops(p + padStart, padLen);
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

    DWORD ts = Morph_U32();
    if (ts == 0) ts = 0x60000000u + (GetTickCount() & 0x0FFFFFFFu);
    pNt->FileHeader.TimeDateStamp = ts;

    WORD nSec = pNt->FileHeader.NumberOfSections;
    DWORD secOff = (DWORD)pDos->e_lfanew + 4u + (DWORD)sizeof(IMAGE_FILE_HEADER)
                 + pNt->FileHeader.SizeOfOptionalHeader;
    if (secOff + nSec * (DWORD)sizeof(IMAGE_SECTION_HEADER) > peSize) return FALSE;

    int nRenamed = 0;
    PIMAGE_SECTION_HEADER pSec = (PIMAGE_SECTION_HEADER)(pPe + secOff);
    for (WORD s = 0; s < nSec; s++) {
        char name[8];
        memcpy(name, pSec[s].Name, 8);
        if (Morph_IsCriticalSection(name)) continue;
        char newName[8];
        Morph_RandomSectionName(newName);
        memcpy(pSec[s].Name, newName, 8);
        nRenamed++;
    }

    IMAGE_DATA_DIRECTORY* pDbg =
        &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (pDbg->VirtualAddress && pDbg->Size) {
        pDbg->VirtualAddress = 0;
        pDbg->Size = 0;
    }

    pNt->OptionalHeader.CheckSum = 0;

    int nIsl = Morph_Islands(pPe, peSize);

    printf("[+] StubMorph: TimeDateStamp=0x%08X  sections_renamed=%d  islands=%d\n",
           ts, nRenamed, nIsl);
    return TRUE;
}
