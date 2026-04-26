#pragma once

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 *  Opsec.h - OPSEC module (process hiding, PEB spoofing, detection)
 * ========================================================================= */

void Opsec_SpoofPeb(const wchar_t* fakePath);

/* Patches EtwEventWrite in the process ntdll to  xor eax,eax / ret,
 * silencing all user-mode ETW events for the lifetime of the process.
 * Must be called after ApiHashing_InitHashes() and Syscalls_Init(). */
BOOL Opsec_PatchEtw(void);

/* Populated by Opsec_PatchEtw: 1..4 identifies which step failed, 0 on success. */
extern DWORD g_EtwFailStep;

#ifdef __cplusplus
}
#endif
