/*
 * ==========================================================================
 *  Syscalls.h – Indirect Syscalls via FreshyCalls/KnownDlls and HellsHall
 * ==========================================================================
 */

#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize the Syscall environment.
 * Maps \KnownDlls\ntdll.dll, parses Export Directory, and builds a sorted
 * structure to resolve System Service Numbers (SSNs) and Trampolines.
 */
BOOL Syscalls_Init(void);

BOOL Syscalls_GetParamsByHash(DWORD dwApiHash, PDWORD pdwSsn, PVOID* ppTrampoline);
void SetSyscallParams(DWORD SSN, PVOID Trampoline);
NTSTATUS HellsHallSyscall(void);

#ifdef __cplusplus
}
#endif

#endif /* SYSCALLS_H */
