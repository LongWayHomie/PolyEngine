/*
 * ==========================================================================
 *  Syscalls.h – Indirect Syscalls via FreshyCalls SSN sort and HellsHall
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
 * Parses process ntdll's Export Directory, sorts Zw* RVAs to derive SSNs
 * (FreshyCalls), and locates a `syscall; ret` site in ntdll's .text for use
 * as the indirect-syscall trampoline.
 */
BOOL Syscalls_Init(void);

BOOL Syscalls_GetParamsByHash(DWORD dwApiHash, PDWORD pdwSsn, PVOID* ppTrampoline);
void SetSyscallParams(DWORD SSN, PVOID Trampoline);
NTSTATUS HellsHallSyscall(void);

#ifdef __cplusplus
}
#endif

#endif /* SYSCALLS_H */
