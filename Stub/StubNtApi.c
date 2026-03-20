#include "..\Engine\NtApi.h"
#include "ApiHashing.h"
#include "Syscalls.h"


#define SYSCALL_WRAPPER(hash, type, ...) \
    DWORD dwSsn = 0; \
    PVOID pTrampoline = NULL; \
    if (Syscalls_GetParamsByHash(hash, &dwSsn, &pTrampoline)) { \
        SetSyscallParams(dwSsn, pTrampoline); \
        type pSyscall = (type)HellsHallSyscall; \
        return pSyscall(__VA_ARGS__); \
    } \
    return 0xC0000001; // STATUS_UNSUCCESSFUL

// Global NT API wrappers
NTSTATUS NTAPI Sys_NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle) {
    SYSCALL_WRAPPER(g_Hash_ZwCreateSection, pfnNtCreateSection, SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
}

NTSTATUS NTAPI Sys_NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {
    SYSCALL_WRAPPER(g_Hash_ZwMapViewOfSection, pfnNtMapViewOfSection, SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
}

NTSTATUS NTAPI Sys_NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    SYSCALL_WRAPPER(g_Hash_ZwUnmapViewOfSection, pfnNtUnmapViewOfSection, ProcessHandle, BaseAddress);
}

NTSTATUS NTAPI Sys_NtClose(HANDLE Handle) {
    SYSCALL_WRAPPER(g_Hash_ZwClose, pfnNtClose, Handle);
}

NTSTATUS NTAPI Sys_NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList) {
    SYSCALL_WRAPPER(g_Hash_ZwCreateThreadEx, pfnNtCreateThreadEx, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

NTSTATUS NTAPI Sys_NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
    SYSCALL_WRAPPER(g_Hash_ZwQueryInformationProcess, pfnNtQueryInformationProcess, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

NTSTATUS NTAPI Sys_NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
    SYSCALL_WRAPPER(g_Hash_ZwWriteVirtualMemory, pfnNtWriteVirtualMemory, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS NTAPI Sys_NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    SYSCALL_WRAPPER(g_Hash_ZwResumeThread, pfnNtResumeThread, ThreadHandle, PreviousSuspendCount);
}

NTSTATUS NTAPI Sys_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    SYSCALL_WRAPPER(g_Hash_ZwAllocateVirtualMemory, pfnNtAllocateVirtualMemory, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS NTAPI Sys_NtFlushInstructionCache(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T Length) {
    SYSCALL_WRAPPER(g_Hash_ZwFlushInstructionCache, pfnNtFlushInstructionCache, ProcessHandle, BaseAddress, Length);
}

NTSTATUS NTAPI Sys_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {
    SYSCALL_WRAPPER(g_Hash_ZwProtectVirtualMemory, pfnNtProtectVirtualMemory, ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

NTSTATUS NTAPI Sys_NtQueueApcThread(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3) {
    SYSCALL_WRAPPER(g_Hash_ZwQueueApcThread, pfnNtQueueApcThread, ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
}

// Redirect global pointers to our local wrappers
pfnNtCreateSection         pNtCreateSection         = Sys_NtCreateSection;
pfnNtMapViewOfSection      pNtMapViewOfSection      = Sys_NtMapViewOfSection;
pfnNtUnmapViewOfSection    pNtUnmapViewOfSection    = Sys_NtUnmapViewOfSection;
pfnNtClose                 pNtClose                 = Sys_NtClose;
pfnNtCreateThreadEx        pNtCreateThreadEx        = Sys_NtCreateThreadEx;
pfnNtQueryInformationProcess pNtQueryInformationProcess = Sys_NtQueryInformationProcess;
pfnNtWriteVirtualMemory    pNtWriteVirtualMemory    = Sys_NtWriteVirtualMemory;
pfnNtResumeThread          pNtResumeThread          = Sys_NtResumeThread;
pfnNtAllocateVirtualMemory pNtAllocateVirtualMemory = Sys_NtAllocateVirtualMemory;
pfnNtFlushInstructionCache pNtFlushInstructionCache = Sys_NtFlushInstructionCache;
pfnNtQueueApcThread           pNtQueueApcThread           = Sys_NtQueueApcThread;
pfnNtProtectVirtualMemory     pNtProtectVirtualMemory     = Sys_NtProtectVirtualMemory;

BOOL InitNtApi(void) {
    // NT API Pointers now natively point to our Indirect Syscalls Engine.
    // Ensure the Syscalls engine is already initialized before using them.
    return TRUE;
}
