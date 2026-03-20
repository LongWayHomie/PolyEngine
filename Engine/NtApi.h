/*
 * ==========================================================================
 *  NtApi.h – Native Windows API (NT API) – types, constants, and function pointers
 * ==========================================================================
 *
 *  PURPOSE:
 *  ----
 *  Windows uses two layers of API:
 *   - Win32 API (kernel32.dll, user32.dll, ...) – high level, documented
 *   - NT API   (ntdll.dll) – low level, less documented
 *
 *  Nt* functions are "real" system functions – they perform syscalle. We use them directly (instead of WinAPI) because:
 *   1. They give more control (e.g. NtCreateSection allows creating shared memory sections between processes – there is no equivalent in WinAPI).
 *   2. Lower chance of hooking by security software, because most hooks are placed on Win32 API.
 *
 *  This file declares:
 *   - Types (NTSTATUS, HANDLE, OBJECT_ATTRIBUTES, ...)
 *   - Pointers to NT API functions that we will resolve in runtime
 *   - Helper function InitNtApi() to load pointers
 *
 *  USED NT API FUNCTIONS:
 *  -----------------------
 *  NtCreateSection       – creates a section object (shared memory segment)
 * NtMapViewOfSection    – maps sections to process address space
 * NtUnmapViewOfSection  – unmaps sections from process
 * NtClose               – closes an object handle (section, file, thread, ...)
 * NtCreateThreadEx      – creates a thread in any process (local + remote)
 * ==========================================================================
 */

#pragma once

#ifndef NTAPI_H
#define NTAPI_H

#include <Windows.h>
#include <winternl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 *  NTSTATUS – return code of NT functions
 *  Bit 31 (MSB) = 1 means error, 0 = success or warning
 * ============================================================ */
typedef LONG NTSTATUS;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

/* ============================================================
 *  Section access constants
 *  Used as flags for NtCreateSection / NtMapViewOfSection
 *  May already be defined in Windows SDK (winnt.h)
 * ============================================================ */
#ifndef SECTION_MAP_WRITE
#define SECTION_MAP_WRITE 0x0002
#endif
#ifndef SECTION_MAP_READ
#define SECTION_MAP_READ 0x0004
#endif
#ifndef SECTION_MAP_EXECUTE
#define SECTION_MAP_EXECUTE 0x0008
#endif
#ifndef SECTION_ALL_ACCESS
#define SECTION_ALL_ACCESS 0x000F
#endif

/* ============================================================
 *  Memory protection constants (beyond standard Windows.h)
 * ============================================================ */
#ifndef PAGE_EXECUTE_READWRITE
#define PAGE_EXECUTE_READWRITE 0x40
#endif

/* ============================================================
 *  Function pointer types for NT API
 *  Each typedef describes the signature of one of the used functions.
 *  Pointers are resolved at runtime by InitNtApi().
 * ============================================================ */

/*
 * NtCreateSection – creates a section object (shared memory segment)
 *
 * SectionHandle   – [out] handle to the new section
 * DesiredAccess   – access rights (SECTION_ALL_ACCESS)
 * ObjectAttributes– object attributes (NULL = anonymous)
 * MaximumSize     – section size in bytes
 * SectionPageProtection – page protection (PAGE_EXECUTE_READWRITE)
 * AllocationAttributes  – allocation type (SEC_COMMIT = immediate)
 * FileHandle      – file handle for mapping (NULL = RAM only)
 */
typedef NTSTATUS(NTAPI *pfnNtCreateSection)(
    PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);

/*
 * NtMapViewOfSection – maps sections to process address space
 *
 * SectionHandle   – handle to the section (from NtCreateSection)
 * ProcessHandle   – handle to the target process (-1 = our process)
 * BaseAddress     – [in/out] base address of the mapping (NULL = system chooses)
 * ZeroBits        – number of zero bits in the address (0 = no restrictions)
 * CommitSize      – initial commit size (0 = entire section)
 * SectionOffset   – offset in the section (NULL = from the beginning)
 * ViewSize        – [in/out] view size (0 = entire section)
 * InheritDisposition – what to do on fork (1=ViewShare, 2=ViewUnmap)
 * AllocationType  – allocation type (0 = standard)
 * Win32Protect    – page protection for this mapping
 */
typedef NTSTATUS(NTAPI *pfnNtMapViewOfSection)(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress,
    ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType,
    ULONG Win32Protect);

/*
 * NtUnmapViewOfSection – unmaps a section view from the process address space
 *
 * ProcessHandle – handle to the process (-1 = our process)
 * BaseAddress   – address where the section was mapped
 */
typedef NTSTATUS(NTAPI *pfnNtUnmapViewOfSection)(HANDLE ProcessHandle,
                                                 PVOID BaseAddress);

/*
 * NtClose – closes an object handle (section, file, thread, ...)
 *
 * Handle – handle to close
 */
typedef NTSTATUS(NTAPI *pfnNtClose)(HANDLE Handle);

/*
 * NtCreateThreadEx – creates a new thread in any process
 *
 * This is the key function for "remote thread injection":
 * by creating a thread in ANOTHER process, we can run our
 * shellcode in the context of that process.
 *
 * ThreadHandle    – [out] handle to the new thread
 * DesiredAccess   – access rights (THREAD_ALL_ACCESS)
 * ObjectAttributes– attributes (NULL)
 * ProcessHandle   – handle to the process where we create the thread
 * StartRoutine    – address of the thread's start function (our shellcode)
 * Argument        – argument to pass to the thread (NULL)
 * CreateFlags     – flags (0 = immediate start)
 * ZeroBits        – (0)
 * StackSize       – stack size (0 = default)
 * MaximumStackSize– max stack size (0 = default)
 * AttributeList   – attribute list (NULL)
 */
typedef NTSTATUS(NTAPI *pfnNtCreateThreadEx)(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
    SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize,
    PVOID AttributeList);

/* ============================================================
 *  Global pointers to NT API functions
 *  Initialized by InitNtApi() – only after initialization
 *  can they be used for calls.
 * ============================================================ */
extern pfnNtCreateSection pNtCreateSection;
extern pfnNtMapViewOfSection pNtMapViewOfSection;
extern pfnNtUnmapViewOfSection pNtUnmapViewOfSection;
extern pfnNtClose pNtClose;
extern pfnNtCreateThreadEx pNtCreateThreadEx;

/* ============================================================
 *  InitNtApi() – initializes NT API function pointers
 *
 *  Loads ntdll.dll (always loaded in every process)
 *  and resolves addresses of all needed Nt* functions.
 *
 *  Returns: TRUE  – all functions found
 *          FALSE – one or more functions not found
 * ============================================================ */
BOOL InitNtApi(void);

/* ============================================================
 *  NtQueueApcThread – queue APC to thread
 * ============================================================ */
typedef NTSTATUS(NTAPI *pfnNtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3);

extern pfnNtQueueApcThread pNtQueueApcThread;

typedef NTSTATUS(NTAPI *pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

extern pfnNtQueryInformationProcess pNtQueryInformationProcess;

typedef NTSTATUS(NTAPI *pfnNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten);

extern pfnNtWriteVirtualMemory pNtWriteVirtualMemory;

typedef NTSTATUS(NTAPI *pfnNtResumeThread)(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount);

extern pfnNtResumeThread pNtResumeThread;

/* ============================================================
 *  NtAllocateVirtualMemory – virtual memory allocation/reservation
 * ============================================================ */
typedef NTSTATUS(NTAPI *pfnNtAllocateVirtualMemory)(
    HANDLE  ProcessHandle,
    PVOID  *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG   AllocationType,
    ULONG   Protect);

extern pfnNtAllocateVirtualMemory pNtAllocateVirtualMemory;

/* ============================================================
 *  NtProtectVirtualMemory – changing permissions
 * ============================================================ */
typedef NTSTATUS(NTAPI *pfnNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect);

extern pfnNtProtectVirtualMemory pNtProtectVirtualMemory;

/* ============================================================
 *  NtFlushInstructionCache – instruction cache flush
 *  Required after writing code to memory before executing it.
 * ============================================================ */
typedef NTSTATUS(NTAPI *pfnNtFlushInstructionCache)(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    SIZE_T  Length);

extern pfnNtFlushInstructionCache pNtFlushInstructionCache;

#ifdef __cplusplus
}
#endif

#endif /* NTAPI_H */
