#include "NtApi.h"
#include <stdio.h>

/* Global pointers to NT API functions */
pfnNtCreateSection pNtCreateSection = NULL;
pfnNtMapViewOfSection pNtMapViewOfSection = NULL;
pfnNtUnmapViewOfSection pNtUnmapViewOfSection = NULL;
pfnNtClose pNtClose = NULL;
pfnNtCreateThreadEx pNtCreateThreadEx = NULL;
pfnNtQueueApcThread pNtQueueApcThread = NULL;
pfnNtQueryInformationProcess pNtQueryInformationProcess = NULL;
pfnNtWriteVirtualMemory pNtWriteVirtualMemory = NULL;
pfnNtResumeThread pNtResumeThread = NULL;
pfnNtAllocateVirtualMemory pNtAllocateVirtualMemory = NULL;
pfnNtFlushInstructionCache pNtFlushInstructionCache = NULL;

BOOL InitNtApi(void) {
  HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
  if (!hNtdll) {
    return FALSE;
  }

  pNtCreateSection = (pfnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
  pNtMapViewOfSection = (pfnNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
  pNtUnmapViewOfSection = (pfnNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
  pNtClose = (pfnNtClose)GetProcAddress(hNtdll, "NtClose");
  pNtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
  pNtQueueApcThread = (pfnNtQueueApcThread)GetProcAddress(hNtdll, "NtQueueApcThread");
  pNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
  pNtWriteVirtualMemory = (pfnNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
  pNtResumeThread = (pfnNtResumeThread)GetProcAddress(hNtdll, "NtResumeThread");
  pNtAllocateVirtualMemory = (pfnNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
  pNtFlushInstructionCache = (pfnNtFlushInstructionCache)GetProcAddress(hNtdll, "NtFlushInstructionCache");

  if (!pNtCreateSection || !pNtMapViewOfSection || !pNtUnmapViewOfSection || !pNtClose || !pNtCreateThreadEx || !pNtQueryInformationProcess || !pNtWriteVirtualMemory || !pNtResumeThread || !pNtAllocateVirtualMemory || !pNtFlushInstructionCache) {
    return FALSE;
  }
  
  return TRUE;
}
