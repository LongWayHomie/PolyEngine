#pragma once

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InMemoryOrderLinks;
    PVOID      Reserved1[2];
    PVOID      DllBase;
    PVOID      EntryPoint;
    PVOID      Reserved3;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE                         Reserved1[2];
    BYTE                         BeingDebugged;
    BYTE                         Reserved2[1];
    PVOID                        Reserved3[2];
    PPEB_LDR_DATA                Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID                        Reserved4[3];
    PVOID                        AtlThunkSListPtr;
    PVOID                        Reserved5;
    ULONG                        Reserved6;
    PVOID                        Reserved7;
    ULONG                        Reserved8;
    ULONG                        AtlThunkSListPtr32;
    PVOID                        Reserved9[45];
    BYTE                         Reserved10[96];
    PVOID                        PostProcessInitRoutine;
    BYTE                         Reserved11[128];
    PVOID                        Reserved12[1];
    ULONG                        SessionId;
} PEB, *PPEB;

#ifdef __cplusplus
}
#endif
