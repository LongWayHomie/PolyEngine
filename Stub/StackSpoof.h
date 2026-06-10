#pragma once
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum number of pre-built synthetic stack configs (one per distinct
 * add_rsp delta).  Valid d1 values < 0x20 give at most 3 (8/16/24 bytes). */
#define SPOOF_POOL_MAX 4

BOOL  StackSpoof_Init(void);
void  StackSpoof_Cleanup(void);

/* 0=ok, 1=ntdll base, 2=AddRsp gadget, 3=JmpRbx gadget, 4=RtlUserThreadStart */
extern DWORD g_SpoofInitFailStep;

/* Pre-built synthetic stack configs and valid count.  HellsHall.asm
 * selects one at random (rdtsc % count) per syscall invocation. */
typedef struct {
    ULONG64 stack[32];      /* full synthetic stack layout (256 bytes) */
} SPOOF_STACK_CONFIG;

extern SPOOF_STACK_CONFIG g_SpoofConfigPool[SPOOF_POOL_MAX];
extern ULONG              g_SpoofPoolCount;

/* Called from HellsHall.asm to copy a random config into g_SpoofSyntheticStack.
 * Uses C calling convention — avoids MASM LEA encoding issues with EXTERNs. */
void StackSpoof_CopyRandomConfig(void);

#ifdef __cplusplus
}
#endif
