#pragma once
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL  StackSpoof_Init(void);
void  StackSpoof_Cleanup(void);

/* 0=ok, 1=ntdll base, 2=AddRsp gadget, 3=JmpRbx gadget, 4=RtlUserThreadStart */
extern DWORD g_SpoofInitFailStep;

#ifdef __cplusplus
}
#endif