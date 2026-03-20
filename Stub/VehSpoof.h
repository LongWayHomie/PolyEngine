#ifndef VEH_SPOOF_H
#define VEH_SPOOF_H

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize the Hardware Breakpoint and VEH for Call Stack Spoofing.
 * pTargetFunc: Typically the address of HellsHallSyscall.
 */
BOOL VehSpoof_Init(PVOID pTargetFunc);

/*
 * Cleanup the VEH and clear hardware breakpoints.
 */
void VehSpoof_Cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // VEH_SPOOF_H
