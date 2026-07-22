#ifndef STUB_MORPH_H
#define STUB_MORPH_H

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Pack-time safe morph of the loader stub PE (Builder only).
 *
 * Applies:
 *   1. Plausible TimeDateStamp drawn from [now-5y, now] — a fully random
 *      DWORD can land in the future, which is a heuristic flag
 *   2. Toolchain-profile section names (MSVC / MinGW / Delphi / NSIS style),
 *      matched by original name; .rsrc/.reloc/.tls/.CRT left alone.
 *      Random 8-char names would trip UPX-style packer heuristics
 *   3. Clear IMAGE_DIRECTORY_ENTRY_DEBUG if present
 *   4. In-place random-byte rewrite of POLY island pads AND their tag
 *      markers (same length) — no PLY pattern or fixed decoy content
 *      survives into the output PE
 *
 * Never touches: PE structure integrity, entry point RVA, TLS directory
 * contents (except section name cosmetics), HellsHall body, marker tags
 * for TLS/ResID (islands use a different tag family).
 *
 * pPe/peSize are the raw stub file buffer; size is not changed.
 * Returns TRUE always for soft failures (logs warnings); FALSE only if
 * buffer is not a parseable PE.
 */
BOOL StubMorph_Apply(BYTE* pPe, DWORD peSize);

#ifdef __cplusplus
}
#endif

#endif /* STUB_MORPH_H */
