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
 *   1. Random TimeDateStamp
 *   2. Random 8-char names for non-critical sections (.rsrc/.reloc left alone)
 *   3. Clear IMAGE_DIRECTORY_ENTRY_DEBUG if present
 *   4. In-place rewrite of POLY_ISLAND pad regions (NOP/junk, same length)
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
