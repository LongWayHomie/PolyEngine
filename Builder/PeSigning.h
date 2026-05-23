/*
 * PeSigning.h - Authenticode signing of the built PE via mssign32.dll
 *
 * Uses SignerSignEx2 directly — no signtool.exe dependency, no Authenticode
 * SDK headers required. Struct definitions are duplicated locally so the
 * Builder links only against crypt32.lib (already used for CryptGenRandom).
 *
 * OPSEC: Timestamping is OPTIONAL because it sends a network request to the
 * timestamp authority, which logs the requester IP + exact build time. Pass
 * NULL for timestampUrl on operator workstations that should stay quiet.
 */
#pragma once
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL SignPeWithPfx(const char* outputPath,
                   const char* pfxPath,
                   const char* pfxPassword,
                   const char* timestampUrl);

#ifdef __cplusplus
}
#endif
