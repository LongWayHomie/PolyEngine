/*
 * PeSigning.cpp - Authenticode signing via mssign32!SignerSignEx2
 *
 * Replaces signtool.exe with a direct WinAPI call so the Builder has zero
 * external tool dependency. Struct definitions are inlined (mssign32.h is
 * not always shipped with the Windows SDK and including it just for these
 * declarations adds nothing).
 *
 * Pipeline:
 *   PFXImportCertStore       — open the .pfx into an in-memory cert store
 *   CertFindCertificateInStore(HAS_PRIVATE_KEY) — pick the signing cert
 *   LoadLibrary mssign32     — resolve SignerSignEx2 at runtime
 *   SignerSignEx2            — signs the PE in place; optionally counter-
 *                              signs with an RFC 3161 timestamp authority
 *
 * The cert store and PCCERT_CONTEXT must outlive the SignerSignEx2 call.
 */
#include "PeSigning.h"

#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>

#pragma comment(lib, "Crypt32.lib")

/* ── mssign32.dll struct/enum declarations ─────────────────────────────────
 * Mirrors the public mssign32.h SDK header. Field order, sizes, and union
 * layout match the Windows ABI exactly — do not reorder. */

typedef struct _SIGNER_FILE_INFO {
    DWORD       cbSize;
    LPCWSTR     pwszFileName;
    HANDLE      hFile;
} SIGNER_FILE_INFO, *PSIGNER_FILE_INFO;

typedef struct _SIGNER_BLOB_INFO {
    DWORD       cbSize;
    GUID*       pGuidSubject;
    DWORD       cbBlob;
    BYTE*       pbBlob;
    LPCWSTR     pwszDisplayName;
} SIGNER_BLOB_INFO, *PSIGNER_BLOB_INFO;

typedef struct _SIGNER_SUBJECT_INFO {
    DWORD       cbSize;
    DWORD*      pdwIndex;
    DWORD       dwSubjectChoice;
    union {
        SIGNER_FILE_INFO* pSignerFileInfo;
        SIGNER_BLOB_INFO* pSignerBlobInfo;
    };
} SIGNER_SUBJECT_INFO, *PSIGNER_SUBJECT_INFO;

#define SIGNER_SUBJECT_FILE     0x01
#define SIGNER_SUBJECT_BLOB     0x02

typedef struct _SIGNER_CERT_STORE_INFO {
    DWORD              cbSize;
    PCCERT_CONTEXT     pSigningCert;
    DWORD              dwCertPolicy;
    HCERTSTORE         hCertStore;
} SIGNER_CERT_STORE_INFO, *PSIGNER_CERT_STORE_INFO;

#define SIGNER_CERT_POLICY_STORE         0x01
#define SIGNER_CERT_POLICY_CHAIN         0x02
#define SIGNER_CERT_POLICY_SPC           0x04
#define SIGNER_CERT_POLICY_CHAIN_NO_ROOT 0x08

typedef struct _SIGNER_SPC_CHAIN_INFO {
    DWORD              cbSize;
    LPCWSTR            pwszSpcFile;
    DWORD              dwCertPolicy;
    HCERTSTORE         hCertStore;
} SIGNER_SPC_CHAIN_INFO, *PSIGNER_SPC_CHAIN_INFO;

typedef struct _SIGNER_CERT {
    DWORD              cbSize;
    DWORD              dwCertChoice;
    union {
        LPCWSTR                 pwszSpcFile;
        SIGNER_CERT_STORE_INFO* pCertStoreInfo;
        SIGNER_SPC_CHAIN_INFO*  pSpcChainInfo;
    };
    HWND               hwnd;
} SIGNER_CERT, *PSIGNER_CERT;

#define SIGNER_CERT_SPC_FILE   0x01
#define SIGNER_CERT_STORE      0x02
#define SIGNER_CERT_SPC_CHAIN  0x03

typedef struct _SIGNER_ATTR_AUTHCODE {
    DWORD              cbSize;
    BOOL               fCommercial;
    BOOL               fIndividual;
    LPCWSTR            pwszName;
    LPCWSTR            pwszInfo;
} SIGNER_ATTR_AUTHCODE, *PSIGNER_ATTR_AUTHCODE;

typedef struct _SIGNER_SIGNATURE_INFO {
    DWORD              cbSize;
    ALG_ID             algidHash;
    DWORD              dwAttrChoice;
    union {
        SIGNER_ATTR_AUTHCODE* pAttrAuthcode;
    };
    PCRYPT_ATTRIBUTES  psAuthenticated;
    PCRYPT_ATTRIBUTES  psUnauthenticated;
} SIGNER_SIGNATURE_INFO, *PSIGNER_SIGNATURE_INFO;

#define SIGNER_NO_ATTR         0x00
#define SIGNER_AUTHCODE_ATTR   0x01

typedef struct _SIGNER_PROVIDER_INFO {
    DWORD              cbSize;
    LPCWSTR            pwszProviderName;
    DWORD              dwProviderType;
    DWORD              dwKeySpec;
    DWORD              dwPvkChoice;
    union {
        LPWSTR             pwszPvkFileName;
        LPWSTR             pwszKeyContainer;
    };
} SIGNER_PROVIDER_INFO, *PSIGNER_PROVIDER_INFO;

typedef struct _SIGNER_CONTEXT {
    DWORD              cbSize;
    DWORD              cbBlob;
    BYTE*              pbBlob;
} SIGNER_CONTEXT, *PSIGNER_CONTEXT;

/* SignerSignEx2 dwTimestampFlags — only RFC 3161 is relevant for us
 * (Authenticode legacy timestamps were the SHA1-only flavour, deprecated). */
#define SIGNER_TIMESTAMP_AUTHENTICODE  1
#define SIGNER_TIMESTAMP_RFC3161       2

/* PFXImportCertStore flags missing from older wincrypt.h shipped with some SDKs.
 * Defined here so the project does not require a specific SDK version.
 *   PKCS12_PREFER_CNG_KSP / PKCS12_ALWAYS_CNG_KSP — control which key storage
 *     provider receives the private key. Without one of these, the import may
 *     land in a legacy CSP that mssign32!SignerSignEx2 cannot then enumerate,
 *     producing NTE_BAD_TYPE (0x8009000A) at signing time for PFX files that
 *     PowerShell New-SelfSignedCertificate / OpenSSL 3.x produce by default. */
#ifndef PKCS12_PREFER_CNG_KSP
#define PKCS12_PREFER_CNG_KSP   0x00000100
#endif
#ifndef PKCS12_ALWAYS_CNG_KSP
#define PKCS12_ALWAYS_CNG_KSP   0x00000200
#endif
#ifndef PKCS12_NO_PERSIST_KEY
#define PKCS12_NO_PERSIST_KEY   0x00008000
#endif
#ifndef PKCS12_INCLUDE_EXTENDED_PROPERTIES
#define PKCS12_INCLUDE_EXTENDED_PROPERTIES 0x00000010
#endif

/* Translate the small set of HRESULTs we are most likely to see from
 * PFXImportCertStore / SignerSignEx2 into a one-line operator hint. */
static const char* SignErrorHint(HRESULT hr) {
    switch ((DWORD)hr) {
        case 0x80090001: return "NTE_BAD_UID (wrong key container)";
        case 0x80090005: return "NTE_BAD_DATA (corrupt PFX or wrong format)";
        case 0x80090008: return "NTE_BAD_ALGID (cert algorithm not supported)";
        case 0x80090009: return "NTE_BAD_FLAGS (signer flag combination invalid)";
        case 0x8009000A: return "NTE_BAD_TYPE (key spec mismatch — likely CNG/CSP issue)";
        case 0x8009000B: return "NTE_BAD_KEY_STATE";
        case 0x8009000D: return "NTE_NO_KEY (cert has no private key)";
        case 0x80070056: return "ERROR_INVALID_PASSWORD (wrong --pfx-pass)";
        case 0x80092002: return "CRYPT_E_BAD_ENCODE";
        case 0x80092004: return "CRYPT_E_NOT_FOUND";
        case 0x800B0100: return "TRUST_E_NOSIGNATURE";
        default:         return "see WinError.h / certutil -error <code>";
    }
}

typedef HRESULT (WINAPI* PFN_SignerSignEx2)(
    DWORD                    dwFlags,
    SIGNER_SUBJECT_INFO*     pSubjectInfo,
    SIGNER_CERT*             pSignerCert,
    SIGNER_SIGNATURE_INFO*   pSignatureInfo,
    SIGNER_PROVIDER_INFO*    pProviderInfo,
    DWORD                    dwTimestampFlags,
    PCSTR                    pszTimestampAlgorithmOid,
    PCWSTR                   pwszHttpTimeStamp,
    PCRYPT_ATTRIBUTES        psRequest,
    LPVOID                   pSipData,
    SIGNER_CONTEXT**         ppSignerContext,
    PCERT_STRONG_SIGN_PARA   pCryptoPolicy,
    LPVOID                   pReserved
);

/* Convert UTF-8/ANSI argv string to a heap-allocated wide string.
 * Caller frees with HeapFree(GetProcessHeap(), 0, ptr). Returns NULL on
 * failure or if input is NULL/empty. */
static LPWSTR AnsiToWideAlloc(const char* s) {
    if (!s || !*s) return NULL;
    int wlen = MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0);
    if (wlen <= 0) return NULL;
    LPWSTR w = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, wlen * sizeof(WCHAR));
    if (!w) return NULL;
    if (MultiByteToWideChar(CP_ACP, 0, s, -1, w, wlen) <= 0) {
        HeapFree(GetProcessHeap(), 0, w);
        return NULL;
    }
    return w;
}

BOOL SignPeWithPfx(const char* outputPath,
                   const char* pfxPath,
                   const char* pfxPassword,
                   const char* timestampUrl)
{
    if (!outputPath || !pfxPath) return FALSE;

    BOOL              bSuccess     = FALSE;
    LPWSTR            wOutputPath  = NULL;
    LPWSTR            wPfxPath     = NULL;
    LPWSTR            wPfxPassword = NULL;
    LPWSTR            wTimestamp   = NULL;
    HANDLE            hPfxFile     = INVALID_HANDLE_VALUE;
    HCERTSTORE        hCertStore   = NULL;
    PCCERT_CONTEXT    pCertContext = NULL;
    HMODULE           hMssign32    = NULL;
    BYTE*             pPfxData     = NULL;
    LARGE_INTEGER     pfxSize      = { 0 };

    wOutputPath = AnsiToWideAlloc(outputPath);
    wPfxPath    = AnsiToWideAlloc(pfxPath);
    if (!wOutputPath || !wPfxPath) {
        fprintf(stderr, "[!] Signing: path conversion failed\n");
        goto cleanup;
    }
    /* Password may legitimately be NULL/empty — PFX without a passphrase. */
    if (pfxPassword && *pfxPassword) {
        wPfxPassword = AnsiToWideAlloc(pfxPassword);
        if (!wPfxPassword) {
            fprintf(stderr, "[!] Signing: password conversion failed\n");
            goto cleanup;
        }
    }
    if (timestampUrl && *timestampUrl) {
        wTimestamp = AnsiToWideAlloc(timestampUrl);
        if (!wTimestamp) {
            fprintf(stderr, "[!] Signing: timestamp URL conversion failed\n");
            goto cleanup;
        }
    }

    /* Read the .pfx into memory — PFXImportCertStore wants a CRYPT_DATA_BLOB. */
    hPfxFile = CreateFileW(wPfxPath, GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hPfxFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[!] Signing: cannot open PFX (LastError=%lu)\n", GetLastError());
        goto cleanup;
    }
    if (!GetFileSizeEx(hPfxFile, &pfxSize) || pfxSize.QuadPart <= 0 || pfxSize.QuadPart > 16 * 1024 * 1024) {
        fprintf(stderr, "[!] Signing: PFX size invalid or too large\n");
        goto cleanup;
    }
    pPfxData = (BYTE*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)pfxSize.QuadPart);
    if (!pPfxData) goto cleanup;

    /* All variables that appear past this point are declared with
     * initialisers, so they sit inside an explicit block — C++ forbids
     * `goto` jumping *into* the scope of an initialised variable, but
     * jumping *out* (toward `cleanup:` below the closing brace) is fine. */
  {
    DWORD bytesRead = 0;
    if (!ReadFile(hPfxFile, pPfxData, (DWORD)pfxSize.QuadPart, &bytesRead, NULL) ||
        bytesRead != (DWORD)pfxSize.QuadPart) {
        fprintf(stderr, "[!] Signing: PFX read failed\n");
        goto cleanup;
    }
    CloseHandle(hPfxFile);
    hPfxFile = INVALID_HANDLE_VALUE;

    CRYPT_DATA_BLOB pfxBlob;
    pfxBlob.cbData = (DWORD)pfxSize.QuadPart;
    pfxBlob.pbData = pPfxData;

    /* PKCS12_NO_PERSIST_KEY keeps the private key in-memory only — no spurious
     * key container files under %APPDATA%\Microsoft\Crypto.
     *
     * PKCS12_PREFER_CNG_KSP routes the import through the modern CNG provider
     * (with CSP fallback). Without it, PFX files produced by current tooling
     * (PowerShell New-SelfSignedCertificate, OpenSSL 3.x) leave the key in a
     * shape that SignerSignEx2 rejects with NTE_BAD_TYPE.
     *
     * PKCS12_INCLUDE_EXTENDED_PROPERTIES preserves key-usage hints (Code
     * Signing EKU, AT_SIGNATURE vs AT_KEYEXCHANGE) that the signer reads. */
    hCertStore = PFXImportCertStore(&pfxBlob, wPfxPassword,
                                    PKCS12_NO_PERSIST_KEY |
                                    PKCS12_PREFER_CNG_KSP |
                                    PKCS12_INCLUDE_EXTENDED_PROPERTIES);
    if (!hCertStore) {
        DWORD le = GetLastError();
        fprintf(stderr, "[!] Signing: PFXImportCertStore failed (LastError=0x%08lX — %s)\n",
                le, SignErrorHint((HRESULT)le));
        goto cleanup;
    }

    pCertContext = CertFindCertificateInStore(hCertStore,
                                              X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                              0, CERT_FIND_HAS_PRIVATE_KEY, NULL, NULL);
    if (!pCertContext) {
        fprintf(stderr, "[!] Signing: no cert with private key found in PFX\n");
        goto cleanup;
    }

    hMssign32 = LoadLibraryA("mssign32.dll");
    if (!hMssign32) {
        fprintf(stderr, "[!] Signing: LoadLibrary mssign32.dll failed\n");
        goto cleanup;
    }
    PFN_SignerSignEx2 pfnSignerSignEx2 =
        (PFN_SignerSignEx2)GetProcAddress(hMssign32, "SignerSignEx2");
    if (!pfnSignerSignEx2) {
        fprintf(stderr, "[!] Signing: SignerSignEx2 not exported\n");
        goto cleanup;
    }

    SIGNER_FILE_INFO fileInfo  = { sizeof(fileInfo), wOutputPath, NULL };
    DWORD            indexZero = 0;
    SIGNER_SUBJECT_INFO subjInfo = { sizeof(subjInfo), &indexZero, SIGNER_SUBJECT_FILE };
    subjInfo.pSignerFileInfo = &fileInfo;

    SIGNER_CERT_STORE_INFO certStoreInfo;
    certStoreInfo.cbSize       = sizeof(certStoreInfo);
    certStoreInfo.pSigningCert = pCertContext;
    certStoreInfo.dwCertPolicy = SIGNER_CERT_POLICY_CHAIN;
    certStoreInfo.hCertStore   = hCertStore;

    SIGNER_CERT signerCert;
    signerCert.cbSize         = sizeof(signerCert);
    signerCert.dwCertChoice   = SIGNER_CERT_STORE;
    signerCert.pCertStoreInfo = &certStoreInfo;
    signerCert.hwnd           = NULL;

    SIGNER_SIGNATURE_INFO sigInfo;
    ZeroMemory(&sigInfo, sizeof(sigInfo));
    sigInfo.cbSize            = sizeof(sigInfo);
    sigInfo.algidHash         = CALG_SHA_256;
    sigInfo.dwAttrChoice      = SIGNER_NO_ATTR;
    sigInfo.psAuthenticated   = NULL;
    sigInfo.psUnauthenticated = NULL;

    DWORD            tsFlags = 0;
    PCSTR            tsOid   = NULL;
    if (wTimestamp) {
        tsFlags = SIGNER_TIMESTAMP_RFC3161;
        tsOid   = szOID_NIST_sha256;
    }

    SIGNER_CONTEXT* pSignerCtx = NULL;
    HRESULT hr = pfnSignerSignEx2(
        0,                  /* dwFlags */
        &subjInfo,
        &signerCert,
        &sigInfo,
        NULL,               /* pProviderInfo — cert already has private-key linkage */
        tsFlags,
        tsOid,
        wTimestamp,
        NULL,               /* psRequest */
        NULL,               /* pSipData */
        &pSignerCtx,
        NULL,               /* pCryptoPolicy */
        NULL);              /* pReserved */

    if (hr != S_OK) {
        fprintf(stderr, "[!] Signing: SignerSignEx2 returned 0x%08lX — %s\n",
                (DWORD)hr, SignErrorHint(hr));
        goto cleanup;
    }

    if (pSignerCtx) {
        /* SignerFreeSignerContext is the documented disposer; resolved lazily
         * because we already have the module handle in hand. */
        typedef HRESULT (WINAPI* PFN_SignerFreeSignerContext)(SIGNER_CONTEXT*);
        PFN_SignerFreeSignerContext pfnFree =
            (PFN_SignerFreeSignerContext)GetProcAddress(hMssign32, "SignerFreeSignerContext");
        if (pfnFree) pfnFree(pSignerCtx);
    }

    bSuccess = TRUE;
  }   /* end of late-declaration block — see comment above PFX read */

cleanup:
    if (pCertContext) CertFreeCertificateContext(pCertContext);
    /* CERT_CLOSE_STORE_FORCE_FLAG releases private-key handles tied to the store
     * (PKCS12_NO_PERSIST_KEY links them to hCertStore's lifetime). */
    if (hCertStore)   CertCloseStore(hCertStore, CERT_CLOSE_STORE_FORCE_FLAG);
    if (hMssign32)    FreeLibrary(hMssign32);
    if (hPfxFile != INVALID_HANDLE_VALUE) CloseHandle(hPfxFile);
    if (pPfxData) {
        SecureZeroMemory(pPfxData, (SIZE_T)pfxSize.QuadPart);
        HeapFree(GetProcessHeap(), 0, pPfxData);
    }
    if (wPfxPassword) {
        SecureZeroMemory(wPfxPassword, lstrlenW(wPfxPassword) * sizeof(WCHAR));
        HeapFree(GetProcessHeap(), 0, wPfxPassword);
    }
    if (wOutputPath) HeapFree(GetProcessHeap(), 0, wOutputPath);
    if (wPfxPath)    HeapFree(GetProcessHeap(), 0, wPfxPath);
    if (wTimestamp)  HeapFree(GetProcessHeap(), 0, wTimestamp);
    return bSuccess;
}
