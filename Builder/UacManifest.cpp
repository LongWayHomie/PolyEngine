#include "UacManifest.h"
#include <stdio.h>

/* Minimal manifest requesting administrator elevation.  Embedded as RT_MANIFEST,
 * resource ID 1 (CREATEPROCESS_MANIFEST_RESOURCE_ID) — the Windows loader reads
 * this slot on process creation and issues a UAC prompt when the process does not
 * already have a high-integrity token. */
static const char kUacManifestXml[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
    "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\r\n"
    "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">\r\n"
    "    <security>\r\n"
    "      <requestedPrivileges>\r\n"
    "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/>\r\n"
    "      </requestedPrivileges>\r\n"
    "    </security>\r\n"
    "  </trustInfo>\r\n"
    "</assembly>\r\n";

/* Default manifest for non-elevated builds.  Every modern legit exe carries an
 * asInvoker trustInfo manifest — its complete absence is a static anomaly. */
static const char kDefaultManifestXml[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
    "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\r\n"
    "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">\r\n"
    "    <security>\r\n"
    "      <requestedPrivileges>\r\n"
    "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>\r\n"
    "      </requestedPrivileges>\r\n"
    "    </security>\r\n"
    "  </trustInfo>\r\n"
    "</assembly>\r\n";

static int EmbedManifest(const char* targetPath, const char* xml, DWORD xmlLen) {
    HANDLE hUpdate = BeginUpdateResourceA(targetPath, FALSE);
    if (!hUpdate) {
        fprintf(stderr, "[!] manifest: BeginUpdateResourceA failed (GLE=%lu)\n", GetLastError());
        return 101;
    }

    if (!UpdateResourceA(hUpdate,
                         (LPCSTR)RT_MANIFEST,
                         MAKEINTRESOURCEA(1),       /* CREATEPROCESS_MANIFEST_RESOURCE_ID */
                         MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                         (LPVOID)xml,
                         xmlLen)) {
        fprintf(stderr, "[!] manifest: UpdateResourceA failed (GLE=%lu)\n", GetLastError());
        EndUpdateResource(hUpdate, TRUE);           /* discard — don't commit partial change */
        return 102;
    }

    if (!EndUpdateResource(hUpdate, FALSE)) {
        fprintf(stderr, "[!] manifest: EndUpdateResource failed (GLE=%lu)\n", GetLastError());
        return 103;
    }

    return 0;
}

int EmbedUacManifest(const char* targetPath) {
    return EmbedManifest(targetPath, kUacManifestXml, (DWORD)(sizeof(kUacManifestXml) - 1));
}

int EmbedDefaultManifest(const char* targetPath) {
    return EmbedManifest(targetPath, kDefaultManifestXml, (DWORD)(sizeof(kDefaultManifestXml) - 1));
}
