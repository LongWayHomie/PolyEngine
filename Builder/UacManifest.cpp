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

int EmbedUacManifest(const char* targetPath) {
    HANDLE hUpdate = BeginUpdateResourceA(targetPath, FALSE);
    if (!hUpdate) {
        fprintf(stderr, "[!] UAC manifest: BeginUpdateResourceA failed (GLE=%lu)\n", GetLastError());
        return 101;
    }

    DWORD xmlLen = (DWORD)(sizeof(kUacManifestXml) - 1);   /* exclude NUL terminator */

    if (!UpdateResourceA(hUpdate,
                         (LPCSTR)RT_MANIFEST,
                         MAKEINTRESOURCEA(1),       /* CREATEPROCESS_MANIFEST_RESOURCE_ID */
                         MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                         (LPVOID)kUacManifestXml,
                         xmlLen)) {
        fprintf(stderr, "[!] UAC manifest: UpdateResourceA failed (GLE=%lu)\n", GetLastError());
        EndUpdateResource(hUpdate, TRUE);           /* discard — don't commit partial change */
        return 102;
    }

    if (!EndUpdateResource(hUpdate, FALSE)) {
        fprintf(stderr, "[!] UAC manifest: EndUpdateResource failed (GLE=%lu)\n", GetLastError());
        return 103;
    }

    return 0;
}
