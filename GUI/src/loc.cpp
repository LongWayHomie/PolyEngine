#include "loc.h"
#include <algorithm>

namespace peg {

// Full EN/PL tables — ported verbatim from Strings.cs.
static const std::map<std::string, std::string> kEn = {
    {"App.Title", "PolyEngine GUI"},
    {"Nav.Build", "Build"},
    {"Nav.Profiles", "Profiles"},
    {"Nav.History", "History"},
    {"Nav.Settings", "Settings"},
    {"Common.Browse", "Browse\u2026"},
    {"Common.Save", "Save"},
    {"Common.Delete", "Delete"},
    {"Common.Apply", "Apply"},
    {"Common.Copy", "Copy"},
    {"Common.Clear", "Clear"},
    {"Common.Build", "Build"},
    {"Common.Cancel", "Cancel"},
    {"Common.None", "(none)"},
    {"Build.PayloadSection", "Payload"},
    {"Build.Subtitle", "Map Builder.exe flags to a form, build, and inspect the output."},
    {"Build.InputPath", "Input payload (.exe / .dll / .bin)"},
    {"Build.OutputPath", "Output executable"},
    {"Build.StubPath", "Loader stub (optional \u2014 default: random stub_v0\u2026v3)"},
    {"Build.LoaderSection", "Loader"},
    {"Build.Preset", "Module stomping preset"},
    {"Build.Overload", "Module overloading (--overload) \u2014 NtCreateSection/NtMapViewOfSection, not in PEB LDR"},
    {"Build.KeepAlive", "Keep alive (--keep-alive) \u2014 ExitThread instead of ExitProcess (required for C2 beacons)"},
    {"Build.Unhook", "Unhook (--unhook) \u2014 restore clean .text of ntdll/kernel32/kernelbase from \\KnownDlls\\"},
    {"Build.PayloadOptionsSection", "Payload options (PE/DLL only)"},
    {"Build.ExportName", "Export to invoke (--export)"},
    {"Build.ExportArg", "Export argument (--arg, max 127 chars)"},
    {"Build.EvasionSection", "Evasion (everything ON by default \u2014 uncheck to disable)"},
    {"Build.EvasionTuning", "Tuning"},
    {"Build.EvasionOpsec", "OPSEC features"},
    {"Build.EvasionSandbox", "Sandbox / debug checks"},
    {"Build.SpoofName", "PEB spoof process name"},
    {"Build.ExecCtrlName", "Exec-control semaphore name (max 31 chars)"},
    {"Build.SleepFwdMs", "Sleep-fwd check (ms)"},
    {"Build.UptimeMin", "Uptime threshold (minutes)"},
    {"Build.HammerS", "API-hammer delay (seconds)"},
    {"Build.IdentitySection", "Identity"},
    {"Build.PfxPath", "PFX certificate (--pfx)"},
    {"Build.PfxPassword", "PFX password (--pfx-pass)"},
    {"Build.TsUrl", "RFC 3161 timestamp URL (--ts-url)"},
    {"Build.CloneMetaPath", "Clone metadata donor PE (--clone-meta)"},
    {"Build.Uac", "UAC elevation manifest (--uac, requireAdministrator)"},
    {"Build.ProfileSection", "Profile"},
    {"Build.Profile", "Apply a saved profile"},
    {"Build.CommandPreview", "Command preview"},
    {"Build.ValidationHeader", "Validation"},
    {"Build.Log", "Build log"},
    {"Build.Progress", "Phase {0} / 12"},
    {"Build.Building", "Build in progress\u2026"},
    {"Build.Succeeded", "Build finished successfully in {0} s"},
    {"Build.Failed", "Build failed (exit code {0})"},
    {"Build.Cancelled", "Build cancelled."},
    {"Build.OutputInfo", "Output: {0}"},
    {"Build.Size", "Size: {0} bytes"},
    {"Build.Sha256", "SHA-256: {0}"},
    {"Build.SigNotSigned", "Signature: not signed"},
    {"Build.SigSignedUnverified", "Signature: {0} (presence only \u2014 hash not verified)"},
    {"Build.BuilderNotConfigured", "Builder.exe not found \u2014 set the path in Settings."},
    {"Build.StubsMissing", "No stub_v*.bin files found in the stub directory."},
    {"Build.DialogInput", "Select input payload"},
    {"Build.DialogOutput", "Select output executable"},
    {"Build.DialogStub", "Select loader stub"},
    {"Build.DialogPfx", "Select PFX certificate"},
    {"Build.DialogCloneMeta", "Select donor PE"},
    {"Build.FilterPayload", "Payloads (*.exe;*.dll;*.bin)|*.exe;*.dll;*.bin|All files (*.*)|*.*"},
    {"Build.FilterExe", "Executables (*.exe)|*.exe|All files (*.*)|*.*"},
    {"Build.FilterStub", "Loader stubs (*.bin)|*.bin|All files (*.*)|*.*"},
    {"Build.FilterPfx", "PFX certificates (*.pfx;*.p12)|*.pfx;*.p12|All files (*.*)|*.*"},
    {"Token.etw", "ETW patch (EtwEventWrite \u2192 STATUS_SUCCESS)"},
    {"Token.amsi", "AMSI patch (AmsiScanBuffer \u2192 E_INVALIDARG)"},
    {"Token.blockdlls", "Block non-Microsoft-signed DLL loads"},
    {"Token.spoofing", "Call-stack spoofing (SilentMoonwalk RSP pivot)"},
    {"Token.peb", "PEB path/cmdline spoof"},
    {"Token.tls", "TLS anti-debug callback"},
    {"Token.hammer", "API-hammer timing delay"},
    {"Token.debugger", "Debugger detection (PEB flags / NtQueryInformationProcess)"},
    {"Token.api-emu", "API emulation probe (RtlComputeCrc32)"},
    {"Token.exec-ctrl", "Execution-control semaphore"},
    {"Token.sleep-fwd", "Sleep-forwarding detection"},
    {"Token.uptime", "System uptime check"},
    {"Token.cpu", "CPU count check (< 2 cores)"},
    {"Token.screen", "Screen resolution check (\u2264 1024 px)"},
    {"Token.files", "Recent-files count check (< 5)"},
    {"Validation.InputRequired", "Input payload path is required."},
    {"Validation.InputNotFound", "Input file does not exist."},
    {"Validation.InputInvalidExtension", "Input must be .exe, .dll or .bin."},
    {"Validation.OutputRequired", "Output path is required."},
    {"Validation.InvalidPreset", "Preset must be PRINT, MEDIA, NETWORK or RANDOM."},
    {"Validation.ExportNameTooLong", "Export name exceeds 63 characters."},
    {"Validation.ExportArgTooLong", "Export argument exceeds 127 characters."},
    {"Validation.SpoofNameTooLong", "Spoof name exceeds 63 characters."},
    {"Validation.ExecCtrlNameTooLong", "Semaphore name exceeds 31 characters."},
    {"Validation.ExportRequiresDll", "--export applies only to DLL payloads."},
    {"Validation.PfxPasswordRequiresPfx", "--pfx-pass requires --pfx."},
    {"Validation.PfxRequiresPassword", "PFX certificate requires a password (--pfx-pass)."},
    {"Validation.TsUrlRequiresPfx", "--ts-url requires --pfx."},
    {"Validation.WarnTsUrlOpsec", "OPSEC: timestamping reveals build IP/time to the TSA."},
    {"Validation.WarnTsUrlFormat", "Timestamp URL should start with http:// or https://."},
    {"Validation.NumberOutOfRange", "Value out of range: {0}"},
    {"Validation.PfxNotFound", "PFX file does not exist."},
    {"Validation.CloneMetaNotFound", "Clone-meta donor PE does not exist."},
    {"Validation.WarnPfxPasswordVisible", "OPSEC: the PFX password lands in the process command line (visible in process listings)."},
    {"Validation.WarnAllEvasionDisabled", "All evasion disabled (--disable all) \u2014 this also turns off OPSEC features (ETW/AMSI patch, spoofing)."},
    {"Validation.WarnKeepAliveSuggested", "If the payload spawns its own threads (C2 beacon), enable --keep-alive."},
    {"Validation.InvalidNumber", "Not a valid number: {0}"},
    {"Validation.BuilderNotConfigured", "Builder.exe not found \u2014 set the path in Settings."},
    {"Validation.StubsMissing", "No stub_v*.bin files found in the stub directory."},
    {"Profiles.Heading", "Configuration profiles"},
    {"Profiles.Subtitle", "Save operator presets as JSON; factory presets are always available."},
    {"Profiles.Name", "Profile name"},
    {"Profiles.Description", "Description"},
    {"Profiles.SaveCurrent", "Save current Build configuration as profile"},
    {"Profiles.Factory", "built-in"},
    {"Profiles.NameRequired", "Enter a profile name first."},
    {"Profiles.Saved", "Profile '{0}' saved."},
    {"Profiles.Deleted", "Profile '{0}' deleted."},
    {"Profiles.Empty", "No profiles yet. Factory presets are always available."},
    {"History.Heading", "Build history"},
    {"History.Subtitle", "Past builds with full command lines and output hashes."},
    {"History.Refresh", "Refresh"},
    {"History.Flush", "Flush Logs"},
    {"History.Empty", "No builds recorded yet."},
    {"History.Time", "Time"},
    {"History.Command", "Command"},
    {"History.Result", "Result"},
    {"History.Size", "Size"},
    {"History.Signature", "Signature"},
    {"History.Rerun", "Load into Build page"},
    {"History.Success", "Success"},
    {"History.Failed", "Failed (exit {0})"},
    {"History.Cancelled", "Cancelled"},
    {"History.NotSigned", "not signed"},
    {"Settings.Heading", "Settings"},
    {"Settings.Subtitle", "Paths to Builder.exe, stubs and the output directory."},
    {"Settings.PathsHeading", "Paths"},
    {"Settings.BuilderPath", "Builder.exe path"},
    {"Settings.StubDirectory", "Stub directory (stub_v*.bin)"},
    {"Settings.OutputDirectory", "Default output directory"},
    {"Settings.Language", "Language / J\u0119zyk"},
    {"Settings.Saved", "Settings saved."},
    {"Settings.DialogBuilder", "Select Builder.exe"},
    {"Settings.FilterBuilder", "Builder.exe|Builder.exe|Executables (*.exe)|*.exe"},
    {"Settings.PathsNote", "Defaults point at the folder this app runs from \u2014 drop PolyEngine.GUI.exe next to Builder.exe and everything resolves automatically."},
};


Loc& Loc::instance() {
    static Loc loc;
    return loc;
}

// English-only (Polish removed on request). setLanguage stays as a no-op shim so
// callers that previously switched tables keep working.
void Loc::setLanguage(const std::string&) {
    language_ = "en";
    table_ = &kEn;
}

void Loc::rebuild() {
    table_ = &kEn;
}

const std::string& Loc::operator[](const std::string& key) const {
    auto it = table_->find(key);
    if (it != table_->end()) return it->second;
    auto fallback = kEn.find(key);
    if (fallback != kEn.end()) return fallback->second;
    static const std::string kMissing = key;
    return kMissing;
}

std::string Loc::format(const std::string& key, const std::string& arg0) const {
    std::string tmpl = (*this)[key];
    std::string out;
    size_t pos = 0;
    while (true) {
        size_t at = tmpl.find("{0}", pos);
        if (at == std::string::npos) { out += tmpl.substr(pos); break; }
        out += tmpl.substr(pos, at - pos);
        out += arg0;
        pos = at + 3;
    }
    return out;
}

} // namespace peg
