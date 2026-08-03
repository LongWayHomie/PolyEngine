#include "services.h"
#include "json.h"
#include <windows.h>
#include <bcrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <shlwapi.h>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <cctype>
#include <chrono>
#include <algorithm>
#include <cwctype>
#include <filesystem>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")

namespace peg {

// ── UTF helpers ────────────────────────────────────────────────────────────────

std::wstring utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), nullptr, 0);
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), out.data(), n);
    return out;
}

std::string wideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), nullptr, 0, nullptr, nullptr);
    std::string out((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), out.data(), n, nullptr, nullptr);
    return out;
}

// ── small helpers ──────────────────────────────────────────────────────────────

bool fileExists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

bool dirExists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY);
}

std::string getFileExtensionUtf8(const std::string& path) {
    auto pos = path.find_last_of('.');
    if (pos == std::string::npos) return {};
    auto slash = path.find_last_of("/\\");
    if (slash != std::string::npos && slash > pos) return {};
    return path.substr(pos);
}

bool isPathRooted(const std::wstring& path) {
    return !path.empty() && (path[0] == L'\\' || (path.size() >= 2 && path[1] == L':'));
}

std::wstring fullPathOf(const std::wstring& path, const std::wstring& relativeToDir) {
    std::wstring combined = isPathRooted(path) ? path : (relativeToDir + L"\\" + path);
    wchar_t buf[MAX_PATH * 2];
    DWORD len = GetFullPathNameW(combined.c_str(), MAX_PATH * 2, buf, nullptr);
    if (len == 0) return combined;
    return std::wstring(buf, len);
}

std::string toLowerAscii(const std::string& s) {
    std::string out = s;
    for (auto& c : out) if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
    return out;
}

std::string trimWhitespace(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace((unsigned char)s[b])) b++;
    while (e > b && std::isspace((unsigned char)s[e - 1])) e--;
    return s.substr(b, e - b);
}

std::vector<std::string> findStubVFiles(const std::wstring& directory) {
    std::vector<std::string> out;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((directory + L"\\stub_v*.bin").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                out.push_back(wideToUtf8(fd.cFileName));
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    return out;
}

std::string codeName(ValidationCode code) {
    switch (code) {
        case ValidationCode::InputRequired: return "InputRequired";
        case ValidationCode::InputNotFound: return "InputNotFound";
        case ValidationCode::InputInvalidExtension: return "InputInvalidExtension";
        case ValidationCode::OutputRequired: return "OutputRequired";
        case ValidationCode::InvalidPreset: return "InvalidPreset";
        case ValidationCode::ExportNameTooLong: return "ExportNameTooLong";
        case ValidationCode::ExportArgTooLong: return "ExportArgTooLong";
        case ValidationCode::SpoofNameTooLong: return "SpoofNameTooLong";
        case ValidationCode::ExecCtrlNameTooLong: return "ExecCtrlNameTooLong";
        case ValidationCode::ExportRequiresDll: return "ExportRequiresDll";
        case ValidationCode::PfxPasswordRequiresPfx: return "PfxPasswordRequiresPfx";
        case ValidationCode::PfxRequiresPassword: return "PfxRequiresPassword";
        case ValidationCode::TsUrlRequiresPfx: return "TsUrlRequiresPfx";
        case ValidationCode::WarnTsUrlOpsec: return "WarnTsUrlOpsec";
        case ValidationCode::WarnTsUrlFormat: return "WarnTsUrlFormat";
        case ValidationCode::WarnPfxPasswordVisible: return "WarnPfxPasswordVisible";
        case ValidationCode::WarnAllEvasionDisabled: return "WarnAllEvasionDisabled";
        case ValidationCode::WarnKeepAliveSuggested: return "WarnKeepAliveSuggested";
        case ValidationCode::InvalidNumber: return "InvalidNumber";
        case ValidationCode::NumberOutOfRange: return "NumberOutOfRange";
        case ValidationCode::PfxNotFound: return "PfxNotFound";
        case ValidationCode::CloneMetaNotFound: return "CloneMetaNotFound";
        case ValidationCode::BuilderNotConfigured: return "BuilderNotConfigured";
        case ValidationCode::StubsMissing: return "StubsMissing";
    }
    return "";
}

bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    return _stricmp(a.c_str(), b.c_str()) == 0;
}

// ── DisableTokens ──────────────────────────────────────────────────────────────

const std::vector<std::string> kOpsecTokens = {"etw", "amsi", "blockdlls", "spoofing", "peb", "tls"};
const std::vector<std::string> kSandboxTokens =
    {"hammer", "debugger", "api-emu", "exec-ctrl", "sleep-fwd", "uptime", "cpu", "screen", "files"};

std::vector<std::string> allTokens() {
    std::vector<std::string> out = kOpsecTokens;
    out.insert(out.end(), kSandboxTokens.begin(), kSandboxTokens.end());
    return out;
}

// ── ArgBuilder ─────────────────────────────────────────────────────────────────

static void addFlag(std::vector<std::string>& args, const std::string& flag, const std::string& value) {
    args.push_back(flag);
    args.push_back(value);
}

std::vector<std::string> buildArguments(const BuildConfig& cfg) {
    std::vector<std::string> args{cfg.inputPath, cfg.outputPath};

    if (!trimWhitespace(cfg.stubPath).empty()) addFlag(args, "--stub", cfg.stubPath);
    if (!iequals(cfg.preset, "PRINT")) {
        std::string upper = cfg.preset;
        for (auto& c : upper) c = (char)std::toupper((unsigned char)c);
        addFlag(args, "--preset", upper);
    }

    if (cfg.overload) args.push_back("--overload");
    if (cfg.keepAlive) args.push_back("--keep-alive");
    if (cfg.unhook) args.push_back("--unhook");

    if (!trimWhitespace(cfg.exportName).empty()) addFlag(args, "--export", cfg.exportName);
    if (!trimWhitespace(cfg.exportArg).empty()) addFlag(args, "--arg", cfg.exportArg);

    if (!trimWhitespace(cfg.spoofName).empty()) addFlag(args, "--spoof-name", cfg.spoofName);
    if (!trimWhitespace(cfg.execCtrlName).empty()) addFlag(args, "--exec-ctrl-name", cfg.execCtrlName);
    if (cfg.sleepFwdMs) addFlag(args, "--sleep-fwd-ms", std::to_string(*cfg.sleepFwdMs));
    if (cfg.uptimeMin) addFlag(args, "--uptime-min", std::to_string(*cfg.uptimeMin));
    if (cfg.hammerS) addFlag(args, "--hammer-s", std::to_string(*cfg.hammerS));

    if (!cfg.disabledTokens.empty()) {
        auto all = allTokens();
        bool disableAll = std::all_of(all.begin(), all.end(), [&](const std::string& t) {
            return std::any_of(cfg.disabledTokens.begin(), cfg.disabledTokens.end(),
                               [&](const std::string& d) { return iequals(d, t); });
        });
        std::string tokens;
        if (disableAll) {
            tokens = "all";
        } else {
            std::vector<std::string> seen;
            for (const auto& t : cfg.disabledTokens) {
                std::string low = toLowerAscii(t);
                if (std::find(seen.begin(), seen.end(), low) == seen.end())
                    seen.push_back(low);
            }
            for (size_t i = 0; i < seen.size(); i++) {
                if (i) tokens += ',';
                tokens += seen[i];
            }
        }
        addFlag(args, "--disable", tokens);
    }

    if (!trimWhitespace(cfg.pfxPath).empty()) addFlag(args, "--pfx", cfg.pfxPath);
    if (!cfg.pfxPassword.empty()) addFlag(args, "--pfx-pass", cfg.pfxPassword);
    if (!trimWhitespace(cfg.tsUrl).empty()) addFlag(args, "--ts-url", cfg.tsUrl);
    if (!trimWhitespace(cfg.cloneMetaPath).empty()) addFlag(args, "--clone-meta", cfg.cloneMetaPath);
    if (cfg.uac) args.push_back("--uac");

    return args;
}

std::string quoteArgument(const std::string& arg) {
    if (!arg.empty() && arg.find_first_of(" \t\"") == std::string::npos)
        return arg;

    std::string out = "\"";
    int backslashes = 0;
    for (char c : arg) {
        if (c == '\\') {
            backslashes++;
            continue;
        }
        if (c == '"') {
            out.append((size_t)backslashes * 2 + 1, '\\');
            out += '"';
            backslashes = 0;
            continue;
        }
        out.append((size_t)backslashes, '\\');
        out += c;
        backslashes = 0;
    }
    out.append((size_t)backslashes * 2, '\\');
    out += '"';
    return out;
}

std::string buildCommandLine(const BuildConfig& cfg) {
    std::string out;
    for (const auto& a : buildArguments(cfg)) {
        if (!out.empty()) out += ' ';
        out += quoteArgument(a);
    }
    return out;
}

// ── ConfigValidator ────────────────────────────────────────────────────────────

static bool containsIc(const std::vector<std::string>& v, const std::string& s) {
    return std::any_of(v.begin(), v.end(), [&](const std::string& e) { return iequals(e, s); });
}

std::vector<ValidationIssue> validateConfig(const BuildConfig& cfg) {
    std::vector<ValidationIssue> issues;
    const std::vector<std::string> validExts = {".exe", ".dll", ".bin"};
    const std::vector<std::string> validPresets = {"PRINT", "MEDIA", "NETWORK", "RANDOM"};

    if (trimWhitespace(cfg.inputPath).empty()) {
        issues.push_back({ValidationSeverity::Error, ValidationCode::InputRequired, "inputPath"});
    } else {
        if (!fileExists(utf8ToWide(cfg.inputPath)))
            issues.push_back({ValidationSeverity::Error, ValidationCode::InputNotFound, "inputPath"});
        if (!containsIc(validExts, getFileExtensionUtf8(cfg.inputPath)))
            issues.push_back({ValidationSeverity::Error, ValidationCode::InputInvalidExtension, "inputPath"});
    }

    if (trimWhitespace(cfg.outputPath).empty())
        issues.push_back({ValidationSeverity::Error, ValidationCode::OutputRequired, "outputPath"});

    if (!containsIc(validPresets, cfg.preset))
        issues.push_back({ValidationSeverity::Error, ValidationCode::InvalidPreset, "preset"});

    if (cfg.exportName.size() > 63)
        issues.push_back({ValidationSeverity::Error, ValidationCode::ExportNameTooLong, "exportName"});
    if (cfg.exportArg.size() > 127)
        issues.push_back({ValidationSeverity::Error, ValidationCode::ExportArgTooLong, "exportArg"});
    if (cfg.spoofName.size() > 63)
        issues.push_back({ValidationSeverity::Error, ValidationCode::SpoofNameTooLong, "spoofName"});
    if (cfg.execCtrlName.size() > 31)
        issues.push_back({ValidationSeverity::Error, ValidationCode::ExecCtrlNameTooLong, "execCtrlName"});

    bool isDll = iequals(getFileExtensionUtf8(cfg.inputPath), ".dll");
    if (!trimWhitespace(cfg.exportName).empty() && !isDll)
        issues.push_back({ValidationSeverity::Error, ValidationCode::ExportRequiresDll, "exportName"});

    if (!cfg.pfxPassword.empty() && trimWhitespace(cfg.pfxPath).empty())
        issues.push_back({ValidationSeverity::Error, ValidationCode::PfxPasswordRequiresPfx, "pfxPassword"});
    if (!trimWhitespace(cfg.pfxPath).empty() && cfg.pfxPassword.empty())
        issues.push_back({ValidationSeverity::Error, ValidationCode::PfxRequiresPassword, "pfxPassword"});
    if (!trimWhitespace(cfg.tsUrl).empty() && trimWhitespace(cfg.pfxPath).empty())
        issues.push_back({ValidationSeverity::Error, ValidationCode::TsUrlRequiresPfx, "tsUrl"});

    // Existence of identity files.
    if (!trimWhitespace(cfg.pfxPath).empty() && !fileExists(utf8ToWide(cfg.pfxPath)))
        issues.push_back({ValidationSeverity::Error, ValidationCode::PfxNotFound, "pfxPath"});
    if (!trimWhitespace(cfg.cloneMetaPath).empty() && !fileExists(utf8ToWide(cfg.cloneMetaPath)))
        issues.push_back({ValidationSeverity::Error, ValidationCode::CloneMetaNotFound, "cloneMetaPath"});

    // Numeric ranges — sane bounds for Builder's thresholds.
    auto checkRange = [&](const std::optional<int>& v, int lo, int hi, const char* flag, ValidationCode code) {
        if (v && (*v < lo || *v > hi))
            issues.push_back({ValidationSeverity::Warning, code, std::string(flag) + " = \"" + std::to_string(*v) + "\""});
    };
    checkRange(cfg.sleepFwdMs, 1, 10000, "--sleep-fwd-ms", ValidationCode::NumberOutOfRange);
    checkRange(cfg.uptimeMin, 1, 1440, "--uptime-min", ValidationCode::NumberOutOfRange);
    checkRange(cfg.hammerS, 1, 3600, "--hammer-s", ValidationCode::NumberOutOfRange);

    if (!trimWhitespace(cfg.tsUrl).empty())
        issues.push_back({ValidationSeverity::Warning, ValidationCode::WarnTsUrlOpsec, "tsUrl"});

    // Timestamp URL must be an absolute http(s) URL — a typo silently breaks signing.
    if (!trimWhitespace(cfg.tsUrl).empty()) {
        std::string url = trimWhitespace(cfg.tsUrl);
        if (url.rfind("http://", 0) != 0 && url.rfind("https://", 0) != 0)
            issues.push_back({ValidationSeverity::Warning, ValidationCode::WarnTsUrlFormat, "tsUrl"});
    }
    if (!cfg.pfxPassword.empty())
        issues.push_back({ValidationSeverity::Warning, ValidationCode::WarnPfxPasswordVisible, "pfxPassword"});

    auto all = allTokens();
    bool disableAll = std::all_of(all.begin(), all.end(), [&](const std::string& t) {
        return std::any_of(cfg.disabledTokens.begin(), cfg.disabledTokens.end(),
                           [&](const std::string& d) { return iequals(d, t); });
    });
    if (disableAll)
        issues.push_back({ValidationSeverity::Warning, ValidationCode::WarnAllEvasionDisabled});

    bool isShellcode = iequals(getFileExtensionUtf8(cfg.inputPath), ".bin");
    if (!cfg.keepAlive && (isDll || isShellcode))
        issues.push_back({ValidationSeverity::Warning, ValidationCode::WarnKeepAliveSuggested, "keepAlive"});

    return issues;
}

// ── OutputParser ───────────────────────────────────────────────────────────────

std::optional<BuildEvent> parseOutputLine(const std::string& rawLine) {
    if (trimWhitespace(rawLine).empty())
        return std::nullopt;

    std::string line = trimWhitespace(rawLine);

    auto stripPrefix = [](const std::string& l) -> std::string {
        return trimWhitespace(l.substr(3));
    };

    if (line.rfind("[+]", 0) == 0)
        return BuildEvent{BuildEventKind::Success, stripPrefix(line)};
    if (line.rfind("[!]", 0) == 0)
        return BuildEvent{BuildEventKind::Warning, stripPrefix(line)};
    if (line.rfind("[*]", 0) == 0) {
        // "[*]\s*Phase\s+(\d+(?:\.\d+)?):"
        size_t p = 3;
        while (p < line.size() && (line[p] == ' ' || line[p] == '\t')) p++;
        if (line.compare(p, 5, "Phase") == 0) {
            p += 5;
            while (p < line.size() && (line[p] == ' ' || line[p] == '\t')) p++;
            size_t start = p;
            while (p < line.size() && (std::isdigit((unsigned char)line[p]) || line[p] == '.')) p++;
            if (p > start && p < line.size() && line[p] == ':') {
                try {
                    double phase = std::stod(line.substr(start, p - start));
                    return BuildEvent{BuildEventKind::Phase, stripPrefix(line), phase};
                } catch (...) { /* fall through to Info */ }
            }
        }
        return BuildEvent{BuildEventKind::Info, stripPrefix(line)};
    }

    return BuildEvent{BuildEventKind::Info, line};
}

// ── BuilderRunner ──────────────────────────────────────────────────────────────

static std::wstring buildCommandLineW(const BuildConfig& cfg) {
    std::wstring out;
    for (const auto& a : buildArguments(cfg)) {
        if (!out.empty()) out += L' ';
        std::wstring wa = utf8ToWide(quoteArgument(a));
        out += wa;
    }
    return out;
}

BuildResult BuilderRunner::run(const BuildConfig& config, const std::wstring& builderExePath,
                               const std::wstring& workingDirectory, std::atomic<bool>& cancelRequested) {
    auto startTime = std::chrono::steady_clock::now();

    // Job object: when we close the handle (or cancel), the whole tree dies —
    // this is the Win32 equivalent of Process.Kill(entireProcessTree: true).
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (job) SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info, sizeof info);

    SECURITY_ATTRIBUTES sa{sizeof sa, nullptr, TRUE}; // inheritable handles
    HANDLE hOutRead = nullptr, hOutWrite = nullptr;
    HANDLE hErrRead = nullptr, hErrWrite = nullptr;
    CreatePipe(&hOutRead, &hOutWrite, &sa, 0);
    CreatePipe(&hErrRead, &hErrWrite, &sa, 0);
    SetHandleInformation(hOutRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hErrRead, HANDLE_FLAG_INHERIT, 0);

    PROCESS_INFORMATION pi{};
    STARTUPINFOW si{};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hOutWrite;
    si.hStdError = hErrWrite;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    std::wstring cmdline = L"\"" + builderExePath + L"\" " + buildCommandLineW(config);

    // Builder.exe resolves its own location for resources, but stub_v*.bin lookup
    // uses the CWD — hence WorkingDirectory.
    std::wstring cwd = workingDirectory;
    if (cwd.empty()) cwd = L".";

    wchar_t* mutableCmd = _wcsdup(cmdline.c_str());
    BOOL started = CreateProcessW(builderExePath.c_str(), mutableCmd, nullptr, nullptr, TRUE,
                                  CREATE_NO_WINDOW, nullptr, cwd.c_str(), &si, &pi);
    free(mutableCmd);

    CloseHandle(hOutWrite);
    CloseHandle(hErrWrite);

    bool startedOk = started != FALSE;
    if (startedOk && job) {
        AssignProcessToJobObject(job, pi.hProcess);
    }

    BuildResult result;
    result.outputFullPath = wideToUtf8(fullPathOf(utf8ToWide(config.outputPath), workingDirectory));

    if (!startedOk) {
        result.exitCode = std::nullopt;
        result.cancelled = cancelRequested.load();
        CloseHandle(hOutRead);
        CloseHandle(hErrRead);
        if (pi.hProcess) CloseHandle(pi.hProcess);
        if (pi.hThread) CloseHandle(pi.hThread);
        if (job) CloseHandle(job);
        return result;
    }

    // Reader threads: drain both pipes until EOF (EOF happens when the process dies).
    std::atomic<bool> done{false};
    auto reader = [&](HANDLE hPipe) {
        char buf[4096];
        std::string pending;
        DWORD n = 0;
        while (ReadFile(hPipe, buf, sizeof buf, &n, nullptr) && n > 0) {
            pending.append(buf, n);
            size_t nl;
            while ((nl = pending.find('\n')) != std::string::npos) {
                std::string line = pending.substr(0, nl);
                if (!line.empty() && line.back() == '\r') line.pop_back();
                pending.erase(0, nl + 1);
                if (auto ev = parseOutputLine(line))
                    if (onEvent) onEvent(*ev);
            }
        }
        if (!pending.empty()) {
            if (auto ev = parseOutputLine(pending))
                if (onEvent) onEvent(*ev);
        }
        (void)done;
    };

    std::thread tOut(reader, hOutRead);
    std::thread tErr(reader, hErrRead);

    // Wait for the process, polling cancellation.
    DWORD waitResult;
    do {
        waitResult = WaitForSingleObject(pi.hProcess, 50);
        if (cancelRequested.load()) {
            // Kill tree: terminate the process; the job kills any descendants.
            TerminateProcess(pi.hProcess, 1);
            break;
        }
    } while (waitResult == WAIT_TIMEOUT);

    bool cancelled = cancelRequested.load();
    if (cancelled) {
        // Wait for the tree to actually die (job kills children asynchronously).
        WaitForSingleObject(pi.hProcess, 3000);
    }

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    tOut.join();
    tErr.join();

    // Closing the job handle kills any surviving descendants.
    if (job) CloseHandle(job);
    CloseHandle(hOutRead);
    CloseHandle(hErrRead);

    auto endTime = std::chrono::steady_clock::now();
    result.cancelled = cancelled;
    result.exitCode = cancelled ? std::nullopt : std::optional<int>((int)exitCode);
    result.durationSeconds = std::chrono::duration<double>(endTime - startTime).count();
    result.outputFileExists = fileExists(utf8ToWide(result.outputFullPath));

    return result;
}

// ── PostBuildInspector ─────────────────────────────────────────────────────────

static std::string sha256OfFile(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::string hex;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0 &&
        BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0) {
        BYTE buf[65536];
        DWORD n = 0;
        while (ReadFile(h, buf, sizeof buf, &n, nullptr) && n > 0) {
            BCryptHashData(hash, buf, (ULONG)n, 0);
        }
        BYTE digest[32];
        BCryptFinishHash(hash, digest, sizeof digest, 0);
        static const char* hexd = "0123456789ABCDEF";
        for (BYTE b : digest) {
            hex += hexd[b >> 4];
            hex += hexd[b & 0xF];
        }
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    CloseHandle(h);
    return hex;
}

// Reads the PE cert directory issuer via CryptQueryObject — reports who the file
// CLAIMS to be signed by (including --clone-meta certs) without verifying the hash.
static std::string signatureIssuerOf(const std::wstring& path) {
    HCERTSTORE store = nullptr;
    HCRYPTMSG msg = nullptr;
    DWORD dwMsgAndCertEncodingType = 0;
    DWORD dwContentType = 0;
    DWORD dwFormatType = 0;
    HCERTSTORE hStore = nullptr;
    const void* pv = path.c_str();

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, pv, CERT_QUERY_CONTENT_FLAG_ALL,
                          CERT_QUERY_FORMAT_FLAG_ALL, 0, &dwMsgAndCertEncodingType,
                          &dwContentType, &dwFormatType, &store, &msg, &pv))
        return {};

    std::string issuer;
    if (store) {
        PCCERT_CONTEXT cert = CertEnumCertificatesInStore(store, nullptr);
        if (cert) {
            wchar_t nameBuf[512];
            DWORD len = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                                           nameBuf, 512);
            if (len > 1)
                issuer = wideToUtf8(std::wstring(nameBuf, len - 1));
            CertFreeCertificateContext(cert);
        }
        CertCloseStore(store, 0);
    }
    if (msg) CryptMsgClose(msg);
    return issuer;
}

PostBuildInfo inspectOutput(const std::wstring& filePath) {
    PostBuildInfo info;
    info.filePath = wideToUtf8(filePath);

    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &fad)) {
        ULARGE_INTEGER sz;
        sz.LowPart = fad.nFileSizeLow;
        sz.HighPart = fad.nFileSizeHigh;
        info.sizeBytes = (int64_t)sz.QuadPart;
    }

    info.sha256Hex = sha256OfFile(filePath);

    info.signatureIssuer = signatureIssuerOf(filePath);
    if (!info.signatureIssuer.empty())
        info.signatureState = SignatureState::SignedUnverified;

    return info;
}

// ── JSON <-> models (shared by stores) ─────────────────────────────────────────

static JsonPtr configToJson(const BuildConfig& c) {
    auto o = JsonValue::makeObject();
    o->set("InputPath", JsonValue::makeString(c.inputPath));
    o->set("OutputPath", JsonValue::makeString(c.outputPath));
    if (!c.stubPath.empty()) o->set("StubPath", JsonValue::makeString(c.stubPath));
    o->set("Preset", JsonValue::makeString(c.preset));
    o->set("Overload", JsonValue::makeBool(c.overload));
    o->set("KeepAlive", JsonValue::makeBool(c.keepAlive));
    o->set("Unhook", JsonValue::makeBool(c.unhook));
    o->set("ExportName", JsonValue::makeString(c.exportName));
    o->set("ExportArg", JsonValue::makeString(c.exportArg));
    o->set("SpoofName", JsonValue::makeString(c.spoofName));
    o->set("ExecCtrlName", JsonValue::makeString(c.execCtrlName));
    if (c.sleepFwdMs) o->set("SleepFwdMs", JsonValue::makeNumber(*c.sleepFwdMs));
    if (c.uptimeMin) o->set("UptimeMin", JsonValue::makeNumber(*c.uptimeMin));
    if (c.hammerS) o->set("HammerS", JsonValue::makeNumber(*c.hammerS));
    auto tokens = JsonValue::makeArray();
    for (const auto& t : c.disabledTokens) tokens->arr.push_back(JsonValue::makeString(t));
    o->set("DisabledTokens", tokens);
    if (!c.pfxPath.empty()) o->set("PfxPath", JsonValue::makeString(c.pfxPath));
    if (!c.tsUrl.empty()) o->set("TsUrl", JsonValue::makeString(c.tsUrl));
    if (!c.cloneMetaPath.empty()) o->set("CloneMetaPath", JsonValue::makeString(c.cloneMetaPath));
    o->set("Uac", JsonValue::makeBool(c.uac));
    return o;
}

static void jsonToConfig(const JsonValue* j, BuildConfig& c) {
    if (!j) return;
    if (auto* v = j->get("InputPath")) c.inputPath = v->asString();
    if (auto* v = j->get("OutputPath")) c.outputPath = v->asString();
    if (auto* v = j->get("StubPath")) c.stubPath = v->asString();
    if (auto* v = j->get("Preset")) c.preset = v->asString("PRINT");
    if (auto* v = j->get("Overload")) c.overload = v->asBool();
    if (auto* v = j->get("KeepAlive")) c.keepAlive = v->asBool();
    if (auto* v = j->get("Unhook")) c.unhook = v->asBool();
    if (auto* v = j->get("ExportName")) c.exportName = v->asString();
    if (auto* v = j->get("ExportArg")) c.exportArg = v->asString();
    if (auto* v = j->get("SpoofName")) c.spoofName = v->asString();
    if (auto* v = j->get("ExecCtrlName")) c.execCtrlName = v->asString();
    if (auto* v = j->get("SleepFwdMs")) c.sleepFwdMs = (int)v->asNumber();
    if (auto* v = j->get("UptimeMin")) c.uptimeMin = (int)v->asNumber();
    if (auto* v = j->get("HammerS")) c.hammerS = (int)v->asNumber();
    if (auto* v = j->get("DisabledTokens")) {
        c.disabledTokens.clear();
        if (v->type == JsonType::Array)
            for (const auto& t : v->arr)
                c.disabledTokens.push_back(t->asString());
    }
    if (auto* v = j->get("PfxPath")) c.pfxPath = v->asString();
    if (auto* v = j->get("TsUrl")) c.tsUrl = v->asString();
    if (auto* v = j->get("CloneMetaPath")) c.cloneMetaPath = v->asString();
    if (auto* v = j->get("Uac")) c.uac = v->asBool();
}

// ── ProfileStore ───────────────────────────────────────────────────────────────

static std::vector<BuildProfile> factoryPresets() {
    BuildProfile p1;
    p1.name = "C2 Beacon";
    p1.description = "Long-running implant: keep loader thread alive, network-themed stomp preset.";
    p1.isFactoryPreset = true;
    p1.config.keepAlive = true;
    p1.config.preset = "NETWORK";

    BuildProfile p2;
    p2.name = "CTF Debug";
    p2.description = "All sandbox/debug checks and OPSEC features off (--disable all) for lab iteration.";
    p2.isFactoryPreset = true;
    p2.config.disabledTokens = allTokens();

    BuildProfile p3;
    p3.name = "Paranoid";
    p3.description = "Tightened thresholds: 8 s hammer, 15 min uptime, 250 ms sleep-fwd, custom mutex.";
    p3.isFactoryPreset = true;
    p3.config.hammerS = 8;
    p3.config.uptimeMin = 15;
    p3.config.sleepFwdMs = 250;
    p3.config.execCtrlName = "TeamsUpdate";

    return {p1, p2, p3};
}

ProfileStore::ProfileStore(const std::wstring& baseDirectory)
    : profilesDir_(baseDirectory + L"\\profiles") {}

std::vector<BuildProfile> ProfileStore::listAll() const {
    std::vector<BuildProfile> result = factoryPresets();

    WIN32_FIND_DATAW fd;
    std::wstring pattern = profilesDir_ + L"\\*.json";
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            std::wstring path = profilesDir_ + L"\\" + fd.cFileName;
            std::ifstream in(std::filesystem::path(path), std::ios::binary);
            std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            auto root = jsonParse(text);
            if (!root) continue;
            auto* name = root->get("Name");
            if (!name || trimWhitespace(name->asString()).empty()) continue;
            BuildProfile p;
            p.name = name->asString();
            if (auto* d = root->get("Description")) p.description = d->asString();
            if (auto* c = root->get("Config")) jsonToConfig(c, p.config);
            p.isFactoryPreset = false;
            result.push_back(std::move(p));
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }

    // Factory presets win name collisions so a stale user file can't shadow a built-in.
    std::vector<BuildProfile> unique;
    for (const auto& p : result) {
        bool shadowed = false;
        for (const auto& f : result) {
            if (f.isFactoryPreset && iequals(f.name, p.name) && !p.isFactoryPreset) {
                shadowed = true;
                break;
            }
        }
        if (!shadowed) unique.push_back(p);
    }
    return unique;
}

static std::wstring safeFileName(const std::string& name) {
    std::string safe = name;
    for (auto& c : safe) {
        if (c == '<' || c == '>' || c == ':' || c == '"' || c == '/' || c == '\\' ||
            c == '|' || c == '?' || c == '*')
            c = '_';
    }
    return utf8ToWide(safe);
}

void ProfileStore::saveUserProfile(const BuildProfile& profile) {
    if (trimWhitespace(profile.name).empty()) return;
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(profilesDir_), ec);

    auto root = JsonValue::makeObject();
    root->set("Name", JsonValue::makeString(profile.name));
    root->set("Description", JsonValue::makeString(profile.description));
    root->set("Config", configToJson(profile.config));

    std::wstring path = profilesDir_ + L"\\" + safeFileName(profile.name) + L".json";
    std::ofstream out(std::filesystem::path(path), std::ios::binary);
    out << jsonSerialize(*root, 4);
}

bool ProfileStore::deleteUserProfile(const std::string& name) {
    std::wstring path = profilesDir_ + L"\\" + safeFileName(name) + L".json";
    if (!fileExists(path)) return false;
    return DeleteFileW(path.c_str()) != FALSE;
}

// ── BuildHistoryStore ──────────────────────────────────────────────────────────

BuildHistoryStore::BuildHistoryStore(const std::wstring& baseDirectory)
    : historyFile_(baseDirectory + L"\\history\\builds.jsonl") {}

void BuildHistoryStore::append(const HistoryEntry& entry) {
    std::wstring dir = historyFile_.substr(0, historyFile_.find_last_of(L"\\/"));
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(dir), ec);

    auto o = JsonValue::makeObject();
    o->set("Timestamp", JsonValue::makeNumber((double)entry.timestampUnixMs));
    o->set("CommandLine", JsonValue::makeString(entry.commandLine));
    o->set("Config", configToJson(entry.config));
    o->set("Success", JsonValue::makeBool(entry.success));
    if (entry.exitCode) o->set("ExitCode", JsonValue::makeNumber(*entry.exitCode));
    o->set("DurationSeconds", JsonValue::makeNumber(entry.durationSeconds));
    o->set("Sha256", JsonValue::makeString(entry.sha256));
    if (entry.outputSizeBytes) o->set("OutputSizeBytes", JsonValue::makeNumber((double)*entry.outputSizeBytes));
    o->set("SignatureIssuer", JsonValue::makeString(entry.signatureIssuer));

    std::ofstream out(std::filesystem::path(historyFile_), std::ios::binary | std::ios::app);
    out << jsonSerialize(*o) << "\n";
}

std::vector<HistoryEntry> BuildHistoryStore::loadAll() const {
    std::vector<HistoryEntry> entries;
    if (!fileExists(historyFile_)) return entries;

    std::ifstream in(std::filesystem::path(historyFile_), std::ios::binary);
    std::string line;
    while (std::getline(in, line)) {
        if (trimWhitespace(line).empty()) continue;
        auto root = jsonParse(line);
        if (!root) continue;
        HistoryEntry e;
        if (auto* v = root->get("Timestamp")) e.timestampUnixMs = (int64_t)v->asNumber(0.0);
        if (auto* v = root->get("CommandLine")) e.commandLine = v->asString();
        if (auto* v = root->get("Config")) jsonToConfig(v, e.config);
        if (auto* v = root->get("Success")) e.success = v->asBool();
        if (auto* v = root->get("ExitCode")) e.exitCode = (int)v->asNumber();
        if (auto* v = root->get("DurationSeconds")) e.durationSeconds = v->asNumber();
        if (auto* v = root->get("Sha256")) e.sha256 = v->asString();
        if (auto* v = root->get("OutputSizeBytes")) e.outputSizeBytes = (int64_t)v->asNumber();
        if (auto* v = root->get("SignatureIssuer")) e.signatureIssuer = v->asString();
        entries.push_back(std::move(e));
    }
    std::reverse(entries.begin(), entries.end()); // newest first
    if (entries.size() > 20)
        entries.resize(20);                       // keep the 20 most recent builds
    return entries;
}

void BuildHistoryStore::flush() {
    // Delete the history file (and prune the empty parent directory).
    DeleteFileW(historyFile_.c_str());
    std::wstring dir = historyFile_.substr(0, historyFile_.find_last_of(L"\\/"));
    RemoveDirectoryW(dir.c_str());
}

// ── AppSettings ────────────────────────────────────────────────────────────────

AppSettings AppSettings::load(const std::wstring& baseDirectory) {
    AppSettings s;
    s.builderPath = baseDirectory + L"\\Builder.exe";
    s.stubDirectory = baseDirectory;
    s.outputDirectory = baseDirectory;

    std::wstring path = baseDirectory + L"\\settings.json";
    if (!fileExists(path)) return s;

    std::ifstream in(std::filesystem::path(path), std::ios::binary);
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    auto root = jsonParse(text);
    if (!root) return s;

    if (auto* v = root->get("BuilderPath")) s.builderPath = utf8ToWide(v->asString());
    if (auto* v = root->get("StubDirectory")) s.stubDirectory = utf8ToWide(v->asString());
    if (auto* v = root->get("OutputDirectory")) s.outputDirectory = utf8ToWide(v->asString());
    if (auto* v = root->get("Language")) s.language = v->asString("en");
    if (auto* v = root->get("LastConfig")) {
        s.lastConfig = std::make_shared<BuildConfig>();
        jsonToConfig(v, *s.lastConfig);
    }
    return s;
}

void AppSettings::save(const std::wstring& baseDirectory) const {
    auto root = JsonValue::makeObject();
    root->set("BuilderPath", JsonValue::makeString(wideToUtf8(builderPath)));
    root->set("StubDirectory", JsonValue::makeString(wideToUtf8(stubDirectory)));
    root->set("OutputDirectory", JsonValue::makeString(wideToUtf8(outputDirectory)));
    root->set("Language", JsonValue::makeString(language));
    if (lastConfig)
        root->set("LastConfig", configToJson(*lastConfig));

    std::wstring path = baseDirectory + L"\\settings.json";
    std::ofstream out(std::filesystem::path(path), std::ios::binary);
    out << jsonSerialize(*root, 4);
}

} // namespace peg
