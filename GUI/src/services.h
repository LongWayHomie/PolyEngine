#pragma once
// services.h — port of the C# PolyEngine.GUI.Services layer.
#include <string>
#include <vector>
#include <functional>
#include <optional>
#include <thread>
#include <atomic>
#include <windows.h>
#include "models.h"

namespace peg {

// ── ArgBuilder ────────────────────────────────────────────────────────────────
// Maps BuildConfig to Builder.exe argv. Flags with default values are omitted so the
// generated command line stays minimal. When every disable token is selected the list
// collapses to "all" (Builder sets EVASION_FLAG_NO_ALL in that case).
std::vector<std::string> buildArguments(const BuildConfig& cfg);
std::string buildCommandLine(const BuildConfig& cfg);
// CommandLineToArgvW-compatible quoting.
std::string quoteArgument(const std::string& arg);

// ── ConfigValidator ───────────────────────────────────────────────────────────
std::vector<ValidationIssue> validateConfig(const BuildConfig& cfg);

// ── OutputParser ──────────────────────────────────────────────────────────────
// Line-by-line parser for Builder.exe stdout. "[+]"→Success, "[!]"→Warning,
// "[*] Phase N:"→Phase (N may be 10.5), anything else→Info. Null for blank lines.
std::optional<BuildEvent> parseOutputLine(const std::string& rawLine);

// ── DisableTokens ─────────────────────────────────────────────────────────────
extern const std::vector<std::string> kOpsecTokens;   // etw, amsi, blockdlls, spoofing, peb, tls
extern const std::vector<std::string> kSandboxTokens; // hammer, debugger, api-emu, exec-ctrl, sleep-fwd, uptime, cpu, screen, files
std::vector<std::string> allTokens();

// ── BuilderRunner ─────────────────────────────────────────────────────────────
// Spawns Builder.exe with redirected stdout/stderr, streaming parsed events as lines
// arrive. WorkingDirectory must point at the stub directory — Builder looks for
// stub_v*.bin in its CWD. Cancel kills the process tree.
class BuilderRunner {
public:
    std::function<void(const BuildEvent&)> onEvent;
    BuildResult run(const BuildConfig& config, const std::wstring& builderExePath,
                    const std::wstring& workingDirectory, std::atomic<bool>& cancelRequested);
};

// ── PostBuildInspector ─────────────────────────────────────────────────────────
PostBuildInfo inspectOutput(const std::wstring& filePath);

// ── ProfileStore ───────────────────────────────────────────────────────────────
class ProfileStore {
public:
    explicit ProfileStore(const std::wstring& baseDirectory);
    std::vector<BuildProfile> listAll() const;
    void saveUserProfile(const BuildProfile& profile);
    bool deleteUserProfile(const std::string& name);
private:
    std::wstring profilesDir_;
};

// ── BuildHistoryStore ──────────────────────────────────────────────────────────
class BuildHistoryStore {
public:
    explicit BuildHistoryStore(const std::wstring& baseDirectory);
    void append(const HistoryEntry& entry);
    std::vector<HistoryEntry> loadAll() const; // newest first, max 20 entries
    void flush();                              // delete all stored history
private:
    std::wstring historyFile_;
};

// ── AppSettings ────────────────────────────────────────────────────────────────
struct AppSettings {
    std::wstring builderPath;
    std::wstring stubDirectory;
    std::wstring outputDirectory;
    std::string language = "en"; // "en" | "pl"
    std::shared_ptr<BuildConfig> lastConfig;

    static AppSettings load(const std::wstring& baseDirectory);
    void save(const std::wstring& baseDirectory) const;
};

// ── shared ─────────────────────────────────────────────────────────────────────
// UTF-8 <-> UTF-16 helpers (Win32-backed, zero deps).
std::wstring utf8ToWide(const std::string& utf8);
std::string wideToUtf8(const std::wstring& wide);

// Cross-platform-style helpers for path handling on Windows.
bool fileExists(const std::wstring& path);
bool dirExists(const std::wstring& path);
std::string getFileExtensionUtf8(const std::string& path);
bool isPathRooted(const std::wstring& path);
std::wstring fullPathOf(const std::wstring& path, const std::wstring& relativeToDir);
std::string toLowerAscii(const std::string& s);
std::string trimWhitespace(const std::string& s);
bool iequals(const std::string& a, const std::string& b);

// stub_v*.bin files in a directory (for the StubsMissing validation).
std::vector<std::string> findStubVFiles(const std::wstring& directory);

// ValidationCode → "Validation.*" localization key suffix.
std::string codeName(ValidationCode code);

} // namespace peg
