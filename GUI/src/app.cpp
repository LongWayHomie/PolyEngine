#include "app.h"
#include "loc.h"
#include <algorithm>
#include <chrono>
#include <windows.h>
#include <shlwapi.h>

namespace peg {

const std::vector<std::string> AppState::kPresetPool = {"PRINT", "MEDIA", "NETWORK", "WEB", "RANDOM"};
const std::vector<std::string> AppState::kSpoofPool = {
    "RuntimeBroker.exe", "SgrmBroker.exe", "WmiPrvSE.exe", "SearchIndexer.exe",
    "taskhostw.exe", "spoolsv.exe", "wlrmdr.exe", "WMPDMC.exe", "hvix64.exe",
};

static std::vector<ToggleItem> makeToggles(const std::vector<std::string>& tokens) {
    // Expanded labels replace the raw CLI tokens on the checkbox; the token itself
    // moves to the tooltip together with the full description.
    static const std::map<std::string, std::string> kLabels = {
        // OPSEC
        {"etw", "ETW patching"},
        {"amsi", "AMSI patching"},
        {"blockdlls", "Block non-MS DLLs"},
        {"spoofing", "Call-stack spoofing"},
        {"peb", "PEB spoofing"},
        {"tls", "TLS anti-debug"},
        // Sandbox / debug
        {"hammer", "API hammer delay"},
        {"debugger", "Debugger detection"},
        {"api-emu", "API emulation probe"},
        {"exec-ctrl", "Exec-control semaphore"},
        {"sleep-fwd", "Sleep-fwd check"},
        {"uptime", "Uptime check"},
        {"cpu", "CPU count check"},
        {"screen", "Screen resolution check"},
        {"files", "Recent-files check"},
    };

    std::vector<ToggleItem> items;
    for (const auto& t : tokens) {
        ToggleItem item;
        item.token = t;
        auto it = kLabels.find(t);
        item.label = it != kLabels.end() ? it->second : t;
        item.description = Loc::instance()["Token." + t];
        items.push_back(std::move(item));
    }
    return items;
}

AppState::AppState()
    : profileStore(AppSettings().stubDirectory), historyStore(AppSettings().stubDirectory) {
    // baseDirectory = exe directory
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring exeDir = exePath;
    auto slash = exeDir.find_last_of(L"\\/");
    if (slash != std::wstring::npos) exeDir = exeDir.substr(0, slash);

    settings = AppSettings::load(exeDir);
    Loc::instance().setLanguage(settings.language);

    // Reconstruct stores with the real base dir (default ctor used exe dir already).
    profileStore = ProfileStore(exeDir);
    historyStore = BuildHistoryStore(exeDir);

    opsecToggles = makeToggles(kOpsecTokens);
    sandboxToggles = makeToggles(kSandboxTokens);

    profiles = profileStore.listAll();
    if (settings.lastConfig)
        applyConfig(*settings.lastConfig);
}

AppState::~AppState() {
    if (buildThread_ && buildThread_->joinable()) {
        cancelRequested_ = true;
        buildThread_->join();
    }
}

// ── config mapping ────────────────────────────────────────────────────────────

static std::optional<int> parseIntText(const std::string& text) {
    std::string t = trimWhitespace(text);
    if (t.empty()) return std::nullopt;
    try {
        size_t idx = 0;
        int v = std::stoi(t, &idx);
        if (idx != t.size()) return std::nullopt;
        return v;
    } catch (...) { return std::nullopt; }
}

// Resolves a user-typed path against the stub directory. Bare file names like
// "implant.exe" become "<stubDir>\implant.exe" — the operator works in one
// folder without pasting full paths. Already-rooted or separator-bearing paths
// pass through untouched.
static std::string resolveAgainstStubDir(const std::string& path, const std::wstring& stubDir) {
    std::string t = trimWhitespace(path);
    if (t.empty()) return t;
    if (t.find('\\') != std::string::npos || t.find('/') != std::string::npos)
        return t;
    if (isPathRooted(utf8ToWide(t)))
        return t;
    return wideToUtf8(fullPathOf(utf8ToWide(t), stubDir));
}

BuildConfig AppState::toConfig() const {
    BuildConfig c;
    c.inputPath = resolveAgainstStubDir(inputPath, settings.stubDirectory);
    c.outputPath = resolveAgainstStubDir(outputPath, settings.stubDirectory);
    c.stubPath = resolveAgainstStubDir(stubPath, settings.stubDirectory);
    c.preset = preset;
    c.overload = overload;
    c.keepAlive = keepAlive;
    c.unhook = unhook;
    c.exportName = trimWhitespace(exportName);
    c.exportArg = exportArg;
    c.spoofName = trimWhitespace(spoofName);
    c.execCtrlName = trimWhitespace(execCtrlName);
    c.sleepFwdMs = parseIntText(sleepFwdMsText);
    c.uptimeMin = parseIntText(uptimeMinText);
    c.hammerS = parseIntText(hammerSText);
    c.disabledTokens = disabledTokensList();
    c.pfxPath = resolveAgainstStubDir(pfxPath, settings.stubDirectory);
    c.pfxPassword = trimWhitespace(pfxPassword);
    c.tsUrl = trimWhitespace(tsUrl);
    c.cloneMetaPath = resolveAgainstStubDir(cloneMetaPath, settings.stubDirectory);
    c.uac = uac;
    return c;
}

std::string AppState::commandPreview() const {
    // Full command line as the operator would run it: quoted Builder.exe path + argv.
    std::string preview;
    std::string builder = wideToUtf8(settings.builderPath);
    if (!builder.empty()) {
        preview += quoteArgument(builder);
        preview += ' ';
    }
    preview += buildCommandLine(toConfig());
    return preview;
}

std::vector<std::string> AppState::disabledTokensList() const {
    std::vector<std::string> out;
    for (const auto& t : opsecToggles)
        if (!t.isEnabled) out.push_back(t.token);
    for (const auto& t : sandboxToggles)
        if (!t.isEnabled) out.push_back(t.token);
    return out;
}

void AppState::applyConfig(const BuildConfig& cfg) {
    inputPath = cfg.inputPath;
    outputPath = cfg.outputPath;
    stubPath = cfg.stubPath;
    preset = cfg.preset;
    overload = cfg.overload;
    keepAlive = cfg.keepAlive;
    unhook = cfg.unhook;
    exportName = cfg.exportName;
    exportArg = cfg.exportArg;
    spoofName = cfg.spoofName;
    execCtrlName = cfg.execCtrlName;
    sleepFwdMsText = cfg.sleepFwdMs ? std::to_string(*cfg.sleepFwdMs) : "";
    uptimeMinText = cfg.uptimeMin ? std::to_string(*cfg.uptimeMin) : "";
    hammerSText = cfg.hammerS ? std::to_string(*cfg.hammerS) : "";
    pfxPath = cfg.pfxPath;
    pfxPassword = ""; // secrets never restored
    tsUrl = cfg.tsUrl;
    cloneMetaPath = cfg.cloneMetaPath;
    uac = cfg.uac;
    setToggles(cfg.disabledTokens);
}

void AppState::applyProfile(const BuildProfile& profile) {
    applyConfig(profile.config);
}

void AppState::setToggles(const std::vector<std::string>& disabled) {
    auto isDisabled = [&](const std::string& token) {
        return std::any_of(disabled.begin(), disabled.end(),
                           [&](const std::string& d) { return iequals(d, token); });
    };
    for (auto& t : opsecToggles) t.isEnabled = !isDisabled(t.token);
    for (auto& t : sandboxToggles) t.isEnabled = !isDisabled(t.token);
}

void AppState::reloadProfiles() {
    profiles = profileStore.listAll();
}

void AppState::refreshTokenDescriptions() {
    auto& loc = Loc::instance();
    for (auto& t : opsecToggles) t.description = loc["Token." + t.token];
    for (auto& t : sandboxToggles) t.description = loc["Token." + t.token];
}

// ── validation ────────────────────────────────────────────────────────────────

void AppState::revalidate() {
    auto cfg = toConfig();
    issues = validateConfig(cfg);

    struct { const std::string& text; const char* label; } numbers[] = {
        {sleepFwdMsText, "--sleep-fwd-ms"},
        {uptimeMinText, "--uptime-min"},
        {hammerSText, "--hammer-s"},
    };
    for (const auto& n : numbers) {
        if (!trimWhitespace(n.text).empty() && !parseIntText(n.text)) {
            issues.push_back({ValidationSeverity::Error, ValidationCode::InvalidNumber,
                              std::string(n.label) + " = \"" + trimWhitespace(n.text) + "\""});
        }
    }

    if (!fileExists(settings.builderPath))
        issues.push_back({ValidationSeverity::Error, ValidationCode::BuilderNotConfigured, ""});
    else if (!dirExists(settings.stubDirectory) ||
             findStubVFiles(settings.stubDirectory).empty())
        issues.push_back({ValidationSeverity::Error, ValidationCode::StubsMissing, ""});
}

bool AppState::hasErrors() const {
    return std::any_of(issues.begin(), issues.end(),
                       [](const ValidationIssue& i) { return i.isError(); });
}

std::vector<AppState::LocalizedIssue> AppState::localizedIssues() const {
    auto& loc = Loc::instance();
    std::vector<LocalizedIssue> out;
    for (const auto& i : issues) {
        std::string text;
        if (i.code == ValidationCode::InvalidNumber && !i.field.empty())
            text = loc.format("Validation.InvalidNumber", i.field);
        else if (i.code == ValidationCode::NumberOutOfRange && !i.field.empty())
            text = loc.format("Validation.NumberOutOfRange", i.field);
        else
            text = loc["Validation." + codeName(i.code)];
        out.push_back({i.isError(), std::move(text)});
    }
    std::stable_sort(out.begin(), out.end(),
                     [](const LocalizedIssue& a, const LocalizedIssue& b) {
                         return a.isError && !b.isError;
                     });
    return out;
}

// ── build execution ───────────────────────────────────────────────────────────

void AppState::startBuild() {
    if (isBuilding || hasErrors()) return;

    log.clear();
    outputInfoText.clear();
    currentPhase = 0.0;
    statusText = Loc::instance()["Build.Building"];
    isBuilding = true;
    cancelRequested_ = false;
    buildDone_ = false;

    auto cfg = toConfig();
    std::wstring builderPath = settings.builderPath;
    std::wstring stubDir = settings.stubDirectory;

    buildThread_ = std::make_unique<std::thread>([this, cfg, builderPath, stubDir]() {
        BuilderRunner runner;
        runner.onEvent = [this](const BuildEvent& e) {
            std::lock_guard<std::mutex> lock(eventMutex_);
            pendingEvents_.push_back(e);
        };
        buildResult_ = runner.run(cfg, builderPath, stubDir, cancelRequested_);
        buildDone_ = true;
    });
}

void AppState::cancelBuild() {
    cancelRequested_ = true;
}

void AppState::pump() {
    // Drain events
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        while (!pendingEvents_.empty()) {
            BuildEvent e = pendingEvents_.front();
            pendingEvents_.pop_front();
            log.push_back(e);
            if (e.kind == BuildEventKind::Phase && e.phase && *e.phase > currentPhase)
                currentPhase = (std::min)(*e.phase, 12.0);
        }
    }

    if (!buildDone_) return;
    if (buildThread_ && buildThread_->joinable()) buildThread_->join();
    buildThread_.reset();

    auto& loc = Loc::instance();
    isBuilding = false;

    if (buildResult_.cancelled) {
        statusText = loc["Build.Cancelled"];
    } else if (buildResult_.success()) {
        char buf[64];
        snprintf(buf, sizeof buf, "%.1f", buildResult_.durationSeconds);
        statusText = loc.format("Build.Succeeded", buf);
        reportPostBuild(buildResult_);
    } else {
        statusText = loc.format("Build.Failed",
                                buildResult_.exitCode ? std::to_string(*buildResult_.exitCode) : "\u2014");
    }
}

void AppState::reportPostBuild(const BuildResult& result) {
    auto info = inspectOutput(utf8ToWide(result.outputFullPath));
    if (info.filePath.empty() && info.sha256Hex.empty() && info.sizeBytes == 0)
        return; // output vanished between build and inspect

    auto& loc = Loc::instance();
    std::string sig = info.signatureState == SignatureState::SignedUnverified && !info.signatureIssuer.empty()
        ? loc.format("Build.SigSignedUnverified", info.signatureIssuer)
        : loc["Build.SigNotSigned"];

    char sizeBuf[64];
    snprintf(sizeBuf, sizeof sizeBuf, "%lld", (long long)info.sizeBytes);
    // Output: <path>\nSize: <bytes> bytes\nSHA-256: <hash>\nSignature: <state>
    outputInfoText = loc.format("Build.OutputInfo", info.filePath);
    outputInfoText += "\n" + loc.format("Build.Size", sizeBuf);
    outputInfoText += "\n" + loc.format("Build.Sha256", info.sha256Hex);
    outputInfoText += "\n" + sig;

    HistoryEntry entry;
    entry.timestampUnixMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    entry.commandLine = commandPreview();
    entry.config = toConfig();
    entry.success = true;
    entry.exitCode = result.exitCode;
    entry.durationSeconds = result.durationSeconds;
    entry.sha256 = info.sha256Hex;
    entry.outputSizeBytes = info.sizeBytes;
    entry.signatureIssuer = info.signatureIssuer;
    historyStore.append(entry);
}

// ── persistence ───────────────────────────────────────────────────────────────

std::vector<HistoryEntry> AppState::loadHistory() {
    return historyStore.loadAll();
}

void AppState::saveProfile(const std::string& name, const std::string& description) {
    BuildProfile p;
    p.name = trimWhitespace(name);
    p.description = trimWhitespace(description);
    p.config = toConfig();
    profileStore.saveUserProfile(p);
    reloadProfiles();
}

void AppState::deleteProfile(const BuildProfile& profile) {
    profileStore.deleteUserProfile(profile.name);
}

void AppState::persist() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring exeDir = exePath;
    auto slash = exeDir.find_last_of(L"\\/");
    if (slash != std::wstring::npos) exeDir = exeDir.substr(0, slash);

    settings.lastConfig = std::make_shared<BuildConfig>(toConfig());
    settings.save(exeDir);
}

} // namespace peg
