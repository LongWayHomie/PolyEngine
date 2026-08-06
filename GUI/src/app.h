#pragma once
// app.h — central application state, port of AppState.cs.
#include <string>
#include <vector>
#include <deque>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>
#include <optional>
#include "models.h"
#include "services.h"

namespace peg {

enum class AppScreen { Build, Profiles, History, Settings };

struct ToggleItem {
    std::string token;        // CLI token, e.g. "etw" (shown in tooltip)
    std::string label;        // expanded human name, e.g. "ETW patching" (checkbox label)
    std::string description;  // full technical description (tooltip)
    bool isEnabled = true;
};

class AppState {
public:
    AppState();

    // ── navigation / settings ────────────────────────────────────────────
    AppScreen currentScreen = AppScreen::Build;
    AppSettings settings;
    ProfileStore profileStore;
    BuildHistoryStore historyStore;

    // ── config fields (UI-bound) ─────────────────────────────────────────
    std::string inputPath, outputPath, stubPath;
    std::string preset = "PRINT";
    bool overload = false, keepAlive = false, unhook = false;
    std::string exportName, exportArg;
    std::string spoofName, execCtrlName;
    std::string sleepFwdMsText, uptimeMinText, hammerSText;
    std::string pfxPath, pfxPassword, tsUrl, cloneMetaPath;
    bool uac = false;

    std::vector<ToggleItem> opsecToggles;
    std::vector<ToggleItem> sandboxToggles;

    static const std::vector<std::string> kPresetPool;
    static const std::vector<std::string> kSpoofPool;

    std::vector<BuildProfile> profiles;

    // ── build state ──────────────────────────────────────────────────────
    bool isBuilding = false;
    double currentPhase = 0.0;
    std::string statusText;
    std::string outputInfoText;
    std::vector<BuildEvent> log;
    std::vector<ValidationIssue> issues;

    // ── config mapping ───────────────────────────────────────────────────
    BuildConfig toConfig() const;
    // redactSecrets=true replaces the PFX password with a placeholder (history persistence).
    std::string commandPreview(bool redactSecrets = false) const;
    void applyConfig(const BuildConfig& cfg);      // full restore (PfxPassword always cleared)
    void applyProfile(const BuildProfile& profile);
    void reloadProfiles();
    void refreshTokenDescriptions();

    // ── validation ───────────────────────────────────────────────────────
    void revalidate();
    bool hasErrors() const;
    struct LocalizedIssue { bool isError; std::string text; };
    std::vector<LocalizedIssue> localizedIssues() const;

    // ── build execution ──────────────────────────────────────────────────
    bool canBuild() const { return !isBuilding && !hasErrors(); }
    void startBuild();
    void cancelBuild();
    void pump(); // drain events + finalize task, called every frame

    // ── persistence helpers ──────────────────────────────────────────────
    std::vector<HistoryEntry> loadHistory();
    void saveProfile(const std::string& name, const std::string& description);
    void deleteProfile(const BuildProfile& profile);
    void persist();

    ~AppState();

private:
    std::vector<std::string> disabledTokensList() const;
    void setToggles(const std::vector<std::string>& disabled);
    void reportPostBuild(const BuildResult& result);

    // thread handoff
    std::mutex eventMutex_;
    std::deque<BuildEvent> pendingEvents_;
    std::unique_ptr<std::thread> buildThread_;
    std::atomic<bool> cancelRequested_{false};
    std::atomic<bool> buildDone_{false};
    BuildResult buildResult_;
    bool threadStarted_ = false;
};

} // namespace peg
