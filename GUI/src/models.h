#pragma once
// Models — 1:1 port of the C# PolyEngine.GUI.Models set.
#include <string>
#include <vector>
#include <optional>
#include <cstdint>

namespace peg {

enum class BuildEventKind { Info, Success, Warning, Phase };

struct BuildEvent {
    BuildEventKind kind = BuildEventKind::Info;
    std::string text;
    std::optional<double> phase; // 10.5 included for progress
};

// Mirror of Builder.exe BUILD_CONFIG. Null/empty numeric fields mean "omit the flag"
// (Builder applies its own defaults: sleep-fwd 500 ms, uptime 2 min, hammer 3 s).
struct BuildConfig {
    std::string inputPath;
    std::string outputPath;
    std::string stubPath;      // empty = omit --stub
    std::string preset = "PRINT";
    bool overload = false;
    bool keepAlive = false;
    bool unhook = false;

    std::string exportName;
    std::string exportArg;

    std::string spoofName;
    std::string execCtrlName;
    std::optional<int> sleepFwdMs;
    std::optional<int> uptimeMin;
    std::optional<int> hammerS;

    std::vector<std::string> disabledTokens; // lower-case --disable tokens

    std::string pfxPath;
    std::string pfxPassword;   // never persisted to disk
    std::string tsUrl;
    std::string cloneMetaPath;
    bool uac = false;

    BuildConfig clone() const { return *this; }
};

enum class ValidationSeverity { Error, Warning };

enum class ValidationCode {
    InputRequired, InputNotFound, InputInvalidExtension, OutputRequired, InvalidPreset,
    ExportNameTooLong, ExportArgTooLong, SpoofNameTooLong, ExecCtrlNameTooLong,
    ExportRequiresDll, PfxPasswordRequiresPfx, PfxRequiresPassword, TsUrlRequiresPfx,
    WarnTsUrlOpsec, WarnPfxPasswordVisible, WarnAllEvasionDisabled, WarnKeepAliveSuggested,
    InvalidNumber, NumberOutOfRange, WarnTsUrlFormat, PfxNotFound, CloneMetaNotFound,
    BuilderNotConfigured, StubsMissing,
};

struct ValidationIssue {
    ValidationSeverity severity = ValidationSeverity::Error;
    ValidationCode code = ValidationCode::InputRequired;
    std::string field; // optional, e.g. "--sleep-fwd-ms = \"x\""
    bool isError() const { return severity == ValidationSeverity::Error; }
};

struct BuildResult {
    bool cancelled = false;
    std::optional<int> exitCode;
    double durationSeconds = 0.0;
    std::string outputFullPath;
    bool outputFileExists = false;

    bool success() const { return !cancelled && exitCode.has_value() && *exitCode == 0 && outputFileExists; }
};

enum class SignatureState { NotSigned, SignedUnverified };

struct PostBuildInfo {
    std::string filePath;
    int64_t sizeBytes = 0;
    std::string sha256Hex;
    SignatureState signatureState = SignatureState::NotSigned;
    std::string signatureIssuer;
};

struct BuildProfile {
    std::string name;
    std::string description;
    BuildConfig config;
    bool isFactoryPreset = false;
};

struct HistoryEntry {
    int64_t timestampUnixMs = 0; // DateTimeOffset.ToUnixTimeMilliseconds
    std::string commandLine;
    BuildConfig config;
    bool success = false;
    std::optional<int> exitCode;
    double durationSeconds = 0.0;
    std::string sha256;
    std::optional<int64_t> outputSizeBytes;
    std::string signatureIssuer;
};

} // namespace peg
