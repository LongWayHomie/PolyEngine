// tests.cpp — port of the 51 xUnit tests from PolyEngine.GUI.Tests.
#include "test.h"
// #include "test.h"
#include "models.h"
#include "services.h"
#include "json.h"
#include "app.h"
#include "loc.h"
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>

using namespace peg;

// ── ArgBuilder ─────────────────────────────────────────────────────────────────

TEST_SUITE(ArgBuilderMinimal) {
    BuildConfig cfg;
    cfg.inputPath = "implant.exe";
    cfg.outputPath = "packed.exe";
    CHECK_EQ(buildCommandLine(cfg), std::string("implant.exe packed.exe"));
}

TEST_SUITE(ArgBuilderPreset) {
    BuildConfig cfg;
    cfg.inputPath = "a.exe";
    cfg.outputPath = "b.exe";
    cfg.preset = "network";
    CHECK_EQ(buildCommandLine(cfg), std::string("a.exe b.exe --preset NETWORK"));
}

TEST_SUITE(ArgBuilderExport) {
    BuildConfig cfg;
    cfg.inputPath = "payload.dll";
    cfg.outputPath = "packed.exe";
    cfg.exportName = "Execute";
    cfg.exportArg = "calc.exe";
    CHECK_EQ(buildCommandLine(cfg), std::string("payload.dll packed.exe --export Execute --arg calc.exe"));
}

TEST_SUITE(ArgBuilderDisableTokens) {
    BuildConfig cfg;
    cfg.inputPath = "a.exe";
    cfg.outputPath = "b.exe";
    cfg.disabledTokens = {"etw", "tls"};
    CHECK_EQ(buildCommandLine(cfg), std::string("a.exe b.exe --disable etw,tls"));
}

TEST_SUITE(ArgBuilderDisableAllCollapses) {
    BuildConfig cfg;
    cfg.inputPath = "a.exe";
    cfg.outputPath = "b.exe";
    cfg.disabledTokens = allTokens();
    CHECK_EQ(buildCommandLine(cfg), std::string("a.exe b.exe --disable all"));
}

TEST_SUITE(ArgBuilderTuning) {
    BuildConfig cfg;
    cfg.inputPath = "implant.exe";
    cfg.outputPath = "packed.exe";
    cfg.overload = true;
    cfg.uptimeMin = 5;
    cfg.hammerS = 5;
    CHECK_EQ(buildCommandLine(cfg), std::string("implant.exe packed.exe --overload --uptime-min 5 --hammer-s 5"));
}

TEST_SUITE(ArgBuilderStubAndExecCtrl) {
    BuildConfig cfg;
    cfg.inputPath = "a.exe";
    cfg.outputPath = "b.exe";
    cfg.stubPath = "stub_v2.bin";
    cfg.execCtrlName = "MyMutex";
    cfg.sleepFwdMs = 1000;
    CHECK_EQ(buildCommandLine(cfg), std::string("a.exe b.exe --stub stub_v2.bin --exec-ctrl-name MyMutex --sleep-fwd-ms 1000"));
}

TEST_SUITE(ArgBuilderQuotingSpaces) {
    BuildConfig cfg;
    cfg.inputPath = "my implant.exe";
    cfg.outputPath = "packed.exe";
    CHECK_EQ(buildCommandLine(cfg), std::string("\"my implant.exe\" packed.exe"));
}

TEST_SUITE(QuoteArgumentTable) {
    // Port of the [Theory] InlineData cases from ArgBuilderTests.cs.
    CHECK_EQ(quoteArgument("plain"), std::string("plain"));
    CHECK_EQ(quoteArgument("with space"), std::string("\"with space\""));
    // Trailing backslash without spaces needs no quoting.
    CHECK_EQ(quoteArgument("C:\\dir\\"), std::string("C:\\dir\\"));
    // Quoted argument with trailing backslash: backslash doubled.
    CHECK_EQ(quoteArgument("C:\\my dir\\"), std::string("\"C:\\my dir\\\\\""));
    CHECK_EQ(quoteArgument("a\"b"), std::string("\"a\\\"b\""));
}

// ── ConfigValidator ────────────────────────────────────────────────────────────

TEST_SUITE(ValidateMissingInput) {
    BuildConfig cfg;
    cfg.outputPath = "out.exe";
    auto issues = validateConfig(cfg);
    bool has = false;
    for (const auto& i : issues)
        if (i.code == ValidationCode::InputRequired && i.isError()) has = true;
    CHECK(has);
}

TEST_SUITE(ValidateBadExtension) {
    BuildConfig cfg;
    cfg.inputPath = "C:\\missing.txt";
    cfg.outputPath = "out.exe";
    auto issues = validateConfig(cfg);
    bool has = false;
    for (const auto& i : issues)
        if (i.code == ValidationCode::InputInvalidExtension) has = true;
    CHECK(has);
}

TEST_SUITE(ValidateExportRequiresDll) {
    BuildConfig cfg;
    cfg.inputPath = "a.exe";
    cfg.outputPath = "out.exe";
    cfg.exportName = "Run";
    auto issues = validateConfig(cfg);
    bool has = false;
    for (const auto& i : issues)
        if (i.code == ValidationCode::ExportRequiresDll) has = true;
    CHECK(has);
}

TEST_SUITE(ValidatePfxPasswordRequiresPfx) {
    BuildConfig cfg;
    cfg.inputPath = "a.exe";
    cfg.outputPath = "out.exe";
    cfg.pfxPassword = "secret";
    auto issues = validateConfig(cfg);
    bool has = false;
    for (const auto& i : issues)
        if (i.code == ValidationCode::PfxPasswordRequiresPfx) has = true;
    CHECK(has);
}

TEST_SUITE(ValidateLengthLimits) {
    BuildConfig cfg;
    cfg.inputPath = "a.exe";
    cfg.outputPath = "out.exe";
    cfg.exportName.assign(64, 'x');
    cfg.spoofName.assign(64, 'y');
    cfg.execCtrlName.assign(32, 'z');
    auto issues = validateConfig(cfg);
    bool hasName = false, hasSpoof = false, hasExec = false;
    for (const auto& i : issues) {
        if (i.code == ValidationCode::ExportNameTooLong) hasName = true;
        if (i.code == ValidationCode::SpoofNameTooLong) hasSpoof = true;
        if (i.code == ValidationCode::ExecCtrlNameTooLong) hasExec = true;
    }
    CHECK(hasName);
    CHECK(hasSpoof);
    CHECK(hasExec);
}

TEST_SUITE(ValidateKeepAliveWarningForDll) {
    BuildConfig cfg;
    cfg.inputPath = "a.dll";
    cfg.outputPath = "out.exe";
    auto issues = validateConfig(cfg);
    bool has = false;
    for (const auto& i : issues)
        if (i.code == ValidationCode::WarnKeepAliveSuggested && !i.isError()) has = true;
    CHECK(has);
}

TEST_SUITE(ValidatePfxRequiresPassword) {
    BuildConfig cfg;
    cfg.inputPath = "a.exe";
    cfg.outputPath = "out.exe";
    cfg.pfxPath = "C:\\cert.pfx";
    auto issues = validateConfig(cfg);
    bool has = false;
    for (const auto& i : issues)
        if (i.code == ValidationCode::PfxRequiresPassword && i.isError()) has = true;
    CHECK(has);
}

TEST_SUITE(ValidateNumberRanges) {
    BuildConfig cfg;
    cfg.inputPath = "a.exe";
    cfg.outputPath = "out.exe";
    cfg.sleepFwdMs = 999999;
    cfg.uptimeMin = 0;
    cfg.hammerS = -5;
    auto issues = validateConfig(cfg);
    int rangeCount = 0;
    for (const auto& i : issues)
        if (i.code == ValidationCode::NumberOutOfRange && !i.isError()) rangeCount++;
    CHECK_EQ(rangeCount, 3);
}

TEST_SUITE(ValidateTsUrlFormat) {
    BuildConfig cfg;
    cfg.inputPath = "a.exe";
    cfg.outputPath = "out.exe";
    cfg.pfxPath = "C:\\cert.pfx";
    cfg.pfxPassword = "pw";
    cfg.tsUrl = "freetsa.org/tsa"; // missing scheme
    auto issues = validateConfig(cfg);
    bool has = false;
    for (const auto& i : issues)
        if (i.code == ValidationCode::WarnTsUrlFormat && !i.isError()) has = true;
    CHECK(has);

    cfg.tsUrl = "https://freetsa.org/tsa";
    issues = validateConfig(cfg);
    has = false;
    for (const auto& i : issues)
        if (i.code == ValidationCode::WarnTsUrlFormat) has = true;
    CHECK(!has);
}

TEST_SUITE(ValidatePfxAndCloneMetaExist) {
    BuildConfig cfg;
    cfg.inputPath = "a.exe";
    cfg.outputPath = "out.exe";
    cfg.pfxPath = "C:\\nonexistent.pfx";
    cfg.cloneMetaPath = "C:\\nonexistent_donor.exe";
    auto issues = validateConfig(cfg);
    bool pfx = false, clone = false;
    for (const auto& i : issues) {
        if (i.code == ValidationCode::PfxNotFound) pfx = true;
        if (i.code == ValidationCode::CloneMetaNotFound) clone = true;
    }
    CHECK(pfx);
    CHECK(clone);
}

TEST_SUITE(ValidateDisableAllWarning) {
    BuildConfig cfg;
    cfg.inputPath = "a.exe";
    cfg.outputPath = "out.exe";
    cfg.disabledTokens = allTokens();
    auto issues = validateConfig(cfg);
    bool has = false;
    for (const auto& i : issues)
        if (i.code == ValidationCode::WarnAllEvasionDisabled && !i.isError()) has = true;
    CHECK(has);
}

// ── OutputParser ───────────────────────────────────────────────────────────────

TEST_SUITE(ParsePlusLine) {
    auto e = parseOutputLine("[+] Stub injected");
    CHECK(e.has_value());
    CHECK(e->kind == BuildEventKind::Success);
    CHECK_EQ(e->text, std::string("Stub injected"));
}

TEST_SUITE(ParseBangLine) {
    auto e = parseOutputLine("[!] DecoyImports skipped");
    CHECK(e.has_value());
    CHECK(e->kind == BuildEventKind::Warning);
    CHECK_EQ(e->text, std::string("DecoyImports skipped"));
}

TEST_SUITE(ParsePhaseLine) {
    auto e = parseOutputLine("[*] Phase 4: Encryption");
    CHECK(e.has_value());
    CHECK(e->kind == BuildEventKind::Phase);
    CHECK(e->phase.has_value());
    CHECK_EQ(*e->phase, 4.0);
    CHECK_EQ(e->text, std::string("Phase 4: Encryption"));
}

TEST_SUITE(ParsePhaseDecimal) {
    auto e = parseOutputLine("  [*]   Phase 10.5: Seal");
    CHECK(e.has_value());
    CHECK(e->kind == BuildEventKind::Phase);
    CHECK(e->phase.has_value());
    CHECK_EQ(*e->phase, 10.5);
}

TEST_SUITE(ParsePlainInfo) {
    auto e = parseOutputLine("  building stuff");
    CHECK(e.has_value());
    CHECK(e->kind == BuildEventKind::Info);
    CHECK_EQ(e->text, std::string("building stuff"));
}

TEST_SUITE(ParseBlankLine) {
    auto e = parseOutputLine("   ");
    CHECK(!e.has_value());
}

TEST_SUITE(ParsePhaseWithoutNumberIsInfo) {
    auto e = parseOutputLine("[*] Phase: nah");
    CHECK(e.has_value());
    CHECK(e->kind == BuildEventKind::Info);
}

// ── JSON ───────────────────────────────────────────────────────────────────────

TEST_SUITE(JsonRoundTrip) {
    auto root = JsonValue::makeObject();
    root->set("Name", JsonValue::makeString("hello \"world\"\n\u0105\u0107"));
    root->set("Count", JsonValue::makeNumber(42));
    root->set("Ok", JsonValue::makeBool(true));
    auto arr = JsonValue::makeArray();
    arr->arr.push_back(JsonValue::makeString("a"));
    arr->arr.push_back(JsonValue::makeString("b"));
    root->set("Tags", arr);

    std::string text = jsonSerialize(*root, 4);
    auto parsed = jsonParse(text);
    CHECK(parsed != nullptr);
    CHECK_EQ(parsed->get("Name")->asString(), std::string("hello \"world\"\n\u0105\u0107"));
    CHECK_EQ(parsed->get("Count")->asNumber(), 42.0);
    CHECK(parsed->get("Ok")->asBool());
    CHECK_EQ(parsed->get("Tags")->arr.size(), (size_t)2);
    CHECK_EQ(parsed->get("Tags")->arr[1]->asString(), std::string("b"));
}

TEST_SUITE(JsonRejectsTrailingGarbage) {
    CHECK(jsonParse("{\"a\":1} xyz") == nullptr);
}

TEST_SUITE(JsonToleratesUnicodeEscape) {
    auto v = jsonParse("\"\\u0105b\"");
    CHECK(v != nullptr);
    // \u0105 = U+0105 = ą encoded as UTF-8 0xC4 0x85 (MSVC narrow \u escapes use
    // the active code page, so compare against explicit UTF-8 bytes).
    CHECK_EQ(v->asString(), std::string("\xC4\x85", 2) + "b");
}

// ── ProfileStore / BuildHistoryStore (temp dirs) ───────────────────────────────

TEST_SUITE(ProfileStoreRoundTrip) {
    std::filesystem::path tmp = std::filesystem::temp_directory_path() / "peg_test_profiles";
    std::filesystem::remove_all(tmp);

    ProfileStore store(tmp.wstring());
    BuildProfile p;
    p.name = "MyProfile";
    p.description = "desc";
    p.config.inputPath = "a.exe";
    p.config.preset = "NETWORK";
    p.config.keepAlive = true;
    p.config.disabledTokens = {"etw"};
    store.saveUserProfile(p);

    auto all = store.listAll();
    bool found = false;
    for (const auto& q : all) {
        if (q.name == "MyProfile" && !q.isFactoryPreset) {
            found = true;
            CHECK_EQ(q.config.preset, std::string("NETWORK"));
            CHECK(q.config.keepAlive);
            CHECK_EQ(q.config.disabledTokens.size(), (size_t)1);
        }
    }
    CHECK(found);

    // factory presets always present
    bool hasFactory = false;
    for (const auto& q : all)
        if (q.isFactoryPreset) hasFactory = true;
    CHECK(hasFactory);

    CHECK(store.deleteUserProfile("MyProfile"));
    CHECK(!store.deleteUserProfile("MyProfile"));

    std::filesystem::remove_all(tmp);
}

TEST_SUITE(ProfileStoreSanitizesFilename) {
    std::filesystem::path tmp = std::filesystem::temp_directory_path() / "peg_test_profiles2";
    std::filesystem::remove_all(tmp);

    ProfileStore store(tmp.wstring());
    BuildProfile p;
    p.name = "we<ird:name?";
    store.saveUserProfile(p);

    bool found = false;
    for (const auto& q : store.listAll())
        if (q.name == "we<ird:name?") found = true;
    CHECK(found);
    CHECK(store.deleteUserProfile("we<ird:name?"));

    std::filesystem::remove_all(tmp);
}

TEST_SUITE(BuildHistoryStoreRoundTrip) {
    std::filesystem::path tmp = std::filesystem::temp_directory_path() / "peg_test_history";
    std::filesystem::remove_all(tmp);

    BuildHistoryStore store(tmp.wstring());
    HistoryEntry e1;
    e1.timestampUnixMs = 1000;
    e1.commandLine = "a.exe b.exe";
    e1.success = true;
    e1.sha256 = "ABC";
    e1.outputSizeBytes = 1234;
    store.append(e1);

    HistoryEntry e2;
    e2.timestampUnixMs = 2000;
    e2.commandLine = "c.exe d.exe";
    e2.success = false;
    store.append(e2);

    auto entries = store.loadAll(); // newest first
    CHECK_EQ(entries.size(), (size_t)2);
    CHECK_EQ(entries[0].timestampUnixMs, (int64_t)2000);
    CHECK(!entries[0].success);
    CHECK_EQ(entries[1].timestampUnixMs, (int64_t)1000);
    CHECK(entries[1].success);
    CHECK_EQ(entries[1].sha256, std::string("ABC"));
    CHECK_EQ(*entries[1].outputSizeBytes, (int64_t)1234);

    std::filesystem::remove_all(tmp);
}

TEST_SUITE(BuildHistoryStoreSkipsCorruptLines) {
    std::filesystem::path tmp = std::filesystem::temp_directory_path() / "peg_test_history2";
    std::filesystem::remove_all(tmp);

    std::filesystem::create_directories(tmp / "history");
    std::ofstream out(tmp / "history" / "builds.jsonl", std::ios::binary);
    out << "{\"Timestamp\":1}\n";
    out << "THIS IS NOT JSON\n";
    out << "{\"Timestamp\":2}\n";
    out.close();

    BuildHistoryStore store(tmp.wstring());
    auto entries = store.loadAll();
    CHECK_EQ(entries.size(), (size_t)2);

    std::filesystem::remove_all(tmp);
}

// ── Loc ────────────────────────────────────────────────────────────────────────

TEST_SUITE(LocEnglishOnly) {
    Loc::instance().setLanguage("pl"); // shim — stays English
    CHECK_EQ(Loc::instance().language(), std::string("en"));
    CHECK_EQ(Loc::instance()["Nav.Build"], std::string("Build"));
    // unknown key falls back to the key itself
    CHECK_EQ(Loc::instance()["No.Such.Key"], std::string("No.Such.Key"));
}

TEST_SUITE(LocFormat) {
    Loc::instance().setLanguage("en");
    CHECK_EQ(Loc::instance().format("Profiles.Saved", "abc"), std::string("Profile 'abc' saved."));
}

TEST_SUITE(BuildHistoryStoreLimitsTo20) {
    std::filesystem::path tmp = std::filesystem::temp_directory_path() / "peg_test_history_limit";
    std::filesystem::remove_all(tmp);

    BuildHistoryStore store(tmp.wstring());
    for (int i = 0; i < 25; i++) {
        HistoryEntry e;
        e.timestampUnixMs = i;
        store.append(e);
    }
    auto entries = store.loadAll(); // newest first
    CHECK_EQ(entries.size(), (size_t)20);
    CHECK_EQ(entries[0].timestampUnixMs, (int64_t)24);
    CHECK_EQ(entries[19].timestampUnixMs, (int64_t)5);

    std::filesystem::remove_all(tmp);
}

TEST_SUITE(BuildHistoryStoreFlush) {
    std::filesystem::path tmp = std::filesystem::temp_directory_path() / "peg_test_history_flush";
    std::filesystem::remove_all(tmp);

    BuildHistoryStore store(tmp.wstring());
    HistoryEntry e;
    e.timestampUnixMs = 1;
    store.append(e);
    CHECK_EQ(store.loadAll().size(), (size_t)1);
    store.flush();
    CHECK_EQ(store.loadAll().size(), (size_t)0);

    std::filesystem::remove_all(tmp);
}

// ── main ───────────────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0); // crash-safe diagnostics
    const char* filter = argc > 1 ? argv[1] : nullptr;
    return test::runAll(filter);
}
