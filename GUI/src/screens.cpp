#include "screens.h"
#include "loc.h"
#include "theme.h"
#include "services.h"
#include <imgui.h>
#include <imgui_impl_win32.h>
#include <imgui_impl_opengl3.h>
#include <windows.h>
#include <commdlg.h>
#include <shlobj.h>
#include <cstdio>
#include <cwchar>

namespace peg {

// ── Win32 dialogs ─────────────────────────────────────────────────────────────

// Pending OS file drop (WM_DROPFILES) — consumed by the path field under the cursor.
static std::wstring g_dropPath;
static bool g_dropPending = false;
static float g_dropX = 0, g_dropY = 0;

void onOsFileDrop(const std::wstring& path, int clientX, int clientY) {
    g_dropPath = path;
    g_dropX = (float)clientX;
    g_dropY = (float)clientY;
    g_dropPending = true;
}

bool consumeFileDrop(float x0, float y0, float x1, float y1, std::string& outPath) {
    if (!g_dropPending) return false;
    if (g_dropX >= x0 && g_dropX <= x1 && g_dropY >= y0 && g_dropY <= y1) {
        outPath = wideToUtf8(g_dropPath);
        g_dropPending = false;
        return true;
    }
    return false;
}

void clearFileDrop() {
    g_dropPending = false;
}

static std::wstring dialogFilter(const std::string& extList) {
    // "exe,dll,bin" → "*.exe;*.dll;*.bin"
    std::wstring out;
    std::string ext = extList;
    size_t start = 0;
    while (true) {
        size_t comma = ext.find(',', start);
        std::string part = ext.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
        if (!out.empty()) out += L';';
        out += L"*." + utf8ToWide(trimWhitespace(part));
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return out;
}

// Builds an OPENFILENAME filter string. The Win32 filter format is
// "Name1\0Pattern1\0Name2\0Pattern2\0\0" — embedded NULs are mandatory and a
// std::wstring literal stops at the first \0, so they are appended explicitly.
static std::wstring buildFilter(const std::wstring& name, const std::wstring& pattern) {
    std::wstring f = name;
    f.push_back(L'\0');
    f += pattern;
    f.push_back(L'\0');
    f += L"All files (*.*)";
    f.push_back(L'\0');
    f += L"*.*";
    f.push_back(L'\0');
    return f;
}

std::string openFileDialog(const std::wstring& title, const std::string& extList) {
    wchar_t fileBuf[2048] = L"";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof ofn;
    ofn.hwndOwner = GetActiveWindow();
    ofn.lpstrTitle = title.c_str();
    ofn.lpstrFile = fileBuf;
    ofn.nMaxFile = 2048;

    static std::wstring filter; // must outlive the call
    if (extList.empty()) {
        filter = buildFilter(L"All files (*.*)", L"*.*");
    } else {
        std::wstring ext = dialogFilter(extList);
        filter = buildFilter(L"Supported files (" + ext + L")", ext);
    }
    ofn.lpstrFilter = filter.c_str();

    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileNameW(&ofn))
        return wideToUtf8(fileBuf);
    return {};
}

std::string saveFileDialog(const std::wstring& title, const std::string& extList) {
    wchar_t fileBuf[2048] = L"";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof ofn;
    ofn.hwndOwner = GetActiveWindow();
    ofn.lpstrTitle = title.c_str();
    ofn.lpstrFile = fileBuf;
    ofn.nMaxFile = 2048;

    static std::wstring filter; // must outlive the call
    std::wstring defExt;
    if (extList.empty()) {
        filter = buildFilter(L"All files (*.*)", L"*.*");
    } else {
        std::wstring ext = dialogFilter(extList);
        filter = buildFilter(L"Supported files (" + ext + L")", ext);
        size_t comma = extList.find(',');
        defExt = utf8ToWide(trimWhitespace(extList.substr(0, comma == std::string::npos ? std::string::npos : comma)));
        ofn.lpstrDefExt = defExt.c_str();
    }
    ofn.lpstrFilter = filter.c_str();
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
    if (GetSaveFileNameW(&ofn))
        return wideToUtf8(fileBuf);
    return {};
}

std::wstring pickFolder(const std::wstring& title) {
    wchar_t buf[MAX_PATH];
    BROWSEINFOW bi{};
    bi.hwndOwner = GetActiveWindow();
    bi.lpszTitle = title.c_str();
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_USENEWUI;
    PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return {};
    bool ok = SHGetPathFromIDListW(pidl, buf);
    CoTaskMemFree(pidl);
    return ok ? std::wstring(buf) : std::wstring();
}

// ── shared UI helpers ─────────────────────────────────────────────────────────

static void Labeled(const char* label, const std::function<void()>& control) {
    ImGui::PushStyleColor(ImGuiCol_Text, theme::kTextMuted);
    ImGui::TextUnformatted(label);
    ImGui::PopStyleColor();
    control();
}

static void Section(const char* title, const std::function<void()>& body, bool openByDefault) {
    ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_OpenOnArrow | ImGuiTreeNodeFlags_SpanAvailWidth;
    if (openByDefault) flags |= ImGuiTreeNodeFlags_DefaultOpen;
    ImGui::PushStyleColor(ImGuiCol_Header, theme::kPanelAlt);
    ImGui::PushStyleColor(ImGuiCol_HeaderHovered, theme::kPanel);
    if (ImGui::CollapsingHeader(title, flags)) {
        ImGui::Indent(14.0f);
        body();
        ImGui::Unindent(14.0f);
    }
    ImGui::PopStyleColor(2);
}

// Checkbox with a label that wraps inside the column — long labels must never
// overflow under the neighbouring Command Preview column.
static void CheckboxRow(const char* label, bool& value) {
    float available = ImGui::GetContentRegionAvail().x;
    float labelWidth = ImGui::CalcTextSize(label).x;
    float frameWidth = ImGui::GetFrameHeight() + ImGui::GetStyle().ItemInnerSpacing.x;
    if (labelWidth + frameWidth < available) {
        ImGui::Checkbox(label, &value);
        return;
    }
    ImGui::Checkbox(("##wrap-" + std::string(label)).c_str(), &value);
    ImGui::SameLine();
    float wrapPos = ImGui::GetCursorPosX() + available;
    ImGui::PushTextWrapPos(wrapPos);
    ImGui::TextWrapped("%s", label);
    ImGui::PopTextWrapPos();
}

static void ToggleRow(const ToggleItem& item) {
    bool value = item.isEnabled;
    ImGui::Checkbox(item.label.c_str(), &const_cast<bool&>(value));
    const_cast<ToggleItem&>(item).isEnabled = value;
    // Tooltip: raw CLI token + full technical description.
    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::PushStyleColor(ImGuiCol_Text, theme::kAccent);
        ImGui::TextUnformatted(item.token.c_str());
        ImGui::PopStyleColor();
        ImGui::PushTextWrapPos(420.0f);
        ImGui::TextUnformatted(item.description.c_str());
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
}

static void ToggleGrid(std::vector<ToggleItem>& items) {
    // Single left-aligned column — every checkbox sits on one vertical line.
    // A checkbox already advances to the next row; an extra NewLine() would
    // double the inter-row spacing.
    for (size_t i = 0; i < items.size(); i++) {
        ToggleRow(items[i]);
    }
}

// Per-field edit buffers, keyed by widget id. ImGui keeps a pointer to the buffer
// for the whole edit session (across frames) — a single shared buffer would make
// fields overwrite each other's text, and a local string would dangle after the
// frame ends (the PFX password "vanishing" bug).
static std::map<std::string, std::vector<char>> g_editBuffers;

static bool InputTextImpl(std::string& value, size_t maxLen, const char* id, ImGuiInputTextFlags flags) {
    auto& buf = g_editBuffers[id];
    // ImGui writes up to maxLen bytes into the buffer — it must be pre-allocated
    // to at least maxLen+1 regardless of the current value length. A short buffer
    // sized to value.size()+1 caused heap corruption (0xc0000374) on typing.
    if (buf.size() < maxLen + 1)
        buf.resize(maxLen + 1, '\0');
    // Resync when the value changed externally (profile load, history rerun) or on first use.
    // memcpy, not assign: assign would shrink the vector and re-open the overflow.
    if (value != std::string(buf.data())) {
        memcpy(buf.data(), value.c_str(), value.size() + 1);
    }
    bool changed = ImGui::InputText(id, buf.data(), (int)maxLen, flags);
    if (changed) value = std::string(buf.data());
    return changed;
}

static bool InputText(std::string& value, size_t maxLen, const char* id) {
    return InputTextImpl(value, maxLen, id, 0);
}

static bool PasswordText(std::string& value, const char* id) {
    return InputTextImpl(value, 256, id, ImGuiInputTextFlags_Password);
}

// Numeric input with a dim placeholder shown when empty — reminds the operator
// which Builder default will apply (500 ms / 2 min / 3 s).
static bool NumericInput(std::string& value, const char* id, const char* placeholder) {
    bool changed = InputTextImpl(value, 16, id, 0);
    if (value.empty() && !ImGui::IsItemActive()) {
        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 p = ImGui::GetItemRectMin();
        ImVec2 s = ImGui::GetItemRectSize();
        float padY = ImGui::GetStyle().FramePadding.y;
        ImVec2 textPos(p.x + ImGui::GetStyle().FramePadding.x,
                       p.y + padY + (s.y - 2 * padY - ImGui::GetFontSize()) * 0.5f);
        dl->AddText(textPos, ImGui::GetColorU32(theme::kTextDim), placeholder);
    }
    return changed;
}

static void Combo(const char* id, const std::vector<std::string>& items,
                  const std::string& current, const std::function<void(const std::string&)>& set) {
    const char* preview = "?";
    for (const auto& it : items) if (iequals(it, current)) preview = it.c_str();
    if (ImGui::BeginCombo(id, preview)) {
        for (const auto& it : items) {
            if (ImGui::Selectable(it.c_str(), iequals(it, current)))
                set(it);
        }
        ImGui::EndCombo();
    }
}

// ── DrawShell ─────────────────────────────────────────────────────────────────

void drawShell(AppState& app) {
    auto& loc = Loc::instance();

    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(io.DisplaySize);
    ImGui::Begin("##shell", nullptr,
                 ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoMove |
                 ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings |
                 ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoBringToFrontOnFocus);

    const float sidebarW = 150.0f;
    ImGui::BeginChild("##sidebar", ImVec2(sidebarW, -1), ImGuiChildFlags_Borders);

    ImGui::PushStyleColor(ImGuiCol_Text, theme::kAccent);
    ImGui::TextUnformatted("PolyEngine");
    ImGui::PopStyleColor();
    theme::dim("GUI v1.0");
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    auto navItem = [&](AppScreen screen, const char* label) {
        bool selected = app.currentScreen == screen;
        if (selected)
            ImGui::PushStyleColor(ImGuiCol_Text, theme::kAccent);
        if (ImGui::Selectable(label, selected))
            app.currentScreen = screen;
        if (selected)
            ImGui::PopStyleColor();
        if (ImGui::IsItemHovered()) ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
    };

    navItem(AppScreen::Build, loc["Nav.Build"].c_str());
    navItem(AppScreen::Profiles, loc["Nav.Profiles"].c_str());
    navItem(AppScreen::History, loc["Nav.History"].c_str());
    navItem(AppScreen::Settings, loc["Nav.Settings"].c_str());

    ImGui::Spacing();
    ImGui::Separator();

    ImGui::EndChild();
    ImGui::SameLine();

    ImGui::BeginChild("##content", ImVec2(-1, -1));
    switch (app.currentScreen) {
        case AppScreen::Build: drawBuildScreen(app); break;
        case AppScreen::Profiles: drawProfilesScreen(app); break;
        case AppScreen::History: drawHistoryScreen(app); break;
        case AppScreen::Settings: drawSettingsScreen(app); break;
    }
    ImGui::EndChild();

    ImGui::End();

    clearFileDrop(); // discard drops that matched no field this frame
}

// ── BuildScreen ───────────────────────────────────────────────────────────────

static void PathField(AppState& app, const char* id, const char* label, std::string& field,
                      const char* extList, bool isSave, const std::wstring& dialogTitle) {
    Labeled(label, [&] {
        bool changed = InputText(field, 512, id);
        if (changed) app.revalidate();

        // OS drag & drop: file dropped onto this field lands directly in it.
        ImVec2 rMin = ImGui::GetItemRectMin();
        ImVec2 rMax = ImGui::GetItemRectMax();
        std::string dropped;
        if (consumeFileDrop(rMin.x, rMin.y, rMax.x, rMax.y, dropped)) {
            field = dropped;
            app.revalidate();
        }

        ImGui::SameLine();
        if (ImGui::Button(("...##" + std::string(id)).c_str())) {
            std::string path = isSave ? saveFileDialog(dialogTitle, extList)
                                      : openFileDialog(dialogTitle, extList);
            if (!path.empty()) {
                field = path;
                app.revalidate();
            }
        }
    });
}

void drawBuildScreen(AppState& app) {
    app.pump();
    auto& loc = Loc::instance();

    ImVec2 avail = ImGui::GetContentRegionAvail();
    const float gap = 10.0f;
    float leftWidth = (std::max)(340.0f, avail.x * 0.55f);
    float rightWidth = (std::max)(320.0f, avail.x - leftWidth - gap);
    float startY = ImGui::GetCursorPosY();

    // ── left: form ──
    ImGui::BeginChild("##form", ImVec2(leftWidth, avail.y), ImGuiChildFlags_Borders);

    Section(loc["Build.PayloadSection"].c_str(), [&] {
        PathField(app, "##input", loc["Build.InputPath"].c_str(), app.inputPath,
                  "exe,dll,bin", false, utf8ToWide(loc["Build.DialogInput"]));
        PathField(app, "##output", loc["Build.OutputPath"].c_str(), app.outputPath,
                  "exe", true, utf8ToWide(loc["Build.DialogOutput"]));
        PathField(app, "##stub", loc["Build.StubPath"].c_str(), app.stubPath,
                  "bin", false, utf8ToWide(loc["Build.DialogStub"]));
    }, true);

    Section(loc["Build.LoaderSection"].c_str(), [&] {
        Labeled(loc["Build.Preset"].c_str(), [&] {
            Combo("##preset", AppState::kPresetPool, app.preset,
                  [&](const std::string& v) { app.preset = v; });
        });
        CheckboxRow(loc["Build.Overload"].c_str(), app.overload);
        CheckboxRow(loc["Build.KeepAlive"].c_str(), app.keepAlive);
        CheckboxRow(loc["Build.Unhook"].c_str(), app.unhook);
    }, true);

    Section(loc["Build.PayloadOptionsSection"].c_str(), [&] {
        Labeled(loc["Build.ExportName"].c_str(), [&] {
            if (InputText(app.exportName, 64, "##export")) app.revalidate();
        });
        Labeled(loc["Build.ExportArg"].c_str(), [&] {
            if (InputText(app.exportArg, 128, "##arg")) app.revalidate();
        });
    }, true);

    Section(loc["Build.EvasionOpsec"].c_str(), [&] {
        ToggleGrid(app.opsecToggles);
    }, true);

    Section(loc["Build.EvasionSandbox"].c_str(), [&] {
        ToggleGrid(app.sandboxToggles);
    }, true);

    Section(loc["Build.EvasionTuning"].c_str(), [&] {
        Labeled(loc["Build.SpoofName"].c_str(), [&] {
            bool changed = InputText(app.spoofName, 64, "##spoof");
            if (changed) app.revalidate();
            ImGui::SameLine();
            if (ImGui::Button("pool##spoof")) ImGui::OpenPopup("##spoollist");
            if (ImGui::BeginPopup("##spoollist")) {
                for (const auto& s : AppState::kSpoofPool) {
                    if (ImGui::Selectable(s.c_str()))
                        app.spoofName = s;
                }
                ImGui::EndPopup();
            }
        });
        Labeled(loc["Build.ExecCtrlName"].c_str(), [&] {
            if (InputText(app.execCtrlName, 32, "##execctl")) app.revalidate();
        });
        Labeled(loc["Build.SleepFwdMs"].c_str(), [&] {
            if (NumericInput(app.sleepFwdMsText, "##sleep", "500")) app.revalidate();
        });
        Labeled(loc["Build.UptimeMin"].c_str(), [&] {
            if (NumericInput(app.uptimeMinText, "##uptime", "2")) app.revalidate();
        });
        Labeled(loc["Build.HammerS"].c_str(), [&] {
            if (NumericInput(app.hammerSText, "##hammer", "3")) app.revalidate();
        });
    }, true);

    Section(loc["Build.IdentitySection"].c_str(), [&] {
        PathField(app, "##pfx", loc["Build.PfxPath"].c_str(), app.pfxPath,
                  "pfx,p12", false, utf8ToWide(loc["Build.DialogPfx"]));
        Labeled(loc["Build.PfxPassword"].c_str(), [&] {
            if (PasswordText(app.pfxPassword, "##pfxpass")) app.revalidate();
        });
        Labeled(loc["Build.TsUrl"].c_str(), [&] {
            if (InputText(app.tsUrl, 256, "##tsurl")) app.revalidate();
        });
        PathField(app, "##clone", loc["Build.CloneMetaPath"].c_str(), app.cloneMetaPath,
                  "exe,dll", false, utf8ToWide(loc["Build.DialogCloneMeta"]));
        CheckboxRow(loc["Build.Uac"].c_str(), app.uac);
    }, true);

    ImGui::EndChild();

    // ── right: command preview + build + log ──
    ImGui::SetCursorPosY(startY);
    ImGui::SetCursorPosX(leftWidth + gap);
    ImGui::BeginChild("##commandpanel", ImVec2(rightWidth, avail.y), ImGuiChildFlags_Borders);

    ImGui::PushStyleColor(ImGuiCol_Text, theme::kAccent);
    ImGui::TextUnformatted(loc["Build.CommandPreview"].c_str());
    ImGui::PopStyleColor();
    ImGui::SameLine(rightWidth - 100);
    if (ImGui::Button(loc["Common.Copy"].c_str())) {
        // ImGui win32 backend already wires clipboard callbacks — just use io.
        ImGui::SetClipboardText(app.commandPreview().c_str());
    }

    // Wrapped text, recomputed every frame — InputTextMultiline kept an internal
    // edit-state cache, so a ReadOnly buffer that changed length/text externally
    // would not refresh on the screen.
    std::string preview = app.commandPreview();
    ImGui::PushStyleColor(ImGuiCol_ChildBg, theme::kPanelAlt);
    ImGui::BeginChild("##cmdline", ImVec2(rightWidth - 24, 162), ImGuiChildFlags_Borders);
    ImGui::PushTextWrapPos(ImGui::GetContentRegionAvail().x - 6);
    ImGui::TextWrapped("%s", preview.c_str());
    ImGui::PopTextWrapPos();
    ImGui::EndChild();
    ImGui::PopStyleColor();

    if (app.isBuilding) {
        if (ImGui::Button(loc["Common.Cancel"].c_str(), ImVec2(110, 30)))
            app.cancelBuild();
    } else {
        ImGui::BeginDisabled(!app.canBuild());
        if (ImGui::Button(loc["Common.Build"].c_str(), ImVec2(110, 30)))
            app.startBuild();
        ImGui::EndDisabled();
    }

    // progress bar
    ImGui::ProgressBar((float)(app.currentPhase / 12.0), ImVec2(rightWidth - 24, 0),
                       app.isBuilding ? loc["Build.Progress"].c_str() : "");

    ImGui::PushStyleColor(ImGuiCol_Text, theme::kText);
    ImGui::TextWrapped("%s", app.statusText.c_str());
    ImGui::PopStyleColor();
    if (!app.outputInfoText.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, theme::kInfo);
        ImGui::TextWrapped("%s", app.outputInfoText.c_str());
        ImGui::PopStyleColor();
    }

    // validation
    auto issues = app.localizedIssues();
    for (const auto& issue : issues) {
        ImGui::PushStyleColor(ImGuiCol_Text, issue.isError ? theme::kError : theme::kWarning);
        ImGui::TextUnformatted(issue.isError ? "[!] " : "[*] ");
        ImGui::SameLine();
        ImGui::TextWrapped("%s", issue.text.c_str());
        ImGui::PopStyleColor();
    }

    ImGui::Separator();

    // log
    ImGui::BeginChild("##log", ImVec2(rightWidth - 4, -1), ImGuiChildFlags_Borders);
    // Auto-follow only while already at the bottom — otherwise the per-frame
    // SetScrollHereY would fight the mouse wheel and scrolling up would be impossible.
    bool atBottom = ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 4.0f;
    ImGui::PushTextWrapPos(ImGui::GetContentRegionAvail().x - 8);
    for (const auto& e : app.log) {
        ImVec4 color = theme::kText;
        switch (e.kind) {
            case BuildEventKind::Success: color = theme::kSuccess; break;
            case BuildEventKind::Warning: color = theme::kWarning; break;
            case BuildEventKind::Phase: color = theme::kPhase; break;
            default: break;
        }
        ImGui::PushStyleColor(ImGuiCol_Text, color);
        ImGui::TextUnformatted(e.text.c_str());
        ImGui::PopStyleColor();
    }
    ImGui::PopTextWrapPos();
    if (atBottom && !app.log.empty())
        ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();

    ImGui::EndChild();
}

// ── ProfilesScreen ────────────────────────────────────────────────────────────

void drawProfilesScreen(AppState& app) {
    auto& loc = Loc::instance();
    static std::string newName, newDescription;
    static std::string status;
    ImVec2 avail = ImGui::GetContentRegionAvail();

    ImGui::PushStyleColor(ImGuiCol_Text, theme::kAccent);
    ImGui::TextUnformatted(loc["Profiles.Heading"].c_str());
    ImGui::PopStyleColor();
    theme::muted(loc["Profiles.Subtitle"].c_str());
    ImGui::Spacing();

    ImGui::BeginChild("##save", ImVec2(avail.x, 150), ImGuiChildFlags_Borders);
    ImGui::PushStyleColor(ImGuiCol_Text, theme::kTextMuted);
    ImGui::TextUnformatted(loc["Profiles.Name"].c_str());
    ImGui::PopStyleColor();
    ImGui::SetNextItemWidth(avail.x * 0.45f);
    InputText(newName, 64, "##name");
    ImGui::PushStyleColor(ImGuiCol_Text, theme::kTextMuted);
    ImGui::TextUnformatted(loc["Profiles.Description"].c_str());
    ImGui::PopStyleColor();
    ImGui::SetNextItemWidth(avail.x * 0.45f);
    InputText(newDescription, 256, "##desc");

    if (ImGui::Button(loc["Common.Save"].c_str())) {
        if (trimWhitespace(newName).empty())
            status = loc["Profiles.NameRequired"];
        else {
            app.saveProfile(newName, newDescription);
            status = loc.format("Profiles.Saved", trimWhitespace(newName));
            newName.clear();
            newDescription.clear();
        }
    }
    ImGui::SameLine();
    if (!status.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, theme::kWarning);
        ImGui::TextUnformatted(status.c_str());
        ImGui::PopStyleColor();
    }
    ImGui::EndChild();

    ImGui::Spacing();
    ImGui::BeginChild("##list", ImVec2(avail.x, -1), ImGuiChildFlags_Borders);
    if (app.profiles.empty()) {
        theme::muted(loc["Profiles.Empty"].c_str());
    }
    for (const auto& p : app.profiles) {
        ImGui::TextUnformatted(p.name.c_str());
        ImGui::SameLine();
        if (p.isFactoryPreset) {
            ImGui::PushStyleColor(ImGuiCol_Text, theme::kAccentDim);
            ImGui::TextUnformatted(("[" + loc["Profiles.Factory"] + "]").c_str());
            ImGui::PopStyleColor();
        }
        ImGui::SameLine(avail.x - 190);
        if (ImGui::Button((loc["Common.Apply"] + "##" + p.name).c_str())) {
            app.applyProfile(p);
            app.currentScreen = AppScreen::Build;
        }
        ImGui::SameLine();
        ImGui::BeginDisabled(p.isFactoryPreset);
        if (ImGui::Button((loc["Common.Delete"] + "##" + p.name).c_str())) {
            app.deleteProfile(p);
            status = loc.format("Profiles.Deleted", p.name);
        }
        ImGui::EndDisabled();
    }
    ImGui::EndChild();
}

// ── HistoryScreen ─────────────────────────────────────────────────────────────

void drawHistoryScreen(AppState& app) {
    auto& loc = Loc::instance();
    static std::vector<HistoryEntry> entries;
    static bool loaded = false;

    ImVec2 avail = ImGui::GetContentRegionAvail();

    ImGui::PushStyleColor(ImGuiCol_Text, theme::kAccent);
    ImGui::TextUnformatted(loc["History.Heading"].c_str());
    ImGui::PopStyleColor();
    ImGui::SameLine(avail.x - 210);
    if (ImGui::Button(loc["History.Refresh"].c_str())) {
        entries = app.loadHistory();
        loaded = true;
    }
    ImGui::SameLine();
    if (ImGui::Button(loc["History.Flush"].c_str())) {
        app.historyStore.flush();
        entries.clear();
        loaded = true;
    }
    theme::muted(loc["History.Subtitle"].c_str());
    ImGui::Spacing();

    if (!loaded) {
        entries = app.loadHistory();
        loaded = true;
    }

    ImGui::BeginChild("##history", ImVec2(avail.x, -1), ImGuiChildFlags_Borders);
    float wrap = avail.x - 16;
    if (entries.empty()) {
        theme::muted(loc["History.Empty"].c_str());
    }
    for (const auto& entry : entries) {
        // timestamp
        std::time_t secs = entry.timestampUnixMs / 1000;
        std::tm tm;
        localtime_s(&tm, &secs);
        char timeBuf[64];
        strftime(timeBuf, sizeof timeBuf, "%Y-%m-%d %H:%M:%S", &tm);

        ImGui::PushStyleColor(ImGuiCol_Text, theme::kTextMuted);
        ImGui::TextUnformatted(timeBuf);
        ImGui::PopStyleColor();
        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Text, entry.success ? theme::kSuccess : theme::kError);
        ImGui::TextUnformatted(entry.success ? "[OK]" : "[FAIL]");
        ImGui::PopStyleColor();

        ImGui::SameLine(avail.x - 170);
        if (ImGui::Button((loc["History.Rerun"] + "##" + std::to_string(entry.timestampUnixMs)).c_str())) {
            app.applyConfig(entry.config);
            app.currentScreen = AppScreen::Build;
        }

        ImGui::PushTextWrapPos(wrap);
        ImGui::TextUnformatted(entry.commandLine.c_str());
        ImGui::PopTextWrapPos();

        std::string details;
        if (entry.outputSizeBytes) {
            char sz[64];
            snprintf(sz, sizeof sz, "%lld", (long long)*entry.outputSizeBytes);
            details = std::string("Size: ") + sz + "  ";
        }
        details += "SHA-256: " + (entry.sha256.empty() ? std::string("\u2014") : entry.sha256);
        ImGui::PushTextWrapPos(wrap);
        theme::dim(details.c_str());
        ImGui::PopTextWrapPos();

        ImGui::Spacing();
        ImGui::Separator();
    }
    ImGui::EndChild();
}

// ── SettingsScreen ────────────────────────────────────────────────────────────

static void DrawPath(AppSettings& settings, const char* id, const char* label,
                     std::wstring& field, bool isFile) {
    ImGui::PushStyleColor(ImGuiCol_Text, theme::kTextMuted);
    ImGui::TextUnformatted(label);
    ImGui::PopStyleColor();

    std::string utf8Field = wideToUtf8(field);
    ImGui::SetNextItemWidth((std::max)(320.0f, ImGui::GetContentRegionAvail().x - 90));
    if (InputText(utf8Field, 512, id))
        field = utf8ToWide(utf8Field);
    ImGui::SameLine();
    if (ImGui::Button(("...##" + std::string(id)).c_str())) {
        if (isFile) {
            std::string path = openFileDialog(L"", "");
            if (!path.empty()) field = utf8ToWide(path);
        } else {
            std::wstring dir = pickFolder(L"");
            if (!dir.empty()) field = dir;
        }
    }
}

void drawSettingsScreen(AppState& app) {
    auto& loc = Loc::instance();
    static std::string status;

    ImGui::PushStyleColor(ImGuiCol_Text, theme::kAccent);
    ImGui::TextUnformatted(loc["Settings.Heading"].c_str());
    ImGui::PopStyleColor();
    theme::muted(loc["Settings.Subtitle"].c_str());
    ImGui::Spacing();

    ImGui::PushStyleColor(ImGuiCol_Text, theme::kAccent);
    ImGui::TextUnformatted(loc["Settings.PathsHeading"].c_str());
    ImGui::PopStyleColor();
    ImGui::Spacing();

    DrawPath(app.settings, "##builder", loc["Settings.BuilderPath"].c_str(),
             app.settings.builderPath, true);
    DrawPath(app.settings, "##stubdir", loc["Settings.StubDirectory"].c_str(),
             app.settings.stubDirectory, false);
    DrawPath(app.settings, "##outdir", loc["Settings.OutputDirectory"].c_str(),
             app.settings.outputDirectory, false);

    theme::muted(loc["Settings.PathsNote"].c_str());
    ImGui::Spacing();

    ImGui::Spacing();
    if (ImGui::Button(loc["Common.Save"].c_str())) {
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        std::wstring exeDir = exePath;
        auto slash = exeDir.find_last_of(L"\\/");
        if (slash != std::wstring::npos) exeDir = exeDir.substr(0, slash);
        app.settings.save(exeDir);
        status = loc["Settings.Saved"];
    }
    ImGui::SameLine();
    if (!status.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, theme::kSuccess);
        ImGui::TextUnformatted(status.c_str());
        ImGui::PopStyleColor();
    }

    ImGui::Spacing();
    ImGui::Separator();
    theme::dim(("Builder: " + wideToUtf8(app.settings.builderPath)).c_str());
    theme::dim(("Stubs:   " + wideToUtf8(app.settings.stubDirectory)).c_str());
    theme::dim(("Output:  " + wideToUtf8(app.settings.outputDirectory)).c_str());
}

} // namespace peg
