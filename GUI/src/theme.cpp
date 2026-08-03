#include "theme.h"
#include "services.h"

namespace peg::theme {

void apply() {
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding = 4.0f;
    s.ChildRounding = 3.0f;
    s.FrameRounding = 3.0f;
    s.PopupRounding = 4.0f;
    s.GrabRounding = 3.0f;
    s.ScrollbarRounding = 3.0f;
    s.TabRounding = 3.0f;
    s.WindowBorderSize = 1.0f;
    s.FrameBorderSize = 1.0f;
    s.WindowPadding = ImVec2(12, 10);
    s.FramePadding = ImVec2(8, 5);
    s.ItemSpacing = ImVec2(8, 6);
    s.ItemInnerSpacing = ImVec2(6, 4);
    s.ScrollbarSize = 10.0f;
    s.WindowTitleAlign = ImVec2(0.5f, 0.5f);

    ImVec4* c = s.Colors;
    c[ImGuiCol_Text] = kText;
    c[ImGuiCol_TextDisabled] = kTextDim;
    c[ImGuiCol_WindowBg] = kBg;
    c[ImGuiCol_ChildBg] = kPanel;
    c[ImGuiCol_PopupBg] = kPanelAlt;
    c[ImGuiCol_Border] = kBorder;
    c[ImGuiCol_BorderShadow] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_FrameBg] = kPanelAlt;
    c[ImGuiCol_FrameBgHovered] = hex(0x1C232C);
    c[ImGuiCol_FrameBgActive] = hex(0x202832);
    c[ImGuiCol_TitleBg] = kPanelAlt;
    c[ImGuiCol_TitleBgActive] = kPanelAlt;
    c[ImGuiCol_TitleBgCollapsed] = kPanel;
    c[ImGuiCol_MenuBarBg] = kPanel;
    c[ImGuiCol_ScrollbarBg] = kPanel;
    c[ImGuiCol_ScrollbarGrab] = hex(0x2E3944);
    c[ImGuiCol_ScrollbarGrabHovered] = hex(0x3A4754);
    c[ImGuiCol_ScrollbarGrabActive] = kBorderStrong;
    c[ImGuiCol_CheckMark] = kAccent;
    c[ImGuiCol_SliderGrab] = kAccentDim;
    c[ImGuiCol_SliderGrabActive] = kAccent;
    c[ImGuiCol_Button] = kPanelAlt;
    c[ImGuiCol_ButtonHovered] = hex(0x1E2630);
    c[ImGuiCol_ButtonActive] = hex(0x242E3A);
    c[ImGuiCol_Header] = kPanelAlt;
    c[ImGuiCol_HeaderHovered] = hex(0x1C232C);
    c[ImGuiCol_HeaderActive] = hex(0x242E3A);
    c[ImGuiCol_Separator] = kBorder;
    c[ImGuiCol_SeparatorHovered] = kBorderStrong;
    c[ImGuiCol_SeparatorActive] = kBorderStrong;
    c[ImGuiCol_ResizeGrip] = kBorder;
    c[ImGuiCol_ResizeGripHovered] = kBorderStrong;
    c[ImGuiCol_ResizeGripActive] = kAccentDim;
    c[ImGuiCol_Tab] = kPanelAlt;
    c[ImGuiCol_TabHovered] = hex(0x1E2630);
    c[ImGuiCol_TabSelected] = kPanelAlt;
    c[ImGuiCol_TabDimmed] = kPanel;
    c[ImGuiCol_TabDimmedSelected] = kPanelAlt;
    c[ImGuiCol_TabSelectedOverline] = kAccent;
    c[ImGuiCol_TabDimmedSelectedOverline] = kBorderStrong;
    c[ImGuiCol_TextSelectedBg] = kAccentBg;
    c[ImGuiCol_NavHighlight] = kAccentDim;
    c[ImGuiCol_ModalWindowDimBg] = ImVec4(0, 0, 0, 0.55f);
}

void tooltip(const char* text) {
    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::PushTextWrapPos(420.0f);
        ImGui::TextUnformatted(text);
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
}

void muted(const char* text) {
    ImGui::PushStyleColor(ImGuiCol_Text, kTextMuted);
    ImGui::TextUnformatted(text);
    ImGui::PopStyleColor();
}

void dim(const char* text) {
    ImGui::PushStyleColor(ImGuiCol_Text, kTextDim);
    ImGui::TextUnformatted(text);
    ImGui::PopStyleColor();
}

} // namespace peg::theme
