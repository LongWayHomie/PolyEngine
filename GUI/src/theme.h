#pragma once
// theme.h — ops-console dark palette, port of Theme.cs.
#include <cstdint>
#include <imgui.h>

namespace peg::theme {

inline ImVec4 hex(uint32_t rgb, float alpha = 1.0f) {
    return ImVec4(((rgb >> 16) & 0xFF) / 255.0f,
                  ((rgb >> 8) & 0xFF) / 255.0f,
                  (rgb & 0xFF) / 255.0f,
                  alpha);
}

// palette
inline const ImVec4 kBg = hex(0x0B0E11);
inline const ImVec4 kPanel = hex(0x12161B);
inline const ImVec4 kPanelAlt = hex(0x171D24);
inline const ImVec4 kBorder = hex(0x242C36);
inline const ImVec4 kBorderStrong = hex(0x33404E);
inline const ImVec4 kText = hex(0xD8E1E8);
inline const ImVec4 kTextMuted = hex(0x6C7A89);
inline const ImVec4 kTextDim = hex(0x4A5766);
inline const ImVec4 kAccent = hex(0x2FE58C);
inline const ImVec4 kAccentDim = hex(0x1E9E64);
inline const ImVec4 kAccentBg = hex(0x122A21);
inline const ImVec4 kError = hex(0xFF5C5C);
inline const ImVec4 kErrorBg = hex(0x2A1414);
inline const ImVec4 kWarning = hex(0xFFB454);
inline const ImVec4 kWarningBg = hex(0x2A1F10);
inline const ImVec4 kPhase = hex(0x4FC1FF);
inline const ImVec4 kSuccess = hex(0x2FE58C);
inline const ImVec4 kInfo = hex(0xB8C4CE);

void apply();
void tooltip(const char* text);      // wrapped tooltip (420px)
void muted(const char* text);        // TextMuted-colored text
void dim(const char* text);          // TextDim-colored text

} // namespace peg::theme
