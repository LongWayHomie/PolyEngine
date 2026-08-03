#pragma once
// screens.h — all UI screens (port of BuildScreen/ProfilesScreen/HistoryScreen/SettingsScreen + shell).
#include "app.h"

namespace peg {

void drawShell(AppState& app);      // root window: sidebar + content + screen switch
void drawBuildScreen(AppState& app);
void drawProfilesScreen(AppState& app);
void drawHistoryScreen(AppState& app);
void drawSettingsScreen(AppState& app);

// Win32 file dialogs (system-native, zero deps). extList like "exe,dll,bin" or "" for all.
std::string openFileDialog(const std::wstring& title, const std::string& extList);
std::string saveFileDialog(const std::wstring& title, const std::string& extList);
std::wstring pickFolder(const std::wstring& title);

// OS drag & drop of files into path fields (WM_DROPFILES).
// Called from WndProc with the drop point already converted to client coords.
void onOsFileDrop(const std::wstring& path, int clientX, int clientY);
// Returns true (and fills outPath) when a pending drop landed inside the rect.
bool consumeFileDrop(float x0, float y0, float x1, float y1, std::string& outPath);
// Drops that matched no field are discarded at the end of the frame.
void clearFileDrop();

} // namespace peg
