// main.cpp — Win32 window + OpenGL 3.3 context + Dear ImGui (win32/opengl3 backends).
// Zero external dependencies: user32, gdi32, opengl32 only.
#include "app.h"
#include "screens.h"
#include "theme.h"
#include "loc.h"
#include <imgui.h>
#include <imgui_impl_win32.h>
#include <imgui_impl_opengl3.h>
#include <windows.h>
#include <GL/gl.h>
#include <chrono>
#include <thread>

// Forward declarations
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace {

constexpr int kWindowWidth = 1120;
constexpr int kWindowHeight = 720;
const wchar_t* kClassName = L"PolyEngineGUI";
const wchar_t* kWindowTitle = L"PolyEngine GUI";

HGLRC g_glrc = nullptr;
HDC g_hdc = nullptr;
HWND g_hwnd = nullptr;
bool g_running = true;

// Pixel format descriptor — OpenGL 3.3 core (forward compatible).
PIXELFORMATDESCRIPTOR g_pfd = [] {
    PIXELFORMATDESCRIPTOR pfd{};
    pfd.nSize = sizeof(PIXELFORMATDESCRIPTOR);
    pfd.nVersion = 1;
    pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
    pfd.iPixelType = PFD_TYPE_RGBA;
    pfd.cColorBits = 32;
    pfd.cAlphaBits = 8;
    pfd.cDepthBits = 24;
    pfd.cStencilBits = 8;
    pfd.iLayerType = PFD_MAIN_PLANE;
    return pfd;
}();

// Window class + message loop
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wParam, lParam))
        return true;

    switch (msg) {
        case WM_SIZE:
            if (g_glrc && wParam != SIZE_MINIMIZED) {
                // GL context is current on the render thread; update viewport next frame.
            }
            return 0;
        case WM_DROPFILES: {
            HDROP drop = (HDROP)wParam;
            wchar_t buf[2048];
            UINT count = DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0);
            if (count > 0 && DragQueryFileW(drop, 0, buf, 2048) > 0) {
                POINT pt;
                DragQueryPoint(drop, &pt);             // screen coords
                ScreenToClient(hwnd, &pt);             // -> client coords (ImGui space)
                peg::onOsFileDrop(buf, pt.x, pt.y);
            }
            DragFinish(drop);
            return 0;
        }
        case WM_DESTROY:
            g_running = false;
            PostQuitMessage(0);
            return 0;
        case WM_GETMINMAXINFO: {
            // Fixed window: clamp min=max so no resize is possible.
            auto* mmi = reinterpret_cast<MINMAXINFO*>(lParam);
            mmi->ptMinTrackSize.x = kWindowWidth;
            mmi->ptMinTrackSize.y = kWindowHeight;
            mmi->ptMaxTrackSize.x = kWindowWidth;
            mmi->ptMaxTrackSize.y = kWindowHeight;
            return 0;
        }
        default:
            return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
}

// WGL_ARB_create_context constants (not in the SDK headers without wglext.h).
#ifndef WGL_CONTEXT_MAJOR_VERSION_ARB
#define WGL_CONTEXT_MAJOR_VERSION_ARB 0x2091
#define WGL_CONTEXT_MINOR_VERSION_ARB 0x2092
#define WGL_CONTEXT_PROFILE_MASK_ARB 0x9126
#define WGL_CONTEXT_CORE_PROFILE_BIT_ARB 0x00000001
#define WGL_CONTEXT_FLAGS_ARB 0x2094
#define WGL_CONTEXT_FORWARD_COMPATIBLE_BIT_ARB 0x00000002
#endif

bool initOpenGL(HWND hwnd) {
    g_hdc = GetDC(hwnd);

    // Temporary legacy context to get a 3.3 core context via wglCreateContextAttribsARB.
    int pixelFormat = ChoosePixelFormat(g_hdc, &g_pfd);
    if (pixelFormat == 0) return false;
    SetPixelFormat(g_hdc, pixelFormat, &g_pfd);

    HGLRC legacy = wglCreateContext(g_hdc);
    if (!legacy) return false;
    wglMakeCurrent(g_hdc, legacy);

    // wglCreateContextAttribsARB (WGL_ARB_create_context)
    typedef HGLRC(WINAPI* PFNWGLCREATECONTEXTATTRIBSARBPROC)(HDC, HGLRC, const int*);
    PFNWGLCREATECONTEXTATTRIBSARBPROC createAttribs =
        (PFNWGLCREATECONTEXTATTRIBSARBPROC)wglGetProcAddress("wglCreateContextAttribsARB");

    HGLRC modern = nullptr;
    if (createAttribs) {
        const int attribs[] = {
            WGL_CONTEXT_MAJOR_VERSION_ARB, 3,
            WGL_CONTEXT_MINOR_VERSION_ARB, 3,
            WGL_CONTEXT_PROFILE_MASK_ARB, WGL_CONTEXT_CORE_PROFILE_BIT_ARB,
            WGL_CONTEXT_FLAGS_ARB, WGL_CONTEXT_FORWARD_COMPATIBLE_BIT_ARB,
            0
        };
        modern = createAttribs(g_hdc, nullptr, attribs);
    }

    wglMakeCurrent(nullptr, nullptr);
    wglDeleteContext(legacy);

    if (!modern) return false;
    g_glrc = modern;
    wglMakeCurrent(g_hdc, g_glrc);
    return true;
}

} // namespace

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    // Register window class
    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = kClassName;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;
    RegisterClassW(&wc);

    // Fixed-size window without maximize box
    DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    RECT rc{0, 0, kWindowWidth, kWindowHeight};
    AdjustWindowRect(&rc, style, FALSE);

    g_hwnd = CreateWindowW(kClassName, kWindowTitle, style,
                           CW_USEDEFAULT, CW_USEDEFAULT,
                           rc.right - rc.left, rc.bottom - rc.top,
                           nullptr, nullptr, hInstance, nullptr);
    if (!g_hwnd) return 1;

    DragAcceptFiles(g_hwnd, TRUE); // OS file drops into path fields

    if (!initOpenGL(g_hwnd)) {
        MessageBoxW(g_hwnd, L"Failed to create OpenGL 3.3 context.", L"PolyEngine GUI",
                    MB_ICONERROR | MB_OK);
        return 1;
    }

    // ImGui init
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr; // no .ini persistence

    // Font: Consolas 13px — ranges must cover Polish diacritics (Latin Extended-A),
    // arrows (→) and math operators (≤) or ImGui renders '?' for missing glyphs.
    const wchar_t* fontPath = L"C:\\Windows\\Fonts\\consola.ttf";
    if (GetFileAttributesW(fontPath) != INVALID_FILE_ATTRIBUTES) {
        std::string utf8 = peg::wideToUtf8(fontPath);
        ImFontConfig cfg;
        cfg.OversampleH = 2;
        cfg.OversampleV = 2;
        static ImVector<ImWchar> ranges; // must outlive font add
        ImFontGlyphRangesBuilder builder;
        builder.AddRanges(io.Fonts->GetGlyphRangesDefault());   // Basic Latin + Latin-1
        builder.AddRanges(io.Fonts->GetGlyphRangesCyrillic());
        for (ImWchar c = 0x0100; c <= 0x017F; c++) builder.AddChar(c); // Latin Extended-A: ą ć ę ł ń ś ź ż
        for (ImWchar c = 0x2018; c <= 0x201F; c++) builder.AddChar(c); // quotes '' „ ”
        for (ImWchar c = 0x2190; c <= 0x21FF; c++) builder.AddChar(c); // arrows → (Token descriptions)
        for (ImWchar c = 0x2200; c <= 0x22FF; c++) builder.AddChar(c); // math operators ≤ ≥
        builder.BuildRanges(&ranges);
        io.Fonts->AddFontFromFileTTF(utf8.c_str(), 13.0f, &cfg, ranges.Data);
    }

    ImGui_ImplWin32_Init(g_hwnd);
    ImGui_ImplOpenGL3_Init("#version 330 core");

    peg::theme::apply();

    // Application state (exe-dir relative stores)
    peg::AppState app;

    ShowWindow(g_hwnd, nCmdShow);
    UpdateWindow(g_hwnd);

    // Main loop
    while (g_running) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if (!g_running) break;

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        peg::drawShell(app);

        ImGui::Render();

        RECT rc;
        GetClientRect(g_hwnd, &rc);
        glViewport(0, 0, rc.right, rc.bottom);
        glClearColor(0.043f, 0.055f, 0.067f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);

        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        SwapBuffers(g_hdc);
    }

    // Shutdown
    app.persist();
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    wglMakeCurrent(nullptr, nullptr);
    if (g_glrc) wglDeleteContext(g_glrc);
    if (g_hdc) ReleaseDC(g_hwnd, g_hdc);

    return 0;
}
