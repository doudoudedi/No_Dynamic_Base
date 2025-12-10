// fix_dynamic_base.cpp
// A minimal Win32 GUI program that accepts a PE file via drag-and-drop
// and clears the IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE flag (fixes base address).
//
// ✅ No dependency on libgcc_s_dw2-1.dll / libstdc++-6.dll
//    Build as PURE Win32 C-style program (no exceptions / no RTTI / static runtime)
//
// Build (MinGW-w64 x86_64):
// x86_64-w64-mingw32-g++ fix_dynamic_base.cpp \
//   -static -static-libgcc -static-libstdc++ \
//   -fno-exceptions -fno-rtti \
//   -municode -o FixDynamicBase.exe -luser32 -lshell32

#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

// IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040

static const wchar_t CLASS_NAME[] = L"FixDynamicBaseClass";

static void Info(HWND hwnd, const wchar_t* fmt, ...) {
    wchar_t buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vswprintf(buf, 1024, fmt, ap);
    va_end(ap);
    MessageBoxW(hwnd, buf, L"FixDynamicBase", MB_OK | MB_ICONINFORMATION);
}

static bool read_file_all(const wchar_t* path, uint8_t** buf, size_t* size) {
    FILE* f = _wfopen(path, L"rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); return false; }
    fseek(f, 0, SEEK_SET);
    uint8_t* b = (uint8_t*)malloc(sz);
    if (!b) { fclose(f); return false; }
    if (fread(b, 1, sz, f) != (size_t)sz) { free(b); fclose(f); return false; }
    fclose(f);
    *buf = b;
    *size = (size_t)sz;
    return true;
}

static bool write_file_all(const wchar_t* path, const uint8_t* buf, size_t size) {
    // backup: original + .bak
    wchar_t bak[MAX_PATH];
    wsprintfW(bak, L"%s.bak", path);
    CopyFileW(path, bak, FALSE);

    FILE* f = _wfopen(path, L"rb+");
    if (!f) return false;
    fseek(f, 0, SEEK_SET);
    fwrite(buf, 1, size, f);
    fflush(f);
    fclose(f);
    return true;
}

static bool fix_pe_clear_dynamic_base(uint8_t* buf, size_t size, bool* modified, wchar_t* reason) {
    *modified = false;

    if (size < sizeof(IMAGE_DOS_HEADER)) {
        lstrcpyW(reason, L"file too small");
        return false;
    }

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        lstrcpyW(reason, L"not a PE file (MZ missing)");
        return false;
    }

    if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > size) {
        lstrcpyW(reason, L"invalid e_lfanew");
        return false;
    }

    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        lstrcpyW(reason, L"PE signature missing");
        return false;
    }

    WORD magic = nt->OptionalHeader.Magic;

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        WORD old = nt->OptionalHeader.DllCharacteristics;
        if (old & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
            nt->OptionalHeader.DllCharacteristics = old & ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
            *modified = true;
        }
        return true;
    }

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_NT_HEADERS32* nt32 = (IMAGE_NT_HEADERS32*)nt;
        WORD old = nt32->OptionalHeader.DllCharacteristics;
        if (old & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
            nt32->OptionalHeader.DllCharacteristics = old & ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
            *modified = true;
        }
        return true;
    }

    lstrcpyW(reason, L"unknown PE optional header type");
    return false;
}

static void process_file(HWND hwnd, const wchar_t* path) {
    uint8_t* buf = NULL;
    size_t size = 0;

    if (!read_file_all(path, &buf, &size)) {
        Info(hwnd, L"Failed to read file:\n%s", path);
        return;
    }

    bool modified = false;
    wchar_t reason[256] = {0};

    if (!fix_pe_clear_dynamic_base(buf, size, &modified, reason)) {
        Info(hwnd, L"Error: %s", reason);
        free(buf);
        return;
    }

    if (!modified) {
        Info(hwnd, L"No change needed (already fixed)");
        free(buf);
        return;
    }

    if (!write_file_all(path, buf, size)) {
        Info(hwnd, L"Write failed (permission or file in use)");
        free(buf);
        return;
    }

    Info(hwnd, L"Success! DYNAMIC_BASE cleared. Backup: %s.bak", path);
    free(buf);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        DragAcceptFiles(hwnd, TRUE);
        return 0;
    case WM_DROPFILES: {
        HDROP drop = (HDROP)wParam;
        wchar_t path[MAX_PATH];
        if (DragQueryFileW(drop, 0, path, MAX_PATH)) {
            process_file(hwnd, path);
        }
        DragFinish(drop);
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nCmdShow) {
    WNDCLASSW wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);

    RegisterClassW(&wc);

    HWND hwnd = CreateWindowW(
        CLASS_NAME,
        L"FixDynamicBase - Drag PE Here",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        520, 120,
        NULL, NULL, hInst, NULL
    );

    ShowWindow(hwnd, nCmdShow);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
