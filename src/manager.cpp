#include "installer.hpp"
#include "password_store.hpp"
#include "reporting.hpp"
#include "viewport.hpp"
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <vector>
using namespace bzap;
namespace {
constexpr COLORREF Background = RGB(244, 246, 250), Ink = RGB(25, 34, 52), Muted = RGB(100, 111, 132),
                   Accent = RGB(79, 70, 229);
enum ControlId {
    InstallButton = 100,
    RemoveButton,
    RecordsButton,
    RefreshButton,
    EnabledCheck,
    NotifyCheck,
    VerifyCheck,
    BrowseButton,
    ClearButton,
    RecycleCheck
};
HWND mainWindow, directoryText, enabledCheck, notifyCheck, verifyCheck, recycleCheck;
HFONT bodyFont, smallFont, titleFont, headingFont;
HBRUSH whiteBrush;
UINT dpi = 96;
int scrollX = 0, scrollY = 0;
bool updatingViewport = false;
UINT previewDpi = 0;
int previewWidth = 0, previewHeight = 0;
bool previewBottom = false;
bool preview = false;
HANDLE elevation = nullptr;
std::wstring installDirectory, packageDirectory, statusTitle, statusHint, passwordHint;
InstallStatus installStatus;
int S(int n) {
    return MulDiv(n, dpi, 96);
}
RECT Rect(int x, int y, int w, int h) {
    return {S(x), S(y), S(x + w), S(y + h)};
}
void Text(HDC dc, const std::wstring &text, RECT r, HFONT font, COLORREF color,
          UINT flags = DT_LEFT | DT_VCENTER | DT_SINGLELINE) {
    SelectObject(dc, font);
    SetTextColor(dc, color);
    SetBkMode(dc, TRANSPARENT);
    DrawTextW(dc, text.c_str(), -1, &r, flags);
}
void Card(HDC dc, RECT r, COLORREF fill) {
    auto b = CreateSolidBrush(fill);
    auto old = SelectObject(dc, b);
    auto pen = SelectObject(dc, GetStockObject(NULL_PEN));
    RoundRect(dc, r.left, r.top, r.right, r.bottom, S(20), S(20));
    SelectObject(dc, old);
    SelectObject(dc, pen);
    DeleteObject(b);
}
void MakeFonts() {
    for (auto f : {bodyFont, smallFont, titleFont, headingFont})
        if (f)
            DeleteObject(f);
    auto font = [](int size, int weight) {
        return CreateFontW(-S(size), 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                           OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH,
                           L"Microsoft YaHei UI");
    };
    bodyFont = font(15, FW_NORMAL);
    smallFont = font(12, FW_NORMAL);
    titleFont = font(28, FW_SEMIBOLD);
    headingFont = font(18, FW_SEMIBOLD);
}
void Refresh() {
    auto settings = preview ? Settings() : LoadSettings();
    if (preview) {
        installStatus = {};
        installStatus.supported = true;
        installStatus.version = L"7.47.0.1";
        passwordHint = L"已保存 12 个不同密码 · 本地读取";
    } else {
        installStatus = GetInstallStatus(installDirectory, packageDirectory);
        auto store = ReadPasswordStore();
        passwordHint = store.status == StoreStatus::Ready
                           ? L"已保存 " + std::to_wstring(store.passwords.size()) + L" 个不同密码 · 本地读取"
                           : StoreDescription(store.status);
    }
    statusTitle = installStatus.updateAvailable ? L"插件有可用更新" : installStatus.installed ? (installStatus.supported ? L"已接入 Bandizip" : L"需要重新适配")
                  : installStatus.supported ? L"准备就绪"
                                            : L"检查 Bandizip 版本";
    statusHint = installStatus.updateAvailable ? L"点击“更新接入”，完成后关闭管理器即可照常使用。" : installStatus.installed && installStatus.supported
                     ? L"照常打开或右键解压。安装后可以关闭此管理器。"
                 : installStatus.supported ? L"安装一次，以后自动尝试密码管理器中已保存的密码。"
                                           : L"支持 Bandizip 7.47.0.1 x64，请选择兼容的安装目录。";
    SetWindowTextW(directoryText, installDirectory.c_str());
    SendMessageW(enabledCheck, BM_SETCHECK, settings.enabled ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessageW(notifyCheck, BM_SETCHECK, settings.notify ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessageW(verifyCheck, BM_SETCHECK, settings.verify ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessageW(recycleCheck, BM_SETCHECK, settings.recycle ? BST_CHECKED : BST_UNCHECKED, 0);
    SetWindowTextW(GetDlgItem(mainWindow, InstallButton),
                   installStatus.updateAvailable ? L"更新接入" : installStatus.installed ? L"修复接入" : L"安装接入");
    EnableWindow(GetDlgItem(mainWindow, InstallButton), installStatus.supported && !elevation);
    EnableWindow(GetDlgItem(mainWindow, RemoveButton), installStatus.installed && !elevation);
    InvalidateRect(mainWindow, nullptr, FALSE);
}
void DrawScene(HDC dc) {
    RECT client;
    GetClientRect(mainWindow, &client);
    auto bg = CreateSolidBrush(Background);
    FillRect(dc, &client, bg);
    DeleteObject(bg);
    int saved = SaveDC(dc);
    SetViewportOrgEx(dc, -scrollX, -scrollY, nullptr);
    auto icon = (HICON)LoadImageW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(101), IMAGE_ICON, S(48), S(48),
                                  LR_SHARED);
    DrawIconEx(dc, S(32), S(30), icon, S(48), S(48), 0, nullptr, DI_NORMAL);
    Text(dc, L"Bandizip 自动密码", Rect(96, 25, 600, 42), titleFont, Ink);
    Text(dc, std::wstring(L"安装包 ") + ProductVersion + L"  ·  " +
                 (installStatus.installed ? L"已安装 " + installStatus.installedVersion : L"未安装"),
         Rect(97, 69, 770, 22), smallFont, Muted);
    Card(dc, Rect(32, 120, 856, 142), RGB(255, 255, 255));
    Card(dc, Rect(56, 145, 5, 86), installStatus.supported ? Accent : RGB(210, 143, 51));
    Text(dc, statusTitle, Rect(78, 141, 620, 28), headingFont, Ink);
    Text(dc, statusHint, Rect(78, 180, 760, 24), bodyFont, Muted);
    Text(dc, passwordHint, Rect(78, 215, 760, 22), smallFont, Muted);
    Text(dc, L"安装位置", Rect(32, 280, 500, 24), bodyFont, Ink);
    Card(dc, Rect(32, 316, 856, 56), RGB(255, 255, 255));
    Text(dc, L"解压偏好", Rect(32, 395, 500, 24), bodyFont, Ink);
    Card(dc, Rect(32, 432, 856, 160), RGB(255, 255, 255));
    Text(dc, L"使用 Bandizip 内已有的密码", Rect(478, 444, 382, 30), smallFont, Muted);
    Text(dc, L"列出未完成的压缩包", Rect(478, 480, 382, 30), smallFont, Muted);
    Text(dc, L"额外读取并解压一次，增加耗时", Rect(478, 516, 382, 30), smallFont, Muted);
    Text(dc, L"仅完整解压成功；含已确认的分卷", Rect(478, 552, 382, 30), smallFont, Muted);
    Text(dc, L"Windows x64  ·  本地处理  ·  无需常驻助手", Rect(32, 674, 810, 20), smallFont, Muted);
    RestoreDC(dc, saved);
}
HWND Control(const wchar_t *kind, const wchar_t *text, DWORD style, int x, int y, int w, int h, int id) {
    if (_wcsicmp(kind, L"BUTTON") == 0) style |= BS_NOTIFY;
    auto c = CreateWindowExW(0, kind, text, WS_CHILD | WS_VISIBLE | style, S(x), S(y), S(w), S(h), mainWindow,
                             (HMENU)(INT_PTR)id, GetModuleHandleW(nullptr), nullptr);
    SendMessageW(c, WM_SETFONT, (WPARAM)bodyFont, TRUE);
    return c;
}
void Layout() {
    const int ids[] = {InstallButton, RemoveButton, RecordsButton, ClearButton, RefreshButton, BrowseButton,
                       EnabledCheck,  NotifyCheck,  VerifyCheck,   200,         RecycleCheck};
    const int boxes[][4] = {{32, 616, 180, 44},  {228, 616, 140, 44}, {384, 616, 140, 44},
                            {540, 616, 140, 44}, {748, 616, 140, 44}, {776, 326, 96, 36},
                            {56, 444, 400, 30},  {56, 480, 400, 30},  {56, 516, 400, 30},
                            {50, 332, 710, 28},  {56, 552, 400, 30}};
    for (int i = 0; i < 11; i++) {
        auto c = GetDlgItem(mainWindow, ids[i]);
        MoveWindow(c, S(boxes[i][0]) - scrollX, S(boxes[i][1]) - scrollY, S(boxes[i][2]), S(boxes[i][3]), TRUE);
        SendMessageW(c, WM_SETFONT, (WPARAM)bodyFont, TRUE);
    }
}
void UpdateViewport() {
    if (updatingViewport) return;
    updatingViewport = true;
    // Recompute after either scrollbar changes the client area.
    for (int pass = 0; pass < 3; ++pass) {
        RECT client; GetClientRect(mainWindow, &client);
        scrollX = ScrollPosition(scrollX, S(920), client.right);
        scrollY = ScrollPosition(scrollY, S(714), client.bottom);
        SCROLLINFO horizontal{sizeof(SCROLLINFO), SIF_RANGE | SIF_PAGE | SIF_POS,
                              0, S(920) - 1, (UINT)client.right, scrollX, 0};
        SCROLLINFO vertical{sizeof(SCROLLINFO), SIF_RANGE | SIF_PAGE | SIF_POS,
                            0, S(714) - 1, (UINT)client.bottom, scrollY, 0};
        SetScrollInfo(mainWindow, SB_HORZ, &horizontal, TRUE);
        SetScrollInfo(mainWindow, SB_VERT, &vertical, TRUE);
    }
    Layout();
    InvalidateRect(mainWindow, nullptr, TRUE);
    updatingViewport = false;
}
void Scroll(int bar, int action, int wheel = 0) {
    SCROLLINFO info{sizeof(SCROLLINFO), SIF_ALL};
    GetScrollInfo(mainWindow, bar, &info);
    int position = bar == SB_VERT ? scrollY : scrollX;
    switch (action) {
    case SB_LINEUP: position -= S(36); break;
    case SB_LINEDOWN: position += S(36); break;
    case SB_PAGEUP: position -= (int)info.nPage; break;
    case SB_PAGEDOWN: position += (int)info.nPage; break;
    case SB_THUMBTRACK: case SB_THUMBPOSITION: position = info.nTrackPos; break;
    case SB_TOP: position = 0; break;
    case SB_BOTTOM: position = info.nMax; break;
    default: position -= wheel; break;
    }
    (bar == SB_VERT ? scrollY : scrollX) = position;
    UpdateViewport();
}
void RevealControl(HWND control) {
    RECT box, client;
    if (!control || !GetWindowRect(control, &box)) return;
    MapWindowPoints(nullptr, mainWindow, (POINT *)&box, 2);
    GetClientRect(mainWindow, &client);
    if (box.left < 0) scrollX += box.left;
    else if (box.right > client.right) scrollX += box.right - client.right;
    if (box.top < 0) scrollY += box.top;
    else if (box.bottom > client.bottom) scrollY += box.bottom - client.bottom;
    UpdateViewport();
}
void SaveSettings() {
    if (preview)
        return;
    std::string data = "[General]\r\n";
    for (auto item : {std::pair<const char *, HWND>{"Enabled", enabledCheck},
                      {"NotifyFailures", notifyCheck},
                      {"FullPreflight", verifyCheck},
                      {"RecycleAfterExtract", recycleCheck}})
        data += std::string(item.first) + "=" +
                (SendMessageW(item.second, BM_GETCHECK, 0, 0) == BST_CHECKED ? "1" : "0") + "\r\n";
    auto file = Join(DataDirectory(), L"settings.ini");
    if (!AtomicWrite(file, data)) {
        MessageBoxW(mainWindow, L"设置未能保存，请检查文件夹权限。", L"保存设置", MB_OK | MB_ICONWARNING);
        Refresh();
    }
    WritePrivateProfileStringW(nullptr, nullptr, nullptr, file.c_str());
}
void Browse() {
    IFileDialog *dialog = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog))))
        return;
    DWORD options;
    dialog->GetOptions(&options);
    dialog->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
    dialog->SetTitle(L"选择 Bandizip 安装目录");
    if (SUCCEEDED(dialog->Show(mainWindow))) {
        IShellItem *item = nullptr;
        if (SUCCEEDED(dialog->GetResult(&item))) {
            PWSTR path = nullptr;
            if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path))) {
                installDirectory = path;
                CoTaskMemFree(path);
                Refresh();
            }
            item->Release();
        }
    }
    dialog->Release();
}
void Manage(bool install) {
    if (preview || elevation)
        return;
    auto result = install ? Install(installDirectory, packageDirectory) : Uninstall(installDirectory);
    if (!result.ok && result.code == ERROR_ACCESS_DENIED && !IsUserAnAdmin()) {
        auto args = std::wstring(install ? L"--install" : L"--uninstall") + L" --directory \"" +
                    installDirectory + L"\"";
        auto self = ModulePath();
        SHELLEXECUTEINFOW info = {sizeof(info)};
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.hwnd = mainWindow;
        info.lpVerb = L"runas";
        info.lpFile = self.c_str();
        info.lpParameters = args.c_str();
        info.nShow = SW_SHOWNORMAL;
        if (ShellExecuteExW(&info)) {
            elevation = info.hProcess;
            SetTimer(mainWindow, 1, 300, nullptr);
            Refresh();
            return;
        }
        result = {false, GetLastError(), L"未完成管理员授权，请重新安装。"};
    }
    MessageBoxW(mainWindow, result.message.c_str(), L"Bandizip 自动密码",
                MB_OK | (result.ok ? MB_ICONINFORMATION : MB_ICONWARNING));
    Refresh();
}
void ClearRecords() {
    if (preview)
        return;
    if (MessageBoxW(mainWindow, L"清除本扩展的全部解压记录？", L"清除记录", MB_YESNO | MB_ICONQUESTION) !=
        IDYES)
        return;
    HANDLE mutex = CreateMutexW(nullptr, FALSE, L"Local\\BandizipAutoPassword.History.v1");
    auto wait = mutex ? WaitForSingleObject(mutex, 3000) : WAIT_FAILED;
    bool ok = false;
    if (wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED) {
        ok = true;
        for (auto name :
             {L"history.jsonl", L"history.jsonl.previous", L"解压记录.txt", L"解压记录.txt.previous"}) {
            auto file = Join(DataDirectory(), name);
            if (Exists(file) && !DeleteFileW(file.c_str()))
                ok = false;
        }
        ReleaseMutex(mutex);
    }
    if (mutex)
        CloseHandle(mutex);
    if (!ok)
        MessageBoxW(mainWindow, L"部分记录正在使用，请稍后重试。", L"清除记录", MB_OK | MB_ICONWARNING);
}
LRESULT CALLBACK WindowProc(HWND window, UINT msg, WPARAM w, LPARAM l) {
    if (msg == WM_CREATE) {
        mainWindow = window;
        dpi = preview && previewDpi ? previewDpi : GetDpiForWindow(window);
        MakeFonts();
        whiteBrush = CreateSolidBrush(RGB(255, 255, 255));
        directoryText =
            Control(L"EDIT", L"", ES_READONLY | ES_AUTOHSCROLL | WS_TABSTOP, 50, 332, 710, 28, 200);
        enabledCheck = Control(L"BUTTON", L"自动尝试保存的密码", BS_AUTOCHECKBOX | WS_TABSTOP, 56, 444, 400,
                               32, EnabledCheck);
        notifyCheck = Control(L"BUTTON", L"失败时显示汇总提醒", BS_AUTOCHECKBOX | WS_TABSTOP, 56, 489, 400,
                              32, NotifyCheck);
        verifyCheck = Control(L"BUTTON", L"完整预校验（可选）", BS_AUTOCHECKBOX | WS_TABSTOP, 56, 534, 400,
                              32, VerifyCheck);
        recycleCheck = Control(L"BUTTON", L"成功解压后移入回收站", BS_AUTOCHECKBOX | WS_TABSTOP, 56, 552, 400,
                               30, RecycleCheck);
        for (auto item : {std::pair<int, const wchar_t *>{InstallButton, L"安装接入"},
                          {RemoveButton, L"卸载插件"},
                          {RecordsButton, L"查看记录"},
                          {ClearButton, L"清除记录"},
                          {RefreshButton, L"刷新状态"},
                          {BrowseButton, L"更改"}})
            Control(L"BUTTON", item.second, BS_OWNERDRAW | WS_TABSTOP, 0, 0, 1, 1, item.first);
        Layout();
        Refresh();
        return 0;
    }
    if (msg == WM_PAINT) {
        PAINTSTRUCT ps;
        auto dc = BeginPaint(window, &ps);
        DrawScene(dc);
        EndPaint(window, &ps);
        return 0;
    }
    if (msg == WM_SIZE) { UpdateViewport(); return 0; }
    if (msg == WM_HSCROLL || msg == WM_VSCROLL) {
        Scroll(msg == WM_VSCROLL ? SB_VERT : SB_HORZ, LOWORD(w)); return 0;
    }
    if (msg == WM_MOUSEWHEEL) {
        Scroll(GetKeyState(VK_SHIFT) < 0 ? SB_HORZ : SB_VERT, -1,
               (short)HIWORD(w) * S(72) / WHEEL_DELTA); return 0;
    }
    if (msg == WM_PRINTCLIENT) {
        DrawScene((HDC)w);
        return 0;
    }
    if (msg == WM_ERASEBKGND)
        return 1;
    if (msg == WM_CTLCOLORSTATIC || msg == WM_CTLCOLOREDIT || msg == WM_CTLCOLORBTN) {
        SetTextColor((HDC)w, Ink);
        SetBkColor((HDC)w, RGB(255, 255, 255));
        return (LRESULT)whiteBrush;
    }
    if (msg == WM_DRAWITEM) {
        auto d = (DRAWITEMSTRUCT *)l;
        auto background = CreateSolidBrush(d->CtlID == BrowseButton ? RGB(255, 255, 255) : Background);
        FillRect(d->hDC, &d->rcItem, background);
        DeleteObject(background);
        bool primary = d->CtlID == InstallButton, disabled = d->itemState & ODS_DISABLED;
        COLORREF fill = disabled ? RGB(225, 228, 236) : primary ? Accent : RGB(255, 255, 255);
        if (d->itemState & ODS_SELECTED)
            fill = primary ? RGB(59, 50, 190) : RGB(232, 235, 245);
        Card(d->hDC, d->rcItem, fill);
        wchar_t label[128];
        GetWindowTextW(d->hwndItem, label, 128);
        Text(d->hDC, label, d->rcItem, bodyFont,
             disabled  ? Muted
             : primary ? RGB(255, 255, 255)
                       : Ink,
             DT_CENTER | DT_SINGLELINE | DT_VCENTER);
        if (d->itemState & ODS_FOCUS) {
            RECT r = d->rcItem;
            InflateRect(&r, -S(4), -S(4));
            DrawFocusRect(d->hDC, &r);
        }
        return TRUE;
    }
    if (msg == WM_DPICHANGED) {
        dpi = HIWORD(w);
        MakeFonts();
        auto r = (RECT *)l;
        MONITORINFO monitor{sizeof(MONITORINFO)};
        GetMonitorInfoW(MonitorFromRect(r, MONITOR_DEFAULTTONEAREST), &monitor);
        auto fitted = FitWindow(*r, monitor.rcWork);
        SetWindowPos(window, nullptr, fitted.left, fitted.top, fitted.right - fitted.left, fitted.bottom - fitted.top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        UpdateViewport();
        InvalidateRect(window, nullptr, TRUE);
        return 0;
    }
    if (msg == WM_TIMER && elevation && WaitForSingleObject(elevation, 0) == WAIT_OBJECT_0) {
        CloseHandle(elevation);
        elevation = nullptr;
        KillTimer(window, 1);
        Refresh();
        return 0;
    }
    if (msg == WM_COMMAND) {
        if (HIWORD(w) == BN_SETFOCUS || HIWORD(w) == EN_SETFOCUS) {
            RevealControl((HWND)l); return 0;
        }
        if (HIWORD(w) != BN_CLICKED) return 0;
        switch (LOWORD(w)) {
        case InstallButton:
            Manage(true);
            break;
        case RemoveButton:
            Manage(false);
            break;
        case BrowseButton:
            Browse();
            break;
        case RecordsButton:
            if (!preview)
                ShowRecords();
            break;
        case ClearButton:
            ClearRecords();
            break;
        case RefreshButton:
            Refresh();
            break;
        case EnabledCheck:
        case NotifyCheck:
        case VerifyCheck:
        case RecycleCheck:
            SaveSettings();
            break;
        }
        return 0;
    }
    if (msg == WM_DESTROY) {
        if (elevation)
            CloseHandle(elevation);
        for (auto f : {bodyFont, smallFont, titleFont, headingFont})
            DeleteObject(f);
        DeleteObject(whiteBrush);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, msg, w, l);
}
// Offscreen rendering uses synthetic data and only this application's controls.
bool RenderPreview(const std::wstring &path) {
    RECT r;
    GetClientRect(mainWindow, &r);
    int width = r.right, height = r.bottom;
    auto screen = GetDC(mainWindow), dc = CreateCompatibleDC(screen);
    auto bitmap = CreateCompatibleBitmap(screen, width, height);
    auto old = SelectObject(dc, bitmap);
    DrawScene(dc);
    for (HWND c = GetWindow(mainWindow, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT)) {
        RECT box;
        GetWindowRect(c, &box);
        POINT p = {box.left, box.top};
        ScreenToClient(mainWindow, &p);
        int saved = SaveDC(dc);
        SetViewportOrgEx(dc, p.x, p.y, nullptr);
        SendMessageW(c, WM_PRINT, (WPARAM)dc, PRF_CLIENT | PRF_ERASEBKGND);
        RestoreDC(dc, saved);
    }
    SelectObject(dc, old);
    BITMAPINFO info = {};
    info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth = width;
    info.bmiHeader.biHeight = -height;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    std::string pixels(width * height * 4, '\0');
    GetDIBits(dc, bitmap, 0, height, pixels.data(), &info, DIB_RGB_COLORS);
    BITMAPFILEHEADER header = {};
    header.bfType = 0x4d42;
    header.bfOffBits = sizeof(header) + sizeof(info.bmiHeader);
    header.bfSize = header.bfOffBits + (DWORD)pixels.size();
    std::string bytes((char *)&header, sizeof(header));
    bytes.append((char *)&info.bmiHeader, sizeof(info.bmiHeader));
    bytes += pixels;
    DeleteObject(bitmap);
    DeleteDC(dc);
    ReleaseDC(mainWindow, screen);
    return AtomicWrite(path, bytes);
}
} // namespace
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    INITCOMMONCONTROLSEX controls = {sizeof(controls), ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&controls);
    packageDirectory = Directory(ModulePath());
    installDirectory = DefaultBandizipDirectory();
    int argc = 0;
    auto argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    bool install = false, remove = false, quiet = false, status = false;
    std::wstring output, render;
    for (int i = 1; i < argc; i++) {
        std::wstring arg = argv[i];
        if (arg == L"--preview")
            preview = true;
        else if (arg == L"--preview-dpi" && i + 1 < argc)
            previewDpi = (UINT)std::clamp(_wtoi(argv[++i]), 96, 288);
        else if (arg == L"--preview-size" && i + 2 < argc) {
            previewWidth = std::max(320, _wtoi(argv[++i]));
            previewHeight = std::max(240, _wtoi(argv[++i]));
        } else if (arg == L"--preview-bottom") previewBottom = true;
        else if (arg == L"--render-preview" && i + 1 < argc) {
            preview = true;
            render = argv[++i];
        } else if (arg == L"--install")
            install = true;
        else if (arg == L"--uninstall")
            remove = true;
        else if (arg == L"--quiet")
            quiet = true;
        else if (arg == L"--status")
            status = true;
        else if (arg == L"--directory" && i + 1 < argc)
            installDirectory = argv[++i];
        else if (arg == L"--result" && i + 1 < argc)
            output = argv[++i];
        else if (arg == L"--records") {
            ShowRecords();
            return 0;
        }
    }
    LocalFree(argv);
    if (status) {
        auto s = GetInstallStatus(installDirectory, packageDirectory);
        auto text = "{\"supported\":" + std::string(s.supported ? "true" : "false") +
                    ",\"installed\":" + (s.installed ? "true" : "false") +
                    ",\"backup_valid\":" + (s.backupValid ? "true" : "false") +
                    ",\"installed_version\":" + Json(s.installedVersion) +
                    ",\"package_version\":" + Json(ProductVersion) +
                    ",\"update_available\":" + (s.updateAvailable ? "true" : "false") +
                    ",\"version\":" + Json(s.version) + ",\"detail\":" + Json(s.detail) + "}";
        if (!output.empty() && !AtomicWrite(output, text))
            return (int)GetLastError();
        return s.installed ? 0 : 2;
    }
    if (install || remove) {
        auto r = install ? Install(installDirectory, packageDirectory) : Uninstall(installDirectory);
        if (!output.empty() && !AtomicWrite(output, "{\"ok\":" + std::string(r.ok ? "true" : "false") +
                                                        ",\"code\":" + std::to_string(r.code) +
                                                        ",\"message\":" + Json(r.message) + "}"))
            return (int)GetLastError();
        if (!quiet)
            MessageBoxW(nullptr, r.message.c_str(), L"Bandizip 自动密码",
                        MB_OK | (r.ok ? MB_ICONINFORMATION : MB_ICONWARNING));
        return r.ok ? 0 : (int)(r.code ? r.code : 1);
    }
    if (preview)
        installDirectory = L"C:\\Program Files\\Bandizip";
    WNDCLASSW cls = {};
    cls.lpfnWndProc = WindowProc;
    cls.hInstance = instance;
    cls.lpszClassName = L"BandizipAutoPassword.Manager";
    cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    cls.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(101));
    RegisterClassW(&cls);
    dpi = previewDpi && preview ? previewDpi : GetDpiForSystem();
    RECT size = Rect(0, 0, 920, 714);
    DWORD style = WS_OVERLAPPEDWINDOW;
    AdjustWindowRectExForDpi(&size, style, FALSE, 0, dpi);
    POINT cursor{}; GetCursorPos(&cursor);
    MONITORINFO monitor{sizeof(MONITORINFO)};
    GetMonitorInfoW(MonitorFromPoint(cursor, MONITOR_DEFAULTTONEAREST), &monitor);
    RECT position{monitor.rcWork.left, monitor.rcWork.top,
                  monitor.rcWork.left + size.right - size.left, monitor.rcWork.top + size.bottom - size.top};
    if (render.empty()) position = FitWindow(position, monitor.rcWork);
    if (preview && previewWidth && previewHeight) {
        position.right = position.left + previewWidth; position.bottom = position.top + previewHeight;
    }
    auto window =
        CreateWindowExW(0, cls.lpszClassName, L"Bandizip 自动密码", style, position.left, position.top,
                        position.right - position.left, position.bottom - position.top, nullptr, nullptr, instance, nullptr);
    if (!window)
        return 1;
    if (!render.empty()) {
        if (previewBottom) { scrollY = S(714); UpdateViewport(); }
        bool ok = RenderPreview(render);
        DestroyWindow(window);
        return ok ? 0 : 1;
    }
    ShowWindow(window, show);
    MSG message;
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(window, &message)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    CoUninitialize();
    return 0;
}
