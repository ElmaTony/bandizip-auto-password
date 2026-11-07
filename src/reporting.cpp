#include "reporting.hpp"
#include "common.hpp"
#include <atomic>
#include <commctrl.h>
#include <mutex>
#include <shellapi.h>
#include <vector>

namespace bzap {
namespace {
std::mutex pendingMutex;
std::vector<Result> pending;
std::atomic<unsigned> activeOperations{0};
std::atomic<bool> exiting{false};
bool notifierActive = false;
HANDLE changed = nullptr, notifierDone = nullptr;
INIT_ONCE eventsOnce = INIT_ONCE_STATIC_INIT;
BOOL CALLBACK CreateEvents(PINIT_ONCE, void *, void **) {
    changed = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    notifierDone = CreateEventW(nullptr, TRUE, TRUE, nullptr);
    return changed && notifierDone;
}
void Append(const std::wstring &path, const std::string &line) {
    HANDLE file = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return;
    LARGE_INTEGER size;
    if (GetFileSizeEx(file, &size) && size.QuadPart > 5 * 1024 * 1024) {
        CloseHandle(file);
        MoveFileExW(path.c_str(), (path + L".previous").c_str(), MOVEFILE_REPLACE_EXISTING);
        file = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    }
    if (file != INVALID_HANDLE_VALUE) {
        DWORD done;
        WriteFile(file, line.data(), (DWORD)line.size(), &done, nullptr);
        FlushFileBuffers(file);
        CloseHandle(file);
    }
}
std::wstring Description(const Result &r) {
    if (r.outcome == L"success")
        return L"已解压";
    if (r.outcome == L"canceled")
        return L"已取消";
    if (r.outcome == L"passwords_exhausted")
        return L"已有密码全部尝试后仍未成功";
    if (r.outcome == L"password_or_data_error")
        return L"已有密码未能完成校验，可能是密码不匹配或压缩包损坏";
    return L"发生其他解压错误";
}
HRESULT CALLBACK NotifyCallback(HWND window, UINT notice, WPARAM elapsed, LPARAM, LONG_PTR) {
    if (notice == TDN_CREATED)
        Trace(L"NOTIFICATION_CREATED");
    if (notice == TDN_TIMER) {
        wchar_t value[32];
        DWORD n = GetEnvironmentVariableW(L"BZAP_TEST_AUTOCLOSE_MS", value, 32);
        if (n && n < 32) {
            unsigned limit = wcstoul(value, nullptr, 10);
            if (limit && elapsed >= limit)
                SendMessageW(window, TDM_CLICK_BUTTON, IDCLOSE, 0);
        }
    }
    return S_OK;
}
void Display(std::vector<Result> &list) {
    if (list.empty())
        return;
    std::wstring instruction = std::to_wstring(list.size()) + L" 个压缩包未能完成处理";
    std::wstring content;
    for (size_t i = 0; i < list.size() && i < 8; i++) {
        content += list[i].archive + L"\n" + Description(list[i]) + L"（自动尝试 " +
                   std::to_wstring(list[i].attempts) + L" 次）\n\n";
    }
    if (list.size() > 8)
        content += L"其余 " + std::to_wstring(list.size() - 8) + L" 项请查看记录。";
    TASKDIALOG_BUTTON buttons[] = {{100, L"查看解压记录"}};
    TASKDIALOGCONFIG config = {};
    config.cbSize = sizeof(config);
    config.dwFlags = TDF_SIZE_TO_CONTENT | TDF_CALLBACK_TIMER;
    config.pszWindowTitle = L"Bandizip 自动密码";
    config.pszMainInstruction = instruction.c_str();
    config.pszContent = content.c_str();
    config.pszMainIcon = TD_WARNING_ICON;
    config.dwCommonButtons = TDCBF_CLOSE_BUTTON;
    config.cButtons = 1;
    config.pButtons = buttons;
    config.pfCallback = NotifyCallback;
    // Keep passive forwarding usable in shell/COM hosts with comctl32 v5 too.
    // Bandizip normally supplies the v6 activation context for TaskDialog.
    HMODULE controls = LoadLibraryW(L"comctl32.dll");
    using Dialog = HRESULT(WINAPI *)(const TASKDIALOGCONFIG *, int *, int *, BOOL *);
    auto dialog = controls ? (Dialog)GetProcAddress(controls, "TaskDialogIndirect") : nullptr;
    int chosen = 0;
    HRESULT hr = dialog ? dialog(&config, &chosen, nullptr, nullptr) : E_NOTIMPL;
    if (controls)
        FreeLibrary(controls);
    if (FAILED(hr))
        MessageBoxW(nullptr, content.c_str(), instruction.c_str(), MB_OK | MB_ICONWARNING);
    if (chosen == 100)
        ShowRecords();
}
DWORD WINAPI NotifyThread(void *reference) {
    for (;;) {
        DWORD wait = WaitForSingleObject(changed, 600);
        if (exiting.load())
            break;
        if (wait == WAIT_TIMEOUT && activeOperations.load() == 0) {
            std::vector<Result> list;
            {
                std::lock_guard<std::mutex> guard(pendingMutex);
                list.swap(pending);
            }
            Display(list);
            bool done;
            {
                std::lock_guard<std::mutex> guard(pendingMutex);
                done = pending.empty();
                if (done) {
                    notifierActive = false;
                    SetEvent(notifierDone);
                }
            }
            if (done)
                FreeLibraryAndExitThread((HMODULE)reference, 0);
        }
    }
    {
        std::lock_guard<std::mutex> guard(pendingMutex);
        notifierActive = false;
        SetEvent(notifierDone);
    }
    FreeLibraryAndExitThread((HMODULE)reference, 0);
}
void Schedule() {
    wchar_t noUI[8];
    if (GetEnvironmentVariableW(L"BZAP_NO_UI", noUI, 8))
        return;
    if (!InitOnceExecuteOnce(&eventsOnce, CreateEvents, nullptr, nullptr))
        return;
    std::lock_guard<std::mutex> guard(pendingMutex);
    if (notifierActive || pending.empty() || exiting.load())
        return;
    HMODULE reference = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)&NotifyThread, &reference))
        return;
    notifierActive = true;
    ResetEvent(notifierDone);
    HANDLE thread = CreateThread(nullptr, 0, NotifyThread, reference, 0, nullptr);
    if (thread)
        CloseHandle(thread);
    else {
        notifierActive = false;
        SetEvent(notifierDone);
        FreeLibrary(reference);
    }
}
} // namespace
void OperationStarted() {
    InitOnceExecuteOnce(&eventsOnce, CreateEvents, nullptr, nullptr);
    activeOperations.fetch_add(1);
    if (changed)
        SetEvent(changed);
}
void OperationFinished() {
    activeOperations.fetch_sub(1);
    if (changed)
        SetEvent(changed);
    Schedule();
}
void RecordResult(const Result &r, bool notify) {
    auto directory = DataDirectory();
    HANDLE mutex = CreateMutexW(nullptr, FALSE, L"Local\\BandizipAutoPassword.History.v1");
    DWORD acquired = mutex ? WaitForSingleObject(mutex, 3000) : WAIT_FAILED;
    if (acquired == WAIT_OBJECT_0 || acquired == WAIT_ABANDONED) {
        if (!directory.empty()) {
            auto time = UtcNow();
            auto json = "{\"time\":\"" + time + "\",\"pid\":" + std::to_string(GetCurrentProcessId()) +
                        ",\"archive\":" + Json(r.archive) + ",\"outcome\":" + Json(r.outcome) +
                        ",\"error\":" + std::to_string(r.error) +
                        ",\"attempts\":" + std::to_string(r.attempts) +
                        ",\"saved_password_count\":" + std::to_string(r.savedCount) +
                        ",\"completed_files\":" + std::to_string(r.completedFiles) +
                        ",\"opening\":" + (r.opening ? "true" : "false") + "}\r\n";
            Append(Join(directory, L"history.jsonl"), json);
            auto line = time + "  " + Utf8(Description(r)) + "\r\n" + Utf8(r.archive) + "\r\n自动尝试：" +
                        std::to_string(r.attempts) + " 次；错误码：" + std::to_string(r.error) + "\r\n\r\n";
            Append(Join(directory, L"解压记录.txt"), line);
        }
        ReleaseMutex(mutex);
    }
    if (mutex)
        CloseHandle(mutex);
    Trace(L"RESULT " + r.outcome + L" " + r.archive);
    if (notify && r.outcome != L"success" && r.outcome != L"canceled") {
        {
            std::lock_guard<std::mutex> guard(pendingMutex);
            pending.push_back(r);
        }
        Schedule();
    }
}
void FinishNotifications() {
    wchar_t noUI[8];
    if (GetEnvironmentVariableW(L"BZAP_NO_UI", noUI, 8))
        return;
    exiting.store(true);
    if (changed)
        SetEvent(changed);
    if (notifierDone)
        WaitForSingleObject(notifierDone, INFINITE);
    std::vector<Result> list;
    {
        std::lock_guard<std::mutex> guard(pendingMutex);
        list.swap(pending);
    }
    Display(list);
}
void ShowRecords() {
    auto file = Join(DataDirectory(), L"解压记录.txt");
    if (!Exists(file))
        AtomicWrite(file, "尚无解压记录。\r\n");
    ShellExecuteW(nullptr, L"open", file.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}
} // namespace bzap
