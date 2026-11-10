#include "installer.hpp"
#include "package_identity.hpp"
#include <memory>
#include <tlhelp32.h>

namespace bzap {
namespace {
struct InstallationLock {
    HANDLE handle = CreateMutexW(nullptr, FALSE, L"Local\\BandizipAutoPassword.Install.v1");
    bool acquired = false;
    InstallationLock() {
        if (handle) {
            auto r = WaitForSingleObject(handle, 5000);
            acquired = r == WAIT_OBJECT_0 || r == WAIT_ABANDONED;
        }
    }
    ~InstallationLock() {
        if (acquired)
            ReleaseMutex(handle);
        if (handle)
            CloseHandle(handle);
    }
};
std::wstring Full(const std::wstring &path) {
    wchar_t result[32768];
    DWORD n = GetFullPathNameW(path.c_str(), 32768, result, nullptr);
    if (!n || n >= 32768)
        return {};
    std::wstring out = result;
    while (out.size() > 3 && (out.back() == L'\\' || out.back() == L'/'))
        out.pop_back();
    return out;
}
std::wstring Manifest(const std::wstring &dir) {
    return Join(Join(dir, L"AutoPassword"), L"installation.ini");
}
std::wstring Ini(const std::wstring &path, const wchar_t *key) {
    wchar_t buffer[1024];
    GetPrivateProfileStringW(L"Installation", key, L"", buffer, 1024, path.c_str());
    return buffer;
}
bool InUse(const std::wstring &dir) {
    auto target = Full(Join(dir, L"Bandizip.exe"));
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return true;
    PROCESSENTRY32W item = {sizeof(item)};
    bool found = false;
    for (BOOL more = Process32FirstW(snapshot, &item); more; more = Process32NextW(snapshot, &item)) {
        if (_wcsicmp(item.szExeFile, L"Bandizip.exe") != 0)
            continue;
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, item.th32ProcessID);
        if (!process)
            continue;
        wchar_t path[32768];
        DWORD size = 32768;
        if (QueryFullProcessImageNameW(process, 0, path, &size) &&
            _wcsicmp(Full(path).c_str(), target.c_str()) == 0)
            found = true;
        CloseHandle(process);
    }
    CloseHandle(snapshot);
    return found;
}
InstallResult Failure(const std::wstring &message, DWORD code = 0) {
    if (!code)
        code = GetLastError();
    return {false, code, message + L"\n" + SystemError(code)};
}
bool SaveManifest(const std::wstring &dir, const std::string &proxy) {
    auto body = "[Installation]\r\nProduct=BandizipAutoPassword\r\nVersion=1.2.1\r\nEngineVersion=7.47.0."
                "1\r\nOriginalSHA256=" +
                std::string(SupportedArkSha256) + "\r\nProxySHA256=" + proxy +
                "\r\nInstalledUTC=" + UtcNow() + "\r\n";
    return AtomicWrite(Manifest(dir), body);
}
} // namespace
InstallStatus GetInstallStatus(const std::wstring &directory, const std::wstring &packageDirectory) {
    InstallStatus out;
    out.directory = Full(directory);
    auto app = Join(out.directory, L"Bandizip.exe");
    auto engine = Join(out.directory, L"ark.x64.dll");
    out.version = FileVersion(app);
    out.backupValid = FileHash(Join(out.directory, OriginalDllName)) == SupportedArkSha256;
    auto currentHash = FileHash(engine);
    auto manifestHash = Utf8(Ini(Manifest(out.directory), L"ProxySHA256"));
    out.installed = out.backupValid &&
                    ((!manifestHash.empty() && currentHash == manifestHash) || currentHash == PackageSha256);
    bool recovery = out.backupValid && !Exists(engine);
    out.supported = out.version == L"7.47.0.1" && IsAmd64Image(app) &&
                    (out.installed || currentHash == SupportedArkSha256 || recovery);
    if (out.installed && !out.supported)
        out.detail = L"Bandizip 版本已变化，自动匹配已停用，请卸载插件";
    else if (out.installed)
        out.detail = L"自动密码扩展已安装";
    else if (recovery && out.supported)
        out.detail = L"解压引擎缺失，可从已校验的备份修复";
    else if (out.supported)
        out.detail = L"当前版本可安装，尚未接入";
    else if (Exists(Manifest(out.directory)))
        out.detail = L"Bandizip 组件已变化，当前自动密码未启用；原有解压功能保留";
    else
        out.detail = L"暂不支持这个 Bandizip 构建（需要 7.47.0.1 x64）";
    return out;
}
InstallResult Install(const std::wstring &directory, const std::wstring &packageDirectory) {
    InstallationLock lock;
    if (!lock.acquired)
        return Failure(L"另一个安装或恢复操作正在进行", ERROR_BUSY);
    auto dir = Full(directory);
    if (dir.empty() || !Exists(Join(dir, L"Bandizip.exe")))
        return Failure(L"这个文件夹内没有 Bandizip.exe", ERROR_PATH_NOT_FOUND);
    if (InUse(dir))
        return Failure(L"请先关闭 Bandizip 的所有窗口，再重新安装。", ERROR_BUSY);
    auto status = GetInstallStatus(dir, packageDirectory);
    if (!status.supported)
        return Failure(status.detail, ERROR_REVISION_MISMATCH);
    auto source = Join(packageDirectory, L"ark.x64.dll");
    auto proxyHash = FileHash(source);
    if (proxyHash != PackageSha256 || !IsAmd64Image(source))
        return Failure(L"扩展 DLL 与管理器不匹配，请重新解压完整安装包", ERROR_INVALID_DATA);
    auto engine = Join(dir, L"ark.x64.dll");
    auto backup = Join(dir, OriginalDllName);
    auto component = Join(dir, L"AutoPassword");
    if (!EnsureDirectory(component))
        return Failure(L"无法写入 Bandizip 文件夹，安装需要管理员权限");
    if (!Exists(backup)) {
        if (!CopyFileW(engine.c_str(), backup.c_str(), TRUE))
            return Failure(L"备份原解压引擎失败，尚未替换任何组件");
    }
    if (FileHash(backup) != SupportedArkSha256)
        return Failure(L"原引擎备份校验失败，已停止安装", ERROR_CRC);
    if (!Exists(engine) && !CopyFileW(backup.c_str(), engine.c_str(), TRUE))
        return Failure(L"无法从已校验的备份恢复缺失的引擎");
    auto stage = Join(dir, L"ark.bzap-stage-" + std::to_wstring(GetCurrentProcessId()) + L".dll");
    if (!CopyFileW(source.c_str(), stage.c_str(), FALSE))
        return Failure(L"复制扩展失败，原组件保留");
    if (FileHash(stage) != proxyHash) {
        DeleteFileW(stage.c_str());
        return Failure(L"扩展复制后校验失败", ERROR_CRC);
    }
    auto retired = Join(component, L"retired-" + std::to_wstring(GetTickCount64()) + L".dll");
    if (!MoveFileExW(engine.c_str(), retired.c_str(), MOVEFILE_WRITE_THROUGH)) {
        DWORD error = GetLastError();
        DeleteFileW(stage.c_str());
        return Failure(L"当前解压引擎正在使用，尚未替换；请稍后重试", error);
    }
    if (!MoveFileExW(stage.c_str(), engine.c_str(), MOVEFILE_WRITE_THROUGH)) {
        DWORD error = GetLastError();
        MoveFileExW(retired.c_str(), engine.c_str(), MOVEFILE_WRITE_THROUGH);
        DeleteFileW(stage.c_str());
        return Failure(L"接入失败，已尝试恢复原组件", error);
    }
    if (!SaveManifest(dir, proxyHash)) {
        auto failed = Join(component, L"uncommitted-" + std::to_wstring(GetTickCount64()) + L".dll");
        MoveFileExW(engine.c_str(), failed.c_str(), MOVEFILE_WRITE_THROUGH);
        MoveFileExW(retired.c_str(), engine.c_str(), MOVEFILE_WRITE_THROUGH);
        return Failure(L"安装记录未能保存，已尝试恢复原组件");
    }
    return {true, 0, L"已安装。以后照常双击或使用原来的右键菜单解压即可。\n无需启动管理器或后台助手。"};
}
InstallResult Uninstall(const std::wstring &directory) {
    InstallationLock lock;
    if (!lock.acquired)
        return Failure(L"另一个安装或恢复操作正在进行", ERROR_BUSY);
    auto dir = Full(directory);
    if (dir.empty() || !Exists(Join(dir, L"Bandizip.exe")))
        return Failure(L"这个文件夹内没有 Bandizip.exe", ERROR_PATH_NOT_FOUND);
    if (InUse(dir))
        return Failure(L"请先关闭 Bandizip 的所有窗口，再卸载插件。", ERROR_BUSY);
    auto manifest = Manifest(dir);
    auto proxyHash = Utf8(Ini(manifest, L"ProxySHA256"));
    auto engine = Join(dir, L"ark.x64.dll");
    auto backup = Join(dir, OriginalDllName);
    if (proxyHash.empty() && FileHash(engine) == PackageSha256)
        proxyHash = PackageSha256;
    if (proxyHash.empty())
        return Failure(L"没有找到此扩展的安装记录，未改动任何组件", ERROR_FILE_NOT_FOUND);
    auto current = FileHash(engine);
    if (!Exists(engine) && FileHash(backup) == SupportedArkSha256) {
        if (!CopyFileW(backup.c_str(), engine.c_str(), TRUE))
            return Failure(L"恢复缺失的引擎失败");
        MoveFileExW(manifest.c_str(), Join(Directory(manifest), L"installation.inactive.ini").c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        return {true, 0, L"已从校验通过的备份恢复原版解压引擎。"};
    }
    if (current != proxyHash) {
        // An application update may have replaced our DLL. Never roll back a
        // newer Bandizip engine while removing this extension.
        if (current.empty())
            return Failure(L"当前引擎无法读取，未自动覆盖组件", ERROR_READ_FAULT);
        auto inactive = Join(Directory(manifest), L"installation.inactive.ini");
        if (!MoveFileExW(manifest.c_str(), inactive.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            return Failure(L"无法停用安装记录");
        return {true, 0, L"当前引擎已不是此扩展，已保留现有组件并停用扩展记录。"};
    }
    if (FileHash(backup) != SupportedArkSha256)
        return Failure(L"原引擎备份缺失或校验失败，未覆盖当前组件", ERROR_CRC);
    auto stage = Join(dir, L"ark.bzap-restore-" + std::to_wstring(GetCurrentProcessId()) + L".dll");
    if (!CopyFileW(backup.c_str(), stage.c_str(), FALSE))
        return Failure(L"准备恢复副本失败");
    if (FileHash(stage) != SupportedArkSha256) {
        DeleteFileW(stage.c_str());
        return Failure(L"恢复副本校验失败", ERROR_CRC);
    }
    auto retired = Join(Directory(manifest), L"retired-proxy-" + std::to_wstring(GetTickCount64()) + L".dll");
    if (!MoveFileExW(engine.c_str(), retired.c_str(), MOVEFILE_WRITE_THROUGH)) {
        DWORD error = GetLastError();
        DeleteFileW(stage.c_str());
        return Failure(L"扩展组件仍在使用，未改动安装", error);
    }
    if (!MoveFileExW(stage.c_str(), engine.c_str(), MOVEFILE_WRITE_THROUGH)) {
        DWORD error = GetLastError();
        MoveFileExW(retired.c_str(), engine.c_str(), MOVEFILE_WRITE_THROUGH);
        DeleteFileW(stage.c_str());
        return Failure(L"恢复失败，已尝试回滚", error);
    }
    MoveFileExW(manifest.c_str(), Join(Directory(manifest), L"installation.inactive.ini").c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    return {true, 0,
            L"已卸载插件并恢复原版解压引擎。原密码管理器和文件关联均保留。\n备份及解压记录继续保留，方便核对。"};
}
} // namespace bzap
