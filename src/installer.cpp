#include "installer.hpp"
#include "package_identity.hpp"
#include <array>
#include <optional>
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
// Historical manifests use three components. Also accept the four-component
// spelling used in Windows version resources, comparing numbers rather than text.
std::optional<std::array<unsigned, 4>> VersionParts(const std::wstring &version) {
    std::array<unsigned, 4> parts{};
    size_t pos = 0;
    for (size_t i = 0; i < parts.size(); ++i) {
        size_t start = pos;
        while (pos < version.size() && version[pos] >= L'0' && version[pos] <= L'9') {
            parts[i] = parts[i] * 10 + (version[pos++] - L'0');
            if (parts[i] > 65535)
                return std::nullopt;
        }
        if (pos == start)
            return std::nullopt;
        if (pos == version.size() && i >= 2)
            return parts;
        if (pos == version.size() || version[pos++] != L'.')
            return std::nullopt;
    }
    return std::nullopt;
}
std::string ManifestHash(const std::wstring &manifest) {
    if (Ini(manifest, L"Product") != L"BandizipAutoPassword")
        return {};
    auto hash = Utf8(Ini(manifest, L"ProxySHA256"));
    return hash.size() == 64 && hash.find_first_not_of("0123456789abcdef") == std::string::npos
               ? hash : std::string{};
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
struct ComponentDirectory {
    HANDLE handle = INVALID_HANDLE_VALUE;
    bool Open(const std::wstring &path) {
        handle = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (handle == INVALID_HANDLE_VALUE)
            return false;
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(handle, &info))
            return false;
        if ((info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != FILE_ATTRIBUTE_DIRECTORY) {
            SetLastError(ERROR_DIRECTORY);
            return false;
        }
        return true;
    }
    ~ComponentDirectory() {
        if (handle != INVALID_HANDLE_VALUE)
            CloseHandle(handle);
    }
};
bool SaveManifest(const std::wstring &dir, const std::string &proxy) {
    auto body = "[Installation]\r\nProduct=BandizipAutoPassword\r\nVersion=" + Utf8(ProductVersion) +
                "\r\nEngineVersion=7.47.0.1\r\nOriginalSHA256=" +
                std::string(SupportedArkSha256) + "\r\nProxySHA256=" + proxy +
                "\r\nInstalledUTC=" + UtcNow() + "\r\n";
    return AtomicWrite(Manifest(dir), body);
}
void CleanRetired(const std::wstring &directory) {
    auto folder = Join(directory, L"AutoPassword");
    WIN32_FIND_DATAW data{};
    HANDLE search = FindFirstFileW(Join(folder, L"*.dll").c_str(), &data);
    if (search == INVALID_HANDLE_VALUE) return;
    do {
        if (data.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) continue;
        std::wstring name = data.cFileName;
        if (name.size() < 5 || _wcsicmp(name.c_str() + name.size() - 4, L".dll"))
            continue;
        bool owned = false;
        for (auto prefix : {L"retired-", L"retired-proxy-", L"uncommitted-"}) {
            size_t start = wcslen(prefix), end = name.size() - 4;
            if (name.compare(0, start, prefix) || start >= end) continue;
            bool numeric = true;
            for (size_t i = start; i < end; ++i) numeric = numeric && name[i] >= L'0' && name[i] <= L'9';
            owned = owned || numeric;
        }
        if (!owned) continue;
        // Delete through the checked handle. Loaded or otherwise locked files
        // remain available and are retried after the next successful operation.
        HANDLE file = CreateFileW(Join(folder, name).c_str(), DELETE | FILE_READ_ATTRIBUTES, 0, nullptr,
                                  OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (file == INVALID_HANDLE_VALUE) continue;
        BY_HANDLE_FILE_INFORMATION info{};
        if (GetFileInformationByHandle(file, &info) &&
            !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
            FILE_DISPOSITION_INFO remove{TRUE};
            SetFileInformationByHandle(file, FileDispositionInfo, &remove, sizeof(remove));
        }
        CloseHandle(file);
    } while (FindNextFileW(search, &data));
    FindClose(search);
}
} // namespace
InstallStatus GetInstallStatus(const std::wstring &directory) {
    InstallStatus out;
    out.directory = Full(directory);
    auto app = Join(out.directory, L"Bandizip.exe");
    auto engine = Join(out.directory, L"ark.x64.dll");
    out.version = FileVersion(app);
    auto backup = Join(out.directory, OriginalDllName);
    out.backupValid = FileHash(backup) == SupportedArkSha256;
    auto currentHash = FileHash(engine);
    auto manifestHash = ManifestHash(Manifest(out.directory));
    out.installed = (!manifestHash.empty() && currentHash == manifestHash && currentHash != SupportedArkSha256) ||
                    currentHash == PackageSha256;
    out.canUninstall = !manifestHash.empty() || out.installed;
    bool recovery = out.backupValid && !Exists(engine);
    out.supported = out.version == L"7.47.0.1" && IsAmd64Image(app) &&
                    ((out.installed && out.backupValid) ||
                     (currentHash == SupportedArkSha256 && (!Exists(backup) || out.backupValid)) || recovery);
    if (out.installed) {
        out.installedVersion = currentHash == PackageSha256 ? ProductVersion : Ini(Manifest(out.directory), L"Version");
        auto installed = VersionParts(out.installedVersion), package = VersionParts(ProductVersion);
        if (installed && package) {
            out.updateAvailable = out.supported && *installed < *package;
            out.newerInstalled = *installed > *package;
        }
        if (out.installedVersion.empty())
            out.installedVersion = L"未知版本";
    }
    if (!out.backupValid && (out.installed || Exists(backup)))
        out.detail = L"原引擎备份缺失或校验失败，请先恢复与此 Bandizip 构建匹配的原版引擎。";
    else if (out.installed && !out.supported)
        out.detail = L"Bandizip 版本已变化，自动匹配已停用，请卸载插件";
    else if (out.updateAvailable)
        out.detail = L"已安装 " + out.installedVersion + L"，可更新到 " + ProductVersion;
    else if (out.newerInstalled)
        out.detail = L"已安装 " + out.installedVersion + L"，高于安装包 " + ProductVersion + L"。";
    else if (out.installed)
        out.detail = L"自动密码扩展已安装";
    else if (recovery && out.supported)
        out.detail = L"解压引擎缺失，可从已校验的备份修复";
    else if (out.canUninstall)
        out.detail = L"当前引擎已变化，可点击“卸载插件”清理上次的接入记录。";
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
    auto status = GetInstallStatus(dir);
    if (!status.supported || status.newerInstalled)
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
    ComponentDirectory componentLock;
    if (!componentLock.Open(component))
        return Failure(L"无法确认扩展组件目录");
    if (!Exists(backup)) {
        if (!CopyFileW(engine.c_str(), backup.c_str(), TRUE))
            return Failure(L"备份原解压引擎失败，尚未替换任何组件");
    }
    if (FileHash(backup) != SupportedArkSha256)
        return Failure(L"原引擎备份校验失败，已停止安装", ERROR_CRC);
    if (FileHash(engine) == PackageSha256) {
        if (!SaveManifest(dir, proxyHash))
            return Failure(L"已安装的扩展校验通过，但无法更新安装记录");
        CleanRetired(dir);
        return {true, 0, L"当前扩展及原引擎备份校验通过，安装记录已更新。"};
    }
    if (!Exists(engine) && !CopyFileW(backup.c_str(), engine.c_str(), TRUE))
        return Failure(L"无法从已校验的备份恢复缺失的引擎");
    auto stage = Join(dir, L"ark.bzap-stage-" + std::to_wstring(GetCurrentProcessId()) + L".dll");
    if (!CopyFileW(source.c_str(), stage.c_str(), TRUE))
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
        DWORD error = GetLastError();
        auto failed = Join(component, L"uncommitted-" + std::to_wstring(GetTickCount64()) + L".dll");
        MoveFileExW(engine.c_str(), failed.c_str(), MOVEFILE_WRITE_THROUGH);
        MoveFileExW(retired.c_str(), engine.c_str(), MOVEFILE_WRITE_THROUGH);
        return Failure(L"安装记录未能保存，已尝试恢复原组件", error);
    }
    CleanRetired(dir);
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
    auto engine = Join(dir, L"ark.x64.dll");
    auto backup = Join(dir, OriginalDllName);
    auto current = FileHash(engine);
    auto proxyHash = current == PackageSha256 ? std::string(PackageSha256) : ManifestHash(manifest);
    if (proxyHash.empty())
        return Failure(L"没有找到此扩展的安装记录，未改动任何组件", ERROR_FILE_NOT_FOUND);
    auto component = Directory(manifest);
    ComponentDirectory componentLock;
    if (!EnsureDirectory(component) || !componentLock.Open(component))
        return Failure(L"无法确认扩展组件目录");
    auto finish = [&](const wchar_t *message) -> InstallResult {
        auto inactive = Join(Directory(manifest), L"installation.inactive.ini");
        if (!MoveFileExW(manifest.c_str(), inactive.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            DWORD error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND)
                return Failure(L"解压引擎已保留，但安装记录未能停用。请解除文件占用后再次卸载。", error);
        }
        CleanRetired(dir);
        return {true, 0, message};
    };
    if (!Exists(engine) && FileHash(backup) == SupportedArkSha256) {
        if (!CopyFileW(backup.c_str(), engine.c_str(), TRUE))
            return Failure(L"恢复缺失的引擎失败");
        return finish(L"已从校验通过的备份恢复原版解压引擎。");
    }
    if (current != proxyHash) {
        // An application update may have replaced our DLL. Never roll back a
        // newer Bandizip engine while removing this extension.
        if (current.empty())
            return Failure(L"当前引擎无法读取，未自动覆盖组件", ERROR_READ_FAULT);
        return finish(L"已保留当前解压引擎并停用扩展记录。");
    }
    if (FileHash(backup) != SupportedArkSha256)
        return Failure(L"原引擎备份缺失或校验失败，未覆盖当前组件", ERROR_CRC);
    auto stage = Join(dir, L"ark.bzap-restore-" + std::to_wstring(GetCurrentProcessId()) + L".dll");
    if (!CopyFileW(backup.c_str(), stage.c_str(), TRUE))
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
    return finish(L"已卸载插件并恢复原版解压引擎。");
}
} // namespace bzap
