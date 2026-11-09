#include "common.hpp"
#include <algorithm>
#include <atomic>
#include <bcrypt.h>
#include <cstdio>
#include <shlobj.h>

namespace bzap {
std::wstring ModulePath(HMODULE module) {
    std::wstring path(32768, L'\0');
    DWORD n = GetModuleFileNameW(module, path.data(), (DWORD)path.size());
    if (!n || n >= path.size())
        return {};
    path.resize(n);
    return path;
}
std::wstring Directory(const std::wstring &path) {
    auto n = path.find_last_of(L"\\/");
    return n == std::wstring::npos ? L"" : path.substr(0, n);
}
std::wstring BaseName(const std::wstring &path) {
    auto n = path.find_last_of(L"\\/");
    return path.substr(n == std::wstring::npos ? 0 : n + 1);
}
std::wstring Join(const std::wstring &a, const std::wstring &b) {
    return a.empty() ? b : a + L"\\" + b;
}
bool EnsureDirectory(const std::wstring &path) {
    if (path.empty()) {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return false;
    }
    int code = SHCreateDirectoryExW(nullptr, path.c_str(), nullptr);
    if (code == ERROR_SUCCESS)
        return true;
    DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY))
        return true;
    SetLastError((DWORD)code);
    return false;
}
bool Exists(const std::wstring &path) {
    return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}
std::wstring DataDirectory() {
    wchar_t overridePath[32768];
    DWORD n = GetEnvironmentVariableW(L"BZAP_DATA_DIR", overridePath, 32768);
    if (n && n < 32768) {
        EnsureDirectory(overridePath);
        return overridePath;
    }
    PWSTR local = nullptr;
    std::wstring result;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &local))) {
        result = Join(local, L"BandizipAutoPassword");
        CoTaskMemFree(local);
    }
    EnsureDirectory(result);
    return result;
}
std::wstring DefaultBandizipDirectory() {
    wchar_t value[32768];
    DWORD size = sizeof(value);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Bandizip", L"ProgramFolder", RRF_RT_REG_SZ, nullptr,
                     value, &size) == ERROR_SUCCESS) {
        std::wstring path = value;
        while (path.size() > 3 && (path.back() == L'\\' || path.back() == L'/'))
            path.pop_back();
        return path;
    }
    wchar_t folder[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PROGRAM_FILES, nullptr, SHGFP_TYPE_CURRENT, folder)))
        return Join(folder, L"Bandizip");
    return L"C:\\Program Files\\Bandizip";
}
std::string Utf8(const std::wstring &s) {
    if (s.empty())
        return {};
    int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), (int)s.size(), nullptr, 0, nullptr,
                                nullptr);
    if (n <= 0)
        return {};
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n, nullptr, nullptr);
    return out;
}
std::wstring Wide(const std::string &s) {
    if (s.empty())
        return {};
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), (int)s.size(), nullptr, 0);
    if (n <= 0)
        return {};
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), (int)s.size(), out.data(), n);
    return out;
}
std::string Json(const std::wstring &s) {
    std::string out = "\"";
    for (unsigned char c : Utf8(s)) {
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (c < 32) {
                char b[7];
                snprintf(b, sizeof(b), "\\u%04x", c);
                out += b;
            } else
                out += (char)c;
        }
    }
    return out + '"';
}
std::string UtcNow() {
    SYSTEMTIME t;
    GetSystemTime(&t);
    char b[40];
    snprintf(b, sizeof(b), "%04u-%02u-%02uT%02u:%02u:%02uZ", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute,
             t.wSecond);
    return b;
}
bool ReadFileBytes(const std::wstring &path, std::vector<unsigned char> &bytes, std::size_t maximum) {
    HANDLE file =
        CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    LARGE_INTEGER size;
    bool ok =
        GetFileSizeEx(file, &size) && size.QuadPart >= 0 && (unsigned long long)size.QuadPart <= maximum;
    if (ok) {
        bytes.resize((size_t)size.QuadPart);
        DWORD done = 0;
        ok = bytes.empty() ||
             (ReadFile(file, bytes.data(), (DWORD)bytes.size(), &done, nullptr) && done == bytes.size());
    }
    CloseHandle(file);
    if (!ok)
        bytes.clear();
    return ok;
}
std::string FileHash(const std::wstring &path) {
    HANDLE file =
        CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return {};
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::vector<unsigned char> object;
    DWORD length = 0, done = 0;
    unsigned char digest[32] = {};
    bool ok = false;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0 &&
        BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&length, sizeof(length), &done, 0) >= 0) {
        object.resize(length);
        if (BCryptCreateHash(alg, &hash, object.data(), length, nullptr, 0, 0) >= 0) {
            unsigned char buffer[65536];
            DWORD count;
            ok = true;
            for (;;) {
                if (!ReadFile(file, buffer, sizeof(buffer), &count, nullptr)) {
                    ok = false;
                    break;
                }
                if (!count)
                    break;
                if (BCryptHashData(hash, buffer, count, 0) < 0) {
                    ok = false;
                    break;
                }
            }
            if (ok)
                ok = BCryptFinishHash(hash, digest, sizeof(digest), 0) >= 0;
        }
    }
    if (hash)
        BCryptDestroyHash(hash);
    if (alg)
        BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(file);
    if (!ok)
        return {};
    const char *hex = "0123456789abcdef";
    std::string text;
    for (auto c : digest) {
        text += hex[c >> 4];
        text += hex[c & 15];
    }
    return text;
}
std::wstring FileVersion(const std::wstring &path) {
    DWORD unused;
    DWORD n = GetFileVersionInfoSizeW(path.c_str(), &unused);
    if (!n || n > 1024 * 1024)
        return {};
    std::vector<unsigned char> data(n);
    if (!GetFileVersionInfoW(path.c_str(), 0, n, data.data()))
        return {};
    VS_FIXEDFILEINFO *info = nullptr;
    UINT size = 0;
    if (!VerQueryValueW(data.data(), L"\\", (void **)&info, &size) || size < sizeof(*info))
        return {};
    return std::to_wstring(HIWORD(info->dwFileVersionMS)) + L"." +
           std::to_wstring(LOWORD(info->dwFileVersionMS)) + L"." +
           std::to_wstring(HIWORD(info->dwFileVersionLS)) + L"." +
           std::to_wstring(LOWORD(info->dwFileVersionLS));
}
bool IsAmd64Image(const std::wstring &path) {
    std::vector<unsigned char> data;
    if (!ReadFileBytes(path, data, 64 * 1024 * 1024) || data.size() < sizeof(IMAGE_DOS_HEADER))
        return false;
    auto dos = (IMAGE_DOS_HEADER *)data.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > data.size())
        return false;
    auto nt = (IMAGE_NT_HEADERS64 *)(data.data() + dos->e_lfanew);
    return nt->Signature == IMAGE_NT_SIGNATURE && nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
}
bool AtomicWrite(const std::wstring &path, const std::string &data) {
    static std::atomic<unsigned long long> sequence{0};
    auto temporary = path + L".tmp-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                     std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(sequence++);
    HANDLE file =
        CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    DWORD done = 0;
    bool ok = WriteFile(file, data.data(), (DWORD)data.size(), &done, nullptr) != FALSE;
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (ok && done != data.size()) {
        ok = false;
        error = ERROR_WRITE_FAULT;
    }
    if (ok && !FlushFileBuffers(file)) {
        ok = false;
        error = GetLastError();
    }
    CloseHandle(file);
    if (ok &&
        !MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        ok = false;
        error = GetLastError();
    }
    if (!ok) {
        DeleteFileW(temporary.c_str());
        SetLastError(error);
    }
    return ok;
}
Settings LoadSettings() {
    Settings s;
    auto ini = Join(DataDirectory(), L"settings.ini");
    s.enabled = GetPrivateProfileIntW(L"General", L"Enabled", 1, ini.c_str()) != 0;
    s.notify = GetPrivateProfileIntW(L"General", L"NotifyFailures", 1, ini.c_str()) != 0;
    // Earlier releases enabled full preflight implicitly. Require a fresh,
    // explicit opt-in rather than carrying that default into single-pass mode.
    s.verify = GetPrivateProfileIntW(L"General", L"FullPreflight", 0, ini.c_str()) != 0;
    s.recycle = GetPrivateProfileIntW(L"General", L"RecycleAfterExtract", 0, ini.c_str()) != 0;
    return s;
}
void Trace(const std::wstring &text) {
    wchar_t path[32768];
    DWORD n = GetEnvironmentVariableW(L"BZAP_TRACE", path, 32768);
    if (!n || n >= 32768)
        return;
    HANDLE file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return;
    auto line = std::to_string(GetCurrentProcessId()) + " " + Utf8(text) + "\r\n";
    DWORD done;
    WriteFile(file, line.data(), (DWORD)line.size(), &done, nullptr);
    CloseHandle(file);
}
std::wstring SystemError(DWORD error) {
    wchar_t *message = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, error, 0, (PWSTR)&message, 0, nullptr);
    std::wstring result = message ? message : L"未知错误";
    if (message)
        LocalFree(message);
    return result + L"（" + std::to_wstring(error) + L"）";
}
} // namespace bzap
