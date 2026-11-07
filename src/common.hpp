#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>

namespace bzap {
inline constexpr wchar_t ProductVersion[] = L"1.1.0";
inline constexpr wchar_t OriginalDllName[] = L"ark.bzap-original.x64.dll";
inline constexpr char SupportedArkSha256[] =
    "868a4b870f43024688d4e9c74d9c4e42bc7f4e439972a93059ee95f4a2dbb135";
struct Settings {
    bool enabled = true, notify = true, verify = true;
};
std::wstring ModulePath(HMODULE module = nullptr);
std::wstring Directory(const std::wstring &path);
std::wstring BaseName(const std::wstring &path);
std::wstring Join(const std::wstring &a, const std::wstring &b);
std::wstring DataDirectory();
std::wstring DefaultBandizipDirectory();
bool EnsureDirectory(const std::wstring &path);
std::string Utf8(const std::wstring &text);
std::wstring Wide(const std::string &text);
std::string Json(const std::wstring &text);
std::string UtcNow();
std::string FileHash(const std::wstring &path);
std::wstring FileVersion(const std::wstring &path);
bool IsAmd64Image(const std::wstring &path);
bool Exists(const std::wstring &path);
bool ReadFileBytes(const std::wstring &path, std::vector<unsigned char> &bytes,
                   std::size_t maximum = 16 * 1024 * 1024);
bool AtomicWrite(const std::wstring &path, const std::string &data);
Settings LoadSettings();
void Trace(const std::wstring &message);
std::wstring SystemError(DWORD error);
} // namespace bzap
