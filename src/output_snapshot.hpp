#pragma once
#include "common.hpp"
#include <filesystem>
#include <utility>

namespace bzap {
// Output identities are independent of recycle-bin eligibility.
inline std::wstring OutputPath(const std::wstring &path) {
    if (path.empty()) return {};
    wchar_t full[32768];
    DWORD length = GetFullPathNameW(path.c_str(), 32768, full, nullptr);
    if (!length || length >= 32768) return {};
    std::wstring result(full, length);
    if (result.compare(0, 4, L"\\\\?\\") == 0) return result;
    if (result.compare(0, 2, L"\\\\") == 0) return L"\\\\?\\UNC\\" + result.substr(2);
    return L"\\\\?\\" + result;
}
inline bool SameOutputPath(const std::wstring &a, const std::wstring &b) {
    auto left = OutputPath(a), right = OutputPath(b);
    return !left.empty() && !right.empty() && _wcsicmp(left.c_str(), right.c_str()) == 0;
}
struct OutputSnapshot {
    std::wstring path;
    BY_HANDLE_FILE_INFORMATION identity{};
    bool existed = false;
};
inline bool OutputInformation(HANDLE file, BY_HANDLE_FILE_INFORMATION &info) {
    return GetFileInformationByHandle(file, &info) &&
           !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT));
}
inline bool CaptureOutput(const std::wstring &path, OutputSnapshot &snapshot) {
    auto full = OutputPath(path);
    if (full.empty()) return false;
    HANDLE file = CreateFileW(full.c_str(), FILE_READ_ATTRIBUTES,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                              OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        if (GetLastError() != ERROR_FILE_NOT_FOUND) return false;
        snapshot = {};
        snapshot.path = path;
        return true;
    }
    BY_HANDLE_FILE_INFORMATION info{};
    bool valid = OutputInformation(file, info);
    CloseHandle(file);
    if (!valid) return false;
    // Preserve the backend's spelling for a later rename callback. The engine
    // applies its own long-path prefix; passing our normalized spelling back
    // can make it apply that prefix twice. Only filesystem calls normalize.
    snapshot = {path, info, true};
    return true;
}
inline bool SameOutputIdentity(const OutputSnapshot &a, const OutputSnapshot &b) {
    return a.existed && b.existed && SameOutputPath(a.path, b.path) &&
           a.identity.dwVolumeSerialNumber == b.identity.dwVolumeSerialNumber &&
           a.identity.nFileIndexHigh == b.identity.nFileIndexHigh &&
           a.identity.nFileIndexLow == b.identity.nFileIndexLow;
}
inline bool SameOutput(const OutputSnapshot &snapshot) {
    OutputSnapshot current;
    if (!CaptureOutput(snapshot.path, current) || current.existed != snapshot.existed) return false;
    return !snapshot.existed ||
           (SameOutputIdentity(snapshot, current) &&
            snapshot.identity.nFileSizeHigh == current.identity.nFileSizeHigh &&
            snapshot.identity.nFileSizeLow == current.identity.nFileSizeLow &&
            CompareFileTime(&snapshot.identity.ftLastWriteTime, &current.identity.ftLastWriteTime) == 0);
}
struct OutputOwner {
    OutputSnapshot first;
    bool placeholder = false;
};
inline bool ReserveOutput(const std::wstring &path, OutputOwner &owner) {
    auto parent = OutputPath(Directory(path));
    if (parent.empty()) return false;
    std::error_code error;
    std::filesystem::create_directories(parent, error);
    if (error) return false;
    OutputSnapshot first;
    if (!CaptureOutput(path, first)) return false;
    if (first.existed) {
        owner = {std::move(first), false};
        return true;
    }
    // Reserve identity BEFORE the decoder writes, never adopt an unknown file
    // after failure. The native overwrite callback recognizes this empty file.
    HANDLE file = CreateFileW(OutputPath(first.path).c_str(), FILE_READ_ATTRIBUTES,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                              CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    bool valid = OutputInformation(file, first.identity);
    CloseHandle(file);
    if (!valid) return false;
    first.existed = true;
    owner = {std::move(first), true};
    return true;
}
inline bool CaptureFailedOutput(const OutputOwner &owner, const std::wstring &path,
                                OutputSnapshot &snapshot) {
    return SameOutputPath(owner.first.path, path) && CaptureOutput(path, snapshot) &&
           (!snapshot.existed || SameOutputIdentity(owner.first, snapshot));
}
inline void RemoveEmptyReservation(const OutputOwner &owner) {
    if (!owner.placeholder) return;
    HANDLE file = CreateFileW(OutputPath(owner.first.path).c_str(), DELETE | FILE_READ_ATTRIBUTES, 0, nullptr,
                              OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;
    OutputSnapshot current{owner.first.path, {}, true};
    if (OutputInformation(file, current.identity) && SameOutputIdentity(owner.first, current) &&
        !current.identity.nFileSizeHigh && !current.identity.nFileSizeLow) {
        FILE_DISPOSITION_INFO remove{TRUE};
        SetFileInformationByHandle(file, FileDispositionInfo, &remove, sizeof(remove));
    }
    CloseHandle(file);
}
} // namespace bzap
