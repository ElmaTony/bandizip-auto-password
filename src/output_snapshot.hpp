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
// Only prepare an output inside the directory selected for this extraction.
// A native rename can supply a different path. Let the host handle that path
// without creating a placeholder or taking ownership for a retry.
inline bool WithinOutputRoot(const std::wstring &root, const std::wstring &path) {
    if (root.empty() || !std::filesystem::path(path).is_absolute())
        return false;
    auto full = OutputPath(path);
    auto prefix = root.back() == L'\\' ? root : root + L'\\';
    if (full.size() <= prefix.size() || full.compare(0, prefix.size(), prefix) != 0)
        return false;
    for (size_t start = prefix.size(); start < full.size();) {
        auto end = full.find(L'\\', start);
        auto part = full.substr(start, end - start);
        if (part.empty() || part.back() == L'.' || part.back() == L' ' ||
            part.find_first_of(L":/") != std::wstring::npos)
            return false;
        if (end == std::wstring::npos)
            return true;
        DWORD attributes = GetFileAttributesW(full.substr(0, end).c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
            return false;
        start = end + 1;
    }
    return false;
}
struct OutputSnapshot {
    std::wstring path;
    BY_HANDLE_FILE_INFORMATION identity{};
    bool existed = false;
};
inline bool OutputInformation(HANDLE file, BY_HANDLE_FILE_INFORMATION &info) {
    if (!GetFileInformationByHandle(file, &info))
        return false;
    if ((info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
        !(info.nFileIndexHigh || info.nFileIndexLow)) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return false;
    }
    return true;
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
inline bool ReserveNewOutput(const std::wstring &path, OutputOwner &owner) {
    // Reserve identity BEFORE the decoder writes, never adopt an unknown file
    // after failure. The native overwrite callback recognizes this empty file.
    HANDLE file = CreateFileW(OutputPath(path).c_str(), FILE_READ_ATTRIBUTES | DELETE,
                              FILE_SHARE_READ, nullptr,
                              CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    OutputSnapshot first{path, {}, true};
    bool valid = OutputInformation(file, first.identity);
    if (!valid) {
        FILE_DISPOSITION_INFO remove{TRUE};
        SetFileInformationByHandle(file, FileDispositionInfo, &remove, sizeof(remove));
    }
    CloseHandle(file);
    if (!valid) return false;
    owner = {std::move(first), true};
    return true;
}
inline bool ReserveOutput(const std::wstring &path, OutputOwner &owner) {
    OutputSnapshot first;
    if (CaptureOutput(path, first)) {
        if (first.existed) {
            owner = {std::move(first), false};
            return true;
        }
    } else {
        if (GetLastError() != ERROR_PATH_NOT_FOUND)
            return false;
        auto parent = OutputPath(Directory(path));
        if (parent.empty())
            return false;
        std::error_code error;
        std::filesystem::create_directories(parent, error);
        if (error)
            return false;
    }
    return ReserveNewOutput(path, owner);
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
