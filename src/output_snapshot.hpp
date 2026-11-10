#pragma once
#include "recycle.hpp"
#include <utility>

namespace bzap {
struct OutputSnapshot {
    SourceFile file;
    bool existed = false;
};
inline bool MissingOutput(const std::wstring &path) {
    return GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES &&
           GetLastError() == ERROR_FILE_NOT_FOUND;
}
inline bool CaptureOutput(const std::wstring &path, OutputSnapshot &snapshot) {
    SourceFile file;
    if (CaptureSource(path, file)) {
        snapshot = {std::move(file), true};
        return true;
    }
    // A failed decoder may remove its partial output. Capture absence as a
    // distinct state, not as permission to overwrite an unknown existing file.
    wchar_t full[32768];
    DWORD length = GetFullPathNameW(path.c_str(), 32768, full, nullptr);
    if (!length || length >= 32768 || full[1] != L':' || full[2] != L'\\' || !MissingOutput(full))
        return false;
    snapshot = {};
    snapshot.file.path = full;
    return true;
}
inline bool SameOutput(const OutputSnapshot &snapshot) {
    return snapshot.existed ? SameSource(snapshot.file) : MissingOutput(snapshot.file.path);
}
} // namespace bzap
