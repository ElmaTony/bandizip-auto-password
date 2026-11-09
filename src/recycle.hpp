#pragma once
#include "common.hpp"

namespace bzap {
struct SourceFile {
    std::wstring path;
    BY_HANDLE_FILE_INFORMATION identity{};
};
bool CaptureSource(const std::wstring &path, SourceFile &file);
bool SameSource(const SourceFile &file);
bool SourcesInUse(const std::vector<SourceFile> &files);
// Bound numbered 7z and spanned ZIP volumes by the archive's own header.
// The input list must come from the engine, never from a wildcard search.
bool TrimSplitSources(int style, const std::wstring &root, std::vector<SourceFile> &files);
struct RecycleResult {
    unsigned moved = 0;
    HRESULT error = S_OK;
};
// Only explicit engine-reported files are accepted. Never searches by filename.
RecycleResult RecycleSources(const std::vector<SourceFile> &files);
} // namespace bzap
