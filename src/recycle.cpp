#include "recycle.hpp"
#include <algorithm>
#include <shlobj.h>
#include <thread>

namespace bzap {
namespace {
template <class T> T LittleEndian(const unsigned char *bytes) {
    T value = 0;
    for (size_t i = 0; i < sizeof(T); ++i)
        value |= (T)bytes[i] << (i * 8);
    return value;
}
uint64_t SourceSize(const SourceFile &file) {
    return ((uint64_t)file.identity.nFileSizeHigh << 32) | file.identity.nFileSizeLow;
}
bool ReadSpan(const SourceFile &file, uint64_t offset, void *bytes, DWORD length) {
    if (!SameSource(file) || offset > INT64_MAX)
        return false;
    HANDLE handle =
        CreateFileW(file.path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (handle == INVALID_HANDLE_VALUE)
        return false;
    LARGE_INTEGER position;
    position.QuadPart = (LONGLONG)offset;
    DWORD read = 0;
    bool ok = SetFilePointerEx(handle, position, nullptr, FILE_BEGIN) &&
              ReadFile(handle, bytes, length, &read, nullptr) && read == length;
    CloseHandle(handle);
    return ok;
}
} // namespace
bool TrimSplitSources(int style, const std::wstring &root, std::vector<SourceFile> &files) {
    if (style != 1 && style != 2)
        return true;
    auto main = std::find_if(files.begin(), files.end(), [&](const SourceFile &file) {
        return _wcsicmp(file.path.c_str(), root.c_str()) == 0;
    });
    if (main == files.end())
        return false;
    if (style == 1) {
        unsigned char header[32];
        static constexpr unsigned char signature[] = {0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c};
        if (main != files.begin() || !ReadSpan(*main, 0, header, sizeof(header)) ||
            memcmp(header, signature, sizeof(signature)))
            return false;
        uint32_t crc = ~0u;
        for (size_t i = 12; i < 32; ++i) {
            crc ^= header[i];
            for (int bit = 0; bit < 8; ++bit)
                crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
        }
        if (~crc != LittleEndian<uint32_t>(header + 8))
            return false;
        uint64_t offset = LittleEndian<uint64_t>(header + 12), size = LittleEndian<uint64_t>(header + 20);
        if (offset > UINT64_MAX - 32 || size > UINT64_MAX - 32 - offset)
            return false;
        uint64_t end = 32 + offset + size, consumed = 0;
        for (size_t i = 0; i < files.size(); ++i) {
            uint64_t part = SourceSize(files[i]);
            if (!part || part > UINT64_MAX - consumed)
                return false;
            consumed += part;
            if (consumed >= end) {
                files.resize(i + 1);
                return true;
            }
        }
        return false;
    }
    uint64_t length = SourceSize(*main);
    DWORD tailSize = (DWORD)std::min<uint64_t>(length, 65557);
    if (tailSize < 22)
        return false;
    std::vector<unsigned char> tail(tailSize);
    if (!ReadSpan(*main, length - tailSize, tail.data(), tailSize))
        return false;
    unsigned disks = 0;
    for (int i = (int)tailSize - 22; i >= 0; --i) {
        if (LittleEndian<uint32_t>(&tail[i]) != 0x06054b50 ||
            i + 22 + LittleEndian<uint16_t>(&tail[i + 20]) != tailSize)
            continue;
        unsigned last = LittleEndian<uint16_t>(&tail[i + 4]);
        if (last != 0xffff)
            disks = last + 1;
        else if (i >= 20 && LittleEndian<uint32_t>(&tail[i - 20]) == 0x07064b50)
            disks = LittleEndian<uint32_t>(&tail[i - 4]);
        break;
    }
    if (disks < 2 || disks > 10000)
        return false;
    auto extension = root.find_last_of(L'.');
    if (extension == std::wstring::npos)
        return false;
    std::vector<SourceFile> confirmed;
    for (unsigned index = 1; index < disks; ++index) {
        auto number = std::to_wstring(index);
        if (number.size() < 2)
            number = L"0" + number;
        auto name = root.substr(0, extension) + L".z" + number;
        auto found = std::find_if(files.begin(), files.end(), [&](const SourceFile &file) {
            return _wcsicmp(name.c_str(), file.path.c_str()) == 0;
        });
        if (found == files.end())
            return false;
        confirmed.push_back(*found);
    }
    confirmed.push_back(*main);
    files = std::move(confirmed);
    return true;
}
bool CaptureSource(const std::wstring &path, SourceFile &file) {
    wchar_t full[32768];
    DWORD count = GetFullPathNameW(path.c_str(), 32768, full, nullptr);
    if (!count || count >= 32768 || full[1] != L':' || full[2] != L'\\')
        return false;
    // Network and removable media may not have a usable recycle bin.
    wchar_t volume[32768];
    if (!GetVolumePathNameW(full, volume, 32768) || GetDriveTypeW(volume) != DRIVE_FIXED)
        return false;
    HANDLE handle =
        CreateFileW(full, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (handle == INVALID_HANDLE_VALUE)
        return false;
    BY_HANDLE_FILE_INFORMATION info{};
    bool valid = GetFileInformationByHandle(handle, &info) &&
                 !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT));
    CloseHandle(handle);
    if (!valid)
        return false;
    file.path = full;
    file.identity = info;
    return true;
}
bool SameSource(const SourceFile &file) {
    SourceFile current;
    if (!CaptureSource(file.path, current))
        return false;
    const auto &a = file.identity;
    const auto &b = current.identity;
    return a.dwVolumeSerialNumber == b.dwVolumeSerialNumber && a.nFileIndexHigh == b.nFileIndexHigh &&
           a.nFileIndexLow == b.nFileIndexLow && a.nFileSizeHigh == b.nFileSizeHigh &&
           a.nFileSizeLow == b.nFileSizeLow && CompareFileTime(&a.ftLastWriteTime, &b.ftLastWriteTime) == 0;
}
bool SourcesInUse(const std::vector<SourceFile> &files) {
    for (const auto &file : files) {
        HANDLE handle =
            CreateFileW(file.path.c_str(), DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (handle == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            if (error == ERROR_SHARING_VIOLATION || error == ERROR_LOCK_VIOLATION)
                return true;
        } else
            CloseHandle(handle);
    }
    return false;
}
namespace {
struct Sink : IFileOperationProgressSink {
    LONG refs = 1;
    const std::vector<SourceFile> &files;
    RecycleResult &result;
    Sink(const std::vector<SourceFile> &f, RecycleResult &r) : files(f), result(r) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id, void **out) override {
        if (!out)
            return E_POINTER;
        *out = nullptr;
        if (id == IID_IUnknown || id == IID_IFileOperationProgressSink) {
            *out = static_cast<IFileOperationProgressSink *>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override {
        return InterlockedIncrement(&refs);
    }
    ULONG STDMETHODCALLTYPE Release() override {
        auto n = InterlockedDecrement(&refs);
        if (!n)
            delete this;
        return n;
    }
    HRESULT STDMETHODCALLTYPE StartOperations() override {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE FinishOperations(HRESULT error) override {
        if (FAILED(error))
            result.error = error;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE PreDeleteItem(DWORD flags, IShellItem *item) override {
        // Abort if the shell proposes a permanent deletion instead of recycling.
        if (!(flags & TSF_DELETE_RECYCLE_IF_POSSIBLE))
            return E_ABORT;
        PWSTR path = nullptr;
        if (FAILED(item->GetDisplayName(SIGDN_FILESYSPATH, &path)))
            return E_ABORT;
        const SourceFile *found = nullptr;
        for (const auto &file : files)
            if (_wcsicmp(file.path.c_str(), path) == 0) {
                found = &file;
                break;
            }
        CoTaskMemFree(path);
        return found && SameSource(*found) ? S_OK : E_ABORT;
    }
    HRESULT STDMETHODCALLTYPE PostDeleteItem(DWORD, IShellItem *source, HRESULT error,
                                             IShellItem *recycled) override {
        if (SUCCEEDED(error) && recycled) {
            result.moved++;
            PWSTR from = nullptr, to = nullptr;
            if (SUCCEEDED(source->GetDisplayName(SIGDN_FILESYSPATH, &from)) &&
                SUCCEEDED(recycled->GetDisplayName(SIGDN_DESKTOPABSOLUTEPARSING, &to)))
                Trace(L"RECYCLED_ITEM " + std::wstring(from) + L"\t" + to);
            CoTaskMemFree(from);
            CoTaskMemFree(to);
        } else if (FAILED(error))
            result.error = error;
        else
            result.error = E_ABORT;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE PreRenameItem(DWORD, IShellItem *, LPCWSTR) override {
        return E_ABORT;
    }
    HRESULT STDMETHODCALLTYPE PostRenameItem(DWORD, IShellItem *, LPCWSTR, HRESULT, IShellItem *) override {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE PreMoveItem(DWORD, IShellItem *, IShellItem *, LPCWSTR) override {
        return E_ABORT;
    }
    HRESULT STDMETHODCALLTYPE PostMoveItem(DWORD, IShellItem *, IShellItem *, LPCWSTR, HRESULT,
                                           IShellItem *) override {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE PreCopyItem(DWORD, IShellItem *, IShellItem *, LPCWSTR) override {
        return E_ABORT;
    }
    HRESULT STDMETHODCALLTYPE PostCopyItem(DWORD, IShellItem *, IShellItem *, LPCWSTR, HRESULT,
                                           IShellItem *) override {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE PreNewItem(DWORD, IShellItem *, LPCWSTR) override {
        return E_ABORT;
    }
    HRESULT STDMETHODCALLTYPE PostNewItem(DWORD, IShellItem *, LPCWSTR, LPCWSTR, DWORD, HRESULT,
                                          IShellItem *) override {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE UpdateProgress(UINT, UINT) override {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE ResetTimer() override {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE PauseTimer() override {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE ResumeTimer() override {
        return S_OK;
    }
};
void RecycleSta(const std::vector<SourceFile> &files, RecycleResult &result) {
    HRESULT initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(initialized)) {
        result.error = initialized;
        return;
    }
    IFileOperation *operation = nullptr;
    result.error =
        CoCreateInstance(CLSID_FileOperation, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&operation));
    if (SUCCEEDED(result.error)) {
        result.error = operation->SetOperationFlags(FOFX_RECYCLEONDELETE | FOFX_EARLYFAILURE | FOF_NOERRORUI |
                                                    FOF_SILENT | FOF_NOCONFIRMATION | FOF_NORECURSION);
        auto sink = new Sink(files, result);
        for (const auto &file : files) {
            if (FAILED(result.error))
                break;
            IShellItem *item = nullptr;
            result.error = SHCreateItemFromParsingName(file.path.c_str(), nullptr, IID_PPV_ARGS(&item));
            if (SUCCEEDED(result.error)) {
                result.error = operation->DeleteItem(item, sink);
                item->Release();
            }
        }
        if (SUCCEEDED(result.error)) {
            HRESULT performed = operation->PerformOperations();
            if (FAILED(performed))
                result.error = performed;
            BOOL aborted = TRUE;
            if (FAILED(operation->GetAnyOperationsAborted(&aborted)) || aborted ||
                result.moved != files.size())
                if (SUCCEEDED(result.error))
                    result.error = E_ABORT;
        }
        operation->Release();
        sink->Release();
    }
    CoUninitialize();
}
} // namespace
RecycleResult RecycleSources(const std::vector<SourceFile> &files) {
    RecycleResult result;
    if (files.empty()) {
        result.error = E_INVALIDARG;
        return result;
    }
    for (const auto &file : files)
        if (!SameSource(file)) {
            result.error = HRESULT_FROM_WIN32(ERROR_FILE_INVALID);
            return result;
        }
    try {
        // The extraction worker may be an MTA. Shell file operations require an STA.
        std::thread worker([&] {
            try {
                RecycleSta(files, result);
            } catch (...) {
                result.error = E_OUTOFMEMORY;
            }
        });
        worker.join();
    } catch (...) {
        result.error = E_OUTOFMEMORY;
    }
    return result;
}
} // namespace bzap
