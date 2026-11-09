// Test-only: restore the specific fixture returned by the shell recycle callback.
#include "common.hpp"
#include <cstdio>
#include <shlobj.h>
int wmain(int argc, wchar_t **argv) {
    if (argc != 4)
        return 2;
    std::wstring root = argv[1], original = argv[2], recycled = argv[3];
    if (original.size() <= root.size() || _wcsnicmp(original.c_str(), root.c_str(), root.size()) ||
        original[root.size()] != L'\\' || bzap::Exists(original))
        return 3;
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    IShellItem *item = nullptr, *folder = nullptr;
    IFileOperation *operation = nullptr;
    HRESULT result = SHCreateItemFromParsingName(recycled.c_str(), nullptr, IID_PPV_ARGS(&item));
    if (SUCCEEDED(result))
        result =
            SHCreateItemFromParsingName(bzap::Directory(original).c_str(), nullptr, IID_PPV_ARGS(&folder));
    if (SUCCEEDED(result))
        result =
            CoCreateInstance(CLSID_FileOperation, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&operation));
    if (SUCCEEDED(result))
        result = operation->SetOperationFlags(FOF_SILENT | FOF_NOERRORUI | FOFX_EARLYFAILURE);
    if (SUCCEEDED(result))
        result = operation->MoveItem(item, folder, bzap::BaseName(original).c_str(), nullptr);
    if (SUCCEEDED(result))
        result = operation->PerformOperations();
    if (operation)
        operation->Release();
    if (folder)
        folder->Release();
    if (item)
        item->Release();
    CoUninitialize();
    return SUCCEEDED(result) && bzap::Exists(original) ? 0 : 1;
}
