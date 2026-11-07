// Invoke the unchanged native context-menu implementation without registering
// a menu or changing system associations. Registry overrides affect this process.
#define UNICODE
#define _UNICODE
#include <cstdio>
#include <fcntl.h>
#include <io.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <string>
#include <vector>
#include <windows.h>
static void PrintMenu(HMENU m, IContextMenu *menu, std::vector<std::pair<UINT, std::wstring>> &entries) {
    for (int i = 0; i < GetMenuItemCount(m); i++) {
        wchar_t label[1024] = {};
        GetMenuStringW(m, i, label, 1024, MF_BYPOSITION);
        UINT id = GetMenuItemID(m, i);
        HMENU sub = GetSubMenu(m, i);
        if (sub) {
            PrintMenu(sub, menu, entries);
            continue;
        }
        if (id >= 1 && id < 10000) {
            wchar_t verb[512] = {};
            menu->GetCommandString(id - 1, GCS_VERBW, nullptr, (char *)verb, 512);
            wprintf(L"MENU id=%u title=%ls verb=%ls\n", id, label, verb);
            entries.emplace_back(id, label);
        }
    }
}
static void Pump() {
    DWORD end = GetTickCount() + 4000;
    while ((int)(end - GetTickCount()) > 0) {
        MSG m;
        while (PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
        Sleep(20);
    }
}
struct Fake {
    void **table;
};
static void *browserTable[48], *viewTable[48], *folderTable[48];
static Fake browser{browserTable}, view{viewTable}, folderView{folderTable};
static IShellItemArray *selectedItems;
static IDataObject *selectedData;
static IShellFolder *selectedParent;
static HWND hostWindow;
static HRESULT WINAPI FakeQI(Fake *self, REFIID iid, void **out) {
    wchar_t guid[80];
    StringFromGUID2(iid, guid, 80);
    wprintf(L"SITE_INTERFACE %ls\n", guid);
    *out = nullptr;
    if (iid == IID_IUnknown)
        *out = self;
    else if (iid == IID_IShellBrowser || iid == IID_IOleWindow)
        *out = &browser;
    else if (iid == IID_IShellView)
        *out = &view;
    else if (iid == IID_IFolderView || iid == IID_IFolderView2)
        *out = &folderView;
    return *out ? S_OK : E_NOINTERFACE;
}
static ULONG WINAPI FakeRef(void *) {
    return 2;
}
static HRESULT WINAPI FakeUnimplemented(void *) {
    wprintf(L"SITE_UNIMPLEMENTED return=%p\n", __builtin_return_address(0));
    return E_NOTIMPL;
}
static HRESULT WINAPI FakeWindow(void *, HWND *out) {
    *out = hostWindow;
    return S_OK;
}
static HRESULT WINAPI FakeActive(void *, IShellView **out) {
    wprintf(L"SITE_ACTIVE_VIEW\n");
    *out = (IShellView *)&view;
    return S_OK;
}
static HRESULT WINAPI FakeSelection(void *, BOOL, IShellItemArray **out) {
    wprintf(L"SITE_SELECTION\n");
    *out = selectedItems;
    selectedItems->AddRef();
    return S_OK;
}
static HRESULT WINAPI FakeItems(void *, UINT flags, REFIID iid, void **out) {
    wprintf(L"SITE_ITEMS flags=%u\n", flags);
    if (iid == IID_IDataObject)
        return selectedData->QueryInterface(iid, out);
    return selectedItems->QueryInterface(iid, out);
}
static HRESULT WINAPI FakeFolder(void *, REFIID iid, void **out) {
    return selectedParent->QueryInterface(iid, out);
}
static HRESULT WINAPI FakeCount(void *, UINT, int *out) {
    *out = 1;
    return S_OK;
}
static HRESULT WINAPI FakeMode(void *, UINT *out) {
    *out = FVM_DETAILS;
    return S_OK;
}
struct Site : IServiceProvider {
    HRESULT WINAPI QueryInterface(REFIID iid, void **out) override {
        if (iid == IID_IUnknown || iid == IID_IServiceProvider) {
            *out = this;
            return S_OK;
        }
        return FakeQI(&browser, iid, out);
    }
    ULONG WINAPI AddRef() override {
        return 2;
    }
    ULONG WINAPI Release() override {
        return 2;
    }
    HRESULT WINAPI QueryService(REFGUID service, REFIID iid, void **out) override {
        wchar_t guid[80];
        StringFromGUID2(service, guid, 80);
        wprintf(L"SITE_SERVICE %ls\n", guid);
        return FakeQI(&browser, iid, out);
    }
};
static Site site;
static void PrepareSite(IExplorerCommand *command, const std::wstring &archive, IShellItemArray *items) {
    selectedItems = items;
    PIDLIST_ABSOLUTE pidl = ILCreateFromPathW(archive.c_str());
    PCUITEMID_CHILD child;
    SHBindToParent(pidl, IID_IShellFolder, (void **)&selectedParent, &child);
    selectedParent->GetUIObjectOf(nullptr, 1, &child, IID_IDataObject, nullptr, (void **)&selectedData);
    for (auto table : {browserTable, viewTable, folderTable}) {
        for (int i = 0; i < 48; i++)
            table[i] = (void *)FakeUnimplemented;
        table[0] = (void *)FakeQI;
        table[1] = (void *)FakeRef;
        table[2] = (void *)FakeRef;
    }
    browserTable[3] = (void *)FakeWindow;
    browserTable[15] = (void *)FakeActive;
    viewTable[3] = (void *)FakeWindow;
    viewTable[15] = (void *)FakeItems;
    folderTable[3] = (void *)FakeMode;
    folderTable[5] = (void *)FakeFolder;
    folderTable[7] = (void *)FakeCount;
    folderTable[8] = (void *)FakeItems;
    folderTable[32] = (void *)FakeSelection;
    hostWindow = CreateWindowExW(0, L"STATIC", L"Bandizip Test Host", WS_POPUP, 0, 0, 10, 10, nullptr,
                                 nullptr, GetModuleHandleW(nullptr), nullptr);
    IObjectWithSite *target = nullptr;
    HRESULT hr = command->QueryInterface(IID_IObjectWithSite, (void **)&target);
    wprintf(L"SITE_QI hr=%lx\n", hr);
    if (SUCCEEDED(hr)) {
        hr = target->SetSite(&site);
        wprintf(L"SITE_SET hr=%lx\n", hr);
        target->Release();
    }
}
int wmain(int argc, wchar_t **argv) {
    _setmode(_fileno(stdout), _O_U8TEXT);
    if (argc < 5)
        return 2; // app-dir, fixture-path, registry-root, classic|modern|open [query]
    std::wstring dir = argv[1], archive = argv[2], key = argv[3], mode = argv[4];
    SetEnvironmentVariableW(L"BANDIZIP_RESEARCH_KEY", key.c_str());
    HKEY hive, fakeLM, fakeCR, sub;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, KEY_ALL_ACCESS, &hive))
        return 11;
    RegCreateKeyExW(hive, L"FakeLM", 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &fakeLM, nullptr);
    RegCreateKeyExW(hive, L"FakeCR", 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &fakeCR, nullptr);
    RegCreateKeyExW(fakeLM, L"SOFTWARE\\Bandizip", 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &sub, nullptr);
    std::wstring appdir = dir + L"\\";
    RegSetValueExW(sub, L"ProgramFolder", 0, REG_SZ, (BYTE *)appdir.c_str(), (DWORD)(appdir.size() + 1) * 2);
    RegCloseKey(sub);
    RegOverridePredefKey(HKEY_CURRENT_USER, hive);
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (mode == L"open") {
        RegCreateKeyExW(fakeCR, L".zip", 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &sub, nullptr);
        RegSetValueExW(sub, nullptr, 0, REG_SZ, (BYTE *)L"Bandizip.zip", 26);
        RegCloseKey(sub);
        RegCreateKeyExW(fakeCR, L"Bandizip.zip\\Shell\\Open\\Command", 0, nullptr, 0, KEY_ALL_ACCESS, nullptr,
                        &sub, nullptr);
        auto cmd = L"\"" + dir + L"\\Bandizip.exe\" \"%1\"";
        RegSetValueExW(sub, nullptr, 0, REG_SZ, (BYTE *)cmd.c_str(), (DWORD)(cmd.size() + 1) * 2);
        RegCloseKey(sub);
        RegOverridePredefKey(HKEY_CLASSES_ROOT, fakeCR);
        SHELLEXECUTEINFOW si = {sizeof(si)};
        si.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_CLASSNAME;
        si.lpClass = L"Bandizip.zip";
        si.lpVerb = L"open";
        si.lpFile = archive.c_str();
        si.nShow = SW_SHOWNORMAL;
        BOOL ok = ShellExecuteExW(&si);
        wprintf(L"SHELL_OPEN ok=%d error=%lu\n", ok, GetLastError());
        return ok ? 0 : 3;
    }
    HMODULE dll =
        LoadLibraryW((dir + (mode == L"modern" ? L"\\data\\bzshell.x64.dll" : L"\\bdzshl.x64.dll")).c_str());
    if (!dll) {
        wprintf(L"Load failed=%lu\n", GetLastError());
        return 4;
    }
    using Factory = HRESULT(WINAPI *)(REFCLSID, REFIID, void **);
    auto factory = (Factory)GetProcAddress(dll, "DllGetClassObject");
    IClassFactory *cf = nullptr;
    CLSID cls;
    CLSIDFromString(mode == L"modern" ? L"{0001DEAD-9BF7-4CFA-8A5C-DE8679340001}"
                                      : L"{5B69A6B4-393B-459C-8EBB-214237A9E7AC}",
                    &cls);
    HRESULT hr = factory(cls, IID_IClassFactory, (void **)&cf);
    wprintf(L"FACTORY hr=%lx\n", hr);
    if (FAILED(hr))
        return 5;
    if (mode == L"classic") {
        IShellExtInit *init = nullptr;
        hr = cf->CreateInstance(nullptr, IID_IShellExtInit, (void **)&init);
        if (FAILED(hr))
            return 6;
        PIDLIST_ABSOLUTE pidl = ILCreateFromPathW(archive.c_str());
        PCUITEMID_CHILD child;
        IShellFolder *parent = nullptr;
        SHBindToParent(pidl, IID_IShellFolder, (void **)&parent, &child);
        IDataObject *data = nullptr;
        hr = parent->GetUIObjectOf(nullptr, 1, &child, IID_IDataObject, nullptr, (void **)&data);
        if (FAILED(hr))
            return 7;
        hr = init->Initialize(nullptr, data, nullptr);
        wprintf(L"INITIALIZE hr=%lx\n", hr);
        IContextMenu *menu = nullptr;
        init->QueryInterface(IID_IContextMenu, (void **)&menu);
        HMENU popup = CreatePopupMenu();
        hr = menu->QueryContextMenu(popup, 0, 1, 9999, CMF_NORMAL);
        wprintf(L"QUERY hr=%lx\n", hr);
        std::vector<std::pair<UINT, std::wstring>> entries;
        PrintMenu(popup, menu, entries);
        if (argc > 5) {
            std::wstring query = argv[5];
            UINT selected = 0;
            for (auto &entry : entries)
                if (entry.second.find(query) != std::wstring::npos) {
                    selected = entry.first;
                    break;
                }
            if (!selected) {
                wprintf(L"No matching native command\n");
                return 8;
            }
            CMINVOKECOMMANDINFOEX ci = {};
            ci.cbSize = sizeof(CMINVOKECOMMANDINFO);
            ci.lpVerb = MAKEINTRESOURCEA(selected - 1);
            ci.nShow = SW_SHOWNORMAL;
            ci.hwnd = CreateWindowExW(0, L"STATIC", L"Bandizip Test Host", WS_POPUP, 0, 0, 10, 10, nullptr,
                                      nullptr, GetModuleHandleW(nullptr), nullptr);
            hr = menu->InvokeCommand((CMINVOKECOMMANDINFO *)&ci);
            wprintf(L"INVOKE hr=%lx id=%u\n", hr, selected);
            Pump();
        }
    } else {
        IExplorerCommand *command = nullptr;
        hr = cf->CreateInstance(nullptr, IID_IExplorerCommand, (void **)&command);
        if (FAILED(hr))
            return 9;
        IShellItem *item = nullptr;
        hr = SHCreateItemFromParsingName(archive.c_str(), nullptr, IID_IShellItem, (void **)&item);
        wprintf(L"ITEM hr=%lx\n", hr);
        IShellItemArray *items = nullptr;
        hr = SHCreateShellItemArrayFromShellItem(item, IID_IShellItemArray, (void **)&items);
        wprintf(L"ITEM_ARRAY hr=%lx\n", hr);
        DWORD count = 0;
        if (items)
            items->GetCount(&count);
        wprintf(L"ITEM_COUNT=%lu\n", count);
        PrepareSite(command, archive, items);
        PWSTR rootTitle = nullptr;
        hr = command->GetTitle(items, &rootTitle);
        wprintf(L"ROOT_TITLE hr=%lx title=%ls\n", hr, rootTitle ? rootTitle : L"?");
        CoTaskMemFree(rootTitle);
        EXPCMDSTATE state;
        hr = command->GetState(items, TRUE, &state);
        wprintf(L"ROOT_STATE hr=%lx state=%u\n", hr, (unsigned)state);
        IEnumExplorerCommand *enumerator = nullptr;
        hr = command->EnumSubCommands(&enumerator);
        wprintf(L"ENUM hr=%lx\n", hr);
        if (FAILED(hr))
            return 10;
        IExplorerCommand *subcmd;
        ULONG fetched;
        int index = 0;
        while (enumerator->Next(1, &subcmd, &fetched) == S_OK) {
            PWSTR title = nullptr;
            subcmd->GetTitle(items, &title);
            wprintf(L"MODERN id=%d title=%ls\n", index, title ? title : L"?");
            if (argc > 5 && title && std::wstring(title).find(argv[5]) != std::wstring::npos) {
                hr = subcmd->Invoke(items, nullptr);
                wprintf(L"INVOKE_MODERN hr=%lx\n", hr);
                CoTaskMemFree(title);
                Pump();
                break;
            }
            CoTaskMemFree(title);
            subcmd->Release();
            index++;
        }
    }
    return 0;
}
