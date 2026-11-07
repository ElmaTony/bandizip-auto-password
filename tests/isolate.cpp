// Test-only DLL, imported solely by a disposable copy of Bandizip.exe.
// It redirects HKCU before application startup. Never install this DLL.
#include <windows.h>
extern "C" __declspec(dllexport) void ResearchNoop() {}
BOOL WINAPI DllMain(HINSTANCE h, DWORD why, void *) {
    if (why == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        wchar_t key[512];
        if (!GetEnvironmentVariableW(L"BANDIZIP_RESEARCH_KEY", key, 512))
            return FALSE;
        HKEY root = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, key, 0, KEY_ALL_ACCESS, &root) != ERROR_SUCCESS)
            return FALSE;
        return RegOverridePredefKey(HKEY_CURRENT_USER, root) == ERROR_SUCCESS;
    }
    return TRUE;
}
