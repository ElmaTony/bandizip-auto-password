#pragma once
#include "common.hpp"
namespace bzap {
struct InstallResult {
    bool ok = false;
    DWORD code = 0;
    std::wstring message;
};
struct InstallStatus {
    std::wstring directory, version, installedVersion;
    bool supported = false, installed = false, backupValid = false, updateAvailable = false;
    bool newerInstalled = false, canUninstall = false;
    std::wstring detail;
};
InstallStatus GetInstallStatus(const std::wstring &directory);
InstallResult Install(const std::wstring &directory, const std::wstring &packageDirectory);
InstallResult Uninstall(const std::wstring &directory);
} // namespace bzap
