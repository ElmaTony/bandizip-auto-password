#pragma once
#include <string>
#include <vector>
namespace bzap {
enum class StoreStatus { Ready, Empty, MasterPassword, Unsupported, Corrupt, ReadError };
struct PasswordStore {
    StoreStatus status = StoreStatus::Empty;
    std::vector<std::wstring> passwords;
    PasswordStore() = default;
    PasswordStore(const PasswordStore &) = delete;
    PasswordStore &operator=(const PasswordStore &) = delete;
    PasswordStore(PasswordStore &&) noexcept;
    PasswordStore &operator=(PasswordStore &&) noexcept;
    ~PasswordStore();
    void Clear();
};
PasswordStore DecodePasswordStore(const std::wstring &encoded);
PasswordStore ReadPasswordStore();
const wchar_t *StoreDescription(StoreStatus);
} // namespace bzap
