#include "password_store.hpp"
#include "common.hpp"
#include <algorithm>
#include <cstdint>
#include <mbedtls/blowfish.h>
#include <utility>

extern "C" void mbedtls_platform_zeroize(void *p, size_t n) {
    if (p && n)
        SecureZeroMemory(p, n);
}
namespace bzap {
// Format-1 obfuscation key of an unprotected Bandizip password store; it is not
// a user password. A different key checksum means a master password is set.
static constexpr char FormatKey[] = "the truth is over there";
static uint32_t Crc(const char *data, size_t size) {
    uint32_t crc = ~0u;
    for (size_t i = 0; i < size; i++) {
        crc ^= (unsigned char)data[i];
        for (int b = 0; b < 8; b++)
            crc = (crc >> 1) ^ (0xedb88320u & -(int)(crc & 1));
    }
    return ~crc;
}
PasswordStore::PasswordStore(PasswordStore &&other) noexcept
    : status(other.status), passwords(std::move(other.passwords)) {}
PasswordStore &PasswordStore::operator=(PasswordStore &&other) noexcept {
    if (this != &other) {
        Clear();
        status = other.status;
        passwords = std::move(other.passwords);
    }
    return *this;
}
void PasswordStore::Clear() {
    for (auto &s : passwords)
        if (!s.empty())
            SecureZeroMemory(s.data(), s.size() * sizeof(wchar_t));
    passwords.clear();
}
PasswordStore::~PasswordStore() {
    Clear();
}
static int Hex(wchar_t c) {
    if (c >= L'0' && c <= L'9')
        return c - L'0';
    if (c >= L'a' && c <= L'f')
        return c - L'a' + 10;
    if (c >= L'A' && c <= L'F')
        return c - L'A' + 10;
    return -1;
}
PasswordStore DecodePasswordStore(const std::wstring &encoded) {
    PasswordStore out;
    if (encoded.empty())
        return out;
    out.status = StoreStatus::Unsupported;
    if (encoded[0] != L'1')
        return out;
    out.status = StoreStatus::Corrupt;
    if (encoded.size() < 9 || encoded.size() > 1024 * 1024 || (encoded.size() - 9) % 16)
        return out;
    uint32_t checksum = 0;
    for (size_t i = 1; i < 9; i++) {
        int v = Hex(encoded[i]);
        if (v < 0)
            return out;
        checksum = checksum * 16 + v;
    }
    if (checksum != Crc(FormatKey, sizeof(FormatKey) - 1)) {
        out.status = StoreStatus::MasterPassword;
        return out;
    }
    struct Buffer {
        std::vector<unsigned char> bytes;
        ~Buffer() {
            if (!bytes.empty())
                SecureZeroMemory(bytes.data(), bytes.size());
        }
    } plain;
    plain.bytes.resize((encoded.size() - 9) / 2 + 1, 0);
    for (size_t i = 0; i + 1 < plain.bytes.size(); i++) {
        int a = Hex(encoded[9 + 2 * i]), b = Hex(encoded[10 + 2 * i]);
        if (a < 0 || b < 0)
            return out;
        plain.bytes[i] = (unsigned char)(a * 16 + b);
    }
    mbedtls_blowfish_context cipher;
    mbedtls_blowfish_init(&cipher);
    if (mbedtls_blowfish_setkey(&cipher, (const unsigned char *)FormatKey, (sizeof(FormatKey) - 1) * 8) !=
        0) {
        mbedtls_blowfish_free(&cipher);
        return out;
    }
    for (size_t i = 0; i + 8 < plain.bytes.size(); i += 8) {
        unsigned char input[8], output[8];
        for (int j = 0; j < 8; j++)
            input[j] = plain.bytes[i + (j / 4) * 4 + 3 - j % 4];
        mbedtls_blowfish_crypt_ecb(&cipher, MBEDTLS_BLOWFISH_DECRYPT, input, output);
        for (int j = 0; j < 8; j++)
            plain.bytes[i + j] = output[(j / 4) * 4 + 3 - j % 4];
        SecureZeroMemory(input, 8);
        SecureZeroMemory(output, 8);
    }
    mbedtls_blowfish_free(&cipher);
    size_t end = 0;
    while (end + 1 < plain.bytes.size() && plain.bytes[end])
        end++;
    if (end == 0) {
        out.status = StoreStatus::Empty;
        return out;
    }
    size_t start = 0;
    bool header = false;
    while (start < end) {
        size_t lineEnd = start;
        while (lineEnd < end && plain.bytes[lineEnd] != '\n')
            lineEnd++;
        if (lineEnd > start && plain.bytes[lineEnd - 1] == '\r')
            lineEnd--;
        size_t tab = start;
        while (tab < lineEnd && plain.bytes[tab] != '\t')
            tab++;
        if (tab < lineEnd) {
            if (tab > start) {
                if (tab - start > 16 * 1024 || out.passwords.size() >= 4096) {
                    out.Clear();
                    return out;
                }
                std::string utf((const char *)plain.bytes.data() + start, tab - start);
                auto password = Wide(utf);
                SecureZeroMemory(utf.data(), utf.size());
                if (password.empty()) {
                    out.Clear();
                    return out;
                }
                if (std::find(out.passwords.begin(), out.passwords.end(), password) == out.passwords.end())
                    out.passwords.push_back(std::move(password));
                else
                    SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
            }
        } else if (lineEnd > start) {
            if (header || plain.bytes[start] != '[' || plain.bytes[lineEnd - 1] != ']') {
                out.Clear();
                return out;
            }
            header = true;
        }
        start = lineEnd;
        while (start < end && (plain.bytes[start] == '\r' || plain.bytes[start] == '\n'))
            start++;
    }
    out.status = out.passwords.empty() ? StoreStatus::Empty : StoreStatus::Ready;
    return out;
}
PasswordStore ReadPasswordStore() {
    PasswordStore result;
    DWORD size = 0;
    LONG code = RegGetValueW(HKEY_CURRENT_USER, L"Software\\Bandizip\\passman", L"data",
                             RRF_RT_REG_SZ | RRF_NOEXPAND, nullptr, nullptr, &size);
    if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND)
        return result;
    if (code != ERROR_SUCCESS || size > 2 * 1024 * 1024 || size % sizeof(wchar_t)) {
        result.status = StoreStatus::ReadError;
        return result;
    }
    std::wstring text(size / 2 + 1, L'\0');
    code = RegGetValueW(HKEY_CURRENT_USER, L"Software\\Bandizip\\passman", L"data",
                        RRF_RT_REG_SZ | RRF_NOEXPAND, nullptr, text.data(), &size);
    if (code != ERROR_SUCCESS) {
        result.status = StoreStatus::ReadError;
        return result;
    }
    text.resize(wcsnlen(text.data(), text.size()));
    result = DecodePasswordStore(text);
    SecureZeroMemory(text.data(), text.size() * sizeof(wchar_t));
    return result;
}
const wchar_t *StoreDescription(StoreStatus s) {
    switch (s) {
    case StoreStatus::Ready:
        return L"可读取已保存密码";
    case StoreStatus::Empty:
        return L"尚未保存密码";
    case StoreStatus::MasterPassword:
        return L"检测到主密码，将保留 Bandizip 原有密码窗口";
    case StoreStatus::Unsupported:
        return L"密码数据格式暂不支持，将保留原有密码窗口";
    case StoreStatus::Corrupt:
        return L"密码数据未能解析，将保留原有密码窗口";
    default:
        return L"无法读取密码管理器，将保留原有密码窗口";
    }
}
} // namespace bzap
