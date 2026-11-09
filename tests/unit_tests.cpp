#include "common.hpp"
#include "password_store.hpp"
#include "recycle.hpp"
#include <cstdio>
#include <mbedtls/blowfish.h>
#include <string>
#include <vector>
using namespace bzap;
static int checks = 0;
static void Check(bool ok, const char *name) {
    if (!ok) {
        fprintf(stderr, "FAIL: %s\n", name);
        ExitProcess(1);
    }
    checks++;
}
static unsigned Crc(const std::string &s) {
    unsigned c = ~0u;
    for (unsigned char b : s) {
        c ^= b;
        for (int j = 0; j < 8; j++)
            c = (c >> 1) ^ (0xedb88320u & -(int)(c & 1));
    }
    return ~c;
}
static std::wstring Encode(std::string plain) {
    const std::string key = "the truth is over there";
    plain.resize((plain.size() + 7) / 8 * 8, '\0');
    char head[10];
    snprintf(head, sizeof(head), "1%08x", Crc(key));
    std::wstring encoded = Wide(head);
    mbedtls_blowfish_context cipher;
    mbedtls_blowfish_init(&cipher);
    mbedtls_blowfish_setkey(&cipher, (const unsigned char *)key.data(), (unsigned)key.size() * 8);
    const wchar_t *hex = L"0123456789abcdef";
    for (size_t i = 0; i < plain.size(); i += 8) {
        unsigned char in[8], out[8];
        for (int j = 0; j < 8; j++)
            in[j] = plain[i + (j / 4) * 4 + 3 - j % 4];
        mbedtls_blowfish_crypt_ecb(&cipher, MBEDTLS_BLOWFISH_ENCRYPT, in, out);
        for (int j = 0; j < 8; j++) {
            auto b = out[(j / 4) * 4 + 3 - j % 4];
            encoded += hex[b >> 4];
            encoded += hex[b & 15];
        }
    }
    mbedtls_blowfish_free(&cipher);
    return encoded;
}
int wmain() {
    mbedtls_blowfish_context bf;
    mbedtls_blowfish_init(&bf);
    unsigned char zero[8] = {}, cipher[8], clear[8];
    const unsigned char expected[] = {0x4e, 0xf9, 0x97, 0x45, 0x61, 0x98, 0xdd, 0x78};
    Check(mbedtls_blowfish_setkey(&bf, zero, 64) == 0, "Blowfish key");
    mbedtls_blowfish_crypt_ecb(&bf, 1, zero, cipher);
    Check(memcmp(cipher, expected, 8) == 0, "published Blowfish zero vector");
    mbedtls_blowfish_crypt_ecb(&bf, 0, cipher, clear);
    Check(memcmp(clear, zero, 8) == 0, "Blowfish decrypt");
    mbedtls_blowfish_free(&bf);
    Check(DecodePasswordStore(L"").status == StoreStatus::Empty, "missing store");
    auto data =
        Encode("[test]\nfirst\tFirst\n" + Utf8(L"中文密码🔑") + "\tUnicode\nfirst\tDuplicate\nlast\tLast\n");
    auto store = DecodePasswordStore(data);
    Check(store.status == StoreStatus::Ready, "store format");
    Check(store.passwords.size() == 3, "deduplicate");
    Check(store.passwords[0] == L"first" && store.passwords[1] == L"中文密码🔑" &&
              store.passwords[2] == L"last",
          "Unicode and order");
    auto master = data;
    master[1] = master[1] == L'0' ? L'1' : L'0';
    Check(DecodePasswordStore(master).status == StoreStatus::MasterPassword, "master password fallback");
    Check(DecodePasswordStore(L"2").status == StoreStatus::Unsupported, "future format fallback");
    Check(DecodePasswordStore(data + L"0").status == StoreStatus::Corrupt, "truncated block");
    auto invalid = data;
    invalid[10] = L'z';
    Check(DecodePasswordStore(invalid).status == StoreStatus::Corrupt, "bad hex");
    Check(DecodePasswordStore(Encode("not a password store")).status == StoreStatus::Corrupt,
          "bad plaintext");
    Check(DecodePasswordStore(Encode("[test]\n")).status == StoreStatus::Empty, "empty list");
    Check(DecodePasswordStore(Encode(std::string("[test]\n\xff\tbad\n"))).status == StoreStatus::Corrupt,
          "invalid UTF-8");
    auto crlf = DecodePasswordStore(Encode("[test]\r\nfirst\tLabel\r\nlast\tLabel\r\n"));
    Check(crlf.status == StoreStatus::Ready && crlf.passwords.size() == 2 && crlf.passwords[1] == L"last",
          "CRLF store parsing");
    Check(DecodePasswordStore(Encode("[test]\n" + std::string(17000, 'a') + "\ttoo long\n")).status ==
              StoreStatus::Corrupt,
          "oversize entry");
    std::wstring key = L"Software\\BandizipAutoPasswordTests\\unit-" + std::to_wstring(GetCurrentProcessId());
    HKEY root = nullptr, pass = nullptr;
    Check(RegCreateKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &root,
                          nullptr) == ERROR_SUCCESS,
          "isolated profile");
    Check(RegCreateKeyExW(root, L"Software\\Bandizip\\passman", 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &pass,
                          nullptr) == ERROR_SUCCESS,
          "isolated password key");
    Check(RegSetValueExW(pass, L"data", 0, REG_SZ, (const BYTE *)data.c_str(),
                         (DWORD)(data.size() + 1) * 2) == ERROR_SUCCESS,
          "dummy store write");
    RegCloseKey(pass);
    Check(RegOverridePredefKey(HKEY_CURRENT_USER, root) == ERROR_SUCCESS, "registry isolation");
    auto registry = ReadPasswordStore();
    Check(registry.passwords == store.passwords, "registry reader");
    RegOverridePredefKey(HKEY_CURRENT_USER, nullptr);
    RegCloseKey(root);
    RegDeleteTreeW(HKEY_CURRENT_USER, key.c_str());
    wchar_t temp[MAX_PATH];
    GetTempPathW(MAX_PATH, temp);
    auto path = Join(temp, L"bzap-unit-" + std::to_wstring(GetCurrentProcessId()));
    Check(AtomicWrite(path, "abc"), "atomic write");
    Check(FileHash(path) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "SHA256 reference");
    Check(!EnsureDirectory(path), "reject file as directory");
    SourceFile original;
    Check(CaptureSource(path, original), "source identity capture");
    Check(SameSource(original), "unchanged source accepted");
    Check(AtomicWrite(path, "replaced"), "replace fixture");
    Check(!SameSource(original), "replaced source rejected");
    Check(!CaptureSource(Directory(path), original), "directory is not recyclable source");
    Check(!CaptureSource(L"\\\\server\\share\\archive.zip", original), "network source rejected");
    DeleteFileW(path.c_str());
    auto settingsDirectory = path + L"-settings";
    EnsureDirectory(settingsDirectory);
    wchar_t oldData[32768];
    DWORD oldDataLength = GetEnvironmentVariableW(L"BZAP_DATA_DIR", oldData, 32768);
    SetEnvironmentVariableW(L"BZAP_DATA_DIR", settingsDirectory.c_str());
    auto settingsFile = Join(settingsDirectory, L"settings.ini");
    Check(!LoadSettings().verify && !LoadSettings().recycle, "single pass and keep archives by default");
    AtomicWrite(settingsFile, "[General]\nVerifyBeforeExtract=1\n");
    Check(!LoadSettings().verify, "legacy implicit preflight is not inherited");
    AtomicWrite(settingsFile, "[General]\nFullPreflight=1\nRecycleAfterExtract=1\n");
    Check(LoadSettings().verify && LoadSettings().recycle, "explicit extraction preferences");
    SetEnvironmentVariableW(L"BZAP_DATA_DIR", oldDataLength && oldDataLength < 32768 ? oldData : nullptr);
    DeleteFileW(settingsFile.c_str());
    RemoveDirectoryW(settingsDirectory.c_str());

    const unsigned char header[] = {0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 4, 0xef, 0x50, 0xd7,
                                    0x23, 0x60, 0,    0,    0,    0,    0, 0, 0,    4,    0,
                                    0,    0,    0,    0,    0,    0,    0, 0, 0,    0};
    std::vector<SourceFile> volumes;
    for (int i = 1; i <= 4; ++i) {
        auto part = path + L".7z.00" + std::to_wstring(i);
        std::string bytes(i <= 2 ? 64 : 4, 'x');
        if (i == 1)
            memcpy(bytes.data(), header, sizeof(header));
        AtomicWrite(part, bytes);
        SourceFile file;
        Check(CaptureSource(part, file), "split fixture identity");
        volumes.push_back(file);
    }
    auto bounded = volumes;
    Check(TrimSplitSources(1, volumes[0].path, bounded) && bounded.size() == 3,
          "7z next numbered decoy excluded");
    bounded = {volumes[0], volumes[1]};
    Check(!TrimSplitSources(1, volumes[0].path, bounded), "7z incomplete volume set refused");
    AtomicWrite(volumes[0].path, std::string(64, 'x'));
    CaptureSource(volumes[0].path, volumes[0]);
    bounded = volumes;
    Check(!TrimSplitSources(1, volumes[0].path, bounded), "unrecognized numbered archive kept");
    for (const auto &volume : volumes)
        DeleteFileW(volume.path.c_str());
    Check(Wide(Utf8(L"测试🔑")) == L"测试🔑", "UTF-8 round trip");
    printf("PASS %d checks\n", checks);
    return 0;
}
