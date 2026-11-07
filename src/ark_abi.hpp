#pragma once
#include <cstddef>
#include <cstdint>
#include <windows.h>

// Interoperability declarations for the explicitly supported x64 Ark build.
// No commercial Ark SDK source is included or needed for this project.
namespace bzap::ark {
using Object = void;
using Error = std::uint32_t;
struct FileItem;
struct Progress {
    float current, total;
    int completing;
    float completingPercent;
    int internal;
};
struct SetString {
    virtual void WINAPI Set(const wchar_t *) = 0;
};
struct Events {
    virtual void WINAPI OpeningVolume(const char *, const wchar_t *, int, int &) = 0;
    virtual void WINAPI Opening(const FileItem *, float, int &) = 0;
    virtual void WINAPI StartFile(const FileItem *, int &, int &, int, const wchar_t *, SetString *) = 0;
    virtual void WINAPI ProgressFile(const Progress *, int &, int &) = 0;
    virtual void WINAPI CompleteFile(const Progress *, Error) = 0;
    virtual void WINAPI OnError(Error, const FileItem *, int, int &) = 0;
    virtual void WINAPI VolumeChanged(const wchar_t *) = 0;
    virtual void WINAPI AskOverwrite(const FileItem *, const wchar_t *, int &, SetString *) = 0;
    virtual void WINAPI AskPassword(const FileItem *, int, int &, SetString *) = 0;
};
struct Output {
    virtual int WINAPI Open(const wchar_t *) = 0;
    virtual int WINAPI SetSize(std::int64_t) = 0;
    virtual int WINAPI Write(const void *, std::uint32_t) = 0;
    virtual int WINAPI Close() = 0;
    virtual int WINAPI CreateFolder(const wchar_t *) = 0;
    virtual std::int64_t WINAPI SetPos(std::int64_t) = 0;
    virtual const wchar_t *WINAPI GetFilePathName() const = 0;
};
// This Bandizip build extends the 59-slot public interface to 82 slots.
// Preserve all private slots unchanged, as well as the preceding RTTI pointer.
// The exact backend SHA256 gate is essential for this layout.
inline constexpr std::size_t Slots = 82;
inline constexpr unsigned LibraryVersion = 0x20250923;
inline constexpr Error Ok = 0, CannotOpen = 0xa0000001, Canceled = 0xa0000017, CrcError = 0xa0000018,
                       PasswordMissing = 0xa0000020, PasswordWrong = 0xa0000021, UserSkip = 0xa0000059,
                       PasswordOrData = 0xa0000060;
inline bool PasswordError(Error e) {
    return e == PasswordMissing || e == PasswordWrong || e == PasswordOrData;
}
template <class T> T Method(void **table, std::size_t slot) {
    return reinterpret_cast<T>(table[slot]);
}
} // namespace bzap::ark
