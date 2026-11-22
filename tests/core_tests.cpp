// Exercise the real proxy state machine with a fake backend. No Ark DLL is
// loaded and the real password registry is never read, including in CI.
#include "password_store.hpp"
namespace bzap { PasswordStore ReadTestStore(); }
#define ReadPasswordStore ReadTestStore
#include "../src/proxy.cpp"
#undef ReadPasswordStore
#include "viewport.hpp"
#include <cstdio>

namespace bzap {
int dummyStoreReads = 0;
PasswordStore ReadTestStore() {
    ++dummyStoreReads;
    PasswordStore store;
    store.status = StoreStatus::Ready;
    store.passwords = {L"dummy-first", L"dummy-second"};
    return store;
}
}
using namespace bzap;
namespace {
int checks = 0, itemCount = 2, selectedCount = 0;
unsigned char items[3][64]{};
std::function<void()> duringVerify;
void Check(bool ok, const char *name) {
    if (!ok) { fprintf(stderr, "FAIL core: %s\n", name); ExitProcess(1); }
    ++checks;
}
int WINAPI Count(void *) { return itemCount; }
int WINAPI SelectedCount(void *) { return selectedCount; }
std::vector<int> nativeSelection;
int rejectedIndex = -1;
int WINAPI AddIndex(void *, int index) {
    if (index == rejectedIndex)
        return FALSE;
    nativeSelection.push_back(index);
    selectedCount = (int)nativeSelection.size();
    return TRUE;
}
void WINAPI ClearIndices(void *) { nativeSelection.clear(); selectedCount = 0; }
int WINAPI ExtractSelected(void *, const wchar_t *, const wchar_t *) {
    return nativeSelection == std::vector<int>{1};
}
int WINAPI Encrypted(void *) { return TRUE; }
ark::Error WINAPI Error(void *) { return ark::CrcError; }
const ark::FileItem *WINAPI Item(void *, int index) { return (const ark::FileItem *)items[index]; }
void WINAPI SetPassword(void *, const wchar_t *) {}
int WINAPI VerifyOne(void *, int, ark::Output *) { if (duringVerify) duringVerify(); return TRUE; }
bool WriteOutput(const std::wstring &path, const char *text) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    bool ok = WriteFile(file, text, (DWORD)strlen(text), &written, nullptr) && written == strlen(text);
    CloseHandle(file);
    return ok;
}
bool OutputEquals(const std::wstring &path, const char *text) {
    std::vector<unsigned char> bytes;
    return ReadFileBytes(path, bytes) && std::string(bytes.begin(), bytes.end()) == text;
}
struct NativeEvents : ark::Events {
    int overwrite = 1, overwriteCalls = 0;
    void WINAPI OpeningVolume(const char *, const wchar_t *, int, int &) override {}
    void WINAPI Opening(const ark::FileItem *, float, int &) override {}
    void WINAPI StartFile(const ark::FileItem *, int &, int &, int, const wchar_t *, ark::SetString *) override {}
    void WINAPI ProgressFile(const ark::Progress *, int &, int &) override {}
    void WINAPI CompleteFile(const ark::Progress *, ark::Error) override {}
    void WINAPI OnError(ark::Error, const ark::FileItem *, int, int &) override {}
    void WINAPI VolumeChanged(const wchar_t *) override {}
    void WINAPI AskOverwrite(const ark::FileItem *, const wchar_t *, int &mode, ark::SetString *) override {
        ++overwriteCalls; mode = overwrite;
    }
    void WINAPI AskPassword(const ark::FileItem *, int, int &, ark::SetString *) override {}
};
}
int wmain() {
    wchar_t temporary[MAX_PATH]; GetTempPathW(MAX_PATH, temporary);
    auto directory = Join(temporary, L"bzap-core-" + std::to_wstring(GetCurrentProcessId()));
    Check(EnsureDirectory(directory), "isolated output folder");
    SetEnvironmentVariableW(L"BZAP_NO_UI", L"1");
    SetEnvironmentVariableW(L"BZAP_DATA_DIR", directory.c_str());
    auto settings = Join(directory, L"settings.ini"), output = Join(directory, L"proof.txt");
    auto configure = [&](bool verify) {
        Check(AtomicWrite(settings, std::string("[General]\nEnabled=1\nNotifyFailures=0\nFullPreflight=") +
                                    (verify ? "1\n" : "0\n")), "write dummy settings");
    };
    void *table[82]{};
    table[11] = (void *)&SetPassword; table[13] = (void *)&Count;
    table[14] = (void *)&Item; table[17] = (void *)&Encrypted;
    table[25] = (void *)&VerifyOne; table[36] = (void *)&Error;
    table[31] = (void *)&SelectedCount;
    table[29] = (void *)&AddIndex;
    table[30] = (void *)&ClearIndices;
    table[33] = (void *)&ExtractSelected;
    auto object = table;
    auto c = std::make_shared<Context>(); c->object = &object; c->original = table;
    c->path = L"synthetic-core.zip"; contexts[&object] = c;
    EventProxy events(c.get(), nullptr);
    auto start = [&](int index, int stop = 0) {
        int all = 0; events.StartFile(Item(nullptr, index), stop, all, index, output.c_str(), nullptr);
        return all;
    };
    auto fail = [&](int index) {
        c->plans[Item(nullptr, index)].last = 0; c->plans[Item(nullptr, index)].next = 1;
        int stop = 0; events.OnError(ark::CrcError, Item(nullptr, index), 0, stop);
        events.CompleteFile(nullptr, ark::CrcError);
    };
    auto execute = [&](const std::function<int()> &extract, const std::function<int(ark::Output *)> &verify,
                       bool disk = false, bool selected = false,
                       const std::function<int(const std::vector<int> &)> &resume = {}) {
        return Execute(&object, extract, verify, disk, selected, resume, directory.c_str());
    };
    auto verified = [](ark::Output *) { return TRUE; };
    int extracted = 0, resumed = 0;
    configure(true);
    int result = execute([&] { ++extracted; return TRUE; }, [&](ark::Output *) {
        c->canceled = true; return TRUE;
    });
    Check(!result && extracted == 0 && ErrorHook(&object) == ark::Canceled, "preflight cancel prevents extraction");
    Check(!c->canResume, "preflight early exit resets retry state");
    int validations = 0;
    result = execute([&] { ++extracted; return TRUE; }, [&](ark::Output *) {
        if (++validations == 1) {
            ++c->attempts;
            fail(0);
        }
        return TRUE;
    });
    Check(result && validations == 2 && extracted == 1,
          "a positive backend return cannot hide a failed preflight item");
    validations = extracted = 0;
    result = execute([&] { ++extracted; return TRUE; }, [&](ark::Output *) {
        ++validations;
        // Other files may progress while the failing item's candidate stays the same.
        ++c->attempts;
        if (validations < 4) fail(0);
        return TRUE;
    });
    Check(!result && validations == 2 && extracted == 0, "stalled verification stops without disk extraction");
    configure(false);
    result = execute([&] { c->exhausted = true; c->lastError = ark::PasswordWrong; return TRUE; }, verified);
    Check(!result && ErrorHook(&object) != 0, "exhaustion overrides a positive extraction return");
    result = execute([&] {
        start(0); Check(WriteOutput(output, "partial"), "write owned partial output");
        fail(0); AtomicWrite(output, "unrelated replacement"); return FALSE;
    }, verified, true, false, [&](const std::vector<int> &) { ++resumed; return TRUE; });
    Check(!result && resumed == 0 && c->canceled, "replacement before failure snapshot rejects retry");
    Check(OutputEquals(output, "unrelated replacement"), "unrelated replacement preserved");
    std::vector<unsigned char> history;
    Check(ReadFileBytes(Join(directory, L"history.jsonl"), history) &&
          std::string(history.begin(), history.end()).find("\"output_changed\"") != std::string::npos,
          "history distinguishes output conflict from user cancellation");
    DeleteFileW(output.c_str());
    duringVerify = [&] { AtomicWrite(output, "replacement during verification"); };
    result = execute([&] { start(0); WriteOutput(output, "partial"); fail(0); return FALSE; },
                     verified, true, false, [&](const std::vector<int> &) {
        Check(start(0) != 0, "replacement during verification cancels native write"); return TRUE;
    });
    Check(!result, "canceled retry is not success");
    Check(OutputEquals(output, "replacement during verification"), "verification replacement preserved");
    duringVerify = {}; DeleteFileW(output.c_str());
    duringVerify = [&] { c->canceled = true; };
    resumed = 0;
    result = execute([&] { start(0); WriteOutput(output, "partial"); fail(0); return FALSE; },
                     verified, true, false, [&](const std::vector<int> &) { ++resumed; return TRUE; });
    Check(!result && !resumed && ErrorHook(&object) == ark::Canceled,
          "canceled retry verification never resumes extraction");
    duringVerify = {}; DeleteFileW(output.c_str());
    result = execute([&] {
        start(0, 1); events.CompleteFile(nullptr, ark::UserSkip);
        start(1); WriteOutput(output, "partial"); fail(1); DeleteFileW(output.c_str()); return FALSE;
    }, verified, true, false, [&](const std::vector<int> &indices) {
        Check(indices == std::vector<int>{1}, "skip retained across retry");
        Check(!start(1), "removed failed output can be recreated");
        int mode = -1; events.AskOverwrite(Item(nullptr, 1), output.c_str(), mode, nullptr);
        Check(mode == 0, "own empty reservation bypasses overwrite prompt");
        WriteOutput(output, "verified output"); events.CompleteFile(nullptr, 0); return TRUE;
    });
    Check(result && !c->canResume && c->outputOwners.empty(), "retry succeeds and releases state");
    DeleteFileW(output.c_str());
    c->selection = {1}; selectedCount = 1;
    result = execute([&] { start(1); WriteOutput(output, "partial"); fail(1); return FALSE; },
                     verified, true, true, [&](const std::vector<int> &indices) {
        Check(indices == std::vector<int>{1}, "selected retry excludes unselected items");
        Check(!start(1), "selected retry retains owned output");
        WriteOutput(output, "selected output"); events.CompleteFile(nullptr, 0); return TRUE;
    });
    Check(result && OutputEquals(output, "selected output"), "selected retry succeeds");
    c->selection.clear(); selectedCount = 0;
    AddIndex(nullptr, 0); c->selection = {0};
    Check(ResumeTo(c, nullptr, nullptr, {1}, true) && nativeSelection == std::vector<int>{0} &&
          c->selection == nativeSelection, "whole archive retry preserves pending native selection");
    rejectedIndex = 2;
    Check(!ResumeTo(c, nullptr, nullptr, {1, 2}, true) && nativeSelection == std::vector<int>{0} &&
          c->selection == nativeSelection, "failed selection setup restores pending items");
    rejectedIndex = -1;
    Check(ResumeTo(c, nullptr, nullptr, {1}, false) && nativeSelection.empty() && c->selection.empty(),
          "selected archive retry consumes its internal selection");
    OutputSnapshot regular, extended;
    Check(CaptureOutput(output, regular) && CaptureOutput(OutputPath(output), extended) &&
              SameOutputIdentity(regular, extended), "extended output paths preserve identity");
    Check(OutputPath(L"\\\\server\\share\\file") == L"\\\\?\\UNC\\server\\share\\file", "UNC normalization");
    NativeEvents native;
    EventProxy nativeProxy(c.get(), &native);
    c->canResume = true; c->store = ReadTestStore();
    int stop = 0, all = 0, mode = -1;
    nativeProxy.StartFile(Item(nullptr, 0), stop, all, 0, output.c_str(), nullptr);
    nativeProxy.AskOverwrite(Item(nullptr, 0), output.c_str(), mode, nullptr);
    Check(mode == 1 && native.overwriteCalls == 1 && c->skippedItems.count(Item(nullptr, 0)),
          "preexisting output keeps native skip policy");
    DeleteFileW(output.c_str());
    OutputOwner owner;
    Check(ReserveOutput(output, owner), "reserve empty output");
    RemoveEmptyReservation(owner);
    Check(!Exists(output), "unused empty reservation cleaned");
    Check(ReserveOutput(output, owner), "reserve for replacement check");
    AtomicWrite(output, "replacement survives cleanup"); RemoveEmptyReservation(owner);
    Check(OutputEquals(output, "replacement survives cleanup"), "cleanup preserves replacement");
    auto longRoot = Join(directory, L"long-path-test");
    auto longOutput = Join(Join(Join(longRoot, std::wstring(120, L'a')), std::wstring(120, L'b')), L"proof.txt");
    Check(longOutput.size() > MAX_PATH && ReserveOutput(longOutput, owner), "reserve beyond MAX_PATH");
    Check(CaptureFailedOutput(owner, OutputPath(longOutput), extended) && SameOutput(extended),
          "long-path failure identity remains retryable");
    RemoveEmptyReservation(owner);
    Check(!Exists(OutputPath(longOutput)), "long-path reservation cleanup");
    std::error_code cleanupError;
    std::filesystem::remove_all(OutputPath(longRoot), cleanupError);
    Check(!cleanupError, "long-path test directory cleanup");
    for (UINT dpi : {96u, 144u, 192u, 288u}) {
        RECT desired{0, 0, MulDiv(920, dpi, 96), MulDiv(714, dpi, 96) + 70};
        RECT work{0, 0, 1366, 728}; auto fitted = FitWindow(desired, work);
        Check(fitted.right <= work.right && fitted.bottom <= work.bottom, "window fits work area");
        Check(ScrollPosition(100000, desired.bottom, 500) == desired.bottom - 500,
              "scroll reaches bottom at each DPI");
    }
    auto root = OutputPath(directory);
    Check(WithinOutputRoot(root, Join(directory, L"folder\\proof.txt")), "nested output belongs to selection");
    Check(!WithinOutputRoot(root, Join(directory + L"-different", L"proof.txt")), "sibling prefix not owned");
    Check(!WithinOutputRoot(root, L"proof.txt"), "unspecified destination is not owned");
    int reads = dummyStoreReads;
    c->Reset(nullptr, true);
    Check(c->passThrough && dummyStoreReads == reads && c->store.passwords.empty(),
          "native-only stream does not read the password store");
    contexts.clear();
    for (auto name : {L"proof.txt", L"settings.ini", L"history.jsonl", L"解压记录.txt"})
        DeleteFileW(Join(directory, name).c_str());
    RemoveDirectoryW(directory.c_str());
    printf("PASS %d core checks\n", checks);
    return 0;
}
