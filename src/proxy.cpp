#include "ark_abi.hpp"
#include "common.hpp"
#include "password_store.hpp"
#include "reporting.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace bzap {
namespace {
HMODULE ownModule = nullptr, originalModule = nullptr;
INIT_ONCE originalOnce = INIT_ONCE_STATIC_INIT, enableOnce = INIT_ONCE_STATIC_INIT;
using Factory = void *(__cdecl *)(unsigned);
Factory originalCreate = nullptr, originalCompressor = nullptr;
bool enabledBuild = false;
using ExitFunction = void(WINAPI *)(UINT);
ExitFunction originalExit = nullptr;
std::mutex contextMutex;
struct Context;
std::unordered_map<void *, std::shared_ptr<Context>> contexts;
thread_local std::unordered_map<Context *, const ark::FileItem *> currentItems;

BOOL CALLBACK LoadOriginal(PINIT_ONCE, void *, void **) {
    auto path = Join(Directory(ModulePath(ownModule)), OriginalDllName);
    originalModule = LoadLibraryExW(path.c_str(), nullptr,
                                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!originalModule)
        return FALSE;
    originalCreate = (Factory)GetProcAddress(originalModule, "CreateArk");
    originalCompressor = (Factory)GetProcAddress(originalModule, "CreateArkCompressor");
    return originalCreate && originalCompressor;
}
void WINAPI ExitHook(UINT code) {
    Trace(L"EXIT_HOOK");
    try {
        FinishNotifications();
    } catch (...) {
    }
    originalExit(code);
}
void HookExit() {
    auto base = (BYTE *)GetModuleHandleW(nullptr);
    auto dos = (IMAGE_DOS_HEADER *)base;
    auto nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    auto descriptor =
        (IMAGE_IMPORT_DESCRIPTOR *)(base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                                               .VirtualAddress);
    for (; descriptor->Name; descriptor++) {
        if (!descriptor->OriginalFirstThunk)
            continue;
        auto name = (IMAGE_THUNK_DATA64 *)(base + descriptor->OriginalFirstThunk);
        auto address = (IMAGE_THUNK_DATA64 *)(base + descriptor->FirstThunk);
        for (; name->u1.AddressOfData; name++, address++) {
            if (IMAGE_SNAP_BY_ORDINAL64(name->u1.Ordinal))
                continue;
            auto imported = (IMAGE_IMPORT_BY_NAME *)(base + name->u1.AddressOfData);
            if (strcmp((char *)imported->Name, "ExitProcess") != 0)
                continue;
            DWORD protection;
            if (!VirtualProtect(&address->u1.Function, sizeof(void *), PAGE_READWRITE, &protection))
                return;
            originalExit = (ExitFunction)address->u1.Function;
            address->u1.Function = (ULONG_PTR)&ExitHook;
            DWORD unused;
            VirtualProtect(&address->u1.Function, sizeof(void *), protection, &unused);
            return;
        }
    }
}
BOOL CALLBACK EnableBuild(PINIT_ONCE, void *, void **) {
    auto host = ModulePath();
    if (_wcsicmp(BaseName(host).c_str(), L"Bandizip.exe") != 0)
        return TRUE;
    auto real = Join(Directory(ModulePath(ownModule)), OriginalDllName);
    if (FileVersion(host) != L"7.47.0.1" || !IsAmd64Image(host) || FileHash(real) != SupportedArkSha256) {
        Trace(L"UNSUPPORTED_BUILD_PASSTHROUGH");
        return TRUE;
    }
    // ExitProcess's IAT entry must never outlive this DLL. Pin only in Bandizip,
    // never in Explorer/COM hosts. Lifetime ends with the existing application.
    HMODULE pin = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                            (LPCWSTR)&EnableBuild, &pin))
        return TRUE;
    enabledBuild = true;
    HookExit();
    Trace(L"SUPPORTED_BUILD_ENABLED");
    return TRUE;
}
struct Plan {
    size_t next = 0;
    int last = -1, confirmed = -1;
    bool confirmedOffered = false;
};
struct EventProxy;
struct Context {
    void *object = nullptr;
    void **original = nullptr;
    std::array<void *, ark::Slots + 1> storage{};
    std::mutex mutex;
    std::vector<std::unique_ptr<EventProxy>> eventObjects;
    PasswordStore store;
    Settings settings;
    std::unordered_map<const ark::FileItem *, Plan> plans;
    std::wstring path;
    std::atomic<bool> preflight{false}, exhausted{false}, canceled{false}, ambiguous{false};
    std::atomic<bool> hadDataError{false};
    std::atomic<unsigned> attempts{0}, completed{0};
    std::atomic<unsigned> extractionDepth{0};
    bool openingRejected = false;
    bool passThrough = false;
    std::atomic<unsigned> openingAttempts{0};
    std::atomic<ark::Error> lastError{0}, overrideError{0};
    bool reported = false;
    void Refresh() {
        settings = LoadSettings();
        store = PasswordStore();
        if (settings.enabled)
            store = ReadPasswordStore();
    }
    bool CanMatch() const {
        return !passThrough && settings.enabled && store.status == StoreStatus::Ready &&
               !store.passwords.empty();
    }
    ark::Error RawError() {
        return ark::Method<ark::Error(WINAPI *)(void *)>(original, 36)(object);
    }
    void ClearEnginePassword() {
        ark::Method<void(WINAPI *)(void *, const wchar_t *)>(original, 11)(object, nullptr);
    }
    void ResetOffers() {
        std::lock_guard<std::mutex> guard(mutex);
        for (auto &p : plans)
            p.second.confirmedOffered = false;
    }
    void Reset(const wchar_t *file) {
        path = file ? file : L"（内存中的压缩包）";
        plans.clear();
        attempts = 0;
        completed = 0;
        openingAttempts = 0;
        passThrough = false;
        exhausted = false;
        canceled = false;
        ambiguous = false;
        hadDataError = false;
        lastError = 0;
        overrideError = 0;
        reported = false;
        openingRejected = false;
        Refresh();
    }
    void Record(bool success, bool opening) {
        if (reported || !settings.enabled || passThrough)
            return;
        if (success && attempts.load() == 0)
            return;
        Result result;
        result.archive = path.empty() ? L"（未能识别名称的压缩包）" : path;
        result.error = success ? 0 : RawError();
        result.attempts = attempts;
        result.savedCount = store.passwords.size();
        result.completedFiles = completed;
        result.opening = opening;
        if (success)
            result.outcome = L"success";
        else if (canceled)
            result.outcome = L"canceled";
        else if (exhausted)
            result.outcome = (hadDataError || lastError == ark::CrcError || lastError == ark::PasswordOrData)
                                 ? L"password_or_data_error"
                                 : L"passwords_exhausted";
        else
            result.outcome = L"error";
        reported = true;
        RecordResult(result, settings.notify && exhausted.load());
    }
};
std::shared_ptr<Context> Find(void *object) {
    std::lock_guard<std::mutex> guard(contextMutex);
    auto p = contexts.find(object);
    return p == contexts.end() ? nullptr : p->second;
}
struct Activity {
    Activity() {
        OperationStarted();
    }
    ~Activity() {
        OperationFinished();
    }
};
// The backend dynamically casts output streams to its optional Ex interface.
// GNU C++ RTTI cannot be consumed by MSVC's __RTDynamicCast. Supply a valid
// single-class MSVC x64 descriptor for the public stream interface; the Ex cast
// correctly returns null and the backend uses the seven public methods.
// Layout reference: LLVM clang/lib/CodeGen/MicrosoftCXXABI.cpp (MS RTTI).
struct StreamRtti {
    struct Type {
        void *vtable;
        void *spare;
        char name[32];
    } type{};
    struct Base {
        int type, count, mdisp, pdisp, vdisp, attributes, hierarchy;
    } base{};
    int bases[1]{};
    struct Hierarchy {
        int signature, attributes, count, bases;
    } hierarchy{};
    struct Locator {
        int signature, offset, constructorOffset, type, hierarchy, self;
    } locator{};
    void *table[8]{};
};
StreamRtti streamRtti;
INIT_ONCE streamOnce = INIT_ONCE_STATIC_INIT;
BOOL CALLBACK InitStreamRtti(PINIT_ONCE, void *input, void **) {
    auto rva = [](const void *p) { return (int)((const BYTE *)p - (const BYTE *)ownModule); };
    strcpy(streamRtti.type.name, ".?AUIArkSimpleOutStream@@");
    streamRtti.base = {rva(&streamRtti.type), 0, 0, -1, 0, 0x40, rva(&streamRtti.hierarchy)};
    streamRtti.bases[0] = rva(&streamRtti.base);
    streamRtti.hierarchy = {0, 0, 1, rva(&streamRtti.bases)};
    streamRtti.locator = {
        1, 0, 0, rva(&streamRtti.type), rva(&streamRtti.hierarchy), rva(&streamRtti.locator)};
    streamRtti.table[0] = &streamRtti.locator;
    std::copy_n(*(void ***)input, 7, streamRtti.table + 1);
    return TRUE;
}
struct DiscardOutput : ark::Output {
    DiscardOutput() {
        InitOnceExecuteOnce(&streamOnce, InitStreamRtti, this, nullptr);
        *(void ***)this = streamRtti.table + 1;
    }
    int WINAPI Open(const wchar_t *) override {
        return TRUE;
    }
    int WINAPI SetSize(std::int64_t n) override {
        return n >= 0;
    }
    int WINAPI Write(const void *, std::uint32_t) override {
        return TRUE;
    }
    int WINAPI Close() override {
        return TRUE;
    }
    int WINAPI CreateFolder(const wchar_t *) override {
        return TRUE;
    }
    std::int64_t WINAPI SetPos(std::int64_t n) override {
        return n;
    }
    const wchar_t *WINAPI GetFilePathName() const override {
        return L"";
    }
};
struct EventProxy : ark::Events {
    Context *context;
    ark::Events *target;
    EventProxy(Context *c, ark::Events *t) : context(c), target(t) {}
    void WINAPI OpeningVolume(const char *a, const wchar_t *w, int n, int &stop) override {
        if (target)
            target->OpeningVolume(a, w, n, stop);
    }
    void WINAPI Opening(const ark::FileItem *item, float p, int &stop) override {
        if (target)
            target->Opening(item, p, stop);
    }
    void WINAPI StartFile(const ark::FileItem *item, int &stop, int &all, int index, const wchar_t *path,
                          ark::SetString *changed) override {
        currentItems[context] = item;
        if (!context->preflight && target)
            target->StartFile(item, stop, all, index, path, changed);
    }
    void WINAPI ProgressFile(const ark::Progress *info, int &stop, int &all) override {
        // Native progress also carries the existing Cancel button's state.
        if (target)
            target->ProgressFile(info, stop, all);
        if (stop || all)
            context->canceled = true;
    }
    void WINAPI CompleteFile(const ark::Progress *info, ark::Error error) override {
        auto item = currentItems.find(context);
        const ark::FileItem *key = item == currentItems.end() ? nullptr : item->second;
        if (error == 0) {
            std::lock_guard<std::mutex> guard(context->mutex);
            auto p = context->plans.find(key);
            if (p != context->plans.end() && p->second.last >= 0)
                p->second.confirmed = p->second.last;
        }
        if (!context->preflight) {
            if (error == 0)
                context->completed++;
            if (target)
                target->CompleteFile(info, error);
        }
        if (item != currentItems.end())
            currentItems.erase(item);
    }
    void WINAPI OnError(ark::Error error, const ark::FileItem *item, int warning, int &stop) override {
        context->lastError = error;
        if (error == ark::CrcError || error == ark::PasswordOrData)
            context->hadDataError = true;
        if (error == ark::Canceled)
            context->canceled = true;
        if (context->preflight) {
            if (!context->exhausted && (error == ark::CrcError || error == ark::PasswordOrData)) {
                std::lock_guard<std::mutex> guard(context->mutex);
                if (!item) {
                    auto current = currentItems.find(context);
                    if (current != currentItems.end())
                        item = current->second;
                }
                auto found = context->plans.find(item);
                if (found != context->plans.end() && found->second.last >= 0) {
                    found->second.confirmed = -1;
                    if (found->second.next < context->store.passwords.size())
                        context->ambiguous = true;
                    else
                        context->exhausted = true;
                }
            }
            stop = TRUE;
            return;
        }
        if (context->exhausted) {
            stop = TRUE;
            return;
        }
        if (target)
            target->OnError(error, item, warning, stop);
    }
    void WINAPI VolumeChanged(const wchar_t *p) override {
        if (target)
            target->VolumeChanged(p);
    }
    void WINAPI AskOverwrite(const ark::FileItem *item, const wchar_t *path, int &mode,
                             ark::SetString *changed) override {
        if (context->preflight) {
            mode = 0;
            return;
        }
        if (target)
            target->AskOverwrite(item, path, mode, changed);
    }
    void WINAPI AskPassword(const ark::FileItem *item, int why, int &answer,
                            ark::SetString *destination) override {
        if (!context->CanMatch()) {
            if (target)
                target->AskPassword(item, why, answer, destination);
            return;
        }
        try {
            std::wstring chosen;
            {
                std::lock_guard<std::mutex> guard(context->mutex);
                auto key = item;
                if (!key) {
                    auto current = currentItems.find(context);
                    if (current != currentItems.end())
                        key = current->second;
                }
                auto &plan = context->plans[key];
                int index = -1;
                if (plan.confirmed >= 0 && !plan.confirmedOffered) {
                    index = plan.confirmed;
                    plan.confirmedOffered = true;
                } else if (why == 1)
                    plan.confirmed = -1;
                if (index < 0) {
                    if (plan.next >= context->store.passwords.size()) {
                        context->exhausted = true;
                        context->lastError = ark::PasswordWrong;
                        answer = 1;
                        Trace(L"PASSWORDS_EXHAUSTED " + context->path);
                        return;
                    }
                    index = (int)plan.next++;
                }
                plan.last = index;
                chosen = context->store.passwords[(size_t)index];
                context->attempts++;
                Trace(L"TRY_SAVED index=" + std::to_wstring(index + 1));
            }
            destination->Set(chosen.c_str());
            SecureZeroMemory(chosen.data(), chosen.size() * sizeof(wchar_t));
            answer = 0;
        } catch (...) {
            if (target)
                target->AskPassword(item, why, answer, destination);
        }
    }
};
int WINAPI SetEventHook(void *object, ark::Events *events) {
    auto c = Find(object);
    if (!c)
        return FALSE;
    try {
        auto proxy = std::make_unique<EventProxy>(c.get(), events);
        auto pointer = proxy.get();
        {
            std::lock_guard<std::mutex> guard(c->mutex);
            c->eventObjects.push_back(std::move(proxy));
        }
        return ark::Method<int(WINAPI *)(void *, ark::Events *)>(c->original, 35)(object, pointer);
    } catch (...) {
        return FALSE;
    }
}
void WINAPI ReleaseHook(void *object) {
    std::shared_ptr<Context> c;
    {
        std::lock_guard<std::mutex> guard(contextMutex);
        auto p = contexts.find(object);
        if (p == contexts.end())
            return;
        c = p->second;
        contexts.erase(p);
    }
    *(void ***)object = c->original;
    ark::Method<void(WINAPI *)(void *)>(c->original, 0)(object);
    c->store.Clear();
    currentItems.erase(c.get());
    Trace(L"CONTEXT_RELEASED");
}
ark::Error WINAPI ErrorHook(void *object) {
    auto c = Find(object);
    return c ? (c->overrideError.load() ? c->overrideError.load() : c->RawError()) : ark::CannotOpen;
}
void WINAPI CloseHook(void *object) {
    auto c = Find(object);
    if (!c)
        return;
    ark::Method<void(WINAPI *)(void *)>(c->original, 6)(object);
}
int OpenWithRetry(const std::shared_ptr<Context> &c, const wchar_t *file, const wchar_t *password,
                  const std::function<int(const wchar_t *)> &open) {
    Activity activity;
    c->Reset(file);
    Trace(L"OPEN " + c->path);
    int result = open(password);
    if (!result && c->CanMatch()) {
        for (;;) {
            auto error = c->RawError();
            c->lastError = error;
            if (!ark::PasswordError(error) || c->exhausted || c->canceled)
                break;
            std::wstring candidate;
            {
                std::lock_guard<std::mutex> guard(c->mutex);
                auto &plan = c->plans[nullptr];
                if (plan.next >= c->store.passwords.size()) {
                    c->exhausted = true;
                    break;
                }
                auto index = plan.next++;
                plan.last = (int)index;
                candidate = c->store.passwords[index];
                c->attempts++;
                Trace(L"TRY_SAVED index=" + std::to_wstring(index + 1) + L" opening");
            }
            result = open(candidate.c_str());
            SecureZeroMemory(candidate.data(), candidate.size() * sizeof(wchar_t));
            if (result)
                break;
        }
    }
    if (result)
        c->openingAttempts = c->attempts.load();
    Trace(result ? L"OPEN_SUCCEEDED" : L"OPEN_FAILED");
    if (!result) {
        // Tell the native host this archive was skipped, so it does not open an
        // extra password dialog after our saved-password list is exhausted.
        if (c->exhausted) {
            c->overrideError = ark::Canceled;
            c->openingRejected = true;
        }
        c->Record(false, true);
    }
    return result;
}
int WINAPI OpenWHook(void *object, const wchar_t *path, const wchar_t *password) {
    auto c = Find(object);
    if (!c)
        return FALSE;
    auto open = ark::Method<int(WINAPI *)(void *, const wchar_t *, const wchar_t *)>(c->original, 4);
    return OpenWithRetry(c, path, password, [=](const wchar_t *p) { return open(object, path, p); });
}
int WINAPI OpenAHook(void *object, const char *path, const char *password) {
    auto c = Find(object);
    if (!c)
        return FALSE;
    auto open = ark::Method<int(WINAPI *)(void *, const char *, const char *)>(c->original, 5);
    int n = path ? MultiByteToWideChar(CP_ACP, 0, path, -1, nullptr, 0) : 0;
    std::wstring w(n, L'\0');
    if (n) {
        MultiByteToWideChar(CP_ACP, 0, path, -1, w.data(), n);
        w.pop_back();
    }
    Activity activity;
    c->Reset(w.c_str());
    int result = open(object, path, password);
    if (!result && c->CanMatch() && ark::PasswordError(c->RawError())) {
        auto openW = ark::Method<int(WINAPI *)(void *, const wchar_t *, const wchar_t *)>(c->original, 4);
        return OpenWithRetry(c, w.c_str(), nullptr,
                             [=](const wchar_t *p) { return openW(object, w.c_str(), p); });
    }
    if (!result)
        c->Record(false, true);
    return result;
}
bool Verify(const std::shared_ptr<Context> &c, const std::function<int(ark::Output *)> &verify) {
    struct Phase {
        Context &c;
        Phase(Context &value) : c(value) {
            c.preflight = true;
        }
        ~Phase() {
            c.preflight = false;
        }
    } phase(*c);
    bool success = false;
    for (;;) {
        c->ambiguous = false;
        c->ResetOffers();
        DiscardOutput discard;
        success = verify(&discard) != 0;
        if (success || c->canceled || c->exhausted || !c->ambiguous)
            break;
        Trace(L"RETRY_AFTER_PASSWORD_OR_CRC_ERROR");
        c->ClearEnginePassword();
    }
    return success;
}
int WINAPI OpenStreamHook(void *o, void *stream, const wchar_t *password) {
    auto c = Find(o);
    if (!c)
        return FALSE;
    c->Reset(nullptr);
    c->passThrough = true;
    c->store.Clear();
    return ark::Method<int(WINAPI *)(void *, void *, const wchar_t *)>(c->original, 2)(o, stream, password);
}
int WINAPI OpenBytesHook(void *o, unsigned char *bytes, int length, const wchar_t *password) {
    auto c = Find(o);
    if (!c)
        return FALSE;
    c->Reset(nullptr);
    c->passThrough = true;
    c->store.Clear();
    return ark::Method<int(WINAPI *)(void *, unsigned char *, int, const wchar_t *)>(c->original, 3)(
        o, bytes, length, password);
}
int Execute(void *object, const std::function<int()> &extract,
            const std::function<int(ark::Output *)> &verify) {
    auto c = Find(object);
    if (!c)
        return FALSE;
    struct Depth {
        std::atomic<unsigned> &value;
        unsigned previous;
        Depth(std::atomic<unsigned> &v) : value(v), previous(v.fetch_add(1)) {}
        ~Depth() {
            value--;
        }
    } depth(c->extractionDepth);
    if (depth.previous || c->preflight || c->passThrough)
        return extract();
    // The host can still request extraction after a canceled Open. Never treat
    // this empty engine state as success (including native delete-after-extract).
    if (c->openingRejected)
        return FALSE;
    Activity activity;
    c->settings = LoadSettings();
    c->reported = false;
    c->completed = 0;
    c->canceled = false;
    c->overrideError = 0;
    c->attempts = c->openingAttempts.exchange(0);
    c->lastError = 0;
    c->hadDataError = false;
    if (!c->settings.enabled)
        return extract();
    c->store = ReadPasswordStore();
    c->plans.clear();
    c->exhausted = false;
    auto isEncrypted = ark::Method<int(WINAPI *)(void *)>(c->original, 17);
    if (c->settings.verify && c->CanMatch() && isEncrypted(object)) {
        Trace(L"VERIFY_BEFORE_EXTRACT");
        if (!Verify(c, verify)) {
            c->Record(false, false);
            return FALSE;
        }
    }
    c->ResetOffers();
    int result = extract();
    Trace(L"EXTRACT_RETURN " + std::to_wstring(result));
    if (!result)
        c->lastError = c->RawError();
    c->Record(result != 0, false);
    return result;
}
// Slots inside overloaded groups are in MSVC order, deliberately independent
// of the C++ compiler used to build this proxy (including Zig/Clang).
int WINAPI AllWHook(void *o, const wchar_t *path, const wchar_t *remove) {
    auto c = Find(o);
    return Execute(
        o,
        [=] {
            return ark::Method<int(WINAPI *)(void *, const wchar_t *, const wchar_t *)>(c->original,
                                                                                        22)(o, path, remove);
        },
        [=](ark::Output *sink) {
            return ark::Method<int(WINAPI *)(void *, ark::Output *, const wchar_t *)>(c->original,
                                                                                      21)(o, sink, remove);
        });
}
int WINAPI AllAHook(void *o, const char *path, const wchar_t *remove) {
    auto c = Find(o);
    return Execute(
        o,
        [=] {
            return ark::Method<int(WINAPI *)(void *, const char *, const wchar_t *)>(c->original, 23)(o, path,
                                                                                                      remove);
        },
        [=](ark::Output *sink) {
            return ark::Method<int(WINAPI *)(void *, ark::Output *, const wchar_t *)>(c->original,
                                                                                      21)(o, sink, remove);
        });
}
int WINAPI AllStreamHook(void *o, ark::Output *stream, const wchar_t *remove) {
    auto c = Find(o);
    return Execute(
        o,
        [=] {
            return ark::Method<int(WINAPI *)(void *, ark::Output *, const wchar_t *)>(c->original,
                                                                                      21)(o, stream, remove);
        },
        [=](ark::Output *sink) {
            return ark::Method<int(WINAPI *)(void *, ark::Output *, const wchar_t *)>(c->original,
                                                                                      21)(o, sink, remove);
        });
}
int WINAPI MultiWHook(void *o, const wchar_t *path, const wchar_t *remove) {
    auto c = Find(o);
    return Execute(
        o,
        [=] {
            return ark::Method<int(WINAPI *)(void *, const wchar_t *, const wchar_t *)>(c->original,
                                                                                        33)(o, path, remove);
        },
        [=](ark::Output *sink) {
            return ark::Method<int(WINAPI *)(void *, ark::Output *)>(c->original, 32)(o, sink);
        });
}
int WINAPI MultiAHook(void *o, const char *path) {
    auto c = Find(o);
    return Execute(
        o, [=] { return ark::Method<int(WINAPI *)(void *, const char *)>(c->original, 34)(o, path); },
        [=](ark::Output *sink) {
            return ark::Method<int(WINAPI *)(void *, ark::Output *)>(c->original, 32)(o, sink);
        });
}
int WINAPI MultiStreamHook(void *o, ark::Output *stream) {
    auto c = Find(o);
    return Execute(
        o, [=] { return ark::Method<int(WINAPI *)(void *, ark::Output *)>(c->original, 32)(o, stream); },
        [=](ark::Output *sink) {
            return ark::Method<int(WINAPI *)(void *, ark::Output *)>(c->original, 32)(o, sink);
        });
}
int WINAPI OneWHook(void *o, int index, const wchar_t *path) {
    auto c = Find(o);
    return Execute(
        o,
        [=] {
            return ark::Method<int(WINAPI *)(void *, int, const wchar_t *)>(c->original, 27)(o, index, path);
        },
        [=](ark::Output *sink) {
            return ark::Method<int(WINAPI *)(void *, int, ark::Output *)>(c->original, 25)(o, index, sink);
        });
}
int WINAPI OneAHook(void *o, int index, const char *path) {
    auto c = Find(o);
    return Execute(
        o,
        [=] {
            return ark::Method<int(WINAPI *)(void *, int, const char *)>(c->original, 26)(o, index, path);
        },
        [=](ark::Output *sink) {
            return ark::Method<int(WINAPI *)(void *, int, ark::Output *)>(c->original, 25)(o, index, sink);
        });
}
int WINAPI OneStreamHook(void *o, int index, ark::Output *stream) {
    auto c = Find(o);
    return Execute(
        o,
        [=] {
            return ark::Method<int(WINAPI *)(void *, int, ark::Output *)>(c->original, 25)(o, index, stream);
        },
        [=](ark::Output *sink) {
            return ark::Method<int(WINAPI *)(void *, int, ark::Output *)>(c->original, 25)(o, index, sink);
        });
}
int WINAPI OneBufferHook(void *o, int index, unsigned char *data, int length) {
    auto c = Find(o);
    return Execute(
        o,
        [=] {
            return ark::Method<int(WINAPI *)(void *, int, unsigned char *, int)>(c->original,
                                                                                 24)(o, index, data, length);
        },
        [=](ark::Output *sink) {
            return ark::Method<int(WINAPI *)(void *, int, ark::Output *)>(c->original, 25)(o, index, sink);
        });
}
int WINAPI OneAsHook(void *o, int index, const wchar_t *path, wchar_t *result, int length) {
    auto c = Find(o);
    return Execute(
        o,
        [=] {
            return ark::Method<int(WINAPI *)(void *, int, const wchar_t *, wchar_t *, int)>(c->original, 28)(
                o, index, path, result, length);
        },
        [=](ark::Output *sink) {
            return ark::Method<int(WINAPI *)(void *, int, ark::Output *)>(c->original, 25)(o, index, sink);
        });
}
} // namespace
} // namespace bzap
extern "C" __declspec(dllexport) const wchar_t *__cdecl BzapPluginVersion() {
    return bzap::ProductVersion;
}
extern "C" __declspec(dllexport) void *__cdecl CreateArk(unsigned version) {
    using namespace bzap;
    if (!InitOnceExecuteOnce(&originalOnce, LoadOriginal, nullptr, nullptr))
        return nullptr;
    void *object = originalCreate(version);
    if (!object)
        return nullptr;
    try {
        InitOnceExecuteOnce(&enableOnce, EnableBuild, nullptr, nullptr);
        if (!enabledBuild || version != ark::LibraryVersion)
            return object;
        auto c = std::make_shared<Context>();
        c->object = object;
        c->original = *(void ***)object;
        std::copy_n(c->original - 1, ark::Slots + 1, c->storage.begin());
        c->settings = LoadSettings();
        auto table = c->storage.data() + 1;
        table[0] = (void *)&ReleaseHook;
        table[2] = (void *)&OpenStreamHook;
        table[3] = (void *)&OpenBytesHook;
        table[4] = (void *)&OpenWHook;
        table[5] = (void *)&OpenAHook;
        table[6] = (void *)&CloseHook;
        table[21] = (void *)&AllStreamHook;
        table[22] = (void *)&AllWHook;
        table[23] = (void *)&AllAHook;
        table[24] = (void *)&OneBufferHook;
        table[25] = (void *)&OneStreamHook;
        table[26] = (void *)&OneAHook;
        table[27] = (void *)&OneWHook;
        table[28] = (void *)&OneAsHook;
        table[32] = (void *)&MultiStreamHook;
        table[33] = (void *)&MultiWHook;
        table[34] = (void *)&MultiAHook;
        table[35] = (void *)&SetEventHook;
        table[36] = (void *)&ErrorHook;
        {
            std::lock_guard<std::mutex> guard(contextMutex);
            contexts.emplace(object, c);
        }
        *(void ***)object = table;
        SetEventHook(object, nullptr);
        Trace(L"CONTEXT_ATTACHED");
    } catch (...) {
        Trace(L"ATTACH_FAILED_PASSTHROUGH");
    }
    return object;
}
extern "C" __declspec(dllexport) void *__cdecl CreateArkCompressor(unsigned version) {
    using namespace bzap;
    if (!InitOnceExecuteOnce(&originalOnce, LoadOriginal, nullptr, nullptr))
        return nullptr;
    return originalCompressor(version);
}
BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, void *) {
    if (reason == DLL_PROCESS_ATTACH) {
        bzap::ownModule = module;
        DisableThreadLibraryCalls(module);
    }
    return TRUE;
}
