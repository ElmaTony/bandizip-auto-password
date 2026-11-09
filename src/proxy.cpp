#include "ark_abi.hpp"
#include "common.hpp"
#include "password_store.hpp"
#include "recycle.hpp"
#include "reporting.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
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
    std::vector<SourceFile> observedSources, pendingSources;
    std::vector<std::wstring> usedSources;
    std::unordered_set<const ark::FileItem *> requiredItems, writtenItems;
    std::unordered_set<const ark::FileItem *> successfulItems, retryItems;
    std::unordered_map<const ark::FileItem *, std::wstring> outputPaths;
    std::unordered_map<const ark::FileItem *, SourceFile> retryOutputs;
    bool canResume = false;
    std::vector<int> selection;
    std::atomic<bool> recycleBlocked{false};
    std::atomic<bool> preflight{false}, exhausted{false}, canceled{false}, ambiguous{false};
    std::atomic<bool> hadDataError{false};
    std::atomic<unsigned> attempts{0}, completed{0};
    std::atomic<unsigned> extractionDepth{0};
    bool openingRejected = false;
    bool passThrough = false;
    std::atomic<unsigned> openingAttempts{0};
    std::atomic<ark::Error> lastError{0}, overrideError{0};
    bool reported = false;
    void ObserveSource(const wchar_t *name, bool used = false) {
        if (!name || !*name)
            return;
        SourceFile file;
        if (!CaptureSource(name, file))
            return;
        std::lock_guard<std::mutex> guard(mutex);
        if (used) {
            bool known = false;
            for (const auto &old : usedSources)
                if (_wcsicmp(old.c_str(), file.path.c_str()) == 0)
                    known = true;
            if (!known)
                usedSources.push_back(file.path);
        }
        for (const auto &old : observedSources)
            if (_wcsicmp(old.path.c_str(), file.path.c_str()) == 0)
                return;
        observedSources.push_back(std::move(file));
    }
    std::vector<std::wstring> EngineSources() {
        auto count = ark::Method<size_t(WINAPI *)(void *)>(original, 49)(object);
        auto style = ark::Method<int(WINAPI *)(void *)>(original, 48)(object);
        if (count > 10000 ||
            (style != 0 && style != 1 && style != 2 && style != 6 && style != 7 && style != 8))
            return {};
        std::vector<std::wstring> files;
        if (count == 0 && style == 0)
            files.push_back(path);
        else
            for (size_t i = 0; i < count; ++i) {
                auto name = ark::Method<const wchar_t *(WINAPI *)(void *, size_t)>(original, 50)(object, i);
                if (!name || !*name)
                    return {};
                files.emplace_back(name);
            }
        return files;
    }
    void ObserveEngineSources() {
        for (const auto &name : EngineSources())
            ObserveSource(name.c_str());
    }
    void FinishRecycle(bool closing) {
        if (pendingSources.empty())
            return;
        if (!LoadSettings().recycle) {
            pendingSources.clear();
            return;
        }
        if (!closing && SourcesInUse(pendingSources)) {
            Trace(L"RECYCLE_WAITING_FOR_CLOSE " + path);
            return;
        }
        auto files = std::move(pendingSources);
        pendingSources.clear();
        auto recycled = RecycleSources(files);
        Result result;
        result.archive = path;
        result.sourceVolumes = (unsigned)files.size();
        result.recycledVolumes = recycled.moved;
        result.error = (ark::Error)recycled.error;
        result.outcome =
            SUCCEEDED(recycled.error) && recycled.moved == files.size() ? L"recycled" : L"recycle_failed";
        RecordResult(result, settings.notify);
    }
    void FinishBeforeOpen() {
        if (pendingSources.empty())
            return;
        ark::Method<void(WINAPI *)(void *)>(original, 6)(object);
        FinishRecycle(true);
    }
    void PrepareRecycle() {
        requiredItems.clear();
        writtenItems.clear();
        recycleBlocked = false;
        if (!settings.recycle)
            return;
        ObserveEngineSources();
        if (ark::Method<int(WINAPI *)(void *)>(original, 16)(object)) {
            recycleBlocked = true;
            return;
        }
        int count = ark::Method<int(WINAPI *)(void *)>(original, 13)(object);
        if (count <= 0 || count > 10000000) {
            recycleBlocked = true;
            return;
        }
        for (int i = 0; i < count; ++i) {
            auto item = ark::Method<const ark::FileItem *(WINAPI *)(void *, int)>(original, 14)(object, i);
            if (!item) {
                recycleBlocked = true;
                return;
            }
            // Attribute offset in the pinned x64 engine's item descriptor.
            // Directory callbacks are optional; require every regular item instead.
            DWORD attributes = 0;
            memcpy(&attributes, (const BYTE *)item + 44, sizeof(attributes));
            if (!(attributes & FILE_ATTRIBUTE_DIRECTORY))
                requiredItems.insert(item);
        }
    }
    void QueueRecycle(bool success) {
        if (!settings.recycle || !success || recycleBlocked || canceled || requiredItems.empty() ||
            writtenItems.size() != requiredItems.size())
            return;
        for (auto item : requiredItems)
            if (!writtenItems.count(item))
                return;
        auto names = EngineSources();
        std::vector<SourceFile> files;
        bool rootIncluded = false;
        SourceFile root;
        bool confirmed = CaptureSource(path, root) && !names.empty();
        auto style = ark::Method<int(WINAPI *)(void *)>(original, 48)(object);
        for (const auto &name : names) {
            SourceFile current;
            if (!CaptureSource(name, current)) {
                confirmed = false;
                break;
            }
            bool used = false;
            for (const auto &source : usedSources)
                if (_wcsicmp(source.c_str(), current.path.c_str()) == 0)
                    used = true;
            // Some engine versions enumerate similarly named RAR files even
            // after the actual last volume. Only recycle volumes it consumed.
            if ((style == 6 || style == 7 || style == 8) && !used)
                continue;
            bool observed = false, duplicate = false;
            for (const auto &old : observedSources) {
                if (_wcsicmp(old.path.c_str(), current.path.c_str()) != 0)
                    continue;
                observed = SameSource(old);
                if (_wcsicmp(root.path.c_str(), old.path.c_str()) == 0)
                    rootIncluded = true;
                for (const auto &f : files)
                    if (_wcsicmp(f.path.c_str(), old.path.c_str()) == 0)
                        duplicate = true;
                if (!duplicate)
                    files.push_back(old);
                break;
            }
            if (!observed) {
                confirmed = false;
                break;
            }
        }
        if (!confirmed || !rootIncluded || !TrimSplitSources(style, root.path, files) ||
            (names.size() > 1 && files.size() < 2)) {
            Result result;
            result.archive = path;
            result.outcome = L"recycle_unconfirmed";
            RecordResult(result, settings.notify);
            return;
        }
        pendingSources = std::move(files);
        Trace(L"RECYCLE_QUEUED count=" + std::to_wstring(pendingSources.size()) + L" " + path);
        FinishRecycle(false);
    }
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
    bool CanRetry(ark::Error error, const ark::FileItem *item) {
        if (!canResume || preflight || !CanMatch() ||
            (error != ark::CrcError && error != ark::PasswordOrData))
            return false;
        std::lock_guard<std::mutex> guard(mutex);
        auto plan = plans.find(item);
        return plan != plans.end() && plan->second.last >= 0 && plan->second.next < store.passwords.size();
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
        FinishBeforeOpen();
        path = file ? file : L"（内存中的压缩包）";
        observedSources.clear();
        usedSources.clear();
        requiredItems.clear();
        writtenItems.clear();
        recycleBlocked = false;
        selection.clear();
        successfulItems.clear();
        retryItems.clear();
        outputPaths.clear();
        retryOutputs.clear();
        canResume = false;
        if (file)
            ObserveSource(file, true);
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
        result.error = success ? 0 : canceled ? ark::Canceled : RawError();
        result.attempts = attempts;
        result.savedCount = store.passwords.size();
        result.completedFiles = completed;
        result.opening = opening;
        if (success)
            result.outcome = L"success";
        else if (canceled)
            result.outcome = L"canceled";
        else if (exhausted || hadDataError)
            result.outcome = (hadDataError || lastError == ark::CrcError || lastError == ark::PasswordOrData)
                                 ? L"password_or_data_error"
                                 : L"passwords_exhausted";
        else
            result.outcome = L"error";
        reported = true;
        RecordResult(result, settings.notify && (exhausted.load() || hadDataError.load()));
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
    struct OutputName : ark::SetString {
        ark::SetString *destination;
        std::wstring name;
        OutputName(ark::SetString *d, const wchar_t *p) : destination(d), name(p ? p : L"") {}
        void WINAPI Set(const wchar_t *value) override {
            name = value ? value : L"";
            if (destination)
                destination->Set(value);
        }
    };
    void WINAPI OpeningVolume(const char *a, const wchar_t *w, int n, int &stop) override {
        if (w)
            Trace(L"VOLUME_OPEN " + std::wstring(w));
        if (w)
            context->ObserveSource(w);
        else if (a) {
            int size = MultiByteToWideChar(CP_ACP, 0, a, -1, nullptr, 0);
            std::wstring name(size, L'\0');
            if (size) {
                MultiByteToWideChar(CP_ACP, 0, a, -1, name.data(), size);
                context->ObserveSource(name.c_str());
            }
        }
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
        if (!context->preflight) {
            OutputName output(changed, path);
            if (target)
                target->StartFile(item, stop, all, index, path, changed ? &output : nullptr);
            std::lock_guard<std::mutex> guard(context->mutex);
            auto retry = context->retryOutputs.find(item);
            if (retry != context->retryOutputs.end()) {
                if (!SameSource(retry->second)) {
                    all = TRUE;
                } else
                    output.Set(retry->second.path.c_str());
            }
            context->outputPaths[item] = output.name;
        }
        if (!context->preflight && (stop || all))
            context->recycleBlocked = true;
        if (all)
            context->canceled = true;
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
        // The native completion callback may re-enter the adapter. Do not keep
        // a thread-local map iterator alive across that callback.
        if (item != currentItems.end())
            currentItems.erase(item);
        if (error == 0) {
            std::lock_guard<std::mutex> guard(context->mutex);
            auto p = context->plans.find(key);
            if (p != context->plans.end() && p->second.last >= 0)
                p->second.confirmed = p->second.last;
        }
        bool retry = context->CanRetry(error, key);
        if (retry) {
            std::lock_guard<std::mutex> guard(context->mutex);
            context->retryItems.insert(key);
        }
        if (!context->preflight && !retry) {
            if (error != 0)
                context->recycleBlocked = true;
            else if (key && context->settings.recycle) {
                std::lock_guard<std::mutex> guard(context->mutex);
                if (context->requiredItems.count(key))
                    context->writtenItems.insert(key);
            }
            if (error == 0) {
                std::lock_guard<std::mutex> guard(context->mutex);
                context->successfulItems.insert(key);
                context->completed++;
            }
            if (target)
                target->CompleteFile(info, error);
        }
    }
    void WINAPI OnError(ark::Error error, const ark::FileItem *item, int warning, int &stop) override {
        if (!item) {
            auto current = currentItems.find(context);
            if (current != currentItems.end())
                item = current->second;
        }
        if (context->CanRetry(error, item)) {
            std::lock_guard<std::mutex> guard(context->mutex);
            context->retryItems.insert(item);
            context->hadDataError = true;
            stop = TRUE;
            return;
        }
        if (!context->preflight && error)
            context->recycleBlocked = true;
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
        context->ObserveSource(p, true);
        if (p)
            Trace(L"VOLUME_READ " + std::wstring(p));
        if (target)
            target->VolumeChanged(p);
    }
    void WINAPI AskOverwrite(const ark::FileItem *item, const wchar_t *path, int &mode,
                             ark::SetString *changed) override {
        if (context->preflight) {
            mode = 0;
            return;
        }
        {
            std::lock_guard<std::mutex> guard(context->mutex);
            auto retry = context->retryOutputs.find(item);
            if (retry != context->retryOutputs.end()) {
                mode = path && _wcsicmp(path, retry->second.path.c_str()) == 0 && SameSource(retry->second)
                           ? 0
                           : 3;
                if (mode == 3) {
                    context->canceled = true;
                    context->recycleBlocked = true;
                }
                return;
            }
        }
        OutputName output(changed, path);
        if (target)
            target->AskOverwrite(item, path, mode, changed ? &output : nullptr);
        {
            std::lock_guard<std::mutex> guard(context->mutex);
            context->outputPaths[item] = output.name;
        }
        if (mode == 1 || mode == 3)
            context->recycleBlocked = true;
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
    c->FinishRecycle(true);
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
    c->FinishRecycle(true);
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
        c->ObserveEngineSources();
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
int WINAPI AddSelectionHook(void *object, int index) {
    auto c = Find(object);
    if (!c)
        return FALSE;
    int result = ark::Method<int(WINAPI *)(void *, int)>(c->original, 29)(object, index);
    if (result)
        c->selection.push_back(index);
    return result;
}
int WINAPI EncryptedHook(void *object) {
    auto c = Find(object);
    if (!c)
        return FALSE;
    int result = ark::Method<int(WINAPI *)(void *)>(c->original, 17)(object);
    auto caller = (uintptr_t)__builtin_return_address(0) - (uintptr_t)GetModuleHandleW(nullptr);
    // The native drag dispatcher asks for a password before it calls any
    // extraction method. Defer only that UI gate to the engine's password
    // callback. All ordinary encryption queries still return the real value.
    // The caller and instruction bytes are pinned to this host build; never
    // change the file-item encryption flags or patch the host executable.
    static constexpr unsigned char gate[] = {0xe8, 0x3c, 0x42, 0xfb, 0xff, 0x48, 0x8b, 0x48, 0x08,
                                             0x48, 0x8b, 0x01, 0x48, 0x8b, 0x80, 0x88, 0x00, 0x00,
                                             0x00, 0xff, 0x15, 0x40, 0x4f, 0x10, 0x00, 0x41, 0xbe,
                                             0xff, 0xff, 0xff, 0xff, 0x85, 0xc0, 0x74, 0x36};
    auto host = (const unsigned char *)GetModuleHandleW(nullptr);
    if (result && caller == 0x142138 && !c->extractionDepth && !c->openingRejected &&
        memcmp(host + 0x14211f, gate, sizeof(gate)) == 0) {
        c->Refresh();
        if (c->CanMatch()) {
            Trace(L"DRAG_PASSWORD_DEFERRED_TO_ENGINE");
            return FALSE;
        }
    }
    return result;
}
void WINAPI ClearSelectionHook(void *object) {
    auto c = Find(object);
    if (!c)
        return;
    ark::Method<void(WINAPI *)(void *)>(c->original, 30)(object);
    c->selection.clear();
}
int Execute(void *object, const std::function<int()> &extract,
            const std::function<int(ark::Output *)> &verify, bool diskExtraction = false,
            bool selectedExtraction = false,
            const std::function<int(const std::vector<int> &)> &resume = {}) {
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
    if (!c->settings.enabled && !c->settings.recycle)
        return extract();
    c->store = c->settings.enabled ? ReadPasswordStore() : PasswordStore();
    c->plans.clear();
    c->exhausted = false;
    c->PrepareRecycle();
    c->successfulItems.clear();
    c->retryItems.clear();
    c->outputPaths.clear();
    c->retryOutputs.clear();
    auto selected = c->selection;
    int selectedCount = selectedExtraction ? ark::Method<int(WINAPI *)(void *)>(c->original, 31)(object) : 0;
    if (!selectedCount)
        selected.clear();
    bool selectionKnown = !selectedExtraction || selectedCount == (int)selected.size();
    c->canResume = bool(resume) && selectionKnown;
    auto restoreSelection = [&] {
        if (!selectedExtraction)
            return true;
        ark::Method<void(WINAPI *)(void *)>(c->original, 30)(object);
        for (int index : selected)
            if (!ark::Method<int(WINAPI *)(void *, int)>(c->original, 29)(object, index))
                return false;
        return true;
    };
    auto isEncrypted = ark::Method<int(WINAPI *)(void *)>(c->original, 17);
    if (c->settings.verify && c->CanMatch() && isEncrypted(object) && selectionKnown) {
        Trace(L"VERIFY_BEFORE_EXTRACT");
        bool verified =
            Verify(c, [&](ark::Output *sink) { return restoreSelection() ? verify(sink) : FALSE; });
        // Multi-file extraction consumes the native selection. Replay it before
        // every validation pass and before writing, or an empty list means ALL.
        if (!restoreSelection()) {
            c->canceled = true;
            verified = false;
        }
        if (!verified) {
            c->Record(false, false);
            return FALSE;
        }
    }
    c->ResetOffers();
    int result = extract();
    while (!c->retryItems.empty() && c->canResume && !c->canceled) {
        auto failed = std::move(c->retryItems);
        c->retryItems.clear();
        std::vector<int> remaining;
        int count = ark::Method<int(WINAPI *)(void *)>(c->original, 13)(object);
        bool verified = true;
        for (int index = 0; index < count; ++index) {
            if (selectedExtraction && !selected.empty() &&
                std::find(selected.begin(), selected.end(), index) == selected.end())
                continue;
            auto item =
                ark::Method<const ark::FileItem *(WINAPI *)(void *, int)>(c->original, 14)(object, index);
            if (c->successfulItems.count(item))
                continue;
            remaining.push_back(index);
            if (!failed.count(item))
                continue;
            SourceFile output;
            auto name = c->outputPaths.find(item);
            // Only replace the exact output left by this failed attempt. If it
            // has been renamed/replaced or its identity cannot be captured,
            // preserve it and report the error instead of overwriting blindly.
            if (name == c->outputPaths.end() || !CaptureSource(name->second, output)) {
                verified = false;
                break;
            }
            c->plans[item].confirmed = -1;
            c->ClearEnginePassword();
            Trace(L"VERIFY_FAILED_ITEM_ONLY index=" + std::to_wstring(index));
            verified = Verify(c, [&](ark::Output *sink) {
                return ark::Method<int(WINAPI *)(void *, int, ark::Output *)>(c->original, 25)(object, index,
                                                                                               sink);
            });
            if (!verified)
                break;
            c->retryOutputs[item] = std::move(output);
        }
        if (!verified || remaining.empty()) {
            result = FALSE;
            break;
        }
        c->ResetOffers();
        Trace(L"RESUME_UNFINISHED_ITEMS count=" + std::to_wstring(remaining.size()));
        result = resume(remaining);
    }
    c->canResume = false;
    c->retryOutputs.clear();
    if (selectedExtraction && !ark::Method<int(WINAPI *)(void *)>(c->original, 31)(object))
        c->selection.clear();
    Trace(L"EXTRACT_RETURN " + std::to_wstring(result));
    if (!result)
        c->lastError = c->RawError();
    if (c->canceled) {
        result = FALSE;
        c->overrideError = ark::Canceled;
    }
    c->Record(result != 0, false);
    if (diskExtraction)
        c->QueueRecycle(result != 0);
    return result;
}
// Slots inside overloaded groups are in MSVC order, deliberately independent
// of the C++ compiler used to build this proxy (including Zig/Clang).
int ResumeTo(const std::shared_ptr<Context> &c, const wchar_t *path, const wchar_t *remove,
             const std::vector<int> &indices) {
    ark::Method<void(WINAPI *)(void *)>(c->original, 30)(c->object);
    c->selection = indices;
    for (int index : indices)
        if (!ark::Method<int(WINAPI *)(void *, int)>(c->original, 29)(c->object, index))
            return FALSE;
    return ark::Method<int(WINAPI *)(void *, const wchar_t *, const wchar_t *)>(c->original,
                                                                                33)(c->object, path, remove);
}
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
        },
        true, false, [=](const std::vector<int> &indices) { return ResumeTo(c, path, remove, indices); });
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
        },
        true);
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
        },
        true, true, [=](const std::vector<int> &indices) { return ResumeTo(c, path, remove, indices); });
}
int WINAPI MultiAHook(void *o, const char *path) {
    auto c = Find(o);
    return Execute(
        o, [=] { return ark::Method<int(WINAPI *)(void *, const char *)>(c->original, 34)(o, path); },
        [=](ark::Output *sink) {
            return ark::Method<int(WINAPI *)(void *, ark::Output *)>(c->original, 32)(o, sink);
        },
        true, true);
}
int WINAPI MultiStreamHook(void *o, ark::Output *stream) {
    auto c = Find(o);
    return Execute(
        o, [=] { return ark::Method<int(WINAPI *)(void *, ark::Output *)>(c->original, 32)(o, stream); },
        [=](ark::Output *sink) {
            return ark::Method<int(WINAPI *)(void *, ark::Output *)>(c->original, 32)(o, sink);
        },
        false, true);
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
        table[17] = (void *)&EncryptedHook;
        table[21] = (void *)&AllStreamHook;
        table[22] = (void *)&AllWHook;
        table[23] = (void *)&AllAHook;
        table[24] = (void *)&OneBufferHook;
        table[25] = (void *)&OneStreamHook;
        table[26] = (void *)&OneAHook;
        table[27] = (void *)&OneWHook;
        table[28] = (void *)&OneAsHook;
        table[29] = (void *)&AddSelectionHook;
        table[30] = (void *)&ClearSelectionHook;
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
