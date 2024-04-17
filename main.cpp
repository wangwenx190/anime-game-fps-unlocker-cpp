#include <windows.h>
#include <shellapi.h>
#include <combaseapi.h>
#include <tlhelp32.h>
#include <io.h>
#include <fcntl.h>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <iostream>
#include <clocale>
#include <cassert>
#include <filesystem>

namespace fs = std::filesystem;

using namespace std::chrono_literals;

static constexpr const auto kFPS_TARGET = std::uint32_t{ 500 };
static constexpr const auto kMaxRetryTimes = std::uint8_t{ 200 };
static constexpr const auto kGame_4_3_0_TDS = DWORD{ 0x656FF9F9 };

static constexpr const char kVT_Color_Default[] = "\x1b[0m";
static constexpr const char kVT_Color_Black[] = "\x1b[1;30m";
static constexpr const char kVT_Color_Red[] = "\x1b[1;31m";
static constexpr const char kVT_Color_Green[] = "\x1b[1;32m";
static constexpr const char kVT_Color_Yellow[] = "\x1b[1;33m";
static constexpr const char kVT_Color_Blue[] = "\x1b[1;34m";
static constexpr const char kVT_Color_Magenta[] = "\x1b[1;35m";
static constexpr const char kVT_Color_Cyan[] = "\x1b[1;36m";
static constexpr const char kVT_Color_White[] = "\x1b[1;37m";

#define PRINT(Message)   std::wcout                     << Message                      << std::endl
#define SUCCESS(Message) std::wcout << kVT_Color_Green  << Message << kVT_Color_Default << std::endl
#define WARN(Message)    std::wcerr << kVT_Color_Yellow << Message << kVT_Color_Default << std::endl
#define ERROR(Message)   std::wcerr << kVT_Color_Red    << Message << kVT_Color_Default << std::endl
#define NOTICE(Message)  std::wcout << kVT_Color_Cyan   << Message << kVT_Color_Default << std::endl

[[nodiscard]] static inline std::uintptr_t PatternScan(const void* module, const char* signature)
{
    assert(module);
    assert(signature);
    assert(*signature != '\0');
    if (!module || !signature || *signature == '\0') {
        return 0;
    }

    static const auto pattern_to_byte = [](const char* pattern) {
        auto bytes = std::vector<int>{};
        auto start = const_cast<char*>(pattern);
        auto end = const_cast<char*>(pattern) + std::strlen(pattern);
        for (auto current = start; current < end; ++current) {
            if (*current == '?') {
                ++current;
                if (*current == '?') {
                    ++current;
                }
                bytes.push_back(-1);
            } else {
                bytes.push_back(static_cast<int>(std::strtoul(current, &current, 16)));
            }
        }
        return bytes;
    };

    const auto dosHeader = static_cast<const IMAGE_DOS_HEADER *>(module);
    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(static_cast<const std::uint8_t*>(module) + dosHeader->e_lfanew);

    const auto patternBytes = pattern_to_byte(signature);
    const auto scanBytes = static_cast<const std::uint8_t*>(module);

    const auto patternSize = patternBytes.size();
    const auto patternData = patternBytes.data();

    for (auto i = 0ul; i < ntHeaders->OptionalHeader.SizeOfImage - patternSize; ++i) {
        bool found = true;
        for (auto j = 0ul; j < patternSize; ++j) {
            if (scanBytes[i + j] != patternData[j] && patternData[j] != -1) {
                found = false;
                break;
            }
        }
        if (found) {
            return reinterpret_cast<std::uintptr_t>(&scanBytes[i]);
        }
    }
    return 0;
}

[[nodiscard]] static inline std::wstring GetLastErrorAsString(const DWORD dwError)
{
    LPWSTR buf = nullptr;
    ::FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPWSTR>(&buf), 0, nullptr);
    const std::wstring str{ buf };
    ::LocalFree(buf);
    return str;
}

[[nodiscard]] static inline std::wstring GetLastErrorAsString()
{
    return GetLastErrorAsString(::GetLastError());
}

[[nodiscard]] static inline bool GetModule(const DWORD pid, const std::wstring &moduleName, PMODULEENTRY32W pEntry)
{
    assert(!moduleName.empty());
    if (moduleName.empty()) {
        return false;
    }
    MODULEENTRY32W me32{};
    me32.dwSize = sizeof(me32);
    const HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (!snap) {
        ERROR("CreateToolhelp32Snapshot failed: " << GetLastErrorAsString());
        return false;
    }
    bool found = false;
    for (::Module32FirstW(snap, &me32); ::Module32NextW(snap, &me32);)
    {
        if (me32.th32ProcessID != pid) {
            continue;
        }
        if (me32.szModule == moduleName)
        {
            found = true;
            if (pEntry) {
                *pEntry = me32;
            }
            break;
        }
    }
    ::CloseHandle(snap);
    return found;
}

[[nodiscard]] static inline DWORD GetPID(const std::wstring &processName)
{
    assert(!processName.empty());
    if (processName.empty()) {
        return 0;
    }
    DWORD pid = 0;
    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof(pe32);
    const HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (!snap) {
        ERROR("CreateToolhelp32Snapshot failed: " << GetLastErrorAsString());
        return 0;
    }
    for (::Process32FirstW(snap, &pe32); ::Process32NextW(snap, &pe32);)
    {
        if (pe32.szExeFile == processName)
        {
            pid = pe32.th32ProcessID;
            break;
        }
    }
    ::CloseHandle(snap);
    return pid;
}

[[nodiscard]] static inline bool IsCurrentProcessElevated()
{
    static const auto result = []() -> bool {
        const HANDLE hProcess = ::GetCurrentProcess();
        if (!hProcess/* || (hProcess == INVALID_HANDLE_VALUE)*/) {
            return false;
        }
        HANDLE hToken = nullptr;
        if (!::OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken)) {
            return false;
        }
        bool elevated = false;
        TOKEN_ELEVATION info{};
        DWORD dwSize = sizeof(info);
        if (::GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS::TokenElevation, &info, dwSize, &dwSize)) {
            elevated = info.TokenIsElevated;
        }
        ::CloseHandle(hToken);
        return elevated;
    }();
    return result;
}

[[nodiscard]] static inline bool RunAsElevated(const std::wstring &path, const std::vector<std::wstring> &params)
{
    assert(!path.empty());
    if (path.empty()) {
        return false;
    }
    const std::wstring workDir = fs::path(path).parent_path().wstring();
    ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.fMask = SEE_MASK_NOASYNC;
    sei.nShow = SW_SHOW;
    sei.lpFile = path.c_str();
    sei.lpDirectory = workDir.c_str();
    std::wstring args{};
    for (std::size_t index = 0; index != params.size(); ++index) {
        args += params.at(index);
        if (index != params.size() - 1) {
            args += ' ';
        }
    }
    sei.lpParameters = args.empty() ? nullptr : args.c_str();
    return ::ShellExecuteExW(&sei);
}

// Helper for reading out PE executable files: return word size of a IMAGE_NT_HEADERS64, IMAGE_NT_HEADERS32
template <typename ImageNtHeader>
[[nodiscard]] static inline std::uint32_t ntHeaderWordSize(const ImageNtHeader *ntHeader)
{
    assert(ntHeader);
    if (!ntHeader) {
        return 0;
    }
#if 1
    switch (ntHeader->OptionalHeader.Magic) {
        case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            return 32;
        case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            return 64;
        default:
            break;
    }
#else
    switch (ntHeader->FileHeader.Machine) {
        case IMAGE_FILE_MACHINE_I386:
            return 32;
        case IMAGE_FILE_MACHINE_IA64:
        case IMAGE_FILE_MACHINE_AMD64:
        case IMAGE_FILE_MACHINE_ARM64:
            return 64;
        default:
            break;
    }
#endif
    return 0;
}

// Helper for reading out PE executable files: Retrieve the NT image header of an
// executable via the legacy DOS header.
[[nodiscard]] static inline IMAGE_NT_HEADERS *getNtHeader(void *fileMemory)
{
    assert(fileMemory);
    if (!fileMemory) {
        return nullptr;
    }
    const auto dosHeader = static_cast<PIMAGE_DOS_HEADER>(fileMemory);
    // Check DOS header consistency
    if (::IsBadReadPtr(dosHeader, sizeof(IMAGE_DOS_HEADER))
        || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        ERROR("DOS header check failed.");
        return nullptr;
    }
    // Retrieve NT header
    const auto ntHeaderC = static_cast<char *>(fileMemory) + dosHeader->e_lfanew;
    const auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS *>(ntHeaderC);
    // Check NT header consistency
    if (::IsBadReadPtr(ntHeaders, sizeof(ntHeaders->Signature))
        || ntHeaders->Signature != IMAGE_NT_SIGNATURE
        || ::IsBadReadPtr(&ntHeaders->FileHeader, sizeof(IMAGE_FILE_HEADER))) {
        ERROR("NT header check failed.");
        return nullptr;
    }
    // Check magic
    if (ntHeaderWordSize(ntHeaders) == 0) {
        ERROR("NT header check failed, magic " << ntHeaders->OptionalHeader.Magic << " is invalid.");
        return nullptr;
    }
    // Check section headers
    IMAGE_SECTION_HEADER *sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);
    if (::IsBadReadPtr(sectionHeaders, ntHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER))) {
        ERROR("NT header section header check failed.");
        return nullptr;
    }
    return ntHeaders;
}

[[nodiscard]] static inline bool IsGameV4Dot3OrGreater(const std::wstring &path)
{
    assert(!path.empty());
    if (path.empty()) {
        return false;
    }

    HANDLE hFile = nullptr;
    HANDLE hFileMap = nullptr;
    void *fileMemory = nullptr;
    DWORD dwTimeStamp = 0;

    do {
        hFile = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (!hFile || hFile == INVALID_HANDLE_VALUE) {
            ERROR("Failed to open file: " << GetLastErrorAsString());
            break;
        }

        hFileMap = ::CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hFileMap || hFileMap == INVALID_HANDLE_VALUE) {
            ERROR("Failed to create file mapping: " << GetLastErrorAsString());
            break;
        }

        fileMemory = ::MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
        if (!fileMemory) {
            ERROR("Failed to map file: " << GetLastErrorAsString());
            break;
        }

        const IMAGE_NT_HEADERS *ntHeaders = getNtHeader(fileMemory);
        if (!ntHeaders) {
            ERROR("Failed to parse PE file NT headers.");
            break;
        }

        const std::uint32_t wordSize = ntHeaderWordSize(ntHeaders);
        if (wordSize == 0) {
            ERROR("Failed to parse PE file word size.");
            break;
        }

        if (wordSize == 32) {
            PRINT("Parsing 32-bit PE file ...");
            dwTimeStamp = reinterpret_cast<const IMAGE_NT_HEADERS32 *>(ntHeaders)->FileHeader.TimeDateStamp;
        } else {
            PRINT("Parsing 64-bit PE file ...");
            dwTimeStamp = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(ntHeaders)->FileHeader.TimeDateStamp;
        }

        PRINT("PE file time date stamp: 0x" << std::hex << dwTimeStamp);
    } while (false);

    if (fileMemory) {
        ::UnmapViewOfFile(fileMemory);
        fileMemory = nullptr;
    }

    if (hFileMap) {
        ::CloseHandle(hFileMap);
        hFileMap = nullptr;
    }

    if (hFile) {
        ::CloseHandle(hFile);
        hFile = nullptr;
    }

    if (dwTimeStamp == 0) {
        ERROR("Failed to parse the game executable's time date stamp.");
        return false;
    }

    return dwTimeStamp >= kGame_4_3_0_TDS;
}

[[nodiscard]] static inline bool IsGenshinGame(const fs::path &path)
{
    assert(!path.empty());
    if (path.empty()) {
        return false;
    }
    const std::wstring gameFileName(path.filename().wstring());
    return gameFileName == L"GenshinImpact.exe" || gameFileName == L"YuanShen.exe";
}

extern "C" int WINAPI wmain(int argc, wchar_t *argv[])
{
    if (!IsCurrentProcessElevated()) {
        std::vector<std::wstring> params{};
        params.reserve(argc - 1);
        for (int index = 1; index != argc; ++index) {
            std::wstring path{ argv[index] };
            if (path.find_first_of(L' ') != std::wstring::npos) {
                path = L"\"" + path + L"\"";
            }
            params.emplace_back(path);
        }
        RunAsElevated(argv[0], params);
        return EXIT_FAILURE;
    }

    std::setlocale(LC_ALL, "C.UTF-8");
    _setmode(_fileno(stdout), _O_U8TEXT);
    _setmode(_fileno(stderr), _O_U8TEXT);

    ::SetConsoleCP(CP_UTF8);
    ::SetConsoleOutputCP(CP_UTF8);

    const auto initConsole = [](const HANDLE handle){
        if (!handle || handle == INVALID_HANDLE_VALUE) {
            return;
        }
        DWORD dwMode{ 0 };
        ::GetConsoleMode(handle, &dwMode);
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        ::SetConsoleMode(handle, dwMode);
    };
    initConsole(::GetStdHandle(STD_OUTPUT_HANDLE));
    initConsole(::GetStdHandle(STD_ERROR_HANDLE));

    ::SetConsoleTitleW(L"Genshin Impact FPS Unlocker");
    
    if (argc <= 1) {
        ERROR("You need to add the absolute path of your game executable file to the command line parameters!");
        std::getchar();
        return EXIT_FAILURE;
    }

    const fs::path processPath{ argv[argc - 1] };

    if (!fs::exists(processPath)) {
        ERROR(processPath << " does not exist!");
        std::getchar();
        return EXIT_FAILURE;
    }

    if (!fs::is_regular_file(processPath)) {
        ERROR(processPath << " does not seem to be an regular file!");
        std::getchar();
        return EXIT_FAILURE;
    }

    if (!IsGenshinGame(processPath)) {
        ERROR(processPath << " does not seem to be the Genshin Impact game executable!");
        std::getchar();
        return EXIT_FAILURE;
    }

    const fs::path processDir = processPath.parent_path();
    const std::wstring fileName = processPath.filename();

    NOTICE("Genshin Impact FPS Unlocker V" << APP_VERSION_STR);
    PRINT("Game path: " << processPath);

    const DWORD pid = GetPID(fileName);
    if (pid) {
        ERROR("The game is running already, please close it. This program will run it automatically for you.");
        std::getchar();
        return EXIT_FAILURE;
    }

    PRINT("Launching the game, please wait patiently ...");
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!::CreateProcessW(processPath.c_str(), nullptr, nullptr, nullptr, FALSE, 0, nullptr, processDir.c_str(), &si, &pi))
    {
        ERROR("CreateProcessW failed: " << GetLastErrorAsString());
        std::getchar();
        return EXIT_FAILURE;
    }
    ::CloseHandle(pi.hThread);

    SUCCESS("Game successfully launched.");
    PRINT("PID: " << pi.dwProcessId);

    PRINT("Finding UnityPlayer.dll in memory ...");
    std::uint8_t retryTimes{ 0 };
    MODULEENTRY32W hUnityPlayer{};
    hUnityPlayer.dwSize = sizeof(hUnityPlayer);
    while (!GetModule(pi.dwProcessId, L"UnityPlayer.dll", &hUnityPlayer)) {
        ++retryTimes;
        if (retryTimes >= kMaxRetryTimes) {
            ERROR("Can't locate the memory address of UnityPlayer.dll, most probably due to the game version or region has not been supported yet.");
            std::getchar();
            return EXIT_FAILURE;
        }
        std::this_thread::sleep_for(100ms);
    }
    SUCCESS("UnityPlayer.dll found.");
    PRINT("UnityPlayer.dll address: 0x" << std::hex << hUnityPlayer.modBaseAddr);

    PRINT("Finding UserAssembly.dll in memory ...");
    retryTimes = 0;
    MODULEENTRY32W hUserAssembly{};
    hUserAssembly.dwSize = sizeof(hUserAssembly);
    while (!GetModule(pi.dwProcessId, L"UserAssembly.dll", &hUserAssembly)) {
        ++retryTimes;
        if (retryTimes >= kMaxRetryTimes) {
            ERROR("Can't locate the memory address of UserAssembly.dll, most probably due to the game version or region has not been supported yet.");
            std::getchar();
            return EXIT_FAILURE;
        }
        std::this_thread::sleep_for(100ms);
    }
    SUCCESS("UserAssembly.dll found.");
    PRINT("UserAssembly.dll address: 0x" << std::hex << hUserAssembly.modBaseAddr);

    LPVOID mem = ::VirtualAlloc(nullptr, hUnityPlayer.modBaseSize + hUserAssembly.modBaseSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        ERROR("VirtualAlloc failed: " << GetLastErrorAsString());
        std::getchar();
        return EXIT_FAILURE;
    }

    PRINT("Reading UnityPlayer.dll's memory ...");
    if (!::ReadProcessMemory(pi.hProcess, hUnityPlayer.modBaseAddr, mem, hUnityPlayer.modBaseSize, nullptr)) {
        ERROR("ReadProcessMemory failed: " << GetLastErrorAsString());
        std::getchar();
        return EXIT_FAILURE;
    }
    SUCCESS("UnityPlayer.dll successfully loaded.");

    PRINT("Reading UserAssembly.dll's memory ...");
    auto ua = reinterpret_cast<LPVOID>(reinterpret_cast<std::uintptr_t>(mem) + hUnityPlayer.modBaseSize);
    if (!::ReadProcessMemory(pi.hProcess, hUserAssembly.modBaseAddr, ua, hUserAssembly.modBaseSize, nullptr)) {
        ERROR("ReadProcessMemory failed: " << GetLastErrorAsString());
        std::getchar();
        return EXIT_FAILURE;
    }
    SUCCESS("UserAssembly.dll successfully loaded.");

    PRINT("Searching for memory pattern ...");

    static const bool v4dot3OrGreater = IsGameV4Dot3OrGreater(processPath);
    std::uintptr_t address = 0;
    if (v4dot3OrGreater) {
        PRINT("Current game version >= V4.3.0");
        address = PatternScan(ua, "B9 3C 00 00 00 FF 15");
    } else {
        PRINT("Current game version >= V4.0.0 but < V4.3.0");
        address = PatternScan(ua, "E8 ? ? ? ? 85 C0 7E 07 E8 ? ? ? ? EB 05");
    }
    if (!address) {
        ERROR("Failed to find a necessary memory address. Please inform the author to update this program!");
        std::getchar();
        return EXIT_FAILURE;
    }

    std::uintptr_t pFPS = 0;
    {
        std::uintptr_t rip = address;
        if (v4dot3OrGreater) {
            rip += 5;
            rip += *reinterpret_cast<std::int32_t*>(rip + 2) + 6;
        } else {
            rip += *reinterpret_cast<std::int32_t*>(rip + 1) + 5;
            rip += *reinterpret_cast<std::int32_t*>(rip + 3) + 7;
        }
        std::uintptr_t ptr = 0;
        std::uintptr_t data = rip - reinterpret_cast<std::uintptr_t>(ua) + reinterpret_cast<std::uintptr_t>(hUserAssembly.modBaseAddr);
        while (!ptr) {
            ::ReadProcessMemory(pi.hProcess, reinterpret_cast<LPCVOID>(data), &ptr, sizeof(std::uintptr_t), nullptr);
            std::this_thread::sleep_for(100ms);
        }
        rip = ptr - reinterpret_cast<std::uintptr_t>(hUnityPlayer.modBaseAddr) + reinterpret_cast<std::uintptr_t>(mem);
        while (*reinterpret_cast<std::uint8_t*>(rip) == 0xE8 || *reinterpret_cast<std::uint8_t*>(rip) == 0xE9) {
            rip += *reinterpret_cast<std::int32_t*>(rip + 1) + 5;
        }
        pFPS = rip + *reinterpret_cast<std::int32_t*>(rip + 2) + 6;
        pFPS -= reinterpret_cast<std::uintptr_t>(mem);
        PRINT("FPS offset: 0x" << std::hex << pFPS);
        pFPS = reinterpret_cast<std::uintptr_t>(hUnityPlayer.modBaseAddr) + pFPS;
    }

    address = PatternScan(mem, "E8 ? ? ? ? 8B E8 49 8B 1E");
    std::uintptr_t pVSync = 0;
    if (address) {
        std::uintptr_t ppvsync = 0;
        std::uintptr_t rip = address;
        std::int32_t rel = *reinterpret_cast<std::int32_t*>(rip + 1);
        rip = rip + rel + 5;
        std::uint64_t rax = *reinterpret_cast<std::uint32_t*>(rip + 3);
        ppvsync = rip + rax + 7;
        ppvsync -= reinterpret_cast<std::uintptr_t>(mem);
        PRINT("VSync offset: 0x" << std::hex << ppvsync);
        ppvsync = reinterpret_cast<std::uintptr_t>(hUnityPlayer.modBaseAddr) + ppvsync;

        std::uintptr_t buffer = 0;
        while (!buffer) {
            ::ReadProcessMemory(pi.hProcess, reinterpret_cast<LPCVOID>(ppvsync), &buffer, sizeof(buffer), nullptr);
            std::this_thread::sleep_for(100ms);
        }

        rip += 7;
        pVSync = *reinterpret_cast<std::uint32_t*>(rip + 2);
        pVSync = buffer + pVSync;
    }

    ::VirtualFree(mem, 0, MEM_RELEASE);

    SUCCESS("We are DONE here.");

    DWORD dwExitCode = STILL_ACTIVE;
    while (dwExitCode == STILL_ACTIVE) {
        ::GetExitCodeProcess(pi.hProcess, &dwExitCode);

        std::this_thread::sleep_for(2s);
        int fps = -1;
        ::ReadProcessMemory(pi.hProcess, reinterpret_cast<LPVOID>(pFPS), &fps, sizeof(fps), nullptr);
        if (fps <= 0) {
            continue;
        }
        if (fps != kFPS_TARGET) {
            WARN("Game FPS is " << std::dec << fps << ". Trying to unlock the limit ...");
            if (::WriteProcessMemory(pi.hProcess, reinterpret_cast<LPVOID>(pFPS), &kFPS_TARGET, sizeof(kFPS_TARGET), nullptr)) {
                SUCCESS("Game FPS is successfully unlocked.");
            } else {
                ERROR("WriteProcessMemory failed: " << GetLastErrorAsString());
            }
        }

        int vsync = -1;
        ::ReadProcessMemory(pi.hProcess, reinterpret_cast<LPVOID>(pVSync), &vsync, sizeof(vsync), nullptr);
        if (vsync != 0) {
            WARN("VSync is enabled. Trying to disable it ...");
            vsync = 0;
            if (::WriteProcessMemory(pi.hProcess, reinterpret_cast<LPVOID>(pVSync), &vsync, sizeof(vsync), nullptr)) {
                SUCCESS("VSync is successfully disabled.");
            } else {
                ERROR("WriteProcessMemory failed: " << GetLastErrorAsString());
            }
        }
    }
    ::CloseHandle(pi.hProcess);

    PRINT("Game closed. Exiting ...");

    return EXIT_SUCCESS;
}
