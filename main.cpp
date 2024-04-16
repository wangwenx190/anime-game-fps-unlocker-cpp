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
#include <filesystem>

namespace fs = std::filesystem;

using namespace std::chrono;

static constexpr const auto kFPS_TARGET = std::int32_t{ 500 };

static constexpr const auto kGame_4_3_0_TDS = DWORD{ 0x656FF9F9 };

[[nodiscard]] static inline std::uintptr_t PatternScan(const void* module, const char* signature)
{
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
    MODULEENTRY32W me32{};
    me32.dwSize = sizeof(me32);
    const HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (!snap) {
        std::wcerr << "CreateToolhelp32Snapshot failed: " << GetLastErrorAsString() << std::endl;
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
    DWORD pid = 0;
    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof(pe32);
    const HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (!snap) {
        std::wcerr << "CreateToolhelp32Snapshot failed: " << GetLastErrorAsString() << std::endl;
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
    ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.fMask = SEE_MASK_NOASYNC;
    sei.nShow = SW_SHOW;
    sei.lpFile = path.c_str();
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
    const auto dosHeader = static_cast<PIMAGE_DOS_HEADER>(fileMemory);
    // Check DOS header consistency
    if (::IsBadReadPtr(dosHeader, sizeof(IMAGE_DOS_HEADER))
        || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::wcerr << "DOS header check failed." << std::endl;
        return nullptr;
    }
    // Retrieve NT header
    const auto ntHeaderC = static_cast<char *>(fileMemory) + dosHeader->e_lfanew;
    const auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS *>(ntHeaderC);
    // Check NT header consistency
    if (::IsBadReadPtr(ntHeaders, sizeof(ntHeaders->Signature))
        || ntHeaders->Signature != IMAGE_NT_SIGNATURE
        || ::IsBadReadPtr(&ntHeaders->FileHeader, sizeof(IMAGE_FILE_HEADER))) {
        std::wcerr << "NT header check failed." << std::endl;
        return nullptr;
    }
    // Check magic
    if (ntHeaderWordSize(ntHeaders) == 0) {
        std::wcerr << "NT header check failed, magic " << ntHeaders->OptionalHeader.Magic << " is invalid." << std::endl;
        return nullptr;
    }
    // Check section headers
    IMAGE_SECTION_HEADER *sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);
    if (::IsBadReadPtr(sectionHeaders, ntHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER))) {
        std::wcerr << "NT header section header check failed." << std::endl;
        return nullptr;
    }
    return ntHeaders;
}

[[nodiscard]] static inline bool IsGameV4Dot3OrGreater(const std::wstring &path)
{
    HANDLE hFile = nullptr;
    HANDLE hFileMap = nullptr;
    void *fileMemory = nullptr;
    DWORD dwTimeStamp = 0;

    do {
        hFile = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (!hFile || hFile == INVALID_HANDLE_VALUE) {
            std::wcerr << "Failed to open file: " << GetLastErrorAsString() << std::endl;
            break;
        }

        hFileMap = ::CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hFileMap || hFileMap == INVALID_HANDLE_VALUE) {
            std::wcerr << "Failed to create file mapping: " << GetLastErrorAsString() << std::endl;
            break;
        }

        fileMemory = ::MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
        if (!fileMemory) {
            std::wcerr << "Failed to map file: " << GetLastErrorAsString() << std::endl;
            break;
        }

        const IMAGE_NT_HEADERS *ntHeaders = getNtHeader(fileMemory);
        if (!ntHeaders) {
            std::wcerr << "Failed to parse PE file NT headers." << std::endl;
            break;
        }

        const std::uint32_t wordSize = ntHeaderWordSize(ntHeaders);
        if (wordSize == 0) {
            std::wcerr << "Failed to parse PE file word size." << std::endl;
            break;
        }

        if (wordSize == 32) {
            std::wcout << "Parsing 32-bit PE file ..." << std::endl;
            dwTimeStamp = reinterpret_cast<const IMAGE_NT_HEADERS32 *>(ntHeaders)->FileHeader.TimeDateStamp;
        } else {
            std::wcout << "Parsing 64-bit PE file ..." << std::endl;
            dwTimeStamp = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(ntHeaders)->FileHeader.TimeDateStamp;
        }

        std::wcout << "PE file time date stamp: " << std::hex << dwTimeStamp << std::endl;
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
        std::wcerr << "Failed to parse the game executable's time date stamp." << std::endl;
        return false;
    }

    return dwTimeStamp >= kGame_4_3_0_TDS;
}

extern "C" int WINAPI wmain(int argc, wchar_t *argv[])
{
    if (!IsCurrentProcessElevated()) {
        std::vector<std::wstring> params{};
        params.reserve(argc - 1);
        for (int index = 1; index != argc; ++index) {
            std::wstring path{ argv[index] };
            path = L"\"" + path + L"\"";
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
        std::wcerr << "You need to add the absolute path of your game executable file to the command line parameters!" << std::endl;
        std::getchar();
        return EXIT_FAILURE;
    }

    const fs::path processPath{ argv[argc - 1] };

    if (!fs::exists(processPath)) {
        std::wcerr << processPath << " does not exist!" << std::endl;
        std::getchar();
        return EXIT_FAILURE;
    }

    if (!fs::is_regular_file(processPath)) {
        std::wcerr << processPath << " does not seem to be a regular file!" << std::endl;
        std::getchar();
        return EXIT_FAILURE;
    }

    const fs::path processDir = processPath.parent_path();
    const std::wstring fileName = processPath.filename();

    std::wcout << "Genshin Impact FPS Unlocker V" << APP_VERSION_STR << std::endl;
    std::wcout << "Game path: " << processPath << std::endl;

    const DWORD pid = GetPID(fileName);
    if (pid) {
        std::wcerr << "The game is running already, please close it. This program will run it automatically for you." << std::endl;
        std::getchar();
        return EXIT_FAILURE;
    }

    std::wcout << "Launching game, please wait ..." << std::endl;
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!::CreateProcessW(processPath.c_str(), nullptr, nullptr, nullptr, FALSE, 0, nullptr, processDir.c_str(), &si, &pi))
    {
        std::wcerr << "CreateProcessW failed: " << GetLastErrorAsString() << std::endl;
        std::getchar();
        return EXIT_FAILURE;
    }
    ::CloseHandle(pi.hThread);

    std::wcout << "Game successfully launched." << std::endl;
    std::wcout << "PID: " << pi.dwProcessId << std::endl;

    std::wcout << "Finding UnityPlayer.dll ..." << std::endl;
    MODULEENTRY32W hUnityPlayer{};
    hUnityPlayer.dwSize = sizeof(hUnityPlayer);
    while (!GetModule(pi.dwProcessId, L"UnityPlayer.dll", &hUnityPlayer)) {
        std::this_thread::sleep_for(100ms);
    }
    std::wcout << "UnityPlayer.dll found." << std::endl;
    std::wcout << "UnityPlayer.dll address: " << std::hex << hUnityPlayer.modBaseAddr << std::endl;

    std::wcout << "Finding UserAssembly.dll ..." << std::endl;
    MODULEENTRY32W hUserAssembly{};
    hUserAssembly.dwSize = sizeof(hUserAssembly);
    while (!GetModule(pi.dwProcessId, L"UserAssembly.dll", &hUserAssembly)) {
        std::this_thread::sleep_for(100ms);
    }
    std::wcout << "UserAssembly.dll found." << std::endl;
    std::wcout << "UserAssembly.dll address: " << std::hex << hUserAssembly.modBaseAddr << std::endl;

    LPVOID mem = ::VirtualAlloc(nullptr, hUnityPlayer.modBaseSize + hUserAssembly.modBaseSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        std::wcerr << "VirtualAlloc failed: " << GetLastErrorAsString() << std::endl;
        std::getchar();
        return EXIT_FAILURE;
    }

    std::wcout << "Reading UnityPlayer.dll's memory ..." << std::endl;
    if (!::ReadProcessMemory(pi.hProcess, hUnityPlayer.modBaseAddr, mem, hUnityPlayer.modBaseSize, nullptr)) {
        std::wcerr << "ReadProcessMemory failed: " << GetLastErrorAsString() << std::endl;
        std::getchar();
        return EXIT_FAILURE;
    }
    std::wcout << "UnityPlayer.dll successfully loaded." << std::endl;

    std::wcout << "Reading UserAssembly.dll's memory ..." << std::endl;
    auto ua = reinterpret_cast<LPVOID>(reinterpret_cast<std::uintptr_t>(mem) + hUnityPlayer.modBaseSize);
    if (!::ReadProcessMemory(pi.hProcess, hUserAssembly.modBaseAddr, ua, hUserAssembly.modBaseSize, nullptr)) {
        std::wcerr << "ReadProcessMemory failed: " << GetLastErrorAsString() << std::endl;
        std::getchar();
        return EXIT_FAILURE;
    }
    std::wcout << "UserAssembly.dll successfully loaded." << std::endl;

    std::wcout << "Searching for pattern ..." << std::endl;

    const bool v4dot3OrGreater = IsGameV4Dot3OrGreater(processPath);
    std::uintptr_t address = 0;
    if (v4dot3OrGreater) {
        std::wcout << "Current game version >= V4.3.0" << std::endl;
        address = PatternScan(ua, "B9 3C 00 00 00 FF 15");
    } else {
        std::wcout << "Current game version >= V4.0.0 but < V4.3.0" << std::endl;
        address = PatternScan(ua, "E8 ? ? ? ? 85 C0 7E 07 E8 ? ? ? ? EB 05");
    }
    if (!address) {
        std::wcerr << "Failed to find a necessary memory address. Please tell the author to update this program!" << std::endl;
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
        std::wcout << "FPS offset: " << std::hex << pFPS << std::endl;
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
        std::wcout << "VSync offset: " << std::hex << ppvsync << std::endl;
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

    std::wcout << "We are DONE here." << std::endl;

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
            std::wcout << "Game FPS is " << std::dec << fps << ". Trying to unlock the limit ..." << std::endl;
            if (::WriteProcessMemory(pi.hProcess, reinterpret_cast<LPVOID>(pFPS), &kFPS_TARGET, sizeof(kFPS_TARGET), nullptr)) {
                std::wcout << "Game FPS is successfully unlocked." << std::endl;
            } else {
                std::wcerr << "WriteProcessMemory failed: " << GetLastErrorAsString() << std::endl;
            }
        }

        int vsync = -1;
        ::ReadProcessMemory(pi.hProcess, reinterpret_cast<LPVOID>(pVSync), &vsync, sizeof(vsync), nullptr);
        if (vsync != 0) {
            std::wcout << "VSync is enabled. Trying to disable it ..." << std::endl;
            vsync = 0;
            if (::WriteProcessMemory(pi.hProcess, reinterpret_cast<LPVOID>(pVSync), &vsync, sizeof(vsync), nullptr)) {
                std::wcout << "VSync is successfully disabled." << std::endl;
            } else {
                std::wcerr << "WriteProcessMemory failed: " << GetLastErrorAsString() << std::endl;
            }
        }
    }
    ::CloseHandle(pi.hProcess);

    std::wcout << "Game closed. Exiting ..." << std::endl;

    return EXIT_SUCCESS;
}
